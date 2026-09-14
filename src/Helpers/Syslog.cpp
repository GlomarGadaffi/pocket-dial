#include "Syslog.hpp"

#include <cstdio>
#include <cstring>
#include <mutex>

// Platform split, same three-term guard the rest of the engine uses
// (src/SIP/RtpReceiver.hpp:39, src/Helpers/LogQueue.hpp:31). Only the socket and
// the NVS read are platform-specific — the formatter, the address parser and the
// enable/disable state machine are not. Given a name once here so the guarded
// spots below read as one decision rather than half a dozen, and so the guard
// itself cannot drift between them.
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	#define SYSLOG_HAS_UDP 1
#else
	#define SYSLOG_HAS_UDP 0
#endif

#if SYSLOG_HAS_UDP
// Exactly what src/SIP/RtpSender.cpp:6-10 includes for its ESP socket arm —
// lwIP's POSIX shims supply sockaddr_in / htons / socket / connect / send /
// close from these two headers alone.
#include <unistd.h>
#include <sys/socket.h>
#include "nvs_flash.h"
#include "nvs.h"
#endif

namespace
{
	// NVS namespace for the persisted PBX config. The canonical definition is
	// pbxpersist::kNvsNamespace (src/SIP/PbxPersist.hpp:16), but that header is
	// part of the SIP layer and src/Helpers must not reach up into it — so this
	// mirrors the precedent DeviceConfig.hpp:161-163 already set for the same
	// string in this same directory. The three must stay in step: a change to the
	// namespace has to be made in all of them.
#if SYSLOG_HAS_UDP
	constexpr auto kNvsNamespace = "pbxcfg";
#endif

	// Parse a plain dotted-quad IPv4 literal into four octets, in a.b.c.d order.
	// Hand-rolled rather than inet_pton() because the validation has to work on
	// the host build too, where this file pulls in no socket headers at all (see
	// Syslog.hpp's layering note) — and because inet_pton()'s acceptance is not
	// uniform across platforms for the odd forms below.
	//
	// Strict on purpose: exactly four decimal octets, 1-3 digits each, 0-255, no
	// leading zeros (a leading zero reads as octal to some resolvers, so
	// "010.1.1.1" is ambiguous rather than merely ugly), no whitespace, no
	// trailing text, no port or CIDR suffix, no shorthand forms ("10.1" as
	// 10.0.0.1). A host string that fails this is a configuration mistake, and
	// the right response is to leave the sink off rather than quietly stream call
	// records to an address the operator did not intend.
	bool parseIpv4(const char* s, uint8_t (&out)[4])
	{
		if (s == nullptr)
		{
			return false;
		}

		size_t i = 0;
		for (int octet = 0; octet < 4; ++octet)
		{
			if (octet > 0)
			{
				if (s[i] != '.')
				{
					return false;
				}
				++i;
			}

			if (s[i] < '0' || s[i] > '9')
			{
				return false;
			}
			// s[i] is a digit here, so s[i + 1] is inside the string (worst case
			// the NUL) — safe to look ahead for the leading-zero case.
			if (s[i] == '0' && s[i + 1] >= '0' && s[i + 1] <= '9')
			{
				return false;
			}

			int value  = 0;
			int digits = 0;
			while (s[i] >= '0' && s[i] <= '9')
			{
				if (++digits > 3)
				{
					return false;
				}
				value = value * 10 + (s[i] - '0');
				++i;
			}
			if (value > 255)
			{
				return false;
			}
			out[octet] = static_cast<uint8_t>(value);
		}

		return s[i] == '\0';   // reject anything trailing the fourth octet
	}

	// RFC 5424 §6.2.5: APP-NAME is 1-48 PRINTUSASCII characters (%d33-126) — no
	// spaces, no control bytes, no UTF-8. This is a CORRECTNESS filter, not
	// cosmetics: a space inside APP-NAME is read by the collector as a field
	// separator, which shifts every later field one place left (the caller's name
	// into PROCID, MSGID into STRUCTURED-DATA...) and silently corrupts the parse
	// of an otherwise well-formed frame. Offending bytes become '_' rather than
	// being dropped, so two differing names never collapse into one. `out` must
	// hold at least kMaxAppNameBytes + 1 bytes.
	void sanitizeAppName(const char* in, char* out, size_t cap)
	{
		size_t w = 0;
		if (in != nullptr)
		{
			for (size_t i = 0; in[i] != '\0' && w + 1 < cap; ++i)
			{
				const unsigned char c = static_cast<unsigned char>(in[i]);
				out[w++] = (c >= 33 && c <= 126) ? static_cast<char>(c) : '_';
			}
		}
		if (w == 0)
		{
			// §6.2.5 allows the NILVALUE when the originator cannot provide the
			// field; an empty APP-NAME is not legal, a "-" is.
			out[w++] = '-';
		}
		out[w] = '\0';
	}

	// Length of `s` with trailing CR/LF/space/tab ignored. One UDP datagram IS
	// one syslog message (RFC 5426 §3.1), so a trailing newline carries no
	// framing information here — it only upsets line-oriented collectors, and the
	// intended producer (the LogQueue drain, LogQueue.hpp:114) hands over lines
	// that still carry the ESP log's '\n'.
	size_t trimmedLen(const char* s)
	{
		if (s == nullptr)
		{
			return 0;
		}
		size_t n = std::strlen(s);
		while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == '\r' || s[n - 1] == ' ' || s[n - 1] == '\t'))
		{
			--n;
		}
		return n;
	}

	struct SyslogState
	{
		std::mutex mutex;
		bool       configured = false;
		uint8_t    addr[4]    = {0, 0, 0, 0};
		uint16_t   port       = Syslog::kDefaultPort;
#if SYSLOG_HAS_UDP
		int        sock       = -1;
#endif
	};

	// Function-local static: constructed on first use, never destroyed before the
	// tasks that use it (a file-scope object could be torn down first at exit on
	// the host build).
	SyslogState& state()
	{
		static SyslogState s;
		return s;
	}

	// Caller must hold state().mutex.
	void closeSocketLocked(SyslogState& s)
	{
#if SYSLOG_HAS_UDP
		if (s.sock >= 0)
		{
			close(s.sock);
			s.sock = -1;
		}
#endif
		s.configured = false;
	}
}

namespace Syslog
{
	size_t formatFrame(char* out, size_t cap, Severity severity, Facility facility,
	                   const char* appName, const char* msg)
	{
		if (out == nullptr || cap == 0)
		{
			return 0;
		}

		char app[kMaxAppNameBytes + 1] = {'\0'};
		sanitizeAppName(appName, app, sizeof(app));

		const int pri = priValue(facility, severity);

		size_t msgLen = trimmedLen(msg);
		if (msgLen > cap)
		{
			// Nothing past `cap` can land anyway; clamping here also keeps the
			// int cast in the "%.*s" precision below well-defined for any input.
			msgLen = cap;
		}

		// THE line this module exists to get right. Field order (RFC 5424 §6.2):
		//   PRI+VERSION, TIMESTAMP, HOSTNAME, APP-NAME, PROCID, MSGID,
		//   STRUCTURED-DATA, MSG
		// which is TWO NILVALUEs before APP-NAME and THREE after it. drawbridge's
		// copy (Syslog.cpp:146) has only two after, putting the caller's event
		// class in PROCID and a fixed product string in APP-NAME — see the
		// "COUNT THE DASHES" note in Syslog.hpp. tests/Syslog_test.cpp asserts
		// each field BY INDEX so a future edit cannot drift a dash back out.
		const int n = (msgLen > 0)
			? std::snprintf(out, cap, "<%d>1 - - %s - - - %.*s",
			                pri, app, static_cast<int>(msgLen), msg)
			: std::snprintf(out, cap, "<%d>1 - - %s - - -", pri, app);

		if (n <= 0)
		{
			out[0] = '\0';
			return 0;
		}

		// snprintf returns the length it WOULD have written and NUL-terminates at
		// cap-1 when that overflows, so clamp to what actually landed. Only the
		// tail of MSG is ever lost: the header is at most 65 bytes.
		return (static_cast<size_t>(n) < cap) ? static_cast<size_t>(n) : (cap - 1);
	}

	std::string formatFrame(Severity severity, Facility facility,
	                        const char* appName, const char* msg)
	{
		char frame[kMaxFrameBytes];
		const size_t n = formatFrame(frame, sizeof(frame), severity, facility, appName, msg);
		return std::string(frame, n);
	}

	bool configure(const std::string& host, uint16_t port)
	{
		SyslogState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);

		// Idempotent, and this IS the disable path: whatever happens below, the
		// previous destination is gone the moment configure() is called.
		closeSocketLocked(s);

		if (host.empty())
		{
			return true;   // successfully disabled
		}

		uint8_t octets[4] = {0, 0, 0, 0};
		if (!parseIpv4(host.c_str(), octets))
		{
			return false;   // not a dotted quad — stay disabled
		}
		std::memcpy(s.addr, octets, sizeof(octets));
		s.port = port;

#if SYSLOG_HAS_UDP
		sockaddr_in dest{};
		dest.sin_family = AF_INET;
		dest.sin_port   = htons(port);
		// The parsed octets are in a.b.c.d order, which IS network byte order for
		// in_addr — a memcpy means no htonl() and the same four bytes serve both
		// the stored state and the sockaddr.
		std::memcpy(&dest.sin_addr, octets, sizeof(octets));

		const int fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (fd < 0)
		{
			return false;   // no ESP_LOGx here — see the RE-ENTRANCY RULE
		}

		// connect() on a UDP socket only fixes the default peer for send(): no
		// handshake, no round trip, still connectionless. It is what lets the hot
		// path call send() with no sockaddr and skip a per-datagram route lookup.
		if (connect(fd, reinterpret_cast<sockaddr*>(&dest), sizeof(dest)) != 0)
		{
			close(fd);
			return false;
		}
		s.sock = fd;
#endif

		s.configured = true;
		return true;
	}

	bool isConfigured()
	{
		SyslogState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);
		return s.configured;
	}

	std::string configuredHost()
	{
		SyslogState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);
		if (!s.configured) return std::string();
		// Rebuilt from the stored octets rather than kept as a second copy of the
		// string: one source of truth, and configure() has already validated it.
		char buf[16];
		std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
		              (unsigned)s.addr[0], (unsigned)s.addr[1],
		              (unsigned)s.addr[2], (unsigned)s.addr[3]);
		return std::string(buf);
	}

	uint16_t configuredPort()
	{
		SyslogState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);
		return s.port;
	}

	void loadFromNvs()
	{
#if SYSLOG_HAS_UDP
		nvs_handle_t h;
		if (nvs_open(kNvsNamespace, NVS_READONLY, &h) != ESP_OK)
		{
			// No namespace yet (a unit that has never had any PBX config written)
			// is the normal case, not an error: the sink stays disabled.
			return;
		}

		// 32 bytes, not 16: a dotted quad needs 16, and the slack means a value
		// with junk in it fails in parseIpv4() — a specific, inspectable reason —
		// rather than as an opaque ESP_ERR_NVS_INVALID_LENGTH from nvs_get_str().
		char hostBuf[32] = {0};
		size_t hostLen = sizeof(hostBuf);
		const esp_err_t hostErr = nvs_get_str(h, "syslog_host", hostBuf, &hostLen);

		uint32_t port = kDefaultPort;
		nvs_get_u32(h, "syslog_port", &port);   // absent key just leaves the default
		nvs_close(h);

		if (hostErr == ESP_OK && hostBuf[0] != '\0' && port > 0 && port <= 0xFFFF)
		{
			configure(hostBuf, static_cast<uint16_t>(port));
		}
#endif
		// Host builds have no NVS; tests call configure() directly.
	}

	bool saveToNvs(const std::string& host, uint16_t port)
	{
#if SYSLOG_HAS_UDP
		// Apply first. configure() is the one place that validates the host, so a
		// rejected address never reaches flash -- otherwise a typo would persist and
		// silently disable logging on every subsequent boot.
		if (!configure(host, port))
		{
			return false;
		}

		nvs_handle_t h;
		if (nvs_open(kNvsNamespace, NVS_READWRITE, &h) != ESP_OK)
		{
			return false;
		}

		esp_err_t err;
		if (host.empty())
		{
			// Disable: erase rather than store an empty string, so loadFromNvs()'s
			// 'absent key' path and the disabled state are the same thing.
			// ESP_ERR_NVS_NOT_FOUND is success here -- already absent is the goal.
			err = nvs_erase_key(h, \"syslog_host\");
			if (err == ESP_ERR_NVS_NOT_FOUND) err = ESP_OK;
			esp_err_t e2 = nvs_erase_key(h, \"syslog_port\");
			if (e2 == ESP_ERR_NVS_NOT_FOUND) e2 = ESP_OK;
			if (err == ESP_OK) err = e2;
		}
		else
		{
			err = nvs_set_str(h, \"syslog_host\", host.c_str());
			if (err == ESP_OK)
			{
				err = nvs_set_u32(h, \"syslog_port\", static_cast<uint32_t>(port));
			}
		}

		if (err == ESP_OK)
		{
			err = nvs_commit(h);
		}
		nvs_close(h);
		return err == ESP_OK;
#else
		// Host builds have no NVS. Apply to the live state so tests and the host
		// binary behave, but report honestly that nothing was persisted.
		(void)port;
		configure(host, port);
		return false;
#endif
	}

	void send(Severity severity, Facility facility, const char* appName, const char* msg)
	{
		SyslogState& s = state();
		std::lock_guard<std::mutex> lock(s.mutex);
		if (!s.configured)
		{
			return;
		}

		// STATIC, not a stack local, and not heap. Two reasons, both load-bearing.
		//
		// The engine invariant forbids heap in this path (CLAUDE.md invariant 1).
		// But a 480-byte stack frame is what kept this module unwired: its intended
		// producer is the LogQueue drain task, which runs on a 2048-byte stack and
		// already spends 256 of it on drainToUart()'s own line buffer -- adding 480
		// more on top of the lwip send() path was the reason the original syslog
		// commit shipped the formatter but hooked up nothing.
		//
		// Safe because every entry to this function already holds s.mutex (acquired
		// above), so there is exactly one writer at a time. The buffer costs 480
		// bytes of BSS once, instead of 480 bytes on whichever task happens to log.
		static char frame[kMaxFrameBytes];
		const size_t len = formatFrame(frame, sizeof(frame), severity, facility, appName, msg);
		if (len == 0)
		{
			return;
		}

#if SYSLOG_HAS_UDP
		// Fire-and-forget. One datagram on a connected UDP socket cannot block
		// waiting for a peer, and the result is deliberately unchecked: there is
		// nothing to do about a failure that would not cost the calling thread far
		// more than the lost line is worth — and logging it would re-enter this
		// function through the log drain (the RE-ENTRANCY RULE in Syslog.hpp).
		::send(s.sock, frame, len, 0);
#else
		// Off-device there is no socket by design (Syslog.hpp's layering note).
		// The frame was still built — that path is what tests/Syslog_test.cpp
		// asserts against, through formatFrame() directly.
#endif
	}

	void send(Severity severity, const char* appName, const char* msg)
	{
		send(severity, kDefaultFacility, appName, msg);
	}
}
