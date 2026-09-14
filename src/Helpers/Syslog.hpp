#ifndef SYSLOG_HPP
#define SYSLOG_HPP

// Syslog — RFC 5424 syslog-over-UDP event sink (issue #183; ported from
// drawbridge's src/Helpers/Syslog.{hpp,cpp}, its issue #129).
//
// Why this exists: the device logs to UART and keeps a bounded CDR ring
// (src/SIP/CdrRing.cpp), and both die with the board — a reboot, a power cut or
// simply nobody having a serial cable attached loses the record. A syslog sink
// puts call / registration events into whatever aggregator the site already
// runs, which is the only way an operator ever sees yesterday's events. It is
// purely ADDITIVE: the sink stays unconfigured (and send() a no-op) until a
// destination is set, so a unit that never turns it on behaves exactly as before.
//
// ── Layering / portability (the convention src/SIP/RtpReceiver.hpp:21-27 sets)
//   * The frame FORMATTER (formatFrame) is pure, platform-independent and
//     host-unit-tested — see tests/Syslog_test.cpp. Every RFC 5424 rule lives
//     there, so the rules are checkable without a socket, a network, or a board.
//   * The UDP socket is ESP-ONLY, behind
//     `#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)`.
//     Off-device, configure() still validates and accepts a destination and
//     send() still formats, but nothing is emitted — the same "accepted, but
//     non-emitting stub" shape RtpReceiver::start() documents at
//     RtpReceiver.hpp:194-195.
//     Deliberately NOT drawbridge's arrangement (it opens a real socket on the
//     host too and its tests bind a fixed loopback port, 15514): the pure
//     formatter is the better seam — it can assert the exact bytes without a
//     listener — and a fixed port makes the host suite collide with itself when
//     two runs overlap, which this repo has already been bitten by.
//
// ── FRAME LAYOUT (RFC 5424 §6) ───────────────────────────────────────────────
// The full grammar is
//     HEADER = PRI VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID
//     SYSLOG-MSG = HEADER SP STRUCTURED-DATA [SP MSG]
// so there are SEVEN space-separated header tokens before MSG. What this module
// puts on the wire is:
//
//     <134>1 - - pbx-call - - - caller=310 callee=210 result=answered
//     ╰──┬─╯ ╰┬╯ │ │ ╰───┬──╯ │ │ │ ╰──────────────┬──────────────────╯
//        │    │  │ │     │    │ │ │                └ MSG        (§6.4, free text)
//        │    │  │ │     │    │ │ └ STRUCTURED-DATA (§6.3, NILVALUE — no SD-ELEMENTs)
//        │    │  │ │     │    │ └── MSGID           (§6.2.7, NILVALUE)
//        │    │  │ │     │    └──── PROCID          (§6.2.6, NILVALUE)
//        │    │  │ │     └───────── APP-NAME        (§6.2.5, the caller's `appName`)
//        │    │  │ └─────────────── HOSTNAME        (§6.2.4, NILVALUE — see below)
//        │    │  └───────────────── TIMESTAMP       (§6.2.3, NILVALUE — see below)
//        │    └──────────────────── VERSION = 1     (§6.2.2, always)
//        └───────────────────────── PRI = facility*8 + severity, in <> (§6.2.1)
//
// COUNT THE DASHES: two before APP-NAME, THREE after. drawbridge's format string
// (`"<%d>1 - - drawbridge %s - - %s"`, Syslog.cpp:146) has only two after, so the
// product name occupies APP-NAME and the caller's "pbx-call" / "pbx-register"
// lands in PROCID — structurally a valid frame, semantically the wrong fields,
// and its own header comment (Syslog.hpp:44-48) claims five NILVALUEs where the
// wire carries four. That is the one thing this port deliberately does NOT copy.
//
// ── TIMESTAMP is NILVALUE, and that is not laziness ──────────────────────────
// RFC 5424 §6.2.3 requires an RFC 3339 timestamp *or* the NILVALUE "-", and
// §6.2.3 is explicit that a NILVALUE is what an originator emits when it has no
// reliable clock. THIS DEVICE HAS NO WALL CLOCK: nothing in the tree ever
// initialises an SNTP client — the only SNTP call anywhere is
// `esp_sntp_restart()` at src/SIP/DtmfFeatureCodes.cpp:123, which restarts a
// client that was never started with esp_sntp_setoperatingmode/setservername/
// init, so it is a no-op on a fresh boot. (Standing SNTP work is issue #194's
// prerequisites section.) The alternatives were both worse: emitting a
// 1970-01-01 stamp from an unset clock is a LIE the collector cannot detect,
// and emitting uptime is not RFC 3339 at all. With NILVALUE the collector falls
// back to its own receive time, which is the honest ordering for a device on the
// same LAN. When SNTP lands, add a timestamp-taking overload of formatFrame()
// (and only then) — the field position is already correct here.
//
// HOSTNAME is NILVALUE for the same kind of reason: §6.2.4 gives a fallback
// ladder (FQDN > static IP > hostname > dynamic IP > NILVALUE) and this board
// has no FQDN and a DHCP address that the collector already sees as the
// datagram's source address, so the bottom of the ladder is the truthful rung.
// PROCID (§6.2.6) has nothing to name on a single-image RTOS firmware, and
// MSGID (§6.2.7) is left free for a future event-class taxonomy.
//
// ── Hot-path contract ────────────────────────────────────────────────────────
// send() formats into a fixed stack buffer and does ONE fire-and-forget UDP
// send() on a persistent, pre-connected socket: no heap (CLAUDE.md invariant 1),
// no retry, no queue, no TCP/TLS, and the result is not checked — a dropped
// syslog line must never cost the calling thread, which may be a real-time task
// or the log-drain task. Reliable delivery is the aggregator's problem.
// `host` must be a NUMERIC IPv4 address: no DNS, so no blocking resolver call
// and no dependency beyond the socket itself.
//
// RE-ENTRANCY RULE: nothing in this file may call ESP_LOGx (or printf to the
// log). The intended producer is the LogQueue drain task (LogQueue.hpp), so a
// line logged from inside send() is enqueued, drained, and handed straight back
// to send() — and when the thing being logged IS a send failure, that closes a
// self-feeding loop: one failure becomes a line, which becomes another failure,
// which becomes another line. It would not deadlock (the enqueue hook returns
// immediately and the state mutex is long released by the time the drain task
// comes back round); it does something quieter and worse — fills the 16-deep
// log queue (LogQueue.hpp:46) with its own noise, so the real log lines the
// operator needs are the ones dropped. Failures here are silent by design.

#include <cstddef>
#include <cstdint>
#include <string>

namespace Syslog
{
	// RFC 5424 §6.2.1 severity codes, the full 0-7 ladder. The whole range is
	// present (unlike drawbridge's Error/Warning/Info subset) because the natural
	// producer here is the ESP log drain, whose lines carry D/V levels too.
	enum class Severity : int
	{
		Emergency = 0,
		Alert     = 1,
		Critical  = 2,
		Error     = 3,
		Warning   = 4,
		Notice    = 5,
		Info      = 6,
		Debug     = 7,
	};

	// RFC 5424 §6.2.1 facility codes. Only the ones a device like this can
	// honestly claim: the numbered local0-7 range reserved for local use, plus
	// user-level and daemon. 16-23 is what every collector expects from an
	// appliance, and local0 is the conventional default.
	enum class Facility : int
	{
		User   = 1,
		Daemon = 3,
		Local0 = 16,
		Local1 = 17,
		Local2 = 18,
		Local3 = 19,
		Local4 = 20,
		Local5 = 21,
		Local6 = 22,
		Local7 = 23,
	};

	// The facility every send() overload without an explicit one uses.
	constexpr Facility kDefaultFacility = Facility::Local0;

	// IANA-assigned syslog UDP port (RFC 5426 §3.1).
	constexpr uint16_t kDefaultPort = 514;

	// RFC 5424 §6.2.5: APP-NAME is 1-48 PRINTUSASCII characters.
	constexpr size_t kMaxAppNameBytes = 48;

	// Frame cap. RFC 5426 §3.2: a syslog receiver MUST be able to take a 480-byte
	// datagram over IPv4 (that is the guaranteed-unfragmented minimum), and only
	// SHOULD handle more. Staying at 480 means one datagram, one IP packet, no
	// reassembly on a board whose lwIP pools are small — and it is comfortably
	// above LogQueue's 256-byte line (LogQueue.hpp:45) plus this 65-byte header.
	constexpr size_t kMaxFrameBytes = 480;

	// PRI = facility * 8 + severity (RFC 5424 §6.2.1). constexpr so a call site
	// can static_assert an expected value.
	constexpr int priValue(Facility facility, Severity severity)
	{
		return static_cast<int>(facility) * 8 + static_cast<int>(severity);
	}

	// ── The pure formatter (this is the whole RFC surface, and it is testable) ──

	// Format one complete RFC 5424 frame into `out`. Returns the number of bytes
	// to put on the wire, NOT counting the NUL that is always written when
	// cap > 0. Pure: no state, no clock, no socket, no allocation.
	//
	// `appName` is sanitized to §6.2.5's charset (see the .cpp) and is emitted as
	// the NILVALUE "-" when null or empty. `msg` may be null/empty, in which case
	// the frame legally ends after STRUCTURED-DATA with no trailing space; a
	// trailing CR/LF/space on `msg` is trimmed (one datagram is one message, and
	// a trailing newline upsets line-oriented collectors).
	//
	// Truncation: the header is bounded at 65 bytes ("<191>1" + six single-byte
	// fields + a 48-byte APP-NAME + seven separators), so for any realistic `cap`
	// only the tail of MSG is ever lost and the frame stays parseable.
	// `timestamp` is an RFC 3339 string, or nullptr/"" for RFC 5424's NILVALUE.
	// Passed in rather than read from a clock so this stays pure and testable;
	// send() supplies timesync::rfc3339Now(), which itself returns "-" while
	// the clock is unsynced.
	size_t formatFrame(char* out, size_t cap, Severity severity, Facility facility,
	                   const char* appName, const char* msg,
	                   const char* timestamp = "-");

	// The same frame as a std::string — the form tests and any non-hot-path
	// caller should use. Allocates, so send() uses the buffer form above.
	std::string formatFrame(Severity severity, Facility facility,
	                        const char* appName, const char* msg,
	                        const char* timestamp = "-");

	// ── Sink lifecycle ──────────────────────────────────────────────────────────

	// (Re)point the sink at host:port. An EMPTY host disables the sink
	// (isConfigured() becomes false, send() a no-op) and closes any open socket;
	// that counts as success and returns true. Returns false — leaving the sink
	// disabled — if `host` is not a plain dotted-quad IPv4 literal or the socket
	// could not be created. Safe to call repeatedly; each call replaces the
	// previous destination.
	bool configure(const std::string& host, uint16_t port = kDefaultPort);

	// True when a destination has been accepted. Off-device this can be true with
	// nothing actually being emitted (see the layering note at the top).
	bool isConfigured();

	// What the board believes it is pointed at. Not a secret -- a collector
	// address is infrastructure, not a credential -- and an operator debugging
	// "why am I getting no logs" needs to see it. Empty host when unconfigured.
	std::string configuredHost();
	uint16_t    configuredPort();

	// Read the destination from NVS at boot: namespace "pbxcfg", key
	// "syslog_host" (a dotted-quad string) and optional "syslog_port" (u32,
	// default 514). Absent/empty host leaves the sink disabled, which is exactly
	// how a unit that never had the feature turned on behaves. No-op off-device
	// (no NVS there — tests call configure() directly).
	void loadFromNvs();

	// Persist host/port to NVS and apply them immediately. The counterpart to
	// loadFromNvs(): without this, the keys loadFromNvs() reads had no writer
	// anywhere in the firmware, so remote logging could not be turned on at all.
	// An empty host clears the keys and disables the sink.
	// Returns false if the host is non-empty and not a valid dotted-quad, or if
	// NVS refuses the write -- callers surface that rather than silently no-op.
	bool saveToNvs(const std::string& host, uint16_t port);

	// Emit one frame. No-op when unconfigured. Never blocks, never throws, never
	// logs (see the RE-ENTRANCY RULE above). `appName` is the event class the
	// collector filters on ("pbx-call", "pbx-register", "pbx-log"); `msg` is free
	// text, conventionally space-separated key=value pairs.
	void send(Severity severity, Facility facility, const char* appName, const char* msg);

	// Same, at kDefaultFacility.
	void send(Severity severity, const char* appName, const char* msg);

	// std::string convenience for call sites that already hold strings (the SIP
	// engine's event paths do). Forwards to the const char* form — nothing is
	// copied.
	inline void send(Severity severity, const std::string& appName, const std::string& msg)
	{
		send(severity, appName.c_str(), msg.c_str());
	}
}

#endif // SYSLOG_HPP
