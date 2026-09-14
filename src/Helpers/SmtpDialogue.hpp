#ifndef SMTP_DIALOGUE_HPP
#define SMTP_DIALOGUE_HPP

// SmtpDialogue: pure, platform-neutral SMTP client protocol engine
// (RFC 5321 conversation, RFC 4954 AUTH, RFC 2045 base64 body encoding).
//
// Deliberately dependency-free beyond the C++17 standard library -- no
// sockets, no TLS, no ESP-IDF headers anywhere in this file or its .cpp.
// SmtpClient.hpp owns the real transport (esp_tls on-device, plain BSD/
// Winsock sockets on host) and drives this engine against it. The split
// mirrors RtpSender/TimeSync/SipDigest: the pure logic is host-unit-tested
// directly, and here specifically it is ALSO exercised against a REAL
// loopback socket talking to a fake SMTP server in SmtpDialogue_test.cpp,
// the same "drive the real thing over a real socket" pattern
// AdminHttpGate_test.cpp uses for HttpServer -- see SmtpClient.hpp's
// SmtpTransport, which is the one and only Transport implementation and
// compiles identically (plain-socket arm) on host and device.
//
// Base64 lives here rather than pulling in mbedtls/base64.h so the host
// build needs no external crypto/encoding dependency (mirrors SipDigest's
// vendored MD5) -- and GoogleServiceAuth.hpp reuses base64UrlEncode() for
// JWT segments rather than vendoring a second copy.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace SmtpDialogue
{
	enum class Mode : uint8_t
	{
		Plain,       // port 25 default, LAN relay only -- caller must opt in
		StartTls,    // port 587 default
		ImplicitTls, // port 465 default
	};

	enum class AuthMethod : uint8_t
	{
		None,
		Plain,
		Login,
		XOAuth2,
	};

	// Structured outcome, surfaced verbatim to the dashboard's "Send test
	// message" result and to `email test <addr>`.
	enum class ResultCode : uint8_t
	{
		Ok = 0,
		InvalidConfig,     // missing host/port/from/to before anything was sent
		ConnectFailed,      // transport connect (plain/implicit-TLS) failed
		TlsFailed,          // STARTTLS not advertised, refused, or handshake failed
		GreetingRejected,   // no 220 banner
		EhloRejected,
		AuthNotSupported,   // configured method not in the server's EHLO capabilities
		AuthRejected,       // 4xx/5xx anywhere in the AUTH exchange
		MailFromRejected,
		RcptToRejected,
		DataRejected,       // no 354 to DATA
		MessageRejected,    // no 250 after the terminating "."
		Timeout,
		TransportError,
	};

	struct SendResult
	{
		ResultCode code = ResultCode::TransportError;
		int smtpReplyCode = 0; // last numeric reply seen (0 = never got one)
		std::string lastError; // server text, or a local reason when there was no reply
		bool ok() const { return code == ResultCode::Ok; }
	};

	struct Config
	{
		std::string host;
		uint16_t port = 587;
		Mode mode = Mode::StartTls;
		AuthMethod auth = AuthMethod::None;
		std::string username;
		std::string password;    // AUTH PLAIN/LOGIN secret; unused for XOAuth2
		std::string accessToken; // AUTH XOAUTH2 bearer token -- SmtpDialogue never
		                          // talks OAuth itself; GoogleServiceAuth.hpp fetches
		                          // and caches this, the caller passes it in.
		std::string ehloName = "pocketdial";
		uint32_t commandTimeoutMs = 10000;
	};

	// Streams attachment bytes without ever holding the whole file in memory --
	// voicemail WAVs (a later consumer, not built by this issue) are read from
	// storage in ~3 KB chunks. Returns 0 for EOF; returns >0 for any successful
	// read, which may be shorter than maxLen even mid-stream.
	class AttachmentSource
	{
	public:
		virtual ~AttachmentSource() = default;
		virtual size_t read(uint8_t* buf, size_t maxLen) = 0;
	};

	struct Attachment
	{
		std::string filename;
		std::string contentType = "application/octet-stream";
		AttachmentSource* source = nullptr; // not owned
	};

	struct Message
	{
		std::string from;
		std::string to; // comma-separated; one RCPT TO per address
		std::string subject;
		std::string textBody;
		const Attachment* attachment = nullptr; // nullptr = text/plain only
		// Pre-formatted RFC 5322 Date header value (see formatRfc5322Date),
		// or "" to omit the header entirely. This engine has no clock of its
		// own (see the header-block comment in SmtpDialogue.cpp) -- the
		// caller (SmtpClient.cpp on-device, TimeSync-aware) fills this in,
		// or leaves it empty when unsynced/on host.
		std::string dateHeader;
	};

	// Everything the dialogue needs from the transport. SmtpClient.hpp's
	// SmtpTransport is the only implementation; kept as an interface purely so
	// this translation unit stays socket/TLS-free.
	class Transport
	{
	public:
		virtual ~Transport() = default;
		virtual bool writeAll(const char* data, size_t len) = 0;
		// Reads one CRLF-terminated line, CRLF stripped. false on timeout,
		// a closed connection, or any transport error.
		virtual bool readLine(std::string& line, uint32_t timeoutMs) = 0;
		// Upgrades an established plain connection to TLS in place (RFC 3207).
		// false if unsupported on this build (e.g. the host transport) or if
		// the handshake failed.
		virtual bool startTls(uint32_t timeoutMs) = 0;
	};

	// Drives the full conversation: greeting -> EHLO -> [STARTTLS -> EHLO
	// again] -> AUTH -> MAIL FROM -> RCPT TO (one per address in msg.to) ->
	// DATA -> headers + body [+ attachment] -> QUIT (best-effort). Returns as
	// soon as any step fails; QUIT is sent but its response is never the
	// reason for a non-Ok result.
	SendResult run(Transport& transport, const Config& cfg, const Message& msg);

	// --- Pieces exposed for direct unit testing --------------------------

	// Standard base64 (RFC 4648 §4, padded).
	std::string base64Encode(const uint8_t* data, size_t len);
	// base64url (RFC 4648 §5, unpadded) -- used by GoogleServiceAuth.hpp for
	// JWT header/payload/signature segments.
	std::string base64UrlEncode(const uint8_t* data, size_t len);

	// The capabilities this client cares about, parsed out of an EHLO
	// response's continuation lines (each already stripped of its "250-"/
	// "250 " reply-code prefix).
	struct EhloCapabilities
	{
		bool startTls = false;
		bool authPlain = false;
		bool authLogin = false;
		bool authXOAuth2 = false;
	};
	EhloCapabilities parseEhloCapabilities(const std::vector<std::string>& lines);

	// Splits a comma-separated address list, trimming surrounding whitespace
	// and dropping empty entries (so "a@x, , b@x" yields exactly two).
	std::vector<std::string> splitAddresses(const std::string& list);

	// RFC 5321 §4.5.2 dot-stuffing + bare-LF-to-CRLF normalization for one
	// message body. Does NOT append the terminating ".\r\n" -- that belongs to
	// the caller, once, after headers+body+attachment are all written.
	std::string dotStuffBody(const std::string& body);

	// RFC 5322 §3.3 Date header value (UTC, "Tue, 15 Nov 1994 12:45:26 +0000"),
	// or "" if `unixTime` is 0 (the TimeSync "never synced" sentinel) -- the
	// caller then omits the Date header entirely rather than emit a fabricated
	// 1970 timestamp; the receiving MTA fills one in, same reasoning as
	// TimeSync's own "-" NILVALUE for an unsynced syslog frame.
	std::string formatRfc5322Date(uint64_t unixTime);

	// Streams raw bytes into base64, one already-CRLF-terminated 76-char line
	// at a time (RFC 2045 §6.8), through `sink`. Holds at most 2 unencoded
	// carry bytes plus one partial output line between calls -- never the
	// whole attachment -- so callers can feed it arbitrarily-sized, even
	// non-multiple-of-3, read() chunks and still get correct padding, applied
	// only once, at finish(). `sink` returns false to abort (mirrors
	// Transport::writeAll's failure contract) and that propagates out of
	// feed()/finish() immediately.
	class ChunkedBase64Writer
	{
	public:
		using Sink = bool (*)(void* ctx, const char* data, size_t len);

		explicit ChunkedBase64Writer(Sink sink, void* ctx) : _sink(sink), _ctx(ctx) {}

		bool feed(const uint8_t* data, size_t len);
		bool finish();

	private:
		bool appendEncoded(const std::string& encoded);
		bool flushLine();

		Sink _sink;
		void* _ctx;
		std::vector<uint8_t> _carry;
		std::string _lineBuf;
	};

} // namespace SmtpDialogue

#endif
