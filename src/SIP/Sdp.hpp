#ifndef SDP_HPP
#define SDP_HPP

// RFC 8866 SDP model (issue #196).
//
// A flat, fixed-capacity, offset-based model of one SDP body: the session-level
// fields, every m= section (up to Limits::kMaxMedia), and per-section attribute
// scoping so a media-level c= or a= overrides the session-level one (RFC 8866
// §5.7, §5.13). It replaces the six-field line scanner that assumed exactly one
// m= line and ignored attributes entirely.
//
// Three properties are load-bearing and every change here must keep them:
//
//  1. FLAT AND BOUNDED. parse() is a single pass over the body, one line at a
//     time, never recursing and never re-dispatching on a token it has already
//     read. Work is bounded by SdpLimits::kMaxLines and the fixed capacities
//     below, never by attacker-chosen structure. This is the CWE-674 lesson from
//     the UNISOC T612 VoLTE RCE (an a=acap decoder that recursed per token) that
//     SipSdpMessage.hpp has carried since the six-field scanner; the model must
//     not reintroduce that surface just because it now reads a= lines.
//  2. OFFSETS, NOT VIEWS. Every Span is (pos, len) into the body the model was
//     parsed from. The message pool recycles SipMessage slots with `*msg =
//     source`, so anything cached as a string_view would dangle into another
//     message's body; offsets copy safely. Resolve a Span against the SAME body
//     with view(). A Span with len == 0 means "absent": every field is at least
//     two bytes long, so the sentinel is unambiguous.
//  3. NO HEAP. Session is a plain aggregate of fixed arrays sized by Limits. Over
//     capacity, extra entries are COUNTED in the dropped* fields and otherwise
//     ignored, never decoded. A Session is ~1.7 KB, which is too big for the 8 KB
//     sip_server_task stack and too big to cache per pooled message, so callers
//     keep one engine-owned scratch Session and parse on demand.

#include <cstddef>
#include <cstdint>
#include <string_view>

namespace sdp
{
	struct Limits
	{
		static constexpr unsigned kMaxMedia        = 3;   // m= sections modelled
		static constexpr unsigned kMaxSessionAttrs = 8;   // a= lines before the first m=
		static constexpr unsigned kMaxMediaAttrs   = 12;  // a= lines per m= section (all kinds)
		static constexpr unsigned kMaxRtpmaps      = 12;  // a=rtpmap entries per m= section
		static constexpr unsigned kMaxFormats      = 32;  // <fmt> tokens on one m= line (== SdpLimits::kMaxMediaFormats)
		// The writer answers with at most this many formats per m=: the board
		// terminates PCMU (and could add PCMA/G.722) plus one telephone-event PT.
		// Kept small on purpose -- a SessionSpec lives on the sip_server_task
		// stack (8 KB) while an answer is built.
		static constexpr unsigned kMaxWriteFormats = 6;
	};

	struct Span
	{
		uint32_t pos = 0;
		uint32_t len = 0;
		bool present() const { return len != 0; }
	};

	// Resolve a Span against the body it was parsed from. Out-of-range (a span
	// applied to the wrong body) yields an empty view rather than a throw.
	std::string_view view(std::string_view body, Span s);

	enum class Direction : uint8_t { None, SendRecv, SendOnly, RecvOnly, Inactive };
	enum class MediaType : uint8_t { Other, Audio, Video };

	struct Attribute
	{
		Span name;    // "sendonly" in a=sendonly; "rtpmap" in a=rtpmap:0 PCMU/8000
		Span value;   // absent for the property form (a=sendonly)
	};

	struct Rtpmap
	{
		uint8_t  pt = 0;
		uint32_t clock = 0;    // 0 if the line was malformed past the encoding name
		Span     encoding;     // "PCMU", "telephone-event" (no clock, no channels)
		Span     fmtp;         // value of the matching a=fmtp:<pt> line, absent if none
		bool     telephoneEvent = false;   // encoding is RFC 4733 telephone-event (case-insensitive)
	};

	struct Media
	{
		Span      line;          // the whole m= line, no terminator
		MediaType type = MediaType::Other;
		Span      typeName;      // "audio" / "video" / whatever was written
		uint32_t  port = 0;      // 0 == rejected/disabled stream (RFC 3264 §6, §8.2)
		uint16_t  portCount = 1; // the "/2" in "m=audio 49170/2 RTP/AVP 0"
		Span      proto;         // "RTP/AVP", "RTP/SAVP", ...
		uint8_t   fmt[Limits::kMaxFormats] = {};
		uint8_t   fmtCount = 0;
		Span      connection;    // media-level c=, absent if the session c= applies
		Attribute attrs[Limits::kMaxMediaAttrs] = {};
		uint8_t   attrCount = 0;
		Rtpmap    rtpmaps[Limits::kMaxRtpmaps] = {};
		uint8_t   rtpmapCount = 0;
		Direction dir = Direction::None;   // media-level a= only; see effectiveDirection()
		uint16_t  ptime = 0;               // a=ptime, 0 if absent
		uint8_t   droppedAttrs = 0;        // a= lines past kMaxMediaAttrs (counted, not decoded)
		uint8_t   droppedRtpmaps = 0;
		uint8_t   droppedFormats = 0;

		bool hasFormat(uint8_t pt) const;
		const Rtpmap* findRtpmap(uint8_t pt) const;
		// The dynamic payload type this section advertises for RFC 4733
		// telephone-event, or -1. Last one wins, matching the relay policy.
		int telephoneEventPt() const;
	};

	struct Session
	{
		Span      version, origin, name, connection, time;
		Attribute attrs[Limits::kMaxSessionAttrs] = {};
		uint8_t   attrCount = 0;
		Direction dir = Direction::None;   // session-level a= only
		Media     media[Limits::kMaxMedia] = {};
		uint8_t   mediaCount = 0;
		uint8_t   droppedAttrs = 0;
		uint8_t   droppedMedia = 0;        // m= sections past kMaxMedia (counted, not decoded)
		uint32_t  lines = 0;               // non-empty lines seen (capped at SdpLimits::kMaxLines)
		bool      truncated = false;       // the line cap stopped the scan early

		// Index of the first m=audio section, or -1.
		int firstAudio() const;
	};

	// Engine-owned scratch Sessions for on-demand parses. A Session is too large
	// for the 8 KB sip_server_task stack and too large to cache per pooled
	// message, so the two consumers that need a full model (SipSdpMessage's
	// accessor cache, SipMessage::getSdpDirection, RequestsHandler's answer
	// construction and answer validation) borrow one of these. Two slots so an
	// offer and an answer can be compared. NOT thread-safe by design: every
	// caller already runs under RequestsHandler::_mutex (the same contract
	// SipSdpMessage.hpp documents for its mutable cache); re-check that if an
	// SDP accessor is ever called from the HTTP/dashboard task or a media task.
	Session& scratch(unsigned slot = 0);

	// One flat pass over `body` into `out`, which is fully reset first: a field
	// present in the PREVIOUS body and absent from this one never survives (the
	// recycled-pool-slot case). Tolerates CRLF, bare LF and blank lines exactly as
	// the decoders it replaces did. Never throws, never allocates.
	void parse(std::string_view body, Session& out);

	// ── Scoped queries (RFC 8866 §5.7 / §5.13) ────────────────────────────────

	// Media-level direction if present, else the session-level one, else SendRecv
	// (RFC 8866 §6.7: sendrecv is the default when nothing is stated).
	Direction effectiveDirection(const Session& s, unsigned mediaIndex);

	// Media-level c= if present, else the session-level c=. Absent if neither.
	Span effectiveConnection(const Session& s, unsigned mediaIndex);

	struct ConnAddress
	{
		Span addr;          // "192.168.1.10" within the c= line; absent if unparsable
		bool isIp4 = false; // "IN IP4"
		bool isZero = false;// 0.0.0.0 (RFC 2543 §B.5 legacy hold, RFC 3264 §8.4 discourages it)
	};
	// Decode a c= line ("c=IN IP4 1.2.3.4[/ttl]") into its address. Flat, bounded.
	ConnAddress connectionAddress(std::string_view body, Span connectionLine);

	// RFC 3264 §8.4 hold semantics plus the RFC 2543 legacy form: the stream is
	// on hold when its effective direction is sendonly or inactive, OR its
	// effective connection address is 0.0.0.0.
	bool isHold(std::string_view body, const Session& s, unsigned mediaIndex);

	// ── Writer ────────────────────────────────────────────────────────────────
	// Builds a body into a caller-owned std::string (the one allocation, same as
	// the hand-assembled builders it replaces). CRLF throughout so the caller's
	// syncContentLength() matches the wire bytes.

	struct FormatSpec
	{
		uint8_t     pt = 0;
		const char* encoding = nullptr;   // "PCMU"; nullptr == emit no a=rtpmap (static PT)
		uint32_t    clock = 8000;
		const char* fmtp = nullptr;       // "0-15" for telephone-event; nullptr == none
	};

	struct MediaSpec
	{
		const char* type = "audio";
		uint32_t    port = 0;
		const char* proto = "RTP/AVP";
		FormatSpec  formats[Limits::kMaxWriteFormats] = {};
		uint8_t     formatCount = 0;
		Direction   dir = Direction::None;    // None == emit no direction line
		uint16_t    ptime = 0;                // 0 == none
		const char* connection = nullptr;     // media-level c= address, nullptr == none

		bool add(const FormatSpec& f);        // false when full (counted by caller if it cares)
	};

	struct SessionSpec
	{
		const char* originUser = "-";
		const char* originAddr = nullptr;     // o= and c= address (required)
		const char* name = "pocketdial-media";
		Direction   dir = Direction::None;    // session-level direction line, None == omit
		MediaSpec   media[Limits::kMaxMedia] = {};
		uint8_t     mediaCount = 0;

		MediaSpec* addMedia();                // nullptr when full
	};

	void write(const SessionSpec& spec, std::string& out);

	const char* directionText(Direction d);   // "sendrecv" etc; "" for None
}

#endif
