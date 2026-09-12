#ifndef SIP_MESSAGE_HPP
#define SIP_MESSAGE_HPP

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include <lwip/sockets.h>
#undef INADDR_NONE
#elif defined(__linux__)
#include <netinet/in.h>
#elif defined _WIN32 || defined _WIN64
#include <WinSock2.h>
#endif

#include <iostream>
#include <string>
#include <string_view>
#include <stdexcept>
#include <optional>
#include <vector>
#include <cstdint>

#include "SipStatus.hpp"

// ── SDP structural limits ───────────────────────────────────────────────────
// Hard caps SipMessage::checkSdp() enforces on every SDP body BEFORE any decoder
// runs (RequestsHandler::handle() applies it to the wire path ahead of dispatch).
// The design rule they pin (docs/THREAT_MODEL.md T-7): SDP's a= extension
// grammar looks like a line-oriented key/value format and is really a nested
// dispatcher; on an RTOS a parser whose work is a function of attacker-chosen
// structure is a stack-exhaustion primitive (the UNISOC T612 VoLTE RCE, CWE-674,
// was exactly that -- an a=acap decoder recursing once per token). So: line
// length, line count, tokens per line and media formats are capped up front, a
// violation is a hard error for the WHOLE body (488 on a request, drop on a
// response) rather than "keep tokenizing", and the RFC 5939 capability-
// negotiation family is rejected outright because this PBX does not implement
// it and must not relay it to a phone that might.
//
// Sizing: a codec-rich softphone offer with ICE/DTLS attributes is ~40 lines of
// <200 bytes; the longest legitimate lines (H.264 fmtp, ICE candidates) stay
// under 300 bytes and 16 tokens; hardphones offer well under 16 payload types.
// Inbound SIP is UDP-capped at 2048 bytes today (UdpServer::BUFFER_SIZE), so
// kMaxBodyBytes only matters for a future TCP/large-MTU transport.
namespace SdpLimits
{
	constexpr size_t   kMaxBodyBytes     = 4096;
	constexpr unsigned kMaxLines         = 256;
	constexpr size_t   kMaxLineBytes     = 512;
	constexpr unsigned kMaxTokensPerLine = 40;   // SP-separated runs on one line
	constexpr unsigned kMaxMediaFormats  = 32;   // <fmt> tokens on one m= line
	constexpr size_t   kMaxAttrNameBytes = 32;   // a=<name>[:value]
}

class SipMessage
{
public:

	SipMessage(const std::string& message, sockaddr_in src);
	virtual ~SipMessage() = default;

	// Issue #81: takes a view, not an owned string — the pool-recycle path
	// (RequestsHandler::getMessageFromPool) hands this a view straight into
	// UdpServer::receiveLoop()'s stack buffer with no copy in between.
	// splitMessage() below copies what it needs (substr into owned _startLine /
	// _headerLines / _body) synchronously before this returns, so nothing here
	// retains the view past the call.
	void reset(std::string_view message, sockaddr_in src);

	// No shared buffer means no string_view to fix up after a copy — plain
	// member-wise copy of the owned start line / header lines / body is already
	// correct.
	SipMessage(const SipMessage& other) = default;
	// NOT `= default`, for one reason: _bodyGen must advance rather than be
	// adopted from `other`. See the comment on _bodyGen — assigning a different
	// message over this one replaces the body, and a derived class's body cache
	// has to be able to notice that. Defaulting this operator broke exactly that
	// (see tests/SipSdpMessage_cache_test.cpp, the pool-style base-subobject
	// assignment case).
	SipMessage& operator=(const SipMessage& other);

	// setType() removed (audit #68): dead, and conflated a header-relative offset
	// with a replace() length. Use setHeader() to rewrite the full start line.
	void setHeader(std::string value);
	void setVia(std::string value);
	void setFrom(std::string value);
	void setTo(std::string value);
	void setCallID(std::string value);
	void setCSeq(std::string value);
	void setContact(std::string value);
	void setContentLength(std::string value);
	void addHeader(const std::string& name, const std::string& value);
	// Pins the SDP payload list to "0 8 101".
	//
	// DEPRECATED, and as of ISSUES.md #139 called from NO production path -- only
	// from tests that use it as a convenient body mutation. Do not reintroduce it:
	// "0 8 101" asserts payload type 101 with no matching a=rtpmap, which RFC 4566
	// §6 forbids for a dynamic PT, and pjsip answers such a body with 400 Bad SDP.
	// On an ANSWER it is doubly wrong -- RFC 3264 §6.1 requires the offer's own
	// payload numbering. Use filterAudioCodecs() for a relayed or echoed body, and
	// for a body the server BUILDS just emit the right m= line (buildMediaSdp() and
	// sipwire::makeInactiveHoldSdp() already do).
	void enforceG711();
	// Codec policy for a RELAYED offer/answer (peer-to-peer legs): keep the
	// endpoint's own payload list and ORDER, dropping only what this PBX
	// won't carry -- anything but PCMU/PCMA (+ G.722 when allowWideband) and
	// telephone-event -- together with the matching a=rtpmap/a=fmtp lines.
	// The offerer's preference order is therefore honoured end to end and a
	// G.722-capable pair negotiates wideband on their own. Returns false and
	// leaves the body untouched when no audio codec would survive (the
	// caller should answer 488 rather than advertise payloads the phone never
	// offered -- the old "signalling completes, media is dead" failure).
	bool filterAudioCodecs(bool allowWideband);
	// The same policy as a query: does this SDP offer at least one audio codec
	// we would keep? True when there is no m=audio line at all.
	bool offersSupportedAudio(bool allowWideband) const;

	// ── SDP admission ───────────────────────────────────────────────────────
	// One flat pass over the body applying SdpLimits and the attribute policy.
	// Never allocates, never recurses, never dispatches on attribute content:
	// the only per-attribute work is a bounded name compare. Ok means "safe to
	// hand to the decoders below and to relay"; anything else is a hard error
	// for the whole body. Run this before offersSupportedAudio(),
	// filterAudioCodecs(), getSdpDirection() or SipSdpMessage's accessors on
	// any body that came off the wire -- handle() already does, once, for
	// every SDP-bearing message regardless of method or status.
	enum class SdpVerdict : uint8_t
	{
		Ok = 0,
		BodyTooLarge,            // > SdpLimits::kMaxBodyBytes
		TooManyLines,            // > SdpLimits::kMaxLines
		LineTooLong,             // > SdpLimits::kMaxLineBytes
		MalformedLine,           // not "<type>=<value>" (RFC 4566 §5)
		TooManyTokens,           // > SdpLimits::kMaxTokensPerLine on one line
		TooManyMediaFormats,     // > SdpLimits::kMaxMediaFormats on one m= line
		BadAttributeName,        // a= name empty, over-long or not a token
		CapabilityNegotiation,   // RFC 5939 / 6871 / 7104 attribute: not implemented
	};
	SdpVerdict checkSdp() const;
	static const char* sdpVerdictText(SdpVerdict v);   // short reason for a Warning header / log
	void clearBody();

	// The message body — everything after the header/body separator (the SDP for
	// an INVITE/200 OK), or empty when there is none. The view is valid until the
	// next mutation of this message. setBody() replaces the body and resyncs
	// Content-Length; used by the call-park retrieve path to swap each leg's SDP
	// onto the opposite dialog so media renegotiates peer-to-peer.
	std::string_view getBody() const;
	void setBody(const std::string& body);

	// Recompute the Content-Length header from the actual body byte count and
	// rewrite it in place (preserving the full/compact header-name form). Call
	// after any edit that changes the body length; an out-of-sync Content-Length
	// causes UDP peers to discard the message as truncated/malformed.
	void syncContentLength();


	std::string_view getType() const;
	std::string_view getHeader() const;
	std::string_view getVia() const;
	std::string_view getFrom() const;
	std::string_view getFromNumber() const;
	std::string_view getTo() const;
	std::string_view getToNumber() const;
	std::string_view getCallID() const;
	std::string_view getCSeq() const;
	std::string_view getViaBranch() const;   // branch= param extracted from Via header
	std::string_view getCSeqMethod() const;  // method token extracted from CSeq header
	// RFC 4028 session timer headers (0 / empty when header absent).
	uint32_t         getSessionExpiresSecs() const;
	std::string_view getSessionExpiresRefresher() const; // "uac", "uas", or empty
	uint32_t         getMinSESecs() const;
	std::string_view getContact() const;
	std::string_view getContactNumber() const;
	std::string_view getContentLength() const;
	// Full `Authorization:` request-header line (or empty if absent). The value
	// is fed to SipDigest::parseAuthorization, which tolerates the header name.
	std::string_view getAuthorization() const;
	// Full `Event:` header line (RFC 6665), compact form `o:`. Empty when absent.
	// The subscription machinery wants the package name only — strip the header
	// name with siphdr::stripHeaderName and cut at the first ';' parameter.
	std::string_view getEvent() const;
	sockaddr_in getSource() const;
	std::optional<PocketDial::SipStatusInfo> getStatusInfo() const
	{
		return PocketDial::parseSipStatusLine(_startLine);
	}

	// SDP media-direction attribute (RFC 4566 / RFC 3264): the line-anchored
	// a=sendrecv / a=sendonly / a=recvonly / a=inactive attribute in the message
	// body. Returns None when there is no body or no direction attribute (RFC
	// 3264: an absent attribute implies sendrecv — the caller decides; we only
	// report what is on the wire). Pure string scan, host-compilable.
	enum class SdpDirection { None, SendRecv, SendOnly, RecvOnly, Inactive };
	SdpDirection getSdpDirection() const;

	// Issue #42: virtual SDP probe replaces dynamic_cast so call setup works
	// on the Arduino ESP32 toolchain, which builds with RTTI disabled (-fno-rtti).
	virtual bool hasSdp() const { return _hasSdp; }

	std::string toString() const;
	// Same serialization into a caller-owned buffer, so a per-packet caller can
	// reuse one allocation instead of a fresh temporary each time (Issue #101(D)).
	// `out` is cleared first, retaining its capacity.
	void toString(std::string& out) const;
	bool isValidMessage() const;

protected:
	std::string_view extractNumber(std::string_view header) const;

	// Issue #101(B): monotonic counter bumped by every mutation of _body, so a
	// derived class can cache a parse of the body and know when it went stale
	// WITHOUT this class having to know that any such cache exists. Messages are
	// pooled and recycled (reset() on a slot handed back out), so "the body I
	// parsed" and "the body this object holds now" can differ across calls that
	// look identical from the outside — the counter is what makes that visible.
	// Deliberately not a dirty *flag*: a flag would have to be cleared by the
	// cache owner, which puts the base class and every derived cache in a
	// two-way handshake. A number only ever goes up, so a stale reader can only
	// ever conclude "re-parse", never "still fresh".
	//
	// Starts at 1, never 0: a cache initialized to generation 0 is therefore
	// stale on first use without needing a separate valid/empty flag.
	//
	// Not atomic, and not internally synchronized: like the rest of SipMessage,
	// a given message is only ever touched under RequestsHandler::_mutex.
	uint64_t bodyGeneration() const { return _bodyGen; }

	bool _hasSdp = false;

private:
	// Every getter/setter below resolves against these three owned pieces —
	// no shared buffer, so mutating one header cannot shift or invalidate any
	// other. There is deliberately no cached "parsed field" state left to keep
	// in sync: named getters look their header up by name on every call (a
	// handful of short string compares against _headerLines, not a rescan of
	// the whole message), so nothing needs a reparse step after a mutation.
	//
	// The body is the one exception, and it is a derived-class concern: an SDP
	// body IS worth parsing once (SipSdpMessage, Issue #101(B)). This class does
	// not hold that cache — it only publishes _bodyGen via bodyGeneration() so
	// the cache's owner can tell when its parse went stale.
	std::string              _startLine;
	std::vector<std::string> _headerLines;
	std::string              _body;
	// Bumped by every _body mutation — see bodyGeneration().
	//
	// This value is meaningful only WITHIN one object: it is that object's
	// private, monotonically-increasing body timeline, never a global version.
	// Two different messages sharing the value 7 means nothing.
	//
	// Which is why operator= bumps it instead of copying it. The pool assigns
	// through a base reference (`*msg = source` on a shared_ptr<SipMessage>,
	// RequestsHandler.cpp), so ONLY this subobject is assigned and a derived
	// cache is left untouched — if the destination also adopted the source's
	// generation, the two could coincide and the stale cache would look fresh.
	// Bumping keeps the invariant local and airtight: a cache's recorded
	// generation only ever holds a value from ITS OWN object's timeline, so
	// "recorded == current" can only mean "parsed from exactly these bytes".
	//
	// The copy CONSTRUCTOR does copy it, which is correct — there is no
	// pre-existing cache in a brand-new object to go stale, and the copied body
	// and copied cache describe the same bytes.
	// 64-bit, not 32: it only ever increments, and a pooled slot on a
	// long-lived device bumps it several times per handled message. A 32-bit
	// counter would eventually wrap onto a value a derived cache had already
	// recorded — reviving a stale SDP parse against a different call's body, the
	// exact hazard this exists to prevent — or onto 0, the fresh-cache sentinel.
	// At even 10k bumps/second a 64-bit counter outlives the hardware.
	uint64_t                 _bodyGen = 1;

	sockaddr_in _src{};

	size_t findHeaderIndex(std::string_view fullName, std::string_view compactName = {}) const;
	// Inserts a new header line just before Content-Length (matching the wire
	// position addHeader() has always used), or at the end of the header block
	// if there is no Content-Length header.
	void insertHeaderLine(std::string value);
	// Shared body for the six setters that only ever replace-or-insert a single
	// named header line (setVia/setFrom/setTo/setCallID/setCSeq/setContact).
	void setNamedHeader(std::string_view fullName, std::string_view compactName, std::string value);
};

#endif
