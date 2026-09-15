#ifndef SIP_SDP_MESSAGE_HPP
#define SIP_SDP_MESSAGE_HPP

#include <cstdint>

#include "SipMessage.hpp"

class SipSdpMessage : public SipMessage
{
public:
	SipSdpMessage(const std::string& message, sockaddr_in src);

	// The copy CONSTRUCTOR is safe defaulted: it takes both the body generation
	// and the cache generation from the same object, so a fresh cache stays
	// fresh and a stale one stays stale.
	SipSdpMessage(const SipSdpMessage& other) = default;

	// Copy ASSIGNMENT is not. The implicit one would bump THIS object's body
	// generation (via SipMessage::operator=) and then overwrite the cache
	// generation with the SOURCE's — mixing two objects' private timelines, which
	// is exactly what SipMessage::_bodyGen's contract forbids. Where the two
	// happen to collide, this object's stale spans would be read as current
	// against a body they were never parsed from. Assignment therefore drops the
	// cache rather than copying it.
	SipSdpMessage& operator=(const SipSdpMessage& other);

	// Issue #42: see SipMessage::hasSdp(). This concrete type always carries SDP.
	bool hasSdp() const override { return _hasSdp; }

	void setMedia(std::string value);

	std::string_view getVersion() const;
	std::string_view getOriginator() const;
	std::string_view getSessionName() const;
	std::string_view getConnectionInformation() const;
	std::string_view getTime() const;
	std::string_view getMedia() const;
	int getRtpPort() const;

private:
	// Issue #101(B): the six accessors above used to re-parse the whole SDP body
	// on every call — getRtpPort() alone walks it twice (once for m=, once to cut
	// the port out), and call setup touches several of them per INVITE. They now
	// share one single-pass parse, cached until the body changes.
	//
	// The cache stores (offset, length) spans into the base class's body, NOT
	// string_views. That is the whole trick, and it is deliberate: SipMessage is
	// copyable by design and the message pool recycles slots with `*msg = source`
	// (RequestsHandler.cpp), so a cached string_view would be copied verbatim and
	// left pointing into the SOURCE message's body — dangling the moment that
	// message is itself recycled. Offsets are position-independent, so the
	// defaulted copy stays correct and SipMessage.hpp's "no string_view to fix up
	// after a copy" property survives intact.
	//
	// len == 0 means "field absent": every line we match starts with a two-char
	// prefix, so a matched span is never shorter than 2 and the sentinel is
	// unambiguous. Absent fields return an empty view, exactly as before.

	// CWE-674 defense-in-depth. The UNISOC T612 VoLTE RCE (SSD advisory, 2026)
	// was uncontrolled recursion in an SDP a=acap decoder: a body of repeated
	// `acap:1 acap:1 ...` drove the parser to recurse per token until the modem
	// stack overflowed into a neighbouring task and became code execution. This
	// parser is structurally immune. Since issue #196 it is sdp::parse() (Sdp.hpp):
	// still a flat, non-recursive line scan, now reading a= lines into fixed-
	// capacity tables with counted overflow and no re-dispatch on tokens -- and
	// on the wire path SipMessage::checkSdp() has already refused any body over
	// SdpLimits before an accessor here can run. The same SdpLimits::kMaxLines
	// cap is applied by sdp::parse() itself, so the "SDP parse work is bounded,
	// never a function of attacker-chosen structure" invariant holds for a body
	// that reached this class by any other route (a locally built or
	// test-constructed message). See SipSdpMessage_hardening_test.cpp and
	// Sdp_test.cpp.

	struct FieldSpan
	{
		uint32_t pos = 0;
		uint32_t len = 0;
	};
	// Issue #196: the spans are now DERIVED from the sdp:: model (Sdp.hpp) rather
	// than from a private six-field scan, so the accessors inherit its RFC 8866
	// semantics: `media` is the FIRST AUDIO m= section (not the first m= of any
	// type, and not the last one -- a second audio m= is a second stream, not a
	// replacement), `connectionInformation` is the c= that EFFECTIVELY applies to
	// that section (its own media-level c= when present, else the session's), and
	// `rtpPort` is that section's port. The offsets-not-views rule is unchanged.
	struct SdpSpans
	{
		FieldSpan version, originator, sessionName, connectionInformation, time, media;
		int rtpPort = 0;
	};

	// mutable: the accessors are const and observably still pure — a re-parse is
	// invisible to the caller. Note this does make the const accessors WRITE, so
	// unlike before they are not safe to call concurrently on one message.
	// Verified survivable: the only call sites outside this class are the two in
	// RequestsHandler::parseCallerRtp (getRtpPort / getConnectionInformation),
	// reached solely from onMediaInvite, which runs under RequestsHandler::_mutex
	// like every other handler. Re-check this if an SDP accessor is ever called
	// from the HTTP/dashboard task or a media task.
	mutable SdpSpans _spans{};
	// Generation of the body _spans was parsed from. 0 is never a live body
	// generation (SipMessage::_bodyGen starts at 1), so a fresh or freshly-copied
	// message re-parses on first access without needing a separate valid flag.
	mutable uint64_t _spansGen = 0;

	// Re-parses the body iff it has changed since the last parse.
	const SdpSpans& ensureParsed() const;
	std::string_view viewOf(const FieldSpan& span) const;

};

#endif
