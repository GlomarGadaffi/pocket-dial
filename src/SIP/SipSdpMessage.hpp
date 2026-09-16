#ifndef SIP_SDP_MESSAGE_HPP
#define SIP_SDP_MESSAGE_HPP

#include <cstdint>

#include "Sdp.hpp"
#include "SipMessage.hpp"

class SipSdpMessage : public SipMessage
{
public:
	SipSdpMessage(const std::string& message, sockaddr_in src);

	// The copy CONSTRUCTOR is safe defaulted: it takes both the body generation
	// and the cache generation from the same object, so a fresh cache stays
	// fresh and a stale one stays stale. It also copies `_slot`, which is only a
	// HINT — ensureParsed() re-checks that the hinted scratch slot is actually
	// owned by `this`, and a copy never owns the source's slot, so the copy
	// re-parses on first access. See the ownership check in ensureParsed().
	SipSdpMessage(const SipSdpMessage& other) = default;

	// Copy ASSIGNMENT is not. The implicit one would bump THIS object's body
	// generation (via SipMessage::operator=) and then overwrite the cache
	// generation with the SOURCE's — mixing two objects' private timelines, which
	// is exactly what SipMessage::_bodyGen's contract forbids. Where the two
	// happen to collide, this object's stale model would be read as current
	// against a body it was never parsed from. Assignment therefore drops the
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

	// ── Explicit section selection (#253) ──────────────────────────────────
	//
	// getMedia()/getRtpPort()/getConnectionInformation() above answer an
	// implicit question ("which section?") two different, disagreeing ways
	// on a multi-section body -- see their own comments. These do not answer
	// it either; they let the CALLER name the section, which is the actual
	// fix #253 asks for. No current offer this PBX handles has more than one
	// m= section, so this is unreachable-in-practice safety, not a live bug
	// fix -- see the issue for why.

	// Index of the first "audio" m= section, or -1 if the offer has none.
	int firstAudioSection() const;

	// Section-aware counterparts to getRtpPort()/getConnectionInformation().
	// `section` is meant to come from firstAudioSection() or similar -- an
	// out-of-range index returns 0 / an empty view rather than asserting,
	// since nothing here can stop a caller racing a re-offer between an
	// index lookup and the read.
	int getRtpPort(int section) const;
	std::string_view getConnectionInformation(int section) const;

private:
	// ── Where the parsed model lives, and why it is not in here ───────────────
	//
	// Issue #196 replaced the six-FieldSpan cache with a full RFC 8866 model
	// (sdp::Session). The model is NOT a member of this class, and that is a RAM
	// decision rather than a style one:
	//
	//   SipMessagePool constructs ALL POCKETDIAL_MSG_POOL slots as SipSdpMessage,
	//   and the heap-fallback path does too. sizeof(sdp::Session) measures 3300
	//   bytes, so an in-object model would cost 52 x 3300 = ~168 KB on an
	//   ESP32-S3. (The original estimate was ~70 KB, from a 12-byte Attribute and
	//   a 16-attribute cap; raising the cap to 32 and Attribute padding to 20
	//   more than doubled it.)
	//
	// Instead there are TWO shared scratch slots, file-static in the .cpp, each
	// tagged with the message that last parsed into it and that message's body
	// generation. Two, because the realistic worst case is one inbound offer and
	// one outbound answer being read in the same handler. A third interleaved
	// message does not break anything — it just re-parses, so the cost is
	// performance, never correctness.
	//
	// ── The invariant that makes shared static scratch safe ───────────────────
	//
	// The accessors are const but observably pure, and they WRITE (to the shared
	// scratch). They are therefore NOT safe to call concurrently on any two
	// messages, let alone one. That is survivable only because every call site
	// runs on the SIP task under RequestsHandler::_mutex: the two outside this
	// class are in RequestsHandler::parseCallerRtp (getRtpPort /
	// getConnectionInformation), reached solely from onMediaInvite, which runs
	// under that mutex like every other handler.
	//
	// RE-CHECK THIS if an SDP accessor is ever called from the HTTP/dashboard
	// task or a media task. With the old per-object cache that would have been a
	// data race on one message; with shared scratch it is a race between
	// UNRELATED messages, which is both more likely to happen and harder to spot.
	//
	// ── Reference lifetime ────────────────────────────────────────────────────
	//
	// ensureParsed() returns a reference INTO the shared scratch, so it is valid
	// only until the next ensureParsed() on a different message evicts the slot.
	// Do not hold it across a call into another SipSdpMessage. Every accessor
	// below uses it and discards it within one expression, which is why they are
	// safe; the string_views they return point into the BODY, not the scratch,
	// so those outlive the slot perfectly well.

	// Generation of the body the model was parsed from. 0 is never a live body
	// generation (SipMessage::_bodyGen starts at 1), so a fresh or freshly
	// assigned message re-parses on first access without a separate valid flag.
	mutable uint64_t _spansGen = 0;

	// Which scratch slot last held this message's model. A HINT only: it is
	// re-validated against the slot's owner pointer before being trusted, so a
	// copied hint pointing at someone else's slot is detected, not followed.
	mutable uint8_t _slot = 0xFF;

	// Re-parses the body iff the model for it is not already in a scratch slot.
	const sdp::Session& ensureParsed() const;

	int extractRtpPort(std::string_view data) const;
};

#endif
