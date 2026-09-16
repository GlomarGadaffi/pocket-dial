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

	// Issue #263: sdp::isHold() applied to the offer's first AUDIO section (see
	// #253 -- explicit section selection, never an implicit media[0]), so the
	// three hold/resume call sites get both RFC 3264 s8.4 direction-based hold
	// AND the legacy RFC 2543 c=0.0.0.0 signal, instead of the direction-only
	// scan getSdpDirection() does. Does not re-validate the body: checkSdp()
	// (RequestsHandler.cpp's SDP admission gate) has already refused a
	// malformed one with 488 before any handler that would call this runs, so
	// ensureParsed() can be assumed to reflect a structurally sound parse.
	bool isHoldOffer() const;

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
	// messages, let alone one. The property that makes that survivable is MUTEX
	// EXCLUSION, not which handler you are in: every caller of an SDP accessor
	// must hold RequestsHandler::_mutex before reaching it. This is not a
	// property of the call path — RequestsHandler::parseCallerRtp
	// (getRtpPort / getConnectionInformation) alone has several call sites
	// spread across this file, one of them the AnchorClient::setEventCallback
	// lambda, which runs off the SIP thread entirely and takes the mutex
	// explicitly before calling in. Don't count them and don't trust an old
	// count: check the lock at whatever site you're looking at, not the call
	// path.
	//
	// RE-CHECK THIS if an SDP accessor is ever reachable without the caller
	// holding that mutex. With the old per-object cache that would have been a
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
