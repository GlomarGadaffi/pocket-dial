#ifndef ANCHOR_WEDGE_HPP
#define ANCHOR_WEDGE_HPP

#include <cstdint>

// Issue #667: when does the anchor's tick() count an outbound call slot as wedged
// and spawn the reconcile watchdog (#100, floored to one pass per 5 s by #94)?
//
// A wedge is a makecall the PBX accepted but whose leg never showed up on the DN.
// A leg the PBX already lists with a live status (Dialing while the far end rings)
// is not a wedge: the reconcile worker only tears down legs ABSENT from the DN, so
// reconciling a listed, ringing leg every 5 s only churns tasks and TLS GETs. Such
// a slot gets the longer ringing grace instead, which still catches a leg that
// vanishes later without a Remove event.
//
// Pure, so the host suite pins the decision; TelephonyAnchorClient::tick() applies
// it on ESP.

namespace pd
{
	inline constexpr int64_t kAnchorWedgeGraceUs   = 15LL * 1000000;    // no leg seen yet
	inline constexpr int64_t kAnchorRingingGraceUs = 120LL * 1000000;   // leg listed, still ringing

	inline bool anchorSlotLooksWedged(bool outboundActive, bool postLive, bool ringing,
	                                  int64_t setUs, int64_t nowUs)
	{
		if (!outboundActive || postLive || setUs == 0) return false;
		const int64_t grace = ringing ? kAnchorRingingGraceUs : kAnchorWedgeGraceUs;
		return nowUs - setUs >= grace;
	}
}

#endif // ANCHOR_WEDGE_HPP
