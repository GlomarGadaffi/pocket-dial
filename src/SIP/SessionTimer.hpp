#pragma once

#include <cstdint>

// RFC 4028 session-interval floor (#198). Pure so it is testable without a
// handler; RequestsHandler::onInvite() is the only caller.
namespace pbx
{
	// RFC 4028 §4: the smallest Min-SE any element may require, and the value
	// this PBX requires. Anything shorter only churns refreshes.
	constexpr uint32_t kSessionTimerMinSE = 90;

	// Returns 0 when an INVITE's Session-Expires is acceptable (absent, or at
	// least the floor). Otherwise returns the Min-SE value a 422 Session Interval
	// Too Small must carry: the larger of our floor and the request's own Min-SE
	// (RFC 4028 §8.1/§9), so the UAC's retry satisfies every hop at once.
	constexpr uint32_t sessionIntervalMinSEFor422(uint32_t sessionExpires, uint32_t requestMinSE)
	{
		if (sessionExpires == 0 || sessionExpires >= kSessionTimerMinSE) return 0;
		return requestMinSE > kSessionTimerMinSE ? requestMinSE : kSessionTimerMinSE;
	}
}
