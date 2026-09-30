#pragma once

#include <cstdint>
#include <cstdio>
#include <string_view>

#include "SipMessage.hpp"

// RFC 4028 session timers (#198): the 422 floor onInvite() applies, and the
// Session-Expires on the 2xx the PBX writes itself for the 777, 888, 555, park,
// trunk-handset and local-UPDATE answers (the 440, CallPickup and SipTrunk
// carrier-side answers still echo the request's line; follow-up). Kept free of
// RequestsHandler so ParkOrbit's answers use the same rule.
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

	// RFC 4028 §9 for a 2xx to an INVITE, re-INVITE or UPDATE that this PBX
	// answers as the UAS. `response` is a clone of `request`, so it arrives
	// carrying the phone's own Session-Expires (with no refresher) and Require.
	//
	// The PBX never sends a refresh, so the only timer it can agree to is one the
	// phone refreshes: `Session-Expires: N;refresher=uac`, N copied unchanged
	// (§9: a UAS MUST NOT raise it), plus the `Require: timer` §9 makes mandatory
	// with refresher=uac. That needs the phone to have sent `Supported: timer`,
	// and not to have named the PBX as refresher (refresher=uas, which §9 would
	// oblige the answer to keep). Otherwise the answer carries NO Session-Expires,
	// which §7.2 defines as no session expiration: the phone then neither
	// refreshes nor ends the call on a timer nobody services.
	//
	// `grant` is false on a leg whose refresh the PBX cannot answer with a 2xx:
	// 777, 888 and the trunk handset leg (onReinvite answers their re-INVITE
	// 488), and park (an UPDATE refresh is relayed back to the caller, #709, and
	// draws 481). RFC 4028 §10 says only a 2xx extends the session, so granting
	// refresher=uac there makes the phone BYE the call at expiry, a 911 trunk
	// call included. Those answers carry no timer at all (§7.2), the same rule
	// as refresher=uas above. It is true on 555 (answerAnchorReinvite answers
	// the re-INVITE 200) and on a local UPDATE answer.
	//
	// ponytail: "timer" is a substring match on the first Supported (or compact
	// `k:`) line, kept small for the 4 MB build (#689). No other registered
	// option tag contains "timer"; tokenise the list if one ever does.
	inline void answerSessionTimer(SipMessage& response, const SipMessage& request, bool grant)
	{
		response.removeHeaders("Session-Expires");
		response.removeHeaders("x");         // compact Session-Expires (RFC 4028 §4)
		response.removeHeaders("Require");   // the phone's own, cloned in
		if (!grant) return;
		std::string_view supported = request.getHeaderLine("Supported");
		if (supported.empty()) supported = request.getHeaderLine("k");
		const uint32_t secs = request.getSessionExpiresSecs();
		if (secs == 0 || request.getSessionExpiresRefresher() == "uas" ||
		    supported.find("timer") == std::string_view::npos) return;
		char value[32]{};   // 10 digits of UINT32_MAX + ";refresher=uac"
		const int n = std::snprintf(value, sizeof(value), "%lu;refresher=uac", static_cast<unsigned long>(secs));
		if (n <= 0 || static_cast<size_t>(n) >= sizeof(value)) return;   // unreachable: always fits
		response.addHeader("Session-Expires", std::string_view(value, static_cast<size_t>(n)));
		response.addHeader("Require", "timer");
	}
}
