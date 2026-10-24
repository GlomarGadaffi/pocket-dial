#pragma once

#include <cstdint>
#include <cstdio>
#include <string_view>

#include "SipMessage.hpp"

// RFC 4028 session timers (#198): the 422 floor onInvite() applies, and the
// Session-Expires on each 2xx the PBX writes by cloning a phone's INVITE or
// UPDATE: the 777, 888, 555, park, voicemail, trunk-handset and local-UPDATE
// answers go through answerSessionTimer() (#724), the 440 and call-pickup
// (both legs) answers through stripSessionTimerUnlessRequired() (#739).
// SipTrunk's carrier-side answer is not a clone (it is composed by
// SipTrunk::buildResponse) and never carries the header. Kept free of
// RequestsHandler so ParkOrbit's and CallPickup's answers use the same rule.
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
	// 777, 888, the 440 tone leg and the trunk handset leg (onReinvite answers
	// their re-INVITE 488), park (an UPDATE refresh is relayed back to the
	// caller, #709, and draws 481), voicemail (a re-INVITE is relayed back to
	// the caller's own address) and call pickup (a spliced dialog relays a
	// re-INVITE refresh into the peer's dialog, #453). RFC 4028 §10 says only a
	// 2xx extends the session, so granting refresher=uac there makes the phone
	// BYE the call at expiry, a 911 trunk call included. Those answers carry no
	// timer at all (§7.2), the same rule as refresher=uas above. It is true on
	// the synchronous 555 answer (answerAnchorReinvite answers the re-INVITE
	// 200) and on a local UPDATE answer. The async anchor answer still passes
	// false (#739).
	//
	// That rule is only legal for a caller that merely SUPPORTS timer. One that
	// REQUIRES it (Require: timer) is owed Session-Expires and Require: timer in
	// the 2xx (§9): pjsua --use-timer=2 hung up on a 440 answer without them
	// (BYE, Reason cause=421 "Failed processing session timer response"; measured
	// on 440 only). The 440 and call-pickup answers honour that
	// (stripSessionTimerUnlessRequired(), #739). The other grant=false legs
	// above still strip for such a caller; the same §9 owes it a timer there,
	// but that has not been measured on them and is not changed here.
	//
	// That strip is only legal for a caller that merely SUPPORTS timer. One that
	// REQUIRES it (Require: timer) is owed Session-Expires and Require: timer in
	// the 2xx (§9): pjsua --use-timer=2 hung up on a 440 answer without them (BYE,
	// Reason cause=421; #1042). So a grant=false answer to such a caller keeps the
	// clone as it arrived, the pre-#724 echo. Nothing arms a reaper from our own 2xx.
	//
	// ponytail: "timer" is a substring match on the first Supported (or compact
	// `k:`) line, kept small for the 4 MB build (#689). No other registered
	// option tag contains "timer"; tokenise the list if one ever does.
	inline void answerSessionTimer(SipMessage& response, const SipMessage& request, bool grant)
	{
		if (!grant && request.requiresTimer()) return;   // #1042
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

	// The 440 tone and call-pickup answers (#739): answerSessionTimer(grant=false)
	// for a caller that merely supports timer, which is owed none. A caller that
	// requires one (Require: timer, any case, in a list or on a second Require
	// line) keeps the clone as it arrived, Session-Expires and Require included:
	// RFC 4028 §9 owes it both, and pjsua hung up without them. The PBX arms no
	// expiry for either leg, so nothing here changes what happens at the interval.
	inline void stripSessionTimerUnlessRequired(SipMessage& response, const SipMessage& request)
	{
		if (!request.requiresTimer()) answerSessionTimer(response, request, /*grant=*/false);
	}
}
