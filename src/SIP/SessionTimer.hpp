#pragma once

#include <charconv>
#include <cstdint>
#include <cstring>
#include <string_view>

#include "SipHeaderUtil.hpp"
#include "SipMessage.hpp"

// RFC 4028 session timers (#198): the 422 floor onInvite() applies, and the
// Session-Expires every 2xx the PBX writes itself carries. Kept free of
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

	// True when the request's Supported list (full or compact `k:` form) carries
	// the "timer" option tag. ponytail: reads the first Supported line only; a
	// phone that splits its option tags over several lines reads as no timer,
	// which only turns the timer off (see answerSessionTimer).
	inline bool supportsTimer(const SipMessage& request)
	{
		std::string_view v = request.getHeaderLine("Supported");
		if (v.empty()) v = request.getHeaderLine("k");
		v = siphdr::stripHeaderNameView(v);
		while (!v.empty())
		{
			const size_t comma = v.find(',');
			std::string_view tag = v.substr(0, comma);
			while (!tag.empty() && (tag.front() == ' ' || tag.front() == '\t')) tag.remove_prefix(1);
			while (!tag.empty() && (tag.back() == ' ' || tag.back() == '\t')) tag.remove_suffix(1);
			if (tag == "timer") return true;
			if (comma == std::string_view::npos) break;
			v.remove_prefix(comma + 1);
		}
		return false;
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
	inline void answerSessionTimer(SipMessage& response, const SipMessage& request)
	{
		response.removeHeaders("x");         // compact Session-Expires (RFC 4028 §4)
		response.removeHeaders("Require");   // the phone's own, cloned in
		const uint32_t secs = request.getSessionExpiresSecs();
		if (secs == 0 || request.getSessionExpiresRefresher() == "uas" || !supportsTimer(request))
		{
			response.removeHeaders("Session-Expires");
			return;
		}
		constexpr std::string_view kUac = ";refresher=uac";
		char value[10 + kUac.size()]{};   // 10 = digits in UINT32_MAX
		const auto conv = std::to_chars(value, value + 10, secs);
		if (conv.ec != std::errc{}) return;   // unreachable: 10 digits always fit
		std::memcpy(conv.ptr, kUac.data(), kUac.size());
		response.setHeaderOnce("Session-Expires",
			std::string_view(value, static_cast<size_t>(conv.ptr - value) + kUac.size()));
		response.addHeader("Require", "timer");
	}
}
