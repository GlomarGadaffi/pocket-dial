#ifndef PBX_CONFIG_HPP
#define PBX_CONFIG_HPP

// PbxConfig.hpp — per-extension call-forwarding and ring/hunt-group configuration
// for the "Class A" PBX feature sweep.
//
// Design mirrors the existing _dnd map (see RequestsHandler): a bounded
// std::unordered_map keyed by extension, guarded by the registrar's _mutex, and
// NVS-persisted so the config survives reboot. Like _dnd, the maps can never grow
// past the client-pool depth because the dashboard/API only ever sets config for
// real (validated) extensions, and clearing an entry erases it.
//
// All NVS access is gated on ESP_PLATFORM so the desktop gtest build stays
// host-compilable (on host the maps are pure RAM; load/persist are no-ops). The
// parsing helpers (parseReferToTarget, splitMembers) are pure and free-standing so
// the unit tests can exercise the routing logic without the full RequestsHandler.

#include <chrono>
#include <string>
#include <string_view>
#include <vector>
#include <utility>
#include <unordered_map>
#include <algorithm>
#include <cctype>

#include "PoolConfig.hpp"

namespace pbx
{
	// How long a rung member (direct CFNA target or one hunt-group leg) is given
	// to answer before the caller gives up on it. Shared by RequestsHandler's
	// direct-call CFNA arm (onInvite) and CallForker::huntRingNext, which is why
	// it lives here rather than file-local to either translation unit.
	inline constexpr std::chrono::seconds kNoAnswerTimeout{20};

	// How a ring group fans an inbound INVITE out to its members.
	enum class GroupMode
	{
		RingAll,   // fork to every member at once; first to answer wins (like 999)
		Hunt       // ring members one at a time with a per-member timeout
	};

	// The three independent call-forward targets for one extension. An empty
	// string means "not configured" for that trigger. Stored value type.
	struct ForwardConfig
	{
		std::string always;     // CFU  — forward unconditionally, before ringing
		std::string busy;       // CFB  — forward when the callee returns 486 Busy
		std::string noAnswer;   // CFNA — forward when the callee never answers

		bool empty() const
		{
			return always.empty() && busy.empty() && noAnswer.empty();
		}
	};

	// One ring/hunt group: an ordered member list plus the fan-out mode.
	struct RingGroup
	{
		std::vector<std::string> members;
		GroupMode mode = GroupMode::RingAll;
	};

	// ── Pure parsing helpers (unit-tested directly) ───────────────────────────

	// Extract the target extension (AOR user-part) from a Refer-To header value.
	// Handles the common forms produced by SIP UAs, e.g.:
	//   Refer-To: <sip:200@host:5060>
	//   Refer-To: "Bob" <sip:200@host>;some=param
	//   Refer-To: sip:200@host
	// Returns the user-part ("200") or "" if no sip: URI / user-part is present.
	// Mirrors SipMessage::extractNumber but works on a header VALUE that may carry
	// a display name and angle brackets, and tolerates a missing '@'.
	inline std::string parseReferToTarget(const std::string& referTo)
	{
		auto sipPos = referTo.find("sip:");
		if (sipPos == std::string::npos)
		{
			return {};
		}
		size_t start = sipPos + 4;

		// The user-part ends at '@' (user@host) or, if there is no host part, at the
		// first URI delimiter: '>', ';', '?' or whitespace.
		size_t end = referTo.size();
		for (size_t i = start; i < referTo.size(); ++i)
		{
			char c = referTo[i];
			if (c == '@' || c == '>' || c == ';' || c == '?' ||
				c == ' ' || c == '\t' || c == '\r' || c == '\n')
			{
				end = i;
				break;
			}
		}
		if (end <= start)
		{
			return {};
		}
		return referTo.substr(start, end - start);
	}

	// Split a comma/whitespace-separated member list (as stored in NVS / posted from
	// the dashboard) into individual extensions, trimming surrounding whitespace and
	// dropping empties. Bounded by POCKETDIAL_MAX_CLIENTS so a malicious list can't
	// allocate without limit.
	inline std::vector<std::string> splitMembers(const std::string& csv)
	{
		std::vector<std::string> out;
		size_t i = 0;
		while (i < csv.size() && out.size() < static_cast<size_t>(POCKETDIAL_MAX_CLIENTS))
		{
			// Skip separators (comma or whitespace).
			while (i < csv.size() &&
				(csv[i] == ',' || std::isspace(static_cast<unsigned char>(csv[i]))))
			{
				++i;
			}
			size_t start = i;
			while (i < csv.size() && csv[i] != ',' &&
				!std::isspace(static_cast<unsigned char>(csv[i])))
			{
				++i;
			}
			if (i > start)
			{
				out.push_back(csv.substr(start, i - start));
			}
		}
		return out;
	}

	// Join a member list back into the canonical comma-separated form used for NVS
	// persistence and the dashboard snapshot.
	inline std::string joinMembers(const std::vector<std::string>& members)
	{
		std::string out;
		for (size_t i = 0; i < members.size(); ++i)
		{
			if (i) out.push_back(',');
			out += members[i];
		}
		return out;
	}

	// ── Paging zones (the 980–989 virtual extensions) ─────────────────────────

	// One paging zone: an unordered member set (stored as a deduped, capped list).
	// A dial of the zone extension forks an intercom (auto-answer) INVITE to every
	// registered member — exactly the 999 all-page machinery, scoped to the zone.
	struct PageZone
	{
		std::vector<std::string> members;
	};

	// True iff `ext` is in the reserved paging-zone dial range 980–989. Pure, so
	// the routing predicate is unit-testable without linking the registrar.
	inline bool isPageZoneExt(const std::string& ext)
	{
		return ext.size() == 3 && ext[0] == '9' && ext[1] == '8' &&
			std::isdigit(static_cast<unsigned char>(ext[2]));
	}

	// Split a zone member list (same CSV grammar as splitMembers), then dedupe
	// (first occurrence wins, order preserved) and clamp to POCKETDIAL_ZONE_MEMBER_CAP.
	inline std::vector<std::string> splitZoneMembers(const std::string& csv)
	{
		std::vector<std::string> out;
		for (auto& m : splitMembers(csv))
		{
			if (out.size() >= static_cast<size_t>(POCKETDIAL_ZONE_MEMBER_CAP))
				break;
			if (std::find(out.begin(), out.end(), m) == out.end())
				out.push_back(m);
		}
		return out;
	}

	// ── Reserved / emergency / PSTN-shaped REGISTER identity guard (Issue #163) ──
	//
	// isValidAor() (RequestsHandler.cpp) is charset-only, so nothing stopped a
	// phone REGISTERing as one of the fixed virtual extensions this engine
	// already treats specially elsewhere, as the emergency number or its test
	// number, or as a PSTN-shaped number. The three helpers below are that
	// missing identity-semantics check, kept pure and free-standing so both
	// REGISTER call sites (onRegister()'s From-number gate and
	// findProvisioningInfo()'s adopted-extension recheck) can ask the same
	// question without a third independent copy of the literal set.

	// The reserved virtual/emergency extensions: 777 (echo test), 999 (all-page/
	// ring-all fan-out), 888 (ConferenceRoom::EXT, the meet-me conference), 555
	// (kAnchorCallExt, the anchor media bridge), 440 (busy/error tone), and 911 /
	// 933 (the US emergency number and its standard E911 TEST number — neither
	// has ANY special handling anywhere in this codebase today, which is exactly
	// why a REGISTER claiming one must be refused outright rather than silently
	// intercepting calls meant for it).
	//
	// HISTORY, because this comment used to say the opposite and a reader needs
	// to know it changed deliberately. Under #163 this was the REGISTER-identity
	// set only, and PbxFeatureConfig.cpp's three config-surface validators kept
	// their own narrower literal lists, omitting 911/933 on purpose so that a
	// future dial-plan rule could route 911 to a trunk.
	//
	// #166 removed that reason. 911 and 933 are now intercepted in onInvite()
	// ahead of ring groups and the dial plan (see EmergencyCall.hpp), so a
	// dial-plan rule for them cannot fire and is not merely redundant but
	// actively dangerous: a "9*" outside-line rule with stripDigits=1 matched a
	// dialed 911 and rewrote it to 11 (issue #240). All three validators
	// therefore call THIS helper now, and the three lists that had drifted
	// apart (forwards and ring groups omitted 440; setDialRule omitted 888;
	// none covered 911/933) are one list again.
	inline bool isReservedExtension(std::string_view ext)
	{
		return ext == "777" || ext == "999" || ext == "888" || ext == "555" ||
			ext == "440" || ext == "911" || ext == "933";
	}

	// True iff `aor` "looks like a direct PSTN number" rather than an internal
	// extension: all-digit and at least POCKETDIAL_MIN_PSTN_AOR_DIGITS long (see
	// PoolConfig.hpp for the threshold and the reasoning behind its default).
	// Deliberately does NOT match a leading '+' — that case is unambiguous E.164
	// and isReservedOrPstnAor() below refuses it unconditionally, without regard
	// to length, so it never reaches this length-based guess at all.
	inline bool looksLikePstnAor(std::string_view aor)
	{
		if (aor.size() < static_cast<std::size_t>(POCKETDIAL_MIN_PSTN_AOR_DIGITS))
		{
			return false;
		}
		for (char c : aor)
		{
			if (!std::isdigit(static_cast<unsigned char>(c)))
			{
				return false;
			}
		}
		return true;
	}

	// The combined REGISTER-time guard (Issue #163): true iff `aor` must never
	// be admitted as a phone's From-number, in ANY registrar mode. ORs the three
	// independent reasons an otherwise charset-valid AOR is inadmissible:
	//   - it names one of the reserved/emergency extensions above, or
	//   - it is unambiguously E.164 (a leading '+' — legitimate on an outbound
	//     INVITE To-number, which is why this lives beside isValidAor() rather
	//     than inside it), or
	//   - it merely looks like a direct-dial PSTN number (long, all-digit).
	inline bool isReservedOrPstnAor(std::string_view aor)
	{
		if (isReservedExtension(aor)) return true;
		if (!aor.empty() && aor.front() == '+') return true;
		return looksLikePstnAor(aor);
	}

	// ── Directed / group call pickup (Issue #68) ──────────────────────────────
	//
	// Design choice: pickup groups are NOT a new config table. They reuse
	// ring-group membership (RingGroup::members, above) exactly as-is: two
	// extensions are pickup-eligible for each other iff they are both members
	// of at least one configured ring group — regardless of that group's mode
	// (RingAll or Hunt; pickup only cares who's in the list, not how it rings).
	// An operator who already set up a "sales" or "support" ring group gets a
	// pickup group for free, with no new dashboard/NVS surface to add or keep
	// in sync. The acceptance criteria for this feature ("only same-pickup-
	// group calls eligible") is written without carving out directed pickup,
	// so BOTH *8 (group) and **<ext> (directed) are restricted to the picker's
	// own ring-group co-members — see RequestsHandler::pickupPeersOf().
	//
	// *8 is the group-pickup code; **<ext> is directed pickup of a specific
	// extension. Both are dialed as the To user-part of an INVITE, exactly
	// like the 700-709 park orbits and 980-989 page zones (isValidAor already
	// allows '*' in an AOR for this reason).

	// True iff `ext` is the group-pickup star code.
	inline bool isGroupPickupCode(const std::string& ext)
	{
		return ext == "*8";
	}

	// Extracts the target extension from a directed-pickup code ("**204" ->
	// "204"). Returns "" for anything not prefixed "**" and for "**" with no
	// extension following it — both are treated as "no target" by the caller.
	inline std::string directedPickupTarget(const std::string& ext)
	{
		if (ext.size() > 2 && ext[0] == '*' && ext[1] == '*')
		{
			return ext.substr(2);
		}
		return {};
	}
}

#endif
