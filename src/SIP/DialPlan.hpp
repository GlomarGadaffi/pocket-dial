#ifndef DIAL_PLAN_HPP
#define DIAL_PLAN_HPP

// DialPlan.hpp — Issue #69: a small, bounded, table-driven pattern → action dial
// plan for LAN routing.
//
// This is the generalization of the ring-group mechanism (setRingGroup /
// getRingGroups): instead of "a dialed number IS a group extension", a dial rule
// says "a dialed number that LOOKS LIKE this pattern is routed to that action".
// The actions are the ones pocket-dial already ships — nothing here invents new
// call handling:
//
//   group  → the ring/hunt group named by the rule's target (RequestsHandler's
//            findRingGroup + the ring-all fork / sequential hunt, Class A sweep)
//   page   → the paging zone named by the rule's target (Issue #66, 980–989)
//   park   → the park orbit named by the rule's target (Issue #65, 700–70N);
//            dialing a rule with this action is exactly dialing the orbit, i.e.
//            park into a free slot / retrieve from an occupied one
//   trunk  → outbound PSTN access via the configured anchor/telephony provider
//            (Issue #165): strip the rule's stripDigits leading digits off the
//            dialed string, prepend `target`, and place the result as an
//            outbound call through RequestsHandler::originateAnchorCall() (the
//            same call-origination core the 555 anchor extension uses). E.g.
//            pattern "9XXXXXXXXXX", stripDigits 1, target "1" turns a dial of
//            "92025550123" into "12025550123".
//
// (Issue #68's directed pickup is deliberately absent: it is not on main. Adding
// it later is one enum value, one parse/name string, and one dispatch arm.)
//
// Design mirrors PbxConfig.hpp: everything here is pure and header-only so the
// host tests can exercise pattern precedence and the size cap without linking
// the registrar. The table lives in RequestsHandler behind _mutex, is capped at
// POCKETDIAL_MAX_DIAL_RULES, and is NVS-persisted alongside the ring groups and
// paging zones.
//
// ── Pattern grammar ──────────────────────────────────────────────────────────
// Deliberately tiny — this is a LAN desk PBX, not a carrier dial plan. There is
// no regex engine, no backtracking, and matching is O(pattern length).
//
//   digits / letters / '#' / '*'   match themselves, literally
//   'X' or 'x'                     match exactly one digit (0–9)
//   a trailing '*'                 matches the rest of the dialed number,
//                                  including nothing at all (prefix match)
//
// A '*' anywhere but the last character is a LITERAL '*', because star-codes
// (`*8`, the *PIN#code admin menu) are real dialable strings on this box —
// treating a leading '*' as a wildcard would make `*8*` ambiguous with the
// pickup-style codes. Only the final character is special.
//
//   "601"    exact match: only 601
//   "6XX"    601, 655, 699 … (three digits, first is 6)
//   "6*"     6, 60, 601, 6123 … (anything starting with 6)
//   "*"      catch-all (a single trailing star with an empty literal prefix)
//   "*8"     the literal star-code *8 — NOT a wildcard
//
// ── Evaluation ───────────────────────────────────────────────────────────────
// Rules are evaluated in TABLE ORDER and the FIRST match wins. Order is the
// operator's, not a specificity heuristic: if a catch-all is listed first it
// shadows everything after it, exactly as written. Rules are appended in the
// order they are configured, and editing an existing pattern keeps its position.

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <string>
#include <vector>

#include "PoolConfig.hpp"

namespace pbx
{
	// The already-shipped call-handling actions a dial rule can select.
	enum class DialActionType : uint8_t
	{
		RingGroup,   // route to the ring/hunt group named by `target`
		PageZone,    // route to the paging zone named by `target`
		ParkOrbit,   // route to the park orbit named by `target` (park/retrieve)
		Trunk        // outbound PSTN access: strip stripDigits, prepend `target`
	};

	// One rule: a pattern, the action it selects, and the action's target (a
	// group extension, a zone extension, an orbit extension, or — for Trunk —
	// the digit string prepended to the dialed number after stripping).
	// stripDigits is meaningless for every action but Trunk, where it counts
	// leading digits removed from the dialed string before prepending target.
	struct DialRule
	{
		std::string pattern;
		DialActionType action = DialActionType::RingGroup;
		std::string target;
		int stripDigits = 0;
	};

	// ── Pure helpers (unit-tested directly) ───────────────────────────────────

	// Wire/NVS/JSON name for an action, and the inverse. Unknown names parse to
	// false so a corrupted NVS record or a bad API parameter is rejected rather
	// than silently defaulting to some action the operator never asked for.
	inline const char* dialActionName(DialActionType a)
	{
		switch (a)
		{
		case DialActionType::PageZone:  return "page";
		case DialActionType::ParkOrbit: return "park";
		case DialActionType::Trunk:     return "trunk";
		case DialActionType::RingGroup:
		default:                        return "group";
		}
	}

	inline bool parseDialAction(const std::string& name, DialActionType& out)
	{
		if (name == "group") { out = DialActionType::RingGroup; return true; }
		if (name == "page")  { out = DialActionType::PageZone;  return true; }
		if (name == "park")  { out = DialActionType::ParkOrbit; return true; }
		if (name == "trunk") { out = DialActionType::Trunk;     return true; }
		return false;
	}

	// Match `dialed` against `pattern` under the grammar documented at the top of
	// this file. Pure, allocation-free, and O(pattern.size()).
	inline bool dialPatternMatches(const std::string& pattern, const std::string& dialed)
	{
		if (pattern.empty())
		{
			return false;   // an empty pattern never matches (also rejected at config time)
		}

		// A trailing '*' is the only wildcard that consumes more than one char:
		// everything before it must match position-for-position, and whatever is
		// left of `dialed` (possibly nothing) is absorbed.
		const bool prefixMode = (pattern.back() == '*');
		const size_t litLen = prefixMode ? pattern.size() - 1 : pattern.size();

		if (!prefixMode && dialed.size() != litLen) return false;
		if (dialed.size() < litLen) return false;

		for (size_t i = 0; i < litLen; ++i)
		{
			const char p = pattern[i];
			const char d = dialed[i];
			if (p == 'X' || p == 'x')
			{
				if (!std::isdigit(static_cast<unsigned char>(d))) return false;
			}
			else if (p != d)
			{
				return false;
			}
		}
		return true;
	}

	// Trunk-access digit transform (Issue #165): strip `stripDigits` leading
	// characters off `dialed` and prepend `prepend`. Returns false (leaving
	// `out` untouched) if `stripDigits` exceeds `dialed`'s length — a stale
	// rule (e.g. strip=1 saved against an 11-digit pattern, then the pattern
	// loosened to match shorter numbers) must refuse rather than silently
	// mis-dial a truncated or garbage number. Pure and allocation-free bar the
	// one output string, so it is host-testable without a rule/pattern at all.
	inline bool applyTrunkTransform(const std::string& dialed, int stripDigits,
		const std::string& prepend, std::string& out)
	{
		if (stripDigits < 0 || static_cast<size_t>(stripDigits) > dialed.size())
		{
			return false;
		}
		out = prepend + dialed.substr(static_cast<size_t>(stripDigits));
		return true;
	}

	// True iff every character of `s` is safe to round-trip through the tab/newline
	// delimited NVS blob and the dashboard JSON: digits, ASCII letters, '#', '*'.
	// Rejecting at config time (rather than escaping) keeps the persisted record
	// format unambiguous — a tab or newline smuggled into a pattern would otherwise
	// corrupt every rule after it on the next boot.
	inline bool isDialTokenSafe(const std::string& s)
	{
		if (s.empty()) return false;
		for (char c : s)
		{
			const unsigned char u = static_cast<unsigned char>(c);
			if (std::isalnum(u) || c == '#' || c == '*') continue;
			return false;
		}
		return true;
	}

	// True iff `ext` is a valid park-orbit extension for this build ("700" ..
	// "70(POCKETDIAL_PARK_SLOTS-1)"). Mirrors ParkOrbit::orbitIndex()'s range test
	// as a pure predicate so a dial rule's target can be validated at CONFIG time,
	// off the SIP thread and without a ParkOrbit instance.
	inline bool isParkOrbitExt(const std::string& ext)
	{
		if (ext.size() != 3 || ext[0] != '7' || ext[1] != '0') return false;
		if (!std::isdigit(static_cast<unsigned char>(ext[2]))) return false;
		return (ext[2] - '0') < POCKETDIAL_PARK_SLOTS;
	}

	// ── The bounded rule table ────────────────────────────────────────────────
	//
	// An ordered vector — order IS the semantics, so this is deliberately not a
	// map. Capacity is hard-capped at POCKETDIAL_MAX_DIAL_RULES (see PoolConfig.hpp
	// for the rationale); upsert() refuses to grow past it but still edits rules
	// that are already in the table, so a full table is never un-editable.
	class DialPlan
	{
	public:
		// Insert `rule` at the end, or replace the existing rule with the same
		// pattern IN PLACE (keeping its evaluation position — editing a rule's
		// action or target must never silently re-order the plan). Returns false
		// only when the rule is new and the table is already full.
		bool upsert(const DialRule& rule)
		{
			for (auto& existing : _rules)
			{
				if (existing.pattern == rule.pattern)
				{
					existing.action = rule.action;
					existing.target = rule.target;
					// stripDigits MUST be copied too. Leaving it out meant an edit
					// silently kept the FIRST insert's strip count while taking the
					// new action/target — so re-POSTing a trunk rule to fix a typo
					// reverted it to "strip nothing" and persistDialPlan() then wrote
					// that stale value to NVS, where it survived a reboot. Since
					// re-POSTing a pattern is the only way to edit a rule, this hit
					// the normal editing path, not a corner case.
					existing.stripDigits = rule.stripDigits;
					return true;
				}
			}
			if (_rules.size() >= static_cast<size_t>(POCKETDIAL_MAX_DIAL_RULES))
			{
				return false;
			}
			_rules.push_back(rule);
			return true;
		}

		// Remove the rule with this pattern. Returns true if one was removed.
		bool erase(const std::string& pattern)
		{
			auto it = std::find_if(_rules.begin(), _rules.end(),
				[&](const DialRule& r) { return r.pattern == pattern; });
			if (it == _rules.end()) return false;
			_rules.erase(it);
			return true;
		}

		// First rule whose pattern matches `dialed`, or nullptr when nothing does
		// (the fallthrough case: the caller must then route exactly as it did
		// before the dial plan existed).
		const DialRule* match(const std::string& dialed) const
		{
			for (const auto& r : _rules)
			{
				if (dialPatternMatches(r.pattern, dialed)) return &r;
			}
			return nullptr;
		}

		const std::vector<DialRule>& rules() const { return _rules; }
		size_t size() const { return _rules.size(); }
		bool empty() const { return _rules.empty(); }
		void clear() { _rules.clear(); }

	private:
		std::vector<DialRule> _rules;
	};
}

#endif
