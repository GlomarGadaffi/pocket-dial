#ifndef EMERGENCY_CALL_HPP
#define EMERGENCY_CALL_HPP

// ── Emergency dialing (Issue #166) ───────────────────────────────────────────
//
// Recognising 911 is three lines of string comparison. The reason this has its
// own file is the part that is NOT obvious: WHERE the comparison has to happen,
// and why every tempting alternative is wrong.
//
// ── Why this cannot be a dial-plan rule ──────────────────────────────────────
//
// The natural instinct is "add a rule that routes 911 to the trunk". That is
// exactly the thing that must not be relied on, because the dial plan is
// operator-editable and first-match-wins (DialPlan.hpp, DialRuleTable::match).
// Concretely, the most natural way an operator writes "dial 9 for an outside
// line" is a rule with pattern "9*" and stripDigits=1. dialPatternMatches()
// treats a trailing '*' as "absorb the rest", so "9*" matches "911", and
// applyTrunkTransform() then strips the leading digit and dials **11** — a
// number that is not 911 and not the operator's intent, with no error anywhere.
// A rule ordered after that one never runs.
//
// So the emergency check is not a rule and does not live in the rule table. It
// runs BEFORE the dial plan, before ring groups, and before every other
// destination lookup in onInvite(), so no configuration an operator can type
// is capable of shadowing, reordering or rewriting it.
//
// ── Capability gates stay, policy gates do not ───────────────────────────────
//
// Issue #166 asks that 911 bypass "whatever dial-plan lock/restriction state
// might otherwise apply". Taken literally that would mean bypassing everything,
// which would turn the PBX into an unauthenticated 911 originator for anything
// that can reach UDP/5060. The line drawn instead:
//
//   * CAPABILITY gates still apply. The caller must be a registered client
//     (onInvite's 403) and must have offered a codec this PBX can actually
//     relay (its 488). These are not restrictions on WHO may dial 911 — they
//     are statements that no working call is possible at all, and pretending
//     otherwise would produce a 911 call with dead audio.
//   * POLICY gates are bypassed. The secure-mode INVITE challenge, ring groups,
//     the dial plan, call-forward and DND are all operator policy. None of them
//     may stand between a person and 911.
//
// ── The trunk-access prefix ──────────────────────────────────────────────────
//
// A user on a system where "dial 9 first" is the habit will dial 9-1-1 and get
// 9911. FCC 19-76 permits supporting that alongside direct dial (it is direct
// dial that is mandatory, not the prefixed form), and swallowing it costs
// nothing. Whatever was dialed, the BARE number is what gets routed: the trunk
// is always handed "911", never "9911" and never "11".

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "PoolConfig.hpp"

namespace pbx
{

// The US emergency number and its standard E911 test number. 933 reaches a
// carrier test service that reads back the registered callback number and
// location; it is a real outbound call and must route identically, but every
// operator-facing string it produces is tagged as a TEST so a test is never
// mistaken for a live emergency in a log or a notification.
inline constexpr std::string_view kEmergencyNumber     = "911";
inline constexpr std::string_view kEmergencyTestNumber = "933";

// The single trunk-access digit a user may have dialed out of habit.
inline constexpr char kTrunkAccessDigit = '9';

struct EmergencyDial
{
	bool isEmergency = false;
	// 933 rather than 911. Routes identically; only the wording differs.
	bool isTest = false;
	// The caller dialed a trunk-access digit first ("9911"). Recorded only so
	// the log can say what was actually dialed — it never changes the routing.
	bool hadTrunkPrefix = false;
	// The bare digits to hand the trunk: "911" or "933", never what was dialed.
	std::string_view number;
};

// Classify a dialed number. `dialed` is the To-header user part as onInvite()
// reads it.
//
// Deliberately an EXACT match against a tiny closed set, with one optional
// leading trunk-access digit. No prefix matching, no "starts with 911", no
// length-based guessing: a wrong POSITIVE here hijacks an ordinary call to the
// emergency path, and a wrong NEGATIVE drops a 911 call into normal routing.
// Both failures are severe, so the rule is the narrowest one that works.
inline EmergencyDial classifyEmergencyDial(std::string_view dialed)
{
	EmergencyDial out;

	std::string_view bare = dialed;
	bool prefixed = false;

	// Strip at most ONE trunk-access digit, and only when what remains is itself
	// an emergency number. "9911" is 911; "9933" is 933. Note this cannot
	// misfire on a real 9-prefixed PSTN call, because the remainder would have
	// to be exactly "911" or "933" -- a 3-digit outside number does not exist.
	if (dialed.size() == 4 && dialed.front() == kTrunkAccessDigit)
	{
		const std::string_view rest = dialed.substr(1);
		if (rest == kEmergencyNumber || rest == kEmergencyTestNumber)
		{
			bare = rest;
			prefixed = true;
		}
	}

	if (bare == kEmergencyNumber)
	{
		out.isEmergency = true;
		out.number = kEmergencyNumber;
	}
	else if (bare == kEmergencyTestNumber)
	{
		out.isEmergency = true;
		out.isTest = true;
		out.number = kEmergencyTestNumber;
	}

	out.hadTrunkPrefix = out.isEmergency && prefixed;
	return out;
}

// ── PSAP callback window (#659) ──────────────────────────────────────────────
//
// A PSAP calling back is not recognised by caller ID, because callback numbers
// vary. An inbound call to an extension that dialed 911 or 933 within this
// window is an emergency session instead (Session::isEmergency()).
inline constexpr std::chrono::minutes kEmergencyCallbackWindow{30};

// When each extension last dialed 911/933. Fixed storage, no heap: one mark per
// client slot, since only a registered extension can dial. More distinct dialers
// than that overwrite the oldest mark.
class EmergencyCallbacks
{
public:
	static constexpr std::size_t kMaxExt = 64;   // RequestsHandler's kMaxAorLen

	void note(std::string_view ext, std::chrono::steady_clock::time_point now)
	{
		if (ext.empty() || ext.size() > kMaxExt) return;
		Mark* slot = &_marks[0];
		for (Mark& m : _marks)
		{
			if (m.view() == ext) { slot = &m; break; }
			if (m.at < slot->at) slot = &m;
		}
		std::copy(ext.begin(), ext.end(), slot->ext.begin());
		slot->len = ext.size();
		slot->at = now;
	}

	bool open(std::string_view ext, std::chrono::steady_clock::time_point now) const
	{
		for (const Mark& m : _marks)
			if (m.len != 0 && m.view() == ext && now - m.at < kEmergencyCallbackWindow) return true;
		return false;
	}

#if !defined(ESP_PLATFORM) && !defined(ESP32) && !defined(ARDUINO)
	// Test-only: move every mark `d` into the past.
	void ageForTest(std::chrono::steady_clock::duration d) { for (Mark& m : _marks) m.at -= d; }
#endif

private:
	struct Mark
	{
		std::array<char, kMaxExt> ext{};
		std::size_t len = 0;
		std::chrono::steady_clock::time_point at{};
		std::string_view view() const { return {ext.data(), len}; }
	};
	std::array<Mark, POCKETDIAL_MAX_CLIENTS> _marks{};
};

// ── Unknown-caller alert coalescing (#1115) ──────────────────────────────────
//
// An INVITE to 911/933 from a caller that is not a registered extension is
// refused (403) and, since #1107, written to the EMERGENCY log and announced to
// the E911 notify list. The log line is never coalesced. The announcement goes
// out once per (source IP, emergency number) per window, so a flood of forged
// 911s cannot teach the notify list to ignore the alert. A registered caller's
// 911 does not pass through here at all. Nothing is lost silently: refusals held
// back are reported as an "N more since" summary, by the next dial after the
// window or, if none comes, by takeExpired() from tick().
//
// 60 s: long enough to absorb a burst, short enough that a real unknown device
// dialling again a minute later is announced afresh.
inline constexpr std::chrono::seconds kUnknownAlertWindow{60};
// 16 pairs: 8 sources x {911, 933}. Distinct sources are bounded upstream by the
// 256-entry rate-bucket cap (further new sources are dropped) and by the one budget
// all unregistered sources share for emergency INVITEs (4 burst, then 1 per 10 s). A
// flood can still exceed 16 pairs: the rest share one overflow entry per number (one
// notice per window, the rest counted and summarised), so fan-out is at most 18.
inline constexpr std::size_t kUnknownAlertMax = 16;

class UnknownEmergencyAlerts
{
public:
	static constexpr std::size_t kFromLen = 32;
	static constexpr std::size_t kDialedLen = 16;

	struct Verdict
	{
		bool notify = true;
		bool overflow = false;   // the shared overflow entry spoke, not a per-source one
		uint32_t summary = 0;    // refusals coalesced since the last announcement
	};

	// A tally due for announcement: window over, nobody dialled again.
	struct Due
	{
		bool overflow = false;
		bool isTest = false;
		char from[kFromLen + 1] = {};
		char dialed[kDialedLen + 1] = {};
		uint32_t held = 0;
	};

	// `ip` is the source address (network order), `isTest` selects 933 over 911.
	Verdict check(uint32_t ip, bool isTest, std::string_view from, std::string_view dialed,
		std::chrono::steady_clock::time_point now)
	{
		Entry* spare = nullptr;
		for (Entry& e : _e)
		{
			if (!e.used) { if (!spare) spare = &e; continue; }
			if (e.ip != ip || e.isTest != isTest) continue;
			return touch(e, now, false);
		}
		if (!spare) spare = reclaimExpired(now);
		if (!spare)
		{
			if (_overflow < UINT32_MAX) ++_overflow;
			Entry& o = _over[isTest ? 1 : 0];   // 911 and 933 never share: a test must not absorb a live dial
			if (!o.used) { fill(o, 0, isTest, from, dialed, now); return {true, true, 0}; }
			return touch(o, now, true);
		}
		fill(*spare, ip, isTest, from, dialed, now);
		return {true, false, 0};
	}

	// One expired entry with a tally, cleared as it is returned. At most
	// kUnknownAlertMax + 2 are ever pending (the table plus the two overflow entries).
	bool takeExpired(std::chrono::steady_clock::time_point now, Due& out)
	{
		for (Entry& e : _e) if (due(e, now)) { give(e, false, out); return true; }
		for (Entry& o : _over) if (due(o, now)) { give(o, true, out); return true; }
		return false;
	}

	uint32_t overflow() const { return _overflow; }
	uint32_t suppressed() const { return _suppressed; }

#if !defined(ESP_PLATFORM) && !defined(ESP32) && !defined(ARDUINO)
	void ageForTest(std::chrono::steady_clock::duration d)
	{
		for (Entry& e : _e) e.since -= d;
		for (Entry& o : _over) o.since -= d;
	}
#endif

private:
	struct Entry
	{
		bool used = false;
		bool isTest = false;
		uint32_t ip = 0;
		std::chrono::steady_clock::time_point since{};
		uint32_t held = 0;
		char from[kFromLen + 1] = {};
		char dialed[kDialedLen + 1] = {};
	};

	static void copyTo(char* dst, std::size_t cap, std::string_view v)
	{
		const std::size_t n = std::min(v.size(), cap);
		std::copy(v.begin(), v.begin() + n, dst);
		dst[n] = '\0';
	}

	static void fill(Entry& e, uint32_t ip, bool isTest, std::string_view from, std::string_view dialed,
		std::chrono::steady_clock::time_point now)
	{
		e.used = true; e.isTest = isTest; e.ip = ip; e.since = now; e.held = 0;
		copyTo(e.from, kFromLen, from);
		copyTo(e.dialed, kDialedLen, dialed);
	}

	Verdict touch(Entry& e, std::chrono::steady_clock::time_point now, bool overflow)
	{
		if (now - e.since < kUnknownAlertWindow)
		{
			if (e.held < UINT32_MAX) ++e.held;
			if (!overflow) ++_suppressed;
			return {false, overflow, 0};
		}
		const Verdict v{true, overflow, e.held};   // window over: announce again, with the tally
		e.since = now;
		e.held = 0;
		return v;
	}

	static bool due(const Entry& e, std::chrono::steady_clock::time_point now)
	{
		return e.used && e.held != 0 && now - e.since >= kUnknownAlertWindow;
	}

	static void give(Entry& e, bool overflow, Due& out)
	{
		out.overflow = overflow;
		out.isTest = e.isTest;
		copyTo(out.from, kFromLen, e.from);
		copyTo(out.dialed, kDialedLen, e.dialed);
		out.held = e.held;
		e.held = 0;   // keeps its window start: the next dial renotifies as usual
	}

	// The oldest expired entry with no tally pending. One with a tally waits for
	// takeExpired(), so a slot is never reused before its summary has gone out.
	Entry* reclaimExpired(std::chrono::steady_clock::time_point now)
	{
		Entry* oldest = nullptr;
		for (Entry& e : _e)
			if (now - e.since >= kUnknownAlertWindow && e.held == 0 && (!oldest || e.since < oldest->since)) oldest = &e;
		return oldest;
	}

	std::array<Entry, kUnknownAlertMax> _e{};
	std::array<Entry, 2> _over{};   // [0] 911, [1] 933
	uint32_t _overflow = 0;
	uint32_t _suppressed = 0;
};

} // namespace pbx

#endif // EMERGENCY_CALL_HPP
