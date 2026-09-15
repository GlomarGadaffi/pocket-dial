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

#include <string_view>

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

} // namespace pbx

#endif // EMERGENCY_CALL_HPP
