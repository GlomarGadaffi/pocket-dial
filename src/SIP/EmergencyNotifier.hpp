#ifndef EMERGENCY_NOTIFIER_HPP
#define EMERGENCY_NOTIFIER_HPP

// ── Kari's Law on-site notification (Issue #166 part 2) ──────────────────────
//
// US federal law (47 CFR 9.16(b)(2), from the Kari's Law Act of 2017) requires
// a multi-line telephone system to send a notification when 911 is dialed, to
// a central location at the facility or to someone able to act on it. 47 CFR
// 9.3's "MLTS Notification" definition fixes what it must carry: the fact a 911
// call was made, a valid callback number, and whatever location information the
// system conveys to the PSAP (the latter two excused where technically
// infeasible).
//
// The wording of the rule is paraphrased here deliberately rather than quoted:
// the research behind this could not retrieve verbatim eCFR text (302s and
// 403s), so nothing in this file should be cited as the letter of the law.
// The behaviour it drives is the conservative reading that four independent
// summaries agreed on.
//
// ── The ordering rule IS the compliance rule ─────────────────────────────────
//
// 9.16(b)(2) requires the notification to be contemporaneous with the call and
// to NOT delay it. That has an exact code form, and it is the single most
// important property of this class:
//
//   the emergency call leg is enqueued FIRST, then this runs, and no failure
//   path in here — pool exhaustion, an unregistered notify extension, an empty
//   config — can prevent, delay or reorder the call.
//
// RequestsHandler::routeEmergencyCall() calls notify() only after
// originateAnchorCall() has already taken the call, and everything here is
// best-effort by construction: nothing returns an error the caller acts on,
// nothing blocks, nothing retries. A test pins this by exhausting the message
// pool and asserting the 911 leg still routes.
//
// Because both the call leg and these notifications land in the same _outbox
// and leave on the same drainOutbox() pass, "contemporaneous" is satisfied
// literally rather than approximately.
//
// ── Fires even when the call FAILS ───────────────────────────────────────────
//
// A 911 attempt that could not be routed is the single most important thing to
// put in front of a human, so notify() runs on both paths and says which
// happened. The rule is about a call being PLACED, not about it succeeding.
//
// ── What it deliberately does not do ─────────────────────────────────────────
//
//   * No SMTP. SmtpClient::sendAndWait() blocks and its own contract forbids
//     calling it from a SIP thread; this runs on the SIP receive thread under
//     the engine mutex.
//   * No webhook. None exists in this firmware, and it would need an HTTP
//     client on a path that must not block.
//   * No delivery receipts, retries, retention or PSAP notification. None is
//     required by the rule, and each would add a failure mode to a path whose
//     whole value is that it cannot fail loudly enough to matter.
//   * No dispatchable location conveyed WITH the call. That is RAY BAUM'S Act
//     §506, a separate obligation, and it lives with the trunk provider rather
//     than here.

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

#include "PbxEnv.hpp"
#include "PoolConfig.hpp"

namespace pbx
{

// Hard cap on notify targets. Small on purpose: this is "the front desk and
// maybe security", not a paging list, and every entry costs a pooled message on
// the emergency path.
inline constexpr std::size_t kMaxE911NotifyExts = 4;

// Operator-set notification settings.
struct E911Config
{
	// Extensions to alert. Empty disables SIP notification (the syslog record
	// is still emitted — that one has no configuration and cannot be turned off).
	std::vector<std::string> notifyExts;

	// A number the PSAP can call back on. Nothing in this firmware's config
	// supplies one today: the anchor's routeDn is an origination DN and
	// DidMapping is inbound-only, so this is operator-set. When empty the
	// notification says so explicitly rather than omitting the field, because
	// "no callback configured" is itself something the person reading it needs
	// to know.
	std::string callback;

	// A free-text site/room string ("Front office, 2nd floor"). This is the
	// cheapest honest step toward a dispatchable location; it is NOT sent to the
	// PSAP and must not be presented as if it were.
	std::string location;
};

// The notification text, built as a pure function so it can be tested without
// a handler, a socket or a clock.
//
// One line, deliberately under the 512-byte body cap the MESSAGE path applies,
// mapped onto 9.3's three elements in the order a human scans them: what
// happened, who, how to reach back, where.
//
//   EMERGENCY: 911 dialed by ext 101 - ROUTED TO TRUNK - callback 5550100 - Front desk
//   TEST: 933 dialed by ext 101 - NOT ROUTED (no trunk) - callback not configured
//
// `routed` false produces the NOT ROUTED wording, which is the case that most
// needs a human. A test asserts the two are never confusable.
std::string formatE911Notification(bool isTest, std::string_view fromExt,
	std::string_view dialed, bool hadTrunkPrefix, bool routed,
	const E911Config& cfg);

} // namespace pbx

// Sends the notification. A sibling machine in the CallForker/RegisterBeeper
// mould: it reaches the engine only through PbxEnv, so it adds nothing to
// RequestsHandler's own surface beyond one member and one call.
//
// Locking: notify() assumes the caller holds the engine's _mutex, matching
// every other machine here. It takes no lock of its own and never blocks.
class EmergencyNotifier
{
public:
	explicit EmergencyNotifier(PbxEnv& env) : _env(env) {}

	// Fire the notification. Best-effort and total: it cannot fail in a way the
	// caller needs to handle, which is exactly what keeps it from ever standing
	// between a person and 911.
	//
	// Emits, in order:
	//   1. a syslog record at Alert severity, app "pbx-911". Unconditional,
	//      unconfigurable, and safe here (Syslog::send never blocks, never
	//      throws and is a no-op when unconfigured).
	//   2. one SIP MESSAGE per configured, currently-registered notify
	//      extension, enqueued onto the same outbox pass as the call leg.
	//
	// Returns how many MESSAGEs were enqueued, for tests and for the caller's
	// log line — NOT as a success/failure signal.
	std::size_t notify(const pbx::E911Config& cfg, bool isTest,
		std::string_view fromExt, std::string_view dialed,
		bool hadTrunkPrefix, bool routed);

private:
	// One MESSAGE to `ext`, or nullptr when the extension is not registered or
	// the message pool is exhausted. Lock-free by construction: it builds and
	// returns, and never touches the outbox itself.
	std::shared_ptr<SipMessage> buildNotifyMessage(const std::string& ext,
		const std::string& text, sockaddr_in& addrOut);

	PbxEnv& _env;
};

#endif // EMERGENCY_NOTIFIER_HPP
