#ifndef CALL_FORKER_HPP
#define CALL_FORKER_HPP

#include <memory>
#include <string>
#include <vector>

#include "ParkOrbit.hpp"
#include "PbxConfig.hpp"
#include "PbxEnv.hpp"
#include "PbxFeatureConfig.hpp"

class SipMessage;
class SipClient;
class Session;

// ── Fork / group / dial-plan routing engine, extracted out of RequestsHandler ─
// Everything that turns a resolved routing decision (a target client, a ring
// group, a page zone, a dial-plan rule) into forked/redirected/cancelled INVITE
// traffic: the shared broadcast-fork core used by 999 and ring-all groups, the
// sequential hunt-group walker, blind-transfer/call-forward redirect, and the
// CANCEL builder for abandoned forks. Every method assumes the caller holds
// the engine's _mutex, same convention as every other extracted machine.
//
// Takes PbxEnv& (enqueue/messageFromPool.../localIp/serverPort/findRegistered/
// findSession/allocSession/insertSession — all pre-existing virtuals, none
// added for this move), PbxFeatureConfig& for the dial-plan/ring-group/page-
// zone lookups routeDialPlan needs, and ParkOrbit& because routeDialPlan's
// ParkOrbit dial-plan action reaches _park.orbitIndex()/_park.onInvite()
// directly — a sibling machine passed by reference, same pattern as _cfg/_cdr
// elsewhere, not a new PbxEnv virtual.
class CallForker
{
public:
	CallForker(PbxEnv& env, PbxFeatureConfig& cfg, ParkOrbit& park) :
		_env(env), _cfg(cfg), _park(park) {}

	// Build and queue a single INVITE fork toward one target, re-pointing the
	// request line / To at that target. `intercom` toggles the auto-answer
	// headers. Caller holds _mutex. Returns false when the message pool
	// refused: no INVITE was sent, so the caller must not report success on
	// its behalf (#101A).
	bool buildInviteFork(const std::shared_ptr<SipMessage>& invite,
		const std::shared_ptr<SipClient>& caller,
		const std::shared_ptr<SipClient>& target,
		bool intercom);

	// Fan an INVITE out to a set of targets (the reusable core extracted from
	// the 999 all-page path). `targets` are pre-selected registered clients
	// (target selection itself stays in the caller — see onInvite's 999
	// branch, which walks its own client pool and passes the result in);
	// `intercom` adds the 999 auto-answer headers (true for 999, false for a
	// ring group so it rings normally). Builds the broadcast Session, the 180
	// Ringing to the caller, and one forked INVITE per target. Caller holds
	// _mutex.
	void startBroadcastFork(std::shared_ptr<SipMessage> invite,
		std::shared_ptr<SipClient> caller,
		const std::vector<std::shared_ptr<SipClient>>& targets,
		bool intercom);

	// Drive the next leg of a sequential hunt group (ring one member, arm
	// timeout). Returns false when the member list is exhausted. Caller
	// holds _mutex.
	bool huntRingNext(const std::shared_ptr<Session>& session);

	// Re-target an INVITE at `target` and (re)send it as a fresh call leg —
	// the engine behind blind-transfer and call-forward "redirect" paths.
	// Caller holds _mutex. Returns false if the target is not registered.
	bool redirectInvite(const std::shared_ptr<SipMessage>& invite,
		const std::shared_ptr<SipClient>& caller,
		const std::string& target);

	// Build a CANCEL for an outstanding forked INVITE leg toward `target`,
	// derived from the original INVITE (same Call-ID / branch). Caller holds
	// _mutex.
	std::shared_ptr<SipMessage> buildCancel(const std::shared_ptr<SipMessage>& invite,
		const std::shared_ptr<SipClient>& target);

	// The two "route this INVITE to an already-shipped action" bodies, lifted
	// verbatim out of onInvite()'s built-in 98x / ring-group branches so the
	// dial plan can reach the same code instead of duplicating it. Both take
	// the action target EXPLICITLY rather than reading it back off the
	// INVITE's To-number, because under a dial rule the dialed number and the
	// group/zone extension are no longer the same string. Both always answer
	// the caller (fork, 480, or 503) and so are terminal for the INVITE.
	// Caller holds _mutex.
	void routePageZone(const std::shared_ptr<SipMessage>& data,
		const std::shared_ptr<SipClient>& caller,
		const pbx::PageZone& zone);
	void routeRingGroup(const std::shared_ptr<SipMessage>& data,
		const std::shared_ptr<SipClient>& caller,
		const std::string& groupExt, const pbx::RingGroup& group);

	// Evaluate the dial plan against the dialed number. Returns true if a
	// rule matched and the INVITE was fully handled (onInvite must return);
	// false means no rule matched and routing falls through to the unchanged
	// extension-lookup path. Caller holds _mutex.
	bool routeDialPlan(const std::shared_ptr<SipMessage>& data,
		const std::shared_ptr<SipClient>& caller,
		const std::string& destNumber);

	// The rule routeDialPlan() applies to `dialed`: DialPlan::match(), except
	// that a WILDCARD Trunk rule whose transform makes an emergency number of
	// `dialed` does not match a number findRegistered() resolves. desmo, #877:
	// "Only wildcard rules yield": a literal rule (0 -> 911) always fires, so a
	// phone that registers 0 cannot take it over; every other rule keeps #69's
	// order. RequestsHandler::dialRuleMakesEmergency() asks this too, so its
	// mirror and this router agree. Caller holds _mutex.
	const pbx::DialRule* matchDialRule(const std::string& dialed) const;

private:
	PbxEnv& _env;
	PbxFeatureConfig& _cfg;
	ParkOrbit& _park;
};

#endif
