// CallForker.cpp: the fork/group/dial-plan routing engine, extracted out of
// RequestsHandler.
#include "CallForker.hpp"

#include <chrono>

#include "DialPlan.hpp"
#include "IDGen.hpp"
#include "Session.hpp"
#include "SipClient.hpp"
#include "SipHeaderUtil.hpp"
#include "SipMessage.hpp"
#include "SipMessagePool.hpp"
#include "SipMessageTypes.h"
#include "SipWireUtil.hpp"

bool CallForker::buildInviteFork(const std::shared_ptr<SipMessage>& invite,
	const std::shared_ptr<SipClient>& caller,
	const std::shared_ptr<SipClient>& target,
	bool intercom)
{
	auto inviteFork = sipmsgpool::getMessageFromPool(*invite);
	// Returns bool because callers report success on this function's behalf —
	// huntRingNext arms a 20 s no-answer timer, redirectInvite NOTIFYs the
	// transferor. A silent void return had them announcing an INVITE that was
	// never sent (#101A).
	if (!inviteFork) return false;
	inviteFork->setContact(_env.contactFor(caller->getNumber()));

	std::string activeIp = _env.localIp();
	std::string targetIpPort = sipwire::addrToIpPort(target->getAddress());
	std::string serverIpPort = activeIp + ":" + std::to_string(_env.serverPort());

	inviteFork->setHeader("INVITE sip:" + target->getNumber() + "@" + targetIpPort + " SIP/2.0");
	inviteFork->setTo("To: <sip:" + target->getNumber() + "@" + serverIpPort + ">");

	if (intercom)
	{
		// Auto-answer / intercom headers — used by 999 all-page only. A ring group
		// omits these so members ring normally (the caller can be picked up by hand).
		inviteFork->addHeader("Call-Info", "<sip:any>;answer-after=0");
		inviteFork->addHeader("Alert-Info", "info=alert-autoanswer");
		inviteFork->addHeader("Alert-Info", "answer-after=0");
		inviteFork->addHeader("Alert-Info", "intercom=true");
		inviteFork->addHeader("P-Auto-Answer", "normal");
	}
	// Caller's offer relayed peer-to-peer: preserve its preference order, drop
	// only unsupported payloads (onInvite already 488'd offers with nothing left).
	(void)inviteFork->filterAudioCodecs(/*allowWideband=*/true);
	_env.enqueue(target->getAddress(), std::move(inviteFork));
	return true;
}

void CallForker::startBroadcastFork(std::shared_ptr<SipMessage> invite,
	std::shared_ptr<SipClient> caller,
	const std::vector<std::shared_ptr<SipClient>>& targets,
	bool intercom)
{
	// Shared fan-out core: build the broadcast Session, send 180 Ringing to the
	// caller, then one forked INVITE per target. First answer wins; onOk() cancels
	// the losers (it walks getPendingTargets()). Used by 999 (intercom=true) and
	// ring-all groups (intercom=false).
	auto newSession = _env.allocSession(std::string(invite->getCallID()), caller);
	if (!newSession)
	{
		std::shared_ptr<SipMessage> responseObj = sipmsgpool::getMessageFromPool(*invite);
		if (!responseObj) return;   // pool exhausted: drop, peer retransmits (#101A)
		responseObj->setHeader("SIP/2.0 503 Service Unavailable");
		responseObj->clearBody();
		responseObj->setContact(_env.contactFor(caller->getNumber()));
		_env.enqueue(invite->getSource(), std::move(responseObj));
		return;
	}
	std::string contactExt = intercom ? std::string("999") : std::string(invite->getToNumber());

	// Drawn BEFORE the session is published. Refusing after insertSession() would
	// register a session under this Call-ID with no target ever invited and —
	// unlike the hunt path — no ring timer for tick() to sweep, so it would sit
	// there permanently; the INVITE retransmit's duplicate insertSession() is a
	// silent no-op, so it would not replace the zombie either (#101A).
	auto ringing = sipmsgpool::getMessageFromPool(*invite);
	if (!ringing) return;   // pool exhausted: drop, peer retransmits (#101A)

	newSession->setBroadcast(true);
	newSession->setPendingTargets(targets);
	newSession->setInviteMessage(invite);
	_env.insertSession(std::string(invite->getCallID()), newSession);

	ringing->setHeader("SIP/2.0 180 Ringing");
	ringing->clearBody();
	std::string activeIp = _env.localIp();
	ringing->setVia(sipwire::viaWithReceived(invite->getVia(), invite->getSource()));
	ringing->setTo(std::string(invite->getTo()) + ";tag=" + IDGen::GenerateID(9));
	ringing->setContact(_env.contactFor(contactExt));
	_env.enqueue(invite->getSource(), std::move(ringing));

	for (auto& target : targets)
	{
		buildInviteFork(invite, caller, target, intercom);
	}
}

bool CallForker::huntRingNext(const std::shared_ptr<Session>& session)
{
	// Ring the next not-yet-tried hunt member. Returns false when the list is
	// exhausted (caller fails the call). The single ringing member is kept in
	// getPendingTargets() so onOk()/onCancel() can address it like a broadcast.
	auto& members = session->getHuntMembers();
	auto invite = session->getInviteMessage();
	auto caller = session->getSrc();
	if (!invite || !caller)
	{
		return false;
	}

	while (session->getHuntIndex() < members.size())
	{
		std::string ext = members[session->getHuntIndex()];
		session->setHuntIndex(session->getHuntIndex() + 1);

		auto mc = _env.findRegistered(ext);
		if (!mc)
		{
			continue;   // member went offline since the call started; skip it
		}

		session->setPendingTargets({ mc });
		if (!buildInviteFork(invite, caller, mc, /*intercom=*/false))
		{
			// Nothing was rung, so do NOT arm the no-answer timer — that would burn
			// the full timeout waiting on a member that never got an INVITE. Try
			// the next member instead (#101A).
			continue;
		}
		session->armRingTimer(std::chrono::steady_clock::now() + pbx::kNoAnswerTimeout);
		return true;
	}

	session->clearRingTimer();
	return false;
}

bool CallForker::redirectInvite(const std::shared_ptr<SipMessage>& invite,
	const std::shared_ptr<SipClient>& caller,
	const std::string& target)
{
	// Re-point an INVITE at `target` and send it as a fresh leg. Powers blind
	// transfer and the call-forward redirect paths. A new Session is allocated under
	// the SAME Call-ID so subsequent responses (180/200/BYE) route normally.
	auto targetClient = _env.findRegistered(target);
	if (!targetClient)
	{
		return false;
	}

	// Don't double-allocate if a session for this Call-ID already exists (e.g. CFU
	// from onInvite, which hasn't created one yet) — reuse or create as needed.
	std::shared_ptr<Session> session;
	auto existing = _env.findSession(invite->getCallID());
	if (existing)
	{
		session = existing;
		session->setDest(targetClient);
	}
	else
	{
		session = _env.allocSession(std::string(invite->getCallID()), caller);
		if (!session)
		{
			std::shared_ptr<SipMessage> responseObj = sipmsgpool::getMessageFromPool(*invite);
			// true, not false, even though nothing was sent. false here means
			// "target not registered — fall through", which on the CFU path would
			// ring the extension the subscriber explicitly forwarded away from, and
			// on the REFER path would report "target not registered" for a target
			// that is. The target WAS resolved; we just could not serve it. Same
			// answer as the 503 branch below (#101A).
			if (!responseObj) return true;
			responseObj->setHeader("SIP/2.0 503 Service Unavailable");
			responseObj->clearBody();
			responseObj->setContact(_env.contactFor(caller->getNumber()));
			_env.enqueue(invite->getSource(), std::move(responseObj));
			return true;   // we DID handle it (with a 503); target lookup succeeded
		}
		_env.insertSession(std::string(invite->getCallID()), session);
	}

	buildInviteFork(invite, caller, targetClient, /*intercom=*/false);
	return true;
}

std::shared_ptr<SipMessage> CallForker::buildCancel(const std::shared_ptr<SipMessage>& invite,
	const std::shared_ptr<SipClient>& target)
{
	// Build a CANCEL for an outstanding forked INVITE leg toward `target`, derived
	// from the original INVITE (same Call-ID / branch). Mirrors the inline CANCEL
	// construction used by onCancel()/onOk() for the 999 path.
	std::string activeIp = _env.localIp();
	std::string serverIpPort = activeIp + ":" + std::to_string(_env.serverPort());

	auto cancelMsg = sipmsgpool::getMessageFromPool(*invite);
	if (!cancelMsg) return nullptr;   // pool exhausted: propagate, caller drops (#101A)

	std::string targetIpPort = sipwire::addrToIpPort(target->getAddress());

	cancelMsg->setHeader("CANCEL sip:" + target->getNumber() + "@" + targetIpPort + " SIP/2.0");
	cancelMsg->setTo("To: <sip:" + target->getNumber() + "@" + serverIpPort + ">");

	std::string cseq(invite->getCSeq());
	size_t invitePos = cseq.find("INVITE");
	if (invitePos != std::string::npos)
	{
		cseq.replace(invitePos, 6, "CANCEL");
		cancelMsg->setCSeq(cseq);
	}
	cancelMsg->clearBody();
	return cancelMsg;
}

void CallForker::routePageZone(const std::shared_ptr<SipMessage>& data,
	const std::shared_ptr<SipClient>& caller,
	const pbx::PageZone& zone)
{
	// A zone page is a scoped 999: fork an intercom (auto-answer) INVITE to every
	// registered member of the zone. Lifted verbatim out of onInvite()'s 98x
	// branch so the dial plan reaches the same code. Unlike routeRingGroup this
	// needs no zone-extension parameter: startBroadcastFork stamps the intercom
	// Contact as 999 for every page, built-in or dial-rule-aliased alike, so the
	// zone's own extension never appears on the wire.
	std::vector<std::shared_ptr<SipClient>> targets;
	for (const auto& m : zone.members)
	{
		if (m == caller->getNumber()) continue;
		auto mc = _env.findRegistered(m);
		if (mc)
			targets.push_back(mc);
	}

	if (targets.empty())
	{
		std::shared_ptr<SipMessage> responseObj = sipmsgpool::getMessageFromPool(*data);
		if (!responseObj) return;   // pool exhausted: drop, peer retransmits (#101A)
		responseObj->setHeader(SipMessageTypes::UNAVAILABLE);
		responseObj->clearBody();
		responseObj->setContact(_env.contactFor(caller->getNumber()));
		_env.enqueue(data->getSource(), std::move(responseObj));
		return;
	}

	startBroadcastFork(data, caller, std::move(targets), /*intercom=*/true);
}

void CallForker::routeRingGroup(const std::shared_ptr<SipMessage>& data,
	const std::shared_ptr<SipClient>& caller,
	const std::string& groupExt, const pbx::RingGroup& group)
{
	// Ring-all reuses the broadcast fork (without the intercom auto-answer headers,
	// so members ring normally); hunt rings members one at a time, driven from
	// tick(). Lifted verbatim out of onInvite()'s ring-group branch. `groupExt` is
	// the REAL group extension — under a dial rule it differs from the dialed
	// number, and Session::setGroupExt feeds the hunt-exhausted CDR and the
	// no-answer Contact, both of which want the group's identity, not the alias.

	// Collect the registered members (skip the caller and any offline member).
	std::vector<std::shared_ptr<SipClient>> members;
	std::vector<std::string> huntOrder;
	for (const auto& m : group.members)
	{
		if (m == caller->getNumber()) continue;
		auto mc = _env.findRegistered(m);
		if (mc)
		{
			members.push_back(mc);
			huntOrder.push_back(m);
		}
	}

	if (members.empty())
	{
		std::shared_ptr<SipMessage> responseObj = sipmsgpool::getMessageFromPool(*data);
		if (!responseObj) return;   // pool exhausted: drop, peer retransmits (#101A)
		responseObj->setHeader(SipMessageTypes::UNAVAILABLE);
		responseObj->clearBody();
		responseObj->setContact(_env.contactFor(caller->getNumber()));
		// Was RequestsHandler::endHandle(data->getFromNumber(), responseObj) before
		// this move: endHandle's "clone + 404 if not registered" fallback could
		// never fire here — `caller` is already a resolved SipClient (a function
		// parameter), so re-resolving data->getFromNumber() through endHandle
		// cannot return "not registered." routePageZone's identical empty-targets
		// branch, three functions up, already enqueues directly for the same
		// reason. Observably identical: a registered caller's address IS
		// data->getSource().
		_env.enqueue(data->getSource(), std::move(responseObj));
		return;
	}

	if (group.mode == pbx::GroupMode::RingAll)
	{
		startBroadcastFork(data, caller, std::move(members), /*intercom=*/false);
		return;
	}

	// Hunt (sequential): build a broadcast-style session but ring one at a time.
	auto newSession = _env.allocSession(std::string(data->getCallID()), caller);
	if (!newSession)
	{
		std::shared_ptr<SipMessage> responseObj = sipmsgpool::getMessageFromPool(*data);
		if (!responseObj) return;   // pool exhausted: drop, peer retransmits (#101A)
		responseObj->setHeader("SIP/2.0 503 Service Unavailable");
		responseObj->clearBody();
		responseObj->setContact(_env.contactFor(caller->getNumber()));
		_env.enqueue(data->getSource(), std::move(responseObj));
		return;
	}
	newSession->setBroadcast(true);
	newSession->setHunt(true);
	newSession->setGroupExt(groupExt);
	newSession->setInviteMessage(data);
	newSession->setHuntMembers(std::move(huntOrder));
	newSession->setHuntIndex(0);
	_env.insertSession(std::string(data->getCallID()), newSession);

	// 180 Ringing back to the caller while we walk the list.
	auto ringing = sipmsgpool::getMessageFromPool(*data);
	if (!ringing) return;   // pool exhausted: drop, peer retransmits (#101A)
	ringing->setHeader("SIP/2.0 180 Ringing");
	ringing->clearBody();
	std::string activeIp = _env.localIp();
	ringing->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
	ringing->setTo(std::string(data->getTo()) + ";tag=" + IDGen::GenerateID(9));
	ringing->setContact(_env.contactFor(groupExt));
	_env.enqueue(data->getSource(), std::move(ringing));

	huntRingNext(newSession);   // ring the first member, arm its timeout
}

bool CallForker::routeDialPlan(const std::shared_ptr<SipMessage>& data,
	const std::shared_ptr<SipClient>& caller,
	const std::string& destNumber)
{
	// Fast path: the table is empty on a default install, so the overwhelmingly
	// common case costs one size check and nothing else.
	if (_cfg.dialPlan().empty())
	{
		return false;
	}

	const pbx::DialRule* rule = _cfg.dialPlan().match(destNumber);
	if (!rule)
	{
		return false;   // fallthrough — routing continues exactly as it did pre-#69
	}

	_env.log("Dial plan: " + destNumber + " matched \"" + rule->pattern + "\" -> " +
		pbx::dialActionName(rule->action) + " " + rule->target);

	switch (rule->action)
	{
	case pbx::DialActionType::RingGroup:
		if (const pbx::RingGroup* group = _cfg.findRingGroup(rule->target))
		{
			routeRingGroup(data, caller, rule->target, *group);
			return true;
		}
		break;

	case pbx::DialActionType::PageZone:
		if (const pbx::PageZone* zone = _cfg.findPageZone(rule->target))
		{
			routePageZone(data, caller, *zone);
			return true;
		}
		break;

	case pbx::DialActionType::ParkOrbit:
	{
		// Park/retrieve is stateless config-wise — the orbit always exists, so the
		// only way this fails is a target outside this build's orbit range, which
		// setDialRule() already refuses. Re-checked here anyway: POCKETDIAL_PARK_SLOTS
		// can shrink under a rebuilt firmware that reloads an older NVS blob.
		const int orbitIdx = _park.orbitIndex(rule->target);
		if (orbitIdx >= 0)
		{
			_park.onInvite(data, caller, orbitIdx);
			return true;
		}
		break;
	}
	}

	// The rule matched but its target no longer resolves — a group or zone deleted
	// after the rule was written, or an orbit outside this build's range. Answer
	// 404 rather than falling through: falling through would silently ring a real
	// extension that happens to share the dialed digits, which is a mis-routed
	// call, whereas a stale rule failing loudly is diagnosable from one 404.
	_env.log("Dial plan: rule \"" + rule->pattern + "\" -> " +
		pbx::dialActionName(rule->action) + " " + rule->target +
		" has no such target; answering 404", true);
	auto responseObj = sipmsgpool::getMessageFromPool(*data);
	if (!responseObj) return true;   // pool exhausted: drop, peer retransmits (#101A)
	responseObj->setHeader(SipMessageTypes::NOT_FOUND);
	responseObj->clearBody();
	responseObj->setContact(_env.contactFor(caller->getNumber()));
	_env.enqueue(data->getSource(), std::move(responseObj));
	return true;
}
