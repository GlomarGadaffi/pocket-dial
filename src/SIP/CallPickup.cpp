// CallPickup.cpp: directed/group call pickup completion, extracted out of
// RequestsHandler.
#include "CallPickup.hpp"
#include "SipWireUtil.hpp"

#include "IDGen.hpp"
#include "Session.hpp"
#include "SipClient.hpp"
#include "SipMessage.hpp"
#include "SipMessagePool.hpp"
#include "SipMessageTypes.h"

void CallPickup::complete(const std::shared_ptr<SipMessage>& data,
	const std::shared_ptr<SipClient>& picker,
	const std::shared_ptr<Session>& ringing,
	const std::string& ringingCallId,
	const std::string& ringingExt)
{
	auto reject486 = [&]()
	{
		auto resp = sipmsgpool::getMessageFromPool(*data);
		if (!resp) return;   // pool exhausted: drop, peer retransmits (#101A)
		resp->setHeader(SipMessageTypes::BUSY);
		resp->clearBody();
		resp->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		resp->setContact(_env.contactFor(picker->getNumber()));
		_env.enqueue(data->getSource(), std::move(resp));
	};

	if (!ringing)
	{
		// Nothing eligible is ringing right now (wrong/no pickup group, no
		// ringing call for a directed target, or the race already lost — see
		// onOk's late-answer guard). Acceptance criterion: 486, never a hang.
		reject486();
		return;
	}

	auto originalCaller = ringing->getSrc();
	auto invite = ringing->getInviteMessage();
	if (!originalCaller || !invite || !invite->hasSdp() || !data->hasSdp())
	{
		// Can't build a valid P2P O/A without both SDPs — decline cleanly
		// rather than half-connect the call.
		reject486();
		return;
	}

	// Draw the picker's session and BOTH 200 OKs before mutating anything
	// (#101A / #71 discipline): a refusal here must leave the original call
	// still ringing, not half-torn-down.
	auto pickerSession = _env.allocSession(std::string(data->getCallID()), picker);
	if (!pickerSession)
	{
		auto resp = sipmsgpool::getMessageFromPool(*data);
		if (resp)
		{
			resp->setHeader("SIP/2.0 503 Service Unavailable");
			resp->clearBody();
			resp->setContact(_env.contactFor(picker->getNumber()));
			_env.enqueue(data->getSource(), std::move(resp));
		}
		return;
	}
	auto okToCaller = sipmsgpool::getMessageFromPool(*invite);
	if (!okToCaller) return;   // pool exhausted: drop, original call keeps ringing (#101A)
	auto okToPicker = sipmsgpool::getMessageFromPool(*data);
	if (!okToPicker) return;   // pool exhausted: drop, original call keeps ringing (#101A)

	// ── Cancel every other still-ringing fork of the picked-up call ─────────
	if (ringing->isBroadcast())
	{
		for (const auto& t : ringing->getPendingTargets())
		{
			auto cancel = _forker.buildCancel(invite, t);
			if (cancel) _env.enqueue(t->getAddress(), std::move(cancel));
		}
		ringing->setPendingTargets({});
	}
	else if (auto target = _env.findRegistered(ringingExt))
	{
		auto cancel = _forker.buildCancel(invite, target);
		if (cancel) _env.enqueue(target->getAddress(), std::move(cancel));
	}
	ringing->clearRingTimer();

	// ── Complete the caller's original (still-open) INVITE transaction with
	// the picker's SDP as the answer ────────────────────────────────────────
	const std::string callerToTag = IDGen::GenerateID(9);
	std::string callerTo(invite->getTo());
	callerTo += ";tag=" + callerToTag;

	okToCaller->setHeader(SipMessageTypes::OK);
	okToCaller->setVia(sipwire::viaWithReceived(invite->getVia(), invite->getSource()));
	okToCaller->setTo(callerTo);
	okToCaller->setContact(_env.contactFor(picker->getNumber()));
	okToCaller->setBody(std::string(data->getBody()));
	(void)okToCaller->filterAudioCodecs(/*allowWideband=*/true);
	okToCaller->syncContentLength();

	// ── Answer the picker's own INVITE with the caller's original SDP ───────
	const std::string pickerToTag = IDGen::GenerateID(9);
	std::string toForPicker(data->getTo());
	toForPicker += ";tag=" + pickerToTag;

	okToPicker->setHeader(SipMessageTypes::OK);
	okToPicker->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
	okToPicker->setTo(toForPicker);
	okToPicker->setContact(_env.contactFor(ringingExt));
	okToPicker->setBody(std::string(invite->getBody()));
	(void)okToPicker->filterAudioCodecs(/*allowWideband=*/true);
	okToPicker->syncContentLength();

	// ── Bridge the two independent dialogs. Both legs are REAL registered
	// clients (unlike ParkOrbit's orbit stand-in), so neither session needs a
	// virtual peer — but the Call-IDs still differ, so peerCallID + the
	// dialog headers captured here are what let onBye's peerCallID branch
	// translate a hangup on one leg into a correctly-addressed BYE on the
	// other's own dialog. ──────────────────────────────────────────────────
	ringing->setDest(picker);
	ringing->setLocalTag(callerToTag);
	ringing->setState(Session::State::Connected);
	ringing->setPeerCallID(std::string(data->getCallID()));
	ringing->setDialogHeaders(std::string(invite->getFrom()), callerTo);

	pickerSession->setDest(originalCaller);
	pickerSession->setInviteMessage(data);
	pickerSession->setLocalTag(pickerToTag);
	pickerSession->setPeerCallID(ringingCallId);
	pickerSession->setDialogHeaders(std::string(data->getFrom()), toForPicker);
	pickerSession->setState(Session::State::Connected);
	_env.insertSession(std::string(data->getCallID()), pickerSession);

	_env.enqueue(originalCaller->getAddress(), std::move(okToCaller));
	_env.enqueue(data->getSource(), std::move(okToPicker));

	_env.log("Pickup: " + picker->getNumber() + " picked up " + ringingExt +
		"'s ringing call from " + originalCaller->getNumber());
}
