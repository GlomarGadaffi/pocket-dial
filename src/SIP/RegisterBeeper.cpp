#include "RegisterBeeper.hpp"

#include <sstream>

#include "IDGen.hpp"
#include "SipHeaderUtil.hpp"
#include "SipMessageTypes.h"
#include "SipWireUtil.hpp"

using sipwire::addrToIpPort;

RegisterBeeper::BeepDialog* RegisterBeeper::findByCallID(std::string_view callID)
{
	// Callers hand us SipMessage::getCallID(), which returns the FULL header line
	// ("Call-ID: x@host"), while slot.callID holds the bare id we generated in
	// sendBeep(). Normalise before comparing — matching the raw line against the
	// bare id never succeeded, so an answered beep was never ACKed or BYEd and
	// sweep() went on to CANCEL an INVITE that already had a final response.
	const std::string key = siphdr::stripHeaderName(callID);
	for (auto& bd : _dialogs)
	{
		if (bd.state != BeepState::Free && bd.callID == key)
		{
			return &bd;
		}
	}
	return nullptr;
}

void RegisterBeeper::sendBeep(const std::shared_ptr<SipClient>& phone)
{
	if (!phone || phone->getNumber().empty())
	{
		return;
	}

	// Grab a free beep slot. Full table → skip (cosmetic); no leak, no blocking.
	BeepDialog* slot = nullptr;
	for (auto& bd : _dialogs)
	{
		if (bd.state == BeepState::Free) { slot = &bd; break; }
	}
	if (!slot)
	{
		_env.log("Register beep: table full, skipping beep for " + phone->getNumber());
		return;
	}

	std::string clientNum = phone->getNumber();
	const sockaddr_in& addr = phone->getAddress();
	std::string destIpPort = addrToIpPort(addr);

	std::string activeIp = _env.localIp();
	std::string srcIpPort = activeIp + ":" + std::to_string(_env.serverPort());

	std::string callId  = IDGen::GenerateID(16) + "@" + activeIp;
	std::string branch  = "z9hG4bK" + IDGen::GenerateID(12);
	std::string fromTag = IDGen::GenerateID(9);

	// Record the dialog BEFORE sending so a (synchronous) response can never race
	// ahead of the bookkeeping.
	slot->state    = BeepState::AwaitingInviteOk;
	slot->callID   = callId;
	slot->branch   = branch;
	slot->fromTag  = fromTag;
	slot->ext      = clientNum;
	slot->addr     = addr;
	slot->deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);

	// Minimal, well-formed SDP. a=inactive: no RTP will flow (server sources none).
	const std::string body = sipwire::makeInactiveHoldSdp(activeIp);

	std::ostringstream ss;
	ss << "INVITE sip:" << clientNum << "@" << destIpPort << " SIP/2.0\r\n"
	   << "Via: SIP/2.0/UDP " << srcIpPort << ";branch=" << branch << "\r\n"
	   << "From: \"PocketDial\" <sip:pbx@" << srcIpPort << ">;tag=" << fromTag << "\r\n"
	   << "To: <sip:" << clientNum << "@" << activeIp << ">\r\n"
	   << "Call-ID: " << callId << "\r\n"
	   << "CSeq: 1 INVITE\r\n"
	   << "Max-Forwards: 70\r\n"
	   << "Contact: <sip:pbx@" << srcIpPort << ";transport=UDP>\r\n"
	   // Auto-answer / intercom headers — identical intent to the 999 all-page fork:
	   // make a Yealink auto-answer in intercom mode and so play its alert tone.
	   << "Call-Info: <sip:any>;answer-after=0\r\n"
	   << "Alert-Info: info=alert-autoanswer\r\n"
	   << "Alert-Info: answer-after=0\r\n"
	   << "Alert-Info: intercom=true\r\n"
	   << "P-Auto-Answer: normal\r\n"
	   << "User-Agent: pocket-dial\r\n"
	   << "Content-Type: application/sdp\r\n"
	   << "Content-Length: " << body.size() << "\r\n\r\n"
	   << body;

	auto invite = _env.messageFromPool(ss.str(), addr);
	if (!invite) return;   // pool exhausted: drop, peer retransmits (#101A)
	// (Re)derive Content-Length from the actual body — a wrong Content-Length
	// silently breaks the offer on UDP (the 777-path bug). No enforceG711(): the
	// body above is already this server's own minimal offer, and enforceG711()
	// rewrote its m= line to "0 8 101", advertising a dynamic PT 101 with no
	// a=rtpmap line. RFC 4566 §6 requires one, and pjsip answers the beep INVITE
	// with 400 Bad SDP because of it. Nothing wants a telephone-event PT here
	// anyway: the offer is a=inactive on port 9 — no media rides it.
	invite->syncContentLength();
	_env.enqueue(addr, std::move(invite));
	_env.log("Register beep: INVITE -> " + clientNum);
}

bool RegisterBeeper::handleOk(const std::shared_ptr<SipMessage>& data)
{
	// Register-beep dialogs (server-originated UAC) have NO Session — they are
	// tracked here by Call-ID. A 200 OK to our INVITE means the phone auto-answered
	// (the tone played): ACK it, then BYE to end the call. A 200 OK to our BYE just
	// frees the slot.
	BeepDialog* bd = findByCallID(data->getCallID());
	if (!bd)
	{
		return false;
	}

	std::string cseq(data->getCSeq());
	// AwaitingCancelDone included: RFC 3261 §9.1 lets the phone's 200 OK race an
	// in-flight CANCEL past the point the CANCEL had any effect. When that
	// happens the call was genuinely answered, so ACK+BYE it exactly as the
	// no-race path does — matching only AwaitingInviteOk here would let this OK
	// fall through unrecognized (a beep dialog has no Session) and leave it
	// neither ACKed nor BYEd.
	if ((bd->state == BeepState::AwaitingInviteOk || bd->state == BeepState::AwaitingCancelDone) &&
		cseq.find(SipMessageTypes::INVITE) != std::string::npos)
	{
		const bool racedCancel = (bd->state == BeepState::AwaitingCancelDone);
		auto ack = buildAck(*bd, data);
		if (ack) _env.enqueue(bd->addr, std::move(ack));
		auto bye = buildBye(*bd, data);
		if (!bye)
		{
			// The pool refused the BYE. Do NOT advance to AwaitingByeOk: sweep()
			// would then free the slot on its deadline having never sent a BYE,
			// leaving the phone off-hook in a call the PBX has forgotten. Staying
			// in the current state lets the phone's 200 OK retransmit re-enter here
			// and retry the teardown (#101A).
			_env.log("Register beep: " + bd->ext + " — pool exhausted, BYE deferred", true);
			return true;
		}
		_env.enqueue(bd->addr, std::move(bye));
		bd->state    = BeepState::AwaitingByeOk;
		// Re-arm the deadline so a phone that never 200s our BYE still frees its
		// slot from sweep() rather than lingering until the original INVITE timeout.
		bd->deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
		_env.log("Register beep: " + bd->ext + (racedCancel
			? " answered after our CANCEL had already gone out — ACK+BYE sent"
			: ", ACK+BYE sent"));
	}
	else if (cseq.find(SipMessageTypes::BYE) != std::string::npos)
	{
		*bd = BeepDialog{};   // BYE acknowledged: dialog fully torn down, free slot
	}
	// Anything else with a matching Call-ID (e.g. the 200 OK to our own CANCEL)
	// is absorbed here without action — still "ours", just nothing to do — so it
	// falls through neither ACKed/BYEd nor to a session lookup that would never
	// find one.
	return true;
}

void RegisterBeeper::sweep(std::chrono::steady_clock::time_point now)
{
	// Any beep dialog whose deadline has passed without the phone answering
	// (AwaitingInviteOk) gets a CANCEL. A dialog still awaiting the 200-to-BYE, or
	// one whose CANCEL fallback window (below) has expired, just frees its slot.
	for (std::size_t i = 0; i < _dialogs.size(); ++i)
	{
		auto& bd = _dialogs[i];
		if (bd.state == BeepState::Free || now < bd.deadline)
		{
			continue;
		}
		if (bd.state == BeepState::AwaitingInviteOk)
		{
			// Send the CANCEL, but do NOT free the slot yet. RFC 3261 §9.1: the UAS
			// may have already sent its 200 OK before processing this CANCEL, in
			// which case the CANCEL has no effect and the call was genuinely
			// answered. Keep matching this Call-ID for a bounded window so
			// handleOk() can still catch that race (see AwaitingCancelDone there);
			// freeing immediately is what let a raced 200 OK go unACKed/unBYEd,
			// with sweep() then CANCELling an INVITE that already had a final
			// response five seconds later. The dialog's own 487 (if the CANCEL
			// really did land in time) is routed to onReqTerminated, not here — it
			// has no Session to key off, so we just fall through to the same
			// bounded fallback below rather than acting on it there too.
			auto cancel = buildCancel(i);
			if (cancel)
			{
				_env.enqueue(bd.addr, std::move(cancel));
				_env.log("Register beep: no answer from " + bd.ext + ", cancelled");
				bd.state    = BeepState::AwaitingCancelDone;
				bd.deadline = now + std::chrono::seconds(5);
			}
			else if (++bd.cancelRetries < kMaxCancelRetries)
			{
				// buildCancel() couldn't get a pool slot (Issue #101(A) territory —
				// precisely the flood conditions under which an operator reads these
				// logs). Do NOT claim a CANCEL went out, and do NOT advance to
				// AwaitingCancelDone: that state means "a CANCEL is in flight, keep
				// matching this Call-ID for a raced 200 OK", which would be a lie
				// here and would abandon the dialog in a half-cancelled limbo where
				// nothing ever CANCELs it and the phone rings forever. Stay in
				// AwaitingInviteOk so the next sweep() retries the CANCEL — once pool
				// pressure eases the retry succeeds and follows the normal path
				// above. Retry after a short, bounded delay (not every tick) so
				// sustained pool exhaustion doesn't spin this slot.
				_env.log("Register beep: no answer from " + bd.ext +
					", cancel build failed — will retry");
				bd.deadline = now + std::chrono::seconds(1);
			}
			else
			{
				// kMaxCancelRetries consecutive failures: pool pressure hasn't let
				// up in ~5s of retrying. Give up on this slot rather than retrying
				// forever — free it like any other abandoned dialog. The phone
				// never got CANCELled, but it will simply ring out on its own
				// timeout; better than pinning a beeper slot indefinitely under
				// sustained load.
				_env.log("Register beep: no answer from " + bd.ext +
					", cancel build failed repeatedly — giving up, slot freed", true);
				bd = BeepDialog{};
			}
			continue;
		}
		bd = BeepDialog{};   // AwaitingByeOk / AwaitingCancelDone fallback: free the slot
	}
}

bool RegisterBeeper::handleInviteFailure(const std::shared_ptr<SipMessage>& data)
{
	BeepDialog* bd = findByCallID(data->getCallID());
	if (!bd)
	{
		return false;
	}

	// Only the INVITE transaction takes an ACK. A failure to our BYE (or to the
	// CANCEL) has nothing to acknowledge — the dialog is over either way, so the
	// slot is simply released.
	const std::string cseq(data->getCSeq());
	if (cseq.find(SipMessageTypes::INVITE) != std::string::npos &&
		(bd->state == BeepState::AwaitingInviteOk || bd->state == BeepState::AwaitingCancelDone))
	{
		// buildAck() already stamps the INVITE's Call-ID/branch/From-tag and takes
		// the To tag off the response, which is exactly what §17.1.1.3 wants for a
		// non-2xx ACK — it travels in the same transaction as the INVITE.
		auto ack = buildAck(*bd, data);
		if (!ack)
		{
			// Pool exhausted. Stay in this state so the phone's retransmitted
			// failure response re-enters here and retries the ACK (#101A); the
			// deadline still frees the slot if it never does.
			_env.log("Register beep: " + bd->ext + " — pool exhausted, ACK of "
				+ std::string(data->getHeader()) + " deferred", true);
			return true;
		}
		_env.log("Register beep: " + bd->ext + " declined the beep ("
			+ std::string(data->getHeader()) + ") — ACKed, slot freed");
		_env.enqueue(bd->addr, std::move(ack));
	}
	*bd = BeepDialog{};
	return true;
}

std::shared_ptr<SipMessage> RegisterBeeper::buildAck(const BeepDialog& bd,
	const std::shared_ptr<SipMessage>& ok)
{
	// ACK the phone's 200 OK to our beep INVITE (RFC 3261 §13.2.2.4 / §17.1.1.3).
	// Same Call-ID/branch/From-tag as the INVITE; To carries the phone's tag from the
	// 200. CSeq stays "1 ACK" (matches the INVITE transaction). No body.
	const std::string destIpPort = addrToIpPort(bd.addr);
	const std::string srcIpPort = _env.localIp() + ":" + std::to_string(_env.serverPort());

	std::ostringstream ss;
	ss << "ACK sip:" << bd.ext << "@" << destIpPort << " SIP/2.0\r\n"
	   << "Via: SIP/2.0/UDP " << srcIpPort << ";branch=" << bd.branch << "\r\n"
	   << "From: \"PocketDial\" <sip:pbx@" << srcIpPort << ">;tag=" << bd.fromTag << "\r\n"
	   << "To: " << siphdr::stripHeaderName(ok->getTo()) << "\r\n"
	   << "Call-ID: " << bd.callID << "\r\n"
	   << "CSeq: 1 ACK\r\n"
	   << "Max-Forwards: 70\r\n"
	   << "Content-Length: 0\r\n\r\n";

	return _env.messageFromPool(ss.str(), bd.addr);
}

std::shared_ptr<SipMessage> RegisterBeeper::buildBye(const BeepDialog& bd,
	const std::shared_ptr<SipMessage>& ok)
{
	// BYE to end the beep call immediately after the tone. Delegated to the engine's
	// one server-BYE builder (PbxEnv::serverBye) so hardening applied there — CSeq 2
	// BYE, header-name stripping, Max-Forwards policy — reaches the beep teardown
	// too, exactly as ParkOrbit::byeParkedParty does. To carries the phone's tag.
	const std::string srcIpPort = _env.localIp() + ":" + std::to_string(_env.serverPort());
	const std::string fromHeader =
		"\"PocketDial\" <sip:pbx@" + srcIpPort + ">;tag=" + bd.fromTag;
	return _env.serverBye(bd.ext, bd.addr, bd.callID,
		fromHeader, std::string(ok->getTo()));
}

std::shared_ptr<SipMessage> RegisterBeeper::buildCancel(std::size_t slot)
{
	// CANCEL the outstanding beep INVITE when the phone never auto-answered. Same
	// Call-ID/branch/From-tag as the INVITE; To has NO tag yet (no final response).
	// CSeq method becomes CANCEL but keeps the INVITE sequence number (RFC 3261 §9.1).
	if (slot >= _dialogs.size())
	{
		return nullptr;
	}
	BeepDialog& bd = _dialogs[slot];

	std::string destIpPort = addrToIpPort(bd.addr);
	std::string activeIp = _env.localIp();
	std::string srcIpPort = activeIp + ":" + std::to_string(_env.serverPort());

	std::ostringstream ss;
	ss << "CANCEL sip:" << bd.ext << "@" << destIpPort << " SIP/2.0\r\n"
	   << "Via: SIP/2.0/UDP " << srcIpPort << ";branch=" << bd.branch << "\r\n"
	   << "From: \"PocketDial\" <sip:pbx@" << srcIpPort << ">;tag=" << bd.fromTag << "\r\n"
	   << "To: <sip:" << bd.ext << "@" << activeIp << ">\r\n"
	   << "Call-ID: " << bd.callID << "\r\n"
	   << "CSeq: 1 CANCEL\r\n"
	   << "Max-Forwards: 70\r\n"
	   << "Content-Length: 0\r\n\r\n";

	return _env.messageFromPool(ss.str(), bd.addr);
}
