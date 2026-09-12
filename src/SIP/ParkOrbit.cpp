#include "ParkOrbit.hpp"

#include <algorithm>
#include <sstream>

#include "IDGen.hpp"
#include "Session.hpp"
#include "SipHeaderUtil.hpp"
#include "SipMessageTypes.h"
#include "SipWireUtil.hpp"

using sipwire::addrToIpPort;

int ParkOrbit::orbitIndex(std::string_view ext) const
{
	if (ext.size() != 3 || ext[0] != '7' || ext[1] != '0') return -1;
	if (ext[2] < '0' || ext[2] > '9') return -1;
	int idx = ext[2] - '0';
	return (idx < static_cast<int>(_slots.size())) ? idx : -1;
}

void ParkOrbit::onInvite(const std::shared_ptr<SipMessage>& data,
	const std::shared_ptr<SipClient>& caller, int orbitIdx)
{
	if (orbitIdx < 0 || orbitIdx >= static_cast<int>(_slots.size()) || !caller)
	{
		return;
	}
	ParkSlot& slot = _slots[orbitIdx];
	const std::string& activeIp = _env.localIp();
	const std::string orbit = "70" + std::to_string(orbitIdx);
	const std::string toTag = IDGen::GenerateID(9);

	if (slot.state == ParkState::Free)
	{
		// ── PARK ── answer with an a=inactive hold SDP so the parked party is held.
		const std::string holdSdp = sipwire::makeInactiveHoldSdp(activeIp);
		auto ok = _env.messageFromPool(data->toString(), data->getSource());
		if (!ok) return;   // pool exhausted: drop, peer retransmits (#101A)
		ok->setHeader(SipMessageTypes::OK);
		ok->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		ok->setTo(std::string(data->getTo()) + ";tag=" + toTag);
		ok->setContact(_env.contactFor(orbit));
		ok->setBody(holdSdp);
		ok->syncContentLength();
		_env.enqueue(data->getSource(), ok);

		slot = ParkSlot{};
		slot.state      = ParkState::Parked;
		slot.orbit      = orbit;
		slot.callID     = std::string(data->getCallID());
		slot.parkedExt  = caller->getNumber();
		slot.parkedAddr = data->getSource();
		slot.parked        = true;
		slot.parkedSdp     = std::string(data->getBody());
		slot.parkedFromTag = siphdr::tagOf(data->getFrom());
		slot.localTag   = toTag;
		slot.parker     = caller->getNumber();
		slot.parkedAt   = std::chrono::steady_clock::now();
		_parkChanged    = true;

		// Both the stand-in peer and the session are required to track the parked
		// dialog; if either pool refuses, skip creating the session rather than
		// registering one with no dest (#101A). Same tolerance the allocSession
		// check already had — the slot is still parked and sweep() will time it out.
		auto virt = _env.allocVirtualPeer(orbit, data->getSource());
		if (auto session = virt ? _env.allocSession(std::string(data->getCallID()), caller) : nullptr)
		{
			session->setDest(virt);
			session->setLocalTag(toTag);
			session->setInviteMessage(data);
			// Captured now, used later: once this parked leg is retrieved (see
			// the RETRIEVE branch below) or rung back on timeout, onBye's
			// peerCallID branch needs this dialog's own From/To (with our
			// to-tag) to build a correctly-addressed BYE toward this party —
			// same convention as CallPickup::complete()'s setDialogHeaders().
			session->setDialogHeaders(std::string(data->getFrom()),
				std::string(data->getTo()) + ";tag=" + toTag);
			_env.insertSession(std::string(data->getCallID()), session);
			session->setState(Session::State::Connected);
		}
		_env.log("Park: " + caller->getNumber() + " parked on " + orbit);
		return;
	}

	// ── RETRIEVE ── the orbit is occupied: SDP-swap retrieve.
	// Allocate the retriever session FIRST (#71): if the pool is exhausted we 503
	// the retriever and leave the slot intact rather than sending a re-INVITE to
	// the parked party and then having no session to track the bridge.
	const std::string parkedSdp(slot.parkedSdp);
	const std::string retrieverSdp(data->getBody());

	auto virt = _env.allocVirtualPeer(slot.parkedExt, slot.parkedAddr);
	auto rsession = virt ? _env.allocSession(std::string(data->getCallID()), caller) : nullptr;
	// `virt` folded into the same rejection as a missing session (#101A): a
	// retrieve with no stand-in peer would bridge to nothing. Both are acquired
	// before any state changes, per #71 — the orbit slot is left intact.
	if (!rsession)
	{
		auto resp = _env.messageFromPool(data->toString(), data->getSource());
		if (!resp) return;   // pool exhausted: drop, peer retransmits (#101A)
		resp->setHeader("SIP/2.0 503 Service Unavailable");
		resp->clearBody();
		resp->syncContentLength();
		_env.enqueue(data->getSource(), std::move(resp));
		_env.log("Park: retrieve rejected — session pool exhausted", true);
		return;
	}

	auto ok = _env.messageFromPool(data->toString(), data->getSource());
	if (!ok) return;   // pool exhausted: drop, peer retransmits (#101A)
	ok->setHeader(SipMessageTypes::OK);
	ok->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
	ok->setTo(std::string(data->getTo()) + ";tag=" + toTag);
	ok->setContact(_env.contactFor(orbit));
	if (!parkedSdp.empty()) ok->setBody(parkedSdp);
	(void)ok->filterAudioCodecs(/*allowWideband=*/true);   // parked party's own SDP, relayed P2P
	ok->syncContentLength();
	_env.enqueue(data->getSource(), ok);

	rsession->setDest(virt);
	rsession->setPeerCallID(slot.callID);
	rsession->setLocalTag(toTag);
	rsession->setInviteMessage(data);
	// Issue #127: onBye's peerCallID branch (RequestsHandler.cpp) only relays a
	// BYE across the bridge when BOTH legs' dialog headers are captured — this
	// was the missing half (the parked leg gets its own setDialogHeaders() call
	// at park time, above). Same convention as CallPickup::complete().
	rsession->setDialogHeaders(std::string(data->getFrom()),
		std::string(data->getTo()) + ";tag=" + toTag);
	_env.insertSession(std::string(data->getCallID()), rsession);
	rsession->setState(Session::State::Connected);

	if (auto parked = _env.findSession(slot.callID))
	{
		parked->setPeerCallID(std::string(data->getCallID()));
	}
	sendReinvite(slot, retrieverSdp);
	_env.log("Park: " + caller->getNumber() + " retrieved " + slot.parkedExt + " from " + orbit);

	releaseSlot(slot);
}

void ParkOrbit::sendReinvite(ParkSlot& slot, const std::string& sdp)
{
	if (slot.callID.empty() || !slot.parked) return;
	const std::string& activeIp = _env.localIp();
	const std::string srcIpPort = activeIp + ":" + std::to_string(_env.serverPort());
	const std::string destIpPort = addrToIpPort(slot.parkedAddr);

	const std::string branch = "z9hG4bK" + IDGen::GenerateID(12);

	std::ostringstream ss;
	ss << "INVITE sip:" << slot.parkedExt << "@" << destIpPort << " SIP/2.0\r\n"
	   << "Via: SIP/2.0/UDP " << srcIpPort << ";branch=" << branch << "\r\n"
	   << "From: <sip:" << slot.orbit << "@" << srcIpPort << ">;tag=" << slot.localTag << "\r\n"
	   << "To: <sip:" << slot.parkedExt << "@" << activeIp << ">;tag=" << slot.parkedFromTag << "\r\n"
	   // slot.callID holds the FULL "Call-ID: x@host" header line (getCallID()
	   // returns the whole line), so strip the name back off before re-stamping it
	   // — otherwise the re-INVITE ships "Call-ID: Call-ID: x@host" and the parked
	   // phone never matches it to the dialog.
	   << "Call-ID: " << siphdr::stripHeaderName(slot.callID) << "\r\n"
	   << "CSeq: 2 INVITE\r\n"
	   << "Max-Forwards: 70\r\n"
	   << "Contact: <sip:" << slot.orbit << "@" << srcIpPort << ";transport=UDP>\r\n"
	   << "User-Agent: pocket-dial\r\n"
	   << "Content-Type: application/sdp\r\n"
	   << "Content-Length: " << sdp.size() << "\r\n\r\n"
	   << sdp;

	auto inv = _env.messageFromPool(ss.str(), slot.parkedAddr);
	if (!inv) return;   // pool exhausted: drop, peer retransmits (#101A)
	(void)inv->filterAudioCodecs(/*allowWideband=*/true);   // phone SDP relayed P2P
	inv->syncContentLength();
	_env.enqueue(slot.parkedAddr, std::move(inv));
	_pendingAcks.push_back(slot.callID);
	_env.log("Park: re-INVITE -> parked party " + slot.parkedExt);
}

void ParkOrbit::byeParkedParty(const ParkSlot& slot)
{
	if (slot.callID.empty()) return;
	const std::string& activeIp = _env.localIp();
	const std::string srcIpPort = activeIp + ":" + std::to_string(_env.serverPort());
	const std::string fromHeader = "<sip:" + slot.orbit + "@" + srcIpPort + ">;tag=" + slot.localTag;
	const std::string toHeader = "<sip:" + slot.parkedExt + "@" + activeIp + ">;tag=" + slot.parkedFromTag;
	auto bye = _env.serverBye(slot.parkedExt, slot.parkedAddr,
		siphdr::stripHeaderName(slot.callID), fromHeader, toHeader);
	if (bye) _env.enqueue(slot.parkedAddr, std::move(bye));
}

void ParkOrbit::startRingback(ParkSlot& slot, const std::shared_ptr<SipClient>& parker,
	std::chrono::steady_clock::time_point now)
{
	if (!parker) { byeParkedParty(slot); freeForCallId(slot.callID); return; }
	const std::string& activeIp = _env.localIp();
	const std::string srcIpPort = activeIp + ":" + std::to_string(_env.serverPort());
	const sockaddr_in& addr = parker->getAddress();
	const std::string destIpPort = addrToIpPort(addr);

	slot.rbCallID  = "Call-ID: " + IDGen::GenerateID(16) + "@" + activeIp;
	slot.rbFromTag = IDGen::GenerateID(9);
	slot.rbBranch  = "z9hG4bK" + IDGen::GenerateID(12);
	slot.rbAddr    = addr;
	slot.state     = ParkState::RingingBack;
	slot.deadline  = now + std::chrono::seconds(30);
	_parkChanged   = true;   // leaves the Parked view: the dashboard row must drop

	std::ostringstream ss;
	ss << "INVITE sip:" << parker->getNumber() << "@" << destIpPort << " SIP/2.0\r\n"
	   << "Via: SIP/2.0/UDP " << srcIpPort << ";branch=" << slot.rbBranch << "\r\n"
	   << "From: \"PocketDial Park\" <sip:" << slot.orbit << "@" << srcIpPort << ">;tag=" << slot.rbFromTag << "\r\n"
	   << "To: <sip:" << parker->getNumber() << "@" << activeIp << ">\r\n"
	   << slot.rbCallID << "\r\n"
	   << "CSeq: 1 INVITE\r\n"
	   << "Max-Forwards: 70\r\n"
	   << "Contact: <sip:" << slot.orbit << "@" << srcIpPort << ";transport=UDP>\r\n"
	   << "User-Agent: pocket-dial\r\n"
	   << "Content-Type: application/sdp\r\n"
	   << "Content-Length: " << slot.parkedSdp.size() << "\r\n\r\n"
	   << slot.parkedSdp;

	auto inv = _env.messageFromPool(ss.str(), addr);
	if (!inv) return;   // pool exhausted: drop, peer retransmits (#101A)
	(void)inv->filterAudioCodecs(/*allowWideband=*/true);   // phone SDP relayed P2P
	inv->syncContentLength();
	_env.enqueue(addr, std::move(inv));
	_env.log("Park: timeout on " + slot.orbit + " — ringing back parker " + parker->getNumber());
}

bool ParkOrbit::handleOk(const std::shared_ptr<SipMessage>& data)
{
	const std::string cseq(data->getCSeq());
	const std::string callID(data->getCallID());
	const bool isInviteOk = cseq.find(SipMessageTypes::INVITE) != std::string::npos;
	if (!isInviteOk) return false;

	// (a) 200 OK to a park re-INVITE sent to the parked party: ACK and free tracking entry.
	if (auto it = std::find(_pendingAcks.begin(), _pendingAcks.end(), callID);
		it != _pendingAcks.end())
	{
		const std::string& activeIp = _env.localIp();
		const std::string srcIpPort = activeIp + ":" + std::to_string(_env.serverPort());
		const std::string destIpPort = addrToIpPort(data->getSource());
		std::ostringstream ss;
		ss << "ACK sip:" << data->getToNumber() << "@" << destIpPort << " SIP/2.0\r\n"
		   << "Via: SIP/2.0/UDP " << srcIpPort << ";branch=z9hG4bK" << IDGen::GenerateID(12) << "\r\n"
		   << "From: " << siphdr::stripHeaderName(data->getFrom()) << "\r\n"
		   << "To: " << siphdr::stripHeaderName(data->getTo()) << "\r\n"
		   << callID << "\r\n"
		   << "CSeq: 2 ACK\r\n"
		   << "Max-Forwards: 70\r\n"
		   << "Content-Length: 0\r\n\r\n";
		_env.enqueue(data->getSource(), _env.messageFromPool(ss.str(), data->getSource()));
		_pendingAcks.erase(it);
		return true;
	}

	// (b) 200 OK to a ring-back INVITE sent to the parker: ACK parker, bridge both legs.
	for (auto& slot : _slots)
	{
		if (slot.state == ParkState::RingingBack && slot.rbCallID == callID)
		{
			const std::string& activeIp = _env.localIp();
			const std::string srcIpPort = activeIp + ":" + std::to_string(_env.serverPort());
			const std::string destIpPort = addrToIpPort(slot.rbAddr);
			std::ostringstream ss;
			ss << "ACK sip:" << data->getToNumber() << "@" << destIpPort << " SIP/2.0\r\n"
			   << "Via: SIP/2.0/UDP " << srcIpPort << ";branch=" << slot.rbBranch << "\r\n"
			   << "From: \"PocketDial Park\" <sip:" << slot.orbit << "@" << srcIpPort << ">;tag=" << slot.rbFromTag << "\r\n"
			   << "To: " << siphdr::stripHeaderName(data->getTo()) << "\r\n"
			   << slot.rbCallID << "\r\n"
			   << "CSeq: 1 ACK\r\n"
			   << "Max-Forwards: 70\r\n"
			   << "Content-Length: 0\r\n\r\n";
			_env.enqueue(slot.rbAddr, _env.messageFromPool(ss.str(), slot.rbAddr));

			sendReinvite(slot, std::string(data->getBody()));

			if (auto parker = _env.findRegistered(slot.parker))
			{
				auto virt = _env.allocVirtualPeer(slot.parkedExt, slot.parkedAddr);
				if (auto rb = virt ? _env.allocSession(slot.rbCallID, parker) : nullptr)
				{
					rb->setDest(virt);
					rb->setPeerCallID(slot.callID);
					rb->setLocalTag(slot.rbFromTag);
					rb->setParkUac(true);
					rb->setInviteMessage(data);
					_env.insertSession(slot.rbCallID, rb);
					rb->setState(Session::State::Connected);
				}
				if (auto parked = _env.findSession(slot.callID))
				{
					parked->setPeerCallID(slot.rbCallID);
				}
			}

			_env.log("Park: parker answered ring-back on " + slot.orbit + " — bridging");
			releaseSlot(slot);
			return true;
		}
	}
	return false;
}

void ParkOrbit::sweep(std::chrono::steady_clock::time_point now)
{
	for (auto& slot : _slots)
	{
		if (slot.state == ParkState::Parked &&
			(now - slot.parkedAt) >= _timeout)
		{
			auto parker = _env.findRegistered(slot.parker);
			if (parker)
			{
				startRingback(slot, parker, now);
			}
			else
			{
				_env.log("Park: timeout on " + slot.orbit + " — parker " + slot.parker +
					" gone, tearing down");
				byeParkedParty(slot);
				freeForCallId(slot.callID);
			}
		}
		else if (slot.state == ParkState::RingingBack && now >= slot.deadline)
		{
			_env.log("Park: ring-back on " + slot.orbit + " not answered — tearing down");
			byeParkedParty(slot);
			freeForCallId(slot.callID);
		}
	}
}

void ParkOrbit::releaseSlot(ParkSlot& slot)
{
	slot = ParkSlot{};
	_parkChanged = true;
}

bool ParkOrbit::consumeParkChanged()
{
	const bool changed = _parkChanged;
	_parkChanged = false;
	return changed;
}

void ParkOrbit::freeForCallId(std::string_view callID)
{
	for (auto& slot : _slots)
	{
		if (slot.state != ParkState::Free && slot.callID == callID)
		{
			releaseSlot(slot);
		}
	}
	_pendingAcks.erase(
		std::remove(_pendingAcks.begin(), _pendingAcks.end(), std::string(callID)),
		_pendingAcks.end());
}

std::vector<std::tuple<std::string, std::string, std::string, int>>
ParkOrbit::snapshotRows(std::chrono::steady_clock::time_point now, bool onlyParked) const
{
	std::vector<std::tuple<std::string, std::string, std::string, int>> rows;
	for (const auto& slot : _slots)
	{
		if (slot.state == ParkState::Free) continue;
		if (onlyParked && slot.state != ParkState::Parked) continue;
		int secs = static_cast<int>(std::chrono::duration_cast<std::chrono::seconds>(
			now - slot.parkedAt).count());
		rows.emplace_back(slot.orbit, slot.parkedExt, slot.parker, secs);
	}
	return rows;
}
