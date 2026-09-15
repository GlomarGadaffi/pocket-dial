#include "SipTrunk.hpp"

#include <sstream>

#include "IDGen.hpp"
#include "RequestsHandler.hpp"
#include "SipHeaderUtil.hpp"
#include "SipMessageTypes.h"
#include "SipWireUtil.hpp"

using sipwire::addrToIpPort;

namespace
{
	// The request-URI / To URI for a PSTN destination. E.164 with the leading '+'
	// is what essentially every ITSP expects; E164.cpp has already normalised the
	// digits by the time a number reaches here, so this only has to not mangle it.
	std::string pstnUri(std::string_view e164, std::string_view host)
	{
		std::string u = "sip:";
		if (!e164.empty() && e164.front() != '+') u += '+';
		u.append(e164);
		u += '@';
		u.append(host);
		return u;
	}

	// The bare URI out of a Contact header. There is no shared helper for this --
	// nothing else in the engine needed a far-end Contact as a ROUTE before; the
	// registrar stores Contacts but only ever reads the user part back out.
	//
	// Getting this right matters more on a trunk than it looks: in-dialog requests
	// go to the Contact, and many carriers answer from a different node than the
	// one that took the INVITE. A BYE sent to the wrong one is silently ignored
	// and the call stays up, billing.
	std::string contactUri(std::string_view header)
	{
		std::string v = siphdr::stripHeaderName(header);
		const size_t lt = v.find('<');
		if (lt != std::string::npos)
		{
			const size_t gt = v.find('>', lt + 1);
			if (gt != std::string::npos) return v.substr(lt + 1, gt - lt - 1);
		}
		// Bare form (RFC 3261 §20.10 allows it when there are no header params).
		// Cut at the first ';': that is a Contact PARAMETER (expires, q), not part
		// of the URI, and carrying it into a request-URI would be malformed.
		const size_t semi = v.find(';');
		if (semi != std::string::npos) v.erase(semi);
		while (!v.empty() && (v.back() == ' ' || v.back() == '\t')) v.pop_back();
		size_t b = 0;
		while (b < v.size() && (v[b] == ' ' || v[b] == '\t')) ++b;
		return v.substr(b);
	}

	// Headers every request on this trunk carries. Factored out so the INVITE and
	// the BYE cannot drift apart -- a carrier that sees a different User-Agent or
	// a missing Max-Forwards between two requests of one dialog is entitled to be
	// suspicious of both.
	void commonRequestTail(std::ostringstream& ss)
	{
		ss << "Max-Forwards: 70\r\n"
		   << "User-Agent: pocket-dial\r\n";
	}
}

// ─────────────────────────────────────────────────────────────────────────────
//  Pure builders
// ─────────────────────────────────────────────────────────────────────────────

std::string SipTrunk::buildInvite(const Dialog& d, const std::string& sdp)
{
	std::ostringstream ss;
	ss << "INVITE " << pstnUri(d.destE164, d.sbcIpPort) << " SIP/2.0\r\n"
	   << "Via: SIP/2.0/UDP " << d.localIpPort << ";branch=" << d.branch << ";rport\r\n"
	   // From carries the trunk identity. A carrier matches its outbound
	   // authorisation against THIS, not against the Contact, so getting it wrong
	   // is a 403 with no further explanation.
	   << "From: <sip:" << d.fromUser << "@" << d.sbcIpPort << ">;tag=" << d.fromTag << "\r\n"
	   << "To: <" << pstnUri(d.destE164, d.sbcIpPort) << ">\r\n"
	   << "Call-ID: " << d.callID << "\r\n"
	   << "CSeq: " << d.cseq << " INVITE\r\n";
	commonRequestTail(ss);
	// Contact must be OUR address, not the SBC's: it is where the carrier sends
	// in-dialog requests, including the BYE when the far party hangs up first.
	ss << "Contact: <sip:" << d.fromUser << "@" << d.localIpPort << ";transport=udp>\r\n"
	   // Advertise what we can actually be sent. Omitting Allow is legal but
	   // invites a carrier to try a re-INVITE or UPDATE we would have to 405.
	   << "Allow: INVITE, ACK, BYE, CANCEL, OPTIONS\r\n"
	   << "Supported: timer\r\n"
	   << "Content-Type: application/sdp\r\n"
	   << "Content-Length: " << sdp.size() << "\r\n\r\n"
	   << sdp;
	return ss.str();
}

std::string SipTrunk::buildAckFor2xx(const Dialog& d, std::string_view freshBranch)
{
	// RFC 3261 §13.2.2.4: the ACK for a 2xx is a NEW transaction of its own --
	// fresh branch -- routed to the dialog's remote target rather than to
	// wherever the INVITE was sent.
	//
	// The branch is a parameter rather than generated in here so this stays a
	// pure function the host tests can pin byte for byte. A builder that reached
	// for IDGen internally would produce a different string every call and could
	// only be tested by regex, which is exactly the level of rigour a wire format
	// does not deserve to be tested at.
	const std::string& target = d.remoteTarget.empty()
		? d.sbcIpPort            // carrier sent no Contact: fall back, better than nothing
		: d.remoteTarget;

	std::ostringstream ss;
	ss << "ACK " << (d.remoteTarget.empty() ? pstnUri(d.destE164, target) : target) << " SIP/2.0\r\n"
	   << "Via: SIP/2.0/UDP " << d.localIpPort << ";branch=" << freshBranch << ";rport\r\n"
	   << "From: <sip:" << d.fromUser << "@" << d.sbcIpPort << ">;tag=" << d.fromTag << "\r\n"
	   << "To: <" << pstnUri(d.destE164, d.sbcIpPort) << ">";
	if (!d.toTag.empty()) ss << ";tag=" << d.toTag;
	ss << "\r\n"
	   << "Call-ID: " << d.callID << "\r\n"
	   // Same sequence NUMBER as the INVITE, method ACK (§13.2.2.4).
	   << "CSeq: " << d.cseq << " ACK\r\n";
	commonRequestTail(ss);
	ss << "Content-Length: 0\r\n\r\n";
	return ss.str();
}

std::string SipTrunk::buildAckForFailure(const Dialog& d)
{
	// RFC 3261 §17.1.1.3: the ACK for a NON-2xx belongs to the INVITE's own
	// transaction and reuses its branch, so the carrier's server transaction can
	// match it and stop retransmitting the failure. Without it the carrier keeps
	// resending the 4xx until Timer H (~32 s) and the slot stays pinned at both
	// ends.
	std::ostringstream ss;
	ss << "ACK " << pstnUri(d.destE164, d.sbcIpPort) << " SIP/2.0\r\n"
	   << "Via: SIP/2.0/UDP " << d.localIpPort << ";branch=" << d.branch << ";rport\r\n"
	   << "From: <sip:" << d.fromUser << "@" << d.sbcIpPort << ">;tag=" << d.fromTag << "\r\n"
	   << "To: <" << pstnUri(d.destE164, d.sbcIpPort) << ">";
	if (!d.toTag.empty()) ss << ";tag=" << d.toTag;
	ss << "\r\n"
	   << "Call-ID: " << d.callID << "\r\n"
	   << "CSeq: " << d.cseq << " ACK\r\n";
	commonRequestTail(ss);
	ss << "Content-Length: 0\r\n\r\n";
	return ss.str();
}

std::string SipTrunk::buildBye(const Dialog& d, std::string_view freshBranch)
{
	// An in-dialog request needs both tags and a route. Refusing to build a
	// half-formed BYE is deliberate: emitting one earns a 481 from the carrier
	// while the call stays up and billing, and the empty return gives the caller
	// something it can actually branch on.
	if (d.toTag.empty() || d.remoteTarget.empty())
	{
		return std::string();
	}

	std::ostringstream ss;
	ss << "BYE " << d.remoteTarget << " SIP/2.0\r\n"
	   << "Via: SIP/2.0/UDP " << d.localIpPort << ";branch=" << freshBranch << ";rport\r\n"
	   << "From: <sip:" << d.fromUser << "@" << d.sbcIpPort << ">;tag=" << d.fromTag << "\r\n"
	   << "To: <" << pstnUri(d.destE164, d.sbcIpPort) << ">;tag=" << d.toTag << "\r\n"
	   << "Call-ID: " << d.callID << "\r\n"
	   // A new request in the dialog takes the NEXT sequence number (§12.2.1.1).
	   << "CSeq: " << (d.cseq + 1) << " BYE\r\n";
	commonRequestTail(ss);
	ss << "Content-Length: 0\r\n\r\n";
	return ss.str();
}

// ─────────────────────────────────────────────────────────────────────────────
//  Slot management
// ─────────────────────────────────────────────────────────────────────────────

SipTrunk::Dialog* SipTrunk::allocDialog()
{
	for (auto& d : _dialogs)
	{
		if (d.state == State::Free) return &d;
	}
	return nullptr;
}

SipTrunk::Dialog* SipTrunk::findMutableByCallID(std::string_view callID)
{
	// Callers hand us SipMessage::getCallID(), which returns the FULL header line
	// ("Call-ID: x@host") while our slots hold the bare id we generated. Normalise
	// before comparing -- the same mismatch that once left every register beep
	// un-ACKed (see RegisterBeeper::findByCallID).
	const std::string key = siphdr::stripHeaderName(callID);
	for (auto& d : _dialogs)
	{
		if (d.state == State::Free) continue;
		// Match either end: a teardown can arrive naming the handset leg.
		if (d.callID == key || (!d.handsetCallID.empty() && d.handsetCallID == key))
		{
			return &d;
		}
	}
	return nullptr;
}

const SipTrunk::Dialog* SipTrunk::findByCallID(std::string_view callID) const
{
	return const_cast<SipTrunk*>(this)->findMutableByCallID(callID);
}

bool SipTrunk::ownsCallID(std::string_view callID) const
{
	return findByCallID(callID) != nullptr;
}

size_t SipTrunk::activeDialogs() const
{
	size_t n = 0;
	for (const auto& d : _dialogs)
	{
		if (d.state != State::Free) ++n;
	}
	return n;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Operations
// ─────────────────────────────────────────────────────────────────────────────

bool SipTrunk::placeCall(std::string_view e164, std::string_view handsetCallID,
	const sockaddr_in& sbc, uint16_t localRtpPort)
{
	if (!_cfg.valid())
	{
		_env.log("Trunk: call refused, trunk not configured", true);
		return false;
	}

	Dialog* d = allocDialog();
	if (!d)
	{
		// Out of slots. Refuse loudly rather than queue: the caller is a person
		// holding a handset, and a call that silently waits is worse than one that
		// fails now.
		_env.log("Trunk: call refused, no free dialog slot", true);
		return false;
	}

	const std::string activeIp = _env.localIp();

	*d = Dialog{};
	d->state         = State::Trying;
	d->callID        = IDGen::GenerateID(16) + "@" + activeIp;
	d->branch        = "z9hG4bK" + IDGen::GenerateID(12);
	d->fromTag       = IDGen::GenerateID(9);
	d->cseq          = 1;
	d->sbcIpPort     = addrToIpPort(sbc);
	d->localIpPort   = activeIp + ":" + std::to_string(_env.serverPort());
	d->destE164.assign(e164);
	d->handsetCallID.assign(handsetCallID);
	d->localRtpPort  = localRtpPort;
	d->peer          = sbc;
	d->fromUser      = _cfg.callerId[0] ? _cfg.callerId : _cfg.fromUser;
	// Generous by internal-extension standards and deliberately so: a PSTN leg
	// routinely rings past 20 s before carrier voicemail answers. The anchor path
	// learned this the hard way -- kNoAnswerTimeout (20 s) applied to a PSTN leg
	// cut calls off ~2 s before a measured 21.2 s voicemail answer.
	d->deadline      = std::chrono::steady_clock::now() + std::chrono::seconds(60);

	// sendrecv, with telephone-event: a trunk that cannot carry DTMF cannot reach
	// an IVR, and buildMediaSdp() already emits the a=rtpmap and a=fmtp lines the
	// dynamic payload type requires. Omitting them is not cosmetic -- an m= line
	// advertising PT 101 with no rtpmap is what made pjsip answer 400 Bad SDP.
	const std::string sdp = RequestsHandler::buildMediaSdp(activeIp, localRtpPort,
		/*sendrecv=*/true, /*dtmfPt=*/101);

	auto invite = _env.messageFromPool(buildInvite(*d, sdp), sbc);
	if (!invite)
	{
		// Pool exhausted. Release the slot -- unlike a retransmittable inbound
		// request there is no peer who will try again for us.
		*d = Dialog{};
		_env.log("Trunk: call refused, message pool exhausted", true);
		return false;
	}
	invite->syncContentLength();
	_env.enqueue(sbc, std::move(invite));
	_env.log("Trunk: INVITE -> " + std::string(e164));
	return true;
}

bool SipTrunk::handleResponse(const std::shared_ptr<SipMessage>& data)
{
	if (!data) return false;

	Dialog* d = findMutableByCallID(data->getCallID());
	if (!d) return false;

	// Only responses to OUR INVITE advance this machine. A response to the BYE is
	// handled below by state, not by CSeq method, because a carrier may answer a
	// BYE with 200 long after we stopped caring.
	// Dispatch on the parsed numeric code, never on the reason phrase: carriers
	// vary it freely ("486 Busy" vs "486 Busy Here") and some localise it.
	// A message with no status line is not a response and is not ours.
	const auto statusInfo = data->getStatusInfo();
	if (!statusInfo.has_value()) return false;
	const int status = static_cast<int>(statusInfo->code);

	// Latch the To-tag from the first response that carries one. Everything
	// in-dialog afterwards -- the ACK, the BYE -- is malformed without it.
	const std::string toTag = siphdr::tagOf(data->getTo());
	if (!toTag.empty() && d->toTag.empty()) d->toTag = toTag;

	if (status >= 100 && status < 200)
	{
		if (d->state == State::Trying) d->state = State::Proceeding;
		if (status == 183)
		{
			// 183 Session Progress means the carrier is already sending media --
			// ringback, or a SIT tone explaining a failure. Recording it is the
			// hook the relay needs: without early media the caller hears silence
			// where a network announcement was played, which is indistinguishable
			// from a broken trunk.
			d->sawSessionProgress = true;
			_env.log("Trunk: 183 session progress (early media) from carrier");
		}
		return true;
	}

	if (status >= 200 && status < 300)
	{
		if (d->state == State::Terminating)
		{
			// 200 to our BYE: the dialog is done.
			*d = Dialog{};
			return true;
		}

		// 2xx to the INVITE. Latch the remote target from Contact BEFORE acking --
		// the ACK is routed to it.
		const std::string contact = contactUri(data->getContact());
		if (!contact.empty()) d->remoteTarget = contact;

		auto ack = _env.messageFromPool(buildAckFor2xx(*d, "z9hG4bK" + IDGen::GenerateID(12)),
			d->peer);
		if (ack)
		{
			ack->syncContentLength();
			_env.enqueue(d->peer, std::move(ack));
		}
		d->state = State::Confirmed;
		_env.log("Trunk: call answered (" + d->destE164 + ")");
		return true;
	}

	// 3xx-6xx final. ACK it in the INVITE's own transaction, then release.
	auto ack = _env.messageFromPool(buildAckForFailure(*d), d->peer);
	if (ack)
	{
		ack->syncContentLength();
		_env.enqueue(d->peer, std::move(ack));
	}
	_env.log("Trunk: call failed " + std::to_string(status) + " (" + d->destE164 + ")", true);
	*d = Dialog{};
	return true;
}

bool SipTrunk::hangup(std::string_view callID)
{
	Dialog* d = findMutableByCallID(callID);
	if (!d) return false;

	if (d->state == State::Confirmed)
	{
		const std::string bye = buildBye(*d, "z9hG4bK" + IDGen::GenerateID(12));
		if (!bye.empty())
		{
			auto msg = _env.messageFromPool(bye, d->peer);
			if (msg)
			{
				msg->syncContentLength();
				_env.enqueue(d->peer, std::move(msg));
			}
		}
		d->state    = State::Terminating;
		// Bounded wait for the 200; sweep() reclaims the slot either way.
		d->deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
		return true;
	}

	// Not yet answered. A CANCEL would be the strictly correct move for a dialog
	// in Proceeding; it is deliberately left to the follow-up that adds inbound
	// and re-INVITE handling, because a CANCEL raced against a 200 needs the
	// ACK+BYE recovery path RegisterBeeper had to grow, and half of that is worse
	// than none. Releasing the slot stops us placing a duplicate call.
	_env.freeTransactionsForCallId(d->callID);
	*d = Dialog{};
	return true;
}

void SipTrunk::sweep(std::chrono::steady_clock::time_point now)
{
	for (auto& d : _dialogs)
	{
		if (d.state == State::Free || now < d.deadline) continue;

		_env.log("Trunk: dialog timed out in state "
			+ std::to_string(static_cast<int>(d.state)) + " (" + d.destE164 + ")", true);
		_env.freeTransactionsForCallId(d.callID);
		d = Dialog{};
	}
}
