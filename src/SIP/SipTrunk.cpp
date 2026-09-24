#include "SipTrunk.hpp"

#include <cstring>
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
	ss << "INVITE " << pstnUri(d.destE164, d.domain) << " SIP/2.0\r\n"
	   << "Via: SIP/2.0/UDP " << d.localIpPort << ";branch=" << d.branch << ";rport\r\n"
	   // From carries the trunk identity. A carrier matches its outbound
	   // authorisation against THIS, not against the Contact, so getting it wrong
	   // is a 403 with no further explanation.
	   << "From: <sip:" << d.fromUser << "@" << d.domain << ">;tag=" << d.fromTag << "\r\n"
	   << "To: <" << pstnUri(d.destE164, d.domain) << ">\r\n"
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
		? d.domain               // carrier sent no Contact: fall back, better than nothing
		: d.remoteTarget;

	std::ostringstream ss;
	ss << "ACK " << (d.remoteTarget.empty() ? pstnUri(d.destE164, target) : target) << " SIP/2.0\r\n"
	   << "Via: SIP/2.0/UDP " << d.localIpPort << ";branch=" << freshBranch << ";rport\r\n"
	   << "From: <sip:" << d.fromUser << "@" << d.domain << ">;tag=" << d.fromTag << "\r\n"
	   << "To: <" << pstnUri(d.destE164, d.domain) << ">";
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
	ss << "ACK " << pstnUri(d.destE164, d.domain) << " SIP/2.0\r\n"
	   << "Via: SIP/2.0/UDP " << d.localIpPort << ";branch=" << d.branch << ";rport\r\n"
	   << "From: <sip:" << d.fromUser << "@" << d.domain << ">;tag=" << d.fromTag << "\r\n"
	   << "To: <" << pstnUri(d.destE164, d.domain) << ">";
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
	   << "From: <sip:" << d.fromUser << "@" << d.domain << ">;tag=" << d.fromTag << "\r\n"
	   << "To: <" << pstnUri(d.destE164, d.domain) << ">;tag=" << d.toTag << "\r\n"
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
		//
		// handsetCallID is normalised on BOTH sides, unlike callID. We generate
		// callID ourselves and always store it bare, but handsetCallID is
		// whatever the engine handed placeCall() -- and the engine's own
		// session map is keyed on SipMessage::getCallID(), the FULL header
		// line. Comparing a stripped key against an unstripped stored value
		// silently never matches, so a handset BYE found no dialog and the
		// carrier leg stayed up and billing. Normalising here rather than at
		// the call site keeps this class correct for either form.
		if (d.callID == key ||
			(!d.handsetCallID.empty() && siphdr::stripHeaderName(d.handsetCallID) == key))
		{
			return &d;
		}
	}
	return nullptr;
}

SipTrunk::Dialog* SipTrunk::findMutableByTrunkCallID(std::string_view callID)
{
	// Same normalisation as findMutableByCallID(); callID is always stored bare.
	const std::string key = siphdr::stripHeaderName(callID);
	for (auto& d : _dialogs)
	{
		if (d.state != State::Free && d.callID == key) return &d;
	}
	return nullptr;
}

bool SipTrunk::setCredentials(std::string_view password)
{
	// Reject rather than truncate. A silently shortened password is a trunk
	// that fails to authenticate with no visible cause -- the worst possible
	// failure for a field that a human typed into a form and cannot read back.
	if (password.size() >= kMaxSecret) return false;

	clearCredentials();
	if (password.empty()) return true;   // empty == "no credential", not an error
	std::memcpy(_secret, password.data(), password.size());
	_secret[password.size()] = '\0';
	return true;
}

void SipTrunk::clearCredentials()
{
	// volatile so the write survives an optimiser that can see the buffer is
	// dead afterwards. Best-effort hygiene, not a security boundary -- the same
	// caveat TelephonyApiConfig's scrub() states, and for the same reason.
	volatile char* p = _secret;
	for (size_t i = 0; i < kMaxSecret; ++i) p[i] = '\0';
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
	// The SIP domain, from Config -- deliberately not addrToIpPort(sbc), which
	// is the transport address and becomes the PROXY's address the moment one
	// is configured. Keeping the port suffix makes this byte-identical to the
	// old sbcIpPort-derived URIs for the common dotted-quad, no-proxy case.
	//
	// KNOWN, DELIBERATELY DEFERRED: the ":port" is unconditional, so a trunk on
	// the default port still emits "sip:+1555@carrier.example.com:5060" rather
	// than the bare domain. By RFC 3261 §19.1.4 a URI omitting a component with
	// a default value does NOT match one explicitly carrying that component at
	// its default, so those are formally distinct URIs -- and some SBCs and
	// proxies route on the Request-URI host and will treat them as different
	// route keys. This config surface is what first makes FQDN registrars and
	// outbound proxies reachable, so it is what makes the case reachable too.
	//
	// Not fixed here, as an explicit decision rather than an oversight: nothing
	// can complete a call on this trunk yet (no REGISTER, no 401/407 handling),
	// so the exposure is theoretical, and a live carrier will settle the exact
	// semantics empirically when the digest path lands. Changing it is not the
	// three-line conditional it looks like -- by the same §19.1.4 reasoning it
	// alters the emitted bytes for the existing dotted-quad case, so the
	// byte-pinned expectations in SipTrunk_test.cpp move with it.
	//
	// SipTrunkUriPort.PortSuffixIsCurrentlyUnconditional pins today's behaviour
	// so this is revisited rather than silently inherited. See issue #365.
	d->domain        = std::string(_cfg.host) + ":" + std::to_string(_cfg.port);
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

	Dialog* d = findMutableByTrunkCallID(data->getCallID());
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
		// 180 and 183 both mean "ringing" to the handset; only 183 says the
		// carrier is already sending audio. 100 Trying is not a listener event:
		// it says a proxy took the request, not that the callee is alerting.
		if (_listener && (status == 180 || status == 183))
		{
			_listener->onTrunkRinging(eventFor(*d), status == 183);
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
		// Fired last, with the ACK already on the outbox and the state already
		// Confirmed: a listener that finds the answer's SDP unusable calls
		// hangup() from in here, and hangup() on a Confirmed dialog emits the
		// BYE. Firing earlier would put that BYE ahead of the ACK on the wire.
		if (_listener) _listener->onTrunkAnswered(eventFor(*d), data);
		return true;
	}

	// A non-2xx to our BYE takes NO ACK and must not fall into the INVITE
	// failure path below. RFC 3261 s17.1.1.3's ACK belongs to an INVITE
	// client transaction; a BYE is a NON-INVITE transaction, which absorbs
	// its own final response (s17.1.2) and is never acknowledged at the
	// application level whatever the status code.
	//
	// Without this the 481 a carrier sends for a dialog it has already torn
	// down produced an ACK stamped with the INVITE's CSeq -- referencing a
	// transaction that completed when the call was answered. Unmatched at
	// the far end, and a message-pool slot spent to send it.
	//
	// The outcome is the same as the 2xx-to-BYE case above: the dialog is
	// over either way. A carrier that refuses our BYE is not going to be
	// talked round, and holding the slot open would leak it.
	if (d->state == State::Terminating)
	{
		_env.log("Trunk: BYE answered " + std::to_string(status)
			+ " (" + d->destE164 + ") -- dialog released regardless", true);
		*d = Dialog{};
		return true;
	}

	// 3xx-6xx final to the INVITE. ACK it in the INVITE's own transaction,
	// then release.
	auto ack = _env.messageFromPool(buildAckForFailure(*d), d->peer);
	if (ack)
	{
		ack->syncContentLength();
		_env.enqueue(d->peer, std::move(ack));
	}
	_env.log("Trunk: call failed " + std::to_string(status) + " (" + d->destE164 + ")", true);

	// Move the dialog out and free the slot BEFORE notifying. The listener's
	// job here is to refuse the handset leg, and it may well place another call
	// straight after -- which needs this slot back. Moving rather than copying
	// steals the string buffers instead of allocating a second set, so the
	// event's views stay valid for the callback without a heap round trip.
	// The ACK above is built first because buildAckForFailure() reads *d.
	const Dialog finished = std::move(*d);
	*d = Dialog{};
	if (_listener) _listener->onTrunkFailed(eventFor(finished), status);
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

bool SipTrunk::handleBye(const std::shared_ptr<SipMessage>& data)
{
	if (!data) return false;
	if (data->getType() != SipMessageTypes::BYE) return false;

	Dialog* d = findMutableByTrunkCallID(data->getCallID());
	if (!d || d->state == State::Free) return false;

	// 200 first, off the request itself so the Via/CSeq match without this
	// class having to know how a response is assembled.
	// Built FROM the request so every header the carrier matches a response on
	// -- Via with its branch, From/To with their tags, Call-ID, CSeq -- comes
	// back byte-identical and only the start line changes.
	auto ok = _env.messageFromPool(data->toString(), data->getSource());
	if (ok)
	{
		ok->setHeader(SipMessageTypes::OK);
		ok->clearBody();
		ok->syncContentLength();
		_env.enqueue(data->getSource(), std::move(ok));
	}

	// Same move-then-free-then-notify order the failure path uses, and for the
	// same reason: the listener tears the handset leg down and may place a new
	// call from inside the callback, so the slot must already be free and the
	// event must not point into it.
	_env.log("Trunk: carrier hung up (" + d->destE164 + ")");
	_env.freeTransactionsForCallId(d->callID);
	const Dialog finished = std::move(*d);
	*d = Dialog{};
	if (_listener) _listener->onTrunkRemoteBye(eventFor(finished));
	return true;
}

#if !defined(ESP_PLATFORM) && !defined(ESP32) && !defined(ARDUINO)
void SipTrunk::expireDeadlinesForTest()
{
	const auto past = std::chrono::steady_clock::now() - std::chrono::hours(1);
	for (auto& d : _dialogs)
	{
		if (d.state != State::Free) d.deadline = past;
	}
}
#endif

void SipTrunk::sweep(std::chrono::steady_clock::time_point now)
{
	for (auto& d : _dialogs)
	{
		if (d.state == State::Free || now < d.deadline) continue;

		// A CONFIRMED dialog is a call that is up, and `deadline` still holds
		// the NO-ANSWER budget placeCall() armed -- 60 s from when the INVITE
		// went out, long expired on any real conversation. Reaping on it would
		// hang up every trunk call about a minute after it was placed.
		//
		// There is deliberately no max-call-duration timer here to replace it:
		// a PBX that drops calls on a timer it never told anyone about is worse
		// than one that does not. Terminating gets its own short deadline from
		// hangup(), which is what reclaims a slot whose BYE went unanswered, so
		// nothing leaks by exempting only this state.
		if (d.state == State::Confirmed) continue;

		_env.log("Trunk: dialog timed out in state "
			+ std::to_string(static_cast<int>(d.state)) + " (" + d.destE164 + ")", true);
		_env.freeTransactionsForCallId(d.callID);

		// A dialog that reached Terminating is our own BYE going unanswered.
		// The listener tore the handset down when it asked for that BYE, so
		// reclaiming the slot is all that is left -- notifying again would be a
		// second teardown of a leg that is already gone.
		const bool notify = (d.state != State::Terminating);

		// Same move-then-free-then-fire order as the failure path above: an
		// INVITE that never got a final response must release the handset, and
		// the listener may immediately reuse this slot.
		const Dialog finished = std::move(d);
		d = Dialog{};
		// 408, not 0: a request that got no final response inside its deadline
		// is a timeout in the RFC 3261 sense, and giving the listener a real
		// status means its failure mapping needs no special case for "0".
		if (notify && _listener) _listener->onTrunkFailed(eventFor(finished), 408);
	}
}
