#include "SipTrunk.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <sstream>

#include "EmergencyCall.hpp"
#include "IDGen.hpp"
#include "RequestsHandler.hpp"
#include "SipHeaderUtil.hpp"
#include "SipMessageTypes.h"
#include "SipWireUtil.hpp"
#include "TrunkResolver.hpp"

using sipwire::addrToIpPort;

// #618/#689: the full INVITE and REGISTER-response dump below is diagnostics
// only. The constrained 4 MB image has no room for it (main/CMakeLists.txt sets
// 0 there); the one-line "Trunk: INVITE ->" summary stays on every build.
#ifndef POCKETDIAL_TRUNK_WIRE_LOG
#define POCKETDIAL_TRUNK_WIRE_LOG 1
#endif

namespace
{
#if POCKETDIAL_TRUNK_WIRE_LOG
	// #618: the whole outbound INVITE on the console, its lines " | "-joined
	// into a few log lines under LogQueue's 256-byte line cap (its queue is only
	// 16 deep, so one log line per SIP line would drop). The body is cut after
	// kMaxLines SIP lines. Authorization values are never logged.
	void logInvite(PbxEnv& env, std::string_view msg)
	{
		constexpr std::string_view kPre = "Trunk: INVITE> ";
		constexpr size_t kMaxLines = 40;
		char buf[200];
		size_t n = 0;
		auto put = [&](std::string_view s) { std::memcpy(buf + n, s.data(), s.size()); n += s.size(); };
		for (size_t i = 0; i < kMaxLines && !msg.empty(); ++i)
		{
			const size_t e = msg.find("\r\n");
			std::string_view l = msg.substr(0, e);
			msg = (e == std::string_view::npos) ? std::string_view{} : msg.substr(e + 2);
			if (l.empty()) continue;   // the blank line before the body
			const std::string_view name = l.substr(0, l.find(':'));
			const bool redact = name == "Authorization" || name == "Proxy-Authorization";
			const std::string_view tail = redact ? ": <redacted>" : "";
			if (redact) l = name;
			if (n && n + 3 + l.size() + tail.size() > sizeof(buf)) { env.log(std::string(buf, n)); n = 0; }
			put(n ? " | " : kPre);
			put(l.substr(0, sizeof(buf) - n - tail.size()));   // a lone over-long line is cut
			put(tail);
		}
		if (n) env.log(std::string(buf, n));
	}
#else
	void logInvite(PbxEnv&, std::string_view) {}
#endif

	// The number in a CSeq header ("CSeq: 2 BYE" -> 2), 0 when there is none.
	uint32_t cseqNumber(std::string_view cseqLine)
	{
		const size_t colon = cseqLine.find(':');
		const std::string_view v = colon == std::string_view::npos ? cseqLine : cseqLine.substr(colon + 1);
		uint32_t n = 0;
		size_t i = 0;
		while (i < v.size() && (v[i] == ' ' || v[i] == '\t')) ++i;
		while (i < v.size() && v[i] >= '0' && v[i] <= '9')
		{
			n = n * 10u + static_cast<uint32_t>(v[i] - '0');
			++i;
		}
		return n;
	}

	// The host of a SIP URI ("sip:+1555@203.0.113.9:5060;transport=udp"), as an
	// address, when -- and only when -- it is a dotted quad. An FQDN yields false:
	// resolving it would mean getaddrinfo on the SIP thread, which is the one
	// thing TrunkResolver exists to prevent (#356's BYE source check).
	bool uriHostIpv4(std::string_view uri, uint32_t& out)
	{
		const size_t colon = uri.find(':');
		if (colon == std::string_view::npos) return false;   // no scheme
		std::string_view rest = uri.substr(colon + 1);
		const size_t at = rest.find('@');
		if (at != std::string_view::npos) rest = rest.substr(at + 1);
		const size_t end = rest.find_first_of(":;>?");
		return TrunkResolver::parseDottedQuad(rest.substr(0, end), out);
	}

	// The request-URI / To URI for a PSTN destination. E.164 with the leading '+'
	// is what essentially every ITSP expects; E164.cpp has already normalised the
	// digits by the time a number reaches here, so this only has to not mangle it.
	//
	// Issue #521: except an emergency service number. 911 and 933 are dial
	// strings, not E.164 numbers -- "+911" reads as country code 91 -- and
	// carriers expect them bare in the user part. Exact match only, the same
	// closed set EmergencyCall.hpp recognises; routeEmergencyCall() always
	// hands the trunk the bare form.
	std::string pstnUri(std::string_view e164, std::string_view host)
	{
		std::string u = "sip:";
		const bool serviceNumber =
			e164 == pbx::kEmergencyNumber || e164 == pbx::kEmergencyTestNumber;
		if (!e164.empty() && e164.front() != '+' && !serviceNumber) u += '+';
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

std::string SipTrunk::buildInvite(const Dialog& d, const std::string& sdp, std::string_view authLine)
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
	if (!authLine.empty()) ss << authLine << "\r\n";   // #399: answering a 401/407
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

std::string SipTrunk::buildBye(const Dialog& d, std::string_view freshBranch, std::string_view authLine)
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
	if (!authLine.empty()) ss << authLine << "\r\n";   // #687: answering a 401/407
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
	// un-ACKed (see RegisterBeeper::findByCallID). A view, not a copy (#464):
	// this runs on every SIP response and BYE the engine handles, trunk or not.
	const std::string_view key = siphdr::stripHeaderNameView(callID);
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
			(!d.handsetCallID.empty() && siphdr::stripHeaderNameView(d.handsetCallID) == key))
		{
			return &d;
		}
	}
	return nullptr;
}

SipTrunk::Dialog* SipTrunk::findMutableByTrunkCallID(std::string_view callID)
{
	// Same normalisation as findMutableByCallID(); callID is always stored bare.
	const std::string_view key = siphdr::stripHeaderNameView(callID);
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
	_regLive = false;          // #399: the registration's copy goes too
	_reg.clearCredentials();
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
	// is configured.
	//
	// Issue #365 (option A): the default port is omitted. By RFC 3261 §19.1.4 a
	// URI omitting a component with a default value does NOT match one that
	// carries it explicitly, so "sip:+1555@carrier.example.com:5060" and
	// "sip:+1555@carrier.example.com" are distinct -- and SBCs and proxies that
	// route on the Request-URI host treat them as different route keys. So the
	// default port is left implicit, and any other configured port, being part
	// of the route key, is kept. This changes the emitted bytes for the
	// dotted-quad default-port case too; SipTrunkUriPort.* pins both halves.
	d->domain        = (_cfg.port == 5060)
		? std::string(_cfg.host)
		: std::string(_cfg.host) + ":" + std::to_string(_cfg.port);
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

	d->offerSdp = sdp;   // #399: re-offered unchanged if the carrier challenges
	const std::string inviteText = buildInvite(*d, sdp);
	auto invite = _env.messageFromPool(inviteText, sbc);
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
	// #618: where it went and from which port, so a silent carrier can be told
	// apart from a misaddressed INVITE without a capture.
	_env.log("Trunk: INVITE -> " + std::string(e164) + " to " + d->sbcIpPort
		+ " from local port " + std::to_string(_env.serverPort()) + " (From " + d->fromUser + ")");
	logInvite(_env, inviteText);
	return true;
}

bool SipTrunk::handleResponse(const std::shared_ptr<SipMessage>& data)
{
	if (!data) return false;
	if (handleRegisterResponse(data)) return true;   // #399

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

	// Issue #356: a response must come from where its request went. Every
	// request this dialog sends -- INVITE, both ACK forms, BYE -- is addressed
	// to d->peer, so nothing legitimate answers from anywhere else, in any
	// state. A forged response is otherwise the carrier: a 200 with its own
	// SDP gets ACKed and redirects the relay's RTP, a 4xx kills the call
	// before answer.
	//
	// Strict, with no tag fallback, on purpose. A forged EARLY response is what
	// SUPPLIES the peer's tag, so there is nothing to match it against. And a
	// wrongly dropped response cannot strand a billing leg: Trying, Proceeding
	// (except a 911/933, #712, which the caller or the carrier ends) and
	// Terminating are all swept, and nothing we send in Confirmed awaits
	// an answer.
	//
	// Dropped AND consumed: returning false would hand a carrier-dialog
	// response to the handset-side paths.
	if (data->getSource().sin_addr.s_addr != d->peer.sin_addr.s_addr)
	{
		const uint32_t n = ++_dialogForgedResponses;   // #663: counted; logged at 1, 2, 4, 8, ...
		if ((n & (n - 1)) == 0)
		{
			_env.log("Trunk: " + std::to_string(status) + " from " + addrToIpPort(data->getSource())
				+ " dropped -- this dialog's carrier is " + addrToIpPort(d->peer)
				+ " (" + d->destE164 + "; " + std::to_string(n) + " dropped so far)", true);
		}
		return true;
	}

	// #581 review B1: once a challenge has been answered this dialog has two
	// INVITE transactions. A response for the FIRST (challenged) one -- the
	// carrier retransmitting its 401/407 until our ACK lands (RFC 3261
	// s17.2.1), or anything else stamped with the old CSeq -- must not drive
	// the live retry: it would latch the dead transaction's To-tag and fail the
	// call while the retry INVITE still rings at the far end. A final response
	// is answered with the first transaction's own ACK again (s17.1.1.2's
	// Completed state); a provisional one is simply absorbed.
	if (d->authAttempted && d->state != State::Terminating)
	{
		const uint32_t respCseq = cseqNumber(data->getCSeq());
		if (respCseq != d->cseq)
		{
			if (status >= 200 && respCseq == d->challengedCseq)
			{
				Dialog first = *d;
				first.branch = d->challengedBranch;
				first.toTag = d->challengedToTag;
				first.cseq = d->challengedCseq;
				auto reAck = _env.messageFromPool(buildAckForFailure(first), d->peer);
				if (reAck)
				{
					reAck->syncContentLength();
					_env.enqueue(d->peer, std::move(reAck));
				}
			}
			_env.log("Trunk: " + std::to_string(status) + " for a superseded INVITE transaction absorbed ("
				+ d->destE164 + ")");
			return true;
		}
	}

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
			_listener->onTrunkRinging(eventFor(*d), status == 183,
				status == 183 ? data : std::shared_ptr<SipMessage>());
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
		// #687 review: once the challenged BYE has been answered, a late
		// response to that FIRST BYE (a UDP retransmission of its 401/407)
		// belongs to a finished transaction. The retry (CSeq d->cseq+1) is
		// still live, so it must not be counted as refused or end the dialog.
		if (d->byeAuthAttempted && cseqNumber(data->getCSeq()) != d->cseq + 1)
		{
			return true;
		}
		// Issue #687: except a 401/407, answered once with digest credentials
		// the way the INVITE's is. Absorbing it left the carrier leg up and
		// billing behind a call the handset had already ended.
		// answerByeChallenge() sends nothing and returns false when it cannot
		// answer (no credentials, unanswerable, already retried once); the
		// dialog is then released as before.
		if ((status == 401 || status == 407) && answerByeChallenge(*d, data, status))
		{
			return true;
		}
		if (d->byeAuthAttempted)
		{
			// The credentialed retry was refused too. Counted, and logged once
			// per dialog: this is the one outcome that may leave a carrier
			// leg up, and there is nothing further to try.
			const uint32_t n = ++_dialogRefusedByeRetries;
			_env.log("Trunk: credentialed BYE retry answered " + std::to_string(status)
				+ " (" + d->destE164 + ") -- dialog released regardless; the carrier leg may still be up ("
				+ std::to_string(n) + " so far)", true);
		}
		else
		{
			_env.log("Trunk: BYE answered " + std::to_string(status)
				+ " (" + d->destE164 + ") -- dialog released regardless", true);
		}
		*d = Dialog{};
		return true;
	}

	// Issue #399: a 401/407 to our INVITE, answered once with digest
	// credentials. answerChallenge() ACKs the challenge itself; if it cannot
	// answer (no credentials, an unanswerable challenge, already tried once) it
	// returns false and the challenge is an ordinary failure below.
	if ((status == 401 || status == 407) && answerChallenge(*d, data, status))
	{
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

	// Issue #356: who may hang up a trunk call. Deliberately looser than the
	// response check in handleResponse(), because the failure costs are
	// reversed: a wrongly REJECTED carrier BYE leaves a Confirmed call up and
	// billing with no reaper (sweep() exempts Confirmed), while a wrongly
	// ACCEPTED one drops one call. Accepted, in order:
	//
	//   1. from d->peer, where every request of ours went;
	//   2. from the remote target's host, when it is a dotted quad -- carriers
	//      commonly send in-dialog requests from the node named in the 2xx's
	//      Contact rather than the one that took the INVITE;
	//   3. from anywhere else, if the call is CONFIRMED and BOTH dialog tags
	//      match. The carrier's tag (our toTag) is minted by the far end, not by
	//      IDGen, so an off-path sender has to have seen the dialog to know it.
	//      Confirmed only, because the no-reaper cost above is a Confirmed-only
	//      cost: an early dialog is swept (a ringing 911/933 excepted, #712), and a 180 can latch toTag before any
	//      answer. RFC 3261 s15 forbids the callee a BYE on an early dialog, so
	//      this refuses nothing a real carrier sends; Terminating is left out
	//      too, since our own BYE is already pending and sweep() reclaims it.
	//      Logged loudly: this is the branch a real carrier's SBC pool would
	//      land in, and the log is what tells whoever brings one up which
	//      address to expect (#164).
	const sockaddr_in& src = data->getSource();
	bool authorised = src.sin_addr.s_addr == d->peer.sin_addr.s_addr;
	if (!authorised)
	{
		uint32_t target = 0;
		authorised = uriHostIpv4(d->remoteTarget, target) && target == src.sin_addr.s_addr;
	}
	if (!authorised && d->state == State::Confirmed && !d->toTag.empty()
		&& siphdr::tagOf(data->getFrom()) == d->toTag
		&& siphdr::tagOf(data->getTo()) == d->fromTag)
	{
		_env.log("Trunk: BYE from " + addrToIpPort(src) + " accepted on dialog tags -- not the carrier "
			+ addrToIpPort(d->peer) + " or its Contact (" + d->destE164 + ")", true);
		authorised = true;
	}
	if (!authorised)
	{
		const uint32_t n = ++_dialogRefusedByes;   // #666: counted; logged at 1, 2, 4, 8, ...
		if ((n & (n - 1)) == 0)
		{
			_env.log("Trunk: BYE from " + addrToIpPort(src) + " refused -- this dialog's carrier is "
				+ addrToIpPort(d->peer) + " and the tags do not match (" + d->destE164 + "; "
				+ std::to_string(n) + " refused so far)", true);
		}
		auto forbidden = _env.messageFromPool(data->toString(), src);
		if (forbidden)
		{
			forbidden->setHeader("SIP/2.0 403 Forbidden");
			forbidden->clearBody();
			forbidden->syncContentLength();
			_env.enqueue(src, std::move(forbidden));
		}
		// Consumed: a false return would pass it to onBye()'s handset paths.
		return true;
	}

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

		// #712 (desmo, 2026-09-29): a 911/933 the carrier is working on (any 1xx
		// seen, so Proceeding) gets no PBX-side no-answer bound; a PSAP may queue
		// it past 60 s. A 911 that never drew a provisional (still Trying) keeps
		// this deadline: Timer B only logs here, so this is what ends it.
		// routeEmergencyCall() always hands the trunk the bare number (pstnUri).
		if (d.state == State::Proceeding &&
		    (d.destE164 == pbx::kEmergencyNumber || d.destE164 == pbx::kEmergencyTestNumber))
		{
			continue;
		}

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

// Issue #399: answer a 401/407 to our INVITE, once. RFC 3261 s22.2: ACK the
// challenge in its own transaction, then send a NEW INVITE transaction -- same
// Call-ID and From-tag, CSeq+1, a fresh branch, no To-tag -- carrying
// Authorization (401) or Proxy-Authorization (407). The credential is never
// logged. Returns false, having sent nothing, when it cannot answer; the
// caller then treats the challenge as the call's failure.
bool SipTrunk::answerChallenge(Dialog& d, const std::shared_ptr<SipMessage>& challenge, int status)
{
	if (d.authAttempted || !hasCredentials()) return false;

	// The digest uri is the Request-URI, verbatim.
	const size_t lineLen = credentialLine(d, challenge, status, "INVITE", pstnUri(d.destE164, d.domain));
	if (lineLen == 0) return false;

	// Draw BOTH messages before anything is sent or changed (#581 review B2),
	// so a pool refusal returns false having sent nothing and left `d` as it
	// was -- the caller's failure path then ACKs the challenge from the
	// untouched transaction, exactly once. The ACK belongs to the challenged
	// transaction (it still carries the challenge's To-tag); the retry is a new
	// one: CSeq+1, a fresh branch, no To-tag.
	auto ack = _env.messageFromPool(buildAckForFailure(d), d.peer);
	if (!ack)
	{
		std::memset(_authLine, 0, sizeof(_authLine));
		_env.log("Trunk: challenge answer dropped, message pool exhausted (" + d.destE164 + ")", true);
		return false;
	}
	const std::string savedBranch = d.branch;
	const std::string savedToTag = d.toTag;
	const uint32_t savedCseq = d.cseq;
	d.cseq += 1;
	d.branch = "z9hG4bK" + IDGen::GenerateID(12);
	d.toTag.clear();

	std::string inviteText =
		buildInvite(d, d.offerSdp, std::string_view(_authLine, lineLen));
	auto invite = _env.messageFromPool(inviteText, d.peer);
	std::memset(_authLine, 0, sizeof(_authLine));
	if (!invite)
	{
		std::fill(inviteText.begin(), inviteText.end(), '\0');
		d.branch = savedBranch;   // back to the challenged transaction, unsent
		d.toTag = savedToTag;
		d.cseq = savedCseq;
		_env.log("Trunk: challenge answer dropped, message pool exhausted (" + d.destE164 + ")", true);
		return false;
	}
	d.authAttempted = true;
	d.challengedBranch = savedBranch;
	d.challengedToTag = savedToTag;
	d.challengedCseq = savedCseq;
	d.state = State::Trying;

	ack->syncContentLength();
	_env.enqueue(d.peer, std::move(ack));
	invite->syncContentLength();
	_env.enqueue(d.peer, std::move(invite));
	_env.log("Trunk: " + std::to_string(status) + " challenge answered (" + d.destE164 + ")");
	logInvite(_env, inviteText);   // #618: Authorization redacted there
	std::fill(inviteText.begin(), inviteText.end(), '\0');
	return true;
}

// The credential header line answering `challenge` for `method` on `uri`,
// built into _authLine: the one digest path, shared by the INVITE retry (#399)
// and the BYE retry (#687) so the two cannot drift. Returns the line's length,
// or 0 when the challenge cannot be answered -- no challenge header, one that
// does not parse (silently, as #581 had it), or one SipDigest refuses (auth-int
// only, an unknown algorithm; logged). The caller zeroes _authLine once the
// line is copied into a message. Nothing here logs the nonce or the digest.
size_t SipTrunk::credentialLine(const Dialog& d, const std::shared_ptr<SipMessage>& challenge, int status,
	std::string_view method, std::string_view uri)
{
	const bool proxy = (status == 407);
	std::string_view hdr = challenge->getHeaderLine(proxy ? "proxy-authenticate" : "www-authenticate");
	if (hdr.empty()) return 0;
	if (!SipDigest::parseChallenge(hdr, _challenge, proxy)) return 0;

	char cnonce[SipDigest::kCnonceLen + 1];
	SipDigest::makeCnonce(cnonce);
	const std::string_view user = _cfg.authUser[0] ? std::string_view(_cfg.authUser)
	                                               : std::string_view(_cfg.fromUser);

	const char* name = SipDigest::authorizationHeaderName(_challenge);
	const size_t nameLen = std::strlen(name);
	std::memcpy(_authLine, name, nameLen);
	_authLine[nameLen] = ':';
	_authLine[nameLen + 1] = ' ';
	size_t valueLen = 0;
	if (!SipDigest::buildAuthorization(_challenge, user, std::string_view(_secret), method, uri,
		/*ncValue=*/1, std::string_view(cnonce, SipDigest::kCnonceLen),
		_authLine + nameLen + 2, sizeof(_authLine) - nameLen - 2, valueLen))
	{
		_env.log("Trunk: " + std::to_string(status) + " challenge cannot be answered ("
			+ d.destE164 + ")", true);
		return 0;
	}
	return nameLen + 2 + valueLen;
}

// Issue #687: answer a 401/407 to our BYE, once, through credentialLine() --
// for method BYE and the BYE's own Request-URI, the remote target. A BYE is a
// non-INVITE transaction (RFC 3261 s17.1.2), so the challenge takes no ACK;
// the retry is a new transaction in the same dialog: same Call-ID, tags and
// route, CSeq+1, a fresh branch. The credential is never logged. Returns
// false, having sent nothing and left `d` as it was, when it cannot answer --
// no credentials, an unanswerable challenge, already retried -- and the caller
// then releases the dialog exactly as it always has.
bool SipTrunk::answerByeChallenge(Dialog& d, const std::shared_ptr<SipMessage>& challenge, int status)
{
	// The last two are buildBye()'s own preconditions, so the string drawn
	// below cannot come back empty.
	if (d.byeAuthAttempted || !hasCredentials() || d.toTag.empty() || d.remoteTarget.empty()) return false;

	const size_t lineLen = credentialLine(d, challenge, status, "BYE", d.remoteTarget);
	if (lineLen == 0) return false;

	// buildBye() stamps d.cseq+1 (s12.2.1.1), so the bump puts the retry one
	// past the challenged BYE. In Terminating nothing reads d.cseq as the
	// INVITE's any more: there is no ACK left to build, and the #581 B1 check
	// in handleResponse() skips this state.
	d.cseq += 1;
	auto bye = _env.messageFromPool(
		buildBye(d, "z9hG4bK" + IDGen::GenerateID(12), std::string_view(_authLine, lineLen)), d.peer);
	std::memset(_authLine, 0, sizeof(_authLine));
	if (!bye)
	{
		d.cseq -= 1;
		_env.log("Trunk: BYE challenge answer dropped, message pool exhausted (" + d.destE164 + ")", true);
		return false;
	}
	d.byeAuthAttempted = true;
	bye->syncContentLength();
	_env.enqueue(d.peer, std::move(bye));
	_env.log("Trunk: " + std::to_string(status) + " to our BYE answered with credentials (" + d.destE164 + ")");
	return true;
}

// ── Issue #399: REGISTER with the carrier ────────────────────────────────────

void SipTrunk::tickRegistration(uint64_t nowMs, const sockaddr_in& sbc)
{
	if (!_cfg.valid() || !hasCredentials()) return;
	if (!_regLive)
	{
		SipRegistrationClient::Config rc;
		if (std::snprintf(rc.registrarHost, sizeof(rc.registrarHost), "%s", _cfg.host) < 0) return;
		rc.registrarPort = _cfg.port;
		if (std::snprintf(rc.domain,   sizeof(rc.domain),   "%s", _cfg.host) < 0) return;
		if (std::snprintf(rc.aorUser,  sizeof(rc.aorUser),  "%s", _cfg.fromUser) < 0) return;
		if (std::snprintf(rc.authUser, sizeof(rc.authUser), "%s",
			_cfg.authUser[0] ? _cfg.authUser : _cfg.fromUser) < 0) return;
		if (std::snprintf(rc.localIp,  sizeof(rc.localIp),  "%s", _env.localIp().c_str()) < 0) return;
		rc.localPort = static_cast<uint16_t>(_env.serverPort());
		if (!_reg.configure(rc, _secret)) return;
		_reg.start(nowMs);
		_regLive = true;
	}
	_regPeer = sbc;
	sendRegisterIfDue(nowMs);
}

void SipTrunk::sendRegisterIfDue(uint64_t nowMs)
{
	// #617: Timer E resends the bytes still in _regReq -- same branch and CSeq.
	// REGISTER is not tracked by TransactionLayer (classify() excludes it), so
	// this is its only retransmit schedule.
	if (!_reg.tick(nowMs, _regReq) && !_reg.retransmitDue(nowMs)) return;
	_env.enqueue(_regPeer, _env.messageFromPool(
		std::string_view(_regReq.bytes, _regReq.len), _regPeer));
}

bool SipTrunk::handleRegisterResponse(const std::shared_ptr<SipMessage>& data)
{
	if (!_regLive || siphdr::stripHeaderNameView(data->getCallID()) != _reg.callId()) return false;
	const auto st = data->getStatusInfo();
	if (!st.has_value()) return false;

	// Same posture as a dialog response (#356): only the address the REGISTER
	// went to may answer it. Consumed either way.
	if (data->getSource().sin_addr.s_addr != _regPeer.sin_addr.s_addr)
	{
		// #617: spoofing is countable, not just a log line. #663: and logged
		// only at 1, 2, 4, 8, ... so a flood cannot flood the log.
		const uint32_t n = ++_regForgedResponses;
		if ((n & (n - 1)) == 0)
		{
			_env.log("Trunk: REGISTER response from a non-carrier address dropped ("
				+ std::to_string(n) + " so far)", true);
		}
		return true;
	}

	auto value = [&](std::string_view name) {
		return siphdr::stripHeaderNameView(data->getHeaderLine(name));
	};
	SipRegistrationClient::ResponseView v;
	v.code              = static_cast<int>(st->code);
	v.wwwAuthenticate   = value("WWW-Authenticate");
	v.proxyAuthenticate = value("Proxy-Authenticate");
	v.expires           = value("Expires");
	v.contact           = siphdr::stripHeaderNameView(data->getContact());   // #686: "m:" too
	v.minExpires        = value("Min-Expires");
	v.retryAfter        = value("Retry-After");

	const uint64_t nowMs = static_cast<uint64_t>(
		std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::steady_clock::now().time_since_epoch()).count());
	const auto before = _reg.state();
	_reg.onResponse(nowMs, v);
	const auto after = _reg.state();

	// #618: every final answer, with its reason phrase (Engage answers a failed
	// REGISTER "200 Authorization failure"), the lease, and the Via
	// received/rport the carrier saw of us from behind CGNAT. Registration
	// behaviour is unchanged; this only reports.
#if POCKETDIAL_TRUNK_WIRE_LOG
	if (v.code >= 200)
	{
		const std::string_view via = data->getVia();
		auto param = [&](std::string_view key) -> std::string_view {
			const size_t p = via.find(key);
			if (p == std::string_view::npos) return "-";
			const std::string_view r = via.substr(p + key.size());
			return r.substr(0, r.find_first_of(";, \t"));
		};
		auto sv = [](std::string_view s) { return s.empty() ? std::string_view("-") : s; };
		const std::string_view status = data->getHeader();
		const std::string_view received = param(";received="), rport = param(";rport=");
		const std::string_view expires = sv(v.expires), contact = sv(v.contact);
		char line[200];   // under LogQueue's 256-byte cap; Contact is cut first
		const int len = std::snprintf(line, sizeof(line),
			"Trunk: REGISTER <- %.*s; Expires %.*s, granted %us; Via received=%.*s rport=%.*s; Contact %.*s",
			static_cast<int>(std::min<size_t>(status.size(), 64)), status.data(),
			static_cast<int>(std::min<size_t>(expires.size(), 10)), expires.data(),
			v.code < 300 ? static_cast<unsigned>(_reg.status().grantedExpiresSec) : 0u,
			static_cast<int>(std::min<size_t>(received.size(), 40)), received.data(),
			static_cast<int>(std::min<size_t>(rport.size(), 6)), rport.data(),
			static_cast<int>(contact.size()), contact.data());
		if (len > 0) _env.log(line);   // a truncated line is still whole up to the cap
	}
#endif
	if (after != before && after == SipRegistrationClient::State::Registered)
		_env.log("Trunk: registered with the carrier");
	else if (after != before && after == SipRegistrationClient::State::Failed)
		_env.log("Trunk: REGISTER failed; backing off", true);

	sendRegisterIfDue(nowMs);   // a 401/407/423 retry goes out now, not a tick later
	return true;
}
