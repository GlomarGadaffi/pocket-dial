#include "BlfSubscriptions.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>

#include "IDGen.hpp"
#include "Session.hpp"
#include "SipClient.hpp"
#include "SipHeaderUtil.hpp"
#include "SipMessageTypes.h"
#include "SipWireUtil.hpp"

std::string BlfSubscriptions::parseEventPackage(std::string_view eventHeader)
{
	// Takes the already-parsed Event header line (SipMessage::getEvent), rather
	// than re-serialising the whole message and running a second, weaker header
	// scan over it — the old scanner also matched any line named "o", which is
	// the SDP origin line's name too.
	std::string pkg = siphdr::stripHeaderName(eventHeader);
	size_t semi = pkg.find(';');            // drop ;id=... and friends
	if (semi != std::string::npos) pkg.erase(semi);
	size_t e = pkg.find_last_not_of(" \t\r\n");
	if (e == std::string::npos) return "";
	pkg.erase(e + 1);
	return pkg;
}

std::string BlfSubscriptions::buildDialogInfoXml(const std::string& entity, unsigned version,
	const std::string& dialogId, const std::string& state, const std::string& direction)
{
	// Minimal RFC 4235 document, always state="full": each NOTIFY carries the
	// complete (zero-or-one element) dialog set, so watchers never need to merge
	// partials. An empty `state` omits the <dialog> element — the canonical
	// "idle lamp" body that Yealink/Grandstream BLF keys expect.
	std::ostringstream xml;
	xml << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
	    << "<dialog-info xmlns=\"urn:ietf:params:xml:ns:dialog-info\" version=\""
	    << version << "\" state=\"full\" entity=\"" << entity << "\">\r\n";
	if (!state.empty())
	{
		xml << "<dialog id=\"" << dialogId << "\"";
		if (!direction.empty()) xml << " direction=\"" << direction << "\"";
		xml << "><state>" << state << "</state></dialog>\r\n";
	}
	xml << "</dialog-info>\r\n";
	return xml.str();
}

std::string BlfSubscriptions::computeDialogState(const std::string& targetAor,
	std::string& outDirection, std::string& outDialogId) const
{
	std::string best;
	auto rank = [](const std::string& s) -> int {
		if (s == "confirmed") return 3;
		if (s == "early")     return 2;
		if (s == "trying")    return 1;
		return 0;
	};
	_env.forEachSessionInvolving(targetAor,
		[&](const std::string& callID, const Session& session, PbxEnv::DialogRole role)
	{
		const bool isSrc  = (role == PbxEnv::DialogRole::Caller);
		const bool isDest = !isSrc;

		std::string state, dir;
		switch (session.getState())
		{
			case Session::State::Invited:
				state = isDest ? "early" : "trying";
				dir   = isDest ? "recipient" : "initiator";
				break;
			case Session::State::Connected:
			case Session::State::Held:
				// RFC 4235 §4: a held call is an established dialog; state stays
				// "confirmed" so the watcher's BLF lamp remains lit (#53).
				state = "confirmed";
				dir   = isSrc ? "initiator" : "recipient";
				break;
			default:
				return;
		}
		if (rank(state) > rank(best))
		{
			best = state;
			outDirection = dir;
			outDialogId  = callID;
		}
	});
	if (best.empty()) { outDirection.clear(); outDialogId.clear(); }
	return best;
}

std::shared_ptr<SipMessage> BlfSubscriptions::buildDialogNotify(DialogSubscription& sub,
	const std::string& state, const std::string& direction, const std::string& dialogId,
	bool terminated, const char* termReason)
{
	const std::string& activeIp = _env.localIp();
	const std::string srcIpPort = activeIp + ":" + std::to_string(_env.serverPort());
	const std::string destIpPort = sipwire::addrToIpPort(sub.addr);
	const std::string branch = "z9hG4bK" + IDGen::GenerateID(12);

	std::string entity = "sip:" + sub.targetAor + "@" + srcIpPort;
	std::string body = buildDialogInfoXml(entity, sub.version, dialogId, state, direction);

	int remaining = 0;
	if (!terminated)
	{
		auto now = std::chrono::steady_clock::now();
		remaining = static_cast<int>(std::chrono::duration_cast<std::chrono::seconds>(
			sub.deadline - now).count());
		if (remaining < 0) remaining = 0;
	}
	std::string subState = terminated
		? ("terminated;reason=" + std::string(termReason))
		: ("active;expires=" + std::to_string(remaining));

	// NOTIFY runs inside the subscription dialog: our To-tag becomes the From,
	// the watcher's From becomes the To (RFC 6665 §4.4.1 — roles swap).
	// subTo / watcherFrom hold FULL header lines ("To: <sip:...>;tag=x"), so the
	// value has to be unwrapped before it is re-stamped under the swapped name.
	// Uses the shared, guarded helper rather than a local "cut at the first colon"
	// lambda, which would mangle any value that is not prefixed with its name.
	std::ostringstream ss;
	ss << "NOTIFY sip:" << destIpPort << " SIP/2.0\r\n"
	   << "Via: SIP/2.0/UDP " << srcIpPort << ";branch=" << branch << "\r\n"
	   << "From: " << siphdr::stripHeaderName(sub.subTo) << "\r\n"
	   << "To: " << siphdr::stripHeaderName(sub.watcherFrom) << "\r\n"
	   << "Call-ID: " << sub.callId << "\r\n"
	   << "CSeq: " << sub.cseq++ << " NOTIFY\r\n"
	   << "Max-Forwards: 70\r\n"
	   << "Event: dialog\r\n"
	   << "Subscription-State: " << subState << "\r\n"
	   << "Contact: <sip:" << sub.targetAor << "@" << srcIpPort << ">\r\n"
	   << "User-Agent: pocket-dial\r\n"
	   << "Content-Type: application/dialog-info+xml\r\n"
	   << "Content-Length: " << body.size() << "\r\n\r\n"
	   << body;

	return _env.messageFromPool(ss.str(), sub.addr);
}

void BlfSubscriptions::onSubscribe(const std::shared_ptr<SipMessage>& data)
{
	// 1. Event-package gate: only the RFC 4235 "dialog" package is implemented.
	std::string pkg = parseEventPackage(data->getEvent());
	if (pkg != "dialog")
	{
		auto resp = _env.messageFromPool(data->toString(), data->getSource());
		if (!resp) return;   // pool exhausted: drop, peer retransmits (#101A)
		resp->setHeader(SipMessageTypes::BAD_EVENT);
		resp->clearBody();
		resp->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		resp->addHeader("Allow-Events", "dialog");
		_env.enqueue(data->getSource(), std::move(resp));
		return;
	}

	// 2. Watched-target validation.
	std::string target(data->getToNumber());
	if (!_env.validAor(target))
	{
		auto resp = _env.messageFromPool(data->toString(), data->getSource());
		if (!resp) return;   // pool exhausted: drop, peer retransmits (#101A)
		resp->setHeader(SipMessageTypes::BAD_REQUEST);
		resp->clearBody();
		resp->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		_env.enqueue(data->getSource(), std::move(resp));
		return;
	}

	const int expires = _env.requestedExpires(data);
	// Subscriptions are keyed by the bare Call-ID value (getCallID() hands back
	// the whole header line). Same guarded helper as everywhere else.
	const std::string callId = siphdr::stripHeaderName(data->getCallID());

	// 3. Refresh / unsubscribe: match existing subscription by Call-ID.
	DialogSubscription* sub = nullptr;
	for (auto& s : _subscriptions)
	{
		if (s.used && s.callId == callId) { sub = &s; break; }
	}

	if (sub == nullptr && expires > 0)
	{
		for (auto& s : _subscriptions)
		{
			if (!s.used) { sub = &s; break; }
		}
		if (sub == nullptr)
		{
			auto resp = _env.messageFromPool(data->toString(), data->getSource());
			if (!resp) return;   // pool exhausted: drop, peer retransmits (#101A)
			resp->setHeader("SIP/2.0 503 Service Unavailable");
			resp->clearBody();
			resp->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
			_env.enqueue(data->getSource(), std::move(resp));
			_env.log("BLF: subscription pool exhausted, 503 to watcher of " + target, true);
			return;
		}
		*sub = DialogSubscription{};
		sub->used        = true;
		sub->callId      = callId;
		sub->watcherFrom = std::string(data->getFrom());
		sub->subTo       = std::string(data->getTo()) + ";tag=" + IDGen::GenerateID(9);
		sub->targetAor   = target;
		_env.log("BLF: new subscription, watcher " + std::string(data->getFromNumber())
			+ " -> target " + target);
	}

	// 4. 202 Accepted (RFC 6665 §4.2.1).
	{
		auto resp = _env.messageFromPool(data->toString(), data->getSource());
		if (!resp) return;   // pool exhausted: drop, peer retransmits (#101A)
		resp->setHeader(SipMessageTypes::ACCEPTED);
		resp->clearBody();
		resp->setVia(sipwire::viaWithReceived(data->getVia(), data->getSource()));
		if (sub) resp->setTo(sub->subTo);
		else     resp->setTo(std::string(data->getTo()) + ";tag=" + IDGen::GenerateID(9));
		resp->setContact(_env.contactFor(target));
		resp->addHeader("Expires", std::to_string(expires));
		_env.enqueue(data->getSource(), std::move(resp));
	}

	if (sub == nullptr) return;

	sub->addr       = data->getSource();
	sub->expiresSec = expires;
	sub->deadline   = std::chrono::steady_clock::now() + std::chrono::seconds(expires);

	// 5. Immediate NOTIFY (RFC 6665 §4.2.1.4).
	std::string dir, dialogId;
	std::string state = computeDialogState(target, dir, dialogId);
	const bool terminating = (expires == 0);
	auto notify = buildDialogNotify(*sub, state, dir, dialogId, terminating, "noresource");
	// Same reasoning as refresh(): only bank lastState if the NOTIFY was actually
	// built, so a pool refusal leaves it empty and the next refresh() retries
	// rather than treating this state as already delivered (#101A). The
	// `terminating` teardown below still runs either way.
	if (notify)
	{
		_env.enqueue(sub->addr, std::move(notify));
		sub->lastState = state + "|" + dir + "|" + dialogId;
		sub->version++;
	}

	if (terminating)
	{
		_env.log("BLF: unsubscribe, watcher of " + target + " released");
		*sub = DialogSubscription{};
	}
}

void BlfSubscriptions::refresh()
{
	for (auto& sub : _subscriptions)
	{
		if (!sub.used) continue;
		std::string dir, dialogId;
		std::string state = computeDialogState(sub.targetAor, dir, dialogId);
		std::string token = state + "|" + dir + "|" + dialogId;
		if (token == sub.lastState) continue;
		auto notify = buildDialogNotify(sub, state, dir, dialogId, false, "");
		// Do NOT record lastState if the pool refused: the token is what suppresses
		// re-notifying, so banking a state we never sent would leave this watcher's
		// lamp stale until the target's state changes AGAIN. Leaving it untouched
		// means the next refresh() retries this NOTIFY (#101A).
		if (!notify) continue;
		_env.enqueue(sub.addr, std::move(notify));
		sub.lastState = token;
		sub.version++;
	}
}

void BlfSubscriptions::sweepExpired()
{
	auto now = std::chrono::steady_clock::now();
	for (auto& sub : _subscriptions)
	{
		if (!sub.used || now < sub.deadline) continue;
		std::string dir, dialogId;
		std::string state = computeDialogState(sub.targetAor, dir, dialogId);
		auto notify = buildDialogNotify(sub, state, dir, dialogId, true, "timeout");
		if (!notify)
		{
			// Keep the slot one more sweep rather than wiping it after silently
			// dropping the terminal NOTIFY: without it the watcher never learns the
			// subscription ended and its lamp stays frozen until it re-SUBSCRIBEs.
			// The deadline has already passed, so the next sweep retries (#101A).
			continue;
		}
		_env.enqueue(sub.addr, std::move(notify));
		_env.log("BLF: subscription to " + sub.targetAor + " expired");
		sub = DialogSubscription{};
	}
}
