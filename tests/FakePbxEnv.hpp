#ifndef FAKE_PBX_ENV_HPP
#define FAKE_PBX_ENV_HPP

// Minimal in-memory PbxEnv for host tests of the decomposed SIP state machines
// (ParkOrbit, RegisterBeeper, BlfSubscriptions). It records everything the
// machine under test enqueues so a test can assert on the exact bytes that would
// have gone out on the wire — the layer the 131-test suite never covered, which
// is how a doubled "Call-ID: Call-ID:" survived in the park re-INVITE.

#if defined(__linux__)
#include <arpa/inet.h>
#elif defined _WIN32 || defined _WIN64
#include <ws2tcpip.h>
#endif

#include <cctype>
#include <cstdlib>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "PbxEnv.hpp"
#include "Session.hpp"
#include "SipClient.hpp"
#include "SipHeaderUtil.hpp"
#include "SipMessage.hpp"

class FakePbxEnv : public PbxEnv
{
public:
	struct Sent
	{
		sockaddr_in to{};
		std::string raw;
	};

	// One recorded serverBye() call. Asserting on these rather than on the bytes
	// the fake minted is what actually pins the delegation: the real builder is
	// RequestsHandler::buildServerBye, which is private and not linked into this
	// target, so any BYE text here is the fake's own and proves nothing about it.
	struct ByeCall
	{
		std::string destExt;
		std::string callId;
		std::string fromHeader;
		std::string toHeader;
	};

	std::vector<Sent>        sent;
	std::vector<std::string> logs;
	std::vector<ByeCall>     byeCalls;

	// Registered extensions findRegistered() resolves against.
	std::unordered_map<std::string, std::shared_ptr<SipClient>> registered;
	std::unordered_map<std::string, std::shared_ptr<Session>>   sessions;

	// Set false to simulate a drained session pool (the 503 guard paths).
	bool sessionPoolAvailable = true;
	// Set false to simulate an exhausted message pool (Issue #101(A) territory):
	// messageFromPool() returns nullptr, as the real pool does once it and its
	// bounded heap fallback are both spent.
	bool messagePoolAvailable = true;

	static sockaddr_in addr(const char* ip, uint16_t port)
	{
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_port   = htons(port);
		::inet_pton(AF_INET, ip, &a.sin_addr);
		return a;
	}

	// Raw text of the nth enqueued message (empty when out of range).
	std::string sentRaw(std::size_t i) const
	{
		return i < sent.size() ? sent[i].raw : std::string{};
	}

	// Count non-overlapping occurrences of `needle` in `hay` — the header-shape
	// assertion every machine test needs ("exactly one To: line").
	static int countOf(const std::string& hay, const std::string& needle)
	{
		int n = 0;
		for (size_t p = hay.find(needle); p != std::string::npos;
			p = hay.find(needle, p + needle.size()))
		{
			++n;
		}
		return n;
	}

	// ── PbxEnv ───────────────────────────────────────────────────────────────
	void enqueue(const sockaddr_in& to, std::shared_ptr<SipMessage> msg) override
	{
		sent.push_back(Sent{to, msg ? msg->toString() : std::string{}});
	}
	std::shared_ptr<SipMessage> messageFromPool(std::string raw, sockaddr_in src) override
	{
		if (!messagePoolAvailable) return nullptr;
		return std::make_shared<SipMessage>(raw, src);
	}
	void log(std::string msg, bool /*isError*/ = false) override
	{
		logs.push_back(std::move(msg));
	}
	const std::string& localIp() const override { return _localIp; }
	int serverPort() const override { return 5060; }

	std::shared_ptr<SipClient> findRegistered(std::string_view number) override
	{
		auto it = registered.find(std::string(number));
		return it == registered.end() ? nullptr : it->second;
	}
	std::shared_ptr<SipClient> allocVirtualPeer(std::string number, const sockaddr_in& a) override
	{
		return std::make_shared<SipClient>(std::move(number), a);
	}
	std::shared_ptr<Session> allocSession(const std::string& callID,
		const std::shared_ptr<SipClient>& src) override
	{
		if (!sessionPoolAvailable) return nullptr;
		return std::make_shared<Session>(callID, src);
	}
	void insertSession(const std::string& callID, const std::shared_ptr<Session>& session) override
	{
		sessions.emplace(callID, session);
	}
	std::shared_ptr<Session> findSession(std::string_view callID) override
	{
		auto it = sessions.find(std::string(callID));
		return it == sessions.end() ? nullptr : it->second;
	}
	std::string contactFor(std::string_view number) const override
	{
		return "<sip:" + std::string(number) + "@" + _localIp + ":5060>";
	}
	std::shared_ptr<SipMessage> serverBye(const std::string& destExt,
		const sockaddr_in& destAddr, const std::string& callId,
		const std::string& fromHeader, const std::string& toHeader) override
	{
		byeCalls.push_back(ByeCall{destExt, callId, fromHeader, toHeader});
		// Mirrors RequestsHandler::buildServerBye: strips any header-name prefix
		// off the three dialog fields and emits CSeq 2 BYE.
		std::string raw =
			"BYE sip:" + destExt + "@" + _localIp + " SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + _localIp + ":5060;branch=z9hG4bKfake\r\n"
			"From: " + siphdr::stripHeaderName(fromHeader) + "\r\n"
			"To: " + siphdr::stripHeaderName(toHeader) + "\r\n"
			"Call-ID: " + siphdr::stripHeaderName(callId) + "\r\n"
			"CSeq: 2 BYE\r\n"
			"Max-Forwards: 70\r\n"
			"Content-Length: 0\r\n\r\n";
		return std::make_shared<SipMessage>(raw, destAddr);
	}
	void forEachSessionInvolving(std::string_view aor,
		const std::function<void(const std::string&, const Session&, DialogRole)>& fn) const override
	{
		for (const auto& [callID, session] : sessions)
		{
			if (!session) continue;
			if (session->getSrc() && session->getSrc()->getNumber() == aor)
				fn(callID, *session, DialogRole::Caller);
			if (session->getDest() && session->getDest()->getNumber() == aor)
				fn(callID, *session, DialogRole::Callee);
		}
	}
	bool validAor(std::string_view s) const override
	{
		if (s.empty() || s.size() > 32) return false;
		for (char c : s)
		{
			if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '-' || c == '_'))
				return false;
		}
		return true;
	}
	int requestedExpires(const std::shared_ptr<SipMessage>& msg) const override
	{
		const std::string raw = msg ? msg->toString() : std::string{};
		auto p = raw.find("Expires:");
		if (p == std::string::npos) return 3600;
		return std::atoi(raw.c_str() + p + 8);
	}

	// One recorded routeTrunkCall() call, for CallForker::routeDialPlan()'s
	// Trunk-action tests (Issue #165) to assert the transformed destination
	// actually reached the anchor-call path.
	struct TrunkCall
	{
		std::string callId;
		std::string callerNumber;
		std::string destination;
	};
	std::vector<TrunkCall> trunkCalls;
	// Set false to simulate "no anchor client connected" — routeTrunkCall()
	// then returns false without sending anything, mirroring
	// RequestsHandler::originateAnchorCall()'s respondIfDisconnected=false path.
	bool trunkAnchorConnected = true;

	bool routeTrunkCall(const std::shared_ptr<SipMessage>& data,
		const std::shared_ptr<SipClient>& caller, const std::string& destination) override
	{
		if (!trunkAnchorConnected) return false;
		trunkCalls.push_back(TrunkCall{
			data ? std::string(data->getCallID()) : std::string{},
			caller ? std::string(caller->getNumber()) : std::string{},
			destination});
		return true;
	}

private:
	std::string _localIp = "192.168.1.10";
};

#endif
