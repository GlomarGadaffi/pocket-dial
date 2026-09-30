// RegisteredContact_test.cpp: issues #797 and #798.
//
// A phone registers a Contact URI, and that URI is where the PBX must address
// requests it sends to the phone (RFC 3261 §10.2.1, §12.2.1.1). A Snom 370
// registers `<sip:1001@ip:1037;line=h2k6k1ih>` and refuses (404 on OPTIONS,
// 481 on BYE) any request whose Request-URI lacks the ;line= parameter.
//
//   #797  the OPTIONS keepalive rebuilt the Request-URI as sip:<ext>@<ip>:<port>.
//   #798  the callee's BYE was relayed to the caller with the Request-URI the
//         callee had addressed to the PBX, and the caller's 481 was not treated
//         as the session being over (RFC 3261 §15.1.2), so the slot leaked.

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "PoolConfig.hpp"
#include "RequestsHandler.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	using Sent = std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>;

	const char* const kPbxIp = "192.168.31.1";
	const char* const kSnomIp = "192.168.31.10";
	const char* const kYealinkIp = "192.168.31.20";
	const char* const kSnomContactUri = "sip:100@192.168.31.10:1037;line=h2k6k1ih";

	sockaddr_in addrFor(const std::string& ip, uint16_t port)
	{
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_addr.s_addr = inet_addr(ip.c_str());
		a.sin_port = htons(port);
		return a;
	}

	std::shared_ptr<SipMessage> makeRegister(const std::string& ext, const std::string& ip, uint16_t port,
	                                         const std::string& contactLine)
	{
		std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":" + std::to_string(port) + ";branch=z9hG4bKreg" + ext + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + ext + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: reg-" + ext + "\r\n"
			"CSeq: 1 REGISTER\r\n" +
			contactLine +
			"Expires: 3600\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip, port));
	}

	std::string snomContactLine()
	{
		return std::string("Contact: <") + kSnomContactUri + ">;reg-id=1\r\n";
	}

	std::string sdpBody()
	{
		return "v=0\r\no=- 0 0 IN IP4 10.0.0.1\r\ns=-\r\nc=IN IP4 10.0.0.1\r\nt=0 0\r\n"
		       "m=audio 10000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n";
	}

	std::string headerLine(const std::string& raw, const std::string& name)
	{
		size_t pos = 0;
		while (pos < raw.size())
		{
			size_t eol = raw.find("\r\n", pos);
			if (eol == std::string::npos) eol = raw.size();
			std::string line = raw.substr(pos, eol - pos);
			if (line.size() > name.size() && line.compare(0, name.size(), name) == 0) return line;
			pos = eol + 2;
		}
		return {};
	}

	std::string requestLineOf(const std::string& raw)
	{
		return raw.substr(0, raw.find("\r\n"));
	}

	// The most recent message sent to `addr` whose text contains `needle`.
	std::string findSentTo(const Sent& sent, const sockaddr_in& addr, const std::string& needle)
	{
		for (auto it = sent.rbegin(); it != sent.rend(); ++it)
		{
			if (it->first.sin_addr.s_addr != addr.sin_addr.s_addr) continue;
			if (it->first.sin_port != addr.sin_port) continue;
			if (!it->second) continue;
			std::string raw = it->second->toString();
			if (raw.find(needle) != std::string::npos) return raw;
		}
		return {};
	}

	// Snom (100) calls Yealink (106), Yealink answers. Returns the Call-ID.
	std::string connectCall(RequestsHandler& handler, Sent& sent, const std::string& callId)
	{
		handler.handle(makeRegister("100", kSnomIp, 1037, snomContactLine()));
		handler.handle(makeRegister("106", kYealinkIp, 5062,
			"Contact: <sip:106@192.168.31.20:5062>\r\n"));

		std::string body = sdpBody();
		std::string invite =
			"INVITE sip:106@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(kSnomIp) + ":1037;branch=z9hG4bKinv" + callId + "\r\n"
			"From: <sip:100@server>;tag=ft" + callId + "\r\n"
			"To: <sip:106@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <" + std::string(kSnomContactUri) + ">\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(invite, addrFor(kSnomIp, 1037)));

		std::string fork = findSentTo(sent, addrFor(kYealinkIp, 5062), "INVITE sip:106@");
		EXPECT_FALSE(fork.empty()) << "the call must be forwarded to 106";
		std::string ok =
			"SIP/2.0 200 OK\r\n" +
			headerLine(fork, "Via:") + "\r\n" +
			headerLine(fork, "From:") + "\r\n"
			"To: <sip:106@server>;tag=ans106\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Contact: <sip:106@192.168.31.20:5062>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(ok, addrFor(kYealinkIp, 5062)));
		EXPECT_EQ(handler.getSession("Call-ID: " + callId).value()->getState(), Session::State::Connected);
		return callId;
	}

	// The callee hangs up, addressing its BYE to the PBX exactly as a phone does
	// with the Contact the PBX presented (#754).
	std::shared_ptr<SipMessage> calleeBye(const std::string& callId)
	{
		std::string raw =
			"BYE sip:100@" + std::string(kPbxIp) + ":5060;transport=UDP SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(kYealinkIp) + ":5062;branch=z9hG4bKbye" + callId + "\r\n"
			"From: <sip:106@server>;tag=ans106\r\n"
			"To: <sip:100@server>;tag=ft" + callId + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 7 BYE\r\n"
			"Max-Forwards: 70\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(kYealinkIp, 5062));
	}
}

TEST(RegisteredContact, OptionsPingRequestUriCarriesTheRegisteredContactUri)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	handler.handle(makeRegister("100", kSnomIp, 1037, snomContactLine()));

	handler.tick();

	const std::string ping = findSentTo(sent, addrFor(kSnomIp, 1037), "OPTIONS ");
	ASSERT_FALSE(ping.empty()) << "a freshly registered phone must be pinged on the first tick";
	EXPECT_EQ(requestLineOf(ping), std::string("OPTIONS ") + kSnomContactUri + " SIP/2.0")
		<< "#797: the Request-URI must be the registered Contact URI, ;line= included";
}

TEST(RegisteredContact, OptionsPingFallsBackToTheObservedAddressWhenNoContactWasRegistered)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	handler.handle(makeRegister("100", kSnomIp, 1037, ""));

	handler.tick();

	const std::string ping = findSentTo(sent, addrFor(kSnomIp, 1037), "OPTIONS ");
	ASSERT_FALSE(ping.empty());
	EXPECT_EQ(requestLineOf(ping), "OPTIONS sip:100@192.168.31.10:1037 SIP/2.0")
		<< "no stored Contact: the pre-#797 form is kept";
}

TEST(RegisteredContact, RelayedByeIsAddressedToTheCallersRegisteredContact)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	const std::string callId = connectCall(handler, sent, "rc-bye-relay");

	handler.handle(calleeBye(callId));

	const std::string atCaller = findSentTo(sent, addrFor(kSnomIp, 1037), "CSeq: 7 BYE");
	ASSERT_FALSE(atCaller.empty()) << "the callee's BYE must be relayed to the caller";
	EXPECT_EQ(requestLineOf(atCaller), std::string("BYE ") + kSnomContactUri + " SIP/2.0")
		<< "#798: the Request-URI is the caller's Contact, not the PBX's own address";
}

TEST(RegisteredContact, A481ToTheRelayedByeFreesTheSession)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	const std::string callId = connectCall(handler, sent, "rc-bye-481");
	handler.handle(calleeBye(callId));
	ASSERT_TRUE(handler.getSession("Call-ID: " + callId).has_value()) << "precondition: the session waits for the caller's answer";

	std::string resp =
		"SIP/2.0 481 Call/Transaction Does Not Exist\r\n"
		"Via: SIP/2.0/UDP " + std::string(kYealinkIp) + ":5062;branch=z9hG4bKbye" + callId + "\r\n"
		"From: <sip:106@server>;tag=ans106\r\n"
		"To: <sip:100@server>;tag=ft" + callId + "\r\n"
		"Call-ID: " + callId + "\r\n"
		"CSeq: 7 BYE\r\n"
		"Content-Length: 0\r\n\r\n";
	handler.handle(RequestsHandler::getMessageFromPool(resp, addrFor(kSnomIp, 1037)));

	EXPECT_FALSE(handler.getSession("Call-ID: " + callId).has_value())
		<< "#798: RFC 3261 §15.1.2: a 481 to a BYE means the session is over, the slot must be freed";
}

TEST(RegisteredContact, ServerOriginatedByeIsAddressedToTheRegisteredContact)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	const std::string callId = connectCall(handler, sent, "rc-bye-server");

	handler.forceDisconnect("106");
	handler.tick();   // drainOutbox() merges _asyncOutbox

	const std::string atCaller = findSentTo(sent, addrFor(kSnomIp, 1037), "BYE ");
	ASSERT_FALSE(atCaller.empty()) << "the admin kill must BYE the caller";
	EXPECT_EQ(requestLineOf(atCaller), std::string("BYE ") + kSnomContactUri + " SIP/2.0")
		<< "a BYE the PBX authors itself needs the registered Contact too";
}
