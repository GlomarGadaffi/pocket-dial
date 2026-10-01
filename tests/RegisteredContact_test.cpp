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

#include <chrono>
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

	// The caller hangs up, from its own Via and with its own dialog tags.
	std::shared_ptr<SipMessage> callerBye(const std::string& callId)
	{
		std::string raw =
			"BYE sip:106@" + std::string(kPbxIp) + ":5060;transport=UDP SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(kSnomIp) + ":1037;branch=z9hG4bKcbye" + callId + "\r\n"
			"From: <sip:100@server>;tag=ft" + callId + "\r\n"
			"To: <sip:106@server>;tag=ans106\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 9 BYE\r\n"
			"Max-Forwards: 70\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(kSnomIp, 1037));
	}

	// A response to the request `rawRequest`, built the way a phone does: its Via,
	// From, To, Call-ID and CSeq copied back (RFC 3261 §8.2.6.2).
	std::shared_ptr<SipMessage> answerTo(const std::string& rawRequest, const std::string& status,
	                                     const sockaddr_in& from)
	{
		std::string raw =
			"SIP/2.0 " + status + "\r\n" +
			headerLine(rawRequest, "Via:") + "\r\n" +
			headerLine(rawRequest, "From:") + "\r\n" +
			headerLine(rawRequest, "To:") + "\r\n" +
			headerLine(rawRequest, "Call-ID:") + "\r\n" +
			headerLine(rawRequest, "CSeq:") + "\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, from);
	}

	// How many messages to `addr` contain `needle`.
	int countSentTo(const Sent& sent, const sockaddr_in& addr, const std::string& needle)
	{
		int n = 0;
		for (const auto& [to, msg] : sent)
		{
			if (to.sin_addr.s_addr != addr.sin_addr.s_addr || to.sin_port != addr.sin_port || !msg) continue;
			if (msg->toString().find(needle) != std::string::npos) ++n;
		}
		return n;
	}

	// The PBX's own top Via on the BYE it originated: its address and a fresh branch,
	// neither of the phones'.
	void expectPbxViaOnBye(const std::string& bye, const std::string& phoneIp)
	{
		EXPECT_EQ(headerLine(bye, "Via:").rfind(std::string("Via: SIP/2.0/UDP ") + kPbxIp + ":5060;branch=z9hG4bK", 0), 0u)
			<< "#808: the PBX's own Via on the BYE it sends, so the far phone answers port 5060: " << headerLine(bye, "Via:");
		EXPECT_EQ(bye.find(phoneIp), std::string::npos)
			<< "#808: the sender's Via must not survive into the PBX's BYE";
		EXPECT_EQ(bye.find("z9hG4bKbye"), std::string::npos) << "the sender's branch must not be reused";
		EXPECT_EQ(bye.find("z9hG4bKcbye"), std::string::npos) << "the sender's branch must not be reused";
	}

	// Every free message-pool slot but `spare`, held by the caller.
	std::vector<std::shared_ptr<SipMessage>> holdAllButSpare(size_t spare)
	{
		std::vector<std::shared_ptr<SipMessage>> held;
		for (size_t i = 0;; ++i)
		{
			auto m = makeRegister("199", "192.168.31.99", 5060, "");
			if (!m) break;
			held.push_back(std::move(m));
		}
		for (size_t i = 0; i < spare && !held.empty(); ++i) held.pop_back();
		return held;
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

	// #808: the BYE the caller gets is the PBX's own, so it carries the PBX's CSeq,
	// not the callee's "7".
	const std::string atCaller = findSentTo(sent, addrFor(kSnomIp, 1037), "BYE ");
	ASSERT_FALSE(atCaller.empty()) << "the callee's hang-up must reach the caller";
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

	// #808: the 481 answers the BYE the PBX sent (its Via, its branch), not the callee's.
	const std::string byeAtCaller = findSentTo(sent, addrFor(kSnomIp, 1037), "BYE ");
	ASSERT_FALSE(byeAtCaller.empty());
	const int toCalleeBefore = static_cast<int>(sent.size());
	handler.handle(answerTo(byeAtCaller, "481 Call/Transaction Does Not Exist", addrFor(kSnomIp, 1037)));

	EXPECT_FALSE(handler.getSession("Call-ID: " + callId).has_value())
		<< "#798: RFC 3261 §15.1.2: a 481 to a BYE means the session is over, the slot must be freed";
	EXPECT_EQ(static_cast<int>(sent.size()), toCalleeBefore)
		<< "#808: the callee was already answered 200; the 481 is not relayed to it";
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

// ── #808: an ordinary relayed call's BYE is answered locally ─────────────────────
//
// Relaying the sender's BYE untouched kept only the sender's Via, so the far phone
// answered it to the sender's port on the PBX's IP (RFC 3261 §18.2.2), the PBX never
// saw the 200, the sender retransmitted to Timer F and the session never freed. The
// PBX now answers the sender 200 itself and sends its own BYE.

TEST(ByeLocalAnswer, CalleeByeIsAnsweredAndTheCallerGetsThePbxsOwnBye)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	const std::string callId = connectCall(handler, sent, "bye808-callee");
	const sockaddr_in yealink = addrFor(kYealinkIp, 5062);
	const sockaddr_in snom = addrFor(kSnomIp, 1037);

	handler.handle(calleeBye(callId));

	const std::string ok = findSentTo(sent, yealink, "SIP/2.0 200");
	ASSERT_FALSE(ok.empty()) << "#808: the sender's transaction is completed by the PBX";
	EXPECT_NE(ok.find("CSeq: 7 BYE"), std::string::npos);
	EXPECT_NE(ok.find("branch=z9hG4bKbye" + callId), std::string::npos) << "its own Via branch, echoed";

	const std::string bye = findSentTo(sent, snom, "BYE ");
	ASSERT_FALSE(bye.empty()) << "the caller must be told";
	EXPECT_EQ(requestLineOf(bye), std::string("BYE ") + kSnomContactUri + " SIP/2.0");
	expectPbxViaOnBye(bye, kYealinkIp);
	EXPECT_EQ(countSentTo(sent, snom, "BYE "), 1);
	ASSERT_TRUE(handler.getSession("Call-ID: " + callId).has_value())
		<< "the session waits for the caller's answer";

	const size_t before = sent.size();
	handler.handle(answerTo(bye, "200 OK", snom));
	EXPECT_FALSE(handler.getSession("Call-ID: " + callId).has_value())
		<< "the caller's 200 to the PBX's BYE frees the session";
	EXPECT_EQ(sent.size(), before) << "and is not relayed to the callee, who already has its 200";
}

TEST(ByeLocalAnswer, CallerByeIsAnsweredAndTheCalleeGetsThePbxsOwnBye)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	const std::string callId = connectCall(handler, sent, "bye808-caller");
	const sockaddr_in yealink = addrFor(kYealinkIp, 5062);
	const sockaddr_in snom = addrFor(kSnomIp, 1037);

	handler.handle(callerBye(callId));

	const std::string ok = findSentTo(sent, snom, "SIP/2.0 200");
	ASSERT_FALSE(ok.empty()) << "#808: the sender's transaction is completed by the PBX";
	EXPECT_NE(ok.find("CSeq: 9 BYE"), std::string::npos);

	const std::string bye = findSentTo(sent, yealink, "BYE ");
	ASSERT_FALSE(bye.empty()) << "the callee must be told";
	EXPECT_EQ(requestLineOf(bye), "BYE sip:106@192.168.31.20:5062 SIP/2.0");
	expectPbxViaOnBye(bye, kSnomIp);
	EXPECT_EQ(countSentTo(sent, yealink, "BYE "), 1);

	const size_t before = sent.size();
	handler.handle(answerTo(bye, "200 OK", yealink));
	EXPECT_FALSE(handler.getSession("Call-ID: " + callId).has_value())
		<< "the callee's 200 to the PBX's BYE frees the session";
	EXPECT_EQ(sent.size(), before) << "and is not relayed to the caller";
}

TEST(ByeLocalAnswer, ARetransmittedByeIsAnsweredAgainAndOriginatesNoSecondBye)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	const std::string callId = connectCall(handler, sent, "bye808-retx");
	const sockaddr_in yealink = addrFor(kYealinkIp, 5062);
	const sockaddr_in snom = addrFor(kSnomIp, 1037);

	handler.handle(calleeBye(callId));
	handler.handle(calleeBye(callId));   // same branch: the callee never saw the first 200

	EXPECT_EQ(countSentTo(sent, yealink, "CSeq: 7 BYE"), 2) << "answered again, RFC 3261 §17.2.2";
	EXPECT_EQ(countSentTo(sent, snom, "BYE "), 1) << "no second BYE toward the caller";
}

TEST(ByeLocalAnswer, AByeCrossingTheOneInFlightIsAnsweredAndOriginatesNothing)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	const std::string callId = connectCall(handler, sent, "bye808-cross");
	const sockaddr_in yealink = addrFor(kYealinkIp, 5062);
	const sockaddr_in snom = addrFor(kSnomIp, 1037);

	handler.handle(calleeBye(callId));
	handler.handle(callerBye(callId));   // the caller hung up at the same moment

	EXPECT_EQ(countSentTo(sent, snom, "CSeq: 9 BYE"), 1) << "the caller's own BYE is answered";
	EXPECT_EQ(countSentTo(sent, yealink, "BYE "), 0) << "and does not make the PBX BYE the phone that hung up";
	EXPECT_EQ(countSentTo(sent, snom, "BYE "), 1);
}

TEST(ByeLocalAnswer, AByeTheFarPhoneNeverAnswersStillEndsTheSessionAtTimerF)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	const std::string callId = connectCall(handler, sent, "bye808-timerf");

	handler.handle(calleeBye(callId));
	ASSERT_TRUE(handler.getSession("Call-ID: " + callId).has_value()) << "precondition: waiting for the caller";

	handler.sweepTransactionsForTest(std::chrono::steady_clock::now() + std::chrono::seconds(10));
	EXPECT_TRUE(handler.getSession("Call-ID: " + callId).has_value()) << "not before Timer F";

	handler.sweepTransactionsForTest(std::chrono::steady_clock::now() + std::chrono::seconds(33));
	EXPECT_FALSE(handler.getSession("Call-ID: " + callId).has_value())
		<< "#808: Timer F on the PBX's BYE (RFC 3261 §17.1.2.2) ends the session it was waiting on";
}

TEST(ByeLocalAnswer, ARefusedPoolDrawCommitsNothingAndTheRetransmitSucceeds)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	const std::string callId = connectCall(handler, sent, "bye808-pool");
	const sockaddr_in yealink = addrFor(kYealinkIp, 5062);
	const sockaddr_in snom = addrFor(kSnomIp, 1037);
	const size_t before = sent.size();

	{
		auto held = holdAllButSpare(1);   // the BYE datagram itself takes the last slot
		auto bye = calleeBye(callId);
		ASSERT_NE(bye, nullptr);
		handler.handle(bye);
		EXPECT_EQ(sent.size(), before) << "#715: no 200 and no BYE when they cannot both be drawn";
		EXPECT_EQ(handler.getSession("Call-ID: " + callId).value()->getState(), Session::State::Connected)
			<< "and no state committed, so the retransmit starts clean";
	}

	handler.handle(calleeBye(callId));
	EXPECT_EQ(countSentTo(sent, yealink, "CSeq: 7 BYE"), 1);
	EXPECT_EQ(countSentTo(sent, snom, "BYE "), 1);
}
