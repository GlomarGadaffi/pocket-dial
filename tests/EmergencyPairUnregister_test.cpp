// Issue #1149: a park retriever that unregisters (REGISTER Expires 0, or a lapsed
// lease) ended its own session through endClientCalls() and left the other half of
// the spliced pair up with a dangling peerCallID. When that other half is an
// emergency call the pair-level check (isSplicedPair / pairHasEmergency, #1141) must
// decide: the emergency leg stays up, is never sent a BYE, and its link to the ended
// peer is cleared. A pair with no emergency leg behaves as before.

#include <gtest/gtest.h>

#include <string>
#include <utility>
#include <vector>

#include "RequestsHandler.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	constexpr const char* kServerIp = "192.168.41.1";
	constexpr const char* kParkedIp = "192.168.41.10";   // 100: parks the call
	constexpr const char* kRetrIp   = "192.168.41.20";   // 106: retrieves it

	using Sent = std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>;

	sockaddr_in addrFor(const std::string& ip, uint16_t port = 5060)
	{
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_addr.s_addr = inet_addr(ip.c_str());
		a.sin_port = htons(port);
		return a;
	}

	std::shared_ptr<SipMessage> makeRegister(const std::string& ext, const std::string& ip,
	                                          const std::string& callId, int expires = 3600)
	{
		std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKr" + callId + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + callId + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + ip + ":5060>;expires=" + std::to_string(expires) + "\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}

	std::string sdpBody(const std::string& ip)
	{
		return
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + ip + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + ip + "\r\n"
			"t=0 0\r\n"
			"m=audio 10000 RTP/AVP 0\r\n"
			"a=rtpmap:0 PCMU/8000\r\n";
	}

	void sendParkInvite(RequestsHandler& h, const std::string& ext, const std::string& ip,
	                    const std::string& callId)
	{
		const std::string body = sdpBody(ip);
		std::string raw =
			"INVITE sip:700@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKp" + callId + "\r\n"
			"From: <sip:" + ext + "@server>;tag=ptag" + callId + "\r\n"
			"To: <sip:700@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:" + ext + "@" + ip + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		h.handle(RequestsHandler::getMessageFromPool(raw, addrFor(ip)));
	}

	size_t totalByes(const Sent& sent)
	{
		size_t n = 0;
		for (const auto& [a, m] : sent)
			if (m && m->toString().rfind("BYE ", 0) == 0) ++n;
		return n;
	}

	struct Rig
	{
		Sent sent;
		RequestsHandler handler;

		Rig() : handler(kServerIp, 5060,
			[this](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
				sent.emplace_back(addr, std::move(msg));
			})
		{
			handler.handle(makeRegister("100", kParkedIp, "reg-100"));
			handler.handle(makeRegister("106", kRetrIp, "reg-106"));
			sendParkInvite(handler, "100", kParkedIp, "pk1");
			sendParkInvite(handler, "106", kRetrIp, "pk2");
		}
	};

	// pk1 = the parked leg (100), pk2 = the retriever's leg (106), spliced to each other.
	void expectSplicedPair(Rig& rig)
	{
		auto parked = rig.handler.getSession("Call-ID: pk1");
		auto retr = rig.handler.getSession("Call-ID: pk2");
		ASSERT_TRUE(parked.has_value()) << "precondition: park session";
		ASSERT_TRUE(retr.has_value()) << "precondition: retrieve session";
		ASSERT_EQ(parked.value()->getPeerCallID(), "Call-ID: pk2") << "precondition: spliced";
		ASSERT_EQ(retr.value()->getPeerCallID(), "Call-ID: pk1") << "precondition: spliced";
	}

	void deregister(RequestsHandler& h, const std::string& ext, const std::string& ip)
	{
		h.handle(makeRegister(ext, ip, "dereg-" + ext, 0));
	}

	void flush(RequestsHandler& h)
	{
		h.forceNextTickForTest();
		h.tick();
	}

	// The parked leg is the emergency one; the retriever's leg ends, and only that.
	void expectEmergencyLegSurvives(Rig& rig)
	{
		auto parked = rig.handler.getSession("Call-ID: pk1");
		ASSERT_TRUE(parked.has_value()) << "the emergency leg was torn down";
		EXPECT_TRUE(parked.value()->isEmergency());
		EXPECT_EQ(parked.value()->getPeerCallID(), "") << "the emergency leg still points at the ended retriever";
		EXPECT_FALSE(rig.handler.getSession("Call-ID: pk2").has_value()) << "the retriever's leg must end";
		EXPECT_EQ(totalByes(rig.sent), 0u) << "the emergency leg was sent a BYE";
		// Positive control: the retriever's leg ended exactly once (one CDR), nothing else did.
		EXPECT_EQ(rig.handler.cdrSnapshotForTest().size(), 1u);
		EXPECT_EQ(rig.handler.getSessionCount(), 1u);
	}
}

TEST(EmergencyPairUnregister, ARetrieverDeregisteringLeavesTheEmergencyLegUpWithNoPeerLink)
{
	Rig rig;
	expectSplicedPair(rig);
	rig.handler.getSession("Call-ID: pk1").value()->setEmergency(true);
	rig.sent.clear();

	deregister(rig.handler, "106", kRetrIp);
	flush(rig.handler);

	expectEmergencyLegSurvives(rig);
}

TEST(EmergencyPairUnregister, ARetrieverWhoseLeaseLapsesLeavesTheEmergencyLegUpWithNoPeerLink)
{
	Rig rig;
	expectSplicedPair(rig);
	rig.handler.getSession("Call-ID: pk1").value()->setEmergency(true);
	rig.sent.clear();

	rig.handler.expireLeaseAndSweepForTest("106");
	flush(rig.handler);

	expectEmergencyLegSurvives(rig);
}

TEST(EmergencyPairUnregister, AnEmergencyRetrieverLegDefersTheParkedPhonesDeregisterAndKeepsBothSessions)
{
	// The other direction: the retriever's own leg is the emergency one, so the parked
	// phone (its stand-in peer) is on a live emergency session and is not torn down.
	Rig rig;
	expectSplicedPair(rig);
	rig.handler.getSession("Call-ID: pk2").value()->setEmergency(true);
	rig.sent.clear();

	deregister(rig.handler, "100", kParkedIp);
	flush(rig.handler);

	ASSERT_TRUE(rig.handler.getSession("Call-ID: pk1").has_value());
	auto retr = rig.handler.getSession("Call-ID: pk2");
	ASSERT_TRUE(retr.has_value());
	EXPECT_EQ(retr.value()->getPeerCallID(), "Call-ID: pk1");
	EXPECT_EQ(totalByes(rig.sent), 0u);
	EXPECT_EQ(rig.handler.getSessionCount(), 2u);
	EXPECT_TRUE(rig.handler.cdrSnapshotForTest().empty());
}

TEST(EmergencyPairUnregister, APlainPairBehavesAsBeforeWhenTheRetrieverDeregisters)
{
	Rig rig;
	expectSplicedPair(rig);
	rig.sent.clear();

	deregister(rig.handler, "106", kRetrIp);
	flush(rig.handler);

	EXPECT_FALSE(rig.handler.getSession("Call-ID: pk2").has_value());
	EXPECT_TRUE(rig.handler.getSession("Call-ID: pk1").has_value());
	EXPECT_EQ(totalByes(rig.sent), 0u);
	EXPECT_EQ(rig.handler.cdrSnapshotForTest().size(), 1u);
	EXPECT_EQ(rig.handler.getSessionCount(), 1u);
}

namespace
{
	size_t messagesTo(const Sent& sent, const std::string& ip)
	{
		size_t n = 0;
		for (const auto& [a, m] : sent)
			if (m && a.sin_addr.s_addr == inet_addr(ip.c_str())) ++n;
		return n;
	}

	// Registrar keepalive pings are not call traffic.
	size_t callMessagesTo(const Sent& sent, const std::string& ip)
	{
		size_t n = 0;
		for (const auto& [a, m] : sent)
			if (m && a.sin_addr.s_addr == inet_addr(ip.c_str()) && m->toString().rfind("OPTIONS ", 0) != 0) ++n;
		return n;
	}

	std::shared_ptr<SipMessage> makePhoneBye(const std::string& ext, const std::string& ip,
	                                          const std::string& callId, const std::string& tagFrom)
	{
		std::string raw =
			"BYE sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKb" + callId + "\r\n"
			"From: <sip:" + ext + "@server>;tag=" + tagFrom + "\r\n"
			"To: <sip:700@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 5 BYE\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}
}

TEST(EmergencyPairUnregister, TheSurvivingEmergencyLegIsSentNothingAtAllAndIsNotReapedByTheSessionTimer)
{
	Rig rig;
	expectSplicedPair(rig);
	auto parked = rig.handler.getSession("Call-ID: pk1").value();
	parked->setEmergency(true);
	// Positive control: this timer WOULD fire on the leg were it not protected.
	parked->setState(Session::State::Connected);
	parked->setDialogHeaders("<sip:100@server>;tag=ptagpk1", "<sip:700@server>;tag=srv");
	parked->armSessionTimer(1800, false, std::chrono::steady_clock::now() - std::chrono::seconds(1801));
	ASSERT_GE(parked->getSessionExpiresSeconds(), 1u);
	rig.sent.clear();

	deregister(rig.handler, "106", kRetrIp);
	EXPECT_EQ(messagesTo(rig.sent, kParkedIp), 0u) << "endCall on the retriever's leg sent something to the emergency phone";
	rig.handler.tick();
	rig.handler.tick();
	flush(rig.handler);

	EXPECT_EQ(callMessagesTo(rig.sent, kParkedIp), 0u) << "the emergency phone was sent call traffic";
	EXPECT_EQ(totalByes(rig.sent), 0u);
	ASSERT_TRUE(rig.handler.getSession("Call-ID: pk1").has_value())
		<< "the session timer reaped the emergency leg once its pair link was cleared";
	EXPECT_TRUE(rig.handler.getSession("Call-ID: pk1").value()->isEmergency());
}

TEST(EmergencyPairUnregister, TheEmergencyPhonesOwnByeEndsTheLegCleanlyWithOneCdr)
{
	Rig rig;
	expectSplicedPair(rig);
	rig.handler.getSession("Call-ID: pk1").value()->setEmergency(true);
	deregister(rig.handler, "106", kRetrIp);
	flush(rig.handler);
	ASSERT_TRUE(rig.handler.getSession("Call-ID: pk1").has_value());
	ASSERT_EQ(rig.handler.cdrSnapshotForTest().size(), 1u);
	rig.sent.clear();

	rig.handler.handle(makePhoneBye("100", kParkedIp, "pk1", "ptagpk1"));
	flush(rig.handler);

	EXPECT_FALSE(rig.handler.getSession("Call-ID: pk1").has_value());
	EXPECT_EQ(rig.handler.getSessionCount(), 0u);
	EXPECT_EQ(rig.handler.cdrSnapshotForTest().size(), 2u) << "one CDR per leg, none doubled";
	EXPECT_EQ(messagesTo(rig.sent, kRetrIp), 0u) << "nothing may go to the ended retriever";
	ASSERT_EQ(rig.sent.size(), 1u) << "only the 200 OK to the hanging-up phone: no BYE back to it";
	EXPECT_EQ(rig.sent[0].second->toString().rfind("SIP/2.0 200", 0), 0u);
	EXPECT_EQ(totalByes(rig.sent), 0u);
}
