// OnOk_test.cpp -- #1120 and #1125: who may answer a ringing call, and what the
// caller is told when the answer has no SDP.
//
// #1120: RequestsHandler::onOk used to decide who answered from the message
// alone (the To header, or "any registered client" for a ring group). A 200 OK
// from another host, carrying the ringing Call-ID, connected the call.
// #1125: a callee's 200 without SDP sent a 400 to the CALLEE and left the
// caller's INVITE with no final.
//
// Rule 5: the emergency tests drive the PSAP-callback path (an extension that
// dialed 911 is called back inside 30 minutes). Nothing leaves the process:
// every message goes to the handler's capturing send callback.

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include "LoopbackAnchorClient.hpp"
#include "RequestsHandler.hpp"

namespace
{
	constexpr const char* kServerIp = "192.168.81.1";
	constexpr const char* kIp401    = "192.168.81.11";
	constexpr const char* kIp402    = "192.168.81.21";
	constexpr const char* kIp403    = "192.168.81.22";
	constexpr const char* kIp404    = "192.168.81.24";
	constexpr const char* kIpThird  = "192.168.81.99";

	sockaddr_in addrFor(const std::string& ip, uint16_t port = 5060)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(port);
		return s;
	}

	std::string sdpFor(const std::string& ip)
	{
		return "v=0\r\no=- 0 0 IN IP4 " + ip + "\r\ns=-\r\nc=IN IP4 " + ip + "\r\nt=0 0\r\n"
		       "m=audio 40000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
	}

	struct Bench
	{
		std::vector<std::pair<sockaddr_in, std::string>> sent;
		std::unique_ptr<RequestsHandler> handler;

		Bench()
		{
			handler = std::make_unique<RequestsHandler>(kServerIp, 5060,
				[this](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
					sent.emplace_back(a, m->toString());
				});
		}

		void reg(const std::string& ext, const char* ip)
		{
			const std::string raw =
				"REGISTER sip:server SIP/2.0\r\n"
				"Via: SIP/2.0/UDP " + std::string(ip) + ":5060;branch=z9hG4bKoo" + ext + "\r\n"
				"From: <sip:" + ext + "@server>;tag=oo" + ext + "\r\n"
				"To: <sip:" + ext + "@server>\r\n"
				"Call-ID: oo-reg-" + ext + "\r\n"
				"CSeq: 1 REGISTER\r\n"
				"Contact: <sip:" + ext + "@" + ip + ":5060>;expires=3600\r\n"
				"Content-Length: 0\r\n\r\n";
			handler->handle(RequestsHandler::getMessageFromPool(raw, addrFor(ip)));
		}

		void invite(const std::string& from, const char* fromIp, const std::string& to,
			const std::string& callId)
		{
			const std::string body = sdpFor(fromIp);
			const std::string raw =
				"INVITE sip:" + to + "@server SIP/2.0\r\n"
				"Via: SIP/2.0/UDP " + std::string(fromIp) + ":5060;branch=z9hG4bK" + callId + "\r\n"
				"From: <sip:" + from + "@server>;tag=f" + callId + "\r\n"
				"To: <sip:" + to + "@server>\r\n"
				"Call-ID: " + callId + "\r\n"
				"CSeq: 1 INVITE\r\n"
				"Max-Forwards: 70\r\n"
				"Contact: <sip:" + from + "@" + std::string(fromIp) + ":5060>\r\n"
				"Content-Type: application/sdp\r\n"
				"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
			handler->handle(RequestsHandler::getMessageFromPool(raw, addrFor(fromIp)));
		}

		// The INVITE the server forked to `ip`, or "".
		std::string forkTo(const char* ip) const
		{
			for (const auto& [addr, raw] : sent)
			{
				if (addr.sin_addr.s_addr == inet_addr(ip) && raw.rfind("INVITE ", 0) == 0) return raw;
			}
			return "";
		}

		static std::string lineOf(const std::string& msg, const std::string& name)
		{
			const size_t at = msg.find("\r\n" + name);
			if (at == std::string::npos) return name + " missing";
			return msg.substr(at + 2, msg.find("\r\n", at + 2) - at - 2);
		}

		// `from` answers the fork `fork` (its Via/From/To) as a 200 OK, with or without SDP.
		void answer(const std::string& fork, const std::string& callId, const char* fromIp,
			const std::string& toUser, bool withSdp, uint16_t port = 5060)
		{
			const std::string body = withSdp ? sdpFor(fromIp) : std::string();
			const std::string ok =
				"SIP/2.0 200 OK\r\n" + lineOf(fork, "Via:") + "\r\n" + lineOf(fork, "From:") + "\r\n"
				"To: <sip:" + toUser + "@server>;tag=ans" + toUser + "\r\n"
				"Call-ID: " + callId + "\r\nCSeq: 1 INVITE\r\n"
				"Contact: <sip:" + toUser + "@" + std::string(fromIp) + ":5060>\r\n" +
				(withSdp ? "Content-Type: application/sdp\r\n" : "") +
				"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
			handler->handle(RequestsHandler::getMessageFromPool(ok, addrFor(fromIp, port)));
		}

		size_t countTo(const char* ip, const std::string& firstLinePrefix) const
		{
			size_t n = 0;
			for (const auto& [addr, raw] : sent)
			{
				if (addr.sin_addr.s_addr != inet_addr(ip)) continue;
				if (raw.rfind(firstLinePrefix, 0) == 0) ++n;
			}
			return n;
		}

		size_t totalTo(const char* ip) const
		{
			size_t n = 0;
			for (const auto& [addr, raw] : sent)
			{
				if (addr.sin_addr.s_addr == inet_addr(ip)) ++n;
			}
			return n;
		}

		std::string dump() const
		{
			std::string out;
			for (const auto& [addr, raw] : sent)
				out += std::string(inet_ntoa(addr.sin_addr)) + " <- " + raw.substr(0, raw.find("\r\n")) + "\n";
			return out;
		}
	};

	size_t countOf(const std::string& hay, const std::string& needle)
	{
		size_t n = 0;
		for (size_t at = hay.find(needle); at != std::string::npos; at = hay.find(needle, at + 1)) ++n;
		return n;
	}

	// 401 calls 402 (at .21); returns the fork 402 received.
	std::string ring402(Bench& b, const std::string& callId)
	{
		b.reg("401", kIp401);
		b.reg("402", kIp402);
		b.invite("401", kIp401, "402", callId);
		return b.forkTo(kIp402);
	}

	// 101 dials 911 and hangs up; 102 then calls 101 back: a PSAP callback leg that rings 101.
	// Returns the fork 101 received.
	std::string ringEmergencyCallback(Bench& b, const std::string& callId)
	{
		b.reg("101", kIp401);
		b.reg("102", kIp402);
		b.handler->setAnchorPlacesRealCallsForTest(true);
		b.invite("101", kIp401, "911", "oo-911");
		b.handler->handle(RequestsHandler::getMessageFromPool(
			"BYE sip:911@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(kIp401) + ":5060;branch=z9hG4bKoo911bye\r\n"
			"From: <sip:101@server>;tag=foo-911\r\n"
			"To: <sip:911@server>;tag=srv\r\n"
			"Call-ID: oo-911\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n", addrFor(kIp401)));
		b.sent.clear();
		b.invite("102", kIp402, "101", callId);
		return b.forkTo(kIp401);
	}
}

// -- #1120 ---------------------------------------------------------------------

TEST(OnOk, OrdinaryAnswerFromAThirdAddressIsIgnored)
{
	Bench b;
	const std::string fork = ring402(b, "oo-third");
	ASSERT_FALSE(fork.empty()) << b.dump();
	b.sent.clear();

	b.answer(fork, "oo-third", kIpThird, "402", true);

	EXPECT_EQ(b.totalTo(kIp401), 0u) << "nothing may reach the caller:\n" << b.dump();
	const auto s = b.handler->getSession("Call-ID: oo-third");
	ASSERT_TRUE(s.has_value()) << "the ringing call must survive:\n" << b.dump();
	EXPECT_EQ(s.value()->getState(), Session::State::Invited);
	EXPECT_TRUE(s.value()->hasRingTimer()) << "the ring timer must stay armed";
}

TEST(OnOk, RingGroupAnswerFromANonMemberIsIgnored)
{
	Bench b;
	b.reg("401", kIp401);
	b.reg("402", kIp402);
	b.reg("403", kIp403);
	b.reg("404", kIp404);
	b.handler->setRingGroup("600", "402,403", "ringall");
	b.invite("401", kIp401, "600", "oo-group");
	const std::string fork = b.forkTo(kIp402);
	ASSERT_FALSE(fork.empty()) << b.dump();
	b.sent.clear();

	testing::internal::CaptureStderr();
	b.answer(fork, "oo-group", kIp404, "402", true);
	const std::string err = testing::internal::GetCapturedStderr();

	EXPECT_EQ(countOf(err, "(#1120)"), 1u) << "exactly one drop line:\n" << err;
	EXPECT_EQ(countOf(err, kIp404), 1u) << "naming the real source:\n" << err;

	EXPECT_EQ(b.totalTo(kIp401), 0u) << "0 relays:\n" << b.dump();
	const auto s = b.handler->getSession("Call-ID: oo-group");
	ASSERT_TRUE(s.has_value()) << b.dump();
	EXPECT_EQ(s.value()->getState(), Session::State::Invited);
	EXPECT_EQ(s.value()->getDest(), nullptr);
}

TEST(OnOk, RingGroupMemberAnswerStillConnects)
{
	Bench b;
	b.reg("401", kIp401);
	b.reg("402", kIp402);
	b.reg("403", kIp403);
	b.handler->setRingGroup("600", "402,403", "ringall");
	b.invite("401", kIp401, "600", "oo-member");
	const std::string fork = b.forkTo(kIp403);
	ASSERT_FALSE(fork.empty()) << b.dump();
	b.sent.clear();

	b.answer(fork, "oo-member", kIp403, "403", true);

	EXPECT_EQ(b.countTo(kIp401, "SIP/2.0 200"), 1u) << b.dump();
	const auto s = b.handler->getSession("Call-ID: oo-member");
	ASSERT_TRUE(s.has_value()) << b.dump();
	EXPECT_EQ(s.value()->getState(), Session::State::Connected);
}

TEST(OnOk, TheRealCalleeAnsweringStillConnects)
{
	Bench b;
	const std::string fork = ring402(b, "oo-real");
	ASSERT_FALSE(fork.empty()) << b.dump();
	b.sent.clear();

	b.answer(fork, "oo-real", kIp402, "402", true);

	EXPECT_EQ(b.totalTo(kIp401), 1u) << b.dump();
	EXPECT_EQ(b.countTo(kIp401, "SIP/2.0 200"), 1u) << b.dump();
	const auto s = b.handler->getSession("Call-ID: oo-real");
	ASSERT_TRUE(s.has_value());
	EXPECT_EQ(s.value()->getState(), Session::State::Connected);
}

TEST(OnOk, AnAnswerWithSdpStillConnects)
{
	Bench b;
	const std::string fork = ring402(b, "oo-sdp");
	ASSERT_FALSE(fork.empty()) << b.dump();
	b.sent.clear();

	b.answer(fork, "oo-sdp", kIp402, "402", true);

	EXPECT_EQ(b.countTo(kIp401, "SIP/2.0 200"), 1u) << b.dump();
	const auto s = b.handler->getSession("Call-ID: oo-sdp");
	ASSERT_TRUE(s.has_value());
	EXPECT_EQ(s.value()->getState(), Session::State::Connected);
}

TEST(OnOk, EmergencyAnswerFromTheRegisteredAddressConnects)
{
	Bench b;
	const std::string fork = ringEmergencyCallback(b, "oo-911-cb");
	ASSERT_FALSE(fork.empty()) << b.dump();
	const auto before = b.handler->getSession("Call-ID: oo-911-cb");
	ASSERT_TRUE(before.has_value());
	ASSERT_TRUE(before.value()->isEmergency()) << "precondition: a PSAP callback";
	b.sent.clear();

	b.answer(fork, "oo-911-cb", kIp401, "101", true);

	EXPECT_EQ(b.totalTo(kIp402), 1u) << "exactly 1 relay to the caller:\n" << b.dump();
	EXPECT_EQ(b.countTo(kIp402, "SIP/2.0 200"), 1u) << b.dump();
	const auto s = b.handler->getSession("Call-ID: oo-911-cb");
	ASSERT_TRUE(s.has_value());
	EXPECT_EQ(s.value()->getState(), Session::State::Connected);
}

// -- #1125 ---------------------------------------------------------------------

TEST(OnOk, TwoHundredWithoutSdpGivesTheCallerExactlyOneFinal)
{
	Bench b;
	const std::string fork = ring402(b, "oo-nosdp");
	ASSERT_FALSE(fork.empty()) << b.dump();
	b.sent.clear();

	b.answer(fork, "oo-nosdp", kIp402, "402", false);

	EXPECT_EQ(b.countTo(kIp401, "SIP/2.0 5"), 1u) << "exactly 1 5xx to the caller:\n" << b.dump();
	EXPECT_EQ(b.countTo(kIp402, "SIP/2.0 4"), 0u) << "no 4xx to the callee:\n" << b.dump();
	EXPECT_FALSE(b.handler->getSession("Call-ID: oo-nosdp").has_value()) << "session gone";
}

TEST(OnOk, TwoHundredWithoutSdpWritesOneCdr)
{
	Bench b;
	const std::string fork = ring402(b, "oo-cdr");
	ASSERT_FALSE(fork.empty()) << b.dump();
	const size_t rows = b.handler->cdrSnapshotForTest().size();

	b.answer(fork, "oo-cdr", kIp402, "402", false);

	// The reason text ("SDP parse error.") goes to the SD archive only; the host ring
	// shows that endCall() ran exactly once.
	EXPECT_EQ(b.handler->cdrSnapshotForTest().size(), rows + 1) << b.dump();
}

TEST(OnOk, AnEmergencyCalleesBodilessTwoHundredAnswersTheCallerInTheSamePass)
{
	Bench b;
	const std::string fork = ringEmergencyCallback(b, "oo-911-nosdp");
	ASSERT_FALSE(fork.empty()) << b.dump();
	b.sent.clear();

	b.answer(fork, "oo-911-nosdp", kIp401, "101", false);   // no tick() between

	EXPECT_EQ(b.countTo(kIp402, "SIP/2.0 5"), 1u) << "the final is in this pass:\n" << b.dump();
	EXPECT_EQ(b.totalTo(kIp402), 1u) << "and it is the only message to the caller:\n" << b.dump();
	EXPECT_EQ(b.countTo(kIp401, "SIP/2.0 4"), 0u) << b.dump();
}

// -- #1120: a forged 200 on a call that is already up ---------------------------

namespace
{
	// The caller's ACK to the 200 it was relayed, sent from the caller's address.
	void callerAcks(Bench& b, const std::string& callId, const std::string& callee)
	{
		b.handler->handle(RequestsHandler::getMessageFromPool(
			"ACK sip:" + callee + "@" + std::string(kServerIp) + ":5060 SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(kIp401) + ":5060;branch=z9hG4bKack" + callId + "\r\n"
			"From: <sip:401@server>;tag=f" + callId + "\r\n"
			"To: <sip:" + callee + "@server>;tag=ans" + callee + "\r\n"
			"Call-ID: " + callId + "\r\nCSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n", addrFor(kIp401)));
	}
}

TEST(OnOk, ForgedTwoHundredOnAConnectedCallChangesNothing)
{
	Bench b;
	const std::string fork = ring402(b, "oo-forged");
	ASSERT_FALSE(fork.empty()) << b.dump();
	b.answer(fork, "oo-forged", kIp402, "402", true);
	const auto s = b.handler->getSession("Call-ID: oo-forged");
	ASSERT_TRUE(s.has_value());
	ASSERT_EQ(s.value()->getState(), Session::State::Connected);
	const std::string sdpBefore = s.value()->getRemoteSdp();
	const auto destBefore = s.value()->getDest();
	ASSERT_NE(destBefore, nullptr);
	b.sent.clear();

	testing::internal::CaptureStderr();
	b.answer(fork, "oo-forged", kIpThird, "402", true);
	const std::string err = testing::internal::GetCapturedStderr();

	EXPECT_EQ(b.sent.size(), 0u) << "nothing relayed anywhere:\n" << b.dump();
	EXPECT_EQ(s.value()->getState(), Session::State::Connected);
	EXPECT_EQ(s.value()->getDest(), destBefore);
	EXPECT_EQ(s.value()->getRemoteSdp(), sdpBefore) << "the stored SDP must not move";
	size_t drops = 0;
	for (size_t at = err.find("(#1120)"); at != std::string::npos; at = err.find("(#1120)", at + 1)) ++drops;
	EXPECT_EQ(drops, 1u) << "exactly one drop line:\n" << err;
	EXPECT_NE(err.find("oo-forged"), std::string::npos) << "the line names the Call-ID:\n" << err;
	EXPECT_NE(err.find(kIpThird), std::string::npos) << "and the sender:\n" << err;
}

TEST(OnOk, EmergencyTwoHundredRetransmitFromTheCalleeStillGetsItsAck)
{
	Bench b;
	const std::string fork = ringEmergencyCallback(b, "oo-911-rtx");
	ASSERT_FALSE(fork.empty()) << b.dump();
	b.answer(fork, "oo-911-rtx", kIp401, "101", true);
	callerAcks(b, "oo-911-rtx", "101");
	b.sent.clear();

	b.answer(fork, "oo-911-rtx", kIp401, "101", true);   // the callee retransmits its 200
	EXPECT_EQ(b.countTo(kIp402, "SIP/2.0 200"), 1u) << "re-relayed to the caller:\n" << b.dump();
	b.sent.clear();
	callerAcks(b, "oo-911-rtx", "101");                  // the caller ACKs it again
	EXPECT_EQ(b.countTo(kIp401, "ACK "), 1u) << "the callee gets its ACK:\n" << b.dump();
	const auto s = b.handler->getSession("Call-ID: oo-911-rtx");
	ASSERT_TRUE(s.has_value());
	EXPECT_EQ(s.value()->getState(), Session::State::Connected);
}

TEST(OnOk, RingGroupAnswerFromAnUnregisteredAddressIsLogged)
{
	Bench b;
	b.reg("401", kIp401);
	b.reg("402", kIp402);
	b.handler->setRingGroup("600", "402", "ringall");
	b.invite("401", kIp401, "600", "oo-group-unreg");
	const std::string fork = b.forkTo(kIp402);
	ASSERT_FALSE(fork.empty()) << b.dump();
	b.sent.clear();

	testing::internal::CaptureStderr();
	b.answer(fork, "oo-group-unreg", kIpThird, "402", true);
	const std::string err = testing::internal::GetCapturedStderr();

	EXPECT_EQ(countOf(err, "(#1120)"), 1u) << err;
	EXPECT_EQ(b.totalTo(kIp401), 0u) << b.dump();
}

// -- #1120: the port rule ---------------------------------------------------------

TEST(OnOk, OrdinaryAnswerFromTheRightIpButAnotherPortIsIgnored)
{
	Bench b;
	const std::string fork = ring402(b, "oo-port");
	ASSERT_FALSE(fork.empty()) << b.dump();
	b.sent.clear();

	b.answer(fork, "oo-port", kIp402, "402", true, 5099);

	EXPECT_EQ(b.totalTo(kIp401), 0u) << b.dump();
	const auto s = b.handler->getSession("Call-ID: oo-port");
	ASSERT_TRUE(s.has_value());
	EXPECT_EQ(s.value()->getState(), Session::State::Invited);
}

TEST(OnOk, EmergencyAnswerFromTheRightIpButAnotherPortConnects)
{
	Bench b;
	const std::string fork = ringEmergencyCallback(b, "oo-911-port");
	ASSERT_FALSE(fork.empty()) << b.dump();
	b.sent.clear();

	testing::internal::CaptureStderr();
	b.answer(fork, "oo-911-port", kIp401, "101", true, 5099);
	const std::string err = testing::internal::GetCapturedStderr();

	EXPECT_EQ(b.totalTo(kIp402), 1u) << "exactly 1 relay to the caller:\n" << b.dump();
	EXPECT_EQ(b.countTo(kIp402, "SIP/2.0 200"), 1u) << b.dump();
	const auto s = b.handler->getSession("Call-ID: oo-911-port");
	ASSERT_TRUE(s.has_value());
	EXPECT_EQ(s.value()->getState(), Session::State::Connected);
	EXPECT_EQ(countOf(err, "port mismatch"), 1u) << err;
	EXPECT_NE(err.find("oo-911-port"), std::string::npos) << err;
}
