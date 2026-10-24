// SessionReset_test.cpp -- Issue #1122 / #1121 item 1: Session::reset() is the only thing
// allocateSession() runs on a recycled pool slot, so every per-call field must be
// cleared there. _degradedReported, _cancelledLegExt, _forwardInvite and _forwardTarget
// were not.

#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "RequestsHandler.hpp"
#include "Session.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	using SentList = std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>;

	sockaddr_in addrFor(const std::string& ip)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(5060);
		return s;
	}

	std::shared_ptr<SipMessage> mk(const std::string& raw, const std::string& ip)
	{
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}

	std::shared_ptr<SipMessage> reg(const std::string& ext, const std::string& ip)
	{
		const std::string cid = "reg-" + ext;
		return mk("REGISTER sip:server SIP/2.0\r\nVia: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKr" + cid + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + cid + "\r\nTo: <sip:" + ext + "@server>\r\nCall-ID: " + cid + "\r\n"
			"CSeq: 1 REGISTER\r\nContact: <sip:" + ext + "@" + ip + ":5060>;expires=3600\r\nContent-Length: 0\r\n\r\n", ip);
	}

	std::shared_ptr<SipMessage> inv(const std::string& from, const std::string& to, const std::string& ip,
		const std::string& cid)
	{
		const std::string b = "v=0\r\no=- 0 0 IN IP4 " + ip + "\r\ns=-\r\nc=IN IP4 " + ip +
			"\r\nt=0 0\r\nm=audio 10000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
		return mk("INVITE sip:" + to + "@server SIP/2.0\r\nVia: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bK" + cid + "\r\n"
			"From: <sip:" + from + "@server>;tag=ft" + cid + "\r\nTo: <sip:" + to + "@server>\r\nCall-ID: " + cid + "\r\n"
			"CSeq: 1 INVITE\r\nMax-Forwards: 70\r\nContact: <sip:" + from + "@" + ip + ":5060>\r\nContent-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(b.size()) + "\r\n\r\n" + b, ip);
	}


	// A callee's final response to the INVITE of call `cid`; To carries `toExt`.
	std::shared_ptr<SipMessage> fin(int code, const std::string& from, const std::string& toExt,
		const std::string& callerIp, const std::string& calleeIp, const std::string& cid)
	{
		return mk("SIP/2.0 " + std::to_string(code) + " X\r\nVia: SIP/2.0/UDP " + callerIp + ":5060;branch=z9hG4bK" + cid + "\r\n"
			"From: <sip:" + from + "@server>;tag=ft" + cid + "\r\nTo: <sip:" + toExt + "@server>;tag=bt" + cid + "\r\n"
			"Call-ID: " + cid + "\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n", calleeIp);
	}

	std::shared_ptr<SipMessage> ackOf(const std::string& from, const std::string& to, const std::string& ip,
		const std::string& cid, const std::string& branch)
	{
		return mk("ACK sip:" + to + "@server SIP/2.0\r\nVia: SIP/2.0/UDP " + ip + ":5060;branch=" + branch + "\r\n"
			"From: <sip:" + from + "@server>;tag=ft" + cid + "\r\nTo: <sip:" + to + "@server>;tag=bt" + cid + "\r\nCall-ID: " + cid + "\r\n"
			"CSeq: 1 ACK\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n", ip);
	}

	int countTo(const SentList& sent, const std::string& ip, const std::string& needle)
	{
		int n = 0;
		const auto a = addrFor(ip);
		for (auto& p : sent)
			if (p.first.sin_addr.s_addr == a.sin_addr.s_addr && p.second &&
				p.second->toString().find(needle) != std::string::npos) ++n;
		return n;
	}
}

TEST(SessionReset, ClearsDegradedReported)
{
	Session s;
	ASSERT_TRUE(s.markDegradedReported());
	ASSERT_FALSE(s.markDegradedReported());
	s.reset("next", nullptr);
	EXPECT_TRUE(s.markDegradedReported()) << "a recycled slot must report a degraded 911/933 again";
}

TEST(SessionReset, ClearsCancelledLegExt)
{
	Session s;
	s.setCancelledLegExt("403");
	s.reset("next", nullptr);
	EXPECT_TRUE(s.getCancelledLegExt().empty());
}

TEST(SessionReset, ClearsTheForwardLeg)
{
	Session s;
	s.setForwardLeg(inv("401", "402", "192.168.50.20", "fwd-x"), "403");
	s.reset("next", nullptr);
	EXPECT_EQ(s.getForwardLegInvite(), nullptr);
	EXPECT_TRUE(s.getForwardLegTarget().empty());
}

// #1011 residual: the no-answer sweep CANCELs 402 before a CFNA divert and records 402 as
// the cancelled leg. The divert ends before 402's 487 arrives. A new call to 402 on the
// recycled slot is then refused with a genuine 487, which must reach the new caller.
TEST(RequestsHandler, StaleCancelledLegDoesNotSwallowAGenuine487)
{
	SentList sent;
	RequestsHandler h("192.168.50.1", 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	h.handle(reg("401", "192.168.50.20")); h.handle(reg("402", "192.168.50.21")); h.handle(reg("403", "192.168.50.23"));
	h.setForward("402", "noanswer", "403");

	h.handle(inv("401", "402", "192.168.50.20", "cfna-a"));
	auto a = h.getSession("Call-ID: cfna-a");
	ASSERT_TRUE(a.has_value());
	Session* slot = a.value().get();
	a.value()->armRingTimer(std::chrono::steady_clock::now() - std::chrono::seconds(1));
	h.forceNextTickForTest();
	h.tick();
	a = h.getSession("Call-ID: cfna-a");
	ASSERT_TRUE(a.has_value()) << "the CFNA divert runs under the same Call-ID";
	ASSERT_EQ(a.value()->getCancelledLegExt(), "402");

	// End the divert before 402's 487 arrives: 403 refuses with 486.
	h.handle(fin(486, "401", "403", "192.168.50.20", "192.168.50.23", "cfna-a"));
	h.handle(ackOf("401", "402", "192.168.50.20", "cfna-a", "z9hG4bKcfna-a"));
	ASSERT_FALSE(h.getSession("Call-ID: cfna-a").has_value()) << "the divert must be over";
	a.reset();

	h.handle(inv("401", "402", "192.168.50.20", "cfna-b"));
	auto b = h.getSession("Call-ID: cfna-b");
	ASSERT_TRUE(b.has_value());
	ASSERT_EQ(b.value().get(), slot) << "the second call must land on the recycled slot";
	b.reset();

	sent.clear();
	h.handle(fin(487, "401", "402", "192.168.50.20", "192.168.50.21", "cfna-b"));
	EXPECT_EQ(countTo(sent, "192.168.50.20", "SIP/2.0 487"), 1) << "the genuine 487 is relayed to the caller";
	EXPECT_EQ(countTo(sent, "192.168.50.21", "ACK sip:402"), 0) << "it was swallowed as a forwarded final";
}
