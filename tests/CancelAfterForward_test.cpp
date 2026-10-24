// CancelAfterForward_test.cpp -- the caller's CANCEL after a CFU/CFB/CFNA forward must reach the
// ringing forward target, not the original callee (endhandle-routing-audit.md row 1, A1).
// Driven end to end through RequestsHandler::handle().

#include <gtest/gtest.h>

#include <memory>
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

	std::shared_ptr<SipMessage> reg(const std::string& ext, const std::string& ip, const std::string& cid)
	{
		return mk("REGISTER sip:server SIP/2.0\r\nVia: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKr" + cid + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + cid + "\r\nTo: <sip:" + ext + "@server>\r\nCall-ID: " + cid + "\r\n"
			"CSeq: 1 REGISTER\r\nContact: <sip:" + ext + "@" + ip + ":5060>;expires=3600\r\nContent-Length: 0\r\n\r\n", ip);
	}

	std::shared_ptr<SipMessage> inv(const std::string& from, const std::string& to, const std::string& ip,
		const std::string& cid, const std::string& br)
	{
		const std::string b = "v=0\r\no=- 0 0 IN IP4 " + ip + "\r\ns=-\r\nc=IN IP4 " + ip +
			"\r\nt=0 0\r\nm=audio 10000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
		return mk("INVITE sip:" + to + "@server SIP/2.0\r\nVia: SIP/2.0/UDP " + ip + ":5060;branch=" + br + "\r\n"
			"From: <sip:" + from + "@server>;tag=ft" + cid + "\r\nTo: <sip:" + to + "@server>\r\nCall-ID: " + cid + "\r\n"
			"CSeq: 1 INVITE\r\nMax-Forwards: 70\r\nContact: <sip:" + from + "@" + ip + ":5060>\r\nContent-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(b.size()) + "\r\n\r\n" + b, ip);
	}

	std::shared_ptr<SipMessage> cancel(const std::string& from, const std::string& to, const std::string& ip,
		const std::string& cid, const std::string& br)
	{
		return mk("CANCEL sip:" + to + "@server SIP/2.0\r\nVia: SIP/2.0/UDP " + ip + ":5060;branch=" + br + "\r\n"
			"From: <sip:" + from + "@server>;tag=ft" + cid + "\r\nTo: <sip:" + to + "@server>\r\nCall-ID: " + cid + "\r\n"
			"CSeq: 1 CANCEL\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n", ip);
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

	struct H
	{
		SentList sent;
		RequestsHandler h;
		H() : h("192.168.50.1", 5060, [this](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); }) {}
	};
}

TEST(CancelAfterForward, CancelAfterCfuReachesTheForwardTarget)
{
	H t;
	t.h.handle(reg("401", "192.168.50.20", "r1")); t.h.handle(reg("402", "192.168.50.21", "r2")); t.h.handle(reg("403", "192.168.50.23", "r3"));
	t.h.setForward("402", "always", "403");
	t.h.handle(inv("401", "402", "192.168.50.20", "cfu1", "z9hG4bKcfu1"));
	ASSERT_EQ(countTo(t.sent, "192.168.50.23", "INVITE sip:403"), 1) << "CFU forked the INVITE to 403";
	t.sent.clear();
	t.h.handle(cancel("401", "402", "192.168.50.20", "cfu1", "z9hG4bKcfu1"));
	EXPECT_EQ(countTo(t.sent, "192.168.50.23", "CANCEL sip:403"), 1) << "the ringing forward target must be CANCELled";
	EXPECT_EQ(countTo(t.sent, "192.168.50.21", "CANCEL"), 0) << "the original callee never saw this INVITE";
}

// Control: no forward, so the CANCEL still goes to the dialled callee (the path every
// non-forwarded call, emergency calls included, takes).
TEST(CancelAfterForward, CancelOfAnUnforwardedCallStillReachesTheDialledCallee)
{
	H t;
	t.h.handle(reg("401", "192.168.50.20", "r1")); t.h.handle(reg("402", "192.168.50.21", "r2")); t.h.handle(reg("403", "192.168.50.23", "r3"));
	t.h.handle(inv("401", "402", "192.168.50.20", "ord1", "z9hG4bKord1"));
	ASSERT_EQ(countTo(t.sent, "192.168.50.21", "INVITE sip:402"), 1);
	t.sent.clear();
	t.h.handle(cancel("401", "402", "192.168.50.20", "ord1", "z9hG4bKord1"));
	EXPECT_EQ(countTo(t.sent, "192.168.50.21", "CANCEL sip:402"), 1);
	EXPECT_EQ(countTo(t.sent, "192.168.50.23", "CANCEL"), 0);
}

// #1121 item 1 / #1122: Session::reset() must clear the forward pair. Call one is forwarded
// 402 -> 403 and ended; call two (401 -> 404) lands on the recycled slot and is CANCELled.
// The CANCEL goes to 404 only, never to call one's forward target.
TEST(CancelAfterForward, ARecycledSlotDoesNotCancelTheEarlierCallsForwardTarget)
{
	H t;
	t.h.handle(reg("401", "192.168.50.20", "r1")); t.h.handle(reg("402", "192.168.50.21", "r2"));
	t.h.handle(reg("403", "192.168.50.23", "r3")); t.h.handle(reg("404", "192.168.50.24", "r4"));
	t.h.setForward("402", "always", "403");
	t.h.handle(inv("401", "402", "192.168.50.20", "rc1", "z9hG4bKrc1"));
	auto first = t.h.getSession("Call-ID: rc1");
	ASSERT_TRUE(first.has_value());
	Session* slot = first.value().get();
	first.reset();
	ASSERT_EQ(countTo(t.sent, "192.168.50.23", "INVITE sip:403"), 1);
	t.h.handle(mk("SIP/2.0 486 X\r\nVia: SIP/2.0/UDP 192.168.50.20:5060;branch=z9hG4bKrc1\r\n"
		"From: <sip:401@server>;tag=ftrc1\r\nTo: <sip:403@server>;tag=btrc1\r\nCall-ID: rc1\r\n"
		"CSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n", "192.168.50.23"));
	t.h.handle(mk("ACK sip:402@server SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.50.20:5060;branch=z9hG4bKrc1\r\n"
		"From: <sip:401@server>;tag=ftrc1\r\nTo: <sip:402@server>;tag=btrc1\r\nCall-ID: rc1\r\n"
		"CSeq: 1 ACK\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n", "192.168.50.20"));
	ASSERT_FALSE(t.h.getSession("Call-ID: rc1").has_value()) << "call one must be over";

	t.h.handle(inv("401", "404", "192.168.50.20", "rc2", "z9hG4bKrc2"));
	auto second = t.h.getSession("Call-ID: rc2");
	ASSERT_TRUE(second.has_value());
	ASSERT_EQ(second.value().get(), slot) << "call two must land on the recycled slot";
	second.reset();
	ASSERT_EQ(countTo(t.sent, "192.168.50.24", "INVITE sip:404"), 1);
	t.sent.clear();
	t.h.handle(cancel("401", "404", "192.168.50.20", "rc2", "z9hG4bKrc2"));
	int total = 0;
	for (auto& p : t.sent) if (p.second && p.second->toString().rfind("CANCEL ", 0) == 0) ++total;
	EXPECT_EQ(total, 1) << "exactly one CANCEL";
	EXPECT_EQ(countTo(t.sent, "192.168.50.24", "CANCEL sip:404"), 1) << "to the second callee";
	EXPECT_EQ(countTo(t.sent, "192.168.50.23", "CANCEL"), 0) << "never to call one's forward target";
}
