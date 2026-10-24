// ByeUnknownDialog_test.cpp: a BYE for a Call-ID the PBX holds no session for is answered 481
// (RFC 3261 s12.2.2), not relayed to the registered To extension (endhandle audit row 20, A10).
// Host only; every message goes to the handler's send callback.
#include <gtest/gtest.h>
#include <chrono>
#include <string>
#include <utility>
#include <vector>
#include "RequestsHandler.hpp"
#include "Session.hpp"
#include <arpa/inet.h>

namespace
{
	using SentList = std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>;
	sockaddr_in addrFor(const std::string& ip)
	{
		sockaddr_in s{}; s.sin_family = AF_INET; s.sin_addr.s_addr = inet_addr(ip.c_str()); s.sin_port = htons(5060); return s;
	}
	std::shared_ptr<SipMessage> mk(const std::string& raw, const std::string& ip)
	{ return RequestsHandler::getMessageFromPool(raw, addrFor(ip)); }

	std::shared_ptr<SipMessage> reg(const std::string& ext, const std::string& ip, const std::string& cid, const std::string& params = ";expires=3600")
	{
		return mk("REGISTER sip:server SIP/2.0\r\nVia: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKr" + cid + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + cid + "\r\nTo: <sip:" + ext + "@server>\r\nCall-ID: " + cid + "\r\n"
			"CSeq: 1 REGISTER\r\nContact: <sip:" + ext + "@" + ip + ":5060>" + params + "\r\nContent-Length: 0\r\n\r\n", ip);
	}
	std::string sdp(const std::string& ip, int port)
	{
		return "v=0\r\no=- 0 0 IN IP4 " + ip + "\r\ns=-\r\nc=IN IP4 " + ip + "\r\nt=0 0\r\nm=audio " + std::to_string(port) +
			" RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
	}
	std::shared_ptr<SipMessage> inv(const std::string& from, const std::string& to, const std::string& ip,
		const std::string& cid, const std::string& br)
	{
		const std::string b = sdp(ip, 10000);
		return mk("INVITE sip:" + to + "@server SIP/2.0\r\nVia: SIP/2.0/UDP " + ip + ":5060;branch=" + br + "\r\n"
			"From: <sip:" + from + "@server>;tag=ft" + cid + "\r\nTo: <sip:" + to + "@server>\r\nCall-ID: " + cid + "\r\n"
			"CSeq: 1 INVITE\r\nMax-Forwards: 70\r\nContact: <sip:" + from + "@" + ip + ":5060>\r\nContent-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(b.size()) + "\r\n\r\n" + b, ip);
	}
	std::shared_ptr<SipMessage> ok(const std::string& from, const std::string& to, const std::string& callerIp,
		const std::string& calleeIp, const std::string& cid, const std::string& br)
	{
		const std::string b = sdp(calleeIp, 20000);
		return mk("SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP " + callerIp + ":5060;branch=" + br + "\r\n"
			"From: <sip:" + from + "@server>;tag=ft" + cid + "\r\nTo: <sip:" + to + "@server>;tag=bt" + cid + "\r\nCall-ID: " + cid + "\r\n"
			"CSeq: 1 INVITE\r\nContact: <sip:" + to + "@" + calleeIp + ":5060>\r\nContent-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(b.size()) + "\r\n\r\n" + b, calleeIp);
	}
	std::shared_ptr<SipMessage> ackm(const std::string& from, const std::string& to, const std::string& ip, const std::string& cid, const std::string& br)
	{
		return mk("ACK sip:" + to + "@server SIP/2.0\r\nVia: SIP/2.0/UDP " + ip + ":5060;branch=" + br + "\r\n"
			"From: <sip:" + from + "@server>;tag=ft" + cid + "\r\nTo: <sip:" + to + "@server>;tag=bt" + cid + "\r\nCall-ID: " + cid + "\r\n"
			"CSeq: 1 ACK\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n", ip);
	}
	// A BYE sent by `byeFrom` (tag byeFromTag) to `byeTo`.
	std::shared_ptr<SipMessage> bye(const std::string& byeFrom, const std::string& fromTag, const std::string& byeTo,
		const std::string& toTag, const std::string& ip, const std::string& cid, int cseq)
	{
		return mk("BYE sip:" + byeTo + "@server SIP/2.0\r\nVia: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKbye" + std::to_string(cseq) + "\r\n"
			"From: <sip:" + byeFrom + "@server>;tag=" + fromTag + "\r\nTo: <sip:" + byeTo + "@server>;tag=" + toTag + "\r\nCall-ID: " + cid + "\r\n"
			"CSeq: " + std::to_string(cseq) + " BYE\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n", ip);
	}
	std::shared_ptr<SipMessage> byeOk(const std::string& from, const std::string& fromTag, const std::string& to, const std::string& toTag,
		const std::string& ip, const std::string& cid, int cseq)
	{
		return mk("SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKbye" + std::to_string(cseq) + "\r\n"
			"From: <sip:" + from + "@server>;tag=" + fromTag + "\r\nTo: <sip:" + to + "@server>;tag=" + toTag + "\r\nCall-ID: " + cid + "\r\n"
			"CSeq: " + std::to_string(cseq) + " BYE\r\nContent-Length: 0\r\n\r\n", ip);
	}
	std::shared_ptr<SipMessage> cancel(const std::string& from, const std::string& to, const std::string& ip, const std::string& cid, const std::string& br)
	{
		return mk("CANCEL sip:" + to + "@server SIP/2.0\r\nVia: SIP/2.0/UDP " + ip + ":5060;branch=" + br + "\r\n"
			"From: <sip:" + from + "@server>;tag=ft" + cid + "\r\nTo: <sip:" + to + "@server>\r\nCall-ID: " + cid + "\r\n"
			"CSeq: 1 CANCEL\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n", ip);
	}
	int countTo(const SentList& sent, const std::string& ip, const std::string& needle)
	{
		int n = 0; const auto a = addrFor(ip);
		for (auto& p : sent)
			if (p.first.sin_addr.s_addr == a.sin_addr.s_addr && p.second && p.second->toString().find(needle) != std::string::npos) ++n;
		return n;
	}
	void dump(const SentList& sent, const char* tag)
	{
		for (auto& p : sent)
			if (p.second) std::cerr << tag << " -> " << inet_ntoa(p.first.sin_addr) << " : " << p.second->toString().substr(0, p.second->toString().find("\r\n")) << "\n";
	}
	struct H
	{
		SentList sent;
		RequestsHandler h;
		H() : h("192.168.50.1", 5060, [this](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); }) {}
	};
}

// Row 20 / A10: nothing holds this Call-ID, so the sender is told so and 402 is left alone.
TEST(ByeUnknownDialog, IsAnswered481AndNotRelayedToTheRegisteredTo)
{
	H t;
	t.h.handle(reg("401", "192.168.50.20", "r1")); t.h.handle(reg("402", "192.168.50.21", "r2"));
	t.sent.clear();
	t.h.handle(bye("401", "x1", "402", "x2", "192.168.50.99", "nosuch-1", 5));
	EXPECT_EQ(countTo(t.sent, "192.168.50.99", "SIP/2.0 481 Call/Transaction Does Not Exist"), 1);
	EXPECT_EQ(countTo(t.sent, "192.168.50.21", "BYE"), 0) << "402 was sent a BYE for a dialog the PBX does not hold";
}

// Control: a BYE on a live two-phone call is still answered 200 and relayed to the far phone.
TEST(ByeUnknownDialog, ByeOnALiveCallIsStillRelayedAndNeverDraws481)
{
	H t;
	t.h.handle(reg("401", "192.168.50.20", "r1")); t.h.handle(reg("402", "192.168.50.21", "r2"));
	t.h.handle(inv("401", "402", "192.168.50.20", "live1", "z9hG4bKlive1"));
	t.h.handle(ok("401", "402", "192.168.50.20", "192.168.50.21", "live1", "z9hG4bKlive1"));
	t.h.handle(ackm("401", "402", "192.168.50.20", "live1", "z9hG4bKlive1"));
	t.sent.clear();
	t.h.handle(bye("401", "ftlive1", "402", "btlive1", "192.168.50.20", "live1", 2));
	EXPECT_EQ(countTo(t.sent, "192.168.50.20", "SIP/2.0 200"), 1);
	EXPECT_EQ(countTo(t.sent, "192.168.50.21", "BYE"), 1);
	EXPECT_EQ(countTo(t.sent, "192.168.50.20", "481"), 0);
}
