// InfoAuth_test.cpp -- a SIP INFO is in-dialog (RFC 6086): it is acted on only when its Call-ID
// names a live session and its source address is one of that session's legs, and the extension
// it acts for is the leg's, not whatever the From header says.
//
// Host only; mocks only. The 911 and PSAP-callback cases use the loopback anchor stand-in, so no
// emergency number is sent to any network. Rule 5: a handset's INFO on its own live 911 or PSAP
// callback dialog is answered exactly once with 200 and reaches the digit collector exactly as
// before; the Control_ tests pin that.

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include <arpa/inet.h>

#include "LoopbackAnchorClient.hpp"
#include "MediaBridge.hpp"
#include "RequestsHandler.hpp"
#include "Session.hpp"

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

	std::string sdp(const std::string& ip, int port)
	{
		return "v=0\r\no=- 0 0 IN IP4 " + ip + "\r\ns=-\r\nc=IN IP4 " + ip + "\r\nt=0 0\r\nm=audio " + std::to_string(port) +
			" RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
	}

	std::shared_ptr<SipMessage> inv(const std::string& from, const std::string& to, const std::string& ip, const std::string& cid)
	{
		const std::string b = sdp(ip, 10000);
		return mk("INVITE sip:" + to + "@server SIP/2.0\r\nVia: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKi" + cid + "\r\n"
			"From: <sip:" + from + "@server>;tag=ft" + cid + "\r\nTo: <sip:" + to + "@server>\r\nCall-ID: " + cid + "\r\n"
			"CSeq: 1 INVITE\r\nMax-Forwards: 70\r\nContact: <sip:" + from + "@" + ip + ":5060>\r\nContent-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(b.size()) + "\r\n\r\n" + b, ip);
	}

	std::shared_ptr<SipMessage> ok200(const std::string& from, const std::string& to, const std::string& callerIp,
		const std::string& calleeIp, const std::string& cid)
	{
		const std::string b = sdp(calleeIp, 20000);
		return mk("SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP " + callerIp + ":5060;branch=z9hG4bKi" + cid + "\r\n"
			"From: <sip:" + from + "@server>;tag=ft" + cid + "\r\nTo: <sip:" + to + "@server>;tag=bt" + cid + "\r\nCall-ID: " + cid + "\r\n"
			"CSeq: 1 INVITE\r\nContact: <sip:" + to + "@" + calleeIp + ":5060>\r\nContent-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(b.size()) + "\r\n\r\n" + b, calleeIp);
	}

	// One INFO digit. `n` makes the branch and CSeq unique, so no packet is a retransmission.
	std::shared_ptr<SipMessage> infoDigit(const std::string& fromExt, const std::string& srcIp, const std::string& cid,
		char d, int n)
	{
		const std::string body = std::string("Signal=") + d + "\r\nDuration=100\r\n";
		return mk("INFO sip:server SIP/2.0\r\nVia: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bKinfo" + std::to_string(n) + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=it\r\nTo: <sip:server>\r\nCall-ID: " + cid + "\r\nCSeq: " + std::to_string(n + 10) + " INFO\r\n"
			"Content-Type: application/dtmf-relay\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body, srcIp);
	}

	size_t countTo(const SentList& sent, const std::string& ip, const std::string& needle)
	{
		size_t n = 0;
		for (const auto& [a, m] : sent)
		{
			if (!m || a.sin_addr.s_addr != inet_addr(ip.c_str())) continue;
			const std::string raw = m->toString();
			if (raw.substr(0, raw.find("\r\n")).find(needle) != std::string::npos) ++n;
		}
		return n;
	}

	bool has(const std::vector<std::string>& v, const std::string& s)
	{
		for (const auto& x : v) if (x == s) return true;
		return false;
	}

	struct Rig
	{
		SentList sent;
		RequestsHandler h;
		Rig() : h("192.168.9.1", 5060, [this](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); }) {}

		// An answered ordinary call: `a` at `aIp` calls `b` at `bIp`.
		void connect(const std::string& a, const std::string& aIp, const std::string& b, const std::string& bIp, const std::string& cid)
		{
			h.handle(reg(a, aIp, "reg-" + a));
			h.handle(reg(b, bIp, "reg-" + b));
			h.handle(inv(a, b, aIp, cid));
			h.handle(ok200(a, b, aIp, bIp, cid));
			sent.clear();
		}

		void infoSeq(const std::string& from, const std::string& ip, const std::string& cid, const std::string& digits)
		{
			int n = 0;
			for (char c : digits) h.handle(infoDigit(from, ip, cid, c, ++n));
		}
	};
}

// An INFO with no live dialog is answered 200 and acted on by no one: a 481 to an in-dialog
// request ends the dialog (RFC 3261 s12.2.1.2).
TEST(InfoAuth, NoSessionIsAnsweredOkAndDoesNotSetDnd)
{
	Rig r;
	r.h.handle(reg("301", "192.168.9.50", "reg-301"));
	r.sent.clear();
	r.infoSeq("301", "192.168.9.99", "nosuchcall", "*60");
	EXPECT_FALSE(has(r.h.getDndExtensions(), "301"));
	EXPECT_EQ(countTo(r.sent, "192.168.9.99", "200"), 3u);   // one per INFO
	EXPECT_EQ(countTo(r.sent, "192.168.9.99", "481"), 0u);
	EXPECT_EQ(countTo(r.sent, "192.168.9.99", "403"), 0u);
	EXPECT_EQ(r.h.dtmfAccumulatorCountForTest(), 0u);
	EXPECT_EQ(r.h.getInfoRefused(), 3u);
}

TEST(InfoAuth, NoSessionIsAnsweredOkAndDoesNotInstallForward)
{
	Rig r;
	r.h.handle(reg("303", "192.168.9.52", "reg-303"));
	r.sent.clear();
	r.infoSeq("303", "192.168.9.99", "nosuchcall2", "*725500");
	bool found = false;
	for (const auto& [ext, always, busy, noAnswer, noAnswerSeconds] : r.h.getForwards())
	{
		(void)busy; (void)noAnswer; (void)noAnswerSeconds;
		if (ext == "303" && always == "5500") found = true;
	}
	EXPECT_FALSE(found);
	EXPECT_EQ(countTo(r.sent, "192.168.9.99", "200"), 7u);   // one per INFO
	EXPECT_EQ(countTo(r.sent, "192.168.9.99", "481"), 0u);
	EXPECT_EQ(r.h.dtmfAccumulatorCountForTest(), 0u);
}

// Rule 5: a handset's INFO whose dialog the server no longer holds must draw 200, never 481.
TEST(InfoAuth, NoSessionInfoOnALostEmergencyDialogDrawsOkNotDialogEnd)
{
	Rig r;
	r.h.setAnchorPlacesRealCallsForTest(true);
	r.h.handle(reg("501", "192.168.9.51", "reg-501"));
	r.sent.clear();
	r.h.handle(infoDigit("501", "192.168.9.51", "ia-lost-911", '5', 1));
	EXPECT_EQ(countTo(r.sent, "192.168.9.51", "200"), 1u);
	EXPECT_EQ(countTo(r.sent, "192.168.9.51", "481"), 0u);
	EXPECT_EQ(countTo(r.sent, "192.168.9.51", "403"), 0u);
	EXPECT_EQ(r.h.dtmfAccumulatorCountForTest(), 0u);
}

TEST(InfoAuth, SourceThatIsNotALegOfTheDialogIsRefused)
{
	Rig r;
	r.connect("301", "192.168.9.50", "302", "192.168.9.51", "ia-live");
	r.infoSeq("301", "192.168.9.99", "ia-live", "*60");
	EXPECT_EQ(countTo(r.sent, "192.168.9.99", "403"), 3u);
	EXPECT_EQ(countTo(r.sent, "192.168.9.99", "200"), 0u);
	EXPECT_EQ(r.h.dtmfAccumulatorCountForTest(), 0u);
	EXPECT_FALSE(has(r.h.getDndExtensions(), "301"));
	EXPECT_EQ(r.h.getInfoRefused(), 3u);
}

TEST(InfoAuth, FromHeaderMustNameTheLegTheSourceMatches)
{
	Rig r;
	r.connect("301", "192.168.9.50", "302", "192.168.9.51", "ia-two");
	// 302's own address, but From names 301.
	r.infoSeq("301", "192.168.9.51", "ia-two", "*60");
	EXPECT_EQ(countTo(r.sent, "192.168.9.51", "403"), 3u);
	EXPECT_EQ(countTo(r.sent, "192.168.9.51", "200"), 0u);
	EXPECT_FALSE(has(r.h.getDndExtensions(), "301"));
	EXPECT_FALSE(has(r.h.getDndExtensions(), "302"));
	EXPECT_EQ(r.h.dtmfAccumulatorCountForTest(), 0u);
}

TEST(InfoAuth, Control_TheHandsetsOwnStar60OnItsOwnCallStillWorks)
{
	Rig r;
	r.connect("301", "192.168.9.50", "302", "192.168.9.51", "ia-own");
	r.infoSeq("301", "192.168.9.50", "ia-own", "*60");
	EXPECT_EQ(countTo(r.sent, "192.168.9.50", "200"), 3u);
	EXPECT_TRUE(has(r.h.getDndExtensions(), "301"));
	EXPECT_FALSE(has(r.h.getDndExtensions(), "302"));
}

TEST(InfoAuth, Control_TheCalleeStar60OnTheSameCallActsForTheCallee)
{
	Rig r;
	r.connect("301", "192.168.9.50", "302", "192.168.9.51", "ia-callee");
	r.infoSeq("302", "192.168.9.51", "ia-callee", "*60");
	EXPECT_EQ(countTo(r.sent, "192.168.9.51", "200"), 3u);
	EXPECT_TRUE(has(r.h.getDndExtensions(), "302"));
	EXPECT_FALSE(has(r.h.getDndExtensions(), "301"));
}

// Rule 5: the handset's own digit on its own live 911 dialog.
TEST(InfoAuth, Control_HandsetInfoOnItsOwn911DialogIsAnsweredOnceAndReachesTheCollector)
{
	Rig r;
	r.h.setAnchorPlacesRealCallsForTest(true);
	r.h.handle(reg("501", "192.168.9.51", "reg-501"));
	r.h.handle(inv("501", "911", "192.168.9.51", "ia-911"));
	auto s = r.h.getSession("Call-ID: ia-911");
	ASSERT_TRUE(s.has_value());
	ASSERT_TRUE(s.value()->isEmergency());
	MediaBridge* bridge = r.h.anchorBridgeForCallIdForTest("Call-ID: ia-911");
	ASSERT_NE(bridge, nullptr);
	const Session::State before = s.value()->getState();
	r.sent.clear();
	r.h.handle(infoDigit("501", "192.168.9.51", "ia-911", '5', 1));
	EXPECT_EQ(countTo(r.sent, "192.168.9.51", "200"), 1u);
	EXPECT_EQ(countTo(r.sent, "192.168.9.51", "481"), 0u);
	EXPECT_EQ(countTo(r.sent, "192.168.9.51", "403"), 0u);
	EXPECT_EQ(r.h.dtmfAccumulatorCountForTest(), 1u);
	EXPECT_EQ(s.value()->getState(), before);
	EXPECT_EQ(r.h.anchorBridgeForCallIdForTest("Call-ID: ia-911"), bridge);
	EXPECT_FALSE(bridge->isHeld());
	EXPECT_EQ(r.h.getInfoRefused(), 0u);
}

// Rule 5: a roaming 911 handset. Its leg address moves in place on re-REGISTER; the digit from
// the new address must still be answered once and reach the collector.
TEST(InfoAuth, Control_Roaming911HandsetInfoFromItsNewAddressStillGetsThrough)
{
	Rig r;
	r.h.setAnchorPlacesRealCallsForTest(true);
	r.h.handle(reg("501", "192.168.9.51", "reg-501"));
	r.h.handle(inv("501", "911", "192.168.9.51", "ia-roam"));
	auto s = r.h.getSession("Call-ID: ia-roam");
	ASSERT_TRUE(s.has_value());
	ASSERT_TRUE(s.value()->isEmergency());
	r.h.handle(reg("501", "192.168.9.77", "reg-501-moved"));
	ASSERT_TRUE(s.value()->getSrc());
	ASSERT_EQ(s.value()->getSrc()->getAddress().sin_addr.s_addr, inet_addr("192.168.9.77"))
		<< "precondition: the leg address moved in place";
	r.sent.clear();
	r.h.handle(infoDigit("501", "192.168.9.77", "ia-roam", '5', 1));
	EXPECT_EQ(countTo(r.sent, "192.168.9.77", "200"), 1u);
	EXPECT_EQ(countTo(r.sent, "192.168.9.77", "481"), 0u);
	EXPECT_EQ(countTo(r.sent, "192.168.9.77", "403"), 0u);
	EXPECT_EQ(r.h.dtmfAccumulatorCountForTest(), 1u);
	EXPECT_EQ(r.h.getInfoRefused(), 0u);
}

// An answered PSAP callback to 106 at .61: returns the session and its Call-ID line.
static std::shared_ptr<Session> answeredPsapCallback(Rig& r, std::string& cidLine)
{
	r.h.handle(reg("106", "192.168.9.61", "reg-106"));
	cidLine = r.h.routeInboundAnchorCallForTest("106", "part-ia", "5551234567");
	EXPECT_FALSE(cidLine.empty());
	r.h.tick();
	std::string fork;
	for (const auto& [a, m] : r.sent)
		if (m && a.sin_addr.s_addr == inet_addr("192.168.9.61") && m->toString().find("INVITE sip:106@") != std::string::npos)
			fork = m->toString();
	EXPECT_FALSE(fork.empty());
	auto hdr = [&fork](const std::string& name) {
		const size_t p = fork.find("\r\n" + name);
		return p == std::string::npos ? std::string() : fork.substr(p + 2, fork.find("\r\n", p + 2) - (p + 2));
	};
	const std::string b = sdp("192.168.9.61", 20000);
	r.h.handle(mk("SIP/2.0 200 OK\r\n" + hdr("Via:") + "\r\n" + hdr("From:") + "\r\nTo: <sip:106@192.168.9.1>;tag=hs106\r\n" +
		cidLine + "\r\nCSeq: 1 INVITE\r\nContact: <sip:106@192.168.9.61:5060>\r\nContent-Type: application/sdp\r\n"
		"Content-Length: " + std::to_string(b.size()) + "\r\n\r\n" + b, "192.168.9.61"));
	auto s = r.h.getSession(cidLine);
	if (!s.has_value()) return nullptr;
	s.value()->setEmergency(true);
	EXPECT_EQ(s.value()->getState(), Session::State::Connected);
	return s.value();
}

// Rule 5: the handset's own digit on an answered PSAP-callback dialog.
TEST(InfoAuth, Control_HandsetInfoOnItsOwnPsapCallbackIsAnsweredOnceAndReachesTheCollector)
{
	Rig r;
	std::string cidLine;
	auto s = answeredPsapCallback(r, cidLine);
	ASSERT_TRUE(s);
	r.sent.clear();
	r.h.handle(infoDigit("106", "192.168.9.61", cidLine.substr(std::string("Call-ID: ").size()), '5', 1));
	EXPECT_EQ(countTo(r.sent, "192.168.9.61", "200"), 1u);
	EXPECT_EQ(countTo(r.sent, "192.168.9.61", "481"), 0u);
	EXPECT_EQ(countTo(r.sent, "192.168.9.61", "403"), 0u);
	EXPECT_EQ(r.h.dtmfAccumulatorCountForTest(), 1u);
	EXPECT_EQ(s->getState(), Session::State::Connected);
	EXPECT_EQ(r.h.getInfoRefused(), 0u);
}

// Rule 5: an INFO from the carrier side of a live PSAP callback (not a leg) is answered 200 and
// acted on by no one: not a 403, and nothing reaches the collector.
TEST(InfoAuth, CarrierInfoOnALivePsapCallbackDrawsOkAndIsNotActedOn)
{
	Rig r;
	std::string cidLine;
	auto s = answeredPsapCallback(r, cidLine);
	ASSERT_TRUE(s);
	r.sent.clear();
	r.infoSeq("5551234567", "203.0.113.5", cidLine.substr(std::string("Call-ID: ").size()), "*60");
	EXPECT_EQ(countTo(r.sent, "203.0.113.5", "200"), 3u);   // one per INFO
	EXPECT_EQ(countTo(r.sent, "203.0.113.5", "403"), 0u);
	EXPECT_EQ(countTo(r.sent, "203.0.113.5", "481"), 0u);
	EXPECT_EQ(r.h.dtmfAccumulatorCountForTest(), 0u);
	EXPECT_FALSE(has(r.h.getDndExtensions(), "106"));
	EXPECT_EQ(s->getState(), Session::State::Connected);
	EXPECT_EQ(r.h.getInfoRefused(), 3u);
}

// Each refusal is counted; the log line is written once per window for a Call-ID, whatever the count.
TEST(InfoAuth, RefusalsAreCountedAndLoggedOncePerWindow)
{
	Rig r;
	r.connect("301", "192.168.9.50", "302", "192.168.9.51", "ia-log");
	testing::internal::CaptureStderr();
	r.infoSeq("301", "192.168.9.99", "ia-log", "*60*80");
	const std::string log = testing::internal::GetCapturedStderr();
	size_t lines = 0;
	for (size_t p = log.find("non-dialog source"); p != std::string::npos; p = log.find("non-dialog source", p + 1)) ++lines;
	EXPECT_EQ(lines, 1u) << log;
	EXPECT_EQ(r.h.getInfoRefused(), 6u);
}
