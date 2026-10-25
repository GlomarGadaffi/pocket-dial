// AnchorReinviteAuth_test.cpp: who may re-INVITE or UPDATE a call this PBX answers itself.
//
// The 555 anchor leg (the 911/933 leg included), the inbound anchor leg and the 997 page are
// terminated here, so onReinvite()/onUpdate() answer them locally. The sender of such a request
// must be a leg of the dialog (the BYE rule, IP only); anything else draws a 403 and changes
// neither the media bridge, the session state nor the session timer.
//
// Rule 5 controls (a 911/933 call and a PSAP callback are never gated, delayed or refused):
// the handset's own hold, resume and session-refresh on its own 911 call draw exactly one
// 200 each and change state exactly as before, including when its call source differs from
// the address it registered from (NAT).

#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "LoopbackAnchorClient.hpp"
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

	const char* const kPbx = "192.168.9.1";
	const char* const kHandset = "192.168.9.51";
	const char* const kOther = "192.168.9.99";

	sockaddr_in addrFor(const std::string& ip, uint16_t port = 5060)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(port);
		return s;
	}

	std::shared_ptr<SipMessage> mk(const std::string& raw, const std::string& ip, uint16_t port = 5060)
	{
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip, port));
	}

	std::shared_ptr<SipMessage> reg(const std::string& ext, const std::string& ip, const std::string& tag = "")
	{
		return mk("REGISTER sip:server SIP/2.0\r\nVia: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKr" + ext + tag + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + ext + tag + "\r\nTo: <sip:" + ext + "@server>\r\nCall-ID: reg-" + ext + tag + "\r\n"
			"CSeq: 1 REGISTER\r\nContact: <sip:" + ext + "@" + ip + ":5060>;expires=3600\r\nContent-Length: 0\r\n\r\n", ip);
	}

	std::string sdp(const std::string& ip, const std::string& dir)
	{
		return "v=0\r\no=- 0 0 IN IP4 " + ip + "\r\ns=-\r\nc=IN IP4 " + ip + "\r\nt=0 0\r\nm=audio 10000 RTP/AVP 0\r\n"
			"a=rtpmap:0 PCMU/8000\r\n" + dir;
	}

	std::shared_ptr<SipMessage> invite(const std::string& from, const std::string& to, const std::string& ip,
		const std::string& cid)
	{
		const std::string b = sdp(ip, "");
		return mk("INVITE sip:" + to + "@server SIP/2.0\r\nVia: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKi" + cid + "\r\n"
			"From: <sip:" + from + "@server>;tag=ft" + cid + "\r\nTo: <sip:" + to + "@server>\r\nCall-ID: " + cid + "\r\n"
			"CSeq: 1 INVITE\r\nMax-Forwards: 70\r\nContact: <sip:" + from + "@" + ip + ":5060>\r\nContent-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(b.size()) + "\r\n\r\n" + b, ip);
	}

	// In-dialog request on the outbound anchor leg. `dir` empty plus withBody=false is a bodiless UPDATE.
	std::shared_ptr<SipMessage> inDialog(const std::string& method, const std::string& toLine, const std::string& srcIp,
		const std::string& cid, int cseq, bool withBody, const std::string& dir, const std::string& ruri = "555", uint16_t port = 5060)
	{
		const std::string body = withBody ? sdp(srcIp, dir) : std::string();
		return mk(method + " sip:" + ruri + "@server SIP/2.0\r\nVia: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bKx" + cid +
			std::to_string(cseq) + "\r\nFrom: <sip:501@server>;tag=ft" + cid + "\r\n" + toLine + "\r\nCall-ID: " + cid + "\r\n"
			"CSeq: " + std::to_string(cseq) + " " + method + "\r\nMax-Forwards: 70\r\nContact: <sip:501@" + srcIp + ":5060>\r\n" +
			(withBody ? "Content-Type: application/sdp\r\n" : "") +
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body, srcIp, port);
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

	struct Rig
	{
		SentList sent;
		RequestsHandler h;
		std::string toLine;
		Rig() : h(kPbx, 5060, [this](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); })
		{
			h.setAnchorPlacesRealCallsForTest(true);
			h.handle(reg("501", kHandset));
			sent.clear();
		}

		// 501 dials `to` from `ip`; returns the bridge. Records the 200's To line (with the board's tag).
		MediaBridge* place(const std::string& to, const std::string& ip, const std::string& cid)
		{
			h.handle(invite("501", to, ip, cid));
			if (sent.empty() || !sent.front().second) return nullptr;
			const std::string t = std::string(sent.front().second->getTo());
			toLine = "To: " + t.substr(t.find('<'));
			sent.clear();
			return h.anchorBridgeForCallIdForTest("Call-ID: " + cid);
		}
		std::shared_ptr<Session> session(const std::string& cid)
		{
			auto s = h.getSession("Call-ID: " + cid);
			return s.has_value() ? s.value() : nullptr;
		}
	};

	void expectRefusedOnce(const SentList& sent)
	{
		EXPECT_EQ(countTo(sent, kOther, "200 OK"), 0u) << "non-leg source got a 200";
		EXPECT_EQ(countTo(sent, kOther, "403"), 1u) << "exactly one 403 to the non-leg source";
	}
}

TEST(AnchorReinviteAuth, NonLegSourceReinviteWithDialogTagIsRefused)
{
	Rig r;
	MediaBridge* bridge = r.place("555", kHandset, "ara-1");
	ASSERT_NE(bridge, nullptr);
	ASSERT_FALSE(bridge->isHeld());
	r.h.handle(inDialog("INVITE", r.toLine, kOther, "ara-1", 2, true, "a=sendonly\r\n"));
	EXPECT_FALSE(bridge->isHeld());
	expectRefusedOnce(r.sent);
	ASSERT_NE(r.session("ara-1"), nullptr);
	EXPECT_EQ(r.session("ara-1")->getState(), Session::State::Connected);
}

TEST(AnchorReinviteAuth, NonLegSourceReinviteWithOtherTagIsRefused)
{
	Rig r;
	MediaBridge* bridge = r.place("555", kHandset, "ara-2");
	ASSERT_NE(bridge, nullptr);
	r.h.handle(inDialog("INVITE", "To: <sip:555@server>;tag=notthetag", kOther, "ara-2", 2, true, "a=sendonly\r\n"));
	EXPECT_FALSE(bridge->isHeld());
	expectRefusedOnce(r.sent);
	ASSERT_NE(r.session("ara-2"), nullptr);
	EXPECT_EQ(r.session("ara-2")->getState(), Session::State::Connected);
}

TEST(AnchorReinviteAuth, NonLegSourceBodilessUpdateIsRefusedAndKeepsTheTimer)
{
	Rig r;
	ASSERT_NE(r.place("555", kHandset, "ara-3"), nullptr);
	auto s = r.session("ara-3");
	ASSERT_NE(s, nullptr);
	s->armSessionTimer(1800, false, std::chrono::steady_clock::now());
	const auto before = s->getSessionExpiry();
	std::this_thread::sleep_for(std::chrono::milliseconds(20));
	r.h.handle(inDialog("UPDATE", r.toLine, kOther, "ara-3", 2, false, ""));
	expectRefusedOnce(r.sent);
	EXPECT_EQ(s->getSessionExpiry(), before) << "a refused UPDATE re-armed the session timer";
}

TEST(AnchorReinviteAuth, NonLegSourceSdpUpdateOnAnchorIsRefused)
{
	Rig r;
	MediaBridge* bridge = r.place("555", kHandset, "ara-4");
	ASSERT_NE(bridge, nullptr);
	r.h.handle(inDialog("UPDATE", r.toLine, kOther, "ara-4", 2, true, "a=sendonly\r\n"));
	EXPECT_FALSE(bridge->isHeld());
	expectRefusedOnce(r.sent);
	ASSERT_NE(r.session("ara-4"), nullptr);
	EXPECT_EQ(r.session("ara-4")->getState(), Session::State::Connected);
}

TEST(AnchorReinviteAuth, EmergencyAnchorHoldRequiresDialogLegSource)
{
	Rig r;
	MediaBridge* bridge = r.place("911", kHandset, "ara-5");
	ASSERT_NE(bridge, nullptr);
	auto s = r.session("ara-5");
	ASSERT_NE(s, nullptr);
	ASSERT_TRUE(s->isEmergency());
	ASSERT_TRUE(s->getDest());
	EXPECT_EQ(s->getDest()->getNumber(), "555");
	r.h.handle(inDialog("INVITE", r.toLine, kOther, "ara-5", 2, true, "a=sendonly\r\n", "911"));
	EXPECT_FALSE(bridge->isHeld()) << "non-leg source held a live 911 call";
	expectRefusedOnce(r.sent);
	EXPECT_EQ(s->getState(), Session::State::Connected);
}

// Rule 5 control: the handset's own hold and resume on its 911 call.
TEST(AnchorReinviteAuth, Control_HandsetOwnHoldAndResumeOnA911StillWork)
{
	Rig r;
	MediaBridge* bridge = r.place("911", kHandset, "ara-6");
	ASSERT_NE(bridge, nullptr);
	auto s = r.session("ara-6");
	ASSERT_NE(s, nullptr);
	r.h.handle(inDialog("INVITE", r.toLine, kHandset, "ara-6", 2, true, "a=sendonly\r\n", "911"));
	EXPECT_EQ(countTo(r.sent, kHandset, "200 OK"), 1u);
	EXPECT_TRUE(bridge->isHeld());
	EXPECT_EQ(s->getState(), Session::State::Held);
	r.sent.clear();
	r.h.handle(inDialog("INVITE", r.toLine, kHandset, "ara-6", 3, true, "a=sendrecv\r\n", "911"));
	EXPECT_EQ(countTo(r.sent, kHandset, "200 OK"), 1u);
	EXPECT_FALSE(bridge->isHeld());
	EXPECT_EQ(s->getState(), Session::State::Connected);
	EXPECT_EQ(countTo(r.sent, kHandset, "403"), 0u);
}

// Rule 5 control: the handset's own session-refresh UPDATE re-arms the timer, answered once.
TEST(AnchorReinviteAuth, Control_HandsetSessionRefreshUpdateOnA911RearmsTheTimer)
{
	Rig r;
	ASSERT_NE(r.place("911", kHandset, "ara-7"), nullptr);
	auto s = r.session("ara-7");
	ASSERT_NE(s, nullptr);
	s->armSessionTimer(1800, false, std::chrono::steady_clock::now());
	const auto before = s->getSessionExpiry();
	std::this_thread::sleep_for(std::chrono::milliseconds(20));
	r.h.handle(inDialog("UPDATE", r.toLine, kHandset, "ara-7", 2, false, "", "911"));
	EXPECT_EQ(countTo(r.sent, kHandset, "200 OK"), 1u);
	EXPECT_EQ(countTo(r.sent, kHandset, "403"), 0u);
	EXPECT_GT(s->getSessionExpiry(), before) << "the handset's refresh did not re-arm the timer";
}

// NAT: the handset registered from .51 but its 911 INVITE arrived from .52 (the session's src is
// the registration, its dest stand-in carries the INVITE source). Either address is the handset.
TEST(AnchorReinviteAuth, Control_HandsetKeepsHoldOnA911WhenRegisteredAddressAndCallSourceDiffer)
{
	Rig r;
	MediaBridge* bridge = r.place("911", "192.168.9.52", "ara-8");
	ASSERT_NE(bridge, nullptr);
	r.h.handle(inDialog("INVITE", r.toLine, "192.168.9.52", "ara-8", 2, true, "a=sendonly\r\n", "911"));
	EXPECT_EQ(countTo(r.sent, "192.168.9.52", "200 OK"), 1u);
	EXPECT_TRUE(bridge->isHeld());
	r.sent.clear();
	r.h.handle(inDialog("INVITE", r.toLine, kHandset, "ara-8", 3, true, "a=sendrecv\r\n", "911"));
	EXPECT_EQ(countTo(r.sent, kHandset, "200 OK"), 1u);
	EXPECT_FALSE(bridge->isHeld());
	EXPECT_EQ(countTo(r.sent, kHandset, "403"), 0u);
}

// Inbound anchored call (PSTN -> handset): src is the zeroed PSTN stand-in, dest the handset.
TEST(AnchorReinviteAuth, NonLegSourceReinviteAndUpdateOnInboundAnchorAreRefused)
{
	SentList sent;
	RequestsHandler h(kPbx, 5060, [&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	h.handle(reg("106", kHandset));
	const std::string cidLine = h.routeInboundAnchorCallForTest("106", "part-ara", "5551234567");
	ASSERT_FALSE(cidLine.empty());
	h.tick();
	std::string fork;
	for (const auto& [a, m] : sent)
		if (m && m->toString().rfind("INVITE sip:106@", 0) == 0) fork = m->toString();
	ASSERT_FALSE(fork.empty());
	auto line = [&](const std::string& name) {
		const size_t at = fork.find("\r\n" + name);
		return fork.substr(at + 2, fork.find("\r\n", at + 2) - at - 2);
	};
	const std::string b = sdp(kHandset, "a=sendrecv\r\n");
	h.handle(mk("SIP/2.0 200 OK\r\n" + line("Via:") + "\r\n" + line("From:") + "\r\nTo: <sip:106@" + kPbx + ">;tag=hs106\r\n" +
		cidLine + "\r\nCSeq: 1 INVITE\r\nContact: <sip:106@" + kHandset + ":5060>\r\nContent-Type: application/sdp\r\n"
		"Content-Length: " + std::to_string(b.size()) + "\r\n\r\n" + b, kHandset));
	MediaBridge* bridge = h.anchorBridgeForCallIdForTest(cidLine);
	ASSERT_NE(bridge, nullptr);
	auto sess = h.getSession(cidLine);
	ASSERT_TRUE(sess.has_value());
	ASSERT_EQ(sess.value()->getState(), Session::State::Connected);
	sent.clear();

	for (const char* method : {"INVITE", "UPDATE"})
	{
		const std::string body = sdp(kOther, "a=sendonly\r\n");
		h.handle(mk(std::string(method) + " sip:106@" + kPbx + ":5060 SIP/2.0\r\nVia: SIP/2.0/UDP " + kOther +
			":5060;branch=z9hG4bKs" + method + "\r\nFrom: <sip:106@" + kPbx + ">;tag=hs106\r\nTo: <sip:106@" + kPbx +
			":5060>;tag=pbxtag\r\n" + cidLine + "\r\nCSeq: 2 " + method + "\r\nMax-Forwards: 70\r\nContact: <sip:106@" +
			kOther + ":5060>\r\nContent-Type: application/sdp\r\nContent-Length: " + std::to_string(body.size()) +
			"\r\n\r\n" + body, kOther));
	}
	EXPECT_EQ(countTo(sent, kOther, "200 OK"), 0u);
	EXPECT_EQ(countTo(sent, kOther, "403"), 2u);
	EXPECT_FALSE(bridge->isHeld());
	EXPECT_EQ(sess.value()->getState(), Session::State::Connected);
}

// ── A 911 handset that roams: a resume is accepted from any source, a hold needs a leg ──────────
// sendLocalMediaAnswer()/answerAnchorReinvite() never move RTP to the offer's address, so
// accepting a resume cannot redirect the call's media.

namespace
{
	size_t countLines(const std::string& text, const std::string& needle)
	{
		size_t n = 0;
		for (size_t at = text.find(needle); at != std::string::npos; at = text.find(needle, at + 1)) ++n;
		return n;
	}
}

TEST(AnchorReinviteAuth, EmergencyResumeAfterReRegisterFromANewAddressIsAnsweredOnce)
{
	Rig r;
	MediaBridge* bridge = r.place("911", kHandset, "ara-9");
	ASSERT_NE(bridge, nullptr);
	auto s = r.session("ara-9");
	ASSERT_NE(s, nullptr);
	r.h.handle(inDialog("INVITE", r.toLine, kHandset, "ara-9", 2, true, "a=sendonly\r\n", "911"));
	ASSERT_TRUE(bridge->isHeld());
	r.h.handle(reg("501", "192.168.9.53", "-b"));
	r.sent.clear();
	r.h.handle(inDialog("INVITE", r.toLine, "192.168.9.53", "ara-9", 3, true, "a=sendrecv\r\n", "911"));
	EXPECT_EQ(countTo(r.sent, "192.168.9.53", "200 OK"), 1u);
	EXPECT_EQ(countTo(r.sent, "192.168.9.53", "403"), 0u);
	EXPECT_FALSE(bridge->isHeld());
	EXPECT_EQ(s->getState(), Session::State::Connected);
}

TEST(AnchorReinviteAuth, EmergencyResumeFromAnUnregisteredAddressIsAcceptedAndLoggedOnce)
{
	Rig r;
	MediaBridge* bridge = r.place("911", kHandset, "ara-10");
	ASSERT_NE(bridge, nullptr);
	auto s = r.session("ara-10");
	ASSERT_NE(s, nullptr);
	r.h.handle(inDialog("INVITE", r.toLine, kHandset, "ara-10", 2, true, "a=sendonly\r\n", "911"));
	ASSERT_TRUE(bridge->isHeld());
	r.sent.clear();
	testing::internal::CaptureStdout();
	r.h.handle(inDialog("INVITE", r.toLine, "192.168.9.77", "ara-10", 3, true, "a=sendrecv\r\n", "911"));
	const std::string out = testing::internal::GetCapturedStdout();
	EXPECT_EQ(countTo(r.sent, "192.168.9.77", "200 OK"), 1u);
	EXPECT_EQ(countTo(r.sent, "192.168.9.77", "403"), 0u);
	EXPECT_FALSE(bridge->isHeld());
	EXPECT_EQ(s->getState(), Session::State::Connected);
	EXPECT_EQ(countLines(out, "non-dialog source"), 1u) << out;
}

TEST(AnchorReinviteAuth, EmergencyHoldFromANonLegSourceIsRefusedAndStateIsUnchanged)
{
	Rig r;
	MediaBridge* bridge = r.place("911", kHandset, "ara-11");
	ASSERT_NE(bridge, nullptr);
	auto s = r.session("ara-11");
	ASSERT_NE(s, nullptr);
	r.h.handle(inDialog("INVITE", r.toLine, "192.168.9.77", "ara-11", 2, true, "a=sendonly\r\n", "911"));
	EXPECT_EQ(countTo(r.sent, "192.168.9.77", "403"), 1u);
	EXPECT_EQ(countTo(r.sent, "192.168.9.77", "200 OK"), 0u);
	EXPECT_FALSE(bridge->isHeld());
	EXPECT_EQ(s->getState(), Session::State::Connected);
}

// ── A bodiless UPDATE on a spliced dialog: only the dialog's own party re-arms the timer ────────
namespace
{
	std::shared_ptr<Session> splicedCall(Rig& r)
	{
		r.h.handle(reg("502", "192.168.9.52"));
		r.h.handle(invite("501", "502", kHandset, "ara-sp"));
		const std::string b = sdp("192.168.9.52", "");
		r.h.handle(mk("SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 192.168.9.51:5060;branch=z9hG4bKiara-sp\r\n"
			"From: <sip:501@server>;tag=ftara-sp\r\nTo: <sip:502@server>;tag=btara-sp\r\nCall-ID: ara-sp\r\n"
			"CSeq: 1 INVITE\r\nContact: <sip:502@192.168.9.52:5060>\r\nContent-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(b.size()) + "\r\n\r\n" + b, "192.168.9.52"));
		auto s = r.session("ara-sp");
		if (s && !s->getDest()) ADD_FAILURE() << "precondition: the call is answered";
		if (s) s->setPeerCallID("ara-sp-peer");
		r.sent.clear();
		return s;
	}
}

TEST(AnchorReinviteAuth, NonPartyBodilessUpdateOnASplicedSessionIsRefusedAndKeepsTheTimer)
{
	Rig r;
	auto s = splicedCall(r);
	ASSERT_NE(s, nullptr);
	ASSERT_FALSE(s->getPeerCallID().empty());
	s->armSessionTimer(1800, false, std::chrono::steady_clock::now());
	const auto before = s->getSessionExpiry();
	std::this_thread::sleep_for(std::chrono::milliseconds(20));
	r.h.handle(inDialog("UPDATE", "To: <sip:502@server>", kOther, "ara-sp", 2, false, "", "502"));
	EXPECT_EQ(countTo(r.sent, kOther, "403"), 1u);
	EXPECT_EQ(countTo(r.sent, kOther, "200 OK"), 0u);
	EXPECT_EQ(s->getSessionExpiry(), before);
}

TEST(AnchorReinviteAuth, Control_PartyBodilessUpdateOnASplicedSessionRearmsTheTimer)
{
	Rig r;
	auto s = splicedCall(r);
	ASSERT_NE(s, nullptr);
	s->armSessionTimer(1800, false, std::chrono::steady_clock::now());
	const auto before = s->getSessionExpiry();
	std::this_thread::sleep_for(std::chrono::milliseconds(20));
	r.h.handle(inDialog("UPDATE", "To: <sip:502@server>", kHandset, "ara-sp", 2, false, "", "502"));
	EXPECT_EQ(countTo(r.sent, kHandset, "200 OK"), 1u);
	EXPECT_EQ(countTo(r.sent, kHandset, "403"), 0u);
	EXPECT_GT(s->getSessionExpiry(), before);
}

// ── The refusal log is rate-limited and the refusals are counted ────────────────────────────────
TEST(AnchorReinviteAuth, RepeatedRefusalsOnOneCallIdLogOnceAndAreAllCounted)
{
	Rig r;
	ASSERT_NE(r.place("555", kHandset, "ara-12"), nullptr);
	testing::internal::CaptureStderr();
	for (int i = 0; i < 40; ++i)
		r.h.handle(inDialog("UPDATE", r.toLine, kOther, "ara-12", 2 + i, false, ""));
	const std::string err = testing::internal::GetCapturedStderr();
	EXPECT_EQ(countTo(r.sent, kOther, "403"), 40u);
	EXPECT_EQ(r.h.localReinviteRefusalsForTest(), 40u);
	EXPECT_EQ(countLines(err, "non-dialog source"), 1u) << err;
}

// A NAT handset's own refresh arrives from the same IP on a different port: the check is IP only.
TEST(AnchorReinviteAuth, Control_PartyBodilessUpdateOnASplicedSessionFromAnotherPortRearmsTheTimer)
{
	Rig r;
	auto s = splicedCall(r);
	ASSERT_NE(s, nullptr);
	s->armSessionTimer(1800, false, std::chrono::steady_clock::now());
	const auto before = s->getSessionExpiry();
	std::this_thread::sleep_for(std::chrono::milliseconds(20));
	r.h.handle(inDialog("UPDATE", "To: <sip:502@server>", kHandset, "ara-sp", 2, false, "", "502", 49152));
	EXPECT_EQ(countTo(r.sent, kHandset, "200 OK"), 1u);
	EXPECT_EQ(countTo(r.sent, kHandset, "403"), 0u);
	EXPECT_GT(s->getSessionExpiry(), before);
}

// Accepted emergency resumes have their own log slot and counter: an earlier refusal on the same
// Call-ID neither hides the accepted line nor is counted with it.
TEST(AnchorReinviteAuth, AcceptedEmergencyResumesHaveTheirOwnLogSlotAndCounter)
{
	Rig r;
	MediaBridge* bridge = r.place("911", kHandset, "ara-13");
	ASSERT_NE(bridge, nullptr);
	r.h.handle(inDialog("INVITE", r.toLine, kHandset, "ara-13", 2, true, "a=sendonly\r\n", "911"));
	ASSERT_TRUE(bridge->isHeld());
	r.h.handle(inDialog("INVITE", r.toLine, "192.168.9.77", "ara-13", 3, true, "a=sendonly\r\n", "911"));
	ASSERT_EQ(r.h.localReinviteRefusalsForTest(), 1u);
	testing::internal::CaptureStdout();
	r.h.handle(inDialog("INVITE", r.toLine, "192.168.9.77", "ara-13", 4, true, "a=sendrecv\r\n", "911"));
	r.h.handle(inDialog("INVITE", r.toLine, "192.168.9.78", "ara-13", 5, true, "a=sendrecv\r\n", "911"));
	const std::string out = testing::internal::GetCapturedStdout();
	EXPECT_EQ(countLines(out, "resume accepted"), 1u) << out;
	EXPECT_EQ(r.h.localResumeAcceptsForTest(), 2u);
	EXPECT_EQ(r.h.localReinviteRefusalsForTest(), 1u);
}
