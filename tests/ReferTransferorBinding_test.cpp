// ReferTransferorBinding_test.cpp -- an in-dialog REFER must come from the leg of
// the party it names as the transferor.
//
// onRefer() resolves the transferor from the From header. The only source check
// was isDialogSourceAuthorized(), which accepts the address of EITHER leg of the
// dialog, so the far party's REFER naming the near party passed it, and the
// transfer then moved the wrong leg. The source address must match the leg whose
// extension is the named transferor. Port is not compared (a NAT handset may send
// from another port).
//
// Rule 5 controls: a REFER on a live 911 call and on a PSAP callback draws exactly
// the answer it drew before (603 from the handset's own address, 403 from a third
// address), and never tears the call down.
//
// Shared address: when both legs of a dialog sit at one IP (two extensions behind
// one NAT), the legs cannot be told apart by address. The check then falls back to
// the From header: the named transferor must be one of the dialog's two parties.

#include <gtest/gtest.h>

#include <string>
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
	const char* const kIp1 = "192.168.9.21";
	const char* const kIp2 = "192.168.9.22";
	const char* const kIp3 = "192.168.9.23";
	const char* const kIpNew = "192.168.9.31";
	const char* const kIp911 = "192.168.9.51";
	const char* const kIpOther = "192.168.9.77";

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

	std::string sdp(const std::string& ip, int port)
	{
		return "v=0\r\no=- 0 0 IN IP4 " + ip + "\r\ns=-\r\nc=IN IP4 " + ip + "\r\nt=0 0\r\nm=audio " + std::to_string(port) +
			" RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
	}

	std::shared_ptr<SipMessage> invite(const std::string& from, const std::string& to, const std::string& ip, const std::string& cid)
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

	// `from` is the extension named in From. `replaces` non-empty makes the REFER attended.
	std::shared_ptr<SipMessage> refer(const std::string& from, const std::string& to, const std::string& srcIp,
		const std::string& cid, const std::string& target, int cseq, const std::string& replaces = "",
		uint16_t port = 5060, const std::string& toTag = "")
	{
		const std::string referTo = "<sip:" + target + "@server" + (replaces.empty() ? "" : "?Replaces=" + replaces) + ">";
		return mk("REFER sip:" + to + "@server SIP/2.0\r\nVia: SIP/2.0/UDP " + srcIp + ":" + std::to_string(port) +
			";branch=z9hG4bKref" + cid + std::to_string(cseq) + "\r\n"
			"From: <sip:" + from + "@server>;tag=ft" + cid + "\r\nTo: <sip:" + to + "@server>;tag=" +
			(toTag.empty() ? "bt" + cid : toTag) + "\r\nCall-ID: " + cid + "\r\nCSeq: " + std::to_string(cseq) +
			" REFER\r\nMax-Forwards: 70\r\nRefer-To: " + referTo + "\r\nContact: <sip:" + from + "@" + srcIp + ":" +
			std::to_string(port) + ">\r\nContent-Length: 0\r\n\r\n", srcIp, port);
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

	size_t countAny(const SentList& sent, const std::string& needle)
	{
		size_t n = 0;
		for (const auto& [a, m] : sent)
		{
			(void)a;
			if (!m) continue;
			const std::string raw = m->toString();
			if (raw.substr(0, raw.find("\r\n")).find(needle) != std::string::npos) ++n;
		}
		return n;
	}

	size_t countLines(const std::string& text, const std::string& needle)
	{
		size_t n = 0;
		for (size_t p = text.find(needle); p != std::string::npos; p = text.find(needle, p + 1)) ++n;
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
		}

		// 401@kIp1, 402@kIp2, 403@kIp3.
		void registerThree(const char* ip2 = kIp2, const char* ip3 = kIp3)
		{
			h.handle(reg("401", kIp1));
			h.handle(reg("402", ip2));
			h.handle(reg("403", ip3));
		}

		// `from` calls `to`, answered. Leaves `sent` cleared.
		bool connect(const std::string& from, const std::string& fromIp, const std::string& to, const std::string& toIp,
			const std::string& cid)
		{
			h.handle(invite(from, to, fromIp, cid));
			h.handle(ok200(from, to, fromIp, toIp, cid));
			auto s = h.getSession("Call-ID: " + cid);
			sent.clear();
			return s.has_value() && s.value()->getState() == Session::State::Connected;
		}

		bool connected(const std::string& cid)
		{
			auto s = h.getSession("Call-ID: " + cid);
			return s.has_value() && s.value()->getState() == Session::State::Connected;
		}

		// 501 dials 911 from kIp911; records the 200's To line (with the board's tag).
		bool place911(const std::string& cid)
		{
			h.handle(reg("501", kIp911));
			sent.clear();
			h.handle(invite("501", "911", kIp911, cid));
			if (sent.empty() || !sent.front().second) return false;
			const std::string t = std::string(sent.front().second->getTo());
			toLine = t.substr(t.find('<'));
			sent.clear();
			auto s = h.getSession("Call-ID: " + cid);
			return s.has_value() && s.value()->isEmergency();
		}
	};

	void expectNothingMoved(const SentList& sent)
	{
		EXPECT_EQ(countAny(sent, "BYE"), 0u) << "a leg was torn down";
		EXPECT_EQ(countAny(sent, "INVITE"), 0u) << "a dialog was started or changed";
		EXPECT_EQ(countAny(sent, "202"), 0u) << "the request was accepted";
	}
}

// ── A REFER whose source is not the named transferor's leg ──────────────────────────────────────

TEST(ReferTransferorBinding, BlindReferFromTheOtherLegNamingTheCallerIsRefused)
{
	Rig r;
	r.registerThree();
	ASSERT_TRUE(r.connect("401", kIp1, "402", kIp2, "rtb-1"));
	r.h.handle(refer("401", "402", kIp2, "rtb-1", "403", 2));
	EXPECT_EQ(countTo(r.sent, kIp2, "202"), 0u);
	EXPECT_EQ(countTo(r.sent, kIp2, "SIP/2.0 403"), 1u);
	EXPECT_EQ(r.sent.size(), 1u) << "the refusal is the only message sent";
	expectNothingMoved(r.sent);
	EXPECT_TRUE(r.connected("rtb-1"));
	EXPECT_EQ(r.h.referBindingRefusalsForTest(), 1u);
}

TEST(ReferTransferorBinding, BlindReferFromTheCallersLegNamingTheCalleeIsRefused)
{
	Rig r;
	r.registerThree();
	ASSERT_TRUE(r.connect("401", kIp1, "402", kIp2, "rtb-2"));
	r.h.handle(refer("402", "401", kIp1, "rtb-2", "403", 2));
	EXPECT_EQ(countTo(r.sent, kIp1, "202"), 0u);
	EXPECT_EQ(countTo(r.sent, kIp1, "SIP/2.0 403"), 1u);
	EXPECT_EQ(r.sent.size(), 1u);
	expectNothingMoved(r.sent);
	EXPECT_TRUE(r.connected("rtb-2"));
	EXPECT_EQ(r.h.referBindingRefusalsForTest(), 1u);
}

// Two extensions at one address, the second also on a consult call with the first: its REFER
// names the first and passes the per-dialog address checks on both dialogs.
TEST(ReferTransferorBinding, AttendedReferFromTheOtherLegNamingTheCallerIsRefused)
{
	Rig r;
	r.registerThree(kIp2, kIp2);
	ASSERT_TRUE(r.connect("401", kIp1, "402", kIp2, "rtb-3a"));
	ASSERT_TRUE(r.connect("401", kIp1, "403", kIp2, "rtb-3b"));
	r.h.handle(refer("401", "402", kIp2, "rtb-3a", "403", 2, "rtb-3b"));
	EXPECT_EQ(countTo(r.sent, kIp2, "202"), 0u);
	EXPECT_EQ(countTo(r.sent, kIp2, "SIP/2.0 403"), 1u);
	EXPECT_EQ(r.sent.size(), 1u);
	expectNothingMoved(r.sent);
	EXPECT_TRUE(r.connected("rtb-3a"));
	EXPECT_TRUE(r.connected("rtb-3b"));
	EXPECT_EQ(r.h.referBindingRefusalsForTest(), 1u);
}

// Where the address of the other party is not on the consult dialog, the earlier per-dialog
// check already refuses, and the new check is not reached.
TEST(ReferTransferorBinding, Control_AttendedReferFromAnAddressOffTheConsultDialogIsRefusedAsBefore)
{
	Rig r;
	r.registerThree();
	ASSERT_TRUE(r.connect("401", kIp1, "402", kIp2, "rtb-4a"));
	ASSERT_TRUE(r.connect("401", kIp1, "403", kIp3, "rtb-4b"));
	r.h.handle(refer("401", "402", kIp2, "rtb-4a", "403", 2, "rtb-4b"));
	EXPECT_EQ(countTo(r.sent, kIp2, "SIP/2.0 403"), 1u);
	EXPECT_EQ(r.sent.size(), 1u);
	expectNothingMoved(r.sent);
	EXPECT_EQ(r.h.referBindingRefusalsForTest(), 0u);
}

// ── The transferor's own REFER still works, with exact counts ───────────────────────────────────

TEST(ReferTransferorBinding, Control_TheCallersOwnBlindReferStillTransfers)
{
	Rig r;
	r.registerThree();
	ASSERT_TRUE(r.connect("401", kIp1, "402", kIp2, "rtb-5"));
	r.h.handle(refer("401", "402", kIp1, "rtb-5", "403", 2));
	EXPECT_EQ(countTo(r.sent, kIp1, "202"), 1u);
	EXPECT_EQ(countTo(r.sent, kIp3, "INVITE"), 1u);
	EXPECT_EQ(countTo(r.sent, kIp1, "BYE"), 1u);
	EXPECT_EQ(countTo(r.sent, kIp2, "BYE"), 0u);
	EXPECT_EQ(countAny(r.sent, "SIP/2.0 403"), 0u);
	EXPECT_EQ(r.h.referBindingRefusalsForTest(), 0u);
}

TEST(ReferTransferorBinding, Control_TheCalleesOwnBlindReferStillTransfers)
{
	Rig r;
	r.registerThree();
	ASSERT_TRUE(r.connect("402", kIp2, "401", kIp1, "rtb-6"));
	r.h.handle(refer("401", "402", kIp1, "rtb-6", "403", 2));
	EXPECT_EQ(countTo(r.sent, kIp1, "202"), 1u);
	EXPECT_EQ(countTo(r.sent, kIp3, "INVITE"), 1u);
	EXPECT_EQ(countTo(r.sent, kIp1, "BYE"), 1u);
	EXPECT_EQ(countTo(r.sent, kIp2, "BYE"), 0u);
	EXPECT_EQ(countAny(r.sent, "SIP/2.0 403"), 0u);
	EXPECT_EQ(r.h.referBindingRefusalsForTest(), 0u);
}

TEST(ReferTransferorBinding, Control_TheCallersOwnAttendedReferStillTransfers)
{
	Rig r;
	r.registerThree();
	ASSERT_TRUE(r.connect("401", kIp1, "402", kIp2, "rtb-7a"));
	ASSERT_TRUE(r.connect("401", kIp1, "403", kIp3, "rtb-7b"));
	r.h.handle(refer("401", "402", kIp1, "rtb-7a", "403", 2, "rtb-7b"));
	EXPECT_EQ(countTo(r.sent, kIp1, "202"), 1u);
	EXPECT_EQ(countTo(r.sent, kIp2, "INVITE"), 1u);
	EXPECT_EQ(countTo(r.sent, kIp3, "INVITE"), 1u);
	EXPECT_EQ(countTo(r.sent, kIp1, "BYE"), 2u);
	EXPECT_EQ(countAny(r.sent, "SIP/2.0 403"), 0u);
	EXPECT_EQ(r.h.referBindingRefusalsForTest(), 0u);
}

// A NAT handset sends from another port of the same address: the match is on the address only.
TEST(ReferTransferorBinding, Control_TheCallersReferFromAnotherPortStillTransfers)
{
	Rig r;
	r.registerThree();
	ASSERT_TRUE(r.connect("401", kIp1, "402", kIp2, "rtb-8"));
	r.h.handle(refer("401", "402", kIp1, "rtb-8", "403", 2, "", 49152));
	EXPECT_EQ(countTo(r.sent, kIp1, "202"), 1u);
	EXPECT_EQ(countTo(r.sent, kIp3, "INVITE"), 1u);
	EXPECT_EQ(countAny(r.sent, "SIP/2.0 403"), 0u);
	EXPECT_EQ(r.h.referBindingRefusalsForTest(), 0u);
}

// The handset re-REGISTERs from a new address mid-call and then transfers from it.
TEST(ReferTransferorBinding, Control_TheCallersReferAfterARoamingReRegisterStillTransfers)
{
	Rig r;
	r.registerThree();
	ASSERT_TRUE(r.connect("401", kIp1, "402", kIp2, "rtb-9"));
	r.h.handle(reg("401", kIpNew, "roam"));
	r.sent.clear();
	r.h.handle(refer("401", "402", kIpNew, "rtb-9", "403", 2));
	EXPECT_EQ(countTo(r.sent, kIpNew, "202"), 1u);
	EXPECT_EQ(countTo(r.sent, kIp3, "INVITE"), 1u);
	EXPECT_EQ(countAny(r.sent, "SIP/2.0 403"), 0u);
	EXPECT_EQ(r.h.referBindingRefusalsForTest(), 0u);
}

// ── Both parties at one address: the legs cannot be told apart, so the From header decides ──────

TEST(ReferTransferorBinding, Control_ASharedAddressStillLetsEitherPartyTransfer)
{
	Rig r;
	r.registerThree(kIp1);
	ASSERT_TRUE(r.connect("401", kIp1, "402", kIp1, "rtb-10"));
	r.h.handle(refer("401", "402", kIp1, "rtb-10", "403", 2));
	EXPECT_EQ(countTo(r.sent, kIp1, "202"), 1u);
	EXPECT_EQ(countTo(r.sent, kIp3, "INVITE"), 1u);
	EXPECT_EQ(countAny(r.sent, "SIP/2.0 403"), 0u);
	EXPECT_EQ(r.h.referBindingRefusalsForTest(), 0u);
}

TEST(ReferTransferorBinding, ASharedAddressRefusesANameThatIsNotAPartyToTheDialog)
{
	Rig r;
	r.registerThree(kIp1);
	ASSERT_TRUE(r.connect("401", kIp1, "402", kIp1, "rtb-11"));
	r.h.handle(refer("403", "402", kIp1, "rtb-11", "401", 2));
	EXPECT_EQ(countTo(r.sent, kIp1, "SIP/2.0 403"), 1u);
	EXPECT_EQ(r.sent.size(), 1u);
	expectNothingMoved(r.sent);
	EXPECT_TRUE(r.connected("rtb-11"));
	EXPECT_EQ(r.h.referBindingRefusalsForTest(), 1u);
}

// ── Counter and rate-limited log ────────────────────────────────────────────────────────────────

TEST(ReferTransferorBinding, RepeatedRefusalsOnOneCallLogOnceAndAreAllCounted)
{
	Rig r;
	r.registerThree();
	ASSERT_TRUE(r.connect("401", kIp1, "402", kIp2, "rtb-12"));
	testing::internal::CaptureStderr();
	for (int i = 0; i < 30; ++i) r.h.handle(refer("401", "402", kIp2, "rtb-12", "403", 2 + i));
	const std::string err = testing::internal::GetCapturedStderr();
	EXPECT_EQ(countTo(r.sent, kIp2, "SIP/2.0 403"), 30u);
	EXPECT_EQ(r.h.referBindingRefusalsForTest(), 30u);
	EXPECT_EQ(countLines(err, "REFER for Call-ID: rtb-12 from"), 1u) << err;
}

// ── Rule 5: a REFER on a 911 call or a PSAP callback is answered as before ──────────────────────

// The handset's own REFER on its 911 call: the anchored leg is declined, the call stays up.
TEST(ReferTransferorBinding, Control_ReferOnALive911CallFromTheHandsetIsDeclinedAsBefore)
{
	Rig r;
	r.h.handle(reg("403", kIp3));
	ASSERT_TRUE(r.place911("rtb-13"));
	r.h.handle(refer("501", "911", kIp911, "rtb-13", "403", 2, "", 5060, r.toLine.substr(r.toLine.find("tag=") + 4)));
	EXPECT_EQ(countTo(r.sent, kIp911, "603"), 1u);
	EXPECT_EQ(r.sent.size(), 1u);
	EXPECT_EQ(countAny(r.sent, "BYE"), 0u);
	EXPECT_TRUE(r.connected("rtb-13"));
	EXPECT_EQ(r.h.referBindingRefusalsForTest(), 0u);
}

// The same REFER from a NAT port of the handset's address.
TEST(ReferTransferorBinding, Control_ReferOnALive911CallFromAnotherPortIsDeclinedAsBefore)
{
	Rig r;
	r.h.handle(reg("403", kIp3));
	ASSERT_TRUE(r.place911("rtb-14"));
	r.h.handle(refer("501", "911", kIp911, "rtb-14", "403", 2, "", 49152, r.toLine.substr(r.toLine.find("tag=") + 4)));
	EXPECT_EQ(countTo(r.sent, kIp911, "603"), 1u);
	EXPECT_EQ(r.sent.size(), 1u);
	EXPECT_EQ(countAny(r.sent, "BYE"), 0u);
	EXPECT_TRUE(r.connected("rtb-14"));
}

// A REFER from an address that is not the call's: refused by the existing dialog check, call kept.
TEST(ReferTransferorBinding, Control_ReferOnALive911CallFromAThirdAddressIsRefusedAsBefore)
{
	Rig r;
	r.h.handle(reg("403", kIp3));
	ASSERT_TRUE(r.place911("rtb-15"));
	r.h.handle(refer("501", "911", kIpOther, "rtb-15", "403", 2, "", 5060, r.toLine.substr(r.toLine.find("tag=") + 4)));
	EXPECT_EQ(countTo(r.sent, kIpOther, "SIP/2.0 403"), 1u);
	EXPECT_EQ(r.sent.size(), 1u);
	EXPECT_EQ(countAny(r.sent, "BYE"), 0u);
	EXPECT_TRUE(r.connected("rtb-15"));
}

// The handset's own address, but From names another registered extension: not the handset's
// REFER, so it is refused by the transferor binding before the anchored-leg decline. The call stays up.
TEST(ReferTransferorBinding, ReferOnALive911CallFromTheHandsetAddressNamingAnotherExtensionIsRefused)
{
	Rig r;
	r.h.handle(reg("403", kIp3));
	ASSERT_TRUE(r.place911("rtb-16"));
	r.h.handle(refer("403", "911", kIp911, "rtb-16", "501", 2, "", 5060, r.toLine.substr(r.toLine.find("tag=") + 4)));
	EXPECT_EQ(countTo(r.sent, kIp911, "SIP/2.0 403"), 1u);
	EXPECT_EQ(countTo(r.sent, kIp911, "603"), 0u);
	EXPECT_EQ(r.sent.size(), 1u);
	EXPECT_EQ(countAny(r.sent, "BYE"), 0u);
	EXPECT_TRUE(r.connected("rtb-16"));
	EXPECT_EQ(r.h.referBindingRefusalsForTest(), 1u);
}

// The handset re-REGISTERs from a new address mid-call and sends its own REFER from there.
TEST(ReferTransferorBinding, Control_ReferOnALive911CallAfterARoamingReRegisterIsDeclinedAsBefore)
{
	Rig r;
	r.h.handle(reg("403", kIp3));
	ASSERT_TRUE(r.place911("rtb-17"));
	r.h.handle(reg("501", kIpNew, "roam"));
	r.sent.clear();
	r.h.handle(refer("501", "911", kIpNew, "rtb-17", "403", 2, "", 5060, r.toLine.substr(r.toLine.find("tag=") + 4)));
	EXPECT_EQ(countTo(r.sent, kIpNew, "603"), 1u);
	EXPECT_EQ(r.sent.size(), 1u);
	EXPECT_EQ(countAny(r.sent, "BYE"), 0u);
	EXPECT_TRUE(r.connected("rtb-17"));
	EXPECT_EQ(r.h.referBindingRefusalsForTest(), 0u);
}
