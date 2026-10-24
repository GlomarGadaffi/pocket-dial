// AnchorInboundDeregister_test.cpp: issue #1098.
//
// An inbound anchored call (PSTN -> handsets) keeps the handsets it rings in the session's
// pendingTargets and has no dest until one answers. sessionOnExtension() knew only src, dest
// and a plain call's ringing callee, so a ringing handset was no party to the call: its
// de-REGISTER or lapsed lease released it from under a live PSAP callback (Rule 5, #712),
// a released client stayed in pendingTargets, and allocateClient() could hand its pool slot
// to a new number. #1094 deferred this for plain and trunk-inbound ringing calls.
//
// Pinned here: a PSAP callback keeps a ringing handset (binding, slot, pending entry) until
// the call is answered elsewhere or ends, then the deferred release happens; an ordinary
// inbound call CANCELs only the departing handset (the others keep ringing) and ends, as a
// plain ringing call does, when the last ringing handset leaves.

#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include "LoopbackAnchorClient.hpp"
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

	const char* const kPbxIp = "192.168.41.1";
	const char* const kHs1Ip = "192.168.41.20";
	const char* const kHs2Ip = "192.168.41.21";
	const char* const kOtherIp = "192.168.41.99";

	sockaddr_in addrFor(const std::string& ip)
	{
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_addr.s_addr = inet_addr(ip.c_str());
		a.sin_port = htons(5060);
		return a;
	}

	std::shared_ptr<SipMessage> registerOf(const std::string& ext, const std::string& ip, int expires)
	{
		const std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKr" + ext + std::to_string(expires) + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + ext + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: reg-1098-" + ext + "\r\n"
			"CSeq: " + std::to_string(expires == 0 ? 2 : 1) + " REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + ip + ":5060>;expires=" + std::to_string(expires) + "\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}

	std::string sdpBody()
	{
		return std::string(
			"v=0\r\no=- 0 0 IN IP4 10.0.0.20\r\ns=-\r\nc=IN IP4 10.0.0.20\r\nt=0 0\r\n"
			"m=audio 10000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n");
	}

	std::string headerLine(const std::string& raw, const std::string& name)
	{
		size_t pos = 0;
		while (pos < raw.size())
		{
			size_t eol = raw.find("\r\n", pos);
			if (eol == std::string::npos) eol = raw.size();
			const std::string line = raw.substr(pos, eol - pos);
			if (line.size() > name.size() && line.compare(0, name.size(), name) == 0) return line;
			pos = eol + 2;
		}
		return {};
	}

	struct RingAll
	{
		Sent sent;
		RequestsHandler handler{kPbxIp, 5060,
			[this](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); }};
		LoopbackAnchorClient* loop = nullptr;
		std::string callIdLine;
		std::shared_ptr<Session> session;
		std::string fork106, fork107;
		unsigned dropsBefore = 0;

		// Rings 106 (and 107 when `two`) as a ring-all inbound call. `psap` flags the session as a
		// PSAP callback, as routeInboundAnchorCall() does for a handset inside #659's window.
		void ring(bool psap, bool two)
		{
			handler.handle(registerOf("106", kHs1Ip, 3600));
			if (two) handler.handle(registerOf("107", kHs2Ip, 3600));
			callIdLine = handler.routeInboundAnchorCallForTest("800", "part-1098", "5551234567");
			ASSERT_FALSE(callIdLine.empty()) << "precondition: an inbound anchored session exists";
			handler.tick();   // the fork INVITEs wait in _asyncOutbox
			fork106 = findSentTo(kHs1Ip, "INVITE sip:106@");
			ASSERT_FALSE(fork106.empty()) << "precondition: 106 is rung";
			if (two)
			{
				fork107 = findSentTo(kHs2Ip, "INVITE sip:107@");
				ASSERT_FALSE(fork107.empty()) << "precondition: 107 is rung";
			}
			auto s = handler.getSession(callIdLine);
			ASSERT_TRUE(s.has_value());
			session = s.value();
			session->setEmergency(psap);
			ASSERT_EQ(session->getState(), Session::State::Invited) << "precondition: ringing";
			ASSERT_EQ(session->getPendingTargets().size(), two ? 2u : 1u);
			loop = dynamic_cast<LoopbackAnchorClient*>(handler.anchorClientForTest());
			ASSERT_NE(loop, nullptr) << "host suite is expected to boot the Loopback anchor";
			dropsBefore = loop->dropCallCount();
			sent.clear();
		}

		std::string findSentTo(const char* ip, const std::string& needle) const
		{
			for (const auto& [a, m] : sent)
				if (m && a.sin_addr.s_addr == addrFor(ip).sin_addr.s_addr && m->toString().find(needle) != std::string::npos)
					return m->toString();
			return {};
		}

		void leave(bool lease, const std::string& ext, const char* ip)
		{
			if (lease) handler.expireLeaseAndSweepForTest(ext);
			else handler.handle(registerOf(ext, ip, 0));
			handler.tick();
			std::this_thread::sleep_for(std::chrono::milliseconds(200));   // the anchor drop runs on a worker
		}

		size_t cancelsTo(const char* ip) const
		{
			size_t n = 0;
			for (const auto& [a, m] : sent)
				if (m && a.sin_addr.s_addr == addrFor(ip).sin_addr.s_addr && m->toString().rfind("CANCEL ", 0) == 0) ++n;
			return n;
		}

		bool bound(const std::string& ext)
		{
			handler.forceNextTickForTest();
			handler.tick();
			for (const auto& [number, address] : handler.getActiveClients())
			{
				(void)address;
				if (number == ext) return true;
			}
			return false;
		}

		// The handset `ext` at `ip` answers the fork INVITE it was sent.
		void answer(const std::string& ext, const char* ip, const std::string& fork)
		{
			const std::string body = sdpBody();
			handler.handle(RequestsHandler::getMessageFromPool(
				"SIP/2.0 200 OK\r\n" + headerLine(fork, "Via:") + "\r\n" + headerLine(fork, "From:") + "\r\n"
				"To: <sip:" + ext + "@" + std::string(kPbxIp) + ">;tag=hs" + ext + "\r\n" + callIdLine + "\r\n"
				"CSeq: 1 INVITE\r\nContact: <sip:" + ext + "@" + std::string(ip) + ":5060>\r\n"
				"Content-Type: application/sdp\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body,
				addrFor(ip)));
		}
	};
}

// Rule 5 (#712): a PSAP callback ringing handset 106 survives 106's de-REGISTER or lapsed
// lease. Nothing is CANCELled or dropped, 106 stays bound and a pending target of the call.
TEST(AnchorInboundDeregister, APsapCallbackKeepsARingingHandsetThatDeregistersOrLapses)
{
	for (const bool lease : { false, true })
	{
		SCOPED_TRACE(lease ? "lease expiry" : "REGISTER Expires 0");
		RingAll r;
		ASSERT_NO_FATAL_FAILURE(r.ring(/*psap=*/true, /*two=*/true));

		r.leave(lease, "106", kHs1Ip);

		EXPECT_TRUE(r.handler.getSession(r.callIdLine).has_value()) << "the callback was torn down";
		EXPECT_EQ(r.loop->dropCallCount(), r.dropsBefore) << "the PSAP leg was dropped";
		EXPECT_EQ(r.cancelsTo(kHs1Ip), 0u) << "the ringing handset was CANCELled";
		EXPECT_EQ(r.cancelsTo(kHs2Ip), 0u) << "the other ringing handset was CANCELled";
		EXPECT_TRUE(r.bound("106")) << "the binding must stay while the callback rings";
		ASSERT_EQ(r.session->getPendingTargets().size(), 2u);
		EXPECT_EQ(r.session->getPendingTargets()[0]->getNumber(), "106")
			<< "a pending target of the live callback was blanked";
	}
}

// The same handset, a full client pool and a new number: the lapsed 106 keeps its slot, so
// the new phone is refused as for any full pool instead of inheriting a pending target.
TEST(AnchorInboundDeregister, APsapCallbacksRingingHandsetKeepsItsSlotWhenThePoolIsFull)
{
	for (const bool lease : { false, true })
	{
		SCOPED_TRACE(lease ? "lease lapsed, not yet swept" : "REGISTER Expires 0");
		RingAll r;
		ASSERT_NO_FATAL_FAILURE(r.ring(true, true));
		for (int i = 2; i < POCKETDIAL_MAX_CLIENTS; ++i)
			r.handler.handle(registerOf("2" + std::to_string(100 + i), kOtherIp, 3600));
		if (lease) r.handler.expireLeaseUnsweptForTest("106");
		else r.handler.handle(registerOf("106", kHs1Ip, 0));

		r.handler.handle(registerOf("300", kOtherIp, 3600));   // pool full: would evict the lapsed 106

		EXPECT_FALSE(r.bound("300")) << "no free slot: refused, as for any full pool";
		ASSERT_EQ(r.session->getPendingTargets().size(), 2u);
		EXPECT_EQ(r.session->getPendingTargets()[0]->getNumber(), "106")
			<< "106's slot was reused: the new number inherits a pending target";
		EXPECT_TRUE(r.handler.getSession(r.callIdLine).has_value());
	}
}

// 106 de-registers, 107 answers: the call goes on, the pending target is no longer a party,
// and the next sweep carries out the deferred release.
TEST(AnchorInboundDeregister, TheDeferredReleaseHappensOnceTheCallbackIsAnsweredElsewhere)
{
	for (const bool lease : { false, true })
	{
		SCOPED_TRACE(lease ? "lease expiry" : "REGISTER Expires 0");
		RingAll r;
		ASSERT_NO_FATAL_FAILURE(r.ring(true, true));
		r.leave(lease, "106", kHs1Ip);
		ASSERT_TRUE(r.bound("106")) << "precondition: deferred";

		r.answer("107", kHs2Ip, r.fork107);
		ASSERT_EQ(r.session->getState(), Session::State::Connected) << "precondition: answered";
		ASSERT_TRUE(r.session->getDest() && r.session->getDest()->getNumber() == "107");

		r.handler.idleClientAndSweepForTest("106", std::chrono::seconds(0));
		EXPECT_FALSE(r.bound("106")) << "the deferred release never happened";
		EXPECT_TRUE(r.bound("107"));
		EXPECT_TRUE(r.handler.getSession(r.callIdLine).has_value()) << "the answered callback ended";
	}
}

// The deferred handset that answers after it re-registers binds to the call.
TEST(AnchorInboundDeregister, ADeferredHandsetThatAnswersBindsToTheCallback)
{
	RingAll r;
	ASSERT_NO_FATAL_FAILURE(r.ring(true, false));
	r.leave(false, "106", kHs1Ip);
	r.handler.handle(registerOf("106", kHs1Ip, 3600));

	r.answer("106", kHs1Ip, r.fork106);

	ASSERT_EQ(r.session->getState(), Session::State::Connected);
	ASSERT_TRUE(r.session->getDest());
	EXPECT_EQ(r.session->getDest()->getNumber(), "106");
	EXPECT_TRUE(r.bound("106"));
}

// An ordinary inbound call (not a callback) is handled as #1094 handles a plain ringing call:
// the departing handset is CANCELled and released. A ring-all keeps ringing the others, and
// ends when the last ringing handset has left.
TEST(AnchorInboundDeregister, AnOrdinaryInboundCallCancelsOnlyTheDepartingHandset)
{
	for (const bool lease : { false, true })
	{
		SCOPED_TRACE(lease ? "lease expiry" : "REGISTER Expires 0");
		RingAll r;
		ASSERT_NO_FATAL_FAILURE(r.ring(/*psap=*/false, /*two=*/true));

		r.leave(lease, "106", kHs1Ip);

		EXPECT_TRUE(r.handler.getSession(r.callIdLine).has_value()) << "107 still rings: the call goes on";
		EXPECT_EQ(r.loop->dropCallCount(), r.dropsBefore);
		EXPECT_EQ(r.cancelsTo(kHs1Ip), 1u) << "the departing handset must stop ringing";
		EXPECT_EQ(r.cancelsTo(kHs2Ip), 0u);
		EXPECT_FALSE(r.bound("106")) << "released";
		ASSERT_EQ(r.session->getPendingTargets().size(), 1u) << "a released client is still a pending target";
		EXPECT_EQ(r.session->getPendingTargets()[0]->getNumber(), "107");

		r.answer("107", kHs2Ip, r.fork107);
		ASSERT_EQ(r.session->getState(), Session::State::Connected);
		EXPECT_EQ(r.session->getDest()->getNumber(), "107");
	}
}

TEST(AnchorInboundDeregister, AnOrdinaryInboundCallEndsWhenItsLastRingingHandsetLeaves)
{
	for (const bool lease : { false, true })
	{
		SCOPED_TRACE(lease ? "lease expiry" : "REGISTER Expires 0");
		RingAll r;
		ASSERT_NO_FATAL_FAILURE(r.ring(false, /*two=*/false));

		r.leave(lease, "106", kHs1Ip);

		EXPECT_EQ(r.cancelsTo(kHs1Ip), 1u) << "the departing handset must stop ringing";
		EXPECT_FALSE(r.handler.getSession(r.callIdLine).has_value()) << "nobody is left to answer";
		EXPECT_EQ(r.loop->dropCallCount(), r.dropsBefore + 1) << "the carrier leg is dropped exactly once";
		EXPECT_FALSE(r.bound("106"));
	}
}
