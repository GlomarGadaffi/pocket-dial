// TelCtlPool_test.cpp — #657: a real anchor's makeCall/answerCall/dropCall run
// on workers created once at boot and fed by bounded queues, not on a task made
// per call.
//
// The host suite boots the loopback anchor, so these drive the async branch over
// it with forceAsyncAnchorForTest(), and park the tel_ctl workers with
// holdTelCtlForTest() the way a makeCall stuck in its TLS round trip would.

#include <gtest/gtest.h>

#include <chrono>
#include <functional>
#include <initializer_list>
#include <memory>
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
	constexpr int kWorkers = RequestsHandler::kTelCtlWorkers;
	constexpr int kDepth = RequestsHandler::kTelCtlDepth;
	// One caller per call, plus the 911 dialer and the notify target. The queue
	// must fill before the session pool does, or a 503 here would be the pool's.
	constexpr int kCallers = kWorkers + kDepth + 1;
	static_assert(kCallers + 1 <= POCKETDIAL_MAX_SESSIONS, "fill the tel_ctl queue before the session pool");

	sockaddr_in addr(const std::string& ip)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(5060);
		return s;
	}

	std::string ext(int i) { return std::to_string(101 + i); }
	std::string ip(int i) { return "192.168.79." + std::to_string(11 + i); }
	std::string callId(int i) { return "ctl-" + std::to_string(i); }

	std::shared_ptr<SipMessage> registerOf(const std::string& e, const std::string& at)
	{
		const std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + at + ":5060;branch=z9hG4bKr" + e + "\r\n"
			"From: <sip:" + e + "@server>;tag=rt" + e + "\r\n"
			"To: <sip:" + e + "@server>\r\n"
			"Call-ID: reg-" + e + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + e + "@" + at + ":5060>;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addr(at));
	}

	std::shared_ptr<SipMessage> inviteOf(const std::string& from, const std::string& to,
		const std::string& at, const std::string& id)
	{
		const std::string body =
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + at + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + at + "\r\n"
			"t=0 0\r\n"
			"m=audio 10000 RTP/AVP 0\r\n"
			"a=rtpmap:0 PCMU/8000\r\n";
		const std::string raw =
			"INVITE sip:" + to + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + at + ":5060;branch=z9hG4bKi" + id + "\r\n"
			"From: <sip:" + from + "@server>;tag=ft" + id + "\r\n"
			"To: <sip:" + to + "@server>\r\n"
			"Call-ID: " + id + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:" + from + "@" + at + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addr(at));
	}

	std::shared_ptr<SipMessage> cancelOf(const std::string& from, const std::string& to,
		const std::string& at, const std::string& id)
	{
		const std::string raw =
			"CANCEL sip:" + to + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + at + ":5060;branch=z9hG4bKi" + id + "\r\n"
			"From: <sip:" + from + "@server>;tag=ft" + id + "\r\n"
			"To: <sip:" + to + "@server>\r\n"
			"Call-ID: " + id + "\r\n"
			"CSeq: 1 CANCEL\r\n"
			"Max-Forwards: 70\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addr(at));
	}

	bool waitFor(const std::function<bool()>& done)
	{
		const auto until = std::chrono::steady_clock::now() + std::chrono::seconds(3);
		while (!done())
		{
			if (std::chrono::steady_clock::now() > until) return false;
			std::this_thread::sleep_for(std::chrono::milliseconds(5));
		}
		return true;
	}

	struct Bench
	{
		std::vector<std::string> wire;   // written only from handle(), on this thread
		std::unique_ptr<RequestsHandler> handler;

		// `noWorker`: lanes whose worker could not be created at boot.
		explicit Bench(std::initializer_list<RequestsHandler::TelLane> noWorker = {})
		{
			handler = std::make_unique<RequestsHandler>("192.168.79.1", 5060,
				[this](const sockaddr_in&, std::shared_ptr<SipMessage> m) { wire.push_back(m->toString()); });
			for (int i = 0; i < kCallers; ++i) handler->handle(registerOf(ext(i), ip(i)));
			handler->handle(registerOf("200", "192.168.79.200"));
			handler->setAnchorPlacesRealCallsForTest(true);
			handler->setE911Config("200", "", "");
			for (const auto lane : noWorker) handler->failTelCtlLaneForTest(lane);
			handler->forceAsyncAnchorForTest(true);
			wire.clear();
		}

		~Bench() { handler->holdTelCtlForTest(false); }

		LoopbackAnchorClient* loopback()
		{
			return dynamic_cast<LoopbackAnchorClient*>(handler->anchorClientForTest());
		}

		void dial(int i, const std::string& to) { handler->handle(inviteOf(ext(i), to, ip(i), callId(i))); }

		// Fill every tel_ctl worker with a parked makeCall, then the queue behind them.
		void fill()
		{
			handler->holdTelCtlForTest(true);
			for (int i = 0; i < kWorkers; ++i) dial(i, "555");
			ASSERT_TRUE(waitFor([this] { return handler->telCtlParkedForTest() == kWorkers; }))
				<< "every tel_ctl worker took a makeCall";
			for (int i = kWorkers; i < kWorkers + kDepth; ++i) dial(i, "555");
		}

		// Responses on the wire that start with `status` and belong to call `id`.
		int answers(const std::string& status, const std::string& id) const
		{
			int n = 0;
			for (const auto& s : wire)
			{
				if (s.rfind(status, 0) == 0 && s.find("Call-ID: " + id + "\r\n") != std::string::npos) ++n;
			}
			return n;
		}

		bool sent(const std::string& needle) const
		{
			for (const auto& s : wire)
			{
				if (s.find(needle) != std::string::npos) return true;
			}
			return false;
		}
	};
}

TEST(TelCtlPool, ACallPastAFullWorkerQueueIsRefused503)
{
	Bench b;
	b.fill();
	for (int i = 0; i < kWorkers + kDepth; ++i)
	{
		EXPECT_EQ(b.answers("SIP/2.0 180", callId(i)), 1) << callId(i);
		EXPECT_EQ(b.answers("SIP/2.0 503", callId(i)), 0) << callId(i) << " waits for a worker, it is not refused";
	}

	const int last = kWorkers + kDepth;
	b.dial(last, "555");

	// The 180 first: the session and vpeer pools refuse before it, so a 503
	// after it can only be the worker queue's.
	EXPECT_EQ(b.answers("SIP/2.0 180", callId(last)), 1);
	EXPECT_EQ(b.answers("SIP/2.0 503", callId(last)), 1)
		<< "a call past a full tel_ctl queue must be refused, not given a task of its own";
	EXPECT_FALSE(b.handler->getSession("Call-ID: " + callId(last)).has_value())
		<< "and its session ended";
}

TEST(TelCtlPool, ADropRunsWhileEveryCallWorkerIsBusy)
{
	Bench b;
	b.fill();
	const unsigned before = b.loopback()->dropCallCount();

	b.handler->anchorMediaNeverOpenedForTest("leg-657");

	EXPECT_TRUE(waitFor([&] { return b.loopback()->dropCallCount() == before + 1; }))
		<< "a drop waited behind parked makeCalls: an orphaned leg stays up and bills";
	EXPECT_GE(b.handler->telCtlParkedForTest(), kWorkers) << "precondition: the makeCalls were parked throughout";
}

TEST(TelCtlPool, OrphanDropsFromCallWorkersAllRunWhenTheQueueWasFull)
{
	// #379 through the pool: every makeCall finishes after its caller hung up,
	// so each worker drops its own leg while the others still hold theirs.
	Bench b;
	b.fill();
	for (int i = 0; i < kWorkers + kDepth; ++i)
	{
		b.handler->handle(cancelOf(ext(i), "555", ip(i), callId(i)));
		ASSERT_FALSE(b.handler->getSession("Call-ID: " + callId(i)).has_value()) << callId(i);
	}
	const unsigned before = b.loopback()->dropCallCount();

	b.handler->holdTelCtlForTest(false);

	EXPECT_TRUE(waitFor([&] { return b.loopback()->dropCallCount() == before + kWorkers + kDepth; }))
		<< "dropped " << b.loopback()->dropCallCount() - before << " of " << kWorkers + kDepth << " orphaned legs";
}

TEST(TelCtlPool, AGenuineInboundCallAfterAnOrphanDropStillRings)
{
	// #379's hardware order: the CANCEL ends the session while makeCall() is on the
	// wire, makeCall() then names the leg and the worker drops it. The anchor-side
	// rule that never announces that leg is ESP-only (TelephonyAnchorLogic_test.cpp,
	// tests/tools/test_anchor_own_leg_not_inbound.py). A genuine inbound call is a
	// new participant id, and it must still ring.
	Bench b;
	b.handler->holdTelCtlForTest(true);
	b.dial(0, "555");
	ASSERT_TRUE(waitFor([&] { return b.handler->telCtlParkedForTest() == 1; }));
	b.handler->handle(cancelOf(ext(0), "555", ip(0), callId(0)));
	ASSERT_FALSE(b.handler->getSession("Call-ID: " + callId(0)).has_value()) << "precondition: the CANCEL ended it";
	const unsigned before = b.loopback()->dropCallCount();

	b.handler->holdTelCtlForTest(false);
	ASSERT_TRUE(waitFor([&] { return b.loopback()->dropCallCount() == before + 1; }))
		<< "the leg makeCall() named after the CANCEL was not dropped";
	b.handler->handle(registerOf(ext(0), ip(0)));   // takes _mutex: the worker has let go of it

	const std::string id = b.handler->routeInboundAnchorCallForTest("800", "part-in-379", "5551234567");
	const auto s = b.handler->getSession(id);
	ASSERT_TRUE(s.has_value()) << "a genuine inbound call after the orphan drop was not routed";
	EXPECT_FALSE(s.value()->getPendingTargets().empty()) << "and it rings no phone";
}

TEST(TelCtlPool, AnEmergencyCallIsNotQueuedBehindOrdinaryCallSetup)
{
	Bench b;
	b.fill();
	const int sos = kWorkers + kDepth;

	b.dial(sos, "911");

	EXPECT_EQ(b.answers("SIP/2.0 180", callId(sos)), 1);
	EXPECT_EQ(b.answers("SIP/2.0 503", callId(sos)), 0) << "a 911 was refused for ordinary call setup";
	EXPECT_TRUE(b.sent("ROUTED TO TRUNK"));
	EXPECT_FALSE(b.sent("NOT ROUTED"));
	EXPECT_TRUE(waitFor([&] { return b.loopback()->lastMakeCallDestination() == "911"; }))
		<< "the 911 makeCall waited behind parked ordinary ones";
}

// A lane whose 12 KB worker could not be created at boot posts to tel_ctl: a
// late 911 or drop beats every one refused until reboot.

TEST(TelCtlPool, A911WhoseWorkerFailedAtBootStillRoutes)
{
	Bench b({ RequestsHandler::kLaneSos });
	const int sos = kWorkers + kDepth;

	b.dial(sos, "911");

	EXPECT_EQ(b.answers("SIP/2.0 180", callId(sos)), 1);
	EXPECT_EQ(b.answers("SIP/2.0 503", callId(sos)), 0) << "tel_sos had no worker, so every 911 was refused";
	EXPECT_TRUE(b.sent("ROUTED TO TRUNK"));
	EXPECT_FALSE(b.sent("NOT ROUTED"));
	EXPECT_TRUE(waitFor([&] { return b.loopback()->lastMakeCallDestination() == "911"; }));
}

TEST(TelCtlPool, ADropWhoseWorkerFailedAtBootStillRuns)
{
	Bench b({ RequestsHandler::kLaneDrop });
	const unsigned before = b.loopback()->dropCallCount();

	b.handler->anchorMediaNeverOpenedForTest("leg-657");

	EXPECT_TRUE(waitFor([&] { return b.loopback()->dropCallCount() == before + 1; }))
		<< "tel_drop had no worker, so every drop was refused: orphaned legs stay up and bill";
}

TEST(TelCtlPool, A911WithNoWorkerAnywhereIsRefused503)
{
	// The fallback has no worker either: the #713 refusal, never a 911 queued
	// where nothing will run it.
	Bench b({ RequestsHandler::kLaneSos, RequestsHandler::kLaneCtl });
	const int sos = kWorkers + kDepth;

	b.dial(sos, "911");

	EXPECT_EQ(b.answers("SIP/2.0 503", callId(sos)), 1);
	EXPECT_FALSE(b.handler->getSession("Call-ID: " + callId(sos)).has_value());
	EXPECT_TRUE(b.sent("NOT ROUTED"));
}

// #691 step 0: the no-answer reap of an outbound call whose makeCall() is still on the wire
// has no leg id to drop yet. It drops nothing (an empty id is not handed to dropCall()); the
// worker then names the leg, finds no session and drops it, once (#379 Case A). Pin of today's
// behaviour: it passes on the sources from before releaseFarLeg() too.
TEST(FarLegReleasePin, ARingReapBeforeMakeCallNamesTheLegDropsNothingAndTheWorkerDropsItOnce)
{
	Bench b;
	b.handler->holdTelCtlForTest(true);
	b.dial(0, "555");
	ASSERT_TRUE(waitFor([&] { return b.handler->telCtlParkedForTest() == 1; }));
	auto found = b.handler->getSession("Call-ID: " + callId(0));
	ASSERT_TRUE(found.has_value());
	const std::shared_ptr<Session> session = found.value();
	ASSERT_TRUE(session->getAnchorParticipantId().empty()) << "precondition: makeCall() has not named the leg";
	const unsigned before = b.loopback()->dropCallCount();

	session->armRingTimer(std::chrono::steady_clock::now() - std::chrono::seconds(1));
	b.handler->forceNextTickForTest();
	b.handler->tick();

	ASSERT_FALSE(b.handler->getSession("Call-ID: " + callId(0)).has_value()) << "the reap ended the call";
	std::this_thread::sleep_for(std::chrono::milliseconds(200));
	EXPECT_EQ(b.loopback()->dropCallCount(), before) << "no leg yet: nothing may be dropped, an empty id included";

	b.handler->holdTelCtlForTest(false);
	EXPECT_TRUE(waitFor([&] { return b.loopback()->dropCallCount() == before + 1; }))
		<< "makeCall() returned to no session and did not drop the leg it named";
	std::this_thread::sleep_for(std::chrono::milliseconds(200));
	EXPECT_EQ(b.loopback()->dropCallCount(), before + 1) << "the leg is dropped exactly once";
}
