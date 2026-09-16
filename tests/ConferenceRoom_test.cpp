// ConferenceRoom_test.cpp — Issue #75: MixBus wired into MediaBridge, and made
// dialable as the 888 meet-me room.
//
// MixBus_test.cpp already proves the arithmetic in isolation. What was missing, and
// what this file covers, is the wiring:
//
//   1. MediaBridge in BUS mode really does route the handset RX/TX callbacks through
//      MixBus::inputFrame/outputFrame — driven through the REAL µ-law rim, so the
//      expected values are computed by round-tripping through G.711 rather than
//      hardcoding integer sums (µ-law is lossy; a hardcoded sum would be wrong).
//   2. Three (and four) legs on one bus each hear the sum of the OTHERS, never
//      themselves, and never the over-saturated "loud leg hears near-silence" bug.
//   3. A leg leaving mid-conference does not disturb the rest — its port only goes
//      Draining and the next tick reclaims it.
//   4. There is exactly ONE tick driver, it is idempotent to start, and it really
//      advances the bus (proved via the Draining->Free reclaim, which only tick() does).
//   5. RequestsHandler's onInvite intercept: 3+ registered extensions dialing 888 are
//      answered 200 OK with a sendrecv SDP and land on one room; a BYE from one leaves
//      the others mixing.
//
// On host RtpReceiver::start() is a no-op stub, so RX is always driven directly through
// MediaBridge::onHandsetRtp. RtpSender is NOT inert on a Linux host: RtpSender.cpp's
// "Linux desktop" branch (Issue #82) spawns a real std::thread the moment startBridge()
// succeeds, and that thread calls the same fillHandsetTx provider on its own 20 ms pacer
// — racing any test that also calls fillHandsetTx (or reads getPlayoutBuffer()) directly
// after startBridge(). A test that wants deterministic, synchronous control over TX must
// stop the RtpSender it passed to init() right after startBridge() returns (the bridge
// itself, and the bus port, stay live — only the background pacer thread is halted) before
// driving fillHandsetTx by hand. See AnchorModeIsUnchangedByTheBusRewiring below.

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "ConferenceRoom.hpp"
#include "LoopbackAnchorClient.hpp"
#include "MediaBridge.hpp"
#include "MixBus.hpp"
#include "PoolConfig.hpp"
#include "RequestsHandler.hpp"
#include "RtpReceiver.hpp"
#include "RtpSender.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	constexpr size_t FRAME = static_cast<size_t>(MixBus::FRAME);

	// One 20 ms µ-law frame of a constant PCM level — what a handset actually puts on
	// the wire, so the test exercises the encode/decode rim rather than bypassing it.
	std::vector<uint8_t> ulawFrame(int16_t level)
	{
		std::vector<int16_t> pcm(FRAME, level);
		std::vector<uint8_t> out(FRAME);
		RtpSender::ulawEncodeBuffer(pcm.data(), pcm.size(), out.data());
		return out;
	}

	// The value a PCM level becomes after one µ-law round trip — i.e. what the bus
	// actually sums, not the level the test asked for.
	int16_t quantized(int16_t level)
	{
		return RtpReceiver::mulawDecode(RtpSender::linearToUlaw(level));
	}

	int16_t saturate(int32_t v)
	{
		if (v > 32767)  return 32767;
		if (v < -32768) return -32768;
		return static_cast<int16_t>(v);
	}

	// What a leg hears for a given int32 mix value: saturated once, then through the
	// outbound µ-law rim and back for comparison.
	int16_t heardAfterRim(int32_t mix)
	{
		return RtpReceiver::mulawDecode(RtpSender::linearToUlaw(saturate(mix)));
	}

	// Halt every named leg's RtpSender pacer thread so the test is the ONLY consumer
	// of each port's out ring before it starts draining legs by hand (issue #135).
	// On this host RtpSender::start() spawns a real 20 ms thread whose provider is
	// MediaBridge::fillHandsetTx -- the same destructive PlayoutBuffer::read() that
	// drainLeg() below performs -- so without this the pacer can pop the very frame
	// the test is about to assert on. stop() joins synchronously; the bridge and its
	// bus port stay live, so tickOnce()/drainLeg() remain valid afterwards. Same shape
	// as the tx.stop("call-x") in AnchorModeIsUnchangedByTheBusRewiring.
	void quiesceSenders(ConferenceRoom& room, const std::vector<std::string>& callIds)
	{
		for (const auto& id : callIds)
		{
			RtpSender* tx = room.senderForCall(id);
			ASSERT_NE(tx, nullptr) << "no leg for " << id;
			ASSERT_TRUE(tx->stop(id)) << "pacer for " << id << " was not running";
		}
	}

	// Pull one 20 ms frame out of a leg and decode it back to PCM16.
	std::vector<int16_t> drainLeg(MediaBridge& bridge)
	{
		std::vector<uint8_t> ulaw(FRAME, 0);
		EXPECT_TRUE(bridge.fillHandsetTx(ulaw.data(), FRAME));
		std::vector<int16_t> pcm(FRAME, 0);
		RtpReceiver::mulawDecodeBuffer(ulaw.data(), FRAME, pcm.data());
		return pcm;
	}

	void speak(MediaBridge& bridge, int16_t level)
	{
		std::vector<uint8_t> f = ulawFrame(level);
		bridge.onHandsetRtp(f.data(), f.size());
	}

	// Every sample in the frame carries the same expected value (constant-level input).
	void expectConstantFrame(const std::vector<int16_t>& pcm, int16_t expected,
		const char* what)
	{
		ASSERT_EQ(pcm.size(), FRAME) << what;
		for (size_t i = 0; i < pcm.size(); ++i)
		{
			ASSERT_EQ(pcm[i], expected) << what << " (sample " << i << ")";
		}
	}

	sockaddr_in addrFor(const std::string& ip)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(5060);
		return s;
	}

	std::shared_ptr<SipMessage> makeRegister(const std::string& ext, const std::string& srcIp,
		const std::string& callId)
	{
		std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bKr" + callId + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + callId + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + srcIp + ":5060>;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}

	std::shared_ptr<SipMessage> makeInvite(const std::string& fromExt, const std::string& toExt,
		const std::string& srcIp, const std::string& callId, int rtpPort = 10000)
	{
		std::string body =
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + srcIp + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + srcIp + "\r\n"
			"t=0 0\r\n"
			"m=audio " + std::to_string(rtpPort) + " RTP/AVP 0\r\n"
			"a=rtpmap:0 PCMU/8000\r\n";
		std::string raw =
			"INVITE sip:" + toExt + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bKi" + callId + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:" + fromExt + "@" + srcIp + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}

	std::shared_ptr<SipMessage> makeBye(const std::string& fromExt, const std::string& toExt,
		const std::string& srcIp, const std::string& callId)
	{
		std::string raw =
			"BYE sip:" + toExt + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bKb" + callId + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>;tag=srv" + callId + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 2 BYE\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}
}

// ── The wiring: MediaBridge BUS mode over a shared MixBus ─────────────────────

TEST(ConferenceRoom, ThreeLegsEachHearTheOthersMinusThemselves)
{
	ConferenceRoom room;   // no driver: the test owns the clock via tickOnce()

	ASSERT_GE(room.join("call-a", "101", "127.0.0.1", 10001), 0);
	ASSERT_GE(room.join("call-b", "102", "127.0.0.1", 10002), 0);
	ASSERT_GE(room.join("call-c", "103", "127.0.0.1", 10003), 0);
	EXPECT_EQ(room.legCount(), 3);
	quiesceSenders(room, {"call-a", "call-b", "call-c"});

	MediaBridge* a = room.bridgeForCall("call-a");
	MediaBridge* b = room.bridgeForCall("call-b");
	MediaBridge* c = room.bridgeForCall("call-c");
	ASSERT_NE(a, nullptr);
	ASSERT_NE(b, nullptr);
	ASSERT_NE(c, nullptr);

	// Distinct ports on ONE bus — the whole point of the issue.
	EXPECT_GE(a->busPort(), 0);
	EXPECT_NE(a->busPort(), b->busPort());
	EXPECT_NE(b->busPort(), c->busPort());
	EXPECT_NE(a->busPort(), c->busPort());

	const int16_t la = 1000, lb = 2000, lc = 4000;
	speak(*a, la);
	speak(*b, lb);
	speak(*c, lc);

	room.tickOnce();

	expectConstantFrame(drainLeg(*a), heardAfterRim(quantized(lb) + quantized(lc)),
		"leg A must hear B+C");
	expectConstantFrame(drainLeg(*b), heardAfterRim(quantized(la) + quantized(lc)),
		"leg B must hear A+C");
	expectConstantFrame(drainLeg(*c), heardAfterRim(quantized(la) + quantized(lb)),
		"leg C must hear A+B");

	// And explicitly NOT the all-inclusive sum: minus-self is the invariant that keeps
	// a talker from hearing themselves one frame late.
	const int16_t allThree = heardAfterRim(quantized(la) + quantized(lb) + quantized(lc));
	speak(*a, la); speak(*b, lb); speak(*c, lc);
	room.tickOnce();
	EXPECT_NE(drainLeg(*a)[0], allThree)
		<< "a leg that hears the full mix is hearing itself — minus-self is broken";
}

TEST(ConferenceRoom, LoudLegsDoNotOverSaturateThroughTheBridge)
{
	// docs/CONFERENCE_MIXER.md §1's worked counterexample, but end-to-end through the
	// bridges: clip the running mix to int16 first and the loud leg hears near-silence.
	ConferenceRoom room;
	ASSERT_GE(ConferenceRoom::MAX_LEGS, 3)
		<< "needs at least three legs for the sum to exceed int16 at this level";
	std::vector<std::string> ids;
	for (int i = 0; i < ConferenceRoom::MAX_LEGS; ++i)
	{
		ids.push_back("loud-" + std::to_string(i));
		ASSERT_GE(room.join(ids.back(), "10" + std::to_string(i), "127.0.0.1",
			static_cast<uint16_t>(11000 + i)), 0);
	}
	quiesceSenders(room, ids);

	const int16_t level = 30000;
	for (const auto& id : ids)
	{
		speak(*room.bridgeForCall(id), level);
	}
	room.tickOnce();

	// N-1 peers at ~30000 each far exceeds int16 -> saturates to 32767 exactly once,
	// then the µ-law rim rounds it to the top companding level. Clip the RUNNING mix
	// instead and this leg would hear 32767-30000 = 2767, i.e. near silence.
	const int16_t expected = heardAfterRim(
		static_cast<int32_t>(ConferenceRoom::MAX_LEGS - 1) * quantized(level));
	expectConstantFrame(drainLeg(*room.bridgeForCall(ids.front())), expected,
		"loud leg must hear full-scale, not the near-silence of a pre-saturated mix");
	EXPECT_GT(expected, 30000)
		<< "sanity: the expected value must be near full scale, or this test proves nothing";
}

TEST(ConferenceRoom, LegLeavingDoesNotDisturbTheRest)
{
	ConferenceRoom room;
	ASSERT_GE(room.join("call-a", "101", "127.0.0.1", 12001), 0);
	ASSERT_GE(room.join("call-b", "102", "127.0.0.1", 12002), 0);
	ASSERT_GE(room.join("call-c", "103", "127.0.0.1", 12003), 0);
	quiesceSenders(room, {"call-a", "call-b", "call-c"});

	MediaBridge* a = room.bridgeForCall("call-a");
	MediaBridge* b = room.bridgeForCall("call-b");
	MediaBridge* c = room.bridgeForCall("call-c");

	const int16_t la = 1000, lb = 2000, lc = 4000;
	speak(*a, la); speak(*b, lb); speak(*c, lc);
	room.tickOnce();
	// Drain every leg so the next tick's frame is the one under test.
	drainLeg(*a); drainLeg(*b); drainLeg(*c);

	// C hangs up.
	EXPECT_TRUE(room.leave("call-c"));
	EXPECT_FALSE(room.hasLeg("call-c"));
	EXPECT_EQ(room.legCount(), 2);

	speak(*a, la); speak(*b, lb);
	room.tickOnce();

	expectConstantFrame(drainLeg(*a), heardAfterRim(quantized(lb)),
		"A must hear only B once C has left");
	expectConstantFrame(drainLeg(*b), heardAfterRim(quantized(la)),
		"B must hear only A once C has left");

	// The departed leg's bridge is idle and refuses to source audio at all.
	EXPECT_FALSE(c->isActive());
	EXPECT_EQ(c->busPort(), -1);
	std::vector<uint8_t> scratch(FRAME, 0);
	EXPECT_FALSE(c->fillHandsetTx(scratch.data(), FRAME));

	// leave() is idempotent — RequestsHandler::endCall() calls it for every teardown.
	EXPECT_FALSE(room.leave("call-c"));
	EXPECT_FALSE(room.leave("never-joined"));
}

TEST(ConferenceRoom, RejoinAfterLeaveReusesTheReclaimedPort)
{
	ConferenceRoom room;
	ASSERT_GE(room.join("call-a", "101", "127.0.0.1", 13001), 0);
	MediaBridge* a = room.bridgeForCall("call-a");
	const int firstPort = a->busPort();
	ASSERT_GE(firstPort, 0);

	EXPECT_TRUE(room.leave("call-a"));
	room.tickOnce();   // the tick is the sole reclaimer: Draining -> Free

	ASSERT_GE(room.join("call-a2", "101", "127.0.0.1", 13002), 0);
	EXPECT_EQ(room.bridgeForCall("call-a2")->busPort(), firstPort)
		<< "a reclaimed slot must be reusable, or the room leaks a port per call";
}

TEST(ConferenceRoom, RoomIsBoundedAndOneCallIdOwnsOneLeg)
{
	ConferenceRoom room;
	for (int i = 0; i < ConferenceRoom::MAX_LEGS; ++i)
	{
		ASSERT_GE(room.join("call-" + std::to_string(i), "10" + std::to_string(i),
			"127.0.0.1", static_cast<uint16_t>(14000 + i)), 0);
	}
	EXPECT_EQ(room.legCount(), ConferenceRoom::MAX_LEGS);
	EXPECT_LT(room.join("one-too-many", "199", "127.0.0.1", 14999), 0);

	// A retransmitted INVITE must not burn a second port for the same dialog.
	EXPECT_TRUE(room.leave("call-0"));
	ASSERT_GE(room.join("dup", "150", "127.0.0.1", 14500), 0);
	EXPECT_LT(room.join("dup", "150", "127.0.0.1", 14500), 0);
	EXPECT_EQ(room.legCount(), ConferenceRoom::MAX_LEGS);
}

TEST(ConferenceRoom, JoinRejectsAnUnusableMediaDestination)
{
	ConferenceRoom room;
	EXPECT_LT(room.join("call-a", "101", "", 15001), 0);
	EXPECT_LT(room.join("call-a", "101", "127.0.0.1", 0), 0);
	EXPECT_LT(room.join("", "101", "127.0.0.1", 15001), 0);
	EXPECT_EQ(room.legCount(), 0);
}

// ── The single tick driver ───────────────────────────────────────────────────

TEST(ConferenceRoom, TickDriverIsSingleIdempotentAndReallyAdvancesTheBus)
{
	ConferenceRoom room;
	EXPECT_FALSE(room.driverRunning());

	room.startDriver();
	EXPECT_TRUE(room.driverRunning());
	room.startDriver();   // idempotent: never a second, competing tick path
	EXPECT_TRUE(room.driverRunning());

	// Fill the bus by hand, free one port, and wait for it to come back. Only tick()
	// performs the Draining -> Free reclaim, so a slot reappearing proves the driver
	// is genuinely running the master clock.
	std::vector<int> ports;
	for (int i = 0; i < MixBus::MAX_PORTS; ++i)
	{
		int p = room.bus().attach();
		ASSERT_GE(p, 0);
		ports.push_back(p);
	}
	ASSERT_LT(room.bus().attach(), 0) << "bus should be full";

	room.bus().detach(ports.back());

	int reclaimed = -1;
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
	while (std::chrono::steady_clock::now() < deadline)
	{
		reclaimed = room.bus().attach();
		if (reclaimed >= 0) break;
		std::this_thread::sleep_for(std::chrono::milliseconds(5));
	}
	EXPECT_EQ(reclaimed, ports.back())
		<< "the mix tick driver never ran: a detached port was never reclaimed";

	room.stopDriver();
	EXPECT_FALSE(room.driverRunning());
	room.stopDriver();   // idempotent
	room.tickOnce();     // still steppable by hand once the driver is down
}

// ── MediaBridge: BUS mode vs the unchanged ANCHOR mode ───────────────────────

TEST(ConferenceRoom, BridgeWithoutAnchorOrBusRefusesToStart)
{
	RtpReceiver rx;
	RtpSender tx;
	MediaBridge bridge;
	bridge.init(&rx, &tx, /*anchor=*/nullptr, /*bus=*/nullptr);
	EXPECT_FALSE(bridge.startBridge("127.0.0.1", 16001, "call-x", "101"))
		<< "a bridge with nowhere to send audio must fail loudly, not run silently";
}

TEST(ConferenceRoom, BusModeFeedRxIsRefusedRatherThanSilentlyDiscarded)
{
	MixBus bus;
	RtpReceiver rx;
	RtpSender tx;
	LoopbackAnchorClient anchor;
	anchor.init("", "", "", "100");
	anchor.start();

	MediaBridge bridge;
	bridge.init(&rx, &tx, &anchor, &bus);
	ASSERT_TRUE(bridge.startBridge("127.0.0.1", 16002, "call-x", "part-1"));

	const int16_t samples[] = {111, 222, 333};
	// In BUS mode the sender reads the bus, so a playout-buffer write would vanish.
	EXPECT_FALSE(bridge.feedRx("part-1", samples, 3));
	EXPECT_EQ(bridge.getPlayoutBuffer().getLength(), 0u);
}

TEST(ConferenceRoom, AnchorModeIsUnchangedByTheBusRewiring)
{
	// The historical 1:1 path must behave exactly as before when no bus is supplied:
	// handset RX -> anchor, anchor feedRx -> playout buffer -> handset TX.
	RtpReceiver rx;
	RtpSender tx;
	LoopbackAnchorClient anchor;
	anchor.init("", "", "", "100");
	anchor.start();

	MediaBridge bridge;
	bridge.init(&rx, &tx, &anchor);   // no bus argument at all
	ASSERT_TRUE(bridge.startBridge("127.0.0.1", 16003, "call-x", "part-1"));
	EXPECT_EQ(bridge.busPort(), -1);

	// Halt RtpSender's own background pacer thread (Linux host only — see the file
	// header comment) before driving the playout buffer by hand below, so its
	// unrelated 20 ms fillHandsetTx tick can't race and drain what this test writes.
	ASSERT_TRUE(tx.stop("call-x"));

	const int16_t in[] = {111, 222, 333};
	EXPECT_TRUE(bridge.feedRx("part-1", in, 3));
	EXPECT_EQ(bridge.getPlayoutBuffer().getLength(), 3u);

	// And the TX callback still drains that playout buffer through the µ-law rim.
	std::vector<uint8_t> ulaw(3, 0);
	EXPECT_TRUE(bridge.fillHandsetTx(ulaw.data(), 3));
	EXPECT_EQ(bridge.getPlayoutBuffer().getLength(), 0u);
	EXPECT_EQ(RtpReceiver::mulawDecode(ulaw[0]), quantized(111));
}

TEST(ConferenceRoom, StartBridgeFailsAndLeavesNoPortBehindWhenTheBusIsFull)
{
	MixBus bus;
	for (int i = 0; i < MixBus::MAX_PORTS; ++i)
	{
		ASSERT_GE(bus.attach(), 0);
	}

	RtpReceiver rx;
	RtpSender tx;
	MediaBridge bridge;
	bridge.init(&rx, &tx, /*anchor=*/nullptr, &bus);
	EXPECT_FALSE(bridge.startBridge("127.0.0.1", 16004, "call-x", "101"));
	EXPECT_FALSE(bridge.isActive());
	EXPECT_EQ(bridge.busPort(), -1);
	// Nothing was opened, so the one-stream socket caps are still free.
	EXPECT_FALSE(rx.isActive());
	EXPECT_FALSE(tx.isActive());
}

// ── The dial mechanism: RequestsHandler's 888 intercept ──────────────────────

TEST(ConferenceRoom, ThreeExtensionsDialingTheConferenceExtensionLandOnOneRoom)
{
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler("192.168.7.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	handler.handle(makeRegister("501", "192.168.7.51", "reg-501"));
	handler.handle(makeRegister("502", "192.168.7.52", "reg-502"));
	handler.handle(makeRegister("503", "192.168.7.53", "reg-503"));
	EXPECT_EQ(handler.getConferenceLegs(), 0) << "no room until someone dials in";

	const std::string ext(ConferenceRoom::EXT);
	struct Caller { const char* num; const char* ip; const char* callId; };
	const Caller callers[] = {
		{"501", "192.168.7.51", "conf-501"},
		{"502", "192.168.7.52", "conf-502"},
		{"503", "192.168.7.53", "conf-503"},
	};

	for (const auto& c : callers)
	{
		sent.clear();
		handler.handle(makeInvite(c.num, ext, c.ip, c.callId));

		ASSERT_FALSE(sent.empty()) << c.num << " got no answer from " << ext;
		std::string raw = sent.front().second ? sent.front().second->toString() : std::string{};
		EXPECT_NE(raw.find("SIP/2.0 200 OK"), std::string::npos)
			<< c.num << " should be answered 200 OK, got:\n" << raw;
		EXPECT_NE(raw.find("a=sendrecv"), std::string::npos)
			<< "a conference leg must be two-way or the phone never sends audio to mix";
		EXPECT_NE(raw.find("RTP/AVP 0"), std::string::npos) << "PCMU only";
		EXPECT_NE(raw.find("Contact: <sip:" + ext), std::string::npos)
			<< "the answer must come from the conference extension";
		EXPECT_TRUE(handler.getSession("Call-ID: " + std::string(c.callId)).has_value());
	}

	EXPECT_EQ(handler.getConferenceLegs(), 3)
		<< "3+ extensions must be bridged onto ONE room — the issue's acceptance criterion";

	// One leg hangs up: the other two keep their legs and their sessions.
	sent.clear();
	handler.handle(makeBye("502", ext, "192.168.7.52", "conf-502"));
	bool sawOk = false;
	for (const auto& [addr, msg] : sent)
	{
		(void)addr;
		if (msg && msg->toString().find("SIP/2.0 200 OK") != std::string::npos) sawOk = true;
	}
	EXPECT_TRUE(sawOk) << "the BYE must be answered";
	EXPECT_EQ(handler.getConferenceLegs(), 2)
		<< "exactly one leg leaves; the rest must be undisturbed";
	EXPECT_TRUE(handler.getSession("Call-ID: conf-501").has_value());
	EXPECT_FALSE(handler.getSession("Call-ID: conf-502").has_value());
	EXPECT_TRUE(handler.getSession("Call-ID: conf-503").has_value());
}

TEST(ConferenceRoom, PcmaOnlyOfferGets488NotMixedInAsSilence)
{
	// Issue #304: conference mixing only understands PCMU -- RtpReceiver.cpp
	// only recognizes PAYLOAD_TYPE_PCMU as audio, so a PCMA-only leg would
	// mix in as permanent silence rather than fail loudly.
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler("192.168.7.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	handler.handle(makeRegister("504", "192.168.7.54", "reg-504"));
	sent.clear();

	const std::string ext(ConferenceRoom::EXT);
	sockaddr_in s{}; s.sin_family = AF_INET;
	s.sin_addr.s_addr = inet_addr("192.168.7.54"); s.sin_port = htons(5060);
	std::string body =
		"v=0\r\n"
		"o=- 0 0 IN IP4 192.168.7.54\r\n"
		"s=-\r\n"
		"c=IN IP4 192.168.7.54\r\n"
		"t=0 0\r\n"
		"m=audio 10000 RTP/AVP 8\r\n"
		"a=rtpmap:8 PCMA/8000\r\n";
	std::string raw =
		"INVITE sip:" + ext + "@server SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.7.54:5060;branch=z9hG4bKconfpcma\r\n"
		"From: <sip:504@server>;tag=ftconfpcma\r\n"
		"To: <sip:" + ext + "@server>\r\n"
		"Call-ID: conf-pcma\r\n"
		"CSeq: 1 INVITE\r\n"
		"Contact: <sip:504@192.168.7.54:5060>\r\n"
		"Content-Type: application/sdp\r\n"
		"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
	handler.handle(RequestsHandler::getMessageFromPool(raw, s));

	ASSERT_FALSE(sent.empty()) << "PCMA-only offer to " << ext << " got no response at all";
	const std::string respRaw = sent.front().second ? sent.front().second->toString() : std::string{};
	EXPECT_NE(respRaw.find("SIP/2.0 488"), std::string::npos)
		<< "PCMA-only offer should be refused with 488, got:\n" << respRaw;
	EXPECT_EQ(handler.getConferenceLegs(), 0) << "no leg should be mixed in";
}

TEST(ConferenceRoom, ConferenceDialIsRefusedWhenTheRoomIsFull)
{
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler("192.168.7.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const std::string ext(ConferenceRoom::EXT);
	// One more caller than the room holds. Keep it inside the session pool so this
	// test fails on the room cap, not on 503 Service Unavailable.
	ASSERT_LE(ConferenceRoom::MAX_LEGS + 1, POCKETDIAL_MAX_SESSIONS)
		<< "test assumes the room fills before the session pool does";

	for (int i = 0; i <= ConferenceRoom::MAX_LEGS; ++i)
	{
		const std::string num = "6" + std::to_string(10 + i);
		const std::string ip = "192.168.7." + std::to_string(100 + i);
		handler.handle(makeRegister(num, ip, "reg-" + num));

		sent.clear();
		handler.handle(makeInvite(num, ext, ip, "conffull-" + num));
		ASSERT_FALSE(sent.empty());
		const std::string raw = sent.front().second ? sent.front().second->toString() : std::string{};

		if (i < ConferenceRoom::MAX_LEGS)
		{
			EXPECT_NE(raw.find("SIP/2.0 200 OK"), std::string::npos)
				<< "leg " << i << " should have been admitted, got:\n" << raw;
		}
		else
		{
			EXPECT_NE(raw.find("486 Busy Here"), std::string::npos)
				<< "a dial past the room cap must degrade to 486, got:\n" << raw;
			EXPECT_EQ(raw.find("SIP/2.0 200 OK"), std::string::npos)
				<< "never a false 200 for a caller that was not actually mixed";
			EXPECT_FALSE(handler.getSession("Call-ID: conffull-" + num).has_value())
				<< "a refused conference dial must not consume a session slot";
		}
	}

	EXPECT_EQ(handler.getConferenceLegs(), ConferenceRoom::MAX_LEGS);
}

TEST(ConferenceRoom, HoldReinviteOnAConferenceLegIsDeclinedNotRelayedBackToTheCaller)
{
	// A conference leg's session "dest" is a stand-in SipClient carrying the CALLER's
	// own address (there is no second phone). Relaying a hold re-INVITE to it would
	// send the phone its own offer back, so the virtual-leg guard must decline instead
	// — the same treatment 777 gets.
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler("192.168.7.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const std::string ext(ConferenceRoom::EXT);
	handler.handle(makeRegister("501", "192.168.7.51", "reg-501"));
	handler.handle(makeInvite("501", ext, "192.168.7.51", "conf-hold"));
	ASSERT_EQ(handler.getConferenceLegs(), 1);

	// Same Call-ID, now WITH a To-tag: an established-dialog re-INVITE (RFC 3261 §12.2).
	sent.clear();
	auto reinvite = makeInvite("501", ext, "192.168.7.51", "conf-hold");
	{
		std::string raw = reinvite->toString();
		const std::string toLine = "To: <sip:" + ext + "@server>";
		const size_t at = raw.find(toLine);
		ASSERT_NE(at, std::string::npos);
		raw.insert(at + toLine.size(), ";tag=srvtag");
		reinvite->reset(std::move(raw), addrFor("192.168.7.51"));
	}
	handler.handle(reinvite);

	ASSERT_FALSE(sent.empty()) << "the re-INVITE got no response at all";
	bool saw488 = false;
	bool sawRelayedInvite = false;
	for (const auto& [addr, msg] : sent)
	{
		(void)addr;
		const std::string raw = msg ? msg->toString() : std::string{};
		if (raw.find("488 Not Acceptable Here") != std::string::npos) saw488 = true;
		if (raw.rfind("INVITE ", 0) == 0) sawRelayedInvite = true;
	}
	EXPECT_TRUE(saw488) << "hold on a conference leg must be declined 488";
	EXPECT_FALSE(sawRelayedInvite)
		<< "nothing INVITE-shaped may be relayed back to the caller's own address";
	EXPECT_EQ(handler.getConferenceLegs(), 1) << "the leg must survive a declined hold";
}

TEST(ConferenceRoom, ConferenceExtensionIsReservedFromForwardsAndRingGroups)
{
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler("192.168.7.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const std::string ext(ConferenceRoom::EXT);
	handler.setForward(ext, "always", "501");
	handler.setRingGroup(ext, "501,502", "ringall");

	// Neither may take: 888 is a virtual extension, exactly like 777/999, so it must
	// never be shadowed by a forward or a ring group.
	handler.handle(makeRegister("501", "192.168.7.51", "reg-501"));
	sent.clear();
	handler.handle(makeInvite("501", ext, "192.168.7.51", "conf-reserved"));
	ASSERT_FALSE(sent.empty());
	const std::string raw = sent.front().second ? sent.front().second->toString() : std::string{};
	EXPECT_NE(raw.find("SIP/2.0 200 OK"), std::string::npos)
		<< "the conference intercept must still win, got:\n" << raw;
	EXPECT_EQ(handler.getConferenceLegs(), 1);
}
