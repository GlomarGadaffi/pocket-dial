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
#include <memory>
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
	// #479: MixBus::MAX_PORTS == MAX_LEGS, so no spare port: the freed one is
	// Draining until the next mix tick reclaims it (the driver's 20 ms tick).
	room.bus().tick();
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

// Issue #498: tick()'s scratch now lives in the bus, 16-byte aligned for the mix
// kernels. make_unique is how RequestsHandler builds the room; alignof(ConferenceRoom)
// being above the target's 8-byte default new alignment is what makes that the
// aligned operator new.
TEST(ConferenceRoom, BusIsSixteenByteAlignedWhenBuiltTheWayTheServerBuildsIt)
{
	static_assert(alignof(ConferenceRoom) >= 16, "the room must carry the bus's alignment");
	auto room = std::make_unique<ConferenceRoom>();
	EXPECT_TRUE(room->busAligned());
	EXPECT_EQ(reinterpret_cast<std::uintptr_t>(&room->bus()) % 16, 0u);
	EXPECT_GE(room->join("call-a", "101", "127.0.0.1", 15101), 0)
		<< "an aligned room must accept a leg";
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

// ── Issue #1003: an 888 leg whose phone vanished is reaped by the #604 sweep ──
//
// A harness that dies mid-conference sends no BYE and no more RTP. tick()'s RTP-
// inactivity sweep used to skip every session that was neither a trunk relay nor
// an anchor bridge, so the legs sat in the room (and kept being streamed to) until
// the registration lease ran out. A conference leg has one received-packet counter,
// MediaBridge::handsetRtpPackets(), and the sweep now watches it.
//
// 777 (SDP loopback), 440 (sendonly tone), and a parked call (sendonly hold music,
// bounded by the park timeout) have no board-side receive path, so there is no
// counter to watch; the last three tests pin that they are NOT reaped.
namespace
{
	// RequestsHandler + the datagrams it sent, with the one-line steps these tests repeat.
	struct ReapBench
	{
		std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
		RequestsHandler handler{"192.168.7.1", 5060,
			[this](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
				sent.emplace_back(addr, std::move(msg));
			}};

		static std::string callIdOf(const std::string& id) { return "Call-ID: " + id; }

		// Registers `num` and dials `to` from it; returns the 200 OK the board answered with.
		std::string dial(const std::string& num, const std::string& ip, const std::string& id,
			const std::string& to = ConferenceRoom::EXT)
		{
			handler.handle(makeRegister(num, ip, "reg-" + num));
			sent.clear();
			handler.handle(makeInvite(num, to, ip, id));
			for (const auto& [addr, msg] : sent)
			{
				(void)addr;
				const std::string raw = msg ? msg->toString() : std::string{};
				if (raw.rfind("SIP/2.0 200 OK", 0) == 0) return raw;
			}
			return {};
		}

		std::shared_ptr<Session> session(const std::string& id)
		{
			auto s = handler.getSession(callIdOf(id));
			return s.has_value() ? s.value() : nullptr;
		}

		bool alive(const std::string& id) { return handler.getSession(callIdOf(id)).has_value(); }

		// One packet of audio from the phone on this conference leg, as its RTP receiver delivers it.
		void rtpFrom(const std::string& id)
		{
			MediaBridge* b = handler.conferenceForTest()->bridgeForCall(callIdOf(id));
			ASSERT_NE(b, nullptr) << id << " has no conference leg";
			const std::vector<uint8_t> f = ulawFrame(1000);
			b->onHandsetRtp(f.data(), f.size());
		}

		// Run the watch clock `age` forward and run one tick() pass.
		void tickAfter(const std::string& id, std::chrono::seconds age)
		{
			auto s = session(id);
			ASSERT_NE(s, nullptr) << id;
			s->ageRtpWatchForTest(age);
			tickNow();
		}
		void tickNow()
		{
			handler.forceNextTickForTest();
			sent.clear();
			handler.tick();
		}

		std::vector<std::string> byesTo(const std::string& ip)
		{
			std::vector<std::string> out;
			for (const auto& [addr, msg] : sent)
			{
				if (!msg || addr.sin_addr.s_addr != addrFor(ip).sin_addr.s_addr) continue;
				const std::string raw = msg->toString();
				if (raw.rfind("BYE ", 0) == 0) out.push_back(raw);
			}
			return out;
		}
	};

	// "To: x" -> "x" (first header of that name).
	std::string headerValue(const std::string& raw, const std::string& name)
	{
		const size_t at = raw.find("\r\n" + name + ": ");
		if (at == std::string::npos) return {};
		const size_t from = at + 4 + name.size();
		return raw.substr(from, raw.find("\r\n", from) - from);
	}
}

TEST(ConferenceReap, AnOrphanedConferenceLegIsReapedAfterSixtySecondsOfRxSilenceAndNotBefore)
{
	ReapBench b;
	const std::string answer = b.dial("501", "192.168.7.51", "conf-1003");
	ASSERT_FALSE(answer.empty()) << "precondition: 501 joined the room";
	ASSERT_EQ(b.handler.getConferenceLegs(), 1);
	b.handler.tick();   // arms the watch

	b.tickAfter("conf-1003", std::chrono::seconds(55));
	ASSERT_TRUE(b.alive("conf-1003")) << "55 s of silence is inside the 60 s limit";
	ASSERT_TRUE(b.byesTo("192.168.7.51").empty());

	b.tickAfter("conf-1003", std::chrono::seconds(6));   // 61 s in all

	EXPECT_FALSE(b.alive("conf-1003")) << "61 s with no RTP from the phone and no BYE: reaped";
	EXPECT_EQ(b.handler.getConferenceLegs(), 0) << "the room leg must go with the session";
	EXPECT_EQ(b.handler.getSessionCount(), 0u);
	EXPECT_EQ(b.handler.conferenceForTest()->legCount(), 0);
	EXPECT_EQ(b.handler.conferenceForTest()->bridgeForCall("Call-ID: conf-1003"), nullptr);
	EXPECT_EQ(b.handler.conferenceForTest()->senderForCall("Call-ID: conf-1003"), nullptr);

	// The phone is told, once, from our side of the dialog (RFC 3261 s12.2.1.1).
	const auto byes = b.byesTo("192.168.7.51");
	ASSERT_EQ(byes.size(), 1u) << "exactly one BYE to the vanished phone";
	EXPECT_EQ(byes[0].rfind("BYE sip:501@192.168.7.51:5060 SIP/2.0", 0), 0u) << byes[0];
	EXPECT_NE(byes[0].find("Call-ID: conf-1003"), std::string::npos);
	EXPECT_EQ(headerValue(byes[0], "From"), headerValue(answer, "To"))
		<< "the BYE is from the PBX end of the dialog: the 200 OK's To, with our tag";
	EXPECT_EQ(headerValue(byes[0], "To"), "<sip:501@server>;tag=ftconf-1003")
		<< "and to the phone's own From, with its tag";

	// The CDR names the room, as a BYE-ended 888 leg's does.
	bool recorded = false;
	for (const auto& rec : b.handler.cdrSnapshotForTest())
	{
		if (rec.caller == "501" && rec.callee == ConferenceRoom::EXT) recorded = true;
	}
	EXPECT_TRUE(recorded) << "CDR 501 -> 888";
}

TEST(ConferenceReap, AConferenceLegThatKeepsReceivingIsNotReapedUntilItGoesQuiet)
{
	ReapBench b;
	ASSERT_FALSE(b.dial("501", "192.168.7.51", "conf-talk").empty());
	b.handler.tick();

	// RTP arrives within every 61 s window: the clock restarts each time, however old it is.
	for (int round = 0; round < 3; ++round)
	{
		b.rtpFrom("conf-talk");
		b.tickAfter("conf-talk", std::chrono::seconds(61));
		ASSERT_TRUE(b.alive("conf-talk")) << "round " << round << ": a talking leg is live";
	}
	EXPECT_EQ(b.handler.getConferenceLegs(), 1);

	// Control: the same leg, now silent, is reaped, so the checks above ran a live watch.
	b.tickAfter("conf-talk", std::chrono::seconds(61));
	EXPECT_FALSE(b.alive("conf-talk"));
}

TEST(ConferenceReap, FourHarnessUasThatDieWithoutByeAreAllReapedAndTheRoomIsReusable)
{
	// The #1003 repro: a harness puts every slot of the room in use and exits without hanging up.
	ReapBench b;
	constexpr int kLegs = ConferenceRoom::MAX_LEGS;
	for (int i = 0; i < kLegs; ++i)
	{
		const std::string num = "61" + std::to_string(i);
		ASSERT_FALSE(b.dial(num, "192.168.7." + std::to_string(60 + i), "conf-dead-" + num).empty());
	}
	ASSERT_EQ(b.handler.getConferenceLegs(), kLegs);
	b.handler.tick();   // arms the watch and refreshes the status snapshot getSessionCount() reads
	ASSERT_EQ(b.handler.getSessionCount(), static_cast<size_t>(kLegs));

	// Each leg has its own counter: one participant still talking does not keep the others up,
	// and its silence is its own, not the room's.
	b.rtpFrom("conf-dead-610");
	for (int i = 0; i < kLegs; ++i) b.session("conf-dead-61" + std::to_string(i))->ageRtpWatchForTest(std::chrono::seconds(61));
	b.tickNow();
	EXPECT_TRUE(b.alive("conf-dead-610")) << "the leg that kept sending stays";
	EXPECT_EQ(b.handler.getConferenceLegs(), 1);
	EXPECT_EQ(b.handler.getSessionCount(), 1u);

	b.tickAfter("conf-dead-610", std::chrono::seconds(61));
	EXPECT_EQ(b.handler.getConferenceLegs(), 0) << "room empty";
	EXPECT_EQ(b.handler.getSessionCount(), 0u) << "sessionCount back to 0";
	for (int i = 0; i < kLegs; ++i)
	{
		EXPECT_EQ(b.handler.conferenceForTest()->legSenderForTest(i)->isActive(), false)
			<< "leg " << i << " must not keep an RTP sender streaming";
	}

	// Nothing leaked: the whole room can be filled again.
	for (int i = 0; i < kLegs; ++i)
	{
		const std::string num = "62" + std::to_string(i);
		EXPECT_FALSE(b.dial(num, "192.168.7." + std::to_string(80 + i), "conf-again-" + num).empty())
			<< "slot " << i << " must be free again after the reap";
	}
	EXPECT_EQ(b.handler.getConferenceLegs(), kLegs);
}

TEST(ConferenceReap, AHeldConferenceLegIsExemptAndTheWatchRestartsWhenItResumes)
{
	// Conference hold is declined (488) so a real leg never reaches Held; this forces the
	// state to pin the shared sweep's exemption for a watched service leg.
	ReapBench b;
	ASSERT_FALSE(b.dial("501", "192.168.7.51", "conf-held").empty());
	b.handler.tick();
	auto s = b.session("conf-held");
	ASSERT_NE(s, nullptr);

	s->setState(Session::State::Held);
	b.tickAfter("conf-held", std::chrono::seconds(61));
	ASSERT_TRUE(b.alive("conf-held")) << "a held leg legitimately sends nothing";

	s->setState(Session::State::Connected);
	b.tickNow();
	ASSERT_TRUE(b.alive("conf-held")) << "resume restarts the watch; it must not fire at once";

	// Control: silent for 61 s after resume, it is reaped.
	b.tickAfter("conf-held", std::chrono::seconds(61));
	EXPECT_FALSE(b.alive("conf-held"));
}

TEST(ConferenceReap, ALegFlaggedEmergencyIsNotReapedAtTheOrdinaryLimit)
{
	// Rule 5: the emergency exemption stays in the shared path. A 911/933 never reaches 888, but a
	// session flagged so (a PSAP callback) is held to the #741 4 h bound, never the 60 s one.
	ReapBench b;
	ASSERT_FALSE(b.dial("501", "192.168.7.51", "conf-911").empty());
	b.handler.tick();
	b.session("conf-911")->setEmergency(true);

	b.tickAfter("conf-911", std::chrono::seconds(61));
	EXPECT_TRUE(b.alive("conf-911")) << "61 s of silence on an emergency session";
	b.tickAfter("conf-911", std::chrono::hours(3));
	EXPECT_TRUE(b.alive("conf-911")) << "3 h of silence on an emergency session";
	EXPECT_EQ(b.handler.getConferenceLegs(), 1);
	EXPECT_TRUE(b.byesTo("192.168.7.51").empty());
}

TEST(ConferenceReap, TheBuildWithoutAConferenceRoomHasNothingToWatchAndDoesNotFault)
{
	// POCKETDIAL_CONFERENCE=0 / SIP_CONSTRAINED leaves _conference null.
	ReapBench b;
	ASSERT_FALSE(b.dial("501", "192.168.7.51", "conf-none").empty());
	b.handler.tick();
	b.handler.dropConferenceForTest();

	b.tickAfter("conf-none", std::chrono::seconds(61));
	EXPECT_TRUE(b.alive("conf-none")) << "no room, so no leg to watch";
}

TEST(ConferenceReap, TheReapedByeKeepsTheURIThePhoneRegistered)
{
	// Rule 1: a Snom 370 answers a BYE to a bare sip:ext@ip:port with 404/481 when it registered ;line=.
	ReapBench b;
	const std::string reg =
		"REGISTER sip:server SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.7.51:5060;branch=z9hG4bKrline\r\n"
		"From: <sip:501@server>;tag=rtline\r\n"
		"To: <sip:501@server>\r\n"
		"Call-ID: reg-line\r\n"
		"CSeq: 1 REGISTER\r\n"
		"Contact: <sip:501@192.168.7.51:5060;line=2>;expires=3600\r\n"
		"Content-Length: 0\r\n\r\n";
	b.handler.handle(RequestsHandler::getMessageFromPool(reg, addrFor("192.168.7.51")));
	b.handler.handle(makeInvite("501", ConferenceRoom::EXT, "192.168.7.51", "conf-line"));
	ASSERT_EQ(b.handler.getConferenceLegs(), 1);
	b.handler.tick();

	b.tickAfter("conf-line", std::chrono::seconds(61));

	const auto byes = b.byesTo("192.168.7.51");
	ASSERT_EQ(byes.size(), 1u);
	EXPECT_EQ(byes[0].rfind("BYE sip:501@192.168.7.51:5060;line=2 SIP/2.0", 0), 0u) << byes[0];
}

// ── Not reaped: service legs with no board-side receive path (green on main, by design) ──

TEST(ConferenceReap, TheEchoTestHasNoBoardMediaToWatchAndIsNeverReapedForRxSilence)
{
	// 777 answers with the caller's own SDP: the phone streams to itself and the board sees no RTP.
	ReapBench b;
	ASSERT_FALSE(b.dial("501", "192.168.7.51", "echo-1003", "777").empty());
	b.handler.tick();

	b.tickAfter("echo-1003", std::chrono::seconds(61));

	EXPECT_TRUE(b.alive("echo-1003")) << "a watch here would hang up every echo test at 60 s";
}

TEST(ConferenceReap, TheToneCallIsSendonlyAndIsNeverReapedForRxSilence)
{
	// 440 answers a=sendonly: the phone is told to send nothing, so silence is the healthy state.
	ReapBench b;
	ASSERT_FALSE(b.dial("501", "192.168.7.51", "tone-1003", "440").empty());
	b.handler.tick();

	b.tickAfter("tone-1003", std::chrono::seconds(61));

	EXPECT_TRUE(b.alive("tone-1003")) << "a watch here would hang up every 440 call at 60 s";
}

TEST(ConferenceReap, AParkedCallIsSendonlyHoldMusicAndIsLeftToTheParkTimeout)
{
	// The parked leg is Connected (not Held) but the phone is told to send nothing; park has its
	// own bound (POCKETDIAL_PARK_TIMEOUT_SEC, then ring-back).
	ReapBench b;
	ASSERT_FALSE(b.dial("501", "192.168.7.51", "park-1003", "700").empty());
	b.handler.tick();
	ASSERT_TRUE(b.alive("park-1003"));
	ASSERT_EQ(b.session("park-1003")->getState(), Session::State::Connected);

	b.tickAfter("park-1003", std::chrono::seconds(61));

	EXPECT_TRUE(b.alive("park-1003")) << "a watch here would take the call off the orbit at 60 s, ahead of the park timeout";
}

// ── Issue #1003: a 440 tone call is bounded at 10 minutes (desmo's ruling, 2026-10-19) ──
//
// 440 is answered a=sendonly, so a healthy phone sends the board nothing and rx silence cannot tell a
// dead phone from a listener (the ConferenceReap tests above pin that it is never reaped for it). A phone
// that vanished without a BYE therefore kept the tone streaming at 50 packets/s to a dead port and held
// the board's one RtpSender slot, so every other 440 caller got 486 until the registration lease ran out.
// The ruling is a hard maximum duration of 600 s, which ends even a healthy long listener's call.
//
// The clock is the #604 watch's: it starts at the first tick that sees the leg Connected, and
// ageRtpWatchForTest() moves it, as in ConferenceReap. Real milliseconds pass between the arming tick and
// the aged one, so the boundary test keeps 5 s clear of 600 rather than sit on it.
namespace
{
	// True when what the board just sent includes a 486 Busy Here (the 440 stream slot is held).
	bool sentBusy(const ReapBench& b)
	{
		for (const auto& [addr, msg] : b.sent)
		{
			(void)addr;
			if (msg && msg->toString().rfind("SIP/2.0 486", 0) == 0) return true;
		}
		return false;
	}
}

TEST(ToneCallCap, A440CallPastTenMinutesIsEndedAndTheStreamSlotGoesToTheNextCaller)
{
	ReapBench b;
	ASSERT_FALSE(b.dial("501", "192.168.7.51", "tone-cap", "440").empty()) << "precondition: 501 has the tone";
	b.handler.tick();   // arms the clock

	// The orphan's cost, pinned first: while the call holds the one stream slot, a second caller is refused.
	EXPECT_TRUE(b.dial("502", "192.168.7.52", "tone-busy", "440").empty());
	EXPECT_TRUE(sentBusy(b)) << "a second 440 caller gets 486 while the first holds the stream";

	b.tickAfter("tone-cap", std::chrono::seconds(601));

	EXPECT_FALSE(b.alive("tone-cap")) << "601 s into a tone call: the 600 s cap ends it, phone gone or not";
	EXPECT_EQ(b.handler.getSessionCount(), 0u);

	const std::string again = b.dial("502", "192.168.7.52", "tone-again", "440");
	EXPECT_FALSE(again.empty()) << "the stream slot is free again: the next 440 caller is answered 200";
	EXPECT_TRUE(b.alive("tone-again"));
}

TEST(ToneCallCap, TheEndedToneCallIsToldByAByeFromOurSideOfTheDialogAndRecordedAs440)
{
	ReapBench b;
	const std::string answer = b.dial("501", "192.168.7.51", "tone-bye", "440");
	ASSERT_FALSE(answer.empty()) << "precondition: 501 has the tone";
	b.handler.tick();

	b.tickAfter("tone-bye", std::chrono::seconds(601));

	// A listener whose call the cap ends must be told, once, or its phone sits on a dead call.
	const auto byes = b.byesTo("192.168.7.51");
	ASSERT_EQ(byes.size(), 1u) << "exactly one BYE to the phone that was on the tone";
	EXPECT_EQ(byes[0].rfind("BYE sip:501@192.168.7.51:5060 SIP/2.0", 0), 0u) << byes[0];
	EXPECT_NE(byes[0].find("Call-ID: tone-bye"), std::string::npos);
	EXPECT_EQ(headerValue(byes[0], "From"), headerValue(answer, "To"))
		<< "the BYE is from the PBX end of the dialog: the 200 OK's To, with our tag";
	EXPECT_EQ(headerValue(byes[0], "To"), "<sip:501@server>;tag=fttone-bye")
		<< "and to the phone's own From, with its tag";

	// The CDR names the number dialed, as a BYE-ended 440 call's does.
	bool recorded = false;
	for (const auto& rec : b.handler.cdrSnapshotForTest())
	{
		if (rec.caller == "501" && rec.callee == "440") recorded = true;
	}
	EXPECT_TRUE(recorded) << "CDR 501 -> 440";
}

TEST(ToneCallCap, A440CallJustUnderTenMinutesStaysAndTheStreamStaysHeld)
{
	ReapBench b;
	ASSERT_FALSE(b.dial("501", "192.168.7.51", "tone-under", "440").empty());
	b.handler.tick();

	b.tickAfter("tone-under", std::chrono::seconds(595));

	ASSERT_TRUE(b.alive("tone-under")) << "595 s is inside the 600 s cap";
	EXPECT_TRUE(b.byesTo("192.168.7.51").empty());
	EXPECT_TRUE(b.dial("502", "192.168.7.52", "tone-busy-2", "440").empty());
	EXPECT_TRUE(sentBusy(b)) << "still one stream: the second caller is still refused";

	// Control: 6 s later the same call is over, so the checks above ran a live cap.
	b.tickAfter("tone-under", std::chrono::seconds(6));
	EXPECT_FALSE(b.alive("tone-under"));
}

TEST(ToneCallCap, TheCapIsThe440sAloneAnEchoTestAndATalkingConferenceLegPastTenMinutesStay)
{
	ReapBench b;
	ASSERT_FALSE(b.dial("501", "192.168.7.51", "mix-tone", "440").empty());
	ASSERT_FALSE(b.dial("502", "192.168.7.52", "mix-echo", "777").empty());
	ASSERT_FALSE(b.dial("503", "192.168.7.53", "mix-conf").empty());   // 888
	b.handler.tick();

	// The conference leg keeps talking, so its own 60 s rule keeps restarting; the echo test has no
	// board-side watch at all. Only the tone call is over 600 s old in a way the cap counts.
	b.rtpFrom("mix-conf");
	for (const char* id : {"mix-tone", "mix-echo", "mix-conf"})
	{
		b.session(id)->ageRtpWatchForTest(std::chrono::seconds(601));
	}
	b.tickNow();

	EXPECT_FALSE(b.alive("mix-tone")) << "the tone call is over the cap";
	EXPECT_TRUE(b.alive("mix-echo")) << "777 has no stream and no cap";
	EXPECT_TRUE(b.alive("mix-conf")) << "a conference leg that is still talking is not a tone call";
	EXPECT_EQ(b.handler.getConferenceLegs(), 1);
	EXPECT_TRUE(b.byesTo("192.168.7.52").empty());
	EXPECT_TRUE(b.byesTo("192.168.7.53").empty());
}

TEST(ToneCallCap, ASessionFlaggedEmergencyIsNeverCappedAtTenMinutes)
{
	// Rule 5: the emergency exemption stays in the shared path. A 911/933 never reaches 440, but a session
	// flagged so is never cut by a limit meant for the tone.
	ReapBench b;
	ASSERT_FALSE(b.dial("501", "192.168.7.51", "tone-911", "440").empty());
	b.handler.tick();
	auto s = b.session("tone-911");
	ASSERT_NE(s, nullptr);
	s->setEmergency(true);

	b.tickAfter("tone-911", std::chrono::seconds(601));

	EXPECT_TRUE(b.alive("tone-911")) << "601 s on an emergency-flagged session";
	EXPECT_TRUE(b.byesTo("192.168.7.51").empty());

	// Control: the same clock, flag cleared, ends it.
	s->setEmergency(false);
	b.tickNow();
	EXPECT_FALSE(b.alive("tone-911"));
}

TEST(ToneCallCap, AHeldToneCallIsExemptAndTheClockRestartsWhenItResumes)
{
	// A real 440 leg never reaches Held (its hold re-INVITE is declined, 488); this forces the state to pin
	// the shared sweep's exemption, as the 888 test does.
	ReapBench b;
	ASSERT_FALSE(b.dial("501", "192.168.7.51", "tone-held", "440").empty());
	b.handler.tick();
	auto s = b.session("tone-held");
	ASSERT_NE(s, nullptr);

	s->setState(Session::State::Held);
	b.tickAfter("tone-held", std::chrono::seconds(601));
	ASSERT_TRUE(b.alive("tone-held")) << "a held call is outside the cap";

	s->setState(Session::State::Connected);
	b.tickNow();
	ASSERT_TRUE(b.alive("tone-held")) << "resume restarts the clock; it must not fire at once";

	// Control: 601 s after resume it is over.
	b.tickAfter("tone-held", std::chrono::seconds(601));
	EXPECT_FALSE(b.alive("tone-held"));
}

// *11 and *69 pressed over SIP INFO repoint a live call's dest at a virtual 777 peer (DtmfFeatureCodes.cpp),
// and the tone stream goes on holding the one RtpSender slot. The dest number is therefore not a tone call's
// identity; the call has to be marked as one when it is answered.
namespace
{
	// One DTMF digit as a SIP INFO from the phone on this dialog. `n` numbers the INFO: its CSeq counts up
	// from the INVITE's and its branch is its own, so no two digits look like a retransmission.
	std::shared_ptr<SipMessage> makeInfoDigit(const std::string& ext, const std::string& ip,
		const std::string& callId, char digit, int n)
	{
		const std::string body = std::string("Signal=") + digit + "\r\nDuration=100\r\n";
		std::string raw =
			"INFO sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKd" + callId + std::to_string(n) + "\r\n"
			"From: <sip:" + ext + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: " + std::to_string(1 + n) + " INFO\r\n"
			"Content-Type: application/dtmf-relay\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}
}

TEST(ToneCallCap, A440CallThatPressedStar11IsStillEndedAtTenMinutes)
{
	ReapBench b;
	ASSERT_FALSE(b.dial("501", "192.168.7.51", "tone-s11", "440").empty());
	b.handler.tick();

	int n = 1;
	for (const char digit : std::string("*11")) b.handler.handle(makeInfoDigit("501", "192.168.7.51", "tone-s11", digit, n++));

	auto s = b.session("tone-s11");
	ASSERT_NE(s, nullptr);
	ASSERT_TRUE(s->getDest());
	ASSERT_EQ(s->getDest()->getNumber(), "777") << "precondition: *11 moved the call's destination to the virtual echo peer";
	b.sent.clear();
	ASSERT_TRUE(b.dial("502", "192.168.7.52", "tone-s11-busy", "440").empty());
	ASSERT_TRUE(sentBusy(b)) << "precondition: the tone stream still holds the one slot";

	b.tickAfter("tone-s11", std::chrono::seconds(601));

	EXPECT_FALSE(b.alive("tone-s11")) << "601 s into a tone call that pressed *11: the cap still ends it";
	EXPECT_EQ(b.byesTo("192.168.7.51").size(), 1u) << "and tells the phone";
	EXPECT_FALSE(b.dial("502", "192.168.7.52", "tone-s11-again", "440").empty())
		<< "the stream slot is free again";
}

// #1123: a conference leg has no spliced peer; an admin kill BYEs the extension
// once on its own dialog, never a stand-in, and leaves the other legs alone.
TEST(ConferenceRoom, AnAdminKillByesOnlyTheKilledLegOnceAndLeavesTheRest)
{
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler("192.168.7.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});
	handler.handle(makeRegister("501", "192.168.7.51", "reg-501"));
	handler.handle(makeRegister("502", "192.168.7.52", "reg-502"));
	handler.handle(makeRegister("503", "192.168.7.53", "reg-503"));
	const std::string ext(ConferenceRoom::EXT);
	handler.handle(makeInvite("501", ext, "192.168.7.51", "conf-501"));
	handler.handle(makeInvite("502", ext, "192.168.7.52", "conf-502"));
	handler.handle(makeInvite("503", ext, "192.168.7.53", "conf-503"));
	ASSERT_EQ(handler.getConferenceLegs(), 3);
	sent.clear();
	ASSERT_TRUE(handler.forceDisconnect("502"));
	handler.handle(makeBye("probe", ext, "192.168.7.99", "flush-1123"));   // next SIP-thread pass
	size_t byes = 0, toKilled = 0;
	for (const auto& [addr, msg] : sent)
	{
		if (!msg) continue;
		const std::string raw = msg->toString();
		if (raw.rfind("BYE ", 0) != 0 || raw.find("Call-ID: conf-502\r\n") == std::string::npos) continue;
		++byes;
		if (addr.sin_addr.s_addr == inet_addr("192.168.7.52")) ++toKilled;
	}
	EXPECT_EQ(byes, 1u);
	EXPECT_EQ(toKilled, 1u);
	EXPECT_EQ(handler.getConferenceLegs(), 2);
	EXPECT_FALSE(handler.getSession("Call-ID: conf-502").has_value());
	EXPECT_TRUE(handler.getSession("Call-ID: conf-501").has_value());
	EXPECT_TRUE(handler.getSession("Call-ID: conf-503").has_value());
}
