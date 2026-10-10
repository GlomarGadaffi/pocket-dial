// RingPin_test.cpp -- #946 option A: every per-call jitter ring is allocated once, when its
// owner is built at boot, and a call only clears it. No production change; this pins what
// main already does (docs/design/ring-pool.md sections 0-2 and 8).
//
// Owners of a PlayoutBuffer ring, by grep of src/ and main/: MediaBridge (one, by value),
// MixBus::Port (two, `in` and `out`), and nothing else. Owners of those: the
// MediaBridge _mediaBridges[POCKETDIAL_MAX_ANCHOR_CALLS] member of RequestsHandler, and
// ConferenceRoom (one bridge per leg plus the bus), which RequestsHandler builds once in its
// constructor. A ring is one std::vector resize in PlayoutBuffer's constructor and is never
// resized, assigned or reserved again.
//
// What AllocCounter can and cannot see here. A call's startBridge() is not allocation-free on a
// Linux host: RtpSender::start() spawns the pacer std::thread, whose state libstdc++ allocates on
// the calling thread (MediaBridge_test.cpp's header, issue #82). So the start of a call is pinned
// as "costs exactly what starting its RtpReceiver and RtpSender costs on their own"; the
// use of the ring, the stop, and the whole MixBus lifecycle are pinned at zero.
//
// Not covered, because it needs a counting seam in src/Helpers/PsramAllocator.hpp (a production
// change): a RequestsHandler that builds a MediaBridge or ConferenceRoom per call instead of
// using its members. That would pass this file; the construction-site grep above is the guard.

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "ConferenceRoom.hpp"
#include "LoopbackAnchorClient.hpp"
#include "MediaBridge.hpp"
#include "MixBus.hpp"
#include "PlayoutBuffer.hpp"
#include "PoolConfig.hpp"
#include "RtpReceiver.hpp"
#include "RtpSender.hpp"
#include "support/AllocCounter.hpp"

namespace
{
	// PlayoutBuffer's default: 1600 samples (200 ms @ 8 kHz), the only size production uses.
	constexpr std::size_t kRingBytes = 1600 * sizeof(int16_t);
	// The allocator may round a block up; a second buffer would be 3,200 B more.
	constexpr std::size_t kRoundingSlack = 64;

	// MSVC's checked iterators (_ITERATOR_DEBUG_LEVEL > 0, the Debug default) allocate a proxy per
	// std::vector, which the counting operator new sees. The exact constructor counts below
	// describe a build without them; the no-allocation assertions hold either way.
#if defined(_MSC_VER) && defined(_ITERATOR_DEBUG_LEVEL) && _ITERATOR_DEBUG_LEVEL > 0
	constexpr bool kExactCtorCounts = false;
#else
	constexpr bool kExactCtorCounts = true;
#endif

	// Where the ring's samples live. PlayoutBuffer has no accessor, and adding one is a production
	// change, so read the first member: libstdc++ keeps a vector's begin pointer at offset 0 and
	// PlayoutBuffer declares its vector first. RingPin.TheStorageProbeSeesTheLiveRing checks that
	// against a written sample, so a layout change fails loudly instead of comparing nullptr.
	// Other standard libraries get nullptr and the address checks compare equal: the allocation
	// counts carry the pin there.
	const int16_t* ringStorage(PlayoutBuffer& rb)
	{
#if defined(__GLIBCXX__)
		const int16_t* p = nullptr;
		std::memcpy(&p, static_cast<const void*>(&rb), sizeof p);
		return p;
#else
		(void)rb;
		return nullptr;
#endif
	}

	// The Linux pacer pops the bridge's ring from its own thread; stopping it first is the
	// existing convention for any test that reads the ring (MediaBridge_test.cpp, issue #135).
	constexpr const char* kIp = "127.0.0.1";
	constexpr const char* kCall = "call-1";
	constexpr const char* kPart = "part-1";

	// What RtpReceiver::start + RtpSender::start allocate with no bridge in the way. Lambdas
	// capture one pointer, as MediaBridge's do, so std::function takes the same storage path.
	std::size_t endpointStartCost(RtpReceiver& rx, RtpSender& tx)
	{
		AllocGuard g;
		const bool rxOk = rx.start(0, [p = &rx](const uint8_t*, std::size_t, uint32_t, uint16_t) { (void)p; });
		const bool txOk = tx.start(kIp, 5004, kCall, [p = &tx](uint8_t*, std::size_t) { (void)p; return false; });
		const std::size_t n = g.delta();
		EXPECT_TRUE(rxOk);
		EXPECT_TRUE(txOk);
		tx.stop(kCall);
		rx.stop();
		return n;
	}

	struct CallCost { std::size_t start, use, stop; };

	// One call on `b`: start it, halt the pacer, move audio through the ring (the MixBus rings in
	// BUS mode), stop it and, in BUS mode, tick once so the bus reclaims the port.
	CallCost callCycle(MediaBridge& b, RtpSender& tx, MixBus* bus)
	{
		CallCost c{};
		{
			AllocGuard g;
			EXPECT_TRUE(b.startBridge(kIp, 5004, kCall, kPart));
			c.start = g.delta();
		}
		EXPECT_TRUE(tx.stop(kCall));

		int16_t pcm[MixBus::FRAME];
		for (int i = 0; i < MixBus::FRAME; ++i) pcm[i] = static_cast<int16_t>(i * 7 - 500);
		uint8_t ulaw[MixBus::FRAME];
		{
			AllocGuard g;
			if (bus)
			{
				bus->inputFrame(b.busPort(), pcm, MixBus::FRAME);
				bus->tick();
			}
			else
			{
				b.feedRx(kPart, pcm, MixBus::FRAME);
				b.feedRx(kPart, pcm, MixBus::FRAME);
			}
			b.fillHandsetTx(ulaw, MixBus::FRAME);
			c.use = g.delta();
		}
		{
			AllocGuard g;
			b.stopBridge();
			if (bus) bus->tick();
			c.stop = g.delta();
		}
		return c;
	}
}

// ── What each owner holds, taken in its constructor ───────────────────────────

// Owners are built on the stack, so the counts are the rings and nothing else (a heap owner adds
// its own block). Each is used afterwards so -O3 cannot drop the construction.

TEST(RingPin, ARingIsOneBlockOf3200BytesTakenInTheConstructor)
{
	const std::size_t blocks0 = heapLiveBlocks(), bytes0 = heapLiveBytes();
	AllocGuard g;
	PlayoutBuffer ring;
	if (kExactCtorCounts) EXPECT_EQ(g.delta(), 1u);
	if (kExactCtorCounts && heapLiveTracked())
	{
		EXPECT_EQ(heapLiveBlocks() - blocks0, 1u);
		EXPECT_GE(heapLiveBytes() - bytes0, kRingBytes);
		EXPECT_LT(heapLiveBytes() - bytes0, kRingBytes + kRoundingSlack);
	}
	EXPECT_EQ(ring.getLength(), 0u);
}

TEST(RingPin, AMediaBridgeHoldsExactlyOneRing)
{
	const std::size_t blocks0 = heapLiveBlocks(), bytes0 = heapLiveBytes();
	AllocGuard g;
	MediaBridge bridge;
	if (kExactCtorCounts) EXPECT_EQ(g.delta(), 1u);
	if (kExactCtorCounts && heapLiveTracked())
	{
		EXPECT_EQ(heapLiveBlocks() - blocks0, 1u);
		EXPECT_GE(heapLiveBytes() - bytes0, kRingBytes);
		EXPECT_LT(heapLiveBytes() - bytes0, kRingBytes + kRoundingSlack);
	}
	EXPECT_EQ(bridge.getPlayoutBuffer().getLength(), 0u);

	RtpReceiver rx;
	RtpSender tx;
	LoopbackAnchorClient anchor;
	AllocGuard wiring;
	bridge.init(&rx, &tx, &anchor);
	EXPECT_EQ(wiring.delta(), 0u) << "init() wires pointers; it does not touch the ring";
}

TEST(RingPin, AMixBusHoldsTwoRingsPerPort)
{
	const std::size_t blocks0 = heapLiveBlocks(), bytes0 = heapLiveBytes();
	AllocGuard g;
	MixBus bus;
	if (kExactCtorCounts) EXPECT_EQ(g.delta(), 2u * MixBus::MAX_PORTS);
	if (kExactCtorCounts && heapLiveTracked())
	{
		EXPECT_EQ(heapLiveBlocks() - blocks0, 2u * MixBus::MAX_PORTS);
		EXPECT_GE(heapLiveBytes() - bytes0, 2u * MixBus::MAX_PORTS * kRingBytes);
		EXPECT_LT(heapLiveBytes() - bytes0, 2u * MixBus::MAX_PORTS * (kRingBytes + kRoundingSlack));
	}
	EXPECT_EQ(bus.activePorts(), 0);
}

TEST(RingPin, AConferenceRoomHoldsOneRingPerLegPlusTwoPerBusPort)
{
	AllocGuard g;
	ConferenceRoom room;
	if (kExactCtorCounts) EXPECT_EQ(g.delta(), ConferenceRoom::MAX_LEGS + 2u * MixBus::MAX_PORTS);
	EXPECT_EQ(room.legCount(), 0);
}

// The totals the design doc quotes, from the constants that produce them. A pool-size change
// lands here by name, so it is a decision rather than a side effect.
TEST(RingPin, TheS3DefaultHoldsSixteenRings)
{
	EXPECT_EQ(POCKETDIAL_MAX_ANCHOR_CALLS, 4);
	EXPECT_EQ(POCKETDIAL_CONF_LEGS, 4);
	EXPECT_EQ(POCKETDIAL_CONFERENCE, 1);
	EXPECT_EQ(MixBus::MAX_PORTS, POCKETDIAL_CONF_LEGS);
	EXPECT_EQ(ConferenceRoom::MAX_LEGS, POCKETDIAL_CONF_LEGS);

	const int anchorBridges = POCKETDIAL_MAX_ANCHOR_CALLS;
	const int legBridges = ConferenceRoom::MAX_LEGS;
	const int busRings = 2 * MixBus::MAX_PORTS;
	EXPECT_EQ(anchorBridges + legBridges + busRings, 16);
	EXPECT_EQ((anchorBridges + legBridges + busRings) * kRingBytes, 51200u);
}

// ── A ring in use is neither allocated nor moved ──────────────────────────────

TEST(RingPin, TheStorageProbeSeesTheLiveRing)
{
#if defined(__GLIBCXX__)
	PlayoutBuffer rb(8);
	const int16_t v = 0x1234;
	ASSERT_EQ(rb.write(&v, 1), 1u);
	const int16_t* p = ringStorage(rb);
	ASSERT_NE(p, nullptr);
	EXPECT_EQ(p[0], v) << "the first word of a PlayoutBuffer is no longer its vector's begin pointer";
#else
	GTEST_SUCCEED() << "address probe is libstdc++-only; the allocation counts pin the ring elsewhere";
#endif
}

TEST(RingPin, UsingARingNeverAllocatesAndNeverMovesIt)
{
	PlayoutBuffer rb;
	const int16_t* const home = ringStorage(rb);
	int16_t in[400], out[400];
	for (int i = 0; i < 400; ++i) in[i] = static_cast<int16_t>(i - 200);

	AllocGuard g;
	for (int cycle = 0; cycle < 50; ++cycle)
	{
		rb.clear();
		ASSERT_EQ(ringStorage(rb), home) << "cycle " << cycle << ": clear() must wipe in place";
		rb.setTargetDepth(160);
		for (int k = 0; k < 8; ++k) rb.write(in, 400);   // 8 x 400 > 1600: the overrun path
		rb.read(out, 400);
		rb.read(out, 400);
		rb.clear();
		rb.read(out, 160);                                // the underrun path
		rb.getLength();
	}
	EXPECT_EQ(g.delta(), 0u);
	EXPECT_EQ(ringStorage(rb), home);
}

TEST(RingPin, MixBusPortChurnAllocatesNothing)
{
	MixBus bus;
	int16_t pcm[MixBus::FRAME], out[MixBus::FRAME];
	for (int i = 0; i < MixBus::FRAME; ++i) pcm[i] = static_cast<int16_t>(i * 5);
	for (int i = 0; i < 3; ++i) { bus.attach(); bus.tick(); }   // warm up
	for (int p = 0; p < MixBus::MAX_PORTS; ++p) bus.detach(p);
	bus.tick();

	const std::size_t blocks0 = heapLiveBlocks(), bytes0 = heapLiveBytes();
	AllocGuard g;
	for (int cycle = 0; cycle < 50; ++cycle)
	{
		const int a = bus.attach();
		const int b = bus.attach();
		ASSERT_GE(a, 0);
		ASSERT_GE(b, 0);
		bus.inputFrame(a, pcm, MixBus::FRAME);
		bus.inputFrame(b, pcm, MixBus::FRAME);
		bus.tick();
		bus.outputFrame(a, out, MixBus::FRAME);
		bus.detach(a);
		bus.detach(b);
		bus.tick();
		ASSERT_EQ(bus.activePorts(), 0);
	}
	EXPECT_EQ(g.delta(), 0u);
	EXPECT_EQ(heapLiveBlocks(), blocks0);
	EXPECT_EQ(heapLiveBytes(), bytes0);
}

TEST(RingPin, AnchorCallCyclesAddNothingToTheirRtpEndpoints)
{
	RtpReceiver rx;
	RtpSender tx;
	LoopbackAnchorClient anchor;   // never started: the bridge only needs a non-null anchor
	MediaBridge bridge;
	bridge.init(&rx, &tx, &anchor);
	const int16_t* const home = ringStorage(bridge.getPlayoutBuffer());

	for (int i = 0; i < 2; ++i) { endpointStartCost(rx, tx); callCycle(bridge, tx, nullptr); }   // warm up
	const std::size_t endpoints = endpointStartCost(rx, tx);
	RecordProperty("endpoint_start_allocs", static_cast<int>(endpoints));

	const std::size_t blocks0 = heapLiveBlocks(), bytes0 = heapLiveBytes();
	for (int cycle = 0; cycle < 5; ++cycle)
	{
		const CallCost c = callCycle(bridge, tx, nullptr);
		EXPECT_EQ(c.start, endpoints) << "cycle " << cycle << ": startBridge must cost what its RTP endpoints cost";
		EXPECT_EQ(c.use, 0u) << "cycle " << cycle;
		EXPECT_EQ(c.stop, 0u) << "cycle " << cycle;
		EXPECT_EQ(ringStorage(bridge.getPlayoutBuffer()), home) << "cycle " << cycle;
	}
	EXPECT_EQ(heapLiveBlocks(), blocks0);
	EXPECT_EQ(heapLiveBytes(), bytes0);
}

TEST(RingPin, BusCallCyclesAddNothingToTheirRtpEndpoints)
{
	RtpReceiver rx;
	RtpSender tx;
	MixBus bus;
	MediaBridge bridge;
	bridge.init(&rx, &tx, nullptr, &bus);

	for (int i = 0; i < 2; ++i) { endpointStartCost(rx, tx); callCycle(bridge, tx, &bus); }   // warm up
	const std::size_t endpoints = endpointStartCost(rx, tx);
	RecordProperty("endpoint_start_allocs", static_cast<int>(endpoints));

	const std::size_t blocks0 = heapLiveBlocks(), bytes0 = heapLiveBytes();
	for (int cycle = 0; cycle < 5; ++cycle)
	{
		const CallCost c = callCycle(bridge, tx, &bus);
		EXPECT_EQ(c.start, endpoints) << "cycle " << cycle << ": a BUS-mode start attaches a port; it must not allocate one";
		EXPECT_EQ(c.use, 0u) << "cycle " << cycle;
		EXPECT_EQ(c.stop, 0u) << "cycle " << cycle;
		EXPECT_EQ(bus.activePorts(), 0) << "cycle " << cycle << ": the tick reclaimed the port";
	}
	EXPECT_EQ(heapLiveBlocks(), blocks0);
	EXPECT_EQ(heapLiveBytes(), bytes0);
}
