// PsramPlacement_test.cpp — issue #466 (#284 batch E): where the big blocks live.
//
// What is host-testable of a PSRAM/internal-DRAM change is the POLICY and the
// race logic; which region a pointer actually lands in is only visible on the
// device (#451's .244 measurement, and /api/status's memory counters):
//
//   1. CLIP PLACEMENT (Sonny-OG's decision on #466): PSRAM builds put a MoH
//      clip / voicemail greeting in PSRAM only -- never internal; builds with
//      no PSRAM hold it internally only up to POCKETDIAL_CLIP_INTERNAL_MAX_BYTES
//      and refuse above it. Mutation-checked: letting a PSRAM build fall back
//      to internal, or dropping the cap, fails it.
//   2. DmaFramePool's init used to xQueueCreate() INSIDE portENTER_CRITICAL.
//      It now builds the queue with no lock held and publishes it once
//      (detail::publishOnce); a racing loser destroys its own copy. Pinned
//      here with real threads: exactly one survives, nothing leaks, every
//      caller sees the same one. Mutation-checked: not destroying the loser
//      fails it.
//   3. PsramAllocator (PlayoutBuffer's storage: the conference's 64 KB of
//      rings and every MediaBridge ring) round-trips on the host through
//      operator new, so tests/support/AllocCounter still sees it.

#include <gtest/gtest.h>

#include <atomic>
#include <thread>
#include <vector>

#include "AllocCounter.hpp"
#include "DmaFramePool.hpp"
#include "HoldMusic.hpp"
#include "PlayoutBuffer.hpp"
#include "PoolConfig.hpp"
#include "PsramAllocator.hpp"

using Placement = HoldMusic::ClipPlacement;

TEST(ClipPlacement, PsramBuildsAreAlwaysPsramNeverInternal)
{
	for (size_t bytes : { size_t{1}, size_t{16384}, size_t{16385}, size_t{8u << 20} })
		EXPECT_EQ(HoldMusic::clipPlacement(bytes, /*havePsram=*/true, 16384), Placement::Psram) << bytes;
}

TEST(ClipPlacement, NoPsramBuildsHoldInternallyOnlyUpToTheCap)
{
	const size_t cap = POCKETDIAL_CLIP_INTERNAL_MAX_BYTES;
	EXPECT_EQ(cap, 16384u) << "the decision's starting value (#466)";
	EXPECT_EQ(HoldMusic::clipPlacement(1, false, cap), Placement::Internal);
	EXPECT_EQ(HoldMusic::clipPlacement(cap, false, cap), Placement::Internal) << "the cap itself fits";
	EXPECT_EQ(HoldMusic::clipPlacement(cap + 1, false, cap), Placement::RefusedOverCap);
	EXPECT_EQ(HoldMusic::clipPlacement(8u << 20, false, cap), Placement::RefusedOverCap);
}

TEST(PublishOnce, RacingInitialisersLeaveExactlyOneAndLeakNothing)
{
	for (int round = 0; round < 50; ++round)
	{
		std::atomic<int*> slot{nullptr};
		std::atomic<int> made{0}, destroyed{0};
		constexpr int kThreads = 8;
		std::vector<int*> seen(kThreads, nullptr);
		std::atomic<bool> go{false};
		std::vector<std::thread> ts;
		for (int t = 0; t < kThreads; ++t)
			ts.emplace_back([&, t] {
				while (!go.load(std::memory_order_acquire)) {}
				seen[t] = l2rtp::detail::publishOnce(slot,
					[&] { ++made; return new int(t); },
					[&](int* p) { ++destroyed; delete p; });
			});
		go.store(true, std::memory_order_release);
		for (auto& th : ts) th.join();

		ASSERT_NE(slot.load(), nullptr);
		EXPECT_EQ(made.load() - destroyed.load(), 1) << "round " << round << ": exactly one survives";
		for (int t = 0; t < kThreads; ++t)
			EXPECT_EQ(seen[t], slot.load()) << "every caller gets the published one";
		delete slot.load();
	}
}

TEST(PublishOnce, AFailedMakeLeavesTheSlotEmptyForALaterSuccess)
{
	std::atomic<int*> slot{nullptr};
	EXPECT_EQ(l2rtp::detail::publishOnce(slot, [] { return static_cast<int*>(nullptr); },
	                                     [](int* p) { delete p; }), nullptr);
	EXPECT_EQ(slot.load(), nullptr);
	int* got = l2rtp::detail::publishOnce(slot, [] { return new int(7); }, [](int* p) { delete p; });
	ASSERT_NE(got, nullptr);
	EXPECT_EQ(*got, 7);
	// Published: a later call returns it without making another.
	int makes = 0;
	EXPECT_EQ(l2rtp::detail::publishOnce(slot, [&] { ++makes; return new int(9); },
	                                     [](int* p) { delete p; }), got);
	EXPECT_EQ(makes, 0);
	delete got;
}

TEST(PsramAllocatorHost, RoundTripsThroughOperatorNewAndNeverCountsAFallback)
{
	const uint32_t fallbacks = psram::internalFallbacks().load();
	{
		AllocGuard g;
		std::vector<int16_t, PsramAllocator<int16_t>> v(1600, 0);
		ASSERT_EQ(v.size(), 1600u);
		for (int16_t s : v) ASSERT_EQ(s, 0);
		EXPECT_GE(g.delta(), 1u) << "host storage goes through the counted operator new";
	}
	// A PlayoutBuffer built on it behaves as before.
	PlayoutBuffer pb(1600);
	int16_t in[160], out[160];
	for (int i = 0; i < 160; ++i) in[i] = static_cast<int16_t>(i * 3);
	pb.setTargetDepth(160);
	EXPECT_EQ(pb.write(in, 160), 160u);
	EXPECT_TRUE(pb.read(out, 160));
	for (int i = 0; i < 160; ++i) EXPECT_EQ(out[i], in[i]) << i;
	EXPECT_EQ(psram::internalFallbacks().load(), fallbacks) << "no PSRAM on the host, so no fallbacks";
}
