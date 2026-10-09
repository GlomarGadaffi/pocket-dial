// Repacketizer_test.cpp -- Issue #170: a leg that is not at 20 ms is reframed to
// the mixer's 160-sample frame before it reaches the port's input ring.
//
// Two halves. The pure Repacketizer (src/SIP/Repacketizer.hpp) first: golden
// frames for 10/20/30 ms inputs, the carried remainder, the drop-oldest overrun
// and its counter, and the fixed-size bound. Then the MixBus wiring: a 10 ms leg
// heard contiguously, mixed sizes never reordered (the routing condition is
// sticky while a remainder is carried), a reused port never replaying the
// previous leg's remainder, and the per-port overrun count.
//
// MixBus_test.cpp's ALegAt30msPtimeLosesNoSamples (#170, the tick guard) is
// deliberately untouched: it must keep passing with the repacketizer in front.

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <type_traits>
#include <vector>

#include "MixBus.hpp"
#include "Repacketizer.hpp"
#include "support/AllocCounter.hpp"

namespace
{
	constexpr size_t FRAME = Repacketizer::FRAME;

	// Sample k of a test stream is 1000 + k: a strictly rising, never-zero ramp, so a
	// lost, repeated or reordered sample shows as a value in the wrong place. (Never
	// zero also lets the MixBus tests tell a real frame from the silence of a late leg.)
	std::vector<int16_t> ramp(size_t first, size_t n, int base = 1000)
	{
		std::vector<int16_t> v(n);
		for (size_t i = 0; i < n; ++i) v[i] = static_cast<int16_t>(base + static_cast<int>(first + i));
		return v;
	}

	std::vector<int16_t> drain(Repacketizer& r)
	{
		std::vector<int16_t> out;
		while (const int16_t* f = r.front())
		{
			out.insert(out.end(), f, f + FRAME);
			r.pop();
		}
		return out;
	}

	bool sameSamples(const std::vector<int16_t>& a, const std::vector<int16_t>& b)
	{
		return a.size() == b.size() && std::memcmp(a.data(), b.data(), a.size() * sizeof(int16_t)) == 0;
	}
}

// ── The pure repacketizer ─────────────────────────────────────────────────────

TEST(Repacketizer, TenMsInputsGiveOneFrameEveryTwo)
{
	Repacketizer r;
	const auto a = ramp(0, 80), b = ramp(80, 80);

	EXPECT_EQ(r.push(a.data(), a.size()), 80u);
	EXPECT_EQ(r.front(), nullptr) << "80 samples is not a whole frame yet";
	EXPECT_EQ(r.size(), 80u);

	EXPECT_EQ(r.push(b.data(), b.size()), 80u);
	const int16_t* f = r.front();
	ASSERT_NE(f, nullptr);
	// Golden: the first 20 ms frame is samples 1000..1159, in order.
	EXPECT_EQ(f[0], 1000);
	EXPECT_EQ(f[79], 1079);
	EXPECT_EQ(f[80], 1080);
	EXPECT_EQ(f[159], 1159);
	EXPECT_EQ(std::memcmp(f, ramp(0, FRAME).data(), FRAME * sizeof(int16_t)), 0);
	r.pop();
	EXPECT_TRUE(r.empty());

	// And it keeps going: eight more 10 ms inputs are four more frames.
	std::vector<int16_t> more;
	for (size_t i = 2; i < 10; ++i)
	{
		const auto x = ramp(i * 80, 80);
		r.push(x.data(), x.size());
		const auto got = drain(r);
		EXPECT_EQ(got.size(), i % 2 == 1 ? FRAME : 0u);
		more.insert(more.end(), got.begin(), got.end());
	}
	EXPECT_TRUE(sameSamples(more, ramp(160, 640)));
	EXPECT_EQ(r.dropped(), 0u);
}

TEST(Repacketizer, ThirtyMsInputsGiveThreeFramesPerTwoWithTheRemainderCarried)
{
	Repacketizer r;

	const auto p0 = ramp(0, 240), p1 = ramp(240, 240);
	r.push(p0.data(), p0.size());
	const auto first = drain(r);
	EXPECT_EQ(first.size(), FRAME) << "240 samples: one frame out, 80 carried";
	EXPECT_EQ(r.size(), 80u);
	EXPECT_EQ(first.front(), 1000);
	EXPECT_EQ(first.back(), 1159);

	r.push(p1.data(), p1.size());
	const auto rest = drain(r);
	EXPECT_EQ(rest.size(), 2 * FRAME) << "the carried 80 + 240 = 320: two frames, nothing left";
	EXPECT_EQ(rest.front(), 1160);    // the carried remainder leads the next frame
	EXPECT_EQ(rest[79], 1239);
	EXPECT_EQ(rest[80], 1240);        // ...and the new packet continues it with no gap
	EXPECT_EQ(rest.back(), 1479);
	EXPECT_TRUE(r.empty());

	std::vector<int16_t> all = first;
	all.insert(all.end(), rest.begin(), rest.end());
	EXPECT_TRUE(sameSamples(all, ramp(0, 480)));
	EXPECT_EQ(r.dropped(), 0u);
}

TEST(Repacketizer, TwentyMsInputPassesThroughAsANoOp)
{
	// A 160-sample input into an empty repacketizer comes straight back out
	// unchanged. MixBus never routes a 20 ms leg through it (see
	// MixBusRepack.TwentyMsLegIsUnchanged); this pins that it would be harmless.
	Repacketizer r;
	for (size_t i = 0; i < 5; ++i)
	{
		const auto x = ramp(i * FRAME, FRAME);
		EXPECT_EQ(r.push(x.data(), x.size()), FRAME);
		const int16_t* f = r.front();
		ASSERT_NE(f, nullptr);
		EXPECT_EQ(std::memcmp(f, x.data(), FRAME * sizeof(int16_t)), 0);
		r.pop();
		EXPECT_TRUE(r.empty());
	}
	EXPECT_EQ(r.dropped(), 0u);
}

TEST(Repacketizer, AnyInputSizeUpToMaxInReframesLosslessly)
{
	// 3000 pushes of pseudo-random size 1..MAX_IN, drained after each push as MixBus does:
	// the output is the input stream in order, the remainder is always < FRAME,
	// and nothing is ever dropped.
	Repacketizer r;
	std::vector<int16_t> sent, heard;
	uint32_t seed = 170;
	size_t next = 0;
	for (int i = 0; i < 3000; ++i)
	{
		seed = seed * 1664525u + 1013904223u;
		const size_t n = 1 + (seed >> 8) % Repacketizer::MAX_IN;
		const auto x = ramp(next % 20000, n);
		next += n;
		sent.insert(sent.end(), x.begin(), x.end());
		r.push(x.data(), x.size());
		const auto got = drain(r);
		heard.insert(heard.end(), got.begin(), got.end());
		ASSERT_LT(r.size(), FRAME);
	}
	EXPECT_EQ(r.dropped(), 0u);
	EXPECT_EQ(heard.size() + r.size(), sent.size());
	EXPECT_EQ(std::memcmp(heard.data(), sent.data(), heard.size() * sizeof(int16_t)), 0);
}

TEST(Repacketizer, OverrunDropsTheOldestAndCountsSamplesWithoutTouchingTheHeap)
{
	Repacketizer r;
	const auto a = ramp(0, 400), b = ramp(400, 200), big = ramp(0, 600);

	{
		AllocGuard guard;
		r.push(a.data(), a.size());        // 400 buffered, nothing drained
		EXPECT_EQ(r.push(b.data(), b.size()), 200u);   // 600 > CAP 479: the oldest 121 go
		EXPECT_EQ(guard.delta(), 0u) << "the overrun path must not allocate";
	}
	EXPECT_EQ(r.size(), Repacketizer::CAP);
	EXPECT_EQ(r.dropped(), 121u);
	// What survives is the NEWEST 479 samples: stream positions 121..599.
	EXPECT_TRUE(sameSamples(drain(r), ramp(121, 2 * FRAME)));
	EXPECT_EQ(r.size(), Repacketizer::CAP - 2 * FRAME);
	EXPECT_EQ(r.front(), nullptr);

	// One input larger than the whole buffer: its newest CAP survive, everything
	// buffered before it is older still and goes too.
	r.reset();
	EXPECT_EQ(r.dropped(), 0u) << "reset() zeroes the count";
	r.push(a.data(), 100);
	r.push(big.data(), big.size());
	EXPECT_EQ(r.size(), Repacketizer::CAP);
	EXPECT_EQ(r.dropped(), 121u + 100u);
	EXPECT_TRUE(sameSamples(drain(r), ramp(121, 2 * FRAME)));
}

TEST(Repacketizer, NullAndEmptyPushesChangeNothing)
{
	Repacketizer r;
	const auto a = ramp(0, 90);
	r.push(a.data(), a.size());
	EXPECT_EQ(r.push(nullptr, 160), 0u);
	EXPECT_EQ(r.push(a.data(), 0), 0u);
	EXPECT_EQ(r.size(), 90u);
	EXPECT_EQ(r.dropped(), 0u);
	r.pop();                                // fewer than a frame: pop() is a no-op
	EXPECT_EQ(r.size(), 90u);
}

TEST(Repacketizer, BufferIsFixedAndBounded)
{
	static_assert(Repacketizer::FRAME == static_cast<size_t>(MixBus::FRAME), "output frame is the mixer's frame");
	static_assert(Repacketizer::CAP == Repacketizer::MAX_IN + Repacketizer::FRAME - 1, "");
	EXPECT_EQ(Repacketizer::CAP, 479u);
	// The buffer is the object: 958 B of samples plus two words, no pointer to anything.
	EXPECT_GE(sizeof(Repacketizer), Repacketizer::CAP * sizeof(int16_t));
	EXPECT_LE(sizeof(Repacketizer), Repacketizer::CAP * sizeof(int16_t) + 32);
	EXPECT_TRUE(std::is_trivially_copyable<Repacketizer>::value);
	EXPECT_TRUE(std::is_trivially_destructible<Repacketizer>::value);

	// The worst legal state for a MAX_IN push: FRAME-1 carried. It still fits whole.
	Repacketizer r;
	const auto carried = ramp(0, FRAME - 1), max = ramp(FRAME - 1, Repacketizer::MAX_IN);
	r.push(carried.data(), carried.size());
	r.push(max.data(), max.size());
	EXPECT_EQ(r.size(), Repacketizer::CAP);
	EXPECT_EQ(r.dropped(), 0u);
}

// ── The MixBus wiring ─────────────────────────────────────────────────────────

namespace
{
	// B only listens, so every non-silent frame it hears is A's audio.
	struct Rig
	{
		MixBus bus;
		int A = bus.attach();
		int B = bus.attach();
		std::vector<int16_t> sent, heard;
		size_t inputAllocs = 0;            // operator-new calls made INSIDE inputFrame, all packets

		bool send(const std::vector<int16_t>& pkt)
		{
			sent.insert(sent.end(), pkt.begin(), pkt.end());
			AllocGuard guard;
			const bool ok = bus.inputFrame(A, pkt.data(), pkt.size());
			inputAllocs += guard.delta();
			return ok;
		}
		void tickAndHear()
		{
			bus.tick();
			int16_t ob[MixBus::FRAME];
			ASSERT_TRUE(bus.outputFrame(B, ob, MixBus::FRAME));
			bool silent = true;
			for (int16_t s : ob) if (s != 0) silent = false;
			if (!silent) heard.insert(heard.end(), ob, ob + MixBus::FRAME);
		}
	};
}

TEST(MixBusRepack, ATenMsLegIsHeardWholeAndInOrder)
{
	Rig rig;
	for (size_t i = 0; i < 12; ++i)        // twelve 10 ms packets = six 20 ms frames
	{
		EXPECT_TRUE(rig.send(ramp(i * 80, 80)));
		rig.tickAndHear();
	}
	EXPECT_TRUE(sameSamples(rig.heard, rig.sent)) << "all six frames, byte for byte";
	EXPECT_EQ(rig.bus.repackDropped(rig.A), 0u);
	EXPECT_EQ(rig.inputAllocs, 0u) << "reframing a leg on the rx task must not touch the heap";
}

TEST(MixBusRepack, MixedSizesNeverReorderTheStream)
{
	// 80, 160, 80, 160. The second packet is a whole frame, but 80 samples are still
	// carried ahead of it, so it must queue BEHIND them: routing on the packet size
	// alone would put samples 80..239 in the ring ahead of samples 0..79.
	Rig rig;
	ASSERT_TRUE(rig.send(ramp(0, 80)));
	rig.tickAndHear();
	ASSERT_TRUE(rig.send(ramp(80, 160)));
	rig.tickAndHear();
	ASSERT_TRUE(rig.send(ramp(240, 80)));
	rig.tickAndHear();
	ASSERT_TRUE(rig.send(ramp(320, 160)));
	rig.tickAndHear();

	ASSERT_EQ(rig.sent.size(), 480u);
	EXPECT_TRUE(sameSamples(rig.heard, rig.sent)) << "heard " << rig.heard.size() << " of 480 samples";
}

TEST(MixBusRepack, AReusedPortNeverReplaysThePreviousLegsRemainder)
{
	MixBus bus;
	const int listener = bus.attach();
	const int a1 = bus.attach();

	// Leg 1 sends 240: one frame reaches the ring, 80 stay carried. It hangs up.
	const auto leg1 = ramp(0, 240, 1000);
	ASSERT_TRUE(bus.inputFrame(a1, leg1.data(), leg1.size()));
	bus.detach(a1);
	bus.tick();                            // reclaims a1: rings cleared, remainder marked for reset
	int16_t reclaimTick[MixBus::FRAME];
	ASSERT_TRUE(bus.outputFrame(listener, reclaimTick, MixBus::FRAME));   // that tick's (silent) frame

	const int a2 = bus.attach();
	ASSERT_EQ(a2, a1) << "the freed port is the one reused";

	// Leg 2 sends one whole 20 ms frame. The listener must hear exactly that, and
	// none of leg 1's carried 80 samples at the front of it.
	const auto leg2 = ramp(0, FRAME, 5000);
	ASSERT_TRUE(bus.inputFrame(a2, leg2.data(), leg2.size()));
	bus.tick();

	int16_t heard[MixBus::FRAME];
	ASSERT_TRUE(bus.outputFrame(listener, heard, MixBus::FRAME));
	EXPECT_EQ(std::memcmp(heard, leg2.data(), sizeof heard), 0)
		<< "first heard sample " << heard[0] << " (leg 1's carried samples are 1160..1239)";
	EXPECT_EQ(bus.repackDropped(a2), 0u);
}

TEST(MixBusRepack, AnOverrunIsCountedPerPort)
{
	Rig rig;
	const auto big = ramp(0, 600);         // upstream caps at MAX_IN; the bus must still be safe past it
	EXPECT_TRUE(rig.bus.inputFrame(rig.A, big.data(), big.size()));
	EXPECT_EQ(rig.bus.repackDropped(rig.A), 121u) << "600 offered, 479 kept: 121 oldest samples dropped";
	EXPECT_EQ(rig.bus.repackDropped(rig.B), 0u);
	EXPECT_EQ(rig.bus.repackDropped(-1), 0u);
	EXPECT_EQ(rig.bus.repackDropped(MixBus::MAX_PORTS), 0u);
}

TEST(MixBusRepack, ATwentyMsLegIsUnchanged)
{
	// Every packet exactly FRAME and nothing carried: the ring path as it always was.
	// Same audio, nothing counted. That the repacketizer is never entered is the routing
	// condition in MixBus::inputFrame (n == FRAME with nothing carried), not observable here.
	Rig rig;
	for (size_t i = 0; i < 8; ++i)
	{
		ASSERT_TRUE(rig.send(ramp(i * FRAME, FRAME)));
		rig.tickAndHear();
	}
	EXPECT_TRUE(sameSamples(rig.heard, rig.sent));
	EXPECT_EQ(rig.bus.repackDropped(rig.A), 0u);
	EXPECT_EQ(rig.inputAllocs, 0u);
}
