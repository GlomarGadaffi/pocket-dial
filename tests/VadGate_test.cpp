// VadGate_test.cpp -- issue #169: VAD energy-gating of MixBus participation.
// The gate is default OFF, so the first bus test pins the ungated mixer byte for byte.

#include <gtest/gtest.h>
#include "MixBus.hpp"
#include "VadGate.hpp"

#include <cstdint>

namespace
{
	constexpr int F = MixBus::FRAME;
	constexpr uint8_t H = pd::vad::kHangoverFrames;

	int16_t sat16(int32_t v)
	{
		return static_cast<int16_t>(v > 32767 ? 32767 : (v < -32768 ? -32768 : v));
	}

	// Speech-level, mixed-sign.
	int16_t speechSample(int i, int t) { return static_cast<int16_t>((i * 37 + t * 101) % 2001 - 1000); }
	// Idle-handset noise floor, mixed-sign, +-20.
	int16_t floorSample(int i, int t) { return static_cast<int16_t>((i * 53 + t * 7) % 41 - 20); }
	// Loud enough that the other two legs' sum saturates.
	int16_t clipSample(int i, int) { return (i & 1) ? 32000 : -32000; }

	using Gen = int16_t (*)(int, int);

	void fill(int16_t* f, Gen gen, int t)
	{
		for (int i = 0; i < F; ++i) f[i] = gen(i, t);
	}

	void push(MixBus& bus, int port, Gen gen, int t)
	{
		int16_t f[F];
		fill(f, gen, t);
		ASSERT_TRUE(bus.inputFrame(port, f, F));
	}

	void hear(MixBus& bus, int port, int16_t* out)
	{
		for (int i = 0; i < F; ++i) out[i] = 0x7FFF;   // a failed read must not look like silence
		ASSERT_TRUE(bus.outputFrame(port, out, F));
	}

	bool silent(const int16_t* f)
	{
		for (int i = 0; i < F; ++i) if (f[i] != 0) return false;
		return true;
	}

	bool is(const int16_t* f, Gen gen, int t)
	{
		for (int i = 0; i < F; ++i) if (f[i] != gen(i, t)) return false;
		return true;
	}

	uint64_t fnv1a(uint64_t h, const int16_t* p, size_t n)
	{
		for (size_t i = 0; i < n; ++i)
		{
			const uint16_t u = static_cast<uint16_t>(p[i]);
			h = (h ^ (u & 0xFF)) * 0x100000001b3ull;
			h = (h ^ (u >> 8)) * 0x100000001b3ull;
		}
		return h;
	}

	// Pure-gate fixtures.
	constexpr int64_t kOpen = pd::vad::kOpenEnergy;
	int16_t loud[F];
	int16_t quiet[F];
	int16_t zeros[F];

	pd::vad::Verdict step(uint8_t hang, const int16_t* f, bool bypass = false)
	{
		return pd::vad::step(hang, f, F, kOpen, H, bypass);
	}

	struct VadGatePure : ::testing::Test
	{
		void SetUp() override
		{
			fill(loud, speechSample, 0);
			fill(quiet, floorSample, 0);
			ASSERT_GE(pd::vad::energy(loud, F), kOpen) << "positive control: speech is above the gate";
			ASSERT_LT(pd::vad::energy(quiet, F), kOpen) << "positive control: the noise floor is below it";
		}
	};
}

// ── The pure gate ────────────────────────────────────────────────────────────

TEST(VadGate, EnergyIsSumOfSquaresInInt64)
{
	const int16_t two[2] = {3, -4};
	EXPECT_EQ(pd::vad::energy(two, 2), 25);
	EXPECT_EQ(pd::vad::energy(two, 0), 0);
	EXPECT_EQ(pd::vad::energy(nullptr, F), 0);

	int16_t full[F];
	for (auto& s : full) s = 32767;
	EXPECT_EQ(pd::vad::energy(full, F), 171788206240LL);   // > 2^32
	for (auto& s : full) s = -32768;
	EXPECT_EQ(pd::vad::energy(full, F), 171798691840LL);   // worst case, still fits int64
}

TEST_F(VadGatePure, SpeechAboveThresholdParticipatesImmediately)
{
	const pd::vad::Verdict v = step(0, loud);   // gate starts closed
	EXPECT_TRUE(v.participates);
	EXPECT_EQ(v.hang, H);
}

TEST_F(VadGatePure, SilenceIsGatedOutOnlyAfterTheHangover)
{
	EXPECT_FALSE(step(0, quiet).participates) << "a closed gate stays closed on silence";

	uint8_t hang = step(0, loud).hang;
	for (int i = 1; i <= H; ++i)
	{
		const pd::vad::Verdict v = step(hang, quiet);
		EXPECT_TRUE(v.participates) << "quiet frame " << i << " is still inside the hangover";
		hang = v.hang;
	}
	EXPECT_FALSE(step(hang, quiet).participates) << "quiet frame " << (H + 1) << " is gated";
}

TEST_F(VadGatePure, ShortDipDoesNotGate)
{
	uint8_t hang = step(0, loud).hang;
	for (int i = 1; i < H; ++i)
	{
		const pd::vad::Verdict v = step(hang, quiet);
		ASSERT_TRUE(v.participates) << "dip frame " << i;
		hang = v.hang;
	}
	const pd::vad::Verdict back = step(hang, loud);
	EXPECT_TRUE(back.participates);
	EXPECT_EQ(back.hang, H) << "speech re-arms the full hangover";
}

TEST_F(VadGatePure, ThresholdIsInclusive)
{
	int16_t f[F] = {};
	f[0] = 1000;
	const int64_t e = pd::vad::energy(f, F);
	ASSERT_EQ(e, 1000000);
	EXPECT_TRUE(pd::vad::step(0, f, F, e, H, false).participates);
	EXPECT_FALSE(pd::vad::step(0, f, F, e + 1, H, false).participates);
}

TEST_F(VadGatePure, ZeroHangoverGatesOnTheFirstQuietFrame)
{
	EXPECT_TRUE(pd::vad::step(0, loud, F, kOpen, 0, false).participates);
	EXPECT_FALSE(pd::vad::step(0, quiet, F, kOpen, 0, false).participates);
}

TEST_F(VadGatePure, EmergencyBypassIsNeverGatedEvenInDigitalSilence)
{
	uint8_t hang = 0;
	for (int i = 0; i < 1000; ++i)
	{
		const pd::vad::Verdict v = step(hang, zeros, /*bypass=*/true);
		ASSERT_TRUE(v.participates) << "frame " << i;
		hang = v.hang;
	}
	EXPECT_FALSE(step(0, zeros, false).participates) << "negative control: same silence, no bypass";
}

// ── MixBus wiring ────────────────────────────────────────────────────────────

TEST(VadGate, DefaultOffMixerIsByteIdenticalToTheUngatedMixer)
{
	MixBus bus;   // default-constructed: gate off
	const int A = bus.attach();
	const int B = bus.attach();
	const int C = bus.attach();
	ASSERT_GE(C, 0);

	uint64_t hash = 0xcbf29ce484222325ull;
	for (int t = 0; t < 4; ++t)
	{
		int16_t a[F], b[F], c[F];
		fill(a, speechSample, t);
		fill(b, floorSample, t);
		fill(c, clipSample, t);
		ASSERT_TRUE(bus.inputFrame(A, a, F));
		ASSERT_TRUE(bus.inputFrame(B, b, F));
		ASSERT_TRUE(bus.inputFrame(C, c, F));
		bus.tick();

		int16_t oa[F], ob[F], oc[F];
		hear(bus, A, oa);
		hear(bus, B, ob);
		hear(bus, C, oc);
		for (int i = 0; i < F; ++i)
		{
			ASSERT_EQ(oa[i], sat16(b[i] + c[i])) << "tick " << t << " sample " << i;
			ASSERT_EQ(ob[i], sat16(a[i] + c[i])) << "tick " << t << " sample " << i;
			ASSERT_EQ(oc[i], sat16(a[i] + b[i])) << "tick " << t << " sample " << i;
		}
		hash = fnv1a(hash, oa, F);
		hash = fnv1a(hash, ob, F);
		hash = fnv1a(hash, oc, F);
	}
	EXPECT_EQ(hash, 6683846020206085863ull) << "golden captured from the unmodified mixer";
}

TEST(VadGate, NoiseFloorPortIsBitExactlyAbsentFromTheMix)
{
	MixBus bus(/*vadGate=*/true);
	const int A = bus.attach();   // talker
	const int B = bus.attach();   // idle handset streaming its floor
	const int C = bus.attach();   // idle handset streaming its floor

	for (int t = 0; t < 3; ++t)
	{
		push(bus, A, speechSample, t);
		push(bus, B, floorSample, t);
		push(bus, C, floorSample, t + 100);
		bus.tick();

		int16_t oa[F], ob[F], oc[F];
		hear(bus, A, oa);
		hear(bus, B, ob);
		hear(bus, C, oc);
		EXPECT_TRUE(is(ob, speechSample, t)) << "B hears exactly A, tick " << t;
		EXPECT_TRUE(is(oc, speechSample, t)) << "C hears exactly A, tick " << t;
		EXPECT_TRUE(silent(oa)) << "A hears neither floor, and no negative self, tick " << t;
	}
}

TEST(VadGate, GatedPortStillHearsTheOthers)
{
	MixBus bus(true);
	const int A = bus.attach();
	const int B = bus.attach();

	push(bus, A, speechSample, 0);
	push(bus, B, floorSample, 0);
	bus.tick();

	int16_t ob[F];
	hear(bus, B, ob);
	EXPECT_TRUE(is(ob, speechSample, 0));
	EXPECT_EQ(bus.activePorts(), 2) << "gated is not detached";
}

TEST(VadGate, SpeechOpensOnTheFirstFrame)
{
	MixBus bus(true);
	const int A = bus.attach();
	const int B = bus.attach();

	push(bus, A, speechSample, 7);
	bus.tick();

	int16_t ob[F];
	hear(bus, B, ob);
	EXPECT_TRUE(is(ob, speechSample, 7));
}

TEST(VadGate, HangoverCarriesQuietFramesThenGates)
{
	MixBus bus(true);
	const int A = bus.attach();
	const int B = bus.attach();   // listener only
	int16_t ob[F];

	push(bus, A, speechSample, 0);
	bus.tick();
	hear(bus, B, ob);
	ASSERT_TRUE(is(ob, speechSample, 0));

	for (int t = 1; t <= H; ++t)   // the hangover: quiet frames still mixed
	{
		push(bus, A, floorSample, t);
		bus.tick();
		hear(bus, B, ob);
		EXPECT_TRUE(is(ob, floorSample, t)) << "quiet frame " << t << " is inside the hangover";
	}

	push(bus, A, floorSample, H + 1);
	bus.tick();
	hear(bus, B, ob);
	EXPECT_TRUE(silent(ob)) << "quiet frame " << (H + 1) << " is gated";
}

TEST(VadGate, EmergencyPortIsNeverGated)
{
	MixBus gated(true);
	MixBus control(true);
	const int A = gated.attach(), B = gated.attach();
	const int cA = control.attach(), cB = control.attach();
	gated.setEmergency(B, true);

	for (int t = 0; t < 3 * H; ++t)
	{
		push(gated, B, floorSample, t);
		push(control, cB, floorSample, t);
		gated.tick();
		control.tick();

		int16_t oa[F], oc[F];
		hear(gated, A, oa);
		hear(control, cA, oc);
		ASSERT_TRUE(is(oa, floorSample, t)) << "emergency leg stays in the mix, tick " << t;
		ASSERT_TRUE(silent(oc)) << "negative control: the same floor, unflagged, is gated, tick " << t;
	}
}

TEST(VadGate, EmergencyFlagDoesNotSurviveReclaim)
{
	MixBus bus(true);
	const int A = bus.attach();
	const int B = bus.attach();
	bus.setEmergency(B, true);
	bus.setEmergency(-1, true);            // out of range: ignored
	bus.setEmergency(MixBus::MAX_PORTS, true);

	bus.detach(B);
	bus.tick();                            // reclaim
	ASSERT_EQ(bus.attach(), B);            // the slot is reused

	push(bus, B, floorSample, 0);
	bus.tick();
	int16_t oa[F];
	hear(bus, A, oa);
	EXPECT_TRUE(silent(oa)) << "the new leg in the reused slot is not an emergency leg";
}
