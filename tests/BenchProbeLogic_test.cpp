// BenchProbeLogic_test.cpp -- issue #384 (H1). The pure decisions behind the
// bench-only anchor probe image (POCKETDIAL_ANCHOR_BENCH_PROBE,
// src/SIP/BenchProbeLogic.hpp). The glue that calls them (heap_caps, esp_timer,
// the anchor client's fault sites, the HTTP route) is ESP-only.

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include "BenchProbeLogic.hpp"
#include "TelephonyAnchorLogic.hpp"

namespace bp = pd::benchprobe;
using bp::Fault;
using bp::Verdict;

namespace
{
bp::FaultRequest req(Fault f, bool hasValue = false, long value = 0)
{
	bp::FaultRequest r;
	r.fault = f;
	r.hasValue = hasValue;
	r.value = value;
	return r;
}
} // namespace

TEST(BenchProbeLogic, EveryFaultNameRoundTripsAndWsDropIsNotOne)
{
	for (size_t i = 0; i < bp::kFaultCount; ++i)
	{
		Fault f = Fault::Count;
		ASSERT_TRUE(bp::parseFault(bp::kFaultNames[i], f)) << bp::kFaultNames[i];
		EXPECT_EQ(static_cast<size_t>(f), i);
		EXPECT_EQ(bp::faultName(f), bp::kFaultNames[i]);
	}
	Fault f = Fault::Count;
	// ws_drop is deliberately absent: no documented IDF call drops the WS
	// transport and keeps the library's reconnect (docs/BENCH_PROBE.md).
	EXPECT_FALSE(bp::parseFault("ws_drop", f));
	EXPECT_FALSE(bp::parseFault("", f));
	EXPECT_FALSE(bp::parseFault("TOKEN_AGE", f));
	EXPECT_FALSE(bp::parseFault("token_age ", f));
}

TEST(BenchProbeLogic, ParametersAreRequiredExactlyWhereTheyMeanSomething)
{
	bp::FaultRequest r;
	EXPECT_EQ(bp::parseFaultRequest("get_status", "403", r), Verdict::Ok);
	EXPECT_EQ(r.fault, Fault::GetStatus);
	EXPECT_TRUE(r.hasValue);
	EXPECT_EQ(r.value, 403);
	EXPECT_EQ(bp::parseFaultRequest("get_status", "404", r), Verdict::Ok);
	EXPECT_EQ(bp::parseFaultRequest("get_status", "599", r), Verdict::Ok);
	// Only a refusal can be forced: a 200 would open nothing, a 3xx is not what the loop waits out.
	EXPECT_EQ(bp::parseFaultRequest("get_status", "200", r), Verdict::BadRequest);
	EXPECT_EQ(bp::parseFaultRequest("get_status", "399", r), Verdict::BadRequest);
	EXPECT_EQ(bp::parseFaultRequest("get_status", "600", r), Verdict::BadRequest);
	EXPECT_EQ(bp::parseFaultRequest("get_status", "", r), Verdict::BadRequest);

	EXPECT_EQ(bp::parseFaultRequest("get_max_attempts", "40", r), Verdict::Ok);
	EXPECT_EQ(r.value, 40);
	EXPECT_EQ(bp::parseFaultRequest("get_max_attempts", "1", r), Verdict::Ok);
	EXPECT_EQ(bp::parseFaultRequest("get_max_attempts", "240", r), Verdict::Ok);
	EXPECT_EQ(bp::parseFaultRequest("get_max_attempts", "241", r), Verdict::BadRequest)
		<< "the override may only shrink the 240-attempt budget";
	EXPECT_EQ(bp::parseFaultRequest("get_max_attempts", "0", r), Verdict::BadRequest);

	for (const char* plain : {"makecall_read_fail", "post_stream_fail", "token_age"})
	{
		EXPECT_EQ(bp::parseFaultRequest(plain, "", r), Verdict::Ok) << plain;
		EXPECT_FALSE(r.hasValue);
		EXPECT_EQ(bp::parseFaultRequest(plain, "1", r), Verdict::BadRequest) << plain;
	}

	for (const char* junk : {"-1", "+4", "4x3", "4 ", " 4", "0x10", "99999999999999999999"})
		EXPECT_EQ(bp::parseFaultRequest("get_max_attempts", junk, r), Verdict::BadRequest) << junk;
	EXPECT_EQ(bp::parseFaultRequest("ws_drop", "", r), Verdict::BadRequest);
}

TEST(BenchProbeLogic, AFaultFiresExactlyOncePerArm)
{
	bp::Faults faults;
	ASSERT_EQ(faults.arm(req(Fault::MakecallReadFail), false), Verdict::Ok);
	EXPECT_TRUE(faults.armed(Fault::MakecallReadFail));
	EXPECT_TRUE(faults.fire(Fault::MakecallReadFail, false, false));
	EXPECT_FALSE(faults.armed(Fault::MakecallReadFail));
	EXPECT_FALSE(faults.fire(Fault::MakecallReadFail, false, false)) << "one-shot";
	EXPECT_EQ(faults.fired(Fault::MakecallReadFail), 1u);

	ASSERT_EQ(faults.arm(req(Fault::MakecallReadFail), false), Verdict::Ok);
	EXPECT_TRUE(faults.fire(Fault::MakecallReadFail, false, false));
	EXPECT_EQ(faults.fired(Fault::MakecallReadFail), 2u);
}

TEST(BenchProbeLogic, AnUnarmedFaultNeverFiresAndCountsNothing)
{
	bp::Faults faults;
	for (size_t i = 0; i < bp::kFaultCount; ++i)
	{
		const Fault f = static_cast<Fault>(i);
		EXPECT_FALSE(faults.armedHint(f));
		EXPECT_FALSE(faults.fire(f, false, false));
		EXPECT_EQ(faults.fired(f), 0u);
		EXPECT_EQ(faults.emergencySkips(f), 0u);
	}
}

TEST(BenchProbeLogic, FiringHandsBackTheArmedValue)
{
	bp::Faults faults;
	ASSERT_EQ(faults.arm(req(Fault::GetStatus, true, 403), false), Verdict::Ok);
	ASSERT_EQ(faults.arm(req(Fault::GetMaxAttempts, true, 40), false), Verdict::Ok);
	int32_t v = 0;
	EXPECT_TRUE(faults.fire(Fault::GetStatus, false, false, &v));
	EXPECT_EQ(v, 403);
	EXPECT_TRUE(faults.fire(Fault::GetMaxAttempts, false, false, &v));
	EXPECT_EQ(v, 40);
}

TEST(BenchProbeLogic, NothingArmsWhileAnEmergencyCallIsLive)
{
	bp::Faults faults;
	EXPECT_EQ(faults.arm(req(Fault::TokenAge), /*emergencyLive=*/true), Verdict::EmergencyLive);
	EXPECT_FALSE(faults.armed(Fault::TokenAge));
	EXPECT_EQ(faults.refusedArms(), 1u);
}

TEST(BenchProbeLogic, AFaultNeverFiresForAnEmergencyDestinationAndDisarmsEverything)
{
	// Rule 5 / S7: a 911 or 933 is never the call a fault lands on. Reaching a
	// fault site for one disarms every fault, so nothing armed before the 911
	// can fire later in the middle of it either.
	bp::Faults faults;
	ASSERT_EQ(faults.arm(req(Fault::MakecallReadFail), false), Verdict::Ok);
	ASSERT_EQ(faults.arm(req(Fault::PostStreamFail), false), Verdict::Ok);
	EXPECT_FALSE(faults.fire(Fault::MakecallReadFail, /*destinationEmergency=*/true, false));
	EXPECT_EQ(faults.fired(Fault::MakecallReadFail), 0u);
	EXPECT_EQ(faults.emergencySkips(Fault::MakecallReadFail), 1u);
	EXPECT_FALSE(faults.armed(Fault::MakecallReadFail));
	EXPECT_FALSE(faults.armed(Fault::PostStreamFail));
	EXPECT_EQ(faults.emergencyDisarms(), 1u);
	// And the next ordinary call does not get it either: it is gone, not deferred.
	EXPECT_FALSE(faults.fire(Fault::MakecallReadFail, false, false));
}

TEST(BenchProbeLogic, AFaultNeverFiresWhileAnyEmergencySessionIsLive)
{
	bp::Faults faults;
	ASSERT_EQ(faults.arm(req(Fault::PostStreamFail), false), Verdict::Ok);
	EXPECT_FALSE(faults.fire(Fault::PostStreamFail, false, /*emergencyLive=*/true));
	EXPECT_EQ(faults.fired(Fault::PostStreamFail), 0u);
	EXPECT_EQ(faults.emergencySkips(Fault::PostStreamFail), 1u);
	EXPECT_FALSE(faults.armed(Fault::PostStreamFail));
}

TEST(BenchProbeLogic, DisarmAllReportsWhetherAnythingWasArmed)
{
	bp::Faults faults;
	EXPECT_FALSE(faults.disarmAll());
	ASSERT_EQ(faults.arm(req(Fault::TokenAge), false), Verdict::Ok);
	EXPECT_TRUE(faults.disarmAll());
	EXPECT_FALSE(faults.armed(Fault::TokenAge));
	EXPECT_EQ(faults.fired(Fault::TokenAge), 0u);
}

TEST(BenchProbeLogic, ConcurrentFireSitesConsumeOneArmOnce)
{
	bp::Faults faults;
	for (int round = 0; round < 50; ++round)
	{
		ASSERT_EQ(faults.arm(req(Fault::PostStreamFail), false), Verdict::Ok);
		std::atomic<int> wins{0};
		std::vector<std::thread> ts;
		for (int t = 0; t < 4; ++t)
			ts.emplace_back([&] { if (faults.fire(Fault::PostStreamFail, false, false)) wins.fetch_add(1); });
		for (auto& t : ts) t.join();
		ASSERT_EQ(wins.load(), 1) << "round " << round;
	}
	EXPECT_EQ(faults.fired(Fault::PostStreamFail), 50u);
}

TEST(BenchProbeLogic, GetFaultsAreClaimedForOneOutboundLegAndNeverAnEmergencyOne)
{
	bp::LegClaim claim;
	EXPECT_FALSE(claim.take("7")) << "nothing claimed";
	EXPECT_FALSE(claim.claim("9", /*destinationEmergency=*/true)) << "a 911/933 leg is never claimed";
	EXPECT_FALSE(claim.take("9"));
	EXPECT_TRUE(claim.claim("7", false));
	EXPECT_FALSE(claim.take("8")) << "another leg (an inbound call, say) is not the claimed one";
	EXPECT_FALSE(claim.take("70")) << "prefix-safe";
	EXPECT_TRUE(claim.take("7"));
	EXPECT_FALSE(claim.take("7")) << "one stream per claim";
	EXPECT_TRUE(claim.claim("7", false));
	EXPECT_TRUE(claim.claim("12", false)) << "a later makeCall replaces the claim";
	EXPECT_FALSE(claim.take("7"));
	EXPECT_TRUE(claim.take("12"));
	EXPECT_FALSE(claim.claim("", false));
	EXPECT_FALSE(claim.claim(std::string(bp::LegClaim::kMaxLeg + 1, 'x'), false)) << "too long to hold, so never claimed";
	EXPECT_TRUE(claim.claim("7", false));
	claim.clear();
	EXPECT_FALSE(claim.take("7"));
}

TEST(BenchProbeLogic, AForcedGetStatusReplacesOnlyARealAnswer)
{
	// Not armed: the real status passes through untouched.
	EXPECT_EQ(bp::overrideGetStatus(404, 0).status, 404);
	EXPECT_FALSE(bp::overrideGetStatus(200, 0).closeUnread);
	EXPECT_EQ(bp::overrideGetStatus(200, 0).status, 200);
	// A real refusal is reported as the forced one, and drained as usual.
	EXPECT_EQ(bp::overrideGetStatus(404, 403).status, 403);
	EXPECT_FALSE(bp::overrideGetStatus(404, 403).closeUnread);
	// A real 200 carries the live audio stream: it is closed unread, never drained.
	EXPECT_EQ(bp::overrideGetStatus(200, 403).status, 403);
	EXPECT_TRUE(bp::overrideGetStatus(200, 403).closeUnread);
	// No response parsed is a transport failure (#350): it stays real.
	EXPECT_EQ(bp::overrideGetStatus(-1, 403).status, -1);
	EXPECT_FALSE(bp::overrideGetStatus(-1, 403).closeUnread);
	EXPECT_EQ(bp::overrideGetStatus(0, 403).status, 0);
}

TEST(BenchProbeLogic, TokenAgeMakesTheHeldTokenReadAsExpiring)
{
	constexpr int64_t kLife = 3600LL * 1000000;    // a 1 h JWT
	constexpr int64_t kMargin = 5LL * 60 * 1000000; // tokenExpiringSoon()'s margin
	const int64_t obtained = 10LL * 60 * 1000000;  // fetched at 10 min
	const int64_t now = 20LL * 60 * 1000000;       // checked at 20 min
	ASSERT_FALSE(telephony::tokenIsExpiringSoon(now, obtained, kLife, kMargin)) << "precondition: fresh";
	EXPECT_TRUE(bp::tokenAgeApplies(obtained, kLife));
	const int64_t aged = bp::agedTokenObtainedUs(now, kLife);
	EXPECT_TRUE(telephony::tokenIsExpiringSoon(now, aged, kLife, kMargin));
	EXPECT_LT(aged, obtained);
	// Early in uptime the aged stamp goes negative; still expiring, never "no token" by accident.
	EXPECT_TRUE(telephony::tokenIsExpiringSoon(1000, bp::agedTokenObtainedUs(1000, kLife), kLife, kMargin));
	// No token yet: it already reads as expiring, so there is nothing to age.
	EXPECT_FALSE(bp::tokenAgeApplies(0, 0));
	EXPECT_FALSE(bp::tokenAgeApplies(obtained, 0));
}

TEST(BenchProbeLogic, TheEmergencyGateHoldsWhileADialIsInFlight)
{
	bp::EmergencyGate gate;
	EXPECT_FALSE(gate.live());
	gate.sessionsLive(true);
	EXPECT_TRUE(gate.live());
	gate.sessionsLive(false);
	EXPECT_FALSE(gate.live());

	// A 911 makeCall can run before its session is flagged; the tick's level
	// must not clear the gate under it.
	gate.dialBegin();
	EXPECT_TRUE(gate.live());
	gate.sessionsLive(false);
	EXPECT_TRUE(gate.live()) << "the in-flight dial keeps the gate shut";
	gate.dialEnd();
	EXPECT_TRUE(gate.live()) << "until the next level read";
	gate.sessionsLive(false);
	EXPECT_FALSE(gate.live());

	gate.sessionAppeared();
	EXPECT_TRUE(gate.live());
}

TEST(BenchProbeLogic, BallastRequestsAreBoundedAndTheDeadManHasADefault)
{
	bp::BallastRequest b;
	ASSERT_EQ(bp::parseBallastRequest("65536", "", b), Verdict::Ok);
	EXPECT_EQ(b.target, 65536u);
	EXPECT_EQ(b.deadmanS, bp::kDeadmanDefaultS);
	EXPECT_EQ(bp::kDeadmanDefaultS, 120u);
	ASSERT_EQ(bp::parseBallastRequest("65536", "30", b), Verdict::Ok);
	EXPECT_EQ(b.deadmanS, 30u);
	EXPECT_EQ(bp::parseBallastRequest("65536", "0", b), Verdict::BadRequest) << "a ballast always dies";
	EXPECT_EQ(bp::parseBallastRequest("65536", "601", b), Verdict::BadRequest);
	EXPECT_EQ(bp::parseBallastRequest(std::to_string(bp::kBallastMinTarget - 1), "", b), Verdict::BadRequest)
		<< "below the floor";
	EXPECT_EQ(bp::parseBallastRequest(std::to_string(bp::kBallastMinTarget), "", b), Verdict::Ok);
	EXPECT_EQ(bp::parseBallastRequest("", "", b), Verdict::BadRequest);
	EXPECT_EQ(bp::parseBallastRequest("64k", "", b), Verdict::BadRequest);
}

TEST(BenchProbeLogic, BallastRefusesToArmDuringAnEmergencyOrOnTopOfItself)
{
	EXPECT_EQ(bp::ballastArmCheck(/*emergencyLive=*/true, false), Verdict::EmergencyLive);
	EXPECT_EQ(bp::ballastArmCheck(true, true), Verdict::EmergencyLive);
	EXPECT_EQ(bp::ballastArmCheck(false, /*held=*/true), Verdict::Busy);
	EXPECT_EQ(bp::ballastArmCheck(false, false), Verdict::Ok);
}

TEST(BenchProbeLogic, BallastBlocksStopAtTheTarget)
{
	EXPECT_EQ(bp::ballastNextBlock(100000, 100000, 4096), 0u) << "at the target";
	EXPECT_EQ(bp::ballastNextBlock(90000, 100000, 4096), 0u) << "already below it";
	EXPECT_EQ(bp::ballastNextBlock(200000, 100000, 4096), 4096u);
	EXPECT_EQ(bp::ballastNextBlock(101000, 100000, 4096), 1000u) << "the last block is only the gap";
	EXPECT_EQ(bp::ballastNextBlock(100000 + bp::kBallastBlockMin - 1, 100000, 4096), 0u) << "close enough";
	EXPECT_EQ(bp::ballastShrink(4096), 2048u);
	EXPECT_EQ(bp::ballastShrink(bp::kBallastBlockMin), 0u) << "stop shrinking below the minimum block";
}

namespace
{
// A fake internal heap: every allocation costs its size plus a header, and no
// single block can exceed `largest` (fragmentation).
struct FakeHeap
{
	size_t free;
	size_t largest;
	size_t header = 16;
	std::vector<std::vector<char>> blocks;
	void* alloc(size_t n)
	{
		if (n > largest || n + header > free) return nullptr;
		free -= n + header;
		blocks.emplace_back(n);
		return blocks.back().data();
	}
};
} // namespace

TEST(BenchProbeLogic, FillingBallastReachesTheTargetWithoutOvershootingIt)
{
	FakeHeap heap{300000, 300000};
	void* slots[bp::kBallastMaxBlocks] = {};
	size_t bytes = 0;
	const size_t n = bp::fillBallast(slots, bp::kBallastMaxBlocks, 100000,
		[&] { return heap.free; }, [&](size_t want) { return heap.alloc(want); }, [] { return false; }, &bytes);
	EXPECT_GT(n, 0u);
	EXPECT_LE(heap.free, 100000u + bp::kBallastBlockMin);
	EXPECT_GE(heap.free + heap.header, 100000u) << "never more than one header under the target";
	EXPECT_EQ(bytes, 300000u - heap.free - n * heap.header);
}

TEST(BenchProbeLogic, FillingBallastShrinksAroundFragmentationAndStopsAtTheSlotCap)
{
	FakeHeap frag{150000, 1000};   // no block larger than 1000 B
	void* slots[bp::kBallastMaxBlocks] = {};
	size_t bytes = 0;
	size_t n = bp::fillBallast(slots, bp::kBallastMaxBlocks, 100000,
		[&] { return frag.free; }, [&](size_t want) { return frag.alloc(want); }, [] { return false; }, &bytes);
	EXPECT_LE(frag.free, 100000u + bp::kBallastBlockMin);
	EXPECT_LE(n, bp::kBallastMaxBlocks);

	FakeHeap big{2000000, 2000000};
	void* few[4] = {};
	n = bp::fillBallast(few, 4, 100000,
		[&] { return big.free; }, [&](size_t want) { return big.alloc(want); }, [] { return false; }, &bytes);
	EXPECT_EQ(n, 4u) << "bounded by the slot array, never more";
	EXPECT_EQ(bytes, 4u * bp::kBallastBlockMax);
}

TEST(BenchProbeLogic, FillingBallastStopsTheMomentAnEmergencyAppears)
{
	FakeHeap heap{300000, 300000};
	void* slots[bp::kBallastMaxBlocks] = {};
	size_t bytes = 0;
	int calls = 0;
	const size_t n = bp::fillBallast(slots, bp::kBallastMaxBlocks, 100000,
		[&] { return heap.free; }, [&](size_t want) { return heap.alloc(want); },
		[&] { return ++calls > 3; }, &bytes);
	EXPECT_EQ(n, 3u);
	EXPECT_GT(heap.free, 100000u);
}

TEST(BenchProbeLogic, TheDeadManFiresAtItsDeadlineAndNotBefore)
{
	const int64_t armed = 5000000;
	const int64_t at = bp::deadmanDeadlineUs(armed, bp::kDeadmanDefaultS);
	EXPECT_EQ(at, armed + 120LL * 1000000);
	EXPECT_FALSE(bp::deadmanExpired(at - 1, at));
	EXPECT_TRUE(bp::deadmanExpired(at, at));
	EXPECT_TRUE(bp::deadmanExpired(at + 1, at));
}

TEST(BenchProbeLogic, StatusRendersEveryCounterAsJsonOrNothing)
{
	bp::Faults faults;
	ASSERT_EQ(faults.arm(req(Fault::GetStatus, true, 403), false), Verdict::Ok);
	ASSERT_EQ(faults.arm(req(Fault::MakecallReadFail), false), Verdict::Ok);
	ASSERT_TRUE(faults.fire(Fault::MakecallReadFail, false, false));
	bp::BallastStatus b;
	b.held = true;
	b.bytes = 204800;
	b.blocks = 50;
	b.target = 65536;
	b.deadmanS = 120;
	b.releasedDeadman = 2;
	char buf[1024];
	const size_t n = bp::renderStatus(buf, sizeof(buf), faults, b, false, 70000);
	ASSERT_GT(n, 0u);
	const std::string s(buf, n);
	EXPECT_EQ(s.front(), '{');
	EXPECT_EQ(s.back(), '}');
	EXPECT_NE(s.find("\"get_status\":{\"armed\":true,\"value\":403,\"fired\":0,\"emergencySkips\":0}"), std::string::npos) << s;
	EXPECT_NE(s.find("\"makecall_read_fail\":{\"armed\":false,\"value\":0,\"fired\":1,\"emergencySkips\":0}"), std::string::npos) << s;
	for (size_t i = 0; i < bp::kFaultCount; ++i)
		EXPECT_NE(s.find("\"" + std::string(bp::kFaultNames[i]) + "\":"), std::string::npos) << bp::kFaultNames[i];
	EXPECT_NE(s.find("\"held\":true,\"bytes\":204800,\"blocks\":50,\"target\":65536,\"deadmanS\":120"), std::string::npos) << s;
	EXPECT_NE(s.find("\"released\":{\"api\":0,\"deadman\":2,\"emergency\":0}"), std::string::npos) << s;
	EXPECT_NE(s.find("\"emergencyLive\":false"), std::string::npos) << s;
	EXPECT_NE(s.find("\"freeInternal\":70000"), std::string::npos) << s;
	EXPECT_EQ(s.find("ws_drop"), std::string::npos);

	char tiny[64];
	EXPECT_EQ(bp::renderStatus(tiny, sizeof(tiny), faults, b, false, 70000), 0u)
		<< "a body that does not fit is refused, never truncated";
}
