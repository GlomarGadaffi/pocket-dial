// TimedMutex_test.cpp -- issue #986 slice 0: RequestsHandler::_mutex measures how
// long it is held (log2-us histogram, max hold + the call site that held it,
// count over 20 ms) and names each site that went over, once per boot.
//
// The unit tests drive pd::BasicTimedMutex with a fake clock, so nothing sleeps
// and no test depends on the scheduler. The two RequestsHandler tests use the
// real mutex and the real clock, and sleep only to make a hold LONGER than the
// threshold, which a loaded host cannot undo.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "RequestsHandler.hpp"
#include "TimedMutex.hpp"
#include "Witness.hpp"

namespace
{
	struct FakeClock
	{
		static inline std::atomic<int64_t> now{0};
		static int64_t nowUs() { return now.load(); }
	};
	using FM = pd::BasicTimedMutex<FakeClock>;

	struct TimedMutexTest : ::testing::Test
	{
		void SetUp() override
		{
			FM::resetForTest();
			FakeClock::now = 0;
		}
	};

	// Two call sites. noinline keeps each a single site however the optimiser unrolls the
	// test, and the trailing statement in B keeps identical-code folding from merging them.
#if defined(_MSC_VER)
#define TM_TEST_NOINLINE __declspec(noinline)
#else
#define TM_TEST_NOINLINE __attribute__((noinline))
#endif
	TM_TEST_NOINLINE void holdAtSiteA(FM& m, int64_t us)
	{
		m.lock();
		FakeClock::now += us;
		m.unlock();
	}
	TM_TEST_NOINLINE void holdAtSiteB(FM& m, int64_t us)
	{
		m.lock();
		FakeClock::now += us;
		m.unlock();
		FakeClock::now += 1;
	}
}

TEST_F(TimedMutexTest, BucketIndexForKnownDurations)
{
	// Bucket b holds [2^(b-1), 2^b) us; bucket 0 is a zero-length hold; the last
	// bucket is open at the top.
	EXPECT_EQ(FM::bucketOf(0), 0u);
	EXPECT_EQ(FM::bucketOf(1), 1u);
	EXPECT_EQ(FM::bucketOf(2), 2u);
	EXPECT_EQ(FM::bucketOf(3), 2u);
	EXPECT_EQ(FM::bucketOf(4), 3u);
	EXPECT_EQ(FM::bucketOf(1000), 10u);    // 512..1023
	EXPECT_EQ(FM::bucketOf(1023), 10u);
	EXPECT_EQ(FM::bucketOf(1024), 11u);
	EXPECT_EQ(FM::bucketOf(20000), 15u);   // 16384..32767: the 20 ms threshold sits inside it
	EXPECT_EQ(FM::bucketOf(32768), 16u);
	EXPECT_EQ(FM::bucketOf(1u << 22), FM::kBuckets - 1);
	EXPECT_EQ(FM::bucketOf(0xffffffffu), FM::kBuckets - 1);
}

TEST_F(TimedMutexTest, P99FromAKnownDistribution)
{
	// 99 short holds and one long one: the 99th-percentile rank (99 of 100) is
	// still inside the short bucket (8..15 us), so p99 is that bucket's top edge.
	for (int i = 0; i < 99; ++i) FM::record(10, 0x1000);
	FM::record(50000, 0x2000);
	pd::MutexHold h = FM::snapshot();
	EXPECT_EQ(h.holds, 100u);
	EXPECT_EQ(h.p99Us, 15u);
	EXPECT_EQ(h.maxUs, 50000u);

	// Two long holds push rank 99 into the long bucket (32768..65535). Its top
	// edge is above the largest hold seen, so p99 is clamped to the max.
	FM::resetForTest();
	for (int i = 0; i < 98; ++i) FM::record(10, 0x1000);
	FM::record(50000, 0x2000);
	FM::record(50000, 0x2000);
	h = FM::snapshot();
	EXPECT_EQ(h.p99Us, 50000u);

	// Every hold the same: the bucket edge (4095) is clamped to the real value.
	FM::resetForTest();
	for (int i = 0; i < 100; ++i) FM::record(3000, 0x1000);
	EXPECT_EQ(FM::snapshot().p99Us, 3000u);

	FM::resetForTest();
	h = FM::snapshot();
	EXPECT_EQ(h.holds, 0u);
	EXPECT_EQ(h.p99Us, 0u);
	EXPECT_EQ(h.maxUs, 0u);
}

TEST_F(TimedMutexTest, OnlyAHoldAboveTwentyMillisecondsCountsAsOver)
{
	pd::SlowSite s;
	FM::record(19999, 0x1000);
	FM::record(20000, 0x1000);   // exactly 20 ms is not over it
	EXPECT_EQ(FM::snapshot().over, 0u);
	EXPECT_FALSE(FM::takeSlowSite(s));

	FM::record(20001, 0x1000);
	EXPECT_EQ(FM::snapshot().over, 1u);
	ASSERT_TRUE(FM::takeSlowSite(s));
	EXPECT_EQ(s.pc, 0x1000u);
	EXPECT_EQ(s.maxUs, 20001u);
}

TEST_F(TimedMutexTest, TheWitnessFiresOncePerSitePerBoot)
{
	FM m;
	pd::SlowSite s;

	// Site A: over, short, over again.
	holdAtSiteA(m, 30000);
	ASSERT_TRUE(FM::takeSlowSite(s)) << "the first hold over 20 ms names its site";
	EXPECT_EQ(s.maxUs, 30000u);
	const uintptr_t sitePc = s.pc;
	EXPECT_NE(sitePc, 0u);

	holdAtSiteA(m, 5);
	EXPECT_FALSE(FM::takeSlowSite(s));
	holdAtSiteA(m, 45000);
	EXPECT_FALSE(FM::takeSlowSite(s)) << "a second hold over 20 ms from a site already reported";
	EXPECT_EQ(FM::snapshot().over, 2u);   // the cap limits the witness, not the count

	// A different call site is a different site: one more witness, not zero.
	holdAtSiteB(m, 25000);
	ASSERT_TRUE(FM::takeSlowSite(s));
	EXPECT_NE(s.pc, sitePc);
	EXPECT_EQ(s.maxUs, 25000u);
	EXPECT_FALSE(FM::takeSlowSite(s));

	// And A stays quiet for the rest of the boot.
	holdAtSiteA(m, 60000);
	EXPECT_FALSE(FM::takeSlowSite(s));
	EXPECT_EQ(FM::snapshot().over, 4u);
}

TEST_F(TimedMutexTest, MaxHoldAndMaxPcMoveOnlyForAStrictlyLongerHold)
{
	FM::record(100, 0x1000);
	EXPECT_EQ(FM::snapshot().maxUs, 100u);
	EXPECT_EQ(FM::snapshot().maxPc, 0x1000u);

	FM::record(100, 0x2000);   // equal: not a new max
	EXPECT_EQ(FM::snapshot().maxPc, 0x1000u);
	FM::record(99, 0x3000);    // shorter
	EXPECT_EQ(FM::snapshot().maxPc, 0x1000u);
	EXPECT_EQ(FM::snapshot().maxUs, 100u);

	FM::record(101, 0x4000);
	EXPECT_EQ(FM::snapshot().maxUs, 101u);
	EXPECT_EQ(FM::snapshot().maxPc, 0x4000u);
}

TEST_F(TimedMutexTest, LockGuardUniqueLockAndTryToLockAllRecordTheirHolds)
{
	FM m;
	{
		std::lock_guard<FM> g(m);
		FakeClock::now += 7;
	}
	EXPECT_EQ(FM::snapshot().holds, 1u);
	EXPECT_NE(FM::snapshot().maxPc, 0u);

	{
		std::unique_lock<FM> u(m);
		FakeClock::now += 9;
		u.unlock();                  // forceDisconnect() unlocks mid-scope
		FakeClock::now += 5000;      // not held: must not be counted
		u.lock();
		FakeClock::now += 3;
	}
	pd::MutexHold h = FM::snapshot();
	EXPECT_EQ(h.holds, 3u);
	EXPECT_EQ(h.maxUs, 9u);

	// A failed try_to_lock holds nothing and records nothing; a successful one is a hold.
	std::atomic<bool> held{false}, release{false};
	std::thread other([&] {
		m.lock();
		held = true;
		while (!release) std::this_thread::yield();
		m.unlock();
	});
	while (!held) std::this_thread::yield();
	{
		std::unique_lock<FM> u(m, std::try_to_lock);
		EXPECT_FALSE(u.owns_lock());
	}
	release = true;
	other.join();
	EXPECT_EQ(FM::snapshot().holds, 4u);   // the other thread's hold, nothing for the failed try

	{
		std::unique_lock<FM> u(m, std::try_to_lock);
		ASSERT_TRUE(u.owns_lock());
		FakeClock::now += 11;
	}
	EXPECT_EQ(FM::snapshot().holds, 5u);
}

TEST(RequestsHandlerMutexHold, TickWitnessesASlowHoldOncePerSiteAfterItsLockScope)
{
	RequestsHandler h("10.0.0.1", 5060, [](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	pd::TimedMutex::resetForTest();
	pdwitness::clear();

	// ONE call site for the hold, so both holds are the same site.
	for (int i = 0; i < 2; ++i)
	{
		h.holdMutexForTest(std::chrono::milliseconds(30));
		// The unlock only records. A line appears when tick() runs, never before.
		EXPECT_EQ(pdwitness::count("_mutex held"), static_cast<size_t>(i));
		h.forceNextTickForTest();
		h.tick();
		EXPECT_EQ(pdwitness::count("_mutex held"), 1u) << "pass " << i;
	}

	const pd::MutexHold m = h.getMutexHold();
	EXPECT_GE(m.over, 2u);
	EXPECT_GE(m.maxUs, 30000u);
	EXPECT_GT(m.holds, 2u) << "tick() and the hold seam both take _mutex";
	for (const std::string& line : pdwitness::lines())
	{
		if (line.find("_mutex held") == std::string::npos) continue;
		EXPECT_NE(line.find("0x"), std::string::npos) << line;
		EXPECT_NE(line.find("#986"), std::string::npos) << line;
	}
}
