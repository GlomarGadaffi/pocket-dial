// TxSlotPool_test.cpp -- issue #479 (desmo: option D). rtp_media_tx stacks are a
// fixed pool shared by every RtpSender, sized to the concurrent media streams,
// not one per object. A stream claims a slot on start() and returns it after
// its parked task is reaped. Pool exhausted -> the start is refused and
// counted; nothing ever falls back to the heap.

#include <gtest/gtest.h>

#include "SlotPool.hpp"

TEST(TxSlotPool, ClaimsEachSlotOnceThenRefusesAndCounts)
{
	pd::SlotPool<3> pool;
	bool seen[3] = {};
	for (int i = 0; i < 3; ++i)
	{
		const int s = pool.claim();
		ASSERT_GE(s, 0);
		ASSERT_LT(s, 3);
		EXPECT_FALSE(seen[s]) << "slot " << s << " handed out twice";
		seen[s] = true;
	}
	EXPECT_EQ(pool.inUse(), 3);
	EXPECT_EQ(pool.refused(), 0u);
	EXPECT_EQ(pool.claim(), -1);
	EXPECT_EQ(pool.claim(), -1);
	EXPECT_EQ(pool.refused(), 2u);
}

TEST(TxSlotPool, AReturnedSlotIsClaimedAgain)
{
	pd::SlotPool<2> pool;
	const int a = pool.claim();
	const int b = pool.claim();
	ASSERT_GE(a, 0);
	ASSERT_GE(b, 0);
	pool.release(a);
	EXPECT_EQ(pool.inUse(), 1);
	EXPECT_EQ(pool.claim(), a);
	EXPECT_EQ(pool.claim(), -1);
}

TEST(TxSlotPool, BadOrRepeatedReleaseCannotFreeAnotherSlot)
{
	pd::SlotPool<2> pool;
	const int a = pool.claim();
	ASSERT_GE(a, 0);
	pool.release(-1);
	pool.release(2);
	pool.release(99);
	EXPECT_EQ(pool.inUse(), 1);
	pool.release(a);
	pool.release(a);   // double return: harmless
	EXPECT_EQ(pool.inUse(), 0);
}
