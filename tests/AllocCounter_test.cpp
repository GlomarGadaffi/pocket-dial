// AllocCounter_test.cpp — positive controls for the shared counting operator new
// (tests/support/AllocCounter). Every "delta() == 0" assertion elsewhere in the
// binary is only meaningful if the counter demonstrably moves when it should, so
// these fail if counting is ever broken or silently stops being per-thread.

#include <gtest/gtest.h>

#include <memory>
#include <thread>

#include "AllocCounter.hpp"

TEST(AllocCounter, ANewOnThisThreadIsCounted)
{
	AllocGuard guard;
	auto p = std::make_unique<int>(7);
	EXPECT_EQ(*p, 7);
	EXPECT_EQ(guard.delta(), 1u);
}

TEST(AllocCounter, ArrayNewIsCounted)
{
	AllocGuard guard;
	std::unique_ptr<char[]> p(new char[64]);
	p[0] = 'x';
	EXPECT_EQ(guard.delta(), 1u);
}

TEST(AllocCounter, AnotherThreadsAllocationIsInvisibleToThisThreadsGuard)
{
	AllocGuard guard;
	const std::size_t globalBefore = heapAllocCount();
	std::size_t otherThreadDelta = 0;
	std::thread t([&otherThreadDelta] {
		AllocGuard inner;
		auto q = std::make_unique<long>(1);
		(void)q;
		otherThreadDelta = inner.delta();
	});
	const std::size_t sinceSpawn = guard.delta();   // std::thread itself may allocate here
	t.join();

	EXPECT_EQ(otherThreadDelta, 1u);
	EXPECT_EQ(guard.delta(), sinceSpawn) << "the other thread's new leaked into this thread's count";
	EXPECT_GE(heapAllocCount() - globalBefore, 1u) << "the process-wide counter missed the other thread";
}
