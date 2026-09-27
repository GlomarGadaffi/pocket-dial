// AllocCounter_test.cpp — positive controls for the shared counting operator new
// (tests/support/AllocCounter). Every "delta() == 0" assertion elsewhere in the
// binary is only meaningful if the counter demonstrably moves when it should, so
// these fail if counting is ever broken or silently stops being per-thread.
//
// Two rules every test here follows, both learned the hard way:
//  * Each allocation escapes through g_sink. GCC at -O3 (CMake Release, which is
//    what CI builds) removes a new-expression whose result is never used, so an
//    unescaped control counts 0 in CI while passing in an unoptimized local build.
//  * Counters are read BEFORE any EXPECT. A failing EXPECT allocates while
//    formatting its message, which would show up as a second, misleading failure.

#include <gtest/gtest.h>

#include <atomic>
#include <cstdint>
#include <memory>
#include <new>
#include <thread>

#include "AllocCounter.hpp"

namespace
{
	void* volatile g_sink = nullptr;
}

TEST(AllocCounter, ANewOnThisThreadIsCounted)
{
	AllocGuard guard;
	auto p = std::make_unique<int>(7);
	g_sink = p.get();
	const std::size_t d = guard.delta();
	EXPECT_EQ(d, 1u);
}

TEST(AllocCounter, ArrayNewIsCounted)
{
	AllocGuard guard;
	std::unique_ptr<char[]> p(new char[64]);
	g_sink = p.get();
	const std::size_t d = guard.delta();
	EXPECT_EQ(d, 1u);
}

TEST(AllocCounter, OverAlignedNewIsCounted)
{
	// Above __STDCPP_DEFAULT_NEW_ALIGNMENT__ (16 on x86-64), so this goes through
	// operator new(std::size_t, std::align_val_t), not the plain overload.
	struct alignas(64) Wide { char c[64]; };
	static_assert(alignof(Wide) > __STDCPP_DEFAULT_NEW_ALIGNMENT__, "not over-aligned");
	AllocGuard guard;
	auto one = std::make_unique<Wide>();
	g_sink = one.get();
	std::unique_ptr<Wide[]> many(new Wide[3]);
	g_sink = many.get();
	const std::size_t d = guard.delta();
	EXPECT_EQ(d, 2u);
	EXPECT_EQ(reinterpret_cast<std::uintptr_t>(one.get()) % 64u, 0u);
	EXPECT_EQ(reinterpret_cast<std::uintptr_t>(many.get()) % 64u, 0u);
}

TEST(AllocCounter, NothrowNewIsCounted)
{
	AllocGuard guard;
	std::unique_ptr<int> p(new (std::nothrow) int(3));
	g_sink = p.get();
	const std::size_t d = guard.delta();
	ASSERT_NE(p, nullptr);
	EXPECT_EQ(d, 1u);
}

TEST(AllocCounter, AnotherThreadsAllocationIsInvisibleToThisThreadsGuard)
{
	// Gated, so the other thread allocates only AFTER this thread's snapshot. Then the
	// only way this thread's count can move is a counter that is not per-thread. An
	// ungated version passed ~1% of the time on a broken counter (Griot, 200 runs).
	std::atomic<bool> go{false};
	std::size_t otherThreadDelta = 0;
	const std::size_t globalBefore = heapAllocCount();

	std::thread t([&go, &otherThreadDelta] {
		while (!go.load(std::memory_order_acquire)) std::this_thread::yield();
		AllocGuard inner;
		auto q = std::make_unique<long>(1);
		g_sink = q.get();
		otherThreadDelta = inner.delta();
	});

	AllocGuard guard;   // after std::thread's own allocations, before the other thread's
	go.store(true, std::memory_order_release);
	t.join();
	const std::size_t mine = guard.delta();
	const std::size_t globalDelta = heapAllocCount() - globalBefore;

	EXPECT_EQ(otherThreadDelta, 1u);
	EXPECT_EQ(mine, 0u) << "the other thread's new leaked into this thread's count";
	EXPECT_GE(globalDelta, 1u) << "the process-wide counter missed the other thread";
}
