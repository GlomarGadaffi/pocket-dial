#include <gtest/gtest.h>
#include <set>
#include <thread>
#include <vector>
#include <atomic>

#include "DmaFramePool.hpp"

using namespace l2rtp;

class DmaFramePoolTest : public ::testing::Test
{
protected:
	void SetUp() override
	{
		DmaFramePool::init();
		DmaFramePool::resetStats();
	}
};

TEST_F(DmaFramePoolTest, InitialStateHasFullCapacity)
{
	EXPECT_EQ(DmaFramePool::available(), DmaFramePool::kPoolSize);
	EXPECT_EQ(DmaFramePool::getExhaustions(), 0u);
	EXPECT_EQ(DmaFramePool::getAllocations(), 0u);
}

TEST_F(DmaFramePoolTest, AcquireAllocatesDistinctAlignedBuffers)
{
	std::vector<DmaFramePool::Handle> handles;
	std::set<void*> uniqueAddresses;

	for (size_t i = 0; i < DmaFramePool::kPoolSize; ++i)
	{
		auto h = DmaFramePool::acquire();
		ASSERT_TRUE(static_cast<bool>(h)) << "Acquire failed on index " << i;
		ASSERT_NE(h.data(), nullptr);
		ASSERT_NE(h.buffer(), nullptr);

		// Check 4-byte alignment
		EXPECT_EQ(reinterpret_cast<uintptr_t>(h.data()) % 4, 0u);

		uniqueAddresses.insert(h.data());
		handles.push_back(std::move(h));
	}

	EXPECT_EQ(uniqueAddresses.size(), DmaFramePool::kPoolSize);
	EXPECT_EQ(DmaFramePool::available(), 0u);
	EXPECT_EQ(DmaFramePool::getAllocations(), DmaFramePool::kPoolSize);
	EXPECT_EQ(DmaFramePool::getExhaustions(), 0u);
}

TEST_F(DmaFramePoolTest, ExhaustionReturnsNullHandleAndIncrementsCounter)
{
	std::vector<DmaFramePool::Handle> handles;
	for (size_t i = 0; i < DmaFramePool::kPoolSize; ++i)
	{
		handles.push_back(DmaFramePool::acquire());
	}

	EXPECT_EQ(DmaFramePool::available(), 0u);

	// The (kPoolSize + 1)-th acquire must fail fast
	auto starved = DmaFramePool::acquire();
	EXPECT_FALSE(static_cast<bool>(starved));
	EXPECT_EQ(starved.data(), nullptr);
	EXPECT_EQ(starved.buffer(), nullptr);
	EXPECT_EQ(DmaFramePool::getExhaustions(), 1u);

	// Another attempt also fails fast
	auto starved2 = DmaFramePool::acquire();
	EXPECT_FALSE(static_cast<bool>(starved2));
	EXPECT_EQ(DmaFramePool::getExhaustions(), 2u);
}

TEST_F(DmaFramePoolTest, HandleReleaseRecyclesBufferImmediately)
{
	{
		auto h = DmaFramePool::acquire();
		EXPECT_TRUE(static_cast<bool>(h));
		EXPECT_EQ(DmaFramePool::available(), DmaFramePool::kPoolSize - 1);
	}
	// h is out of scope and released
	EXPECT_EQ(DmaFramePool::available(), DmaFramePool::kPoolSize);

	// Acquire again succeeds
	auto h2 = DmaFramePool::acquire();
	EXPECT_TRUE(static_cast<bool>(h2));
	EXPECT_EQ(DmaFramePool::available(), DmaFramePool::kPoolSize - 1);
}

TEST_F(DmaFramePoolTest, MoveSemanticsTransferOwnershipCorrectly)
{
	auto h1 = DmaFramePool::acquire();
	ASSERT_TRUE(static_cast<bool>(h1));
	uint8_t* ptr = h1.data();

	// Move construct
	DmaFramePool::Handle h2(std::move(h1));
	EXPECT_FALSE(static_cast<bool>(h1));
	EXPECT_EQ(h1.data(), nullptr);
	EXPECT_TRUE(static_cast<bool>(h2));
	EXPECT_EQ(h2.data(), ptr);

	// Move assign
	DmaFramePool::Handle h3;
	h3 = std::move(h2);
	EXPECT_FALSE(static_cast<bool>(h2));
	EXPECT_TRUE(static_cast<bool>(h3));
	EXPECT_EQ(h3.data(), ptr);

	// Releasing h3 returns buffer
	h3.release();
	EXPECT_FALSE(static_cast<bool>(h3));
	EXPECT_EQ(DmaFramePool::available(), DmaFramePool::kPoolSize);
}

TEST_F(DmaFramePoolTest, ConcurrentAcquireAndReleaseStress)
{
	constexpr int kIterations = 1000;
	std::atomic<bool> start{false};
	std::atomic<int> completed{0};

	auto worker = [&]()
	{
		while (!start.load(std::memory_order_acquire)) {}

		for (int i = 0; i < kIterations; ++i)
		{
			auto h = DmaFramePool::acquire();
			if (h)
			{
				// Simulate brief payload write
				h.data()[0] = 0x80;
			}
		}
		completed.fetch_add(1);
	};

	std::thread t1(worker);
	std::thread t2(worker);
	std::thread t3(worker);
	std::thread t4(worker);

	start.store(true, std::memory_order_release);

	t1.join();
	t2.join();
	t3.join();
	t4.join();

	EXPECT_EQ(completed.load(), 4);
	// When all threads exit, all borrowed buffers must have been returned
	EXPECT_EQ(DmaFramePool::available(), DmaFramePool::kPoolSize);
}
