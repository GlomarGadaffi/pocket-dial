// #1162: psram::MallocScope asks IDF's malloc to serve allocations of
// kMallocScopeMinBytes and up from PSRAM while it is alive, and puts the board's
// own threshold back when the last scope ends. The anchor's HTTP and WebSocket
// clients are created inside one, so their 4096 B buffers stop living in
// internal DRAM. On the host the threshold is a recorded number; these tests
// pin the numbers the device arm passes to heap_caps_malloc_extmem_enable().

#include <gtest/gtest.h>

#include "PsramAllocator.hpp"

TEST(PsramMallocScope, AppliesTheLowerThresholdWhileAliveAndRestoresIt)
{
	ASSERT_EQ(psram::kMallocDefaultInternalLimit, psram::appliedMallocInternalLimit());
	{
		psram::MallocScope scope;
		// IDF serves size <= limit from internal DRAM, so 4096 B needs 4095.
		EXPECT_EQ(psram::kMallocScopeMinBytes - 1, psram::appliedMallocInternalLimit());
	}
	EXPECT_EQ(psram::kMallocDefaultInternalLimit, psram::appliedMallocInternalLimit());
}

TEST(PsramMallocScope, AnInnerScopeEndingDoesNotRestoreUnderTheOuterOne)
{
	psram::MallocScope outer;
	{
		psram::MallocScope inner;
		EXPECT_EQ(psram::kMallocScopeMinBytes - 1, psram::appliedMallocInternalLimit());
	}
	// Positive control for the test above: the lower threshold is still in force.
	EXPECT_EQ(psram::kMallocScopeMinBytes - 1, psram::appliedMallocInternalLimit());
}

TEST(PsramMallocScope, TheThresholdCoversTheAnchorClientBuffers)
{
	// TelephonyAnchorClient sets buffer_size = 4096 on its HTTP and WebSocket
	// clients (pinned by tests/tools/test_anchor_client_buffers_psram.py). A
	// scope that started above that would move nothing.
	EXPECT_LE(psram::kMallocScopeMinBytes, static_cast<std::size_t>(4096));
	EXPECT_GT(psram::kMallocScopeMinBytes, static_cast<std::size_t>(1024));   // the 1 KB transmit buffers stay internal
	EXPECT_LT(psram::kMallocScopeMinBytes, psram::kMallocDefaultInternalLimit);
}
