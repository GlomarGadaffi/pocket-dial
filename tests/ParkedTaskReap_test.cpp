// ParkedTaskReap_test.cpp -- issue #535 / #572 review. The owner of a media
// task that parks itself may delete it ONLY once it has cleared its running
// flag and is suspended; anything else is Wait (keep the handle, retry).

#include <gtest/gtest.h>

#include "ParkedTaskReap.hpp"

using pd::ReapDecision;
using pd::reapDecision;

TEST(ParkedTaskReap, NoHandleMeansTheSlotIsFree)
{
	EXPECT_EQ(reapDecision(false, false, false), ReapDecision::Nothing);
	EXPECT_EQ(reapDecision(false, true, true), ReapDecision::Nothing);
}

TEST(ParkedTaskReap, OnlyAFinishedSuspendedTaskIsReaped)
{
	EXPECT_EQ(reapDecision(true, /*running=*/false, /*suspended=*/true), ReapDecision::Reap);
}

TEST(ParkedTaskReap, ARunningOrNotYetSuspendedTaskIsNeverDeleted)
{
	// The #572 review's cases: the old code deleted after a timeout whatever
	// the state, which could kill a task holding _slotMutex.
	EXPECT_EQ(reapDecision(true, /*running=*/true, /*suspended=*/false), ReapDecision::Wait)
		<< "still running";
	EXPECT_EQ(reapDecision(true, /*running=*/false, /*suspended=*/false), ReapDecision::Wait)
		<< "cleared its flag but not yet parked (between the store and vTaskSuspend)";
	EXPECT_EQ(reapDecision(true, /*running=*/true, /*suspended=*/true), ReapDecision::Wait)
		<< "suspended while its flag says running: not at the park loop";
}
