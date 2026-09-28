// RxRestart_test.cpp -- issue #554, #575 review. The pure decisions behind
// TelephonyAnchorClient::startRxIfNeeded() (src/SIP/RxRestart.hpp); the anchor
// client itself is ESP-only.

#include <gtest/gtest.h>

#include <string>

#include "RxRestart.hpp"

using pd::RxStart;
using pd::rxRestartDecision;

TEST(RxRestart, NoHandleStartsAndALiveOrTearingDownTaskIsLeftAlone)
{
	EXPECT_EQ(rxRestartDecision(false, false, false, false), RxStart::Start);
	EXPECT_EQ(rxRestartDecision(true, true, false, false), RxStart::AlreadyPolling);
	EXPECT_EQ(rxRestartDecision(true, false, true, false), RxStart::AlreadyPolling)
		<< "teardown owns the slot; never restart under it";
	EXPECT_EQ(rxRestartDecision(true, true, true, false), RxStart::AlreadyPolling);
}

TEST(RxRestart, AnExitedTaskIsReplacedOnlyOnceItsDoneSemIsTaken)
{
	// The #575 review's race: rxRunning is clear but the task has not given its
	// done-sem yet, so it still touches the slot. Restarting there deleted the
	// sem under it and put a second task on the slot.
	EXPECT_EQ(rxRestartDecision(true, false, false, false), RxStart::StillExiting);
	EXPECT_EQ(rxRestartDecision(true, false, false, true), RxStart::Restart);
}

TEST(RxRestart, ADroppedLegIsRefusedAnotherIsNot)
{
	RecentIdRing<8, 64> dropped;
	dropped.add("leg-554");
	EXPECT_FALSE(pd::rxStartAllowedFor(dropped, "leg-554"))
		<< "a late upsert for a leg we dropped must not get a fresh rx task";
	EXPECT_TRUE(pd::rxStartAllowedFor(dropped, "leg-555"));
	EXPECT_TRUE(pd::rxStartAllowedFor(dropped, "leg-55"))
		<< "a prefix of a dropped id is a different leg";
	// Bounded: after 8 newer drops the oldest is forgotten (documented bound).
	for (int i = 0; i < 8; ++i) dropped.add("newer-" + std::to_string(i));
	EXPECT_TRUE(pd::rxStartAllowedFor(dropped, "leg-554"));
}

TEST(RxRestart, ASlotWithALiveRxTaskIsNotAllocatable)
{
	// Issue #553: a task detached on a join timeout (or not yet parked) still owns its
	// slot. Handing that slot to a new call would put two rx tasks on one slot, the
	// #370 crash. Only a free slot whose old task is gone (Nothing) or was just reaped
	// (Reap) may be allocated.
	EXPECT_FALSE(pd::rxSlotAllocatable(true, false, pd::ReapDecision::Wait))
		<< "free by participantId but its old rx task is still alive";
	EXPECT_TRUE(pd::rxSlotAllocatable(true, false, pd::ReapDecision::Nothing));
	EXPECT_TRUE(pd::rxSlotAllocatable(true, false, pd::ReapDecision::Reap));
}

TEST(RxRestart, ABusyOrTearingDownSlotIsNeverAllocatable)
{
	// Positive control for the test above: the other two conditions still refuse
	// on their own, whatever the reap says.
	EXPECT_FALSE(pd::rxSlotAllocatable(false, false, pd::ReapDecision::Nothing)) << "owned by a participant";
	EXPECT_FALSE(pd::rxSlotAllocatable(true, true, pd::ReapDecision::Nothing)) << "mid-teardown";
}

TEST(RxRestart, AReapedDetachedTaskIsTakenBackOutOfTheRestartCount)
{
	// #608 review: a join-timeout detach is counted toward the #65 anchor restart,
	// but only while that task is alive. Reaping it must take it back out.
	int detachedCount = 0;
	bool slotDetached = false;

	++detachedCount;           // stopMediaStreams(): join timed out, detach
	slotDetached = true;
	detachedCount += pd::detachCountDeltaOnReap(slotDetached);   // later reaped

	EXPECT_EQ(detachedCount, 0);
	EXPECT_FALSE(slotDetached);
	EXPECT_EQ(pd::detachCountDeltaOnReap(slotDetached), 0) << "a slot is taken out once only";
}

TEST(RxRestart, ThreeBenignDetachesNeverRequestARestart)
{
	// The restart drops every live call, so three detaches that each ended in a
	// clean reap must never reach the threshold (kLeakRestartThreshold = 3).
	constexpr int kThreshold = 3;
	int detachedCount = 0;
	bool slotDetached = false;
	for (int i = 0; i < kThreshold; ++i)
	{
		++detachedCount;
		slotDetached = true;
		EXPECT_LT(detachedCount, kThreshold) << "cycle " << i;
		detachedCount += pd::detachCountDeltaOnReap(slotDetached);
	}
	EXPECT_EQ(detachedCount, 0);
}
