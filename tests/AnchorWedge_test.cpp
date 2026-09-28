// AnchorWedge_test.cpp -- issue #667. tick() spawns the #100 reconcile watchdog
// for an outbound slot it counts as wedged. A leg the PBX already lists as
// Dialing is ringing, not wedged: it must not trigger a reconcile every 5 s.

#include <gtest/gtest.h>

#include "AnchorWedge.hpp"

using pd::anchorSlotLooksWedged;
using pd::kAnchorRingingGraceUs;
using pd::kAnchorWedgeGraceUs;

namespace
{
	constexpr int64_t kSet = 1000000;   // makecall time (any non-zero value)
}

TEST(AnchorWedge, ARingingLegPastTheWedgeGraceIsNotWedged)
{
	// Positive control first: the real #100 wedge (no leg listed) still fires.
	EXPECT_TRUE(anchorSlotLooksWedged(true, false, /*ringing=*/false, kSet, kSet + kAnchorWedgeGraceUs));
	// 45 s of ringing, as seen on .244: not a wedge.
	EXPECT_FALSE(anchorSlotLooksWedged(true, false, /*ringing=*/true, kSet, kSet + 45LL * 1000000));
	// A listed leg that outlives the ringing grace is checked again.
	EXPECT_TRUE(anchorSlotLooksWedged(true, false, /*ringing=*/true, kSet, kSet + kAnchorRingingGraceUs));
}

TEST(AnchorWedge, WithinTheGraceOrLiveOrIdleIsNotWedged)
{
	EXPECT_FALSE(anchorSlotLooksWedged(true, false, false, kSet, kSet + kAnchorWedgeGraceUs - 1));
	EXPECT_FALSE(anchorSlotLooksWedged(true, /*postLive=*/true, false, kSet, kSet + kAnchorRingingGraceUs));
	EXPECT_FALSE(anchorSlotLooksWedged(/*outboundActive=*/false, false, false, kSet, kSet + kAnchorRingingGraceUs));
	EXPECT_FALSE(anchorSlotLooksWedged(true, false, false, /*setUs=*/0, kAnchorRingingGraceUs));
}
