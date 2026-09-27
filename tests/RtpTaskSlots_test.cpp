// RtpTaskSlots_test.cpp -- issue #479. The RTP media tasks run on stacks
// preallocated per slot (one per RtpSender/RtpReceiver object), so the boot
// cost is fixed by the caps. Pin the slot counts to the members that own them
// and the stated cost: tx slots x 6 KB internal, rx slots x 6 KB PSRAM.

#include <gtest/gtest.h>

#include "RtpTaskSlots.hpp"

TEST(RtpTaskSlots, SlotCountsFollowTheCaps)
{
	// tx: _rtpSender + _anchorRtpSenders + _vmRtpSenders + conference legs.
	EXPECT_EQ(pd::rtpslots::kTxSlots,
		1 + POCKETDIAL_MAX_ANCHOR_CALLS + POCKETDIAL_MAX_VOICEMAIL_LEGS + POCKETDIAL_CONF_LEGS);
	// rx: _anchorRtpReceivers + _vmRtpReceivers + _trunkRx + _handsetRx + conference legs.
	EXPECT_EQ(pd::rtpslots::kRxSlots,
		POCKETDIAL_MAX_ANCHOR_CALLS + POCKETDIAL_MAX_VOICEMAIL_LEGS
		+ 2 * POCKETDIAL_MAX_TRUNK_CALLS + POCKETDIAL_CONF_LEGS);
}

TEST(RtpTaskSlots, BootCostIsSixKilobytesPerSlot)
{
	EXPECT_EQ(pd::rtpslots::kStackBytes, 6144u);
	EXPECT_EQ(pd::rtpslots::kTxInternalBytes, pd::rtpslots::kTxSlots * 6144u);
	EXPECT_EQ(pd::rtpslots::kRxPsramBytes, pd::rtpslots::kRxSlots * 6144u);
}

TEST(RtpTaskSlots, DefaultCapsCostIsStated)
{
	// Defaults (PoolConfig.hpp): 11 tx = 66 KB internal, 14 rx = 84 KB PSRAM.
	EXPECT_EQ(pd::rtpslots::kTxInternalBytes, 11u * 6144u);
	EXPECT_EQ(pd::rtpslots::kRxPsramBytes, 14u * 6144u);
}
