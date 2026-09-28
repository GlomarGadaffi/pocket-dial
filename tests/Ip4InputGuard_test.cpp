// Ip4InputGuard_test.cpp -- issue #496 / #509 review. The IPv4 input guard's
// decision (src/Helpers/Ip4InputGuard.h), which the ESP-only lwIP hook
// (main/pd_lwip_hooks.c) applies before ip4_input() trims a frame. Pure: no
// lwIP here, just the header fields the hook reads.

#include <gtest/gtest.h>

#include "Ip4InputGuard.h"

namespace
{
	constexpr uint32_t kHdr = 20;   // IPv4 header, no options

	int unfragmented(uint32_t totLen, uint32_t ipLen)
	{
		return pd_ip4_input_verdict(totLen, ipLen, kHdr, /*moreFragments=*/0);
	}
}

TEST(Ip4InputGuard, OrdinaryAndMinimumPaddedFramesPass)
{
	EXPECT_EQ(unfragmented(1500, 1500), PD_IP4_PASS);
	EXPECT_EQ(unfragmented(200, 200), PD_IP4_PASS);
	// A 28-byte datagram (empty UDP) in a minimum Ethernet frame: padded to 46.
	EXPECT_EQ(unfragmented(46, 28), PD_IP4_PASS);
	// ...with a driver that leaves the 4-byte FCS on.
	EXPECT_EQ(unfragmented(50, 28), PD_IP4_PASS);
	EXPECT_EQ(unfragmented(1504, 1500), PD_IP4_PASS);
}

TEST(Ip4InputGuard, PaddingBeyondEthernetsMinimumIsDropped)
{
	// The #509 review's attack: a full-size frame whose IP header claims 92 B.
	// Trimmed, it would count 72 B of payload against SO_RCVBUF while pinning
	// the whole 1,514 B driver buffer.
	EXPECT_EQ(pd_ip4_input_verdict(1500, 92, kHdr, 1), PD_IP4_DROP_PADDED);
	EXPECT_EQ(unfragmented(1500, 92), PD_IP4_DROP_PADDED)
		<< "unfragmented too: the pin is the same without reassembly";
	EXPECT_EQ(unfragmented(51, 28), PD_IP4_DROP_PADDED) << "one byte past the slack";
	EXPECT_EQ(unfragmented(1505, 1500), PD_IP4_DROP_PADDED);
}

TEST(Ip4InputGuard, ShortNonFinalFragmentsAreDroppedEverythingElsePasses)
{
	// A real non-final fragment at the Ethernet MTU passes to reassembly as is:
	// the driver buffer is the frame's own size, so nothing needs copying.
	EXPECT_EQ(pd_ip4_input_verdict(1500, 1500, kHdr, 1), PD_IP4_PASS);
	// The final fragment (MF clear) may be any size.
	EXPECT_EQ(pd_ip4_input_verdict(46, 28, kHdr, 0), PD_IP4_PASS);
	// A non-final fragment under 256 B of payload: dropped, the cheapest
	// per-pbuf overhead multiplier against the byte cap.
	EXPECT_EQ(pd_ip4_input_verdict(120, 120, kHdr, 1), PD_IP4_DROP_TINY_FRAGMENT);
	EXPECT_EQ(pd_ip4_input_verdict(kHdr + 255, kHdr + 255, kHdr, 1), PD_IP4_DROP_TINY_FRAGMENT);
	EXPECT_EQ(pd_ip4_input_verdict(kHdr + 256, kHdr + 256, kHdr, 1), PD_IP4_PASS);
	// IP options count in the header, not the payload.
	EXPECT_EQ(pd_ip4_input_verdict(24 + 255, 24 + 255, 24, 1), PD_IP4_DROP_TINY_FRAGMENT);
}
