// L2IngressVerdict_test.cpp -- issue #1145. The pure L2 ingress verdict
// (src/Helpers/L2IngressVerdict.h): one table row per case. The rule order is
// the property under test, so most rows set every flag a LATER rule would act
// on; a row then fails if the rule it names is removed.

#include <gtest/gtest.h>

#include "L2IngressVerdict.h"

namespace
{
	constexpr uint32_t ip(uint32_t a, uint32_t b, uint32_t c, uint32_t d)
	{
		return (a << 24) | (b << 16) | (c << 8) | d;
	}

	constexpr uint32_t kOur = ip(192, 168, 12, 244);
	constexpr uint32_t kMask = ip(255, 255, 255, 0);
	constexpr uint32_t kGw = ip(192, 168, 12, 1);
	constexpr uint32_t kLan = ip(192, 168, 12, 50);   // on-link, not the gateway
	constexpr uint32_t kWan = ip(203, 0, 113, 7);     // off-link

	// A known IPv4 UDP/TCP frame whose source MAC is visible and the gateway
	// MAC pinned, unchanged.
	constexpr uint32_t kBase = PD_L2F_IP4_UDP_TCP | PD_L2F_MAC_VISIBLE | PD_L2F_GW_MAC_PINNED;
	// On-link source arriving with the gateway's MAC.
	constexpr uint32_t kGwMac = kBase | PD_L2F_SRC_MAC_IS_GW;
	// Off-link source to a listed service port.
	constexpr uint32_t kSvc = kBase | PD_L2F_SERVICE_PORT;

	struct Row
	{
		const char *name;
		uint32_t ourIp, mask, gateway, srcIp, dstIp, flags;
		int want;
	};

	const Row kRows[] = {
		// 1. Unknown state defers.
		// dst equals the unknown ourIp, so only rule 1 keeps it from WAN_SERVICE.
		{"UnknownOurIp", 0, kMask, kGw, kWan, 0, kSvc, PD_L2_DEFER},
		{"UnknownMask", kOur, 0, kGw, kLan, kOur, kGwMac, PD_L2_DEFER},
		{"UnknownGateway", kOur, kMask, 0, kLan, kOur, kGwMac, PD_L2_DEFER},
		{"NonFirstFragment", kOur, kMask, kGw, kWan, kOur, kSvc | PD_L2F_NON_FIRST_FRAGMENT, PD_L2_DEFER},
		{"NotIp4UdpTcp", kOur, kMask, kGw, kWan, kOur, kSvc & ~PD_L2F_IP4_UDP_TCP, PD_L2_DEFER},
		{"EmergencyWithUnknownStateStillDefers", 0, kMask, kGw, kWan, kOur, kSvc | PD_L2F_EMERGENCY,
			PD_L2_DEFER},
		// 2. Emergency or callback window passes, ahead of every later rule.
		{"EmergencyMartian", kOur, kMask, kGw, ip(127, 0, 0, 9), kOur, kSvc | PD_L2F_EMERGENCY, PD_L2_PASS},
		{"EmergencyLanGwMac", kOur, kMask, kGw, kLan, kOur, kGwMac | PD_L2F_EMERGENCY, PD_L2_PASS},
		{"EmergencyWanService", kOur, kMask, kGw, kWan, kOur, kSvc | PD_L2F_EMERGENCY, PD_L2_PASS},
		{"CallbackWindowWanService", kOur, kMask, kGw, kWan, kOur, kSvc | PD_L2F_CALLBACK_WINDOW, PD_L2_PASS},
		{"CallbackWindowMartian", kOur, kMask, kGw, ip(0, 1, 2, 3), kOur, kSvc | PD_L2F_CALLBACK_WINDOW,
			PD_L2_PASS},
		// 3. Trunk peer passes.
		{"TrunkPeerWanService", kOur, kMask, kGw, kWan, kOur, kSvc | PD_L2F_TRUNK_PEER, PD_L2_PASS},
		{"TrunkPeerMartian", kOur, kMask, kGw, ip(240, 0, 0, 1), kOur, kSvc | PD_L2F_TRUNK_PEER, PD_L2_PASS},
		// 4. Broadcast/multicast destination defers. Off-link, a destination
		// that is not ours already defers in rule 7, so the rows that prove
		// rule 4 use an on-link source with the gateway's MAC: without the
		// rule each would reach LAN_GW_MAC.
		{"DhcpDiscoverBroadcast", kOur, kMask, kGw, 0, 0xFFFFFFFFu, kSvc | PD_L2F_DST_BCAST_MCAST,
			PD_L2_DEFER},
		{"MulticastDestination", kOur, kMask, kGw, kLan, ip(224, 0, 0, 251), kGwMac | PD_L2F_DST_BCAST_MCAST,
			PD_L2_DEFER},
		// No caller flag: derived from dstIp and mask.
		{"SubnetDirectedBroadcast", kOur, kMask, kGw, kLan, ip(192, 168, 12, 255), kGwMac, PD_L2_DEFER},
		{"LimitedBroadcastNoFlag", kOur, kMask, kGw, kLan, 0xFFFFFFFFu, kGwMac, PD_L2_DEFER},
		{"MulticastNoFlag", kOur, kMask, kGw, kLan, ip(239, 255, 255, 250), kGwMac, PD_L2_DEFER},
		// 5. Martian source to our unicast.
		{"MartianZeroNet", kOur, kMask, kGw, ip(0, 1, 2, 3), kOur, kBase, PD_L2_WOULD_DROP_MARTIAN},
		{"MartianLoopback", kOur, kMask, kGw, ip(127, 0, 0, 1), kOur, kBase, PD_L2_WOULD_DROP_MARTIAN},
		{"MartianClassE", kOur, kMask, kGw, ip(240, 0, 0, 1), kOur, kBase, PD_L2_WOULD_DROP_MARTIAN},
		{"Martian255Source", kOur, kMask, kGw, ip(255, 1, 2, 3), kOur, kBase, PD_L2_WOULD_DROP_MARTIAN},
		// To another unicast it is not martian: off-link, unlisted port, so DEFER.
		{"MartianToOtherUnicast", kOur, kMask, kGw, ip(127, 0, 0, 1), kLan, kBase, PD_L2_DEFER},
		// 6. On-link source.
		{"OnLinkNormalMac", kOur, kMask, kGw, kLan, kOur, kBase, PD_L2_PASS},
		{"OnLinkSourceWithGatewayMac", kOur, kMask, kGw, kLan, kOur, kGwMac, PD_L2_WOULD_DROP_LAN_GW_MAC},
		{"GatewayIpWithGatewayMac", kOur, kMask, kGw, kGw, kOur, kGwMac, PD_L2_PASS},
		{"GatewayMacNotPinned", kOur, kMask, kGw, kLan, kOur, kGwMac & ~PD_L2F_GW_MAC_PINNED, PD_L2_PASS},
		{"GatewayMacPinChanged", kOur, kMask, kGw, kLan, kOur, kGwMac | PD_L2F_GW_MAC_CHANGED, PD_L2_PASS},
		{"MacNotVisible", kOur, kMask, kGw, kLan, kOur, kGwMac & ~PD_L2F_MAC_VISIBLE, PD_L2_PASS},
		// 7. Off-link source.
		{"OffLinkInAcl", kOur, kMask, kGw, kWan, kOur, kSvc | PD_L2F_SRC_IN_ACL, PD_L2_PASS},
		{"OffLinkBoardOpenedFlow", kOur, kMask, kGw, kWan, kOur, kSvc | PD_L2F_OWN_FLOW, PD_L2_PASS},
		{"OffLinkUnlistedPort", kOur, kMask, kGw, kWan, kOur, kBase, PD_L2_DEFER},
		{"OffLinkListedPort", kOur, kMask, kGw, kWan, kOur, kSvc, PD_L2_WOULD_DROP_WAN_SERVICE},
		{"OffLinkListedPortNotToUs", kOur, kMask, kGw, kWan, kLan, kSvc, PD_L2_DEFER},
	};

	class L2IngressVerdict : public ::testing::TestWithParam<Row>
	{
	};
}

TEST_P(L2IngressVerdict, Row)
{
	const Row &r = GetParam();
	const pd_l2_frame_t f = {r.ourIp, r.mask, r.gateway, r.srcIp, r.dstIp, r.flags};
	EXPECT_EQ(pd_l2_ingress_verdict(&f), r.want);
}

INSTANTIATE_TEST_SUITE_P(L2Ingress, L2IngressVerdict, ::testing::ValuesIn(kRows),
	[](const ::testing::TestParamInfo<Row> &i) { return std::string(i.param.name); });
