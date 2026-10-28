// L2EthIngress_test.cpp -- issue #1145. The pure parts of the esp_eth input
// hook (main/pd_eth_ingress.c): the frame-facts parser (L2FrameFacts.h), the
// gateway MAC pin, the seqlock defer rule and the per-frame classify that ties
// them to pd_l2_ingress_verdict() (L2GwPin.h). Counting only: nothing here
// drops a frame.

#include <gtest/gtest.h>

#include <cstring>
#include <vector>

#include "L2GwPin.h"

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

	const uint8_t kMacA[6] = {0x02, 0, 0, 0, 0, 0xA};
	const uint8_t kMacB[6] = {0x02, 0, 0, 0, 0, 0xB};
	const uint8_t kMacOur[6] = {0x02, 0, 0, 0, 0, 0x1};

	struct Spec
	{
		const uint8_t *srcMac = kMacA;
		uint32_t srcIp = kLan, dstIp = kOur;
		uint8_t proto = 17;
		uint16_t sport = 5060, dport = 5061;
		uint16_t ethertype = 0x0800;
		int ihlWords = 5;
		uint16_t fragField = 0;   // flags + offset, as on the wire
		bool bcastDstMac = false;
	};

	void put16(std::vector<uint8_t> &b, size_t at, uint32_t v)
	{
		b[at] = uint8_t(v >> 8);
		b[at + 1] = uint8_t(v);
	}

	void put32(std::vector<uint8_t> &b, size_t at, uint32_t v)
	{
		put16(b, at, v >> 16);
		put16(b, at + 2, v & 0xFFFF);
	}

	std::vector<uint8_t> frame(const Spec &s)
	{
		const size_t ihl = size_t(s.ihlWords) * 4;
		std::vector<uint8_t> b(14 + (ihl < 20 ? 20 : ihl) + 8, 0);
		std::memset(b.data(), s.bcastDstMac ? 0xFF : 0, 6);
		if (!s.bcastDstMac) std::memcpy(b.data(), kMacOur, 6);
		std::memcpy(b.data() + 6, s.srcMac, 6);
		put16(b, 12, s.ethertype);
		b[14] = uint8_t(0x40 | (s.ihlWords & 0xF));
		put16(b, 14 + 2, uint32_t(b.size() - 14));
		put16(b, 14 + 6, s.fragField);
		b[14 + 9] = s.proto;
		put32(b, 14 + 12, s.srcIp);
		put32(b, 14 + 16, s.dstIp);
		put16(b, 14 + ihl, s.sport);
		put16(b, 14 + ihl + 2, s.dport);
		return b;
	}

	pd_l2_frame_t ours()
	{
		pd_l2_frame_t f{};
		f.ourIp = kOur;
		f.mask = kMask;
		f.gateway = kGw;
		return f;
	}

	struct Hook
	{
		pd_l2_gw_pin_t pin{};
		uint32_t gen = 2;
		int changes = 0;

		int feed(const Spec &s)
		{
			const std::vector<uint8_t> b = frame(s);
			pd_l2_frame_t f = ours();
			int changed = 0;
			const int v = pd_l2_eth_classify(b.data(), uint32_t(b.size()), gen, &f, &pin, &changed);
			changes += changed;
			return v;
		}

		// A frame from the gateway's IP with the given MAC.
		int fromGw(const uint8_t *mac)
		{
			Spec s;
			s.srcMac = mac;
			s.srcIp = kGw;
			return feed(s);
		}

		// An on-link, non-gateway source arriving with the given MAC.
		int fromLan(const uint8_t *mac)
		{
			Spec s;
			s.srcMac = mac;
			return feed(s);
		}
	};
}

// ── Gateway MAC pin ──────────────────────────────────────────────────────────

TEST(L2GwPin, NoPinMeansNoLanGwMac)
{
	Hook h;
	EXPECT_EQ(h.fromLan(kMacA), PD_L2_PASS);
	EXPECT_EQ(h.pin.state, PD_L2_PIN_NONE);
}

TEST(L2GwPin, OneGatewayFrameIsACandidateOnly)
{
	Hook h;
	h.fromGw(kMacA);
	EXPECT_EQ(h.pin.state, PD_L2_PIN_CANDIDATE);
	EXPECT_EQ(pd_l2_gw_pin_flags(&h.pin, kMacA), 0u);
	EXPECT_EQ(h.fromLan(kMacA), PD_L2_PASS);
}

TEST(L2GwPin, ASecondAgreeingFramePins)
{
	Hook h;
	h.fromGw(kMacA);
	h.fromGw(kMacA);
	EXPECT_EQ(h.pin.state, PD_L2_PIN_PINNED);
	EXPECT_EQ(0, std::memcmp(h.pin.mac, kMacA, 6));
	EXPECT_EQ(pd_l2_gw_pin_flags(&h.pin, kMacA), uint32_t(PD_L2F_GW_MAC_PINNED | PD_L2F_SRC_MAC_IS_GW));
	EXPECT_EQ(pd_l2_gw_pin_flags(&h.pin, kMacB), uint32_t(PD_L2F_GW_MAC_PINNED));
	EXPECT_EQ(h.changes, 0);
}

TEST(L2GwPin, ADisagreeingCandidateIsReplacedNotPinned)
{
	Hook h;
	h.fromGw(kMacA);
	h.fromGw(kMacB);
	EXPECT_EQ(h.pin.state, PD_L2_PIN_CANDIDATE);
	EXPECT_EQ(0, std::memcmp(h.pin.mac, kMacB, 6));
	EXPECT_EQ(h.changes, 0);
	h.fromGw(kMacB);   // the replacement pins on its own second frame
	EXPECT_EQ(h.pin.state, PD_L2_PIN_PINNED);
	EXPECT_EQ(0, std::memcmp(h.pin.mac, kMacB, 6));
}

TEST(L2GwPin, AChangeIsCountedAndThePinKept)
{
	Hook h;
	h.fromGw(kMacA);
	h.fromGw(kMacA);
	h.fromGw(kMacB);
	EXPECT_EQ(h.changes, 1);
	EXPECT_EQ(h.pin.state, PD_L2_PIN_CHANGED);
	EXPECT_EQ(0, std::memcmp(h.pin.mac, kMacA, 6));
	EXPECT_TRUE(pd_l2_gw_pin_flags(&h.pin, kMacA) & PD_L2F_GW_MAC_CHANGED);
	// While changed, the class is never counted.
	EXPECT_EQ(h.fromLan(kMacA), PD_L2_PASS);
}

TEST(L2GwPin, ASecondChangeIsCountedAgainWithNoRepin)
{
	Hook h;
	h.fromGw(kMacA);
	h.fromGw(kMacA);
	h.fromGw(kMacB);
	h.fromGw(kMacB);
	EXPECT_EQ(h.changes, 2);
	h.fromGw(kMacA);   // the pinned MAC again: no count, still changed
	EXPECT_EQ(h.changes, 2);
	EXPECT_EQ(h.pin.state, PD_L2_PIN_CHANGED);
	EXPECT_EQ(0, std::memcmp(h.pin.mac, kMacA, 6));
	EXPECT_EQ(h.fromLan(kMacA), PD_L2_PASS);
}

TEST(L2GwPin, ANewGenerationResetsAndCanPinAgain)
{
	Hook h;
	h.fromGw(kMacA);
	h.fromGw(kMacA);
	h.fromGw(kMacB);
	h.gen += 2;   // link up / DHCP bind
	h.fromGw(kMacB);
	EXPECT_EQ(h.pin.state, PD_L2_PIN_CANDIDATE);
	h.fromGw(kMacB);
	EXPECT_EQ(h.pin.state, PD_L2_PIN_PINNED);
	EXPECT_EQ(0, std::memcmp(h.pin.mac, kMacB, 6));
	EXPECT_EQ(h.fromLan(kMacB), PD_L2_WOULD_DROP_LAN_GW_MAC);
}

TEST(L2GwPin, TheResetLandsBeforeTheFrameIsClassified)
{
	// The pin is fed first, so the first frame of a new generation is judged
	// against the reset state, not the old pin.
	Hook h;
	h.fromGw(kMacA);
	h.fromGw(kMacA);
	h.gen += 2;
	EXPECT_EQ(h.fromLan(kMacA), PD_L2_PASS);
	EXPECT_EQ(h.pin.state, PD_L2_PIN_NONE);
}

TEST(L2GwPin, GatewayUnknownNeverPins)
{
	pd_l2_gw_pin_t pin{};
	EXPECT_EQ(pd_l2_gw_pin_observe(&pin, 2, 0, 0, kMacA), 0);
	EXPECT_EQ(pd_l2_gw_pin_observe(&pin, 2, 0, 0, kMacA), 0);
	EXPECT_EQ(pin.state, PD_L2_PIN_NONE);
}

// ── lanGwMac: only pinned, unchanged, visible, src MAC == gw, src IP != gw, on-link

TEST(L2GwPin, LanGwMacNeedsEveryCondition)
{
	Hook h;
	h.fromGw(kMacA);
	h.fromGw(kMacA);
	EXPECT_EQ(h.fromLan(kMacA), PD_L2_WOULD_DROP_LAN_GW_MAC);   // all of them
	EXPECT_EQ(h.fromLan(kMacB), PD_L2_PASS);                    // src MAC is not the gateway's
	EXPECT_EQ(h.fromGw(kMacA), PD_L2_PASS);                     // src IP is the gateway's
	Spec off;
	off.srcIp = kWan;                                           // off-link
	EXPECT_NE(h.feed(off), PD_L2_WOULD_DROP_LAN_GW_MAC);
	Spec icmp;
	icmp.proto = 1;                                             // not UDP/TCP
	EXPECT_EQ(h.feed(icmp), PD_L2_DEFER);
	// Visible is the parser's fact: every parsed frame carries its source MAC.
	pd_l2_frame_facts_t ff;
	const std::vector<uint8_t> b = frame(Spec{});
	ASSERT_EQ(pd_l2_parse_frame(b.data(), uint32_t(b.size()), &ff), 1);
	EXPECT_TRUE(ff.flags & PD_L2F_MAC_VISIBLE);
	// Unknown own state defers even with a pin.
	pd_l2_frame_t f{};
	int changed = 0;
	const std::vector<uint8_t> lan = frame(Spec{});
	EXPECT_EQ(pd_l2_eth_classify(lan.data(), uint32_t(lan.size()), h.gen, &f, &h.pin, &changed), PD_L2_DEFER);
}

// ── Frame-facts parser ───────────────────────────────────────────────────────

TEST(L2FrameFacts, ReadsUdpAddressesAndPorts)
{
	Spec s;
	s.srcIp = kWan;
	s.sport = 40000;
	s.dport = 5060;
	const std::vector<uint8_t> b = frame(s);
	pd_l2_frame_facts_t ff;
	ASSERT_EQ(pd_l2_parse_frame(b.data(), uint32_t(b.size()), &ff), 1);
	EXPECT_EQ(ff.srcIp, kWan);
	EXPECT_EQ(ff.dstIp, kOur);
	EXPECT_EQ(ff.srcPort, 40000);
	EXPECT_EQ(ff.dstPort, 5060);
	EXPECT_EQ(ff.flags, uint32_t(PD_L2F_IP4_UDP_TCP | PD_L2F_MAC_VISIBLE));
	EXPECT_EQ(0, std::memcmp(ff.srcMac, kMacA, 6));
}

TEST(L2FrameFacts, ReadsTcpPortsPastIhlOptions)
{
	Spec s;
	s.proto = 6;
	s.ihlWords = 6;   // 4 bytes of options
	s.sport = 443;
	s.dport = 80;
	const std::vector<uint8_t> b = frame(s);
	pd_l2_frame_facts_t ff;
	ASSERT_EQ(pd_l2_parse_frame(b.data(), uint32_t(b.size()), &ff), 1);
	EXPECT_EQ(ff.srcPort, 443);
	EXPECT_EQ(ff.dstPort, 80);
	EXPECT_TRUE(ff.flags & PD_L2F_IP4_UDP_TCP);
}

TEST(L2FrameFacts, NonIpv4FramesDefer)
{
	for (uint16_t type : {uint16_t(0x8100), uint16_t(0x0806), uint16_t(0x86DD)})
	{
		Spec s;
		s.ethertype = type;
		const std::vector<uint8_t> b = frame(s);
		pd_l2_frame_facts_t ff;
		EXPECT_EQ(pd_l2_parse_frame(b.data(), uint32_t(b.size()), &ff), 0) << std::hex << type;
		Hook h;
		EXPECT_EQ(h.feed(s), PD_L2_DEFER) << std::hex << type;
	}
}

TEST(L2FrameFacts, ShortAndMalformedFramesDefer)
{
	const std::vector<uint8_t> b = frame(Spec{});
	pd_l2_frame_facts_t ff;
	EXPECT_EQ(pd_l2_parse_frame(b.data(), 13, &ff), 0);        // no Ethernet header
	EXPECT_EQ(pd_l2_parse_frame(b.data(), 14 + 19, &ff), 0);   // truncated IPv4 header
	Spec small;
	small.ihlWords = 4;                                        // IHL below 5
	const std::vector<uint8_t> s = frame(small);
	EXPECT_EQ(pd_l2_parse_frame(s.data(), uint32_t(s.size()), &ff), 0);
	Spec opts;
	opts.ihlWords = 15;                                        // IHL past the frame's end
	std::vector<uint8_t> o = frame(opts);
	EXPECT_EQ(pd_l2_parse_frame(o.data(), 14 + 40, &ff), 0);
	std::vector<uint8_t> v6 = frame(Spec{});
	v6[14] = 0x65;                                             // IP version 6 under 0x0800
	EXPECT_EQ(pd_l2_parse_frame(v6.data(), uint32_t(v6.size()), &ff), 0);
	// Header complete but no room for the ports: addresses known, not classified.
	EXPECT_EQ(pd_l2_parse_frame(b.data(), 14 + 20 + 3, &ff), 1);
	EXPECT_FALSE(ff.flags & PD_L2F_IP4_UDP_TCP);
}

TEST(L2FrameFacts, NonFirstFragmentDefersButFirstFragmentIsRead)
{
	Spec later;
	later.fragField = 0x2000 | 185;   // MF + offset 1480
	const std::vector<uint8_t> b = frame(later);
	pd_l2_frame_facts_t ff;
	ASSERT_EQ(pd_l2_parse_frame(b.data(), uint32_t(b.size()), &ff), 1);
	EXPECT_TRUE(ff.flags & PD_L2F_NON_FIRST_FRAGMENT);
	EXPECT_FALSE(ff.flags & PD_L2F_IP4_UDP_TCP);
	Hook h;
	EXPECT_EQ(h.feed(later), PD_L2_DEFER);

	Spec first;
	first.fragField = 0x2000;         // MF, offset 0: the ports are here
	const std::vector<uint8_t> f = frame(first);
	ASSERT_EQ(pd_l2_parse_frame(f.data(), uint32_t(f.size()), &ff), 1);
	EXPECT_TRUE(ff.flags & PD_L2F_IP4_UDP_TCP);
	EXPECT_FALSE(ff.flags & PD_L2F_NON_FIRST_FRAGMENT);
}

TEST(L2FrameFacts, GroupDestinationMacIsFlagged)
{
	Spec s;
	s.bcastDstMac = true;
	const std::vector<uint8_t> b = frame(s);
	pd_l2_frame_facts_t ff;
	ASSERT_EQ(pd_l2_parse_frame(b.data(), uint32_t(b.size()), &ff), 1);
	EXPECT_TRUE(ff.flags & PD_L2F_DST_BCAST_MCAST);
}

TEST(L2FrameFacts, AnIcmpFrameFromTheGatewayStillFeedsThePin)
{
	Hook h;
	Spec s;
	s.srcIp = kGw;
	s.proto = 1;
	h.feed(s);
	h.feed(s);
	EXPECT_EQ(h.pin.state, PD_L2_PIN_PINNED);
}

// ── Seqlock reader ───────────────────────────────────────────────────────────

TEST(L2IpSeqlock, OddOrChangedGenerationDefers)
{
	EXPECT_EQ(pd_l2_seq_defer(3, 3), 1);   // a write in progress
	EXPECT_EQ(pd_l2_seq_defer(2, 4), 1);   // a write landed mid-read
	EXPECT_EQ(pd_l2_seq_defer(2, 3), 1);   // a write began mid-read
	EXPECT_EQ(pd_l2_seq_defer(4, 4), 0);   // a stable snapshot
}
