// L2IngressParse_test.cpp -- issue #1145. The header-byte parse that feeds the
// IPv4 input hook's would-drop counters (src/Helpers/L2IngressParse.h). Frames
// are big-endian byte arrays, as they arrive, so a missing byte swap fails here.

#include <gtest/gtest.h>

#include <stdint.h>
#include <vector>

#include "L2IngressParse.h"

namespace
{
	constexpr uint32_t ip(uint32_t a, uint32_t b, uint32_t c, uint32_t d)
	{
		return (a << 24) | (b << 16) | (c << 8) | d;
	}

	constexpr uint32_t kOur = ip(192, 168, 12, 244);
	constexpr uint32_t kMask = ip(255, 255, 255, 0);
	constexpr uint32_t kGw = ip(192, 168, 12, 1);

	void put32(std::vector<uint8_t>& b, size_t at, uint32_t v)
	{
		b[at] = uint8_t(v >> 24); b[at + 1] = uint8_t(v >> 16);
		b[at + 2] = uint8_t(v >> 8); b[at + 3] = uint8_t(v);
	}

	// IPv4 header (ihlWords * 4 bytes) + 8 transport bytes, src/dst port set.
	std::vector<uint8_t> frame(uint8_t proto, uint16_t dport, uint32_t src = ip(203, 0, 113, 7),
		uint32_t dst = kOur, uint8_t ihlWords = 5, uint16_t fragField = 0)
	{
		const size_t ihl = size_t(ihlWords) * 4u;
		std::vector<uint8_t> b(ihl + 8, 0);
		b[0] = uint8_t(0x40 | ihlWords);
		b[6] = uint8_t(fragField >> 8); b[7] = uint8_t(fragField);
		b[8] = 64; b[9] = proto;
		put32(b, 12, src);
		put32(b, 16, dst);
		b[ihl] = 0xC3; b[ihl + 1] = 0x50;                 // src port 50000
		b[ihl + 2] = uint8_t(dport >> 8); b[ihl + 3] = uint8_t(dport);
		return b;
	}

	int32_t port(const std::vector<uint8_t>& b, size_t len)
	{
		return pd_l2_ip4_dst_port(b.data(), uint32_t(len));
	}
}

TEST(L2IngressParse, AShortBufferDefers)
{
	const auto b = frame(PD_L2_PROTO_UDP, 5060);
	EXPECT_EQ(port(b, 19), -1);        // not even a full IPv4 header
	EXPECT_EQ(port(b, 23), -1);        // header, but the dst port's last byte is missing
	EXPECT_EQ(port(b, 24), 5060);
}

TEST(L2IngressParse, HeaderOptionsMoveThePortRead)
{
	const auto b = frame(PD_L2_PROTO_UDP, 5060, ip(203, 0, 113, 7), kOur, 7);   // 28-byte header
	EXPECT_EQ(port(b, b.size()), 5060);
	EXPECT_EQ(port(b, 31), -1);        // port bytes beyond the first buffer
}

TEST(L2IngressParse, ANonFirstFragmentDefers)
{
	const auto b = frame(PD_L2_PROTO_UDP, 5060, ip(203, 0, 113, 7), kOur, 5, 0x2000 | 185);
	EXPECT_EQ(port(b, b.size()), -1);
	// A first fragment (MF set, offset 0) still carries the transport header.
	const auto first = frame(PD_L2_PROTO_UDP, 5060, ip(203, 0, 113, 7), kOur, 5, 0x2000);
	EXPECT_EQ(port(first, first.size()), 5060);
}

TEST(L2IngressParse, IcmpHasNoPort)
{
	const auto b = frame(1, 5060);
	EXPECT_EQ(port(b, b.size()), -1);
}

TEST(L2IngressParse, UdpAndTcpDstPortsReadInHostOrder)
{
	EXPECT_EQ(port(frame(PD_L2_PROTO_UDP, 5060), 28), 5060);
	EXPECT_EQ(port(frame(PD_L2_PROTO_TCP, 80), 28), 80);
	EXPECT_EQ(port(frame(PD_L2_PROTO_TCP, 0x1234), 28), 0x1234);
}

TEST(L2IngressParse, AnIhlBelowFiveDefers)
{
	auto b = frame(PD_L2_PROTO_UDP, 5060);
	b[0] = 0x44;
	EXPECT_EQ(port(b, b.size()), -1);
}

TEST(L2IngressClassify, AZeroNetifAddressDefers)
{
	const auto b = frame(PD_L2_PROTO_UDP, 5060);
	EXPECT_EQ(pd_l2_classify_ip4(b.data(), uint32_t(b.size()), kOur, kMask, kGw), PD_L2_WOULD_DROP_WAN_SERVICE);
	EXPECT_EQ(pd_l2_classify_ip4(b.data(), uint32_t(b.size()), 0, kMask, kGw), PD_L2_DEFER);
	EXPECT_EQ(pd_l2_classify_ip4(b.data(), uint32_t(b.size()), kOur, 0, kGw), PD_L2_DEFER);
	EXPECT_EQ(pd_l2_classify_ip4(b.data(), uint32_t(b.size()), kOur, kMask, 0), PD_L2_DEFER);
}

TEST(L2IngressClassify, OnlyListedServicePortsCount)
{
	const auto udp80 = frame(PD_L2_PROTO_UDP, 80);
	const auto tcp80 = frame(PD_L2_PROTO_TCP, 80);
	const auto rtp = frame(PD_L2_PROTO_UDP, 10002);
	EXPECT_EQ(pd_l2_classify_ip4(tcp80.data(), 28, kOur, kMask, kGw), PD_L2_WOULD_DROP_WAN_SERVICE);
	EXPECT_EQ(pd_l2_classify_ip4(udp80.data(), 28, kOur, kMask, kGw), PD_L2_DEFER);
	EXPECT_EQ(pd_l2_classify_ip4(rtp.data(), 28, kOur, kMask, kGw), PD_L2_DEFER);
}

TEST(L2IngressClassify, AMartianSourceToUsCounts)
{
	const auto b = frame(PD_L2_PROTO_UDP, 10002, ip(127, 0, 0, 1));
	EXPECT_EQ(pd_l2_classify_ip4(b.data(), 28, kOur, kMask, kGw), PD_L2_WOULD_DROP_MARTIAN);
	const auto other = frame(PD_L2_PROTO_UDP, 10002, ip(127, 0, 0, 1), ip(192, 168, 12, 9));
	EXPECT_NE(pd_l2_classify_ip4(other.data(), 28, kOur, kMask, kGw), PD_L2_WOULD_DROP_MARTIAN);
}
