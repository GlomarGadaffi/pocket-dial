#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#include <gtest/gtest.h>
#include <cstring>
#include <vector>

#include "L2RtpFrame.hpp"
#include "DmaFramePool.hpp"
#include "EthAccess.hpp"
#include "ArpLookup.hpp"

using namespace l2rtp;

namespace
{
	sockaddr_in makeAddr(const char* ipStr, uint16_t port)
	{
		sockaddr_in sa{};
		sa.sin_family = AF_INET;
		sa.sin_port = htons(port);
		sa.sin_addr.s_addr = inet_addr(ipStr);
		return sa;
	}

	uint32_t ipToHost(const char* ipStr)
	{
		return ntohl(inet_addr(ipStr));
	}

	uint16_t be16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }
	uint32_t be32(const uint8_t* p)
	{
		return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16)
			| (static_cast<uint32_t>(p[2]) << 8) | p[3];
	}
}

class L2EgressChannelTest : public ::testing::Test
{
protected:
	void SetUp() override
	{
		EthAccess::resetMocks();
		ArpLookup::clearMockMacs();
		DmaFramePool::init();
		DmaFramePool::resetStats();
	}

	void TearDown() override
	{
		EthAccess::resetMocks();
		ArpLookup::clearMockMacs();
		DmaFramePool::resetStats();
	}
};

// ── 1. Pure helpers ──────────────────────────────────────────────────────────

TEST_F(L2EgressChannelTest, SubnetVsGatewayPureFunction)
{
	const uint32_t localIp = ipToHost("192.168.12.244");
	const uint32_t localGw = ipToHost("192.168.12.1");
	const uint32_t netmask24 = ipToHost("255.255.255.0");

	// Same subnet (/24) -> next hop is the target host itself
	const uint32_t onSubnetDest = ipToHost("192.168.12.50");
	EXPECT_EQ(resolveNextHop(onSubnetDest, localIp, localGw, netmask24), onSubnetDest);

	// Off subnet (/24) -> next hop is the default gateway
	const uint32_t offSubnetDest = ipToHost("10.0.1.99");
	EXPECT_EQ(resolveNextHop(offSubnetDest, localIp, localGw, netmask24), localGw);

	// Different mask: /16
	const uint32_t netmask16 = ipToHost("255.255.0.0");
	const uint32_t wideDest = ipToHost("192.168.99.1");
	EXPECT_EQ(resolveNextHop(wideDest, localIp, localGw, netmask16), wideDest);
	EXPECT_EQ(resolveNextHop(wideDest, localIp, localGw, netmask24), localGw);
}

TEST_F(L2EgressChannelTest, ArpCadencePureFunction)
{
	// When not ready, always resolve
	EXPECT_TRUE(shouldResolveArp(/*ready=*/false, 0));
	EXPECT_TRUE(shouldResolveArp(/*ready=*/false, 100));
	EXPECT_TRUE(shouldResolveArp(/*ready=*/false, 250));

	// When ready, resolve only on multiples of 250 ticks (~5s at 20ms)
	EXPECT_TRUE(shouldResolveArp(/*ready=*/true, 0));
	EXPECT_FALSE(shouldResolveArp(/*ready=*/true, 1));
	EXPECT_FALSE(shouldResolveArp(/*ready=*/true, 249));
	EXPECT_TRUE(shouldResolveArp(/*ready=*/true, 250));
	EXPECT_FALSE(shouldResolveArp(/*ready=*/true, 251));
	EXPECT_TRUE(shouldResolveArp(/*ready=*/true, 500));
}

// ── 2. Routing decisions via EgressChannel::updateAddressing ──────────────────

TEST_F(L2EgressChannelTest, SameSubnetResolvesTargetMacDirectly)
{
	EthAccess::setMockIpInfo(true, ipToHost("192.168.12.244"), ipToHost("192.168.12.1"), ipToHost("255.255.255.0"));
	const std::array<uint8_t, 6> localMac = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
	EthAccess::setMockMac(true, localMac);

	const sockaddr_in peer = makeAddr("192.168.12.50", 30000);
	const ArpLookup::Mac peerMac = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};
	ArpLookup::setMockMac(peer, peerMac);

	EgressChannel ch;
	EXPECT_TRUE(ch.updateAddressing(peer, 5062, 0x11223344));
	EXPECT_TRUE(ch.ready);
	EXPECT_EQ(ch.ep.dstMac, peerMac);
	EXPECT_EQ(ch.ep.srcMac, localMac);
	EXPECT_EQ(ch.ep.dstIp, ipToHost("192.168.12.50"));
	EXPECT_EQ(ch.ep.srcIp, ipToHost("192.168.12.244"));
}

TEST_F(L2EgressChannelTest, OffSubnetResolvesGatewayMacWithOriginalDstIp)
{
	EthAccess::setMockIpInfo(true, ipToHost("192.168.12.244"), ipToHost("192.168.12.1"), ipToHost("255.255.255.0"));
	const std::array<uint8_t, 6> localMac = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
	EthAccess::setMockMac(true, localMac);

	const sockaddr_in gwAddr = makeAddr("192.168.12.1", 0);
	const ArpLookup::Mac gwMac = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
	ArpLookup::setMockMac(gwAddr, gwMac);

	// Off-subnet destination (no direct ARP entry)
	const sockaddr_in remotePeer = makeAddr("10.0.1.200", 40000);

	EgressChannel ch;
	EXPECT_TRUE(ch.updateAddressing(remotePeer, 5062, 0x11223344));
	EXPECT_TRUE(ch.ready);
	// Link layer destination must be the gateway
	EXPECT_EQ(ch.ep.dstMac, gwMac);
	// Network layer destination must remain the remote peer
	EXPECT_EQ(ch.ep.dstIp, ipToHost("10.0.1.200"));
}

// ── 3. Cadence & recovery ───────────────────────────────────────────────────

TEST_F(L2EgressChannelTest, CadenceReResolvesAt250TicksAndFastRetriesOnFailure)
{
	EthAccess::setMockIpInfo(true, ipToHost("192.168.12.244"), ipToHost("192.168.12.1"), ipToHost("255.255.255.0"));
	const std::array<uint8_t, 6> localMac = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
	EthAccess::setMockMac(true, localMac);

	const sockaddr_in peer = makeAddr("192.168.12.50", 30000);
	const ArpLookup::Mac initialMac = {0xAA, 0x00, 0x00, 0x00, 0x00, 0x01};
	ArpLookup::setMockMac(peer, initialMac);

	EgressChannel ch;
	EXPECT_TRUE(ch.updateAddressing(peer, 5062, 0x11223344));
	EXPECT_EQ(ch.ep.dstMac, initialMac);

	// Change the ARP table entry. Ticks 1 to 249 must NOT re-resolve (cached)
	const ArpLookup::Mac updatedMac = {0xBB, 0x11, 0x22, 0x33, 0x44, 0x55};
	ArpLookup::setMockMac(peer, updatedMac);

	for (uint32_t tick = 1; tick < 250; ++tick)
	{
		EXPECT_TRUE(ch.updateAddressing(peer, 5062, 0x11223344));
		EXPECT_EQ(ch.ep.dstMac, initialMac); // Still old cached MAC
	}

	// At tick 250, re-resolve fires and picks up the new MAC
	EXPECT_TRUE(ch.updateAddressing(peer, 5062, 0x11223344));
	EXPECT_EQ(ch.ep.dstMac, updatedMac);

	// Advance another 250 ticks to 500, but simulate ARP cache eviction
	ArpLookup::clearMockMacs();
	for (uint32_t tick = 251; tick < 500; ++tick)
	{
		EXPECT_TRUE(ch.updateAddressing(peer, 5062, 0x11223344));
	}
	// At tick 500, ARP lookup fails -> ready drops to false
	EXPECT_FALSE(ch.updateAddressing(peer, 5062, 0x11223344));
	EXPECT_FALSE(ch.ready);

	// Next tick (501): because ready is false, it MUST retry immediately without waiting 250 ticks
	ArpLookup::setMockMac(peer, initialMac);
	EXPECT_TRUE(ch.updateAddressing(peer, 5062, 0x11223344));
	EXPECT_TRUE(ch.ready);
	EXPECT_EQ(ch.ep.dstMac, initialMac);
}

// ── 4. HAL safety (EthAccess::getLocalMac failure) ───────────────────────────

TEST_F(L2EgressChannelTest, HalMacReadFailurePreventsL2Transmit)
{
	EthAccess::setMockIpInfo(true, ipToHost("192.168.12.244"), ipToHost("192.168.12.1"), ipToHost("255.255.255.0"));
	const sockaddr_in peer = makeAddr("192.168.12.50", 30000);
	const ArpLookup::Mac peerMac = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};
	ArpLookup::setMockMac(peer, peerMac);

	// Simulate esp_read_mac() HAL failure
	EthAccess::setMockMac(/*available=*/false);

	EgressChannel ch;
	EXPECT_FALSE(ch.updateAddressing(peer, 5062, 0x11223344));
	EXPECT_FALSE(ch.ready);

	// Transmit must refuse and not put bogus MAC frames on the wire
	uint8_t payload[160] = {0};
	EXPECT_FALSE(ch.transmit(true, 0, 1, 160, payload, sizeof(payload)));
	EXPECT_EQ(EthAccess::getMockTransmitCount(), 0u);

	// Once HAL recovers, channel becomes ready
	const std::array<uint8_t, 6> localMac = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
	EthAccess::setMockMac(true, localMac);
	EXPECT_TRUE(ch.updateAddressing(peer, 5062, 0x11223344));
	EXPECT_TRUE(ch.ready);
}

// ── 5. Full L2 transmission & wire frame verification ────────────────────────

TEST_F(L2EgressChannelTest, TransmitSuccessAndWireByteIntegrity)
{
	EthAccess::setMockIpInfo(true, ipToHost("192.168.12.244"), ipToHost("192.168.12.1"), ipToHost("255.255.255.0"));
	const std::array<uint8_t, 6> localMac = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
	EthAccess::setMockMac(true, localMac);

	const sockaddr_in peer = makeAddr("192.168.12.50", 30000);
	const ArpLookup::Mac peerMac = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};
	ArpLookup::setMockMac(peer, peerMac);
	EthAccess::setMockTransmitResult(true);

	EgressChannel ch;
	ASSERT_TRUE(ch.updateAddressing(peer, 5062, 0x12345678));

	uint8_t payload[160];
	for (size_t i = 0; i < sizeof(payload); ++i) payload[i] = static_cast<uint8_t>(i ^ 0x55);

	const uint16_t seq = 1042;
	const uint32_t ts = 160000;
	EXPECT_TRUE(ch.transmit(/*marker=*/true, /*payloadType=*/0, seq, ts, payload, sizeof(payload)));
	EXPECT_EQ(EthAccess::getMockTransmitCount(), 1u);

	const auto& frame = EthAccess::getLastTransmittedFrame();
	// Frame size: 14 (Eth) + 20 (IP) + 8 (UDP) + 12 (RTP) + 160 (payload) = 214 bytes
	ASSERT_EQ(frame.size(), 214u);

	// Ethernet header
	EXPECT_EQ(std::memcmp(frame.data() + 0, peerMac.data(), 6), 0);
	EXPECT_EQ(std::memcmp(frame.data() + 6, localMac.data(), 6), 0);
	EXPECT_EQ(be16(frame.data() + 12), 0x0800); // IPv4

	// IPv4 header
	const uint8_t* ipHdr = frame.data() + 14;
	EXPECT_EQ(ipHdr[0], 0x45); // Version 4, IHL 5
	EXPECT_EQ(be16(ipHdr + 2), 200); // 20 (IP) + 8 (UDP) + 12 (RTP) + 160
	EXPECT_EQ(ipHdr[9], 17); // Protocol UDP
	EXPECT_EQ(be32(ipHdr + 12), ipToHost("192.168.12.244"));
	EXPECT_EQ(be32(ipHdr + 16), ipToHost("192.168.12.50"));

	// Internet checksum verification: folding the header with checksum must yield 0xFFFF
	uint32_t sum = 0;
	for (int i = 0; i < 20; i += 2) sum += be16(ipHdr + i);
	while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
	EXPECT_EQ(sum, 0xFFFFu);

	// UDP header
	const uint8_t* udpHdr = frame.data() + 34;
	EXPECT_EQ(be16(udpHdr + 0), 5062);
	EXPECT_EQ(be16(udpHdr + 2), 30000);
	EXPECT_EQ(be16(udpHdr + 4), 180); // 8 (UDP) + 12 (RTP) + 160
	EXPECT_EQ(be16(udpHdr + 6), 0);   // UDP checksum optional in IPv4

	// RTP header
	const uint8_t* rtpHdr = frame.data() + 42;
	EXPECT_EQ(rtpHdr[0], 0x80); // V=2
	EXPECT_EQ(rtpHdr[1], 0x80); // M=1, PT=0
	EXPECT_EQ(be16(rtpHdr + 2), seq);
	EXPECT_EQ(be32(rtpHdr + 4), ts);
	EXPECT_EQ(be32(rtpHdr + 8), 0x12345678);

	// Payload
	EXPECT_EQ(std::memcmp(frame.data() + 54, payload, sizeof(payload)), 0);
}

// ── 6. Fallback scenarios ────────────────────────────────────────────────────

TEST_F(L2EgressChannelTest, FallbackOnDmaPoolExhaustion)
{
	EthAccess::setMockIpInfo(true, ipToHost("192.168.12.244"), ipToHost("192.168.12.1"), ipToHost("255.255.255.0"));
	const std::array<uint8_t, 6> localMac = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
	EthAccess::setMockMac(true, localMac);
	const sockaddr_in peer = makeAddr("192.168.12.50", 30000);
	ArpLookup::setMockMac(peer, {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01});
	EthAccess::setMockTransmitResult(true);

	EgressChannel ch;
	ASSERT_TRUE(ch.updateAddressing(peer, 5062, 0x12345678));

	// Exhaust all 6 frames in the pool
	std::vector<DmaFramePool::Handle> held;
	for (size_t i = 0; i < DmaFramePool::kPoolSize; ++i)
	{
		auto h = DmaFramePool::acquire();
		ASSERT_TRUE(h);
		held.push_back(std::move(h));
	}
	EXPECT_EQ(DmaFramePool::available(), 0u);

	// Transmit must return false (signaling fallback to socket)
	uint8_t payload[160] = {0};
	EXPECT_FALSE(ch.transmit(false, 0, 1, 160, payload, sizeof(payload)));
	EXPECT_EQ(EthAccess::getMockTransmitCount(), 0u);

	// Release one frame back to pool
	held.pop_back();
	EXPECT_EQ(DmaFramePool::available(), 1u);

	// Transmit now succeeds
	EXPECT_TRUE(ch.transmit(false, 0, 2, 320, payload, sizeof(payload)));
	EXPECT_EQ(EthAccess::getMockTransmitCount(), 1u);
}

TEST_F(L2EgressChannelTest, FallbackOnDriverTransmitFailure)
{
	EthAccess::setMockIpInfo(true, ipToHost("192.168.12.244"), ipToHost("192.168.12.1"), ipToHost("255.255.255.0"));
	const std::array<uint8_t, 6> localMac = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
	EthAccess::setMockMac(true, localMac);
	const sockaddr_in peer = makeAddr("192.168.12.50", 30000);
	ArpLookup::setMockMac(peer, {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01});

	// Driver fails (e.g. SPI transmit queue full)
	EthAccess::setMockTransmitResult(false);

	EgressChannel ch;
	ASSERT_TRUE(ch.updateAddressing(peer, 5062, 0x12345678));

	uint8_t payload[160] = {0};
	EXPECT_FALSE(ch.transmit(false, 0, 1, 160, payload, sizeof(payload)));
}

TEST_F(L2EgressChannelTest, FallbackOnLocalIpUnavailable)
{
	// Ethernet link down or not yet configured with DHCP
	EthAccess::setMockIpInfo(/*available=*/false);

	const sockaddr_in peer = makeAddr("192.168.12.50", 30000);
	EgressChannel ch;
	EXPECT_FALSE(ch.updateAddressing(peer, 5062, 0x12345678));
	EXPECT_FALSE(ch.ready);

	uint8_t payload[160] = {0};
	EXPECT_FALSE(ch.transmit(false, 0, 1, 160, payload, sizeof(payload)));
	EXPECT_EQ(EthAccess::getMockTransmitCount(), 0u);
}
