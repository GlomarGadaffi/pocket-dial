#include <gtest/gtest.h>
#include <cstring>
#include <vector>

#include "L2RtpFrame.hpp"
#include "RtpReceiver.hpp"

using namespace l2rtp;

// The drift guard the header says a static_assert can't reach across headers
// for (true from L2RtpFrame.hpp's side, to avoid an include cycle) -- but a
// test file can include both, so enforce it here instead of leaving the two
// caps to drift silently apart.
static_assert(l2rtp::kMaxRtpDatagramBytes == static_cast<size_t>(RtpReceiver::MAX_DATAGRAM_BYTES),
	"l2rtp::kMaxRtpDatagramBytes must track RtpReceiver::MAX_DATAGRAM_BYTES");

namespace
{
	// Read back a big-endian field, for asserting on the bytes patchTick()/
	// buildTemplate() actually wrote -- independent of the module's own
	// put16/put32 helpers (those are private to the .cpp; these are a
	// from-scratch re-implementation so a bug shared between production code
	// and helper code here can't hide a real defect).
	uint16_t be16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }
	uint32_t be32(const uint8_t* p)
	{
		return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16)
			| (static_cast<uint32_t>(p[2]) << 8) | p[3];
	}

	Endpoint testEndpoint()
	{
		Endpoint ep;
		ep.srcMac  = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
		ep.dstMac  = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
		ep.srcIp   = 0xC0A80CF4;   // 192.168.12.244
		ep.dstIp   = 0xC0A80C0A;   // 192.168.12.10
		ep.srcPort = 5062;
		ep.dstPort = 30000;
		return ep;
	}
}

// -- ipChecksum: pure function, independent of frame layout -----------------

TEST(L2RtpFrameChecksum, KnownVectorMatchesIndependentlyComputedValue)
{
	// Classic RFC1071-style example header, checksum field zeroed. Verified
	// against a from-scratch Python re-implementation before being committed
	// here (not taken on faith from a remembered "textbook" figure).
	const uint8_t hdr[20] = {
		0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06,
		0x00, 0x00, 0xac, 0x10, 0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c
	};
	EXPECT_EQ(ipChecksum(hdr), 0xb1e6);
}

TEST(L2RtpFrameChecksum, InsertingTheComputedChecksumMakesTheWholeHeaderFoldToAllOnes)
{
	// The defining property of a correct Internet checksum (RFC 791 section
	// 3.1): summing the header WITH the correct checksum in place, then
	// folding carries, yields 0xFFFF (equivalently, one's-complementing it
	// gives 0x0000). This is what a NIC/receiver actually checks --
	// exercising it end-to-end is a stronger test than one fixed vector.
	uint8_t hdr[20] = {
		0x45, 0x00, 0x00, 0xc0, 0x12, 0x34, 0x40, 0x00, 0x40, 0x11,
		0x00, 0x00, 0xc0, 0xa8, 0x0c, 0xf4, 0xc0, 0xa8, 0x0c, 0x0a
	};
	const uint16_t cs = ipChecksum(hdr);
	hdr[10] = static_cast<uint8_t>(cs >> 8);
	hdr[11] = static_cast<uint8_t>(cs & 0xFF);

	uint32_t sum = 0;
	for (int i = 0; i < 20; i += 2) sum += be16(hdr + i);
	while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
	EXPECT_EQ(sum, 0xFFFFu);
}

TEST(L2RtpFrameChecksum, AllZeroHeaderChecksumsToAllOnes)
{
	// Edge case: RFC 791 defines no special case for an all-zero header --
	// the one's-complement of a zero sum is 0xFFFF, not folded to 0x0000.
	const uint8_t hdr[20] = {0};
	EXPECT_EQ(ipChecksum(hdr), 0xFFFF);
}

// -- buildTemplate: the fixed portion ----------------------------------------

TEST(L2RtpFrameTemplate, WritesEthernetHeaderExactly)
{
	uint8_t buf[kHeaderBytes];
	const Endpoint ep = testEndpoint();
	buildTemplate(buf, ep, /*ssrc=*/0);

	EXPECT_EQ(std::memcmp(buf + 0, ep.dstMac.data(), 6), 0) << "dst MAC first";
	EXPECT_EQ(std::memcmp(buf + 6, ep.srcMac.data(), 6), 0) << "src MAC second";
	EXPECT_EQ(be16(buf + 12), 0x0800) << "EtherType must be IPv4";
}

TEST(L2RtpFrameTemplate, WritesFixedIpv4FieldsExactly)
{
	uint8_t buf[kHeaderBytes];
	const Endpoint ep = testEndpoint();
	buildTemplate(buf, ep, /*ssrc=*/0);
	const uint8_t* ip = buf + kIpOffset;

	EXPECT_EQ(ip[0], 0x45) << "version 4, IHL 5 (no options)";
	EXPECT_EQ(ip[1], 0x00) << "DSCP/ECN unmarked";
	EXPECT_EQ(be16(ip + 6), 0x4000) << "Don't Fragment set, offset 0";
	EXPECT_EQ(ip[8], 64) << "TTL";
	EXPECT_EQ(ip[9], 17) << "protocol UDP";
	EXPECT_EQ(be32(ip + 12), ep.srcIp);
	EXPECT_EQ(be32(ip + 16), ep.dstIp);
}

TEST(L2RtpFrameTemplate, WritesUdpPortsAndZeroChecksum)
{
	uint8_t buf[kHeaderBytes];
	const Endpoint ep = testEndpoint();
	buildTemplate(buf, ep, /*ssrc=*/0);
	const uint8_t* udp = buf + kUdpOffset;

	EXPECT_EQ(be16(udp + 0), ep.srcPort);
	EXPECT_EQ(be16(udp + 2), ep.dstPort);
	EXPECT_EQ(be16(udp + 6), 0x0000) << "UDP checksum 0 is legal for IPv4 (RFC 768)";
}

TEST(L2RtpFrameTemplate, WritesRtpVersionByteAndSsrcOnceUpFront)
{
	uint8_t buf[kHeaderBytes];
	const Endpoint ep = testEndpoint();
	buildTemplate(buf, ep, /*ssrc=*/0xDEADBEEF);
	const uint8_t* rtp = buf + kRtpOffset;

	EXPECT_EQ(rtp[0], 0x80) << "V=2,P=0,X=0,CC=0";
	EXPECT_EQ(be32(rtp + 8), 0xDEADBEEFu);
}

// -- patchTick: the part that changes every 20 ms ----------------------------

TEST(L2RtpFramePatch, StampsRtpFieldsAndReturnsCorrectTotalLength)
{
	uint8_t buf[kMaxFrameBytes];
	buildTemplate(buf, testEndpoint(), /*ssrc=*/0x11223344);

	const uint8_t payload[4] = {0xAA, 0xBB, 0xCC, 0xDD};
	const size_t total = patchTick(buf, /*marker=*/true, /*pt=*/0,
		/*seq=*/1000, /*timestamp=*/8000, payload, sizeof(payload), /*ipIdent=*/0x0001);

	ASSERT_NE(total, 0u);
	EXPECT_EQ(total, kHeaderBytes + sizeof(payload));

	const uint8_t* rtp = buf + kRtpOffset;
	EXPECT_EQ(rtp[0], 0x80) << "version byte untouched by patchTick";
	EXPECT_EQ(rtp[1], 0x80) << "marker set, PT 0";
	EXPECT_EQ(be16(rtp + 2), 1000);
	EXPECT_EQ(be32(rtp + 4), 8000u);
	EXPECT_EQ(be32(rtp + 8), 0x11223344u) << "SSRC still the one buildTemplate() wrote";
	EXPECT_EQ(std::memcmp(rtp + kRtpHeaderBytes, payload, sizeof(payload)), 0);
}

TEST(L2RtpFramePatch, MarkerClearAndNonZeroPayloadType)
{
	uint8_t buf[kMaxFrameBytes];
	buildTemplate(buf, testEndpoint(), 0);
	patchTick(buf, /*marker=*/false, /*pt=*/101, 1, 160, nullptr, 0, 0);
	EXPECT_EQ((buf + kRtpOffset)[1], 101) << "marker bit clear, PT 101 in the low 7 bits";
}

TEST(L2RtpFramePatch, ZeroLengthPayloadProducesHeaderOnlyFrame)
{
	uint8_t buf[kMaxFrameBytes];
	buildTemplate(buf, testEndpoint(), 0);
	const size_t total = patchTick(buf, false, 0, 1, 160, nullptr, 0, 0);
	EXPECT_EQ(total, kHeaderBytes);
}

TEST(L2RtpFramePatch, LengthsAndChecksumAreByteExactForAKnownPayload)
{
	// The full pipeline, checked against independently-computed expected
	// bytes -- not just "does it look plausible".
	uint8_t buf[kMaxFrameBytes];
	Endpoint ep = testEndpoint();
	buildTemplate(buf, ep, 0);

	std::vector<uint8_t> payload(160, 0xFF);   // one 20ms PCMU silence frame
	const size_t total = patchTick(buf, true, 0, 500, 16000, payload.data(), payload.size(), 0x2A2B);
	ASSERT_NE(total, 0u);
	EXPECT_EQ(total, kHeaderBytes + 160);

	const uint8_t* ip = buf + kIpOffset;
	const size_t expectedIpTotalLen = kIpHeaderBytes + kUdpHeaderBytes + kRtpHeaderBytes + 160;   // 200
	EXPECT_EQ(be16(ip + 2), expectedIpTotalLen);
	EXPECT_EQ(be16(ip + 4), 0x2A2B) << "IP identification is the caller's own counter";

	const uint8_t* udp = buf + kUdpOffset;
	const size_t expectedUdpLen = kUdpHeaderBytes + kRtpHeaderBytes + 160;   // 180
	EXPECT_EQ(be16(udp + 4), expectedUdpLen);

	// Re-verify the checksum the production path just wrote using the
	// "insert and fold to all-ones" property, independent of ipChecksum().
	uint32_t sum = 0;
	for (int i = 0; i < 20; i += 2) sum += be16(ip + i);
	while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
	EXPECT_EQ(sum, 0xFFFFu);
}

TEST(L2RtpFramePatch, SuccessiveTicksAdvanceOnlyTheTickFields)
{
	uint8_t buf[kMaxFrameBytes];
	Endpoint ep = testEndpoint();
	buildTemplate(buf, ep, 0x99);

	uint16_t seq = 1;
	uint32_t ts  = 0;
	for (int i = 0; i < 5; ++i)
	{
		patchTick(buf, i == 0, 0, seq, ts, nullptr, 0, static_cast<uint16_t>(i));
		EXPECT_EQ(be16(buf + kRtpOffset + 2), seq);
		EXPECT_EQ(be32(buf + kRtpOffset + 4), ts);
		// Addressing never moves between ticks.
		EXPECT_EQ(std::memcmp(buf + 0, ep.dstMac.data(), 6), 0);
		EXPECT_EQ(be32(buf + kRtpOffset + 8), 0x99u) << "SSRC stable across ticks";
		++seq;
		ts += 160;
	}
}

TEST(L2RtpFramePatch, RefusesRatherThanTruncatesAnOversizePayload)
{
	uint8_t buf[kMaxFrameBytes];
	buildTemplate(buf, testEndpoint(), 0);

	// Snapshot the WHOLE buffer, including the payload region past the
	// header, so this actually catches a bug that copies the payload before
	// checking its length (the header-only snapshot this test used to take
	// would miss exactly that bug).
	uint8_t before[kMaxFrameBytes];
	std::memcpy(before, buf, sizeof(before));

	std::vector<uint8_t> tooBig(kMaxRtpDatagramBytes - kRtpHeaderBytes + 1, 0x42);
	const size_t total = patchTick(buf, true, 0, 1, 1, tooBig.data(), tooBig.size(), 0);

	EXPECT_EQ(total, 0u);
	EXPECT_EQ(std::memcmp(buf, before, sizeof(before)), 0)
		<< "a refused patchTick() must not have written anything, anywhere in the buffer";
}

TEST(L2RtpFramePatch, RefusesRatherThanDereferenceNullPayloadWithNonzeroLength)
{
	uint8_t buf[kMaxFrameBytes];
	buildTemplate(buf, testEndpoint(), 0);
	uint8_t before[kMaxFrameBytes];
	std::memcpy(before, buf, sizeof(before));

	const size_t total = patchTick(buf, true, 0, 1, 1, /*payload=*/nullptr, /*payloadLen=*/10, 0);

	EXPECT_EQ(total, 0u);
	EXPECT_EQ(std::memcmp(buf, before, sizeof(before)), 0);
}

TEST(L2RtpFrameBuffer, IsCorrectlySizedAndAligned)
{
	// The type the header recommends every real caller use, so its own
	// contract (big enough, DMA-alignment-friendly) is asserted, not just
	// described in a comment.
	//
	// `sizeof(FrameBuffer)` itself is NOT asserted equal to kMaxFrameBytes:
	// alignas(4) pads the whole struct up to a multiple of 4 (554 -> 556 on
	// every toolchain tried), which is correct, required C++ behaviour, not
	// a defect -- that padding sits after the array and nothing ever reads
	// or writes it. What must hold, and is what buildTemplate()/patchTick()
	// actually rely on, is that the `bytes` MEMBER is exactly big enough.
	FrameBuffer fb{};
	EXPECT_EQ(sizeof(fb.bytes), kMaxFrameBytes);
	EXPECT_GE(sizeof(FrameBuffer), kMaxFrameBytes) << "struct must be at least as large as the array it wraps";
	EXPECT_GE(alignof(FrameBuffer), 4u);

	// And it actually works as a buildTemplate()/patchTick() target.
	buildTemplate(fb.bytes, testEndpoint(), 0x42);
	const size_t total = patchTick(fb.bytes, false, 0, 1, 160, nullptr, 0, 0);
	EXPECT_EQ(total, kHeaderBytes);
}

TEST(L2RtpFramePatch, AcceptsExactlyTheMaximumPayload)
{
	uint8_t buf[kMaxFrameBytes];
	buildTemplate(buf, testEndpoint(), 0);
	std::vector<uint8_t> maxPayload(kMaxRtpDatagramBytes - kRtpHeaderBytes, 0x7E);
	const size_t total = patchTick(buf, false, 0, 1, 1, maxPayload.data(), maxPayload.size(), 0);
	EXPECT_EQ(total, kHeaderBytes + maxPayload.size());
}
