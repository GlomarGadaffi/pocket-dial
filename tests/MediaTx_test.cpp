// MediaTx_test.cpp -- issue #985 slice 0: the media TX instrument.
//
// Outbound audio waits in two places nothing measured: the anchor's blocking TLS write
// (one per 20 ms frame, TelephonyAnchorClient::writeAudio) and the L2 path to LAN phones
// (frame build, esp_eth_transmit, a 6-frame DMA pool). pd::MediaTx keeps their histograms,
// counters and capped witness records in static storage; /api/status carries a summary
// (HttpStatusAlloc_test.cpp) and tick() writes the witness lines.
//
// Everything here runs on a fake clock (pd::MediaTx::setClockForTest), so nothing sleeps
// and no result depends on the scheduler. The MediaBridge cases drive the real
// onHandsetRtp()/feedMohTick() with an anchor whose writeAudio() advances that clock.

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#include <gtest/gtest.h>

#include <atomic>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "AnchorClient.hpp"
#include "ArpLookup.hpp"
#include "DmaFramePool.hpp"
#include "EthAccess.hpp"
#include "HoldMusic.hpp"
#include "L2RtpFrame.hpp"
#include "MediaBridge.hpp"
#include "MediaTxStats.hpp"
#include "RequestsHandler.hpp"
#include "RtpReceiver.hpp"
#include "RtpSender.hpp"
#include "Witness.hpp"

using pd::MediaTx;

namespace
{
	std::atomic<int64_t> g_nowUs{0};
	int64_t fakeNow() { return g_nowUs.load(); }

	// A clock that moves 10 us every time it is read: a stretch of code that reads it
	// twice measures 10 us, however fast the host is.
	int64_t steppingNow() { return g_nowUs.fetch_add(10); }

	struct MediaTxTest : ::testing::Test
	{
		void SetUp() override
		{
			MediaTx::resetForTest();
			g_nowUs = 0;
			MediaTx::setClockForTest(&fakeNow);
		}
		void TearDown() override
		{
			MediaTx::setClockForTest(nullptr);
			MediaTx::resetForTest();
		}
	};

	std::vector<MediaTx::Witness> drain()
	{
		std::vector<MediaTx::Witness> out;
		MediaTx::Witness w;
		while (out.size() < 64 && MediaTx::takeWitness(w)) out.push_back(w);
		return out;
	}
}

// ── the histograms ────────────────────────────────────────────────────────────

TEST_F(MediaTxTest, SamplesLandInTheLog2BucketsAndThePercentilesAreTheirTopEdges)
{
	// 99 short writes and one long one: the 99th-percentile rank (99 of 100) is still in
	// the short bucket (8..15 us), so p99 is that bucket's top edge; p99.9 needs rank 100
	// and reaches the long bucket, whose top edge is clamped to the largest write seen.
	for (int i = 0; i < 99; ++i) MediaTx::recordWrite(false, 0, 10);
	MediaTx::recordWrite(false, 0, 50000);
	MediaTx::Summary s = MediaTx::writeSummary();
	EXPECT_EQ(s.count, 100u);
	EXPECT_EQ(s.maxUs, 50000u);
	EXPECT_EQ(s.p50Us, 15u);
	EXPECT_EQ(s.p99Us, 15u);
	EXPECT_EQ(s.p999Us, 50000u);

	// Bucket edges: 7 is the top of [4,8), 8 the bottom of [8,16).
	MediaTx::resetForTest();
	for (int i = 0; i < 99; ++i) MediaTx::recordWrite(false, 0, 7);
	MediaTx::recordWrite(false, 0, 100000);
	EXPECT_EQ(MediaTx::writeSummary().p99Us, 7u);
	MediaTx::resetForTest();
	for (int i = 0; i < 99; ++i) MediaTx::recordWrite(false, 0, 8);
	MediaTx::recordWrite(false, 0, 100000);
	EXPECT_EQ(MediaTx::writeSummary().p99Us, 15u);

	// A bucket's top edge is never reported above the real maximum.
	MediaTx::resetForTest();
	for (int i = 0; i < 100; ++i) MediaTx::recordWrite(false, 0, 3000);
	s = MediaTx::writeSummary();
	EXPECT_EQ(s.p50Us, 3000u);
	EXPECT_EQ(s.p99Us, 3000u);

	// Three samples a decade apart: the median is the middle one's bucket top edge.
	MediaTx::resetForTest();
	MediaTx::recordWrite(false, 0, 1);
	MediaTx::recordWrite(false, 0, 100);
	MediaTx::recordWrite(false, 0, 1000000);
	EXPECT_EQ(MediaTx::writeSummary().p50Us, 127u);

	// A zero-length sample is a sample (bucket 0, p-values 0), and an empty histogram is all zeros.
	MediaTx::resetForTest();
	EXPECT_EQ(MediaTx::writeSummary().count, 0u);
	MediaTx::recordWrite(false, 0, 0);
	EXPECT_EQ(MediaTx::writeSummary().count, 1u);
	EXPECT_EQ(MediaTx::writeSummary().p99Us, 0u);
}

TEST_F(MediaTxTest, AWriteIsOverOnlyWhenStrictlyLongerThanTwentyMilliseconds)
{
	MediaTx::recordWrite(false, 1, 19999);
	MediaTx::recordWrite(false, 1, 20000);   // exactly 20 ms is not over it
	EXPECT_EQ(MediaTx::writeOver(), 0u);
	EXPECT_EQ(MediaTx::legOver(1), 0u);
	EXPECT_TRUE(drain().empty());

	MediaTx::recordWrite(false, 1, 20001);
	EXPECT_EQ(MediaTx::writeOver(), 1u);
	EXPECT_EQ(MediaTx::legOver(1), 1u);
	EXPECT_EQ(MediaTx::legOver(0), 0u) << "per-leg counts are per leg";
	const auto w = drain();
	ASSERT_EQ(w.size(), 1u);
	EXPECT_EQ(w[0].path, MediaTx::Path::AnchorWrite);
	EXPECT_EQ(w[0].leg, 1u);
	EXPECT_EQ(w[0].us, 20001u);
	EXPECT_EQ(MediaTx::writeSummary().count, 3u) << "every call is in the histogram, slow or not";
}

TEST_F(MediaTxTest, TheMaximumMovesOnlyUp)
{
	MediaTx::recordWrite(false, 0, 100);
	MediaTx::recordWrite(false, 0, 40);
	EXPECT_EQ(MediaTx::writeSummary().maxUs, 100u);
	MediaTx::recordWrite(false, 0, 101);
	EXPECT_EQ(MediaTx::writeSummary().maxUs, 101u);
}

// ── the witness records ───────────────────────────────────────────────────────

TEST_F(MediaTxTest, AWitnessIsDataUntilSomeoneDrainsItAndNamesPathLegStampAndRunningTotal)
{
	g_nowUs = 1234567;   // 1234 ms since boot
	MediaTx::recordWrite(/*viaHold=*/true, 2, 33000);
	MediaTx::recordWrite(/*viaHold=*/true, 2, 21000);
	auto w = drain();
	ASSERT_EQ(w.size(), 2u);
	EXPECT_EQ(w[0].path, MediaTx::Path::HoldWrite);
	EXPECT_EQ(w[0].leg, 2u);
	EXPECT_EQ(w[0].us, 33000u);
	EXPECT_EQ(w[0].stampMs, 1234u);
	EXPECT_EQ(w[0].total, 2u) << "the running total is read when the line is written, not when it happened";
	EXPECT_EQ(w[1].us, 21000u);
	EXPECT_TRUE(drain().empty()) << "a drained record is not handed out twice";

	MediaTx::recordWrite(false, 3, 25000);
	w = drain();
	ASSERT_EQ(w.size(), 1u);
	EXPECT_EQ(w[0].total, 3u);
}

TEST_F(MediaTxTest, TheWitnessIsCappedPerSlotAndInAllButTheCountersAreNot)
{
	for (int i = 0; i < 10; ++i) MediaTx::recordWrite(false, 0, 30000);
	EXPECT_EQ(MediaTx::writeOver(), 10u);
	EXPECT_EQ(drain().size(), static_cast<size_t>(MediaTx::kWitnessPerSlot)) << "the first N for a slot, per boot";
	for (int i = 0; i < 5; ++i) MediaTx::recordWrite(false, 0, 30000);
	EXPECT_TRUE(drain().empty()) << "draining does not reopen a full slot";
	EXPECT_EQ(MediaTx::writeOver(), 15u);

	// Every other leg takes its own N, up to the table-wide cap.
	MediaTx::resetForTest();
	size_t want = 0;
	for (unsigned leg = 0; leg < MediaTx::kLegs; ++leg)
	{
		for (int i = 0; i < 10; ++i) MediaTx::recordWrite(false, static_cast<uint8_t>(leg), 30000);
		want += MediaTx::kWitnessPerSlot;
	}
	if (want > MediaTx::kWitnessTotal) want = MediaTx::kWitnessTotal;
	// The hold task has a slot of its own, but the table-wide cap is spent by then.
	for (int i = 0; i < 10; ++i) MediaTx::recordTickMiss(30000);
	const size_t got = drain().size();
	EXPECT_EQ(got, want);
	EXPECT_LE(got, static_cast<size_t>(MediaTx::kWitnessTotal));
	EXPECT_EQ(MediaTx::tickMisses(), 10u);
}

TEST_F(MediaTxTest, TheHoldTaskHasItsOwnSlot)
{
	for (int i = 0; i < 10; ++i) MediaTx::recordTickMiss(2000);
	const auto w = drain();
	ASSERT_EQ(w.size(), static_cast<size_t>(MediaTx::kWitnessPerSlot));
	EXPECT_EQ(w[0].path, MediaTx::Path::HoldTick);
	EXPECT_EQ(w[0].leg, MediaTx::kNoLeg);
	EXPECT_EQ(w[0].us, 2000u);
}

// ── missed ticks and the handset feed ─────────────────────────────────────────

TEST_F(MediaTxTest, AMissedTickCountsAndKeepsTheWorstOverrun)
{
	MediaTx::recordTickMiss(5000);
	MediaTx::recordTickMiss(12000);
	MediaTx::recordTickMiss(7000);
	EXPECT_EQ(MediaTx::tickMisses(), 3u);
	EXPECT_EQ(MediaTx::tickMaxOverrunUs(), 12000u);
}

TEST_F(MediaTxTest, AFeedGapIsLateOnlyWhenStrictlyLongerThanFortyMilliseconds)
{
	MediaTx::recordFeedFrame(0, /*prevEnd=*/0, 123456);   // no previous frame: nothing to measure
	EXPECT_EQ(MediaTx::feedFrames(), 0u);

	MediaTx::recordFeedFrame(0, 1000, 1000 + 40000);   // exactly 40 ms
	EXPECT_EQ(MediaTx::feedFrames(), 1u);
	EXPECT_EQ(MediaTx::feedLate(), 0u);
	EXPECT_EQ(MediaTx::feedMaxGapUs(), 40000u);
	EXPECT_TRUE(drain().empty());

	MediaTx::recordFeedFrame(3, 1000, 1000 + 40001);
	EXPECT_EQ(MediaTx::feedFrames(), 2u);
	EXPECT_EQ(MediaTx::feedLate(), 1u);
	EXPECT_EQ(MediaTx::feedMaxGapUs(), 40001u);
	const auto w = drain();
	ASSERT_EQ(w.size(), 1u);
	EXPECT_EQ(w[0].path, MediaTx::Path::FeedGap);
	EXPECT_EQ(w[0].leg, 3u);
	EXPECT_EQ(w[0].us, 40001u);
}

TEST_F(MediaTxTest, AGapAcrossTheWrapOfTheThirtyTwoBitClockIsStillTheRightLength)
{
	MediaTx::recordFeedFrame(0, 0xfffffff0u, 0x10u);   // 32 us across the wrap
	EXPECT_EQ(MediaTx::feedFrames(), 1u);
	EXPECT_EQ(MediaTx::feedMaxGapUs(), 32u);
	EXPECT_EQ(MediaTx::feedLate(), 0u);
}

// ── the Nagle A/B flag ────────────────────────────────────────────────────────

TEST_F(MediaTxTest, TheNodelayFlagIsOffAtBootSetsAndClears)
{
	// The boot value is a constant, so a build that flips it does not compile; the fixture's
	// reset restores that same constant, so the runtime check below reads the boot value too.
	static_assert(!MediaTx::kNodelayDefault, "the Nagle A/B switch is off at every boot (#985)");
	EXPECT_EQ(MediaTx::nodelay(), MediaTx::kNodelayDefault);
	EXPECT_FALSE(MediaTx::nodelay()) << "off at every boot";
	MediaTx::setNodelay(true);
	EXPECT_TRUE(MediaTx::nodelay());
	MediaTx::setNodelay(false);
	EXPECT_FALSE(MediaTx::nodelay());
}

// ── the L2 path ───────────────────────────────────────────────────────────────

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

	uint32_t ipToHost(const char* ipStr) { return ntohl(inet_addr(ipStr)); }

	struct MediaTxL2Test : ::testing::Test
	{
		l2rtp::EgressChannel ch;
		uint8_t payload[160] = {};

		void SetUp() override
		{
			EthAccess::resetMocks();
			ArpLookup::clearMockMacs();
			l2rtp::DmaFramePool::init();
			l2rtp::DmaFramePool::resetStats();
			MediaTx::resetForTest();
			g_nowUs = 0;
			MediaTx::setClockForTest(&steppingNow);

			EthAccess::setMockIpInfo(true, ipToHost("192.168.12.244"), ipToHost("192.168.12.1"), ipToHost("255.255.255.0"));
			EthAccess::setMockMac(true, {0x02, 0x11, 0x22, 0x33, 0x44, 0x55});
			const sockaddr_in peer = makeAddr("192.168.12.50", 30000);
			ArpLookup::setMockMac(peer, {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01});
			ASSERT_TRUE(ch.updateAddressing(peer, 5062, 0x12345678));
			EthAccess::setMockTransmitResult(true);
		}
		void TearDown() override
		{
			MediaTx::setClockForTest(nullptr);
			MediaTx::resetForTest();
			EthAccess::resetMocks();
			ArpLookup::clearMockMacs();
			l2rtp::DmaFramePool::resetStats();
		}

		bool send(uint16_t seq) { return ch.transmit(false, 0, seq, seq * 160u, payload, sizeof(payload)); }

		uint32_t sumOfCauses() const
		{
			return MediaTx::l2Fails(MediaTx::L2Fail::PoolEmpty) + MediaTx::l2Fails(MediaTx::L2Fail::ZeroLength) +
			       MediaTx::l2Fails(MediaTx::L2Fail::NoHandle) + MediaTx::l2Fails(MediaTx::L2Fail::Driver);
		}
	};

	void expectOnly(MediaTx::L2Fail cause, uint32_t n)
	{
		for (MediaTx::L2Fail c : { MediaTx::L2Fail::PoolEmpty, MediaTx::L2Fail::ZeroLength,
		                           MediaTx::L2Fail::NoHandle, MediaTx::L2Fail::Driver })
		{
			EXPECT_EQ(MediaTx::l2Fails(c), c == cause ? n : 0u) << "cause " << static_cast<int>(c);
		}
	}
}

TEST_F(MediaTxL2Test, EachFailureCauseCountsExactlyItsOwnCounter)
{
	// Pool empty: every frame is out.
	{
		std::vector<l2rtp::DmaFramePool::Handle> held;
		for (size_t i = 0; i < l2rtp::DmaFramePool::kPoolSize; ++i) held.push_back(l2rtp::DmaFramePool::acquire());
		EXPECT_FALSE(send(1));
		expectOnly(MediaTx::L2Fail::PoolEmpty, 1);
	}
	MediaTx::resetForTest();

	// A zero-length frame: patchTick refuses a payload over the datagram cap.
	{
		uint8_t big[600] = {};
		EXPECT_FALSE(ch.transmit(false, 0, 2, 320, big, sizeof(big)));
		expectOnly(MediaTx::L2Fail::ZeroLength, 1);
	}
	MediaTx::resetForTest();

	// No Ethernet handle at all.
	EthAccess::setMockEthHandle(false);
	EXPECT_FALSE(send(3));
	expectOnly(MediaTx::L2Fail::NoHandle, 1);
	EthAccess::setMockEthHandle(true);
	MediaTx::resetForTest();

	// The driver refuses the frame.
	EthAccess::setMockTransmitResult(false);
	EXPECT_FALSE(send(4));
	expectOnly(MediaTx::L2Fail::Driver, 1);
	EthAccess::setMockTransmitResult(true);
	MediaTx::resetForTest();

	// And a good frame counts no failure.
	EXPECT_TRUE(send(5));
	expectOnly(MediaTx::L2Fail::Driver, 0);
	EXPECT_EQ(sumOfCauses(), 0u);
}

TEST_F(MediaTxL2Test, TheFourCausesSumToTheCallersOwnAggregate)
{
	// HoldMusic::runLoop and RtpSender::runLoop each count ++_l2TxErrors when a READY channel's
	// transmit() returns false (the python pin in test_media_tx_instrument.py holds that
	// shape). So across every caller the four counters add up to the sum of those aggregates.
	uint32_t aggregate = 0;
	auto asTheCallersDo = [&](uint16_t seq) {
		if (!ch.ready) return false;                 // updateAddressing() said not ready: no attempt
		const bool ok = send(seq);
		if (!ok) ++aggregate;
		return ok;
	};

	uint16_t seq = 0;
	for (int round = 0; round < 25; ++round)
	{
		EthAccess::setMockTransmitResult(round % 3 != 0);
		EthAccess::setMockEthHandle(round % 5 != 0);
		std::vector<l2rtp::DmaFramePool::Handle> held;
		if (round % 7 == 0)
		{
			for (size_t i = 0; i < l2rtp::DmaFramePool::kPoolSize; ++i) held.push_back(l2rtp::DmaFramePool::acquire());
		}
		for (int i = 0; i < 4; ++i) asTheCallersDo(++seq);
	}
	EXPECT_GT(aggregate, 0u);
	EXPECT_EQ(sumOfCauses(), aggregate);
	// Each cause really was exercised: a split that lumped them would not show it.
	EXPECT_GT(MediaTx::l2Fails(MediaTx::L2Fail::PoolEmpty), 0u);
	EXPECT_GT(MediaTx::l2Fails(MediaTx::L2Fail::NoHandle), 0u);
	EXPECT_GT(MediaTx::l2Fails(MediaTx::L2Fail::Driver), 0u);
}

TEST_F(MediaTxL2Test, AChannelThatIsNotReadyIsNotATransmitAttemptAndCountsNothing)
{
	// Positive control: a ready channel whose driver refuses counts one.
	EthAccess::setMockTransmitResult(false);
	EXPECT_FALSE(send(1));
	ASSERT_EQ(sumOfCauses(), 1u);
	MediaTx::resetForTest();
	l2rtp::DmaFramePool::resetStats();

	l2rtp::EgressChannel cold;
	EXPECT_FALSE(cold.transmit(false, 0, 1, 160, payload, sizeof(payload)));
	EXPECT_EQ(sumOfCauses(), 0u);
	EXPECT_EQ(MediaTx::l2BuildSummary().count, 0u);
	EXPECT_EQ(l2rtp::DmaFramePool::getAllocations(), 0u) << "and it borrowed no frame";
}

TEST_F(MediaTxL2Test, FrameBuildAndDriverHandOffAreTimedSeparatelyAndOnlyWhenReached)
{
	EXPECT_TRUE(send(1));
	MediaTx::Summary b = MediaTx::l2BuildSummary();
	MediaTx::Summary t = MediaTx::l2TxSummary();
	EXPECT_EQ(b.count, 1u);
	EXPECT_EQ(t.count, 1u);
	EXPECT_EQ(b.maxUs, 10u) << "one 10 us step between the first and the middle stamp";
	EXPECT_EQ(t.maxUs, 10u) << "and one between the middle and the last";

	// A failed hand-off was still built and still timed.
	EthAccess::setMockTransmitResult(false);
	EXPECT_FALSE(send(2));
	EXPECT_EQ(MediaTx::l2BuildSummary().count, 2u);
	EXPECT_EQ(MediaTx::l2TxSummary().count, 2u);

	// Pool empty and zero-length never reach the hand-off: nothing to time there.
	{
		std::vector<l2rtp::DmaFramePool::Handle> held;
		for (size_t i = 0; i < l2rtp::DmaFramePool::kPoolSize; ++i) held.push_back(l2rtp::DmaFramePool::acquire());
		EXPECT_FALSE(send(3));
	}
	uint8_t big[600] = {};
	EXPECT_FALSE(ch.transmit(false, 0, 4, 640, big, sizeof(big)));
	EXPECT_EQ(MediaTx::l2BuildSummary().count, 2u);
	EXPECT_EQ(MediaTx::l2TxSummary().count, 2u);
}

TEST_F(MediaTxL2Test, ThePoolIsBackToBaselineAfterEveryCycleWhateverTheDriverDid)
{
	// #985 gap 6: many frames, with the driver, the handle and the frame length failing in
	// turn. Handle is RAII, so a leak is unlikely by construction; this holds that by test.
	// After each cycle every frame is back, and the caller's fallback ran for every failure.
	constexpr int kCycles = 600;
	int fallbacks = 0, queued = 0;
	for (int i = 0; i < kCycles; ++i)
	{
		bool ok = false;
		switch (i % 4)
		{
			case 0: EthAccess::setMockTransmitResult(true);  ok = send(static_cast<uint16_t>(i)); break;
			case 1: EthAccess::setMockTransmitResult(false); ok = send(static_cast<uint16_t>(i)); break;
			case 2:
			{
				EthAccess::setMockTransmitResult(true);
				EthAccess::setMockEthHandle(false);
				ok = send(static_cast<uint16_t>(i));
				EthAccess::setMockEthHandle(true);
				break;
			}
			default:
			{
				uint8_t big[600] = {};
				EthAccess::setMockTransmitResult(true);
				ok = ch.transmit(false, 0, static_cast<uint16_t>(i), 0, big, sizeof(big));
				break;
			}
		}
		if (ok) ++queued; else ++fallbacks;   // the caller's socket fallback
		ASSERT_EQ(l2rtp::DmaFramePool::available(), l2rtp::DmaFramePool::kPoolSize) << "cycle " << i;
	}
	EXPECT_EQ(queued, kCycles / 4);
	EXPECT_EQ(fallbacks, kCycles - kCycles / 4);
	EXPECT_EQ(EthAccess::getMockTransmitCount(), static_cast<size_t>(queued));
	EXPECT_EQ(sumOfCauses(), static_cast<uint32_t>(fallbacks));
	EXPECT_EQ(l2rtp::DmaFramePool::getAllocations(), static_cast<uint32_t>(kCycles));
	EXPECT_EQ(l2rtp::DmaFramePool::getExhaustions(), 0u);
	EXPECT_EQ(l2rtp::DmaFramePool::getMinAvailable(), l2rtp::DmaFramePool::kPoolSize - 1)
		<< "one frame out at a time, so the low-water mark is one below full";
}

TEST_F(MediaTxL2Test, ThePoolLowWaterMarkSeesADipThatSamplingAvailableMisses)
{
	using l2rtp::DmaFramePool;
	ASSERT_EQ(DmaFramePool::getMinAvailable(), DmaFramePool::kPoolSize);
	{
		std::vector<DmaFramePool::Handle> held;
		for (size_t i = 0; i < DmaFramePool::kPoolSize; ++i) held.push_back(DmaFramePool::acquire());
		EXPECT_EQ(DmaFramePool::available(), 0u);
	}
	// Everything is back: a sample reads full. The mark remembers the dip to empty.
	EXPECT_EQ(DmaFramePool::available(), DmaFramePool::kPoolSize);
	EXPECT_EQ(DmaFramePool::getMinAvailable(), 0u);
	EXPECT_EQ(DmaFramePool::getExhaustions(), 0u) << "the dip emptied the pool without anyone being refused";

	// resetStats() restarts it from the level it is at now.
	DmaFramePool::resetStats();
	EXPECT_EQ(DmaFramePool::getMinAvailable(), DmaFramePool::kPoolSize);
	{
		auto a = DmaFramePool::acquire();
		auto b = DmaFramePool::acquire();
		DmaFramePool::resetStats();   // two are out: the mark restarts there
		EXPECT_EQ(DmaFramePool::getMinAvailable(), DmaFramePool::kPoolSize - 2);
	}
	EXPECT_EQ(DmaFramePool::getMinAvailable(), DmaFramePool::kPoolSize - 2);

	// A refused acquire is an empty pool too.
	DmaFramePool::resetStats();
	{
		std::vector<DmaFramePool::Handle> held;
		for (size_t i = 0; i < DmaFramePool::kPoolSize; ++i) held.push_back(DmaFramePool::acquire());
		EXPECT_FALSE(static_cast<bool>(DmaFramePool::acquire()));
		EXPECT_EQ(DmaFramePool::getMinAvailable(), 0u);
	}
}

TEST_F(MediaTxL2Test, AFailedFallbackSendIsCounted)
{
	// The fallback itself is ESP-only (RtpSender::runLoop); test_media_tx_instrument.py pins that it
	// calls this on a sendto() below zero. The counter is plain.
	EXPECT_EQ(MediaTx::fallbackSendFails(), 0u);
	MediaTx::recordFallbackSendFail();
	MediaTx::recordFallbackSendFail();
	EXPECT_EQ(MediaTx::fallbackSendFails(), 2u);
}

// ── MediaBridge: the two writeAudio() callers and the handset feed ────────────

namespace
{
	std::vector<uint8_t> ulawFrame(uint8_t v = 0xFF)
	{
		return std::vector<uint8_t>(HoldMusic::BYTES_PER_TICK, v);
	}

	// An anchor whose write takes `costUs` of (fake) time.
	class SlowAnchor : public AnchorClient
	{
	public:
		bool init(const std::string&, const std::string&, const std::string&, const std::string&) override { return true; }
		bool start() override { return true; }
		void stop() override {}
		bool isConnected() const override { return true; }
		bool makeCall(const std::string&, std::string* = nullptr) override { return true; }
		bool answerCall(const std::string&) override { return true; }
		bool dropCall(const std::string&) override { return true; }
		void setEventCallback(EventCallback) override {}
		bool writeAudio(std::string_view, const int16_t*, size_t) override
		{
			g_nowUs += costUs;
			++writes;
			return true;
		}
		void registerAudioRxCallback(AudioRxCallback) override {}
		void tick() override {}

		int64_t costUs = 0;
		int writes = 0;
	};

	struct BridgeFixture : MediaTxTest
	{
		RtpReceiver receiver;
		RtpSender sender;
		SlowAnchor anchor;
		MediaBridge bridge;

		void SetUp() override
		{
			MediaTxTest::SetUp();
			bridge.init(&receiver, &sender, &anchor);
			bridge.setStatsLeg(2);
			ASSERT_TRUE(bridge.startBridge("127.0.0.1", 5004, "call-985", "part-985"));
			ASSERT_TRUE(sender.stop("call-985"));   // the Linux pacer thread, as MediaBridge_test.cpp does (#135)
		}
		void TearDown() override
		{
			bridge.stopBridge();
			MediaTxTest::TearDown();
		}

		void handsetFrame() { const auto f = ulawFrame(); bridge.onHandsetRtp(f.data(), f.size()); }
	};
}

TEST_F(BridgeFixture, AHandsetFrameTimesTheWholeWriteAndNamesItsLeg)
{
	anchor.costUs = 25000;
	handsetFrame();
	EXPECT_EQ(anchor.writes, 1);
	EXPECT_EQ(MediaTx::writeSummary().count, 1u);
	EXPECT_EQ(MediaTx::writeSummary().maxUs, 25000u);
	EXPECT_EQ(MediaTx::writeOver(), 1u);
	EXPECT_EQ(MediaTx::legOver(2), 1u);
	const auto w = drain();
	ASSERT_EQ(w.size(), 1u);
	EXPECT_EQ(w[0].path, MediaTx::Path::AnchorWrite);
	EXPECT_EQ(w[0].leg, 2u);
	EXPECT_EQ(w[0].us, 25000u);

	anchor.costUs = 1000;   // a fast write is in the histogram and not over
	handsetFrame();
	EXPECT_EQ(MediaTx::writeSummary().count, 2u);
	EXPECT_EQ(MediaTx::writeOver(), 1u);
}

TEST_F(BridgeFixture, TheHoldMusicTapTimesItsWriteAsTheHoldPath)
{
	bridge.setHeld(true);
	anchor.costUs = 30000;
	const auto f = ulawFrame(0xAA);
	bridge.feedMohTick(f.data(), f.size());
	EXPECT_EQ(anchor.writes, 1);
	EXPECT_EQ(MediaTx::writeOver(), 1u);
	const auto w = drain();
	ASSERT_EQ(w.size(), 1u);
	EXPECT_EQ(w[0].path, MediaTx::Path::HoldWrite);
	EXPECT_EQ(w[0].leg, 2u);
	EXPECT_EQ(w[0].us, 30000u);
	EXPECT_EQ(MediaTx::feedFrames(), 0u) << "the hold tap is not the handset feed";
}

TEST_F(BridgeFixture, TheFeedGapExcludesOurOwnWriteTime)
{
	// Frame 1 arrives at 0 and its write takes 60 ms, so it leaves the hand-off at 60 ms. Frame 2
	// is already waiting in the socket and starts at 60 ms: the feed was never idle. That is a
	// slow write (counted above), not a late frame.
	anchor.costUs = 60000;
	handsetFrame();
	handsetFrame();
	EXPECT_EQ(MediaTx::feedFrames(), 1u);
	EXPECT_EQ(MediaTx::feedMaxGapUs(), 0u);
	EXPECT_EQ(MediaTx::feedLate(), 0u);
	EXPECT_EQ(MediaTx::writeOver(), 2u);

	// Now the phone goes quiet for 45 ms before the next frame: a late frame, and not ours.
	anchor.costUs = 1000;
	g_nowUs += 45000;
	handsetFrame();
	EXPECT_EQ(MediaTx::feedFrames(), 2u);
	EXPECT_EQ(MediaTx::feedLate(), 1u);
	EXPECT_EQ(MediaTx::feedMaxGapUs(), 45000u);
	bool sawFeed = false;
	for (const auto& w : drain())
	{
		if (w.path == MediaTx::Path::FeedGap) { sawFeed = true; EXPECT_EQ(w.leg, 2u); EXPECT_EQ(w.us, 45000u); }
	}
	EXPECT_TRUE(sawFeed);

	// Exactly 40 ms idle is on time.
	g_nowUs += 40000;   // from the end of the last hand-off to the next arrival
	handsetFrame();
	EXPECT_EQ(MediaTx::feedLate(), 1u);
	EXPECT_EQ(MediaTx::feedMaxGapUs(), 45000u);
}

TEST_F(BridgeFixture, AHoldAResumeAndANewCallAreNotFeedGaps)
{
	anchor.costUs = 1000;
	handsetFrame();
	bridge.setHeld(true);
	g_nowUs += 5000000;          // five seconds on hold
	bridge.setHeld(false);
	handsetFrame();              // the first frame after the resume: no previous frame to measure from
	EXPECT_EQ(MediaTx::feedFrames(), 0u);
	EXPECT_EQ(MediaTx::feedLate(), 0u);

	handsetFrame();              // and the next is measured again
	EXPECT_EQ(MediaTx::feedFrames(), 1u);

	bridge.stopBridge();
	g_nowUs += 5000000;
	ASSERT_TRUE(bridge.startBridge("127.0.0.1", 5004, "call-985b", "part-985b"));
	ASSERT_TRUE(sender.stop("call-985b"));
	handsetFrame();
	EXPECT_EQ(MediaTx::feedFrames(), 1u) << "a new call starts with no previous frame";
	EXPECT_EQ(MediaTx::feedLate(), 0u);
}

TEST_F(BridgeFixture, AHeldBridgeDiscardsHandsetFramesWithoutMeasuringThem)
{
	anchor.costUs = 1000;
	handsetFrame();   // positive control: a live frame is written and measured
	ASSERT_EQ(anchor.writes, 1);
	ASSERT_EQ(MediaTx::writeSummary().count, 1u);

	bridge.setHeld(true);
	handsetFrame();
	handsetFrame();
	EXPECT_EQ(anchor.writes, 1);
	EXPECT_EQ(MediaTx::writeSummary().count, 1u);
	EXPECT_EQ(MediaTx::feedFrames(), 0u);
}

// ── tick() writes the lines, from outside the media tasks ─────────────────────

TEST_F(MediaTxTest, TickWritesOneLinePerWitnessRecordAndNeverTheRecordingCall)
{
	RequestsHandler h("10.0.0.1", 5060, [](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	pdwitness::clear();

	MediaTx::recordWrite(false, 1, 47000);
	MediaTx::recordWrite(true, 3, 31000);
	MediaTx::recordTickMiss(40000);
	MediaTx::recordFeedFrame(2, 1000, 1000 + 63000);
	EXPECT_EQ(pdwitness::count("(#985)"), 0u) << "recording leaves data behind, never a line";

	h.forceNextTickForTest();
	h.tick();
	EXPECT_EQ(pdwitness::count("anchor write took 47 ms (over 20 ms), handset frame, leg 1"), 1u);
	EXPECT_EQ(pdwitness::count("anchor write took 31 ms (over 20 ms), hold-music tap, leg 3"), 1u);
	EXPECT_EQ(pdwitness::count("hold-music tick finished 40 ms past its deadline, 1 missed so far"), 1u);
	EXPECT_EQ(pdwitness::count("handset feed idle 63 ms (over 40 ms), bridge leg 2, 1 late so far"), 1u);
	EXPECT_EQ(pdwitness::count("(#985)"), 4u);

	// The cumulative count in the line is the path's running total at the time of the line.
	for (const std::string& line : pdwitness::lines())
	{
		if (line.find("anchor write took 47 ms") != std::string::npos) EXPECT_NE(line.find("2 so far"), std::string::npos) << line;
		if (line.find("(#985)") != std::string::npos) EXPECT_NE(line.find("uptime"), std::string::npos) << line;
	}

	h.forceNextTickForTest();
	h.tick();
	EXPECT_EQ(pdwitness::count("(#985)"), 4u) << "each record is written once";
}
