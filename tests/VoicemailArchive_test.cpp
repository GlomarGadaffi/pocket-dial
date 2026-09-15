// VoicemailArchive_test.cpp — Issue #246 (voicemail Stage 3 of #194).
//
// The pure pieces of the SD-flush pipeline: the mu-law WAV header builder
// (round-tripped through HoldMusic::parseUlawWav, the actual production
// reader, rather than asserting on byte offsets by hand) and the
// WriterQueue/drainAll queue mechanics, mirroring CdrArchive_test.cpp's
// shape for the same reasons CdrArchive.hpp's class comment gives.

#include <gtest/gtest.h>

#include <cstring>
#include <vector>

#include "HoldMusic.hpp"
#include "VoicemailArchive.hpp"

namespace
{
	class FakeSink : public vmarchive::Sink
	{
	public:
		struct Call
		{
			vmarchive::QueuedRecording rec;
			std::vector<uint8_t> mulaw;
		};
		std::vector<Call> calls;

		void write(const vmarchive::QueuedRecording& rec, const uint8_t* mulaw) override
		{
			Call c;
			c.rec = rec;
			c.mulaw.assign(mulaw, mulaw + rec.length);
			calls.push_back(std::move(c));
		}
	};

	vmarchive::QueuedRecording makeRec(int slot, const char* ext, const char* callId,
		uint64_t seq, size_t length)
	{
		vmarchive::QueuedRecording r;
		r.stagingSlot = slot;
		std::strncpy(r.extension, ext, sizeof(r.extension) - 1);
		std::strncpy(r.callId, callId, sizeof(r.callId) - 1);
		r.sequence = seq;
		r.length = length;
		return r;
	}
}

TEST(VoicemailArchive, WavHeaderRoundTripsThroughHoldMusicsRealParser)
{
	const size_t dataBytes = 4000;
	std::vector<uint8_t> file(vmarchive::kWavHeaderBytes + dataBytes, 0);
	vmarchive::buildWavHeader(dataBytes, file.data());
	for (size_t i = 0; i < dataBytes; ++i)
	{
		file[vmarchive::kWavHeaderBytes + i] = static_cast<uint8_t>(i & 0xFF);
	}

	size_t outOffset = 0, outBytes = 0;
	ASSERT_TRUE(HoldMusic::parseUlawWav(file.data(), file.size(), outOffset, outBytes))
		<< "the production reader must accept exactly what the writer produces";
	EXPECT_EQ(outOffset, vmarchive::kWavHeaderBytes);
	EXPECT_EQ(outBytes, dataBytes);

	// The parsed offset/length must actually point at the real audio, not
	// just satisfy the parser's bookkeeping.
	EXPECT_EQ(std::memcmp(file.data() + outOffset, file.data() + vmarchive::kWavHeaderBytes,
		dataBytes), 0);
}

TEST(VoicemailArchive, WavHeaderIsExactly58Bytes)
{
	uint8_t header[vmarchive::kWavHeaderBytes];
	vmarchive::buildWavHeader(1234, header);
	// If this ever needs to grow, kWavHeaderBytes and every caller sizing a
	// staging/file buffer around it must move together -- pinned here so a
	// silent drift is a build-time-visible test failure, not a corrupt file.
	EXPECT_EQ(sizeof(header), 58u);
}

TEST(VoicemailArchive, WavHeaderZeroLengthProducesAStructurallyValidHeader)
{
	// A caller that hangs up before saying anything -- must not corrupt/crash
	// the header builder. NOT round-tripped through HoldMusic::parseUlawWav()
	// here: that parser deliberately rejects dataLen == 0 (a zero-length loop
	// clip is meaningless for hold music), which is correct for ITS purpose
	// but not a constraint this builder itself needs to satisfy -- whether an
	// empty recording is even worth writing to SD at all is a decision for
	// the flush-wiring slice, not this header builder.
	std::vector<uint8_t> file(vmarchive::kWavHeaderBytes, 0xAA);
	vmarchive::buildWavHeader(0, file.data());
	EXPECT_EQ(std::memcmp(file.data(), "RIFF", 4), 0);
	EXPECT_EQ(std::memcmp(file.data() + 8, "WAVE", 4), 0);
	EXPECT_EQ(std::memcmp(file.data() + 50, "data", 4), 0);
	// data chunk size field (offset 54, little-endian u32) must be 0.
	EXPECT_EQ(file[54], 0); EXPECT_EQ(file[55], 0);
	EXPECT_EQ(file[56], 0); EXPECT_EQ(file[57], 0);
}

TEST(WriterQueue, PushPopIsFifo)
{
	vmarchive::WriterQueue q(4);
	ASSERT_TRUE(q.push(makeRec(0, "301", "call-1", 1, 100)));
	ASSERT_TRUE(q.push(makeRec(1, "302", "call-2", 2, 200)));

	vmarchive::QueuedRecording out;
	ASSERT_TRUE(q.pop(out));
	EXPECT_STREQ(out.extension, "301");
	ASSERT_TRUE(q.pop(out));
	EXPECT_STREQ(out.extension, "302");
	EXPECT_FALSE(q.pop(out));
}

TEST(WriterQueue, DropsRatherThanBlocksWhenFull)
{
	vmarchive::WriterQueue q(2);
	EXPECT_TRUE(q.push(makeRec(0, "301", "c1", 1, 1)));
	EXPECT_TRUE(q.push(makeRec(1, "302", "c2", 2, 1)));
	EXPECT_FALSE(q.push(makeRec(0, "303", "c3", 3, 1)))
		<< "must drop, not overwrite or block, when the queue is full";
	EXPECT_EQ(q.size(), 2u);
}

TEST(WriterQueue, ClearDiscardsEverythingQueued)
{
	vmarchive::WriterQueue q(4);
	q.push(makeRec(0, "301", "c1", 1, 1));
	q.push(makeRec(1, "302", "c2", 2, 1));
	q.clear();
	EXPECT_EQ(q.size(), 0u);
	vmarchive::QueuedRecording out;
	EXPECT_FALSE(q.pop(out));
}

TEST(DrainAll, DrainsEveryQueuedJobInOrderReadingFromItsOwnStagingSlot)
{
	vmarchive::WriterQueue q(4);
	uint8_t stagingA[8] = {1, 2, 3, 4, 5, 6, 7, 8};
	uint8_t stagingB[4] = {9, 9, 9, 9};
	uint8_t* stagingBufs[2] = {stagingA, stagingB};

	q.push(makeRec(0, "301", "call-1", 1, sizeof(stagingA)));
	q.push(makeRec(1, "302", "call-2", 2, sizeof(stagingB)));

	FakeSink sink;
	vmarchive::drainAll(q, sink, stagingBufs);

	ASSERT_EQ(sink.calls.size(), 2u);
	EXPECT_STREQ(sink.calls[0].rec.extension, "301");
	EXPECT_EQ(sink.calls[0].mulaw, std::vector<uint8_t>({1, 2, 3, 4, 5, 6, 7, 8}));
	EXPECT_STREQ(sink.calls[1].rec.extension, "302");
	EXPECT_EQ(sink.calls[1].mulaw, std::vector<uint8_t>({9, 9, 9, 9}));

	EXPECT_EQ(q.size(), 0u) << "drainAll must actually drain, not peek";
}

TEST(DrainAll, OnAnEmptyQueueCallsTheSinkZeroTimes)
{
	vmarchive::WriterQueue q(4);
	uint8_t staging[4] = {};
	uint8_t* stagingBufs[1] = {staging};
	FakeSink sink;
	vmarchive::drainAll(q, sink, stagingBufs);
	EXPECT_TRUE(sink.calls.empty());
}
