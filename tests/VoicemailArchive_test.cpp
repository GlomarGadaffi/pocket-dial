// VoicemailArchive_test.cpp — Issue #246 (voicemail Stage 3 of #194).
//
// The pure pieces of the SD-flush pipeline: the mu-law WAV header builder
// (round-tripped through HoldMusic::parseUlawWav, the actual production
// reader, rather than asserting on byte offsets by hand) and the
// WriterQueue/drainAll queue mechanics, mirroring CdrArchive_test.cpp's
// shape for the same reasons CdrArchive.hpp's class comment gives.

#include <gtest/gtest.h>

#include <cstring>
#include <map>
#include <string>
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
		int wipes = 0;
		void wipe() override { ++wipes; }
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

	// In-memory double for vmarchive::Source -- what the retrieval routing
	// and VoicemailMenu slices test against, the same role FakeSink plays
	// for the write side. Not a model of FatFsSource's file-parsing (that's
	// ESP-gated and untested on host, same as FatFsSink) -- just the
	// CONTRACT: list skips deleted, read returns exact bytes or 0, delete
	// is idempotent.
	class FakeSource : public vmarchive::Source
	{
	public:
		struct Stored
		{
			vmarchive::MessageInfo info;
			std::vector<uint8_t> body;
			bool deleted = false;
		};
		std::map<std::string, std::vector<Stored>> mailboxes;

		void deposit(const std::string& ext, const char* name, uint64_t epoch,
			const char* callId, std::vector<uint8_t> body)
		{
			Stored s;
			std::strncpy(s.info.name, name, sizeof(s.info.name) - 1);
			s.info.epochSeconds = epoch;
			s.info.length = body.size();
			std::strncpy(s.info.callId, callId, sizeof(s.info.callId) - 1);
			s.body = std::move(body);
			mailboxes[ext].push_back(std::move(s));
		}

		size_t listMessages(const char* extension, vmarchive::MessageInfo* out,
			size_t maxCount) const override
		{
			auto it = mailboxes.find(extension);
			if (it == mailboxes.end()) return 0;
			size_t count = 0;
			for (const auto& s : it->second)
			{
				if (s.deleted) continue;
				if (count >= maxCount) break;
				out[count++] = s.info;
			}
			return count;
		}

		size_t readMessage(const char* extension, const char* name,
			uint8_t* out, size_t capacity) const override
		{
			auto it = mailboxes.find(extension);
			if (it == mailboxes.end()) return 0;
			for (const auto& s : it->second)
			{
				if (s.deleted || std::strcmp(s.info.name, name) != 0) continue;
				if (s.body.size() > capacity) return 0;
				std::memcpy(out, s.body.data(), s.body.size());
				return s.body.size();
			}
			return 0;
		}

		bool markDeleted(const char* extension, const char* name) override
		{
			auto it = mailboxes.find(extension);
			if (it == mailboxes.end()) return true;
			for (auto& s : it->second)
			{
				if (std::strcmp(s.info.name, name) == 0) { s.deleted = true; break; }
			}
			return true;
		}
	};
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

// ── Source contract (FakeSource) ─────────────────────────────────────────

TEST(VoicemailArchiveSource, ListMessagesOnUnknownExtensionReturnsZeroNotError)
{
	FakeSource src;
	vmarchive::MessageInfo out[4];
	EXPECT_EQ(src.listMessages("999", out, 4), 0u);
}

TEST(VoicemailArchiveSource, ListMessagesReturnsWhatWasDeposited)
{
	FakeSource src;
	src.deposit("301", "1000", 1000, "call-1", {1, 2, 3});
	src.deposit("301", "1001", 1001, "call-2", {4, 5});

	vmarchive::MessageInfo out[4];
	ASSERT_EQ(src.listMessages("301", out, 4), 2u);
	EXPECT_STREQ(out[0].name, "1000");
	EXPECT_EQ(out[0].length, 3u);
	EXPECT_STREQ(out[1].name, "1001");
	EXPECT_EQ(out[1].length, 2u);
}

TEST(VoicemailArchiveSource, ListMessagesRespectsMaxCount)
{
	FakeSource src;
	src.deposit("301", "1000", 1000, "call-1", {1});
	src.deposit("301", "1001", 1001, "call-2", {2});
	vmarchive::MessageInfo out[1];
	EXPECT_EQ(src.listMessages("301", out, 1), 1u);
}

TEST(VoicemailArchiveSource, ReadMessageReturnsExactBytes)
{
	FakeSource src;
	src.deposit("301", "1000", 1000, "call-1", {9, 8, 7, 6});
	uint8_t out[8] = {};
	EXPECT_EQ(src.readMessage("301", "1000", out, sizeof(out)), 4u);
	EXPECT_EQ(std::vector<uint8_t>(out, out + 4), std::vector<uint8_t>({9, 8, 7, 6}));
}

TEST(VoicemailArchiveSource, ReadMessageRefusesRatherThanTruncateWhenTooLargeForCapacity)
{
	FakeSource src;
	src.deposit("301", "1000", 1000, "call-1", {1, 2, 3, 4, 5});
	uint8_t out[3] = {};
	EXPECT_EQ(src.readMessage("301", "1000", out, sizeof(out)), 0u)
		<< "must refuse outright, not clip, when the message doesn't fit";
}

TEST(VoicemailArchiveSource, ReadMessageOnUnknownNameReturnsZero)
{
	FakeSource src;
	src.deposit("301", "1000", 1000, "call-1", {1});
	uint8_t out[4];
	EXPECT_EQ(src.readMessage("301", "nope", out, sizeof(out)), 0u);
}

TEST(VoicemailArchiveSource, MarkDeletedHidesFromListingAndFromRead)
{
	FakeSource src;
	src.deposit("301", "1000", 1000, "call-1", {1, 2, 3});
	ASSERT_TRUE(src.markDeleted("301", "1000"));

	vmarchive::MessageInfo out[4];
	EXPECT_EQ(src.listMessages("301", out, 4), 0u);
	uint8_t body[4];
	EXPECT_EQ(src.readMessage("301", "1000", body, sizeof(body)), 0u);
}

TEST(VoicemailArchiveSource, MarkDeletedIsIdempotentOnAnAlreadyDeletedOrUnknownName)
{
	FakeSource src;
	src.deposit("301", "1000", 1000, "call-1", {1});
	EXPECT_TRUE(src.markDeleted("301", "1000"));
	EXPECT_TRUE(src.markDeleted("301", "1000"));           // already deleted
	EXPECT_TRUE(src.markDeleted("999", "nope"));           // unknown mailbox entirely
}

// ── Pure index.csv line parsing (FatFsSource's non-filesystem half) ────────

TEST(VoicemailArchiveIndexParsing, ChompStripsTrailingCrLf)
{
	char line[32];
	std::strcpy(line, "hello\r\n");
	vmarchive::chompIndexLine(line);
	EXPECT_STREQ(line, "hello");
}

TEST(VoicemailArchiveIndexParsing, ChompIsANoOpWithNoTrailingNewline)
{
	char line[32];
	std::strcpy(line, "hello");
	vmarchive::chompIndexLine(line);
	EXPECT_STREQ(line, "hello");
}

TEST(VoicemailArchiveIndexParsing, ParseTombstoneLineExtractsTheName)
{
	char name[48] = {};
	ASSERT_TRUE(vmarchive::parseTombstoneLine("#DEL,1234567890", name, sizeof(name)));
	EXPECT_STREQ(name, "1234567890");
}

TEST(VoicemailArchiveIndexParsing, ParseTombstoneLineRejectsARealEntryRow)
{
	char name[48] = {};
	EXPECT_FALSE(vmarchive::parseTombstoneLine("1234567890,1000,3,call-1", name, sizeof(name)));
}

TEST(VoicemailArchiveIndexParsing, ParseEntryLineExtractsAllFourFields)
{
	vmarchive::MessageInfo info;
	ASSERT_TRUE(vmarchive::parseEntryLine("1234567890,1000,3,vm-greet-1", info));
	EXPECT_STREQ(info.name, "1234567890");
	EXPECT_EQ(info.epochSeconds, 1000u);
	EXPECT_EQ(info.length, 3u);
	EXPECT_STREQ(info.callId, "vm-greet-1");
}

TEST(VoicemailArchiveIndexParsing, ParseEntryLineToleratesCommasInsideCallId)
{
	// The write side never escapes callId -- a Call-ID header value could in
	// principle contain a comma (unusual, but not forbidden by RFC 3261).
	// Only the first three commas are structural; everything after belongs
	// to callId verbatim.
	vmarchive::MessageInfo info;
	ASSERT_TRUE(vmarchive::parseEntryLine("1234567890,1000,3,weird,call,id", info));
	EXPECT_STREQ(info.callId, "weird,call,id");
}

TEST(VoicemailArchiveIndexParsing, ParseEntryLineRejectsATombstoneRow)
{
	vmarchive::MessageInfo info;
	EXPECT_FALSE(vmarchive::parseEntryLine("#DEL,1234567890", info));
}

TEST(VoicemailArchiveIndexParsing, ParseEntryLineRejectsAMalformedRow)
{
	vmarchive::MessageInfo info;
	EXPECT_FALSE(vmarchive::parseEntryLine("not,enough,fields", info));
	EXPECT_FALSE(vmarchive::parseEntryLine("", info));
}

TEST(VoicemailArchiveIndexParsing, ParseEntryLineRejectsAnEmptyNameField)
{
	vmarchive::MessageInfo info;
	EXPECT_FALSE(vmarchive::parseEntryLine(",1000,3,call-1", info));
}
