#include <gtest/gtest.h>
#include "CdrArchive.hpp"
#include "CallDetailRecord.hpp"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

// CdrArchive (issue #194 Stage 1) -- what's covered here, and what ISN'T.
//
// COVERED: the whole pure/portable half of the module -- formatLine()'s CSV
// serialization (including the wall-clock derivation, the clock-skew clamps,
// and RFC 4180 escaping/truncation of the two fields that aren't already
// charset-safe), WriterQueue's push/pop/drop-when-full/clear mechanics, and
// drainAll()'s queue-to-sink decoupling, all driven with a FakeSink so none
// of it touches a filesystem.
//
// NOT COVERED, honestly: real SD file I/O (FatFsSink, PD_ETH_HAS_SD-gated,
// ESP-only) and the writer FreeRTOS task -- see the issue's own tests section
// ("SNTP bring-up and real file I/O are not host-testable"). Also NOT
// coverable on host: record()'s "actually enqueues a line" happy path,
// because that requires timesync::epochSeconds() != 0, and the host build's
// SNTP client is permanently unsynced by construction (TimeSync_test.cpp
// pins that same fact for TimeSync itself). What IS tested below for
// record()/wipeAll() is their host-REACHABLE contract: no sink installed ->
// harmless no-op, and an unsynced clock -> record() never queues anything
// even once a sink exists. The "line actually gets queued and drained"
// happy path is covered instead at the formatLine()/WriterQueue/drainAll()
// level, which does not need a clock at all -- the caller supplies "now".

namespace
{

class FakeSink : public cdrarchive::Sink
{
public:
	struct Entry { std::string date; std::string line; };
	std::vector<Entry> appended;
	bool wiped = false;

	void append(const cdrarchive::QueuedLine& l) override
	{
		appended.push_back({std::string(l.date), std::string(l.line)});
	}
	void wipe() override { wiped = true; }
};

// RAII so a test can install a FakeSink without leaking state into whichever
// test happens to run next in this shared binary -- same pattern
// TelephonyApiConfig_test.cpp's setStorePath() fixture uses for host isolation.
class ScopedSink
{
public:
	explicit ScopedSink(cdrarchive::Sink* s) : _prev(cdrarchive::setSinkForTest(s)) {}
	~ScopedSink() { cdrarchive::setSinkForTest(_prev); }
private:
	cdrarchive::Sink* _prev;
};

CallDetailRecord makeRecord(std::string caller, std::string callee,
	uint64_t startMs, uint32_t durationSec, CdrResult result)
{
	CallDetailRecord r;
	r.caller = std::move(caller);
	r.callee = std::move(callee);
	r.startMs = startMs;
	r.durationSec = durationSec;
	r.result = result;
	return r;
}

}  // namespace

// ── csvHeader() ──────────────────────────────────────────────────────────────

TEST(CdrArchive, HeaderHasSevenFieldsMatchingFormatLineOrder)
{
	const std::string h = cdrarchive::csvHeader();
	EXPECT_EQ(h, "timestamp,call_id,caller,callee,duration_sec,result,reason");
	EXPECT_EQ(std::count(h.begin(), h.end(), ','), 6);
}

// ── formatLine(): the wall-clock derivation ───────────────────────────────────

TEST(CdrArchive, FormatLineStampsTheCallStartNotTheArchiveMoment)
{
	// startMs == nowSteadyMs (delta 0) so the derived wall-clock start equals
	// nowEpochSeconds exactly -- 1700000000 = 2023-11-14T22:13:20Z, the same
	// fixed vector TimeSync_test.cpp uses, so a formatRfc3339 regression would
	// be caught there first.
	auto rec = makeRecord("1001", "1002", /*startMs=*/5000, 42, CdrResult::Answered);
	cdrarchive::QueuedLine line;
	ASSERT_TRUE(cdrarchive::formatLine(rec, "abc123@host", "", /*nowEpochSeconds=*/1700000000,
		/*nowSteadyMs=*/5000, line));

	EXPECT_STREQ(line.date, "2023-11-14");
	EXPECT_EQ(std::string(line.line).substr(0, 20), "2023-11-14T22:13:20Z");
}

TEST(CdrArchive, FormatLineSubtractsElapsedTimeFromNow)
{
	// The call started 10 s (10000 ms of steady-clock time) before "now".
	// nowEpochSeconds=1700000010 minus 10 s = 1700000000 = the same fixed
	// vector as above.
	auto rec = makeRecord("1001", "1002", /*startMs=*/0, 10, CdrResult::Answered);
	cdrarchive::QueuedLine line;
	ASSERT_TRUE(cdrarchive::formatLine(rec, "call-1", "", 1700000010, /*nowSteadyMs=*/10000, line));
	EXPECT_STREQ(line.date, "2023-11-14");
}

TEST(CdrArchive, FormatLineClampsNegativeSkewInsteadOfUnderflowing)
{
	// nowSteadyMs BEFORE rec.startMs (a stale snapshot racing a fresher
	// CdrRing::record() call) must not go negative -- clamp to 0 elapsed.
	auto rec = makeRecord("1001", "1002", /*startMs=*/50000, 0, CdrResult::Answered);
	cdrarchive::QueuedLine line;
	ASSERT_TRUE(cdrarchive::formatLine(rec, "call-2", "", 1700000000, /*nowSteadyMs=*/1000, line));
	// Elapsed clamped to 0 -> start == now == the fixed vector.
	EXPECT_STREQ(line.date, "2023-11-14");
}

TEST(CdrArchive, FormatLineClampsElapsedLargerThanTheWallClockItself)
{
	// A pathological steady-clock delta (bigger than nowEpochSeconds) must
	// clamp to "now", not wrap a uint64 subtraction into a huge bogus epoch.
	auto rec = makeRecord("1001", "1002", /*startMs=*/0, 0, CdrResult::Answered);
	cdrarchive::QueuedLine line;
	ASSERT_TRUE(cdrarchive::formatLine(rec, "call-3", "", /*nowEpochSeconds=*/10,
		/*nowSteadyMs=*/50000, line));
	EXPECT_STREQ(line.date, "1970-01-01");  // clamped to nowEpochSeconds=10, not underflowed
}

TEST(CdrArchive, FormatLineDropsTheRecordWhenNeverSynced)
{
	// nowEpochSeconds == 0 is timesync::epochSeconds()'s "never synced"
	// sentinel -- there is no honest date to file this row under.
	auto rec = makeRecord("1001", "1002", 0, 5, CdrResult::Answered);
	cdrarchive::QueuedLine line;
	line.date[0] = 'X';  // sentinel so we can see formatLine() reset it
	EXPECT_FALSE(cdrarchive::formatLine(rec, "call-4", "", /*nowEpochSeconds=*/0, 0, line));
	EXPECT_EQ(line.date[0], '\0');
}

// ── formatLine(): field content, escaping, truncation ─────────────────────────

TEST(CdrArchive, FormatLineIncludesAllSevenFieldsInOrder)
{
	auto rec = makeRecord("1001", "2002", 0, 90, CdrResult::Busy);
	cdrarchive::QueuedLine line;
	ASSERT_TRUE(cdrarchive::formatLine(rec, "call-xyz", "peer busy", 1700000000, 0, line));

	EXPECT_EQ(std::string(line.line),
		"2023-11-14T22:13:20Z,call-xyz,1001,2002,90,busy,peer busy");
}

TEST(CdrArchive, FormatLineEscapesACommaInReason)
{
	auto rec = makeRecord("1001", "2002", 0, 0, CdrResult::Failed);
	cdrarchive::QueuedLine line;
	ASSERT_TRUE(cdrarchive::formatLine(rec, "call-1", "busy, retry later", 1700000000, 0, line));
	EXPECT_NE(std::string(line.line).find("\"busy, retry later\""), std::string::npos);
}

TEST(CdrArchive, FormatLineDoublesEmbeddedQuotesInReason)
{
	auto rec = makeRecord("1001", "2002", 0, 0, CdrResult::Failed);
	cdrarchive::QueuedLine line;
	ASSERT_TRUE(cdrarchive::formatLine(rec, "call-1", "said \"no\"", 1700000000, 0, line));
	// RFC 4180: a literal quote inside a quoted field is written as two quotes.
	EXPECT_NE(std::string(line.line).find("\"said \"\"no\"\"\""), std::string::npos);
}

TEST(CdrArchive, FormatLineTruncatesAnOversizedCallId)
{
	// SIP Call-ID has no practical upper bound on the wire; the archive must
	// not let one grow the row unboundedly.
	const std::string longCallId(200, 'x');
	auto rec = makeRecord("1001", "2002", 0, 0, CdrResult::Answered);
	cdrarchive::QueuedLine line;
	ASSERT_TRUE(cdrarchive::formatLine(rec, longCallId, "", 1700000000, 0, line));

	// call_id is the 2nd of 7 comma-separated fields (none of which need
	// quoting here, since 'x' triggers no escaping).
	const std::string s(line.line);
	const size_t f1 = s.find(',');
	const size_t f2 = s.find(',', f1 + 1);
	ASSERT_NE(f1, std::string::npos);
	ASSERT_NE(f2, std::string::npos);
	EXPECT_LE(f2 - f1 - 1, 64u);   // kMaxCallIdRaw
	EXPECT_GT(f2 - f1 - 1, 0u);
}

TEST(CdrArchive, FormatLineTruncatesAnOversizedAor)
{
	// CallDetailRecord.hpp's corrected comment: anchor-sourced caller/callee
	// values bypass isValidAor()'s length bound entirely. The archive must
	// enforce its own regardless of what wrote the CDR.
	const std::string longAor(200, 'y');
	auto rec = makeRecord(longAor, "2002", 0, 0, CdrResult::Answered);
	cdrarchive::QueuedLine line;
	ASSERT_TRUE(cdrarchive::formatLine(rec, "call-1", "", 1700000000, 0, line));

	const std::string s(line.line);
	// caller is the 3rd field.
	const size_t f1 = s.find(',');
	const size_t f2 = s.find(',', f1 + 1);
	const size_t f3 = s.find(',', f2 + 1);
	ASSERT_NE(f3, std::string::npos);
	EXPECT_LE(f3 - f2 - 1, 48u);  // kMaxAorRaw
}

TEST(CdrArchive, FormatLineNeverOverflowsTheFixedLineBuffer)
{
	// Every field simultaneously at its cap AND maximally quote-heavy -- the
	// exact worst case QueuedLine::line's doc comment sizes against.
	const std::string quotes200(200, '"');
	auto rec = makeRecord(quotes200, quotes200, 0, 4000000000u, CdrResult::Unavailable);
	cdrarchive::QueuedLine line;
	ASSERT_TRUE(cdrarchive::formatLine(rec, quotes200, quotes200, 1700000000, 0, line));
	// No crash/overflow (ASan/UBSan would catch a real one in this suite),
	// and the row is still NUL-terminated within the buffer.
	EXPECT_LT(std::string(line.line).size(), sizeof(line.line));
}

// ── WriterQueue ────────────────────────────────────────────────────────────────

TEST(CdrArchiveWriterQueue, PushPopIsFifo)
{
	cdrarchive::WriterQueue q(4);
	cdrarchive::QueuedLine a, b, c;
	std::strcpy(a.line, "a"); std::strcpy(b.line, "b"); std::strcpy(c.line, "c");
	ASSERT_TRUE(q.push(a));
	ASSERT_TRUE(q.push(b));
	ASSERT_TRUE(q.push(c));
	EXPECT_EQ(q.size(), 3u);

	cdrarchive::QueuedLine out;
	ASSERT_TRUE(q.pop(out)); EXPECT_STREQ(out.line, "a");
	ASSERT_TRUE(q.pop(out)); EXPECT_STREQ(out.line, "b");
	ASSERT_TRUE(q.pop(out)); EXPECT_STREQ(out.line, "c");
	EXPECT_FALSE(q.pop(out));
	EXPECT_EQ(q.size(), 0u);
}

TEST(CdrArchiveWriterQueue, DropsRatherThanBlocksWhenFull)
{
	cdrarchive::WriterQueue q(2);
	cdrarchive::QueuedLine l;
	EXPECT_TRUE(q.push(l));
	EXPECT_TRUE(q.push(l));
	EXPECT_FALSE(q.push(l));   // full -- dropped, not blocked
	EXPECT_EQ(q.size(), 2u);
}

TEST(CdrArchiveWriterQueue, ClearDiscardsEverythingQueued)
{
	cdrarchive::WriterQueue q(4);
	cdrarchive::QueuedLine l;
	q.push(l); q.push(l); q.push(l);
	ASSERT_EQ(q.size(), 3u);

	q.clear();
	EXPECT_EQ(q.size(), 0u);
	cdrarchive::QueuedLine out;
	EXPECT_FALSE(q.pop(out));
}

TEST(CdrArchiveWriterQueue, ZeroCapacityQueueAlwaysDrops)
{
	cdrarchive::WriterQueue q(0);
	cdrarchive::QueuedLine l;
	EXPECT_FALSE(q.push(l));
	EXPECT_EQ(q.size(), 0u);
}

// ── drainAll(): the queue/writer-task decoupling contract ─────────────────────

TEST(CdrArchive, DrainAllAppendsEveryQueuedLineInOrderThenEmptiesTheQueue)
{
	cdrarchive::WriterQueue q(8);
	for (int i = 0; i < 5; ++i)
	{
		cdrarchive::QueuedLine l;
		std::snprintf(l.line, sizeof(l.line), "line-%d", i);
		std::strcpy(l.date, "2026-09-14");
		ASSERT_TRUE(q.push(l));
	}

	FakeSink sink;
	cdrarchive::drainAll(q, sink);

	ASSERT_EQ(sink.appended.size(), 5u);
	for (int i = 0; i < 5; ++i)
	{
		EXPECT_EQ(sink.appended[static_cast<size_t>(i)].line, "line-" + std::to_string(i));
		EXPECT_EQ(sink.appended[static_cast<size_t>(i)].date, "2026-09-14");
	}
	EXPECT_EQ(q.size(), 0u);
}

TEST(CdrArchive, DrainAllOnAnEmptyQueueAppendsNothing)
{
	cdrarchive::WriterQueue q(4);
	FakeSink sink;
	cdrarchive::drainAll(q, sink);
	EXPECT_TRUE(sink.appended.empty());
}

// ── Singleton entry points: the host-REACHABLE contract only ──────────────────
// (see the file header comment for exactly what this can and can't prove here)

TEST(CdrArchiveSingleton, RecordWithNoSinkInstalledIsAHarmlessNoOp)
{
	ScopedSink guard(nullptr);   // explicit "no archive installed" state
	auto rec = makeRecord("1001", "1002", 0, 1, CdrResult::Answered);
	cdrarchive::record(rec, "call-1", "test");
	EXPECT_EQ(cdrarchive::pendingForTest(), 0u);
}

TEST(CdrArchiveSingleton, RecordNeverQueuesOnAnUnsyncedHostClock)
{
	// The host build's SNTP client is permanently unsynced (TimeSync_test.cpp
	// pins this same fact for TimeSync directly) -- so even WITH a sink
	// installed, record() must still drop every call rather than archive it
	// under a fabricated date. This is the "graceful no-op on a build with no
	// [working clock]" contract the issue asks to be tested.
	FakeSink sink;
	ScopedSink guard(&sink);
	auto rec = makeRecord("1001", "1002", 0, 1, CdrResult::Answered);
	cdrarchive::record(rec, "call-1", "test");
	EXPECT_EQ(cdrarchive::pendingForTest(), 0u);
	EXPECT_TRUE(sink.appended.empty());
}

TEST(CdrArchiveSingleton, WipeAllCallsSinkWipe)
{
	FakeSink sink;
	ScopedSink guard(&sink);
	cdrarchive::wipeAll();
	EXPECT_TRUE(sink.wiped);
}

TEST(CdrArchiveSingleton, WipeAllWithNoSinkInstalledIsAHarmlessNoOp)
{
	ScopedSink guard(nullptr);
	cdrarchive::wipeAll();   // must not crash
	SUCCEED();
}
