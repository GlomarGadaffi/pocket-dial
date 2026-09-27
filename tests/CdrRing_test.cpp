#include <gtest/gtest.h>
#include "CdrRing.hpp"
#include "CallDetailRecord.hpp"
#include "PbxPersist.hpp"

#include <array>
#include <cstring>
#include <string>
#include <vector>

// CdrRing_test.cpp -- issue #273/#277/#288's fix.
//
// COVERED: CdrRing::serializeForPersist()'s whole contract -- the exact blob
// format persist() now builds (unchanged wire format from before the fix),
// oldest-first ordering across a wrapped ring, empty/full/over-cap inputs,
// caller/callee truncation at the fixed-buffer boundary, and round-tripping
// the result through pbxpersist::deserializeBlob() (the SAME function
// CdrRing::load() uses) to prove the persisted format load() will read back
// is unchanged -- the one thing that must be true for this fix to be safe to
// ship, since load()/deserializeBlob() were deliberately NOT touched.
//
// NOT COVERED, honestly: the FreeRTOS queue, the writer task, and the actual
// nvs_set_str/nvs_commit call -- all ESP-only, all gated out of the host
// build, same as CdrArchive_test.cpp's writer task. What IS host-testable is
// the ENTIRE reason the fix is safe: that moving the flash write off the
// calling task changes nothing about what gets persisted, which is exactly
// serializeForPersist()'s contract. The one thing this file cannot prove --
// that the fix actually stops the panic -- needs a hardware bench pass
// against issue #273's repro; see the PR description.

namespace
{
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

	// Builds a ring array with `records` written starting at logical index 0,
	// with `head` landing wherever writing that many records from a given
	// starting head would put it -- mirrors how CdrRing::record() actually
	// advances _head, so wrap-around tests exercise the real indexing math.
	std::array<CallDetailRecord, POCKETDIAL_CDR_RECORDS> makeRing(
		const std::vector<CallDetailRecord>& records, size_t startHead, size_t& headOut)
	{
		std::array<CallDetailRecord, POCKETDIAL_CDR_RECORDS> ring{};
		size_t head = startHead;
		for (const auto& r : records)
		{
			ring[head] = r;
			head = (head + 1) % POCKETDIAL_CDR_RECORDS;
		}
		headOut = head;
		return ring;
	}
}

TEST(CdrRingSerialize, EmptyRingProducesEmptyBlob)
{
	std::array<CallDetailRecord, POCKETDIAL_CDR_RECORDS> ring{};
	CdrRingBlob blob;
	CdrRing::serializeForPersist(ring, /*head=*/0, /*count=*/0, blob);
	EXPECT_STREQ(blob.text, "");
}

TEST(CdrRingSerialize, OneRecordMatchesExactByteFormat)
{
	std::array<CallDetailRecord, POCKETDIAL_CDR_RECORDS> ring{};
	ring[0] = makeRecord("1001", "5551234567", 1000, 42, CdrResult::Answered);
	CdrRingBlob blob;
	CdrRing::serializeForPersist(ring, /*head=*/1, /*count=*/1, blob);
	EXPECT_STREQ(blob.text, "1001\t5551234567\t1000\t42\t0\n");
}

TEST(CdrRingSerialize, MultipleRecordsAreOldestFirst)
{
	size_t head = 0;
	auto ring = makeRing({
		makeRecord("a", "b", 1, 1, CdrResult::Answered),
		makeRecord("c", "d", 2, 2, CdrResult::Busy),
		makeRecord("e", "f", 3, 3, CdrResult::Cancelled),
	}, 0, head);

	CdrRingBlob blob;
	CdrRing::serializeForPersist(ring, head, /*count=*/3, blob);
	EXPECT_STREQ(blob.text, "a\tb\t1\t1\t0\nc\td\t2\t2\t1\ne\tf\t3\t3\t2\n");
}

TEST(CdrRingSerialize, OrderingSurvivesRingWraparound)
{
	// Start head near the end of the ring so writing 5 records wraps.
	size_t head = 0;
	const size_t startHead = POCKETDIAL_CDR_RECORDS - 2;
	auto ring = makeRing({
		makeRecord("r1", "x", 1, 0, CdrResult::Answered),
		makeRecord("r2", "x", 2, 0, CdrResult::Answered),
		makeRecord("r3", "x", 3, 0, CdrResult::Answered),   // wraps to index 0
		makeRecord("r4", "x", 4, 0, CdrResult::Answered),
		makeRecord("r5", "x", 5, 0, CdrResult::Answered),
	}, startHead, head);

	CdrRingBlob blob;
	CdrRing::serializeForPersist(ring, head, /*count=*/5, blob);
	EXPECT_STREQ(blob.text, "r1\tx\t1\t0\t0\nr2\tx\t2\t0\t0\nr3\tx\t3\t0\t0\nr4\tx\t4\t0\t0\nr5\tx\t5\t0\t0\n");
}

TEST(CdrRingSerialize, FullRingKeepsOnlyTheNewestCountRecordsInOrder)
{
	// count is always <= POCKETDIAL_CDR_RECORDS by construction in CdrRing
	// (record() caps it), but exercise the exact-capacity boundary anyway --
	// this is the value CdrRing::record() actually reaches once the ring has
	// wrapped at least once.
	std::vector<CallDetailRecord> records;
	for (size_t i = 0; i < POCKETDIAL_CDR_RECORDS; ++i)
	{
		records.push_back(makeRecord("c" + std::to_string(i), "d", i, 0, CdrResult::Answered));
	}
	size_t head = 0;
	auto ring = makeRing(records, 0, head);
	ASSERT_EQ(head, 0u) << "writing exactly POCKETDIAL_CDR_RECORDS from head 0 must wrap back to 0";

	CdrRingBlob blob;
	CdrRing::serializeForPersist(ring, head, POCKETDIAL_CDR_RECORDS, blob);

	auto parsed = pbxpersist::deserializeBlob(blob.text);
	ASSERT_EQ(parsed.size(), static_cast<size_t>(POCKETDIAL_CDR_RECORDS));
	EXPECT_EQ(parsed.front()[0], "c0") << "oldest record first";
	EXPECT_EQ(parsed.back()[0], "c" + std::to_string(POCKETDIAL_CDR_RECORDS - 1)) << "newest record last";
}

TEST(CdrRingSerialize, OverlongCallerAndCalleeAreTruncatedNotOverflowed)
{
	std::array<CallDetailRecord, POCKETDIAL_CDR_RECORDS> ring{};
	// Anchor-sourced values can exceed isValidAor()'s bound -- see
	// CdrRing.cpp's kMaxAorRaw comment. 200 bytes is comfortably past the
	// 48-byte cap.
	const std::string tooLong(200, 'x');
	ring[0] = makeRecord(tooLong, tooLong, 1, 1, CdrResult::Answered);

	CdrRingBlob blob;
	CdrRing::serializeForPersist(ring, /*head=*/1, /*count=*/1, blob);

	// Still a well-formed, parseable single record -- truncation must not
	// eat the field separators or corrupt the following fields.
	auto parsed = pbxpersist::deserializeBlob(blob.text);
	ASSERT_EQ(parsed.size(), 1u);
	ASSERT_EQ(parsed[0].size(), 5u);
	EXPECT_LE(parsed[0][0].size(), 48u) << "caller truncated to the cap";
	EXPECT_LE(parsed[0][1].size(), 48u) << "callee truncated to the cap";
	EXPECT_EQ(parsed[0][2], "1");
	EXPECT_EQ(parsed[0][3], "1");
	EXPECT_EQ(parsed[0][4], "0");
}

TEST(CdrRingSerialize, WorstCaseFullRingOfMaximalFieldsNeverOverflowsAndStaysParseable)
{
	// Adversarial: every one of POCKETDIAL_CDR_RECORDS records at its worst
	// case -- maximal caller/callee (so truncation runs on every field of
	// every record, not just one) and the largest values every numeric field
	// can hold. This is the exact scenario kMaxLineBytes's arithmetic in
	// CdrRing.cpp is sized against; if that arithmetic is wrong, this test
	// is where it would show up as a truncated LAST record, a missing
	// trailing newline, or a parse count short of POCKETDIAL_CDR_RECORDS --
	// not as a crash, because serializeForPersist()'s appendField() clips at
	// the buffer boundary by construction rather than overflowing it.
	std::vector<CallDetailRecord> records;
	const std::string maxAor(200, 'z');
	for (size_t i = 0; i < POCKETDIAL_CDR_RECORDS; ++i)
	{
		records.push_back(makeRecord(maxAor, maxAor,
			UINT64_MAX, UINT32_MAX, CdrResult::Failed));
	}
	size_t head = 0;
	auto ring = makeRing(records, 0, head);

	CdrRingBlob blob;
	CdrRing::serializeForPersist(ring, head, POCKETDIAL_CDR_RECORDS, blob);

	// The buffer itself must still be a valid, NUL-terminated C string within
	// its declared capacity (a raw strlen scan would run off the end of an
	// unterminated buffer, which is exactly what this checks for).
	size_t len = strnlen(blob.text, sizeof(blob.text));
	ASSERT_LT(len, sizeof(blob.text)) << "blob.text must be NUL-terminated within its own capacity";

	auto parsed = pbxpersist::deserializeBlob(std::string(blob.text, len));
	EXPECT_EQ(parsed.size(), static_cast<size_t>(POCKETDIAL_CDR_RECORDS))
		<< "every record must still parse even when every field is at its truncation cap";
	for (const auto& rec : parsed)
	{
		ASSERT_EQ(rec.size(), 5u) << "a partially-written last field must not merge with the next record";
	}
}

TEST(CdrRingSerialize, ReusingTheSameOutBufferForAShorterBlobLeavesNoStaleBytes)
{
	// serializeForPersist() takes `out` by reference specifically so a
	// caller (persist(), cdrPersistWriterTask) can reuse ONE static buffer
	// across calls instead of a fresh stack-local each time (see
	// CdrRing.cpp's doc comments for why). That reuse is only safe if this
	// function fully resets `out` every call -- a shorter second blob must
	// not leave any trailing byte from a longer first one sitting after its
	// own NUL terminator, which would make blob.text a longer, corrupted
	// C-string than intended the moment nvs_set_str (or this test's
	// std::string(blob.text)) reads past the real end.
	CdrRingBlob blob;
	std::array<CallDetailRecord, POCKETDIAL_CDR_RECORDS> ring{};

	ring[0] = makeRecord("first-long-caller", "first-long-callee", 111, 222, CdrResult::Answered);
	CdrRing::serializeForPersist(ring, /*head=*/1, /*count=*/1, blob);
	ASSERT_STREQ(blob.text, "first-long-caller\tfirst-long-callee\t111\t222\t0\n");

	ring[0] = makeRecord("s", "t", 1, 2, CdrResult::Busy);
	CdrRing::serializeForPersist(ring, /*head=*/1, /*count=*/1, blob);
	EXPECT_STREQ(blob.text, "s\tt\t1\t2\t1\n")
		<< "must not still contain any trailing byte from the previous, longer call";
}

TEST(CdrRingBlobType, CapacityMatchesTheDocumentedArithmetic)
{
	// 140 bytes/line * 32 records + 1 NUL, restated here independent of
	// CdrRing.cpp's own static_assert so a future edit to one without the
	// other fails a test, not just silently compiles differently than
	// documented.
	EXPECT_EQ(CdrRingBlob::kCapacity, static_cast<size_t>(POCKETDIAL_CDR_RECORDS) * 140 + 1);
}

// Issue #458: clearAll() resets the slots in place (no ring-sized temporary on
// the http_conn stack). Whatever the mechanism, the contract is that EVERY
// slot -- not just the live window -- is emptied, and that a cleared record
// never resurfaces once new ones are written.
TEST(CdrRingClearAll, EmptiesEverySlotAndNothingResurfaces)
{
	CdrRing ring;
	// Wrap the ring more than once, so every slot holds a record and _head is
	// somewhere in the middle.
	const size_t n = POCKETDIAL_CDR_RECORDS + POCKETDIAL_CDR_RECORDS / 2 + 3;
	for (size_t i = 0; i < n; ++i)
		ring.record(nullptr, "old-caller-" + std::to_string(i), "old-callee-" + std::to_string(i));
	for (const CallDetailRecord& r : ring.slotsForTest())
		ASSERT_FALSE(r.caller.empty()) << "precondition: every slot is written";
	ASSERT_EQ(ring.snapshot().size(), static_cast<size_t>(POCKETDIAL_CDR_RECORDS));

	ring.clearAll();

	size_t slot = 0;
	for (const CallDetailRecord& r : ring.slotsForTest())
	{
		SCOPED_TRACE(::testing::Message() << "slot " << slot++);
		EXPECT_TRUE(r.caller.empty());
		EXPECT_TRUE(r.callee.empty());
		EXPECT_EQ(r.startMs, 0u);
		EXPECT_EQ(r.durationSec, 0u);
		EXPECT_EQ(r.result, CallDetailRecord{}.result);
	}
	EXPECT_TRUE(ring.snapshot().empty());
	EXPECT_EQ(ring.lastCallerFor("old-callee-" + std::to_string(n - 1)), "");

	// New records start from a clean ring: exactly what was written, nothing old.
	ring.record(nullptr, "new-caller", "new-callee");
	const std::vector<CallDetailRecord> snap = ring.snapshot();
	ASSERT_EQ(snap.size(), 1u);
	EXPECT_EQ(snap[0].caller, "new-caller");
	EXPECT_EQ(ring.lastCallerFor("new-callee"), "new-caller");
	for (size_t i = 0; i < n; ++i)
		EXPECT_EQ(ring.lastCallerFor("old-callee-" + std::to_string(i)), "") << i;
}
