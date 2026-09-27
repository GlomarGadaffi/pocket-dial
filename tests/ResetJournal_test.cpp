// Issue #473 item 1: a factory reset that did not complete is reported on the
// next boot (src/Helpers/ResetJournal.hpp). The host arm keeps the record in
// process memory and models a reboot with simulateRebootForTest(), which drops
// the cached boot status and the RAM failure mask but KEEPS the record, as the
// flash sector would.

#include <gtest/gtest.h>

#include "ResetJournal.hpp"

#include <atomic>
#include <chrono>
#include <future>
#include <thread>

namespace
{
	struct Fresh
	{
		Fresh() { resetjournal::resetForTest(); }
		~Fresh() { resetjournal::resetForTest(); }
	};
}

TEST(ResetJournal, ABoardThatNeverResetReportsComplete)
{
	Fresh f;
	const auto s = resetjournal::bootStatus();
	EXPECT_FALSE(s.incomplete());
	EXPECT_EQ(s.stage, resetjournal::Stage::None);
	EXPECT_EQ(s.storage, resetjournal::Storage::Flash);
}

// The case RTC_NOINIT could not catch: power is cut (or the restart task hangs)
// after the reset began and before it finished.
TEST(ResetJournal, AResetThatBeganButNeverFinishedIsReportedInterrupted)
{
	Fresh f;
	resetjournal::begin();
	resetjournal::simulateRebootForTest();
	const auto s = resetjournal::bootStatus();
	EXPECT_TRUE(s.incomplete());
	EXPECT_EQ(s.stage, resetjournal::Stage::Begun);
	EXPECT_STREQ(resetjournal::stageName(s.stage), "interrupted");
}

TEST(ResetJournal, ACleanResetLeavesNoRecord)
{
	Fresh f;
	resetjournal::begin();
	resetjournal::finish();
	resetjournal::simulateRebootForTest();
	EXPECT_FALSE(resetjournal::bootStatus().incomplete());
}

// noteFailure() from the erase steps, plus finish()'s own extra bits (the
// whole-partition erase), all land in the persisted mask.
TEST(ResetJournal, AFailedResetIsReportedWithEveryFailedStore)
{
	Fresh f;
	resetjournal::begin();
	resetjournal::noteFailure(resetjournal::kTrunk);
	resetjournal::noteFailure(resetjournal::kSecrets);
	resetjournal::finish(resetjournal::kNvsErase);
	resetjournal::simulateRebootForTest();
	const auto s = resetjournal::bootStatus();
	EXPECT_TRUE(s.incomplete());
	EXPECT_EQ(s.stage, resetjournal::Stage::Failed);
	EXPECT_EQ(s.failedMask, resetjournal::kTrunk | resetjournal::kSecrets | resetjournal::kNvsErase);
}

// The report persists across plain reboots and is cleared only by the next
// reset that completes cleanly -- and that reset starts with an EMPTY mask, not
// the old one.
TEST(ResetJournal, OnlyTheNextCleanResetClearsAnEarlierFailure)
{
	Fresh f;
	resetjournal::begin();
	resetjournal::finish(resetjournal::kNvsErase);
	resetjournal::simulateRebootForTest();
	ASSERT_TRUE(resetjournal::bootStatus().incomplete());
	resetjournal::simulateRebootForTest();
	EXPECT_TRUE(resetjournal::bootStatus().incomplete()) << "a plain reboot must not clear it";

	resetjournal::begin();
	resetjournal::finish();
	resetjournal::simulateRebootForTest();
	EXPECT_FALSE(resetjournal::bootStatus().incomplete());
}

// Within one boot the status reports what the boot FOUND: a reset run now does
// not rewrite what /api/status says about the previous one.
TEST(ResetJournal, BootStatusIsFixedAtFirstLookForThisBoot)
{
	Fresh f;
	resetjournal::begin();
	resetjournal::simulateRebootForTest();
	ASSERT_TRUE(resetjournal::bootStatus().incomplete());
	resetjournal::begin();
	resetjournal::finish();
	EXPECT_TRUE(resetjournal::bootStatus().incomplete());
}

// A torn write of the journal itself reads as incomplete, never as clean.
TEST(ResetJournal, AnUnreadableRecordIsTreatedAsIncomplete)
{
	Fresh f;
	resetjournal::corruptRecordForTest();
	const auto s = resetjournal::bootStatus();
	EXPECT_TRUE(s.incomplete());
	EXPECT_EQ(s.stage, resetjournal::Stage::Unreadable);
}

// #481 review: a journal that cannot be written must not stop the reset. begin()
// says so and the failure is counted (/api/status "resetJournalWriteFailures");
// finish() still runs normally afterwards.
TEST(ResetJournal, AJournalWriteFailureIsCountedAndTheResetProceeds)
{
	Fresh f;
	resetjournal::failNextWriteForTest();
	EXPECT_FALSE(resetjournal::begin());
	EXPECT_EQ(resetjournal::writeFailureCount(), 1u);
	resetjournal::finish();
	resetjournal::simulateRebootForTest();
	EXPECT_FALSE(resetjournal::bootStatus().incomplete()) << "nothing was recorded, and the reset completed";

	EXPECT_TRUE(resetjournal::begin()) << "a later write succeeds again";
}

// #481 review (BLOCKING): two http_conn threads can make the very first
// GET /api/status at the same moment. The one that arrives while the other is
// still reading the record must NOT get the default "complete" status: it
// waits for the load. The hook runs inside the load, before the record is
// read, and asks for bootStatus() from a second thread.
namespace
{
	std::promise<resetjournal::BootStatus>* g_second = nullptr;
	void askFromAnotherThreadMidLoad()
	{
		resetjournal::setLoadHookForTest(nullptr);   // the second caller must not re-enter this
		auto* p = g_second;
		std::thread([p] { p->set_value(resetjournal::bootStatus()); }).detach();
		// Give the second thread time to return early if the cache lets it.
		std::this_thread::sleep_for(std::chrono::milliseconds(100));
	}
}

TEST(ResetJournal, AConcurrentFirstLookWaitsForTheLoadInsteadOfReportingComplete)
{
	Fresh f;
	resetjournal::begin();                    // a reset that never finished
	resetjournal::simulateRebootForTest();

	std::promise<resetjournal::BootStatus> second;
	auto fut = second.get_future();
	g_second = &second;
	resetjournal::setLoadHookForTest(&askFromAnotherThreadMidLoad);

	const auto first = resetjournal::bootStatus();
	ASSERT_EQ(fut.wait_for(std::chrono::seconds(5)), std::future_status::ready);
	const auto other = fut.get();
	resetjournal::setLoadHookForTest(nullptr);
	g_second = nullptr;

	EXPECT_TRUE(first.incomplete());
	EXPECT_TRUE(other.incomplete())
		<< "a status request racing the first load reported the interrupted reset as complete";
	EXPECT_EQ(other.stage, resetjournal::Stage::Begun);
}
