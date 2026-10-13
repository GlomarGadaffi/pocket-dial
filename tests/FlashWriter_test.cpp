// FlashWriter_test.cpp -- #991: one flash-writer task for the CDR ring and the
// NVS writer.
//
// On the board the flash_writer task runs
// flashwriter::passOnce<&CdrRing::writePending, &nvswriter::writePending>() and
// then waits for a notification. These tests drive the same passOnce template
// with the real NVS writer policy (a Stager over the host's depth-1 mailboxes)
// and, for the CDR ring, whose writer half is board only, a stand-in with the
// same shape: a depth-1 overwrite queue, taken, then written under a
// resetguard::WriteScope (CdrRing::writePending's order). Deterministic: a
// "flood" is a source re-queueing itself from inside its own write, never a
// thread or a sleep. The board wiring (one task, the wakes, start() order) is
// pinned by tests/tools/test_one_flash_writer.py.

#include <gtest/gtest.h>

#include <array>
#include <functional>
#include <string>
#include <vector>

#include "FlashWriter.hpp"
#include "NvsWriterLogic.hpp"
#include "ResetGuard.hpp"

using nvswriter::BlobWriter;
using nvswriter::Key;
using nvswriter::StageResult;

namespace
{
	struct World
	{
		// The CDR ring stand-in: one depth-1 queue.
		bool cdrFull = false;
		std::string cdrWaiting;
		void persistCdr(const std::string& snapshot) { cdrWaiting = snapshot; cdrFull = true; }

		// The real NVS writer policy, small slots.
		nvswriter::Slot<64> devices;
		nvswriter::Slot<64> forwards;
		nvswriter::Slot<64> didmap;
		nvswriter::Slot<64> scratch;
		std::array<nvswriter::SlotRef, nvswriter::kKeyCount> refs{{nvswriter::refOf(devices), nvswriter::refOf(forwards), nvswriter::refOf(didmap)}};
		nvswriter::DepthOneMailboxes mail{refs};
		nvswriter::Stager<nvswriter::DepthOneMailboxes> st{mail, refs, &scratch};
		StageResult stage(Key k, const std::string& s)
		{
			return st.stage(k, [&](BlobWriter& w) { w.str(s); });
		}

		std::vector<std::string> written;             // "<source>:<bytes>", in write order
		std::function<void(const std::string&)> during;   // runs inside each write, given the source
	};
	World* g = nullptr;

	const char* nameOf(Key k)
	{
		switch (k)
		{
		case Key::Devices:  return "dev";
		case Key::Forwards: return "fwd";
		case Key::DidMap:   return "did";
		}
		return "?";
	}

	unsigned cdrSource()
	{
		if (!g->cdrFull) return 0;
		const std::string blob = g->cdrWaiting;   // take
		g->cdrFull = false;
		resetguard::WriteScope scope;              // then register, as CdrRing::writePending does
		if (!scope.allowed()) return 0;
		g->written.push_back("cdr:" + blob);
		if (g->during) g->during("cdr");
		return 1;
	}

	unsigned nvsSource()
	{
		return g->st.drainOnce([](Key k, const char* p, size_t n) {
			g->written.push_back(std::string(nameOf(k)) + ":" + std::string(p, n));
			if (g->during) g->during(nameOf(k));
			return true;
		});
	}

	unsigned pass() { return flashwriter::passOnce<&cdrSource, &nvsSource>(); }

	class FlashWriter : public ::testing::Test
	{
	protected:
		void SetUp() override
		{
			resetguard::resetForTest();
			g = &w;
		}
		void TearDown() override
		{
			g = nullptr;
			resetguard::resetForTest();
		}
		World w;
	};

	using Seen = std::vector<std::string>;
}

TEST_F(FlashWriter, OnePassWritesTheCdrRingAndEveryNvsKeyThatHasABlob)
{
	w.persistCdr("ring1");
	ASSERT_EQ(w.stage(Key::Devices, "d"), StageResult::Ok);
	ASSERT_EQ(w.stage(Key::Forwards, "f"), StageResult::Ok);
	ASSERT_EQ(w.stage(Key::DidMap, "m"), StageResult::Ok);

	EXPECT_EQ(pass(), 4u);
	EXPECT_EQ(w.written, (Seen{"cdr:ring1", "dev:d", "fwd:f", "did:m"})) << "one task, every source, fixed order";

	EXPECT_EQ(pass(), 0u) << "nothing is written twice";
	EXPECT_EQ(w.written.size(), 4u);
}

TEST_F(FlashWriter, ACdrRingThatNeverStopsDoesNotStarveAForward)
{
	// Every CDR write re-queues a newer snapshot (calls ending back to back), and
	// a *72 is staged once.
	int n = 0;
	w.during = [&](const std::string& src) {
		if (src == "cdr") w.persistCdr("ring" + std::to_string(++n));
	};
	w.persistCdr("ring0");
	ASSERT_EQ(w.stage(Key::Forwards, "303\t5500\t\t\n"), StageResult::Ok);

	EXPECT_EQ(pass(), 2u);
	EXPECT_EQ(w.written, (Seen{"cdr:ring0", "fwd:303\t5500\t\t\n"}))
		<< "the forward is written in the same pass, behind one CDR unit only";

	// The flood goes on: one CDR unit a pass, and each pass ends.
	EXPECT_EQ(pass(), 1u);
	EXPECT_EQ(pass(), 1u);
	EXPECT_EQ(w.written, (Seen{"cdr:ring0", "fwd:303\t5500\t\t\n", "cdr:ring1", "cdr:ring2"}));
	EXPECT_TRUE(w.cdrFull) << "ring3 waits for the next pass";
}

TEST_F(FlashWriter, ADeviceTableThatNeverStopsDoesNotStarveTheCdrRingOrTheOtherKeys)
{
	int n = 0;
	w.during = [&](const std::string& src) {
		if (src == "dev")
		{
			EXPECT_EQ(w.stage(Key::Devices, "d" + std::to_string(++n)), StageResult::Ok);
		}
	};
	ASSERT_EQ(w.stage(Key::Devices, "d0"), StageResult::Ok);
	ASSERT_EQ(w.stage(Key::DidMap, "m"), StageResult::Ok);

	EXPECT_EQ(pass(), 2u);
	EXPECT_EQ(w.written, (Seen{"dev:d0", "did:m"}));

	// A call ends while the adoptions keep coming: the ring's snapshot is first
	// in the very next pass.
	w.persistCdr("ring");
	EXPECT_EQ(pass(), 2u);
	EXPECT_EQ(w.written, (Seen{"dev:d0", "did:m", "cdr:ring", "dev:d1"}));
}

TEST_F(FlashWriter, EachSourceKeepsItsOwnDepthOneQueueNewestWinsAndNoneReplacesAnother)
{
	w.persistCdr("old ring");
	w.persistCdr("new ring");
	ASSERT_EQ(w.stage(Key::Forwards, "f1"), StageResult::Ok);
	ASSERT_EQ(w.stage(Key::Devices, "dev table"), StageResult::Ok);
	ASSERT_EQ(w.stage(Key::Forwards, "f2"), StageResult::Ok);
	EXPECT_EQ(w.st.stats().overwrites, 1u) << "only f2 replaced anything: f1, in its own key's queue";

	EXPECT_EQ(pass(), 3u);
	EXPECT_EQ(w.written, (Seen{"cdr:new ring", "dev:dev table", "fwd:f2"}))
		<< "the newest of each queue, and the CDR blob, the device table and the forward all survive each other";
}

TEST_F(FlashWriter, ASourceWithNothingWaitingOrNotStartedDoesNotStopThePass)
{
	// CdrRing::writePending() and nvswriter::writePending() return 0 before their
	// start() published them; a pass must go on to the next source.
	ASSERT_EQ(w.stage(Key::Forwards, "f"), StageResult::Ok);
	EXPECT_EQ(pass(), 1u);
	EXPECT_EQ(w.written, (Seen{"fwd:f"}));

	w.persistCdr("ring");
	EXPECT_EQ(pass(), 1u);
	EXPECT_EQ(w.written, (Seen{"fwd:f", "cdr:ring"}));
}

TEST_F(FlashWriter, TheResetDrainSeesAUnitInFlightFromEitherSourceAndNothingBetweenUnits)
{
	w.persistCdr("ring");
	ASSERT_EQ(w.stage(Key::Devices, "d"), StageResult::Ok);
	std::vector<bool> busyInside;
	w.during = [&](const std::string&) { busyInside.push_back(!resetguard::waitForWritersIdle(0)); };

	EXPECT_TRUE(resetguard::waitForWritersIdle(0)) << "queued data is not a write in flight";
	EXPECT_EQ(pass(), 2u);
	EXPECT_EQ(busyInside, (std::vector<bool>{true, true})) << "the CDR unit and the NVS unit each hold a WriteScope";
	EXPECT_TRUE(resetguard::waitForWritersIdle(0)) << "the pass itself holds none: a reset is never kept waiting between units";
}

TEST_F(FlashWriter, AResetThatBeginsDuringTheCdrUnitRefusesTheNvsUnitBehindItInTheSamePass)
{
	w.persistCdr("ring");
	ASSERT_EQ(w.stage(Key::Devices, "d"), StageResult::Ok);
	bool sawCdrInFlight = false;
	w.during = [&](const std::string& src) {
		if (src != "cdr") return;
		resetguard::begin();   // the HTTP/DTMF reset door: flag first, then drain
		sawCdrInFlight = !resetguard::waitForWritersIdle(0);
	};

	EXPECT_EQ(pass(), 1u);
	EXPECT_TRUE(sawCdrInFlight) << "the reset's drain must see the CDR write it began during";
	EXPECT_EQ(w.written, (Seen{"cdr:ring"})) << "the device table behind it is not written once the reset began";
	EXPECT_EQ(w.st.stats().suppressed, 1u);
	EXPECT_FALSE(w.mail.waiting(Key::Devices)) << "...and is not kept for later";
	EXPECT_TRUE(resetguard::waitForWritersIdle(0));
}
