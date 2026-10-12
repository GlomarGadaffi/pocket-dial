// DidMapStaging_test.cpp -- #986 slice 4: the DID table's NVS write leaves
// RequestsHandler::_mutex.
//
// DidMapping::setMapping/removeMapping (and the import's clearAllStaged) used to
// run 2 * kMaxMappings nvs_set_str plus an nvs_commit with the engine lock held
// (52.9 ms measured during /api/config/import). They now copy a snapshot of the
// table into the NVS writer's Key::DidMap staging slot and return; the writer
// task applies it with DidMapping::writeSnapshot(). The writer does not exist on
// the host, so these tests play it: nvswriter::drainForTest() takes what was
// staged and DidMapping::emitSnapshot() -- the walk writeSnapshot() makes, with
// the put callback in place of nvs_set_str -- records the (key, value) pairs.
//
// The oracle for "what the old persist() wrote" is the expected pair list,
// spelled out here (m0did, m0ext, m1did ... for every slot, "" for an unused
// one), never computed with production code. The board-only half (the nvs_*
// calls, the third slot and queue, who calls what under which lock) is pinned by
// tests/tools/test_didmap_staging_wiring.py.

#include <gtest/gtest.h>

#include <cstdio>
#include <fstream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "DidMapping.hpp"
#include "NvsWriter.hpp"
#include "RequestsHandler.hpp"
#include "ResetGuard.hpp"
#include "SipMessage.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

using nvswriter::BlobWriter;
using nvswriter::Key;

static_assert(DidMapping::kMaxMappings == 8, "the literal expectations below spell out eight slots");
static_assert(DidMapping::kMaxFieldLen == 32, "the full-table test uses 32-character fields");

namespace
{
	using Pairs = std::vector<std::pair<std::string, std::string>>;
	using Rows = std::vector<std::pair<std::string, std::string>>;   // did, extension

	// What the old whole-table write stored: every slot, did then extension, "" when unused.
	Pairs expectedPairs(const Rows& rows)
	{
		Pairs out;
		for (size_t i = 0; i < DidMapping::kMaxMappings; ++i)
		{
			const bool live = i < rows.size();
			out.emplace_back("m" + std::to_string(i) + "did", live ? rows[i].first : std::string());
			out.emplace_back("m" + std::to_string(i) + "ext", live ? rows[i].second : std::string());
		}
		return out;
	}

	struct Drained
	{
		unsigned didmapWrites = 0;   // times the writer was handed a DID snapshot
		unsigned otherWrites = 0;    // writes for any other key
		bool wellFormed = true;      // the snapshot passed emitSnapshot()'s checks
		Pairs pairs;                 // the last snapshot's (key, value) walk
	};

	// One writer pass.
	Drained drain()
	{
		Drained d;
		nvswriter::drainForTest([&](Key k, const char* p, size_t n) {
			if (k != Key::DidMap)
			{
				++d.otherWrites;
				return true;
			}
			++d.didmapWrites;
			d.pairs.clear();
			d.wellFormed = DidMapping::emitSnapshot(p, n, [&](const char* key, const char* val) {
				d.pairs.emplace_back(key, val);
				return true;
			});
			return d.wellFormed;
		});
		return d;
	}

	std::string stagedDid() { return std::string(nvswriter::stagedForTest(Key::DidMap)); }

	std::string slurp(const std::string& path)
	{
		std::ifstream f(path, std::ios::binary);
		return std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
	}

	// The host store's key=value form, built from a walk -- the loader's input.
	std::string asStoreFile(const Pairs& pairs)
	{
		std::string out;
		for (const auto& [k, v] : pairs) out += k + "=" + v + "\n";
		return out;
	}

	class DidMapStaging : public ::testing::Test
	{
	protected:
		void SetUp() override
		{
			resetguard::resetForTest();
			nvswriter::resetForTest();
			const std::string name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
			_path = "test_didstage_" + name + ".cfg";
			_path2 = "test_didstage2_" + name + ".cfg";
			std::remove(_path.c_str());
			std::remove(_path2.c_str());
			_map.setStorePath(_path);
			_map.load();
			nvswriter::resetForTest();
		}
		void TearDown() override
		{
			std::remove(_path.c_str());
			std::remove(_path2.c_str());
			nvswriter::resetForTest();
			resetguard::resetForTest();
		}

		DidMapping _map;
		std::string _path;
		std::string _path2;
	};
}

TEST_F(DidMapStaging, SetMappingStagesTheWholeTableAsTheOldPerSlotKeys)
{
	ASSERT_EQ(_map.setMapping("+15551234567", "1001"), "");
	ASSERT_EQ(_map.setMapping("+15559876543", "1002"), "");
	EXPECT_EQ(nvswriter::stats().staged, 2u);
	EXPECT_EQ(nvswriter::stats().overwrites, 1u) << "the second set replaced a snapshot nobody had taken";
	EXPECT_EQ(stagedDid().size(), DidMapping::kSnapshotLen);

	const Drained d = drain();
	EXPECT_EQ(d.didmapWrites, 1u) << "two sets, one write: the newest snapshot";
	EXPECT_EQ(d.otherWrites, 0u);
	ASSERT_TRUE(d.wellFormed);

	// Spelled out: this is what DidMapping::persist() handed nvs_set_str, in this order.
	const Pairs want = {
		{"m0did", "+15551234567"}, {"m0ext", "1001"},
		{"m1did", "+15559876543"}, {"m1ext", "1002"},
		{"m2did", ""}, {"m2ext", ""}, {"m3did", ""}, {"m3ext", ""},
		{"m4did", ""}, {"m4ext", ""}, {"m5did", ""}, {"m5ext", ""},
		{"m6did", ""}, {"m6ext", ""}, {"m7did", ""}, {"m7ext", ""},
	};
	EXPECT_EQ(d.pairs, want);
	EXPECT_EQ(d.pairs, expectedPairs({{"+15551234567", "1001"}, {"+15559876543", "1002"}}));
}

TEST_F(DidMapStaging, AnUpdateInPlaceAndARemoveRestageTheCompactedTable)
{
	ASSERT_EQ(_map.setMapping("did-a", "100"), "");
	ASSERT_EQ(_map.setMapping("did-b", "101"), "");
	ASSERT_EQ(_map.setMapping("did-c", "102"), "");
	ASSERT_EQ(_map.setMapping("(202) 555-0123", "103"), "");
	// Same line re-typed: updates in place and adopts the new rendering (#243).
	ASSERT_EQ(_map.setMapping("+12025550123", "104"), "");
	ASSERT_EQ(drain().pairs, expectedPairs({{"did-a", "100"}, {"did-b", "101"}, {"did-c", "102"}, {"+12025550123", "104"}}));

	ASSERT_EQ(_map.removeMapping("did-b"), "");
	const Drained d = drain();
	ASSERT_EQ(d.didmapWrites, 1u);
	EXPECT_EQ(d.pairs, expectedPairs({{"did-a", "100"}, {"did-c", "102"}, {"+12025550123", "104"}}))
		<< "the survivors move up and the tail slot is written empty";
}

TEST_F(DidMapStaging, ARemoveThatChangesNothingStagesNothing)
{
	ASSERT_EQ(_map.setMapping("did-a", "100"), "");
	nvswriter::resetForTest();
	EXPECT_EQ(_map.removeMapping("not-there"), "");
	EXPECT_EQ(nvswriter::stats().staged, 0u);
	EXPECT_TRUE(stagedDid().empty());
}

TEST_F(DidMapStaging, AFullTableOfMaximumLengthFieldsStagesWholeAndNothingIsRefused)
{
	Rows rows;
	for (size_t i = 0; i < DidMapping::kMaxMappings; ++i)
	{
		const char tag = static_cast<char>('0' + i);
		rows.emplace_back(std::string(DidMapping::kMaxFieldLen - 1, 'd') + tag,
		                  std::string(DidMapping::kMaxFieldLen - 1, 'e') + tag);
		ASSERT_EQ(rows.back().first.size(), DidMapping::kMaxFieldLen);
		ASSERT_EQ(_map.setMapping(rows.back().first, rows.back().second), "") << "row " << i;
	}
	EXPECT_EQ(nvswriter::stats().tooBig, 0u) << "every table setMapping() accepts must fit its slot";
	EXPECT_EQ(stagedDid().size(), DidMapping::kSnapshotLen);
	const Drained d = drain();
	ASSERT_EQ(d.didmapWrites, 1u);
	EXPECT_EQ(d.pairs, expectedPairs(rows)) << "no field is cut short";
}

TEST_F(DidMapStaging, AFieldLongerThanItsCellIsRefusedNotTruncated)
{
	// Only a hand-edited store can hold one: setMapping() refuses it, and the
	// board's load() reads at most kMaxFieldLen characters.
	{
		std::ofstream f(_path, std::ios::binary);
		f << "m0did=" << std::string(DidMapping::kMaxFieldLen + 8, 'x') << "\nm0ext=1001\n";
	}
	_map.load();
	ASSERT_EQ(_map.size(), 1u);
	nvswriter::resetForTest();

	const std::string err = _map.setMapping("5550100", "1002");
	EXPECT_NE(err, "") << "a table that could not be staged is an error, not a 200";
	EXPECT_EQ(nvswriter::stats().tooBig, 1u);
	EXPECT_EQ(nvswriter::stats().staged, 0u);
	EXPECT_TRUE(stagedDid().empty()) << "refused whole: nothing half-written reaches the writer";
	EXPECT_EQ(drain().didmapWrites, 0u);
	EXPECT_EQ(_map.size(), 2u) << "the in-memory table changed, as it always did when a write failed";
}

TEST_F(DidMapStaging, AnEmbeddedNulCutsAFieldWhereTheOldCStringWriteDid)
{
	// fieldValid() lets a NUL through; nvs_set_str(value.c_str()) stored "ab".
	const std::string withNul("ab\0cd", 5);
	ASSERT_EQ(_map.setMapping(withNul, "1001"), "");
	EXPECT_EQ(drain().pairs, expectedPairs({{"ab", "1001"}}));
}

TEST_F(DidMapStaging, TheWalkStopsAtTheFirstFailedPut)
{
	ASSERT_EQ(_map.setMapping("did-a", "100"), "");
	const std::string blob = stagedDid();
	ASSERT_EQ(blob.size(), DidMapping::kSnapshotLen);

	unsigned puts = 0;
	EXPECT_FALSE(DidMapping::emitSnapshot(blob.data(), blob.size(), [&](const char*, const char*) {
		return ++puts < 5;
	}));
	EXPECT_EQ(puts, 5u) << "the old `ok && nvs_set_str(...)` chain made no call after a failure";

	puts = 0;
	EXPECT_TRUE(DidMapping::emitSnapshot(blob.data(), blob.size(), [&](const char*, const char*) {
		++puts;
		return true;
	}));
	EXPECT_EQ(puts, 2 * DidMapping::kMaxMappings);
}

TEST_F(DidMapStaging, AMalformedSnapshotIsRefusedBeforeTheFirstPut)
{
	ASSERT_EQ(_map.setMapping("did-a", "100"), "");
	const std::string good = stagedDid();
	unsigned puts = 0;
	auto count = [&](const char*, const char*) { ++puts; return true; };

	EXPECT_FALSE(DidMapping::emitSnapshot(good.data(), 0, count));
	EXPECT_FALSE(DidMapping::emitSnapshot(good.data(), good.size() - 1, count)) << "one byte short";
	const std::string longer = good + std::string(1, '\0');
	EXPECT_FALSE(DidMapping::emitSnapshot(longer.data(), longer.size(), count)) << "one byte over";

	std::string noNul = good;   // a cell that is not NUL-terminated would be read past its end
	noNul[3 * DidMapping::kSlotCellLen + DidMapping::kMaxFieldLen] = 'x';
	EXPECT_FALSE(DidMapping::emitSnapshot(noNul.data(), noNul.size(), count));

	EXPECT_EQ(puts, 0u) << "a refused snapshot must not have written a single slot";
	EXPECT_TRUE(DidMapping::emitSnapshot(good.data(), good.size(), count));
}

TEST_F(DidMapStaging, WhatTheWriterEmitsIsWhatLoadReadsBack)
{
	ASSERT_EQ(_map.setMapping("+15551234567", "1001"), "");
	ASSERT_EQ(_map.setMapping("(555) 987-6543", "1002"), "");
	ASSERT_EQ(_map.setMapping("did-x", "1003"), "");
	ASSERT_EQ(_map.removeMapping("+15551234567"), "");
	const Drained d = drain();
	ASSERT_EQ(d.didmapWrites, 1u);

	// The writer's output, as the host store, in a file persist() never touched.
	{
		std::ofstream f(_path2, std::ios::binary);
		f << asStoreFile(d.pairs);
	}
	DidMapping reloaded;
	reloaded.setStorePath(_path2);
	reloaded.load();

	const auto want = _map.list();
	const auto got = reloaded.list();
	ASSERT_EQ(got.size(), want.size());
	ASSERT_EQ(got.size(), 2u);
	for (size_t i = 0; i < got.size(); ++i)
	{
		EXPECT_EQ(got[i].did, want[i].did) << i;
		EXPECT_EQ(got[i].extension, want[i].extension) << i;
	}
	EXPECT_EQ(reloaded.extensionForDid("did-x"), "1003");
	EXPECT_EQ(reloaded.extensionForDid("+15551234567"), "");
}

TEST_F(DidMapStaging, TheInMemoryTableIsRightBeforeTheWriterHasRun)
{
	ASSERT_EQ(_map.setMapping("did-a", "100"), "");
	ASSERT_EQ(_map.setMapping("did-a", "200"), "");
	ASSERT_EQ(_map.setMapping("did-b", "300"), "");
	EXPECT_EQ(nvswriter::stats().written, 0u) << "nothing has reached the writer";
	EXPECT_EQ(_map.extensionForDid("did-a"), "200") << "the SIP path and the export read this, not flash";
	EXPECT_EQ(_map.extensionForDid("did-b"), "300");
	EXPECT_TRUE(_map.isTarget("200"));
	ASSERT_EQ(_map.list().size(), 2u);
	EXPECT_EQ(drain().pairs, expectedPairs({{"did-a", "200"}, {"did-b", "300"}}));
}

TEST_F(DidMapStaging, ClearAllStagedStagesTheEmptyTable)
{
	ASSERT_EQ(_map.setMapping("did-a", "100"), "");
	ASSERT_EQ(_map.setMapping("did-b", "101"), "");
	nvswriter::resetForTest();

	EXPECT_EQ(_map.clearAllStaged(), "");
	EXPECT_EQ(_map.size(), 0u);
	EXPECT_EQ(nvswriter::stats().staged, 1u);
	const Drained d = drain();
	ASSERT_EQ(d.didmapWrites, 1u);
	EXPECT_EQ(d.pairs, expectedPairs({})) << "an empty table is written as sixteen empty values, as before";
}

#if !defined(_WIN32)
TEST_F(DidMapStaging, ClearAllStaysSynchronousAndStagesNothingEvenAfterTheResetBegan)
{
	ASSERT_EQ(_map.setMapping("did-a", "100"), "");
	ASSERT_FALSE(slurp(_path).empty());
	nvswriter::resetForTest();

	// /api/factory-reset: resetguard::begin() first, then the erase, then it reports.
	resetguard::begin();
	EXPECT_EQ(_map.clearAll(), "") << "the reset's erase must not be refused like a staged write";
	EXPECT_EQ(nvswriter::stats().staged, 0u);
	EXPECT_EQ(nvswriter::stats().suppressed, 0u) << "it never goes through the writer";

	std::string empty;
	for (size_t i = 0; i < DidMapping::kMaxMappings; ++i)
		empty += "m" + std::to_string(i) + "did=\nm" + std::to_string(i) + "ext=\n";
	EXPECT_EQ(slurp(_path), empty) << "the store was erased before clearAll() returned";
}

TEST_F(DidMapStaging, StagingIsRefusedWithAnErrorDuringAFactoryResetAndTheTableStaysRight)
{
	resetguard::begin();
	EXPECT_NE(_map.setMapping("did-a", "100"), "");
	EXPECT_EQ(nvswriter::stats().suppressed, 1u);
	EXPECT_EQ(nvswriter::stats().staged, 0u);
	EXPECT_TRUE(stagedDid().empty()) << "nothing may reach the queue behind a reset";
	EXPECT_TRUE(slurp(_path).empty()) << "...and the host store is not written either";
	EXPECT_EQ(_map.extensionForDid("did-a"), "100") << "only the flash copy is refused";

	EXPECT_NE(_map.removeMapping("did-a"), "");
	EXPECT_EQ(nvswriter::stats().suppressed, 2u);
}
#endif

TEST_F(DidMapStaging, ASnapshotStagedBeforeAResetIsDiscardedUnwrittenWhenTheWriterGetsToIt)
{
	ASSERT_EQ(_map.setMapping("did-a", "100"), "");
	resetguard::begin();   // the reset opens between the stage and the writer's pass

	const Drained d = drain();
	EXPECT_EQ(d.didmapWrites, 0u) << "the writer refuses data during a reset like any NVS writer";
	EXPECT_EQ(nvswriter::stats().suppressed, 1u);
	EXPECT_EQ(nvswriter::stats().written, 0u);
	EXPECT_TRUE(stagedDid().empty()) << "...and does not keep it for later";
}

TEST_F(DidMapStaging, TheDidTableAndTheDeviceAndForwardBlobsDoNotDropEachOther)
{
	ASSERT_EQ(nvswriter::stage(Key::Devices, [](BlobWriter& w) { w.str("dev-table"); }), nvswriter::StageResult::Ok);
	ASSERT_EQ(nvswriter::stage(Key::Forwards, [](BlobWriter& w) { w.str("fwd-table"); }), nvswriter::StageResult::Ok);
	ASSERT_EQ(_map.setMapping("did-a", "100"), "");
	EXPECT_EQ(nvswriter::stats().overwrites, 0u) << "different keys never replace each other";

	std::vector<std::pair<Key, std::string>> seen;
	EXPECT_EQ(nvswriter::drainForTest([&](Key k, const char* p, size_t n) {
		seen.emplace_back(k, std::string(p, n));
		return true;
	}), 3u);
	ASSERT_EQ(seen.size(), 3u);
	EXPECT_EQ(seen[0].first, Key::Devices);
	EXPECT_EQ(seen[0].second, "dev-table");
	EXPECT_EQ(seen[1].first, Key::Forwards);
	EXPECT_EQ(seen[1].second, "fwd-table");
	EXPECT_EQ(seen[2].first, Key::DidMap);
	EXPECT_EQ(seen[2].second.size(), DidMapping::kSnapshotLen);

	// And the other way round: a later device blob does not displace the DID table.
	ASSERT_EQ(_map.setMapping("did-b", "101"), "");
	ASSERT_EQ(nvswriter::stage(Key::Devices, [](BlobWriter& w) { w.str("dev-2"); }), nvswriter::StageResult::Ok);
	EXPECT_EQ(nvswriter::stats().overwrites, 0u);
	const Drained d = drain();
	EXPECT_EQ(d.didmapWrites, 1u);
	EXPECT_EQ(d.otherWrites, 1u);
	EXPECT_EQ(d.pairs, expectedPairs({{"did-a", "100"}, {"did-b", "101"}}));
}

// ---------------------------------------------------------------------------
// Through RequestsHandler, the way the HTTP setters and the import reach it.

namespace
{
	class DidMapImport : public ::testing::Test
	{
	protected:
		void SetUp() override
		{
			resetguard::resetForTest();
			nvswriter::resetForTest();
			const std::string name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
			_tapi = "test_didimport_tapi_" + name + ".cfg";
			_did = "test_didimport_did_" + name + ".cfg";
			std::remove(_tapi.c_str());
			std::remove(_did.c_str());
			_h = std::make_unique<RequestsHandler>("192.168.60.1", 5060,
				[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
			_h->setTelephonyStorePathsForTest(_tapi, _did);
			nvswriter::resetForTest();   // construction may have staged
		}
		void TearDown() override
		{
			_h.reset();
			std::remove(_tapi.c_str());
			std::remove(_did.c_str());
			nvswriter::resetForTest();
			resetguard::resetForTest();
		}

		// What /api/config/import does to the DID table, minus the HTTP.
		void importTable(const Rows& rows)
		{
			_h->clearAllDidMappingsStaged();
			for (const auto& [did, ext] : rows) _h->setDidMapping(did, ext);
		}

		std::unique_ptr<RequestsHandler> _h;
		std::string _tapi;
		std::string _did;
	};
}

TEST_F(DidMapImport, AnImportOfNEntriesCollapsesToOneWriteOfTheFinalTable)
{
	const Rows rows = {{"+15550100001", "1001"}, {"+15550100002", "1002"}, {"+15550100003", "1003"},
	                   {"+15550100004", "1004"}, {"+15550100005", "1005"}};
	importTable(rows);

	EXPECT_EQ(nvswriter::stats().staged, rows.size() + 1) << "the clear and one stage per entry";
	EXPECT_EQ(nvswriter::stats().overwrites, rows.size()) << "...each replacing the one the writer had not taken";

	const Drained d = drain();
	EXPECT_EQ(d.didmapWrites, 1u) << "N+1 changes, one write of the final table";
	EXPECT_EQ(d.otherWrites, 0u);
	EXPECT_EQ(d.pairs, expectedPairs(rows));
	EXPECT_EQ(drain().didmapWrites, 0u) << "nothing is written twice";
}

TEST_F(DidMapImport, ASecondImportReplacesTheFirstSnapshotWithoutWritingIt)
{
	importTable({{"old-a", "1001"}, {"old-b", "1002"}, {"old-c", "1003"}});
	importTable({{"new-a", "2001"}});
	EXPECT_EQ(nvswriter::stats().staged, 6u);
	EXPECT_EQ(nvswriter::stats().overwrites, 5u);

	const Drained d = drain();
	EXPECT_EQ(d.didmapWrites, 1u);
	EXPECT_EQ(d.pairs, expectedPairs({{"new-a", "2001"}})) << "replace, not merge: the first import never reaches flash";
}

TEST_F(DidMapImport, TheHttpSettersStageAndTheFactoryResetClearStaysSynchronous)
{
	EXPECT_EQ(_h->setDidMapping("+15550100001", "1001"), "");
	EXPECT_EQ(_h->setDidMapping("+15550100002", "1002"), "");
	EXPECT_EQ(_h->removeDidMapping("+15550100001"), "");
	EXPECT_EQ(nvswriter::stats().staged, 3u);
	EXPECT_EQ(drain().pairs, expectedPairs({{"+15550100002", "1002"}}));

	nvswriter::resetForTest();
	resetguard::begin();
	EXPECT_EQ(_h->clearAllDidMappings(), "") << "/api/factory-reset erases after resetguard::begin() and reports the result";
	EXPECT_EQ(nvswriter::stats().staged, 0u);
	EXPECT_EQ(nvswriter::stats().suppressed, 0u);
	EXPECT_TRUE(_h->getDidMappings().empty());
}
