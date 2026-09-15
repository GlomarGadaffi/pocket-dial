// DidMapping_test.cpp — the bounded DID -> extension inbound routing table
// (DidMapping.hpp). This is a NEW data model: neither pocket-dial nor
// drawbridge had per-DID targeting before this (drawbridge RING-ALLs every
// registered extension off its one route point). RequestsHandler::
// routeInboundAnchorCall() DOES call extensionForDid() now -- see the
// BOUNDARY comment at the top of DidMapping.hpp -- but only the single
// configured route DN can ever match (there is no per-call dialed-DID field
// to key on), so a mapping row for any other DID is stored but inert. These
// tests exercise the class directly rather than through call routing.
//
// Covers: CRUD (add/update-in-place/remove/list), lookup (including the
// empty-did and no-mapping "" cases), field validation, the
// POCKETDIAL_MAX_DID_MAPPINGS bound (a 9th distinct DID fails cleanly, an
// update to an existing one still succeeds on a full table), and the on-disk
// round trip on POSIX hosts (mirrors TelephonyApiConfig's persistence model,
// including the honest _WIN32 in-memory-only fallback).

#include <gtest/gtest.h>

#include "DidMapping.hpp"
#include "PoolConfig.hpp"

#include <cstdio>
#include <string>

namespace
{
	class DidMappingTest : public ::testing::Test
	{
	protected:
		void SetUp() override
		{
			_path = std::string("test_didmap_") +
			        ::testing::UnitTest::GetInstance()->current_test_info()->name() + ".cfg";
			std::remove(_path.c_str());
			_map.setStorePath(_path);
			_map.load();  // no file yet: empty table stands
		}
		void TearDown() override
		{
			std::remove(_path.c_str());
		}

		DidMapping _map;
		std::string _path;
	};
}

TEST_F(DidMappingTest, StartsEmpty)
{
	EXPECT_EQ(_map.size(), 0u);
	EXPECT_TRUE(_map.list().empty());
	EXPECT_EQ(_map.extensionForDid("+15551234567"), "");
	EXPECT_EQ(_map.extensionForDid(""), "");
}

TEST_F(DidMappingTest, AddAndLookup)
{
	EXPECT_EQ(_map.setMapping("+15551234567", "1001"), "");
	EXPECT_EQ(_map.size(), 1u);
	EXPECT_EQ(_map.extensionForDid("+15551234567"), "1001");
	EXPECT_EQ(_map.extensionForDid("+10000000000"), "");  // unmapped DID
}

TEST_F(DidMappingTest, UpdateInPlaceDoesNotConsumeAnotherSlot)
{
	ASSERT_EQ(_map.setMapping("+15551234567", "1001"), "");
	ASSERT_EQ(_map.setMapping("+15551234567", "1002"), "");
	EXPECT_EQ(_map.size(), 1u);
	EXPECT_EQ(_map.extensionForDid("+15551234567"), "1002");
}

// Issue #243: a re-set with a DIFFERENT RENDERING of an already-stored DID
// must adopt that new rendering, not just the extension -- otherwise list()/
// the dashboard keep showing whatever spelling was typed first, with no way
// to correct it short of delete-and-re-add.
TEST_F(DidMappingTest, UpdateInPlaceAdoptsTheNewRendering)
{
	ASSERT_EQ(_map.setMapping("(202) 555-0123", "1001"), "");
	ASSERT_EQ(_map.setMapping("+12025550123", "1001"), "");  // same line, re-typed
	EXPECT_EQ(_map.size(), 1u);

	const auto list = _map.list();
	ASSERT_EQ(list.size(), 1u);
	EXPECT_EQ(list[0].did, "+12025550123");  // latest write wins, not the first
	EXPECT_EQ(list[0].extension, "1001");

	// Still findable/updatable under either rendering afterward.
	EXPECT_EQ(_map.extensionForDid("(202) 555-0123"), "1001");
	EXPECT_EQ(_map.extensionForDid("+12025550123"), "1001");
}

TEST_F(DidMappingTest, RemoveIsIdempotentAndCompacts)
{
	ASSERT_EQ(_map.setMapping("did-a", "100"), "");
	ASSERT_EQ(_map.setMapping("did-b", "101"), "");
	ASSERT_EQ(_map.setMapping("did-c", "102"), "");

	EXPECT_EQ(_map.removeMapping("did-b"), "");
	EXPECT_EQ(_map.size(), 2u);
	EXPECT_EQ(_map.extensionForDid("did-b"), "");

	const auto list = _map.list();
	ASSERT_EQ(list.size(), 2u);
	EXPECT_EQ(list[0].did, "did-a");
	EXPECT_EQ(list[0].extension, "100");
	EXPECT_EQ(list[1].did, "did-c");  // compacted, order-preserving
	EXPECT_EQ(list[1].extension, "102");

	EXPECT_EQ(_map.removeMapping("did-b"), "");  // idempotent: already gone
	EXPECT_EQ(_map.size(), 2u);
	EXPECT_EQ(_map.removeMapping("never-existed"), "");
}

TEST_F(DidMappingTest, ClearAllRemovesEveryMapping)
{
	ASSERT_EQ(_map.setMapping("did-a", "100"), "");
	ASSERT_EQ(_map.setMapping("did-b", "101"), "");
	ASSERT_EQ(_map.setMapping("did-c", "102"), "");
	ASSERT_EQ(_map.size(), 3u);

	EXPECT_EQ(_map.clearAll(), "");

	EXPECT_EQ(_map.size(), 0u);
	EXPECT_TRUE(_map.list().empty());
	EXPECT_EQ(_map.extensionForDid("did-a"), "");
	EXPECT_EQ(_map.extensionForDid("did-b"), "");
	EXPECT_EQ(_map.extensionForDid("did-c"), "");

	// A fresh add works again afterward (table isn't left in some half-cleared state).
	EXPECT_EQ(_map.setMapping("did-new", "200"), "");
	EXPECT_EQ(_map.size(), 1u);
}

TEST_F(DidMappingTest, ValidationRejectsBadFieldsAndNothingLands)
{
	EXPECT_NE(_map.setMapping("", "100"), "");                 // empty DID
	EXPECT_NE(_map.setMapping("did-a", ""), "");                // empty extension
	EXPECT_NE(_map.setMapping(std::string(DidMapping::kMaxFieldLen + 1, 'x'), "100"), "");
	EXPECT_NE(_map.setMapping("did-a", std::string(DidMapping::kMaxFieldLen + 1, 'x')), "");
	EXPECT_NE(_map.setMapping("did\nwith-newline", "100"), "");
	EXPECT_NE(_map.setMapping("did-a", "ext=100"), "");         // '=' would corrupt the host store
	EXPECT_EQ(_map.size(), 0u);                                 // none of the above landed
	EXPECT_TRUE(_map.list().empty());
}

TEST_F(DidMappingTest, EightSlotsMaxNinthAddFailsCleanly)
{
	ASSERT_EQ(DidMapping::kMaxMappings, static_cast<size_t>(POCKETDIAL_MAX_DID_MAPPINGS));

	for (size_t i = 0; i < DidMapping::kMaxMappings; ++i)
	{
		ASSERT_EQ(_map.setMapping("did-" + std::to_string(i), "ext" + std::to_string(i)), "");
	}
	EXPECT_EQ(_map.size(), DidMapping::kMaxMappings);

	// Table is full: a 9th DISTINCT did is refused cleanly (no crash, error
	// string returned, table left unchanged) rather than growing past the bound.
	const std::string err = _map.setMapping("did-overflow", "999");
	EXPECT_NE(err, "");
	EXPECT_EQ(_map.size(), DidMapping::kMaxMappings);
	EXPECT_EQ(_map.extensionForDid("did-overflow"), "");
	EXPECT_EQ(_map.list().size(), DidMapping::kMaxMappings);

	// Updating one of the EXISTING dids still succeeds on a full table -- an
	// update never consumes a slot.
	EXPECT_EQ(_map.setMapping("did-0", "ext0-updated"), "");
	EXPECT_EQ(_map.extensionForDid("did-0"), "ext0-updated");
	EXPECT_EQ(_map.size(), DidMapping::kMaxMappings);

	// Freeing a slot lets a new DID back in.
	EXPECT_EQ(_map.removeMapping("did-1"), "");
	EXPECT_EQ(_map.setMapping("did-overflow", "999"), "");
	EXPECT_EQ(_map.size(), DidMapping::kMaxMappings);
	EXPECT_EQ(_map.extensionForDid("did-overflow"), "999");
}

#if !defined(_WIN32)
TEST_F(DidMappingTest, PersistsAcrossReload)
{
	ASSERT_EQ(_map.setMapping("+15551234567", "1001"), "");
	ASSERT_EQ(_map.setMapping("+15559876543", "1002"), "");

	DidMapping reloaded;
	reloaded.setStorePath(_path);
	reloaded.load();

	EXPECT_EQ(reloaded.size(), 2u);
	EXPECT_EQ(reloaded.extensionForDid("+15551234567"), "1001");
	EXPECT_EQ(reloaded.extensionForDid("+15559876543"), "1002");
}

TEST_F(DidMappingTest, RemoveThenReloadPersistsCompaction)
{
	ASSERT_EQ(_map.setMapping("did-a", "100"), "");
	ASSERT_EQ(_map.setMapping("did-b", "101"), "");
	ASSERT_EQ(_map.removeMapping("did-a"), "");

	DidMapping reloaded;
	reloaded.setStorePath(_path);
	reloaded.load();

	EXPECT_EQ(reloaded.size(), 1u);
	EXPECT_EQ(reloaded.extensionForDid("did-a"), "");
	EXPECT_EQ(reloaded.extensionForDid("did-b"), "101");
}

TEST_F(DidMappingTest, ClearAllPersistsAcrossReload)
{
	// ClearAllRemovesEveryMapping above only proves the in-memory wipe; on
	// POSIX this proves it reached the on-disk store persist() writes to, so
	// a factory reset really does leave nothing recoverable from a reload.
	ASSERT_EQ(_map.setMapping("did-a", "100"), "");
	ASSERT_EQ(_map.setMapping("did-b", "101"), "");

	ASSERT_EQ(_map.clearAll(), "");

	DidMapping reloaded;
	reloaded.setStorePath(_path);
	reloaded.load();

	EXPECT_EQ(reloaded.size(), 0u);
	EXPECT_TRUE(reloaded.list().empty());
}
#else
TEST_F(DidMappingTest, PersistIsHonestlyInMemoryOnlyOnWindows)
{
	GTEST_SKIP() << "DidMapping::persist() is in-memory only under _WIN32 (mirrors TelephonyApiConfig)";
}
#endif
