// SchemaVersion_test.cpp — the NVS schema decision table and migration dispatch.
//
// Issue #181. This device keeps its whole identity in NVS (admin credential,
// extensions and their secrets, dial plan, ring groups, DID map, trunk API
// slots, WiFi config, syslog target) and is updated over the air. The decision
// taken at boot about what layout that data is in therefore has a worst case
// measured in re-provisioned phone systems, not in failed unit tests.
//
// The one case that MUST be right is "data present, no version stamp". That is
// every board already in the field on the release that introduces versioning.
// Read it as "blank device" and the firmware wipes or re-seeds a live PBX; read
// it as "already current" and a future release skips the migrations that device
// actually needs. It must be read as v1.
//
// Why these tests can exist at all: planSchema() and runSchemaMigrations() are
// deliberately pure and platform-neutral, so they compile and run on the host
// where there is no NVS. ensureSchemaVersion() — the nvs_open/nvs_get_u16 glue
// around them — is inside `#if defined(ESP_PLATFORM)` and is NOT covered here.
// That split is the same lesson #151 taught: logic buried in the device branch
// shipped inert through two releases because nothing could run it.
//
// Why `current` is a parameter of planSchema(): with kSchemaVersion at 1 (as it was),
// "treat legacy data as v1" and "stamp a blank device with current" produce the
// identical number, so a test against the shipped constant cannot distinguish a
// correct implementation from one that conflates the two. Every case below that
// cares drives a synthetic `current` of 3.

#include <gtest/gtest.h>

#include "DeviceConfig.hpp"

#include <vector>

using DeviceConfig::SchemaOutcome;
using DeviceConfig::SchemaPlan;
using DeviceConfig::SchemaProbe;

namespace
{
	// A probe for a device whose NVS could be inspected successfully. The two
	// interesting axes are "is there a stamp" and "is there any data".
	SchemaProbe probeOf(bool versionPresent, uint16_t version, bool hasData)
	{
		SchemaProbe p;
		p.storeReadable   = true;
		p.versionPresent  = versionPresent;
		p.version         = version;
		p.hasExistingData = hasData;
		return p;
	}

	// --- Migration-walker scaffolding -------------------------------------
	// The walker takes plain function pointers (no std::function, no captures)
	// so it stays allocation-free and usable from boot code. Recording state
	// therefore lives in file-static vectors, reset by resetRecorder().

	std::vector<uint16_t> g_ran;       // `to` version of each migration invoked
	std::vector<uint16_t> g_stamped;   // every version handed to the stamp fn
	bool g_failAt2 = false;            // make the 2->3 step fail
	bool g_stampFails = false;         // make the stamp callback fail

	void resetRecorder()
	{
		g_ran.clear();
		g_stamped.clear();
		g_failAt2 = false;
		g_stampFails = false;
	}

	bool migrate1to2(void*) { g_ran.push_back(2); return true; }
	bool migrate2to3(void*) { g_ran.push_back(3); return !g_failAt2; }
	bool migrate3to4(void*) { g_ran.push_back(4); return true; }

	bool recordStamp(void*, uint16_t v)
	{
		g_stamped.push_back(v);
		return !g_stampFails;
	}

	const DeviceConfig::SchemaMigration kChain[] = {
		{1, 2, &migrate1to2, "1->2"},
		{2, 3, &migrate2to3, "2->3"},
		{3, 4, &migrate3to4, "3->4"},
	};
}

// =====================================================================
// The decision table
// =====================================================================

TEST(SchemaVersion, LegacyDeviceIsAdoptedAsV1AndNeverWiped)
{
	// ***** The case this whole framework exists for. *****
	// A board provisioned by any shipped release: it has data, it has no stamp,
	// because no release ever wrote one. Its layout IS v1 — that is a fact about
	// what those releases wrote, not an assumption.
	//
	// `current` is 3 so this can be told apart from the fresh-install row, which
	// would also produce 1 if `current` were left at kSchemaVersion.
	const SchemaPlan plan = DeviceConfig::planSchema(
		probeOf(/*versionPresent=*/false, /*version=*/0, /*hasData=*/true), 3);

	EXPECT_EQ(plan.outcome, SchemaOutcome::AdoptedLegacy);
	EXPECT_EQ(plan.fromVersion, 1);    // adopted at the baseline, NOT at `current`
	EXPECT_EQ(plan.toVersion, 3);
	EXPECT_TRUE(plan.migrate);         // so the 1->2->3 steps actually run
	EXPECT_TRUE(plan.stamp);           // and the result is recorded
}

TEST(SchemaVersion, LegacyDeviceOnBaselineFirmwareIsStampedWithoutMigrating)
{
	// Firmware whose current version IS the baseline (the release that
	// introduced versioning, kSchemaVersion == 1): adopting a legacy device
	// converts nothing and only writes the stamp. It must not touch a single
	// config key.
	const SchemaPlan plan = DeviceConfig::planSchema(
		probeOf(false, 0, true), DeviceConfig::kSchemaBaselineVersion);

	EXPECT_EQ(plan.outcome, SchemaOutcome::AdoptedLegacy);
	EXPECT_EQ(plan.fromVersion, DeviceConfig::kSchemaBaselineVersion);
	EXPECT_FALSE(plan.migrate);
	EXPECT_TRUE(plan.stamp);
}

TEST(SchemaVersion, LegacyDeviceOnShippedFirmwareRunsTheV2Migration)
{
	// Shipped today (v2, #397/#441): a pre-versioning board is adopted as v1 and
	// then MIGRATED, because v2 changed what an absent reg_mode means.
	const SchemaPlan plan = DeviceConfig::planSchema(
		probeOf(false, 0, true), DeviceConfig::kSchemaVersion);

	EXPECT_EQ(plan.outcome, SchemaOutcome::AdoptedLegacy);
	EXPECT_EQ(plan.fromVersion, DeviceConfig::kSchemaBaselineVersion);
	EXPECT_EQ(plan.toVersion, 2);
	EXPECT_TRUE(plan.migrate);
	EXPECT_TRUE(plan.stamp);
}

TEST(SchemaVersion, BlankDeviceIsBornCurrent)
{
	// No stamp and no data anywhere: a genuinely fresh install. It is born at
	// today's layout, so there is nothing to migrate FROM — running the 1->2->3
	// chain over keys that do not exist would at best waste flash writes.
	const SchemaPlan plan = DeviceConfig::planSchema(
		probeOf(false, 0, /*hasData=*/false), 3);

	EXPECT_EQ(plan.outcome, SchemaOutcome::FreshInstall);
	EXPECT_EQ(plan.fromVersion, 3);    // current, NOT the v1 baseline
	EXPECT_FALSE(plan.migrate);
	EXPECT_TRUE(plan.stamp);
}

TEST(SchemaVersion, CurrentDeviceWritesNothing)
{
	// Every ordinary reboot. A stamp write here would be flash wear on every
	// power cycle for no information gained.
	const SchemaPlan plan = DeviceConfig::planSchema(probeOf(true, 3, true), 3);

	EXPECT_EQ(plan.outcome, SchemaOutcome::UpToDate);
	EXPECT_EQ(plan.fromVersion, 3);
	EXPECT_FALSE(plan.migrate);
	EXPECT_FALSE(plan.stamp);
}

TEST(SchemaVersion, OlderStampMigratesForward)
{
	const SchemaPlan plan = DeviceConfig::planSchema(probeOf(true, 1, true), 3);

	EXPECT_EQ(plan.outcome, SchemaOutcome::Migrated);
	EXPECT_EQ(plan.fromVersion, 1);
	EXPECT_EQ(plan.toVersion, 3);
	EXPECT_TRUE(plan.migrate);
	EXPECT_TRUE(plan.stamp);
}

TEST(SchemaVersion, NewerStampIsADowngradeThatWritesNothing)
{
	// Old firmware on a store written by newer firmware. This is not a
	// hypothetical: OTA rollback is armed (CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE)
	// and the new image is only marked valid after several seconds of healthy
	// operation, so "migrated to v4, stamped, crashed, rolled back" puts an old
	// image on a v4 store with no operator involved.
	//
	// Nothing may be written. Stamping backwards would let the newer firmware
	// return and mistake its own v4 data for v3; migrating would convert data it
	// does not understand. The device still BOOTS — that decision lives in
	// ensureSchemaVersion(), which logs the banner and carries on, because a PBX
	// that refuses to ring is worse than one running on possibly-misread config.
	const SchemaPlan plan = DeviceConfig::planSchema(probeOf(true, 4, true), 3);

	EXPECT_EQ(plan.outcome, SchemaOutcome::Downgrade);
	EXPECT_EQ(plan.fromVersion, 4);
	EXPECT_FALSE(plan.migrate);
	EXPECT_FALSE(plan.stamp);
}

TEST(SchemaVersion, UnreadableStoreIsNeverTreatedAsBlank)
{
	// nvs_open() or nvs_get_u16() failed with something other than NOT_FOUND. We
	// do not know what is on flash. The dangerous mistake is collapsing "cannot
	// tell" into "nothing there", which would stamp a fully provisioned device as
	// a fresh install and, on a later release, skip every migration it needed.
	SchemaProbe p;
	p.storeReadable = false;

	const SchemaPlan plan = DeviceConfig::planSchema(p, 3);

	EXPECT_EQ(plan.outcome, SchemaOutcome::StoreUnavailable);
	EXPECT_FALSE(plan.migrate);
	EXPECT_FALSE(plan.stamp);
}

TEST(SchemaVersion, StampedZeroIsTreatedAsUnstamped)
{
	// No release has written 0, so reading one means a foreign or corrupt write.
	// Routing it through the legacy path re-stamps it with a real version rather
	// than leaving a meaningless value on flash forever — and crucially does NOT
	// try to migrate "from version 0", for which no table row can exist.
	const SchemaPlan plan = DeviceConfig::planSchema(probeOf(true, 0, true), 3);

	EXPECT_EQ(plan.outcome, SchemaOutcome::AdoptedLegacy);
	EXPECT_EQ(plan.fromVersion, 1);
	EXPECT_TRUE(plan.stamp);
}

// =====================================================================
// Migration dispatch
// =====================================================================

TEST(SchemaVersion, ShippedTableIsExactlyTheRegModeRow)
{
	// Guard against speculative migrations: the only row is v1 -> v2, the real
	// change of meaning #397 made (an absent reg_mode: Open -> Learn). Its NVS
	// body is ESP-only; this pins the table's shape.
	size_t count = 12345;
	const DeviceConfig::SchemaMigration* table = DeviceConfig::schemaMigrations(&count);

	EXPECT_EQ(DeviceConfig::kSchemaVersion, 2);
	EXPECT_EQ(DeviceConfig::kSchemaBaselineVersion, 1);
	ASSERT_EQ(count, 1u);
	ASSERT_NE(table, nullptr);
	EXPECT_EQ(table[0].from, 1);
	EXPECT_EQ(table[0].to, 2);
	EXPECT_NE(table[0].fn, nullptr);
}

TEST(SchemaVersion, ShippedTableWalksBaselineToCurrentWithoutAGap)
{
	// A future kSchemaVersion bump that forgets its row fails here, on the host,
	// instead of leaving every board unstamped (MigrationFailed) in the field.
	resetRecorder();
	size_t count = 0;
	const DeviceConfig::SchemaMigration* table = DeviceConfig::schemaMigrations(&count);
	uint16_t reached = 0;

	EXPECT_TRUE(DeviceConfig::runSchemaMigrations(DeviceConfig::kSchemaBaselineVersion,
		DeviceConfig::kSchemaVersion, table, count, nullptr, &recordStamp, &reached));
	EXPECT_EQ(reached, DeviceConfig::kSchemaVersion);
}

TEST(SchemaVersion, ChainRunsInOrderAndStampsAfterEveryStep)
{
	// Per-step stamping is the whole reason the walker takes a stamp callback
	// instead of returning a final version: a power cut between two conversions
	// must leave the device at the last layout that actually landed.
	resetRecorder();
	uint16_t reached = 0;

	EXPECT_TRUE(DeviceConfig::runSchemaMigrations(
		1, 4, kChain, 3, nullptr, &recordStamp, &reached));

	EXPECT_EQ(reached, 4);
	EXPECT_EQ(g_ran, (std::vector<uint16_t>{2, 3, 4}));
	EXPECT_EQ(g_stamped, (std::vector<uint16_t>{2, 3, 4}));
}

TEST(SchemaVersion, FailedStepStopsTheChainAtTheLastGoodVersion)
{
	// 1->2 succeeds, 2->3 fails. The device must end up stamped 2 (not 1, which
	// would re-run a conversion that already landed; not 4, which would claim
	// work that never happened), and 3->4 must never be invoked.
	resetRecorder();
	g_failAt2 = true;
	uint16_t reached = 0;

	EXPECT_FALSE(DeviceConfig::runSchemaMigrations(
		1, 4, kChain, 3, nullptr, &recordStamp, &reached));

	EXPECT_EQ(reached, 2);
	EXPECT_EQ(g_ran, (std::vector<uint16_t>{2, 3}));   // 3->4 never attempted
	EXPECT_EQ(g_stamped, (std::vector<uint16_t>{2}));  // only the step that landed
}

TEST(SchemaVersion, FailedStampAbortsTheChain)
{
	// A migration that converted the data but could not record that it did is
	// worse than one that failed outright: continuing would run the next step on
	// top of it and leave the stamp describing neither layout.
	resetRecorder();
	g_stampFails = true;
	uint16_t reached = 0;

	EXPECT_FALSE(DeviceConfig::runSchemaMigrations(
		1, 4, kChain, 3, nullptr, &recordStamp, &reached));

	EXPECT_EQ(reached, 1);
	EXPECT_EQ(g_ran, (std::vector<uint16_t>{2}));   // stopped before 2->3
}

TEST(SchemaVersion, GapInTheTableFailsRatherThanSkipping)
{
	// Table jumps 1->2 then 3->4 with nothing for 2. Silently landing on 4
	// because "we got as far as we could" would stamp a half-converted device as
	// finished, which is undiagnosable in the field.
	resetRecorder();
	const DeviceConfig::SchemaMigration gapped[] = {
		{1, 2, &migrate1to2, "1->2"},
		{3, 4, &migrate3to4, "3->4"},
	};
	uint16_t reached = 0;

	EXPECT_FALSE(DeviceConfig::runSchemaMigrations(
		1, 4, gapped, 2, nullptr, &recordStamp, &reached));

	EXPECT_EQ(reached, 2);
	EXPECT_EQ(g_ran, (std::vector<uint16_t>{2}));
}

TEST(SchemaVersion, EmptyTableCannotSatisfyAMigration)
{
	// If a kSchemaVersion bump ever forgets its row, this is the behaviour that
	// keeps the device honest rather than stamping it as converted.
	resetRecorder();
	uint16_t reached = 0;

	EXPECT_FALSE(DeviceConfig::runSchemaMigrations(
		1, 2, nullptr, 0, nullptr, &recordStamp, &reached));

	EXPECT_EQ(reached, 1);
	EXPECT_TRUE(g_stamped.empty());
}

TEST(SchemaVersion, NothingToDoIsSuccess)
{
	// from == to, which is what a fresh install and an up-to-date device both
	// produce. It must succeed without calling anything.
	resetRecorder();
	uint16_t reached = 0;

	EXPECT_TRUE(DeviceConfig::runSchemaMigrations(
		3, 3, kChain, 3, nullptr, &recordStamp, &reached));

	EXPECT_EQ(reached, 3);
	EXPECT_TRUE(g_ran.empty());
	EXPECT_TRUE(g_stamped.empty());
}

TEST(SchemaVersion, BackwardsRowIsRefusedWithoutRunningIt)
{
	// A hand-written table with 2->1 alongside 1->2 would, unguarded, spin
	// forever inside app_main() — no watchdog kicked, no console output, a board
	// that simply never finishes booting. Two things must hold: the walker stops,
	// and the backwards row is NEVER EXECUTED. Running it and only then noticing
	// would have already converted the data in the wrong direction.
	resetRecorder();
	const DeviceConfig::SchemaMigration cyclic[] = {
		{1, 2, &migrate1to2, "1->2"},
		{2, 1, &migrate2to3, "2->1 (bogus)"},
	};
	uint16_t reached = 0;

	EXPECT_FALSE(DeviceConfig::runSchemaMigrations(
		1, 4, cyclic, 2, nullptr, &recordStamp, &reached));
	EXPECT_EQ(reached, 2);
	// Only the forward step ran. If the backwards row had been executed this
	// would hold {2, 3} and the device's data would already be wrong.
	EXPECT_EQ(g_ran, (std::vector<uint16_t>{2}));
}

TEST(SchemaVersion, OutcomeNamesAreStable)
{
	// These strings go into boot logs and are the handle an operator or a future
	// dashboard field uses. Pin them so a reordered enum does not silently
	// relabel a downgrade as an up-to-date device.
	EXPECT_STREQ(DeviceConfig::schemaOutcomeName(SchemaOutcome::FreshInstall), "fresh-install");
	EXPECT_STREQ(DeviceConfig::schemaOutcomeName(SchemaOutcome::AdoptedLegacy), "adopted-legacy");
	EXPECT_STREQ(DeviceConfig::schemaOutcomeName(SchemaOutcome::UpToDate), "up-to-date");
	EXPECT_STREQ(DeviceConfig::schemaOutcomeName(SchemaOutcome::Migrated), "migrated");
	EXPECT_STREQ(DeviceConfig::schemaOutcomeName(SchemaOutcome::MigrationFailed), "migration-failed");
	EXPECT_STREQ(DeviceConfig::schemaOutcomeName(SchemaOutcome::Downgrade), "downgrade");
	EXPECT_STREQ(DeviceConfig::schemaOutcomeName(SchemaOutcome::StoreUnavailable), "store-unavailable");
}
