// RegistrarBootMode_test.cpp — issue #397: what registrar mode a board boots in
// when NVS holds no reg_mode.
//
// The rule lives in the pure Registrar::chooseBootMode() so this suite tests the
// exact decision the firmware's loadMode() runs (the NVS read and the mapping
// from DeviceConfig::lastSchemaOutcome() are the ESP-only wrapper around it).
// The host itself keeps the Open seed -- it has no NVS -- which is why the rest
// of the suite can REGISTER without credentials.
//
// #441 review invariant: NO failure of a write or a read may end in Open on a
// board that was fresh or factory-reset. A missing key is what every failed
// write looks like, so "no stored mode" never means Open. Deployed pre-#397
// boards keep Open because the schema v1 -> v2 migration WRITES it (pinned in
// SchemaVersion_test's ShippedTableIsExactlyTheRegModeRow).

#include <gtest/gtest.h>

#include <optional>

#include "Registrar.hpp"

using Mode = Registrar::Mode;
using Schema = Registrar::BootSchema;

namespace
{
	// One boot against a one-key store: what loadMode() does, minus NVS.
	// `persistSucceeds` = false models a failed nvs_open/set/commit, which
	// leaves the store exactly as it was.
	Mode boot(std::optional<Mode>& store, Schema schema, bool persistSucceeds)
	{
		const auto d = Registrar::chooseBootMode(store.has_value(), store.value_or(Mode::Open), schema);
		if (d.persist && persistSucceeds) store = d.mode;
		return d.mode;
	}

	const Schema kAllSchemas[] = {Schema::FreshInstall, Schema::Upgraded, Schema::Uncertain};
}

TEST(RegistrarBootMode, AFreshInstallIsNotAnOpenRegistrar)
{
	// This is also the case after a factory reset: poll #455 made the reset a
	// full nvs_flash_erase(), which takes the schema stamp with it, so the next
	// boot is FreshInstall -> Learn.
	const auto d = Registrar::chooseBootMode(false, Mode::Open, Schema::FreshInstall);
	EXPECT_EQ(d.mode, Mode::Learn)
		<< "a board out of the box must not accept every REGISTER (#397)";
	EXPECT_TRUE(d.persist) << "the choice is made once and saved, not re-decided every boot";
}

TEST(RegistrarBootMode, AfterAFullEraseFactoryResetTheBoardBootsLearn)
{
	// Named for the post-reset state (asked by G-dubs): since #455/#456 the HTTP
	// reset ends in nvs_flash_erase(), so reg_mode AND the schema stamp are gone
	// and the next boot is FreshInstall, whatever mode the board had before.
	for (Mode before : {Mode::Open, Mode::Learn, Mode::Secure})
	{
		const auto d = Registrar::chooseBootMode(false, before, Schema::FreshInstall);
		EXPECT_EQ(d.mode, Mode::Learn) << "mode before the reset: " << static_cast<int>(before);
		EXPECT_TRUE(d.persist);
	}
}

TEST(RegistrarBootMode, NoStoredModeIsNeverOpenWhateverTheSchema)
{
	// #441 review: before, "no key + a stamped schema" meant Open. Every failed
	// persist produces exactly that state, so it must not.
	for (Schema schema : kAllSchemas)
	{
		const auto d = Registrar::chooseBootMode(false, Mode::Open, schema);
		EXPECT_EQ(d.mode, Mode::Learn) << "schema " << static_cast<int>(schema);
	}
}

TEST(RegistrarBootMode, AnUncertainStoreBootsLearnAndDecidesNothing)
{
	// Store unreadable, or a failed/downgraded schema (including a v1 -> v2
	// migration that could not write): Learn -- which still admits every first
	// REGISTER -- and write nothing, so the next healthy boot decides.
	const auto d = Registrar::chooseBootMode(false, Mode::Open, Schema::Uncertain);
	EXPECT_EQ(d.mode, Mode::Learn);
	EXPECT_FALSE(d.persist);
}

TEST(RegistrarBootMode, APersistThatFailsCannotOpenTheNextBoot)
{
	// Sonny-OG's case, as a sequence: a fresh board's first boot fails to save
	// its mode. The schema is already stamped, so the second boot sees "no key,
	// UpToDate" -- which is what used to map to Open.
	std::optional<Mode> store;
	EXPECT_EQ(boot(store, Schema::FreshInstall, /*persistSucceeds=*/false), Mode::Learn);
	ASSERT_FALSE(store.has_value()) << "precondition: the persist really failed";

	EXPECT_EQ(boot(store, Schema::Upgraded, /*persistSucceeds=*/false), Mode::Learn)
		<< "second boot after a failed persist";
	EXPECT_EQ(boot(store, Schema::Upgraded, /*persistSucceeds=*/true), Mode::Learn)
		<< "and once the store heals, Learn is what gets saved";
	EXPECT_EQ(store, std::optional<Mode>(Mode::Learn));
	EXPECT_EQ(boot(store, Schema::Upgraded, /*persistSucceeds=*/true), Mode::Learn) << "and it sticks";
}

TEST(RegistrarBootMode, AFactoryResetWhoseWriteFailedCannotBootOpen)
{
	// DeviceConfig::clearAll() writes Learn; if that write fails on a board whose
	// schema stamp survived, the key may simply be gone. That board boots Learn.
	for (Schema schema : kAllSchemas)
	{
		std::optional<Mode> store;   // key gone, write failed
		EXPECT_NE(boot(store, schema, /*persistSucceeds=*/false), Mode::Open)
			<< "schema " << static_cast<int>(schema);
	}
}

TEST(RegistrarBootMode, AStoredModeAlwaysWinsAndIsNotRewritten)
{
	// Including Open: that is how a deployed board, migrated v1 -> v2, keeps it.
	for (Mode stored : {Mode::Open, Mode::Learn, Mode::Secure})
	{
		for (Schema schema : kAllSchemas)
		{
			const auto d = Registrar::chooseBootMode(true, stored, schema);
			EXPECT_EQ(d.mode, stored) << "an operator's (or the flash seed's) choice must stand";
			EXPECT_FALSE(d.persist);
		}
	}
}
