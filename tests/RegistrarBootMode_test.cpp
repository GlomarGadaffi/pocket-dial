// RegistrarBootMode_test.cpp — issue #397: what registrar mode a board boots in
// when NVS holds no reg_mode.
//
// The rule lives in the pure Registrar::chooseBootMode() so this suite tests the
// exact decision the firmware's loadMode() runs (the NVS read and the mapping
// from DeviceConfig::lastSchemaOutcome() are the ESP-only wrapper around it).
// The host keeps the constructor's Learn seed -- it has no NVS -- and host Learn
// takes the ARP-miss branch and accepts, which is why the rest of the suite can
// REGISTER without credentials.
//
// #441 review invariant: a missing key is what every failed write looks like,
// so "no stored mode" means Learn. #500: open is retired outright -- there is no
// Mode::Open left to boot into, and a stored retired-open byte decodes as Learn
// (Registrar::decodeStored). The schema v1 -> v2 migration writes Learn onto
// deployed pre-#397 boards (pinned in SchemaVersion_test).

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
		// The stored value is ignored when there is none; Secure as the filler
		// proves the decision does not leak it.
		const auto d = Registrar::chooseBootMode(store.has_value(), store.value_or(Mode::Secure), schema);
		if (d.persist && persistSucceeds) store = d.mode;
		return d.mode;
	}

	const Schema kAllSchemas[] = {Schema::FreshInstall, Schema::Upgraded, Schema::Uncertain};
}

TEST(RegistrarBootMode, AFreshInstallBootsLearn)
{
	// This is also the case after a factory reset: poll #455 made the reset a
	// full nvs_flash_erase(), which takes the schema stamp with it, so the next
	// boot is FreshInstall -> Learn.
	const auto d = Registrar::chooseBootMode(false, Mode::Secure, Schema::FreshInstall);
	EXPECT_EQ(d.mode, Mode::Learn)
		<< "a board out of the box must not accept every REGISTER (#397)";
	EXPECT_TRUE(d.persist) << "the choice is made once and saved, not re-decided every boot";
}

TEST(RegistrarBootMode, AfterAFullEraseFactoryResetTheBoardBootsLearn)
{
	// Named for the post-reset state (asked by G-dubs): since #455/#456 the HTTP
	// reset ends in nvs_flash_erase(), so reg_mode AND the schema stamp are gone
	// and the next boot is FreshInstall, whatever mode the board had before.
	for (Mode before : {Mode::Learn, Mode::Secure})
	{
		const auto d = Registrar::chooseBootMode(false, before, Schema::FreshInstall);
		EXPECT_EQ(d.mode, Mode::Learn) << "mode before the reset: " << static_cast<int>(before);
		EXPECT_TRUE(d.persist);
	}
}

TEST(RegistrarBootMode, NoStoredModeBootsLearnWhateverTheSchema)
{
	// #441 review: before, "no key + a stamped schema" meant open. Every failed
	// persist produces exactly that state, so it must mean Learn.
	for (Schema schema : kAllSchemas)
	{
		const auto d = Registrar::chooseBootMode(false, Mode::Secure, schema);
		EXPECT_EQ(d.mode, Mode::Learn) << "schema " << static_cast<int>(schema);
	}
}

TEST(RegistrarBootMode, AnUncertainStoreBootsLearnAndDecidesNothing)
{
	// Store unreadable, or a failed/downgraded schema (including a v1 -> v2
	// migration that could not write): Learn -- which still admits every first
	// REGISTER -- and write nothing, so the next healthy boot decides.
	const auto d = Registrar::chooseBootMode(false, Mode::Secure, Schema::Uncertain);
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

TEST(RegistrarBootMode, AFactoryResetWhoseWriteFailedBootsLearn)
{
	// DeviceConfig::clearAll() writes Learn; if that write fails on a board whose
	// schema stamp survived, the key may simply be gone. That board boots Learn.
	for (Schema schema : kAllSchemas)
	{
		std::optional<Mode> store;   // key gone, write failed
		EXPECT_EQ(boot(store, schema, /*persistSucceeds=*/false), Mode::Learn)
			<< "schema " << static_cast<int>(schema);
	}
}

TEST(RegistrarBootMode, AStoredModeAlwaysWinsAndIsNotRewritten)
{
	// An operator's Learn or Secure stands. (A stored retired-open byte never
	// reaches here as open: decodeStored() has already made it Learn.)
	for (Mode stored : {Mode::Learn, Mode::Secure})
	{
		for (Schema schema : kAllSchemas)
		{
			const auto d = Registrar::chooseBootMode(true, stored, schema);
			EXPECT_EQ(d.mode, stored) << "an operator's (or the flash seed's) choice must stand";
			EXPECT_FALSE(d.persist);
		}
	}
}

TEST(RegistrarBootMode, TheRetiredOpenByteDecodesAsLearnAndIsFlaggedForRewrite)
{
	// #500 (desmo, 2026-09-27): a board that stored 0 (the retired open) must
	// keep admitting its phones -- as Learn -- and loadMode() rewrites the byte
	// once, which is what the flag tells it to do.
	const auto s = Registrar::decodeStored(0);
	EXPECT_TRUE(s.valid) << "a stored open is a known history, not garbage";
	EXPECT_EQ(s.mode, Mode::Learn);
	EXPECT_TRUE(s.wasRetiredOpen);

	const auto learn = Registrar::decodeStored(1);
	EXPECT_TRUE(learn.valid);
	EXPECT_EQ(learn.mode, Mode::Learn);
	EXPECT_FALSE(learn.wasRetiredOpen) << "only the retired byte is rewritten";

	const auto secure = Registrar::decodeStored(2);
	EXPECT_TRUE(secure.valid);
	EXPECT_EQ(secure.mode, Mode::Secure);
	EXPECT_FALSE(secure.wasRetiredOpen);
}

TEST(RegistrarBootMode, AnUnknownModeByteIsNotAMode)
{
	// Out of range stays "no stored mode", which then boots Learn.
	for (uint8_t v : {uint8_t{3}, uint8_t{7}, uint8_t{255}})
	{
		const auto s = Registrar::decodeStored(v);
		EXPECT_FALSE(s.valid) << "byte " << static_cast<int>(v);
		EXPECT_EQ(Registrar::chooseBootMode(s.valid, s.mode, Schema::Upgraded).mode, Mode::Learn);
	}
}
