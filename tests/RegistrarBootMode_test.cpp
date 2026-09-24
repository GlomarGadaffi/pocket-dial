// RegistrarBootMode_test.cpp — issue #397: what registrar mode a board boots in
// when NVS holds no reg_mode.
//
// The rule lives in the pure Registrar::chooseBootMode() so this suite tests the
// exact decision the firmware's loadMode() runs (the NVS read and the mapping
// from DeviceConfig::lastSchemaOutcome() are the ESP-only wrapper around it).
// The host itself keeps the Open seed -- it has no NVS -- which is why the rest
// of the suite can REGISTER without credentials.

#include <gtest/gtest.h>

#include "Registrar.hpp"

using Mode = Registrar::Mode;
using Schema = Registrar::BootSchema;

TEST(RegistrarBootMode, AFreshInstallIsNotAnOpenRegistrar)
{
	const auto d = Registrar::chooseBootMode(false, Mode::Open, Schema::FreshInstall);
	EXPECT_EQ(d.mode, Mode::Learn)
		<< "a board out of the box must not accept every REGISTER (#397)";
	EXPECT_TRUE(d.persist) << "the choice is made once and saved, not re-decided every boot";
}

TEST(RegistrarBootMode, AnExistingBoardWithNoStoredModeKeepsOpen)
{
	// A deployed board predating #397 has no reg_mode and runs Open; flipping it
	// would silently change how its phones are admitted. Keep Open -- but write
	// it, so it becomes a visible setting instead of a compiled-in default.
	const auto d = Registrar::chooseBootMode(false, Mode::Open, Schema::Upgraded);
	EXPECT_EQ(d.mode, Mode::Open);
	EXPECT_TRUE(d.persist);
}

TEST(RegistrarBootMode, AnUncertainStoreDecidesNothing)
{
	// Store unreadable, or a failed/downgraded schema: boot Open as before, but
	// write nothing, so the next healthy boot makes the real decision.
	const auto d = Registrar::chooseBootMode(false, Mode::Open, Schema::Uncertain);
	EXPECT_EQ(d.mode, Mode::Open);
	EXPECT_FALSE(d.persist);
}

TEST(RegistrarBootMode, AStoredModeAlwaysWinsAndIsNotRewritten)
{
	for (Mode stored : {Mode::Open, Mode::Learn, Mode::Secure})
	{
		for (Schema schema : {Schema::FreshInstall, Schema::Upgraded, Schema::Uncertain})
		{
			const auto d = Registrar::chooseBootMode(true, stored, schema);
			EXPECT_EQ(d.mode, stored) << "an operator's (or the flash seed's) choice must stand";
			EXPECT_FALSE(d.persist);
		}
	}
}
