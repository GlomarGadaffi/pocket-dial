// TelephonyApiConfig_test.cpp — the bounded Telephony-API credential slot
// table (TelephonyApiConfig.hpp), ported verbatim from drawbridge, plus the
// TelephonyProviderType::Telephony enumerator this project declares -- now
// backed by the real TelephonyAnchorClient (also ported from drawbridge; see
// TelephonyProvider.hpp).
//
// Covers: slot CRUD + validation (including the enabled-slot https:// gate),
// the active-slot selector, out-of-range handling, and -- the property that
// matters most for a credential store -- that view() (and therefore any
// GET/dashboard/UI surface built on it) NEVER exposes the plaintext secret,
// only bootSlot() (the engine-only, boot-time accessor) does. Also covers
// the on-disk round trip on POSIX hosts; TelephonyApiConfig::persistNow()
// documents that the _WIN32 fallback is honestly in-memory-only, so that
// half is a GTEST_SKIP there rather than a silently-vacuous assertion.

#include <gtest/gtest.h>

#include "TelephonyApiConfig.hpp"
#include "TelephonyProvider.hpp"

#include <cstdio>
#include <fstream>
#include <string>

namespace
{
	// #1073: enabling a slot needs the administrator's acceptance of the current warning text.
	const TelephonyApiConfig::Acceptance kAccepted{TelephonyApiConfig::kAcceptanceVersion, 2, 1760000000};

	class TelephonyApiConfigTest : public ::testing::Test
	{
	protected:
		void SetUp() override
		{
			_path = std::string("test_tapicfg_") +
			        ::testing::UnitTest::GetInstance()->current_test_info()->name() + ".cfg";
			std::remove(_path.c_str());
			_cfg.setStorePath(_path);
			_cfg.load();  // no file yet: defaults stand
		}
		void TearDown() override
		{
			std::remove(_path.c_str());
		}

		TelephonyApiConfig _cfg;
		std::string _path;
	};
}

TEST_F(TelephonyApiConfigTest, DefaultsAreEmptyAndNoActiveSlot)
{
	EXPECT_EQ(_cfg.activeSlot(), TelephonyApiConfig::kNoActiveSlot);
	for (size_t i = 0; i < TelephonyApiConfig::kSlots; ++i)
	{
		const auto v = _cfg.view(i);
		EXPECT_EQ(v.type, TelephonyProviderType::Loopback);
		EXPECT_FALSE(v.enabled);
		EXPECT_FALSE(v.active);
		EXPECT_FALSE(v.secretSet);
	}
}

TEST_F(TelephonyApiConfigTest, SetSlotRoundTripsNonSecretFields)
{
	TelephonyApiConfig::Slot s;
	s.type = TelephonyProviderType::Loopback;
	s.baseUrl = "https://example.invalid";
	s.clientId = "client-123";
	s.secret = "sssh";
	s.routeDn = "100";

	EXPECT_EQ(_cfg.setSlot(0, s, /*keepSecret=*/false), "");

	const auto v = _cfg.view(0);
	EXPECT_EQ(v.baseUrl, "https://example.invalid");
	EXPECT_EQ(v.clientId, "client-123");
	EXPECT_EQ(v.routeDn, "100");
	EXPECT_TRUE(v.secretSet);
}

TEST_F(TelephonyApiConfigTest, EnabledRealSlotRefusesIncompleteIdentity)
{
	// Regression: an ENABLED real-provider slot used to be accepted with a blank
	// route DN. Nothing downstream can catch that -- isConnected() is WebSocket
	// state and the control socket carries no DN -- so the board boots
	// "connected", every makeCall POSTs to ".../callcontrol//makecall", the
	// provider really is reached and answers non-2xx. In the field that reads as
	// "the API was hit but no call happened". This is the only place it is
	// detectable, so it has to be refused here.
	TelephonyApiConfig::Slot base;
	base.type = TelephonyProviderType::Telephony;
	base.baseUrl = "https://pbx.example.invalid";
	base.clientId = "id";
	base.secret = "sssh";
	base.routeDn = "100";
	base.enabled = true;

	{   // blank route DN
		TelephonyApiConfig::Slot s = base;
		s.routeDn.clear();
		EXPECT_EQ(_cfg.setSlot(0, s, false), "Enabled slot needs a route DN");
	}
	{   // blank client id
		TelephonyApiConfig::Slot s = base;
		s.clientId.clear();
		EXPECT_EQ(_cfg.setSlot(0, s, false), "Enabled slot needs a client ID");
	}
	{   // blank secret
		TelephonyApiConfig::Slot s = base;
		s.secret.clear();
		EXPECT_EQ(_cfg.setSlot(0, s, false), "Enabled slot needs a client secret");
	}

	// None of those wrote anything.
	EXPECT_FALSE(_cfg.view(0).enabled);

	// The complete slot saves.
	ASSERT_EQ(_cfg.setSlot(0, base, false, &kAccepted), "");
	EXPECT_TRUE(_cfg.view(0).enabled);

	// keepSecret validates the STORED secret, not the deliberately-empty
	// incoming one -- editing the route DN of a saved slot must still work.
	TelephonyApiConfig::Slot edit = base;
	edit.secret.clear();
	edit.routeDn = "200";
	EXPECT_EQ(_cfg.setSlot(0, edit, /*keepSecret=*/true), "");
	EXPECT_EQ(_cfg.view(0).routeDn, "200");
	EXPECT_TRUE(_cfg.view(0).secretSet);

	// A DISABLED slot is still free to be incomplete -- it is a draft.
	TelephonyApiConfig::Slot draft = base;
	draft.enabled = false;
	draft.routeDn.clear();
	EXPECT_EQ(_cfg.setSlot(1, draft, false), "");

	// ...and so is a Loopback slot, which needs no credentials at all.
	TelephonyApiConfig::Slot loop;
	loop.type = TelephonyProviderType::Loopback;
	loop.enabled = true;
	EXPECT_EQ(_cfg.setSlot(2, loop, false), "");
}

TEST_F(TelephonyApiConfigTest, EmergencyRouteDnIsRefusedEnabledOrDraft)
{
	// #1047: routeDn is the number testDialSlot() self-dials, so an emergency number
	// there would have the provider place a real 911/933 call from a connectivity
	// probe. setSlot refuses it, enabled or not. The set is every spelling the
	// emergency classifier knows (the bare codes and the trunk-prefixed 9911/9933)
	// plus 112 and 113, which classifyEmergencyDial does not recognise.
	TelephonyApiConfig::Slot base;
	base.type = TelephonyProviderType::Telephony;
	base.baseUrl = "https://pbx.example.invalid";
	base.clientId = "id";
	base.secret = "sssh";
	base.enabled = true;

	for (const char* dn : {"911", "933", "9911", "9933", "112", "113"})
	{
		TelephonyApiConfig::Slot s = base;
		s.routeDn = dn;
		EXPECT_EQ(_cfg.setSlot(0, s, false), "Route DN may not be an emergency number")
			<< "an enabled slot with routeDn " << dn << " must be refused";
		EXPECT_FALSE(_cfg.view(0).enabled)
			<< "a refused routeDn " << dn << " must not have been saved";

		TelephonyApiConfig::Slot draft = s;
		draft.enabled = false;
		EXPECT_EQ(_cfg.setSlot(1, draft, false), "Route DN may not be an emergency number")
			<< "a disabled slot with routeDn " << dn << " must be refused too";
		EXPECT_EQ(_cfg.view(1).routeDn, "")
			<< "a refused routeDn " << dn << " must not have been saved";
	}

	// A real route DN still saves, so the refusal is narrow.
	base.routeDn = "100";
	EXPECT_EQ(_cfg.setSlot(0, base, false, &kAccepted), "");
	EXPECT_TRUE(_cfg.view(0).enabled);
}

TEST_F(TelephonyApiConfigTest, StoredEmergencyRouteDnIsDisabledOnLoad)
{
	// #1060: a store written before the #1047 refusal can hold an emergency routeDn in an
	// enabled slot, and the boot path copies an enabled slot's routeDn into the anchor
	// config. load() disables such a slot; a slot with a real routeDn is left alone.
	for (const char* dn : {"911", "933", "9911", "9933", "112", "113"})
	{
		{
			std::ofstream f(_path, std::ios::trunc);
			const char* dns[] = {dn, "100"};
			for (size_t i = 0; i < 2; ++i)
			{
				const std::string k = "s" + std::to_string(i);
				f << k << "type=" << static_cast<int>(TelephonyProviderType::Telephony) << "\n"
				  << k << "en=1\n"
				  << k << "url=https://pbx.example.invalid\n"
				  << k << "id=id\n"
				  << k << "sec=sssh\n"
				  << k << "dn=" << dns[i] << "\n";
			}
			f << "active=0\n";
		}
		TelephonyApiConfig loaded;
		loaded.setStorePath(_path);
		loaded.load();

		EXPECT_FALSE(loaded.view(0).enabled) << "routeDn " << dn << " must load disabled";
		EXPECT_FALSE(loaded.bootSlot(0)->enabled) << "the boot path reads bootSlot(): " << dn;
		EXPECT_TRUE(loaded.view(1).enabled) << "a real routeDn still loads enabled";
		EXPECT_EQ(loaded.view(1).routeDn, "100");
	}
}

TEST_F(TelephonyApiConfigTest, SecretNeverAppearsInView)
{
	TelephonyApiConfig::Slot s;
	s.type = TelephonyProviderType::Telephony;
	s.baseUrl = "https://example.invalid";
	s.clientId = "id";
	s.secret = "top-secret-value";
	s.routeDn = "100";
	ASSERT_EQ(_cfg.setSlot(0, s, false), "");

	const auto v = _cfg.view(0);
	// SlotView has no secret field at all (compile-time guarantee); also
	// assert the plaintext doesn't leak out through any OTHER displayable
	// field.
	EXPECT_NE(v.baseUrl, s.secret);
	EXPECT_NE(v.clientId, s.secret);
	EXPECT_NE(v.routeDn, s.secret);
	EXPECT_TRUE(v.secretSet);

	// Only bootSlot() -- the engine-only, boot-time accessor -- returns the
	// plaintext.
	const TelephonyApiConfig::Slot* boot = _cfg.bootSlot(0);
	ASSERT_NE(boot, nullptr);
	EXPECT_EQ(boot->secret, "top-secret-value");
}

TEST_F(TelephonyApiConfigTest, TelephonyApiSlotReportsImplemented)
{
	TelephonyApiConfig::Slot s;
	s.type = TelephonyProviderType::Telephony;
	s.baseUrl = "https://example.invalid";
	s.clientId = "id";
	s.secret = "secret";
	s.routeDn = "100";
	ASSERT_EQ(_cfg.setSlot(0, s, false), "");

	// TelephonyAnchorClient (ported from drawbridge) is now registered for
	// this enumerator, so a slot pointing at it is honestly reported as
	// implemented -- the pre-port honesty check (this used to assert FALSE
	// for a declared-but-stubbed provider) flips the other way once the real
	// client lands, exactly as SlotView::implemented is meant to.
	EXPECT_TRUE(_cfg.view(0).implemented);
	EXPECT_TRUE(_cfg.view(0).secretSet);
}

TEST_F(TelephonyApiConfigTest, LoopbackSlotReportsImplemented)
{
	TelephonyApiConfig::Slot s;
	s.type = TelephonyProviderType::Loopback;
	ASSERT_EQ(_cfg.setSlot(0, s, false), "");
	EXPECT_TRUE(_cfg.view(0).implemented);
}

TEST_F(TelephonyApiConfigTest, KeepSecretRetainsStoredValue)
{
	TelephonyApiConfig::Slot s;
	s.type = TelephonyProviderType::Loopback;
	s.baseUrl = "https://example.invalid";
	s.clientId = "id1";
	s.secret = "first-secret";
	s.routeDn = "100";
	ASSERT_EQ(_cfg.setSlot(0, s, false), "");

	TelephonyApiConfig::Slot edit = s;
	edit.clientId = "id2";
	edit.secret = "";  // the UI sends an empty field for "unchanged"
	ASSERT_EQ(_cfg.setSlot(0, edit, /*keepSecret=*/true), "");

	EXPECT_EQ(_cfg.view(0).clientId, "id2");
	ASSERT_NE(_cfg.bootSlot(0), nullptr);
	EXPECT_EQ(_cfg.bootSlot(0)->secret, "first-secret");
}

TEST_F(TelephonyApiConfigTest, ClearSlotWipesSecretAndFields)
{
	TelephonyApiConfig::Slot s;
	s.type = TelephonyProviderType::Loopback;
	s.baseUrl = "https://example.invalid";
	s.clientId = "id";
	s.secret = "secret";
	s.routeDn = "100";
	ASSERT_EQ(_cfg.setSlot(0, s, false), "");
	ASSERT_EQ(_cfg.clearSlot(0), "");

	const auto v = _cfg.view(0);
	EXPECT_FALSE(v.secretSet);
	EXPECT_EQ(v.baseUrl, "");
	EXPECT_EQ(v.type, TelephonyProviderType::Loopback);
}

TEST_F(TelephonyApiConfigTest, ClearingActiveSlotClearsActiveSelection)
{
	TelephonyApiConfig::Slot s;
	s.type = TelephonyProviderType::Loopback;
	ASSERT_EQ(_cfg.setSlot(0, s, false), "");
	ASSERT_EQ(_cfg.setActiveSlot(0), "");
	ASSERT_EQ(_cfg.activeSlot(), 0u);

	ASSERT_EQ(_cfg.clearSlot(0), "");
	EXPECT_EQ(_cfg.activeSlot(), TelephonyApiConfig::kNoActiveSlot);
}

TEST_F(TelephonyApiConfigTest, ClearAllWipesEverySlotAndActiveSelection)
{
	// Populate every slot with a live secret, and mark one active.
	for (size_t i = 0; i < TelephonyApiConfig::kSlots; ++i)
	{
		TelephonyApiConfig::Slot s;
		s.type = TelephonyProviderType::Loopback;
		s.baseUrl = "https://example.invalid";
		s.clientId = "id" + std::to_string(i);
		s.secret = "secret" + std::to_string(i);
		s.routeDn = "10" + std::to_string(i);
		ASSERT_EQ(_cfg.setSlot(i, s, false), "");
	}
	ASSERT_EQ(_cfg.setActiveSlot(1), "");
	ASSERT_EQ(_cfg.activeSlot(), 1u);

	EXPECT_EQ(_cfg.clearAll(), "");

	EXPECT_EQ(_cfg.activeSlot(), TelephonyApiConfig::kNoActiveSlot);
	for (size_t i = 0; i < TelephonyApiConfig::kSlots; ++i)
	{
		const auto v = _cfg.view(i);
		EXPECT_FALSE(v.secretSet) << "slot " << i;
		EXPECT_EQ(v.baseUrl, "") << "slot " << i;
		EXPECT_EQ(v.clientId, "") << "slot " << i;
		EXPECT_EQ(v.routeDn, "") << "slot " << i;
		EXPECT_EQ(v.type, TelephonyProviderType::Loopback) << "slot " << i;
	}
}

TEST_F(TelephonyApiConfigTest, EnabledNonLoopbackSlotRequiresHttps)
{
	TelephonyApiConfig::Slot s;
	s.type = TelephonyProviderType::Telephony;
	s.enabled = true;
	s.baseUrl = "http://example.invalid";  // not https
	s.clientId = "id";
	s.secret = "secret";
	s.routeDn = "100";
	EXPECT_NE(_cfg.setSlot(0, s, false), "");
	EXPECT_FALSE(_cfg.view(0).enabled);  // rejected edit must never apply

	s.baseUrl = "https://example.invalid";
	EXPECT_EQ(_cfg.setSlot(0, s, false, &kAccepted), "");
	EXPECT_TRUE(_cfg.view(0).enabled);
}

TEST_F(TelephonyApiConfigTest, OutOfRangeIndexIsRejectedEverywhere)
{
	TelephonyApiConfig::Slot s;
	EXPECT_NE(_cfg.setSlot(TelephonyApiConfig::kSlots, s, false), "");
	EXPECT_NE(_cfg.clearSlot(TelephonyApiConfig::kSlots), "");
	// kSlots itself is the valid "clear the active selection" sentinel;
	// only past that is out of range.
	EXPECT_EQ(_cfg.setActiveSlot(TelephonyApiConfig::kSlots), "");
	EXPECT_NE(_cfg.setActiveSlot(TelephonyApiConfig::kSlots + 1), "");

	const auto v = _cfg.view(TelephonyApiConfig::kSlots);
	EXPECT_EQ(v.type, TelephonyProviderType::Loopback);  // default view, no crash
}

// ── #1073: enabling a slot needs the administrator's acceptance ───────────────

namespace
{
	TelephonyApiConfig::Slot realSlot()
	{
		TelephonyApiConfig::Slot s;
		s.type = TelephonyProviderType::Telephony;
		s.enabled = true;
		s.baseUrl = "https://pbx.example.invalid";
		s.clientId = "id";
		s.secret = "sssh";
		s.routeDn = "100";
		return s;
	}

	bool refusedForAcceptance(const std::string& err)
	{
		return err.rfind(TelephonyApiConfig::kAcceptanceRequiredPrefix, 0) == 0;
	}
}

TEST_F(TelephonyApiConfigTest, EnablingASlotWithoutAcceptanceIsRefusedAndChangesNothing)
{
	const std::string err = _cfg.setSlot(0, realSlot(), false);
	EXPECT_TRUE(refusedForAcceptance(err)) << "got: " << err;
	EXPECT_NE(err.find("acceptLimitations=" + std::to_string(TelephonyApiConfig::kAcceptanceVersion)), std::string::npos)
		<< "the error names the field that is missing: " << err;
	EXPECT_FALSE(_cfg.view(0).enabled);
	EXPECT_EQ(_cfg.view(0).baseUrl, "") << "a refused enable must not have saved the rest of the edit";
	EXPECT_FALSE(_cfg.view(0).secretSet);

	// An acceptance of some other warning-text version is no acceptance.
	TelephonyApiConfig::Acceptance stale = kAccepted;
	stale.version = static_cast<uint8_t>(TelephonyApiConfig::kAcceptanceVersion + 1);
	EXPECT_TRUE(refusedForAcceptance(_cfg.setSlot(0, realSlot(), false, &stale)));
	stale.version = 0;
	EXPECT_TRUE(refusedForAcceptance(_cfg.setSlot(0, realSlot(), false, &stale)));
	EXPECT_FALSE(_cfg.view(0).enabled);

	// Disabling needs none.
	TelephonyApiConfig::Slot draft = realSlot();
	draft.enabled = false;
	EXPECT_EQ(_cfg.setSlot(0, draft, false), "");
}

TEST_F(TelephonyApiConfigTest, AcceptanceIsStoredWithTheSlotWhoWhenAndWhichText)
{
	ASSERT_EQ(_cfg.setSlot(1, realSlot(), false, &kAccepted), "");
	const auto v = _cfg.view(1);
	EXPECT_TRUE(v.enabled);
	EXPECT_TRUE(v.accepted);
	EXPECT_FALSE(v.acceptanceMissing);
	EXPECT_EQ(v.acceptedVersion, TelephonyApiConfig::kAcceptanceVersion);
	EXPECT_EQ(v.acceptedRole, 2u);
	EXPECT_EQ(v.acceptedAt, 1760000000u);
	EXPECT_EQ(_cfg.acceptanceMissingMask(), 0u);

	// Editing an enabled, accepted slot needs no new acceptance and keeps the stored one.
	TelephonyApiConfig::Slot edit = realSlot();
	edit.routeDn = "200";
	ASSERT_EQ(_cfg.setSlot(1, edit, true), "");
	EXPECT_EQ(_cfg.view(1).routeDn, "200");
	EXPECT_EQ(_cfg.view(1).acceptedAt, 1760000000u);
	EXPECT_EQ(_cfg.view(1).acceptedRole, 2u);

#if !defined(_WIN32)
	// ...and it is in the store, so a reboot still has it.
	TelephonyApiConfig reloaded;
	reloaded.setStorePath(_path);
	reloaded.load();
	EXPECT_TRUE(reloaded.view(1).accepted);
	EXPECT_EQ(reloaded.view(1).acceptedVersion, TelephonyApiConfig::kAcceptanceVersion);
	EXPECT_EQ(reloaded.view(1).acceptedRole, 2u);
	EXPECT_EQ(reloaded.view(1).acceptedAt, 1760000000u);
#endif
}

TEST_F(TelephonyApiConfigTest, DisablingClearsTheAcceptanceSoTheNextEnableAsksAgain)
{
	ASSERT_EQ(_cfg.setSlot(0, realSlot(), false, &kAccepted), "");
	TelephonyApiConfig::Slot off = realSlot();
	off.enabled = false;
	ASSERT_EQ(_cfg.setSlot(0, off, true), "");
	EXPECT_FALSE(_cfg.view(0).enabled);
	EXPECT_FALSE(_cfg.view(0).accepted);
	EXPECT_EQ(_cfg.view(0).acceptedAt, 0u);

	EXPECT_TRUE(refusedForAcceptance(_cfg.setSlot(0, realSlot(), true)))
		<< "each enable asks: the earlier acceptance did not survive the disable";
	EXPECT_FALSE(_cfg.view(0).enabled);
}

TEST_F(TelephonyApiConfigTest, ActivatingNeedsAnAcceptanceTheSlotHoldsOrTheCallerCarries)
{
	TelephonyApiConfig::Slot draft = realSlot();
	draft.enabled = false;
	ASSERT_EQ(_cfg.setSlot(2, draft, false), "");

	EXPECT_TRUE(refusedForAcceptance(_cfg.activateSlot(2, nullptr)));
	EXPECT_EQ(_cfg.activeSlot(), TelephonyApiConfig::kNoActiveSlot) << "a refused activation selects nothing";

	EXPECT_EQ(_cfg.activateSlot(2, &kAccepted), "");
	EXPECT_EQ(_cfg.activeSlot(), 2u);
	EXPECT_TRUE(_cfg.view(2).accepted);

	// A slot that holds an acceptance activates without one.
	ASSERT_EQ(_cfg.setSlot(3, realSlot(), false, &kAccepted), "");
	EXPECT_EQ(_cfg.activateSlot(3, nullptr), "");
	EXPECT_EQ(_cfg.activeSlot(), 3u);

	// Deactivating, and a bad index, are not acceptance questions.
	EXPECT_EQ(_cfg.activateSlot(TelephonyApiConfig::kNoActiveSlot, nullptr), "");
	EXPECT_EQ(_cfg.activeSlot(), TelephonyApiConfig::kNoActiveSlot);
	EXPECT_EQ(_cfg.activateSlot(TelephonyApiConfig::kSlots + 1, nullptr), "Bad slot index");
}

#if !defined(_WIN32)
namespace
{
	// A store as an earlier build left it: slot 1 enabled and complete, no acceptance key at all.
	void writeLegacyStore(const std::string& path, const char* accLine)
	{
		std::ofstream f(path, std::ios::trunc);
		f << "s1type=" << static_cast<int>(TelephonyProviderType::Telephony) << "\ns1en=1\n"
		  << "s1url=https://pbx.example.invalid\ns1id=id\ns1sec=sssh\ns1dn=100\n" << accLine
		  << "active=1\n";
	}
}

TEST_F(TelephonyApiConfigTest, ASlotEnabledBeforeThisShippedKeepsWorkingAndReportsTheMissingAcceptance)
{
	writeLegacyStore(_path, "");
	TelephonyApiConfig legacy;
	legacy.setStorePath(_path);
	legacy.load();

	const auto v = legacy.view(1);
	EXPECT_TRUE(v.enabled) << "not disabled by this change";
	EXPECT_TRUE(v.active);
	EXPECT_TRUE(v.acceptanceMissing);
	EXPECT_FALSE(v.accepted);
	EXPECT_EQ(legacy.acceptanceMissingMask(), 1u << 1);
	ASSERT_NE(legacy.bootSlot(1), nullptr);
	EXPECT_TRUE(legacy.bootSlot(1)->enabled) << "the boot path still brings it up";
	EXPECT_FALSE(legacy.view(0).acceptanceMissing) << "an unused slot is not 'missing' anything";

	// Re-saving it enabled needs the acceptance like any enable, and a refusal leaves it as it was.
	EXPECT_TRUE(refusedForAcceptance(legacy.setSlot(1, realSlot(), true)));
	EXPECT_TRUE(legacy.view(1).enabled);
	EXPECT_TRUE(legacy.view(1).active);
	EXPECT_EQ(legacy.activateSlot(1, &kAccepted), "");
	EXPECT_FALSE(legacy.view(1).acceptanceMissing);
	EXPECT_EQ(legacy.acceptanceMissingMask(), 0u);
}

TEST_F(TelephonyApiConfigTest, AnAcceptanceOfAnOlderWarningTextCountsAsMissing)
{
	// The text changed (kAcceptanceVersion was bumped): what was stored for the old text is stale.
	const std::string stale = std::to_string(TelephonyApiConfig::kAcceptanceVersion + 1);
	const std::string line = "s1acc=" + stale + ",2,1700000000\n";
	writeLegacyStore(_path, line.c_str());
	TelephonyApiConfig loaded;
	loaded.setStorePath(_path);
	loaded.load();
	EXPECT_TRUE(loaded.view(1).enabled);
	EXPECT_TRUE(loaded.view(1).acceptanceMissing);
	EXPECT_FALSE(loaded.view(1).accepted);

	// A current-version line is read back whole.
	const std::string good = "s1acc=" + std::to_string(TelephonyApiConfig::kAcceptanceVersion) + ",1,1700000000\n";
	writeLegacyStore(_path, good.c_str());
	TelephonyApiConfig fresh;
	fresh.setStorePath(_path);
	fresh.load();
	EXPECT_TRUE(fresh.view(1).accepted);
	EXPECT_EQ(fresh.view(1).acceptedRole, 1u);
	EXPECT_EQ(fresh.view(1).acceptedAt, 1700000000u);

	// A mangled line is no acceptance, not a crash.
	writeLegacyStore(_path, "s1acc=garbage\n");
	TelephonyApiConfig bad;
	bad.setStorePath(_path);
	bad.load();
	EXPECT_TRUE(bad.view(1).acceptanceMissing);
}
#endif

#if !defined(_WIN32)
TEST_F(TelephonyApiConfigTest, PersistsAcrossReload)
{
	TelephonyApiConfig::Slot s;
	s.type = TelephonyProviderType::Loopback;
	s.baseUrl = "https://example.invalid";
	s.clientId = "id";
	s.secret = "secret-value";
	s.routeDn = "100";
	ASSERT_EQ(_cfg.setSlot(1, s, false), "");
	ASSERT_EQ(_cfg.setActiveSlot(1), "");

	TelephonyApiConfig reloaded;
	reloaded.setStorePath(_path);
	reloaded.load();

	EXPECT_EQ(reloaded.activeSlot(), 1u);
	EXPECT_EQ(reloaded.view(1).clientId, "id");
	EXPECT_EQ(reloaded.view(1).routeDn, "100");
	EXPECT_TRUE(reloaded.view(1).secretSet);
	ASSERT_NE(reloaded.bootSlot(1), nullptr);
	EXPECT_EQ(reloaded.bootSlot(1)->secret, "secret-value");
}

TEST_F(TelephonyApiConfigTest, ClearAllPersistsAcrossReload)
{
	// The in-memory assertions in ClearAllWipesEverySlotAndActiveSelection
	// above only prove clearAll() zeroized _slots; on POSIX this proves the
	// wipe actually reached the on-disk store persist() writes to, so a
	// factory reset really does leave nothing recoverable from a reload.
	TelephonyApiConfig::Slot s;
	s.type = TelephonyProviderType::Loopback;
	s.baseUrl = "https://example.invalid";
	s.clientId = "id";
	s.secret = "secret-value";
	s.routeDn = "100";
	ASSERT_EQ(_cfg.setSlot(1, s, false), "");
	ASSERT_EQ(_cfg.setActiveSlot(1), "");

	ASSERT_EQ(_cfg.clearAll(), "");

	TelephonyApiConfig reloaded;
	reloaded.setStorePath(_path);
	reloaded.load();

	EXPECT_EQ(reloaded.activeSlot(), TelephonyApiConfig::kNoActiveSlot);
	EXPECT_FALSE(reloaded.view(1).secretSet);
	EXPECT_EQ(reloaded.view(1).clientId, "");
	EXPECT_EQ(reloaded.view(1).routeDn, "");
}
#else
TEST_F(TelephonyApiConfigTest, PersistIsHonestlyInMemoryOnlyOnWindows)
{
	// TelephonyApiConfig::persistNow() documents this: no POSIX permission
	// model, so the host fallback stays in-memory rather than writing a
	// world-readable file. GTEST_SKIP rather than silently dropping the
	// round-trip assertion, so CI on this platform says so explicitly.
	GTEST_SKIP() << "TelephonyApiConfig::persistNow() is in-memory only under _WIN32";
}
#endif
