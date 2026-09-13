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
// the on-disk round trip on POSIX hosts; TelephonyApiConfig::persist()
// documents that the _WIN32 fallback is honestly in-memory-only, so that
// half is a GTEST_SKIP there rather than a silently-vacuous assertion.

#include <gtest/gtest.h>

#include "TelephonyApiConfig.hpp"
#include "TelephonyProvider.hpp"

#include <cstdio>
#include <string>

namespace
{
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
	EXPECT_EQ(_cfg.setSlot(0, s, false), "");
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
	// TelephonyApiConfig::persist() documents this: no POSIX permission
	// model, so the host fallback stays in-memory rather than writing a
	// world-readable file. GTEST_SKIP rather than silently dropping the
	// round-trip assertion, so CI on this platform says so explicitly.
	GTEST_SKIP() << "TelephonyApiConfig::persist() is in-memory only under _WIN32";
}
#endif
