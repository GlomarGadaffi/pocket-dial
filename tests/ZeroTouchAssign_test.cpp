// Issue #826 part B: zero-touch extension assignment.
//
// While an admin-opened window is open, a config fetch from an unknown MAC can
// be handed the next free extension in the window's range (Registrar::
// assignNext). The new row is LOCKED, so the extension is reserved for that
// MAC, and ASSIGNED (unclaimed) until the MAC first registers. An unclaimed
// row is evictable, first, and at most kMaxUnclaimed exist: unauthenticated
// fetches cannot pin the table. These tests pin those rules, the #487 order
// (a refusal for want of a token evicts nothing), the persisted flag layout,
// and RequestsHandler's gates (verified MAC, Learn mode, routing).

#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <string>

#include "ArpLookup.hpp"
#include "DidMapping.hpp"
#include "FakePbxEnv.hpp"
#include "PoolConfig.hpp"
#include "Registrar.hpp"
#include "RequestsHandler.hpp"

namespace
{
	using Clock = std::chrono::steady_clock;
	using Decision = Registrar::AuthDecision;

	// 10.82.6.<n> is used by no other test.
	std::string ipFor(int n) { return "10.82.6." + std::to_string(n); }
	std::string macFor(int n)
	{
		char buf[13];
		std::snprintf(buf, sizeof(buf), "0282060000%02x", n & 0xFF);
		return buf;
	}

	std::string registerRaw(const std::string& ext, const std::string& ip)
	{
		return "REGISTER sip:10.82.6.1 SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bK826" + ext + "\r\n"
			"From: <sip:" + ext + "@10.82.6.1>;tag=t" + ext + "\r\n"
			"To: <sip:" + ext + "@10.82.6.1>\r\n"
			"Call-ID: zt826-" + ext + "-" + ip + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + ip + ":5060>;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
	}

	auto noneUnusable = [](const std::string&) { return false; };

	class ZeroTouch : public ::testing::Test
	{
	protected:
		FakePbxEnv env;
		Registrar reg{env, Registrar::Mode::Learn};
		Clock::time_point t0 = Clock::now();

		void TearDown() override { ArpLookup::clearMockMacs(); }

		void open(uint32_t lo, uint32_t hi) { ASSERT_TRUE(reg.openAssignWindow(lo, hi, t0, t0 + std::chrono::minutes(30))); }

		std::string assign(int n, Clock::time_point when)
		{
			std::string ext;
			Registrar::AssignRefusal why = Registrar::AssignRefusal::None;
			return reg.assignNext(macFor(n), when, noneUnusable, ext, why) ? ext : std::string();
		}

		// A REGISTER for `ext` from phone n (source 10.82.6.n, MAC macFor(n)).
		Decision registerAs(int n, const std::string& ext, bool arpHit = true)
		{
			const sockaddr_in a = FakePbxEnv::addr(ipFor(n).c_str(), 5060);
			if (arpHit)
			{
				ArpLookup::setMockMac(a, {0x02, 0x82, 0x06, 0x00, 0x00, static_cast<uint8_t>(n)});
			}
			std::string reason;
			return reg.admitLearn(std::make_shared<SipMessage>(registerRaw(ext, ipFor(n)), a), ext, reason, t0);
		}

		bool hasRow(const std::string& mac)
		{
			for (const auto& d : reg.adoptedDevices()) if (d.mac == mac) return true;
			return false;
		}
	};
}

TEST_F(ZeroTouch, AssignsTheLowestFreeExtensionAndTheSameOneAgain)
{
	open(2001, 2010);
	EXPECT_EQ(assign(1, t0), "2001");
	EXPECT_EQ(assign(2, t0), "2002");
	EXPECT_EQ(assign(1, t0), "2001");   // same MAC, same extension
	EXPECT_EQ(reg.unclaimedCount(), 2u);
	for (const auto& d : reg.adoptedDevices())
	{
		EXPECT_TRUE(d.locked);
		EXPECT_TRUE(d.assigned);
	}
}

TEST_F(ZeroTouch, SkipsExtensionsHeldByARowOrUnusable)
{
	open(2001, 2010);
	reg.adoptDeviceForTest("aa0000000001", "2001");
	auto unusable = [](const std::string& e) { return e == "2002"; };
	std::string ext;
	Registrar::AssignRefusal why = Registrar::AssignRefusal::None;
	ASSERT_TRUE(reg.assignNext(macFor(1), t0, unusable, ext, why));
	EXPECT_EQ(ext, "2003");
}

TEST_F(ZeroTouch, NothingIsAssignedOutsideAnOpenWindow)
{
	EXPECT_EQ(assign(1, t0), "");                     // never opened
	ASSERT_TRUE(reg.openAssignWindow(2001, 2010, t0, t0 + std::chrono::minutes(1)));
	EXPECT_EQ(assign(1, t0 + std::chrono::minutes(2)), "");   // expired
	EXPECT_FALSE(reg.assignWindow(t0 + std::chrono::minutes(2)).open);
	EXPECT_EQ(assign(1, t0), "2001");
	reg.closeAssignWindow();
	EXPECT_EQ(assign(2, t0), "");
	EXPECT_FALSE(hasRow(macFor(2)));
}

TEST_F(ZeroTouch, RangeIsValidatedAndBounded)
{
	EXPECT_FALSE(reg.openAssignWindow(2010, 2001, t0, t0 + std::chrono::minutes(5)));
	EXPECT_FALSE(reg.openAssignWindow(1000, 1000 + Registrar::kMaxAssignSpan, t0, t0 + std::chrono::minutes(5)));
	EXPECT_TRUE(reg.openAssignWindow(1000, 1000 + Registrar::kMaxAssignSpan - 1, t0, t0 + std::chrono::minutes(5)));
	reg.adoptDeviceForTest("aa0000000001", "3000");
	ASSERT_TRUE(reg.openAssignWindow(3000, 3000, t0, t0 + std::chrono::minutes(5)));
	EXPECT_EQ(assign(1, t0), "");   // the only extension is taken
}

TEST_F(ZeroTouch, AtMostKMaxUnclaimedAndRegisteringClaims)
{
	open(2001, 2050);
	for (int n = 1; n <= static_cast<int>(Registrar::kMaxUnclaimed); ++n) EXPECT_NE(assign(n, t0), "");
	const auto later = t0 + std::chrono::minutes(5);   // tokens are back
	EXPECT_EQ(assign(99, later), "") << "the unclaimed cap, not the token bucket, refuses this";
	reg.markOnline(macFor(1), true, "2001");            // phone 1 registered its extension
	EXPECT_EQ(reg.unclaimedCount(), Registrar::kMaxUnclaimed - 1);
	EXPECT_NE(assign(99, later), "");
}

TEST_F(ZeroTouch, AnAssignedExtensionIsReservedForItsMac)
{
	open(2001, 2010);
	ASSERT_EQ(assign(1, t0), "2001");
	EXPECT_EQ(registerAs(2, "2001"), Decision::Reject) << "another MAC cannot take it";
	EXPECT_EQ(registerAs(1, "2001"), Decision::Accept) << "its own phone can";
}

TEST_F(ZeroTouch, AnArpMissOnTheFirstRegisterIsRetriedNotRefused)
{
	open(2001, 2010);
	ASSERT_EQ(assign(1, t0), "2001");
	EXPECT_EQ(registerAs(1, "2001", /*arpHit=*/false), Decision::RetryLater);
	EXPECT_EQ(registerAs(1, "2001", /*arpHit=*/true), Decision::Accept);
}

TEST_F(ZeroTouch, AFullTableEvictsAnUnclaimedRowFirst)
{
	open(2001, 2100);
	const int max = POCKETDIAL_MAX_CLIENTS;
	for (int n = 0; n < max - 1; ++n)
	{
		char mac[13];
		std::snprintf(mac, sizeof(mac), "bb00000000%02x", n);
		reg.adoptDeviceForTest(mac, std::to_string(3000 + n));
	}
	ASSERT_EQ(assign(1, t0), "2001");                   // the table is now full
	ASSERT_EQ(reg.adoptedDevices().size(), static_cast<size_t>(max));
	// The free extension is chosen before the eviction, so phone 2 gets 2002;
	// what matters is WHICH row made room: phone 1's unclaimed one, not a
	// plain Learned row (all of which are older).
	EXPECT_EQ(assign(2, t0), "2002");
	EXPECT_FALSE(hasRow(macFor(1)));
	EXPECT_TRUE(hasRow("bb0000000000"));
	EXPECT_EQ(reg.adoptedDevices().size(), static_cast<size_t>(max));
}

TEST_F(ZeroTouch, ARefusalForWantOfATokenEvictsNothing)
{
	open(2001, 2100);
	// Spend all four tokens, then claim the rows so the unclaimed cap is not
	// what refuses below.
	for (int n = 1; n <= Registrar::kAdoptBurst; ++n)
	{
		const std::string e = assign(n, t0);
		ASSERT_NE(e, "");
		reg.markOnline(macFor(n), true, e);
	}
	const int max = POCKETDIAL_MAX_CLIENTS;
	for (int n = 0; static_cast<int>(reg.adoptedDevices().size()) < max; ++n)
	{
		char mac[13];
		std::snprintf(mac, sizeof(mac), "cc00000000%02x", n);
		reg.adoptDeviceForTest(mac, std::to_string(4000 + n));
	}
	const auto before = reg.adoptedDevices().size();
	EXPECT_EQ(assign(99, t0), "") << "no token left at t0";
	EXPECT_EQ(reg.adoptedDevices().size(), before);
	EXPECT_TRUE(hasRow("cc0000000000")) << "the oldest evictable row must survive a refusal";
}

TEST_F(ZeroTouch, CanAssignAgreesWithAssignNextAndChangesNothing)
{
	EXPECT_FALSE(reg.canAssign(macFor(1), t0, noneUnusable));
	open(2001, 2001);
	EXPECT_TRUE(reg.canAssign(macFor(1), t0, noneUnusable));
	EXPECT_EQ(reg.adoptedDevices().size(), 0u);
	ASSERT_EQ(assign(1, t0), "2001");
	EXPECT_TRUE(reg.canAssign(macFor(1), t0, noneUnusable)) << "an existing row is servable";
	EXPECT_FALSE(reg.canAssign(macFor(2), t0, noneUnusable)) << "no free extension left";
}

TEST(ZeroTouchFlags, PersistedFlagsRoundTripAndOldBlobsDecodeUnassigned)
{
	for (int bits = 0; bits < 8; ++bits)
	{
		const Registrar::RowFlags f = Registrar::decodeRowFlags(bits);
		EXPECT_EQ(Registrar::encodeRowFlags(f), bits);
	}
	for (int old = 0; old <= 3; ++old)   // pre-#826 values
	{
		const Registrar::RowFlags f = Registrar::decodeRowFlags(old);
		EXPECT_FALSE(f.assigned);
		EXPECT_EQ(f.locked, (old & 1) != 0);
		EXPECT_EQ(f.shared, (old & 2) != 0);
	}
	EXPECT_TRUE(Registrar::decodeRowFlags(5).assigned);
}

// ── RequestsHandler gates ────────────────────────────────────────────────────

TEST(ZeroTouchHandler, NeedsAVerifiedMacLearnModeAndAnOpenWindow)
{
	RequestsHandler h("10.82.6.1", 5060, [](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	std::string ext;
	EXPECT_FALSE(h.autoAssign("0282060000aa", true, ext)) << "no window";
	EXPECT_EQ(h.autoAssignState().refusals, 0u) << "with no window open, nothing to explain";
	ASSERT_TRUE(h.openAutoAssign(2001, 2010, 10));
	EXPECT_FALSE(h.autoAssign("0282060000aa", false, ext)) << "unverified MAC";
	h.setRegistrarMode(RequestsHandler::RegistrarMode::Secure);
	EXPECT_FALSE(h.autoAssign("0282060000aa", true, ext)) << "Secure mode";
	h.setRegistrarMode(RequestsHandler::RegistrarMode::Learn);
	ASSERT_TRUE(h.autoAssign("0282060000aa", true, ext));
	EXPECT_EQ(ext, "2001");
	EXPECT_TRUE(h.canProvisionMac("0282060000aa"));
	const auto info = h.findProvisioningInfo("0282060000aa");
	ASSERT_TRUE(info.has_value());
	EXPECT_EQ(info->extension, "2001");
	EXPECT_EQ(h.autoAssignState().unclaimed, 1u);
	EXPECT_FALSE(h.openAutoAssign(2001, 2010, 0));
	EXPECT_FALSE(h.openAutoAssign(2001, 2010, RequestsHandler::kMaxAssignMinutes + 1));
}

TEST(ZeroTouchHandler, NeverAssignsAnExtensionRoutingWouldShadow)
{
	RequestsHandler h("10.82.6.1", 5060, [](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	EXPECT_TRUE(h.isRoutedElsewhere("911"));
	EXPECT_TRUE(h.isRoutedElsewhere("777"));
	EXPECT_TRUE(h.isRoutedElsewhere("981"));    // page zone
	EXPECT_TRUE(h.isRoutedElsewhere("700"));    // park orbit
	EXPECT_FALSE(h.isRoutedElsewhere("2001"));
	h.setRingGroup("600", "2001,2002", "ringall");
	EXPECT_TRUE(h.isRoutedElsewhere("600"));
	// A window over 600-601 skips the ring-group pilot.
	ASSERT_TRUE(h.openAutoAssign(600, 601, 10));
	std::string ext;
	ASSERT_TRUE(h.autoAssign("0282060000ab", true, ext));
	EXPECT_EQ(ext, "601");
}

TEST_F(ZeroTouch, ARegisterForAnotherExtensionDoesNotClaim)
{
	open(2001, 2010);
	ASSERT_EQ(assign(1, t0), "2001");
	reg.markOnline(macFor(1), true, "2999");
	EXPECT_EQ(reg.unclaimedCount(), 1u);
	reg.markOnline(macFor(1), true, "2001");
	EXPECT_EQ(reg.unclaimedCount(), 0u);
}

TEST_F(ZeroTouch, ANewWindowDropsRowsLeftUnclaimedByTheLastOne)
{
	// Four phones fetch and never register: without this the cap would hold
	// zero-touch shut for good.
	open(2001, 2050);
	for (int n = 1; n <= static_cast<int>(Registrar::kMaxUnclaimed); ++n) ASSERT_NE(assign(n, t0), "");
	ASSERT_EQ(assign(9, t0 + std::chrono::minutes(5)), "");   // capped
	reg.closeAssignWindow();
	const auto t1 = t0 + std::chrono::minutes(10);
	ASSERT_TRUE(reg.openAssignWindow(2001, 2050, t1, t1 + std::chrono::minutes(30)));
	EXPECT_EQ(reg.unclaimedCount(), 0u);
	EXPECT_FALSE(hasRow(macFor(1)));
	EXPECT_EQ(assign(9, t1), "2001");
	// Reopening an OPEN window only moves its end; this window's row stays.
	ASSERT_TRUE(reg.openAssignWindow(2001, 2050, t1, t1 + std::chrono::minutes(60)));
	EXPECT_TRUE(hasRow(macFor(9)));
}

TEST_F(ZeroTouch, RefusalsSayWhy)
{
	std::string ext;
	Registrar::AssignRefusal why = Registrar::AssignRefusal::None;
	EXPECT_FALSE(reg.assignNext(macFor(1), t0, noneUnusable, ext, why));
	EXPECT_EQ(why, Registrar::AssignRefusal::NoWindow);
	open(2001, 2001);
	auto all = [](const std::string&) { return true; };
	EXPECT_FALSE(reg.assignNext(macFor(1), t0, all, ext, why));
	EXPECT_EQ(why, Registrar::AssignRefusal::NoFreeExtension);
	EXPECT_EQ(reg.freeExtensionCount(t0, all), 0u);
	EXPECT_EQ(reg.freeExtensionCount(t0, noneUnusable), 1u);
}

TEST(ZeroTouchHandler, ARealRegisterThroughTheEngineClaimsTheRow)
{
	RequestsHandler h("10.82.6.1", 5060, [](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	ASSERT_TRUE(h.openAutoAssign(2001, 2010, 10));
	std::string ext;
	ASSERT_TRUE(h.autoAssign(macFor(7), true, ext));
	ASSERT_EQ(ext, "2001");
	const sockaddr_in a = FakePbxEnv::addr(ipFor(7).c_str(), 5060);
	ArpLookup::setMockMac(a, {0x02, 0x82, 0x06, 0x00, 0x00, 0x07});
	h.handle(RequestsHandler::getMessageFromPool(registerRaw("2001", ipFor(7)), a));
	bool found = false;
	for (const auto& d : h.getAdoptedDevices())
	{
		if (d.mac != macFor(7)) continue;
		found = true;
		EXPECT_EQ(d.extension, "2001");
		EXPECT_TRUE(d.locked);
		EXPECT_FALSE(d.assigned) << "registering its own extension claims the row";
	}
	EXPECT_TRUE(found);
	EXPECT_EQ(h.autoAssignState().unclaimed, 0u);
	ArpLookup::clearMockMacs();
}

TEST(ZeroTouchHandler, AnExtensionWithStateIsNeverAssigned)
{
	// Voicemail, DND, a forward: each belongs to someone already. (DID
	// targets: DidMapping.isTarget below; a handler mapping persists to disk.)
	RequestsHandler h("10.82.6.1", 5060, [](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	h.setVoicemail("2001", true);
	h.setDnd("2002", true);
	h.setForward("2003", "always", "2001");
	ASSERT_TRUE(h.openAutoAssign(2001, 2010, 10));
	EXPECT_EQ(h.autoAssignState().free, 7u);
	std::string ext;
	ASSERT_TRUE(h.autoAssign(macFor(8), true, ext));
	EXPECT_EQ(ext, "2004");
	EXPECT_FALSE(h.autoAssign(macFor(9), false, ext));
	EXPECT_EQ(h.autoAssignState().lastRefusal, RequestsHandler::ZeroTouchRefusal::Unverified);
	EXPECT_STREQ(RequestsHandler::zeroTouchRefusalName(h.autoAssignState().lastRefusal), "unverified");
}

TEST(ZeroTouchDid, ADidTargetIsVisibleWithoutAHeapScanOfTheStore)
{
	DidMapping m;
	m.setStorePath(::testing::TempDir() + "zt826_didmap.cfg");
	ASSERT_TRUE(m.setMapping("+15551234567", "2001").empty());
	EXPECT_TRUE(m.isTarget("2001"));
	EXPECT_FALSE(m.isTarget("2002"));
	m.clearAll();
}
