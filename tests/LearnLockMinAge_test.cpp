// LearnLockMinAge_test.cpp — issue #515 item 1: a minimum age for the locking
// sighting.
//
// Since #440 Learn locks an extension to a MAC on that MAC's next REGISTER for
// it. An on-link host answering ARP for many fake MACs could lock one extension
// per MAC with two REGISTERs sent back to back (squatting a fresh board; each
// lock is also an NVS write). The locking sighting must now come at least 30 s
// after the MAC's first sighting for that extension. A real phone's refresh is
// later than that; a burst is not. A younger sighting is still admitted (TOFU)
// and does not move the first-sighting time.
//
// Every test drives Registrar::admitLearn() with explicit time points. The host
// has no ARP table, so each source IP gets a mock MAC (ArpLookup::setMockMac),
// cleared in TearDown: the rest of the suite relies on the host's permanent miss.

#include <gtest/gtest.h>

#include <chrono>
#include <memory>
#include <string>

#include "ArpLookup.hpp"
#include "FakePbxEnv.hpp"
#include "PoolConfig.hpp"
#include "Registrar.hpp"

namespace
{
	using Clock = std::chrono::steady_clock;
	using Decision = Registrar::AuthDecision;
	using std::chrono::milliseconds;
	using std::chrono::seconds;

	// 10.51.15.<n> is used by no other test.
	std::string ipFor(int n) { return "10.51.15." + std::to_string(n); }

	std::string registerRaw(const std::string& ext, const std::string& ip)
	{
		return "REGISTER sip:10.51.15.1 SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bK515age" + ext + "\r\n"
			"From: <sip:" + ext + "@10.51.15.1>;tag=t" + ext + "\r\n"
			"To: <sip:" + ext + "@10.51.15.1>\r\n"
			"Call-ID: lockage515-" + ext + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + ip + ":5060>;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
	}

	class LearnLockMinAge : public ::testing::Test
	{
	protected:
		void TearDown() override { ArpLookup::clearMockMacs(); }

		// Device n: source 10.51.15.n, MAC 02:00:00:00:15:n.
		static ArpLookup::Mac macOf(int n) { return {0x02, 0x00, 0x00, 0x00, 0x15, static_cast<uint8_t>(n)}; }
		static std::string hexOf(int n) { return ArpLookup::toHex12(macOf(n)); }

		Decision admit(int device, const std::string& ext, Clock::time_point at)
		{
			const sockaddr_in src = FakePbxEnv::addr(ipFor(device).c_str(), 5060);
			ArpLookup::setMockMac(src, macOf(device));
			std::string reason;
			return _reg.admitLearn(std::make_shared<SipMessage>(registerRaw(ext, ipFor(device)), src), ext, reason, at);
		}

		// -1: not adopted; 0: adopted, unlocked; 1: locked.
		int lockState(int device) const
		{
			for (const auto& d : _reg.adoptedDevices())
				if (d.mac == hexOf(device)) return d.locked ? 1 : 0;
			return -1;
		}

		FakePbxEnv _env;
		Registrar _reg{_env, Registrar::Mode::Learn};
		const Clock::time_point t0{};
	};
}

TEST_F(LearnLockMinAge, ASecondRegisterTenSecondsInIsAdmittedButDoesNotLock)
{
	// Threat: two quick REGISTERs from one fake MAC lock the extension.
	ASSERT_EQ(admit(1, "5301", t0), Decision::Accept);
	EXPECT_EQ(admit(1, "5301", t0 + seconds(10)), Decision::Accept) << "a young sighting is still TOFU";
	EXPECT_EQ(lockState(1), 0) << "a sighting 10 s after the first must not lock";

	EXPECT_EQ(admit(2, "5301", t0 + seconds(11)), Decision::Accept)
		<< "the extension is not locked, so another device is admitted as TOFU";
	EXPECT_EQ(lockState(2), 0);
}

TEST_F(LearnLockMinAge, TheFirstSightingThirtySecondsLaterLocksAndAYoungOneDoesNotRestartTheAge)
{
	ASSERT_EQ(admit(1, "5301", t0), Decision::Accept);
	ASSERT_EQ(admit(1, "5301", t0 + seconds(10)), Decision::Accept);
	ASSERT_EQ(lockState(1), 0);

	// 31 s after the first sighting but only 21 s after the young one: it locks
	// only if the young sighting left the first-sighting time alone.
	EXPECT_EQ(admit(1, "5301", t0 + seconds(31)), Decision::Accept);
	EXPECT_EQ(lockState(1), 1) << "the phone's refresh, 31 s after its first REGISTER, locks";

	EXPECT_EQ(admit(2, "5301", t0 + seconds(32)), Decision::Reject) << "and the lock holds against another device";
	EXPECT_EQ(lockState(2), -1);
}

TEST_F(LearnLockMinAge, TheMinimumAgeIsThirtySecondsInclusive)
{
	ASSERT_EQ(admit(1, "5301", t0), Decision::Accept);
	EXPECT_EQ(admit(1, "5301", t0 + seconds(30) - milliseconds(1)), Decision::Accept);
	EXPECT_EQ(lockState(1), 0) << "1 ms short of 30 s is too young";
	EXPECT_EQ(admit(1, "5301", t0 + seconds(30)), Decision::Accept);
	EXPECT_EQ(lockState(1), 1) << "30 s after the first sighting is old enough";
}

TEST_F(LearnLockMinAge, ABurstOfMacsRegisteringTwiceWithinASecondLocksNone)
{
	// Threat: a host answering ARP for many fake MACs squats one extension per
	// MAC with two REGISTERs each. Past kAdoptBurst new MACs the adoption bucket
	// answers 503 (LearnAdoptionLimit_test), so every MAC here is adopted and the
	// burst is refused its locks by the age alone.
	const int n = Registrar::kAdoptBurst;
	for (int i = 1; i <= n; ++i)
		ASSERT_EQ(admit(i, std::to_string(5310 + i), t0 + milliseconds(i)), Decision::Accept) << "device " << i;
	for (int i = 1; i <= n; ++i)
		EXPECT_EQ(admit(i, std::to_string(5310 + i), t0 + milliseconds(500 + i)), Decision::Accept) << "device " << i;
	for (int i = 1; i <= n; ++i)
		EXPECT_EQ(lockState(i), 0) << "device " << i << " locked its extension inside one second";

	// Positive control: the same devices lock once they are old enough, so
	// nothing else above kept them unlocked.
	for (int i = 1; i <= n; ++i)
	{
		EXPECT_EQ(admit(i, std::to_string(5310 + i), t0 + seconds(31)), Decision::Accept) << "device " << i;
		EXPECT_EQ(lockState(i), 1) << "device " << i;
	}
}

TEST_F(LearnLockMinAge, ARowLoadedFromNvsLocksAtItsFirstSightingAfterBoot)
{
	// No behaviour change for a board that already adopted its phones. A row from
	// NVS has no first-sighting time (it is not persisted), so it counts as old
	// enough. loadDevices() is ESP-only; adoptDeviceForTest() builds the row the
	// same way (an unlocked record with no first-sighting time).
	_reg.adoptDeviceForTest(hexOf(1), "5301");
	ASSERT_EQ(lockState(1), 0);

	EXPECT_EQ(admit(1, "5301", t0), Decision::Accept);
	EXPECT_EQ(lockState(1), 1) << "an upgraded board's phone locks at its next REGISTER, as before";
	EXPECT_EQ(admit(2, "5301", t0 + seconds(1)), Decision::Reject);
}

TEST_F(LearnLockMinAge, AReExtensionedRecordDoesNotLockItsNewExtensionEarly)
{
	// Guard. A record whose extension changes restarts its age, so its old age
	// cannot lock the new extension. Today the shared-MAC rule also keeps it
	// unlocked (one MAC, two extensions), so this passes either way; it fails if
	// the shared rule ever lets such a record lock without the age restarting.
	ASSERT_EQ(admit(1, "5301", t0), Decision::Accept);
	ASSERT_EQ(admit(1, "5302", t0 + seconds(40)), Decision::Accept);
	EXPECT_EQ(admit(1, "5302", t0 + seconds(41)), Decision::Accept);
	EXPECT_EQ(lockState(1), 0) << "41 s after its first REGISTER, 1 s after its new extension";
	EXPECT_EQ(admit(2, "5302", t0 + seconds(42)), Decision::Accept) << "the new extension is not locked";
}

TEST_F(LearnLockMinAge, AnOldEnoughLaterClaimNeverLocksWhileTheFirstClaimIsYoung)
{
	// First claim wins (#487 review) also inside the age window: the first
	// claimant is too young to lock, and a later claimant that is old enough
	// must not use that window to take the extension.
	ASSERT_EQ(admit(1, "5301", t0), Decision::Accept);                  // the phone claims 5301
	ASSERT_EQ(admit(2, "5301", t0 + seconds(1)), Decision::Accept);     // a later claim, TOFU
	ASSERT_EQ(admit(1, "5301", t0 + seconds(5)), Decision::Accept);
	ASSERT_EQ(lockState(1), 0) << "too young to lock";

	EXPECT_EQ(admit(2, "5301", t0 + seconds(35)), Decision::Accept);
	EXPECT_EQ(lockState(2), 0) << "an earlier-adopted row holds 5301: the later claim must not lock it";

	EXPECT_EQ(admit(1, "5301", t0 + seconds(36)), Decision::Accept);
	EXPECT_EQ(lockState(1), 1) << "the first claim locks once it is old enough";
	EXPECT_EQ(admit(2, "5301", t0 + seconds(37)), Decision::Reject);
}
