// Issue #986 slice 4 (Rule 5): the web login hashes with AdminAuth's mutex released.
//
// The web login (authenticate / verifyCredential) ran its 50000 software SHA-256 rounds
// (2.9 s on the S3) under AdminAuth's mutex. The SIP/tick task takes that same mutex inside
// RequestsHandler::_mutex (beginDtmfPinVerify, finishDtmfPinVerify), so a dashboard login
// that overlapped a DTMF admin entry stalled it, and with it every 911 INVITE, for as long
// as the hash took. The login now copies what it needs under the mutex, hashes with nothing
// of AdminAuth's held, then takes the mutex again to compare and account. Hashes still run
// one at a time (a second mutex, taken only by hashers), so three http_conn threads do not
// become three hashes at once.
//
// The tests park a hash with the host-only hook (AdminAuth::setHashHookForTest). Everything
// that can wait on a parked hash runs on a fixture-owned thread with a bounded wait, so a
// regression fails a test and does not hang the suite.
//
//   AdminLoginUnlocked   the SIP side does not wait behind a hash; hashes are one at a time;
//                        the hash still always runs; what happens when the credential or the
//                        lockout changes while a hash runs; the accounting stays honest.
//   AdminLoginHash       the digest is the one python hashlib computes.

#include <gtest/gtest.h>

#include <chrono>
#include <condition_variable>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "AdminAuth.hpp"
#include "ResetGuard.hpp"

namespace
{
	using std::chrono::milliseconds;
	using AdminAuth::HashPhase;
	using AdminAuth::Role;

	constexpr const char* kUser = "alice";
	constexpr const char* kPass = "correct-horse-1";
	constexpr const char* kNewPass = "replaced-pass-9";
	constexpr const char* kWrong = "wrong-pass-000";
	constexpr const char* kOwner = "olivia";
	constexpr const char* kOwnerPass = "owner-pass-77";
	constexpr const char* kOwnerNewPass = "owner-new-pass-8";
	constexpr const char* kPin = "4321";
	constexpr const char* kIp = "10.0.0.1";

	// Computed independently of this code base (python3 hashlib): round 0 is SHA-256(salt || secret),
	// then 49999 times SHA-256(salt || digest), salt being the ASCII hex text. The second secret
	// makes round 0 60 bytes, past the 55-byte padding limit, so it takes two blocks.
	constexpr const char* kKatSalt = "000102030405060708090a0b0c0d0e0f";
	constexpr const char* kKatHash4321 = "2c3453e4deb24e717c8ed61e1b9203c7dcc53007db7f0bf02f226dea38b68084";
	constexpr const char* kKatSecretLong = "correct-horse-battery-staple";
	constexpr const char* kKatHashLong = "58ed268c4af412d759f7b1c96b8d6d330bdf0446b4b5e8d083ce23ae0b03fd10";

	// The hash hook: counts both phases and parks one hash on request.
	struct Probe
	{
		std::mutex m;
		std::condition_variable cv;
		HashPhase parkAt = HashPhase::Running;
		bool armed = false;      // park the next hash that reaches parkAt
		bool parked = false;     // one is parked now
		bool released = false;
		int queued = 0;
		int running = 0;
	};
	Probe g_probe;

	void probeHook(HashPhase phase)
	{
		std::unique_lock<std::mutex> lk(g_probe.m);
		++(phase == HashPhase::Queued ? g_probe.queued : g_probe.running);
		g_probe.cv.notify_all();
		if (g_probe.armed && phase == g_probe.parkAt)
		{
			g_probe.armed = false;
			g_probe.parked = true;
			g_probe.cv.notify_all();
			g_probe.cv.wait(lk, [] { return g_probe.released; });
		}
	}

	// A DTMF admin entry as the SIP/tick task makes it: begin and finish under _mutex, the hash
	// in between on the worker. True when the right PIN was accepted.
	bool dtmfEntry()
	{
		AdminAuth::DtmfPinTicket t;
		if (!AdminAuth::beginDtmfPinVerify(t)) return false;
		return AdminAuth::finishDtmfPinVerify(t, AdminAuth::matchesDtmfPin(t, kPin, nullptr));
	}

	class AdminLoginUnlocked : public ::testing::Test
	{
	protected:
		void SetUp() override
		{
			resetguard::resetForTest();   // a factory-reset test elsewhere leaves the guard up on host
			AdminAuth::clearCredential();
			ASSERT_TRUE(AdminAuth::setLoginCredential(kUser, kPass));
			ASSERT_TRUE(AdminAuth::setDtmfPin(kPin));
			{
				std::lock_guard<std::mutex> lk(g_probe.m);
				g_probe.armed = g_probe.parked = g_probe.released = false;
				g_probe.queued = g_probe.running = 0;
			}
			AdminAuth::setHashHookForTest(probeHook);
		}

		void TearDown() override
		{
			release();
			for (auto& t : _threads) t.join();
			AdminAuth::setHashHookForTest(nullptr);
			AdminAuth::clearCredential();
			resetguard::resetForTest();   // never leave the guard begun for the next test
		}

		// Park the next hash that reaches `phase`, until release().
		void parkNext(HashPhase phase)
		{
			std::lock_guard<std::mutex> lk(g_probe.m);
			g_probe.parkAt = phase;
			g_probe.armed = true;
			g_probe.parked = false;
			g_probe.released = false;
		}
		bool waitParked()
		{
			std::unique_lock<std::mutex> lk(g_probe.m);
			return g_probe.cv.wait_for(lk, milliseconds(10000), [] { return g_probe.parked; });
		}
		void release()
		{
			std::lock_guard<std::mutex> lk(g_probe.m);
			g_probe.released = true;
			g_probe.cv.notify_all();
		}
		int queued() { std::lock_guard<std::mutex> lk(g_probe.m); return g_probe.queued; }
		int running() { std::lock_guard<std::mutex> lk(g_probe.m); return g_probe.running; }

		// `f` on its own thread. Under the old locking a call made while a hash is parked
		// blocks, and a blocked test thread would hang the suite instead of failing the test.
		// The thread is joined in TearDown, after release().
		template <class F>
		auto bg(F f) -> std::shared_future<decltype(f())>
		{
			using R = decltype(f());
			auto p = std::make_shared<std::promise<R>>();
			std::shared_future<R> fut = p->get_future().share();
			_threads.emplace_back([p, f]() mutable { p->set_value(f()); });
			return fut;
		}
		template <class R>
		static bool done(const std::shared_future<R>& f, int ms = 5000)
		{
			return f.wait_for(milliseconds(ms)) == std::future_status::ready;
		}

		// begin/finish of a DTMF entry must complete while `op` is parked inside its hash.
		template <class F, class R>
		void expectDtmfNotBlockedBy(F op, R expected)
		{
			parkNext(HashPhase::Running);
			auto a = bg(op);
			ASSERT_TRUE(waitParked()) << "the operation never reached its hash";
			auto b = bg([] { return dtmfEntry(); });
			const bool prompt = done(b);
			EXPECT_TRUE(prompt) << "beginDtmfPinVerify/finishDtmfPinVerify waited behind a web-side hash: "
				"the SIP/tick task holds RequestsHandler::_mutex while it waits";
			EXPECT_FALSE(done(a, 0)) << "the operation finished while its hash was parked";
			if (prompt) EXPECT_TRUE(b.get()) << "the right PIN is accepted";
			release();
			ASSERT_TRUE(done(a)) << "the operation never finished after the release";
			EXPECT_TRUE(a.get() == expected);
		}

		// `login(password, clientKey)` is accepted. `locked(clientKey)` is that client's cooldown.
		// A login whose stored password was replaced while it hashed the old one: refused, even
		// with the old password, and the new password then works.
		template <class Login>
		void expectReplacedMidHashIsRefused(Login login)
		{
			parkNext(HashPhase::Queued);
			auto a = bg([login] { return login(kPass, kIp); });
			ASSERT_TRUE(waitParked());
			auto b = bg([] { return AdminAuth::setLoginCredential(kUser, kNewPass); });
			EXPECT_TRUE(done(b)) << "a credential change waited behind a login's hash";
			release();
			ASSERT_TRUE(done(a));
			ASSERT_TRUE(done(b));
			EXPECT_TRUE(b.get());
			EXPECT_FALSE(a.get()) << "the OLD password must not open a session once it was replaced";
			EXPECT_TRUE(login(kNewPass, "10.0.0.9")) << "and the new one does";
		}

		// The same, with a wrong password: a miss against a credential that no longer exists
		// is not an attempt. Four more misses then do not lock the client; if the stale one
		// had been counted, the fourth would be the fifth.
		template <class Login, class Locked>
		void expectReplacedMidHashCountsNothing(Login login, Locked locked)
		{
			parkNext(HashPhase::Queued);
			auto a = bg([login] { return login(kWrong, kIp); });
			ASSERT_TRUE(waitParked());
			auto b = bg([] { return AdminAuth::setLoginCredential(kUser, kNewPass); });
			EXPECT_TRUE(done(b)) << "a credential change waited behind a login's hash";
			release();
			ASSERT_TRUE(done(a));
			ASSERT_TRUE(done(b));
			EXPECT_TRUE(b.get());
			EXPECT_FALSE(a.get());
			for (int i = 1; i < AdminAuth::kMaxFailedAttempts; ++i)
			{
				EXPECT_FALSE(login(kWrong, kIp));
				EXPECT_FALSE(locked(kIp)) << "locked after " << i << " counted misses: the stale one was counted";
			}
			EXPECT_TRUE(login(kNewPass, kIp));
		}

		// A credential wiped (factory reset) while a login hashed it: refused.
		template <class Login>
		void expectClearedMidHashIsRefused(Login login)
		{
			parkNext(HashPhase::Queued);
			auto a = bg([login] { return login(kPass, kIp); });
			ASSERT_TRUE(waitParked());
			auto b = bg([] { AdminAuth::clearCredential(); return true; });
			EXPECT_TRUE(done(b)) << "a factory reset waited behind a login's hash";
			release();
			ASSERT_TRUE(done(a));
			ASSERT_TRUE(done(b));
			EXPECT_FALSE(a.get()) << "a credential that no longer exists must not open a session";
			EXPECT_TRUE(AdminAuth::needsInitialSetup());
		}

		// A miss from client 0 is counted against client 0 even if its bucket was recycled
		// while it hashed (eight other clients fill the 8-slot table meanwhile). It must not be
		// written into the slot that used to be its own, which another client owns now.
		template <class Login, class Locked>
		void expectRecycledBucketIsNotMiscounted(Login login, Locked locked)
		{
			parkNext(HashPhase::Queued);
			auto a = bg([login] { return login(kWrong, "10.0.1.0"); });
			ASSERT_TRUE(waitParked());
			auto b = bg([login] {
				for (int i = 1; i <= static_cast<int>(AdminAuth::kMaxAttemptBuckets); ++i)
				{
					(void)login(kWrong, "10.0.1." + std::to_string(i));
				}
				return true;
			});
			ASSERT_TRUE(done(b, 20000)) << "eight other clients waited behind a login's hash";
			release();
			ASSERT_TRUE(done(a));
			EXPECT_FALSE(a.get());
			// The last of the eight took the slot that was client 0's. It has one miss of its own;
			// three more are four, and not yet a lockout. A miss of client 0's written into that
			// slot would make it five.
			const std::string last = "10.0.1." + std::to_string(AdminAuth::kMaxAttemptBuckets);
			for (int i = 0; i < AdminAuth::kMaxFailedAttempts - 2; ++i) EXPECT_FALSE(login(kWrong, last));
			EXPECT_FALSE(locked(last)) << "client 0's miss was charged to another client's bucket";
		}

		// `setter` hashes, parked in the hook; a factory reset begins (either door's first step,
		// resetguard::begin(), which takes no lock); the setter is released. Returns its result.
		template <class Setter>
		bool runSetterAcrossAReset(Setter setter, bool resetBegins)
		{
			parkNext(HashPhase::Running);
			auto a = bg(setter);
			if (!waitParked()) { ADD_FAILURE() << "the setter never reached its hash"; return false; }
			if (resetBegins) resetguard::begin();
			release();
			if (!done(a)) { ADD_FAILURE() << "the setter never finished after the release"; return false; }
			return a.get();
		}
	private:
		std::vector<std::thread> _threads;
	};

	bool authSysop(const char* pw, const std::string& ip) { return AdminAuth::authenticate(kUser, pw, ip) == Role::Sysop; }
	bool verifySysop(const char* pw, const std::string& ip) { return AdminAuth::verifyCredential(kUser, pw, ip); }
	bool authLocked(const std::string& ip) { return AdminAuth::isLockedOutForAuth(kUser, ip); }
	bool verifyLocked(const std::string& ip) { return AdminAuth::isLockedOut(ip); }
}

// ── The SIP side does not wait behind a web-side hash ────────────────────────

TEST_F(AdminLoginUnlocked, ADtmfEntryDoesNotWaitBehindAnAuthenticateHash)
{
	expectDtmfNotBlockedBy([] { return AdminAuth::authenticate(kUser, kPass, kIp); }, Role::Sysop);
}

TEST_F(AdminLoginUnlocked, ADtmfEntryDoesNotWaitBehindAVerifyCredentialHash)
{
	expectDtmfNotBlockedBy([] { return AdminAuth::verifyCredential(kUser, kPass, kIp); }, true);
}

TEST_F(AdminLoginUnlocked, ADtmfEntryDoesNotWaitBehindASetLoginCredentialHash)
{
	expectDtmfNotBlockedBy([] { return AdminAuth::setLoginCredential(kUser, kNewPass); }, true);
}

TEST_F(AdminLoginUnlocked, ADtmfEntryDoesNotWaitBehindASetOwnerCredentialHash)
{
	expectDtmfNotBlockedBy([] { return AdminAuth::setOwnerCredential(kOwner, kOwnerPass); }, true);
}

TEST_F(AdminLoginUnlocked, ADtmfEntryDoesNotWaitBehindASetDtmfPinHash)
{
	expectDtmfNotBlockedBy([] { return AdminAuth::setDtmfPin("9876"); }, true);
}

// ── Hashes still run one at a time ───────────────────────────────────────────

TEST_F(AdminLoginUnlocked, TwoLoginsAreHashedOneAtATime)
{
	parkNext(HashPhase::Running);
	auto a = bg([] { return AdminAuth::authenticate(kUser, kPass, "10.0.0.1"); });
	ASSERT_TRUE(waitParked());
	auto b = bg([] { return AdminAuth::authenticate(kUser, kPass, "10.0.0.2"); });

	std::this_thread::sleep_for(milliseconds(300));
	EXPECT_EQ(running(), 1) << "a second hash started while the first was parked: three connections would be three hashes";
	release();
	ASSERT_TRUE(done(a));
	ASSERT_TRUE(done(b));
	EXPECT_TRUE(a.get() == Role::Sysop);
	EXPECT_TRUE(b.get() == Role::Sysop) << "the second login waits its turn and then succeeds";
	EXPECT_EQ(running(), 2);
}

TEST_F(AdminLoginUnlocked, ALoginAndACredentialSetAreHashedOneAtATime)
{
	parkNext(HashPhase::Running);
	auto a = bg([] { return AdminAuth::authenticate(kUser, kPass, kIp); });
	ASSERT_TRUE(waitParked());
	auto b = bg([] { return AdminAuth::setDtmfPin("9876"); });

	std::this_thread::sleep_for(milliseconds(300));
	EXPECT_EQ(running(), 1) << "a credential set hashed beside a login";
	release();
	ASSERT_TRUE(done(a));
	ASSERT_TRUE(done(b));
	EXPECT_TRUE(a.get() == Role::Sysop);
	EXPECT_TRUE(b.get());
	EXPECT_EQ(running(), 2);
}

// ── The hash still always runs ───────────────────────────────────────────────

TEST_F(AdminLoginUnlocked, AWrongUsernameStillCostsAHashInAuthenticate)
{
	EXPECT_TRUE(AdminAuth::authenticate("mallory", kPass, kIp) == Role::None);
	EXPECT_EQ(running(), 1) << "a wrong username must cost the same wall-clock as a wrong password";
	EXPECT_TRUE(AdminAuth::authenticate(kUser, kWrong, kIp) == Role::None);
	EXPECT_EQ(running(), 2);
}

TEST_F(AdminLoginUnlocked, AWrongUsernameStillCostsAHashInVerifyCredential)
{
	EXPECT_FALSE(AdminAuth::verifyCredential("mallory", kPass, kIp));
	EXPECT_EQ(running(), 1);
	EXPECT_FALSE(AdminAuth::verifyCredential(kUser, kWrong, kIp));
	EXPECT_EQ(running(), 2);
}

TEST_F(AdminLoginUnlocked, TheOwnerPathHashesToo)
{
	ASSERT_TRUE(AdminAuth::setOwnerCredential(kOwner, kOwnerPass));
	const int before = running();
	EXPECT_TRUE(AdminAuth::authenticate(kOwner, kWrong, kIp) == Role::None);
	EXPECT_EQ(running(), before + 1);
	EXPECT_TRUE(AdminAuth::authenticate(kOwner, kOwnerPass, kIp) == Role::Owner);
	EXPECT_EQ(running(), before + 2);
}

TEST_F(AdminLoginUnlocked, ALockedOutClientIsRefusedBeforeAnyHash)
{
	for (int i = 0; i < AdminAuth::kMaxFailedAttempts; ++i)
	{
		EXPECT_FALSE(authSysop(kWrong, kIp));
		EXPECT_FALSE(verifySysop(kWrong, "10.0.0.2"));
	}
	ASSERT_TRUE(authLocked(kIp));
	ASSERT_TRUE(verifyLocked("10.0.0.2"));
	const int hashed = running();
	EXPECT_EQ(hashed, 2 * AdminAuth::kMaxFailedAttempts);

	EXPECT_FALSE(authSysop(kPass, kIp)) << "locked out: even the right password is refused";
	EXPECT_FALSE(verifySysop(kPass, "10.0.0.2"));
	EXPECT_EQ(running(), hashed) << "and it is refused before any hashing";
	EXPECT_TRUE(authLocked(kIp));
	EXPECT_TRUE(verifyLocked("10.0.0.2"));
}

TEST_F(AdminLoginUnlocked, TheDefaultCredentialNeedsNoHashAndNoTurn)
{
	AdminAuth::clearCredential();
	EXPECT_TRUE(AdminAuth::authenticate("admin", "admin", kIp) == Role::Sysop);
	EXPECT_TRUE(AdminAuth::verifyCredential("admin", "admin", "10.0.0.2"));
	EXPECT_FALSE(AdminAuth::verifyCredential("admin", "nope", "10.0.0.3"));
	EXPECT_EQ(running(), 0);
	EXPECT_EQ(queued(), 0);
}

// ── The credential changes while the hash runs ───────────────────────────────

TEST_F(AdminLoginUnlocked, AnAuthenticateWhoseCredentialWasReplacedMidHashIsRefusedEvenWithTheOldPassword)
{
	expectReplacedMidHashIsRefused(authSysop);
}

TEST_F(AdminLoginUnlocked, AVerifyCredentialWhoseCredentialWasReplacedMidHashIsRefusedEvenWithTheOldPassword)
{
	expectReplacedMidHashIsRefused(verifySysop);
}

TEST_F(AdminLoginUnlocked, AnAuthenticateMissAgainstAReplacedCredentialCountsNothing)
{
	expectReplacedMidHashCountsNothing(authSysop, authLocked);
}

TEST_F(AdminLoginUnlocked, AVerifyCredentialMissAgainstAReplacedCredentialCountsNothing)
{
	expectReplacedMidHashCountsNothing(verifySysop, verifyLocked);
}

TEST_F(AdminLoginUnlocked, AnAuthenticateWhoseCredentialWasClearedMidHashIsRefused)
{
	expectClearedMidHashIsRefused(authSysop);
}

TEST_F(AdminLoginUnlocked, AVerifyCredentialWhoseCredentialWasClearedMidHashIsRefused)
{
	expectClearedMidHashIsRefused(verifySysop);
}

TEST_F(AdminLoginUnlocked, AnOwnerLoginWhoseCredentialWasReplacedMidHashIsRefused)
{
	ASSERT_TRUE(AdminAuth::setOwnerCredential(kOwner, kOwnerPass));
	parkNext(HashPhase::Queued);
	auto a = bg([] { return AdminAuth::authenticate(kOwner, kOwnerPass, kIp); });
	ASSERT_TRUE(waitParked());
	auto b = bg([] { return AdminAuth::setOwnerCredential(kOwner, kOwnerNewPass); });
	EXPECT_TRUE(done(b)) << "an owner credential change waited behind a login's hash";
	release();
	ASSERT_TRUE(done(a));
	ASSERT_TRUE(done(b));
	EXPECT_TRUE(b.get());
	EXPECT_TRUE(a.get() == Role::None) << "the old owner password must not open a session once it was replaced";
	EXPECT_TRUE(AdminAuth::authenticate(kOwner, kOwnerNewPass, kIp) == Role::Owner);
	EXPECT_TRUE(AdminAuth::authenticate(kUser, kPass, kIp) == Role::Sysop) << "the sysop credential was not touched";
}

// ── The lockout engages while the hash runs ──────────────────────────────────

TEST_F(AdminLoginUnlocked, ALockoutThatEngagesWhileAnAuthenticateHashesDiscardsAMatchAndKeepsTheLockout)
{
	parkNext(HashPhase::Queued);
	auto a = bg([] { return AdminAuth::authenticate(kUser, kPass, kIp); });
	ASSERT_TRUE(waitParked());
	auto b = bg([] {
		for (int i = 0; i < AdminAuth::kMaxFailedAttempts; ++i) (void)AdminAuth::authenticate(kUser, kWrong, kIp);
		return AdminAuth::isLockedOutForAuth(kUser, kIp);
	});
	ASSERT_TRUE(done(b, 10000)) << "failed logins waited behind another login's hash";
	EXPECT_TRUE(b.get());
	release();
	ASSERT_TRUE(done(a));
	EXPECT_TRUE(a.get() == Role::None) << "no success is accepted while locked out";
	EXPECT_TRUE(authLocked(kIp)) << "and it must not clear the lockout";
}

TEST_F(AdminLoginUnlocked, ABackstopThatTripsWhileAnAuthenticateHashesDiscardsAMatch)
{
	parkNext(HashPhase::Queued);
	auto a = bg([] { return AdminAuth::authenticate(kUser, kPass, "10.0.9.99"); });
	ASSERT_TRUE(waitParked());
	// Twenty clients, one miss each: no bucket locks, but the sysop aggregate backstop does.
	auto b = bg([] {
		for (int i = 0; i < AdminAuth::kMaxFailedAttemptsGlobal; ++i)
		{
			(void)AdminAuth::authenticate(kUser, kWrong, "10.0.8." + std::to_string(i));
		}
		return AdminAuth::isLockedOutForAuth(kUser, "10.0.9.99");
	});
	ASSERT_TRUE(done(b, 20000)) << "failed logins waited behind another login's hash";
	EXPECT_TRUE(b.get()) << "the backstop is engaged for a client with no failures of its own";
	release();
	ASSERT_TRUE(done(a));
	EXPECT_TRUE(a.get() == Role::None) << "no success is accepted while the aggregate backstop is engaged";
	EXPECT_TRUE(authLocked("10.0.9.99"));
}

TEST_F(AdminLoginUnlocked, ADtmfLockoutThatEngagesWhileAVerifyCredentialHashesDiscardsTheMatch)
{
	// "" is the key the DTMF PIN accounts against: web logins with no peer share its bucket.
	parkNext(HashPhase::Queued);
	auto a = bg([] { return AdminAuth::verifyCredential(kUser, kPass, ""); });
	ASSERT_TRUE(waitParked());
	auto b = bg([] {
		for (int i = 0; i < AdminAuth::kMaxFailedAttempts; ++i)
		{
			AdminAuth::DtmfPinTicket t;
			if (AdminAuth::beginDtmfPinVerify(t)) (void)AdminAuth::finishDtmfPinVerify(t, false);
		}
		return AdminAuth::isLockedOut();
	});
	ASSERT_TRUE(done(b)) << "DTMF attempts waited behind a web login's hash";
	EXPECT_TRUE(b.get());
	release();
	ASSERT_TRUE(done(a));
	EXPECT_FALSE(a.get()) << "the shared bucket is locked: the match is discarded";
	EXPECT_TRUE(AdminAuth::isLockedOut()) << "and it must not clear the lockout";
}

// ── The accounting after the hash is the accounting of the client that guessed ─

TEST_F(AdminLoginUnlocked, AnAuthenticateMissIsChargedToItsOwnClientEvenIfItsBucketWasRecycledMeanwhile)
{
	expectRecycledBucketIsNotMiscounted(authSysop, authLocked);
}

TEST_F(AdminLoginUnlocked, AVerifyCredentialMissIsChargedToItsOwnClientEvenIfItsBucketWasRecycledMeanwhile)
{
	expectRecycledBucketIsNotMiscounted(verifySysop, verifyLocked);
}

// ── A factory reset begins while a setter hashes ────────────────────────────

TEST_F(AdminLoginUnlocked, ASetLoginCredentialWhoseHashStraddlesAResetRefusesAndChangesNothing)
{
	EXPECT_FALSE(runSetterAcrossAReset([] { return AdminAuth::setLoginCredential(kUser, kNewPass); }, true));
	EXPECT_TRUE(authSysop(kPass, "10.0.0.8")) << "the old password still works: nothing was committed";
	EXPECT_FALSE(authSysop(kNewPass, "10.0.0.8"));
}

TEST_F(AdminLoginUnlocked, ASetOwnerCredentialWhoseHashStraddlesAResetRefusesAndChangesNothing)
{
	EXPECT_FALSE(runSetterAcrossAReset([] { return AdminAuth::setOwnerCredential(kOwner, kOwnerPass); }, true));
	EXPECT_FALSE(AdminAuth::isOwnerProvisioned());
	EXPECT_TRUE(AdminAuth::authenticate(kOwner, kOwnerPass, "10.0.0.8") == Role::None);
}

TEST_F(AdminLoginUnlocked, ASetDtmfPinWhoseHashStraddlesAResetRefusesAndChangesNothing)
{
	EXPECT_FALSE(runSetterAcrossAReset([] { return AdminAuth::setDtmfPin("9876"); }, true));
	EXPECT_TRUE(dtmfEntry()) << "the old PIN still works: nothing was committed";
	AdminAuth::DtmfPinTicket t;
	ASSERT_TRUE(AdminAuth::beginDtmfPinVerify(t));
	EXPECT_FALSE(AdminAuth::matchesDtmfPin(t, "9876", nullptr));
}

TEST_F(AdminLoginUnlocked, WithNoResetTheSameSetLoginCredentialSequenceCommits)
{
	EXPECT_TRUE(runSetterAcrossAReset([] { return AdminAuth::setLoginCredential(kUser, kNewPass); }, false));
	EXPECT_TRUE(authSysop(kNewPass, "10.0.0.8"));
	EXPECT_FALSE(authSysop(kPass, "10.0.0.8"));
}

TEST_F(AdminLoginUnlocked, WithNoResetTheSameSetOwnerCredentialSequenceCommits)
{
	EXPECT_TRUE(runSetterAcrossAReset([] { return AdminAuth::setOwnerCredential(kOwner, kOwnerPass); }, false));
	EXPECT_TRUE(AdminAuth::isOwnerProvisioned());
	EXPECT_TRUE(AdminAuth::authenticate(kOwner, kOwnerPass, "10.0.0.8") == Role::Owner);
}

TEST_F(AdminLoginUnlocked, WithNoResetTheSameSetDtmfPinSequenceCommits)
{
	EXPECT_TRUE(runSetterAcrossAReset([] { return AdminAuth::setDtmfPin("9876"); }, false));
	AdminAuth::DtmfPinTicket t;
	ASSERT_TRUE(AdminAuth::beginDtmfPinVerify(t));
	EXPECT_TRUE(AdminAuth::matchesDtmfPin(t, "9876", nullptr));
	EXPECT_FALSE(AdminAuth::matchesDtmfPin(t, kPin, nullptr));
}

TEST_F(AdminLoginUnlocked, NoSetterCommitsOnceAResetBegan)
{
	resetguard::begin();
	EXPECT_FALSE(AdminAuth::setLoginCredential(kUser, kNewPass));
	EXPECT_FALSE(AdminAuth::setOwnerCredential(kOwner, kOwnerPass));
	EXPECT_FALSE(AdminAuth::setDtmfPin("9876"));
	EXPECT_TRUE(authSysop(kPass, "10.0.0.8"));
	EXPECT_FALSE(AdminAuth::isOwnerProvisioned());
	EXPECT_TRUE(dtmfEntry());
}

// ── The digest ───────────────────────────────────────────────────────────────

TEST(AdminLoginHash, TheLoginHashIsTheOnePythonComputesForTheSameSaltAndSecret)
{
	EXPECT_EQ(AdminAuth::loginHashForTest(kKatSalt, "4321"), kKatHash4321);
	EXPECT_EQ(AdminAuth::loginHashForTest(kKatSalt, kKatSecretLong), kKatHashLong)
		<< "a 60-byte round 0: salt and secret together take two blocks";
	EXPECT_NE(AdminAuth::loginHashForTest(kKatSalt, "4322"), kKatHash4321);
}

TEST(AdminLoginHash, ACredentialStoredByTheSettersIsTheDigestOfItsSaltAndSecret)
{
	AdminAuth::clearCredential();
	ASSERT_TRUE(AdminAuth::setDtmfPin("4321"));
	AdminAuth::DtmfPinTicket t;
	ASSERT_TRUE(AdminAuth::beginDtmfPinVerify(t));
	EXPECT_EQ(AdminAuth::loginHashForTest(t.salt, "4321"), std::string(t.hash))
		<< "the stored hash is the login hash of the stored salt and the secret";
	AdminAuth::clearCredential();
}
