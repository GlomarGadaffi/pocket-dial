// Issue #986 slice 3 (Rule 5): the DTMF admin PIN check leaves the SIP thread.
//
// A completed *PIN#code hashed the PIN with AdminAuth's 50000 software SHA-256
// rounds (2,872 ms on the S3, measured on .244) on the task that drained the digit,
// inside RequestsHandler::_mutex, so a 911 INVITE arriving in that window waited
// 2.9 s. It is now a hand-off: the SIP side copies the entry into one static slot and
// wakes a worker (submit), the worker hashes with no lock held (workOnce), and tick()
// records the attempt and runs the code (applyIfReady).
//
// Three suites:
//   AdminPinHandoff   the policy in AdminPinVerifyLogic.hpp, on fakes: the slot, depth one,
//                     refusal, the result, the apply.
//   AdminAuthSplit    verifyDtmfPin() in its three steps: the same digest, the same
//                     accounting, and what happens when the PIN or the lockout changes
//                     while the hash runs.
//   AdminPinWiring    the real path through RequestsHandler::handle() and tick(): SIP INFO and
//                     RFC 4733 digits in, the worker played by the test (adminpin::workForTest).
//
// The Python pins that the drain never calls the hash, that only the worker does,
// and that the worker reaches no flash API are tests/tools/test_admin_pin_offthread.py.

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "AdminAuth.hpp"
#include "AdminPinTestUtil.hpp"
#include "AdminPinVerify.hpp"
#include "CdrArchive.hpp"
#include "RequestsHandler.hpp"
#include "ResetGuard.hpp"
#include "ResetJournal.hpp"
#include "SipMessage.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

using adminpin_test::settle;
using adminpin_test::startEchoCall;

// ── AdminPinHandoff ──────────────────────────────────────────────────────────

namespace
{
	struct FakeExecutor
	{
		int wakes = 0;
		void wake() { ++wakes; }
	};

	struct HandoffRig
	{
		FakeExecutor ex;
		adminpin::Handoff<FakeExecutor> h{ex};
		int begins = 0;
		bool beginOk = true;

		adminpin::SubmitResult submit(std::string_view pin = "4321", std::string_view callId = "Call-ID: c1",
			std::string_view ext = "1001", std::string_view code = "001", char confirm = 0)
		{
			return h.submit(pin, callId, ext, code, confirm, [this](AdminAuth::DtmfPinTicket& t) {
				++begins;
				std::strcpy(t.salt, "salt");
				std::strcpy(t.hash, "hash");
				return beginOk;
			});
		}
	};
}

TEST(AdminPinHandoff, SubmitCopiesTheEntryIntoTheSlotAndWakesTheWorkerOnce)
{
	HandoffRig r;
	ASSERT_EQ(r.submit("4321", "Call-ID: c1", "1001", "999", '1'), adminpin::SubmitResult::Accepted);
	EXPECT_EQ(r.ex.wakes, 1);
	EXPECT_EQ(r.h.phase(), adminpin::Phase::Running);

	bool seen = false;
	EXPECT_TRUE(r.h.workOnce([&](const adminpin::Job& j) {
		seen = true;
		EXPECT_STREQ(j.pin, "4321");
		EXPECT_STREQ(j.callId, "Call-ID: c1");
		EXPECT_STREQ(j.callerExt, "1001");
		EXPECT_STREQ(j.code, "999");
		EXPECT_EQ(j.confirm, '1');
		EXPECT_STREQ(j.ticket.salt, "salt");
		EXPECT_STREQ(j.ticket.hash, "hash");
		return true;
	}));
	EXPECT_TRUE(seen);
	EXPECT_EQ(r.h.phase(), adminpin::Phase::Done);
}

TEST(AdminPinHandoff, ASecondSubmitWhileRunningOrWaitingIsBusyAndTouchesNothing)
{
	HandoffRig r;
	ASSERT_EQ(r.submit("4321", "Call-ID: first"), adminpin::SubmitResult::Accepted);

	EXPECT_EQ(r.submit("9999", "Call-ID: second"), adminpin::SubmitResult::Busy) << "running";
	EXPECT_EQ(r.begins, 1) << "a refused entry must not even ask AdminAuth, so it cannot count";
	EXPECT_EQ(r.ex.wakes, 1);

	ASSERT_TRUE(r.h.workOnce([](const adminpin::Job& j) {
		EXPECT_STREQ(j.callId, "Call-ID: first") << "the second entry must not overwrite the slot";
		EXPECT_STREQ(j.pin, "4321");
		return true;
	}));
	EXPECT_EQ(r.submit("9999", "Call-ID: second"), adminpin::SubmitResult::Busy) << "result waiting to be applied";
	EXPECT_EQ(r.begins, 1);
	EXPECT_EQ(r.ex.wakes, 1);

	ASSERT_TRUE(r.h.applyIfReady([](const AdminAuth::DtmfPinTicket&, bool m) { return m; }, [](const adminpin::Job&, bool) {}));
	EXPECT_EQ(r.h.phase(), adminpin::Phase::Idle);
	EXPECT_EQ(r.submit("9999", "Call-ID: second"), adminpin::SubmitResult::Accepted) << "free again after the apply";
}

TEST(AdminPinHandoff, ARefusedBeginLeavesTheSlotIdleAndWakesNothing)
{
	HandoffRig r;
	r.beginOk = false;   // no PIN set, or locked out: AdminAuth says no before any hashing
	EXPECT_EQ(r.submit(), adminpin::SubmitResult::Refused);
	EXPECT_EQ(r.h.phase(), adminpin::Phase::Idle);
	EXPECT_EQ(r.ex.wakes, 0);
	r.beginOk = true;
	EXPECT_EQ(r.submit(), adminpin::SubmitResult::Accepted) << "a refusal must not leave the slot claimed";
}

TEST(AdminPinHandoff, TheWorkerHashesAJobOnceAndOnlyWhenOneIsRunning)
{
	HandoffRig r;
	int hashes = 0;
	auto hash = [&](const adminpin::Job&) { ++hashes; return true; };
	EXPECT_FALSE(r.h.workOnce(hash)) << "idle";
	ASSERT_EQ(r.submit(), adminpin::SubmitResult::Accepted);
	EXPECT_TRUE(r.h.workOnce(hash));
	EXPECT_FALSE(r.h.workOnce(hash)) << "done, not applied: no second hash";
	EXPECT_EQ(hashes, 1);
}

TEST(AdminPinHandoff, TheApplyWaitsForTheResultThenAccountsThenRunsThenFreesTheSlot)
{
	HandoffRig r;
	std::vector<std::string> order;
	auto finish = [&](const AdminAuth::DtmfPinTicket& t, bool matched) {
		order.push_back(std::string("finish:") + t.salt + (matched ? ":match" : ":miss"));
		return matched;
	};
	adminpin::Phase seenInRun = adminpin::Phase::Idle;
	auto run = [&](const adminpin::Job& j, bool authenticated) {
		order.push_back(std::string("run:") + j.code + (authenticated ? ":ok" : ":no"));
		seenInRun = r.h.phase();
		EXPECT_EQ(r.submit(), adminpin::SubmitResult::Busy) << "no new entry may start mid-apply";
	};

	EXPECT_FALSE(r.h.applyIfReady(finish, run)) << "idle";
	ASSERT_EQ(r.submit("4321", "Call-ID: c1", "1001", "001"), adminpin::SubmitResult::Accepted);
	EXPECT_FALSE(r.h.applyIfReady(finish, run)) << "running: the result is not in yet";
	EXPECT_TRUE(order.empty());

	ASSERT_TRUE(r.h.workOnce([](const adminpin::Job&) { return true; }));
	EXPECT_TRUE(r.h.applyIfReady(finish, run));
	ASSERT_EQ(order.size(), 2u);
	EXPECT_EQ(order[0], "finish:salt:match") << "the accounting comes first";
	EXPECT_EQ(order[1], "run:001:ok");
	EXPECT_EQ(seenInRun, adminpin::Phase::Done);
	EXPECT_EQ(r.h.phase(), adminpin::Phase::Idle);
	EXPECT_FALSE(r.h.applyIfReady(finish, run)) << "applied once";
}

TEST(AdminPinHandoff, AMissIsAccountedAndReportedUnauthenticated)
{
	HandoffRig r;
	ASSERT_EQ(r.submit(), adminpin::SubmitResult::Accepted);
	ASSERT_TRUE(r.h.workOnce([](const adminpin::Job&) { return false; }));
	bool authenticated = true;
	int accounted = 0;
	ASSERT_TRUE(r.h.applyIfReady(
		[&](const AdminAuth::DtmfPinTicket&, bool matched) { ++accounted; return matched; },
		[&](const adminpin::Job&, bool a) { authenticated = a; }));
	EXPECT_EQ(accounted, 1);
	EXPECT_FALSE(authenticated);
}

TEST(AdminPinHandoff, AnOverlongPinIsCutNotRejectedAndStaysAMismatch)
{
	HandoffRig r;
	const std::string forty(40, '7');
	ASSERT_EQ(r.submit(forty), adminpin::SubmitResult::Accepted);
	ASSERT_TRUE(r.h.workOnce([](const adminpin::Job& j) {
		EXPECT_EQ(std::strlen(j.pin), adminpin::kPinCap - 1);
		EXPECT_GT(adminpin::kPinCap - 1, AdminAuth::kMaxDtmfPinLength)
			<< "longer than any PIN setDtmfPin accepts, so it can never match one";
		return false;
	}));
}

TEST(AdminPinHandoff, AnIdentityThatDoesNotFitIsRefusedBeforeAnythingIsClaimed)
{
	HandoffRig r;
	EXPECT_EQ(r.submit("4321", std::string(adminpin::kCallIdCap, 'c')), adminpin::SubmitResult::TooLong);
	EXPECT_EQ(r.submit("4321", "Call-ID: c1", std::string(adminpin::kExtCap, '1')), adminpin::SubmitResult::TooLong);
	EXPECT_EQ(r.begins, 0);
	EXPECT_EQ(r.ex.wakes, 0);
	EXPECT_EQ(r.h.phase(), adminpin::Phase::Idle);
}

TEST(AdminPinHandoff, TheWorkerWipesThePinOnceItIsHashed)
{
	HandoffRig r;
	ASSERT_EQ(r.submit("4321"), adminpin::SubmitResult::Accepted);
	ASSERT_TRUE(r.h.workOnce([](const adminpin::Job&) { return true; }));
	ASSERT_TRUE(r.h.applyIfReady([](const AdminAuth::DtmfPinTicket&, bool m) { return m; },
		[](const adminpin::Job& j, bool) {
			for (char c : j.pin) EXPECT_EQ(c, 0) << "the candidate PIN must not outlive its hash";
		}));
}

// ── AdminAuthSplit ───────────────────────────────────────────────────────────

namespace
{
	std::atomic<int> g_yields{0};
	void countYield() { ++g_yields; }

	// Computed independently of this code base (python3 hashlib): round 0 is SHA-256(salt || pin),
	// then 49999 times SHA-256(salt || digest), salt being the ASCII hex text.
	constexpr const char* kKatSalt = "000102030405060708090a0b0c0d0e0f";
	constexpr const char* kKatHash4321 = "2c3453e4deb24e717c8ed61e1b9203c7dcc53007db7f0bf02f226dea38b68084";
	constexpr const char* kKatHash10 = "ed35e17f8b9816dfc9052f132b5c610a1760dccf0efc8129908a1fbca6097e24";

	AdminAuth::DtmfPinTicket ticketOf(const char* salt, const char* hash)
	{
		AdminAuth::DtmfPinTicket t{};
		std::strcpy(t.salt, salt);
		std::strcpy(t.hash, hash);
		return t;
	}

	class AdminAuthSplit : public ::testing::Test
	{
	protected:
		void SetUp() override { AdminAuth::clearCredential(); }
		void TearDown() override { AdminAuth::clearCredential(); }

		// One attempt the way the DTMF path makes it: begin, hash, finish.
		bool attempt(const char* pin)
		{
			AdminAuth::DtmfPinTicket t;
			if (!AdminAuth::beginDtmfPinVerify(t)) return false;
			return AdminAuth::finishDtmfPinVerify(t, AdminAuth::matchesDtmfPin(t, pin, nullptr));
		}
	};
}

TEST_F(AdminAuthSplit, TheDigestIsTheOnePythonComputesForTheSameSaltAndPin)
{
	EXPECT_TRUE(AdminAuth::matchesDtmfPin(ticketOf(kKatSalt, kKatHash4321), "4321", nullptr));
	EXPECT_FALSE(AdminAuth::matchesDtmfPin(ticketOf(kKatSalt, kKatHash4321), "4322", nullptr));
	EXPECT_TRUE(AdminAuth::matchesDtmfPin(ticketOf(kKatSalt, kKatHash10), "2468135790", nullptr));
	EXPECT_FALSE(AdminAuth::matchesDtmfPin(ticketOf(kKatSalt, kKatHash10), "4321", nullptr))
		<< "a hash of another PIN under the same salt must not match";
}

TEST_F(AdminAuthSplit, APinStoredByTheUnchangedPathMatchesTheWorkersDigest)
{
	ASSERT_TRUE(AdminAuth::setDtmfPin("4321"));   // stores hashSecret(salt, pin), as it always has
	AdminAuth::DtmfPinTicket t;
	ASSERT_TRUE(AdminAuth::beginDtmfPinVerify(t));
	EXPECT_EQ(std::strlen(t.hash), 64u);
	EXPECT_TRUE(AdminAuth::matchesDtmfPin(t, "4321", nullptr));
	EXPECT_FALSE(AdminAuth::matchesDtmfPin(t, "4320", nullptr));
	EXPECT_FALSE(AdminAuth::matchesDtmfPin(t, "", nullptr));
}

TEST_F(AdminAuthSplit, TheWorkerYieldsEveryKYieldEveryRoundsAndTheDigestIsUnchanged)
{
	g_yields = 0;
	EXPECT_TRUE(AdminAuth::matchesDtmfPin(ticketOf(kKatSalt, kKatHash4321), "4321", countYield));
	// Rounds 1 .. kHashIterations-1 are the loop; it yields on every multiple of the stride.
	EXPECT_EQ(g_yields.load(), static_cast<int>((AdminAuth::kHashIterations - 1) / AdminAuth::kYieldEveryRounds));
	EXPECT_GE(g_yields.load(), 100) << "a 2.9 s hash must give the idle task far more than one chance";
}

TEST_F(AdminAuthSplit, NothingIsHandedOutWhenNoPinIsSet)
{
	AdminAuth::DtmfPinTicket t;
	EXPECT_FALSE(AdminAuth::beginDtmfPinVerify(t));
	EXPECT_FALSE(AdminAuth::verifyDtmfPin("4321"));
}

TEST_F(AdminAuthSplit, FiveMissesLockOutAndALockedOutPinIsRefusedBeforeHashingAndCountsNothing)
{
	ASSERT_TRUE(AdminAuth::setDtmfPin("4321"));
	for (int i = 0; i < AdminAuth::kMaxFailedAttempts - 1; ++i)
	{
		EXPECT_FALSE(attempt("0000"));
		EXPECT_FALSE(AdminAuth::isLockedOut()) << "miss " << (i + 1);
	}
	EXPECT_FALSE(attempt("0000"));
	ASSERT_TRUE(AdminAuth::isLockedOut());

	AdminAuth::DtmfPinTicket t;
	EXPECT_FALSE(AdminAuth::beginDtmfPinVerify(t)) << "locked out: refused before any hashing, even for the right PIN";
	EXPECT_FALSE(attempt("4321"));
	EXPECT_TRUE(AdminAuth::isLockedOut());
}

TEST_F(AdminAuthSplit, VerifyDtmfPinIsTheThreeStepsInARow)
{
	ASSERT_TRUE(AdminAuth::setDtmfPin("4321"));
	EXPECT_TRUE(AdminAuth::verifyDtmfPin("4321"));
	for (int i = 0; i < AdminAuth::kMaxFailedAttempts; ++i)
	{
		EXPECT_FALSE(AdminAuth::isLockedOut());
		EXPECT_FALSE(AdminAuth::verifyDtmfPin("0000"));
	}
	EXPECT_TRUE(AdminAuth::isLockedOut());
	EXPECT_FALSE(AdminAuth::verifyDtmfPin("4321"));
}

TEST_F(AdminAuthSplit, ACorrectPinClearsTheFailuresSoFar)
{
	ASSERT_TRUE(AdminAuth::setDtmfPin("4321"));
	for (int i = 0; i < AdminAuth::kMaxFailedAttempts - 1; ++i) EXPECT_FALSE(attempt("0000"));
	EXPECT_TRUE(attempt("4321"));
	for (int i = 0; i < AdminAuth::kMaxFailedAttempts - 1; ++i) EXPECT_FALSE(attempt("0000"));
	EXPECT_FALSE(AdminAuth::isLockedOut()) << "the success in the middle restarted the count";
}

TEST_F(AdminAuthSplit, AResultForAPinThatWasReplacedMeanwhileAuthenticatesNothingAndCountsNothing)
{
	ASSERT_TRUE(AdminAuth::setDtmfPin("4321"));
	AdminAuth::DtmfPinTicket t;
	ASSERT_TRUE(AdminAuth::beginDtmfPinVerify(t));
	ASSERT_TRUE(AdminAuth::setDtmfPin("8765"));   // the dashboard changes the PIN while the hash runs

	EXPECT_FALSE(AdminAuth::finishDtmfPinVerify(t, /*matched=*/true)) << "the old PIN must not open the menu";
	for (int i = 0; i < AdminAuth::kMaxFailedAttempts; ++i)
	{
		EXPECT_FALSE(AdminAuth::finishDtmfPinVerify(t, /*matched=*/false));
	}
	EXPECT_FALSE(AdminAuth::isLockedOut()) << "a guess against a PIN that no longer exists is not an attempt";
	EXPECT_TRUE(attempt("8765")) << "and the new PIN works";
}

TEST_F(AdminAuthSplit, AResultForAPinThatWasClearedMeanwhileAuthenticatesNothing)
{
	ASSERT_TRUE(AdminAuth::setDtmfPin("4321"));
	AdminAuth::DtmfPinTicket t;
	ASSERT_TRUE(AdminAuth::beginDtmfPinVerify(t));
	AdminAuth::clearCredential();   // a factory reset from the dashboard
	EXPECT_FALSE(AdminAuth::finishDtmfPinVerify(t, true));
}

TEST_F(AdminAuthSplit, ALockoutThatEngagesWhileTheHashRunsDiscardsAMatch)
{
	ASSERT_TRUE(AdminAuth::setDtmfPin("4321"));
	AdminAuth::DtmfPinTicket t;
	ASSERT_TRUE(AdminAuth::beginDtmfPinVerify(t));
	for (int i = 0; i < AdminAuth::kMaxFailedAttempts; ++i) EXPECT_FALSE(AdminAuth::verifyDtmfPin("0000"));
	ASSERT_TRUE(AdminAuth::isLockedOut());

	EXPECT_FALSE(AdminAuth::finishDtmfPinVerify(t, true)) << "no success is accepted while locked out";
	EXPECT_TRUE(AdminAuth::isLockedOut()) << "and it must not clear the lockout";
}

// ── AdminPinWiring ───────────────────────────────────────────────────────────

namespace
{
	constexpr const char* kAdminExt = "1001";
	constexpr const char* kAdminIp = "192.168.9.50";
	constexpr const char* kServerIp = "192.168.9.1";
	constexpr const char* kPin = "445566";
	// Not "11...", "60...", "73...", "69...", "72..." or "80...": *11 *60 *73 *69 *72NNNN *80 are CLASS
	// star codes, which fire as soon as they are typed and clear the sequence, so a PIN that starts with one
	// can never reach the admin menu (found while writing these tests; not changed here).
	constexpr const char* kWrongPin = "778899";
	constexpr const char* kCallId = "pin-986-call";

	// The hasher seam: counts, and (blockingHasher) waits for a release.
	struct Gate
	{
		std::mutex m;
		std::condition_variable cv;
		bool entered = false;
		bool release = false;
	};
	Gate g_gate;
	std::atomic<int> g_hashCalls{0};

	void resetGate()
	{
		std::lock_guard<std::mutex> lk(g_gate.m);
		g_gate.entered = false;
		g_gate.release = false;
		g_hashCalls = 0;
	}

	bool countingHasher(const adminpin::Job& j)
	{
		++g_hashCalls;
		return AdminAuth::matchesDtmfPin(j.ticket, std::string_view(j.pin), nullptr);
	}

	bool blockingHasher(const adminpin::Job& j)
	{
		++g_hashCalls;
		{
			std::unique_lock<std::mutex> lk(g_gate.m);
			g_gate.entered = true;
			g_gate.cv.notify_all();
			g_gate.cv.wait(lk, [] { return g_gate.release; });
		}
		return AdminAuth::matchesDtmfPin(j.ticket, std::string_view(j.pin), nullptr);
	}

	// The worker task, played on a test thread so the hasher can block it.
	class BlockedWorker
	{
	public:
		BlockedWorker() : _t([] { (void)adminpin::workForTest(); }) {}
		~BlockedWorker()
		{
			release();
			if (_t.joinable()) _t.join();
		}
		bool waitEntered()
		{
			std::unique_lock<std::mutex> lk(g_gate.m);
			return g_gate.cv.wait_for(lk, std::chrono::seconds(10), [] { return g_gate.entered; });
		}
		void release()
		{
			std::lock_guard<std::mutex> lk(g_gate.m);
			g_gate.release = true;
			g_gate.cv.notify_all();
		}
		void join() { if (_t.joinable()) _t.join(); }
	private:
		std::thread _t;
	};

	class WipeSpySink : public cdrarchive::Sink
	{
	public:
		int wipes = 0;
		void append(const cdrarchive::QueuedLine&) override {}
		void wipe() override { ++wipes; }
	};

	std::shared_ptr<SipMessage> makeRegisterFor(const std::string& from, const std::string& srcIp,
		const std::string& callId)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(srcIp.c_str());
		s.sin_port = htons(5060);
		std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bKr" + callId + "\r\n"
			"From: <sip:" + from + "@server>;tag=rt" + callId + "\r\n"
			"To: <sip:" + from + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + from + "@" + srcIp + ":5060>;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, s);
	}

	std::shared_ptr<SipMessage> makeInfoDigit(const std::string& from, const std::string& srcIp,
		const std::string& callId, char digit)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(srcIp.c_str());
		s.sin_port = htons(5060);
		std::string body = std::string("Signal=") + digit + "\r\nDuration=100\r\n";
		std::string head =
			"INFO sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bKi\r\n"
			"From: <sip:" + from + "@server>;tag=it\r\n"
			"To: <sip:server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INFO\r\n"
			"Content-Type: application/dtmf-relay\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
		return RequestsHandler::getMessageFromPool(head + body, s);
	}

	std::string entry(const char* pin, const char* code)
	{
		return std::string("*") + pin + "#" + code;
	}

	class AdminPinWiring : public ::testing::Test
	{
	protected:
		void SetUp() override
		{
			AdminAuth::clearCredential();
			ASSERT_TRUE(AdminAuth::setDtmfPin(kPin));
			adminpin::resetForTest();
			resetGate();
			adminpin::setHasherForTest(countingHasher);
			prevSink = cdrarchive::setSinkForTest(&sink);
			handler = std::make_unique<RequestsHandler>(kServerIp, 5060,
				[this](const sockaddr_in&, std::shared_ptr<SipMessage> m) {
					if (!m) return;
					std::lock_guard<std::mutex> lk(sentMutex);
					sent.push_back(m->toString());
				});
			handler->handle(makeRegisterFor(kAdminExt, kAdminIp, "reg-admin-986"));
			startEchoCall(*handler, kAdminExt, kAdminIp, kCallId);
		}
		void TearDown() override
		{
			handler.reset();
			cdrarchive::setSinkForTest(prevSink);
			adminpin::resetForTest();
			AdminAuth::clearCredential();
			resetguard::resetForTest();
			resetjournal::resetForTest();
		}

		// One INFO per digit. Each call comes from its own source address: the engine rate-limits
		// a source to a burst of 40 packets (Issue #38) and a test makes several entries in a
		// moment, which a person at a keypad never does.
		void digits(const std::string& seq, const char* callId = kCallId)
		{
			const std::string ip = "192.168.9." + std::to_string(100 + (ipSeq++ % 100));
			for (char c : seq) handler->handle(makeInfoDigit(kAdminExt, ip, callId, c));
		}
		void tickOnce()
		{
			handler->forceNextTickForTest();
			handler->tick();
		}
		// One whole admin entry: the digits, the worker, the tick.
		void cycle(const char* pin, const char* code, const char* callId = kCallId)
		{
			digits(entry(pin, code), callId);
			settle(*handler);
		}
		size_t sentCount()
		{
			std::lock_guard<std::mutex> lk(sentMutex);
			return sent.size();
		}
		bool sawResponseTo(const std::string& callId, const char* status)
		{
			std::lock_guard<std::mutex> lk(sentMutex);
			for (const auto& s : sent)
			{
				if (s.rfind(status, 0) == 0 && s.find("Call-ID: " + callId) != std::string::npos) return true;
			}
			return false;
		}

		std::unique_ptr<RequestsHandler> handler;
		int ipSeq = 0;
		WipeSpySink sink;
		cdrarchive::Sink* prevSink = nullptr;
		std::mutex sentMutex;
		std::vector<std::string> sent;
	};
}

TEST_F(AdminPinWiring, ACompletedEntryHandsOffAndNeverHashesOnTheThreadThatDrainedTheDigit)
{
	digits(entry(kPin, "200"));

	EXPECT_EQ(g_hashCalls.load(), 0) << "the drain must not hash";
	EXPECT_EQ(adminpin::phaseForTest(), adminpin::Phase::Running) << "the entry is in the slot, waiting for the worker";
	EXPECT_EQ(adminpin::wakesForTest(), 1u);
	EXPECT_FALSE(AdminAuth::isLockedOut());
}

TEST_F(AdminPinWiring, TheSipThreadAnswersWhileTheHashIsStillRunning)
{
	digits(entry(kPin, "200"));
	ASSERT_EQ(adminpin::phaseForTest(), adminpin::Phase::Running);
	adminpin::setHasherForTest(blockingHasher);
	BlockedWorker worker;
	ASSERT_TRUE(worker.waitEntered()) << "the worker never reached the hasher: the hash did not run on the worker";

	// The hash is "running" and will not finish until released. The engine must carry on.
	const size_t before = sentCount();
	handler->handle(makeRegisterFor("1002", "192.168.9.60", "reg-1002-986"));
	EXPECT_TRUE(sawResponseTo("reg-1002-986", "SIP/2.0 200")) << "a REGISTER was not answered while the PIN hash runs";
	EXPECT_GT(sentCount(), before);
	tickOnce();   // a full tick pass too
	digits("5", "other-call");   // and a digit from anywhere else is taken
	EXPECT_EQ(adminpin::phaseForTest(), adminpin::Phase::Running) << "still not applied";

	worker.release();
	worker.join();
	EXPECT_EQ(adminpin::phaseForTest(), adminpin::Phase::Done);
	EXPECT_EQ(g_hashCalls.load(), 1);
}

TEST_F(AdminPinWiring, AWrongPinIsCountedOnTheTickAndNotBefore)
{
	for (int i = 0; i < AdminAuth::kMaxFailedAttempts - 1; ++i)
	{
		cycle(kWrongPin, "200");
		ASSERT_FALSE(AdminAuth::isLockedOut()) << "miss " << (i + 1);
	}
	digits(entry(kWrongPin, "200"));      // the fifth miss ...
	while (adminpin::workForTest()) {}    // ... hashed ...
	EXPECT_FALSE(AdminAuth::isLockedOut()) << "the attempt is recorded on the tick, not by the drain or the worker";
	tickOnce();
	EXPECT_TRUE(AdminAuth::isLockedOut()) << "... and counted on the tick";
}

TEST_F(AdminPinWiring, ACorrectPinRunsTheCodeOnTheTickAndNotBefore)
{
	digits(entry(kPin, "999") + "1");
	EXPECT_EQ(sink.wipes, 0) << "not by the drain";
	while (adminpin::workForTest()) {}
	EXPECT_EQ(sink.wipes, 0) << "not by the worker";
	EXPECT_EQ(adminpin::phaseForTest(), adminpin::Phase::Done);
	tickOnce();
	EXPECT_EQ(sink.wipes, 1) << "the 3-digit code runs on the tick";
	EXPECT_EQ(adminpin::phaseForTest(), adminpin::Phase::Idle);
	tickOnce();
	EXPECT_EQ(sink.wipes, 1) << "and only once";
}

TEST_F(AdminPinWiring, ASecondEntryWhileOneIsInFlightIsRefusedLikeAWrongPinAndNotCounted)
{
	digits(entry(kWrongPin, "200"));     // A, in flight
	ASSERT_EQ(adminpin::phaseForTest(), adminpin::Phase::Running);

	testing::internal::CaptureStderr();
	digits(entry(kWrongPin, "200"));     // B: refused
	digits(entry(kWrongPin, "200"));     // C: refused
	const std::string refusedLog = testing::internal::GetCapturedStderr();
	EXPECT_EQ(adminpin::wakesForTest(), 1u) << "no second job";
	EXPECT_EQ(adminpin::phaseForTest(), adminpin::Phase::Running);

	// The same line a wrong PIN gets once it is applied.
	testing::internal::CaptureStderr();
	settle(*handler);                    // A is applied: one miss
	const std::string wrongLog = testing::internal::GetCapturedStderr();
	ASSERT_NE(wrongLog.find("[admin] DTMF admin auth failed"), std::string::npos) << wrongLog;
	size_t refusals = 0;
	for (size_t p = 0; (p = refusedLog.find("[admin] DTMF admin auth failed", p)) != std::string::npos; ++p) ++refusals;
	EXPECT_EQ(refusals, 2u) << "each refused entry says what a wrong PIN says: " << refusedLog;

	// A counted once, B and C not at all: three more misses make four, one short of the lockout.
	for (int i = 0; i < 3; ++i) cycle(kWrongPin, "200");
	EXPECT_FALSE(AdminAuth::isLockedOut()) << "a refused entry was counted as an attempt";
	cycle(kWrongPin, "200");
	EXPECT_TRUE(AdminAuth::isLockedOut()) << "the fifth counted miss locks out";
}

TEST_F(AdminPinWiring, AnEntryFromAnotherCallWhileOneIsInFlightIsRefusedToo)
{
	startEchoCall(*handler, kAdminExt, kAdminIp, "pin-986-second-call");
	digits(entry(kPin, "999") + "1");
	ASSERT_EQ(adminpin::phaseForTest(), adminpin::Phase::Running);
	digits(entry(kPin, "999") + "1", "pin-986-second-call");
	EXPECT_EQ(adminpin::wakesForTest(), 1u);
	settle(*handler);
	EXPECT_EQ(sink.wipes, 1) << "one entry, one reset";
}

TEST_F(AdminPinWiring, FiveWrongPinsLockOutAsBeforeAndALockedOutCallerIsRefusedBeforeHashing)
{
	for (int i = 0; i < AdminAuth::kMaxFailedAttempts; ++i) cycle(kWrongPin, "200");
	ASSERT_TRUE(AdminAuth::isLockedOut());
	const int hashed = g_hashCalls.load();
	const unsigned wakes = adminpin::wakesForTest();

	testing::internal::CaptureStderr();
	digits(entry(kPin, "999") + "1");    // the right PIN, but locked out
	const std::string log = testing::internal::GetCapturedStderr();
	EXPECT_NE(log.find("[admin] DTMF admin auth failed"), std::string::npos) << log;
	EXPECT_EQ(adminpin::wakesForTest(), wakes) << "refused before any hashing";
	EXPECT_EQ(adminpin::phaseForTest(), adminpin::Phase::Idle) << "and nothing was claimed";
	settle(*handler);
	EXPECT_EQ(g_hashCalls.load(), hashed);
	EXPECT_EQ(sink.wipes, 0);
	EXPECT_TRUE(AdminAuth::isLockedOut());
}

TEST_F(AdminPinWiring, ACallerWhoHungUpBeforeTheResultStillHasAWrongPinCounted)
{
	for (int i = 0; i < AdminAuth::kMaxFailedAttempts - 1; ++i) cycle(kWrongPin, "200");
	ASSERT_FALSE(AdminAuth::isLockedOut());

	digits(entry(kWrongPin, "200"));
	handler->forceDisconnect(kAdminExt);   // the caller hangs up while the hash runs
	ASSERT_FALSE(handler->getSession(std::string("Call-ID: ") + kCallId).has_value());
	settle(*handler);
	EXPECT_TRUE(AdminAuth::isLockedOut())
		<< "dial a wrong PIN, hang up, repeat must not be a way round the lockout";
}

TEST_F(AdminPinWiring, ACorrectPinWhoseCallerHungUpRunsNoCodeButIsAccountedAndSaysSo)
{
	// One miss short of a lockout, so a recorded success is visible afterwards.
	for (int i = 0; i < AdminAuth::kMaxFailedAttempts - 1; ++i) EXPECT_FALSE(AdminAuth::verifyDtmfPin(kWrongPin));

	digits(entry(kPin, "999") + "1");
	handler->forceDisconnect(kAdminExt);
	testing::internal::CaptureStderr();
	settle(*handler);
	const std::string log = testing::internal::GetCapturedStderr();

	EXPECT_EQ(sink.wipes, 0) << "the issuer is gone: a reset must not run";
	EXPECT_FALSE(resetguard::inProgress());
	EXPECT_NE(log.find("DTMF admin command dropped"), std::string::npos) << log;

	// The success was recorded: the failures are back to zero, so four more misses do not lock out.
	for (int i = 0; i < AdminAuth::kMaxFailedAttempts - 1; ++i) EXPECT_FALSE(AdminAuth::verifyDtmfPin(kWrongPin));
	EXPECT_FALSE(AdminAuth::isLockedOut());
}

TEST_F(AdminPinWiring, APinChangedWhileTheHashRunsDoesNotAuthenticateAndItsMissIsNotCounted)
{
	digits(entry(kPin, "999") + "1");              // the old, right PIN
	ASSERT_TRUE(AdminAuth::setDtmfPin("987654"));  // the dashboard replaces it mid-flight
	settle(*handler);
	EXPECT_EQ(sink.wipes, 0) << "the old PIN must not open the menu";

	digits(entry(kWrongPin, "200"));
	ASSERT_TRUE(AdminAuth::setDtmfPin("123123"));
	settle(*handler);
	for (int i = 0; i < AdminAuth::kMaxFailedAttempts - 1; ++i) cycle(kWrongPin, "200");
	EXPECT_FALSE(AdminAuth::isLockedOut()) << "the stale miss was counted";
}

TEST_F(AdminPinWiring, TheFactoryResetPinIsNotCheckedUntilTheConfirmDigitArrives)
{
	// *PIN#999 used to be hashed and then left waiting for the '1'. The '1' arrives within a
	// second or two, while a hash is still running, so the check waits for the whole entry.
	digits(entry(kPin, "999"));
	EXPECT_EQ(adminpin::wakesForTest(), 0u);
	EXPECT_EQ(adminpin::phaseForTest(), adminpin::Phase::Idle);
	digits("1");
	EXPECT_EQ(adminpin::wakesForTest(), 1u);
	settle(*handler);
	EXPECT_EQ(sink.wipes, 1);
}

TEST_F(AdminPinWiring, AnUnknownCodeIsCheckedOnceAndTrailingDigitsStartNothing)
{
	digits(entry(kPin, "123") + "45");
	EXPECT_EQ(adminpin::wakesForTest(), 1u) << "checked once; the digits after it are a new, unfinished sequence";
	settle(*handler);
	EXPECT_EQ(sink.wipes, 0);
	EXPECT_FALSE(AdminAuth::isLockedOut());
}

TEST_F(AdminPinWiring, ARtpDigitReachesTheSameHandoffFromTheTickTask)
{
	for (char c : entry(kPin, "999") + "1") handler->queueDtmfDigit(std::string("Call-ID: ") + kCallId, c);
	tickOnce();   // drainDtmfInbox runs in tick
	EXPECT_EQ(g_hashCalls.load(), 0) << "the tick task must not hash either";
	EXPECT_EQ(adminpin::phaseForTest(), adminpin::Phase::Running);
	EXPECT_EQ(sink.wipes, 0);
	settle(*handler);
	EXPECT_EQ(sink.wipes, 1);
}

TEST_F(AdminPinWiring, ANonAdminCallerNeverReachesTheHandoff)
{
	handler->handle(makeRegisterFor("302", "192.168.9.60", "reg-302-986"));
	startEchoCall(*handler, "302", "192.168.9.60", "pin-986-302");
	for (char c : entry(kPin, "999") + "1")
	{
		handler->handle(makeInfoDigit("302", "192.168.9.60", "pin-986-302", c));
	}
	EXPECT_EQ(adminpin::wakesForTest(), 0u);
	settle(*handler);
	EXPECT_EQ(sink.wipes, 0);
}
