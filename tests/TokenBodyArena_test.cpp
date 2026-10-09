// TokenBodyArena_test.cpp -- the token-body arena and its bounded field scanner (#862).
//
// The contract is the one the operator recorded on #948 for the 911/933 lane:
//   1. a bounded arena, reserved with the client, no per-read std::vector and no spill;
//   2. a body that does not fit, or a read that fails, is an ERROR and the arena then
//      shows no bytes at all -- never a prefix. The caller keeps the token it has;
//   3. no mutex is held across the socket read, and nobody waits for the arena;
//   4. one test per failure branch: arena full, read error, timeout;
//   5. a 911/933 has an arena of its own (telephony::TokenLanes): it never waits on an ordinary
//      fetch, is never turned away by one, and its own failure branches leave nothing behind.
//
// The ESP arm (TelephonyAnchorClient::readJsonStringField / fetchToken) cannot be host
// compiled. These tests drive the host-compiled halves it calls: telephony::BodyArena,
// its Lease::collect(), telephony::TokenLanes and telephony::jsonStringField().

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "AllocCounter.hpp"
#include "TelephonyAnchorLogic.hpp"

namespace
{
	using Arena = telephony::BodyArena<telephony::kTokenBodyBytes>;
	using telephony::BodyStatus;
	constexpr std::size_t kN = telephony::kTokenBodyBytes;

	// A scripted socket. read() answers exactly as esp_http_client_read() does: n > 0 bytes,
	// 0 at the end of the body, a negative code on an error. Like the real call it hands back
	// 0 for a request of 0 bytes, which is why asking for 0 is a test failure here: that answer
	// is indistinguishable from the end of the body.
	class Script
	{
	public:
		Script& bytes(std::string b) { _steps.push_back({std::move(b), 0, false}); return *this; }
		Script& code(int c) { _steps.push_back({std::string(), c, true}); return *this; }
		Script& chunk(std::size_t n) { _chunk = n; return *this; }
		Script& perReadUs(std::int64_t us, std::int64_t* clock) { _perReadUs = us; _clock = clock; return *this; }

		int read(char* dst, std::size_t room)
		{
			EXPECT_GT(room, 0u) << "a read of 0 bytes reads as 'end of body'";
			++_calls;
			if (_clock) *_clock += _perReadUs;
			if (_i >= _steps.size() || room == 0) return 0;
			Step& s = _steps[_i];
			if (s.isCode) { ++_i; return s.code; }
			std::size_t n = s.data.size() - _pos;
			if (n > room) n = room;
			if (n > _chunk) n = _chunk;
			for (std::size_t k = 0; k < n; ++k) dst[k] = s.data[_pos + k];
			_pos += n;
			_consumed += n;
			if (_pos == s.data.size()) { ++_i; _pos = 0; }
			return static_cast<int>(n);
		}

		std::size_t consumed() const { return _consumed; }
		std::size_t calls() const { return _calls; }

	private:
		struct Step { std::string data; int code; bool isCode; };
		std::vector<Step> _steps;
		std::size_t       _i = 0, _pos = 0, _chunk = 512, _consumed = 0, _calls = 0;
		std::int64_t      _perReadUs = 0;
		std::int64_t*     _clock = nullptr;
	};

	BodyStatus run(Arena::Lease& lease, Script& s, std::int64_t& clockUs,
	               std::int64_t budgetUs = telephony::kTokenBodyBudgetUs)
	{
		return lease.collect([&](char* d, std::size_t room) { return s.read(d, room); },
		                     [&] { return clockUs; }, budgetUs);
	}

	std::string_view held(Arena::Lease& lease) { return std::string_view(lease.data(), lease.size()); }

	std::string filler(std::size_t n)
	{
		std::string s;
		for (std::size_t i = 0; i < n; ++i) s.push_back(static_cast<char>('a' + i % 26));
		return s;
	}

	std::string tokenBody(const std::string& token)
	{
		return "{\"token_type\":\"Bearer\",\"expires_in\":60,\"access_token\":\"" + token +
		       "\",\"scope\":\"call_control\"}";
	}

	constexpr std::int64_t kT0 = 5000000;   // not 0: the deadline must be relative to the start
}

// ── the arena: happy path and the capacity edge ────────────────────────────────────

TEST(TokenBodyArena, ABodyThatFitsIsCollectedAndScannedWithoutTheHeap)
{
	const std::string token = filler(1400);               // a JWT-sized token
	const std::string body = tokenBody(token);
	Arena arena;
	Script script;
	script.bytes(body);
	std::int64_t clock = kT0;
	std::string_view got;
	BodyStatus st = BodyStatus::ReadError;
	bool found = false;
	std::size_t heap = 0;
	{
		AllocGuard g;
		Arena::Lease lease = arena.tryClaim();
		ASSERT_TRUE(lease);
		st = run(lease, script, clock);
		found = telephony::jsonStringField(lease.data(), lease.size(), "access_token", got);
		heap = g.delta();
		EXPECT_EQ(got, token);
	}
	EXPECT_EQ(st, BodyStatus::Ok);
	EXPECT_TRUE(found);
	EXPECT_EQ(heap, 0u) << "claim + read + scan must not touch the heap";
}

TEST(TokenBodyArena, ABodyExactlyTheArenaSizeIsAccepted)
{
	const std::string body = filler(kN);
	Arena arena;
	Script script;
	script.bytes(body);
	std::int64_t clock = kT0;
	Arena::Lease lease = arena.tryClaim();
	ASSERT_TRUE(lease);
	EXPECT_EQ(run(lease, script, clock), BodyStatus::Ok);
	EXPECT_EQ(lease.size(), kN);
	EXPECT_EQ(held(lease), body) << "all of it, in order";
}

TEST(TokenBodyArena, ABodyOneByteOverTheArenaIsRefusedNotTruncated)
{
	Arena arena;
	Script script;
	script.bytes(filler(kN + 1));
	std::int64_t clock = kT0;
	Arena::Lease lease = arena.tryClaim();
	ASSERT_TRUE(lease);
	EXPECT_EQ(run(lease, script, clock), BodyStatus::ArenaFull);
	EXPECT_EQ(lease.size(), 0u) << "a refused body leaves no bytes behind, not even the first N";
	EXPECT_EQ(script.consumed(), kN + 1) << "it reads the one byte that proves the overflow, and no more";
}

// ── the three failure branches ─────────────────────────────────────────────────────

TEST(TokenBodyArena, FailureArenaFull_AHugeBodyIsRefusedAndNotReadPastTheProbeByte)
{
	Arena arena;
	Script script;
	script.bytes(filler(10 * kN));
	std::int64_t clock = kT0;
	Arena::Lease lease = arena.tryClaim();
	ASSERT_TRUE(lease);
	EXPECT_EQ(run(lease, script, clock), BodyStatus::ArenaFull);
	EXPECT_EQ(lease.size(), 0u);
	EXPECT_EQ(script.consumed(), kN + 1) << "a hostile server cannot make the read run on";
}

TEST(TokenBodyArena, FailureReadError_BeforeAnyDataIsAnError)
{
	Arena arena;
	Script script;
	script.code(-1);
	std::int64_t clock = kT0;
	Arena::Lease lease = arena.tryClaim();
	ASSERT_TRUE(lease);
	EXPECT_EQ(run(lease, script, clock), BodyStatus::ReadError);
	EXPECT_EQ(lease.size(), 0u);
}

TEST(TokenBodyArena, FailureReadError_AfterPartOfTheBodyLeavesNoPartialBody)
{
	Arena arena;
	Script script;
	script.bytes(tokenBody(filler(900)).substr(0, 700)).code(-1);
	std::int64_t clock = kT0;
	Arena::Lease lease = arena.tryClaim();
	ASSERT_TRUE(lease);
	EXPECT_EQ(run(lease, script, clock), BodyStatus::ReadError);
	EXPECT_EQ(lease.size(), 0u) << "the 700 bytes that did arrive must not be offered to the parser";
	EXPECT_GT(script.consumed(), 0u) << "the failure really came after data, or this proves nothing";
}

TEST(TokenBodyArena, FailureTimeout_TheReadTimingOutBeforeAnyDataIsATimeout)
{
	Arena arena;
	Script script;
	script.code(telephony::kHttpReadTimedOut);
	std::int64_t clock = kT0;
	Arena::Lease lease = arena.tryClaim();
	ASSERT_TRUE(lease);
	EXPECT_EQ(run(lease, script, clock), BodyStatus::Timeout);
	EXPECT_EQ(lease.size(), 0u);
}

TEST(TokenBodyArena, FailureTimeout_TheReadTimingOutAfterPartOfTheBodyLeavesNoPartialBody)
{
	Arena arena;
	Script script;
	script.bytes(filler(300)).code(telephony::kHttpReadTimedOut);
	std::int64_t clock = kT0;
	Arena::Lease lease = arena.tryClaim();
	ASSERT_TRUE(lease);
	EXPECT_EQ(run(lease, script, clock), BodyStatus::Timeout);
	EXPECT_EQ(lease.size(), 0u);
	EXPECT_EQ(script.consumed(), 300u);
}

TEST(TokenBodyArena, FailureTimeout_ABodyDrippedPastTheTotalBudgetIsATimeoutAndStopsReading)
{
	// One byte per read, each read a second later. Every read succeeds, so only the total
	// budget can stop it; without one this runs for kN reads, i.e. over an hour.
	Arena arena;
	Script script;
	std::int64_t clock = kT0;
	script.bytes(filler(kN)).chunk(1).perReadUs(1000000, &clock);
	Arena::Lease lease = arena.tryClaim();
	ASSERT_TRUE(lease);
	EXPECT_EQ(run(lease, script, clock, 3000000), BodyStatus::Timeout);
	EXPECT_EQ(lease.size(), 0u);
	EXPECT_EQ(script.calls(), 3u) << "it must stop at the deadline, not read on";
}

TEST(TokenBodyArena, ABodyInsideTheBudgetIsNotTimedOut)
{
	// The same one-byte drip, a millisecond per read: 2,000 reads, 2 s, inside a 3 s budget.
	const std::string body = filler(2000);
	Arena arena;
	Script script;
	std::int64_t clock = kT0;
	script.bytes(body).chunk(1).perReadUs(1000, &clock);
	Arena::Lease lease = arena.tryClaim();
	ASSERT_TRUE(lease);
	EXPECT_EQ(run(lease, script, clock, 3000000), BodyStatus::Ok);
	EXPECT_EQ(held(lease), body);
}

// ── the claim: nobody waits, nothing is held across the read ───────────────────────

TEST(TokenBodyArena, ASecondClaimIsRefusedAtOnceAndTheHolderIsNotDisturbed)
{
	Arena arena;
	Arena::Lease first = arena.tryClaim();
	ASSERT_TRUE(first);
	Arena::Lease second = arena.tryClaim();
	EXPECT_FALSE(second) << "refused, not queued";
	Script script;
	script.bytes("{}");
	std::int64_t clock = kT0;
	EXPECT_EQ(run(first, script, clock), BodyStatus::Ok) << "the refused claim must not have touched the holder";
	EXPECT_EQ(held(first), "{}");
}

TEST(TokenBodyArena, ACallerOnAnotherThreadIsRefusedWhileTheSocketIsBeingRead)
{
	Arena arena;
	Arena::Lease lease = arena.tryClaim();
	ASSERT_TRUE(lease);
	int callsWhileReading = 0;
	bool otherThreadGotIt = true;
	const std::string body = tokenBody("abc");
	std::size_t pos = 0;
	const BodyStatus st = lease.collect(
	    [&](char* dst, std::size_t room) -> int {
		    // This is inside the socket read: a second fetch arrives on another task now.
		    std::thread other([&] { otherThreadGotIt = static_cast<bool>(arena.tryClaim()); });
		    other.join();
		    ++callsWhileReading;
		    if (pos >= body.size()) return 0;
		    const std::size_t n = std::min(room, body.size() - pos);
		    for (std::size_t k = 0; k < n; ++k) dst[k] = body[pos + k];
		    pos += n;
		    return static_cast<int>(n);
	    },
	    [] { return kT0; }, telephony::kTokenBodyBudgetUs);
	EXPECT_EQ(st, BodyStatus::Ok);
	EXPECT_GT(callsWhileReading, 0);
	EXPECT_FALSE(otherThreadGotIt) << "the second task is turned away and carries on; it does not wait for this read";
}

TEST(TokenBodyArena, ALeaseReleasesTheArenaOnEveryExitAndTheNextClaimStartsEmpty)
{
	Arena arena;
	std::int64_t clock = kT0;
	{
		Arena::Lease lease = arena.tryClaim();
		ASSERT_TRUE(lease);
		Script bad;
		bad.bytes("{\"a\"").code(-1);
		EXPECT_EQ(run(lease, bad, clock), BodyStatus::ReadError);
	}   // lease goes out of scope on the failure path
	Arena::Lease again = arena.tryClaim();
	ASSERT_TRUE(again) << "a failed read must not leave the arena claimed";
	EXPECT_EQ(again.size(), 0u);
	Script good;
	good.bytes(tokenBody("tok"));
	EXPECT_EQ(run(again, good, clock), BodyStatus::Ok);
	std::string_view got;
	EXPECT_TRUE(telephony::jsonStringField(again.data(), again.size(), "access_token", got));
	EXPECT_EQ(got, "tok");
}

TEST(TokenBodyArena, AMovedLeaseKeepsTheClaimOnceAndReleasesItOnce)
{
	Arena arena;
	Arena::Lease a = arena.tryClaim();
	ASSERT_TRUE(a);
	Arena::Lease b = std::move(a);
	EXPECT_FALSE(a);
	EXPECT_TRUE(b);
	EXPECT_FALSE(arena.tryClaim()) << "still claimed through the new owner";
	b = Arena::Lease();   // move-assigning an empty lease releases the old claim
	EXPECT_TRUE(arena.tryClaim());
}

TEST(TokenBodyArena, AnEmptyBodyIsCollectedAsEmptyAndHasNoToken)
{
	Arena arena;
	Script script;   // nothing: the first read answers 0
	std::int64_t clock = kT0;
	Arena::Lease lease = arena.tryClaim();
	ASSERT_TRUE(lease);
	EXPECT_EQ(run(lease, script, clock), BodyStatus::Ok);
	EXPECT_EQ(lease.size(), 0u);
	std::string_view got;
	EXPECT_FALSE(telephony::jsonStringField(lease.data(), lease.size(), "access_token", got));
}

// ── the 911/933 lane: an arena of its own (#862, Rule 5) ───────────────────────────
// A 911/933 never waits on an ordinary token fetch and is never turned away by one, and a
// failed 911/933 read costs nothing but the read. The ESP arm (fetchToken) cannot be host
// compiled; it claims through telephony::TokenLanes, which these tests drive with the same
// calls. The sleeper counts instead of sleeping, so "did not wait" is exact: no wall clock.

namespace
{
	using Lanes = telephony::TokenLanes;
	using telephony::TokenLane;

	// What fetchToken() gives claimWaiting() for start(): 50 polls, 100 ms apart.
	constexpr int           kPolls  = 50;
	constexpr std::uint32_t kPollMs = 100;

	struct Sleeper
	{
		int           calls = 0;
		std::uint64_t ms    = 0;
		void operator()(std::uint32_t m) { ++calls; ms += m; }
	};

	// A 911/933 fetch whose body read ends in `want`, while an ordinary fetch holds its own arena
	// mid-fetch. Afterwards the emergency arena shows no bytes and can be claimed again at once,
	// the 911/933 never slept, and the ordinary lane's arena and claim are exactly as they were.
	void expectEmergencyReadFailsCleanly(Script& script, std::int64_t& clock, BodyStatus want,
	                                     std::int64_t budgetUs = telephony::kTokenBodyBudgetUs)
	{
		Lanes lanes;
		Sleeper sleeper;
		Arena::Lease ordinary = lanes.claim(TokenLane::Ordinary);
		ASSERT_TRUE(ordinary);
		Script ordinaryBody;
		ordinaryBody.bytes(tokenBody("ordinary"));
		ASSERT_EQ(run(ordinary, ordinaryBody, clock), BodyStatus::Ok);
		const std::string ordinaryBytes(held(ordinary));

		{
			Arena::Lease emergency = lanes.claimWaiting(TokenLane::Emergency, kPolls, kPollMs, sleeper);
			ASSERT_TRUE(emergency) << "the 911/933 arena is its own: an ordinary fetch does not hold it";
			EXPECT_EQ(run(emergency, script, clock, budgetUs), want);
			EXPECT_EQ(emergency.size(), 0u) << "a failed read offers the parser no bytes, not even the ones that arrived";
		}   // the lease goes out of scope on the failure path

		EXPECT_EQ(sleeper.calls, 0) << "a 911/933 never waits for its arena";
		EXPECT_EQ(held(ordinary), ordinaryBytes) << "the ordinary lane's arena is not touched by a 911/933 failure";
		EXPECT_FALSE(lanes.claim(TokenLane::Ordinary)) << "the ordinary fetch still holds its own claim";
		Arena::Lease again = lanes.claim(TokenLane::Emergency);
		EXPECT_TRUE(again) << "a failed 911/933 read must not leave its arena claimed";
		EXPECT_EQ(again.size(), 0u);
	}
}

TEST(TokenLanes, Emergency_ArenaFull_ABodyOverTheArenaIsRefusedAndLeavesNoBytes)
{
	Script script;
	script.bytes(filler(10 * kN));
	std::int64_t clock = kT0;
	expectEmergencyReadFailsCleanly(script, clock, BodyStatus::ArenaFull);
	EXPECT_EQ(script.consumed(), kN + 1) << "a hostile server cannot make the 911/933 read run on";
}

TEST(TokenLanes, Emergency_ReadError_AfterPartOfTheBodyLeavesNoPartialBody)
{
	Script script;
	script.bytes(tokenBody(filler(900)).substr(0, 700)).code(-1);
	std::int64_t clock = kT0;
	expectEmergencyReadFailsCleanly(script, clock, BodyStatus::ReadError);
	EXPECT_GT(script.consumed(), 0u) << "the failure really came after data, or this proves nothing";
}

TEST(TokenLanes, Emergency_Timeout_TheReadTimingOutAfterPartOfTheBodyLeavesNoPartialBody)
{
	Script script;
	script.bytes(filler(300)).code(telephony::kHttpReadTimedOut);
	std::int64_t clock = kT0;
	expectEmergencyReadFailsCleanly(script, clock, BodyStatus::Timeout);
	EXPECT_EQ(script.consumed(), 300u);
}

TEST(TokenLanes, Emergency_Timeout_ABodyDrippedPastTheTotalBudgetStopsReading)
{
	Script script;
	std::int64_t clock = kT0;
	script.bytes(filler(kN)).chunk(1).perReadUs(1000000, &clock);
	expectEmergencyReadFailsCleanly(script, clock, BodyStatus::Timeout, 3000000);
	EXPECT_EQ(script.calls(), 3u) << "the 911/933 stops at the deadline, not after kN reads";
}

TEST(TokenLanes, Emergency_ClaimHeldByAnother911FallsThroughAtOnceAndRefusesNothing)
{
	Lanes lanes;
	std::int64_t clock = kT0;
	Arena::Lease first = lanes.claim(TokenLane::Emergency);   // another 911/933's fetch
	ASSERT_TRUE(first);
	Script firstBody;
	firstBody.bytes(tokenBody("first"));
	ASSERT_EQ(run(first, firstBody, clock), BodyStatus::Ok);

	Sleeper sleeper;
	Arena::Lease second = lanes.claimWaiting(TokenLane::Emergency, kPolls, kPollMs, sleeper);
	EXPECT_FALSE(second) << "turned away, not queued: the caller carries on with the token it has";
	EXPECT_EQ(sleeper.calls, 0) << "it did not wait at all, so well inside the 10 ms the lane may spend";
	EXPECT_EQ(sleeper.ms, 0u);
	EXPECT_EQ(held(first), tokenBody("first")) << "the refused claim must not have touched the holder";

	Arena::Lease ordinary = lanes.claim(TokenLane::Ordinary);
	EXPECT_TRUE(ordinary) << "the ordinary lane is not involved";
}

TEST(TokenLanes, Emergency_ClaimWhileAnOrdinaryFetchHoldsItsArenaProceedsAtOnce)
{
	Lanes lanes;
	std::int64_t clock = kT0;
	Arena::Lease ordinary = lanes.claim(TokenLane::Ordinary);   // an ordinary refresh, mid-read
	ASSERT_TRUE(ordinary);
	Script ordinaryBody;
	ordinaryBody.bytes(tokenBody("ordinary"));
	ASSERT_EQ(run(ordinary, ordinaryBody, clock), BodyStatus::Ok);

	Sleeper sleeper;
	Arena::Lease emergency = lanes.claimWaiting(TokenLane::Emergency, kPolls, kPollMs, sleeper);
	ASSERT_TRUE(emergency) << "an ordinary fetch must not hold up a 911/933";
	EXPECT_EQ(sleeper.calls, 0) << "and the 911/933 did not wait to find out";
	EXPECT_NE(emergency.data(), ordinary.data());
	Script sos;
	sos.bytes(tokenBody("sos"));
	ASSERT_EQ(run(emergency, sos, clock), BodyStatus::Ok);
	std::string_view got;
	ASSERT_TRUE(telephony::jsonStringField(emergency.data(), emergency.size(), "access_token", got));
	EXPECT_EQ(got, "sos");
	EXPECT_EQ(held(ordinary), tokenBody("ordinary")) << "and the ordinary fetch is undisturbed";
}

TEST(TokenLanes, Emergency_FetchCompletesWhileAnOrdinaryReadIsStillInProgress)
{
	Lanes lanes;
	Arena::Lease ordinary = lanes.claim(TokenLane::Ordinary);
	ASSERT_TRUE(ordinary);
	std::string sosToken;
	int sosSleeps = -1;
	bool ordinaryReadDuringSos = false;
	const std::string body = tokenBody("ordinary");
	std::size_t pos = 0;
	const BodyStatus st = ordinary.collect(
	    [&](char* dst, std::size_t room) -> int {
		    // Inside the ordinary socket read, a 911/933 arrives on another task and finishes its
		    // whole fetch. If it had to wait for this read, the join below would never return.
		    if (pos == 0)
		    {
			    std::thread other([&] {
				    Sleeper s;
				    Arena::Lease e = lanes.claimWaiting(TokenLane::Emergency, kPolls, kPollMs, s);
				    sosSleeps = s.calls;
				    if (!e) return;
				    Script sos;
				    sos.bytes(tokenBody("sos"));
				    std::int64_t c = kT0;
				    if (run(e, sos, c) != BodyStatus::Ok) return;
				    std::string_view tok;
				    if (telephony::jsonStringField(e.data(), e.size(), "access_token", tok)) sosToken.assign(tok);
			    });
			    other.join();
			    ordinaryReadDuringSos = true;
		    }
		    if (pos >= body.size()) return 0;
		    const std::size_t n = std::min(room, body.size() - pos);
		    std::memcpy(dst, body.data() + pos, n);
		    pos += n;
		    return static_cast<int>(n);
	    },
	    [] { return kT0; }, telephony::kTokenBodyBudgetUs);
	EXPECT_EQ(st, BodyStatus::Ok);
	EXPECT_TRUE(ordinaryReadDuringSos);
	EXPECT_EQ(sosSleeps, 0);
	EXPECT_EQ(sosToken, "sos") << "the 911/933 fetched its token while the ordinary read was still open";
	EXPECT_EQ(held(ordinary), body);
}

TEST(TokenLanes, AnOrdinaryFetchIsNeverHandedTheEmergencyArena)
{
	Lanes lanes;
	Arena::Lease ordinary = lanes.claim(TokenLane::Ordinary);
	ASSERT_TRUE(ordinary);
	// The 911/933 arena is free, and an ordinary caller that finds its own busy, even one that
	// polls for it, still does not borrow it.
	Sleeper sleeper;
	Arena::Lease second = lanes.claimWaiting(TokenLane::Ordinary, kPolls, kPollMs, sleeper);
	EXPECT_FALSE(second) << "the free 911/933 arena is not for an ordinary fetch";
	Arena::Lease emergency = lanes.claim(TokenLane::Emergency);
	ASSERT_TRUE(emergency) << "and it was never taken";
	EXPECT_NE(emergency.data(), ordinary.data());
	// The other way round: with the 911/933 arena held, an ordinary claim gets the ordinary one.
	ordinary = Arena::Lease();
	Arena::Lease again = lanes.claim(TokenLane::Ordinary);
	ASSERT_TRUE(again);
	EXPECT_NE(again.data(), emergency.data());
}

TEST(TokenLanes, TheOrdinaryLaneStillPollsForItsClaimForStartAndTheEmergencyLaneNeverDoes)
{
	Lanes lanes;
	// start() polls: it loses the claim to a refresh, and gets it when that refresh lets go.
	Arena::Lease holder = lanes.claim(TokenLane::Ordinary);
	ASSERT_TRUE(holder);
	int sleeps = 0;
	Arena::Lease got = lanes.claimWaiting(TokenLane::Ordinary, kPolls, kPollMs, [&](std::uint32_t ms) {
		EXPECT_EQ(ms, kPollMs);
		if (++sleeps == 3) holder = Arena::Lease();
	});
	EXPECT_TRUE(got);
	EXPECT_EQ(sleeps, 3);
	// It gives up after the polls it was given, and a plain fetch (0 polls) does not poll at all.
	Sleeper giveUp;
	EXPECT_FALSE(lanes.claimWaiting(TokenLane::Ordinary, kPolls, kPollMs, giveUp));
	EXPECT_EQ(giveUp.calls, kPolls);
	Sleeper plain;
	EXPECT_FALSE(lanes.claimWaiting(TokenLane::Ordinary, 0, kPollMs, plain));
	EXPECT_EQ(plain.calls, 0);
	// The same polls, asked of the 911/933 lane with its arena busy: not one sleep.
	Arena::Lease sos = lanes.claim(TokenLane::Emergency);
	ASSERT_TRUE(sos);
	Sleeper emergency;
	EXPECT_FALSE(lanes.claimWaiting(TokenLane::Emergency, kPolls, kPollMs, emergency));
	EXPECT_EQ(emergency.calls, 0) << "no waitForArena for a 911/933, whoever asks";
}

TEST(TokenLanes, TheTwoArenasAreTheWholeCost)
{
	// "Two arenas of 4,096 B usable each": kTokenBodyBytes of body plus the byte that shows an
	// overflow, and the flag and length beside it. Two of them is what the client carries, reserved
	// with it, and a host's pointer-sized padding is the most the bound allows beyond the buffers.
	EXPECT_GE(sizeof(Arena), kN + 1);
	EXPECT_LE(sizeof(Arena), kN + 1 + 3 * sizeof(void*));
	EXPECT_GE(sizeof(Lanes), 2 * sizeof(Arena));
	EXPECT_LE(sizeof(Lanes), 2 * sizeof(Arena) + 16) << "two arenas and nothing that grows";
}

// ── the 911/933 fetch's overall deadline (#862, Rule 5) ──────────────────────────────

TEST(TokenLanes, AnOperationGetsItsOwnCapWhileTheBudgetHasRoomAndWhatIsLeftAfter)
{
	constexpr std::int64_t kNow = 7000000;
	const std::int64_t deadline = kNow + telephony::kSosTokenBudgetUs;
	EXPECT_EQ(telephony::kSosTokenBudgetUs, 3000000);
	EXPECT_EQ(telephony::opTimeoutMs(kNow, deadline, 2000), 2000) << "3 s left, a 2 s cap";
	EXPECT_EQ(telephony::opTimeoutMs(deadline - 2000000, deadline, 2000), 2000);
	EXPECT_EQ(telephony::opTimeoutMs(deadline - 1500000, deadline, 2000), 1500) << "less is left than the cap";
	EXPECT_EQ(telephony::opTimeoutMs(deadline - 1001, deadline, 2000), 2) << "rounded up, never down to a poll";
	EXPECT_EQ(telephony::opTimeoutMs(deadline - 1, deadline, 2000), 1);
}

TEST(TokenLanes, ASpentBudgetGivesZeroSoTheOperationIsNotStarted)
{
	constexpr std::int64_t kNow = 7000000;
	EXPECT_EQ(telephony::opTimeoutMs(kNow, kNow, 2000), 0);
	EXPECT_EQ(telephony::opTimeoutMs(kNow + 1, kNow, 2000), 0);
	EXPECT_EQ(telephony::opTimeoutMs(kNow + 100000000, kNow, 2000), 0) << "long overdue is still 0, never negative";
}

TEST(TokenLanes, AServerThatStallsEveryOperationCannotTakeMoreThanTheBudget)
{
	// Every operation lasts min(the timeout it was given, the server's gap). The fetch asks for the
	// next operation's timeout until it is told 0. However small or large the gap, the operations
	// together never outlast the budget, and none was given more than its cap or than was left.
	for (const std::int64_t gapMs : {1, 3, 100, 700, 1999, 2000, 5000})
	{
		const std::int64_t startUs = 90000000;
		const std::int64_t deadline = startUs + telephony::kSosTokenBudgetUs;
		std::int64_t now = startUs;
		int ops = 0;
		for (;;)
		{
			const int ms = telephony::opTimeoutMs(now, deadline, 2000);
			if (ms == 0) break;
			ASSERT_GT(ms, 0);
			ASSERT_LE(ms, 2000);
			ASSERT_LE(now + static_cast<std::int64_t>(ms) * 1000, deadline + 999) << "never more than was left";
			now += std::min<std::int64_t>(ms, gapMs) * 1000;
			++ops;
			ASSERT_LT(ops, 5000);
		}
		EXPECT_LE(now - startUs, telephony::kSosTokenBudgetUs) << "gap " << gapMs << " ms";
		EXPECT_GE(now, deadline - 1000) << "and it ran until the budget was spent, gap " << gapMs << " ms";
	}
}

// ── the bounded field scanner ──────────────────────────────────────────────────────

namespace
{
	// jsonStringField() unescapes in place, so it takes a writable copy.
	bool scan(std::string json, std::string_view key, std::string& value)
	{
		std::string_view v;
		if (!telephony::jsonStringField(json.data(), json.size(), key, v)) return false;
		value.assign(v.data(), v.size());
		return true;
	}
}

TEST(JsonStringField, FindsTheTokenAmongOtherMembers)
{
	std::string v;
	ASSERT_TRUE(scan("{ \"token_type\" : \"Bearer\", \"expires_in\": 60,\n \"access_token\" :\t\"a.b-c_d\", \"scope\": \"x\" }",
	                 "access_token", v));
	EXPECT_EQ(v, "a.b-c_d");
}

TEST(JsonStringField, TheKeyTextInsideAStringValueIsNotTheMember)
{
	std::string v;
	ASSERT_TRUE(scan("{\"error_description\":\"no \\\"access_token\\\": here\",\"access_token\":\"real\"}", "access_token", v));
	EXPECT_EQ(v, "real");
	EXPECT_FALSE(scan("{\"error_description\":\"{\\\"access_token\\\":\\\"fake\\\"}\"}", "access_token", v));
}

TEST(JsonStringField, OnlyATopLevelMemberCounts)
{
	std::string v;
	ASSERT_TRUE(scan("{\"meta\":{\"access_token\":\"inner\",\"k\":[1,{\"access_token\":\"deeper\"}]},\"access_token\":\"outer\"}",
	                 "access_token", v));
	EXPECT_EQ(v, "outer");
	EXPECT_FALSE(scan("{\"meta\":{\"access_token\":\"inner\"},\"list\":[\"access_token\"]}", "access_token", v));
}

TEST(JsonStringField, UnescapesInPlaceWhatAServerMayEscape)
{
	std::string v;
	// \/ is legal JSON for '/', and .NET writes '+' as +.
	ASSERT_TRUE(scan("{\"access_token\":\"ab\\/cd\\u002Bef\\\\g\\\"h\\n\"}", "access_token", v));
	EXPECT_EQ(v, "ab/cd+ef\\g\"h\n");
	ASSERT_TRUE(scan("{\"access_token\":\"\\u00e9\\u20ac\"}", "access_token", v));
	EXPECT_EQ(v, "\xC3\xA9\xE2\x82\xAC") << "BMP code points come out as UTF-8";
}

TEST(JsonStringField, AnEscapeItCannotRepresentIsAnErrorNotAGuess)
{
	std::string v;
	EXPECT_FALSE(scan("{\"access_token\":\"a\\ud83d\\ude00b\"}", "access_token", v)) << "surrogate pair";
	EXPECT_FALSE(scan("{\"access_token\":\"a\\u0000b\"}", "access_token", v)) << "NUL would end a C string";
	EXPECT_FALSE(scan("{\"access_token\":\"a\\qb\"}", "access_token", v)) << "not a JSON escape";
	EXPECT_FALSE(scan("{\"access_token\":\"a\\u12\"}", "access_token", v)) << "short \\u";
	EXPECT_FALSE(scan("{\"access_token\":\"a\\u12G4\"}", "access_token", v)) << "non-hex digit";
}

TEST(JsonStringField, AMemberThatIsNotAStringIsNotAToken)
{
	std::string v;
	EXPECT_FALSE(scan("{\"access_token\":12345}", "access_token", v));
	EXPECT_FALSE(scan("{\"access_token\":null}", "access_token", v));
	EXPECT_FALSE(scan("{\"access_token\":{\"x\":\"y\"}}", "access_token", v));
	EXPECT_FALSE(scan("{\"access_token\":[\"y\"]}", "access_token", v));
}

TEST(JsonStringField, TruncatedOrMalformedInputIsAnErrorAndNeverAPrefix)
{
	const char* bad[] = {
	    "", "   ", "[]", "\"access_token\"", "{", "{\"access_token", "{\"access_token\"", "{\"access_token\":",
	    "{\"access_token\":\"abc", "{\"access_token\":\"abc\\", "{\"access_token\" \"abc\"}", "{access_token:\"abc\"}",
	    "{\"a\":\"b\" \"access_token\":\"abc\"}",
	};
	for (const char* b : bad)
	{
		std::string_view out;
		std::string copy(b);
		EXPECT_FALSE(telephony::jsonStringField(copy.data(), copy.size(), "access_token", out)) << "input: " << b;
		EXPECT_TRUE(out.empty()) << "no partial value for: " << b;
	}
}

TEST(JsonStringField, TheFirstOfTwoMembersWithTheSameKeyWins)
{
	std::string v;
	ASSERT_TRUE(scan("{\"access_token\":\"one\",\"access_token\":\"two\"}", "access_token", v));
	EXPECT_EQ(v, "one");
}

TEST(JsonStringField, ScansWithoutTheHeap)
{
	std::string json = tokenBody(filler(1400));
	std::string_view out;
	bool ok = false;
	std::size_t heap = 0;
	{
		AllocGuard g;
		ok = telephony::jsonStringField(json.data(), json.size(), "access_token", out);
		heap = g.delta();
	}
	EXPECT_TRUE(ok);
	EXPECT_EQ(heap, 0u);
	EXPECT_EQ(out.size(), 1400u);
}
