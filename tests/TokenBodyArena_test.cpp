// TokenBodyArena_test.cpp -- the token-body arena and its bounded field scanner (#862).
//
// The contract is the one the operator recorded on #948 for the 911/933 lane:
//   1. a bounded arena, reserved with the client, no per-read std::vector and no spill;
//   2. a body that does not fit, or a read that fails, is an ERROR and the arena then
//      shows no bytes at all -- never a prefix. The caller keeps the token it has;
//   3. no mutex is held across the socket read, and nobody waits for the arena;
//   4. one test per failure branch: arena full, read error, timeout.
//
// The ESP arm (TelephonyAnchorClient::readJsonStringField / fetchToken) cannot be host
// compiled. These tests drive the host-compiled halves it calls: telephony::BodyArena,
// its Lease::collect(), and telephony::jsonStringField().

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
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
