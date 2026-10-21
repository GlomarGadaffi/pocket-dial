// SosStatusGet_test.cpp -- #948: the 911/933 lane's status GET. The operator ruling on #948:
// the GET allocates only under a failure contract (a failed allocation, a failed or short read
// or a body over the arena is an error, never partial data), and teardown waits at most 10 ms
// for the handle's claim, then takes a fallback. TelephonyAnchorClient.cpp is ESP-only, so
// these drive src/SIP/SosStatusGet.hpp, the code its sos lane calls.

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <future>
#include <string>
#include <thread>
#include <vector>

#include "AllocCounter.hpp"
#include "PsramAllocator.hpp"
#include "SosStatusGet.hpp"
#include "Witness.hpp"

namespace
{
using namespace telephony;

constexpr std::size_t kNever = static_cast<std::size_t>(-1);

// A server's body, handed out the way esp_http_client_read does. failAt: a read starting at or
// after that many bytes returns -1. endAt: the peer closes after that many bytes, so reads return
// 0 while the response is not complete.
struct ScriptedRead
{
	std::string body;
	std::size_t chunk  = 512;
	std::size_t failAt = kNever;
	std::size_t endAt  = kNever;
	std::size_t pos    = 0;
	int         reads  = 0;

	int read(char* p, int n)
	{
		++reads;
		if (pos >= failAt) return -1;
		const std::size_t limit = std::min(body.size(), endAt);
		if (pos >= limit) return 0;
		const std::size_t k = std::min({ static_cast<std::size_t>(n), chunk, limit - pos });
		std::memcpy(p, body.data() + pos, k);
		pos += k;
		return static_cast<int>(k);
	}
	bool complete() const { return pos >= body.size(); }
};

std::string patternBody(std::size_t n)
{
	std::string s(n, '\0');
	for (std::size_t i = 0; i < n; ++i) s[i] = static_cast<char>('a' + (i % 26));
	return s;
}

template <class Out>
BodyRead readAll(const SosBodyArena& arena, ScriptedRead& src, Out& out)
{
	return readSosBody(
		arena, [&](char* p, int n) { return src.read(p, n); }, [&] { return src.complete(); }, out);
}

// A string whose assign throws std::bad_alloc: a real heap cannot be made to fail on demand.
struct ThrowingString
{
	std::string value = "stale";
	bool        throwOnAssign = true;
	int         assigns = 0;

	void clear() { value.clear(); }
	void assign(const char* p, std::size_t n)
	{
		++assigns;
		if (throwOnAssign) throw std::bad_alloc();
		value.assign(p, n);
	}
};

bool reserveReal(SosBodyArena& a, std::size_t cap)
{
	return a.reserve(cap, &psram::allocPreferPsram, &psram::freePreferPsram);
}

void* refuseAlloc(std::size_t) { return nullptr; }

int g_allocs = 0;
int g_frees  = 0;
void* countingAlloc(std::size_t n)
{
	++g_allocs;
	return psram::allocPreferPsram(n);
}
void countingFree(void* p)
{
	++g_frees;
	psram::freePreferPsram(p);
}

// ── The GET failure contract ─────────────────────────────────────────────────

TEST(SosStatusBody, AWholeBodyIsReturnedWithNoAllocationPerRead)
{
	SosBodyArena arena;
	ASSERT_TRUE(reserveReal(arena, 4096));
	ScriptedRead src;
	src.body = patternBody(3000);   // six reads of 512 and a tail

	std::string out;
	out.reserve(4096);   // the hand-back string is the documented exemption; the drain loop is not
	AllocGuard guard;
	const BodyRead r = readAll(arena, src, out);
	EXPECT_EQ(guard.delta(), 0u) << "the per-read vector growth is gone: reading allocates nothing";
	EXPECT_EQ(r, BodyRead::Ok);
	EXPECT_EQ(out, src.body);
}

TEST(SosStatusBody, ABodyExactlyTheSizeOfTheArenaFits)
{
	SosBodyArena arena;
	ASSERT_TRUE(reserveReal(arena, 1024));
	ScriptedRead src;
	src.body = patternBody(1024);

	std::string out;
	EXPECT_EQ(readAll(arena, src, out), BodyRead::Ok);
	EXPECT_EQ(out, src.body) << "the last byte of the arena is a body byte, not a terminator slot";
}

TEST(SosStatusBody, ABodyOverTheArenaIsAnErrorNeverATruncatedBody)
{
	SosBodyArena arena;
	ASSERT_TRUE(reserveReal(arena, 1024));
	ScriptedRead src;
	src.body = patternBody(1025);   // one byte more than fits

	std::string out = "stale";
	const BodyRead r = readAll(arena, src, out);
	EXPECT_EQ(r, BodyRead::TooBig);
	EXPECT_TRUE(out.empty()) << "a truncated participant list can mis-decide the 911's own leg: no body at all";
}

TEST(SosStatusBody, AReadErrorAfterPartialDataReturnsNoData)
{
	SosBodyArena arena;
	ASSERT_TRUE(reserveReal(arena, 4096));
	ScriptedRead src;
	src.body   = patternBody(2000);
	src.failAt = 1024;   // two good reads, then the transport fails

	std::string out = "stale";
	const BodyRead r = readAll(arena, src, out);
	EXPECT_EQ(r, BodyRead::ReadError);
	EXPECT_TRUE(out.empty()) << "the 1024 bytes already read are not shown";
}

TEST(SosStatusBody, APeerCloseBeforeTheBodyIsCompleteIsAnErrorNotAShortBody)
{
	// esp_http_client_read returns 0 for a FIN before Content-Length bytes arrived; 0 alone is
	// not the end of the body.
	SosBodyArena arena;
	ASSERT_TRUE(reserveReal(arena, 4096));
	ScriptedRead src;
	src.body  = patternBody(2000);
	src.endAt = 700;

	std::string out = "stale";
	const BodyRead r = readAll(arena, src, out);
	EXPECT_EQ(r, BodyRead::Short);
	EXPECT_TRUE(out.empty());
}

TEST(SosStatusBody, AFailedReserveIsAnErrorAndNothingIsRead)
{
	SosBodyArena arena;
	EXPECT_FALSE(arena.reserve(4096, &refuseAlloc, &psram::freePreferPsram));
	EXPECT_EQ(arena.data(), nullptr);
	ScriptedRead src;
	src.body = patternBody(100);

	std::string out = "stale";
	const BodyRead r = readAll(arena, src, out);
	EXPECT_EQ(r, BodyRead::NoArena);
	EXPECT_TRUE(out.empty());
	EXPECT_EQ(src.reads, 0) << "no arena, no read: the response is not consumed into nowhere";
}

TEST(SosStatusBody, AnEarlierAttemptsBytesNeverReachALaterBody)
{
	// httpGetBody rebuilds the handle and retries once after a failed read; the arena stays.
	SosBodyArena arena;
	ASSERT_TRUE(reserveReal(arena, 4096));
	std::string out;

	ScriptedRead first;
	first.body   = std::string(1500, 'X');
	first.failAt = 1024;
	EXPECT_EQ(readAll(arena, first, out), BodyRead::ReadError);

	ScriptedRead second;
	second.body = patternBody(900);
	EXPECT_EQ(readAll(arena, second, out), BodyRead::Ok);
	EXPECT_EQ(out, second.body) << "no X from the failed attempt, no gap, no prefix";
}

TEST(SosStatusBody, AFullListOfTheLargestParticipantsFitsTheArena)
{
	// The sizing basis (SosStatusGet.hpp): the largest participant object the 3CX entity allows,
	// 2 legs per anchor call plus kSosSpareLegs of them. Unmeasured: the shape is 3CX's published
	// Participant, not a capture.
	const std::string longName(64, 'N'), longNum(32, '1'), longDev(128, 'd');
	const std::string obj =
		"{\"id\":2147483647,\"status\":\"Connected\",\"party_caller_name\":\"" + longName + "\",\"party_dn\":\"" + longNum +
		"\",\"party_caller_id\":\"" + longNum + "\",\"party_did\":\"" + longNum + "\",\"device_id\":\"" + longDev +
		"\",\"party_dn_type\":\"Wextension\",\"direct_control\":true,\"originated_by_dn\":\"" + longNum +
		"\",\"originated_by_type\":\"Wextension\",\"referred_by_dn\":\"" + longNum +
		"\",\"referred_by_type\":\"Wextension\",\"on_behalf_of_dn\":\"" + longNum +
		"\",\"on_behalf_of_type\":\"Wextension\",\"callid\":2147483647,\"legid\":2147483647}";
	ASSERT_LE(obj.size(), kSosListObjectBytes) << "the per-object budget covers the longest object";

	const unsigned calls = 4;   // POCKETDIAL_MAX_ANCHOR_CALLS
	const std::size_t objects = 2 * calls + kSosSpareLegs;
	std::string list = "[";
	for (std::size_t i = 0; i < objects; ++i) list += (i ? "," : "") + obj;
	list += "]";
	EXPECT_EQ(sosBodyArenaBytes(calls), 12288u);
	EXPECT_EQ(sosBodyArenaBytes(1), 7680u) << "the constrained build's single call slot";

	SosBodyArena arena;
	ASSERT_TRUE(reserveReal(arena, sosBodyArenaBytes(calls)));
	ScriptedRead src;
	src.body = list;
	std::string out;
	EXPECT_EQ(readAll(arena, src, out), BodyRead::Ok) << list.size() << " B of " << sosBodyArenaBytes(calls);
	EXPECT_EQ(out, list);
}

TEST(SosStatusBody, AFailedHandBackAllocationIsAnErrorNotAnEscapingException)
{
	// An exhausted heap during a 911 status GET must come back as an error. Uncaught, the
	// std::bad_alloc from the hand-back string is std::terminate on the 911's task.
	SosBodyArena arena;
	ASSERT_TRUE(reserveReal(arena, 4096));
	ScriptedRead src;
	src.body = patternBody(300);

	ThrowingString out;
	BodyRead r = BodyRead::Ok;
	EXPECT_NO_THROW(r = readAll(arena, src, out));
	EXPECT_EQ(r, BodyRead::AllocFailed);
	EXPECT_EQ(out.assigns, 1);
	EXPECT_TRUE(out.value.empty()) << "no body, partial or otherwise";

	// the arena is intact: the next attempt, with memory back, reads the whole body
	out.throwOnAssign = false;
	ScriptedRead again;
	again.body = patternBody(300);
	EXPECT_EQ(readAll(arena, again, out), BodyRead::Ok);
	EXPECT_EQ(out.value, again.body);
}

TEST(SosStatusBody, TheOtherErrorsNeverReachTheHandBackAllocation)
{
	SosBodyArena arena;
	ASSERT_TRUE(reserveReal(arena, 1024));
	ThrowingString out;

	ScriptedRead big;
	big.body = patternBody(1025);
	EXPECT_EQ(readAll(arena, big, out), BodyRead::TooBig);
	ScriptedRead fails;
	fails.body   = patternBody(900);
	fails.failAt = 512;
	EXPECT_EQ(readAll(arena, fails, out), BodyRead::ReadError);
	ScriptedRead shortRead;
	shortRead.body  = patternBody(900);
	shortRead.endAt = 400;
	EXPECT_EQ(readAll(arena, shortRead, out), BodyRead::Short);
	SosBodyArena none;
	ScriptedRead any;
	EXPECT_EQ(readAll(none, any, out), BodyRead::NoArena);

	EXPECT_EQ(out.assigns, 0);
	EXPECT_TRUE(out.value.empty());
}

TEST(SosStatusBody, TheArenaIsReservedOnceAndFreedOnce)
{
	g_allocs = g_frees = 0;
	{
		SosBodyArena arena;
		EXPECT_TRUE(arena.reserve(2048, &countingAlloc, &countingFree));
		EXPECT_TRUE(arena.reserve(2048, &countingAlloc, &countingFree)) << "a second GET or a handle rebuild";
		EXPECT_EQ(g_allocs, 1);
		EXPECT_EQ(arena.capacity(), 2048u);
		arena.release();
		arena.release();
		EXPECT_EQ(g_frees, 1);
		EXPECT_EQ(arena.data(), nullptr);

		EXPECT_TRUE(arena.reserve(2048, &countingAlloc, &countingFree)) << "start() after a teardown";
		EXPECT_EQ(g_allocs, 2);
	}
	EXPECT_EQ(g_frees, 2) << "the destructor frees a block still held";
}

// ── The claim ────────────────────────────────────────────────────────────────

// Runs f on its own thread. Still running after 250 ms means an open-ended spin: fail, and
// clear the flag so it can finish and the test can join instead of hanging the suite.
template <class F>
auto runGuarded(std::atomic<bool>& flag, F f) -> decltype(f())
{
	auto fut = std::async(std::launch::async, f);
	if (fut.wait_for(std::chrono::milliseconds(250)) != std::future_status::ready)
	{
		ADD_FAILURE() << "still waiting for the claim after 250 ms: an open-ended spin";
		flag.store(false);
	}
	return fut.get();
}

int64_t steadyUs()
{
	return std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

void pauseOneMs()
{
	const auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(1);
	while (std::chrono::steady_clock::now() < end) std::this_thread::yield();
}

// A clock that moves one step per pause. A claim that never gives up is cut off after
// kRunaway pauses (the holder "lets go") and flagged, so the test fails instead of hanging.
struct FakeClock
{
	static constexpr int kRunaway = 1000;

	explicit FakeClock(std::atomic<bool>& f) : flag(f) {}
	std::atomic<bool>& flag;
	int64_t nowUs = 0;
	int     pauses = 0;
	int     releaseAfter = -1;   // the holder lets go at this pause
	int64_t stepUs = 1000;
	bool    runaway = false;

	int64_t now() const { return nowUs; }
	void pause()
	{
		nowUs += stepUs;
		++pauses;
		if (pauses == releaseAfter) flag.store(false);
		if (pauses >= kRunaway)
		{
			runaway = true;
			flag.store(false);
		}
	}
};

TEST(SosStatusClaim, AFreeFlagIsTakenAndReleased)
{
	std::atomic<bool> flag{false};
	FakeClock c(flag);
	{
		SosStatusClaim claim(&flag, kSosClaimBoundUs, c.stepUs, [&] { return c.now(); }, [&] { c.pause(); });
		EXPECT_TRUE(claim.held());
		EXPECT_TRUE(flag.load());
		EXPECT_EQ(c.pauses, 0);
	}
	EXPECT_FALSE(flag.load());
}

TEST(SosStatusClaim, ANullFlagClaimsNothingAndCountsAsHeld)
{
	std::atomic<bool> unused{false};
	FakeClock c(unused);
	SosStatusClaim claim(nullptr, 0, c.stepUs, [&] { return c.now(); }, [&] { c.pause(); });
	EXPECT_TRUE(claim.held()) << "the ordinary lane has no claim to lose";
}

TEST(SosStatusClaim, AHeldClaimAtBoundZeroFallsBackAtOnceWithoutPausing)
{
	// The 911 caller: a claim held by someone else is never waited for.
	std::atomic<bool> flag{true};
	FakeClock c(flag);
	SosStatusClaim claim(&flag, 0, c.stepUs, [&] { return c.now(); }, [&] { c.pause(); });
	EXPECT_FALSE(c.runaway) << "an open-ended spin";
	EXPECT_FALSE(claim.held());
	EXPECT_EQ(c.pauses, 0);
}

TEST(SosStatusClaim, AFailedClaimLeavesTheOtherHoldersFlagSet)
{
	std::atomic<bool> flag{true};   // somebody's GET is mid-flight
	FakeClock c(flag);
	{
		SosStatusClaim claim(&flag, 0, c.stepUs, [&] { return c.now(); }, [&] { c.pause(); });
		ASSERT_FALSE(claim.held());
	}
	EXPECT_TRUE(flag.load()) << "freeing the holder's claim would let teardown free a handle under its read";
}

TEST(SosStatusClaim, AHeldClaimGivesUpWithinTheBoundOnAFakeClock)
{
	std::atomic<bool> flag{true};
	FakeClock c(flag);
	const bool won = claimWithin(flag, kSosClaimBoundUs, c.stepUs, [&] { return c.now(); }, [&] { c.pause(); });
	EXPECT_FALSE(c.runaway) << "an open-ended spin";
	EXPECT_FALSE(won);
	EXPECT_LE(c.nowUs, kSosClaimBoundUs) << "paused " << c.pauses << " x " << c.stepUs << " us";
	EXPECT_GT(c.pauses, 0) << "it did wait, up to the bound";
	EXPECT_LE(kSosClaimBoundUs, 10'000) << "the ruling's ceiling";
}

TEST(SosStatusClaim, ATickLongerThanTheBoundNeverPausesAndDoesNotSpin)
{
	// At CONFIG_FREERTOS_HZ=100 one tick is 10 ms, more than the 8 ms bound: the claim is tried
	// once and given up, not spun on. (The build is 1000 Hz: sdkconfig.defaults.)
	std::atomic<bool> flag{true};
	FakeClock c(flag);
	c.stepUs = 10'000;
	const bool won = claimWithin(flag, kSosClaimBoundUs, c.stepUs, [&] { return c.now(); }, [&] { c.pause(); });
	EXPECT_FALSE(c.runaway) << "a busy-wait";
	EXPECT_FALSE(won);
	EXPECT_EQ(c.pauses, 0);
}

TEST(SosStatusClaim, AHolderThatLetsGoInsideTheBoundIsFollowed)
{
	std::atomic<bool> flag{true};
	FakeClock c(flag);
	c.releaseAfter = 3;
	{
		SosStatusClaim claim(&flag, kSosClaimBoundUs, c.stepUs, [&] { return c.now(); }, [&] { c.pause(); });
		EXPECT_TRUE(claim.held());
		EXPECT_EQ(c.pauses, 3);
		EXPECT_TRUE(flag.load());
	}
	EXPECT_FALSE(flag.load());
}

// ── Teardown ─────────────────────────────────────────────────────────────────

struct Timed
{
	bool    freed;
	int64_t us;
};

TEST(SosStatusTeardown, ReturnsWithinTenMsWhileAnotherHolderHoldsTheClaimAndTakesTheFallback)
{
	pdwitness::clear();
	int64_t worst = 0;
	for (int run = 0; run < 5; ++run)
	{
		std::atomic<bool> flag{true};   // tel_sos is mid-GET and does not let go
		SosWitness witness;
		int freeCalls = 0;
		const Timed t = runGuarded(flag, [&] {
			const int64_t t0 = steadyUs();
			const bool freed = closeWithinBound(flag, 1000, steadyUs, pauseOneMs, [&] { ++freeCalls; }, witness);
			return Timed{ freed, steadyUs() - t0 };
		});
		EXPECT_FALSE(t.freed);
		EXPECT_EQ(freeCalls, 0) << "the handle is not freed under another holder's read";
		EXPECT_EQ(witness.count(SosFallback::Teardown), 1u);
		worst = std::max(worst, t.us);
	}
	RecordProperty("measured_wait_worst_us", static_cast<int>(worst));
	std::fprintf(stderr, "[ #948 ] teardown wait with the claim held: worst of 5 runs %lld us (bound 10000)\n",
	             static_cast<long long>(worst));
	EXPECT_LE(worst, 10'000) << "closeSosStatusClient returns within 10 ms, every run";
	EXPECT_EQ(pdwitness::count("teardown claim not won within the bound"), 5u) << "one witness line per fallback";
}

TEST(SosStatusTeardown, FreesOnceWhenTheClaimIsFree)
{
	std::atomic<bool> flag{false};
	SosWitness witness;
	int freeCalls = 0;
	const bool freed = closeWithinBound(flag, 1000, steadyUs, pauseOneMs, [&] { ++freeCalls; }, witness);
	EXPECT_TRUE(freed);
	EXPECT_EQ(freeCalls, 1);
	EXPECT_FALSE(flag.load()) << "the claim is released after the free";
	EXPECT_EQ(witness.count(SosFallback::Teardown), 0u);
}

TEST(SosStatusTeardown, TheNinetyOneOneGetTakesTheFallbackWithoutWaiting)
{
	// The operator: a 911 is never delayed (<= 10 ms), no wait of any length on the 911 path.
	int64_t worst = 0;
	for (int run = 0; run < 5; ++run)
	{
		std::atomic<bool> flag{true};
		std::atomic<int> pauses{0};
		const Timed t = runGuarded(flag, [&] {
			const int64_t t0 = steadyUs();
			SosStatusClaim claim(&flag, kSosGetClaimBoundUs, 1000, steadyUs, [&] { ++pauses; pauseOneMs(); });
			return Timed{ claim.held(), steadyUs() - t0 };
		});
		EXPECT_FALSE(t.freed) << "held() must be false: the GET falls back";
		EXPECT_EQ(pauses.load(), 0) << "the 911 path never waits for the claim";
		EXPECT_TRUE(flag.load());
		worst = std::max(worst, t.us);
	}
	std::fprintf(stderr, "[ #948 ] 911 GET with the claim held: worst of 5 runs %lld us (limit 10000)\n",
	             static_cast<long long>(worst));
	EXPECT_LE(worst, 10'000) << "every run returns within the 10 ms bound; zero pauses is what keeps it there";
}

// ── The #349 window: every list read failing is the usual 503, 911/933 included ──────

// What a sos list read does around httpGetBody on the sos lane: the claim (waited for not at all),
// then the arena read. The leg pick (cJSON) is replaced by "a non-empty body names leg 517".
struct SosListRead
{
	std::atomic<bool> claim{false};
	SosBodyArena         arena;
	ScriptedRead      response;   // each read gets a fresh copy: a new response
	SosWitness        witness;
	std::atomic<int>  pauses{0};
	int64_t           slowestUs = 0;
	int               gets = 0;

	std::string operator()()
	{
		const int64_t t0 = steadyUs();
		std::string leg;
		{
			SosStatusClaim c(&claim, kSosGetClaimBoundUs, 1000, steadyUs, [&] { ++pauses; pauseOneMs(); });
			if (!c.held())
			{
				witness.note(SosFallback::Get);
			}
			else
			{
				++gets;
				ScriptedRead r = response;
				std::string body;
				if (readAll(arena, r, body) == BodyRead::Ok && !body.empty()) leg = "517";
			}
		}
		slowestUs = std::max(slowestUs, steadyUs() - t0);
		return leg;
	}
};

struct PlacedCall
{
	bool        success;   // makeCall() returns true; false is the 503 (NOT ROUTED for a 911)
	std::string ownLeg;
	int         reads;
	int64_t     windowUs;  // the simulated pauses between the reads
};

// makeCall()'s #349 path: the window, then the outcome. Time is simulated: a pause is the poll gap.
template <class ReadFn>
PlacedCall placeUnreadCall(ReadFn&& readOnce)
{
	int64_t t = 0;
	const UnreadWindow w = readOwnLegWindow(
		readOnce, [&] { return t; }, [] { return true; }, [](int) {},
		[&] { t += int64_t{ kUnreadAdoptPollMs } * 1000; });
	const UnreadOutcome o = unreadOutcome(!w.ownLeg.empty());
	return PlacedCall{ o != UnreadOutcome::Fail, w.ownLeg, w.reads, t };
}

// The window is main's: a read every kUnreadAdoptPollMs until since + poll reaches kUnreadAdoptWindowUs.
// Reads that fail at once leave 10 reads and 9 pauses of 400 ms. This change adds no wait to it.
constexpr int64_t kInstantFailureWindowUs = kUnreadAdoptWindowUs - int64_t{ kUnreadAdoptPollMs } * 1000;

void expectTheUsual503(const PlacedCall& call, const char* how)
{
	EXPECT_FALSE(call.success) << how << ": makeCall returns false, so 503 (NOT ROUTED for a 911)";
	EXPECT_TRUE(call.ownLeg.empty()) << "no own leg";
	EXPECT_EQ(call.reads, 10) << "the window is unchanged";
	EXPECT_EQ(call.windowUs, kInstantFailureWindowUs) << "no wait added to it";
	std::fprintf(stderr, "[ #948 ] %s: 503 after %d reads, %lld ms of simulated pauses (the unchanged window)\n", how,
	             call.reads, static_cast<long long>(call.windowUs / 1000));
}

TEST(SosStatusUnread, ASosCallIs503WhenTheListIsOverTheArena)
{
	SosListRead list;
	ASSERT_TRUE(reserveReal(list.arena, 1024));
	list.response.body = patternBody(1025);
	const PlacedCall call = placeUnreadCall([&] { return list(); });
	EXPECT_EQ(list.gets, call.reads) << "every read was a real GET, refused as over the arena";
	expectTheUsual503(call, "list over the arena");
}

TEST(SosStatusUnread, ASosCallIs503WhenTheListReadIsShort)
{
	SosListRead list;
	ASSERT_TRUE(reserveReal(list.arena, 4096));
	list.response.body  = patternBody(900);
	list.response.endAt = 400;
	const PlacedCall call = placeUnreadCall([&] { return list(); });
	EXPECT_EQ(list.gets, call.reads);
	expectTheUsual503(call, "short read");
}

TEST(SosStatusUnread, ASosCallIs503WhenAnOverlapping911HoldsTheClaim)
{
	SosListRead list;
	ASSERT_TRUE(reserveReal(list.arena, 4096));
	list.response.body = patternBody(300);
	list.claim.store(true);   // the other 911's GET is mid-flight for the whole window
	const PlacedCall call = placeUnreadCall([&] { return list(); });
	EXPECT_EQ(list.gets, 0) << "no GET was issued on the held handle";
	EXPECT_EQ(list.witness.count(SosFallback::Get), static_cast<uint32_t>(call.reads)) << "the fallback, every read";
	EXPECT_EQ(list.pauses.load(), 0) << "the 911 never waits for the claim: no vTaskDelay on its path";
	EXPECT_LE(list.slowestUs, 10'000) << "each read returns within the 10 ms bound";
	EXPECT_TRUE(list.claim.load()) << "the other holder's claim is untouched";
	expectTheUsual503(call, "overlapping 911 holding the claim");
}

TEST(SosStatusUnread, AnyOtherCallWhoseReadsAllFailIsRefusedTheSameWay)
{
	// Control: the refusal does not depend on how the reads failed or on the lane.
	const PlacedCall call = placeUnreadCall([] { return std::string(); });
	expectTheUsual503(call, "any read that shows no leg");
}

TEST(SosStatusUnread, AListedLegIsAdopted)
{
	SosListRead list;
	ASSERT_TRUE(reserveReal(list.arena, 4096));
	list.response.body = patternBody(300);
	const PlacedCall call = placeUnreadCall([&] { return list(); });
	EXPECT_TRUE(call.success);
	EXPECT_EQ(call.ownLeg, "517");
	EXPECT_EQ(call.reads, 1);
}

TEST(SosStatusUnread, TheOutcomeTable)
{
	EXPECT_EQ(unreadOutcome(true), UnreadOutcome::Adopt);
	EXPECT_EQ(unreadOutcome(false), UnreadOutcome::Fail) << "the 503 stands for a 911/933 as for any call";
}

// ── start()'s warm GET ───────────────────────────────────────────────────────

// The warm GET runs after the WS connects (TelephonyAnchorClient.cpp start(), step 3b), so for about a
// second a 911 can land while it holds the sos claim. The reviewed fast-fail: the 911's status GET
// fails at once, resolveDevice() fails and makeCall() uses the legacy makecall endpoint, and the call
// still routes. The host cannot run makeCall()/resolveDevice(); test_anchor_sos_status_bounded.py pins
// that wiring by source text. These pin the claim, the GET result, and the #349 window.
TEST(SosStatusWarm, A911GetDuringTheWarmGetFailsAtOnceAndReadsNothing)
{
	SosListRead list;
	ASSERT_TRUE(reserveReal(list.arena, 4096));
	list.response.body = patternBody(300);
	list.claim.store(true);   // the warm GET holds the claim

	const std::string leg = list();
	EXPECT_TRUE(leg.empty()) << "no status read: an error, not a stale answer";
	EXPECT_EQ(list.gets, 0);
	EXPECT_EQ(list.pauses.load(), 0) << "the 911 does not wait for the warm GET";
	EXPECT_LE(list.slowestUs, 10'000);
	EXPECT_EQ(list.witness.count(SosFallback::Get), 1u) << "a real 911 fallback, so it is counted";
	EXPECT_TRUE(list.claim.load()) << "the warm GET's claim is untouched";
}

TEST(SosStatusWarm, A911InTheUnreadWindowDuringTheWarmGetIsNotRefused)
{
	// The warm GET holds the claim for about a second: the first reads of the #349 window fail at once,
	// then it lets go and a real read finds the leg. The window is 3.6 s, so the warm GET alone cannot
	// run it out.
	SosListRead list;
	ASSERT_TRUE(reserveReal(list.arena, 4096));
	list.response.body = patternBody(300);
	list.claim.store(true);
	int reads = 0;
	const PlacedCall call = placeUnreadCall([&] {
		if (++reads == 4) list.claim.store(false);   // after 3 refused reads and 3 pauses of 400 ms: 1.2 s
		return list();
	});
	EXPECT_TRUE(call.success) << "not refused: the call routes";
	EXPECT_EQ(call.ownLeg, "517") << "and its own leg is adopted";
	EXPECT_EQ(call.reads, 4);
	EXPECT_EQ(list.witness.count(SosFallback::Get), 3u) << "three reads fast-failed";
	EXPECT_EQ(list.pauses.load(), 0);
	EXPECT_LT(call.windowUs, kUnreadAdoptWindowUs);
}

TEST(SosStatusWarm, AWarmGetThatLosesTheClaimBurnsNoWitnessLine)
{
	pdwitness::clear();
	SosWitness w;
	std::atomic<bool> claim{true};   // somebody holds it
	for (int i = 0; i < 5; ++i)
	{
		SosStatusClaim c(&claim, kSosGetClaimBoundUs, 1000, steadyUs, pauseOneMs);
		ASSERT_FALSE(c.held());
		noteGetFallback(w, /*warm=*/true);
	}
	EXPECT_EQ(w.count(SosFallback::Get), 0u) << "the warm GET is not a 911";
	EXPECT_EQ(pdwitness::count("911 status GET: handle claim held"), 0u);

	// the three lines a real 911 fallback is entitled to are all still there
	for (int i = 0; i < 4; ++i) noteGetFallback(w, /*warm=*/false);
	EXPECT_EQ(w.count(SosFallback::Get), 4u);
	EXPECT_EQ(pdwitness::count("911 status GET: handle claim held"), static_cast<std::size_t>(SosWitness::kLinesPerSite));
}

// ── The largest body read this boot ──────────────────────────────────────────

TEST(SosStatusBodyWitness, TheMaxTracksAndALineIsWrittenOnlyWhenItGrows)
{
	pdwitness::clear();
	SosBodyWitness w;
	EXPECT_TRUE(w.noteBody(430, 12288));
	EXPECT_FALSE(w.noteBody(430, 12288)) << "no growth, no line";
	EXPECT_FALSE(w.noteBody(100, 12288));
	EXPECT_TRUE(w.noteBody(2000, 12288));
	EXPECT_EQ(w.maxBody(), 2000u);
	EXPECT_EQ(pdwitness::count("911 status body: "), 2u);
	EXPECT_EQ(pdwitness::count("911 status body: 2000 B, the largest this boot, in a 12288 B arena"), 1u);
}

TEST(SosStatusBodyWitness, TheLineCapHoldsButTheMaxKeepsTracking)
{
	pdwitness::clear();
	SosBodyWitness w;
	for (std::size_t i = 1; i <= 12; ++i) w.noteBody(i * 100, 12288);
	EXPECT_EQ(w.growLines(), SosBodyWitness::kLinesPerKind);
	EXPECT_EQ(pdwitness::count("911 status body: "), static_cast<std::size_t>(SosBodyWitness::kLinesPerKind));
	EXPECT_EQ(w.maxBody(), 1200u) << "the cap limits the log, not the tracking";
	EXPECT_EQ(SosBodyWitness::kLinesPerKind, 8u);
}

TEST(SosStatusBodyWitness, AnOversizeBodyLogsItsContentLengthOnItsOwnCap)
{
	pdwitness::clear();
	SosBodyWitness w;
	for (int i = 0; i < 12; ++i) w.noteBody(static_cast<std::size_t>(i + 1) * 10, 12288);   // spend the growth lines
	EXPECT_TRUE(w.noteOversize(13000, 12288)) << "not starved by the growth lines";
	EXPECT_TRUE(w.noteOversize(-1, 12288));
	EXPECT_EQ(pdwitness::count("911 status body over the 12288 B arena: content-length 13000 B"), 1u);
	EXPECT_EQ(pdwitness::count("content-length -1 B, -1 is unknown"), 1u);
	for (int i = 0; i < 10; ++i) w.noteOversize(20000, 12288);
	EXPECT_EQ(w.oversizeLines(), SosBodyWitness::kLinesPerKind);
}

// ── Witness ──────────────────────────────────────────────────────────────────

TEST(SosStatusWitness, EachSiteWritesItsFirstLinesOnlyAndCountsEveryFallback)
{
	pdwitness::clear();
	SosWitness w;
	for (int i = 0; i < 10; ++i) w.note(SosFallback::Teardown);
	for (int i = 0; i < 2; ++i) w.note(SosFallback::Get);

	EXPECT_EQ(pdwitness::count("teardown claim not won within the bound"), static_cast<std::size_t>(SosWitness::kLinesPerSite))
		<< "capped per boot";
	EXPECT_EQ(pdwitness::count("911 status GET: handle claim held"), 2u) << "the other site has its own cap";
	EXPECT_EQ(w.count(SosFallback::Teardown), 10u);
	EXPECT_EQ(w.count(SosFallback::Get), 2u);
}

// ── #977: every list read of the #349 window errored; look for the orphan and drop it ─────────
// Owner ruling on #977 (option 2): the 503 stands, at the same moment, and nothing is answered early or
// adopted. A sweep after makeCall() has returned reads the list again and drops the one leg it finds.
// TelephonyAnchorClient.cpp is ESP-only; these drive the decisions it calls (SosStatusGet.hpp), and
// tests/tools/test_anchor_orphan_sweep.py pins the wiring by source text.

// A sweep on a simulated clock: only the pauses move time, and the sweep is armed at 0. The n-th read
// answers script[n] (the last one repeats). Every step is recorded, in order.
struct SweepRun
{
	std::vector<OrphanRead>  script;
	int64_t                  t         = 0;
	bool                     keepGoing = true;
	bool                     dropOk    = true;
	int                      readNo    = 0;
	int                      pauses    = 0;
	std::vector<std::string> events;

	OrphanSweepResult run()
	{
		if (script.empty()) script.push_back(OrphanRead{});
		return runOrphanSweep(
			0,
			[&] {
				events.push_back("read");
				const std::size_t i = std::min(static_cast<std::size_t>(readNo), script.size() - 1);
				++readNo;
				return script[i];
			},
			[&] { return t; },
			[&] { return keepGoing; },
			[&] {
				events.push_back("pause");
				++pauses;
				t += int64_t{ kOrphanSweepPollMs } * 1000;
			},
			[&](const std::string& leg) { events.push_back("hold:" + leg); },
			[&](const std::string& leg) {
				events.push_back("drop:" + leg);
				return dropOk;
			});
	}

	int count(const char* prefix) const
	{
		int n = 0;
		for (const std::string& e : events) n += e.compare(0, std::strlen(prefix), prefix) == 0 ? 1 : 0;
		return n;
	}
};

TEST(SosOrphanSweep, ASweepIsWantedOnlyForA911WhoseEveryListReadErrored)
{
	const UnreadOutcome fail = UnreadOutcome::Fail;
	EXPECT_TRUE(orphanSweepWanted(/*sosLane=*/true, fail, /*reads=*/10, /*listsRead=*/0)) << "all ten reads errored";
	EXPECT_TRUE(orphanSweepWanted(true, fail, 1, 0)) << "the anchor stopping after the first read";
	EXPECT_FALSE(orphanSweepWanted(false, fail, 10, 0)) << "an ordinary call is refused as on main";
	EXPECT_FALSE(orphanSweepWanted(true, UnreadOutcome::Adopt, 4, 0)) << "a leg was listed and is adopted";
	EXPECT_FALSE(orphanSweepWanted(true, fail, 10, 1)) << "3CX answered the list once: its answer was no leg";
	EXPECT_FALSE(orphanSweepWanted(true, fail, 10, 10)) << "3CX answered every read: no leg";
	EXPECT_FALSE(orphanSweepWanted(true, fail, 0, 0)) << "no read was made";
}

TEST(SosOrphanSweep, TheCallerStillGetsTheUsual503AtTheSameTimeAndTheSweepIsDecidedAfterIt)
{
	// The window and its outcome are the ones SosStatusUnread pins; the sweep adds nothing to them.
	int64_t t = 0;
	int pauses = 0;
	const UnreadWindow w = readOwnLegWindow(
		[] { return std::string(); },   // every list read errored: no leg, and no list shown
		[&] { return t; }, [] { return true; }, [](int) {},
		[&] {
			++pauses;
			t += int64_t{ kUnreadAdoptPollMs } * 1000;
		});
	const UnreadOutcome outcome = unreadOutcome(!w.ownLeg.empty());
	EXPECT_EQ(outcome, UnreadOutcome::Fail) << "the 503 stands: no early answer, no adopted leg";
	EXPECT_TRUE(w.ownLeg.empty());
	EXPECT_EQ(w.reads, 10);
	EXPECT_EQ(pauses, 9);
	EXPECT_EQ(t, kInstantFailureWindowUs) << "the window, and so the moment of the 503, is unchanged";
	EXPECT_TRUE(orphanSweepWanted(/*sosLane=*/true, outcome, w.reads, /*listsRead=*/0))
		<< "the sweep is decided from the window's outcome alone: it moves nothing the caller sees";
}

TEST(SosOrphanSweep, TheStepTable)
{
	const int64_t lastRead = kOrphanSweepWindowUs - int64_t{ kOrphanSweepPollMs } * 1000;
	EXPECT_EQ(orphanSweepStep(1, 0), OrphanSweepStep::Drop) << "one candidate is the orphan";
	EXPECT_EQ(orphanSweepStep(1, kOrphanSweepWindowUs * 3), OrphanSweepStep::Drop) << "a leg on a late read is still dropped";
	EXPECT_EQ(orphanSweepStep(2, 0), OrphanSweepStep::Ambiguous) << "one of two may be a PSAP callback";
	EXPECT_EQ(orphanSweepStep(5, lastRead), OrphanSweepStep::Ambiguous);
	EXPECT_EQ(orphanSweepStep(0, 0), OrphanSweepStep::ReadAgain) << "a failed read, or a list with no candidate yet";
	EXPECT_EQ(orphanSweepStep(0, lastRead - 1), OrphanSweepStep::ReadAgain);
	EXPECT_EQ(orphanSweepStep(0, lastRead), OrphanSweepStep::GiveUp) << "no read starts once the bound would pass";
	EXPECT_EQ(orphanSweepStep(0, kOrphanSweepWindowUs * 10), OrphanSweepStep::GiveUp);
}

TEST(SosOrphanSweep, TheSweepReadsAgainAndDropsTheOneLegItFinds)
{
	SweepRun s;
	s.script = { { "", 0 }, { "", 0 }, { "517", 1 } };   // two reads that errored, then the list shows the leg
	const OrphanSweepResult r = s.run();
	EXPECT_EQ(r.end, OrphanSweepEnd::Dropped);
	EXPECT_EQ(r.reads, 3);
	EXPECT_EQ(r.leg, "517");
	const std::vector<std::string> expected = { "read", "pause", "read", "pause", "read", "hold:517", "drop:517" };
	EXPECT_EQ(s.events, expected) << "a pause between reads only, and the leg is noted as ours before its drop";
	EXPECT_EQ(s.t, 2 * int64_t{ kOrphanSweepPollMs } * 1000) << "a vTaskDelay-sized gap per pause, nothing else";
}

TEST(SosOrphanSweep, ASweepThatNeverSeesALegGivesUpWithinTheBoundAndDropsNothing)
{
	SweepRun s;   // every read errors
	const OrphanSweepResult r = s.run();
	EXPECT_EQ(r.end, OrphanSweepEnd::GaveUp);
	EXPECT_EQ(r.reads, 10) << "the window's own count: a read every 400 ms while another still fits";
	EXPECT_EQ(s.pauses, 9);
	EXPECT_EQ(s.t, kInstantFailureWindowUs);
	EXPECT_LT(s.t, kOrphanSweepWindowUs) << "never the whole bound spent asleep";
	EXPECT_EQ(s.count("hold:"), 0);
	EXPECT_EQ(s.count("drop:"), 0) << "nothing found, nothing dropped";
	EXPECT_TRUE(r.leg.empty());
}

TEST(SosOrphanSweep, TwoCandidatesAreNeverDroppedBecauseOneMayBeAPsapCallback)
{
	SweepRun s;
	s.script = { { "517", 2 } };   // resolveOutboundLeg picked one of two candidates
	const OrphanSweepResult r = s.run();
	EXPECT_EQ(r.end, OrphanSweepEnd::Ambiguous);
	EXPECT_EQ(r.reads, 1);
	EXPECT_EQ(s.pauses, 0) << "ends at once: waiting does not tell the two legs apart";
	EXPECT_EQ(s.count("hold:"), 0);
	EXPECT_EQ(s.count("drop:"), 0) << "a leg left up is better than a PSAP callback hung up";
	EXPECT_TRUE(r.leg.empty());
}

TEST(SosOrphanSweep, ASweepTelMaintReachesAfterTheBoundReadsNothing)
{
	SweepRun late;
	late.t = kOrphanSweepWindowUs;   // a restart job ran first on tel_maint
	const OrphanSweepResult r = late.run();
	EXPECT_EQ(r.end, OrphanSweepEnd::TooLate);
	EXPECT_EQ(r.reads, 0);
	EXPECT_TRUE(late.events.empty()) << "no read, no pause, no drop: the hold has lapsed with the bound";

	SweepRun justInside;
	justInside.t = kOrphanSweepWindowUs - 1;
	const OrphanSweepResult r2 = justInside.run();
	EXPECT_EQ(r2.end, OrphanSweepEnd::GaveUp);
	EXPECT_EQ(r2.reads, 1) << "inside the bound it reads once";
	EXPECT_EQ(justInside.pauses, 0);
}

TEST(SosOrphanSweep, AStoppingAnchorEndsTheSweepBeforeItReadsAnything)
{
	SweepRun s;
	s.keepGoing = false;
	s.script = { { "517", 1 } };
	const OrphanSweepResult r = s.run();
	EXPECT_EQ(r.end, OrphanSweepEnd::Stopped);
	EXPECT_EQ(r.reads, 0);
	EXPECT_TRUE(s.events.empty()) << "the client is going away: no read, and no drop on a dying connection";
}

TEST(SosOrphanSweep, AFailedDropIsReportedAndNotRetried)
{
	SweepRun s;
	s.script = { { "517", 1 } };
	s.dropOk = false;
	const OrphanSweepResult r = s.run();
	EXPECT_EQ(r.end, OrphanSweepEnd::DropFailed);
	EXPECT_EQ(r.leg, "517");
	const std::vector<std::string> expected = { "read", "hold:517", "drop:517" };
	EXPECT_EQ(s.events, expected) << "one attempt: dropCall() has its own retry, and the sweep has a bound";
}

TEST(SosOrphanSweep, TheLegIsOursBeforeItsDropAndALateUpsertForItIsNotAnInboundCall)
{
	AnchorOwnLegs own;
	constexpr uint64_t kPostSeq = 40;   // the WS event number when the makecall POST went out
	int64_t t = 0;
	bool oursWhenTheDropWentOut = false;
	const OrphanSweepResult r = runOrphanSweep(
		0,
		[&] { return t < 800'000 ? OrphanRead{} : OrphanRead{ "517", 1 }; },
		[&] { return t; }, [] { return true; },
		[&] { t += int64_t{ kOrphanSweepPollMs } * 1000; },
		[&](const std::string& leg) { own.noteNamed(leg, t, kPostSeq); },   // what the client's hold hook does
		[&](const std::string& leg) {
			oursWhenTheDropWentOut = !inboundAnnounceAllowed(own, leg, t, kPostSeq + 1);
			return true;
		});
	ASSERT_EQ(r.end, OrphanSweepEnd::Dropped);
	EXPECT_TRUE(oursWhenTheDropWentOut) << "an upsert between the hold's end and 3CX's Remove must not ring the handsets";

	// 3CX repeats the orphan's upsert while the drop is in flight: not an inbound call.
	EXPECT_FALSE(inboundAnnounceAllowed(own, "517", t, kPostSeq + 5)) << "the phantom inbound";
	// A PSAP callback is another participant: announced as always.
	EXPECT_TRUE(inboundAnnounceAllowed(own, "518", t, kPostSeq + 5));
	// After 3CX's Remove of 517 the id is released.
	own.release("517", kPostSeq + 10);
	EXPECT_TRUE(inboundAnnounceAllowed(own, "517", t, kPostSeq + 11));
}

TEST(SosOrphanSweep, TheHoldCoversTheGapBetweenThe503AndTheDropAndNoLonger)
{
	// makeCall() has returned, so its own pending count is 0 again. The classifier promotes an unmatched
	// upsert to a new inbound call only when the count it sees is 0.
	const int64_t armed = 1'000'000'000;
	const int64_t until = orphanHoldUntil(armed);
	EXPECT_EQ(until, armed + kOrphanSweepWindowUs) << "from the arm, so a queued sweep cannot extend it";
	EXPECT_GE(pendingWithOrphanHold(0, until, armed, true), 1) << "the orphan's repeat upsert right after the 503";
	EXPECT_GE(pendingWithOrphanHold(0, until, until - 1, true), 1);
	EXPECT_EQ(pendingWithOrphanHold(0, until, until, true), 0) << "the hold lapses at the bound, however the job fares";
	EXPECT_EQ(pendingWithOrphanHold(0, until, until + 5'000'000, true), 0);
	EXPECT_EQ(pendingWithOrphanHold(0, 0, armed, true), 0) << "no sweep armed (or the hold taken back): no hold";
	EXPECT_EQ(pendingWithOrphanHold(2, until, armed, true), 2) << "a real pending makeCall count is never changed";
	EXPECT_EQ(pendingWithOrphanHold(2, 0, armed, true), 2);
}

// Rule 5 review of #1040, point 1: the sole candidate is dropped only if it is a leg 3CX upserted while OUR
// makeCall was pending (the orphan is one: it exists from the POST). A PSAP callback is a participant this
// unit never saw in that window, and it is never dropped, however alone it is in the list.
TEST(SosOrphanSweep, ASoleCandidateNeverSeenDuringTheMakeCallIsAPsapCallbackAndIsNeverDropped)
{
	SweepRun s;
	s.script = { { "518", 1, /*stranger=*/true } };
	const OrphanSweepResult r = s.run();
	EXPECT_NE(r.end, OrphanSweepEnd::Dropped);
	EXPECT_EQ(s.count("hold:"), 0) << "not noted as ours: its upserts are announced as the callback they are";
	EXPECT_EQ(s.count("drop:"), 0) << "a callback hung up is worse than an orphan left up";
	EXPECT_EQ(r.end, OrphanSweepEnd::GaveUp);
	EXPECT_EQ(r.reads, 10) << "it keeps looking for the orphan within the bound, and drops nothing else";

	SweepRun orphan;   // positive control: the same lone leg, seen during the makeCall, is the orphan
	orphan.script = { { "517", 1, /*stranger=*/false } };
	EXPECT_EQ(orphan.run().end, OrphanSweepEnd::Dropped);
	EXPECT_EQ(orphan.count("drop:"), 1);
}

// Point 2: the hold swallows only an upsert whose id was already upserted while a makeCall was pending.
TEST(SosOrphanSweep, TheHoldNeverSwallowsAnUpsertForAnIdTheMakeCallNeverSaw)
{
	const int64_t until = orphanHoldUntil(1'000'000'000);
	const int64_t now   = 1'000'000'000;
	EXPECT_EQ(pendingWithOrphanHold(0, until, now, /*idSeenInWindow=*/false), 0)
		<< "a PSAP callback right after the 503 is promoted at once, not held for up to 4 s";
	EXPECT_GE(pendingWithOrphanHold(0, until, now, /*idSeenInWindow=*/true), 1) << "the orphan's repeat upsert is still held";
	EXPECT_EQ(pendingWithOrphanHold(2, until, now, false), 2) << "a real pending count is never changed";
}

TEST(SosOrphanSweep, TheIdsSeenWhileAMakeCallWasPendingAreAFixedTableScopedToTheSweepsWindow)
{
	constexpr uint64_t kPostSeq = 40;   // the WS event number when the makecall POST went out
	constexpr uint64_t kArmSeq  = 60;   // the WS event number when the sweep was armed
	PendingSeenIds<4, 8> ids;
	EXPECT_FALSE(ids.seenIn("517", kPostSeq, kArmSeq));
	EXPECT_FALSE(ids.anyIn(kPostSeq, kArmSeq));
	ids.note("517", kPostSeq + 3, 1);
	EXPECT_TRUE(ids.seenIn("517", kPostSeq, kArmSeq)) << "upserted after the POST while pending: the orphan";
	EXPECT_TRUE(ids.anyIn(kPostSeq, kArmSeq));
	EXPECT_FALSE(ids.seenIn("518", kPostSeq, kArmSeq)) << "another participant: a callback";
	EXPECT_FALSE(ids.seenIn("", kPostSeq, kArmSeq)) << "no id is never seen";

	// A PSAP callback that arrived during an EARLIER makeCall's pending window was ignored then (#888) and
	// stays listed unslotted. It is not this POST's orphan, and it must never become the sweep's drop.
	ids.note("519", kPostSeq - 7, 1);
	EXPECT_FALSE(ids.seenIn("519", kPostSeq, kArmSeq)) << "seen before this POST: a stranger, not held, not dropped";
	// And one that arrived during a LATER makeCall's window (a redial after the arm) is past the window.
	ids.note("520", kArmSeq + 5, 1);
	EXPECT_FALSE(ids.seenIn("520", kPostSeq, kArmSeq)) << "seen after the arm: a stranger";
	// The first sighting stands: a later one (the orphan's repeat upsert during a redial) neither moves it out of
	// the window nor, for an id first seen outside it, into it.
	ids.note("517", kArmSeq + 20, 1);
	EXPECT_TRUE(ids.seenIn("517", kPostSeq, kArmSeq)) << "the orphan's repeat upsert during a redial keeps it seen";
	ids.note("519", kPostSeq + 9, 1);
	EXPECT_FALSE(ids.seenIn("519", kPostSeq, kArmSeq)) << "a later sighting does not move a stranger into the window";
	ids.note("517", kPostSeq - 30, 1);
	EXPECT_TRUE(ids.seenIn("517", kPostSeq, kArmSeq)) << "an older number does not move it out either";

	ids.note("a-very-long-id", kPostSeq + 1, 1);   // does not fit: not recorded
	EXPECT_FALSE(ids.seenIn("a-very-long-id", kPostSeq, kArmSeq));
	for (const char* id : { "1", "2", "3", "4" }) ids.note(id, kPostSeq + 10, 1);   // four slots: 517 is the oldest
	EXPECT_FALSE(ids.seenIn("517", kPostSeq, kArmSeq)) << "evicted: announced and not dropped, the safe direction";
	EXPECT_TRUE(ids.seenIn("4", kPostSeq, kArmSeq));
}

// A list read's pick whose record carries the given party_dn (the destination of the armed 911 unless said otherwise).
static OrphanRead pick(const char* leg, const char* partyDn = "911", const char* partyCid = "")
{
	OrphanRead rd;
	rd.leg      = leg;
	rd.candidates = 1;
	rd.partyDn  = partyDn;
	rd.partyCid = partyCid;
	return rd;
}

// What the ESP arm does, with the I/O lent in: the read goes through readOrphanOnce (the pending guards and the
// stranger decision), the candidate check through the ring, and the sweep through runOrphanSweep.
struct SweepWorld
{
	static constexpr uint64_t kPostSeq = 40;
	static constexpr uint64_t kArmSeq  = 60;
	PendingSeenIds<8, 32>    ring;
	std::string              dest = "911";   // the number the armed 911 dialed
	std::vector<OrphanRead>  lists;          // what the n-th list read returns (the last repeats)
	std::vector<int>         pendingAtRead;  // _outboundPending at the n-th call to pendingCount (the last repeats)
	UnslottedRecord          unslotted;                  // a 911 that succeeded with no own leg
	bool                     restartRequested = false;   // a restart is wanted (a WS drop with a stale token)
	bool                     unslottedDuringRead = false; // it happens while the first list read is in flight
	int                      readNo = 0, readNo2 = 0;
	int64_t                  t = 0;
	std::vector<std::string> events;

	OrphanSweepResult run()
	{
		if (lists.empty()) lists.push_back(OrphanRead{});
		if (pendingAtRead.empty()) pendingAtRead.push_back(0);
		return runOrphanSweep(
			0,
			[&] {
				events.push_back("read");
				const int attempt = readNo2++;
				return readOrphanOnce(
					[&] {
						const std::size_t i = std::min(static_cast<std::size_t>(readNo), lists.size() - 1);
						++readNo;
						if (unslottedDuringRead) unslotted.note();
						return lists[i];
					},
					[&] { return pendingAtRead[std::min(static_cast<std::size_t>(attempt), pendingAtRead.size() - 1)]; },
					[] { return int64_t{ 0 }; },
					[&](const std::string& leg) { return ring.seenIn(leg, kPostSeq, kArmSeq); }, dest);
			},
			[&] { return t; }, [&] { return sweepMayContinue(true, restartRequested); },
			[&] {
				events.push_back("pause");
				t += int64_t{ kOrphanSweepPollMs } * 1000;
			},
			[&](const std::string& leg) { events.push_back("hold:" + leg); },
			[&](const std::string& leg) {
				events.push_back("drop:" + leg);
				return true;
			},
			[&] { return ring.anyIn(kPostSeq, kArmSeq); },
			[&] { return unslotted.recorded(); });
	}

	int count(const char* prefix) const
	{
		int n = 0;
		for (const std::string& e : events) n += e.compare(0, std::strlen(prefix), prefix) == 0 ? 1 : 0;
		return n;
	}
};

// Opus review of #1040, blocker 1. 911-A fails and the sweep arms; the user redials 911-B within the window; a
// PSAP callback arrives while B is pending and #888 ignores it (and notes it). It is the only leg in the list.
TEST(SosOrphanSweep, APsapCallbackThatArrivesDuringARedialIsNeverDropped)
{
	SweepWorld w;
	w.ring.note("517", SweepWorld::kPostSeq + 3, 1);   // A's orphan, upserted while A was pending
	w.ring.note("518", SweepWorld::kArmSeq + 12, 1);   // the callback, during B's pending window
	w.lists = { pick("518") };                     // the orphan is already gone from the list; only the callback is up
	const OrphanSweepResult r = w.run();
	EXPECT_NE(r.end, OrphanSweepEnd::Dropped);
	EXPECT_EQ(w.count("hold:"), 0);
	EXPECT_EQ(w.count("drop:"), 0) << "a callback hung up is worse than an orphan left up";
	EXPECT_EQ(r.end, OrphanSweepEnd::GaveUp);

	SweepWorld orphan;   // positive control: the orphan, seen in the window, is dropped even after a redial repeats it
	orphan.ring.note("517", SweepWorld::kPostSeq + 3, 1);
	orphan.ring.note("517", SweepWorld::kArmSeq + 12, 1);   // its repeat upsert while B is pending
	orphan.lists = { pick("517") };
	EXPECT_EQ(orphan.run().end, OrphanSweepEnd::Dropped);
	EXPECT_EQ(orphan.count("drop:517"), 1);
}

// The same blocker, other half: 911-B succeeded without a resolved own leg of its own, so its live leg is in the
// list, unslotted, and is the sole candidate once B's makeCall has ended.
TEST(SosOrphanSweep, ALiveLegOfTheRedialWhoseOwnLegWasNotResolvedIsNeverDropped)
{
	SweepWorld w;
	w.ring.note("517", SweepWorld::kPostSeq + 3, 1);   // A's orphan
	w.ring.note("601", SweepWorld::kArmSeq + 8, 1);    // B's leg, upserted while B was pending
	w.pendingAtRead = { 1, 0 };                     // the first read is while B is pending, then B is done
	w.lists = { pick("601") };
	const OrphanSweepResult r = w.run();
	EXPECT_EQ(w.count("drop:"), 0) << "B's live call is not the orphan";
	EXPECT_EQ(w.count("hold:"), 0);
	EXPECT_NE(r.end, OrphanSweepEnd::Dropped);
	EXPECT_GE(r.reads, 2) << "the read made while B was pending decided nothing, and the sweep read again";
}

// Blocker 3: when no leg was upserted in the window nothing can be a candidate, so there is nothing to read for.
// Opus review of #1040, round 3, A. A callback for an EARLIER dropped 911 lands inside A's window: #888 ignores it
// and it is noted as seen. A's orphan is missing from the list (the POST was rejected, or the orphan already
// ended), so the callback is the sole candidate. Its remote party is the PSAP's number, not what A dialed.
TEST(SosOrphanSweep, ACallbackForAnEarlierDropped911InsideTheWindowIsNeverDroppedEvenSeenAndAlone)
{
	SweepWorld w;
	w.ring.note("518", SweepWorld::kPostSeq + 4, 1);   // the callback, ignored while A alone was pending
	w.lists = { pick("518", "5551234", "5551234") };
	const OrphanSweepResult r = w.run();
	EXPECT_NE(r.end, OrphanSweepEnd::Dropped);
	EXPECT_EQ(w.count("hold:"), 0);
	EXPECT_EQ(w.count("drop:"), 0) << "a PSAP callback is not the orphan: its party is the PSAP, not 911";
	EXPECT_EQ(r.end, OrphanSweepEnd::GaveUp);
}

// B. Two handsets dial 911 together. B's leg is noted with two makeCalls pending, and B succeeded without
// resolving its own leg, so that leg is unslotted, listed, and its party is 911 too.
TEST(SosOrphanSweep, ALegSeenWhileTwoMakeCallsWerePendingIsNeverDropped)
{
	SweepWorld w;
	w.ring.note("601", SweepWorld::kPostSeq + 2, 2);   // B's leg, upserted with A and B both pending
	w.lists = { pick("601", "911") };
	const OrphanSweepResult r = w.run();
	EXPECT_NE(r.end, OrphanSweepEnd::Dropped);
	EXPECT_EQ(w.count("drop:"), 0) << "whose leg it is cannot be told: B's live 911 is not dropped";
	EXPECT_EQ(r.end, OrphanSweepEnd::NoCandidate) << "and with nothing provable in the window there is nothing to read for";
	EXPECT_EQ(w.count("read"), 0);

	PendingSeenIds<4, 8> ids;
	ids.note("601", 50, 2);
	EXPECT_FALSE(ids.seenIn("601", 40, 60));
	EXPECT_FALSE(ids.anyIn(40, 60));
	ids.note("601", 52, 1);   // a later sighting with one pending does not make it provable
	EXPECT_FALSE(ids.seenIn("601", 40, 60));
	ids.note("517", 51, 1);
	EXPECT_TRUE(ids.seenIn("517", 40, 60)) << "positive control: one makeCall pending, in the window";
	EXPECT_TRUE(ids.anyIn(40, 60));
}

TEST(SosOrphanSweep, AnOrphanWhoseRemotePartyIsWhatTheArmed911DialedIsStillDropped)
{
	for (const char* party : { "911", "+911" }) {
		SweepWorld w;
		w.ring.note("517", SweepWorld::kPostSeq + 3, 1);
		w.lists = { pick("517", party) };
		EXPECT_EQ(w.run().end, OrphanSweepEnd::Dropped) << party;
		EXPECT_EQ(w.count("drop:517"), 1) << party;
	}
	SweepWorld cid;   // the number can be in party_caller_id instead of party_dn
	cid.ring.note("517", SweepWorld::kPostSeq + 3, 1);
	cid.lists = { pick("517", "", "933") };
	cid.dest = "933";
	EXPECT_EQ(cid.run().end, OrphanSweepEnd::Dropped);
	EXPECT_TRUE(partyIsDestination("911", "911", ""));
	EXPECT_TRUE(partyIsDestination("911", "x", "911"));
	EXPECT_FALSE(partyIsDestination("911", "9111", "")) << "equal, not a prefix";
	EXPECT_FALSE(partyIsDestination("", "911", "911")) << "no destination proves nothing";
}

TEST(SosOrphanSweep, ALegWhoseRecordCarriesNoPartyIsNotProvablyTheOrphanAndIsNotDropped)
{
	SweepWorld w;
	w.ring.note("517", SweepWorld::kPostSeq + 3, 1);
	w.lists = { pick("517", "", "") };
	const OrphanSweepResult r = w.run();
	EXPECT_NE(r.end, OrphanSweepEnd::Dropped);
	EXPECT_EQ(w.count("drop:"), 0);
	EXPECT_EQ(w.count("hold:"), 0);
	EXPECT_EQ(r.end, OrphanSweepEnd::GaveUp);
}

// Opus review of #1040, round 4, 1. A makeCall for a second 911 got 200 with no result.id and its list read failed,
// so it returned success with no own leg: a live 911 with no slot. Its first upsert arrives while A's window is
// open and A alone is pending, so it is noted with count 1, its party is 911, and it is the sole candidate.
TEST(SosOrphanSweep, ALive911ThatSucceededWithNoOwnLegAfterThePostIsNeverDropped)
{
	SweepWorld w;
	w.ring.note("601", SweepWorld::kPostSeq + 9, 1);
	w.lists = { pick("601", "911") };
	w.unslotted.note();   // the second 911's POST, after A's
	const OrphanSweepResult r = w.run();
	EXPECT_EQ(r.end, OrphanSweepEnd::UnslottedLiveEmergency);
	EXPECT_EQ(w.count("drop:"), 0) << "that leg is a live 911";
	EXPECT_EQ(w.count("hold:"), 0);
	EXPECT_EQ(r.reads, 0) << "it ends before spending a read";

	SweepWorld during;   // the second 911 returns while the sweep's read is in flight
	during.ring.note("601", SweepWorld::kPostSeq + 9, 1);
	during.lists = { pick("601", "911") };
	during.unslottedDuringRead = true;
	const OrphanSweepResult r2 = during.run();
	EXPECT_EQ(r2.end, OrphanSweepEnd::UnslottedLiveEmergency);
	EXPECT_EQ(r2.reads, 1);
	EXPECT_EQ(during.count("drop:"), 0) << "checked again before the drop";

	// B got 200 with no id and a failed list read BEFORE A: it has no slot and no media, so the caller redialed (A).
	// B's ~750 ms repeat upsert is first seen inside A's window, with one makeCall pending and party 911: it looks
	// exactly like A's orphan, and it is a live PSAP call.
	SweepWorld before;
	before.ring.note("517", SweepWorld::kPostSeq + 3, 1);
	before.lists = { pick("517", "911") };
	before.unslotted.note();
	const OrphanSweepResult r3 = before.run();
	EXPECT_EQ(r3.end, OrphanSweepEnd::UnslottedLiveEmergency);
	EXPECT_EQ(before.count("drop:"), 0) << "an earlier unslotted live 911 is never dropped either";

	SweepWorld none;   // positive control: with none recorded the same orphan is dropped
	none.ring.note("517", SweepWorld::kPostSeq + 3, 1);
	none.lists = { pick("517", "911") };
	EXPECT_EQ(none.run().end, OrphanSweepEnd::Dropped);

	UnslottedRecord rec;
	EXPECT_FALSE(rec.recorded()) << "none recorded";
	EXPECT_TRUE(rec.note());
	EXPECT_TRUE(rec.recorded()) << "any recorded, before or after A's POST";
}

// Opus review of #1040, round 6, 1. _wsSeq starts at 0 and only participant events advance it, so a 911 that is the
// first call after boot and hits the no-own-leg branch has a POST seq of 0. That is a record, not "none".
TEST(SosOrphanSweep, AnUnslotted911WhosePostSeqIsZeroStillEndsEverySweep)
{
	UnslottedRecord rec;
	EXPECT_TRUE(rec.note()) << "the first one: the caller logs that the sweep is disabled";
	EXPECT_TRUE(rec.recorded());
	EXPECT_FALSE(rec.note()) << "logged once";

	SweepWorld w;
	w.unslotted.note();
	w.ring.note("517", SweepWorld::kPostSeq + 3, 1);
	w.lists = { pick("517", "911") };
	const OrphanSweepResult r = w.run();
	EXPECT_EQ(r.end, OrphanSweepEnd::UnslottedLiveEmergency);
	EXPECT_EQ(w.count("drop:"), 0) << "B's live PSAP call is not dropped";
}

// 2. tel_maint runs the sweep, and a restart queues behind it; makeCall refuses 911s while the anchor is down. A
// sweep never delays a restart: it yields at once when one is wanted, before a read and before a drop.
TEST(SosOrphanSweep, ARestartWantedWhileASweepIsArmedIsNotDelayedByIt)
{
	EXPECT_TRUE(sweepMayContinue(true, false));
	EXPECT_FALSE(sweepMayContinue(true, true)) << "a restart is wanted";
	EXPECT_FALSE(sweepMayContinue(false, false)) << "the anchor is stopping";

	SweepWorld w;
	w.ring.note("517", SweepWorld::kPostSeq + 3, 1);
	w.lists = { pick("517", "911") };
	w.restartRequested = true;
	const OrphanSweepResult r = w.run();
	EXPECT_EQ(r.end, OrphanSweepEnd::Stopped);
	EXPECT_EQ(r.reads, 0);
	EXPECT_TRUE(w.events.empty()) << "no read, no pause, no drop in front of the restart";

	SweepWorld during;   // the restart is wanted while the read is in flight: the drop POST would delay it
	during.ring.note("517", SweepWorld::kPostSeq + 3, 1);
	during.lists = { pick("517", "911") };
	OrphanSweepResult r2 = runOrphanSweep(
		0,
		[&] { during.restartRequested = true; return pick("517", "911"); },
		[&] { return during.t; }, [&] { return sweepMayContinue(true, during.restartRequested); },
		[&] { during.events.push_back("pause"); },
		[&](const std::string& leg) { during.events.push_back("hold:" + leg); },
		[&](const std::string& leg) { during.events.push_back("drop:" + leg); return true; });
	EXPECT_EQ(r2.end, OrphanSweepEnd::Stopped);
	EXPECT_EQ(r2.reads, 1);
	EXPECT_EQ(during.count("drop:"), 0);
	EXPECT_EQ(during.count("hold:"), 0);
}

// 2. The arm's window, number and time are one snapshot: a take never pairs one arm's window with another's number.
TEST(SosOrphanSweep, TheArmedWindowAndNumberAreTakenTogetherAndOnlyOnce)
{
	OrphanArmSlot slot;
	OrphanArmSlot::Snapshot snap;
	EXPECT_FALSE(slot.take(snap)) << "nothing armed";

	slot.arm(1000, 40, 60, "911");
	slot.arm(2000, 70, 90, "+1 (933)");   // a second 911 arms before tel_maint runs
	ASSERT_TRUE(slot.take(snap));
	EXPECT_EQ(snap.armedUs, 2000);
	EXPECT_EQ(snap.postSeq, 70u);
	EXPECT_EQ(snap.armSeq, 90u);
	EXPECT_STREQ(snap.dest, "1933") << "digits only";
	EXPECT_FALSE(slot.take(snap)) << "an arm is spent once";
	EXPECT_EQ(slot.postSeq(), 70u) << "the window stays readable for the hold";
	EXPECT_EQ(slot.armSeq(), 90u);

	slot.arm(3000, 100, 120, "123456789012345678901234");
	ASSERT_TRUE(slot.take(snap));
	EXPECT_EQ(std::strlen(snap.dest), OrphanArmSlot::kDestDigits) << "within a std::string's own buffer: no heap";
	slot.arm(4000, 130, 150, "911");
	slot.disarm();
	EXPECT_FALSE(slot.take(snap)) << "a wake with no worker takes the arm back";
}

TEST(SosOrphanSweep, WithNoLegUpsertedInTheWindowTheSweepEndsAtOnceWithoutReading)
{
	SweepWorld none;   // an empty ring: the WS delivered nothing (or another outbound call kept it from being noted)
	none.lists = { pick("517") };
	const OrphanSweepResult r = none.run();
	EXPECT_EQ(r.end, OrphanSweepEnd::NoCandidate);
	EXPECT_EQ(r.reads, 0);
	EXPECT_TRUE(none.events.empty()) << "no read, no pause, no TLS handshake for nothing";

	SweepWorld outside;   // ids only outside (postSeq, armSeq] do not make a candidate either
	outside.ring.note("519", SweepWorld::kPostSeq - 1, 1);
	outside.ring.note("520", SweepWorld::kArmSeq + 1, 1);
	EXPECT_EQ(outside.run().end, OrphanSweepEnd::NoCandidate);
	EXPECT_TRUE(outside.events.empty());

	SweepWorld some;   // positive control: one id in the window and the sweep reads
	some.ring.note("517", SweepWorld::kArmSeq, 1);
	some.lists = { pick("517") };
	EXPECT_EQ(some.run().end, OrphanSweepEnd::Dropped);
}

TEST(SosOrphanSweep, ASweepReadDecidesNothingWhileAMakeCallIsInFlightOrFailsToAllocate)
{
	auto seen = [](const std::string&) { return true; };
	const OrphanRead pk = pick("517");

	int reads = 0;
	OrphanRead rd = readOrphanOnce([&] { ++reads; return pk; }, [] { return 1; }, [] { return int64_t{ 5 }; }, seen, "911");
	EXPECT_TRUE(rd.leg.empty());
	EXPECT_EQ(reads, 0) << "a makeCall pending before the read: no read at all";

	int asks = 0;   // a makeCall begins during the read
	rd = readOrphanOnce([&] { return pk; }, [&] { return ++asks == 1 ? 0 : 1; }, [] { return int64_t{ 5 }; }, seen, "911");
	EXPECT_TRUE(rd.leg.empty()) << "pending after the read";

	int64_t since = 5;   // a makeCall began and ended during the read
	rd = readOrphanOnce([&] { since = 9; return pk; }, [] { return 0; }, [&] { return since; }, seen, "911");
	EXPECT_TRUE(rd.leg.empty()) << "the oldest pending began afresh";

	rd = readOrphanOnce([]() -> OrphanRead { throw std::bad_alloc(); }, [] { return 0; }, [] { return int64_t{ 5 }; }, seen, "911");
	EXPECT_TRUE(rd.leg.empty()) << "an allocation failure is a failed read, not a terminate";

	rd = readOrphanOnce([&] { return pk; }, [] { return 0; }, [] { return int64_t{ 5 }; }, seen, "911");   // positive control
	EXPECT_EQ(rd.leg, "517");
	EXPECT_EQ(rd.candidates, 1);
	EXPECT_FALSE(rd.stranger);
	rd = readOrphanOnce([&] { return pk; }, [] { return 0; }, [] { return int64_t{ 5 }; }, [](const std::string&) { return false; }, "911");
	EXPECT_TRUE(rd.stranger) << "a pick the window never saw";
}

TEST(SosOrphanSweepWitness, EachEndIsCountedAndItsLineIsCappedAndCarriesNoNumber)
{
	pdwitness::clear();
	OrphanSweepWitness w;
	for (int i = 0; i < 12; ++i) w.noteEnd(OrphanSweepEnd::GaveUp);
	EXPECT_TRUE(w.noteEnd(OrphanSweepEnd::Dropped));
	EXPECT_TRUE(w.noteEnd(OrphanSweepEnd::DropFailed));
	EXPECT_TRUE(w.noteEnd(OrphanSweepEnd::Ambiguous));
	EXPECT_TRUE(w.noteEnd(OrphanSweepEnd::Stopped));
	EXPECT_TRUE(w.noteEnd(OrphanSweepEnd::TooLate));
	EXPECT_TRUE(w.noteEnd(OrphanSweepEnd::NoCandidate));
	EXPECT_TRUE(w.noteEnd(OrphanSweepEnd::UnslottedLiveEmergency));
	EXPECT_TRUE(w.noteNoWorker());

	EXPECT_EQ(w.count(OrphanSweepEnd::GaveUp), 12u) << "the cap limits the log, not the count";
	EXPECT_EQ(w.count(OrphanSweepEnd::Dropped), 1u);
	EXPECT_EQ(w.count(OrphanSweepEnd::DropFailed), 1u);
	EXPECT_EQ(w.count(OrphanSweepEnd::Ambiguous), 1u);
	EXPECT_EQ(w.count(OrphanSweepEnd::Stopped), 1u);
	EXPECT_EQ(w.count(OrphanSweepEnd::TooLate), 1u);
	EXPECT_EQ(w.noWorker(), 1u);

	EXPECT_EQ(pdwitness::count("911 orphan sweep: no leg listed within the bound, none dropped (#977)"),
	          static_cast<std::size_t>(OrphanSweepWitness::kLinesPerEnd));
	EXPECT_EQ(pdwitness::count("911 orphan sweep: the leg left on 3CX was found and dropped (#977)"), 1u);
	EXPECT_EQ(pdwitness::count("911 orphan sweep: the leg left on 3CX was found, the drop failed (#977)"), 1u);
	EXPECT_EQ(pdwitness::count("911 orphan sweep: more than one candidate leg, none dropped (#977)"), 1u);
	EXPECT_EQ(pdwitness::count("911 orphan sweep: anchor stopping, ended (#977)"), 1u);
	EXPECT_EQ(pdwitness::count("911 orphan sweep: tel_maint reached it after the bound, nothing read (#977)"), 1u);
	EXPECT_EQ(pdwitness::count("911 orphan sweep: no leg was upserted in the window, nothing to find, no read (#977)"), 1u);
	EXPECT_EQ(pdwitness::count("911 orphan sweep: another 911 succeeded with no own leg after this one, its leg may be that live call, none dropped (#977)"), 1u);
	EXPECT_EQ(pdwitness::count("911 orphan sweep: no tel_maint task, not armed (#977)"), 1u);

	const std::vector<std::string> lines = pdwitness::lines();
	EXPECT_EQ(lines.size(), std::size_t{ OrphanSweepWitness::kLinesPerEnd } + 8u);
	for (const std::string& line : lines)
	{
		// Only the issue tag, the emergency lane's name and the PBX's name have digits in them.
		std::string rest = line;
		for (const char* word : { "#977", "911", "3CX" })
		{
			for (std::size_t at; (at = rest.find(word)) != std::string::npos;) rest.erase(at, std::strlen(word));
		}
		EXPECT_TRUE(std::none_of(rest.begin(), rest.end(), [](unsigned char c) { return std::isdigit(c) != 0; }))
			<< "a witness never carries a number: " << line;
	}
}

}  // namespace
