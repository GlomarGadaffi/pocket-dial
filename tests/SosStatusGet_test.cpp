// SosStatusGet_test.cpp -- #948: the 911/933 lane's status GET. The operator ruling on #948:
// the GET allocates only under a failure contract (a failed allocation, a failed or short read
// or a body over the arena is an error, never partial data), and teardown waits at most 10 ms
// for the handle's claim, then takes a fallback. TelephonyAnchorClient.cpp is ESP-only, so
// these drive src/SIP/SosStatusGet.hpp, the code its sos lane calls.

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <future>
#include <string>
#include <thread>

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
BodyRead readAll(const BodyArena& arena, ScriptedRead& src, Out& out)
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

bool reserveReal(BodyArena& a, std::size_t cap)
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
	BodyArena arena;
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
	BodyArena arena;
	ASSERT_TRUE(reserveReal(arena, 1024));
	ScriptedRead src;
	src.body = patternBody(1024);

	std::string out;
	EXPECT_EQ(readAll(arena, src, out), BodyRead::Ok);
	EXPECT_EQ(out, src.body) << "the last byte of the arena is a body byte, not a terminator slot";
}

TEST(SosStatusBody, ABodyOverTheArenaIsAnErrorNeverATruncatedBody)
{
	BodyArena arena;
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
	BodyArena arena;
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
	BodyArena arena;
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
	BodyArena arena;
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
	BodyArena arena;
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

	BodyArena arena;
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
	BodyArena arena;
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
	BodyArena arena;
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
	BodyArena none;
	ScriptedRead any;
	EXPECT_EQ(readAll(none, any, out), BodyRead::NoArena);

	EXPECT_EQ(out.assigns, 0);
	EXPECT_TRUE(out.value.empty());
}

TEST(SosStatusBody, TheArenaIsReservedOnceAndFreedOnce)
{
	g_allocs = g_frees = 0;
	{
		BodyArena arena;
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
	BodyArena         arena;
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

}  // namespace
