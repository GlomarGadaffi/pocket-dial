// TrunkResolver_test.cpp — issue #164: resolving a carrier SBC without
// blocking the SIP thread.
//
// The reason this class exists is untestable on the host: getaddrinfo() under
// ESP-IDF's lwIP is untimed-blocking (~7 s per DNS server, ~21 s with three),
// so it runs on a worker task. What IS testable, and is where the bugs would
// live, is everything around that call:
//
//   * the literal parser, which decides whether a configured host is an
//     ADDRESS or a NAME — and gets that wrong in a security-relevant way if it
//     inherits inet_addr()'s shorthand forms;
//   * the cache, including negative caching, which is what stops a bad name
//     re-queueing a 21 s lookup on every call attempt;
//   * the in-flight state machine, which is what stops two lookups racing.
//
// On host, start-the-worker runs the resolve inline and records a failure
// (there is no getaddrinfo call in the host arm), so the cache and state
// machine are exercisable without the test depending on whatever DNS the build
// machine happens to have. That is deliberate: a test that resolved a real name
// would be a network test pretending to be a unit test.

#include <gtest/gtest.h>

#include <chrono>
#include <cstring>
#include <string>

#include "TrunkResolver.hpp"

namespace
{
	using Clock  = std::chrono::steady_clock;
	using Status = TrunkResolver::Status;

	uint32_t quad(std::string_view s)
	{
		uint32_t v = 0;
		EXPECT_TRUE(TrunkResolver::parseDottedQuad(s, v)) << "expected to parse: " << s;
		return v;
	}
}

// ── The literal parser ───────────────────────────────────────────────────────

TEST(TrunkResolverParse, AcceptsOrdinaryDottedQuads)
{
	uint32_t v = 0;
	EXPECT_TRUE(TrunkResolver::parseDottedQuad("0.0.0.0", v));
	EXPECT_EQ(v, htonl(0x00000000u));

	EXPECT_TRUE(TrunkResolver::parseDottedQuad("255.255.255.255", v));
	EXPECT_EQ(v, htonl(0xFFFFFFFFu));

	EXPECT_TRUE(TrunkResolver::parseDottedQuad("203.0.113.5", v));
	EXPECT_EQ(v, htonl((203u << 24) | (0u << 16) | (113u << 8) | 5u));

	EXPECT_EQ(quad("192.168.1.10"), htonl(0xC0A8010Au));
}

// The point of not using inet_addr(). Each of these is something inet_addr()
// ACCEPTS and maps to some address — so inheriting it would silently turn a
// carrier hostname into a completely different destination rather than
// resolving it. Every one of them must be treated as a NAME.
TEST(TrunkResolverParse, RejectsEveryShorthandInetAddrWouldAccept)
{
	uint32_t v = 0;
	EXPECT_FALSE(TrunkResolver::parseDottedQuad("1.2.3", v))        << "3-part form";
	EXPECT_FALSE(TrunkResolver::parseDottedQuad("1.2", v))          << "2-part form";
	EXPECT_FALSE(TrunkResolver::parseDottedQuad("16909060", v))     << "bare integer";
	EXPECT_FALSE(TrunkResolver::parseDottedQuad("0x7f.0.0.1", v))   << "hex octet";
	EXPECT_FALSE(TrunkResolver::parseDottedQuad("0177.0.0.1", v))   << "octal octet";
}

TEST(TrunkResolverParse, RejectsMalformedAndOutOfRange)
{
	uint32_t v = 0;
	EXPECT_FALSE(TrunkResolver::parseDottedQuad("", v));
	EXPECT_FALSE(TrunkResolver::parseDottedQuad("256.0.0.1", v))    << "octet > 255";
	EXPECT_FALSE(TrunkResolver::parseDottedQuad("1.2.3.4.5", v))    << "five parts";
	EXPECT_FALSE(TrunkResolver::parseDottedQuad("1.2.3.", v))       << "trailing dot";
	EXPECT_FALSE(TrunkResolver::parseDottedQuad(".1.2.3", v))       << "leading dot";
	EXPECT_FALSE(TrunkResolver::parseDottedQuad("1..2.3", v))       << "empty octet";
	EXPECT_FALSE(TrunkResolver::parseDottedQuad("1.2.3.4 ", v))     << "trailing space";
	EXPECT_FALSE(TrunkResolver::parseDottedQuad("1.2.3.4:5060", v)) << "host:port";
	EXPECT_FALSE(TrunkResolver::parseDottedQuad("sbc.carrier.net", v));
}

// A real hostname must never parse as a literal, including ones that start
// with digits — carriers do use names like "1.sbc.example.net".
TEST(TrunkResolverParse, DigitLeadingHostnamesAreNamesNotLiterals)
{
	uint32_t v = 0;
	EXPECT_FALSE(TrunkResolver::parseDottedQuad("1.sbc.example.net", v));
	EXPECT_FALSE(TrunkResolver::parseDottedQuad("10.example.com", v));
}

// ── Literals bypass the cache entirely ───────────────────────────────────────

TEST(TrunkResolver, ADottedQuadResolvesWithoutTouchingTheCache)
{
	TrunkResolver r;
	sockaddr_in addr{};
	const auto now = Clock::now();

	EXPECT_EQ(r.resolve("203.0.113.5", 5060, addr, now), Status::Hit);
	EXPECT_EQ(addr.sin_addr.s_addr, quad("203.0.113.5"));
	EXPECT_EQ(addr.sin_port, htons(5060));
	EXPECT_EQ(addr.sin_family, AF_INET);

	// Spending a cache slot on a literal would evict a real answer for nothing.
	EXPECT_EQ(r.cachedEntries(), 0u);
	EXPECT_FALSE(r.busy()) << "a literal must not start a worker";
}

TEST(TrunkResolver, PortIsAppliedToEveryAnswer)
{
	TrunkResolver r;
	sockaddr_in addr{};
	ASSERT_EQ(r.resolve("198.51.100.7", 5080, addr, Clock::now()), Status::Hit);
	EXPECT_EQ(addr.sin_port, htons(5080));
}

// ── Rejections that must not start work ──────────────────────────────────────

TEST(TrunkResolver, EmptyAndOversizeHostsAreRefusedWithoutAWorker)
{
	TrunkResolver r;
	sockaddr_in addr{};
	const auto now = Clock::now();

	EXPECT_EQ(r.resolve("", 5060, addr, now), Status::Refused);
	EXPECT_FALSE(r.busy());

	const std::string tooLong(TrunkResolver::kMaxHostBytes + 10, 'a');
	EXPECT_EQ(r.resolve(tooLong, 5060, addr, now), Status::Refused);
	EXPECT_FALSE(r.busy());
	EXPECT_EQ(r.cachedEntries(), 0u);
}

// ── Negative caching: the thing that stops a bad name eating the worker ─────

TEST(TrunkResolver, AFailedNameIsRememberedAndAnsweredInstantly)
{
	TrunkResolver r;
	sockaddr_in addr{};
	const auto t0 = Clock::now();

	// On host the worker runs inline and records a failure (no getaddrinfo in
	// the host arm), which is exactly the state this test needs.
	r.resolve("sbc.carrier.invalid", 5060, addr, t0);
	EXPECT_EQ(r.cachedEntries(), 1u);

	// Immediately afterwards the failure answers from cache. Without this, every
	// call attempt would re-queue a ~7-21 s lookup and the worker would never
	// get ahead of the retries.
	EXPECT_EQ(r.lookup("sbc.carrier.invalid", 5060, addr, t0), Status::Failed);
	EXPECT_EQ(r.resolve("sbc.carrier.invalid", 5060, addr, t0), Status::Failed);
}

TEST(TrunkResolver, ANegativeEntryExpiresSoonerThanAPositiveOneWould)
{
	TrunkResolver r;
	sockaddr_in addr{};
	const auto t0 = Clock::now();
	r.resolve("sbc.carrier.invalid", 5060, addr, t0);

	// Still remembered just inside the negative TTL...
	EXPECT_EQ(r.lookup("sbc.carrier.invalid", 5060, addr,
		t0 + TrunkResolver::kNegativeTtl - std::chrono::seconds(1)), Status::Failed);

	// ...and forgotten just after it, so a carrier fixing their DNS is picked up
	// in seconds rather than minutes.
	EXPECT_EQ(r.lookup("sbc.carrier.invalid", 5060, addr,
		t0 + TrunkResolver::kNegativeTtl + std::chrono::seconds(1)), Status::Refused);

	// And the negative TTL really is the short one.
	EXPECT_LT(TrunkResolver::kNegativeTtl, TrunkResolver::kTtl);
}

// ── Cache lifecycle ──────────────────────────────────────────────────────────

TEST(TrunkResolver, ClearDropsEverything)
{
	TrunkResolver r;
	sockaddr_in addr{};
	r.resolve("a.example.net", 5060, addr, Clock::now());
	ASSERT_GT(r.cachedEntries(), 0u);

	// A config change does not make the old answer stale, it makes it WRONG --
	// the operator has pointed the trunk at a different carrier.
	r.clear();
	EXPECT_EQ(r.cachedEntries(), 0u);
}

TEST(TrunkResolver, TheCacheIsBoundedAndNeverGrowsPastItsCap)
{
	TrunkResolver r;
	sockaddr_in addr{};
	const auto now = Clock::now();

	for (int i = 0; i < static_cast<int>(TrunkResolver::kCacheEntries) * 3; ++i)
	{
		r.resolve("sbc" + std::to_string(i) + ".example.net", 5060, addr, now);
	}
	EXPECT_LE(r.cachedEntries(), TrunkResolver::kCacheEntries)
		<< "fixed capacity, no heap growth (CONTRIBUTING_FIRMWARE rule 1)";
}

TEST(TrunkResolver, LookupNeverStartsWork)
{
	TrunkResolver r;
	sockaddr_in addr{};

	// lookup() is the non-committal half of the API: a caller polling it must
	// not accidentally queue a resolution on every poll.
	EXPECT_EQ(r.lookup("sbc.carrier.net", 5060, addr, Clock::now()), Status::Refused);
	EXPECT_EQ(r.cachedEntries(), 0u);
	EXPECT_FALSE(r.busy());
}

// ── The output is always well-formed ─────────────────────────────────────────

TEST(TrunkResolver, TheOutputAddressIsInitialisedEvenOnFailure)
{
	TrunkResolver r;
	sockaddr_in addr{};
	std::memset(&addr, 0xAB, sizeof(addr));   // poison it

	// A caller that ignores the status and uses the address must not end up
	// sending an INVITE to whatever garbage was on the stack.
	EXPECT_EQ(r.resolve("", 5060, addr, Clock::now()), Status::Refused);
	EXPECT_EQ(addr.sin_family, AF_INET);
	EXPECT_EQ(addr.sin_addr.s_addr, 0u);
}
