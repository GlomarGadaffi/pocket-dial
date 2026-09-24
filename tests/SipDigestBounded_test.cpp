// SipDigestBounded_test.cpp -- the allocation-free digest client API (#399).
//
// ── What this file proves, and against what ──────────────────────────────────
//
// The bounded API is a second implementation of an algorithm that already has
// a tested one. Two independent anchors, because either alone is weak:
//
//   1. DIFFERENTIAL, against the std::string API. For every challenge shape in
//      a corpus -- quoting, ordering, whitespace, header names, qop lists,
//      algorithms, the lot -- both APIs must agree on whether it parses, on
//      every field, on whether it can be answered, and on the emitted
//      Authorization value BYTE FOR BYTE. This is what catches a drift in
//      emit order or quoting.
//
//   2. EXTERNAL, against the published RFC vectors that SipDigestClient_test
//      already uses (RFC 2617 §3.5, RFC 7616 §3.9.1, RFC 2069 per Verified
//      Erratum 749). Differential alone would only prove the new code agrees
//      with our OWN old code; if both were wrong the same way, it would pass.
//      The published response values are not ours.
//
// Plus what only the bounded API has: overflow refusal rather than truncation,
// and exact-fit behaviour at every buffer edge.
//
// And the reason the API exists at all: ZERO heap allocations, asserted with
// the binary's one shared counting operator new (tests/support/AllocCounter,
// #426) through its per-thread AllocGuard -- this file does not define its own,
// because a second global operator new would not link.

#include <gtest/gtest.h>

#include <cstring>
#include <string>
#include <vector>

#include "AllocCounter.hpp"
#include "SipDigest.hpp"

using namespace SipDigest;

namespace
{
	// ── Published vectors (same constants as SipDigestClient_test.cpp) ───────
	constexpr const char* k2617Challenge =
		"Digest realm=\"testrealm@host.com\", qop=\"auth,auth-int\", "
		"nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", "
		"opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";
	constexpr const char* k2617Response = "6629fae49393a05397450978507c4ef1";

	constexpr const char* k7616Challenge =
		"WWW-Authenticate: Digest realm=\"http-auth@example.org\", "
		"qop=\"auth, auth-int\", algorithm=MD5, "
		"nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", "
		"opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"";
	constexpr const char* k7616Cnonce   = "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ";
	constexpr const char* k7616Response = "8ca523f5e9506fed4657c9700eebdbec";

	constexpr const char* k2069Challenge =
		"Digest realm=\"testrealm@host.com\", "
		"nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", "
		"opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";
	constexpr const char* k2069Response = "1949323746fe6a43ef61f9606e7febea";

	// Run the bounded builder into a big buffer and hand back a std::string for
	// comparison. The std::string is built AFTER the call, in the test -- it is
	// not part of what the bounded API does.
	bool bounded(const BoundedChallenge& ch, const char* user, const char* pass,
	             const char* method, const char* uri, uint32_t nc, const char* cnonce,
	             std::string& out)
	{
		char buf[kMaxAuthorizationValue];
		size_t len = 0;
		if (!buildAuthorization(ch, user, pass, method, uri, nc, cnonce, buf, sizeof(buf), len))
		{
			return false;
		}
		EXPECT_EQ(std::strlen(buf), len) << "outLen must equal the NUL-terminated length";
		out.assign(buf, len);
		return true;
	}

	// Pull one parameter's value out of an emitted header -- the same deliberately
	// dumb helper SipDigestClient_test uses, so a test cannot pass by agreeing
	// with the parser under test.
	std::string paramOf(const std::string& header, const std::string& key)
	{
		const std::string needle = key + "=";
		size_t p = 0;
		while ((p = header.find(needle, p)) != std::string::npos)
		{
			if (p != 0 && header[p - 1] != ' ' && header[p - 1] != ',')
			{
				p += needle.size();
				continue;
			}
			size_t v = p + needle.size();
			if (v < header.size() && header[v] == '"')
			{
				size_t e = header.find('"', v + 1);
				return header.substr(v + 1, e - v - 1);
			}
			size_t e = header.find(',', v);
			if (e == std::string::npos) e = header.size();
			return header.substr(v, e - v);
		}
		return {};
	}

	// Every challenge shape the two parsers must agree on. Deliberately
	// includes the awkward ones: a comma inside a quoted value, a header name
	// present and absent, whitespace everywhere, reordered parameters, every
	// qop list shape, both answerable algorithms and two unanswerable ones.
	const std::vector<std::string>& corpus()
	{
		static const std::vector<std::string> c = {
			k2617Challenge,
			k7616Challenge,
			k2069Challenge,
			"Digest realm=\"r\", nonce=\"n\"",
			"Digest nonce=\"n\", realm=\"r\"",                             // reordered
			"Digest   realm = \"r\" ,  nonce=\"n\"  , qop=\"auth\"",       // whitespace
			"Digest realm=r, nonce=n, qop=auth",                           // all bare
			"Digest realm=\"a, b\", nonce=\"n\", qop=\"auth\"",           // comma in quotes
			"Proxy-Authenticate: Digest realm=\"sbc\", nonce=\"abc\", qop=\"auth\"",
			"WWW-Authenticate: Digest realm=\"sbc\", nonce=\"abc\"",
			"Digest realm=\"r\", nonce=\"n\", qop=\"auth-int\"",          // auth-int only
			"Digest realm=\"r\", nonce=\"n\", qop=\"auth-int, auth\"",    // auth second
			"Digest realm=\"r\", nonce=\"n\", qop=\"auth,auth-int\"",     // auth first
			"Digest realm=\"r\", nonce=\"n\", qop=\"auth\", algorithm=MD5-sess",
			"Digest realm=\"r\", nonce=\"n\", algorithm=MD5-sess",        // sess, no qop
			"Digest realm=\"r\", nonce=\"n\", algorithm=SHA-256",         // RFC 8760
			"Digest realm=\"r\", nonce=\"n\", algorithm=\"md5\"",         // quoted, lowercase
			"Digest realm=\"r\", nonce=\"n\", stale=true",
			"Digest realm=\"r\", nonce=\"n\", stale=\"TRUE\"",
			"Digest realm=\"r\", nonce=\"n\", stale=false",
			"Digest realm=\"r\", nonce=\"n\", opaque=\"o\", qop=\"auth\"",
			"Digest realm=\"r\", nonce=\"n\", domain=\"sip:a sip:b\"",    // ignored param
			"Digest realm=\"r\", nonce=\"n\", unknownparam=\"x\"",
			"Digest nonce=\"n\"",                                          // realm-less
			"Digest realm=\"r\", qop=\"auth\"",                            // nonce-less
			"Digest realm=\"r\", nonce=\"\"",                              // empty nonce
			"Basic realm=\"r\"",                                           // wrong scheme
			"",
		};
		return c;
	}
}

// ── 1. Differential: the two APIs agree on every corpus entry ────────────────

TEST(SipDigestBounded, ParseAgreesWithTheStringApiOnEveryField)
{
	for (const std::string& hdr : corpus())
	{
		SCOPED_TRACE("challenge: " + hdr);
		for (bool proxyDefault : {false, true})
		{
			DigestChallenge s;
			BoundedChallenge b;
			const bool okS = parseChallenge(hdr, s, proxyDefault);
			const bool okB = parseChallenge(std::string_view(hdr), b, proxyDefault);
			ASSERT_EQ(okS, okB) << "the two parsers disagree on whether this parses";
			if (!okS) continue;

			EXPECT_EQ(s.realm,     b.realm);
			EXPECT_EQ(s.nonce,     b.nonce);
			EXPECT_EQ(s.opaque,    b.opaque);
			EXPECT_EQ(s.algorithm, b.algorithm);
			EXPECT_EQ(s.qopList,   b.qopList);
			EXPECT_EQ(s.stale,     b.stale);
			EXPECT_EQ(s.proxy,     b.proxy);
			EXPECT_EQ(algorithmOf(s), algorithmOf(b));
			EXPECT_STREQ(authorizationHeaderName(s), authorizationHeaderName(b));

			std::string qopS;
			bool useAuth = false;
			EXPECT_EQ(selectQop(s, qopS), selectQop(b, useAuth));
			EXPECT_EQ(qopS == "auth", useAuth);
		}
	}
}

TEST(SipDigestBounded, AuthorizationIsByteIdenticalToTheStringApi)
{
	// Several (method, uri, nc, cnonce) combinations per challenge, including
	// an empty cnonce to drive the refusal gates.
	struct Call { const char* method; const char* uri; uint32_t nc; const char* cnonce; };
	const Call calls[] = {
		{"REGISTER", "sip:carrier.example",         1,          "0a4f113b"},
		{"INVITE",   "sip:+15551234567@sbc.example", 2,         "deadbeefcafef00d"},
		{"GET",      "/dir/index.html",             0x0000002a, k7616Cnonce},
		{"INVITE",   "sip:x",                       0xffffffff, ""},
	};

	int answeredCount = 0;
	for (const std::string& hdr : corpus())
	{
		DigestChallenge s;
		BoundedChallenge b;
		if (!parseChallenge(hdr, s)) continue;
		ASSERT_TRUE(parseChallenge(std::string_view(hdr), b));

		for (const Call& c : calls)
		{
			SCOPED_TRACE("challenge: " + hdr + "  method: " + c.method +
			             "  cnonce: '" + c.cnonce + "'");
			std::string outS;
			std::string outB;
			const bool okS = buildAuthorization(s, "Mufasa", "Circle Of Life",
				c.method, c.uri, c.nc, c.cnonce, outS);
			const bool okB = bounded(b, "Mufasa", "Circle Of Life",
				c.method, c.uri, c.nc, c.cnonce, outB);
			ASSERT_EQ(okS, okB) << "the two builders disagree on whether this is answerable";
			if (!okS) continue;
			EXPECT_EQ(outS, outB);
			++answeredCount;
		}
	}
	// Guard against a corpus that silently stopped exercising the emit path:
	// a differential test that compares nothing passes vacuously.
	EXPECT_GE(answeredCount, 20) << "too few answerable cases reached the byte comparison";
}

// ── 2. External anchor: the published RFC response values ───────────────────

TEST(SipDigestBounded, Rfc2617Section35)
{
	BoundedChallenge ch;
	ASSERT_TRUE(parseChallenge(k2617Challenge, ch));
	std::string out;
	ASSERT_TRUE(bounded(ch, "Mufasa", "Circle Of Life", "GET", "/dir/index.html",
		1, "0a4f113b", out));
	EXPECT_EQ(paramOf(out, "response"), k2617Response);
	EXPECT_EQ(paramOf(out, "qop"), "auth");
	EXPECT_EQ(paramOf(out, "nc"), "00000001");
}

TEST(SipDigestBounded, Rfc7616Section391Md5)
{
	BoundedChallenge ch;
	ASSERT_TRUE(parseChallenge(k7616Challenge, ch));
	std::string out;
	ASSERT_TRUE(bounded(ch, "Mufasa", "Circle of Life", "GET", "/dir/index.html",
		1, k7616Cnonce, out));
	EXPECT_EQ(paramOf(out, "response"), k7616Response);
	EXPECT_EQ(paramOf(out, "algorithm"), "MD5");
	EXPECT_EQ(paramOf(out, "opaque"), "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS");
}

TEST(SipDigestBounded, Rfc2069LegacyNoQopPerErratum749)
{
	BoundedChallenge ch;
	ASSERT_TRUE(parseChallenge(k2069Challenge, ch));
	std::string out;
	ASSERT_TRUE(bounded(ch, "Mufasa", "CircleOfLife", "GET", "/dir/index.html",
		1, "unused", out));
	EXPECT_EQ(paramOf(out, "response"), k2069Response);
	// The legacy form must carry NO qop/nc/cnonce -- sending them while the
	// server computes the short form is a silent mismatch.
	EXPECT_EQ(out.find("qop="), std::string::npos);
	EXPECT_EQ(out.find("nc="), std::string::npos);
	EXPECT_EQ(out.find("cnonce="), std::string::npos);
}

// ── 3. Overflow: refuse, never truncate ─────────────────────────────────────

namespace
{
	std::string challengeWith(const std::string& key, const std::string& value)
	{
		// Every other field minimal so only `key` is under test.
		std::string c = "Digest ";
		if (key != "realm") c += "realm=\"r\", ";
		if (key != "nonce") c += "nonce=\"n\", ";
		c += key + "=\"" + value + "\"";
		return c;
	}
}

TEST(SipDigestBounded, EachFieldAcceptsItsLongestValueAndRefusesOneMore)
{
	struct Field { const char* key; size_t cap; };
	const Field fields[] = {
		{"realm",     BoundedChallenge::kMaxRealm},
		{"nonce",     BoundedChallenge::kMaxNonce},
		{"opaque",    BoundedChallenge::kMaxOpaque},
		{"algorithm", BoundedChallenge::kMaxAlgorithm},
		{"qop",       BoundedChallenge::kMaxQopList},
	};
	for (const Field& f : fields)
	{
		SCOPED_TRACE(f.key);
		BoundedChallenge fits;
		EXPECT_TRUE(parseChallenge(challengeWith(f.key, std::string(f.cap - 1, 'x')), fits))
			<< "the longest value that fits (cap - 1 plus the NUL) must be accepted";

		BoundedChallenge over;
		EXPECT_FALSE(parseChallenge(challengeWith(f.key, std::string(f.cap, 'x')), over))
			<< "one past the buffer must be refused, not truncated";

		// And the std::string API accepts it -- the documented, deliberate
		// difference. If this ever stops being true the header's claim is stale.
		DigestChallenge s;
		EXPECT_TRUE(parseChallenge(challengeWith(f.key, std::string(f.cap, 'x')), s));
	}
}

TEST(SipDigestBounded, AnOverflowLeavesNoHalfParsedChallengeBehind)
{
	// A caller that ignores the return value must still be unable to answer.
	BoundedChallenge ch;
	const std::string hdr = "Digest realm=\"r\", nonce=\"real-nonce\", opaque=\"" +
		std::string(BoundedChallenge::kMaxOpaque, 'o') + "\"";
	ASSERT_FALSE(parseChallenge(hdr, ch));
	EXPECT_STREQ(ch.nonce, "") << "the nonce parsed before the overflow must not survive";
	EXPECT_STREQ(ch.realm, "");

	char buf[kMaxAuthorizationValue];
	size_t len = 12345;
	EXPECT_FALSE(buildAuthorization(ch, "u", "p", "INVITE", "sip:x", 1, "cn",
		buf, sizeof(buf), len)) << "a reset challenge has no nonce, so it is unanswerable";
}

TEST(SipDigestBounded, TheOutputBufferIsExactFitAndNeverTruncated)
{
	BoundedChallenge ch;
	ASSERT_TRUE(parseChallenge(k2617Challenge, ch));

	char big[kMaxAuthorizationValue];
	size_t need = 0;
	ASSERT_TRUE(buildAuthorization(ch, "Mufasa", "Circle Of Life", "GET", "/dir/index.html",
		1, "0a4f113b", big, sizeof(big), need));
	ASSERT_GT(need, 0u);

	// need + 1 is exactly enough (the value plus its NUL).
	std::vector<char> exact(need + 1, '#');
	size_t len = 0;
	EXPECT_TRUE(buildAuthorization(ch, "Mufasa", "Circle Of Life", "GET", "/dir/index.html",
		1, "0a4f113b", exact.data(), exact.size(), len));
	EXPECT_EQ(len, need);
	EXPECT_EQ(std::string(exact.data(), len), std::string(big, need));

	// One byte short: refused, and what is left is an EMPTY string -- never a
	// prefix that could be sent as a (wrong) credential.
	std::vector<char> shortBuf(need, '#');
	len = 999;
	EXPECT_FALSE(buildAuthorization(ch, "Mufasa", "Circle Of Life", "GET", "/dir/index.html",
		1, "0a4f113b", shortBuf.data(), shortBuf.size(), len));
	EXPECT_EQ(len, 0u);
	EXPECT_EQ(shortBuf[0], '\0');

	// Zero capacity: refused without writing anything.
	char none = '#';
	EXPECT_FALSE(buildAuthorization(ch, "Mufasa", "Circle Of Life", "GET", "/dir/index.html",
		1, "0a4f113b", &none, 0, len));
	EXPECT_EQ(none, '#');
}

TEST(SipDigestBounded, RefusalGatesLeaveTheOutputUntouched)
{
	// Mirrors the std::string overload, which leaves `out` untouched on refusal.
	const char* unanswerable[] = {
		"Digest realm=\"r\", nonce=\"n\", qop=\"auth-int\"",   // auth-int only
		"Digest realm=\"r\", nonce=\"n\", algorithm=SHA-256",  // RFC 8760
		"Digest realm=\"r\", nonce=\"n\", algorithm=MD5-sess", // sess without qop
	};
	for (const char* hdr : unanswerable)
	{
		SCOPED_TRACE(hdr);
		BoundedChallenge ch;
		ASSERT_TRUE(parseChallenge(hdr, ch));
		char buf[64];
		std::memset(buf, '#', sizeof(buf));
		size_t len = 777;
		EXPECT_FALSE(buildAuthorization(ch, "u", "p", "INVITE", "sip:x", 1, "cn",
			buf, sizeof(buf), len));
		EXPECT_EQ(len, 777u);
		EXPECT_EQ(buf[0], '#');
	}

	// qop=auth with no cnonce.
	BoundedChallenge ch;
	ASSERT_TRUE(parseChallenge("Digest realm=\"r\", nonce=\"n\", qop=\"auth\"", ch));
	char buf[64];
	std::memset(buf, '#', sizeof(buf));
	size_t len = 777;
	EXPECT_FALSE(buildAuthorization(ch, "u", "p", "INVITE", "sip:x", 1, "",
		buf, sizeof(buf), len));
	EXPECT_EQ(len, 777u);
	EXPECT_EQ(buf[0], '#');
}

// ── 4. The password never leaves the hash ───────────────────────────────────

TEST(SipDigestBounded, ThePasswordNeverAppearsInTheEmittedHeader)
{
	for (const std::string& hdr : corpus())
	{
		BoundedChallenge ch;
		if (!parseChallenge(std::string_view(hdr), ch)) continue;
		std::string out;
		if (!bounded(ch, "user", "Pa55-w0rd-UNIQUE", "INVITE", "sip:x", 1, "cn", out)) continue;
		EXPECT_EQ(out.find("Pa55-w0rd-UNIQUE"), std::string::npos) << hdr;
	}
}

// ── 5. Fixed-width forms ────────────────────────────────────────────────────

TEST(SipDigestBounded, FormatNcIsEightLowercaseHexDigitsAndMatchesTheStringForm)
{
	for (uint32_t v : {0u, 1u, 42u, 0xABCDu, 0xffffffffu})
	{
		char nc[kNcLen + 1];
		std::memset(nc, '#', sizeof(nc));
		formatNc(v, nc);
		EXPECT_EQ(std::strlen(nc), kNcLen);
		EXPECT_EQ(std::string(nc), formatNc(v));
	}
}

TEST(SipDigestBounded, MakeCnonceIsSixteenLowercaseHexAndFreshEachTime)
{
	char a[kCnonceLen + 1];
	char b[kCnonceLen + 1];
	makeCnonce(a);
	makeCnonce(b);
	EXPECT_EQ(std::strlen(a), kCnonceLen);
	for (size_t i = 0; i < kCnonceLen; ++i)
	{
		EXPECT_TRUE((a[i] >= '0' && a[i] <= '9') || (a[i] >= 'a' && a[i] <= 'f')) << a;
	}
	// 64 random bits: a collision here is ~2^-64, i.e. a broken generator.
	EXPECT_STRNE(a, b);
}

// ── 6. Zero heap: the reason this API exists ────────────────────────────────
//
// Uses the binary's one counting operator new (tests/support/AllocCounter,
// #426) through AllocGuard, whose delta() counts THIS thread only -- RtpSender's
// pacer and the conference tick driver allocate concurrently elsewhere in this
// binary and must not be able to make these flaky. That the counter really
// moves, and really is per-thread, is AllocCounter_test's job; these only
// assert zero.
//
// Everything that is allowed to allocate -- the challenge string, the corpus,
// gtest's own bookkeeping -- is built BEFORE the guard. Inside it runs only
// the bounded API.

TEST(SipDigestBounded, ParsingAChallengeAllocatesNothing)
{
	const std::string hdr = k7616Challenge;   // allocated before the guard
	BoundedChallenge ch;

	AllocGuard guard;
	const bool ok = parseChallenge(std::string_view(hdr), ch);
	const std::size_t allocs = guard.delta();

	ASSERT_TRUE(ok);
	EXPECT_EQ(allocs, 0u) << "bounded parseChallenge touched the heap";
}

TEST(SipDigestBounded, BuildingAnAuthorizationAllocatesNothing)
{
	BoundedChallenge ch;
	ASSERT_TRUE(parseChallenge(k7616Challenge, ch));
	char buf[kMaxAuthorizationValue];
	size_t len = 0;

	AllocGuard guard;
	const bool ok = buildAuthorization(ch, "Mufasa", "Circle of Life", "GET",
		"/dir/index.html", 1, k7616Cnonce, buf, sizeof(buf), len);
	const std::size_t allocs = guard.delta();

	ASSERT_TRUE(ok);
	EXPECT_EQ(allocs, 0u) << "bounded buildAuthorization touched the heap";
}

TEST(SipDigestBounded, TheWholeAnswerPathAllocatesNothingAcrossTheCorpus)
{
	// Every shape, every branch: qop and legacy, MD5 and MD5-sess, refusals,
	// overflow. A path that only allocates on, say, the MD5-sess branch or
	// the overflow reset would slip past a single-vector test.
	const std::vector<std::string>& c = corpus();   // built before the guard
	std::vector<std::string_view> views(c.begin(), c.end());
	const std::string overflowing = "Digest realm=\"r\", nonce=\"" +
		std::string(BoundedChallenge::kMaxNonce, 'n') + "\"";

	// First-call initialisation is not the steady state: on host, fillRandom()
	// seeds a static std::mt19937_64 from std::random_device on first use.
	// Warm it up outside the guard so the measurement is the per-call cost.
	char warm[kCnonceLen + 1];
	makeCnonce(warm);

	int answered = 0;
	AllocGuard guard;
	for (std::string_view hdr : views)
	{
		BoundedChallenge ch;
		if (!parseChallenge(hdr, ch)) continue;
		char cnonce[kCnonceLen + 1];
		makeCnonce(cnonce);
		char nc[kNcLen + 1];
		formatNc(7, nc);
		bool useAuth = false;
		(void)selectQop(ch, useAuth);
		(void)algorithmOf(ch);
		(void)authorizationHeaderName(ch);
		char buf[kMaxAuthorizationValue];
		size_t len = 0;
		if (buildAuthorization(ch, "user", "pass", "INVITE", "sip:+15551234567@sbc",
		                       7, cnonce, buf, sizeof(buf), len))
		{
			++answered;
		}
	}
	BoundedChallenge over;
	(void)parseChallenge(std::string_view(overflowing), over);   // overflow + reset path
	const std::size_t allocs = guard.delta();

	EXPECT_EQ(allocs, 0u) << "the bounded answer path touched the heap";
	// And the loop really did run the emit path, so the zero is not vacuous.
	EXPECT_GE(answered, 15);
}
