// TelephonyAnchorLogic_test.cpp — host coverage for the Telephony anchor's pure parsing
// and URL logic (src/SIP/TelephonyAnchorLogic.hpp). Issue #49 [H-8]: the real
// TelephonyAnchorClient impl is ESP-only (cJSON/mbedTLS/esp_http_client), so its
// JWT-lifetime decode, WS entity-path parse, and call-control URL builders had
// no behavioral test. This suite drives the extracted, dependency-free logic —
// the SAME functions the on-device arm now calls — so the parse contract that
// issue #40 hardened is locked in on the host build.

#include <gtest/gtest.h>
#include <string>
#include <vector>

#include "TelephonyAnchorLogic.hpp"

namespace
{
using namespace telephony;

// ── base64url decode helper ─────────────────────────────────────────────────

TEST(TelephonyLogic, Base64UrlDecodesPlainJson)
{
	// {"a":1} -> base64url "eyJhIjoxfQ" (no padding)
	std::vector<uint8_t> out;
	ASSERT_TRUE(base64UrlDecode("eyJhIjoxfQ", out));
	std::string s(out.begin(), out.end());
	EXPECT_EQ(s, "{\"a\":1}");
}

TEST(TelephonyLogic, Base64UrlRejectsInvalidByte)
{
	std::vector<uint8_t> out;
	EXPECT_FALSE(base64UrlDecode("not valid!", out));   // space + '!' are non-alphabet
}

TEST(TelephonyLogic, Base64UrlHandlesUrlAlphabet)
{
	// '-' and '_' are the URL-safe substitutes for '+' and '/'. Decoding must
	// accept them without requiring a prior translation step.
	std::vector<uint8_t> a, b;
	ASSERT_TRUE(base64UrlDecode("-_-_", a));
	ASSERT_TRUE(base64UrlDecode("+/+/", b));
	EXPECT_EQ(a, b);   // same bytes either way
}

// ── scanJsonNumber ──────────────────────────────────────────────────────────

TEST(TelephonyLogic, ScanJsonNumberExtractsField)
{
	int64_t v = 0;
	ASSERT_TRUE(scanJsonNumber("{\"iat\":1700000000,\"exp\":1700003600}", "exp", v));
	EXPECT_EQ(v, 1700003600);
	ASSERT_TRUE(scanJsonNumber("{\"iat\":1700000000,\"exp\":1700003600}", "iat", v));
	EXPECT_EQ(v, 1700000000);
}

TEST(TelephonyLogic, ScanJsonNumberMissingOrNonNumeric)
{
	int64_t v = 0;
	EXPECT_FALSE(scanJsonNumber("{\"exp\":123}", "iat", v));         // absent
	EXPECT_FALSE(scanJsonNumber("{\"exp\":\"soon\"}", "exp", v));    // quoted value
	// A key that only appears as a string value, never as a real field, is ignored.
	EXPECT_FALSE(scanJsonNumber("{\"note\":\"exp pending\"}", "exp", v));
}

TEST(TelephonyLogic, ScanJsonNumberToleratesWhitespace)
{
	int64_t v = 0;
	ASSERT_TRUE(scanJsonNumber("{ \"exp\" :  42 }", "exp", v));
	EXPECT_EQ(v, 42);
}

// ── decodeJwtLifetimeUs ─────────────────────────────────────────────────────

// Build a JWT with the given payload JSON (header + payload + dummy sig).
static std::string makeJwt(const std::string& payloadJson)
{
	// Minimal base64url encoder for the test fixtures.
	static const char* alpha =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	auto enc = [&](const std::string& in) {
		std::string out;
		uint32_t buf = 0; int bits = 0;
		for (unsigned char c : in)
		{
			buf = (buf << 8) | c; bits += 8;
			while (bits >= 6) { bits -= 6; out.push_back(alpha[(buf >> bits) & 0x3F]); }
		}
		if (bits > 0) out.push_back(alpha[(buf << (6 - bits)) & 0x3F]);
		return out;
	};
	return enc("{\"alg\":\"HS256\"}") + "." + enc(payloadJson) + ".sigsig";
}

TEST(TelephonyLogic, DecodeJwtLifetimeRealClaims)
{
	// exp - iat = 3600s -> 3.6e9 µs.
	std::string jwt = makeJwt("{\"iat\":1700000000,\"exp\":1700003600}");
	EXPECT_EQ(decodeJwtLifetimeUs(jwt), 3600LL * 1000000);
}

TEST(TelephonyLogic, DecodeJwtFallbackOnMalformed)
{
	// No dots / one dot / empty payload all fall back to the safe lifetime —
	// never the bogus OAuth expires_in:60 that would trigger a refresh storm.
	EXPECT_EQ(decodeJwtLifetimeUs("not-a-jwt"), kTokenFallbackLifetimeUs);
	EXPECT_EQ(decodeJwtLifetimeUs("header.only"), kTokenFallbackLifetimeUs);
	EXPECT_EQ(decodeJwtLifetimeUs("a..c"), kTokenFallbackLifetimeUs);
}

TEST(TelephonyLogic, DecodeJwtFallbackOnMissingClaims)
{
	// Payload decodes but lacks iat — fall back.
	EXPECT_EQ(decodeJwtLifetimeUs(makeJwt("{\"exp\":1700003600}")), kTokenFallbackLifetimeUs);
}

TEST(TelephonyLogic, DecodeJwtFallbackOnInsaneSpan)
{
	// Negative span (exp before iat) and an over-a-day span are both rejected by
	// the sanity window -> fallback, not a garbage lifetime.
	EXPECT_EQ(decodeJwtLifetimeUs(makeJwt("{\"iat\":1700003600,\"exp\":1700000000}")),
	          kTokenFallbackLifetimeUs);
	EXPECT_EQ(decodeJwtLifetimeUs(makeJwt("{\"iat\":1700000000,\"exp\":1700200000}")),
	          kTokenFallbackLifetimeUs);   // ~55h
}

// ── entity-path tokenizer + participant parse ───────────────────────────────

TEST(TelephonyLogic, SplitEntityPathDropsEmptySegments)
{
	auto t = splitEntityPath("/callcontrol/100/participants/7");
	ASSERT_EQ(t.size(), 4u);
	EXPECT_EQ(t[0], "callcontrol");
	EXPECT_EQ(t[1], "100");
	EXPECT_EQ(t[2], "participants");
	EXPECT_EQ(t[3], "7");
	// A trailing slash / doubled slashes must not produce empty tokens.
	EXPECT_EQ(splitEntityPath("//a///b//").size(), 2u);
	EXPECT_TRUE(splitEntityPath("").empty());
}

TEST(TelephonyLogic, ParseParticipantEntityValid)
{
	ParticipantEntity e = parseParticipantEntity("/callcontrol/2001/participants/42");
	EXPECT_TRUE(e.valid);
	EXPECT_EQ(e.dn, "2001");
	EXPECT_EQ(e.participantId, "42");
	// Works without the leading slash too (token shape is what matters).
	EXPECT_TRUE(parseParticipantEntity("callcontrol/2001/participants/42").valid);
}

TEST(TelephonyLogic, ParseParticipantEntityRejectsWrongShape)
{
	// Wrong length, wrong literals, or a different resource → not valid. This is
	// the gate that stops the anchor acting on an unrelated WS event.
	EXPECT_FALSE(parseParticipantEntity("/callcontrol/2001/participants").valid);          // 3 tokens
	EXPECT_FALSE(parseParticipantEntity("/callcontrol/2001/participants/42/extra").valid); // 5 tokens
	EXPECT_FALSE(parseParticipantEntity("/other/2001/participants/42").valid);             // wrong root
	EXPECT_FALSE(parseParticipantEntity("/callcontrol/2001/devices/42").valid);            // wrong resource
	EXPECT_FALSE(parseParticipantEntity("").valid);
}

// ── URL builders ────────────────────────────────────────────────────────────

TEST(TelephonyLogic, UrlBuilders)
{
	const std::string base = "https://pbx.example.com";
	EXPECT_EQ(tokenUrl(base), "https://pbx.example.com/connect/token");
	EXPECT_EQ(participantsUrl(base, "100"), "https://pbx.example.com/callcontrol/100/participants");
	EXPECT_EQ(devicesUrl(base, "100"), "https://pbx.example.com/callcontrol/100/devices");
	EXPECT_EQ(legacyMakeCallUrl(base, "100"), "https://pbx.example.com/callcontrol/100/makecall");
}

TEST(TelephonyLogic, ParticipantActionUrls)
{
	const std::string base = "https://pbx.example.com";
	// The drop/answer/stream actions are what issue #40's teardown fix POSTs to.
	EXPECT_EQ(participantActionUrl(base, "100", "7", "drop"),
	          "https://pbx.example.com/callcontrol/100/participants/7/drop");
	EXPECT_EQ(participantActionUrl(base, "100", "7", "answer"),
	          "https://pbx.example.com/callcontrol/100/participants/7/answer");
	EXPECT_EQ(participantActionUrl(base, "100", "7", "stream"),
	          "https://pbx.example.com/callcontrol/100/participants/7/stream");
	// Empty action yields the bare participant URL (the specific-id GET path).
	EXPECT_EQ(participantActionUrl(base, "100", "7", ""),
	          "https://pbx.example.com/callcontrol/100/participants/7");
}

TEST(TelephonyLogic, ControlWsUrlSchemeRewrite)
{
	EXPECT_EQ(controlWsUrl("https://pbx.example.com"),
	          "wss://pbx.example.com/callcontrol/ws");
	EXPECT_EQ(controlWsUrl("http://pbx.example.com"),
	          "ws://pbx.example.com/callcontrol/ws");
	// A bare host (no scheme) defaults to wss.
	EXPECT_EQ(controlWsUrl("pbx.example.com"),
	          "wss://pbx.example.com/callcontrol/ws");
}

// ── tokenIsExpiringSoon (issue #336) ─────────────────────────────────────────
// The comparison behind BOTH TelephonyAnchorClient::tokenExpiringSoon() (gates
// the existing HTTP-side ensureToken() refresh) and requestRestartIfTokenStale()
// (the new WS-side fix: reconnect-in-place can't rebuild a stale header, so a
// disconnected/errored WS with an expiring token now requests a full anchor
// restart instead of retrying forever with the same 401). One comparison,
// tested once, trusted by both call sites.

constexpr int64_t kMinute = 60LL * 1000000;
constexpr int64_t kMargin = 5 * kMinute;

TEST(TelephonyLogic, TokenExpiringSoonFalseWellBeforeMargin)
{
	// Obtained "now" (age 0) with a full hour of lifetime -- nowhere near the
	// 5-minute margin.
	EXPECT_FALSE(tokenIsExpiringSoon(/*now=*/100 * kMinute, /*obtained=*/100 * kMinute,
	                                 /*lifetime=*/60 * kMinute, kMargin));
}

TEST(TelephonyLogic, TokenExpiringSoonTrueInsideMargin)
{
	// Obtained 56 minutes ago, 60-minute lifetime -- 4 minutes of real life left,
	// inside the 5-minute margin.
	EXPECT_TRUE(tokenIsExpiringSoon(/*now=*/156 * kMinute, /*obtained=*/100 * kMinute,
	                                /*lifetime=*/60 * kMinute, kMargin));
}

TEST(TelephonyLogic, TokenExpiringSoonTrueAtExactMarginBoundary)
{
	// age == lifetime - margin is the documented boundary (>=, not >): exactly
	// 55 minutes in on a 60-minute/5-minute-margin token must already read as
	// expiring, not one tick later.
	EXPECT_TRUE(tokenIsExpiringSoon(/*now=*/155 * kMinute, /*obtained=*/100 * kMinute,
	                                /*lifetime=*/60 * kMinute, kMargin));
}

TEST(TelephonyLogic, TokenExpiringSoonTrueAfterActualExpiry)
{
	// Well past the JWT's own exp claim, not just inside the refresh margin --
	// must still read as expiring, not wrap or go false.
	EXPECT_TRUE(tokenIsExpiringSoon(/*now=*/300 * kMinute, /*obtained=*/100 * kMinute,
	                                /*lifetime=*/60 * kMinute, kMargin));
}

TEST(TelephonyLogic, TokenExpiringSoonTrueWhenNeverObtained)
{
	// obtainedUs==0 (no token fetched yet) must read as expiring so a client
	// that has never fetched a token is treated as needing one, not as holding
	// an eternally-valid one.
	EXPECT_TRUE(tokenIsExpiringSoon(/*now=*/1000, /*obtained=*/0, /*lifetime=*/60 * kMinute,
	                                kMargin));
}

TEST(TelephonyLogic, TokenExpiringSoonTrueWhenLifetimeUnknown)
{
	// Same guard, the other missing field: lifetimeUs==0 (decodeJwtLifetimeUs
	// itself never returns this, but the check exists independently -- pin it
	// directly rather than only through that function's own fallback).
	EXPECT_TRUE(tokenIsExpiringSoon(/*now=*/1000, /*obtained=*/500, /*lifetime=*/0, kMargin));
}

// ── httpResponseParsed (issues #349 / #350) ─────────────────────────────────
// The arithmetic (status > 0) needs no test. What these pin is WHY the boundary
// sits at zero, so that a later "tidy-up" to >= 0 -- because zero looks like it
// could be a valid status -- fails with a test name that says what it broke.

TEST(TelephonyLogic, HttpResponseParsedFalseForFetchHeadersSentinel)
{
	// -1 is not a status the server sent. esp_http_client_fetch_headers() assigns
	// status_code = -1 itself before reading a byte (esp_http_client.c:1658), so a
	// failed read leaves it there. This is the value seen in BOTH #349's and #350's
	// hardware captures, and reading it as a verdict is what caused both bugs.
	EXPECT_FALSE(httpResponseParsed(-1));
}

TEST(TelephonyLogic, HttpResponseParsedFalseForNeverAssigned)
{
	// 0 is the same class of non-answer: what a caller's own `int status = 0;`
	// still holds when the call bailed before assigning anything.
	EXPECT_FALSE(httpResponseParsed(0));
}

TEST(TelephonyLogic, HttpResponseParsedTrueForAnyRealStatus)
{
	// Every status the server actually sent is a verdict the caller can act on --
	// including the error ones. 404/424 are the "not ready yet" this project's GET
	// retry loop exists to wait out; 403/500 are a definitive decline. None of them
	// are unknown state, which is the whole distinction.
	EXPECT_TRUE(httpResponseParsed(200));
	EXPECT_TRUE(httpResponseParsed(404));
	EXPECT_TRUE(httpResponseParsed(424));
	EXPECT_TRUE(httpResponseParsed(500));
}

}  // namespace
