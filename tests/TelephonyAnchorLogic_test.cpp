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

#include "AllocCounter.hpp"
#include "TelephonyAnchorLogic.hpp"

namespace
{
using namespace telephony;

// ── base64url decode helper ─────────────────────────────────────────────────

TEST(TelephonyLogic, Base64UrlDecodesPlainJson)
{
	// {"a":1} -> base64url "eyJhIjoxfQ" (no padding)
	char out[16];
	std::size_t n = 0;
	ASSERT_TRUE(base64UrlDecode("eyJhIjoxfQ", out, sizeof out, n));
	EXPECT_EQ(std::string(out, n), "{\"a\":1}");
}

TEST(TelephonyLogic, Base64UrlRejectsInvalidByte)
{
	char out[16];
	std::size_t n = 0;
	EXPECT_FALSE(base64UrlDecode("not valid!", out, sizeof out, n));   // space + '!' are non-alphabet
}

TEST(TelephonyLogic, Base64UrlHandlesUrlAlphabet)
{
	// '-' and '_' are the URL-safe substitutes for '+' and '/'. Decoding must
	// accept them without requiring a prior translation step.
	char a[8], b[8];
	std::size_t na = 0, nb = 0;
	ASSERT_TRUE(base64UrlDecode("-_-_", a, sizeof a, na));
	ASSERT_TRUE(base64UrlDecode("+/+/", b, sizeof b, nb));
	EXPECT_EQ(std::string(a, na), std::string(b, nb));   // same bytes either way
}

TEST(TelephonyLogic, Base64UrlRefusesWhatDoesNotFitTheBufferLentToIt)
{
	// "eyJhIjoxfQ" is 7 bytes. #951: the buffer is the caller's, so a short one is an error, never a prefix.
	char out[16];
	std::size_t n = 0;
	EXPECT_FALSE(base64UrlDecode("eyJhIjoxfQ", out, 6, n));
	EXPECT_TRUE(base64UrlDecode("eyJhIjoxfQ", out, 7, n));
	EXPECT_EQ(n, 7u);
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

// decodeJwtLifetimeUs() is lent its scratch (#951): fetchToken() lends the arena's unused tail.
static int64_t lifetimeOf(std::string_view jwt)
{
	std::vector<char> scratch(jwt.size() + 1);
	return decodeJwtLifetimeUs(jwt, scratch.data(), scratch.size());
}

TEST(TelephonyLogic, DecodeJwtLifetimeRealClaims)
{
	// exp - iat = 3600s -> 3.6e9 µs.
	std::string jwt = makeJwt("{\"iat\":1700000000,\"exp\":1700003600}");
	EXPECT_EQ(lifetimeOf(jwt), 3600LL * 1000000);
}

TEST(TelephonyLogic, DecodeJwtFallbackOnMalformed)
{
	// No dots / one dot / empty payload all fall back to the safe lifetime —
	// never the bogus OAuth expires_in:60 that would trigger a refresh storm.
	EXPECT_EQ(lifetimeOf("not-a-jwt"), kTokenFallbackLifetimeUs);
	EXPECT_EQ(lifetimeOf("header.only"), kTokenFallbackLifetimeUs);
	EXPECT_EQ(lifetimeOf("a..c"), kTokenFallbackLifetimeUs);
}

TEST(TelephonyLogic, DecodeJwtFallbackOnMissingClaims)
{
	// Payload decodes but lacks iat — fall back.
	EXPECT_EQ(lifetimeOf(makeJwt("{\"exp\":1700003600}")), kTokenFallbackLifetimeUs);
}

TEST(TelephonyLogic, DecodeJwtFallbackOnInsaneSpan)
{
	// Negative span (exp before iat) and an over-a-day span are both rejected by
	// the sanity window -> fallback, not a garbage lifetime.
	EXPECT_EQ(lifetimeOf(makeJwt("{\"iat\":1700003600,\"exp\":1700000000}")),
	          kTokenFallbackLifetimeUs);
	EXPECT_EQ(lifetimeOf(makeJwt("{\"iat\":1700000000,\"exp\":1700200000}")),
	          kTokenFallbackLifetimeUs);   // ~55h
}

TEST(TelephonyLogic, DecodeJwtLifetimeFromARealisticPayload)
{
	// More members than exp and iat, in the order an issuer writes them, with a space and an
	// array in the way. This is what the cJSON version it replaced (#862) read on the board.
	const std::string payload =
	    "{\"iss\":\"https://pbx.example.com\",\"aud\":[\"call_control\"],\"nbf\":1700000000,"
	    "\"exp\": 1700003600,\"iat\":1700000000,\"client_id\":\"900\",\"scope\":\"exp iat\"}";
	EXPECT_EQ(lifetimeOf(makeJwt(payload)), 3600LL * 1000000);
}

TEST(TelephonyLogic, DecodeJwtLifetimeFallsBackOnAFractionOrAnExponent)
{
	// Supersedes the earlier "a fraction is cut, not rounded" (#862). Cutting exp and iat each to
	// whole seconds can put the lifetime up to a second HIGH, the unsafe direction (exp 101.0 and
	// iat 100.9 would read as 1 s for 0.1 s), and "1.7e9" used to read as 1. A number with a '.',
	// 'e' or 'E' after its digits is not read at all, so the lifetime is the 50 minute fallback.
	for (const char* payload : {
	         "{\"iat\":1700000000.2,\"exp\":1700003600.9}", "{\"iat\":1700000000,\"exp\":1700003600.5}",
	         "{\"iat\":1700000000.5,\"exp\":1700003600}", "{\"iat\":1.7e9,\"exp\":1.7000036e9}",
	         "{\"iat\":1700000000,\"exp\":1700003600E0}", "{\"iat\":1700000000,\"exp\":17000036e2}"})
	{
		EXPECT_EQ(lifetimeOf(makeJwt(payload)), kTokenFallbackLifetimeUs) << payload;
	}
}

TEST(TelephonyLogic, ScanJsonNumberRefusesWhatItCannotReadExactly)
{
	int64_t v = 777;
	// "1.7e9" must not read as 1, and 19 or more digits must not overflow a signed 64-bit value.
	for (const char* json : {"{\"exp\":1.7e9}", "{\"exp\":1700000000.5}", "{\"exp\":1700000000E0}", "{\"exp\":17e8}",
	                         "{\"exp\":1234567890123456789}", "{\"exp\":9223372036854775808}",
	                         "{\"exp\":99999999999999999999999}"})
	{
		EXPECT_FALSE(scanJsonNumber(json, "exp", v)) << json;
	}
	EXPECT_EQ(v, 777) << "a refusal leaves out alone";
	// What it can read exactly still reads: 18 digits is the most it takes.
	ASSERT_TRUE(scanJsonNumber("{\"exp\":123456789012345678}", "exp", v));
	EXPECT_EQ(v, 123456789012345678);
	ASSERT_TRUE(scanJsonNumber("{\"exp\":-5}", "exp", v));
	EXPECT_EQ(v, -5);
	for (const char* json : {"{\"exp\":42}", "{\"exp\":42,\"x\":1}", "{\"exp\":42 }", "{\"a\":[1],\"exp\":42}"})
	{
		v = 0;
		ASSERT_TRUE(scanJsonNumber(json, "exp", v)) << json;
		EXPECT_EQ(v, 42) << json;
	}
}

TEST(TelephonyLogic, DecodeJwtLifetimeTakesNoHeap)
{
	// fetchToken() decodes this on every fetch, into the arena's unused tail (#951). It was three
	// allocations (payload, decoded bytes, JSON text); the caller lends the scratch now, so none.
	const std::string jwt = makeJwt(
	    "{\"iss\":\"https://pbx.example.com\",\"aud\":[\"call_control\"],\"nbf\":1700000000,"
	    "\"exp\":1700003600,\"iat\":1700000000,\"client_id\":\"900\"}");
	char scratch[512];
	int64_t lifetime = 0;
	std::size_t heap = 0;
	{
		AllocGuard g;
		lifetime = decodeJwtLifetimeUs(jwt, scratch, sizeof scratch);
		heap = g.delta();
	}
	EXPECT_EQ(lifetime, 3600LL * 1000000);
	EXPECT_EQ(heap, 0u);
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

// ── #379/#681: a leg this PBX created is never announced as an inbound call ────
// The x4 re-run on .244 (main 1fcd6d4b, #379 issuecomment-5985911668), on its
// syslog clock in µs. The handset CANCELled at 422.512 and the session ended.
// The WS event numbers are the order the anchor client received them in.
constexpr int64_t  kNamed     = 2'477'423'517'000;   // resolveOutboundLeg: result.id=38
constexpr int64_t  kFreed     = 2'477'423'600'000;   // the drop freed its slot (between 423.539 and 423.608)
constexpr int64_t  kUpsert    = 2'477'423'930'000;   // "Inbound call on DN ***: participant 38"
constexpr int64_t  kRemove    = 2'477'424'724'000;   // "Participant Remove 38"
constexpr uint64_t kSeqPost   = 40;                  // _wsSeq when makeCall() sent the makecall
constexpr uint64_t kSeqUpsert = 41;                  // the upsert for 38
constexpr uint64_t kSeqRemove = 42;                  // 3CX's Remove of 38

TEST(OwnLegs, AnOwnLegUpsertWhileItsDropStallsIsNotAnnounced)
{
	AnchorOwnLegs own;
	own.noteNamed("38", kNamed, kSeqPost);   // makeCall(): the makecall response named it
	own.note("38", kFreed);        // freeSlotLocked(): its outbound slot was freed
	EXPECT_FALSE(inboundAnnounceAllowed(own, "38", kUpsert, kSeqUpsert))
		<< "our own leg 38 was announced as an inbound call while its drop reconnected";
}

TEST(OwnLegs, AnUpsertAfterTheRemoveIsANewCall)
{
	// 3CX removed 38, so an upsert it sends for 38 afterwards names a new participant.
	AnchorOwnLegs own;
	own.noteNamed("38", kNamed, kSeqPost);
	own.note("38", kFreed);
	own.release("38", kSeqRemove);
	EXPECT_TRUE(inboundAnnounceAllowed(own, "38", kRemove + 300'000, kSeqRemove + 1))
		<< "a call that reuses 38 after its Remove was held back";
}

TEST(OwnLegs, AFreedSlotOrADropAfterTheRemoveDoesNotHoldItAgain)
{
	// The Remove's own worker frees the slot after the Remove arrived; a drop may refresh it.
	AnchorOwnLegs own;
	own.noteNamed("38", kNamed, kSeqPost);
	own.release("38", kSeqRemove);
	own.note("38", kRemove + 50'000);
	own.refresh("38", kRemove + 60'000);
	EXPECT_TRUE(inboundAnnounceAllowed(own, "38", kRemove + 300'000, kSeqRemove + 1));
}

TEST(OwnLegs, OnlyAnIdFromTheMakecallResponseIsHeld)
{
	// The list fallback's picks can be a genuine inbound call that rang while the
	// makecall was pending (it gets no slot then). Nothing in the repo defines
	// party_dn, so a party_dn match is no better than the first controllable leg.
	EXPECT_TRUE(ownLegMayBeHeld(OwnLegSource::MakecallResult));
	EXPECT_FALSE(ownLegMayBeHeld(OwnLegSource::OwnPartyDn)) << "a party_dn pick was held";
	EXPECT_FALSE(ownLegMayBeHeld(OwnLegSource::FirstControllable)) << "a guessed leg was held";
}

TEST(OwnLegs, ALegRemovedBeforeItIsNamedIsNotHeld)
{
	// 3CX removed the leg after our makecall went out but before its response named
	// it: nothing will upsert that leg again, so an upsert after the Remove is not ours.
	AnchorOwnLegs own;
	own.release("38", kSeqRemove);
	own.noteNamed("38", kNamed, kSeqPost);
	EXPECT_TRUE(inboundAnnounceAllowed(own, "38", kNamed + 300'000, kSeqRemove + 1))
		<< "a call that reuses 38 after its leg's Remove was held back";
	EXPECT_FALSE(inboundAnnounceAllowed(own, "38", kNamed + 300'000, kSeqUpsert))
		<< "the removed leg's own upsert, received before the Remove, is still ours";
}

// The ring of recent Removes: the last 8, oldest overwritten (#883 review S2).

// The leg's own Remove at kSeqRemove, then `others` Removes of other participants.
AnchorOwnLegs removedThenOthers(int others)
{
	AnchorOwnLegs own;
	own.release("38", kSeqRemove);
	for (int i = 0; i < others; ++i) own.release(std::to_string(100 + i), kSeqRemove + 1 + i);
	own.noteNamed("38", kNamed, kSeqPost);
	return own;
}

TEST(OwnLegs, EightLaterRemovesPushTheLegsOwnOutOfTheRing)
{
	const AnchorOwnLegs own = removedThenOthers(8);
	EXPECT_FALSE(inboundAnnounceAllowed(own, "38", kNamed + 300'000, kSeqRemove + 9))
		<< "the leg's Remove was the oldest of 9, so the ring forgot it and the leg is held";
}

TEST(OwnLegs, SevenLaterRemovesKeepTheLegsOwnInTheRing)
{
	const AnchorOwnLegs own = removedThenOthers(7);
	EXPECT_TRUE(inboundAnnounceAllowed(own, "38", kNamed + 300'000, kSeqRemove + 8))
		<< "the leg's Remove was still among the last 8, so the leg is released";
}

TEST(OwnLegs, ARemoveNumberedAtTheMakecallIsNotCounted)
{
	// postSeq is the last number taken before the makecall went out, so a Remove that
	// carries it was received before the makecall: an earlier participant's.
	AnchorOwnLegs own;
	own.release("38", kSeqPost);
	own.noteNamed("38", kNamed, kSeqPost);
	EXPECT_FALSE(inboundAnnounceAllowed(own, "38", kNamed + 300'000, kSeqPost + 1));
}

TEST(OwnLegs, OfTwoRemovesOfOneIdTheLaterCounts)
{
	AnchorOwnLegs own;
	own.release("38", kSeqPost - 1);   // an earlier participant's, before the makecall
	own.release("38", kSeqRemove);     // the leg's own
	own.noteNamed("38", kNamed, kSeqPost);
	EXPECT_TRUE(inboundAnnounceAllowed(own, "38", kNamed + 300'000, kSeqRemove + 1));
	EXPECT_FALSE(inboundAnnounceAllowed(own, "38", kNamed + 300'000, kSeqUpsert))
		<< "released at the leg's own Remove, not before it";
}

TEST(OwnLegs, AnIdThatDoesNotFitTakesNoPlaceInTheRing)
{
	// The leg's Remove is the oldest of 8; an id of 32 characters must not evict it.
	AnchorOwnLegs own;
	own.release("38", kSeqRemove);
	for (int i = 0; i < 7; ++i) own.release(std::to_string(100 + i), kSeqRemove + 1 + i);
	own.release(std::string(32, '7'), kSeqRemove + 8);
	own.noteNamed("38", kNamed, kSeqPost);
	EXPECT_TRUE(inboundAnnounceAllowed(own, "38", kNamed + 300'000, kSeqRemove + 9));
}

TEST(OwnLegs, UnderIdReuseAnEarlierParticipantsRemoveReleasesTheNewLegEarly)
{
	// Accepted behaviour (case d'): an earlier participant 38 was still live when our
	// makecall went out; its Remove came after, and 3CX then gave 38 to our leg. The
	// table takes that Remove as our leg's own, so our leg is announced after it, as on
	// main, phantom included. Counter-allocated ids (accepted 2026-10-05) rule it out.
	AnchorOwnLegs own;
	own.release("38", kSeqRemove);
	own.noteNamed("38", kNamed, kSeqPost);
	own.note("38", kFreed);
	EXPECT_TRUE(inboundAnnounceAllowed(own, "38", kUpsert, kSeqRemove + 1));
}

TEST(OwnLegs, ALegIsOursFromTheMomentTheMakecallResponseNamesIt)
{
	// Named but not keyed onto a call slot yet (or never: every slot busy).
	AnchorOwnLegs own;
	own.noteNamed("38", kNamed, kSeqPost);
	EXPECT_FALSE(inboundAnnounceAllowed(own, "38", kNamed + 22'000, kSeqUpsert));
}

TEST(OwnLegs, TheHoldLapsesTheGraceAfterTheLastEvent)
{
	AnchorOwnLegs own;
	own.note("38", kFreed);
	EXPECT_FALSE(inboundAnnounceAllowed(own, "38", kFreed + 5'000'000, kSeqUpsert));
	EXPECT_FALSE(inboundAnnounceAllowed(own, "38", kFreed + kOwnLegGraceUs - 1, kSeqUpsert));
	EXPECT_TRUE(inboundAnnounceAllowed(own, "38", kFreed + kOwnLegGraceUs, kSeqUpsert))
		<< "a check at +5 s must not extend the hold";
	EXPECT_FALSE(own.refresh("38", kFreed + kOwnLegGraceUs)) << "a drop does not revive a lapsed leg";
}

TEST(OwnLegs, AFullTableOverwritesTheLeastRecentlySeenLeg)
{
	static_assert(sizeof(OwnLegs<4, 32>) == 4 * sizeof(OwnLegs<1, 32>), "fixed storage only");
	static_assert(sizeof(AnchorOwnLegs) == 8 * sizeof(OwnLegs<1, 32>), "fixed storage only");
	static_assert(sizeof(AnchorOwnLegs) == 704, "8 held legs of 48 B and 8 Removes of 40 B");
	OwnLegs<4, 32> own;
	for (int i = 0; i < 4; ++i) own.note(std::to_string(10 + i), kNamed + i);
	own.note("10", kNamed + 10);
	own.note("20", kNamed + 20);
	EXPECT_TRUE(inboundAnnounceAllowed(own, "11", kNamed + 21, kSeqUpsert)) << "11 was the least recently seen";
	for (const char* id : { "10", "12", "13", "20" })
	{
		EXPECT_FALSE(inboundAnnounceAllowed(own, id, kNamed + 21, kSeqUpsert)) << id;
	}
}

// Guards: these pass on the unfixed code too, and must keep passing.

TEST(OwnLegs, WorkQueuedBeforeTheRemoveIsStillOurs)
{
	// The trace's order: the upsert for 38 was received before 3CX's Remove, and a
	// worker may reach it only after the Remove.
	AnchorOwnLegs own;
	own.noteNamed("38", kNamed, kSeqPost);
	own.note("38", kFreed);
	own.release("38", kSeqRemove);
	EXPECT_FALSE(inboundAnnounceAllowed(own, "38", kRemove + 300'000, kSeqUpsert));
}

TEST(OwnLegs, ANameAfterARemoveHoldsTheLegAgain)
{
	// 3CX names our next outbound leg with an id it removed before: that leg is ours.
	AnchorOwnLegs own;
	own.noteNamed("38", kNamed, kSeqPost);
	own.release("38", kSeqRemove);
	own.noteNamed("38", kRemove + 1'000'000, kSeqRemove + 3);   // its makecall went out after the Remove
	EXPECT_FALSE(inboundAnnounceAllowed(own, "38", kRemove + 1'100'000, kSeqRemove + 5));
}

TEST(OwnLegs, ANewParticipantIdIsAnnounced)
{
	AnchorOwnLegs own;
	own.noteNamed("38", kNamed, kSeqPost);
	own.note("38", kFreed);
	EXPECT_TRUE(inboundAnnounceAllowed(own, "39", kUpsert, kSeqUpsert));
	EXPECT_TRUE(inboundAnnounceAllowed(own, "3", kUpsert, kSeqUpsert)) << "a prefix of a held id is another participant";
	EXPECT_TRUE(inboundAnnounceAllowed(own, "380", kUpsert, kSeqUpsert));
}

TEST(OwnLegs, APsapCallbackAfterADroppedEmergencyLegIsAnnounced)
{
	// The caller abandoned a 911: its own leg was named, freed and dropped. 3CX
	// offers the PSAP's callback as a new participant on the route DN.
	AnchorOwnLegs own;
	own.noteNamed("40", kNamed, kSeqPost);
	own.note("40", kFreed);
	own.refresh("40", kFreed + 10'000);
	EXPECT_TRUE(inboundAnnounceAllowed(own, "41", kUpsert, kSeqUpsert));
}

TEST(OwnLegs, AnInboundLegThePbxRefusedAndDroppedIsStillAnnounced)
{
	// dropCall() refreshes only a leg already held. A refused inbound leg (say every
	// bridge busy while a 911 is up) is not ours: if its drop fails, 3CX's next
	// upsert announces it again, as before.
	AnchorOwnLegs own;
	EXPECT_FALSE(own.refresh("50", kUpsert));
	own.release("50", kSeqRemove);
	EXPECT_TRUE(inboundAnnounceAllowed(own, "50", kUpsert + 750'000, kSeqUpsert));
}

TEST(OwnLegs, AnIdThatDoesNotFitIsNeverHeld)
{
	AnchorOwnLegs own;
	const std::string longId(40, '7');
	own.noteNamed(longId, kNamed, kSeqPost);
	own.note("", kNamed);
	EXPECT_TRUE(inboundAnnounceAllowed(own, longId, kNamed + 1, kSeqUpsert));
	EXPECT_TRUE(inboundAnnounceAllowed(own, longId.substr(0, 31), kNamed + 1, kSeqUpsert)) << "never truncated into a match";
	EXPECT_TRUE(inboundAnnounceAllowed(own, "", kNamed + 1, kSeqUpsert));
}

// ── #349: the makecall POST reached 3CX and its response was never read ──────
// The x349_unread_makecall run on .244 (main 61132ada, #349 issuecomment-6004433436):
// 3CX had already named the leg (the probe threw result.id away), the list read
// found no leg, makeCall() gave up, and 3CX's leg 509 rang the far end, was
// answered, and came back as a phantom inbound call.

TEST(UnreadMakecall, ALegTheListShowsIsAdopted)
{
	EXPECT_EQ(unreadMakecallStep(/*legListed=*/true, 0), UnreadMakecallStep::Adopt);
	EXPECT_EQ(unreadMakecallStep(true, kUnreadAdoptWindowUs), UnreadMakecallStep::Adopt)
		<< "a leg on the last read is still ours";
}

TEST(UnreadMakecall, AListWithNoLegYetIsReadAgain)
{
	// One read that shows no leg is not "no call": 3CX had placed it on .244.
	EXPECT_EQ(unreadMakecallStep(false, 0), UnreadMakecallStep::ReadAgain)
		<< "the first list read with no leg ended the reconcile: the .244 orphan";
	EXPECT_EQ(unreadMakecallStep(false, 2'000'000), UnreadMakecallStep::ReadAgain);
}

TEST(UnreadMakecall, TheReadsStopWithinTheWindow)
{
	// While makeCall() reads, an unmatched upsert is ignored (#888), so the window is bounded.
	static_assert(kUnreadAdoptWindowUs <= 5'000'000, "#888: a longer window hides an inbound upsert longer");
	const int64_t lastRead = kUnreadAdoptWindowUs - int64_t{kUnreadAdoptPollMs} * 1000;
	EXPECT_EQ(unreadMakecallStep(false, lastRead - 1), UnreadMakecallStep::ReadAgain);
	EXPECT_EQ(unreadMakecallStep(false, lastRead), UnreadMakecallStep::GiveUp)
		<< "a read after the window closes";
	EXPECT_EQ(unreadMakecallStep(false, kUnreadAdoptWindowUs * 10), UnreadMakecallStep::GiveUp);
}

TEST(OwnLegs, ALegAdoptedAfterAnUnreadResponseIsHeld)
{
	// Once adopted the leg is ours: freed at hangup, its upserts before 3CX's
	// Remove must not ring the route DN. The list fallback alone stays unheld.
	EXPECT_TRUE(ownLegMayBeHeld(OwnLegSource::AdoptedAfterUnreadResponse))
		<< "an adopted leg's late upsert can still be announced as inbound";
	EXPECT_FALSE(ownLegMayBeHeld(OwnLegSource::OwnPartyDn));
	EXPECT_FALSE(ownLegMayBeHeld(OwnLegSource::FirstControllable));
}

// ── #349 review (#903): which list entries the adopt reads may pick, and the counts ──
// resolveOutboundLeg() classifies each participant of the live list with these.

TEST(ListLeg, OnlyAControllableUnclaimedLegWithAnIdIsACandidate)
{
	using D = DirectControlField;
	EXPECT_EQ(classifyListLeg(D::True, true, false, false), ListLegVerdict::Candidate);
	EXPECT_EQ(classifyListLeg(D::False, true, false, false), ListLegVerdict::NotControllable);
	EXPECT_EQ(classifyListLeg(D::Absent, true, false, false), ListLegVerdict::NotControllable)
		<< "audit #76: a missing direct_control is not controllable";
	EXPECT_EQ(classifyListLeg(D::NotBool, true, false, false), ListLegVerdict::NotControllable);
	EXPECT_EQ(classifyListLeg(D::True, false, false, false), ListLegVerdict::NoId);
	EXPECT_EQ(classifyListLeg(D::True, true, true, false), ListLegVerdict::Claimed)
		<< "#100: another call's slot holds it";
}

TEST(ListLeg, AnEarlierCallsLegIsNeverAdopted)
{
	// A leg the PBX dropped, or one #883 still holds after its slot was freed, is
	// still listed until 3CX's Remove. It is unslotted and controllable, so the
	// adopt reads would take it for the new call's leg.
	EXPECT_EQ(classifyListLeg(DirectControlField::True, true, false, /*oursAlready=*/true),
	          ListLegVerdict::OursAlready)
		<< "the previous call's freed leg was adopted for the new call";
}

TEST(ListLeg, TheCountsTellTheFilterFromASlotClaim)
{
	// The rerun's question: did direct_control reject the leg, or was it claimed?
	ListLegCounts claimed;
	claimed.add(DirectControlField::True, ListLegVerdict::Claimed);
	EXPECT_EQ(claimed.listed, 1);
	EXPECT_EQ(claimed.controllable, 1);
	EXPECT_EQ(claimed.claimed, 1);
	EXPECT_EQ(claimed.candidates, 0);
	EXPECT_EQ(claimed.dcAbsent + claimed.dcFalse + claimed.dcNotBool, 0) << "a claimed leg is not a filter reject";

	ListLegCounts filtered;
	filtered.add(DirectControlField::Absent, ListLegVerdict::NotControllable);
	filtered.add(DirectControlField::False, ListLegVerdict::NotControllable);
	filtered.add(DirectControlField::NotBool, ListLegVerdict::NotControllable);
	EXPECT_EQ(filtered.listed, 3);
	EXPECT_EQ(filtered.controllable, 0);
	EXPECT_EQ(filtered.dcAbsent, 1);
	EXPECT_EQ(filtered.dcFalse, 1);
	EXPECT_EQ(filtered.dcNotBool, 1);

	ListLegCounts mixed;
	mixed.add(DirectControlField::True, ListLegVerdict::OursAlready);
	mixed.add(DirectControlField::True, ListLegVerdict::NoId);
	mixed.add(DirectControlField::True, ListLegVerdict::Candidate);
	EXPECT_EQ(mixed.listed, 3);
	EXPECT_EQ(mixed.controllable, 3);
	EXPECT_EQ(mixed.oursAlready, 1);
	EXPECT_EQ(mixed.noId, 1);
	EXPECT_EQ(mixed.candidates, 1);
}

// #902: a 403 on the media GET stream, once the far end has answered, is an
// authorisation answer, not a readiness one; an ordinary outbound leg gives up
// after kGetForbiddenMaxAfterAnswer of them in a row instead of 240 attempts.
// A 404/424, a 911/933 and an inbound leg keep the budget.
TEST(GetForbidden, SixConsecutive403sAfterTheAnswerGiveUpAnOrdinaryLeg)
{
	int n = 0;
	for (int i = 1; i < kGetForbiddenMaxAfterAnswer; ++i)
	{
		n = nextGetForbiddenCount(n, 403);
		EXPECT_FALSE(getForbiddenGivesUp(n, /*failFastLeg=*/true)) << "attempt " << i << " is still within the bound";
	}
	n = nextGetForbiddenCount(n, 403);
	EXPECT_EQ(n, kGetForbiddenMaxAfterAnswer);
	EXPECT_TRUE(getForbiddenGivesUp(n, true));
	EXPECT_EQ(kGetForbiddenMaxAfterAnswer, 6) << "the chosen bound (#902): about 3 s of backoff at the 500 ms cap";
}

TEST(GetForbidden, A403BeforeTheAnswerCountsToo)
{
	// desmo, 2026-10-09: fail fast before the answer as well. Before the answer a 403 still
	// counts toward the bound for an ordinary leg.
	int n = 0;
	for (int i = 0; i < kGetForbiddenMaxAfterAnswer; ++i) n = nextGetForbiddenCount(n, 403);
	EXPECT_TRUE(getForbiddenGivesUp(n, true));
}

TEST(GetForbidden, AnyOtherAnswerResetsTheCount)
{
	int n = 0;
	for (int i = 0; i < 5; ++i) n = nextGetForbiddenCount(n, 403);
	ASSERT_EQ(n, 5);
	for (const int status : { 404, 424, 500, 200, -1, 0 })
	{
		EXPECT_EQ(nextGetForbiddenCount(n, status), 0) << status;
	}
	n = nextGetForbiddenCount(n, 404);
	for (int i = 0; i < 5; ++i) n = nextGetForbiddenCount(n, 403);
	EXPECT_FALSE(getForbiddenGivesUp(n, true)) << "5 + 404 + 5 is not 6 in a row";
}

TEST(GetForbidden, A404Or424KeepsTheWholeBudget)
{
	int n = 0;
	for (int i = 0; i < 240; ++i)
	{
		n = nextGetForbiddenCount(n, (i % 2) ? 404 : 424);
		ASSERT_FALSE(getForbiddenGivesUp(n, true)) << "attempt " << i;
	}
}

TEST(GetForbidden, AnEmergencyOrInboundLegNeverGivesUpEarly)
{
	// failFastLeg is false for a 911/933 (Rule 5: nothing may delay or refuse an
	// emergency call, and a connected PSAP may still hear the caller) and for every
	// inbound leg, a PSAP callback among them.
	int n = 0;
	for (int i = 0; i < 240; ++i)
	{
		n = nextGetForbiddenCount(n, 403);
		ASSERT_FALSE(getForbiddenGivesUp(n, /*failFastLeg=*/false)) << "403 #" << (i + 1);
	}
}

}  // namespace
