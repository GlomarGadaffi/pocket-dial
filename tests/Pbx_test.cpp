// Pbx_test.cpp — unit coverage for the Class A PBX feature sweep's pure routing
// logic: Refer-To target extraction (blind transfer), ring-group membership
// parsing, and the call-forward config value type. These helpers live in the
// header-only PbxConfig.hpp so they can be exercised here without linking the full
// RequestsHandler (which pulls in sockets / the object pools).

#include <gtest/gtest.h>
#include "PbxConfig.hpp"
#include "SipMessage.hpp"
#include "SipMessageTypes.h"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#endif

#include <string>
#include <sstream>

// ── Refer-To extraction (RFC 3515 blind transfer) ────────────────────────────

TEST(Pbx, ReferToAngleBracketUserHost) {
    EXPECT_EQ(pbx::parseReferToTarget("<sip:200@192.168.4.1:5060>"), "200");
}

TEST(Pbx, ReferToWithDisplayNameAndParams) {
    EXPECT_EQ(pbx::parseReferToTarget("\"Bob\" <sip:201@host>;some=param"), "201");
}

TEST(Pbx, ReferToBareUri) {
    EXPECT_EQ(pbx::parseReferToTarget("sip:300@host"), "300");
}

TEST(Pbx, ReferToNoHostPartStopsAtBracket) {
    // Some UAs emit a host-less URI; the user-part must still be recovered.
    EXPECT_EQ(pbx::parseReferToTarget("<sip:404>"), "404");
}

TEST(Pbx, ReferToNoHostPartStopsAtParam) {
    EXPECT_EQ(pbx::parseReferToTarget("sip:405;user=phone"), "405");
}

TEST(Pbx, ReferToMissingSipUriReturnsEmpty) {
    EXPECT_TRUE(pbx::parseReferToTarget("tel:+15551234").empty());
    EXPECT_TRUE(pbx::parseReferToTarget("").empty());
}

TEST(Pbx, ReferToEmptyUserPartReturnsEmpty) {
    // "sip:@host" has no user-part — must not yield a spurious target.
    EXPECT_TRUE(pbx::parseReferToTarget("<sip:@host>").empty());
}

// ── Ring-group membership parsing ─────────────────────────────────────────────

TEST(Pbx, SplitMembersCommaSeparated) {
    auto m = pbx::splitMembers("100,101,102");
    ASSERT_EQ(m.size(), 3u);
    EXPECT_EQ(m[0], "100");
    EXPECT_EQ(m[1], "101");
    EXPECT_EQ(m[2], "102");
}

TEST(Pbx, SplitMembersMixedWhitespaceAndCommas) {
    auto m = pbx::splitMembers("  100 , 101 ,,  102  ");
    ASSERT_EQ(m.size(), 3u);
    EXPECT_EQ(m[0], "100");
    EXPECT_EQ(m[1], "101");
    EXPECT_EQ(m[2], "102");
}

TEST(Pbx, SplitMembersEmptyYieldsNone) {
    EXPECT_TRUE(pbx::splitMembers("").empty());
    EXPECT_TRUE(pbx::splitMembers("  , , ").empty());
}

TEST(Pbx, SplitMembersBoundedByClientCap) {
    // Build an over-long list; splitMembers must clamp to POCKETDIAL_MAX_CLIENTS.
    std::string csv;
    for (int i = 0; i < POCKETDIAL_MAX_CLIENTS * 2; ++i) {
        if (i) csv += ',';
        csv += std::to_string(1000 + i);
    }
    auto m = pbx::splitMembers(csv);
    EXPECT_LE(m.size(), static_cast<size_t>(POCKETDIAL_MAX_CLIENTS));
}

TEST(Pbx, JoinRoundTripsSplit) {
    auto m = pbx::splitMembers("600,601,602");
    EXPECT_EQ(pbx::joinMembers(m), "600,601,602");
}

// ── Call pickup codes (Issue #68) ─────────────────────────────────────────────

TEST(Pbx, IsGroupPickupCodeMatchesOnlyStarEight) {
    EXPECT_TRUE(pbx::isGroupPickupCode("*8"));
    EXPECT_FALSE(pbx::isGroupPickupCode("*80"));
    EXPECT_FALSE(pbx::isGroupPickupCode("8"));
    EXPECT_FALSE(pbx::isGroupPickupCode(""));
}

TEST(Pbx, DirectedPickupTargetExtractsExtensionAfterDoubleStar) {
    EXPECT_EQ(pbx::directedPickupTarget("**204"), "204");
    EXPECT_EQ(pbx::directedPickupTarget("**100"), "100");
}

TEST(Pbx, DirectedPickupTargetEmptyForNonMatchingInput) {
    EXPECT_EQ(pbx::directedPickupTarget("**"), "");      // no extension named
    EXPECT_EQ(pbx::directedPickupTarget("*8"), "");       // that's the group code
    EXPECT_EQ(pbx::directedPickupTarget("*204"), "");     // single star, not directed pickup
    EXPECT_EQ(pbx::directedPickupTarget("204"), "");      // plain extension
    EXPECT_EQ(pbx::directedPickupTarget(""), "");
}

// ── Call-forward config value type ───────────────────────────────────────────

TEST(Pbx, ForwardConfigEmptyByDefault) {
    pbx::ForwardConfig cfg;
    EXPECT_TRUE(cfg.empty());
}

TEST(Pbx, ForwardConfigNonEmptyWhenAnyTriggerSet) {
    pbx::ForwardConfig cfg;
    cfg.busy = "200";
    EXPECT_FALSE(cfg.empty());

    cfg.busy.clear();
    cfg.noAnswer = "201";
    EXPECT_FALSE(cfg.empty());

    cfg.noAnswer.clear();
    EXPECT_TRUE(cfg.empty());
}

// ── Star/pound codes stay dialable AORs (future feature codes) ────────────────
//
// isValidAor() is a private RequestsHandler method (not linked into this test
// binary), but its accept rule is exact and stable: non-empty, no longer than
// kMaxAorLen (64), every char alphanumeric or one of '.', '-', '_', '+', '*', '#'.
// This free function mirrors it so we can assert star/pound codes are still
// accepted (the roster *55 behaviour was removed, but the AOR charset change
// that makes star codes dialable is KEPT) and, as of issue #194, that the length
// bound added alongside the charset check (RequestsHandler.cpp's kMaxAorLen --
// see CallDetailRecord.hpp's corrected comment for why one was needed at all:
// isValidAor() used to be claimed as a length bound elsewhere in the codebase
// when it never was one) is mirrored here too.
namespace {
constexpr size_t kMirrorMaxAorLen = 64;
bool mirrorsIsValidAor(const std::string& s) {
    if (s.empty() || s.size() > kMirrorMaxAorLen) return false;
    for (char c : s) {
        if (!std::isalnum(static_cast<unsigned char>(c)) &&
            c != '.' && c != '-' && c != '_' && c != '+' &&
            c != '*' && c != '#') {
            return false;
        }
    }
    return true;
}
}

TEST(Aor, StarAndPoundCodesAreDialable) {
    EXPECT_TRUE(mirrorsIsValidAor("*55"));    // star codes are dialable AORs
    EXPECT_TRUE(mirrorsIsValidAor("#9"));     // pound codes too
    EXPECT_FALSE(mirrorsIsValidAor(""));      // empty still rejected
    EXPECT_FALSE(mirrorsIsValidAor("55 5"));  // whitespace still rejected
    EXPECT_FALSE(mirrorsIsValidAor("a@b"));   // delimiters/host chars still rejected
}

TEST(Aor, LengthIsBoundedAt64Chars) {
    // Issue #194 audit: isValidAor() was charset-only with no length check, so
    // an unbounded AOR (nothing stops a REGISTER/INVITE from carrying one) could
    // heap-allocate without limit inside every CdrRing slot. 64 chars is exactly
    // at the bound; 65 must be refused.
    const std::string ok(64, 'a');
    const std::string tooLong(65, 'a');
    EXPECT_TRUE(mirrorsIsValidAor(ok));
    EXPECT_FALSE(mirrorsIsValidAor(tooLong));
}

// ── Register-beep INVITE: auto-answer headers + correct Content-Length ─────────
//
// The register beep is a server-originated INVITE that mirrors the 999 all-page
// auto-answer header set, carrying a minimal SDP. The 777 path was bitten by a wrong
// Content-Length (UDP peers drop such packets), so we assert the advertised length
// matches the actual body. RequestsHandler isn't linked here, so the request is
// constructed inline using the SAME template sendRegisterBeep() emits, then parsed
// back through SipMessage and enforceG711()/syncContentLength() are exercised.
namespace {
size_t parsedContentLength(const SipMessage& msg) {
    std::string cl(msg.getContentLength());
    size_t colon = cl.find(':');
    if (colon == std::string::npos) return static_cast<size_t>(-1);
    return static_cast<size_t>(std::stoul(cl.substr(colon + 1)));
}

std::string buildTestBeepInvite(const std::string& body) {
    std::ostringstream ss;
    ss << "INVITE sip:106@192.168.4.5:5060 SIP/2.0\r\n"
       << "Via: SIP/2.0/UDP 192.168.4.1:5060;branch=z9hG4bKabc123\r\n"
       << "From: \"PocketDial\" <sip:pbx@192.168.4.1:5060>;tag=tag1\r\n"
       << "To: <sip:106@192.168.4.1>\r\n"
       << "Call-ID: beep-1@192.168.4.1\r\n"
       << "CSeq: 1 INVITE\r\n"
       << "Max-Forwards: 70\r\n"
       << "Contact: <sip:pbx@192.168.4.1:5060;transport=UDP>\r\n"
       << "Call-Info: <sip:any>;answer-after=0\r\n"
       << "Alert-Info: info=alert-autoanswer\r\n"
       << "Alert-Info: answer-after=0\r\n"
       << "Alert-Info: intercom=true\r\n"
       << "P-Auto-Answer: normal\r\n"
       << "Content-Type: application/sdp\r\n"
       << "Content-Length: " << body.size() << "\r\n\r\n"
       << body;
    return ss.str();
}

std::string beepSdpBody() {
    return
        "v=0\r\n"
        "o=- 0 0 IN IP4 192.168.4.1\r\n"
        "s=pocket-dial\r\n"
        "c=IN IP4 192.168.4.1\r\n"
        "t=0 0\r\n"
        "m=audio 9 RTP/AVP 0\r\n"
        "a=inactive\r\n";
}
}

TEST(RegisterBeep, InviteCarriesAutoAnswerHeaders) {
    SipMessage msg(buildTestBeepInvite(beepSdpBody()), sockaddr_in{});
    const std::string raw = msg.toString();
    EXPECT_EQ(std::string(msg.getType()), std::string(SipMessageTypes::INVITE));
    // The 999-style intercom auto-answer header set must be present so a Yealink
    // auto-answers in intercom mode and plays its alert tone.
    EXPECT_NE(raw.find("Call-Info: <sip:any>;answer-after=0"), std::string::npos);
    EXPECT_NE(raw.find("Alert-Info: info=alert-autoanswer"), std::string::npos);
    EXPECT_NE(raw.find("Alert-Info: intercom=true"), std::string::npos);
    EXPECT_NE(raw.find("P-Auto-Answer: normal"), std::string::npos);
    // Signaling-only: the offer is inactive (no RTP will flow from the server).
    EXPECT_NE(raw.find("a=inactive"), std::string::npos);
}

TEST(RegisterBeep, InviteContentLengthMatchesBody) {
    std::string body = beepSdpBody();
    SipMessage msg(buildTestBeepInvite(body), sockaddr_in{});
    EXPECT_EQ(parsedContentLength(msg), body.size());
}

TEST(RegisterBeep, EnforceG711AndSyncKeepsContentLengthCorrect) {
    // sendRegisterBeep() runs enforceG711() then syncContentLength() on the offer.
    // enforceG711() rewrites the m= codec list (changing the body length); the
    // advertised Content-Length must still equal the actual body afterwards, else the
    // offer is dropped on UDP (the exact 777-path bug this guards against).
    SipMessage msg(buildTestBeepInvite(beepSdpBody()), sockaddr_in{});
    msg.enforceG711();
    msg.syncContentLength();

    const std::string out = msg.toString();
    size_t sep = out.find("\r\n\r\n");
    ASSERT_NE(sep, std::string::npos);
    size_t actualBody = out.size() - (sep + 4);
    EXPECT_EQ(parsedContentLength(msg), actualBody);
}

// ── Reserved/emergency/PSTN-shaped REGISTER identity guard (Issue #163) ────────
//
// Pure coverage for the three PbxConfig.hpp helpers behind onRegister()'s
// identity guard and findProvisioningInfo()'s recheck. The REGISTER-level
// behaviour (403 in every registrar mode) is covered separately in
// RegisterIdentityGuard_test.cpp, which links the full RequestsHandler; these
// stay here, alongside the rest of PbxConfig.hpp's pure logic, because they
// need nothing else.

TEST(ReservedExtension, MatchesExactlyTheEightReservedOrEmergencyLiterals) {
    // Issue #246 added "796" (the voicemail retrieval pilot) as the eighth --
    // deliberately updated here, not left broken, since this test existing
    // at all is the point: it forces exactly this kind of touch whenever the
    // literal set changes.
    for (const char* ext : {"777", "999", "888", "555", "440", "911", "933", "796"}) {
        EXPECT_TRUE(pbx::isReservedExtension(ext)) << ext;
    }
}

TEST(ReservedExtension, DoesNotMatchOrdinaryExtensionsOrLookalikes) {
    // Real extensions this codebase's own docs/tests use, an empty AOR, and
    // near-miss spellings that must NOT be swept in by a sloppier comparison
    // (substring, prefix, or digit-only match).
    for (const char* ext : {"101", "1001", "610", "620", "reception", "",
                             "9110", "0911", "91", "4400", "*440", "555a"}) {
        EXPECT_FALSE(pbx::isReservedExtension(ext)) << ext;
    }
}

TEST(LooksLikePstnAor, AcceptsAllDigitAtOrAboveTheConfiguredThreshold) {
    // Default threshold is POCKETDIAL_MIN_PSTN_AOR_DIGITS (PoolConfig.hpp) = 7.
    EXPECT_TRUE(pbx::looksLikePstnAor("5551234"));       // exactly 7
    EXPECT_TRUE(pbx::looksLikePstnAor("15551234567"));   // NANP w/ country code, no '+'
}

TEST(LooksLikePstnAor, RejectsShortOrNonDigitOrEmpty) {
    EXPECT_FALSE(pbx::looksLikePstnAor(""));
    EXPECT_FALSE(pbx::looksLikePstnAor("101"));          // ordinary 3-digit extension
    EXPECT_FALSE(pbx::looksLikePstnAor("620"));
    EXPECT_FALSE(pbx::looksLikePstnAor("555123"));       // one short of the threshold
    EXPECT_FALSE(pbx::looksLikePstnAor("555123a"));      // right length, not all-digit
    EXPECT_FALSE(pbx::looksLikePstnAor("+5551234"));     // '+' is handled separately
}

TEST(IsReservedOrPstnAor, BlocksEveryReservedLiteral) {
    for (const char* ext : {"777", "999", "888", "555", "440", "911", "933", "796"}) {
        EXPECT_TRUE(pbx::isReservedOrPstnAor(ext)) << ext;
    }
}

TEST(IsReservedOrPstnAor, BlocksAnyLeadingPlusRegardlessOfLength) {
    EXPECT_TRUE(pbx::isReservedOrPstnAor("+15551234567"));
    EXPECT_TRUE(pbx::isReservedOrPstnAor("+1"));
    EXPECT_TRUE(pbx::isReservedOrPstnAor("+"))
        << "unconditional per the issue: reject ANY leading '+', not just a "
           "plausibly-long one";
}

TEST(IsReservedOrPstnAor, BlocksLongAllDigitAors) {
    EXPECT_TRUE(pbx::isReservedOrPstnAor("5551234567"));
}

TEST(IsReservedOrPstnAor, AllowsOrdinaryExtensionsAndAlphanumericNames) {
    // The other half of every guard in this file: it must refuse ONLY the
    // three specific cases above, not every '+'-free, non-3-digit AOR.
    for (const char* ext : {"101", "1001", "610", "620", "reception",
                             "voicemail", "*55", "*8", "**204", "1_0.1-a"}) {
        EXPECT_FALSE(pbx::isReservedOrPstnAor(ext)) << ext;
    }
}
