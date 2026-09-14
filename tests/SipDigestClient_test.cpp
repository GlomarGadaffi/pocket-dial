// SipDigestClient_test.cpp — the CLIENT half of SIP digest auth.
//
// ── Why the RFC vectors are the whole point ──────────────────────────────────
//
// A digest implementation that only agrees with itself is worthless: it will
// agree with itself while failing against every real SBC. Every hash asserted in
// this file is a response value PUBLISHED in an RFC (or in an RFC-Editor
// VERIFIED erratum), not a value produced by this code and then frozen. The
// three sources, and why each earns its place:
//
//   RFC 2617 §3.5     qop="auth". The canonical worked example every digest
//                     implementation on the internet is checked against.
//                     username "Mufasa", password "Circle Of Life" (capital O),
//                     realm "testrealm@host.com".
//                     -> response 6629fae49393a05397450978507c4ef1
//
//   RFC 7616 §3.9.1   qop=auth, algorithm=MD5, with a MODERN challenge shape:
//                     a base64-ish 44-char nonce, a 44-char cnonce, an opaque,
//                     and qop="auth, auth-int" as a LIST with a space in it.
//                     Note the password differs from 2617's by one letter's
//                     case ("Circle of Life") — which is exactly the kind of
//                     detail that makes a second, independent vector worth
//                     having. -> response 8ca523f5e9506fed4657c9700eebdbec
//
//   RFC 2069 §2.4     The legacy NO-qop form, response = MD5(HA1:nonce:HA2).
//                     The value PRINTED in RFC 2069 is wrong; RFC-Editor
//                     Errata ID 749 (status: Verified, reported by Frank
//                     Ellermann) corrects it to 1949323746fe6a43ef61f9606e7febea.
//                     The erratum is the published vector here, not the body
//                     text. Using the printed value would have made this test
//                     fail against a CORRECT implementation, which is its own
//                     useful lesson about "known-good" constants.
//
// Every one of those three was additionally cross-checked against Python's
// hashlib (an implementation with no relationship to the vendored MD5 in
// SipDigest.cpp) before being written down, so a vector transcription typo
// cannot masquerade as an implementation bug.
//
// The vectors are HTTP GETs, not SIP REGISTERs. That is deliberate and correct:
// RFC 3261 §22.4 adopts RFC 2617's algorithm verbatim, with the SIP method
// substituted into HA2 and the SIP Request-URI as the digest-uri. Hashing "GET"
// and "/dir/index.html" exercises the identical code path a "REGISTER" and
// "sip:carrier.example" take — and it is the path with published answers.

#include <gtest/gtest.h>
#include <string>

#include "SipDigest.hpp"

using namespace SipDigest;

namespace {

// ── RFC 2617 §3.5 ────────────────────────────────────────────────────────────
constexpr const char* k2617Challenge =
    "Digest realm=\"testrealm@host.com\", qop=\"auth,auth-int\", "
    "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", "
    "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";
constexpr const char* k2617User     = "Mufasa";
constexpr const char* k2617Password = "Circle Of Life";
constexpr const char* k2617Cnonce   = "0a4f113b";
constexpr const char* k2617Response = "6629fae49393a05397450978507c4ef1";
constexpr const char* k2617Ha1      = "939e7578ed9e3c518a452acee763bce9";

// ── RFC 7616 §3.9.1 (the MD5 arm) ────────────────────────────────────────────
constexpr const char* k7616Challenge =
    "WWW-Authenticate: Digest realm=\"http-auth@example.org\", "
    "qop=\"auth, auth-int\", algorithm=MD5, "
    "nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", "
    "opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"";
constexpr const char* k7616User     = "Mufasa";
constexpr const char* k7616Password = "Circle of Life";
constexpr const char* k7616Cnonce   = "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ";
constexpr const char* k7616Response = "8ca523f5e9506fed4657c9700eebdbec";

// ── RFC 2069 §2.4, as corrected by Verified Errata ID 749 ────────────────────
constexpr const char* k2069Challenge =
    "Digest realm=\"testrealm@host.com\", "
    "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", "
    "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"";
constexpr const char* k2069User     = "Mufasa";
constexpr const char* k2069Password = "CircleOfLife";
constexpr const char* k2069Response = "1949323746fe6a43ef61f9606e7febea";

// Pull one parameter's value out of an emitted Authorization header value.
// Deliberately a separate, dumb implementation rather than parseAuthorization():
// the tests must not be able to pass by agreeing with the parser they are
// testing the emitter against.
std::string paramOf(const std::string& header, const std::string& key)
{
    const std::string needle = key + "=";
    size_t p = 0;
    while ((p = header.find(needle, p)) != std::string::npos)
    {
        // Must be at a parameter boundary, not inside another token
        // (so "nc=" does not match inside "cnonce=").
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

} // namespace

// ---------------------------------------------------------------------------
// Challenge parsing
// ---------------------------------------------------------------------------

TEST(SipDigestChallenge, ParsesTheRFC7616ChallengeIncludingTheHeaderName)
{
    DigestChallenge ch;
    ASSERT_TRUE(parseChallenge(k7616Challenge, ch));
    EXPECT_EQ(ch.realm, "http-auth@example.org");
    EXPECT_EQ(ch.nonce, "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v");
    EXPECT_EQ(ch.opaque, "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS");
    EXPECT_EQ(ch.algorithm, "MD5");
    EXPECT_EQ(ch.qopList, "auth, auth-int");
    EXPECT_FALSE(ch.stale);
    // The header NAME was WWW-Authenticate, so this is a UAS challenge and the
    // answer goes in Authorization.
    EXPECT_FALSE(ch.proxy);
    EXPECT_STREQ(authorizationHeaderName(ch), "Authorization");
}

TEST(SipDigestChallenge, ProxyAuthenticateIsAnsweredInProxyAuthorization)
{
    DigestChallenge ch;
    ASSERT_TRUE(parseChallenge(
        "Proxy-Authenticate: Digest realm=\"sbc.example\", nonce=\"abc123\", qop=\"auth\"",
        ch));
    EXPECT_TRUE(ch.proxy);
    EXPECT_STREQ(authorizationHeaderName(ch), "Proxy-Authorization");

    // And the bare-value form takes its direction from the caller's 407/401.
    DigestChallenge bare;
    ASSERT_TRUE(parseChallenge("Digest realm=\"sbc.example\", nonce=\"abc123\"", bare,
                               /*proxyDefault=*/true));
    EXPECT_TRUE(bare.proxy);
    EXPECT_STREQ(authorizationHeaderName(bare), "Proxy-Authorization");
}

TEST(SipDigestChallenge, StaleTrueIsRecognisedQuotedAndBare)
{
    DigestChallenge bare;
    ASSERT_TRUE(parseChallenge("Digest realm=\"r\", nonce=\"n\", stale=true", bare));
    EXPECT_TRUE(bare.stale);

    DigestChallenge quoted;
    ASSERT_TRUE(parseChallenge("Digest realm=\"r\", nonce=\"n\", stale=\"TRUE\"", quoted));
    EXPECT_TRUE(quoted.stale);

    DigestChallenge absent;
    ASSERT_TRUE(parseChallenge("Digest realm=\"r\", nonce=\"n\"", absent));
    EXPECT_FALSE(absent.stale);

    DigestChallenge falseish;
    ASSERT_TRUE(parseChallenge("Digest realm=\"r\", nonce=\"n\", stale=false", falseish));
    EXPECT_FALSE(falseish.stale);
}

TEST(SipDigestChallenge, ANonceLessChallengeIsRejected)
{
    // There is nothing to answer: a response computed over an empty nonce is a
    // digest the server can never reproduce.
    DigestChallenge ch;
    EXPECT_FALSE(parseChallenge("Digest realm=\"r\", qop=\"auth\"", ch));
    EXPECT_FALSE(parseChallenge("Basic realm=\"r\"", ch));
    EXPECT_FALSE(parseChallenge("", ch));
}

// ---------------------------------------------------------------------------
// qop selection — the substring trap
// ---------------------------------------------------------------------------

TEST(SipDigestQop, AuthIntOnlyIsRefusedRatherThanMatchedAsASubstring)
{
    // "auth-int" CONTAINS "auth". A naive find() says yes and the client then
    // answers qop=auth against a server that never offered it.
    DigestChallenge ch;
    ASSERT_TRUE(parseChallenge("Digest realm=\"r\", nonce=\"n\", qop=\"auth-int\"", ch));
    std::string qop = "sentinel";
    EXPECT_FALSE(selectQop(ch, qop));
    EXPECT_EQ(qop, "");

    // And the whole build refuses, rather than emitting a wrong header.
    std::string out = "untouched";
    EXPECT_FALSE(buildAuthorization(ch, "u", "p", "REGISTER", "sip:x", 1, "cn", out));
    EXPECT_EQ(out, "untouched");
}

TEST(SipDigestQop, AuthIsPickedOutOfAListAndNoQopMeansLegacy)
{
    DigestChallenge list;
    ASSERT_TRUE(parseChallenge(
        "Digest realm=\"r\", nonce=\"n\", qop=\"auth-int, auth\"", list));
    std::string qop;
    EXPECT_TRUE(selectQop(list, qop));
    EXPECT_EQ(qop, "auth");

    DigestChallenge none;
    ASSERT_TRUE(parseChallenge("Digest realm=\"r\", nonce=\"n\"", none));
    std::string legacy = "sentinel";
    EXPECT_TRUE(selectQop(none, legacy));
    EXPECT_EQ(legacy, "");   // true + empty == RFC 2069, not "unsupported"
}

// ---------------------------------------------------------------------------
// Algorithm handling. MD5-sess is IMPLEMENTED; SHA-2 is REFUSED.
// ---------------------------------------------------------------------------

TEST(SipDigestAlgorithm, ClassifiesAndRefusesRFC8760)
{
    auto algOf = [](const char* token) {
        DigestChallenge ch;
        EXPECT_TRUE(parseChallenge(
            std::string("Digest realm=\"r\", nonce=\"n\", algorithm=") + token, ch));
        return algorithmOf(ch);
    };
    EXPECT_EQ(algOf("MD5"),          DigestAlgorithm::Md5);
    EXPECT_EQ(algOf("md5"),          DigestAlgorithm::Md5);
    EXPECT_EQ(algOf("MD5-sess"),     DigestAlgorithm::Md5Sess);
    EXPECT_EQ(algOf("md5-SESS"),     DigestAlgorithm::Md5Sess);
    EXPECT_EQ(algOf("SHA-256"),      DigestAlgorithm::Unsupported);
    EXPECT_EQ(algOf("SHA-512-256"),  DigestAlgorithm::Unsupported);
    EXPECT_EQ(algOf("SHA-256-sess"), DigestAlgorithm::Unsupported);

    DigestChallenge absent;
    ASSERT_TRUE(parseChallenge("Digest realm=\"r\", nonce=\"n\"", absent));
    EXPECT_EQ(algorithmOf(absent), DigestAlgorithm::Md5);  // RFC 7616 §3.3 default
}

TEST(SipDigestAlgorithm, ASha256ChallengeIsRefusedNotAnsweredWithMd5)
{
    // This is the "reject it explicitly" half of the requirement. Answering a
    // SHA-256 challenge with an MD5 response produces a 401 loop that looks, on
    // the wire, exactly like a wrong password.
    DigestChallenge ch;
    ASSERT_TRUE(parseChallenge(
        "Digest realm=\"r\", nonce=\"n\", qop=\"auth\", algorithm=SHA-256", ch));
    std::string out = "untouched";
    EXPECT_FALSE(buildAuthorization(ch, "u", "p", "REGISTER", "sip:x", 1, "cn", out));
    EXPECT_EQ(out, "untouched");
}

TEST(SipDigestAlgorithm, Md5SessBindsHa1ToTheNonceAndCnonce)
{
    // NOTE: no RFC publishes an MD5-sess worked example, so unlike every other
    // hash in this file this one is checked STRUCTURALLY, against the RFC 7616
    // §3.4.2 definition composed from md5Hex() directly — not against a value
    // this implementation produced. The honest statement is: the construction is
    // pinned, the constant is not third-party.
    const std::string ha1 = computeHa1("u", "r", "p");
    EXPECT_EQ(computeHa1Sess(ha1, "thenonce", "thecnonce"),
              md5Hex(ha1 + ":thenonce:thecnonce"));

    // Changing only the cnonce must change HA1-sess — that is the entire reason
    // MD5-sess exists, and a client that cached HA1 across cnonces would break it.
    EXPECT_NE(computeHa1Sess(ha1, "thenonce", "cnonceA"),
              computeHa1Sess(ha1, "thenonce", "cnonceB"));

    // And the emitted response must be the session HA1's, not the plain one.
    DigestChallenge ch;
    ASSERT_TRUE(parseChallenge(
        "Digest realm=\"r\", nonce=\"thenonce\", qop=\"auth\", algorithm=MD5-sess", ch));
    std::string out;
    ASSERT_TRUE(buildAuthorization(ch, "u", "p", "REGISTER", "sip:x", 1, "thecnonce", out));
    const std::string expected = computeResponse(
        computeHa1Sess(ha1, "thenonce", "thecnonce"),
        "REGISTER", "sip:x", "thenonce", "00000001", "thecnonce", "auth");
    EXPECT_EQ(paramOf(out, "response"), expected);
    EXPECT_NE(paramOf(out, "response"),
              computeResponse(ha1, "REGISTER", "sip:x", "thenonce",
                              "00000001", "thecnonce", "auth"));
}

// ---------------------------------------------------------------------------
// THE RFC VECTORS
// ---------------------------------------------------------------------------

TEST(SipDigestClientVectors, RFC2617Section35QopAuth)
{
    DigestChallenge ch;
    ASSERT_TRUE(parseChallenge(k2617Challenge, ch));
    EXPECT_EQ(computeHa1(k2617User, ch.realm, k2617Password), k2617Ha1);

    std::string out;
    ASSERT_TRUE(buildAuthorization(ch, k2617User, k2617Password,
                                   "GET", "/dir/index.html",
                                   /*nc=*/1, k2617Cnonce, out));

    // The published response hash. If this line ever changes, the change is wrong.
    EXPECT_EQ(paramOf(out, "response"), k2617Response);

    // And the rest of the header reproduces the RFC's Authorization example
    // parameter for parameter.
    EXPECT_EQ(paramOf(out, "username"), "Mufasa");
    EXPECT_EQ(paramOf(out, "realm"),    "testrealm@host.com");
    EXPECT_EQ(paramOf(out, "nonce"),    "dcd98b7102dd2f0e8b11d0f600bfb0c093");
    EXPECT_EQ(paramOf(out, "uri"),      "/dir/index.html");
    EXPECT_EQ(paramOf(out, "qop"),      "auth");
    EXPECT_EQ(paramOf(out, "nc"),       "00000001");
    EXPECT_EQ(paramOf(out, "cnonce"),   "0a4f113b");
    EXPECT_EQ(paramOf(out, "opaque"),   "5ccc069c403ebaf9f0171e9517f40e41");
    // The 2617 challenge named NO algorithm, so neither does the answer — just
    // like the RFC's own example Authorization header.
    EXPECT_EQ(out.find("algorithm"), std::string::npos);
}

TEST(SipDigestClientVectors, RFC7616Section391Md5)
{
    DigestChallenge ch;
    ASSERT_TRUE(parseChallenge(k7616Challenge, ch));

    std::string out;
    ASSERT_TRUE(buildAuthorization(ch, k7616User, k7616Password,
                                   "GET", "/dir/index.html",
                                   /*nc=*/1, k7616Cnonce, out));

    EXPECT_EQ(paramOf(out, "response"), k7616Response);
    EXPECT_EQ(paramOf(out, "algorithm"), "MD5");   // echoed, because it was sent
    EXPECT_EQ(paramOf(out, "qop"), "auth");        // picked out of "auth, auth-int"
    EXPECT_EQ(paramOf(out, "nc"), "00000001");
    EXPECT_EQ(paramOf(out, "opaque"),
              "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS");
}

TEST(SipDigestClientVectors, RFC2069LegacyNoQopPerErratum749)
{
    DigestChallenge ch;
    ASSERT_TRUE(parseChallenge(k2069Challenge, ch));
    std::string qop = "x";
    ASSERT_TRUE(selectQop(ch, qop));
    ASSERT_EQ(qop, "");   // no qop offered -> legacy

    std::string out;
    ASSERT_TRUE(buildAuthorization(ch, k2069User, k2069Password,
                                   "GET", "/dir/index.html",
                                   /*nc=*/1, "ignored-cnonce", out));

    EXPECT_EQ(paramOf(out, "response"), k2069Response);

    // The load-bearing negative assertions. An RFC 2069 server IGNORES qop/nc/
    // cnonce and computes MD5(HA1:nonce:HA2). If we compute the short form but
    // still SEND those parameters, a server that does look at them computes the
    // long form instead and the two sides disagree with no diagnostic anywhere.
    EXPECT_EQ(out.find("qop="),    std::string::npos);
    EXPECT_EQ(out.find("nc="),     std::string::npos);
    EXPECT_EQ(out.find("cnonce="), std::string::npos);
}

// ---------------------------------------------------------------------------
// Emission shape
// ---------------------------------------------------------------------------

TEST(SipDigestEmit, NcIsEightHexDigitsAndQopAndNcAreUnquoted)
{
    EXPECT_EQ(formatNc(1),          "00000001");
    EXPECT_EQ(formatNc(0),          "00000000");
    EXPECT_EQ(formatNc(15),         "0000000f");
    EXPECT_EQ(formatNc(4096),       "00001000");
    EXPECT_EQ(formatNc(0xFFFFFFFFu), "ffffffff");

    DigestChallenge ch;
    ASSERT_TRUE(parseChallenge(
        "Digest realm=\"r\", nonce=\"n\", qop=\"auth\", algorithm=MD5", ch));
    std::string out;
    ASSERT_TRUE(buildAuthorization(ch, "u", "p", "REGISTER", "sip:r", 42, "cn", out));

    // Quoting matters on the wire: Kamailio and several SBCs reject a QUOTED nc
    // outright, and the RFC 7616 §3.4 ABNF makes nc/qop/algorithm bare tokens.
    EXPECT_NE(out.find("nc=0000002a"),   std::string::npos);
    EXPECT_EQ(out.find("nc=\""),         std::string::npos);
    EXPECT_NE(out.find("qop=auth"),      std::string::npos);
    EXPECT_EQ(out.find("qop=\""),        std::string::npos);
    EXPECT_NE(out.find("algorithm=MD5"), std::string::npos);
    EXPECT_EQ(out.find("algorithm=\""),  std::string::npos);
    // ...and the opposite for the quoted-string parameters.
    EXPECT_NE(out.find("username=\"u\""), std::string::npos);
    EXPECT_NE(out.find("uri=\"sip:r\""),  std::string::npos);
}

TEST(SipDigestEmit, QopAuthWithoutACnonceIsRefused)
{
    // RFC 7616 §3.4 requires a cnonce under qop. Hashing an empty one "works"
    // and destroys the client-nonce's entire purpose.
    DigestChallenge ch;
    ASSERT_TRUE(parseChallenge("Digest realm=\"r\", nonce=\"n\", qop=\"auth\"", ch));
    std::string out = "untouched";
    EXPECT_FALSE(buildAuthorization(ch, "u", "p", "REGISTER", "sip:r", 1, "", out));
    EXPECT_EQ(out, "untouched");
}

TEST(SipDigestEmit, Md5SessWithoutQopIsRefusedBecauseNobodyCouldVerifyIt)
{
    // The combination that LOOKS answerable and is not. HA1-sess is
    // MD5(HA1:nonce:cnonce), so the server needs our cnonce to recompute it — but
    // the legacy no-qop emission omits cnonce entirely, and RFC 2617 says a
    // cnonce MUST NOT be sent without qop. Emitting anyway produces a perfectly
    // well-formed header carrying a response nobody on earth can verify, which is
    // the same silent-wrong-answer failure the SHA-2 refusal exists to prevent.
    DigestChallenge ch;
    ASSERT_TRUE(parseChallenge(
        "Digest realm=\"r\", nonce=\"n\", algorithm=MD5-sess", ch));
    ASSERT_EQ(algorithmOf(ch), DigestAlgorithm::Md5Sess);
    std::string qop = "x";
    ASSERT_TRUE(selectQop(ch, qop));
    ASSERT_EQ(qop, "") << "no qop offered at all";

    std::string out = "untouched";
    EXPECT_FALSE(buildAuthorization(ch, "u", "p", "REGISTER", "sip:x", 1, "cn", out));
    EXPECT_EQ(out, "untouched");

    // ...and the very same challenge WITH qop is answerable, so the refusal is
    // about the missing qop and not about MD5-sess itself.
    DigestChallenge withQop;
    ASSERT_TRUE(parseChallenge(
        "Digest realm=\"r\", nonce=\"n\", qop=\"auth\", algorithm=MD5-sess", withQop));
    std::string ok;
    EXPECT_TRUE(buildAuthorization(withQop, "u", "p", "REGISTER", "sip:x", 1, "cn", ok));
}

TEST(SipDigestEmit, CnoncesAreFreshAndNotObviouslyPredictable)
{
    // A predictable cnonce lets an observer of one response precompute others
    // (RFC 7616 §5.10). We cannot prove unpredictability in a unit test; we can
    // prove the thing that actually regresses — a cnonce that is CONSTANT.
    const std::string a = makeCnonce();
    const std::string b = makeCnonce();
    EXPECT_EQ(a.size(), 16u);
    EXPECT_NE(a, b);
    for (char c : a)
    {
        EXPECT_TRUE((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) << "non-hex cnonce";
    }
}

// ---------------------------------------------------------------------------
// The scanner is shared with the SERVER half — prove the refactor kept it.
// ---------------------------------------------------------------------------

TEST(SipDigestSharedScanner, ACommaInsideAQuotedValueDoesNotSplitAParameter)
{
    // The reason parseChallenge and parseAuthorization share one scanner: this
    // rule is subtle and a second copy would not have it. `qop="auth, auth-int"`
    // in the challenge and an opaque containing a comma in the credential are
    // the same production.
    DigestChallenge ch;
    ASSERT_TRUE(parseChallenge(
        "Digest realm=\"a,b\", nonce=\"n\", qop=\"auth, auth-int\", opaque=\"x,y\"", ch));
    EXPECT_EQ(ch.realm,   "a,b");
    EXPECT_EQ(ch.qopList, "auth, auth-int");
    EXPECT_EQ(ch.opaque,  "x,y");

    DigestAuth au;
    ASSERT_TRUE(parseAuthorization(
        "Digest username=\"u\", realm=\"a,b\", nonce=\"n\", response=\"r\", opaque=\"x,y\"",
        au));
    EXPECT_EQ(au.realm,  "a,b");
    EXPECT_EQ(au.opaque, "x,y");
}

TEST(SipDigestSharedScanner, ServerSideParseAuthorizationIsUnchangedByTheRefactor)
{
    // Regression guard for the extraction: the server half's tolerances
    // (optional header name, reordering, unknown parameters, whitespace) must be
    // exactly what they were before the scanner moved.
    DigestAuth au;
    ASSERT_TRUE(parseAuthorization(
        "Authorization:  Digest  nc=00000002 ,  username = \"alice\" , "
        "future-param=whatever, response=\"deadbeef\", qop=auth, realm=\"pocketdial\"",
        au));
    EXPECT_EQ(au.username, "alice");
    EXPECT_EQ(au.response, "deadbeef");
    EXPECT_EQ(au.nc,       "00000002");
    EXPECT_EQ(au.qop,      "auth");
    EXPECT_EQ(au.realm,    "pocketdial");

    // Still NOT a digest credential without a username or a response.
    DigestAuth none;
    EXPECT_FALSE(parseAuthorization("Digest realm=\"pocketdial\"", none));
    EXPECT_FALSE(parseAuthorization("Basic dXNlcjpwYXNz", none));

    // A full Proxy-Authorization LINE is still refused by the server-side parser,
    // exactly as before — the name is not one it strips, so the scheme check
    // fails. Pinned so that widening it later is a deliberate decision.
    DigestAuth proxy;
    EXPECT_FALSE(parseAuthorization(
        "Proxy-Authorization: Digest username=\"u\", response=\"r\"", proxy));
}

// ---------------------------------------------------------------------------
// Round trip: what this client emits, the server half of this very module
// accepts. Not a substitute for the RFC vectors — an addition to them.
// ---------------------------------------------------------------------------

TEST(SipDigestRoundTrip, TheRegistrarAcceptsWhatThisClientEmits)
{
    const std::string realm = "pocketdial";
    const std::string nonce = generateNonce();
    const std::string challenge = buildWwwAuthenticate(realm, nonce);

    DigestChallenge ch;
    ASSERT_TRUE(parseChallenge(challenge, ch));
    EXPECT_EQ(ch.realm, realm);
    EXPECT_EQ(ch.nonce, nonce);

    std::string header;
    ASSERT_TRUE(buildAuthorization(ch, "1001", "s3cret", "REGISTER",
                                   "sip:pocketdial", 1, makeCnonce(), header));

    DigestAuth au;
    ASSERT_TRUE(parseAuthorization(header, au));
    EXPECT_TRUE(validateNonce(au.nonce));
    EXPECT_TRUE(verify(au, computeHa1("1001", realm, "s3cret"), "REGISTER"));

    // A wrong password must not verify — otherwise the round trip proves nothing.
    EXPECT_FALSE(verify(au, computeHa1("1001", realm, "wrong"), "REGISTER"));
    // Nor may the method be substituted: HA2 binds it.
    EXPECT_FALSE(verify(au, computeHa1("1001", realm, "s3cret"), "INVITE"));
}
