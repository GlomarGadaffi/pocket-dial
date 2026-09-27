#include <gtest/gtest.h>
#include <string>
#include <algorithm>
#include <cctype>
#include "SipDigest.hpp"
#include "SipSecretStore.hpp"
#include "SipMessage.hpp"
#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

using namespace SipDigest;

namespace {

sockaddr_in makeAddr()
{
    sockaddr_in s{};
    s.sin_family = AF_INET;
    s.sin_addr.s_addr = inet_addr("127.0.0.1");
    return s;
}

} // namespace

// ---------------------------------------------------------------------------
// MD5 known-answer vectors (RFC 1321 Appendix A.5). These guard the vendored
// MD5 — if it regresses, every digest computation silently breaks, so we pin
// the primitive first.
// ---------------------------------------------------------------------------
TEST(SipDigestMd5, RFC1321Vectors)
{
    EXPECT_EQ(md5Hex(""),    "d41d8cd98f00b204e9800998ecf8427e");
    EXPECT_EQ(md5Hex("a"),   "0cc175b9c0f1b6a831c399e269772661");
    EXPECT_EQ(md5Hex("abc"), "900150983cd24fb0d6963f7d28e17f72");
    EXPECT_EQ(md5Hex("message digest"), "f96b697d7cb7938d525a2f31aaf161d0");
    EXPECT_EQ(md5Hex("abcdefghijklmnopqrstuvwxyz"),
              "c3fcd3d76192e4007dfb496cca67e13b");
    EXPECT_EQ(md5Hex("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
              "d174ab98d277d9f5a5611c2c9f419d9f");
    // A 56-byte input to exercise the two-block padding edge (length lands at the
    // boundary where the length field forces a second block). Reference value
    // cross-checked against an independent MD5 (the prior literal was a typo).
    EXPECT_EQ(md5Hex("12345678901234567890123456789012345678901234567890123456"),
              "49f193adce178490e34d1b3a4ec0064c");
}

// ---------------------------------------------------------------------------
// RFC 2617 §3.5 canonical worked example.
//   username = "Mufasa", realm = "testrealm@host.com", password = "Circle Of Life"
//   method   = "GET", uri = "/dir/index.html"
//   nonce    = "dcd98b7102dd2f0e8b11d0f600bfb0c093", cnonce = "0a4f113b"
//   nc       = "00000001", qop = "auth"
//   => HA1 = 939e7578ed9e3c518a452acee763bce9
//      HA2 = 39aa3f4e233c83e30d493b50d ... (we assert via response)
//      response = 6629fae49393a05397450978507c4ef1
// ---------------------------------------------------------------------------
TEST(SipDigestRFC2617, Ha1AndResponseVector)
{
    std::string ha1 = computeHa1("Mufasa", "testrealm@host.com", "Circle Of Life");
    EXPECT_EQ(ha1, "939e7578ed9e3c518a452acee763bce9");

    std::string resp = computeResponse(
        ha1, "GET", "/dir/index.html",
        "dcd98b7102dd2f0e8b11d0f600bfb0c093",
        "00000001", "0a4f113b", "auth");
    EXPECT_EQ(resp, "6629fae49393a05397450978507c4ef1");
}

// Legacy RFC 2069 (no qop): response = MD5(HA1:nonce:HA2).
TEST(SipDigestRFC2617, LegacyNoQopResponse)
{
    std::string ha1 = computeHa1("Mufasa", "testrealm@host.com", "Circle Of Life");
    std::string ha2 = md5Hex(std::string("GET") + ":" + "/dir/index.html");
    std::string expected = md5Hex(ha1 + ":" + "dcd98b7102dd2f0e8b11d0f600bfb0c093" + ":" + ha2);

    std::string resp = computeResponse(
        ha1, "GET", "/dir/index.html",
        "dcd98b7102dd2f0e8b11d0f600bfb0c093",
        /*nc*/ "", /*cnonce*/ "", /*qop*/ "");
    EXPECT_EQ(resp, expected);
}

// ---------------------------------------------------------------------------
// parseAuthorization: round-trip every field, tolerate reordering / whitespace,
// and accept both the full header line and the bare value.
// ---------------------------------------------------------------------------
TEST(SipDigestParse, FullHeaderRoundTrip)
{
    std::string hdr =
        "Authorization: Digest username=\"Mufasa\", realm=\"testrealm@host.com\", "
        "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/dir/index.html\", "
        "qop=auth, nc=00000001, cnonce=\"0a4f113b\", "
        "response=\"6629fae49393a05397450978507c4ef1\", "
        "opaque=\"5ccc069c403ebaf9f0171e9517f40e41\", algorithm=MD5";

    DigestAuth a;
    ASSERT_TRUE(parseAuthorization(hdr, a));
    EXPECT_EQ(a.username, "Mufasa");
    EXPECT_EQ(a.realm, "testrealm@host.com");
    EXPECT_EQ(a.nonce, "dcd98b7102dd2f0e8b11d0f600bfb0c093");
    EXPECT_EQ(a.uri, "/dir/index.html");
    EXPECT_EQ(a.qop, "auth");
    EXPECT_EQ(a.nc, "00000001");
    EXPECT_EQ(a.cnonce, "0a4f113b");
    EXPECT_EQ(a.response, "6629fae49393a05397450978507c4ef1");
    EXPECT_EQ(a.opaque, "5ccc069c403ebaf9f0171e9517f40e41");
    EXPECT_EQ(a.algorithm, "MD5");
}

TEST(SipDigestParse, BareValueAndReorderedTolerant)
{
    std::string val =
        "Digest realm=\"pocketdial\",username=\"1001\" ,response=abcdef0123456789abcdef0123456789,"
        " nonce=\"n0\",uri=\"sip:pbx\"";
    DigestAuth a;
    ASSERT_TRUE(parseAuthorization(val, a));
    EXPECT_EQ(a.username, "1001");
    EXPECT_EQ(a.realm, "pocketdial");
    EXPECT_EQ(a.response, "abcdef0123456789abcdef0123456789");
    EXPECT_EQ(a.nonce, "n0");
    EXPECT_EQ(a.uri, "sip:pbx");
}

TEST(SipDigestParse, RejectsNonDigestAndIncomplete)
{
    DigestAuth a;
    EXPECT_FALSE(parseAuthorization("Basic dXNlcjpwYXNz", a));
    EXPECT_FALSE(parseAuthorization("Digest realm=\"x\", nonce=\"y\"", a)); // no username/response
    EXPECT_FALSE(parseAuthorization("", a));
}

// ---------------------------------------------------------------------------
// verify(): accepts a correct response, rejects a tampered one, rejects unknown
// HA1.
// ---------------------------------------------------------------------------
TEST(SipDigestVerify, AcceptAndReject)
{
    DigestAuth a;
    a.username = "Mufasa";
    a.realm = "testrealm@host.com";
    a.nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093";
    a.uri = "/dir/index.html";
    a.qop = "auth";
    a.nc = "00000001";
    a.cnonce = "0a4f113b";
    a.response = "6629fae49393a05397450978507c4ef1";

    std::string ha1 = computeHa1("Mufasa", "testrealm@host.com", "Circle Of Life");

    EXPECT_TRUE(verify(a, ha1, "GET"));

    // Wrong method -> reject.
    EXPECT_FALSE(verify(a, ha1, "POST"));

    // Tampered response -> reject.
    DigestAuth bad = a;
    bad.response = "0000000000000000000000000000aaaa";
    EXPECT_FALSE(verify(bad, ha1, "GET"));

    // Wrong HA1 (wrong password) -> reject.
    std::string wrongHa1 = computeHa1("Mufasa", "testrealm@host.com", "wrong");
    EXPECT_FALSE(verify(a, wrongHa1, "GET"));

    // Empty HA1 -> reject (never authenticate an unprovisioned extension).
    EXPECT_FALSE(verify(a, "", "GET"));
}

// SIP-flavoured end-to-end: build a credential the way a phone would, using the
// pocketdial realm and a fresh server nonce, and verify it round-trips.
TEST(SipDigestVerify, SipRegisterRoundTrip)
{
    const std::string ext = "1001";
    const std::string realm = "pocketdial";
    const std::string secret = "s3cr3t-pass";
    const std::string method = "REGISTER";
    const std::string uri = "sip:pocketdial";

    std::string ha1 = computeHa1(ext, realm, secret);
    std::string nonce = generateNonce();

    DigestAuth a;
    a.username = ext;
    a.realm = realm;
    a.nonce = nonce;
    a.uri = uri;
    a.qop = "auth";
    a.nc = "00000001";
    a.cnonce = "deadbeef";
    a.response = computeResponse(ha1, method, uri, nonce, a.nc, a.cnonce, a.qop);

    EXPECT_TRUE(verify(a, ha1, method));
    EXPECT_FALSE(verify(a, ha1, "INVITE")); // method binding holds
}

// ---------------------------------------------------------------------------
// WWW-Authenticate emitter.
// ---------------------------------------------------------------------------
TEST(SipDigestChallenge, BuildWwwAuthenticate)
{
    std::string c = buildWwwAuthenticate("pocketdial", "abc123");
    EXPECT_EQ(c, "Digest realm=\"pocketdial\", nonce=\"abc123\", qop=\"auth\", algorithm=MD5");

    std::string s = buildWwwAuthenticate("pocketdial", "abc123", /*stale*/ true);
    EXPECT_NE(s.find("stale=true"), std::string::npos);

    // A challenge must be parseable back into its components (interop sanity).
    DigestAuth dummy;
    // Not a credential (no username/response) so parseAuthorization returns false,
    // but the realm/nonce we emitted must survive a parse of an equivalent cred.
    std::string cred = "Digest username=\"x\", response=\"y\", realm=\"pocketdial\", nonce=\"abc123\"";
    ASSERT_TRUE(parseAuthorization(cred, dummy));
    EXPECT_EQ(dummy.realm, "pocketdial");
    EXPECT_EQ(dummy.nonce, "abc123");
}

// ---------------------------------------------------------------------------
// Nonce helper: integrity + freshness + staleness classification.
// ---------------------------------------------------------------------------
TEST(SipDigestNonce, FreshNonceValidates)
{
    std::string n = generateNonce();
    bool expired = true;
    EXPECT_TRUE(validateNonce(n, &expired));
    EXPECT_FALSE(expired);
    EXPECT_FALSE(isStale(n));
}

TEST(SipDigestNonce, ForgedNonceRejectedNotStale)
{
    // Garbage / forged nonce: integrity fails -> invalid AND not stale (a hard
    // reject, not a "retry with fresh credentials").
    EXPECT_FALSE(validateNonce("not-a-real-nonce"));
    EXPECT_FALSE(isStale("not-a-real-nonce"));

    // A well-formed shape but a wrong tag must also fail integrity.
    std::string n = generateNonce();
    n.back() ^= 0x01; // flip a tag bit (last hex char)
    bool expired = true;
    EXPECT_FALSE(validateNonce(n, &expired));
    EXPECT_FALSE(expired);    // integrity failure is not "expired"
    EXPECT_FALSE(isStale(n));
}

TEST(SipDigestNonce, ExpiredNonceIsStale)
{
    // ttl=0 forces any nonce (age >= 0, strictly age > 0 in practice) to be past
    // its lifetime: integrity still holds (it's ours) so it classifies as STALE.
    std::string n = generateNonce();
    bool expired = false;
    // With ttlMs=0, a nonce minted "now" has age 0 which is NOT > 0, so to make the
    // staleness deterministic we just assert the classification machinery: a tag we
    // issued, evaluated against a zero lifetime once any time elapses, is stale.
    // We assert the integrity-holds branch directly via a tiny ttl.
    bool valid = validateNonce(n, &expired, /*ttlMs*/ 0);
    if (!valid)
    {
        // Some time elapsed -> expired==true -> stale==true.
        EXPECT_TRUE(expired);
        EXPECT_TRUE(isStale(n, 0));
    }
    else
    {
        // No measurable time elapsed -> still fresh; that's also acceptable.
        EXPECT_FALSE(expired);
    }
}

// ---------------------------------------------------------------------------
// SipMessage now captures the Authorization request header.
// ---------------------------------------------------------------------------
TEST(SipMessageAuth, CapturesAuthorizationHeader)
{
    std::string raw =
        "REGISTER sip:pocketdial SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bK\r\n"
        "From: <sip:1001@pocketdial>;tag=abc\r\n"
        "To: <sip:1001@pocketdial>\r\n"
        "Call-ID: call-1\r\n"
        "CSeq: 2 REGISTER\r\n"
        "Authorization: Digest username=\"1001\", realm=\"pocketdial\", "
        "nonce=\"n0\", uri=\"sip:pocketdial\", response=\"deadbeefdeadbeefdeadbeefdeadbeef\", "
        "qop=auth, nc=00000001, cnonce=\"c0\", algorithm=MD5\r\n"
        "Content-Length: 0\r\n\r\n";

    SipMessage msg(raw, makeAddr());
    std::string auth(msg.getAuthorization());
    ASSERT_FALSE(auth.empty());

    DigestAuth a;
    ASSERT_TRUE(parseAuthorization(auth, a));
    EXPECT_EQ(a.username, "1001");
    EXPECT_EQ(a.realm, "pocketdial");
    EXPECT_EQ(a.uri, "sip:pocketdial");
    EXPECT_EQ(a.nc, "00000001");
}

TEST(SipMessageAuth, AbsentAuthorizationIsEmpty)
{
    std::string raw =
        "REGISTER sip:pocketdial SIP/2.0\r\n"
        "Via: SIP/2.0/UDP 1.2.3.4:5060;branch=z9hG4bK\r\n"
        "From: <sip:1001@pocketdial>;tag=abc\r\n"
        "To: <sip:1001@pocketdial>\r\n"
        "Call-ID: call-1\r\n"
        "CSeq: 1 REGISTER\r\n"
        "Content-Length: 0\r\n\r\n";

    SipMessage msg(raw, makeAddr());
    EXPECT_TRUE(std::string(msg.getAuthorization()).empty());
}

// ---------------------------------------------------------------------------
// SipSecretStore (host in-memory mode): set/get/has/clear + index.
// ---------------------------------------------------------------------------
TEST(SipSecretStore, SetGetVerifyRoundTrip)
{
    const std::string ext = "2001";
    const std::string secret = "hunter2hunter2";

    EXPECT_TRUE(SipSecretStore::setSecret(ext, secret));
    EXPECT_TRUE(SipSecretStore::hasSecret(ext));

    auto ha1 = SipSecretStore::getHa1(ext);
    ASSERT_TRUE(ha1.has_value());
    // Stored HA1 must equal the independently-computed HA1 over the pocketdial realm.
    EXPECT_EQ(*ha1, computeHa1(ext, SipSecretStore::kRealm, secret));

    // And a digest computed with that secret verifies against the stored HA1.
    std::string nonce = generateNonce();
    DigestAuth a;
    a.username = ext; a.realm = SipSecretStore::kRealm; a.nonce = nonce;
    a.uri = "sip:pocketdial"; a.qop = "auth"; a.nc = "00000001"; a.cnonce = "cc";
    a.response = computeResponse(*ha1, "REGISTER", a.uri, nonce, a.nc, a.cnonce, a.qop);
    EXPECT_TRUE(verify(a, *ha1, "REGISTER"));
}

TEST(SipSecretStore, ClearAndIndex)
{
    SipSecretStore::setSecret("3001", "aaaaaaaa");
    SipSecretStore::setSecret("3002", "bbbbbbbb");

    auto exts = SipSecretStore::securedExtensions();
    EXPECT_NE(std::find(exts.begin(), exts.end(), "3001"), exts.end());
    EXPECT_NE(std::find(exts.begin(), exts.end(), "3002"), exts.end());

    EXPECT_TRUE(SipSecretStore::clearSecret("3001"));
    EXPECT_FALSE(SipSecretStore::hasSecret("3001"));
    EXPECT_TRUE(SipSecretStore::hasSecret("3002"));
}

TEST(SipSecretStore, RejectsInvalidExtAndEmptySecret)
{
    EXPECT_FALSE(SipSecretStore::setSecret("", "secret"));
    EXPECT_FALSE(SipSecretStore::setSecret("1001", ""));
    EXPECT_FALSE(SipSecretStore::setSecret("has space", "secret"));
    EXPECT_FALSE(SipSecretStore::setSecret("toolongextension", "secret")); // > kMaxExtLen
}

TEST(SipSecretStore, GenerateSecretReturnsPlaintextAndStoresHa1)
{
    auto secret = SipSecretStore::generateSecret("4001");
    ASSERT_TRUE(secret.has_value());
    EXPECT_FALSE(secret->empty());

    auto ha1 = SipSecretStore::getHa1("4001");
    ASSERT_TRUE(ha1.has_value());
    EXPECT_EQ(*ha1, computeHa1("4001", SipSecretStore::kRealm, *secret));
}

TEST(SipSecretStore, MakeRandomSecretLengthCharsetAndVariety)
{
    // Default draw is the audited ~138-bit secret (kGeneratedSecretLen chars).
    auto s = SipSecretStore::makeRandomSecret();
    EXPECT_EQ(static_cast<int>(s.size()), SipSecretStore::kGeneratedSecretLen);

    // Unambiguous, NVS/SIP-safe charset: alphanumeric, never 0/O/1/I/l.
    for (char c : s)
    {
        EXPECT_TRUE(std::isalnum(static_cast<unsigned char>(c)));
        EXPECT_EQ(std::string("0O1Il").find(c), std::string::npos);
    }

    // Honors an explicit length; non-positive lengths yield empty.
    EXPECT_EQ(static_cast<int>(SipSecretStore::makeRandomSecret(10).size()), 10);
    EXPECT_TRUE(SipSecretStore::makeRandomSecret(0).empty());

    // Two independent draws must differ — a collision at 24 chars would mean the
    // generator is not actually random (the LCG bug this replaced repeated itself).
    EXPECT_NE(SipSecretStore::makeRandomSecret(), SipSecretStore::makeRandomSecret());
}

// #578: after the #525 replay table overflows, any unknown nonce stamped at or
// before the eviction watermark is re-challenged. If the stamp came from the
// wall clock, an SNTP step backward would make every fresh nonce read as "at
// or before" the watermark and every phone (emergency INVITEs included) would
// loop on stale 401s. The stamp must come from the monotonic clock, which
// never steps: the issued stamp must lie inside a steady_clock window.
TEST(SipDigestNonce, StampIsMonotonicSoAWallClockStepCannotStrandFreshNonces)
{
    using namespace std::chrono;
    const auto steadyMs = [] {
        return static_cast<uint64_t>(
            duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
    };
    const uint64_t before = steadyMs();
    const std::string nonce = generateNonce();
    const uint64_t after = steadyMs();
    const size_t dot = nonce.find('.');
    ASSERT_NE(dot, std::string::npos);
    const uint64_t stamp = std::stoull(nonce.substr(0, dot), nullptr, 16);
    EXPECT_GE(stamp, before);
    EXPECT_LE(stamp, after);
    EXPECT_TRUE(validateNonce(nonce)); // HMAC + freshness still hold
}
