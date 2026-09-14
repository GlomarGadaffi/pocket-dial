// SipRegistrationClient_test.cpp — the REGISTER user agent (RFC 3261 §10.2).
//
// The board has only ever been a registrar. This drives the opposite direction
// end to end against a scripted SBC: challenge, retry, refresh, 423, backoff.
//
// The clock is a plain uint64_t the test advances by hand. Nothing here sleeps,
// nothing here opens a socket, and the state machine allocates nothing — so
// every assertion is exact rather than "within a tolerance".

#include <gtest/gtest.h>
#include <string>
#include <string_view>

#include "SipDigest.hpp"
#include "SipRegistrationClient.hpp"

using State = SipRegistrationClient::State;

namespace {

SipRegistrationClient::Config makeConfig(uint32_t expires = 3600)
{
    SipRegistrationClient::Config c{};
    std::snprintf(c.registrarHost, sizeof(c.registrarHost), "%s", "sbc.carrier.example");
    c.registrarPort = 5060;
    std::snprintf(c.domain,   sizeof(c.domain),   "%s", "carrier.example");
    std::snprintf(c.aorUser,  sizeof(c.aorUser),  "%s", "15551234567");
    std::snprintf(c.authUser, sizeof(c.authUser), "%s", "trunkuser");
    std::snprintf(c.localIp,  sizeof(c.localIp),  "%s", "192.0.2.10");
    c.localPort = 5060;
    c.requestedExpiresSec = expires;
    return c;
}

std::string wire(const SipRegistrationClient::Request& r)
{
    return std::string(r.bytes, r.len);
}

// Pull a header value out of a composed request. Dumb on purpose: it must not
// share code with anything under test.
std::string headerOf(const std::string& msg, const std::string& name)
{
    const std::string needle = "\r\n" + name + ": ";
    size_t p = msg.find(needle);
    if (p == std::string::npos) return {};
    size_t v = p + needle.size();
    size_t e = msg.find("\r\n", v);
    return msg.substr(v, e - v);
}

std::string digestParam(const std::string& header, const std::string& key)
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

constexpr const char* kChallenge =
    "Digest realm=\"carrier.example\", nonce=\"NONCE-AAA\", qop=\"auth\", algorithm=MD5";

SipRegistrationClient::ResponseView challenge401(std::string_view hdr = kChallenge)
{
    SipRegistrationClient::ResponseView r;
    r.code = 401;
    r.wwwAuthenticate = hdr;
    return r;
}

SipRegistrationClient::ResponseView ok200(std::string_view expires,
                                          std::string_view contact = {})
{
    SipRegistrationClient::ResponseView r;
    r.code = 200;
    r.expires = expires;
    r.contact = contact;
    return r;
}

// Drive the client from Idle to Registered against a challenging SBC, returning
// the authenticated REGISTER that was accepted.
std::string registerSuccessfully(SipRegistrationClient& c, uint64_t& now,
                                 uint32_t grantedSec = 3600)
{
    SipRegistrationClient::Request req;
    c.start(now);
    EXPECT_TRUE(c.tick(now, req));                 // unauthenticated REGISTER
    c.onResponse(now, challenge401());
    EXPECT_TRUE(c.tick(now, req));                 // authenticated REGISTER
    const std::string authed = wire(req);
    c.onResponse(now, ok200(std::to_string(grantedSec)));
    EXPECT_EQ(c.state(), State::Registered);
    return authed;
}

} // namespace

// ---------------------------------------------------------------------------
// The happy path, and the shape of what actually goes on the wire.
// ---------------------------------------------------------------------------

TEST(SipRegistrationClient, FirstRegisterIsUnauthenticatedAndWellFormed)
{
    SipRegistrationClient c;
    ASSERT_TRUE(c.configure(makeConfig(), "hunter2"));

    uint64_t now = 1000;
    SipRegistrationClient::Request req;
    EXPECT_FALSE(c.tick(now, req)) << "an un-started client must emit nothing";

    c.start(now);
    ASSERT_TRUE(c.tick(now, req));
    const std::string msg = wire(req);

    // RFC 3261 §10.2: the Request-URI names the REGISTRAR's domain, not a user.
    EXPECT_EQ(msg.rfind("REGISTER sip:sbc.carrier.example SIP/2.0\r\n", 0), 0u);
    EXPECT_EQ(headerOf(msg, "To"),      "<sip:15551234567@carrier.example>");
    EXPECT_EQ(headerOf(msg, "Contact"), "<sip:15551234567@192.0.2.10:5060>");
    EXPECT_EQ(headerOf(msg, "Expires"), "3600");
    EXPECT_EQ(headerOf(msg, "CSeq"),    "1 REGISTER");
    EXPECT_NE(msg.find(";branch=z9hG4bK"), std::string::npos);
    EXPECT_NE(msg.find(";rport"), std::string::npos);
    EXPECT_TRUE(headerOf(msg, "Authorization").empty())
        << "the first REGISTER has no credential to send";
    EXPECT_EQ(msg.substr(msg.size() - 4), "\r\n\r\n");

    EXPECT_EQ(c.state(), State::Registering);
    EXPECT_FALSE(c.tick(now, req)) << "tick is edge-driven: one REGISTER per decision";
}

TEST(SipRegistrationClient, ChallengeIsAnsweredWithAValidCredentialTheRegistrarAccepts)
{
    SipRegistrationClient c;
    ASSERT_TRUE(c.configure(makeConfig(), "hunter2"));

    uint64_t now = 1000;
    SipRegistrationClient::Request req;
    c.start(now);
    ASSERT_TRUE(c.tick(now, req));
    c.onResponse(now, challenge401());

    // A challenge is a normal part of the exchange, so the retry is IMMEDIATE —
    // it must not consume the failure backoff.
    EXPECT_EQ(c.status().consecutiveFailures, 0u);
    ASSERT_TRUE(c.tick(now, req)) << "the authenticated retry must go out at once";

    const std::string msg  = wire(req);
    const std::string auth = headerOf(msg, "Authorization");
    ASSERT_FALSE(auth.empty());

    EXPECT_EQ(digestParam(auth, "username"), "trunkuser");
    EXPECT_EQ(digestParam(auth, "realm"),    "carrier.example");
    EXPECT_EQ(digestParam(auth, "nonce"),    "NONCE-AAA");
    EXPECT_EQ(digestParam(auth, "nc"),       "00000001");
    EXPECT_EQ(digestParam(auth, "qop"),      "auth");
    // The digest uri MUST be byte-identical to the Request-URI: HA2 is
    // MD5(method:uri) and an SBC that sees them differ rejects the credential.
    EXPECT_EQ(digestParam(auth, "uri"), "sip:sbc.carrier.example");
    EXPECT_EQ(headerOf(msg, "CSeq"), "2 REGISTER") << "CSeq increments per REGISTER";

    // The real check: recompute the response the way a registrar would.
    SipDigest::DigestAuth parsed;
    ASSERT_TRUE(SipDigest::parseAuthorization(auth, parsed));
    EXPECT_TRUE(SipDigest::verify(
        parsed, SipDigest::computeHa1("trunkuser", "carrier.example", "hunter2"),
        "REGISTER"));
    EXPECT_FALSE(SipDigest::verify(
        parsed, SipDigest::computeHa1("trunkuser", "carrier.example", "wrong"),
        "REGISTER"));

    // The password is nowhere on the wire and nowhere in the dashboard view.
    EXPECT_EQ(msg.find("hunter2"), std::string::npos);
    const auto st = c.status();
    EXPECT_EQ(std::string(st.lastError).find("hunter2"), std::string::npos);
}

// ---------------------------------------------------------------------------
// nc MUST increment across requests sent against the same nonce.
// ---------------------------------------------------------------------------

TEST(SipRegistrationClient, NcIncrementsAcrossRetriesAgainstTheSameNonce)
{
    SipRegistrationClient c;
    ASSERT_TRUE(c.configure(makeConfig(60), "hunter2"));

    uint64_t now = 1000;
    SipRegistrationClient::Request req;
    c.start(now);
    ASSERT_TRUE(c.tick(now, req));
    c.onResponse(now, challenge401());
    ASSERT_TRUE(c.tick(now, req));
    EXPECT_EQ(digestParam(headerOf(wire(req), "Authorization"), "nc"), "00000001");

    // 200 OK with a 60 s lease. The challenge is CACHED, so the refresh
    // authenticates pre-emptively — against the same nonce, with nc+1.
    c.onResponse(now, ok200("60"));
    ASSERT_EQ(c.state(), State::Registered);
    EXPECT_TRUE(c.hasCachedChallenge());

    now += 54 * 1000;            // 90% of 60 s
    ASSERT_TRUE(c.tick(now, req));
    const std::string auth2 = headerOf(wire(req), "Authorization");
    EXPECT_EQ(digestParam(auth2, "nonce"), "NONCE-AAA");
    EXPECT_EQ(digestParam(auth2, "nc"), "00000002")
        << "nc counts requests sent with THIS nonce; a repeated 00000001 is a "
           "replay to a strict SBC";

    c.onResponse(now, ok200("60"));
    now += 54 * 1000;
    ASSERT_TRUE(c.tick(now, req));
    EXPECT_EQ(digestParam(headerOf(wire(req), "Authorization"), "nc"), "00000003");

    // Each of those carried a FRESH cnonce even though the nonce is unchanged.
    EXPECT_NE(digestParam(auth2, "cnonce"),
              digestParam(headerOf(wire(req), "Authorization"), "cnonce"));
}

TEST(SipRegistrationClient, AStaleNonceReChallengeRestartsTheCountAtOne)
{
    SipRegistrationClient c;
    ASSERT_TRUE(c.configure(makeConfig(), "hunter2"));

    uint64_t now = 1000;
    registerSuccessfully(c, now);
    EXPECT_EQ(c.ncValue(), 1u);

    // The refresh goes out pre-emptively with nc=2 against the cached nonce...
    now += 3240 * 1000;
    SipRegistrationClient::Request req;
    ASSERT_TRUE(c.tick(now, req));
    EXPECT_EQ(digestParam(headerOf(wire(req), "Authorization"), "nc"), "00000002");

    // ...and the SBC has rotated its nonce, so it answers stale=true. That is NOT
    // a credential failure: retry at once, with the NEW nonce and nc back to 1.
    c.onResponse(now, challenge401(
        "Digest realm=\"carrier.example\", nonce=\"NONCE-BBB\", qop=\"auth\", "
        "algorithm=MD5, stale=true"));
    EXPECT_EQ(c.status().consecutiveFailures, 0u)
        << "a stale-nonce re-challenge must not count as a failure";

    ASSERT_TRUE(c.tick(now, req));
    const std::string auth = headerOf(wire(req), "Authorization");
    EXPECT_EQ(digestParam(auth, "nonce"), "NONCE-BBB");
    EXPECT_EQ(digestParam(auth, "nc"), "00000001")
        << "a NEW nonce restarts the count; carrying 00000003 over trips a "
           "strict SBC's replay detector";
}

TEST(SipRegistrationClient, AReChallengeOnTheSameNonceWithoutStaleIsTreatedAsBadCredentials)
{
    // The distinction that keeps a wrong password from becoming a retry storm:
    // same nonce + stale absent == the server rejected the CREDENTIAL, and no
    // amount of retrying fixes that. Several ITSPs auto-blacklist a source that
    // hammers after a rejection.
    SipRegistrationClient c;
    ASSERT_TRUE(c.configure(makeConfig(), "wrong-password"));

    uint64_t now = 1000;
    SipRegistrationClient::Request req;
    c.start(now);
    ASSERT_TRUE(c.tick(now, req));
    c.onResponse(now, challenge401());
    ASSERT_TRUE(c.tick(now, req));
    c.onResponse(now, challenge401());      // same nonce, no stale

    EXPECT_EQ(c.state(), State::Failed);
    EXPECT_EQ(c.status().consecutiveFailures, 1u);
    EXPECT_NE(std::string(c.status().lastError).find("credentials rejected"),
              std::string::npos);
    EXPECT_FALSE(c.tick(now, req)) << "a rejected credential must not retry instantly";
    EXPECT_GE(c.status().nextActionMs, now + 2000);
}

// ---------------------------------------------------------------------------
// Expires: the SERVER's number wins.
// ---------------------------------------------------------------------------

TEST(SipRegistrationClient, RefreshFollowsTheServerShortenedExpiresNotTheRequestedOne)
{
    SipRegistrationClient c;
    ASSERT_TRUE(c.configure(makeConfig(/*expires=*/3600), "hunter2"));

    uint64_t now = 1000;
    SipRegistrationClient::Request req;
    c.start(now);
    ASSERT_TRUE(c.tick(now, req));
    EXPECT_EQ(headerOf(wire(req), "Expires"), "3600") << "we ASK for an hour";

    // The carrier grants 120 s. Refreshing on 3600 would let the binding lapse
    // at t+120 and inbound calls would simply stop, with the client still
    // showing "Registered".
    c.onResponse(now, ok200("120"));
    ASSERT_EQ(c.state(), State::Registered);

    const auto st = c.status();
    EXPECT_EQ(st.grantedExpiresSec, 120u);
    EXPECT_EQ(st.bindingExpiresAtMs, now + 120u * 1000u);
    EXPECT_EQ(st.nextActionMs, now + 108u * 1000u) << "90% of the GRANTED lease";

    EXPECT_FALSE(c.tick(now + 107 * 1000, req)) << "not yet";
    ASSERT_TRUE(c.tick(now + 108 * 1000, req)) << "refresh at 90% of 120 s";
    EXPECT_LT(now + 108 * 1000, st.bindingExpiresAtMs)
        << "the refresh must precede the lapse, with headroom to retry";
}

TEST(SipRegistrationClient, TheContactExpiresParamBeatsTheExpiresHeaderAndOurBindingWins)
{
    SipRegistrationClient c;
    ASSERT_TRUE(c.configure(makeConfig(3600), "hunter2"));

    uint64_t now = 1000;
    SipRegistrationClient::Request req;
    c.start(now);
    ASSERT_TRUE(c.tick(now, req));

    // RFC 3261 §10.2.4: the lease rides on OUR binding's ;expires parameter. The
    // SBC is also holding somebody else's binding for the same AOR with a much
    // shorter lease — arming our refresh off that one would re-register every
    // 27 s forever.
    c.onResponse(now, ok200(
        /*Expires header*/ "3600",
        /*Contact*/ "<sip:15551234567@198.51.100.9:5060>;expires=30, "
                    "<sip:15551234567@192.0.2.10:5060>;expires=240"));

    const auto st = c.status();
    EXPECT_EQ(st.grantedExpiresSec, 240u) << "our own binding's lease, not the "
                                             "first one listed and not the header";
    EXPECT_EQ(st.nextActionMs, now + 216u * 1000u);
}

TEST(SipRegistrationClient, AZeroSecondGrantIsAFailureNotASuccess)
{
    // "Expires: 0" is the registrar saying "you are not registered". Parking in
    // Registered on it means a dashboard that says green over a dead trunk.
    SipRegistrationClient c;
    ASSERT_TRUE(c.configure(makeConfig(), "hunter2"));

    uint64_t now = 1000;
    SipRegistrationClient::Request req;
    c.start(now);
    ASSERT_TRUE(c.tick(now, req));
    c.onResponse(now, ok200("0"));

    EXPECT_EQ(c.state(), State::Failed);
    EXPECT_NE(std::string(c.status().lastError).find("0 second"), std::string::npos);
}

// ---------------------------------------------------------------------------
// 423 Interval Too Brief
// ---------------------------------------------------------------------------

TEST(SipRegistrationClient, Adopts423MinExpiresAndRetriesImmediately)
{
    SipRegistrationClient c;
    ASSERT_TRUE(c.configure(makeConfig(/*expires=*/60), "hunter2"));

    uint64_t now = 1000;
    SipRegistrationClient::Request req;
    c.start(now);
    ASSERT_TRUE(c.tick(now, req));
    EXPECT_EQ(headerOf(wire(req), "Expires"), "60");

    SipRegistrationClient::ResponseView r;
    r.code = 423;
    r.minExpires = "3600";
    c.onResponse(now, r);

    // A 423 is a NEGOTIATION, not a failure: no backoff is consumed, and the
    // retry is immediate.
    EXPECT_EQ(c.status().consecutiveFailures, 0u);
    EXPECT_EQ(c.status().requestedExpiresSec, 3600u);
    ASSERT_TRUE(c.tick(now, req)) << "the 423 retry must go out at once";
    EXPECT_EQ(headerOf(wire(req), "Expires"), "3600")
        << "the retry must carry the server's Min-Expires, or it gets 423 again";

    c.onResponse(now, ok200("3600"));
    EXPECT_EQ(c.state(), State::Registered);
    EXPECT_EQ(c.status().grantedExpiresSec, 3600u);
}

TEST(SipRegistrationClient, A423WithoutAUsableMinExpiresFailsInsteadOfLooping)
{
    SipRegistrationClient c;
    ASSERT_TRUE(c.configure(makeConfig(60), "hunter2"));

    uint64_t now = 1000;
    SipRegistrationClient::Request req;
    c.start(now);
    ASSERT_TRUE(c.tick(now, req));

    SipRegistrationClient::ResponseView r;
    r.code = 423;                      // RFC 3261 §10.3 step 7 makes it mandatory
    c.onResponse(now, r);              // ...and this SBC omitted it anyway
    EXPECT_EQ(c.state(), State::Failed);
    EXPECT_NE(std::string(c.status().lastError).find("Min-Expires"), std::string::npos);

    // And a SECOND 423 after we already adopted one is a moving floor, not a
    // negotiation — it must not loop.
    SipRegistrationClient c2;
    ASSERT_TRUE(c2.configure(makeConfig(60), "hunter2"));
    uint64_t t = 1000;
    c2.start(t);
    ASSERT_TRUE(c2.tick(t, req));
    SipRegistrationClient::ResponseView r1;
    r1.code = 423; r1.minExpires = "120";
    c2.onResponse(t, r1);
    ASSERT_TRUE(c2.tick(t, req));
    SipRegistrationClient::ResponseView r2;
    r2.code = 423; r2.minExpires = "240";
    c2.onResponse(t, r2);
    EXPECT_EQ(c2.state(), State::Failed);
    EXPECT_FALSE(c2.tick(t, req));
}

// ---------------------------------------------------------------------------
// Backoff. The single most important non-RFC property here: never a tight loop.
// ---------------------------------------------------------------------------

TEST(SipRegistrationClient, RepeatedFailuresBackOffExponentiallyAndCapOut)
{
    SipRegistrationClient c;
    ASSERT_TRUE(c.configure(makeConfig(), "hunter2"));

    uint64_t now = 1000;
    SipRegistrationClient::Request req;
    c.start(now);

    SipRegistrationClient::ResponseView forbidden;
    forbidden.code = 403;

    const uint64_t expected[] = {2000, 4000, 8000, 16000, 32000, 64000,
                                 128000, 256000, 300000, 300000, 300000};
    for (size_t i = 0; i < sizeof(expected) / sizeof(expected[0]); ++i)
    {
        ASSERT_TRUE(c.tick(now, req)) << "attempt " << i;
        c.onResponse(now, forbidden);
        ASSERT_EQ(c.state(), State::Failed);
        EXPECT_EQ(c.status().nextActionMs, now + expected[i]) << "attempt " << i;

        // The load-bearing assertion: nothing goes out one millisecond early.
        EXPECT_FALSE(c.tick(now + expected[i] - 1, req))
            << "attempt " << i << " retried before its backoff elapsed";
        now += expected[i];
    }
    EXPECT_EQ(c.status().consecutiveFailures, 11u);
    EXPECT_EQ(c.status().lastStatusCode, 403u);
}

TEST(SipRegistrationClient, RetryAfterCanOnlyLengthenTheBackoffNeverShortenIt)
{
    SipRegistrationClient c;
    ASSERT_TRUE(c.configure(makeConfig(), "hunter2"));

    uint64_t now = 1000;
    SipRegistrationClient::Request req;
    c.start(now);
    ASSERT_TRUE(c.tick(now, req));

    SipRegistrationClient::ResponseView busy;
    busy.code = 503;
    busy.retryAfter = "60 (maintenance window)";   // parameters/comments tolerated
    c.onResponse(now, busy);
    EXPECT_EQ(c.status().nextActionMs, now + 60000u) << "honour a longer Retry-After";

    // A server must not be able to talk us into retrying sooner than our own
    // backoff — that is a self-inflicted hammer with extra steps.
    now += 60000;
    ASSERT_TRUE(c.tick(now, req));
    SipRegistrationClient::ResponseView impatient;
    impatient.code = 503;
    impatient.retryAfter = "0";
    c.onResponse(now, impatient);
    EXPECT_EQ(c.status().nextActionMs, now + 4000u) << "our 2nd-failure backoff wins";
}

TEST(SipRegistrationClient, ASilentRegistrarTimesOutAtTimerFRatherThanHangingForever)
{
    SipRegistrationClient c;
    ASSERT_TRUE(c.configure(makeConfig(), "hunter2"));

    uint64_t now = 1000;
    SipRegistrationClient::Request req;
    c.start(now);
    ASSERT_TRUE(c.tick(now, req));
    EXPECT_EQ(c.state(), State::Registering);

    EXPECT_FALSE(c.tick(now + 31999, req));
    EXPECT_EQ(c.state(), State::Registering) << "still inside Timer F";

    EXPECT_FALSE(c.tick(now + 32000, req));
    EXPECT_EQ(c.state(), State::Failed) << "64*T1 elapsed with no final response";
    EXPECT_NE(std::string(c.status().lastError).find("timer F"), std::string::npos);
}

TEST(SipRegistrationClient, TooManyChallengesInOneCycleGivesUpInsteadOfLooping)
{
    SipRegistrationClient c;
    ASSERT_TRUE(c.configure(makeConfig(), "hunter2"));

    uint64_t now = 1000;
    SipRegistrationClient::Request req;
    c.start(now);

    // A broken SBC that rotates its nonce on every answer. Each one is
    // individually legitimate ("stale"), so only the per-cycle cap stops it.
    for (int i = 0; i < 3; ++i)
    {
        ASSERT_TRUE(c.tick(now, req)) << "challenge round " << i;
        c.onResponse(now, challenge401(
            "Digest realm=\"carrier.example\", nonce=\"N" + std::to_string(i) +
            "\", qop=\"auth\", stale=true"));
    }
    ASSERT_TRUE(c.tick(now, req));
    c.onResponse(now, challenge401(
        "Digest realm=\"carrier.example\", nonce=\"N9\", qop=\"auth\", stale=true"));

    EXPECT_EQ(c.state(), State::Failed);
    EXPECT_NE(std::string(c.status().lastError).find("too many challenges"),
              std::string::npos);
    EXPECT_FALSE(c.tick(now, req));
}

// ---------------------------------------------------------------------------
// Refusals that must not become a silent wrong answer.
// ---------------------------------------------------------------------------

TEST(SipRegistrationClient, ASha256ChallengeFailsTheCycleRatherThanAnsweringWithMd5)
{
    SipRegistrationClient c;
    ASSERT_TRUE(c.configure(makeConfig(), "hunter2"));

    uint64_t now = 1000;
    SipRegistrationClient::Request req;
    c.start(now);
    ASSERT_TRUE(c.tick(now, req));
    c.onResponse(now, challenge401(
        "Digest realm=\"carrier.example\", nonce=\"N\", qop=\"auth\", algorithm=SHA-256"));

    // The challenge caches fine; the REFUSAL happens when the answer is composed,
    // and it must be a backed-off failure with a readable reason — not a REGISTER
    // carrying an MD5 response the SBC will 401 forever.
    EXPECT_FALSE(c.tick(now, req));
    EXPECT_EQ(c.state(), State::Failed);
    EXPECT_NE(std::string(c.status().lastError).find("algorithm"), std::string::npos);
}

TEST(SipRegistrationClient, AnOversizedChallengeFieldIsRefusedNotTruncated)
{
    SipRegistrationClient c;
    ASSERT_TRUE(c.configure(makeConfig(), "hunter2"));

    uint64_t now = 1000;
    SipRegistrationClient::Request req;
    c.start(now);
    ASSERT_TRUE(c.tick(now, req));

    const std::string huge(SipRegistrationClient::kMaxNonce + 10, 'x');
    c.onResponse(now, challenge401(
        "Digest realm=\"carrier.example\", nonce=\"" + huge + "\", qop=\"auth\""));

    // A truncated nonce hashes to a digest the server can never reproduce, and
    // nothing on the wire says why.
    EXPECT_EQ(c.state(), State::Failed);
    EXPECT_FALSE(c.hasCachedChallenge());
    EXPECT_NE(std::string(c.status().lastError).find("fixed buffer"), std::string::npos);
}

TEST(SipRegistrationClient, ConfigureRefusesRatherThanTruncatingACredential)
{
    SipRegistrationClient c;
    const std::string tooLong(SipRegistrationClient::kMaxSecret, 'p');
    EXPECT_FALSE(c.configure(makeConfig(), tooLong));
    EXPECT_FALSE(c.configure(makeConfig(), ""));

    SipRegistrationClient::Config noHost = makeConfig();
    noHost.registrarHost[0] = '\0';
    EXPECT_FALSE(c.configure(noHost, "hunter2"));

    // ...and none of those left the object half-configured.
    uint64_t now = 1000;
    SipRegistrationClient::Request req;
    c.start(now);
    EXPECT_FALSE(c.tick(now, req));
    EXPECT_EQ(c.state(), State::Idle);
}

// ---------------------------------------------------------------------------
// Housekeeping the trunk wiring will depend on.
// ---------------------------------------------------------------------------

TEST(SipRegistrationClient, CallIdIsStableAcrossEveryRegisterOfOneRegistration)
{
    // RFC 3261 §10.2: all REGISTERs for one AOR from one UA share a Call-ID with
    // a monotonically increasing CSeq. A fresh Call-ID per refresh makes a
    // registrar treat each one as a new, competing registration.
    SipRegistrationClient c;
    ASSERT_TRUE(c.configure(makeConfig(60), "hunter2"));

    uint64_t now = 1000;
    const std::string first = registerSuccessfully(c, now, 60);
    const std::string cid = headerOf(first, "Call-ID");
    EXPECT_FALSE(cid.empty());
    EXPECT_STREQ(c.callId(), cid.c_str());

    SipRegistrationClient::Request req;
    for (int i = 0; i < 3; ++i)
    {
        now += 54 * 1000;
        ASSERT_TRUE(c.tick(now, req));
        EXPECT_EQ(headerOf(wire(req), "Call-ID"), cid);
        c.onResponse(now, ok200("60"));
    }
    EXPECT_EQ(headerOf(wire(req), "CSeq"), "5 REGISTER");
}

TEST(SipRegistrationClient, StatusCarriesNoCredentialMaterial)
{
    // The property TelephonyApiConfig_test pins for view(): a dashboard-facing
    // snapshot never exposes the secret. Here it also must not expose the nonce
    // or a composed Authorization header.
    SipRegistrationClient c;
    ASSERT_TRUE(c.configure(makeConfig(), "hunter2"));
    uint64_t now = 1000;
    registerSuccessfully(c, now);

    const auto st = c.status();
    const std::string err(st.lastError);
    EXPECT_EQ(err.find("hunter2"),   std::string::npos);
    EXPECT_EQ(err.find("NONCE-AAA"), std::string::npos);
    EXPECT_EQ(err.find("Digest"),    std::string::npos);
    EXPECT_EQ(st.state, State::Registered);
    EXPECT_TRUE(st.authenticated);

    // clearCredentials() disarms the client entirely.
    c.clearCredentials();
    SipRegistrationClient::Request req;
    c.start(now);
    EXPECT_FALSE(c.tick(now, req));
    EXPECT_EQ(c.state(), State::Idle);
}

TEST(SipRegistrationClient, StartIsIdempotentAndStopDisarms)
{
    SipRegistrationClient c;
    ASSERT_TRUE(c.configure(makeConfig(), "hunter2"));

    uint64_t now = 1000;
    SipRegistrationClient::Request req;
    c.start(now);
    c.start(now + 5);
    c.start(now + 10);
    ASSERT_TRUE(c.tick(now + 20, req));
    EXPECT_EQ(headerOf(wire(req), "CSeq"), "1 REGISTER")
        << "three starts must not produce three REGISTERs";
    EXPECT_FALSE(c.tick(now + 20, req));

    c.onResponse(now + 20, ok200("3600"));
    c.start(now + 21);                 // stray start on a live registration
    EXPECT_FALSE(c.tick(now + 21, req)) << "start() must not force an early refresh";

    c.stop();
    EXPECT_EQ(c.state(), State::Idle);
    EXPECT_FALSE(c.tick(now + 100000000, req));
}

TEST(SipRegistrationClient, StrayResponsesAreIgnored)
{
    SipRegistrationClient c;
    ASSERT_TRUE(c.configure(makeConfig(), "hunter2"));

    uint64_t now = 1000;
    registerSuccessfully(c, now);
    const auto before = c.status();

    // A retransmitted 200, or a response to a transaction we already gave up on.
    // Acting on either would resurrect a dead cycle or re-arm the refresh timer
    // off the wrong clock.
    c.onResponse(now + 50, ok200("30"));
    SipRegistrationClient::ResponseView late;
    late.code = 403;
    c.onResponse(now + 60, late);

    const auto after = c.status();
    EXPECT_EQ(after.state, State::Registered);
    EXPECT_EQ(after.grantedExpiresSec, before.grantedExpiresSec);
    EXPECT_EQ(after.nextActionMs, before.nextActionMs);
    EXPECT_EQ(after.consecutiveFailures, 0u);
}

TEST(SipRegistrationClient, ProvisionalResponsesDoNotEndTheTransaction)
{
    SipRegistrationClient c;
    ASSERT_TRUE(c.configure(makeConfig(), "hunter2"));

    uint64_t now = 1000;
    SipRegistrationClient::Request req;
    c.start(now);
    ASSERT_TRUE(c.tick(now, req));

    SipRegistrationClient::ResponseView trying;
    trying.code = 100;
    c.onResponse(now, trying);
    EXPECT_EQ(c.state(), State::Registering) << "a 1xx ends nothing (RFC 3261 §17.1.2)";

    c.onResponse(now, ok200("3600"));
    EXPECT_EQ(c.state(), State::Registered);
}

TEST(SipRegistrationClient, A407IsAnsweredInProxyAuthorization)
{
    SipRegistrationClient c;
    ASSERT_TRUE(c.configure(makeConfig(), "hunter2"));

    uint64_t now = 1000;
    SipRegistrationClient::Request req;
    c.start(now);
    ASSERT_TRUE(c.tick(now, req));

    SipRegistrationClient::ResponseView r;
    r.code = 407;
    r.proxyAuthenticate =
        "Digest realm=\"sbc.carrier.example\", nonce=\"P1\", qop=\"auth\"";
    c.onResponse(now, r);

    ASSERT_TRUE(c.tick(now, req));
    const std::string msg = wire(req);
    // Putting it in Authorization instead is a silent auth loop: the proxy never
    // sees its credential and just re-challenges.
    EXPECT_TRUE(headerOf(msg, "Authorization").empty());
    const std::string pa = headerOf(msg, "Proxy-Authorization");
    ASSERT_FALSE(pa.empty());
    EXPECT_EQ(digestParam(pa, "nonce"), "P1");
    EXPECT_EQ(digestParam(pa, "realm"), "sbc.carrier.example");
}
