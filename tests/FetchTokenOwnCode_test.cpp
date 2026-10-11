// FetchTokenOwnCode_test.cpp -- the allocations fetchToken() made itself, and the checks that keep a
// token it cannot hold whole out of the cache (#951, slice 1).
//
// fetchToken() (TelephonyAnchorClient, ESP arm) cannot be host compiled. Everything it does with
// its own buffers is done by host-compiled pieces, and these tests run those pieces in fetchToken's
// order with the lane's real arena, under the binary-wide counting operator new:
//   telephony::buildTokenRequest (URL + form body, built in the arena), BodyArena::collect (the
//   response), jsonStringField, checkToken, readTokenLifetime (scratch = the arena's unused tail),
//   TokenInstallGate, BearerHeader (a string reserved once, as init() does) and
//   wsAuthHeaderInPlace (the WebSocket header, rebuilt in the arena).
// What the ESP arm itself may contain (no std::string, no vector, _mutex held for the copy and the
// install and never across the socket, the too-big check before the gate) is pinned by
// tests/tools/test_anchor_fetch_token_wiring.py. This file does not reach the lock.
//
// What stays allocating, and is not measured here: esp_http_client_init and TLS (ESP-IDF's).

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include "AllocCounter.hpp"
#include "TelephonyAnchorLogic.hpp"
#include "UrlEncode.hpp"
#include "Witness.hpp"

namespace
{
	using Arena = telephony::BodyArena<telephony::kTokenBodyBytes>;
	using telephony::BodyStatus;
	using telephony::TokenLane;

	constexpr std::int64_t kT0 = 5000000;
	// Sizes a board sees, past the 15 bytes a std::string keeps inline: a std::string anywhere in the
	// path would show up as a count.
	const char* const kBase   = "https://pbx-7f3a9c.carrier-example.net:5001";
	const char* const kId     = "pocketdial-anchor-0042";
	const char* const kSecret = "q7Zk+/Rm2xT9vB0c=Lw3Yp8HdN5sUe1AaGfJ4iOo";

	struct Config
	{
		std::string baseUrl = kBase, id = kId, secret = kSecret;
	};

	// What _baseUrl/_clientId/_clientSecret hold, built the way fetchToken() built the request before #951.
	std::string oldBody(const Config& c)
	{
		return "grant_type=client_credentials&client_id=" + urlEncode(c.id) + "&client_secret=" + urlEncode(c.secret);
	}

	std::string b64url(const std::string& in)
	{
		static const char* alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
		std::string out;
		std::uint32_t buf = 0;
		int bits = 0;
		for (unsigned char c : in)
		{
			buf = (buf << 8) | c;
			bits += 8;
			while (bits >= 6) { bits -= 6; out.push_back(alpha[(buf >> bits) & 0x3F]); }
		}
		if (bits > 0) out.push_back(alpha[(buf << (6 - bits)) & 0x3F]);
		return out;
	}

	// A JWT-shaped token: header, a payload with `padBytes` of extra claim text, an RS256-sized signature.
	std::string makeToken(std::size_t padBytes, long expSec = 1700003600, long iatSec = 1700000000)
	{
		std::string payload = "{\"iss\":\"https://pbx-7f3a9c.carrier-example.net\",\"aud\":[\"call_control\"],"
		                      "\"nbf\":" + std::to_string(iatSec) + ",\"exp\":" + std::to_string(expSec) +
		                      ",\"iat\":" + std::to_string(iatSec) + ",\"client_id\":\"900\",\"pad\":\"" +
		                      std::string(padBytes, 'p') + "\"}";
		return b64url("{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"k1\"}") + "." + b64url(payload) + "." +
		       std::string(342, 'S');
	}

	// Just the member: the response of a token near the limit still fits the 4096 byte arena.
	std::string bareResponse(const std::string& token)
	{
		return "{\"access_token\":\"" + token + "\"}";
	}

	// A token whose payload is padBytes bigger than the arena's unused tail can hold. padFirst: the pad is
	// before exp and iat, so the start of the payload that does fit the scratch has neither of them.
	std::string makeBigToken(std::size_t padBytes, bool padFirst)
	{
		const std::string claims = "\"iat\":1700000000,\"exp\":1700003600";
		const std::string pad = "\"pad\":\"" + std::string(padBytes, 'p') + "\"";
		const std::string payload = padFirst ? "{" + pad + "," + claims + "}" : "{" + claims + "," + pad + "}";
		return b64url("{\"alg\":\"RS256\",\"typ\":\"JWT\",\"kid\":\"k1\"}") + "." + b64url(payload) + "." +
		       std::string(342, 'S');
	}

	// expiresInMember: "" or "\"expires_in\":600,"
	std::string responseWith(const std::string& token, const char* expiresInMember)
	{
		return std::string("{\"token_type\":\"Bearer\",") + expiresInMember + "\"access_token\":\"" + token + "\"}";
	}

	std::string tokenResponse(const std::string& token)
	{
		return "{\"token_type\":\"Bearer\",\"expires_in\":60,\"access_token\":\"" + token + "\",\"scope\":\"call_control\"}";
	}

	// What TelephonyAnchorClient keeps for the cached token.
	struct Cache
	{
		telephony::TokenInstallGate gate;
		telephony::BearerHeader     bearer;   // _bearerHeader
		std::int64_t                obtainedUs = 0, lifetimeUs = 0;
		Cache() { bearer.reserve(); }   // init() does this once
	};

	// A scripted socket: the response, optionally cut short (the connection closed early).
	struct Feed
	{
		const std::string& body;
		std::size_t        cutAt;
		std::size_t        pos = 0;
		bool               complete() const { return pos == body.size(); }
		int read(char* dst, std::size_t room)
		{
			if (pos >= cutAt) return 0;
			std::size_t n = cutAt - pos;
			if (n > room) n = room;
			std::memcpy(dst, body.data() + pos, n);
			pos += n;
			return static_cast<int>(n);
		}
	};

	void copyz(char* dst, std::size_t cap, const char* src)
	{
		const std::size_t n = std::strlen(src) < cap - 1 ? std::strlen(src) : cap - 1;
		std::memcpy(dst, src, n);
		dst[n] = '\0';
	}

	// Fixed storage for what the test looks at before the lease wipes the arena: no allocation.
	struct Capture
	{
		char          url[256] = {};
		char          body[512] = {};
		std::size_t   bodyLen = 0;
		bool          built = false;
		BodyStatus    status = BodyStatus::Ok;
		std::size_t   arenaBytesAfterFailedRead = 99;
		char          ws[telephony::kTokenBodyBytes + 2] = {};
		bool          wsSet = false;
		std::size_t   readCalls = 0;
	};

	enum class Outcome { Installed, Discarded, Failed };

	// fetchToken() after the claim, in its order, with a scripted socket for the I/O it does.
	Outcome fetchOwnCode(telephony::TokenLanes& lanes, TokenLane lane, const Config& cfg, Cache& cache,
	                     std::int64_t issuedUs, const std::string& response, Capture& cap, std::size_t cutAt = std::string::npos)
	{
		telephony::TokenLanes::Lease lease = lanes.claim(lane);
		if (!lease) return Outcome::Failed;

		telephony::TokenRequest req;
		cap.built = telephony::buildTokenRequest(lease.data(), lease.capacity(), cfg.baseUrl, cfg.id, cfg.secret, req);
		if (!cap.built)
		{
			lanes.noteFetchFailed(lane);
			return Outcome::Failed;
		}
		copyz(cap.url, sizeof cap.url, req.url);
		cap.bodyLen = req.bodyLen;
		std::memcpy(cap.body, req.body, req.bodyLen < sizeof cap.body ? req.bodyLen : sizeof cap.body);

		// esp_http_client_open/write are over; the response is read into the same arena
		Feed feed{response, cutAt < response.size() ? cutAt : response.size()};
		std::int64_t clockUs = kT0;
		cap.status = lease.collect(
		    [&](char* dst, std::size_t room) {
			    ++cap.readCalls;
			    const int n = feed.read(dst, room);
			    return telephony::httpReadResult(n, n != 0 || feed.complete());
		    },
		    [&] { return clockUs; }, telephony::kTokenBodyBudgetUs);
		if (cap.status != BodyStatus::Ok)
		{
			cap.arenaBytesAfterFailedRead = lease.size();
			lanes.noteFetchFailed(lane);
			return Outcome::Failed;
		}
		std::string_view tokenStr;
		if (!telephony::jsonStringField(lease.data(), lease.size(), "access_token", tokenStr) ||
		    telephony::checkToken(tokenStr) != telephony::TokenCheck::Ok)   // acceptToken()
		{
			lanes.noteFetchFailed(lane);
			return Outcome::Failed;
		}

		const telephony::TokenLifetime life = telephony::readTokenLifetime(
		    std::string_view(lease.data(), lease.size()), tokenStr, lease.spare(), lease.spareBytes());
		lanes.noteLifetimeFields(life);
		const std::int64_t lifetimeUs = life.lifetimeUs;
				bool installed = false;
		{   // _mutex
			installed = cache.gate.installIfNewer(issuedUs);
			if (installed)
			{
				cache.bearer.set(tokenStr);
				cache.obtainedUs = clockUs;
				cache.lifetimeUs = lifetimeUs;
			}
		}
		if (!installed)
		{
			cache.gate.noteDiscarded(lane);
			return Outcome::Discarded;
		}
		if (const char* ws = telephony::wsAuthHeaderInPlace(lease.data(), lease.capacity(), tokenStr))
		{
			copyz(cap.ws, sizeof cap.ws, ws);
			cap.wsSet = true;
		}
		return Outcome::Installed;
	}
}

// ── the whole path, no heap ─────────────────────────────────────────────────────────

TEST(FetchTokenOwnCode, TheWholeOwnCodePathTakesNoHeapAndInstallsTheTokenWhole)
{
	telephony::TokenLanes lanes;
	Cache                 cache;
	const Config          cfg;
	const std::string     token = makeToken(400);
	ASSERT_GT(token.size(), 1000u) << "a JWT-sized token, well past any inline string";
	const std::string response = tokenResponse(token);
	Capture           cap;
	Outcome           out = Outcome::Failed;
	std::size_t       heap = 0;
	{
		AllocGuard g;
		out = fetchOwnCode(lanes, TokenLane::Emergency, cfg, cache, kT0 + 10, response, cap);
		heap = g.delta();
	}
	EXPECT_EQ(heap, 0u) << "request, response, lifetime, cache and WebSocket header: none of it touches the heap";
	ASSERT_EQ(out, Outcome::Installed);
	EXPECT_EQ(std::string(cache.bearer), "Bearer " + token);
	EXPECT_EQ(cache.lifetimeUs, 3600LL * 1000000);
	EXPECT_EQ(std::string(cap.ws), "Authorization: Bearer " + token + "\r\n");
	EXPECT_EQ(std::string(cap.url), telephony::tokenUrl(cfg.baseUrl));
	EXPECT_EQ(std::string(cap.body, cap.bodyLen), oldBody(cfg));
}

TEST(FetchTokenOwnCode, AResponseIssuedEarlierIsDiscardedWithNoHeapEitherAndTheInstalledTokenStays)
{
	telephony::TokenLanes lanes;
	Cache                 cache;
	const Config          cfg;
	const std::string     later = makeToken(300), earlier = makeToken(200);
	Capture               c1, c2;
	ASSERT_EQ(fetchOwnCode(lanes, TokenLane::Ordinary, cfg, cache, kT0 + 2000, tokenResponse(later), c1),
	          Outcome::Installed);
	pdwitness::clear();
	Outcome     out = Outcome::Failed;
	std::size_t heap = 0;
	const std::string response = tokenResponse(earlier);
	{
		AllocGuard g;
		out = fetchOwnCode(lanes, TokenLane::Maintenance, cfg, cache, kT0 + 1000, response, c2);
		heap = g.delta();
	}
	EXPECT_EQ(out, Outcome::Discarded) << "a discard is a success: a token issued later is in hand";
	EXPECT_EQ(heap, 0u);
	EXPECT_EQ(std::string(cache.bearer), "Bearer " + later);
	EXPECT_FALSE(c2.wsSet) << "the WebSocket keeps the header of the token that stays";
	EXPECT_EQ(pdwitness::count("token_install_older_862"), 1u);
}

TEST(FetchTokenOwnCode, PositiveControlTheSameRequestBuiltWithStringsIsCounted)
{
	// The sizes above are past what a std::string keeps inline, so the zero above is not an artefact of
	// short strings. The control builds the request the way fetchToken() did before #951.
	const Config cfg;
	std::size_t  heap = 0;
	volatile std::size_t keep = 0;
	{
		AllocGuard g;
		std::string url = cfg.baseUrl + "/connect/token";
		std::string clientId = cfg.id, clientSecret = cfg.secret;
		std::string body = oldBody(cfg);
		keep = url.size() + clientId.size() + clientSecret.size() + body.size();
		heap = g.delta();
	}
	EXPECT_GE(heap, 3u);
	(void)keep;
}

// ── the request ─────────────────────────────────────────────────────────────────────

TEST(FetchTokenOwnCode, TheRequestIsTheSameBytesTheStringsBuilt)
{
	// Every byte value in the secret: the unreserved set passes, everything else is %XX in capitals.
	std::string every;
	for (int c = 1; c < 256; ++c) every.push_back(static_cast<char>(c));
	for (const std::string& secret : {std::string(kSecret), every, std::string(), std::string("a b&c=d%e+f/g")})
	{
		Config cfg;
		cfg.secret = secret;
		char                  buf[telephony::kTokenBodyBytes + 1];
		telephony::TokenRequest req;
		ASSERT_TRUE(telephony::buildTokenRequest(buf, sizeof buf, cfg.baseUrl, cfg.id, cfg.secret, req));
		EXPECT_EQ(std::string(req.url), telephony::tokenUrl(cfg.baseUrl));
		EXPECT_EQ(std::string(req.body, req.bodyLen), oldBody(cfg));
		EXPECT_EQ(req.body, req.url + cfg.baseUrl.size() + std::strlen("/connect/token") + 1) << "the body follows the URL's NUL";
	}
}

TEST(FetchTokenOwnCode, ARequestThatFitsExactlyIsBuiltAndOneByteLessIsRefusedNotCut)
{
	const Config cfg;
	const std::size_t need = cfg.baseUrl.size() + std::strlen("/connect/token") + 1 + oldBody(cfg).size();
	char                  buf[512];
	std::memset(buf, 0x5A, sizeof buf);
	telephony::TokenRequest req;
	EXPECT_TRUE(telephony::buildTokenRequest(buf, need, cfg.baseUrl, cfg.id, cfg.secret, req));
	EXPECT_EQ(buf[need], 0x5A) << "never a byte past cap";
	EXPECT_FALSE(telephony::buildTokenRequest(buf, need - 1, cfg.baseUrl, cfg.id, cfg.secret, req));
	EXPECT_FALSE(telephony::buildTokenRequest(buf, 0, cfg.baseUrl, cfg.id, cfg.secret, req));
}

TEST(FetchTokenOwnCode, ARequestTooBigForTheArenaFailsTheFetchBeforeAnyReadAndLeavesTheCache)
{
	telephony::TokenLanes lanes;
	Cache                 cache;
	Config                cfg;
	Capture               first;
	ASSERT_EQ(fetchOwnCode(lanes, TokenLane::Ordinary, cfg, cache, kT0 + 1, tokenResponse(makeToken(100)), first),
	          Outcome::Installed);
	const std::string cached = cache.bearer;

	cfg.secret.assign(2000, '\x01');   // 2000 bytes, each %01: 6000 bytes of body, past the 4097 byte arena
	Capture cap;
	pdwitness::clear();
	EXPECT_EQ(fetchOwnCode(lanes, TokenLane::Emergency, cfg, cache, kT0 + 2, tokenResponse(makeToken(100)), cap),
	          Outcome::Failed);
	EXPECT_FALSE(cap.built);
	EXPECT_EQ(cap.readCalls, 0u) << "nothing was sent or read";
	EXPECT_EQ(std::string(cache.bearer), cached) << "Rule 5: the token already cached is kept";
	EXPECT_EQ(pdwitness::count("token_fetch_failed_951"), 1u);
	EXPECT_TRUE(cache.gate.installIfNewer(kT0 + 1 + 1)) << "and the install stamp did not move";
}

TEST(FetchTokenOwnCode, UrlEncodeIntoGivesUrlEncodesBytesForEveryByteAndStopsAtItsCapacity)
{
	for (int c = 0; c < 256; ++c)
	{
		const std::string one(1, static_cast<char>(c));
		char              out[8];
		std::size_t       n = 0;
		ASSERT_TRUE(urlEncodeInto(one, out, sizeof out, n)) << c;
		EXPECT_EQ(std::string(out, n), urlEncode(one)) << c;
	}
	const std::string text = "a b/c+d=e~f.g-h_i%j";
	const std::string full = urlEncode(text);
	char              out[64];
	std::memset(out, 0x5A, sizeof out);
	std::size_t n = 0;
	EXPECT_TRUE(urlEncodeInto(text, out, full.size(), n));
	EXPECT_EQ(n, full.size());
	EXPECT_EQ(out[full.size()], 0x5A);
	n = 0;
	EXPECT_FALSE(urlEncodeInto(text, out, full.size() - 1, n)) << "an escape that would not fit whole is not started";
	EXPECT_LE(n, full.size() - 1);
	std::size_t m = 3;
	EXPECT_FALSE(urlEncodeInto(" ", out, 4, m)) << "the offset is honoured: 1 byte left, 3 needed";
	EXPECT_EQ(m, 3u);
}

// ── the token: too big, short read, scratch ──────────────────────────────────────────

TEST(FetchTokenOwnCode, TheLimitIsWhatTheWebSocketHeaderLeavesOfTheArena)
{
	static_assert(telephony::kMaxTokenBytes + telephony::kWsAuthPrefixBytes + telephony::kWsAuthSuffixBytes ==
	                  telephony::kTokenBodyBytes + 1,
	              "the header line takes the whole arena at the limit");
	EXPECT_EQ(telephony::kMaxTokenBytes, 4072u);
	EXPECT_EQ(telephony::kBearerHeaderBytes, 4079u);
	std::string t = "a.b." + std::string(telephony::kMaxTokenBytes - 4, 'c');
	EXPECT_EQ(telephony::checkToken(t), telephony::TokenCheck::Ok);
	EXPECT_EQ(telephony::checkToken(t + "c"), telephony::TokenCheck::TooBig);
	EXPECT_STREQ(telephony::tokenCheckName(telephony::TokenCheck::TooBig), "too big for the token cache");
	EXPECT_EQ(telephony::checkToken(""), telephony::TokenCheck::Empty) << "the old verdicts are unchanged";
	EXPECT_EQ(telephony::checkToken("nodots"), telephony::TokenCheck::NotAJwt);

	// At the limit the header line is the whole arena, and one byte more is refused, untouched.
	char buf[telephony::kTokenBodyBytes + 1];
	std::memcpy(buf + 24, t.data(), telephony::kMaxTokenBytes);
	const char* ws = telephony::wsAuthHeaderInPlace(buf, sizeof buf, std::string_view(buf + 24, telephony::kMaxTokenBytes));
	ASSERT_NE(ws, nullptr);
	EXPECT_EQ(std::string(ws), "Authorization: Bearer " + t + "\r\n");
	std::memset(buf, 0x5A, sizeof buf);
	EXPECT_EQ(telephony::wsAuthHeaderInPlace(buf, sizeof buf, std::string_view(buf + 24, telephony::kMaxTokenBytes + 1)),
	          nullptr);
	EXPECT_EQ(buf[0], 0x5A);
	EXPECT_EQ(buf[telephony::kTokenBodyBytes], 0x5A);
}

TEST(FetchTokenOwnCode, ATokenOneByteOverTheLimitIsRefusedNotCutTheCachedTokenStaysAndTheStampDoesNotMove)
{
	telephony::TokenLanes lanes;
	Cache                 cache;
	const Config          cfg;
	Capture               first;
	ASSERT_EQ(fetchOwnCode(lanes, TokenLane::Ordinary, cfg, cache, kT0 + 1000, tokenResponse(makeToken(100)), first),
	          Outcome::Installed);
	const std::string cachedBearer = cache.bearer;
	const std::int64_t cachedObtained = cache.obtainedUs, cachedLifetime = cache.lifetimeUs;

	std::string big = "a.b." + std::string(telephony::kMaxTokenBytes - 3, 'c');   // one over
	ASSERT_EQ(big.size(), telephony::kMaxTokenBytes + 1);
	const std::string response = bareResponse(big);
	ASSERT_LE(response.size(), telephony::kTokenBodyBytes) << "the arena itself would have taken it";
	Capture cap;
	pdwitness::clear();
	std::size_t heap = 0;
	Outcome     out = Outcome::Installed;
	{
		AllocGuard g;
		out = fetchOwnCode(lanes, TokenLane::Emergency, cfg, cache, kT0 + 2000, response, cap);
		heap = g.delta();
	}
	EXPECT_EQ(out, Outcome::Failed);
	EXPECT_EQ(cap.status, BodyStatus::Ok) << "the body read fine: it is the token that is refused";
	EXPECT_EQ(std::string(cache.bearer), cachedBearer) << "no cut token, and the one cached before is kept";
	EXPECT_EQ(cache.obtainedUs, cachedObtained);
	EXPECT_EQ(cache.lifetimeUs, cachedLifetime);
	EXPECT_FALSE(cap.wsSet);
	EXPECT_EQ(heap, 0u) << "a refusal allocates nothing either";
	EXPECT_EQ(pdwitness::count("token_fetch_failed_951"), 1u) << "and leaves its witness line";
	// the check runs before the gate: a response issued after the cached one but before the refused one still installs
	EXPECT_TRUE(cache.gate.installIfNewer(kT0 + 1500)) << "the refused response did not advance the install stamp";
}

TEST(FetchTokenOwnCode, ATokenAtTheLimitIsCachedWholeAndItsHeaderIsBuiltWithNoHeap)
{
	telephony::TokenLanes lanes;
	Cache                 cache;
	const Config          cfg;
	const std::string     token = "a.b." + std::string(telephony::kMaxTokenBytes - 4, 'c');
	const std::string     response = bareResponse(token);
	ASSERT_LE(response.size(), telephony::kTokenBodyBytes);
	Capture     cap;
	std::size_t heap = 0;
	Outcome     out = Outcome::Failed;
	{
		AllocGuard g;
		out = fetchOwnCode(lanes, TokenLane::Ordinary, cfg, cache, kT0 + 1, response, cap);
		heap = g.delta();
	}
	EXPECT_EQ(out, Outcome::Installed);
	EXPECT_EQ(heap, 0u) << "the string reserved at init() holds the longest token without growing";
	EXPECT_EQ(std::string(cache.bearer), "Bearer " + token);
	EXPECT_EQ(std::string(cap.ws), "Authorization: Bearer " + token + "\r\n");
	EXPECT_EQ(cache.lifetimeUs, telephony::kTokenFallbackLifetimeUs) << "no claims in it: the fallback";
}

TEST(FetchTokenOwnCode, AShortReadIsAnErrorWithNoBytesAndNoTokenTheCachedOneStays)
{
	telephony::TokenLanes lanes;
	Cache                 cache;
	const Config          cfg;
	Capture               first;
	ASSERT_EQ(fetchOwnCode(lanes, TokenLane::Ordinary, cfg, cache, kT0 + 1000, tokenResponse(makeToken(100)), first),
	          Outcome::Installed);
	const std::string cached = cache.bearer;

	// The connection closes early: the socket answers 0 (end) but the response is not whole. The cut
	// is after the token's own closing quote, so the JSON up to there holds a complete token.
	const std::string token = makeToken(100);
	const std::string response = tokenResponse(token);
	const std::size_t cut = response.find("\",\"scope\"") + 1;
	ASSERT_LT(cut, response.size());
	for (const std::size_t at : {std::size_t(0), response.size() / 2, cut})
	{
		Capture cap;
		pdwitness::clear();
		EXPECT_EQ(fetchOwnCode(lanes, TokenLane::Emergency, cfg, cache, kT0 + 2000, response, cap, at), Outcome::Failed)
		    << "cut at " << at;
		EXPECT_EQ(cap.status, BodyStatus::ReadError) << "cut at " << at << ": a short body is an error, not a shorter token";
		EXPECT_EQ(cap.arenaBytesAfterFailedRead, 0u) << "cut at " << at << ": the arena shows nothing";
		EXPECT_EQ(std::string(cache.bearer), cached) << "cut at " << at;
		EXPECT_EQ(pdwitness::count("token_fetch_failed_951"), 1u) << "cut at " << at;
	}
}

TEST(FetchTokenOwnCode, TheLifetimeDecodeNeedsOnlyThreeQuartersOfThePayloadAndTakesNoHeap)
{
	const std::string jwt = makeToken(300);
	const std::size_t dot1 = jwt.find('.'), dot2 = jwt.find('.', dot1 + 1);
	const std::size_t need = (dot2 - dot1 - 1) * 3 / 4;
	std::string       scratch(need, '\0');
	pdwitness::clear();
	std::size_t heap = 0;
	std::int64_t got = 0;
	{
		AllocGuard g;
		got = telephony::decodeJwtLifetimeUs(jwt, &scratch[0], need);
		heap = g.delta();
	}
	EXPECT_EQ(got, 3600LL * 1000000);
	EXPECT_EQ(heap, 0u);
	EXPECT_EQ(telephony::decodeJwtLifetimeUs(jwt, &scratch[0], need - 1), telephony::kLifetimeNoScratch)
	    << "one byte short: it does not look, and answers with a value that is no lifetime";
	EXPECT_EQ(telephony::decodeJwtLifetimeUs(jwt, nullptr, 0), telephony::kLifetimeNoScratch);
	EXPECT_EQ(pdwitness::count("token_lifetime_scratch_951"), 0u) << "the decode itself says nothing; tokenLifetimeUs() does";
}

// ── the lifetime of a token (#951) ───────────────────────────────────────────────────────────────
// The operator's rule: exp - iat of the payload (read from the start of it when it does not fit the
// scratch), else five minutes; the token is always installed, whatever is cached; expires_in is
// logged and never used.

TEST(FetchTokenLifetime, EndToEndTheClaimsAreTheLifetimeAndExpiresInIsNotUsedWithNoHeap)
{
	telephony::TokenLanes lanes;
	Cache                 cache;
	const Config          cfg;
	const std::string     token = makeToken(2400);   // iat and exp early in a 2.4 KB payload; tokenResponse() says expires_in 60
	ASSERT_LT(token.size(), telephony::kMaxTokenBytes);
	const std::string response = tokenResponse(token);
	Capture           cap;
	pdwitness::clear();
	std::size_t heap = 0;
	Outcome     out = Outcome::Failed;
	{
		AllocGuard g;
		out = fetchOwnCode(lanes, TokenLane::Ordinary, cfg, cache, kT0 + 1, response, cap);
		heap = g.delta();
	}
	EXPECT_EQ(out, Outcome::Installed);
	EXPECT_EQ(heap, 0u);
	EXPECT_EQ(cache.lifetimeUs, 3600LL * 1000000) << "exp - iat, not the response's expires_in 60";
	EXPECT_EQ(pdwitness::count("token_lifetime_scratch_951"), 1u);
	EXPECT_EQ(pdwitness::count("token_lifetime_fields_951"), 1u) << "one line per fetch";
	EXPECT_EQ(std::string(cache.bearer), "Bearer " + token) << "the token itself is whole";
}

TEST(FetchTokenLifetime, PayloadTooBigWithTheClaimsAtItsStartInstallsWithExpMinusIat)
{
	telephony::TokenLanes lanes;
	Cache                 cache;
	const Config          cfg;
	const std::string     token = makeBigToken(2400, false);   // exp and iat at the start of the payload, the pad after
	const std::string     response = responseWith(token, "");   // no expires_in
	Capture               cap;
	EXPECT_EQ(fetchOwnCode(lanes, TokenLane::Ordinary, cfg, cache, kT0 + 1, response, cap), Outcome::Installed);
	EXPECT_EQ(cache.lifetimeUs, 3600LL * 1000000);
}

TEST(FetchTokenLifetime, PayloadTooBigWithUnreadableClaimsInstallsWithTheFiveMinuteFallbackWhateverExpiresInSays)
{
	telephony::TokenLanes lanes;
	Cache                 cache;
	const Config          cfg;
	ASSERT_TRUE(cache.bearer.empty());
	const std::string token = makeBigToken(2400, true);   // the pad comes first: no claims in the start of the payload
	const std::string response = responseWith(token, "\"expires_in\":600,");
	Capture           cap;
	pdwitness::clear();
	std::size_t heap = 0;
	Outcome     out = Outcome::Failed;
	{
		AllocGuard g;
		out = fetchOwnCode(lanes, TokenLane::Emergency, cfg, cache, kT0 + 1, response, cap);
		heap = g.delta();
	}
	EXPECT_EQ(out, Outcome::Installed) << "a 911/933 with no token is never refused for want of a lifetime";
	EXPECT_EQ(heap, 0u);
	EXPECT_EQ(cache.lifetimeUs, telephony::kTokenShortFallbackLifetimeUs) << "not the 600 s expires_in says";
	EXPECT_EQ(telephony::kTokenShortFallbackLifetimeUs, 5LL * 60 * 1000000);
	EXPECT_LT(telephony::kTokenShortFallbackLifetimeUs, telephony::kTokenFallbackLifetimeUs) << "it errs short";
	EXPECT_EQ(std::string(cache.bearer), "Bearer " + token);
	EXPECT_EQ(pdwitness::count("token_lifetime_short_951"), 1u);
}

TEST(FetchTokenLifetime, PayloadTooBigWithUnreadableClaimsInstallsTheFreshTokenWithTheFiveMinuteFallbackEvenWhenATokenIsCached)
{
	telephony::TokenLanes lanes;
	Cache                 cache;
	const Config          cfg;
	Capture               first;
	ASSERT_EQ(fetchOwnCode(lanes, TokenLane::Ordinary, cfg, cache, kT0 + 1000, tokenResponse(makeToken(100)), first),
	          Outcome::Installed);
	const std::string cachedBearer = cache.bearer;

	const std::string token = makeBigToken(2400, true);   // nothing readable in its start
	const std::string response = responseWith(token, "");   // and no expires_in
	Capture           cap;
	pdwitness::clear();
	std::size_t heap = 0;
	Outcome     out = Outcome::Failed;
	{
		AllocGuard g;
		out = fetchOwnCode(lanes, TokenLane::Emergency, cfg, cache, kT0 + 2000, response, cap);
		heap = g.delta();
	}
	EXPECT_EQ(out, Outcome::Installed) << "Telephony dropped the cached token when it granted this one: it is never kept over it";
	EXPECT_EQ(heap, 0u);
	EXPECT_NE(std::string(cache.bearer), cachedBearer);
	EXPECT_EQ(std::string(cache.bearer), "Bearer " + token);
	EXPECT_EQ(cache.lifetimeUs, telephony::kTokenShortFallbackLifetimeUs);
	EXPECT_TRUE(cap.wsSet) << "and the WebSocket gets the new header";
	EXPECT_EQ(pdwitness::count("token_fetch_failed_951"), 0u);
	EXPECT_FALSE(cache.gate.installIfNewer(kT0 + 2000)) << "the newer install moved the stamp to its own issue time";
	EXPECT_TRUE(cache.gate.installIfNewer(kT0 + 2001));
}

TEST(FetchTokenLifetime, ANumberTheScratchCutsThroughIsNeverReadAsIfItWereWhole)
{
	// iat 100, exp 3700: 3600 s. A scratch that ends inside "3700" would read exp as 370 (270 s).
	const std::string json = "{\"iat\":100,\"exp\":3700,\"pad\":\"" + std::string(900, 'p') + "\"}";
	const std::string token = b64url("{\"alg\":\"none\"}") + "." + b64url(json) + ".sig";
	const std::size_t cut = json.find("\"exp\":370") + std::strlen("\"exp\":370");
	std::string       scratch(cut, '\0');
	const telephony::TokenLifetime cutRead = telephony::readTokenLifetime("{}", token, &scratch[0], cut);
	EXPECT_EQ(cutRead.lifetimeUs, telephony::kTokenShortFallbackLifetimeUs) << "nothing readable: not 270 s";
	EXPECT_EQ(cutRead.spanS, -1);
	const telephony::TokenLifetime withExpiresIn = telephony::readTokenLifetime("{\"expires_in\":900}", token, &scratch[0], cut);
	EXPECT_EQ(withExpiresIn.lifetimeUs, telephony::kTokenShortFallbackLifetimeUs) << "expires_in is not a lifetime";
	EXPECT_EQ(withExpiresIn.expiresInS, 900) << "but it is read, for the witness";
	// a scratch that holds both claims and the comma after them reads them
	std::string wider(json.find("\"pad\""), '\0');
	const telephony::TokenLifetime wide = telephony::readTokenLifetime("{}", token, &wider[0], wider.size());
	EXPECT_EQ(wide.lifetimeUs, 3600LL * 1000000);
	EXPECT_EQ(wide.spanS, 3600);
}

TEST(FetchTokenLifetime, ANormalSizePayloadIsReadAsBeforeIgnoresExpiresInAndAnUnparseableOneKeepsTheOldFallback)
{
	std::vector<char> scratch(4096);
	const telephony::TokenLifetime fits =
	    telephony::readTokenLifetime("{\"expires_in\":60}", makeToken(100), scratch.data(), scratch.size());
	EXPECT_EQ(fits.lifetimeUs, 3600LL * 1000000)
	    << "Telephony reports expires_in:60 for a token that lives an hour: a payload that fits is not min()'d with it";
	EXPECT_EQ(fits.spanS, 3600);
	EXPECT_EQ(fits.expiresInS, 60);
	// exp and iat missing from a payload that fits: the unchanged #945 fallback, tracked in #975
	const std::string noClaims = b64url("{\"alg\":\"none\"}") + "." + b64url("{\"iss\":\"x\"}") + ".sig";
	const telephony::TokenLifetime unparsed =
	    telephony::readTokenLifetime("{\"expires_in\":600}", noClaims, scratch.data(), scratch.size());
	EXPECT_EQ(unparsed.lifetimeUs, telephony::kTokenFallbackLifetimeUs);
	EXPECT_EQ(unparsed.spanS, -1);
	EXPECT_EQ(unparsed.expiresInS, 600);
	EXPECT_EQ(telephony::readTokenLifetime("{}", "not-a-jwt", scratch.data(), scratch.size()).lifetimeUs,
	          telephony::kTokenFallbackLifetimeUs);
	EXPECT_EQ(telephony::kTokenFallbackLifetimeUs, 50LL * 60 * 1000000);
}

// token_lifetime_fields_951: the bench's check of what expires_in really is (#951)

TEST(FetchTokenLifetime, TheLifetimeFieldsWitnessLogsExpiresInTheSpanAndTheLifetimeUsedAsNumbersAndNothingElse)
{
	telephony::TokenLanes lanes;
	std::vector<char>     scratch(4096);
	const std::string     token = makeToken(100);
	pdwitness::clear();
	lanes.noteLifetimeFields(telephony::readTokenLifetime("{\"expires_in\":60}", token, scratch.data(), scratch.size()));
	lanes.noteLifetimeFields(telephony::readTokenLifetime("{}", "not-a-jwt", scratch.data(), scratch.size()));
	const std::string bigNeither = makeBigToken(2400, true);
	char              small[256];
	lanes.noteLifetimeFields(telephony::readTokenLifetime("{\"expires_in\":900}", bigNeither, small, sizeof small));
	const auto lines = pdwitness::lines();
	std::vector<std::string> fields;
	for (const std::string& l : lines)
		if (l.find("token_lifetime_fields_951") != std::string::npos) fields.push_back(l);
	ASSERT_EQ(fields.size(), 3u);
	EXPECT_EQ(fields[0], "anchor: token_lifetime_fields_951: expires_in=60 exp_minus_iat=3600 lifetime_used=3600 "
	                     "(seconds; -1: not read) (#951)");
	EXPECT_EQ(fields[1], "anchor: token_lifetime_fields_951: expires_in=-1 exp_minus_iat=-1 lifetime_used=3000 "
	                     "(seconds; -1: not read) (#951)")
	    << "nothing read: -1 twice, and the unparseable-JWT fallback (#975) as the lifetime";
	EXPECT_EQ(fields[2], "anchor: token_lifetime_fields_951: expires_in=900 exp_minus_iat=-1 lifetime_used=300 "
	                     "(seconds; -1: not read) (#951)")
	    << "expires_in read and logged, not used";
	for (const std::string& l : fields)
	{
		EXPECT_EQ(l.find(token.substr(0, 24)), std::string::npos) << "no token in it";
		EXPECT_EQ(l.find(bigNeither.substr(0, 24)), std::string::npos);
		EXPECT_EQ(l.find("Bearer"), std::string::npos);
		EXPECT_EQ(l.find(kSecret), std::string::npos);
	}
}

TEST(FetchTokenLifetime, TheLifetimeFieldsWitnessIsCappedAtEightPerBootAndLogsTheFirstEight)
{
	EXPECT_EQ(telephony::kLifetimeFieldsWitnessCap, 8u);
	telephony::TokenLanes lanes;
	pdwitness::clear();
	for (int i = 0; i < 30; ++i)
		lanes.noteLifetimeFields(telephony::TokenLifetime{(i + 1) * 1000000LL, i, i + 100});
	EXPECT_EQ(pdwitness::count("token_lifetime_fields_951"), 8u);
	EXPECT_EQ(pdwitness::count("expires_in=7 exp_minus_iat=107 lifetime_used=8 "), 1u) << "the eighth is the last";
	EXPECT_EQ(pdwitness::count("expires_in=8 "), 0u) << "the ninth is not logged";
	telephony::TokenLanes another;   // a boot is a client: a second one has its own eight
	another.noteLifetimeFields(telephony::TokenLifetime{1000000, 0, 0});
	EXPECT_EQ(pdwitness::count("token_lifetime_fields_951"), 9u);
}

// ── a short lifetime and the background refresh ─────────────────────────────────────────────────
// The maintenance lane cannot storm on a short fallback: a token that lives no longer than the
// refresh margin is never due for it, and the job is woken at most once a minute whatever is due.

TEST(FetchTokenLifetime, ATokenWithTheFiveMinuteFallbackIsNeverDueForTheBackgroundRefresh)
{
	constexpr std::int64_t kStamp = 7LL * 1000000, kMin = 60LL * 1000000;
	for (const std::int64_t ageUs : {std::int64_t(0), kMin, 4 * kMin, 5 * kMin, 10 * kMin, 60 * kMin, 600 * kMin})
	{
		const std::int64_t now = kStamp + ageUs;
		EXPECT_FALSE(telephony::maintTokenDue(now, kStamp, telephony::kTokenShortFallbackLifetimeUs)) << ageUs;
		EXPECT_FALSE(telephony::maintRefreshWakeDue(now, kStamp, telephony::kTokenShortFallbackLifetimeUs, 0)) << ageUs;
		const telephony::MaintRefreshDecision d =
		    telephony::maintRefreshDecision(now, kStamp, telephony::kTokenShortFallbackLifetimeUs, false, false, false);
		EXPECT_FALSE(d.refresh) << ageUs;
		EXPECT_EQ(d.reason, telephony::MaintRefreshReason::NotDue) << ageUs;
	}
	// positive control: a lifetime past the margin is due once its age reaches lifetime - margin
	const std::int64_t life = telephony::kMaintRefreshMarginUs + kMin;
	EXPECT_FALSE(telephony::maintTokenDue(kStamp + kMin - 1, kStamp, life));
	EXPECT_TRUE(telephony::maintTokenDue(kStamp + kMin, kStamp, life));
}

TEST(FetchTokenLifetime, TheBackgroundRefreshIsWokenNoMoreOftenThanOnceAMinute)
{
	constexpr std::int64_t kStamp = 7LL * 1000000, kSec = 1000000, kHour = 3600 * kSec;
	const std::int64_t     now = kStamp + 55 * 60 * kSec;   // an hour token, past lifetime - 10 minutes: due
	ASSERT_TRUE(telephony::maintTokenDue(now, kStamp, kHour));
	EXPECT_EQ(telephony::kMaintRefreshRetryUs, 60 * kSec);
	EXPECT_TRUE(telephony::maintRefreshWakeDue(now, kStamp, kHour, 0)) << "never woken";
	EXPECT_FALSE(telephony::maintRefreshWakeDue(now, kStamp, kHour, now - 30 * kSec)) << "a second wake 30 s after the first";
	EXPECT_FALSE(telephony::maintRefreshWakeDue(now, kStamp, kHour, now - 60 * kSec + 1));
	EXPECT_TRUE(telephony::maintRefreshWakeDue(now, kStamp, kHour, now - 60 * kSec)) << "and one after 60 s";
	// a run of ticks, one a second, for ten minutes with the token due all along: one wake a minute
	std::int64_t last = 0;
	int          wakes = 0;
	for (std::int64_t t = now; t < now + 600 * kSec; t += kSec)
	{
		if (telephony::maintRefreshWakeDue(t, kStamp, kHour, last))
		{
			last = t;
			++wakes;
		}
	}
	EXPECT_EQ(wakes, 10);
}

TEST(FetchTokenOwnCode, ScanJsonNumberBuildsNoNeedleSoAKeyOfAnyLengthTakesNoHeap)
{
	const std::string json = "{\"a_key_much_longer_than_any_inline_string\":1700003600,\"x\":2}";
	std::int64_t      v = 0;
	bool              ok = false;
	std::size_t       heap = 0;
	{
		AllocGuard g;
		ok = telephony::scanJsonNumber(json, "a_key_much_longer_than_any_inline_string", v);
		heap = g.delta();
	}
	EXPECT_TRUE(ok);
	EXPECT_EQ(v, 1700003600);
	EXPECT_EQ(heap, 0u);
	// a key that only starts like the one asked for, and one cut off by the end of the text
	EXPECT_FALSE(telephony::scanJsonNumber("{\"expx\":1}", "exp", v));
	EXPECT_FALSE(telephony::scanJsonNumber("{\"exp", "exp", v));
	EXPECT_FALSE(telephony::scanJsonNumber("\"", "exp", v));
	EXPECT_TRUE(telephony::scanJsonNumber("{\"exp\"\"exp\":7}", "exp", v)) << "a key with no colon after it is skipped whole";
	EXPECT_EQ(v, 7);
}

// ── the cached token, the WebSocket header, the arena's wipe, the witness ───────────────────

TEST(FetchTokenOwnCode, TheCachedTokenIsAssignedInsideTheCapacityReservedOnceAndWithoutItTheAssignAllocates)
{
	const std::string token = makeToken(300);
	telephony::BearerHeader reserved;
	std::size_t       reserveHeap = 0;
	{
		AllocGuard g;
		reserved.reserve();
		reserveHeap = g.delta();
	}
	EXPECT_GE(reserveHeap, 1u) << "init() pays for it once, through PsramAllocator (operator new on the host)";
	EXPECT_GE(reserved.capacity(), telephony::kBearerHeaderBytes);
	EXPECT_TRUE(reserved.empty());
	const std::string longer = token + "x";
	std::size_t heap = 0;
	{
		AllocGuard g;
		reserved.set(token);
		reserved.set(longer);
		heap = g.delta();
	}
	EXPECT_EQ(heap, 0u);
	EXPECT_EQ(std::string(reserved), "Bearer " + longer);

	telephony::BearerHeader unreserved;
	std::size_t control = 0;
	{
		AllocGuard g;
		unreserved.set(token);
		control = g.delta();
	}
	EXPECT_GE(control, 1u) << "positive control: without the reserve the assign allocates";
}

TEST(FetchTokenOwnCode, TheCachedTokenIsCopiedOutAsAStdStringTheWayTheReadersTakeIt)
{
	telephony::BearerHeader bearer;
	bearer.reserve();
	EXPECT_TRUE(bearer.empty());
	std::string empty = bearer;   // what a reader gets before any token: an empty string, as before
	EXPECT_TRUE(empty.empty());
	bearer.set("a.b.c");
	std::string copy;
	copy = bearer;   // `bearerHeader = _bearerHeader;` at the reader sites
	EXPECT_EQ(copy, "Bearer a.b.c");
	std::string initialised = bearer;   // `std::string s = _bearerHeader;`
	EXPECT_EQ(initialised, "Bearer a.b.c");
	EXPECT_FALSE(bearer.empty());
	bearer.set("d.e.f");
	EXPECT_EQ(std::string(bearer), "Bearer d.e.f") << "the next token replaces the last whole";
	EXPECT_EQ(copy, "Bearer a.b.c") << "and a copy taken before is unaffected";
}

TEST(FetchTokenOwnCode, TheWebSocketHeaderIsRebuiltInPlaceWhereverTheTokenSits)
{
	const std::string token = makeToken(100);
	for (const std::size_t at : {std::size_t(0), std::size_t(5), std::size_t(17), std::size_t(22), std::size_t(300)})
	{
		std::string buf(telephony::kTokenBodyBytes + 1, '\0');
		std::memcpy(&buf[at], token.data(), token.size());
		const std::string_view view(&buf[at], token.size());
		std::size_t            heap = 0;
		const char*            ws = nullptr;
		{
			AllocGuard g;
			ws = telephony::wsAuthHeaderInPlace(&buf[0], buf.size(), view);
			heap = g.delta();
		}
		ASSERT_NE(ws, nullptr) << "token at " << at;
		EXPECT_EQ(heap, 0u);
		EXPECT_EQ(std::string(ws), "Authorization: Bearer " + token + "\r\n") << "token at " << at;
	}
	char small[10];
	EXPECT_EQ(telephony::wsAuthHeaderInPlace(small, sizeof small, std::string_view(small, 4)), nullptr);
}

TEST(FetchTokenOwnCode, TheRequestAndItsClientSecretAreWipedWithTheArenaWhenTheFetchEnds)
{
	telephony::TokenLanes lanes;
	Cache                 cache;
	const Config          cfg;
	Capture               cap;
	// A fetch that dies on the read: the request is still in the arena when it returns.
	ASSERT_EQ(fetchOwnCode(lanes, TokenLane::Emergency, cfg, cache, kT0 + 1, tokenResponse(makeToken(50)), cap, 0),
	          Outcome::Failed);
	Arena::Lease lease = lanes.claim(TokenLane::Emergency);
	ASSERT_TRUE(lease);
	const std::string seen(lease.data(), lease.capacity());
	EXPECT_EQ(seen.find(cfg.id), std::string::npos);
	EXPECT_EQ(seen.find(urlEncode(cfg.secret)), std::string::npos);
	EXPECT_EQ(seen.find_first_not_of('\0'), std::string::npos) << "the whole arena is zeros";
}

TEST(FetchTokenOwnCode, TheFailureWitnessNamesTheLaneAndNoOtherDetail)
{
	telephony::TokenLanes lanes;
	pdwitness::clear();
	lanes.noteFetchFailed(TokenLane::Ordinary);
	lanes.noteFetchFailed(TokenLane::Emergency);
	lanes.noteFetchFailed(TokenLane::Maintenance);
	const auto lines = pdwitness::lines();
	ASSERT_EQ(lines.size(), 3u);
	EXPECT_NE(lines[0].find("the ordinary lane's token fetch failed"), std::string::npos) << lines[0];
	EXPECT_NE(lines[1].find("the 911/933 lane's token fetch failed"), std::string::npos) << lines[1];
	EXPECT_NE(lines[2].find("the maintenance lane's token fetch failed"), std::string::npos) << lines[2];
	for (const std::string& l : lines)
	{
		EXPECT_NE(l.find("the token already cached is kept"), std::string::npos) << l;
		EXPECT_EQ(l.find(kBase), std::string::npos);
		EXPECT_EQ(l.find(kSecret), std::string::npos);
	}
}
