#ifndef TELEPHONY_ANCHOR_LOGIC_HPP
#define TELEPHONY_ANCHOR_LOGIC_HPP

// ── Telephony anchor: pure, host-compilable parsing/URL logic ──────────────────────
// Issue #49 [H-8]: the TelephonyAnchorClient implementation (cJSON + mbedTLS +
// esp_http_client + FreeRTOS) compiles only on-device, so the JWT-lifetime
// decode, the WS-event entity-path tokenizer, and the call-control URL builders
// were locked behind `#if ESP_PLATFORM` and never unit-tested. CI compiled them
// but never exercised the logic — the exact bug class issue #40 fixed.
//
// This header extracts those three concerns as DEPENDENCY-FREE free functions
// (C++17 stdlib only — no cJSON, no mbedTLS; the one ESP header is Witness.hpp,
// which pulls esp_log.h on the board and a host ring in tests, and is only for
// the 911/933 path witnesses of #862) so the same code
// runs on the device AND in the host GoogleTest suite. The ESP .cpp arm calls
// these for the URL builders, the entity-path parse and the token's JWT lifetime
// (decodeJwtLifetimeUs: a self-contained base64url + a minimal exp/iat scan; the
// cJSON/mbedTLS version it replaced is gone, #862).
//
// Everything here is intentionally allocation-light and total: every malformed
// input maps to a documented, safe return value (the fallback lifetime / empty
// string / "no match"), never UB.

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

#include "PsramAllocator.hpp"   // #951: the cached bearer string's storage
#include "UrlEncode.hpp"  // #951: urlEncodeInto(), the token request's credentials without a std::string
#include "Witness.hpp"   // #862: the 911/933 token witnesses (one-line, no numbers)

namespace telephony
{

// Fallback token lifetime when the JWT can't be decoded: 50 minutes (µs). This
// is the JWT's real ~1h validity minus margin, deliberately NOT the OAuth
// expires_in (Telephony reports 60s there, which would cause a refresh storm).
inline constexpr int64_t kTokenFallbackLifetimeUs = 50LL * 60 * 1000000;

// #951: the lifetime of a token whose payload is too big to read exp and iat from, whose response
// carries no readable expires_in, and when there is no cached token to keep: 5 minutes. It errs
// short on purpose. The 50 minute constant above errs long (a token that really lives 10 minutes
// would be called valid for 50, and expire under a call), and is left as it is for a payload that
// cannot be parsed at all (#975). A token this short is never due for the background refresh
// (maintTokenDue: a lifetime within the 10 minute margin is not), so it is renewed ahead of an
// ordinary call, or by the one fetch a 911/933 makes after its POST is answered 401.
inline constexpr int64_t kTokenShortFallbackLifetimeUs = 5LL * 60 * 1000000;

// What decodeJwtLifetimeUs() returns when the payload's decoded bytes do not fit the scratch it was
// lent: it did not look, and tokenLifetimeUs() decides what to do. Not a lifetime (they are positive).
inline constexpr int64_t kLifetimeNoScratch = -1;

// ── base64url decode (no padding required) ───────────────────────────────────
// Decodes a JWT payload segment into dst[0..cap). Accepts the URL alphabet ('-'/'_'), tolerates
// missing '=' padding, and ignores a trailing partial group. Returns false if a non-alphabet byte
// is met or the bytes do not fit in cap. n is how many were written. The caller lends the buffer,
// so nothing here allocates (#951).
inline bool base64UrlDecode(std::string_view in, char* dst, std::size_t cap, std::size_t& n)
{
	auto val = [](char c) -> int {
		if (c >= 'A' && c <= 'Z') return c - 'A';
		if (c >= 'a' && c <= 'z') return c - 'a' + 26;
		if (c >= '0' && c <= '9') return c - '0' + 52;
		if (c == '-' || c == '+') return 62;
		if (c == '_' || c == '/') return 63;
		return -1;
	};

	uint32_t buf = 0;
	int bits = 0;
	n = 0;
	for (char c : in)
	{
		if (c == '=') break; // padding: stop
		int v = val(c);
		if (v < 0) return false; // invalid byte
		buf = (buf << 6) | static_cast<uint32_t>(v);
		bits += 6;
		if (bits >= 8)
		{
			bits -= 8;
			if (n == cap) return false;
			dst[n++] = static_cast<char>((buf >> bits) & 0xFF);
		}
	}
	return true;
}

// Scan a flat JSON object string for a top-level numeric field named `key` and
// write it to `out`. Minimal, allocation-free: finds "\"key\"", skips ':' and
// whitespace, parses an integer (optionally signed). Returns false if the key
// is absent or the value is not numeric. Sufficient for JWT `exp`/`iat` claims,
// which are integer seconds as Telephony issues them. A number it cannot read exactly (a
// fraction, an exponent, 19 or more digits) is refused, not cut or wrapped.
inline bool scanJsonNumber(std::string_view json, std::string_view key, int64_t& out)
{
	const size_t needleLen = key.size() + 2; // "key", quotes included; matched in place, no string built
	size_t pos = 0;
	while ((pos = json.find('"', pos)) != std::string_view::npos)
	{
		if (pos + needleLen > json.size() || json.compare(pos + 1, key.size(), key) != 0 ||
		    json[pos + needleLen - 1] != '"')
		{
			++pos;
			continue;
		}
		size_t i = pos + needleLen;
		// Skip whitespace then a single ':'.
		while (i < json.size() && (json[i] == ' ' || json[i] == '\t')) ++i;
		if (i >= json.size() || json[i] != ':')
		{
			pos += needleLen;
			continue; // a string value that merely contains the key text
		}
		++i;
		while (i < json.size() && (json[i] == ' ' || json[i] == '\t')) ++i;
		if (i >= json.size()) return false;

		bool neg = false;
		if (json[i] == '-') { neg = true; ++i; }
		if (i >= json.size() || json[i] < '0' || json[i] > '9')
		{
			return false; // not a number (e.g. a quoted/boolean value)
		}
		int64_t v = 0;
		int digits = 0;
		while (i < json.size() && json[i] >= '0' && json[i] <= '9')
		{
			if (++digits > 18) return false; // 19 digits can overflow an int64; no JWT time has them
			v = v * 10 + (json[i] - '0');
			++i;
		}
		// A fraction or an exponent is a number this scan cannot read exactly: "1.7e9" must not
		// read as 1, and cutting exp and iat each to whole seconds can overstate the lifetime by up
		// to a second, the unsafe direction. Refused, so decodeJwtLifetimeUs() takes its fallback.
		if (i < json.size() && (json[i] == '.' || json[i] == 'e' || json[i] == 'E')) return false;
		out = neg ? -v : v;
		return true;
	}
	return false;
}

// Decode a JWT's declared lifetime (exp - iat) in microseconds from its payload
// segment. Returns kTokenFallbackLifetimeUs if anything is unparseable. The span
// must be positive and under a day, else the fallback.
//
// The payload is decoded into scratch[0..scratchBytes), lent by the caller: fetchToken() lends the
// arena's unused tail, so this allocates nothing (#951; it was three allocations: the payload, the
// decoded bytes and the JSON text). A payload whose decoded bytes do not fit returns
// kLifetimeNoScratch, not a lifetime: tokenLifetimeUs() decides from there.
inline int64_t decodeJwtLifetimeUs(std::string_view jwt, char* scratch, std::size_t scratchBytes)
{
	const size_t firstDot = jwt.find('.');
	if (firstDot == std::string_view::npos) return kTokenFallbackLifetimeUs;
	const size_t secondDot = jwt.find('.', firstDot + 1);
	if (secondDot == std::string_view::npos) return kTokenFallbackLifetimeUs;

	const std::string_view payload = jwt.substr(firstDot + 1, secondDot - firstDot - 1);
	if (payload.empty()) return kTokenFallbackLifetimeUs;
	if (payload.size() * 3 / 4 > scratchBytes) return kLifetimeNoScratch;

	size_t n = 0;
	if (!base64UrlDecode(payload, scratch, scratchBytes, n) || n == 0)
	{
		return kTokenFallbackLifetimeUs;
	}

	const std::string_view json(scratch, n);
	int64_t exp = 0, iat = 0;
	if (!scanJsonNumber(json, "exp", exp) || !scanJsonNumber(json, "iat", iat))
	{
		return kTokenFallbackLifetimeUs;
	}

	int64_t span = exp - iat; // seconds
	if (span > 0 && span < 86400) // sanity: positive, under a day
	{
		return span * 1000000;
	}
	return kTokenFallbackLifetimeUs;
}

// ── The lifetime a fetched token is installed with (#951) ───────────────────────────────────
// 0 means: do not install this token. Otherwise microseconds.
//  * The payload fits the scratch: decodeJwtLifetimeUs(), exactly as before. expires_in is NOT
//    consulted: Telephony reports expires_in:60 for a token that lives about an hour, so taking
//    the shorter of the two here would turn every token into a one minute one. A payload it cannot
//    parse (no dots, bad base64, no exp or iat, a span out of range) still takes
//    kTokenFallbackLifetimeUs; that is unchanged here and tracked in #975.
//  * The payload does not fit: the shortest of what can still be read, never the 50 minute constant.
//    The response's expires_in (body is the whole response), and exp - iat from the start of the
//    payload, which is decoded as far as the scratch goes and cut back to its last ',' so a number
//    the cut went through is never read. Either alone is used; both give the shorter.
//  * Neither readable: with a token already cached the new one is refused (0) and the cached one
//    stays; with none cached it is installed with kTokenShortFallbackLifetimeUs, so a 911/933 is
//    never left without a token for want of a lifetime. haveCachedToken is only called here.
// Witness lines: one when the payload did not fit, one more for the refusal or the short fallback.
// None names a number or a credential.
template <class HaveCachedToken>
inline int64_t tokenLifetimeUs(std::string_view body, std::string_view jwt, char* scratch, std::size_t scratchBytes,
                               HaveCachedToken&& haveCachedToken)
{
	const int64_t fromPayload = decodeJwtLifetimeUs(jwt, scratch, scratchBytes);
	if (fromPayload != kLifetimeNoScratch) return fromPayload;

	PD_WITNESS_W("anchor", "token_lifetime_scratch_951: the token's payload does not fit the arena's unused bytes, so "
	                       "its lifetime comes from expires_in and the start of the payload (#951)");
	int64_t shortestUs = 0;   // 0: nothing read yet
	auto take = [&shortestUs](int64_t seconds) {
		if (seconds <= 0 || seconds >= 86400) return;   // the span rule decodeJwtLifetimeUs() applies
		const int64_t us = seconds * 1000000;
		if (shortestUs == 0 || us < shortestUs) shortestUs = us;
	};
	int64_t expiresIn = 0;
	if (scanJsonNumber(body, "expires_in", expiresIn)) take(expiresIn);

	// decodeJwtLifetimeUs() only answers kLifetimeNoScratch for a payload with both dots around it
	const size_t firstDot = jwt.find('.');
	const size_t secondDot = jwt.find('.', firstDot + 1);
	const std::string_view payload = jwt.substr(firstDot + 1, secondDot - firstDot - 1);
	size_t n = 0;
	if (base64UrlDecode(payload, scratch, scratchBytes, n) || n == scratchBytes)   // false at the cap: n bytes are its start
	{
		std::string_view head(scratch, n);
		const size_t comma = head.rfind(',');
		if (comma != std::string_view::npos)
		{
			head = head.substr(0, comma + 1);
			int64_t exp = 0, iat = 0;
			if (scanJsonNumber(head, "exp", exp) && scanJsonNumber(head, "iat", iat)) take(exp - iat);
		}
	}
	if (shortestUs != 0) return shortestUs;

	if (haveCachedToken())
	{
		PD_WITNESS_W("anchor", "token_lifetime_unread_951: the token's lifetime cannot be read (payload too big, no expires_in); "
		                       "it is not installed and the cached token stays (#951)");
		return 0;
	}
	PD_WITNESS_W("e911", "token_lifetime_short_951: the token's lifetime cannot be read (payload too big, no expires_in) and "
	                     "no token is cached: installed with the short fallback, so a 911/933 still has a token (#951)");
	return kTokenShortFallbackLifetimeUs;
}

// ── WS entity-path tokenizer ─────────────────────────────────────────────────
// Split a Telephony WS-event entity path on '/', dropping empty segments. The control
// events carry "/callcontrol/{dn}/participants/{id}". Mirrors the inline
// std::getline split in handleWsEvent().
inline std::vector<std::string> splitEntityPath(const std::string& entity)
{
	std::vector<std::string> tokens;
	std::string item;
	for (char c : entity)
	{
		if (c == '/')
		{
			if (!item.empty()) tokens.push_back(item);
			item.clear();
		}
		else
		{
			item.push_back(c);
		}
	}
	if (!item.empty()) tokens.push_back(item);
	return tokens;
}

// Parsed participant entity: a valid /callcontrol/{dn}/participants/{id} path.
struct ParticipantEntity
{
	bool        valid = false;
	std::string dn;
	std::string participantId;
};

// Parse an entity path into {dn, participantId}, valid only for the exact shape
// ["callcontrol", dn, "participants", id]. Anything else → valid=false. This is
// the gate handleWsEvent() applies before acting on an event.
inline ParticipantEntity parseParticipantEntity(const std::string& entity)
{
	ParticipantEntity e;
	std::vector<std::string> t = splitEntityPath(entity);
	if (t.size() == 4 && t[0] == "callcontrol" && t[2] == "participants")
	{
		e.valid         = true;
		e.dn            = t[1];
		e.participantId = t[3];
	}
	return e;
}

// ── Call-control URL builders ────────────────────────────────────────────────
// These mirror the string concatenations scattered through TelephonyAnchorClient
// (makeCall / dropCall / answerCall / reconcile / stream). Centralizing them
// makes the path shape testable and keeps the on-device builders consistent.

inline std::string tokenUrl(const std::string& baseUrl)
{
	return baseUrl + "/connect/token";
}

inline std::string participantsUrl(const std::string& baseUrl, const std::string& dn)
{
	return baseUrl + "/callcontrol/" + dn + "/participants";
}

inline std::string devicesUrl(const std::string& baseUrl, const std::string& dn)
{
	return baseUrl + "/callcontrol/" + dn + "/devices";
}

inline std::string legacyMakeCallUrl(const std::string& baseUrl, const std::string& dn)
{
	return baseUrl + "/callcontrol/" + dn + "/makecall";
}

// Per-participant action endpoint (drop / answer / stream). The action string is
// appended verbatim, e.g. "drop", "answer", "stream".
inline std::string participantActionUrl(const std::string& baseUrl, const std::string& dn,
                                        const std::string& participantId, const std::string& action)
{
	std::string u = baseUrl + "/callcontrol/" + dn + "/participants/" + participantId;
	if (!action.empty()) u += "/" + action;
	return u;
}

// Convert an https://host base URL to the call-control WebSocket URL. Mirrors the
// scheme rewrite in connectWs(): https→wss, http→ws, bare host→wss.
inline std::string controlWsUrl(const std::string& baseUrl)
{
	if (baseUrl.rfind("https://", 0) == 0)
	{
		return "wss://" + baseUrl.substr(8) + "/callcontrol/ws";
	}
	if (baseUrl.rfind("http://", 0) == 0)
	{
		return "ws://" + baseUrl.substr(7) + "/callcontrol/ws";
	}
	return "wss://" + baseUrl + "/callcontrol/ws";
}

// Issue #336: the pure comparison behind TelephonyAnchorClient::tokenExpiringSoon(),
// extracted so the decision that gates BOTH the existing HTTP-side token refresh
// (ensureToken()) and the new WS-side stale-reconnect fix (requestRestartIfTokenStale())
// is host-tested once rather than trusted twice. Mirrors tokenExpiringSoon()'s own
// logic exactly: obtainedUs/lifetimeUs == 0 means "no token yet", which must read as
// expiring (true) so a client that has never fetched one still gets treated as needing
// one, not as having an eternally-valid token.
inline bool tokenIsExpiringSoon(int64_t nowUs, int64_t obtainedUs, int64_t lifetimeUs,
                                 int64_t marginUs)
{
	if (obtainedUs == 0 || lifetimeUs == 0) return true;
	int64_t age = nowUs - obtainedUs;
	return age >= (lifetimeUs - marginUs);
}

// Issues #349/#350: did the transport actually deliver a parsed HTTP response?
//
// This is the distinction both of those bugs turned on, and getting it wrong cost
// a CORRUPT HEAP panic (#350) and a phantom inbound call (#349), so it lives in one
// named place with the reason attached instead of as three bare `status > 0` tests.
//
// THE REASON THE BOUNDARY IS AT ZERO, and not something to "tidy up" later:
// esp_http_client_fetch_headers() assigns client->response->status_code = -1 ITSELF,
// before it reads a single byte (esp_http_client.c:1658, IDF 6.0). If the read then
// fails, the status STAYS -1. So -1 does not mean "the server sent -1" -- it means no
// status line was ever parsed. Zero is the same class of non-answer: it is what a
// caller's own `int status = 0;` still holds when the call bailed before assigning
// (and what httpGetBody/httpPostBody leave if they fail before their own -1 init runs).
//
// Both are UNKNOWN state, which is categorically different from an error the server
// actually sent. A 404, a 424, a 500 -- those are verdicts, and the caller can act on
// them. Treating "no response" as if it were one of those verdicts is precisely what
// reused a transport-dead handle in #350 and declared a live call failed in #349.
inline bool httpResponseParsed(int status)
{
	return status > 0;
}

// Issue #902: a 403 on the media GET stream is an authorisation answer, not a
// readiness one (404/424). Every 403 counts, before the far end answers or after
// it (desmo, 2026-10-09: fail fast before the answer too), consecutively; any other
// answer resets the count. An ordinary outbound leg (makeCall's own, not a 911/933)
// gives up after kGetForbiddenMaxAfterAnswer of them. The GET loop backs off 50, 100,
// 200, 400 ms before the sixth attempt, so the give-up lands about 1.3 s of backoff
// after the first 403, plus six round trips. That is the whole budget for such a leg,
// instead of 240 attempts (~2 min). A 911/933 and an inbound leg (a PSAP callback among them) keep the whole
// budget, as before.
constexpr int kGetForbiddenMaxAfterAnswer = 6;

inline int nextGetForbiddenCount(int count, int status)
{
	return status == 403 ? count + 1 : 0;
}

inline bool getForbiddenGivesUp(int count, bool failFastLeg)
{
	return failFastLeg && count >= kGetForbiddenMaxAfterAnswer;
}

// Issues #379/#681: the participant ids this PBX itself created. On .244 a handset
// CANCELled before 3CX's makecall response named the PBX's own leg; the drop freed
// the leg's call slot, then stalled reconnecting, and an upsert for the leg that
// matched no slot was announced as a new inbound call (#379 issuecomment-5985911668).
//
// Only an id the makecall response named is noted (ownLegMayBeHeld below), when it is
// named and when its outbound slot is freed; never a leg the PBX merely dropped:
// dropCall() also drops refused inbound legs, and a PSAP callback refused while a
// bridge is busy must be announced again on 3CX's next upsert if its drop fails. A
// genuine inbound call, a PSAP callback among them, is a new participant id.
//
// Until 3CX's Remove the id names a live participant of ours. The Remove releases it at
// once: an upsert received after the Remove may be a new call reusing the id, and is
// announced as before. Only work received before the Remove stays ours, told apart by
// the WS event number it was queued with. A Remove of the id received after our
// makecall went out but before its response named the leg is taken as that leg's own,
// and releases it too. A held-back new call could be lost, not merely delayed: a route
// point's first upsert is already Connected, and the client's model is that 3CX does
// not repeat a Connected upsert.
//
// If 3CX reuses participant ids, the rule can misfire both ways. Held: with no Remove
// numbered after the makecall went out (a WS outage lost it, 3CX removed only the far
// leg, or N later Removes pushed it out of the ring before the naming), a reused id is
// held for up to kOwnLegGraceUs after the slot is freed. Released early: an earlier
// participant's Remove of the same id received after our makecall went out, before or
// after the naming, is taken as this leg's own, and the leg is then announced as on
// main, phantom included. The early release is the chosen trade; ids allocated from a
// counter retire both directions.
//
// Without a Remove the hold lapses kOwnLegGraceUs after the last event noted, never
// extended by the upserts it suppresses. It spans the slot being freed to 3CX's Remove
// across a stalled drop: performCtrl() makes two attempts with socket operations of up
// to 2 s each (timeout_ms bounds each operation, not the request) and one cold TLS
// handshake, about 5-7 s; the trace took 1.1 s. Fixed size: a full table overwrites its
// least recently seen entry, and an id that does not fit is not recorded; both forget a
// leg, which errs toward announcing. Not synchronised.
inline constexpr int64_t kOwnLegGraceUs = 10'000'000;

template <std::size_t N, std::size_t Len>
class OwnLegs
{
public:
	// The makecall response named this leg: ours, even if 3CX removed an earlier
	// participant with the same id before the makecall went out (postSeq is the WS event
	// number then). A Remove of the id since then is taken as this leg's own; under id
	// reuse it may be an earlier participant's, which releases the leg early.
	void noteNamed(std::string_view id, int64_t nowUs, uint64_t postSeq)
	{
		uint64_t removedSeq = 0;
		for (const Removed& r : _removed)
		{
			if (id == r.id && r.seq > removedSeq) removedSeq = r.seq;
		}
		if (Entry* e = put(id, nowUs)) e->removedSeq = removedSeq > postSeq ? removedSeq : 0;
	}

	// Held from nowUs (our outbound slot was freed); a Remove already seen stands.
	void note(std::string_view id, int64_t nowUs) { put(id, nowUs); }

	// A later time for a leg still held (its drop has begun); a leg not held is not added.
	bool refresh(std::string_view id, int64_t nowUs)
	{
		const std::size_t i = indexOf(id);
		if (i == N || nowUs - _e[i].seenUs >= kOwnLegGraceUs) return false;
		_e[i].seenUs = nowUs;
		return true;
	}

	// 3CX removed the participant; wsSeq is that event's number. Also remembered for a
	// leg not named yet; the oldest of the last N Removes is overwritten.
	void release(std::string_view id, uint64_t wsSeq)
	{
		const std::size_t i = indexOf(id);
		if (i != N && _e[i].removedSeq == 0) _e[i].removedSeq = wsSeq;
		if (id.empty() || id.size() >= Len) return;
		Removed* oldest = &_removed[0];
		for (Removed& r : _removed)
		{
			if (r.seq < oldest->seq) oldest = &r;
		}
		std::memcpy(oldest->id, id.data(), id.size());
		oldest->id[id.size()] = '\0';
		oldest->seq = wsSeq;
	}

	// Is an upset received as WS event wsSeq still ours?
	bool holds(std::string_view id, int64_t nowUs, uint64_t wsSeq) const
	{
		const std::size_t i = indexOf(id);
		return i != N && nowUs - _e[i].seenUs < kOwnLegGraceUs &&
		       (_e[i].removedSeq == 0 || wsSeq < _e[i].removedSeq);
	}

private:
	struct Entry
	{
		char     id[Len]    = {};
		int64_t  seenUs     = 0;
		uint64_t removedSeq = 0;   // the WS event of 3CX's Remove; 0 = none seen
	};
	struct Removed
	{
		char     id[Len] = {};
		uint64_t seq     = 0;
	};

	std::size_t indexOf(std::string_view id) const   // N when absent
	{
		if (id.empty()) return N;
		for (std::size_t i = 0; i < N; ++i)
		{
			if (id == _e[i].id) return i;
		}
		return N;
	}

	Entry* put(std::string_view id, int64_t nowUs)
	{
		if (id.empty() || id.size() >= Len) return nullptr;
		std::size_t i = indexOf(id);
		if (i == N)
		{
			i = 0;
			for (std::size_t j = 1; j < N; ++j)
			{
				if (age(_e[j]) < age(_e[i])) i = j;
			}
			std::memcpy(_e[i].id, id.data(), id.size());
			_e[i].id[id.size()] = '\0';
			_e[i].removedSeq = 0;
		}
		_e[i].seenUs = nowUs;
		return &_e[i];
	}

	static int64_t age(const Entry& e) { return e.id[0] != '\0' ? e.seenUs : std::numeric_limits<int64_t>::min(); }
	Entry   _e[N]       = {};
	Removed _removed[N] = {};
};

using AnchorOwnLegs = OwnLegs<8, 32>;

// May an upset for partId, received as WS event wsSeq, which no call slot holds as an
// outbound call, be announced as a new inbound call? Every id the table does not hold is
// announced as before.
template <std::size_t N, std::size_t Len>
inline bool inboundAnnounceAllowed(const OwnLegs<N, Len>& own, std::string_view partId, int64_t nowUs,
                                   uint64_t wsSeq)
{
	return !own.holds(partId, nowUs, wsSeq);
}

// Where makeCall() got its own leg's id (resolveOutboundLeg).
enum class OwnLegSource : uint8_t
{
	MakecallResult,      // result.id in the makecall response
	OwnPartyDn,          // the list fallback: the controllable leg whose party_dn is our source DN
	FirstControllable,   // the list fallback: the first controllable leg with no slot
	AdoptedAfterUnreadResponse,   // #349: a list pick after the makecall response went unread
};

// Only the makecall response's own id is held. A list-fallback pick can be a genuine
// inbound leg that rang while the makecall was pending (it gets no slot then), and
// nothing here defines party_dn, so such a leg is treated as on main.
//
// #349's adopted leg is held: it is bound to the outbound call, so once its slot is
// freed 3CX's upserts before the Remove would ring the route DN (the .244 phantom).
// If the pick was in fact an inbound leg, that call was already taken as ours.
inline bool ownLegMayBeHeld(OwnLegSource s)
{
	return s == OwnLegSource::MakecallResult || s == OwnLegSource::AdoptedAfterUnreadResponse;
}

// #349: makeCall()'s POST reached 3CX and no response was read, so 3CX may have placed
// the call. On .244 it had (it named the leg in the response the probe threw away), and
// one list read showing no leg was taken as "no call": a 503, while 3CX's leg rang the
// far end, was answered and came back as a phantom inbound. So the list is read every
// kUnreadAdoptPollMs until it shows a leg, whatever an earlier read answered, and no
// read starts kUnreadAdoptWindowUs or later after the first. The window is bounded
// because while it is open an unmatched upsert is ignored (#888). sinceFirstReadUs is
// the time from the start of the first read to the end of the latest.
// A 911/933 gets the same decision: adopted at the first read that shows its leg.
inline constexpr int64_t kUnreadAdoptWindowUs = 4'000'000;
inline constexpr int     kUnreadAdoptPollMs   = 400;

enum class UnreadMakecallStep : uint8_t { Adopt, ReadAgain, GiveUp };

inline UnreadMakecallStep unreadMakecallStep(bool legListed, int64_t sinceFirstReadUs)
{
	if (legListed) return UnreadMakecallStep::Adopt;
	if (sinceFirstReadUs + int64_t{kUnreadAdoptPollMs} * 1000 < kUnreadAdoptWindowUs) return UnreadMakecallStep::ReadAgain;
	return UnreadMakecallStep::GiveUp;
}

// #349 (#903 review): resolveOutboundLeg()'s verdict on one entry of the live list.
// The pick rule is unchanged (direct_control true, an id, no slot: audit #76, #100).
// The adopt reads also pass oursAlready for a leg the PBX dropped or still holds
// from an earlier call (_droppedLegs, _ownLegs): 3CX lists it until its Remove, and
// it is never the new call's leg. An unrelated inbound leg that appears in the window
// still qualifies; nothing in the list tells it apart.
enum class DirectControlField : uint8_t { True, False, Absent, NotBool };
enum class ListLegVerdict : uint8_t { NotControllable, NoId, Claimed, OursAlready, Candidate };

inline ListLegVerdict classifyListLeg(DirectControlField dc, bool hasId, bool slotClaimed, bool oursAlready)
{
	if (dc != DirectControlField::True) return ListLegVerdict::NotControllable;
	if (!hasId) return ListLegVerdict::NoId;
	if (slotClaimed) return ListLegVerdict::Claimed;
	if (oursAlready) return ListLegVerdict::OursAlready;
	return ListLegVerdict::Candidate;
}

// What one list read held, for the no-leg and adopt log lines: a direct_control
// reject (by how the field looked) is told apart from a slot claim or an old leg.
struct ListLegCounts
{
	int listed = 0;         // participant objects
	int controllable = 0;   // direct_control true
	int noId = 0;
	int claimed = 0;
	int oursAlready = 0;
	int candidates = 0;
	int dcFalse = 0;
	int dcAbsent = 0;
	int dcNotBool = 0;

	void add(DirectControlField dc, ListLegVerdict v)
	{
		++listed;
		switch (dc)
		{
			case DirectControlField::True:    ++controllable; break;
			case DirectControlField::False:   ++dcFalse; break;
			case DirectControlField::Absent:  ++dcAbsent; break;
			case DirectControlField::NotBool: ++dcNotBool; break;
		}
		switch (v)
		{
			case ListLegVerdict::NoId:            ++noId; break;
			case ListLegVerdict::Claimed:         ++claimed; break;
			case ListLegVerdict::OursAlready:     ++oursAlready; break;
			case ListLegVerdict::Candidate:       ++candidates; break;
			case ListLegVerdict::NotControllable: break;
		}
	}
};

// ── Fixed-storage buffers for the ESP arm (#862) ────────────────────────────────
// The teardown snapshot (IdSnapshot) and the token-body arena (BodyArena) exist so the ESP
// arm allocates nothing for them in the common case. Their logic is testable here.

// Participant ids up to this many bytes are copied inline by IdSnapshot. Participant
// ids are short (AnchorOwnLegs uses the same 32 for the same reason). Not checked
// against a live 3CX capture; a longer id still works, it just takes the heap.
inline constexpr std::size_t kParticipantIdBytes = 32;

// Participant ids copied out of the call slots under _mutex, to be stopped after it is
// released (stopMediaStreams() takes _mutex itself). Holds up to N ids (N is the call-slot
// count, so add() cannot run out). An id of Len bytes or fewer is copied inline, which
// is the common case and allocates nothing. A longer one goes into a std::string, which
// allocates only for that id. No id is dropped, because a dropped id would leave its call
// running.
template <std::size_t N, std::size_t Len>
class IdSnapshot
{
public:
	void add(std::string_view id)
	{
		if (_n == N) return;   // unreachable: callers add at most one id per slot
		Entry& e = _e[_n++];
		e.len = id.size();
		if (id.size() <= Len)
		{
			std::memcpy(e.buf, id.data(), id.size());
		}
		else
		{
			e.big.assign(id.data(), id.size());
		}
	}

	std::size_t size() const { return _n; }

	// Valid while the snapshot lives. It does not move, so the view stays valid.
	std::string_view at(std::size_t i) const
	{
		const Entry& e = _e[i];
		return e.len <= Len ? std::string_view(e.buf, e.len) : std::string_view(e.big);
	}

private:
	struct Entry
	{
		char        buf[Len] = {};
		std::size_t len      = 0;
		std::string big;
	};
	Entry       _e[N];
	std::size_t _n = 0;
};

// ── The token body: bounded arenas and a bounded scanner (#862) ─────────────────
// The OAuth token response is read into an arena that is reserved with the client and never
// grows: no std::vector per read and no spill to the heap. That was the body read only (#945).
// #951 slice 1 puts the rest of fetchToken's own buffers in the same claim (the request, the
// lifetime decode's scratch, the WebSocket header) and keeps the cached token in a string reserved
// once; what stays is esp_http_client_init and TLS, which are ESP-IDF's. The contract is the one
// recorded on #948 for the 911/933 lane:
//   * Fits or fails. A body that does not fit is an error (ArenaFull), never a prefix, and a
//     failed read (an error, a timeout, a stream that stops short) is an error too. After any
//     error the arena shows no bytes at all, and the caller keeps the token it already has.
//   * Nobody waits. An arena is claimed with an atomic flag, not a mutex: a second caller of
//     the same arena is turned away at once with an empty lease, and the holder is never
//     blocked or slowed by it. No lock is held across the socket read.
//   * It is bounded in time as well as in size: the whole body must arrive inside a budget.

// The arena holds a body of exactly this many bytes and refuses one byte more. The size is an
// estimate, not a measurement: a 3CX token is a JWT (an RS256 signature is 342 base64url
// characters, an RS4096 one is 683) plus its claims, so a response should be on the order of
// 1-2 KB. 4 KB leaves margin, because without a spill a body that does not fit is a token that
// is never fetched. The ESP arm logs a refusal, so a real unit can confirm the size.
inline constexpr std::size_t kTokenBodyBytes = 4096;

// The whole body must arrive inside this budget. Each socket read already has its own timeout
// (2 s, makeAuthedClient), but a server that sends one byte per read never trips it; this
// bounds the sum. The budget is looked at between read() calls, and a read() is one byte
// (kTokenReadSliceBytes), so the worst case is the budget plus the one transport read in progress
// (plus the framing reads of a chunked body's size line, which ride along inside the same call).
// It covers the body only: the connect and the response headers come before it, and the 911/933
// lane bounds them with kSosTokenBudgetUs.
inline constexpr std::int64_t kTokenBodyBudgetUs = 3LL * 1000 * 1000;

// The most bytes collect() asks one read() for. esp_http_client_read() (ESP-IDF v6.0.1) does not
// return until it has stored that many or the body ends: it loops esp_transport_read(), each with
// the client's timeout. Room for the whole arena would let a server that drips the body hold ONE
// call as long as it likes, and the budget would never be looked at. One byte means one
// transport read per call, so the clock is checked every time.
inline constexpr std::size_t kTokenReadSliceBytes = 1;

// What esp_http_client_read() returns when its read times out before any data arrived:
// -ESP_ERR_HTTP_EAGAIN, -0x7007 in ESP-IDF v6.0.1 (esp_http_client.h). The ESP arm static_asserts it.
inline constexpr int kHttpReadTimedOut = -0x7007;

// What esp_http_client_read() answered, in collect()'s terms. n > 0: bytes stored. 0 ends the
// body only if the response says it is whole (bodyComplete, esp_http_client_is_complete_data_received):
// cut short, e.g. the connection closed early, it is an error, never a shorter token. The timeout
// code passes through; every other negative (ESP_FAIL is -1, or a transport error) is an error.
inline int httpReadResult(int n, bool bodyComplete)
{
	if (n > 0) return n;
	if (n == 0) return bodyComplete ? 0 : -1;
	return n == kHttpReadTimedOut ? kHttpReadTimedOut : -1;
}

// The most bytes an access_token may have and still be cached (#951). The cached copy is
// "Bearer " + token in a string reserved once (BearerHeader::reserve), and the WebSocket's
// "Authorization: Bearer <token>\r\n" is rebuilt in the lane's arena (wsAuthHeaderInPlace), so the
// limit is what that line leaves of the arena. A bigger token is refused, never cut. The arena
// could hold a token of 4077 bytes (it is 4096 less {"access_token":""}); this refuses only
// 4073 and more, where a Telephony JWT is expected to be 1-2 KB (kTokenBodyBytes).
inline constexpr char kWsAuthPrefix[] = "Authorization: Bearer ";
inline constexpr std::size_t kWsAuthPrefixBytes = sizeof(kWsAuthPrefix) - 1;
inline constexpr std::size_t kWsAuthSuffixBytes = 3; // "\r\n" and the NUL
inline constexpr std::size_t kMaxTokenBytes = kTokenBodyBytes + 1 - kWsAuthPrefixBytes - kWsAuthSuffixBytes;
inline constexpr char kBearerPrefix[] = "Bearer ";
inline constexpr std::size_t kBearerPrefixBytes = sizeof(kBearerPrefix) - 1;
inline constexpr std::size_t kBearerHeaderBytes = kBearerPrefixBytes + kMaxTokenBytes;

// Whether an access_token from the token response is worth installing (#862). It has to be
// non-empty, no longer than kMaxTokenBytes (#951) and have the two dots of a JWT's three segments,
// which is what decodeJwtLifetimeUs() and Telephony's tokens assume. Anything else is not installed
// and the caller keeps the token it has: an empty or garbled one would replace a working token with
// one every request answers 401, and a cut one is the same.
enum class TokenCheck : std::uint8_t { Ok, Empty, NotAJwt, TooBig };

inline TokenCheck checkToken(std::string_view token)
{
	if (token.empty()) return TokenCheck::Empty;
	if (token.size() > kMaxTokenBytes) return TokenCheck::TooBig;
	const std::size_t first = token.find('.');
	if (first == std::string_view::npos || token.find('.', first + 1) == std::string_view::npos)
	{
		return TokenCheck::NotAJwt;
	}
	return TokenCheck::Ok;
}

inline const char* tokenCheckName(TokenCheck c)
{
	switch (c)
	{
		case TokenCheck::Ok: return "ok";
		case TokenCheck::Empty: return "empty";
		case TokenCheck::NotAJwt: return "not a JWT (no two dots)";
		case TokenCheck::TooBig: return "too big for the token cache";
	}
	return "?";
}

// The token request, built where the response will be read (#951). fetchToken() builds it in the
// claimed lane's arena before any I/O: the arena is empty until the body is read into it, the
// claim is the lane's alone, and release() wipes it, the client secret with it. So the URL, the
// form body and the percent-encoding take no heap and no stack. The response overwrites the
// request later, by which time the client has copied the URL and the body has been written.
struct TokenRequest
{
	const char* url = nullptr;  // NUL-terminated, inside buf
	const char* body = nullptr; // bodyLen bytes, inside buf
	std::size_t bodyLen = 0;
};

// baseUrl + "/connect/token" (the same as tokenUrl()), then the form body with both credentials
// percent-encoded (a carrier secret commonly holds '+', '/' and '=', which corrupt an unencoded
// x-www-form-urlencoded body). False when buf (cap bytes) cannot hold all of it: nothing is cut.
inline bool buildTokenRequest(char* buf, std::size_t cap, std::string_view baseUrl, std::string_view clientId,
                              std::string_view clientSecret, TokenRequest& out)
{
	std::size_t n = 0;
	auto put = [&](std::string_view s) {
		if (cap - n < s.size()) return false;
		if (!s.empty()) std::memcpy(buf + n, s.data(), s.size());
		n += s.size();
		return true;
	};
	if (!put(baseUrl) || !put("/connect/token") || !put(std::string_view("", 1))) return false;
	const std::size_t bodyAt = n;
	if (!put("grant_type=client_credentials&client_id=") || !urlEncodeInto(clientId, buf, cap, n) ||
	    !put("&client_secret=") || !urlEncodeInto(clientSecret, buf, cap, n))
	{
		return false;
	}
	out.url = buf;
	out.body = buf + bodyAt;
	out.bodyLen = n - bodyAt;
	return true;
}

// The cached "Bearer <token>" (TelephonyAnchorClient::_bearerHeader, under _mutex). init() reserves
// it once for the longest token checkToken() lets through, so set() assigns inside its capacity and
// never reallocates under the lock. Nothing is cut: a longer token is refused by checkToken() before
// it gets here. Its storage is PSRAM where the board has it (PsramAllocator: internal DRAM on a
// board without, or when PSRAM is exhausted, counted in psram::internalFallbacks()), 4 KB that
// would otherwise sit in the scarce internal heap. Only anchor tasks touch it, and none writes
// flash (the allocator's rule), and the readers copy it under _mutex: a string copy, not a hot path.
// The readers are unchanged: `std::string s = _bearerHeader;` converts through operator std::string.
class BearerHeader
{
public:
	using Storage = std::basic_string<char, std::char_traits<char>, PsramAllocator<char>>;

	void reserve() { _s.reserve(kBearerHeaderBytes); }
	void set(std::string_view token)
	{
		_s.assign(kBearerPrefix, kBearerPrefixBytes);
		_s.append(token.data(), token.size());
	}
	bool        empty() const { return _s.empty(); }
	std::size_t capacity() const { return _s.capacity(); }
	operator std::string() const { return std::string(_s.data(), _s.size()); }   // NOLINT: the readers' one copy-out

private:
	Storage _s;
};

// Rewrites buf[0..cap) in place into "Authorization: Bearer <token>\r\n" plus a NUL and returns it,
// or nullptr when that does not fit. `token` is a view into buf (the arena holding the response),
// which is moved right to make room for the prefix. The caller no longer needs the response by now.
inline const char* wsAuthHeaderInPlace(char* buf, std::size_t cap, std::string_view token)
{
	if (token.size() > cap || cap - token.size() < kWsAuthPrefixBytes + kWsAuthSuffixBytes) return nullptr;
	std::memmove(buf + kWsAuthPrefixBytes, token.data(), token.size());
	std::memcpy(buf, kWsAuthPrefix, kWsAuthPrefixBytes);
	buf[kWsAuthPrefixBytes + token.size()] = '\r';
	buf[kWsAuthPrefixBytes + token.size() + 1] = '\n';
	buf[kWsAuthPrefixBytes + token.size() + 2] = '\0';
	return buf;
}

enum class BodyStatus : std::uint8_t { Ok, ArenaFull, ReadError, Timeout };

inline const char* bodyStatusName(BodyStatus s)
{
	switch (s)
	{
		case BodyStatus::Ok:        return "ok";
		case BodyStatus::ArenaFull: return "body larger than the arena";
		case BodyStatus::ReadError: return "read error";
		case BodyStatus::Timeout:   return "timeout";
	}
	return "?";
}

template <std::size_t N>
class BodyArena
{
public:
	// Ownership of the arena. Empty (false) when the claim was refused. Releases on every exit,
	// so no return path can leave the arena claimed.
	class Lease
	{
	public:
		Lease() = default;
		Lease(Lease&& o) noexcept : _a(o._a) { o._a = nullptr; }
		Lease& operator=(Lease&& o) noexcept
		{
			if (this != &o)
			{
				release();
				_a = o._a;
				o._a = nullptr;
			}
			return *this;
		}
		Lease(const Lease&) = delete;
		Lease& operator=(const Lease&) = delete;
		~Lease() { release(); }

		explicit operator bool() const { return _a != nullptr; }

		// Read the body. read(char* dst, std::size_t room) answers like esp_http_client_read():
		// n > 0 bytes stored, 0 at the end of the body, kHttpReadTimedOut on a timeout, any
		// other negative on an error; room is never 0. nowUs() is a monotonic clock in
		// microseconds. Ok means the whole body is in data()/size(). Anything else leaves
		// size() at 0.
		template <class Read, class Now>
		BodyStatus collect(Read&& read, Now&& nowUs, std::int64_t budgetUs)
		{
			BodyArena& a = *_a;
			a._used = 0;
			const std::int64_t deadline = nowUs() + budgetUs;
			for (;;)
			{
				// One slot past N is how an oversize body is seen. It is never kept: asking for
				// 0 bytes instead would read as "end of body" and hand back a truncated one.
				// And never more than a slice (kTokenReadSliceBytes), so one read() cannot hold
				// the socket past the budget.
				const std::size_t room = N + 1 - a._used;
				const int n = read(a._buf + a._used, room < kTokenReadSliceBytes ? room : kTokenReadSliceBytes);
				if (n == 0) return BodyStatus::Ok;
				if (n < 0) return fail(n == kHttpReadTimedOut ? BodyStatus::Timeout : BodyStatus::ReadError);
				a._used += static_cast<std::size_t>(n);
				if (a._used > N) return fail(BodyStatus::ArenaFull);
				if (nowUs() >= deadline) return fail(BodyStatus::Timeout);
			}
		}

		char*       data() { return _a->_buf; }
		std::size_t size() const { return _a->_used; }

		// The claim holder's workspace (#951). data() is the whole arena, capacity() its size.
		// spare() is what the body does not use: all of it before the read, the tail behind the
		// body after. Neither moves size(), so a request built before the read is not a body, and
		// release() wipes whatever was put there.
		static constexpr std::size_t capacity() { return N + 1; }
		char*       spare() { return _a->_buf + _a->_used; }
		std::size_t spareBytes() const { return N + 1 - _a->_used; }

	private:
		friend BodyArena;
		explicit Lease(BodyArena* a) : _a(a) {}

		BodyStatus fail(BodyStatus s)
		{
			_a->_used = 0;
			return s;
		}
		void release()
		{
			if (!_a) return;
			_a->_used = 0;
			// Cleared on every release, so a token (or the start of a body that then failed) does
			// not stay in the reserved arena until the next fetch overwrites it. Before _busy
			// is released, so the next claimant starts on zeros.
			std::memset(_a->_buf, 0, N + 1);
			_a->_busy.store(false, std::memory_order_release);
			_a = nullptr;
		}

		BodyArena* _a = nullptr;
	};

	// Never waits: a second caller gets an empty lease and carries on with what it has.
	Lease tryClaim()
	{
		return _busy.exchange(true, std::memory_order_acquire) ? Lease() : Lease(this);
	}

	// Whether a lease is out. A read, not a claim: it can be stale by the time it is used.
	bool busy() const { return _busy.load(std::memory_order_acquire); }

private:
	std::atomic<bool> _busy{false};
	std::size_t       _used = 0;
	char              _buf[N + 1] = {};
};

// ── The token's three lanes: a 911/933 and the background refresh each have an arena of their own (#862, Rule 5) ──
// Telephony drops the old token the moment a new one is granted, so two fetches on the same
// lane must not run together: the second is turned away and keeps the token it has. The
// emergency lane is a lane of its own for another reason. A 911/933 must not wait on an
// ordinary fetch (a refresh ahead of a normal call, or start()) and must not be turned away
// by one, so it has its own arena and its own claim, and an ordinary fetch is never handed it.
// The emergency lane does not wait for its own arena either: if another 911/933 holds it, the
// caller carries on at once with the token it has. Nothing here refuses a call.
//
// The maintenance lane is the background refresh (maintRefreshDecision, run on tel_maint). It has an
// arena of its own so that it takes neither of the others: it can never hold up a 911/933 or an
// ordinary fetch by holding their arena, and it never waits for its own, for it is gated to one
// at a time and a claim it loses is a skipped tick.
//
// All three lanes can have a fetch in flight together. Telephony then grants the tokens and drops
// the older ones, and the cache keeps the token whose request was issued last (TokenInstallGate,
// ruling 2 on #945), whichever fetch finishes last.
//
// Cost: three arenas, kTokenBodyBytes + 1 bytes of buffer each, reserved with the client: about
// 12.3 KB on the 32-bit ESP32. That is the object size, not a heap measurement.
enum class TokenLane : std::uint8_t { Ordinary, Emergency, Maintenance };

inline const char* laneName(TokenLane lane)
{
	switch (lane)
	{
		case TokenLane::Ordinary:    return "ordinary";
		case TokenLane::Emergency:   return "911/933";
		case TokenLane::Maintenance: return "maintenance";
	}
	return "?";
}

// The sampled witnesses (token_sos_fallback_862, token_install_older_862, token_maint_skip_862) log
// the first of a boot and then every this-many-th, so a run of them cannot flood the log.
inline constexpr std::uint32_t kWitnessSampleEvery = 16;

// ── The background refresh keeps a token ten minutes from its expiry (#862, #945) ───────────
// tick() wakes a job on tel_maint when the token is due (maintRefreshWakeDue, atomics only); the job
// decides again with every input read at that moment (maintRefreshDecision) and only then fetches,
// on the maintenance lane. Due means the token's age has reached its lifetime minus this margin.
// The ordinary refresh ahead of a call keeps its own, smaller margin (5 minutes, tokenExpiringSoon).
inline constexpr std::int64_t kMaintRefreshMarginUs = 10LL * 60 * 1000000;

// The least time between two wakes of the job. A token that stays due because its fetch failed, or
// because a call keeps it from being refreshed, would otherwise wake the job on every tick, and a
// fetch is a TLS handshake the S3 does in software (about a second of CPU, at a time a 911/933 may
// need it). The same floor as the reconcile watchdog's (#94), longer: this one is not urgent.
inline constexpr std::int64_t kMaintRefreshRetryUs = 60LL * 1000000;

enum class MaintRefreshReason : std::uint8_t { Due, NotDue, NoToken, EmergencyPending, StreamsLive, FetchInFlight };

inline const char* maintRefreshReasonName(MaintRefreshReason r)
{
	switch (r)
	{
		case MaintRefreshReason::Due:              return "due";
		case MaintRefreshReason::NotDue:           return "not due";
		case MaintRefreshReason::NoToken:          return "no token";
		case MaintRefreshReason::EmergencyPending: return "a 911/933 is pending";
		case MaintRefreshReason::StreamsLive:      return "media streams are live";
		case MaintRefreshReason::FetchInFlight:    return "a token fetch is in flight";
	}
	return "?";
}

struct MaintRefreshDecision
{
	bool               refresh;
	MaintRefreshReason reason;   // Due iff refresh
};

// Age (nowUs - obtainedUs) has reached lifetimeUs - kMaintRefreshMarginUs. A token that lives no
// longer than the margin is never due: the test would hold at every age, the refresh would run again
// the moment it finished, and no refresh could keep such a token ten minutes from expiry anyway
// (the ordinary refresh ahead of a call still renews it). obtainedUs == 0 is no token.
inline bool maintTokenDue(std::int64_t nowUs, std::int64_t obtainedUs, std::int64_t lifetimeUs)
{
	if (obtainedUs == 0 || lifetimeUs <= kMaintRefreshMarginUs) return false;
	return nowUs - obtainedUs >= lifetimeUs - kMaintRefreshMarginUs;
}

// tick()'s test, on the SIP task under RequestsHandler's lock: due, and not tried within the floor.
// lastWakeUs == 0: never woken.
inline bool maintRefreshWakeDue(std::int64_t nowUs, std::int64_t obtainedUs, std::int64_t lifetimeUs,
                                std::int64_t lastWakeUs)
{
	if (!maintTokenDue(nowUs, obtainedUs, lifetimeUs)) return false;
	return lastWakeUs == 0 || nowUs - lastWakeUs >= kMaintRefreshRetryUs;
}

// Whether to refresh now. Everything but the clock is a fact the caller read: the token's stamp
// (obtainedUs == 0 or lifetimeUs == 0: none) and lifetime; streamsLive (a slot with postLive, or an
// open GET handle: a new grant revokes the old token and the live streams hold it); emergencyPending
// (a 911/933 makeCall() is pending, or a slot holds a live 911/933: Rule 5, it keeps the token it
// has); fetchInFlight (any lane's arena is claimed). A token that is not due is not due whatever is
// going on, so a long call leaves no skip line for a refresh nobody wanted. Past that the reason
// is the first of: a 911/933, streams, another fetch.
inline MaintRefreshDecision maintRefreshDecision(std::int64_t nowUs, std::int64_t obtainedUs, std::int64_t lifetimeUs,
                                                 bool streamsLive, bool emergencyPending, bool fetchInFlight)
{
	using R = MaintRefreshReason;
	if (obtainedUs == 0 || lifetimeUs == 0) return {false, R::NoToken};
	if (!maintTokenDue(nowUs, obtainedUs, lifetimeUs)) return {false, R::NotDue};
	if (emergencyPending) return {false, R::EmergencyPending};
	if (streamsLive) return {false, R::StreamsLive};
	if (fetchInFlight) return {false, R::FetchInFlight};
	return {true, R::Due};
}

class TokenLanes
{
public:
	using Arena = BodyArena<kTokenBodyBytes>;
	using Lease = Arena::Lease;

	// Never waits. An Ordinary caller cannot be handed the emergency arena.
	Lease claim(TokenLane lane) { return arena(lane).tryClaim(); }

	// claim(), then, for the Ordinary lane only, up to `polls` more tries `pollMs` apart (start():
	// off the 911 lane, and a restart that lost the claim would leave the anchor down). The
	// Emergency lane makes the one try and never calls sleepMs. A refused Emergency claim is one
	// witness line naming the 911/933 that lost (sosCallId, EmergencyScope::id()) and why: another
	// 911/933's fetch holds the arena, so the loser is refused at once, waits for nothing and goes on
	// with the best token it has (operator ruling 4 on #945, revised). The Maintenance lane never
	// waits either: a refused claim is a skipped refresh, and one token_maint_skip_862 line says so.
	template <class Sleep>
	Lease claimWaiting(TokenLane lane, int polls, std::uint32_t pollMs, Sleep&& sleepMs, std::uint32_t sosCallId = 0)
	{
		Lease lease = claim(lane);
		for (int i = 0; lane == TokenLane::Ordinary && !lease && i < polls; ++i)
		{
			sleepMs(pollMs);
			lease = claim(lane);
		}
		if (!lease && lane == TokenLane::Emergency)
		{
			PD_WITNESS_W("e911", "token_sos_claim_lost_862: 911/933 call %u lost the 911/933 token arena claim: another 911/933 "
			                     "token fetch holds the arena, so it is refused at once and goes on with the best token it has "
			                     "(maybe none); a failed POST takes the 401 step, then NOT ROUTED (#880) (#862)",
			             static_cast<unsigned>(sosCallId));
		}
		if (!lease && lane == TokenLane::Maintenance) noteMaintSkip(MaintRefreshReason::FetchInFlight);
		return lease;
	}

	// A 911/933 is about to POST on the token it has. If that token is stale (near or past expiry,
	// or none: tokenStale), no fresh one was in hand and the call goes out regardless; this only
	// leaves a witness, sampled so a run of them cannot flood the log: the first of a boot, then
	// every kWitnessSampleEvery-th. It returns nothing, so nothing can refuse a call on it.
	void noteSosDial(bool tokenStale)
	{
		if (!tokenStale) return;
		if (_sosFallbacks.fetch_add(1, std::memory_order_relaxed) % kWitnessSampleEvery != 0) return;
		PD_WITNESS_W("e911", "token_sos_fallback_862: a 911/933 goes out on the token it has, near or past expiry or none, "
		                     "no fresh one (#862)");
	}

	// Held for the whole of a 911/933 makeCall(): its token step, its POST and a 401 retry. A refresh
	// grants a new token and Telephony drops the old one at that instant, so one that lands between
	// the 911/933 reading its token and its POST (or its retry) revokes the token the POST carries.
	// While one of these is held an ordinary refresh does not start (ordinaryRefreshMayStart): the
	// 911/933 keeps the token it has and the refresh waits for a later call. Rule 5's safe default.
	// Not covered: an ordinary fetch already in flight when the 911/933 arrives lands when it lands,
	// and the 911/933's own fetches are never held back.
	class EmergencyScope
	{
	public:
		EmergencyScope(TokenLanes& lanes, bool active) : _lanes(active ? &lanes : nullptr)
		{
			if (!_lanes) return;
			_lanes->_emergenciesPending.fetch_add(1, std::memory_order_acq_rel);
			_id = _lanes->_sosCalls.fetch_add(1, std::memory_order_relaxed) + 1;
		}
		~EmergencyScope()
		{
			if (_lanes) _lanes->_emergenciesPending.fetch_sub(1, std::memory_order_acq_rel);
		}
		EmergencyScope(const EmergencyScope&) = delete;
		EmergencyScope& operator=(const EmergencyScope&) = delete;

		// This 911/933's number among those since boot (1, 2, ...); 0 for an ordinary call's scope.
		// The witnesses name a call by it: makeCall() is not given the SIP Call-ID, and passing it
		// through AnchorClient::makeCall() would touch every implementation.
		std::uint32_t id() const { return _id; }

	private:
		TokenLanes*   _lanes;
		std::uint32_t _id = 0;
	};

	// False while a 911/933 makeCall() is pending, for a refresh ahead of an ordinary call. start()
	// (startup) is not a refresh ahead of a call and is never held: the anchor must come up.
	bool ordinaryRefreshMayStart(bool startup) const
	{
		return startup || _emergenciesPending.load(std::memory_order_acquire) == 0;
	}

	// A fetch holds an arena on some lane. A read: it can be stale by the time it is used, which is why
	// fetchToken() still claims and re-checks before any I/O.
	bool fetchInFlight() const { return _ordinary.busy() || _emergency.busy() || _maintenance.busy(); }

	// The background refresh asks this, on tel_maint, with the facts it has just read (see
	// maintRefreshDecision). sosSlotUp: a call slot holds a live 911/933 (CallSlot::emergency). The
	// 911/933 makeCall() in progress is read here, from the same count ordinaryRefreshMayStart() reads.
	// True: fetch now, on the Maintenance lane. False: skip this tick, and leave one
	// token_maint_skip_862 line (sampled) saying why. Reads only; it changes no state a 911/933 reads.
	bool maintRefreshWanted(std::int64_t nowUs, std::int64_t obtainedUs, std::int64_t lifetimeUs, bool streamsLive,
	                        bool sosSlotUp)
	{
		const bool emergencyPending = sosSlotUp || _emergenciesPending.load(std::memory_order_acquire) != 0;
		const MaintRefreshDecision d =
		    maintRefreshDecision(nowUs, obtainedUs, lifetimeUs, streamsLive, emergencyPending, fetchInFlight());
		if (!d.refresh) noteMaintSkip(d.reason);
		return d.refresh;
	}

	// A refresh whose request is about to be issued: one line per refresh, never sampled, with the
	// age in seconds of the token it replaces. A duration, not an identifier: nothing in it names a
	// token, a number or a credential.
	void noteMaintRefresh(std::int64_t ageUs)
	{
		PD_WITNESS_W("anchor", "token_maint_refresh_862: the background refresh fetches a new token, the one it replaces is "
		                       "%lld s old (#862)",
		             static_cast<long long>(ageUs / 1000000));
	}

	// A refresh that did not start, and why. Sampled, so a call that outlasts the due time cannot
	// flood the log: the first of a boot, then every kWitnessSampleEvery-th.
	void noteMaintSkip(MaintRefreshReason why)
	{
		if (_maintSkips.fetch_add(1, std::memory_order_relaxed) % kWitnessSampleEvery != 0) return;
		PD_WITNESS_W("anchor", "token_maint_skip_862: the background token refresh is skipped: %s (#862)",
		             maintRefreshReasonName(why));
	}

	// A fetch that was started and did not end in a token it could use: the request did not fit, the
	// client was not made, the connect, the write or the status failed, the body did not read or the
	// token was refused (checkToken). One line each, never sampled: a fetch is a TLS handshake, so
	// they come no faster than that. The token already cached is kept; the reason is in the error
	// line before this one. It names the lane and nothing else: no number, no credential.
	void noteFetchFailed(TokenLane lane)
	{
		PD_WITNESS_W("anchor",
		             "token_fetch_failed_951: the %s lane's token fetch failed, the token already cached is kept (#951)",
		             laneName(lane));
	}

private:
	Arena& arena(TokenLane lane)
	{
		switch (lane)
		{
			case TokenLane::Emergency:   return _emergency;
			case TokenLane::Maintenance: return _maintenance;
			case TokenLane::Ordinary:    break;
		}
		return _ordinary;
	}

	Arena                      _ordinary;
	Arena                      _emergency;
	Arena                      _maintenance;
	std::atomic<std::uint32_t> _sosFallbacks{0};
	std::atomic<int>           _emergenciesPending{0};
	std::atomic<std::uint32_t> _sosCalls{0};
	std::atomic<std::uint32_t> _maintSkips{0};
};

// ── The cache keeps the token whose request was issued last (#862, ruling 2 on #945) ───────
// The lanes can have fetches in flight together, Telephony drops the older token the moment it
// grants a newer one, and they finish in any order. So a response is installed only if its
// request was ISSUED later than the installed token's request, not by when it finished: an older
// response is discarded and the token it would have replaced stays. The stamp is the time the
// request was issued, kept with the installed token. fetchToken() calls installIfNewer() under
// the lock that guards the cached token, noteDiscarded() after releasing it, and a discard returns
// success: a token issued later is in hand, which is what its caller (a 911/933's 401 retry, say) needed.
//
// Residual, by the ruling's own definition: Telephony grants in the order it handles the requests,
// which need not be the order they were issued in, so the token kept can be the one it dropped.
class TokenInstallGate
{
public:
	// True: the response's request was issued after the installed token's (or nothing is installed
	// yet, so even boot time 0 installs), and this is now the installed one's stamp. False: it was
	// issued before, or at the same instant; the caller keeps what it has. Not synchronised.
	bool installIfNewer(std::int64_t issuedUs)
	{
		if (issuedUs <= _installedIssuedUs) return false;
		_installedIssuedUs = issuedUs;
		return true;
	}

	// A discard's witness, sampled: the first of a boot, then every kWitnessSampleEvery-th. It names
	// the lane and carries no token.
	void noteDiscarded(TokenLane lane)
	{
		if (_discards.fetch_add(1, std::memory_order_relaxed) % kWitnessSampleEvery != 0) return;
		PD_WITNESS_W("e911", "token_install_older_862: a token response from the %s lane was discarded, its request was issued "
		                     "before the installed token's; the newer token stays (#862)",
		             laneName(lane));
	}

private:
	std::int64_t               _installedIssuedUs = std::numeric_limits<std::int64_t>::min();
	std::atomic<std::uint32_t> _discards{0};
};

// What a 911/933 does about its token before its POST (#862, operator ruling on #945). With any
// token cached, even one past expiry, it POSTs at once: it does not fetch inline, because a
// fetch in front of a 911 is a TLS handshake it need not wait for, and a dead token is
// recovered after the POST is answered 401 (sosRetryOn401). Only with no token at all does it
// fetch first, on its own arena, inside kSosTokenBudgetUs.
enum class SosFirstStep : std::uint8_t { PostNow, FetchThenPost };

inline SosFirstStep sosFirstStep(bool haveCachedToken)
{
	return haveCachedToken ? SosFirstStep::PostNow : SosFirstStep::FetchThenPost;
}

// A POST's answer, as the 401 step needs it: whether it was a 2xx, and the status (negative or 0
// when no response was parsed).
struct PostResult
{
	bool ok;
	int  status;
};

// A 911/933's makecall POST has been sent at once on the token it had (SosFirstStep::PostNow).
// If it was answered 401 that token was dead, and (operator ruling on #945) there is exactly one
// recovery: ONE token fetch on the 911/933 arena (fetch(), which is bounded by
// kSosTokenBudgetUs), then ONE retry of the POST (retry(), which must read the new bearer
// afterwards). One witness line per step. If the fetch fails, or the retry fails whatever it
// answers (a second 401 included), the failed result is returned and the call fails the way any
// failed makecall does, which the caller handles (#880): not a refusal made here, not a second
// fetch, not a second retry. Any answer other than a 401 is returned untouched.
//
// The fetch runs whether or not another 911/933 is pending or up (revised operator ruling 1 on
// #945: an earlier interim skip is gone). The one addition is a count for #952's bench, which settles
// whether a fetch really tears down a live call: liveSosCall() (asked after a 401 only, so a POST that
// was not answered 401 never pays for it) is the number of a 911/933 whose streams are up, 0 for none,
// and a non-zero answer leaves token_sos_live_fetch_862 naming both calls (callId, EmergencyScope::id()).
// The line is emitted for every occurrence, never sampled, and its answer never gates the fetch. A 911/933
// that is only pending in makeCall() has no streams and does not count. On the ESP arm liveSosCall()
// is one atomic load per call slot, plus the slot's getMutex for an open GET handle as ensureToken()
// does it. The line is left as the fetch is about to start, before its arena claim: a fetch turned
// away at the claim also leaves token_sos_claim_lost_862 for the same call (claimWaiting), which a
// count of fetches that really ran subtracts.
template <class LiveSos, class Fetch, class Retry>
PostResult sosRetryOn401(PostResult first, std::uint32_t callId, LiveSos&& liveSosCall, Fetch&& fetch, Retry&& retry)
{
	if (first.ok || first.status != 401) return first;
	if (const std::uint32_t live = liveSosCall())
	{
		PD_WITNESS_W("e911", "token_sos_live_fetch_862: 911/933 call %u fetches a token while 911/933 call %u has live streams; "
		                     "the fetch is not held back, this only counts it for #952 (#862)",
		             static_cast<unsigned>(callId), static_cast<unsigned>(live));
	}
	PD_WITNESS_W("e911", "token_sos_401_fetch_862: a 911/933 POST was answered 401, fetching one token on its own arena (#862)");
	if (!fetch()) return first;
	PD_WITNESS_W("e911", "token_sos_401_retry_862: a new token is in hand, retrying the 911/933 POST once (#862)");
	return retry();
}

// ── A 911/933 token fetch has an overall deadline (#862, Rule 5) ─────────────────
// The HTTP client's timeouts are per operation (connect and handshake, the request, the response
// headers, each body read), so a fetch of four or more operations at 2 s each can run for ten
// seconds with every one of them inside its timeout. The 911/933 lane's fetch gets this budget for
// the whole of it, and each operation is given the smaller of its own cap and what is left.
// One operation can still overrun what it was given: fetch_headers, and a read of a chunked body,
// make more than one transport read inside a single call, each with the same timeout, so a server
// that drips bytes stretches the bound to the budget plus those reads.
inline constexpr std::int64_t kSosTokenBudgetUs = 3LL * 1000 * 1000;

// The timeout to give the next operation of a fetch that must be over by deadlineUs: its cap
// (capMs), or what is left of the budget if that is less, rounded up to a whole millisecond. 0
// means the budget is spent, and then the operation must NOT be started: a timeout of 0 is "poll
// once" in the transport, not "no wait".
inline int opTimeoutMs(std::int64_t nowUs, std::int64_t deadlineUs, int capMs)
{
	const std::int64_t leftUs = deadlineUs - nowUs;
	if (leftUs <= 0) return 0;
	const std::int64_t leftMs = (leftUs + 999) / 1000;
	return leftMs < capMs ? static_cast<int>(leftMs) : capMs;
}

namespace detail
{
	inline constexpr std::size_t kNoPos = static_cast<std::size_t>(-1);

	inline std::size_t skipWs(const char* s, std::size_t i, std::size_t n)
	{
		while (i < n && (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n')) ++i;
		return i;
	}

	// s[i] is an opening quote. The index just past the closing quote, or kNoPos.
	inline std::size_t endOfString(const char* s, std::size_t i, std::size_t n)
	{
		for (++i; i < n; ++i)
		{
			if (s[i] == '\\') { ++i; continue; }
			if (s[i] == '"') return i + 1;
		}
		return kNoPos;
	}

	// The index just past the value that starts at s[i], or kNoPos if it never ends.
	inline std::size_t skipValue(const char* s, std::size_t i, std::size_t n)
	{
		if (i >= n) return kNoPos;
		if (s[i] == '"') return endOfString(s, i, n);
		if (s[i] == '{' || s[i] == '[')
		{
			std::size_t depth = 0;
			while (i < n)
			{
				const char c = s[i];
				if (c == '"')
				{
					i = endOfString(s, i, n);
					if (i == kNoPos) return kNoPos;
					continue;
				}
				if (c == '{' || c == '[') ++depth;
				else if ((c == '}' || c == ']') && --depth == 0) return i + 1;
				++i;
			}
			return kNoPos;
		}
		while (i < n && s[i] != ',' && s[i] != '}' && s[i] != ']' &&
		       s[i] != ' ' && s[i] != '\t' && s[i] != '\r' && s[i] != '\n') ++i;
		return i;
	}

	// s[start] is the opening quote of a string. Unescapes it where it stands (the result is
	// never longer than the text it came from) and views it in `out`. A string it cannot
	// represent exactly is refused: a surrogate pair, a \u0000, an escape JSON does not have.
	inline bool unescapeInPlace(char* s, std::size_t start, std::size_t n, std::string_view& out)
	{
		std::size_t r = start + 1;
		std::size_t w = start;
		while (r < n)
		{
			char c = s[r++];
			if (c == '"')
			{
				out = std::string_view(s + start, w - start);
				return true;
			}
			if (c != '\\')
			{
				s[w++] = c;
				continue;
			}
			if (r >= n) return false;
			c = s[r++];
			switch (c)
			{
				case '"': case '\\': case '/': s[w++] = c; break;
				case 'b': s[w++] = '\b'; break;
				case 'f': s[w++] = '\f'; break;
				case 'n': s[w++] = '\n'; break;
				case 'r': s[w++] = '\r'; break;
				case 't': s[w++] = '\t'; break;
				case 'u':
				{
					if (n - r < 4) return false;
					unsigned cp = 0;
					for (int k = 0; k < 4; ++k)
					{
						const char h = s[r++];
						const int d = (h >= '0' && h <= '9') ? h - '0'
						            : (h >= 'a' && h <= 'f') ? h - 'a' + 10
						            : (h >= 'A' && h <= 'F') ? h - 'A' + 10 : -1;
						if (d < 0) return false;
						cp = cp * 16 + static_cast<unsigned>(d);
					}
					if (cp == 0 || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
					if (cp < 0x80)
					{
						s[w++] = static_cast<char>(cp);
					}
					else if (cp < 0x800)
					{
						s[w++] = static_cast<char>(0xC0 | (cp >> 6));
						s[w++] = static_cast<char>(0x80 | (cp & 0x3F));
					}
					else
					{
						s[w++] = static_cast<char>(0xE0 | (cp >> 12));
						s[w++] = static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
						s[w++] = static_cast<char>(0x80 | (cp & 0x3F));
					}
					break;
				}
				default: return false;
			}
		}
		return false;   // no closing quote: the text was cut short
	}
}  // namespace detail

// Finds the top-level member `key` of the JSON object in json[0..len) and, if it is a string,
// views its unescaped value in `out`. The text is rewritten in place (so json must be
// writable) and `out` points into it. Replaces cJSON_Parse for the token response: no heap,
// no recursion, one pass. Anything it cannot place exactly -- truncated or malformed text, a
// missing member, a member that is not a string, an escape it cannot represent -- returns false
// and leaves `out` alone: it never returns a prefix. Keys match case-sensitively and the first
// of two equal keys wins. A key written with escapes is not matched.
inline bool jsonStringField(char* json, std::size_t len, std::string_view key, std::string_view& out)
{
	std::size_t i = detail::skipWs(json, 0, len);
	if (i >= len || json[i] != '{') return false;
	++i;
	for (;;)
	{
		i = detail::skipWs(json, i, len);
		if (i >= len || json[i] != '"') return false;   // '}' lands here too: no such member
		const std::size_t keyEnd = detail::endOfString(json, i, len);
		if (keyEnd == detail::kNoPos) return false;
		const std::string_view k(json + i + 1, keyEnd - i - 2);
		i = detail::skipWs(json, keyEnd, len);
		if (i >= len || json[i] != ':') return false;
		i = detail::skipWs(json, i + 1, len);
		if (k == key)
		{
			if (i >= len || json[i] != '"') return false;   // there, but not a string
			return detail::unescapeInPlace(json, i, len, out);
		}
		i = detail::skipValue(json, i, len);
		if (i == detail::kNoPos) return false;
		i = detail::skipWs(json, i, len);
		if (i >= len || json[i] != ',') return false;
		++i;
	}
}

}  // namespace telephony

#endif // TELEPHONY_ANCHOR_LOGIC_HPP
