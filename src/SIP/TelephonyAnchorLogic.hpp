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
// (C++17 stdlib only — no cJSON, no mbedTLS, no ESP headers) so the same code
// runs on the device AND in the host GoogleTest suite. The ESP .cpp arm calls
// these for the URL builders and the entity-path parse; decodeJwtLifetimeUs has
// a self-contained base64url + a minimal exp/iat scan that matches the on-device
// mbedTLS/cJSON path for well-formed tokens, with the SAME fallback contract.
//
// Everything here is intentionally allocation-light and total: every malformed
// input maps to a documented, safe return value (the fallback lifetime / empty
// string / "no match"), never UB.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

namespace telephony
{

// Fallback token lifetime when the JWT can't be decoded: 50 minutes (µs). This
// is the JWT's real ~1h validity minus margin, deliberately NOT the OAuth
// expires_in (Telephony reports 60s there, which would cause a refresh storm). Mirrors
// kTokenFallbackLifetimeUs in TelephonyAnchorClient.cpp.
inline constexpr int64_t kTokenFallbackLifetimeUs = 50LL * 60 * 1000000;

// ── base64url decode (no padding required) ───────────────────────────────────
// Decodes a JWT payload segment. Accepts the URL alphabet ('-'/'_'), tolerates
// missing '=' padding, and ignores a trailing partial group. Returns false only
// if a non-alphabet byte is encountered. Output is appended to `out`.
inline bool base64UrlDecode(const std::string& in, std::vector<uint8_t>& out)
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
	for (char c : in)
	{
		if (c == '=') break;          // padding: stop
		int v = val(c);
		if (v < 0) return false;      // invalid byte
		buf = (buf << 6) | static_cast<uint32_t>(v);
		bits += 6;
		if (bits >= 8)
		{
			bits -= 8;
			out.push_back(static_cast<uint8_t>((buf >> bits) & 0xFF));
		}
	}
	return true;
}

// Scan a flat JSON object string for a top-level numeric field named `key` and
// write it to `out`. Minimal, allocation-free: finds "\"key\"", skips ':' and
// whitespace, parses an integer (optionally signed). Returns false if the key
// is absent or the value is not numeric. Sufficient for JWT `exp`/`iat` claims,
// which are always integer seconds. (The on-device path uses cJSON; for the
// well-formed tokens Telephony issues the two agree.)
inline bool scanJsonNumber(const std::string& json, const std::string& key, int64_t& out)
{
	const std::string needle = "\"" + key + "\"";
	size_t pos = 0;
	while ((pos = json.find(needle, pos)) != std::string::npos)
	{
		size_t i = pos + needle.size();
		// Skip whitespace then a single ':'.
		while (i < json.size() && (json[i] == ' ' || json[i] == '\t')) ++i;
		if (i >= json.size() || json[i] != ':')
		{
			pos += needle.size();
			continue;   // a string value that merely contains the key text
		}
		++i;
		while (i < json.size() && (json[i] == ' ' || json[i] == '\t')) ++i;
		if (i >= json.size()) return false;

		bool neg = false;
		if (json[i] == '-') { neg = true; ++i; }
		if (i >= json.size() || json[i] < '0' || json[i] > '9')
		{
			return false;   // not a number (e.g. a quoted/boolean value)
		}
		int64_t v = 0;
		while (i < json.size() && json[i] >= '0' && json[i] <= '9')
		{
			v = v * 10 + (json[i] - '0');
			++i;
		}
		out = neg ? -v : v;
		return true;
	}
	return false;
}

// Decode a JWT's declared lifetime (exp - iat) in microseconds from its payload
// segment. Returns kTokenFallbackLifetimeUs if anything is unparseable. Same
// contract and sanity window (positive, under a day) as the on-device
// decodeJwtLifetimeUs.
inline int64_t decodeJwtLifetimeUs(const std::string& jwt)
{
	size_t firstDot = jwt.find('.');
	if (firstDot == std::string::npos) return kTokenFallbackLifetimeUs;
	size_t secondDot = jwt.find('.', firstDot + 1);
	if (secondDot == std::string::npos) return kTokenFallbackLifetimeUs;

	std::string payload = jwt.substr(firstDot + 1, secondDot - firstDot - 1);
	if (payload.empty()) return kTokenFallbackLifetimeUs;

	std::vector<uint8_t> decoded;
	if (!base64UrlDecode(payload, decoded) || decoded.empty())
	{
		return kTokenFallbackLifetimeUs;
	}

	std::string json(decoded.begin(), decoded.end());
	int64_t exp = 0, iat = 0;
	if (!scanJsonNumber(json, "exp", exp) || !scanJsonNumber(json, "iat", iat))
	{
		return kTokenFallbackLifetimeUs;
	}

	int64_t span = exp - iat;                 // seconds
	if (span > 0 && span < 86400)             // sanity: positive, under a day
	{
		return span * 1000000;
	}
	return kTokenFallbackLifetimeUs;
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

// Issues #379/#681: the participant ids this PBX itself created. On .244 a handset
// CANCELled before 3CX's makecall response named the PBX's own leg; the drop freed
// the leg's call slot, then stalled reconnecting, and an upsert for the leg that
// matched no slot was announced as a new inbound call (#379 issuecomment-5985911668).
//
// Only legs the makecall response named, or that an outbound slot held, are noted,
// never a leg the PBX merely dropped: dropCall() also drops refused inbound legs, and
// a PSAP callback refused while a bridge is busy must be announced again on 3CX's
// next upsert if its drop fails. A PSAP callback or any other genuine inbound call
// is a new participant id, which this table never holds.
//
// The hold is bounded: kOwnLegGraceUs after the last event noted for the leg, never
// extended by the upserts it suppresses, so an id 3CX might reuse is at worst
// announced one grace late. The window it has to span runs from the slot being freed
// to 3CX's Remove across a stalled drop: performCtrl() makes two attempts with
// socket operations of up to 2 s each (timeout_ms bounds each operation, not the
// request) and one cold TLS handshake, about 5-7 s; the trace took 1.1 s. Fixed size:
// a full table overwrites its least recently seen entry, and an id that does not fit
// is not recorded; both forget a leg, which errs toward announcing. Not synchronised.
inline constexpr int64_t kOwnLegGraceUs = 10'000'000;

template <std::size_t N, std::size_t Len>
class OwnLegs
{
public:
	void note(std::string_view id, int64_t nowUs)
	{
		if (id.empty() || id.size() >= Len) return;
		Entry* victim = &_e[0];
		for (Entry& e : _e)
		{
			if (id == e.id)
			{
				e.seenUs = nowUs;
				return;
			}
			if (age(e) < age(*victim)) victim = &e;
		}
		std::memcpy(victim->id, id.data(), id.size());
		victim->id[id.size()] = '\0';
		victim->seenUs = nowUs;
	}

	// A later time for a leg still held; a leg not held is not added.
	bool refresh(std::string_view id, int64_t nowUs)
	{
		if (!holds(id, nowUs)) return false;
		note(id, nowUs);
		return true;
	}

	bool holds(std::string_view id, int64_t nowUs) const
	{
		if (id.empty()) return false;
		for (const Entry& e : _e)
		{
			if (id == e.id) return nowUs - e.seenUs < kOwnLegGraceUs;
		}
		return false;
	}

	// RED (#883 review): the API of the Remove release, with the head's behaviour:
	// a Remove releases nothing.
	void noteNamed(std::string_view id, int64_t nowUs) { note(id, nowUs); }
	void release(std::string_view, uint64_t) {}
	bool holds(std::string_view id, int64_t nowUs, uint64_t) const { return holds(id, nowUs); }

private:
	struct Entry
	{
		char    id[Len] = {};
		int64_t seenUs  = 0;
	};
	static int64_t age(const Entry& e) { return e.id[0] != '\0' ? e.seenUs : std::numeric_limits<int64_t>::min(); }
	Entry _e[N] = {};
};

using AnchorOwnLegs = OwnLegs<8, 32>;

// May an upset for partId, which no call slot holds as an outbound call, be announced
// as a new inbound call? Every id the table does not hold is announced as before.
template <std::size_t N, std::size_t Len>
inline bool inboundAnnounceAllowed(const OwnLegs<N, Len>& own, std::string_view partId, int64_t nowUs)
{
	return !own.holds(partId, nowUs);
}

template <std::size_t N, std::size_t Len>
inline bool inboundAnnounceAllowed(const OwnLegs<N, Len>& own, std::string_view partId, int64_t nowUs,
                                   uint64_t wsSeq)
{
	return !own.holds(partId, nowUs, wsSeq);
}

// RED (#883 review): where makeCall() got its own leg's id; the head holds every one.
enum class OwnLegSource : uint8_t
{
	MakecallResult,
	OwnPartyDn,
	FirstControllable,
};

inline bool ownLegMayBeHeld(OwnLegSource) { return true; }

}  // namespace telephony

#endif // TELEPHONY_ANCHOR_LOGIC_HPP
