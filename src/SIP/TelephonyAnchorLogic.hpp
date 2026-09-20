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

#include <cstdint>
#include <string>
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

}  // namespace telephony

#endif // TELEPHONY_ANCHOR_LOGIC_HPP
