#ifndef SIP_DIGEST_HPP
#define SIP_DIGEST_HPP

// SipDigest: self-contained SIP HTTP-Digest (RFC 2617, MD5 / qop=auth) primitives.
// NOTE: only the MD5 algorithm is implemented. RFC 8760 (SHA-256/SHA-512-256
// digest) is NOT supported — MD5 matches the installed-phone fleet; SHA-256 is a
// tracked hardening follow-up.
//
// Why this exists: the registrar at RequestsHandler::onRegister is fully open.
// STAGE 1 adds the digest-auth building blocks so a later stage can challenge a
// REGISTER with WWW-Authenticate, parse the client's Authorization, and verify
// the response against a stored HA1.
//
// Design constraints (mirrors AdminAuth):
//   * Dependency-free beyond the C++17 standard library and the platform guards.
//     A small, self-contained MD5 (RFC 1321 reference) lives in SipDigest.cpp so
//     the digest is identical on host and ESP and the host build needs NO external
//     crypto dependency. (IDF v6.0.1 only ships mbedtls/private/md5.h, so vendoring
//     a portable MD5 is both more portable AND avoids the private-header churn.)
//   * Pure functions + a nonce helper. No NVS, no SIP, no sockets here — the
//     secret store (SipSecretStore) and the SIP wiring live elsewhere.
//   * Constant-time response comparison so verification does not leak how many
//     leading hex digits matched.
//
// Algorithm (RFC 2617, qop="auth"):
//   HA1      = MD5(username:realm:password)              <- computeHa1
//   HA2      = MD5(method:digestURI)
//   response = MD5(HA1:nonce:nc:cnonce:qop:HA2)          <- computeResponse
//
// The realm is fixed to "pocketdial" by the caller (not hard-coded here).

#include <string>
#include <cstdint>

namespace SipDigest
{
	// Parsed fields of an inbound `Authorization: Digest ...` header value.
	// Only the digest parameters relevant to qop="auth" verification are kept.
	// Missing parameters are left as empty strings.
	struct DigestAuth
	{
		std::string username;
		std::string realm;
		std::string nonce;
		std::string uri;        // the "uri" digest-uri parameter
		std::string response;   // 32 hex chars
		std::string qop;        // "auth" (or empty for legacy RFC 2069)
		std::string nc;         // nonce-count, 8 hex chars (e.g. "00000001")
		std::string cnonce;     // client nonce
		std::string algorithm;  // "MD5" (or empty -> defaults to MD5)
		std::string opaque;     // echoed back if the server issued one
	};

	// --- MD5 helper (exposed because the secret store and tests want it) ---
	// Returns the lowercase 32-char hex MD5 of `input`.
	std::string md5Hex(const std::string& input);

	// --- Header emit / parse ---------------------------------------------

	// Build a `WWW-Authenticate` HEADER VALUE (without the "WWW-Authenticate: "
	// name) suitable for a 401 challenge:
	//   Digest realm="<realm>", nonce="<nonce>", qop="auth", algorithm=MD5
	// When `stale` is true, appends `, stale=true` so a client that used an
	// expired nonce knows to retry with fresh credentials rather than re-prompt.
	std::string buildWwwAuthenticate(const std::string& realm,
	                                 const std::string& nonce,
	                                 bool stale = false);

	// Parse an `Authorization` HEADER VALUE. Accepts either the full header line
	// ("Authorization: Digest ...") or just the value ("Digest ..."). Tolerates
	// arbitrary whitespace, optional quoting, and parameter reordering. Returns
	// true iff the value parsed as a Digest credential with a non-empty
	// username/response (the minimum needed to attempt verification).
	bool parseAuthorization(const std::string& authHeaderValue, DigestAuth& out);

	// --- Digest computation ----------------------------------------------

	// HA1 = MD5(ext:realm:secret). This is what the secret store persists.
	std::string computeHa1(const std::string& ext,
	                       const std::string& realm,
	                       const std::string& secret);

	// response = MD5(HA1:nonce:nc:cnonce:qop:HA2), HA2 = MD5(method:uri).
	// When `qop` is empty, falls back to the legacy RFC 2069 form
	// response = MD5(HA1:nonce:HA2) so older UACs still verify.
	std::string computeResponse(const std::string& ha1,
	                            const std::string& method,
	                            const std::string& uri,
	                            const std::string& nonce,
	                            const std::string& nc,
	                            const std::string& cnonce,
	                            const std::string& qop);

	// Constant-time verify of `auth.response` against the locally-recomputed
	// response built from `ha1` and the request `method`. All digest inputs
	// (uri/nonce/nc/cnonce/qop) come from the parsed `auth`. Returns false on a
	// length mismatch or any differing byte (no short-circuit).
	bool verify(const DigestAuth& auth,
	            const std::string& ha1,
	            const std::string& method);

	// --- Nonce helper -----------------------------------------------------
	//
	// Nonces are stateless and self-validating: a nonce embeds a creation
	// timestamp and an HMAC-style keyed MD5 tag over that timestamp using a
	// process-lifetime server secret. No server-side nonce table is needed, and
	// a tampered or expired nonce is detected on the next request.
	//
	// Wire form: lowercase hex of "<timestampMs>" + ":" + MD5(secret:timestampMs),
	// joined as "<hex(timestampMs)>.<tagHex>" (the '.' is not a hex char so it is
	// an unambiguous separator).

	// Default nonce lifetime: 5 minutes. Long enough for a phone to compute and
	// resend its credentials, short enough to bound replay.
	constexpr uint64_t kNonceTtlMs = 5ULL * 60ULL * 1000ULL;

	// Generate a fresh nonce bound to "now" and signed with the server secret.
	std::string generateNonce();

	// Validate a nonce's integrity AND freshness. Returns true iff the tag verifies
	// (it is one WE issued) AND the nonce is within `ttlMs`. If `expiredOut` is
	// non-null it is set true when the tag verified but the nonce is past `ttlMs`
	// (i.e. stale → answer 401 with stale=true), and false otherwise. Returns false
	// for a forged/corrupt tag OR an expired nonce.
	bool validateNonce(const std::string& nonce,
	                   bool* expiredOut = nullptr,
	                   uint64_t ttlMs = kNonceTtlMs);

	// Convenience: a nonce is "stale" iff its tag verifies (it is one WE issued)
	// but it is past `ttlMs`. A stale nonce -> answer 401 with stale=true so the
	// client silently retries. A forged/garbage nonce is NOT stale (returns false)
	// -> treat as a fresh challenge / hard reject.
	bool isStale(const std::string& nonce, uint64_t ttlMs = kNonceTtlMs);

	// =====================================================================
	// CLIENT SIDE (UAC) — the mirror image of everything above.
	// =====================================================================
	//
	// Everything before this point answers the question a REGISTRAR asks: "is
	// this inbound Authorization good?". Everything below answers the question a
	// UAC asks: "what Authorization do I have to send?". They share the MD5 core,
	// the parameter scanner and the qop/no-qop response construction — which is
	// exactly why this lives in the same translation unit rather than a parallel
	// one that would drift.
	//
	// Groundwork for issue #164 (generic SIP trunk): a trunk that registers to a
	// carrier SBC needs this half. Nothing here knows about sockets, tasks or
	// NVS; SipRegistrationClient (src/SIP) is the state machine that drives it.
	//
	// SECURITY: no function here logs, returns or stores a password. The password
	// is a by-value input to buildAuthorization() and is consumed inside one
	// MD5 of HA1; it never reaches the emitted header, the parsed structs, or a
	// log line. Callers holding a password long-term should follow
	// SipSecretStore's discipline (see SipRegistrationClient's Config comment for
	// why a CLIENT, unlike the registrar, cannot store HA1 instead).

	// Which digest algorithm a challenge asked for. RFC 8760 (SHA-256 /
	// SHA-512-256) is deliberately NOT implemented — see the file header — and
	// maps to Unsupported so a caller REFUSES rather than silently computing an
	// MD5 response the server will reject with a second 401 forever.
	enum class DigestAlgorithm
	{
		Md5,          // "MD5", or absent (RFC 7616 §3.3: MD5 is the default)
		Md5Sess,      // "MD5-sess" (RFC 7616 §3.4.2)
		Unsupported   // anything else — SHA-256, SHA-512-256, SHA-256-sess, junk
	};

	// Parsed fields of an inbound `WWW-Authenticate:` (401) or
	// `Proxy-Authenticate:` (407) challenge HEADER VALUE. Missing parameters are
	// left as empty strings.
	struct DigestChallenge
	{
		std::string realm;
		std::string nonce;
		std::string opaque;      // echoed back verbatim if present
		std::string algorithm;   // AS SENT; "" means MD5 (RFC 7616 §3.3)
		std::string qopList;     // RAW list as sent, e.g. `auth,auth-int`
		std::string domainParam; // the "domain" parameter, if any (unused, kept
		                         // so an unknown-parameter round-trip is visible)
		bool stale = false;      // stale=true -> retry with a FRESH nonce, do NOT
		                         // treat as bad credentials
		bool proxy = false;      // this challenge came from Proxy-Authenticate,
		                         // so the answer goes in Proxy-Authorization
	};

	// Parse a `WWW-Authenticate` / `Proxy-Authenticate` HEADER VALUE. Accepts
	// either the full header line ("WWW-Authenticate: Digest ...") or just the
	// value ("Digest ..."), exactly like parseAuthorization.
	//
	// `proxyDefault` sets out.proxy when the input carries NO header name to
	// disambiguate — pass true when you pulled the value off a 407. A header name
	// that IS present always wins over `proxyDefault`.
	//
	// Returns true iff the value parsed as a Digest challenge carrying a nonce.
	// A realm-less challenge still parses (realm == "" hashes as an empty realm,
	// which is what a server that omitted it must itself have done), but a
	// nonce-less one does not: there is nothing to answer.
	bool parseChallenge(const std::string& challengeHeaderValue,
	                    DigestChallenge& out,
	                    bool proxyDefault = false);

	// Classify ch.algorithm. Case-insensitive; "" -> Md5.
	DigestAlgorithm algorithmOf(const DigestChallenge& ch);

	// Choose the qop this client will use from the challenge's (possibly
	// multi-valued) qop list.
	//
	//   returns true , out == "auth"  : the list offered auth — use RFC 2617 qop.
	//   returns true , out == ""      : the challenge carried NO qop parameter at
	//                                   all — fall back to legacy RFC 2069.
	//   returns false, out == ""      : a qop list WAS offered but contains no
	//                                   "auth" (e.g. auth-int only). We do not
	//                                   hash message bodies, so we cannot answer.
	//
	// The two `true` cases are distinguished by `out`, not by the return: the
	// return is purely "can this client answer at all".
	bool selectQop(const DigestChallenge& ch, std::string& out);

	// HA1 for algorithm=MD5-sess (RFC 7616 §3.4.2):
	//   HA1 = MD5( MD5(username:realm:password) : nonce : cnonce )
	// `ha1` is the ordinary computeHa1() result. Note the session HA1 is bound to
	// the cnonce, so it MUST be recomputed whenever the cnonce changes — which is
	// why MD5-sess and a per-request cnonce are mutually exclusive in practice.
	std::string computeHa1Sess(const std::string& ha1,
	                           const std::string& nonce,
	                           const std::string& cnonce);

	// The header NAME an answer to `ch` must be sent under: "Authorization" for a
	// 401 challenge, "Proxy-Authorization" for a 407. Sending the wrong one is a
	// silent auth loop — the proxy never sees its credential and re-challenges.
	const char* authorizationHeaderName(const DigestChallenge& ch);

	// Format a nonce-count as the 8 lowercase hex digits RFC 7616 §3.4.3
	// requires. Anything shorter is rejected outright by several SBCs.
	std::string formatNc(uint32_t count);

	// A fresh, unpredictable cnonce: 16 lowercase hex chars (64 bits) drawn from
	// the same CSPRNG that keys the server nonce secret (esp_random() on device).
	// Unpredictability is load-bearing: a predictable cnonce lets an attacker who
	// can see one response precompute others, defeating the client-nonce's whole
	// purpose (RFC 7616 §5.10).
	std::string makeCnonce();

	// Build an `Authorization` / `Proxy-Authorization` HEADER VALUE (without the
	// header name — mirroring buildWwwAuthenticate) answering `ch`.
	//
	//   * qop=auth      -> response = MD5(HA1:nonce:nc:cnonce:qop:HA2), and the
	//                      emitted header carries qop/nc/cnonce.
	//   * no qop        -> response = MD5(HA1:nonce:HA2) (legacy RFC 2069), and
	//                      the emitted header carries NO qop/nc/cnonce. Sending
	//                      them anyway is the classic interop bug: an RFC 2069
	//                      server ignores them and computes the short form, so
	//                      the two sides disagree with no diagnostic.
	//   * algorithm and opaque are ECHOED ONLY when the challenge named them, so
	//     the emitted header reproduces the RFC 2617 §3.5 and RFC 7616 §3.9.1
	//     worked examples parameter-for-parameter.
	//
	// `ncValue` is the caller's nonce-count — it MUST increment on every request
	// sent against the same nonce and reset to 1 when the nonce changes. This
	// function does not track it: the count belongs to the registration/dialog,
	// not to a pure function.
	//
	// Returns false and leaves `out` UNTOUCHED when the challenge cannot be
	// answered: no nonce, an algorithm we do not implement (RFC 8760 SHA-2), a
	// qop list offering only auth-int, qop=auth with no cnonce, or MD5-sess with
	// no qop (HA1-sess is defined over the cnonce, and the no-qop form may not
	// send one — so the server could never recompute it). Refusing is the point:
	// a client that answers an unknown algorithm with an MD5 response, or emits a
	// response nobody can verify, loops forever against a server that will never
	// accept it — and on the wire that is indistinguishable from a wrong password.
	bool buildAuthorization(const DigestChallenge& ch,
	                        const std::string& username,
	                        const std::string& password,
	                        const std::string& method,
	                        const std::string& uri,
	                        uint32_t ncValue,
	                        const std::string& cnonce,
	                        std::string& out);
}

#endif // SIP_DIGEST_HPP
