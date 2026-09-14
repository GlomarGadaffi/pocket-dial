#ifndef SIP_REGISTRATION_CLIENT_HPP
#define SIP_REGISTRATION_CLIENT_HPP

// ── SipRegistrationClient: the REGISTER *user agent* (RFC 3261 §10.2) ─────────
//
// The board has always been a REGISTRAR — Registrar.cpp accepts REGISTERs from
// desk phones and holds their bindings. This is the opposite direction: the
// board as a CLIENT, registering itself to somebody else's registrar (a carrier
// SBC). Groundwork for issue #164 (generic SIP trunk); the trunk itself is not
// built here, because it needs carrier credentials we do not have.
//
// NAMING: "Registrar" is the server half and lives in Registrar.{hpp,cpp}. This
// is deliberately NOT called RegisterClient/Registrant — the two files sit next
// to each other in src/SIP and a reader must never have to guess which way the
// REGISTER is flowing.
//
// ── It never touches a socket ─────────────────────────────────────────────────
//
// tick() hands back BYTES. It does not send them, and it must not: sends from
// the SIP receive thread go through RequestsHandler::_outbox, and sends from any
// other thread go through _asyncOutbox. A class that picked one for its caller
// would be wrong half the time — and wrong in the worst possible way. Commit
// 9c4664a's predecessor is the case study: a message queued onto _outbox from a
// non-SIP thread was silently wiped by the next tick()'s drain, while the caller
// still reported success. Nothing about that failure is visible at the call site.
//
// So the contract is: this class composes, the caller dispatches, and the caller
// is the one that knows which thread it is on. Likewise nothing here blocks and
// nothing here takes a lock, so it is safe to drive from inside the engine's big
// _mutex and hand the bytes to the outbox after the unlock.
//
// ── Memory ────────────────────────────────────────────────────────────────────
//
// Every long-lived field is a fixed char array and the composed request goes
// into a caller-provided fixed buffer via snprintf. The object allocates nothing
// after configure(), and a challenge field that does not fit is REFUSED rather
// than truncated (a truncated nonce hashes to a digest the server can never
// reproduce — silently, forever). The transient std::strings inside
// SipDigest::buildAuthorization() are the same ones the inbound REGISTER path
// already builds on every challenge it verifies; this half does not add a new
// allocation class, and it does so at most once per registration cycle rather
// than once per packet.
//
// ── The credential ────────────────────────────────────────────────────────────
//
// SipSecretStore persists HA1, never a password, because a REGISTRAR only ever
// needs to RECOMPUTE a digest. A CLIENT cannot do that: HA1 is
// MD5(user:realm:password) and the realm arrives at runtime in the challenge, so
// the password itself has to be held until the first 401. It therefore lives
// here in a fixed buffer with the same discipline SipSecretStore and
// TelephonyApiConfig::view() apply to their secrets:
//
//   * no getter returns it, and Status carries no credential material at all;
//   * nothing logs it — the error strings name the failure, never the input;
//   * clearCredentials() overwrites it in place;
//   * copy and assignment are deleted, so it cannot be duplicated by accident;
//   * a password that would not fit is a hard configure() failure, never a
//     silent truncation.

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "SipDigest.hpp"

class SipRegistrationClient
{
public:
	// ── Bounds ────────────────────────────────────────────────────────────────
	static constexpr size_t kMaxHost    = 64;   // registrar host / SIP domain
	static constexpr size_t kMaxUser    = 64;   // AOR user part / auth username
	static constexpr size_t kMaxSecret  = 64;   // password
	static constexpr size_t kMaxIp      = 46;   // INET6_ADDRSTRLEN
	static constexpr size_t kMaxNonce   = 128;  // nonce / opaque, as sent
	static constexpr size_t kMaxAlgo    = 16;
	static constexpr size_t kMaxQop     = 32;
	static constexpr size_t kMaxError   = 64;
	static constexpr size_t kMaxCallId  = 40;
	static constexpr size_t kMaxTag     = 24;
	static constexpr size_t kMaxRequest = 1024; // composed REGISTER, fixed

	// ── Lease bounds ──────────────────────────────────────────────────────────
	static constexpr uint32_t kDefaultExpiresSec = 3600;
	static constexpr uint32_t kMaxExpiresSec     = 86400;

	// RFC 3261 Timer F (64*T1) — a non-INVITE client transaction gives up after
	// 32 s with no final response. Matching it means a black-holed REGISTER
	// becomes a normal backed-off failure instead of a client stuck in
	// Registering forever.
	static constexpr uint64_t kTransactionTimeoutMs = 32000;

	// ── Backoff ───────────────────────────────────────────────────────────────
	// Exponential from 2 s, doubling, capped at 5 minutes. The cap is the point:
	// a carrier SBC that is refusing us (wrong password, account suspended,
	// source IP not allow-listed) must see one attempt every 5 minutes, not a
	// tight loop — several ITSPs auto-blacklist a source that retries hard, and
	// a blacklist is much harder to get out of than a config mistake.
	//
	// There is deliberately NO random jitter. Jitter exists to de-synchronise a
	// FLEET; this is one board talking to one SBC, so jitter would buy nothing
	// and cost the tests their determinism. If pocket-dial ever grows many
	// trunks to one carrier, add it there.
	static constexpr uint64_t kBackoffBaseMs = 2000;
	static constexpr uint64_t kBackoffCapMs  = 300000;

	// How many challenges one registration cycle will answer before giving up.
	// A correct exchange needs exactly one; a stale-nonce re-challenge makes two.
	// Three bounds the pathological case where an SBC challenges every answer.
	static constexpr uint32_t kMaxAuthAttempts = 3;

	// ── State ─────────────────────────────────────────────────────────────────
	enum class State : uint8_t
	{
		Idle,        // not configured, or stopped
		Registering, // a REGISTER is in flight (initial, authed, or a refresh)
		Registered,  // 200 OK; binding live until bindingExpiresAtMs
		Failed       // backing off; will retry at nextActionMs
	};

	// Everything a dashboard needs and NOTHING a dashboard must not have: no
	// password, no HA1, no nonce, no composed Authorization header.
	struct Status
	{
		State    state                = State::Idle;
		uint32_t grantedExpiresSec    = 0;  // what the SERVER granted, not asked
		uint32_t requestedExpiresSec  = 0;  // what we ask for now (a 423 moves it)
		uint64_t nextActionMs         = 0;  // next refresh, or next retry
		uint64_t bindingExpiresAtMs   = 0;  // when the live binding actually lapses
		uint32_t consecutiveFailures  = 0;
		uint32_t registerAttempts     = 0;  // REGISTERs emitted since configure()
		uint16_t lastStatusCode       = 0;
		bool     authenticated        = false; // THIS registration was carried by a
		                                       // credential (an IP-authenticated
		                                       // trunk never sets it) -- not merely
		                                       // that a challenge was seen
		char     lastError[kMaxError] = {0};
	};

	struct Config
	{
		char     registrarHost[kMaxHost] = {0}; // SBC host or IP
		uint16_t registrarPort           = 5060;
		char     domain[kMaxHost]        = {0}; // SIP domain in the AOR
		char     aorUser[kMaxUser]       = {0}; // user part of the AOR
		char     authUser[kMaxUser]      = {0}; // digest username (often == aorUser)
		char     localIp[kMaxIp]         = {0}; // Via / Contact host
		uint16_t localPort               = 5060;
		uint32_t requestedExpiresSec     = kDefaultExpiresSec;
	};

	// The composed request. Caller-owned storage so this class allocates nothing.
	struct Request
	{
		char   bytes[kMaxRequest] = {0};
		size_t len                = 0;
	};

	// One SIP response, reduced to the header values this machine reads. Views,
	// not copies: the caller owns the backing buffer for the duration of the call.
	//
	// BOUNDARY / KNOWN GAP -- multiple challenges. RFC 7616 §3.7 lets a server
	// send ONE WWW-Authenticate per algorithm, strongest first, and the §3.9.1
	// example this module's vectors come from sends exactly two: SHA-256 then
	// MD5. This struct carries ONE view per header name, so the caller chooses
	// which challenge is offered here. A caller that blindly hands over the FIRST
	// WWW-Authenticate line of such a response gets a permanent refusal with a
	// perfectly good MD5 challenge sitting on the next line.
	//
	// Until the trunk wiring grows a "pick the first answerable challenge"
	// helper (which belongs there, with the SipMessage header iteration, not
	// here), the mitigation is inside this class rather than in its API: an
	// unanswerable challenge is DROPPED rather than cached, so the next backed-off
	// retry goes out unauthenticated and draws a fresh challenge instead of
	// re-failing forever at compose time. See composeRegister().
	struct ResponseView
	{
		int              code = 0;
		std::string_view wwwAuthenticate;   // 401
		std::string_view proxyAuthenticate; // 407
		std::string_view expires;           // "Expires" header VALUE
		std::string_view contact;           // "Contact" header VALUE (may carry
		                                    //  ;expires= per binding)
		std::string_view minExpires;        // "Min-Expires" VALUE (423)
		std::string_view retryAfter;        // "Retry-After" VALUE (5xx/486/600)
	};

	SipRegistrationClient() = default;
	~SipRegistrationClient();

	// The credential must not be copyable.
	SipRegistrationClient(const SipRegistrationClient&)            = delete;
	SipRegistrationClient& operator=(const SipRegistrationClient&) = delete;

	// Install the trunk identity. Returns false — changing nothing — when a field
	// is empty or would not fit. Truncating any of these produces a REGISTER that
	// is wrong in a way no error ever surfaces, so the refusal is the feature.
	// Resets all state: a reconfigure is a new registration, new Call-ID included.
	bool configure(const Config& cfg, std::string_view password);

	// Overwrite the password in place and drop any cached challenge. The
	// configuration survives, so status() still names the trunk, but nothing can
	// authenticate until configure() runs again.
	void clearCredentials();

	// Arm the machine: the next tick() at or after `nowMs` emits a REGISTER.
	// Idempotent — calling it on an already-armed or Registered client does
	// nothing, so a caller may poke it freely (e.g. on a link-up event).
	void start(uint64_t nowMs);

	// Disarm. The remote binding is NOT torn down: an explicit de-registration
	// (a REGISTER with Expires: 0, RFC 3261 §10.2.2) is deliberately not
	// implemented yet — it needs a terminal state and a guaranteed send, which
	// belongs with the trunk wiring, not with this state machine. Until then the
	// carrier binding simply lapses at its own expiry.
	void stop();

	// Drive the clock. Returns true and fills `out` exactly when a REGISTER must
	// go on the wire now. Safe to call at any rate; it is edge-driven, not
	// level-driven, so a REGISTER is emitted once per decision, never per tick.
	bool tick(uint64_t nowMs, Request& out);

	// Feed the response to the REGISTER most recently emitted by tick().
	// Responses arriving in any other state are ignored as stray.
	void onResponse(uint64_t nowMs, const ResponseView& r);

	Status status() const;

	// ── Introspection (tests, and a future /api/trunk) ────────────────────────
	// None of these expose credential material.
	State       state()   const { return _state; }
	uint32_t    ncValue() const { return _nc; }    // last nonce-count SENT
	uint32_t    cseq()    const { return _cseq; }
	const char* callId()  const { return _callId; }
	bool        hasCachedChallenge() const { return _haveChallenge; }

private:
	bool composeRegister(Request& out);
	void failCycle(uint64_t nowMs, int code, const char* reason, uint64_t retryAfterMs = 0);
	void armSend(uint64_t whenMs);
	bool cacheChallenge(const SipDigest::DigestChallenge& ch);
	SipDigest::DigestChallenge cachedChallenge() const;
	void setError(const char* reason);
	uint64_t backoffMs() const;

	// Identity
	Config _cfg{};
	char   _password[kMaxSecret] = {0};
	bool   _configured           = false;

	// Dialog-ish identity, stable for the lifetime of one registration (RFC 3261
	// §10.2: all REGISTERs for one AOR from one UA share a Call-ID and an
	// increasing CSeq).
	char     _callId[kMaxCallId] = {0};
	char     _fromTag[kMaxTag]   = {0};
	uint32_t _cseq               = 0;

	// Cached challenge, as fixed storage. Kept after a SUCCESSFUL registration on
	// purpose: the next refresh authenticates pre-emptively against the same
	// nonce with nc+1, which is what the nonce-count is FOR (RFC 7616 §3.4.3) and
	// what saves a 401 round trip per hour, per trunk.
	bool _haveChallenge              = false;
	char _chRealm[kMaxHost]          = {0};
	char _chNonce[kMaxNonce]         = {0};
	char _chOpaque[kMaxNonce]        = {0};
	char _chAlgorithm[kMaxAlgo]      = {0};
	char _chQop[kMaxQop]             = {0};
	bool _chStale                    = false;
	bool _chProxy                    = false;

	// nonce-count for the CACHED nonce. Reset to 0 whenever the nonce changes, so
	// the first request against a new nonce sends nc=00000001.
	uint32_t _nc = 0;

	// Cycle bookkeeping
	State    _state                = State::Idle;
	bool     _sendArmed            = false;
	uint64_t _sendAtMs             = 0;
	uint64_t _sentAtMs             = 0;
	uint64_t _refreshAtMs          = 0;
	uint64_t _bindingExpiresAtMs   = 0;
	uint32_t _grantedExpiresSec    = 0;
	uint32_t _requestedExpiresSec  = kDefaultExpiresSec;
	uint32_t _authAttempts         = 0;
	bool     _minExpiresApplied    = false;
	uint32_t _consecutiveFailures  = 0;
	uint32_t _registerAttempts     = 0;
	uint16_t _lastStatusCode       = 0;
	bool     _authenticated        = false;
	char     _lastError[kMaxError] = {0};
};

#endif // SIP_REGISTRATION_CLIENT_HPP
