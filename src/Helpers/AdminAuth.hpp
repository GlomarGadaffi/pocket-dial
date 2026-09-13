#ifndef ADMIN_AUTH_HPP
#define ADMIN_AUTH_HPP

// AdminAuth: a small, self-contained, platform-portable admin credential and
// session manager for the HTTP dashboard.
//
// Why this exists: the dashboard's state-changing endpoints (/api/kill,
// /api/wifi/connect, /api/wifi/mode_ap, /api/factory-reset) were protected only
// by a same-origin/CSRF check. The device ships an OPEN WiFi AP, so any device
// that joins the AP could disconnect calls, rewrite WiFi credentials, switch
// modes, or factory-reset. AdminAuth adds a login-gated session layer on top of
// the existing same-origin check (defense in depth).
//
// Credential model: the web dashboard uses a username + password (no more
// "unprovisioned = open to anyone on the LAN" window — the device ships with a
// well-known default credential, kDefaultUsername/kDefaultPassword, that MUST
// be changed before any other admin action is allowed; see needsInitialSetup()
// and HttpServer::requireAdmin()'s enforcement of it). The phone-keypad DTMF
// admin menu (*PIN#code — NTP resync, topology switch, factory reset) is a
// SEPARATE, independent numeric secret: a keypad cannot type a username, and
// there is deliberately no default for it — the DTMF menu stays fully disabled
// until a PIN is explicitly set during initial setup (or later).
//
// Design constraints:
//   * Dependency-free beyond the C++17 standard library and the platform guards.
//   * Identical hashing on host and ESP (a self-contained, public-domain SHA-256
//     lives in AdminAuth.cpp) so a credential is portable and verifiable the same
//     way everywhere — and so the host build needs no external crypto dependency.
//   * Credential persistence: NVS namespace "storage" on ESP (keys admin_user /
//     admin_pw_salt / admin_pw_hash / admin_pin_salt / admin_pin_hash); an
//     in-process static on host (documented: host has no NVS).
//   * Thread-safety: all shared state is guarded by an internal std::mutex. The
//     HTTP server handles one client at a time per accept, but it detaches a
//     thread per connection, so concurrent access is possible.

#include <string>
#include <cstdint>

namespace AdminAuth
{
	// --- Tunables (documented in docs/THREAT_MODEL.md) ---
	constexpr size_t   kMinUsernameLength = 1;        // reject an empty username
	constexpr size_t   kMaxUsernameLength = 32;
	constexpr size_t   kMinPasswordLength = 8;        // reject passwords shorter than this
	constexpr size_t   kMaxPasswordLength = 128;      // sanity cap, not a security boundary
	constexpr size_t   kMinDtmfPinLength  = 4;        // reject DTMF PINs shorter than this
	constexpr size_t   kMaxDtmfPinLength  = 16;
	// Shipped default so the dashboard is reachable and usable out of the box;
	// needsInitialSetup() stays true (and every admin action except changing
	// this credential stays refused — see HttpServer::requireAdmin()) until the
	// operator replaces it. There is deliberately NO default DTMF PIN — the
	// DTMF admin menu stays disabled until one is explicitly set.
	constexpr const char* kDefaultUsername = "admin";
	constexpr const char* kDefaultPassword = "admin";
	constexpr size_t   kSessionTokenHex   = 32;       // >= 32 hex chars (128 bits)
	constexpr size_t   kMaxSessions       = 8;        // fixed-capacity session table
	// 30 min, SLIDING: every successful validateSession() pushes the deadline out
	// by a full TTL so an actively-working admin is not logged out mid-session.
	constexpr uint64_t kSessionTtlMs      = 30ULL * 60ULL * 1000ULL;
	constexpr int      kMaxFailedAttempts = 5;        // consecutive failures before lockout
	constexpr uint64_t kLockoutMs         = 60ULL * 1000ULL;           // 60 s cooldown
	constexpr uint32_t kHashIterations    = 50000;    // PBKDF-style iterated SHA-256 rounds
	constexpr size_t   kCsrfTokenHex      = 32;       // per-session CSRF token (128 bits)
	// Brute-force accounting is per-client, not global. A single global counter
	// lets one attacker lock the legitimate admin out of new logins (docs/THREAT_MODEL.md
	// D-3), and it shares one budget across every peer on the AP. Buckets are a
	// fixed-size, least-recently-seen-evicted table so a flood of distinct source
	// addresses cannot grow memory. Shared by both the web login and the DTMF PIN
	// (DTMF uses the unkeyed "" bucket, same as before this credential split).
	constexpr size_t   kMaxAttemptBuckets = 8;
	// Consecutive lockouts back off exponentially: kLockoutMs << min(trips-1, this).
	// 4 caps a single client at 60 s << 4 = 16 minutes per window.
	constexpr int      kMaxLockoutShift   = 4;
	// Aggregate backstop across ALL clients. Per-client buckets alone are not
	// enough on a shared link: source addresses are spoofable, so an attacker who
	// rotates them gets a fresh bucket — and a fresh escalation ladder — every
	// few guesses, which would be a WEAKER position than the single global
	// counter this replaced. This ceiling bounds the aggregate guess rate no
	// matter how many identities the attacker invents. It is set well above
	// kMaxFailedAttempts so ordinary fat-fingering never reaches it, which is
	// what keeps the D-3 self-DoS from coming back with it.
	constexpr int      kMaxFailedAttemptsGlobal = 20;

	// True iff a REAL (operator-set, non-default) login credential is stored.
	// False on a freshly-flashed device, and again immediately after
	// clearCredential() — in both cases kDefaultUsername/kDefaultPassword is
	// what verifyCredential() accepts until setLoginCredential() is called.
	bool isProvisioned();

	// True iff the device is still running on the default login credential and
	// therefore must not be allowed to do anything else yet. Equivalent to
	// !isProvisioned(); named separately so call sites read as intent
	// ("is setup required") rather than a double negative.
	bool needsInitialSetup();

	// Set/replace the admin login credential. Enforces the username/password
	// length bounds above and rejects a username containing whitespace or
	// control characters. Generates a fresh random salt, computes a salted,
	// iterated SHA-256 hash of the password, and persists username + salt +
	// hash (NVS on ESP, in-memory on host). Returns false if either field is
	// out of bounds or persistence fails.
	bool setLoginCredential(const std::string& username, const std::string& password);

	// Constant-time verification of a candidate username+password. Honors the
	// brute-force lockout: returns false while locked out (without even
	// hashing). On a correct credential, resets the failure counter. On a
	// wrong one, increments it and may engage the lockout. Before
	// setLoginCredential() has ever been called, only kDefaultUsername/
	// kDefaultPassword verifies successfully (still subject to the same
	// lockout accounting — the default is not a bypass of brute-force
	// protection). `clientKey` is the HTTP client's IP; accounted the same way
	// verifyDtmfPin's unkeyed bucket is (see there for why an empty key is
	// used for callers with no HTTP peer, though the web login always has one).
	bool verifyCredential(const std::string& username, const std::string& password,
		const std::string& clientKey);

	// True while the brute-force lockout is engaged (cooldown not yet elapsed).
	bool isLockedOut();

	// True while `clientKey`'s own cooldown is engaged. Other clients are unaffected.
	bool isLockedOut(const std::string& clientKey);

	// True iff a DTMF admin PIN has been explicitly set. False on a freshly-
	// flashed device and again after clearCredential() — there is no default,
	// so the *PIN#code menu is entirely unreachable until this is true.
	bool dtmfPinIsSet();

	// Set/replace the DTMF admin PIN. Enforces kMinDtmfPinLength/
	// kMaxDtmfPinLength and a digits-only charset (a keypad cannot send
	// anything else). Same salted/iterated-hash/persist story as
	// setLoginCredential(), in its own NVS keys so clearing/rotating one never
	// touches the other.
	bool setDtmfPin(const std::string& pin);

	// Constant-time verification of a candidate DTMF PIN. Returns false
	// unconditionally (no hashing, not even a lockout check) if dtmfPinIsSet()
	// is false. Uses the unkeyed ("") attempt bucket — the DTMF path has no
	// HTTP peer to key accounting on — shared with any other unkeyed caller.
	bool verifyDtmfPin(const std::string& pin);

	// Create a new server-side session and return its opaque random token
	// (kSessionTokenHex hex chars). Evicts the oldest/expired entry if the table
	// is full. Returns an empty string only on catastrophic RNG failure.
	std::string createSession();

	// True iff the token names a live (non-expired) session.
	bool validateSession(const std::string& token);

	// The CSRF token bound to a live session, or "" if the session is unknown or
	// expired. Generated with the session and stored beside it, so it is bound by
	// storage rather than derived from anything the client controls. It is rendered
	// into the dashboard page (never set as a cookie), so a cross-site page cannot
	// read it even though the browser would happily attach the cookie.
	std::string sessionCsrf(const std::string& token);

	// Constant-time check of a submitted CSRF token against the one bound to
	// `token`'s session. False if the session is unknown/expired or the token does
	// not match. Does NOT slide the session expiry (validateSession does that).
	bool validateCsrf(const std::string& token, const std::string& csrf);

	// Milliseconds until `token`'s session expires, or 0 if the token is
	// unknown/expired. Read-only — unlike validateSession(), this does NOT
	// slide the expiry, so a dashboard polling this to show a countdown
	// doesn't itself keep resetting the countdown it is displaying.
	uint64_t sessionRemainingMs(const std::string& token);

	// Destroy a session by token (logout). No-op if unknown.
	void destroySession(const std::string& token);

	// Wipe the stored login credential AND the DTMF PIN AND all live sessions,
	// and reset the lockout state. Used by factory-reset so the device returns
	// to the default-credential/needs-initial-setup state.
	void clearCredential();

	// True iff a REAL (non-default) login credential is persisted in NVS.
	// Intended for the boot provisioning gate in app_main() — called before
	// the RTOS scheduler has spawned real-time tasks, so it may block briefly
	// on NVS I/O without issue. Equivalent to isProvisioned(), kept as a
	// separate name/entry point because it reads NVS directly rather than
	// through the in-memory AuthState cache (the boot gate runs before that
	// cache would otherwise be populated).
	// On non-ESP (host) builds this delegates to isProvisioned() so the host
	// unit tests exercise the same code path.
	bool credentialIsSet();
}

#endif // ADMIN_AUTH_HPP
