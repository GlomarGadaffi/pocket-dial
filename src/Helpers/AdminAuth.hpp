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

	// --- Issue #173: two-role privilege model ---
	//
	// "admin_*"/kDefaultUsername stays the SYSOP principal (unchanged identity
	// and wire behavior — every existing call site and test that authenticates
	// as "admin" keeps meaning "sysop"). A second, independent principal
	// ("owner_*") is layered on top: same PBKDF2 derivation, its own salt/hash/
	// username, persisted the same way. A session now carries a resolved Role
	// rather than being a bare yes/no.
	//
	// NO-OWNER FALLBACK: until an owner credential is ever set, a sysop session
	// satisfies an owner-gated action too (see sessionSatisfiesRole()) — see
	// that function's comment for why this is load-bearing, not a shortcut.
	//
	// THE OWNER SECRET IS NOT SOFTWARE-RECOVERABLE. There is no "forgot owner
	// password" flow, and no way to read one back once set (same as the
	// sysop credential and the DTMF PIN — see hashSecret()'s one-way
	// salted-iterated-SHA-256 storage). If the owner credential AND the DTMF
	// admin PIN are both lost, the only way back in is a factory reflash
	// with physical/USB access. This is a deliberate floor, not a gap: an
	// owner privilege that could be recovered over the network would not be
	// a meaningfully stronger boundary than the single sysop credential
	// this feature replaces.
	enum class Role : uint8_t
	{
		None  = 0,   // no session / expired / never authenticated
		Sysop = 1,
		Owner = 2,
	};

	// True iff an owner credential has ever been set (setOwnerCredential()).
	bool isOwnerProvisioned();

	// Set/replace the OWNER login credential. Same length/charset validation as
	// setLoginCredential(); additionally rejects a username identical to the
	// current sysop (admin_*) username — the two principals must be
	// distinguishable, both so a login attempt can be attributed to the right
	// lockout bucket (see authenticate()) and so "which one did I just log in
	// as" is never ambiguous to the operator. Returns false on any rejection
	// (nothing is changed) or persistence failure.
	bool setOwnerCredential(const std::string& username, const std::string& password);

	// Constant-time credential check that resolves to a ROLE rather than a
	// bool. `username` selects the principal to check against: if an owner
	// credential is set and `username` matches the owner's, this verifies
	// against the owner secret; otherwise it verifies against the sysop
	// secret (including the compiled-in default before setLoginCredential()
	// has ever run — identical to verifyCredential()'s pre-provisioning
	// branch). Returns Role::None on any failure. Brute-force accounting is
	// keyed on (clientKey, resolved-principal) — see the .cpp — so spraying
	// one principal's password cannot lock the other principal out, and the
	// aggregate backstop is tracked per principal for the same reason.
	//
	// This is the primary HTTP login path (sendApiAdminLogin) going forward.
	// verifyCredential() below is kept, UNCHANGED, purely so existing sysop-
	// only callers/tests keep working without churn — it does not know about
	// the owner principal at all.
	Role authenticate(const std::string& username, const std::string& password,
		const std::string& clientKey);

	// True while the (clientKey, principal-resolved-from-username) bucket
	// authenticate() would use is in cooldown — resolves the principal the
	// same way authenticate() does, WITHOUT hashing or accounting an attempt.
	// Mirrors isLockedOut(clientKey)'s role for verifyCredential(): a caller
	// checks this before paying the hash cost, and again afterward (once
	// authenticate() may have just engaged the lockout) to tell "wrong
	// credential" apart from "the cooldown just started" for the HTTP status
	// it sends back.
	bool isLockedOutForAuth(const std::string& username, const std::string& clientKey);

	// The role bound to a live session, or Role::None if the token is
	// unknown/expired. Read-only (does not slide expiry), same contract as
	// sessionCsrf().
	Role sessionRole(const std::string& token);

	// True iff a session with role `sessionRole(token)` may perform an action
	// gated at `need`. Owner-gated actions (`need == Role::Owner`) ALSO admit a
	// Sysop session, but ONLY while isOwnerProvisioned() is false: without this,
	// every already-deployed single-credential board would lose factory-reset,
	// OTA upload and the encrypted config-export block from its OWN dashboard
	// the instant it upgrades to this firmware, with no owner account yet to
	// grant them back. Once an owner exists, this floor closes — only an Owner
	// session satisfies an Owner gate from then on. Sysop-gated actions
	// (`need == Role::Sysop`) admit either role, since Owner is a superset.
	bool sessionSatisfiesRole(const std::string& token, Role need);

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
	// `role` defaults to Sysop so every pre-existing call site (this codebase's
	// tests call createSession() with no argument in several files) keeps its
	// old meaning exactly.
	std::string createSession(Role role = Role::Sysop);

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
	// Returns false if the persisted credential could not be erased (the in-RAM
	// state is cleared regardless). Not [[nodiscard]]: most callers are tests.
	bool clearCredential();
#if !(defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO))
	// Test-only: the next clearCredential() reports failure (the host store
	// never fails on its own), so /api/factory-reset's error path is reachable.
	void failNextEraseForTest();
#endif

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

	// --- Issue #186: password-based sealing for the config-export "secrets_enc"
	// block. Self-contained (no external crypto dependency), for the same
	// portability reason as the SHA-256 above: host and ESP must derive
	// byte-identical output from the same inputs. NOT a general crypto toolkit —
	// sized and shaped for exactly this one use (a few KB of JSON, encrypted
	// once, decrypted once), not for streaming or reuse elsewhere. ---

	constexpr size_t kAesKeyBytes   = 32;  // AES-256
	constexpr size_t kGcmNonceBytes = 12;  // 96-bit — the GCM-recommended size,
	                                       // the only size this implementation
	                                       // supports (no generic-length IV path)
	constexpr size_t kGcmTagBytes   = 16;  // 128-bit authentication tag
	constexpr size_t kKdfSaltBytes  = 16;
	// Iteration count for the export/import KDF. Higher than AdminAuth's own
	// kHashIterations (50000): this key protects a whole config backup — every
	// extension secret and trunk credential on the device — offline, with no
	// online lockout to slow a guesser down, so it earns a larger stretch cost.
	constexpr uint32_t kExportKdfIterations = 200000;

	// Fills `len` bytes with cryptographically-strong randomness (the hardware
	// CSPRNG on ESP, std::random_device-seeded on host — the exact same source
	// randomHex() already uses internally for session tokens/salts). Exposed
	// so a caller sealing a config-export block can generate its own KDF salt
	// and GCM nonce without duplicating the ESP-vs-host RNG selection this
	// file already has to make for its own salts.
	void secureRandomBytes(uint8_t* buf, size_t len);

	// PBKDF2-HMAC-SHA256 (RFC 8018). Writes exactly `dkLen` bytes to `out`.
	// Returns false only on a degenerate call (iterations == 0 or dkLen == 0);
	// any valid input succeeds. Pure function — no shared state, safe to call
	// off any thread.
	bool pbkdf2Sha256(const std::string& password, const uint8_t* salt, size_t saltLen,
		uint32_t iterations, uint8_t* out, size_t dkLen);

	// AES-256-GCM seal: encrypts `plaintext` under `key`/`nonce`, authenticating
	// `aad` alongside it without encrypting it. Appends the kGcmTagBytes
	// authentication tag to `outCiphertext`, so on return
	// outCiphertext.size() == plaintext.size() + kGcmTagBytes.
	void aesGcmSeal(const uint8_t key[kAesKeyBytes], const uint8_t nonce[kGcmNonceBytes],
		const std::string& aad, const std::string& plaintext, std::string& outCiphertext);

	// AES-256-GCM open: verifies the tag and, only if it matches, decrypts.
	// `ciphertextAndTag` must be at least kGcmTagBytes long. Returns false
	// (leaving `outPlaintext` untouched) on ANY authentication failure — a
	// wrong password and a tampered/truncated blob are deliberately
	// indistinguishable to the caller; nothing is ever returned from an
	// unauthenticated buffer.
	bool aesGcmOpen(const uint8_t key[kAesKeyBytes], const uint8_t nonce[kGcmNonceBytes],
		const std::string& aad, const std::string& ciphertextAndTag, std::string& outPlaintext);
}

#endif // ADMIN_AUTH_HPP
