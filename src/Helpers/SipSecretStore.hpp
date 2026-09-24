#ifndef SIP_SECRET_STORE_HPP
#define SIP_SECRET_STORE_HPP

// SipSecretStore: per-extension SIP digest credential store.
//
// Mirrors AdminAuth's NVS open/set/commit pattern, but with one crucial
// difference: AdminAuth stores a ONE-WAY salted SHA-256 of the admin PIN (you can
// only verify, never recover). SIP digest CANNOT use a one-way hash of the secret
// — the server must recompute MD5(HA1:nonce:...:HA2), which requires HA1. So this
// store persists HA1 = MD5(ext:realm:secret) per extension. HA1 is plaintext-
// equivalent for impersonating that one extension, hence:
//
//   SECURITY NOTE: HA1-at-rest is sensitive. On the device it lives in NVS, which
//   is NOT encrypted by default. A follow-up should enable ESP-IDF flash
//   encryption (and/or NVS encryption) so a flash dump does not yield every
//   extension's HA1. Tracked as an M2 hardening item.
//
// Realm is fixed to kRealm ("pocketdial").
//
// Storage layout (ESP): NVS namespace "sipauth", one string key per extension:
//   key   = "ext_" + <sanitized extension>          (NVS keys ≤ 15 chars)
//   value = HA1 (32 lowercase hex chars)
// Plus an index key "idx" holding a newline-separated list of secured extensions
// (so securedExtensions() does not need NVS enumeration, which is awkward to use).
//
// Host build: an in-memory std::map IS the store (no NVS). Same API, same logic.
//
// Thread-safety: all shared state is guarded by an internal std::mutex.

#include <string>
#include <vector>
#include <optional>

namespace SipSecretStore
{
	// The digest realm. Must match what the WWW-Authenticate challenge advertises
	// and what the client echoes back in its Authorization.
	inline constexpr const char* kRealm = "pocketdial";

	// Longest extension we will key on. Bounds the NVS key ("ext_" + ext ≤ 15).
	constexpr size_t kMaxExtLen = 11;

	// Default length of an auto-generated secret. Drawn from a 54-symbol
	// unambiguous alphabet (~5.75 bits/char) by makeRandomSecret(), so 24 chars
	// is ~138 bits of entropy — comfortably past the 128-bit floor and not
	// brute-forceable. (The previous 12-char/IDGen path was ≤32 effective bits.)
	constexpr int kGeneratedSecretLen = 24;

	// Generate a fresh, CSPRNG-backed random secret of `len` characters from an
	// unambiguous alphabet (no 0/O/1/I/l). This is the SINGLE audited entropy
	// source for SIP secrets — generateSecret() and the TUI [G] generator both
	// call it. Each character is drawn from a fresh CSPRNG byte (esp_random() on
	// device, std::random_device on host) with rejection sampling to remove modulo
	// bias. Does NOT persist anything — pair with setSecret(), or use
	// generateSecret() to do both. Returns "" if len <= 0.
	std::string makeRandomSecret(int len = kGeneratedSecretLen);

	// Prewarm the in-RAM HA1 cache from NVS for every secured extension. Call once
	// at boot (off the REGISTER hot path) so the first Secure REGISTER does not pay
	// a flash read while holding the registrar mutex. No-op on host. Thread-safe.
	void warmCache();

	// Compute + store HA1 for `ext` from a plaintext secret. Overwrites any
	// existing secret for that extension. Returns false on an invalid extension
	// (empty / too long / unsafe chars), an empty secret, or persistence failure.
	bool setSecret(const std::string& ext, const std::string& plaintextSecret);

	// Store a ready-made HA1 for `ext` (32 lowercase hex chars) -- the config
	// import's restore path (#482: HA1s travel only inside the password-
	// encrypted export block). Same validation, persistence and cache update as
	// setSecret(); false on an invalid extension or a malformed HA1.
	bool setHa1(const std::string& ext, const std::string& ha1);

	// Generate a fresh random secret for `ext`, store its HA1, and return the
	// PLAINTEXT secret (the only chance to read it — only HA1 is persisted) so the
	// caller can show/deliver it. Returns std::nullopt on failure.
	std::optional<std::string> generateSecret(const std::string& ext);

	// The stored HA1 for `ext`, or std::nullopt if none.
	std::optional<std::string> getHa1(const std::string& ext);

	// True iff `ext` has a stored secret.
	bool hasSecret(const std::string& ext);

	// Remove `ext`'s secret. Returns true if it existed and was removed (or if the
	// erase otherwise succeeded). No-op-safe on an unknown extension.
	bool clearSecret(const std::string& ext);

	// All extensions that currently have a secret. Order is unspecified.
	std::vector<std::string> securedExtensions();
}

#endif // SIP_SECRET_STORE_HPP
