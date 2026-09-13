#ifndef TELEPHONY_API_CONFIG_HPP
#define TELEPHONY_API_CONFIG_HPP

// ── "Telephony APIs" credential table ─────────────────────────────────────────
// A bounded, fixed-size table of per-provider credential slots: provider type,
// base URL / FQDN, client id, client secret, and a route-point DN (or the
// provider's equivalent origination identity). One slot may be marked ACTIVE —
// that slot selects the boot-time anchor provider via TelephonyProviderRegistry.
//
// Secret-handling model (read this before touching the class):
//   * Secrets are WRITE-ONLY from every UI/API perspective. The display-safe
//     `SlotView` carries only `secretSet` — the value itself never reaches a
//     renderer, an HTTP response, or a log line. Only `bootSlot()` (engine-only,
//     used once at boot to init the provider) returns the plaintext.
//   * Buffers are best-effort zeroized before release (`scrub()` overwrites the
//     std::string storage in place before clearing). std::string cannot give a
//     hard guarantee against reallocation copies; treat this as hygiene, not a
//     security boundary.
//   * AT-REST PROTECTION IS THE PLATFORM'S JOB: on ESP the values land in NVS
//     namespace "tapicfg" in plaintext unless flash encryption + NVS encryption
//     are enabled on the device. Do NOT describe this store as "secure storage"
//     anywhere unless that platform feature is actually on. On host builds the
//     fallback is a 0600-permission config file (plaintext, same caveat).
//
// Thread-safety: this class is NOT internally locked. RequestsHandler owns the
// instance and serializes access under its _mutex (same pattern as TrunkConfig).

#include "TelephonyProvider.hpp"
#include <string>
#include <cstddef>

class TelephonyApiConfig
{
public:
	static constexpr size_t kSlots = 4;            // hard table bound
	static constexpr size_t kMaxUrlLen = 128;      // field caps (display + NVS)
	static constexpr size_t kMaxFieldLen = 64;     // clientId / secret / routeDn
	static constexpr size_t kNoActiveSlot = kSlots; // activeSlot() when none

	// Full slot — engine/boot side only. Never hand this to a UI layer.
	struct Slot
	{
		TelephonyProviderType type = TelephonyProviderType::Loopback;
		bool enabled = false;
		std::string baseUrl;
		std::string clientId;
		std::string secret;     // never log, never echo
		std::string routeDn;
	};

	// Display-safe projection: the secret is reduced to set-or-not.
	struct SlotView
	{
		TelephonyProviderType type = TelephonyProviderType::Loopback;
		bool enabled = false;
		bool implemented = false;  // telephonyProviderImplemented(type)
		bool active = false;       // this slot selects the boot provider
		std::string baseUrl;
		std::string clientId;
		std::string routeDn;
		bool secretSet = false;
	};

	// Load the table from the backing store (NVS "tapicfg" on ESP, the config
	// file on host). Missing store → all-default slots, no active slot.
	void load();

	// Apply edits to a slot and persist. `keepSecret`=true ignores `s.secret`
	// and retains the stored one (the UI sends an empty field for "unchanged").
	// Returns "" on success, else a short operator-facing error.
	std::string setSlot(size_t idx, const Slot& s, bool keepSecret);

	// Wipe a slot (zeroize + persist). Returns "" on success.
	std::string clearSlot(size_t idx);

	// Wipe EVERY slot (zeroize + persist), clearing the active-slot selection
	// too. Used by /api/factory-reset so a reset never leaves a live carrier
	// OAuth client_id/client_secret sitting in flash under this class's own
	// "tapicfg" namespace/file. Returns "" only if every slot persisted
	// cleanly, else the last non-empty per-slot error (each slot is still
	// cleared and persisted regardless).
	std::string clearAll();

	// Mark a slot as the boot-time provider source (idx == kNoActiveSlot clears
	// the selection → legacy/loopback behavior). Persisted. "" on success.
	std::string setActiveSlot(size_t idx);
	size_t activeSlot() const { return _active; }

	// Display-safe snapshot of one slot (default SlotView when idx is out of range).
	SlotView view(size_t idx) const;

	// Engine-only plaintext access for boot-time provider init. nullptr when idx
	// is out of range. Callers must not log or forward the secret.
	const Slot* bootSlot(size_t idx) const;

	// Host builds: override the fallback config file path (tests use a temp dir).
	// Default: "pocketdial_tapi.cfg" in the working directory.
	void setStorePath(const std::string& path) { _storePath = path; }

private:
	std::string persist();              // write the whole table; "" on success
	static void scrub(std::string& s);  // best-effort zeroize-then-clear

	Slot _slots[kSlots];
	size_t _active = kNoActiveSlot;
	std::string _storePath = "pocketdial_tapi.cfg";
};

#endif // TELEPHONY_API_CONFIG_HPP
