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
// ── Staged persistence, and why the secret is not part of it (#986, #997) ─────
// A change used to write all four slots (4 x 6 keys + `active` = 25 nvs_set_* and
// a commit) with RequestsHandler::_mutex held. Everything EXCEPT the client secret
// is now copied into the NVS writer's staging slot (nvswriter::Key::Telephony) and
// the nvs_writer task applies it with writeSnapshot(), into the same keys the
// whole-table write always used, so the on-flash form and load() are unchanged.
// A "" return from a setter therefore means accepted and staged, not yet on flash.
//
// The secret is NOT staged: the slot, the queue item and the writer's scratch are
// never zeroised, and none of them may ever hold it. It is written separately, by
// the caller, synchronously: one nvs_set_str per slot whose secret changed (the
// live std::string's c_str(), no copy) and one commit, and nothing at all when no
// secret changed, which is every edit except the one that types a new secret and
// DELETE of a slot that had one. `_secretPending[i]` is the "changed since it was
// last written" flag; it is cleared only by a write that succeeded, so a failed
// write is retried by the next persist instead of being forgotten.
//
// Order: the stage first, then the secret. A stage that is refused (a factory reset
// is running, the writer never started, a value that does not fit) writes nothing
// at all, secret included, so flash keeps the previous, consistent configuration;
// the change stays live in RAM and its secret stays pending. clearAll() (the
// factory reset's erase) is neither staged nor split: it writes every key,
// synchronously, because a staged write is refused once the reset has begun.
//
// Thread-safety: this class is NOT internally locked. RequestsHandler owns the
// instance and serializes access under its _mutex (same pattern as TrunkConfig),
// which is also what makes the staging slot single-producer.

#include "FunctionRef.hpp"
#include "TelephonyProvider.hpp"
#include <cstddef>
#include <cstdint>
#include <string>

namespace nvswriter { class BlobWriter; }

class TelephonyApiConfig
{
public:
	static constexpr size_t kSlots = 4;            // hard table bound
	static constexpr size_t kMaxUrlLen = 128;      // field caps (display + NVS)
	static constexpr size_t kMaxFieldLen = 64;     // clientId / secret / routeDn
	static constexpr size_t kNoActiveSlot = kSlots; // activeSlot() when none

	// The staged snapshot (everything but the secrets): for each slot its type byte,
	// its enabled byte, then the base URL, the client id and the route DN, each in one
	// cell of kCellLen bytes (the value, then NULs; a cell's last byte is always NUL);
	// then the active-slot byte. Every cell is as wide as the longest value load() can
	// read back (it reads into kMaxUrlLen + 1 bytes), so a table that load() or
	// setSlot() produced always fits and a stale long value cannot jam the stage.
	// kSnapshotCap adds the NUL every staging slot keeps after its payload.
	static constexpr size_t kCellLen = kMaxUrlLen + 1;
	static constexpr size_t kSlotSnapshotLen = 2 + 3 * kCellLen;
	static constexpr size_t kSnapshotLen = kSlots * kSlotSnapshotLen + 1;
	static constexpr size_t kSnapshotCap = kSnapshotLen + 1;

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
	// Returns "" on success, else a short operator-facing error. "" means the
	// table is accepted and staged for the NVS writer (not yet on flash) and, if
	// the secret changed, written; see "Staged persistence" above. An error from
	// persisting ("Telephony config not persisted: ...") leaves the edit live in RAM.
	std::string setSlot(size_t idx, const Slot& s, bool keepSecret);

	// Wipe a slot (zeroize + persist). Returns "" on success. Same staging contract
	// as setSlot(); the slot's secret, if it had one, is erased synchronously.
	std::string clearSlot(size_t idx);

	// Wipe EVERY slot (zeroize), clearing the active-slot selection too, and write
	// the empty table SYNCHRONOUSLY, secrets included. Used by /api/factory-reset so
	// a reset never leaves a live carrier OAuth client_id/client_secret sitting in
	// flash under this class's own "tapicfg" namespace/file. It runs after
	// resetguard::begin(), when a staged write is refused by design, so it is not
	// staged. Returns "" on success, else the write's error; every slot is cleared in
	// RAM either way.
	std::string clearAll();

	// Mark a slot as the boot-time provider source (idx == kNoActiveSlot clears
	// the selection → legacy/loopback behavior). Persisted (staged). "" on success.
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

	// The nvs_writer's half (see "Staged persistence" above). emitSnapshot() walks a
	// staged snapshot in the order and with the keys the whole-table write always
	// used, minus the secret: s0type, s0en, s0url, s0id, s0dn, s1type ... then
	// "active". It checks that `blob` is exactly a snapshot BEFORE the first put and
	// returns false without one if it is not, and it stops at the first put that
	// returns false. It never builds a secret key. Pure: the host suite runs the same
	// walk the board does.
	static bool emitSnapshot(const char* blob, size_t len,
		FunctionRef<bool(const char* key, uint8_t value)> putU8,
		FunctionRef<bool(const char* key, const char* value)> putStr);

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// Applies a staged snapshot to NVS ("tapicfg"): every slot's two nvs_set_u8 and
	// three nvs_set_str, "active", then one nvs_commit. Called by the nvs_writer
	// task, never under _mutex. False if the snapshot is malformed or any step failed.
	static bool writeSnapshot(const char* blob, size_t len);
#endif

	// How many times persist() has written secrets (not a count of secrets), and
	// whether slot `idx` has a secret that is changed but not yet written. A change
	// that does not touch a secret leaves both alone.
	uint32_t secretWrites() const { return _secretWrites; }
	bool secretPending(size_t idx) const { return idx < kSlots && _secretPending[idx]; }

private:
	std::string persist();      // stage the table without secrets, then write changed secrets; "" when done
	std::string persistNow();   // write the whole table, secrets included, here, now; "" on success
	std::string writeSecretsNow();   // the changed secrets, synchronously (host: the whole file)
	void fillSnapshot(nvswriter::BlobWriter& w) const;   // the staged form, built in the writer's slot
	bool anySecretPending() const;
	void wipeSlot(size_t idx);          // zeroize one slot in RAM; its secret becomes pending if it had one
	static void scrub(std::string& s);  // best-effort zeroize-then-clear

	Slot _slots[kSlots];
	size_t _active = kNoActiveSlot;
	std::string _storePath = "pocketdial_tapi.cfg";
	bool _secretPending[kSlots] = {};   // secret changed since it was last written to the store
	uint32_t _secretWrites = 0;
};

#endif // TELEPHONY_API_CONFIG_HPP
