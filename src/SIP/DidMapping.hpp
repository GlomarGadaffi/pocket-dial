#ifndef DID_MAPPING_HPP
#define DID_MAPPING_HPP

// ── DID -> extension inbound routing table ────────────────────────────────
// A bounded table mapping an inbound DID (the number/DN a PSTN caller dialed,
// as reported by a Telephony-API anchor's inbound event) to the local
// extension that should receive it.
//
// Today — in pocket-dial AND in drawbridge — there is exactly one configured
// route point (TelephonyApiConfig::Slot::routeDn) and any inbound call on it
// is RING-ALLed to every registered extension; see the RING-ALL comment on
// drawbridge's RequestsHandler::routeInboundAnchorCall() for the existing
// behavior this table is meant to narrow. This class is the bounded,
// persisted DATA MODEL for per-DID targeting — nothing more.
//
// BOUNDARY: extensionForDid() is called by RequestsHandler::routeInboundAnchorCall()
// (Stage B of the TelephonyAnchorClient port) — an inbound CallEvent looks the
// monitored route DN up here BEFORE the ring-all gather over _clientPool; an
// empty return (no mapping, or the mapped extension isn't currently
// registered) falls back to that existing ring-all behavior unchanged.
//
// Persistence mirrors TelephonyApiConfig exactly (see TelephonyApiConfig.hpp
// for the full rationale): NVS namespace "didmap" on ESP — deliberately
// separate from "tapicfg" and "pbxcfg" so a factory-reset of either doesn't
// collaterally wipe this table — or a 0600-permission config file on host.
// DIDs and extensions are not secrets, so there is no write-only/redaction
// model here, only the same bounded-table and validated-field discipline.
//
// ── DID identity: E.164 equivalence, not string equality (Issue #165) ──────
// Every lookup in this table (extensionForDid, and the update-in-place and
// remove paths through findIndex) matches on pbx::e164SameNumber() as well as
// on exact string equality. The same line is written many ways — a carrier
// reports "+15551234567", an operator types "(555) 123-4567" — and before
// #165 these did not match, so per-DID routing silently degraded to the
// ring-all fallback described in the BOUNDARY note above. Nothing errors in
// that case; a phone still rings; the operator's configuration is simply
// ignored. See E164.hpp for the normalization rule and the one false positive
// it knowingly accepts.
//
// Two consequences worth knowing at the call sites:
//   * setMapping() with a DIFFERENT RENDERING of an existing DID updates that
//     entry in place rather than adding a second one. That is deliberate: two
//     rows that both match one inbound call would make routing depend on
//     table order, which is not something an operator can see or control.
//     The update also adopts the caller's rendering as the stored `did`
//     (not just the extension), so list()/the dashboard show the spelling
//     most recently typed rather than whichever one landed first.
//   * A DID that is not a telephone number at all (a hand-edited store) is
//     still matched by exact string equality, so it can always be listed and
//     removed. E.164 equivalence is added on top of the old behaviour, never
//     in place of it.
//
// ── Staged persistence (#986 slice 4) ────────────────────────────────────────
// setMapping()/removeMapping()/clearAllStaged() no longer write NVS under the
// caller's lock (a table write is 2 * kMaxMappings nvs_set_str plus a commit,
// measured at 52.9 ms under RequestsHandler::_mutex during a config import).
// They copy a snapshot of the table into the NVS writer's staging slot
// (nvswriter::Key::DidMap) and return; the nvs_writer task applies it with
// writeSnapshot(), slot by slot, with the same keys persist() always used, so
// the on-flash form is unchanged and load() reads it as before. The in-memory
// table is already right when the call returns -- only the flash copy lags -- so
// a "" return means accepted and staged, not yet persisted. A restart or power
// loss before the writer's commit loses the change.
//
// clearAll() stays synchronous: /api/factory-reset calls it after
// resetguard::begin(), when staging is refused by design, and it must leave the
// PII table erased before it answers.
//
// The staging slot has ONE producer: every caller of setMapping/removeMapping/
// clearAll*/persist holds RequestsHandler::_mutex.
//
// Thread-safety: this class is NOT internally locked, same caller-holds-lock
// convention as TelephonyApiConfig — RequestsHandler owns the instance
// (alongside TelephonyApiConfig) and serializes access under its own _mutex.
// clearAll() does blocking NVS/file I/O, so it belongs on the factory-reset path
// only. extensionForDid() itself is a bounded linear scan over at most
// POCKETDIAL_MAX_DID_MAPPINGS entries with no I/O, so it is safe to call from
// routeInboundAnchorCall() under a lock, the same as any other small
// in-memory lookup on this codebase's dashboard/config tables.

#include "FunctionRef.hpp"
#include "PoolConfig.hpp"

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace nvswriter { class BlobWriter; }

class DidMapping
{
public:
	static constexpr size_t kMaxMappings = POCKETDIAL_MAX_DID_MAPPINGS; // hard table bound
	static constexpr size_t kMaxFieldLen = 32;                          // did / extension field cap

	// The staged snapshot: for each of the kMaxMappings slots, the did and then
	// the extension, each in one cell of kSlotCellLen bytes (the value, then
	// NULs; a cell's last byte is always NUL). kSnapshotCap adds the NUL every
	// staging slot keeps after its payload.
	static constexpr size_t kSlotCellLen = kMaxFieldLen + 1;
	static constexpr size_t kSnapshotLen = 2 * kMaxMappings * kSlotCellLen;
	static constexpr size_t kSnapshotCap = kSnapshotLen + 1;

	struct Entry
	{
		std::string did;        // inbound DID as the provider reports it (E.164 or local form)
		std::string extension;  // local extension that should receive calls to this DID
	};

	// Load the table from the backing store (NVS "didmap" on ESP, the config
	// file on host). Missing store -> empty table. Always resets in-memory
	// state first, so a re-load is idempotent. Defensive against a store that
	// was hand-edited or written by a build with a larger cap: any slot with
	// an empty/missing field is skipped rather than kept as a hole, and
	// loading never reads past kMaxMappings.
	void load();

	// Add a new mapping, or update an existing one (matched by `did`, which
	// may be a different rendering of the same line — see the ── DID
	// identity ── note above) in place — an update never consumes an
	// additional slot, so it can succeed even when the table is otherwise
	// full. An update replaces BOTH the stored `did` and the extension with
	// the values just passed in, so a re-set never leaves a stale rendering
	// behind. Returns "" on success, else a short operator-facing error:
	// "DID required", "Extension required", "Field too long", "Field
	// contains a control character", or "DID mapping table full" (only for a
	// genuinely NEW did once all kMaxMappings slots are taken by other
	// DIDs). Stages the new table for the NVS writer on success ("" then means
	// accepted and staged, not yet on flash); a table that could not be staged
	// ("DID table not persisted: ...": a factory reset is running, a field does
	// not fit its cell, the writer is not running) is an error, and the in-memory
	// table has changed all the same, as it always did when a write failed.
	std::string setMapping(const std::string& did, const std::string& extension);

	// Remove the mapping for `did`, compacting the table so list() never has
	// gaps. "" on success, INCLUDING when no mapping existed (idempotent) —
	// the caller doesn't need to check existence first. Stages only when a
	// mapping actually changed (a no-op remove stages nothing).
	std::string removeMapping(const std::string& did);

	// Remove EVERY mapping and persist the now-empty table SYNCHRONOUSLY. Used by
	// /api/factory-reset so a reset never leaves the DID -> extension table
	// sitting in flash under this class's own "didmap" namespace/file, and so the
	// reset can report whether it did. Its one caller runs after
	// resetguard::begin(), when a staged write would be refused, which is why this
	// is not staged. "" on success, else a short operator-facing error ("NVS open
	// failed", "NVS write failed"; the host's file errors) -- the in-memory table
	// is cleared either way.
	std::string clearAll();

	// clearAll() for the config import, which replaces the table and must not hold
	// the engine lock across a flash write: the empty table is staged like any
	// other change, so the import's clear plus N setMapping() calls leave one
	// snapshot for the writer, the last. Same return contract as setMapping().
	std::string clearAllStaged();

	// All configured mappings, in table order (oldest add first; updates keep
	// their original position).
	std::vector<Entry> list() const;

	// The local extension registered for `did`, or "" when no mapping exists
	// (also "" for an empty `did`). See the BOUNDARY comment at the top of
	// this file for who calls this and when.
	std::string extensionForDid(const std::string& did) const;

	// Issue #826: true if any DID maps to `extension` (zero-touch must not hand
	// a new phone someone's inbound number). Linear over _count; no heap.
	bool isTarget(std::string_view extension) const
	{
		for (size_t i = 0; i < _count; ++i)
		{
			if (_entries[i].extension == extension) return true;
		}
		return false;
	}

	size_t size() const { return _count; }
	static constexpr size_t capacity() { return kMaxMappings; }

	// Host builds: override the fallback config file path (tests use a temp
	// file). Default: "pocketdial_didmap.cfg" in the working directory.
	void setStorePath(const std::string& path) { _storePath = path; }

	// The nvs_writer's half (see "Staged persistence" above). emitSnapshot()
	// walks a staged snapshot in the exact order and with the exact keys the
	// whole-table write always used: put("m0did", ...), put("m0ext", ...),
	// put("m1did", ...) ... for every slot, "" for an unused one. It checks that
	// `blob` is exactly a snapshot BEFORE the first put and returns false without
	// one if it is not; it stops at the first put that returns false. Pure: the
	// host suite runs the same walk the board does.
	static bool emitSnapshot(const char* blob, size_t len,
		FunctionRef<bool(const char* key, const char* value)> put);

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// Applies a staged snapshot to NVS ("didmap" namespace): every slot's two
	// nvs_set_str, then one nvs_commit. Called by the nvs_writer task, never under
	// _mutex. False if the snapshot is malformed or any step failed.
	static bool writeSnapshot(const char* blob, size_t len);
#endif

private:
	std::string persist();     // stage the whole table for the writer; "" when staged
	std::string persistNow();  // write the whole table here, now; "" on success
	void fillSnapshot(nvswriter::BlobWriter& w) const;   // the staged form, built in the writer's slot
	void clearEntries();
	// Index of the live entry for `did`, or kMaxMappings if none. Linear scan
	// over _count entries — no heap, no I/O.
	size_t findIndex(const std::string& did) const;

	// DID identity for every lookup in this table: exact string match, OR
	// E.164 equivalence (Issue #165). See the ── DID identity ── note at the
	// top of this file.
	static bool sameDid(const std::string& a, const std::string& b);

	static bool fieldValid(const std::string& s);

	Entry _entries[kMaxMappings];
	size_t _count = 0;
	std::string _storePath = "pocketdial_didmap.cfg";
};

#endif // DID_MAPPING_HPP
