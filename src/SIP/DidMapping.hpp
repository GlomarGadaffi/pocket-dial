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
//   * A DID that is not a telephone number at all (a hand-edited store) is
//     still matched by exact string equality, so it can always be listed and
//     removed. E.164 equivalence is added on top of the old behaviour, never
//     in place of it.
//
// Thread-safety: this class is NOT internally locked, same caller-holds-lock
// convention as TelephonyApiConfig — RequestsHandler owns the instance
// (alongside TelephonyApiConfig) and serializes access under its own _mutex.
// persist() does blocking NVS/file I/O, so mutating calls (setMapping/
// removeMapping) belong on the config plane only — never under the
// packet-hot-path lock, and never as a step inside a real inbound call's
// handling. extensionForDid() itself is a bounded linear scan over at most
// POCKETDIAL_MAX_DID_MAPPINGS entries with no I/O, so it is safe to call from
// routeInboundAnchorCall() under a lock, the same as any other small
// in-memory lookup on this codebase's dashboard/config tables.

#include "PoolConfig.hpp"

#include <cstddef>
#include <string>
#include <vector>

class DidMapping
{
public:
	static constexpr size_t kMaxMappings = POCKETDIAL_MAX_DID_MAPPINGS; // hard table bound
	static constexpr size_t kMaxFieldLen = 32;                          // did / extension field cap

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

	// Add a new mapping, or update the extension of an existing one (matched
	// by `did`) in place — an update never consumes an additional slot, so it
	// can succeed even when the table is otherwise full. Returns "" on
	// success, else a short operator-facing error: "DID required",
	// "Extension required", "Field too long", "Field contains a control
	// character", or "DID mapping table full" (only for a genuinely NEW did
	// once all kMaxMappings slots are taken by other DIDs). Persists on
	// success.
	std::string setMapping(const std::string& did, const std::string& extension);

	// Remove the mapping for `did`, compacting the table so list() never has
	// gaps. "" on success, INCLUDING when no mapping existed (idempotent) —
	// the caller doesn't need to check existence first. Persists only when a
	// mapping actually changed (a no-op remove skips the blocking write).
	std::string removeMapping(const std::string& did);

	// Remove EVERY mapping and persist the now-empty table. Used by
	// /api/factory-reset so a reset never leaves the DID -> extension table
	// sitting in flash under this class's own "didmap" namespace/file. ""
	// on success, else a short operator-facing error (same persist() failure
	// modes as setMapping/removeMapping) -- the in-memory table is cleared
	// either way.
	std::string clearAll();

	// All configured mappings, in table order (oldest add first; updates keep
	// their original position).
	std::vector<Entry> list() const;

	// The local extension registered for `did`, or "" when no mapping exists
	// (also "" for an empty `did`). See the BOUNDARY comment at the top of
	// this file for who calls this and when.
	std::string extensionForDid(const std::string& did) const;

	size_t size() const { return _count; }
	static constexpr size_t capacity() { return kMaxMappings; }

	// Host builds: override the fallback config file path (tests use a temp
	// file). Default: "pocketdial_didmap.cfg" in the working directory.
	void setStorePath(const std::string& path) { _storePath = path; }

private:
	std::string persist();  // write the whole table; "" on success
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
