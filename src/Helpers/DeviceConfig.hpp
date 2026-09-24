#ifndef DEVICE_CONFIG_HPP
#define DEVICE_CONFIG_HPP

// DeviceConfig: SoftAP security settings + the flash-time configuration seed.
//
// Two responsibilities, kept together because they write the same NVS keys:
//
//   1. **SoftAP security** (`ap_secure`, `ap_psk`). docs/THREAT_MODEL.md §6 and
//      docs/FEATURE_ROADMAP.md name WPA2 on the SoftAP as the single
//      highest-leverage hardening in the project: it encrypts the dashboard,
//      SIP signalling AND RTP media in one change, gates association, needs no
//      per-device certificates, and produces no browser warning — everything
//      self-signed HTTPS would not do (§6 rejects TLS as the primary control).
//
//      `ap_secure` DEFAULTS TO FALSE. Turning WPA2 on is a breaking change for
//      an already-deployed fleet — every phone must be re-associated with the
//      new passphrase — so an existing device keeps its open AP across a
//      firmware update and is switched over deliberately, from the dashboard or
//      at flash time (see 2). `ap_psk` is generated on first access regardless,
//      so the toggle always has a real passphrase to display.
//
//   2. **The flash-time configuration seed** (`cfgseed`). The browser flasher
//      (docs/flasher/index.html) writes a small fixed-layout blob to the
//      `cfgseed` partition so a board can be configured at install time. This
//      matters most on the headless `esp32s3-wifi` / `esp32s3-eth` variants,
//      where there is no screen to read a generated passphrase off.
//
//      A seed blob, NOT an NVS image, deliberately: generating a valid NVS
//      partition in JavaScript means reimplementing page headers, entry-state
//      bitmaps, span entries and CRCs, and writing it at 0x9000 would destroy
//      the saved WiFi credentials and admin PIN. A raw fixed-layout partition
//      follows the pattern partitions.csv already documents for `prompts`.
//
//      The firmware NEVER WRITES the seed partition — it only reads it — so the
//      erase-before-write discipline documented in partitions.csv for raw
//      (subtype 0x40/0x41) partitions does not apply here.
//
// Persistence: NVS namespace "storage" (the same one AdminAuth and the
// transports use), keys `ap_secure` (u8), `ap_psk` (str), `cfgseed_gen` (u32).
// All three are erased by /api/factory-reset, so a factory reset returns the
// board to its as-flashed configuration rather than to a hardcoded default.
//
// Host builds: this file compiles on the desktop/CI simulator, where there is no
// NVS and no `cfgseed` partition. Settings live in process memory for a single
// run (the AdminAuth.cpp pattern) and applyFlashSeed() is a no-op. This keeps
// the host test suite able to exercise the dashboard endpoints.

#include <string>
#include <cstdint>
#include <cstddef>

namespace DeviceConfig
{
	// ---------------------------------------------------------------------
	// Tunables
	// ---------------------------------------------------------------------

	// Generated passphrase length, in characters, from kPskAlphabet below.
	// 20 chars over a 32-symbol alphabet is 100 bits — far above what WPA2-PSK
	// offline handshake cracking can reach, and still readable off a screen.
	constexpr size_t kGeneratedPskChars = 20;

	// WPA2-PSK passphrase bounds, from IEEE 802.11i. Enforced on BOTH the
	// dashboard path and the seed path; esp_wifi rejects anything outside it.
	constexpr size_t kMinPskChars = 8;
	constexpr size_t kMaxPskChars = 63;

	// Crockford-style alphabet: no 0/O, no 1/I/L, no U. A passphrase read off a
	// small LCD or a serial log and retyped into a phone must not be ambiguous.
	constexpr const char* kPskAlphabet = "23456789ABCDEFGHJKMNPQRSTVWXYZ";

	// ---------------------------------------------------------------------
	// SoftAP security
	// ---------------------------------------------------------------------

	// True iff the standalone SoftAP should come up WPA2-PSK rather than open.
	// Defaults to FALSE on a device that has never been told otherwise — see the
	// fleet-compatibility note at the top of this file.
	bool isApSecure();

	// Persist the WPA2-on/off choice. Returns false if persistence failed.
	bool setApSecure(bool secure);

	// The AP passphrase. Generated (kGeneratedPskChars from kPskAlphabet, via the
	// hardware CSPRNG on device) and persisted on first access if none is stored,
	// so this never returns a string too short for WPA2. Callers may display it:
	// it is meant to be shown on the LVGL onboarding screen and logged to serial
	// on headless builds.
	std::string getApPsk();

	// Replace the stored passphrase with a freshly generated one and return it.
	// Existing associations break at the next AP restart — that is the point.
	std::string regenerateApPsk();

	// Overwrite the stored passphrase. Returns false (leaving the stored value
	// untouched) if `psk` is outside [kMinPskChars, kMaxPskChars] or contains a
	// byte outside printable ASCII, which esp_wifi would reject anyway.
	bool setApPsk(const std::string& psk);

	// ---------------------------------------------------------------------
	// WiFi station config readback (issue #186)
	// ---------------------------------------------------------------------
	//
	// sendApiWifiConnect()/sendApiWifiModeAp() (HttpServer.cpp) and the DTMF
	// topology-switch code (DtmfFeatureCodes.cpp) write "wifi_ssid"/"wifi_pass"/
	// "wifi_mode" directly to NVS namespace "storage" — the SAME namespace this
	// file already owns for ap_secure/ap_psk — without going through any shared
	// accessor. These getters/setters read/write those SAME keys so the config
	// export/import feature can round-trip them, WITHOUT changing any existing
	// writer's behavior (none of the getters below is ever cached: every ESP
	// call opens NVS fresh, because ANY of those other writers can change the
	// value between calls and a stale in-memory mirror would silently diverge
	// from what a plain reboot actually applies).
	//
	// `mode`: 0 = captive-portal default, 1 = STATION, 2 = AP — matches the
	// existing "wifi_mode" convention (see the cfgseed wire format above).

	// The stored upstream SSID, or "" if never set. Plaintext — see #186.
	std::string getWifiSsid();
	// The stored operating mode (0/1/2 as above), or 0 if never set.
	uint8_t getWifiMode();
	// The stored upstream WiFi password, or "" if none. PASSWORD-GATED in the
	// export feature — never included in a plaintext export.
	std::string getWifiPassword();

	// Writes ssid + mode ONLY (the plaintext-importable half). Does not touch
	// the stored password and does NOT reboot — unlike sendApiWifiConnect(),
	// which is a live user action that reasonably reboots immediately, an
	// import may be restoring several fields in one request and a mid-import
	// reboot would abandon the rest. The mode change (like ap-security's)
	// takes effect at the next boot. Returns false if `ssid` is empty or
	// longer than 32 octets (IEEE 802.11) or `mode` is not 0/1/2; on ESP, also
	// false on an NVS write failure.
	bool setWifiConfig(const std::string& ssid, uint8_t mode);

	// Writes the upstream WiFi password alone (the password-gated half, applied
	// only once an encrypted config-import block has been decrypted). An empty
	// password is valid (an open upstream network). Returns false only on an
	// ESP NVS write failure.
	bool setWifiPassword(const std::string& password);

	// ---------------------------------------------------------------------
	// Flash-time configuration seed
	// ---------------------------------------------------------------------

	// ==== WIRE FORMAT — keep in lockstep with docs/flasher/index.html ====
	//
	// A single 256-byte little-endian record at offset 0 of the `cfgseed`
	// partition. Every multi-byte field is little-endian; every string field is
	// NUL-padded to its full width and need not be NUL-terminated if it exactly
	// fills the field.
	//
	//   off  size  field
	//   ---  ----  -----------------------------------------------------------
	//     0     4  magic     kSeedMagic ("PDCS" as a LE u32)
	//     4     2  version   kSeedVersion
	//     6     2  flags     kSeedHas* bitmask below
	//     8     4  gen       generation counter; the flasher writes a UNIX
	//                        timestamp so every opt-in write is a new value
	//    12     1  wifiMode  0 = captive-portal default, 1 = STATION, 2 = AP
	//                        (matches the existing NVS key "wifi_mode")
	//    13     1  regMode   SIP registrar admission mode: 0 = open, 1 = learn,
	//                        2 = secure. Matches Registrar::Mode and the existing
	//                        NVS key "reg_mode" (u8) byte-for-byte.
	//    14     2  --        reserved, zero
	//    16    64  apPsk     SoftAP WPA2 passphrase
	//    80    33  staSsid   upstream WiFi SSID (STATION mode)
	//   113     3  --        reserved, zero
	//   116    64  staPass   upstream WiFi passphrase
	//   180    72  --        reserved, zero
	//   252     4  crc32     CRC-32 (IEEE 802.3, reflected poly 0xEDB88320,
	//                        init 0xFFFFFFFF, final xor 0xFFFFFFFF) over
	//                        bytes [0, 252)
	//
	// A record whose magic, version, size or CRC does not check out is IGNORED
	// silently — an unwritten partition reads as 0xFF and must not be an error.
	//
	// `regMode` was added after the first release of this format and deliberately
	// did NOT bump kSeedVersion. Each field is gated by its own "Has" flag and
	// every reader ignores flags it does not recognise, so the two directions are
	// both safe: older firmware reading a newer blob skips bit 5 and applies the
	// rest; newer firmware reading an older blob sees bit 5 clear and leaves
	// `reg_mode` alone. Bumping the version would instead have made older
	// firmware reject the whole record. Keep that property — add fields in the
	// reserved space with a new flag bit, never by repurposing an existing one.

	constexpr uint32_t kSeedMagic   = 0x53434450u;  // 'P','D','C','S' little-endian
	constexpr uint16_t kSeedVersion = 1;
	constexpr size_t   kSeedSize    = 256;

	// Where the seed's `regMode` must be written. The registrar keeps its
	// admission mode in its OWN NVS namespace, NOT the "storage" one every other
	// field of the seed lands in: Registrar::loadMode() opens
	// pbxpersist::kNvsNamespace (src/SIP/PbxPersist.hpp).
	//
	// The literal is duplicated here rather than included so this header stays
	// free of any src/SIP dependency — it is pulled into the host test suite and
	// into the pure-Ethernet transports, neither of which should drag the
	// registrar in. tests/DeviceConfig_test.cpp static_asserts the two against
	// each other, so the duplication cannot silently drift.
	//
	// Getting this wrong was issue #151: the write went to "storage", the read
	// came from "pbxcfg", and flash-time registrar mode did nothing at all on
	// every release that shipped it.
	constexpr const char* kRegistrarNvsNamespace = "pbxcfg";

	// `flags` bits. Each "Has" bit says "this field is meaningful"; a seed may
	// carry any subset, so the flasher can write only what the user changed.
	constexpr uint16_t kSeedHasApSecure = 1u << 0;  // apply the bit below
	constexpr uint16_t kSeedApSecureOn  = 1u << 1;  // the value: 1 = WPA2, 0 = open
	constexpr uint16_t kSeedHasApPsk    = 1u << 2;
	constexpr uint16_t kSeedHasWifiMode = 1u << 3;
	// staSsid and staPass are written as a pair. An SSID paired with the wrong
	// password is a device that never associates, so a bad half discards both.
	// An EMPTY staPass is valid and means an open upstream network -- the SSID
	// is what is required, not the password.
	constexpr uint16_t kSeedHasStaCreds = 1u << 4;
	// Set the SIP registrar's admission mode at flash time. This is the only
	// operator-facing way to reach `secure`/`learn` on a headless board: digest
	// auth has always been implemented, but nothing outside the tests ever wrote
	// `reg_mode`, so a device came up in the compiled-in default and stayed there.
	constexpr uint16_t kSeedHasRegMode  = 1u << 5;

	// Read the `cfgseed` partition and, if it holds a valid record whose `gen`
	// differs from the stored `cfgseed_gen`, apply the flagged settings to NVS
	// and record the new generation.
	//
	// Call once at boot, right after nvs_flash_init() and BEFORE the WiFi
	// bringup that reads these keys.
	//
	// Silently does nothing when:
	//   * there is no `cfgseed` partition — an OTA update does not rewrite the
	//     partition table, so firmware that expects `cfgseed` WILL run on boards
	//     flashed before it existed, and on the 4 MB
	//     sdkconfig.defaults.esp32_constrained layout, which has no such
	//     partition. This is the normal case, not an error;
	//   * the record fails validation (blank/erased flash);
	//   * `gen` matches the stored `cfgseed_gen` — the seed was already applied,
	//     so a plain reboot never re-clobbers settings changed since.
	//
	// Returns true iff settings were applied this call. Host build: no-op,
	// returns false.
	bool applyFlashSeed();

	// Erase ap_secure / ap_psk / cfgseed_gen. Called by /api/factory-reset.
	// Dropping cfgseed_gen is deliberate: the next boot re-applies the flash-time
	// seed, so "factory" means "as flashed", not "as hardcoded".
	//
	// `schema_ver` is deliberately NOT dropped — see the schema section below.
	// Returns false if any NVS step failed (#441 review): the factory-reset
	// route reports that instead of claiming a completed reset.
	bool clearAll();

	// =====================================================================
	// NVS schema versioning (issue #181)
	// =====================================================================
	//
	// This device keeps its entire identity in NVS: the admin credential, the
	// SIP extensions and their secrets, the dial plan, ring groups, DID map,
	// trunk API slots, WiFi config, syslog target. Firmware is updated over the
	// air. Until now nothing recorded WHICH LAYOUT those keys were written in,
	// so the first firmware that changes the meaning of a key would either
	// misread the old value in silence or force the operator to factory-reset a
	// live phone system and re-provision it by hand.
	//
	// The fix is one stamp and one decision, taken at boot before anything reads
	// config. It is deliberately shaped as a sibling of applyFlashSeed(): both
	// are "inspect persistent state once at boot, act exactly once, record that
	// you acted so the next boot doesn't repeat it". `cfgseed_gen` is that
	// counter for the seed; `schema_ver` is it for the key layout.
	//
	// ---- WHERE THE STAMP LIVES ----
	// Key `schema_ver` (u16) in the "storage" namespace, and it describes the
	// WHOLE device, not one namespace. A firmware image is upgraded atomically,
	// so every namespace it owns ("storage", "pbxcfg", "sipauth", "didmap",
	// "tapicfg") changes layout together; six independent stamps would be six
	// chances to disagree. "storage" is chosen over "pbxcfg" because
	// DeviceConfig already owns it, it exists on every transport including the
	// pure-Ethernet ones, and reaching into "pbxcfg" from this file is the exact
	// move that produced #151 and #188.
	//
	// ---- THE DECISION TABLE ----
	//   stamp absent, every config namespace absent  -> FreshInstall.  Stamp
	//        kSchemaVersion. A device born under this firmware is born current.
	//   stamp absent, SOME config namespace present  -> AdoptedLegacy. This is
	//        the case that matters: a device provisioned before versioning
	//        existed. Its data IS v1 by definition — v1 is what every shipped
	//        release wrote — so it is treated as v1, migrated forward if this
	//        firmware is newer, and stamped. It is NEVER wiped. Erasing here
	//        would factory-reset every deployed board on the update that
	//        introduced versioning.
	//   stamp == kSchemaVersion                      -> UpToDate. No write at
	//        all, so a plain reboot costs zero flash wear.
	//   stamp <  kSchemaVersion                      -> Migrated. Walk the
	//        dispatch table one step at a time, re-stamping after EACH step, so
	//        a failure halfway leaves the device at the last version that
	//        actually completed and the next boot retries only the failed step.
	//   stamp >  kSchemaVersion                      -> Downgrade. See below.
	//   the store cannot be inspected               -> StoreUnavailable. No
	//        stamp, no migration. Guessing on a flaky store is how you stamp a
	//        provisioned device as fresh.
	//
	// ---- WHY A DOWNGRADE DOES NOT REFUSE TO BOOT ----
	// Old firmware meeting a newer stamp is not a hypothetical: OTA rollback is
	// armed (CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE) and the new image is only
	// marked valid after several seconds of healthy operation. So "new firmware
	// migrated to v2, stamped it, then crashed and the bootloader rolled back"
	// lands an old image on a v2 store automatically, with no operator involved.
	// Refusing to start would turn the anti-crash safety net into the brick.
	// A PBX that will not ring is worse than a PBX running on defaults.
	//
	// So a downgrade: is detected; is logged at ERROR with an unmissable banner;
	// does NOT write the stamp backwards (which would let the newer firmware
	// return and mistake its own data for old); does NOT migrate backwards; and
	// boots. The newer data is left untouched on flash, so re-flashing the newer
	// image restores the device exactly.
	//
	// KNOWN GAP, stated plainly: this release detects and reports the downgrade
	// but does not quarantine the store against the old firmware's own writes,
	// so v1-shaped values can be written into a v2-stamped store. Gating every
	// loader and writer on the outcome is a much larger change and there is no
	// v2 to test it against yet; lastSchemaOutcome() is exposed so that work can
	// be built on this without redesigning it.

	// The layout this firmware reads and writes. Bump this in the same PR that
	// changes what any persisted key MEANS, and add the matching row to the
	// migration table. Do not bump it for a key that is merely ADDED — an absent
	// key already has a defined meaning everywhere in this codebase (use the
	// default), which is why adding syslog_host or reg_mode needed no migration.
	//
	// v2 (#397/#441): an ABSENT reg_mode used to mean Open and now means Learn.
	// The v1 -> v2 row writes Open onto every pre-#397 board that has no key, so
	// deployed boards keep admitting their phones exactly as before.
	constexpr uint16_t kSchemaVersion = 2;

	// What a pre-versioning device is assumed to be holding. Every release up to
	// and including the one that introduced this framework wrote exactly this
	// layout, so the assumption is a fact about shipped history, not a guess.
	constexpr uint16_t kSchemaBaselineVersion = 1;

	// NVS key for the stamp, in the "storage" namespace.
	constexpr const char* kKeySchemaVersion = "schema_ver";

	// What ensureSchemaVersion() concluded. Reported, logged, and available to
	// callers afterwards via lastSchemaOutcome().
	enum class SchemaOutcome : uint8_t
	{
		FreshInstall,       // blank store; stamped current
		AdoptedLegacy,      // data but no stamp; treated as v1 and stamped
		UpToDate,           // stamp already current; nothing written
		Migrated,           // migrations ran to completion; stamped current
		MigrationFailed,    // a step failed; stamped at the last good version
		Downgrade,          // stamp newer than this firmware; nothing written
		StoreUnavailable,   // could not inspect NVS; nothing written
	};

	// Stable short name, for logs and for a future dashboard field.
	const char* schemaOutcomeName(SchemaOutcome outcome);

	// What ensureSchemaVersion() found in NVS, pre-decision. `versionPresent`
	// distinguishes "no stamp" from "stamped zero"; `hasExistingData` is true iff
	// any namespace this firmware owns already exists on flash.
	struct SchemaProbe
	{
		bool     storeReadable   = false;   // false => we could not tell, at all
		bool     versionPresent  = false;
		uint16_t version         = 0;
		bool     hasExistingData = false;
	};

	// What to do about it.
	struct SchemaPlan
	{
		SchemaOutcome outcome     = SchemaOutcome::StoreUnavailable;
		uint16_t      fromVersion = 0;
		uint16_t      toVersion   = 0;
		bool          migrate     = false;
		bool          stamp       = false;
	};

	// The decision table above, as a pure function of the probe. Split out from
	// the NVS access deliberately: NVS is ESP-only, so a decision baked into the
	// device branch could never be tested, and this one is the decision that
	// destroys a live PBX if it is wrong.
	//
	// `current` is a PARAMETER rather than kSchemaVersion so the tests can drive
	// it past 1. With current fixed at 1, "legacy data -> treat as v1" and
	// "blank -> stamp current" produce the same number and a test cannot tell a
	// correct implementation from one that conflates them.
	SchemaPlan planSchema(const SchemaProbe& probe, uint16_t current);

	// ---- Migration dispatch ----
	//
	// One row per single version step. `ctx` is reserved (always nullptr today):
	// a migration may need to touch several NVS namespaces, so each one opens
	// and COMMITS what it needs itself rather than inheriting one handle. Return
	// false to stop the chain; the device is then left stamped at the last step
	// that succeeded.
	using SchemaMigrationFn = bool (*)(void* ctx);

	struct SchemaMigration
	{
		uint16_t          from;
		uint16_t          to;
		SchemaMigrationFn fn;
		const char*       what;   // short description, for the boot log
	};

	// The shipped table. EMPTY at kSchemaVersion == 1 — there is nothing to
	// migrate from, and inventing rows for changes that have not happened would
	// ship untested flash-mutating code. Returns nullptr with *count == 0.
	const SchemaMigration* schemaMigrations(size_t* count);

	// Called after each successful step with the version just reached, so the
	// stamp is advanced step by step rather than once at the end.
	using SchemaStampFn = bool (*)(void* ctx, uint16_t version);

	// Walk `from` -> `to` one row at a time, stamping after each. Returns true
	// iff the chain completed; `*reached` (required) receives the highest
	// version actually attained, which is what the caller reports and keeps.
	// A missing row for the current version is a failure, not a skip: silently
	// jumping a gap is how a half-migrated device gets stamped as finished.
	bool runSchemaMigrations(uint16_t from, uint16_t to,
	                         const SchemaMigration* table, size_t count,
	                         void* ctx, SchemaStampFn stamp, uint16_t* reached);

	// Probe NVS, apply the table above, and log the outcome. Call ONCE at boot,
	// immediately after nvs_flash_init() and BEFORE applyFlashSeed() — the seed
	// writer creates the very namespaces the pre-versioning probe looks for, so
	// running it first would make every device look freshly installed.
	//
	// Host build: there is no NVS and the in-memory store is rebuilt every
	// process, so the store is blank by definition and the outcome is
	// FreshInstall.
	SchemaOutcome ensureSchemaVersion();

	// The outcome of the last ensureSchemaVersion() call, and the version that
	// was found on flash before any migration (== kSchemaVersion when the device
	// was already current or freshly installed; 0 when the store could not be
	// inspected, or before ensureSchemaVersion() has run at all). Safe to call
	// from any task.
	SchemaOutcome lastSchemaOutcome();
	uint16_t      observedSchemaVersion();
}

#endif // DEVICE_CONFIG_HPP
