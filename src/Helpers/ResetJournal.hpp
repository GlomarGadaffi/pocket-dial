#pragma once

// resetjournal -- "the last factory reset did not complete", reported on the
// next boot (issue #473 item 1).
//
// A factory reset erases stores key by key and (since #456) finishes with
// nvs_flash_erase() in the restart task, AFTER the HTTP response has gone out.
// A failure there -- or a power cut or crash anywhere mid-reset -- could leave
// secrets readable in flash with nothing on the next boot saying so.
//
// This is a one-record intent log:
//   begin()          at the very start of a reset: records "reset begun";
//   noteFailure(m)   any step that fails ORs its bit into a RAM mask;
//   finish(extra)    last thing before the restart: if nothing failed, the
//                    record is ERASED (a clean board has no record at all);
//                    otherwise it is rewritten as "reset failed" + the mask.
// So on the next boot a record means either the reset was interrupted after
// begin() (stage Begun: power cut, crash, a hung restart task) or it finished
// with failures (stage Failed). It stays until the next reset that completes
// cleanly -- the operator keeps seeing it until the device is really clean.
//
// WHERE (the #473 design question). Not in NVS -- NVS is the thing that may
// have failed. Not RTC_NOINIT by default -- that does not survive a power cut,
// which is exactly one of the failures to catch. The record lives in the LAST
// 4 KB sector of the raw `prompts` partition (subtype 0x40), which nothing
// writes today (partitions.csv: reserved for future prompt/voicemail audio;
// that future writer must leave its final sector alone -- noted there). Not
// the coredump partition: the factory reset erases it (#437), so a marker
// there would erase itself. Not cfgseed: firmware never writes it by contract.
//
// FALLBACK: the 4 MB layout (partitions_4mb.csv, esp32_constrained) has no
// prompts partition and no free sector at all. There the record lives in
// RTC_NOINIT memory, which survives esp_restart() -- so a failed
// nvs_flash_erase() is still reported -- but NOT a power cut. storage() says
// which one is in use, and /api/status reports it.

#include <cstdint>

namespace resetjournal
{
	// Bits for noteFailure()/finish(). Stable: they are persisted.
	enum : uint8_t
	{
		kAdmin    = 1u << 0,   // AdminAuth credential erase
		kTrunk    = 1u << 1,   // carrier trunk credentials
		kSecrets  = 1u << 2,   // email / SIP-digest secret stores (#363)
		kForwards = 1u << 3,   // call-forward targets (#450)
		kNvsErase = 1u << 4,   // the whole-partition nvs_flash_erase()
		kOther    = 1u << 7,
	};

	enum class Stage : uint8_t { None = 0, Begun = 1, Failed = 2, Unreadable = 3 };
	enum class Storage : uint8_t { None, Flash, Rtc };

	struct BootStatus
	{
		Stage   stage = Stage::None;   // None: the last reset (if any) completed
		uint8_t failedMask = 0;
		Storage storage = Storage::None;
		bool incomplete() const { return stage != Stage::None; }
	};

	// False if the record could not be written (logged at WARN and counted in
	// writeFailureCount()); the caller proceeds with the reset regardless.
	bool begin();
	void noteFailure(uint8_t mask);
	void finish(uint8_t extraMask = 0);

	// What the journal said when this boot first looked (cached; later
	// begin()/finish() in this boot do not change it). The first call logs a
	// WARN if the last reset was incomplete.
	BootStatus bootStatus();
	Storage storage();
	// Journal writes that failed this boot (begin/finish), for /api/status.
	uint32_t writeFailureCount();

	const char* stageName(Stage s);
	const char* storageName(Storage s);

#if !(defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO))
	// Host: the record lives in process memory. "Reboot" = forget the cached
	// boot status and the RAM mask, keep the record (as flash would).
	void simulateRebootForTest();
	// Wipe the record too (a fresh board).
	void resetForTest();
	// Write raw bytes over the record (a torn or corrupt write).
	void corruptRecordForTest();
	// The next record write/erase fails, as a flash error would.
	void failNextWriteForTest();
#endif
}
