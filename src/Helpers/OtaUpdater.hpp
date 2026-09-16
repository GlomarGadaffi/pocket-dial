#ifndef OTA_UPDATER_HPP
#define OTA_UPDATER_HPP

// OtaUpdater: a thin, portable wrapper over the ESP-IDF app_update API
// (esp_ota_ops.h / esp_partition.h) used by the HTTP dashboard to stream a new
// firmware image into the inactive OTA slot and activate it.
//
// Why this exists: the device ships a single `factory` app partition; Phase-1
// production hardening adds dual-OTA (ota_0 / ota_1 + otadata, see
// docs/OTA.md). This class hides the esp_ota_* state machine behind a tiny,
// testable surface and — crucially for this repo — compiles on the desktop
// (host) build too, where the ESP-IDF APIs do not exist. On host every method
// is a deterministic stub so the cross-compiled binary links and the host smoke
// tests stay green; no real flashing happens off-device.
//
// Lifecycle (device):
//     begin(totalSize)  -> esp_ota_get_next_update_partition + esp_ota_begin
//     write(data, len)  -> esp_ota_write   (call repeatedly while streaming)
//     end()             -> esp_ota_end     (finalizes + validates the image)
//     activate()        -> esp_ota_set_boot_partition (next boot uses new slot)
//     abort()           -> esp_ota_abort   (release the handle on any failure)
//
// Rollback strategy (see docs/OTA.md): with
// CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y the freshly activated image boots in
// the "pending verify" state. The application confirms a healthy boot by calling
// markValid() (esp_ota_mark_app_valid_cancel_rollback). If the new image never
// reaches markValid() (crash/boot loop), the bootloader rolls back to the
// previous slot on the next reset.
//
// Thread-safety: a single OTA session is expected to run on one connection
// thread at a time (the HTTP server streams one upload per request). The class
// does not add its own locking; callers must not drive one instance from
// multiple threads concurrently. All shared state is per-instance.

#include <cstddef>
#include <cstdint>
#include <string>

class OtaUpdater
{
public:
	OtaUpdater() = default;
	~OtaUpdater();

	// Non-copyable / non-movable: it owns an esp_ota handle (an opaque
	// resource) for the duration of a session.
	OtaUpdater(const OtaUpdater&) = delete;
	OtaUpdater& operator=(const OtaUpdater&) = delete;
	OtaUpdater(OtaUpdater&&) = delete;
	OtaUpdater& operator=(OtaUpdater&&) = delete;

	// Open a write session against esp_ota_get_next_update_partition(NULL).
	// totalSize is the expected image size (may be OTA_SIZE_UNKNOWN/0 if not
	// known; we pass the Content-Length when we have it so the IDF can pre-erase
	// efficiently). Returns false (and sets lastError) on failure.
	// Host stub: records the size, marks the session active, returns true.
	bool begin(size_t totalSize);

	// Write the next chunk of image bytes. Must be called only after a
	// successful begin(). Returns false (and sets lastError) on failure.
	// Host stub: accumulates the byte count and discards the data.
	bool write(const uint8_t* data, size_t len);

	// Finalize the image: esp_ota_end() runs the integrity/signature checks.
	// Returns false (and sets lastError) on a corrupt/invalid image.
	// Host stub: returns true.
	bool end();

	// Set the just-written partition as the boot partition for the next reset.
	// Call only after a successful end(). Returns false on failure.
	// Host stub: marks an update pending and returns true.
	bool activate();

	// Release the open handle (esp_ota_abort) if a session is in progress.
	// Safe to call when no session is open. Host stub: clears the active flag.
	void abort();

	// True while begin() has succeeded and end()/abort() has not yet been called.
	bool isInProgress() const { return _inProgress; }

	// True once activate() has succeeded: a new image is staged and the device
	// should reboot to run it.
	bool isUpdatePending() const { return _updatePending; }

	// Human-readable last error (empty if none). Stable, caller-owned copy.
	const std::string& lastError() const { return _lastError; }

	// Total bytes accepted by write() so far in the current/last session.
	size_t bytesWritten() const { return _bytesWritten; }

	// --- Static status helpers (no session required) ---

	// True while an OTA upload/flash session is actively in progress.
	// Thread-safe and non-blocking.
	static bool isUpdateInProgress();

	// Label of the partition the device is currently running from
	// (e.g. "ota_0"). Host: a fixed placeholder string.
	static std::string runningPartitionLabel();

	// Label of the partition a new image would be written to / will boot next
	// (esp_ota_get_next_update_partition). Host: a fixed placeholder string.
	static std::string nextUpdatePartitionLabel();

	// Label of the configured boot partition (esp_ota_get_boot_partition).
	// Host: a fixed placeholder string.
	static std::string bootPartitionLabel();

	// True iff the running image is in the "pending verify" state (i.e. it was
	// just OTA-activated and has not yet been confirmed via markValid()).
	// Host: always false.
	static bool isPendingVerify();

	// Confirm a healthy boot: cancels the pending rollback so the running image
	// becomes the permanent boot choice
	// (esp_ota_mark_app_valid_cancel_rollback). Returns false on failure.
	// Safe / idempotent to call when no verification is pending.
	// Host: no-op, returns true.
	static bool markValid();

private:
	bool        _inProgress    = false;
	bool        _updatePending = false;
	size_t      _expectedSize  = 0;
	size_t      _bytesWritten  = 0;
	std::string _lastError;

#if defined(ESP_PLATFORM)
	// esp_ota_handle_t is a uint64 typedef in ESP-IDF; we store it type-erased to
	// keep esp_ota_ops.h out of this header (so host TUs never see it). The .cpp
	// reinterprets it back. 0 is the "no handle" sentinel.
	uint64_t    _otaHandle     = 0;
	// const esp_partition_t* of the slot we are writing to. Opaque here.
	const void* _updatePart    = nullptr;
#endif
};

#endif // OTA_UPDATER_HPP
