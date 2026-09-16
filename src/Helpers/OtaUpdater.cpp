// OtaUpdater.cpp — see OtaUpdater.hpp for the design notes and lifecycle.
//
// Two implementations live side by side, selected by the platform guard:
//   * ESP_PLATFORM: a thin wrapper over the ESP-IDF app_update component
//     (esp_ota_ops.h / esp_partition.h). Every esp_* call is error-checked and
//     surfaced through _lastError; we never abort()/restart from inside here.
//   * Host (desktop Linux / CI): deterministic stubs with identical signatures
//     so the host binary links and behaves predictably for the smoke tests.

#include "OtaUpdater.hpp"
#include <atomic>

namespace
{
	std::atomic<bool> s_inProgress{false};
}

bool OtaUpdater::isUpdateInProgress()
{
	return s_inProgress.load(std::memory_order_relaxed);
}

#if defined(ESP_PLATFORM)
#include "esp_ota_ops.h"   // esp_ota_*; esp_ota_img_states_t / ESP_OTA_IMG_* enums
#include "esp_partition.h" // esp_partition_t
#include "esp_err.h"       // esp_err_t, esp_err_to_name

namespace
{
	// Reinterpret the type-erased handle stored in the header back to the real
	// IDF type. esp_ota_handle_t is an unsigned integer typedef.
	inline esp_ota_handle_t toHandle(uint64_t h) { return static_cast<esp_ota_handle_t>(h); }

	std::string partLabel(const esp_partition_t* p)
	{
		return (p != nullptr) ? std::string(p->label) : std::string("(none)");
	}
}

OtaUpdater::~OtaUpdater()
{
	// Defensive: never leave an esp_ota handle dangling if the object is
	// destroyed mid-session (e.g. the connection thread unwinds on an error).
	abort();
}

bool OtaUpdater::begin(size_t totalSize)
{
	if (_inProgress)
	{
		_lastError = "OTA session already in progress";
		return false;
	}

	_bytesWritten  = 0;
	_expectedSize  = totalSize;
	_updatePending = false;
	_lastError.clear();

	const esp_partition_t* part = esp_ota_get_next_update_partition(nullptr);
	if (part == nullptr)
	{
		_lastError = "no OTA update partition available (check partition table)";
		return false;
	}

	// Pass the known size so the IDF can erase exactly what it needs; if we don't
	// know it, OTA_SIZE_UNKNOWN makes esp_ota_begin erase the whole slot lazily.
	const size_t imageSize = (totalSize > 0) ? totalSize : OTA_SIZE_UNKNOWN;

	esp_ota_handle_t handle = 0;
	esp_err_t err = esp_ota_begin(part, imageSize, &handle);
	if (err != ESP_OK)
	{
		_lastError = std::string("esp_ota_begin failed: ") + esp_err_to_name(err);
		return false;
	}

	_updatePart = part;
	_otaHandle  = static_cast<uint64_t>(handle);
	_inProgress = true;
	s_inProgress.store(true, std::memory_order_relaxed);
	return true;
}

bool OtaUpdater::write(const uint8_t* data, size_t len)
{
	if (!_inProgress)
	{
		_lastError = "OTA write before begin()";
		return false;
	}
	if (data == nullptr || len == 0)
	{
		// Treat an empty chunk as a no-op success (e.g. a 0-byte recv slice).
		return true;
	}

	esp_err_t err = esp_ota_write(toHandle(_otaHandle), data, len);
	if (err != ESP_OK)
	{
		_lastError = std::string("esp_ota_write failed: ") + esp_err_to_name(err);
		return false;
	}

	_bytesWritten += len;
	return true;
}

bool OtaUpdater::end()
{
	if (!_inProgress)
	{
		_lastError = "OTA end() without an active session";
		return false;
	}

	esp_err_t err = esp_ota_end(toHandle(_otaHandle));
	// Whether end() succeeds or fails, the handle is consumed by esp_ota_end.
	_inProgress = false;
	s_inProgress.store(false, std::memory_order_relaxed);
	_otaHandle  = 0;

	if (err != ESP_OK)
	{
		if (err == ESP_ERR_OTA_VALIDATE_FAILED)
			_lastError = "image validation failed (corrupt or wrong magic)";
		else
			_lastError = std::string("esp_ota_end failed: ") + esp_err_to_name(err);
		return false;
	}
	return true;
}

bool OtaUpdater::activate()
{
	if (_inProgress)
	{
		_lastError = "activate() called before end()";
		return false;
	}
	const esp_partition_t* part = static_cast<const esp_partition_t*>(_updatePart);
	if (part == nullptr)
	{
		_lastError = "no written partition to activate";
		return false;
	}

	esp_err_t err = esp_ota_set_boot_partition(part);
	if (err != ESP_OK)
	{
		_lastError = std::string("esp_ota_set_boot_partition failed: ") + esp_err_to_name(err);
		return false;
	}

	_updatePending = true;
	return true;
}

void OtaUpdater::abort()
{
	if (_inProgress && _otaHandle != 0)
	{
		// Best-effort: release the handle so the slot can be reused. Ignore the
		// return; there is nothing actionable on an abort failure.
		esp_ota_abort(toHandle(_otaHandle));
	}
	_inProgress = false;
	s_inProgress.store(false, std::memory_order_relaxed);
	_otaHandle  = 0;
}

std::string OtaUpdater::runningPartitionLabel()
{
	return partLabel(esp_ota_get_running_partition());
}

std::string OtaUpdater::nextUpdatePartitionLabel()
{
	return partLabel(esp_ota_get_next_update_partition(nullptr));
}

std::string OtaUpdater::bootPartitionLabel()
{
	return partLabel(esp_ota_get_boot_partition());
}

bool OtaUpdater::isPendingVerify()
{
	const esp_partition_t* running = esp_ota_get_running_partition();
	if (running == nullptr) return false;

	esp_ota_img_states_t state = ESP_OTA_IMG_UNDEFINED;
	if (esp_ota_get_state_partition(running, &state) != ESP_OK) return false;
	return state == ESP_OTA_IMG_PENDING_VERIFY;
}

bool OtaUpdater::markValid()
{
	esp_err_t err = esp_ota_mark_app_valid_cancel_rollback();
	return err == ESP_OK;
}

#else // ---------------------------------------------------------------- HOST

// Host stubs: no flash, no esp_ota_*. We simulate the state machine so the
// desktop binary links and behaves deterministically. No real update occurs.

OtaUpdater::~OtaUpdater()
{
	abort();
}

bool OtaUpdater::begin(size_t totalSize)
{
	if (_inProgress)
	{
		_lastError = "OTA session already in progress";
		return false;
	}
	_bytesWritten  = 0;
	_expectedSize  = totalSize;
	_updatePending = false;
	_inProgress    = true;
	s_inProgress.store(true, std::memory_order_relaxed);
	_lastError.clear();
	return true;
}

bool OtaUpdater::write(const uint8_t* data, size_t len)
{
	if (!_inProgress)
	{
		_lastError = "OTA write before begin()";
		return false;
	}
	(void)data; // host: discard the bytes, just account for them
	_bytesWritten += len;
	return true;
}

bool OtaUpdater::end()
{
	if (!_inProgress)
	{
		_lastError = "OTA end() without an active session";
		return false;
	}
	_inProgress = false;
	s_inProgress.store(false, std::memory_order_relaxed);
	return true;
}

bool OtaUpdater::activate()
{
	if (_inProgress)
	{
		_lastError = "activate() called before end()";
		return false;
	}
	_updatePending = true;
	return true;
}

void OtaUpdater::abort()
{
	_inProgress = false;
	s_inProgress.store(false, std::memory_order_relaxed);
}

std::string OtaUpdater::runningPartitionLabel()  { return "host"; }
std::string OtaUpdater::nextUpdatePartitionLabel() { return "host-sim"; }
std::string OtaUpdater::bootPartitionLabel()     { return "host"; }
bool        OtaUpdater::isPendingVerify()         { return false; }
bool        OtaUpdater::markValid()               { return true; }

#endif // ESP_PLATFORM
