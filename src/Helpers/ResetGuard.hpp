#pragma once

// resetguard -- "a factory reset is in progress": NVS writers refuse new data
// (issue #473 item 2, landed with #470).
//
// The HTTP factory reset erases stores key by key, answers, and (since #456)
// ends with nvs_flash_erase() + esp_restart() in its restart task. Between the
// first erase and the restart, any other task that writes NVS -- the CDR
// persist writer today, the registrar's device table and others later -- could
// put PII straight back. Until now nothing survived only because the final
// whole-partition erase happens to come last: an ordering held by timing.
// This makes it structural:
//
//   reset path:   resetguard::begin();  resetguard::waitForWritersIdle(ms);
//                 ... erases ...
//   every writer: resetguard::WriteScope w;  if (!w.allowed()) skip;
//                 ... nvs_set_* / nvs_commit ...
//
// A writer bumps an in-flight count BEFORE checking the flag, and the reset
// sets the flag BEFORE waiting for that count to reach zero (all seq_cst), so
// once waitForWritersIdle() returns true no data write can start or still be
// running. Erasures are deliberately NOT gated: removing data during a reset
// is the point.
//
// There is no end(): the reset always restarts the board, and a fresh boot
// starts with the flag clear.

#include <atomic>
#include <cstdint>

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#else
#include <chrono>
#include <thread>
#endif

namespace resetguard
{
	inline std::atomic<bool>& flagRef()
	{
		static std::atomic<bool> f{false};
		return f;
	}

	inline std::atomic<int>& writersRef()
	{
		static std::atomic<int> w{0};
		return w;
	}

	inline void begin() { flagRef().store(true); }
	inline bool inProgress() { return flagRef().load(); }

#if !(defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO))
	// Host-only seam (#476 review): runs INSIDE WriteScope's constructor, between
	// its two steps, so a test can start a reset at exactly the point where the
	// order of those steps matters -- deterministically, with no timing race.
	using BetweenStepsHook = void (*)();
	inline BetweenStepsHook& betweenStepsHookForTest()
	{
		static BetweenStepsHook h = nullptr;
		return h;
	}
#endif

	// RAII around one NVS data write. Construct first, then check allowed().
	class WriteScope
	{
	public:
		WriteScope()
		{
			// Count first, THEN check. The reverse order lets a reset that
			// begins between the two steps see zero writers and erase under a
			// writer that has already decided it is allowed.
			writersRef().fetch_add(1);
#if !(defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO))
			if (BetweenStepsHook h = betweenStepsHookForTest()) h();
#endif
			_allowed = !inProgress();
		}
		~WriteScope() { writersRef().fetch_sub(1); }
		WriteScope(const WriteScope&) = delete;
		WriteScope& operator=(const WriteScope&) = delete;
		bool allowed() const { return _allowed; }

	private:
		bool _allowed = false;
	};

	// After begin(): wait (bounded) until no data write is in flight. Returns
	// false on timeout, which the caller should log; the reset still proceeds.
	inline bool waitForWritersIdle(uint32_t timeoutMs)
	{
		for (uint32_t waited = 0; writersRef().load() != 0; waited += 5)
		{
			if (waited >= timeoutMs) return false;
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
			vTaskDelay(pdMS_TO_TICKS(5));
#else
			std::this_thread::sleep_for(std::chrono::milliseconds(5));
#endif
		}
		return true;
	}

#if !(defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO))
	// Host tests share one process: clear the flag a test set.
	inline void resetForTest() { flagRef().store(false); writersRef().store(0); betweenStepsHookForTest() = nullptr; }
#endif
}
