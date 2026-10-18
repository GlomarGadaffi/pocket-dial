// FlashWriter.cpp -- see FlashWriter.hpp (#991). Board only: the host has no
// task, and its tests drive passOnce() directly.
#include "FlashWriter.hpp"

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include <atomic>

#include "CdrRing.hpp"
#include "NvsWriter.hpp"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "PsramTask.hpp"   // PD_ASSERT_NOT_PSRAM_STACK -- issue #277

namespace flashwriter
{
namespace
{
	std::atomic<TaskHandle_t>& taskHandle()
	{
		static std::atomic<TaskHandle_t> h{nullptr};
		return h;
	}

	void flashWriterTask(void*)
	{
		for (;;)
		{
			// Defense in depth (#277): created with a plain stack below, so this
			// never fires unless someone changes that call without reading
			// PsramTask.hpp first.
			PD_ASSERT_NOT_PSRAM_STACK();
			// The pass before the wait, so the first one runs on entry.
			(void)passOnce<&CdrRing::writePending, &nvswriter::writePending>();
			(void)ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
		}
	}
}

bool start()
{
	if (taskHandle().load(std::memory_order_acquire) != nullptr) return true;
	// PLAIN stack (no PD_TASK_STACK_CAPS): this task does every flash write for
	// the CDR ring and the NVS writer's keys -- see PsramTask.hpp. 6144 B is what
	// cdr_persist and nvs_writer each had: the deepest chain of the two, not their
	// sum. The static gate stops at the IDF nvs_* calls, so stackHwm_flash_writer
	// on /api/status is the figure to size it by.
	TaskHandle_t h = nullptr;
	if (xTaskCreatePinnedToCore(flashWriterTask, "flash_writer", 6144, nullptr, 1, &h, 0) != pdPASS)
	{
		ESP_LOGE("flash_writer", "xTaskCreate flash_writer failed");
		return false;
	}
	taskHandle().store(h, std::memory_order_release);
	return true;
}

void wake()
{
	const TaskHandle_t h = taskHandle().load(std::memory_order_acquire);
	if (h != nullptr) xTaskNotifyGive(h);   // never blocks
}
}
#endif
