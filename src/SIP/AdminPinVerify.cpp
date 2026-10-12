// AdminPinVerify.cpp -- see AdminPinVerify.hpp and AdminPinVerifyLogic.hpp (#986 slice 3).
#include "AdminPinVerify.hpp"

#include <atomic>

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "PsramTask.hpp"   // pd::createTaskPreferPsram
#endif

namespace adminpin
{
namespace
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	constexpr const char* kTag = "pin_verify";

	// What the worker's stack has to hold, and logging is included in the figure. The witness line
	// (pinVerifyTask) goes esp_log_write -> the log hook (LogQueue's log_queue_vprintf, or the display
	// build's screen_log_vprintf: a 256-byte buffer either way) -> vsnprintf, and that printf chain,
	// not the hash, is the deepest thing the task does. The hash chain is pinVerifyTask, workOnce,
	// matchesDtmfPin and hashSecretDigest, whose deepest frame is Sha256::transform's 64-word schedule
	// (256 B) with a Sha256 (about 112 B) and the 32-byte digest above it: about 1 KB, plus
	// vTaskDelay / ulTaskNotifyTake. The stack-depth gate charges a printf with no frame data 2048 B
	// (tools/ci/task_stacks.json), so with the hook's buffer and the esp_log frames the log path is
	// about 2.6 KB: 3072 B left no margin on it, 4096 does. Neither is a measurement. The task now
	// measures: each witness line carries the stack high-water mark, read after the hash and BEFORE
	// that line's own log call, so line n includes the depth of the log calls of lines 1..n-1 (the mark
	// is a minimum over the task's life). Read the last of the lines, not the first.
	constexpr uint32_t kStackBytes = 4096;

	// Witness lines per boot: one per verify, the first 16 only.
	constexpr unsigned kWitnessLines = 16;

	struct Executor
	{
		std::atomic<TaskHandle_t> task{nullptr};
		void wake() { xTaskNotifyGive(task.load(std::memory_order_acquire)); }   // never blocks
	};

	std::atomic<bool>& running()
	{
		static std::atomic<bool> r{false};
		return r;
	}

	// One tick (1 ms, CONFIG_FREERTOS_HZ=1000) lets the priority-0 idle task run;
	// taskYIELD() would not. See pbkdf2Sha256 for the same reasoning.
	void yieldOneTick() { vTaskDelay(1); }
	void (*const kYield)() = yieldOneTick;
#else
	struct Executor
	{
		std::atomic<unsigned> wakes{0};
		void wake() { wakes.fetch_add(1, std::memory_order_relaxed); }
	};
	void (*const kYield)() = nullptr;
#endif

	Executor& executor()
	{
		static Executor e;
		return e;
	}

	Handoff<Executor>& handoff()
	{
		static Handoff<Executor> h(executor());
		return h;
	}

	// The hash: no lock, no heap, no flash. It reads the job's own copy of the salt
	// and stored hash and nothing else -- in particular not AdminAuth's state or its
	// NVS loader -- which is what lets the task have a PSRAM stack (PsramTask.hpp, #277).
	bool realHash(const Job& j)
	{
		return AdminAuth::matchesDtmfPin(j.ticket, std::string_view(j.pin), kYield);
	}

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// The handoff arrives as the task argument, so no function-local static (and no
	// __cxa_guard) sits on this task's call chain.
	void pinVerifyTask(void* arg)
	{
		auto* h = static_cast<Handoff<Executor>*>(arg);
		unsigned logged = 0;   // a plain local: no function-local static on this chain either
		for (;;)
		{
			// A give that lands while a check runs is not lost: the next take returns at once.
			(void)ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
			const int64_t t0 = esp_timer_get_time();
			if (!h->workOnce(realHash)) continue;
			// The witness line (#986): how long a check really takes with its yields, and how deep this
			// stack really goes, so the 4096 B can be judged on the board. After the hash and outside
			// everything it takes, holding nothing of ours. It carries no PIN, no length, and not the
			// result. Capped, because it is only there to be read once. esp_log_write takes the log
			// mutex for at most 10 ms to read the tag's level, and both log hooks only enqueue
			// (xQueueSend with a timeout of 0); nothing on this path allocates.
			if (logged < kWitnessLines)
			{
				const unsigned ms = static_cast<unsigned>((esp_timer_get_time() - t0) / 1000);
				const unsigned hwm = static_cast<unsigned>(uxTaskGetStackHighWaterMark(nullptr)) * sizeof(StackType_t);
				++logged;
				ESP_LOGW(kTag, "check %u/%u: hash %u ms, stack high-water %u B free of %u B",
					logged, kWitnessLines, ms, hwm, static_cast<unsigned>(kStackBytes));
			}
		}
	}
#endif
}

void start()
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	static bool started = false;   // boot is single-threaded
	if (started) return;
	started = true;
	// Built now, not under _mutex on the first *PIN#.
	Handoff<Executor>& h = handoff();
	TaskHandle_t task = nullptr;
	// Priority 1, so media (and everything else of note) wins; core 0, like the other
	// writers. A PSRAM stack is allowed because this task never performs a flash
	// operation: nothing it reaches calls nvs_*, esp_partition_*, esp_flash_* or
	// esp_ota_*, and test_admin_pin_offthread.py pins that. Internal where there is
	// no PSRAM (createTaskPreferPsram falls back and counts it).
	if (pd::createTaskPreferPsram(pinVerifyTask, "pin_verify", kStackBytes, &h, 1, &task, 0) != pdPASS)
	{
		ESP_LOGE(kTag, "xTaskCreate pin_verify failed -- the DTMF admin menu is unavailable");
		started = false;
		return;
	}
	executor().task.store(task, std::memory_order_release);
	running().store(true, std::memory_order_release);
#endif
}

SubmitResult submit(std::string_view pin, std::string_view callId, std::string_view callerExt,
	std::string_view code, char confirm)
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	if (!running().load(std::memory_order_acquire)) return SubmitResult::NotRunning;
#endif
	return handoff().submit(pin, callId, callerExt, code, confirm, AdminAuth::beginDtmfPinVerify);
}

bool applyIfReady(FunctionRef<void(const Job&, bool)> run)
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	if (!running().load(std::memory_order_acquire)) return false;
#endif
	return handoff().applyIfReady(AdminAuth::finishDtmfPinVerify, run);
}

#if !(defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO))
namespace
{
	std::atomic<Hasher> s_hasher{nullptr};
}

void setHasherForTest(Hasher h) { s_hasher.store(h); }

bool workForTest()
{
	return handoff().workOnce([](const Job& j) {
		const Hasher h = s_hasher.load();
		return h != nullptr ? h(j) : realHash(j);
	});
}

Phase phaseForTest() { return handoff().phase(); }

unsigned wakesForTest() { return executor().wakes.load(); }

void resetForTest()
{
	s_hasher.store(nullptr);
	handoff().reset();
	executor().wakes.store(0);
}
#endif
}
