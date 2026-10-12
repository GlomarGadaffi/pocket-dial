// AdminPinVerify.cpp -- see AdminPinVerify.hpp and AdminPinVerifyLogic.hpp (#986 slice 3).
#include "AdminPinVerify.hpp"

#include <atomic>

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include "esp_log.h"
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

	// What the worker's stack has to hold: pinVerifyTask, workOnce, matchesDtmfPin and
	// hashSecretDigest, whose deepest frame is Sha256::transform's 64-word schedule
	// (256 B) with a Sha256 (about 112 B) and the 32-byte digest above it; and
	// vTaskDelay / ulTaskNotifyTake. The chain allocates nothing (the round loop reads
	// views and writes a fixed digest) and logs nothing. About 1 KB by that count plus
	// the task context; 3072 B is the same budget as conf_mix_tick and rtp_media_tx. A
	// reasoned figure, unmeasured: stackHwm will show the real one.
	constexpr uint32_t kStackBytes = 3072;

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
		for (;;)
		{
			// A give that lands while a check runs is not lost: the next take returns at once.
			(void)ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
			(void)h->workOnce(realHash);
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
