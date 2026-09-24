#ifndef PD_PSRAM_TASK_HPP
#define PD_PSRAM_TASK_HPP

// #100: place selected FreeRTOS task stacks + TCBs in PSRAM (8 MB) instead of the scarce ~290 KB
// internal-RAM heap. The per-call anchor media tasks (RtpReceiver / RtpSender / GET-stream rx) and
// the transient TLS workers (makecall / answer / dropcall) each take 6–12 KB of stack; with N
// concurrent calls those stacks exhaust internal RAM and xTaskCreate starts failing — the measured
// concurrent-call ceiling (the freeHeap telemetry hides it because that counts PSRAM). Moving these
// stacks to PSRAM lifts the ceiling toward the per-call socket/CPU limits instead.
//
// SAFE ONLY for tasks that never perform a flash / NVS write THEMSELVES: when the flash cache is
// disabled for a write, code accessing a PSRAM stack faults. The media/TLS tasks here do socket +
// TLS I/O only.
//
// CORRECTED (issues #273/#277/#288, 2026-09-16): this comment used to claim "NVS/CDR writes run on
// the SIP/anchor task, which is frozen during the flash op, so the PSRAM-stack tasks are simply not
// scheduled in that window." That was WRONG, and it is the reason #273's panic and #288's second
// instance of it existed at all: RequestsHandler::endCall() -- which every call-teardown path
// reaches, including tel_wsw's WebSocket-event handling and the makecall worker's failure path --
// calls CdrRing::record() -> persist() -> nvs_set_str/nvs_commit DIRECTLY, on whatever task called
// endCall(). Both tel_wsw and the makecall worker are themselves PD_TASK_STACK_CAPS tasks, so the
// "frozen SIP task" assumption was simply false for those call paths: the flash write ran on a
// PSRAM-stacked task's own stack, which is exactly what this comment (correctly) says must never
// happen. Fixed in CdrRing.cpp: persist() now only builds a fixed-size blob (no allocation) and
// hands it to a dedicated, ordinary-stack writer task via a queue -- see CdrRing.cpp's
// ensureWriterTaskStarted()/writerTaskBody() for the reference pattern, and
// PD_ASSERT_NOT_PSRAM_STACK() below for a cheap defense-in-depth check any future flash-writing code
// should call before touching NVS/a partition/OTA, so a repeat of this mistake fails with a clear
// message here instead of deep inside IDF's cache teardown.
//
// The rule, restated plainly: A PSRAM-stacked task must NEVER perform a flash operation
// (nvs_*, esp_partition_*, esp_flash_*, esp_ota_*, or anything that reaches
// spi_flash_disable_interrupts_caches_and_other_cpu) itself. That includes transitively, through
// any function it calls -- #277 found this hazard invisible at the task's own call site precisely
// because grepping the task's own file finds nothing; the actual flash write can be several stack
// frames away. Trace the full call graph of anything new created with PD_TASK_STACK_CAPS before
// assuming it is safe.
//
// Create PSRAM-stack tasks with pd::createTaskPreferPsram() and delete them with pd::deleteTask()
// (#466, below): the pair works on boards without PSRAM and picks vTaskDeleteWithCaps vs
// vTaskDelete from where the stack actually is, so a PSRAM stack + TCB is always reclaimed. Host
// builds get nothing (the callers are all inside ESP_PLATFORM guards).

#if defined(ESP_PLATFORM) || defined(ESP32)
#include <cassert>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/idf_additions.h"   // xTaskCreate*WithCaps / vTaskDeleteWithCaps
#include "esp_heap_caps.h"            // MALLOC_CAP_SPIRAM, esp_ptr_external_ram

// PSRAM, byte-addressable — the stack + TCB allocation caps for an off-internal-RAM task.
#define PD_TASK_STACK_CAPS (MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT)

// Issue #277 suggestion 3: call this immediately before any flash operation (nvs_*,
// esp_partition_*, esp_flash_*, esp_ota_*), from any task, on any board. It is a cheap
// (one address-range check) way to turn a silent-until-it-crashes mistake into a clear assertion
// message naming exactly what went wrong, rather than letting the calling task discover the hazard
// via IDF's own `esp_task_stack_is_sane_cache_disabled()` assert deep inside the cache-teardown path
// -- which names the symptom, not the cause, and is not obviously connected to PD_TASK_STACK_CAPS
// unless the reader already knows this file. Checks a STACK-LOCAL address (this function's own
// argument frame), which is exactly where PD_TASK_STACK_CAPS places the task's stack when it applies
// and exactly what the real hazard depends on -- not the heap, not the TCB, the stack pointer.
// See CdrRing.cpp's writer task for the reference caller.
#define PD_ASSERT_NOT_PSRAM_STACK() \
	do { \
		int pd_stack_probe_; \
		assert(!esp_ptr_external_ram(&pd_stack_probe_) && \
			"flash operation attempted from a PSRAM-stacked task (PD_TASK_STACK_CAPS) -- " \
			"see PsramTask.hpp and issue #277"); \
	} while (0)

#include "sdkconfig.h"          // CONFIG_SPIRAM
#include "esp_log.h"
#include "PsramAllocator.hpp"   // psram::internalFallbacks() -- the one PSRAM-fallback counter

namespace pd
{
	// Issue #466: create a task with its stack + TCB in PSRAM where the board has
	// PSRAM, and an ordinary internal-stack task otherwise. Every PSRAM-stack
	// task goes through here, because a bare xTaskCreate*WithCaps(PD_TASK_STACK_CAPS)
	// simply FAILS on a board without PSRAM (esp32_constrained: CONFIG_SPIRAM=n)
	// -- every such task silently never started there.
	//   * No PSRAM configured: plain create, by design (not counted).
	//   * PSRAM configured but the WithCaps create fails (PSRAM exhausted): falls
	//     back to a plain create, COUNTED in psram::internalFallbacks() (/api/status
	//     memory.psramFallbacks) and logged at WARN -- never silent.
	// The same #273/#277 rule applies to anything created here: the task must
	// never perform a flash operation itself, even transitively.
	// Delete with pd::deleteTask(), which picks the matching delete call from
	// where the stack actually is.
	inline BaseType_t createTaskPreferPsram(TaskFunction_t fn, const char* name, uint32_t stackBytes,
	                                        void* arg, UBaseType_t prio, TaskHandle_t* out,
	                                        BaseType_t core = tskNO_AFFINITY)
	{
#if defined(CONFIG_SPIRAM) && CONFIG_SPIRAM
		if (xTaskCreatePinnedToCoreWithCaps(fn, name, stackBytes, arg, prio, out, core,
		                                    PD_TASK_STACK_CAPS) == pdPASS)
			return pdPASS;
		psram::internalFallbacks().fetch_add(1, std::memory_order_relaxed);
		ESP_LOGW("PsramTask", "%s: no PSRAM for a %u B stack -- falling back to INTERNAL (#466)",
		         name, static_cast<unsigned>(stackBytes));
#endif
		return xTaskCreatePinnedToCore(fn, name, stackBytes, arg, prio, out, core);
	}

	// Delete `task` (nullptr: the calling task) with the call that matches where
	// its stack really lives: vTaskDeleteWithCaps for a PSRAM stack (reclaims the
	// PSRAM stack + TCB), vTaskDelete for an internal one. Deciding from the
	// stack's address rather than from how the task was meant to be created is
	// what makes createTaskPreferPsram()'s fallback safe to delete -- the wrong
	// call either asserts or leaks.
	inline void deleteTask(TaskHandle_t task)
	{
		TaskHandle_t t = (task != nullptr) ? task : xTaskGetCurrentTaskHandle();
		if (esp_ptr_external_ram(xTaskGetStackStart(t)))
			vTaskDeleteWithCaps(task);
		else
			vTaskDelete(task);
	}
}
#endif

#endif // PD_PSRAM_TASK_HPP
