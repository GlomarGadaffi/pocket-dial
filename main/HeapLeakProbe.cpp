// Internal-DRAM leak probe for issue #273. COMPILES TO NOTHING unless
// CONFIG_HEAP_TRACING is set, which only sdkconfig.defaults.heap_trace does.
//
// WHY THIS EXISTS
// ---------------
// #295 added freeHeapInternal / largestFreeBlockInternal / the MALLOC_CAP_DMA
// pair to /api/status. Those answer "is internal DRAM draining, how fast, and
// is it fragmenting" — and they cannot answer "who is holding it," which is
// the only question left on #273. Two sessions have now measured the same
// drain on two firmware revisions (onset 218–276 s, dashboard dead, W5500
// transmits failing, board still up 76–91 minutes later) without a candidate
// allocator.
//
// IDF ships the tool for exactly this and the project has never switched it
// on. HEAP_TRACE_LEAKS keeps a record per allocation and DELETES it on free,
// so whatever is still in the buffer at dump time is, by construction, what
// leaked — with the call stack that allocated it. Paired with
// CONFIG_HEAP_TASK_TRACKING it also names the owning task.
//
// HOW IT STARTS WITHOUT TOUCHING THE THREE app_main()s
// ----------------------------------------------------
// There are three transport-specific mains (esp_main.cpp, esp_main_eth.cpp,
// esp_main_display.cpp, plus the lan8720 variant) and editing all of them for
// a diagnostic build would put conflict surface into files other sessions are
// actively working in. Instead this self-registers from a file-scope
// constructor. That is safe here specifically because ESP-IDF runs global C++
// constructors from main_task, AFTER the scheduler is running — so
// xTaskCreate() from a constructor is legal. It would not be on bare metal.
//
// THE TRACE BUFFER LIVES IN PSRAM, deliberately. The thing being measured is
// internal DRAM; an instrument that consumes the resource under study changes
// the result it reports. heap_trace_init_standalone() takes any buffer, so
// MALLOC_CAP_SPIRAM costs the measurement nothing.

#include "sdkconfig.h"

#if CONFIG_HEAP_TRACING

#include <cinttypes>

#include "esp_heap_caps.h"
#include "esp_heap_trace.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#if CONFIG_HEAP_TASK_TRACKING
#include "esp_heap_task_info.h"
#endif

namespace
{

constexpr char TAG[] = "HeapProbe";

// 4000 records x 40-odd bytes each, in PSRAM. Sized to comfortably outlast the
// ~220 s onset window rather than to be frugal: HEAP_TRACE_LEAKS drops a
// record when its allocation is freed, so only genuinely-outstanding
// allocations accumulate, and a buffer that fills silently stops recording
// exactly the tail you came for. heap_trace_get_count() is logged at each dump
// so a full buffer is visible rather than inferred.
constexpr size_t kTraceRecords = 4000;

// Dump schedule, seconds after boot. Chosen around the measured onset of
// 218–276 s (#273): one reading clearly BEFORE it, two bracketing it, then a
// late one well into the degraded steady state. A single dump at the end
// cannot separate "allocated early and never freed" from "allocated during
// the collapse."
constexpr uint32_t kDumpsSec[] = { 120, 240, 360, 900 };

void logInternalState(const char* phase, uint32_t atSec)
{
	const size_t freeInt = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
	const size_t bigInt  = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL);
	const size_t minInt  = heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL);
	const size_t freeDma = heap_caps_get_free_size(MALLOC_CAP_DMA);
	const size_t bigDma  = heap_caps_get_largest_free_block(MALLOC_CAP_DMA);

	// Same four figures /api/status reports (#295), logged here too so a
	// serial capture is self-contained — the dashboard is dead by the third
	// dump, which is precisely when the numbers matter most.
	ESP_LOGW(TAG, "[%s t=%" PRIu32 "s] internal free=%u largest=%u min=%u | dma free=%u largest=%u",
		phase, atSec, static_cast<unsigned>(freeInt), static_cast<unsigned>(bigInt),
		static_cast<unsigned>(minInt), static_cast<unsigned>(freeDma),
		static_cast<unsigned>(bigDma));

	// free - largest is the fragmentation signal: it widening while free()
	// holds roughly steady means the DMA bounce-buffer allocation can fail on
	// a board that still reports plenty available.
	ESP_LOGW(TAG, "[%s t=%" PRIu32 "s] fragmentation gap (free - largest) = %u bytes",
		phase, atSec, static_cast<unsigned>(freeInt - bigInt));
}

#if CONFIG_HEAP_TASK_TRACKING
void logPerTask(uint32_t atSec)
{
	constexpr size_t kMaxTasks = 24;
	static heap_task_totals_t totals[kMaxTasks];
	static size_t totalsCount = 0;

	heap_task_info_params_t params = {};
	// caps[]/mask[] are int32_t in IDF's header while MALLOC_CAP_* are
	// unsigned macros -- cast explicitly rather than rely on the implicit
	// conversion being quiet. Only slot 0 is set: a region's caps ANDed with
	// mask[0] must equal caps[0], so slot 0 collects internal RAM and
	// totals[i].size[0] is the figure #273 cares about.
	params.caps[0]       = static_cast<int32_t>(MALLOC_CAP_INTERNAL);
	params.mask[0]       = static_cast<int32_t>(MALLOC_CAP_INTERNAL);
	params.tasks         = nullptr;      // all tasks
	params.num_tasks     = 0;
	params.totals        = totals;
	params.num_totals    = &totalsCount;
	params.max_totals    = kMaxTasks;
	params.blocks        = nullptr;      // totals only; per-block is huge
	params.max_blocks    = 0;

	totalsCount = 0;
	heap_caps_get_per_task_info(&params);

	ESP_LOGW(TAG, "[per-task internal DRAM t=%" PRIu32 "s] %u tasks", atSec,
		static_cast<unsigned>(totalsCount));
	for (size_t i = 0; i < totalsCount; ++i)
	{
		const char* name = totals[i].task ? pcTaskGetName(totals[i].task) : "pre-scheduler";
		// size[] is size_t; cast rather than trusting %d to be right on a
		// 32-bit target by accident.
		ESP_LOGW(TAG, "    %-16s %8u bytes", name ? name : "?",
			static_cast<unsigned>(totals[i].size[0]));
	}
}
#endif  // CONFIG_HEAP_TASK_TRACKING

void heapProbeTask(void*)
{
	auto* buf = static_cast<heap_trace_record_t*>(
		heap_caps_malloc(kTraceRecords * sizeof(heap_trace_record_t), MALLOC_CAP_SPIRAM));
	if (buf == nullptr)
	{
		// Falling back to internal RAM would consume the resource under study
		// and corrupt the measurement, so refuse rather than report a number
		// the instrument itself moved.
		ESP_LOGE(TAG, "no PSRAM for %u trace records -- probe disabled (will NOT "
			"fall back to internal RAM; that would change what it measures)",
			static_cast<unsigned>(kTraceRecords));
		vTaskDelete(nullptr);
		return;
	}

	if (heap_trace_init_standalone(buf, kTraceRecords) != ESP_OK ||
	    heap_trace_start(HEAP_TRACE_LEAKS) != ESP_OK)
	{
		ESP_LOGE(TAG, "heap_trace_start failed -- probe disabled");
		vTaskDelete(nullptr);
		return;
	}

	ESP_LOGW(TAG, "leak probe armed: %u records in PSRAM, HEAP_TRACE_LEAKS. "
		"Dumps at 120/240/360/900 s (#273 onset measured 218-276 s).",
		static_cast<unsigned>(kTraceRecords));
	logInternalState("armed", 0);

	for (uint32_t target : kDumpsSec)
	{
		const uint32_t nowSec = static_cast<uint32_t>(xTaskGetTickCount() / configTICK_RATE_HZ);
		if (target > nowSec)
		{
			vTaskDelay(pdMS_TO_TICKS((target - nowSec) * 1000));
		}

		logInternalState("dump", target);
		ESP_LOGW(TAG, "[dump t=%" PRIu32 "s] outstanding trace records: %u of %u",
			target, static_cast<unsigned>(heap_trace_get_count()),
			static_cast<unsigned>(kTraceRecords));

		// Only the internal-RAM allocations. A full dump is dominated by PSRAM
		// traffic that has nothing to do with #273.
		heap_trace_dump_caps(MALLOC_CAP_INTERNAL);

#if CONFIG_HEAP_TASK_TRACKING
		logPerTask(target);
#endif
	}

	// Deliberately keeps tracing after the last scheduled dump rather than
	// stopping: the board stays up for 76-91 minutes in the degraded state
	// (measured, two boots, two trees), so someone may want a manual dump much
	// later. heap_trace_stop() is never called here.
	ESP_LOGW(TAG, "scheduled dumps complete; tracing still ACTIVE for later manual dumps");
	vTaskDelete(nullptr);
}

// Runs from main_task after the scheduler is up -- see the header comment.
// Internal-RAM stack (plain xTaskCreate, not PD_TASK_STACK_CAPS): this task
// calls into the heap subsystem and logs, and a PSRAM stack is the hazard
// #277/#309 exist to prevent.
struct HeapProbeInstaller
{
	HeapProbeInstaller()
	{
		if (xTaskCreate(heapProbeTask, "heap_probe", 4096, nullptr, 1, nullptr) != pdPASS)
		{
			ESP_LOGE(TAG, "xTaskCreate heap_probe failed -- probe disabled");
		}
	}
};

const HeapProbeInstaller g_heapProbeInstaller;

}  // namespace

#endif  // CONFIG_HEAP_TRACING
