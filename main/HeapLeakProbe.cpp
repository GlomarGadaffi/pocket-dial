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
// HOW IT STARTS -- AND WHY NOT FROM A CONSTRUCTOR
// ------------------------------------------------
// pdHeapLeakProbeStart() is called from each transport's app_main(). The first
// revision instead self-registered from a file-scope constructor, to avoid
// touching four files, justified in this comment as: "safe because ESP-IDF
// runs global C++ constructors from main_task, AFTER the scheduler is
// running." That was asserted, never checked, and it is FALSE.
//
// esp_system/startup.c, start_cpu0_default(): __libc_init_array() and
// __do_global_ctors_1() run there, and the comment immediately following that
// call says "the scheduler (and ipc service) is not available."
// esp_startup_start_app() -- which creates main_task and starts the scheduler
// -- runs AFTER. So constructors execute with no scheduler, and the
// xTaskCreate() in one produced a deterministic crash ~3.8 s into every boot,
// nine identical cycles in under a minute:
//
//   assert failed: prvSelectHighestPriorityTaskSMP tasks.c:3642
//                  (xTaskScheduled == ( ( BaseType_t ) 1 ))
//
// with 0xa5a5a5a5 (FreeRTOS stack poison) in the backtrace. The probe never
// logged a line; the board never lived long enough to reach it. Caught on
// hardware by madmax, not by CI -- a build that compiles and a build that
// boots are different claims, and this file's own header previously conflated
// them.
//
// app_main() has the property the constructor was assumed to have: scheduler
// up, both cores live. The header gives the call site an inline no-op when
// CONFIG_HEAP_TRACING is off, so no #if is needed at any of the four sites.
//
// THE TRACE BUFFER LIVES IN PSRAM, deliberately. The thing being measured is
// internal DRAM; an instrument that consumes the resource under study changes
// the result it reports. heap_trace_init_standalone() takes any buffer, so
// MALLOC_CAP_SPIRAM costs the measurement nothing.

#include "HeapLeakProbe.hpp"

#if CONFIG_HEAP_TRACING


#include "esp_heap_caps.h"
#include "esp_heap_trace.h"
#include "esp_memory_utils.h"   // esp_ptr_internal
#include <cstdio>                 // snprintf
#include "esp_log.h"
#include "esp_rom_sys.h"    // esp_rom_printf -- see probePrintf above
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#if CONFIG_HEAP_TASK_TRACKING
#include "esp_heap_task_info.h"
#endif

namespace
{

constexpr char TAG[] = "HeapProbe";

// EVERY LINE THIS PROBE PRINTS GOES THROUGH esp_rom_printf, NOT ESP_LOGx.
// This is not a style choice; ESP_LOGx cannot carry this output at all.
//
// The non-display builds install LogQueue's non-blocking hook via
// esp_log_set_vprintf (src/Helpers/LogQueue.hpp). That hook formats into a
// stack buffer and does xQueueSend(..., 0) -- "drop the line if the queue is
// full, never block a real-time task." Correct for a PBX. Fatal for a dump:
//
//   QUEUE_DEPTH            = 16 lines          (LogQueue.hpp:46)
//   drain task body        = ONE drainToUart() per vTaskDelay(10 ms)
//                            (esp_main*.cpp), so ~100 lines/second, ceiling
//   this dump              = up to 400 record lines, emitted as fast as the
//                            CPU can format them
//
// Two orders of magnitude apart. Over 99% of the records were being dropped
// silently while the footer cheerfully reported "printed 400" -- a dump that
// looks complete and is hollow, which is worse than one that crashes. It also
// explains madmax's two captures exactly: boot 2 showed 4 record lines and
// boot 3 showed 0, from the same code at the same point. That was never crash
// timing; it was how many of ~400 lines happened to win a 16-slot queue before
// the panic, and a panic discards whatever is still queued.
//
// esp_rom_printf writes the UART FIFO directly: synchronous, no heap, no
// queue, nothing to drop, and no syslog tee (the drain task's tee does an lwip
// send per line, on a board whose Ethernet is the thing dying). It is what
// IDF's own heap_trace_dump_base() uses, with these same %p / %u conversions
// -- IDF's mistake was the critical section wrapped around the loop, not the
// print. Our loop holds no critical section.
//
// Blocking on the UART FIFO paces the loop to 115200 baud (~2 s for a full
// 400-line dump), which is why the vTaskDelay(1) every batch in
// dumpInternalRecords() is load-bearing: esp_rom_printf spins rather than
// yielding, and starving the idle task for 2 s would trade this bug for a
// task-watchdog panic.
//
// Consequence: these lines carry no "W (12345)" ESP_LOG prefix. The literal
// "HeapProbe:" prefix below is what tooling greps for, and every line is
// emitted in true program order -- unlike ESP_LOGx, which lags by up to the
// drain interval and would let records overtake their own dump header.
// ONE THING ESP_LOGx GAVE US THAT esp_rom_printf DOES NOT: format checking.
// esp_rom_sys.h:46 declares `int esp_rom_printf(const char *fmt, ...);` with NO
// __attribute__((format(printf, 1, 2))), so gcc will not diagnose a %u fed a
// size_t, or a conversion with no argument behind it -- on a diagnostic whose
// entire job is printing, and where a bad %s is precisely the bug that just
// crashed this board twice.
//
// probePrintfFormatCheck() restores it. The call sits under `if (false)`, so
// gcc type-checks the arguments against the format string at compile time and
// then discards the branch: the arguments are evaluated zero times and no code
// is emitted. -Werror is on in this build, so a format mistake is a build
// failure rather than a runtime surprise.
__attribute__((format(printf, 1, 2)))
inline void probePrintfFormatCheck(const char*, ...) {}

#define probePrintf(...)                                 \
	do {                                                 \
		if (false) probePrintfFormatCheck(__VA_ARGS__);  \
		esp_rom_printf(__VA_ARGS__);                     \
	} while (false)

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
	probePrintf("HeapProbe: [%s t=%us] internal free=%u largest=%u min=%u | dma free=%u largest=%u\n",
		phase, static_cast<unsigned>(atSec), static_cast<unsigned>(freeInt), static_cast<unsigned>(bigInt),
		static_cast<unsigned>(minInt), static_cast<unsigned>(freeDma),
		static_cast<unsigned>(bigDma));

	// free - largest is the fragmentation signal: it widening while free()
	// holds roughly steady means the DMA bounce-buffer allocation can fail on
	// a board that still reports plenty available.
	probePrintf("HeapProbe: [%s t=%us] fragmentation gap (free - largest) = %u bytes\n",
		phase, static_cast<unsigned>(atSec), static_cast<unsigned>(freeInt - bigInt));
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

	probePrintf("HeapProbe: [per-task internal DRAM t=%us] %u owners\n",
		static_cast<unsigned>(atSec), static_cast<unsigned>(totalsCount));
	for (size_t i = 0; i < totalsCount; ++i)
	{
		// DO NOT call pcTaskGetName(totals[i].task) HERE. That crashed the
		// bench twice, reproducibly, and the reason is in IDF's own docs.
		//
		// heap_caps_get_per_task_info() fills .task from
		// MULTI_HEAP_GET_BLOCK_OWNER(p) -- the TCB pointer stamped into the
		// block header when it was allocated (heap_task_info.c:957). It
		// performs NO liveness check, and esp_heap_task_info.h says so
		// explicitly: the totals array is stable across calls "even if some
		// tasks have freed their blocks OR HAVE BEEN DELETED."
		//
		// So a handle here may belong to a task that no longer exists. This
		// PBX creates and destroys a task per call leg, so by t=120 s several
		// of these are guaranteed dead. pcTaskGetName() is pure pointer
		// arithmetic -- &pxTCB->pcTaskName[0] -- so it happily returns an
		// interior pointer to a freed TCB, and the fault lands downstream in
		// vsnprintf's %s walk looking for a terminator that isn't there:
		//
		//   Guru Meditation Error: Core 1 panic'ed (Cache error)
		//   Cache error: MMU entry fault error     EXCVADDR: 0x00000000
		//   heapProbeTask -> logPerTask -> esp_log_va -> vsnprintf -> vfprintf
		//
		// A dead owner is not noise, it is the single most interesting row in
		// this table: memory still held by a task that has exited is a leak by
		// definition. So print the raw handle and let addr2line/analysis
		// correlate it. count[0] comes free from the same struct and separates
		// "one big block" from "a thousand small ones".
		//
		// IDF 6 has a safe API for this -- heap_caps_get_all_task_stat() fills
		// task_stat_t{ char name[configMAX_TASK_NAME_LEN]; bool is_alive; },
		// copying the name by value under CONFIG_HEAP_TRACK_DELETED_TASKS.
		// That is the right follow-up; it is not worth a second untested change
		// on a bench that has already taken three crashes from this file.
		probePrintf("HeapProbe:   owner %p  %8u bytes  %5u blocks\n",
			totals[i].task,
			static_cast<unsigned>(totals[i].size[0]),
			static_cast<unsigned>(totals[i].count[0]));
	}
}
#endif  // CONFIG_HEAP_TASK_TRACKING

// Print the outstanding internal-RAM trace records WITHOUT using
// heap_trace_dump_caps().
//
// WHY WE CANNOT USE IDF'S DUMP. heap_trace_dump_base()
// (components/heap/heap_trace_standalone.c:341) does portENTER_CRITICAL()
// and then runs its whole `for (i < records.count)` print loop inside it --
// esp_rom_printf per record, plus one %p per backtrace frame, with
// CONFIG_HEAP_TRACING_STACK_DEPTH=8 frames each. Interrupts stay off for the
// entire dump.
//
// On the first real run that was 904 outstanding records at t=120 s. It
// printed ~50 of them, then:
//
//   Guru Meditation Error: Core 0 panic'ed (Interrupt wdt timeout on CPU0)
//
// reproducibly, on consecutive boots. CONFIG_ESP_INT_WDT_TIMEOUT_MS defaults
// to 300 ms; ~6 ms per record means 904 of them need ~5.4 s with interrupts
// disabled. The dump can never finish on a board with a real number of
// outstanding allocations, which is exactly the board we want to dump.
//
// Feeding a watchdog inside that loop is not an option -- it is IDF's code,
// and you cannot delay or yield inside a critical section anyway.
//
// heap_trace_get() takes its OWN short critical section per call, covering a
// single record copy rather than 904 prints. So we iterate at our own pace,
// print outside any critical section, and yield between batches. Interrupts
// are then off for microseconds at a time instead of seconds.
void dumpInternalRecords(uint32_t atSec)
{
	// Bounded so a badly-leaking board cannot emit megabytes over a 115200
	// line faster than anyone can capture it. If we hit the cap the count is
	// reported, so a truncated dump is visible rather than silently partial.
	constexpr size_t kMaxPrinted  = 400;
	constexpr size_t kBatchSize   = 16;   // records per yield

	const size_t total = heap_trace_get_count();
	size_t printed = 0, internalSeen = 0;

	probePrintf("HeapProbe: [dump t=%us] %u outstanding records total; listing "
		"internal-RAM ones (max %u)\n", static_cast<unsigned>(atSec), static_cast<unsigned>(total),
		static_cast<unsigned>(kMaxPrinted));

	for (size_t i = 0; i < total; ++i)
	{
		heap_trace_record_t rec;
		if (heap_trace_get(i, &rec) != ESP_OK) continue;
		if (rec.address == nullptr) continue;
		if (!esp_ptr_internal(rec.address)) continue;   // PSRAM: not #273's pool

		++internalSeen;
		if (printed < kMaxPrinted)
		{
			// One line per record: size, address, then the call stack. Raw
			// addresses -- symbolize in bulk with xtensa-esp32s3-elf-addr2line
			// against the ELF whose SHA256 matches this boot's banner.
			char frames[9 * 11 + 1];
			int  off = 0;
			for (int f = 0; f < CONFIG_HEAP_TRACING_STACK_DEPTH; ++f)
			{
				if (rec.alloced_by[f] == nullptr) break;
				off += snprintf(frames + off, sizeof(frames) - off, " %p",
					rec.alloced_by[f]);
				if (off >= static_cast<int>(sizeof(frames)) - 1) break;
			}
			frames[sizeof(frames) - 1] = '\0';
			probePrintf("HeapProbe:   %6u B @ %p by%s\n",
				static_cast<unsigned>(rec.size), rec.address, frames);
			++printed;
		}

		// Yield outside any critical section so the idle task runs and both
		// watchdogs stay fed. This is the whole point of not using IDF's dump.
		if ((i % kBatchSize) == (kBatchSize - 1))
		{
			vTaskDelay(1);
		}
	}

	probePrintf("HeapProbe: [dump t=%us] internal-RAM records: %u (printed %u%s)\n",
		static_cast<unsigned>(atSec), static_cast<unsigned>(internalSeen), static_cast<unsigned>(printed),
		internalSeen > printed ? ", TRUNCATED" : "");
}

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

	probePrintf("HeapProbe: leak probe armed: %u records in PSRAM, HEAP_TRACE_LEAKS. "
		"Dumps at 120/240/360/900 s (#273 onset measured 218-276 s).\n",
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
		probePrintf("HeapProbe: [dump t=%us] outstanding trace records: %u of %u\n",
			static_cast<unsigned>(target), static_cast<unsigned>(heap_trace_get_count()),
			static_cast<unsigned>(kTraceRecords));
		// The probe's own stack depth was picked (4096, bumped to 8192 below),
		// not measured -- heap_trace_dump_caps() walks up to
		// HEAP_TRACING_STACK_DEPTH (8) %p-formatted frames per outstanding
		// record via esp_rom_printf, and at t=360s that could be hundreds of
		// records. A diagnostic tool overflowing its own stack would look like
		// a brand-new crash in the thing being diagnosed (the #309 bug class,
		// inside the tool built to find it). Logging the real high-water mark
		// each dump turns the next stack-size decision into a measurement
		// instead of a second guess.
		// uxTaskGetStackHighWaterMark() returns WORDS, not bytes -- matches
		// HoldMusic.cpp's/HttpServer.cpp's own convention elsewhere in this
		// tree; multiplying by sizeof(StackType_t) is not optional.
		const UBaseType_t freeWords = uxTaskGetStackHighWaterMark(nullptr);
		probePrintf("HeapProbe: [dump t=%us] heap_probe stack high-water: %u bytes free of %d\n",
			static_cast<unsigned>(target), static_cast<unsigned>(freeWords * sizeof(StackType_t)), 8192);

		// NOT heap_trace_dump_caps(). See dumpInternalRecords() -- IDF's own
		// dump holds a critical section across its entire per-record print
		// loop, which at 904 records tripped the interrupt watchdog and
		// crashed the board mid-dump, losing the very data it was printing.
		dumpInternalRecords(target);

#if CONFIG_HEAP_TASK_TRACKING
		logPerTask(target);
#endif
	}

	// Deliberately keeps tracing after the last scheduled dump rather than
	// stopping: the board stays up for 76-91 minutes in the degraded state
	// (measured, two boots, two trees), so someone may want a manual dump much
	// later. heap_trace_stop() is never called here.
	probePrintf("HeapProbe: scheduled dumps complete; tracing still ACTIVE for later manual dumps\n");
	vTaskDelete(nullptr);
}

}  // namespace

// Entry point, called from app_main() -- see the header for why this is not a
// constructor. Internal-RAM stack (plain xTaskCreate, not PD_TASK_STACK_CAPS):
// this task calls into the heap subsystem and logs, and a PSRAM stack is the
// hazard #277/#309 exist to prevent.
void pdHeapLeakProbeStart()
{
	static bool started = false;
	if (started)
	{
		// Defensive: four app_main()s exist but only one runs per build. A
		// second call would arm a second tracer over the first's buffer.
		return;
	}
	started = true;

	if (xTaskCreate(heapProbeTask, "heap_probe", 8192, nullptr, 1, nullptr) != pdPASS)
	{
		ESP_LOGE(TAG, "xTaskCreate heap_probe failed -- probe disabled");
	}
}


#endif  // CONFIG_HEAP_TRACING
