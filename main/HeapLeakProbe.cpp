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
#include <cstdarg>                // va_list, for probePrintf
#include <cstring>                // memcmp, memcpy
#include <cstdio>                 // vsnprintf
#include <cstdint>                // uintptr_t
#include <unistd.h>               // write(), STDERR_FILENO
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#if CONFIG_HEAP_TASK_TRACKING
#include "esp_heap_task_info.h"
#endif

namespace
{

constexpr char TAG[] = "HeapProbe";

// HOW THIS PROBE PRINTS, AND WHY IT IS NEITHER ESP_LOGx NOR esp_rom_printf.
//
// Every line goes through probePrintf() below: vsnprintf into a stack buffer,
// then one write() to fd 2. Both of the obvious alternatives are wrong here,
// and each was wrong in a way that cost a board cycle or nearly did.
//
// NOT ESP_LOGx -- it silently discards this output.
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
// Consequence of leaving ESP_LOGx: these lines carry no "W (12345)" prefix.
// The literal "HeapProbe:" below is what tooling greps for, and every line is
// emitted in true program order -- which ESP_LOGx could not guarantee anyway,
// since the queue lags by up to a drain interval and records could overtake
// their own dump header.
//
// NOT esp_rom_printf EITHER -- it writes the UART FIFO with no lock.
//
// IDF's heap_trace_dump_base() gets away with esp_rom_printf only because the
// critical section that tripped the interrupt watchdog ALSO serialized the
// port. This loop deliberately holds no critical section, so during a ~2 s
// dump there would be two unsynchronized writers on UART0: heap_probe
// (unaffinitized) and log_drain (pinned core 0, fputs(stderr)). The probe
// occupies the wire for essentially all of that window, and the window is
// never quiet -- the Yealink re-registers every ~30 s by design, plus OPTIONS
// and mDNS. Drained lines would land mid-record and garble them.
//
// That failure is especially nasty here: a garbled record makes the capture
// fail the very line-count check built to detect dropped records, on a dump
// that completed correctly on the device. A false integrity failure teaches
// people to ignore the integrity check.
//
// So: format into a stack buffer, emit with ONE write() to fd 2.
//
//   - Still bypasses LogQueue. The queue hook is installed only on
//     esp_log_set_vprintf; the drain task's own fputs(stderr) is the proof
//     that fd 2 is the raw console path underneath it.
//   - ATOMIC per line. uart_vfs.c:236 takes
//     _lock_acquire_recursive(&s_ctx[fd]->write_lock) around the whole write,
//     so a HeapProbe: line cannot be split by another writer.
//   - Goes wherever the console goes. Verified CONFIG_ESP_CONSOLE_UART_DEFAULT
//     (UART0, 115200), with USB-Serial-JTAG only secondary -- worth checking
//     rather than assuming, because on a USB-SJ-primary board esp_rom_printf
//     would have gone to pins nobody was listening on and the probe would have
//     looked silent rather than broken.
//   - snprintf carries a real __attribute__((format(printf,...))), unlike
//     esp_rom_printf (esp_rom_sys.h:46 declares it bare). So -Wformat applies
//     directly and no checking workaround is needed: with -Werror on, a %u fed
//     a size_t is a build failure. Mutation-tested by adding an unmatched %d.
//   - No heap; one 256-byte stack buffer, reused.
//
// write() blocks on the UART at 115200, which paces the loop, which is why the
// vTaskDelay(1) per batch in dumpInternalRecords() is load-bearing -- without
// it a ~2 s dump starves the idle task into a task-WDT panic.
constexpr size_t kLineBytes = 256;

__attribute__((format(printf, 1, 2)))
void probePrintf(const char* fmt, ...)
{
	char line[kLineBytes];
	va_list ap;
	va_start(ap, fmt);
	const int n = vsnprintf(line, sizeof(line), fmt, ap);
	va_end(ap);
	if (n <= 0) return;
	// vsnprintf returns what it WOULD have written; clamp so an over-long
	// line is truncated rather than reading past the buffer.
	const size_t len = (static_cast<size_t>(n) < sizeof(line))
		? static_cast<size_t>(n) : sizeof(line) - 1;
	write(STDERR_FILENO, line, len);
}

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
		probePrintf("HeapProbe:   owner 0x%08x  %8u bytes  %5u blocks\n",
			static_cast<unsigned>(reinterpret_cast<uintptr_t>(totals[i].task)),
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
// Aggregation table for the dump, in PSRAM.
//
// SIZED SO OVERFLOW IS STRUCTURALLY IMPOSSIBLE, not so it is usually enough.
// The first aggregated run on hardware read:
//
//   905 outstanding records total, 887 in internal RAM ... across 192 call sites
//   call sites: 192 (records unplaced: 596, TRUNCATED -- raise kMaxSites)
//
// 192 was a guess that "records collapse to far fewer unique stacks," and the
// board disagreed: 291 records filled all 192 slots, a collapse ratio of only
// 1.5 records per site, which projects to roughly 585 distinct stacks for 887
// records. Guessing again with a bigger number would just be a slower version
// of the same mistake.
//
// A dump can never contain more distinct call sites than it contains records,
// and the trace buffer caps records at kTraceRecords. So sizing the table at
// kTraceRecords makes `records unplaced` provably always zero, at 40 bytes an
// entry -- about 156 KB of PSRAM, which costs the measurement nothing (same
// reasoning as the trace buffer: PSRAM is not the resource under study).
//
// Cost is O(records x sites) memcmp of a 32-byte key. Realistically ~600 sites
// x 887 records is under a million short comparisons; the 4000 x 4000 ceiling
// only arises if the trace buffer fills. All of it runs outside any critical
// section, yielding every batch.
constexpr size_t kMaxSites = kTraceRecords;

struct SiteTotal
{
	void*    frames[CONFIG_HEAP_TRACING_STACK_DEPTH];
	uint32_t bytes;
	uint32_t count;
};

SiteTotal* g_sites = nullptr;   // kMaxSites entries, allocated once in PSRAM

// Print outstanding internal-RAM allocations AGGREGATED BY CALL STACK.
//
// WHY NOT ONE LINE PER RECORD (the previous design, and why it was wrong).
//
// The first working capture said: `internal-RAM records: 886 (printed 400,
// TRUNCATED)`. The cap existed so a badly-leaking board could not emit
// megabytes over a 115200 line -- a real concern -- but it discarded exactly
// the records the analysis needs.
//
// heap_trace_standalone.c:604 inserts new allocations with TAILQ_INSERT_TAIL,
// and heap_trace_get(0) returns TAILQ_FIRST (line 287). Index order is
// therefore OLDEST FIRST. Printing indices 0..399 prints the 400 oldest
// outstanding allocations and throws away the tail -- and in HEAP_TRACE_LEAKS
// mode the tail is, by construction, where a growing leak lives.
//
// A leak is found by diffing two dumps: the signal IS the set of allocations
// added between them, which is precisely the set the cap deleted. The
// comparison would have reported "nothing grew" -- not an error, not a crash,
// just a plausible wrong answer. The line-count integrity check passes it too,
// because every line the probe emitted did arrive; they were simply the wrong
// 400.
//
// Raising the cap only moves the cliff. Aggregating removes it: output is
// bounded by the number of DISTINCT call sites, which does not grow with the
// leak, so nothing is ever discarded. It also computes on-device exactly what
// the host-side analysis was going to compute anyway -- bytes and allocation
// count per call stack -- so the delta between dumps becomes exact rather than
// a diff of two truncated samples.
//
// Cost: O(records x sites) memcmp of a 32-byte key. At 4000 x 192 that is
// bounded work outside any critical section, yielding every batch.
void dumpInternalRecords(uint32_t atSec)
{
	constexpr size_t kBatchSize = 16;   // records per yield

	if (g_sites == nullptr)
	{
		probePrintf("HeapProbe: [dump t=%us] no aggregation table -- skipped\n",
			static_cast<unsigned>(atSec));
		return;
	}

	const size_t total = heap_trace_get_count();
	size_t siteCount = 0, internalSeen = 0, overflow = 0;
	uint64_t internalBytes = 0;

	for (size_t i = 0; i < total; ++i)
	{
		heap_trace_record_t rec;
		if (heap_trace_get(i, &rec) == ESP_OK &&
		    rec.address != nullptr &&
		    esp_ptr_internal(rec.address))     // PSRAM: not #273's pool
		{
			++internalSeen;
			internalBytes += rec.size;

			size_t k = 0;
			for (; k < siteCount; ++k)
			{
				if (memcmp(g_sites[k].frames, rec.alloced_by,
				           sizeof(g_sites[k].frames)) == 0)
				{
					break;
				}
			}
			if (k == siteCount)
			{
				if (siteCount < kMaxSites)
				{
					memcpy(g_sites[siteCount].frames, rec.alloced_by,
					       sizeof(g_sites[siteCount].frames));
					g_sites[siteCount].bytes = 0;
					g_sites[siteCount].count = 0;
					++siteCount;
				}
				else
				{
					// Reported, never silent. A table this small overflowing
					// would mean the stacks are far more varied than measured,
					// and the number below says so rather than the totals
					// quietly under-counting.
					++overflow;
					goto yield_point;
				}
			}
			g_sites[k].bytes += rec.size;
			g_sites[k].count += 1;
		}

	yield_point:
		// Outside any critical section, so the idle task runs and both
		// watchdogs stay fed. The whole point of not using IDF's dump.
		if ((i % kBatchSize) == (kBatchSize - 1))
		{
			vTaskDelay(1);
		}
	}

	probePrintf("HeapProbe: [dump t=%us] %u outstanding records total, %u in "
		"internal RAM holding %u B across %u call sites\n",
		static_cast<unsigned>(atSec), static_cast<unsigned>(total),
		static_cast<unsigned>(internalSeen),
		static_cast<unsigned>(internalBytes),
		static_cast<unsigned>(siteCount));

	// Selection sort by bytes held, descending. siteCount is small and this
	// runs once per dump; an in-place sort avoids a second allocation.
	for (size_t a = 0; a + 1 < siteCount; ++a)
	{
		size_t best = a;
		for (size_t b = a + 1; b < siteCount; ++b)
		{
			if (g_sites[b].bytes > g_sites[best].bytes) best = b;
		}
		if (best != a)
		{
			SiteTotal tmp = g_sites[a];
			g_sites[a] = g_sites[best];
			g_sites[best] = tmp;
		}
	}

	for (size_t k = 0; k < siteCount; ++k)
	{
		// Raw addresses -- symbolize in bulk with xtensa-esp32s3-elf-addr2line
		// against the ELF whose SHA256 matches this boot's banner.
		char frames[CONFIG_HEAP_TRACING_STACK_DEPTH * 11 + 1];
		int  off = 0;
		for (int f = 0; f < CONFIG_HEAP_TRACING_STACK_DEPTH; ++f)
		{
			if (g_sites[k].frames[f] == nullptr) break;
			off += snprintf(frames + off, sizeof(frames) - off, " 0x%08x",
				static_cast<unsigned>(
					reinterpret_cast<uintptr_t>(g_sites[k].frames[f])));
			if (off >= static_cast<int>(sizeof(frames)) - 1) break;
		}
		frames[sizeof(frames) - 1] = '\0';
		probePrintf("HeapProbe:   site %8u B  %5u allocs by%s\n",
			static_cast<unsigned>(g_sites[k].bytes),
			static_cast<unsigned>(g_sites[k].count), frames);

		if ((k % kBatchSize) == (kBatchSize - 1)) vTaskDelay(1);
	}

	// PREFIX CENSUS -- measurement, not a change in behaviour.
	//
	// Sites are keyed on the full CONFIG_HEAP_TRACING_STACK_DEPTH frames, and
	// the first hardware run collapsed only 1.5 records per site. For a LEAK
	// that is suspicious: a leaking site should repeat, so either this board
	// genuinely leaks from hundreds of distinct places, or an 8-frame key is
	// splitting what is really one allocation site reached by different outer
	// call paths.
	//
	// Those two have opposite fixes and guessing between them costs a board
	// cycle each time. So count how many DISTINCT sites remain when only the
	// first 1, 2 and 4 frames are considered.
	//
	// HOW TO READ THE RESULT -- and how NOT to. First hardware census was
	// 4 / 18 / 214 / 449 (depths 1, 2, 4, full). The tempting reading is
	// "4 to 18 is the honest number of leak sources, the deep key is
	// fragmenting them." That reading is wrong.
	//
	// heap_trace.inc:29 sets STACK_OFFSET to 2, commented "Caller is 2 stack
	// frames deeper than we care about", so the capture skips get_call_stack
	// and trace_malloc. But it lands on whoever called
	// __wrap_heap_caps_malloc, and in IDF that is STILL the allocator: the
	// four depth-1 addresses from the first census symbolized to exactly
	// heap_caps_malloc_default, heap_caps_malloc, calloc and malloc
	// (madmax, addr2line, on this tree). The skip stops INSIDE the allocator
	// stack, not above it.
	//
	// So frames[0] AND frames[1] are allocator plumbing on every record, and
	// real program context does not begin until roughly frames[2]. Two
	// consequences: ranking at depth 1-2 would report that malloc is
	// leaking, and the 8-frame key carries only ~6 frames of actual signal,
	// which argues AGAINST re-keying shallower rather than for it. When
	// symbolizing for a ranking, skip the first two frames -- they are the
	// same handful of names on every row.
	//
	// So this census describes the SHAPE of the fan-out and nothing more.
	// Which depth to rank at is a question for symbols, not for a ratio.
	// An earlier version of this comment offered "depth-4 far below
	// full-depth means the key is too specific" as a decision rule; that was
	// a threshold invented before anyone had symbolized a single frame, and
	// it is not a sound basis for changing the key.
	//
	// Usually the question does not need answering at all: the leak is found
	// by diffing two dumps, and a large TOTAL site count only matters if the
	// GROWTH is spread just as wide. Check the diff before re-keying.
	//
	// Costs O(sites^2) short memcmp per depth, once per dump, outside any
	// critical section.
	for (size_t depth = 1; depth <= 4; depth *= 2)
	{
		if (depth >= static_cast<size_t>(CONFIG_HEAP_TRACING_STACK_DEPTH)) break;
		size_t distinct = 0;
		const size_t keyBytes = depth * sizeof(void*);
		for (size_t a = 0; a < siteCount; ++a)
		{
			bool seen = false;
			for (size_t b = 0; b < a; ++b)
			{
				if (memcmp(g_sites[a].frames, g_sites[b].frames, keyBytes) == 0)
				{
					seen = true;
					break;
				}
			}
			if (!seen) ++distinct;
			if ((a % 64) == 63) vTaskDelay(1);
		}
		probePrintf("HeapProbe: [dump t=%us] distinct sites at depth %u: %u\n",
			static_cast<unsigned>(atSec), static_cast<unsigned>(depth),
			static_cast<unsigned>(distinct));
	}

	// Closing line. `records unplaced` should now always be 0 -- the table
	// cannot be smaller than the record count. If it is ever non-zero, the
	// sizing invariant above has been broken and every total below
	// under-counts, so it is stated explicitly rather than inferred.
	probePrintf("HeapProbe: [dump t=%us] call sites: %u (records unplaced: %u%s)\n",
		static_cast<unsigned>(atSec), static_cast<unsigned>(siteCount),
		static_cast<unsigned>(overflow),
		overflow ? ", TRUNCATED -- kMaxSites invariant broken" : "");
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

	// Aggregation table, also in PSRAM and for the same reason as the trace
	// buffer: an instrument that consumes internal DRAM changes the internal
	// DRAM figure it exists to report. Allocated once at arm time rather than
	// per dump, so a dump never depends on an allocation succeeding on a board
	// whose whole symptom is allocations failing.
	g_sites = static_cast<SiteTotal*>(
		heap_caps_malloc(kMaxSites * sizeof(SiteTotal), MALLOC_CAP_SPIRAM));
	if (g_sites == nullptr)
	{
		probePrintf("HeapProbe: no PSRAM for the %u-entry call-site table -- "
			"dumps will report gauges only\n", static_cast<unsigned>(kMaxSites));
	}

	probePrintf("HeapProbe: leak probe armed: %u records in PSRAM, HEAP_TRACE_LEAKS. "
		"Aggregating by call site (table %u, cannot overflow). "
		"Dumps at 120/240/360/900 s (#273 onset measured 218-276 s).\n",
		static_cast<unsigned>(kTraceRecords), static_cast<unsigned>(kMaxSites));
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
