#pragma once

// PsramAllocator -- put a container's storage in PSRAM where the board has it
// (issue #466, #284 batch E; #328's binding constraint is INTERNAL DRAM).
//
// IDF's heap already sends allocations of SPIRAM_MALLOC_ALWAYSINTERNAL
// (16 KB) and up to PSRAM, but everything smaller -- every jitter ring, for
// one -- lands in internal DRAM. A container whose storage is long-lived,
// touched only by tasks (never an ISR, never DMA) and not needed while the
// flash cache is off is exactly what PSRAM is for; this allocator says so
// explicitly instead of relying on the size threshold.
//
//   * PSRAM builds (CONFIG_SPIRAM): heap_caps_malloc(SPIRAM | 8BIT). If PSRAM
//     is exhausted it falls back to internal DRAM so construction still
//     succeeds (a ring cannot fail gracefully), and COUNTS the fallback --
//     psram::internalFallbacks(), exported on /api/status -- so a board
//     quietly spilling rings into internal RAM is visible.
//   * No-PSRAM builds (esp32_constrained): internal DRAM, as before.
//   * Host: plain operator new/delete, so tests' counting operator new
//     (tests/support/AllocCounter) still sees these allocations.
//
// Storage allocated here must never be touched from an ISR, by DMA, or by a
// task while it writes flash (the #273 rule: the cache -- and so PSRAM -- is
// off during a flash write on the writing task).

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <new>

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include "sdkconfig.h"
#include "esp_heap_caps.h"
#endif

namespace psram
{
	// How many allocations wanted PSRAM, found it exhausted, and were served
	// from internal DRAM instead. Always 0 on builds without PSRAM.
	inline std::atomic<uint32_t>& internalFallbacks()
	{
		static std::atomic<uint32_t> n{0};
		return n;
	}

	// Issue #479: tasks created dynamically (heap stack + TCB) since boot, via
	// pd::createTaskPreferPsram() and the media call path's direct creates
	// (moh_tx). RTP media tasks and conf_mix_tick use boot-preallocated stacks
	// and are NOT counted. Read it before and after a call: the delta is what the
	// call path allocated for tasks. Exported on /api/status memory.
	inline std::atomic<uint32_t>& dynamicTaskCreates()
	{
		static std::atomic<uint32_t> n{0};
		return n;
	}

	inline void* allocPreferPsram(std::size_t bytes)
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#if defined(CONFIG_SPIRAM) && CONFIG_SPIRAM
		void* p = heap_caps_malloc(bytes, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
		if (p != nullptr) return p;
		p = heap_caps_malloc(bytes, MALLOC_CAP_8BIT);
		if (p != nullptr) internalFallbacks().fetch_add(1, std::memory_order_relaxed);
		return p;
#else
		return heap_caps_malloc(bytes, MALLOC_CAP_8BIT);
#endif
#else
		return ::operator new(bytes, std::nothrow);
#endif
	}

	inline void freePreferPsram(void* p) noexcept
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		heap_caps_free(p);   // correct for either region
#else
		::operator delete(p);
#endif
	}
}

// #1162: MallocScope -- for a library that allocates with plain malloc().
//
// The allocator above only helps code that calls it. esp_http_client and
// esp_websocket_client allocate their own buffers with malloc(), and IDF serves
// every malloc() of CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL (16 KB) or less from
// internal DRAM. The anchor's clients each take a 4096 B receive buffer that
// way: about 30 KB held for as long as the anchor runs, and 4 KB more for a
// second at every token fetch, on the board with the least internal DRAM to
// spare (.244 fell to 3.6 KB free in the v1.8.0-rc.1 soak).
//
// While a MallocScope is alive, IDF's threshold is kMallocScopeMinBytes - 1, so
// a malloc() of kMallocScopeMinBytes or more prefers PSRAM (and still falls back
// to internal DRAM if PSRAM is full). When the last scope ends the board's own
// threshold goes back.
//
// The threshold is one global, so for as long as a scope lives EVERY task's
// malloc() of that size prefers PSRAM too. Keep a scope around the one call
// that allocates and nothing else: the create calls take well under a
// millisecond. Storage that lands in PSRAM this way must meet the rule at the
// top of this file (no ISR, no DMA, not touched by a task while it writes flash).
//
// Scopes may nest and may overlap across tasks: a count holds the lower
// threshold until the last one ends. Two tasks racing on the first and last
// step can leave the board's own threshold in force for a moment early, which
// costs one allocation its PSRAM placement and nothing else.
//
// No-PSRAM builds and the host: the device call is absent. The host records
// the number it would have passed, for tests/PsramMallocScope_test.cpp.
namespace psram
{
	inline constexpr std::size_t kMallocScopeMinBytes = 4096;
#if (defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)) && defined(CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL)
	inline constexpr std::size_t kMallocDefaultInternalLimit = CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL;
#else
	inline constexpr std::size_t kMallocDefaultInternalLimit = 16384;   // IDF's default
#endif

	inline std::atomic<std::size_t>& mallocInternalLimitRecord()
	{
		static std::atomic<std::size_t> v{kMallocDefaultInternalLimit};
		return v;
	}

	// The threshold last asked for. On the device it is what IDF was given.
	inline std::size_t appliedMallocInternalLimit()
	{
		return mallocInternalLimitRecord().load(std::memory_order_acquire);
	}

	inline void applyMallocInternalLimit(std::size_t limit)
	{
		mallocInternalLimitRecord().store(limit, std::memory_order_release);
#if (defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)) && defined(CONFIG_SPIRAM_USE_MALLOC) && CONFIG_SPIRAM_USE_MALLOC
		heap_caps_malloc_extmem_enable(limit);
#endif
	}

	inline std::atomic<int>& mallocScopeDepth()
	{
		static std::atomic<int> n{0};
		return n;
	}

	class MallocScope
	{
	public:
		MallocScope()
		{
			if (mallocScopeDepth().fetch_add(1, std::memory_order_acq_rel) == 0)
			{
				applyMallocInternalLimit(kMallocScopeMinBytes - 1);
			}
		}
		~MallocScope()
		{
			if (mallocScopeDepth().fetch_sub(1, std::memory_order_acq_rel) == 1)
			{
				applyMallocInternalLimit(kMallocDefaultInternalLimit);
			}
		}
		MallocScope(const MallocScope&) = delete;
		MallocScope& operator=(const MallocScope&) = delete;
	};
}

// Standard-allocator wrapper, e.g. std::vector<int16_t, PsramAllocator<int16_t>>.
template <class T>
struct PsramAllocator
{
	using value_type = T;

	PsramAllocator() noexcept = default;
	template <class U>
	PsramAllocator(const PsramAllocator<U>&) noexcept {}

	T* allocate(std::size_t n)
	{
		void* p = psram::allocPreferPsram(n * sizeof(T));
		if (p == nullptr) throw std::bad_alloc();
		return static_cast<T*>(p);
	}
	void deallocate(T* p, std::size_t) noexcept { psram::freePreferPsram(p); }

	template <class U>
	bool operator==(const PsramAllocator<U>&) const noexcept { return true; }
	template <class U>
	bool operator!=(const PsramAllocator<U>&) const noexcept { return false; }
};
