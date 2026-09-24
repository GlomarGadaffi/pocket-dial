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
