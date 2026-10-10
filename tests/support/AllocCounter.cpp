#include "AllocCounter.hpp"

#include <atomic>
#include <cstdlib>
#include <new>

#if defined(_WIN32) || defined(_WIN64)
#include <malloc.h>   // _msize, _aligned_msize
#elif defined(__APPLE__)
#include <malloc/malloc.h>   // malloc_size
#elif defined(__GLIBC__)
#include <malloc.h>   // malloc_usable_size
#endif

namespace
{
	std::atomic<std::size_t> g_allocs{0};
	// Trivially constructible, so reading it inside operator new never allocates.
	thread_local std::size_t t_allocs = 0;

	std::atomic<std::size_t> g_liveBlocks{0};
	std::atomic<std::size_t> g_liveBytes{0};

	std::atomic<std::size_t> g_watchedSize{0};
	thread_local std::size_t t_watchedAllocs = 0;

	void count(std::size_t bytes)
	{
		g_allocs.fetch_add(1, std::memory_order_relaxed);
		++t_allocs;
		if (bytes == g_watchedSize.load(std::memory_order_relaxed)) ++t_watchedAllocs;
	}

	// The C library's size for a block: what operator new adds to the live
	// total, and what operator delete takes back off it.
#if defined(_WIN32) || defined(_WIN64)
	constexpr bool kLiveTracked = true;
	std::size_t blockBytes(void* p) { return _msize(p); }
	std::size_t alignedBlockBytes(void* p, std::size_t a) { return _aligned_msize(p, a, 0); }
#elif defined(__APPLE__)
	constexpr bool kLiveTracked = true;
	std::size_t blockBytes(void* p) { return malloc_size(p); }
	std::size_t alignedBlockBytes(void* p, std::size_t) { return malloc_size(p); }
#elif defined(__GLIBC__)
	constexpr bool kLiveTracked = true;
	std::size_t blockBytes(void* p) { return malloc_usable_size(p); }
	std::size_t alignedBlockBytes(void* p, std::size_t) { return malloc_usable_size(p); }
#else
	constexpr bool kLiveTracked = false;
	std::size_t blockBytes(void*) { return 0; }
	std::size_t alignedBlockBytes(void*, std::size_t) { return 0; }
#endif

	void taken(std::size_t bytes)
	{
		g_liveBlocks.fetch_add(1, std::memory_order_relaxed);
		g_liveBytes.fetch_add(bytes, std::memory_order_relaxed);
	}

	void given(std::size_t bytes)
	{
		g_liveBlocks.fetch_sub(1, std::memory_order_relaxed);
		g_liveBytes.fetch_sub(bytes, std::memory_order_relaxed);
	}

	void* alignedAlloc(std::size_t n, std::align_val_t al)
	{
		const std::size_t a = static_cast<std::size_t>(al);
#if defined(_WIN32) || defined(_WIN64)
		return _aligned_malloc(n ? n : 1, a);
#else
		// aligned_alloc requires the size to be a multiple of the alignment.
		const std::size_t size = ((n ? n : 1) + a - 1) / a * a;
		return std::aligned_alloc(a, size);
#endif
	}

	void alignedFree(void* p, std::align_val_t al)
	{
		if (p == nullptr) return;
		given(alignedBlockBytes(p, static_cast<std::size_t>(al)));
#if defined(_WIN32) || defined(_WIN64)
		_aligned_free(p);
#else
		std::free(p);
#endif
	}

	void plainFree(void* p)
	{
		if (p == nullptr) return;
		given(blockBytes(p));
		std::free(p);
	}
}

std::size_t heapAllocCount() { return g_allocs.load(std::memory_order_relaxed); }
std::size_t threadHeapAllocCount() { return t_allocs; }
std::size_t heapLiveBlocks() { return g_liveBlocks.load(std::memory_order_relaxed); }
std::size_t heapLiveBytes() { return g_liveBytes.load(std::memory_order_relaxed); }
bool heapLiveTracked() { return kLiveTracked; }
void watchAllocSize(std::size_t bytes) { g_watchedSize.store(bytes, std::memory_order_relaxed); }
std::size_t threadWatchedAllocCount() { return t_watchedAllocs; }

// The nothrow forms are not replaced: the standard library implements them by
// calling these, so they are counted through here.
void* operator new(std::size_t n)
{
	count(n);
	if (void* p = std::malloc(n ? n : 1))
	{
		taken(blockBytes(p));
		return p;
	}
	throw std::bad_alloc();
}
void* operator new[](std::size_t n) { return operator new(n); }
void operator delete(void* p) noexcept { plainFree(p); }
void operator delete(void* p, std::size_t) noexcept { plainFree(p); }
void operator delete[](void* p) noexcept { plainFree(p); }
void operator delete[](void* p, std::size_t) noexcept { plainFree(p); }

// Over-aligned types (alignas > __STDCPP_DEFAULT_NEW_ALIGNMENT__) go through these.
void* operator new(std::size_t n, std::align_val_t al)
{
	count(n);
	if (void* p = alignedAlloc(n, al))
	{
		taken(alignedBlockBytes(p, static_cast<std::size_t>(al)));
		return p;
	}
	throw std::bad_alloc();
}
void* operator new[](std::size_t n, std::align_val_t al) { return operator new(n, al); }
void operator delete(void* p, std::align_val_t al) noexcept { alignedFree(p, al); }
void operator delete(void* p, std::size_t, std::align_val_t al) noexcept { alignedFree(p, al); }
void operator delete[](void* p, std::align_val_t al) noexcept { alignedFree(p, al); }
void operator delete[](void* p, std::size_t, std::align_val_t al) noexcept { alignedFree(p, al); }
