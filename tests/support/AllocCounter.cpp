#include "AllocCounter.hpp"

#include <atomic>
#include <cstdlib>
#include <new>

namespace
{
	std::atomic<std::size_t> g_allocs{0};
	// Trivially constructible, so reading it inside operator new never allocates.
	thread_local std::size_t t_allocs = 0;

	void count()
	{
		g_allocs.fetch_add(1, std::memory_order_relaxed);
		++t_allocs;
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

	void alignedFree(void* p)
	{
#if defined(_WIN32) || defined(_WIN64)
		_aligned_free(p);
#else
		std::free(p);
#endif
	}
}

std::size_t heapAllocCount() { return g_allocs.load(std::memory_order_relaxed); }
std::size_t threadHeapAllocCount() { return t_allocs; }

// The nothrow forms are not replaced: the standard library implements them by
// calling these, so they are counted through here.
void* operator new(std::size_t n)
{
	count();
	if (void* p = std::malloc(n ? n : 1)) return p;
	throw std::bad_alloc();
}
void* operator new[](std::size_t n) { return operator new(n); }
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }

// Over-aligned types (alignas > __STDCPP_DEFAULT_NEW_ALIGNMENT__) go through these.
void* operator new(std::size_t n, std::align_val_t al)
{
	count();
	if (void* p = alignedAlloc(n, al)) return p;
	throw std::bad_alloc();
}
void* operator new[](std::size_t n, std::align_val_t al) { return operator new(n, al); }
void operator delete(void* p, std::align_val_t) noexcept { alignedFree(p); }
void operator delete(void* p, std::size_t, std::align_val_t) noexcept { alignedFree(p); }
void operator delete[](void* p, std::align_val_t) noexcept { alignedFree(p); }
void operator delete[](void* p, std::size_t, std::align_val_t) noexcept { alignedFree(p); }
