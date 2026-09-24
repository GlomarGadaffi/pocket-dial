#include "AllocCounter.hpp"

#include <atomic>
#include <cstdlib>
#include <new>

namespace
{
	std::atomic<std::size_t> g_allocs{0};
	// Trivially constructible, so reading it inside operator new never allocates.
	thread_local std::size_t t_allocs = 0;
}

std::size_t heapAllocCount() { return g_allocs.load(std::memory_order_relaxed); }
std::size_t threadHeapAllocCount() { return t_allocs; }

void* operator new(std::size_t n)
{
	g_allocs.fetch_add(1, std::memory_order_relaxed);
	++t_allocs;
	if (void* p = std::malloc(n ? n : 1)) return p;
	throw std::bad_alloc();
}
void* operator new[](std::size_t n) { return operator new(n); }
void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }
