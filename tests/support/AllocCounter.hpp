#ifndef POCKETDIAL_TEST_ALLOC_COUNTER_HPP
#define POCKETDIAL_TEST_ALLOC_COUNTER_HPP

// Counting global operator new, shared by every test in sip_parser_tests.
//
// AllocCounter.cpp replaces the global operator new/delete for the whole test
// binary. There can only be one replacement per binary, so any test that wants
// to assert "this path touches no heap" includes this header rather than
// defining its own. Memory still comes from malloc/free; counting is the only
// behavioural change. Deallocations are not counted.

#include <cstddef>

// Every operator new / new[] call in the process since startup.
std::size_t heapAllocCount();

// Only those made on the calling thread. Prefer this for "zero allocations in
// this block" assertions: other threads in the binary (RtpSender's pacer, the
// conference tick driver) allocate concurrently and would add noise.
std::size_t threadHeapAllocCount();

// Counts the calling thread's allocations between construction and delta().
class AllocGuard
{
public:
	AllocGuard() : _start(threadHeapAllocCount()) {}
	std::size_t delta() const { return threadHeapAllocCount() - _start; }

private:
	std::size_t _start;
};

#endif
