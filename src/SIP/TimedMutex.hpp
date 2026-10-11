#ifndef POCKETDIAL_TIMED_MUTEX_HPP
#define POCKETDIAL_TIMED_MUTEX_HPP

// Issue #986 slice 0 (instrument only): RequestsHandler::_mutex guards nearly all
// signalling state and the SIP thread holds it across handle(). This wraps
// std::mutex and measures how long each hold lasts, so the work done under it
// (NVS commits, the PIN hash, the syslog send) can be ranked by real cost
// before any of it moves. It changes no behaviour.
//
//  - lock() stamps the clock and the CALLER's return address (it is noinline so
//    __builtin_return_address(0) names the call site that took the lock; that
//    holds for std::lock_guard and std::unique_lock because their constructors
//    inline into the site). unlock() records the hold BEFORE it releases the inner
//    mutex, so the writers are serialised by the lock itself and the counters
//    are plain relaxed load+store, never a read-modify-write.
//  - The stats are static storage (BSS), one set per process: the firmware has
//    one RequestsHandler, so one mutex. Nothing here allocates. A log2-us
//    histogram, the max hold with its call site, and the count over 20 ms.
//  - Nothing here logs. A hold over kOverUs claims a slot in a fixed site table.
//    RequestsHandler::tick() drains it with takeSlowSite() AFTER its own lock
//    scope and writes one witness line per site per boot. Logging from unlock
//    would put the console, or a syslog send, inside the lock being measured.
//  - Readers (/api/status, tick) take no lock, only 32-bit relaxed atomics. The
//    max hold and its pc are two loads, so a reader can pair a new max with the
//    previous holder for one poll; the next poll is consistent.
//
// The clock is a template parameter so the unit tests can drive it.

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>

#if defined(ESP_PLATFORM)
#include "esp_timer.h"
#endif

#if defined(_MSC_VER)
#include <intrin.h>
#define PD_TIMED_MUTEX_NOINLINE __declspec(noinline)
#define PD_TIMED_MUTEX_RETURN_ADDRESS() _ReturnAddress()
#else
#define PD_TIMED_MUTEX_NOINLINE __attribute__((noinline))
#define PD_TIMED_MUTEX_RETURN_ADDRESS() __builtin_return_address(0)
#endif

namespace pd
{
	// What /api/status reports. p99Us is an upper bound: the top edge of the log2
	// bucket holding the 99th-percentile hold, never above maxUs.
	struct MutexHold
	{
		uint32_t  holds = 0;
		uint32_t  maxUs = 0;
		uint32_t  p99Us = 0;
		uint32_t  over  = 0;
		uintptr_t maxPc = 0;
	};

	// A call site whose hold went over the threshold, and its longest hold so far.
	struct SlowSite
	{
		uintptr_t pc    = 0;
		uint32_t  maxUs = 0;
	};

	struct MutexClockUs
	{
		static int64_t nowUs()
		{
#if defined(ESP_PLATFORM)
			return esp_timer_get_time();
#else
			return std::chrono::duration_cast<std::chrono::microseconds>(
				std::chrono::steady_clock::now().time_since_epoch()).count();
#endif
		}
	};

	template <class Clock>
	class BasicTimedMutex
	{
	public:
		static constexpr uint32_t kOverUs   = 20000;   // 20 ms: an anchor worker takes the lock every 20 ms frame
		static constexpr unsigned kBuckets  = 24;      // bucket b = [2^(b-1), 2^b) us; the last is open (>= 4.2 s)
		static constexpr unsigned kSites    = 8;       // ponytail: a ninth slow site counts in `over` and is never named

		PD_TIMED_MUTEX_NOINLINE void lock()
		{
			_m.lock();
			_startUs = Clock::nowUs();
			_pc = callSite(reinterpret_cast<uintptr_t>(PD_TIMED_MUTEX_RETURN_ADDRESS()));
		}

		PD_TIMED_MUTEX_NOINLINE bool try_lock()
		{
			if (!_m.try_lock()) return false;
			_startUs = Clock::nowUs();
			_pc = callSite(reinterpret_cast<uintptr_t>(PD_TIMED_MUTEX_RETURN_ADDRESS()));
			return true;
		}

		void unlock()
		{
			record(Clock::nowUs() - _startUs, _pc);
			_m.unlock();
		}

		static unsigned bucketOf(uint32_t us)
		{
			unsigned b = 0;
			while (us != 0 && b < kBuckets - 1) { ++b; us >>= 1; }
			return b;
		}

		// One finished hold. Writers must be serialised: unlock() holds the mutex.
		static void record(int64_t holdUs, uintptr_t pc)
		{
			const uint32_t us = holdUs <= 0 ? 0u : holdUs > 0xffffffffLL ? 0xffffffffu : static_cast<uint32_t>(holdUs);
			bump(s_.hist[bucketOf(us)]);
			if (us > s_.maxUs.load(kRelaxed))
			{
				s_.maxUs.store(us, kRelaxed);
				s_.maxPc.store(pc, kRelaxed);
			}
			if (us > kOverUs)
			{
				bump(s_.over);
				noteSlow(pc, us);
			}
		}

		static MutexHold snapshot()
		{
			MutexHold r;
			r.maxUs = s_.maxUs.load(kRelaxed);
			r.maxPc = s_.maxPc.load(kRelaxed);
			r.over  = s_.over.load(kRelaxed);
			for (unsigned b = 0; b < kBuckets; ++b) r.holds += s_.hist[b].load(kRelaxed);
			const uint64_t rank = (uint64_t{r.holds} * 99 + 99) / 100;   // ceil(0.99 * holds)
			uint64_t cum = 0;
			r.p99Us = r.maxUs;
			for (unsigned b = 0; b < kBuckets; ++b)
			{
				cum += s_.hist[b].load(kRelaxed);
				if (cum < rank) continue;
				const uint32_t top = b == 0 ? 0u : b == kBuckets - 1 ? r.maxUs : (1u << b) - 1;
				r.p99Us = top < r.maxUs ? top : r.maxUs;
				break;
			}
			return r;
		}

		// The next slow site not yet reported, marked reported. false when none is left.
		// One consumer: RequestsHandler::tick(), outside the lock.
		static bool takeSlowSite(SlowSite& out)
		{
			for (Site& e : s_.sites)
			{
				const uintptr_t pc = e.pc.load(std::memory_order_acquire);
				if (pc == 0) return false;   // sites fill in order
				if (e.reported.exchange(true, kRelaxed)) continue;
				out.pc    = pc;
				out.maxUs = e.maxUs.load(kRelaxed);
				return true;
			}
			return false;
		}

		static void resetForTest()
		{
			for (auto& h : s_.hist) h.store(0, kRelaxed);
			s_.maxUs.store(0, kRelaxed);
			s_.maxPc.store(0, kRelaxed);
			s_.over.store(0, kRelaxed);
			for (Site& e : s_.sites)
			{
				e.pc.store(0, kRelaxed);
				e.maxUs.store(0, kRelaxed);
				e.reported.store(false, kRelaxed);
			}
		}

	private:
		static constexpr std::memory_order kRelaxed = std::memory_order_relaxed;

		struct Site
		{
			std::atomic<uintptr_t> pc;
			std::atomic<uint32_t>  maxUs;
			std::atomic<bool>      reported;
		};
		struct Stats
		{
			std::atomic<uint32_t>  hist[kBuckets];
			std::atomic<uint32_t>  maxUs;
			std::atomic<uintptr_t> maxPc;
			std::atomic<uint32_t>  over;
			Site                   sites[kSites];
		};

		static void bump(std::atomic<uint32_t>& a) { a.store(a.load(kRelaxed) + 1, kRelaxed); }

		static void noteSlow(uintptr_t pc, uint32_t us)
		{
			for (Site& e : s_.sites)
			{
				const uintptr_t at = e.pc.load(kRelaxed);
				if (at == pc)
				{
					if (us > e.maxUs.load(kRelaxed)) e.maxUs.store(us, kRelaxed);
					return;
				}
				if (at == 0)
				{
					e.maxUs.store(us, kRelaxed);
					e.pc.store(pc, std::memory_order_release);   // last: takeSlowSite() reads maxUs after pc
					return;
				}
			}
		}

		// GCC's Xtensa __builtin_return_address already replaces the window-increment
		// bits of a0; this keeps maxPc addr2line-able even if a toolchain does not. Code
		// on the S3 is all in 0x40000000..0x7fffffff, so it changes nothing else.
		static uintptr_t callSite(uintptr_t ra)
		{
#if defined(ESP_PLATFORM)
			return (ra & 0x3fffffffu) | 0x40000000u;
#else
			return ra;
#endif
		}

		std::mutex _m;
		int64_t    _startUs = 0;   // written and read only by the holder
		uintptr_t  _pc = 0;

		static inline Stats s_{};
	};

	using TimedMutex = BasicTimedMutex<MutexClockUs>;
}

#undef PD_TIMED_MUTEX_NOINLINE
#undef PD_TIMED_MUTEX_RETURN_ADDRESS

#endif // POCKETDIAL_TIMED_MUTEX_HPP
