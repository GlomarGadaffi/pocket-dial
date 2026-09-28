#ifndef PD_SLOT_POOL_HPP
#define PD_SLOT_POOL_HPP

// Issue #479 (option D): a fixed set of N slots handed out by index. RtpSender
// claims one of the boot-allocated rtp_media_tx stacks on start() and returns it
// once its parked task has been reaped (pd::reapDecision). Empty pool: claim()
// returns -1 and counts the refusal; there is no heap fallback. Lock-free (one
// CAS on a bitmap), so any task may claim or release. Pure: host-tested.

#include <atomic>
#include <cstdint>

namespace pd
{
	template <int N>
	class SlotPool
	{
		static_assert(N > 0 && N <= 32, "SlotPool is a 32-bit bitmap");

	public:
		// Lowest free index, or -1 (counted) when every slot is in use.
		int claim()
		{
			uint32_t used = _used.load(std::memory_order_acquire);
			for (;;)
			{
				int i = 0;
				while (i < N && (used & (1u << i)) != 0) ++i;
				if (i == N)
				{
					_refused.fetch_add(1, std::memory_order_relaxed);
					return -1;
				}
				if (_used.compare_exchange_weak(used, used | (1u << i),
				                                std::memory_order_acq_rel, std::memory_order_acquire))
					return i;
			}
		}

		// Return a claimed slot. Out-of-range and repeated returns are no-ops.
		void release(int i)
		{
			if (i < 0 || i >= N) return;
			if ((_retiredMask.load(std::memory_order_acquire) & (1u << i)) != 0) return;
			_used.fetch_and(~(1u << i), std::memory_order_acq_rel);
		}

		int inUse() const
		{
			uint32_t u = _used.load(std::memory_order_acquire);
			int n = 0;
			for (; u != 0; u &= u - 1) ++n;
			return n;
		}

		uint32_t refused() const { return _refused.load(std::memory_order_relaxed); }

		// #598 review: take slot i out of service for good (its boot memory failed),
		// so claim() never hands it out and release() never revives it. Counted.
		void retire(int i)
		{
			if (i < 0 || i >= N) return;
			const uint32_t bit = 1u << i;
			if ((_retiredMask.fetch_or(bit, std::memory_order_acq_rel) & bit) != 0) return;
			_used.fetch_or(bit, std::memory_order_acq_rel);
		}

		uint32_t retired() const
		{
			uint32_t r = _retiredMask.load(std::memory_order_acquire), n = 0;
			for (; r != 0; r &= r - 1) ++n;
			return n;
		}

	private:
		std::atomic<uint32_t> _used{0};
		std::atomic<uint32_t> _refused{0};
		std::atomic<uint32_t> _retiredMask{0};
	};
}

#endif // PD_SLOT_POOL_HPP
