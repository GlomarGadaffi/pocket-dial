#ifndef POCKETDIAL_LOG2_US_HPP
#define POCKETDIAL_LOG2_US_HPP

// The log2-microsecond histogram arithmetic #988 introduced for TimedMutex,
// factored out so the media-path instrument (MediaTxStats.hpp, #985) buckets and
// reads percentiles exactly the same way. Pure functions: no storage, no clock.
// Each user keeps its own counters, because the writers differ (TimedMutex's are
// serialised by the lock it measures; the media tasks' are not).

#include <cstdint>

namespace pd
{
	namespace log2us
	{
		// Bucket b holds [2^(b-1), 2^b) us; bucket 0 is a zero-length sample; the last
		// is open at the top (>= 4.2 s).
		inline constexpr unsigned kBuckets = 24;

		inline unsigned bucketOf(uint32_t us)
		{
			unsigned b = 0;
			while (us != 0 && b < kBuckets - 1) { ++b; us >>= 1; }
			return b;
		}

		// The upper bound, in us, of the bucket holding the num/den quantile of `total`
		// samples (99/100 is p99), never above `maxUs`. `load(b)` returns bucket b's count.
		// ceil(total * num / den) is the rank, so one slow sample in a hundred is p99's
		// edge, not p100's.
		template <class Load>
		inline uint32_t quantileUs(Load load, uint32_t total, uint32_t num, uint32_t den, uint32_t maxUs)
		{
			const uint64_t rank = (uint64_t{total} * num + (den - 1)) / den;
			uint64_t cum = 0;
			for (unsigned b = 0; b < kBuckets; ++b)
			{
				cum += load(b);
				if (cum < rank) continue;
				const uint32_t top = b == 0 ? 0u : b == kBuckets - 1 ? maxUs : (1u << b) - 1;
				return top < maxUs ? top : maxUs;
			}
			return maxUs;
		}
	}
}

#endif // POCKETDIAL_LOG2_US_HPP
