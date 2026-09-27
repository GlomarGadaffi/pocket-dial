#ifndef PLAYOUT_BUFFER_HPP
#define PLAYOUT_BUFFER_HPP

#include <vector>
#include <mutex>
#include <cstdint>
#include <cstddef>
#include <atomic>

#include "PsramAllocator.hpp"

class PlayoutBuffer
{
public:
	// Default max samples 1600 (200 ms @ 8 kHz) — the HARD latency ceiling: a producer
	// burst can never park more than 200 ms of audio here (overrun drops oldest). The old
	// 8000 (1 s) let mouth-to-ear delay balloon. Steady-state is held far lower by the
	// target-depth drain in read() (see _targetDepth).
	explicit PlayoutBuffer(size_t maxSamples = 1600);
	~PlayoutBuffer() = default;

	// Write linear PCM16 samples to the buffer (called by the HTTP RX thread).
	// If the buffer overflows, oldest samples are dropped to make room.
	// Returns the number of samples successfully written.
	size_t write(const int16_t* samples, size_t count);

	// Read linear PCM16 samples from the buffer (called by the RTP TX thread every 20ms).
	// Always fills 'out' with 'count' samples. If underrun, fills the rest with
	// low-amplitude comfort noise.
	// Returns true if all requested samples were read from the buffer,
	// false if an underrun occurred.
	bool read(int16_t* out, size_t count);

	// Get current buffered sample count
	size_t getLength() const;

	// Reset buffer (clear all samples, reset stats)
	void clear();

	// Statistics queries
	uint64_t getUnderruns() const { return _underruns.load(std::memory_order_relaxed); }
	uint64_t getOverruns() const { return _overruns.load(std::memory_order_relaxed); }
	size_t getTargetDepth() const { return _targetDepth.load(std::memory_order_relaxed); }

	// Set/Get target playout delay (in samples)
	void setTargetDepth(size_t samples);

private:
	// Issue #466: the ring lives in PSRAM where the board has it. At the
	// default 1600 samples it is 3,200 B -- under IDF's 16 KB PSRAM threshold,
	// so a plain vector put every ring in internal DRAM: the first 888 call's
	// ConferenceRoom alone holds 20 of them (64 KB, never freed), and every
	// bridged call's MediaBridge more. Only tasks touch it (RTP rx/tx, the
	// conference tick) -- never an ISR, DMA, or a task mid flash-write.
	std::vector<int16_t, PsramAllocator<int16_t>> _buffer;
	size_t _maxSamples;
	size_t _readPtr = 0;
	size_t _writePtr = 0;
	size_t _count = 0;

	mutable std::mutex _mutex;

	// Target playout depth = the standing jitter cushion read() drains toward (60 ms = 480
	// samples @ 8 kHz). read() drops the oldest excess whenever the buffer drifts above
	// target, so latency walks back DOWN instead of accumulating. Lower = less delay but
	// more underrun risk on a bursty/lossy (TCP) trunk; tune against getUnderruns().
	std::atomic<size_t> _targetDepth{480};

	// Statistics
	std::atomic<uint64_t> _underruns{0};
	std::atomic<uint64_t> _overruns{0};
};

#endif // PLAYOUT_BUFFER_HPP
