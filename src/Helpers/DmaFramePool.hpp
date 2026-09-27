#ifndef DMA_FRAME_POOL_HPP
#define DMA_FRAME_POOL_HPP

#include <atomic>
#include <cstddef>
#include <cstdint>

#include "L2RtpFrame.hpp"
#include "PoolConfig.hpp"

// DmaFramePool: a shared, pre-allocated, fixed-size pool of DMA-capable
// FrameBuffers for real-time L2 RTP transmission (Issues #282 and #329).
//
// Why this exists (#329):
// On the W5500 SPI Ethernet variants, RTP frames transmitted via sendto()
// cross to lwIP, allocate pbufs that fall back to PSRAM under memory pressure,
// and trigger per-packet bounce allocations in the SPI driver
// (spicommon_dma_setup_priv_buffer). At 50 pkt/s, this burns through internal
// DMA headroom and causes total TX failure (#328).
//
// Instead of statically partitioning internal DRAM into dedicated per-feature
// arrays (e.g. 5.5 KB in HoldMusic, 4.4 KB in MixBus, etc.), this pool provides
// a small set of shared buffers in internal MALLOC_CAP_DMA memory.
//
// Concurrency & Real-Time Model:
// - SPI transmit is synchronous (spi_device_polling_transmit takes 52-85 us).
// - Buffers are borrowed only for the duration of template copy + patchTick +
//   transmitL2, then immediately returned.
// - At most 3 RTOS tasks ever transmit RTP (rtp_media_tx, hold_music_tx,
//   conf_mix_tick). On a dual-core ESP32-S3, at most 2 cores execute at once.
// - Sized to POCKETDIAL_DMA_FRAME_POOL_SIZE (default 6 frames, ~3.3 KB total).
// - Non-blocking acquire(): if the pool is momentarily starved, acquire()
//   fails fast (returns null) so the 20 ms packet drops cleanly and the remote
//   endpoint applies Packet Loss Concealment (PLC), rather than blocking and
//   introducing jitter or triggering watchdog timeouts.
namespace l2rtp
{
namespace detail
{
	// Issue #466: build a shared resource OUTSIDE any lock, then publish it
	// exactly once. `make()` may allocate (it must never run inside a
	// critical section -- allocating with interrupts masked is invalid on
	// IDF); a caller that loses the publish race destroys its own copy. Returns
	// whatever is published afterwards (null only if make() failed and nobody
	// else has published). Header-only and platform-free so the race logic is
	// host-tested (DmaFramePool_test) even though its user is ESP-only.
	template <class T, class Make, class Destroy>
	T publishOnce(std::atomic<T>& slot, Make make, Destroy destroy)
	{
		T cur = slot.load(std::memory_order_acquire);
		if (cur != T{}) return cur;
		T mine = make();
		if (mine == T{}) return slot.load(std::memory_order_acquire);
		T expected{};
		if (slot.compare_exchange_strong(expected, mine, std::memory_order_acq_rel,
		                                 std::memory_order_acquire))
			return mine;
		destroy(mine);
		return expected;
	}
}

class DmaFramePool
{
public:
	static constexpr size_t kPoolSize = POCKETDIAL_DMA_FRAME_POOL_SIZE;

	// RAII handle that borrows a FrameBuffer from the pool and automatically
	// recycles it back to the pool upon going out of scope.
	class Handle
	{
	public:
		Handle() noexcept = default;
		explicit Handle(FrameBuffer* buf) noexcept : _buf(buf) {}
		~Handle() { release(); }

		Handle(Handle&& other) noexcept : _buf(other._buf)
		{
			other._buf = nullptr;
		}

		Handle& operator=(Handle&& other) noexcept
		{
			if (this != &other)
			{
				release();
				_buf = other._buf;
				other._buf = nullptr;
			}
			return *this;
		}

		Handle(const Handle&) = delete;
		Handle& operator=(const Handle&) = delete;

		uint8_t* data() noexcept { return _buf ? _buf->bytes : nullptr; }
		const uint8_t* data() const noexcept { return _buf ? _buf->bytes : nullptr; }

		FrameBuffer* buffer() noexcept { return _buf; }
		const FrameBuffer* buffer() const noexcept { return _buf; }

		explicit operator bool() const noexcept { return _buf != nullptr; }

		void release() noexcept;

	private:
		FrameBuffer* _buf = nullptr;
	};

	// Initialize the buffer pool. Safe to call multiple times (idempotent).
	// Typically invoked once during network startup (e.g. esp_main_eth.cpp).
	static void init();

	// Borrow a buffer from the pool without blocking.
	// Returns a valid Handle if a buffer is available, or an empty Handle (evaluates
	// to false) if the pool is exhausted.
	static Handle acquire();

	// Telemetry & diagnostics
	static uint32_t getExhaustions() noexcept;
	static uint32_t getAllocations() noexcept;
	static size_t   available() noexcept;
	static void     resetStats() noexcept;
};
}   // namespace l2rtp

#endif // DMA_FRAME_POOL_HPP
