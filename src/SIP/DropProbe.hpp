#pragma once

// DropProbe -- why RequestsHandler::handle() refused a datagram (issue #430).
//
// packetsDropped used to be one number covering two unrelated refusals:
// structurally invalid messages (isValidMessage()) and the per-IP allowlist /
// token bucket. On .244 it climbed a steady ~5% at idle with no way to tell
// which, or from whom. This keeps a count per reason plus the last kRingSize
// refusals: when, from where, how long, and the first kHeadBytes bytes.
//
// Rules (milestone 1), on BOTH sides:
//   - note() (SIP receive path) never allocates and never logs. The ring is a
//     fixed std::array inside the owner, written under the probe's own small
//     mutex -- never RequestsHandler::_mutex, which handle() does not hold at
//     either drop site.
//   - the reader (HTTP, /api/status) never allocates either, and never holds
//     the mutex while it formats: it copies ONE Record at a time with at(), so
//     the only stack it needs is one Record (the http_conn thread is 4 KB and
//     its margin is what #405 measures), and note() is never blocked behind
//     string formatting.
//   - counters are 32-bit: a 64-bit std::atomic is not lock-free on Xtensa.

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string_view>

class DropProbe
{
public:
	enum class Reason : uint8_t
	{
		Invalid,   // null or !isValidMessage() (SEC-02 / #265)
		Rate,      // !ipAllowed() || !allowPacket() (#38)
	};

	static constexpr std::size_t kRingSize  = 16;
	static constexpr std::size_t kHeadBytes = 16;

	struct Record
	{
		uint64_t tsUs    = 0;   // steady clock, same basis as PcapCapture
		uint32_t seq     = 0;   // monotonic across evictions
		uint32_t ip      = 0;   // network byte order; 0 when the message had no source
		uint16_t port    = 0;   // network byte order
		uint16_t len     = 0;   // full datagram length, saturated at 65535
		Reason   reason  = Reason::Invalid;
		uint8_t  headLen = 0;   // bytes valid in `head`
		std::array<uint8_t, kHeadBytes> head{};
	};

	// ip/port in network byte order, straight from sockaddr_in.
	void note(Reason reason, uint32_t ip, uint16_t port, std::string_view bytes)
	{
		(reason == Reason::Invalid ? _invalid : _rate).fetch_add(1, std::memory_order_relaxed);

		std::lock_guard<std::mutex> lk(_mutex);
		Record& r = _ring[_nextSeq % kRingSize];
		r.seq     = _nextSeq++;
		if (_live < kRingSize) ++_live;
		r.tsUs    = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
			std::chrono::steady_clock::now().time_since_epoch()).count());
		r.ip      = ip;
		r.port    = port;
		r.len     = static_cast<uint16_t>(std::min<std::size_t>(bytes.size(), 0xFFFFu));
		r.reason  = reason;
		r.headLen = static_cast<uint8_t>(std::min(bytes.size(), kHeadBytes));
		if (r.headLen > 0) std::memcpy(r.head.data(), bytes.data(), r.headLen);   // an empty view's data() may be null
	}

	uint32_t invalidCount() const { return _invalid.load(std::memory_order_relaxed); }
	uint32_t rateCount() const { return _rate.load(std::memory_order_relaxed); }

	// The live window as sequence numbers [first, end): oldest first, at most
	// kRingSize. Read it with at(); a record evicted in between reports false.
	void window(uint32_t& first, uint32_t& end) const
	{
		std::lock_guard<std::mutex> lk(_mutex);
		end   = _nextSeq;
		first = end - _live;   // modular: stays right across a 2^32 wrap
	}

	bool at(uint32_t seq, Record& out) const
	{
		std::lock_guard<std::mutex> lk(_mutex);
		const uint32_t age = _nextSeq - seq;   // modular, like window()
		if (age == 0 || age > _live) return false;
		out = _ring[seq % kRingSize];
		return true;
	}

	static const char* reasonName(Reason r) { return r == Reason::Rate ? "rate" : "invalid"; }

private:
	std::atomic<uint32_t> _invalid{0};
	std::atomic<uint32_t> _rate{0};
	mutable std::mutex _mutex;
	std::array<Record, kRingSize> _ring{};
	uint32_t _nextSeq = 0;
	uint32_t _live = 0;   // records written so far, saturating at kRingSize
};
