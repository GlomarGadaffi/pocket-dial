#pragma once

// DropProbe -- why RequestsHandler::handle() refused a datagram (issue #430).
//
// packetsDropped used to be one number covering two unrelated refusals:
// structurally invalid messages (isValidMessage()) and the per-IP allowlist /
// token bucket. On .244 it climbed a steady ~5% at idle with no way to tell
// which, or from whom. This keeps a count per reason plus the last kRingSize
// refusals: when, from where, how long, and the first kHeadBytes bytes.
//
// Hot-path rules (milestone 1): note() never allocates and never logs. The ring
// is a fixed std::array inside the owner, written under its own small mutex
// (never RequestsHandler::_mutex, which handle() does not hold at either drop
// site). Only recent() -- the HTTP side -- builds a vector.

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include <lwip/sockets.h>
#elif defined(__linux__)
#include <arpa/inet.h>
#elif defined _WIN32 || defined _WIN64
#include <WinSock2.h>
#include <ws2tcpip.h>
#endif

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string_view>
#include <vector>

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
		uint64_t    seq      = 0;   // monotonic across evictions
		uint64_t    tsUs     = 0;   // steady clock, same basis as PcapCapture
		sockaddr_in src{};          // zero when the message had no source (null request)
		uint32_t    len      = 0;   // full datagram length
		Reason      reason   = Reason::Invalid;
		uint8_t     headLen  = 0;   // bytes valid in `head`
		std::array<uint8_t, kHeadBytes> head{};
	};

	void note(Reason reason, const sockaddr_in& src, std::string_view bytes)
	{
		(reason == Reason::Invalid ? _invalid : _rate).fetch_add(1, std::memory_order_relaxed);

		std::lock_guard<std::mutex> lk(_mutex);
		Record& r = _ring[_nextSeq % kRingSize];
		r.seq     = _nextSeq++;
		r.tsUs    = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
			std::chrono::steady_clock::now().time_since_epoch()).count());
		r.src     = src;
		r.len     = static_cast<uint32_t>(bytes.size());
		r.reason  = reason;
		r.headLen = static_cast<uint8_t>(std::min(bytes.size(), kHeadBytes));
		if (r.headLen > 0) std::memcpy(r.head.data(), bytes.data(), r.headLen);   // an empty view's data() may be null
	}

	uint64_t invalidCount() const { return _invalid.load(std::memory_order_relaxed); }
	uint64_t rateCount() const { return _rate.load(std::memory_order_relaxed); }

	// Oldest first, at most kRingSize. HTTP side only: allocates the vector.
	std::vector<Record> recent() const
	{
		std::vector<Record> out;
		out.reserve(kRingSize);
		std::lock_guard<std::mutex> lk(_mutex);
		const uint64_t n = std::min<uint64_t>(_nextSeq, kRingSize);
		for (uint64_t s = _nextSeq - n; s < _nextSeq; ++s)
		{
			out.push_back(_ring[s % kRingSize]);
		}
		return out;
	}

	static const char* reasonName(Reason r) { return r == Reason::Rate ? "rate" : "invalid"; }

private:
	std::atomic<uint64_t> _invalid{0};
	std::atomic<uint64_t> _rate{0};
	mutable std::mutex _mutex;
	std::array<Record, kRingSize> _ring{};
	uint64_t _nextSeq = 0;
};
