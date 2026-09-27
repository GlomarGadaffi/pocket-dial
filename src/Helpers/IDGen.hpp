#ifndef IDGEN_HPP
#define IDGEN_HPP

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include "esp_random.h"
#else
#include <chrono>
#include <mutex>
#include <random>
#endif

// Every Call-ID, To-tag, From-tag and Via branch the PBX mints comes from here,
// so these identifiers must be UNPREDICTABLE: on most paths they are the only
// thing distinguishing a real in-dialog message from a forged one (#385, #356).
//
// Until #385 this drew from a thread_local std::minstd_rand -- 31 bits of state,
// recoverable from ONE observed 16-character Call-ID by brute force (seconds on
// a laptop; tests/IDGenPredict_test.cpp runs that attack for real), after which
// every later identifier from that task was predictable.
//
// Randomness now follows the split AdminAuth::fillRandom() established:
//   * ESP: esp_fill_random(), the hardware CSPRNG (the batch form of the
//     esp_random() AdminAuth calls per byte). STATELESS -- no thread_local, so
//     it cannot reproduce #74, where an mt19937 in the per-task TLS block
//     overran the ~1.3 KB IPC task stacks and bootlooped the board.
//   * Host: a function-local static mt19937_64 seeded from random_device plus a
//     steady_clock sample, behind a mutex. NOT thread_local (the #74 shape).
//     Host is a developer/CI simulator, not the production trust boundary --
//     see docs/THREAT_MODEL.md.
class IDGen
{
public:
	IDGen() = delete;

	static std::string GenerateID(int len)
	{
		std::string id;
		id.reserve(len > 0 ? static_cast<size_t>(len) : 0);
		uint8_t block[16];
		size_t pos = sizeof(block);
		while (static_cast<int>(id.size()) < len)
		{
			if (pos == sizeof(block))
			{
				fillRandom(block, sizeof(block));
				pos = 0;
			}
			// Rejection sampling, not `% 62`: the low 6 bits are uniform over
			// 0..63, and redrawing 62/63 leaves 0..61 exactly uniform. A modulo
			// would favour the first symbols -- small, but this is the one
			// generator whose whole job is to be unguessable.
			const uint8_t v = block[pos++] & 0x3F;
			if (v < kAlphabetSize) id += alphanum[v];
		}
		return id;
	}

#if !(defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO))
	// Host test seam (tests/IDGen_test.cpp): route GenerateID's bytes through a
	// fixed source, which pins that GenerateID draws from fillRandom() and
	// nothing else -- an "optimisation" back to a local LCG fails it. nullptr
	// restores the real source. Not compiled into device firmware.
	using ByteSource = void (*)(uint8_t* buf, size_t len);
	static void setByteSourceForTest(ByteSource source) { byteSource().store(source); }
#endif

private:
	static void fillRandom(uint8_t* buf, size_t len)
	{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		esp_fill_random(buf, len);
#else
		if (ByteSource source = byteSource().load())
		{
			source(buf, len);
			return;
		}
		static std::mutex mutex;
		static std::mt19937_64 rng = [] {
			std::random_device rd;
			uint64_t seed = (static_cast<uint64_t>(rd()) << 32) ^ rd();
			seed ^= static_cast<uint64_t>(
				std::chrono::steady_clock::now().time_since_epoch().count());
			return std::mt19937_64(seed);
		}();
		std::lock_guard<std::mutex> lock(mutex);
		for (size_t i = 0; i < len; ++i)
		{
			buf[i] = static_cast<uint8_t>(rng() & 0xFF);
		}
#endif
	}

#if !(defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO))
	static std::atomic<ByteSource>& byteSource()
	{
		static std::atomic<ByteSource> source{nullptr};
		return source;
	}
#endif

	static constexpr char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";
	static constexpr uint8_t kAlphabetSize = sizeof(alphanum) - 1;   // 62
	static_assert(kAlphabetSize == 62, "rejection sampling above assumes 62 symbols in a 64-slot draw");
};

#endif
