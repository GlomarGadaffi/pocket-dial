#ifndef HTTP_DRAM_ACCOUNT_HPP
#define HTTP_DRAM_ACCOUNT_HPP

// Per-consumer internal-DRAM accounting for the HTTP path (#410, #328).
//
// BENCH ONLY. HttpServer.cpp includes this and feeds it only when
// POCKETDIAL_HTTP_DRAM_ACCOUNT is 1 (PoolConfig.hpp, default 0); the
// counters then ride out as "httpDramAccount" on /api/status. docs/BENCH_PROBE.md
// has the how-to-read.
//
// Why it exists: on .244 minFreeHeapInternal fell from 31567 B to 475 B under
// HTTP load alone, and nothing said which part of the HTTP path held the bytes.
// Each consumer below is the bytes it actually holds, updated where it is
// allocated and released, so the operator can set the sum against that drop:
//
//   taskStack  the 4096 B stack of every live connection thread
//   reqBuf     the 4096 B read buffer of handleClient(), while a request is in flight and
//              only if it is in internal RAM (a PSRAM slot buffer, #410, counts 0)
//   reqRaw     the std::string copy of the request (heap only; a small string is free)
//   reqParsed  the parsed request's strings (the body is a second copy)
//   respBody   a response body built on the heap, while it is being sent
//              (the leased /api/status-style buffers are standing, not counted)
//
// Per consumer: now, hwm (its own high-water) and atPeak (what it held at the
// moment the TOTAL last set a new high). The per-consumer high-waters happen at
// different instants and do not add up to anything; total.hwm is the most the
// five ever held at once, and atPeak is who held it.
//
// Pure and header-only so the arithmetic is host-tested without a server. No
// mutex (a pthread mutex allocates on first lock) and no allocation: fixed
// atomics, relaxed ordering. atPeak is copied slot by slot, so it is
// approximate when connections overlap; the totals are exact.

#include <atomic>
#include <cstdint>
#include <string>

#if defined(ESP_PLATFORM)
#include "esp_memory_utils.h"   // esp_ptr_internal (main/HeapLeakProbe.cpp includes it too)
#endif

namespace httpdram
{
	enum Slot : unsigned { kTaskStack, kReqBuf, kReqRaw, kReqParsed, kRespBody, kSlotCount };
	inline constexpr const char* kSlotNames[kSlotCount] = {
		"taskStack", "reqBuf", "reqRaw", "reqParsed", "respBody"
	};

	// Is `p` in internal RAM? Only that counts as internal DRAM: a block malloc
	// placed in PSRAM (or a literal in flash) costs the bytes below nothing. On
	// the host everything counts, so the arithmetic stays testable.
	inline bool internalRam(const void* p)
	{
#if defined(ESP_PLATFORM)
		return esp_ptr_internal(p);
#else
		(void)p;
		return true;
#endif
	}

	// Internal bytes a std::string holds on the heap: 0 while it fits its
	// small-string buffer (the data pointer then points inside the object), else
	// capacity plus the terminator. Allocator overhead per block is not included.
	inline uint32_t heapBytes(const std::string& s)
	{
		const auto obj = reinterpret_cast<std::uintptr_t>(&s);
		const auto dat = reinterpret_cast<std::uintptr_t>(s.data());
		if (dat >= obj && dat < obj + sizeof(s)) return 0u;
		return internalRam(s.data()) ? static_cast<uint32_t>(s.capacity() + 1) : 0u;
	}
	template <class... S> uint32_t heapBytesOf(const S&... s) { return (heapBytes(s) + ... + 0u); }

	class Account
	{
	public:
		void add(Slot s, uint32_t n)
		{
			if (n == 0) return;
			raise(_hwm[s], _now[s].fetch_add(n, kRelaxed) + n);
			if (raise(_totalHwm, _totalNow.fetch_add(n, kRelaxed) + n))
				for (unsigned i = 0; i < kSlotCount; ++i) _atPeak[i].store(_now[i].load(kRelaxed), kRelaxed);
		}
		// Saturating: a release larger than the hold takes only what is held, so a
		// bookkeeping slip can never wrap a counter.
		void sub(Slot s, uint32_t n)
		{
			if (n == 0) return;
			uint32_t held = _now[s].load(kRelaxed), take;
			do { take = n < held ? n : held; } while (!_now[s].compare_exchange_weak(held, held - take, kRelaxed));
			if (take != 0) _totalNow.fetch_sub(take, kRelaxed);
		}

		// One connection thread and its stack. spawnFailed() undoes opened() for a
		// thread that could not be created.
		void opened(uint32_t stackBytes)
		{
			raise(_connsHwm, _connsNow.fetch_add(1, kRelaxed) + 1);
			add(kTaskStack, stackBytes);
		}
		void closed(uint32_t stackBytes)
		{
			uint32_t c = _connsNow.load(kRelaxed);
			while (c != 0 && !_connsNow.compare_exchange_weak(c, c - 1, kRelaxed)) {}
			sub(kTaskStack, stackBytes);
		}
		void spawnFailed(uint32_t stackBytes) { closed(stackBytes); _spawnFailures.fetch_add(1, kRelaxed); }

		// The largest response body built on the heap and handed to the send path.
		void noteBody(uint32_t n) { raise(_bodyMax, n); }

		uint32_t now(Slot s) const { return _now[s].load(kRelaxed); }
		uint32_t hwm(Slot s) const { return _hwm[s].load(kRelaxed); }
		uint32_t atPeak(Slot s) const { return _atPeak[s].load(kRelaxed); }
		uint32_t totalNow() const { return _totalNow.load(kRelaxed); }
		uint32_t totalHwm() const { return _totalHwm.load(kRelaxed); }
		uint32_t connsNow() const { return _connsNow.load(kRelaxed); }
		uint32_t connsHwm() const { return _connsHwm.load(kRelaxed); }
		uint32_t bodyMax() const { return _bodyMax.load(kRelaxed); }
		uint32_t spawnFailures() const { return _spawnFailures.load(kRelaxed); }

		// Tests only, with no other thread touching the account.
		void reset()
		{
			for (unsigned i = 0; i < kSlotCount; ++i) { _now[i] = 0; _hwm[i] = 0; _atPeak[i] = 0; }
			_totalNow = 0; _totalHwm = 0; _connsNow = 0; _connsHwm = 0; _bodyMax = 0; _spawnFailures = 0;
		}

		// ,"httpDramAccount":{...} for a writer with s(string_view) and n(number).
		template <class Out> void writeJson(Out& out) const
		{
			out.s(",\"httpDramAccount\":{\"conns\":{\"now\":").n(connsNow()).s(",\"hwm\":").n(connsHwm()).s("}");
			for (unsigned i = 0; i < kSlotCount; ++i)
			{
				const Slot s = static_cast<Slot>(i);
				out.s(",\"").s(kSlotNames[i]).s("\":{\"now\":").n(now(s)).s(",\"hwm\":").n(hwm(s))
				   .s(",\"atPeak\":").n(atPeak(s)).s("}");
			}
			out.s(",\"total\":{\"now\":").n(totalNow()).s(",\"hwm\":").n(totalHwm())
			   .s("},\"respBodyMax\":").n(bodyMax()).s(",\"spawnFailures\":").n(spawnFailures()).s("}");
		}

	private:
		static constexpr std::memory_order kRelaxed = std::memory_order_relaxed;
		// C++17 has no fetch_max. True when this call raised the mark.
		static bool raise(std::atomic<uint32_t>& hwm, uint32_t v)
		{
			uint32_t h = hwm.load(kRelaxed);
			while (v > h)
				if (hwm.compare_exchange_weak(h, v, kRelaxed)) return true;
			return false;
		}

		std::atomic<uint32_t> _now[kSlotCount]{};
		std::atomic<uint32_t> _hwm[kSlotCount]{};
		std::atomic<uint32_t> _atPeak[kSlotCount]{};
		std::atomic<uint32_t> _totalNow{0}, _totalHwm{0};
		std::atomic<uint32_t> _connsNow{0}, _connsHwm{0};
		std::atomic<uint32_t> _bodyMax{0}, _spawnFailures{0};
	};

	// One request's hold on one consumer. set() moves the account by the
	// difference, so a buffer that grows or shrinks is tracked with no bookkeeping
	// at the call site, and the destructor releases whatever is still held on
	// every exit path (handleClient() has dozens of returns).
	class Held
	{
	public:
		Held(Account& a, Slot s) : _a(a), _s(s) {}
		Held(const Held&) = delete;
		Held& operator=(const Held&) = delete;
		~Held() { _a.sub(_s, _held); }
		void set(uint32_t bytes)
		{
			if (bytes > _held) _a.add(_s, bytes - _held);
			else if (bytes < _held) _a.sub(_s, _held - bytes);
			_held = bytes;
		}
	private:
		Account& _a;
		Slot _s;
		uint32_t _held = 0;
	};

	// The process-wide account HttpServer.cpp feeds. Constant-initialised: no
	// guard variable, no allocation, usable before main().
	inline Account gAccount;
}

#endif
