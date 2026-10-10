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
//   reqBuf     the 4096 B read buffer handleClient() allocates per request
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
		// `tail(out)` writes more members INSIDE the object, each starting with a
		// comma, after spawnFailures (the Probes below): the object stays one key of
		// /api/status, so the top-level key list is not touched.
		template <class Out, class Tail> void writeJson(Out& out, Tail&& tail) const
		{
			out.s(",\"httpDramAccount\":{\"conns\":{\"now\":").n(connsNow()).s(",\"hwm\":").n(connsHwm()).s("}");
			for (unsigned i = 0; i < kSlotCount; ++i)
			{
				const Slot s = static_cast<Slot>(i);
				out.s(",\"").s(kSlotNames[i]).s("\":{\"now\":").n(now(s)).s(",\"hwm\":").n(hwm(s))
				   .s(",\"atPeak\":").n(atPeak(s)).s("}");
			}
			out.s(",\"total\":{\"now\":").n(totalNow()).s(",\"hwm\":").n(totalHwm())
			   .s("},\"respBodyMax\":").n(bodyMax()).s(",\"spawnFailures\":").n(spawnFailures());
			tail(out);
			out.s("}");
		}
		template <class Out> void writeJson(Out& out) const { writeJson(out, [](Out&) {}); }

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

	// ---- Probes: the share the five consumers above cannot see (#410, #328) ----
	//
	// On .244 the HTTP-load drop of minFreeHeapInternal was 38.4 KB with 16.9 KB
	// accounted: about 21.5 KB elastic and unattributed. Candidates are the lwIP
	// send queues (a socket send COPIES the response into heap pbufs, from PSRAM
	// or not, and holds them until the peer acknowledges), the per-thread cost
	// beyond the stack (TCB, pthread state), heap fragmentation and the task
	// count. These are sampled readings, not holds: each Gauge keeps the last,
	// lowest and highest value it was given and how many samples that was.

	// Fixed atomics, no allocation. min reads 0 until the first sample.
	class Gauge
	{
	public:
		void sample(uint32_t v)
		{
			_last.store(v, kRelaxed);
			uint32_t h = _max.load(kRelaxed);
			while (v > h && !_max.compare_exchange_weak(h, v, kRelaxed)) {}
			uint32_t l = _min.load(kRelaxed);
			while (v < l && !_min.compare_exchange_weak(l, v, kRelaxed)) {}
			_n.fetch_add(1, kRelaxed);
		}
		uint32_t n() const { return _n.load(kRelaxed); }
		uint32_t last() const { return _last.load(kRelaxed); }
		uint32_t min() const { return n() != 0 ? _min.load(kRelaxed) : 0u; }
		uint32_t max() const { return _max.load(kRelaxed); }
		void reset() { _n = 0; _last = 0; _max = 0; _min = UINT32_MAX; }
		template <class Out> void writeJson(Out& out) const
		{
			out.s("{\"n\":").n(n()).s(",\"last\":").n(last()).s(",\"min\":").n(min()).s(",\"max\":").n(max()).s("}");
		}

	private:
		static constexpr std::memory_order kRelaxed = std::memory_order_relaxed;
		std::atomic<uint32_t> _n{0}, _last{0}, _max{0}, _min{UINT32_MAX};
	};

	// One walk of the TCP control blocks: how many there are and what their send
	// queues hold. `http` marks the ones on the HTTP server's port.
	struct TcpSnapshot
	{
		uint32_t pcbs = 0, httpPcbs = 0;
		uint32_t queuedBytes = 0, httpQueuedBytes = 0;   // written and not yet acknowledged
		uint32_t queuedBufs = 0;                         // pbufs in those queues (snd_queuelen)
	};

	// Bytes in one pcb's send queue: the buffer it was given minus what is still
	// free. Saturating, so a pcb reporting more free than its size holds 0.
	inline uint32_t queuedBytesOf(uint32_t sndBufMax, uint32_t sndBufFree)
	{
		return sndBufFree < sndBufMax ? sndBufMax - sndBufFree : 0u;
	}
	inline void addPcb(TcpSnapshot& t, bool http, uint32_t sndBufMax, uint32_t sndBufFree, uint32_t queueLen)
	{
		const uint32_t q = queuedBytesOf(sndBufMax, sndBufFree);
		++t.pcbs;
		t.queuedBytes += q;
		t.queuedBufs += queueLen;
		if (http) { ++t.httpPcbs; t.httpQueuedBytes += q; }
	}

	// One lwIP memp pool as lwIP counts it (needs LWIP_STATS and MEMP_STATS; see
	// docs/BENCH_PROBE.md). `size` is the element size, 0 if not known: the byte
	// columns are used*size and max*size, saturating. max is that pool's own
	// high-water; the pools' maxima peak at different instants.
	struct MempRow { const char* name; uint32_t used, max, err, size; };
	inline uint32_t saturatingMul(uint32_t a, uint32_t b)
	{
		const uint64_t p = static_cast<uint64_t>(a) * b;
		return p > UINT32_MAX ? UINT32_MAX : static_cast<uint32_t>(p);
	}
	template <class Out> void writeMempRow(Out& out, const MempRow& r)
	{
		out.s("{\"name\":\"").s(r.name).s("\",\"used\":").n(r.used).s(",\"max\":").n(r.max).s(",\"err\":").n(r.err)
		   .s(",\"size\":").n(r.size).s(",\"bytesNow\":").n(saturatingMul(r.used, r.size))
		   .s(",\"bytesMax\":").n(saturatingMul(r.max, r.size)).s("}");
	}

	class Probes
	{
	public:
		Gauge heapFree, heapLargest;   // internal, 8-bit capable
		Gauge connCreate;              // internal bytes the heap lost across one std::thread creation
		Gauge tasks;                   // FreeRTOS task count
		Gauge tcpPcbs, tcpHttpPcbs, tcpQueuedBytes, tcpHttpQueuedBytes, tcpQueuedBufs;

		void sampleHeap(uint32_t freeInternal, uint32_t largestInternal, uint32_t taskCount)
		{
			heapFree.sample(freeInternal);
			heapLargest.sample(largestInternal);
			tasks.sample(taskCount);
		}
		// before/after: free internal bytes either side of creating one connection
		// thread (stack, TCB, pthread state, the std::thread state). 0 if other tasks
		// freed more in that instant than the thread took; allocations other tasks
		// make in it are included, so the lowest value is the best estimate.
		void connCreated(uint32_t freeBefore, uint32_t freeAfter)
		{
			connCreate.sample(freeBefore > freeAfter ? freeBefore - freeAfter : 0u);
		}
		void sampleTcp(const TcpSnapshot& t)
		{
			tcpPcbs.sample(t.pcbs);
			tcpHttpPcbs.sample(t.httpPcbs);
			tcpQueuedBytes.sample(t.queuedBytes);
			tcpHttpQueuedBytes.sample(t.httpQueuedBytes);
			tcpQueuedBufs.sample(t.queuedBufs);
		}
		void reset()
		{
			heapFree.reset(); heapLargest.reset(); connCreate.reset(); tasks.reset();
			tcpPcbs.reset(); tcpHttpPcbs.reset(); tcpQueuedBytes.reset(); tcpHttpQueuedBytes.reset(); tcpQueuedBufs.reset();
		}

		// Members for the inside of the httpDramAccount object, each led by a comma.
		template <class Out> void writeJson(Out& out) const
		{
			out.s(",\"heap\":{\"free\":"); heapFree.writeJson(out);
			out.s(",\"largest\":"); heapLargest.writeJson(out);
			out.s("},\"connCreate\":"); connCreate.writeJson(out);
			out.s(",\"tasks\":"); tasks.writeJson(out);
			out.s(",\"tcp\":{\"pcbs\":"); tcpPcbs.writeJson(out);
			out.s(",\"httpPcbs\":"); tcpHttpPcbs.writeJson(out);
			out.s(",\"queuedBytes\":"); tcpQueuedBytes.writeJson(out);
			out.s(",\"httpQueuedBytes\":"); tcpHttpQueuedBytes.writeJson(out);
			out.s(",\"queuedBufs\":"); tcpQueuedBufs.writeJson(out);
			out.s("}");
		}
	};
	inline Probes gProbes;
}

#endif
