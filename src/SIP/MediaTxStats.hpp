#ifndef POCKETDIAL_MEDIA_TX_STATS_HPP
#define POCKETDIAL_MEDIA_TX_STATS_HPP

// Issue #985 slice 0 (instrument only): where does outbound media wait?
//
// A caller on the anchor hears small dropouts. The audio goes out as one blocking TLS
// chunked write per 20 ms frame (TelephonyAnchorClient::writeAudio), and HoldMusic's
// 20 ms loop turns a write that runs past its tick into "a brief gap" without a log
// line. Nothing measured that, nor the L2 path that carries audio to LAN phones. This
// header is the whole instrument: counters and histograms in static storage (BSS),
// written by the media tasks, read by /api/status (the `mediaTx` block) and drained
// into witness lines by RequestsHandler::tick(). It changes no behaviour.
//
// Discipline for the writers (priority 5/6 media tasks, two cores, no common lock):
//  - A recording call is a few relaxed atomic read-modify-writes into fixed storage.
//    No allocation, no lock, no printf, no log. The callers read the clock themselves
//    (two stamps around the thing they time) and pass durations in, so this file never
//    decides when to look at a clock and the tests never sleep.
//  - Every atomic is 32 bits: 64-bit atomics are not lock-free on Xtensa. A stamp is the
//    low 32 bits of the microsecond clock; an interval is the unsigned difference of two
//    of them, right for any interval under 71 minutes.
//  - A slow event only leaves DATA behind (a record in a fixed per-slot table, capped);
//    the line is written later from a non-media task (takeWitness(), drained by
//    RequestsHandler::tick() after its lock scope). Logging from a media task would put
//    the console inside the 20 ms loop being measured.
//
// Definitions (docs/API.md, `mediaTx`):
//  - write: one MediaBridge -> AnchorClient::writeAudio() call, from either caller (the
//    handset's RTP task, or HoldMusic's tap), measured around the whole call, so it
//    includes the anchor's slot lock wait and the blocking send. `over` is strictly
//    longer than 20 ms. Calls that return early (stream not live) count too.
//  - tick miss: HoldMusic's xTaskDelayUntil returned pdFALSE, i.e. the previous
//    iteration (its taps' writes included) ran past the 20 ms tick; the overrun is how
//    far past. A tick that woke late after a real delay is not counted.
//  - feed gap: per bridge, the time between the END of one handset frame's hand-off to
//    the anchor and the ARRIVAL of the next, for consecutive frames that both reached
//    the write (anchor mode, not held). Late is strictly more than 40 ms. It excludes
//    our own write time, so it is the idle time of the feed: upstream (phone, LAN)
//    jitter, silence suppression, or the rx task not being scheduled.
//  - L2: frame build (pool acquire, template copy, patchTick) and the esp_eth_transmit
//    hand-off, each a histogram; the four ways EgressChannel::transmit() returns false,
//    one counter each; a failed fallback sendto() in RtpSender.

#include <atomic>
#include <chrono>
#include <cstdint>

#include "Log2Us.hpp"
#include "PoolConfig.hpp"

#if defined(ESP_PLATFORM)
#include "esp_timer.h"
#endif

namespace pd
{
	class MediaTx
	{
	public:
		static constexpr uint32_t kOverUs         = 20000;   // a write is over when strictly longer
		static constexpr uint32_t kLateGapUs      = 40000;   // a feed gap is late when strictly longer
		static constexpr unsigned kLegs           = POCKETDIAL_MAX_ANCHOR_CALLS;
		static constexpr uint8_t  kNoLeg          = 0xff;
		static constexpr unsigned kWitnessPerSlot = 3;       // first N slow events per slot per boot
		static constexpr unsigned kWitnessTotal   = 12;      // and this many in all
		static constexpr bool     kNodelayDefault = false;   // the Nagle A/B switch is off at every boot

		enum class Path : uint8_t { AnchorWrite = 1, HoldWrite = 2, HoldTick = 3, FeedGap = 4 };
		enum class L2Fail : uint8_t { PoolEmpty = 0, ZeroLength = 1, NoHandle = 2, Driver = 3 };

		struct Summary
		{
			uint32_t count = 0;
			uint32_t maxUs = 0;
			uint32_t p50Us = 0;
			uint32_t p99Us = 0;
			uint32_t p999Us = 0;
		};

		// One slow event, as takeWitness() hands it out. `total` is the cumulative count
		// of that path's slow events at the time of the call.
		struct Witness
		{
			Path     path    = Path::AnchorWrite;
			uint8_t  leg     = kNoLeg;
			uint32_t us      = 0;
			uint32_t stampMs = 0;
			uint32_t total   = 0;
		};

		// ── clock ───────────────────────────────────────────────────────────────
		static uint32_t nowUs() { return static_cast<uint32_t>(clockUs()); }
		static uint32_t nowMs() { return static_cast<uint32_t>(clockUs() / 1000); }

		// ── recording: media tasks. Relaxed atomics into static storage, nothing else ──
		static void recordWrite(bool viaHold, uint8_t leg, uint32_t us)
		{
			s_.write.add(us);
			if (us > kOverUs)
			{
				bump(s_.writeOver);
				if (leg < kLegs) bump(s_.legOver[leg]);
				noteSlow(viaHold ? Path::HoldWrite : Path::AnchorWrite, leg, us);
			}
		}

		static void recordTickMiss(uint32_t overrunUs)
		{
			bump(s_.tickMiss);
			raiseTo(s_.tickMaxOverrunUs, overrunUs);
			noteSlow(Path::HoldTick, kNoLeg, overrunUs);
		}

		// prevEndUs is the stamp taken when this bridge's previous frame left the
		// hand-off (0 = none: first frame of the call, or the first after a hold).
		static void recordFeedFrame(uint8_t leg, uint32_t prevEndUs, uint32_t entryUs)
		{
			if (prevEndUs == 0) return;
			const uint32_t gap = entryUs - prevEndUs;
			bump(s_.feedFrames);
			raiseTo(s_.feedMaxGapUs, gap);
			if (gap > kLateGapUs)
			{
				bump(s_.feedLate);
				noteSlow(Path::FeedGap, leg, gap);
			}
		}

		static void recordL2Build(uint32_t us) { s_.l2Build.add(us); }
		static void recordL2Tx(uint32_t us) { s_.l2Tx.add(us); }
		static void recordL2Fail(L2Fail why) { bump(s_.l2Fail[static_cast<unsigned>(why)]); }
		static void recordFallbackSendFail() { bump(s_.fallbackSendFail); }

		// ── reading: /api/status and tick(). No locks ──────────────────────────────
		static Summary writeSummary() { return summarize(s_.write); }
		static Summary l2BuildSummary() { return summarize(s_.l2Build); }
		static Summary l2TxSummary() { return summarize(s_.l2Tx); }
		static uint32_t writeOver() { return s_.writeOver.load(kRelaxed); }
		static uint32_t legOver(unsigned leg) { return leg < kLegs ? s_.legOver[leg].load(kRelaxed) : 0u; }
		static uint32_t tickMisses() { return s_.tickMiss.load(kRelaxed); }
		static uint32_t tickMaxOverrunUs() { return s_.tickMaxOverrunUs.load(kRelaxed); }
		static uint32_t feedFrames() { return s_.feedFrames.load(kRelaxed); }
		static uint32_t feedLate() { return s_.feedLate.load(kRelaxed); }
		static uint32_t feedMaxGapUs() { return s_.feedMaxGapUs.load(kRelaxed); }
		static uint32_t l2Fails(L2Fail why) { return s_.l2Fail[static_cast<unsigned>(why)].load(kRelaxed); }
		static uint32_t fallbackSendFails() { return s_.fallbackSendFail.load(kRelaxed); }

		// The next slow event not yet reported, marked reported; false when none is left.
		// One consumer: RequestsHandler::tick(), outside its lock scope.
		static bool takeWitness(Witness& out)
		{
			for (WSlot& w : s_.slots)
			{
				const uint32_t r = w.reported.load(kRelaxed);
				if (r >= kWitnessPerSlot) continue;
				WRec& rec = w.rec[r];
				const uint8_t p = rec.path.load(std::memory_order_acquire);
				if (p == 0) continue;
				out.path    = static_cast<Path>(p);
				out.leg     = rec.leg.load(kRelaxed);
				out.us      = rec.us.load(kRelaxed);
				out.stampMs = rec.stampMs.load(kRelaxed);
				out.total   = totalFor(out.path);
				w.reported.store(r + 1, kRelaxed);
				return true;
			}
			return false;
		}

		// ── the Nagle A/B lever (#985): TCP_NODELAY on the anchor's audio POST socket ──
		// Off at every boot; never persisted. TelephonyAnchorClient reads it right after
		// each successful open of the audio POST stream.
		static bool nodelay() { return s_nodelay.load(kRelaxed); }
		static void setNodelay(bool on) { s_nodelay.store(on, kRelaxed); }

		static void resetForTest()
		{
			s_.write.clear();
			s_.l2Build.clear();
			s_.l2Tx.clear();
			s_.writeOver.store(0, kRelaxed);
			for (auto& a : s_.legOver) a.store(0, kRelaxed);
			s_.tickMiss.store(0, kRelaxed);
			s_.tickMaxOverrunUs.store(0, kRelaxed);
			s_.feedFrames.store(0, kRelaxed);
			s_.feedLate.store(0, kRelaxed);
			s_.feedMaxGapUs.store(0, kRelaxed);
			for (auto& a : s_.l2Fail) a.store(0, kRelaxed);
			s_.fallbackSendFail.store(0, kRelaxed);
			s_.witnessTotal.store(0, kRelaxed);
			for (WSlot& w : s_.slots)
			{
				w.claimed.store(0, kRelaxed);
				w.reported.store(0, kRelaxed);
				for (WRec& r : w.rec) r.path.store(0, kRelaxed);
			}
			s_nodelay.store(kNodelayDefault, kRelaxed);
		}

#if !defined(ESP_PLATFORM)
		// Host tests drive the clock; the device build has no such hook.
		static void setClockForTest(int64_t (*fn)()) { s_testClock = fn; }
#endif

	private:
		static constexpr std::memory_order kRelaxed = std::memory_order_relaxed;

		struct Hist
		{
			std::atomic<uint32_t> b[log2us::kBuckets];
			std::atomic<uint32_t> maxUs;

			void add(uint32_t us)
			{
				bump(b[log2us::bucketOf(us)]);
				raiseTo(maxUs, us);
			}
			void clear()
			{
				for (auto& a : b) a.store(0, kRelaxed);
				maxUs.store(0, kRelaxed);
			}
		};

		struct WRec
		{
			std::atomic<uint32_t> us;
			std::atomic<uint32_t> stampMs;
			std::atomic<uint8_t>  path;   // last, release: 0 = not published yet
			std::atomic<uint8_t>  leg;
		};
		struct WSlot
		{
			std::atomic<uint32_t> claimed;    // records claimed by writers
			std::atomic<uint32_t> reported;   // records drained (the one consumer)
			WRec                  rec[kWitnessPerSlot];
		};

		struct Stats
		{
			Hist                  write;
			std::atomic<uint32_t> writeOver;
			std::atomic<uint32_t> legOver[kLegs];
			std::atomic<uint32_t> tickMiss;
			std::atomic<uint32_t> tickMaxOverrunUs;
			std::atomic<uint32_t> feedFrames;
			std::atomic<uint32_t> feedLate;
			std::atomic<uint32_t> feedMaxGapUs;
			Hist                  l2Build;
			Hist                  l2Tx;
			std::atomic<uint32_t> l2Fail[4];
			std::atomic<uint32_t> fallbackSendFail;
			std::atomic<uint32_t> witnessTotal;
			WSlot                 slots[kLegs + 1];   // one per bridge, and the last for the hold task
		};

		static void bump(std::atomic<uint32_t>& a) { a.fetch_add(1, kRelaxed); }

		static void raiseTo(std::atomic<uint32_t>& a, uint32_t v)
		{
			uint32_t cur = a.load(kRelaxed);
			while (v > cur && !a.compare_exchange_weak(cur, v, kRelaxed)) {}
		}

		static uint32_t totalFor(Path p)
		{
			switch (p)
			{
				case Path::AnchorWrite:
				case Path::HoldWrite: return s_.writeOver.load(kRelaxed);
				case Path::HoldTick:  return s_.tickMiss.load(kRelaxed);
				case Path::FeedGap:   return s_.feedLate.load(kRelaxed);
			}
			return 0;
		}

		// A slow event leaves one record, if its slot and the table still have room.
		static void noteSlow(Path p, uint8_t leg, uint32_t us)
		{
			WSlot& w = s_.slots[leg < kLegs ? leg : kLegs];
			if (w.claimed.load(kRelaxed) >= kWitnessPerSlot) return;
			if (s_.witnessTotal.load(kRelaxed) >= kWitnessTotal) return;
			s_.witnessTotal.fetch_add(1, kRelaxed);
			const uint32_t n = w.claimed.fetch_add(1, kRelaxed);
			if (n >= kWitnessPerSlot) return;
			WRec& r = w.rec[n];
			r.us.store(us, kRelaxed);
			r.stampMs.store(nowMs(), kRelaxed);
			r.leg.store(leg, kRelaxed);
			r.path.store(static_cast<uint8_t>(p), std::memory_order_release);
		}

		static Summary summarize(const Hist& h)
		{
			Summary s;
			s.maxUs = h.maxUs.load(kRelaxed);
			for (const auto& a : h.b) s.count += a.load(kRelaxed);
			const auto load = [&h](unsigned b) { return h.b[b].load(kRelaxed); };
			s.p50Us  = log2us::quantileUs(load, s.count, 1, 2, s.maxUs);
			s.p99Us  = log2us::quantileUs(load, s.count, 99, 100, s.maxUs);
			s.p999Us = log2us::quantileUs(load, s.count, 999, 1000, s.maxUs);
			return s;
		}

		static int64_t clockUs()
		{
#if defined(ESP_PLATFORM)
			return esp_timer_get_time();
#else
			if (s_testClock != nullptr) return s_testClock();
			return std::chrono::duration_cast<std::chrono::microseconds>(
				std::chrono::steady_clock::now().time_since_epoch()).count();
#endif
		}

		static inline Stats s_{};
		static inline std::atomic<bool> s_nodelay{kNodelayDefault};
#if !defined(ESP_PLATFORM)
		static inline int64_t (*s_testClock)() = nullptr;
#endif
	};
}

#endif // POCKETDIAL_MEDIA_TX_STATS_HPP
