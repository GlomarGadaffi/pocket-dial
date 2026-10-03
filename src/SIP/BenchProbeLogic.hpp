#ifndef BENCH_PROBE_LOGIC_HPP
#define BENCH_PROBE_LOGIC_HPP

// Issue #384 (H1): the pure decisions behind the bench-only anchor probe image
// (POCKETDIAL_ANCHOR_BENCH_PROBE, docs/BENCH_PROBE.md): one-shot fault arming,
// the emergency rule, the GET-stream overrides, token aging, the DRAM ballast's
// arithmetic and dead-man, and the counters body. Host-tested in
// tests/BenchProbeLogic_test.cpp. Firmware includes it only through
// BenchProbe.hpp, from inside the probe's own #if blocks, so a release image
// carries none of it.

#include <atomic>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string_view>

namespace pd::benchprobe {

enum class Fault : uint8_t { MakecallReadFail, GetStatus, GetMaxAttempts, PostStreamFail, TokenAge, Count };
inline constexpr size_t kFaultCount = static_cast<size_t>(Fault::Count);
// The names POST /api/bench/fault takes and the counters body reports. There is
// no ws_drop: esp_websocket_client has no documented call that drops the
// transport and keeps its own reconnect (stop() and close() end the client).
inline constexpr std::string_view kFaultNames[kFaultCount] = {
	"makecall_read_fail", "get_status", "get_max_attempts", "post_stream_fail", "token_age"};

inline std::string_view faultName(Fault f)
{
	const auto i = static_cast<size_t>(f);
	return i < kFaultCount ? kFaultNames[i] : std::string_view();
}

inline bool parseFault(std::string_view name, Fault& out)
{
	for (size_t i = 0; i < kFaultCount; ++i)
	{
		if (name == kFaultNames[i])
		{
			out = static_cast<Fault>(i);
			return true;
		}
	}
	return false;
}

// TelephonyAnchorClient::runRxLoop's GET budget. get_max_attempts may only shrink it.
inline constexpr int kGetMaxAttempts = 240;

enum class Verdict : uint8_t { Ok, BadRequest, EmergencyLive, Busy, NoMemory };

// Plain decimal, no sign, no spaces, at most 9 digits (fits a long everywhere).
inline bool parseCount(std::string_view s, long& out)
{
	if (s.empty() || s.size() > 9) return false;
	for (char c : s)
		if (c < '0' || c > '9') return false;
	const auto r = std::from_chars(s.data(), s.data() + s.size(), out);
	return r.ec == std::errc{} && r.ptr == s.data() + s.size();
}

struct FaultRequest
{
	Fault fault = Fault::Count;
	bool hasValue = false;
	long value = 0;
};

// get_status takes a refusal (400-599), get_max_attempts a budget (1-240); the
// others take no value.
inline Verdict parseFaultRequest(std::string_view name, std::string_view value, FaultRequest& out)
{
	FaultRequest r;
	if (!parseFault(name, r.fault)) return Verdict::BadRequest;
	r.hasValue = !value.empty();
	if (r.hasValue && !parseCount(value, r.value)) return Verdict::BadRequest;
	switch (r.fault)
	{
		case Fault::GetStatus:
			if (!r.hasValue || r.value < 400 || r.value > 599) return Verdict::BadRequest;
			break;
		case Fault::GetMaxAttempts:
			if (!r.hasValue || r.value < 1 || r.value > kGetMaxAttempts) return Verdict::BadRequest;
			break;
		default:
			if (r.hasValue) return Verdict::BadRequest;
			break;
	}
	out = r;
	return Verdict::Ok;
}

// The armed faults and their counters. Every member is atomic: fault sites run
// on the anchor's tasks, arming on an HTTP connection thread.
class Faults
{
public:
	Verdict arm(const FaultRequest& r, bool emergencyLive)
	{
		const auto i = static_cast<size_t>(r.fault);
		if (i >= kFaultCount) return Verdict::BadRequest;
		if (emergencyLive)
		{
			_refusedArms.fetch_add(1, std::memory_order_relaxed);
			return Verdict::EmergencyLive;
		}
		_value[i].store(static_cast<int32_t>(r.value), std::memory_order_relaxed);
		_armed[i].store(true, std::memory_order_release);
		return Verdict::Ok;
	}

	// The hot-path pre-check: one relaxed load, nothing else, while disarmed.
	bool armedHint(Fault f) const { return _armed[idx(f)].load(std::memory_order_relaxed); }
	bool armed(Fault f) const { return _armed[idx(f)].load(std::memory_order_acquire); }

	// Rule 5: true exactly once per arm, and never for a 911/933 destination or
	// while any emergency session is live. Reaching a site in either case
	// disarms every fault instead, so nothing armed earlier fires mid-emergency.
	bool fire(Fault f, bool destinationEmergency, bool emergencyLive, int32_t* valueOut = nullptr)
	{
		const size_t i = idx(f);
		if (!_armed[i].load(std::memory_order_acquire)) return false;
		if (destinationEmergency || emergencyLive)
		{
			_emergencySkips[i].fetch_add(1, std::memory_order_relaxed);
			if (disarmAll()) _emergencyDisarms.fetch_add(1, std::memory_order_relaxed);
			return false;
		}
		if (!_armed[i].exchange(false, std::memory_order_acq_rel)) return false;
		_fired[i].fetch_add(1, std::memory_order_relaxed);
		if (valueOut) *valueOut = _value[i].load(std::memory_order_relaxed);
		return true;
	}

	// True if anything was armed.
	bool disarmAll()
	{
		bool any = false;
		for (auto& a : _armed) any = a.exchange(false, std::memory_order_acq_rel) || any;
		return any;
	}
	void noteEmergencyDisarm() { _emergencyDisarms.fetch_add(1, std::memory_order_relaxed); }

	uint32_t fired(Fault f) const { return _fired[idx(f)].load(std::memory_order_relaxed); }
	uint32_t emergencySkips(Fault f) const { return _emergencySkips[idx(f)].load(std::memory_order_relaxed); }
	int32_t value(Fault f) const { return _value[idx(f)].load(std::memory_order_relaxed); }
	uint32_t refusedArms() const { return _refusedArms.load(std::memory_order_relaxed); }
	uint32_t emergencyDisarms() const { return _emergencyDisarms.load(std::memory_order_relaxed); }

private:
	static size_t idx(Fault f)
	{
		const auto i = static_cast<size_t>(f);
		return i < kFaultCount ? i : 0;
	}
	std::atomic<bool> _armed[kFaultCount]{};
	std::atomic<int32_t> _value[kFaultCount]{};
	std::atomic<uint32_t> _fired[kFaultCount]{};
	std::atomic<uint32_t> _emergencySkips[kFaultCount]{};
	std::atomic<uint32_t> _refusedArms{0};
	std::atomic<uint32_t> _emergencyDisarms{0};
};

// The leg the GET faults apply to. makeCall() claims its own outbound leg
// (never a 911/933); the rx loop takes it once, for that leg only, so an
// inbound call (a PSAP callback among them) is never the one forced.
class LegClaim
{
public:
	static constexpr size_t kMaxLeg = 64;

	bool claim(std::string_view leg, bool destinationEmergency)
	{
		std::lock_guard<std::mutex> lock(_m);
		_len = 0;
		if (destinationEmergency || leg.empty() || leg.size() > kMaxLeg) return false;
		std::memcpy(_leg, leg.data(), leg.size());
		_len = leg.size();
		return true;
	}
	bool take(std::string_view leg)
	{
		std::lock_guard<std::mutex> lock(_m);
		if (_len == 0 || std::string_view(_leg, _len) != leg) return false;
		_len = 0;
		return true;
	}
	void clear()
	{
		std::lock_guard<std::mutex> lock(_m);
		_len = 0;
	}

private:
	std::mutex _m;
	char _leg[kMaxLeg] = {};
	size_t _len = 0;
};

// The rx loop's view of get_status / get_max_attempts for one stream.
struct GetLoopFaults
{
	int forcedStatus = 0;   // 0 = real statuses
	int maxAttempts = kGetMaxAttempts;
};

// A forced refusal replaces a real HTTP answer only; no answer parsed is a
// transport failure (#350) and stays real. A real 200's body is the live audio
// stream, which never ends, so it is closed unread instead of drained.
struct GetStatusOverride
{
	int status;
	bool closeUnread;
};
inline GetStatusOverride overrideGetStatus(int realStatus, int forcedStatus)
{
	if (forcedStatus == 0 || realStatus <= 0) return {realStatus, false};
	return {forcedStatus, realStatus == 200};
}

// token_age: a held token is aged by moving its obtained-at stamp back one full
// lifetime, so telephony::tokenIsExpiringSoon() reads it as expiring (#336).
inline bool tokenAgeApplies(int64_t obtainedUs, int64_t lifetimeUs)
{
	return obtainedUs != 0 && lifetimeUs > 0;
}
inline int64_t agedTokenObtainedUs(int64_t nowUs, int64_t lifetimeUs)
{
	const int64_t aged = nowUs - lifetimeUs;
	return aged == 0 ? -1 : aged;   // 0 means "no token" to tokenIsExpiringSoon()
}

// Is an emergency (911/933, or a PSAP callback) live? The level comes from the
// sessions once a second; a session flagged emergency, or a 911/933 makeCall
// in flight, shuts the gate at once and the level cannot reopen it under a
// dial that is still running.
class EmergencyGate
{
public:
	void dialBegin()
	{
		_dials.fetch_add(1, std::memory_order_acq_rel);
		_live.store(true, std::memory_order_release);
	}
	void dialEnd() { _dials.fetch_sub(1, std::memory_order_acq_rel); }
	void sessionsLive(bool any)
	{
		_live.store(any || _dials.load(std::memory_order_acquire) > 0, std::memory_order_release);
	}
	void sessionAppeared() { _live.store(true, std::memory_order_release); }
	bool live() const { return _live.load(std::memory_order_acquire); }

private:
	std::atomic<int> _dials{0};
	std::atomic<bool> _live{false};
};

// ── DRAM ballast ──────────────────────────────────────────────────────────────
inline constexpr size_t kBallastBlockMax = 4096;
inline constexpr size_t kBallastBlockMin = 64;
inline constexpr size_t kBallastMaxBlocks = 256;          // 1 MB at 4 KB: more than all internal DRAM
inline constexpr size_t kBallastMinTarget = 8 * 1024;      // never squeeze below this much free
inline constexpr uint32_t kDeadmanDefaultS = 120;
inline constexpr uint32_t kDeadmanMaxS = 600;

struct BallastRequest
{
	size_t target = 0;       // free internal heap to leave, bytes
	uint32_t deadmanS = 0;   // released by itself after this long
};

inline Verdict parseBallastRequest(std::string_view target, std::string_view deadman, BallastRequest& out)
{
	long t = 0;
	long d = kDeadmanDefaultS;
	if (!parseCount(target, t) || static_cast<size_t>(t) < kBallastMinTarget) return Verdict::BadRequest;
	if (!deadman.empty() && (!parseCount(deadman, d) || d < 1 || d > static_cast<long>(kDeadmanMaxS)))
		return Verdict::BadRequest;
	out.target = static_cast<size_t>(t);
	out.deadmanS = static_cast<uint32_t>(d);
	return Verdict::Ok;
}

inline Verdict ballastArmCheck(bool emergencyLive, bool held)
{
	if (emergencyLive) return Verdict::EmergencyLive;
	if (held) return Verdict::Busy;
	return Verdict::Ok;
}

// The next block to take: the gap to the target, at most `cap`; 0 = stop
// (at the target, or within one minimum block of it).
inline size_t ballastNextBlock(size_t freeNow, size_t target, size_t cap)
{
	if (freeNow <= target) return 0;
	const size_t gap = freeNow - target;
	if (gap < kBallastBlockMin) return 0;
	return gap < cap ? gap : cap;
}

// After a refused allocation (fragmentation), try half; 0 = give up.
inline size_t ballastShrink(size_t cap)
{
	const size_t half = cap / 2;
	return half < kBallastBlockMin ? 0 : half;
}

// Take blocks into `slots` until freeNow() <= target. stop() is asked before
// every allocation and ends the fill at once (an emergency appeared).
template <class FreeNow, class Alloc, class Stop>
size_t fillBallast(void** slots, size_t maxSlots, size_t target, FreeNow freeNow, Alloc alloc, Stop stop,
                   size_t* bytesOut)
{
	size_t n = 0;
	size_t bytes = 0;
	size_t cap = kBallastBlockMax;
	while (n < maxSlots && cap != 0 && !stop())
	{
		const size_t want = ballastNextBlock(freeNow(), target, cap);
		if (want == 0) break;
		void* p = alloc(want);
		if (p == nullptr)
		{
			cap = ballastShrink(cap);
			continue;
		}
		slots[n++] = p;
		bytes += want;
	}
	*bytesOut = bytes;
	return n;
}

inline int64_t deadmanDeadlineUs(int64_t armedAtUs, uint32_t deadmanS)
{
	return armedAtUs + static_cast<int64_t>(deadmanS) * 1000000;
}
inline bool deadmanExpired(int64_t nowUs, int64_t deadlineUs) { return nowUs >= deadlineUs; }

struct BallastStatus
{
	bool held = false;
	size_t bytes = 0;
	size_t blocks = 0;
	size_t target = 0;
	uint32_t deadmanS = 0;
	uint32_t releasedApi = 0;
	uint32_t releasedDeadman = 0;
	uint32_t releasedEmergency = 0;
	uint32_t refusedEmergency = 0;
};

// ── The counters body (GET/POST /api/bench/fault) ─────────────────────────────
namespace detail {
struct Out
{
	char* buf = nullptr;
	size_t cap = 0;
	size_t len = 0;
	bool full = false;
	Out& s(std::string_view v)
	{
		if (full || v.size() > cap - len) { full = true; return *this; }
		std::memcpy(buf + len, v.data(), v.size());
		len += v.size();
		return *this;
	}
	Out& b(bool v) { return s(v ? "true" : "false"); }
	template <class T> Out& n(T v)
	{
		char t[24];
		const auto r = std::to_chars(t, t + sizeof(t), v);
		if (r.ec != std::errc{}) { full = true; return *this; }
		return s(std::string_view(t, static_cast<size_t>(r.ptr - t)));
	}
};
} // namespace detail

// Writes the whole body or nothing: 0 when it does not fit.
inline size_t renderStatus(char* buf, size_t cap, const Faults& f, const BallastStatus& b, bool emergencyLive,
                           size_t freeInternal)
{
	detail::Out o{buf, cap};
	o.s("{\"image\":\"anchor-bench-probe\",\"emergencyLive\":").b(emergencyLive)
	 .s(",\"refusedArms\":").n(f.refusedArms())
	 .s(",\"emergencyDisarms\":").n(f.emergencyDisarms())
	 .s(",\"faults\":{");
	for (size_t i = 0; i < kFaultCount; ++i)
	{
		const auto fault = static_cast<Fault>(i);
		o.s(i ? ",\"" : "\"").s(kFaultNames[i])
		 .s("\":{\"armed\":").b(f.armed(fault))
		 .s(",\"value\":").n(f.value(fault))
		 .s(",\"fired\":").n(f.fired(fault))
		 .s(",\"emergencySkips\":").n(f.emergencySkips(fault)).s("}");
	}
	o.s("},\"ballast\":{\"held\":").b(b.held)
	 .s(",\"bytes\":").n(b.bytes)
	 .s(",\"blocks\":").n(b.blocks)
	 .s(",\"target\":").n(b.target)
	 .s(",\"deadmanS\":").n(b.deadmanS)
	 .s(",\"released\":{\"api\":").n(b.releasedApi)
	 .s(",\"deadman\":").n(b.releasedDeadman)
	 .s(",\"emergency\":").n(b.releasedEmergency)
	 .s("},\"refusedEmergency\":").n(b.refusedEmergency)
	 .s("},\"freeInternal\":").n(freeInternal).s("}");
	return o.full ? 0 : o.len;
}

} // namespace pd::benchprobe

#endif // BENCH_PROBE_LOGIC_HPP
