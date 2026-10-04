// Issue #384 (H1): the bench-only anchor probe image's glue (docs/BENCH_PROBE.md).
// The decisions are in the pure header (host-tested); this file holds the one
// probe state, the log lines, the DRAM ballast (heap_caps) and its dead-man
// (esp_timer). Compiles to nothing outside the probe image.

#if defined(POCKETDIAL_ANCHOR_BENCH_PROBE) && defined(ESP_PLATFORM)
#include "BenchProbe.hpp"

#include <mutex>

#include "esp_heap_caps.h"
#include "esp_log.h"
#include "esp_timer.h"

namespace pd::benchprobe {

Faults g_faults;

namespace {
const char* TAG = "BenchProbe";

EmergencyGate s_gate;
LegClaim s_claim;

std::mutex s_tokenMutex;   // guards the three below
std::atomic<int64_t>* s_tokenAt = nullptr;
int64_t s_tokenAged = 0;
int64_t s_tokenReal = 0;

// The ballast. Bookkeeping is static (#284): no heap but the ballast itself.
std::mutex s_ballastMutex;  // guards everything down to s_deadman; a leaf lock
void* s_blocks[kBallastMaxBlocks];
size_t s_blockCount = 0;
size_t s_ballastBytes = 0;
size_t s_ballastTarget = 0;
uint32_t s_deadmanS = 0;
int64_t s_deadlineUs = 0;
bool s_held = false;
esp_timer_handle_t s_deadman = nullptr;
std::atomic<uint32_t> s_releasedApi{0};
std::atomic<uint32_t> s_releasedDeadman{0};
std::atomic<uint32_t> s_releasedEmergency{0};
std::atomic<uint32_t> s_refusedEmergency{0};

enum class Why : uint8_t { Api, Deadman, Emergency };

void freeBlocksLocked()
{
	for (size_t i = 0; i < s_blockCount; ++i) heap_caps_free(s_blocks[i]);
	s_blockCount = 0;
	s_ballastBytes = 0;
}

void releaseLocked(Why why)
{
	if (!s_held) return;
	const size_t bytes = s_ballastBytes;
	freeBlocksLocked();
	s_held = false;
	(void)esp_timer_stop(s_deadman);   // ESP_ERR_INVALID_STATE when it already fired
	const char* name = why == Why::Api ? "api" : why == Why::Deadman ? "deadman" : "emergency";
	(why == Why::Api ? s_releasedApi : why == Why::Deadman ? s_releasedDeadman : s_releasedEmergency)
		.fetch_add(1, std::memory_order_relaxed);
	ESP_LOGW(TAG, "BENCHFAULT ballast released (%s): %u bytes", name, static_cast<unsigned>(bytes));
}

void release(Why why)
{
	std::lock_guard<std::mutex> lock(s_ballastMutex);
	releaseLocked(why);
}

void deadmanFired(void*) { release(Why::Deadman); }

void undoTokenAge()
{
	std::lock_guard<std::mutex> lock(s_tokenMutex);
	if (s_tokenAt == nullptr) return;
	int64_t aged = s_tokenAged;
	// Only while the aged stamp is still there: a fetch since then is a real token.
	if (s_tokenAt->compare_exchange_strong(aged, s_tokenReal))
		ESP_LOGW(TAG, "BENCHFAULT token_age undone: emergency call");
	s_tokenAt = nullptr;
}
} // namespace

bool fire(Fault f, bool destinationEmergency, int32_t* valueOut)
{
	if (!g_faults.fire(f, destinationEmergency, s_gate.live(), valueOut)) return false;
	const std::string_view n = faultName(f);
	ESP_LOGW(TAG, "BENCHFAULT %.*s fired", static_cast<int>(n.size()), n.data());
	return true;
}

void onEmergency()
{
	s_gate.sessionAppeared();
	if (g_faults.disarmAll())
	{
		g_faults.noteEmergencyDisarm();
		ESP_LOGW(TAG, "BENCHFAULT every fault disarmed: emergency call");
	}
	s_claim.clear();
	undoTokenAge();
	release(Why::Emergency);
}

void tick(bool emergencySessionLive)
{
	s_gate.sessionsLive(emergencySessionLive);
	if (s_gate.live())
	{
		onEmergency();
		return;
	}
	// Backstop to the esp_timer dead-man. Never blocks the SIP task on an arm.
	std::unique_lock<std::mutex> lock(s_ballastMutex, std::try_to_lock);
	if (lock.owns_lock() && s_held && deadmanExpired(esp_timer_get_time(), s_deadlineUs))
		releaseLocked(Why::Deadman);
}

bool emergencyLive() { return s_gate.live(); }
void dialBegin() { s_gate.dialBegin(); }
void dialEnd() { s_gate.dialEnd(); }

void claimGetFaults(std::string_view leg, bool destinationEmergency)
{
	if (!g_faults.armedHint(Fault::GetStatus) && !g_faults.armedHint(Fault::GetMaxAttempts)) return;
	s_claim.claim(leg, destinationEmergency || s_gate.live());
}

GetLoopFaults takeGetFaults(std::string_view leg)
{
	GetLoopFaults g;
	if (!s_claim.take(leg)) return g;
	int32_t v = 0;
	if (fire(Fault::GetStatus, false, &v)) g.forcedStatus = v;
	if (fire(Fault::GetMaxAttempts, false, &v)) g.maxAttempts = v;
	return g;
}

void noteTokenAged(std::atomic<int64_t>* obtainedUs, int64_t aged, int64_t real)
{
	{
		std::lock_guard<std::mutex> lock(s_tokenMutex);
		s_tokenAt = obtainedUs;
		s_tokenAged = aged;
		s_tokenReal = real;
	}
	if (s_gate.live()) undoTokenAge();   // an emergency that began after fire()
}

Verdict armFault(std::string_view name, std::string_view value, bool emergencySessionLive)
{
	if (emergencySessionLive) onEmergency();
	if (name == "disarm")
	{
		g_faults.disarmAll();
		s_claim.clear();
		ESP_LOGW(TAG, "BENCHFAULT every fault disarmed: api");
		return Verdict::Ok;
	}
	FaultRequest r;
	if (parseFaultRequest(name, value, r) != Verdict::Ok) return Verdict::BadRequest;
	const Verdict v = g_faults.arm(r, s_gate.live());
	if (v == Verdict::Ok)
		ESP_LOGW(TAG, "BENCHFAULT %.*s armed (value %ld)", static_cast<int>(name.size()), name.data(), r.value);
	return v;
}

Verdict armBallast(std::string_view target, std::string_view deadman, bool emergencySessionLive)
{
	BallastRequest r;
	if (parseBallastRequest(target, deadman, r) != Verdict::Ok) return Verdict::BadRequest;
	if (emergencySessionLive) onEmergency();
	std::lock_guard<std::mutex> lock(s_ballastMutex);
	const Verdict v = ballastArmCheck(s_gate.live(), s_held);
	if (v == Verdict::EmergencyLive) s_refusedEmergency.fetch_add(1, std::memory_order_relaxed);
	if (v != Verdict::Ok) return v;
	if (s_deadman == nullptr)
	{
		esp_timer_create_args_t args = {};
		args.callback = &deadmanFired;
		args.name = "bench_deadman";
		if (esp_timer_create(&args, &s_deadman) != ESP_OK) return Verdict::NoMemory;
	}
	size_t bytes = 0;
	s_blockCount = fillBallast(s_blocks, kBallastMaxBlocks, r.target,
		[] { return heap_caps_get_free_size(MALLOC_CAP_INTERNAL); },
		[](size_t want) { return heap_caps_malloc(want, MALLOC_CAP_INTERNAL | MALLOC_CAP_DMA); },
		[] { return s_gate.live(); }, &bytes);
	s_ballastBytes = bytes;
	if (s_gate.live())
	{
		// An emergency appeared mid-fill: give it all back before anything else.
		freeBlocksLocked();
		s_refusedEmergency.fetch_add(1, std::memory_order_relaxed);
		return Verdict::EmergencyLive;
	}
	if (s_blockCount == 0) return Verdict::Ok;   // already at or under the target
	if (esp_timer_start_once(s_deadman, static_cast<uint64_t>(r.deadmanS) * 1000000ULL) != ESP_OK)
	{
		freeBlocksLocked();   // no dead-man, no ballast
		return Verdict::NoMemory;
	}
	s_held = true;
	s_ballastTarget = r.target;
	s_deadmanS = r.deadmanS;
	s_deadlineUs = deadmanDeadlineUs(esp_timer_get_time(), r.deadmanS);
	ESP_LOGW(TAG, "BENCHFAULT ballast held: %u bytes in %u blocks, free internal %u, dead-man %u s",
		static_cast<unsigned>(s_ballastBytes), static_cast<unsigned>(s_blockCount),
		static_cast<unsigned>(heap_caps_get_free_size(MALLOC_CAP_INTERNAL)), static_cast<unsigned>(r.deadmanS));
	return Verdict::Ok;
}

void releaseBallast() { release(Why::Api); }

size_t renderStatus(char* buf, size_t cap)
{
	BallastStatus b;
	{
		std::lock_guard<std::mutex> lock(s_ballastMutex);
		b.held = s_held;
		b.bytes = s_ballastBytes;
		b.blocks = s_blockCount;
		b.target = s_ballastTarget;
		b.deadmanS = s_deadmanS;
	}
	b.releasedApi = s_releasedApi.load(std::memory_order_relaxed);
	b.releasedDeadman = s_releasedDeadman.load(std::memory_order_relaxed);
	b.releasedEmergency = s_releasedEmergency.load(std::memory_order_relaxed);
	b.refusedEmergency = s_refusedEmergency.load(std::memory_order_relaxed);
	return renderStatus(buf, cap, g_faults, b, s_gate.live(), heap_caps_get_free_size(MALLOC_CAP_INTERNAL));
}

} // namespace pd::benchprobe
#endif
