#ifndef BENCH_PROBE_HPP
#define BENCH_PROBE_HPP

// Issue #384 (H1): the bench-only anchor probe image's glue (docs/BENCH_PROBE.md).
// Compiled only into that image; a release build sees an empty header.

#if defined(POCKETDIAL_ANCHOR_BENCH_PROBE) && defined(ESP_PLATFORM)
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "BenchProbeLogic.hpp"

namespace pd::benchprobe {

extern Faults g_faults;

// Fault sites. While disarmed, armedHint() is one relaxed load.
inline bool armedHint(Fault f) { return g_faults.armedHint(f); }
// One-shot; logs "BENCHFAULT <name> fired". Never for an emergency destination
// or while an emergency is live (that disarms every fault instead).
bool fire(Fault f, bool destinationEmergency = false, int32_t* valueOut = nullptr);

// Rule 5. onEmergency() shuts the gate, disarms every fault, drops the GET
// claim, undoes token_age and releases the ballast, at once. Session::
// setEmergency(true) and an emergency makeCall() call it; tick() re-reads the
// sessions' level once a second (RequestsHandler::tick(), under its _mutex).
void onEmergency();
void tick(bool emergencySessionLive);
bool emergencyLive();
void dialBegin();
void dialEnd();

// Held across a makeCall(): a 911/933 shuts the gate before any I/O and keeps
// it shut until the dial returns, even before its session is flagged.
class EmergencyDialScope
{
public:
	explicit EmergencyDialScope(bool emergency) : _on(emergency)
	{
		if (_on) { dialBegin(); onEmergency(); }
	}
	~EmergencyDialScope() { if (_on) dialEnd(); }
	EmergencyDialScope(const EmergencyDialScope&) = delete;
	EmergencyDialScope& operator=(const EmergencyDialScope&) = delete;

private:
	bool _on;
};

// get_status / get_max_attempts: claimed by makeCall() for its own leg,
// taken once by that leg's rx loop.
void claimGetFaults(std::string_view leg, bool destinationEmergency);
GetLoopFaults takeGetFaults(std::string_view leg);

// token_age: the client stores the aged stamp first, then registers it here so
// an emergency can put the real one back (if no fetch replaced it meanwhile).
void noteTokenAged(std::atomic<int64_t>* obtainedUs, int64_t aged, int64_t real);

// POST/GET /api/bench/fault (HttpServer::sendApiBenchFault).
Verdict armFault(std::string_view name, std::string_view value, bool emergencySessionLive);
Verdict armBallast(std::string_view target, std::string_view deadman, bool emergencySessionLive);
void releaseBallast();
size_t renderStatus(char* buf, size_t cap);

} // namespace pd::benchprobe
#endif

#endif // BENCH_PROBE_HPP
