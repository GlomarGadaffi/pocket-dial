#ifndef DTMF_FEATURE_CODES_HPP
#define DTMF_FEATURE_CODES_HPP

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#endif

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>

#include "CdrRing.hpp"
#include "PbxEnv.hpp"
#include "PbxFeatureConfig.hpp"

class SipMessage;

// ── DTMF digit-collection state machine + CLASS feature codes + admin menu ───
// extracted out of RequestsHandler (Task 2C / Task 2C-4 / Task 2C-5).
//
// Every method here assumes the caller holds the engine's _mutex — the same
// "single-threaded SIP handler path" convention the original onDtmfInfo()
// documented — except load(), called once from the constructor before any
// handler is dispatching.
//
// Takes PbxEnv& (log/enqueue/findRegistered/findSession/validAor/localIp —
// all pre-existing virtuals, none added for this move), PbxFeatureConfig&
// for the *60/*80/*73/*72 CLASS codes, and CdrRing& for the *69 last-caller
// lookup.
class DtmfFeatureCodes
{
public:
	DtmfFeatureCodes(PbxEnv& env, PbxFeatureConfig& cfg, CdrRing& cdr) :
		_env(env), _cfg(cfg), _cdr(cdr) {}

	// Parse one SIP INFO's Signal=X body, accumulate digits per Call-ID, and
	// act on completed CLASS/admin sequences. Caller holds _mutex.
	void onInfo(std::shared_ptr<SipMessage> data);

	// Drop this Call-ID's accumulator as its dialog ends (Fix #4 — accumulators
	// share the dialog lifecycle and must not outlive it). Caller holds _mutex.
	void forgetCall(std::string_view callId);

	// Belt-and-suspenders sweep: drop accumulators whose dialog is gone, in
	// case a teardown path bypassed forgetCall(). Bounded by the small session
	// pool. Caller holds _mutex.
	void sweepStale();

	// Test/diagnostic accessor: live accumulators (one per Call-ID that has sent
	// at least one digit and not yet been forgotten). Caller holds _mutex.
	size_t accumulatorCount() const { return _dtmfState.size(); }

	// NVS-persisted admin extension identity (default "1001"). Returned by
	// value, not `const&`: callers are not required to hold _mutex (dashboard/
	// HTTP reads reach this off the SIP thread), and saveAdminExt() below
	// mutates _adminExt from those other call paths with no lock of its own —
	// a reference would dangle/tear if a concurrent save reallocates the
	// string while the caller still holds it. See
	// RequestsHandler::getAdminExt(), the public forwarder that keeps this
	// contract.
	// cppcheck-suppress returnByReference
	std::string adminExt() const;

	// Boot-time reload from NVS. Construction is single-threaded (no handler
	// is dispatching yet), so this runs without holding _mutex, same as
	// before this split.
	void load();

private:
	// Currently uncalled from anywhere in the codebase (the *200 admin code
	// is a stub that never reaches it either) — moved as-is per the plan's
	// mechanical-move rule; deleting dead code is a separate later change.
	void saveAdminExt(const std::string& ext);

	PbxEnv& _env;
	PbxFeatureConfig& _cfg;
	CdrRing& _cdr;

	std::string _adminExt{"1001"};

	// Per-Call-ID accumulator. Accessed only from the single-threaded UDP
	// receiver task (the same path that calls handle()), so no additional
	// mutex is needed.
	struct DtmfAccum
	{
		std::string digits;          // accumulated digit string
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		TickType_t  lastTick{0};     // xTaskGetTickCount() of last digit
#else
		uint32_t    lastTick{0};     // monotonic ms counter on host
#endif
		static constexpr uint32_t TIMEOUT_MS = 5000;
	};
	std::unordered_map<std::string, DtmfAccum> _dtmfState;
};

#endif
