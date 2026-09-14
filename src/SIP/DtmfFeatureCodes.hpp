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

	// Where a digit came from. Both sources converge on onDigit() below, which is
	// the point: the feature-code table, the admin menu and the inter-digit
	// timeout must behave identically whichever way the key press reached us.
	enum class DigitSource : uint8_t { Info = 1, Rfc4733 = 2 };

	// Parse one SIP INFO's Signal=X body and hand the digit to onDigit().
	// Caller holds _mutex.
	void onInfo(std::shared_ptr<SipMessage> data);

	// One key press, from either source. Accumulates per Call-ID and acts on
	// completed CLASS/admin sequences. Caller holds _mutex.
	//
	// `arrivedTick` is when the digit ARRIVED, not when this runs. For an RFC
	// 4733 digit the two differ: the press is captured on the RTP receive task
	// and marshalled onto the SIP thread, where it waits for the next drain. The
	// inter-digit TIMEOUT_MS budget has to be measured against the press, or the
	// drain cadence silently eats part of the user's dialling time.
	//
	// `data` is the INFO request when the digit arrived that way, and nullptr for
	// RFC 4733 — there is no SIP request to answer over RTP. The one response
	// this path can emit (403 to a non-admin caller attempting the admin menu) is
	// therefore skipped for an RTP digit; the accumulator is still cleared, so
	// the refusal has the same effect on state either way.
	void onDigit(std::string_view callId, char digit, DigitSource source,
		uint32_t arrivedTick, const std::shared_ptr<SipMessage>& data);

	// The clock onDigit()'s timeouts are measured on: FreeRTOS ticks on device,
	// a monotonic millisecond counter on host. Public so the RTP-side capture
	// can stamp a press with the SAME clock at the moment it arrives, rather
	// than having it stamped later at drain time.
	static uint32_t nowTickMs();

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

		// Dual-source de-duplication state (Issue #199 item 3).
		//
		// A phone can be configured to send BOTH RFC 4733 and SIP INFO for the
		// same keypress — Grandstream's "SIP INFO + RFC2833" DTMF mode does
		// exactly this, and it is a real setting people leave on. Without a
		// guard, every `*` would accumulate as `**` and no feature code would
		// ever match.
		//
		// The rule is deliberately narrow: drop a digit only when it is the SAME
		// digit, from the OTHER source, within DUP_WINDOW_MS. Same-source repeats
		// are never dropped, so a genuine fast double-press still registers
		// twice — press `1` via INFO, its RTP twin is dropped; press `1` again
		// 150 ms later via INFO, that is the same source and is accepted.
		//
		// Per-call source affinity ("first source wins for this dialog") was the
		// alternative and is worse: a phone that sends `*` via INFO and digits
		// via RTP exists, and affinity would silently eat half its keypad.
		char     lastDigit{0};
		uint8_t  lastSource{0};      // DigitSource, 0 when nothing accepted yet
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
		TickType_t lastAcceptedTick{0};
#else
		uint32_t   lastAcceptedTick{0};
#endif
		static constexpr uint32_t DUP_WINDOW_MS = 250;
	};
	std::unordered_map<std::string, DtmfAccum> _dtmfState;
};

#endif
