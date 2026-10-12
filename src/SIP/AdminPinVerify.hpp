#pragma once

// AdminPinVerify -- the process-wide DTMF admin PIN check (#986 slice 3). The
// policy is AdminPinVerifyLogic.hpp; this is the instance, and (board only) the
// worker task. First and only caller: DtmfFeatureCodes, under RequestsHandler::_mutex.

#include <cstdint>

#include "AdminPinVerifyLogic.hpp"
#include "FunctionRef.hpp"

namespace adminpin
{
	// Boot-time and idempotent (DtmfFeatureCodes::load(), before any handler dispatches).
	// Board: creates the worker. Host: nothing.
	void start();

	// Copies the entry into the slot and wakes the worker; never hashes, never blocks.
	SubmitResult submit(std::string_view pin, std::string_view callId, std::string_view callerExt,
		std::string_view code, char confirm);

	// Called from tick(). A finished check gets its attempt/lockout accounting, then
	// `run(job, authenticated)`; false when nothing was waiting.
	bool applyIfReady(FunctionRef<void(const Job&, bool)> run);

#if !(defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO))
	// Host test seams: the worker task does not exist here, so a test plays it.
	using Hasher = bool (*)(const Job&);
	void setHasherForTest(Hasher h);   // nullptr: the real one (AdminAuth::matchesDtmfPin)
	bool workForTest();                // one worker pass; blocks inside the hasher, like the task
	Phase phaseForTest();
	unsigned wakesForTest();           // how many times submit() woke the worker
	void resetForTest();               // Idle, slot wiped, real hasher
#endif
}
