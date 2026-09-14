#include "ConferenceRoom.hpp"

#include <chrono>

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#endif

ConferenceRoom::ConferenceRoom()
{
	// Every leg's bridge is wired to the SHARED bus and to no anchor: a local
	// conference needs no vendor/anchor at all (see ISSUES.md #75's "handset legs
	// alone are enough ports"). Wiring happens once here, not per join(), so a leg
	// slot can be reused without re-init.
	for (auto& leg : _legs)
	{
		leg.bridge.init(&leg.rx, &leg.tx, /*anchor=*/nullptr, &_bus);
	}
}

ConferenceRoom::~ConferenceRoom()
{
	stopDriver();
	std::lock_guard<std::mutex> lock(_mutex);
	for (auto& leg : _legs)
	{
		if (leg.inUse)
		{
			leg.bridge.stopBridge();
			leg.inUse = false;
		}
	}
}

int ConferenceRoom::indexOfLocked(const std::string& callID) const
{
	if (callID.empty()) return -1;
	for (int i = 0; i < MAX_LEGS; ++i)
	{
		if (_legs[static_cast<size_t>(i)].inUse && _legs[static_cast<size_t>(i)].callID == callID)
		{
			return i;
		}
	}
	return -1;
}

void ConferenceRoom::setDigitSink(MediaBridge::DigitSink sink)
{
	std::lock_guard<std::mutex> lock(_mutex);
	_digitSink = std::move(sink);
	for (auto& leg : _legs)
	{
		leg.bridge.setDigitSink(_digitSink);
	}
}

int ConferenceRoom::join(const std::string& callID, const std::string& ext,
	const std::string& handsetIp, uint16_t handsetPort, int dtmfPt)
{
	std::lock_guard<std::mutex> lock(_mutex);

	if (callID.empty() || handsetIp.empty() || handsetPort == 0)
	{
		return -1;
	}

	// Re-INVITE / retransmit safety: one Call-ID owns at most one leg. Answering the
	// same dialog twice would burn a second bus port that nothing can ever release.
	if (indexOfLocked(callID) >= 0)
	{
		return -1;
	}

	for (int i = 0; i < MAX_LEGS; ++i)
	{
		Leg& leg = _legs[static_cast<size_t>(i)];
		if (leg.inUse) continue;

		// startBridge() attaches the MixBus port and, on any failure past that point,
		// unwinds it itself — so a false return leaves this slot exactly as free as it
		// was, with no port leaked.
		// Re-apply in case this leg was created after setDigitSink() ran; cheap,
		// and it removes the ordering constraint between wiring and joining.
		leg.bridge.setDigitSink(_digitSink);

		if (!leg.bridge.startBridge(handsetIp, handsetPort, callID, ext, dtmfPt))
		{
			return -1;
		}

		leg.callID = callID;
		leg.ext    = ext;
		leg.inUse  = true;
		return i;
	}

	return -1;   // room full
}

bool ConferenceRoom::leave(const std::string& callID)
{
	std::lock_guard<std::mutex> lock(_mutex);
	const int idx = indexOfLocked(callID);
	if (idx < 0)
	{
		return false;
	}

	Leg& leg = _legs[static_cast<size_t>(idx)];
	// Marks the port Draining and stops this leg's sockets. The other legs keep
	// mixing untouched; the next tick clears this port's rings and returns it to Free.
	leg.bridge.stopBridge();
	leg.callID.clear();
	leg.ext.clear();
	leg.inUse = false;
	return true;
}

int ConferenceRoom::rtpPortFor(const std::string& callID) const
{
	std::lock_guard<std::mutex> lock(_mutex);
	const int idx = indexOfLocked(callID);
	return (idx < 0) ? 0 : _legs[static_cast<size_t>(idx)].bridge.receiverPort();
}

bool ConferenceRoom::hasLeg(const std::string& callID) const
{
	std::lock_guard<std::mutex> lock(_mutex);
	return indexOfLocked(callID) >= 0;
}

int ConferenceRoom::legCount() const
{
	std::lock_guard<std::mutex> lock(_mutex);
	int n = 0;
	for (const auto& leg : _legs)
	{
		if (leg.inUse) ++n;
	}
	return n;
}

std::array<std::string, ConferenceRoom::MAX_LEGS> ConferenceRoom::legExtensions() const
{
	std::lock_guard<std::mutex> lock(_mutex);
	std::array<std::string, MAX_LEGS> out;
	for (int i = 0; i < MAX_LEGS; ++i)
	{
		out[static_cast<size_t>(i)] = _legs[static_cast<size_t>(i)].inUse
			? _legs[static_cast<size_t>(i)].ext : std::string();
	}
	return out;
}

MediaBridge* ConferenceRoom::bridgeForCall(const std::string& callID)
{
	std::lock_guard<std::mutex> lock(_mutex);
	const int idx = indexOfLocked(callID);
	return (idx < 0) ? nullptr : &_legs[static_cast<size_t>(idx)].bridge;
}

RtpSender* ConferenceRoom::senderForCall(const std::string& callID)
{
	std::lock_guard<std::mutex> lock(_mutex);
	const int idx = indexOfLocked(callID);
	return (idx < 0) ? nullptr : &_legs[static_cast<size_t>(idx)].tx;
}

// ── The single mix-tick driver ───────────────────────────────────────────────
// One periodic clock for the whole room. Deliberately NOT hung off a leg's
// RtpSender cadence: there are N senders and only one bus, so that would be N
// competing tick paths racing to drain the same rings (docs/CONFERENCE_MIXER.md §3).

void ConferenceRoom::runDriver()
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	TickType_t next = xTaskGetTickCount();
	const TickType_t period = pdMS_TO_TICKS(TICK_MS);
	while (!_stopRequested.load(std::memory_order_acquire))
	{
		vTaskDelayUntil(&next, period);
		_bus.tick();
	}
#else
	auto next = std::chrono::steady_clock::now();
	const auto period = std::chrono::milliseconds(TICK_MS);
	while (!_stopRequested.load(std::memory_order_acquire))
	{
		next += period;
		std::this_thread::sleep_until(next);
		_bus.tick();
	}
#endif
	// Cleared LAST so stopDriver()/the destructor can tell the driver is really gone.
	_driverRunning.store(false, std::memory_order_release);
}

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)

void ConferenceRoom::taskTrampoline(void* arg)
{
	static_cast<ConferenceRoom*>(arg)->runDriver();
	vTaskDelete(nullptr);
}

void ConferenceRoom::startDriver()
{
	if (_driverRunning.load(std::memory_order_acquire))
	{
		return;   // idempotent — never a second tick path
	}
	_stopRequested.store(false, std::memory_order_release);
	_driverRunning.store(true, std::memory_order_release);

	// Core 0 alongside the SIP engine and the RTP media tasks (Issue #49: the display
	// build reserves Core 1 for LVGL). Priority 6 matches RtpSender's media task so the
	// mix tick is not starved by signaling bursts — it IS the master clock.
	BaseType_t ok = xTaskCreatePinnedToCore(
		&ConferenceRoom::taskTrampoline, "conf_mix_tick", 3072, this, 6, nullptr, 0);
	if (ok != pdPASS)
	{
		_driverRunning.store(false, std::memory_order_release);
		ESP_LOGE("ConferenceRoom", "mix tick task could not be created");
	}
}

void ConferenceRoom::stopDriver()
{
	_stopRequested.store(true, std::memory_order_release);
	// The task owns its own teardown; wait (bounded) for it to clear the flag so a
	// destructor never frees the bus out from under a tick in progress.
	for (int i = 0; i < 100 && _driverRunning.load(std::memory_order_acquire); ++i)
	{
		vTaskDelay(pdMS_TO_TICKS(TICK_MS / 2 + 1));
	}
}

#else

void ConferenceRoom::startDriver()
{
	if (_driverRunning.load(std::memory_order_acquire))
	{
		return;   // idempotent — never a second tick path
	}
	_stopRequested.store(false, std::memory_order_release);
	_driverRunning.store(true, std::memory_order_release);
	_driverThread = std::thread([this] { runDriver(); });
}

void ConferenceRoom::stopDriver()
{
	_stopRequested.store(true, std::memory_order_release);
	if (_driverThread.joinable())
	{
		_driverThread.join();
	}
	_driverRunning.store(false, std::memory_order_release);
}

#endif
