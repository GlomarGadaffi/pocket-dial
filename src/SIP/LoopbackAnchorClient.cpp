// LoopbackAnchorClient — reference implementation of AnchorClient.
//
// This is not only useful for echo-testing: it shows exactly what any AnchorClient
// implementation must do. Swap it for your own subclass to bridge active calls to a
// SIP trunk, a recording server, an AI pipeline, or any system that can consume and
// inject G.711/PCM-16 audio. The engine calls makeCall(), feeds audio via writeAudio(),
// and receives audio from the external system through the AudioRxCallback. The loopback
// simply returns whatever audio it receives — a useful smoke test that exercises the
// full call-setup and audio-path without any external dependency.

#include "LoopbackAnchorClient.hpp"
#include <chrono>
#include <atomic>

namespace
{
	std::atomic<uint64_t> g_activeCallId{0};
}

LoopbackAnchorClient::LoopbackAnchorClient() = default;

LoopbackAnchorClient::~LoopbackAnchorClient()
{
	shutdownImpl();   // non-virtual: never dispatch a virtual call from a destructor
}

bool LoopbackAnchorClient::init(const std::string& baseUrl,
                               const std::string& clientId,
                               const std::string& /*clientSecret*/,
                               const std::string& sourceDn)
{
	_baseUrl = baseUrl;
	_clientId = clientId;
	_sourceDn = sourceDn;
	return true;
}

bool LoopbackAnchorClient::start()
{
	_connected = true;
	return true;
}

void LoopbackAnchorClient::stop()
{
	shutdownImpl();
}

void LoopbackAnchorClient::shutdownImpl()
{
	_connected = false;
	_stopSimThread = true;
	g_activeCallId++;
	reapSimThreads();
	std::lock_guard<std::mutex> lock(_mutex);
	_eventCb = nullptr;
	_audioCb = nullptr;
}

void LoopbackAnchorClient::reapSimThreads()
{
	// Join the previous call's simulation threads so _simThreads doesn't grow
	// unboundedly on a long-running instance. Callers bump g_activeCallId first,
	// so every outstanding thread exits at its next checkpoint (≤ ~40ms). Joins
	// happen outside _mutex — the sim threads lock it in their callbacks.
	std::vector<std::thread> threadsToJoin;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		threadsToJoin = std::move(_simThreads);
	}
	for (auto& t : threadsToJoin)
	{
		if (t.joinable())
		{
			t.join();
		}
	}
}

bool LoopbackAnchorClient::isConnected() const
{
	return _connected;
}

bool LoopbackAnchorClient::makeCall(const std::string& destination, std::string* ownLegOut)
{
	if (!_connected)
	{
		return false;
	}

	{
		std::lock_guard<std::mutex> lock(_mutex);
		_lastMakeCallDestination = destination;
	}

	// Resolve our own leg synchronously so the engine can bind the session before any
	// Answered event arrives.
	//
	// The id is FIXED, and that is why maxConcurrentCalls() reports 1 (see the
	// override in the header). The previous comment here claimed this kept "call
	// correlation correct even when multiple calls are in flight", which cannot be
	// true of a constant: the engine keys its rx-audio fan-out on the participant
	// id, so two live loopback calls would collide on "mock-part-123". The sim-thread
	// machinery below says the same thing in code — `_stopSimThread = true` plus
	// reapSimThreads() deliberately SUPERSEDES any previous call, and the stale-call
	// guard (`myCallId != g_activeCallId`) exists to let it. This is a single-call
	// mock by construction, not by accident.
	if (ownLegOut) *ownLegOut = "mock-part-123";

	_stopSimThread = true;
	uint64_t myCallId = ++g_activeCallId;
	reapSimThreads();
	_stopSimThread = false;

	{
		std::lock_guard<std::mutex> lock(_mutex);
		_simThreads.emplace_back([this, myCallId]() {
			// Simulate network delay for ringing
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
			if (myCallId != g_activeCallId.load()) return;

			EventCallback evCb;
			{
				std::lock_guard<std::mutex> lock(_mutex);
				evCb = _eventCb;
				_activeParticipantId = "mock-part-123";
			}

			if (evCb)
			{
				CallEvent ringingEv{CallEvent::Ringing, _activeParticipantId, "", ""};
				evCb(ringingEv);
			}

			// Simulate call answering
			std::this_thread::sleep_for(std::chrono::milliseconds(30));
			if (myCallId != g_activeCallId.load()) return;

			if (evCb)
			{
				CallEvent answerEv{CallEvent::Answered, _activeParticipantId, "", ""};
				evCb(answerEv);
			}
		});
	}

	return true;
}

bool LoopbackAnchorClient::answerCall(const std::string& participantId)
{
	if (!_connected)
	{
		return false;
	}

	std::string partId;
	EventCallback evCb;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		partId = participantId.empty() ? _activeParticipantId : participantId;
		if (partId.empty())
		{
			return false;
		}
		_activeParticipantId = partId;
		evCb = _eventCb;
	}

	// Answering the inbound participant connects the leg — fire the Answered event
	// on a sim thread so the callback never runs under the caller's lock.
	if (evCb)
	{
		std::thread answerThread([evCb, partId]() {
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
			CallEvent answerEv{CallEvent::Answered, partId, "", ""};
			evCb(answerEv);
		});
		std::lock_guard<std::mutex> lock(_mutex);
		_simThreads.push_back(std::move(answerThread));
	}
	return true;
}

void LoopbackAnchorClient::simulateInboundCall(const std::string& callerId)
{
	if (!_connected)
	{
		return;
	}

	_stopSimThread = true;
	uint64_t myCallId = ++g_activeCallId;
	reapSimThreads();
	_stopSimThread = false;

	std::lock_guard<std::mutex> lock(_mutex);
	_simThreads.emplace_back([this, myCallId, callerId]() {
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
		if (myCallId != g_activeCallId.load()) return;

		EventCallback evCb;
		std::string partId = "mock-in-" + std::to_string(myCallId);
		{
			std::lock_guard<std::mutex> lock(_mutex);
			evCb = _eventCb;
			_activeParticipantId = partId;
		}
		if (evCb)
		{
			CallEvent inEv{CallEvent::Incoming, partId, "", callerId};
			evCb(inEv);
		}
	});
}

bool LoopbackAnchorClient::dropCall(const std::string& participantId)
{
	if (!_connected)
	{
		return false;
	}

	std::string partId;
	EventCallback evCb;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		partId = participantId.empty() ? _activeParticipantId : participantId;
		if (partId.empty())
		{
			return false;
		}
		_activeParticipantId.clear();
		evCb = _eventCb;
	}

	_stopSimThread = true;
	g_activeCallId++;
	reapSimThreads();

	if (evCb)
	{
		// Spawn the event callback thread outside the lock. emplace_back under
		// _mutex risks vector reallocation while stop() is moving threads out,
		// and mirrors the lock-free join pattern already used in stop().
		std::thread dropThread([evCb, partId]() {
			CallEvent dropEv{CallEvent::Dropped, partId, "", ""};
			evCb(dropEv);
		});
		{
			std::lock_guard<std::mutex> lock(_mutex);
			_simThreads.push_back(std::move(dropThread));
		}
	}

	return true;
}

void LoopbackAnchorClient::setEventCallback(EventCallback cb)
{
	std::lock_guard<std::mutex> lock(_mutex);
	_eventCb = cb;
}

bool LoopbackAnchorClient::writeAudio(const std::string& participantId, const int16_t* pcmSamples, size_t count)
{
	if (!_connected)
	{
		return false;
	}

	AudioRxCallback audioCb;
	std::string partId;
	{
		std::lock_guard<std::mutex> lock(_mutex);
		audioCb = _audioCb;
		partId = participantId.empty() ? _activeParticipantId : participantId;
	}

	if (audioCb && pcmSamples != nullptr && count > 0)
	{
		audioCb(partId, pcmSamples, count);   // loopback: echo this participant's audio back
	}

	return true;
}

void LoopbackAnchorClient::registerAudioRxCallback(AudioRxCallback cb)
{
	std::lock_guard<std::mutex> lock(_mutex);
	_audioCb = cb;
}
