#ifndef LOOPBACK_ANCHOR_CLIENT_HPP
#define LOOPBACK_ANCHOR_CLIENT_HPP

#include "AnchorClient.hpp"
#include <mutex>
#include <thread>
#include <atomic>
#include <string>
#include <vector>

class LoopbackAnchorClient : public AnchorClient
{
public:
	LoopbackAnchorClient();
	~LoopbackAnchorClient() override;

	bool init(const std::string& baseUrl,
	          const std::string& clientId,
	          const std::string& clientSecret,
	          const std::string& sourceDn) override;

	bool start() override;
	void stop() override;
	bool isConnected() const override;
	bool makeCall(const std::string& destination, std::string* ownLegOut = nullptr) override;
	bool answerCall(const std::string& participantId) override;
	bool dropCall(const std::string& participantId) override;
	void setEventCallback(EventCallback cb) override;
	bool writeAudio(const std::string& participantId, const int16_t* pcmSamples, size_t count) override;
	void registerAudioRxCallback(AudioRxCallback cb) override;
	void tick() override {}   // no periodic maintenance for the in-process loopback

	// Single-call by construction: makeCall() hands back the constant participant id
	// "mock-part-123" (LoopbackAnchorClient.cpp), and the engine keys rx-audio
	// fan-out on that id, so a second concurrent call would collide with the first
	// and silently starve one leg's audio. The sim threads reinforce it — a new
	// makeCall() supersedes the previous one rather than running alongside it.
	// Reported explicitly rather than left to the base default so that raising
	// POCKETDIAL_MAX_ANCHOR_CALLS can never quietly enable concurrency here.
	unsigned maxConcurrentCalls() const override { return 1; }

	// Test hook: pretend the upstream is delivering a PSTN call to the monitored DN.
	// Fires a single CallEvent::Incoming (participant id "mock-in-<n>", the given
	// callerId). The engine is expected to ring a local extension and then call
	// answerCall(), which drives the participant to Answered — mirroring makeCall().
	void simulateInboundCall(const std::string& callerId);

	// Test hook (Issue #165): the `destination` argument makeCall() was last called
	// with. LoopbackAnchorClient otherwise ignores it entirely (it's a mock loop, not
	// a real trunk), so this is the only way a host test can prove a dial-plan Trunk
	// rule's strip/prepend transform actually reached the anchor call rather than the
	// caller's own untransformed number.
	std::string lastMakeCallDestination() const
	{
		std::lock_guard<std::mutex> lock(_mutex);
		return _lastMakeCallDestination;
	}

private:
	std::string _baseUrl;
	std::string _clientId;
	std::string _sourceDn;

	std::atomic<bool> _connected{false};
	std::string _activeParticipantId;
	std::string _lastMakeCallDestination;

	EventCallback   _eventCb;
	AudioRxCallback _audioCb;

	mutable std::mutex _mutex;

	void reapSimThreads();
	// Non-virtual teardown shared by stop() and the destructor so ~LoopbackAnchorClient()
	// never makes a virtual call (cppcheck virtualCallInConstructor).
	void shutdownImpl();

	std::vector<std::thread> _simThreads;
	std::atomic<bool> _stopSimThread{false};
};

#endif // LOOPBACK_ANCHOR_CLIENT_HPP
