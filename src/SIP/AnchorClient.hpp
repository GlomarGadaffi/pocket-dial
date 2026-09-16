#ifndef ANCHOR_CLIENT_HPP
#define ANCHOR_CLIENT_HPP

// AnchorClient: interface for handing a SIP call leg off to an external audio system.
//
// Implement this to bridge pocket-dial calls to anything: a SIP trunk, a recording
// server, an AI voice pipeline, a PSTN gateway — whatever needs to receive and inject
// G.711 audio into an active call. LoopbackAnchorClient (same directory) is a working
// reference implementation that echoes audio back to the caller.

#include <string>
#include <string_view>
#include <functional>
#include <cstdint>
#include <cstddef>

class AnchorClient
{
public:
	struct CallEvent
	{
		// Ringing/Answered/Dropped/Dtmf describe a call the device ORIGINATED (outbound,
		// via makeCall). Incoming is the inverse: an external system is delivering an
		// inbound call to a DN this device monitors; ring a local extension, then call
		// answerCall() to accept it. callerId carries the caller's number/name (best-effort).
		// cppcheck flags `type` as uninitMemberVarNoCtor. False positive: every
		// CallEvent is constructed at its call sites (LoopbackAnchorClient.cpp)
		// with all four fields brace-initialised.
		// cppcheck-suppress uninitMemberVarNoCtor
		enum Type { Ringing, Answered, Dropped, Dtmf, Incoming } type;
		std::string participantId;
		std::string dtmfDigit;
		std::string callerId;
	};
	using EventCallback = std::function<void(const CallEvent&)>;
	// Issue #284: string_view, not `const std::string&` -- installed once at
	// boot wiring time ([this]-only capture, SBO-safe as a std::function), but
	// every implementation's per-chunk invocation used to copy the participant
	// id into a real std::string first. That copy is SBO-safe today only
	// because 3CX participant ids are short numerics; string_view lets every
	// caller pass a fixed on-stack buffer instead of depending on that staying
	// true.
	using AudioRxCallback = std::function<void(std::string_view participantId, const int16_t* pcmSamples, size_t count)>;

	virtual ~AnchorClient() = default;

	// Initialize credentials and endpoints
	virtual bool init(const std::string& baseUrl,
	                  const std::string& clientId,
	                  const std::string& clientSecret,
	                  const std::string& sourceDn) = 0;

	// Connect / start the client
	virtual bool start() = 0;

	// Disconnect and release all handles
	virtual void stop() = 0;

	// Status query
	virtual bool isConnected() const = 0;

	// Originate an outbound call. If ownLegOut is non-null, on success it receives the
	// participant id of the leg WE control so the caller can bind it to the session before
	// any Answered event arrives — keeping call correlation correct under concurrency.
	virtual bool makeCall(const std::string& destination, std::string* ownLegOut = nullptr) = 0;

	// Accept an inbound call the external system is delivering (mirror of makeCall).
	// Call this once the local extension has accepted; participantId is from CallEvent::Incoming.
	virtual bool answerCall(const std::string& participantId) = 0;

	// Hang up an active call
	virtual bool dropCall(const std::string& participantId) = 0;

	// Register listener for call-state events
	virtual void setEventCallback(EventCallback cb) = 0;

	// Push a PCM-16 audio chunk into an active call, keyed by participant id.
	// string_view, not const std::string& (issue #218 follow-up): MediaBridge's
	// HoldMusic-tap call site (feedMohTick()) must not allocate to build this
	// argument -- it runs on HoldMusic's real-time pacing task, where the
	// embedded firmware rules forbid heap allocation after init, and the
	// participant id there comes from a fixed on-stack buffer, not a
	// std::string. Every implementation still receives a valid, non-owning
	// view; a std::string argument at any other call site converts for free.
	virtual bool writeAudio(std::string_view participantId, const int16_t* pcmSamples, size_t count) = 0;

	// Register the callback that receives inbound PCM-16 audio chunks from the external system.
	virtual void registerAudioRxCallback(AudioRxCallback cb) = 0;

	// Periodic, non-blocking maintenance pump driven from RequestsHandler::tick() (≤1 Hz).
	// Do only constant-time work here — read flags, spawn workers for blocking I/O —
	// never block, log, or allocate inside this call.
	virtual void tick() = 0;

	// TLS handshake telemetry: full vs resumed sessions. Default 0/0 for implementations
	// that don't maintain a persistent TLS stream.
	virtual void getTlsHandshakeStats(uint32_t& fullOut, uint32_t& resumedOut) const
	{
		fullOut = 0;
		resumedOut = 0;
	}

	// Idle re-warm cadence (SECONDS): implementations that hold a persistent TLS connection
	// can refresh it while idle so the first call after a quiet period doesn't pay a cold
	// handshake. 0 = disabled. Default no-op.
	virtual void setRewarmIntervalSec(uint32_t sec) { (void)sec; }

	// How many calls THIS implementation can anchor at once.
	//
	// POCKETDIAL_MAX_ANCHOR_CALLS sizes the engine's per-call arrays (bridges, RTP
	// port pairs, WS workers) — it is a ceiling on the machinery. It is NOT a
	// statement that whatever provider is plugged in can actually drive that many,
	// and the two are genuinely different limits:
	//
	//   * A real provider's makeCall() must hand back a DISTINCT participant id per
	//     call, because the engine keys its rx-audio fan-out on that id. One that
	//     returns a constant cannot be used concurrently at all: two calls would
	//     collide on the id and the fan-out would feed whichever bridge it found
	//     first, silently starving the other call's audio. That is not a crash, it
	//     is one-way audio nobody can explain.
	//   * So the safe default here is 1 — a new implementation is single-call until
	//     it proves otherwise, rather than inheriting a ceiling it cannot honour.
	//
	// The engine takes min(this, POCKETDIAL_MAX_ANCHOR_CALLS) when deciding whether
	// to accept another anchored call.
	virtual unsigned maxConcurrentCalls() const { return 1; }
};

#endif // ANCHOR_CLIENT_HPP
