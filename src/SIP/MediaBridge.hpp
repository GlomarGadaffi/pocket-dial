#ifndef MEDIA_BRIDGE_HPP
#define MEDIA_BRIDGE_HPP

#include "RtpReceiver.hpp"
#include "RtpSender.hpp"
#include "AnchorClient.hpp"
#include "PlayoutBuffer.hpp"
#include "MixBus.hpp"
#include <string>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>

// MediaBridge anchors one call's LAN RTP to either an AnchorClient implementation or a
// shared MixBus — it owns the handset-facing RtpReceiver/RtpSender pair and shuttles
// PCM16 audio between them and whichever far side it was wired to. It is itself
// anchor-agnostic: everything it knows about an anchor comes through the AnchorClient
// interface, never a concrete implementation.
//
// Two mutually exclusive modes, chosen once at init() and fixed for the bridge's life:
//
//   * ANCHOR mode (init() with a non-null AnchorClient and no bus) — the historical
//     1:1 leg. Handset RTP is decoded and pushed to AnchorClient::writeAudio(); the
//     anchor's inbound audio arrives via feedRx() into _playoutBuffer, which the
//     sender drains. Unchanged behaviour.
//
//   * BUS mode (init() with a non-null MixBus) — the N-way conference leg
//     (docs/CONFERENCE_MIXER.md §7, Issue #75). startBridge() attaches a MixBus port
//     and the two callbacks swap ends: decoded handset audio goes to
//     MixBus::inputFrame(), and the sender pulls MixBus::outputFrame() — the
//     saturated sum of every OTHER port. _playoutBuffer is unused in this mode; the
//     bus owns the per-port rings. stopBridge() detaches the port, which the mix tick
//     reclaims at the next frame boundary, so one leg leaving never disturbs the rest.
class MediaBridge
{
public:
	MediaBridge();
	~MediaBridge();

	// Set up the bridge dependencies. `anchor` and `bus` may not BOTH be null — the
	// bridge needs somewhere to send the handset's audio. Passing a non-null `bus`
	// selects BUS mode (see the class comment); the default null keeps the historical
	// anchor-only wiring for every existing call site.
	void init(RtpReceiver* receiver, RtpSender* sender, AnchorClient* anchor, MixBus* bus = nullptr);

	// Where an RFC 4733 key press decoded off this bridge's handset stream goes.
	//
	// Invoked ON THE RTP RECEIVE TASK, so the implementation must be thread-safe
	// and must not block — RequestsHandler::queueDtmfDigit() is the intended
	// target and is built for exactly this (a memcpy into a fixed ring under its
	// own small mutex, never the engine lock).
	//
	// Set once at wiring time rather than per call, because the destination is a
	// property of the engine, not of the dialog; the Call-ID that varies per call
	// is supplied by startBridge() and captured for you.
	using DigitSink = std::function<void(std::string_view callId, char digit)>;
	void setDigitSink(DigitSink sink);

	// Start bridging a handset's RTP stream. participantId is the anchor-side
	// participant this bridge serves — it tags writeAudio() so the anchor can route this
	// bridge's handset audio correctly when multiple bridges are active concurrently.
	// In BUS mode it is just an opaque identity used by isFor()/the dashboard.
	// `dtmfPt` is the RFC 4733 telephone-event payload type the handset offered in
	// its SDP (SipMessage::getTelephoneEventPayloadType()); -1 means it offered
	// none, and the receiver stays DTMF-deaf as before. Per-CALL, unlike the sink
	// above, because the payload type is negotiated per dialog — most phones say
	// 101 but the number is theirs to choose.
	bool startBridge(const std::string& handsetIp, uint16_t handsetPort, const std::string& callID, const std::string& participantId, int dtmfPt = -1);

	// Stop all active streams and tear down the bridge
	void stopBridge();

	// Check if the bridge is currently active
	bool isActive() const { return _active.load(std::memory_order_acquire); }

	// Route one inbound PCM chunk from the anchor to this bridge's playout buffer IFF this
	// bridge is active and serving `participantId`. Returns true if it consumed the chunk. The
	// anchor exposes a SINGLE rx callback; RequestsHandler owns it and fans out to the bridge that
	// owns the participant (the bridge no longer registers the anchor callback itself).
	//
	// BUS mode returns false: the sender reads from MixBus::outputFrame(), so anything
	// written into _playoutBuffer here would be silently discarded. Giving the anchor
	// leg its own MixBus port (docs/CONFERENCE_MIXER.md §7's "anchor leg is just another
	// port") is follow-up work — the local N-way conference this bridge serves today
	// needs handset legs only.
	bool feedRx(const std::string& participantId, const int16_t* samples, size_t count);

	// ── The RX/TX callback bodies ────────────────────────────────────────────────
	// These ARE what startBridge() hands to RtpReceiver/RtpSender; they live here as
	// named members rather than inline lambdas so the host suite can drive the exact
	// production code path with no socket (RtpReceiver/RtpSender::start() are no-op
	// stubs on host, and never invoke the callbacks they were given).

	// Handset -> (bus | anchor): decode one µ-law RTP payload and route the PCM16.
	void onHandsetRtp(const uint8_t* mulaw, size_t n);

	// (bus | playout) -> handset: fill one 20 ms µ-law frame for the sender. Returns
	// false only when the bridge is inactive; on underrun it still returns true so
	// RtpSender keeps its comfort-noise samples rather than wiping them.
	bool fillHandsetTx(uint8_t* outUlaw, size_t count);

	// Lookups so RequestsHandler can find the bridge serving a participant / call id (for
	// per-call teardown + the rx fan-out). Both return false when the bridge is idle.
	bool isFor(const std::string& participantId) const;
	bool isForCallId(const std::string& callID) const;
	// The participant / call id this bridge is serving ("" if idle). For the orphan-bridge sweep:
	// drop the upstream leg of a bridge that has outlived its session.
	std::string participantId() const;
	std::string callId() const;

	// The UDP port the bridge's RTP receiver is bound on (0 if not active). This
	// is the port the handset must send its audio to, so it MUST be the value
	// advertised in the 200 OK SDP answer — not the sender's source port.
	int receiverPort() const;

	// The MixBus port this bridge holds, or -1 when idle / not in BUS mode.
	int busPort() const { return _busPort.load(std::memory_order_acquire); }

	// Access statistics
	PlayoutBuffer& getPlayoutBuffer() { return _playoutBuffer; }

private:
	// Largest PCM16 chunk either callback moves in one go (320 samples = 40 ms @ 8 kHz,
	// twice the 20 ms RTP frame). Both directions are bounded by this so neither ever
	// touches the heap on the media path.
	static constexpr size_t MAX_FRAME_SAMPLES = 320;

	// Hand this bridge's MixBus port back (Active -> Draining) and forget it. Caller
	// MUST hold _mutex. Idempotent: a no-op when no port is held or in ANCHOR mode.
	void releaseBusPortLocked();

	// Pointers to the shared dependencies
	RtpReceiver* _receiver = nullptr;
	RtpSender*   _sender = nullptr;
	AnchorClient* _anchor = nullptr;
	// Non-null selects BUS mode. Set once in init() and never mutated afterwards, so
	// the media callbacks may read it without taking _mutex (same as _anchor).
	MixBus*      _bus = nullptr;

	PlayoutBuffer _playoutBuffer;

	std::atomic<bool> _active{false};
	// MixBus port held between startBridge() and stopBridge(); -1 when unheld. Atomic
	// because the media callbacks read it outside _mutex.
	std::atomic<int>  _busPort{-1};
	std::string       _callID;
	std::string       _participantId;   // the anchor-side participant id this bridge serves

	// Set once at wiring time, before any bridge starts, and never mutated after —
	// so the RTP task reads it without synchronisation, the same way it reads the
	// other init()-time dependencies.
	DigitSink _digitSink;

	mutable std::mutex _mutex;
};

#endif // MEDIA_BRIDGE_HPP
