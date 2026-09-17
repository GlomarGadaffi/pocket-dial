#ifndef MEDIA_BRIDGE_HPP
#define MEDIA_BRIDGE_HPP

#include "RtpReceiver.hpp"
#include "RtpSender.hpp"
#include "AnchorClient.hpp"
#include "PlayoutBuffer.hpp"
#include "MixBus.hpp"
#include "HoldMusic.hpp"
#include <string>
#include <string_view>
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

	// Issue #218: the shared hold-music source, for ANCHOR-mode calls only.
	// Wired once at boot alongside init(), same as ParkOrbit::setHoldMusic() —
	// not owned, may be null (in which case setHeld(true) just plays nothing,
	// same fail-safe-to-silence philosophy as every other HoldMusic consumer).
	void setHoldMusic(HoldMusic* moh) { _moh = moh; }

	// Issue #218: put the handset leg on/off hold. While held, onHandsetRtp()
	// discards the handset's real audio instead of forwarding it to the
	// anchor, and this bridge taps into `_moh` so the anchor hears hold music
	// in its place; leaving hold releases the tap and resumes the normal
	// handset -> anchor path. No-op in BUS mode (conference hold is a
	// separate, still-refused case — see onReinvite()'s 777/888 branch) and
	// idempotent (calling with the current state is a no-op).
	void setHeld(bool held);
	bool isHeld() const { return _held.load(std::memory_order_acquire); }

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

	// Issue #280: true once a call whose audio path was genuinely working has
	// then failed kMaxConsecutiveWriteFailures writes in a row, with no
	// success in between. onHandsetRtp()/feedMohTick() are the only writers,
	// so a caller (RequestsHandler's tick() sweep) can poll this instead of
	// the write path having to know anything about SIP teardown.
	//
	// Gated on _hasWrittenSuccessfully (advisor caught this, verified against
	// the real call-setup ordering rather than taken on faith): the INBOUND
	// anchor path pre-warms TelephonyAnchorClient's POST stream during local
	// ringing so it's normally live before the handset ever answers, but
	// answerCall()'s own fallback re-opens it AFTER the ACK already went to
	// the handset if that pre-warm didn't take -- a real ~1s TLS handshake
	// window (this codebase's own comments on the S3's software ECDHE cost)
	// in which the handset can legitimately be sending RTP into a socket that
	// isn't live yet. "Never worked yet" and "was working, now isn't" are
	// different failure shapes, and only the second one is what #280 is
	// actually about -- a connection that never got established isn't
	// "degraded," it just hasn't finished starting.
	bool isAudioDegraded() const
	{
		return _active.load(std::memory_order_acquire) &&
			_hasWrittenSuccessfully.load(std::memory_order_acquire) &&
			_consecutiveWriteFailures.load(std::memory_order_acquire) >= kMaxConsecutiveWriteFailures;
	}

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
	bool feedRx(std::string_view participantId, const int16_t* samples, size_t count);

	// ── The RX/TX callback bodies ────────────────────────────────────────────────
	// These ARE what startBridge() hands to RtpReceiver/RtpSender; they live here as
	// named members rather than inline lambdas so the host suite can drive the exact
	// production code path with no socket (RtpReceiver/RtpSender::start() are no-op
	// stubs on host, and never invoke the callbacks they were given).

	// Handset -> (bus | anchor): decode one µ-law RTP payload and route the PCM16.
	// While held (issue #218), discards the payload instead of forwarding it —
	// see setHeld()'s doc comment.
	void onHandsetRtp(const uint8_t* mulaw, size_t n);

	// Issue #218: HoldMusic's tap target while held (ANCHOR mode only) —
	// decodes one tick's worth of the shared clip and hands it to the anchor
	// in place of the handset's own audio. Public so it matches HoldMusic::
	// TapFn's raw-function-pointer shape via the static trampoline below;
	// callers should go through setHeld(), not call this directly.
	//
	// Invoked from HoldMusic's pacing task, and ONLY after it has released
	// its own _mutex (see HoldMusic::tickLocked()'s doc comment) — never
	// nested under it. This function takes MediaBridge's OWN _mutex briefly,
	// standalone, to snapshot _participantId before the network write below;
	// that lock is never held across the write itself (see the .cpp), so
	// stopBridge() — which also takes this _mutex — can never be made to
	// wait on a slow trunk.
	void feedMohTick(const uint8_t* ulawTick, size_t n);

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

	// Issue #218: fixed capacity for feedMohTick()'s on-stack participant-id
	// snapshot (see the .cpp). 3CX Call Control API participant ids are short
	// numerics (single/double/triple-digit call-leg ids); 32 is generous
	// headroom over that, not a measured maximum. feedMohTick() refuses to
	// deliver a tick rather than silently truncate if this is ever exceeded —
	// see its doc comment for why a truncated id is a correctness hazard
	// (could collide with a different call's slot), not just a lost frame.
	static constexpr size_t kMohParticipantIdBufSize = 32;

	// Issue #284: fixed capacity for dtmfSinkTrampoline()'s on-stack Call-ID
	// snapshot. 128 matches the buffer size this codebase already uses for a
	// Call-ID everywhere else (RequestsHandler.hpp, VoicemailArchive.hpp,
	// TransactionLayer.hpp) -- a SIP Call-ID has no RFC 3261 length cap, unlike
	// the short numeric participant ids kMohParticipantIdBufSize sizes for.
	static constexpr size_t kCallIdBufSize = 128;

	// Issue #280: how many consecutive AnchorClient::writeAudio() failures on
	// one bridge mean "this leg's audio path is actually broken", not "one
	// transient short write". Both writers run on a 20 ms cadence
	// (onHandsetRtp per handset RTP packet, feedMohTick per HoldMusic tick),
	// so 25 is ~500 ms of unbroken failure -- long enough that a single dropped
	// TCP segment or one slow poll cannot trip it, short enough that a genuinely
	// dead anchor connection is caught well inside the multi-second timescale
	// #273's own investigation cared about, not left silently degraded for
	// the rest of the call.
	static constexpr int kMaxConsecutiveWriteFailures = 25;

	// Hand this bridge's MixBus port back (Active -> Draining) and forget it. Caller
	// MUST hold _mutex. Idempotent: a no-op when no port is held or in ANCHOR mode.
	void releaseBusPortLocked();

	// Issue #218: the free-function shape HoldMusic::TapFn needs. Casts `ctx`
	// back to `this` and calls feedMohTick() — kept as a one-line static
	// rather than a capturing lambda so nothing here allocates.
	static void mohTapTrampoline(void* ctx, const uint8_t* ulawTick, size_t n);

	// Issue #284: the free-function shape RtpReceiver::DtmfSink now needs, same
	// reasoning as mohTapTrampoline above. Casts `ctx` back to `this`, snapshots
	// _callID into a fixed on-stack buffer under a short _mutex hold (exactly
	// feedMohTick()'s pattern, for the same reason -- this runs on the RTP
	// receive task, so nothing here may allocate), and forwards to _digitSink,
	// which is boot-time-fixed and safe to read unlocked (see its own doc
	// comment).
	static void dtmfSinkTrampoline(void* ctx, char digit, uint16_t durationMs);

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
	// The anchor-side participant id this bridge serves. Read/written under
	// _mutex almost everywhere already; feedMohTick() (issue #218) is the one
	// caller that reads it from a different thread than the SIP thread that
	// writes it (HoldMusic's pacing task, not RtpReceiver's rx task like
	// onHandsetRtp()'s read below), so it copies this into a fixed buffer
	// under a short, standalone _mutex hold rather than reading it directly —
	// see feedMohTick()'s doc comment in the header and its .cpp body.
	std::string       _participantId;

	// Set once at wiring time, before any bridge starts, and never mutated after —
	// so the RTP task reads it without synchronisation, the same way it reads the
	// other init()-time dependencies.
	DigitSink _digitSink;

	// Issue #218. Not owned; may be null (see setHoldMusic()). Set once at
	// wiring time like _anchor/_bus above, so read without _mutex.
	HoldMusic* _moh = nullptr;
	// Touched from the SIP thread (setHeld()), the handset RTP task
	// (onHandsetRtp()'s discard check) and HoldMusic's own pacing task
	// (feedMohTick()'s active check) -- three different threads, one flag,
	// atomic is sufficient since nothing here depends on it changing
	// atomically WITH anything else.
	std::atomic<bool> _held{false};
	// The tap id addTap() returned, or -1 when not tapped in. Only ever
	// touched from setHeld(), which the SIP thread calls under _mutex
	// (RequestsHandler's engine lock, not this class's own _mutex) — same
	// single-writer assumption _callID/_participantId already make.
	int _mohTapId = -1;

	// Issue #280: count of consecutive AnchorClient::writeAudio() failures on
	// the ACTIVE call, reset on every success and by startBridge()/stopBridge().
	// Written from whichever of onHandsetRtp()/feedMohTick() is currently
	// calling writeAudio() -- setHeld() routes handset audio to one or the
	// other, so the two are not NORMALLY concurrent, though a hold/resume
	// transition could in principle interleave one packet from each. Not
	// worth a lock either way: both are plain atomic ops, so the worst a race
	// does is under- or over-count a single frame at a transition boundary,
	// nothing isAudioDegraded()'s ~500ms threshold would ever notice.
	std::atomic<int> _consecutiveWriteFailures{0};

	// Issue #280: true once ANY writeAudio() has succeeded on the current
	// call. See isAudioDegraded()'s doc comment for why this gate exists --
	// a connection still coming up must never look "degraded" just because
	// it hasn't finished starting yet.
	std::atomic<bool> _hasWrittenSuccessfully{false};

	// Issue #280: record one writeAudio() outcome. Called from both writers
	// right after the call, so the counters reflect the ACTUAL result rather
	// than each writer reimplementing the same bookkeeping.
	void recordWriteAudioResult(bool ok)
	{
		if (ok)
		{
			_hasWrittenSuccessfully.store(true, std::memory_order_release);
			_consecutiveWriteFailures.store(0, std::memory_order_release);
		}
		else
		{
			_consecutiveWriteFailures.fetch_add(1, std::memory_order_acq_rel);
		}
	}

	mutable std::mutex _mutex;
};

#endif // MEDIA_BRIDGE_HPP
