#ifndef VOICEMAIL_LEG_HPP
#define VOICEMAIL_LEG_HPP

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>

// VoicemailLeg: one active deposit-or-retrieval call terminated locally by
// the board (Issue #246, Stage 3 of #194) -- the 1:1 record+playback
// counterpart to ConferenceRoom's N-way mix legs and MediaBridge's
// anchor/bus relay. Deliberately much smaller than either: no mixing, no
// anchor/bus duality, no MoH tap-while-held. A pool of these (see
// POCKETDIAL_MAX_VOICEMAIL_LEGS) is wired to its own {RtpReceiver,RtpSender}
// pair the same way RequestsHandler wires _mediaBridges to
// _anchorRtpReceivers/_anchorRtpSenders.
//
// Pure/host-testable: this whole class holds no FreeRTOS/socket state of its
// own -- that lives in the RtpReceiver/RtpSender pair the caller wires up,
// exactly as MediaBridge does. onCallerRtp()/fillTx() are the callback
// BODIES those objects invoke on the receive/send tasks; every other public
// method runs on the SIP thread.
//
// Locking contract (found in review -- see PR discussion on #246): every
// public method takes `_mutex` for its whole body, MediaBridge-style, rather
// than relying on a join-before-reset ordering at the wiring site. Unlike
// MediaBridge, nothing here ever does slow/blocking work (no network write,
// just a bounded memcpy), so there is no need to release the lock before the
// "real work" the way MediaBridge does around AnchorClient::writeAudio() --
// holding it for the whole call is simplest and matches HoldMusic's
// simpler tickLocked()-under-one-lock shape. This is what makes it safe for
// onCallerRtp() (receive task) and fillTx() (send task) to run concurrently
// with startRecording()/stopRecording()/startPlaying()/reset() (SIP thread)
// without the SIP thread's reset() being able to null out _recordBuf/_clip
// mid-memcpy on a media task.
//
// Recording safety (the reason a separate buffer-handoff class exists
// instead of writing to SD inline): the caller's audio is appended into a
// PSRAM buffer THE CALLER PROVIDES -- one fixed pool slot per leg, allocated
// once at boot, never here, never per-call. This class never touches the SD
// card. finalize (the Recording -> Finalizing transition) just exposes
// {data, length} for RequestsHandler to hand off to a dedicated flush task
// after BYE. See docs/RTP.md's Music-on-Hold entry for why the SD card must
// stay off this class's producer path (the RTP receive task): sdspi
// poll_busy() busy-spins and 100-250ms card GC stalls would corrupt/drop
// live audio, the same reasoning issue #162 already established.
//
// Playback is ONE-SHOT, not a loop (found in review): a greeting, an IVR
// prompt or a retrieved message must play once and then signal "done" so the
// SIP side / DTMF menu can react ("press 1 to delete") -- unlike HoldMusic,
// which is deliberately a looping radio station. fillTx() advances a plain
// linear cursor (not HoldMusic::advanceCursor(), which wraps) and the leg
// transitions to PlaybackDone once the whole clip has been delivered; a
// clip length that doesn't evenly divide the caller's frame size gets the
// remainder of that last frame padded with HoldMusic::kUlawSilence rather
// than looping back into the clip's own start.
class VoicemailLeg
{
public:
	enum class State
	{
		Idle,          // not serving a call; ready to be claimed from the pool
		Recording,     // deposit: appending caller audio into the record buffer
		Playing,       // retrieval/greeting: streaming a clip out via fillTx()
		PlaybackDone,  // the clip started in Playing has been delivered once
		Finalizing,    // recording stopped, {data,length} ready for hand-off
	};

	VoicemailLeg() = default;

	State state() const;
	bool isIdle() const;

	// True once a Playing clip has been delivered in full (see the class
	// comment on one-shot playback). The SIP side polls this (or a
	// caller-supplied callback in a later slice) to know when to advance a
	// menu or hang up. Always false outside PlaybackDone.
	bool playbackDone() const;

	// Claim this leg to record caller audio. `recordBuf`/`recordCap` is a
	// pool slot the CALLER owns and allocated once at boot (see the class
	// comment) -- this class never allocates. `maxBytes` additionally bounds
	// THIS recording to at most `maxBytes` (the configured per-message
	// duration cap), which must not exceed `recordCap` -- the physical slot
	// is sized once for the largest allowed message so every recording
	// still respects the cap even if it's later lowered without resizing
	// the pool. Allowed from Idle, Playing or PlaybackDone (e.g. after a
	// greeting finishes); refused (returns false, no state change) from
	// Recording or Finalizing, so an in-progress OR not-yet-handed-off
	// recording can never be silently abandoned or overwritten -- call
	// reset() first to discard a Finalizing recording deliberately.
	bool startRecording(uint8_t* recordBuf, size_t recordCap, size_t maxBytes,
		const std::string& extension, const std::string& callId);

	// The RtpReceiver::Sink body for a Recording leg: append `n` raw mu-law
	// bytes. Bounds-checked against the cap passed to startRecording() --
	// force-finalizes (transitions to Finalizing) on the frame that would
	// exceed it rather than overrunning the buffer, so a caller who never
	// hangs up still gets a message capped at the configured duration
	// instead of corrupting adjacent PSRAM. No-op (returns false) when not
	// Recording.
	bool onCallerRtp(const uint8_t* mulaw, size_t n);

	// Stop recording early (BYE, DTMF '#', or a silence-detection timeout)
	// and move to Finalizing. No-op if not Recording. Same effect as
	// onCallerRtp() hitting the cap, just caller-triggered instead of
	// buffer-triggered.
	void stopRecording();

	// The recorded span, valid only in Finalizing state (empty otherwise).
	// The caller (RequestsHandler) hands this off BY VALUE to the flush
	// queue and must not read it after reset() is called -- reset() returns
	// the slot to the pool without zeroing it.
	const uint8_t* recordedData() const;
	size_t recordedLength() const;
	std::string extension() const;
	std::string callId() const;

	// Claim this leg for prompt/message PLAYBACK (a deposit call's greeting
	// before recording starts, or the retrieval menu / a fetched message).
	// `clip`/`clipLen` is a PSRAM-resident buffer this class does NOT own
	// (loaded once, the same one-shot way HoldMusic::loadClip() is) --
	// mirrors HoldMusic's clip storage but plays it exactly ONCE with a
	// PER-INSTANCE cursor, not HoldMusic's single global looping one (see
	// the class comment). Refuses a null or zero-length clip (returns false,
	// no state change) rather than entering Playing with nothing to play --
	// found in review: without this, an empty/failed-to-load greeting would
	// hang the leg in Playing forever, since fillTx() would return false but
	// never reach PlaybackDone. Otherwise allowed from Idle, Playing or
	// PlaybackDone (replay / advancing to the next prompt); refused from
	// Recording or Finalizing, so starting playback can never silently
	// abandon an in-progress OR not-yet-handed-off recording.
	bool startPlaying(const uint8_t* clip, size_t clipLen,
		const std::string& extension, const std::string& callId);

	// The RtpSender::FrameProvider body for a Playing leg: fill `count`
	// mu-law bytes from the current clip, advancing a plain linear cursor
	// (no wrap -- see the class comment). Once the clip is exhausted mid-
	// frame, the remainder of that frame is padded with
	// HoldMusic::kUlawSilence and the leg transitions to PlaybackDone.
	// Returns false (silence) when not Playing or no clip is loaded --
	// RtpSender keeps its own comfort-noise samples on a false return, the
	// same contract HoldMusic/MediaBridge already rely on.
	bool fillTx(uint8_t* outUlaw, size_t count);

	// Release back to Idle for pool reuse. Safe from any state, including
	// Finalizing (the intended way to discard a recording once its
	// {data,length} has been handed off). Clears the buffer/clip pointers
	// (does NOT free or return them -- that is the pool owner's job) and
	// the extension/callId identity.
	void reset();

private:
	// Internal, lock-already-held bodies. Every public method above takes
	// _mutex and calls straight through to one of these -- see the class
	// comment's Locking contract paragraph for why holding the lock across
	// the whole body (including the memcpy in the two media-task-invoked
	// methods) is safe here, unlike MediaBridge's release-before-slow-work
	// pattern.
	bool startRecordingLocked(uint8_t* recordBuf, size_t recordCap, size_t maxBytes,
		const std::string& extension, const std::string& callId);
	bool onCallerRtpLocked(const uint8_t* mulaw, size_t n);
	bool startPlayingLocked(const uint8_t* clip, size_t clipLen,
		const std::string& extension, const std::string& callId);
	bool fillTxLocked(uint8_t* outUlaw, size_t count);

	mutable std::mutex _mutex;

	State       _state = State::Idle;

	// Recording (deposit).
	uint8_t*    _recordBuf = nullptr;   // not owned; a pool slot
	// Physical slot size, kept only so startRecording()'s maxBytes <=
	// recordCap sanity check has something to check against -- never
	// consulted again after that (the enforced bound for onCallerRtp() is
	// always _maxBytes, the smaller of the two).
	size_t      _recordCap = 0;
	size_t      _maxBytes  = 0;         // the smaller, per-message duration cap
	size_t      _recordLen = 0;         // bytes written so far

	// Playback (prompt/greeting/message). One-shot: _cursor is a plain
	// linear offset into [0, _clipLen), never wrapped -- see the class
	// comment on why looping is wrong for this class.
	const uint8_t* _clip    = nullptr;  // not owned
	size_t         _clipLen = 0;
	size_t         _cursor  = 0;

	std::string _extension;
	std::string _callId;
};

#endif
