#ifndef VOICEMAIL_MENU_HPP
#define VOICEMAIL_MENU_HPP

// VoicemailMenu -- Issue #246 (voicemail Stage 3 of #194), retrieval slice
// 2 of 3 (vmarchive read side -> THIS -> SIP routing/wiring).
//
// Pure retrieval-menu state machine: digits and playback-done events in,
// one Command out per event. No RequestsHandler, no RTP, no filesystem --
// unit-tested directly. Deliberately NOT bolted onto DtmfFeatureCodes's
// flat completed-pattern matcher (see pocket_dial_246_voicemail.md):
// retrieval needs PER-LEG modal state (which message is current), and its
// digits arrive on the voicemail leg's own RtpReceiver, never through the
// global accumulator.
//
// MVP UX is deliberately minimal: auto-play messages back to back with no
// spoken prompts (no "press 1 to listen" preamble -- this repo has no
// voice-prompt assets beyond the deposit-side greeting, and playing THAT
// clip in a retrieval context would be semantically wrong). Three digits,
// fixed for MVP, not configurable: '7' deletes the message currently
// playing and moves on, '#' skips to the next message without deleting,
// '*' hangs up immediately from any active state. Any other digit is
// ignored. Don't add save/replay/rewind or per-extension digit config --
// this is the whole MVP menu.
//
// LATENCY WART, inherited from the deposit side and NOT fixed here: this
// class's onPlaybackDone() is driven from sweepVoicemailLegs(), which
// tick() throttles to 1 Hz (see pocket_dial_build_environment.md). A
// caller sits through up to ~1s of dead air between one message ending
// and the next starting. The fix is NOT to drive this class from the RTP
// thread -- it is not thread-safe and must stay that way (this class
// assumes a single caller, matching RequestsHandler's own single-SIP-
// thread invariant) -- it is to shorten tick()'s own cadence, a separate,
// broader change outside this issue.
//
// LOADING is NOT this class's concern: answerVoicemailRetrieval() answers
// on the SIP thread, but vmarchive::Source::listMessages() is SD I/O and
// must run on the SD-I/O task (never the SIP thread -- see
// VoicemailArchive.hpp's class comment). The wiring layer owns the
// "answered, list requested, not yet back" period (e.g. a Loading flag on
// the Session) and calls start() only once the list has actually arrived
// -- this class has no concept of "loading" and assumes its message count
// is already known when start() is called.

#include <cstddef>
#include <cstdint>

class VoicemailMenu
{
public:
	enum class Command : uint8_t
	{
		None,          // nothing to do: digit ignored, or called before start()/after Done
		PlayMessage,   // play playIndex from the caller's own listing
		PlayPrompt,    // play the "you have no messages" prompt (falls back to an
		               // immediate onPlaybackDone() call if none is loaded, the
		               // same graceful-degradation convention the deposit-side
		               // greeting already uses)
		Hangup,        // end the call
	};

	// One event's outcome. `playIndex` is set (>=0) only for a PlayMessage
	// command. `deleteIndex` is set (>=0) whenever THIS event also
	// requires deleting a message (currently only the '7' digit) --
	// independently of `command`, since deleting message N and then
	// playing message N+1 (or hanging up, if N was last) both happen on
	// the SAME event. The wiring layer must check `deleteIndex` on every
	// Result, not only when `command == Hangup`.
	struct Result
	{
		Command command = Command::None;
		int playIndex = -1;
		int deleteIndex = -1;
	};

	// Starts the menu once `messageCount` (from a listMessages() call the
	// wiring layer already ran off the SIP thread -- see the class comment)
	// is known. Call exactly once, before any onDigit()/onPlaybackDone().
	Result start(size_t messageCount);

	// One DTMF digit arrived on this leg.
	Result onDigit(char digit);

	// The audio started by the last PlayMessage/PlayPrompt Command finished.
	Result onPlaybackDone();

	bool isDone() const { return _state == State::Done; }

private:
	enum class State : uint8_t { Idle, PlayingMessage, PlayingPrompt, Done };

	// Shared "this message/prompt is over, what's next" transition -- used
	// by start() (from index -1), onPlaybackDone() (natural end), and
	// onDigit('#') (skip without deleting). Never sets deleteIndex itself;
	// onDigit('7') sets that field on the Result this returns.
	Result advance();

	State _state = State::Idle;
	size_t _messageCount = 0;
	int _currentIndex = -1;
};

#endif
