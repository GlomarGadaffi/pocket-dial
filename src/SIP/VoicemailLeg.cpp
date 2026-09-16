// VoicemailLeg.cpp — Issue #246 (voicemail Stage 3 of #194).
#include "VoicemailLeg.hpp"

#include "HoldMusic.hpp"

#include <algorithm>
#include <cstring>

VoicemailLeg::State VoicemailLeg::state() const
{
	std::lock_guard<std::mutex> lock(_mutex);
	return _state;
}

bool VoicemailLeg::isIdle() const
{
	std::lock_guard<std::mutex> lock(_mutex);
	return _state == State::Idle;
}

bool VoicemailLeg::playbackDone() const
{
	std::lock_guard<std::mutex> lock(_mutex);
	return _state == State::PlaybackDone;
}

bool VoicemailLeg::startRecording(uint8_t* recordBuf, size_t recordCap, size_t maxBytes,
	const std::string& extension, const std::string& callId)
{
	std::lock_guard<std::mutex> lock(_mutex);
	return startRecordingLocked(recordBuf, recordCap, maxBytes, extension, callId);
}

bool VoicemailLeg::startRecordingLocked(uint8_t* recordBuf, size_t recordCap, size_t maxBytes,
	const std::string& extension, const std::string& callId)
{
	if (_state == State::Recording || _state == State::Finalizing) return false;
	if (recordBuf == nullptr || recordCap == 0 || maxBytes == 0 || maxBytes > recordCap) return false;

	_recordBuf = recordBuf;
	_recordCap = recordCap;
	_maxBytes  = maxBytes;
	_recordLen = 0;
	_extension = extension;
	_callId    = callId;
	_state     = State::Recording;
	return true;
}

bool VoicemailLeg::onCallerRtp(const uint8_t* mulaw, size_t n)
{
	std::lock_guard<std::mutex> lock(_mutex);
	return onCallerRtpLocked(mulaw, n);
}

bool VoicemailLeg::onCallerRtpLocked(const uint8_t* mulaw, size_t n)
{
	if (_state != State::Recording) return false;
	if (mulaw == nullptr || n == 0) return false;

	// Force-finalize on the frame that would exceed the cap, rather than
	// truncating it into the buffer -- a partial-frame write here would just
	// mean recordedLength() is a few bytes short of maxBytes, so nothing is
	// gained by accepting it, and refusing keeps the "never overrun" boundary
	// exact rather than "never overrun, except sometimes by 1 frame minus 1
	// byte."
	if (_recordLen + n > _maxBytes)
	{
		_state = State::Finalizing;
		return false;
	}

	std::memcpy(_recordBuf + _recordLen, mulaw, n);
	_recordLen += n;
	return true;
}

void VoicemailLeg::stopRecording()
{
	std::lock_guard<std::mutex> lock(_mutex);
	if (_state != State::Recording) return;
	_state = State::Finalizing;
}

const uint8_t* VoicemailLeg::recordedData() const
{
	std::lock_guard<std::mutex> lock(_mutex);
	return (_state == State::Finalizing) ? _recordBuf : nullptr;
}

size_t VoicemailLeg::recordedLength() const
{
	std::lock_guard<std::mutex> lock(_mutex);
	return (_state == State::Finalizing) ? _recordLen : 0;
}

std::string VoicemailLeg::extension() const
{
	std::lock_guard<std::mutex> lock(_mutex);
	return _extension;
}

std::string VoicemailLeg::callId() const
{
	std::lock_guard<std::mutex> lock(_mutex);
	return _callId;
}

bool VoicemailLeg::startPlaying(const uint8_t* clip, size_t clipLen,
	const std::string& extension, const std::string& callId)
{
	std::lock_guard<std::mutex> lock(_mutex);
	return startPlayingLocked(clip, clipLen, extension, callId);
}

bool VoicemailLeg::startPlayingLocked(const uint8_t* clip, size_t clipLen,
	const std::string& extension, const std::string& callId)
{
	if (_state == State::Recording || _state == State::Finalizing) return false;
	if (clip == nullptr || clipLen == 0) return false;

	_clip      = clip;
	_clipLen   = clipLen;
	_cursor    = 0;
	_extension = extension;
	_callId    = callId;
	_state     = State::Playing;
	return true;
}

bool VoicemailLeg::fillTx(uint8_t* outUlaw, size_t count)
{
	std::lock_guard<std::mutex> lock(_mutex);
	return fillTxLocked(outUlaw, count);
}

bool VoicemailLeg::fillTxLocked(uint8_t* outUlaw, size_t count)
{
	if (_state != State::Playing) return false;
	if (_clip == nullptr || _clipLen == 0 || outUlaw == nullptr || count == 0) return false;

	// One-shot, not a loop (see the class comment): copy at most what's left
	// in the clip, pad any remainder of this frame with silence, and signal
	// PlaybackDone once the whole clip has been delivered -- never wrap
	// back into the clip's own start the way HoldMusic::advanceCursor() would.
	const size_t remaining = _clipLen - _cursor;
	const size_t toCopy = std::min(count, remaining);
	std::memcpy(outUlaw, _clip + _cursor, toCopy);
	_cursor += toCopy;

	if (toCopy < count)
	{
		std::memset(outUlaw + toCopy, HoldMusic::kUlawSilence, count - toCopy);
	}

	if (_cursor >= _clipLen)
	{
		_state = State::PlaybackDone;
	}

	return true;
}

void VoicemailLeg::reset()
{
	std::lock_guard<std::mutex> lock(_mutex);
	_state     = State::Idle;
	_recordBuf = nullptr;
	_recordCap = 0;
	_maxBytes  = 0;
	_recordLen = 0;
	_clip      = nullptr;
	_clipLen   = 0;
	_cursor    = 0;
	_extension.clear();
	_callId.clear();
}
