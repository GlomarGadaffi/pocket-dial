// VoicemailMenu.cpp -- Issue #246 (voicemail Stage 3 of #194).
#include "VoicemailMenu.hpp"

VoicemailMenu::Result VoicemailMenu::advance()
{
	++_currentIndex;
	if (_currentIndex >= static_cast<int>(_messageCount))
	{
		_state = State::Done;
		return {Command::Hangup, -1, -1};
	}
	_state = State::PlayingMessage;
	return {Command::PlayMessage, _currentIndex, -1};
}

VoicemailMenu::Result VoicemailMenu::start(size_t messageCount)
{
	_messageCount = messageCount;
	_currentIndex = -1;
	if (messageCount == 0)
	{
		_state = State::PlayingPrompt;
		return {Command::PlayPrompt, -1, -1};
	}
	return advance();
}

VoicemailMenu::Result VoicemailMenu::onDigit(char digit)
{
	if (_state == State::Done || _state == State::Idle) return {Command::None, -1, -1};

	if (digit == '*')
	{
		_state = State::Done;
		return {Command::Hangup, -1, -1};
	}

	if (_state == State::PlayingPrompt)
	{
		// Any digit while "you have no messages" is playing means hang up --
		// a caller who hears that and presses anything expects the call to
		// end, not silence until the prompt itself times out.
		_state = State::Done;
		return {Command::Hangup, -1, -1};
	}

	// _state == PlayingMessage from here.
	if (digit == '7')
	{
		const int deleted = _currentIndex;
		Result r = advance();
		r.deleteIndex = deleted;
		return r;
	}
	if (digit == '#')
	{
		return advance();
	}
	return {Command::None, -1, -1};
}

VoicemailMenu::Result VoicemailMenu::onPlaybackDone()
{
	if (_state == State::PlayingPrompt)
	{
		_state = State::Done;
		return {Command::Hangup, -1, -1};
	}
	if (_state == State::PlayingMessage)
	{
		return advance();
	}
	return {Command::None, -1, -1};
}
