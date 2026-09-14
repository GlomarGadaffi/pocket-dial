// Session.cpp: Issue #28 resolved.
#include "Session.hpp"

Session::Session()
	: _state(State::Invited), _startTime(std::chrono::steady_clock::now())
{
}

Session::Session(std::string callID, std::shared_ptr<SipClient> src) :
	_callID(std::move(callID)), _src(src), _state(State::Invited),
	_startTime(std::chrono::steady_clock::now())
{
}

void Session::reset(std::string callID, std::shared_ptr<SipClient> src)
{
	_callID = std::move(callID);
	_src = src;
	_dest.reset();
	_state = State::Invited;
	_startTime = std::chrono::steady_clock::now();
	_isBroadcast = false;
	_isAnchor = false;
	_anchorInbound = false;
	_remoteTag.clear();
	_uacBranch.clear();
	_anchorParticipantId.clear();
	_pendingTargets.clear();
	_inviteMessage.reset();
	_ringTimerArmed = false;
	_noAnswerTarget.clear();
	_huntActive = false;
	_huntMembers.clear();
	_huntIndex = 0;
	_groupExt.clear();
	_peerCallID.clear();
	_parkUac = false;
	_localTag.clear();
	_sessionExpiresSeconds = 0;
	_isRefresher = false;
	_nextRefresh  = {};
	_sessionExpiry = {};
	_dialogFrom.clear();
	_dialogTo.clear();
	_remoteSdp.clear();
	_isTransferBridge = false;
	_blindXferLeg = false;
}

void Session::setState(State state)
{
	if (state == _state)
		return;
	const State prev = _state;
	_state = state;
	if (state == State::Connected)
	{
		if (prev == State::Held)
		{
			// Hold resume inside the same dialog: keep the original connect
			// instant so CDR talk time spans the hold.
			return;
		}
		_startTime = std::chrono::steady_clock::now();
		if (!_dest)
		{
			std::cerr << "Session::setState(Connected): destination not set for call " << _callID << '\n';
			return;
		}
		std::cout << "Session Created between " << _src->getNumber() << " and " << _dest->getNumber() << '\n';
	}
}

void Session::setDest(std::shared_ptr<SipClient> dest)
{
	_dest = dest;
}

const std::string& Session::getCallID() const
{
	return _callID;
}

std::shared_ptr<SipClient> Session::getSrc() const
{
	return _src;
}

std::shared_ptr<SipClient> Session::getDest() const
{
	return _dest;
}

Session::State Session::getState() const
{
	return _state;
}

std::chrono::steady_clock::time_point Session::getStartTime() const
{
	return _startTime;
}

void Session::removePendingTarget(const std::string& number)
{
	for (auto it = _pendingTargets.begin(); it != _pendingTargets.end(); ++it)
	{
		if ((*it)->getNumber() == number)
		{
			_pendingTargets.erase(it);
			break;
		}
	}
}

void Session::release()
{
	_callID.clear();
	_src.reset();
	_dest.reset();
	_state = State::Invited;
	_isBroadcast = false;
	_isAnchor = false;
	_anchorInbound = false;
	_remoteTag.clear();
	_uacBranch.clear();
	_anchorParticipantId.clear();
	_pendingTargets.clear();
	_inviteMessage.reset();
	_ringTimerArmed = false;
	_noAnswerTarget.clear();
	_huntActive = false;
	_huntMembers.clear();
	_huntIndex = 0;
	_groupExt.clear();
	_peerCallID.clear();
	_parkUac = false;
	_localTag.clear();
	_sessionExpiresSeconds = 0;
	_isRefresher = false;
	_nextRefresh  = {};
	_sessionExpiry = {};
	_dialogFrom.clear();
	_dialogTo.clear();
	_remoteSdp.clear();
	_isTransferBridge = false;
	_blindXferLeg = false;
}
