#ifndef RX_RESTART_HPP
#define RX_RESTART_HPP

// Issue #554 (#575 review): the pure decisions TelephonyAnchorClient::
// startRxIfNeeded() makes about a call slot's rx task, pulled out so the host
// suite can pin them (the anchor client itself is ESP-only).

#include <string_view>

#include "RecentIdRing.hpp"

namespace pd
{
	enum class RxStart
	{
		Start,           // no rx task on this slot: create one
		AlreadyPolling,  // a live task (or a teardown in progress) owns the slot
		Restart,         // the old task has provably finished with the slot: replace it
		StillExiting,    // it cleared rxRunning but has not given its done-sem yet
	};

	// handleSet:   slot->rxTaskHandle != nullptr
	// rxRunning:   slot->rxRunning (the task clears it, THEN gives its done-sem)
	// tearingDown: slot->tearingDown
	// semTaken:    xSemaphoreTake(slot->rxDoneSem, 0) succeeded. The caller takes
	//              it only for a handle that is neither running nor tearing down.
	// Restart needs the sem: rxRunning==false alone is not proof, because the
	// task still touches the slot to give the sem. Deleting and recreating that
	// sem under a task that is about to give it is a use-after-free, and a
	// second task on the same slot would follow.
	inline RxStart rxRestartDecision(bool handleSet, bool rxRunning, bool tearingDown, bool semTaken)
	{
		if (!handleSet) return RxStart::Start;
		if (rxRunning || tearingDown) return RxStart::AlreadyPolling;
		return semTaken ? RxStart::Restart : RxStart::StillExiting;
	}

	// Issue #554 (b): a leg we dropped never gets a fresh rx task (and its POST)
	// from a late upsert. Bounded: the ring remembers the last N drops.
	template <std::size_t N, std::size_t Len>
	inline bool rxStartAllowedFor(const RecentIdRing<N, Len>& droppedLegs, std::string_view participantId)
	{
		return !droppedLegs.contains(participantId);
	}
}

#endif // RX_RESTART_HPP
