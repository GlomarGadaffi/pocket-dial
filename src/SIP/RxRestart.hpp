#ifndef RX_RESTART_HPP
#define RX_RESTART_HPP

// Issue #554 (#575 review): the pure decisions TelephonyAnchorClient::
// startRxIfNeeded() makes about a call slot's rx task, pulled out so the host
// suite can pin them (the anchor client itself is ESP-only).

#include <cstdint>
#include <string_view>

#include "ParkedTaskReap.hpp"
#include "RecentIdRing.hpp"

namespace pd
{
	enum class RxStart
	{
		Start,           // no rx task on this slot: create one
		AlreadyPolling,  // a live task (or a teardown in progress) owns the slot
		Restart,         // the old task has provably finished with the slot: replace it
		StillExiting,    // it cleared rxRunning but has not given its done-sem yet, or (#682)
		                 // a teardown with no rx task is still freeing the slot: refuse, retry
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
		// #682: a stop that found no rx task still closes getClient and frees the slot; a
		// task started under it would lose both. Refuse until the teardown is done.
		if (!handleSet) return tearingDown ? RxStart::StillExiting : RxStart::Start;
		if (rxRunning || tearingDown) return RxStart::AlreadyPolling;
		return semTaken ? RxStart::Restart : RxStart::StillExiting;
	}

	// Issue #553: may allocSlotLocked() hand this slot to a new participant?
	// Only when it is free, not mid-teardown, and holds no rx task that is still
	// alive. A task detached on a join timeout keeps running until its own bounded
	// exit, and parks; until the owner reaps it (reap != Wait) the slot is off
	// limits, so a new call can never share a slot with an old rx task.
	inline bool rxSlotAllocatable(bool participantEmpty, bool tearingDown, ReapDecision reap)
	{
		return participantEmpty && !tearingDown && reap != ReapDecision::Wait;
	}

	// #608 review: a detached rx task counts toward the #65 restart only while it
	// is still alive. Reaping it takes it back out, or benign detaches add up and
	// the restart drops live calls. Returns the delta for the detach counter.
	inline int detachCountDeltaOnReap(bool& slotDetached)
	{
		if (!slotDetached) return 0;
		slotDetached = false;
		return -1;
	}

	// Issue #554 (b): a leg we dropped never gets a fresh rx task (and its POST)
	// from a late upsert. Bounded: the ring remembers the last N drops.
	template <std::size_t N, std::size_t Len>
	inline bool rxStartAllowedFor(const RecentIdRing<N, Len>& droppedLegs, std::string_view participantId)
	{
		return !droppedLegs.contains(participantId);
	}

	// #743: a 911/933 placed while a call slot is still tearing down (the
	// victim of a #624 pre-emption on the async anchor, or a call that ended a
	// moment before) finds no slot on makeCall()'s first ask: stopMediaStreams()
	// joins the old rx task for up to 2 s before it frees the slot, and a task
	// that outlives the join parks within one more 2 s client timeout. A leg
	// left unkeyed gets no rx pump, and its next upsert reads as a new inbound
	// call. So an emergency makeCall() keeps asking for 4 s (desmo, #878); an
	// ordinary call gets its one ask, as before. Bounded: a slot still held
	// after that is not waited on, and the 911 is refused (#821).
	inline constexpr int64_t kEmergencySlotWaitUs = 4'000'000;
	inline constexpr int     kEmergencySlotPollMs = 100;
	inline bool emergencySlotRetryContinues(bool emergency, bool primed, int64_t waitedUs)
	{
		return emergency && !primed && waitedUs < kEmergencySlotWaitUs;
	}
}

#endif // RX_RESTART_HPP
