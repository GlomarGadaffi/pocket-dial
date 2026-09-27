#ifndef PARKED_TASK_REAP_HPP
#define PARKED_TASK_REAP_HPP

// Issue #535 (#572 review): when may the owner delete a media task that parks
// itself instead of self-deleting?
//
// Only when the task has provably stopped touching shared state: it has cleared
// its running flag (its last access to the object) AND the scheduler reports
// it suspended (it reached its park loop). Deleting it on a timeout instead can
// kill a task that still holds _slotMutex, or is mid-way on the other core --
// the #421 class of bug. Anything short of both conditions means WAIT: keep the
// handle, count it, and try again later; never force it.
//
// Pure, so the host suite pins the decision; RtpReceiver applies it on ESP.

namespace pd
{
	enum class ReapDecision
	{
		Nothing,   // no parked handle: the slot is free
		Reap,      // cleared its flag and is suspended: safe to delete now
		Wait,      // still running, or not yet suspended: do NOT delete
	};

	inline ReapDecision reapDecision(bool haveHandle, bool taskRunning, bool suspended)
	{
		if (!haveHandle) return ReapDecision::Nothing;
		if (!taskRunning && suspended) return ReapDecision::Reap;
		return ReapDecision::Wait;
	}
}

#endif // PARKED_TASK_REAP_HPP
