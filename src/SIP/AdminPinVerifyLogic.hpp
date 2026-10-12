#pragma once

// AdminPinVerifyLogic.hpp -- the hand-off of the DTMF admin PIN check to a worker
// task (#986 slice 3, Rule 5).
//
// The problem: a completed *PIN#code hashed the PIN (AdminAuth's 50000 software
// SHA-256 rounds, 2,872 ms on the S3) on whichever task was draining DTMF digits:
// the SIP receive task for a SIP INFO digit, the tick task for an RFC 4733 one.
// Both hold RequestsHandler::_mutex while they do, so a 911 INVITE that arrived in
// the window waited that long. Dropping the lock would not help, because the
// task would still be busy and answer nothing.
//
// The shape (the cdr_persist / NvsWriter one): the SIP side, still under _mutex,
// only copies what the check needs into one static slot and wakes the worker;
// the worker hashes with no lock held; tick() picks the result up under _mutex
// and does what the synchronous code did, in the same order.
//
//   submit()       SIP side, under _mutex. Refuses -- and counts nothing -- when a
//                  check is already running or waiting to be applied, when no PIN is
//                  set, when a lockout is engaged, or when an identity does not fit
//                  the slot. Otherwise the slot is Running.
//   workOnce()     worker. Running -> Done. No lock, no heap.
//   applyIfReady() tick(), under _mutex. Done -> the attempt and lockout accounting
//                  (AdminAuth::finishDtmfPinVerify), then `run`. The slot is Idle again
//                  after `run` returns, so a second entry cannot start mid-apply.
//
// Depth is one: the slot is Idle only between an apply and the next submit. A
// slot is never given up unseen -- a caller who hung up still has the accounting
// applied (a wrong PIN counts toward the lockout whether or not anyone is
// still listening); only `run` is told, and decides what a gone caller may do.
//
// The Executor is what wakes the worker: xTaskNotifyGive on the board, a counter on
// the host, where a test plays the worker with workOnce() itself. Nothing here includes
// FreeRTOS, so the host suite runs the policy the board runs.

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string_view>

#include "AdminAuth.hpp"

namespace adminpin
{
	// One digit more than the longest PIN, then the NUL: a longer entry cannot be the
	// PIN, and cut to this length it still is not (it differs from every PIN).
	constexpr size_t kPinCap = AdminAuth::kMaxDtmfPinLength + 2;
	constexpr size_t kCallIdCap = 128;   // DtmfPress::callId: a longer Call-ID is not tracked either
	constexpr size_t kExtCap = 65;       // an AOR (validAor) is at most 64

	struct Job
	{
		AdminAuth::DtmfPinTicket ticket;   // the stored salt and hash, as of submit
		char pin[kPinCap];                 // the candidate; wiped by the worker as soon as it is hashed
		char callId[kCallIdCap];           // who asked: the dialog ...
		char callerExt[kExtCap];           // ... and the extension, to check again at apply
		char code[4];                      // the three digits after '#', NUL-terminated
		char confirm;                      // the digit after them (factory reset), or 0
		bool matched;                      // the worker's answer
	};

	enum class Phase : uint8_t { Idle, Filling, Running, Done };

	enum class SubmitResult : uint8_t
	{
		Accepted,
		Busy,         // a check is running, or its result has not been applied yet
		NotRunning,   // the worker task never started (board only)
		TooLong,      // the Call-ID or extension does not fit the slot
		Refused,      // no PIN set, or locked out: AdminAuth said no before any hashing
	};

	// Wipes a buffer in a way the optimiser may not drop.
	template <size_t N>
	void scrub(char (&buf)[N])
	{
		volatile char* p = buf;
		for (size_t i = 0; i < N; ++i) p[i] = 0;
	}

	template <class Executor>
	class Handoff
	{
	public:
		explicit Handoff(Executor& ex) : _ex(ex) {}

		// `begin(DtmfPinTicket&) -> bool` is AdminAuth::beginDtmfPinVerify on the board
		// and in the product build; a test hands in a fake.
		template <class Begin>
		SubmitResult submit(std::string_view pin, std::string_view callId, std::string_view callerExt,
			std::string_view code, char confirm, Begin&& begin)
		{
			if (callId.size() >= kCallIdCap || callerExt.size() >= kExtCap || code.size() != 3)
			{
				return SubmitResult::TooLong;
			}
			Phase idle = Phase::Idle;
			if (!_phase.compare_exchange_strong(idle, Phase::Filling, std::memory_order_acq_rel))
			{
				return SubmitResult::Busy;
			}
			if (!begin(_job.ticket))
			{
				_phase.store(Phase::Idle, std::memory_order_release);
				return SubmitResult::Refused;
			}
			const size_t n = (std::min)(pin.size(), kPinCap - 1);   // parenthesised: windows.h defines min
			std::memcpy(_job.pin, pin.data(), n);
			_job.pin[n] = '\0';
			std::memcpy(_job.callId, callId.data(), callId.size());
			_job.callId[callId.size()] = '\0';
			std::memcpy(_job.callerExt, callerExt.data(), callerExt.size());
			_job.callerExt[callerExt.size()] = '\0';
			std::memcpy(_job.code, code.data(), 3);
			_job.code[3] = '\0';
			_job.confirm = confirm;
			_job.matched = false;
			_phase.store(Phase::Running, std::memory_order_release);
			_ex.wake();
			return SubmitResult::Accepted;
		}

		// The worker. `hash(const Job&) -> bool`: no lock may be held while it runs.
		// False when there was nothing to do.
		template <class Hash>
		bool workOnce(Hash&& hash)
		{
			if (_phase.load(std::memory_order_acquire) != Phase::Running)
			{
				return false;
			}
			_job.matched = hash(static_cast<const Job&>(_job));
			scrub(_job.pin);
			_phase.store(Phase::Done, std::memory_order_release);
			return true;
		}

		// tick(), under _mutex. `finish(ticket, matched) -> bool` is the accounting
		// (AdminAuth::finishDtmfPinVerify); `run(const Job&, bool authenticated)` acts on it.
		template <class Finish, class Run>
		bool applyIfReady(Finish&& finish, Run&& run)
		{
			if (_phase.load(std::memory_order_acquire) != Phase::Done)
			{
				return false;
			}
			const bool authenticated = finish(_job.ticket, _job.matched);
			run(static_cast<const Job&>(_job), authenticated);
			std::memset(&_job, 0, sizeof(_job));   // no Job{} temporary: this runs on the tick task's stack
			_phase.store(Phase::Idle, std::memory_order_release);
			return true;
		}

		Phase phase() const { return _phase.load(std::memory_order_acquire); }

		// Test seam: Idle again with the slot wiped. Nothing on the board calls it.
		void reset()
		{
			std::memset(&_job, 0, sizeof(_job));
			_phase.store(Phase::Idle, std::memory_order_release);
		}

	private:
		Executor& _ex;
		Job _job{};
		std::atomic<Phase> _phase{Phase::Idle};
	};
}
