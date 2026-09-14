#include "TransactionLayer.hpp"

#include <cstring>

#include "SipStatus.hpp"

TransactionLayer::SipTransaction::Type
TransactionLayer::classify(const std::shared_ptr<SipMessage>& msg)
{
	if (!msg || msg->getStatusInfo().has_value()) return SipTransaction::Type::None;
	if (msg->getType() == "INVITE") return SipTransaction::Type::InviteClient;
	return SipTransaction::Type::None;
}

void TransactionLayer::maybeTrack(const sockaddr_in& peer,
                                  const std::shared_ptr<SipMessage>& msg)
{
	if (classify(msg) == SipTransaction::Type::None) return;

	// An INVITE we are ALREADY tracking must never claim a SECOND slot.
	//
	// sweep()'s Timer-A retransmit re-enqueues the INVITE through _env.enqueue(),
	// which appends to RequestsHandler's _outbox — and drainOutbox() runs
	// maybeTrack() over EVERY _outbox entry (issue #70 moved the scan there
	// deliberately, so that anything appended during a pass still gets tracked).
	// Without this guard the two compose into a feedback loop: each retransmit is
	// registered as a brand-new transaction, which retransmits and registers
	// again — 1 -> 2 -> 4 -> ... until the pool is exhausted, every stranded slot
	// then logging its own Timer B against the SAME Call-ID.
	//
	// Observed on hardware (issue #148): one unanswered register-beep INVITE to a
	// Yealink T29 produced 23 "[tx] Timer B expired" lines for a single Call-ID
	// plus "[tx] pool exhausted", within ~60 s of boot. With this guard the beep
	// gets exactly one transaction and the RFC 3261 §17.1.1.2 retransmit schedule.
	const auto branchSv = msg->getViaBranch();
	const auto methodSv = msg->getCSeqMethod();
	if (!branchSv.empty())
	{
		for (const auto& tx : _pool)
		{
			if (tx.type == SipTransaction::Type::None) continue;
			if (branchSv != std::string_view(tx.viaBranch)) continue;
			if (!methodSv.empty() && methodSv != std::string_view(tx.cseqMethod)) continue;
			return;   // already tracked — that slot owns this INVITE's retransmission
		}
	}

	SipTransaction* slot = nullptr;
	for (auto& tx : _pool)
	{
		if (tx.type == SipTransaction::Type::None) { slot = &tx; break; }
	}
	if (!slot)
	{
		_env.log("[tx] pool exhausted — INVITE sent without retransmit tracking", true);
		return;
	}

	auto raw = msg->toString();
	auto now = std::chrono::steady_clock::now();
	constexpr uint32_t kT1ms     = 500;
	constexpr uint32_t kTimerBms = 64 * kT1ms; // 32 s

	slot->type          = SipTransaction::Type::InviteClient;
	slot->state         = SipTransaction::State::Calling;
	slot->peer          = peer;
	slot->msgTruncated  = (raw.size() >= sizeof(slot->msg));
	slot->msgLen        = raw.size() < sizeof(slot->msg) ? raw.size() : sizeof(slot->msg) - 1;
	std::memcpy(slot->msg, raw.data(), slot->msgLen);
	slot->msg[slot->msgLen] = '\0';

	auto branch = msg->getViaBranch();
	auto bLen   = branch.size() < sizeof(slot->viaBranch) ? branch.size() : sizeof(slot->viaBranch) - 1;
	std::memcpy(slot->viaBranch, branch.data(), bLen);
	slot->viaBranch[bLen] = '\0';

	auto method = msg->getCSeqMethod();
	auto mLen   = method.size() < sizeof(slot->cseqMethod) ? method.size() : sizeof(slot->cseqMethod) - 1;
	std::memcpy(slot->cseqMethod, method.data(), mLen);
	slot->cseqMethod[mLen] = '\0';

	auto callId = msg->getCallID();
	auto cLen   = callId.size() < sizeof(slot->callId) ? callId.size() : sizeof(slot->callId) - 1;
	std::memcpy(slot->callId, callId.data(), cLen);
	slot->callId[cLen] = '\0';

	slot->nextRetransmit     = now + std::chrono::milliseconds(kT1ms);
	slot->transactionTimeout = now + std::chrono::milliseconds(kTimerBms);
	slot->absorbDeadline     = {};
	slot->retransmitCount    = 0;
	slot->currentIntervalMs  = kT1ms;
}

bool TransactionLayer::matchAndAdvance(const std::shared_ptr<SipMessage>& msg)
{
	if (!msg) return false;
	auto viaBranch = msg->getViaBranch();
	if (viaBranch.empty()) return false;
	auto cseqMethod = msg->getCSeqMethod();

	bool matched = false;
	auto now = std::chrono::steady_clock::now();
	constexpr uint32_t kAbsorbWindowMs = 64 * 500; // Timer M (2xx, RFC 6026 §8.4) / Timer D (3xx-6xx, RFC 3261 §17.1.1.2) -- NOT Timer L (server-side); see hpp:65-72

	for (auto& tx : _pool)
	{
		if (tx.type == SipTransaction::Type::None) continue;
		if (viaBranch != std::string_view(tx.viaBranch)) continue;
		if (!cseqMethod.empty() && cseqMethod != std::string_view(tx.cseqMethod)) continue;

		matched = true;
		auto si = msg->getStatusInfo();
		if (!si.has_value()) continue;

		using Cls = PocketDial::SipStatusClass;
		switch (si->klass)
		{
			case Cls::Provisional:
				if (tx.state == SipTransaction::State::Calling)
					tx.state = SipTransaction::State::Proceeding;
				break;
			case Cls::Success:
				tx.state = SipTransaction::State::Accepted;
				tx.absorbDeadline = now + std::chrono::milliseconds(kAbsorbWindowMs);
				break;
			default:
				tx.state = SipTransaction::State::Completed;
				tx.absorbDeadline = now + std::chrono::milliseconds(kAbsorbWindowMs);
				break;
		}
	}
	return matched;
}

void TransactionLayer::sweep(std::chrono::steady_clock::time_point now)
{
	for (auto& tx : _pool)
	{
		if (tx.type == SipTransaction::Type::None) continue;

		if (tx.state == SipTransaction::State::Completed ||
		    tx.state == SipTransaction::State::Accepted)
		{
			if (now >= tx.absorbDeadline)
				tx.type = SipTransaction::Type::None;
			continue;
		}

		if (tx.state == SipTransaction::State::Calling &&
		    now >= tx.transactionTimeout)
		{
			_env.log(std::string("[tx] Timer B expired — INVITE for ") + tx.callId
				+ " timed out (no provisional response)", true);
			tx.type = SipTransaction::Type::None;
			continue;
		}

		if (tx.state == SipTransaction::State::Calling &&
		    now >= tx.nextRetransmit)
		{
			if (tx.msgLen > 0 && !tx.msgTruncated)
			{
				// messageFromPool takes its raw string by value — hand it the copy
				// straight off the transaction buffer instead of copying twice.
				auto retx = _env.messageFromPool(std::string(tx.msg, tx.msgLen), tx.peer);
				if (retx) _env.enqueue(tx.peer, std::move(retx));
			}
			tx.currentIntervalMs *= 2;
			tx.nextRetransmit     = now + std::chrono::milliseconds(tx.currentIntervalMs);
			tx.retransmitCount++;
		}
	}
}

void TransactionLayer::freeForCallId(std::string_view callId)
{
	for (auto& tx : _pool)
	{
		if (tx.type != SipTransaction::Type::None &&
		    std::string_view(tx.callId) == callId)
		{
			tx.type = SipTransaction::Type::None;
		}
	}
}
