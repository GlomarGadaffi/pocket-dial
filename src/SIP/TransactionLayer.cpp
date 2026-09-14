#include "TransactionLayer.hpp"

#include <cstring>

#include "SipStatus.hpp"

namespace
{
	// RFC 3261 §17.1.1.1 timer base values, UDP.
	constexpr uint32_t kT1ms   = 500;    // RTT estimate
	constexpr uint32_t kT2ms   = 4000;   // max retransmit interval for non-INVITE / INVITE-server
	constexpr uint32_t kT4ms   = 5000;   // max duration a message lingers in the network
	constexpr uint32_t k64T1ms = 64 * kT1ms;  // 32 s — Timers B, D, F, H, J, L, M

	using Tp = std::chrono::steady_clock::time_point;

	// A zero time_point is the "this timer is not running" sentinel. It has to be
	// tested explicitly: `now >= Tp{}` is true for every real `now`, so a plain
	// deadline comparison on an unarmed timer would fire immediately.
	inline bool armed(const Tp& t) { return t != Tp{}; }

	inline Tp after(const Tp& now, uint32_t ms)
	{
		return now + std::chrono::milliseconds(ms);
	}

	// CSeq sequence number out of a full "CSeq: 101 INVITE" header line. 0 when
	// the header is absent or has no leading number — which never matches a real
	// CSeq, so a parse failure degrades to "this slot matches nothing" rather
	// than to a false match.
	uint32_t parseCSeqNum(std::string_view cseq)
	{
		size_t i = 0;
		while (i < cseq.size() && (cseq[i] < '0' || cseq[i] > '9')) ++i;
		uint32_t n = 0;
		bool any = false;
		for (; i < cseq.size() && cseq[i] >= '0' && cseq[i] <= '9'; ++i)
		{
			// Saturate rather than wrap: a 32-bit CSeq is already the RFC's
			// ceiling (2**31-1), and a wrapped value could alias a real one.
			if (n > (0xFFFFFFFFu - 9) / 10) return 0;
			n = n * 10 + static_cast<uint32_t>(cseq[i] - '0');
			any = true;
		}
		return any ? n : 0;
	}
}

bool TransactionLayer::sameEndpoint(const sockaddr_in& a, const sockaddr_in& b)
{
	return a.sin_addr.s_addr == b.sin_addr.s_addr && a.sin_port == b.sin_port;
}

bool TransactionLayer::authoredHere(const sockaddr_in& peer,
                                    const std::shared_ptr<SipMessage>& msg)
{
	// See the long note on the declaration in TransactionLayer.hpp. In one line:
	// a response cloned from the requester's own request still carries that
	// requester's address, so source == destination means we built this answer
	// ourselves; a response relayed from the far leg carries the far leg's
	// address instead.
	return sameEndpoint(msg->getSource(), peer);
}

void TransactionLayer::storeField(char* dst, size_t cap, std::string_view src)
{
	const size_t n = src.size() < cap ? src.size() : cap - 1;
	std::memcpy(dst, src.data(), n);
	dst[n] = '\0';
}

TransactionLayer::SipTransaction::Type
TransactionLayer::classify(const sockaddr_in& peer, const std::shared_ptr<SipMessage>& msg)
{
	using Type = SipTransaction::Type;
	if (!msg) return Type::None;

	if (msg->getStatusInfo().has_value())
	{
		// ── A response we are sending: we are the UAS, if we wrote it ─────────
		if (!authoredHere(peer, msg)) return Type::None;

		const auto method = msg->getCSeqMethod();
		if (method == "INVITE") return Type::InviteServer;

		// Non-INVITE server transactions cost a 32 s Timer J slot each and buy
		// nothing for an idempotent method, so they are restricted to the four
		// where re-running the handler on a duplicate does real damage: a doubled
		// REFER is a double transfer, a doubled BYE/CANCEL answers 481 for a
		// dialog we tore down cleanly, and a doubled UPDATE re-relays an offer.
		// See PoolConfig.hpp for why INFO is excluded despite the same argument.
		if (method == "BYE" || method == "CANCEL" ||
		    method == "REFER" || method == "UPDATE")
		{
			return Type::NonInviteServer;
		}
		return Type::None;
	}

	// ── A request we are sending: we are the UAC ─────────────────────────────
	const auto method = msg->getType();

	// §17.1.1.3: an ACK is never a transaction of its own. For a non-2xx it is
	// part of the INVITE client transaction; for a 2xx it is re-emitted only in
	// answer to a retransmitted 2xx. Either way, putting it on a retransmit timer
	// would emit unmatched ACKs.
	if (method == "ACK") return Type::None;

	if (method == "INVITE") return Type::InviteClient;

	// Excluded on purpose — see the header's "what this layer does NOT track".
	if (method == "OPTIONS")  return Type::None;  // keepalive probe: loss IS the signal
	if (method == "REGISTER") return Type::None;  // SipRegistrationClient owns its own retry

	return Type::NonInviteClient;
}

template <size_t N>
TransactionLayer::SipTransaction*
TransactionLayer::claimSlot(std::array<SipTransaction, N>& pool)
{
	for (auto& tx : pool)
	{
		if (tx.type == SipTransaction::Type::None) return &tx;
	}
	return nullptr;
}

void TransactionLayer::fillSlot(SipTransaction& slot, const sockaddr_in& peer,
                                const std::shared_ptr<SipMessage>& msg)
{
	const auto raw = msg->toString();

	slot.peer         = peer;
	slot.msgTruncated = (raw.size() >= sizeof(slot.msg));
	slot.msgLen       = slot.msgTruncated ? sizeof(slot.msg) - 1 : raw.size();
	std::memcpy(slot.msg, raw.data(), slot.msgLen);
	slot.msg[slot.msgLen] = '\0';

	if (slot.msgTruncated)
	{
		// Loud, because the consequence is silent: this message will never be
		// retransmitted, so whatever reliability the slot was claimed for is not
		// actually there. Logged at claim time rather than at the first missed
		// retransmit so it shows up even on a call that happens not to lose a
		// packet.
		_env.log(std::string("[tx] message too large to retransmit (")
			+ std::to_string(raw.size()) + " > " + std::to_string(sizeof(slot.msg))
			+ " bytes) — no retransmit coverage for " + std::string(msg->getCSeqMethod())
			+ " on " + std::string(msg->getCallID()), true);
	}

	storeField(slot.viaBranch,  sizeof(slot.viaBranch),  msg->getViaBranch());
	storeField(slot.cseqMethod, sizeof(slot.cseqMethod), msg->getCSeqMethod());
	storeField(slot.callId,     sizeof(slot.callId),     msg->getCallID());
	slot.cseqNum = parseCSeqNum(msg->getCSeq());

	slot.nextRetransmit     = Tp{};
	slot.transactionTimeout = Tp{};
	slot.absorbDeadline     = Tp{};
	slot.retransmitCount    = 0;
	slot.currentIntervalMs  = kT1ms;
}

void TransactionLayer::maybeTrack(const sockaddr_in& peer,
                                  const std::shared_ptr<SipMessage>& msg)
{
	const auto type = classify(peer, msg);
	if (type == SipTransaction::Type::None) return;

	const auto branchSv = msg->getViaBranch();
	// Without a branch there is no key to match a response or a retransmission
	// against later, so a slot would only ever time out. Not worth one.
	if (branchSv.empty()) return;

	const auto methodSv = msg->getCSeqMethod();
	const auto now      = std::chrono::steady_clock::now();
	const bool isServer = (type == SipTransaction::Type::InviteServer ||
	                       type == SipTransaction::Type::NonInviteServer);

	if (!isServer)
	{
		// ── CLIENT: an INVITE/BYE/NOTIFY/... we are ALREADY tracking must never
		// claim a SECOND slot.
		//
		// sweep()'s retransmit re-enqueues the request through _env.enqueue(),
		// which appends to RequestsHandler's _outbox — and drainOutbox() runs
		// maybeTrack() over EVERY _outbox entry (issue #70 moved the scan there
		// deliberately, so that anything appended during a pass still gets
		// tracked). Without this guard the two compose into a feedback loop: each
		// retransmit is registered as a brand-new transaction, which retransmits
		// and registers again — 1 -> 2 -> 4 -> ... until the pool is exhausted,
		// every stranded slot then logging its own Timer B against the SAME
		// Call-ID.
		//
		// Observed on hardware (issue #148): one unanswered register-beep INVITE
		// to a Yealink T29 produced 23 "[tx] Timer B expired" lines for a single
		// Call-ID plus "[tx] pool exhausted", within ~60 s of boot. With this
		// guard the beep gets exactly one transaction and the RFC 3261 §17.1.1.2
		// retransmit schedule.
		for (const auto& tx : _clientPool)
		{
			if (tx.type == SipTransaction::Type::None) continue;
			if (branchSv != std::string_view(tx.viaBranch)) continue;
			if (!methodSv.empty() && methodSv != std::string_view(tx.cseqMethod)) continue;
			return;   // already tracked — that slot owns this request's retransmission
		}

		auto* slot = claimSlot(_clientPool);
		if (!slot)
		{
			_env.log("[tx] client pool exhausted — " + std::string(msg->getType())
				+ " sent without retransmit tracking", true);
			return;
		}

		fillSlot(*slot, peer, msg);
		slot->type  = type;
		slot->state = (type == SipTransaction::Type::InviteClient)
			? SipTransaction::State::Calling   // §17.1.1.2
			: SipTransaction::State::Trying;   // §17.1.2.2
		slot->nextRetransmit     = after(now, kT1ms);   // Timer A / Timer E
		slot->transactionTimeout = after(now, k64T1ms); // Timer B / Timer F
		return;
	}

	// ── SERVER: unlike the client side, a second response for the same request
	// is NORMAL and must UPDATE the slot rather than be refused. A 180 followed
	// by a 200 is one transaction moving Proceeding -> Accepted, and the slot has
	// to end up holding the 200 — that is the message a retransmitted INVITE must
	// be answered with, and the one §13.3.1.4 says to retransmit until ACKed.
	SipTransaction* slot = nullptr;
	for (auto& tx : _serverPool)
	{
		if (tx.type == SipTransaction::Type::None) continue;
		if (branchSv != std::string_view(tx.viaBranch)) continue;
		if (!methodSv.empty() && methodSv != std::string_view(tx.cseqMethod)) continue;
		if (!sameEndpoint(peer, tx.peer)) continue;
		slot = &tx;
		break;
	}

	if (slot)
	{
		// Our OWN retransmit coming back around the loop. resend() enqueues the
		// stored bytes, drainOutbox() hands them straight back here, and re-arming
		// the timers on that would reset Timer H on every tick and retransmit for
		// ever — the #148 feedback loop wearing a server-side hat. Identical bytes
		// mean nothing changed, so there is nothing to re-arm.
		const auto raw = msg->toString();
		if (raw.size() == slot->msgLen &&
		    std::memcmp(raw.data(), slot->msg, slot->msgLen) == 0)
		{
			return;
		}
	}
	else
	{
		slot = claimSlot(_serverPool);
		if (!slot)
		{
			_env.log("[tx] server pool exhausted — response sent without "
				"retransmit/absorb tracking", true);
			return;
		}
	}

	fillSlot(*slot, peer, msg);
	slot->type = type;

	const auto si = msg->getStatusInfo();
	const bool provisional = si.has_value() &&
		si->klass == PocketDial::SipStatusClass::Provisional;
	const bool success = si.has_value() &&
		si->klass == PocketDial::SipStatusClass::Success;

	if (provisional)
	{
		// §17.2.1 / §17.2.2 Proceeding. A provisional is NOT retransmitted on a
		// timer — it is only re-sent when the request itself is retransmitted,
		// which absorbRetransmittedRequest() handles. So the slot exists purely
		// as a response cache until the final answer replaces it.
		slot->state = SipTransaction::State::Proceeding;
		return;
	}

	if (type == SipTransaction::Type::InviteServer)
	{
		if (success)
		{
			// §13.3.1.4 + RFC 6026 §7.1 Accepted: the 2xx is retransmitted by the
			// UAS core with T1 doubling capped at T2 until the ACK arrives, and
			// given up on at 64*T1. The ACK moves this to Timer L.
			slot->state             = SipTransaction::State::Accepted;
			slot->nextRetransmit    = after(now, kT1ms);
			slot->transactionTimeout = after(now, k64T1ms);
		}
		else
		{
			// §17.2.1 Completed: Timer G retransmits the final non-2xx, Timer H
			// gives up. The ACK moves this to Confirmed / Timer I.
			slot->state             = SipTransaction::State::Completed;
			slot->nextRetransmit    = after(now, kT1ms);   // Timer G
			slot->transactionTimeout = after(now, k64T1ms); // Timer H
		}
		return;
	}

	// §17.2.2 Completed: a non-INVITE server transaction never retransmits its
	// response on a timer. It just holds it for Timer J so a retransmitted
	// request is answered from the cache instead of re-running the handler.
	slot->state         = SipTransaction::State::Completed;
	slot->absorbDeadline = after(now, k64T1ms);   // Timer J
}

bool TransactionLayer::matchAndAdvance(const std::shared_ptr<SipMessage>& msg)
{
	if (!msg) return false;
	auto viaBranch = msg->getViaBranch();
	if (viaBranch.empty()) return false;
	auto cseqMethod = msg->getCSeqMethod();

	bool matched = false;
	auto now = std::chrono::steady_clock::now();

	for (auto& tx : _clientPool)
	{
		if (tx.type == SipTransaction::Type::None) continue;
		if (viaBranch != std::string_view(tx.viaBranch)) continue;
		if (!cseqMethod.empty() && cseqMethod != std::string_view(tx.cseqMethod)) continue;

		matched = true;
		auto si = msg->getStatusInfo();
		if (!si.has_value()) continue;

		using Cls = PocketDial::SipStatusClass;
		const bool invite = (tx.type == SipTransaction::Type::InviteClient);

		switch (si->klass)
		{
			case Cls::Provisional:
				if (invite)
				{
					// §17.1.1.2: a provisional moves Calling -> Proceeding and
					// STOPS Timer A outright.
					if (tx.state == SipTransaction::State::Calling)
					{
						tx.state = SipTransaction::State::Proceeding;
					}
					tx.nextRetransmit = Tp{};
				}
				else
				{
					// §17.1.2.2: a non-INVITE client keeps retransmitting in
					// Proceeding — the interval is merely capped at T2. Dropping
					// the retransmits here instead would re-create the
					// fire-and-forget hole for any peer that 100-Tryings a BYE
					// and then loses the 200.
					tx.state = SipTransaction::State::Proceeding;
					if (tx.currentIntervalMs > kT2ms) tx.currentIntervalMs = kT2ms;
				}
				break;

			case Cls::Success:
				tx.state          = SipTransaction::State::Accepted;
				tx.nextRetransmit = Tp{};
				tx.transactionTimeout = Tp{};
				// INVITE: Timer M (RFC 6026 §8.4), 64*T1. Non-INVITE: Timer K
				// (§17.1.2.2), T4 — a much shorter soak, because a non-INVITE
				// final response is not followed by an ACK that could still be
				// in flight.
				tx.absorbDeadline = after(now, invite ? k64T1ms : kT4ms);
				break;

			default:
				tx.state          = SipTransaction::State::Completed;
				tx.nextRetransmit = Tp{};
				tx.transactionTimeout = Tp{};
				// INVITE: Timer D, 32 s over UDP. Non-INVITE: Timer K, T4.
				tx.absorbDeadline = after(now, invite ? k64T1ms : kT4ms);
				break;
		}
	}
	return matched;
}

bool TransactionLayer::absorbRetransmittedRequest(const std::shared_ptr<SipMessage>& msg)
{
	if (!msg) return false;
	// Responses are the client half's business (matchAndAdvance).
	if (msg->getStatusInfo().has_value()) return false;

	const auto now    = std::chrono::steady_clock::now();
	const auto src    = msg->getSource();
	const auto branch = msg->getViaBranch();
	const auto method = msg->getCSeqMethod();
	const auto callId = msg->getCallID();
	const uint32_t cseqNum = parseCSeqNum(msg->getCSeq());

	if (method == "ACK")
	{
		// An ACK ends an INVITE server transaction's retransmission.
		//
		// Matching is deliberately not branch-only. §17.1.1.3: the ACK for a
		// NON-2xx is part of the INVITE transaction and carries the SAME branch,
		// but the ACK for a 2xx is a brand-new transaction with a DIFFERENT
		// branch — so a branch-keyed match would silently never stop a 2xx
		// retransmit, which is the exact case §13.3.1.4 exists for. The CSeq
		// NUMBER is what both forms share with their INVITE, so it anchors the
		// match, with branch-or-Call-ID as the second key and the peer address as
		// the third.
		for (auto& tx : _serverPool)
		{
			if (tx.type != SipTransaction::Type::InviteServer) continue;
			if (tx.cseqNum != cseqNum) continue;
			if (!sameEndpoint(src, tx.peer)) continue;
			const bool byBranch = !branch.empty() &&
				branch == std::string_view(tx.viaBranch);
			const bool byCallId = !callId.empty() &&
				callId == std::string_view(tx.callId);
			if (!byBranch && !byCallId) continue;

			tx.nextRetransmit     = Tp{};
			tx.transactionTimeout = Tp{};
			if (tx.state == SipTransaction::State::Accepted)
			{
				// RFC 6026 §7.1 Timer L: soak up ACK retransmissions for 64*T1.
				tx.absorbDeadline = after(now, k64T1ms);
			}
			else
			{
				// §17.2.1 Confirmed / Timer I: T4.
				tx.state          = SipTransaction::State::Confirmed;
				tx.absorbDeadline = after(now, kT4ms);
			}
			break;
		}
		// Never swallowed: onAck has real work to do (bridging media, completing
		// a transfer splice, clearing an anchor's ACK deadline).
		return false;
	}

	if (branch.empty()) return false;

	for (auto& tx : _serverPool)
	{
		if (tx.type != SipTransaction::Type::InviteServer &&
		    tx.type != SipTransaction::Type::NonInviteServer) continue;
		if (branch != std::string_view(tx.viaBranch)) continue;
		if (!method.empty() && method != std::string_view(tx.cseqMethod)) continue;
		if (tx.cseqNum != cseqNum) continue;
		// Call-ID is NOT part of RFC 3261 §17.2.3's match (branch + sent-by +
		// method), because a conformant branch is already globally unique. It is
		// compared anyway, because the cost of a false match here is silently
		// swallowing a real request — and not every UA generates branches as
		// carefully as §8.1.1.7 requires. A phone that reuses one across two
		// dialogs would otherwise have its second call answered with the first
		// call's response and never processed. Strictly narrowing: it can only
		// ever cause FEWER absorbs.
		if (callId != std::string_view(tx.callId)) continue;
		if (!sameEndpoint(src, tx.peer)) continue;

		// An INVITE we have already answered with a 2xx is deliberately NOT
		// absorbed.
		//
		// Two reasons. Reliability is already covered: §13.3.1.4 has the UAS core
		// retransmitting that 2xx on its own timer until the ACK arrives, which is
		// the actual fix for a dropped answer — absorbing adds nothing on top.
		// And a request arriving on an ESTABLISHED dialog is usually not a
		// retransmission at all but a re-INVITE (hold/resume, RFC 3261 §12.2),
		// distinguishable from a true retransmission only by its To-tag, which a
		// stored RESPONSE cannot tell us about. Absorbing one would answer a hold
		// request with the original call-setup 200 OK and never run the handler
		// that is supposed to decline or relay it.
		//
		// Leaving these to the TU keeps the pre-existing behaviour exactly: the
		// re-INVITE path in onInvite() handles the in-dialog case, and its older
		// "Task 2A" guard still silently drops a genuine retransmission. The
		// absorb therefore only adds re-answering where the phone is actually
		// stuck waiting — Proceeding (we sent a 180) and Completed (we sent a
		// final non-2xx) — which is precisely where today it gets nothing back
		// and retransmits until its own Timer B.
		if (tx.type == SipTransaction::Type::InviteServer &&
		    tx.state == SipTransaction::State::Accepted)
		{
			return false;
		}

		// Nothing to answer with. Fall through to the TU and let it re-process,
		// which is what this path did before the transaction layer existed —
		// strictly better than swallowing the request and sending nothing.
		if (tx.msgLen == 0 || tx.msgTruncated) return false;

		// §17.2.1 / §17.2.2: a retransmitted request is answered with the most
		// recent response, and the TU is NOT re-run.
		resend(tx);
		return true;
	}
	return false;
}

void TransactionLayer::resend(SipTransaction& tx)
{
	if (tx.msgLen == 0 || tx.msgTruncated) return;
	// messageFromPool takes its raw string by value — hand it the copy straight
	// off the transaction buffer instead of copying twice.
	auto retx = _env.messageFromPool(std::string(tx.msg, tx.msgLen), tx.peer);
	if (retx) _env.enqueue(tx.peer, std::move(retx));
}

void TransactionLayer::sweepOne(SipTransaction& tx, std::chrono::steady_clock::time_point now)
{
	if (tx.type == SipTransaction::Type::None) return;

	// A slot in its absorb window has already done its job and is only soaking up
	// duplicates (Timer D/M client-side, Timer I/J/L server-side). Nothing
	// retransmits while absorbing.
	if (armed(tx.absorbDeadline))
	{
		if (now >= tx.absorbDeadline) tx.type = SipTransaction::Type::None;
		return;
	}

	// Give-up timers: B (INVITE client), F (non-INVITE client), H (INVITE server
	// non-2xx), and the §13.3.1.4 64*T1 ceiling on 2xx retransmission.
	if (armed(tx.transactionTimeout) && now >= tx.transactionTimeout)
	{
		switch (tx.type)
		{
			case SipTransaction::Type::InviteClient:
				// Exact wording preserved: hardware logs and the #148 regression
				// test both key on this string.
				_env.log(std::string("[tx] Timer B expired — INVITE for ") + tx.callId
					+ " timed out (no provisional response)", true);
				break;
			case SipTransaction::Type::NonInviteClient:
				_env.log(std::string("[tx] Timer F expired — ") + tx.cseqMethod
					+ " for " + tx.callId + " got no response after 32 s", true);
				break;
			case SipTransaction::Type::InviteServer:
				if (tx.state == SipTransaction::State::Accepted)
				{
					// §13.3.1.4 says the UAS SHOULD then BYE the dialog. That is a
					// TU-level decision with its own teardown path, so this layer
					// reports it and stops rather than growing a second way to end
					// a call. Tracked as a follow-up on #199.
					_env.log(std::string("[tx] no ACK for 2xx on ") + tx.callId
						+ " after 32 s — giving up retransmitting (dialog may be "
						"half-open)", true);
				}
				else
				{
					_env.log(std::string("[tx] Timer H expired — final response for ")
						+ tx.callId + " never ACKed", true);
				}
				break;
			default:
				break;
		}
		tx.type = SipTransaction::Type::None;
		return;
	}

	if (!armed(tx.nextRetransmit) || now < tx.nextRetransmit) return;

	resend(tx);
	tx.retransmitCount++;

	// Timer A (INVITE client) doubles without a ceiling — §17.1.1.2 gives it no
	// T2 cap, because an INVITE's Timer B ends the whole thing at 32 s anyway.
	// Timers E and G are capped at T2 (§17.1.2.2 / §17.2.1).
	tx.currentIntervalMs *= 2;
	if (tx.type != SipTransaction::Type::InviteClient && tx.currentIntervalMs > kT2ms)
	{
		tx.currentIntervalMs = kT2ms;
	}
	tx.nextRetransmit = after(now, tx.currentIntervalMs);
}

void TransactionLayer::sweep(std::chrono::steady_clock::time_point now)
{
	for (auto& tx : _clientPool) sweepOne(tx, now);
	for (auto& tx : _serverPool) sweepOne(tx, now);
}

void TransactionLayer::freeForCallId(std::string_view callId)
{
	// INVITE transactions only — see the declaration's note. Freeing the
	// NonInviteClient slot that holds the BYE doing the tearing down would cancel
	// the retransmission that makes teardown reliable, which is the whole point
	// of this layer.
	for (auto& tx : _clientPool)
	{
		if (tx.type == SipTransaction::Type::InviteClient &&
		    std::string_view(tx.callId) == callId)
		{
			tx.type = SipTransaction::Type::None;
		}
	}
	for (auto& tx : _serverPool)
	{
		if (tx.type == SipTransaction::Type::InviteServer &&
		    std::string_view(tx.callId) == callId)
		{
			tx.type = SipTransaction::Type::None;
		}
	}
}

size_t TransactionLayer::activeClientTransactions() const
{
	size_t n = 0;
	for (const auto& tx : _clientPool)
	{
		if (tx.type != SipTransaction::Type::None) ++n;
	}
	return n;
}

size_t TransactionLayer::activeServerTransactions() const
{
	size_t n = 0;
	for (const auto& tx : _serverPool)
	{
		if (tx.type != SipTransaction::Type::None) ++n;
	}
	return n;
}
