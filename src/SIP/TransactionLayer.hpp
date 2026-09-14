#ifndef TRANSACTION_LAYER_HPP
#define TRANSACTION_LAYER_HPP

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <string_view>

#include "PbxEnv.hpp"
#include "PoolConfig.hpp"
#include "SipMessage.hpp"

// ── RFC 3261 §17 transaction layer ────────────────────────────────────────────
//
// Four transaction types, two pools:
//
//   CLIENT  (_clientPool) — something this PBX SENT as a request, and will
//           retransmit until answered:
//     InviteClient     §17.1.1  Timer A (T1 doubling, uncapped) / B (64*T1)
//                               / D (32 s) / M (RFC 6026 §8.4, 64*T1)
//     NonInviteClient  §17.1.2  Timer E (T1 doubling, capped at T2) / F (64*T1)
//                               / K (T4)
//
//   SERVER  (_serverPool) — a response this PBX AUTHORED, kept so a retransmitted
//           request gets the same answer instead of being re-processed, and (for
//           INVITE) retransmitted until it is ACKed:
//     InviteServer     §17.2.1  Timer G (T1 doubling, capped at T2) / H (64*T1)
//                               / I (T4), plus §13.3.1.4 2xx-retransmit-until-ACK
//                               and Timer L (RFC 6026 §7.1, 64*T1)
//     NonInviteServer  §17.2.2  Timer J (64*T1) — response cache only, no
//                               retransmit schedule
//
// Pool exhaustion → the message is still sent, just once, with no retransmit
// tracking. That is precisely the behaviour every one of these paths had before
// this layer existed, so running out of slots degrades to the old semantics
// rather than dropping anything.
//
// ── What this layer deliberately does NOT track ───────────────────────────────
//
// RELAYED responses. This engine is a forwarding proxy / forked-UAC hybrid, not
// a B2BUA, for ordinary extension-to-extension calls: callee B's 200 OK is
// passed through to caller A almost verbatim. B is the real UAS on that dialog
// and is already retransmitting its own 200 under its own transaction layer, so
// a timer here would retransmit a response we do not own — two copies on the
// wire for every loss. Only responses this PBX AUTHORED get a server
// transaction; see authoredHere() for how that is decided and why the test
// fails safe.
//
// ACK requests. An ACK is never a transaction of its own (§17.1.1.3): for a
// non-2xx it belongs to the INVITE client transaction, and for a 2xx it is
// re-emitted only in answer to a retransmitted 2xx. Retransmitting it on a timer
// would put unmatched ACKs on the wire.
//
// OPTIONS keepalive pings. The registrar pings each registered phone to notice
// dead ones (RequestsHandler::buildOptionsPing). Loss IS the signal there, so
// retransmitting would defeat the feature — and at MAX_CLIENTS phones × a 32 s
// Timer F slot each it would swamp the pool on its own.
//
// Outbound REGISTER. SipRegistrationClient runs its own RFC 3261 §10.2 refresh
// and retry schedule (_sendArmed/_sendAtMs) and hands back bytes rather than
// sending them; a second retry schedule layered on top would fight it.
//
// ── Timer granularity ─────────────────────────────────────────────────────────
//
// sweep() is driven from RequestsHandler::tick(), which self-throttles to 1 Hz,
// so a T1=500 ms first retransmit actually lands at ~1 s and the T4=5 s absorb
// timers at 5–6 s. This is pre-existing (Timer A has always had it) and is
// conservative under §17 — it puts FEWER retransmits on the wire, never more —
// so it is left alone here rather than re-architected. It is documented so the
// next reader does not file it as a bug.
//
// Locking: every method assumes the caller holds the engine's _mutex, matching
// the convention of the RequestsHandler code this was extracted from.
class TransactionLayer
{
public:
	explicit TransactionLayer(PbxEnv& env) : _env(env) {}

	// Register `msg` for retransmit/absorb coverage if it is something this PBX
	// owns. Called for each outbox entry just before a handle()/tick() pass
	// flushes it — the single choke point every deferred message passes through,
	// so coverage is structural rather than re-implemented at each flush site
	// (issue #70). `peer` is the destination, and is load-bearing for responses:
	// it is what distinguishes a response we authored from one we are relaying.
	void maybeTrack(const sockaddr_in& peer, const std::shared_ptr<SipMessage>& msg);

	// CLIENT half. Advance the state machine for any tracked client transaction
	// matching this response's Via branch + CSeq method. A 1xx moves Calling →
	// Proceeding (stops retransmitting); a 2xx → Accepted (Timer M), 3xx-6xx →
	// Completed (Timer D) — both absorb retransmissions for 32 s over UDP, which
	// is why one deadline field serves both. Returns true if a slot matched.
	bool matchAndAdvance(const std::shared_ptr<SipMessage>& msg);

	// SERVER half. Called for every inbound REQUEST before the TU handler runs.
	//
	// Returns true when `msg` is a retransmission of a request this PBX has
	// already answered: the stored response has been re-enqueued and the caller
	// MUST NOT dispatch the message to a handler. That is the whole point —
	// re-running the handler is what turns a retransmitted REFER into a double
	// transfer, a retransmitted INFO into a doubled DTMF digit, and a
	// retransmitted BYE into a 481 for a dialog we already tore down cleanly.
	//
	// Also consumes ACKs: an ACK matching an InviteServer transaction stops the
	// 2xx/non-2xx retransmit and moves the slot into its absorb window. ACKs are
	// NOT swallowed — onAck has real work to do — so this returns false for them.
	//
	// Deliberately a separate entry point from matchAndAdvance() rather than more
	// branches inside it: that function reports "a client slot matched" and sets
	// its flag before it even looks at whether the message is a response, so
	// overloading its return value with "and also, stop dispatching" would be a
	// trap for the next reader.
	bool absorbRetransmittedRequest(const std::shared_ptr<SipMessage>& msg);

	// Retransmit timed-out transactions and free completed/absorbed slots.
	void sweep(std::chrono::steady_clock::time_point now);

	// Stop INVITE transactions (client and server) for a call being torn down.
	//
	// Deliberately INVITE-only. A non-INVITE client transaction for this Call-ID
	// is almost always the BYE/CANCEL doing the tearing down, and freeing it here
	// would cancel the very retransmission that makes teardown reliable — the
	// dropped-BYE-leaves-a-handset-stuck failure this layer exists to fix. Those
	// slots are already bounded by their own Timer F (32 s give-up) and Timer K
	// (T4 absorb), so leaving them alone cannot leak.
	void freeForCallId(std::string_view callId);

	// Test/diagnostic accessors. Cheap linear scans over fixed arrays.
	size_t activeClientTransactions() const;
	size_t activeServerTransactions() const;

private:
	struct SipTransaction
	{
		enum class Type : uint8_t
		{
			None,
			InviteClient,
			NonInviteClient,
			InviteServer,
			NonInviteServer,
		};
		// Union of the four state machines' states. Calling/Trying are the two
		// initial client states (§17.1.1.2 / §17.1.2.2); Confirmed is INVITE-server
		// only (§17.2.1, post-ACK); Accepted is the RFC 6026 2xx state on both
		// sides.
		enum class State : uint8_t { Calling, Trying, Proceeding, Completed, Confirmed, Accepted };

		Type  type  = Type::None;
		State state = State::Calling;

		sockaddr_in peer{};
		char msg[POCKETDIAL_TX_MSG_BYTES]{}; // serialized bytes ready for retransmit
		size_t msgLen       = 0;
		bool   msgTruncated = false;

		char callId[128]{};    // Call-ID for freeForCallId() lifecycle linkage
		char viaBranch[72]{};  // z9hG4bK… branch param (primary matching key)
		char cseqMethod[12]{}; // "INVITE" etc. — disambiguates CANCEL sharing the branch
		uint32_t cseqNum = 0;  // CSeq sequence number — see the ACK note below

		std::chrono::steady_clock::time_point nextRetransmit{};     // Timer A/E/G
		std::chrono::steady_clock::time_point transactionTimeout{}; // Timer B/F/H
		// Absorb window for a transaction that has reached a final state and is
		// only waiting to soak up duplicates. Client side: Timer M on a 2xx (RFC
		// 6026 §8.4, the replacement text for RFC 3261 §17.1.1.2) or Timer D on a
		// 3xx-6xx — both 32 s over UDP. Server side: Timer I (T4) after an ACK for
		// a non-2xx, Timer L (RFC 6026 §7.1, 64*T1) after an ACK for a 2xx, or
		// Timer J (64*T1) for a non-INVITE server transaction. One field serves
		// all of them because a slot is only ever in one absorb state at a time.
		std::chrono::steady_clock::time_point absorbDeadline{};

		uint32_t retransmitCount   = 0;
		uint32_t currentIntervalMs = 500; // Timer A/E/G: starts at T1
	};

	// Which transaction — if any — this outbound message earns. `peer` is the
	// destination; see authoredHere().
	static SipTransaction::Type classify(const sockaddr_in& peer,
		const std::shared_ptr<SipMessage>& msg);

	// Did THIS PBX author `response`, or is it relaying one from the far leg?
	//
	// Every outbound response in this engine is built by cloning some other
	// message through getMessageFromPool(const SipMessage&), which carries the
	// clone source's `_src` — the address the bytes were parsed from — along with
	// it. That gives a clean discriminator:
	//
	//   authored : cloned from the REQUESTER'S OWN request, so _src == the
	//              destination.  (A's INVITE → we build 486/488/603, or the 200 OK
	//              for a virtual extension → we send it back to A.)
	//   relayed  : cloned from the FAR LEG'S response, so _src (B) != the
	//              destination (A).
	//
	// A message built from raw text carries whatever address its builder passed,
	// so an authoring site that passes something other than the destination reads
	// as "relayed" here. That direction is safe: it loses retransmit coverage the
	// path never had, rather than adding a retransmit for a response we do not
	// own. Unknown provenance therefore means "do not track", which is exactly
	// today's behaviour.
	static bool authoredHere(const sockaddr_in& peer, const std::shared_ptr<SipMessage>& msg);

	static bool sameEndpoint(const sockaddr_in& a, const sockaddr_in& b);

	// Copy `src` into a fixed char buffer, NUL-terminating and reporting overflow.
	static void storeField(char* dst, size_t cap, std::string_view src);

	// Claim a free slot in `pool`, or nullptr when every slot is busy.
	template <size_t N>
	static SipTransaction* claimSlot(std::array<SipTransaction, N>& pool);

	// Fill a freshly claimed slot from `msg`. Shared by all four types; the
	// caller sets type/state and arms the timers.
	void fillSlot(SipTransaction& slot, const sockaddr_in& peer,
		const std::shared_ptr<SipMessage>& msg);

	// Re-send a slot's stored bytes through the engine's outbox. No-op when the
	// message overflowed the slot buffer.
	void resend(SipTransaction& tx);

	// One sweep step for a single slot. Split out so sweep() reads as "walk both
	// pools" rather than one long nested loop.
	void sweepOne(SipTransaction& tx, std::chrono::steady_clock::time_point now);

	std::array<SipTransaction, POCKETDIAL_MAX_TRANSACTIONS>        _clientPool{};
	std::array<SipTransaction, POCKETDIAL_MAX_SERVER_TRANSACTIONS> _serverPool{};
	PbxEnv& _env;
};

#endif
