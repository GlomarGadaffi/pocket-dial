// #199 root cause 1: the rest of RFC 3261 §17.
//
// TransactionLayer_test.cpp covers the INVITE CLIENT transaction (Timer A/B) and
// the issue #148 duplicate-tracking regression. This file covers everything that
// was missing around it: the non-INVITE CLIENT transaction (Timer E/F/K) and
// both SERVER transactions (Timer G/H/I/J/L, plus §13.3.1.4).
//
// Before this, classify() returned None for every response and for every
// non-INVITE request, so each PBX-originated BYE, NOTIFY, REFER-NOTIFY and
// CANCEL went out exactly once. One lost UDP datagram then leaked state
// permanently: a dropped BYE leaves a handset showing a live call for ever (the
// failure behind park retrieve, pickup, transfer splice, session-timer reap and
// register-beep teardown all needing workarounds), and a dropped NOTIFY freezes
// a BLF lamp until that extension's dialog state next happens to change.
//
// These tests drive the layer directly rather than through RequestsHandler,
// which is what lets them feed exact message sequences and step a clock.

#include <gtest/gtest.h>

#include <chrono>
#include <string>

#include "FakePbxEnv.hpp"
#include "TransactionLayer.hpp"

namespace
{
	const sockaddr_in kPhone = FakePbxEnv::addr("192.168.1.50", 5060);
	const sockaddr_in kOther = FakePbxEnv::addr("192.168.1.51", 5060);
	// Same IP as kPhone, different port — two handsets behind one address, the
	// case an IP-only endpoint comparison would conflate (#146 is this codebase's
	// documented history with exactly that class of bug).
	const sockaddr_in kSameIpOtherPort = FakePbxEnv::addr("192.168.1.50", 5062);

	const char* kCRLF = "\r\n";

	std::string line(const std::string& s) { return s + kCRLF; }

	// A request the PBX is SENDING (so `src` is where it is going — every
	// PBX-originated request is built with the destination as its source
	// address; see the authoredHere() note in TransactionLayer.hpp).
	std::shared_ptr<SipMessage> request(const std::string& method,
		const sockaddr_in& src, const std::string& branch = "z9hG4bK-req",
		const std::string& callId = "call-1@pbx", int cseq = 2)
	{
		const std::string raw =
			line(method + " sip:101@192.168.1.50:5060 SIP/2.0") +
			line("Via: SIP/2.0/UDP 192.168.1.10:5060;branch=" + branch) +
			line("From: <sip:pbx@192.168.1.10:5060>;tag=servertag") +
			line("To: <sip:101@192.168.1.10>;tag=phonetag") +
			line("Call-ID: " + callId) +
			line("CSeq: " + std::to_string(cseq) + " " + method) +
			line("Content-Length: 0") + kCRLF;
		return std::make_shared<SipMessage>(raw, src);
	}

	// A response. `src` is the address the message was cloned from: pass the
	// destination for one the PBX authored, and some other leg for a relay.
	std::shared_ptr<SipMessage> response(const std::string& statusLine,
		const std::string& cseqMethod, const sockaddr_in& src,
		const std::string& branch = "z9hG4bK-req",
		const std::string& callId = "call-1@pbx", int cseq = 2)
	{
		const std::string raw =
			line("SIP/2.0 " + statusLine) +
			line("Via: SIP/2.0/UDP 192.168.1.10:5060;branch=" + branch) +
			line("From: <sip:101@192.168.1.10>;tag=phonetag") +
			line("To: <sip:pbx@192.168.1.10:5060>;tag=servertag") +
			line("Call-ID: " + callId) +
			line("CSeq: " + std::to_string(cseq) + " " + cseqMethod) +
			line("Content-Length: 0") + kCRLF;
		return std::make_shared<SipMessage>(raw, src);
	}

	int logsContaining(const FakePbxEnv& env, const std::string& needle)
	{
		int n = 0;
		for (const auto& l : env.logs)
		{
			if (l.find(needle) != std::string::npos) ++n;
		}
		return n;
	}
}

// ── Non-INVITE client transaction (§17.1.2) ──────────────────────────────────

TEST(TxNonInviteClient, ByeIsRetransmittedInsteadOfBeingFireAndForget)
{
	// THE headline fix. A server-originated BYE used to be sent exactly once; if
	// that one datagram was lost, the handset kept showing a call the PBX had
	// already torn down, with nothing anywhere that would ever correct it.
	FakePbxEnv env;
	TransactionLayer tx(env);
	tx.maybeTrack(kPhone, request("BYE", kPhone));

	const auto t0 = std::chrono::steady_clock::now();
	// Timer E: T1 doubling. Each deadline is re-based on the sweep that fired it
	// (the layer schedules from `now`, not from the previous deadline), so this
	// steps the same way the existing Timer A test does.
	tx.sweep(t0 + std::chrono::milliseconds(600));    // 1st resend, next +1000
	tx.sweep(t0 + std::chrono::milliseconds(1700));   // 2nd resend, next +2000
	tx.sweep(t0 + std::chrono::milliseconds(3800));   // 3rd resend, next +4000 (T2)
	EXPECT_EQ(env.sent.size(), 3u) << "a BYE with no answer must be retransmitted";
	EXPECT_NE(env.sentRaw(0).find("BYE sip:"), std::string::npos)
		<< "what is retransmitted must be the BYE itself";
}

TEST(TxNonInviteClient, TimerEIntervalIsCappedAtT2)
{
	// §17.1.2.2: unlike Timer A, Timer E stops doubling at T2 (4 s). Uncapped it
	// would run 0.5/1/2/4/8/16 s and a 32 s Timer F window would buy about five
	// attempts instead of about ten — worst exactly when the network is worst.
	FakePbxEnv env;
	TransactionLayer tx(env);
	tx.maybeTrack(kPhone, request("NOTIFY", kPhone));

	const auto t0 = std::chrono::steady_clock::now();
	size_t previous = 0;
	for (int i = 1; i <= 6; ++i)
	{
		// A 4.1 s gap always clears a T2-capped interval; it would NOT clear an
		// uncapped one once the doubling passed 4 s.
		tx.sweep(t0 + std::chrono::milliseconds(600 + i * 4100));
		EXPECT_GT(env.sent.size(), previous) << "sweep " << i << " produced no resend";
		previous = env.sent.size();
	}
}

TEST(TxNonInviteClient, ProvisionalDoesNotStopRetransmitsAndFinalStartsTimerK)
{
	// §17.1.2.2 differs from the INVITE client here, and getting it wrong
	// re-creates the fire-and-forget hole for any peer that 100-Tryings a BYE and
	// then loses the 200: a provisional only CAPS the interval for a non-INVITE
	// client transaction, it does not stop retransmission the way a 1xx stops
	// Timer A.
	FakePbxEnv env;
	TransactionLayer tx(env);
	tx.maybeTrack(kPhone, request("BYE", kPhone));

	const auto t0 = std::chrono::steady_clock::now();
	tx.sweep(t0 + std::chrono::milliseconds(600));
	ASSERT_EQ(env.sent.size(), 1u);

	ASSERT_TRUE(tx.matchAndAdvance(response("100 Trying", "BYE", kPhone)));
	tx.sweep(t0 + std::chrono::milliseconds(5000));
	EXPECT_EQ(env.sent.size(), 2u)
		<< "a 100 Trying must NOT stop a non-INVITE client transaction retransmitting";

	// The final response does stop it, and opens Timer K (T4 = 5 s) rather than
	// the 32 s Timer D/M an INVITE client gets: a non-INVITE final is not
	// followed by an ACK that could still be in flight.
	ASSERT_TRUE(tx.matchAndAdvance(response("200 OK", "BYE", kPhone)));
	const auto atFinal = env.sent.size();
	tx.sweep(t0 + std::chrono::seconds(10));
	EXPECT_EQ(env.sent.size(), atFinal) << "a final response must stop Timer E";
	EXPECT_EQ(tx.activeClientTransactions(), 0u)
		<< "Timer K (T4 = 5 s) must have freed the slot well before 10 s";
}

TEST(TxNonInviteClient, TimerFGivesUpAndNamesTheMethod)
{
	FakePbxEnv env;
	TransactionLayer tx(env);
	tx.maybeTrack(kPhone, request("NOTIFY", kPhone));

	const auto t0 = std::chrono::steady_clock::now();
	tx.sweep(t0 + std::chrono::seconds(40));
	EXPECT_EQ(logsContaining(env, "Timer F expired"), 1);
	EXPECT_EQ(logsContaining(env, "NOTIFY"), 1)
		<< "the give-up log must name the method, so a stuck BLF lamp is diagnosable";
	EXPECT_EQ(tx.activeClientTransactions(), 0u);
}

TEST(TxNonInviteClient, AckAndKeepalivePingsAndRegisterAreNeverTracked)
{
	FakePbxEnv env;
	TransactionLayer tx(env);
	// §17.1.1.3: an ACK is never its own transaction. A retransmit timer on one
	// would put unmatched ACKs on the wire.
	tx.maybeTrack(kPhone, request("ACK", kPhone, "z9hG4bK-ack"));
	// A keepalive OPTIONS ping is a liveness probe: loss IS the signal, so
	// retransmitting defeats the feature it serves — and at one 32 s slot per
	// registered phone it would swamp the pool on its own.
	tx.maybeTrack(kPhone, request("OPTIONS", kPhone, "z9hG4bK-opt"));
	// SipRegistrationClient runs its own RFC 3261 §10.2 refresh/retry schedule.
	tx.maybeTrack(kPhone, request("REGISTER", kPhone, "z9hG4bK-reg"));

	EXPECT_EQ(tx.activeClientTransactions(), 0u);
	const auto t0 = std::chrono::steady_clock::now();
	tx.sweep(t0 + std::chrono::milliseconds(600));
	EXPECT_EQ(env.sent.size(), 0u) << "none of these three may ever be retransmitted";
}

// ── INVITE server transaction (§17.2.1, §13.3.1.4, RFC 6026 §7.1) ────────────

TEST(TxInviteServer, TwoHundredIsRetransmittedUntilAcked)
{
	// The missing server half of RFC 6026. A single dropped 200 OK permanently
	// fails a conference join, echo test, park or anchor call: the phone never
	// learns it was answered, and nothing here used to re-send it.
	FakePbxEnv env;
	TransactionLayer tx(env);
	tx.maybeTrack(kPhone, response("200 OK", "INVITE", kPhone));
	ASSERT_EQ(tx.activeServerTransactions(), 1u);

	const auto t0 = std::chrono::steady_clock::now();
	tx.sweep(t0 + std::chrono::milliseconds(600));
	tx.sweep(t0 + std::chrono::milliseconds(1700));
	EXPECT_EQ(env.sent.size(), 2u) << "§13.3.1.4: retransmit the 2xx until it is ACKed";
	EXPECT_NE(env.sentRaw(0).find("SIP/2.0 200 OK"), std::string::npos);
}

TEST(TxInviteServer, AnAckWithADifferentBranchStillStopsTheTwoHundred)
{
	// The trap this test exists for. §17.1.1.3: the ACK to a 2xx is a BRAND NEW
	// transaction carrying a DIFFERENT Via branch — confirmed against the real
	// pjsua captures in tests/interop/.logs/, where every ACK-to-2xx has a fresh
	// z9hG4bKPj… branch while its CSeq NUMBER matches the INVITE's. A
	// branch-keyed match would therefore never fire and the 2xx would keep
	// retransmitting for the full 32 s while the call was already up, which is
	// the exact case §13.3.1.4 exists for. The match is anchored on the CSeq
	// number plus the peer address, with branch-or-Call-ID as the second key.
	FakePbxEnv env;
	TransactionLayer tx(env);
	tx.maybeTrack(kPhone, response("200 OK", "INVITE", kPhone, "z9hG4bK-invite",
		"call-1@pbx", 7));

	const auto t0 = std::chrono::steady_clock::now();
	tx.sweep(t0 + std::chrono::milliseconds(600));
	ASSERT_EQ(env.sent.size(), 1u);

	auto ack = request("ACK", kPhone, "z9hG4bK-COMPLETELY-DIFFERENT", "call-1@pbx", 7);
	EXPECT_FALSE(tx.absorbRetransmittedRequest(ack))
		<< "an ACK must never be swallowed — onAck bridges media and completes splices";

	tx.sweep(t0 + std::chrono::seconds(5));
	tx.sweep(t0 + std::chrono::seconds(20));
	EXPECT_EQ(env.sent.size(), 1u) << "the ACK must have stopped the 2xx retransmit";
}

TEST(TxInviteServer, AnAckFromADifferentPortDoesNotStopTheTwoHundred)
{
	// Two handsets behind one address on different ports. An IP-only endpoint
	// comparison would let one phone's ACK silence the other phone's 200 OK.
	FakePbxEnv env;
	TransactionLayer tx(env);
	tx.maybeTrack(kPhone, response("200 OK", "INVITE", kPhone, "z9hG4bK-inv",
		"call-1@pbx", 7));

	const auto t0 = std::chrono::steady_clock::now();
	tx.sweep(t0 + std::chrono::milliseconds(600));
	ASSERT_EQ(env.sent.size(), 1u);

	tx.absorbRetransmittedRequest(
		request("ACK", kSameIpOtherPort, "z9hG4bK-other", "call-1@pbx", 7));

	tx.sweep(t0 + std::chrono::milliseconds(1700));
	EXPECT_EQ(env.sent.size(), 2u)
		<< "same IP but a different port is a different endpoint: the 2xx keeps going";
}

TEST(TxInviteServer, NonTwoXxRetransmitsOnTimerGThenAnAckConfirmsOnTimerI)
{
	// §17.2.1. The ACK to a NON-2xx is part of the INVITE transaction and carries
	// the SAME branch — the opposite of the 2xx case above, which is why the
	// matcher accepts either key rather than picking one.
	FakePbxEnv env;
	TransactionLayer tx(env);
	tx.maybeTrack(kPhone, response("486 Busy Here", "INVITE", kPhone, "z9hG4bK-inv"));

	const auto t0 = std::chrono::steady_clock::now();
	tx.sweep(t0 + std::chrono::milliseconds(600));
	tx.sweep(t0 + std::chrono::milliseconds(1700));
	EXPECT_EQ(env.sent.size(), 2u) << "Timer G retransmits a final non-2xx until ACKed";

	tx.absorbRetransmittedRequest(request("ACK", kPhone, "z9hG4bK-inv"));
	tx.sweep(t0 + std::chrono::seconds(3));
	EXPECT_EQ(env.sent.size(), 2u) << "the ACK stops Timer G";
	// Timer I is T4 (5 s), far shorter than the 32 s Timer L a 2xx gets.
	tx.sweep(t0 + std::chrono::seconds(10));
	EXPECT_EQ(tx.activeServerTransactions(), 0u) << "Timer I must have freed the slot";
}

TEST(TxInviteServer, TimerHGivesUpWhenNoAckEverArrives)
{
	FakePbxEnv env;
	TransactionLayer tx(env);
	tx.maybeTrack(kPhone, response("200 OK", "INVITE", kPhone));

	const auto t0 = std::chrono::steady_clock::now();
	tx.sweep(t0 + std::chrono::seconds(40));
	EXPECT_EQ(logsContaining(env, "no ACK for 2xx"), 1)
		<< "an unACKed 2xx must be reported, not silently abandoned";
	EXPECT_EQ(tx.activeServerTransactions(), 0u);
}

TEST(TxInviteServer, AProvisionalThenAFinalShareOneSlot)
{
	// 180 followed by 200 is ONE transaction changing state, not two. If the 200
	// claimed a second slot, the stale 180 would go on answering retransmitted
	// INVITEs after the call was already up.
	FakePbxEnv env;
	TransactionLayer tx(env);
	tx.maybeTrack(kPhone, response("180 Ringing", "INVITE", kPhone));
	EXPECT_EQ(tx.activeServerTransactions(), 1u);

	const auto t0 = std::chrono::steady_clock::now();
	// A provisional is never retransmitted on a timer (§17.2.1) — it is re-sent
	// only when the INVITE itself is retransmitted.
	tx.sweep(t0 + std::chrono::seconds(3));
	EXPECT_EQ(env.sent.size(), 0u) << "a 180 must not be put on a retransmit timer";

	tx.maybeTrack(kPhone, response("200 OK", "INVITE", kPhone));
	EXPECT_EQ(tx.activeServerTransactions(), 1u) << "still exactly one transaction";

	const auto t1 = std::chrono::steady_clock::now();
	tx.sweep(t1 + std::chrono::milliseconds(600));
	ASSERT_EQ(env.sent.size(), 1u);
	EXPECT_NE(env.sentRaw(0).find("200 OK"), std::string::npos)
		<< "the slot must now hold the 200, not the stale 180";
}

TEST(TxInviteServer, ItsOwnRetransmitComingBackDoesNotRearmTheTimers)
{
	// The #148 feedback loop wearing a server-side hat. resend() enqueues the
	// stored bytes, drainOutbox() hands them straight back to maybeTrack(), and
	// re-arming on that would reset Timer H on every tick — retransmitting for
	// ever and never expiring. Identical bytes mean nothing changed.
	FakePbxEnv env;
	TransactionLayer tx(env);
	tx.maybeTrack(kPhone, response("200 OK", "INVITE", kPhone));

	const auto t0 = std::chrono::steady_clock::now();
	for (int i = 0; i < 10; ++i)
	{
		tx.sweep(t0 + std::chrono::seconds(i * 4));
		// Exactly what the real drain does with whatever sweep() just enqueued.
		tx.maybeTrack(kPhone, response("200 OK", "INVITE", kPhone));
	}
	EXPECT_EQ(tx.activeServerTransactions(), 1u) << "no second slot may ever be claimed";

	tx.sweep(t0 + std::chrono::seconds(40));
	EXPECT_EQ(tx.activeServerTransactions(), 0u)
		<< "Timer H must still expire on schedule despite the re-tracking";
}

// ── The authored-vs-relayed boundary ─────────────────────────────────────────

TEST(TxRelayBoundary, ARelayedResponseGetsNoServerTransaction)
{
	// This engine is a forwarding proxy / forked-UAC hybrid, not a B2BUA, for
	// ordinary extension-to-extension calls: callee B's 200 OK reaches caller A
	// almost verbatim. B is the real UAS there and is already retransmitting that
	// 200 under its own transaction layer, so a timer here would put a SECOND
	// copy on the wire for every loss.
	//
	// A relayed response is recognisable because it was cloned from B's message
	// and still carries B's address, which is not where it is going.
	FakePbxEnv env;
	TransactionLayer tx(env);

	// Cloned from the callee (kOther), sent to the caller (kPhone) — a relay.
	tx.maybeTrack(kPhone, response("200 OK", "INVITE", kOther));
	EXPECT_EQ(tx.activeServerTransactions(), 0u)
		<< "a response we are only relaying must never be retransmitted by us";

	// Cloned from the requester's own request and sent back to them — authored.
	tx.maybeTrack(kPhone, response("200 OK", "INVITE", kPhone));
	EXPECT_EQ(tx.activeServerTransactions(), 1u);
}

TEST(TxRelayBoundary, OnlyHarmfulToRepeatMethodsGetANonInviteServerSlot)
{
	// A 32 s Timer J slot per response is only worth claiming where re-running
	// the handler on a duplicate does damage. REGISTER/OPTIONS/MESSAGE/SUBSCRIBE
	// are idempotent enough to simply re-process, and tracking them would swamp
	// the pool — REGISTER alone is the highest-volume method on the box.
	FakePbxEnv env;
	TransactionLayer tx(env);
	int branch = 0;
	auto track = [&](const char* method) {
		tx.maybeTrack(kPhone, response("200 OK", method, kPhone,
			"z9hG4bK-" + std::to_string(branch++)));
	};

	track("REGISTER"); track("OPTIONS"); track("MESSAGE"); track("SUBSCRIBE");
	EXPECT_EQ(tx.activeServerTransactions(), 0u);

	track("BYE"); track("CANCEL"); track("REFER"); track("UPDATE");
	EXPECT_EQ(tx.activeServerTransactions(), 4u);
}

// ── Absorbing retransmitted requests (§17.2.1 / §17.2.2) ─────────────────────

TEST(TxAbsorb, ARetransmittedRequestIsAnsweredFromTheCacheNotReprocessed)
{
	// Re-running the handler is what turns one lost packet into a second action:
	// a retransmitted REFER transfers the call twice.
	FakePbxEnv env;
	TransactionLayer tx(env);
	tx.maybeTrack(kPhone, response("202 Accepted", "REFER", kPhone, "z9hG4bK-ref"));
	ASSERT_EQ(tx.activeServerTransactions(), 1u);

	EXPECT_TRUE(tx.absorbRetransmittedRequest(request("REFER", kPhone, "z9hG4bK-ref")))
		<< "the caller must NOT dispatch this to the transfer handler a second time";
	ASSERT_EQ(env.sent.size(), 1u);
	EXPECT_NE(env.sentRaw(0).find("202 Accepted"), std::string::npos)
		<< "the stored response is what goes back";
}

TEST(TxAbsorb, AFirstArrivalIsNeverAbsorbed)
{
	FakePbxEnv env;
	TransactionLayer tx(env);
	EXPECT_FALSE(tx.absorbRetransmittedRequest(request("BYE", kPhone)))
		<< "nothing is tracked yet — this must reach the handler";
	EXPECT_EQ(env.sent.size(), 0u);
}

TEST(TxAbsorb, ADifferentCSeqOnTheSameBranchIsNotARetransmission)
{
	FakePbxEnv env;
	TransactionLayer tx(env);
	tx.maybeTrack(kPhone, response("200 OK", "UPDATE", kPhone, "z9hG4bK-u",
		"call-1@pbx", 4));

	// Same branch, next CSeq — a genuinely new request from a UA that reuses
	// branches. Absorbing it would silently swallow real traffic, which is the
	// worst thing this path could do.
	EXPECT_FALSE(tx.absorbRetransmittedRequest(
		request("UPDATE", kPhone, "z9hG4bK-u", "call-1@pbx", 5)));
	EXPECT_EQ(env.sent.size(), 0u);
}

TEST(TxAbsorb, ARequestFromADifferentPeerIsNotARetransmission)
{
	FakePbxEnv env;
	TransactionLayer tx(env);
	tx.maybeTrack(kPhone, response("200 OK", "BYE", kPhone, "z9hG4bK-b"));

	EXPECT_FALSE(tx.absorbRetransmittedRequest(request("BYE", kOther, "z9hG4bK-b")))
		<< "a branch collision from another endpoint must not be absorbed";
}

TEST(TxAbsorb, AnOversizedResponseIsNotAbsorbedSoTheHandlerStillRuns)
{
	// A response too large for the slot buffer is stored truncated and never
	// retransmitted — putting truncated SIP on the wire is worse than sending
	// nothing. The absorb path must then decline too: swallowing the request
	// while having nothing to answer with would be strictly worse than the
	// pre-existing behaviour of just re-processing it.
	FakePbxEnv env;
	TransactionLayer tx(env);

	const std::string padding(POCKETDIAL_TX_MSG_BYTES, 'x');
	const std::string raw =
		line("SIP/2.0 200 OK") +
		line("Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bK-big") +
		line("From: <sip:101@192.168.1.10>;tag=phonetag") +
		line("To: <sip:pbx@192.168.1.10:5060>;tag=servertag") +
		line("Call-ID: call-1@pbx") +
		line("CSeq: 2 BYE") +
		line("X-Padding: " + padding) +
		line("Content-Length: 0") + kCRLF;
	tx.maybeTrack(kPhone, std::make_shared<SipMessage>(raw, kPhone));

	EXPECT_EQ(logsContaining(env, "too large to retransmit"), 1)
		<< "lost retransmit coverage must be logged, never silent";
	EXPECT_FALSE(tx.absorbRetransmittedRequest(request("BYE", kPhone, "z9hG4bK-big")))
		<< "with nothing to answer with, fall through to the handler instead";
	EXPECT_EQ(env.sent.size(), 0u);
}

// ── Lifecycle ────────────────────────────────────────────────────────────────

TEST(TxLifecycle, FreeForCallIdStopsTheInviteButNotTheByeTearingItDown)
{
	// The subtle one. endCall() calls freeForCallId() for the dialog it is
	// tearing down — and the BYE doing the tearing down carries that very same
	// Call-ID. Freeing it here would cancel the retransmission that makes
	// teardown reliable, i.e. silently undo the entire point of this layer.
	// Non-INVITE client slots are bounded by their own Timer F/K, so leaving
	// them alone cannot leak.
	FakePbxEnv env;
	TransactionLayer tx(env);

	auto invite = request("INVITE", kPhone, "z9hG4bK-inv", "call-1@pbx", 1);
	tx.maybeTrack(kPhone, invite);
	tx.maybeTrack(kPhone, request("BYE", kPhone, "z9hG4bK-bye", "call-1@pbx", 2));
	ASSERT_EQ(tx.activeClientTransactions(), 2u);

	// Take the key off the message rather than restating the literal: getCallID()
	// yields the whole "Call-ID: …" line, header name included, and that is the
	// form endCall() passes through from data->getCallID().
	const std::string callId(invite->getCallID());
	ASSERT_FALSE(callId.empty());
	tx.freeForCallId(callId);
	EXPECT_EQ(tx.activeClientTransactions(), 1u) << "the INVITE goes, the BYE stays";

	const auto t0 = std::chrono::steady_clock::now();
	tx.sweep(t0 + std::chrono::milliseconds(600));
	ASSERT_EQ(env.sent.size(), 1u);
	EXPECT_NE(env.sentRaw(0).find("BYE sip:"), std::string::npos)
		<< "the surviving retransmit must be the BYE";

	// And it is still bounded — leaving it alone is not a leak.
	tx.sweep(t0 + std::chrono::seconds(40));
	EXPECT_EQ(tx.activeClientTransactions(), 0u) << "Timer F still ends it";
}

TEST(TxLifecycle, FreeForCallIdAlsoStopsAnInviteServerTransaction)
{
	FakePbxEnv env;
	TransactionLayer tx(env);
	auto ok = response("200 OK", "INVITE", kPhone, "z9hG4bK-s", "call-9@pbx", 3);
	tx.maybeTrack(kPhone, ok);
	ASSERT_EQ(tx.activeServerTransactions(), 1u);

	tx.freeForCallId(ok->getCallID());
	EXPECT_EQ(tx.activeServerTransactions(), 0u)
		<< "a torn-down dialog must stop retransmitting its own 2xx";
}

// ── The two rules that keep absorb from swallowing real traffic ──────────────

TEST(TxAbsorb, ASecondCallReusingABranchIsNotMistakenForARetransmission)
{
	// RFC 3261 §8.1.1.7 requires a unique branch per transaction, and §17.2.3's
	// match key is branch + sent-by + method on that basis — but real UAs are not
	// all careful, and tests/Rtp_test.cpp's own fixture hardcodes
	// `branch=z9hG4bK1` with `CSeq: 1` for every INVITE it builds. Without
	// Call-ID in the key, a phone's SECOND call would be answered with the FIRST
	// call's response and never reach the handler at all — a silently swallowed
	// call, the worst thing this path could do.
	FakePbxEnv env;
	TransactionLayer tx(env);
	tx.maybeTrack(kPhone, response("486 Busy Here", "INVITE", kPhone, "z9hG4bK1",
		"media-1", 1));

	EXPECT_FALSE(tx.absorbRetransmittedRequest(
		request("INVITE", kPhone, "z9hG4bK1", "media-2", 1)))
		<< "same branch and CSeq but a different Call-ID is a different call";
	EXPECT_EQ(env.sent.size(), 0u);

	// The genuine retransmission — everything identical — still absorbs.
	EXPECT_TRUE(tx.absorbRetransmittedRequest(
		request("INVITE", kPhone, "z9hG4bK1", "media-1", 1)));
	EXPECT_EQ(env.sent.size(), 1u);
}

TEST(TxAbsorb, AnInviteAlreadyAnsweredWithA2xxIsLeftToTheHandler)
{
	// A request arriving on an ESTABLISHED dialog is usually a re-INVITE
	// (hold/resume, §12.2), not a retransmission — and the two are distinguishable
	// only by the To-tag, which a stored RESPONSE cannot report. Absorbing one
	// would answer a hold with the original call-setup 200 OK and never run the
	// handler meant to decline or relay it (tests/ConferenceRoom_test.cpp's
	// "hold on a conference leg must be declined 488" is exactly that case).
	//
	// Nothing is lost by declining: §13.3.1.4's timer already retransmits the 2xx
	// until it is ACKed, which is the actual reliability fix.
	FakePbxEnv env;
	TransactionLayer tx(env);
	tx.maybeTrack(kPhone, response("200 OK", "INVITE", kPhone, "z9hG4bK-c", "conf", 1));
	ASSERT_EQ(tx.activeServerTransactions(), 1u);

	EXPECT_FALSE(tx.absorbRetransmittedRequest(
		request("INVITE", kPhone, "z9hG4bK-c", "conf", 1)))
		<< "an INVITE on a dialog we already 2xx'd belongs to the handler";
	EXPECT_EQ(env.sent.size(), 0u);

	// A non-2xx answer is the opposite: the phone IS stuck waiting on it, gets
	// nothing back today, and retransmits until its own Timer B.
	FakePbxEnv env2;
	TransactionLayer tx2(env2);
	tx2.maybeTrack(kPhone, response("180 Ringing", "INVITE", kPhone, "z9hG4bK-r", "ring", 1));
	EXPECT_TRUE(tx2.absorbRetransmittedRequest(
		request("INVITE", kPhone, "z9hG4bK-r", "ring", 1)));
	ASSERT_EQ(env2.sent.size(), 1u);
	EXPECT_NE(env2.sentRaw(0).find("180 Ringing"), std::string::npos)
		<< "the stored provisional is re-sent, which ends the phone's retransmits";
}

TEST(TxLifecycle, ServerAndClientPoolsDoNotStarveEachOther)
{
	// Separate pools are the point: a BLF NOTIFY burst filling the client pool
	// must not cost an authored 200 OK its retransmit coverage, and vice versa.
	FakePbxEnv env;
	TransactionLayer tx(env);

	for (int i = 0; i < POCKETDIAL_MAX_TRANSACTIONS + 4; ++i)
	{
		tx.maybeTrack(kPhone, request("NOTIFY", kPhone,
			"z9hG4bK-n" + std::to_string(i),
			"call-" + std::to_string(i) + "@pbx"));
	}
	EXPECT_EQ(tx.activeClientTransactions(),
		static_cast<size_t>(POCKETDIAL_MAX_TRANSACTIONS));
	EXPECT_GT(logsContaining(env, "client pool exhausted"), 0)
		<< "over-subscription must degrade loudly, not silently";

	tx.maybeTrack(kPhone, response("200 OK", "INVITE", kPhone, "z9hG4bK-srv"));
	EXPECT_EQ(tx.activeServerTransactions(), 1u)
		<< "a full client pool must not deny the server pool a slot";
}

TEST(TxLifecycle, TheLayerStaticFootprintIsVisibleHere)
{
	// Not a behavioural assertion — a tripwire. Every slot carries a
	// POCKETDIAL_TX_MSG_BYTES retransmit buffer, which makes this layer the
	// single largest fixed allocation the SIP engine makes. On the default S3R8
	// profile that lands in PSRAM with the rest of RequestsHandler; on a no-PSRAM
	// board (sdkconfig.defaults.esp32_constrained sets CONFIG_SPIRAM=n) it is
	// internal RAM. Anyone raising a pool count or the buffer size should see the
	// cost change HERE rather than discover it on the constrained build.
	constexpr size_t kSlots =
		POCKETDIAL_MAX_TRANSACTIONS + POCKETDIAL_MAX_SERVER_TRANSACTIONS;
	constexpr size_t kPerSlotCeiling = POCKETDIAL_TX_MSG_BYTES + 320;
	EXPECT_LE(sizeof(TransactionLayer), kSlots * kPerSlotCeiling)
		<< "sizeof(TransactionLayer) = " << sizeof(TransactionLayer)
		<< " across " << kSlots << " slots. If this grew on purpose, update the "
		   "per-slot cost in docs/SCALING.md in the same commit.";
}
