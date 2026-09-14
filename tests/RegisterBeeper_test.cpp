// Wire-level tests for the register-beep UAC dialog (src/SIP/RegisterBeeper.cpp).
// The beep builds its INVITE/ACK/BYE by hand, so only a byte-level assertion
// catches header defects — the ACK used to stamp "To: " on top of getTo(), which
// already returns the full "To: ..." header line.

#include <gtest/gtest.h>

#include "FakePbxEnv.hpp"
#include "RegisterBeeper.hpp"

namespace
{
	// The phone's 200 OK to our beep INVITE, echoing the Call-ID we generated.
	std::shared_ptr<SipMessage> okFor(const std::string& callId, const sockaddr_in& from)
	{
		const std::string raw =
			"SIP/2.0 200 OK\r\n"
			"Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bKbeep\r\n"
			"From: \"PocketDial\" <sip:pbx@192.168.1.10:5060>;tag=servertag\r\n"
			"To: <sip:101@192.168.1.10>;tag=phonetag\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Content-Length: 0\r\n\r\n";
		return std::make_shared<SipMessage>(raw, from);
	}

	// Pull the Call-ID value out of the INVITE the beeper just sent.
	std::string callIdOf(const std::string& raw)
	{
		auto p = raw.find("Call-ID: ");
		if (p == std::string::npos) return {};
		p += 9;
		return raw.substr(p, raw.find("\r\n", p) - p);
	}
}

TEST(RegisterBeeper, AnsweredBeepAcksAndByesWithWellFormedHeaders)
{
	FakePbxEnv env;
	RegisterBeeper beeper(env);

	const sockaddr_in phoneAddr = FakePbxEnv::addr("192.168.1.50", 5060);
	beeper.sendBeep(std::make_shared<SipClient>("101", phoneAddr));

	ASSERT_EQ(env.sent.size(), 1u);
	const std::string invite = env.sentRaw(0);
	EXPECT_EQ(invite.rfind("INVITE sip:101@192.168.1.50:5060", 0), 0u) << invite;
	EXPECT_NE(invite.find("a=inactive"), std::string::npos) << invite;

	const std::string callId = callIdOf(invite);
	ASSERT_FALSE(callId.empty());

	// Phone auto-answers: expect ACK then BYE.
	EXPECT_TRUE(beeper.handleOk(okFor(callId, phoneAddr)));
	ASSERT_EQ(env.sent.size(), 3u);

	const std::string ack = env.sentRaw(1);
	EXPECT_EQ(ack.rfind("ACK sip:101@", 0), 0u) << ack;
	EXPECT_EQ(FakePbxEnv::countOf(ack, "To:"), 1) << ack;
	EXPECT_EQ(FakePbxEnv::countOf(ack, "From:"), 1) << ack;
	EXPECT_EQ(FakePbxEnv::countOf(ack, "Call-ID:"), 1) << ack;
	// The phone's tag must survive onto the ACK or the dialog does not match.
	EXPECT_NE(ack.find("tag=phonetag"), std::string::npos) << ack;
	EXPECT_NE(ack.find("Call-ID: " + callId + "\r\n"), std::string::npos) << ack;

	// The BYE is delegated to PbxEnv::serverBye (the engine's single server-BYE
	// builder), so assert on what the beeper handed it — asserting on the bytes
	// would only be testing FakePbxEnv's own stand-in for that builder.
	ASSERT_EQ(env.byeCalls.size(), 1u);
	const auto& bye = env.byeCalls[0];
	EXPECT_EQ(bye.destExt, "101");
	EXPECT_EQ(bye.callId, callId);                    // bare value, not the header line
	EXPECT_NE(bye.toHeader.find("tag=phonetag"), std::string::npos) << bye.toHeader;
	EXPECT_NE(bye.fromHeader.find("<sip:pbx@"), std::string::npos) << bye.fromHeader;
	EXPECT_NE(bye.fromHeader.find(";tag="), std::string::npos) << bye.fromHeader;
}

// Issue #148: a beep dialog has NO Session, so it never reaches endCall() — which
// used to be the only caller of TransactionLayer::freeForCallId(). Every terminal
// path must therefore release the INVITE transaction itself, or the beep keeps
// retransmitting to a phone we have already given up on, holding a pool slot for
// the rest of its 32 s Timer B window. Observed on hardware as a pool-exhaustion
// burst after a single unanswered beep.
TEST(RegisterBeeper, UnansweredBeepReleasesItsInviteTransaction)
{
	FakePbxEnv env;
	RegisterBeeper beeper(env);
	const sockaddr_in phoneAddr = FakePbxEnv::addr("192.168.1.50", 5060);

	beeper.sendBeep(std::make_shared<SipClient>("101", phoneAddr));
	ASSERT_EQ(env.sent.size(), 1u);
	const std::string callId = callIdOf(env.sentRaw(0));
	ASSERT_FALSE(callId.empty());
	EXPECT_TRUE(env.freedTransactionCallIds.empty())
		<< "nothing is released while the beep is still in flight";

	// Deadline passes with no answer: sweep CANCELs but deliberately keeps the
	// slot for the RFC 3261 §9.1 race window (issue #98) — still not released.
	const auto t0 = std::chrono::steady_clock::now();
	beeper.sweep(t0 + std::chrono::seconds(30));
	EXPECT_TRUE(env.freedTransactionCallIds.empty())
		<< "the CANCEL window must not release the transaction yet — a raced 200 "
		   "OK still has to be matchable";

	// The race window itself expires: now the dialog is genuinely abandoned and
	// the transaction must go with it.
	beeper.sweep(t0 + std::chrono::seconds(120));
	ASSERT_EQ(env.freedTransactionCallIds.size(), 1u)
		<< "an abandoned beep must free its INVITE transaction";
	EXPECT_EQ(env.freedTransactionCallIds[0], callId);
}

// The happy path frees it too: once the phone 200s our BYE the dialog is over.
TEST(RegisterBeeper, CompletedBeepReleasesItsInviteTransaction)
{
	FakePbxEnv env;
	RegisterBeeper beeper(env);
	const sockaddr_in phoneAddr = FakePbxEnv::addr("192.168.1.50", 5060);

	beeper.sendBeep(std::make_shared<SipClient>("101", phoneAddr));
	const std::string callId = callIdOf(env.sentRaw(0));
	ASSERT_TRUE(beeper.handleOk(okFor(callId, phoneAddr)));   // ACK + BYE

	// The phone's 200 to our BYE tears the dialog down for good.
	const std::string byeOk =
		"SIP/2.0 200 OK\r\n"
		"Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bKbye\r\n"
		"From: \"PocketDial\" <sip:pbx@192.168.1.10:5060>;tag=servertag\r\n"
		"To: <sip:101@192.168.1.10>;tag=phonetag\r\n"
		"Call-ID: " + callId + "\r\n"
		"CSeq: 2 BYE\r\n"
		"Content-Length: 0\r\n\r\n";
	EXPECT_TRUE(beeper.handleOk(std::make_shared<SipMessage>(byeOk, phoneAddr)));

	ASSERT_EQ(env.freedTransactionCallIds.size(), 1u);
	EXPECT_EQ(env.freedTransactionCallIds[0], callId);
}

// A 200 OK for an unknown Call-ID is not ours — handleOk must decline it so the
// engine goes on to its normal session lookup.
TEST(RegisterBeeper, ForeignOkIsNotConsumed)
{
	FakePbxEnv env;
	RegisterBeeper beeper(env);
	const sockaddr_in phoneAddr = FakePbxEnv::addr("192.168.1.50", 5060);

	EXPECT_FALSE(beeper.handleOk(okFor("not-a-beep-dialog@192.168.1.50", phoneAddr)));
	EXPECT_TRUE(env.sent.empty());
}

// Issue #98: RFC 3261 §9.1 lets a phone's 200 OK race an in-flight CANCEL past
// the point the CANCEL had any effect. sweep() must not free the slot the
// instant it sends the CANCEL, or that raced OK is unrecognized (a beep dialog
// has no Session) and never gets ACKed/BYEd.
TEST(RegisterBeeper, LateOkAfterSweepCancelStillGetsAckedAndByed)
{
	FakePbxEnv env;
	RegisterBeeper beeper(env);

	const sockaddr_in phoneAddr = FakePbxEnv::addr("192.168.1.50", 5060);
	const auto t0 = std::chrono::steady_clock::now();
	beeper.sendBeep(std::make_shared<SipClient>("101", phoneAddr));
	ASSERT_EQ(env.sent.size(), 1u);
	const std::string callId = callIdOf(env.sentRaw(0));
	ASSERT_FALSE(callId.empty());

	// No answer within the beep deadline: sweep() sends CANCEL.
	beeper.sweep(t0 + std::chrono::seconds(6));
	ASSERT_EQ(env.sent.size(), 2u);
	EXPECT_EQ(env.sentRaw(1).rfind("CANCEL sip:", 0), 0u) << env.sentRaw(1);

	// The phone's 200 OK to the original INVITE was already in flight and lands
	// right after — the race the CANCEL cannot prevent. It must still be ACKed
	// and BYEd, not silently dropped.
	EXPECT_TRUE(beeper.handleOk(okFor(callId, phoneAddr)));
	ASSERT_EQ(env.sent.size(), 4u);   // + ACK, + (BYE delegated to serverBye)

	const std::string ack = env.sentRaw(2);
	EXPECT_EQ(ack.rfind("ACK sip:101@", 0), 0u) << ack;
	EXPECT_NE(ack.find("tag=phonetag"), std::string::npos) << ack;
	EXPECT_NE(ack.find("Call-ID: " + callId + "\r\n"), std::string::npos) << ack;

	ASSERT_EQ(env.byeCalls.size(), 1u);
	EXPECT_EQ(env.byeCalls[0].callId, callId);
}

// Issue #104: buildCancel() draws a message from the pool, which can be spent
// under the same flood conditions that make an operator watch this log
// (Issue #101(A)). sweep() must not claim "cancelled" or advance to
// AwaitingCancelDone when nothing was actually sent — that would abandon the
// dialog in a half-cancelled limbo no later tick ever revisits. It must retry
// on a later tick instead, succeeding once pool pressure eases.
TEST(RegisterBeeper, SweepRetriesCancelWhenBuildCancelFailsUnderPoolPressure)
{
	FakePbxEnv env;
	RegisterBeeper beeper(env);

	const sockaddr_in phoneAddr = FakePbxEnv::addr("192.168.1.50", 5060);
	const auto t0 = std::chrono::steady_clock::now();
	beeper.sendBeep(std::make_shared<SipClient>("101", phoneAddr));
	ASSERT_EQ(env.sent.size(), 1u);
	const std::string callId = callIdOf(env.sentRaw(0));
	ASSERT_FALSE(callId.empty());

	// No answer within the beep deadline, but the message pool is exhausted:
	// buildCancel() returns nullptr. No CANCEL goes out, no "cancelled" log,
	// and the dialog must not move to AwaitingCancelDone (verified below: it is
	// still recognized as an in-flight beep dialog on the next sweep, i.e. it
	// was not silently freed either).
	env.messagePoolAvailable = false;
	beeper.sweep(t0 + std::chrono::seconds(6));
	EXPECT_EQ(env.sent.size(), 1u) << "no CANCEL should have been sent";
	ASSERT_FALSE(env.logs.empty());
	EXPECT_EQ(env.logs.back().find("cancelled"), std::string::npos) << env.logs.back();
	EXPECT_NE(env.logs.back().find("cancel build failed"), std::string::npos)
		<< env.logs.back();

	// Pool pressure eases; the next sweep tick must retry and succeed, proving
	// the dialog was left retryable rather than stuck forever.
	env.messagePoolAvailable = true;
	beeper.sweep(t0 + std::chrono::seconds(7));
	ASSERT_EQ(env.sent.size(), 2u);
	EXPECT_EQ(env.sentRaw(1).rfind("CANCEL sip:", 0), 0u) << env.sentRaw(1);
	EXPECT_NE(env.logs.back().find("cancelled"), std::string::npos) << env.logs.back();

	// The dialog is still tracked (now AwaitingCancelDone): a raced 200 OK is
	// still ACKed/BYEd, exactly like the non-pool-pressure path.
	EXPECT_TRUE(beeper.handleOk(okFor(callId, phoneAddr)));
	ASSERT_EQ(env.sent.size(), 4u);   // + ACK, + (BYE delegated to serverBye)
}

// Issue #104 follow-up: retrying forever is its own bug ("don't leave it stuck
// forever either"). If the message pool never recovers, sweep() must eventually
// give up and free the slot instead of retrying indefinitely.
TEST(RegisterBeeper, SweepGivesUpAndFreesSlotAfterSustainedPoolPressure)
{
	FakePbxEnv env;
	RegisterBeeper beeper(env);

	const sockaddr_in phoneAddr = FakePbxEnv::addr("192.168.1.50", 5060);
	const auto t0 = std::chrono::steady_clock::now();
	beeper.sendBeep(std::make_shared<SipClient>("101", phoneAddr));
	const std::string callId = callIdOf(env.sentRaw(0));
	ASSERT_FALSE(callId.empty());

	// Pool pressure never eases: every retry tick fails to build the CANCEL.
	env.messagePoolAvailable = false;
	auto t = t0 + std::chrono::seconds(6);
	for (int i = 0; i < 10; ++i)
	{
		beeper.sweep(t);
		t += std::chrono::seconds(1);
	}

	// No CANCEL was ever sent (pool never had a slot for it) ...
	EXPECT_EQ(env.sent.size(), 1u) << "only the original INVITE, never a CANCEL";
	// ... and sweep eventually gave up rather than retrying forever.
	ASSERT_FALSE(env.logs.empty());
	EXPECT_NE(env.logs.back().find("giving up"), std::string::npos) << env.logs.back();

	// The slot is free again: this now-stale Call-ID is no longer recognized,
	// exactly like the normal fallback-expiry path (SlotFreedByFallback...).
	EXPECT_FALSE(beeper.handleOk(okFor(callId, phoneAddr)));
}

// If nothing further ever arrives after the CANCEL (the CANCEL landed cleanly,
// or the response was simply lost), the slot must still be freed by the bounded
// fallback rather than lingering forever.
TEST(RegisterBeeper, SlotFreedByFallbackWhenNoResponseFollowsTheCancel)
{
	FakePbxEnv env;
	RegisterBeeper beeper(env);

	const sockaddr_in phoneAddr = FakePbxEnv::addr("192.168.1.50", 5060);
	const auto t0 = std::chrono::steady_clock::now();
	beeper.sendBeep(std::make_shared<SipClient>("101", phoneAddr));
	const std::string callId = callIdOf(env.sentRaw(0));

	beeper.sweep(t0 + std::chrono::seconds(6));    // sends CANCEL, arms the fallback
	beeper.sweep(t0 + std::chrono::seconds(12));   // fallback window elapses: slot freed

	// The slot is free again: a late/foreign OK for this now-stale Call-ID is no
	// longer recognized as ours.
	EXPECT_FALSE(beeper.handleOk(okFor(callId, phoneAddr)));
}
