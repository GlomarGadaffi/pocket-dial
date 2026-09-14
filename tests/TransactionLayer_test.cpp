// Tests for the RFC 3261 §17 INVITE client transaction layer
// (src/SIP/TransactionLayer.cpp), focused on the duplicate-tracking feedback
// loop behind issue #148.
//
// The loop, in the engine: sweep()'s Timer-A retransmit calls _env.enqueue(),
// which appends to RequestsHandler's _outbox; drainOutbox() then runs
// maybeTrack() over EVERY _outbox entry (issue #70 moved the scan there on
// purpose). Without a dedupe guard each retransmit registers a BRAND-NEW
// transaction for the same INVITE, which retransmits and registers again.
// On hardware that produced 23 "[tx] Timer B expired" lines for a single
// register-beep Call-ID plus "[tx] pool exhausted".
//
// These tests drive maybeTrack() directly rather than through RequestsHandler,
// which is what lets them re-feed the same INVITE deterministically.

#include <gtest/gtest.h>

#include <chrono>

#include "FakePbxEnv.hpp"
#include "TransactionLayer.hpp"

namespace
{
	constexpr const char* kBranch = "z9hG4bKbeep-148";

	std::shared_ptr<SipMessage> beepInvite(const sockaddr_in& to,
		const std::string& callId = "beep-call-id@192.168.1.10",
		const std::string& branch = kBranch)
	{
		const std::string raw =
			"INVITE sip:101@192.168.1.50:5060 SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.1.10:5060;branch=" + branch + "\r\n"
			"From: \"PocketDial\" <sip:pbx@192.168.1.10:5060>;tag=servertag\r\n"
			"To: <sip:101@192.168.1.10>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Content-Length: 0\r\n\r\n";
		return std::make_shared<SipMessage>(raw, to);
	}

	int countLogsContaining(const FakePbxEnv& env, const std::string& needle)
	{
		int n = 0;
		for (const auto& l : env.logs)
		{
			if (l.find(needle) != std::string::npos) ++n;
		}
		return n;
	}
}

TEST(TransactionLayer, ReTrackingTheSameInviteDoesNotClaimASecondSlot)
{
	// THE issue #148 regression. Feed the identical INVITE back in many more
	// times than the pool has slots -- exactly what drainOutbox() does with each
	// Timer-A retransmit -- and the layer must still own exactly one transaction.
	FakePbxEnv env;
	TransactionLayer tx(env);
	const sockaddr_in phone = FakePbxEnv::addr("192.168.1.50", 5060);

	for (int i = 0; i < POCKETDIAL_MAX_TRANSACTIONS + 16; ++i)
	{
		tx.maybeTrack(phone, beepInvite(phone));
	}

	EXPECT_EQ(countLogsContaining(env, "pool exhausted"), 0)
		<< "re-tracking one INVITE must not consume the transaction pool";

	// Drive past Timer B (32 s). Exactly one transaction => exactly one expiry.
	const auto t0 = std::chrono::steady_clock::now();
	tx.sweep(t0 + std::chrono::seconds(40));

	EXPECT_EQ(countLogsContaining(env, "Timer B expired"), 1)
		<< "one unanswered INVITE must produce exactly one Timer B expiry, "
		   "not one per duplicate tracker";
}

TEST(TransactionLayer, DistinctInvitesStillGetTheirOwnSlots)
{
	// The dedupe keys on Via branch + CSeq method, so genuinely different forks
	// (a ring-group fan-out sends one INVITE per member) must each be tracked.
	FakePbxEnv env;
	TransactionLayer tx(env);
	const sockaddr_in phone = FakePbxEnv::addr("192.168.1.50", 5060);

	tx.maybeTrack(phone, beepInvite(phone, "call-a@pbx", "z9hG4bK-aaa"));
	tx.maybeTrack(phone, beepInvite(phone, "call-b@pbx", "z9hG4bK-bbb"));
	tx.maybeTrack(phone, beepInvite(phone, "call-c@pbx", "z9hG4bK-ccc"));

	const auto t0 = std::chrono::steady_clock::now();
	tx.sweep(t0 + std::chrono::seconds(40));

	EXPECT_EQ(countLogsContaining(env, "Timer B expired"), 3)
		<< "three distinct branches are three transactions";
}

TEST(TransactionLayer, RetransmitsFollowRfc3261AndStopOnAProvisional)
{
	// With the dedupe in place the beep INVITE gets the RFC 3261 §17.1.1.2
	// schedule -- T1 doubling -- and a provisional stops it, rather than the
	// runaway resend the feedback loop produced.
	FakePbxEnv env;
	TransactionLayer tx(env);
	const sockaddr_in phone = FakePbxEnv::addr("192.168.1.50", 5060);
	tx.maybeTrack(phone, beepInvite(phone));

	const auto t0 = std::chrono::steady_clock::now();
	// Timer A doubles, and the next deadline is re-based on the SWEEP time rather
	// than the previous deadline, so the schedule drifts by however late each
	// sweep lands: fire at 600 ms (next 600+1000), 1700 ms (next 1700+2000),
	// 3800 ms. Three retransmits.
	tx.sweep(t0 + std::chrono::milliseconds(600));
	tx.sweep(t0 + std::chrono::milliseconds(1700));
	tx.sweep(t0 + std::chrono::milliseconds(3800));
	const size_t afterThree = env.sent.size();
	EXPECT_EQ(afterThree, 3u) << "T1 doubling: one resend per elapsed interval";

	// A 180 moves Calling -> Proceeding, which must stop retransmitting.
	const std::string ringing =
		"SIP/2.0 180 Ringing\r\n"
		"Via: SIP/2.0/UDP 192.168.1.10:5060;branch=" + std::string(kBranch) + "\r\n"
		"From: \"PocketDial\" <sip:pbx@192.168.1.10:5060>;tag=servertag\r\n"
		"To: <sip:101@192.168.1.10>;tag=phonetag\r\n"
		"Call-ID: beep-call-id@192.168.1.10\r\n"
		"CSeq: 1 INVITE\r\n"
		"Content-Length: 0\r\n\r\n";
	EXPECT_TRUE(tx.matchAndAdvance(std::make_shared<SipMessage>(ringing, phone)));

	tx.sweep(t0 + std::chrono::seconds(10));
	tx.sweep(t0 + std::chrono::seconds(20));
	EXPECT_EQ(env.sent.size(), afterThree)
		<< "a provisional response must stop Timer A retransmits";
}

TEST(TransactionLayer, FreeForCallIdStopsRetransmittingImmediately)
{
	// The other half of #148: a register-beep dialog has no Session, so nothing
	// used to call this for it. Once called, the slot must go quiet at once --
	// no further resends and no Timer B expiry.
	FakePbxEnv env;
	TransactionLayer tx(env);
	const sockaddr_in phone = FakePbxEnv::addr("192.168.1.50", 5060);
	auto inv = beepInvite(phone);
	tx.maybeTrack(phone, inv);

	const auto t0 = std::chrono::steady_clock::now();
	tx.sweep(t0 + std::chrono::milliseconds(600));
	ASSERT_EQ(env.sent.size(), 1u);

	// Take the Call-ID from the message itself rather than restating the literal,
	// so this asserts the same key the layer stored.
	const std::string callId(inv->getCallID());
	ASSERT_FALSE(callId.empty());
	tx.freeForCallId(callId);

	tx.sweep(t0 + std::chrono::seconds(5));
	tx.sweep(t0 + std::chrono::seconds(40));
	EXPECT_EQ(env.sent.size(), 1u) << "a freed transaction must not retransmit";
	EXPECT_EQ(countLogsContaining(env, "Timer B expired"), 0)
		<< "a freed transaction must not later report a timeout";
}
