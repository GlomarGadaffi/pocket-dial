// SipTrunk_test.cpp — issue #164: the outbound half of a generic ITSP SIP trunk.
//
// What is worth testing here is the WIRE FORMAT and the dialog bookkeeping, not
// the socket. A carrier that dislikes a request answers with a 4xx and nothing
// else to go on: no log, no explanation, often no retry. So the builders are
// static and pure, and these tests pin the bytes.
//
// Three RFC rules carry most of the risk, and each has a test that fails if the
// rule is broken rather than one that merely exercises the code:
//
//   §17.1.1.3  the ACK for a NON-2xx reuses the INVITE's branch. Get this wrong
//              and the carrier retransmits its failure until Timer H (~32 s).
//   §13.2.2.4  the ACK for a 2xx is a NEW transaction with a fresh branch, sent
//              to the dialog's remote target. Sending the §17.1.1.3 form here is
//              the classic "carrier keeps resending the 200 then drops the call".
//   §12.2.1.1  a BYE takes the NEXT CSeq, and needs both tags plus a route.
//
// The two ACK forms being genuinely different is the single easiest thing to get
// wrong in a trunk, so it gets an explicit contrast test rather than being left
// implied by two separate assertions.

#include <gtest/gtest.h>

#include <cstdio>
#include <string>
#include <vector>

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

#include "FakePbxEnv.hpp"
#include "SipTrunk.hpp"

namespace
{
	constexpr const char* kSbcIp = "203.0.113.5";     // RFC 5737 TEST-NET-3
	constexpr uint16_t    kSbcPort = 5060;

	sockaddr_in sbcAddr()
	{
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_addr.s_addr = inet_addr(kSbcIp);
		a.sin_port = htons(kSbcPort);
		return a;
	}

	SipTrunk::Config workingConfig()
	{
		SipTrunk::Config c;
		std::snprintf(c.host, sizeof(c.host), "%s", kSbcIp);
		c.port = kSbcPort;
		std::snprintf(c.fromUser, sizeof(c.fromUser), "%s", "15551230000");
		c.enabled = true;
		return c;
	}

	// A dialog filled in as placeCall() would leave it, but with fixed identifiers
	// so a builder's output can be compared byte for byte.
	SipTrunk::Dialog pinnedDialog()
	{
		SipTrunk::Dialog d;
		d.state        = SipTrunk::State::Trying;
		d.callID       = "abc123@192.168.1.10";
		d.branch       = "z9hG4bKinvite01";
		d.fromTag      = "ftag01";
		d.cseq         = 1;
		d.sbcIpPort    = std::string(kSbcIp) + ":5060";
		d.localIpPort  = "192.168.1.10:5060";
		d.destE164     = "+15551234567";
		d.fromUser     = "15551230000";
		return d;
	}

	bool hasLine(const std::string& msg, const std::string& line)
	{
		return msg.find("\r\n" + line + "\r\n") != std::string::npos
			|| msg.compare(0, line.size() + 2, line + "\r\n") == 0;
	}

	std::string firstLine(const std::string& msg)
	{
		const size_t e = msg.find("\r\n");
		return e == std::string::npos ? msg : msg.substr(0, e);
	}
}

// ── Configuration gating ─────────────────────────────────────────────────────

TEST(SipTrunkConfig, IncompleteConfigIsNotValid)
{
	SipTrunk::Config c;
	EXPECT_FALSE(c.valid()) << "a default-constructed config must never be usable";

	c.enabled = true;
	EXPECT_FALSE(c.valid()) << "enabled alone is not enough";

	std::snprintf(c.host, sizeof(c.host), "%s", kSbcIp);
	EXPECT_FALSE(c.valid()) << "a carrier needs an identity to authorise the call";

	std::snprintf(c.fromUser, sizeof(c.fromUser), "%s", "15551230000");
	EXPECT_TRUE(c.valid());

	c.enabled = false;
	EXPECT_FALSE(c.valid()) << "disabled must override a complete config";
}

TEST(SipTrunkConfig, UnconfiguredTrunkPlacesNoCall)
{
	FakePbxEnv env;
	SipTrunk trunk(env);

	EXPECT_FALSE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	EXPECT_TRUE(env.sent.empty()) << "nothing may reach the wire from an unconfigured trunk";
	EXPECT_EQ(trunk.activeDialogs(), 0u) << "a refused call must not consume a slot";
}

// ── INVITE ───────────────────────────────────────────────────────────────────

TEST(SipTrunkInvite, RequestUriAndToAreE164AtTheSbc)
{
	const auto d = pinnedDialog();
	const std::string inv = SipTrunk::buildInvite(d, "v=0\r\n");

	EXPECT_EQ(firstLine(inv), "INVITE sip:+15551234567@203.0.113.5:5060 SIP/2.0");
	EXPECT_TRUE(hasLine(inv, "To: <sip:+15551234567@203.0.113.5:5060>"));
	EXPECT_TRUE(hasLine(inv, "CSeq: 1 INVITE"));
}

// A number arriving without the leading '+' still goes out as E.164. Carriers
// route on the URI user part, and a bare 11-digit string is not the same
// request as +1... to most of them.
TEST(SipTrunkInvite, AddsThePlusWhenTheNumberLacksIt)
{
	auto d = pinnedDialog();
	d.destE164 = "15551234567";
	const std::string inv = SipTrunk::buildInvite(d, "v=0\r\n");
	EXPECT_EQ(firstLine(inv), "INVITE sip:+15551234567@203.0.113.5:5060 SIP/2.0");
}

// Contact is OUR address, never the SBC's. It is where the carrier sends the BYE
// when the far party hangs up first; pointing it at the SBC loses that BYE and
// the call stays up locally forever.
TEST(SipTrunkInvite, ContactPointsAtUsNotTheCarrier)
{
	const auto d = pinnedDialog();
	const std::string inv = SipTrunk::buildInvite(d, "v=0\r\n");

	EXPECT_TRUE(hasLine(inv, "Contact: <sip:15551230000@192.168.1.10:5060;transport=udp>"));
	EXPECT_EQ(inv.find("Contact: <sip:15551230000@203.0.113.5"), std::string::npos)
		<< "Contact must not advertise the carrier's own address back at it";
}

TEST(SipTrunkInvite, ContentLengthMatchesTheBodyBytes)
{
	const auto d = pinnedDialog();
	const std::string sdp = "v=0\r\no=- 0 0 IN IP4 192.168.1.10\r\ns=-\r\n";
	const std::string inv = SipTrunk::buildInvite(d, sdp);

	EXPECT_TRUE(hasLine(inv, "Content-Length: " + std::to_string(sdp.size())));
	// And the body really is the last thing on the wire, byte for byte. A wrong
	// Content-Length silently truncates the offer over UDP and earns a 400.
	ASSERT_GE(inv.size(), sdp.size());
	EXPECT_EQ(inv.substr(inv.size() - sdp.size()), sdp);
}

// ── ACK: the two forms are not interchangeable ───────────────────────────────

TEST(SipTrunkAck, FailureAckReusesTheInviteBranch)
{
	auto d = pinnedDialog();
	d.toTag = "carrier-tag";
	const std::string ack = SipTrunk::buildAckForFailure(d);

	EXPECT_NE(ack.find(";branch=z9hG4bKinvite01"), std::string::npos)
		<< "RFC 3261 s17.1.1.3: a non-2xx ACK belongs to the INVITE transaction";
	EXPECT_TRUE(hasLine(ack, "CSeq: 1 ACK")) << "same sequence number as the INVITE";
	EXPECT_TRUE(hasLine(ack, "To: <sip:+15551234567@203.0.113.5:5060>;tag=carrier-tag"));
	EXPECT_TRUE(hasLine(ack, "Content-Length: 0"));
}

TEST(SipTrunkAck, TwoXxAckUsesAFreshBranchAndTheRemoteTarget)
{
	auto d = pinnedDialog();
	d.toTag        = "carrier-tag";
	d.remoteTarget = "sip:+15551234567@203.0.113.99:5060";

	const std::string ack = SipTrunk::buildAckFor2xx(d, "z9hG4bKack99");

	EXPECT_EQ(firstLine(ack), "ACK sip:+15551234567@203.0.113.99:5060 SIP/2.0")
		<< "RFC 3261 s13.2.2.4: routed to the dialog's remote target";
	EXPECT_NE(ack.find(";branch=z9hG4bKack99"), std::string::npos);
	EXPECT_EQ(ack.find("z9hG4bKinvite01"), std::string::npos)
		<< "a 2xx ACK is a NEW transaction and must not reuse the INVITE branch";
	EXPECT_TRUE(hasLine(ack, "CSeq: 1 ACK"));
}

// The contrast, stated directly. If someone ever "simplifies" the two builders
// into one, exactly this assertion is what should stop them.
TEST(SipTrunkAck, TheTwoAckFormsDifferInBranchAndTarget)
{
	auto d = pinnedDialog();
	d.toTag        = "carrier-tag";
	d.remoteTarget = "sip:+15551234567@203.0.113.99:5060";

	const std::string onFailure = SipTrunk::buildAckForFailure(d);
	const std::string on2xx     = SipTrunk::buildAckFor2xx(d, "z9hG4bKack99");

	EXPECT_NE(onFailure, on2xx);
	EXPECT_NE(firstLine(onFailure), firstLine(on2xx)) << "different request-URI";
	EXPECT_NE(onFailure.find("z9hG4bKinvite01"), std::string::npos);
	EXPECT_NE(on2xx.find("z9hG4bKack99"), std::string::npos);
}

// A carrier that answers without a Contact still has to be ACKed — falling back
// to the SBC address is wrong-ish but reachable, whereas not acking at all loses
// the call outright.
TEST(SipTrunkAck, TwoXxAckFallsBackToTheSbcWhenNoContactWasOffered)
{
	auto d = pinnedDialog();
	d.toTag = "carrier-tag";   // remoteTarget deliberately left empty

	const std::string ack = SipTrunk::buildAckFor2xx(d, "z9hG4bKack99");
	EXPECT_EQ(firstLine(ack), "ACK sip:+15551234567@203.0.113.5:5060 SIP/2.0");
}

// ── BYE ──────────────────────────────────────────────────────────────────────

TEST(SipTrunkBye, TakesTheNextCseqAndRoutesToTheRemoteTarget)
{
	auto d = pinnedDialog();
	d.toTag        = "carrier-tag";
	d.remoteTarget = "sip:+15551234567@203.0.113.99:5060";
	d.cseq         = 1;

	const std::string bye = SipTrunk::buildBye(d, "z9hG4bKbye77");

	EXPECT_EQ(firstLine(bye), "BYE sip:+15551234567@203.0.113.99:5060 SIP/2.0");
	EXPECT_TRUE(hasLine(bye, "CSeq: 2 BYE")) << "RFC 3261 s12.2.1.1: next sequence number";
	EXPECT_TRUE(hasLine(bye, "To: <sip:+15551234567@203.0.113.5:5060>;tag=carrier-tag"));
	EXPECT_TRUE(hasLine(bye, "From: <sip:15551230000@203.0.113.5:5060>;tag=ftag01"));
}

// Refusing to build a half-formed BYE is the feature. One sent without a To-tag
// earns a 481 while the call stays up and billing, which is the worst outcome
// available.
TEST(SipTrunkBye, RefusesToBuildWithoutBothTagsAndARoute)
{
	auto noTag = pinnedDialog();
	noTag.remoteTarget = "sip:x@203.0.113.99:5060";
	EXPECT_TRUE(SipTrunk::buildBye(noTag, "z9hG4bKbye77").empty()) << "no To-tag";

	auto noTarget = pinnedDialog();
	noTarget.toTag = "carrier-tag";
	EXPECT_TRUE(SipTrunk::buildBye(noTarget, "z9hG4bKbye77").empty()) << "no remote target";

	auto ok = pinnedDialog();
	ok.toTag        = "carrier-tag";
	ok.remoteTarget = "sip:x@203.0.113.99:5060";
	EXPECT_FALSE(SipTrunk::buildBye(ok, "z9hG4bKbye77").empty());
}

// ── Dialog lifecycle through the engine ──────────────────────────────────────

TEST(SipTrunkDialog, PlaceCallSendsOneInviteAndHoldsOneSlot)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(workingConfig());

	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	ASSERT_EQ(env.sent.size(), 1u);
	EXPECT_EQ(firstLine(env.sentRaw(0)).substr(0, 6), "INVITE");
	EXPECT_EQ(trunk.activeDialogs(), 1u);

	// The handset leg can find the trunk leg and vice versa — a teardown may name
	// either.
	EXPECT_TRUE(trunk.ownsCallID("handset-1"));
}

// The slot cap refuses rather than queues. An outbound PSTN call that cannot be
// placed must fail now, not wait somewhere the caller cannot see.
TEST(SipTrunkDialog, RefusesBeyondTheSlotCapWithoutSending)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(workingConfig());

	for (int i = 0; i < POCKETDIAL_MAX_TRUNK_CALLS; ++i)
	{
		ASSERT_TRUE(trunk.placeCall("+1555123456" + std::to_string(i),
			"handset-" + std::to_string(i), sbcAddr(), 40000))
			<< "slot " << i << " should have been available";
	}
	const size_t sentBefore = env.sent.size();

	EXPECT_FALSE(trunk.placeCall("+15559999999", "handset-overflow", sbcAddr(), 40000));
	EXPECT_EQ(env.sent.size(), sentBefore) << "a refused call must put nothing on the wire";
	EXPECT_EQ(trunk.activeDialogs(), static_cast<size_t>(POCKETDIAL_MAX_TRUNK_CALLS));
}

TEST(SipTrunkDialog, SweepReclaimsADialogThatNeverGotAFinalResponse)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(workingConfig());

	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	ASSERT_EQ(trunk.activeDialogs(), 1u);

	// Well inside the 60 s budget: a PSTN leg routinely rings past 20 s before
	// carrier voicemail answers, and cutting it short is a real bug this codebase
	// has already shipped once on the anchor path.
	trunk.sweep(std::chrono::steady_clock::now() + std::chrono::seconds(30));
	EXPECT_EQ(trunk.activeDialogs(), 1u) << "30 s must not time out a ringing PSTN call";

	trunk.sweep(std::chrono::steady_clock::now() + std::chrono::seconds(61));
	EXPECT_EQ(trunk.activeDialogs(), 0u);
}

TEST(SipTrunkDialog, HangupOnAnUnknownCallIdDoesNothing)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(workingConfig());

	EXPECT_FALSE(trunk.hangup("no-such-call"));
	EXPECT_TRUE(env.sent.empty());
}

// ── Responses to our BYE ─────────────────────────────────────────────────────
//
// These exist because a second reader found the gap by reading the diff, not
// because a test failed: the 3xx-6xx branch had no Terminating check, so a
// carrier refusing our BYE fell through to the INVITE failure path and got an
// ACK it should never have been sent. Both BYE outcomes are pinned now.

namespace
{
	// Build a response the way the engine would. Uses a plain SipMessage rather
	// than RequestsHandler's pool so this file keeps its light include set --
	// SipTrunk itself only ever sees messages through PbxEnv.
	std::shared_ptr<SipMessage> responseFor(const std::string& raw)
	{
		return std::make_shared<SipMessage>(raw, sbcAddr());
	}

	std::string okFor(const SipTrunk::Dialog& d)
	{
		return
			"SIP/2.0 200 OK\r\n"
			"Via: SIP/2.0/UDP 192.168.1.10:5060;branch=" + d.branch + "\r\n"
			"From: <sip:15551230000@" + d.sbcIpPort + ">;tag=" + d.fromTag + "\r\n"
			"To: <sip:" + d.destE164 + "@" + d.sbcIpPort + ">;tag=carrier-tag\r\n"
			"Call-ID: " + d.callID + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Contact: <sip:" + d.destE164 + "@203.0.113.99:5060>\r\n"
			"Content-Length: 0\r\n\r\n";
	}
}

TEST(SipTrunkBye, ANonTwoXxAnsweringOurByeIsNotAcked)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(workingConfig());

	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	ASSERT_NE(d, nullptr);

	ASSERT_TRUE(trunk.handleResponse(responseFor(okFor(*d))));   // answered
	ASSERT_TRUE(trunk.hangup("handset-1"));                      // BYE sent
	const size_t sentAfterBye = env.sent.size();

	// The carrier refuses the BYE for a dialog it has already dropped.
	std::string notFound = okFor(*trunk.findByCallID("handset-1"));
	notFound.replace(0, notFound.find("\r\n"), "SIP/2.0 481 Call/Transaction Does Not Exist");
	ASSERT_TRUE(trunk.handleResponse(responseFor(notFound)));

	// RFC 3261 s17.1.2: a BYE is a non-INVITE transaction and absorbs its own
	// final response. Nothing may go on the wire.
	EXPECT_EQ(env.sent.size(), sentAfterBye)
		<< "a non-2xx to a BYE must not be ACKed -- that ACK would carry the "
		   "INVITE's CSeq for a transaction that completed at answer time";
	EXPECT_EQ(trunk.activeDialogs(), 0u) << "the dialog is over either way";
}

// The inverse, so the test above cannot pass for the wrong reason: a non-2xx to
// the INVITE *is* still ACKed, in the INVITE's own transaction.
TEST(SipTrunkBye, ANonTwoXxAnsweringTheInviteIsStillAcked)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(workingConfig());

	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	ASSERT_NE(d, nullptr);
	const std::string branch = d->branch;

	std::string busy = okFor(*d);
	busy.replace(0, busy.find("\r\n"), "SIP/2.0 486 Busy Here");
	ASSERT_TRUE(trunk.handleResponse(responseFor(busy)));

	ASSERT_EQ(env.sent.size(), 2u) << "INVITE then its ACK";
	const std::string ack = env.sentRaw(1);
	EXPECT_EQ(ack.substr(0, 3), "ACK");
	EXPECT_NE(ack.find(";branch=" + branch), std::string::npos)
		<< "RFC 3261 s17.1.1.3: same branch as the INVITE";
	EXPECT_EQ(trunk.activeDialogs(), 0u);
}

// ── Listener: how the engine learns a dialog moved (#164 wiring) ─────────────
//
// The B2BUA wiring hangs entirely off these four callbacks, so what matters is
// not that they fire but WHEN, relative to the wire and to the slot's lifetime.
// Two orderings are load-bearing and each has a test that fails if it is broken:
//
//   * answered fires AFTER the ACK is enqueued. A listener that dislikes the
//     answer's SDP hangs up from inside the callback, and BYE-before-ACK is a
//     sequence carriers reject.
//   * failed fires AFTER the slot is released, so the listener can place a
//     replacement call from inside it. The event's string views still have to
//     be readable at that point, which is the part a naive "reset then fire"
//     gets wrong.

namespace
{
	// Records what fired, in order, and copies the views immediately -- which
	// is also what a real listener must do, so this doubles as a check that the
	// views are readable for the callback's duration.
	struct RecordingListener : SipTrunk::Listener
	{
		struct Event
		{
			std::string kind;
			std::string trunkCallID;
			std::string handsetCallID;
			uint16_t    localRtpPort = 0;
			int         status = 0;
			bool        earlyMedia = false;
		};

		std::vector<Event> events;
		SipTrunk*          trunk = nullptr;      // set to exercise re-entrancy
		bool               hangupOnAnswer = false;
		size_t             dialogsSeenDuringFailure = SIZE_MAX;
		// Sampled INSIDE onTrunkAnswered. Checking env.sent AFTER handleResponse
		// returns would pass whether the ACK went out before or after the
		// callback, which is the whole property under test.
		const FakePbxEnv*  env = nullptr;
		size_t             sentAtAnswerTime = SIZE_MAX;

		void record(const char* kind, const SipTrunk::TrunkEvent& ev)
		{
			events.push_back(Event{ kind, std::string(ev.trunkCallID),
				std::string(ev.handsetCallID), ev.localRtpPort, 0, false });
		}

		void onTrunkRinging(const SipTrunk::TrunkEvent& ev, bool earlyMedia) override
		{
			record("ringing", ev);
			events.back().earlyMedia = earlyMedia;
		}

		void onTrunkAnswered(const SipTrunk::TrunkEvent& ev,
			const std::shared_ptr<SipMessage>& ok) override
		{
			record("answered", ev);
			EXPECT_NE(ok, nullptr) << "the answer is handed over for its SDP";
			if (env) sentAtAnswerTime = env->sent.size();
			if (hangupOnAnswer && trunk) trunk->hangup(ev.trunkCallID);
		}

		void onTrunkFailed(const SipTrunk::TrunkEvent& ev, int status) override
		{
			record("failed", ev);
			events.back().status = status;
			// Captured inside the callback: the slot must already be free here.
			if (trunk) dialogsSeenDuringFailure = trunk->activeDialogs();
		}

		void onTrunkRemoteBye(const SipTrunk::TrunkEvent& ev) override
		{
			record("remoteBye", ev);
		}
	};

	std::string withStatus(std::string response, const std::string& statusLine)
	{
		response.replace(0, response.find("\r\n"), statusLine);
		return response;
	}
}

TEST(SipTrunkListener, RingingReportsEarlyMediaOnlyForOneEightyThree)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	RecordingListener lis;
	trunk.setConfig(workingConfig());
	trunk.setListener(&lis);

	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	ASSERT_NE(d, nullptr);
	const std::string base = okFor(*d);

	ASSERT_TRUE(trunk.handleResponse(responseFor(withStatus(base, "SIP/2.0 100 Trying"))));
	EXPECT_TRUE(lis.events.empty())
		<< "100 Trying means a proxy took the request, not that anyone is alerting";

	ASSERT_TRUE(trunk.handleResponse(responseFor(withStatus(base, "SIP/2.0 180 Ringing"))));
	ASSERT_EQ(lis.events.size(), 1u);
	EXPECT_EQ(lis.events[0].kind, "ringing");
	EXPECT_FALSE(lis.events[0].earlyMedia);
	EXPECT_EQ(lis.events[0].handsetCallID, "handset-1") << "the leg to ring back";
	EXPECT_EQ(lis.events[0].localRtpPort, 40000);

	ASSERT_TRUE(trunk.handleResponse(responseFor(withStatus(base, "SIP/2.0 183 Session Progress"))));
	ASSERT_EQ(lis.events.size(), 2u);
	EXPECT_TRUE(lis.events[1].earlyMedia) << "183 is the carrier already sending audio";
}

TEST(SipTrunkListener, AnsweredFiresAfterTheAckIsOnTheWire)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	RecordingListener lis;
	trunk.setConfig(workingConfig());
	trunk.setListener(&lis);

	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	ASSERT_NE(d, nullptr);
	const std::string trunkCallID = d->callID;

	lis.env = &env;
	ASSERT_TRUE(trunk.handleResponse(responseFor(okFor(*d))));

	ASSERT_EQ(lis.events.size(), 1u);
	EXPECT_EQ(lis.events[0].kind, "answered");
	EXPECT_EQ(lis.events[0].trunkCallID, trunkCallID);
	EXPECT_EQ(lis.events[0].handsetCallID, "handset-1");
	// The load-bearing assertion, sampled inside the callback rather than after
	// it: the ACK is already enqueued by the time the listener runs.
	EXPECT_EQ(lis.sentAtAnswerTime, 2u)
		<< "INVITE and its ACK must both be on the outbox before the callback fires";
	ASSERT_EQ(env.sent.size(), 2u);
	EXPECT_EQ(env.sentRaw(1).substr(0, 3), "ACK");
}

TEST(SipTrunkListener, HangingUpFromInsideAnsweredPutsTheByeAfterTheAck)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	RecordingListener lis;
	lis.trunk = &trunk;
	lis.hangupOnAnswer = true;          // what the wiring does when the SDP is unusable
	trunk.setConfig(workingConfig());
	trunk.setListener(&lis);

	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	ASSERT_NE(d, nullptr);
	ASSERT_TRUE(trunk.handleResponse(responseFor(okFor(*d))));

	ASSERT_EQ(env.sent.size(), 3u) << "INVITE, ACK, then the BYE the listener asked for";
	EXPECT_EQ(env.sentRaw(1).substr(0, 3), "ACK");
	EXPECT_EQ(env.sentRaw(2).substr(0, 3), "BYE")
		<< "ACK must precede BYE or the carrier rejects the sequence";
}

TEST(SipTrunkListener, FailureFiresAfterTheSlotIsReleasedAndTheViewsStillRead)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	RecordingListener lis;
	lis.trunk = &trunk;
	trunk.setConfig(workingConfig());
	trunk.setListener(&lis);

	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	ASSERT_NE(d, nullptr);
	ASSERT_TRUE(trunk.handleResponse(responseFor(withStatus(okFor(*d), "SIP/2.0 486 Busy Here"))));

	ASSERT_EQ(lis.events.size(), 1u);
	EXPECT_EQ(lis.events[0].kind, "failed");
	EXPECT_EQ(lis.events[0].status, 486);
	EXPECT_EQ(lis.events[0].handsetCallID, "handset-1")
		<< "moved out of the slot, not read back from it -- this is the dangling case";
	EXPECT_EQ(lis.dialogsSeenDuringFailure, 0u)
		<< "slot released BEFORE the callback, so a replacement call can be placed from it";
}

TEST(SipTrunkListener, SweepTimeoutReportsFourOhEight)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	RecordingListener lis;
	trunk.setConfig(workingConfig());
	trunk.setListener(&lis);

	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	trunk.sweep(std::chrono::steady_clock::now() + std::chrono::minutes(5));

	ASSERT_EQ(lis.events.size(), 1u);
	EXPECT_EQ(lis.events[0].kind, "failed");
	EXPECT_EQ(lis.events[0].status, 408)
		<< "a request with no final response inside its deadline is a timeout";
	EXPECT_EQ(lis.events[0].handsetCallID, "handset-1");
	EXPECT_EQ(trunk.activeDialogs(), 0u);
}

TEST(SipTrunkListener, OurOwnByeCompletingIsNotReportedAsARemoteHangup)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	RecordingListener lis;
	trunk.setConfig(workingConfig());
	trunk.setListener(&lis);

	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	ASSERT_NE(d, nullptr);
	ASSERT_TRUE(trunk.handleResponse(responseFor(okFor(*d))));   // answered
	ASSERT_TRUE(trunk.hangup("handset-1"));                      // we hang up
	lis.events.clear();

	// The carrier's 200 to OUR BYE. The handset leg is already gone; telling the
	// listener again would tear down a second time.
	const SipTrunk::Dialog* term = trunk.findByCallID("handset-1");
	ASSERT_NE(term, nullptr);
	ASSERT_TRUE(trunk.handleResponse(responseFor(okFor(*term))));

	EXPECT_TRUE(lis.events.empty())
		<< "our own BYE completing is not a carrier hangup";
	EXPECT_EQ(trunk.activeDialogs(), 0u);
}

TEST(SipTrunkListener, SweepOfOurOwnUnansweredByeNotifiesNobody)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	RecordingListener lis;
	trunk.setConfig(workingConfig());
	trunk.setListener(&lis);

	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	ASSERT_NE(d, nullptr);
	ASSERT_TRUE(trunk.handleResponse(responseFor(okFor(*d))));
	ASSERT_TRUE(trunk.hangup("handset-1"));   // Terminating, waiting on the 200
	lis.events.clear();

	trunk.sweep(std::chrono::steady_clock::now() + std::chrono::minutes(5));

	EXPECT_TRUE(lis.events.empty())
		<< "the handset was released when we asked for the BYE; do not fail it twice";
	EXPECT_EQ(trunk.activeDialogs(), 0u) << "the slot is still reclaimed";
}

TEST(SipTrunkListener, AnUnsetListenerChangesNothing)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(workingConfig());        // deliberately no setListener()

	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	ASSERT_NE(d, nullptr);
	ASSERT_TRUE(trunk.handleResponse(responseFor(withStatus(okFor(*d), "SIP/2.0 180 Ringing"))));
	ASSERT_TRUE(trunk.handleResponse(responseFor(okFor(*d))));
	EXPECT_EQ(trunk.activeDialogs(), 1u);
	trunk.sweep(std::chrono::steady_clock::now() + std::chrono::minutes(5));
	EXPECT_EQ(trunk.activeDialogs(), 1u)
		<< "an ANSWERED call is not swept -- see SweepLeavesAnAnsweredCallAlone";
}

// The no-answer deadline placeCall() arms is 60 s from the INVITE. It is still
// sitting on the dialog after the call is answered, so a sweep that only asked
// "is the deadline past" would hang up every trunk call about a minute in.
//
// This was the tested behaviour until sonnet-OG caught it on PR #355: the old
// version of the test above answered the call, swept at +5 min and asserted the
// dialog was GONE. It passed, because nothing called sweep() from the engine
// yet -- the bug could not bite until the wiring it needed was added, and the
// test was quietly asserting it was correct.
TEST(SipTrunkDialog, SweepLeavesAnAnsweredCallAlone)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(workingConfig());

	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	ASSERT_NE(d, nullptr);
	ASSERT_TRUE(trunk.handleResponse(responseFor(okFor(*d))));   // Confirmed

	trunk.sweep(std::chrono::steady_clock::now() + std::chrono::hours(2));

	EXPECT_EQ(trunk.activeDialogs(), 1u)
		<< "a call that is UP has no no-answer deadline; there is no max-duration timer";
}

// The other half: a dialog we are trying to hang up DOES still get reclaimed,
// so exempting Confirmed leaks nothing. hangup() moves it to Terminating with
// its own short deadline, and that one is swept.
TEST(SipTrunkDialog, SweepStillReclaimsADialogWhoseByeWentUnanswered)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(workingConfig());

	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	ASSERT_NE(d, nullptr);
	ASSERT_TRUE(trunk.handleResponse(responseFor(okFor(*d))));
	ASSERT_TRUE(trunk.hangup("handset-1"));                      // Terminating
	ASSERT_EQ(trunk.activeDialogs(), 1u) << "still held, waiting on the carrier's 200";

	trunk.sweep(std::chrono::steady_clock::now() + std::chrono::minutes(1));

	EXPECT_EQ(trunk.activeDialogs(), 0u)
		<< "a carrier that never answers our BYE must not pin the slot forever";
}
