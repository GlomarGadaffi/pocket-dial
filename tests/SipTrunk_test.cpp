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
