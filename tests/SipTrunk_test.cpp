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

#include <chrono>
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
		// The SIP domain the URIs are built from. Equal to sbcIpPort here
		// because this fixture has no outbound proxy and a dotted-quad host --
		// which is exactly why the byte-pinned expectations below are unchanged
		// by the domain/transport split. TrunkProxy.* covers the case where the
		// two genuinely differ.
		d.domain       = std::string(kSbcIp);   // #365: the default port is omitted
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

	EXPECT_EQ(firstLine(inv), "INVITE sip:+15551234567@203.0.113.5 SIP/2.0");
	EXPECT_TRUE(hasLine(inv, "To: <sip:+15551234567@203.0.113.5>"));
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
	EXPECT_EQ(firstLine(inv), "INVITE sip:+15551234567@203.0.113.5 SIP/2.0");
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

// #753: "Supported: timer" would let the carrier choose itself as RFC 4028
// refresher, and the trunk leg does not answer a refresh re-INVITE with a 2xx,
// so the carrier would drop every call at the first session interval. No claim
// without an implementation.
TEST(SipTrunkInvite, DoesNotClaimSessionTimerSupport)
{
	const auto d = pinnedDialog();
	const std::string inv = SipTrunk::buildInvite(d, "v=0\r\n");

	EXPECT_EQ(inv.find("Supported:"), std::string::npos)
		<< "the trunk leg answers no session refresh, so the INVITE must not offer one";
	EXPECT_EQ(inv.find("timer"), std::string::npos);
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
	EXPECT_TRUE(hasLine(ack, "To: <sip:+15551234567@203.0.113.5>;tag=carrier-tag"));
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
// A 2xx with no Contact violates RFC 3261 §12.1.1, so this is a best-effort
// path either way. The fallback targets the configured DOMAIN, not the
// resolved transport address: a proxy forwards on the Request-URI, so naming
// the carrier's domain is the likelier-to-route choice of the two. Transport
// is unaffected -- the ACK is still enqueued to the dialog's `peer` socket.
TEST(SipTrunkAck, TwoXxAckFallsBackToTheDomainWhenNoContactWasOffered)
{
	auto d = pinnedDialog();
	d.toTag = "carrier-tag";   // remoteTarget deliberately left empty

	const std::string ack = SipTrunk::buildAckFor2xx(d, "z9hG4bKack99");
	EXPECT_EQ(firstLine(ack), "ACK sip:+15551234567@203.0.113.5 SIP/2.0");

	// Pin that it really is the domain and not the transport address, which
	// the default fixture cannot distinguish (there the two are equal).
	d.domain    = "sip.carrier.example";
	d.sbcIpPort = "198.51.100.77:5080";
	const std::string viaProxy = SipTrunk::buildAckFor2xx(d, "z9hG4bKack99");
	EXPECT_EQ(firstLine(viaProxy), "ACK sip:+15551234567@sip.carrier.example SIP/2.0");
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
	EXPECT_TRUE(hasLine(bye, "To: <sip:+15551234567@203.0.113.5>;tag=carrier-tag"));
	EXPECT_TRUE(hasLine(bye, "From: <sip:15551230000@203.0.113.5>;tag=ftag01"));
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

// #618: the carrier answered the REGISTER but not the INVITE, and the console
// could not say where the INVITE went. The log line must name the destination
// ip:port, the local port it leaves from, and the From user the carrier checks.
TEST(SipTrunkDialog, InviteLogNamesDestinationLocalPortAndFromUser)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(workingConfig());
	sockaddr_in proxy = sbcAddr();
	proxy.sin_port = htons(5080);   // distinct from the local 5060

	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", proxy, 40000));
	bool found = false;
	for (const auto& l : env.logs)
		if (l.find("Trunk: INVITE") != std::string::npos &&
		    l.find("203.0.113.5:5080") != std::string::npos &&
		    l.find("local port 5060") != std::string::npos &&
		    l.find("From 15551230000") != std::string::npos) found = true;
	EXPECT_TRUE(found);
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

		void onTrunkRinging(const SipTrunk::TrunkEvent& ev, bool earlyMedia,
			const std::shared_ptr<SipMessage>& progress) override
		{
			EXPECT_EQ(progress != nullptr, earlyMedia) << "a 183 hands over its response, a 180 does not";
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

// ── Source authorisation (#356) ──────────────────────────────────────────────
//
// A Call-ID alone must not let an arbitrary sender act as the carrier. The two
// directions get different rules because their failure costs differ:
//
//   responses  strict: from d->peer or dropped, every state. A wrongly dropped
//              response is bounded by sweep(); a forged 200 redirects RTP.
//   BYE        peer, OR the Contact's dotted-quad host, OR both dialog tags.
//              A wrongly refused BYE bills forever -- Confirmed has no reaper.
//
// Every "nothing happened" below is asserted as a COUNT on the wire, the
// listener and the log, not as the absence of one particular message.

namespace
{
	constexpr const char* kForgerIp  = "198.51.100.66";   // RFC 5737 TEST-NET-2
	constexpr const char* kContactIp = "203.0.113.99";    // okFor()'s Contact host

	std::shared_ptr<SipMessage> responseFrom(const std::string& raw, const char* ip)
	{
		return std::make_shared<SipMessage>(raw, FakePbxEnv::addr(ip, 5060));
	}

	// The carrier hanging up: its tag in From, ours in To.
	std::shared_ptr<SipMessage> carrierByeFrom(const SipTrunk::Dialog& d, const char* ip,
		const std::string& carrierTag, const std::string& ourTag)
	{
		const std::string raw =
			"BYE sip:15551230000@192.168.1.10:5060 SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(ip) + ":5060;branch=z9hG4bKcbye\r\n"
			"From: <sip:" + d.destE164 + "@" + d.sbcIpPort + ">;tag=" + carrierTag + "\r\n"
			"To: <sip:15551230000@" + d.sbcIpPort + ">;tag=" + ourTag + "\r\n"
			"Call-ID: " + d.callID + "\r\n"
			"CSeq: 2 BYE\r\n"
			"Content-Length: 0\r\n\r\n";
		return std::make_shared<SipMessage>(raw, FakePbxEnv::addr(ip, 5060));
	}

	size_t logsContaining(const FakePbxEnv& env, const std::string& needle)
	{
		size_t n = 0;
		for (const auto& l : env.logs) if (l.find(needle) != std::string::npos) ++n;
		return n;
	}

	size_t sentTo(const FakePbxEnv& env, const char* ip)
	{
		const uint32_t want = inet_addr(ip);
		size_t n = 0;
		for (const auto& s : env.sent) if (s.to.sin_addr.s_addr == want) ++n;
		return n;
	}

	// A call answered by the real carrier, ready for a BYE.
	struct Answered
	{
		FakePbxEnv        env;
		SipTrunk          trunk{env};
		RecordingListener lis;
		std::string       trunkCallID, ourTag;

		Answered()
		{
			trunk.setConfig(workingConfig());
			trunk.setListener(&lis);
			EXPECT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
			const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
			EXPECT_TRUE(trunk.handleResponse(responseFor(okFor(*d))));
			trunkCallID = d->callID;
			ourTag      = d->fromTag;
			lis.events.clear();
			env.sent.clear();
			env.logs.clear();
		}
		// Only valid while the dialog is live -- use before a BYE, not after.
		const SipTrunk::Dialog& dialog() const { return *trunk.findByCallID("handset-1"); }
	};
}

TEST(SipTrunkSource, ForgedResponsesChangeNothingInAnyState)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	RecordingListener lis;
	trunk.setConfig(workingConfig());
	trunk.setListener(&lis);

	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	ASSERT_NE(d, nullptr);
	const std::string ok = okFor(*d);

	// Trying: ringing, a failure, and the dangerous one -- an answer with the
	// forger's Contact, which would be ACKed and have its SDP relayed.
	for (const char* status : { "SIP/2.0 180 Ringing", "SIP/2.0 486 Busy Here", "SIP/2.0 200 OK" })
	{
		EXPECT_TRUE(trunk.handleResponse(responseFrom(withStatus(ok, status), kForgerIp)))
			<< status << ": a response on a trunk Call-ID is consumed even when refused";
	}
	EXPECT_EQ(d->state, SipTrunk::State::Trying) << "no forged response may move the dialog";
	EXPECT_TRUE(d->toTag.empty()) << "nor latch the forger's tag";
	EXPECT_TRUE(d->remoteTarget.empty()) << "nor latch the forger's Contact as our route";
	EXPECT_EQ(env.sent.size(), 1u) << "the INVITE, and no ACK to anything forged";
	EXPECT_TRUE(lis.events.empty()) << "the handset side must hear nothing";

	// The real answer still works afterwards.
	ASSERT_TRUE(trunk.handleResponse(responseFor(ok)));
	EXPECT_EQ(d->state, SipTrunk::State::Confirmed);
	ASSERT_EQ(lis.events.size(), 1u);
	EXPECT_EQ(lis.events[0].kind, "answered");

	// Terminating: a forged 200 to our BYE must not release the slot early.
	ASSERT_TRUE(trunk.hangup("handset-1"));
	EXPECT_TRUE(trunk.handleResponse(responseFrom(ok, kForgerIp)));
	EXPECT_EQ(trunk.activeDialogs(), 1u) << "still waiting on the carrier's own 200";

	EXPECT_EQ(trunk.forgedDialogResponses(), 4u) << "every refused response is counted";
	EXPECT_EQ(logsContaining(env, "dropped"), 3u) << "#663: logged at counts 1, 2 and 4 only";
}

TEST(SipTrunkSource, ByeFromThePeerIsAccepted)
{
	Answered a;
	ASSERT_TRUE(a.trunk.handleBye(carrierByeFrom(a.dialog(), kSbcIp, "carrier-tag", a.ourTag)));

	EXPECT_EQ(a.env.sent.size(), 1u);
	EXPECT_EQ(sentTo(a.env, kSbcIp), 1u) << "the 200 goes back to the carrier";
	EXPECT_EQ(firstLine(a.env.sentRaw(0)), "SIP/2.0 200 OK");
	ASSERT_EQ(a.lis.events.size(), 1u);
	EXPECT_EQ(a.lis.events[0].kind, "remoteBye");
	EXPECT_EQ(a.trunk.activeDialogs(), 0u);
}

// Wrong tags on purpose: this must pass on the ADDRESS, so the tag rule cannot
// be what lets it through.
TEST(SipTrunkSource, ByeFromTheDottedQuadContactIsAcceptedOnAddressAlone)
{
	Answered a;
	ASSERT_EQ(a.dialog().remoteTarget, "sip:+15551234567@" + std::string(kContactIp) + ":5060");

	ASSERT_TRUE(a.trunk.handleBye(carrierByeFrom(a.dialog(), kContactIp, "wrong", "wrong")));

	EXPECT_EQ(sentTo(a.env, kContactIp), 1u);
	EXPECT_EQ(firstLine(a.env.sentRaw(0)), "SIP/2.0 200 OK");
	EXPECT_EQ(a.lis.events.size(), 1u);
	EXPECT_EQ(logsContaining(a.env, "accepted on dialog tags"), 0u)
		<< "a Contact-host BYE is not a tag-rule acceptance";
}

TEST(SipTrunkSource, ByeFromElsewhereWithBothTagsIsAcceptedAndLogged)
{
	Answered a;
	ASSERT_TRUE(a.trunk.handleBye(carrierByeFrom(a.dialog(), kForgerIp, "carrier-tag", a.ourTag)));

	EXPECT_EQ(firstLine(a.env.sentRaw(0)), "SIP/2.0 200 OK");
	EXPECT_EQ(a.lis.events.size(), 1u);
	EXPECT_EQ(a.trunk.activeDialogs(), 0u);
	EXPECT_EQ(logsContaining(a.env, "accepted on dialog tags"), 1u)
		<< "the SBC-pool case must be visible to whoever brings a carrier up";
}

TEST(SipTrunkSource, ByeFromElsewhereWithoutBothTagsIsRefused)
{
	// Each tag alone is not enough, and neither is a pair in swapped positions.
	struct Case { const char* carrierTag; bool ourTagRight; const char* what; };
	for (const Case c : { Case{ "wrong",       true,  "carrier tag wrong" },
	                      Case{ "carrier-tag", false, "our tag wrong" },
	                      Case{ "wrong",       false, "both wrong" } })
	{
		Answered a;
		const std::string ourTag = c.ourTagRight ? a.ourTag : "wrong";
		ASSERT_TRUE(a.trunk.handleBye(carrierByeFrom(a.dialog(), kForgerIp, c.carrierTag, ourTag)))
			<< c.what << ": consumed, never passed to the handset paths";

		EXPECT_EQ(a.env.sent.size(), 1u) << c.what;
		EXPECT_EQ(sentTo(a.env, kForgerIp), 1u) << c.what;
		EXPECT_EQ(firstLine(a.env.sentRaw(0)), "SIP/2.0 403 Forbidden") << c.what;
		EXPECT_TRUE(a.lis.events.empty()) << c.what << ": the handset must not be hung up";
		// Looked up, not a.dialog(): an accepted BYE frees the slot, and a
		// regression must fail here, not segfault the whole binary.
		const SipTrunk::Dialog* still = a.trunk.findByCallID("handset-1");
		ASSERT_NE(still, nullptr) << c.what << ": the dialog was released";
		EXPECT_EQ(still->state, SipTrunk::State::Confirmed) << c.what << ": the call is still up";
		EXPECT_TRUE(a.env.freedTransactionCallIds.empty()) << c.what;
		EXPECT_EQ(logsContaining(a.env, "refused"), 1u) << c.what;
	}
}

// An FQDN Contact cannot be resolved on the SIP thread, so it grants nothing;
// the peer and the tags remain the only ways in.
TEST(SipTrunkSource, AnFqdnContactGrantsNoAddress)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(workingConfig());
	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	std::string ok = okFor(*d);
	ok.replace(ok.find(kContactIp), std::string(kContactIp).size(), "media.carrier.example");
	ASSERT_TRUE(trunk.handleResponse(responseFor(ok)));
	ASSERT_EQ(d->remoteTarget, "sip:+15551234567@media.carrier.example:5060");
	env.sent.clear();

	ASSERT_TRUE(trunk.handleBye(carrierByeFrom(*d, kContactIp, "wrong", "wrong")));
	EXPECT_EQ(firstLine(env.sentRaw(0)), "SIP/2.0 403 Forbidden");
	EXPECT_EQ(trunk.activeDialogs(), 1u);
}

// With no carrier tag latched yet, an empty guessed tag must not "match" it.
TEST(SipTrunkSource, AnEmptyCarrierTagMatchesNothing)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(workingConfig());
	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	ASSERT_TRUE(d->toTag.empty());
	env.sent.clear();

	// The forger guesses an empty carrier tag to match our empty toTag.
	ASSERT_TRUE(trunk.handleBye(carrierByeFrom(*d, kForgerIp, "", d->fromTag)));
	EXPECT_EQ(firstLine(env.sentRaw(0)), "SIP/2.0 403 Forbidden");
	EXPECT_EQ(d->state, SipTrunk::State::Trying);
}

// The tag rule is for CONFIRMED calls only. A 180 carrying a To-tag latches the
// carrier's tag before any answer, so without the state gate a tag-matched BYE
// from anywhere would be accepted on an early dialog -- which the rule's own
// justification (a refused BYE bills forever) does not cover: an unanswered
// dialog is swept. RFC 3261 s15: the callee MUST NOT send a BYE on an early
// dialog, so the gate refuses nothing a real carrier sends.
TEST(SipTrunkSource, AnEarlyDialogAcceptsNoByeOnTags)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	RecordingListener lis;
	trunk.setConfig(workingConfig());
	trunk.setListener(&lis);
	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	ASSERT_TRUE(trunk.handleResponse(responseFor(withStatus(okFor(*d), "SIP/2.0 180 Ringing"))));
	ASSERT_EQ(d->state, SipTrunk::State::Proceeding);
	ASSERT_EQ(d->toTag, "carrier-tag") << "the 180 latched the carrier's tag";
	env.sent.clear();
	lis.events.clear();

	ASSERT_TRUE(trunk.handleBye(carrierByeFrom(*d, kForgerIp, "carrier-tag", d->fromTag)));

	ASSERT_EQ(env.sent.size(), 1u);
	EXPECT_EQ(firstLine(env.sentRaw(0)), "SIP/2.0 403 Forbidden");
	EXPECT_EQ(d->state, SipTrunk::State::Proceeding) << "the call is still ringing";
	EXPECT_TRUE(lis.events.empty()) << "the handset must not be torn down";
	EXPECT_EQ(logsContaining(env, "accepted on dialog tags"), 0u);
}

// ── Outbound proxy: the domain/transport split ───────────────────────────────
//
// The single subtlest thing this feature added. Before it, Dialog::sbcIpPort
// held the RESOLVED address and fed the Request-URI, To and From. An outbound
// proxy breaks that conflation: packets must go to the proxy while the dialog
// stays addressed to the carrier's SIP domain. If these two ever collapse back
// into one value the failure is silent and carrier-side -- a 403 or a 404 with
// no diagnostic, which is exactly the kind of bug that costs a cutover window.

TEST(TrunkProxy, TransportTargetsProxyWhileUrisKeepTheRegistrar)
{
	SipTrunk::Config c = workingConfig();
	std::snprintf(c.proxyHost, sizeof(c.proxyHost), "%s", "proxy.carrier.example");
	c.proxyPort = 5080;

	EXPECT_STREQ(c.transportHost(), "proxy.carrier.example")
		<< "packets must be addressed to the proxy once one is configured";
	EXPECT_EQ(c.transportPort(), 5080);

	// ...while host/port remain what the URIs are built from.
	EXPECT_STREQ(c.host, kSbcIp);
	EXPECT_EQ(c.port, kSbcPort);
}

TEST(TrunkProxy, NoProxyMeansTransportIsTheRegistrar)
{
	const SipTrunk::Config c = workingConfig();
	EXPECT_STREQ(c.transportHost(), kSbcIp);
	EXPECT_EQ(c.transportPort(), kSbcPort);
}

// An empty proxyHost must not be treated as "a proxy on port proxyPort". A
// half-filled form (port typed, host left blank) would otherwise silently
// retarget the trunk at the registrar's address on the wrong port.
TEST(TrunkProxy, ProxyPortAloneDoesNotDivertTransport)
{
	SipTrunk::Config c = workingConfig();
	c.proxyPort = 5080;           // host deliberately left empty
	EXPECT_STREQ(c.transportHost(), kSbcIp);
	EXPECT_EQ(c.transportPort(), kSbcPort)
		<< "proxyPort is meaningless without a proxyHost and must be ignored";
}

// The URI builders must read domain, never the resolved transport address.
// This is the test that goes red if someone "simplifies" domain back to
// sbcIpPort.
TEST(TrunkProxy, UriBuildersUseTheDomainNotTheResolvedAddress)
{
	SipTrunk::Dialog d = pinnedDialog();
	d.domain    = "sip.carrier.example";   // what the operator configured
	d.sbcIpPort = "198.51.100.77:5080";         // where the packet actually went
	d.toTag     = "carrier-tag";
	d.remoteTarget = "sip:+15551234567@198.51.100.77:5080";

	const std::string inv = SipTrunk::buildInvite(d, "v=0\r\n");
	EXPECT_EQ(firstLine(inv), "INVITE sip:+15551234567@sip.carrier.example SIP/2.0");
	EXPECT_TRUE(hasLine(inv, "To: <sip:+15551234567@sip.carrier.example>"));
	EXPECT_TRUE(hasLine(inv, "From: <sip:15551230000@sip.carrier.example>;tag=ftag01"));
	EXPECT_EQ(inv.find("198.51.100.77"), std::string::npos)
		<< "the transport address must never appear in a URI";

	// The failure ACK is built from the same inputs and must agree.
	const std::string ackFail = SipTrunk::buildAckForFailure(d);
	EXPECT_EQ(firstLine(ackFail), "ACK sip:+15551234567@sip.carrier.example SIP/2.0");
	EXPECT_EQ(ackFail.find("198.51.100.77"), std::string::npos);

	// The BYE routes to the remote target (which IS a transport-derived URI the
	// carrier gave us, and must be honoured verbatim), but its To/From still
	// carry the domain.
	const std::string bye = SipTrunk::buildBye(d, "z9hG4bKbye01");
	EXPECT_EQ(firstLine(bye), "BYE sip:+15551234567@198.51.100.77:5080 SIP/2.0")
		<< "an in-dialog request goes to the Contact the carrier supplied";
	EXPECT_TRUE(hasLine(bye, "To: <sip:+15551234567@sip.carrier.example>;tag=carrier-tag"));
	EXPECT_TRUE(hasLine(bye, "From: <sip:15551230000@sip.carrier.example>;tag=ftag01"));
}

// placeCall() is what actually populates domain. A dialog left with an empty
// domain would emit "sip:+1...@" -- malformed, and rejected by every carrier.
TEST(TrunkProxy, PlaceCallStampsTheDomainFromConfigNotTheSocket)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	SipTrunk::Config c = workingConfig();
	std::snprintf(c.host, sizeof(c.host), "%s", "sip.carrier.example");
	std::snprintf(c.proxyHost, sizeof(c.proxyHost), "%s", "proxy.carrier.example");
	c.proxyPort = 5080;
	trunk.setConfig(c);

	// The caller resolved the PROXY and hands us its address, as RequestsHandler
	// now does via transportHost()/transportPort().
	sockaddr_in proxy{};
	proxy.sin_family = AF_INET;
	proxy.sin_addr.s_addr = inet_addr("198.51.100.77");
	proxy.sin_port = htons(5080);

	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", proxy, 40000));
	ASSERT_EQ(env.sent.size(), 1u);

	const std::string inv = env.sentRaw(0);
	EXPECT_NE(inv.find("INVITE sip:+15551234567@sip.carrier.example SIP/2.0"), std::string::npos)
		<< "the Request-URI must name the configured registrar, not the proxy";
	EXPECT_EQ(inv.find("198.51.100.77"), std::string::npos)
		<< "the resolved proxy address must not leak into any URI";
}

// ── The ":port" in emitted URIs (#365, option A) ─────────────────────────────
//
// By RFC 3261 §19.1.4 a URI that omits a component with a default value does
// NOT match one that carries it explicitly, so "sip:x@carrier.example.com"
// and "sip:x@carrier.example.com:5060" are different route keys to an SBC that
// routes on the Request-URI. #365 (option A, decided 2026-09-27): the default
// 5060 is omitted; any other configured port is kept. No storage change.
TEST(SipTrunkUriPort, TheDefaultPortIsOmittedFromEveryUri)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	SipTrunk::Config c = workingConfig();
	std::snprintf(c.host, sizeof(c.host), "%s", "carrier.example.com");
	c.port = 5060;   // the DEFAULT port -- the case the RFC note is about
	trunk.setConfig(c);

	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	ASSERT_EQ(env.sent.size(), 1u);
	const std::string inv = env.sentRaw(0);

	EXPECT_EQ(firstLine(inv), "INVITE sip:+15551234567@carrier.example.com SIP/2.0");
	EXPECT_TRUE(hasLine(inv, "To: <sip:+15551234567@carrier.example.com>"));
	EXPECT_EQ(inv.find("carrier.example.com:5060"), std::string::npos)
		<< "no URI may carry the default port explicitly (#365)";
}

TEST(SipTrunkUriPort, ANonDefaultPortIsKeptInEveryUri)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	SipTrunk::Config c = workingConfig();
	std::snprintf(c.host, sizeof(c.host), "%s", "carrier.example.com");
	c.port = 5080;   // an operator-chosen port is part of the route key: keep it
	trunk.setConfig(c);

	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	ASSERT_EQ(env.sent.size(), 1u);
	const std::string inv = env.sentRaw(0);

	EXPECT_EQ(firstLine(inv), "INVITE sip:+15551234567@carrier.example.com:5080 SIP/2.0");
	EXPECT_TRUE(hasLine(inv, "To: <sip:+15551234567@carrier.example.com:5080>"));
	EXPECT_NE(inv.find("From: <sip:15551230000@carrier.example.com:5080>"), std::string::npos);
}

// ── Credentials ──────────────────────────────────────────────────────────────

TEST(TrunkCredentials, StoredAndReportedButNeverInConfig)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	EXPECT_FALSE(trunk.hasCredentials());

	EXPECT_TRUE(trunk.setCredentials("s3cret-pw"));
	EXPECT_TRUE(trunk.hasCredentials());

	// The whole point of keeping the secret out of Config: a caller that copies
	// the config cannot copy the password with it.
	const SipTrunk::Config copy = trunk.config();
	const char* raw = reinterpret_cast<const char*>(&copy);
	const std::string blob(raw, sizeof(copy));
	EXPECT_EQ(blob.find("s3cret-pw"), std::string::npos)
		<< "the password must not be reachable through a copied Config";
}

TEST(TrunkCredentials, OverLongPasswordIsRejectedNotTruncated)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	ASSERT_TRUE(trunk.setCredentials("short"));

	const std::string tooLong(SipTrunk::kMaxSecret, 'x');   // one past what fits
	EXPECT_FALSE(trunk.setCredentials(tooLong))
		<< "silently storing a truncated password would authenticate nothing "
		   "while the UI reported success";

	// The longest value that DOES fit is accepted.
	const std::string justFits(SipTrunk::kMaxSecret - 1, 'x');
	EXPECT_TRUE(trunk.setCredentials(justFits));
	EXPECT_TRUE(trunk.hasCredentials());
}

TEST(TrunkCredentials, EmptyPasswordClearsRatherThanFailing)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	ASSERT_TRUE(trunk.setCredentials("s3cret-pw"));
	ASSERT_TRUE(trunk.hasCredentials());

	EXPECT_TRUE(trunk.setCredentials("")) << "an empty credential is a valid state, not an error";
	EXPECT_FALSE(trunk.hasCredentials());
}

TEST(TrunkCredentials, ClearCredentialsRemovesIt)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	ASSERT_TRUE(trunk.setCredentials("s3cret-pw"));
	trunk.clearCredentials();
	EXPECT_FALSE(trunk.hasCredentials());
}

// Guards the claim made in Config::authUser's comment and on the setup page:
// credentials are stored but nothing transmits them yet. If a challenge path
// lands without this test being updated, it goes red and forces the claim to
// be corrected rather than left stale (#296's pattern).
TEST(TrunkCredentials, NothingCredentialShapedReachesTheWireToday)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	SipTrunk::Config c = workingConfig();
	std::snprintf(c.authUser, sizeof(c.authUser), "%s", "auth-id-9876");
	trunk.setConfig(c);
	ASSERT_TRUE(trunk.setCredentials("s3cret-pw"));

	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	ASSERT_EQ(env.sent.size(), 1u);

	const std::string inv = env.sentRaw(0);
	EXPECT_EQ(inv.find("s3cret-pw"), std::string::npos) << "the password must never be on the wire";
	EXPECT_EQ(inv.find("auth-id-9876"), std::string::npos)
		<< "authUser is stored only -- no Authorization header is generated yet";
	EXPECT_EQ(inv.find("Authorization"), std::string::npos);
	EXPECT_EQ(inv.find("Proxy-Authorization"), std::string::npos);
}

// ── #399: answering a 401/407 on our INVITE ─────────────────────────────────
//
// All against the TEST-NET-3 SBC through FakePbxEnv's capture; nothing leaves
// the process and no real number is dialled.
namespace
{
	std::string challengeFor(const SipTrunk::Dialog& d, int code, const char* header)
	{
		std::string r = okFor(d);
		r.replace(0, r.find("\r\n"), code == 407
			? "SIP/2.0 407 Proxy Authentication Required"
			: "SIP/2.0 401 Unauthorized");
		const std::string cseqLine = "CSeq: " + std::to_string(d.cseq) + " INVITE";
		r.replace(r.find("CSeq: 1 INVITE"), std::string("CSeq: 1 INVITE").size(), cseqLine);
		r.insert(r.find("Content-Length"),
			std::string(header) + ": Digest realm=\"carrier.example\", nonce=\"n0nce399\", qop=\"auth\"\r\n");
		return r;
	}

	bool anySentOrLoggedContains(const FakePbxEnv& env, const std::string& needle)
	{
		for (std::size_t i = 0; i < env.sent.size(); ++i)
			if (env.sentRaw(i).find(needle) != std::string::npos) return true;
		for (const auto& l : env.logs)
			if (l.find(needle) != std::string::npos) return true;
		return false;
	}
}

TEST(SipTrunkAuth, A401IsAckedAndTheInviteResentOnceWithCredentials)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(workingConfig());
	ASSERT_TRUE(trunk.setCredentials("s3cret-399"));

	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	ASSERT_NE(d, nullptr);
	const std::string firstBranch = d->branch;
	const std::string callId = d->callID;

	ASSERT_TRUE(trunk.handleResponse(responseFor(challengeFor(*d, 401, "WWW-Authenticate"))));

	ASSERT_EQ(env.sent.size(), 3u) << "INVITE, the challenge's ACK, the credentialed INVITE";
	const std::string ack = env.sentRaw(1);
	EXPECT_EQ(ack.substr(0, 3), "ACK");
	EXPECT_NE(ack.find(";branch=" + firstBranch), std::string::npos)
		<< "RFC 3261 s17.1.1.3: the challenge is ACKed in the first INVITE's transaction";

	const std::string retry = env.sentRaw(2);
	EXPECT_EQ(firstLine(retry), "INVITE sip:+15551234567@203.0.113.5 SIP/2.0");
	EXPECT_NE(retry.find("Call-ID: " + callId), std::string::npos) << "same dialog";
	EXPECT_NE(retry.find("CSeq: 2 INVITE"), std::string::npos) << "a new transaction: CSeq+1";
	EXPECT_EQ(retry.find(";branch=" + firstBranch), std::string::npos) << "and a fresh branch";
	EXPECT_NE(retry.find("\r\nAuthorization: Digest username=\"15551230000\""), std::string::npos) << retry;
	EXPECT_NE(retry.find("uri=\"sip:+15551234567@203.0.113.5\""), std::string::npos)
		<< "the digest uri is the Request-URI";
	EXPECT_NE(retry.find("nonce=\"n0nce399\""), std::string::npos);
	EXPECT_NE(retry.find("v=0"), std::string::npos) << "the same offer goes out again";
	EXPECT_EQ(trunk.activeDialogs(), 1u) << "the call is still being placed";
	EXPECT_FALSE(anySentOrLoggedContains(env, "s3cret-399")) << "the password never leaves the box";
}

// #618: both INVITEs are on the console in full, and the credentialed one's
// Authorization value (the digest response) is not.
TEST(SipTrunkAuth, TheFullInviteIsLoggedWithAuthorizationRedacted)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(workingConfig());
	ASSERT_TRUE(trunk.setCredentials("s3cret-399"));
	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	ASSERT_NE(d, nullptr);
	ASSERT_TRUE(trunk.handleResponse(responseFor(challengeFor(*d, 401, "WWW-Authenticate"))));

	std::string all;
	for (const auto& l : env.logs)
	{
		EXPECT_LE(l.size(), 200u) << "over LogQueue's line cap: " << l;
		if (l.rfind("Trunk: INVITE> ", 0) == 0) all += l + "\n";
	}
	EXPECT_NE(all.find("Trunk: INVITE> INVITE sip:+15551234567@203.0.113.5 SIP/2.0 | Via: "),
		std::string::npos) << all;
	EXPECT_NE(all.find("CSeq: 1 INVITE"), std::string::npos) << all;
	EXPECT_NE(all.find("CSeq: 2 INVITE"), std::string::npos) << "the retry too: " << all;
	EXPECT_NE(all.find("Contact: "), std::string::npos) << all;
	EXPECT_NE(all.find("c=IN IP4 "), std::string::npos) << "the SDP too: " << all;
	EXPECT_NE(all.find("Authorization: <redacted>"), std::string::npos) << all;
	EXPECT_EQ(all.find("response="), std::string::npos) << all;
	EXPECT_EQ(all.find("nonce="), std::string::npos) << all;
	EXPECT_FALSE(anySentOrLoggedContains(env, "s3cret-399"));
}

TEST(SipTrunkAuth, A407IsAnsweredWithProxyAuthorizationAndTheAuthUser)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	SipTrunk::Config cfg = workingConfig();
	std::snprintf(cfg.authUser, sizeof(cfg.authUser), "%s", "auth-id-399");
	trunk.setConfig(cfg);
	ASSERT_TRUE(trunk.setCredentials("s3cret-399"));

	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	ASSERT_NE(d, nullptr);
	ASSERT_TRUE(trunk.handleResponse(responseFor(challengeFor(*d, 407, "Proxy-Authenticate"))));

	ASSERT_EQ(env.sent.size(), 3u);
	const std::string retry = env.sentRaw(2);
	EXPECT_NE(retry.find("\r\nProxy-Authorization: Digest username=\"auth-id-399\""), std::string::npos)
		<< "a 407 is answered in Proxy-Authorization, as the configured auth ID:\n" << retry;
	EXPECT_EQ(retry.find("\r\nAuthorization:"), std::string::npos);
}

TEST(SipTrunkAuth, ASecondChallengeFailsTheCallInsteadOfLooping)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(workingConfig());
	ASSERT_TRUE(trunk.setCredentials("wrong-password"));

	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	ASSERT_NE(d, nullptr);
	ASSERT_TRUE(trunk.handleResponse(responseFor(challengeFor(*d, 401, "WWW-Authenticate"))));
	d = trunk.findByCallID("handset-1");
	ASSERT_NE(d, nullptr);
	ASSERT_TRUE(trunk.handleResponse(responseFor(challengeFor(*d, 401, "WWW-Authenticate"))));

	ASSERT_EQ(env.sent.size(), 4u) << "INVITE, ACK, INVITE, ACK -- never a third INVITE";
	EXPECT_EQ(env.sentRaw(3).substr(0, 3), "ACK");
	EXPECT_EQ(trunk.activeDialogs(), 0u) << "the rejected call is released";
}

TEST(SipTrunkAuth, WithoutCredentialsAChallengeIsAnOrdinaryFailure)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(workingConfig());

	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	ASSERT_NE(d, nullptr);
	ASSERT_TRUE(trunk.handleResponse(responseFor(challengeFor(*d, 401, "WWW-Authenticate"))));

	ASSERT_EQ(env.sent.size(), 2u) << "INVITE and its ACK only";
	EXPECT_EQ(trunk.activeDialogs(), 0u);
}

TEST(SipTrunkAuth, ARetransmittedFirstChallengeAfterTheRetryDoesNotFailTheCall)
{
	// #581 review B1: the carrier resends its 401 for CSeq 1 until our ACK lands
	// (RFC 3261 s17.2.1). Arriving after the credentialed retry went out, it
	// used to latch the dead transaction's To-tag and fail the call while the
	// CSeq 2 INVITE still rang at the far end.
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(workingConfig());
	ASSERT_TRUE(trunk.setCredentials("s3cret-399"));

	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	ASSERT_NE(d, nullptr);
	const std::string firstBranch = d->branch;
	const std::string challenge = challengeFor(*d, 401, "WWW-Authenticate");
	ASSERT_TRUE(trunk.handleResponse(responseFor(challenge)));
	ASSERT_EQ(env.sent.size(), 3u) << "INVITE, the challenge's ACK, the credentialed INVITE";

	ASSERT_TRUE(trunk.handleResponse(responseFor(challenge)));   // the same CSeq 1 401, again

	EXPECT_EQ(trunk.activeDialogs(), 1u) << "the retry is still live; the call must not fail";
	d = trunk.findByCallID("handset-1");
	ASSERT_NE(d, nullptr);
	EXPECT_EQ(d->cseq, 2u);
	ASSERT_EQ(env.sent.size(), 4u) << "one new message only: the first transaction's ACK again";
	const std::string reAck = env.sentRaw(3);
	EXPECT_EQ(reAck.substr(0, 3), "ACK");
	EXPECT_NE(reAck.find(";branch=" + firstBranch), std::string::npos) << reAck;
	EXPECT_NE(reAck.find("CSeq: 1 ACK"), std::string::npos) << reAck;
}

TEST(SipTrunkAuth, APoolRefusalOnTheRetryAcksTheChallengeOnceFromTheUntouchedTransaction)
{
	// #581 review B2: the retry INVITE's pool draw failed AFTER the ACK went out
	// and the dialog had moved to CSeq 2, so the failure path sent a second ACK
	// from the mutated dialog (new branch, CSeq 2, no To-tag).
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(workingConfig());
	ASSERT_TRUE(trunk.setCredentials("s3cret-399"));

	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	ASSERT_NE(d, nullptr);
	const std::string firstBranch = d->branch;
	const std::string challenge = challengeFor(*d, 401, "WWW-Authenticate");
	env.messagePoolFailDrawIn = 2;   // the challenge's ACK draws; the retry INVITE does not

	ASSERT_TRUE(trunk.handleResponse(responseFor(challenge)));

	std::size_t acks = 0;
	for (std::size_t i = 0; i < env.sent.size(); ++i)
	{
		const std::string raw = env.sentRaw(i);
		if (raw.rfind("ACK", 0) != 0) continue;
		++acks;
		EXPECT_NE(raw.find(";branch=" + firstBranch), std::string::npos) << raw;
		EXPECT_NE(raw.find("CSeq: 1 ACK"), std::string::npos) << raw;
	}
	EXPECT_EQ(acks, 1u) << "exactly one ACK, in the challenged transaction";
	EXPECT_EQ(trunk.activeDialogs(), 0u) << "unanswerable for now: an ordinary failure";
}

// ── #399: REGISTER with the carrier, digest-signed ──────────────────────────
//
// Engage's SBC never answered .244's INVITEs because the trunk never
// registered. Same TEST-NET-3 SBC and FakePbxEnv capture as above; nothing
// leaves the process. `nowMs` is steady_clock, because handleResponse() reads
// the real clock when it hands a response to the registration client.
namespace
{
	uint64_t steadyMs()
	{
		return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
			std::chrono::steady_clock::now().time_since_epoch()).count());
	}

	std::string headerValue(const std::string& m, const std::string& name)
	{
		const size_t p = m.find("\r\n" + name + ": ");
		if (p == std::string::npos) return {};
		const size_t v = p + 2 + name.size() + 2;
		return m.substr(v, m.find("\r\n", v) - v);
	}

	// The registrar's answer to `reg`, echoing its Via/From/To/Call-ID/CSeq.
	std::string regResponse(const std::string& reg, const std::string& statusLine,
		const std::string& extraHeaders)
	{
		return statusLine + "\r\n"
			"Via: " + headerValue(reg, "Via") + "\r\n"
			"From: " + headerValue(reg, "From") + "\r\n"
			"To: " + headerValue(reg, "To") + ";tag=reg-tag\r\n"
			"Call-ID: " + headerValue(reg, "Call-ID") + "\r\n"
			"CSeq: " + headerValue(reg, "CSeq") + "\r\n"
			+ extraHeaders +
			"Content-Length: 0\r\n\r\n";
	}

	// #686: a registrar's 2xx lists our binding: it echoes our Contact.
	std::string echoContact(const std::string& reg)
	{
		return "Contact: " + headerValue(reg, "Contact") + "\r\n";
	}

	SipTrunk::Config regConfig()
	{
		SipTrunk::Config c = workingConfig();
		std::snprintf(c.authUser, sizeof(c.authUser), "%s", "authid399");
		return c;
	}

	const char* const kRegChallenge =
		"Digest realm=\"carrier.example\", nonce=\"regn0nce\", qop=\"auth\", algorithm=MD5";
}

TEST(SipTrunkRegister, TheFirstTickSendsAnUnsignedRegisterToTheSbc)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(regConfig());
	ASSERT_TRUE(trunk.setCredentials("s3cret-reg"));

	trunk.tickRegistration(steadyMs(), sbcAddr());

	ASSERT_EQ(env.sent.size(), 1u) << "boot must REGISTER, or the carrier never routes to us";
	const std::string reg = env.sentRaw(0);
	EXPECT_EQ(firstLine(reg), "REGISTER sip:203.0.113.5 SIP/2.0");
	EXPECT_EQ(env.sent[0].to.sin_addr.s_addr, sbcAddr().sin_addr.s_addr);
	EXPECT_EQ(headerValue(reg, "To"), "<sip:15551230000@203.0.113.5>");
	EXPECT_EQ(reg.find("Authorization"), std::string::npos) << "nothing to sign until challenged";
}

TEST(SipTrunkRegister, A401IsAnsweredWithDigestAndThe200ArmsARefreshBeforeExpires)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(regConfig());
	ASSERT_TRUE(trunk.setCredentials("s3cret-reg"));
	const uint64_t t0 = steadyMs();
	trunk.tickRegistration(t0, sbcAddr());
	ASSERT_EQ(env.sent.size(), 1u);

	ASSERT_TRUE(trunk.handleResponse(responseFor(regResponse(env.sentRaw(0),
		"SIP/2.0 401 Unauthorized", std::string("WWW-Authenticate: ") + kRegChallenge + "\r\n"))))
		<< "a response on the REGISTER Call-ID is the trunk's";
	ASSERT_EQ(env.sent.size(), 2u) << "the 401 is answered at once, not a tick later";
	const std::string signedReg = env.sentRaw(1);
	EXPECT_EQ(headerValue(signedReg, "CSeq"), "2 REGISTER");

	SipDigest::DigestAuth auth;
	ASSERT_TRUE(SipDigest::parseAuthorization(headerValue(signedReg, "Authorization"), auth))
		<< signedReg;
	EXPECT_EQ(auth.username, "authid399") << "the auth ID, not the AOR user";
	EXPECT_EQ(auth.uri, "sip:203.0.113.5");
	EXPECT_TRUE(SipDigest::verify(auth,
		SipDigest::computeHa1("authid399", "carrier.example", "s3cret-reg"), "REGISTER"))
		<< "the carrier must be able to verify it";
	EXPECT_EQ(signedReg.find("s3cret-reg"), std::string::npos);

	ASSERT_TRUE(trunk.handleResponse(responseFor(regResponse(signedReg,
		"SIP/2.0 200 OK", echoContact(signedReg) + "Expires: 120\r\n"))));
	EXPECT_EQ(trunk.registration().state(), SipRegistrationClient::State::Registered);
	EXPECT_EQ(env.sent.size(), 2u) << "a 200 needs no answer";

	trunk.tickRegistration(t0 + 60 * 1000, sbcAddr());
	EXPECT_EQ(env.sent.size(), 2u) << "no refresh half way through the lease";

	trunk.tickRegistration(t0 + 115 * 1000, sbcAddr());
	ASSERT_EQ(env.sent.size(), 3u) << "the binding must be refreshed before it lapses at 120 s";
	EXPECT_NE(env.sentRaw(2).find("nc=00000002"), std::string::npos)
		<< "the refresh re-signs against the cached nonce: " << env.sentRaw(2);
}

// #618: Engage answers a FAILED REGISTER with "200 Authorization failure", and
// .244 sits behind CGNAT. The console must show the reason phrase and what the
// carrier saw of us (Via received/rport), or "registered" cannot be trusted.
TEST(SipTrunkRegister, AFinalRegisterResponseLogsItsStatusLineAndViaReceived)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(regConfig());
	ASSERT_TRUE(trunk.setCredentials("s3cret-reg"));
	trunk.tickRegistration(steadyMs(), sbcAddr());
	ASSERT_EQ(env.sent.size(), 1u);

	std::string resp = regResponse(env.sentRaw(0), "SIP/2.0 200 Authorization failure",
		"Contact: <sip:198.51.100.14:5065>\r\n");
	const size_t rp = resp.find(";rport");
	ASSERT_NE(rp, std::string::npos) << resp;
	resp.replace(rp, 6, ";rport=40123;received=198.51.100.7");
	ASSERT_TRUE(trunk.handleResponse(responseFor(resp)));

	std::string line;
	for (const auto& l : env.logs)
		if (l.find("Trunk: REGISTER <-") != std::string::npos) line = l;
	std::printf("[#618] %s\n", line.c_str());
	EXPECT_NE(line.find("SIP/2.0 200 Authorization failure"), std::string::npos) << line;
	EXPECT_NE(line.find("received=198.51.100.7"), std::string::npos) << line;
	EXPECT_NE(line.find("rport=40123"), std::string::npos) << line;
	EXPECT_NE(line.find("Contact <sip:198.51.100.14:5065>"), std::string::npos) << line;
}

TEST(SipTrunkRegister, A407IsAnsweredInProxyAuthorization)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(regConfig());
	ASSERT_TRUE(trunk.setCredentials("s3cret-reg"));
	trunk.tickRegistration(steadyMs(), sbcAddr());
	ASSERT_EQ(env.sent.size(), 1u);

	ASSERT_TRUE(trunk.handleResponse(responseFor(regResponse(env.sentRaw(0),
		"SIP/2.0 407 Proxy Authentication Required",
		std::string("Proxy-Authenticate: ") + kRegChallenge + "\r\n"))));
	ASSERT_EQ(env.sent.size(), 2u);
	EXPECT_NE(env.sentRaw(1).find("\r\nProxy-Authorization: Digest username=\"authid399\""),
		std::string::npos) << env.sentRaw(1);
}

TEST(SipTrunkRegister, ARegisterResponseFromAnotherAddressIsConsumedAndIgnored)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(regConfig());
	ASSERT_TRUE(trunk.setCredentials("s3cret-reg"));
	trunk.tickRegistration(steadyMs(), sbcAddr());
	ASSERT_EQ(env.sent.size(), 1u);

	sockaddr_in forger = sbcAddr();
	forger.sin_addr.s_addr = inet_addr("198.51.100.7");   // TEST-NET-2
	const auto forged = std::make_shared<SipMessage>(regResponse(env.sentRaw(0),
		"SIP/2.0 401 Unauthorized", std::string("WWW-Authenticate: ") + kRegChallenge + "\r\n"),
		forger);

	EXPECT_TRUE(trunk.handleResponse(forged)) << "claimed, so no handset path sees it";
	EXPECT_EQ(env.sent.size(), 1u) << "and never answered: a signed REGISTER is not "
		"something a third party gets to ask for";
	EXPECT_EQ(trunk.registration().state(), SipRegistrationClient::State::Registering);
}

// #686: Engage answers a failed REGISTER "SIP/2.0 200 Authorization failure",
// no Expires, its own address as the only Contact (#618's capture). The code
// is 200; only the missing binding says it failed. Control: the same status
// line listing our binding registers, so the reason phrase is never read.
TEST(SipTrunkRegister, A200AuthorizationFailureListingOnlyTheCarriersContactIsNotARegistration)
{
	for (const bool echoOurs : {false, true})
	{
		FakePbxEnv env;
		SipTrunk trunk(env);
		trunk.setConfig(regConfig());
		ASSERT_TRUE(trunk.setCredentials("s3cret-reg"));
		trunk.tickRegistration(steadyMs(), sbcAddr());
		ASSERT_EQ(env.sent.size(), 1u);
		const std::string reg = env.sentRaw(0);

		ASSERT_TRUE(trunk.handleResponse(responseFor(regResponse(reg,
			"SIP/2.0 200 Authorization failure",
			echoOurs ? echoContact(reg) + "Expires: 3600\r\n"
			         : std::string("Contact: <sip:203.0.113.5:5065>\r\n")))));
		EXPECT_EQ(trunk.registration().state(), echoOurs
			? SipRegistrationClient::State::Registered
			: SipRegistrationClient::State::Failed) << (echoOurs ? "control" : "Engage's 200");
	}
}

// #686: the binding now decides registration, so a registrar that lists it
// under Contact's compact form "m:" (RFC 3261 §7.3.3) must still be read.
TEST(SipTrunkRegister, OurBindingUnderTheCompactContactFormRegisters)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(regConfig());
	ASSERT_TRUE(trunk.setCredentials("s3cret-reg"));
	trunk.tickRegistration(steadyMs(), sbcAddr());
	ASSERT_EQ(env.sent.size(), 1u);
	const std::string reg = env.sentRaw(0);

	ASSERT_TRUE(trunk.handleResponse(responseFor(regResponse(reg, "SIP/2.0 200 OK",
		"m: " + headerValue(reg, "Contact") + ";expires=90\r\n"))));
	EXPECT_EQ(trunk.registration().state(), SipRegistrationClient::State::Registered);
	EXPECT_EQ(trunk.registration().status().grantedExpiresSec, 90u);
}

// #617: Timer E. TransactionLayer::classify() excludes REGISTER, so before this
// nothing resent an unanswered one: one lost datagram cost a full Timer F plus
// backoff cycle. RFC 3261 §17.1.2.2: resend at T1, doubling, capped at T2.
TEST(SipTrunkRegister, AnUnansweredRegisterIsResentOnTheTimerESchedule)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(regConfig());
	ASSERT_TRUE(trunk.setCredentials("s3cret-reg"));
	const uint64_t t0 = steadyMs();
	trunk.tickRegistration(t0, sbcAddr());
	ASSERT_EQ(env.sent.size(), 1u);
	const std::string first = env.sentRaw(0);

	// T1=500 ms, then +1000, +2000, +4000, then capped at T2: +4000.
	const uint64_t due[] = {500, 1500, 3500, 7500, 11500};
	for (size_t i = 0; i < sizeof(due) / sizeof(due[0]); ++i)
	{
		trunk.tickRegistration(t0 + due[i] - 1, sbcAddr());
		ASSERT_EQ(env.sent.size(), 1u + i) << "resent early, before " << due[i] << " ms";
		trunk.tickRegistration(t0 + due[i], sbcAddr());
		ASSERT_EQ(env.sent.size(), 2u + i) << "no Timer E retransmit at " << due[i] << " ms";
		EXPECT_EQ(env.sentRaw(1 + i), first) << "a retransmit is the same request: same branch, same CSeq";
		EXPECT_EQ(env.sent[1 + i].to.sin_addr.s_addr, sbcAddr().sin_addr.s_addr);
	}
	EXPECT_EQ(trunk.registration().cseq(), 1u) << "a retransmit consumes no CSeq";

	// Any response ends the schedule.
	ASSERT_TRUE(trunk.handleResponse(responseFor(regResponse(first,
		"SIP/2.0 200 OK", echoContact(first) + "Expires: 3600\r\n"))));
	ASSERT_EQ(trunk.registration().state(), SipRegistrationClient::State::Registered);
	const size_t sentAtAnswer = env.sent.size();
	trunk.tickRegistration(t0 + 20000, sbcAddr());
	EXPECT_EQ(env.sent.size(), sentAtAnswer) << "a REGISTER that was answered is not resent";
}

// #617: a REGISTER response from anywhere but the SBC was dropped with only a
// log line. It is now counted, so spoofing shows up as a number.
TEST(SipTrunkRegister, AForgedRegisterResponseIsCounted)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(regConfig());
	ASSERT_TRUE(trunk.setCredentials("s3cret-reg"));
	trunk.tickRegistration(steadyMs(), sbcAddr());
	ASSERT_EQ(env.sent.size(), 1u);
	const std::string ok = regResponse(env.sentRaw(0), "SIP/2.0 200 OK",
		echoContact(env.sentRaw(0)) + "Expires: 3600\r\n");

	sockaddr_in forger = sbcAddr();
	forger.sin_addr.s_addr = inet_addr("198.51.100.7");   // TEST-NET-2
	EXPECT_EQ(trunk.forgedRegisterResponses(), 0u);
	EXPECT_TRUE(trunk.handleResponse(std::make_shared<SipMessage>(ok, forger)));
	EXPECT_EQ(trunk.forgedRegisterResponses(), 1u);
	EXPECT_EQ(trunk.registration().state(), SipRegistrationClient::State::Registering)
		<< "a forged 200 must not register us";

	// Control: the same 200 from the SBC is not counted, and does register.
	ASSERT_TRUE(trunk.handleResponse(responseFor(ok)));
	EXPECT_EQ(trunk.forgedRegisterResponses(), 1u);
	EXPECT_EQ(trunk.registration().state(), SipRegistrationClient::State::Registered);
}

// Issue #663: both drops are counted, and each logs only when its count reaches
// a power of two, so a spoofing flood costs log lines logarithmically. Five
// drops: counted 5, logged at 1, 2 and 4.
TEST(SipTrunkSource, ForgedDialogResponsesLogOnlyAtPowersOfTwo)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(workingConfig());
	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	ASSERT_NE(d, nullptr);
	const std::string ringing = withStatus(okFor(*d), "SIP/2.0 180 Ringing");
	env.logs.clear();

	for (int i = 0; i < 5; ++i)
	{
		EXPECT_TRUE(trunk.handleResponse(responseFrom(ringing, kForgerIp)));
	}
	EXPECT_EQ(trunk.forgedDialogResponses(), 5u);
	EXPECT_EQ(logsContaining(env, "dropped"), 3u) << "one line at 1, 2 and 4 each";
	EXPECT_EQ(logsContaining(env, "; 1 dropped so far"), 1u);
	EXPECT_EQ(logsContaining(env, "; 2 dropped so far"), 1u);
	EXPECT_EQ(logsContaining(env, "; 4 dropped so far"), 1u);
	EXPECT_EQ(logsContaining(env, "; 3 dropped so far"), 0u);
	EXPECT_EQ(logsContaining(env, "; 5 dropped so far"), 0u);
}

// Issue #666: the #356 BYE refusal gets the same treatment. Five refused BYEs:
// each answered 403, counted 5, logged at 1, 2 and 4.
TEST(SipTrunkSource, RefusedByesAreCountedAndLogOnlyAtPowersOfTwo)
{
	Answered a;
	for (int i = 0; i < 5; ++i)
	{
		a.env.sent.clear();
		ASSERT_TRUE(a.trunk.handleBye(carrierByeFrom(a.dialog(), kForgerIp, "wrong", "wrong")));
		ASSERT_EQ(a.env.sent.size(), 1u);
		EXPECT_EQ(firstLine(a.env.sentRaw(0)), "SIP/2.0 403 Forbidden") << "BYE " << i + 1;
	}
	EXPECT_EQ(a.trunk.refusedDialogByes(), 5u);
	EXPECT_EQ(logsContaining(a.env, "refused"), 3u) << "one line at 1, 2 and 4 each";
	EXPECT_EQ(logsContaining(a.env, "; 4 refused so far"), 1u);
	EXPECT_EQ(logsContaining(a.env, "; 3 refused so far"), 0u);
	EXPECT_EQ(logsContaining(a.env, "; 5 refused so far"), 0u);

	// Control: the carrier's own BYE is accepted and not counted.
	a.env.sent.clear();
	ASSERT_TRUE(a.trunk.handleBye(carrierByeFrom(a.dialog(), kSbcIp, "carrier-tag", a.ourTag)));
	EXPECT_EQ(firstLine(a.env.sentRaw(0)), "SIP/2.0 200 OK");
	EXPECT_EQ(a.trunk.refusedDialogByes(), 5u);
}

TEST(SipTrunkRegister, ForgedRegisterResponsesLogOnlyAtPowersOfTwo)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(regConfig());
	ASSERT_TRUE(trunk.setCredentials("s3cret-reg"));
	trunk.tickRegistration(steadyMs(), sbcAddr());
	ASSERT_EQ(env.sent.size(), 1u);
	const std::string ok = regResponse(env.sentRaw(0), "SIP/2.0 200 OK", "Expires: 3600\r\n");
	env.logs.clear();

	sockaddr_in forger = sbcAddr();
	forger.sin_addr.s_addr = inet_addr("198.51.100.7");   // TEST-NET-2
	for (int i = 0; i < 5; ++i)
	{
		EXPECT_TRUE(trunk.handleResponse(std::make_shared<SipMessage>(ok, forger)));
	}
	EXPECT_EQ(trunk.forgedRegisterResponses(), 5u);
	EXPECT_EQ(logsContaining(env, "REGISTER response from a non-carrier address"), 3u)
		<< "one line at 1, 2 and 4 each";
	EXPECT_EQ(logsContaining(env, "(4 so far)"), 1u);
	EXPECT_EQ(logsContaining(env, "(5 so far)"), 0u);
}

// ── #747: a handset hanging up while the carrier leg still rings ─────────────
//
// hangup() used to free an unanswered dialog without telling the carrier, so the
// far end kept ringing (and could answer a call nobody was left to take). A
// dialog that has had a provisional response now sends a CANCEL and waits out
// the INVITE's own final response.

TEST(SipTrunkCancel, BuildsTheCancelOfTheInviteItNames)
{
	auto d = pinnedDialog();
	d.toTag = "carrier-tag";   // latched from a 180: must NOT reach the CANCEL's To

	const std::string c = SipTrunk::buildCancel(d);

	EXPECT_EQ(firstLine(c), "CANCEL sip:+15551234567@203.0.113.5 SIP/2.0");
	EXPECT_TRUE(hasLine(c, "Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bKinvite01;rport"))
		<< "RFC 3261 s9.1: the INVITE's own branch, not a fresh one";
	EXPECT_TRUE(hasLine(c, "From: <sip:15551230000@203.0.113.5>;tag=ftag01"));
	EXPECT_TRUE(hasLine(c, "To: <sip:+15551234567@203.0.113.5>"))
		<< "the INVITE's To, which had no tag";
	EXPECT_TRUE(hasLine(c, "Call-ID: abc123@192.168.1.10"));
	EXPECT_TRUE(hasLine(c, "CSeq: 1 CANCEL")) << "the INVITE's CSeq number";
}

TEST(SipTrunkCancel, HangupOfARingingDialogSendsCancelAndTheCarrier487FreesIt)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	RecordingListener lis;
	trunk.setConfig(workingConfig());
	trunk.setListener(&lis);
	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	ASSERT_TRUE(trunk.handleResponse(responseFor(withStatus(okFor(*d), "SIP/2.0 180 Ringing"))));
	lis.events.clear();
	env.sent.clear();

	ASSERT_TRUE(trunk.hangup("handset-1"));

	ASSERT_EQ(env.sent.size(), 1u);
	EXPECT_EQ(firstLine(env.sentRaw(0)).substr(0, 6), "CANCEL");
	EXPECT_EQ(trunk.activeDialogs(), 1u) << "held until the INVITE's own final response";
	EXPECT_TRUE(trunk.hangup("handset-1")) << "a second hangup finds the dialog";
	EXPECT_EQ(trunk.activeDialogs(), 1u) << "and must not release it or send a second CANCEL";
	EXPECT_EQ(env.sent.size(), 1u);
	env.sent.clear();

	ASSERT_TRUE(trunk.handleResponse(responseFor(withStatus(okFor(*d), "SIP/2.0 487 Request Terminated"))));

	ASSERT_EQ(env.sent.size(), 1u);
	EXPECT_EQ(firstLine(env.sentRaw(0)).substr(0, 3), "ACK") << "s17.1.1.3: a non-2xx is ACKed";
	EXPECT_EQ(trunk.activeDialogs(), 0u);
	EXPECT_TRUE(lis.events.empty()) << "the handset was answered when it cancelled; nothing to tell";
}

TEST(SipTrunkCancel, A2xxThatCrossesTheCancelIsAckedAndByed)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	RecordingListener lis;
	trunk.setConfig(workingConfig());
	trunk.setListener(&lis);
	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	ASSERT_TRUE(trunk.handleResponse(responseFor(withStatus(okFor(*d), "SIP/2.0 180 Ringing"))));
	ASSERT_TRUE(trunk.hangup("handset-1"));   // CANCEL out
	lis.events.clear();
	env.sent.clear();

	// The carrier answered before the CANCEL reached it (s9.1).
	ASSERT_TRUE(trunk.handleResponse(responseFor(okFor(*d))));

	ASSERT_EQ(env.sent.size(), 2u);
	EXPECT_EQ(firstLine(env.sentRaw(0)).substr(0, 3), "ACK");
	EXPECT_EQ(firstLine(env.sentRaw(1)).substr(0, 3), "BYE") << "the call is up at the carrier and billing";
	EXPECT_TRUE(lis.events.empty()) << "the handset is gone: no answered event may bridge it";
	EXPECT_EQ(d->state, SipTrunk::State::Terminating);
}

// #794: hangup() before any provisional response used to free the slot, so the
// INVITE stayed live at the carrier with nobody to answer its 1xx or 2xx. The
// slot is now held; the CANCEL s9.1 forbade goes out on the first provisional.
TEST(SipTrunkCancel, HangupBeforeAnyProvisionalHoldsTheSlotAndTheFirst1xxSendsTheCancel)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	RecordingListener lis;
	trunk.setConfig(workingConfig());
	trunk.setListener(&lis);
	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	env.sent.clear();

	ASSERT_TRUE(trunk.hangup("handset-1"));

	EXPECT_TRUE(env.sent.empty()) << "RFC 3261 s9.1: no CANCEL before a provisional response";
	ASSERT_EQ(trunk.activeDialogs(), 1u) << "the INVITE is live at the carrier; the slot must wait for its answer";
	EXPECT_TRUE(trunk.hangup("handset-1")) << "a second hangup finds the dialog";
	EXPECT_TRUE(env.sent.empty()) << "and sends nothing either";

	ASSERT_TRUE(trunk.handleResponse(responseFor(withStatus(okFor(*d), "SIP/2.0 180 Ringing"))));

	ASSERT_EQ(env.sent.size(), 1u) << "exactly one CANCEL on the first provisional";
	EXPECT_EQ(firstLine(env.sentRaw(0)).substr(0, 6), "CANCEL");
	EXPECT_EQ(d->state, SipTrunk::State::Cancelling);
	EXPECT_TRUE(lis.events.empty()) << "the handset already hung up: no ringing event";
	env.sent.clear();

	ASSERT_TRUE(trunk.handleResponse(responseFor(withStatus(okFor(*d), "SIP/2.0 487 Request Terminated"))));

	ASSERT_EQ(env.sent.size(), 1u);
	EXPECT_EQ(firstLine(env.sentRaw(0)).substr(0, 3), "ACK");
	EXPECT_EQ(trunk.activeDialogs(), 0u);
	EXPECT_TRUE(lis.events.empty());
}

TEST(SipTrunkCancel, A2xxAsTheFirstResponseAfterAHangupInTryingIsAckedAndByedWithNoListenerEvent)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	RecordingListener lis;
	trunk.setConfig(workingConfig());
	trunk.setListener(&lis);
	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	ASSERT_TRUE(trunk.hangup("handset-1"));
	env.sent.clear();

	// The carrier answered without ever sending a provisional.
	ASSERT_TRUE(trunk.handleResponse(responseFor(okFor(*d))));

	ASSERT_EQ(env.sent.size(), 2u);
	EXPECT_EQ(firstLine(env.sentRaw(0)).substr(0, 3), "ACK");
	EXPECT_EQ(firstLine(env.sentRaw(1)).substr(0, 3), "BYE") << "the call is up at the carrier and billing";
	EXPECT_TRUE(lis.events.empty()) << "the handset is gone: no answered event may bridge it";
	EXPECT_EQ(d->state, SipTrunk::State::Terminating);
}

TEST(SipTrunkCancel, AFailureAsTheFirstResponseAfterAHangupInTryingIsAckedAndFreedQuietly)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	RecordingListener lis;
	trunk.setConfig(workingConfig());
	trunk.setListener(&lis);
	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	ASSERT_TRUE(trunk.hangup("handset-1"));
	env.sent.clear();

	ASSERT_TRUE(trunk.handleResponse(responseFor(withStatus(okFor(*d), "SIP/2.0 486 Busy Here"))));

	ASSERT_EQ(env.sent.size(), 1u);
	EXPECT_EQ(firstLine(env.sentRaw(0)).substr(0, 3), "ACK") << "s17.1.1.3: a non-2xx is ACKed";
	EXPECT_EQ(trunk.activeDialogs(), 0u);
	EXPECT_TRUE(lis.events.empty()) << "the handset already ended the call; no failure to relay";
}

TEST(SipTrunkCancel, AHangupInTryingThatNeverGetsAResponseIsSweptQuietlyAtTimerB)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	RecordingListener lis;
	trunk.setConfig(workingConfig());
	trunk.setListener(&lis);
	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	ASSERT_TRUE(trunk.hangup("handset-1"));
	ASSERT_EQ(trunk.activeDialogs(), 1u);

	trunk.sweep(std::chrono::steady_clock::now() + std::chrono::seconds(31));
	EXPECT_EQ(trunk.activeDialogs(), 1u) << "held for the INVITE's Timer B (32 s)";

	trunk.sweep(std::chrono::steady_clock::now() + std::chrono::seconds(33));

	EXPECT_EQ(trunk.activeDialogs(), 0u) << "a carrier that never answers cannot pin the slot";
	EXPECT_TRUE(lis.events.empty()) << "the handset already ended the call; no second failure";
}

TEST(SipTrunkCancel, ACancelledDialogThatNeverGetsAFinalResponseIsSweptQuietly)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	RecordingListener lis;
	trunk.setConfig(workingConfig());
	trunk.setListener(&lis);
	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	ASSERT_TRUE(trunk.handleResponse(responseFor(withStatus(okFor(*d), "SIP/2.0 180 Ringing"))));
	ASSERT_TRUE(trunk.hangup("handset-1"));
	lis.events.clear();

	trunk.sweep(std::chrono::steady_clock::now() + std::chrono::seconds(33));

	EXPECT_EQ(trunk.activeDialogs(), 0u);
	EXPECT_TRUE(lis.events.empty()) << "the handset already ended the call; no second failure";
}

// ── #687: answering a 401/407 on our BYE ────────────────────────────────────
//
// A carrier that challenges the BYE and gets no answer keeps the leg up and
// billing after the handset has hung up. The retry goes through the same
// digest path as the INVITE's (SipTrunkAuth.* above); same fixtures too:
// TEST-NET-3 through FakePbxEnv's capture, no real number dialled.
namespace
{
	// The Via branch of a request ("...;branch=X;rport").
	std::string branchOf(const std::string& msg)
	{
		const size_t b = msg.find(";branch=");
		if (b == std::string::npos) return {};
		const size_t v = b + 8;
		return msg.substr(v, msg.find_first_of(";\r", v) - v);
	}

	// The value of a quoted digest parameter (`response="..."`) in a message.
	std::string digestParam(const std::string& msg, const std::string& name)
	{
		const size_t p = msg.find(name + "=\"");
		if (p == std::string::npos) return {};
		const size_t v = p + name.size() + 2;
		return msg.substr(v, msg.find('"', v) - v);
	}

	// The carrier's answer to the BYE hangup() just sent -- CSeq d.cseq+1, as
	// buildBye() stamps it. `authenticate` names the challenge header for a
	// 401/407 ("WWW-Authenticate" / "Proxy-Authenticate"); a 200 carries none.
	std::string byeResponseFor(const SipTrunk::Dialog& d, int code, const char* authenticate = nullptr)
	{
		std::string r = okFor(d);
		if (code == 401) r.replace(0, r.find("\r\n"), "SIP/2.0 401 Unauthorized");
		if (code == 407) r.replace(0, r.find("\r\n"), "SIP/2.0 407 Proxy Authentication Required");
		const std::string cseqLine = "CSeq: " + std::to_string(d.cseq + 1) + " BYE";
		r.replace(r.find("CSeq: 1 INVITE"), std::string("CSeq: 1 INVITE").size(), cseqLine);
		if (authenticate)
		{
			r.insert(r.find("Content-Length"), std::string(authenticate)
				+ ": Digest realm=\"carrier.example\", nonce=\"n0nce687\", qop=\"auth\"\r\n");
		}
		return r;
	}

	// A call answered by the carrier and hung up by us: INVITE, its ACK and
	// the BYE are sent[0..2]. Checks the positive control here, once for every
	// test below -- the first BYE carries no credential, so a credential on
	// the retry is the change under test and not something every BYE has.
	struct ByeSent
	{
		FakePbxEnv  env;
		SipTrunk    trunk{env};
		std::string callId, fromTag, byeBranch;

		ByeSent(const SipTrunk::Config& cfg, const char* password)
		{
			trunk.setConfig(cfg);
			EXPECT_TRUE(trunk.setCredentials(password));
			EXPECT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
			const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
			EXPECT_TRUE(trunk.handleResponse(responseFor(okFor(*d))));   // answered
			EXPECT_TRUE(trunk.hangup("handset-1"));                      // BYE sent
			callId  = d->callID;
			fromTag = d->fromTag;
			EXPECT_EQ(env.sent.size(), 3u) << "INVITE, its ACK, the BYE";
			const std::string bye = env.sentRaw(2);
			EXPECT_EQ(firstLine(bye), "BYE sip:+15551234567@203.0.113.99:5060 SIP/2.0");
			EXPECT_TRUE(hasLine(bye, "CSeq: 2 BYE"));
			EXPECT_EQ(bye.find("Authorization"), std::string::npos)
				<< "positive control: the first BYE goes out uncredentialed";
			byeBranch = branchOf(bye);
			EXPECT_FALSE(byeBranch.empty());
		}
		// Only valid while the dialog is live.
		const SipTrunk::Dialog& dialog() const { return *trunk.findByCallID("handset-1"); }
	};
}

TEST(SipTrunkByeAuth, A401ToOurByeIsAnsweredOnceWithCredentialsAndNothingElse)
{
	ByeSent f(workingConfig(), "s3cret-687");
	ASSERT_EQ(f.env.sent.size(), 3u);

	ASSERT_TRUE(f.trunk.handleResponse(responseFor(byeResponseFor(f.dialog(), 401, "WWW-Authenticate"))));

	ASSERT_EQ(f.env.sent.size(), 4u)
		<< "exactly one credentialed BYE retry, and no ACK: a BYE is a non-INVITE transaction";
	const std::string retry = f.env.sentRaw(3);
	EXPECT_EQ(firstLine(retry), "BYE sip:+15551234567@203.0.113.99:5060 SIP/2.0") << "the same route";
	EXPECT_TRUE(hasLine(retry, "CSeq: 3 BYE")) << "CSeq+1 on the challenged BYE:\n" << retry;
	EXPECT_TRUE(hasLine(retry, "Call-ID: " + f.callId)) << "the same dialog";
	EXPECT_NE(retry.find(";tag=" + f.fromTag), std::string::npos) << "the same From-tag";
	EXPECT_NE(retry.find(";tag=carrier-tag"), std::string::npos) << "the same To-tag";
	EXPECT_NE(branchOf(retry), f.byeBranch) << "a fresh branch";
	EXPECT_NE(retry.find("\r\nAuthorization: Digest username=\"15551230000\""), std::string::npos) << retry;
	EXPECT_NE(retry.find("uri=\"sip:+15551234567@203.0.113.99:5060\""), std::string::npos)
		<< "the digest uri is the BYE's Request-URI, not the INVITE's:\n" << retry;
	EXPECT_NE(retry.find("nonce=\"n0nce687\""), std::string::npos) << "the BYE challenge's nonce, not a reused one";
	const std::string digest = digestParam(retry, "response");
	EXPECT_EQ(digest.size(), 32u) << retry;
	EXPECT_EQ(f.trunk.activeDialogs(), 1u) << "still Terminating, waiting on the retry's answer";
	EXPECT_EQ(f.trunk.refusedByeRetries(), 0u);

	// Nothing secret reaches the log: not the password, the nonce or the digest.
	EXPECT_FALSE(anySentOrLoggedContains(f.env, "s3cret-687"));
	EXPECT_EQ(logsContaining(f.env, "n0nce687"), 0u);
	EXPECT_EQ(logsContaining(f.env, digest), 0u);

	// The carrier accepts the retry: the dialog is over and nothing follows.
	ASSERT_TRUE(f.trunk.handleResponse(responseFor(byeResponseFor(f.dialog(), 200))));
	EXPECT_EQ(f.env.sent.size(), 4u) << "nothing follows the 200";
	EXPECT_EQ(f.trunk.activeDialogs(), 0u);
	EXPECT_EQ(f.trunk.refusedByeRetries(), 0u) << "an accepted retry is not a refused one";
}

TEST(SipTrunkByeAuth, ARetryRefusedAgainIsNotRetriedAndIsCounted)
{
	ByeSent f(workingConfig(), "wrong-password");
	ASSERT_TRUE(f.trunk.handleResponse(responseFor(byeResponseFor(f.dialog(), 401, "WWW-Authenticate"))));
	ASSERT_EQ(f.env.sent.size(), 4u) << "the one credentialed retry";
	ASSERT_EQ(f.trunk.activeDialogs(), 1u);

	ASSERT_TRUE(f.trunk.handleResponse(responseFor(byeResponseFor(f.dialog(), 401, "WWW-Authenticate"))));

	EXPECT_EQ(f.env.sent.size(), 4u) << "no third BYE, and no ACK -- never a loop";
	EXPECT_EQ(f.trunk.activeDialogs(), 0u) << "released regardless, as before #687";
	EXPECT_EQ(f.trunk.refusedByeRetries(), 1u);
	EXPECT_EQ(logsContaining(f.env, "credentialed BYE retry answered 401"), 1u) << "one WARN";
	EXPECT_FALSE(anySentOrLoggedContains(f.env, "wrong-password"));
}

TEST(SipTrunkByeAuth, ALateCopyOfTheFirstChallengeNeitherCountsNorEndsTheRetry)
{
	ByeSent f(workingConfig(), "s3cret-687");
	const std::string first401 = byeResponseFor(f.dialog(), 401, "WWW-Authenticate");   // CSeq 2, the first BYE
	ASSERT_TRUE(f.trunk.handleResponse(responseFor(first401)));
	ASSERT_EQ(f.env.sent.size(), 4u) << "the one credentialed retry (CSeq 3)";

	// The carrier's UDP retransmission of that first 401, landing after the retry went out.
	EXPECT_TRUE(f.trunk.handleResponse(responseFor(first401)));
	EXPECT_EQ(f.env.sent.size(), 4u) << "nothing is sent for it";
	EXPECT_EQ(f.trunk.activeDialogs(), 1u) << "the retry's transaction is still live";
	EXPECT_EQ(f.trunk.refusedByeRetries(), 0u) << "a stale copy is not a refused retry";
	EXPECT_EQ(logsContaining(f.env, "credentialed BYE retry answered"), 0u) << "and no false WARN";

	ASSERT_TRUE(f.trunk.handleResponse(responseFor(byeResponseFor(f.dialog(), 200))));
	EXPECT_EQ(f.trunk.activeDialogs(), 0u) << "the retry's own 200 ends the dialog";
}

TEST(SipTrunkByeAuth, A407ToOurByeIsAnsweredInProxyAuthorizationAsTheAuthUser)
{
	SipTrunk::Config cfg = workingConfig();
	std::snprintf(cfg.authUser, sizeof(cfg.authUser), "%s", "auth-id-687");
	ByeSent f(cfg, "s3cret-687");

	ASSERT_TRUE(f.trunk.handleResponse(responseFor(byeResponseFor(f.dialog(), 407, "Proxy-Authenticate"))));

	ASSERT_EQ(f.env.sent.size(), 4u);
	const std::string retry = f.env.sentRaw(3);
	EXPECT_EQ(firstLine(retry), "BYE sip:+15551234567@203.0.113.99:5060 SIP/2.0");
	EXPECT_TRUE(hasLine(retry, "CSeq: 3 BYE"));
	EXPECT_NE(retry.find("\r\nProxy-Authorization: Digest username=\"auth-id-687\""), std::string::npos)
		<< "a 407 is answered in Proxy-Authorization, as the configured auth ID:\n" << retry;
	EXPECT_EQ(retry.find("\r\nAuthorization:"), std::string::npos);
	EXPECT_NE(retry.find("uri=\"sip:+15551234567@203.0.113.99:5060\""), std::string::npos);
	EXPECT_EQ(f.trunk.activeDialogs(), 1u);
	EXPECT_EQ(f.trunk.refusedByeRetries(), 0u);
}

// ── Record-Route (#748) ──────────────────────────────────────────────────────
//
// RFC 3261 s12.1.2: the UAC's route set is the 2xx's Record-Route, reversed.
// s12.2.1.1: every in-dialog request carries it, and goes to its first hop.

namespace
{
	// A 200 to the INVITE with `recordRoute` (complete header lines) added.
	std::string okWithRecordRoute(const SipTrunk::Dialog& d, const std::string& recordRoute)
	{
		std::string ok = okFor(d);
		ok.insert(ok.find("Contact:"), recordRoute);
		return ok;
	}

	const std::string kRouteHeader = "Route: <sip:198.51.100.7:5070;lr>, <sip:198.51.100.8:5062;lr>";
}

TEST(SipTrunkRoute, AckAndByeCarryTheRouteSetOnlyWhenThereIsOne)
{
	auto d = pinnedDialog();
	d.toTag        = "carrier-tag";
	d.remoteTarget = "sip:+15551234567@203.0.113.99:5060";

	EXPECT_EQ(SipTrunk::buildBye(d, "z9hG4bKbye77").find("Route:"), std::string::npos);
	EXPECT_EQ(SipTrunk::buildAckFor2xx(d, "z9hG4bKack99").find("Route:"), std::string::npos);

	d.routeSet = "<sip:198.51.100.7:5070;lr>, <sip:198.51.100.8:5062;lr>";
	EXPECT_TRUE(hasLine(SipTrunk::buildBye(d, "z9hG4bKbye77"), kRouteHeader));
	EXPECT_TRUE(hasLine(SipTrunk::buildAckFor2xx(d, "z9hG4bKack99"), kRouteHeader));
	// Out of dialog, or in the INVITE's own transaction: no Route.
	EXPECT_EQ(SipTrunk::buildInvite(d, "v=0\r\n").find("Route:"), std::string::npos);
	EXPECT_EQ(SipTrunk::buildAckForFailure(d).find("Route:"), std::string::npos);
}

TEST(SipTrunkRoute, TwoXxRecordRouteIsReversedAndAckAndByeGoToTheFirstHop)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(workingConfig());
	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	ASSERT_NE(d, nullptr);

	// As the carrier's UAS copied them: the hop nearest the carrier first.
	ASSERT_TRUE(trunk.handleResponse(responseFor(okWithRecordRoute(*d,
		"Record-Route: <sip:198.51.100.8:5062;lr>\r\n"
		"Record-Route: <sip:198.51.100.7:5070;lr>\r\n"))));
	EXPECT_EQ(d->routeSet, "<sip:198.51.100.7:5070;lr>, <sip:198.51.100.8:5062;lr>");

	const sockaddr_in hop = FakePbxEnv::addr("198.51.100.7", 5070);
	ASSERT_EQ(env.sent.size(), 2u);
	EXPECT_EQ(env.sent[1].raw.substr(0, 3), "ACK");
	EXPECT_TRUE(hasLine(env.sent[1].raw, kRouteHeader));
	EXPECT_EQ(env.sent[1].to.sin_addr.s_addr, hop.sin_addr.s_addr);
	EXPECT_EQ(env.sent[1].to.sin_port, hop.sin_port);

	ASSERT_TRUE(trunk.hangup("handset-1"));
	ASSERT_EQ(env.sent.size(), 3u);
	EXPECT_EQ(env.sent[2].raw.substr(0, 3), "BYE");
	EXPECT_TRUE(hasLine(env.sent[2].raw, kRouteHeader));
	EXPECT_EQ(env.sent[2].to.sin_addr.s_addr, hop.sin_addr.s_addr);
	EXPECT_EQ(env.sent[2].to.sin_port, hop.sin_port);

	// The 200 to the BYE comes back from the hop. An unrelated address is still
	// dropped as forged (#356), so the hop's is not a blanket allowance.
	const std::string byeOk = okFor(*d);
	ASSERT_TRUE(trunk.handleResponse(std::make_shared<SipMessage>(byeOk,
		FakePbxEnv::addr("198.51.100.99", 5060))));
	EXPECT_EQ(trunk.forgedDialogResponses(), 1u);
	EXPECT_EQ(trunk.activeDialogs(), 1u);
	ASSERT_TRUE(trunk.handleResponse(std::make_shared<SipMessage>(byeOk, hop)));
	EXPECT_EQ(trunk.forgedDialogResponses(), 1u);
	EXPECT_EQ(trunk.activeDialogs(), 0u);
}

TEST(SipTrunkRoute, OneRecordRouteLineWithSeveralEntriesIsSplitAndReversed)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(workingConfig());
	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	ASSERT_NE(d, nullptr);

	ASSERT_TRUE(trunk.handleResponse(responseFor(okWithRecordRoute(*d,
		"Record-Route: <sip:198.51.100.8:5062;lr>, <sip:198.51.100.7:5070;lr>\r\n"))));
	EXPECT_EQ(d->routeSet, "<sip:198.51.100.7:5070;lr>, <sip:198.51.100.8:5062;lr>");
}

// No Record-Route, a strict-router first hop, or an FQDN hop: the ACK and BYE
// still go to the peer, as they did before #748.
TEST(SipTrunkRoute, NoUsableRouteSetLeavesAckAndByeOnThePeer)
{
	const char* cases[] = {
		"",                                                        // none
		"Record-Route: <sip:198.51.100.7:5070>\r\n",               // strict router
	};
	for (const char* rr : cases)
	{
		FakePbxEnv env;
		SipTrunk trunk(env);
		trunk.setConfig(workingConfig());
		ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
		const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
		ASSERT_NE(d, nullptr);
		ASSERT_TRUE(trunk.handleResponse(responseFor(okWithRecordRoute(*d, rr))));
		ASSERT_TRUE(trunk.hangup("handset-1"));
		ASSERT_EQ(env.sent.size(), 3u) << rr;
		for (size_t i = 1; i < 3; ++i)
		{
			EXPECT_EQ(env.sent[i].raw.find("Route:"), std::string::npos) << rr;
			EXPECT_EQ(env.sent[i].to.sin_addr.s_addr, sbcAddr().sin_addr.s_addr) << rr;
		}
	}

	// An FQDN hop keeps its Route header (the carrier's proxy reads it) but
	// cannot be resolved here, so the packet still goes to the peer.
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(workingConfig());
	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	ASSERT_NE(d, nullptr);
	ASSERT_TRUE(trunk.handleResponse(responseFor(okWithRecordRoute(*d,
		"Record-Route: <sip:sbc.carrier.example;lr>\r\n"))));
	ASSERT_EQ(env.sent.size(), 2u);
	EXPECT_TRUE(hasLine(env.sent[1].raw, "Route: <sip:sbc.carrier.example;lr>"));
	EXPECT_EQ(env.sent[1].to.sin_addr.s_addr, sbcAddr().sin_addr.s_addr);
}

// #775 review: the 407/401 retry of a BYE is an in-dialog request like the one it
// answers, so it carries the same Route set and goes to the same first hop. Left
// on d.peer it reached the carrier with a Route naming a proxy it had skipped.
TEST(SipTrunkRoute, ByeChallengeRetryGoesToTheFirstHopWithTheRouteSet)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(workingConfig());
	ASSERT_TRUE(trunk.setCredentials("s3cret-775"));
	ASSERT_TRUE(trunk.placeCall("+15551234567", "handset-1", sbcAddr(), 40000));
	const SipTrunk::Dialog* d = trunk.findByCallID("handset-1");
	ASSERT_NE(d, nullptr);
	ASSERT_TRUE(trunk.handleResponse(responseFor(okWithRecordRoute(*d,
		"Record-Route: <sip:198.51.100.8:5062;lr>\r\n"
		"Record-Route: <sip:198.51.100.7:5070;lr>\r\n"))));
	ASSERT_TRUE(trunk.hangup("handset-1"));
	ASSERT_EQ(env.sent.size(), 3u) << "INVITE, its ACK, the BYE";
	const sockaddr_in hop = FakePbxEnv::addr("198.51.100.7", 5070);
	ASSERT_EQ(env.sent[2].to.sin_addr.s_addr, hop.sin_addr.s_addr) << "positive control: the first BYE goes to the hop";

	// The challenge comes back from the hop that took the BYE.
	ASSERT_TRUE(trunk.handleResponse(std::make_shared<SipMessage>(
		byeResponseFor(*d, 407, "Proxy-Authenticate"), hop)));

	ASSERT_EQ(env.sent.size(), 4u);
	EXPECT_EQ(env.sent[3].raw.substr(0, 3), "BYE");
	EXPECT_NE(env.sent[3].raw.find("\r\nProxy-Authorization: Digest"), std::string::npos);
	EXPECT_TRUE(hasLine(env.sent[3].raw, kRouteHeader));
	EXPECT_EQ(env.sent[3].to.sin_addr.s_addr, hop.sin_addr.s_addr)
		<< "the retry follows the Route set to its first hop, not the carrier peer";
	EXPECT_EQ(env.sent[3].to.sin_port, hop.sin_port);
}
