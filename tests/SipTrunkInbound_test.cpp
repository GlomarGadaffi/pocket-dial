// SipTrunkInbound_test.cpp — issue #398 part A: SipTrunk answers a call.
//
// The carrier places the call, so the PBX is the UAS on the trunk dialog and
// every identifier sits the other way round from an outbound call: the
// carrier's From tag is the remote tag, ours goes in To, the remote target is
// the INVITE's Contact, and our BYE takes our own CSeq (RFC 3261 s12.1.1,
// s12.2.1.1). Nothing in RequestsHandler calls this yet; part C wires it.
//
// The outbound builders are pinned byte for byte first: part A adds a role to
// the dialog, and an outbound call must not change by a single byte.
//
// Numbers are the fictional 555-01xx range; addresses are RFC 5737 TEST-NETs.

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
	// An outbound dialog after its 2xx, with every field a builder reads fixed.
	SipTrunk::Dialog outboundDialog()
	{
		SipTrunk::Dialog d;
		d.state        = SipTrunk::State::Confirmed;
		d.callID       = "abc123@192.168.1.10";
		d.branch       = "z9hG4bKinvite01";
		d.fromTag      = "ftag01";
		d.toTag        = "carrier-tag";
		d.cseq         = 1;
		d.domain       = "203.0.113.5";
		d.localIpPort  = "192.168.1.10:5060";
		d.destE164     = "+15551234567";
		d.fromUser     = "15551230000";
		d.remoteTarget = "sip:+15551234567@203.0.113.99:5060";
		d.routeSet     = "<sip:203.0.113.7;lr>";
		return d;
	}
}

// ── Outbound: unchanged, byte for byte (captured from main 4e56650) ──────────

TEST(SipTrunkOutboundGolden, EveryBuilderIsByteForByteUnchanged)
{
	const auto d = outboundDialog();

	EXPECT_EQ(SipTrunk::buildInvite(d, "v=0\r\n"),
		"INVITE sip:+15551234567@203.0.113.5 SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bKinvite01;rport\r\n"
		"From: <sip:15551230000@203.0.113.5>;tag=ftag01\r\n"
		"To: <sip:+15551234567@203.0.113.5>\r\n"
		"Call-ID: abc123@192.168.1.10\r\n"
		"CSeq: 1 INVITE\r\n"
		"Max-Forwards: 70\r\n"
		"User-Agent: pocket-dial\r\n"
		"Contact: <sip:15551230000@192.168.1.10:5060;transport=udp>\r\n"
		"Allow: INVITE, ACK, BYE, CANCEL, OPTIONS\r\n"
		"Content-Type: application/sdp\r\n"
		"Content-Length: 5\r\n\r\n"
		"v=0\r\n");

	EXPECT_EQ(SipTrunk::buildAckFor2xx(d, "z9hG4bKack02"),
		"ACK sip:+15551234567@203.0.113.99:5060 SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bKack02;rport\r\n"
		"Route: <sip:203.0.113.7;lr>\r\n"
		"From: <sip:15551230000@203.0.113.5>;tag=ftag01\r\n"
		"To: <sip:+15551234567@203.0.113.5>;tag=carrier-tag\r\n"
		"Call-ID: abc123@192.168.1.10\r\n"
		"CSeq: 1 ACK\r\n"
		"Max-Forwards: 70\r\n"
		"User-Agent: pocket-dial\r\n"
		"Content-Length: 0\r\n\r\n");

	EXPECT_EQ(SipTrunk::buildAckForFailure(d),
		"ACK sip:+15551234567@203.0.113.5 SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bKinvite01;rport\r\n"
		"From: <sip:15551230000@203.0.113.5>;tag=ftag01\r\n"
		"To: <sip:+15551234567@203.0.113.5>;tag=carrier-tag\r\n"
		"Call-ID: abc123@192.168.1.10\r\n"
		"CSeq: 1 ACK\r\n"
		"Max-Forwards: 70\r\n"
		"User-Agent: pocket-dial\r\n"
		"Content-Length: 0\r\n\r\n");

	EXPECT_EQ(SipTrunk::buildBye(d, "z9hG4bKbye03", "Authorization: Digest x"),
		"BYE sip:+15551234567@203.0.113.99:5060 SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bKbye03;rport\r\n"
		"Route: <sip:203.0.113.7;lr>\r\n"
		"From: <sip:15551230000@203.0.113.5>;tag=ftag01\r\n"
		"To: <sip:+15551234567@203.0.113.5>;tag=carrier-tag\r\n"
		"Call-ID: abc123@192.168.1.10\r\n"
		"CSeq: 2 BYE\r\n"
		"Max-Forwards: 70\r\n"
		"User-Agent: pocket-dial\r\n"
		"Authorization: Digest x\r\n"
		"Content-Length: 0\r\n\r\n");

	EXPECT_EQ(SipTrunk::buildCancel(d),
		"CANCEL sip:+15551234567@203.0.113.5 SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bKinvite01;rport\r\n"
		"From: <sip:15551230000@203.0.113.5>;tag=ftag01\r\n"
		"To: <sip:+15551234567@203.0.113.5>\r\n"
		"Call-ID: abc123@192.168.1.10\r\n"
		"CSeq: 1 CANCEL\r\n"
		"Max-Forwards: 70\r\n"
		"User-Agent: pocket-dial\r\n"
		"Content-Length: 0\r\n\r\n");
}

// ── Inbound: the carrier calls us ────────────────────────────────────────────

namespace
{
	constexpr const char* kSbcIp    = "203.0.113.5";     // RFC 5737 TEST-NET-3
	constexpr const char* kForgerIp = "198.51.100.66";   // RFC 5737 TEST-NET-2
	constexpr const char* kCallId   = "carrier-call-1@203.0.113.5";
	constexpr const char* kFork     = "handset-fork-1";  // the fork's own Call-ID (part C)

	SipTrunk::Config workingConfig()
	{
		SipTrunk::Config c;
		std::snprintf(c.host, sizeof(c.host), "%s", kSbcIp);
		c.port = 5060;
		std::snprintf(c.fromUser, sizeof(c.fromUser), "%s", "15551230000");
		c.enabled = true;
		return c;
	}

	// As a Record-Routing SBC sends it: two Vias (the top asking for rport), a
	// display name in From. `padLines` extra headers before Max-Forwards push
	// the message past the 64-line cap (#838).
	std::string carrierInviteText(const std::string& callId = kCallId,
		const std::string& toParams = "", bool withContact = true, int padLines = 0)
	{
		const std::string sdp =
			"v=0\r\no=- 0 0 IN IP4 203.0.113.9\r\ns=-\r\nc=IN IP4 203.0.113.9\r\n"
			"t=0 0\r\nm=audio 41000 RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\n";
		std::string pad;
		for (int i = 0; i < padLines; ++i) pad += "X-Pad-" + std::to_string(i) + ": x\r\n";
		return
			"INVITE sip:15551230000@192.168.1.10:5060 SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 203.0.113.5:5060;branch=z9hG4bKsbc1;rport\r\n"
			"Via: SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bKcore1;received=10.0.0.9\r\n"
			"Record-Route: <sip:203.0.113.5;lr>\r\n"
			"From: \"Caller\" <sip:+12025550177@203.0.113.5>;tag=carrier-ftag\r\n"
			"To: <sip:+12025550188@192.168.1.10>" + toParams + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 101 INVITE\r\n" +
			std::string(withContact ? "Contact: <sip:+12025550177@203.0.113.9:5060>\r\n" : "") + pad +
			"Max-Forwards: 69\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(sdp.size()) + "\r\n\r\n" + sdp;
	}

	// From the SBC's address, but source port 5062: what the top Via's rport learns.
	std::shared_ptr<SipMessage> fromSbc(const std::string& raw)
	{
		return std::make_shared<SipMessage>(raw, FakePbxEnv::addr(kSbcIp, 5062));
	}

	std::shared_ptr<SipMessage> carrierInvite(const std::string& callId = kCallId,
		const std::string& toParams = "", bool withContact = true)
	{
		return fromSbc(carrierInviteText(callId, toParams, withContact));
	}

	std::string replaced(std::string s, const std::string& from, const std::string& to)
	{
		s.replace(s.find(from), from.size(), to);
		return s;
	}

	// The carrier hanging up, from `ip`, with the given From and To tags.
	std::shared_ptr<SipMessage> carrierBye(const char* ip, const std::string& fromTag, const std::string& toTag)
	{
		const std::string raw =
			"BYE sip:15551230000@192.168.1.10:5060 SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(ip) + ":5060;branch=z9hG4bKcbye\r\n"
			"From: <sip:+12025550177@203.0.113.5>;tag=" + fromTag + "\r\n"
			"To: <sip:+12025550188@192.168.1.10>;tag=" + toTag + "\r\n"
			"Call-ID: " + std::string(kCallId) + "\r\n"
			"CSeq: 102 BYE\r\n"
			"Content-Length: 0\r\n\r\n";
		return std::make_shared<SipMessage>(raw, FakePbxEnv::addr(ip, 5060));
	}

	// The carrier's answer to a request we sent: `status` over that request's headers.
	std::shared_ptr<SipMessage> carrierAnswer(const std::string& ours, const std::string& status,
		const std::string& extraHeader = "")
	{
		const size_t from = ours.find("\r\n");
		const std::string head = ours.substr(from, ours.find("Content-Length:") - from);
		const std::string raw = status + head + extraHeader + "Content-Length: 0\r\n\r\n";
		return std::make_shared<SipMessage>(raw, FakePbxEnv::addr(kSbcIp, 5060));
	}

	std::string firstLine(const std::string& msg) { return msg.substr(0, msg.find("\r\n")); }

	std::string lineStarting(const std::string& msg, const std::string& prefix)
	{
		const size_t p = msg.find("\r\n" + prefix);
		if (p == std::string::npos) return {};
		return msg.substr(p + 2, msg.find("\r\n", p + 2) - p - 2);
	}

	struct Recorder : SipTrunk::Listener
	{
		std::vector<std::string> events;
		void onTrunkRinging(const SipTrunk::TrunkEvent&, bool, const std::shared_ptr<SipMessage>&) override
		{ events.push_back("ringing"); }
		void onTrunkAnswered(const SipTrunk::TrunkEvent&, const std::shared_ptr<SipMessage>&) override
		{ events.push_back("answered"); }
		void onTrunkFailed(const SipTrunk::TrunkEvent&, int status) override
		{ events.push_back("failed " + std::to_string(status)); }
		void onTrunkRemoteBye(const SipTrunk::TrunkEvent&) override { events.push_back("remoteBye"); }
	};

	// A configured trunk that has taken carrierInvite() into a slot.
	struct Inbound
	{
		FakePbxEnv env;
		SipTrunk   trunk{env};
		Recorder   lis;

		Inbound()
		{
			trunk.setConfig(workingConfig());
			trunk.setListener(&lis);
			EXPECT_EQ(trunk.acceptCall(*carrierInvite(), kFork, 40000), 0);
		}
		const SipTrunk::Dialog* dialog() const { return trunk.findByCallID(kFork); }
		bool sentTo(size_t i, const char* ip) const
		{
			return i < env.sent.size() && env.sent[i].to.sin_addr.s_addr == inet_addr(ip);
		}
	};

	const std::string kVias =
		"Via: SIP/2.0/UDP 203.0.113.5:5060;branch=z9hG4bKsbc1;rport\r\n"
		"Via: SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bKcore1;received=10.0.0.9\r\n";
	// As a response carries them: the top one stamped (RFC 3261 s18.2.1, RFC 3581 s4).
	const std::string kEchoedVias =
		"Via: SIP/2.0/UDP 203.0.113.5:5060;branch=z9hG4bKsbc1;rport=5062;received=203.0.113.5\r\n"
		"Via: SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bKcore1;received=10.0.0.9\r\n";
	const std::string kEchoed =
		"From: \"Caller\" <sip:+12025550177@203.0.113.5>;tag=carrier-ftag\r\n"
		"To: <sip:+12025550188@192.168.1.10>;tag=ourtag01\r\n"
		"Call-ID: carrier-call-1@203.0.113.5\r\n"
		"CSeq: 101 INVITE\r\n";

	SipTrunk::Dialog pinnedInbound()
	{
		return SipTrunk::dialogFromInvite(*carrierInvite(), "ourtag01", "192.168.1.10:5060", "15551230000");
	}
}

// ── The dialog and the builders (pure) ────────────────────────────────────────

TEST(SipTrunkInbound, ADialogFromTheInviteTakesTheCarriersIdentifiers)
{
	const auto d = pinnedInbound();

	EXPECT_EQ(d.role, SipTrunk::Role::Inbound);
	EXPECT_EQ(d.callID, kCallId) << "bare, as handleBye() matches it";
	EXPECT_EQ(d.fromTag, "carrier-ftag") << "the carrier's From tag is the remote tag";
	EXPECT_EQ(d.toTag, "ourtag01") << "ours goes in To";
	EXPECT_EQ(d.remoteTarget, "sip:+12025550177@203.0.113.9:5060") << "in-dialog requests go to its Contact";
	EXPECT_EQ(d.remoteCseq, 101u);
	EXPECT_EQ(d.cseq, 0u) << "our own sequence number is empty until our first request (s12.1.1)";
	EXPECT_EQ(d.inviteVias, kEchoedVias) << "every Via, in order, the top one stamped";
}

TEST(SipTrunkInbound, TheTopViaComesBackWithReceivedAndItsRportFilled)
{
	const std::string trying = SipTrunk::buildResponse(pinnedInbound(), 100);
	EXPECT_EQ(lineStarting(trying, "Via: "),
		"Via: SIP/2.0/UDP 203.0.113.5:5060;branch=z9hG4bKsbc1;rport=5062;received=203.0.113.5")
		<< "RFC 3581 s4: the source port the INVITE came from, and received";
	EXPECT_NE(trying.find("\r\nVia: SIP/2.0/UDP 10.0.0.9:5060;branch=z9hG4bKcore1;received=10.0.0.9\r\n"),
		std::string::npos) << "only the top Via is ours to stamp";
}

TEST(SipTrunkInbound, TheTryingEchoesEveryViaAndCarriesOurTag)
{
	EXPECT_EQ(SipTrunk::buildResponse(pinnedInbound(), 100),
		"SIP/2.0 100 Trying\r\n" + kEchoedVias + kEchoed +
		"Content-Length: 0\r\n\r\n");
}

TEST(SipTrunkInbound, TheRingingAddsRecordRouteAndOurContact)
{
	EXPECT_EQ(SipTrunk::buildResponse(pinnedInbound(), 180),
		"SIP/2.0 180 Ringing\r\n" + kEchoedVias +
		"Record-Route: <sip:203.0.113.5;lr>\r\n" + kEchoed +
		"Contact: <sip:15551230000@192.168.1.10:5060;transport=udp>\r\n"
		"Content-Length: 0\r\n\r\n");
}

TEST(SipTrunkInbound, TheOkCarriesTheSdpAnswer)
{
	EXPECT_EQ(SipTrunk::buildResponse(pinnedInbound(), 200, "v=0\r\n"),
		"SIP/2.0 200 OK\r\n" + kEchoedVias +
		"Record-Route: <sip:203.0.113.5;lr>\r\n" + kEchoed +
		"Contact: <sip:15551230000@192.168.1.10:5060;transport=udp>\r\n"
		"Allow: INVITE, ACK, BYE, CANCEL, OPTIONS\r\n"
		"Content-Type: application/sdp\r\n"
		"Content-Length: 5\r\n\r\n"
		"v=0\r\n");
}

TEST(SipTrunkInbound, OurByeIsTheUasFormWithOurOwnCseq)
{
	EXPECT_EQ(SipTrunk::buildBye(pinnedInbound(), "z9hG4bKbye09"),
		"BYE sip:+12025550177@203.0.113.9:5060 SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.1.10:5060;branch=z9hG4bKbye09;rport\r\n"
		"From: <sip:+12025550188@192.168.1.10>;tag=ourtag01\r\n"
		"To: <sip:+12025550177@203.0.113.5>;tag=carrier-ftag\r\n"
		"Call-ID: carrier-call-1@203.0.113.5\r\n"
		"CSeq: 1 BYE\r\n"
		"Max-Forwards: 70\r\n"
		"User-Agent: pocket-dial\r\n"
		"Content-Length: 0\r\n\r\n")
		<< "RFC 3261 s12.2.1.1: our CSeq, never the INVITE's 101 + 1";
}

// ── The slot ──────────────────────────────────────────────────────────────────

TEST(SipTrunkInbound, AcceptingHoldsOneSlotUnderBothCallIdsAndSendsNothing)
{
	Inbound in;
	ASSERT_NE(in.dialog(), nullptr);
	EXPECT_EQ(in.trunk.activeDialogs(), 1u);
	EXPECT_TRUE(in.env.sent.empty());
	EXPECT_TRUE(in.trunk.ownsCallID("Call-ID: carrier-call-1@203.0.113.5")) << "the carrier's Call-ID";
	EXPECT_TRUE(in.trunk.ownsCallID(kFork)) << "and the fork's own";
	EXPECT_EQ(in.dialog()->state, SipTrunk::State::Trying);
	EXPECT_EQ(in.dialog()->peer.sin_addr.s_addr, inet_addr(kSbcIp));
}

TEST(SipTrunkInbound, AcceptingRefusesWhatItCouldNotAnswerOrEnd)
{
	// Each refusal names the final the caller answers the carrier with; nothing is claimed.
	FakePbxEnv env;
	SipTrunk trunk(env);
	EXPECT_EQ(trunk.acceptCall(*carrierInvite(), kFork, 40000), 503) << "an unconfigured trunk";

	trunk.setConfig(workingConfig());
	EXPECT_EQ(trunk.acceptCall(*carrierInvite("c-tagged", ";tag=x"), "f1", 40000), 481)
		<< "a To tag: a dialog we do not have";
	EXPECT_EQ(trunk.acceptCall(*carrierInvite("c-nocontact", "", false), "f2", 40000), 400)
		<< "no Contact: the call could never be BYEd";
	ASSERT_EQ(trunk.acceptCall(*carrierInvite(), kFork, 40000), 0);
	EXPECT_EQ(trunk.acceptCall(*carrierInvite(), "f3", 40000), 482)
		<< "the same Call-ID twice: a merged request (s8.2.2.2)";
	for (int i = 1; i < static_cast<int>(POCKETDIAL_MAX_TRUNK_CALLS); ++i)
	{
		ASSERT_EQ(trunk.acceptCall(*carrierInvite("c-" + std::to_string(i)), "g" + std::to_string(i), 40000), 0);
	}
	EXPECT_EQ(trunk.acceptCall(*carrierInvite("c-over"), "f4", 40000), 486) << "no free slot";
	EXPECT_EQ(trunk.activeDialogs(), static_cast<size_t>(POCKETDIAL_MAX_TRUNK_CALLS));
	EXPECT_TRUE(env.sent.empty());
}

TEST(SipTrunkInbound, AFromWithoutATagIsABadRequest)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(workingConfig());

	EXPECT_EQ(trunk.acceptCall(*fromSbc(replaced(carrierInviteText(), ";tag=carrier-ftag", "")), kFork, 40000), 400)
		<< "RFC 3261 s8.1.1.3: without it our BYE would carry an empty To tag";
	EXPECT_EQ(trunk.activeDialogs(), 0u);
}

TEST(SipTrunkInbound, AContactThatIsNotASipUriIsABadRequest)
{
	FakePbxEnv env;
	SipTrunk trunk(env);
	trunk.setConfig(workingConfig());
	const std::string contact = "Contact: <sip:+12025550177@203.0.113.9:5060>";

	for (const char* bad : { "Contact: *", "Contact: <tel:+12025550177>", "Contact: <>" })
	{
		EXPECT_EQ(trunk.acceptCall(*fromSbc(replaced(carrierInviteText(), contact, bad)), kFork, 40000), 400)
			<< bad << ": our BYE's Request-URI would be it";
	}
	EXPECT_EQ(trunk.activeDialogs(), 0u);
	EXPECT_EQ(trunk.acceptCall(*fromSbc(replaced(carrierInviteText(), contact,
		"Contact: <SIPS:+12025550177@203.0.113.9:5061>")), kFork, 40000), 0) << "sips:, in any case, is a SIP URI";
}

TEST(SipTrunkInbound, AnInviteCutAtTheLineCapEchoesNoRecordRoute)
{
	Inbound in;
	const auto cut = fromSbc("");
	cut->resetFromWire(carrierInviteText("c-cut", "", true, 70), FakePbxEnv::addr(kSbcIp, 5062));   // as off the socket
	ASSERT_TRUE(cut->headerLinesTruncated()) << "precondition: past the 64-line cap (#838)";
	ASSERT_EQ(in.trunk.acceptCall(*cut, "fork-cut", 40000), 0) << "still answered: it may be a PSAP callback";
	in.env.sent.clear();

	ASSERT_TRUE(in.trunk.respond("fork-cut", 180));

	ASSERT_EQ(in.env.sent.size(), 1u);
	EXPECT_EQ(in.env.sentRaw(0).find("Record-Route"), std::string::npos)
		<< "RFC 3261 s12.1.1: a partial Record-Route is a wrong route set; none is safer";
	EXPECT_NE(in.env.sentRaw(0).find("\r\nVia: SIP/2.0/UDP 10.0.0.9"), std::string::npos)
		<< "the Vias, ahead of the cut, are all still echoed";
	bool logged = false;
	for (const auto& l : in.env.logs) logged = logged || l.find("Record-Route") != std::string::npos;
	EXPECT_TRUE(logged) << "the drop is visible to whoever brings the carrier up";
}

TEST(SipTrunkInbound, RespondingWalksTheDialogToConfirmedUnderOneTag)
{
	Inbound in;
	ASSERT_TRUE(in.trunk.respond(kFork, 100));
	EXPECT_EQ(in.dialog()->state, SipTrunk::State::Trying);
	ASSERT_TRUE(in.trunk.respond(kFork, 180));
	EXPECT_EQ(in.dialog()->state, SipTrunk::State::Proceeding);
	ASSERT_TRUE(in.trunk.respond("Call-ID: carrier-call-1@203.0.113.5", 200, "v=0\r\n"));
	EXPECT_EQ(in.dialog()->state, SipTrunk::State::Confirmed);

	ASSERT_EQ(in.env.sent.size(), 3u);
	EXPECT_EQ(firstLine(in.env.sentRaw(0)), "SIP/2.0 100 Trying");
	EXPECT_EQ(firstLine(in.env.sentRaw(1)), "SIP/2.0 180 Ringing");
	EXPECT_EQ(firstLine(in.env.sentRaw(2)), "SIP/2.0 200 OK");
	for (size_t i = 0; i < 3; ++i) EXPECT_TRUE(in.sentTo(i, kSbcIp)) << "to the carrier, message " << i;
	EXPECT_EQ(lineStarting(in.env.sentRaw(1), "To: "), lineStarting(in.env.sentRaw(2), "To: "))
		<< "one To tag for every response to the INVITE (s8.2.6.2)";
	EXPECT_FALSE(in.trunk.respond(kFork, 486)) << "an answered INVITE takes no second final";
}

TEST(SipTrunkInbound, ARefusalReleasesTheSlotButNotItsTransaction)
{
	Inbound in;
	ASSERT_TRUE(in.trunk.respond(kFork, 486));

	ASSERT_EQ(in.env.sent.size(), 1u);
	EXPECT_EQ(firstLine(in.env.sentRaw(0)), "SIP/2.0 486 Busy Here");
	EXPECT_TRUE(in.sentTo(0, kSbcIp));
	EXPECT_EQ(in.trunk.activeDialogs(), 0u);
	EXPECT_TRUE(in.env.freedTransactionCallIds.empty())
		<< "the engine still retransmits the 486 until the carrier's ACK (s17.2.1)";
}

// ── Teardown ──────────────────────────────────────────────────────────────────

TEST(SipTrunkInbound, HangingUpAnAnsweredCallByesTheCarrierInTheUasForm)
{
	Inbound in;
	ASSERT_TRUE(in.trunk.respond(kFork, 200, "v=0\r\n"));
	in.env.sent.clear();

	ASSERT_TRUE(in.trunk.hangup(kFork));

	ASSERT_EQ(in.env.sent.size(), 1u);
	const std::string bye = in.env.sentRaw(0);
	EXPECT_TRUE(in.sentTo(0, kSbcIp));
	EXPECT_EQ(firstLine(bye), "BYE sip:+12025550177@203.0.113.9:5060 SIP/2.0");
	EXPECT_NE(lineStarting(bye, "From: ").find(";tag=" + in.dialog()->toTag), std::string::npos);
	EXPECT_EQ(lineStarting(bye, "To: "), "To: <sip:+12025550177@203.0.113.5>;tag=carrier-ftag");
	EXPECT_EQ(lineStarting(bye, "CSeq: "), "CSeq: 1 BYE");
	EXPECT_EQ(in.dialog()->state, SipTrunk::State::Terminating);

	ASSERT_TRUE(in.trunk.handleResponse(carrierAnswer(bye, "SIP/2.0 200 OK")));
	EXPECT_EQ(in.trunk.activeDialogs(), 0u);
	EXPECT_TRUE(in.lis.events.empty()) << "our own BYE completing is not a remote hangup";
}

TEST(SipTrunkInbound, AChallengedByeRetriesWithOurNextCseq)
{
	Inbound in;
	ASSERT_TRUE(in.trunk.setCredentials("s3cret-pw"));
	ASSERT_TRUE(in.trunk.respond(kFork, 200, "v=0\r\n"));
	ASSERT_TRUE(in.trunk.hangup(kFork));
	ASSERT_EQ(in.env.sent.size(), 2u);
	const std::string bye = in.env.sentRaw(1);
	in.env.sent.clear();

	ASSERT_TRUE(in.trunk.handleResponse(carrierAnswer(bye, "SIP/2.0 401 Unauthorized",
		"WWW-Authenticate: Digest realm=\"carrier\", nonce=\"n0nce1\", algorithm=MD5\r\n")));

	ASSERT_EQ(in.env.sent.size(), 1u);
	EXPECT_EQ(lineStarting(in.env.sentRaw(0), "CSeq: "), "CSeq: 2 BYE");
	EXPECT_NE(in.env.sentRaw(0).find("\r\nAuthorization: Digest "), std::string::npos);
}

TEST(SipTrunkInbound, HangingUpBeforeAnswerSendsAFinalNeverACancel)
{
	for (const bool rang : { false, true })
	{
		Inbound in;
		if (rang) ASSERT_TRUE(in.trunk.respond(kFork, 180));
		in.env.sent.clear();

		ASSERT_TRUE(in.trunk.hangup(kFork));

		ASSERT_EQ(in.env.sent.size(), 1u) << "rang=" << rang;
		EXPECT_EQ(firstLine(in.env.sentRaw(0)), "SIP/2.0 480 Temporarily Unavailable")
			<< "rang=" << rang << ": a UAS ends the INVITE with a final (RFC 3261 s9)";
		EXPECT_TRUE(in.sentTo(0, kSbcIp));
		EXPECT_EQ(in.trunk.activeDialogs(), 0u);
	}
}

TEST(SipTrunkInbound, ACarrierByeIsAcceptedOnTheReversedTagsOnly)
{
	{
		Inbound in;
		ASSERT_TRUE(in.trunk.respond(kFork, 200, "v=0\r\n"));
		const std::string ours = in.dialog()->toTag;
		in.env.sent.clear();

		ASSERT_TRUE(in.trunk.handleBye(carrierBye(kForgerIp, "carrier-ftag", ours)));
		EXPECT_EQ(firstLine(in.env.sentRaw(0)), "SIP/2.0 200 OK")
			<< "from an unknown address, the carrier's tag in From and ours in To";
		EXPECT_EQ(in.lis.events, std::vector<std::string>{"remoteBye"});
		EXPECT_EQ(in.trunk.activeDialogs(), 0u);
	}
	{
		Inbound in;
		ASSERT_TRUE(in.trunk.respond(kFork, 200, "v=0\r\n"));
		const std::string ours = in.dialog()->toTag;
		in.env.sent.clear();

		ASSERT_TRUE(in.trunk.handleBye(carrierBye(kForgerIp, ours, "carrier-ftag")));
		EXPECT_EQ(firstLine(in.env.sentRaw(0)), "SIP/2.0 403 Forbidden") << "the outbound orientation";
		EXPECT_TRUE(in.lis.events.empty());
		ASSERT_NE(in.dialog(), nullptr);
		EXPECT_EQ(in.dialog()->state, SipTrunk::State::Confirmed);
	}
}

TEST(SipTrunkInbound, AByeBeforeOurAnswerAlsoEndsTheInviteWith487)
{
	Inbound in;
	ASSERT_TRUE(in.trunk.respond(kFork, 180));
	const std::string ours = in.dialog()->toTag;
	in.env.sent.clear();

	ASSERT_TRUE(in.trunk.handleBye(carrierBye(kSbcIp, "carrier-ftag", ours)));

	ASSERT_EQ(in.env.sent.size(), 2u);
	EXPECT_EQ(firstLine(in.env.sentRaw(0)), "SIP/2.0 200 OK");
	EXPECT_EQ(firstLine(in.env.sentRaw(1)), "SIP/2.0 487 Request Terminated") << "RFC 3261 s15.1.2";
	EXPECT_EQ(lineStarting(in.env.sentRaw(1), "CSeq: "), "CSeq: 101 INVITE");
	EXPECT_EQ(in.lis.events, std::vector<std::string>{"remoteBye"});
	EXPECT_EQ(in.trunk.activeDialogs(), 0u);
}

TEST(SipTrunkInbound, AResponseOnAnUnansweredInboundDialogIsConsumedAndIgnored)
{
	Inbound in;
	const std::string ok = "SIP/2.0 200 OK\r\n" + kVias +
		"From: \"Caller\" <sip:+12025550177@203.0.113.5>;tag=carrier-ftag\r\n"
		"To: <sip:+12025550188@192.168.1.10>;tag=stray\r\n"
		"Call-ID: carrier-call-1@203.0.113.5\r\n"
		"CSeq: 101 INVITE\r\n"
		"Contact: <sip:+12025550177@203.0.113.66:5060>\r\n"
		"Content-Length: 0\r\n\r\n";

	EXPECT_TRUE(in.trunk.handleResponse(std::make_shared<SipMessage>(ok, FakePbxEnv::addr(kSbcIp, 5060))));

	EXPECT_TRUE(in.env.sent.empty()) << "no ACK: we sent no INVITE";
	EXPECT_TRUE(in.lis.events.empty()) << "and no answered event";
	ASSERT_NE(in.dialog(), nullptr);
	EXPECT_EQ(in.dialog()->state, SipTrunk::State::Trying);
	EXPECT_EQ(in.dialog()->remoteTarget, "sip:+12025550177@203.0.113.9:5060");
}

TEST(SipTrunkInbound, TheSweepAnswersTheCarrierBeforeReleasing)
{
	Inbound in;
	ASSERT_TRUE(in.trunk.respond(kFork, 180));
	in.env.sent.clear();

	in.trunk.sweep(std::chrono::steady_clock::now() + std::chrono::minutes(2));

	ASSERT_EQ(in.env.sent.size(), 1u);
	EXPECT_EQ(firstLine(in.env.sentRaw(0)), "SIP/2.0 480 Temporarily Unavailable");
	EXPECT_EQ(in.lis.events, std::vector<std::string>{"failed 408"});
	EXPECT_EQ(in.trunk.activeDialogs(), 0u);
}
