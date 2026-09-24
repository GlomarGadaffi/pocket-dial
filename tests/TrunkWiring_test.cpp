// TrunkWiring_test.cpp — issue #164: the B2BUA that joins a handset dialog to
// a carrier dialog.
//
// SipTrunk_test.cpp already pins the carrier-facing wire format, and
// TrunkResolver_test.cpp pins the address cache. Neither of them can catch the
// class of bug that actually breaks a trunk in the field, because those live in
// the JOIN: a call that signals perfectly while the media goes nowhere, or a
// teardown that answers the signalling and leaks the relay.
//
// So these tests assert on two things at once wherever both apply — what
// reached the wire, AND whether the relay pair was still held afterwards.
// trunkRelaysInUseForTest() is the only external view of the media state, and a
// test that checks only the SIP side would pass through every leak this file
// exists to prevent.
//
// The trunk is configured with a dotted-quad host throughout. That is the
// common static-IP-trunk case and it makes TrunkResolver answer from the
// literal without a DNS round trip, so these tests exercise the wiring rather
// than the resolver.

#include <gtest/gtest.h>

#include <cstdio>
#include <string>
#include <vector>

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

#include "RequestsHandler.hpp"

namespace
{
	constexpr const char* kServerIp  = "192.168.50.1";
	constexpr const char* kHandsetIp = "192.168.50.20";
	constexpr const char* kSbcIp     = "203.0.113.5";     // RFC 5737 TEST-NET-3

	using SentList = std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>;

	sockaddr_in addrFor(const std::string& ip, uint16_t port = 5060)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(port);
		return s;
	}

	SipTrunk::Config trunkConfig()
	{
		SipTrunk::Config c;
		std::snprintf(c.host, sizeof(c.host), "%s", kSbcIp);
		c.port = 5060;
		std::snprintf(c.fromUser, sizeof(c.fromUser), "%s", "15551230000");
		c.enabled = true;
		return c;
	}

	std::shared_ptr<SipMessage> makeRegister(const std::string& ext, const std::string& callId)
	{
		const std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(kHandsetIp) + ":5060;branch=z9hG4bKr" + callId + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + callId + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + kHandsetIp + ":5060>;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(kHandsetIp));
	}

	// A handset dialling a PSTN number. The 9 prefix is what the dial rule
	// strips; 101 is the telephone-event payload type the answer must echo.
	std::shared_ptr<SipMessage> makeTrunkDial(const std::string& fromExt,
		const std::string& dialed, const std::string& callId, int rtpPort = 40000)
	{
		const std::string body =
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + std::string(kHandsetIp) + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + std::string(kHandsetIp) + "\r\n"
			"t=0 0\r\n"
			"m=audio " + std::to_string(rtpPort) + " RTP/AVP 0 101\r\n"
			"a=rtpmap:0 PCMU/8000\r\n"
			"a=rtpmap:101 telephone-event/8000\r\n"
			"a=fmtp:101 0-15\r\n";
		const std::string raw =
			"INVITE sip:" + dialed + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(kHandsetIp) + ":5060;branch=z9hG4bKi" + callId + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + dialed + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:" + fromExt + "@" + kHandsetIp + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(kHandsetIp));
	}

	std::shared_ptr<SipMessage> makeHandsetBye(const std::string& fromExt,
		const std::string& dialed, const std::string& callId, const std::string& toTag)
	{
		const std::string raw =
			"BYE sip:" + dialed + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(kHandsetIp) + ":5060;branch=z9hG4bKb" + callId + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + dialed + "@server>;tag=" + toTag + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 2 BYE\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(kHandsetIp));
	}

	// Everything the SBC would send back, built off the INVITE the handler
	// actually put on the wire so the dialog identifiers match for real rather
	// than by construction.
	struct CarrierView
	{
		std::string callID, branch, fromTag, toTag = "carrier-tag";

		static CarrierView from(const std::string& invite)
		{
			CarrierView v;
			v.callID  = field(invite, "Call-ID: ");
			v.branch  = between(invite, ";branch=", "\r\n");
			v.fromTag = between(invite, ";tag=", "\r\n");
			return v;
		}

		std::string response(const std::string& statusLine, bool withSdp) const
		{
			const std::string sdp = withSdp
				? "v=0\r\no=- 0 0 IN IP4 203.0.113.9\r\ns=-\r\nc=IN IP4 203.0.113.9\r\n"
				  "t=0 0\r\nm=audio 41000 RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\n"
				  "a=rtpmap:101 telephone-event/8000\r\n"
				: std::string();
			std::string r = statusLine + "\r\n"
				"Via: SIP/2.0/UDP 192.168.50.1:5060;branch=" + branch + "\r\n"
				"From: <sip:15551230000@" + kSbcIp + ":5060>;tag=" + fromTag + "\r\n"
				"To: <sip:+12025550123@" + kSbcIp + ":5060>;tag=" + toTag + "\r\n"
				"Call-ID: " + callID + "\r\n"
				"CSeq: 1 INVITE\r\n"
				"Contact: <sip:+12025550123@203.0.113.9:5060>\r\n";
			if (withSdp) r += "Content-Type: application/sdp\r\n";
			r += "Content-Length: " + std::to_string(sdp.size()) + "\r\n\r\n" + sdp;
			return r;
		}

		// The carrier hanging up first.
		std::string bye() const
		{
			return
				"BYE sip:15551230000@192.168.50.1:5060 SIP/2.0\r\n"
				"Via: SIP/2.0/UDP " + std::string(kSbcIp) + ":5060;branch=z9hG4bKcarrierbye\r\n"
				"From: <sip:+12025550123@" + kSbcIp + ":5060>;tag=" + toTag + "\r\n"
				"To: <sip:15551230000@" + kSbcIp + ":5060>;tag=" + fromTag + "\r\n"
				"Call-ID: " + callID + "\r\n"
				"CSeq: 2 BYE\r\n"
				"Content-Length: 0\r\n\r\n";
		}

		static std::string field(const std::string& m, const std::string& name)
		{
			const size_t p = m.find(name);
			if (p == std::string::npos) return {};
			const size_t e = m.find("\r\n", p);
			return m.substr(p + name.size(), e - p - name.size());
		}
		static std::string between(const std::string& m, const std::string& a, const std::string& b)
		{
			const size_t p = m.find(a);
			if (p == std::string::npos) return {};
			const size_t e = m.find(b, p + a.size());
			return m.substr(p + a.size(), e - p - a.size());
		}
	};

	// A handler with one "9 + digits goes to the trunk" rule and a registered
	// handset, ready to dial.
	struct Bench
	{
		SentList sent;
		RequestsHandler handler;

		Bench() : handler(kServerIp, 5060,
			[this](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
				sent.emplace_back(a, std::move(m));
			})
		{
			handler.setDialRule("9XXXXXXXXXX", "trunk", "1", 1);
			handler.handle(makeRegister("1001", "reg-1001"));
			sent.clear();
		}

		// Raw text of the first message sent whose first line contains `needle`.
		std::string firstWith(const std::string& needle) const
		{
			for (const auto& [addr, msg] : sent)
			{
				(void)addr;
				if (!msg) continue;
				const std::string raw = msg->toString();
				if (raw.substr(0, raw.find("\r\n")).find(needle) != std::string::npos) return raw;
			}
			return {};
		}

		size_t countWith(const std::string& needle) const
		{
			size_t n = 0;
			for (const auto& [addr, msg] : sent)
			{
				(void)addr;
				if (!msg) continue;
				const std::string raw = msg->toString();
				if (raw.substr(0, raw.find("\r\n")).find(needle) != std::string::npos) ++n;
			}
			return n;
		}

		// As countWith(), but only messages ADDRESSED to `ip`. A teardown has two
		// parties and a BYE to the wrong one is not a BYE to the right one --
		// countWith("BYE") alone let a handset hangup pass while the carrier leg
		// was never told (#356).
		size_t countWithTo(const std::string& needle, const std::string& ip) const
		{
			const uint32_t want = inet_addr(ip.c_str());
			size_t n = 0;
			for (const auto& [addr, msg] : sent)
			{
				if (!msg || addr.sin_addr.s_addr != want) continue;
				const std::string raw = msg->toString();
				if (raw.substr(0, raw.find("\r\n")).find(needle) != std::string::npos) ++n;
			}
			return n;
		}
	};
}

// ── Originate ───────────────────────────────────────────────────────────────

TEST(TrunkWiring, WithNoTrunkConfiguredTheRuleStillRoutesToTheAnchor)
{
	Bench b;   // deliberately no setTrunkConfig()

	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-1"));

	EXPECT_TRUE(b.firstWith("INVITE sip:+1").empty())
		<< "an unconfigured trunk must not place a carrier INVITE";
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 0u)
		<< "and must not consume relay media either";
}

TEST(TrunkWiring, DiallingTheRulePlacesACarrierInviteAndRingsTheHandset)
{
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());

	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-1"));

	const std::string inv = b.firstWith("INVITE sip:+1");
	ASSERT_FALSE(inv.empty()) << "no INVITE reached the carrier";
	EXPECT_NE(inv.find("INVITE sip:+12025550123@" + std::string(kSbcIp)), std::string::npos)
		<< "the rule strips the 9 and prepends 1, and the URI is E.164 at the SBC";

	EXPECT_FALSE(b.firstWith("180 Ringing").empty())
		<< "the handset must be told the call is progressing";

	// The offer advertises the trunk-facing receiver's own bound port, which is
	// the whole reason that half is started before the INVITE goes out.
	EXPECT_NE(inv.find("m=audio "), std::string::npos) << "the INVITE carries an SDP offer";
	EXPECT_EQ(inv.find("m=audio 0 "), std::string::npos) << "and the port is a real bound one";

	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 1u)
		<< "one relay pair is held from the moment the call is placed";
}

TEST(TrunkWiring, AnUnresolvableHostIsRefusedWithoutSendingOrConsumingAnything)
{
	Bench b;
	SipTrunk::Config c = trunkConfig();
	// A name, not a literal. Nothing has resolved it, and placeCall consults
	// the CACHE ONLY -- it must never block the SIP thread on DNS.
	std::snprintf(c.host, sizeof(c.host), "%s", "sbc.carrier.example");
	b.handler.setTrunkConfig(c);

	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-1"));

	EXPECT_TRUE(b.firstWith("INVITE sip:+1").empty())
		<< "no INVITE may go out to an address we do not have";
	EXPECT_FALSE(b.firstWith("503").empty())
		<< "the handset gets a final response rather than silence";
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 0u)
		<< "a refused call must not strand a relay pair";
}

// ── Answer ──────────────────────────────────────────────────────────────────

TEST(TrunkWiring, TheCarrierAnswerIsAckedAndTheHandsetGetsATwoWaySdpAnswer)
{
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-1"));
	const auto carrier = CarrierView::from(b.firstWith("INVITE sip:+1"));
	b.sent.clear();

	b.handler.handle(RequestsHandler::getMessageFromPool(
		carrier.response("SIP/2.0 200 OK", /*withSdp=*/true), addrFor(kSbcIp)));

	EXPECT_FALSE(b.firstWith("ACK").empty()) << "RFC 3261: a 2xx must be ACKed";

	const std::string ok = b.firstWith("200 OK");
	ASSERT_FALSE(ok.empty()) << "the handset was never answered";
	EXPECT_NE(ok.find("a=sendrecv"), std::string::npos)
		<< "a trunk call is two-way, unlike 440's one-way tone";
	EXPECT_NE(ok.find("a=rtpmap:101 telephone-event"), std::string::npos)
		<< "the handset's own telephone-event PT is echoed back, or DTMF cannot cross";

	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 1u)
		<< "both halves of the pair are live once the call is up";
}

TEST(TrunkWiring, AnAnswerWithNoUsableMediaHangsTheCarrierUpRatherThanConnectSilence)
{
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-1"));
	const auto carrier = CarrierView::from(b.firstWith("INVITE sip:+1"));
	b.sent.clear();

	// A 200 with no SDP at all: signalling says connected, media has nowhere
	// to go. Answering the handset here would produce a live-looking call with
	// permanent one-way silence, which is worse than a clean failure.
	b.handler.handle(RequestsHandler::getMessageFromPool(
		carrier.response("SIP/2.0 200 OK", /*withSdp=*/false), addrFor(kSbcIp)));

	EXPECT_TRUE(b.firstWith("200 OK").empty())
		<< "the handset must NOT be answered when the media cannot be bridged";
	EXPECT_FALSE(b.firstWith("BYE").empty())
		<< "the carrier leg is answered and billing; it has to be hung up";
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 0u)
		<< "and the relay pair released";
}

// ── Failure ─────────────────────────────────────────────────────────────────

TEST(TrunkWiring, ABusyFromTheCarrierReachesTheHandsetAndFreesTheSlot)
{
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-1"));
	const auto carrier = CarrierView::from(b.firstWith("INVITE sip:+1"));
	b.sent.clear();

	b.handler.handle(RequestsHandler::getMessageFromPool(
		carrier.response("SIP/2.0 486 Busy Here", /*withSdp=*/false), addrFor(kSbcIp)));

	EXPECT_FALSE(b.firstWith("486").empty())
		<< "486 is true end to end -- the callee really is busy";
	EXPECT_FALSE(b.firstWith("ACK").empty())
		<< "RFC 3261 s17.1.1.3: a non-2xx is ACKed or the carrier retransmits for 32s";
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 0u);
}

TEST(TrunkWiring, ACarrierSideFailureIsNotPassedThroughVerbatim)
{
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-1"));
	const auto carrier = CarrierView::from(b.firstWith("INVITE sip:+1"));
	b.sent.clear();

	// 403 describes the CARRIER's opinion of US (bad authorisation, blocked
	// destination). Relaying it to the handset tells the user their own call
	// was forbidden, which is a confidently wrong diagnosis.
	b.handler.handle(RequestsHandler::getMessageFromPool(
		carrier.response("SIP/2.0 403 Forbidden", /*withSdp=*/false), addrFor(kSbcIp)));

	EXPECT_TRUE(b.firstWith("403").empty())
		<< "a trunk-authorisation failure is not the handset's 403";
	EXPECT_FALSE(b.firstWith("502").empty())
		<< "502 Bad Gateway: the far side failed in a way the caller cannot act on";
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 0u);
}

// ── Teardown, both directions ───────────────────────────────────────────────

TEST(TrunkWiring, TheHandsetHangingUpByesTheCarrierAndReleasesTheRelay)
{
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-1"));
	const auto carrier = CarrierView::from(b.firstWith("INVITE sip:+1"));
	b.handler.handle(RequestsHandler::getMessageFromPool(
		carrier.response("SIP/2.0 200 OK", true), addrFor(kSbcIp)));
	const std::string ok = b.firstWith("200 OK");
	const std::string localTag = CarrierView::between(ok, ";tag=", "\r\n");
	b.sent.clear();

	b.handler.handle(makeHandsetBye("1001", "92025550123", "call-1", localTag));

	EXPECT_EQ(b.countWithTo("BYE", kSbcIp), 1u)
		<< "the carrier leg is billing until it is hung up";
	EXPECT_EQ(b.countWithTo("BYE", kHandsetIp), 0u)
		<< "the handset hung up itself; it gets a 200, not a BYE of its own";
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 0u)
		<< "endCall() is the one place the pair is released, on every path";
}

TEST(TrunkWiring, TheCarrierHangingUpByesTheHandsetAndReleasesTheRelay)
{
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-1"));
	const auto carrier = CarrierView::from(b.firstWith("INVITE sip:+1"));
	b.handler.handle(RequestsHandler::getMessageFromPool(
		carrier.response("SIP/2.0 200 OK", true), addrFor(kSbcIp)));
	b.sent.clear();

	b.handler.handle(RequestsHandler::getMessageFromPool(carrier.bye(), addrFor(kSbcIp)));

	EXPECT_EQ(b.countWithTo("BYE", kHandsetIp), 1u)
		<< "the handset has to be told; it is not in the carrier's dialog";
	EXPECT_EQ(b.countWithTo("BYE", kSbcIp), 0u)
		<< "the carrier hung up itself; BYEing it back would earn a 481";
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 0u);
}

// ── Capacity ────────────────────────────────────────────────────────────────

TEST(TrunkWiring, RelayPairsAreBoundedAndReusableOnceReleased)
{
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());

	for (int i = 0; i < static_cast<int>(POCKETDIAL_MAX_TRUNK_CALLS); ++i)
	{
		b.handler.handle(makeRegister("200" + std::to_string(i), "reg-x" + std::to_string(i)));
		b.handler.handle(makeTrunkDial("200" + std::to_string(i), "92025550123",
			"fill-" + std::to_string(i), 41000 + i));
	}
	ASSERT_EQ(b.handler.trunkRelaysInUseForTest(),
		static_cast<size_t>(POCKETDIAL_MAX_TRUNK_CALLS)) << "every pair claimed";
	b.sent.clear();

	b.handler.handle(makeTrunkDial("1001", "92025550123", "overflow"));
	EXPECT_FALSE(b.firstWith("503").empty())
		<< "past capacity an outbound PSTN call fails fast and audibly, it is not queued";
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(),
		static_cast<size_t>(POCKETDIAL_MAX_TRUNK_CALLS)) << "and claims nothing";
}

// ── The session-timer sweep must never reap a relay leg ─────────────────────
//
// Honest framing, because the guard is easy to over-claim: NO path today arms
// a session timer on a trunk session. onOk()'s relay branch is the only arming
// site for a fresh call, and the carrier's 200 never reaches it -- SipTrunk
// consumes it first. The re-INVITE and UPDATE re-arm sites are now refused for
// a trunk leg by the same isTrunk() guard, which is the point sweepSessionTimers()
// makes in its own comment: the set we refuse to REFRESH and the set we refuse
// to REAP have to stay identical.
//
// So this arms the timer directly on the live session, which is the only way to
// reach the guard, and it is worth reaching: if anyone later gives a trunk leg
// a refresh path, the sweep is already correct instead of quietly hanging up
// live PSTN calls four minutes in.
TEST(TrunkWiring, TheSessionTimerSweepDoesNotReapAConnectedTrunkCall)
{
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-1"));
	const auto carrier = CarrierView::from(b.firstWith("INVITE sip:+1"));
	b.handler.handle(RequestsHandler::getMessageFromPool(
		carrier.response("SIP/2.0 200 OK", true), addrFor(kSbcIp)));
	ASSERT_EQ(b.handler.trunkRelaysInUseForTest(), 1u) << "precondition: the call is up";

	auto session = b.handler.getSession("Call-ID: call-1");
	ASSERT_TRUE(session.has_value());
	// Already expired the moment it is armed, so one tick() is enough.
	session.value()->armSessionTimer(90, /*weAreRefresher=*/false,
		std::chrono::steady_clock::now() - std::chrono::minutes(10));
	b.sent.clear();

	b.handler.tick();

	EXPECT_TRUE(b.firstWith("BYE").empty())
		<< "a relay leg has no local UA to answer a refresh; reaping it hangs up a live call";
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 1u)
		<< "and the media must still be bridged afterwards";
}

// ── The engine must actually drive SipTrunk's clock ─────────────────────────
//
// SipTrunk has no clock of its own: placeCall() arms a 60 s no-answer deadline
// and sweep() is what reads it. If nothing calls sweep(), a silent SBC leaks
// the dialog slot, the relay pair AND the handset session, with the phone
// ringing forever and no log line.
//
// SipTrunk_test.cpp calls trunk.sweep() directly on a standalone object, which
// proves the machine works and proves nothing about whether the engine ever
// turns the handle. That gap is exactly what shipped in the first version of
// this PR: every comment said "SipTrunk::sweep() owns the no-answer deadline",
// and no call site existed. This test asserts the wiring, through tick().
TEST(TrunkWiring, AnUnansweredCarrierInviteTimesOutThroughTick)
{
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-1"));
	ASSERT_FALSE(b.firstWith("INVITE sip:+1").empty()) << "precondition: the call was placed";
	ASSERT_EQ(b.handler.trunkRelaysInUseForTest(), 1u);
	b.sent.clear();

	// The carrier says nothing at all -- no 100, no 180, no final response.
	// Age the dialog past its own deadline rather than sleeping 60 s; tick()
	// reads steady_clock and this engine has no injectable clock.
	//
	// Exactly ONE tick() per test, deliberately: tick() self-throttles to 1 Hz
	// and returns immediately if called again inside the same second, so a
	// second call in the same test proves nothing. That throttle is why the
	// first version of this test passed a no-op off as a result.
	b.handler.expireTrunkDeadlinesForTest();
	b.handler.tick();

	EXPECT_FALSE(b.firstWith("503").empty())
		<< "the still-ringing handset must get a final response, not silence";
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 0u)
		<< "and the relay pair must come back, or the next call cannot be placed";
}

// The other side of that boundary: a carrier that is merely slow is not a
// carrier that has failed. Same single-tick discipline.
TEST(TrunkWiring, ASlowCarrierIsNotReapedBeforeItsDeadline)
{
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-1"));
	ASSERT_EQ(b.handler.trunkRelaysInUseForTest(), 1u);
	b.sent.clear();

	b.handler.tick();   // deadline is 60 s out and untouched

	EXPECT_TRUE(b.firstWith("503").empty())
		<< "nothing has expired; hanging up here would cut off a carrier "
		   "that is simply taking its time to ring";
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 1u);
}

TEST(TrunkWiring, TickKeepsTheSbcAddressResolvedForAnFqdnTrunk)
{
	Bench b;
	SipTrunk::Config c = trunkConfig();
	std::snprintf(c.host, sizeof(c.host), "%s", "sbc.carrier.example");
	b.handler.setTrunkConfig(c);

	// routeTrunkCall() uses the cache-only lookup(), so SOMETHING has to
	// populate the cache or an FQDN trunk can never place a call. Before this
	// was wired, nothing did: only a dotted quad worked, forever.
	//
	// The resolution itself needs real DNS and is covered by
	// TrunkResolver_test.cpp; what is asserted here is the part that was
	// missing and is cheap to state -- tick() asks the resolver, and does so
	// without blocking the caller.
	ASSERT_EQ(b.handler.trunkResolveStatusForTest(), TrunkResolver::Status::Refused)
		<< "precondition: nothing known about this name and nothing in flight";

	const auto before = std::chrono::steady_clock::now();
	b.handler.tick();
	const auto elapsed = std::chrono::steady_clock::now() - before;

	EXPECT_LT(elapsed, std::chrono::seconds(2))
		<< "tick() must never block on DNS -- that is the whole reason "
		   "routeTrunkCall() is cache-only";
	EXPECT_NE(b.handler.trunkResolveStatusForTest(), TrunkResolver::Status::Refused)
		<< "after a tick the name is at least in flight; Refused means tick() "
		   "never asked and an FQDN trunk can never place a call";
}
