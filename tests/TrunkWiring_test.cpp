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

#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "HttpServer.hpp"
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
		const std::string& dialed, const std::string& callId, int rtpPort = 40000,
		const std::string& extraHeaders = "")
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
			"Contact: <sip:" + fromExt + "@" + kHandsetIp + ":5060>\r\n" + extraHeaders +
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

	// The handset's CANCEL of its own INVITE: same Request-URI, Via branch, From
	// tag and CSeq number, To without a tag (RFC 3261 s9.1).
	std::shared_ptr<SipMessage> makeHandsetCancel(const std::string& fromExt,
		const std::string& dialed, const std::string& callId)
	{
		const std::string raw =
			"CANCEL sip:" + dialed + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(kHandsetIp) + ":5060;branch=z9hG4bKi" + callId + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + dialed + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 CANCEL\r\n"
			"Max-Forwards: 70\r\n"
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

		// The carrier's session-refresh re-INVITE (RFC 4028): in-dialog, so tagged.
		std::string reinvite(const std::string& id) const
		{
			return
				"INVITE sip:15551230000@192.168.50.1:5060 SIP/2.0\r\n"
				"Via: SIP/2.0/UDP " + std::string(kSbcIp) + ":5060;branch=z9hG4bKreinv" + id + "\r\n"
				"From: <sip:+12025550123@" + kSbcIp + ":5060>;tag=" + toTag + "\r\n"
				"To: <sip:15551230000@" + kSbcIp + ":5060>;tag=" + fromTag + "\r\n"
				"Call-ID: " + id + "\r\n"
				"CSeq: 2 INVITE\r\n"
				"Contact: <sip:+12025550123@203.0.113.9:5060>\r\n"
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

		// The SIP thread's next pass is what drains _asyncOutbox. A bare OPTIONS
		// from an address on no dialog stands in for it (same as ForceDisconnect_test).
		void flushAsyncOutbox()
		{
			const std::string raw =
				"OPTIONS sip:server SIP/2.0\r\n"
				"Via: SIP/2.0/UDP 192.168.50.99:5060;branch=z9hG4bKflush\r\n"
				"From: <sip:probe@server>;tag=probetag\r\n"
				"To: <sip:server@server>\r\n"
				"Call-ID: flush-714\r\n"
				"CSeq: 1 OPTIONS\r\n"
				"Max-Forwards: 70\r\n"
				"Content-Length: 0\r\n\r\n";
			handler.handle(RequestsHandler::getMessageFromPool(raw, addrFor("192.168.50.99")));
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

		// As firstWith(), but only messages ADDRESSED to `ip`.
		std::string firstWithTo(const std::string& needle, const std::string& ip) const
		{
			const uint32_t want = inet_addr(ip.c_str());
			for (const auto& [addr, msg] : sent)
			{
				if (!msg || addr.sin_addr.s_addr != want) continue;
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
		// was never told (#386).
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

// #198: the handset's 200 is the PBX's own answer, so RFC 4028 applies to it.
// The PBX never refreshes, and onReinvite() answers a trunk-leg re-INVITE 488,
// so a timer it granted here would end the call at expiry (§10: only a 2xx
// extends the session) -- on a 911 call too. The answer carries no
// Session-Expires and no Require at all instead (§7.2: no expiration).
TEST(TrunkWiring, TheHandsetAnswerCarriesNoSessionTimer)
{
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-se", 40000,
		"Supported: timer\r\nSession-Expires: 1800\r\n"));
	const auto carrier = CarrierView::from(b.firstWith("INVITE sip:+1"));
	b.sent.clear();

	b.handler.handle(RequestsHandler::getMessageFromPool(
		carrier.response("SIP/2.0 200 OK", /*withSdp=*/true), addrFor(kSbcIp)));

	const std::string ok = b.firstWith("200 OK");
	ASSERT_FALSE(ok.empty()) << "the handset was never answered";
	// Positive control: this is the handset's two-way SDP answer.
	EXPECT_NE(ok.find("a=sendrecv"), std::string::npos) << ok;
	EXPECT_EQ(ok.find("\r\nSession-Expires:"), std::string::npos)
		<< "a timer the PBX cannot service (re-INVITE refresh: 488) ends the call at expiry\n" << ok;
	EXPECT_EQ(ok.find("\r\nx:"), std::string::npos) << ok;
	EXPECT_EQ(ok.find("\r\nRequire:"), std::string::npos) << ok;
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

TEST(TrunkWiring, AnExpiredLeaseMidCallByesTheCarrierAndReleasesTheRelay)
{
	// #603 review: sweepExpired() erased an expired phone's sessions by hand --
	// no endCall(), so the carrier leg kept billing and the relay pair leaked.
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-lease"));
	const auto carrier = CarrierView::from(b.firstWith("INVITE sip:+1"));
	b.handler.handle(RequestsHandler::getMessageFromPool(
		carrier.response("SIP/2.0 200 OK", true), addrFor(kSbcIp)));
	ASSERT_EQ(b.handler.trunkRelaysInUseForTest(), 1u) << "precondition: the call is up";
	b.sent.clear();

	b.handler.expireLeaseAndSweepForTest("1001");

	EXPECT_EQ(b.countWithTo("BYE", kSbcIp), 1u) << "the carrier leg must be hung up";
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 0u) << "and its relay pair released";
}

TEST(TrunkWiring, AnAdminKillMidCallByesTheCarrierAsWellAsTheHandset)
{
	// #714: /api/kill reaches forceDisconnect() on the HTTP task. endCall()
	// queued the carrier BYE in _outbox, which the next SIP pass cleared before
	// draining, so only the handset BYE (via _asyncOutbox) ever left.
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-kill"));
	const auto carrier = CarrierView::from(b.firstWith("INVITE sip:+1"));
	b.handler.handle(RequestsHandler::getMessageFromPool(
		carrier.response("SIP/2.0 200 OK", true), addrFor(kSbcIp)));
	ASSERT_EQ(b.handler.trunkRelaysInUseForTest(), 1u) << "precondition: the call is up";
	b.sent.clear();

	b.handler.forceDisconnect("1001");
	b.flushAsyncOutbox();

	EXPECT_EQ(b.countWithTo("BYE", kHandsetIp), 1u)
		<< "positive control: the killed handset is told, once (#795)";
	EXPECT_EQ(b.countWithTo("BYE", kSbcIp), 1u)
		<< "the carrier leg keeps billing until it is hung up";
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 0u) << "and the relay pair is released";
}

TEST(TrunkWiring, AnAdminKillNeverEndsAnEmergencyCall)
{
	// #714 (desmo): an admin kill of a 911 trunk call is refused. Nothing is sent
	// to the carrier or the handset, the session and its media stay, and the
	// extension stays registered. The control half is the test above: the same
	// kill on a non-emergency call hangs up the carrier.
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "911", "call-714-911"));
	const auto e911 = CarrierView::from(b.firstWith("INVITE sip:911"));
	ASSERT_FALSE(e911.callID.empty()) << "precondition: 911 went to the trunk";
	b.handler.handle(RequestsHandler::getMessageFromPool(
		e911.response("SIP/2.0 200 OK", true), addrFor(kSbcIp)));
	ASSERT_EQ(b.handler.trunkRelaysInUseForTest(), 1u) << "precondition: the 911 is up";
	b.sent.clear();

	EXPECT_FALSE(b.handler.forceDisconnect("1001")) << "the kill must be refused";
	b.flushAsyncOutbox();

	EXPECT_EQ(b.countWithTo("BYE", kSbcIp), 0u) << "the kill hung up the PSAP";
	EXPECT_EQ(b.countWithTo("BYE", kHandsetIp), 0u) << "or the 911 caller";
	EXPECT_TRUE(b.handler.getSession("Call-ID: call-714-911").has_value()) << "the 911 session is kept";
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 1u) << "with its media";
	b.handler.forceNextTickForTest();   // getActiveClients() reads the tick snapshot
	b.handler.tick();
	bool registered = false;
	for (const auto& [number, address] : b.handler.getActiveClients())
	{
		if (number == "1001") registered = true;
	}
	EXPECT_TRUE(registered) << "the extension stays registered";
}

TEST(TrunkWiring, AnExpiredLeaseNeverEndsAnEmergencyCall)
{
	// #712 (desmo): a lapsed registration is bookkeeping; hanging up a 911 over
	// it is not. The client is kept until the emergency call ends, then pruned
	// by the next sweep as usual (the control half of this test).
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "911", "call-712-lease"));
	const auto e911 = CarrierView::from(b.firstWith("INVITE sip:911"));
	ASSERT_FALSE(e911.callID.empty()) << "precondition: 911 went to the trunk";
	b.handler.handle(RequestsHandler::getMessageFromPool(
		e911.response("SIP/2.0 200 OK", true), addrFor(kSbcIp)));
	ASSERT_EQ(b.handler.trunkRelaysInUseForTest(), 1u) << "precondition: the 911 is up";
	b.sent.clear();

	b.handler.expireLeaseAndSweepForTest("1001");

	EXPECT_EQ(b.countWithTo("BYE", kSbcIp), 0u) << "the lease sweep hung up the PSAP";
	EXPECT_EQ(b.countWithTo("BYE", kHandsetIp), 0u) << "or the 911 caller";
	EXPECT_TRUE(b.handler.getSession("Call-ID: call-712-lease").has_value()) << "the 911 session is kept";
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 1u) << "with its media";

	// Control: once the 911 has ended, the same expired client is pruned.
	b.handler.handle(RequestsHandler::getMessageFromPool(e911.bye(), addrFor(kSbcIp)));
	ASSERT_FALSE(b.handler.getSession("Call-ID: call-712-lease").has_value()) << "precondition: the 911 ended";
	b.handler.expireLeaseAndSweepForTest("1001");
	b.handler.forceNextTickForTest();   // getActiveClients() reads the tick snapshot
	b.handler.tick();
	bool still1001 = false;
	for (const auto& [number, address] : b.handler.getActiveClients())
	{
		(void)address;
		if (number == "1001") still1001 = true;
	}
	EXPECT_FALSE(still1001) << "the expired client is pruned once no emergency call holds it";
}

TEST(TrunkWiring, ARingingEmergencyCallIsNeverTimedOutButASilentOneStillIs)
{
	// #712 (desmo): a 911/933 the carrier is working on (a 100 or 180 seen,
	// Proceeding) gets no PBX-side no-answer bound; a PSAP may queue it past
	// 60 s. One that never drew any provisional (Trying) keeps the 60 s
	// deadline, because Timer B only logs: that half is the control, proving
	// the sweep did run on this tick.
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "911", "call-712-ring"));
	const auto ringing = CarrierView::from(b.firstWith("INVITE sip:911"));
	ASSERT_FALSE(ringing.callID.empty()) << "precondition: 911 went to the trunk";
	b.handler.handle(RequestsHandler::getMessageFromPool(
		ringing.response("SIP/2.0 180 Ringing", false), addrFor(kSbcIp)));
	b.handler.handle(makeTrunkDial("1001", "933", "call-712-silent", 40002));
	ASSERT_FALSE(b.firstWith("INVITE sip:933").empty()) << "precondition: 933 went to the trunk";
	ASSERT_EQ(b.handler.trunkRelaysInUseForTest(), 2u) << "precondition: both are placed";
	b.sent.clear();

	b.handler.expireTrunkDeadlinesForTest();
	b.handler.tick();

	EXPECT_TRUE(b.handler.getSession("Call-ID: call-712-ring").has_value())
		<< "a ringing 911 was timed out by the PBX";
	EXPECT_FALSE(b.handler.getSession("Call-ID: call-712-silent").has_value())
		<< "control: a 933 that never drew a provisional still times out";
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 1u) << "only the silent leg's relay is released";
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

// #700: the BYE we originate to the handset is in the handset's dialog, where WE
// are the UAS (it INVITEd us). RFC 3261 12.2.1.1: From = our URI and local tag
// (the 200 OK's To), To = the handset's own From. A phone matches the BYE on
// those tags and answers 481, staying off-hook, when they are swapped.
namespace
{
	void expectHandsetByeIsFromUs(const std::string& ok, const std::string& bye,
		const std::string& handsetTag)
	{
		const std::string localTag = CarrierView::between(ok, "To: ", "\r\n");
		const std::string ourTag   = CarrierView::between(localTag, ";tag=", "\r\n");
		ASSERT_FALSE(ourTag.empty()) << "precondition: the 200 OK carried our To tag";
		const std::string from = CarrierView::field(bye, "From: ");
		const std::string to   = CarrierView::field(bye, "To: ");
		EXPECT_NE(from.find(";tag=" + ourTag), std::string::npos)
			<< "BYE From must carry our local tag; got: " << from;
		EXPECT_EQ(from.find(";tag=" + handsetTag), std::string::npos)
			<< "BYE From must not carry the handset's own tag; got: " << from;
		EXPECT_NE(to.find(";tag=" + handsetTag), std::string::npos)
			<< "BYE To must carry the handset's tag; got: " << to;
		EXPECT_EQ(to.find(";tag=" + ourTag), std::string::npos)
			<< "BYE To must not carry our own tag; got: " << to;
	}
}

TEST(TrunkWiring, TheByeToTheHandsetAfterACarrierHangupIsFromUsAndToTheHandset)
{
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-700"));
	const auto carrier = CarrierView::from(b.firstWith("INVITE sip:+1"));
	b.handler.handle(RequestsHandler::getMessageFromPool(
		carrier.response("SIP/2.0 200 OK", true), addrFor(kSbcIp)));
	const std::string ok = b.firstWithTo("SIP/2.0 200 OK", kHandsetIp);
	ASSERT_FALSE(ok.empty()) << "precondition: the handset was answered";
	b.sent.clear();

	b.handler.handle(RequestsHandler::getMessageFromPool(carrier.bye(), addrFor(kSbcIp)));

	const std::string bye = b.firstWithTo("BYE", kHandsetIp);
	ASSERT_FALSE(bye.empty());
	expectHandsetByeIsFromUs(ok, bye, "ftcall-700");
}

// #795: an admin kill BYEs both legs of the session, but a trunk session's
// "dest" is a stand-in peer at the HANDSET's own address, so the handset got a
// second BYE with the tags reversed and answered it 481.
TEST(TrunkWiring, AnAdminKillOfATrunkCallByesTheHandsetExactlyOnceAndFromUs)
{
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-795"));
	const auto carrier = CarrierView::from(b.firstWith("INVITE sip:+1"));
	b.handler.handle(RequestsHandler::getMessageFromPool(
		carrier.response("SIP/2.0 200 OK", true), addrFor(kSbcIp)));
	const std::string ok = b.firstWithTo("SIP/2.0 200 OK", kHandsetIp);
	ASSERT_FALSE(ok.empty()) << "precondition: the handset was answered";
	b.sent.clear();

	b.handler.forceDisconnect("1001");
	b.flushAsyncOutbox();

	EXPECT_EQ(b.countWithTo("BYE", kHandsetIp), 1u)
		<< "one BYE to the killed handset; a second, reversed one draws a 481";
	const std::string bye = b.firstWithTo("BYE", kHandsetIp);
	ASSERT_FALSE(bye.empty());
	expectHandsetByeIsFromUs(ok, bye, "ftcall-795");
}

// ── Forged carrier messages (#356) ──────────────────────────────────────────
//
// SipTrunk_test.cpp covers the rules state by state. These pin what the rules
// protect end to end: a forger who knows a live trunk Call-ID can neither
// tear the call down nor answer it with its own media address.

namespace
{
	constexpr const char* kForgerIp = "198.51.100.66";   // RFC 5737 TEST-NET-2
}

TEST(TrunkWiring, AForgedCarrierByeLeavesTheCallUp)
{
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-1"));
	auto carrier = CarrierView::from(b.firstWith("INVITE sip:+1"));
	b.handler.handle(RequestsHandler::getMessageFromPool(
		carrier.response("SIP/2.0 200 OK", true), addrFor(kSbcIp)));
	b.sent.clear();

	// Right Call-ID, wrong carrier tag, from neither the SBC nor its Contact.
	CarrierView forger = carrier;
	forger.toTag = "guessed";
	b.handler.handle(RequestsHandler::getMessageFromPool(forger.bye(), addrFor(kForgerIp)));

	EXPECT_EQ(b.countWithTo("403", kForgerIp), 1u) << "the forger is refused";
	EXPECT_EQ(b.sent.size(), 1u) << "and that is the only thing that happens";
	EXPECT_EQ(b.countWithTo("BYE", kHandsetIp), 0u) << "the handset's call is not torn down";
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 1u) << "and its media keeps flowing";

	// The real carrier can still hang up.
	b.handler.handle(RequestsHandler::getMessageFromPool(carrier.bye(), addrFor(kSbcIp)));
	EXPECT_EQ(b.countWithTo("BYE", kHandsetIp), 1u);
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 0u);
}

TEST(TrunkWiring, AForgedAnswerIsNeitherAckedNorBridged)
{
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-1"));
	const auto carrier = CarrierView::from(b.firstWith("INVITE sip:+1"));
	b.sent.clear();

	// A 200 carrying SDP, racing the carrier's own answer. Accepted, it would
	// be ACKed and the relay pointed at whatever media address it names.
	b.handler.handle(RequestsHandler::getMessageFromPool(
		carrier.response("SIP/2.0 200 OK", true), addrFor(kForgerIp)));

	EXPECT_TRUE(b.sent.empty()) << "no ACK to anyone, and the handset is not answered";
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 1u) << "still ringing, pair still held";

	// The carrier's real answer connects normally afterwards.
	b.handler.handle(RequestsHandler::getMessageFromPool(
		carrier.response("SIP/2.0 200 OK", true), addrFor(kSbcIp)));
	EXPECT_EQ(b.countWithTo("ACK", kSbcIp), 1u);
	EXPECT_EQ(b.countWithTo("200 OK", kHandsetIp), 1u);
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

// ── Issue #546: "trunk" only after the carrier has answered ─────────────────

TEST(TrunkWiring, TheEmergencyRouteIsUnverifiedUntilTheCarrierAnswers)
{
	// A valid config proves the trunk is CONFIGURED, nothing more: a carrier
	// that demands digest (#399) would fail every 911 with 502. The report
	// only reads "trunk" after a real 2xx to one of our INVITEs.
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	EXPECT_EQ(b.handler.emergencyRoute(), RequestsHandler::EmergencyRoute::TrunkUnverified);

	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-546"));
	const auto carrier = CarrierView::from(b.firstWith("INVITE sip:+1"));
	ASSERT_FALSE(carrier.callID.empty());
	EXPECT_EQ(b.handler.emergencyRoute(), RequestsHandler::EmergencyRoute::TrunkUnverified)
		<< "sending an INVITE proves nothing";

	b.handler.handle(RequestsHandler::getMessageFromPool(
		carrier.response("SIP/2.0 200 OK", /*withSdp=*/true), addrFor(kSbcIp)));
	EXPECT_EQ(b.handler.emergencyRoute(), RequestsHandler::EmergencyRoute::Trunk)
		<< "a carrier 2xx is the proof";

	b.handler.setTrunkConfig(trunkConfig());
	EXPECT_EQ(b.handler.emergencyRoute(), RequestsHandler::EmergencyRoute::TrunkUnverified)
		<< "a changed trunk config starts unproved again";
}

TEST(TrunkWiring, ACarrier183WithSdpIsRelayedAsEarlyMediaAndThe200KeepsTheSameRelay)
{
	// #400: the carrier's 183 audio (ringback, SIT tone, "number disconnected")
	// reaches the caller instead of local ringback, and the answer continues on
	// the same relay port with no gap.
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-em"));
	const auto carrier = CarrierView::from(b.firstWith("INVITE sip:+1"));
	b.sent.clear();

	b.handler.handle(RequestsHandler::getMessageFromPool(
		carrier.response("SIP/2.0 183 Session Progress", /*withSdp=*/true), addrFor(kSbcIp)));
	const std::string early = b.firstWith("183 Session Progress");
	ASSERT_FALSE(early.empty()) << "the handset must get the carrier's early media";
	const std::string port = CarrierView::between(early, "m=audio ", " ");
	ASSERT_FALSE(port.empty());
	EXPECT_EQ(b.countWithTo("183 Session Progress", kHandsetIp), 1u);

	b.sent.clear();
	b.handler.handle(RequestsHandler::getMessageFromPool(
		carrier.response("SIP/2.0 200 OK", /*withSdp=*/true), addrFor(kSbcIp)));
	const std::string ok = b.firstWith("200 OK");
	ASSERT_FALSE(ok.empty());
	EXPECT_EQ(CarrierView::between(ok, "m=audio ", " "), port) << "the 200 continues on the early-media relay";
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 1u);
}

TEST(TrunkWiring, A183WithoutSdpLeavesLocalRingback)
{
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-em2"));
	const auto carrier = CarrierView::from(b.firstWith("INVITE sip:+1"));
	b.sent.clear();

	b.handler.handle(RequestsHandler::getMessageFromPool(
		carrier.response("SIP/2.0 183 Session Progress", /*withSdp=*/false), addrFor(kSbcIp)));
	EXPECT_TRUE(b.firstWith("183 Session Progress").empty()) << "nothing to relay without SDP";
}

TEST(TrunkWiring, ACarrierRefusalAfterEarlyMediaRefusesTheHandsetAndFreesTheRelay)
{
	// #600 review: a 183 with SDP took a relay pair; a carrier 486 afterwards
	// must answer the handset 486 in the SAME early dialog (the 183's To-tag)
	// and give the pair back.
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-em3"));
	const auto carrier = CarrierView::from(b.firstWith("INVITE sip:+1"));
	b.sent.clear();

	b.handler.handle(RequestsHandler::getMessageFromPool(
		carrier.response("SIP/2.0 183 Session Progress", /*withSdp=*/true), addrFor(kSbcIp)));
	const std::string early = b.firstWith("183 Session Progress");
	ASSERT_FALSE(early.empty());
	ASSERT_EQ(b.handler.trunkRelaysInUseForTest(), 1u);
	const std::string earlyTo = CarrierView::between(early, "\nTo: ", "\r\n");
	ASSERT_NE(earlyTo.find(";tag="), std::string::npos) << early;

	b.sent.clear();
	b.handler.handle(RequestsHandler::getMessageFromPool(
		carrier.response("SIP/2.0 486 Busy Here", /*withSdp=*/false), addrFor(kSbcIp)));
	const std::string busy = b.firstWith("SIP/2.0 486 Busy Here");
	ASSERT_FALSE(busy.empty()) << "the handset must hear the carrier's busy";
	EXPECT_EQ(b.countWithTo("SIP/2.0 486 Busy Here", kHandsetIp), 1u);
	EXPECT_EQ(CarrierView::between(busy, "\nTo: ", "\r\n"), earlyTo)
		<< "the refusal ends the early dialog the 183 opened";
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 0u);
}

TEST(TrunkWiring, ACarrierRefreshReinviteOnATrunkCallIsNotAnswered481)
{
	// #611 review: the trunk dialog has no Session, so #379's "tagged INVITE for
	// an unknown dialog gets 481" answered the carrier's session refresh with a
	// 481 -- which ends the call, 911 over the trunk included.
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-1"));
	const auto carrier = CarrierView::from(b.firstWith("INVITE sip:+1"));
	ASSERT_FALSE(carrier.callID.empty());
	b.handler.handle(RequestsHandler::getMessageFromPool(
		carrier.response("SIP/2.0 200 OK", /*withSdp=*/true), addrFor(kSbcIp)));
	ASSERT_EQ(b.handler.trunkRelaysInUseForTest(), 1u) << "precondition: the call is up";

	b.sent.clear();
	b.handler.handle(RequestsHandler::getMessageFromPool(carrier.reinvite(carrier.callID), addrFor(kSbcIp)));
	EXPECT_EQ(b.countWithTo("481", kSbcIp), 0u) << "the carrier's refresh must not end the call";
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 1u);

	// Positive control: the same tagged re-INVITE naming a dialog nobody owns
	// IS answered 481, so the check above is not passing for want of a 481 path.
	b.sent.clear();
	b.handler.handle(RequestsHandler::getMessageFromPool(carrier.reinvite("nobody-owns-this"), addrFor(kSbcIp)));
	EXPECT_EQ(b.countWithTo("481", kSbcIp), 1u);
}

// ── Issue #604: RTP inactivity ends a call whose media stopped with no BYE ──

TEST(TrunkWiring, ATrunkCallWhoseLegsBothGoSilentIsEndedAfterTheInactivityTimeout)
{
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-604"));
	const auto carrier = CarrierView::from(b.firstWith("INVITE sip:+1"));
	b.handler.handle(RequestsHandler::getMessageFromPool(
		carrier.response("SIP/2.0 200 OK", true), addrFor(kSbcIp)));
	ASSERT_EQ(b.handler.trunkRelaysInUseForTest(), 1u) << "precondition: the call is up";
	const std::string id = "Call-ID: call-604";
	auto session = b.handler.getSession(id);
	ASSERT_TRUE(session.has_value());
	b.handler.tick();   // arms the watch

	// Control: both legs still flowing 61 s on. The call stays up.
	session.value()->ageRtpWatchForTest(std::chrono::seconds(61));
	ASSERT_TRUE(b.handler.trunkRtpForTest(id, /*fromCarrier=*/true));
	ASSERT_TRUE(b.handler.trunkRtpForTest(id, /*fromCarrier=*/false));
	b.handler.forceNextTickForTest();
	b.sent.clear();
	b.handler.tick();
	ASSERT_EQ(b.countWithTo("BYE", kSbcIp), 0u) << "a call with media both ways is live";
	ASSERT_EQ(b.handler.trunkRelaysInUseForTest(), 1u);

	// The phone loses power and the carrier goes quiet: both legs dead for 61 s.
	session.value()->ageRtpWatchForTest(std::chrono::seconds(61));
	b.handler.forceNextTickForTest();
	b.sent.clear();
	b.handler.tick();

	EXPECT_EQ(b.countWithTo("BYE", kSbcIp), 1u) << "the billed carrier leg must be hung up";
	EXPECT_EQ(b.countWithTo("BYE", kHandsetIp), 1u) << "and the handset told, best effort";
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 0u) << "and the relay pair released";
	EXPECT_FALSE(b.handler.getSession(id).has_value());
}

TEST(TrunkWiring, TheInactivityReapByeToTheHandsetOfATrunkCallIsFromUsAndToTheHandset)
{
	// #700, the #604 reap: same orientation rule as the carrier-hangup BYE.
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-700r"));
	const auto carrier = CarrierView::from(b.firstWith("INVITE sip:+1"));
	b.handler.handle(RequestsHandler::getMessageFromPool(
		carrier.response("SIP/2.0 200 OK", true), addrFor(kSbcIp)));
	const std::string ok = b.firstWithTo("SIP/2.0 200 OK", kHandsetIp);
	ASSERT_FALSE(ok.empty()) << "precondition: the handset was answered";
	const std::string id = "Call-ID: call-700r";
	auto session = b.handler.getSession(id);
	ASSERT_TRUE(session.has_value());
	b.handler.tick();   // arms the watch
	session.value()->ageRtpWatchForTest(std::chrono::seconds(61));
	b.handler.forceNextTickForTest();
	b.sent.clear();

	b.handler.tick();

	const std::string bye = b.firstWithTo("BYE", kHandsetIp);
	ASSERT_FALSE(bye.empty()) << "the silent trunk call must be ended with a BYE to the handset";
	expectHandsetByeIsFromUs(ok, bye, "ftcall-700r");
}

TEST(TrunkWiring, ATrunkCallWithOneLegSilentAndTheOtherTalkingStaysUp)
{
	// CaveJay on #612: one silent leg is a healthy call (a VAD-silent listener,
	// far-end hold, mute). Only BOTH legs silent ends it.
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-604c"));
	const auto carrier = CarrierView::from(b.firstWith("INVITE sip:+1"));
	b.handler.handle(RequestsHandler::getMessageFromPool(
		carrier.response("SIP/2.0 200 OK", true), addrFor(kSbcIp)));
	ASSERT_EQ(b.handler.trunkRelaysInUseForTest(), 1u) << "precondition: the call is up";
	const std::string id = "Call-ID: call-604c";
	auto session = b.handler.getSession(id);
	ASSERT_TRUE(session.has_value());
	b.handler.tick();   // arms the watch

	for (bool fromCarrier : {true, false})
	{
		session.value()->ageRtpWatchForTest(std::chrono::seconds(61));
		ASSERT_TRUE(b.handler.trunkRtpForTest(id, fromCarrier));
		b.handler.forceNextTickForTest();
		b.sent.clear();
		b.handler.tick();
		ASSERT_TRUE(b.handler.getSession(id).has_value())
			<< "only the " << (fromCarrier ? "carrier" : "handset") << " leg talked; the call stays up";
		ASSERT_EQ(b.countWithTo("BYE", kSbcIp), 0u);
	}
}

TEST(TrunkWiring, AnEmergencyCallIsNotEndedForTenMinutesOfRtpSilence)
{
	// A 911 caller who cannot speak, on a phone with silence suppression, sends
	// no RTP. Hanging up on them is worse than holding a leg. Positive control:
	// an ordinary call equally silent beside it IS ended.
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "911", "call-911"));
	const auto e911 = CarrierView::from(b.firstWith("INVITE sip:911"));
	ASSERT_FALSE(e911.callID.empty()) << "precondition: 911 went to the trunk";
	b.handler.handle(RequestsHandler::getMessageFromPool(
		e911.response("SIP/2.0 200 OK", true), addrFor(kSbcIp)));
	b.sent.clear();
	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-604b", 40002));
	const auto plain = CarrierView::from(b.firstWith("INVITE sip:+1"));
	b.handler.handle(RequestsHandler::getMessageFromPool(
		plain.response("SIP/2.0 200 OK", true), addrFor(kSbcIp)));
	ASSERT_EQ(b.handler.trunkRelaysInUseForTest(), 2u) << "precondition: both calls are up";
	auto s911 = b.handler.getSession("Call-ID: call-911");
	auto sPlain = b.handler.getSession("Call-ID: call-604b");
	ASSERT_TRUE(s911.has_value() && sPlain.has_value());
	b.handler.tick();   // arms the watch

	s911.value()->ageRtpWatchForTest(std::chrono::seconds(600));
	sPlain.value()->ageRtpWatchForTest(std::chrono::seconds(61));
	b.handler.forceNextTickForTest();
	b.sent.clear();
	b.handler.tick();

	EXPECT_TRUE(b.handler.getSession("Call-ID: call-911").has_value()) << "911 is not reaped at 10 min (its bound is 4 h, #741)";
	EXPECT_FALSE(b.handler.getSession("Call-ID: call-604b").has_value())
		<< "control: the ordinary silent call is";
	EXPECT_EQ(b.countWithTo("BYE", kSbcIp), 1u) << "exactly one carrier leg hung up";
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 1u) << "the 911 relay pair is untouched";
}

TEST(TrunkWiring, AnEmergencyCallWithBothLegsSilentEndsAtFourHoursAndNotBefore)
{
	// #741 (desmo): a 911 whose phone and far end both vanished (no BYE, no RTP
	// on either leg) is ended after 4 h of silence, through endCall, and
	// counted. A live 911 is never cut: the clock only runs while BOTH legs
	// are silent. AnEmergencyCallIsNotEndedForTenMinutesOfRtpSilence above keeps pinning
	// that 10 minutes of silence ends nothing.
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "911", "call-741"));
	const auto e911 = CarrierView::from(b.firstWith("INVITE sip:911"));
	ASSERT_FALSE(e911.callID.empty()) << "precondition: 911 went to the trunk";
	b.handler.handle(RequestsHandler::getMessageFromPool(
		e911.response("SIP/2.0 200 OK", true), addrFor(kSbcIp)));
	auto s911 = b.handler.getSession("Call-ID: call-741");
	ASSERT_TRUE(s911.has_value());
	b.handler.tick();   // arms the watch

	s911.value()->ageRtpWatchForTest(std::chrono::hours(4) - std::chrono::seconds(1));
	b.handler.forceNextTickForTest();
	b.sent.clear();
	b.handler.tick();
	EXPECT_TRUE(b.handler.getSession("Call-ID: call-741").has_value()) << "ended before 4 h";
	EXPECT_EQ(b.countWithTo("BYE", kSbcIp), 0u);
	EXPECT_EQ(b.handler.getEmergencyRtpReaps(), 0u);

	s911.value()->ageRtpWatchForTest(std::chrono::seconds(1));
	b.handler.forceNextTickForTest();
	b.handler.tick();
	EXPECT_FALSE(b.handler.getSession("Call-ID: call-741").has_value()) << "not ended at 4 h";
	EXPECT_EQ(b.countWithTo("BYE", kSbcIp), 1u) << "the carrier leg is hung up through endCall";
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 0u) << "and its relay pair released";
	EXPECT_EQ(b.handler.getEmergencyRtpReaps(), 1u) << "and counted";
}

TEST(TrunkWiring, AnEmergencyCallWithOneWayAudioIsNeverEndedPastFourHours)
{
	// #741 review: the 4 h clock runs only while BOTH legs are silent. A 911
	// where one side talks (a caller who cannot speak, a PSAP on hold music) is
	// a live call: each leg's audio restarts the clock, so it outlives 4 h.
	// Mirrors ATrunkCallWithOneLegSilentAndTheOtherTalkingStaysUp. Positive
	// control: the test above ends the same call shape at 4 h when silent.
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "911", "call-741o"));
	const auto e911 = CarrierView::from(b.firstWith("INVITE sip:911"));
	ASSERT_FALSE(e911.callID.empty()) << "precondition: 911 went to the trunk";
	b.handler.handle(RequestsHandler::getMessageFromPool(
		e911.response("SIP/2.0 200 OK", true), addrFor(kSbcIp)));
	const std::string id = "Call-ID: call-741o";
	auto s911 = b.handler.getSession(id);
	ASSERT_TRUE(s911.has_value());
	b.handler.tick();   // arms the watch

	for (bool fromCarrier : {true, false})
	{
		s911.value()->ageRtpWatchForTest(std::chrono::hours(4) + std::chrono::seconds(1));
		ASSERT_TRUE(b.handler.trunkRtpForTest(id, fromCarrier));
		b.handler.forceNextTickForTest();
		b.sent.clear();
		b.handler.tick();
		ASSERT_TRUE(b.handler.getSession(id).has_value())
			<< "only the " << (fromCarrier ? "carrier" : "handset") << " leg talked; the 911 stays up";
		ASSERT_EQ(b.countWithTo("BYE", kSbcIp), 0u);
	}
	EXPECT_EQ(b.handler.getEmergencyRtpReaps(), 0u);
}

// ── Issue #399: the trunk REGISTERs, from tick(), and answers the 401 ───────
//
// SipTrunk_test.cpp pins the REGISTER itself. This pins the part #355 taught
// us to check separately: that the engine actually calls it, and that a
// response arriving through handle() reaches it.
TEST(TrunkWiring, TickRegistersTheTrunkAndA401ThroughHandleIsAnswered)
{
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	ASSERT_TRUE(b.handler.setTrunkCredentials("s3cret-reg"));

	b.handler.tick();
	ASSERT_EQ(b.countWithTo("REGISTER sip:", kSbcIp), 1u)
		<< "tick() never registered the trunk: the carrier will not answer our INVITEs";

	const std::string reg = b.firstWith("REGISTER sip:");
	const std::string callId = CarrierView::field(reg, "Call-ID: ");
	const std::string challenge =
		"SIP/2.0 401 Unauthorized\r\n"
		"Via: " + CarrierView::field(reg, "Via: ") + "\r\n"
		"From: " + CarrierView::field(reg, "From: ") + "\r\n"
		"To: " + CarrierView::field(reg, "To: ") + ";tag=reg-tag\r\n"
		"Call-ID: " + callId + "\r\n"
		"CSeq: 1 REGISTER\r\n"
		"WWW-Authenticate: Digest realm=\"carrier.example\", nonce=\"wiren0nce\", qop=\"auth\"\r\n"
		"Content-Length: 0\r\n\r\n";
	b.sent.clear();
	b.handler.handle(RequestsHandler::getMessageFromPool(challenge, addrFor(kSbcIp)));

	ASSERT_EQ(b.countWithTo("REGISTER sip:", kSbcIp), 1u) << "the 401 must be answered";
	const std::string signedReg = b.firstWith("REGISTER sip:");
	EXPECT_NE(signedReg.find("Call-ID: " + callId), std::string::npos);
	EXPECT_NE(signedReg.find("\r\nAuthorization: Digest username=\"15551230000\""),
		std::string::npos) << signedReg;
	EXPECT_EQ(b.sent.size(), 1u) << "and nothing else answers the carrier's 401";
}

// ── Issue #663: the forged-response counters reach /api/status ─────────────
//
// SipTrunk_test.cpp pins the counting and the power-of-two logging. This pins
// that an operator can actually see the counts: both drops arrive through
// handle(), and /api/status reports each with its own value.
namespace
{
	std::string statusBody(int port)
	{
#if defined(_WIN32) || defined(_WIN64)
		SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
		if (s == INVALID_SOCKET) return "";
#else
		int s = socket(AF_INET, SOCK_STREAM, 0);
		if (s < 0) return "";
#endif
		sockaddr_in addr{};
		addr.sin_family = AF_INET;
		addr.sin_port = htons(static_cast<uint16_t>(port));
		inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
		std::string resp;
		if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0)
		{
			const std::string req = "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\n"
			                        "Connection: close\r\n\r\n";
			send(s, req.c_str(), static_cast<int>(req.size()), 0);
			char buf[512];
			int n;
			while ((n = recv(s, buf, sizeof(buf), 0)) > 0) resp.append(buf, static_cast<size_t>(n));
		}
#if defined(_WIN32) || defined(_WIN64)
		closesocket(s);
#else
		close(s);
#endif
		return resp;
	}
}

TEST(TrunkWiring, StatusReportsForgedRegisterAndDialogResponseCounts)
{
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	ASSERT_TRUE(b.handler.setTrunkCredentials("s3cret-reg"));
	b.handler.tick();
	const std::string reg = b.firstWith("REGISTER sip:");
	ASSERT_FALSE(reg.empty()) << "tick() must have registered the trunk";

	HttpServer server("127.0.0.1", 0, nullptr);   // #540: OS-assigned port
	const int port = server.port();
	server.attachHandler(&b.handler);
	server.start();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));

	// Positive control: both fields are there, at zero, before anything is forged.
	std::string status = statusBody(port);
	EXPECT_NE(status.find("\"trunkForgedRegisterResponses\":0,"), std::string::npos) << status;
	EXPECT_NE(status.find("\"trunkForgedDialogResponses\":0,"), std::string::npos) << status;

	// Two forged answers to our REGISTER...
	const std::string regOk =
		"SIP/2.0 200 OK\r\n"
		"Via: " + CarrierView::field(reg, "Via: ") + "\r\n"
		"From: " + CarrierView::field(reg, "From: ") + "\r\n"
		"To: " + CarrierView::field(reg, "To: ") + ";tag=reg-tag\r\n"
		"Call-ID: " + CarrierView::field(reg, "Call-ID: ") + "\r\n"
		"CSeq: 1 REGISTER\r\n"
		"Expires: 3600\r\n"
		"Content-Length: 0\r\n\r\n";
	for (int i = 0; i < 2; ++i)
	{
		b.handler.handle(RequestsHandler::getMessageFromPool(regOk, addrFor(kForgerIp)));
	}

	// ...and three forged answers to a trunk call's INVITE.
	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-1"));
	const auto carrier = CarrierView::from(b.firstWith("INVITE sip:+1"));
	for (int i = 0; i < 3; ++i)
	{
		b.handler.handle(RequestsHandler::getMessageFromPool(
			carrier.response("SIP/2.0 200 OK", true), addrFor(kForgerIp)));
	}

	status = statusBody(port);
	EXPECT_NE(status.find("\"trunkForgedRegisterResponses\":2,"), std::string::npos) << status;
	EXPECT_NE(status.find("\"trunkForgedDialogResponses\":3,"), std::string::npos) << status;
}

// Issue #666: BYEs refused by the #356 check show in /api/status too.
TEST(TrunkWiring, StatusReportsRefusedDialogByes)
{
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-1"));
	auto carrier = CarrierView::from(b.firstWith("INVITE sip:+1"));
	b.handler.handle(RequestsHandler::getMessageFromPool(
		carrier.response("SIP/2.0 200 OK", true), addrFor(kSbcIp)));

	HttpServer server("127.0.0.1", 0, nullptr);   // #540: OS-assigned port
	const int port = server.port();
	server.attachHandler(&b.handler);
	server.start();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));

	// Positive control: the field is there, at zero, before any BYE.
	std::string status = statusBody(port);
	EXPECT_NE(status.find("\"trunkRefusedDialogByes\":0,"), std::string::npos) << status;

	CarrierView forger = carrier;
	forger.toTag = "guessed";
	b.sent.clear();
	// Two distinct BYEs (own branch and CSeq): an identical resend is a
	// retransmission, answered without reaching the #356 check again.
	for (int i = 0; i < 2; ++i)
	{
		std::string bye = forger.bye();
		bye.replace(bye.find("z9hG4bKcarrierbye"), 17, "z9hG4bKforgedbye" + std::to_string(i));
		bye.replace(bye.find("CSeq: 2 BYE"), 11, "CSeq: " + std::to_string(2 + i) + " BYE");
		b.handler.handle(RequestsHandler::getMessageFromPool(bye, addrFor(kForgerIp)));
	}
	ASSERT_EQ(b.countWithTo("403", kForgerIp), 2u);

	status = statusBody(port);
	EXPECT_NE(status.find("\"trunkRefusedDialogByes\":2,"), std::string::npos) << status;
}

// ── #747: the handset hangs up while the carrier leg still rings ────────────
//
// onCancel() had no trunk branch, so the CANCEL fell through to a 404 for the
// dialled PSTN number, the carrier kept ringing, and the handset's INVITE never
// got its 487.

TEST(TrunkWiring, AHandsetCancelWhileTheCarrierRingsCancelsTheCarrierLeg)
{
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-1"));
	const auto carrier = CarrierView::from(b.firstWith("INVITE sip:+1"));
	b.handler.handle(RequestsHandler::getMessageFromPool(
		carrier.response("SIP/2.0 180 Ringing", /*withSdp=*/false), addrFor(kSbcIp)));
	b.sent.clear();

	b.handler.handle(makeHandsetCancel("1001", "92025550123", "call-1"));

	EXPECT_TRUE(b.firstWith("404").empty()) << "RFC 3261 s9.2: a CANCEL is answered 200 or 481, never 404";
	EXPECT_EQ(b.countWithTo("SIP/2.0 200", kHandsetIp), 1u) << "the CANCEL itself";
	EXPECT_EQ(b.countWithTo("SIP/2.0 487", kHandsetIp), 1u) << "the handset's INVITE";
	ASSERT_EQ(b.countWithTo("CANCEL", kSbcIp), 1u) << "the carrier leg keeps ringing until told";
	// RFC 3261 s8.2.6.2 and s9.2: the CANCEL's own 200 is a dialog-forming response, so it
	// carries a To tag, and it is the same tag the 487 to the INVITE carries.
	const auto toTag = [](const std::string& m) {
		const size_t at = m.find("\r\nTo: ");
		if (at == std::string::npos) return std::string();
		const std::string line = m.substr(at + 2, m.find("\r\n", at + 2) - at - 2);
		const size_t t = line.find(";tag=");
		return t == std::string::npos ? std::string() : line.substr(t + 5);
	};
	const std::string cancelOkToHandset = b.firstWith("SIP/2.0 200");
	const std::string inviteFinal = b.firstWith("SIP/2.0 487");
	EXPECT_FALSE(toTag(cancelOkToHandset).empty()) << "the 200 to the CANCEL has no To tag:\n" << cancelOkToHandset;
	EXPECT_EQ(toTag(cancelOkToHandset), toTag(inviteFinal)) << "one tag for the CANCEL's 200 and the INVITE's 487";
	const std::string cancel = b.firstWith("CANCEL sip:+12025550123");
	EXPECT_NE(cancel.find(";branch=" + carrier.branch), std::string::npos)
		<< "on the carrier INVITE's own branch";
	EXPECT_EQ(b.countWithTo("BYE", kSbcIp), 0u) << "the call was never answered";
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 0u);
	b.sent.clear();

	// The carrier's 200 to the CANCEL, then its 487 to the INVITE: the 487 is
	// ACKed and nothing further reaches the handset.
	std::string cancelOk = carrier.response("SIP/2.0 200 OK", /*withSdp=*/false);
	cancelOk.replace(cancelOk.find("CSeq: 1 INVITE"), 14, "CSeq: 1 CANCEL");
	b.handler.handle(RequestsHandler::getMessageFromPool(cancelOk, addrFor(kSbcIp)));
	b.handler.handle(RequestsHandler::getMessageFromPool(
		carrier.response("SIP/2.0 487 Request Terminated", /*withSdp=*/false), addrFor(kSbcIp)));

	EXPECT_EQ(b.countWithTo("ACK", kSbcIp), 1u);
	EXPECT_EQ(b.sent.size(), 1u) << "no stray 404 or second 487 at the handset";
}

TEST(TrunkWiring, ACarrierAnswerThatCrossesTheHandsetCancelIsByedAndNeverBridged)
{
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-1"));
	const auto carrier = CarrierView::from(b.firstWith("INVITE sip:+1"));
	b.handler.handle(RequestsHandler::getMessageFromPool(
		carrier.response("SIP/2.0 180 Ringing", /*withSdp=*/false), addrFor(kSbcIp)));
	b.handler.handle(makeHandsetCancel("1001", "92025550123", "call-1"));
	b.sent.clear();

	b.handler.handle(RequestsHandler::getMessageFromPool(
		carrier.response("SIP/2.0 200 OK", /*withSdp=*/true), addrFor(kSbcIp)));

	EXPECT_EQ(b.countWithTo("ACK", kSbcIp), 1u);
	EXPECT_EQ(b.countWithTo("BYE", kSbcIp), 1u) << "the carrier leg is up and billing";
	EXPECT_EQ(b.sent.size(), 2u) << "nothing at the handset: it already has its 487";
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 0u);
}

// #794: the handset gives up before the carrier has sent ANY provisional. RFC
// 3261 s9.1 forbids a CANCEL then, and hangup() used to free the trunk slot
// instead, so the carrier's later 180 found no dialog and the far end rang on.
TEST(TrunkWiring, AHandsetCancelBeforeAnyCarrierProvisionalCancelsTheCarrierLegOnItsFirst1xx)
{
	Bench b;
	b.handler.setTrunkConfig(trunkConfig());
	b.handler.handle(makeTrunkDial("1001", "92025550123", "call-794"));
	const auto carrier = CarrierView::from(b.firstWith("INVITE sip:+1"));
	b.sent.clear();

	b.handler.handle(makeHandsetCancel("1001", "92025550123", "call-794"));

	EXPECT_EQ(b.countWithTo("SIP/2.0 200", kHandsetIp), 1u) << "the CANCEL itself";
	EXPECT_EQ(b.countWithTo("SIP/2.0 487", kHandsetIp), 1u) << "the handset's INVITE";
	EXPECT_EQ(b.countWithTo("CANCEL", kSbcIp), 0u) << "RFC 3261 s9.1: no CANCEL before a provisional";
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 0u);
	b.sent.clear();

	// The carrier's first provisional lands after the handset is gone.
	b.handler.handle(RequestsHandler::getMessageFromPool(
		carrier.response("SIP/2.0 180 Ringing", /*withSdp=*/false), addrFor(kSbcIp)));

	ASSERT_EQ(b.countWithTo("CANCEL", kSbcIp), 1u) << "the far end keeps ringing until the carrier is told";
	EXPECT_NE(b.firstWith("CANCEL sip:+12025550123").find(";branch=" + carrier.branch), std::string::npos)
		<< "on the carrier INVITE's own branch";
	EXPECT_EQ(b.sent.size(), 1u) << "nothing at the handset: it already has its 487";
	b.sent.clear();

	b.handler.handle(RequestsHandler::getMessageFromPool(
		carrier.response("SIP/2.0 487 Request Terminated", /*withSdp=*/false), addrFor(kSbcIp)));

	EXPECT_EQ(b.countWithTo("ACK", kSbcIp), 1u);
	EXPECT_EQ(b.sent.size(), 1u) << "no stray 404 or second 487 at the handset";
}
