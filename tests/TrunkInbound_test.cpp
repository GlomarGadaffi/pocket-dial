// TrunkInbound_test.cpp — issue #398 part B: a new INVITE from the SIP trunk's
// SBC is caught before the registered-caller checks and refused cleanly.
//
// Before this, every carrier call was answered 403 by onInvite's findClient(From)
// check, because a carrier's From names a PSTN caller, never one of our phones.
// Part B recognises the carrier by its source address alone (#356), looks the DID
// up, and gives a final answer the carrier can ACK. Part C forks a routable call
// to the DID's extension and answers the carrier when the handset does.
//
// Extensions here are 2xxx on purpose. Numbers are the fictional 555-01xx range;
// addresses are RFC 5737 TEST-NETs. The 911/933 INVITEs are synthetic host
// messages captured in `sent`; nothing reaches a network.

#include <gtest/gtest.h>

#include <cstdio>
#include <string>
#include <vector>

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include "RequestsHandler.hpp"

namespace
{
	constexpr const char* kServerIp = "192.168.50.1";
	constexpr const char* kPhoneIp  = "192.168.50.21";
	constexpr const char* kSbcIp    = "203.0.113.5";     // RFC 5737 TEST-NET-3
	constexpr const char* kForgerIp = "198.51.100.66";   // RFC 5737 TEST-NET-2
	constexpr const char* kDid      = "+12025550188";
	constexpr const char* kTrunkUser = "15551230000";    // the trunk's own identity (fromUser)
	constexpr const char* kExt      = "2001";

	using SentList = std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>;

	sockaddr_in addrFor(const std::string& ip, uint16_t port = 5060)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(port);
		return s;
	}

	SipTrunk::Config trunkConfig(bool enabled = true, const char* host = kSbcIp)
	{
		SipTrunk::Config c;
		std::snprintf(c.host, sizeof(c.host), "%s", host);
		c.port = 5060;
		std::snprintf(c.fromUser, sizeof(c.fromUser), "%s", kTrunkUser);
		c.enabled = enabled;
		return c;
	}

	std::shared_ptr<SipMessage> makeRegister(const std::string& ext, const std::string& ip)
	{
		const std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKr" + ext + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + ext + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: reg-" + ext + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + ip + ":5060>;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}

	std::string offer(const std::string& ip, const std::string& payloads, const std::string& rtpmap)
	{
		return
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + ip + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + ip + "\r\n"
			"t=0 0\r\n"
			"m=audio 41000 RTP/AVP " + payloads + "\r\n" + rtpmap;
	}

	const std::string kPcmuRtpmap = "a=rtpmap:0 PCMU/8000\r\na=rtpmap:101 telephone-event/8000\r\n";
	const std::string kPcmaRtpmap = "a=rtpmap:8 PCMA/8000\r\na=rtpmap:101 telephone-event/8000\r\n";

	// An INVITE from `srcIp` with the given Request-URI and To users. A registered
	// trunk (#399) is called at the Contact it registered, so its Request-URI user
	// is the trunk's own; an IP-authenticated trunk puts the DID there instead.
	std::shared_ptr<SipMessage> makeInvite(const std::string& ruriUser, const std::string& toUser,
		const std::string& callId, const std::string& srcIp = kSbcIp, bool pcmu = true,
		const std::string& fromUser = "+12025550177", int dtmfPt = 101)
	{
		const std::string pt = std::to_string(dtmfPt);
		const std::string body = !pcmu ? offer(srcIp, "8 101", kPcmaRtpmap)
			: offer(srcIp, "0 " + pt, "a=rtpmap:0 PCMU/8000\r\na=rtpmap:" + pt + " telephone-event/8000\r\n");
		const std::string raw =
			"INVITE sip:" + ruriUser + "@" + kServerIp + ":5060 SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bKc" + callId + "\r\n"
			"From: <sip:" + fromUser + "@" + srcIp + ">;tag=cf" + callId + "\r\n"
			"To: <sip:" + toUser + "@" + kServerIp + ">\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:" + fromUser + "@" + srcIp + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}

	// The carrier's ACK for a non-2xx final (RFC 3261 s17.1.1.3): the INVITE's
	// branch and CSeq number, and the To of the response, tag included.
	std::shared_ptr<SipMessage> makeCarrierAck(const std::string& ruriUser, const std::string& toLine,
		const std::string& callId)
	{
		const std::string raw =
			"ACK sip:" + ruriUser + "@" + kServerIp + ":5060 SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(kSbcIp) + ":5060;branch=z9hG4bKc" + callId + "\r\n"
			"From: <sip:+12025550177@" + kSbcIp + ">;tag=cf" + callId + "\r\n"
			"To: " + toLine + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 ACK\r\n"
			"Max-Forwards: 70\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(kSbcIp));
	}

	std::string field(const std::string& m, const std::string& name)
	{
		const size_t p = m.find("\r\n" + name);
		if (p == std::string::npos) return {};
		const size_t s = p + 2 + name.size();
		return m.substr(s, m.find("\r\n", s) - s);
	}

	std::string between(const std::string& m, const std::string& a, const std::string& b)
	{
		const size_t p = m.find(a);
		if (p == std::string::npos) return {};
		const size_t s = p + a.size();
		return m.substr(s, m.find(b, s) - s);
	}

	// An outbound trunk dialog as the carrier sees it, read off the INVITE the
	// PBX sent, so the carrier's messages below match it for real.
	struct CarrierLeg
	{
		std::string callID, branch, fromTag;

		static CarrierLeg from(const std::string& invite)
		{
			CarrierLeg c;
			c.callID  = field(invite, "Call-ID: ");
			c.branch  = between(invite, ";branch=", "\r\n");
			c.fromTag = between(invite, ";tag=", "\r\n");
			return c;
		}

		std::string ok() const
		{
			const std::string sdp =
				"v=0\r\no=- 0 0 IN IP4 203.0.113.9\r\ns=-\r\nc=IN IP4 203.0.113.9\r\n"
				"t=0 0\r\nm=audio 41000 RTP/AVP 0 101\r\na=rtpmap:0 PCMU/8000\r\n"
				"a=rtpmap:101 telephone-event/8000\r\n";
			return
				"SIP/2.0 200 OK\r\n"
				"Via: SIP/2.0/UDP " + std::string(kServerIp) + ":5060;branch=" + branch + "\r\n"
				"From: <sip:" + kTrunkUser + "@" + kSbcIp + ":5060>;tag=" + fromTag + "\r\n"
				"To: <sip:+12025550123@" + kSbcIp + ":5060>;tag=carrier-tag\r\n"
				"Call-ID: " + callID + "\r\n"
				"CSeq: 1 INVITE\r\n"
				"Contact: <sip:+12025550123@203.0.113.9:5060>\r\n"
				"Content-Type: application/sdp\r\n"
				"Content-Length: " + std::to_string(sdp.size()) + "\r\n\r\n" + sdp;
		}

		// The carrier's RFC 4028 session refresh: in-dialog, so To carries our
		// tag, and its To user is the trunk's own identity.
		std::string refresh() const
		{
			return
				"INVITE sip:" + std::string(kTrunkUser) + "@" + kServerIp + ":5060 SIP/2.0\r\n"
				"Via: SIP/2.0/UDP " + std::string(kSbcIp) + ":5060;branch=z9hG4bKrefresh\r\n"
				"From: <sip:+12025550123@" + kSbcIp + ":5060>;tag=carrier-tag\r\n"
				"To: <sip:" + kTrunkUser + "@" + kSbcIp + ":5060>;tag=" + fromTag + "\r\n"
				"Call-ID: " + callID + "\r\n"
				"CSeq: 2 INVITE\r\n"
				"Contact: <sip:+12025550123@203.0.113.9:5060>\r\n"
				"Content-Length: 0\r\n\r\n";
		}
	};

	// A trunk pointed at kSbcIp, an isolated DID table, and kExt registered.
	struct Bench
	{
		SentList sent;
		RequestsHandler handler;
		std::string tapiPath, didPath;

		explicit Bench(bool trunkEnabled = true, const char* sbcHost = kSbcIp) : handler(kServerIp, 5060,
			[this](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
				sent.emplace_back(a, std::move(m));
			})
		{
			const std::string name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
			tapiPath = "test_trunkinbound_tapicfg_" + name + ".cfg";
			didPath  = "test_trunkinbound_didmap_" + name + ".cfg";
			std::remove(tapiPath.c_str());
			std::remove(didPath.c_str());
			handler.setTelephonyStorePathsForTest(tapiPath, didPath);
			handler.setTrunkConfig(trunkConfig(trunkEnabled, sbcHost));
			handler.handle(makeRegister(kExt, kPhoneIp));
			sent.clear();
		}
		~Bench()
		{
			std::remove(tapiPath.c_str());
			std::remove(didPath.c_str());
		}

		// Raw text of the first message sent to `ip` whose first line contains `needle`.
		std::string firstTo(const std::string& needle, const std::string& ip) const
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

		size_t countTo(const std::string& ip) const
		{
			const uint32_t want = inet_addr(ip.c_str());
			size_t n = 0;
			for (const auto& [addr, msg] : sent)
			{
				if (msg && addr.sin_addr.s_addr == want) ++n;
			}
			return n;
		}

		// The status line of the first response sent to the carrier. Responses
		// only: a live outbound trunk call may put a retransmitted INVITE there too.
		std::string carrierStatus() const
		{
			for (const auto& [addr, msg] : sent)
			{
				if (!msg || addr.sin_addr.s_addr != inet_addr(kSbcIp)) continue;
				const std::string raw = msg->toString();
				if (raw.rfind("SIP/2.0 ", 0) == 0) return raw.substr(0, raw.find("\r\n"));
			}
			return {};
		}
	};
}

// ── The catch: by source address, never by From ──────────────────────────────

TEST(TrunkInbound, ACarrierInviteToAMappedDidIsNotRefusedForItsSource)
{
	Bench b;
	ASSERT_EQ(b.handler.setDidMapping(kDid, kExt), "");

	b.handler.handle(makeInvite(kDid, kDid, "in-mapped"));

	EXPECT_EQ(b.carrierStatus(), "SIP/2.0 100 Trying")
		<< "mapped, registered, PCMU, relay free: the call is taken (part C), "
		   "never the 403 an unregistered caller gets";
	EXPECT_NE(field(b.firstTo("100", kSbcIp), "To: ").find(";tag="), std::string::npos)
		<< "every response to the INVITE carries our one To tag (RFC 3261 s8.2.6.2)";
	EXPECT_FALSE(b.firstTo("INVITE sip:2001@", kPhoneIp).empty()) << "the extension rings";
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 1u) << "on a relay pair of its own";
	EXPECT_FALSE(b.handler.getSession("Call-ID: in-mapped").has_value())
		<< "the fork has a Call-ID of its own, never the carrier's (the #386 trap)";
}

TEST(TrunkInbound, AnInviteFromAnyOtherAddressIsStillRefusedAsBefore)
{
	Bench b;
	ASSERT_EQ(b.handler.setDidMapping(kDid, kExt), "");

	b.handler.handle(makeInvite(kDid, kDid, "in-forged", kForgerIp));

	EXPECT_FALSE(b.firstTo("403", kForgerIp).empty())
		<< "only the SBC's address is the carrier (#356); a stranger naming a mapped DID is a stranger";
	EXPECT_TRUE(b.firstTo("480", kForgerIp).empty());
	EXPECT_EQ(b.countTo(kPhoneIp), 0u);
}

TEST(TrunkInbound, WithTheTrunkDisabledTheSbcAddressIsRefusedAsBefore)
{
	Bench b(/*trunkEnabled=*/false);
	ASSERT_EQ(b.handler.setDidMapping(kDid, kExt), "");

	b.handler.handle(makeInvite(kDid, kDid, "in-off"));

	EXPECT_EQ(b.carrierStatus(), "SIP/2.0 403 Forbidden");
}

TEST(TrunkInbound, ACarrierRefreshOnALiveOutboundTrunkCallIsNotCaught)
{
	// Review of #847: the 481 check lets a tagged INVITE on a trunk-owned Call-ID
	// through (#611), so the catch must take only a dialog-initial INVITE. A 404
	// to this refresh would end the call (RFC 5057 s5.1); main answers it 403,
	// which ends only the transaction.
	Bench b;
	b.handler.setDialRule("9XXXXXXXXXX", "trunk", "1", 1);
	b.handler.handle(makeInvite("92025550123", "92025550123", "out-refresh", kPhoneIp, true, kExt));
	const CarrierLeg leg = CarrierLeg::from(b.firstTo("INVITE sip:+1", kSbcIp));
	ASSERT_FALSE(leg.callID.empty()) << "precondition: the call went to the trunk";
	b.handler.handle(RequestsHandler::getMessageFromPool(leg.ok(), addrFor(kSbcIp)));
	ASSERT_EQ(b.handler.trunkRelaysInUseForTest(), 1u) << "precondition: the call is up";
	b.sent.clear();

	b.handler.handle(RequestsHandler::getMessageFromPool(leg.refresh(), addrFor(kSbcIp)));

	for (const char* code : {"404", "480", "486", "488", "481"})
	{
		EXPECT_TRUE(b.firstTo(code, kSbcIp).empty()) << "the carrier's refresh was answered " << code;
	}
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 1u) << "the call stays up";
}

TEST(TrunkInbound, ATrunkHostOfTheAnyAddressMatchesNoSource)
{
	// Review of #847: "0.0.0.0" resolves as a literal, and must not make a
	// datagram forged from 0.0.0.0 the carrier.
	Bench b(/*trunkEnabled=*/true, "0.0.0.0");
	ASSERT_EQ(b.handler.setDidMapping(kDid, kExt), "");

	b.handler.handle(makeInvite(kDid, kDid, "in-any", "0.0.0.0"));

	EXPECT_FALSE(b.firstTo("403", "0.0.0.0").empty()) << "refused as any unregistered caller, as before #398";
	EXPECT_TRUE(b.firstTo("480", "0.0.0.0").empty());
}

TEST(TrunkInbound, APhoneRegisteredFromTheSbcAddressStillCallsAsAPhone)
{
	// An FXS port on the carrier's own gateway is a phone, and its calls keep
	// the phone path.
	Bench b;
	b.handler.handle(makeRegister("2002", kSbcIp));
	b.sent.clear();

	b.handler.handle(makeInvite(kExt, kExt, "in-phone", kSbcIp, true, "2002"));

	EXPECT_FALSE(b.firstTo("INVITE", kPhoneIp).empty()) << "2002 rings 2001 as any phone would";
	EXPECT_TRUE(b.firstTo("404", kSbcIp).empty());
	EXPECT_TRUE(b.firstTo("480", kSbcIp).empty());
}

namespace
{
	// From names 2001, registered from kPhoneIp, so the phone exclusion does not
	// apply: only the 911/933 exclusion keeps this off the trunk-inbound path.
	// Today's path for it is the emergency branch, which runs before #497
	// (#454) and places the call on the trunk.
	void expectEmergencyFromSbcKeepsTodaysPath(const std::string& number)
	{
		Bench b;
		b.handler.handle(makeInvite(number, number, "in-" + number, kSbcIp, true, kExt));

		EXPECT_FALSE(b.firstTo("INVITE sip:" + number, kSbcIp).empty())
			<< number << " reached the emergency branch and went out on the trunk, as before #398";
		EXPECT_TRUE(b.firstTo("404", kSbcIp).empty()) << "not refused as an unmapped DID";
		EXPECT_TRUE(b.firstTo("480", kSbcIp).empty());
	}
}

TEST(TrunkInbound, A911FromTheSbcAddressIsNotCaughtAndKeepsTheEmergencyPath)
{
	expectEmergencyFromSbcKeepsTodaysPath("911");
}

TEST(TrunkInbound, A933FromTheSbcAddressIsNotCaughtAndKeepsTheEmergencyPath)
{
	expectEmergencyFromSbcKeepsTodaysPath("933");
}

// ── The DID ───────────────────────────────────────────────────────────────────

TEST(TrunkInbound, AnUnmappedDidIsNotFound)
{
	Bench b;
	ASSERT_EQ(b.handler.setDidMapping(kDid, kExt), "");

	b.handler.handle(makeInvite("+12025550199", "+12025550199", "in-unmapped"));

	EXPECT_EQ(b.carrierStatus(), "SIP/2.0 404 Not Found")
		<< "no mapping is a 404, never the anchor's ring-all (decision 2)";
	EXPECT_EQ(b.countTo(kPhoneIp), 0u);
}

TEST(TrunkInbound, TheDidIsFoundInToWhenTheRequestUriNamesTheTrunk)
{
	Bench b;
	ASSERT_EQ(b.handler.setDidMapping(kDid, kExt), "");

	b.handler.handle(makeInvite(kTrunkUser, kDid, "in-to"));

	EXPECT_FALSE(b.firstTo("INVITE sip:2001@", kPhoneIp).empty())
		<< "a registered trunk is called at its own Contact; the DID is the To user (decision 1)";
}

TEST(TrunkInbound, TheDidIsFoundInTheRequestUriWhenToDoesNotMap)
{
	Bench b;
	ASSERT_EQ(b.handler.setDidMapping(kDid, kExt), "");

	b.handler.handle(makeInvite(kDid, kTrunkUser, "in-ruri"));

	EXPECT_FALSE(b.firstTo("INVITE sip:2001@", kPhoneIp).empty())
		<< "an IP-authenticated trunk puts the DID in the Request-URI (decision 1)";
}

TEST(TrunkInbound, ADidMatchesHoweverTheCarrierSpellsIt)
{
	Bench b;
	ASSERT_EQ(b.handler.setDidMapping("(202) 555-0188", kExt), "");

	b.handler.handle(makeInvite(kDid, kDid, "in-e164"));

	EXPECT_FALSE(b.firstTo("INVITE sip:2001@", kPhoneIp).empty())
		<< "the operator's spelling and the carrier's E.164 are the same line (#165)";
}

// ── The answers ───────────────────────────────────────────────────────────────

TEST(TrunkInbound, AMappedExtensionThatIsNotRegisteredIsUnavailable)
{
	Bench b;
	ASSERT_EQ(b.handler.setDidMapping(kDid, "2009"), "");

	// PCMA only: were the registration not checked first, this would be a 488.
	b.handler.handle(makeInvite(kDid, kDid, "in-unreg", kSbcIp, /*pcmu=*/false));

	EXPECT_EQ(b.carrierStatus(), "SIP/2.0 480 Temporarily Unavailable")
		<< "the carrier can retry or fail over; no other phone rings (decision 3)";
}

TEST(TrunkInbound, WithEveryRelayPairBusyTheCarrierHearsBusy)
{
	Bench b;
	ASSERT_EQ(b.handler.setDidMapping(kDid, kExt), "");
	b.handler.setDialRule("9XXXXXXXXXX", "trunk", "1", 1);
	for (int i = 0; i < static_cast<int>(POCKETDIAL_MAX_TRUNK_CALLS); ++i)
	{
		const std::string ext = "210" + std::to_string(i);
		b.handler.handle(makeRegister(ext, kPhoneIp));
		b.handler.handle(makeInvite("92025550123", "92025550123", "out-" + std::to_string(i),
			kPhoneIp, true, ext));
	}
	ASSERT_EQ(b.handler.trunkRelaysInUseForTest(), static_cast<size_t>(POCKETDIAL_MAX_TRUNK_CALLS));
	b.sent.clear();

	b.handler.handle(makeInvite(kDid, kDid, "in-busy"));

	EXPECT_EQ(b.carrierStatus(), "SIP/2.0 486 Busy Here");
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), static_cast<size_t>(POCKETDIAL_MAX_TRUNK_CALLS));
}

TEST(TrunkInbound, AnOfferWithoutPcmuIsNotAcceptable)
{
	Bench b;
	ASSERT_EQ(b.handler.setDidMapping(kDid, kExt), "");

	b.handler.handle(makeInvite(kDid, kDid, "in-pcma", kSbcIp, /*pcmu=*/false));

	EXPECT_EQ(b.carrierStatus(), "SIP/2.0 488 Not Acceptable Here")
		<< "the relay copies packets, so the carrier leg must be PCMU like the handset leg (decision 4)";
}

// ── The transaction: retransmission and ACK ───────────────────────────────────

TEST(TrunkInbound, ARetransmittedCarrierInviteGetsTheSameAnswerAndIsNotRoutedAgain)
{
	Bench b;
	b.handler.handle(makeInvite(kDid, kDid, "in-rtx"));
	const std::string first = b.firstTo("404", kSbcIp);
	ASSERT_FALSE(first.empty());
	const std::string toTag = field(first, "To: ");
	ASSERT_NE(toTag.find(";tag="), std::string::npos);

	// Mapped between the INVITE and its retransmission: re-routing would now
	// ring the extension.
	ASSERT_EQ(b.handler.setDidMapping(kDid, kExt), "");
	b.sent.clear();
	b.handler.handle(makeInvite(kDid, kDid, "in-rtx"));

	const std::string again = b.firstTo("404", kSbcIp);
	ASSERT_FALSE(again.empty()) << "a retransmission is answered from the server transaction (RFC 3261 s17.2.1)";
	EXPECT_EQ(field(again, "To: "), toTag) << "the same response, not a second run of the routing";
	EXPECT_TRUE(b.firstTo("INVITE", kPhoneIp).empty());

	b.sent.clear();
	b.handler.handle(makeInvite(kDid, kDid, "in-fresh"));
	EXPECT_EQ(b.carrierStatus(), "SIP/2.0 100 Trying") << "a new call sees the new mapping";
}

TEST(TrunkInbound, TheCarriersAckForTheRefusalIsAbsorbed)
{
	Bench b;
	b.handler.handle(makeInvite(kDid, kDid, "in-ack"));
	const std::string refusal = b.firstTo("404", kSbcIp);
	ASSERT_FALSE(refusal.empty());
	b.sent.clear();

	b.handler.handle(makeCarrierAck(kDid, field(refusal, "To: "), "in-ack"));

	EXPECT_TRUE(b.sent.empty()) << "the ACK ends our transaction; nothing is relayed or answered";
	EXPECT_FALSE(b.handler.getSession("Call-ID: in-ack").has_value());
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 0u);
}

// ── Part C: the fork to the extension, and the answer ─────────────────────────

namespace
{
	// The handset's reply to the fork: its Via, From, Call-ID and CSeq echoed,
	// To with the handset's tag.
	std::shared_ptr<SipMessage> handsetReply(const std::string& fork, const std::string& statusLine,
		const std::string& sdp = "")
	{
		std::string raw = statusLine + "\r\n"
			"Via: " + field(fork, "Via: ") + "\r\n"
			"From: " + field(fork, "From: ") + "\r\n"
			"To: " + field(fork, "To: ") + ";tag=hs1\r\n"
			"Call-ID: " + field(fork, "Call-ID: ") + "\r\n"
			"CSeq: " + field(fork, "CSeq: ") + "\r\n"
			"Contact: <sip:2001@" + std::string(kPhoneIp) + ":5060>\r\n";
		if (!sdp.empty()) raw += "Content-Type: application/sdp\r\n";
		raw += "Content-Length: " + std::to_string(sdp.size()) + "\r\n\r\n" + sdp;
		return RequestsHandler::getMessageFromPool(raw, addrFor(kPhoneIp));
	}

	// The carrier calls kDid, mapped to 2001, offering telephone-event as PT 100;
	// returns the INVITE forked to the handset.
	std::string ringFork(Bench& b, const std::string& callId)
	{
		EXPECT_EQ(b.handler.setDidMapping(kDid, kExt), "");
		b.handler.handle(makeInvite(kDid, kDid, callId, kSbcIp, true, "+12025550177", 100));
		return b.firstTo("INVITE sip:2001@", kPhoneIp);
	}

	const std::string kHandsetAnswer =
		"v=0\r\no=- 0 0 IN IP4 192.168.50.21\r\ns=-\r\nc=IN IP4 192.168.50.21\r\nt=0 0\r\n"
		"m=audio 42000 RTP/AVP 0 100\r\na=rtpmap:0 PCMU/8000\r\na=rtpmap:100 telephone-event/8000\r\n";

	// INVITEs sent to the handset on any Call-ID but `fork`'s: a second fork. A
	// Timer A retransmission of the first one keeps its Call-ID.
	size_t otherForks(const Bench& b, const std::string& fork)
	{
		size_t n = 0;
		for (const auto& [addr, msg] : b.sent)
		{
			if (!msg || addr.sin_addr.s_addr != inet_addr(kPhoneIp)) continue;
			const std::string raw = msg->toString();
			if (raw.rfind("INVITE ", 0) == 0 && field(raw, "Call-ID: ") != field(fork, "Call-ID: ")) ++n;
		}
		return n;
	}
}

TEST(TrunkInbound, AMappedDidRingsItsExtensionAndItsAnswerIsRelayedBothWays)
{
	Bench b;
	const std::string fork = ringFork(b, "in-answer");
	ASSERT_FALSE(fork.empty()) << "the extension rings";
	EXPECT_EQ(b.carrierStatus(), "SIP/2.0 100 Trying");
	EXPECT_NE(fork.find("\r\nFrom: \"+12025550177\" <sip:2001@"), std::string::npos) << "the handset shows the caller";
	EXPECT_NE(fork.find("\r\nc=IN IP4 192.168.50.1\r\n"), std::string::npos) << "our offer, not the carrier's";
	EXPECT_NE(fork.find(" RTP/AVP 0 100\r\n"), std::string::npos)
		<< "PCMU only, and the carrier's own telephone-event number, so the relay copies DTMF unchanged";
	const std::string forkId = "Call-ID: " + field(fork, "Call-ID: ");
	EXPECT_EQ(forkId.find("in-answer"), std::string::npos) << "a Call-ID of its own (the #386 trap)";

	b.sent.clear();
	b.handler.handle(handsetReply(fork, "SIP/2.0 100 Trying"));
	EXPECT_EQ(b.countTo(kSbcIp), 0u) << "the handset's 100 is ours alone";
	b.handler.handle(handsetReply(fork, "SIP/2.0 180 Ringing"));
	EXPECT_EQ(b.carrierStatus(), "SIP/2.0 180 Ringing");

	b.sent.clear();
	b.handler.handle(handsetReply(fork, "SIP/2.0 200 OK", kHandsetAnswer));
	const std::string ack = b.firstTo("ACK sip:2001@", kPhoneIp);
	ASSERT_FALSE(ack.empty()) << "the handset's 2xx is ACKed";
	EXPECT_NE(field(ack, "Via: "), field(fork, "Via: ")) << "as a new transaction (RFC 3261 s13.2.2.4)";
	const std::string ok = b.firstTo("SIP/2.0 200 OK", kSbcIp);
	ASSERT_FALSE(ok.empty()) << "the carrier is answered";
	EXPECT_NE(ok.find("\r\nc=IN IP4 192.168.50.1\r\n"), std::string::npos);
	EXPECT_NE(ok.find(" RTP/AVP 0 100\r\n"), std::string::npos) << "the answer reuses the carrier's numbering";
	EXPECT_EQ(field(ok, "Call-ID: "), "in-answer");
	EXPECT_TRUE(b.handler.trunkRtpForTest(forkId, /*fromCarrier=*/true)) << "carrier to handset";
	EXPECT_TRUE(b.handler.trunkRtpForTest(forkId, /*fromCarrier=*/false)) << "handset to carrier";
	const auto session = b.handler.getSession(forkId);
	ASSERT_TRUE(session.has_value());
	EXPECT_EQ(session.value()->getState(), Session::State::Connected);

	b.sent.clear();
	b.handler.handle(makeCarrierAck(kDid, field(ok, "To: "), "in-answer"));
	EXPECT_EQ(b.countTo(kPhoneIp), 0u) << "the carrier's ACK is taken, not relayed to the handset";
	EXPECT_TRUE(b.firstTo("ACK", kSbcIp).empty()) << "nor echoed back";
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 1u);
}

TEST(TrunkInbound, AHandsetBusyGivesTheCarrier486AndFreesTheRelay)
{
	Bench b;
	const std::string fork = ringFork(b, "in-busy486");
	ASSERT_FALSE(fork.empty());
	b.sent.clear();

	b.handler.handle(handsetReply(fork, "SIP/2.0 486 Busy Here"));

	const std::string ack = b.firstTo("ACK sip:2001@", kPhoneIp);
	ASSERT_FALSE(ack.empty()) << "its final is ACKed (RFC 3261 s17.1.1.3)";
	EXPECT_EQ(ack.substr(4, ack.find(' ', 4) - 4), fork.substr(7, fork.find(' ', 7) - 7))
		<< "in the INVITE's own transaction: its Request-URI";
	EXPECT_EQ(field(ack, "Via: "), field(fork, "Via: ")) << "and its branch";
	EXPECT_EQ(b.carrierStatus(), "SIP/2.0 486 Busy Here");
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 0u);
	EXPECT_FALSE(b.handler.getSession("Call-ID: " + field(fork, "Call-ID: ")).has_value());
}

TEST(TrunkInbound, AHandsetThatIsUnavailableOrDeclinesGivesTheCarrier480)
{
	for (const char* reply : { "SIP/2.0 480 Temporarily Unavailable", "SIP/2.0 603 Decline" })
	{
		Bench b;
		const std::string fork = ringFork(b, "in-unavail");
		ASSERT_FALSE(fork.empty());
		b.sent.clear();

		b.handler.handle(handsetReply(fork, reply));

		EXPECT_FALSE(b.firstTo("ACK sip:2001@", kPhoneIp).empty()) << reply;
		EXPECT_EQ(b.carrierStatus(), "SIP/2.0 480 Temporarily Unavailable") << reply;
		EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 0u) << reply;
	}
}

TEST(TrunkInbound, ARetransmittedCarrierInviteNeverForksTwice)
{
	Bench b;
	const std::string fork = ringFork(b, "in-twice");
	ASSERT_FALSE(fork.empty());

	b.sent.clear();
	b.handler.handle(makeInvite(kDid, kDid, "in-twice", kSbcIp, true, "+12025550177", 100));
	EXPECT_EQ(otherForks(b, fork), 0u) << "while ringing: no second fork";

	// After our 200 the INVITE's server transaction is no longer absorbed
	// (TransactionLayer: Accepted), so this retransmission reaches onInvite.
	b.handler.handle(handsetReply(fork, "SIP/2.0 200 OK", kHandsetAnswer));
	b.sent.clear();
	b.handler.handle(makeInvite(kDid, kDid, "in-twice", kSbcIp, true, "+12025550177", 100));

	EXPECT_EQ(otherForks(b, fork), 0u) << "after the answer: no second fork";
	EXPECT_TRUE(b.firstTo("482", kSbcIp).empty()) << "nor a 482, which would end the answered call";
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 1u);
}

TEST(TrunkInbound, AForkThatDrawsNoResponseIsEndedAtTimerB)
{
	// RFC 3261 s17.1.1.2: a handset that answers the fork with nothing at all
	// (off since it registered) is given up at 64*T1. The carrier gets its final
	// then, not at SipTrunk's 60 s backstop, and the relay is released. Only the
	// transaction timers are aged, so this is Timer B's doing.
	Bench b;
	const std::string fork = ringFork(b, "in-silent");
	ASSERT_FALSE(fork.empty());
	ASSERT_EQ(b.handler.trunkRelaysInUseForTest(), 1u);
	b.sent.clear();

	b.handler.expireTransactionTimersForTest();
	b.handler.forceNextTickForTest();
	b.handler.tick();

	EXPECT_EQ(b.carrierStatus(), "SIP/2.0 480 Temporarily Unavailable");
	EXPECT_FALSE(b.handler.getSession("Call-ID: " + field(fork, "Call-ID: ")).has_value());
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 0u);
	EXPECT_EQ(b.countTo("0.0.0.0"), 0u) << "nothing goes to the stand-in caller's zero address";
}

TEST(TrunkInbound, AHandsetAnswerTheRelayCannotCarryIsRefusedCleanly)
{
	Bench b;
	const std::string fork = ringFork(b, "in-pcma-answer");
	ASSERT_FALSE(fork.empty());
	b.sent.clear();

	b.handler.handle(handsetReply(fork, "SIP/2.0 200 OK", offer(kPhoneIp, "8 101", kPcmaRtpmap)));

	EXPECT_FALSE(b.firstTo("ACK sip:2001@", kPhoneIp).empty()) << "its 2xx is still ACKed";
	EXPECT_FALSE(b.firstTo("BYE sip:2001@", kPhoneIp).empty()) << "and then hung up";
	EXPECT_EQ(b.carrierStatus(), "SIP/2.0 488 Not Acceptable Here")
		<< "the relay copies packets: a PCMA leg against a PCMU leg is silence (decision 4)";
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 0u);
	EXPECT_FALSE(b.handler.getSession("Call-ID: " + field(fork, "Call-ID: ")).has_value());
}

// ── Part D: teardown in both directions ───────────────────────────────────────

namespace
{
	struct Answered { std::string fork, forkId, ok; };

	// 2001 answers the carrier's call; the carrier ACKs our 200 unless `ackIt` is false.
	Answered answer(Bench& b, const std::string& callId, bool ackIt = true)
	{
		Answered a;
		a.fork = ringFork(b, callId);
		a.forkId = "Call-ID: " + field(a.fork, "Call-ID: ");
		b.handler.handle(handsetReply(a.fork, "SIP/2.0 200 OK", kHandsetAnswer));
		a.ok = b.firstTo("SIP/2.0 200 OK", kSbcIp);
		if (ackIt) b.handler.handle(makeCarrierAck(kDid, field(a.ok, "To: "), callId));
		b.sent.clear();
		return a;
	}

	// A request from the carrier in the call `callId` made. A CANCEL reuses the
	// INVITE's branch (RFC 3261 s9.1); a BYE is a new transaction.
	std::shared_ptr<SipMessage> carrierRequest(const std::string& method, const std::string& callId,
		const std::string& toLine, int cseq)
	{
		const std::string branch = method == "CANCEL" ? "z9hG4bKc" + callId : "z9hG4bK" + method + callId;
		const std::string raw =
			method + " sip:" + std::string(kDid) + "@" + kServerIp + ":5060 SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(kSbcIp) + ":5060;branch=" + branch + "\r\n"
			"From: <sip:+12025550177@" + kSbcIp + ">;tag=cf" + callId + "\r\n"
			"To: " + toLine + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: " + std::to_string(cseq) + " " + method + "\r\n"
			"Max-Forwards: 70\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(kSbcIp));
	}

	// The handset hanging up its side of the fork: its To (with its tag) as From.
	std::shared_ptr<SipMessage> handsetBye(const std::string& fork)
	{
		const std::string raw =
			"BYE sip:2001@" + std::string(kServerIp) + ":5060 SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(kPhoneIp) + ":5060;branch=z9hG4bKhbye\r\n"
			"From: " + field(fork, "To: ") + ";tag=hs1\r\n"
			"To: " + field(fork, "From: ") + "\r\n"
			"Call-ID: " + field(fork, "Call-ID: ") + "\r\n"
			"CSeq: 2 BYE\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(kPhoneIp));
	}

	std::string requestUri(const std::string& m) { return m.substr(m.find(' ') + 1, m.find(" SIP/2.0") - m.find(' ') - 1); }

	// The SIP thread's next pass drains what an HTTP-task path put on _asyncOutbox.
	void flushAsync(Bench& b)
	{
		b.handler.handle(RequestsHandler::getMessageFromPool(
			"OPTIONS sip:server SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.50.99:5060;branch=z9hG4bKflush\r\n"
			"From: <sip:probe@server>;tag=p\r\nTo: <sip:server@server>\r\nCall-ID: flush-398d\r\n"
			"CSeq: 1 OPTIONS\r\nMax-Forwards: 70\r\nContent-Length: 0\r\n\r\n", addrFor("192.168.50.99")));
	}

	void expectAllReleased(Bench& b, const std::string& forkId)
	{
		EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 0u) << "the relay pair is released";
		EXPECT_FALSE(b.handler.getSession(forkId).has_value()) << "and the session ended";
		EXPECT_EQ(b.countTo("0.0.0.0"), 0u) << "nothing to the stand-in caller's zero address (#819)";
	}
}

TEST(TrunkInbound, ACarrierByeHangsUpTheHandsetAtItsRealAddress)
{
	Bench b;
	const Answered a = answer(b, "in-cbye");

	b.handler.handle(carrierRequest("BYE", "in-cbye", field(a.ok, "To: "), 2));

	EXPECT_FALSE(b.firstTo("SIP/2.0 200 OK", kSbcIp).empty()) << "the carrier's BYE is answered";
	const std::string bye = b.firstTo("BYE ", kPhoneIp);
	ASSERT_FALSE(bye.empty()) << "the handset is told, at its own address";
	EXPECT_EQ(field(bye, "From: "), field(a.fork, "From: ")) << "From: our side of the fork (s12.2.1.1)";
	EXPECT_EQ(field(bye, "To: "), field(a.fork, "To: ") + ";tag=hs1") << "To: the handset, with its tag";
	expectAllReleased(b, a.forkId);
}

TEST(TrunkInbound, AHandsetByeHangsUpTheCarrierOnlyOnceItHasAckedOurOk)
{
	Bench b;
	const Answered a = answer(b, "in-hbye", /*ackIt=*/false);

	b.handler.handle(handsetBye(a.fork));

	EXPECT_FALSE(b.firstTo("SIP/2.0 200 OK", kPhoneIp).empty()) << "the handset's BYE is answered";
	EXPECT_TRUE(b.firstTo("BYE", kSbcIp).empty()) << "RFC 3261 s15: no BYE to the carrier before its ACK";
	expectAllReleased(b, a.forkId);

	b.handler.handle(makeCarrierAck(kDid, field(a.ok, "To: "), "in-hbye"));

	const std::string bye = b.firstTo("BYE ", kSbcIp);
	ASSERT_FALSE(bye.empty()) << "the ACK releases the carrier's BYE";
	EXPECT_EQ(field(bye, "To: "), "<sip:+12025550177@203.0.113.5>;tag=cfin-hbye") << "the carrier's From, with its tag";
	EXPECT_EQ(field(bye, "CSeq: "), "1 BYE") << "our own CSeq, not the INVITE's";
}

TEST(TrunkInbound, ACarrierCancelWhileRingingEndsBothLegs)
{
	Bench b;
	const std::string fork = ringFork(b, "in-cancel");
	ASSERT_FALSE(fork.empty());
	b.handler.handle(handsetReply(fork, "SIP/2.0 180 Ringing"));
	b.sent.clear();

	b.handler.handle(carrierRequest("CANCEL", "in-cancel", "<sip:" + std::string(kDid) + "@" + kServerIp + ">", 1));

	EXPECT_EQ(field(b.firstTo("SIP/2.0 200", kSbcIp), "CSeq: "), "1 CANCEL") << "the CANCEL is answered 200";
	EXPECT_EQ(field(b.firstTo("SIP/2.0 487", kSbcIp), "CSeq: "), "1 INVITE") << "and the INVITE 487 (s9.2)";
	const std::string cancel = b.firstTo("CANCEL ", kPhoneIp);
	ASSERT_FALSE(cancel.empty()) << "the fork is cancelled";
	EXPECT_EQ(requestUri(cancel), requestUri(fork)) << "s9.1: the INVITE's Request-URI";
	EXPECT_EQ(field(cancel, "Via: "), field(fork, "Via: ")) << "and its branch";
	EXPECT_EQ(field(cancel, "CSeq: "), "1 CANCEL");

	b.sent.clear();
	b.handler.handle(handsetReply(fork, "SIP/2.0 487 Request Terminated"));
	EXPECT_FALSE(b.firstTo("ACK ", kPhoneIp).empty()) << "the handset's 487 is ACKed";
	EXPECT_EQ(b.countTo(kSbcIp), 0u) << "and absorbed: the carrier already has its 487";
	expectAllReleased(b, "Call-ID: " + field(fork, "Call-ID: "));
}

TEST(TrunkInbound, NoAnswerInTwentySecondsGivesTheCarrier480AndCancelsTheFork)
{
	Bench b;
	const std::string fork = ringFork(b, "in-noanswer");
	ASSERT_FALSE(fork.empty());
	b.handler.handle(handsetReply(fork, "SIP/2.0 180 Ringing"));
	const std::string forkId = "Call-ID: " + field(fork, "Call-ID: ");
	auto s = b.handler.getSession(forkId);
	ASSERT_TRUE(s.has_value());
	const auto now = std::chrono::steady_clock::now();
	EXPECT_FALSE(s.value()->isRingExpired(now + std::chrono::seconds(19))) << "decision 5: 20 s";
	EXPECT_TRUE(s.value()->isRingExpired(now + std::chrono::seconds(21)));

	s.value()->armRingTimer(now - std::chrono::seconds(1));
	b.sent.clear();
	b.handler.forceNextTickForTest();
	b.handler.tick();

	EXPECT_EQ(b.carrierStatus(), "SIP/2.0 480 Temporarily Unavailable");
	EXPECT_FALSE(b.firstTo("CANCEL ", kPhoneIp).empty()) << "the handset stops ringing";
	b.handler.handle(handsetReply(fork, "SIP/2.0 487 Request Terminated"));
	EXPECT_FALSE(b.firstTo("ACK ", kPhoneIp).empty());
	expectAllReleased(b, forkId);
}

TEST(TrunkInbound, TheSixtySecondBackstopAlsoCancelsARingingHandset)
{
	Bench b;
	const std::string fork = ringFork(b, "in-backstop");
	ASSERT_FALSE(fork.empty());
	b.handler.handle(handsetReply(fork, "SIP/2.0 180 Ringing"));
	b.sent.clear();

	b.handler.expireTrunkDeadlinesForTest();
	b.handler.forceNextTickForTest();
	b.handler.tick();

	EXPECT_EQ(b.carrierStatus(), "SIP/2.0 480 Temporarily Unavailable");
	EXPECT_FALSE(b.firstTo("CANCEL ", kPhoneIp).empty()) << "the handset stops ringing too";
	b.handler.handle(handsetReply(fork, "SIP/2.0 487 Request Terminated"));
	expectAllReleased(b, "Call-ID: " + field(fork, "Call-ID: "));
}

TEST(TrunkInbound, AnAdminKillByesTheHandsetAndTheCarrier)
{
	Bench b;
	const Answered a = answer(b, "in-kill");

	ASSERT_TRUE(b.handler.forceDisconnect(kExt));
	flushAsync(b);

	EXPECT_FALSE(b.firstTo("BYE ", kPhoneIp).empty()) << "the handset";
	EXPECT_FALSE(b.firstTo("BYE ", kSbcIp).empty()) << "and the carrier";
	expectAllReleased(b, a.forkId);
}

TEST(TrunkInbound, AnExpiredLeaseByesTheHandsetAndTheCarrier)
{
	Bench b;
	const Answered a = answer(b, "in-lease");

	b.handler.expireLeaseAndSweepForTest(kExt);

	EXPECT_FALSE(b.firstTo("BYE ", kPhoneIp).empty()) << "the handset, best effort";
	EXPECT_FALSE(b.firstTo("BYE ", kSbcIp).empty()) << "and the billed carrier leg";
	expectAllReleased(b, a.forkId);
}

TEST(TrunkInbound, AnRtpAddressThatIsNotAUnicastDottedQuadIsNeverARelayPeer)
{
	// C review: inet_addr("999.0.113.5") is 255.255.255.255, which setRawPeer()
	// took, aiming the relay at broadcast. Same length as 203.0.113.5, so the
	// Content-Length still holds.
	{
		Bench b;
		ASSERT_EQ(b.handler.setDidMapping(kDid, kExt), "");
		std::string raw = makeInvite(kDid, kDid, "in-badc", kSbcIp, true, "+12025550177", 100)->toString();
		raw.replace(raw.find("c=IN IP4 203.0.113.5"), 20, "c=IN IP4 999.0.113.5");
		b.handler.handle(RequestsHandler::getMessageFromPool(raw, addrFor(kSbcIp)));

		EXPECT_EQ(b.carrierStatus(), "SIP/2.0 488 Not Acceptable Here") << "the carrier's offer";
		EXPECT_EQ(b.countTo(kSbcIp), 1u);
		EXPECT_TRUE(b.firstTo("INVITE", kPhoneIp).empty());
		EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 0u);
	}
	{
		Bench b;
		const std::string fork = ringFork(b, "in-badanswer");
		ASSERT_FALSE(fork.empty());
		std::string answer = kHandsetAnswer;
		answer.replace(answer.find("c=IN IP4 192.168.50.21"), 22, "c=IN IP4 999.168.50.21");
		b.sent.clear();
		b.handler.handle(handsetReply(fork, "SIP/2.0 200 OK", answer));

		EXPECT_EQ(b.carrierStatus(), "SIP/2.0 488 Not Acceptable Here") << "the handset's answer";
		EXPECT_EQ(b.countTo(kSbcIp), 1u);
		EXPECT_FALSE(b.firstTo("BYE ", kPhoneIp).empty());
		EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 0u);
	}
}

TEST(TrunkInbound, ASilentInboundCallByesTheHandsetNotTheCallersStandIn)
{
	Bench b;
	const Answered a = answer(b, "in-quiet");
	auto s = b.handler.getSession(a.forkId);
	ASSERT_TRUE(s.has_value());
	b.handler.tick();   // arms the RTP watch

	s.value()->ageRtpWatchForTest(std::chrono::seconds(61));
	b.handler.forceNextTickForTest();
	b.sent.clear();
	b.handler.tick();

	EXPECT_FALSE(b.firstTo("BYE ", kPhoneIp).empty()) << "the handset is dest on an inbound call";
	EXPECT_FALSE(b.firstTo("BYE ", kSbcIp).empty()) << "and the carrier is hung up";
	expectAllReleased(b, a.forkId);
}
