// TrunkInbound_test.cpp — issue #398 part B: a new INVITE from the SIP trunk's
// SBC is caught before the registered-caller checks and refused cleanly.
//
// Before this, every carrier call was answered 403 by onInvite's findClient(From)
// check, because a carrier's From names a PSTN caller, never one of our phones.
// Part B recognises the carrier by its source address alone (#356), looks the DID
// up, and gives a final answer the carrier can ACK. The fork to the handset is
// part C, so even a routable call is answered 480 for now.
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
		const std::string& fromUser = "+12025550177")
	{
		const std::string body = pcmu ? offer(srcIp, "0 101", kPcmuRtpmap) : offer(srcIp, "8 101", kPcmaRtpmap);
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

	EXPECT_EQ(b.carrierStatus(), "SIP/2.0 480 Temporarily Unavailable")
		<< "mapped, registered, PCMU, relay free: 480 until the fork (part C) lands, "
		   "and never the 403 an unregistered caller gets";
	const std::string answer = b.firstTo("480", kSbcIp);
	EXPECT_NE(field(answer, "To: ").find(";tag="), std::string::npos)
		<< "a final the carrier can ACK carries our To tag (RFC 3261 s8.2.6.2)";
	EXPECT_EQ(b.countTo(kPhoneIp), 0u) << "nothing is forked to the handset in part B";
	EXPECT_EQ(b.handler.trunkRelaysInUseForTest(), 0u) << "and no relay pair is claimed";
	EXPECT_FALSE(b.handler.getSession("Call-ID: in-mapped").has_value());
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

	EXPECT_EQ(b.carrierStatus(), "SIP/2.0 480 Temporarily Unavailable")
		<< "a registered trunk is called at its own Contact; the DID is the To user (decision 1)";
}

TEST(TrunkInbound, TheDidIsFoundInTheRequestUriWhenToDoesNotMap)
{
	Bench b;
	ASSERT_EQ(b.handler.setDidMapping(kDid, kExt), "");

	b.handler.handle(makeInvite(kDid, kTrunkUser, "in-ruri"));

	EXPECT_EQ(b.carrierStatus(), "SIP/2.0 480 Temporarily Unavailable")
		<< "an IP-authenticated trunk puts the DID in the Request-URI (decision 1)";
}

TEST(TrunkInbound, ADidMatchesHoweverTheCarrierSpellsIt)
{
	Bench b;
	ASSERT_EQ(b.handler.setDidMapping("(202) 555-0188", kExt), "");

	b.handler.handle(makeInvite(kDid, kDid, "in-e164"));

	EXPECT_EQ(b.carrierStatus(), "SIP/2.0 480 Temporarily Unavailable")
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
	// answer 480, under a fresh To tag.
	ASSERT_EQ(b.handler.setDidMapping(kDid, kExt), "");
	b.sent.clear();
	b.handler.handle(makeInvite(kDid, kDid, "in-rtx"));

	const std::string again = b.firstTo("404", kSbcIp);
	ASSERT_FALSE(again.empty()) << "a retransmission is answered from the server transaction (RFC 3261 s17.2.1)";
	EXPECT_EQ(field(again, "To: "), toTag) << "the same response, not a second run of the routing";
	EXPECT_TRUE(b.firstTo("480", kSbcIp).empty());

	b.sent.clear();
	b.handler.handle(makeInvite(kDid, kDid, "in-fresh"));
	EXPECT_EQ(b.carrierStatus(), "SIP/2.0 480 Temporarily Unavailable") << "a new call sees the new mapping";
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
