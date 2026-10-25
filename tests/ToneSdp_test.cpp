// ToneSdp_test.cpp -- where a board-sourced stream (the 440 tone, the 888 leg's
// mix, the voicemail playback) is sent when the caller's SDP names an address
// that is not a place a stream may go: loopback, multicast, broadcast, this
// host, a malformed string. Such an address is replaced by the INVITE's source
// (what parseCallerRtp() already does for 0.0.0.0) and the call is NOT refused.
// A LAN address is used as offered. The anchor / 911 / 933 paths keep the
// offered address exactly as before (Rule 5); the control tests pin that.
//
// Every log line is read from the handler's own output, counted exactly.
// No packet is aimed at an address outside the test host's loopback.

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

#include "ConferenceRoom.hpp"
#include "RequestsHandler.hpp"
#include "SipWireUtil.hpp"

namespace
{
	constexpr const char* kServerIp  = "192.168.9.1";
	constexpr const char* kHandsetIp = "192.168.9.51";

	sockaddr_in addrFor(const std::string& ip)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(5060);
		return s;
	}

	std::shared_ptr<SipMessage> makeRegister(const std::string& ext, const std::string& ip)
	{
		const std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKts" + ext + "\r\n"
			"From: <sip:" + ext + "@server>;tag=ts" + ext + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: ts-reg-" + ext + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + ip + ":5060>;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}

	// `cAddr` is what the SDP c= line says; `srcIp` is where the INVITE comes from.
	std::shared_ptr<SipMessage> makeInvite(const std::string& dialed, const std::string& callId,
		const std::string& cAddr, const std::string& ext = "501", const std::string& srcIp = kHandsetIp,
		int rtpPort = 10000)
	{
		const std::string body =
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + srcIp + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + cAddr + "\r\n"
			"t=0 0\r\n"
			"m=audio " + std::to_string(rtpPort) + " RTP/AVP 0\r\n"
			"a=rtpmap:0 PCMU/8000\r\n";
		const std::string raw =
			"INVITE sip:" + dialed + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bKti" + callId + "\r\n"
			"From: <sip:" + ext + "@server>;tag=tf" + callId + "\r\n"
			"To: <sip:" + dialed + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:" + ext + "@" + srcIp + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}

	size_t countOf(const std::string& hay, const std::string& needle)
	{
		size_t n = 0;
		for (size_t at = hay.find(needle); at != std::string::npos; at = hay.find(needle, at + needle.size())) ++n;
		return n;
	}

	// Ext 501 registered at kHandsetIp; every handler log line (both streams)
	// and every outbound message is captured.
	struct Bench
	{
		std::vector<std::pair<sockaddr_in, std::string>> sent;
		RequestsHandler handler{kServerIp, 5060,
			[this](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, m->toString()); }};

		Bench() { handler.handle(makeRegister("501", kHandsetIp)); sent.clear(); }

		// Delivers `msg` and returns everything the handler logged for it.
		std::string log(std::shared_ptr<SipMessage> msg)
		{
			testing::internal::CaptureStdout();
			testing::internal::CaptureStderr();
			handler.handle(std::move(msg));
			return testing::internal::GetCapturedStdout() + testing::internal::GetCapturedStderr();
		}

		size_t statusCount(const std::string& status) const
		{
			size_t n = 0;
			for (const auto& p : sent) if (p.second.rfind("SIP/2.0 " + status, 0) == 0) ++n;
			return n;
		}
	};

	// 440 with this c= from 501 at kHandsetIp: the log it produced.
	std::string dialTone(Bench& b, const std::string& cAddr, const std::string& id)
	{
		return b.log(makeInvite("440", id, cAddr));
	}
}

// ── The defect: a tone stream aimed at an address the caller chose ─────────

TEST(ToneSdp, LoopbackCAddressFallsBackToTheInviteSource)
{
	Bench b;
	const std::string log = dialTone(b, "127.0.0.1", "tone-lo");

	EXPECT_EQ(countOf(log, "streaming tone to 192.168.9.51:10000"), 1u) << log;
	EXPECT_EQ(countOf(log, "127.0.0.1"), 0u) << log;
	EXPECT_EQ(b.statusCount("200 OK"), 1u) << "the call is answered, not refused";
}

TEST(ToneSdp, MulticastAndBroadcastCAddressesFallBackToo)
{
	for (const char* c : { "224.0.0.251", "239.255.255.250", "255.255.255.255", "240.0.0.1" })
	{
		Bench b;
		const std::string log = dialTone(b, c, "tone-mc");

		EXPECT_EQ(countOf(log, std::string("streaming tone to ") + c), 0u) << c << ": " << log;
		EXPECT_EQ(countOf(log, "streaming tone to 192.168.9.51:10000"), 1u) << c << ": " << log;
		EXPECT_EQ(b.statusCount("200 OK"), 1u) << c;
		EXPECT_EQ(b.statusCount("488"), 0u) << c;
	}
}

TEST(ToneSdp, MalformedAndThisHostCAddressesFallBackToo)
{
	// "300.1.1.1" and "1.2.3" are digits and dots, which parseCallerRtp() takes;
	// 192.168.9.1 is this board.
	for (const char* c : { "300.1.1.1", "1.2.3", "1.2.3.4.5", "192.168.9.1", "0.1.2.3" })
	{
		Bench b;
		const std::string log = dialTone(b, c, "tone-bad");

		EXPECT_EQ(countOf(log, std::string("streaming tone to ") + c + ":"), 0u) << c << ": " << log;
		EXPECT_EQ(countOf(log, "streaming tone to 192.168.9.51:10000"), 1u) << c << ": " << log;
		EXPECT_EQ(b.statusCount("200 OK"), 1u) << c;
	}
}

TEST(ToneSdp, Control_ALanCAddressIsUsedAsOffered)
{
	Bench b;
	const std::string log = dialTone(b, "192.168.9.77", "tone-lan");

	EXPECT_EQ(countOf(log, "streaming tone to 192.168.9.77:10000"), 1u) << log;
	EXPECT_EQ(countOf(log, "streaming tone to"), 1u) << log;
	EXPECT_EQ(b.statusCount("200 OK"), 1u);
}

TEST(ToneSdp, Control_APublicCarrierCAddressIsUsedAsOffered)
{
	Bench b;
	const std::string log = dialTone(b, "198.51.100.20", "tone-pub");

	EXPECT_EQ(countOf(log, "streaming tone to 198.51.100.20:10000"), 1u) << log;
	EXPECT_EQ(countOf(log, "streaming tone to"), 1u) << log;
	EXPECT_EQ(b.statusCount("200 OK"), 1u);
}

TEST(ToneSdp, Control_ZeroCAddressStillFallsBackToTheInviteSource)
{
	Bench b;
	const std::string log = dialTone(b, "0.0.0.0", "tone-zero");

	EXPECT_EQ(countOf(log, "streaming tone to 192.168.9.51:10000"), 1u) << log;
	EXPECT_EQ(countOf(log, "streaming tone to"), 1u) << log;
}

// ── 888: the conference leg is sent the room's mix at the caller's c= ──────

TEST(ToneSdp, ConferenceLegWithAnOddCAddressIsMixedToTheInviteSource)
{
	Bench b;
	const std::string log = b.log(makeInvite(ConferenceRoom::EXT, "conf-lo", "127.0.0.1"));

	EXPECT_EQ(countOf(log, "joined leg"), 1u) << log;
	EXPECT_EQ(countOf(log, "media to 192.168.9.51:10000"), 1u) << log;
	EXPECT_EQ(countOf(log, "media to 127.0.0.1"), 0u) << log;
	EXPECT_EQ(b.statusCount("200 OK"), 1u);
}

TEST(ToneSdp, Control_AConferenceLegWithALanCAddressIsMixedThere)
{
	Bench b;
	const std::string log = b.log(makeInvite(ConferenceRoom::EXT, "conf-lan", "192.168.9.77"));

	EXPECT_EQ(countOf(log, "media to 192.168.9.77:10000"), 1u) << log;
	EXPECT_EQ(b.statusCount("200 OK"), 1u);
}

// ── Rule 5: the emergency anchor path is untouched ─────────────────────────
//
// A 911 reaches the anchor bridge only on a board whose anchor places real calls
// (setAnchorPlacesRealCallsForTest). The bridge media goes to the INVITE's c=
// as before: 0.0.0.0 falls back to the source in parseCallerRtp(), any other
// address is kept as offered. Nothing here is refused 488.

TEST(ToneSdp, Control_911KeepsTheOfferedCAddressAndIsNeverRefused)
{
	{
		Bench b;
		b.handler.setAnchorPlacesRealCallsForTest(true);
		const std::string log = b.log(makeInvite("911", "e911-zero", "0.0.0.0"));
		EXPECT_EQ(countOf(log, "bridged (participant"), 1u) << log;
		EXPECT_EQ(countOf(log, "media to 192.168.9.51:10000"), 1u) << log;
		EXPECT_EQ(b.statusCount("488"), 0u);
	}
	{
		Bench b;
		b.handler.setAnchorPlacesRealCallsForTest(true);
		const std::string log = b.log(makeInvite("911", "e911-lo", "127.0.0.1"));
		EXPECT_EQ(countOf(log, "bridged (participant"), 1u) << log;
		EXPECT_EQ(countOf(log, "media to 127.0.0.1:10000"), 1u)
			<< "unchanged from main: the 911 leg keeps the offered address\n" << log;
		EXPECT_EQ(b.statusCount("488"), 0u);
	}
}

// -- Park hold music and the MoH preview: sipwire::parseRtpTarget ---------------

namespace
{
	std::string sdpWithC(const std::string& c)
	{
		return "v=0\r\no=- 0 0 IN IP4 10.0.0.7\r\ns=-\r\nc=IN IP4 " + c + "\r\nt=0 0\r\n"
		       "m=audio 40000 RTP/AVP 0\r\n";
	}
}

TEST(ToneSdp, HoldMusicTargetWithAnOddCAddressIsTheSipSource)
{
	for (const char* c : { "127.0.0.1", "224.0.0.251", "255.255.255.255", "300.1.1.1", "1.2.3", "240.0.0.1" })
	{
		std::string ip;
		uint16_t port = 0;
		ASSERT_TRUE(sipwire::parseRtpTarget(sdpWithC(c), addrFor("192.168.9.51"), ip, port)) << c;
		EXPECT_EQ(ip, "192.168.9.51") << c << ": the stream is not aimed at the offered address";
		EXPECT_EQ(port, 40000) << c;
	}
}

TEST(ToneSdp, Control_HoldMusicTargetWithALanCAddressIsAsOffered)
{
	std::string ip;
	uint16_t port = 0;
	ASSERT_TRUE(sipwire::parseRtpTarget(sdpWithC("192.168.9.77"), addrFor("192.168.9.51"), ip, port));
	EXPECT_EQ(ip, "192.168.9.77");
	ASSERT_TRUE(sipwire::parseRtpTarget(sdpWithC("0.0.0.0"), addrFor("192.168.9.51"), ip, port));
	EXPECT_EQ(ip, "192.168.9.51") << "0.0.0.0 still means the source";
}

// -- Voicemail playback (796) and deposit greeting: real datagrams on the host's loopback -----------
//
// The leg's sender is a real UDP thread on the host, so the destination can be
// observed on the wire. The mailbox is dialled from 127.0.0.1 with a multicast
// c= and the m= port of a socket listening on 127.0.0.1: the stream must arrive
// there (the INVITE source), and nothing is aimed at the multicast group.

namespace
{
	struct Listener
	{
		int fd = -1;
		uint16_t port = 0;
		Listener()
		{
			fd = ::socket(AF_INET, SOCK_DGRAM, 0);
			sockaddr_in a = addrFor("127.0.0.1");
			a.sin_port = 0;
			if (fd >= 0 && ::bind(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) == 0)
			{
				socklen_t len = sizeof(a);
				::getsockname(fd, reinterpret_cast<sockaddr*>(&a), &len);
				port = ntohs(a.sin_port);
			}
		}
		~Listener() { if (fd >= 0) ::close(fd); }
		// True as soon as one datagram arrives, false after `ms` milliseconds.
		bool waitForDatagram(int ms)
		{
			const auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
			while (std::chrono::steady_clock::now() < end)
			{
				pollfd p{ fd, POLLIN, 0 };
				char buf[512];
				if (::poll(&p, 1, 20) > 0 && ::recv(fd, buf, sizeof(buf), 0) > 0) return true;
			}
			return false;
		}
	};
}

TEST(ToneSdp, VoicemailPlaybackWithAMulticastCAddressStreamsToTheInviteSource)
{
	Listener rx;
	ASSERT_NE(rx.port, 0);
	std::vector<std::pair<sockaddr_in, std::string>> sent;
	RequestsHandler handler{kServerIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, m->toString()); }};
	handler.handle(makeRegister("501", "127.0.0.1"));
	handler.setVoicemail("501", true);
	sent.clear();

	handler.handle(makeInvite("796", "vm-mc", "224.0.0.251", "501", "127.0.0.1", rx.port));

	ASSERT_TRUE(handler.getSession("Call-ID: vm-mc").has_value()) << "answered, not refused";
	EXPECT_TRUE(rx.waitForDatagram(3000)) << "the leg streams to the INVITE source";
}


// A deposit: 501 (at 127.0.0.1) dials 502, who has voicemail and answers 486. The
// greeting leg streams to 501's c= address; a multicast c= must fall back to the
// INVITE source, the listening socket.
TEST(ToneSdp, VoicemailDepositGreetingWithAMulticastCAddressStreamsToTheInviteSource)
{
	Listener rx;
	ASSERT_NE(rx.port, 0);
	std::vector<std::pair<sockaddr_in, std::string>> sent;
	RequestsHandler handler{kServerIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, m->toString()); }};
	handler.handle(makeRegister("501", "127.0.0.1"));
	handler.handle(makeRegister("502", kHandsetIp));
	handler.setVoicemail("502", true);

	handler.handle(makeInvite("502", "vm-dep", "224.0.0.251", "501", "127.0.0.1", rx.port));
	const std::string busy =
		"SIP/2.0 486 Busy Here\r\n"
		"Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKtivm-dep\r\n"
		"From: <sip:501@server>;tag=tfvm-dep\r\n"
		"To: <sip:502@server>;tag=btvm-dep\r\n"
		"Call-ID: vm-dep\r\n"
		"CSeq: 1 INVITE\r\n"
		"Content-Length: 0\r\n\r\n";
	handler.handle(RequestsHandler::getMessageFromPool(busy, addrFor(kHandsetIp)));

	auto session = handler.getSession("Call-ID: vm-dep");
	ASSERT_TRUE(session.has_value());
	ASSERT_GE(session.value()->getVoicemailLegSlot(), 0) << "precondition: the deposit leg is up";
	EXPECT_TRUE(rx.waitForDatagram(3000)) << "the greeting leg streams to the INVITE source";
}

// -- Leading-zero octets: lwIP reads them as octal, the checker as decimal -----

TEST(ToneSdp, LeadingZeroCAddressesAreNotStrictAndFallBack)
{
	for (const char* c : { "192.168.011.001", "0177.0.0.1", "010.1.2.3", "192.168.9.077" })
	{
		Bench b;
		const std::string log = dialTone(b, c, "tone-oct");

		EXPECT_EQ(countOf(log, std::string("streaming tone to ") + c), 0u) << c << ": " << log;
		EXPECT_EQ(countOf(log, "streaming tone to 192.168.9.51:10000"), 1u) << c << ": " << log;
		EXPECT_EQ(b.statusCount("200 OK"), 1u) << c;
	}
}

TEST(ToneSdp, HoldMusicTargetRefusesThisHostTheSubnetBroadcastAndLeadingZeros)
{
	for (const char* c : { "192.168.9.1", "192.168.9.255", "192.168.009.077", "0177.0.0.1" })
	{
		std::string ip;
		uint16_t port = 0;
		ASSERT_TRUE(sipwire::parseRtpTarget(sdpWithC(c), addrFor("192.168.9.51"), ip, port, kServerIp, 0xFFFFFF00u)) << c;
		EXPECT_EQ(ip, "192.168.9.51") << c;
	}
	std::string ip;
	uint16_t port = 0;
	ASSERT_TRUE(sipwire::parseRtpTarget(sdpWithC("192.168.9.77"), addrFor("192.168.9.51"), ip, port, kServerIp, 0xFFFFFF00u));
	EXPECT_EQ(ip, "192.168.9.77") << "control: a LAN host is used as offered";
}

// -- The anchor: ordinary calls fall back, 911/933 keep the offered address ----

TEST(ToneSdp, AnOrdinaryAnchoredCallWithAnOddCAddressBridgesToTheInviteSource)
{
	for (const char* c : { "127.0.0.1", "224.0.0.251", "300.1.1.1" })
	{
		Bench b;
		const std::string log = b.log(makeInvite("555", "anc-odd", c));
		EXPECT_EQ(countOf(log, "bridged (participant"), 1u) << c << ": " << log;
		EXPECT_EQ(countOf(log, "media to 192.168.9.51:10000"), 1u) << c << ": " << log;
		EXPECT_EQ(b.statusCount("200 OK"), 1u) << c;
	}
}

TEST(ToneSdp, Control_AnOrdinaryAnchoredCallWithALanCAddressBridgesThere)
{
	Bench b;
	const std::string log = b.log(makeInvite("555", "anc-lan", "192.168.9.77"));
	EXPECT_EQ(countOf(log, "media to 192.168.9.77:10000"), 1u) << log;
}

namespace
{
	// Inbound anchored call to handset 502 (at kHandsetIp); the handset answers with
	// `cAddr` in its SDP. `emergency` marks the session first, as a PSAP callback is.
	std::string answerInbound(Bench& b, const std::string& cAddr, bool emergency)
	{
		b.handler.handle(makeRegister("502", kHandsetIp));
		const std::string callIdLine = b.handler.routeInboundAnchorCallForTest("502", "part-ts", "5551234567");
		b.handler.tick();
		std::string fork;
		for (const auto& [addr, raw] : b.sent) if (raw.rfind("INVITE sip:502@", 0) == 0) fork = raw;
		if (fork.empty()) return "NO FORK";
		auto line = [&](const std::string& name) {
			const size_t at = fork.find("\r\n" + name);
			return at == std::string::npos ? std::string() : fork.substr(at + 2, fork.find("\r\n", at + 2) - at - 2);
		};
		if (emergency)
		{
			auto sess = b.handler.getSession(callIdLine);
			if (sess.has_value()) sess.value()->setEmergency(true);
		}
		const std::string body =
			"v=0\r\no=- 0 0 IN IP4 " + std::string(kHandsetIp) + "\r\ns=-\r\nc=IN IP4 " + cAddr +
			"\r\nt=0 0\r\nm=audio 10000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n";
		const std::string ok =
			"SIP/2.0 200 OK\r\n" + line("Via:") + "\r\n" + line("From:") + "\r\n"
			"To: <sip:502@" + std::string(kServerIp) + ">;tag=hs502\r\n" + callIdLine + "\r\n"
			"CSeq: 1 INVITE\r\nContact: <sip:502@" + std::string(kHandsetIp) + ":5060>\r\n"
			"Content-Type: application/sdp\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return b.log(RequestsHandler::getMessageFromPool(ok, addrFor(kHandsetIp)));
	}
}

TEST(ToneSdp, AnInboundAnchoredCallAnsweredWithAnOddCAddressBridgesToTheHandsetSource)
{
	Bench b;
	const std::string log = answerInbound(b, "127.0.0.1", /*emergency=*/false);
	EXPECT_EQ(countOf(log, "handset 192.168.9.51:10000 answered; bridge up"), 1u) << log;
	EXPECT_EQ(countOf(log, "handset 127.0.0.1"), 0u) << log;
}

TEST(ToneSdp, Control_AnInboundEmergencyCallbackKeepsTheOfferedCAddress)
{
	Bench b;
	const std::string log = answerInbound(b, "127.0.0.1", /*emergency=*/true);
	EXPECT_EQ(countOf(log, "handset 127.0.0.1:10000 answered; bridge up"), 1u)
		<< "Rule 5: unchanged from main\n" << log;
}

// -- The pure leading-zero check ------------------------------------------------

TEST(ToneSdp, HasLeadingZeroOctetSeesOnlyOctetsWrittenWithALeadingZero)
{
	for (const char* yes : { "011.1.1.1", "1.02.3.4", "192.168.9.077", "0177.0.0.1", "1.2.3.04", "00.0.0.0" })
		EXPECT_TRUE(sipwire::hasLeadingZeroOctet(yes)) << yes;
	for (const char* no : { "0.1.2.3", "10.0.0.1", "192.168.9.1", "1.0.0.0", "100.200.30.40", "0.0.0.0", "" })
		EXPECT_FALSE(sipwire::hasLeadingZeroOctet(no)) << no;
}
