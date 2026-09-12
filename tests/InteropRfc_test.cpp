// InteropRfc_test.cpp — regressions for three RFC violations that only showed up
// once a production SIP stack (pjsip's pjsua, via tests/interop/) was pointed at
// the PBX. Every one of them passed SIPp and .smoke/office_smoke.py, because
// neither of those validates what it receives: they match the bytes they were
// told to expect and ignore the rest.
//
//   1. Answers invented payload type 101 with no a=rtpmap (RFC 4566 §6) and
//      overwrote the offer's own payload numbering (RFC 3264 §6.1). pjsip
//      answers such an INVITE with "400 Bad SDP" and the call never comes up.
//   2. Responses stamped Via ";received=" with the SERVER's address instead of
//      the request's source (RFC 3261 §18.2.1), and rport with the server's port
//      instead of the source port (RFC 3581 §4). pjsip reads the mismatch as NAT
//      and rewrites its Contact to what we told it, after which in-dialog
//      requests are addressed to a host:port where nothing is listening.
//   3. A non-2xx final response to a PBX-originated INVITE was never ACKed
//      (RFC 3261 §17.1.1.3) — it matched no entry in the response dispatch
//      table and was dropped — so the phone retransmitted its failure until
//      Timer H while the beep slot stayed pinned until a sweep that then sent a
//      CANCEL, which §9.1 forbids after a final response.

#include <gtest/gtest.h>

#include <string>
#include <utility>
#include <vector>

#include "RequestsHandler.hpp"
#include "SipWireUtil.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	constexpr const char* kServerIp = "192.168.7.1";
	constexpr uint16_t    kPhonePort = 5062;   // deliberately NOT the server's 5060

	sockaddr_in addrFor(const std::string& ip, uint16_t port = kPhonePort)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(port);
		return s;
	}

	std::shared_ptr<SipMessage> makeRegister(const std::string& ext, const std::string& srcIp,
	                                         const std::string& callId, bool withRport)
	{
		const std::string port = std::to_string(kPhonePort);
		std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":" + port +
				(withRport ? ";rport" : "") + ";branch=z9hG4bKr" + callId + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + callId + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + srcIp + ":" + port + ">;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}

	// An INVITE whose offer looks like a real softphone's: dynamic payload types
	// the PBX has never heard of, its own numbering for telephone-event, and a
	// preference order that must survive into the answer.
	std::shared_ptr<SipMessage> makeRichInvite(const std::string& fromExt, const std::string& toExt,
	                                           const std::string& srcIp, const std::string& callId,
	                                           const std::string& mLine)
	{
		std::string body =
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + srcIp + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + srcIp + "\r\n"
			"t=0 0\r\n" + mLine +
			"a=rtpmap:96 speex/16000\r\n"
			"a=rtpmap:0 PCMU/8000\r\n"
			"a=rtpmap:8 PCMA/8000\r\n"
			"a=rtpmap:120 telephone-event/8000\r\n"
			"a=fmtp:120 0-15\r\n";
		std::string raw =
			"INVITE sip:" + toExt + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":" + std::to_string(kPhonePort) +
				";branch=z9hG4bKi" + callId + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:" + fromExt + "@" + srcIp + ":" +
				std::to_string(kPhonePort) + ">\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}

	std::string firstMatching(const std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>& sent,
	                          const std::string& needle)
	{
		for (const auto& [addr, msg] : sent)
		{
			(void)addr;
			std::string raw = msg ? msg->toString() : std::string{};
			if (raw.find(needle) != std::string::npos) return raw;
		}
		return {};
	}

	// The m= audio payload list of an SDP body, as separate tokens.
	std::vector<std::string> audioPayloads(const std::string& raw)
	{
		std::vector<std::string> out;
		size_t m = raw.find("m=audio ");
		if (m == std::string::npos) return out;
		size_t rtp = raw.find("RTP/AVP ", m);
		size_t eol = raw.find("\r\n", m);
		if (rtp == std::string::npos || eol == std::string::npos || rtp > eol) return out;
		std::string list = raw.substr(rtp + 8, eol - (rtp + 8));
		size_t pos = 0;
		while (pos < list.size())
		{
			size_t sp = list.find(' ', pos);
			std::string tok = list.substr(pos, (sp == std::string::npos ? list.size() : sp) - pos);
			if (!tok.empty()) out.push_back(tok);
			if (sp == std::string::npos) break;
			pos = sp + 1;
		}
		return out;
	}
}

// ── 1. SDP answers ───────────────────────────────────────────────────────────

TEST(InteropRfc, EchoAnswerKeepsTheOffersPayloadNumberingAndInventsNothing)
{
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler(kServerIp, 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	handler.handle(makeRegister("500", "192.168.7.50", "reg-500", /*withRport=*/false));
	sent.clear();

	handler.handle(makeRichInvite("500", "777", "192.168.7.50", "echo-1",
		"m=audio 10000 RTP/AVP 96 0 8 120\r\n"));

	const std::string ok = firstMatching(sent, "SIP/2.0 200 OK");
	ASSERT_FALSE(ok.empty()) << "777 echo produced no 200 OK";

	const auto pts = audioPayloads(ok);
	ASSERT_FALSE(pts.empty()) << "answer has no m=audio payload list";

	// Every payload type in the answer must have been in the offer. 101 in
	// particular was invented by the old enforceG711() rewrite; the offer above
	// numbers telephone-event 120.
	for (const auto& pt : pts)
	{
		EXPECT_TRUE(pt == "0" || pt == "8" || pt == "120")
			<< "answer offers payload type " << pt << ", which the caller never offered";
	}
	EXPECT_EQ(ok.find(" 101"), std::string::npos)
		<< "answer re-introduced payload type 101 (the caller numbered telephone-event 120)";

	// And every dynamic payload type (>= 96) that survives must carry its rtpmap:
	// RFC 4566 §6. pjsip rejects the whole body with 400 Bad SDP otherwise.
	for (const auto& pt : pts)
	{
		if (std::stoi(pt) < 96) continue;
		EXPECT_NE(ok.find("a=rtpmap:" + pt + " "), std::string::npos)
			<< "dynamic payload type " << pt << " kept in the answer with no a=rtpmap line";
	}

	// The caller's own preference order is preserved among what survives.
	std::vector<std::string> expected{"0", "8", "120"};
	EXPECT_EQ(pts, expected);
}

TEST(InteropRfc, EchoRefuses488WhenNothingTheEchoLegSpeaksWasOffered)
{
	// The relay-level admission gate allows G.722 (a peer-to-peer pair may
	// negotiate wideband between themselves), but the 777 echo is server
	// terminated and G.711 only. A wideband-only offer must be refused outright
	// rather than answered with codecs this leg will never send.
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler(kServerIp, 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	handler.handle(makeRegister("501", "192.168.7.51", "reg-501", /*withRport=*/false));
	sent.clear();

	handler.handle(makeRichInvite("501", "777", "192.168.7.51", "echo-wb",
		"m=audio 10000 RTP/AVP 9\r\n"));

	EXPECT_FALSE(firstMatching(sent, "488 Not Acceptable Here").empty())
		<< "G.722-only offer to the echo test was not refused with 488";
	EXPECT_TRUE(firstMatching(sent, "SIP/2.0 200 OK").empty())
		<< "G.722-only offer to the echo test was answered 200 OK";
}

// ── 2. Via received / rport ──────────────────────────────────────────────────

TEST(InteropRfc, ViaReceivedIsTheRequestSourceNotTheServer)
{
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler(kServerIp, 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	handler.handle(makeRegister("502", "192.168.7.52", "reg-502", /*withRport=*/false));

	const std::string ok = firstMatching(sent, "SIP/2.0 200 OK");
	ASSERT_FALSE(ok.empty()) << "REGISTER produced no 200 OK";
	EXPECT_NE(ok.find("received=192.168.7.52"), std::string::npos)
		<< "Via received must name the phone's address (RFC 3261 §18.2.1)";
	EXPECT_EQ(ok.find("received=" + std::string(kServerIp)), std::string::npos)
		<< "Via received still names the server's own address";
}

TEST(InteropRfc, BareRportIsAnsweredWithTheSourcePort)
{
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler(kServerIp, 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	handler.handle(makeRegister("503", "192.168.7.53", "reg-503", /*withRport=*/true));

	const std::string ok = firstMatching(sent, "SIP/2.0 200 OK");
	ASSERT_FALSE(ok.empty()) << "REGISTER produced no 200 OK";
	EXPECT_NE(ok.find("rport=" + std::to_string(kPhonePort)), std::string::npos)
		<< "a bare rport must come back carrying the SOURCE port (RFC 3581 §4)";
	EXPECT_EQ(ok.find("rport=5060"), std::string::npos)
		<< "rport still echoes the server's own port";
}

TEST(InteropRfc, ViaWithReceivedLeavesAnAlreadyValuedRportAlone)
{
	// Only a bare ";rport" is ours to fill in. One that already carries a value
	// was set by an upstream hop and must survive untouched.
	EXPECT_EQ(sipwire::viaWithReceived(
			"Via: SIP/2.0/UDP 10.0.0.9:5060;rport=1234;branch=z9hG4bKx",
			addrFor("10.0.0.9", 6000)),
		"Via: SIP/2.0/UDP 10.0.0.9:5060;rport=1234;branch=z9hG4bKx;received=10.0.0.9");
}

// ── 3. ACK for a non-2xx final response to a PBX-originated INVITE ───────────

TEST(InteropRfc, BeepInviteRefusedByThePhoneIsAckedNotLeftHanging)
{
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler(kServerIp, 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	// A new registration triggers the register-beep INVITE.
	handler.handle(makeRegister("504", "192.168.7.54", "reg-504", /*withRport=*/false));
	const std::string beep = firstMatching(sent, "INVITE sip:504@");
	ASSERT_FALSE(beep.empty()) << "no register-beep INVITE was sent";

	// Pull the dialog identifiers back off the wire, exactly as the phone would.
	auto headerValue = [&beep](const std::string& name) {
		size_t at = beep.find(name);
		if (at == std::string::npos) return std::string{};
		size_t eol = beep.find("\r\n", at);
		return beep.substr(at + name.size(), eol - (at + name.size()));
	};
	const std::string via    = headerValue("Via: ");
	const std::string from   = headerValue("From: ");
	const std::string callId = headerValue("Call-ID: ");
	ASSERT_FALSE(via.empty());
	ASSERT_FALSE(callId.empty());

	sent.clear();

	// The phone rejects the beep. 400 is what pjsip actually answered when the
	// offer was malformed; any non-2xx final has to take the same path.
	std::string failure =
		"SIP/2.0 400 Bad SDP\r\n"
		"Via: " + via + "\r\n"
		"From: " + from + "\r\n"
		"To: <sip:504@" + std::string(kServerIp) + ">;tag=phonetag\r\n"
		"Call-ID: " + callId + "\r\n"
		"CSeq: 1 INVITE\r\n"
		"Content-Length: 0\r\n\r\n";
	handler.handle(RequestsHandler::getMessageFromPool(failure, addrFor("192.168.7.54")));

	const std::string ack = firstMatching(sent, "ACK sip:504@");
	EXPECT_FALSE(ack.empty())
		<< "a non-2xx final response to our own INVITE was not ACKed (RFC 3261 §17.1.1.3)";
	if (!ack.empty())
	{
		EXPECT_NE(ack.find(callId), std::string::npos)
			<< "the ACK belongs to a different dialog than the INVITE it answers";
		EXPECT_NE(ack.find("CSeq: 1 ACK"), std::string::npos)
			<< "the ACK must reuse the INVITE's CSeq number";
	}
	EXPECT_TRUE(firstMatching(sent, "CANCEL sip:504@").empty())
		<< "CANCEL sent after a final response (RFC 3261 §9.1 forbids it)";
}
