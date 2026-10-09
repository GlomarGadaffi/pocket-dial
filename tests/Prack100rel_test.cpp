// Prack100rel_test.cpp — Issue #172: RFC 3262 Require: 100rel on the 777 echo INVITE.
//
// The echo test (777) is the one route where this PBX is the UAS end to end, so it
// is the one route that honours Require: 100rel: its 180 is sent reliably (RFC 3262
// §3: "MUST send any non-100 provisional response reliably if the initial request
// contained a Require header field with the option tag 100rel"), and a matching PRACK
// is answered with 2xx, a non-matching one with 481 (§3). Every other route still
// answers 420 Bad Extension with Unsupported: 100rel, which §3 permits for a UAS
// unwilling to send reliably. Emergency traffic keeps its existing path (no RSeq,
// no 420). Peers that send neither Require nor Supported 100rel are unaffected.

#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "PoolConfig.hpp"
#include "RequestsHandler.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	using Sent = std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>;

	sockaddr_in addrFor(const std::string& ip)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(5060);
		return s;
	}

	std::shared_ptr<SipMessage> makeRegister(const std::string& ext, const std::string& srcIp,
	                                          const std::string& callId)
	{
		std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bKr" + callId + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + callId + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + srcIp + ":5060>;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}

	// extraHeaders is inserted verbatim before the body, one "Name: value\r\n" per line.
	std::shared_ptr<SipMessage> makeInvite(const std::string& fromExt, const std::string& toExt,
	                                        const std::string& srcIp, const std::string& callId,
	                                        const std::string& extraHeaders = "")
	{
		std::string body =
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + srcIp + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + srcIp + "\r\n"
			"t=0 0\r\n"
			"m=audio 10000 RTP/AVP 0\r\n"
			"a=rtpmap:0 PCMU/8000\r\n";
		std::string raw =
			"INVITE sip:" + toExt + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bKi" + callId + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:" + fromExt + "@" + srcIp + ":5060>\r\n" +
			extraHeaders +
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}

	std::shared_ptr<SipMessage> makePrack(const std::string& callId, const std::string& localTag,
	                                       const std::string& rack)
	{
		std::string raw =
			"PRACK sip:777@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.7.50:5060;branch=z9hG4bKp" + callId + "\r\n"
			"From: <sip:500@server>;tag=ft" + callId + "\r\n"
			"To: <sip:777@server>;tag=" + localTag + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 2 PRACK\r\n"
			"RAck: " + rack + "\r\n"
			"Max-Forwards: 70\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor("192.168.7.50"));
	}

	// The first sent message whose status line starts with `status` and whose raw text
	// contains `needle`, or "" if none.
	std::string findSent(const Sent& sent, const std::string& status, const std::string& needle)
	{
		for (const auto& [addr, msg] : sent)
		{
			std::string raw = msg ? msg->toString() : std::string{};
			if (raw.rfind(status, 0) == 0 && raw.find(needle) != std::string::npos) return raw;
		}
		return {};
	}

	bool anySent(const Sent& sent, const std::string& text)
	{
		for (const auto& [addr, msg] : sent)
		{
			if (msg && msg->toString().find(text) != std::string::npos) return true;
		}
		return false;
	}

	// Value of the header named `name` (without the colon), or "".
	std::string headerValue(const std::string& raw, const std::string& name)
	{
		const std::string key = "\r\n" + name + ":";
		size_t at = raw.find(key);
		if (at == std::string::npos) return {};
		at += key.size();
		size_t end = raw.find("\r\n", at);
		std::string v = raw.substr(at, end - at);
		while (!v.empty() && v.front() == ' ') v.erase(0, 1);
		return v;
	}

	// The To-tag the 180 carried, which is the dialog's local tag.
	std::string toTagOf(const std::string& raw)
	{
		const std::string to = headerValue(raw, "To");
		const size_t at = to.find("tag=");
		if (at == std::string::npos) return {};
		return to.substr(at + 4);
	}

	struct EchoRig
	{
		Sent sent;
		RequestsHandler handler{"192.168.7.1", 5060,
			[this](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
				sent.emplace_back(addr, std::move(msg));
			}};

		EchoRig()
		{
			handler.handle(makeRegister("500", "192.168.7.50", "reg-500"));
		}
	};
}

// Red on unfixed code: the header gate answers 420 for any Require: 100rel.
TEST(Prack100rel, Require100relTo777EchoGets180WithRSeqNot420)
{
	EchoRig rig;
	rig.handler.handle(makeInvite("500", "777", "192.168.7.50", "e-req",
		"Require: 100rel\r\n"));

	EXPECT_FALSE(anySent(rig.sent, "420 Bad Extension"))
		<< "a 777 INVITE with Require: 100rel is honoured, not refused with 420";
	const std::string ringing = findSent(rig.sent, "SIP/2.0 180 Ringing", "CSeq: 1 INVITE");
	ASSERT_FALSE(ringing.empty()) << "777 INVITE with Require: 100rel produced no 180 Ringing";
	EXPECT_NE(headerValue(ringing, "RSeq"), "")
		<< "RFC 3262 §3: a reliable provisional MUST include an RSeq header";
	EXPECT_NE(headerValue(ringing, "Require").find("100rel"), std::string::npos)
		<< "RFC 3262 §3: a reliable provisional MUST contain Require: 100rel";
	const std::string rs = headerValue(ringing, "RSeq");
	const uint64_t rseq = rs.empty() ? 0 : std::stoull(rs);
	EXPECT_GE(rseq, 1u) << "RFC 3262 §7.1: the first RSeq must be between 1 and 2**31 - 1";
	EXPECT_LE(rseq, 2147483647u) << "RFC 3262 §7.1: the first RSeq must be between 1 and 2**31 - 1";
}

// Red on unfixed code: PRACK has no handler, so nothing is answered.
TEST(Prack100rel, MatchingPrackTo777EchoGets200)
{
	EchoRig rig;
	rig.handler.handle(makeInvite("500", "777", "192.168.7.50", "e-ok", "Require: 100rel\r\n"));
	const std::string ringing = findSent(rig.sent, "SIP/2.0 180 Ringing", "CSeq: 1 INVITE");
	ASSERT_FALSE(ringing.empty());
	const std::string rseq = headerValue(ringing, "RSeq");
	const std::string tag = toTagOf(ringing);
	ASSERT_FALSE(rseq.empty());
	ASSERT_FALSE(tag.empty());

	rig.sent.clear();
	rig.handler.handle(makePrack("e-ok", tag, rseq + " 1 INVITE"));

	EXPECT_FALSE(findSent(rig.sent, "SIP/2.0 200 OK", "CSeq: 2 PRACK").empty())
		<< "RFC 3262 §3: a PRACK matching the reliable provisional MUST be answered with 2xx";
}

// Red on unfixed code: PRACK has no handler, so nothing is answered.
TEST(Prack100rel, MismatchedPrackTo777EchoGets481)
{
	EchoRig rig;
	rig.handler.handle(makeInvite("500", "777", "192.168.7.50", "e-bad", "Require: 100rel\r\n"));
	const std::string ringing = findSent(rig.sent, "SIP/2.0 180 Ringing", "CSeq: 1 INVITE");
	ASSERT_FALSE(ringing.empty());
	const std::string rseq = headerValue(ringing, "RSeq");
	const std::string tag = toTagOf(ringing);
	ASSERT_FALSE(rseq.empty());

	rig.sent.clear();
	// RSeq + 1 matches no reliable provisional the PBX sent.
	const std::string wrong = std::to_string(std::stoull(rseq) + 1) + " 1 INVITE";
	rig.handler.handle(makePrack("e-bad", tag, wrong));

	EXPECT_FALSE(findSent(rig.sent, "SIP/2.0 481", "CSeq: 2 PRACK").empty())
		<< "RFC 3262 §3: a PRACK that matches no outstanding reliable provisional gets 481";
}

// Red on unfixed code: PRACK has no handler, so nothing is answered.
TEST(Prack100rel, RepeatPrackAfterAckGets481)
{
	EchoRig rig;
	rig.handler.handle(makeInvite("500", "777", "192.168.7.50", "e-rep", "Require: 100rel\r\n"));
	const std::string ringing = findSent(rig.sent, "SIP/2.0 180 Ringing", "CSeq: 1 INVITE");
	const std::string rseq = headerValue(ringing, "RSeq");
	const std::string tag = toTagOf(ringing);
	ASSERT_FALSE(rseq.empty());
	rig.handler.handle(makePrack("e-rep", tag, rseq + " 1 INVITE"));

	rig.sent.clear();
	rig.handler.handle(makePrack("e-rep", tag, rseq + " 1 INVITE"));

	EXPECT_FALSE(findSent(rig.sent, "SIP/2.0 481", "CSeq: 2 PRACK").empty())
		<< "RFC 3262 §3: once acknowledged, the same PRACK no longer matches anything";
}

// Red on unfixed code: checkHeaders reports the first unknown tag, which is 100rel.
TEST(Prack100rel, Require100relWithAnotherUnknownTagNamesThatTag)
{
	EchoRig rig;
	rig.handler.handle(makeInvite("500", "777", "192.168.7.50", "e-two",
		"Require: 100rel, path\r\n"));

	EXPECT_TRUE(anySent(rig.sent, "420 Bad Extension"));
	EXPECT_TRUE(anySent(rig.sent, "Unsupported: path"))
		<< "RFC 3261 §8.2.2.3: the 420 must name each option tag the UAS does not understand";
	EXPECT_FALSE(anySent(rig.sent, "Unsupported: 100rel"));
}

// Guard, passes on unfixed code: Supported: 100rel alone is a MAY (RFC 3262 §3), not a MUST.
TEST(Prack100rel, SupportedOnly100relTo777EchoSendsNoRSeq)
{
	EchoRig rig;
	rig.handler.handle(makeInvite("500", "777", "192.168.7.50", "e-sup", "Supported: 100rel\r\n"));

	const std::string ringing = findSent(rig.sent, "SIP/2.0 180 Ringing", "CSeq: 1 INVITE");
	ASSERT_FALSE(ringing.empty());
	EXPECT_EQ(headerValue(ringing, "RSeq"), "")
		<< "a peer that only offers Supported: 100rel must see the unchanged unreliable 180";
}

// Guard, passes on unfixed code: an ordinary extension call keeps its 420.
TEST(Prack100rel, Require100relToOrdinaryExtensionStays420)
{
	EchoRig rig;
	rig.handler.handle(makeRegister("600", "192.168.7.60", "reg-600"));
	rig.handler.handle(makeInvite("500", "600", "192.168.7.50", "e-ord", "Require: 100rel\r\n"));

	EXPECT_TRUE(anySent(rig.sent, "420 Bad Extension"));
	EXPECT_TRUE(anySent(rig.sent, "Unsupported: 100rel"))
		<< "RFC 3262 §3: a UAS unwilling to send reliably MUST answer 420 naming 100rel";
	EXPECT_FALSE(anySent(rig.sent, "RSeq:"));
}

// Guard, passes on unfixed code: Proxy-Require is not 100rel's place (RFC 3262 §4).
TEST(Prack100rel, ProxyRequire100relTo777EchoStays420)
{
	EchoRig rig;
	rig.handler.handle(makeInvite("500", "777", "192.168.7.50", "e-pxy",
		"Proxy-Require: 100rel\r\n"));

	EXPECT_TRUE(anySent(rig.sent, "420 Bad Extension"));
	EXPECT_TRUE(anySent(rig.sent, "Unsupported: 100rel"));
}

// Guard, passes on unfixed code: a 911 with Require: 100rel is not refused and gets no
// RSeq. Its path is the existing emergency yield, so it is never reliable (Rule 5).
TEST(Prack100rel, Emergency911WithRequire100relIsNotRefusedAndGetsNoRSeq)
{
	EchoRig rig;
	rig.handler.handle(makeInvite("500", "911", "192.168.7.50", "e-911", "Require: 100rel\r\n"));

	EXPECT_FALSE(anySent(rig.sent, "420 Bad Extension"))
		<< "Rule 5: a 911 must never be refused for its Require header";
	EXPECT_FALSE(anySent(rig.sent, "RSeq:"))
		<< "Rule 5: a 911 is never answered on the reliable-provisional path";
}

// Guard, passes on unfixed code: a PRACK on a dialog that never offered 100rel is not
// owned by the 100rel path and stays unanswered, as it is today.
TEST(Prack100rel, PrackOnNon100relDialogStaysUnanswered)
{
	EchoRig rig;
	rig.handler.handle(makeInvite("500", "777", "192.168.7.50", "e-plain"));
	const std::string ringing = findSent(rig.sent, "SIP/2.0 180 Ringing", "CSeq: 1 INVITE");
	const std::string tag = toTagOf(ringing);
	ASSERT_FALSE(tag.empty());

	rig.sent.clear();
	rig.handler.handle(makePrack("e-plain", tag, "1 1 INVITE"));

	EXPECT_FALSE(anySent(rig.sent, "PRACK")) << "no response is owed to a PRACK for a non-100rel dialog";
	EXPECT_FALSE(anySent(rig.sent, "SIP/2.0 481"));
}
