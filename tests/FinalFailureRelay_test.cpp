// FinalFailureRelay_test.cpp — Issue #746: a callee's final failure that has no
// dispatch key of its own (415, 420, 488, 603, ...) used to reach
// onFinalFailure() and stop there. The caller got no final response and the
// callee's response was never ACKed (RFC 3261 §17.1.1.3), so it retransmitted
// until Timer H. Driven end to end through RequestsHandler::handle(), the same
// style CallForwardBusy_test.cpp uses.

#include <gtest/gtest.h>

#include <string>
#include <utility>
#include <vector>

#include "RequestsHandler.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	using SentList = std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>;

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

	std::shared_ptr<SipMessage> makeInvite(const std::string& fromExt, const std::string& toExt,
		const std::string& srcIp, const std::string& callId, const std::string& branch)
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
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=" + branch + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:" + fromExt + "@" + srcIp + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}

	// A final response to the INVITE, sent by `calleeIp`. The Via is the
	// caller's (the PBX relays the INVITE without adding its own), From is still
	// the caller, To is the callee plus its tag.
	std::shared_ptr<SipMessage> makeFinal(int code, const std::string& fromExt,
		const std::string& toExt, const std::string& callerIp, const std::string& calleeIp,
		const std::string& callId, const std::string& branch)
	{
		std::string raw =
			"SIP/2.0 " + std::to_string(code) + " Refused\r\n"
			"Via: SIP/2.0/UDP " + callerIp + ":5060;branch=" + branch + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>;tag=bt" + callId + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(calleeIp));
	}

	std::shared_ptr<SipMessage> makeAck(const std::string& fromExt, const std::string& toExt,
		const std::string& srcIp, const std::string& callId, const std::string& branch)
	{
		std::string raw =
			"ACK sip:" + toExt + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=" + branch + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>;tag=bt" + callId + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 ACK\r\n"
			"Max-Forwards: 70\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}

	std::string findSentTo(const SentList& sent, const sockaddr_in& addr, const std::string& needle)
	{
		for (auto it = sent.rbegin(); it != sent.rend(); ++it)
		{
			if (it->first.sin_addr.s_addr != addr.sin_addr.s_addr) continue;
			if (it->first.sin_port != addr.sin_port) continue;
			if (!it->second) continue;
			std::string raw = it->second->toString();
			if (raw.find(needle) != std::string::npos) return raw;
		}
		return {};
	}
}

// The ordinary relayed call: the callee refuses with a code nothing named, the
// caller must be told, and the caller's ACK must complete the callee's
// transaction.
TEST(FinalFailureRelay, CalleeRefusalIsRelayedToTheCallerAndItsAckReachesTheCallee)
{
	for (const int code : { 415, 420, 488, 603 })
	{
		SCOPED_TRACE(code);
		SentList sent;
		RequestsHandler handler("192.168.50.1", 5060,
			[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
				sent.emplace_back(addr, std::move(msg));
			});

		const sockaddr_in callerAddr = addrFor("192.168.50.20");
		const sockaddr_in calleeAddr = addrFor("192.168.50.21");
		handler.handle(makeRegister("401", "192.168.50.20", "reg-401"));
		handler.handle(makeRegister("402", "192.168.50.21", "reg-402"));
		handler.handle(makeInvite("401", "402", "192.168.50.20", "ff-1", "z9hG4bKff1"));

		sent.clear();
		handler.handle(makeFinal(code, "401", "402", "192.168.50.20", "192.168.50.21",
			"ff-1", "z9hG4bKff1"));

		EXPECT_FALSE(findSentTo(sent, callerAddr, "SIP/2.0 " + std::to_string(code)).empty())
			<< "the caller must get the callee's final response";
		EXPECT_TRUE(findSentTo(sent, calleeAddr, "404").empty())
			<< "nothing may be answered back at the callee's response";

		sent.clear();
		handler.handle(makeAck("401", "402", "192.168.50.20", "ff-1", "z9hG4bKff1"));
		EXPECT_FALSE(findSentTo(sent, calleeAddr, "ACK sip:402").empty())
			<< "the caller's ACK must reach the callee, completing its transaction";
	}
}

// A ring-group member's refusal is not relayed (the caller is still ringing the
// others), but the PBX forked that INVITE, so the ACK is its to send.
TEST(FinalFailureRelay, RingGroupMemberRefusalIsAckedNotRelayed)
{
	SentList sent;
	RequestsHandler handler("192.168.50.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in callerAddr = addrFor("192.168.50.20");
	const sockaddr_in memberAddr = addrFor("192.168.50.21");
	handler.handle(makeRegister("100", "192.168.50.20", "reg-100"));
	handler.handle(makeRegister("101", "192.168.50.21", "reg-101"));
	handler.handle(makeRegister("102", "192.168.50.22", "reg-102"));
	handler.setRingGroup("600", "101,102", "ringall");
	handler.handle(makeInvite("100", "600", "192.168.50.20", "ff-2", "z9hG4bKff2"));

	sent.clear();
	handler.handle(makeFinal(603, "100", "101", "192.168.50.20", "192.168.50.21",
		"ff-2", "z9hG4bKff2"));

	const std::string ack = findSentTo(sent, memberAddr, "ACK sip:101@192.168.50.21:5060 SIP/2.0");
	ASSERT_FALSE(ack.empty()) << "the refusing member must be ACKed";
	EXPECT_NE(ack.find("branch=z9hG4bKff2"), std::string::npos)
		<< "the ACK belongs to the forked INVITE's transaction";
	EXPECT_NE(ack.find("CSeq: 1 ACK"), std::string::npos);
	EXPECT_TRUE(findSentTo(sent, callerAddr, "SIP/2.0 603").empty())
		<< "one member declining must not end the caller's ring";
}

// The ring-group loser's 487 answers the CANCEL the PBX sent; it is ACKed too.
TEST(FinalFailureRelay, RingGroupLosersRequestTerminatedIsAcked)
{
	SentList sent;
	RequestsHandler handler("192.168.50.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in loserAddr = addrFor("192.168.50.22");
	handler.handle(makeRegister("100", "192.168.50.20", "reg-100"));
	handler.handle(makeRegister("101", "192.168.50.21", "reg-101"));
	handler.handle(makeRegister("102", "192.168.50.22", "reg-102"));
	handler.setRingGroup("600", "101,102", "ringall");
	handler.handle(makeInvite("100", "600", "192.168.50.20", "ff-3", "z9hG4bKff3"));

	sent.clear();
	handler.handle(makeFinal(487, "100", "102", "192.168.50.20", "192.168.50.22",
		"ff-3", "z9hG4bKff3"));

	const std::string ack = findSentTo(sent, loserAddr, "ACK sip:102@192.168.50.22:5060 SIP/2.0");
	ASSERT_FALSE(ack.empty()) << "the loser's 487 must be ACKed";
	EXPECT_NE(ack.find("branch=z9hG4bKff3"), std::string::npos);
	EXPECT_NE(ack.find("CSeq: 1 ACK"), std::string::npos);
}

// Absence guard: a final to something that is not an INVITE is not this
// handler's business and must not be ACKed or relayed.
TEST(FinalFailureRelay, AFinalToANonInviteIsNeitherAckedNorRelayed)
{
	SentList sent;
	RequestsHandler handler("192.168.50.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	handler.handle(makeRegister("401", "192.168.50.20", "reg-401"));
	handler.handle(makeRegister("402", "192.168.50.21", "reg-402"));
	handler.handle(makeInvite("401", "402", "192.168.50.20", "ff-4", "z9hG4bKff4"));

	std::string raw =
		"SIP/2.0 603 Decline\r\n"
		"Via: SIP/2.0/UDP 192.168.50.20:5060;branch=z9hG4bKff4\r\n"
		"From: <sip:401@server>;tag=ftff-4\r\n"
		"To: <sip:402@server>;tag=btff-4\r\n"
		"Call-ID: ff-4\r\n"
		"CSeq: 2 INFO\r\n"
		"Content-Length: 0\r\n\r\n";
	sent.clear();
	handler.handle(RequestsHandler::getMessageFromPool(raw, addrFor("192.168.50.21")));

	EXPECT_TRUE(sent.empty()) << "a non-INVITE final is left to the existing paths";
}
