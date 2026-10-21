// FinalFailureRelay_test.cpp — Issue #746: a callee's final failure that has no
// dispatch key of its own (415, 420, 488, 603, ...) used to reach
// onFinalFailure() and stop there. The caller got no final response and the
// callee's response was never ACKed (RFC 3261 §17.1.1.3), so it retransmitted
// until Timer H. Driven end to end through RequestsHandler::handle(), the same
// style CallForwardBusy_test.cpp uses.

#include <gtest/gtest.h>

#include <chrono>
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
		const std::string& callId, const std::string& branch, int cseq = 1)
	{
		std::string raw =
			"SIP/2.0 " + std::to_string(code) + " Refused\r\n"
			"Via: SIP/2.0/UDP " + callerIp + ":5060;branch=" + branch + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>;tag=bt" + callId + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: " + std::to_string(cseq) + " INVITE\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(calleeIp));
	}

	// The callee answers: 200 OK with its own Contact and an SDP answer.
	std::shared_ptr<SipMessage> makeOk(const std::string& fromExt, const std::string& toExt,
		const std::string& callerIp, const std::string& calleeIp, const std::string& callId,
		const std::string& branch)
	{
		const std::string body =
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + calleeIp + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + calleeIp + "\r\n"
			"t=0 0\r\n"
			"m=audio 20000 RTP/AVP 0\r\n"
			"a=rtpmap:0 PCMU/8000\r\n";
		std::string raw =
			"SIP/2.0 200 OK\r\n"
			"Via: SIP/2.0/UDP " + callerIp + ":5060;branch=" + branch + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>;tag=bt" + callId + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Contact: <sip:" + toExt + "@" + calleeIp + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(calleeIp));
	}

	// The callee's mandatory 200 to the PBX's CANCEL (RFC 3261 s9.2): CSeq names CANCEL, no SDP.
	std::shared_ptr<SipMessage> makeCancelOk(const std::string& fromExt, const std::string& toExt,
		const std::string& callerIp, const std::string& calleeIp, const std::string& callId,
		const std::string& branch)
	{
		std::string raw =
			"SIP/2.0 200 OK\r\n"
			"Via: SIP/2.0/UDP " + callerIp + ":5060;branch=" + branch + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>;tag=bt" + callId + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 CANCEL\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(calleeIp));
	}

	// The caller's re-INVITE inside the established dialog (To carries the callee's tag).
	std::shared_ptr<SipMessage> makeReinvite(const std::string& fromExt, const std::string& toExt,
		const std::string& srcIp, const std::string& callId, const std::string& branch, int cseq)
	{
		const std::string body =
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + srcIp + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + srcIp + "\r\n"
			"t=0 0\r\n"
			"m=audio 10000 RTP/AVP 0\r\n"
			"a=rtpmap:0 PCMU/8000\r\n"
			"a=sendrecv\r\n";
		std::string raw =
			"INVITE sip:" + toExt + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=" + branch + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>;tag=bt" + callId + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: " + std::to_string(cseq) + " INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:" + fromExt + "@" + srcIp + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}

	// The caller's CANCEL of its own INVITE (same branch, no To tag).
	std::shared_ptr<SipMessage> makeCancel(const std::string& fromExt, const std::string& toExt,
		const std::string& srcIp, const std::string& callId, const std::string& branch)
	{
		std::string raw =
			"CANCEL sip:" + toExt + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=" + branch + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 CANCEL\r\n"
			"Max-Forwards: 70\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}

	std::shared_ptr<SipMessage> makeAck(const std::string& fromExt, const std::string& toExt,
		const std::string& srcIp, const std::string& callId, const std::string& branch, int cseq = 1)
	{
		std::string raw =
			"ACK sip:" + toExt + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=" + branch + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>;tag=bt" + callId + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: " + std::to_string(cseq) + " ACK\r\n"
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

// The glare row of #746: a final to a RELAYED re-INVITE (491 here) goes back to
// the sender, the dialog survives it, and the sender's ACK reaches the far leg.
TEST(FinalFailureRelay, A491ToARelayedReInviteGoesBackToTheSenderAndTheDialogSurvives)
{
	SentList sent;
	RequestsHandler handler("192.168.50.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});
	const sockaddr_in callerAddr = addrFor("192.168.50.20");
	const sockaddr_in calleeAddr = addrFor("192.168.50.21");
	handler.handle(makeRegister("401", "192.168.50.20", "reg-401"));
	handler.handle(makeRegister("402", "192.168.50.21", "reg-402"));
	handler.handle(makeInvite("401", "402", "192.168.50.20", "ff-5", "z9hG4bKff5"));
	handler.handle(makeOk("401", "402", "192.168.50.20", "192.168.50.21", "ff-5", "z9hG4bKff5"));
	handler.handle(makeAck("401", "402", "192.168.50.20", "ff-5", "z9hG4bKack5"));
	ASSERT_TRUE(handler.getSession("Call-ID: ff-5").has_value()) << "precondition: the call is up";

	sent.clear();
	handler.handle(makeReinvite("401", "402", "192.168.50.20", "ff-5", "z9hG4bKre5", 2));
	ASSERT_FALSE(findSentTo(sent, calleeAddr, "CSeq: 2 INVITE").empty()) << "precondition: the re-INVITE is relayed";

	sent.clear();
	handler.handle(makeFinal(491, "401", "402", "192.168.50.20", "192.168.50.21",
		"ff-5", "z9hG4bKre5", 2));
	EXPECT_FALSE(findSentTo(sent, callerAddr, "SIP/2.0 491").empty())
		<< "the sender of the re-INVITE must be told";
	EXPECT_TRUE(findSentTo(sent, calleeAddr, "SIP/2.0 491").empty())
		<< "and the 491 must not be echoed back to the leg it came from";
	auto s = handler.getSession("Call-ID: ff-5");
	ASSERT_TRUE(s.has_value()) << "a refused re-INVITE does not end the dialog";
	EXPECT_EQ(s.value()->getState(), Session::State::Connected);

	sent.clear();
	handler.handle(makeAck("401", "402", "192.168.50.20", "ff-5", "z9hG4bKre5", 2));
	EXPECT_FALSE(findSentTo(sent, calleeAddr, "ACK sip:402").empty())
		<< "the sender's ACK must reach the far leg, completing its transaction";
}

// The CANCEL/final race: the caller CANCELled, but the callee answered the
// INVITE with a refusal instead of 487. The caller still needs a final.
TEST(FinalFailureRelay, ACalleeRefusalThatCrossesTheCallersCancelStillReachesTheCaller)
{
	SentList sent;
	RequestsHandler handler("192.168.50.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});
	const sockaddr_in callerAddr = addrFor("192.168.50.20");
	handler.handle(makeRegister("401", "192.168.50.20", "reg-401"));
	handler.handle(makeRegister("402", "192.168.50.21", "reg-402"));
	handler.handle(makeInvite("401", "402", "192.168.50.20", "ff-6", "z9hG4bKff6"));
	handler.handle(makeCancel("401", "402", "192.168.50.20", "ff-6", "z9hG4bKff6"));

	sent.clear();
	handler.handle(makeFinal(603, "401", "402", "192.168.50.20", "192.168.50.21",
		"ff-6", "z9hG4bKff6"));
	EXPECT_FALSE(findSentTo(sent, callerAddr, "SIP/2.0 603").empty())
		<< "the caller must get a final for its INVITE, not wait out Timer B";
}

// A retransmitted final after the relay means the callee never saw the ACK.
// It is repaired hop by hop, and the caller is not told a second time.
TEST(FinalFailureRelay, ARetransmittedRefusalIsReAckedAndNotRelayedTwice)
{
	SentList sent;
	RequestsHandler handler("192.168.50.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});
	const sockaddr_in callerAddr = addrFor("192.168.50.20");
	const sockaddr_in calleeAddr = addrFor("192.168.50.21");
	handler.handle(makeRegister("401", "192.168.50.20", "reg-401"));
	handler.handle(makeRegister("402", "192.168.50.21", "reg-402"));
	handler.handle(makeInvite("401", "402", "192.168.50.20", "ff-7", "z9hG4bKff7"));
	handler.handle(makeFinal(603, "401", "402", "192.168.50.20", "192.168.50.21",
		"ff-7", "z9hG4bKff7"));
	ASSERT_TRUE(handler.getSession("Call-ID: ff-7").has_value()) << "precondition: still awaiting the caller's ACK";

	sent.clear();
	handler.handle(makeFinal(603, "401", "402", "192.168.50.20", "192.168.50.21",
		"ff-7", "z9hG4bKff7"));   // the caller's ACK was lost: the callee retransmits
	EXPECT_FALSE(findSentTo(sent, calleeAddr, "ACK sip:402").empty())
		<< "the retransmitted final must be ACKed";
	EXPECT_TRUE(findSentTo(sent, callerAddr, "SIP/2.0 603").empty())
		<< "and not relayed to the caller a second time";
}

// A hunt member's refusal advances to the next member (as a busy one does); the
// last member's refusal fails the caller.
TEST(FinalFailureRelay, AHuntMemberRefusalAdvancesTheHuntAndTheLastEndsTheCall)
{
	SentList sent;
	RequestsHandler handler("192.168.50.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});
	const sockaddr_in callerAddr = addrFor("192.168.50.20");
	const sockaddr_in m101 = addrFor("192.168.50.21");
	const sockaddr_in m102 = addrFor("192.168.50.22");
	handler.handle(makeRegister("100", "192.168.50.20", "reg-100"));
	handler.handle(makeRegister("101", "192.168.50.21", "reg-101"));
	handler.handle(makeRegister("102", "192.168.50.22", "reg-102"));
	handler.setRingGroup("620", "101,102", "hunt");
	handler.handle(makeInvite("100", "620", "192.168.50.20", "ff-8", "z9hG4bKff8"));
	ASSERT_FALSE(findSentTo(sent, m101, "Call-ID: ff-8").empty()) << "precondition: the hunt rings 101 first";
	ASSERT_TRUE(findSentTo(sent, m102, "Call-ID: ff-8").empty());

	sent.clear();
	handler.handle(makeFinal(603, "100", "101", "192.168.50.20", "192.168.50.21",
		"ff-8", "z9hG4bKff8"));
	EXPECT_FALSE(findSentTo(sent, m102, "INVITE sip:102").empty()) << "the hunt advances to 102";
	EXPECT_TRUE(findSentTo(sent, callerAddr, "SIP/2.0 603").empty()) << "the caller is still ringing";

	sent.clear();
	handler.handle(makeFinal(603, "100", "102", "192.168.50.20", "192.168.50.22",
		"ff-8", "z9hG4bKff8"));
	EXPECT_FALSE(findSentTo(sent, callerAddr, "SIP/2.0 603").empty())
		<< "the list is exhausted: the caller gets the final";
	EXPECT_FALSE(handler.getSession("Call-ID: ff-8").has_value()) << "and the call ends";
}

// Ring-all: only the LAST member's refusal fails the caller; before that the
// caller keeps ringing (the first member's refusal is the test above's control).
TEST(FinalFailureRelay, RingAllFailsTheCallerOnlyWhenTheLastMemberRefuses)
{
	SentList sent;
	RequestsHandler handler("192.168.50.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});
	const sockaddr_in callerAddr = addrFor("192.168.50.20");
	handler.handle(makeRegister("100", "192.168.50.20", "reg-100"));
	handler.handle(makeRegister("101", "192.168.50.21", "reg-101"));
	handler.handle(makeRegister("102", "192.168.50.22", "reg-102"));
	handler.setRingGroup("600", "101,102", "ringall");
	handler.handle(makeInvite("100", "600", "192.168.50.20", "ff-9", "z9hG4bKff9"));

	sent.clear();
	handler.handle(makeFinal(603, "100", "101", "192.168.50.20", "192.168.50.21",
		"ff-9", "z9hG4bKff9"));
	EXPECT_TRUE(findSentTo(sent, callerAddr, "SIP/2.0 603").empty()) << "102 is still ringing";
	EXPECT_TRUE(handler.getSession("Call-ID: ff-9").has_value());

	sent.clear();
	handler.handle(makeFinal(603, "100", "102", "192.168.50.20", "192.168.50.22",
		"ff-9", "z9hG4bKff9"));
	EXPECT_FALSE(findSentTo(sent, callerAddr, "SIP/2.0 603").empty())
		<< "every member refused: the caller must get a final, not ring forever";
	EXPECT_FALSE(handler.getSession("Call-ID: ff-9").has_value());
}

// desmo: a callee that refuses with voicemail armed is diverted to voicemail,
// as its ring timer would after 20 s; the raw refusal is not relayed. (The
// control is the first test: without voicemail, the refusal is relayed.)
TEST(FinalFailureRelay, ARefusingCalleeWithVoicemailArmedIsDivertedToVoicemail)
{
	SentList sent;
	RequestsHandler handler("192.168.50.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});
	const sockaddr_in callerAddr = addrFor("192.168.50.20");
	const sockaddr_in calleeAddr = addrFor("192.168.50.21");
	handler.handle(makeRegister("401", "192.168.50.20", "reg-401"));
	handler.handle(makeRegister("402", "192.168.50.21", "reg-402"));
	handler.setVoicemail("402", true);
	handler.handle(makeInvite("401", "402", "192.168.50.20", "ff-10", "z9hG4bKff10"));

	sent.clear();
	handler.handle(makeFinal(603, "401", "402", "192.168.50.20", "192.168.50.21",
		"ff-10", "z9hG4bKff10"));
	const std::string ok = findSentTo(sent, callerAddr, "SIP/2.0 200 OK");
	ASSERT_FALSE(ok.empty()) << "the caller must be answered by voicemail";
	EXPECT_NE(ok.find("v=0"), std::string::npos) << "with an SDP answer";
	EXPECT_TRUE(findSentTo(sent, callerAddr, "SIP/2.0 603").empty()) << "the refusal itself is not relayed";
	EXPECT_FALSE(findSentTo(sent, calleeAddr, "ACK sip:402").empty()) << "the callee's final is ACKed";
}

// The same for call-forward-no-answer: the call goes to the CFNA target.
TEST(FinalFailureRelay, ARefusingCalleeWithCfnaArmedIsForwardedToTheTarget)
{
	SentList sent;
	RequestsHandler handler("192.168.50.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});
	const sockaddr_in callerAddr = addrFor("192.168.50.20");
	const sockaddr_in targetAddr = addrFor("192.168.50.23");
	handler.handle(makeRegister("401", "192.168.50.20", "reg-401"));
	handler.handle(makeRegister("402", "192.168.50.21", "reg-402"));
	handler.handle(makeRegister("403", "192.168.50.23", "reg-403"));
	handler.setForward("402", "noanswer", "403");
	handler.handle(makeInvite("401", "402", "192.168.50.20", "ff-11", "z9hG4bKff11"));

	sent.clear();
	handler.handle(makeFinal(603, "401", "402", "192.168.50.20", "192.168.50.21",
		"ff-11", "z9hG4bKff11"));
	EXPECT_FALSE(findSentTo(sent, targetAddr, "Call-ID: ff-11").empty())
		<< "the call must be forwarded to the CFNA target";
	EXPECT_TRUE(findSentTo(sent, callerAddr, "SIP/2.0 603").empty()) << "the refusal is not relayed";
}

// #803: a member's 486 / 480 carries From = the caller (the fork is a copy of the
// caller's INVITE), so onBusy()/onUnavailable() must drop the pending target by To.
TEST(FinalFailureRelay, RingAllFailsTheCallerWhenEveryMemberAnswersBusyOrUnavailable)
{
	for (const int code : { 486, 480 })
	{
		SCOPED_TRACE(code);
		SentList sent;
		RequestsHandler handler("192.168.50.1", 5060,
			[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
				sent.emplace_back(addr, std::move(msg));
			});
		const sockaddr_in callerAddr = addrFor("192.168.50.20");
		handler.handle(makeRegister("100", "192.168.50.20", "reg-100"));
		handler.handle(makeRegister("101", "192.168.50.21", "reg-101"));
		handler.handle(makeRegister("102", "192.168.50.22", "reg-102"));
		handler.setRingGroup("600", "101,102", "ringall");
		handler.handle(makeInvite("100", "600", "192.168.50.20", "ab-1", "z9hG4bKab1"));

		sent.clear();
		handler.handle(makeFinal(code, "100", "101", "192.168.50.20", "192.168.50.21",
			"ab-1", "z9hG4bKab1"));
		EXPECT_TRUE(findSentTo(sent, callerAddr, "SIP/2.0 " + std::to_string(code)).empty())
			<< "102 is still ringing";
		EXPECT_TRUE(handler.getSession("Call-ID: ab-1").has_value());

		sent.clear();
		handler.handle(makeFinal(code, "100", "102", "192.168.50.20", "192.168.50.22",
			"ab-1", "z9hG4bKab1"));
		EXPECT_FALSE(findSentTo(sent, callerAddr, "SIP/2.0 " + std::to_string(code)).empty())
			<< "every member declined: the caller must get a final, not ring forever";
		EXPECT_FALSE(handler.getSession("Call-ID: ab-1").has_value())
			<< "and the session slot must be freed";
	}
}

// #1049: a caller's CANCEL leaves the session in state Cancel until the callee's 487
// arrives. A silent callee never sends one, so nothing ended the call. The bounded wait
// (RFC 3261 s17.1.1.2, 64*T1 = 32 s) is armed on the CANCEL itself. There is no
// injectable clock: the window is checked with the before/after bracket NoAnswerTimeout
// uses, and the sweep is forced by arming the deadline in the past.
namespace
{
	using TestClock = std::chrono::steady_clock;

	int countSentTo(const SentList& sent, const sockaddr_in& addr, const std::string& needle)
	{
		int n = 0;
		for (const auto& entry : sent)
		{
			const sockaddr_in& to = entry.first;
			if (to.sin_addr.s_addr != addr.sin_addr.s_addr || to.sin_port != addr.sin_port) continue;
			if (!entry.second) continue;
			if (entry.second->toString().find(needle) != std::string::npos) ++n;
		}
		return n;
	}
}

// RED on main: the INVITE-time ring timer (20 s) stays armed through the CANCEL, so the
// first assertion fails; and nothing ends a Cancel session, so the last two fail too.
TEST(FinalFailureRelay, ASilentCalleesCancelIsEndedAt32sWithTheCallersOwn487)
{
	SentList sent;
	RequestsHandler handler("192.168.50.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});
	const sockaddr_in callerAddr = addrFor("192.168.50.20");
	handler.handle(makeRegister("401", "192.168.50.20", "reg-401"));
	handler.handle(makeRegister("402", "192.168.50.21", "reg-402"));
	handler.handle(makeInvite("401", "402", "192.168.50.20", "cb-1", "z9hG4bKcb1"));

	const auto before = TestClock::now();
	handler.handle(makeCancel("401", "402", "192.168.50.20", "cb-1", "z9hG4bKcb1"));
	const auto after = TestClock::now();
	const std::string key = "Call-ID: cb-1";
	auto session = handler.getSession(key);
	ASSERT_TRUE(session.has_value());
	EXPECT_FALSE(session.value()->isRingExpired(before + std::chrono::seconds(31)))
		<< "the cancelled call must not be ended before 32 s";
	EXPECT_TRUE(session.value()->isRingExpired(after + std::chrono::seconds(32)))
		<< "the cancelled call must be ended by 32 s";

	handler.forceNextTickForTest();
	handler.tick();
	EXPECT_TRUE(handler.getSession(key).has_value())
		<< "the session waits for the callee's 487 at ~0 s";
	EXPECT_EQ(countSentTo(sent, callerAddr, "SIP/2.0 487"), 0)
		<< "nothing is sent to the caller before the 32 s are up";

	session.value()->armRingTimer(TestClock::now() - std::chrono::seconds(1));   // the 32 s have passed
	sent.clear();
	handler.forceNextTickForTest();
	handler.tick();
	EXPECT_FALSE(handler.getSession(key).has_value())
		<< "the session must be gone after 32 s with no 487 from the callee";
	EXPECT_EQ(countSentTo(sent, callerAddr, "SIP/2.0 487"), 1)
		<< "the PBX answers the caller's INVITE with its own 487, exactly once";
}

// A retransmitted CANCEL (same branch, same Call-ID, 500 ms later while the callee stays silent)
// must leave the 32 s window armed from the first CANCEL: it neither clears it nor pushes it out.
// RED against the first fix commit: the second CANCEL finds state Cancel and clears the timer.
TEST(FinalFailureRelay, ARetransmittedCancelKeepsTheBoundedWaitArmedFromTheFirstCancel)
{
	SentList sent;
	RequestsHandler handler("192.168.50.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});
	const sockaddr_in callerAddr = addrFor("192.168.50.20");
	handler.handle(makeRegister("401", "192.168.50.20", "reg-401"));
	handler.handle(makeRegister("402", "192.168.50.21", "reg-402"));
	handler.handle(makeInvite("401", "402", "192.168.50.20", "cb-4", "z9hG4bKcb4"));

	handler.handle(makeCancel("401", "402", "192.168.50.20", "cb-4", "z9hG4bKcb4"));
	const auto afterFirst = TestClock::now();
	handler.handle(makeCancel("401", "402", "192.168.50.20", "cb-4", "z9hG4bKcb4"));   // retransmit

	const std::string key = "Call-ID: cb-4";
	auto session = handler.getSession(key);
	ASSERT_TRUE(session.has_value());
	EXPECT_EQ(session.value()->getState(), Session::State::Cancel);
	EXPECT_TRUE(session.value()->isRingExpired(afterFirst + std::chrono::seconds(32)))
		<< "a retransmitted CANCEL must not disarm the 32 s bound";

	session.value()->armRingTimer(TestClock::now() - std::chrono::seconds(1));
	sent.clear();
	handler.forceNextTickForTest();
	handler.tick();
	EXPECT_FALSE(handler.getSession(key).has_value())
		<< "the call is still ended once the 32 s are up";
	EXPECT_EQ(countSentTo(sent, callerAddr, "SIP/2.0 487"), 1)
		<< "exactly one 487 reaches the caller";
}

// RED on main for the plain call (its ring deadline is never honoured in state Cancel).
// The emergency twin, armed past its deadline in the same tick, must stay untouched.
TEST(FinalFailureRelay, AnEmergencyCancelIsNotEndedByTheBoundedWait)
{
	SentList sent;
	RequestsHandler handler("192.168.50.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});
	const sockaddr_in emergencyCallerAddr = addrFor("192.168.50.22");
	handler.handle(makeRegister("401", "192.168.50.20", "reg-401"));
	handler.handle(makeRegister("402", "192.168.50.21", "reg-402"));
	handler.handle(makeRegister("403", "192.168.50.22", "reg-403"));
	handler.handle(makeRegister("404", "192.168.50.23", "reg-404"));
	handler.handle(makeInvite("401", "402", "192.168.50.20", "cb-2", "z9hG4bKcb2"));
	handler.handle(makeInvite("403", "404", "192.168.50.22", "cb-3", "z9hG4bKcb3"));

	auto emergency = handler.getSession("Call-ID: cb-3");
	ASSERT_TRUE(emergency.has_value());
	emergency.value()->setEmergency(true);

	handler.handle(makeCancel("401", "402", "192.168.50.20", "cb-2", "z9hG4bKcb2"));
	handler.handle(makeCancel("403", "404", "192.168.50.22", "cb-3", "z9hG4bKcb3"));

	auto plain = handler.getSession("Call-ID: cb-2");
	ASSERT_TRUE(plain.has_value());
	const auto past = TestClock::now() - std::chrono::seconds(1);
	plain.value()->armRingTimer(past);
	emergency.value()->armRingTimer(past);

	sent.clear();
	handler.forceNextTickForTest();
	handler.tick();
	EXPECT_FALSE(handler.getSession("Call-ID: cb-2").has_value())
		<< "the plain cancelled call is ended once its 32 s are up";
	ASSERT_TRUE(handler.getSession("Call-ID: cb-3").has_value())
		<< "an emergency Cancel session is never ended by the bounded wait";
	EXPECT_EQ(emergency.value()->getState(), Session::State::Cancel);
	EXPECT_EQ(countSentTo(sent, emergencyCallerAddr, "SIP/2.0 487"), 0)
		<< "no 487 goes to the emergency caller";
}

// Found on hardware (.244, RC 3237af5f): a callee that answers the CANCEL with its mandatory
// 200 but never sends the 487 must still be bounded. That 200 has CSeq "n CANCEL"; it is not a
// 2xx that answers the call, so it must neither disarm the 32 s window nor mark the cancel answered.
// RED against 3237af5f: onOk's Cancel branch clears the timer for any 200.
TEST(FinalFailureRelay, ACalleesOwn200ToTheCancelDoesNotDisarmTheBoundedWait)
{
	SentList sent;
	RequestsHandler handler("192.168.50.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});
	const sockaddr_in callerAddr = addrFor("192.168.50.20");
	handler.handle(makeRegister("401", "192.168.50.20", "reg-401"));
	handler.handle(makeRegister("402", "192.168.50.21", "reg-402"));
	handler.handle(makeInvite("401", "402", "192.168.50.20", "cb-6", "z9hG4bKcb6"));
	handler.handle(makeCancel("401", "402", "192.168.50.20", "cb-6", "z9hG4bKcb6"));
	const auto afterCancel = TestClock::now();

	handler.handle(makeCancelOk("401", "402", "192.168.50.20", "192.168.50.21", "cb-6", "z9hG4bKcb6"));

	const std::string key = "Call-ID: cb-6";
	auto session = handler.getSession(key);
	ASSERT_TRUE(session.has_value());
	EXPECT_TRUE(session.value()->isRingExpired(afterCancel + std::chrono::seconds(32)))
		<< "the callee's 200 to the CANCEL must not disarm the 32 s bound";
	EXPECT_FALSE(session.value()->cancelAnswered())
		<< "a 200 to the CANCEL does not mean the caller was answered";

	session.value()->armRingTimer(TestClock::now() - std::chrono::seconds(1));
	sent.clear();
	handler.forceNextTickForTest();
	handler.tick();
	EXPECT_FALSE(handler.getSession(key).has_value())
		<< "the silent callee's call is still ended once the 32 s are up";
	EXPECT_EQ(countSentTo(sent, callerAddr, "SIP/2.0 487"), 1)
		<< "exactly one 487 reaches the caller";
}

// Guard, green after the fix: once the bounded wait has ended the call, the callee's late 487
// and a stray CANCEL find no session and send nothing more (teardown runs exactly once).
TEST(FinalFailureRelay, ALate487OrCancelAfterTheBoundedReapSendsNothingMore)
{
	SentList sent;
	RequestsHandler handler("192.168.50.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});
	const sockaddr_in callerAddr = addrFor("192.168.50.20");
	const sockaddr_in calleeAddr = addrFor("192.168.50.21");
	handler.handle(makeRegister("401", "192.168.50.20", "reg-401"));
	handler.handle(makeRegister("402", "192.168.50.21", "reg-402"));
	handler.handle(makeInvite("401", "402", "192.168.50.20", "cb-5", "z9hG4bKcb5"));
	handler.handle(makeCancel("401", "402", "192.168.50.20", "cb-5", "z9hG4bKcb5"));

	auto session = handler.getSession("Call-ID: cb-5");
	ASSERT_TRUE(session.has_value());
	session.value()->armRingTimer(TestClock::now() - std::chrono::seconds(1));
	handler.forceNextTickForTest();
	handler.tick();
	ASSERT_FALSE(handler.getSession("Call-ID: cb-5").has_value()) << "reaped at 32 s";

	sent.clear();
	handler.handle(makeFinal(487, "401", "402", "192.168.50.20", "192.168.50.21",
		"cb-5", "z9hG4bKcb5"));
	handler.handle(makeCancel("401", "402", "192.168.50.20", "cb-5", "z9hG4bKcb5"));
	handler.forceNextTickForTest();
	handler.tick();
	EXPECT_EQ(countSentTo(sent, callerAddr, "SIP/2.0 487"), 0)
		<< "no second 487 reaches the caller after the reap";
	EXPECT_EQ(countSentTo(sent, callerAddr, "BYE "), 0);
	EXPECT_EQ(countSentTo(sent, calleeAddr, "BYE "), 0)
		<< "no BYE or drop follows a reaped call";
	EXPECT_FALSE(handler.getSession("Call-ID: cb-5").has_value());
}

// Guard, green on main and after the fix: the callee's 487 ends the call through the
// relay, and the bounded wait afterwards sends nothing more and leaves nothing behind.
TEST(FinalFailureRelay, TheCalleesRequestTerminatedEndsACancelledCallWithNoSecond487)
{
	SentList sent;
	RequestsHandler handler("192.168.50.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});
	const sockaddr_in callerAddr = addrFor("192.168.50.20");
	handler.handle(makeRegister("401", "192.168.50.20", "reg-401"));
	handler.handle(makeRegister("402", "192.168.50.21", "reg-402"));
	handler.handle(makeInvite("401", "402", "192.168.50.20", "cb-4", "z9hG4bKcb4"));
	handler.handle(makeCancel("401", "402", "192.168.50.20", "cb-4", "z9hG4bKcb4"));

	sent.clear();
	handler.handle(makeFinal(487, "401", "402", "192.168.50.20", "192.168.50.21",
		"cb-4", "z9hG4bKcb4"));
	EXPECT_EQ(countSentTo(sent, callerAddr, "SIP/2.0 487"), 1)
		<< "the callee's 487 is relayed to the caller once";

	auto session = handler.getSession("Call-ID: cb-4");
	ASSERT_TRUE(session.has_value()) << "the relayed 487 waits for the caller's ACK";
	session.value()->armRingTimer(TestClock::now() - std::chrono::seconds(1));
	sent.clear();
	handler.forceNextTickForTest();
	handler.tick();
	EXPECT_EQ(countSentTo(sent, callerAddr, "SIP/2.0 487"), 0)
		<< "no second 487 after the callee's own was relayed";

	sent.clear();
	handler.handle(makeAck("401", "402", "192.168.50.20", "cb-4", "z9hG4bKcb4"));
	EXPECT_FALSE(handler.getSession("Call-ID: cb-4").has_value())
		<< "the caller's ACK ends the call and leaves nothing behind";
	handler.forceNextTickForTest();
	handler.tick();
	EXPECT_EQ(countSentTo(sent, callerAddr, "SIP/2.0 487"), 0);
}

// RED on main, by the same deadline check: the 200 that crosses the CANCEL is relayed,
// the session stays in Cancel, and no ring deadline may fire after it (a 487 would follow a 200).
TEST(FinalFailureRelay, A2xxThatCrossesTheCancelDisarmsTheBoundedWait)
{
	SentList sent;
	RequestsHandler handler("192.168.50.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});
	const sockaddr_in callerAddr = addrFor("192.168.50.20");
	handler.handle(makeRegister("401", "192.168.50.20", "reg-401"));
	handler.handle(makeRegister("402", "192.168.50.21", "reg-402"));
	handler.handle(makeInvite("401", "402", "192.168.50.20", "cb-5", "z9hG4bKcb5"));
	handler.handle(makeCancel("401", "402", "192.168.50.20", "cb-5", "z9hG4bKcb5"));

	sent.clear();
	handler.handle(makeOk("401", "402", "192.168.50.20", "192.168.50.21", "cb-5", "z9hG4bKcb5"));
	EXPECT_EQ(countSentTo(sent, callerAddr, "SIP/2.0 200"), 1)
		<< "the 200 that crossed the CANCEL is relayed to the caller";

	auto session = handler.getSession("Call-ID: cb-5");
	ASSERT_TRUE(session.has_value());
	EXPECT_FALSE(session.value()->isRingExpired(TestClock::now() + std::chrono::hours(1)))
		<< "no ring deadline may fire after the 200: a 487 must never follow it";

	sent.clear();
	handler.forceNextTickForTest();
	handler.tick();
	EXPECT_EQ(countSentTo(sent, callerAddr, "SIP/2.0 487"), 0)
		<< "the caller must not be sent a 487 after its 200";
}

// #1057 (RFC 3261 s9.2): the PBX is the UAS of the caller's CANCEL and answers it with its own 200 at
// once, whether or not the callee ever answers. Before the fix the CANCEL was only relayed, so a
// callee that sent 180 and then nothing left the caller's CANCEL transaction to time out.
// RED on main: no "SIP/2.0 200" with CSeq CANCEL reaches the caller after the CANCEL.
TEST(FinalFailureRelay, TheCallersCancelGetsTheProxysOwn200EvenWhenTheCalleeStaysSilent)
{
	SentList sent;
	RequestsHandler handler("192.168.50.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});
	const sockaddr_in callerAddr = addrFor("192.168.50.20");
	const sockaddr_in calleeAddr = addrFor("192.168.50.21");
	handler.handle(makeRegister("401", "192.168.50.20", "reg-401"));
	handler.handle(makeRegister("402", "192.168.50.21", "reg-402"));
	handler.handle(makeInvite("401", "402", "192.168.50.20", "cb-7", "z9hG4bKcb7"));

	sent.clear();
	handler.handle(makeCancel("401", "402", "192.168.50.20", "cb-7", "z9hG4bKcb7"));
	const std::string own200 = findSentTo(sent, callerAddr, "SIP/2.0 200");
	EXPECT_FALSE(own200.empty()) << "the PBX answers the caller's CANCEL with a 200 in the same tick";
	EXPECT_NE(own200.find("CSeq: 1 CANCEL"), std::string::npos) << "that 200 names the CANCEL transaction";
	EXPECT_NE(own200.find(";tag="), std::string::npos) << "a 2xx carries a To tag (RFC 3261 s8.2.6.2)";
	EXPECT_EQ(countSentTo(sent, callerAddr, "SIP/2.0 200"), 1) << "exactly one 200";
	EXPECT_EQ(countSentTo(sent, calleeAddr, "CANCEL "), 1) << "the CANCEL is still relayed to the callee";

	// The callee's own 200 to the relayed CANCEL is absorbed: relayed, the caller would get two.
	sent.clear();
	handler.handle(makeCancelOk("401", "402", "192.168.50.20", "192.168.50.21", "cb-7", "z9hG4bKcb7"));
	EXPECT_EQ(countSentTo(sent, callerAddr, "SIP/2.0 200"), 0)
		<< "the callee's 200 to the CANCEL is not relayed after the PBX answered it";
	auto session = handler.getSession("Call-ID: cb-7");
	ASSERT_TRUE(session.has_value());
	EXPECT_TRUE(session.value()->isRingExpired(TestClock::now() + std::chrono::seconds(33)))
		<< "the #1049 bound is still armed";
}

// Rule 5: an emergency caller's CANCEL gets the same 200, and the bound stays off it.
TEST(FinalFailureRelay, AnEmergencyCallersCancelGetsTheSame200)
{
	SentList sent;
	RequestsHandler handler("192.168.50.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});
	const sockaddr_in callerAddr = addrFor("192.168.50.22");
	handler.handle(makeRegister("403", "192.168.50.22", "reg-403"));
	handler.handle(makeRegister("404", "192.168.50.23", "reg-404"));
	handler.handle(makeInvite("403", "404", "192.168.50.22", "cb-8", "z9hG4bKcb8"));
	auto session = handler.getSession("Call-ID: cb-8");
	ASSERT_TRUE(session.has_value());
	session.value()->setEmergency(true);

	sent.clear();
	handler.handle(makeCancel("403", "404", "192.168.50.22", "cb-8", "z9hG4bKcb8"));
	const std::string own200 = findSentTo(sent, callerAddr, "SIP/2.0 200");
	EXPECT_FALSE(own200.empty()) << "an emergency caller's CANCEL is answered with a 200";
	EXPECT_NE(own200.find("CSeq: 1 CANCEL"), std::string::npos);
	EXPECT_EQ(countSentTo(sent, callerAddr, "SIP/2.0 200"), 1);
}
