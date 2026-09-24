// NoReplyToResponse_test.cpp: issue #424.
//
// A response is never answered (RFC 3261 §17.1) and neither is an ACK
// (§17.2.1). The PBX did both, through endHandle()'s not-found branch, which
// clones WHATEVER it is given, stamps 404 on it and sends it back:
//   (a) the register beep: the phone's 100 Trying to the beep INVITE reached
//       endHandle(From-user = the server's own "pbx", not a client) and drew a
//       404, which drainOutbox() then tracked as an authored final response and
//       re-sent on Timer G for 32 s;
//   (b) park retrieve: the retriever's ACK to its 200 reached endHandle(To-user
//       = the orbit, not a client) and drew "404/ACK".
// The fix is structural (drainOutbox() refuses any reply to a response or an
// ACK, and counts it), so each test asserts ZERO replies, the refusal count,
// AND that the leg still reaches its correct end state: absence of the reply
// alone would also pass if the message never reached the handler at all.

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "RequestsHandler.hpp"
#include "SipMessage.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	struct Sent
	{
		sockaddr_in to;
		std::string raw;
	};

	sockaddr_in addrFor(const std::string& ip)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(5060);
		return s;
	}

	bool sameAddr(const sockaddr_in& a, const sockaddr_in& b)
	{
		return a.sin_addr.s_addr == b.sin_addr.s_addr && a.sin_port == b.sin_port;
	}

	std::string headerLine(const std::string& raw, const std::string& name)
	{
		size_t pos = 0;
		while (pos < raw.size())
		{
			size_t eol = raw.find("\r\n", pos);
			if (eol == std::string::npos) eol = raw.size();
			std::string line = raw.substr(pos, eol - pos);
			if (line.size() > name.size() && line.compare(0, name.size(), name) == 0) return line;
			pos = eol + 2;
		}
		return {};
	}

	// Responses sent to `to` in the transaction identified by Call-ID + CSeq.
	size_t repliesTo(const std::vector<Sent>& sent, const sockaddr_in& to,
		const std::string& callIdLine, const std::string& cseqLine)
	{
		size_t n = 0;
		for (const auto& s : sent)
		{
			if (!sameAddr(s.to, to) || s.raw.rfind("SIP/2.0 ", 0) != 0) continue;
			if (headerLine(s.raw, "Call-ID:") == callIdLine && headerLine(s.raw, "CSeq:") == cseqLine) ++n;
		}
		return n;
	}

	size_t requestsTo(const std::vector<Sent>& sent, const sockaddr_in& to, const std::string& method,
		const std::string& callIdLine)
	{
		size_t n = 0;
		for (const auto& s : sent)
		{
			if (sameAddr(s.to, to) && s.raw.rfind(method + " ", 0) == 0 &&
				headerLine(s.raw, "Call-ID:") == callIdLine) ++n;
		}
		return n;
	}

	std::shared_ptr<SipMessage> makeRegister(const std::string& ext, const std::string& ip)
	{
		std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKreg" + ext + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + ext + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: reg-" + ext + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + ip + ":5060>;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}

	std::string sdpBody(const std::string& ip)
	{
		return
			"v=0\r\n"
			"o=- 1 1 IN IP4 " + ip + "\r\n"
			"s=call\r\n"
			"c=IN IP4 " + ip + "\r\n"
			"t=0 0\r\n"
			"m=audio 4000 RTP/AVP 0\r\n";
	}

	std::shared_ptr<SipMessage> makeInvite(const std::string& fromExt, const std::string& toExt,
		const std::string& ip, const std::string& callId)
	{
		const std::string body = sdpBody(ip);
		std::string raw =
			"INVITE sip:" + toExt + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bK" + callId + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=from" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Contact: <sip:" + fromExt + "@" + ip + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}

	// The phone's answer to a PBX-originated INVITE: Via/From/Call-ID/CSeq
	// copied from it, as a UAS must (RFC 3261 §8.2.6.2).
	std::shared_ptr<SipMessage> answerTo(const std::string& invite, const std::string& statusLine,
		const std::string& ext, const std::string& ip, bool withSdp)
	{
		const std::string body = withSdp ? sdpBody(ip) : std::string();
		std::string raw =
			statusLine + "\r\n" +
			headerLine(invite, "Via:") + "\r\n" +
			headerLine(invite, "From:") + "\r\n" +
			headerLine(invite, "To:") + ";tag=ph" + ext + "\r\n" +
			headerLine(invite, "Call-ID:") + "\r\n" +
			headerLine(invite, "CSeq:") + "\r\n"
			"Contact: <sip:" + ext + "@" + ip + ":5060>\r\n" +
			(withSdp ? "Content-Type: application/sdp\r\n" : "") +
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}

	RequestsHandler::OnHandledEvent recorder(std::vector<Sent>& sent)
	{
		return [&sent](const sockaddr_in& to, std::shared_ptr<SipMessage> msg) {
			sent.push_back({ to, msg->toString() });
		};
	}
}

// (a) The register beep's 100 Trying must not be answered, and the beep must
// still complete: the phone's 200 is ACKed and the leg is hung up with a BYE.
TEST(NoReplyToResponse, RegisterBeepTryingIsNeverAnsweredAndTheBeepStillCompletes)
{
	std::vector<Sent> sent;
	RequestsHandler handler("192.168.24.1", 5060, recorder(sent));
	const sockaddr_in phone = addrFor("192.168.24.10");

	handler.handle(makeRegister("200", "192.168.24.10"));
	std::string beep;
	for (const auto& s : sent)
		if (sameAddr(s.to, phone) && s.raw.rfind("INVITE sip:200@", 0) == 0) beep = s.raw;
	ASSERT_FALSE(beep.empty()) << "precondition: registering sends the beep INVITE";
	const std::string callId = headerLine(beep, "Call-ID:");
	const std::string cseq = headerLine(beep, "CSeq:");

	handler.handle(answerTo(beep, "SIP/2.0 100 Trying", "200", "192.168.24.10", false));
	EXPECT_EQ(repliesTo(sent, phone, callId, cseq), 0u) << "#424(a): the PBX answered the phone's 100 Trying";

	handler.handle(answerTo(beep, "SIP/2.0 200 OK", "200", "192.168.24.10", true));
	EXPECT_EQ(repliesTo(sent, phone, callId, cseq), 0u) << "#424(a): the PBX answered the phone's 200 OK";

	// End state: the beep leg is ACKed and torn down, exactly once each.
	handler.tick();
	EXPECT_EQ(requestsTo(sent, phone, "ACK", callId), 1u) << "the beep's 200 is ACKed";
	EXPECT_EQ(requestsTo(sent, phone, "BYE", callId), 1u) << "the beep leg is hung up";

	// A 32 s retransmit burst is what a tracked stray 404 cost; with nothing
	// refused into the tracker, nothing more reaches the phone later.
	EXPECT_EQ(handler.getRepliesRefused(), 1u) << "the guard, not luck, dropped the reply to the 100";
}

// (b) The retriever's ACK on a park-retrieve dialog must not be answered, and
// the retrieved call must stay up.
TEST(NoReplyToResponse, ParkRetrieveAckIsNeverAnsweredAndTheCallStaysUp)
{
	std::vector<Sent> sent;
	RequestsHandler handler("192.168.24.1", 5060, recorder(sent));
	const sockaddr_in retriever = addrFor("192.168.24.51");

	handler.handle(makeRegister("100", "192.168.24.50"));
	handler.handle(makeRegister("101", "192.168.24.51"));
	handler.handle(makeInvite("100", "700", "192.168.24.50", "park-424"));
	handler.handle(makeInvite("101", "700", "192.168.24.51", "retrieve-424"));

	auto session = handler.getSession("Call-ID: retrieve-424");
	ASSERT_TRUE(session.has_value()) << "precondition: the retrieve dialog exists";
	ASSERT_FALSE(session.value()->getPeerCallID().empty()) << "precondition: bridged to the parked leg";
	std::string ok;
	for (const auto& s : sent)
		if (sameAddr(s.to, retriever) && s.raw.rfind("SIP/2.0 200 OK", 0) == 0 &&
			headerLine(s.raw, "Call-ID:") == "Call-ID: retrieve-424") ok = s.raw;
	ASSERT_FALSE(ok.empty()) << "precondition: the retrieve INVITE was answered 200";

	const auto stateBefore = session.value()->getState();
	const auto refusedBefore = handler.getRepliesRefused();
	std::string ack =
		"ACK sip:700@192.168.24.1:5060 SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.24.51:5060;branch=z9hG4bKack424\r\n" +
		headerLine(ok, "From:") + "\r\n" +
		headerLine(ok, "To:") + "\r\n"
		"Call-ID: retrieve-424\r\n"
		"CSeq: 1 ACK\r\n"
		"Content-Length: 0\r\n\r\n";
	handler.handle(RequestsHandler::getMessageFromPool(ack, retriever));

	EXPECT_EQ(repliesTo(sent, retriever, "Call-ID: retrieve-424", "CSeq: 1 ACK"), 0u)
		<< "#424(b): the PBX answered an ACK";
	EXPECT_EQ(handler.getRepliesRefused(), refusedBefore + 1) << "the guard, not luck, dropped it";

	session = handler.getSession("Call-ID: retrieve-424");
	ASSERT_TRUE(session.has_value()) << "the ACK must not tear the retrieved call down";
	EXPECT_EQ(session.value()->getState(), stateBefore);
	EXPECT_TRUE(handler.getSession("Call-ID: park-424").has_value()) << "the parked leg stays up";
}
