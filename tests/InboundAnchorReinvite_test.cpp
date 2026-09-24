// InboundAnchorReinvite_test.cpp: issue #445.
//
// On an INBOUND anchored call (PSTN -> handset) the session's src is the
// synthetic PSTN peer allocated with a ZEROED address, and dest is the handset.
// onReinvite()/onUpdate() matched the anchored leg only by `destNum == 555`,
// which is true for an OUTBOUND anchor call alone. So a handset's hold
// re-INVITE or SDP UPDATE on an inbound call fell through to the relay path and
// was forwarded to 0.0.0.0: nobody answered it, and the handset's hold failed.
//
// The board is the handset's UAS on this leg, exactly as on an outbound 555
// leg, so the request must be ANSWERED by answerAnchorReinvite(). And that
// answer is a 2xx to a target-refresh request, so it must carry the PBX's own
// Contact -- the one the handset was offered at setup -- not the handset's
// (the #425 rule). answerAnchorReinvite() used to clone the request's Contact.
//
// Done-criteria (Sonny-OG): exactly one answer to the handset, and zero
// datagrams to the zeroed PSTN peer, for both a re-INVITE and an SDP UPDATE.

#include <gtest/gtest.h>

#include <string>
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

	const char* const kPbxIp = "192.168.40.1";
	const char* const kHandsetIp = "192.168.40.20";

	sockaddr_in addrFor(const std::string& ip, uint16_t port = 5060)
	{
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_addr.s_addr = inet_addr(ip.c_str());
		a.sin_port = htons(port);
		return a;
	}

	std::string pbxContactFor(const std::string& ext)
	{
		return "Contact: <sip:" + ext + "@" + kPbxIp + ":5060;transport=UDP>";
	}

	std::string sdpBody(const char* direction)
	{
		return std::string(
			"v=0\r\n"
			"o=- 0 0 IN IP4 10.0.0.20\r\n"
			"s=-\r\n"
			"c=IN IP4 10.0.0.20\r\n"
			"t=0 0\r\n"
			"m=audio 10000 RTP/AVP 0\r\n"
			"a=rtpmap:0 PCMU/8000\r\n") + "a=" + direction + "\r\n";
	}

	std::string findSentTo(const Sent& sent, const sockaddr_in& addr, const std::string& needle)
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

	// Responses (status line "SIP/2.0 ...") sent to `addr` for the given CSeq.
	size_t responsesTo(const Sent& sent, const sockaddr_in& addr, const std::string& cseq)
	{
		size_t n = 0;
		for (const auto& [a, msg] : sent)
		{
			if (a.sin_addr.s_addr != addr.sin_addr.s_addr || a.sin_port != addr.sin_port || !msg) continue;
			const std::string raw = msg->toString();
			if (raw.compare(0, 8, "SIP/2.0 ") == 0 && raw.find(cseq) != std::string::npos) ++n;
		}
		return n;
	}

	size_t toZeroedPeer(const Sent& sent, const std::string& cseq)
	{
		size_t n = 0;
		for (const auto& [a, msg] : sent)
		{
			if (a.sin_addr.s_addr == 0 && msg && msg->toString().find(cseq) != std::string::npos) ++n;
		}
		return n;
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

	// Routes an inbound anchored call to handset 106 and has 106 answer it.
	// Returns the Call-ID line. Asserts (via gtest) the preconditions that make
	// the verdict meaningful: Connected, dest == handset, and a media bridge
	// behind the Call-ID -- without a bridge, answerAnchorReinvite() answers 481,
	// and a test that only looked for "an answer" could pass on that.
	std::string answeredInboundCall(RequestsHandler& handler, Sent& sent)
	{
		handler.handle(makeRegister("106", kHandsetIp));
		const std::string callIdLine =
			handler.routeInboundAnchorCallForTest("106", "part-445", "5551234567");
		EXPECT_FALSE(callIdLine.empty()) << "precondition: an inbound anchored session exists";

		handler.tick();   // drainOutbox() merges _asyncOutbox, where the fork INVITE waits
		const std::string fork = findSentTo(sent, addrFor(kHandsetIp), "INVITE sip:106@");
		EXPECT_FALSE(fork.empty()) << "precondition: the call is forked to the handset";

		std::string body = sdpBody("sendrecv");
		std::string ok =
			"SIP/2.0 200 OK\r\n" +
			headerLine(fork, "Via:") + "\r\n" +
			headerLine(fork, "From:") + "\r\n"
			"To: <sip:106@" + std::string(kPbxIp) + ">;tag=hs106\r\n" +
			callIdLine + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Contact: <sip:106@" + std::string(kHandsetIp) + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(ok, addrFor(kHandsetIp)));

		auto sess = handler.getSession(callIdLine);
		EXPECT_TRUE(sess.has_value());
		if (sess.has_value())
		{
			EXPECT_EQ(sess.value()->getState(), Session::State::Connected) << "precondition: answered";
			EXPECT_TRUE(sess.value()->getDest() && sess.value()->getDest()->getNumber() == "106")
				<< "precondition: dest is the handset";
		}
		EXPECT_NE(handler.anchorBridgeForCallIdForTest(callIdLine), nullptr)
			<< "precondition: a media bridge backs the inbound call";
		return callIdLine;
	}

	// An in-dialog request from the handset: re-INVITE or UPDATE, with an offer.
	std::shared_ptr<SipMessage> handsetOffer(const std::string& method, const std::string& callIdLine,
	                                         const char* direction)
	{
		std::string body = sdpBody(direction);
		std::string raw =
			method + " sip:106@" + std::string(kPbxIp) + ":5060 SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(kHandsetIp) + ":5060;branch=z9hG4bK445" + method + "\r\n"
			"From: <sip:106@" + std::string(kPbxIp) + ">;tag=hs106\r\n"
			"To: <sip:106@" + std::string(kPbxIp) + ":5060>;tag=pbxtag\r\n" +
			callIdLine + "\r\n"
			"CSeq: 2 " + method + "\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:106@" + std::string(kHandsetIp) + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(kHandsetIp));
	}

	void expectAnsweredByTheBoard(RequestsHandler& handler, const Sent& sent, const std::string& callIdLine,
	                              const std::string& cseq)
	{
		EXPECT_EQ(toZeroedPeer(sent, cseq), 0u)
			<< "#445: the request must never be relayed to the PSTN peer's zeroed address";
		EXPECT_EQ(responsesTo(sent, addrFor(kHandsetIp), cseq), 1u)
			<< "#445: exactly one answer to the handset";
		const std::string ans = findSentTo(sent, addrFor(kHandsetIp), cseq);
		ASSERT_FALSE(ans.empty());
		EXPECT_EQ(ans.compare(0, 15, "SIP/2.0 200 OK\r"), 0) << "the board is the UAS: it answers 200";
		EXPECT_NE(ans.find("application/sdp"), std::string::npos) << "the answer carries the board's SDP";
		EXPECT_EQ(headerLine(ans, "Contact:"), pbxContactFor("106"))
			<< "#425 rule: a 2xx to a target refresh carries the Contact the handset was offered";
		auto sess = handler.getSession(callIdLine);
		ASSERT_TRUE(sess.has_value());
		EXPECT_EQ(sess.value()->getState(), Session::State::Held) << "a sendonly offer puts the call on hold";
	}
}

TEST(InboundAnchorReinvite, HandsetHoldReinviteOnAnInboundAnchoredCallIsAnsweredNotSentToThePstnPeer)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	const std::string callIdLine = answeredInboundCall(handler, sent);

	handler.handle(handsetOffer("INVITE", callIdLine, "sendonly"));
	expectAnsweredByTheBoard(handler, sent, callIdLine, "CSeq: 2 INVITE");
}

TEST(InboundAnchorReinvite, HandsetSdpUpdateOnAnInboundAnchoredCallIsAnsweredNotSentToThePstnPeer)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	const std::string callIdLine = answeredInboundCall(handler, sent);

	handler.handle(handsetOffer("UPDATE", callIdLine, "sendonly"));
	expectAnsweredByTheBoard(handler, sent, callIdLine, "CSeq: 2 UPDATE");
}
