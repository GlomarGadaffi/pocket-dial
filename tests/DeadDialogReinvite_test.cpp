// DeadDialogReinvite_test.cpp -- issue #379. An INVITE whose To carries a tag is
// an in-dialog request. If no live dialog matches its Call-ID, RFC 3261 §12.2.2
// says answer 481; it must never be treated as a new call. On .244 a late hold
// re-INVITE for a dead dialog placed a fresh anchored leg (to "555", presented
// as "pbx") that nothing ever dropped.

#include <gtest/gtest.h>

#include <memory>
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
	sockaddr_in addrFor(const std::string& ip)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(5060);
		return s;
	}

	std::shared_ptr<SipMessage> makeRegister()
	{
		const std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.37.51:5060;branch=z9hG4bKreg379\r\n"
			"From: <sip:501@server>;tag=reg379\r\n"
			"To: <sip:501@server>\r\n"
			"Call-ID: reg-379\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:501@192.168.37.51:5060>;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor("192.168.37.51"));
	}

	// An INVITE from 501 to 555 (the anchor), optionally carrying a To-tag.
	std::shared_ptr<SipMessage> makeInvite(const std::string& callId, const std::string& toTag)
	{
		const std::string body =
			"v=0\r\no=- 0 0 IN IP4 192.168.37.51\r\ns=-\r\nc=IN IP4 192.168.37.51\r\nt=0 0\r\n"
			"m=audio 10000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
		const std::string raw =
			"INVITE sip:555@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.37.51:5060;branch=z9hG4bK" + callId + "\r\n"
			"From: <sip:501@server>;tag=f" + callId + "\r\n"
			"To: <sip:555@server>" + (toTag.empty() ? std::string() : ";tag=" + toTag) + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 2 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:501@192.168.37.51:5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor("192.168.37.51"));
	}

	struct Bench
	{
		std::vector<std::string> sent;
		RequestsHandler handler{"192.168.37.1", 5060,
			[this](const sockaddr_in&, std::shared_ptr<SipMessage> m) { sent.push_back(m->toString()); }};
		Bench() { handler.handle(makeRegister()); sent.clear(); }

		size_t count(const std::string& startLine) const
		{
			size_t n = 0;
			for (const auto& s : sent) if (s.rfind(startLine, 0) == 0) ++n;
			return n;
		}
	};
}

TEST(DeadDialogReinvite, AReinviteForAnUnknownDialogIsAnswered481NotANewCall)
{
	Bench b;
	b.handler.handle(makeInvite("dead-379", "gone379"));

	EXPECT_EQ(b.count("SIP/2.0 481"), 1u) << "an in-dialog INVITE for a dead dialog gets 481";
	EXPECT_EQ(b.count("SIP/2.0 200"), 0u) << "no anchored call may be placed for it";
	EXPECT_FALSE(b.handler.getSession("Call-ID: dead-379").has_value())
		<< "and no session is created";
}

TEST(DeadDialogReinvite, AFreshInviteWithoutAToTagStillStartsACall)
{
	// Positive control: the same INVITE without a To-tag is a new call.
	Bench b;
	b.handler.handle(makeInvite("new-379", ""));

	EXPECT_EQ(b.count("SIP/2.0 481"), 0u);
	EXPECT_EQ(b.count("SIP/2.0 200"), 1u) << "the loopback anchor answers a fresh 555 call";
	EXPECT_TRUE(b.handler.getSession("Call-ID: new-379").has_value());
}
