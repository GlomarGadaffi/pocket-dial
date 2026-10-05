// GroupInDialog_test.cpp — Issue #802: a ring-group / page-zone / dial-rule-alias
// call is answered with To = the dialled number (the group), so the caller's
// in-dialog ACK, BYE and CANCEL carry a To that no phone owns. They used to be
// dispatched on that To literal ("999" only for ACK; "999" or a real 98x zone for
// BYE/CANCEL) and everything else fell to findClient("600") -> 404, leaving the
// answering member without its ACK, its BYE, or its CANCEL. Driven end to end
// through RequestsHandler::handle(), the style FinalFailureRelay_test.cpp uses.

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

	const std::string kCallerIp = "192.168.50.20";
	const std::string kMemberIp = "192.168.50.21";
	const std::string kOtherIp  = "192.168.50.22";

	sockaddr_in addrFor(const std::string& ip)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(5060);
		return s;
	}

	// `contactParams` lets a member register the way a Snom does (";line=...").
	std::shared_ptr<SipMessage> makeRegister(const std::string& ext, const std::string& srcIp,
		const std::string& contactParams = "")
	{
		const std::string callId = "reg-" + ext;
		std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bKr" + callId + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + callId + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + srcIp + ":5060" + contactParams + ">;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}

	std::string sdp(const std::string& ip, int port)
	{
		return "v=0\r\n"
			"o=- 0 0 IN IP4 " + ip + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + ip + "\r\n"
			"t=0 0\r\n"
			"m=audio " + std::to_string(port) + " RTP/AVP 0\r\n"
			"a=rtpmap:0 PCMU/8000\r\n";
	}

	std::shared_ptr<SipMessage> makeInvite(const std::string& toExt, const std::string& callId)
	{
		const std::string body = sdp(kCallerIp, 10000);
		std::string raw =
			"INVITE sip:" + toExt + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + kCallerIp + ":5060;branch=z9hG4bK" + callId + "\r\n"
			"From: <sip:100@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:100@" + kCallerIp + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(kCallerIp));
	}

	// The member's 200 OK: its own To-tag, Contact and SDP answer.
	std::shared_ptr<SipMessage> makeMemberOk(const std::string& member, const std::string& memberIp,
		const std::string& callId)
	{
		const std::string body = sdp(memberIp, 20000);
		std::string raw =
			"SIP/2.0 200 OK\r\n"
			"Via: SIP/2.0/UDP " + kCallerIp + ":5060;branch=z9hG4bK" + callId + "\r\n"
			"From: <sip:100@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + member + "@server>;tag=bt" + callId + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Contact: <sip:" + member + "@" + memberIp + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(memberIp));
	}

	// The caller's in-dialog request to the dialled number: To = the group.
	std::shared_ptr<SipMessage> makeCallerRequest(const std::string& method, const std::string& toExt,
		const std::string& callId, int cseq, bool toTag = true)
	{
		std::string raw =
			method + " sip:" + toExt + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + kCallerIp + ":5060;branch=z9hG4bKx" + method + callId + "\r\n"
			"From: <sip:100@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>" + (toTag ? ";tag=bt" + callId : std::string()) + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: " + std::to_string(cseq) + " " + method + "\r\n"
			"Max-Forwards: 70\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(kCallerIp));
	}

	// The CANCEL carries the INVITE's branch and CSeq number (RFC 3261 §9.1).
	std::shared_ptr<SipMessage> makeCancel(const std::string& toExt, const std::string& callId)
	{
		std::string raw =
			"CANCEL sip:" + toExt + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + kCallerIp + ":5060;branch=z9hG4bK" + callId + "\r\n"
			"From: <sip:100@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 CANCEL\r\n"
			"Max-Forwards: 70\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(kCallerIp));
	}

	// The answering member hangs up: From = member, To = the caller.
	std::shared_ptr<SipMessage> makeMemberBye(const std::string& member, const std::string& memberIp,
		const std::string& callId)
	{
		std::string raw =
			"BYE sip:100@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + memberIp + ":5060;branch=z9hG4bKmb" + callId + "\r\n"
			"From: <sip:" + member + "@server>;tag=bt" + callId + "\r\n"
			"To: <sip:100@server>;tag=ft" + callId + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 BYE\r\n"
			"Max-Forwards: 70\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(memberIp));
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

	struct Fixture
	{
		SentList sent;
		RequestsHandler handler;

		Fixture()
			: handler("192.168.50.1", 5060,
				[this](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
					sent.emplace_back(addr, std::move(msg));
				})
		{
			handler.handle(makeRegister("100", kCallerIp));
			// 101 registers the way a Snom does: the ;line= is part of its Contact.
			handler.handle(makeRegister("101", kMemberIp, ";line=h2k6k1ih"));
			handler.handle(makeRegister("102", kOtherIp));
		}

		// Dial `dialled`, have 101 answer, and leave the call Connected.
		void answeredCall(const std::string& dialled, const std::string& callId)
		{
			handler.handle(makeInvite(dialled, callId));
			handler.handle(makeMemberOk("101", kMemberIp, callId));
			sent.clear();
		}
	};
}

TEST(GroupInDialog, RingGroupCallersAckReachesTheAnsweringMember)
{
	Fixture f;
	f.handler.setRingGroup("600", "101,102", "ringall");
	f.answeredCall("600", "gid-1");
	ASSERT_TRUE(f.handler.getSession("Call-ID: gid-1").has_value()) << "precondition: the call is up";

	f.handler.handle(makeCallerRequest("ACK", "600", "gid-1", 1));

	const std::string ack = findSentTo(f.sent, addrFor(kMemberIp), "ACK sip:101@");
	ASSERT_FALSE(ack.empty()) << "the member's 200 must be ACKed, or it retransmits until Timer H";
	EXPECT_NE(ack.find("ACK sip:101@192.168.50.21:5060;line=h2k6k1ih SIP/2.0"), std::string::npos)
		<< "the Request-URI is the member's registered Contact, ;line= included (RFC 3261 §12.2.1.1)";
	EXPECT_TRUE(findSentTo(f.sent, addrFor(kCallerIp), "404").empty());
}

TEST(GroupInDialog, RingGroupCallersByeReachesTheMemberAndEndsTheSession)
{
	Fixture f;
	f.handler.setRingGroup("600", "101,102", "ringall");
	f.answeredCall("600", "gid-2");

	f.handler.handle(makeCallerRequest("BYE", "600", "gid-2", 2));

	EXPECT_FALSE(findSentTo(f.sent, addrFor(kCallerIp), "SIP/2.0 200 OK").empty())
		<< "the caller's BYE must be answered 200";
	EXPECT_TRUE(findSentTo(f.sent, addrFor(kCallerIp), "404").empty());
	const std::string bye = findSentTo(f.sent, addrFor(kMemberIp), "BYE sip:101@");
	ASSERT_FALSE(bye.empty()) << "the member must be told the caller hung up";
	EXPECT_NE(bye.find("BYE sip:101@192.168.50.21:5060;line=h2k6k1ih SIP/2.0"), std::string::npos);
	EXPECT_FALSE(f.handler.getSession("Call-ID: gid-2").has_value()) << "and the session must be freed";
}

// The other direction must keep working: the ANSWERING MEMBER's BYE has To = the
// caller, and goes to the caller -- never back to the member.
TEST(GroupInDialog, RingGroupMembersByeStillGoesToTheCaller)
{
	Fixture f;
	f.handler.setRingGroup("600", "101,102", "ringall");
	f.answeredCall("600", "gid-3");

	f.handler.handle(makeMemberBye("101", kMemberIp, "gid-3"));

	EXPECT_FALSE(findSentTo(f.sent, addrFor(kCallerIp), "BYE sip:100@").empty())
		<< "the caller must be told the member hung up";
	EXPECT_TRUE(findSentTo(f.sent, addrFor(kMemberIp), "BYE sip:").empty())
		<< "the member's own BYE must not be echoed back at it";
}

TEST(GroupInDialog, RingGroupCancelWhileRingingReachesEveryRingingMember)
{
	Fixture f;
	f.handler.setRingGroup("600", "101,102", "ringall");
	f.handler.handle(makeInvite("600", "gid-4"));
	ASSERT_TRUE(f.handler.getSession("Call-ID: gid-4").has_value());
	f.sent.clear();

	f.handler.handle(makeCancel("600", "gid-4"));

	EXPECT_FALSE(findSentTo(f.sent, addrFor(kMemberIp), "CANCEL sip:101@").empty())
		<< "101 must stop ringing";
	EXPECT_FALSE(findSentTo(f.sent, addrFor(kOtherIp), "CANCEL sip:102@").empty())
		<< "102 must stop ringing";
	EXPECT_TRUE(findSentTo(f.sent, addrFor(kCallerIp), "404").empty());
	EXPECT_FALSE(f.handler.getSession("Call-ID: gid-4").has_value());
}

// A real zone (981): BYE and CANCEL already worked on the To literal; its ACK did not.
TEST(GroupInDialog, PageZoneCallersAckReachesTheAnsweringMember)
{
	Fixture f;
	f.handler.setPageZone("981", "101,102");
	f.answeredCall("981", "gid-5");

	f.handler.handle(makeCallerRequest("ACK", "981", "gid-5", 1));

	EXPECT_FALSE(findSentTo(f.sent, addrFor(kMemberIp), "ACK sip:101@").empty())
		<< "the zone member's 200 must be ACKed";
}

// A dial rule aliases "55" to zone 981 and "66" to group 600; the To the caller
// dialled matches neither a zone nor "999".
TEST(GroupInDialog, ADialRuleAliasBehavesLikeItsTarget)
{
	Fixture f;
	f.handler.setRingGroup("600", "101,102", "ringall");
	f.handler.setPageZone("981", "101,102");
	f.handler.setDialRule("55", "page", "981");
	f.handler.setDialRule("66", "group", "600");

	f.handler.handle(makeInvite("66", "gid-6"));
	f.handler.handle(makeCancel("66", "gid-6"));
	EXPECT_FALSE(findSentTo(f.sent, addrFor(kOtherIp), "CANCEL sip:102@").empty())
		<< "a CANCEL of an aliased group call must reach the ringing members";
	EXPECT_FALSE(f.handler.getSession("Call-ID: gid-6").has_value());

	f.handler.handle(makeInvite("55", "gid-7"));
	f.handler.handle(makeMemberOk("101", kMemberIp, "gid-7"));
	f.sent.clear();
	f.handler.handle(makeCallerRequest("ACK", "55", "gid-7", 1));
	EXPECT_FALSE(findSentTo(f.sent, addrFor(kMemberIp), "ACK sip:101@").empty())
		<< "an aliased zone call's ACK must reach the member";
	f.sent.clear();
	f.handler.handle(makeCallerRequest("BYE", "55", "gid-7", 2));
	EXPECT_FALSE(findSentTo(f.sent, addrFor(kMemberIp), "BYE sip:101@").empty())
		<< "an aliased zone call's BYE must reach the member";
	EXPECT_FALSE(f.handler.getSession("Call-ID: gid-7").has_value());
}
