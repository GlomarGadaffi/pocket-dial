// CallForwardBusy_test.cpp — Issue #256: onBusy()'s CFB (call-forward-busy)
// lookup used to key off data->getFromNumber(), which for an ordinary
// proxied call's 486 (RFC 3261 mirrors the original INVITE's From/To) names
// the CALLER, not the busy callee -- so CFB configured on a normal extension
// could never be found. Driven end to end through RequestsHandler::handle(),
// the same style VoicemailDivert_test.cpp and AnchorRouting_test.cpp use.

#include <gtest/gtest.h>

#include <string>
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

	// A 486 echoes the ORIGINAL INVITE's From/To (RFC 3261): From is still the
	// caller, To is still the callee. This is the exact fact issue #256 is
	// about -- onBusy()'s CFB lookup must key off the To, not the From.
	std::shared_ptr<SipMessage> makeBusy(const std::string& fromExt, const std::string& toExt,
		const std::string& srcIp, const std::string& callId, const std::string& branch)
	{
		std::string raw =
			"SIP/2.0 486 Busy Here\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=" + branch + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>;tag=bt" + callId + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
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

// The core fix: CFB configured on the busy CALLEE must be found and used.
TEST(CallForwardBusy, RedirectsUsingCalleeIdentityNotCallerIdentity)
{
	SentList sent;
	RequestsHandler handler("192.168.50.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in callerAddr = addrFor("192.168.50.21");
	const sockaddr_in targetAddr = addrFor("192.168.50.23");

	handler.handle(makeRegister("401", "192.168.50.21", "reg-401"));
	handler.handle(makeRegister("402", "192.168.50.22", "reg-402"));
	handler.handle(makeRegister("403", "192.168.50.23", "reg-403"));
	handler.setForward("402", "busy", "403");   // CFB on the CALLEE, 402

	// Registration fires its own register-beep INVITE to each newly-registered
	// extension (including 403), which would otherwise collide with the
	// "INVITE sip:403@..." check below. Only the actual test call matters.
	sent.clear();

	const std::string callId = "cfb-1";
	const std::string branch = "z9hG4bKcfb1";
	handler.handle(makeInvite("401", "402", "192.168.50.21", callId, branch));
	handler.handle(makeBusy("401", "402", "192.168.50.22", callId, branch));

	EXPECT_TRUE(findSentTo(sent, callerAddr, "SIP/2.0 486").empty())
		<< "the caller must never see the bare 486 once the busy callee's CFB target resolves";

	std::string forkedInvite = findSentTo(sent, targetAddr, "INVITE sip:403@");
	EXPECT_FALSE(forkedInvite.empty())
		<< "CFB must fork a fresh INVITE to 403, the busy callee's configured forward target";
}

// The regression this issue is actually about: CFB configured on the CALLER
// must NOT be consulted just because the caller happens to have a "busy"
// forward of their own. Before #256, data->getFromNumber() named the caller
// on this leg, so the caller's own config would be found and used instead of
// the (absent) callee config -- misrouting a call that should have just
// failed plainly back to the caller.
TEST(CallForwardBusy, CallersOwnForwardConfigIsNeverConsulted)
{
	SentList sent;
	RequestsHandler handler("192.168.51.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in callerAddr = addrFor("192.168.51.21");
	const sockaddr_in wrongTargetAddr = addrFor("192.168.51.24");

	handler.handle(makeRegister("411", "192.168.51.21", "reg-411"));
	handler.handle(makeRegister("412", "192.168.51.22", "reg-412"));
	handler.handle(makeRegister("414", "192.168.51.24", "reg-414"));
	handler.setForward("411", "busy", "414");   // CFB on the CALLER, 411 -- must be ignored here

	// See the sibling test above: registration's own register-beep INVITE to
	// 414 would otherwise collide with the "no INVITE to 414" check below.
	sent.clear();

	const std::string callId = "cfb-2";
	const std::string branch = "z9hG4bKcfb2";
	handler.handle(makeInvite("411", "412", "192.168.51.21", callId, branch));
	handler.handle(makeBusy("411", "412", "192.168.51.22", callId, branch));

	EXPECT_FALSE(findSentTo(sent, callerAddr, "SIP/2.0 486").empty())
		<< "callee 412 has no CFB configured, so the caller must see the plain 486";
	EXPECT_TRUE(findSentTo(sent, wrongTargetAddr, "INVITE sip:414@").empty())
		<< "the caller's own forward-on-busy target must never be reached from this leg";
}
