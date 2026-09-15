// VoicemailDivert_test.cpp — Issue #246 (voicemail Stage 3 of #194), the SIP
// divert-hook slice: CFNA/CFB falling back to a locally-terminated voicemail
// leg when an extension has voicemail enabled but no explicit forward
// target. Driven end to end through RequestsHandler::handle()/tick(), the
// same style AnchorRouting_test.cpp and DtmfClassCodes_test.cpp use.

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
		const std::string& srcIp, const std::string& callId, const std::string& branch,
		int rtpPort = 10000)
	{
		std::string body =
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + srcIp + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + srcIp + "\r\n"
			"t=0 0\r\n"
			"m=audio " + std::to_string(rtpPort) + " RTP/AVP 0\r\n"
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

	std::shared_ptr<SipMessage> makeBusy(const std::string& fromExt, const std::string& toExt,
		const std::string& srcIp, const std::string& callId, const std::string& branch)
	{
		// A 486 response echoes the ORIGINAL request's From/To (RFC 3261): From
		// is still the caller, To is still the callee -- onBusy() reads
		// data->getFromNumber() for the busy party (see the caller's own note
		// in the review thread: don't re-derive this, just match what the
		// existing CFB path already reads).
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

	// `toValue` is the FULL captured "To:" header value from the 200 OK
	// (e.g. "<sip:303@server>;tag=d7iFV4UhN"), not just the tag -- it already
	// carries the URI, so the caller must not also prepend one.
	std::shared_ptr<SipMessage> makeBye(const std::string& fromExt, const std::string& toValue,
		const std::string& srcIp, const std::string& callId)
	{
		std::string raw =
			"BYE sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bKbye" + callId + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: " + toValue + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 2 BYE\r\n"
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

	std::string extractHeaderLine(const std::string& raw, const std::string& name)
	{
		size_t pos = 0;
		while (pos < raw.size())
		{
			size_t eol = raw.find("\r\n", pos);
			if (eol == std::string::npos) eol = raw.size();
			std::string line = raw.substr(pos, eol - pos);
			if (line.size() > name.size() && line.compare(0, name.size(), name) == 0)
			{
				return line;
			}
			pos = eol + 2;
		}
		return {};
	}
}

// CFNA fallback: no explicit no-answer forward, voicemail enabled. The
// still-ringing callee must be CANCELed (the forked-dialog hazard) BEFORE
// the caller gets a local 200 OK.
TEST(VoicemailDivert, CfnaFallsBackToVoicemailAndCancelsTheRingingCallee)
{
	SentList sent;
	RequestsHandler handler("192.168.40.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in calleeAddr = addrFor("192.168.40.10");  // 301
	const sockaddr_in callerAddr = addrFor("192.168.40.20");  // 302

	handler.handle(makeRegister("301", "192.168.40.10", "reg-301-a"));
	handler.handle(makeRegister("302", "192.168.40.20", "reg-302-a"));
	handler.setVoicemail("301", true);

	const std::string callId = "vm-cfna-1";
	const std::string branch = "z9hG4bKvmcfna1";
	handler.handle(makeInvite("302", "301", "192.168.40.20", callId, branch));

	// The callee is a real registered extension, so the INVITE is relayed
	// (proxied) to it untouched -- confirms the divert hook's premise before
	// forcing the timeout. Search by Call-ID, not just "INVITE sip:301@" --
	// the register-beep sends its OWN INVITE to 301 on registration
	// (RegisterBeeper.cpp) that would otherwise false-positive the same needle.
	ASSERT_FALSE(findSentTo(sent, calleeAddr, "Call-ID: " + callId).empty());

	ASSERT_TRUE(handler.getSession("Call-ID: " + callId).has_value());
	handler.getSession("Call-ID: " + callId).value()->armRingTimer(
		std::chrono::steady_clock::now() - std::chrono::seconds(1));
	handler.tick();

	std::string cancelToCallee = findSentTo(sent, calleeAddr, "CANCEL sip:");
	EXPECT_FALSE(cancelToCallee.empty())
		<< "the still-ringing callee must be CANCELed -- RFC 3261 S13.2.2.4 forked-dialog hazard";
	if (!cancelToCallee.empty())
	{
		EXPECT_NE(cancelToCallee.find("Call-ID: " + callId), std::string::npos) << cancelToCallee;
	}

	std::string okToCaller = findSentTo(sent, callerAddr, "SIP/2.0 200 OK");
	ASSERT_FALSE(okToCaller.empty()) << "the caller must be answered locally, not left hanging";
	EXPECT_NE(okToCaller.find("v=0"), std::string::npos) << "the 200 OK must carry an SDP answer";
	EXPECT_NE(extractHeaderLine(okToCaller, "To:").find("tag="), std::string::npos)
		<< "the 200 OK needs the board's own To-tag: " << okToCaller;
}

// #232 regression: a BYE against the locally-answered voicemail leg must
// actually be matched and torn down, not silently ignored the way 777/888
// legs were before setDialogHeaders() was added here.
TEST(VoicemailDivert, ByeAfterVoicemailAnswerIsHandledAndEndsTheCall)
{
	SentList sent;
	RequestsHandler handler("192.168.40.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in callerAddr = addrFor("192.168.40.21");

	handler.handle(makeRegister("303", "192.168.40.11", "reg-303-b"));
	handler.handle(makeRegister("304", "192.168.40.21", "reg-304-b"));
	handler.setVoicemail("303", true);

	const std::string callId = "vm-cfna-bye";
	handler.handle(makeInvite("304", "303", "192.168.40.21", callId, "z9hG4bKvmbye"));
	ASSERT_TRUE(handler.getSession("Call-ID: " + callId).has_value());
	handler.getSession("Call-ID: " + callId).value()->armRingTimer(
		std::chrono::steady_clock::now() - std::chrono::seconds(1));
	handler.tick();

	std::string okToCaller = findSentTo(sent, callerAddr, "SIP/2.0 200 OK");
	ASSERT_FALSE(okToCaller.empty());
	std::string toLine = extractHeaderLine(okToCaller, "To:");
	ASSERT_NE(toLine.find("tag="), std::string::npos) << toLine;

	ASSERT_TRUE(handler.getSession("Call-ID: " + callId).has_value())
		<< "the voicemail session must still be live, waiting for the caller to hang up";

	handler.handle(makeBye("304", toLine.substr(4), "192.168.40.21", callId));

	std::string okToBye = findSentTo(sent, callerAddr, "SIP/2.0 200 OK");
	EXPECT_NE(okToBye.find("CSeq: 2 BYE"), std::string::npos)
		<< "the BYE must be answered with its own 200 OK: " << okToBye;
	EXPECT_FALSE(handler.getSession("Call-ID: " + callId).has_value())
		<< "the session must be torn down once the depositor hangs up -- this is the #232 class "
		   "of bug (777/888 legs never matching a BYE) that setDialogHeaders() exists to avoid";
}

// Explicit forward wins over the voicemail fallback -- deciding this once at
// arm time (the sentinel), not re-derived at sweep time, is what makes this
// deterministic regardless of when the timer actually fires.
TEST(VoicemailDivert, ExplicitCfnaTargetWinsOverVoicemailFallback)
{
	SentList sent;
	RequestsHandler handler("192.168.40.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	handler.handle(makeRegister("305", "192.168.40.12", "reg-305-c"));
	handler.handle(makeRegister("306", "192.168.40.22", "reg-306-c"));
	handler.handle(makeRegister("307", "192.168.40.13", "reg-307-c"));
	handler.setVoicemail("305", true);
	handler.setForward("305", "noanswer", "307");

	const std::string callId = "vm-cfna-explicit";
	handler.handle(makeInvite("306", "305", "192.168.40.22", callId, "z9hG4bKvmexplicit"));
	ASSERT_TRUE(handler.getSession("Call-ID: " + callId).has_value());
	handler.getSession("Call-ID: " + callId).value()->armRingTimer(
		std::chrono::steady_clock::now() - std::chrono::seconds(1));
	handler.tick();

	EXPECT_FALSE(findSentTo(sent, addrFor("192.168.40.13"), "INVITE sip:307@").empty())
		<< "an explicit CFNA target must still be used, not overridden by the voicemail fallback";
}

// CFB fallback: the callee already sent a final 486, so there is nothing
// ringing left to CANCEL -- unlike CFNA, this path answers straight away.
TEST(VoicemailDivert, CfbFallsBackToVoicemailWithNoCancelNeeded)
{
	SentList sent;
	RequestsHandler handler("192.168.40.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in callerAddr = addrFor("192.168.40.23");

	handler.handle(makeRegister("308", "192.168.40.14", "reg-308-d"));
	handler.handle(makeRegister("309", "192.168.40.23", "reg-309-d"));
	handler.setVoicemail("308", true);

	const std::string callId = "vm-cfb-1";
	const std::string branch = "z9hG4bKvmcfb1";
	handler.handle(makeInvite("309", "308", "192.168.40.23", callId, branch));
	handler.handle(makeBusy("309", "308", "192.168.40.14", callId, branch));

	std::string okToCaller = findSentTo(sent, callerAddr, "SIP/2.0 200 OK");
	ASSERT_FALSE(okToCaller.empty()) << "busy must fall back to voicemail, not fail the call";
	EXPECT_NE(okToCaller.find("v=0"), std::string::npos);

	EXPECT_TRUE(findSentTo(sent, callerAddr, "SIP/2.0 486").empty())
		<< "the caller must never see the bare 486 once voicemail is enabled";
}

// Neither an explicit CFB target nor voicemail configured: the existing,
// unmodified behaviour (the bare 486 reaches the caller) must be unchanged.
TEST(VoicemailDivert, NoForwardNoVoicemailStillFailsPlainly)
{
	SentList sent;
	RequestsHandler handler("192.168.40.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in callerAddr = addrFor("192.168.40.24");

	handler.handle(makeRegister("310", "192.168.40.15", "reg-310-e"));
	handler.handle(makeRegister("311", "192.168.40.24", "reg-311-e"));

	const std::string callId = "vm-none-1";
	const std::string branch = "z9hG4bKvmnone1";
	handler.handle(makeInvite("311", "310", "192.168.40.24", callId, branch));
	handler.handle(makeBusy("311", "310", "192.168.40.15", callId, branch));

	EXPECT_FALSE(findSentTo(sent, callerAddr, "SIP/2.0 486").empty())
		<< "with no forward configured and voicemail off, the caller must still see 486";
}
