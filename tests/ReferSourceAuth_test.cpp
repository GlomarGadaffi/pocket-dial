// ReferSourceAuth_test.cpp — Issue #133 regression coverage.
//
// RequestsHandler::onBye() has issue #46's guard: a BYE for an established
// two-party dialog must arrive from one of that dialog's own leg IPs, or it is
// a forged teardown and gets 403. onRefer() had no equivalent. Its only
// admission check was findClient(data->getFromNumber()) — which proves the
// From header names a REGISTERed extension, nothing more. From is chosen by
// the sender, so any registered phone could put someone else's Call-ID on a
// REFER and:
//
//   * blind path — endCall() the victim's session and (since #128) send the
//     victim's peer a BYE built from the attacker's own tags; or
//   * attended path — name the victim's call as ?Replaces= and splice it.
//
// The attended path's own "A must be common to both dialogs" check is not a
// substitute: it compares NUMBERS taken from the same attacker-chosen From.
//
// These drive a real RequestsHandler through handle() end-to-end (same shape
// as BlindTransfer_test.cpp) and assert the forged REFER is refused 403 with
// the victim's session and peer both left untouched, while the legitimate
// in-dialog REFER from a real leg still works.

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
	sockaddr_in addrFor(const std::string& ip, uint16_t port = 5060)
	{
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_addr.s_addr = inet_addr(ip.c_str());
		a.sin_port = htons(port);
		return a;
	}

	std::shared_ptr<SipMessage> makeRegister(const std::string& ext, const std::string& ip,
	                                          const std::string& callId)
	{
		std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKr" + callId + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + callId + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + ip + ":5060>;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}

	std::string sdpBody(const std::string& ip)
	{
		return
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + ip + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + ip + "\r\n"
			"t=0 0\r\n"
			"m=audio 10000 RTP/AVP 0\r\n"
			"a=rtpmap:0 PCMU/8000\r\n";
	}

	// `since` skips everything the setup already emitted. It matters: RegisterBeeper
	// sends every extension an "INVITE sip:<ext>@..." beep at REGISTER time, and the
	// A-C call's own setup INVITE also reaches C — so an unscoped search for
	// "INVITE sip:107@" finds a legitimate earlier message and can never prove that
	// the forged REFER dialled nobody.
	std::string findSentTo(const std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>& sent,
	                       const sockaddr_in& addr, const std::string& needle,
	                       size_t since = 0)
	{
		for (size_t i = sent.size(); i > since; --i)
		{
			const auto& e = sent[i - 1];
			if (e.first.sin_addr.s_addr != addr.sin_addr.s_addr) continue;
			if (e.first.sin_port != addr.sin_port) continue;
			if (!e.second) continue;
			std::string raw = e.second->toString();
			if (raw.find(needle) != std::string::npos) return raw;
		}
		return {};
	}

	// Drives REGISTER -> INVITE -> 200 OK so `callId` names a Connected dialog
	// between `callerExt`@`callerIp` and `calleeExt`@`calleeIp`.
	void establishCall(RequestsHandler& handler,
	                   std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>& sent,
	                   const std::string& callerExt, const std::string& callerIp,
	                   const std::string& callerTag,
	                   const std::string& calleeExt, const std::string& calleeIp,
	                   const std::string& calleeTag,
	                   const std::string& callId)
	{
		const sockaddr_in callerAddr = addrFor(callerIp);
		const sockaddr_in calleeAddr = addrFor(calleeIp);
		{
			std::string body = sdpBody(callerIp);
			std::string raw =
				"INVITE sip:" + calleeExt + "@server SIP/2.0\r\n"
				"Via: SIP/2.0/UDP " + callerIp + ":5060;branch=z9hG4bKi" + callId + "\r\n"
				"From: <sip:" + callerExt + "@server>;tag=" + callerTag + "\r\n"
				"To: <sip:" + calleeExt + "@server>\r\n"
				"Call-ID: " + callId + "\r\n"
				"CSeq: 1 INVITE\r\n"
				"Max-Forwards: 70\r\n"
				"Contact: <sip:" + callerExt + "@" + callerIp + ":5060>\r\n"
				"Content-Type: application/sdp\r\n"
				"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
			handler.handle(RequestsHandler::getMessageFromPool(raw, callerAddr));
		}
		std::string fork = findSentTo(sent, calleeAddr, "INVITE sip:" + calleeExt + "@");
		ASSERT_FALSE(fork.empty()) << "call must reach " << calleeExt;

		// Echo back the forked INVITE's own Via/From so the 200 OK matches its
		// transaction, exactly as a real callee's UA would.
		std::string via, fromLine;
		{
			size_t pos = 0;
			while (pos < fork.size())
			{
				size_t eol = fork.find("\r\n", pos);
				if (eol == std::string::npos) eol = fork.size();
				std::string line = fork.substr(pos, eol - pos);
				if (line.rfind("Via:", 0) == 0) via = line;
				if (line.rfind("From:", 0) == 0) fromLine = line;
				pos = eol + 2;
			}
		}
		ASSERT_FALSE(via.empty());
		ASSERT_FALSE(fromLine.empty());
		{
			std::string body = sdpBody(calleeIp);
			std::string raw =
				"SIP/2.0 200 OK\r\n" +
				via + "\r\n" +
				fromLine + "\r\n"
				"To: <sip:" + calleeExt + "@server>;tag=" + calleeTag + "\r\n"
				"Call-ID: " + callId + "\r\n"
				"CSeq: 1 INVITE\r\n"
				"Contact: <sip:" + calleeExt + "@" + calleeIp + ":5060>\r\n"
				"Content-Type: application/sdp\r\n"
				"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
			handler.handle(RequestsHandler::getMessageFromPool(raw, calleeAddr));
		}
	}
}

// The core hole: a third registered phone (D) sends a blind-transfer REFER
// carrying the A-B dialog's Call-ID, with From spoofed to A's number and A's
// tag, from D's own IP. Pre-#133 that passed findClient() and tore the call
// down. It must now be refused 403 with nothing torn down and no BYE emitted.
TEST(ReferSourceAuth, ForgedBlindTransferFromOffPathSourceIsRejected)
{
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler("192.168.40.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in aAddr        = addrFor("192.168.40.10"); // A: 100
	const sockaddr_in bAddr        = addrFor("192.168.40.20"); // B: 106
	const sockaddr_in attackerAddr = addrFor("192.168.40.40"); // D: 108 — off-path

	handler.handle(makeRegister("100", "192.168.40.10", "reg-a-133"));
	handler.handle(makeRegister("106", "192.168.40.20", "reg-b-133"));
	handler.handle(makeRegister("107", "192.168.40.30", "reg-c-133"));
	handler.handle(makeRegister("108", "192.168.40.40", "reg-d-133"));

	const std::string callId = "victim-dialog-133";
	establishCall(handler, sent, "100", "192.168.40.10", "atag",
	                             "106", "192.168.40.20", "btag", callId);

	auto before = handler.getSession("Call-ID: " + callId);
	ASSERT_TRUE(before.has_value());
	ASSERT_EQ(before.value()->getState(), Session::State::Connected);

	const size_t sentBefore = sent.size();

	// D forges the REFER: A's number and A's tag in From, but D's own source
	// address on the wire. Everything except the source IP is attacker-chosen.
	{
		std::string raw =
			"REFER sip:106@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.40.40:5060;branch=z9hG4bKforged\r\n"
			"From: <sip:100@server>;tag=atag\r\n"
			"To: <sip:106@server>;tag=btag\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 2 REFER\r\n"
			"Max-Forwards: 70\r\n"
			"Refer-To: <sip:107@server>\r\n"
			"Contact: <sip:100@192.168.40.40:5060>\r\n"
			"Content-Length: 0\r\n\r\n";
		handler.handle(RequestsHandler::getMessageFromPool(raw, attackerAddr));
	}

	// 403 goes back to the forger, and only to the forger.
	EXPECT_FALSE(findSentTo(sent, attackerAddr, "SIP/2.0 403", sentBefore).empty())
		<< "forged REFER must be refused 403";
	EXPECT_TRUE(findSentTo(sent, attackerAddr, "SIP/2.0 202 Accepted", sentBefore).empty())
		<< "forged REFER must never be accepted";

	// Neither leg of the victim's call hears anything at all — this is the
	// #128-era wire-visible symptom the guard has to prevent, not just the
	// bookkeeping teardown.
	EXPECT_TRUE(findSentTo(sent, bAddr, "BYE sip:", sentBefore).empty())
		<< "B must not be BYE'd by a forged transfer";
	EXPECT_TRUE(findSentTo(sent, aAddr, "BYE sip:", sentBefore).empty())
		<< "A must not be BYE'd by a forged transfer";

	// The transfer target must never be dialled.
	EXPECT_TRUE(findSentTo(sent, addrFor("192.168.40.30"), "INVITE sip:107@", sentBefore).empty())
		<< "forged transfer must not dial the target";

	// And the session is still there, still Connected.
	auto after = handler.getSession("Call-ID: " + callId);
	ASSERT_TRUE(after.has_value()) << "victim session must survive a forged REFER";
	EXPECT_EQ(after.value()->getState(), Session::State::Connected);

	// Exactly one message (the 403) resulted.
	EXPECT_EQ(sent.size(), sentBefore + 1);
}

// The guard must not break the legitimate case: the same REFER, from A's real
// address, still transfers. Without this the test above would pass on a
// handler that refused every REFER.
TEST(ReferSourceAuth, InDialogTransferFromARealLegStillSucceeds)
{
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler("192.168.41.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in aAddr      = addrFor("192.168.41.10"); // A: 100 — transferor
	const sockaddr_in bAddr      = addrFor("192.168.41.20"); // B: 106 — dropped
	const sockaddr_in targetAddr = addrFor("192.168.41.30"); // C: 107 — target

	handler.handle(makeRegister("100", "192.168.41.10", "reg-a-133ok"));
	handler.handle(makeRegister("106", "192.168.41.20", "reg-b-133ok"));
	handler.handle(makeRegister("107", "192.168.41.30", "reg-c-133ok"));

	const std::string callId = "legit-dialog-133";
	establishCall(handler, sent, "100", "192.168.41.10", "atag",
	                             "106", "192.168.41.20", "btag", callId);

	const size_t sentBefore = sent.size();

	{
		std::string raw =
			"REFER sip:106@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.41.10:5060;branch=z9hG4bKlegit\r\n"
			"From: <sip:100@server>;tag=atag\r\n"
			"To: <sip:106@server>;tag=btag\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 2 REFER\r\n"
			"Max-Forwards: 70\r\n"
			"Refer-To: <sip:107@server>\r\n"
			"Contact: <sip:100@192.168.41.10:5060>\r\n"
			"Content-Length: 0\r\n\r\n";
		handler.handle(RequestsHandler::getMessageFromPool(raw, aAddr));
	}

	EXPECT_FALSE(findSentTo(sent, aAddr, "SIP/2.0 202 Accepted", sentBefore).empty())
		<< "a real leg's REFER must still be accepted";
	EXPECT_TRUE(findSentTo(sent, aAddr, "SIP/2.0 403", sentBefore).empty())
		<< "a real leg's REFER must not be forbidden";
	// #128's BYE still goes out, and since #197 it goes to the party the transfer
	// DROPS — the transferor, A, who is the one asking to leave. B is the
	// transferee: it stays on its own dialog and is re-pointed at the target.
	// (Before #197 this assertion named bAddr, because the handler hung up on the
	// transferee and dialled the transferor through instead.)
	EXPECT_FALSE(findSentTo(sent, aAddr, "BYE sip:", sentBefore).empty())
		<< "the transferor must still get its #128 BYE";
	EXPECT_TRUE(findSentTo(sent, bAddr, "BYE sip:", sentBefore).empty())
		<< "the transferee must not be hung up on (#197)";
	EXPECT_FALSE(findSentTo(sent, targetAddr, "INVITE sip:107@", sentBefore).empty())
		<< "the transfer target must still be dialled";
}

// A REFER whose source IS a leg of the A-B dialog (B, the far end) but which
// names an unrelated call as ?Replaces=. B passes the A-B source check, and
// spoofing A's number in From satisfies the attended path's own
// "A common to both dialogs" coherence test — only the consult-dialog source
// check stops B from splicing A out of A's other call.
TEST(ReferSourceAuth, ReplacesNamingADialogTheSourceIsNotOnIsRejected)
{
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler("192.168.42.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in aAddr = addrFor("192.168.42.10"); // A: 100
	const sockaddr_in bAddr = addrFor("192.168.42.20"); // B: 106 — on A-B only
	const sockaddr_in cAddr = addrFor("192.168.42.30"); // C: 107 — on A-C only

	handler.handle(makeRegister("100", "192.168.42.10", "reg-a-133r"));
	handler.handle(makeRegister("106", "192.168.42.20", "reg-b-133r"));
	handler.handle(makeRegister("107", "192.168.42.30", "reg-c-133r"));

	const std::string abCallId = "ab-dialog-133r";
	const std::string acCallId = "ac-dialog-133r";
	establishCall(handler, sent, "100", "192.168.42.10", "atag1",
	                             "106", "192.168.42.20", "btag1", abCallId);
	establishCall(handler, sent, "100", "192.168.42.10", "atag2",
	                             "107", "192.168.42.30", "ctag2", acCallId);

	ASSERT_TRUE(handler.getSession("Call-ID: " + acCallId).has_value());
	const size_t sentBefore = sent.size();

	// B sends the attended REFER on its own A-B dialog (so the first source
	// check passes) with From spoofed as A, naming A's separate A-C call.
	{
		std::string raw =
			"REFER sip:100@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.42.20:5060;branch=z9hG4bKrepl\r\n"
			"From: <sip:100@server>;tag=atag1\r\n"
			"To: <sip:106@server>;tag=btag1\r\n"
			"Call-ID: " + abCallId + "\r\n"
			"CSeq: 2 REFER\r\n"
			"Max-Forwards: 70\r\n"
			"Refer-To: <sip:107@server?Replaces=" + acCallId + ">\r\n"
			"Contact: <sip:106@192.168.42.20:5060>\r\n"
			"Content-Length: 0\r\n\r\n";
		handler.handle(RequestsHandler::getMessageFromPool(raw, bAddr));
	}

	EXPECT_FALSE(findSentTo(sent, bAddr, "SIP/2.0 403", sentBefore).empty())
		<< "a Replaces naming a dialog the source is not on must be refused 403";
	EXPECT_TRUE(findSentTo(sent, bAddr, "SIP/2.0 202 Accepted", sentBefore).empty())
		<< "the splice must never be accepted";

	// No leg of either dialog is torn down or re-INVITEd.
	EXPECT_TRUE(findSentTo(sent, aAddr, "BYE sip:", sentBefore).empty()) << "A must not be dropped";
	EXPECT_TRUE(findSentTo(sent, cAddr, "INVITE sip:107@", sentBefore).empty())
		<< "C must not be re-INVITEd by a forged splice";

	auto ab = handler.getSession("Call-ID: " + abCallId);
	auto ac = handler.getSession("Call-ID: " + acCallId);
	ASSERT_TRUE(ab.has_value());
	ASSERT_TRUE(ac.has_value());
	EXPECT_FALSE(ab.value()->isTransferBridge()) << "no bridge may be established";
	EXPECT_FALSE(ac.value()->isTransferBridge()) << "no bridge may be established";

	EXPECT_EQ(sent.size(), sentBefore + 1);
}
