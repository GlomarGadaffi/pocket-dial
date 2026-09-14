// BlindTransfer_test.cpp — Issue #128 regression coverage.
//
// RequestsHandler::onRefer() already tears down the transferor's ORIGINAL
// session (endCall()) before driving the fresh INVITE to the transfer target
// — but endCall() is pure local bookkeeping (session/pool/CDR); it never puts
// a packet on the wire. The OTHER party on that original dialog (the one
// being dropped by the transfer, not the transferor) was never sent a BYE, so
// its phone sat on a call the server considered long over.
//
// This drives a real RequestsHandler through handle() end-to-end (mirroring
// BroadcastHoldResume_test.cpp's pattern): register three extensions, place a
// direct call, answer it, then blind-transfer it and assert the dropped
// party actually receives a BYE for the SAME dialog it was on — not just
// that the transfer target gets a fresh INVITE.

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

	std::string sdpBody()
	{
		return
			"v=0\r\n"
			"o=- 0 0 IN IP4 10.0.0.1\r\n"
			"s=-\r\n"
			"c=IN IP4 10.0.0.1\r\n"
			"t=0 0\r\n"
			"m=audio 10000 RTP/AVP 0\r\n"
			"a=rtpmap:0 PCMU/8000\r\n";
	}

	std::string findSentTo(const std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>& sent,
	                       const sockaddr_in& addr, const std::string& needle)
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
			if (line.size() > name.size() &&
				line.compare(0, name.size(), name) == 0)
			{
				return line;
			}
			pos = eol + 2;
		}
		return {};
	}
}

TEST(BlindTransfer, DroppedPartyReceivesByeAndTargetReceivesFreshInvite)
{
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler("192.168.30.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in transferorAddr = addrFor("192.168.30.10"); // A: 100
	const sockaddr_in droppedAddr    = addrFor("192.168.30.20"); // B: 106
	const sockaddr_in targetAddr     = addrFor("192.168.30.30"); // C: 107

	handler.handle(makeRegister("100", "192.168.30.10", "reg-100"));
	handler.handle(makeRegister("106", "192.168.30.20", "reg-106"));
	handler.handle(makeRegister("107", "192.168.30.30", "reg-107"));

	// ── A calls B directly ──────────────────────────────────────────────────
	const std::string callId = "blindxfer-128";
	{
		std::string body = sdpBody();
		std::string raw =
			"INVITE sip:106@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.30.10:5060;branch=z9hG4bKinv\r\n"
			"From: <sip:100@server>;tag=atag\r\n"
			"To: <sip:106@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:100@192.168.30.10:5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(raw, transferorAddr));
	}
	std::string forkToB = findSentTo(sent, droppedAddr, "INVITE sip:106@");
	ASSERT_FALSE(forkToB.empty()) << "direct call must reach B";

	// ── B answers ────────────────────────────────────────────────────────────
	{
		std::string fromLine = extractHeaderLine(forkToB, "From:");
		std::string via = extractHeaderLine(forkToB, "Via:");
		ASSERT_FALSE(fromLine.empty());
		std::string body = sdpBody();
		std::string raw =
			"SIP/2.0 200 OK\r\n" +
			via + "\r\n" +
			fromLine + "\r\n"
			"To: <sip:106@server>;tag=btag\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Contact: <sip:106@192.168.30.20:5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(raw, droppedAddr));
	}
	ASSERT_FALSE(findSentTo(sent, transferorAddr, "SIP/2.0 200 OK").empty())
		<< "A must see B's answer relayed";

	auto sessionOpt = handler.getSession("Call-ID: " + callId);
	ASSERT_TRUE(sessionOpt.has_value());
	EXPECT_EQ(sessionOpt.value()->getState(), Session::State::Connected);

	// ── A blind-transfers the call to C (107) — REFER in-dialog on the A-B
	// dialog established above, so its From/To carry A's and B's own tags. ──
	{
		std::string raw =
			"REFER sip:106@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.30.10:5060;branch=z9hG4bKref\r\n"
			"From: <sip:100@server>;tag=atag\r\n"
			"To: <sip:106@server>;tag=btag\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 2 REFER\r\n"
			"Max-Forwards: 70\r\n"
			"Refer-To: <sip:107@server>\r\n"
			"Contact: <sip:100@192.168.30.10:5060>\r\n"
			"Content-Length: 0\r\n\r\n";
		handler.handle(RequestsHandler::getMessageFromPool(raw, transferorAddr));
	}

	// A gets the 202 Accepted.
	EXPECT_FALSE(findSentTo(sent, transferorAddr, "SIP/2.0 202 Accepted").empty())
		<< "REFER must be accepted";

	// B — the party being dropped, NOT the transferor — must get an explicit
	// BYE for the SAME dialog (Call-ID) it was on. This is the #128 regression:
	// endCall() alone never sends this.
	std::string byeToB = findSentTo(sent, droppedAddr, "BYE sip:");
	ASSERT_FALSE(byeToB.empty()) << "B must receive a BYE ending its dialog with A";
	EXPECT_NE(byeToB.find("Call-ID: " + callId), std::string::npos) << byeToB;
	// The whole point: B's UA must actually ACCEPT this as its own dialog, which
	// means the tags aren't just present but in the right slots — From carries
	// the transferor's (A's) tag, To carries B's own tag, exactly as REFER's own
	// From/To did. Swapping the two buildServerBye() args would still produce a
	// message starting with "BYE sip:" and containing the right Call-ID, so the
	// Call-ID check above can't catch that mistake — only this can.
	EXPECT_NE(extractHeaderLine(byeToB, "From:").find("tag=atag"), std::string::npos) << byeToB;
	EXPECT_NE(extractHeaderLine(byeToB, "To:").find("tag=btag"), std::string::npos) << byeToB;

	// C — the transfer target — must get a fresh INVITE. redirectInvite()
	// reuses the SAME Call-ID for the new A-C leg (that reuse is exactly why
	// endCall() must run before it, per the ordering comment in onRefer()),
	// so the session under this Call-ID legitimately still exists afterward —
	// it now represents A's continuation with C, not the torn-down A-B leg.
	EXPECT_FALSE(findSentTo(sent, targetAddr, "INVITE sip:107@").empty())
		<< "transfer target must receive a fresh INVITE";
}

// The transferor can be either side of the original call — issue #128's own
// repro has the CALLEE transfer ("A calls B; B answers; B sends REFER"), the
// more common real-world shape (a receptionist transferring an inbound call).
// onRefer()'s other/src/dest selection must BYE the ORIGINAL CALLER in that
// orientation, not always the callee — this exercises the ternary's second
// branch, which the caller-as-transferor test above never reaches.
TEST(BlindTransfer, CalleeAsTransferorByesTheOriginalCaller)
{
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler("192.168.31.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in callerAddr     = addrFor("192.168.31.10"); // A: 100 (original caller, dropped)
	const sockaddr_in transferorAddr = addrFor("192.168.31.20"); // B: 106 (callee, does the REFER)
	const sockaddr_in targetAddr     = addrFor("192.168.31.30"); // C: 107

	handler.handle(makeRegister("100", "192.168.31.10", "reg-100b"));
	handler.handle(makeRegister("106", "192.168.31.20", "reg-106b"));
	handler.handle(makeRegister("107", "192.168.31.30", "reg-107b"));

	// ── A calls B ────────────────────────────────────────────────────────────
	const std::string callId = "blindxfer-128b";
	{
		std::string body = sdpBody();
		std::string raw =
			"INVITE sip:106@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.31.10:5060;branch=z9hG4bKinvb\r\n"
			"From: <sip:100@server>;tag=atagb\r\n"
			"To: <sip:106@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:100@192.168.31.10:5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(raw, callerAddr));
	}
	std::string forkToB = findSentTo(sent, transferorAddr, "INVITE sip:106@");
	ASSERT_FALSE(forkToB.empty()) << "direct call must reach B";

	// ── B answers ────────────────────────────────────────────────────────────
	{
		std::string fromLine = extractHeaderLine(forkToB, "From:");
		std::string via = extractHeaderLine(forkToB, "Via:");
		ASSERT_FALSE(fromLine.empty());
		std::string body = sdpBody();
		std::string raw =
			"SIP/2.0 200 OK\r\n" +
			via + "\r\n" +
			fromLine + "\r\n"
			"To: <sip:106@server>;tag=btagb\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Contact: <sip:106@192.168.31.20:5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(raw, transferorAddr));
	}
	ASSERT_FALSE(findSentTo(sent, callerAddr, "SIP/2.0 200 OK").empty())
		<< "A must see B's answer relayed";

	// ── B (the callee) blind-transfers to C. REFER's From carries B's own tag,
	// To carries A's — B is the transferor here, A is the party to drop. ──────
	{
		std::string raw =
			"REFER sip:100@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.31.20:5060;branch=z9hG4bKrefb\r\n"
			"From: <sip:106@server>;tag=btagb\r\n"
			"To: <sip:100@server>;tag=atagb\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 2 REFER\r\n"
			"Max-Forwards: 70\r\n"
			"Refer-To: <sip:107@server>\r\n"
			"Contact: <sip:106@192.168.31.20:5060>\r\n"
			"Content-Length: 0\r\n\r\n";
		handler.handle(RequestsHandler::getMessageFromPool(raw, transferorAddr));
	}

	EXPECT_FALSE(findSentTo(sent, transferorAddr, "SIP/2.0 202 Accepted").empty())
		<< "REFER must be accepted";

	// A — the original caller, NOT the transferor this time — must get the BYE,
	// correctly tagged (From=B's tag, To=A's tag, matching the REFER's own).
	std::string byeToA = findSentTo(sent, callerAddr, "BYE sip:");
	ASSERT_FALSE(byeToA.empty()) << "A must receive a BYE ending its dialog with B";
	EXPECT_NE(byeToA.find("Call-ID: " + callId), std::string::npos) << byeToA;
	EXPECT_NE(extractHeaderLine(byeToA, "From:").find("tag=btagb"), std::string::npos) << byeToA;
	EXPECT_NE(extractHeaderLine(byeToA, "To:").find("tag=atagb"), std::string::npos) << byeToA;

	EXPECT_FALSE(findSentTo(sent, targetAddr, "INVITE sip:107@").empty())
		<< "transfer target must receive a fresh INVITE";
}

// Issue #203 — the failure case the two tests above never reach, because both
// transfer to a REGISTERED target.
//
// A transfer that cannot be completed must DECLINE, not destroy. Previously
// onRefer() sent the dropped party's BYE and ran endCall() unconditionally, and
// only afterwards asked whether the target resolved — so REFERing to anything
// unresolvable hung up on the other party and erased the session before
// reporting 404. The transferor was told the truth and still lost the call.
//
// The target here is a park orbit (701), which is #203's actual repro:
// "transfer to 701" is how a call gets parked on any real PBX, and orbits live
// in _virtualPeerPool, not _clientPool, so findClient() misses them. But the
// contract under test is general — an unregistered extension, a typo, or a
// phone that just dropped its registration must all land here.
//
// Making 701 a *workable* transfer target is a different job: it needs #202
// (virtual endpoints findable) AND #197 (blind transfer currently moves the
// transferor, so a resolvable orbit would park the wrong party). Until then the
// correct answer is the one asserted below — decline, and leave the call up.
TEST(BlindTransfer, TransferToUnresolvableTargetDeclinesWithoutDestroyingTheCall)
{
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler("192.168.32.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in transferorAddr = addrFor("192.168.32.10"); // A: 100
	const sockaddr_in peerAddr       = addrFor("192.168.32.20"); // B: 106

	handler.handle(makeRegister("100", "192.168.32.10", "reg-100c"));
	handler.handle(makeRegister("106", "192.168.32.20", "reg-106c"));

	const std::string callId = "blindxfer-203";
	{
		std::string body = sdpBody();
		std::string raw =
			"INVITE sip:106@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.32.10:5060;branch=z9hG4bKinvc\r\n"
			"From: <sip:100@server>;tag=atagc\r\n"
			"To: <sip:106@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:100@192.168.32.10:5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(raw, transferorAddr));
	}
	std::string forkToB = findSentTo(sent, peerAddr, "INVITE sip:106@");
	ASSERT_FALSE(forkToB.empty()) << "direct call must reach B";

	{
		std::string fromLine = extractHeaderLine(forkToB, "From:");
		std::string via = extractHeaderLine(forkToB, "Via:");
		ASSERT_FALSE(fromLine.empty());
		std::string body = sdpBody();
		std::string raw =
			"SIP/2.0 200 OK\r\n" +
			via + "\r\n" +
			fromLine + "\r\n"
			"To: <sip:106@server>;tag=btagc\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Contact: <sip:106@192.168.32.20:5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(raw, peerAddr));
	}

	auto before = handler.getSession("Call-ID: " + callId);
	ASSERT_TRUE(before.has_value());
	ASSERT_EQ(before.value()->getState(), Session::State::Connected);

	const size_t sentBeforeRefer = sent.size();

	// ── A blind-transfers to a park orbit, which findClient() cannot resolve ──
	{
		std::string raw =
			"REFER sip:106@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.32.10:5060;branch=z9hG4bKrefc\r\n"
			"From: <sip:100@server>;tag=atagc\r\n"
			"To: <sip:106@server>;tag=btagc\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 2 REFER\r\n"
			"Max-Forwards: 70\r\n"
			"Refer-To: <sip:701@server>\r\n"
			"Contact: <sip:100@192.168.32.10:5060>\r\n"
			"Content-Length: 0\r\n\r\n";
		handler.handle(RequestsHandler::getMessageFromPool(raw, transferorAddr));
	}

	// The REFER is still accepted and still answered honestly — that part was
	// never wrong, and the transferor's phone already handles it.
	EXPECT_FALSE(findSentTo(sent, transferorAddr, "SIP/2.0 202 Accepted").empty())
		<< "REFER must still be accepted";
	std::string notify = findSentTo(sent, transferorAddr, "NOTIFY sip:");
	ASSERT_FALSE(notify.empty()) << "transferor must be NOTIFYed of the outcome";
	EXPECT_NE(notify.find("SIP/2.0 404 Not Found"), std::string::npos)
		<< "sipfrag must report the transfer failed:\n" << notify;

	// THE FIX: nothing was torn down. B keeps its call.
	EXPECT_TRUE(findSentTo(sent, peerAddr, "BYE sip:").empty())
		<< "B must NOT be hung up on for a transfer that never happened";

	auto after = handler.getSession("Call-ID: " + callId);
	ASSERT_TRUE(after.has_value()) << "the A-B session must survive a declined transfer";
	EXPECT_EQ(after.value()->getState(), Session::State::Connected)
		<< "and must still be connected, not left in a torn-down state";

	// Belt and braces: the ONLY things that went out because of the REFER are
	// the 202 and the NOTIFY. Anything else means some other teardown leaked.
	size_t emittedByRefer = sent.size() - sentBeforeRefer;
	EXPECT_EQ(emittedByRefer, 2u)
		<< "a declined transfer should emit exactly 202 + NOTIFY, got "
		<< emittedByRefer;
}
