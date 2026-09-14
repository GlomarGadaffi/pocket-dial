// BlindTransfer_test.cpp — blind-transfer topology and teardown coverage
// (issues #128, #197, #203).
//
// What a blind transfer is, since this file used to assert the opposite
// (RFC 3515 §2, RFC 5359 §2.4): A and B are talking, A sends REFER with
// Refer-To: C inside the A-B dialog. B — the TRANSFEREE — ends up talking to C.
// A, the transferor, drops out. The referred request goes to the referee, never
// back to the referrer.
//
// Until #197 this PBX did the reverse: it BYEd B and re-INVITEd A to C, so a
// receptionist transferring an inbound caller hung up on the customer and was
// dialled through to the target themselves — reported as 200 OK by the sipfrag
// NOTIFY, so the lost call was invisible. These tests pinned that inversion in
// place, comments and all; they are rewritten here rather than merely flipped,
// because the topology they describe is what changed.
//
// Because media is peer-to-peer (the board relays SDP and never carries audio),
// "B ends up talking to C" is a two-dialog B2BUA operation, and the tests below
// cover both halves of it:
//
//   at REFER time — a NEW leg carries B's media to C, A is BYEd off the A-B
//                   dialog, and that dialog SURVIVES as B's half of a bridge;
//   at answer     — C's 200 OK is ACKed by the server (it is the UAC there) and
//                   turned into a re-INVITE of B, inside B's own untouched
//                   dialog, carrying C's SDP.
//
// #128's contribution survives intact, just pointed at the other party: whoever
// the transfer drops gets a real BYE on the wire with correctly-placed tags,
// because endCall() is pure local bookkeeping and never tells a phone anything.
//
// Everything drives a real RequestsHandler through handle() end-to-end, the same
// pattern as BroadcastHoldResume_test.cpp.

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

	// Per-party SDP. The media half of #197 is a SWAP — the target is offered the
	// transferee's media and the transferee is re-offered the target's — and a
	// shared, identical body (which is what this file used to use) cannot tell a
	// correct swap from a body that was simply copied along, or from no swap at
	// all. Every party here gets its own address, port and direction.
	std::string sdpBodyFor(const std::string& ip, int port,
	                       const std::string& direction = "sendrecv")
	{
		return
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + ip + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + ip + "\r\n"
			"t=0 0\r\n"
			"m=audio " + std::to_string(port) + " RTP/AVP 0\r\n"
			"a=rtpmap:0 PCMU/8000\r\n"
			"a=" + direction + "\r\n";
	}

	std::string sdpBody()
	{
		return sdpBodyFor("10.0.0.1", 10000);
	}

	std::string findSentTo(const SentList& sent,
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

	// ";branch=..." of a Via line, so an ACK can be checked against the very
	// INVITE it belongs to (RFC 3261 §17.1.1.3 requires the same branch for a
	// non-2xx ACK — a fresh one puts the ACK in a different transaction, which
	// the far end ignores while it keeps retransmitting).
	std::string branchOf(const std::string& viaLine)
	{
		size_t b = viaLine.find(";branch=");
		if (b == std::string::npos) return {};
		size_t s = b + 8;
		size_t e = viaLine.find_first_of(";\r\n", s);
		return viaLine.substr(s, (e == std::string::npos) ? std::string::npos : e - s);
	}

	// Place caller -> callee and answer it, each side offering its own media.
	// Leaves a Connected session under `callId`, exactly as a real call would.
	void connectCall(RequestsHandler& handler, SentList& sent, const std::string& callId,
		const std::string& callerExt, const sockaddr_in& callerAddr, const std::string& callerTag,
		const std::string& callerSdp,
		const std::string& calleeExt, const sockaddr_in& calleeAddr, const std::string& calleeTag,
		const std::string& calleeSdp)
	{
		{
			std::string raw =
				"INVITE sip:" + calleeExt + "@server SIP/2.0\r\n"
				"Via: SIP/2.0/UDP " + std::string(inet_ntoa(callerAddr.sin_addr)) +
					":5060;branch=z9hG4bKi" + callId + "\r\n"
				"From: <sip:" + callerExt + "@server>;tag=" + callerTag + "\r\n"
				"To: <sip:" + calleeExt + "@server>\r\n"
				"Call-ID: " + callId + "\r\n"
				"CSeq: 1 INVITE\r\n"
				"Max-Forwards: 70\r\n"
				"Contact: <sip:" + callerExt + "@" + inet_ntoa(callerAddr.sin_addr) + ":5060>\r\n"
				"Content-Type: application/sdp\r\n"
				"Content-Length: " + std::to_string(callerSdp.size()) + "\r\n\r\n" + callerSdp;
			handler.handle(RequestsHandler::getMessageFromPool(raw, callerAddr));
		}
		std::string fork = findSentTo(sent, calleeAddr, "INVITE sip:" + calleeExt + "@");
		ASSERT_FALSE(fork.empty()) << "call must reach the callee";

		std::string fromLine = extractHeaderLine(fork, "From:");
		std::string via = extractHeaderLine(fork, "Via:");
		ASSERT_FALSE(fromLine.empty());
		std::string raw =
			"SIP/2.0 200 OK\r\n" +
			via + "\r\n" +
			fromLine + "\r\n"
			"To: <sip:" + calleeExt + "@server>;tag=" + calleeTag + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Contact: <sip:" + calleeExt + "@" + inet_ntoa(calleeAddr.sin_addr) + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(calleeSdp.size()) + "\r\n\r\n" + calleeSdp;
		handler.handle(RequestsHandler::getMessageFromPool(raw, calleeAddr));
		ASSERT_FALSE(findSentTo(sent, callerAddr, "SIP/2.0 200 OK").empty())
			<< "the caller must see the answer relayed";
	}

	// A blind-transfer REFER sent in-dialog by `transferorExt`.
	std::shared_ptr<SipMessage> makeRefer(const std::string& callId,
		const std::string& transferorExt, const sockaddr_in& transferorAddr, const std::string& transferorTag,
		const std::string& peerExt, const std::string& peerTag,
		const std::string& target)
	{
		std::string raw =
			"REFER sip:" + peerExt + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(inet_ntoa(transferorAddr.sin_addr)) +
				":5060;branch=z9hG4bKref" + callId + "\r\n"
			"From: <sip:" + transferorExt + "@server>;tag=" + transferorTag + "\r\n"
			"To: <sip:" + peerExt + "@server>;tag=" + peerTag + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 2 REFER\r\n"
			"Max-Forwards: 70\r\n"
			"Refer-To: <sip:" + target + "@server>\r\n"
			"Contact: <sip:" + transferorExt + "@" + inet_ntoa(transferorAddr.sin_addr) + ":5060>\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, transferorAddr);
	}
}

// ── #197: the caller transfers ───────────────────────────────────────────────
// A calls B, then transfers B to C. The party that MOVES is B; the party that
// leaves is A. Every assertion here was the other way round before #197: the
// BYE went to B (the party a transfer exists to keep) and the INVITE named A.
TEST(BlindTransfer, TransferorIsDroppedAndTheTransfereeIsMovedToTheTarget)
{
	SentList sent;
	RequestsHandler handler("192.168.30.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in transferorAddr = addrFor("192.168.30.10"); // A: 100, does the REFER
	const sockaddr_in transfereeAddr = addrFor("192.168.30.20"); // B: 106, the moved party
	const sockaddr_in targetAddr     = addrFor("192.168.30.30"); // C: 107

	handler.handle(makeRegister("100", "192.168.30.10", "reg-100"));
	handler.handle(makeRegister("106", "192.168.30.20", "reg-106"));
	handler.handle(makeRegister("107", "192.168.30.30", "reg-107"));

	const std::string callId = "blindxfer-197";
	connectCall(handler, sent, callId,
		"100", transferorAddr, "atag", sdpBodyFor("10.1.1.1", 10001),
		"106", transfereeAddr, "btag", sdpBodyFor("10.2.2.2", 20002));

	const size_t before = sent.size();
	handler.handle(makeRefer(callId, "100", transferorAddr, "atag", "106", "btag", "107"));

	EXPECT_FALSE(findSentTo(sent, transferorAddr, "SIP/2.0 202 Accepted").empty())
		<< "REFER must be accepted";

	// The BYE goes to the TRANSFEROR. A asked to leave; A leaves.
	std::string byeToA = findSentTo(sent, transferorAddr, "BYE sip:");
	ASSERT_FALSE(byeToA.empty()) << "the transferor must be dropped off the call";
	EXPECT_NE(byeToA.find("Call-ID: " + callId), std::string::npos) << byeToA;
	// Tags, #128's other half: the server sends this BYE impersonating B, so B's
	// tag is in From and A's in To — the exact reverse of the pre-#197 BYE. A
	// phone rejects a BYE whose tags do not match a dialog it holds, so wrong
	// slots here mean the transferor's phone stays on a call nobody is on.
	EXPECT_NE(extractHeaderLine(byeToA, "From:").find("tag=btag"), std::string::npos) << byeToA;
	EXPECT_NE(extractHeaderLine(byeToA, "To:").find("tag=atag"), std::string::npos) << byeToA;

	// And NOT to the transferee. This single assertion is the issue: B is the
	// customer on the other end of a receptionist's transfer.
	EXPECT_TRUE(findSentTo(sent, transfereeAddr, "BYE sip:").empty())
		<< "the transferee must NOT be hung up on — it is the party being transferred";

	// C is invited on a NEW dialog that stands in for B: B's identity, B's media.
	std::string inviteToC = findSentTo(sent, targetAddr, "INVITE sip:107@");
	ASSERT_FALSE(inviteToC.empty()) << "the transfer target must receive an INVITE";
	EXPECT_EQ(extractHeaderLine(inviteToC, "Call-ID:").find("Call-ID: " + callId), std::string::npos)
		<< "the new leg must be its own dialog, not a reuse of the A-B Call-ID:\n" << inviteToC;
	EXPECT_NE(extractHeaderLine(inviteToC, "From:").find("sip:106@"), std::string::npos)
		<< "C's phone must announce the transferee, not the extension that pressed Transfer:\n"
		<< inviteToC;
	EXPECT_NE(inviteToC.find("c=IN IP4 10.2.2.2"), std::string::npos)
		<< "C must be offered the TRANSFEREE's media (10.2.2.2), not the transferor's:\n" << inviteToC;
	EXPECT_NE(inviteToC.find("m=audio 20002"), std::string::npos) << inviteToC;
	EXPECT_NE(inviteToC.find("Referred-By:"), std::string::npos)
		<< "RFC 3892: the target should be told who caused this call";

	// The A-B session SURVIVES — it is B's dialog and B is staying on it.
	auto surviving = handler.getSession("Call-ID: " + callId);
	ASSERT_TRUE(surviving.has_value())
		<< "the transferee's dialog must not be torn down by the transfer";
	EXPECT_TRUE(surviving.value()->isTransferBridge())
		<< "it must be linked to the new leg so a later BYE reaches the right party";

	(void)before;
}

// ── #197: the receptionist orientation ───────────────────────────────────────
// The transferor can be either side of the call, and the common real shape has
// them as the CALLEE: a customer rings in, reception answers, reception presses
// Transfer. The party that must survive is then the original CALLER. #128's
// repro was exactly this orientation, and the old code's other/src/dest ternary
// was written to BYE the caller here — which is the customer.
TEST(BlindTransfer, ReceptionistTransferMovesTheInboundCallerNotTheReceptionist)
{
	SentList sent;
	RequestsHandler handler("192.168.31.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in callerAddr     = addrFor("192.168.31.10"); // A: 100, inbound caller (moved)
	const sockaddr_in transferorAddr = addrFor("192.168.31.20"); // B: 106, receptionist (drops out)
	const sockaddr_in targetAddr     = addrFor("192.168.31.30"); // C: 107

	handler.handle(makeRegister("100", "192.168.31.10", "reg-100b"));
	handler.handle(makeRegister("106", "192.168.31.20", "reg-106b"));
	handler.handle(makeRegister("107", "192.168.31.30", "reg-107b"));

	const std::string callId = "blindxfer-197b";
	connectCall(handler, sent, callId,
		"100", callerAddr, "atagb", sdpBodyFor("10.1.1.1", 10001),
		"106", transferorAddr, "btagb", sdpBodyFor("10.2.2.2", 20002));

	handler.handle(makeRefer(callId, "106", transferorAddr, "btagb", "100", "atagb", "107"));

	EXPECT_FALSE(findSentTo(sent, transferorAddr, "SIP/2.0 202 Accepted").empty())
		<< "REFER must be accepted";

	// The receptionist leaves; the customer does not.
	std::string byeToB = findSentTo(sent, transferorAddr, "BYE sip:");
	ASSERT_FALSE(byeToB.empty()) << "the receptionist (transferor) must be dropped";
	EXPECT_NE(byeToB.find("Call-ID: " + callId), std::string::npos) << byeToB;
	EXPECT_NE(extractHeaderLine(byeToB, "From:").find("tag=atagb"), std::string::npos) << byeToB;
	EXPECT_NE(extractHeaderLine(byeToB, "To:").find("tag=btagb"), std::string::npos) << byeToB;

	EXPECT_TRUE(findSentTo(sent, callerAddr, "BYE sip:").empty())
		<< "the inbound caller must NOT be hung up on — that is the whole bug";

	// The transferee here is the CALLER, so its media comes off the stored INVITE
	// (getRemoteSdp() is always the callee's SDP, which in this orientation is the
	// transferor's own answer). Reading the wrong one ships the receptionist's
	// media to the target and the audio never lands.
	std::string inviteToC = findSentTo(sent, targetAddr, "INVITE sip:107@");
	ASSERT_FALSE(inviteToC.empty()) << "the transfer target must receive an INVITE";
	EXPECT_NE(extractHeaderLine(inviteToC, "From:").find("sip:100@"), std::string::npos)
		<< "C must be told it is being connected to the inbound caller:\n" << inviteToC;
	EXPECT_NE(inviteToC.find("c=IN IP4 10.1.1.1"), std::string::npos)
		<< "C must be offered the CALLER's media (10.1.1.1):\n" << inviteToC;
	EXPECT_NE(inviteToC.find("m=audio 10001"), std::string::npos) << inviteToC;

	EXPECT_TRUE(handler.getSession("Call-ID: " + callId).has_value())
		<< "the inbound caller's dialog must survive the transfer";
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
// Making 701 a *workable* transfer target is still a different job: #197 has
// since landed (the transfer now moves the transferee, so a resolvable orbit
// would park the right party), but #202 has not — virtual endpoints are still
// invisible to findClient(), so 701 does not resolve and the correct answer
// remains the one asserted below: decline, and leave the call up.
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

// ── #197: the media half ─────────────────────────────────────────────────────
// Everything above stops at "C was invited". This is the part that makes the
// transfer real: media here is peer-to-peer, so B and C have to be handed each
// other's SDP or the call completes silent. The server is the UAC on the leg
// toward C, so C's 200 OK is ours to ACK — relaying it at B (whose dialog it
// does not belong to) would leave both phones pointed at a party that has gone.
//
// This is ParkOrbit's retrieve swap arriving one round-trip late: park answers
// the retriever with the parked party's SDP and re-INVITEs the parked party with
// the retriever's, all inside one handler call, because both offers already
// exist. Here C has to be rung before it has an answer to swap in.
TEST(BlindTransfer, TargetAnswerIsAckedAndSwappedIntoTheTransfereesOwnDialog)
{
	SentList sent;
	RequestsHandler handler("192.168.33.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in transferorAddr = addrFor("192.168.33.10"); // A: 100
	const sockaddr_in transfereeAddr = addrFor("192.168.33.20"); // B: 106
	const sockaddr_in targetAddr     = addrFor("192.168.33.30"); // C: 107

	handler.handle(makeRegister("100", "192.168.33.10", "reg-100d"));
	handler.handle(makeRegister("106", "192.168.33.20", "reg-106d"));
	handler.handle(makeRegister("107", "192.168.33.30", "reg-107d"));

	const std::string callId = "blindxfer-197-media";
	connectCall(handler, sent, callId,
		"100", transferorAddr, "atag", sdpBodyFor("10.1.1.1", 10001),
		"106", transfereeAddr, "btag", sdpBodyFor("10.2.2.2", 20002));
	handler.handle(makeRefer(callId, "100", transferorAddr, "atag", "106", "btag", "107"));

	std::string inviteToC = findSentTo(sent, targetAddr, "INVITE sip:107@");
	ASSERT_FALSE(inviteToC.empty());
	const std::string legCallId = extractHeaderLine(inviteToC, "Call-ID:");
	const std::string legVia    = extractHeaderLine(inviteToC, "Via:");
	const std::string legFrom   = extractHeaderLine(inviteToC, "From:");
	ASSERT_FALSE(legCallId.empty());

	// ── C answers with its own media ──────────────────────────────────────────
	const size_t beforeAnswer = sent.size();
	{
		std::string body = sdpBodyFor("10.3.3.3", 30003);
		std::string raw =
			"SIP/2.0 200 OK\r\n" +
			legVia + "\r\n" +
			legFrom + "\r\n"
			"To: <sip:107@192.168.33.1:5060>;tag=ctag\r\n" +
			legCallId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Contact: <sip:107@192.168.33.30:5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(raw, targetAddr));
	}

	// The server owns that dialog, so it owes C the ACK. Nobody else would send
	// one and C retransmits its 200 OK until somebody does.
	std::string ackToC = findSentTo(sent, targetAddr, "ACK sip:");
	ASSERT_FALSE(ackToC.empty()) << "the target's answer must be ACKed by the server";
	EXPECT_NE(ackToC.find(legCallId), std::string::npos) << ackToC;

	// And B is re-INVITEd — inside its OWN dialog, untouched since the call began
	// (same Call-ID, same tags) — with C's media.
	std::string reinviteToB = findSentTo(sent, transfereeAddr, "INVITE sip:106@");
	ASSERT_FALSE(reinviteToB.empty()) << "the transferee must be re-INVITEd with the target's SDP";
	EXPECT_NE(reinviteToB.find("Call-ID: " + callId), std::string::npos)
		<< "the transferee must stay in its own dialog — no reconnect, no new Call-ID:\n"
		<< reinviteToB;
	EXPECT_NE(reinviteToB.find("c=IN IP4 10.3.3.3"), std::string::npos)
		<< "B must be re-pointed at C's media (10.3.3.3):\n" << reinviteToB;
	EXPECT_NE(reinviteToB.find("m=audio 30003"), std::string::npos) << reinviteToB;
	// Impersonating the departed transferor: A's tag in From, B's in To. These are
	// the only tags B's dialog will accept.
	EXPECT_NE(extractHeaderLine(reinviteToB, "From:").find("tag=atag"), std::string::npos)
		<< reinviteToB;
	EXPECT_NE(extractHeaderLine(reinviteToB, "To:").find("tag=btag"), std::string::npos)
		<< reinviteToB;

	// Nothing went to the transferor: it left the call at REFER time.
	for (size_t i = beforeAnswer; i < sent.size(); ++i)
	{
		EXPECT_NE(sent[i].first.sin_addr.s_addr, transferorAddr.sin_addr.s_addr)
			<< "the transferor must receive nothing once it has been dropped: "
			<< sent[i].second->toString();
	}

	// ── B answers the re-INVITE: the server ACKs it and does NOT relay it ──────
	const size_t beforeBAnswer = sent.size();
	{
		std::string body = sdpBodyFor("10.2.2.2", 20002);
		std::string raw =
			"SIP/2.0 200 OK\r\n" +
			extractHeaderLine(reinviteToB, "Via:") + "\r\n" +
			extractHeaderLine(reinviteToB, "From:") + "\r\n" +
			extractHeaderLine(reinviteToB, "To:") + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 100 INVITE\r\n"
			"Contact: <sip:106@192.168.33.20:5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(raw, transfereeAddr));
	}
	std::string ackToB = findSentTo(sent, transfereeAddr, "ACK sip:");
	ASSERT_FALSE(ackToB.empty()) << "the transferee's answer to our re-INVITE must be ACKed";
	for (size_t i = beforeBAnswer; i < sent.size(); ++i)
	{
		EXPECT_NE(sent[i].first.sin_addr.s_addr, transferorAddr.sin_addr.s_addr)
			<< "B's answer must not be relayed to the transferor";
	}

	// Both halves of the bridge are live and linked.
	auto bLeg = handler.getSession("Call-ID: " + callId);
	auto cLeg = handler.getSession(legCallId);
	ASSERT_TRUE(bLeg.has_value());
	ASSERT_TRUE(cLeg.has_value());
	EXPECT_EQ(cLeg.value()->getState(), Session::State::Connected);
	EXPECT_EQ(bLeg.value()->getPeerCallID(), legCallId);
	EXPECT_EQ(cLeg.value()->getPeerCallID(), "Call-ID: " + callId);
}

// A phone's Transfer softkey holds the call before it REFERs, so the last SDP
// the PBX captured for the transferee is routinely a HOLD answer (a=recvonly /
// a=inactive / a=sendonly). Relaying that direction into the new leg completes
// the transfer with one-way audio — a failure that never shows up in a
// signalling trace, only on the handsets. The offer to the target is normalised
// to sendrecv (RFC 3264 §6.1: a new offer renegotiates direction, and this
// re-INVITE is precisely what ends the hold).
TEST(BlindTransfer, HoldBeforeReferStillOffersTheTargetTwoWayMedia)
{
	SentList sent;
	RequestsHandler handler("192.168.34.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in transferorAddr = addrFor("192.168.34.10"); // A: 100
	const sockaddr_in transfereeAddr = addrFor("192.168.34.20"); // B: 106
	const sockaddr_in targetAddr     = addrFor("192.168.34.30"); // C: 107

	handler.handle(makeRegister("100", "192.168.34.10", "reg-100e"));
	handler.handle(makeRegister("106", "192.168.34.20", "reg-106e"));
	handler.handle(makeRegister("107", "192.168.34.30", "reg-107e"));

	const std::string callId = "blindxfer-197-hold";
	connectCall(handler, sent, callId,
		"100", transferorAddr, "atag", sdpBodyFor("10.1.1.1", 10001),
		"106", transfereeAddr, "btag", sdpBodyFor("10.2.2.2", 20002));

	// ── A puts B on hold, exactly as a phone does before offering a transfer ───
	const std::string holdVia = "Via: SIP/2.0/UDP 192.168.34.10:5060;branch=z9hG4bKhold";
	{
		std::string body = sdpBodyFor("10.1.1.1", 10001, "sendonly");
		std::string raw =
			"INVITE sip:106@server SIP/2.0\r\n" +
			holdVia + "\r\n"
			"From: <sip:100@server>;tag=atag\r\n"
			"To: <sip:106@server>;tag=btag\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 2 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:100@192.168.34.10:5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(raw, transferorAddr));
	}
	{
		std::string body = sdpBodyFor("10.2.2.2", 20002, "recvonly");
		std::string raw =
			"SIP/2.0 200 OK\r\n" +
			holdVia + "\r\n"
			"From: <sip:100@server>;tag=atag\r\n"
			"To: <sip:106@server>;tag=btag\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 2 INVITE\r\n"
			"Contact: <sip:106@192.168.34.20:5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(raw, transfereeAddr));
	}

	handler.handle(makeRefer(callId, "100", transferorAddr, "atag", "106", "btag", "107"));

	std::string inviteToC = findSentTo(sent, targetAddr, "INVITE sip:107@");
	ASSERT_FALSE(inviteToC.empty()) << "the transfer must still reach the target";
	EXPECT_EQ(inviteToC.find("a=recvonly"), std::string::npos)
		<< "the held direction must not be relayed into the new leg — that is one-way audio:\n"
		<< inviteToC;
	EXPECT_EQ(inviteToC.find("a=inactive"), std::string::npos) << inviteToC;
	EXPECT_NE(inviteToC.find("a=sendrecv"), std::string::npos) << inviteToC;
	// The address/port are the transferee's own and are NOT invented for it.
	EXPECT_NE(inviteToC.find("c=IN IP4 10.2.2.2"), std::string::npos) << inviteToC;
}

// RFC 5589 §6.1: a transferor's phone commonly hangs up its own leg the moment
// it sees the sipfrag NOTIFY rather than waiting for the server's BYE — so that
// BYE crosses ours on the wire and lands on a dialog the server has already
// re-purposed as the transferee's half of the bridge. Relaying it (which the
// bridge-teardown branch does for a BYE from the party still ON the dialog)
// would tear down the transfer a beat after it completed.
TEST(BlindTransfer, TransferorsOwnByeDoesNotTearDownTheCompletedTransfer)
{
	SentList sent;
	RequestsHandler handler("192.168.35.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in transferorAddr = addrFor("192.168.35.10"); // A: 100
	const sockaddr_in transfereeAddr = addrFor("192.168.35.20"); // B: 106
	const sockaddr_in targetAddr     = addrFor("192.168.35.30"); // C: 107

	handler.handle(makeRegister("100", "192.168.35.10", "reg-100f"));
	handler.handle(makeRegister("106", "192.168.35.20", "reg-106f"));
	handler.handle(makeRegister("107", "192.168.35.30", "reg-107f"));

	const std::string callId = "blindxfer-197-race";
	connectCall(handler, sent, callId,
		"100", transferorAddr, "atag", sdpBodyFor("10.1.1.1", 10001),
		"106", transfereeAddr, "btag", sdpBodyFor("10.2.2.2", 20002));
	handler.handle(makeRefer(callId, "100", transferorAddr, "atag", "106", "btag", "107"));

	std::string inviteToC = findSentTo(sent, targetAddr, "INVITE sip:107@");
	ASSERT_FALSE(inviteToC.empty());
	const std::string legCallId = extractHeaderLine(inviteToC, "Call-ID:");
	{
		std::string body = sdpBodyFor("10.3.3.3", 30003);
		std::string raw =
			"SIP/2.0 200 OK\r\n" +
			extractHeaderLine(inviteToC, "Via:") + "\r\n" +
			extractHeaderLine(inviteToC, "From:") + "\r\n"
			"To: <sip:107@192.168.35.1:5060>;tag=ctag\r\n" +
			legCallId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Contact: <sip:107@192.168.35.30:5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(raw, targetAddr));
	}
	ASSERT_TRUE(handler.getSession(legCallId).has_value());

	// ── The transferor hangs up its own (already BYEd) leg ────────────────────
	const size_t beforeRaceBye = sent.size();
	{
		std::string raw =
			"BYE sip:106@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.35.10:5060;branch=z9hG4bKrace\r\n"
			"From: <sip:100@server>;tag=atag\r\n"
			"To: <sip:106@server>;tag=btag\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 3 BYE\r\n"
			"Max-Forwards: 70\r\n"
			"Content-Length: 0\r\n\r\n";
		handler.handle(RequestsHandler::getMessageFromPool(raw, transferorAddr));
	}

	EXPECT_FALSE(findSentTo(sent, transferorAddr, "SIP/2.0 200 OK").empty())
		<< "the stale BYE must still be answered — it is a well-formed request";
	for (size_t i = beforeRaceBye; i < sent.size(); ++i)
	{
		if (!sent[i].second) continue;
		EXPECT_TRUE(sent[i].second->toString().compare(0, 4, "BYE ") != 0)
			<< "nobody may be hung up on by the transferor's own stale BYE: "
			<< sent[i].second->toString();
	}
	EXPECT_TRUE(handler.getSession("Call-ID: " + callId).has_value())
		<< "the transferee's half of the bridge must survive";
	EXPECT_TRUE(handler.getSession(legCallId).has_value())
		<< "the target's half of the bridge must survive";
}

// The target can refuse. The transferor is already gone by then, so nothing can
// recover the call — but the leg is a server-originated INVITE, which means the
// 486 is OURS to ACK (RFC 3261 §17.1.1.3, in the INVITE's own branch) and the
// transferee is ours to release. Left alone, the target retransmits its 486
// until Timer H and the transferee sits on a dialog with nobody on either end.
TEST(BlindTransfer, TargetRefusalIsAckedAndTheTransfereeIsReleased)
{
	SentList sent;
	RequestsHandler handler("192.168.36.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in transferorAddr = addrFor("192.168.36.10"); // A: 100
	const sockaddr_in transfereeAddr = addrFor("192.168.36.20"); // B: 106
	const sockaddr_in targetAddr     = addrFor("192.168.36.30"); // C: 107

	handler.handle(makeRegister("100", "192.168.36.10", "reg-100g"));
	handler.handle(makeRegister("106", "192.168.36.20", "reg-106g"));
	handler.handle(makeRegister("107", "192.168.36.30", "reg-107g"));

	const std::string callId = "blindxfer-197-busy";
	connectCall(handler, sent, callId,
		"100", transferorAddr, "atag", sdpBodyFor("10.1.1.1", 10001),
		"106", transfereeAddr, "btag", sdpBodyFor("10.2.2.2", 20002));
	handler.handle(makeRefer(callId, "100", transferorAddr, "atag", "106", "btag", "107"));

	std::string inviteToC = findSentTo(sent, targetAddr, "INVITE sip:107@");
	ASSERT_FALSE(inviteToC.empty());
	const std::string legCallId  = extractHeaderLine(inviteToC, "Call-ID:");
	const std::string legVia     = extractHeaderLine(inviteToC, "Via:");
	const std::string inviteBranch = branchOf(legVia);
	ASSERT_FALSE(inviteBranch.empty());

	{
		std::string raw =
			"SIP/2.0 486 Busy Here\r\n" +
			legVia + "\r\n" +
			extractHeaderLine(inviteToC, "From:") + "\r\n"
			"To: <sip:107@192.168.36.1:5060>;tag=ctag\r\n" +
			legCallId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Content-Length: 0\r\n\r\n";
		handler.handle(RequestsHandler::getMessageFromPool(raw, targetAddr));
	}

	std::string ackToC = findSentTo(sent, targetAddr, "ACK sip:");
	ASSERT_FALSE(ackToC.empty()) << "a non-2xx final to OUR INVITE must be ACKed";
	EXPECT_EQ(branchOf(extractHeaderLine(ackToC, "Via:")), inviteBranch)
		<< "the ACK must travel in the INVITE's own transaction (same branch), or the "
		   "target keeps retransmitting:\n" << ackToC;

	std::string byeToB = findSentTo(sent, transfereeAddr, "BYE sip:");
	ASSERT_FALSE(byeToB.empty())
		<< "the transferee has nobody left on either side — it must not be abandoned there";
	EXPECT_NE(byeToB.find("Call-ID: " + callId), std::string::npos) << byeToB;

	EXPECT_FALSE(handler.getSession(legCallId).has_value());
	EXPECT_FALSE(handler.getSession("Call-ID: " + callId).has_value());
}

// The transferee can give up while the target is still ringing. There is no
// dialog to BYE at that point — the target has sent no To-tag — so the only
// correct teardown is a CANCEL of the INVITE the server still has outstanding
// (RFC 3261 §9.1). Without it the target rings on after everyone has gone.
TEST(BlindTransfer, TransfereeHangingUpWhileTheTargetRingsCancelsTheLeg)
{
	SentList sent;
	RequestsHandler handler("192.168.37.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in transferorAddr = addrFor("192.168.37.10"); // A: 100
	const sockaddr_in transfereeAddr = addrFor("192.168.37.20"); // B: 106
	const sockaddr_in targetAddr     = addrFor("192.168.37.30"); // C: 107

	handler.handle(makeRegister("100", "192.168.37.10", "reg-100h"));
	handler.handle(makeRegister("106", "192.168.37.20", "reg-106h"));
	handler.handle(makeRegister("107", "192.168.37.30", "reg-107h"));

	const std::string callId = "blindxfer-197-giveup";
	connectCall(handler, sent, callId,
		"100", transferorAddr, "atag", sdpBodyFor("10.1.1.1", 10001),
		"106", transfereeAddr, "btag", sdpBodyFor("10.2.2.2", 20002));
	handler.handle(makeRefer(callId, "100", transferorAddr, "atag", "106", "btag", "107"));
	ASSERT_FALSE(findSentTo(sent, targetAddr, "INVITE sip:107@").empty());

	{
		std::string raw =
			"BYE sip:100@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.37.20:5060;branch=z9hG4bKgiveup\r\n"
			"From: <sip:106@server>;tag=btag\r\n"
			"To: <sip:100@server>;tag=atag\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 5 BYE\r\n"
			"Max-Forwards: 70\r\n"
			"Content-Length: 0\r\n\r\n";
		handler.handle(RequestsHandler::getMessageFromPool(raw, transfereeAddr));
	}

	EXPECT_FALSE(findSentTo(sent, targetAddr, "CANCEL sip:107@").empty())
		<< "the still-ringing target must be CANCELled, not left ringing";
	EXPECT_FALSE(handler.getSession("Call-ID: " + callId).has_value());
}

// Once the bridge is up, a BYE from either survivor must reach the other — they
// are on two separate dialogs that only the server's bookkeeping links, so the
// raw BYE cannot simply be forwarded (the far phone would 481 a Call-ID it has
// never held). Same contract the attended splice has, now exercised for blind.
TEST(BlindTransfer, PostTransferByeFromTheTransfereeReachesTheTarget)
{
	SentList sent;
	RequestsHandler handler("192.168.38.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in transferorAddr = addrFor("192.168.38.10"); // A: 100
	const sockaddr_in transfereeAddr = addrFor("192.168.38.20"); // B: 106
	const sockaddr_in targetAddr     = addrFor("192.168.38.30"); // C: 107

	handler.handle(makeRegister("100", "192.168.38.10", "reg-100i"));
	handler.handle(makeRegister("106", "192.168.38.20", "reg-106i"));
	handler.handle(makeRegister("107", "192.168.38.30", "reg-107i"));

	const std::string callId = "blindxfer-197-teardown";
	connectCall(handler, sent, callId,
		"100", transferorAddr, "atag", sdpBodyFor("10.1.1.1", 10001),
		"106", transfereeAddr, "btag", sdpBodyFor("10.2.2.2", 20002));
	handler.handle(makeRefer(callId, "100", transferorAddr, "atag", "106", "btag", "107"));

	std::string inviteToC = findSentTo(sent, targetAddr, "INVITE sip:107@");
	ASSERT_FALSE(inviteToC.empty());
	const std::string legCallId = extractHeaderLine(inviteToC, "Call-ID:");
	{
		std::string body = sdpBodyFor("10.3.3.3", 30003);
		std::string raw =
			"SIP/2.0 200 OK\r\n" +
			extractHeaderLine(inviteToC, "Via:") + "\r\n" +
			extractHeaderLine(inviteToC, "From:") + "\r\n"
			"To: <sip:107@192.168.38.1:5060>;tag=ctag\r\n" +
			legCallId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Contact: <sip:107@192.168.38.30:5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(raw, targetAddr));
	}
	ASSERT_TRUE(handler.getSession(legCallId).has_value());

	{
		std::string raw =
			"BYE sip:100@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.38.20:5060;branch=z9hG4bKbye2\r\n"
			"From: <sip:106@server>;tag=btag\r\n"
			"To: <sip:100@server>;tag=atag\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 6 BYE\r\n"
			"Max-Forwards: 70\r\n"
			"Content-Length: 0\r\n\r\n";
		handler.handle(RequestsHandler::getMessageFromPool(raw, transfereeAddr));
	}

	std::string byeToC = findSentTo(sent, targetAddr, "BYE sip:");
	ASSERT_FALSE(byeToC.empty()) << "the target must be told the call ended";
	EXPECT_NE(byeToC.find(legCallId), std::string::npos)
		<< "and told inside ITS OWN dialog, not the transferee's:\n" << byeToC;
	EXPECT_FALSE(handler.getSession(legCallId).has_value());
	EXPECT_FALSE(handler.getSession("Call-ID: " + callId).has_value());
}
