// TargetRefreshContact_test.cpp: issues #198 and #425.
//
// re-INVITE and UPDATE are TARGET-REFRESH requests (RFC 3261 §12.2, RFC 3311
// §5.2): the Contact in the request, and the Contact in its 2xx, replaces the
// receiving UA's remote target for the dialog. The PBX keeps itself in the
// signalling path at call setup by presenting each phone to the other as
// contactFor(<that phone's extension>) — an address on THIS board. Every
// in-dialog target-refresh message it relays or authors must keep doing that, or
// the receiving phone repoints the dialog somewhere else.
//
// Both failures were measured with real pjsua before this test existed:
//
//   #425  A relayed hold re-INVITE and its 200 were forwarded untouched, so each
//         phone learned the OTHER PHONE's real Contact. After one hold the BYE
//         went phone-to-phone, the PBX never saw it, and /api/status kept a
//         ghost 601<->602 session after both phones had hung up.
//
//   #198  onUpdate()'s bodiless branch (a session-timer refresh) answered EVERY
//         refresh itself, before any per-leg logic. On a relay call the far phone
//         therefore never saw the refresh, its own session timer expired, and it
//         hung up a healthy call ("408 No session refresh received") -- the
//         ~30-minute drop at Session-Expires: 1800. On a leg the PBX terminates
//         (777) the locally built 200 was a clone of the request and carried the
//         CALLER's own Contact, so the caller repointed the dialog at itself and
//         its next refresh and its BYE looped to its own socket.
//
// Each test drives a real RequestsHandler through handle(), the same way
// BroadcastHoldResume_test.cpp does, and asserts on the Contact header of what
// actually reached each phone. Absence is never the only assertion: every "the
// caller's real address is gone" is paired with "the PBX's address is there".

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

	const char* const kPbxIp = "192.168.30.1";
	const char* const kCallerIp = "192.168.30.10";
	const char* const kCalleeIp = "192.168.30.20";

	sockaddr_in addrFor(const std::string& ip, uint16_t port = 5060)
	{
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_addr.s_addr = inet_addr(ip.c_str());
		a.sin_port = htons(port);
		return a;
	}

	// The exact Contact the PBX presents for `ext` -- RequestsHandler::buildContact().
	std::string pbxContactFor(const std::string& ext)
	{
		return "Contact: <sip:" + ext + "@" + kPbxIp + ":5060;transport=UDP>";
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

	std::string sdpBody(const char* direction)
	{
		return std::string(
			"v=0\r\n"
			"o=- 0 0 IN IP4 10.0.0.1\r\n"
			"s=-\r\n"
			"c=IN IP4 10.0.0.1\r\n"
			"t=0 0\r\n"
			"m=audio 10000 RTP/AVP 0\r\n"
			"a=rtpmap:0 PCMU/8000\r\n") + "a=" + direction + "\r\n";
	}

	// The most recent message sent to `addr` whose text contains `needle`.
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

	size_t countSentTo(const Sent& sent, const sockaddr_in& addr, const std::string& needle)
	{
		size_t n = 0;
		for (const auto& [a, msg] : sent)
		{
			if (a.sin_addr.s_addr != addr.sin_addr.s_addr || a.sin_port != addr.sin_port) continue;
			if (msg && msg->toString().find(needle) != std::string::npos) ++n;
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

	// A caller-side in-dialog request (re-INVITE or UPDATE) carrying the caller's
	// REAL Contact, exactly as a phone sends it.
	std::shared_ptr<SipMessage> callerInDialog(const std::string& method, const std::string& ruriUser,
	                                           const std::string& callId, const std::string& dialogTo,
	                                           int cseq, const std::string& branch, const char* direction)
	{
		std::string body = direction ? sdpBody(direction) : std::string();
		std::string raw =
			method + " sip:" + ruriUser + "@" + kPbxIp + ":5060 SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(kCallerIp) + ":5060;branch=" + branch + "\r\n"
			"From: <sip:100@server>;tag=ft" + callId + "\r\n" +
			dialogTo + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: " + std::to_string(cseq) + " " + method + "\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:100@" + std::string(kCallerIp) + ":5060>\r\n"
			"Session-Expires: 90;refresher=uac\r\n" +
			(direction ? "Content-Type: application/sdp\r\n" : "") +
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(kCallerIp));
	}

	// The callee's 200 to an in-dialog request, carrying the callee's REAL Contact.
	std::shared_ptr<SipMessage> calleeOk(const std::string& method, const std::string& callId,
	                                     const std::string& dialogTo, int cseq, const std::string& branch,
	                                     const char* direction)
	{
		std::string body = direction ? sdpBody(direction) : std::string();
		std::string raw =
			"SIP/2.0 200 OK\r\n"
			"Via: SIP/2.0/UDP " + std::string(kCallerIp) + ":5060;branch=" + branch + "\r\n"
			"From: <sip:100@server>;tag=ft" + callId + "\r\n" +
			dialogTo + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: " + std::to_string(cseq) + " " + method + "\r\n"
			"Contact: <sip:106@" + std::string(kCalleeIp) + ":5060>\r\n" +
			(direction ? "Content-Type: application/sdp\r\n" : "") +
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(kCalleeIp));
	}

	// Sets up an ordinary 100 -> 106 call answered by 106, and returns the To line
	// (with 106's tag) that the caller will echo on every in-dialog request.
	std::string connectOrdinaryCall(RequestsHandler& handler, Sent& sent, const std::string& callId)
	{
		handler.handle(makeRegister("100", kCallerIp));
		handler.handle(makeRegister("106", kCalleeIp));

		std::string body = sdpBody("sendrecv");
		std::string invite =
			"INVITE sip:106@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(kCallerIp) + ":5060;branch=z9hG4bKinv" + callId + "\r\n"
			"From: <sip:100@server>;tag=ft" + callId + "\r\n"
			"To: <sip:106@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:100@" + std::string(kCallerIp) + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(invite, addrFor(kCallerIp)));

		std::string fork = findSentTo(sent, addrFor(kCalleeIp), "INVITE sip:106@");
		EXPECT_FALSE(fork.empty()) << "the call must be forwarded to 106";
		std::string ok =
			"SIP/2.0 200 OK\r\n" +
			headerLine(fork, "Via:") + "\r\n" +
			headerLine(fork, "From:") + "\r\n"
			"To: <sip:106@server>;tag=ans106\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Contact: <sip:106@" + std::string(kCalleeIp) + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(ok, addrFor(kCalleeIp)));

		std::string callerOk = findSentTo(sent, addrFor(kCallerIp), "CSeq: 1 INVITE");
		EXPECT_FALSE(callerOk.empty()) << "the caller must receive the setup 200";
		// Sanity: at setup the PBX already presents 106 as itself. This is the
		// identity every later target refresh has to keep.
		EXPECT_NE(callerOk.find(pbxContactFor("106")), std::string::npos)
			<< "precondition: the setup 200 presents 106 via the PBX";
		return headerLine(callerOk, "To:");
	}
}

// ── #425: hold re-INVITE ─────────────────────────────────────────────────────

TEST(TargetRefreshContact, RelayedHoldReinviteReachesTheCalleeWithThePbxContactForTheCaller)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	const std::string callId = "trc-hold-req";
	const std::string dialogTo = connectOrdinaryCall(handler, sent, callId);

	handler.handle(callerInDialog("INVITE", "106", callId, dialogTo, 2, "z9hG4bKhold", "sendonly"));

	std::string atCallee = findSentTo(sent, addrFor(kCalleeIp), "CSeq: 2 INVITE");
	ASSERT_FALSE(atCallee.empty()) << "the hold re-INVITE must be relayed to 106";
	EXPECT_NE(atCallee.find("a=sendonly"), std::string::npos) << "the hold SDP must still arrive intact";
	EXPECT_EQ(headerLine(atCallee, "Contact:"), pbxContactFor("100"))
		<< "#425: the callee must see the caller via the PBX, the same identity as at setup";
	EXPECT_EQ(atCallee.find(std::string(kCallerIp) + ":5060>"), std::string::npos)
		<< "#425: the caller's real address must not reach the callee as a target";
}

TEST(TargetRefreshContact, RelayedOkToHoldReachesTheCallerWithThePbxContactForTheCallee)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	const std::string callId = "trc-hold-ok";
	const std::string dialogTo = connectOrdinaryCall(handler, sent, callId);

	handler.handle(callerInDialog("INVITE", "106", callId, dialogTo, 2, "z9hG4bKhold", "sendonly"));
	handler.handle(calleeOk("INVITE", callId, dialogTo, 2, "z9hG4bKhold", "sendonly"));

	std::string atCaller = findSentTo(sent, addrFor(kCallerIp), "CSeq: 2 INVITE");
	ASSERT_FALSE(atCaller.empty()) << "106's 200 to the hold must be relayed to the caller";
	EXPECT_NE(atCaller.find("SIP/2.0 200 OK"), std::string::npos);
	EXPECT_EQ(headerLine(atCaller, "Contact:"), pbxContactFor("106"))
		<< "#425: the caller must keep seeing 106 via the PBX, or its BYE goes phone-to-phone";
	EXPECT_EQ(atCaller.find(std::string(kCalleeIp) + ":5060>"), std::string::npos)
		<< "#425: 106's real address must not reach the caller as a target";
}

// ── #198: session-refresh UPDATE on an ordinary (relay) call ─────────────────

TEST(TargetRefreshContact, BodilessRefreshUpdateOnARelayCallIsForwardedNotAnsweredByThePbx)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	const std::string callId = "trc-upd-relay";
	const std::string dialogTo = connectOrdinaryCall(handler, sent, callId);

	handler.handle(callerInDialog("UPDATE", "106", callId, dialogTo, 2, "z9hG4bKupd", nullptr));

	// Positive evidence first: the far phone actually receives the refresh.
	std::string atCallee = findSentTo(sent, addrFor(kCalleeIp), "CSeq: 2 UPDATE");
	ASSERT_FALSE(atCallee.empty())
		<< "#198: the refresh must reach 106, or 106's own session timer expires and it hangs up";
	EXPECT_NE(atCallee.find("UPDATE sip:"), std::string::npos) << "106 must receive the request itself";
	EXPECT_EQ(headerLine(atCallee, "Contact:"), pbxContactFor("100"))
		<< "UPDATE is a target refresh: the callee must keep seeing the caller via the PBX";

	// ...and the PBX did not answer it itself on the far phone's behalf.
	EXPECT_EQ(countSentTo(sent, addrFor(kCallerIp), "CSeq: 2 UPDATE"), 0u)
		<< "#198: the PBX must not answer a relay-call refresh itself; the 200 is 106's to give";

	// 106 answers; exactly that answer reaches the caller, presenting 106 via the PBX.
	handler.handle(calleeOk("UPDATE", callId, dialogTo, 2, "z9hG4bKupd", nullptr));
	std::string atCaller = findSentTo(sent, addrFor(kCallerIp), "CSeq: 2 UPDATE");
	ASSERT_FALSE(atCaller.empty()) << "106's 200 to the refresh must be relayed to the caller";
	EXPECT_NE(atCaller.find("SIP/2.0 200 OK"), std::string::npos);
	EXPECT_EQ(headerLine(atCaller, "Contact:"), pbxContactFor("106"));
	EXPECT_EQ(countSentTo(sent, addrFor(kCallerIp), "CSeq: 2 UPDATE"), 1u)
		<< "exactly one 200 to the refresh: 106's, relayed";
}

TEST(TargetRefreshContact, SdpUpdateOnARelayCallReachesTheCalleeWithThePbxContact)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	const std::string callId = "trc-upd-sdp";
	const std::string dialogTo = connectOrdinaryCall(handler, sent, callId);

	handler.handle(callerInDialog("UPDATE", "106", callId, dialogTo, 2, "z9hG4bKupds", "sendonly"));

	std::string atCallee = findSentTo(sent, addrFor(kCalleeIp), "CSeq: 2 UPDATE");
	ASSERT_FALSE(atCallee.empty()) << "an SDP UPDATE must be relayed to 106";
	EXPECT_NE(atCallee.find("a=sendonly"), std::string::npos) << "the SDP must arrive intact";
	EXPECT_EQ(headerLine(atCallee, "Contact:"), pbxContactFor("100"));
}

// ── #198: refresh on an INBOUND anchored call (PSTN -> handset) ──────────────
// Review catch on #439 (G-dubs). The session's src is the synthetic PSTN peer,
// allocated with a ZEROED address; dest is the handset. It is neither 555, 777
// nor a trunk, so the first cut of the reordered onUpdate() classified it as a
// relay dialog and forwarded the handset's refresh to 0.0.0.0 -- never answered
// -- where main had answered it locally. The PBX is the handset's UAS here.

TEST(TargetRefreshContact, BodilessRefreshOnAnInboundAnchoredCallIsAnsweredLocallyNotSentToThePstnPeer)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	handler.handle(makeRegister("106", kCalleeIp));

	const std::string callIdLine = handler.routeInboundAnchorCallForTest("106", "part-inbound-1", "5551234567");
	ASSERT_FALSE(callIdLine.empty()) << "precondition: an inbound anchored session must exist";

	// The handset must ANSWER first. Before the answer the session has no dest,
	// and `!dest` already routes to the local answer -- a green result for the
	// wrong reason (the first draft of this test passed on the broken code for
	// exactly that). The review's case is the answered call: dest == handset.
	handler.tick();   // drainOutbox() merges _asyncOutbox, where the fork INVITE waits
	const std::string fork = findSentTo(sent, addrFor(kCalleeIp), "INVITE sip:106@");
	ASSERT_FALSE(fork.empty()) << "precondition: the inbound call must be forked to the handset";
	{
		std::string body = sdpBody("sendrecv");
		std::string ok =
			"SIP/2.0 200 OK\r\n" +
			headerLine(fork, "Via:") + "\r\n" +
			headerLine(fork, "From:") + "\r\n"
			"To: <sip:106@" + std::string(kPbxIp) + ">;tag=hs106\r\n" +
			callIdLine + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Contact: <sip:106@" + std::string(kCalleeIp) + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(ok, addrFor(kCalleeIp)));
	}
	auto sess = handler.getSession(callIdLine);
	ASSERT_TRUE(sess.has_value());
	ASSERT_EQ(sess.value()->getState(), Session::State::Connected) << "precondition: the handset answered";
	ASSERT_TRUE(sess.value()->getDest()) << "precondition: dest is the handset, the review's case";
	ASSERT_EQ(sess.value()->getDest()->getNumber(), "106");

	// The handset's in-dialog refresh. On this dialog the PBX's own From/Contact
	// user is the handset's DN (buildInboundInviteFork), so the refresh's To-user
	// is 106 and the Contact the handset was offered is contactFor("106").
	std::string raw =
		"UPDATE sip:106@" + std::string(kPbxIp) + ":5060 SIP/2.0\r\n"
		"Via: SIP/2.0/UDP " + std::string(kCalleeIp) + ":5060;branch=z9hG4bKinbupd\r\n"
		"From: <sip:106@" + std::string(kPbxIp) + ">;tag=hs106\r\n"
		"To: <sip:106@" + std::string(kPbxIp) + ":5060>;tag=pbxtag\r\n" +
		callIdLine + "\r\n"
		"CSeq: 2 UPDATE\r\n"
		"Contact: <sip:106@" + std::string(kCalleeIp) + ":5060>\r\n"
		"Session-Expires: 90;refresher=uac\r\n"
		"Content-Length: 0\r\n\r\n";
	handler.handle(RequestsHandler::getMessageFromPool(raw, addrFor(kCalleeIp)));

	size_t toZero = 0;
	for (const auto& [a, msg] : sent)
	{
		if (a.sin_addr.s_addr == 0 && msg && msg->toString().find("CSeq: 2 UPDATE") != std::string::npos) ++toZero;
	}
	EXPECT_EQ(toZero, 0u) << "the refresh must never be relayed to the PSTN peer's zeroed address";

	std::string atHandset = findSentTo(sent, addrFor(kCalleeIp), "CSeq: 2 UPDATE");
	ASSERT_FALSE(atHandset.empty()) << "the PBX is the handset's UAS here: it must answer the refresh";
	EXPECT_NE(atHandset.find("SIP/2.0 200 OK"), std::string::npos);
	EXPECT_EQ(headerLine(atHandset, "Contact:"), pbxContactFor("106"))
		<< "the answer must carry the Contact the handset was offered on this dialog";
}

// ── #198: session-refresh UPDATE on a leg the PBX terminates (777) ───────────

TEST(TargetRefreshContact, BodilessRefreshUpdateOn777IsAnsweredWithThePbxsOwnContact)
{
	Sent sent;
	RequestsHandler handler(kPbxIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });
	handler.handle(makeRegister("100", kCallerIp));

	const std::string callId = "trc-upd-777";
	std::string body = sdpBody("sendrecv");
	std::string invite =
		"INVITE sip:777@server SIP/2.0\r\n"
		"Via: SIP/2.0/UDP " + std::string(kCallerIp) + ":5060;branch=z9hG4bKinv777\r\n"
		"From: <sip:100@server>;tag=ft" + callId + "\r\n"
		"To: <sip:777@server>\r\n"
		"Call-ID: " + callId + "\r\n"
		"CSeq: 1 INVITE\r\n"
		"Max-Forwards: 70\r\n"
		"Contact: <sip:100@" + std::string(kCallerIp) + ":5060>\r\n"
		"Content-Type: application/sdp\r\n"
		"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
	handler.handle(RequestsHandler::getMessageFromPool(invite, addrFor(kCallerIp)));

	std::string setupOk = findSentTo(sent, addrFor(kCallerIp), "CSeq: 1 INVITE");
	ASSERT_NE(setupOk.find("SIP/2.0 200 OK"), std::string::npos) << "precondition: 777 answers";
	ASSERT_EQ(headerLine(setupOk, "Contact:"), pbxContactFor("777"))
		<< "precondition: 777's setup 200 presents the PBX as 777";
	const std::string dialogTo = headerLine(setupOk, "To:");

	handler.handle(callerInDialog("UPDATE", "777", callId, dialogTo, 2, "z9hG4bKupd777", nullptr));

	std::string atCaller = findSentTo(sent, addrFor(kCallerIp), "CSeq: 2 UPDATE");
	ASSERT_FALSE(atCaller.empty()) << "777 has no peer: the PBX must answer the refresh itself";
	EXPECT_NE(atCaller.find("SIP/2.0 200 OK"), std::string::npos) << "a refresh on a live 777 leg succeeds";
	EXPECT_EQ(headerLine(atCaller, "Contact:"), pbxContactFor("777"))
		<< "#198: the PBX's 200 must carry the PBX's Contact, the same identity as the setup 200";
	EXPECT_EQ(atCaller.find(std::string(kCallerIp) + ":5060>"), std::string::npos)
		<< "#198: echoing the caller's own Contact repoints the caller's dialog at itself";
}
