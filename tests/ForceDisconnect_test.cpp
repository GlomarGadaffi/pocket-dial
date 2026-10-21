// Issue #228: RequestsHandler::forceDisconnect() (the engine behind /api/kill)
// used to tear a call down entirely server-side — erase the Session, release
// the pool slot, stop any owned RTP — and send NOTHING to either phone. The
// far end kept a call the PBX had forgotten; P2P media carried on until one
// side hung up locally into a 481.
//
// Worse than the missing BYE: the inline erase bypassed endCall(), the one
// teardown path that also forgets the DTMF accumulator, frees the transaction-
// layer slots for the Call-ID (#226), clears park/conference state and writes
// the CDR record. And it released the SipClient (which clears its number)
// BEFORE the "is this extension on the session" comparison, so the comparison
// could never match and no session was ever removed at all.
//
// Every test here drives a real RequestsHandler through handle() end to end and
// then calls forceDisconnect() the way sendApiKill() does, off the SIP thread's
// pass. The BYEs go to _asyncOutbox (HTTP-thread rule), so a follow-up packet
// on the SIP thread is what flushes them — the tests send a bare OPTIONS from an
// unrelated address for that and then look at what went out.

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
	constexpr const char* kServerIp = "192.168.40.1";
	constexpr const char* kCallerIp = "192.168.40.10";
	constexpr const char* kCalleeIp = "192.168.40.20";
	constexpr const char* kOtherIp  = "192.168.40.99";

	using Sent = std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>;

	sockaddr_in addrFor(const std::string& ip, uint16_t port = 5060)
	{
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_addr.s_addr = inet_addr(ip.c_str());
		a.sin_port = htons(port);
		return a;
	}

	bool sameAddr(const sockaddr_in& a, const sockaddr_in& b)
	{
		return a.sin_addr.s_addr == b.sin_addr.s_addr && a.sin_port == b.sin_port;
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

	// 100 INVITEs 106. Returns nothing; the caller decides whether 106 answers.
	void sendInvite(RequestsHandler& handler, const std::string& callId)
	{
		std::string body = sdpBody(kCallerIp);
		std::string raw =
			"INVITE sip:106@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(kCallerIp) + ":5060;branch=z9hG4bKi" + callId + "\r\n"
			"From: <sip:100@server>;tag=ctag" + callId + "\r\n"
			"To: <sip:106@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:100@" + std::string(kCallerIp) + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(raw, addrFor(kCallerIp)));
	}

	// 106 answers 100's INVITE. Deliberately NOT followed by an ACK, so the
	// #226 INVITE server transaction for the relayed 200 OK stays occupied —
	// that is what lets a test see endCall()'s freeForCallId() actually run.
	void sendAnswer(RequestsHandler& handler, const std::string& callId)
	{
		std::string body = sdpBody(kCalleeIp);
		std::string raw =
			"SIP/2.0 200 OK\r\n"
			"Via: SIP/2.0/UDP " + std::string(kCallerIp) + ":5060;branch=z9hG4bKi" + callId + "\r\n"
			"From: <sip:100@server>;tag=ctag" + callId + "\r\n"
			"To: <sip:106@server>;tag=etag" + callId + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Contact: <sip:106@" + std::string(kCalleeIp) + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(raw, addrFor(kCalleeIp)));
	}

	// One RFC 2833-relay digit from 100 on the dialog, so the DTMF accumulator
	// for this Call-ID exists and its fate can be observed.
	void sendDigit(RequestsHandler& handler, const std::string& callId, char digit)
	{
		std::string body = std::string("Signal=") + digit + "\r\nDuration=100\r\n";
		std::string raw =
			"INFO sip:106@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(kCallerIp) + ":5060;branch=z9hG4bKinfo" + callId + "\r\n"
			"From: <sip:100@server>;tag=ctag" + callId + "\r\n"
			"To: <sip:106@server>;tag=etag" + callId + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 2 INFO\r\n"
			"Content-Type: application/dtmf-relay\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(raw, addrFor(kCallerIp)));
	}

	// The SIP thread's next pass is what drains _asyncOutbox. A bare OPTIONS
	// from an address that is on no dialog stands in for it.
	void flushAsyncOutbox(RequestsHandler& handler)
	{
		std::string raw =
			"OPTIONS sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(kOtherIp) + ":5060;branch=z9hG4bKflush\r\n"
			"From: <sip:probe@server>;tag=probetag\r\n"
			"To: <sip:server@server>\r\n"
			"Call-ID: flush-228\r\n"
			"CSeq: 1 OPTIONS\r\n"
			"Max-Forwards: 70\r\n"
			"Content-Length: 0\r\n\r\n";
		handler.handle(RequestsHandler::getMessageFromPool(raw, addrFor(kOtherIp)));
	}

	std::string headerValue(const std::string& raw, const std::string& name)
	{
		size_t pos = 0;
		while (pos < raw.size())
		{
			size_t eol = raw.find("\r\n", pos);
			if (eol == std::string::npos) eol = raw.size();
			if (eol == pos) break;
			if (raw.compare(pos, name.size(), name) == 0 &&
				pos + name.size() < raw.size() && raw[pos + name.size()] == ':')
			{
				size_t v = pos + name.size() + 1;
				while (v < eol && (raw[v] == ' ' || raw[v] == '\t')) ++v;
				return raw.substr(v, eol - v);
			}
			pos = eol + 2;
		}
		return {};
	}

	// Every BYE in `sent` addressed to `to`, as raw text.
	std::vector<std::string> byesTo(const Sent& sent, const sockaddr_in& to)
	{
		std::vector<std::string> out;
		for (const auto& [addr, msg] : sent)
		{
			if (!msg || !sameAddr(addr, to)) continue;
			std::string raw = msg->toString();
			if (raw.rfind("BYE ", 0) == 0) out.push_back(raw);
		}
		return out;
	}

	struct Rig
	{
		Sent sent;
		RequestsHandler handler;

		Rig() : handler(kServerIp, 5060,
			[this](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
				sent.emplace_back(addr, std::move(msg));
			})
		{
			handler.handle(makeRegister("100", kCallerIp, "reg-100"));
			handler.handle(makeRegister("106", kCalleeIp, "reg-106"));
		}
	};
}

TEST(ForceDisconnect, ConnectedCallByesBothLegsOnTheRightDialog)
{
	Rig rig;
	const std::string callId = "kill-228-a";
	sendInvite(rig.handler, callId);
	sendAnswer(rig.handler, callId);
	ASSERT_TRUE(rig.handler.getSession("Call-ID: " + callId).has_value())
		<< "precondition: the call must be up before it is killed";

	rig.sent.clear();
	rig.handler.forceDisconnect("100");

	// Nothing may have gone out yet: forceDisconnect() runs off the SIP thread
	// and must not write _outbox. The BYEs surface on the next SIP-thread pass.
	EXPECT_TRUE(rig.sent.empty())
		<< "forceDisconnect() must queue to _asyncOutbox, not send directly";
	flushAsyncOutbox(rig.handler);

	// The far end (106) is the party the issue is about: it must be told.
	const auto toCallee = byesTo(rig.sent, addrFor(kCalleeIp));
	ASSERT_EQ(toCallee.size(), 1u) << "exactly one BYE to the peer phone";
	EXPECT_EQ(toCallee[0].rfind("BYE sip:106@" + std::string(kCalleeIp) + ":5060 SIP/2.0", 0), 0u)
		<< toCallee[0];
	// Server-authored BYE toward the callee impersonates the caller: From is the
	// dialog's From (caller tag), To is the dialog's To (callee tag). A BYE on
	// the wrong tags is dropped by the phone as not matching any dialog.
	EXPECT_NE(headerValue(toCallee[0], "From").find("tag=ctag" + callId), std::string::npos) << toCallee[0];
	EXPECT_NE(headerValue(toCallee[0], "To").find("tag=etag" + callId), std::string::npos) << toCallee[0];
	EXPECT_EQ(headerValue(toCallee[0], "Call-ID"), callId) << toCallee[0];
	EXPECT_EQ(headerValue(toCallee[0], "CSeq"), "2 BYE") << toCallee[0];

	// The killed extension's own handset gets one too, with the roles reversed.
	const auto toCaller = byesTo(rig.sent, addrFor(kCallerIp));
	ASSERT_EQ(toCaller.size(), 1u) << "exactly one BYE to the killed extension";
	EXPECT_EQ(toCaller[0].rfind("BYE sip:100@" + std::string(kCallerIp) + ":5060 SIP/2.0", 0), 0u)
		<< toCaller[0];
	EXPECT_NE(headerValue(toCaller[0], "From").find("tag=etag" + callId), std::string::npos) << toCaller[0];
	EXPECT_NE(headerValue(toCaller[0], "To").find("tag=ctag" + callId), std::string::npos) << toCaller[0];

	EXPECT_FALSE(rig.handler.getSession("Call-ID: " + callId).has_value())
		<< "the session must be gone server-side as well";
}

TEST(ForceDisconnect, RoutesThroughEndCallSideEffects)
{
	Rig rig;
	const std::string callId = "kill-228-b";
	sendInvite(rig.handler, callId);
	sendAnswer(rig.handler, callId);
	sendDigit(rig.handler, callId, '1');

	// Preconditions — each of these is state endCall() owns and the old inline
	// erase left behind. If any is already zero the assertion after the kill
	// proves nothing, so pin them first.
	ASSERT_EQ(rig.handler.dtmfAccumulatorCountForTest(), 1u)
		<< "precondition: the INFO digit must have created an accumulator";
	// No server slot on this shape: a relayed 200 OK belongs to the callee phone,
	// which retransmits it itself, so #226 deliberately does not track it. The
	// server-slot half of endCall()'s cleanup is pinned on the echo leg below.
	// Client slots at this point: the two register-beep INVITEs (unrelated
	// Call-IDs, must survive) plus this call's relayed INVITE (Accepted, waiting
	// on Timer M). Only the last belongs to the killed dialog.
	const size_t clientBefore = rig.handler.getClientTransactionCount();
	ASSERT_GT(clientBefore, 0u)
		<< "precondition: the relayed INVITE must be holding a client slot";
	ASSERT_TRUE(rig.handler.cdrSnapshotForTest().empty())
		<< "precondition: no CDR record before the call ends";

	rig.handler.forceDisconnect("100");
	flushAsyncOutbox(rig.handler);

	EXPECT_EQ(rig.handler.dtmfAccumulatorCountForTest(), 0u)
		<< "endCall() forgets the dialog's DTMF accumulator (Fix #4)";
	// -1: the dialog's INVITE client slot is freed by freeForCallId().
	// +2: the two server BYEs just sent are NON-INVITE client transactions, and
	//     freeForCallId() must leave those alone — cancelling them would cancel
	//     the retransmission that makes this very teardown reliable (#226).
	EXPECT_EQ(rig.handler.getClientTransactionCount(), clientBefore - 1 + 2)
		<< "endCall() frees the INVITE client slot and keeps the BYE slots (#226)";

	const auto cdr = rig.handler.cdrSnapshotForTest();
	ASSERT_EQ(cdr.size(), 1u) << "a force-killed call must still produce exactly one CDR record";
	EXPECT_EQ(cdr[0].caller, "100");
	EXPECT_EQ(cdr[0].callee, "106");
}

TEST(ForceDisconnect, EchoLegFreesTheServerTransactionAndNeverByesTheStandInPeer)
{
	// 100 calls the 777 echo test. The PBX is the UAS: it authors the 200 OK
	// itself, so #226 tracks an INVITE server transaction for it until the ACK
	// (never sent here). The session's "dest" is a stand-in SipClient carrying
	// 100's OWN address, so a "peer" BYE would reach 100 with the tags reversed
	// and must never go out. 100 itself ("src") is the killed handset, though,
	// and since #232 the echo answer path records its own dialog headers on
	// the Session, so exactly one correctly-addressed BYE (from the src leg,
	// not the dest stand-in) reaches this same address now.
	Rig rig;
	const std::string callId = "kill-228-echo";
	{
		std::string body = sdpBody(kCallerIp);
		std::string raw =
			"INVITE sip:777@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(kCallerIp) + ":5060;branch=z9hG4bKi" + callId + "\r\n"
			"From: <sip:100@server>;tag=ctag" + callId + "\r\n"
			"To: <sip:777@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:100@" + std::string(kCallerIp) + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		rig.handler.handle(RequestsHandler::getMessageFromPool(raw, addrFor(kCallerIp)));
	}
	ASSERT_TRUE(rig.handler.getSession("Call-ID: " + callId).has_value());
	ASSERT_GT(rig.handler.getServerTransactionCount(), 0u)
		<< "precondition: the un-ACKed PBX-authored 200 OK must hold a server slot";

	// The echo leg's own 200 OK carries the To-tag #232 now stores on the
	// Session — capture it here (it is random, minted by IDGen) so the BYE
	// below can be checked against the tag this call actually used rather
	// than a value the test would otherwise have to guess.
	std::string echoToTag;
	for (const auto& [addr, msg] : rig.sent)
	{
		if (!msg) continue;
		std::string raw = msg->toString();
		if (raw.rfind("SIP/2.0 200 OK", 0) == 0 && headerValue(raw, "Call-ID") == callId)
		{
			echoToTag = headerValue(raw, "To");
			break;
		}
	}
	ASSERT_NE(echoToTag.find("tag="), std::string::npos)
		<< "precondition: the echo leg's own 200 OK must carry a To-tag";

	rig.sent.clear();
	rig.handler.forceDisconnect("100");
	flushAsyncOutbox(rig.handler);

	// Both the stand-in dest and the real src leg live at kCallerIp (the
	// stand-in carries the caller's OWN address), so this is the one place
	// both halves of forceDisconnect()'s per-leg BYE logic are visible at
	// once: exactly one BYE must cross the wire, and it must be the src leg's
	// (never the dest stand-in's, which the #72/#228 comment above forbids).
	const auto toCaller = byesTo(rig.sent, addrFor(kCallerIp));
	ASSERT_EQ(toCaller.size(), 1u)
		<< "exactly one BYE to the killed handset — the stand-in dest must stay silent (#228) "
		   "while the src leg, which #232 gave a real To-tag, now gets told";
	EXPECT_EQ(toCaller[0].rfind("BYE sip:100@" + std::string(kCallerIp) + ":5060 SIP/2.0", 0), 0u)
		<< toCaller[0];
	// Server-authored BYE impersonates the echo leg itself (the PBX was the
	// UAS on this dialog): From carries the tag #232 recorded from the leg's
	// own 200 OK, To carries the caller's original tag from the INVITE.
	EXPECT_NE(headerValue(toCaller[0], "From").find(echoToTag.substr(echoToTag.find("tag="))),
		std::string::npos) << toCaller[0];
	EXPECT_NE(headerValue(toCaller[0], "To").find("tag=ctag" + callId), std::string::npos) << toCaller[0];
	EXPECT_EQ(rig.handler.getServerTransactionCount(), 0u)
		<< "endCall() frees the INVITE server transaction for the Call-ID (#226)";
	EXPECT_FALSE(rig.handler.getSession("Call-ID: " + callId).has_value());
}

TEST(ForceDisconnect, ToneLegByesTheKilledHandsetOnceAndNeverTheStandInPeer)
{
	// #1003: 100 dials the 440 tone. As on the echo leg above, the PBX is the UAS and the session's "dest" is a
	// stand-in carrying 100's OWN address. The tone answer records its dialog headers (the 10-minute cap BYEs
	// the phone from them), so a kill now has a src BYE to send, and the stand-in must stay silent: a second,
	// tag-reversed BYE to the same phone is the #228 bug.
	Rig rig;
	const std::string callId = "kill-1003-tone";
	{
		std::string body = sdpBody(kCallerIp);
		std::string raw =
			"INVITE sip:440@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(kCallerIp) + ":5060;branch=z9hG4bKi" + callId + "\r\n"
			"From: <sip:100@server>;tag=ctag" + callId + "\r\n"
			"To: <sip:440@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:100@" + std::string(kCallerIp) + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		rig.handler.handle(RequestsHandler::getMessageFromPool(raw, addrFor(kCallerIp)));
	}
	ASSERT_TRUE(rig.handler.getSession("Call-ID: " + callId).has_value())
		<< "precondition: the tone call must be up before it is killed";

	// The tone leg's own 200 OK carries the To-tag the Session must hold: capture it (it is random) so the
	// BYE below is checked against the tag this call actually used.
	std::string toneToTag;
	for (const auto& [addr, msg] : rig.sent)
	{
		if (!msg) continue;
		std::string raw = msg->toString();
		if (raw.rfind("SIP/2.0 200 OK", 0) == 0 && headerValue(raw, "Call-ID") == callId)
		{
			toneToTag = headerValue(raw, "To");
			break;
		}
	}
	ASSERT_NE(toneToTag.find("tag="), std::string::npos)
		<< "precondition: the tone leg's own 200 OK must carry a To-tag";

	rig.sent.clear();
	rig.handler.forceDisconnect("100");
	flushAsyncOutbox(rig.handler);

	const auto toCaller = byesTo(rig.sent, addrFor(kCallerIp));
	ASSERT_EQ(toCaller.size(), 1u)
		<< "exactly one BYE to the killed handset: the src leg's, never the dest stand-in's";
	EXPECT_EQ(toCaller[0].rfind("BYE sip:100@" + std::string(kCallerIp) + ":5060 SIP/2.0", 0), 0u)
		<< toCaller[0];
	EXPECT_NE(headerValue(toCaller[0], "From").find(toneToTag.substr(toneToTag.find("tag="))),
		std::string::npos) << toCaller[0];
	EXPECT_NE(headerValue(toCaller[0], "To").find("tag=ctag" + callId), std::string::npos) << toCaller[0];
	EXPECT_FALSE(rig.handler.getSession("Call-ID: " + callId).has_value());
}

TEST(ForceDisconnect, KillingTheCalleeSideWorksToo)
{
	// The involvement check must match whichever leg the extension is on. This
	// is also the regression for the old release-before-compare ordering: the
	// SipClient's number was cleared before it was compared, so NEITHER side
	// ever matched.
	Rig rig;
	const std::string callId = "kill-228-c";
	sendInvite(rig.handler, callId);
	sendAnswer(rig.handler, callId);

	rig.sent.clear();
	rig.handler.forceDisconnect("106");
	flushAsyncOutbox(rig.handler);

	EXPECT_EQ(byesTo(rig.sent, addrFor(kCallerIp)).size(), 1u) << "the caller (the peer) is told";
	EXPECT_EQ(byesTo(rig.sent, addrFor(kCalleeIp)).size(), 1u) << "the killed callee is told";
	EXPECT_FALSE(rig.handler.getSession("Call-ID: " + callId).has_value());
	EXPECT_EQ(rig.handler.cdrSnapshotForTest().size(), 1u);
}

TEST(ForceDisconnect, RingingCallIsClearedWithoutAMalformedBye)
{
	// No 200 OK yet: no To-tag, no dialog headers. A BYE built from empty
	// From/To is malformed and phones drop it (#72 guard), so none may go out —
	// but the ringing session must still be cleared server-side, as before.
	Rig rig;
	const std::string callId = "kill-228-d";
	sendInvite(rig.handler, callId);
	ASSERT_TRUE(rig.handler.getSession("Call-ID: " + callId).has_value());

	rig.sent.clear();
	rig.handler.forceDisconnect("100");
	flushAsyncOutbox(rig.handler);

	EXPECT_TRUE(byesTo(rig.sent, addrFor(kCallerIp)).empty());
	EXPECT_TRUE(byesTo(rig.sent, addrFor(kCalleeIp)).empty());
	EXPECT_FALSE(rig.handler.getSession("Call-ID: " + callId).has_value());
}

TEST(ForceDisconnect, ExtensionOnNoCallSendsNothingAndLeavesOtherCallsAlone)
{
	Rig rig;
	rig.handler.handle(makeRegister("107", kOtherIp, "reg-107"));
	const std::string callId = "kill-228-e";
	sendInvite(rig.handler, callId);
	sendAnswer(rig.handler, callId);

	rig.sent.clear();
	rig.handler.forceDisconnect("107");
	flushAsyncOutbox(rig.handler);

	EXPECT_TRUE(byesTo(rig.sent, addrFor(kCallerIp)).empty());
	EXPECT_TRUE(byesTo(rig.sent, addrFor(kCalleeIp)).empty());
	EXPECT_TRUE(rig.handler.getSession("Call-ID: " + callId).has_value())
		<< "a call 107 is not on must survive 107's kill";
	EXPECT_TRUE(rig.handler.cdrSnapshotForTest().empty());
}

// Issue #1089: REGISTER Expires: 0 reached unregisterClient(), which released
// the pool SipClient (blanking its number) and ended none of its sessions. The
// sessions kept pointing at the blank client, sweepExpired() matches by number,
// so they leaked their pool slot for good (4 of 8 slots held for 10 h on .195).
namespace
{
	void sendDeregister(RequestsHandler& handler, const std::string& ext, const std::string& ip,
	                    const std::string& callId)
	{
		std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKd" + callId + "\r\n"
			"From: <sip:" + ext + "@server>;tag=dt" + callId + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 2 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + ip + ":5060>;expires=0\r\n"
			"Content-Length: 0\r\n\r\n";
		handler.handle(RequestsHandler::getMessageFromPool(raw, addrFor(ip)));
	}

	void sendCallerBye(RequestsHandler& handler, const std::string& callId)
	{
		std::string raw =
			"BYE sip:106@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + std::string(kCallerIp) + ":5060;branch=z9hG4bKbye" + callId + "\r\n"
			"From: <sip:100@server>;tag=ctag" + callId + "\r\n"
			"To: <sip:106@server>;tag=etag" + callId + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 3 BYE\r\n"
			"Max-Forwards: 70\r\n"
			"Content-Length: 0\r\n\r\n";
		handler.handle(RequestsHandler::getMessageFromPool(raw, addrFor(kCallerIp)));
	}

	// The callee's 200 OK to the relayed BYE: that, not the BYE itself, ends the session.
	void sendCalleeByeOk(RequestsHandler& handler, const std::string& callId)
	{
		std::string raw =
			"SIP/2.0 200 OK\r\n"
			"Via: SIP/2.0/UDP " + std::string(kCallerIp) + ":5060;branch=z9hG4bKbye" + callId + "\r\n"
			"From: <sip:100@server>;tag=ctag" + callId + "\r\n"
			"To: <sip:106@server>;tag=etag" + callId + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 3 BYE\r\n"
			"Content-Length: 0\r\n\r\n";
		handler.handle(RequestsHandler::getMessageFromPool(raw, addrFor(kCalleeIp)));
	}

	bool isBoundExt(RequestsHandler& handler, const std::string& ext)
	{
		handler.forceNextTickForTest();
		handler.tick();
		for (const auto& [number, address] : handler.getActiveClients())
		{
			(void)address;
			if (number == ext) return true;
		}
		return false;
	}

	size_t liveSessions(RequestsHandler& handler)
	{
		handler.forceNextTickForTest();
		handler.tick();
		return handler.getSessionCount();
	}

	// Both legs of a connected call are hung up by a de-REGISTER from `who`.
	void expectDeregisterEndsTheCall(const std::string& who, const std::string& whoIp,
	                                 const std::string& peerIp, const std::string& callId)
	{
		Rig rig;
		sendInvite(rig.handler, callId);
		sendAnswer(rig.handler, callId);
		ASSERT_TRUE(rig.handler.getSession("Call-ID: " + callId).has_value()) << "precondition: call up";
		ASSERT_EQ(liveSessions(rig.handler), 1u) << "precondition: one session";
		ASSERT_TRUE(rig.handler.cdrSnapshotForTest().empty()) << "precondition: no CDR yet";

		rig.sent.clear();
		sendDeregister(rig.handler, who, whoIp, "dereg-" + callId);

		EXPECT_FALSE(rig.handler.getSession("Call-ID: " + callId).has_value());
		EXPECT_EQ(liveSessions(rig.handler), 0u) << "the session slot leaked";
		EXPECT_EQ(byesTo(rig.sent, addrFor(peerIp)).size(), 1u) << "the far party must be told";
		const auto cdr = rig.handler.cdrSnapshotForTest();
		ASSERT_EQ(cdr.size(), 1u) << "exactly one CDR";
		EXPECT_EQ(cdr[0].caller, "100");
		EXPECT_EQ(cdr[0].callee, "106");
		EXPECT_FALSE(isBoundExt(rig.handler, who)) << "the client must still be released";
	}
}

TEST(DeregisterMidCall, CallersDeregisterEndsTheCallByesThePeerAndWritesTheCdr)
{
	expectDeregisterEndsTheCall("100", kCallerIp, kCalleeIp, "dereg-1089-a");
}

TEST(DeregisterMidCall, CalleesDeregisterEndsTheCallByesThePeerAndWritesTheCdr)
{
	expectDeregisterEndsTheCall("106", kCalleeIp, kCallerIp, "dereg-1089-b");
}

TEST(DeregisterMidCall, ADeregisterDuringAnEmergencyCallDefersUntilTheCallEnds)
{
	// Rule 5, matching sweepExpired()'s #712: a de-REGISTER never ends a 911/933
	// and never blanks the number the call's BYE and CDR still read.
	Rig rig;
	const std::string callId = "dereg-1089-911";
	sendInvite(rig.handler, callId);
	sendAnswer(rig.handler, callId);
	auto s = rig.handler.getSession("Call-ID: " + callId);
	ASSERT_TRUE(s.has_value());
	s.value()->setEmergency(true);

	rig.sent.clear();
	sendDeregister(rig.handler, "100", kCallerIp, "dereg-1089-911-r");

	EXPECT_TRUE(rig.handler.getSession("Call-ID: " + callId).has_value()) << "the 911 was torn down";
	EXPECT_TRUE(byesTo(rig.sent, addrFor(kCalleeIp)).empty()) << "the PSAP leg was hung up";
	EXPECT_TRUE(byesTo(rig.sent, addrFor(kCallerIp)).empty());
	ASSERT_TRUE(s.value()->getSrc());
	EXPECT_EQ(s.value()->getSrc()->getNumber(), "100") << "the caller was blanked under the live 911";
	EXPECT_TRUE(rig.handler.cdrSnapshotForTest().empty());
	size_t finals200 = 0;
	for (const auto& [addr, msg] : rig.sent)
		if (msg && sameAddr(addr, addrFor(kCallerIp)) && msg->toString().rfind("SIP/2.0 200", 0) == 0) ++finals200;
	EXPECT_EQ(finals200, 1u) << "the REGISTER is still answered normally";

	// The 911 ends; the next sweep prunes the deferred binding.
	sendCallerBye(rig.handler, callId);
	sendCalleeByeOk(rig.handler, callId);
	ASSERT_FALSE(rig.handler.getSession("Call-ID: " + callId).has_value()) << "precondition: BYE ended it";
	EXPECT_EQ(rig.handler.cdrSnapshotForTest().size(), 1u);
	rig.handler.idleClientAndSweepForTest("100", std::chrono::seconds(0));
	EXPECT_FALSE(isBoundExt(rig.handler, "100")) << "the deferred de-register must complete";
	EXPECT_EQ(liveSessions(rig.handler), 0u);
}

TEST(DeregisterMidCall, ADeregisterWithNoCallsReleasesTheClientAsBefore)
{
	Rig rig;
	ASSERT_TRUE(isBoundExt(rig.handler, "100"));
	rig.sent.clear();
	sendDeregister(rig.handler, "100", kCallerIp, "dereg-1089-idle");
	EXPECT_FALSE(isBoundExt(rig.handler, "100"));
	EXPECT_TRUE(isBoundExt(rig.handler, "106")) << "another extension is untouched";
	EXPECT_TRUE(byesTo(rig.sent, addrFor(kCallerIp)).empty());
	EXPECT_TRUE(byesTo(rig.sent, addrFor(kCalleeIp)).empty());
	EXPECT_TRUE(rig.handler.cdrSnapshotForTest().empty());
	EXPECT_EQ(liveSessions(rig.handler), 0u);
}

// #1089 follow-ups: a freed pool slot is reused by a later REGISTER, the sweep path
// shares the de-register path's BYE and CDR, and a lapsed client on a live call
// keeps its slot.
namespace
{
	size_t byeCount(const Sent& sent, const std::string& ip)
	{
		return byesTo(sent, addrFor(ip)).size();
	}

	void expectLeaseExpiryEndsTheCall(const std::string& who, const char* peerIp, const char* whoIp,
	                                  const std::string& callId)
	{
		Rig rig;
		sendInvite(rig.handler, callId);
		sendAnswer(rig.handler, callId);
		ASSERT_TRUE(rig.handler.getSession("Call-ID: " + callId).has_value());
		rig.sent.clear();

		rig.handler.expireLeaseAndSweepForTest(who);

		EXPECT_EQ(byeCount(rig.sent, peerIp), 1u) << "exactly one BYE to the surviving phone";
		EXPECT_EQ(byeCount(rig.sent, whoIp), 0u) << "none to the phone whose lease lapsed";
		EXPECT_EQ(liveSessions(rig.handler), 0u);
		const auto cdr = rig.handler.cdrSnapshotForTest();
		ASSERT_EQ(cdr.size(), 1u);
		EXPECT_EQ(cdr[0].caller, "100");
		EXPECT_EQ(cdr[0].callee, "106");
	}
}

TEST(DeregisterMidCall, ANewPhoneTakingAFreedSlotInheritsNoCall)
{
	Rig rig;
	const std::string callId = "dereg-1089-slot";
	sendInvite(rig.handler, callId);
	sendAnswer(rig.handler, callId);
	ASSERT_TRUE(rig.handler.getSession("Call-ID: " + callId).has_value());
	sendDeregister(rig.handler, "100", kCallerIp, "dereg-1089-slot-a");
	sendDeregister(rig.handler, "106", kCalleeIp, "dereg-1089-slot-b");
	rig.handler.handle(makeRegister("107", kOtherIp, "reg-107"));   // takes 100's freed slot
	ASSERT_TRUE(isBoundExt(rig.handler, "107")) << "precondition: 107 is registered";
	rig.sent.clear();

	EXPECT_EQ(liveSessions(rig.handler), 0u) << "a phantom session outlived its clients";
	rig.handler.expireLeaseAndSweepForTest("107");
	EXPECT_EQ(byeCount(rig.sent, kOtherIp), 0u) << "107 was BYEd for a dialog it never had";
	EXPECT_EQ(rig.handler.cdrSnapshotForTest().size(), 1u) << "one CDR, for the real call only";
}

TEST(DeregisterMidCall, ALeaseExpiringOnTheCallerByesThePeerOnceAndKeepsTheCdrOrder)
{
	expectLeaseExpiryEndsTheCall("100", kCalleeIp, kCallerIp, "lease-1089-a");
}

TEST(DeregisterMidCall, ALeaseExpiringOnTheCalleeByesThePeerOnceAndKeepsTheCdrOrder)
{
	expectLeaseExpiryEndsTheCall("106", kCallerIp, kCalleeIp, "lease-1089-b");
}

TEST(DeregisterMidCall, ALapsedClientOnALiveEmergencyCallKeepsItsSlotWhenThePoolIsFull)
{
	Rig rig;
	const std::string callId = "dereg-1089-evict";
	sendInvite(rig.handler, callId);
	sendAnswer(rig.handler, callId);
	auto s = rig.handler.getSession("Call-ID: " + callId);
	ASSERT_TRUE(s.has_value());
	s.value()->setEmergency(true);
	for (int i = 2; i < POCKETDIAL_MAX_CLIENTS; ++i)
		rig.handler.handle(makeRegister("2" + std::to_string(100 + i), kOtherIp, "fill" + std::to_string(i)));
	rig.handler.expireLeaseUnsweptForTest("100");   // lapsed, not yet swept
	rig.handler.handle(makeRegister("300", kOtherIp, "reg-300"));   // pool full: would evict 100

	ASSERT_TRUE(s.value()->getSrc());
	EXPECT_EQ(s.value()->getSrc()->getNumber(), "100") << "the live 911 was handed to another number";
	EXPECT_TRUE(rig.handler.getSession("Call-ID: " + callId).has_value());
	EXPECT_FALSE(isBoundExt(rig.handler, "300")) << "no free slot: refused, as for any full pool";
}
