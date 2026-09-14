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
	// — none may go out. (The 777/888/555 answer paths do not record their
	// generated To-tag on the Session, so no valid BYE toward 100 can be built
	// from here either; there is no far-end phone left holding the call on
	// these legs, which is the failure #228 is about. Recording the tag so the
	// killed handset also hears a BYE is a separate change.)
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

	rig.sent.clear();
	rig.handler.forceDisconnect("100");
	flushAsyncOutbox(rig.handler);

	EXPECT_TRUE(byesTo(rig.sent, addrFor(kCallerIp)).empty())
		<< "no BYE may be addressed to the stand-in peer (it is the caller's own address)";
	EXPECT_EQ(rig.handler.getServerTransactionCount(), 0u)
		<< "endCall() frees the INVITE server transaction for the Call-ID (#226)";
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
