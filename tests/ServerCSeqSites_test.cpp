// Issue #422: the four server-originated in-dialog requests #407 did not reach.
//
// The PBX relays in-dialog requests untouched, so on an ordinary call each phone
// has already seen the OTHER phone's CSeqs -- and a real UA (pjsua: a random
// ~5-digit first CSeq) refuses a request at or below them with 500 Invalid CSeq.
// These four sites still sent the builders' default 2:
//
//   sweepSessionTimers()     the session-timer expiry BYEs
//   forceDisconnect()        the /api/kill BYEs
//   handleBlindXferFailure() the BYE to the transferee when the target refuses
//   onRefer() blind decline  the 404 refer NOTIFY to the transferor
//
// Each test makes one party send a relayed in-dialog request at a realistic
// CSeq first (as pjsua would), then asserts the server's request goes above it.
// Every test drives a real RequestsHandler through handle(), like the #407 tests.

#include <gtest/gtest.h>

#include <chrono>
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

	constexpr uint32_t kCallerCSeq = 23669;   // a pjsua-style first CSeq
	constexpr uint32_t kCalleeCSeq = 31007;

	sockaddr_in addrFor(const std::string& ip, uint16_t port = 5060)
	{
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_addr.s_addr = inet_addr(ip.c_str());
		a.sin_port = htons(port);
		return a;
	}

	std::string ipOf(const sockaddr_in& a) { return inet_ntoa(a.sin_addr); }

	std::shared_ptr<SipMessage> makeRegister(const std::string& ext, const sockaddr_in& a)
	{
		const std::string ip = ipOf(a);
		std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKr422" + ext + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + ext + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: reg-422-" + ext + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + ip + ":5060>;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, a);
	}

	std::string sdpFor(const std::string& ip)
	{
		return "v=0\r\no=- 0 0 IN IP4 " + ip + "\r\ns=-\r\nc=IN IP4 " + ip + "\r\nt=0 0\r\n"
		       "m=audio 10000 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\na=sendrecv\r\n";
	}

	std::string headerLine(const std::string& raw, const std::string& name)
	{
		size_t pos = 0;
		while (pos < raw.size())
		{
			size_t eol = raw.find("\r\n", pos);
			if (eol == std::string::npos) eol = raw.size();
			if (eol == pos) break;
			if (raw.compare(pos, name.size(), name) == 0) return raw.substr(pos, eol - pos);
			pos = eol + 2;
		}
		return {};
	}

	long cseqOf(const std::string& raw)
	{
		const std::string line = headerLine(raw, "CSeq:");
		return line.empty() ? -1 : std::stol(line.substr(5));
	}

	// Every message sent to `to` whose first line starts with `method` on `callId`.
	std::vector<std::string> sentTo(const SentList& sent, const sockaddr_in& to,
	                                const std::string& method, const std::string& callId)
	{
		std::vector<std::string> out;
		for (const auto& [addr, msg] : sent)
		{
			if (!msg || addr.sin_addr.s_addr != to.sin_addr.s_addr || addr.sin_port != to.sin_port) continue;
			const std::string raw = msg->toString();
			if (raw.rfind(method + " ", 0) != 0) continue;
			if (raw.find("Call-ID: " + callId + "\r\n") == std::string::npos) continue;
			out.push_back(raw);
		}
		return out;
	}

	struct Rig
	{
		SentList sent;
		RequestsHandler handler;
		const sockaddr_in a = addrFor("192.168.42.10");   // 100
		const sockaddr_in b = addrFor("192.168.42.20");   // 106
		const sockaddr_in c = addrFor("192.168.42.30");   // 107
		const sockaddr_in other = addrFor("192.168.42.99");

		Rig() : handler("192.168.42.1", 5060,
			[this](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
				sent.emplace_back(addr, std::move(msg));
			})
		{
			handler.handle(makeRegister("100", a));
			handler.handle(makeRegister("106", b));
			handler.handle(makeRegister("107", c));
		}

		// 100 calls 106 at CSeq 1 and 106 answers. `timer` adds a session timer
		// with the callee as refresher, which arms the PBX's expiry reaper.
		void connect(const std::string& callId, bool timer = false)
		{
			const std::string aSdp = sdpFor(ipOf(a));
			std::string inv =
				"INVITE sip:106@server SIP/2.0\r\n"
				"Via: SIP/2.0/UDP " + ipOf(a) + ":5060;branch=z9hG4bKi" + callId + "\r\n"
				"From: <sip:100@server>;tag=atag\r\n"
				"To: <sip:106@server>\r\n"
				"Call-ID: " + callId + "\r\n"
				"CSeq: 1 INVITE\r\n"
				"Max-Forwards: 70\r\n"
				"Contact: <sip:100@" + ipOf(a) + ":5060>\r\n" +
				std::string(timer ? "Supported: timer\r\nSession-Expires: 1800\r\nMin-SE: 90\r\n" : "") +
				"Content-Type: application/sdp\r\n"
				"Content-Length: " + std::to_string(aSdp.size()) + "\r\n\r\n" + aSdp;
			handler.handle(RequestsHandler::getMessageFromPool(inv, a));

			std::string fork;
			for (const auto& raw : sentTo(sent, b, "INVITE", callId)) fork = raw;
			ASSERT_FALSE(fork.empty()) << "the call must reach 106";

			const std::string bSdp = sdpFor(ipOf(b));
			std::string ok =
				"SIP/2.0 200 OK\r\n" +
				headerLine(fork, "Via:") + "\r\n" +
				headerLine(fork, "From:") + "\r\n"
				"To: <sip:106@server>;tag=btag\r\n"
				"Call-ID: " + callId + "\r\n"
				"CSeq: 1 INVITE\r\n"
				"Contact: <sip:106@" + ipOf(b) + ":5060>\r\n" +
				std::string(timer ? "Session-Expires: 1800;refresher=uas\r\n" : "") +
				"Content-Type: application/sdp\r\n"
				"Content-Length: " + std::to_string(bSdp.size()) + "\r\n\r\n" + bSdp;
			handler.handle(RequestsHandler::getMessageFromPool(ok, b));
		}

		// A relayed in-dialog re-INVITE (a resume, so the call stays Connected).
		void reinvite(const std::string& callId, bool fromCaller, uint32_t cseq)
		{
			const sockaddr_in& src = fromCaller ? a : b;
			const std::string from = fromCaller ? "<sip:100@server>;tag=atag" : "<sip:106@server>;tag=btag";
			const std::string to   = fromCaller ? "<sip:106@server>;tag=btag" : "<sip:100@server>;tag=atag";
			const std::string sdp  = sdpFor(ipOf(src));
			std::string raw =
				std::string("INVITE sip:") + (fromCaller ? "106" : "100") + "@server SIP/2.0\r\n"
				"Via: SIP/2.0/UDP " + ipOf(src) + ":5060;branch=z9hG4bKre" + std::to_string(cseq) + "\r\n"
				"From: " + from + "\r\n"
				"To: " + to + "\r\n"
				"Call-ID: " + callId + "\r\n"
				"CSeq: " + std::to_string(cseq) + " INVITE\r\n"
				"Max-Forwards: 70\r\n"
				"Contact: <sip:" + (fromCaller ? "100@" : "106@") + ipOf(src) + ":5060>\r\n"
				"Content-Type: application/sdp\r\n"
				"Content-Length: " + std::to_string(sdp.size()) + "\r\n\r\n" + sdp;
			handler.handle(RequestsHandler::getMessageFromPool(raw, src));
		}

		void refer(const std::string& callId, uint32_t cseq, const std::string& target)
		{
			std::string raw =
				"REFER sip:106@server SIP/2.0\r\n"
				"Via: SIP/2.0/UDP " + ipOf(a) + ":5060;branch=z9hG4bKref" + std::to_string(cseq) + "\r\n"
				"From: <sip:100@server>;tag=atag\r\n"
				"To: <sip:106@server>;tag=btag\r\n"
				"Call-ID: " + callId + "\r\n"
				"CSeq: " + std::to_string(cseq) + " REFER\r\n"
				"Max-Forwards: 70\r\n"
				"Refer-To: <sip:" + target + "@server>\r\n"
				"Contact: <sip:100@" + ipOf(a) + ":5060>\r\n"
				"Content-Length: 0\r\n\r\n";
			handler.handle(RequestsHandler::getMessageFromPool(raw, a));
		}

		// forceDisconnect() queues on the async outbox; the SIP thread's next
		// packet is what flushes it (same trick as ForceDisconnect_test.cpp).
		void flush()
		{
			std::string raw =
				"OPTIONS sip:server SIP/2.0\r\n"
				"Via: SIP/2.0/UDP " + ipOf(other) + ":5060;branch=z9hG4bKflush422\r\n"
				"From: <sip:probe@server>;tag=probe\r\n"
				"To: <sip:server@server>\r\n"
				"Call-ID: flush-422\r\n"
				"CSeq: 1 OPTIONS\r\n"
				"Max-Forwards: 70\r\n"
				"Content-Length: 0\r\n\r\n";
			handler.handle(RequestsHandler::getMessageFromPool(raw, other));
		}
	};
}

// sweepSessionTimers(): the callee has seen the caller's relayed re-INVITE at
// 23669, so the expiry BYE to it must go above that -- as must the one to the
// caller, which sits on the same dialog.
TEST(ServerCSeqSites, SessionTimerExpiryByesGoAboveTheRelayedCSeqs)
{
	Rig r;
	const std::string callId = "cseq422-timer";
	r.connect(callId, /*timer=*/true);
	r.reinvite(callId, /*fromCaller=*/true, kCallerCSeq);

	auto session = r.handler.getSession("Call-ID: " + callId);
	ASSERT_TRUE(session.has_value());
	ASSERT_GT(session.value()->getSessionExpiresSeconds(), 0u) << "the reaper must be armed";
	// Back-date the expiry instead of waiting 30 minutes.
	session.value()->armSessionTimer(session.value()->getSessionExpiresSeconds(), false,
		std::chrono::steady_clock::now() - std::chrono::hours(2));

	r.sent.clear();
	r.handler.tick();

	const auto toCallee = sentTo(r.sent, r.b, "BYE", callId);
	const auto toCaller = sentTo(r.sent, r.a, "BYE", callId);
	ASSERT_EQ(toCallee.size(), 1u) << "the expired call must be BYEd to the callee";
	ASSERT_EQ(toCaller.size(), 1u) << "and to the caller";
	EXPECT_GT(cseqOf(toCallee[0]), static_cast<long>(kCallerCSeq))
		<< "the callee has seen the caller's CSeq " << kCallerCSeq << " -- a lower BYE is refused:\n"
		<< toCallee[0];
	EXPECT_GT(cseqOf(toCaller[0]), static_cast<long>(kCallerCSeq)) << toCaller[0];
}

// forceDisconnect() (/api/kill): the same relayed-dialog rule.
TEST(ServerCSeqSites, ForceDisconnectByesGoAboveTheRelayedCSeqs)
{
	Rig r;
	const std::string callId = "cseq422-kill";
	r.connect(callId);
	r.reinvite(callId, /*fromCaller=*/true, kCallerCSeq);

	r.sent.clear();
	r.handler.forceDisconnect("100");
	r.flush();

	const auto toCallee = sentTo(r.sent, r.b, "BYE", callId);
	const auto toCaller = sentTo(r.sent, r.a, "BYE", callId);
	ASSERT_EQ(toCallee.size(), 1u);
	ASSERT_EQ(toCaller.size(), 1u);
	EXPECT_GT(cseqOf(toCallee[0]), static_cast<long>(kCallerCSeq)) << toCallee[0];
	EXPECT_GT(cseqOf(toCaller[0]), static_cast<long>(kCallerCSeq)) << toCaller[0];
}

// handleBlindXferFailure(): the target refuses (486), and the transferee is BYEd
// in the transferor's name on the A-B dialog, where it has seen A's CSeqs.
// Refused at the old 2, it sat on a dead dialog -- the outcome #128 was about.
TEST(ServerCSeqSites, TargetRefusedByeToTheTransfereeGoesAboveTheTransferorsCSeq)
{
	Rig r;
	const std::string callId = "cseq422-refused";
	r.connect(callId);
	r.reinvite(callId, /*fromCaller=*/true, kCallerCSeq);
	r.refer(callId, kCallerCSeq + 1, "107");

	std::string toC;
	for (const auto& raw : r.sent)
	{
		if (!raw.second || raw.first.sin_addr.s_addr != r.c.sin_addr.s_addr) continue;
		const std::string s = raw.second->toString();
		if (s.rfind("INVITE sip:107@", 0) == 0) toC = s;
	}
	ASSERT_FALSE(toC.empty()) << "the transfer must ring the target";

	r.sent.clear();
	{
		std::string busy =
			"SIP/2.0 486 Busy Here\r\n" +
			headerLine(toC, "Via:") + "\r\n" +
			headerLine(toC, "From:") + "\r\n"
			"To: <sip:107@192.168.42.1:5060>;tag=ctag\r\n" +
			headerLine(toC, "Call-ID:") + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Content-Length: 0\r\n\r\n";
		r.handler.handle(RequestsHandler::getMessageFromPool(busy, r.c));
	}

	const auto toB = sentTo(r.sent, r.b, "BYE", callId);
	ASSERT_EQ(toB.size(), 1u) << "the transferee must be released";
	EXPECT_GT(cseqOf(toB[0]), static_cast<long>(kCallerCSeq + 1))
		<< "the transferee has seen A's CSeqs up to the REFER's " << (kCallerCSeq + 1) << ":\n" << toB[0];
}

// onRefer() blind decline: an unresolvable target draws a 404 refer NOTIFY to
// the transferor, in the transferee's name. The transferor has seen the
// transferee's relayed re-INVITE at 31007, so the NOTIFY must go above it.
TEST(ServerCSeqSites, DeclinedTransferNotifyGoesAboveTheTransfereesRelayedCSeq)
{
	Rig r;
	const std::string callId = "cseq422-declined";
	r.connect(callId);
	r.reinvite(callId, /*fromCaller=*/false, kCalleeCSeq);

	r.sent.clear();
	r.refer(callId, 2, "199");   // no such extension

	const auto notifies = sentTo(r.sent, r.a, "NOTIFY", callId);
	ASSERT_EQ(notifies.size(), 1u) << "a declined transfer sends exactly one refer NOTIFY";
	EXPECT_NE(notifies[0].find("SIP/2.0 404 Not Found"), std::string::npos) << notifies[0];
	EXPECT_GT(cseqOf(notifies[0]), static_cast<long>(kCalleeCSeq))
		<< "the transferor has seen the transferee's CSeq " << kCalleeCSeq << ":\n" << notifies[0];
	EXPECT_TRUE(r.handler.getSession("Call-ID: " + callId).has_value())
		<< "a declined transfer leaves the call up";
}
