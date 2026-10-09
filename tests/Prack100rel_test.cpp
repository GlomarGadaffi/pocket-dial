// Prack100rel_test.cpp — Issue #172: RFC 3262 Require: 100rel on the 777 echo INVITE.
//
// The echo test (777) is the one route where this PBX is the UAS end to end, so it
// is the one route that honours Require: 100rel: its 180 is sent reliably (RFC 3262
// §3: "MUST send any non-100 provisional response reliably if the initial request
// contained a Require header field with the option tag 100rel"), and a matching PRACK
// is answered with 2xx, a non-matching one with 481 (§3). Every other route still
// answers 420 Bad Extension with Unsupported: 100rel, which §3 permits for a UAS
// unwilling to send reliably. Emergency traffic keeps its existing path (no RSeq,
// no 420). Peers that send neither Require nor Supported 100rel are unaffected.
//
// The PBX is a PRACK UAS only for the echo test's own dialog (Session::isEchoDialog). A
// call whose dest *11 or *69 repointed at the virtual 777 peer (a 911 included) and a
// PSAP callback to 777 are not that dialog: a PRACK on them stays unanswered (Rule 5).
// The PRACK 200 alone holds a Timer J slot, so refused PRACKs cannot starve it.

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdio>
#include <string>
#include <utility>
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

	// extraHeaders is inserted verbatim before the body, one "Name: value\r\n" per line.
	// A non-empty toTag makes it an in-dialog INVITE (a re-INVITE), which the PBX answers 481 when it has no such dialog.
	std::shared_ptr<SipMessage> makeInvite(const std::string& fromExt, const std::string& toExt,
	                                        const std::string& srcIp, const std::string& callId,
	                                        const std::string& extraHeaders = "",
	                                        const std::string& contentType = "application/sdp",
	                                        const std::string& toTag = "")
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
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bKi" + callId + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>" + (toTag.empty() ? std::string{} : ";tag=" + toTag) + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:" + fromExt + "@" + srcIp + ":5060>\r\n" +
			extraHeaders +
			"Content-Type: " + contentType + "\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}

	// The defaults are the dialog's first PRACK, from the caller's address. A byte-identical resend
	// is a retransmission (RFC 3261 §17.2.3: same branch). A later PRACK is a new transaction: new
	// CSeq and branch. An empty `rack` leaves the RAck header out.
	std::shared_ptr<SipMessage> makePrack(const std::string& callId, const std::string& localTag,
	                                       const std::string& rack, int cseq = 2,
	                                       const std::string& branchTag = "p",
	                                       const std::string& srcIp = "192.168.7.50",
	                                       const std::string& extraHeaders = "")
	{
		std::string raw =
			"PRACK sip:777@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bK" + branchTag + callId + "\r\n"
			"From: <sip:500@server>;tag=ft" + callId + "\r\n"
			"To: <sip:777@server>;tag=" + localTag + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: " + std::to_string(cseq) + " PRACK\r\n" +
			(rack.empty() ? std::string{} : "RAck: " + rack + "\r\n") +
			extraHeaders +
			"Max-Forwards: 70\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}

	// A bodiless in-dialog request the header gate sees and nothing else needs: CSeq 7, from the caller.
	std::shared_ptr<SipMessage> makeGateProbe(const std::string& method, const std::string& callId,
	                                           const std::string& extraHeaders)
	{
		std::string raw =
			method + " sip:600@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.7.50:5060;branch=z9hG4bKg" + callId + "\r\n"
			"From: <sip:500@server>;tag=ft" + callId + "\r\n"
			"To: <sip:600@server>;tag=tt" + callId + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 7 " + method + "\r\n"
			"Max-Forwards: 70\r\n" +
			extraHeaders +
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor("192.168.7.50"));
	}

	// One DTMF digit as a SIP INFO from the caller, as DtmfClassCodes_test sends them.
	std::shared_ptr<SipMessage> makeInfoDigit(const std::string& callId, char digit)
	{
		const std::string body = std::string("Signal=") + digit + "\r\nDuration=100\r\n";
		std::string raw =
			"INFO sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.7.50:5060;branch=z9hG4bKd" + callId + "\r\n"
			"From: <sip:500@server>;tag=ft" + callId + "\r\n"
			"To: <sip:server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 9 INFO\r\n"
			"Content-Type: application/dtmf-relay\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor("192.168.7.50"));
	}

	// The ACK to the echo's 200 (RFC 3261 §13.2.2.4: a new transaction, so a new branch).
	std::shared_ptr<SipMessage> makeAck(const std::string& callId, const std::string& localTag)
	{
		std::string raw =
			"ACK sip:777@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.7.50:5060;branch=z9hG4bKa" + callId + "\r\n"
			"From: <sip:500@server>;tag=ft" + callId + "\r\n"
			"To: <sip:777@server>;tag=" + localTag + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 ACK\r\n"
			"Max-Forwards: 70\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor("192.168.7.50"));
	}

	// The first sent message whose status line starts with `status` and whose raw text
	// contains `needle`, or "" if none.
	std::string findSent(const Sent& sent, const std::string& status, const std::string& needle)
	{
		for (const auto& [addr, msg] : sent)
		{
			std::string raw = msg ? msg->toString() : std::string{};
			if (raw.rfind(status, 0) == 0 && raw.find(needle) != std::string::npos) return raw;
		}
		return {};
	}

	bool anySent(const Sent& sent, const std::string& text)
	{
		for (const auto& [addr, msg] : sent)
		{
			if (msg && msg->toString().find(text) != std::string::npos) return true;
		}
		return false;
	}

	// Value of the header named `name` (without the colon), or "".
	std::string headerValue(const std::string& raw, const std::string& name)
	{
		const std::string key = "\r\n" + name + ":";
		size_t at = raw.find(key);
		if (at == std::string::npos) return {};
		at += key.size();
		size_t end = raw.find("\r\n", at);
		std::string v = raw.substr(at, end - at);
		while (!v.empty() && v.front() == ' ') v.erase(0, 1);
		return v;
	}

	// The To-tag the 180 carried, which is the dialog's local tag.
	std::string toTagOf(const std::string& raw)
	{
		const std::string to = headerValue(raw, "To");
		const size_t at = to.find("tag=");
		if (at == std::string::npos) return {};
		return to.substr(at + 4);
	}

	struct EchoRig
	{
		Sent sent;
		RequestsHandler handler{"192.168.7.1", 5060,
			[this](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
				sent.emplace_back(addr, std::move(msg));
			}};

		EchoRig()
		{
			handler.handle(makeRegister("500", "192.168.7.50", "reg-500"));
		}
	};

	// Position of the first sent message that starts with `status` and contains `needle`, or -1.
	int indexOfSent(const Sent& sent, const std::string& status, const std::string& needle)
	{
		for (size_t i = 0; i < sent.size(); ++i)
		{
			const std::string raw = sent[i].second ? sent[i].second->toString() : std::string{};
			if (raw.rfind(status, 0) == 0 && raw.find(needle) != std::string::npos) return static_cast<int>(i);
		}
		return -1;
	}

	// A Require: 100rel call to the echo. rseq and tag come from its reliable 180.
	struct EchoCall
	{
		std::string rseq;
		std::string tag;
	};

	EchoCall startReliableEcho(EchoRig& rig, const std::string& callId)
	{
		rig.handler.handle(makeInvite("500", "777", "192.168.7.50", callId, "Require: 100rel\r\n"));
		const std::string ringing = findSent(rig.sent, "SIP/2.0 180 Ringing", "CSeq: 1 INVITE");
		return {headerValue(ringing, "RSeq"), toTagOf(ringing)};
	}

	// RFC 5737 TEST-NET-3: not routable, and the send callback above only captures.
	constexpr const char* kSbcIp = "203.0.113.5";

	void configureTrunk(RequestsHandler& handler)
	{
		SipTrunk::Config c;
		std::snprintf(c.host, sizeof(c.host), "%s", kSbcIp);
		c.port = 5060;
		std::snprintf(c.fromUser, sizeof(c.fromUser), "%s", "15551230000");
		c.enabled = true;
		handler.setTrunkConfig(c);
	}

	size_t countSentTo(const Sent& sent, const char* ip, const std::string& startLine)
	{
		size_t n = 0;
		for (const auto& [addr, msg] : sent)
		{
			if (addr.sin_addr.s_addr == inet_addr(ip) && msg && msg->toString().rfind(startLine, 0) == 0) ++n;
		}
		return n;
	}

	// handle() drops a source's packets past a burst of 40 (allowPacket), which would look like a full pool.
	constexpr int kPoolFill = POCKETDIAL_MAX_SERVER_TRANSACTIONS + 2;
	static_assert(kPoolFill + 6 <= 40, "the pool-filling tests would hit the per-source packet burst limit");

	// Fills the server transaction pool with 481s to INVITEs for dialogs that do not exist (each is a
	// tracked, authored response). Returns the pool's size, or 0 if a further one never stopped taking a slot.
	size_t fillServerPool(EchoRig& rig)
	{
		size_t before = rig.handler.getServerTransactionCount();
		for (int i = 0; i < kPoolFill; ++i)
		{
			rig.sent.clear();   // the capture holds message-pool slots
			rig.handler.handle(makeInvite("500", "600", "192.168.7.50", "e-fill" + std::to_string(i), "",
				"application/sdp", "nodialog"));
			const size_t after = rig.handler.getServerTransactionCount();
			if (after == before) return after;
			before = after;
		}
		return 0;
	}
}

// Red on unfixed code: the header gate answers 420 for any Require: 100rel.
TEST(Prack100rel, Require100relTo777EchoGets180WithRSeqNot420)
{
	EchoRig rig;
	rig.handler.handle(makeInvite("500", "777", "192.168.7.50", "e-req",
		"Require: 100rel\r\n"));

	EXPECT_FALSE(anySent(rig.sent, "420 Bad Extension"))
		<< "a 777 INVITE with Require: 100rel is honoured, not refused with 420";
	const std::string ringing = findSent(rig.sent, "SIP/2.0 180 Ringing", "CSeq: 1 INVITE");
	ASSERT_FALSE(ringing.empty()) << "777 INVITE with Require: 100rel produced no 180 Ringing";
	EXPECT_NE(headerValue(ringing, "RSeq"), "")
		<< "RFC 3262 §3: a reliable provisional MUST include an RSeq header";
	EXPECT_NE(headerValue(ringing, "Require").find("100rel"), std::string::npos)
		<< "RFC 3262 §3: a reliable provisional MUST contain Require: 100rel";
	const std::string rs = headerValue(ringing, "RSeq");
	const uint64_t rseq = rs.empty() ? 0 : std::stoull(rs);
	EXPECT_GE(rseq, 1u) << "RFC 3262 §7.1: the first RSeq must be between 1 and 2**31 - 1";
	EXPECT_LE(rseq, 2147483647u) << "RFC 3262 §7.1: the first RSeq must be between 1 and 2**31 - 1";
}

// Red on unfixed code: PRACK has no handler, so nothing is answered.
TEST(Prack100rel, MatchingPrackTo777EchoGets200)
{
	EchoRig rig;
	rig.handler.handle(makeInvite("500", "777", "192.168.7.50", "e-ok", "Require: 100rel\r\n"));
	const std::string ringing = findSent(rig.sent, "SIP/2.0 180 Ringing", "CSeq: 1 INVITE");
	ASSERT_FALSE(ringing.empty());
	const std::string rseq = headerValue(ringing, "RSeq");
	const std::string tag = toTagOf(ringing);
	ASSERT_FALSE(rseq.empty());
	ASSERT_FALSE(tag.empty());

	rig.sent.clear();
	rig.handler.handle(makePrack("e-ok", tag, rseq + " 1 INVITE"));

	EXPECT_FALSE(findSent(rig.sent, "SIP/2.0 200 OK", "CSeq: 2 PRACK").empty())
		<< "RFC 3262 §3: a PRACK matching the reliable provisional MUST be answered with 2xx";
}

// Red on unfixed code: PRACK has no handler, so nothing is answered.
TEST(Prack100rel, MismatchedPrackTo777EchoGets481)
{
	EchoRig rig;
	rig.handler.handle(makeInvite("500", "777", "192.168.7.50", "e-bad", "Require: 100rel\r\n"));
	const std::string ringing = findSent(rig.sent, "SIP/2.0 180 Ringing", "CSeq: 1 INVITE");
	ASSERT_FALSE(ringing.empty());
	const std::string rseq = headerValue(ringing, "RSeq");
	const std::string tag = toTagOf(ringing);
	ASSERT_FALSE(rseq.empty());

	rig.sent.clear();
	// RSeq + 1 matches no reliable provisional the PBX sent.
	const std::string wrong = std::to_string(std::stoull(rseq) + 1) + " 1 INVITE";
	rig.handler.handle(makePrack("e-bad", tag, wrong));

	EXPECT_FALSE(findSent(rig.sent, "SIP/2.0 481", "CSeq: 2 PRACK").empty())
		<< "RFC 3262 §3: a PRACK that matches no outstanding reliable provisional gets 481";
}

// Red on unfixed code: the PRACK 200 holds no server transaction, so a resend re-runs onPrack and gets 481.
TEST(Prack100rel, RetransmittedMatchedPrackGetsTheSame200AndRunsNothingAgain)
{
	EchoRig rig;
	const EchoCall call = startReliableEcho(rig, "e-rtx");
	ASSERT_FALSE(call.rseq.empty());
	rig.handler.handle(makePrack("e-rtx", call.tag, call.rseq + " 1 INVITE"));
	const std::string first = findSent(rig.sent, "SIP/2.0 200 OK", "CSeq: 2 PRACK");
	ASSERT_FALSE(first.empty());

	rig.sent.clear();
	rig.handler.handle(makePrack("e-rtx", call.tag, call.rseq + " 1 INVITE"));   // same branch, same CSeq

	EXPECT_EQ(findSent(rig.sent, "SIP/2.0 200 OK", "CSeq: 2 PRACK"), first)
		<< "RFC 3261 §17.2.3: a retransmitted request is answered with the same response";
	EXPECT_EQ(rig.sent.size(), 1u) << "the retransmission is answered from the cache and nothing else is sent";
	EXPECT_FALSE(anySent(rig.sent, "SIP/2.0 481"));
}

// Guard: a new PRACK (new CSeq, new branch) after the first was matched and the ACK arrived is a
// repeat, not a retransmission, and matches no unacknowledged reliable provisional.
TEST(Prack100rel, NewPrackAfterAckGets481)
{
	EchoRig rig;
	const EchoCall call = startReliableEcho(rig, "e-rep");
	ASSERT_FALSE(call.rseq.empty());
	rig.handler.handle(makePrack("e-rep", call.tag, call.rseq + " 1 INVITE"));
	ASSERT_FALSE(findSent(rig.sent, "SIP/2.0 200 OK", "CSeq: 2 PRACK").empty());
	rig.handler.handle(makeAck("e-rep", call.tag));

	rig.sent.clear();
	rig.handler.handle(makePrack("e-rep", call.tag, call.rseq + " 1 INVITE", 3, "q"));

	EXPECT_FALSE(findSent(rig.sent, "SIP/2.0 481", "CSeq: 3 PRACK").empty())
		<< "RFC 3262 §3: once acknowledged, the same RAck no longer matches anything";
	EXPECT_TRUE(findSent(rig.sent, "SIP/2.0 200 OK", "CSeq: 3 PRACK").empty());
}

// Guard: a PRACK that is refused consumes nothing. With no ACK yet and the provisional still
// pending, a later PRACK gets the normal match answer.
TEST(Prack100rel, RefusedPrackLeavesTheReliableProvisionalPending)
{
	EchoRig rig;
	const EchoCall call = startReliableEcho(rig, "e-pend");
	ASSERT_FALSE(call.rseq.empty());
	rig.handler.handle(makePrack("e-pend", call.tag, std::to_string(std::stoull(call.rseq) + 1) + " 1 INVITE"));
	ASSERT_FALSE(findSent(rig.sent, "SIP/2.0 481", "CSeq: 2 PRACK").empty());

	rig.sent.clear();
	rig.handler.handle(makePrack("e-pend", call.tag, call.rseq + " 1 INVITE", 3, "q"));

	EXPECT_FALSE(findSent(rig.sent, "SIP/2.0 200 OK", "CSeq: 3 PRACK").empty())
		<< "a 481 for a wrong RAck must not retire the pending reliable provisional";
}

// Guard, passes on unfixed code: the echo's 200 does not wait for a PRACK. The 180 carries no SDP,
// so RFC 3262 §3 lets the final response go at once; the answer is the INVITE's, with no Require.
TEST(Prack100rel, InviteFinal200GoesOutBeforeAnyPrack)
{
	EchoRig rig;
	rig.handler.handle(makeInvite("500", "777", "192.168.7.50", "e-fin", "Require: 100rel\r\n"));

	const int ringing = indexOfSent(rig.sent, "SIP/2.0 180 Ringing", "CSeq: 1 INVITE");
	const int ok = indexOfSent(rig.sent, "SIP/2.0 200 OK", "CSeq: 1 INVITE");
	ASSERT_GE(ringing, 0) << "no reliable 180";
	ASSERT_GE(ok, 0) << "RFC 3262 §3: the final response is not held for the PRACK, and no PRACK has been sent";
	EXPECT_LT(ringing, ok);
	const std::string okRaw = rig.sent[static_cast<size_t>(ok)].second->toString();
	EXPECT_EQ(headerValue(okRaw, "Require"), "") << "the caller's Require is not echoed into the 200";
	EXPECT_EQ(headerValue(okRaw, "RSeq"), "") << "only the provisional is reliable";
}

// Guard, passes on unfixed code: a PRACK whose RAck is anything but "<RSeq> <INVITE CSeq> INVITE"
// gets 481 (RFC 3262 §3, §7.2) and changes nothing, so the right PRACK still matches afterwards.
TEST(Prack100rel, MalformedOrForeignRAckGets481AndChangesNothing)
{
	struct Row
	{
		const char* what;
		std::string rack;   // '$' stands for the RSeq the 180 carried; empty leaves the header out
		bool matches;
	};
	const std::vector<Row> rows = {
		{"matching RAck",       "$ 1 INVITE",       true},
		{"wrong INVITE CSeq",   "$ 2 INVITE",       false},
		{"wrong method",        "$ 1 BYE",          false},
		{"method missing",      "$ 1",              false},
		{"RSeq not a number",   "x 1 INVITE",       false},
		{"RAck header missing", "",                 false},
		{"trailing token",      "$ 1 INVITE extra", false},
	};
	int n = 0;
	for (const Row& row : rows)
	{
		SCOPED_TRACE(row.what);
		const std::string id = "e-rack" + std::to_string(n++);
		EchoRig rig;
		const EchoCall call = startReliableEcho(rig, id);
		ASSERT_FALSE(call.rseq.empty());
		std::string rack = row.rack;
		if (const size_t at = rack.find('$'); at != std::string::npos) rack.replace(at, 1, call.rseq);

		rig.sent.clear();
		rig.handler.handle(makePrack(id, call.tag, rack));

		EXPECT_EQ(findSent(rig.sent, "SIP/2.0 200 OK", "CSeq: 2 PRACK").empty(), !row.matches);
		EXPECT_EQ(findSent(rig.sent, "SIP/2.0 481", "CSeq: 2 PRACK").empty(), row.matches);
		if (row.matches) continue;

		rig.sent.clear();
		rig.handler.handle(makePrack(id, call.tag, call.rseq + " 1 INVITE", 3, "q"));
		EXPECT_FALSE(findSent(rig.sent, "SIP/2.0 200 OK", "CSeq: 3 PRACK").empty())
			<< "a refused PRACK must leave the reliable provisional pending";
	}
}

// Red on unfixed code: checkHeaders reports the first unknown tag, which is 100rel.
TEST(Prack100rel, Require100relWithAnotherUnknownTagNamesThatTag)
{
	EchoRig rig;
	rig.handler.handle(makeInvite("500", "777", "192.168.7.50", "e-two",
		"Require: 100rel, path\r\n"));

	EXPECT_TRUE(anySent(rig.sent, "420 Bad Extension"));
	EXPECT_TRUE(anySent(rig.sent, "Unsupported: path"))
		<< "RFC 3261 §8.2.2.3: the 420 must name each option tag the UAS does not understand";
	EXPECT_FALSE(anySent(rig.sent, "Unsupported: 100rel"));
}

// Guard, passes on unfixed code: Supported: 100rel alone is a MAY (RFC 3262 §3), not a MUST.
TEST(Prack100rel, SupportedOnly100relTo777EchoSendsNoRSeq)
{
	EchoRig rig;
	rig.handler.handle(makeInvite("500", "777", "192.168.7.50", "e-sup", "Supported: 100rel\r\n"));

	const std::string ringing = findSent(rig.sent, "SIP/2.0 180 Ringing", "CSeq: 1 INVITE");
	ASSERT_FALSE(ringing.empty());
	EXPECT_EQ(headerValue(ringing, "RSeq"), "")
		<< "a peer that only offers Supported: 100rel must see the unchanged unreliable 180";
}

// Guard, passes on unfixed code: an ordinary extension call keeps its 420.
TEST(Prack100rel, Require100relToOrdinaryExtensionStays420)
{
	EchoRig rig;
	rig.handler.handle(makeRegister("600", "192.168.7.60", "reg-600"));
	rig.handler.handle(makeInvite("500", "600", "192.168.7.50", "e-ord", "Require: 100rel\r\n"));

	EXPECT_TRUE(anySent(rig.sent, "420 Bad Extension"));
	EXPECT_TRUE(anySent(rig.sent, "Unsupported: 100rel"))
		<< "RFC 3262 §3: a UAS unwilling to send reliably MUST answer 420 naming 100rel";
	EXPECT_FALSE(anySent(rig.sent, "RSeq:"));
}

// Guard, passes on unfixed code: Proxy-Require is not 100rel's place (RFC 3262 §4).
TEST(Prack100rel, ProxyRequire100relTo777EchoStays420)
{
	EchoRig rig;
	rig.handler.handle(makeInvite("500", "777", "192.168.7.50", "e-pxy",
		"Proxy-Require: 100rel\r\n"));

	EXPECT_TRUE(anySent(rig.sent, "420 Bad Extension"));
	EXPECT_TRUE(anySent(rig.sent, "Unsupported: 100rel"));
}

// Guard, passes on unfixed code: a 911 with Require: 100rel is not refused and gets no
// RSeq. Its path is the existing emergency yield, so it is never reliable (Rule 5). The caller
// hears ringback, so the 911 was taken up rather than refused; the rig configures a capture-only
// carrier just so it is not answered 503, and where the call goes from there is not asserted.
TEST(Prack100rel, Emergency911WithRequire100relIsNotRefusedAndGetsNoRSeq)
{
	EchoRig rig;
	configureTrunk(rig.handler);
	rig.sent.clear();
	rig.handler.handle(makeInvite("500", "911", "192.168.7.50", "e-911", "Require: 100rel\r\n"));

	EXPECT_FALSE(anySent(rig.sent, "420 Bad Extension"))
		<< "Rule 5: a 911 must never be refused for its Require header";
	EXPECT_FALSE(anySent(rig.sent, "RSeq:"))
		<< "Rule 5: a 911 is never answered on the reliable-provisional path";
	EXPECT_EQ(rig.handler.getEmergencyHeaderYields(), 1u)
		<< "the 911 takes the header gate's emergency yield, exactly as it does without the 100rel work";
	EXPECT_EQ(countSentTo(rig.sent, "192.168.7.50", "SIP/2.0 180 Ringing"), 1u)
		<< "the caller must hear ringback";
}

// Red on unfixed code: the PRACK was dropped. The echo sent no reliable provisional, so
// RFC 3262 §3 makes any PRACK on it a non-match: 481.
TEST(Prack100rel, PrackOnEchoDialogWithout100relGets481)
{
	EchoRig rig;
	rig.handler.handle(makeInvite("500", "777", "192.168.7.50", "e-plain"));
	const std::string ringing = findSent(rig.sent, "SIP/2.0 180 Ringing", "CSeq: 1 INVITE");
	const std::string tag = toTagOf(ringing);
	ASSERT_FALSE(tag.empty());

	rig.sent.clear();
	rig.handler.handle(makePrack("e-plain", tag, "1 1 INVITE"));

	EXPECT_FALSE(findSent(rig.sent, "SIP/2.0 481", "CSeq: 2 PRACK").empty())
		<< "RFC 3262 §3: a PRACK that matches no reliable provisional MUST get 481";
	EXPECT_FALSE(anySent(rig.sent, "SIP/2.0 200 OK"));
}

// Guard, passes on unfixed code: the PBX answers PRACK only as the echo's UAS. With no session at all,
// or on a call it merely relays, a PRACK stays unanswered as it was before onPrack existed (a 481
// there would make the caller end an early dialog the PBX is not the UAS of, RFC 3261 §12.2.1.2).
TEST(Prack100rel, PrackWithoutAnEchoDialogStaysUnanswered)
{
	{
		EchoRig rig;
		rig.handler.handle(makePrack("e-none", "sometag", "1 1 INVITE"));
		EXPECT_FALSE(anySent(rig.sent, "PRACK")) << "no session: nothing to answer for";
	}
	{
		EchoRig rig;
		rig.handler.handle(makeRegister("600", "192.168.7.60", "reg-600"));
		rig.handler.handle(makeInvite("500", "600", "192.168.7.50", "e-relay"));
		ASSERT_TRUE(anySent(rig.sent, "INVITE sip:600")) << "precondition: the call was relayed, so its session exists";
		rig.sent.clear();
		rig.handler.handle(makePrack("e-relay", "calleetag", "1 1 INVITE"));
		EXPECT_FALSE(anySent(rig.sent, "PRACK")) << "a relayed call is not the PBX's dialog to answer";
	}
}

// Red on unfixed code: isEmergencyRequest() is true for Priority: psap-callback on any To, so the
// PBX must stay on the base behaviour for it (Rule 5): the plain 180, no RSeq, and the call is answered.
TEST(Prack100rel, PsapCallbackTo777WithRequire100relKeepsThePlain180)
{
	EchoRig rig;
	rig.handler.handle(makeInvite("500", "777", "192.168.7.50", "e-psap",
		"Require: 100rel\r\nPriority: psap-callback\r\n"));

	EXPECT_FALSE(anySent(rig.sent, "420 Bad Extension"));
	const std::string ringing = findSent(rig.sent, "SIP/2.0 180 Ringing", "CSeq: 1 INVITE");
	ASSERT_FALSE(ringing.empty());
	EXPECT_EQ(headerValue(ringing, "RSeq"), "") << "a PSAP callback never gets a reliable provisional";
	EXPECT_EQ(headerValue(ringing, "Require"), "") << "the caller's Require must not be echoed into a plain 180";
	EXPECT_FALSE(findSent(rig.sent, "SIP/2.0 200 OK", "CSeq: 1 INVITE").empty());
}

// Red on 6dd8ed9e: only the 777 echo honours 100rel, and the header gate decides that. An INVITE to
// anything else is refused at its Require line, before a later violation or another tag is looked at,
// as it was before #172. 6dd8ed9e accepted 100rel on every INVITE, so the first row named "path" and
// the second answered 415.
TEST(Prack100rel, NonEchoInviteWithRequire100relIsRefusedAtTheRequireLineAsOnMain)
{
	struct Row
	{
		const char* what;
		std::string extra;
		std::string contentType;
	};
	const std::vector<Row> rows = {
		{"another unknown tag follows",       "Require: 100rel, path\r\n", "application/sdp"},
		{"a body type the PBX does not parse", "Require: 100rel\r\n",       "text/plain"},
	};
	int n = 0;
	for (const Row& row : rows)
	{
		SCOPED_TRACE(row.what);
		EchoRig rig;
		rig.handler.handle(makeRegister("600", "192.168.7.60", "reg-600"));
		rig.handler.handle(makeInvite("500", "600", "192.168.7.50", "e-gate" + std::to_string(n++),
			row.extra, row.contentType));

		EXPECT_FALSE(findSent(rig.sent, "SIP/2.0 420 Bad Extension", "Unsupported: 100rel").empty())
			<< "RFC 3261 §8.2.2.3 and RFC 3262 §3: the 420 names the first tag the PBX will not honour";
		EXPECT_FALSE(anySent(rig.sent, "SIP/2.0 415"));
		EXPECT_FALSE(anySent(rig.sent, "INVITE sip:600")) << "a refused INVITE is not relayed";
	}
}

// Guard, passes on 6dd8ed9e: 100rel is a Require the PBX honours on the echo's initial INVITE and
// nowhere else, so every other request that carries it still gets the 420 it got before #172.
TEST(Prack100rel, Require100relOnARequestOtherThanInviteStays420)
{
	for (const char* method : {"UPDATE", "BYE", "REFER", "MESSAGE", "PRACK"})
	{
		SCOPED_TRACE(method);
		EchoRig rig;
		rig.handler.handle(makeGateProbe(method, std::string("e-nr-") + method, "Require: 100rel\r\n"));

		EXPECT_FALSE(findSent(rig.sent, "SIP/2.0 420 Bad Extension", std::string("CSeq: 7 ") + method).empty());
		EXPECT_TRUE(anySent(rig.sent, "Unsupported: 100rel"));
	}
}

// Red on 6dd8ed9e: a PSAP callback is emergency traffic on any To (Rule 5), so the header gate treats
// its Require: 100rel exactly as it did before #172 (a 420 verdict that yields and is counted). 6dd8ed9e
// let it through as honoured, so the yield counter stayed 0.
TEST(Prack100rel, PsapCallbackTo777WithRequire100relTakesTheEmergencyGateYield)
{
	EchoRig rig;
	rig.handler.handle(makeInvite("500", "777", "192.168.7.50", "e-psap-y",
		"Require: 100rel\r\nPriority: psap-callback\r\n"));

	EXPECT_EQ(rig.handler.getEmergencyHeaderYields(), 1u);
	EXPECT_FALSE(anySent(rig.sent, "420 Bad Extension"));
}

// Red on 6dd8ed9e (Rule 5): a PSAP callback to 777 reaches the echo branch of onInvite as an ordinary echo
// answer, and its session's dest is the virtual 777 peer. The PBX is not a PRACK UAS for it, so a PRACK
// stays unanswered whether or not the INVITE asked for 100rel; 6dd8ed9e answered it 481.
TEST(Prack100rel, PrackOnAPsapCallbackTo777DialogStaysSilent)
{
	for (const bool require100rel : {true, false})
	{
		SCOPED_TRACE(require100rel ? "with Require: 100rel" : "without Require: 100rel");
		EchoRig rig;
		const std::string id = require100rel ? "e-psap-r" : "e-psap-n";
		rig.handler.handle(makeInvite("500", "777", "192.168.7.50", id,
			std::string(require100rel ? "Require: 100rel\r\n" : "") + "Priority: psap-callback\r\n"));
		const std::string tag = toTagOf(findSent(rig.sent, "SIP/2.0 180 Ringing", "CSeq: 1 INVITE"));
		ASSERT_FALSE(tag.empty());
		ASSERT_FALSE(findSent(rig.sent, "SIP/2.0 200 OK", "CSeq: 1 INVITE").empty()) << "the callback is answered";

		rig.sent.clear();
		rig.handler.handle(makePrack(id, tag, "1 1 INVITE"));

		EXPECT_FALSE(anySent(rig.sent, "PRACK")) << "Rule 5: no 481 on an emergency dialog";
	}
}

// Red on 6dd8ed9e (Rule 5): *11 (and *69) repoint a live call's dest at a virtual 777 peer, so a call that
// is not the echo test, a relayed call or a 911 over the trunk, looks like one by its dest number. Its PRACK is
// the far leg's to answer, not the PBX's. 6dd8ed9e answered it 481.
TEST(Prack100rel, PrackOnACallRedirectedToTheEchoByStar11StaysSilent)
{
	for (const char* dialed : {"600", "911"})
	{
		SCOPED_TRACE(dialed);
		EchoRig rig;
		rig.handler.handle(makeRegister("600", "192.168.7.60", "reg-600"));
		configureTrunk(rig.handler);
		const std::string id = std::string("e-s11-") + dialed;
		const std::string key = "Call-ID: " + id;
		rig.handler.handle(makeInvite("500", dialed, "192.168.7.50", id));
		ASSERT_TRUE(rig.handler.getSession(key).has_value()) << "precondition: the call has a session";

		for (const char digit : std::string("*11")) rig.handler.handle(makeInfoDigit(id, digit));

		const auto session = rig.handler.getSession(key);
		ASSERT_TRUE(session.has_value());
		ASSERT_TRUE(session.value()->getDest());
		ASSERT_EQ(session.value()->getDest()->getNumber(), "777")
			<< "precondition: *11 moved the call's destination to the virtual echo peer";
		rig.sent.clear();
		rig.handler.handle(makePrack(id, "calleetag", "1 1 INVITE"));

		EXPECT_FALSE(anySent(rig.sent, "PRACK")) << "a relayed call's PRACK is not the PBX's to answer";
	}
}

// Guard, passes on 6dd8ed9e: RAck 0 is not an RSeq (RFC 3262 §7.1 starts at 1), so an unarmed provisional
// (RSeq 0, CSeq 0 in the session) and a retired one (RSeq back to 0, CSeq still the INVITE's) must never
// match it. Both rows depend on matchesReliableProvisional() testing _prackRSeq != 0: without it "0 0 INVITE"
// matches the plain echo and "0 1 INVITE" matches the acknowledged one.
TEST(Prack100rel, ZeroRAckNeverMatchesAnUnarmedOrRetiredProvisional)
{
	{
		SCOPED_TRACE("plain echo, no reliable provisional was sent");
		EchoRig rig;
		rig.handler.handle(makeInvite("500", "777", "192.168.7.50", "e-z0"));
		const std::string tag = toTagOf(findSent(rig.sent, "SIP/2.0 180 Ringing", "CSeq: 1 INVITE"));
		ASSERT_FALSE(tag.empty());

		rig.sent.clear();
		rig.handler.handle(makePrack("e-z0", tag, "0 0 INVITE"));

		EXPECT_FALSE(findSent(rig.sent, "SIP/2.0 481", "CSeq: 2 PRACK").empty());
		EXPECT_TRUE(findSent(rig.sent, "SIP/2.0 200 OK", "CSeq: 2 PRACK").empty());
	}
	{
		SCOPED_TRACE("reliable echo, PRACK matched and ACK received");
		EchoRig rig;
		const EchoCall call = startReliableEcho(rig, "e-z1");
		ASSERT_FALSE(call.rseq.empty());
		rig.handler.handle(makePrack("e-z1", call.tag, call.rseq + " 1 INVITE"));
		ASSERT_FALSE(findSent(rig.sent, "SIP/2.0 200 OK", "CSeq: 2 PRACK").empty());
		rig.handler.handle(makeAck("e-z1", call.tag));

		rig.sent.clear();
		rig.handler.handle(makePrack("e-z1", call.tag, "0 1 INVITE", 3, "q"));

		EXPECT_FALSE(findSent(rig.sent, "SIP/2.0 481", "CSeq: 3 PRACK").empty());
		EXPECT_TRUE(findSent(rig.sent, "SIP/2.0 200 OK", "CSeq: 3 PRACK").empty());
	}
}

// Guard, passes on 6dd8ed9e: only the dialog's own legs may PRACK it (isDialogSourceAuthorized, as BYE does).
// A PRACK naming the Call-ID from a foreign address is not answered and does not retire the reliable
// provisional, so the caller's real PRACK still matches afterwards.
TEST(Prack100rel, PrackFromAForeignAddressOnTheEchoDialogStaysSilentAndConsumesNothing)
{
	EchoRig rig;
	const EchoCall call = startReliableEcho(rig, "e-for");
	ASSERT_FALSE(call.rseq.empty());

	rig.sent.clear();
	rig.handler.handle(makePrack("e-for", call.tag, call.rseq + " 1 INVITE", 2, "x", "192.168.7.99"));

	EXPECT_FALSE(anySent(rig.sent, "PRACK")) << "a forged PRACK from a third address gets no answer at all";

	rig.handler.handle(makePrack("e-for", call.tag, call.rseq + " 1 INVITE", 3, "q"));
	EXPECT_FALSE(findSent(rig.sent, "SIP/2.0 200 OK", "CSeq: 3 PRACK").empty())
		<< "the forged PRACK must not have consumed the pending reliable provisional";
}

// Red on 6dd8ed9e: a 481 or a 420 re-processes to the same answer, so it takes no Timer J slot; only the
// matched PRACK's 200 does (RFC 3261 §17.2.3 absorbs its retransmission). 6dd8ed9e tracked every PRACK
// response the PBX authored, so the first two checks counted one slot more.
TEST(Prack100rel, OnlyTheMatchedPrackTakesAServerTransactionSlot)
{
	EchoRig rig;
	const EchoCall call = startReliableEcho(rig, "e-slot");
	ASSERT_FALSE(call.rseq.empty());
	const size_t base = rig.handler.getServerTransactionCount();

	rig.handler.handle(makePrack("e-slot", call.tag, "99 1 INVITE", 2, "a"));
	ASSERT_FALSE(findSent(rig.sent, "SIP/2.0 481", "CSeq: 2 PRACK").empty());
	EXPECT_EQ(rig.handler.getServerTransactionCount(), base) << "a 481 takes no slot";

	rig.handler.handle(makePrack("e-slot", call.tag, call.rseq + " 1 INVITE", 3, "b", "192.168.7.50", "Require: foo\r\n"));
	ASSERT_FALSE(findSent(rig.sent, "SIP/2.0 420", "CSeq: 3 PRACK").empty());
	EXPECT_EQ(rig.handler.getServerTransactionCount(), base) << "the header gate's 420 takes no slot";

	rig.handler.handle(makePrack("e-slot", call.tag, call.rseq + " 1 INVITE", 4, "c"));
	ASSERT_FALSE(findSent(rig.sent, "SIP/2.0 200 OK", "CSeq: 4 PRACK").empty());
	EXPECT_EQ(rig.handler.getServerTransactionCount(), base + 1) << "the matched PRACK's 200 takes the one slot";
}

// Red on 6dd8ed9e: refused PRACKs used to fill the server pool, so the matched PRACK's 200 found no slot,
// was not cached, and its retransmission re-ran onPrack and drew a 481. Now the flood takes no slot and
// the retransmission is answered from the cache with the same 200.
TEST(Prack100rel, RetransmittedMatchedPrackIsStillAbsorbedAfterAFloodOfRefusedPracks)
{
	EchoRig rig;
	const EchoCall call = startReliableEcho(rig, "e-flood");
	ASSERT_FALSE(call.rseq.empty());
	for (int i = 0; i < kPoolFill; ++i)
	{
		rig.sent.clear();   // the capture holds message-pool slots; the pool is smaller than the flood
		rig.handler.handle(makePrack("e-flood", call.tag, "99 1 INVITE", 3 + i, "f" + std::to_string(i)));
		ASSERT_FALSE(findSent(rig.sent, "SIP/2.0 481", "CSeq: " + std::to_string(3 + i) + " PRACK").empty())
			<< "precondition: flood PRACK " << i << " was refused";
	}
	rig.handler.handle(makePrack("e-flood", call.tag, call.rseq + " 1 INVITE", 100, "m"));
	const std::string first = findSent(rig.sent, "SIP/2.0 200 OK", "CSeq: 100 PRACK");
	ASSERT_FALSE(first.empty());

	rig.sent.clear();
	rig.handler.handle(makePrack("e-flood", call.tag, call.rseq + " 1 INVITE", 100, "m"));

	EXPECT_EQ(findSent(rig.sent, "SIP/2.0 200 OK", "CSeq: 100 PRACK"), first)
		<< "RFC 3261 §17.2.3: the retransmission gets the same response";
	EXPECT_FALSE(anySent(rig.sent, "SIP/2.0 481"));
}

// Guard, passes on 6dd8ed9e: the server transaction pool is bookkeeping for retransmission. When it is
// full nothing is refused, delayed or dropped: the reliable 180, the 200 and the matched PRACK's 200 all go out.
TEST(Prack100rel, ReliableEchoStillSendsEveryMessageWhileTheServerPoolIsFull)
{
	EchoRig rig;
	const size_t full = fillServerPool(rig);
	ASSERT_GT(full, 0u) << "precondition: the pool filled and stopped growing";
	rig.sent.clear();

	const EchoCall call = startReliableEcho(rig, "e-full");
	EXPECT_FALSE(call.rseq.empty()) << "the reliable 180 is sent although the pool cannot track it";
	EXPECT_FALSE(findSent(rig.sent, "SIP/2.0 200 OK", "CSeq: 1 INVITE").empty());

	rig.handler.handle(makePrack("e-full", call.tag, call.rseq + " 1 INVITE"));
	EXPECT_FALSE(findSent(rig.sent, "SIP/2.0 200 OK", "CSeq: 2 PRACK").empty())
		<< "the matched PRACK is answered although its 200 cannot be tracked";
	EXPECT_EQ(rig.handler.getServerTransactionCount(), full) << "nothing new fits";
}
