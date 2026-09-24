// SpliceInDialog_test.cpp -- issue #453: a B2BUA splice joins two dialogs with
// DIFFERENT Call-IDs (the sessions are linked by peerCallID), so an in-dialog
// request from one phone must be rebuilt in the OTHER dialog before it reaches
// the other phone: that dialog's Call-ID and tags, a CSeq above everything the
// PBX has sent on it (#402), and the PBX's own Contact (#425). The answer must
// come back the same way, onto the originator's own transaction. Before #453
// the relay forwarded the request verbatim, so the far phone saw a Call-ID it
// had never seen and answered 481 (Globox's audit, issuecomment-5813671968),
// and on a parked call the parked party's re-INVITE was sent back to itself.
//
// Every test drives the real handler with real packets, built in the shape of
// the park_retrieve trace in #453. The assertion is the same for every splice
// and method (expectRelayIntoPeer below).

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "RequestsHandler.hpp"
#include "SipMessage.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	constexpr const char* kPbxIp = "192.168.9.1";

	sockaddr_in addrFor(const std::string& ip)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(5060);
		return s;
	}

	std::string ipOf(const sockaddr_in& a)
	{
		char buf[INET_ADDRSTRLEN]{};
		inet_ntop(AF_INET, &a.sin_addr, buf, sizeof(buf));
		return buf;
	}

	struct Sent
	{
		std::string destIp;
		std::string raw;
	};

	std::string sessionKey(const std::string& callId) { return "Call-ID: " + callId; }

	std::string stripName(const std::string& header)
	{
		const auto colon = header.find(':');
		if (colon == std::string::npos) return header;
		size_t i = colon + 1;
		while (i < header.size() && header[i] == ' ') ++i;
		return header.substr(i);
	}

	// Value of a header line (without its name), or "" if absent.
	std::string headerValue(const std::string& raw, const std::string& name)
	{
		const std::string needle = "\r\n" + name + ": ";
		const auto at = raw.find(needle);
		if (at == std::string::npos) return "";
		const auto start = at + needle.size();
		return raw.substr(start, raw.find("\r\n", start) - start);
	}

	uint32_t cseqNumber(const std::string& raw)
	{
		const std::string v = headerValue(raw, "CSeq");
		return v.empty() ? 0u : static_cast<uint32_t>(std::stoul(v));
	}

	std::string sdpBody(const std::string& mediaIp, const char* direction = nullptr)
	{
		std::string b =
			"v=0\r\n"
			"o=- 1 1 IN IP4 " + mediaIp + "\r\n"
			"s=call\r\n"
			"c=IN IP4 " + mediaIp + "\r\n"
			"t=0 0\r\n"
			"m=audio 4000 RTP/AVP 0\r\n";
		if (direction) b += std::string("a=") + direction + "\r\n";
		return b;
	}

	std::shared_ptr<SipMessage> makeRegister(const std::string& ext, const std::string& ip)
	{
		const std::string cid = "reg-" + ext;
		std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKr" + ext + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + ext + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: " + cid + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + ip + ":5060>;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}

	std::shared_ptr<SipMessage> makeInvite(const std::string& fromExt, const std::string& toExt,
		const std::string& fromIp, const std::string& callId)
	{
		const std::string body = sdpBody(fromIp);
		std::string raw =
			"INVITE sip:" + toExt + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + fromIp + ":5060;branch=z9hG4bK" + callId + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=from" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Contact: <sip:" + fromExt + "@" + fromIp + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(fromIp));
	}

	// A phone's answer to a request the PBX sent it: echoes Via/From/To/Call-ID/
	// CSeq from that request (adding the phone's To-tag if the request had none),
	// as a real UAS does.
	std::shared_ptr<SipMessage> answerTo(const std::string& request, const std::string& fromIp,
		const std::string& status = "200 OK", const std::string& body = "")
	{
		std::string to = headerValue(request, "To");
		if (to.find(";tag=") == std::string::npos) to += ";tag=uas" + fromIp;
		std::string raw =
			"SIP/2.0 " + status + "\r\n"
			"Via: " + headerValue(request, "Via") + "\r\n"
			"From: " + headerValue(request, "From") + "\r\n"
			"To: " + to + "\r\n"
			"Call-ID: " + headerValue(request, "Call-ID") + "\r\n"
			"CSeq: " + headerValue(request, "CSeq") + "\r\n"
			"Contact: <sip:phone@" + fromIp + ":5060>\r\n";
		if (!body.empty())
			raw += "Content-Type: application/sdp\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		else
			raw += "Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(fromIp));
	}

	// The in-dialog request a phone sends on its OWN dialog: its own From/tag and
	// the PBX's tag (taken from the dialog headers the session captured).
	std::shared_ptr<SipMessage> inDialog(const std::string& method, const std::shared_ptr<Session>& own,
		const std::string& fromIp, uint32_t cseq, const std::string& body)
	{
		const std::string callId = stripName(std::string(own->getCallID()));
		std::string raw =
			method + " sip:pbx@" + std::string(kPbxIp) + ":5060 SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + fromIp + ":5060;branch=z9hG4bKin" + method + std::to_string(cseq) + "\r\n"
			"From: " + stripName(own->getDialogFrom()) + "\r\n"
			"To: " + stripName(own->getDialogTo()) + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: " + std::to_string(cseq) + " " + method + "\r\n"
			"Contact: <sip:phone@" + fromIp + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(fromIp));
	}

	std::shared_ptr<SipMessage> ackFor(const std::string& okRaw, const std::string& fromIp)
	{
		std::string raw =
			"ACK sip:pbx@" + std::string(kPbxIp) + ":5060 SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + fromIp + ":5060;branch=z9hG4bKack" + std::to_string(cseqNumber(okRaw)) + "\r\n"
			"From: " + headerValue(okRaw, "From") + "\r\n"
			"To: " + headerValue(okRaw, "To") + "\r\n"
			"Call-ID: " + headerValue(okRaw, "Call-ID") + "\r\n"
			"CSeq: " + std::to_string(cseqNumber(okRaw)) + " ACK\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(fromIp));
	}

	const Sent* onlyOne(const std::vector<Sent>& sent, const std::string& ip, const std::string& startLine,
		size_t& count)
	{
		const Sent* hit = nullptr;
		count = 0;
		for (const auto& s : sent)
		{
			if (s.destIp == ip && s.raw.rfind(startLine, 0) == 0)
			{
				++count;
				hit = &s;
			}
		}
		return hit;
	}

	struct Harness
	{
		std::vector<Sent> sent;
		RequestsHandler handler{kPbxIp, 5060,
			[this](const sockaddr_in& to, std::shared_ptr<SipMessage> msg) {
				sent.push_back({ ipOf(to), msg->toString() });
			}};
	};

	// The whole #453 contract for one in-dialog request, from the phone that owns
	// `ownKey`'s session (at `fromIp`) to the phone on the peer dialog (at `peerIp`).
	// `peerOwnTag` / `peerRemoteTag`, when given, are the tags the TARGET phone
	// knows its dialog by (its own, and the one it knows the other side by). A
	// transfer bridge impersonates the dropped transferor, so there the test pins
	// the tags themselves rather than re-deriving the code's orientation.
	void expectRelayIntoPeer(Harness& h, const std::string& ownKey, const std::string& fromIp,
		const std::string& peerIp, const std::string& method, uint32_t cseq,
		const char* peerOwnTag = nullptr, const char* peerRemoteTag = nullptr)
	{
		SCOPED_TRACE(method + " from " + fromIp + " on " + ownKey);
		auto own = h.handler.getSession(ownKey);
		ASSERT_TRUE(own.has_value()) << "precondition: sender's session";
		ASSERT_FALSE(own.value()->getPeerCallID().empty()) << "precondition: spliced";
		auto peer = h.handler.getSession(own.value()->getPeerCallID());
		ASSERT_TRUE(peer.has_value()) << "precondition: peer session";
		const uint32_t peerCSeqBefore = peer.value()->lastServerCSeq();
		const std::string peerCallId = stripName(std::string(peer.value()->getCallID()));

		// ── 1. the request ───────────────────────────────────────────────────
		h.sent.clear();
		h.handler.handle(inDialog(method, own.value(), fromIp, cseq, sdpBody(fromIp, "sendonly")));

		for (const auto& s : h.sent)
		{
			EXPECT_EQ(s.raw.find("481 Call"), std::string::npos) << "no 481 anywhere:\n" << s.raw;
			EXPECT_FALSE(s.destIp == fromIp && s.raw.rfind(method + " ", 0) == 0)
				<< "the originator must never receive its own request back:\n" << s.raw;
		}
		size_t n = 0;
		const Sent* req = onlyOne(h.sent, peerIp, method + " ", n);
		ASSERT_EQ(n, 1u) << "exactly one " << method << " must reach the peer phone";
		EXPECT_EQ(headerValue(req->raw, "Call-ID"), peerCallId) << "the PEER dialog's Call-ID:\n" << req->raw;
		if (peerOwnTag)
		{
			EXPECT_NE(headerValue(req->raw, "To").find(std::string(";tag=") + peerOwnTag), std::string::npos)
				<< "To carries the peer phone's own tag:\n" << req->raw;
			EXPECT_NE(headerValue(req->raw, "From").find(std::string(";tag=") + peerRemoteTag), std::string::npos)
				<< "From carries the tag the peer phone knows the other side by:\n" << req->raw;
		}
		else
		{
			EXPECT_EQ(headerValue(req->raw, "From"), stripName(peer.value()->getDialogTo()))
				<< "From = the PBX's side of the peer dialog:\n" << req->raw;
			EXPECT_EQ(headerValue(req->raw, "To"), stripName(peer.value()->getDialogFrom()))
				<< "To = the peer phone's own URI and tag:\n" << req->raw;
		}
		const uint32_t sentCSeq = cseqNumber(req->raw);
		EXPECT_GT(sentCSeq, peerCSeqBefore) << "above every CSeq the PBX sent on that dialog (#402)";
		EXPECT_NE(headerValue(req->raw, "CSeq").find(method), std::string::npos);
		EXPECT_NE(headerValue(req->raw, "Contact").find(std::string(kPbxIp) + ":5060"), std::string::npos)
			<< "the PBX's own Contact (#425):\n" << req->raw;
		EXPECT_NE(req->raw.find("c=IN IP4 " + fromIp), std::string::npos) << "the sender's SDP, untouched";
		EXPECT_EQ(peer.value()->lastServerCSeq(), sentCSeq) << "recorded on the peer dialog";
		size_t early = 0;
		(void)onlyOne(h.sent, fromIp, "SIP/2.0 200", early);
		EXPECT_EQ(early, 0u) << "no final answer to the originator before the peer answers";

		// ── 2. the peer answers ──────────────────────────────────────────────
		const std::string reqRaw = req->raw;
		h.sent.clear();
		h.handler.handle(answerTo(reqRaw, peerIp, "200 OK", sdpBody(peerIp)));

		const Sent* ok = onlyOne(h.sent, fromIp, "SIP/2.0 200 OK", n);
		ASSERT_EQ(n, 1u) << "exactly one final answer on the originator's own transaction";
		EXPECT_EQ(headerValue(ok->raw, "Call-ID"), stripName(ownKey)) << ok->raw;
		EXPECT_EQ(headerValue(ok->raw, "CSeq"), std::to_string(cseq) + " " + method) << ok->raw;
		EXPECT_NE(ok->raw.find("c=IN IP4 " + peerIp), std::string::npos) << "the peer's SDP answer";
		EXPECT_NE(headerValue(ok->raw, "Contact").find(std::string(kPbxIp) + ":5060"), std::string::npos)
			<< "the PBX's own Contact (#425):\n" << ok->raw;
		size_t acks = 0;
		const Sent* ack = onlyOne(h.sent, peerIp, "ACK ", acks);
		if (method == "INVITE")
		{
			ASSERT_EQ(acks, 1u) << "the PBX ACKs the peer's 2xx itself";
			EXPECT_EQ(headerValue(ack->raw, "Call-ID"), peerCallId);
			EXPECT_EQ(headerValue(ack->raw, "CSeq"), std::to_string(sentCSeq) + " ACK");
		}
		else
		{
			EXPECT_EQ(acks, 0u) << "UPDATE is not ACKed";
		}
		for (const auto& s : h.sent) EXPECT_EQ(s.raw.find("481 Call"), std::string::npos) << s.raw;

		// ── 3. the originator's ACK stays in its own dialog ──────────────────
		if (method == "INVITE")
		{
			const std::string okRaw = ok->raw;
			h.sent.clear();
			h.handler.handle(ackFor(okRaw, fromIp));
			EXPECT_TRUE(h.sent.empty()) << "the originator's ACK is absorbed, never relayed:\n"
				<< (h.sent.empty() ? "" : h.sent.front().raw);
		}
	}

	// ── splice setups ────────────────────────────────────────────────────────

	// Directed pickup: 200 (192.168.9.10) calls 100; 102 (192.168.9.30) picks it
	// up with **100. Sessions: call-P (caller) and pickup-P (picker), spliced.
	void setUpPickup(Harness& h)
	{
		h.handler.handle(makeRegister("200", "192.168.9.10"));
		h.handler.handle(makeRegister("100", "192.168.9.20"));
		h.handler.handle(makeRegister("102", "192.168.9.30"));
		// Pickup needs the picker grouped with the target (same setup as
		// CallPickup_test's spliced-refresh test).
		h.handler.setRingGroup("607", "100,102", "ringall");
		h.handler.handle(makeInvite("200", "100", "192.168.9.10", "call-P"));
		h.handler.handle(makeInvite("102", "**100", "192.168.9.30", "pickup-P"));
	}

	// Attended transfer (the AttendedTransfer_test orientation): A=100
	// (192.168.9.60) calls B=106 (.61), consults C=107 (.62), then REFERs B to C
	// with Replaces. The PBX's splice re-INVITEs to B and C are answered and
	// ACKed, as real phones would, so B and C are bridged and A is gone.
	// B's dialog tags: btag (own) / abtag (A's). C's: ctag (own) / actag (A's).
	void setUpAttendedTransfer(Harness& h)
	{
		const std::string aIp = "192.168.9.60", bIp = "192.168.9.61", cIp = "192.168.9.62";
		h.handler.handle(makeRegister("100", aIp));
		h.handler.handle(makeRegister("106", bIp));
		h.handler.handle(makeRegister("107", cIp));

		auto callAndAnswer = [&](const std::string& toExt, const std::string& toIp, const std::string& callId,
			const std::string& aTag, const std::string& farTag) {
			const std::string body = sdpBody(aIp);
			std::string raw =
				"INVITE sip:" + toExt + "@server SIP/2.0\r\n"
				"Via: SIP/2.0/UDP " + aIp + ":5060;branch=z9hG4bK" + callId + "\r\n"
				"From: <sip:100@server>;tag=" + aTag + "\r\n"
				"To: <sip:" + toExt + "@server>\r\n"
				"Call-ID: " + callId + "\r\n"
				"CSeq: 1 INVITE\r\n"
				"Contact: <sip:100@" + aIp + ":5060>\r\n"
				"Content-Type: application/sdp\r\n"
				"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
			h.sent.clear();
			h.handler.handle(RequestsHandler::getMessageFromPool(raw, addrFor(aIp)));
			std::string fork;
			for (const auto& m : h.sent)
				if (m.destIp == toIp && m.raw.rfind("INVITE ", 0) == 0) { fork = m.raw; break; }
			ASSERT_FALSE(fork.empty()) << "precondition: the call reached " << toExt;
			const std::string answer = sdpBody(toIp);
			std::string ok =
				"SIP/2.0 200 OK\r\n"
				"Via: " + headerValue(fork, "Via") + "\r\n"
				"From: " + headerValue(fork, "From") + "\r\n"
				"To: <sip:" + toExt + "@server>;tag=" + farTag + "\r\n"
				"Call-ID: " + callId + "\r\n"
				"CSeq: 1 INVITE\r\n"
				"Contact: <sip:" + toExt + "@" + toIp + ":5060>\r\n"
				"Content-Type: application/sdp\r\n"
				"Content-Length: " + std::to_string(answer.size()) + "\r\n\r\n" + answer;
			h.handler.handle(RequestsHandler::getMessageFromPool(ok, addrFor(toIp)));
		};
		callAndAnswer("106", bIp, "xfer-AB", "abtag", "btag");
		callAndAnswer("107", cIp, "xfer-AC", "actag", "ctag");

		h.sent.clear();
		std::string refer =
			"REFER sip:106@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + aIp + ":5060;branch=z9hG4bKref\r\n"
			"From: <sip:100@server>;tag=abtag\r\n"
			"To: <sip:106@server>;tag=btag\r\n"
			"Call-ID: xfer-AB\r\n"
			"CSeq: 2 REFER\r\n"
			"Refer-To: <sip:107@server?Replaces=xfer-AC%3Bfrom-tag%3Dactag%3Bto-tag%3Dctag>\r\n"
			"Contact: <sip:100@" + aIp + ":5060>\r\n"
			"Content-Length: 0\r\n\r\n";
		h.handler.handle(RequestsHandler::getMessageFromPool(refer, addrFor(aIp)));

		// Answer the PBX's splice re-INVITEs to B and C.
		std::vector<std::pair<std::string, std::string>> reinvites;
		for (const auto& m : h.sent)
			if ((m.destIp == bIp || m.destIp == cIp) && m.raw.rfind("INVITE ", 0) == 0)
				reinvites.emplace_back(m.destIp, m.raw);
		ASSERT_EQ(reinvites.size(), 2u) << "precondition: the splice re-INVITEs went to B and C";
		for (const auto& [ip, inv] : reinvites)
			h.handler.handle(answerTo(inv, ip, "200 OK", sdpBody(ip)));
	}

	// Park retrieve: 101 (192.168.9.50) parks on 700; 103 (192.168.9.51)
	// retrieves. The PBX's retrieve re-INVITE to 101 is answered and ACKed
	// first, as a real phone would, so the bridge is fully up.
	void setUpParkRetrieve(Harness& h)
	{
		h.handler.handle(makeRegister("101", "192.168.9.50"));
		h.handler.handle(makeRegister("103", "192.168.9.51"));
		h.handler.handle(makeInvite("101", "700", "192.168.9.50", "parked-P"));
		h.sent.clear();
		h.handler.handle(makeInvite("103", "700", "192.168.9.51", "retrieve-P"));
		for (const auto& s : h.sent)
		{
			if (s.destIp == "192.168.9.50" && s.raw.rfind("INVITE ", 0) == 0)
			{
				const std::string reinvite = s.raw;
				h.handler.handle(answerTo(reinvite, "192.168.9.50", "200 OK", sdpBody("192.168.9.50")));
				break;
			}
		}
	}
}

// ── Directed pickup ──────────────────────────────────────────────────────────

TEST(SpliceInDialog, PickupReinviteFromThePickerReachesTheCallerInTheCallersDialog)
{
	Harness h;
	setUpPickup(h);
	expectRelayIntoPeer(h, sessionKey("pickup-P"), "192.168.9.30", "192.168.9.10", "INVITE", 5);
}

TEST(SpliceInDialog, PickupReinviteFromTheCallerReachesThePickerInThePickersDialog)
{
	Harness h;
	setUpPickup(h);
	expectRelayIntoPeer(h, sessionKey("call-P"), "192.168.9.10", "192.168.9.30", "INVITE", 5);
}

TEST(SpliceInDialog, PickupSdpUpdateCrossesInBothDirections)
{
	Harness h;
	setUpPickup(h);
	expectRelayIntoPeer(h, sessionKey("pickup-P"), "192.168.9.30", "192.168.9.10", "UPDATE", 6);
	expectRelayIntoPeer(h, sessionKey("call-P"), "192.168.9.10", "192.168.9.30", "UPDATE", 7);
}

// ── Park retrieve (the #453 trace) ───────────────────────────────────────────

TEST(SpliceInDialog, ParkRetrieverUpdateReachesTheParkedPartyInTheParkedDialog)
{
	// The trace: the retriever's UPDATE, forwarded untranslated, drew a 481.
	Harness h;
	setUpParkRetrieve(h);
	expectRelayIntoPeer(h, sessionKey("retrieve-P"), "192.168.9.51", "192.168.9.50", "UPDATE", 5);
}

TEST(SpliceInDialog, ParkRetrieverReinviteReachesTheParkedPartyInTheParkedDialog)
{
	Harness h;
	setUpParkRetrieve(h);
	expectRelayIntoPeer(h, sessionKey("retrieve-P"), "192.168.9.51", "192.168.9.50", "INVITE", 5);
}

TEST(SpliceInDialog, ParkedPartysReinviteReachesTheRetrieverNotItself)
{
	// The parked session's dest is a virtual peer carrying the parked party's
	// OWN address; the raw relay sent its re-INVITE back to it.
	Harness h;
	setUpParkRetrieve(h);
	expectRelayIntoPeer(h, sessionKey("parked-P"), "192.168.9.50", "192.168.9.51", "INVITE", 5);
}

TEST(SpliceInDialog, ParkedPartysSdpUpdateReachesTheRetrieverNotItself)
{
	Harness h;
	setUpParkRetrieve(h);
	expectRelayIntoPeer(h, sessionKey("parked-P"), "192.168.9.50", "192.168.9.51", "UPDATE", 5);
}

// ── Attended transfer (the survivors B and C, A dropped) ─────────────────────

TEST(SpliceInDialog, AttendedTransferSurvivorBsReinviteReachesCNotTheDroppedTransferor)
{
	// The audit: B's re-INVITE on A-B went to A (gone) under A-B's Call-ID.
	Harness h;
	setUpAttendedTransfer(h);
	expectRelayIntoPeer(h, sessionKey("xfer-AB"), "192.168.9.61", "192.168.9.62", "INVITE", 5,
		"ctag", "actag");
}

TEST(SpliceInDialog, AttendedTransferSurvivorCsReinviteReachesBNotTheDroppedTransferor)
{
	Harness h;
	setUpAttendedTransfer(h);
	expectRelayIntoPeer(h, sessionKey("xfer-AC"), "192.168.9.62", "192.168.9.61", "INVITE", 5,
		"btag", "abtag");
}

TEST(SpliceInDialog, AttendedTransferSdpUpdateCrossesBetweenTheSurvivors)
{
	Harness h;
	setUpAttendedTransfer(h);
	expectRelayIntoPeer(h, sessionKey("xfer-AB"), "192.168.9.61", "192.168.9.62", "UPDATE", 6, "ctag", "actag");
	expectRelayIntoPeer(h, sessionKey("xfer-AC"), "192.168.9.62", "192.168.9.61", "UPDATE", 7, "btag", "abtag");
}

TEST(SpliceInDialog, AttendedTransferDroppedTransferorsReinviteIsNotRelayedAnywhere)
{
	// A is no longer a party to either dialog; nothing it sends may reach B or C.
	Harness h;
	setUpAttendedTransfer(h);
	auto ab = h.handler.getSession(sessionKey("xfer-AB"));
	ASSERT_TRUE(ab.has_value());
	h.sent.clear();
	std::string raw =
		"INVITE sip:106@server SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.9.60:5060;branch=z9hG4bKstaleA\r\n"
		"From: <sip:100@server>;tag=abtag\r\n"
		"To: <sip:106@server>;tag=btag\r\n"
		"Call-ID: xfer-AB\r\n"
		"CSeq: 9 INVITE\r\n"
		"Contact: <sip:100@192.168.9.60:5060>\r\n"
		"Content-Type: application/sdp\r\n"
		"Content-Length: " + std::to_string(sdpBody("192.168.9.60").size()) + "\r\n\r\n" + sdpBody("192.168.9.60");
	h.handler.handle(RequestsHandler::getMessageFromPool(raw, addrFor("192.168.9.60")));
	for (const auto& m : h.sent)
	{
		EXPECT_NE(m.destIp, "192.168.9.61") << "nothing from A reaches B:\n" << m.raw;
		EXPECT_NE(m.destIp, "192.168.9.62") << "nothing from A reaches C:\n" << m.raw;
	}
}
