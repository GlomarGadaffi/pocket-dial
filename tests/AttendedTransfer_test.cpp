// AttendedTransfer_test.cpp — Issue #131 regression coverage.
//
// RequestsHandler::onRefer() splices two live P2P sessions (A-B, the REFER's
// own dialog, and A-C, the consult session named by a ?Replaces= URI param on
// the Refer-To) into one B-C call: cross re-INVITEs carry each leg's SDP to
// the other, A is BYE'd out of both dialogs, and the two sessions are linked
// as a transfer bridge so a later BYE from either B or C relays to the other
// (RequestsHandler::onBye's isTransferBridge() branch) instead of reaching A.
//
// This is a port of drawbridge's e594914 ("Phase C-2 — attended transfer via
// REFER + Replaces"), adapted for pocket-dial's #101A pool-refusal discipline
// (every pool draw here is null-checked, and the whole splice draws all of its
// wire-critical messages before mutating any session state or sending
// anything) and the fact pocket-dial has no SIP-trunk/anchor concept on
// Session to guard against.
//
// Drives a real RequestsHandler through handle() end-to-end (mirroring
// BlindTransfer_test.cpp's pattern): register three extensions, A calls B and
// answers, A calls C (consult) and answers, then A sends REFER with Replaces
// naming the A-C dialog.

#include <gtest/gtest.h>

#include <memory>
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

	std::string sdpBody(const std::string& mediaIp, int port)
	{
		return
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + mediaIp + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + mediaIp + "\r\n"
			"t=0 0\r\n"
			"m=audio " + std::to_string(port) + " RTP/AVP 0\r\n"
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

	size_t countContaining(const std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>& sent,
	                       const sockaddr_in& addr, const std::string& needle)
	{
		size_t n = 0;
		for (const auto& [a, msg] : sent)
		{
			if (a.sin_addr.s_addr != addr.sin_addr.s_addr || a.sin_port != addr.sin_port) continue;
			if (msg && msg->toString().find(needle) != std::string::npos) ++n;
		}
		return n;
	}

	// Like findSentTo, but requires BOTH needles -- needed once the transferor's
	// two splice BYEs (one per leg) share the same request-line target (A's own
	// number) and are distinguishable only by which leg's Call-ID they carry.
	std::string findSentToBoth(const std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>& sent,
	                           const sockaddr_in& addr, const std::string& needle1, const std::string& needle2)
	{
		for (auto it = sent.rbegin(); it != sent.rend(); ++it)
		{
			if (it->first.sin_addr.s_addr != addr.sin_addr.s_addr) continue;
			if (it->first.sin_port != addr.sin_port) continue;
			if (!it->second) continue;
			std::string raw = it->second->toString();
			if (raw.find(needle1) != std::string::npos && raw.find(needle2) != std::string::npos) return raw;
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

	// Test fixture: registers A/B/C, places A-B and A-C direct calls, answers
	// both, and returns everything a scenario needs to send the REFER.
	struct Rig
	{
		std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
		std::unique_ptr<RequestsHandler> handler;
		sockaddr_in aAddr, bAddr, cAddr;
		std::string abCallId, acCallId;
	};

	// Takes `rig` by reference and fills it in place, rather than constructing a
	// local Rig and returning it by value: the handler's send-callback lambda
	// captures &rig, so rig must never move/relocate after construction — a
	// by-value return would risk exactly that (NRVO is compiler best-effort in
	// this shape, not guaranteed the way a prvalue return is).
	void setUpSplicedCalls(Rig& rig)
	{
		rig.aAddr = addrFor("192.168.40.10");
		rig.bAddr = addrFor("192.168.40.20");
		rig.cAddr = addrFor("192.168.40.30");
		rig.abCallId = "attxfer-ab";
		rig.acCallId = "attxfer-ac";

		rig.handler = std::make_unique<RequestsHandler>("192.168.40.1", 5060,
			[&rig](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
				rig.sent.emplace_back(addr, std::move(msg));
			});
		auto& handler = *rig.handler;
		auto& sent = rig.sent;

		handler.handle(makeRegister("100", "192.168.40.10", "reg-100c"));
		handler.handle(makeRegister("106", "192.168.40.20", "reg-106c"));
		handler.handle(makeRegister("107", "192.168.40.30", "reg-107c"));

		// A calls B, B answers.
		{
			std::string body = sdpBody("192.168.40.10", 10000);
			std::string raw =
				"INVITE sip:106@server SIP/2.0\r\n"
				"Via: SIP/2.0/UDP 192.168.40.10:5060;branch=z9hG4bKab\r\n"
				"From: <sip:100@server>;tag=abtag\r\n"
				"To: <sip:106@server>\r\n"
				"Call-ID: " + rig.abCallId + "\r\n"
				"CSeq: 1 INVITE\r\n"
				"Max-Forwards: 70\r\n"
				"Contact: <sip:100@192.168.40.10:5060>\r\n"
				"Content-Type: application/sdp\r\n"
				"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
			handler.handle(RequestsHandler::getMessageFromPool(raw, rig.aAddr));
		}
		std::string forkToB = findSentTo(sent, rig.bAddr, "INVITE sip:106@");
		{
			std::string fromLine = extractHeaderLine(forkToB, "From:");
			std::string via = extractHeaderLine(forkToB, "Via:");
			std::string body = sdpBody("192.168.40.20", 20000);
			std::string raw =
				"SIP/2.0 200 OK\r\n" + via + "\r\n" + fromLine + "\r\n"
				"To: <sip:106@server>;tag=btag\r\n"
				"Call-ID: " + rig.abCallId + "\r\n"
				"CSeq: 1 INVITE\r\n"
				"Contact: <sip:106@192.168.40.20:5060>\r\n"
				"Content-Type: application/sdp\r\n"
				"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
			handler.handle(RequestsHandler::getMessageFromPool(raw, rig.bAddr));
		}

		// A calls C (consult), C answers. Same From tag reused is fine — different
		// Call-ID makes it a distinct dialog.
		{
			std::string body = sdpBody("192.168.40.10", 10002);
			std::string raw =
				"INVITE sip:107@server SIP/2.0\r\n"
				"Via: SIP/2.0/UDP 192.168.40.10:5060;branch=z9hG4bKac\r\n"
				"From: <sip:100@server>;tag=actag\r\n"
				"To: <sip:107@server>\r\n"
				"Call-ID: " + rig.acCallId + "\r\n"
				"CSeq: 1 INVITE\r\n"
				"Max-Forwards: 70\r\n"
				"Contact: <sip:100@192.168.40.10:5060>\r\n"
				"Content-Type: application/sdp\r\n"
				"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
			handler.handle(RequestsHandler::getMessageFromPool(raw, rig.aAddr));
		}
		std::string forkToC = findSentTo(sent, rig.cAddr, "INVITE sip:107@");
		{
			std::string fromLine = extractHeaderLine(forkToC, "From:");
			std::string via = extractHeaderLine(forkToC, "Via:");
			std::string body = sdpBody("192.168.40.30", 30000);
			std::string raw =
				"SIP/2.0 200 OK\r\n" + via + "\r\n" + fromLine + "\r\n"
				"To: <sip:107@server>;tag=ctag\r\n"
				"Call-ID: " + rig.acCallId + "\r\n"
				"CSeq: 1 INVITE\r\n"
				"Contact: <sip:107@192.168.40.30:5060>\r\n"
				"Content-Type: application/sdp\r\n"
				"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
			handler.handle(RequestsHandler::getMessageFromPool(raw, rig.cAddr));
		}

		sent.clear(); // scenarios only care about traffic from the REFER onward
	}

	// Sends A's REFER on the A-B dialog with Refer-To: 107, Replaces=<A-C
	// call-id>;from-tag=actag;to-tag=ctag — percent-encoded exactly like
	// office_smoke.py's construction (Replaces=%3Bfrom-tag%3D...%3Bto-tag%3D...).
	void sendAttendedRefer(Rig& rig)
	{
		std::string raw =
			"REFER sip:106@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.40.10:5060;branch=z9hG4bKref\r\n"
			"From: <sip:100@server>;tag=abtag\r\n"
			"To: <sip:106@server>;tag=btag\r\n"
			"Call-ID: " + rig.abCallId + "\r\n"
			"CSeq: 2 REFER\r\n"
			"Max-Forwards: 70\r\n"
			"Refer-To: <sip:107@server?Replaces=" + rig.acCallId +
				"%3Bfrom-tag%3Dactag%3Bto-tag%3Dctag>\r\n"
			"Contact: <sip:100@192.168.40.10:5060>\r\n"
			"Content-Length: 0\r\n\r\n";
		rig.handler->handle(RequestsHandler::getMessageFromPool(raw, rig.aAddr));
	}

	// Adversarial-review regression (issue #131 follow-up): "the receptionist
	// case" -- B calls A first (A is the AB dialog's CALLEE, not its caller),
	// then A calls C to consult. Before the orientation fix, onRefer() assumed
	// A was always the caller of both dialogs, so bClient/bSdp resolved to A's
	// OWN identity/SDP instead of B's whenever A was actually the callee.
	void setUpSplicedCallsReceptionist(Rig& rig)
	{
		rig.aAddr = addrFor("192.168.40.10");
		rig.bAddr = addrFor("192.168.40.20");
		rig.cAddr = addrFor("192.168.40.30");
		rig.abCallId = "attxfer-ab-recept";
		rig.acCallId = "attxfer-ac-recept";

		rig.handler = std::make_unique<RequestsHandler>("192.168.40.1", 5060,
			[&rig](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
				rig.sent.emplace_back(addr, std::move(msg));
			});
		auto& handler = *rig.handler;
		auto& sent = rig.sent;

		handler.handle(makeRegister("100", "192.168.40.10", "reg-100r"));
		handler.handle(makeRegister("106", "192.168.40.20", "reg-106r"));
		handler.handle(makeRegister("107", "192.168.40.30", "reg-107r"));

		// B calls A: src=B, dest=A in the AB dialog (opposite of the base rig).
		{
			std::string body = sdpBody("192.168.40.20", 21000);
			std::string raw =
				"INVITE sip:100@server SIP/2.0\r\n"
				"Via: SIP/2.0/UDP 192.168.40.20:5060;branch=z9hG4bKrab\r\n"
				"From: <sip:106@server>;tag=rbatag\r\n"
				"To: <sip:100@server>\r\n"
				"Call-ID: " + rig.abCallId + "\r\n"
				"CSeq: 1 INVITE\r\n"
				"Max-Forwards: 70\r\n"
				"Contact: <sip:106@192.168.40.20:5060>\r\n"
				"Content-Type: application/sdp\r\n"
				"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
			handler.handle(RequestsHandler::getMessageFromPool(raw, rig.bAddr));
		}
		std::string forkToA = findSentTo(sent, rig.aAddr, "INVITE sip:100@");
		{
			std::string fromLine = extractHeaderLine(forkToA, "From:");
			std::string via = extractHeaderLine(forkToA, "Via:");
			std::string body = sdpBody("192.168.40.10", 11000);
			std::string raw =
				"SIP/2.0 200 OK\r\n" + via + "\r\n" + fromLine + "\r\n"
				"To: <sip:100@server>;tag=raatag\r\n"
				"Call-ID: " + rig.abCallId + "\r\n"
				"CSeq: 1 INVITE\r\n"
				"Contact: <sip:100@192.168.40.10:5060>\r\n"
				"Content-Type: application/sdp\r\n"
				"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
			handler.handle(RequestsHandler::getMessageFromPool(raw, rig.aAddr));
		}

		// A calls C to consult -- same orientation as the base rig for this leg.
		{
			std::string body = sdpBody("192.168.40.10", 11002);
			std::string raw =
				"INVITE sip:107@server SIP/2.0\r\n"
				"Via: SIP/2.0/UDP 192.168.40.10:5060;branch=z9hG4bKrac\r\n"
				"From: <sip:100@server>;tag=ractag\r\n"
				"To: <sip:107@server>\r\n"
				"Call-ID: " + rig.acCallId + "\r\n"
				"CSeq: 1 INVITE\r\n"
				"Max-Forwards: 70\r\n"
				"Contact: <sip:100@192.168.40.10:5060>\r\n"
				"Content-Type: application/sdp\r\n"
				"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
			handler.handle(RequestsHandler::getMessageFromPool(raw, rig.aAddr));
		}
		std::string forkToC = findSentTo(sent, rig.cAddr, "INVITE sip:107@");
		{
			std::string fromLine = extractHeaderLine(forkToC, "From:");
			std::string via = extractHeaderLine(forkToC, "Via:");
			std::string body = sdpBody("192.168.40.30", 31000);
			std::string raw =
				"SIP/2.0 200 OK\r\n" + via + "\r\n" + fromLine + "\r\n"
				"To: <sip:107@server>;tag=rctag\r\n"
				"Call-ID: " + rig.acCallId + "\r\n"
				"CSeq: 1 INVITE\r\n"
				"Contact: <sip:107@192.168.40.30:5060>\r\n"
				"Content-Type: application/sdp\r\n"
				"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
			handler.handle(RequestsHandler::getMessageFromPool(raw, rig.cAddr));
		}

		sent.clear();
	}

	// A originates the REFER within the AB dialog where A is the CALLEE: A's own
	// tag is the To-tag from the original INVITE (raatag), B's is the From-tag
	// (rbatag) -- the REFER's own From/To must swap to match, since a request's
	// From is always the SENDER's own tag, not "whoever was the original caller."
	void sendAttendedReferReceptionist(Rig& rig)
	{
		std::string raw =
			"REFER sip:106@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.40.10:5060;branch=z9hG4bKrrefer\r\n"
			"From: <sip:100@server>;tag=raatag\r\n"
			"To: <sip:106@server>;tag=rbatag\r\n"
			"Call-ID: " + rig.abCallId + "\r\n"
			"CSeq: 2 REFER\r\n"
			"Max-Forwards: 70\r\n"
			"Refer-To: <sip:107@server?Replaces=" + rig.acCallId +
				"%3Bfrom-tag%3Dractag%3Bto-tag%3Drctag>\r\n"
			"Contact: <sip:100@192.168.40.10:5060>\r\n"
			"Content-Length: 0\r\n\r\n";
		rig.handler->handle(RequestsHandler::getMessageFromPool(raw, rig.aAddr));
	}

	// Both legs inverted: B calls A AND C calls A. Exercises the
	// getInviteMessage()->getBody() SDP fallback on BOTH sides of the splice at
	// once (getRemoteSdp() would silently return A's own answer on either leg
	// if the orientation fix didn't cover both dialogs independently).
	void setUpSplicedCallsBothLegsCallee(Rig& rig)
	{
		rig.aAddr = addrFor("192.168.40.10");
		rig.bAddr = addrFor("192.168.40.20");
		rig.cAddr = addrFor("192.168.40.30");
		rig.abCallId = "attxfer-ab-bothcallee";
		rig.acCallId = "attxfer-ac-bothcallee";

		rig.handler = std::make_unique<RequestsHandler>("192.168.40.1", 5060,
			[&rig](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
				rig.sent.emplace_back(addr, std::move(msg));
			});
		auto& handler = *rig.handler;
		auto& sent = rig.sent;

		handler.handle(makeRegister("100", "192.168.40.10", "reg-100bc"));
		handler.handle(makeRegister("106", "192.168.40.20", "reg-106bc"));
		handler.handle(makeRegister("107", "192.168.40.30", "reg-107bc"));

		// B calls A.
		{
			std::string body = sdpBody("192.168.40.20", 22000);
			std::string raw =
				"INVITE sip:100@server SIP/2.0\r\n"
				"Via: SIP/2.0/UDP 192.168.40.20:5060;branch=z9hG4bKbcab\r\n"
				"From: <sip:106@server>;tag=bcbatag\r\n"
				"To: <sip:100@server>\r\n"
				"Call-ID: " + rig.abCallId + "\r\n"
				"CSeq: 1 INVITE\r\n"
				"Max-Forwards: 70\r\n"
				"Contact: <sip:106@192.168.40.20:5060>\r\n"
				"Content-Type: application/sdp\r\n"
				"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
			handler.handle(RequestsHandler::getMessageFromPool(raw, rig.bAddr));
		}
		std::string forkToA1 = findSentTo(sent, rig.aAddr, "INVITE sip:100@");
		{
			std::string fromLine = extractHeaderLine(forkToA1, "From:");
			std::string via = extractHeaderLine(forkToA1, "Via:");
			std::string body = sdpBody("192.168.40.10", 12000);
			std::string raw =
				"SIP/2.0 200 OK\r\n" + via + "\r\n" + fromLine + "\r\n"
				"To: <sip:100@server>;tag=bcaatag\r\n"
				"Call-ID: " + rig.abCallId + "\r\n"
				"CSeq: 1 INVITE\r\n"
				"Contact: <sip:100@192.168.40.10:5060>\r\n"
				"Content-Type: application/sdp\r\n"
				"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
			handler.handle(RequestsHandler::getMessageFromPool(raw, rig.aAddr));
		}

		// C calls A (a second inbound call, arriving while A is already on with
		// B -- serves as the "consult" leg for this test even though a real
		// phone would normally hold B and originate the consult itself).
		{
			std::string body = sdpBody("192.168.40.30", 33000);
			std::string raw =
				"INVITE sip:100@server SIP/2.0\r\n"
				"Via: SIP/2.0/UDP 192.168.40.30:5060;branch=z9hG4bKbcac\r\n"
				"From: <sip:107@server>;tag=bccatag\r\n"
				"To: <sip:100@server>\r\n"
				"Call-ID: " + rig.acCallId + "\r\n"
				"CSeq: 1 INVITE\r\n"
				"Max-Forwards: 70\r\n"
				"Contact: <sip:107@192.168.40.30:5060>\r\n"
				"Content-Type: application/sdp\r\n"
				"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
			handler.handle(RequestsHandler::getMessageFromPool(raw, rig.cAddr));
		}
		std::string forkToA2 = findSentToBoth(sent, rig.aAddr, "INVITE sip:100@", "Call-ID: " + rig.acCallId);
		{
			std::string fromLine = extractHeaderLine(forkToA2, "From:");
			std::string via = extractHeaderLine(forkToA2, "Via:");
			std::string body = sdpBody("192.168.40.10", 12002);
			std::string raw =
				"SIP/2.0 200 OK\r\n" + via + "\r\n" + fromLine + "\r\n"
				"To: <sip:100@server>;tag=bcaatag2\r\n"
				"Call-ID: " + rig.acCallId + "\r\n"
				"CSeq: 1 INVITE\r\n"
				"Contact: <sip:100@192.168.40.10:5060>\r\n"
				"Content-Type: application/sdp\r\n"
				"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
			handler.handle(RequestsHandler::getMessageFromPool(raw, rig.aAddr));
		}

		sent.clear();
	}

	// A originates the REFER within the AB dialog (A is callee: From carries
	// A's own tag bcaatag, To carries B's tag bcbatag) naming the AC dialog
	// (also A-as-callee) via Replaces.
	void sendAttendedReferBothLegsCallee(Rig& rig)
	{
		std::string raw =
			"REFER sip:106@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.40.10:5060;branch=z9hG4bKbcrefer\r\n"
			"From: <sip:100@server>;tag=bcaatag\r\n"
			"To: <sip:106@server>;tag=bcbatag\r\n"
			"Call-ID: " + rig.abCallId + "\r\n"
			"CSeq: 2 REFER\r\n"
			"Max-Forwards: 70\r\n"
			"Refer-To: <sip:107@server?Replaces=" + rig.acCallId +
				"%3Bfrom-tag%3Dbccatag%3Bto-tag%3Dbcaatag2>\r\n"
			"Contact: <sip:100@192.168.40.10:5060>\r\n"
			"Content-Length: 0\r\n\r\n";
		rig.handler->handle(RequestsHandler::getMessageFromPool(raw, rig.aAddr));
	}
}

// (a) 202 to A, plus a cross re-INVITE to each leg carrying the OTHER leg's SDP.
TEST(AttendedTransfer, SpliceSendsAcceptedAndCrossedReinvites)
{
	Rig rig;
	setUpSplicedCalls(rig);
	sendAttendedRefer(rig);

	EXPECT_FALSE(findSentTo(rig.sent, rig.aAddr, "SIP/2.0 202 Accepted").empty())
		<< "REFER must be accepted";

	// Issue #257. abCseq is the REFER's own CSeq (2, see sendAttendedRefer) + 1;
	// acCseq is the consult INVITE's own CSeq (1, see setUpSplicedCalls) + 1.
	// Computed independently from the fix's own stated logic, not copied from
	// a prior run's output, then confirmed to match what the code actually
	// emits -- see the code comment at the computation site for why each is a
	// real, directly-observed floor rather than an arbitrary constant.
	std::string invToB = findSentTo(rig.sent, rig.bAddr, "CSeq: 3 INVITE");
	ASSERT_FALSE(invToB.empty()) << "B must get the splice re-INVITE with a real CSeq (REFER's own CSeq + 1), not a hardcoded constant";
	EXPECT_NE(invToB.find("Call-ID: " + rig.abCallId), std::string::npos) << invToB;
	EXPECT_NE(invToB.find("c=IN IP4 192.168.40.30"), std::string::npos)
		<< "B's re-INVITE must carry C's SDP:\n" << invToB;

	std::string invToC = findSentTo(rig.sent, rig.cAddr, "CSeq: 2 INVITE");
	ASSERT_FALSE(invToC.empty()) << "C must get the splice re-INVITE with a real CSeq (consult INVITE's own CSeq + 1), not a hardcoded constant";
	EXPECT_NE(invToC.find("Call-ID: " + rig.acCallId), std::string::npos) << invToC;
	EXPECT_NE(invToC.find("c=IN IP4 192.168.40.20"), std::string::npos)
		<< "C's re-INVITE must carry B's SDP:\n" << invToC;
}

// (b) B's 200 OK to the splice re-INVITE gets ACKed and does NOT reach A —
// handleTransferOk() must intercept it before the generic onOk() relay.
TEST(AttendedTransfer, SpliceReinviteOkIsAckedNotRelayedToA)
{
	Rig rig;
	setUpSplicedCalls(rig);
	sendAttendedRefer(rig);

	// Issue #257: invToB's CSeq is now a real value (REFER's CSeq + 1 = 3, see
	// the sibling test's comment), not the old hardcoded 100.
	std::string invToB = findSentTo(rig.sent, rig.bAddr, "CSeq: 3 INVITE");
	ASSERT_FALSE(invToB.empty());
	std::string fromLine = extractHeaderLine(invToB, "From:");
	std::string toLine = extractHeaderLine(invToB, "To:");
	std::string via = extractHeaderLine(invToB, "Via:");

	rig.sent.clear();
	{
		std::string body = sdpBody("192.168.40.20", 20001);
		std::string raw =
			"SIP/2.0 200 OK\r\n" + via + "\r\n" + fromLine + "\r\n" + toLine + "\r\n"
			"Call-ID: " + rig.abCallId + "\r\n"
			// Echoes invToB's own CSeq, matching what a real UA's 200 OK to
			// that specific request would carry (RFC 3261: a response's CSeq
			// always echoes the request's).
			"CSeq: 3 INVITE\r\n"
			"Contact: <sip:106@192.168.40.20:5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		rig.handler->handle(RequestsHandler::getMessageFromPool(raw, rig.bAddr));
	}

	EXPECT_FALSE(findSentTo(rig.sent, rig.bAddr, "ACK sip:").empty())
		<< "B's splice-reinvite 200 OK must be ACKed";
	EXPECT_EQ(countContaining(rig.sent, rig.aAddr, ""), 0u)
		<< "nothing should be sent to A once the splice has completed";
}

// (c) B hangs up -> C gets a correctly-tagged BYE; A gets nothing (A is gone).
TEST(AttendedTransfer, PostSpliceByeFromOneLegRelaysToTheOtherNotToA)
{
	Rig rig;
	setUpSplicedCalls(rig);
	sendAttendedRefer(rig);
	rig.sent.clear();

	{
		std::string raw =
			"BYE sip:100@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.40.20:5060;branch=z9hG4bKbye\r\n"
			"From: <sip:106@server>;tag=btag\r\n"
			"To: <sip:100@server>;tag=abtag\r\n"
			"Call-ID: " + rig.abCallId + "\r\n"
			"CSeq: 2 BYE\r\n"
			"Max-Forwards: 70\r\n"
			"Content-Length: 0\r\n\r\n";
		rig.handler->handle(RequestsHandler::getMessageFromPool(raw, rig.bAddr));
	}

	EXPECT_FALSE(findSentTo(rig.sent, rig.bAddr, "SIP/2.0 200 OK").empty())
		<< "B's own BYE must be 200 OK'd";

	std::string byeToC = findSentTo(rig.sent, rig.cAddr, "BYE sip:");
	ASSERT_FALSE(byeToC.empty()) << "C must receive a relayed BYE";
	EXPECT_NE(byeToC.find("Call-ID: " + rig.acCallId), std::string::npos) << byeToC;
	// Impersonates A: From carries A's tag in the AC dialog, To carries C's tag.
	EXPECT_NE(extractHeaderLine(byeToC, "From:").find("tag=actag"), std::string::npos) << byeToC;
	EXPECT_NE(extractHeaderLine(byeToC, "To:").find("tag=ctag"), std::string::npos) << byeToC;

	EXPECT_EQ(countContaining(rig.sent, rig.aAddr, ""), 0u)
		<< "A is already dropped and must receive nothing for this teardown";
}

// (d) Replaces naming a Call-ID that doesn't exist -> 603, both original calls
// untouched (no BYE to anyone, no re-INVITEs).
TEST(AttendedTransfer, UnknownReplacesCallIdDeclines603LeavingBothCallsUp)
{
	Rig rig;
	setUpSplicedCalls(rig);

	std::string raw =
		"REFER sip:106@server SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.40.10:5060;branch=z9hG4bKrefbad\r\n"
		"From: <sip:100@server>;tag=abtag\r\n"
		"To: <sip:106@server>;tag=btag\r\n"
		"Call-ID: " + rig.abCallId + "\r\n"
		"CSeq: 2 REFER\r\n"
		"Max-Forwards: 70\r\n"
		"Refer-To: <sip:107@server?Replaces=no-such-call-id%40nowhere>\r\n"
		"Contact: <sip:100@192.168.40.10:5060>\r\n"
		"Content-Length: 0\r\n\r\n";
	rig.handler->handle(RequestsHandler::getMessageFromPool(raw, rig.aAddr));

	EXPECT_FALSE(findSentTo(rig.sent, rig.aAddr, "SIP/2.0 603 Decline").empty())
		<< "an unresolvable Replaces target must decline, not silently do nothing";
	EXPECT_TRUE(findSentTo(rig.sent, rig.bAddr, "BYE sip:").empty())
		<< "B must not be torn down for a splice that never happened";
	EXPECT_TRUE(findSentTo(rig.sent, rig.cAddr, "BYE sip:").empty())
		<< "C must not be torn down for a splice that never happened";

	auto ab = rig.handler->getSession("Call-ID: " + rig.abCallId);
	auto ac = rig.handler->getSession("Call-ID: " + rig.acCallId);
	ASSERT_TRUE(ab.has_value());
	ASSERT_TRUE(ac.has_value());
	EXPECT_EQ(ab.value()->getState(), Session::State::Connected);
	EXPECT_EQ(ac.value()->getState(), Session::State::Connected);
}

// (e) The receptionist case, found by adversarial review of this feature: B
// called A first (A is the AB dialog's CALLEE, not its caller), then A called
// C to consult. Before the orientation fix, onRefer() unconditionally treated
// A as the caller of both dialogs -- bClient/bSdp would resolve to A's OWN
// identity/SDP instead of B's, corrupting the splice instead of declining it.
TEST(AttendedTransfer, SpliceHandlesReceptionistOrientationBCalledAThenAConsultedC)
{
	Rig rig;
	setUpSplicedCallsReceptionist(rig);
	sendAttendedReferReceptionist(rig);

	EXPECT_FALSE(findSentTo(rig.sent, rig.aAddr, "SIP/2.0 202 Accepted").empty())
		<< "REFER must be accepted";

	// Issue #257: same REFER/consult-INVITE CSeq values as setUpSplicedCalls
	// (2 and 1 respectively), so the same expected floors apply: 3 for B, 2 for C.
	std::string invToB = findSentTo(rig.sent, rig.bAddr, "CSeq: 3 INVITE");
	ASSERT_FALSE(invToB.empty()) << "B must get the splice re-INVITE, addressed to B not A, with a real CSeq";
	EXPECT_NE(invToB.find("INVITE sip:106@"), std::string::npos)
		<< "must be addressed to B's own extension, not A's:\n" << invToB;
	EXPECT_NE(invToB.find("c=IN IP4 192.168.40.30"), std::string::npos)
		<< "B's re-INVITE must carry C's real SDP, not A's own answer:\n" << invToB;
	EXPECT_NE(extractHeaderLine(invToB, "To:").find("tag=rbatag"), std::string::npos)
		<< "must carry B's own dialog tag as To, not A's:\n" << invToB;

	std::string invToC = findSentTo(rig.sent, rig.cAddr, "CSeq: 2 INVITE");
	ASSERT_FALSE(invToC.empty()) << "C must get the splice re-INVITE with a real CSeq";
	EXPECT_NE(invToC.find("c=IN IP4 192.168.40.20"), std::string::npos)
		<< "C's re-INVITE must carry B's real SDP, not A's own answer:\n" << invToC;

	// BYE-to-A on the AB leg must impersonate B: From carries B's tag, To
	// carries A's tag -- the swapped orientation vs. the base A-as-caller case.
	std::string byeToAOnAB = findSentToBoth(rig.sent, rig.aAddr, "BYE sip:", "Call-ID: " + rig.abCallId);
	ASSERT_FALSE(byeToAOnAB.empty()) << "A must be dropped from the AB dialog";
	EXPECT_NE(extractHeaderLine(byeToAOnAB, "From:").find("tag=rbatag"), std::string::npos) << byeToAOnAB;
	EXPECT_NE(extractHeaderLine(byeToAOnAB, "To:").find("tag=raatag"), std::string::npos) << byeToAOnAB;

	// And a post-splice BYE from B must relay to C, not to the already-dropped A.
	rig.sent.clear();
	{
		std::string raw =
			"BYE sip:100@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.40.20:5060;branch=z9hG4bKrbye\r\n"
			"From: <sip:106@server>;tag=rbatag\r\n"
			"To: <sip:100@server>;tag=raatag\r\n"
			"Call-ID: " + rig.abCallId + "\r\n"
			"CSeq: 2 BYE\r\n"
			"Max-Forwards: 70\r\n"
			"Content-Length: 0\r\n\r\n";
		rig.handler->handle(RequestsHandler::getMessageFromPool(raw, rig.bAddr));
	}
	std::string byeToC = findSentTo(rig.sent, rig.cAddr, "BYE sip:");
	ASSERT_FALSE(byeToC.empty()) << "C must receive a relayed BYE, not A";
	EXPECT_EQ(countContaining(rig.sent, rig.aAddr, ""), 0u)
		<< "A is already dropped and must receive nothing for this teardown";
}

// (f) Both legs A-as-callee: B called A AND C called A. Exercises the SDP
// fallback (getInviteMessage()->getBody() instead of getRemoteSdp()) on BOTH
// sides of the splice independently -- a bug that only got one leg right
// would still pass test (e) above (which inverts only the AB leg) but fail
// here.
TEST(AttendedTransfer, SpliceHandlesBothLegsAAsCallee)
{
	Rig rig;
	setUpSplicedCallsBothLegsCallee(rig);
	sendAttendedReferBothLegsCallee(rig);

	EXPECT_FALSE(findSentTo(rig.sent, rig.aAddr, "SIP/2.0 202 Accepted").empty())
		<< "REFER must be accepted";

	// Issue #257: same REFER/consult-INVITE CSeq values as setUpSplicedCalls
	// (2 and 1 respectively), so the same expected floors apply: 3 for B, 2 for C.
	std::string invToB = findSentTo(rig.sent, rig.bAddr, "CSeq: 3 INVITE");
	ASSERT_FALSE(invToB.empty()) << "B must get the splice re-INVITE with a real CSeq";
	EXPECT_NE(invToB.find("c=IN IP4 192.168.40.30"), std::string::npos)
		<< "B's re-INVITE must carry C's real (offered) SDP, not A's own answer:\n" << invToB;

	std::string invToC = findSentTo(rig.sent, rig.cAddr, "CSeq: 2 INVITE");
	ASSERT_FALSE(invToC.empty()) << "C must get the splice re-INVITE with a real CSeq";
	EXPECT_NE(invToC.find("c=IN IP4 192.168.40.20"), std::string::npos)
		<< "C's re-INVITE must carry B's real (offered) SDP, not A's own answer:\n" << invToC;
}

// Issue #402: the flow pjsua (and RFC 5589) actually uses. A holds B with a
// re-INVITE, consults C, then REFERs on the CONSULT dialog with Replaces naming
// the held A-B one. The held dialog's splice re-INVITE used to be "its setup
// INVITE's CSeq + 1" -- exactly the hold re-INVITE's CSeq -- so B answered 500
// Invalid CSeq on every interop run and was never connected to C. Every
// server-built request on each dialog must go above what that dialog carried.
TEST(AttendedTransfer, ReferOnConsultDialogSplicesAboveTheHoldReinviteCSeq)
{
	Rig rig;
	setUpSplicedCalls(rig);   // A-B and A-C both set up at CSeq 1

	auto cseqOf = [](const std::string& raw) -> long {
		const auto at = raw.find("CSeq: ");
		return at == std::string::npos ? -1 : std::stol(raw.substr(at + 6));
	};

	// A holds B: an in-dialog re-INVITE on A-B at CSeq 2, relayed to B untouched.
	{
		std::string body = sdpBody("192.168.40.10", 10000) + "a=sendonly\r\n";
		std::string raw =
			"INVITE sip:106@192.168.40.20:5060 SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.40.10:5060;branch=z9hG4bKhold\r\n"
			"From: <sip:100@server>;tag=abtag\r\n"
			"To: <sip:106@server>;tag=btag\r\n"
			"Call-ID: " + rig.abCallId + "\r\n"
			"CSeq: 2 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:100@192.168.40.10:5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		rig.handler->handle(RequestsHandler::getMessageFromPool(raw, rig.aAddr));
	}
	const std::string holdToB = findSentTo(rig.sent, rig.bAddr, "Call-ID: " + rig.abCallId);
	ASSERT_FALSE(holdToB.empty()) << "the hold re-INVITE must be relayed to B";
	const long holdCSeq = cseqOf(holdToB);
	ASSERT_EQ(holdCSeq, 2);

	// A REFERs on the CONSULT dialog (A-C) at CSeq 2: Refer-To B, Replaces=A-B.
	rig.sent.clear();
	{
		std::string raw =
			"REFER sip:107@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.40.10:5060;branch=z9hG4bKrefc\r\n"
			"From: <sip:100@server>;tag=actag\r\n"
			"To: <sip:107@server>;tag=ctag\r\n"
			"Call-ID: " + rig.acCallId + "\r\n"
			"CSeq: 2 REFER\r\n"
			"Max-Forwards: 70\r\n"
			"Refer-To: <sip:106@server?Replaces=" + rig.abCallId +
				"%3Bfrom-tag%3Dabtag%3Bto-tag%3Dbtag>\r\n"
			"Contact: <sip:100@192.168.40.10:5060>\r\n"
			"Content-Length: 0\r\n\r\n";
		rig.handler->handle(RequestsHandler::getMessageFromPool(raw, rig.aAddr));
	}
	ASSERT_FALSE(findSentTo(rig.sent, rig.aAddr, "202 Accepted").empty())
		<< "the splice must be accepted";

	// B's splice re-INVITE travels on the HELD dialog and must go above the hold.
	ASSERT_EQ(countContaining(rig.sent, rig.bAddr, "Call-ID: " + rig.abCallId), 1u)
		<< "exactly one splice re-INVITE to B";
	const std::string spliceToB = findSentTo(rig.sent, rig.bAddr, "Call-ID: " + rig.abCallId);
	ASSERT_EQ(spliceToB.rfind("INVITE sip:", 0), 0u) << spliceToB;
	EXPECT_GT(cseqOf(spliceToB), holdCSeq)
		<< "splice re-INVITE CSeq " << cseqOf(spliceToB) << " must exceed the hold re-INVITE's "
		<< holdCSeq << " -- B answers 500 Invalid CSeq otherwise";

	// C's splice re-INVITE travels on the consult dialog and must go above A's REFER.
	const std::string spliceToC = findSentTo(rig.sent, rig.cAddr, "INVITE sip:");
	ASSERT_FALSE(spliceToC.empty());
	EXPECT_GT(cseqOf(spliceToC), 2) << "must exceed the REFER's CSeq on the consult dialog";

	// Everything the server sends A on each dialog goes above what that dialog carried.
	const std::string byeAonAB = findSentToBoth(rig.sent, rig.aAddr, "BYE sip:", "Call-ID: " + rig.abCallId);
	const std::string byeAonAC = findSentToBoth(rig.sent, rig.aAddr, "BYE sip:", "Call-ID: " + rig.acCallId);
	ASSERT_FALSE(byeAonAB.empty());
	ASSERT_FALSE(byeAonAC.empty());
	EXPECT_GT(cseqOf(byeAonAB), holdCSeq);
	EXPECT_GT(cseqOf(byeAonAC), 2);
}
