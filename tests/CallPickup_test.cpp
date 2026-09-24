// CallPickup_test.cpp — Issue #68: directed (**<ext>) and group (*8) call
// pickup.
//
// Pickup groups reuse ring-group membership as-is (see PbxConfig.hpp's
// isGroupPickupCode/directedPickupTarget doc comment): two extensions are
// pickup-eligible for each other iff setRingGroup() has them in the same
// group's member list. These tests drive the whole thing through
// RequestsHandler::handle() with real SIP packets (REGISTER, INVITE, OK, BYE)
// — the same style as DtmfClassCodes_test.cpp — and capture every outbound
// message via the onHandledEvent callback so the CANCEL-the-loser and the
// swapped-SDP 200 OKs are asserted at the wire level, not just via internal
// state.

#include <gtest/gtest.h>

#include <chrono>
#include <thread>
#include <vector>

#include "RequestsHandler.hpp"
#include "SipMessage.hpp"
#include "SipMessageTypes.h"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	sockaddr_in addrFor(const std::string& ip)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(5060);
		return s;
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

	std::string sdpBody(const std::string& mediaIp)
	{
		return
			"v=0\r\n"
			"o=- 1 1 IN IP4 " + mediaIp + "\r\n"
			"s=call\r\n"
			"c=IN IP4 " + mediaIp + "\r\n"
			"t=0 0\r\n"
			"m=audio 4000 RTP/AVP 0\r\n";
	}

	// A fresh, out-of-dialog INVITE — used both for the original caller->callee
	// call and for the picker's own **ext/*8 dial (which is, from the server's
	// point of view, just another INVITE to a virtual extension).
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

	// The ORIGINAL callee answering its own fork directly (used only by the
	// "target answers first" race test — everywhere else the callee never
	// answers, that's the whole point of picking it up).
	std::shared_ptr<SipMessage> makeOk(const std::string& callerExt, const std::string& calleeExt,
		const std::string& calleeIp, const std::string& callId)
	{
		const std::string body = sdpBody(calleeIp);
		std::string raw =
			"SIP/2.0 200 OK\r\n"
			"Via: SIP/2.0/UDP 192.168.9.1:5060;branch=z9hG4bK" + callId + "\r\n"
			"From: <sip:" + callerExt + "@server>;tag=from" + callId + "\r\n"
			"To: <sip:" + calleeExt + "@server>;tag=to" + callId + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Contact: <sip:" + calleeExt + "@" + calleeIp + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(calleeIp));
	}

	std::shared_ptr<SipMessage> makeBye(const std::string& fromExt, const std::string& toExt,
		const std::string& fromIp, const std::string& callId)
	{
		std::string raw =
			"BYE sip:" + toExt + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + fromIp + ":5060;branch=z9hG4bKbye" + callId + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=byefrom" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>;tag=byeto" + callId + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 2 BYE\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(fromIp));
	}

	// Records every message the handler ever enqueued, keyed by destination IP,
	// so assertions can look for "was a CANCEL sent to 192.168.9.20" without
	// caring which handle() call produced it.
	struct Sent
	{
		std::string destIp;
		std::string raw;
	};

	std::string ipOf(const sockaddr_in& a)
	{
		char buf[INET_ADDRSTRLEN]{};
		inet_ntop(AF_INET, &a.sin_addr, buf, sizeof(buf));
		return buf;
	}

	bool anyTo(const std::vector<Sent>& sent, const std::string& ip,
		const std::string& needle)
	{
		for (const auto& s : sent)
		{
			if (s.destIp == ip && s.raw.find(needle) != std::string::npos) return true;
		}
		return false;
	}

	size_t countTo(const std::vector<Sent>& sent, const std::string& ip)
	{
		size_t n = 0;
		for (const auto& s : sent) if (s.destIp == ip) ++n;
		return n;
	}

	// SipMessage::getCallID() (and therefore the _sessions map key) is the
	// FULL "Call-ID: <value>" header line, not the bare value used to build
	// the raw messages above.
	std::string sessionKey(const std::string& callId)
	{
		return "Call-ID: " + callId;
	}
}

// ── Directed pickup ────────────────────────────────────────────────────────

TEST(CallPickup, DirectedPickupCancelsTargetAndBridgesCallerToPicker)
{
	std::vector<Sent> sent;
	RequestsHandler handler("192.168.9.1", 5060,
		[&](const sockaddr_in& to, std::shared_ptr<SipMessage> msg) {
			sent.push_back({ ipOf(to), msg->toString() });
		});

	handler.handle(makeRegister("200", "192.168.9.10", "reg-caller"));
	handler.handle(makeRegister("100", "192.168.9.20", "reg-target"));
	handler.handle(makeRegister("102", "192.168.9.30", "reg-picker"));
	handler.setRingGroup("600", "100,102", "ringall");

	handler.handle(makeInvite("200", "100", "192.168.9.10", "call-1"));
	auto ringing = handler.getSession(sessionKey("call-1"));
	ASSERT_TRUE(ringing.has_value());
	EXPECT_EQ(ringing.value()->getState(), Session::State::Invited);

	handler.handle(makeInvite("102", "**100", "192.168.9.30", "pickup-1"));

	// The target's fork must be CANCELed — it never gets to answer.
	EXPECT_TRUE(anyTo(sent, "192.168.9.20", "CANCEL sip:100@"))
		<< "target's ringing fork must be cancelled once picked up";

	// The caller's original (still-open) INVITE transaction is completed with
	// the PICKER's SDP as the answer.
	bool callerGotPickerSdp = false;
	for (const auto& s : sent)
	{
		if (s.destIp == "192.168.9.10" && s.raw.rfind("SIP/2.0 200 OK", 0) == 0 &&
			s.raw.find("c=IN IP4 192.168.9.30") != std::string::npos)
		{
			callerGotPickerSdp = true;
		}
	}
	EXPECT_TRUE(callerGotPickerSdp) << "caller must be answered with the picker's SDP";

	// The picker's own INVITE is answered with the CALLER's original SDP.
	bool pickerGotCallerSdp = false;
	for (const auto& s : sent)
	{
		if (s.destIp == "192.168.9.30" && s.raw.rfind("SIP/2.0 200 OK", 0) == 0 &&
			s.raw.find("c=IN IP4 192.168.9.10") != std::string::npos)
		{
			pickerGotCallerSdp = true;
		}
	}
	EXPECT_TRUE(pickerGotCallerSdp) << "picker must be answered with the caller's original SDP";

	// Internal state: the original session is now Connected to the picker;
	// the picker's own session is Connected to the caller.
	auto orig = handler.getSession(sessionKey("call-1"));
	ASSERT_TRUE(orig.has_value());
	EXPECT_EQ(orig.value()->getState(), Session::State::Connected);
	ASSERT_NE(orig.value()->getDest(), nullptr);
	EXPECT_EQ(orig.value()->getDest()->getNumber(), "102");

	auto pickerSession = handler.getSession(sessionKey("pickup-1"));
	ASSERT_TRUE(pickerSession.has_value());
	EXPECT_EQ(pickerSession.value()->getState(), Session::State::Connected);
	ASSERT_NE(pickerSession.value()->getDest(), nullptr);
	EXPECT_EQ(pickerSession.value()->getDest()->getNumber(), "200");
}

TEST(CallPickup, DirectedPickupOfNonPeerExtensionGets486AndLeavesTargetRinging)
{
	std::vector<Sent> sent;
	RequestsHandler handler("192.168.9.1", 5060,
		[&](const sockaddr_in& to, std::shared_ptr<SipMessage> msg) {
			sent.push_back({ ipOf(to), msg->toString() });
		});

	handler.handle(makeRegister("200", "192.168.9.10", "reg-caller2"));
	handler.handle(makeRegister("100", "192.168.9.20", "reg-target2"));
	handler.handle(makeRegister("104", "192.168.9.40", "reg-outsider"));
	// 104 is NOT in any ring group with 100 — no shared pickup group.

	handler.handle(makeInvite("200", "100", "192.168.9.10", "call-2"));
	sent.clear();

	handler.handle(makeInvite("104", "**100", "192.168.9.40", "pickup-2"));

	EXPECT_TRUE(anyTo(sent, "192.168.9.40", "486 Busy Here"))
		<< "a picker outside the target's pickup group must be refused";
	EXPECT_FALSE(anyTo(sent, "192.168.9.20", "CANCEL"))
		<< "an ineligible pickup attempt must not disturb the still-ringing target";

	auto s = handler.getSession(sessionKey("call-2"));
	ASSERT_TRUE(s.has_value());
	EXPECT_EQ(s.value()->getState(), Session::State::Invited);
}

// ── Group pickup ───────────────────────────────────────────────────────────

TEST(CallPickup, GroupPickupAnswersTheOldestRingingCallInTheGroup)
{
	std::vector<Sent> sent;
	RequestsHandler handler("192.168.9.1", 5060,
		[&](const sockaddr_in& to, std::shared_ptr<SipMessage> msg) {
			sent.push_back({ ipOf(to), msg->toString() });
		});

	handler.handle(makeRegister("201", "192.168.9.11", "reg-c1"));
	handler.handle(makeRegister("202", "192.168.9.12", "reg-c2"));
	handler.handle(makeRegister("100", "192.168.9.21", "reg-A"));
	handler.handle(makeRegister("101", "192.168.9.22", "reg-B"));
	handler.handle(makeRegister("103", "192.168.9.33", "reg-picker3"));
	handler.setRingGroup("601", "100,101,103", "ringall");

	// 100 starts ringing first (the OLDER call)...
	handler.handle(makeInvite("201", "100", "192.168.9.11", "call-old"));
	std::this_thread::sleep_for(std::chrono::milliseconds(15));
	// ...then 101 starts ringing (the NEWER call).
	handler.handle(makeInvite("202", "101", "192.168.9.12", "call-new"));
	sent.clear();

	handler.handle(makeInvite("103", "*8", "192.168.9.33", "pickup-3"));

	// The OLDER call (100 <- 201) is the one picked up: 100's fork is
	// cancelled and 201 is bridged to the picker.
	EXPECT_TRUE(anyTo(sent, "192.168.9.21", "CANCEL sip:100@"))
		<< "the older ringing member's fork must be cancelled";
	EXPECT_FALSE(anyTo(sent, "192.168.9.22", "CANCEL"))
		<< "the newer ringing call must be left alone";

	auto oldSession = handler.getSession(sessionKey("call-old"));
	ASSERT_TRUE(oldSession.has_value());
	EXPECT_EQ(oldSession.value()->getState(), Session::State::Connected);

	auto newSession = handler.getSession(sessionKey("call-new"));
	ASSERT_TRUE(newSession.has_value());
	EXPECT_EQ(newSession.value()->getState(), Session::State::Invited)
		<< "the newer call must still be ringing untouched";
}

// ── The race: whoever answers first wins, the other never both connects ────

TEST(CallPickup, RaceTargetAnswersFirst_PickupThenGets486)
{
	std::vector<Sent> sent;
	RequestsHandler handler("192.168.9.1", 5060,
		[&](const sockaddr_in& to, std::shared_ptr<SipMessage> msg) {
			sent.push_back({ ipOf(to), msg->toString() });
		});

	handler.handle(makeRegister("200", "192.168.9.10", "reg-caller4"));
	handler.handle(makeRegister("100", "192.168.9.20", "reg-target4"));
	handler.handle(makeRegister("102", "192.168.9.30", "reg-picker4"));
	handler.setRingGroup("602", "100,102", "ringall");

	handler.handle(makeInvite("200", "100", "192.168.9.10", "call-4"));
	// The target answers on its own, before anyone tries to pick it up.
	handler.handle(makeOk("200", "100", "192.168.9.20", "call-4"));

	auto connected = handler.getSession(sessionKey("call-4"));
	ASSERT_TRUE(connected.has_value());
	EXPECT_EQ(connected.value()->getState(), Session::State::Connected);
	ASSERT_NE(connected.value()->getDest(), nullptr);
	EXPECT_EQ(connected.value()->getDest()->getNumber(), "100");

	sent.clear();
	handler.handle(makeInvite("102", "**100", "192.168.9.30", "pickup-4"));

	EXPECT_TRUE(anyTo(sent, "192.168.9.30", "486 Busy Here"))
		<< "the target already answered — pickup must lose the race";
	EXPECT_FALSE(anyTo(sent, "192.168.9.20", "CANCEL"))
		<< "an already-answered call must never be cancelled";

	// dest must still be the target — the picker never took over.
	auto after = handler.getSession(sessionKey("call-4"));
	ASSERT_TRUE(after.has_value());
	ASSERT_NE(after.value()->getDest(), nullptr);
	EXPECT_EQ(after.value()->getDest()->getNumber(), "100");
}

TEST(CallPickup, RacePickupFirst_LateAnswerFromCancelledTargetIsDropped)
{
	std::vector<Sent> sent;
	RequestsHandler handler("192.168.9.1", 5060,
		[&](const sockaddr_in& to, std::shared_ptr<SipMessage> msg) {
			sent.push_back({ ipOf(to), msg->toString() });
		});

	handler.handle(makeRegister("200", "192.168.9.10", "reg-caller5"));
	handler.handle(makeRegister("100", "192.168.9.20", "reg-target5"));
	handler.handle(makeRegister("102", "192.168.9.30", "reg-picker5"));
	handler.setRingGroup("603", "100,102", "ringall");

	handler.handle(makeInvite("200", "100", "192.168.9.10", "call-5"));
	handler.handle(makeInvite("102", "**100", "192.168.9.30", "pickup-5"));

	auto afterPickup = handler.getSession(sessionKey("call-5"));
	ASSERT_TRUE(afterPickup.has_value());
	ASSERT_NE(afterPickup.value()->getDest(), nullptr);
	EXPECT_EQ(afterPickup.value()->getDest()->getNumber(), "102");

	size_t caller200MessagesBefore = countTo(sent, "192.168.9.10");

	// The target's phone answers anyway (CANCEL/200 crossed on the wire) —
	// this must be silently dropped, not resurrect/steal the session.
	handler.handle(makeOk("200", "100", "192.168.9.20", "call-5"));

	EXPECT_EQ(countTo(sent, "192.168.9.10"), caller200MessagesBefore)
		<< "a late answer from the cancelled fork must not reach the caller";

	auto stillPicker = handler.getSession(sessionKey("call-5"));
	ASSERT_TRUE(stillPicker.has_value());
	ASSERT_NE(stillPicker.value()->getDest(), nullptr);
	EXPECT_EQ(stillPicker.value()->getDest()->getNumber(), "102")
		<< "the late answer must not overwrite the pickup winner";
}

// ── Bridge teardown ──────────────────────────────────────────────────────

TEST(CallPickup, CallerHangupTearsDownBothBridgedDialogsViaPeerCallId)
{
	std::vector<Sent> sent;
	RequestsHandler handler("192.168.9.1", 5060,
		[&](const sockaddr_in& to, std::shared_ptr<SipMessage> msg) {
			sent.push_back({ ipOf(to), msg->toString() });
		});

	handler.handle(makeRegister("200", "192.168.9.10", "reg-caller6"));
	handler.handle(makeRegister("100", "192.168.9.20", "reg-target6"));
	handler.handle(makeRegister("102", "192.168.9.30", "reg-picker6"));
	handler.setRingGroup("604", "100,102", "ringall");

	handler.handle(makeInvite("200", "100", "192.168.9.10", "call-6"));
	handler.handle(makeInvite("102", "**100", "192.168.9.30", "pickup-6"));
	ASSERT_TRUE(handler.getSession(sessionKey("call-6")).has_value());
	ASSERT_TRUE(handler.getSession(sessionKey("pickup-6")).has_value());

	sent.clear();
	handler.handle(makeBye("200", "100", "192.168.9.10", "call-6"));

	// The picker's phone must receive a BYE — but addressed within ITS OWN
	// dialog (pickup-6's Call-ID), never the caller's (call-6): a raw relay
	// of the caller's own BYE would carry the wrong Call-ID and the picker's
	// phone would reject it 481.
	bool pickerGotOwnDialogBye = false;
	bool pickerGotWrongCallId = false;
	for (const auto& s : sent)
	{
		if (s.destIp != "192.168.9.30") continue;
		if (s.raw.rfind("BYE sip:", 0) != 0) continue;
		if (s.raw.find("Call-ID: pickup-6") != std::string::npos) pickerGotOwnDialogBye = true;
		if (s.raw.find("Call-ID: call-6\r\n") != std::string::npos) pickerGotWrongCallId = true;
	}
	EXPECT_TRUE(pickerGotOwnDialogBye) << "picker's teardown BYE must use its own Call-ID";
	EXPECT_FALSE(pickerGotWrongCallId) << "the caller's Call-ID must never be relayed to the picker";

	// Both legs are gone.
	EXPECT_FALSE(handler.getSession(sessionKey("call-6")).has_value());
	EXPECT_FALSE(handler.getSession(sessionKey("pickup-6")).has_value());
}

// onBye's new peerCallID branch also fires for ParkOrbit's retrieve bridge
// (it sets peerCallID too), which never calls setDialogHeaders(). This pins
// the #72-style guard: such a leg must get session cleanup WITHOUT emitting
// the malformed "From: \r\nTo: \r\n" BYE that guard exists to prevent.
TEST(CallPickup, ParkRetrieveBridgeByeGetsCleanupWithoutMalformedBye)
{
	std::vector<Sent> sent;
	RequestsHandler handler("192.168.9.1", 5060,
		[&](const sockaddr_in& to, std::shared_ptr<SipMessage> msg) {
			sent.push_back({ ipOf(to), msg->toString() });
		});

	handler.handle(makeRegister("100", "192.168.9.50", "reg-parked"));
	handler.handle(makeRegister("101", "192.168.9.51", "reg-retriever"));

	// 100 parks itself on orbit 700.
	handler.handle(makeInvite("100", "700", "192.168.9.50", "park-call"));
	ASSERT_TRUE(handler.getSession(sessionKey("park-call")).has_value());

	// 101 retrieves it from the same orbit — this bridges park-call and
	// retrieve-call via peerCallID, exactly like a pickup, but WITHOUT ever
	// calling setDialogHeaders() on either session.
	handler.handle(makeInvite("101", "700", "192.168.9.51", "retrieve-call"));
	ASSERT_TRUE(handler.getSession(sessionKey("retrieve-call")).has_value());

	sent.clear();
	handler.handle(makeBye("101", "700", "192.168.9.51", "retrieve-call"));

	for (const auto& s : sent)
	{
		EXPECT_EQ(s.raw.find("From: \r\n"), std::string::npos)
			<< "empty-header BYE (Issue #72 class) must never be sent:\n" << s.raw;
		EXPECT_EQ(s.raw.find("To: \r\n"), std::string::npos)
			<< "empty-header BYE (Issue #72 class) must never be sent:\n" << s.raw;
	}

	// Both sessions are still cleaned up (CDR + pool slot) even though no
	// peer-phone BYE could be built for the park leg.
	EXPECT_FALSE(handler.getSession(sessionKey("retrieve-call")).has_value());
	EXPECT_FALSE(handler.getSession(sessionKey("park-call")).has_value());
}

// Issue #389: when the retriever hangs up, the BYE relayed to the PARKER goes on
// the same dialog as the server's retrieve re-INVITE, so its CSeq must be higher.
// Reusing it (both were a hardcoded 2) got pjsua's "500 Invalid CSeq" on every
// interop run and left the parker's leg up. Counted, not just found: exactly one.
TEST(CallPickup, ParkRetrieveByeToParkerGoesAboveTheReinviteCSeq)
{
	std::vector<Sent> sent;
	RequestsHandler handler("192.168.9.1", 5060,
		[&](const sockaddr_in& to, std::shared_ptr<SipMessage> msg) {
			sent.push_back({ ipOf(to), msg->toString() });
		});

	handler.handle(makeRegister("100", "192.168.9.52", "reg-parked-389"));
	handler.handle(makeRegister("101", "192.168.9.53", "reg-retriever-389"));

	handler.handle(makeInvite("100", "700", "192.168.9.52", "park-call-389"));
	handler.handle(makeInvite("101", "700", "192.168.9.53", "retrieve-call-389"));

	auto cseqOf = [](const std::string& raw) -> long {
		const auto at = raw.find("CSeq: ");
		return at == std::string::npos ? -1 : std::stol(raw.substr(at + 6));
	};
	long reinviteCSeq = -1;
	for (const auto& s : sent)
	{
		if (s.destIp == "192.168.9.52" && s.raw.rfind("INVITE sip:", 0) == 0 &&
			s.raw.find("Call-ID: park-call-389\r\n") != std::string::npos)
		{
			reinviteCSeq = cseqOf(s.raw);
		}
	}
	ASSERT_GT(reinviteCSeq, 0) << "retrieve must re-INVITE the parker on its own dialog";

	sent.clear();
	handler.handle(makeBye("101", "700", "192.168.9.53", "retrieve-call-389"));

	std::vector<long> byeCSeqs;
	for (const auto& s : sent)
	{
		if (s.destIp == "192.168.9.52" && s.raw.rfind("BYE sip:", 0) == 0 &&
			s.raw.find("Call-ID: park-call-389\r\n") != std::string::npos)
		{
			byeCSeqs.push_back(cseqOf(s.raw));
		}
	}
	ASSERT_EQ(byeCSeqs.size(), 1u) << "exactly one BYE to the parker";
	EXPECT_GT(byeCSeqs[0], reinviteCSeq)
		<< "BYE CSeq " << byeCSeqs[0] << " must exceed the re-INVITE's " << reinviteCSeq;
}
