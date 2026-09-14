// RegisterBeepRouting_test.cpp — response-dispatch routing for the register-beep
// dialog (drawbridge #178 and #90).
//
// The beep is a server-originated UAC INVITE with no Session: RegisterBeeper owns
// it, keyed by Call-ID. RequestsHandler::onFinalFailure() consults the beeper, but
// handle()'s dispatch switch (RequestsHandler.cpp, the getStatusInfo() switch) only
// routes a response THERE when its status code has no more specific handlerKey.
// 180, 480, 486 and 487 all have their own keys, so onRinging(), onUnavailable(),
// onBusy() and onReqTerminated() saw them instead — and none of those consulted the
// beeper. Every one of them ended at endHandle(data->getFromNumber(), ...), which
// resolves the beep's own From. That From is the server's <sip:pbx@...>
// (RegisterBeeper::sendBeep), "pbx" is not a registered extension, and endHandle's
// else branch answers an unresolvable destination with 404 Not Found — aimed
// straight back at the phone that had just been beeped. The finals additionally
// went unACKed, which RFC 3261 §17.1.1.3 makes mandatory inside the INVITE
// transaction, so the phone retransmitted them until Timer H (~32 s) while the beep
// slot stayed pinned.
//
// tests/InteropRfc_test.cpp:BeepInviteRefusedByThePhoneIsAckedNotLeftHanging covers
// the SAME dialog with a 400 Bad SDP — the one code with no specific handlerKey,
// and therefore the one code that already reached the guarded handler. That is
// exactly why this survived. These tests drive the four codes that did not.
//
// The 180 case is deliberately asymmetric: a provisional response takes NO ACK
// (RFC 3261 §17.1.1) and does not end the INVITE transaction, so the assertion is
// "no 404 AND no ACK", followed by a 200 OK proving the dialog kept its slot.

#include <gtest/gtest.h>

#include <memory>
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
	constexpr const char* kServerIp = "192.168.9.1";
	constexpr uint16_t    kPhonePort = 5062;   // deliberately NOT the server's 5060

	sockaddr_in addrFor(const std::string& ip, uint16_t port = kPhonePort)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(port);
		return s;
	}

	std::shared_ptr<SipMessage> makeRegister(const std::string& ext, const std::string& srcIp,
	                                         const std::string& callId)
	{
		const std::string port = std::to_string(kPhonePort);
		std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":" + port + ";branch=z9hG4bKr" + callId + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + callId + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + srcIp + ":" + port + ">;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}

	std::string firstMatching(const std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>& sent,
	                          const std::string& needle)
	{
		for (const auto& [addr, msg] : sent)
		{
			(void)addr;
			std::string raw = msg ? msg->toString() : std::string{};
			if (raw.find(needle) != std::string::npos) return raw;
		}
		return {};
	}

	// One live beep dialog, pulled off the wire exactly as the phone would read it:
	// register an extension, capture the INVITE the registration triggers, and keep
	// the dialog identifiers needed to answer it. `sent` is cleared afterward so
	// every assertion below concerns only what the RESPONSE produced.
	struct BeepScenario
	{
		std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
		std::unique_ptr<RequestsHandler> handler;
		std::string ext;
		std::string phoneIp;
		std::string via;
		std::string from;
		std::string callId;

		// Feed the phone's response for this dialog back through handle(), the same
		// entry point the UDP receive path uses — so the dispatch switch under test
		// is the real one, not a direct call into a handler.
		void reply(const std::string& statusLine, const std::string& cseq = "1 INVITE")
		{
			std::string raw =
				statusLine + "\r\n"
				"Via: " + via + "\r\n"
				"From: " + from + "\r\n"
				"To: <sip:" + ext + "@" + std::string(kServerIp) + ">;tag=phonetag\r\n"
				"Call-ID: " + callId + "\r\n"
				"CSeq: " + cseq + "\r\n"
				"Content-Length: 0\r\n\r\n";
			handler->handle(RequestsHandler::getMessageFromPool(raw, addrFor(phoneIp)));
		}
	};

	// Each scenario takes its own extension/IP: the message and client pools are
	// process-global, so two tests sharing "505" would collide.
	std::unique_ptr<BeepScenario> beepFor(const std::string& ext, const std::string& phoneIp)
	{
		auto s = std::make_unique<BeepScenario>();
		s->ext = ext;
		s->phoneIp = phoneIp;
		BeepScenario* raw = s.get();
		s->handler = std::make_unique<RequestsHandler>(kServerIp, 5060,
			[raw](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
				raw->sent.emplace_back(addr, std::move(msg));
			});

		s->handler->handle(makeRegister(ext, phoneIp, "reg-" + ext));
		const std::string beep = firstMatching(s->sent, "INVITE sip:" + ext + "@");
		if (beep.empty()) return s;   // caller ASSERTs on the empty callId

		auto headerValue = [&beep](const std::string& name) {
			size_t at = beep.find(name);
			if (at == std::string::npos) return std::string{};
			size_t eol = beep.find("\r\n", at);
			return beep.substr(at + name.size(), eol - (at + name.size()));
		};
		s->via    = headerValue("Via: ");
		s->from   = headerValue("From: ");
		s->callId = headerValue("Call-ID: ");
		s->sent.clear();
		return s;
	}

	// The two failures shared by every case: the phone must never be answered with a
	// 404 minted off the beep's own "pbx" From, and a CANCEL must never follow a
	// final response (RFC 3261 §9.1).
	void expectNo404(const BeepScenario& s, const char* what)
	{
		EXPECT_TRUE(firstMatching(s.sent, "SIP/2.0 404 Not Found").empty())
			<< what << " was turned into a 404 Not Found aimed back at the phone "
			   "(endHandle() resolving the beep's own \"pbx\" From)";
	}

	void expectAckedInTransaction(const BeepScenario& s, const char* what)
	{
		const std::string ack = firstMatching(s.sent, "ACK sip:" + s.ext + "@");
		ASSERT_FALSE(ack.empty())
			<< what << " to our own INVITE was not ACKed (RFC 3261 §17.1.1.3): the "
			   "phone retransmits it until Timer H and the beep slot stays pinned";
		EXPECT_NE(ack.find(s.callId), std::string::npos)
			<< "the ACK belongs to a different dialog than the INVITE it answers";
		EXPECT_NE(ack.find("CSeq: 1 ACK"), std::string::npos)
			<< "the ACK must reuse the INVITE's CSeq number (same transaction)";
		EXPECT_TRUE(firstMatching(s.sent, "CANCEL sip:" + s.ext + "@").empty())
			<< "CANCEL sent after a final response (RFC 3261 §9.1 forbids it)";
	}
}

// ── Finals: 487 / 486 / 480 ──────────────────────────────────────────────────

TEST(RegisterBeepRouting, RequestTerminatedIsAckedNotAnswered404)
{
	// 487 is the response the phone sends to the CANCEL sweep() issues when the
	// beep goes unanswered — the #90 case. handlerKey REQUEST_TERMINATED routes it
	// to onReqTerminated(), which never consulted the beeper.
	auto s = beepFor("505", "192.168.9.55");
	ASSERT_FALSE(s->callId.empty()) << "no register-beep INVITE was sent";

	s->reply("SIP/2.0 487 Request Terminated");

	expectNo404(*s, "487 Request Terminated");
	expectAckedInTransaction(*s, "487 Request Terminated");
}

TEST(RegisterBeepRouting, BusyHereIsAckedNotAnswered404)
{
	// A phone that is already on a call declines the beep with 486. handlerKey
	// BUSY routes it to onBusy().
	auto s = beepFor("506", "192.168.9.56");
	ASSERT_FALSE(s->callId.empty()) << "no register-beep INVITE was sent";

	s->reply("SIP/2.0 486 Busy Here");

	expectNo404(*s, "486 Busy Here");
	expectAckedInTransaction(*s, "486 Busy Here");
}

TEST(RegisterBeepRouting, TemporarilyUnavailableIsAckedNotAnswered404)
{
	// A phone in DND answers 480. handlerKey UNAVAILABLE routes it to
	// onUnavailable(). This is the most common of the four in practice: DND is
	// exactly the state a freshly-registered desk phone is often left in.
	auto s = beepFor("507", "192.168.9.57");
	ASSERT_FALSE(s->callId.empty()) << "no register-beep INVITE was sent";

	s->reply("SIP/2.0 480 Temporarily Unavailable");

	expectNo404(*s, "480 Temporarily Unavailable");
	expectAckedInTransaction(*s, "480 Temporarily Unavailable");
}

// ── Provisional: 180 ─────────────────────────────────────────────────────────

TEST(RegisterBeepRouting, RingingIsSwallowedWithoutAckAndLeavesTheDialogLive)
{
	// A phone that rings the beep instead of auto-answering sends 180 first.
	// Provisional: no ACK is owed (RFC 3261 §17.1.1) and the INVITE transaction is
	// still open, so the ONLY thing that must change versus the old behaviour is
	// that no 404 goes back. ACKing here would be the opposite bug — acknowledging
	// a response that takes none and releasing a dialog still awaiting its final.
	auto s = beepFor("508", "192.168.9.58");
	ASSERT_FALSE(s->callId.empty()) << "no register-beep INVITE was sent";

	s->reply("SIP/2.0 180 Ringing");

	expectNo404(*s, "180 Ringing");
	EXPECT_TRUE(firstMatching(s->sent, "ACK sip:508@").empty())
		<< "a provisional 180 was ACKed — RFC 3261 §17.1.1 acknowledges only finals";
	EXPECT_TRUE(firstMatching(s->sent, "CANCEL sip:508@").empty())
		<< "180 Ringing triggered a CANCEL";

	// The dialog must have SURVIVED the 180 with its slot intact. Prove it the only
	// way the wire can: answer it, and require the normal ACK+BYE teardown. If the
	// 180 had been routed through the consuming failure path, the beeper would have
	// released the slot and this 200 OK would match nothing.
	s->sent.clear();
	s->reply("SIP/2.0 200 OK");

	EXPECT_FALSE(firstMatching(s->sent, "ACK sip:508@").empty())
		<< "the 200 OK after a 180 was not ACKed — the 180 released the beep slot";
	EXPECT_FALSE(firstMatching(s->sent, "BYE sip:508@").empty())
		<< "the answered beep was never torn down with a BYE";
	expectNo404(*s, "the 200 OK following a 180");
}
