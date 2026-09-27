// Deregistration_test.cpp — issue #523: a de-REGISTER is answered 200, not 404.
//
// onRegister() handles Expires: 0 by releasing the number's pool client, then
// sent its 200 OK through endHandle(), which looks the destination up BY NUMBER.
// The client had just been released, so endHandle() took its not-found branch
// and answered 404 Not Found. Every test UA's final unregister on .244 got 404
// (BigDog, #523), while REGISTERs with a non-zero lease got 200.
//
// RFC 3261 §10.3: a successful REGISTER, including a removal, is answered 200.
// The fix sends the REGISTER response to the transaction's source. These tests
// go through handle() end to end and fail with the old endHandle() call: each
// de-REGISTER draws a 404.

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "ConferenceRoom.hpp"
#include "RequestsHandler.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	constexpr const char* kServerIp = "192.168.52.1";

	sockaddr_in addrFor(const std::string& ip, uint16_t port = 5060)
	{
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_addr.s_addr = inet_addr(ip.c_str());
		a.sin_port = htons(port);
		return a;
	}

	using Outbox = std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>;

	// `contactParams` goes on the Contact (";expires=0" or ""); `extraHeaders`
	// carries a standalone Expires header when a test wants that form instead.
	std::shared_ptr<SipMessage> makeRegister(const std::string& ext, const std::string& ip,
		const std::string& callId, int cseq, const std::string& contactParams,
		const std::string& extraHeaders = "")
	{
		std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKd" + callId + std::to_string(cseq) + "\r\n"
			"From: <sip:" + ext + "@server>;tag=dt" + callId + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: " + std::to_string(cseq) + " REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + ip + ":5060>" + contactParams + "\r\n" +
			extraHeaders +
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}

	bool isBound(RequestsHandler& handler, const std::string& ext)
	{
		handler.forceNextTickForTest();   // getActiveClients() reads the snapshot tick() publishes,
		handler.tick();                   // and tick() republishes at most once a second
		for (const auto& [number, address] : handler.getActiveClients())
		{
			(void)address;
			if (number == ext) return true;
		}
		return false;
	}

	// The REGISTER draws exactly one response: a 200 OK, addressed to `ip`.
	// Only responses are counted, so a register-beep request can't confuse it.
	void expectOnly200To(const Outbox& sent, const std::string& ip)
	{
		std::vector<std::pair<sockaddr_in, std::string>> responses;
		for (const auto& [addr, msg] : sent)
		{
			ASSERT_NE(msg, nullptr);
			std::string raw = msg->toString();
			if (raw.rfind("SIP/2.0 ", 0) == 0) responses.emplace_back(addr, std::move(raw));
		}
		ASSERT_EQ(responses.size(), 1u) << "a de-REGISTER draws exactly one response";
		const auto& [addr, raw] = responses.front();
		EXPECT_EQ(raw.rfind("SIP/2.0 200 OK", 0), 0u)
			<< "RFC 3261 §10.3: a removal is answered 200, got: " << raw.substr(0, raw.find("\r\n"));
		EXPECT_EQ(addr.sin_addr.s_addr, inet_addr(ip.c_str())) << "answered to the wrong address";
		EXPECT_EQ(addr.sin_port, htons(5060));
	}
}

TEST(Deregistration, AnExpiresZeroContactIsAnswered200AndReleasesTheBinding)
{
	Outbox sent;
	RequestsHandler handler(kServerIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
			sent.emplace_back(a, std::move(m));
		});

	handler.handle(makeRegister("430", "192.168.52.30", "dereg-430", 1, ";expires=3600"));
	ASSERT_TRUE(isBound(handler, "430"));
	sent.clear();

	handler.handle(makeRegister("430", "192.168.52.30", "dereg-430", 2, ";expires=0"));

	ASSERT_NO_FATAL_FAILURE(expectOnly200To(sent, "192.168.52.30"));
	EXPECT_FALSE(isBound(handler, "430")) << "the binding must be gone after the 200";
}

TEST(Deregistration, AStandaloneExpiresZeroHeaderIsAnswered200Too)
{
	// The other RFC 3261 §10.2.2 spelling: no expires param on the Contact, an
	// Expires: 0 header instead.
	Outbox sent;
	RequestsHandler handler(kServerIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
			sent.emplace_back(a, std::move(m));
		});

	handler.handle(makeRegister("431", "192.168.52.31", "dereg-431", 1, ";expires=3600"));
	ASSERT_TRUE(isBound(handler, "431"));
	sent.clear();

	handler.handle(makeRegister("431", "192.168.52.31", "dereg-431", 2, "", "Expires: 0\r\n"));

	ASSERT_NO_FATAL_FAILURE(expectOnly200To(sent, "192.168.52.31"));
	EXPECT_FALSE(isBound(handler, "431"));
}

TEST(Deregistration, RemovingABindingThatNeverExistedIsStill200)
{
	// A phone that reboots twice, or a UA whose REGISTER was lost, de-registers
	// a binding the registrar never held. There is nothing to remove, and that
	// is still a successful REGISTER (RFC 3261 §10.3), not a 404.
	Outbox sent;
	RequestsHandler handler(kServerIp, 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) {
			sent.emplace_back(a, std::move(m));
		});

	handler.handle(makeRegister("432", "192.168.52.32", "dereg-432", 1, ";expires=0"));

	ASSERT_NO_FATAL_FAILURE(expectOnly200To(sent, "192.168.52.32"));
	EXPECT_FALSE(isBound(handler, "432"));
}
