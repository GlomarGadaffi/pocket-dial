// NoAnswerTimeout_test.cpp -- Issue #1009: a per-extension no-answer timeout.
// A direct call rings the callee for the callee's configured time (5-120 s,
// default 20 s) before the CFNA target or the voicemail fallback takes it.

#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <vector>

#include "NvsWriter.hpp"
#include "RequestsHandler.hpp"
#include "ResetGuard.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	using Clock = std::chrono::steady_clock;

	sockaddr_in addrFor(const std::string& ip)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(5060);
		return s;
	}

	std::shared_ptr<SipMessage> makeRegister(const std::string& ext, const std::string& ip)
	{
		const std::string callId = "reg-" + ext;
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

	std::shared_ptr<SipMessage> makeInvite(const std::string& fromExt, const std::string& toExt,
		const std::string& ip, const std::string& callId)
	{
		std::string body =
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + ip + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + ip + "\r\n"
			"t=0 0\r\n"
			"m=audio 10000 RTP/AVP 0\r\n"
			"a=rtpmap:0 PCMU/8000\r\n";
		std::string raw =
			"INVITE sip:" + toExt + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bK" + callId + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:" + fromExt + "@" + ip + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(ip));
	}

	class NoAnswerTimeout : public ::testing::Test
	{
	protected:
		void SetUp() override
		{
			resetguard::resetForTest();
			nvswriter::resetForTest();
			_h = std::make_unique<RequestsHandler>("192.168.70.1", 5060,
				[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
			_h->handle(makeRegister("401", "192.168.70.11"));
			_h->handle(makeRegister("402", "192.168.70.12"));
			_h->handle(makeRegister("403", "192.168.70.13"));
		}
		void TearDown() override
		{
			_h.reset();
			nvswriter::resetForTest();
			resetguard::resetForTest();
		}

		// Calls 401 from 402 and checks the ring timer fires `seconds` after the INVITE.
		void expectRingTime(const std::string& callId, int seconds)
		{
			const auto before = Clock::now();
			_h->handle(makeInvite("402", "401", "192.168.70.12", callId));
			const auto after = Clock::now();
			auto session = _h->getSession("Call-ID: " + callId);
			ASSERT_TRUE(session.has_value());
			ASSERT_TRUE(session.value()->hasRingTimer());
			EXPECT_FALSE(session.value()->isRingExpired(before + std::chrono::seconds(seconds - 1)))
				<< "the timer fired before " << seconds << " s";
			EXPECT_TRUE(session.value()->isRingExpired(after + std::chrono::seconds(seconds)))
				<< "the timer had not fired by " << seconds << " s";
		}

		int rowSeconds(const std::string& ext)
		{
			for (const auto& row : _h->getForwards())
				if (std::get<0>(row) == ext) return std::get<4>(row);
			return -1;
		}

		std::unique_ptr<RequestsHandler> _h;
	};
}

TEST_F(NoAnswerTimeout, TheDefaultRingTimeIsTwentySeconds)
{
	_h->setVoicemail("401", true);
	expectRingTime("nat-default", 20);
}

TEST_F(NoAnswerTimeout, TheVoicemailFallbackUsesTheCalleesRingTime)
{
	_h->setVoicemail("401", true);
	ASSERT_TRUE(_h->setNoAnswerSeconds("401", 30));
	expectRingTime("nat-vm", 30);
}

TEST_F(NoAnswerTimeout, AnExplicitNoAnswerForwardUsesTheCalleesRingTime)
{
	_h->setForward("401", "noanswer", "403");
	ASSERT_TRUE(_h->setNoAnswerSeconds("401", 45));
	expectRingTime("nat-cfna", 45);
}

TEST_F(NoAnswerTimeout, APlainDirectCallIsBoundedByTheDefaultRingTime)
{
	expectRingTime("nat-plain", 20);
}

TEST_F(NoAnswerTimeout, TheCallersRingTimeDoesNotApply)
{
	_h->setVoicemail("401", true);
	ASSERT_TRUE(_h->setNoAnswerSeconds("402", 90));
	expectRingTime("nat-caller", 20);
}

TEST_F(NoAnswerTimeout, ZeroRestoresTheDefaultAndDropsTheOtherwiseEmptyEntry)
{
	ASSERT_TRUE(_h->setNoAnswerSeconds("401", 60));
	EXPECT_EQ(rowSeconds("401"), 60);
	ASSERT_TRUE(_h->setNoAnswerSeconds("401", 0));
	EXPECT_EQ(rowSeconds("401"), -1) << "no forward and no ring time left: the entry goes";

	_h->setVoicemail("401", true);
	expectRingTime("nat-reset", 20);
}

TEST_F(NoAnswerTimeout, OutOfRangeValuesAndReservedExtensionsAreRefused)
{
	EXPECT_FALSE(_h->setNoAnswerSeconds("401", 4));
	EXPECT_FALSE(_h->setNoAnswerSeconds("401", 121));
	EXPECT_FALSE(_h->setNoAnswerSeconds("401", -5));
	EXPECT_FALSE(_h->setNoAnswerSeconds("911", 30));
	EXPECT_FALSE(_h->setNoAnswerSeconds("888", 30));
	EXPECT_EQ(rowSeconds("401"), -1);
	EXPECT_TRUE(_h->setNoAnswerSeconds("401", 5));
	EXPECT_TRUE(_h->setNoAnswerSeconds("401", 120));
	EXPECT_EQ(rowSeconds("401"), 120);
}

TEST_F(NoAnswerTimeout, TheRingTimeIsPersistedAsAFifthForwardFieldOnlyWhenSet)
{
	nvswriter::resetForTest();
	_h->setForward("401", "noanswer", "403");
	EXPECT_EQ(std::string(nvswriter::stagedForTest(nvswriter::Key::Forwards)), "401\t\t\t403\n")
		<< "unset: byte-identical to the older four-field format";

	ASSERT_TRUE(_h->setNoAnswerSeconds("401", 30));
	EXPECT_EQ(std::string(nvswriter::stagedForTest(nvswriter::Key::Forwards)), "401\t\t\t403\t30\n");
}
