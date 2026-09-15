// Issue #222: the DTMF admin menu's factory reset (*<PIN>#999#1) must wipe the
// SD CDR archive, the same as the HTTP /api/factory-reset path already does.
//
// Before this fix the DTMF path ran nvs_flash_erase() + esp_restart() and never
// touched the card, so which door the operator used decided whether a dated
// plaintext call history survived a "forget everything". These tests drive the
// real digit path (SIP INFO packets through RequestsHandler::handle(), one
// digit per packet, exactly like DtmfClassCodes_test.cpp) with a FakeSink
// installed through cdrarchive::setSinkForTest(), and assert on the one
// observable the fix adds: Sink::wipe() being called.
//
// The NVS erase and the restart are stubbed on host (platform-guarded in
// DtmfFeatureCodes.cpp), so the confirm branch is reachable here without
// rebooting the test runner.

#include <gtest/gtest.h>
#include "AdminAuth.hpp"
#include "CdrArchive.hpp"
#include "RequestsHandler.hpp"
#include "SipMessage.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	// Default admin extension is "1001" (DtmfFeatureCodes::_adminExt); the
	// admin gate only fires for a caller registered as that extension.
	constexpr const char* kAdminExt = "1001";
	constexpr const char* kAdminIp  = "192.168.7.50";
	constexpr const char* kPin      = "445566";

	class WipeSpySink : public cdrarchive::Sink
	{
	public:
		int wipes = 0;
		int appends = 0;
		void append(const cdrarchive::QueuedLine&) override { ++appends; }
		void wipe() override { ++wipes; }
	};

	class ScopedSink
	{
	public:
		explicit ScopedSink(cdrarchive::Sink* s) : _prev(cdrarchive::setSinkForTest(s)) {}
		~ScopedSink() { cdrarchive::setSinkForTest(_prev); }
	private:
		cdrarchive::Sink* _prev;
	};

	std::shared_ptr<SipMessage> makeRegisterFor(const std::string& from, const std::string& srcIp,
	                                             const std::string& callId)
	{
		sockaddr_in s{}; s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(srcIp.c_str());
		s.sin_port = htons(5060);
		std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bKr\r\n"
			"From: <sip:" + from + "@server>;tag=rt\r\n"
			"To: <sip:" + from + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + from + "@" + srcIp + ":5060>;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, s);
	}

	std::shared_ptr<SipMessage> makeInfoDigit(const std::string& from, const std::string& srcIp,
	                                           const std::string& callId, char digit)
	{
		sockaddr_in s{}; s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(srcIp.c_str());
		s.sin_port = htons(5060);
		std::string body = std::string("Signal=") + digit + "\r\nDuration=100\r\n";
		std::string head =
			"INFO sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bKi\r\n"
			"From: <sip:" + from + "@server>;tag=it\r\n"
			"To: <sip:server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INFO\r\n"
			"Content-Type: application/dtmf-relay\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
		return RequestsHandler::getMessageFromPool(head + body, s);
	}

	void sendDtmfSequence(RequestsHandler& handler, const std::string& callId, const std::string& seq)
	{
		for (char c : seq)
		{
			handler.handle(makeInfoDigit(kAdminExt, kAdminIp, callId, c));
		}
	}

	// One fixture per test: a fresh credential store with a known DTMF PIN and
	// the admin extension registered, torn back down so no PIN leaks into the
	// other suites that share AdminAuth's process-wide state.
	class DtmfFactoryReset : public ::testing::Test
	{
	protected:
		void SetUp() override
		{
			AdminAuth::clearCredential();
			ASSERT_TRUE(AdminAuth::setDtmfPin(kPin));
			handler = std::make_unique<RequestsHandler>("192.168.7.1", 5060,
				[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
			handler->handle(makeRegisterFor(kAdminExt, kAdminIp, "reg-admin-222"));
		}
		void TearDown() override
		{
			handler.reset();
			AdminAuth::clearCredential();
		}
		std::unique_ptr<RequestsHandler> handler;
	};
}

TEST_F(DtmfFactoryReset, ConfirmedResetWipesSdArchive)
{
	WipeSpySink sink;
	ScopedSink installed(&sink);

	sendDtmfSequence(*handler, "dtmf-222-confirm", std::string("*") + kPin + "#9991");

	EXPECT_EQ(sink.wipes, 1)
		<< "*<PIN>#999#1 must wipe the SD CDR archive, matching the HTTP factory "
		   "reset -- before #222 it only erased NVS and left the card intact";
}

TEST_F(DtmfFactoryReset, AbortedConfirmDigitDoesNotWipe)
{
	WipeSpySink sink;
	ScopedSink installed(&sink);

	sendDtmfSequence(*handler, "dtmf-222-abort", std::string("*") + kPin + "#9990");

	EXPECT_EQ(sink.wipes, 0)
		<< "a confirm digit other than '1' aborts the reset and must not touch the card";
}

TEST_F(DtmfFactoryReset, PendingConfirmDoesNotWipeYet)
{
	WipeSpySink sink;
	ScopedSink installed(&sink);

	// Code received, confirm digit not yet: the accumulator waits and nothing
	// destructive may have happened.
	sendDtmfSequence(*handler, "dtmf-222-pending", std::string("*") + kPin + "#999");

	EXPECT_EQ(sink.wipes, 0) << "no wipe before the '1' confirm digit arrives";
}

TEST_F(DtmfFactoryReset, WrongPinDoesNotWipe)
{
	WipeSpySink sink;
	ScopedSink installed(&sink);

	sendDtmfSequence(*handler, "dtmf-222-badpin", "*000000#9991");

	EXPECT_EQ(sink.wipes, 0) << "a failed PIN must never reach the reset branch";
}

TEST_F(DtmfFactoryReset, NonAdminCallerDoesNotWipe)
{
	WipeSpySink sink;
	ScopedSink installed(&sink);

	handler->handle(makeRegisterFor("302", "192.168.7.60", "reg-302-222"));
	const std::string seq = std::string("*") + kPin + "#9991";
	for (char c : seq)
	{
		handler->handle(makeInfoDigit("302", "192.168.7.60", "dtmf-222-nonadmin", c));
	}

	EXPECT_EQ(sink.wipes, 0) << "the admin gate only fires for the admin extension";
}

TEST_F(DtmfFactoryReset, NoSinkInstalledIsAHarmlessNoOp)
{
	// Builds without an SD archive (every non-eth-SD variant, and this host
	// build with no test Sink) must go straight through to the NVS erase.
	ScopedSink none(nullptr);

	sendDtmfSequence(*handler, "dtmf-222-nosink", std::string("*") + kPin + "#9991");

	EXPECT_EQ(cdrarchive::pendingForTest(), 0u);
	SUCCEED() << "reached the confirm branch with no Sink and did not crash";
}
