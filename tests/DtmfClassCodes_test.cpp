// DtmfClassCodes_test.cpp — Issue #77 regression coverage.
//
// onDtmfInfo() runs inside handle()'s _mutex lock, so *60/*80 (DND) and
// *73/*72NNNN (call forward) used to write _dnd/_forwards directly instead of
// calling setDnd()/setForward() (which independently take the same
// non-recursive _mutex and would deadlock). That bypassed the dashboard
// snapshot refresh those setters do, so a DTMF-triggered DND/forward change
// never showed up on the HTTP dashboard (getDndExtensions()/getForwards(),
// which read the snapshot, not the live maps) until an unrelated HTTP-side
// call happened to touch the same extension.
//
// These tests drive onDtmfInfo() through RequestsHandler::handle() (real SIP
// INFO packets, one digit per packet, mirroring how a handset accumulates
// DTMF) and assert against the snapshot-reading getters a dashboard poll
// would actually use — the same observable the bug hid from.

#include <gtest/gtest.h>
#include "RequestsHandler.hpp"
#include "SipMessage.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
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

	void sendDtmfSequence(RequestsHandler& handler, const std::string& from,
	                      const std::string& srcIp, const std::string& callId,
	                      const std::string& seq)
	{
		for (char c : seq)
		{
			handler.handle(makeInfoDigit(from, srcIp, callId, c));
		}
	}

	bool contains(const std::vector<std::string>& v, const std::string& s)
	{
		for (const auto& x : v) if (x == s) return true;
		return false;
	}
}

TEST(DtmfClassCodes, StarSixty_SetsDndAndSnapshotReflectsItImmediately)
{
	RequestsHandler handler("192.168.5.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	handler.handle(makeRegisterFor("301", "192.168.5.50", "reg-60"));

	ASSERT_FALSE(contains(handler.getDndExtensions(), "301"));

	sendDtmfSequence(handler, "301", "192.168.5.50", "dtmf-60", "*60");

	EXPECT_TRUE(contains(handler.getDndExtensions(), "301"))
		<< "*60 must be visible via the same snapshot the HTTP dashboard reads, "
		   "not just in the internal _dnd map";
}

TEST(DtmfClassCodes, StarEighty_ClearsDndSetByStarSixty)
{
	RequestsHandler handler("192.168.5.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	handler.handle(makeRegisterFor("302", "192.168.5.51", "reg-80"));

	sendDtmfSequence(handler, "302", "192.168.5.51", "dtmf-80a", "*60");
	ASSERT_TRUE(contains(handler.getDndExtensions(), "302"));

	sendDtmfSequence(handler, "302", "192.168.5.51", "dtmf-80b", "*80");
	EXPECT_FALSE(contains(handler.getDndExtensions(), "302"));
}

TEST(DtmfClassCodes, Star72NNNN_SetsForwardAndSnapshotReflectsItImmediately)
{
	RequestsHandler handler("192.168.5.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	handler.handle(makeRegisterFor("303", "192.168.5.52", "reg-72"));

	sendDtmfSequence(handler, "303", "192.168.5.52", "dtmf-72", "*725500");

	bool found = false;
	for (const auto& [ext, always, busy, noAnswer, noAnswerSeconds] : handler.getForwards())
	{
		if (ext == "303")
		{
			found = true;
			EXPECT_EQ(always, "5500");
		}
	}
	EXPECT_TRUE(found) << "*72NNNN must be visible via the same snapshot the "
	                       "HTTP dashboard reads, not just in the internal "
	                       "_forwards map";
}

TEST(DtmfClassCodes, Star73_ClearsForwardSetByStar72NNNN)
{
	RequestsHandler handler("192.168.5.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	handler.handle(makeRegisterFor("304", "192.168.5.53", "reg-73"));

	sendDtmfSequence(handler, "304", "192.168.5.53", "dtmf-73a", "*725501");
	bool foundBefore = false;
	for (const auto& [ext, always, busy, noAnswer, noAnswerSeconds] : handler.getForwards())
	{
		if (ext == "304") foundBefore = true;
	}
	ASSERT_TRUE(foundBefore);

	sendDtmfSequence(handler, "304", "192.168.5.53", "dtmf-73b", "*73");
	for (const auto& [ext, always, busy, noAnswer, noAnswerSeconds] : handler.getForwards())
	{
		EXPECT_NE(ext, "304") << "*73 must clear the entry entirely once no trigger remains set";
	}
}

TEST(DtmfClassCodes, Star72NNNN_RejectsVirtualExtensionAsTheConfiguredExtension)
{
	// Issue #77: setForward()'s "extension == 777/999" guard used to only
	// apply to the HTTP-facing setter — the DTMF *72NNNN inline path skipped
	// it. A crafted mid-dialog INFO with From: 777 must not be able to set up
	// a forward entry on the virtual echo extension.
	RequestsHandler handler("192.168.5.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});

	sendDtmfSequence(handler, "777", "192.168.5.54", "dtmf-virt", "*725502");

	for (const auto& [ext, always, busy, noAnswer, noAnswerSeconds] : handler.getForwards())
	{
		EXPECT_NE(ext, "777") << "virtual extension 777 must never get a forward entry";
	}
}
