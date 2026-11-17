// #1048 item 1: the orphan-bridge sweep in RequestsHandler::tick() asked each
// active bridge for copies of its participant id and call id, every second, per
// bridge. The ownership check is now one lookup made under the bridge's own lock
// that compares against views of the session's ids and copies nothing.
//
// The first test measures the lookup itself (positive control: the bridge is
// reported owned, so a path that bailed out early would not pass). The other two
// drive the real tick() and pin the empty-id rule: an empty id on either side
// owns nothing, so a bridge is reaped, never kept alive by an empty match.

#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "LoopbackAnchorClient.hpp"
#include "RequestsHandler.hpp"
#include "support/AllocCounter.hpp"

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

	std::shared_ptr<SipMessage> makeRegister(const std::string& ext, const std::string& srcIp)
	{
		std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bKr1048" + ext + "\r\n"
			"From: <sip:" + ext + "@server>;tag=rt" + ext + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: reg-1048-" + ext + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + srcIp + ":5060>;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}

	std::shared_ptr<SipMessage> makeInvite(const std::string& fromExt, const std::string& toExt,
		const std::string& srcIp, const std::string& callId)
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
			"To: <sip:" + toExt + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:" + fromExt + "@" + srcIp + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}

	// Mirrors how the sweep decides one bridge against one anchor session.
	bool ownedBy(const MediaBridge& b, std::string_view sessionCallId, std::string_view sessionPart)
	{
		return b.isOwnedBy(sessionCallId, sessionPart);
	}

	struct Rig
	{
		std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
		RequestsHandler handler;
		Rig() : handler("192.168.9.1", 5060,
			[this](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
				sent.emplace_back(addr, std::move(msg));
			})
		{
			handler.handle(makeRegister("501", "192.168.9.51"));
		}
		void tickNow()
		{
			handler.forceNextTickForTest();
			handler.tick();
		}
	};
}

TEST(OrphanSweepAlloc, OwnedBridgeCheckAllocatesNothing)
{
	Rig r;
	const std::string id = "Call-ID: anchor-own-1048-long-id";
	r.handler.handle(makeInvite("501", "555", "192.168.9.51", "anchor-own-1048-long-id"));
	auto session = r.handler.getSession(id);
	ASSERT_TRUE(session.has_value());
	MediaBridge* bridge = r.handler.anchorBridgeForCallIdForTest(id);
	ASSERT_NE(bridge, nullptr);
	ASSERT_TRUE(bridge->isActive());
	const std::string part = session.value()->getAnchorParticipantId();
	ASSERT_FALSE(part.empty());

	bool owned = false;
	size_t allocs = 0;
	{
		AllocGuard guard;
		owned = ownedBy(*bridge, id, session.value()->getAnchorParticipantId());
		allocs = guard.delta();
	}
	EXPECT_TRUE(owned) << "positive control: the bridge serves this session";
	EXPECT_EQ(allocs, 0u) << "the ownership check must copy no string";
}

TEST(OrphanSweepAlloc, BridgeWithNoSessionIsStillReaped)
{
	Rig r;
	auto* loop = dynamic_cast<LoopbackAnchorClient*>(r.handler.anchorClientForTest());
	ASSERT_NE(loop, nullptr);
	const std::string id = "Call-ID: anchor-reap-1048";
	r.handler.handle(makeInvite("501", "555", "192.168.9.51", "anchor-reap-1048"));
	MediaBridge* bridge = r.handler.anchorBridgeForCallIdForTest(id);
	ASSERT_NE(bridge, nullptr);

	// Rebind the bridge to a call and a leg no session knows: an orphan.
	bridge->stopBridge();
	ASSERT_TRUE(bridge->startBridge("192.168.9.51", 10000, "Call-ID: gone-1048", "leg-gone-1048"));
	ASSERT_TRUE(bridge->isActive());

	const unsigned before = loop->dropCallCount();
	r.tickNow();
	EXPECT_FALSE(bridge->isActive()) << "an active bridge with no session is reaped";
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	EXPECT_EQ(loop->dropCallCount(), before + 1) << "its upstream leg is dropped once";

	r.tickNow();
	std::this_thread::sleep_for(std::chrono::milliseconds(100));
	EXPECT_EQ(loop->dropCallCount(), before + 1) << "a reaped bridge is not reaped again";
}

TEST(OrphanSweepAlloc, EmptyParticipantDoesNotClaimABridge)
{
	Rig r;
	const std::string id = "Call-ID: anchor-empty-1048";
	r.handler.handle(makeInvite("501", "555", "192.168.9.51", "anchor-empty-1048"));
	auto session = r.handler.getSession(id);
	ASSERT_TRUE(session.has_value());
	MediaBridge* bridge = r.handler.anchorBridgeForCallIdForTest(id);
	ASSERT_NE(bridge, nullptr);

	// Both sides have an empty participant id, and the call ids differ.
	session.value()->setAnchorParticipantId("");
	bridge->stopBridge();
	ASSERT_TRUE(bridge->startBridge("192.168.9.51", 10000, "Call-ID: other-1048", ""));
	ASSERT_TRUE(bridge->isActive());

	EXPECT_FALSE(ownedBy(*bridge, id, session.value()->getAnchorParticipantId()))
		<< "two empty ids are not a match";
	r.tickNow();
	EXPECT_FALSE(bridge->isActive()) << "an empty id owns nothing, so the bridge is reaped";
}

// The real sweep: an owned active bridge and a participant id past any small-string
// limit. The call site must build no temporary id per session per tick.
TEST(OrphanSweepAlloc, SteadyTickWithOwnedBridgeAllocatesNothing)
{
	Rig r;
	const std::string id = "Call-ID: anchor-tick-1048";
	r.handler.handle(makeInvite("501", "555", "192.168.9.51", "anchor-tick-1048"));
	auto session = r.handler.getSession(id);
	ASSERT_TRUE(session.has_value());
	MediaBridge* bridge = r.handler.anchorBridgeForCallIdForTest(id);
	ASSERT_NE(bridge, nullptr);

	// 30 chars: well past the small-string limit, and the most a bridge accepts (it
	// refuses an id of 32 or more when no bus is wired).
	const std::string longPart = "participant-0123456789-abcdefg";
	ASSERT_GE(longPart.size(), 30u);
	session.value()->setAnchorParticipantId(longPart);
	bridge->stopBridge();
	ASSERT_TRUE(bridge->startBridge("192.168.9.51", 10000, id, longPart));

	r.tickNow();
	r.tickNow();
	r.sent.clear();

	AllocGuard guard;
	r.tickNow();
	const size_t allocs = guard.delta();

	EXPECT_TRUE(bridge->isActive()) << "positive control: the sweep ran and found the bridge owned";
	EXPECT_TRUE(bridge->isOwnedBy(id, longPart));
	EXPECT_EQ(allocs, 0u) << "the sweep must copy no id per session per tick";
}
