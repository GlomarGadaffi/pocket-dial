// AnchorRouting_test.cpp — wiring the AnchorClient/MediaBridge/TelephonyProvider
// extension point (docs/FEATURE_ROADMAP.md's "Anchored media") into call routing.
//
// AnchorClient_test.cpp already proves LoopbackAnchorClient's own contract in
// isolation, and MediaBridge_test.cpp already proves the AnchorClient <-> MediaBridge
// <-> PlayoutBuffer rx-fanout wiring a caller (RequestsHandler) is expected to do.
// What was missing, and what this file covers, is RequestsHandler actually doing
// that wiring at boot and routing a real dial to it: virtual extension 555 bridges
// a registered caller to whichever AnchorClient the provider registry selected
// (Loopback, since that is the only implementation this project ships) — driven
// end to end through RequestsHandler::handle(), the same style
// ConferenceRoom_test.cpp uses for the 888 intercept.
//
// Deliberately NOT asserted here: PlayoutBuffer contents. ConferenceRoom_test.cpp's
// file comment explains why -- RtpSender.cpp's "Linux desktop" branch spawns a REAL
// background pacer thread the moment startBridge() succeeds, racing any test that
// reads the playout buffer directly, and this test has no handle on the anchor
// bridges' senders to stop it first. The anchor-audio rx-fanout itself is already
// proven, thread-free, by MediaBridge_test.cpp's
// AnchorAudioReachesPlayoutBufferThroughRxFanout.

#include <gtest/gtest.h>

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

	std::shared_ptr<SipMessage> makeInvite(const std::string& fromExt, const std::string& toExt,
		const std::string& srcIp, const std::string& callId, int rtpPort = 10000)
	{
		std::string body =
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + srcIp + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + srcIp + "\r\n"
			"t=0 0\r\n"
			"m=audio " + std::to_string(rtpPort) + " RTP/AVP 0\r\n"
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

	std::shared_ptr<SipMessage> makeBye(const std::string& fromExt, const std::string& toExt,
		const std::string& srcIp, const std::string& callId)
	{
		std::string raw =
			"BYE sip:" + toExt + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bKb" + callId + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>;tag=srv" + callId + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 2 BYE\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}
}

// ── RequestsHandler's 555 intercept: dial -> anchor -> bridge ────────────────────

TEST(AnchorRouting, DialingReservedExtensionReachesAnchorAndBridgeAttaches)
{
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler("192.168.9.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	handler.handle(makeRegister("501", "192.168.9.51", "reg-501"));

	sent.clear();
	handler.handle(makeInvite("501", "555", "192.168.9.51", "anchor-1"));

	ASSERT_FALSE(sent.empty()) << "501 got no answer from 555";
	const std::string raw = sent.front().second ? sent.front().second->toString() : std::string{};
	EXPECT_NE(raw.find("SIP/2.0 200 OK"), std::string::npos)
		<< "dialing the anchor extension should be answered 200 OK, got:\n" << raw;
	EXPECT_NE(raw.find("a=sendrecv"), std::string::npos)
		<< "an anchor leg must be two-way or the bridged audio never reaches the anchor";
	EXPECT_NE(raw.find("RTP/AVP 0"), std::string::npos) << "PCMU only";
	EXPECT_NE(raw.find("Contact: <sip:555"), std::string::npos)
		<< "the answer must come from the anchor extension";

	// A real SIP session was actually allocated for this dialog...
	EXPECT_TRUE(handler.getSession("Call-ID: anchor-1").has_value());

	// ...and — the load-bearing assertion — a MediaBridge really attached and the
	// anchor's makeCall() was really invoked: LoopbackAnchorClient::makeCall()
	// hands back its fixed mock participant id ("mock-part-123") only when it was
	// actually called and that id was actually threaded through to startBridge().
	MediaBridge* bridge = handler.anchorBridgeForCallIdForTest("Call-ID: anchor-1");
	ASSERT_NE(bridge, nullptr) << "no anchor MediaBridge is bridging this call";
	EXPECT_TRUE(bridge->isActive());
	EXPECT_EQ(bridge->participantId(), "mock-part-123");
	EXPECT_EQ(bridge->callId(), "Call-ID: anchor-1");
}

TEST(AnchorRouting, DialPastCapacityIsRefusedWithoutConsumingASession)
{
	// Generalized over POCKETDIAL_MAX_ANCHOR_CALLS (documented default: 1, see
	// PoolConfig.hpp) rather than hardcoding the cap, so a deliberate -D override
	// doesn't fail this test — one caller per slot connects, then one more finds
	// every slot busy. Mirrors ConferenceRoom_test.cpp's
	// ConferenceDialIsRefusedWhenTheRoomIsFull.
	ASSERT_LE(POCKETDIAL_MAX_ANCHOR_CALLS + 1, POCKETDIAL_MAX_SESSIONS)
		<< "test assumes the anchor-bridge pool fills before the session pool does";

	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler("192.168.9.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	for (int i = 0; i <= POCKETDIAL_MAX_ANCHOR_CALLS; ++i)
	{
		const std::string ext = "6" + std::to_string(10 + i);
		const std::string ip = "192.168.9." + std::to_string(100 + i);
		const std::string callId = "anchor-busy-" + ext;
		handler.handle(makeRegister(ext, ip, "reg-" + ext));

		sent.clear();
		handler.handle(makeInvite(ext, "555", ip, callId));
		ASSERT_FALSE(sent.empty());
		const std::string raw = sent.front().second ? sent.front().second->toString() : std::string{};

		if (i < POCKETDIAL_MAX_ANCHOR_CALLS)
		{
			EXPECT_NE(raw.find("SIP/2.0 200 OK"), std::string::npos)
				<< "call " << i << " should have gotten a free bridge slot, got:\n" << raw;
		}
		else
		{
			EXPECT_NE(raw.find("503 Service Unavailable"), std::string::npos)
				<< "a dial past the anchor-bridge capacity must degrade to 503, got:\n" << raw;
			EXPECT_EQ(raw.find("SIP/2.0 200 OK"), std::string::npos)
				<< "never a false 200 for a caller that got no bridge";
			EXPECT_FALSE(handler.getSession("Call-ID: " + callId).has_value())
				<< "a refused anchor dial must not consume a session slot";
		}
	}
}

TEST(AnchorRouting, ByeReleasesTheBridgeAndEndsTheSessionThenTheSlotCanBeReused)
{
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler("192.168.9.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	handler.handle(makeRegister("501", "192.168.9.51", "reg-501"));

	sent.clear();
	handler.handle(makeInvite("501", "555", "192.168.9.51", "anchor-bye"));
	ASSERT_FALSE(sent.empty());
	ASSERT_NE(sent.front().second->toString().find("SIP/2.0 200 OK"), std::string::npos);
	ASSERT_NE(handler.anchorBridgeForCallIdForTest("Call-ID: anchor-bye"), nullptr);

	sent.clear();
	handler.handle(makeBye("501", "555", "192.168.9.51", "anchor-bye"));

	bool sawOk = false;
	for (const auto& [addr, msg] : sent)
	{
		(void)addr;
		if (msg && msg->toString().find("SIP/2.0 200 OK") != std::string::npos) sawOk = true;
	}
	EXPECT_TRUE(sawOk) << "the BYE must be answered";
	EXPECT_FALSE(handler.getSession("Call-ID: anchor-bye").has_value());
	EXPECT_EQ(handler.anchorBridgeForCallIdForTest("Call-ID: anchor-bye"), nullptr)
		<< "endCall() must release the bridge, not just the session";

	// The freed slot is really free: a fresh dial succeeds rather than 503ing.
	sent.clear();
	handler.handle(makeInvite("501", "555", "192.168.9.51", "anchor-after-bye"));
	ASSERT_FALSE(sent.empty());
	EXPECT_NE(sent.front().second->toString().find("SIP/2.0 200 OK"), std::string::npos)
		<< "the slot the first call released must be usable by the next call";
}

// ── Reserved-extension hygiene (mirrors ConferenceRoom_test.cpp's ─────────────────
// ── ConferenceExtensionIsReservedFromForwardsAndRingGroups) ────────────────────────

TEST(AnchorRouting, AnchorExtensionIsReservedFromForwardsRingGroupsAndDialPlan)
{
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler("192.168.9.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	handler.handle(makeRegister("501", "192.168.9.51", "reg-501"));
	handler.handle(makeRegister("502", "192.168.9.52", "reg-502"));

	// None of these may take: 555 is a virtual extension, exactly like 777/999/888,
	// so it must never be shadowed by a forward, a ring group, or a dial-plan rule.
	handler.setForward("555", "always", "502");
	handler.setRingGroup("555", "501,502", "ringall");
	handler.setDialRule("555", "group", "600");

	sent.clear();
	handler.handle(makeInvite("501", "555", "192.168.9.51", "anchor-reserved"));
	ASSERT_FALSE(sent.empty());
	const std::string raw = sent.front().second ? sent.front().second->toString() : std::string{};
	EXPECT_NE(raw.find("SIP/2.0 200 OK"), std::string::npos)
		<< "the anchor intercept must still win over any forward/ring-group/dial-plan "
		<< "config for 555, got:\n" << raw;
	EXPECT_NE(raw.find("Contact: <sip:555"), std::string::npos)
		<< "must still be answered as the anchor extension, not redirected to 502";
}
