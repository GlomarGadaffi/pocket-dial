// AnchorRouting_test.cpp — wiring the AnchorClient/MediaBridge/TelephonyProvider
// extension point (docs/FEATURE_ROADMAP.md's "Anchored media") into call routing.
//
// AnchorClient_test.cpp already proves LoopbackAnchorClient's own contract in
// isolation, and MediaBridge_test.cpp already proves the AnchorClient <-> MediaBridge
// <-> PlayoutBuffer rx-fanout wiring a caller (RequestsHandler) is expected to do.
// What was missing, and what this file covers, is RequestsHandler actually doing
// that wiring at boot and routing a real dial to it: virtual extension 555 bridges
// a registered caller to whichever AnchorClient the provider registry selected
// (Loopback here, for deterministic, no-network testing — a second real
// implementation, TelephonyAnchorClient, exists but isn't exercised by this
// host suite) — driven end to end through RequestsHandler::handle(), the same
// style ConferenceRoom_test.cpp uses for the 888 intercept.
//
// Deliberately NOT asserted here: PlayoutBuffer contents. ConferenceRoom_test.cpp's
// file comment explains why -- RtpSender.cpp's "Linux desktop" branch spawns a REAL
// background pacer thread the moment startBridge() succeeds, racing any test that
// reads the playout buffer directly, and this test has no handle on the anchor
// bridges' senders to stop it first. The anchor-audio rx-fanout itself is already
// proven, thread-free, by MediaBridge_test.cpp's
// AnchorAudioReachesPlayoutBufferThroughRxFanout.

#include <algorithm>
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

	// A phone's in-dialog re-INVITE — issue #218. `toHeaderLine` is the exact
	// FULL "To: ...;tag=..." line the ORIGINAL 200 OK carried, straight from
	// toHeaderOf() below — not a fresh one, since this is a request on an
	// already-established dialog. `direction` is the SDP attribute line to
	// offer ("a=sendonly\r\n" for hold, "a=sendrecv\r\n" for resume).
	std::shared_ptr<SipMessage> makeHoldReinvite(const std::string& fromExt,
		const std::string& toHeaderLine, const std::string& srcIp, const std::string& callId,
		int cseq, const std::string& direction, int rtpPort = 10000)
	{
		std::string body =
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + srcIp + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + srcIp + "\r\n"
			"t=0 0\r\n"
			"m=audio " + std::to_string(rtpPort) + " RTP/AVP 0\r\n"
			"a=rtpmap:0 PCMU/8000\r\n" + direction;
		std::string raw =
			"INVITE sip:555@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bKih" + callId + std::to_string(cseq) + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			+ toHeaderLine + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: " + std::to_string(cseq) + " INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:" + fromExt + "@" + srcIp + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}

	// Issue #263: the legacy RFC 2543 hold shape -- session level says
	// "a=sendrecv" (an explicit, unambiguous "not holding" by direction alone)
	// while the AUDIO section's own connection address is blackholed. Same
	// request shape as makeHoldReinvite() above; the only difference is the
	// body, which needs a session-level line makeHoldReinvite()'s single
	// trailing `direction` parameter cannot express.
	std::shared_ptr<SipMessage> makeLegacyHoldReinvite(const std::string& fromExt,
		const std::string& toHeaderLine, const std::string& srcIp, const std::string& callId,
		int cseq, int rtpPort = 10000)
	{
		std::string body =
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + srcIp + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + srcIp + "\r\n"
			"t=0 0\r\n"
			"a=sendrecv\r\n"
			"m=audio " + std::to_string(rtpPort) + " RTP/AVP 0\r\n"
			"c=IN IP4 0.0.0.0\r\n"
			"a=rtpmap:0 PCMU/8000\r\n";
		std::string raw =
			"INVITE sip:555@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bKih" + callId + std::to_string(cseq) + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			+ toHeaderLine + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: " + std::to_string(cseq) + " INVITE\r\n"
			"Max-Forwards: 70\r\n"
			"Contact: <sip:" + fromExt + "@" + srcIp + ":5060>\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}

	// Pulls the FULL "To: ...;tag=..." line out of a sent SipMessage
	// (SipMessage::getTo() already returns the complete raw header line, not
	// just its value — see setTo()'s symmetric contract), for building the
	// next in-dialog request in a test.
	std::string toHeaderOf(const std::shared_ptr<SipMessage>& msg)
	{
		return std::string(msg->getTo());
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

TEST(AnchorRouting, PcmaOnlyOfferGets488NotABridgeItCannotDecode)
{
	// Issue #304: MediaBridge::onHandsetRtp only mu-law-decodes, and
	// buildMediaSdp's answer is PCMU-only regardless of what was offered,
	// so a PCMA-only offer must be refused rather than bridged into silence.
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler("192.168.9.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	handler.handle(makeRegister("505", "192.168.9.55", "reg-505"));

	sent.clear();
	sockaddr_in s = addrFor("192.168.9.55");
	std::string body =
		"v=0\r\n"
		"o=- 0 0 IN IP4 192.168.9.55\r\n"
		"s=-\r\n"
		"c=IN IP4 192.168.9.55\r\n"
		"t=0 0\r\n"
		"m=audio 10000 RTP/AVP 8\r\n"
		"a=rtpmap:8 PCMA/8000\r\n";
	std::string raw =
		"INVITE sip:555@server SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.9.55:5060;branch=z9hG4bKanchorpcma\r\n"
		"From: <sip:505@server>;tag=ftanchorpcma\r\n"
		"To: <sip:555@server>\r\n"
		"Call-ID: anchor-pcma\r\n"
		"CSeq: 1 INVITE\r\n"
		"Max-Forwards: 70\r\n"
		"Contact: <sip:505@192.168.9.55:5060>\r\n"
		"Content-Type: application/sdp\r\n"
		"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
	handler.handle(RequestsHandler::getMessageFromPool(raw, s));

	ASSERT_FALSE(sent.empty()) << "PCMA-only offer to 555 got no response at all";
	const std::string respRaw = sent.front().second ? sent.front().second->toString() : std::string{};
	EXPECT_NE(respRaw.find("SIP/2.0 488"), std::string::npos)
		<< "PCMA-only offer should be refused with 488, got:\n" << respRaw;
	EXPECT_FALSE(handler.getSession("Call-ID: anchor-pcma").has_value())
		<< "must refuse before claiming a session";
}

TEST(AnchorRouting, DialPastCapacityIsRefusedWithoutConsumingASession)
{
	// Generalized over the EFFECTIVE limit, not the array size. Those are two
	// different numbers and conflating them is the bug this guards:
	//
	//   * POCKETDIAL_MAX_ANCHOR_CALLS sizes _mediaBridges — the machinery.
	//   * AnchorClient::maxConcurrentCalls() is what the plugged-in provider can
	//     actually drive.
	//
	// This test runs against LoopbackAnchorClient, which hands back the CONSTANT
	// participant id "mock-part-123" (asserted a few tests above). The engine keys
	// its rx-audio fan-out on that id via bridgeForParticipant(), which returns the
	// FIRST match — so a second concurrent loopback call would be signalled fine
	// and then have its audio fed to the first call's bridge. Signalling-only
	// assertions cannot see that, which is exactly why the limit has to be the
	// provider's, and why the loopback reports 1 however large the array grows.
	//
	// Mirrors ConferenceRoom_test.cpp's ConferenceDialIsRefusedWhenTheRoomIsFull.
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler("192.168.9.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	ASSERT_NE(handler.anchorClientForTest(), nullptr);
	const int kLimit = static_cast<int>(
		std::min<unsigned>(handler.anchorClientForTest()->maxConcurrentCalls(),
		                   static_cast<unsigned>(POCKETDIAL_MAX_ANCHOR_CALLS)));
	ASSERT_GE(kLimit, 1);
	ASSERT_LE(kLimit + 1, POCKETDIAL_MAX_SESSIONS)
		<< "test assumes the anchor-bridge capacity fills before the session pool does";

	for (int i = 0; i <= kLimit; ++i)
	{
		const std::string ext = "6" + std::to_string(10 + i);
		const std::string ip = "192.168.9." + std::to_string(100 + i);
		const std::string callId = "anchor-busy-" + ext;
		handler.handle(makeRegister(ext, ip, "reg-" + ext));

		sent.clear();
		handler.handle(makeInvite(ext, "555", ip, callId));
		ASSERT_FALSE(sent.empty());
		const std::string raw = sent.front().second ? sent.front().second->toString() : std::string{};

		if (i < kLimit)
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

// ── Hold/resume on an anchored leg (issue #218) ──────────────────────────────
//
// Before this fix, onReinvite()/onUpdate() refused a re-INVITE on the anchor
// extension with the same 488 the two genuinely peer-less virtual legs
// (777/888) get — confirmed on hardware: a phone could never hold an
// anchored/trunk call at all, so the far end heard silence (from the phone's
// own local mute), never hold music. These tests drive the fix end to end
// through RequestsHandler::handle() -- the same style the rest of this file
// already uses for the anchor intercept itself.

TEST(AnchorRouting, HoldOnTheAnchorLegIsAnsweredNotRefused)
{
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler("192.168.9.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	handler.handle(makeRegister("501", "192.168.9.51", "reg-501"));

	sent.clear();
	handler.handle(makeInvite("501", "555", "192.168.9.51", "anchor-hold"));
	ASSERT_FALSE(sent.empty());
	const std::string toLine = toHeaderOf(sent.front().second);
	ASSERT_NE(toLine.find(";tag="), std::string::npos)
		<< "the original 200 OK must have minted a to-tag, got: " << toLine;

	MediaBridge* bridge = handler.anchorBridgeForCallIdForTest("Call-ID: anchor-hold");
	ASSERT_NE(bridge, nullptr);
	ASSERT_FALSE(bridge->isHeld());

	sent.clear();
	handler.handle(makeHoldReinvite("501", toLine, "192.168.9.51", "anchor-hold",
		/*cseq=*/2, "a=sendonly\r\n"));

	ASSERT_FALSE(sent.empty()) << "the hold re-INVITE got no answer at all";
	const std::string holdRaw = sent.front().second ? sent.front().second->toString() : std::string{};
	EXPECT_NE(holdRaw.find("SIP/2.0 200 OK"), std::string::npos)
		<< "a hold on the anchor leg must be ANSWERED, not refused with 488 -- "
		<< "this is the exact bug (#218): the caller never actually put the "
		<< "call on hold, so the far end heard silence instead of hold music. Got:\n"
		<< holdRaw;
	EXPECT_EQ(holdRaw.find("SIP/2.0 488"), std::string::npos) << holdRaw;

	EXPECT_TRUE(bridge->isHeld())
		<< "the bridge must switch to held mode so the anchor hears hold music "
		<< "instead of the handset";

	auto session = handler.getSession("Call-ID: anchor-hold");
	ASSERT_TRUE(session.has_value());
	EXPECT_EQ(session.value()->getState(), Session::State::Held);
}

TEST(AnchorRouting, ResumingTheAnchorLegClearsHeldStateAndRestoresTheHandsetPath)
{
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler("192.168.9.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	handler.handle(makeRegister("501", "192.168.9.51", "reg-501"));

	sent.clear();
	handler.handle(makeInvite("501", "555", "192.168.9.51", "anchor-resume"));
	ASSERT_FALSE(sent.empty());
	const std::string toLine = toHeaderOf(sent.front().second);

	handler.handle(makeHoldReinvite("501", toLine, "192.168.9.51", "anchor-resume",
		/*cseq=*/2, "a=sendonly\r\n"));

	MediaBridge* bridge = handler.anchorBridgeForCallIdForTest("Call-ID: anchor-resume");
	ASSERT_NE(bridge, nullptr);
	ASSERT_TRUE(bridge->isHeld()) << "setup: the hold must have taken for this test to mean anything";

	sent.clear();
	handler.handle(makeHoldReinvite("501", toLine, "192.168.9.51", "anchor-resume",
		/*cseq=*/3, "a=sendrecv\r\n"));

	ASSERT_FALSE(sent.empty());
	const std::string resumeRaw = sent.front().second ? sent.front().second->toString() : std::string{};
	EXPECT_NE(resumeRaw.find("SIP/2.0 200 OK"), std::string::npos) << resumeRaw;
	EXPECT_FALSE(bridge->isHeld())
		<< "resuming must switch the bridge back to forwarding the handset's own audio";

	auto session = handler.getSession("Call-ID: anchor-resume");
	ASSERT_TRUE(session.has_value());
	EXPECT_EQ(session.value()->getState(), Session::State::Connected);
}

// Issue #263: sdp::isHold() had zero production callers, so the legacy RFC
// 2543 hold shape (session-level a=sendrecv, the AUDIO section's OWN
// connection blackholed) was never detected on the anchor leg either --
// answerAnchorReinvite() called getSdpDirection(), which never looks at the
// connection address at all. Same end-to-end style as
// HoldOnTheAnchorLegIsAnsweredNotRefused above, legacy body instead.
TEST(AnchorRouting, HoldOnTheAnchorLegDetectsTheLegacyZeroAddressSignal)
{
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler("192.168.9.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	handler.handle(makeRegister("501", "192.168.9.51", "reg-501"));

	sent.clear();
	handler.handle(makeInvite("501", "555", "192.168.9.51", "anchor-legacy-hold"));
	ASSERT_FALSE(sent.empty());
	const std::string toLine = toHeaderOf(sent.front().second);

	MediaBridge* bridge = handler.anchorBridgeForCallIdForTest("Call-ID: anchor-legacy-hold");
	ASSERT_NE(bridge, nullptr);
	ASSERT_FALSE(bridge->isHeld());

	sent.clear();
	handler.handle(makeLegacyHoldReinvite("501", toLine, "192.168.9.51", "anchor-legacy-hold",
		/*cseq=*/2));

	ASSERT_FALSE(sent.empty()) << "the legacy-hold re-INVITE got no answer at all";
	const std::string holdRaw = sent.front().second ? sent.front().second->toString() : std::string{};
	EXPECT_NE(holdRaw.find("SIP/2.0 200 OK"), std::string::npos) << holdRaw;

	EXPECT_TRUE(bridge->isHeld())
		<< "a=sendrecv at session level with the audio section's connection "
		   "blackholed (c=IN IP4 0.0.0.0) is the legacy hold signal -- "
		   "getSdpDirection() alone (pre-#263) reads this as an active call "
		   "and the anchor would never hear hold music";

	auto session = handler.getSession("Call-ID: anchor-legacy-hold");
	ASSERT_TRUE(session.has_value());
	EXPECT_EQ(session.value()->getState(), Session::State::Held);
}

TEST(AnchorRouting, HoldOnAVirtualLegIsStillRefused)
{
	// Issue #218's fix is scoped to 555 specifically -- 777 (echo) and 888
	// (conference) genuinely have no second party's media to hand back on
	// resume, so they must keep the pre-existing 488 refusal. This is the
	// regression guard for that boundary.
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler("192.168.9.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	handler.handle(makeRegister("501", "192.168.9.51", "reg-501"));

	sent.clear();
	handler.handle(makeInvite("501", "777", "192.168.9.51", "echo-hold"));
	ASSERT_FALSE(sent.empty());
	const std::string toLine = toHeaderOf(sent.front().second);

	sent.clear();
	handler.handle(makeHoldReinvite("501", toLine, "192.168.9.51", "echo-hold",
		/*cseq=*/2, "a=sendonly\r\n"));

	ASSERT_FALSE(sent.empty());
	const std::string raw = sent.front().second ? sent.front().second->toString() : std::string{};
	EXPECT_NE(raw.find("SIP/2.0 488"), std::string::npos)
		<< "777 has no real peer and must still be refused, got:\n" << raw;
}

TEST(AnchorRouting, TickTearsDownAnAnchorCallAfterRepeatedWriteAudioFailures)
{
	// Issue #280 end-to-end: writeAudio() failures used to be logged and
	// discarded, so a genuinely broken anchor connection pumped handset audio
	// (or hold music) into nowhere for the rest of the call. This drives a
	// real 555 dial through RequestsHandler, breaks the anchor connection the
	// same way a real failed POST write would (LoopbackAnchorClient::
	// writeAudio() refuses once disconnected -- same observable shape as
	// TelephonyAnchorClient's real short/failed write), and asserts tick()'s
	// new sweep actually tears the call down instead of leaving it degraded
	// forever.
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler("192.168.9.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	handler.handle(makeRegister("501", "192.168.9.51", "reg-501"));

	sent.clear();
	handler.handle(makeInvite("501", "555", "192.168.9.51", "anchor-280"));
	ASSERT_FALSE(sent.empty());

	MediaBridge* bridge = handler.anchorBridgeForCallIdForTest("Call-ID: anchor-280");
	ASSERT_NE(bridge, nullptr);
	ASSERT_TRUE(bridge->isActive());
	ASSERT_FALSE(bridge->isAudioDegraded()) << "must start healthy";

	// One real G.711 20ms frame's worth of mu-law bytes (8 kHz * 20 ms), fed
	// repeatedly the way the RTP receive task would for a live handset stream.
	const std::vector<uint8_t> frame(160, 0xFF);
	bridge->onHandsetRtp(frame.data(), frame.size());   // establish "has worked at least once"
	ASSERT_FALSE(bridge->isAudioDegraded());

	ASSERT_NE(handler.anchorClientForTest(), nullptr);
	handler.anchorClientForTest()->stop();   // simulate a dead anchor connection

	for (int i = 0; i < 30; ++i)
	{
		bridge->onHandsetRtp(frame.data(), frame.size());
	}
	ASSERT_TRUE(bridge->isAudioDegraded())
		<< "30 writes against a disconnected anchor must cross the failure threshold";

	handler.tick();

	EXPECT_FALSE(handler.getSession("Call-ID: anchor-280").has_value())
		<< "a degraded anchor leg must be torn down by tick(), not left "
		   "pumping audio into a dead connection for the rest of the call";
	EXPECT_FALSE(bridge->isActive())
		<< "tick() must have released the bridge along with the session";
}

TEST(AnchorRouting, TickTearsDownAHeldAnchorCallAfterRepeatedMohWriteFailures)
{
	// Issue #279's actual shape: the call desmo found stuck was ON HOLD,
	// MoH playing into a dead anchor connection, no crash and no remote BYE
	// to notice by. Session::State::Held is NOT Session::State::Connected --
	// a sweep that only checked Connected (the no-answer/ACK-deadline reap's
	// own condition, copied without rechecking it here first) would silently
	// never fire for exactly this case. This is the regression guard for that.
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler("192.168.9.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	handler.handle(makeRegister("501", "192.168.9.51", "reg-501"));

	sent.clear();
	handler.handle(makeInvite("501", "555", "192.168.9.51", "anchor-279"));
	ASSERT_FALSE(sent.empty());
	const std::string toLine = toHeaderOf(sent.front().second);

	sent.clear();
	handler.handle(makeHoldReinvite("501", toLine, "192.168.9.51", "anchor-279",
		/*cseq=*/2, "a=sendonly\r\n"));
	ASSERT_FALSE(sent.empty());

	auto heldSession = handler.getSession("Call-ID: anchor-279");
	ASSERT_TRUE(heldSession.has_value());
	ASSERT_EQ(heldSession.value()->getState(), Session::State::Held);

	MediaBridge* bridge = handler.anchorBridgeForCallIdForTest("Call-ID: anchor-279");
	ASSERT_NE(bridge, nullptr);
	ASSERT_TRUE(bridge->isHeld());

	// While held, MoH ticks (not handset RTP) are what drive writeAudio().
	const std::vector<uint8_t> tick(160, 0xFF);
	bridge->feedMohTick(tick.data(), tick.size());   // establish "has worked at least once"
	ASSERT_FALSE(bridge->isAudioDegraded());

	ASSERT_NE(handler.anchorClientForTest(), nullptr);
	handler.anchorClientForTest()->stop();   // simulate the dead anchor connection

	for (int i = 0; i < 30; ++i)
	{
		bridge->feedMohTick(tick.data(), tick.size());
	}
	ASSERT_TRUE(bridge->isAudioDegraded());

	handler.tick();

	EXPECT_FALSE(handler.getSession("Call-ID: anchor-279").has_value())
		<< "a degraded HELD anchor leg must also be torn down -- this is "
		   "exactly the #279 shape (MoH into a dead connection, no crash, "
		   "no remote BYE to notice by)";
	EXPECT_FALSE(bridge->isActive());
}

TEST(AnchorRouting, TickDoesNotTearDownAnAnchorCallThatHasNeverWrittenSuccessfully)
{
	// Advisor caught this before it shipped: a call whose writeAudio() has
	// NEVER succeeded yet is "still starting" (e.g. the real anchor client's
	// pre-warm fallback window while a TLS handshake completes), not
	// "degraded" -- tick()'s sweep must not tear it down just because its
	// first N frames arrived before the connection was ready. Same 555 dial
	// as the sibling test above, except the anchor is broken BEFORE any
	// frame gets a chance to succeed.
	std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> sent;
	RequestsHandler handler("192.168.9.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	handler.handle(makeRegister("501", "192.168.9.51", "reg-501"));

	sent.clear();
	handler.handle(makeInvite("501", "555", "192.168.9.51", "anchor-280-nevergood"));
	ASSERT_FALSE(sent.empty());

	MediaBridge* bridge = handler.anchorBridgeForCallIdForTest("Call-ID: anchor-280-nevergood");
	ASSERT_NE(bridge, nullptr);

	ASSERT_NE(handler.anchorClientForTest(), nullptr);
	handler.anchorClientForTest()->stop();   // broken from the very first frame -- no prior success

	const std::vector<uint8_t> frame(160, 0xFF);
	for (int i = 0; i < 100; ++i)   // far past the failure threshold
	{
		bridge->onHandsetRtp(frame.data(), frame.size());
	}
	ASSERT_FALSE(bridge->isAudioDegraded())
		<< "never having succeeded once must never read as degraded, no matter "
		   "how many failed frames arrive";

	handler.tick();

	EXPECT_TRUE(handler.getSession("Call-ID: anchor-280-nevergood").has_value())
		<< "tick() must not tear down a call that is still starting, only one "
		   "that was genuinely working and then broke";
	EXPECT_TRUE(bridge->isActive());
}
