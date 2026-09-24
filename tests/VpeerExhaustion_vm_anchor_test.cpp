// VpeerExhaustion_vm_anchor_test.cpp — Issue #412: every caller of
// RequestsHandler::allocateVirtualPeer() must survive a nullptr, which it
// returns once its capacity -- the pool, with no heap fallback since #409 --
// is spent.
// This file pins the voicemail and anchor call sites; the conference site
// lives beside it in VpeerExhaustion_test.cpp.
//
// What is pinned, per call site, driven end to end through handle():
//   * the caller gets EXACTLY ONE 503 (counted, not "some 503 went out") and
//     no 200 OK -- a refusal that also answered would leave the phone in a
//     dialog nobody is serving;
//   * nothing is published for the Call-ID (getSession()/getSessionCount());
//   * whatever the path claimed before the draw is released (voicemail slot,
//     anchor bridge + anchor leg) -- proven by the SAME dial succeeding once
//     the pool is refilled, landing on the SAME resources (slot 0 / the one
//     anchor bridge), which it could not if the refusal had leaked them.
// The "refill then succeed" half is what makes the refusal attributable to the
// pool rather than to a broken setup.
//
// Exhaustion goes through exhaustVirtualPeersForTest(), which draws through
// the REAL allocator until it refuses; holding its vector keeps the pool dry.
// It is drawn immediately before the triggering request, so registration and
// any earlier leg of the call have already taken whatever peers they need.
//
// Two #412 call sites are deliberately NOT covered here, because no host test
// can reach them through the public API -- say so rather than fake it:
//   * originateAnchorCall()'s ASYNC branch (after allBridgesBusy()) and
//   * routeInboundAnchorCall() (inbound PSTN via the anchor).
// Both run only when the boot-selected provider is not Loopback
// (anchorIsSynchronous() false / the CallEvent callback wired). The host build
// always boots Loopback unless a Telephony slot is active, and the host
// TelephonyAnchorClient is a stub whose isConnected() is false (so the async
// branch 404s before reaching the draw) and whose setEventCallback() discards
// the callback (so CallEvent::Incoming can never reach routeInboundAnchorCall()).
// RequestsHandler.hpp's anchorIsSynchronous() comment documents the same
// limit. Covering them needs a host-only seam in RequestsHandler (e.g. forcing
// the async calling convention over the Loopback client, and invoking
// routeInboundAnchorCall() with a route DN set) -- out of scope for a test-only
// change. In their place this file pins the SYNCHRONOUS anchor branch's draw,
// the reachable sibling with the same shape (stopBridge + dropCall + 503).

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "LoopbackAnchorClient.hpp"
#include "PoolConfig.hpp"
#include "RequestsHandler.hpp"
#include "VoicemailLeg.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	using SentList = std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>;

	sockaddr_in addrFor(const std::string& ip)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(5060);
		return s;
	}

	// Same shapes as VoicemailDivert_test.cpp / VoicemailRetrieval_test.cpp /
	// AnchorRouting_test.cpp -- kept file-local, matching this codebase's
	// convention of small per-file test helpers.
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
		const std::string& srcIp, const std::string& callId, const std::string& branch)
	{
		std::string body =
			"v=0\r\n"
			"o=- 0 0 IN IP4 " + srcIp + "\r\n"
			"s=-\r\n"
			"c=IN IP4 " + srcIp + "\r\n"
			"t=0 0\r\n"
			"m=audio 10000 RTP/AVP 0 101\r\n"
			"a=rtpmap:0 PCMU/8000\r\n"
			"a=rtpmap:101 telephone-event/8000\r\n";
		std::string raw =
			"INVITE sip:" + toExt + "@server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=" + branch + "\r\n"
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

	// The callee's 486 for a proxied INVITE (VoicemailDivert_test.cpp's
	// makeBusy): From/To mirror the original request, so getToNumber() names
	// the busy party -- which is what routes the call to its voicemail.
	std::shared_ptr<SipMessage> makeBusy(const std::string& fromExt, const std::string& toExt,
		const std::string& srcIp, const std::string& callId, const std::string& branch)
	{
		std::string raw =
			"SIP/2.0 486 Busy Here\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=" + branch + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: <sip:" + toExt + "@server>;tag=bt" + callId + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INVITE\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}

	bool sameAddr(const sockaddr_in& a, const sockaddr_in& b)
	{
		return a.sin_addr.s_addr == b.sin_addr.s_addr && a.sin_port == b.sin_port;
	}

	// How many RESPONSES with this status line went to `to` for this Call-ID.
	// A count, not a find: "exactly one 503" is the contract -- a refusal path
	// that fell through into a second answer would still contain "a" 503.
	int countResponses(const SentList& sent, const sockaddr_in& to, const std::string& callId,
		const std::string& statusPrefix)
	{
		const std::string callIdLine = "Call-ID: " + callId + "\r\n";
		int n = 0;
		for (const auto& [addr, msg] : sent)
		{
			if (!msg || !sameAddr(addr, to)) continue;
			const std::string raw = msg->toString();
			if (raw.rfind(statusPrefix, 0) != 0) continue;
			if (raw.find(callIdLine) == std::string::npos) continue;
			++n;
		}
		return n;
	}

	int count503(const SentList& sent, const sockaddr_in& to, const std::string& callId)
	{
		return countResponses(sent, to, callId, "SIP/2.0 503");
	}

	int count200(const SentList& sent, const sockaddr_in& to, const std::string& callId)
	{
		return countResponses(sent, to, callId, "SIP/2.0 200 OK");
	}

	// Every voicemail leg is back to rest: nothing playing/recording and no
	// SD-I/O job queued. (The RTP receiver/sender stop is proven separately,
	// by the follow-up dial landing on slot 0 again -- findFreeVoicemailSlot()
	// treats a still-active receiver as busy.)
	void expectAllVoicemailLegsAtRest(RequestsHandler& handler)
	{
		for (int slot = 0; slot < static_cast<int>(POCKETDIAL_MAX_VOICEMAIL_LEGS); ++slot)
		{
			EXPECT_EQ(handler.voicemailLegStateForTest(slot), VoicemailLeg::State::Idle)
				<< "voicemail leg " << slot << " must be released by the refusal";
			EXPECT_FALSE(handler.voicemailSdJobPendingForTest(slot))
				<< "voicemail leg " << slot << " must have no SD job queued by a refused call";
		}
	}
}

// ── Voicemail deposit (answerVoicemailDeposit's "700" dummy dest) ────────────

TEST(VpeerExhaustionVmAnchor, VoicemailDepositIsRefused503AndReleasesItsLegWhenThePoolIsDry)
{
	// Setup copied from VoicemailDivert_test.cpp's
	// CfbFallsBackToVoicemailWithNoCancelNeeded: 309 calls 308, 308 answers
	// 486, 308 has voicemail and no CFB target -> answerVoicemailDeposit().
	// The deposit claims a leg, starts its RTP receiver+sender and allocates
	// the session BEFORE drawing the dummy peer, so all three must unwind.
	SentList sent;
	RequestsHandler handler("192.168.61.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in callerAddr = addrFor("192.168.61.23");

	handler.handle(makeRegister("308", "192.168.61.14", "reg-308-x"));
	handler.handle(makeRegister("309", "192.168.61.23", "reg-309-x"));
	handler.setVoicemail("308", true);
	const size_t baselineSessions = handler.getSessionCount();

	{
		const std::string callId = "vm-dep-dry";
		const std::string branch = "z9hG4bKvmdepdry";
		handler.handle(makeInvite("309", "308", "192.168.61.23", callId, branch));
		ASSERT_TRUE(handler.getSession("Call-ID: " + callId).has_value())
			<< "setup: the INVITE must have been relayed to 308 first";

		auto held = handler.exhaustVirtualPeersForTest();
		ASSERT_FALSE(held.empty());

		sent.clear();
		handler.handle(makeBusy("309", "308", "192.168.61.14", callId, branch));

		EXPECT_EQ(count503(sent, callerAddr, callId), 1)
			<< "the depositor must get exactly one 503 when the virtual-peer pool is dry";
		EXPECT_EQ(count200(sent, callerAddr, callId), 0)
			<< "a refused deposit must never also be answered";
		EXPECT_FALSE(handler.getSession("Call-ID: " + callId).has_value())
			<< "a refused deposit must not publish a session";
		EXPECT_EQ(handler.getSessionCount(), baselineSessions)
			<< "the relay leg is ended and nothing replaces it";
		expectAllVoicemailLegsAtRest(handler);
	}   // held dropped: pool refilled

	// Same dial again: must now be answered locally, on slot 0 -- the slot the
	// refused deposit claimed. Landing anywhere else (or 486ing) would mean the
	// refusal leaked the slot's receiver/sender.
	const std::string callId = "vm-dep-ok";
	const std::string branch = "z9hG4bKvmdepok";
	handler.handle(makeInvite("309", "308", "192.168.61.23", callId, branch));
	sent.clear();
	handler.handle(makeBusy("309", "308", "192.168.61.14", callId, branch));

	EXPECT_EQ(count200(sent, callerAddr, callId), 1) << "with the pool refilled the deposit must be answered";
	EXPECT_EQ(count503(sent, callerAddr, callId), 0);
	auto session = handler.getSession("Call-ID: " + callId);
	ASSERT_TRUE(session.has_value());
	EXPECT_TRUE(session.value()->isVoicemail());
	EXPECT_EQ(session.value()->getVoicemailLegSlot(), 0)
		<< "the refused deposit must have given slot 0 back";
	EXPECT_NE(session.value()->getDest(), nullptr);
}

// ── Voicemail retrieval (answerVoicemailRetrieval's "796" dummy dest) ────────

TEST(VpeerExhaustionVmAnchor, VoicemailRetrievalIsRefused503AndReleasesItsLegWhenThePoolIsDry)
{
	// Setup copied from VoicemailRetrieval_test.cpp's
	// FullWalkThroughTwoMessagesWithADeleteViaDigitSeven: a voicemail-enabled
	// extension dials 796 from its own phone. Retrieval starts the slot's RTP
	// receiver (arming its DTMF sink) and sender and allocates the session
	// before the draw.
	SentList sent;
	RequestsHandler handler("192.168.62.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in callerAddr = addrFor("192.168.62.11");

	handler.handle(makeRegister("801", "192.168.62.11", "reg-801-x"));
	handler.setVoicemail("801", true);
	const size_t baselineSessions = handler.getSessionCount();

	{
		const std::string callId = "vm-ret-dry";
		auto held = handler.exhaustVirtualPeersForTest();
		ASSERT_FALSE(held.empty());

		sent.clear();
		handler.handle(makeInvite("801", "796", "192.168.62.11", callId, "z9hG4bKvmretdry"));

		EXPECT_EQ(count503(sent, callerAddr, callId), 1)
			<< "the retrieval dial-in must get exactly one 503 when the virtual-peer pool is dry";
		EXPECT_EQ(count200(sent, callerAddr, callId), 0)
			<< "a refused retrieval must never also be answered";
		EXPECT_FALSE(handler.getSession("Call-ID: " + callId).has_value())
			<< "a refused retrieval must not publish a session";
		EXPECT_EQ(handler.getSessionCount(), baselineSessions);
		expectAllVoicemailLegsAtRest(handler);
	}   // held dropped: pool refilled

	const std::string callId = "vm-ret-ok";
	sent.clear();
	handler.handle(makeInvite("801", "796", "192.168.62.11", callId, "z9hG4bKvmretok"));

	EXPECT_EQ(count200(sent, callerAddr, callId), 1) << "with the pool refilled the retrieval must be answered";
	EXPECT_EQ(count503(sent, callerAddr, callId), 0);
	auto session = handler.getSession("Call-ID: " + callId);
	ASSERT_TRUE(session.has_value());
	EXPECT_TRUE(session.value()->isVoicemail());
	EXPECT_EQ(session.value()->getVoicemailLegSlot(), 0)
		<< "the refused retrieval must have given slot 0 back (its RTP receiver stopped)";
	EXPECT_TRUE(handler.voicemailSdJobPendingForTest(0))
		<< "the successful dial-in must kick off its mailbox listing";
	EXPECT_NE(session.value()->getDest(), nullptr);
}

// ── Anchor, SYNCHRONOUS branch (the reachable stand-in; see file header) ─────

TEST(VpeerExhaustionVmAnchor, SyncAnchorDialIsRefused503AndReleasesBridgeAndLegWhenThePoolIsDry)
{
	// Setup copied from AnchorRouting_test.cpp's
	// DialingReservedExtensionReachesAnchorAndBridgeAttaches (a registered
	// phone dials 555 against the host's boot-default Loopback anchor) plus
	// that file's TeardownThatAlreadyDroppedTheLegDoesNotDropItAgain for the
	// dropCallCount() observable. The sync branch has already called
	// makeCall(), started the bridge and allocated the session when it draws
	// the dummy peer, so the refusal must stop the bridge and drop the leg
	// exactly once.
	SentList sent;
	RequestsHandler handler("192.168.63.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in callerAddr = addrFor("192.168.63.51");

	handler.handle(makeRegister("501", "192.168.63.51", "reg-501-x"));
	auto* loop = dynamic_cast<LoopbackAnchorClient*>(handler.anchorClientForTest());
	ASSERT_NE(loop, nullptr) << "host suite is expected to boot the Loopback anchor";
	const size_t baselineSessions = handler.getSessionCount();

	{
		const std::string callId = "anchor-dry";
		auto held = handler.exhaustVirtualPeersForTest();
		ASSERT_FALSE(held.empty());

		const unsigned dropsBefore = loop->dropCallCount();
		sent.clear();
		handler.handle(makeInvite("501", "555", "192.168.63.51", callId, "z9hG4bKanchordry"));

		EXPECT_EQ(count503(sent, callerAddr, callId), 1)
			<< "the 555 dial must get exactly one 503 when the virtual-peer pool is dry";
		EXPECT_EQ(count200(sent, callerAddr, callId), 0)
			<< "a refused anchor dial must never also be answered";
		EXPECT_FALSE(handler.getSession("Call-ID: " + callId).has_value())
			<< "a refused anchor dial must not publish a session";
		EXPECT_EQ(handler.getSessionCount(), baselineSessions);
		EXPECT_EQ(handler.anchorBridgeForCallIdForTest("Call-ID: " + callId), nullptr)
			<< "the bridge started for this call must be stopped by the refusal";
		EXPECT_EQ(loop->dropCallCount(), dropsBefore + 1)
			<< "the anchor leg makeCall() placed must be dropped exactly once";
	}   // held dropped: pool refilled

	// Same dial again. Loopback allows ONE anchored call, so this is only
	// answered if the refused call really gave its bridge back.
	const std::string callId = "anchor-ok";
	sent.clear();
	handler.handle(makeInvite("501", "555", "192.168.63.51", callId, "z9hG4bKanchorok"));

	EXPECT_EQ(count200(sent, callerAddr, callId), 1) << "with the pool refilled the 555 dial must be answered";
	EXPECT_EQ(count503(sent, callerAddr, callId), 0);
	auto session = handler.getSession("Call-ID: " + callId);
	ASSERT_TRUE(session.has_value());
	EXPECT_TRUE(session.value()->isAnchor());
	EXPECT_NE(session.value()->getDest(), nullptr);
	MediaBridge* bridge = handler.anchorBridgeForCallIdForTest("Call-ID: " + callId);
	ASSERT_NE(bridge, nullptr);
	EXPECT_TRUE(bridge->isActive());
}
