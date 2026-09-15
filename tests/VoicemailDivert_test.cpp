// VoicemailDivert_test.cpp — Issue #246 (voicemail Stage 3 of #194), the SIP
// divert-hook slice: CFNA/CFB falling back to a locally-terminated voicemail
// leg when an extension has voicemail enabled but no explicit forward
// target. Driven end to end through RequestsHandler::handle()/tick(), the
// same style AnchorRouting_test.cpp and DtmfClassCodes_test.cpp use.

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "RequestsHandler.hpp"
#include "VoicemailArchive.hpp"

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
		const std::string& srcIp, const std::string& callId, const std::string& branch,
		int rtpPort = 10000)
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

	std::shared_ptr<SipMessage> makeBusy(const std::string& fromExt, const std::string& toExt,
		const std::string& srcIp, const std::string& callId, const std::string& branch)
	{
		// A 486 response echoes the ORIGINAL request's From/To (RFC 3261): From
		// is still the caller, To is still the callee -- onBusy() reads
		// data->getFromNumber() for the busy party (see the caller's own note
		// in the review thread: don't re-derive this, just match what the
		// existing CFB path already reads).
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

	// `toValue` is the FULL captured "To:" header value from the 200 OK
	// (e.g. "<sip:303@server>;tag=d7iFV4UhN"), not just the tag -- it already
	// carries the URI, so the caller must not also prepend one.
	std::shared_ptr<SipMessage> makeBye(const std::string& fromExt, const std::string& toValue,
		const std::string& srcIp, const std::string& callId)
	{
		std::string raw =
			"BYE sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bKbye" + callId + "\r\n"
			"From: <sip:" + fromExt + "@server>;tag=ft" + callId + "\r\n"
			"To: " + toValue + "\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 2 BYE\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, addrFor(srcIp));
	}

	std::string findSentTo(const SentList& sent, const sockaddr_in& addr, const std::string& needle)
	{
		for (auto it = sent.rbegin(); it != sent.rend(); ++it)
		{
			if (it->first.sin_addr.s_addr != addr.sin_addr.s_addr) continue;
			if (it->first.sin_port != addr.sin_port) continue;
			if (!it->second) continue;
			std::string raw = it->second->toString();
			if (raw.find(needle) != std::string::npos) return raw;
		}
		return {};
	}

	std::string extractHeaderLine(const std::string& raw, const std::string& name)
	{
		size_t pos = 0;
		while (pos < raw.size())
		{
			size_t eol = raw.find("\r\n", pos);
			if (eol == std::string::npos) eol = raw.size();
			std::string line = raw.substr(pos, eol - pos);
			if (line.size() > name.size() && line.compare(0, name.size(), name) == 0)
			{
				return line;
			}
			pos = eol + 2;
		}
		return {};
	}

	class FakeSink : public vmarchive::Sink
	{
	public:
		struct Call
		{
			vmarchive::QueuedRecording rec;
			std::vector<uint8_t> mulaw;
		};
		std::vector<Call> calls;

		void write(const vmarchive::QueuedRecording& rec, const uint8_t* mulaw) override
		{
			Call c;
			c.rec = rec;
			c.mulaw.assign(mulaw, mulaw + rec.length);
			calls.push_back(std::move(c));
		}
	};
}

// CFNA fallback: no explicit no-answer forward, voicemail enabled. The
// still-ringing callee must be CANCELed (the forked-dialog hazard) BEFORE
// the caller gets a local 200 OK.
TEST(VoicemailDivert, CfnaFallsBackToVoicemailAndCancelsTheRingingCallee)
{
	SentList sent;
	RequestsHandler handler("192.168.40.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in calleeAddr = addrFor("192.168.40.10");  // 301
	const sockaddr_in callerAddr = addrFor("192.168.40.20");  // 302

	handler.handle(makeRegister("301", "192.168.40.10", "reg-301-a"));
	handler.handle(makeRegister("302", "192.168.40.20", "reg-302-a"));
	handler.setVoicemail("301", true);

	const std::string callId = "vm-cfna-1";
	const std::string branch = "z9hG4bKvmcfna1";
	handler.handle(makeInvite("302", "301", "192.168.40.20", callId, branch));

	// The callee is a real registered extension, so the INVITE is relayed
	// (proxied) to it untouched -- confirms the divert hook's premise before
	// forcing the timeout. Search by Call-ID, not just "INVITE sip:301@" --
	// the register-beep sends its OWN INVITE to 301 on registration
	// (RegisterBeeper.cpp) that would otherwise false-positive the same needle.
	ASSERT_FALSE(findSentTo(sent, calleeAddr, "Call-ID: " + callId).empty());

	ASSERT_TRUE(handler.getSession("Call-ID: " + callId).has_value());
	handler.getSession("Call-ID: " + callId).value()->armRingTimer(
		std::chrono::steady_clock::now() - std::chrono::seconds(1));
	handler.tick();

	std::string cancelToCallee = findSentTo(sent, calleeAddr, "CANCEL sip:");
	EXPECT_FALSE(cancelToCallee.empty())
		<< "the still-ringing callee must be CANCELed -- RFC 3261 S13.2.2.4 forked-dialog hazard";
	if (!cancelToCallee.empty())
	{
		EXPECT_NE(cancelToCallee.find("Call-ID: " + callId), std::string::npos) << cancelToCallee;
	}

	std::string okToCaller = findSentTo(sent, callerAddr, "SIP/2.0 200 OK");
	ASSERT_FALSE(okToCaller.empty()) << "the caller must be answered locally, not left hanging";
	EXPECT_NE(okToCaller.find("v=0"), std::string::npos) << "the 200 OK must carry an SDP answer";
	EXPECT_NE(extractHeaderLine(okToCaller, "To:").find("tag="), std::string::npos)
		<< "the 200 OK needs the board's own To-tag: " << okToCaller;
}

// #232 regression: a BYE against the locally-answered voicemail leg must
// actually be matched and torn down, not silently ignored the way 777/888
// legs were before setDialogHeaders() was added here.
TEST(VoicemailDivert, ByeAfterVoicemailAnswerIsHandledAndEndsTheCall)
{
	SentList sent;
	RequestsHandler handler("192.168.40.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in callerAddr = addrFor("192.168.40.21");

	handler.handle(makeRegister("303", "192.168.40.11", "reg-303-b"));
	handler.handle(makeRegister("304", "192.168.40.21", "reg-304-b"));
	handler.setVoicemail("303", true);

	const std::string callId = "vm-cfna-bye";
	handler.handle(makeInvite("304", "303", "192.168.40.21", callId, "z9hG4bKvmbye"));
	ASSERT_TRUE(handler.getSession("Call-ID: " + callId).has_value());
	handler.getSession("Call-ID: " + callId).value()->armRingTimer(
		std::chrono::steady_clock::now() - std::chrono::seconds(1));
	handler.tick();

	std::string okToCaller = findSentTo(sent, callerAddr, "SIP/2.0 200 OK");
	ASSERT_FALSE(okToCaller.empty());
	std::string toLine = extractHeaderLine(okToCaller, "To:");
	ASSERT_NE(toLine.find("tag="), std::string::npos) << toLine;

	ASSERT_TRUE(handler.getSession("Call-ID: " + callId).has_value())
		<< "the voicemail session must still be live, waiting for the caller to hang up";

	handler.handle(makeBye("304", toLine.substr(4), "192.168.40.21", callId));

	std::string okToBye = findSentTo(sent, callerAddr, "SIP/2.0 200 OK");
	EXPECT_NE(okToBye.find("CSeq: 2 BYE"), std::string::npos)
		<< "the BYE must be answered with its own 200 OK: " << okToBye;
	EXPECT_FALSE(handler.getSession("Call-ID: " + callId).has_value())
		<< "the session must be torn down once the depositor hangs up -- this is the #232 class "
		   "of bug (777/888 legs never matching a BYE) that setDialogHeaders() exists to avoid";
}

// Explicit forward wins over the voicemail fallback -- deciding this once at
// arm time (the sentinel), not re-derived at sweep time, is what makes this
// deterministic regardless of when the timer actually fires.
TEST(VoicemailDivert, ExplicitCfnaTargetWinsOverVoicemailFallback)
{
	SentList sent;
	RequestsHandler handler("192.168.40.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	handler.handle(makeRegister("305", "192.168.40.12", "reg-305-c"));
	handler.handle(makeRegister("306", "192.168.40.22", "reg-306-c"));
	handler.handle(makeRegister("307", "192.168.40.13", "reg-307-c"));
	handler.setVoicemail("305", true);
	handler.setForward("305", "noanswer", "307");

	const std::string callId = "vm-cfna-explicit";
	handler.handle(makeInvite("306", "305", "192.168.40.22", callId, "z9hG4bKvmexplicit"));
	ASSERT_TRUE(handler.getSession("Call-ID: " + callId).has_value());
	handler.getSession("Call-ID: " + callId).value()->armRingTimer(
		std::chrono::steady_clock::now() - std::chrono::seconds(1));
	handler.tick();

	EXPECT_FALSE(findSentTo(sent, addrFor("192.168.40.13"), "INVITE sip:307@").empty())
		<< "an explicit CFNA target must still be used, not overridden by the voicemail fallback";
}

// CFB fallback: the callee already sent a final 486, so there is nothing
// ringing left to CANCEL -- unlike CFNA, this path answers straight away.
TEST(VoicemailDivert, CfbFallsBackToVoicemailWithNoCancelNeeded)
{
	SentList sent;
	RequestsHandler handler("192.168.40.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in callerAddr = addrFor("192.168.40.23");

	handler.handle(makeRegister("308", "192.168.40.14", "reg-308-d"));
	handler.handle(makeRegister("309", "192.168.40.23", "reg-309-d"));
	handler.setVoicemail("308", true);

	const std::string callId = "vm-cfb-1";
	const std::string branch = "z9hG4bKvmcfb1";
	handler.handle(makeInvite("309", "308", "192.168.40.23", callId, branch));
	handler.handle(makeBusy("309", "308", "192.168.40.14", callId, branch));

	std::string okToCaller = findSentTo(sent, callerAddr, "SIP/2.0 200 OK");
	ASSERT_FALSE(okToCaller.empty()) << "busy must fall back to voicemail, not fail the call";
	EXPECT_NE(okToCaller.find("v=0"), std::string::npos);

	EXPECT_TRUE(findSentTo(sent, callerAddr, "SIP/2.0 486").empty())
		<< "the caller must never see the bare 486 once voicemail is enabled";
}

// Neither an explicit CFB target nor voicemail configured: the existing,
// unmodified behaviour (the bare 486 reaches the caller) must be unchanged.
TEST(VoicemailDivert, NoForwardNoVoicemailStillFailsPlainly)
{
	SentList sent;
	RequestsHandler handler("192.168.40.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in callerAddr = addrFor("192.168.40.24");

	handler.handle(makeRegister("310", "192.168.40.15", "reg-310-e"));
	handler.handle(makeRegister("311", "192.168.40.24", "reg-311-e"));

	const std::string callId = "vm-none-1";
	const std::string branch = "z9hG4bKvmnone1";
	handler.handle(makeInvite("311", "310", "192.168.40.24", callId, branch));
	handler.handle(makeBusy("311", "310", "192.168.40.15", callId, branch));

	EXPECT_FALSE(findSentTo(sent, callerAddr, "SIP/2.0 486").empty())
		<< "with no forward configured and voicemail off, the caller must still see 486";
}

// Found in review: the free-slot scan used to key off VoicemailLeg's own
// state, which this slice never advances past Idle (startRecording() isn't
// wired yet), so every deposit picked slot 0 regardless of how many were
// already active. Two genuinely concurrent deposits must land on two
// distinct legs, and a third (with POCKETDIAL_MAX_VOICEMAIL_LEGS == 2) must
// be refused rather than clobber an active one.
TEST(VoicemailDivert, TwoConcurrentDepositsUseDistinctSlotsAndAThirdIsRefused)
{
	SentList sent;
	RequestsHandler handler("192.168.41.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in caller1Addr = addrFor("192.168.41.21");
	const sockaddr_in caller2Addr = addrFor("192.168.41.22");
	const sockaddr_in caller3Addr = addrFor("192.168.41.23");

	handler.handle(makeRegister("401", "192.168.41.11", "reg-401"));
	handler.handle(makeRegister("402", "192.168.41.12", "reg-402"));
	handler.handle(makeRegister("403", "192.168.41.13", "reg-403"));
	handler.handle(makeRegister("411", "192.168.41.21", "reg-411"));
	handler.handle(makeRegister("412", "192.168.41.22", "reg-412"));
	handler.handle(makeRegister("413", "192.168.41.23", "reg-413"));
	handler.setVoicemail("401", true);
	handler.setVoicemail("402", true);
	handler.setVoicemail("403", true);

	handler.handle(makeInvite("411", "401", "192.168.41.21", "vm-slot-1", "z9hG4bKvmslot1"));
	handler.handle(makeBusy("411", "401", "192.168.41.11", "vm-slot-1", "z9hG4bKvmslot1"));
	handler.handle(makeInvite("412", "402", "192.168.41.22", "vm-slot-2", "z9hG4bKvmslot2"));
	handler.handle(makeBusy("412", "402", "192.168.41.12", "vm-slot-2", "z9hG4bKvmslot2"));

	EXPECT_NE(findSentTo(sent, caller1Addr, "SIP/2.0 200 OK").find("v=0"), std::string::npos)
		<< "first deposit must be answered locally";
	EXPECT_NE(findSentTo(sent, caller2Addr, "SIP/2.0 200 OK").find("v=0"), std::string::npos)
		<< "second, CONCURRENT deposit must land on the OTHER slot, not be refused or "
		   "silently drop the first leg's still-active RTP receiver";

	// A third deposit, with both legs still active, must be refused rather
	// than corrupt whichever slot the scan mistakenly thinks is free.
	handler.handle(makeInvite("413", "403", "192.168.41.23", "vm-slot-3", "z9hG4bKvmslot3"));
	handler.handle(makeBusy("413", "403", "192.168.41.13", "vm-slot-3", "z9hG4bKvmslot3"));

	EXPECT_FALSE(findSentTo(sent, caller3Addr, "Call-ID: vm-slot-3").empty())
		<< "the third deposit's own transaction must at least be answered somehow";
	std::string thirdResponse = findSentTo(sent, caller3Addr, "Call-ID: vm-slot-3");
	EXPECT_NE(thirdResponse.find("486"), std::string::npos)
		<< "every leg busy must refuse the third deposit with 486, not fail some other way -- "
		   "got: " << thirdResponse;
	EXPECT_EQ(thirdResponse.find("v=0"), std::string::npos)
		<< "the third deposit must not be silently answered with SDP on top of an active leg -- "
		   "got: " << thirdResponse;
}

// Found in review: releaseVoicemailLeg() used to be called only from onBye(),
// so any OTHER teardown path reaching endCall() (session-timer expiry,
// forceDisconnect/admin hangup, the orphan sweep) left the RTP receiver/
// sender running and the slot claimed forever. Proven black-box: fill both
// legs, forceDisconnect one of them, then confirm a THIRD deposit can still
// be answered -- which is only possible if the slot actually came back.
TEST(VoicemailDivert, EndCallViaNonByePathReleasesTheVoicemailLegSlot)
{
	SentList sent;
	RequestsHandler handler("192.168.42.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in caller3Addr = addrFor("192.168.42.23");

	handler.handle(makeRegister("501", "192.168.42.11", "reg-501"));
	handler.handle(makeRegister("502", "192.168.42.12", "reg-502"));
	handler.handle(makeRegister("503", "192.168.42.13", "reg-503"));
	handler.handle(makeRegister("511", "192.168.42.21", "reg-511"));
	handler.handle(makeRegister("512", "192.168.42.22", "reg-512"));
	handler.handle(makeRegister("513", "192.168.42.23", "reg-513"));
	handler.setVoicemail("501", true);
	handler.setVoicemail("502", true);
	handler.setVoicemail("503", true);

	handler.handle(makeInvite("511", "501", "192.168.42.21", "vm-fd-1", "z9hG4bKvmfd1"));
	handler.handle(makeBusy("511", "501", "192.168.42.11", "vm-fd-1", "z9hG4bKvmfd1"));
	handler.handle(makeInvite("512", "502", "192.168.42.22", "vm-fd-2", "z9hG4bKvmfd2"));
	handler.handle(makeBusy("512", "502", "192.168.42.12", "vm-fd-2", "z9hG4bKvmfd2"));

	ASSERT_TRUE(handler.getSession("Call-ID: vm-fd-1").has_value());
	ASSERT_TRUE(handler.getSession("Call-ID: vm-fd-2").has_value());

	// Tear down the first depositor by a path OTHER than its own BYE --
	// forceDisconnect() is what /api/kill uses, and it reaches endCall() the
	// same way session-timer expiry and the orphan sweep do.
	handler.forceDisconnect("511");
	EXPECT_FALSE(handler.getSession("Call-ID: vm-fd-1").has_value())
		<< "forceDisconnect must actually tear the voicemail session down";

	// A third deposit only succeeds if slot 1's RTP receiver/sender were
	// actually stopped -- otherwise this hits the same single-stream-cap
	// failure the leaked slot would cause.
	handler.handle(makeInvite("513", "503", "192.168.42.23", "vm-fd-3", "z9hG4bKvmfd3"));
	handler.handle(makeBusy("513", "503", "192.168.42.13", "vm-fd-3", "z9hG4bKvmfd3"));

	EXPECT_NE(findSentTo(sent, caller3Addr, "SIP/2.0 200 OK").find("v=0"), std::string::npos)
		<< "the slot forceDisconnect freed must be reusable by a new deposit";
}

// End-to-end: deposit, caller audio actually recorded (injected via the
// dispatchDtmf()-style test seam, since RtpReceiver::start() is a no-op stub
// on host), BYE, and the finished message reaches the flush queue with the
// right identity and the exact bytes recorded -- not just "some 200 OK went
// out", but the whole record -> finalize -> stage -> queue pipeline.
TEST(VoicemailDivert, RecordedAudioReachesTheFlushQueueAfterBye)
{
	SentList sent;
	RequestsHandler handler("192.168.43.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	handler.handle(makeRegister("601", "192.168.43.11", "reg-601"));
	handler.handle(makeRegister("611", "192.168.43.21", "reg-611"));
	handler.setVoicemail("601", true);

	const std::string callId = "vm-audio-1";
	const std::string branch = "z9hG4bKvmaudio1";
	handler.handle(makeInvite("611", "601", "192.168.43.21", callId, branch));
	handler.handle(makeBusy("611", "601", "192.168.43.11", callId, branch));

	auto session = handler.getSession("Call-ID: " + callId);
	ASSERT_TRUE(session.has_value());
	const int slot = session.value()->getVoicemailLegSlot();
	ASSERT_GE(slot, 0);

	const uint8_t frame1[] = {10, 20, 30, 40};
	const uint8_t frame2[] = {50, 60};
	ASSERT_TRUE(handler.feedVoicemailAudioForTest(slot, frame1, sizeof(frame1)));
	ASSERT_TRUE(handler.feedVoicemailAudioForTest(slot, frame2, sizeof(frame2)));

	// forceDisconnect rather than a real BYE: ByeAfterVoicemail... already
	// pins the exact-dialog-tag-matching requirement for a real BYE, and
	// endCall()'s voicemail safety net fires on ANY teardown reaching it --
	// this test's interest is the flush pipeline, not dialog matching.
	handler.forceDisconnect("611");

	FakeSink sink;
	handler.drainVoicemailFlush(sink);

	ASSERT_EQ(sink.calls.size(), 1u);
	EXPECT_STREQ(sink.calls[0].rec.extension, "601");
	// VoicemailLeg::callId() stores whatever SipMessage::getCallID() returns
	// verbatim -- the FULL "Call-ID: <value>" header line, same convention
	// _sessions' map key and every getSession() caller in this file already
	// account for, not just the bare value.
	EXPECT_STREQ(sink.calls[0].rec.callId, ("Call-ID: " + callId).c_str());
	EXPECT_EQ(sink.calls[0].rec.length, 6u);
	EXPECT_EQ(sink.calls[0].mulaw, std::vector<uint8_t>({10, 20, 30, 40, 50, 60}));
}

// A caller who hangs up without saying anything must not produce a flushed
// message at all -- enqueueVoicemailFlush() drops a zero-length recording.
TEST(VoicemailDivert, HangingUpWithNoAudioProducesNoFlushedMessage)
{
	SentList sent;
	RequestsHandler handler("192.168.44.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	handler.handle(makeRegister("602", "192.168.44.11", "reg-602"));
	handler.handle(makeRegister("612", "192.168.44.21", "reg-612"));
	handler.setVoicemail("602", true);

	const std::string callId = "vm-empty-1";
	const std::string branch = "z9hG4bKvmempty1";
	handler.handle(makeInvite("612", "602", "192.168.44.21", callId, branch));
	handler.handle(makeBusy("612", "602", "192.168.44.11", callId, branch));
	ASSERT_TRUE(handler.getSession("Call-ID: " + callId).has_value());

	handler.forceDisconnect("612");

	FakeSink sink;
	handler.drainVoicemailFlush(sink);
	EXPECT_TRUE(sink.calls.empty())
		<< "nobody said anything -- nothing should reach the flush queue";
}

// With a greeting loaded, a deposit must play it BEFORE recording -- not
// record immediately (dead silence to the caller, the pre-greeting
// behavior). tick() is what advances Playing -> PlaybackDone -> Recording;
// nothing else polls playbackDone().
TEST(VoicemailDivert, DepositPlaysGreetingBeforeRecordingWhenOneIsLoaded)
{
	SentList sent;
	RequestsHandler handler("192.168.45.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const uint8_t greeting[] = {77, 78, 79};
	handler.setVoicemailGreetingForTest(greeting, sizeof(greeting));

	handler.handle(makeRegister("801", "192.168.45.11", "reg-701"));
	handler.handle(makeRegister("811", "192.168.45.21", "reg-711"));
	handler.setVoicemail("801", true);

	const std::string callId = "vm-greet-1";
	const std::string branch = "z9hG4bKvmgreet1";
	handler.handle(makeInvite("811", "801", "192.168.45.21", callId, branch));
	handler.handle(makeBusy("811", "801", "192.168.45.11", callId, branch));

	auto session = handler.getSession("Call-ID: " + callId);
	ASSERT_TRUE(session.has_value());
	const int slot = session.value()->getVoicemailLegSlot();
	ASSERT_GE(slot, 0);

	// Immediately after answer: playing the greeting, NOT recording yet. Feed
	// audio now and it must be silently dropped (leg is Playing, not
	// Recording) -- proves the greeting-first ordering, not just that a
	// greeting CAN play.
	const uint8_t earlyAudio[] = {1, 2, 3};
	EXPECT_FALSE(handler.feedVoicemailAudioForTest(slot, earlyAudio, sizeof(earlyAudio)))
		<< "must still be playing the greeting, not recording, right after answer";

	uint8_t out[3] = {};
	ASSERT_TRUE(handler.readVoicemailPlaybackForTest(slot, out, sizeof(out)));
	EXPECT_EQ(out[0], 77); EXPECT_EQ(out[1], 78); EXPECT_EQ(out[2], 79);

	// The greeting (3 bytes) is now fully delivered -> PlaybackDone. tick()
	// is the only thing that advances this to Recording.
	handler.tick();

	const uint8_t frame[] = {10, 20};
	EXPECT_TRUE(handler.feedVoicemailAudioForTest(slot, frame, sizeof(frame)))
		<< "tick() must have advanced the leg to Recording once the greeting finished";

	handler.forceDisconnect("811");
	FakeSink sink;
	handler.drainVoicemailFlush(sink);
	ASSERT_EQ(sink.calls.size(), 1u);
	EXPECT_EQ(sink.calls[0].mulaw, std::vector<uint8_t>({10, 20}))
		<< "only the post-greeting audio should have been recorded";
}

// Regression: with no greeting loaded (the default, and every other test in
// this file), a deposit must still record immediately -- the behavior every
// earlier test already relies on, pinned explicitly here.
TEST(VoicemailDivert, DepositRecordsImmediatelyWithNoGreetingLoaded)
{
	SentList sent;
	RequestsHandler handler("192.168.45.2", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	handler.handle(makeRegister("802", "192.168.45.12", "reg-702"));
	handler.handle(makeRegister("812", "192.168.45.22", "reg-712"));
	handler.setVoicemail("802", true);

	const std::string callId = "vm-nogreet-1";
	const std::string branch = "z9hG4bKvmnogreet1";
	handler.handle(makeInvite("812", "802", "192.168.45.22", callId, branch));
	handler.handle(makeBusy("812", "802", "192.168.45.12", callId, branch));

	auto session = handler.getSession("Call-ID: " + callId);
	ASSERT_TRUE(session.has_value());
	const int slot = session.value()->getVoicemailLegSlot();
	ASSERT_GE(slot, 0);

	const uint8_t frame[] = {5, 6, 7};
	EXPECT_TRUE(handler.feedVoicemailAudioForTest(slot, frame, sizeof(frame)))
		<< "no greeting loaded -- must record from the start, no tick() needed";
}

// Wall-clock safety net: a session whose voicemail deadline has passed must
// be BYEd and torn down even if onCallerRtp()'s byte-cap was never hit (a
// caller whose audio silently stopped arriving).
TEST(VoicemailDivert, ExpiredVoicemailDeadlineByesAndTearsDownTheSession)
{
	SentList sent;
	RequestsHandler handler("192.168.45.3", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	const sockaddr_in callerAddr = addrFor("192.168.45.23");

	handler.handle(makeRegister("803", "192.168.45.13", "reg-703"));
	handler.handle(makeRegister("813", "192.168.45.23", "reg-713"));
	handler.setVoicemail("803", true);

	const std::string callId = "vm-deadline-1";
	const std::string branch = "z9hG4bKvmdeadline1";
	handler.handle(makeInvite("813", "803", "192.168.45.23", callId, branch));
	handler.handle(makeBusy("813", "803", "192.168.45.13", callId, branch));

	auto session = handler.getSession("Call-ID: " + callId);
	ASSERT_TRUE(session.has_value());
	session.value()->armVoicemailDeadline(std::chrono::steady_clock::now() - std::chrono::seconds(1));

	handler.tick();

	EXPECT_FALSE(findSentTo(sent, callerAddr, "BYE sip:").empty())
		<< "an expired voicemail deadline must BYE the caller, not just silently drop the session";
	EXPECT_FALSE(handler.getSession("Call-ID: " + callId).has_value());
}
