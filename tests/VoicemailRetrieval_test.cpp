// VoicemailRetrieval_test.cpp — Issue #246 (voicemail Stage 3 of #194),
// retrieval slice 3 of 3: the SIP-level ext-796 dial-in wired to the SD-I/O
// job machine and the VoicemailMenu state machine. Driven end to end through
// RequestsHandler::handle()/tick()/runVoicemailSdJobs(), the same style
// VoicemailDivert_test.cpp uses for the deposit side.

#include <gtest/gtest.h>

#include <chrono>
#include <cstring>
#include <map>
#include <string>
#include <thread>
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
			"m=audio " + std::to_string(rtpPort) + " RTP/AVP 0 101\r\n"
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

	// In-memory vmarchive::Source double, same shape as VoicemailArchive_test.cpp's
	// own FakeSource -- kept file-local rather than shared, matching this
	// codebase's existing convention of small per-file test doubles (FakeSink
	// is likewise duplicated between VoicemailArchive_test.cpp and
	// VoicemailDivert_test.cpp).
	class FakeSource : public vmarchive::Source
	{
	public:
		struct Stored
		{
			vmarchive::MessageInfo info;
			std::vector<uint8_t> body;
			bool deleted = false;
		};
		std::map<std::string, std::vector<Stored>> mailboxes;

		void deposit(const std::string& ext, const char* name, uint64_t epoch,
			const char* callId, std::vector<uint8_t> body)
		{
			Stored s;
			std::strncpy(s.info.name, name, sizeof(s.info.name) - 1);
			s.info.epochSeconds = epoch;
			s.info.length = body.size();
			std::strncpy(s.info.callId, callId, sizeof(s.info.callId) - 1);
			s.body = std::move(body);
			mailboxes[ext].push_back(std::move(s));
		}

		bool isDeleted(const std::string& ext, const char* name) const
		{
			auto it = mailboxes.find(ext);
			if (it == mailboxes.end()) return false;
			for (const auto& s : it->second)
			{
				if (std::strcmp(s.info.name, name) == 0) return s.deleted;
			}
			return false;
		}

		size_t listMessages(const char* extension, vmarchive::MessageInfo* out,
			size_t maxCount) const override
		{
			auto it = mailboxes.find(extension);
			if (it == mailboxes.end()) return 0;
			size_t count = 0;
			for (const auto& s : it->second)
			{
				if (s.deleted) continue;
				if (count >= maxCount) break;
				out[count++] = s.info;
			}
			return count;
		}

		size_t readMessage(const char* extension, const char* name,
			uint8_t* out, size_t capacity) const override
		{
			auto it = mailboxes.find(extension);
			if (it == mailboxes.end()) return 0;
			for (const auto& s : it->second)
			{
				if (s.deleted || std::strcmp(s.info.name, name) != 0) continue;
				if (s.body.size() > capacity) return 0;
				std::memcpy(out, s.body.data(), s.body.size());
				return s.body.size();
			}
			return 0;
		}

		bool markDeleted(const char* extension, const char* name) override
		{
			auto it = mailboxes.find(extension);
			if (it == mailboxes.end()) return true;
			for (auto& s : it->second)
			{
				if (std::strcmp(s.info.name, name) == 0) { s.deleted = true; break; }
			}
			return true;
		}
	};

	// Same reasoning as VoicemailDivert_test.cpp's greeting-test fix: RtpSender
	// is REAL on a WSL/Linux host build (#82) and starts draining fillTx() the
	// instant startPlaying() flips the leg to Playing, racing this thread for
	// the clip. Poll for the expected state, draining a frame ourselves each
	// iteration so the assertion holds on the MSVC stub too (where no sender
	// thread exists to drain it at all).
	bool waitForVoicemailLegState(RequestsHandler& handler, int slot, VoicemailLeg::State want)
	{
		for (int i = 0; i < 1000; ++i)
		{
			if (handler.voicemailLegStateForTest(slot) == want) return true;
			uint8_t discard[8];
			handler.readVoicemailPlaybackForTest(slot, discard, sizeof(discard));
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
		}
		return false;
	}
}

// The full advisor-specified walk: answer -> list job -> menu starts ->
// read job -> real playback -> digit '7' -> delete+advance -> next message.
TEST(VoicemailRetrieval, FullWalkThroughTwoMessagesWithADeleteViaDigitSeven)
{
	SentList sent;
	RequestsHandler handler("192.168.47.1", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	handler.handle(makeRegister("801", "192.168.47.11", "reg-r1"));
	handler.setVoicemail("801", true);

	FakeSource source;
	source.deposit("801", "1000", 1000, "call-old-1", {10, 20, 30});
	source.deposit("801", "1001", 1001, "call-old-2", {40, 50});

	const std::string callId = "vm-retrieve-1";
	const std::string branch = "z9hG4bKvmr1";
	// Caller-ID IS the mailbox: 801 dials 796 from its own extension.
	handler.handle(makeInvite("801", "796", "192.168.47.11", callId, branch));

	auto session = handler.getSession("Call-ID: " + callId);
	ASSERT_TRUE(session.has_value());
	const int slot = session.value()->getVoicemailLegSlot();
	ASSERT_GE(slot, 0);
	ASSERT_TRUE(session.value()->isVoicemail());

	const sockaddr_in callerAddr = addrFor("192.168.47.11");
	EXPECT_FALSE(findSentTo(sent, callerAddr, "SIP/2.0 200 OK").empty())
		<< "must answer immediately -- the list load happens off the SIP thread";

	ASSERT_TRUE(handler.voicemailSdJobPendingForTest(slot))
		<< "answering must kick off the initial mailbox listing";
	EXPECT_EQ(handler.voicemailLegStateForTest(slot), VoicemailLeg::State::Idle)
		<< "nothing to play until the list comes back";

	// SD-I/O task runs the list job.
	handler.runVoicemailSdJobs(source);
	ASSERT_FALSE(handler.voicemailSdJobPendingForTest(slot));
	handler.sweepVoicemailLegsForTest();   // consumes the Done list -> menu.start(2) -> PlayMessage(0) -> issues a Read job

	EXPECT_EQ(handler.voicemailMessageCountForTest(slot), 2u);
	ASSERT_TRUE(handler.voicemailSdJobPendingForTest(slot))
		<< "PlayMessage must issue a Read job before anything can play";
	EXPECT_EQ(handler.voicemailLegStateForTest(slot), VoicemailLeg::State::Idle)
		<< "still nothing to play until the read comes back";

	// SD-I/O task runs the read job for message 0.
	handler.runVoicemailSdJobs(source);
	handler.sweepVoicemailLegsForTest();   // consumes the Done read -> startPlaying() for real

	ASSERT_TRUE(waitForVoicemailLegState(handler, slot, VoicemailLeg::State::PlaybackDone))
		<< "message 0's 3 bytes must finish playing";

	// Press '7' BEFORE the next tick: sweepVoicemailLegs() checks a pending
	// digit first, so this exercises the digit-driven advance (delete +
	// move on) rather than the natural PlaybackDone-driven one -- the menu
	// itself doesn't care which one fires first, only that exactly one
	// does, since it hasn't been told the message finished yet either way.
	handler.feedVoicemailDigitForTest(slot, '7');
	handler.sweepVoicemailLegsForTest();   // onDigit('7') -> delete message 0, advance to message 1 -> issues a Read job

	EXPECT_EQ(handler.voicemailLegStateForTest(slot), VoicemailLeg::State::Idle)
		<< "reset() before requesting the next read -- see dispatchVoicemailMenuCommand()'s doc comment";
	ASSERT_TRUE(handler.voicemailSdJobPendingForTest(slot))
		<< "the digit must have queued a delete-and-read job";

	handler.runVoicemailSdJobs(source);
	handler.sweepVoicemailLegsForTest();   // consumes the Done read -> startPlaying() for message 1

	ASSERT_TRUE(waitForVoicemailLegState(handler, slot, VoicemailLeg::State::PlaybackDone))
		<< "message 1's 2 bytes must finish playing";

	EXPECT_TRUE(source.isDeleted("801", "1000"))
		<< "the '7' press must have actually deleted message 0 in the archive";
	EXPECT_FALSE(source.isDeleted("801", "1001"))
		<< "only the message that was playing gets deleted, not the one that replaced it";

	// Let message 1 finish naturally -> no more messages -> Hangup -> BYE.
	sent.clear();
	handler.sweepVoicemailLegsForTest();
	EXPECT_FALSE(findSentTo(sent, callerAddr, "BYE sip:").empty())
		<< "end of mailbox must BYE the caller, not just go silent";
	EXPECT_FALSE(handler.getSession("Call-ID: " + callId).has_value());
}

// A caller with an empty mailbox gets the (asset-less, MVP) prompt path,
// which synthesizes an immediate finish and hangs up -- no messages to
// list/read/play at all.
TEST(VoicemailRetrieval, EmptyMailboxHangsUpAfterTheSyntheticPrompt)
{
	SentList sent;
	RequestsHandler handler("192.168.47.2", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	handler.handle(makeRegister("802", "192.168.47.12", "reg-r2"));
	handler.setVoicemail("802", true);

	FakeSource source;   // nothing deposited for 802

	const std::string callId = "vm-retrieve-empty";
	handler.handle(makeInvite("802", "796", "192.168.47.12", callId, "z9hG4bKvmempty"));

	auto session = handler.getSession("Call-ID: " + callId);
	ASSERT_TRUE(session.has_value());
	const int slot = session.value()->getVoicemailLegSlot();
	ASSERT_GE(slot, 0);
	EXPECT_FALSE(session.value()->getDialogFrom().empty()) << "dialog From must be captured at answer time";
	EXPECT_FALSE(session.value()->getDialogTo().empty()) << "dialog To must be captured at answer time";
	EXPECT_TRUE(session.value()->getSrc() != nullptr);

	ASSERT_TRUE(handler.voicemailSdJobPendingForTest(slot));
	handler.runVoicemailSdJobs(source);
	ASSERT_FALSE(handler.voicemailSdJobPendingForTest(slot)) << "list job never completed";
	sent.clear();
	handler.sweepVoicemailLegsForTest();   // list=0 -> menu.start(0) -> PlayPrompt -> synthesized done -> Hangup -> BYE

	const sockaddr_in callerAddr = addrFor("192.168.47.12");
	EXPECT_FALSE(handler.getSession("Call-ID: " + callId).has_value()) << "session must be torn down";
	EXPECT_FALSE(findSentTo(sent, callerAddr, "BYE sip:").empty());
	EXPECT_FALSE(handler.getSession("Call-ID: " + callId).has_value());
}

// A caller who isn't enabled for voicemail must be refused outright, no
// slot claimed -- the mailbox-owner identity IS the auth for this MVP, so
// disabled means "no mailbox to authenticate into."
TEST(VoicemailRetrieval, RefusesADialInFromAnExtensionWithVoicemailDisabled)
{
	SentList sent;
	RequestsHandler handler("192.168.47.3", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	handler.handle(makeRegister("803", "192.168.47.13", "reg-r3"));
	// Deliberately NOT calling handler.setVoicemail("803", true).

	const std::string callId = "vm-retrieve-disabled";
	handler.handle(makeInvite("803", "796", "192.168.47.13", callId, "z9hG4bKvmdisabled"));

	EXPECT_FALSE(handler.getSession("Call-ID: " + callId).has_value())
		<< "must refuse before claiming a slot";
	const sockaddr_in callerAddr = addrFor("192.168.47.13");
	EXPECT_FALSE(findSentTo(sent, callerAddr, "403 Forbidden").empty());
}

TEST(VoicemailRetrieval, PcmaOnlyDialInGets488NotAMailboxItCanNeverHear)
{
	// Issue #304: retrieval only ever SENDS PCMU (buildMediaSdp is PCMU-only
	// regardless of what was offered), so a PCMA-only caller could never
	// hear their own mailbox even though this leg discards the caller's own
	// audio (nothing to decode on THIS leg's own account).
	SentList sent;
	RequestsHandler handler("192.168.47.3", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	handler.handle(makeRegister("804", "192.168.47.14", "reg-r4"));
	handler.setVoicemail("804", true);
	sent.clear();   // else findSentTo's reverse scan matches 804's own REGISTER 200 OK

	const std::string callId = "vm-retrieve-pcma";
	const sockaddr_in callerAddr = addrFor("192.168.47.14");
	std::string body =
		"v=0\r\n"
		"o=- 0 0 IN IP4 192.168.47.14\r\n"
		"s=-\r\n"
		"c=IN IP4 192.168.47.14\r\n"
		"t=0 0\r\n"
		"m=audio 10000 RTP/AVP 8\r\n"
		"a=rtpmap:8 PCMA/8000\r\n";
	std::string raw =
		"INVITE sip:796@server SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.47.14:5060;branch=z9hG4bKvmretpcma\r\n"
		"From: <sip:804@server>;tag=ft" + callId + "\r\n"
		"To: <sip:796@server>\r\n"
		"Call-ID: " + callId + "\r\n"
		"CSeq: 1 INVITE\r\n"
		"Max-Forwards: 70\r\n"
		"Contact: <sip:804@192.168.47.14:5060>\r\n"
		"Content-Type: application/sdp\r\n"
		"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
	handler.handle(RequestsHandler::getMessageFromPool(raw, callerAddr));

	EXPECT_FALSE(handler.getSession("Call-ID: " + callId).has_value())
		<< "must refuse before claiming a slot";
	EXPECT_FALSE(findSentTo(sent, callerAddr, "SIP/2.0 488").empty())
		<< "PCMA-only retrieval dial-in should be refused with 488";
	EXPECT_TRUE(findSentTo(sent, callerAddr, "SIP/2.0 200 OK").empty());
}

// SIP INFO digits on a voicemail leg must never leak into the star-code
// parser (Fable-Low review finding: this guard was previously absent
// entirely). Pin it with a real, directly observable feature code -- *60
// (Selective Call Rejection / DND) toggles the DIALING extension's DND
// flag, visible via the same snapshot the HTTP dashboard reads. Sending
// "*60" via SIP INFO on a voicemail Call-ID must NOT set DND for 805;
// without the isVoicemail() guard added alongside this slice, it would.
TEST(VoicemailRetrieval, SipInfoDigitsOnAVoicemailLegNeverReachTheStarCodeParser)
{
	SentList sent;
	RequestsHandler handler("192.168.47.4", 5060,
		[&sent](const sockaddr_in& addr, std::shared_ptr<SipMessage> msg) {
			sent.emplace_back(addr, std::move(msg));
		});

	handler.handle(makeRegister("805", "192.168.47.15", "reg-r5"));
	handler.setVoicemail("805", true);

	FakeSource source;
	source.deposit("805", "2000", 2000, "call-x", {1, 2, 3});

	const std::string callId = "vm-info-guard";
	handler.handle(makeInvite("805", "796", "192.168.47.15", callId, "z9hG4bKvminfo"));
	ASSERT_TRUE(handler.getSession("Call-ID: " + callId).has_value());

	auto contains = [](const std::vector<std::string>& v, const std::string& s) {
		for (const auto& x : v) if (x == s) return true;
		return false;
	};
	ASSERT_FALSE(contains(handler.getDndExtensions(), "805"));

	// "*60" via three separate SIP INFO dtmf-relay messages on the SAME
	// (voicemail) Call-ID -- the exact shape DtmfClassCodes_test.cpp's own
	// StarSixty test uses against an ordinary extension.
	for (char digit : std::string("*60"))
	{
		std::string body = std::string("Signal=") + digit + "\r\nDuration=100\r\n";
		std::string head =
			"INFO sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 192.168.47.15:5060;branch=z9hG4bKvminfod\r\n"
			"From: <sip:805@server>;tag=it" + callId + "\r\n"
			"To: <sip:796@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 2 INFO\r\n"
			"Content-Type: application/dtmf-relay\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
		handler.handle(RequestsHandler::getMessageFromPool(head, addrFor("192.168.47.15")));
	}

	EXPECT_FALSE(contains(handler.getDndExtensions(), "805"))
		<< "a voicemail leg's SIP INFO digits must never reach the star-code parser";
}
