// NvsWriter_test.cpp -- #986 slice 2: NVS persistence off the SIP thread.
//
// NvsWriterLogic.* tests drive the policy (Stager) against the host's
// depth-1 mailboxes with small slots, so the oversize and per-key cases are
// cheap to hit. NvsWriterWiring.* tests drive the real callers on the real
// process-wide instance: a REGISTER adoption (Registrar::persistDevices) and the
// *72/*73 codes (PbxFeatureConfig::persistForwards via setForwardLocked) must
// STAGE their blob, in the format the boot loaders read, not write NVS. The
// board-only half (FreeRTOS queues, the task, the nvs_* sink) is pinned by
// tests/tools/test_nvs_writer_wiring.py.

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <chrono>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "ArpLookup.hpp"
#include "NvsWriter.hpp"
#include "NvsWriterLogic.hpp"
#include "RequestsHandler.hpp"
#include "ResetGuard.hpp"
#include "SipMessage.hpp"
#include "SipSecretStore.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

using nvswriter::BlobWriter;
using nvswriter::Key;
using nvswriter::StageResult;

namespace
{
	// Three keys, tiny slots: Devices holds 15 payload bytes, Forwards and DidMap 63.
	struct Rig
	{
		nvswriter::Slot<16> devices;
		nvswriter::Slot<64> forwards;
		nvswriter::Slot<64> didmap;
		nvswriter::Slot<64> scratch;
		std::array<nvswriter::SlotRef, nvswriter::kKeyCount> refs{{nvswriter::refOf(devices), nvswriter::refOf(forwards), nvswriter::refOf(didmap)}};
		nvswriter::DepthOneMailboxes mail{refs};
		nvswriter::Stager<nvswriter::DepthOneMailboxes> st{mail, refs, &scratch};

		StageResult put(Key k, std::string_view s)
		{
			return st.stage(k, [&](BlobWriter& w) { w.str(s); });
		}
	};

	struct Seen
	{
		Key key;
		std::string bytes;
	};

	struct Recorder
	{
		std::vector<Seen> seen;
		bool result = true;
		bool operator()(Key k, const char* p, size_t n)
		{
			seen.push_back({k, std::string(p, n)});
			return result;
		}
	};

	class NvsWriterLogic : public ::testing::Test
	{
	protected:
		void SetUp() override { resetguard::resetForTest(); }
		void TearDown() override { resetguard::resetForTest(); }
		Rig rig;
	};
}

TEST_F(NvsWriterLogic, StagingAKeyTwiceKeepsOnlyTheLastAndCountsOneOverwrite)
{
	EXPECT_EQ(rig.put(Key::Devices, "first"), StageResult::Ok);
	EXPECT_EQ(rig.put(Key::Devices, "second"), StageResult::Ok);

	EXPECT_EQ(rig.st.stats().staged, 2u);
	EXPECT_EQ(rig.st.stats().overwrites, 1u) << "the second stage replaced a blob nobody had taken";

	Recorder r;
	EXPECT_EQ(rig.st.drainOnce(r), 1u);
	ASSERT_EQ(r.seen.size(), 1u) << "last write wins: the first snapshot is never written";
	EXPECT_EQ(r.seen[0].key, Key::Devices);
	EXPECT_EQ(r.seen[0].bytes, "second");

	// A stage after the writer took the key replaces nothing.
	EXPECT_EQ(rig.put(Key::Devices, "third"), StageResult::Ok);
	EXPECT_EQ(rig.st.stats().overwrites, 1u);
}

TEST_F(NvsWriterLogic, TwoDifferentKeysDoNotDropEachOther)
{
	// The device table behind a *72, and a *72 behind the device table.
	EXPECT_EQ(rig.put(Key::Devices, "dev-table"), StageResult::Ok);
	EXPECT_EQ(rig.put(Key::Forwards, "fwd-table"), StageResult::Ok);
	EXPECT_EQ(rig.st.stats().overwrites, 0u) << "different keys never replace each other";

	Recorder r;
	EXPECT_EQ(rig.st.drainOnce(r), 2u);
	ASSERT_EQ(r.seen.size(), 2u);
	EXPECT_EQ(r.seen[0].key, Key::Devices);
	EXPECT_EQ(r.seen[0].bytes, "dev-table");
	EXPECT_EQ(r.seen[1].key, Key::Forwards);
	EXPECT_EQ(r.seen[1].bytes, "fwd-table");

	// Same, with the newer write on the other side of the pair.
	EXPECT_EQ(rig.put(Key::Devices, "d1"), StageResult::Ok);
	EXPECT_EQ(rig.put(Key::Forwards, "f1"), StageResult::Ok);
	EXPECT_EQ(rig.put(Key::Devices, "d2"), StageResult::Ok);
	Recorder r2;
	EXPECT_EQ(rig.st.drainOnce(r2), 2u);
	ASSERT_EQ(r2.seen.size(), 2u);
	EXPECT_EQ(r2.seen[0].bytes, "d2");
	EXPECT_EQ(r2.seen[1].bytes, "f1");
}

TEST_F(NvsWriterLogic, TheStagedBlobEqualsTheSourceBytes)
{
	const std::string src = std::string("aabbccddeeff\t201\t0\t0\t1\n") + "112233445566\t202\t1\t3\t4294967295\n";
	nvswriter::Slot<128> big;
	nvswriter::Slot<128> scratch;
	std::array<nvswriter::SlotRef, nvswriter::kKeyCount> refs{{nvswriter::refOf(big), nvswriter::refOf(big), nvswriter::refOf(big)}};
	nvswriter::DepthOneMailboxes mail(refs);
	nvswriter::Stager<nvswriter::DepthOneMailboxes> st(mail, refs, &scratch);

	EXPECT_EQ(st.stage(Key::Devices, [&](BlobWriter& w) {
		w.str("aabbccddeeff"); w.ch('\t'); w.str("201"); w.ch('\t'); w.uint(0); w.ch('\t'); w.uint(0); w.ch('\t'); w.uint(1); w.ch('\n');
		w.str("112233445566"); w.ch('\t'); w.str("202"); w.ch('\t'); w.uint(1); w.ch('\t'); w.uint(3); w.ch('\t'); w.uint(4294967295u); w.ch('\n');
	}), StageResult::Ok);
	EXPECT_EQ(mail.payload(Key::Devices), src) << "what waits in the queue is the serialised table, byte for byte";

	Recorder r;
	EXPECT_EQ(st.drainOnce(r), 1u);
	ASSERT_EQ(r.seen.size(), 1u);
	EXPECT_EQ(r.seen[0].bytes, src);
}

TEST_F(NvsWriterLogic, ABlobLargerThanTheSlotIsRefusedAndCountedNeverTruncated)
{
	const std::string fits(15, 'a');       // Slot<16>: 15 payload bytes + the NUL
	const std::string tooLong(16, 'b');
	EXPECT_EQ(rig.put(Key::Devices, fits), StageResult::Ok);

	EXPECT_EQ(rig.put(Key::Devices, tooLong), StageResult::TooBig);
	EXPECT_EQ(rig.st.stats().tooBig, 1u);
	EXPECT_EQ(rig.st.stats().staged, 1u);

	// Appended in pieces, the sum is what counts: no half-written blob.
	EXPECT_EQ(rig.st.stage(Key::Devices, [](BlobWriter& w) { w.str(std::string(8, 'c')); w.str(std::string(8, 'c')); }),
		StageResult::TooBig);
	EXPECT_EQ(rig.st.stats().tooBig, 2u);

	// A refused stage leaves the blob already queued exactly as it was.
	Recorder r;
	EXPECT_EQ(rig.st.drainOnce(r), 1u);
	ASSERT_EQ(r.seen.size(), 1u);
	EXPECT_EQ(r.seen[0].bytes, fits);

	// And on an empty queue a refused blob queues nothing at all.
	EXPECT_EQ(rig.put(Key::Devices, tooLong), StageResult::TooBig);
	EXPECT_TRUE(rig.mail.payload(Key::Devices).empty());
	Recorder none;
	EXPECT_EQ(rig.st.drainOnce(none), 0u);
	EXPECT_TRUE(none.seen.empty());
}

TEST_F(NvsWriterLogic, BlobWriterFormatsUnsignedLikeToString)
{
	for (const uint32_t v : {0u, 7u, 10u, 99u, 100u, 65535u, 2147483648u, 4294967295u})
	{
		char buf[16] = {};
		BlobWriter w(buf, sizeof(buf));
		w.uint(v);
		ASSERT_TRUE(w.finish());
		EXPECT_EQ(std::string(buf), std::to_string(v));
	}
}

TEST_F(NvsWriterLogic, AStageDuringAFactoryResetIsRefusedAtStageTime)
{
	resetguard::begin();
	EXPECT_EQ(rig.put(Key::Devices, "late"), StageResult::Reset);
	EXPECT_EQ(rig.st.stats().suppressed, 1u);
	EXPECT_EQ(rig.st.stats().staged, 0u);
	EXPECT_TRUE(rig.mail.payload(Key::Devices).empty());
	EXPECT_FALSE(rig.mail.waiting(Key::Devices)) << "nothing may reach the queue behind a reset";
}

TEST_F(NvsWriterLogic, ABlobStagedBeforeAResetIsDiscardedUnwrittenWhenTheWriterGetsToIt)
{
	EXPECT_EQ(rig.put(Key::Devices, "before"), StageResult::Ok);
	resetguard::begin();   // the reset opens between the stage and the writer's pass

	Recorder r;
	EXPECT_EQ(rig.st.drainOnce(r), 0u);
	EXPECT_TRUE(r.seen.empty()) << "the writer refuses data during a reset like any NVS writer";
	EXPECT_EQ(rig.st.stats().suppressed, 1u);
	EXPECT_EQ(rig.st.stats().written, 0u);
	EXPECT_FALSE(rig.mail.waiting(Key::Devices)) << "...and does not keep it for later";
}

TEST_F(NvsWriterLogic, TheDrainWritesEveryKeyOnceAndIsIdleAfter)
{
	EXPECT_EQ(rig.put(Key::Forwards, "f"), StageResult::Ok);
	EXPECT_EQ(rig.put(Key::Devices, "d"), StageResult::Ok);

	Recorder r;
	EXPECT_EQ(rig.st.drainOnce(r), 2u);
	EXPECT_EQ(r.seen.size(), 2u);
	EXPECT_EQ(rig.st.stats().written, 2u);
	EXPECT_TRUE(resetguard::waitForWritersIdle(0)) << "no writer is registered once the pass is over";

	Recorder again;
	EXPECT_EQ(rig.st.drainOnce(again), 0u);
	EXPECT_TRUE(again.seen.empty()) << "nothing is written twice";
	EXPECT_TRUE(resetguard::waitForWritersIdle(0));
}

TEST_F(NvsWriterLogic, TheWriterIsRegisteredAsAResetguardWriterExactlyWhileItHoldsData)
{
	EXPECT_TRUE(resetguard::waitForWritersIdle(0)) << "idle before anything is staged";
	EXPECT_EQ(rig.put(Key::Devices, "d"), StageResult::Ok);
	EXPECT_TRUE(resetguard::waitForWritersIdle(0)) << "a staged blob is data in a queue, not a write in flight";

	bool busyInside = false;
	const unsigned wrote = rig.st.drainOnce([&](Key, const char*, size_t) {
		busyInside = !resetguard::waitForWritersIdle(0);
		return true;
	});
	EXPECT_EQ(wrote, 1u);
	EXPECT_TRUE(busyInside) << "the factory reset's drain must see the writer while it writes";
	EXPECT_TRUE(resetguard::waitForWritersIdle(0)) << "and not a moment after";
}

TEST_F(NvsWriterLogic, AResetThatBeginsMidWriteWaitsForTheWriterToFinish)
{
	EXPECT_EQ(rig.put(Key::Devices, "d"), StageResult::Ok);

	std::atomic<bool> sinkDone{false};
	std::atomic<bool> idleReturned{false};
	bool sawSinkDone = false;
	std::thread resetter;

	rig.st.drainOnce([&](Key, const char*, size_t) {
		resetguard::begin();   // the HTTP/DTMF reset door: flag first, then drain
		resetter = std::thread([&] {
			idleReturned = resetguard::waitForWritersIdle(2000);
			sawSinkDone = sinkDone.load();
		});
		std::this_thread::sleep_for(std::chrono::milliseconds(40));
		sinkDone = true;
		return true;
	});
	resetter.join();

	EXPECT_TRUE(idleReturned.load());
	EXPECT_TRUE(sawSinkDone) << "waitForWritersIdle returned while the writer was still writing";
}

TEST_F(NvsWriterLogic, AFailedWriteIsCountedAndNotRetried)
{
	EXPECT_EQ(rig.put(Key::Forwards, "f"), StageResult::Ok);
	Recorder r;
	r.result = false;
	EXPECT_EQ(rig.st.drainOnce(r), 0u);
	EXPECT_EQ(rig.st.stats().failed, 1u);
	EXPECT_EQ(rig.st.stats().written, 0u);

	Recorder again;
	EXPECT_EQ(rig.st.drainOnce(again), 0u);
	EXPECT_TRUE(again.seen.empty()) << "the in-RAM table is the truth; the next change restages it";
}

// ---------------------------------------------------------------------------
// The real callers, on the process-wide instance.

namespace
{
	sockaddr_in addrFor(const std::string& ip, int port = 5060)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip.c_str());
		s.sin_port = htons(static_cast<uint16_t>(port));
		return s;
	}

	std::string registerRaw(const std::string& ext, const std::string& ip, int seq)
	{
		const std::string id = "w" + std::to_string(seq);
		const std::string hostPort = ip + ":5060";
		return "REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + hostPort + ";branch=z9hG4bK" + id + "\r\n"
			"From: <sip:" + ext + "@server>;tag=t" + id + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: " + id + "@" + ip + "\r\n"
			"CSeq: " + std::to_string(seq) + " REGISTER\r\n"
			"Contact: <sip:" + ext + "@" + hostPort + ">;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
	}

	ArpLookup::Mac macOf(uint8_t last) { return ArpLookup::Mac{0x02, 0x00, 0x00, 0x00, 0x00, last}; }
	std::string hexOf(uint8_t last) { return ArpLookup::toHex12(macOf(last)); }

	std::shared_ptr<SipMessage> infoDigit(const std::string& from, const std::string& ip, const std::string& callId, char digit)
	{
		const std::string body = std::string("Signal=") + digit + "\r\nDuration=100\r\n";
		const std::string head =
			"INFO sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + ip + ":5060;branch=z9hG4bKi\r\n"
			"From: <sip:" + from + "@server>;tag=it\r\n"
			"To: <sip:server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 INFO\r\n"
			"Content-Type: application/dtmf-relay\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n\r\n";
		return RequestsHandler::getMessageFromPool(head + body, addrFor(ip));
	}

	std::vector<std::string> rowsOf(std::string_view blob)
	{
		std::vector<std::string> rows;
		size_t pos = 0;
		while (pos < blob.size())
		{
			const size_t nl = blob.find('\n', pos);
			if (nl == std::string_view::npos) { rows.emplace_back(blob.substr(pos)); break; }
			rows.emplace_back(blob.substr(pos, nl - pos));
			pos = nl + 1;
		}
		return rows;
	}

	class NvsWriterWiring : public ::testing::Test
	{
	protected:
		void SetUp() override
		{
			resetguard::resetForTest();
			nvswriter::resetForTest();
			ArpLookup::clearMockMacs();
			_h = std::make_unique<RequestsHandler>("192.168.60.1", 5060,
				[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
			_h->setRegistrarMode(RequestsHandler::RegistrarMode::Learn);
			_h->setLearnLockMinAgeForTest(std::chrono::seconds(0));
			nvswriter::resetForTest();   // the setup above may have staged
		}
		void TearDown() override
		{
			_h.reset();
			ArpLookup::clearMockMacs();
			SipSecretStore::clearSecret("201");   // here, not in a body: a failed ASSERT returns early
			nvswriter::resetForTest();
			resetguard::resetForTest();
		}

		void registerFrom(const std::string& ext, const std::string& ip)
		{
			_h->handle(RequestsHandler::getMessageFromPool(registerRaw(ext, ip, ++_seq), addrFor(ip)));
		}
		void dial(const std::string& from, const std::string& ip, const std::string& callId, const std::string& seq)
		{
			for (const char c : seq) _h->handle(infoDigit(from, ip, callId, c));
		}
		static std::string staged(Key k) { return std::string(nvswriter::stagedForTest(k)); }

		std::unique_ptr<RequestsHandler> _h;
		int _seq = 0;
	};
}

TEST_F(NvsWriterWiring, ALearnAdoptionStagesTheDeviceTableInTheFormatTheBootLoaderReads)
{
	ArpLookup::setMockMac(addrFor("192.168.60.21"), macOf(0x21));
	registerFrom("201", "192.168.60.21");

	// mac \t extension \t state \t flags \t seq \n -- Registrar::loadDevices()
	const std::vector<std::string> rows = rowsOf(staged(Key::Devices));
	ASSERT_EQ(rows.size(), 1u);
	EXPECT_EQ(rows[0].rfind(hexOf(0x21) + "\t201\t0\t0\t", 0), 0u) << rows[0];
	const std::string seq = rows[0].substr(rows[0].rfind('\t') + 1);
	ASSERT_FALSE(seq.empty());
	EXPECT_EQ(seq.find_first_not_of("0123456789"), std::string::npos) << rows[0];
	EXPECT_EQ(staged(Key::Devices).back(), '\n');
	EXPECT_EQ(nvswriter::stats().staged, 1u);
}

TEST_F(NvsWriterWiring, EveryChangeToTheDeviceTableRestagesTheWholeTable)
{
	ArpLookup::setMockMac(addrFor("192.168.60.21"), macOf(0x21));
	ArpLookup::setMockMac(addrFor("192.168.60.22"), macOf(0x22));
	registerFrom("201", "192.168.60.21");
	registerFrom("202", "192.168.60.22");
	ASSERT_TRUE(SipSecretStore::setSecret("201", "s3cret-201"));   // secure() refuses an extension with none
	EXPECT_EQ(rowsOf(staged(Key::Devices)).size(), 2u) << "the second adoption's blob holds both rows";
	EXPECT_EQ(nvswriter::stats().overwrites, 1u) << "...and replaced the first one, which no writer had taken";

	ASSERT_TRUE(_h->secureDevice("201"));
	std::string secured;
	for (const std::string& row : rowsOf(staged(Key::Devices)))
		if (row.rfind(hexOf(0x21) + "\t201\t", 0) == 0) secured = row;
	EXPECT_EQ(secured.rfind(hexOf(0x21) + "\t201\t1\t", 0), 0u) << "state 1 = Secured: " << secured;

	ASSERT_TRUE(_h->forgetDevice("202"));
	const std::vector<std::string> left = rowsOf(staged(Key::Devices));
	ASSERT_EQ(left.size(), 1u);
	EXPECT_EQ(left[0].rfind(hexOf(0x21) + "\t201\t", 0), 0u);
}

TEST_F(NvsWriterWiring, StarSeventyTwoStagesTheForwardTableInTheFormatTheBootLoaderReads)
{
	registerFrom("303", "192.168.60.52");
	nvswriter::resetForTest();
	dial("303", "192.168.60.52", "dtmf-72", "*725500");

	EXPECT_EQ(staged(Key::Forwards), "303\t5500\t\t\n") << "ext \\t always \\t busy \\t noAnswer \\n";
	EXPECT_EQ(nvswriter::stats().staged, 1u);
}

TEST_F(NvsWriterWiring, StarSeventyThreeStagesTheClearedTableAndReplacesTheUnwrittenOne)
{
	registerFrom("304", "192.168.60.53");
	nvswriter::resetForTest();
	dial("304", "192.168.60.53", "dtmf-73a", "*725501");
	dial("304", "192.168.60.53", "dtmf-73b", "*73");

	EXPECT_EQ(nvswriter::stats().staged, 2u);
	EXPECT_EQ(nvswriter::stats().overwrites, 1u) << "*73 replaced the *72 blob the writer had not taken";

	std::vector<Seen> seen;
	EXPECT_EQ(nvswriter::drainForTest([&](Key k, const char* p, size_t n) {
		seen.push_back({k, std::string(p, n)});
		return true;
	}), 1u);
	ASSERT_EQ(seen.size(), 1u);
	EXPECT_EQ(seen[0].key, Key::Forwards);
	EXPECT_EQ(seen[0].bytes, "") << "an empty table is persisted as an empty string, as before";
}

TEST_F(NvsWriterWiring, ADeviceAdoptionAndAForwardDoNotDropEachOther)
{
	ArpLookup::setMockMac(addrFor("192.168.60.21"), macOf(0x21));
	registerFrom("201", "192.168.60.21");
	dial("201", "192.168.60.21", "dtmf-both", "*725500");
	EXPECT_EQ(nvswriter::stats().overwrites, 0u);

	std::vector<Seen> seen;
	EXPECT_EQ(nvswriter::drainForTest([&](Key k, const char* p, size_t n) {
		seen.push_back({k, std::string(p, n)});
		return true;
	}), 2u);
	ASSERT_EQ(seen.size(), 2u);
	EXPECT_EQ(seen[0].key, Key::Devices);
	EXPECT_EQ(seen[0].bytes.rfind(hexOf(0x21) + "\t201\t", 0), 0u);
	EXPECT_EQ(seen[1].key, Key::Forwards);
	EXPECT_EQ(seen[1].bytes, "201\t5500\t\t\n");
}

TEST_F(NvsWriterWiring, NothingIsStagedWhileAFactoryResetRunsButTheTableStaysRight)
{
	registerFrom("305", "192.168.60.54");
	nvswriter::resetForTest();
	resetguard::begin();
	dial("305", "192.168.60.54", "dtmf-reset", "*725500");

	EXPECT_EQ(nvswriter::stats().staged, 0u);
	EXPECT_GE(nvswriter::stats().suppressed, 1u);
	EXPECT_TRUE(staged(Key::Forwards).empty());
	bool inRam = false;
	for (const auto& [ext, always, busy, noAnswer, noAnswerSeconds] : _h->getForwards())
		if (ext == "305" && always == "5500") inRam = true;
	EXPECT_TRUE(inRam) << "the live forward still works; only the flash copy is refused";
}
