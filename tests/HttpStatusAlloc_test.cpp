// HttpStatusAlloc_test.cpp -- issue #410 phase 3: GET /api/status, polled
// every second by the dashboard, builds its body in a fixed per-connection
// buffer allocated at construction -- no heap per request.
//
//   1. ZERO ALLOCATION: with every snapshot table populated, and both with and
//      without a session, serving /api/status allocates nothing on the calling
//      thread (AllocGuard). Red on the old ostringstream + vector-copy route.
//   2. REFUSE, DON'T TRUNCATE: a body larger than the buffer is a 500 with no
//      partial JSON, counted in statusRefusals() and reported as
//      httpStatusRefusals on the next status.

#include <gtest/gtest.h>

#include <algorithm>
#include <memory>
#include <regex>
#include <string>
#include <thread>
#include <vector>

#include "AlertCapture.hpp"      // #1126: the pbx-911 frames a boot alert puts on the wire
#include "AllocCounter.hpp"
#include "ArpLookup.hpp"
#include "BootTaskSlots.hpp"   // #1126: which boot-allocated task slots failed
#include "DmaFramePool.hpp"     // #985: mediaTx.l2.poolMin
#include "HttpServer.hpp"
#include "MediaTxStats.hpp"     // #985: the mediaTx block
#include "PoolConfig.hpp"       // POCKETDIAL_HTTP_DRAM_ACCOUNT (#410/#328)
#include "PsramAllocator.hpp"   // #479: psram::dynamicTaskCreates()
#include "RequestsHandler.hpp"

#ifndef POCKETDIAL_HTTP_DRAM_ACCOUNT
#error "PoolConfig.hpp must define POCKETDIAL_HTTP_DRAM_ACCOUNT (default 0)"
#endif

#if !defined(_WIN32) && !defined(_WIN64)   // socketpair(): POSIX host only

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

namespace
{
	std::shared_ptr<SipMessage> makeRegister(const std::string& ext)
	{
		const std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 10.0.0.50:5060;branch=z9hG4bKst" + ext + "\r\n"
			"From: <sip:" + ext + "@server>;tag=st" + ext + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: st-reg-" + ext + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@10.0.0.50:5060>;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_port = htons(5060);
		inet_pton(AF_INET, "10.0.0.50", &a.sin_addr);
		return RequestsHandler::getMessageFromPool(raw, a);
	}

	struct StatusBench
	{
		std::unique_ptr<RequestsHandler> handler;
		HttpServer server{"127.0.0.1", 28412, nullptr};   // never start()ed

		StatusBench()
		{
			handler = std::make_unique<RequestsHandler>("10.0.0.1", 5060,
				[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
			handler->handle(makeRegister("101"));
			handler->handle(makeRegister("102"));
			handler->setDnd("101", true);
			handler->setVoicemail("102", true);
			handler->setForward("101", "busy", "102");
			handler->setRingGroup("600", "101,102", "ringall");
			handler->tick();
			server.attachHandler(handler.get());
		}

		// Serve /api/status on THIS thread; the socket is drained on another.
		std::string serve(bool authenticated, size_t* allocs = nullptr)
		{
			int sv[2];
			if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { ADD_FAILURE() << "socketpair"; return {}; }
			std::string got;
			std::thread reader([&] {
				char buf[4096];
				for (ssize_t n; (n = ::recv(sv[1], buf, sizeof(buf), 0)) > 0;) got.append(buf, static_cast<size_t>(n));
			});
			{
				AllocGuard g;
				server.sendApiStatusForTest(sv[0], authenticated);
				if (allocs) *allocs = g.delta();
			}
			::shutdown(sv[0], SHUT_WR);
			reader.join();
			::close(sv[0]);
			::close(sv[1]);
			return got;
		}
	};
}

TEST(HttpStatusAlloc, ServingStatusAllocatesNothing)
{
	StatusBench b;
	for (bool authed : {false, true})
	{
		SCOPED_TRACE(authed ? "with session" : "anonymous");
		b.serve(authed);   // warm-up: first-use statics (e.g. the IP probe) are init, not per request
		size_t allocs = 1;
		const std::string resp = b.serve(authed, &allocs);
		ASSERT_EQ(resp.rfind("HTTP/1.1 200", 0), 0u) << resp.substr(0, 200);
		EXPECT_NE(resp.find("\"clientCount\":2"), std::string::npos) << resp;
		EXPECT_NE(resp.find("\"members\":\"101,102\""), std::string::npos) << resp;
		EXPECT_EQ(resp.find("\"number\":\"101\"") != std::string::npos, authed) << resp;
		EXPECT_EQ(allocs, 0u);
	}
}

TEST(HttpStatusAlloc, AnOfficeSizedBodyFitsTheSmallestBuffer)
{
	// #599 review: the no-PSRAM profile's buffer is 16 KB. A full small office
	// (~15 KB, Globox's #410 inventory) must be served there, not refused.
	StatusBench b;
	for (int g = 0; g < 32; ++g)
	{
		std::string members;
		for (int m = 0; m < 32; ++m)
		{
			if (m) members += ",";
			members += std::to_string(10000000 + g * 100 + m);
		}
		b.handler->setRingGroup(std::to_string(600 + g), members, "ringall");
		b.handler->setForward(std::to_string(1000 + g), "busy", std::to_string(2000 + g));
	}
	b.handler->tick();
	b.server.setStatusCapForTest(16384);
	const std::string resp = b.serve(true);
	ASSERT_EQ(resp.rfind("HTTP/1.1 200", 0), 0u) << resp.substr(0, 200);
	const size_t body = resp.size() - (resp.find("\r\n\r\n") + 4);
	EXPECT_GE(body, 14000u) << "not office-sized; grow the bench";
	EXPECT_LE(body, 16384u);
	EXPECT_EQ(b.server.statusRefusals(), 0u);
}

TEST(HttpStatusAlloc, ABodyThatDoesNotFitIsRefusedAndCounted)
{
	StatusBench b;
	b.server.setStatusCapForTest(256);
	const std::string refused = b.serve(true);
	EXPECT_EQ(refused.rfind("HTTP/1.1 500", 0), 0u) << refused;
	EXPECT_EQ(refused.find("\"ip\""), std::string::npos) << "no partial status: " << refused;
	EXPECT_EQ(b.server.statusRefusals(), 1u);

	b.server.setStatusCapForTest(HttpServer::kStatusBufBytes);
	EXPECT_NE(b.serve(false).find("\"httpStatusRefusals\":1,"), std::string::npos);
}


TEST(HttpStatusAlloc, TheDynamicTaskCreateCountIsOnStatus)
{
	// #479 done-when: an exported count of dynamic task creates, read before and
	// after a call on .244 (the increments sit in ESP-only create paths).
	StatusBench b;
	const uint32_t before = psram::dynamicTaskCreates().load();
	psram::dynamicTaskCreates().fetch_add(3);
	const std::string resp = b.serve(false);
	EXPECT_NE(resp.find("\"dynamicTaskCreates\":" + std::to_string(before + 3) + ","), std::string::npos)
		<< resp;
	psram::dynamicTaskCreates().store(before);
}

TEST(HttpStatusAlloc, TheTelCtlWorkerStackWatermarksAreOnStatus)
{
	// #657: the anchor's call-control workers keep 12 KB stacks by precedent (a
	// TLS handshake runs on them); their high-water marks are the evidence any
	// smaller size needs. null on the host build, like every stackHwm_* field.
	StatusBench b;
	const std::string resp = b.serve(false);
	for (const char* key : { "stackHwm_tel_ctl0", "stackHwm_tel_ctl1", "stackHwm_tel_drop", "stackHwm_tel_sos", "stackHwm_tel_sweep" })
	{
		EXPECT_NE(resp.find(std::string("\"") + key + "\":null"), std::string::npos) << key << " missing from /api/status";
	}
}

TEST(HttpStatusAlloc, TheHandlerBugCountersAreOnStatusAndPacketsDroppedIsTheirSum)
{
	// #702 item 19 (desmo): repliesRefused (#424) and optionsPingTruncated (#463)
	// were readable only by tests; a board could never show them. Both are now
	// on /api/status. packetsDropped is derived from the two per-reason counts,
	// so it equals their sum exactly. One malformed datagram is the positive
	// control that the fields carry live values, not constants.
	StatusBench b;
	b.handler->handle(RequestsHandler::getMessageFromPool("not sip at all\r\n\r\n", sockaddr_in{}));
	const std::string resp = b.serve(false);
	EXPECT_NE(resp.find("\"repliesRefused\":0,"), std::string::npos) << resp;
	EXPECT_NE(resp.find("\"optionsPingTruncated\":0,"), std::string::npos) << resp;
	EXPECT_NE(resp.find("\"byeTruncated\":0,"), std::string::npos) << resp;   // #744
	EXPECT_NE(resp.find("\"packetsDropped\":1,"), std::string::npos) << resp;
	EXPECT_NE(resp.find("\"droppedInvalid\":1,"), std::string::npos) << resp;
	EXPECT_EQ(b.handler->getPacketsDropped(), b.handler->getDroppedInvalid() + b.handler->getDroppedRate());
}

TEST(HttpStatusAlloc, LearnArpRequestsLimitedIsOnStatus)
{
	// #864 review (Stray): the ARP requests held back for unanswered Learn
	// REGISTERs are visible on a board. Two copies of a REGISTER for a locked
	// extension from an on-link source that never answers ARP: the second
	// copy's request is held back.
	struct ClearMocks { ~ClearMocks() { ArpLookup::clearMockMacs(); } } clearMocks;
	StatusBench b;
	EXPECT_NE(b.serve(false).find("\"learnArpRequestsLimited\":0,"), std::string::npos);
	b.handler->setRegistrarMode(RequestsHandler::RegistrarMode::Learn);
	b.handler->adoptDeviceForTest("020000000021", "201", Registrar::DeviceState::Learned, /*locked=*/true);
	sockaddr_in src{};
	src.sin_family = AF_INET;
	inet_pton(AF_INET, "10.0.0.50", &src.sin_addr);
	ArpLookup::setMockOnLink(src, std::nullopt);
	b.handler->handle(makeRegister("201"));
	b.handler->handle(makeRegister("201"));
	const std::string resp = b.serve(false);
	EXPECT_NE(resp.find("\"learnArpRequestsLimited\":1,"), std::string::npos) << resp;
}

TEST(HttpStatusAlloc, TheMediaTxBlockIsOnStatusAsSummariesAndCarriesTheNagleFlag)
{
	// #985 slice 0: the media TX instrument on the ungated route. Summaries only, no bucket
	// arrays, so the block stays small (the 16 KB no-PSRAM buffer has to hold an office body
	// with it). The same keys on the host as on the board, real zeros here: the counters are
	// platform-free statics. nodelay is the TCP_NODELAY A/B flag a bench capture is labelled by.
	struct Reset { ~Reset() { pd::MediaTx::resetForTest(); } } reset;
	pd::MediaTx::resetForTest();
	l2rtp::DmaFramePool::resetStats();
	StatusBench b;

	auto zeroHist = [] { return std::string("{\"n\":0,\"p50\":0,\"p99\":0,\"p999\":0,\"max\":0}"); };
	std::string legs;
	for (unsigned i = 0; i < pd::MediaTx::kLegs; ++i) legs += (i ? ",0" : "0");
	const std::string zeros =
		"\"mediaTx\":{\"nodelay\":0,\"write\":{\"n\":0,\"p99\":0,\"max\":0,\"over\":0,\"legOver\":[" + legs + "]}"
		",\"hold\":{\"miss\":0,\"maxOverrun\":0},\"feed\":{\"n\":0,\"late\":0,\"max\":0}"
		",\"l2\":{\"build\":" + zeroHist() + ",\"tx\":" + zeroHist() +
		",\"poolMin\":" + std::to_string(l2rtp::DmaFramePool::kPoolSize) +
		",\"errPoolEmpty\":0,\"errZeroLen\":0,\"errNoHandle\":0,\"errDriver\":0,\"retryOk\":0,\"fallbackSendFail\":0}}";
	for (bool authed : {false, true})
	{
		SCOPED_TRACE(authed ? "with session" : "anonymous");
		const std::string resp = b.serve(authed);
		EXPECT_NE(resp.find(zeros), std::string::npos) << resp;
		EXPECT_LT(zeros.size(), 520u) << "added to every /api/status body";
	}

	pd::MediaTx::recordWrite(false, 1, 25000);
	pd::MediaTx::recordTickMiss(7000);
	pd::MediaTx::recordFeedFrame(0, 100, 100 + 50000);
	pd::MediaTx::recordL2Fail(pd::MediaTx::L2Fail::Driver);
	pd::MediaTx::recordL2RetryOk();   // #999
	pd::MediaTx::recordFallbackSendFail();
	pd::MediaTx::setNodelay(true);
	const std::string live = b.serve(false);
	EXPECT_NE(live.find("\"mediaTx\":{\"nodelay\":1,\"write\":{\"n\":1,\"p99\":25000,\"max\":25000,\"over\":1,\"legOver\":[0,1"),
	          std::string::npos) << live;
	EXPECT_NE(live.find("\"hold\":{\"miss\":1,\"maxOverrun\":7000}"), std::string::npos) << live;
	EXPECT_NE(live.find("\"feed\":{\"n\":1,\"late\":1,\"max\":50000}"), std::string::npos) << live;
	EXPECT_NE(live.find("\"errDriver\":1,\"retryOk\":1,\"fallbackSendFail\":1}}"), std::string::npos) << live;
}

TEST(HttpStatusAlloc, TheMutexHoldIsOnStatus)
{
	// #986 slice 0: how long RequestsHandler::_mutex has been held. The values
	// depend on the host's scheduler, so this pins the shape: four fields, the
	// address a hex string. The anonymous route carries it too, like the heap figures.
	StatusBench b;
	const std::regex shape("\"mutexHold\":\\{\"max\":[0-9]+,\"p99\":[0-9]+,\"over\":[0-9]+,\"maxPc\":\"0x[0-9a-f]+\"\\}");
	for (bool authed : {false, true})
	{
		const std::string resp = b.serve(authed);
		EXPECT_TRUE(std::regex_search(resp, shape)) << resp;
	}
}

namespace
{
	// The top-level keys of a compact JSON object, in order. Tracks string and
	// nesting state, so keys of nested objects and arrays, and string values
	// containing a colon, are not reported.
	std::vector<std::string> topLevelKeys(const std::string& json)
	{
		std::vector<std::string> keys;
		std::string cur, pending;
		int depth = 0;
		bool inStr = false, esc = false, havePending = false;
		char prev = 0;
		for (char c : json)
		{
			if (inStr)
			{
				if (esc) { esc = false; cur += c; }
				else if (c == '\\') esc = true;
				else if (c == '"')
				{
					inStr = false;
					if (depth == 1 && (prev == '{' || prev == ',')) { pending = cur; havePending = true; }
					prev = '"';
				}
				else cur += c;
				continue;
			}
			if (c == '"') { inStr = true; cur.clear(); continue; }
			if (c == ':' && havePending) keys.push_back(pending);
			havePending = false;
			if (c == '{' || c == '[') ++depth;
			else if (c == '}' || c == ']') --depth;
			prev = c;
		}
		return keys;
	}
}

// #1126: a tel_sweep worker that never got its stack must be visible. The tests drive the same
// noteAlloc() that StaticTaskSlot::alloc() calls on the board, so the host sees what the board would.
namespace
{
	struct CleanBootSlots
	{
		CleanBootSlots() { pd::bootTaskSlots().resetForTest(); }
		~CleanBootSlots() { pd::bootTaskSlots().resetForTest(); }
	};

	void tickTimes(RequestsHandler& h, int n)
	{
		for (int i = 0; i < n; ++i)
		{
			h.forceNextTickForTest();
			h.tick();
		}
	}
}

TEST(HttpStatusAlloc, AFailedTelSweepSlotIsAbsentOnStatusCountedAndAlertedOnce)
{
	CleanBootSlots clean;
	StatusBench b;
	AlertCapture alerts;   // after the REGISTERs: a REGISTER pass ends in flushPass() too
	pd::bootTaskSlots().noteAlloc("tel_sweep", false);
	tickTimes(*b.handler, 1);
	const std::string resp = b.serve(false);
	EXPECT_NE(resp.find("\"telSweepWorker\":\"absent\""), std::string::npos) << resp;
	EXPECT_NE(resp.find("\"bootSlotFailures\":{\"tel_sweep\":1,"), std::string::npos) << resp;
	EXPECT_EQ(AlertCapture::frames().size(), 1u);
	ASSERT_FALSE(AlertCapture::frames().empty());
	EXPECT_NE(AlertCapture::frames()[0].find("tel_sweep"), std::string::npos) << AlertCapture::frames()[0];
}

TEST(HttpStatusAlloc, ANormalBootReportsTelSweepRunningWithNoFailuresAndNoAlert)
{
	CleanBootSlots clean;
	StatusBench b;
	AlertCapture alerts;
	tickTimes(*b.handler, 3);
	const std::string resp = b.serve(false);
	EXPECT_NE(resp.find("\"telSweepWorker\":\"running\""), std::string::npos) << resp;
	EXPECT_NE(resp.find("\"bootSlotFailures\":{\"tel_sweep\":0,\"tel_media_rx\":0,"
	                    "\"rtp_media_rx\":0,\"rtp_media_tx\":0,\"conf_mix_tick\":0}"), std::string::npos) << resp;
	EXPECT_EQ(AlertCapture::frames().size(), 0u);
}

TEST(HttpStatusAlloc, SeveralTicksAfterAFailedBootStillSendExactlyOneAlert)
{
	CleanBootSlots clean;
	StatusBench b;
	AlertCapture alerts;
	pd::bootTaskSlots().noteAlloc("tel_sweep", false);
	tickTimes(*b.handler, 6);
	EXPECT_EQ(AlertCapture::frames().size(), 1u);
	EXPECT_NE(b.serve(false).find("\"telSweepWorker\":\"absent\""), std::string::npos);
}

TEST(HttpStatusAlloc, AFailedSlotThatIsNotOnTheEmergencyPathCountsButRaisesNoAlert)
{
	CleanBootSlots clean;
	StatusBench b;
	AlertCapture alerts;
	pd::bootTaskSlots().noteAlloc("rtp_media_tx", false);
	tickTimes(*b.handler, 3);
	const std::string resp = b.serve(false);
	EXPECT_NE(resp.find("\"rtp_media_tx\":1,"), std::string::npos) << resp;
	EXPECT_NE(resp.find("\"telSweepWorker\":\"running\""), std::string::npos) << resp;
	EXPECT_EQ(AlertCapture::frames().size(), 0u);
}

namespace
{
	// A handler whose send callback counts the boot alert's MESSAGEs. No phone is registered at the start.
	struct FanBench
	{
		int messages = 0;
		std::unique_ptr<RequestsHandler> handler;
		FanBench()
		{
			handler = std::make_unique<RequestsHandler>("10.0.0.1", 5060,
				[this](const sockaddr_in&, std::shared_ptr<SipMessage> m) {
					if (m && m->toString().find("DEGRADED") != std::string::npos) ++messages;
				});
			handler->tick();
		}
	};
}

TEST(HttpStatusAlloc, TheBootAlertMessageWaitsForANotifyPhoneThenGoesOutExactlyOnce)
{
	CleanBootSlots clean;
	FanBench b;
	b.handler->setE911Config("200", "", "");
	AlertCapture alerts;
	pd::bootTaskSlots().noteAlloc("tel_sweep", false);
	tickTimes(*b.handler, 1);
	EXPECT_EQ(b.messages, 0) << "nobody is registered at the first tick";
	EXPECT_EQ(AlertCapture::frames().size(), 1u);
	b.handler->handle(makeRegister("200"));
	tickTimes(*b.handler, 1);
	EXPECT_EQ(b.messages, 1);
	tickTimes(*b.handler, 5);
	EXPECT_EQ(b.messages, 1);
	EXPECT_EQ(AlertCapture::frames().size(), 1u) << "the syslog frame is latched once";
}

TEST(HttpStatusAlloc, AnEmptyNotifyListSendsTheFrameOnceAndRetriesNothing)
{
	CleanBootSlots clean;
	FanBench b;
	AlertCapture alerts;
	pd::bootTaskSlots().noteAlloc("tel_sweep", false);
	tickTimes(*b.handler, 2);   // stage + flush, then a pass with nothing pending
	size_t allocs = 1;
	{
		AllocGuard g;
		tickTimes(*b.handler, 1);
		allocs = g.delta();
	}
	EXPECT_EQ(allocs, 0u);
	b.handler->setE911Config("200", "", "");
	b.handler->handle(makeRegister("200"));
	tickTimes(*b.handler, 3);
	EXPECT_EQ(b.messages, 0) << "an empty list at the alert means no retry, even if a phone is added later";
	EXPECT_EQ(AlertCapture::frames().size(), 1u);
}

TEST(HttpStatusAlloc, ARetryThatRunsOutOfTimeLogsOnceAndStops)
{
	CleanBootSlots clean;
	FanBench b;
	b.handler->setE911Config("200", "", "");
	AlertCapture alerts;
	b.handler->setBootAlertLimitForTest(std::chrono::milliseconds(0));
	pd::bootTaskSlots().noteAlloc("tel_sweep", false);
	tickTimes(*b.handler, 4);
	EXPECT_EQ(pdwitness::count("MESSAGE retries stopped"), 1u);
	b.handler->handle(makeRegister("200"));
	tickTimes(*b.handler, 3);
	EXPECT_EQ(b.messages, 0);
	EXPECT_EQ(pdwitness::count("MESSAGE retries stopped"), 1u);
	EXPECT_EQ(AlertCapture::frames().size(), 1u);
}

TEST(HttpStatusAlloc, TheStatusKeyListIsPinnedAndTheDramAccountGuardAddsOnlyItsOwnKey)
{
	// #410/#328: POCKETDIAL_HTTP_DRAM_ACCOUNT is bench-only and defaults to 0.
	// Off, /api/status must be exactly what it was before the accounting existed:
	// these are main's top-level keys, in main's order, taken from main's output
	// before the guard was added. On, the one extra key is httpDramAccount, last.
	StatusBench b;
	std::vector<std::string> want = {
		"ip", "port", "httpPort", "version", "httpReadDeadlineDrops", "httpPerSourceRefusals",
		"httpStatusRefusals", "wifiCapable", "emergencyRoute", "uptime", "cdrPersistFailures", "cdrPersistSuppressed",
		"cdrLoadFailures", "packetsProcessed", "packetsDropped", "msgPoolRefusals", "vpeerPoolRefusals", "repliesRefused", "e911UnknownAlertOverflow", "e911UnknownAlertSuppressed",
		"optionsPingTruncated", "byeTruncated", "trunkForgedRegisterResponses", "trunkForgedDialogResponses",
		"trunkRefusedDialogByes", "emergencyRtpReaps", "learnArpRequestsLimited", "e911Configured", "droppedInvalid",
		"droppedRate", "keepalivesCrlf", "droppedNoPool", "droppedOversize", "rtpRxOversize", "rtpTxPoolRefused",
		"rtpTxPoolRetired", "recvErrors", "lastRecvErrno", "recentDrops", "sd", "resetIncomplete", "resetIncompleteStage",
		"resetFailedMask", "resetJournal", "resetJournalWriteFailures", "clients", "clientCount", "rosterVisible",
		"sessionCount", "oldestSessionSec", "sessions", "dnd", "voicemail", "forwards", "groups", "dialplan",
		"parkedCount", "parkedCalls", "freeHeap", "minFreeHeap", "minFreeHeapSpiram", "minFreeHeapInternal",
		"freeHeapInternal", "largestFreeBlockInternal", "freeHeapDma", "largestFreeBlockDma", "resetReason",
		"stackHwm_sip_server_task", "stackHwm_udp_receiver_task", "stackHwm_rtp_media_tx", "stackHwm_rtp_media_rx",
		"stackHwm_conf_mix_tick", "stackHwm_tel_ctl0", "stackHwm_tel_ctl1", "stackHwm_tel_drop", "stackHwm_tel_sos",
		"stackHwm_tel_sweep", "stackHwm_flash_writer", "stackHwm_http_conn", "telSweepWorker", "httpConnWorstRoute", "coredump", "l2Tx", "memory", "mutexHold", "mediaTx",
	};
#if POCKETDIAL_HTTP_DRAM_ACCOUNT
	want.push_back("httpDramAccount");
#endif
	for (bool authed : {false, true})
	{
		SCOPED_TRACE(authed ? "with session" : "anonymous");
		const std::string resp = b.serve(authed);
		ASSERT_EQ(resp.rfind("HTTP/1.1 200", 0), 0u) << resp.substr(0, 200);
		const std::string body = resp.substr(resp.find("\r\n\r\n") + 4);
		std::vector<std::string> expected = want;
		if (authed)
		{
			// #1073: the per-slot "enabled without an acceptance" flags, behind the session.
			expected.insert(std::find(expected.begin(), expected.end(), "uptime"), "anchorAcceptanceMissing");
		}
		EXPECT_EQ(topLevelKeys(body), expected);
#if !POCKETDIAL_HTTP_DRAM_ACCOUNT
		EXPECT_EQ(body.find("httpDramAccount"), std::string::npos);
#endif
	}
}

#endif
