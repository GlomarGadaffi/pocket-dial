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

#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "AllocCounter.hpp"
#include "ArpLookup.hpp"
#include "HttpServer.hpp"
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
	EXPECT_NE(resp.find("\"dynamicTaskCreates\":" + std::to_string(before + 3) + "}"), std::string::npos)
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
	for (const char* key : { "stackHwm_tel_ctl0", "stackHwm_tel_ctl1", "stackHwm_tel_drop", "stackHwm_tel_sos" })
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
		"cdrLoadFailures", "packetsProcessed", "packetsDropped", "msgPoolRefusals", "vpeerPoolRefusals", "repliesRefused",
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
		"stackHwm_http_conn", "httpConnWorstRoute", "coredump", "l2Tx", "memory",
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
		EXPECT_EQ(topLevelKeys(body), want);
#if !POCKETDIAL_HTTP_DRAM_ACCOUNT
		EXPECT_EQ(body.find("httpDramAccount"), std::string::npos);
#endif
	}
}

#endif
