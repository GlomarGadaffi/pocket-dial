// HttpDramAccount_test.cpp -- #410/#328: the bench-only internal-DRAM accounting
// for the HTTP path (POCKETDIAL_HTTP_DRAM_ACCOUNT, docs/BENCH_PROBE.md).
//
//   1. The counter arithmetic (add, release, high-water, the simultaneous total,
//      the composition at its peak) as a pure helper: no server, no socket, so
//      it runs on every platform in the default build.
//   2. The wiring into HttpServer, compiled only when the guard is on (POSIX
//      host build with -DPOCKETDIAL_HTTP_DRAM_ACCOUNT=1). The guard-off output is
//      pinned in HttpStatusAlloc_test.cpp.

#include <gtest/gtest.h>

#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "HttpDramAccount.hpp"
#include "PoolConfig.hpp"

using httpdram::Account;
using httpdram::Held;
using httpdram::kReqBuf;
using httpdram::kReqParsed;
using httpdram::kReqRaw;
using httpdram::kRespBody;
using httpdram::kTaskStack;

namespace
{
	// The two members writeJson() needs from a writer, backed by a string.
	struct StrOut
	{
		std::string out;
		StrOut& s(std::string_view v) { out.append(v); return *this; }
		template <class T> StrOut& n(T v) { out += std::to_string(v); return *this; }
	};
}

TEST(HttpDramAccount, AddAndReleaseMoveNowAndKeepTheHighWater)
{
	Account a;
	a.add(kReqBuf, 4096);
	a.add(kReqBuf, 4096);
	EXPECT_EQ(a.now(kReqBuf), 8192u);
	EXPECT_EQ(a.hwm(kReqBuf), 8192u);
	a.sub(kReqBuf, 4096);
	EXPECT_EQ(a.now(kReqBuf), 4096u);
	EXPECT_EQ(a.hwm(kReqBuf), 8192u) << "the high-water never falls";
	a.sub(kReqBuf, 4096);
	EXPECT_EQ(a.now(kReqBuf), 0u);
	EXPECT_EQ(a.totalNow(), 0u);
	EXPECT_EQ(a.totalHwm(), 8192u);
}

TEST(HttpDramAccount, ReleasingMoreThanHeldSaturatesAtZeroAndKeepsTheTotalHonest)
{
	Account a;
	a.add(kReqRaw, 10);
	a.add(kRespBody, 100);
	a.sub(kReqRaw, 50);   // a release larger than the hold must not wrap
	EXPECT_EQ(a.now(kReqRaw), 0u);
	EXPECT_EQ(a.totalNow(), 100u) << "only the 10 that were held come off the total";
	a.sub(kRespBody, 100);
	EXPECT_EQ(a.totalNow(), 0u);
}

TEST(HttpDramAccount, TheTotalPeakIsTheSimultaneousPeakNotTheSumOfThePeaks)
{
	// The request buffer peaks and is gone before the response body exists, so
	// the two never overlap: the bytes ever held at once is 100, not 200.
	Account a;
	a.add(kReqBuf, 100);
	a.sub(kReqBuf, 100);
	a.add(kRespBody, 100);
	EXPECT_EQ(a.hwm(kReqBuf), 100u);
	EXPECT_EQ(a.hwm(kRespBody), 100u);
	EXPECT_EQ(a.totalHwm(), 100u);
}

TEST(HttpDramAccount, TheCompositionAtThePeakIsKeptUntilTheTotalSetsANewHigh)
{
	Account a;
	a.add(kTaskStack, 4096);
	a.add(kReqBuf, 4096);   // total 8192: a new high
	EXPECT_EQ(a.atPeak(kTaskStack), 4096u);
	EXPECT_EQ(a.atPeak(kReqBuf), 4096u);
	EXPECT_EQ(a.atPeak(kReqRaw), 0u);

	a.add(kReqRaw, 100);    // total 8292: a new high, now with the raw string in it
	EXPECT_EQ(a.atPeak(kReqRaw), 100u);

	a.sub(kReqRaw, 100);
	a.sub(kTaskStack, 4096);
	a.add(kRespBody, 50);   // total 4146: below the peak, so the picture is not redrawn
	EXPECT_EQ(a.totalHwm(), 8292u);
	EXPECT_EQ(a.atPeak(kTaskStack), 4096u);
	EXPECT_EQ(a.atPeak(kReqRaw), 100u);
	EXPECT_EQ(a.atPeak(kRespBody), 0u);
}

TEST(HttpDramAccount, HeldFollowsGrowthAndShrinkAndReleasesOnEveryExitPath)
{
	Account a;
	{
		Held h(a, kReqRaw);
		h.set(100);
		h.set(300);   // the string grew
		EXPECT_EQ(a.now(kReqRaw), 300u);
		h.set(50);    // and shrank
		EXPECT_EQ(a.now(kReqRaw), 50u);
		h.set(50);    // unchanged: no movement
		EXPECT_EQ(a.totalNow(), 50u);
	}
	EXPECT_EQ(a.now(kReqRaw), 0u);
	EXPECT_EQ(a.hwm(kReqRaw), 300u);

	// handleClient() has many early returns: the holder, not the code path, releases.
	const auto request = [&a](bool early) {
		Held h(a, kReqBuf);
		h.set(4096);
		if (early) return;
		h.set(8192);
	};
	request(true);
	request(false);
	EXPECT_EQ(a.now(kReqBuf), 0u);
	EXPECT_EQ(a.hwm(kReqBuf), 8192u);
}

TEST(HttpDramAccount, HeapBytesCountsOnlyAStringThatLeftItsSmallBuffer)
{
	const std::string empty;
	const std::string small = "abc";
	const std::string big(200, 'x');
	std::string reserved;
	reserved.reserve(1000);

	EXPECT_EQ(httpdram::heapBytes(empty), 0u);
	EXPECT_EQ(httpdram::heapBytes(small), 0u) << "a small string lives inside the object, not on the heap";
	EXPECT_EQ(httpdram::heapBytes(big), static_cast<uint32_t>(big.capacity() + 1));
	EXPECT_GE(httpdram::heapBytes(reserved), 1001u) << "capacity, not size, is what is held";
	EXPECT_EQ(httpdram::heapBytesOf(small, big, reserved),
	          httpdram::heapBytes(big) + httpdram::heapBytes(reserved));
}

TEST(HttpDramAccount, ConnectionsCountThreadsAndTheirStacksAndASpawnFailureUndoesItsClaim)
{
	Account a;
	a.opened(4096);
	a.opened(4096);
	EXPECT_EQ(a.connsNow(), 2u);
	EXPECT_EQ(a.now(kTaskStack), 8192u);
	a.closed(4096);
	EXPECT_EQ(a.connsNow(), 1u);
	EXPECT_EQ(a.connsHwm(), 2u);
	EXPECT_EQ(a.now(kTaskStack), 4096u);
	EXPECT_EQ(a.hwm(kTaskStack), 8192u);

	a.opened(4096);       // claimed, then the thread could not be created
	a.spawnFailed(4096);
	EXPECT_EQ(a.connsNow(), 1u);
	EXPECT_EQ(a.now(kTaskStack), 4096u);
	EXPECT_EQ(a.spawnFailures(), 1u);
}

TEST(HttpDramAccount, TheLargestBodyIsKept)
{
	Account a;
	a.noteBody(300);
	a.noteBody(100);
	a.noteBody(5000);
	a.noteBody(4999);
	EXPECT_EQ(a.bodyMax(), 5000u);
}

TEST(HttpDramAccount, ConcurrentHoldsLoseNoUpdates)
{
	Account a;
	constexpr int kThreads = 4, kLaps = 20000;
	std::vector<std::thread> ts;
	for (int t = 0; t < kThreads; ++t)
		ts.emplace_back([&a] {
			for (int i = 0; i < kLaps; ++i) { a.add(kReqBuf, 3); a.sub(kReqBuf, 3); }
		});
	for (auto& t : ts) t.join();
	EXPECT_EQ(a.now(kReqBuf), 0u);
	EXPECT_EQ(a.totalNow(), 0u);
	EXPECT_GE(a.hwm(kReqBuf), 3u);
	EXPECT_LE(a.hwm(kReqBuf), 3u * kThreads) << "at most every thread holds one at the same moment";
	EXPECT_EQ(a.totalHwm(), a.hwm(kReqBuf));

	ts.clear();
	for (int t = 0; t < kThreads; ++t)
		ts.emplace_back([&a] { for (int i = 0; i < kLaps; ++i) a.add(kReqRaw, 3); });
	for (auto& t : ts) t.join();
	EXPECT_EQ(a.now(kReqRaw), 3u * kThreads * kLaps);
	EXPECT_EQ(a.hwm(kReqRaw), a.now(kReqRaw));
}

TEST(HttpDramAccount, ResetClearsEveryCounter)
{
	Account a;
	a.opened(4096);
	a.add(kReqBuf, 4096);
	a.noteBody(77);
	a.spawnFailed(4096);
	a.reset();
	EXPECT_EQ(a.totalHwm(), 0u);
	EXPECT_EQ(a.connsHwm(), 0u);
	EXPECT_EQ(a.atPeak(kReqBuf), 0u);
	EXPECT_EQ(a.bodyMax(), 0u);
	EXPECT_EQ(a.spawnFailures(), 0u);
}

TEST(HttpDramAccount, TheStatusFragmentHasAPinnedShape)
{
	Account a;
	a.opened(4096);
	a.add(kReqBuf, 4096);
	a.add(kReqRaw, 120);
	a.add(kReqParsed, 50);
	a.noteBody(900);
	a.sub(kReqRaw, 120);
	StrOut o;
	a.writeJson(o);
	EXPECT_EQ(o.out,
		",\"httpDramAccount\":{"
		"\"conns\":{\"now\":1,\"hwm\":1},"
		"\"taskStack\":{\"now\":4096,\"hwm\":4096,\"atPeak\":4096},"
		"\"reqBuf\":{\"now\":4096,\"hwm\":4096,\"atPeak\":4096},"
		"\"reqRaw\":{\"now\":0,\"hwm\":120,\"atPeak\":120},"
		"\"reqParsed\":{\"now\":50,\"hwm\":50,\"atPeak\":50},"
		"\"respBody\":{\"now\":0,\"hwm\":0,\"atPeak\":0},"
		"\"total\":{\"now\":8242,\"hwm\":8362},"
		"\"respBodyMax\":900,"
		"\"spawnFailures\":0}");
}

#if POCKETDIAL_HTTP_DRAM_ACCOUNT && !defined(_WIN32) && !defined(_WIN64)

// The wiring, with the guard on. HttpServer.cpp feeds the process-wide
// httpdram::gAccount, so each test resets it first and nothing else is running.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>

#include "HttpServer.hpp"

namespace
{
	// One whole request through handleClient() on THIS thread (the same shape as
	// HttpRouteAlloc_test); returns what the server wrote back.
	std::string serveOne(HttpServer& server, const std::string& request)
	{
		int sv[2];
		if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { ADD_FAILURE() << "socketpair"; return {}; }
		::send(sv[1], request.data(), request.size(), MSG_NOSIGNAL);
		::shutdown(sv[1], SHUT_WR);
		std::string got;
		std::thread reader([&] {
			char buf[4096];
			for (ssize_t n; (n = ::recv(sv[1], buf, sizeof(buf), 0)) > 0;) got.append(buf, static_cast<size_t>(n));
		});
		server.handleClientForTest(sv[0]);   // closes sv[0] itself
		reader.join();
		::close(sv[1]);
		return got;
	}
}

TEST(HttpDramAccountServer, ARequestIsAccountedWhileInFlightAndFullyReleasedAfter)
{
	httpdram::gAccount.reset();
	HttpServer server("127.0.0.1", 0, nullptr);   // never start()ed; OS-assigned port (#540)
	const std::string path = "/no-such-route-for-the-accounting-test";   // 38 bytes: spills out of a small string
	const std::string request = "GET " + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
	const std::string resp = serveOne(server, request);
	ASSERT_EQ(resp.rfind("HTTP/1.1 404", 0), 0u) << resp.substr(0, 100);

	httpdram::Account& a = httpdram::gAccount;
	for (unsigned s = 0; s < httpdram::kSlotCount; ++s)
		EXPECT_EQ(a.now(static_cast<httpdram::Slot>(s)), 0u) << httpdram::kSlotNames[s] << " still held";
	EXPECT_EQ(a.totalNow(), 0u);

	EXPECT_EQ(a.hwm(kReqBuf), 4096u);
	EXPECT_GE(a.hwm(kReqRaw), request.size());
	EXPECT_GE(a.hwm(kReqParsed), path.size());
	EXPECT_GT(a.hwm(kRespBody), 0u);
	EXPECT_EQ(a.bodyMax(), a.hwm(kRespBody));
	EXPECT_EQ(a.hwm(kTaskStack), 0u) << "no thread was spawned: handleClient ran on the test's own";

	// All four are held at the moment the 404 is sent, so that is the peak.
	EXPECT_EQ(a.totalHwm(), a.hwm(kReqBuf) + a.hwm(kReqRaw) + a.hwm(kReqParsed) + a.hwm(kRespBody));
	EXPECT_EQ(a.atPeak(kReqBuf), 4096u);
	EXPECT_EQ(a.atPeak(kRespBody), a.hwm(kRespBody));
}

TEST(HttpDramAccountServer, TheLeasedStatusBodyIsNotCountedAsAResponseBuilderAndTheFieldIsReported)
{
	httpdram::gAccount.reset();
	HttpServer server("127.0.0.1", 0, nullptr);
	const std::string resp = serveOne(server, "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n");
	ASSERT_EQ(resp.rfind("HTTP/1.1 200", 0), 0u) << resp.substr(0, 100);
	// /api/status is formatted into a buffer allocated once at construction (PSRAM
	// on S3): standing, not per-request builder heap, so it must not count.
	EXPECT_EQ(httpdram::gAccount.hwm(kRespBody), 0u);
	EXPECT_NE(resp.find(",\"httpDramAccount\":{\"conns\":"), std::string::npos) << resp;
	EXPECT_NE(resp.find("\"respBody\":{\"now\":0,\"hwm\":0,\"atPeak\":0}"), std::string::npos) << resp;
	EXPECT_NE(resp.find("\"reqBuf\":{\"now\":4096,\"hwm\":4096,"), std::string::npos)
		<< "the status request itself is in flight while it is reported";
}

TEST(HttpDramAccountServer, ConnectionThreadsAreCountedWhileTheyRunAndReleasedWhenTheyEnd)
{
	httpdram::gAccount.reset();
	HttpServer server("127.0.0.1", 0, nullptr);
	server.setReadDeadlineMsForTest(3000);
	server.start();

	std::vector<int> clients;
	for (int i = 0; i < 2; ++i)
	{
		const int c = ::socket(AF_INET, SOCK_STREAM, 0);
		ASSERT_GE(c, 0);
		sockaddr_in to{};
		to.sin_family = AF_INET;
		to.sin_port = htons(static_cast<uint16_t>(server.port()));
		::inet_pton(AF_INET, "127.0.0.1", &to.sin_addr);
		ASSERT_EQ(::connect(c, reinterpret_cast<sockaddr*>(&to), sizeof(to)), 0);
		clients.push_back(c);
	}

	// Each handler thread is parked in recv() waiting for a request that never comes.
	const auto until = [](auto pred) {
		for (int i = 0; i < 400 && !pred(); ++i) std::this_thread::sleep_for(std::chrono::milliseconds(5));
		return pred();
	};
	httpdram::Account& a = httpdram::gAccount;
	ASSERT_TRUE(until([&] { return a.connsNow() == 2; }));
	EXPECT_EQ(a.now(kTaskStack), 2u * HttpServer::kHttpConnStackBytes);

	for (int c : clients) ::close(c);
	ASSERT_TRUE(until([&] { return server.activeConnectionsForTest() == 0; }));
	EXPECT_EQ(a.connsNow(), 0u);
	EXPECT_EQ(a.now(kTaskStack), 0u);
	EXPECT_EQ(a.connsHwm(), 2u);
	EXPECT_EQ(a.hwm(kTaskStack), 2u * HttpServer::kHttpConnStackBytes);
	EXPECT_EQ(a.spawnFailures(), 0u);
}

#endif   // POCKETDIAL_HTTP_DRAM_ACCOUNT && POSIX
