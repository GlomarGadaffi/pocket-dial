// HttpReadDeadline_test.cpp — issue #529: one LAN host must not be able to
// hold every HTTP connection slot.
//
// The server serves at most HttpServer::kMaxConcurrentConnections (3) at once.
// Its only read timeout used to be per recv() (5 s), and the buffered body loop
// runs before any auth check, so a client that sent a Content-Length and then a
// byte every few seconds held its slot for as long as it liked. Three of those
// and every dashboard, /api/status and login request got 503.
//
// Now: everything read before dispatch must arrive within one deadline, and one
// source address may hold at most kMaxConnectionsPerSource slots. Both tests
// drive a real HttpServer over loopback; the second needs 127.0.0.2 as a source
// address and skips where the stack can't bind it.
//
// Ports: this file owns 18250-18259. See CONTRIBUTING_FIRMWARE.md's table.

#include <gtest/gtest.h>
#include "HttpServer.hpp"
#include "RequestsHandler.hpp"
#include "SipMessage.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#endif

#include <atomic>
#include <memory>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

namespace
{
#if !defined(_WIN32) && !defined(_WIN64)
	// Same guard as EmailHttp_test.cpp and SmtpDialogue_test.cpp: when a holder
	// closes, its handler still answers the partial request, and a send() to a
	// closed peer raises SIGPIPE, which would kill the whole test binary.
	struct SigpipeIgnoreDeadline
	{
		SigpipeIgnoreDeadline() { std::signal(SIGPIPE, SIG_IGN); }
	};
	SigpipeIgnoreDeadline g_sigpipeIgnoreDeadline;
#endif

#if defined(_WIN32) || defined(_WIN64)
	using Sock = SOCKET;
	constexpr int kNoSigPipe = 0;
	bool valid(Sock s) { return s != INVALID_SOCKET; }
	void closeSock(Sock s) { closesocket(s); }
#else
	using Sock = int;
	constexpr int kNoSigPipe = MSG_NOSIGNAL;   // the server closes on us mid-trickle
	bool valid(Sock s) { return s >= 0; }
	void closeSock(Sock s) { close(s); }
#endif

	// Connected TCP socket from `srcIp` to 127.0.0.1:port, with a receive
	// timeout; an invalid socket if that source can't be bound or connect fails.
	Sock connectFrom(const std::string& srcIp, int port, int recvTimeoutMs = 3000)
	{
		Sock s = socket(AF_INET, SOCK_STREAM, 0);
		if (!valid(s)) return s;
		sockaddr_in src{};
		src.sin_family = AF_INET;
		inet_pton(AF_INET, srcIp.c_str(), &src.sin_addr);
		sockaddr_in dst{};
		dst.sin_family = AF_INET;
		dst.sin_port = htons(static_cast<uint16_t>(port));
		inet_pton(AF_INET, "127.0.0.1", &dst.sin_addr);
#if defined(_WIN32) || defined(_WIN64)
		DWORD tv = static_cast<DWORD>(recvTimeoutMs);
		setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
		const Sock bad = INVALID_SOCKET;
#else
		timeval tv{};
		tv.tv_sec = recvTimeoutMs / 1000;
		tv.tv_usec = (recvTimeoutMs % 1000) * 1000;
		setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		const Sock bad = -1;
#endif
		if (bind(s, reinterpret_cast<sockaddr*>(&src), sizeof(src)) != 0 ||
			connect(s, reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) != 0)
		{
			closeSock(s);
			return bad;
		}
		return s;
	}

	bool sendAll(Sock s, const std::string& data)
	{
		return send(s, data.c_str(), static_cast<int>(data.size()), kNoSigPipe) == static_cast<int>(data.size());
	}

	std::string recvAll(Sock s)
	{
		std::string resp;
		char buf[512];
		int n;
		while ((n = static_cast<int>(recv(s, buf, sizeof(buf), 0))) > 0)
		{
			resp.append(buf, static_cast<size_t>(n));
		}
		return resp;
	}

	int statusOf(const std::string& resp)
	{
		const size_t sp1 = resp.find(' ');
		if (sp1 == std::string::npos) return -1;
		return std::atoi(resp.c_str() + sp1 + 1);
	}

	// A request that parks in the body loop: headers promising 100 bytes, then 1.
	const std::string kSlowHead =
		"POST /api/does-not-exist HTTP/1.1\r\n"
		"Host: 127.0.0.1\r\n"
		"Content-Length: 100\r\n"
		"Connection: close\r\n\r\n"
		"x";

	// The handler threads reference the server: let them finish before it goes.
	void waitIdle(const HttpServer& server)
	{
		for (int i = 0; i < 200 && server.activeConnectionsForTest() > 0; ++i)
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
		}
	}
}

TEST(HttpReadDeadline, ATrickledBodyIsDroppedAtTheDeadline)
{
	RequestsHandler handler("192.168.52.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	HttpServer server("127.0.0.1", 18250, nullptr);
	server.attachHandler(&handler);
	server.setReadDeadlineMsForTest(300);
	server.start();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));

	Sock s = connectFrom("127.0.0.1", 18250);
	ASSERT_TRUE(valid(s));
	ASSERT_TRUE(sendAll(s, kSlowHead));

	// One byte every 50 ms: no single recv() ever waits long, which is exactly
	// what a per-recv timeout cannot catch. On main this keeps going.
	std::atomic<bool> stop{false};
	std::thread trickle([&]() {
		for (int i = 0; i < 60 && !stop.load(); ++i)
		{
			if (!sendAll(s, "y")) break;
			std::this_thread::sleep_for(std::chrono::milliseconds(50));
		}
	});

	const auto t0 = std::chrono::steady_clock::now();
	const std::string resp = recvAll(s);   // returns when the server closes (or 3 s)
	const auto waited = std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::steady_clock::now() - t0).count();
	stop = true;
	trickle.join();
	closeSock(s);

	EXPECT_TRUE(resp.empty()) << "a request not in by the deadline is dropped, not answered: " << resp;
	EXPECT_LT(waited, 1500) << "the server must close at the 300 ms deadline, not wait on the trickle";
	EXPECT_EQ(server.readDeadlineDrops(), 1u);
	waitIdle(server);
}

TEST(HttpReadDeadline, OneSourceCannotHoldEverySlot)
{
	RequestsHandler handler("192.168.52.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	HttpServer server("127.0.0.1", 18251, nullptr);
	server.attachHandler(&handler);
	server.setReadDeadlineMsForTest(3000);   // long enough to hold the slots for the test
	server.start();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));

	// One source takes every slot it is allowed, each parked in the body loop.
	std::vector<Sock> holders;
	for (int i = 0; i < HttpServer::kMaxConnectionsPerSource; ++i)
	{
		Sock h = connectFrom("127.0.0.2", 18251);
		if (!valid(h))
		{
			for (Sock x : holders) closeSock(x);
			waitIdle(server);
			GTEST_SKIP() << "this stack can't use 127.0.0.2 as a source address";
		}
		ASSERT_TRUE(sendAll(h, kSlowHead));
		holders.push_back(h);
	}
	std::this_thread::sleep_for(std::chrono::milliseconds(100));

	// The same source asking for one more is refused...
	Sock extra = connectFrom("127.0.0.2", 18251);
	ASSERT_TRUE(valid(extra));
	ASSERT_TRUE(sendAll(extra, "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"));
	const std::string refused = recvAll(extra);
	closeSock(extra);
	EXPECT_EQ(statusOf(refused), 503) << refused;
	EXPECT_NE(refused.find("this address"), std::string::npos) << refused;
	EXPECT_EQ(server.perSourceRefusals(), 1u);

	// ...and anyone else still gets served.
	Sock other = connectFrom("127.0.0.1", 18251);
	ASSERT_TRUE(valid(other));
	ASSERT_TRUE(sendAll(other, "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"));
	const std::string served = recvAll(other);
	closeSock(other);
	EXPECT_EQ(statusOf(served), 200) << "a second client must still be served while one source holds its share";

	for (Sock h : holders) closeSock(h);
	waitIdle(server);
}

TEST(HttpReadDeadline, ASocketWhoseTimeoutCannotBeSetIsClosedUnanswered)
{
	// #534 review: setsockopt(SO_RCVTIMEO)'s result was discarded, so a socket
	// it failed on would recv() with no bound at all -- the very hang #529
	// exists to stop. It is now closed unread, and counted with the deadline
	// drops. The seam makes the failure deterministic.
	struct ResetSeam
	{
		~ResetSeam() { HttpServer::setFailSocketTimeoutsForTest(false, false); }
	} resetSeam;

	RequestsHandler handler("192.168.52.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	HttpServer server("127.0.0.1", 18252, nullptr);
	server.attachHandler(&handler);
	server.start();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));

	HttpServer::setFailSocketTimeoutsForTest(/*failRecv=*/true, /*failSend=*/false);
	Sock s = connectFrom("127.0.0.1", 18252);
	ASSERT_TRUE(valid(s));
	ASSERT_TRUE(sendAll(s, "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"));
	const std::string resp = recvAll(s);
	closeSock(s);

	EXPECT_TRUE(resp.empty()) << "an unbounded socket must not be served: " << resp;
	EXPECT_EQ(server.readDeadlineDrops(), 1u);
	HttpServer::setFailSocketTimeoutsForTest(false, false);
	waitIdle(server);
}

TEST(HttpReadDeadline, ARefusalWhoseSendTimeoutCannotBeSetClosesUnanswered)
{
	// #534 review: the accept thread's 503 refusals must never block it. If
	// SO_SNDTIMEO cannot be set, refuseBusy() closes WITHOUT sending, rather
	// than risk a send() with no bound on the one thread every client needs.
	struct ResetSeam
	{
		~ResetSeam() { HttpServer::setFailSocketTimeoutsForTest(false, false); }
	} resetSeam;

	RequestsHandler handler("192.168.52.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	HttpServer server("127.0.0.1", 18253, nullptr);
	server.attachHandler(&handler);
	server.setReadDeadlineMsForTest(3000);   // long enough to hold the slots for the test
	server.start();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));

	// One source takes every slot it is allowed, each parked in the body loop.
	std::vector<Sock> holders;
	for (int i = 0; i < HttpServer::kMaxConnectionsPerSource; ++i)
	{
		Sock h = connectFrom("127.0.0.2", 18253);
		if (!valid(h))
		{
			for (Sock x : holders) closeSock(x);
			waitIdle(server);
			GTEST_SKIP() << "this stack can't use 127.0.0.2 as a source address";
		}
		ASSERT_TRUE(sendAll(h, kSlowHead));
		holders.push_back(h);
	}
	for (int i = 0; i < 100 && server.activeConnectionsForTest() < HttpServer::kMaxConnectionsPerSource; ++i)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
	ASSERT_EQ(server.activeConnectionsForTest(), HttpServer::kMaxConnectionsPerSource);

	// The holders' own timeouts are already set; only the refusal's fails.
	HttpServer::setFailSocketTimeoutsForTest(/*failRecv=*/false, /*failSend=*/true);
	Sock extra = connectFrom("127.0.0.2", 18253);
	ASSERT_TRUE(valid(extra));
	sendAll(extra, "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
	const std::string refused = recvAll(extra);
	closeSock(extra);
	HttpServer::setFailSocketTimeoutsForTest(false, false);

	EXPECT_TRUE(refused.empty()) << "no send without a send bound: " << refused;
	EXPECT_EQ(server.perSourceRefusals(), 1u);

	for (Sock h : holders) closeSock(h);
	waitIdle(server);
}

namespace
{
	// #871: holds each handler thread after its socket is closed and before its
	// slot is freed, until a ticket lets one go (or 3 s pass).
	struct ClosedHold
	{
		std::atomic<int> parked{0};
		std::atomic<int> tickets{0};
		std::atomic<bool> open{false};
		void hold()
		{
			++parked;
			const auto end = std::chrono::steady_clock::now() + std::chrono::seconds(3);
			while (!open.load() && std::chrono::steady_clock::now() < end)
			{
				int t = tickets.load();
				if (t > 0 && tickets.compare_exchange_weak(t, t - 1)) break;
				std::this_thread::sleep_for(std::chrono::milliseconds(1));
			}
			--parked;
		}
		void waitParked(int n)
		{
			for (int i = 0; i < 300 && parked.load() < n; ++i)
				std::this_thread::sleep_for(std::chrono::milliseconds(5));
		}
	};

	std::string getStatus(int port)
	{
		Sock s = connectFrom("127.0.0.1", port);
		if (!valid(s)) return {};
		sendAll(s, "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
		std::string resp = recvAll(s);   // to EOF, as TelephonyConfigHttp_test's client reads
		closeSock(s);
		return resp;
	}
}

// #871: the flake. A client that sends one request after another, each read to
// EOF, was refused 503 "too many connections from this address" when three of
// its own finished connections' threads had not yet returned: the source slot
// was released only after handleClient(), which had already closed the socket.
// The hold makes that window deterministic.
TEST(HttpReadDeadline, AClientsNextRequestIsNeverRefusedByItsOwnClosedConnections)
{
	RequestsHandler handler("192.168.52.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	HttpServer server("127.0.0.1", 18255, nullptr);
	server.attachHandler(&handler);
	ClosedHold hold;
	server.setAfterCloseHookForTest([&hold]() { hold.hold(); });
	server.start();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));

	for (int i = 0; i < HttpServer::kMaxConnectionsPerSource; ++i)
	{
		EXPECT_EQ(statusOf(getStatus(18255)), 200) << "request " << i;
	}
	hold.waitParked(HttpServer::kMaxConnectionsPerSource);
	ASSERT_EQ(hold.parked.load(), HttpServer::kMaxConnectionsPerSource);

	const std::string next = getStatus(18255);
	EXPECT_EQ(statusOf(next), 200) << next;
	EXPECT_EQ(server.perSourceRefusals(), 0u);

	hold.open = true;
	waitIdle(server);
}

// The global cap still bounds the threads (#368). A full house of closed but not
// yet returned handlers is waited for, briefly: one that returns inside the wait
// lets the next request in; none returning still gets the 503.
TEST(HttpReadDeadline, TheGlobalCapWaitsBrieflyForAClosedHandlerAndNoLonger)
{
	RequestsHandler handler("192.168.52.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	HttpServer server("127.0.0.1", 18256, nullptr);
	server.attachHandler(&handler);
	ClosedHold hold;
	server.setAfterCloseHookForTest([&hold]() { hold.hold(); });
	server.start();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));

	for (int i = 0; i < HttpServer::kMaxConcurrentConnections; ++i)
	{
		ASSERT_EQ(statusOf(getStatus(18256)), 200) << "request " << i;
	}
	hold.waitParked(HttpServer::kMaxConcurrentConnections);
	ASSERT_EQ(server.activeConnectionsForTest(), HttpServer::kMaxConcurrentConnections);

	const std::string refused = getStatus(18256);
	EXPECT_EQ(statusOf(refused), 503) << "no thread returned: the bound holds";
	EXPECT_NE(refused.find("too many concurrent connections"), std::string::npos) << refused;

	server.setClosingWaitMsForTest(2000);   // the 10 ms below is far inside it, loaded host or not
	std::thread letOneGo([&hold]() {
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
		++hold.tickets;
	});
	const std::string served = getStatus(18256);
	letOneGo.join();
	EXPECT_EQ(statusOf(served), 200) << served;

	hold.open = true;
	waitIdle(server);
}

TEST(HttpReadDeadline, DestroyingTheServerWaitsForItsConnectionThreads)
{
	// #540: connection threads are detached and touch the server after
	// handleClient() returns. The destructor used to return at once, freeing the
	// server under a live handler (the segfault seen in a later, unrelated test).
	// A handler parked in the body loop must hold the destructor until it exits
	// at the 300 ms read deadline; without the wait this took ~0 ms.
	RequestsHandler handler("192.168.52.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	auto server = std::make_unique<HttpServer>("127.0.0.1", 18254, nullptr);
	server->attachHandler(&handler);
	server->setReadDeadlineMsForTest(300);
	server->start();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));

	Sock s = connectFrom("127.0.0.1", 18254);
	ASSERT_TRUE(valid(s));
	ASSERT_TRUE(sendAll(s, kSlowHead));
	for (int i = 0; i < 100 && server->activeConnectionsForTest() < 1; ++i)
		std::this_thread::sleep_for(std::chrono::milliseconds(5));
	ASSERT_EQ(server->activeConnectionsForTest(), 1);

	const auto t0 = std::chrono::steady_clock::now();
	server.reset();
	const auto destroyMs = std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::steady_clock::now() - t0).count();
	closeSock(s);
	EXPECT_GE(destroyMs, 150) << "the destructor must wait for the parked handler";
}
