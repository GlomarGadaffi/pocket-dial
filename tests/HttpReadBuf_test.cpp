// HttpReadBuf_test.cpp -- issues #410/#328: a connection's 4 KB recv buffer is
// reserved once per connection slot (PSRAM where the board has it), never
// allocated per request.
//
// The buffer is told apart from every other allocation by its size
// (SizedAllocGuard, tests/support/AllocCounter). On the host
// psram::allocPreferPsram() is plain operator new, so the reserved buffers
// show up in that count; the PSRAM branch and its spill into internal RAM
// (psram::internalFallbacks()) exist on the device only and are not run here.
// Servers use port 0 (#540): no fixed port to claim.

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <string>
#include <thread>

#include "AllocCounter.hpp"
#include "HttpServer.hpp"
#include "PsramAllocator.hpp"   // psram::internalFallbacks()

#if !defined(_WIN32) && !defined(_WIN64)   // socketpair(): POSIX host only

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace
{
	// The read buffer's size: std::vector<char>(4096) before #410, HttpServer::kReadBufBytes since.
	constexpr size_t kBufBytes = 4096;

	const std::string kNotFound = "GET /no-such-route HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";

	// One whole request through handleClient() ON THIS THREAD, so the per-thread
	// counts see it. Returns what the server wrote back.
	std::string serveOne(HttpServer& server, const std::string& request)
	{
		int sv[2];
		if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { ADD_FAILURE() << "socketpair"; return {}; }
		::send(sv[1], request.data(), request.size(), MSG_NOSIGNAL);
		::shutdown(sv[1], SHUT_WR);
		std::string got;
		std::thread reader([&] {
			char buf[1024];
			for (ssize_t n; (n = ::recv(sv[1], buf, sizeof(buf), 0)) > 0;) got.append(buf, static_cast<size_t>(n));
		});
		server.handleClientForTest(sv[0]);   // closes sv[0] itself
		reader.join();
		::close(sv[1]);
		return got;
	}
}

TEST(HttpReadBuf, OneBufferPerConnectionSlotIsAllocatedAtConstruction)
{
	SizedAllocGuard g(kBufBytes);
	HttpServer server("127.0.0.1", 0, nullptr);
	EXPECT_EQ(g.delta(), static_cast<size_t>(HttpServer::kMaxConcurrentConnections));
}

TEST(HttpReadBuf, ARequestDoesNotAllocateItsReadBuffer)
{
	HttpServer server("127.0.0.1", 0, nullptr);   // never start()ed
	serveOne(server, kNotFound);                  // warm-up: first-use statics are init, not per request
	SizedAllocGuard g(kBufBytes);
	for (int i = 0; i < 3; ++i)
	{
		const std::string resp = serveOne(server, kNotFound);
		ASSERT_EQ(resp.rfind("HTTP/1.1 404", 0), 0u) << resp.substr(0, 200);
	}
	EXPECT_EQ(g.delta(), 0u) << "three requests each took a 4096-byte read buffer";
}

TEST(HttpReadBuf, TheRequestIsReadIntoItsSlotsReservedBuffer)
{
	HttpServer server("127.0.0.1", 0, nullptr);
	for (int i = 0; i < HttpServer::kMaxConcurrentConnections; ++i)
	{
		ASSERT_NE(server.readBufForTest(i), nullptr) << "slot " << i;
		for (int j = 0; j < i; ++j) EXPECT_NE(server.readBufForTest(i), server.readBufForTest(j)) << "slots " << i << "," << j;
	}

	// Slot 0 is the one handleClientForTest() serves on. Each request lands at its
	// start, in the same block, with the rest zeroed (nothing of the previous one).
	const char* slot0 = server.readBufForTest(0);
	const std::string longer = "GET /no-such-route-at-all HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Pad: 0123456789\r\n\r\n";
	for (const std::string* req : {&longer, &kNotFound})
	{
		serveOne(server, *req);
		EXPECT_EQ(server.readBufForTest(0), slot0) << "the slot's buffer was replaced";
		EXPECT_EQ(std::memcmp(slot0, req->data(), req->size()), 0);
		EXPECT_EQ(std::count(slot0 + req->size(), slot0 + HttpServer::kReadBufBytes, '\0'),
		          static_cast<std::ptrdiff_t>(HttpServer::kReadBufBytes - req->size()));
	}
}

TEST(HttpReadBuf, AConnectionFromTheAcceptLoopReadsIntoOneSlotBuffer)
{
	// The wiring handleClientForTest() skips: acceptLoop() hands the handler thread
	// the buffer of the slot it claimed.
	HttpServer server("127.0.0.1", 0, nullptr);
	server.start();
	const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
	ASSERT_GE(fd, 0);
	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(static_cast<uint16_t>(server.port()));
	::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
	ASSERT_EQ(::connect(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)), 0);
	::send(fd, kNotFound.data(), kNotFound.size(), MSG_NOSIGNAL);
	std::string got;
	char buf[1024];
	for (ssize_t n; (n = ::recv(fd, buf, sizeof(buf), 0)) > 0;) got.append(buf, static_cast<size_t>(n));
	::close(fd);
	EXPECT_EQ(got.rfind("HTTP/1.1 404", 0), 0u) << got.substr(0, 200);

	for (int i = 0; i < 400 && server.activeConnectionsForTest() > 0; ++i)   // the handler thread, done
		std::this_thread::sleep_for(std::chrono::milliseconds(5));
	ASSERT_EQ(server.activeConnectionsForTest(), 0);
	int slotsHoldingIt = 0;
	for (int i = 0; i < HttpServer::kMaxConcurrentConnections; ++i)
		slotsHoldingIt += std::memcmp(server.readBufForTest(i), kNotFound.data(), kNotFound.size()) == 0;
	EXPECT_EQ(slotsHoldingIt, 1);
}

TEST(HttpReadBuf, ASlotWithNoBufferTakesAHeapBufferAndCountsAPsramFallback)
{
	struct RestoreCounter   // process-wide: other tests read it as 0 on the host
	{
		uint32_t v = psram::internalFallbacks().load();
		~RestoreCounter() { psram::internalFallbacks().store(v); }
	} restoreCounter;
	HttpServer server("127.0.0.1", 0, nullptr);
	server.dropReadBufForTest(0);                 // what a failed allocation at boot leaves
	ASSERT_NE(server.readBufForTest(1), nullptr);   // the other slots are untouched
	serveOne(server, kNotFound);                  // warm-up

	const uint32_t fallbacks = psram::internalFallbacks().load();
	SizedAllocGuard g(kBufBytes);
	const std::string resp = serveOne(server, kNotFound);
	EXPECT_EQ(resp.rfind("HTTP/1.1 404", 0), 0u) << resp.substr(0, 200);
	EXPECT_EQ(g.delta(), 1u) << "the fallback is one 4096-byte heap buffer for the request";
	EXPECT_EQ(psram::internalFallbacks().load() - fallbacks, 1u);
}

#endif
