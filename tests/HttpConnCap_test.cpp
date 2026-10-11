// HttpConnCap_test.cpp -- issues #410/#328: the HTTP server serves at most 3
// connections at once and at most 2 from one source address; the 4th concurrent
// request is answered 503 (the .244 bench: each connection costs a task stack, a
// TCB and a TCP send queue out of internal DRAM, and four were too many).
//
// The other cap tests (AdminHttpGate_test, HttpReadDeadline_test) are written in
// terms of the constants, so they follow a change of them. These pin the numbers
// themselves, and the behaviour at them, so a change back to 4 and 3 fails here.
// Servers use port 0 (#540); the holders connect from distinct loopback sources
// (127.0.0.N), each of which stays inside the per-source cap.

#include <gtest/gtest.h>

#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include "HttpServer.hpp"

#if !defined(_WIN32) && !defined(_WIN64)   // bind() to a chosen 127.0.0.N source: POSIX host only

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

namespace
{
	// Connects to the server from `srcIp` and says nothing: the handler sits in recv()
	// until its read deadline, so the slot is genuinely held. -1 if `srcIp` cannot be
	// used as a source address here.
	int connectFrom(const char* srcIp, int port)
	{
		const int s = ::socket(AF_INET, SOCK_STREAM, 0);
		if (s < 0) return -1;
		sockaddr_in src{};
		src.sin_family = AF_INET;
		::inet_pton(AF_INET, srcIp, &src.sin_addr);
		sockaddr_in dst{};
		dst.sin_family = AF_INET;
		dst.sin_port = htons(static_cast<uint16_t>(port));
		::inet_pton(AF_INET, "127.0.0.1", &dst.sin_addr);
		if (::bind(s, reinterpret_cast<sockaddr*>(&src), sizeof(src)) != 0 ||
		    ::connect(s, reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) != 0)
		{
			::close(s);
			return -1;
		}
		return s;
	}

	// One whole GET /api/status from `srcIp`, read to EOF (3 s at most).
	std::string getFrom(const char* srcIp, int port)
	{
		const int s = connectFrom(srcIp, port);
		if (s < 0) return "connect failed";
		timeval tv{};
		tv.tv_sec = 3;
		::setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
		const std::string req = "GET /api/status HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
		::send(s, req.data(), req.size(), MSG_NOSIGNAL);
		std::string got;
		char buf[2048];
		for (ssize_t n; (n = ::recv(s, buf, sizeof(buf), 0)) > 0;) got.append(buf, static_cast<size_t>(n));
		::close(s);
		return got;
	}

	bool waitActive(const HttpServer& server, int want)
	{
		for (int i = 0; i < 400; ++i)
		{
			if (server.activeConnectionsForTest() == want) return true;
			std::this_thread::sleep_for(std::chrono::milliseconds(5));
		}
		return false;
	}

	void closeAll(std::vector<int>& fds)
	{
		for (int s : fds) ::close(s);
		fds.clear();
	}
}

TEST(HttpConnCapPinned, TheCapsAreThreeConnectionsAndTwoPerSource)
{
	EXPECT_EQ(HttpServer::kMaxConcurrentConnections, 3);
	EXPECT_EQ(HttpServer::kMaxConnectionsPerSource, 2);
	EXPECT_LE(HttpServer::kStatusBufCount, HttpServer::kMaxConcurrentConnections);

	// Everything sized from the cap has a slot per connection: a read buffer each.
	HttpServer server("127.0.0.1", 0, nullptr);
	for (int i = 0; i < HttpServer::kMaxConcurrentConnections; ++i)
		EXPECT_NE(server.readBufForTest(i), nullptr) << "slot " << i;
}

TEST(HttpConnCapPinned, TheFourthConcurrentRequestIsAnswered503WhileThreeAreHeld)
{
	HttpServer server("127.0.0.1", 0, nullptr);
	server.setReadDeadlineMsForTest(3000);   // a stuck holder frees its slot soon, whatever happens
	server.start();

	// Three holders from three sources: three slots, none over a per-source share.
	std::vector<int> held;
	for (const char* src : {"127.0.0.2", "127.0.0.3", "127.0.0.4"})
	{
		const int s = connectFrom(src, server.port());
		if (s < 0)
		{
			closeAll(held);
			GTEST_SKIP() << "this stack can't use " << src << " as a source address";
		}
		held.push_back(s);
	}
	ASSERT_TRUE(waitActive(server, 3)) << "the accept loop took " << server.activeConnectionsForTest() << " of 3";

	const std::string fourth = getFrom("127.0.0.5", server.port());
	EXPECT_EQ(fourth.rfind("HTTP/1.1 503", 0), 0u) << fourth.substr(0, 200);
	EXPECT_NE(fourth.find("too many concurrent connections"), std::string::npos) << fourth.substr(0, 300);
	EXPECT_EQ(server.busyRefusalsForTest(), 1u) << "the accept loop counts its own 503s";

	// One holder lets go: the slot is free again, so the same request is served.
	::close(held.back());
	held.pop_back();
	ASSERT_TRUE(waitActive(server, 2));
	const std::string served = getFrom("127.0.0.5", server.port());
	EXPECT_EQ(served.rfind("HTTP/1.1 200", 0), 0u) << served.substr(0, 200);

	closeAll(held);
	ASSERT_TRUE(waitActive(server, 0));
}

TEST(HttpConnCapPinned, TheThirdConnectionFromOneAddressIsRefusedAndAnotherAddressIsStillServed)
{
	HttpServer server("127.0.0.1", 0, nullptr);
	server.setReadDeadlineMsForTest(3000);
	server.start();

	std::vector<int> held;
	for (int i = 0; i < 2; ++i)
	{
		const int s = connectFrom("127.0.0.2", server.port());
		if (s < 0)
		{
			closeAll(held);
			GTEST_SKIP() << "this stack can't use 127.0.0.2 as a source address";
		}
		held.push_back(s);
	}
	ASSERT_TRUE(waitActive(server, 2));

	const std::string third = getFrom("127.0.0.2", server.port());
	EXPECT_EQ(third.rfind("HTTP/1.1 503", 0), 0u) << third.substr(0, 200);
	EXPECT_NE(third.find("too many connections from this address"), std::string::npos) << third.substr(0, 300);
	EXPECT_EQ(server.perSourceRefusals(), 1u);

	// The one slot left is for everyone else.
	const std::string other = getFrom("127.0.0.3", server.port());
	EXPECT_EQ(other.rfind("HTTP/1.1 200", 0), 0u) << other.substr(0, 200);

	closeAll(held);
	ASSERT_TRUE(waitActive(server, 0));
}

#endif
