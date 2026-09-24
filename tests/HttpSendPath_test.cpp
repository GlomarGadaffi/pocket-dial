// HttpSendPath_test.cpp — issue #410 phase 2: every route's response goes out
// in place, not copied.
//
// sendResponseWithHeader() -- behind sendResponse(), i.e. every route -- used
// to build the head in an ostringstream, copy it and the whole body into a
// second one, then copy that again with str(): two full body copies plus the
// head per response, from internal DRAM for anything under the 16 KB
// SPIRAM_MALLOC_ALWAYSINTERNAL line (#328). It now formats only the two
// numbers into stack buffers and sends every other piece from where it lives,
// in one scatter-gather sendmsg(). Three things are pinned here:
//
//   1. WIRE IDENTITY: for a spread of statuses, content types, extra headers
//      and bodies (empty, binary with NULs, larger than the socket buffer), the
//      bytes are identical to buildResponseHead() + body -- the old path's own
//      head function, not a copy of it in the test.
//   2. SHORT WRITES: the resume step (consumeSent) is driven at every split
//      point of a multi-range response -- inside, at the start and at the end
//      of each range -- and must leave exactly the unsent remainder.
//      Mutation-checked: not trimming the range a write stopped inside fails it.
//   3. ZERO ALLOCATION: sending a response allocates nothing on the calling
//      thread (AllocGuard, tests/support/AllocCounter), including the literal
//      status/type/body shape every route uses -- the string_view parameters
//      build no temporaries. Mutation-checked: the old ostringstream code
//      fails this on the count.

#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "AllocCounter.hpp"
#include "HttpServer.hpp"

#if !defined(_WIN32) && !defined(_WIN64)   // socketpair(): POSIX host only

#include <sys/socket.h>
#include <unistd.h>

namespace
{
	struct Case
	{
		const char* name;
		int status;
		const char* statusText;
		const char* contentType;
		std::string body;
		const char* extraHeader;
	};

	std::string binaryBody(size_t n)
	{
		std::string s(n, '\0');
		for (size_t i = 0; i < n; ++i) s[i] = static_cast<char>((i * 131u + 7u) & 0xFF);
		return s;
	}

	std::vector<Case> cases()
	{
		return {
			{ "json 200",       200, "OK", "application/json", "{\"ok\":true}", "" },
			{ "error 400",      400, "Bad Request", "application/json", "{\"error\":\"missing field\"}", "" },
			{ "error 503",      503, "Service Unavailable", "application/json",
			                    "{\"error\":\"SIP engine not attached yet\"}", "" },
			{ "long status",    500, "Internal Server Error", "application/json", "{\"ok\":false}", "" },
			{ "redirect",       302, "Found", "text/plain", "", "Location: /" },
			{ "set-cookie",     200, "OK", "application/json", "{\"ok\":true}",
			                    "Set-Cookie: pd_session=abc; HttpOnly; Path=/; SameSite=Strict" },
			{ "pcap attach",    200, "OK", "application/vnd.tcpdump.pcap", binaryBody(4096),
			                    "Content-Disposition: attachment; filename=\"pocketdial.pcap\"" },
			{ "big body",       200, "OK", "application/xml", binaryBody(600 * 1024), "" },
		};
	}

	// Send one response on THIS thread into a socketpair, draining the other
	// end on a helper thread (bodies beyond the socket buffer would otherwise
	// deadlock).
	std::string sendAndCapture(HttpServer& server, const Case& c)
	{
		int sv[2];
		if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { ADD_FAILURE() << "socketpair"; return {}; }
		std::string got;
		std::thread reader([&] {
			char buf[4096];
			for (;;)
			{
				const ssize_t n = ::recv(sv[1], buf, sizeof(buf), 0);
				if (n <= 0) break;
				got.append(buf, static_cast<size_t>(n));
			}
		});
		server.sendResponseForTest(sv[0], c.status, c.statusText, c.contentType, c.body, c.extraHeader);
		::shutdown(sv[0], SHUT_WR);
		reader.join();
		::close(sv[0]);
		::close(sv[1]);
		return got;
	}

	std::string legacy(const Case& c)
	{
		return HttpServer::legacyResponseForTest(c.status, c.statusText, c.contentType, c.body, c.extraHeader);
	}

	class HttpSendPath : public ::testing::Test
	{
	protected:
		// Never start()ed: only the response sender is exercised, on this thread.
		HttpServer server{"127.0.0.1", 28411, nullptr};
	};
}

TEST_F(HttpSendPath, ResponsesAreByteIdenticalToTheOldPath)
{
	for (const Case& c : cases())
	{
		SCOPED_TRACE(c.name);
		const std::string want = legacy(c);
		const std::string got = sendAndCapture(server, c);
		ASSERT_EQ(got.size(), want.size());
		EXPECT_TRUE(got == want) << "first difference at byte "
			<< std::mismatch(got.begin(), got.end(), want.begin()).first - got.begin();
	}
}

TEST(HttpSendPathResume, ShortWritesResumeAtTheRightByteForEverySplit)
{
	// A socket will not produce short writes on demand (a blocking AF_UNIX
	// send times out per buffer wait, not per call), so the resume step is
	// driven directly: a simulated sendmsg() takes the first `k` bytes of what
	// is left -- or `k` and 1 alternately, so the cut lands at every offset
	// relative to every range boundary -- and consumeSent() must leave exactly
	// the unsent remainder. Ranges of 1, 2 and 13 bytes, plus a longer one,
	// so cuts fall inside, at the start and at the end of each.
	const std::string a = "HTTP/1.1 200 ", b = "OK", c = "\r", d = "\nContent-Type: text/plain\r\n", e = "b";
	const std::string all = a + b + c + d + e;
	for (size_t k = 1; k <= all.size(); ++k)
	{
		for (int alternate = 0; alternate < 2; ++alternate)
		{
			SCOPED_TRACE(::testing::Message() << "k=" << k << " alternate=" << alternate);
			HttpServer::SendPiece rest[5];
			const std::string* src[] = { &a, &b, &c, &d, &e };
			for (size_t i = 0; i < 5; ++i)
			{
				rest[i].iov_base = const_cast<char*>(src[i]->data());
				rest[i].iov_len = src[i]->size();
			}
			const size_t n = sizeof(rest) / sizeof(rest[0]);
			std::string out;
			size_t first = 0, calls = 0;
			while (first < n && calls++ < 4 * all.size())
			{
				// What one sendmsg() over rest[first..n) would put on the wire.
				size_t want = (alternate && (calls % 2 == 0)) ? 1 : k, sent = 0;
				for (size_t i = first; i < n && sent < want; ++i)
				{
					const size_t take = std::min(want - sent, static_cast<size_t>(rest[i].iov_len));
					out.append(static_cast<const char*>(rest[i].iov_base), take);
					sent += take;
				}
				first = HttpServer::consumeSent(rest, first, n, sent);
			}
			ASSERT_EQ(first, n) << "never finished";
			EXPECT_EQ(out, all);
		}
	}
}

TEST_F(HttpSendPath, SendingAResponseAllocatesNothing)
{
	// The receiving end drains on its own thread; AllocGuard counts only this
	// one, so the reader's buffer growth is not measured -- only the send.
	int sv[2];
	ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
	std::thread reader([&] {
		char buf[4096];
		while (::recv(sv[1], buf, sizeof(buf), 0) > 0) {}
	});
	const std::string jsonBody(3000, 'x');   // a typical /api/status-sized body, built outside the guard
	const std::string cookie = "Set-Cookie: pd_session=0123456789abcdef0123456789abcdef; HttpOnly; Path=/; SameSite=Strict";

	size_t literalAllocs, stringAllocs, headerAllocs;
	{
		// The shape almost every route uses: literals for all three, which as
		// const std::string& built a temporary each ("application/json" and most
		// error bodies are past the SSO limit).
		AllocGuard g;
		server.sendResponseForTest(sv[0], 503, "Service Unavailable", "application/json",
		                           "{\"error\":\"SIP engine not attached yet\"}", "");
		literalAllocs = g.delta();
	}
	{
		AllocGuard g;
		server.sendResponseForTest(sv[0], 200, "OK", "application/json", jsonBody, "");
		stringAllocs = g.delta();
	}
	{
		AllocGuard g;
		server.sendResponseForTest(sv[0], 200, "OK", "application/json", jsonBody, cookie);
		headerAllocs = g.delta();
	}
	::shutdown(sv[0], SHUT_WR);
	reader.join();
	::close(sv[0]);
	::close(sv[1]);

	EXPECT_EQ(literalAllocs, 0u) << "literal status/type/body";
	EXPECT_EQ(stringAllocs, 0u) << "3 KB std::string body";
	EXPECT_EQ(headerAllocs, 0u) << "with an extra header";
}

#endif
