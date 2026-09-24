// HttpStaticPages_test.cpp — issue #410 phase 1: the static HTML pages stream
// from flash instead of being copied.
//
// "/" (PD_HTML_0..7, ~116 KB), /setup/email (PD_HTML_8) and /setup/trunk
// (PD_HTML_9) used to be assembled into a std::string just to swap the CSRF
// marker for the session's token, then copied twice more by sendResponse. They
// now go out part by part via HttpServer::sendStaticHtml(). Three things are
// pinned here, and each would fail on its own kind of regression:
//
//   1. PRECONDITION: every page carries exactly ONE "__PD_CSRF__" marker. Both
//      the old find()/replace() and the streamer replace only the first; a
//      second marker would ship literally. A gate, not an assumption.
//   2. WIRE IDENTITY: for each page, anonymous and logged in, the streamed
//      response is byte-identical to what the old path produced -- the head
//      from buildResponseHead() itself (legacyHtmlHeadForTest), then the
//      assembled page with the first marker replaced. Also: Content-Length
//      equals the body actually sent, the token appears exactly once, and the
//      literal marker never does.
//   3. ZERO-COPY: serving a page allocates exactly as much as deriving its CSRF
//      token alone, on this thread (AllocGuard, tests/support/AllocCounter). The
//      token path still allocates small strings -- that is #410's request-side
//      phase -- but the page itself costs nothing. Mutation-checked: the old
//      assemble-and-copy code fails this on the count.

#include <gtest/gtest.h>

#include <string>
#include <string_view>
#include <thread>

#include "AdminAuth.hpp"
#include "AllocCounter.hpp"
#include "HttpServer.hpp"
#include "index_html.h"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <sys/socket.h>
#include <unistd.h>
#endif

#if !defined(_WIN32) && !defined(_WIN64)   // socketpair(): POSIX host only

namespace
{
	constexpr std::string_view kMarker = "__PD_CSRF__";

	struct Page { int id; const char* name; std::string (*assemble)(); };

	std::string assembleIndex()
	{
		std::string s;
		for (size_t i = 0; i < CGA_INDEX_HTML_PART_COUNT; ++i)
			s.append(CGA_INDEX_HTML_PARTS[i].data, CGA_INDEX_HTML_PARTS[i].size);
		return s;
	}
	std::string assembleEmail() { return std::string(PD_HTML_8, sizeof(PD_HTML_8) - 1); }
	std::string assembleTrunk() { return std::string(PD_HTML_9, sizeof(PD_HTML_9) - 1); }

	const Page kPages[] = {
		{ 0, "/",            &assembleIndex },
		{ 8, "/setup/email", &assembleEmail },
		{ 9, "/setup/trunk", &assembleTrunk },
	};

	size_t countOf(std::string_view hay, std::string_view needle)
	{
		if (needle.empty()) return 0;
		size_t n = 0;
		for (size_t p = hay.find(needle); p != std::string_view::npos; p = hay.find(needle, p + needle.size())) ++n;
		return n;
	}

	// Serve one page on THIS thread into a socketpair, draining the other end
	// on a helper thread (a ~116 KB page exceeds the socket buffer, so a
	// synchronous read-after-write would deadlock). Returns what hit the wire.
	std::string serveAndCapture(HttpServer& server, int page, const std::string& cookie)
	{
		int sv[2];
		if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { ADD_FAILURE() << "socketpair"; return {}; }
		std::string got;
		std::thread reader([&] {
			char buf[8192];
			for (;;)
			{
				const ssize_t n = ::recv(sv[1], buf, sizeof(buf), 0);
				if (n <= 0) break;
				got.append(buf, static_cast<size_t>(n));
			}
		});
		server.servePageForTest(sv[0], page, cookie);
		::shutdown(sv[0], SHUT_WR);
		reader.join();
		::close(sv[0]);
		::close(sv[1]);
		return got;
	}

	// A real session, so the token is non-empty (an anonymous load substitutes
	// "" and would let a broken substitution pass unnoticed).
	std::string loggedInCookie()
	{
		EXPECT_TRUE(AdminAuth::setLoginCredential("admin", "realpassword123"));
		return "pd_session=" + AdminAuth::createSession();
	}

	class HttpStaticPages : public ::testing::Test
	{
	protected:
		void SetUp() override { AdminAuth::clearCredential(); }
		void TearDown() override { AdminAuth::clearCredential(); }
		// Never start()ed: only the per-page senders are exercised, on this thread.
		HttpServer server{"127.0.0.1", 28410, nullptr};
	};
}

TEST(HttpStaticPagesPrecondition, EveryPageCarriesExactlyOneCsrfMarker)
{
	for (const Page& p : kPages)
	{
		EXPECT_EQ(countOf(p.assemble(), kMarker), 1u)
			<< p.name << ": the streamer (like the old find/replace) substitutes only the "
			   "first marker, so a page needs exactly one";
	}
	// Per part for "/": the marker must sit whole inside ONE part. That is NOT
	// structural -- index_html.h's parts may be re-split at any byte -- so this
	// check is what enforces it. A straddled marker counts 1 assembled but 0 per
	// part, and the streamer would then send it literally.
	size_t perPart = 0;
	for (size_t i = 0; i < CGA_INDEX_HTML_PART_COUNT; ++i)
		perPart += countOf(std::string_view(CGA_INDEX_HTML_PARTS[i].data, CGA_INDEX_HTML_PARTS[i].size), kMarker);
	EXPECT_EQ(perPart, 1u) << "the marker must sit whole inside one PD_HTML part";
}

TEST_F(HttpStaticPages, StreamedPagesAreByteIdenticalToTheOldPath)
{
	for (const bool loggedIn : { false, true })
	{
		const std::string cookie = loggedIn ? loggedInCookie() : std::string();
		const std::string token  = server.csrfForTest(cookie);
		if (loggedIn) ASSERT_FALSE(token.empty()) << "a logged-in load must carry a real token";

		for (const Page& p : kPages)
		{
			std::string body = p.assemble();
			const size_t at = body.find(kMarker);
			ASSERT_NE(at, std::string::npos) << p.name;
			body.replace(at, kMarker.size(), token);
			const std::string expected = HttpServer::legacyHtmlHeadForTest(body.size()) + body;

			const std::string got = serveAndCapture(server, p.id, cookie);
			SCOPED_TRACE(std::string(p.name) + (loggedIn ? " (logged in)" : " (anonymous)"));
			EXPECT_EQ(got.size(), expected.size());
			EXPECT_TRUE(got == expected) << "streamed response differs from the old path's bytes";

			const size_t sep = got.find("\r\n\r\n");
			ASSERT_NE(sep, std::string::npos);
			const std::string_view sentBody = std::string_view(got).substr(sep + 4);
			EXPECT_NE(got.find("Content-Length: " + std::to_string(sentBody.size()) + "\r\n"), std::string::npos)
				<< "Content-Length must equal the body actually sent";
			EXPECT_EQ(countOf(sentBody, kMarker), 0u) << "a literal marker reached the client";
			if (loggedIn) EXPECT_EQ(countOf(sentBody, token), 1u) << "the token must appear exactly once";
		}
		if (loggedIn) AdminAuth::clearCredential();
	}
}

TEST_F(HttpStaticPages, ServingAPageAllocatesNothingBeyondItsToken)
{
	const std::string cookie = loggedInCookie();

	for (const Page& p : kPages)
	{
		// Warm-up: first-use allocations (session tables, iostream state) are not
		// the page's cost and must not skew the comparison.
		serveAndCapture(server, p.id, cookie);

		int sv[2];
		ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv), 0);
		std::thread reader([&] { char b[8192]; while (::recv(sv[1], b, sizeof(b), 0) > 0) {} });

		AllocGuard pageGuard;
		server.servePageForTest(sv[0], p.id, cookie);
		const size_t pageAllocs = pageGuard.delta();

		AllocGuard tokenGuard;
		volatile size_t keep = server.csrfForTest(cookie).size();   // escapes: see AllocCounter.hpp
		(void)keep;
		const size_t tokenAllocs = tokenGuard.delta();

		::shutdown(sv[0], SHUT_WR);
		reader.join();
		::close(sv[0]);
		::close(sv[1]);

		EXPECT_GT(tokenAllocs, 0u) << p.name << ": sanity -- deriving a real session's token allocates today";
		EXPECT_EQ(pageAllocs, tokenAllocs)
			<< p.name << ": serving the page allocated " << pageAllocs << " times, deriving its token alone "
			<< tokenAllocs << " -- the difference is the page being copied";
	}
}

#endif   // POSIX host
