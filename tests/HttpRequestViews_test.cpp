// HttpRequestViews_test.cpp -- issue #1048 item 2: the shared HTTP request path
// (read, parse, same-origin check, session/CSRF check) works on views over the
// connection's read buffer and allocates nothing.
//
// Views are easy to get subtly wrong on the authentication path, so this file
// pins what a copy-based parser did and a view-based one must keep doing:
// padded and mixed-case header names, Cookie pairs in either order, the
// refusals (401 / 403), an over-long header line, and the byte-exact /api/cdr
// body. Every refusal is paired with a request that is accepted, so a server
// that refused everything would not pass.

#include <gtest/gtest.h>

#include <cstdio>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "AdminAuth.hpp"
#include "AllocCounter.hpp"
#include "DeviceConfig.hpp"
#include "HttpServer.hpp"
#include "OtaUpdater.hpp"
#include "RequestsHandler.hpp"

#if !defined(_WIN32) && !defined(_WIN64)   // socketpair(): POSIX host only

#include <sys/socket.h>
#include <unistd.h>

namespace
{
	// The pre-#1048 /api/cdr serializer, kept verbatim as the reference the
	// in-place writer must match byte for byte.
	std::string refJsonEscape(const std::string& s)
	{
		static const char* hex = "0123456789abcdef";
		std::string out;
		for (unsigned char c : s)
		{
			switch (c)
			{
				case '"':  out += "\\\""; break;
				case '\\': out += "\\\\"; break;
				case '\n': out += "\\n";  break;
				case '\r': out += "\\r";  break;
				case '\t': out += "\\t";  break;
				default:
					if (c < 0x20)
					{
						out += "\\u00";
						out += hex[(c >> 4) & 0x0F];
						out += hex[c & 0x0F];
					}
					else
					{
						out += static_cast<char>(c);
					}
			}
		}
		return out;
	}

	std::string refCdrJson(const std::vector<CallDetailRecord>& records, uint64_t nowMs)
	{
		std::ostringstream json;
		json << "[";
		for (size_t i = 0; i < records.size(); i++)
		{
			if (i > 0) json << ",";
			const CallDetailRecord& r = records[i];
			uint64_t ageSec = (nowMs >= r.startMs) ? (nowMs - r.startMs) / 1000 : 0;
			json << "{\"caller\":\"" << refJsonEscape(r.caller) << "\","
			     << "\"callee\":\"" << refJsonEscape(r.callee) << "\","
			     << "\"startMs\":" << r.startMs << ","
			     << "\"ageSec\":" << ageSec << ","
			     << "\"duration\":" << r.durationSec << ","
			     << "\"result\":\"" << cdrResultToString(r.result) << "\"}";
		}
		json << "]";
		return json.str();
	}

	struct Bench
	{
		std::unique_ptr<RequestsHandler> handler;
		HttpServer server{"127.0.0.1", 0, nullptr};   // never start()ed
		std::string token;
		std::string csrf;

		Bench()
		{
			handler = std::make_unique<RequestsHandler>("10.0.0.1", 5060,
				[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
			server.attachHandler(handler.get());
			AdminAuth::clearCredential();
			EXPECT_TRUE(AdminAuth::setLoginCredential("admin", "gatepassword123"));
			token = AdminAuth::createSession(AdminAuth::Role::Owner);
			csrf = AdminAuth::sessionCsrf(token);
		}
		~Bench() { AdminAuth::clearCredential(); }

		// Serves `raw` byte for byte. Returns the response; `wholeAllocs`, when
		// given, receives this thread's allocation count over the whole of
		// handleClient() -- request read and parse included.
		std::string serve(const std::string& raw, long* wholeAllocs = nullptr)
		{
			int sv[2];
			if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { ADD_FAILURE() << "socketpair"; return ""; }
			::send(sv[1], raw.data(), raw.size(), MSG_NOSIGNAL);
			::shutdown(sv[1], SHUT_WR);
			std::string got;
			std::thread reader([&] {
				char buf[4096];
				for (ssize_t n; (n = ::recv(sv[1], buf, sizeof(buf), 0)) > 0;) got.append(buf, static_cast<size_t>(n));
			});
			const std::size_t before = threadHeapAllocCount();
			server.handleClientForTest(sv[0]);   // closes sv[0] itself
			const std::size_t after = threadHeapAllocCount();
			reader.join();
			::close(sv[1]);
			if (wholeAllocs) *wholeAllocs = static_cast<long>(after - before);
			return got;
		}

		// A request with the given header block; every header is the caller's text.
		static std::string request(const std::string& method, const std::string& path,
			const std::string& headers, const std::string& body = "")
		{
			std::string r = method + " " + path + " HTTP/1.1\r\n" + headers;
			if (!body.empty())
				r += "Content-Length: " + std::to_string(body.size()) + "\r\n";
			return r + "\r\n" + body;
		}

		std::string goodHeaders() const
		{
			return "Host: 127.0.0.1\r\nOrigin: http://127.0.0.1\r\nCookie: pd_session=" + token +
			       "\r\nX-CSRF: " + csrf + "\r\n";
		}
	};

	int statusOf(const std::string& resp)
	{
		if (resp.size() < 12 || resp.compare(0, 9, "HTTP/1.1 ") != 0) return -1;
		return std::atoi(resp.c_str() + 9);
	}

	std::string bodyOf(const std::string& resp)
	{
		const size_t at = resp.find("\r\n\r\n");
		return at == std::string::npos ? std::string() : resp.substr(at + 4);
	}
}

TEST(HttpRequestViews, PaddedAndMixedCaseHeadersStillAuthenticate)
{
	Bench b;
	// Positive control: the plain request is admitted, so the padded one below
	// can only differ by how its headers were read.
	const std::string plainGet = Bench::request("GET", "/api/cdr", b.goodHeaders());
	ASSERT_EQ(statusOf(b.serve(plainGet)), 200);
	const std::string plainPost = Bench::request("POST", "/api/media-tx", b.goodHeaders(), "nodelay=0");
	ASSERT_EQ(statusOf(b.serve(plainPost)), 200);

	// Mixed-case names, spaces before the colon, and leading/trailing blanks on every value.
	const std::string padded =
		"hOsT :   127.0.0.1   \r\n"
		"ORIGIN:\t http://127.0.0.1 \t\r\n"
		"cOOkIe:   pd_session=" + b.token + "   \r\n"
		"x-CsRf:    " + b.csrf + "  \r\n"
		"User-AGENT:  probe/1.0  \r\n";
	EXPECT_EQ(statusOf(b.serve(Bench::request("GET", "/api/cdr", padded))), 200);
	EXPECT_EQ(statusOf(b.serve(Bench::request("POST", "/api/media-tx", padded, "nodelay=0"))), 200);
	// A query string is cut from the path before routing.
	EXPECT_EQ(statusOf(b.serve(Bench::request("GET", "/api/cdr?x=1", padded))), 200);

	// The same padding does not turn a bad token into a good one.
	const std::string badToken =
		"HOST:  127.0.0.1 \r\nCOOKIE:  pd_session=" + std::string(b.token.size(), '0') + "  \r\n";
	EXPECT_EQ(statusOf(b.serve(Bench::request("GET", "/api/cdr", badToken))), 401);
}

TEST(HttpRequestViews, PdSessionIsFoundFirstOrSecondInTheCookieHeader)
{
	Bench b;
	const std::string host = "Host: 127.0.0.1\r\n";
	const std::string sess = "pd_session=" + b.token;
	auto get = [&](const std::string& cookie) {
		return statusOf(b.serve(Bench::request("GET", "/api/cdr", host + "Cookie: " + cookie + "\r\n")));
	};
	EXPECT_EQ(get(sess), 200);
	EXPECT_EQ(get(sess + "; theme=dark"), 200);
	EXPECT_EQ(get("theme=dark; " + sess), 200);
	EXPECT_EQ(get("a=1; " + sess + "; b=2"), 200);
	EXPECT_EQ(get("theme=dark;" + sess), 200);
	// Negative controls: a name that merely ends in pd_session, a wrong value,
	// and no cookie at all are all refused.
	EXPECT_EQ(get("xpd_session=" + b.token + "; theme=dark"), 401);
	EXPECT_EQ(get("theme=dark; pd_session=" + std::string(b.token.size(), 'f')), 401);
	EXPECT_EQ(get("theme=dark"), 401);
	EXPECT_EQ(statusOf(b.serve(Bench::request("GET", "/api/cdr", host))), 401);
}

TEST(HttpRequestViews, CsrfAndOriginRefusalsAreUnchanged)
{
	Bench b;
	const std::string post = "nodelay=0";
	auto send = [&](const std::string& hdrs) {
		return statusOf(b.serve(Bench::request("POST", "/api/media-tx", hdrs, post)));
	};
	const std::string cookie = "Cookie: pd_session=" + b.token + "\r\n";
	// Admitted.
	ASSERT_EQ(send("Host: 127.0.0.1\r\nOrigin: http://127.0.0.1\r\n" + cookie + "X-CSRF: " + b.csrf + "\r\n"), 200);
	// Wrong, truncated, extended and missing CSRF tokens: 403.
	EXPECT_EQ(send("Host: 127.0.0.1\r\n" + cookie + "X-CSRF: " + std::string(b.csrf.size(), '0') + "\r\n"), 403);
	EXPECT_EQ(send("Host: 127.0.0.1\r\n" + cookie + "X-CSRF: " + b.csrf.substr(1) + "\r\n"), 403);
	EXPECT_EQ(send("Host: 127.0.0.1\r\n" + cookie + "X-CSRF: " + b.csrf + "0\r\n"), 403);
	EXPECT_EQ(send("Host: 127.0.0.1\r\n" + cookie), 403);
	// Cross-origin: a foreign Origin, a foreign port when both carry one, and an
	// Origin whose host is not ours.
	const std::string csrfHdr = "X-CSRF: " + b.csrf + "\r\n";
	EXPECT_EQ(send("Host: 127.0.0.1\r\nOrigin: http://evil.example\r\n" + cookie + csrfHdr), 403);
	EXPECT_EQ(send("Host: 127.0.0.1:80\r\nOrigin: http://127.0.0.1:8080\r\n" + cookie + csrfHdr), 403);
	EXPECT_EQ(send("Host: evil.example\r\nOrigin: http://evil.example\r\n" + cookie + csrfHdr), 403);
	// Same host, same explicit port; and a port on only one side: admitted.
	EXPECT_EQ(send("Host: 127.0.0.1:80\r\nOrigin: http://127.0.0.1:80\r\n" + cookie + csrfHdr), 200);
	EXPECT_EQ(send("Host: localhost\r\nOrigin: http://localhost:80\r\n" + cookie + csrfHdr), 200);
	// The refusal body is the same JSON as ever.
	const std::string refused = b.serve(Bench::request("POST", "/api/media-tx",
		"Host: 127.0.0.1\r\nOrigin: http://evil.example\r\n" + cookie + csrfHdr, post));
	EXPECT_EQ(bodyOf(refused), "{\"error\":\"cross-origin request rejected\"}");
}

TEST(HttpRequestViews, AnOverLongHeaderLineIsHandledAsBefore)
{
	Bench b;
	// A 3000-byte header of no interest, then the credentials: all inside the 4 KB read.
	const std::string fits = "X-Pad: " + std::string(3000, 'a') + "\r\n";
	EXPECT_EQ(statusOf(b.serve(Bench::request("GET", "/api/cdr", fits + b.goodHeaders()))), 200);
	// The same, then a long Cookie line that is itself cut off by the read size:
	// the unterminated line is not a header, so the caller is unauthenticated.
	const std::string cutCookie = "Host: 127.0.0.1\r\nCookie: " + std::string(5000, 'b') + "\r\n";
	EXPECT_EQ(statusOf(b.serve(Bench::request("GET", "/api/cdr", cutCookie))), 401);
	// Credentials that sit past the end of what one read returns are never seen.
	const std::string pastTheEnd = "X-Pad: " + std::string(5000, 'a') + "\r\n" + b.goodHeaders();
	EXPECT_EQ(statusOf(b.serve(Bench::request("GET", "/api/cdr", pastTheEnd))), 401);
	// And the server is still serving afterwards.
	EXPECT_EQ(statusOf(b.serve(Bench::request("GET", "/api/cdr", b.goodHeaders()))), 200);
}

TEST(HttpRequestViews, ACdrBodyIsByteIdenticalToTheOldSerializer)
{
	Bench b;
	b.handler->recordCallForTest("1001", "1002");
	b.handler->recordCallForTest("quote\"back\\slash", "tab\tnl\ncr\rctl\x01" "end");
	b.handler->recordCallForTest("1003", "voicemail");
	b.handler->forceNextTickForTest();
	b.handler->tick();   // publishes the CDR view /api/cdr reads
	const std::vector<CallDetailRecord> snap = b.handler->getCallDetailRecords();
	ASSERT_EQ(snap.size(), 3u);

	const std::string resp = b.serve(Bench::request("GET", "/api/cdr", b.goodHeaders()));
	ASSERT_EQ(statusOf(resp), 200);
	// Calls recorded a moment ago are 0 s old; startMs/duration/result come from the ring.
	const std::string expected = refCdrJson(snap, snap.front().startMs);
	EXPECT_EQ(bodyOf(resp), expected);
	// The reference is not empty and carries the awkward characters, escaped.
	EXPECT_NE(expected.find("quote\\\"back\\\\slash"), std::string::npos);
	EXPECT_NE(expected.find("\\u0001"), std::string::npos);
	EXPECT_NE(resp.find("Content-Length: " + std::to_string(expected.size()) + "\r\n"), std::string::npos);
	EXPECT_NE(resp.find("Content-Type: application/json\r\n"), std::string::npos);
}

TEST(HttpRequestViews, AnEmptyCdrRingIsAnEmptyArray)
{
	Bench b;
	b.handler->forceNextTickForTest();
	b.handler->tick();
	const std::string resp = b.serve(Bench::request("GET", "/api/cdr", b.goodHeaders()));
	EXPECT_EQ(statusOf(resp), 200);
	EXPECT_EQ(bodyOf(resp), "[]");
	EXPECT_NE(resp.find("Content-Length: 2\r\n"), std::string::npos);
}

TEST(HttpRequestViews, TheDashboardPollsAllocateNothingAcrossTheWholeRequest)
{
	Bench b;
	const std::string hdrs = b.goodHeaders();
	// Positive control: the same counter sees a route that does allocate.
	{
		const std::string req = Bench::request("GET", "/api/telephony-config", hdrs);
		b.serve(req);   // warm-up: first-use statics
		long allocs = 0;
		ASSERT_EQ(statusOf(b.serve(req, &allocs)), 200);
		EXPECT_GT(allocs, 0) << "the counter must see a route that allocates";
	}
	for (const char* path : {"/api/status", "/api/cdr", "/api/trace", "/api/admin/status", "/api/ota/status"})
	{
		SCOPED_TRACE(path);
		const std::string req = Bench::request("GET", path, hdrs);
		b.serve(req);   // warm-up
		long allocs = -1;
		const std::string resp = b.serve(req, &allocs);
		EXPECT_EQ(statusOf(resp), 200) << resp.substr(0, 200);
		EXPECT_EQ(allocs, 0) << "read + parse + auth + route allocated";
	}
	// A request with every header the parser keeps, padded, still allocates nothing.
	const std::string all = "Host: 127.0.0.1\r\nOrigin: http://127.0.0.1\r\nUser-Agent: some-browser/1.0 (a long enough agent string)\r\n"
		"Cookie: theme=dark-and-long; pd_session=" + b.token + "; other=value-value\r\nX-CSRF: " + b.csrf + "\r\n";
	const std::string req = Bench::request("GET", "/api/cdr", all);
	b.serve(req);
	long allocs = -1;
	EXPECT_EQ(statusOf(b.serve(req, &allocs)), 200);
	EXPECT_EQ(allocs, 0);
}

TEST(HttpRequestViews, ARefusedRequestAllocatesNothingEither)
{
	Bench b;
	const std::string noSession = Bench::request("GET", "/api/cdr", "Host: 127.0.0.1\r\n");
	const std::string crossOrigin = Bench::request("GET", "/api/cdr", "Host: 127.0.0.1\r\nOrigin: http://evil.example\r\n" +
		std::string("Cookie: pd_session=") + b.token + "\r\n");
	for (const std::string* req : {&noSession, &crossOrigin})
	{
		b.serve(*req);
		long allocs = -1;
		const std::string resp = b.serve(*req, &allocs);
		EXPECT_TRUE(statusOf(resp) == 401 || statusOf(resp) == 403) << resp.substr(0, 40);
		EXPECT_EQ(allocs, 0);
	}
}

TEST(HttpRequestViews, ABodyThatNeedsASecondReadKeepsTheEarlierHeaders)
{
	Bench b;
	// The first recv fills the 4 KB buffer, so the rest of the body is read into
	// the same buffer afterwards. The views taken from the headers must not be
	// read from the overwritten bytes: the session, CSRF token and origin are
	// still those of the first segment.
	const std::string body = "nodelay=0&pad=" + std::string(7000, 'a');
	const std::string good = Bench::request("POST", "/api/media-tx", b.goodHeaders(), body);
	ASSERT_GT(good.size(), 4096u);
	EXPECT_EQ(statusOf(b.serve(good)), 200);
	// Negative controls on the same large body: a wrong CSRF and a foreign origin.
	const std::string cookie = "Cookie: pd_session=" + b.token + "\r\n";
	EXPECT_EQ(statusOf(b.serve(Bench::request("POST", "/api/media-tx",
		"Host: 127.0.0.1\r\n" + cookie + "X-CSRF: " + std::string(b.csrf.size(), '0') + "\r\n", body))), 403);
	EXPECT_EQ(statusOf(b.serve(Bench::request("POST", "/api/media-tx",
		"Host: 127.0.0.1\r\nOrigin: http://evil.example\r\n" + cookie + "X-CSRF: " + b.csrf + "\r\n", body))), 403);
}

TEST(HttpRequestViews, LookalikeCookieNamesAndValuesAreRefused)
{
	Bench b;
	const std::string host = "Host: 127.0.0.1\r\n";
	auto get = [&](const std::string& cookie) {
		return statusOf(b.serve(Bench::request("GET", "/api/cdr", host + "Cookie: " + cookie + "\r\n")));
	};
	ASSERT_EQ(get("pd_session=" + b.token), 200);   // positive control
	EXPECT_EQ(get("pd_session2=" + b.token), 401);
	EXPECT_EQ(get("Pd_Session=" + b.token), 401);
	EXPECT_EQ(get("pd_session="), 401);
	EXPECT_EQ(get("pd_session=; theme=" + b.token), 401);
	EXPECT_EQ(get("pd_session=" + b.token.substr(0, b.token.size() - 1)), 401);   // prefix
	EXPECT_EQ(get("pd_session=" + b.token + "0"), 401);                            // extended
	// The first of two pd_session cookies is the one used, as before.
	EXPECT_EQ(get("pd_session=" + std::string(b.token.size(), '0') + "; pd_session=" + b.token), 401);
	EXPECT_EQ(get("pd_session=" + b.token + "; pd_session=" + std::string(b.token.size(), '0')), 200);
}

TEST(HttpRequestViews, CsrfIsMatchedExactlyAndOriginHostIsNotAPrefixMatch)
{
	Bench b;
	const std::string cookie = "Cookie: pd_session=" + b.token + "\r\n";
	auto send = [&](const std::string& hdrs) {
		return statusOf(b.serve(Bench::request("POST", "/api/media-tx", hdrs, "nodelay=0")));
	};
	ASSERT_EQ(send("Host: 127.0.0.1\r\n" + cookie + "X-CSRF: " + b.csrf + "\r\n"), 200);
	EXPECT_EQ(send("Host: 127.0.0.1\r\n" + cookie + "X-CSRF:\r\n"), 403);                         // empty
	EXPECT_EQ(send("Host: 127.0.0.1\r\n" + cookie + "X-CSRF: " + b.csrf.substr(0, b.csrf.size() - 1) + "\r\n"), 403);
	EXPECT_EQ(send("Host: 127.0.0.1\r\n" + cookie + "X-CSRF: " + std::string(600, 'a') + "\r\n"), 403);   // over-long
	EXPECT_EQ(send("Host: 127.0.0.1\r\n" + cookie + "X-CSRF: " + b.csrf + " junk\r\n"), 403);
	// Duplicate CSRF header: the last one wins, as before.
	EXPECT_EQ(send("Host: 127.0.0.1\r\n" + cookie + "X-CSRF: " + b.csrf + "\r\nX-CSRF: bad\r\n"), 403);
	EXPECT_EQ(send("Host: 127.0.0.1\r\n" + cookie + "X-CSRF: bad\r\nX-CSRF: " + b.csrf + "\r\n"), 200);
	// Origin host that merely starts with ours, and a Host that merely starts with ours.
	EXPECT_EQ(send("Host: 127.0.0.1\r\nOrigin: http://127.0.0.1.evil.example\r\n" + cookie + "X-CSRF: " + b.csrf + "\r\n"), 403);
	EXPECT_EQ(send("Host: 127.0.0.10\r\nOrigin: http://127.0.0.10\r\n" + cookie + "X-CSRF: " + b.csrf + "\r\n"), 403);
}

TEST(HttpRequestViews, AdminAndOtaStatusBodiesAreByteIdenticalToTheOldSerializers)
{
	Bench b;
	// /api/ota/status, as the old ostringstream wrote it.
	const std::string ota = std::string("{\"running\":\"") + OtaUpdater::runningPartitionLabel() +
		"\",\"runningPartition\":\"" + OtaUpdater::runningPartitionLabel() +
		"\",\"inProgress\":" + (OtaUpdater::isUpdateInProgress() ? "true" : "false") +
		",\"boot\":\"" + OtaUpdater::bootPartitionLabel() +
		"\",\"next\":\"" + OtaUpdater::nextUpdatePartitionLabel() +
		"\",\"pendingVerify\":" + (OtaUpdater::isPendingVerify() ? "true" : "false") +
		",\"otaSupported\":false,\"error\":\"\"}";
	const std::string otaResp = b.serve(Bench::request("GET", "/api/ota/status", b.goodHeaders()));
	ASSERT_EQ(statusOf(otaResp), 200);
	EXPECT_EQ(bodyOf(otaResp), ota);
	EXPECT_NE(otaResp.find("Content-Length: " + std::to_string(ota.size()) + "\r\n"), std::string::npos);

	// /api/admin/status, unauthenticated: every field is fixed.
	const std::string owner = AdminAuth::isOwnerProvisioned() ? "true" : "false";
	const std::string anon = b.serve(Bench::request("GET", "/api/admin/status", "Host: 127.0.0.1\r\n"));
	ASSERT_EQ(statusOf(anon), 200);
	EXPECT_EQ(bodyOf(anon), "{\"provisioned\":true,\"needsSetup\":false,\"authenticated\":false,\"role\":\"\","
		"\"ownerProvisioned\":" + owner + ",\"sessionRemainingSec\":0}");

	// Authenticated as owner: the same shape, the remaining seconds a number.
	const std::string authed = bodyOf(b.serve(Bench::request("GET", "/api/admin/status", b.goodHeaders())));
	const std::string head = "{\"provisioned\":true,\"needsSetup\":false,\"authenticated\":true,\"role\":\"owner\","
		"\"ownerProvisioned\":" + owner + ",\"sessionRemainingSec\":";
	ASSERT_EQ(authed.compare(0, head.size(), head), 0) << authed;
	ASSERT_GT(authed.size(), head.size() + 1);
	EXPECT_EQ(authed.back(), '}');
	for (size_t i = head.size(); i + 1 < authed.size(); ++i)
		EXPECT_TRUE(authed[i] >= '0' && authed[i] <= '9') << authed;
}

#endif
