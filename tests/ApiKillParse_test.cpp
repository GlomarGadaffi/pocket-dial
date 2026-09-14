// ApiKillParse_test.cpp — issue #191: POST /api/kill's body parse.
//
// The parser under test (getFormParam, src/Helpers/HttpServer.cpp) is file-static,
// so it cannot be called from this translation unit. It does not need to be: the
// endpoint echoes the value it parsed back as {"status":"ok","disconnected":"..."},
// which makes the parse observable end-to-end over a real socket — the same
// real-socket-through-HttpServer style as AdminHttpGate_test.cpp and
// TelephonyConfigHttp_test.cpp. That is also the level the bug actually bit at:
// the defect was never "getFormParam is wrong", it was "this endpoint didn't use
// it", and only a test that drives the route can tell those apart.
//
// Pins the three defects the hand-rolled parse had, each of which produced a 200
// naming an extension that could match no registered client:
//   - a key that merely ENDS in "extension" ("myextension=999") being accepted as
//     "extension" (the same boundary bug that once silently inverted DND),
//   - the value running past '&' to the end of the body ("101&reason=test"),
//   - no URL-decoding, so a percent-encoded extension was compared literally.
//
// No RequestsHandler is attached: sendApiKill skips forceDisconnect() when the
// handler is null and still echoes the parsed extension, so the parse is
// exercised without pulling in the SIP engine or its host-file stores.

#include <gtest/gtest.h>
#include "HttpServer.hpp"
#include "AdminAuth.hpp"

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

#include <chrono>
#include <cstdlib>
#include <memory>
#include <string>
#include <thread>

namespace
{
	// Minimal blocking HTTP request over a raw socket. Duplicated from
	// TelephonyConfigHttp_test.cpp rather than shared because anonymous-namespace
	// helpers don't cross translation units (same note that file carries).
	std::string httpRaw(int port, const std::string& method, const std::string& path,
	                    const std::string& body, const std::string& cookie = "",
	                    const std::string& csrf = "")
	{
#if defined(_WIN32) || defined(_WIN64)
		SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
		if (s == INVALID_SOCKET) return "";
#else
		int s = socket(AF_INET, SOCK_STREAM, 0);
		if (s < 0) return "";
#endif
		sockaddr_in addr{};
		addr.sin_family = AF_INET;
		addr.sin_port = htons(static_cast<uint16_t>(port));
		inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
		if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
		{
#if defined(_WIN32) || defined(_WIN64)
			closesocket(s);
#else
			close(s);
#endif
			return "";
		}
		std::string cookieHeader = cookie.empty() ? "" : ("Cookie: " + cookie + "\r\n");
		std::string csrfHeader   = csrf.empty()   ? "" : ("X-CSRF: " + csrf + "\r\n");
		std::string req = method + " " + path + " HTTP/1.1\r\n"
			"Host: 127.0.0.1\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n"
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			cookieHeader + csrfHeader +
			"Connection: close\r\n\r\n" + body;
		send(s, req.c_str(), static_cast<int>(req.size()), 0);
		std::string resp;
		char buf[512];
		int n;
		while ((n = recv(s, buf, sizeof(buf), 0)) > 0)
		{
			resp.append(buf, static_cast<size_t>(n));
		}
#if defined(_WIN32) || defined(_WIN64)
		closesocket(s);
#else
		close(s);
#endif
		return resp;
	}

	int statusOf(const std::string& resp)
	{
		size_t sp1 = resp.find(' ');
		if (sp1 == std::string::npos) return -1;
		size_t sp2 = resp.find(' ', sp1 + 1);
		if (sp2 == std::string::npos) return -1;
		return std::atoi(resp.substr(sp1 + 1, sp2 - sp1 - 1).c_str());
	}

	std::string bodyOf(const std::string& resp)
	{
		size_t sep = resp.find("\r\n\r\n");
		return sep == std::string::npos ? "" : resp.substr(sep + 4);
	}

	std::string cookieOf(const std::string& resp, const std::string& name)
	{
		std::string marker = "Set-Cookie: " + name + "=";
		size_t pos = resp.find(marker);
		if (pos == std::string::npos) return "";
		size_t start = pos + marker.size();
		size_t end = resp.find(';', start);
		if (end == std::string::npos) end = resp.find("\r\n", start);
		if (end == std::string::npos) return "";
		return resp.substr(start, end - start);
	}

	std::string csrfOf(const std::string& resp)
	{
		const std::string marker = "\"csrf\":\"";
		size_t pos = resp.find(marker);
		if (pos == std::string::npos) return "";
		size_t start = pos + marker.size();
		size_t end = resp.find('"', start);
		if (end == std::string::npos) return "";
		return resp.substr(start, end - start);
	}

	struct AdminSession { std::string cookie; std::string csrf; };

	// Logs in with the shipped default credential, then completes initial setup
	// with a real one -- requireAdmin() refuses every admin-gated route except
	// /api/admin/set-credential while needsInitialSetup() is true, and
	// setLoginCredential() does not invalidate the session it was called through.
	AdminSession loginOn(int port)
	{
		AdminSession a;
		std::string loginResp = httpRaw(port, "POST", "/api/admin/login",
			"username=admin&password=admin");
		EXPECT_EQ(statusOf(loginResp), 200);
		a.cookie = cookieOf(loginResp, "pd_session");
		a.csrf   = csrfOf(loginResp);

		std::string setupResp = httpRaw(port, "POST", "/api/admin/set-credential",
			"username=admin&password=realpassword123", "pd_session=" + a.cookie, a.csrf);
		EXPECT_EQ(statusOf(setupResp), 200);
		return a;
	}

	// One HttpServer per test on its own port. The 193xx range is deliberately
	// clear of the ports the other HTTP suites bind (18080-18103,
	// AdminHttpGate/DialPlan/HttpTraceCommand/PcapCapture; 19100+,
	// TelephonyConfigHttp) so a whole-suite run never collides.
	class ApiKillParseTest : public ::testing::Test
	{
	protected:
		void SetUp() override
		{
			AdminAuth::clearCredential();
			_port = _nextPort++;
			// nullptr handler: sendApiKill guards its forceDisconnect() call on a
			// non-null handler but echoes the parsed extension either way, which is
			// exactly the observable this suite needs.
			_server = std::make_unique<HttpServer>("127.0.0.1", _port, nullptr);
			_server->start();
			std::this_thread::sleep_for(std::chrono::milliseconds(50));
		}

		void TearDown() override
		{
			_server.reset();
			AdminAuth::clearCredential();
		}

		// POSTs `body` to /api/kill as an authenticated admin and returns the raw
		// response, so each test states only the body shape it cares about.
		std::string kill(const AdminSession& a, const std::string& body)
		{
			return httpRaw(_port, "POST", "/api/kill", body,
				"pd_session=" + a.cookie, a.csrf);
		}

		int _port = 0;
		std::unique_ptr<HttpServer> _server;
		static int _nextPort;
	};
	int ApiKillParseTest::_nextPort = 19300;
}

// ---- Defect 1: a key that merely ENDS in "extension" is not "extension" ----
//
// The hand-rolled body.find("extension=") matched inside "myextension=", so the
// endpoint disconnected 999 and left the jack the operator clicked still up.
TEST_F(ApiKillParseTest, SuffixKeyDoesNotMatchExtension)
{
	AdminSession a = loginOn(_port);

	std::string resp = kill(a, "myextension=999&extension=101");
	ASSERT_EQ(statusOf(resp), 200) << resp;
	std::string body = bodyOf(resp);
	EXPECT_NE(body.find("\"disconnected\":\"101\""), std::string::npos) << body;
	EXPECT_EQ(body.find("999"), std::string::npos)
		<< "a key ending in \"extension\" must not be read as \"extension\": " << body;
}

// A suffix key ALONE is not an extension parameter at all, so this is a 400 —
// the deliberate behaviour change in the fix, pinned here so it is not mistaken
// for a regression later.
TEST_F(ApiKillParseTest, SuffixKeyAloneIsMissingParameter)
{
	AdminSession a = loginOn(_port);

	std::string resp = kill(a, "myextension=999");
	EXPECT_EQ(statusOf(resp), 400) << resp;
	EXPECT_NE(bodyOf(resp).find("missing extension parameter"), std::string::npos)
		<< bodyOf(resp);
}

// ---- Defect 2: the value ends at '&', not at the end of the body ----
//
// substr(pos + prefix.size()) ran to the end, so "extension=101&reason=test"
// yielded "101&reason=test" — a string no registered client can equal, i.e. a
// kill that matched nothing while still answering 200.
TEST_F(ApiKillParseTest, ValueStopsAtParameterSeparator)
{
	AdminSession a = loginOn(_port);

	std::string resp = kill(a, "extension=101&reason=test");
	ASSERT_EQ(statusOf(resp), 200) << resp;
	std::string body = bodyOf(resp);
	EXPECT_NE(body.find("\"disconnected\":\"101\""), std::string::npos) << body;
	EXPECT_EQ(body.find("reason"), std::string::npos)
		<< "the value must stop at '&', not run to the end of the body: " << body;
}

// The parameter is found wherever it sits, not just at offset 0 — the boundary
// check admits "start of body" and "just after '&'" equally.
TEST_F(ApiKillParseTest, ParameterFoundAfterAnotherParameter)
{
	AdminSession a = loginOn(_port);

	std::string resp = kill(a, "reason=stuck&extension=102");
	ASSERT_EQ(statusOf(resp), 200) << resp;
	EXPECT_NE(bodyOf(resp).find("\"disconnected\":\"102\""), std::string::npos)
		<< bodyOf(resp);
}

// ---- Defect 3: the value is URL-decoded ----
//
// isValidAor admits '*' and '#' (park orbits, page zones, *8 group pickup — see
// PbxConfig.hpp), and a conservative encoder sends those as escapes: curl
// --data-urlencode and Python's quote() both put "*8" on the wire as "%2A8".
// (The dashboard's own encodeURIComponent() leaves '*' alone, but escapes '#' as
// "%23", so the endpoint must decode either way.) Without a decode the escape was
// compared literally and matched nothing.
TEST_F(ApiKillParseTest, PercentEncodedExtensionIsDecoded)
{
	AdminSession a = loginOn(_port);

	std::string resp = kill(a, "extension=%2A8");
	ASSERT_EQ(statusOf(resp), 200) << resp;
	std::string body = bodyOf(resp);
	EXPECT_NE(body.find("\"disconnected\":\"*8\""), std::string::npos) << body;
	EXPECT_EQ(body.find("%2A"), std::string::npos)
		<< "the percent escape must be decoded, not passed through: " << body;
}

// ---- Unchanged contract: a missing/empty parameter is still a 400 ----
//
// tests/http/test_api.sh's TC-ED-02 asserts this against a live device; pinning
// it here too keeps the host suite honest about the empty-body path the rewrite
// touched.
TEST_F(ApiKillParseTest, EmptyBodyIsMissingParameter)
{
	AdminSession a = loginOn(_port);

	std::string resp = kill(a, "");
	EXPECT_EQ(statusOf(resp), 400) << resp;

	std::string present = kill(a, "extension=");
	EXPECT_EQ(statusOf(present), 400)
		<< "a present-but-empty extension is as unusable as a missing one: " << present;
}

// ---- Unchanged contract: trailing CR/LF is trimmed ----
//
// The old parse trimmed trailing whitespace explicitly; getFormParam does the
// same, so a body a client terminated with CRLF still names a clean extension.
TEST_F(ApiKillParseTest, TrailingNewlineIsTrimmed)
{
	AdminSession a = loginOn(_port);

	std::string resp = kill(a, "extension=103\r\n");
	ASSERT_EQ(statusOf(resp), 200) << resp;
	EXPECT_NE(bodyOf(resp).find("\"disconnected\":\"103\""), std::string::npos)
		<< bodyOf(resp);
}
