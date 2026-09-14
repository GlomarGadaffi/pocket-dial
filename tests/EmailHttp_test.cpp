// EmailHttp_test.cpp — issue #159's HTTP admin surface: GET/POST /api/email
// and POST /api/email/test, driven through a real HttpServer socket exactly
// like DialPlan_test.cpp/TelephonyConfigHttp_test.cpp's other routes (same
// requireAdmin gate). No RequestsHandler needed -- these routes talk to
// EmailConfigStore/SmtpClient directly, so every fixture here is a bare
// `HttpServer(..., nullptr)`, same pattern as DialPlan_test.cpp/
// MetricsEndpoint_test.cpp/PcapCapture_test.cpp use for handler-independent
// routes.
//
// Covers the #207 class this project has been bitten by twice: GET never
// echoes the stored password or service-account private key, even to an
// authenticated session -- only hasPassword/hasGsaKey booleans. Also covers
// the same-origin/session/CSRF gate, the "empty submitted secret means keep
// the stored one" merge policy, mode-based default port, input validation,
// and one full end-to-end test-send through a real (loopback, plain-TCP)
// fake SMTP server -- proving the HTTP route actually reaches
// SmtpClient::sendAndWait() and back, not just that each piece works in
// isolation.
//
// Ports: this file owns 18160-18169 via an auto-incrementing `_nextPort`,
// per CONTRIBUTING_FIRMWARE.md's table.

#include <gtest/gtest.h>
#include "HttpServer.hpp"
#include "AdminAuth.hpp"
#include "EmailConfigStore.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#define PD_ET_CLOSESOCK(s) closesocket(s)
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#define PD_ET_CLOSESOCK(s) close(s)
#endif

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <functional>
#include <string>
#include <thread>

namespace
{
#if !defined(_WIN32) && !defined(_WIN64)
	// See SmtpDialogue_test.cpp's identical guard: the scripted fake SMTP
	// server thread below can race a client that has already closed, and an
	// unguarded send() on POSIX raises SIGPIPE, whose default action kills
	// the whole test process (every other case in this binary, not just this
	// one). Ignore it once, process-wide, same as production code must.
	struct SigpipeIgnore
	{
		SigpipeIgnore() { std::signal(SIGPIPE, SIG_IGN); }
	};
	SigpipeIgnore g_sigpipeIgnore;
#endif

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
			PD_ET_CLOSESOCK(s);
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
		char buf[4096];
		int n;
		while ((n = recv(s, buf, sizeof(buf), 0)) > 0) resp.append(buf, static_cast<size_t>(n));
		PD_ET_CLOSESOCK(s);
		return resp;
	}
	std::string httpGet(int port, const std::string& path, const std::string& cookie = "")
	{
		return httpRaw(port, "GET", path, "", cookie);
	}
	std::string httpPost(int port, const std::string& path, const std::string& body,
	                      const std::string& cookie, const std::string& csrf)
	{
		return httpRaw(port, "POST", path, body, cookie, csrf);
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
		size_t at = resp.find("\r\n\r\n");
		return at == std::string::npos ? "" : resp.substr(at + 4);
	}

	struct AdminSession { std::string cookie; std::string csrf; };

	// Bypasses the HTTP login round trip (not what these tests are about) --
	// same shortcut DialPlan_test.cpp's HTTP suite uses.
	AdminSession bypassLogin()
	{
		AdminSession a;
		if (!AdminAuth::setLoginCredential("admin", "realpassword123"))
		{
			ADD_FAILURE() << "setLoginCredential failed";
			return a;
		}
		std::string token = AdminAuth::createSession();
		a.cookie = "pd_session=" + token;
		a.csrf = AdminAuth::sessionCsrf(token);
		return a;
	}

	class EmailHttpTest : public ::testing::Test
	{
	protected:
		void SetUp() override
		{
			AdminAuth::clearCredential();
			EmailConfigStore::resetForTest();
			_port = _nextPort++;
			_server = std::make_unique<HttpServer>("127.0.0.1", _port, nullptr);
			_server->start();
			std::this_thread::sleep_for(std::chrono::milliseconds(50));
		}
		void TearDown() override
		{
			_server.reset();
			AdminAuth::clearCredential();
			EmailConfigStore::resetForTest();
		}

		int _port = 0;
		std::unique_ptr<HttpServer> _server;
		static int _nextPort;
	};
	int EmailHttpTest::_nextPort = 18160;

	// --- Minimal fake SMTP server for the one end-to-end test below. ---
	// Duplicated rather than shared with SmtpDialogue_test.cpp -- anonymous-
	// namespace helpers don't cross translation units (see
	// TelephonyConfigHttp_test.cpp's identical note).
	std::atomic<int> g_smtpPort{18500}; // well clear of every HttpServer block

	int startListener(int port)
	{
		int s = static_cast<int>(socket(AF_INET, SOCK_STREAM, 0));
		if (s < 0) return -1;
		int yes = 1;
		setsockopt(s, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&yes), sizeof(yes));
		sockaddr_in addr{};
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		addr.sin_port = htons(static_cast<uint16_t>(port));
		if (bind(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) { PD_ET_CLOSESOCK(s); return -1; }
		if (listen(s, 1) != 0) { PD_ET_CLOSESOCK(s); return -1; }
		return s;
	}
	void srvSend(int fd, const std::string& line)
	{
		std::string wire = line + "\r\n";
		send(fd, wire.data(), static_cast<int>(wire.size()), 0);
	}
	std::string srvRecvLine(int fd)
	{
		std::string buf; char c;
		for (;;)
		{
			int n = recv(fd, &c, 1, 0);
			if (n <= 0) return buf;
			if (c == '\n') { if (!buf.empty() && buf.back() == '\r') buf.pop_back(); return buf; }
			buf += c;
		}
	}
	std::string srvRecvData(int fd)
	{
		std::string all; char c;
		for (;;)
		{
			int n = recv(fd, &c, 1, 0);
			if (n <= 0) break;
			all += c;
			if (all.size() >= 5 && all.compare(all.size() - 5, 5, "\r\n.\r\n") == 0)
				return all.substr(0, all.size() - 5);
		}
		return all;
	}
	struct FakeSmtpThread
	{
		int port;
		int listenFd;
		std::thread th;
		explicit FakeSmtpThread(std::function<void(int)> script)
		{
			port = g_smtpPort.fetch_add(1);
			listenFd = startListener(port);
			th = std::thread([this, script]() {
				sockaddr_in peer{};
#if defined(_WIN32) || defined(_WIN64)
				int peerLen = sizeof(peer);
#else
				socklen_t peerLen = sizeof(peer);
#endif
				int c = static_cast<int>(accept(listenFd, reinterpret_cast<sockaddr*>(&peer), &peerLen));
				if (c >= 0) { script(c); PD_ET_CLOSESOCK(c); }
			});
		}
		~FakeSmtpThread()
		{
			if (th.joinable()) th.join();
			if (listenFd >= 0) PD_ET_CLOSESOCK(listenFd);
		}
	};
} // namespace

TEST_F(EmailHttpTest, GetConfig_Unauthenticated_401)
{
	auto resp = httpGet(_port, "/api/email");
	EXPECT_EQ(statusOf(resp), 401);
}

TEST_F(EmailHttpTest, PostConfig_Unauthenticated_401)
{
	auto resp = httpPost(_port, "/api/email", "host=smtp.example.test", "", "");
	EXPECT_EQ(statusOf(resp), 401);
}

TEST_F(EmailHttpTest, GetSetupPage_Unauthenticated_Serves200_NoLoginRequired)
{
	// The page SHELL is ungated (see sendEmailSetupHtml's declaration
	// comment) -- only the data endpoints require a session.
	auto resp = httpGet(_port, "/setup/email");
	EXPECT_EQ(statusOf(resp), 200);
	EXPECT_NE(bodyOf(resp).find("Email (SMTP)"), std::string::npos);
}

TEST_F(EmailHttpTest, PostThenGet_RoundTripsFields_NeverEchoesSecrets)
{
	auto a = bypassLogin();
	std::string body =
		"host=smtp.example.test&port=465&mode=tls&auth=plain&user=bot@example.test"
		"&pass=SuperSecretPassword123&from=bot@example.test&to=ops@example.test";
	auto postResp = httpPost(_port, "/api/email", body, a.cookie, a.csrf);
	ASSERT_EQ(statusOf(postResp), 200) << bodyOf(postResp);
	// The POST response itself must not echo the secret either.
	EXPECT_EQ(bodyOf(postResp).find("SuperSecretPassword123"), std::string::npos);

	auto getResp = httpGet(_port, "/api/email", a.cookie);
	ASSERT_EQ(statusOf(getResp), 200);
	std::string getBody = bodyOf(getResp);
	EXPECT_EQ(getBody.find("SuperSecretPassword123"), std::string::npos)
		<< "GET /api/email must never echo the stored password";
	EXPECT_NE(getBody.find("\"hasPassword\":true"), std::string::npos);
	EXPECT_NE(getBody.find("\"host\":\"smtp.example.test\""), std::string::npos);
	EXPECT_NE(getBody.find("\"port\":465"), std::string::npos);
	EXPECT_NE(getBody.find("\"mode\":\"tls\""), std::string::npos);
	EXPECT_NE(getBody.find("\"auth\":\"plain\""), std::string::npos);

	// The real secret IS persisted, verified in-process (the only legitimate
	// way to read it back -- see EmailConfigStore.hpp's contract).
	EXPECT_EQ(EmailConfigStore::load().pass, "SuperSecretPassword123");
}

TEST_F(EmailHttpTest, PostConfig_EmptySecret_KeepsStoredValue)
{
	auto a = bypassLogin();
	ASSERT_EQ(statusOf(httpPost(_port, "/api/email",
		"host=smtp.example.test&auth=plain&user=u&pass=KeepMe123", a.cookie, a.csrf)), 200);
	ASSERT_EQ(EmailConfigStore::load().pass, "KeepMe123");

	// Second save, pass field submitted empty -- host changes, password must not.
	ASSERT_EQ(statusOf(httpPost(_port, "/api/email",
		"host=smtp2.example.test&auth=plain&user=u&pass=", a.cookie, a.csrf)), 200);
	EXPECT_EQ(EmailConfigStore::load().host, "smtp2.example.test");
	EXPECT_EQ(EmailConfigStore::load().pass, "KeepMe123");
}

TEST_F(EmailHttpTest, PostConfig_DefaultPortAppliedFromMode)
{
	auto a = bypassLogin();
	ASSERT_EQ(statusOf(httpPost(_port, "/api/email", "host=h&mode=tls", a.cookie, a.csrf)), 200);
	EXPECT_EQ(EmailConfigStore::load().port, 465);

	ASSERT_EQ(statusOf(httpPost(_port, "/api/email", "host=h&mode=plain", a.cookie, a.csrf)), 200);
	EXPECT_EQ(EmailConfigStore::load().port, 25);

	ASSERT_EQ(statusOf(httpPost(_port, "/api/email", "host=h&mode=starttls", a.cookie, a.csrf)), 200);
	EXPECT_EQ(EmailConfigStore::load().port, 587);
}

TEST_F(EmailHttpTest, PostConfig_InvalidModeRejected400)
{
	auto a = bypassLogin();
	auto resp = httpPost(_port, "/api/email", "host=h&mode=bogus", a.cookie, a.csrf);
	EXPECT_EQ(statusOf(resp), 400);
}

TEST_F(EmailHttpTest, PostConfig_InvalidAuthRejected400)
{
	auto a = bypassLogin();
	auto resp = httpPost(_port, "/api/email", "host=h&auth=bogus", a.cookie, a.csrf);
	EXPECT_EQ(statusOf(resp), 400);
}

TEST_F(EmailHttpTest, PostConfig_InvalidPortRejected400)
{
	auto a = bypassLogin();
	auto resp = httpPost(_port, "/api/email", "host=h&port=999999", a.cookie, a.csrf);
	EXPECT_EQ(statusOf(resp), 400);
}

TEST_F(EmailHttpTest, PostConfig_NoCsrf_Rejected403)
{
	auto a = bypassLogin();
	auto resp = httpPost(_port, "/api/email", "host=h", a.cookie, /*csrf=*/"");
	EXPECT_EQ(statusOf(resp), 403);
}

TEST_F(EmailHttpTest, TestSend_NoHostConfigured_ReturnsOkFalseNot500)
{
	auto a = bypassLogin();
	auto resp = httpPost(_port, "/api/email/test", "to=someone@example.test", a.cookie, a.csrf);
	ASSERT_EQ(statusOf(resp), 200);
	EXPECT_NE(bodyOf(resp).find("\"ok\":false"), std::string::npos);
}

TEST_F(EmailHttpTest, TestSend_NoRecipientAnywhere_ReturnsOkFalse)
{
	auto a = bypassLogin();
	ASSERT_EQ(statusOf(httpPost(_port, "/api/email", "host=smtp.example.test", a.cookie, a.csrf)), 200);
	auto resp = httpPost(_port, "/api/email/test", "", a.cookie, a.csrf);
	ASSERT_EQ(statusOf(resp), 200);
	EXPECT_NE(bodyOf(resp).find("\"ok\":false"), std::string::npos);
}

TEST_F(EmailHttpTest, TestSend_EndToEnd_RealFakeServerRoundTrip)
{
	std::string capturedTo;
	FakeSmtpThread srv([&capturedTo](int c) {
		srvSend(c, "220 fake.smtp ready");
		srvRecvLine(c); // EHLO
		srvSend(c, "250 fake.smtp");
		srvRecvLine(c); // MAIL FROM
		srvSend(c, "250 OK");
		capturedTo = srvRecvLine(c); // RCPT TO
		srvSend(c, "250 OK");
		srvRecvLine(c); // DATA
		srvSend(c, "354 go");
		srvRecvData(c);
		srvSend(c, "250 Queued");
		srvRecvLine(c); // QUIT
		srvSend(c, "221 Bye");
	});

	auto a = bypassLogin();
	std::string cfgBody = "host=127.0.0.1&port=" + std::to_string(srv.port) +
	                       "&mode=plain&auth=none&from=pbx@example.test&to=ops@example.test";
	ASSERT_EQ(statusOf(httpPost(_port, "/api/email", cfgBody, a.cookie, a.csrf)), 200);

	auto resp = httpPost(_port, "/api/email/test", "", a.cookie, a.csrf);
	ASSERT_EQ(statusOf(resp), 200);
	std::string body = bodyOf(resp);
	EXPECT_NE(body.find("\"ok\":true"), std::string::npos) << body;
	EXPECT_NE(body.find("\"smtpReplyCode\":250"), std::string::npos) << body;
	EXPECT_EQ(capturedTo, "RCPT TO:<ops@example.test>");
}
