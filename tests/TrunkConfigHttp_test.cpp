// TrunkConfigHttp_test.cpp — issue #164's configuration surface: the
// TrunkConfigStore round trip and the GET/POST /api/trunk admin routes,
// driven through a real HttpServer socket exactly as EmailHttp_test.cpp
// drives /api/email (same requireAdmin gate, same bare
// `HttpServer(..., nullptr)` fixture -- these routes talk to
// TrunkConfigStore directly and need no RequestsHandler).
//
// The centrepiece is the #207 class this project has been bitten by twice:
// GET never echoes the stored digest password, even to an authenticated
// session -- only a hasPassword boolean. Also covered: the "empty submitted
// password means keep the stored one" merge, the explicit clearPassword
// escape hatch, port and length validation, and the refusal to persist an
// enabled-but-unusable trunk.
//
// Ports: this file owns 18180-18189 via an auto-incrementing `_nextPort`.

#include <gtest/gtest.h>
#include "HttpServer.hpp"
#include "AdminAuth.hpp"
#include "TrunkConfigStore.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#define PD_TC_CLOSESOCK(s) closesocket(s)
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#define PD_TC_CLOSESOCK(s) close(s)
#endif

#include <chrono>
#include <csignal>
#include <cstdlib>
#include <memory>
#include <string>
#include <thread>

namespace
{
#if !defined(_WIN32) && !defined(_WIN64)
	// See EmailHttp_test.cpp's identical guard: an unguarded send() on a
	// socket the peer already closed raises SIGPIPE, whose default action
	// kills the whole test process -- every case in this binary, not just
	// the one that raced.
	struct SigpipeIgnoreTrunk
	{
		SigpipeIgnoreTrunk() { std::signal(SIGPIPE, SIG_IGN); }
	};
	SigpipeIgnoreTrunk g_sigpipeIgnoreTrunk;
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
			PD_TC_CLOSESOCK(s);
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
		PD_TC_CLOSESOCK(s);
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
	// the same shortcut EmailHttp_test.cpp/DialPlan_test.cpp use.
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

	// A fully populated stored config, so a test that checks "this field was
	// left alone" starts from a value that is visibly not the default.
	TrunkConfigStore::Config storedConfig()
	{
		TrunkConfigStore::Config c;
		c.host      = "sip.carrier.example";
		c.port      = 5060;
		c.proxyHost = "proxy.carrier.example";
		c.proxyPort = 5080;
		c.fromUser  = "15551230000";
		c.callerId  = "15551239999";
		c.authUser  = "auth-id-9876";
		c.pass      = "s3cret-pw";
		c.enabled   = true;
		return c;
	}

	class TrunkHttpTest : public ::testing::Test
	{
	protected:
		void SetUp() override
		{
			AdminAuth::clearCredential();
			TrunkConfigStore::resetForTest();
			_port = _nextPort++;
			_server = std::make_unique<HttpServer>("127.0.0.1", _port, nullptr);
			_server->start();
			std::this_thread::sleep_for(std::chrono::milliseconds(50));
		}
		void TearDown() override
		{
			_server.reset();
			AdminAuth::clearCredential();
			TrunkConfigStore::resetForTest();
		}

		int _port = 0;
		std::unique_ptr<HttpServer> _server;
		static int _nextPort;
	};
	int TrunkHttpTest::_nextPort = 18180;
}

// ── The store itself ─────────────────────────────────────────────────────────

TEST(TrunkConfigStoreTest, RoundTripsEveryField)
{
	TrunkConfigStore::resetForTest();
	const auto in = storedConfig();
	ASSERT_TRUE(TrunkConfigStore::save(in));

	const auto out = TrunkConfigStore::load();
	EXPECT_EQ(out.host, in.host);
	EXPECT_EQ(out.port, in.port);
	EXPECT_EQ(out.proxyHost, in.proxyHost);
	EXPECT_EQ(out.proxyPort, in.proxyPort);
	EXPECT_EQ(out.fromUser, in.fromUser);
	EXPECT_EQ(out.callerId, in.callerId);
	EXPECT_EQ(out.authUser, in.authUser);
	EXPECT_EQ(out.pass, in.pass) << "load() returns the real secret -- the ROUTE is what withholds it";
	EXPECT_EQ(out.enabled, in.enabled);
	TrunkConfigStore::resetForTest();
}

TEST(TrunkConfigStoreTest, DefaultsAreASafeDisabledTrunk)
{
	TrunkConfigStore::resetForTest();
	const auto c = TrunkConfigStore::load();
	EXPECT_FALSE(c.enabled) << "an unprovisioned device must not have a live trunk";
	EXPECT_TRUE(c.host.empty());
	EXPECT_TRUE(c.pass.empty());
	EXPECT_EQ(c.port, 5060);
	EXPECT_EQ(c.proxyPort, 5060);
}

// ── The #207 class: the password never leaves ────────────────────────────────

TEST_F(TrunkHttpTest, GetNeverEchoesThePasswordEvenAuthenticated)
{
	ASSERT_TRUE(TrunkConfigStore::save(storedConfig()));
	auto s = bypassLogin();

	const std::string resp = httpGet(_port, "/api/trunk", s.cookie);
	ASSERT_EQ(statusOf(resp), 200);
	const std::string body = bodyOf(resp);

	EXPECT_EQ(body.find("s3cret-pw"), std::string::npos)
		<< "the stored password must never appear in a response body: " << body;
	EXPECT_NE(body.find("\"hasPassword\":true"), std::string::npos)
		<< "presence must still be reported so the UI can show 'set'";

	// The non-secret fields SHOULD be there -- this is a config editor.
	EXPECT_NE(body.find("sip.carrier.example"), std::string::npos);
	EXPECT_NE(body.find("proxy.carrier.example"), std::string::npos);
	EXPECT_NE(body.find("auth-id-9876"), std::string::npos)
		<< "the auth ID is not a secret and the operator must be able to read it back";
}

TEST_F(TrunkHttpTest, PostResponseAlsoWithholdsThePassword)
{
	auto s = bypassLogin();
	const std::string resp = httpPost(_port, "/api/trunk",
		"host=sip.carrier.example&fromUser=15551230000&pass=s3cret-pw&enabled=1",
		s.cookie, s.csrf);
	ASSERT_EQ(statusOf(resp), 200);
	const std::string body = bodyOf(resp);
	EXPECT_EQ(body.find("s3cret-pw"), std::string::npos)
		<< "the echoed config must be as redacted as the GET: " << body;
	EXPECT_NE(body.find("\"hasPassword\":true"), std::string::npos);
}

TEST_F(TrunkHttpTest, HasPasswordIsFalseWhenNoneStored)
{
	auto s = bypassLogin();
	const std::string body = bodyOf(httpGet(_port, "/api/trunk", s.cookie));
	EXPECT_NE(body.find("\"hasPassword\":false"), std::string::npos) << body;
}

// ── The gate ─────────────────────────────────────────────────────────────────

TEST_F(TrunkHttpTest, UnauthenticatedGetIsRefused)
{
	ASSERT_TRUE(TrunkConfigStore::save(storedConfig()));
	const std::string resp = httpGet(_port, "/api/trunk");
	EXPECT_EQ(statusOf(resp), 401);
	EXPECT_EQ(bodyOf(resp).find("sip.carrier.example"), std::string::npos)
		<< "a refused request must disclose no infrastructure detail at all";
}

TEST_F(TrunkHttpTest, PostWithoutCsrfIsRefused)
{
	auto s = bypassLogin();
	const std::string resp = httpPost(_port, "/api/trunk",
		"host=evil.example&fromUser=1&enabled=1", s.cookie, "");
	EXPECT_NE(statusOf(resp), 200);
	EXPECT_TRUE(TrunkConfigStore::load().host.empty())
		<< "a CSRF-less POST must not have reached the store";
}

// ── The secret merge policy ──────────────────────────────────────────────────

TEST_F(TrunkHttpTest, EmptySubmittedPasswordKeepsTheStoredOne)
{
	ASSERT_TRUE(TrunkConfigStore::save(storedConfig()));
	auto s = bypassLogin();

	// The form always posts `pass`, and it is blank unless the operator typed
	// a new one. Reading that as "clear it" would silently break a working
	// trunk on any unrelated edit -- e.g. just changing the caller ID.
	const std::string resp = httpPost(_port, "/api/trunk",
		"host=sip.carrier.example&fromUser=15551230000&callerId=15558887777"
		"&authUser=auth-id-9876&pass=&enabled=1",
		s.cookie, s.csrf);
	ASSERT_EQ(statusOf(resp), 200);

	const auto after = TrunkConfigStore::load();
	EXPECT_EQ(after.pass, "s3cret-pw") << "the stored password must survive an edit that did not touch it";
	EXPECT_EQ(after.callerId, "15558887777") << "...while the edit itself still applied";
}

TEST_F(TrunkHttpTest, ClearPasswordIsTheExplicitEscapeHatch)
{
	ASSERT_TRUE(TrunkConfigStore::save(storedConfig()));
	auto s = bypassLogin();

	const std::string resp = httpPost(_port, "/api/trunk",
		"host=sip.carrier.example&fromUser=15551230000&pass=&clearPassword=1&enabled=1",
		s.cookie, s.csrf);
	ASSERT_EQ(statusOf(resp), 200);
	EXPECT_TRUE(TrunkConfigStore::load().pass.empty());
	EXPECT_NE(bodyOf(resp).find("\"hasPassword\":false"), std::string::npos);
}

// clearPassword must win over a simultaneously submitted new password rather
// than the two silently racing on parameter order.
TEST_F(TrunkHttpTest, ClearPasswordBeatsASubmittedPassword)
{
	ASSERT_TRUE(TrunkConfigStore::save(storedConfig()));
	auto s = bypassLogin();

	const std::string resp = httpPost(_port, "/api/trunk",
		"host=sip.carrier.example&fromUser=15551230000&pass=newpw&clearPassword=1&enabled=1",
		s.cookie, s.csrf);
	ASSERT_EQ(statusOf(resp), 200);
	EXPECT_TRUE(TrunkConfigStore::load().pass.empty());
}

TEST_F(TrunkHttpTest, ANewPasswordReplacesTheStoredOne)
{
	ASSERT_TRUE(TrunkConfigStore::save(storedConfig()));
	auto s = bypassLogin();

	ASSERT_EQ(statusOf(httpPost(_port, "/api/trunk",
		"host=sip.carrier.example&fromUser=15551230000&pass=rotated-pw&enabled=1",
		s.cookie, s.csrf)), 200);
	EXPECT_EQ(TrunkConfigStore::load().pass, "rotated-pw");
}

// ── Validation ───────────────────────────────────────────────────────────────

TEST_F(TrunkHttpTest, RejectsAnOutOfRangePort)
{
	auto s = bypassLogin();
	for (const char* bad : { "0", "65536", "-1", "notaport", "5060x" })
	{
		const std::string resp = httpPost(_port, "/api/trunk",
			std::string("host=sip.carrier.example&fromUser=1555&enabled=1&port=") + bad,
			s.cookie, s.csrf);
		EXPECT_EQ(statusOf(resp), 400) << "port=" << bad << " must be refused";
	}
	EXPECT_TRUE(TrunkConfigStore::load().host.empty()) << "no rejected request may have persisted";
}

TEST_F(TrunkHttpTest, RejectsAnOutOfRangeProxyPort)
{
	auto s = bypassLogin();
	const std::string resp = httpPost(_port, "/api/trunk",
		"host=sip.carrier.example&fromUser=1555&enabled=1&proxyPort=70000",
		s.cookie, s.csrf);
	EXPECT_EQ(statusOf(resp), 400);
}

// An empty port field means "leave it alone", which is how the form behaves
// when the operator never touches the default.
TEST_F(TrunkHttpTest, AnEmptyPortKeepsTheStoredValue)
{
	auto pre = storedConfig();
	pre.port = 5070;
	ASSERT_TRUE(TrunkConfigStore::save(pre));
	auto s = bypassLogin();

	ASSERT_EQ(statusOf(httpPost(_port, "/api/trunk",
		"host=sip.carrier.example&fromUser=15551230000&port=&enabled=1", s.cookie, s.csrf)), 200);
	EXPECT_EQ(TrunkConfigStore::load().port, 5070);
}

// Length ceilings are enforced at the door rather than left to the silent
// truncation in applyStoredTrunkConfig(). A trunk holding a half-stored
// password while the UI says "set" is undiagnosable from the outside.
TEST_F(TrunkHttpTest, RejectsOverLongFieldsRatherThanTruncating)
{
	auto s = bypassLogin();
	const std::string longHost(64, 'h');   // host[64] holds 63
	const std::string longPass(64, 'p');   // kMaxSecret 64 holds 63
	const std::string longFrom(40, 'f');   // fromUser[40] holds 39
	const std::string longCid(24, 'c');    // callerId[24] holds 23
	const std::string longAuth(64, 'a');   // authUser[64] holds 63

	EXPECT_EQ(statusOf(httpPost(_port, "/api/trunk",
		"fromUser=1555&host=" + longHost, s.cookie, s.csrf)), 400);
	EXPECT_EQ(statusOf(httpPost(_port, "/api/trunk",
		"host=a.example&fromUser=1555&pass=" + longPass, s.cookie, s.csrf)), 400);
	EXPECT_EQ(statusOf(httpPost(_port, "/api/trunk",
		"host=a.example&fromUser=" + longFrom, s.cookie, s.csrf)), 400);
	EXPECT_EQ(statusOf(httpPost(_port, "/api/trunk",
		"host=a.example&fromUser=1555&callerId=" + longCid, s.cookie, s.csrf)), 400);
	EXPECT_EQ(statusOf(httpPost(_port, "/api/trunk",
		"host=a.example&fromUser=1555&authUser=" + longAuth, s.cookie, s.csrf)), 400);
	EXPECT_EQ(statusOf(httpPost(_port, "/api/trunk",
		"fromUser=1555&host=" + longHost.substr(0, 63), s.cookie, s.csrf)), 200)
		<< "the longest value that fits must still be accepted";
}

// Saving enabled=1 without the fields SipTrunk::Config::valid() requires would
// leave the UI showing an enabled trunk the engine silently treats as invalid.
TEST_F(TrunkHttpTest, RefusesToEnableAnUnusableTrunk)
{
	auto s = bypassLogin();
	EXPECT_EQ(statusOf(httpPost(_port, "/api/trunk",
		"host=&fromUser=15551230000&enabled=1", s.cookie, s.csrf)), 400)
		<< "a trunk with no registrar cannot place a call";
	EXPECT_EQ(statusOf(httpPost(_port, "/api/trunk",
		"host=sip.carrier.example&fromUser=&enabled=1", s.cookie, s.csrf)), 400)
		<< "a carrier needs an identity to authorise the call";

	// The same incomplete config is fine while DISABLED -- an operator must be
	// able to save a half-filled form and come back to it.
	EXPECT_EQ(statusOf(httpPost(_port, "/api/trunk",
		"host=sip.carrier.example&fromUser=&enabled=0", s.cookie, s.csrf)), 200);
	EXPECT_FALSE(TrunkConfigStore::load().enabled);
}

TEST_F(TrunkHttpTest, PersistsAndReadsBackAFullConfig)
{
	auto s = bypassLogin();
	ASSERT_EQ(statusOf(httpPost(_port, "/api/trunk",
		"host=sip.carrier.example&port=5061"
		"&proxyHost=proxy.carrier.example&proxyPort=5080"
		"&fromUser=15551230000&callerId=15551239999"
		"&authUser=auth-id-9876&pass=s3cret-pw&enabled=1",
		s.cookie, s.csrf)), 200);

	const auto c = TrunkConfigStore::load();
	EXPECT_EQ(c.host, "sip.carrier.example");
	EXPECT_EQ(c.port, 5061);
	EXPECT_EQ(c.proxyHost, "proxy.carrier.example");
	EXPECT_EQ(c.proxyPort, 5080);
	EXPECT_EQ(c.fromUser, "15551230000");
	EXPECT_EQ(c.callerId, "15551239999");
	EXPECT_EQ(c.authUser, "auth-id-9876");
	EXPECT_EQ(c.pass, "s3cret-pw");
	EXPECT_TRUE(c.enabled);
}

// ── Factory reset ────────────────────────────────────────────────────────────

// trunk_pass is a plaintext, billable carrier credential living in a namespace
// nothing else in sendApiFactoryReset() reaches. Without an explicit clear, a
// factory-reset board handed to someone else still holds the previous
// operator's SIP trunk password in flash.
TEST_F(TrunkHttpTest, FactoryResetClearsTheTrunkCredential)
{
	ASSERT_TRUE(TrunkConfigStore::save(storedConfig()));
	ASSERT_FALSE(TrunkConfigStore::load().pass.empty());
	auto s = bypassLogin();

	ASSERT_EQ(statusOf(httpRaw(_port, "POST", "/api/factory-reset", "confirm=ERASE",
		s.cookie, s.csrf)), 200);

	const auto after = TrunkConfigStore::load();
	EXPECT_TRUE(after.pass.empty()) << "the carrier password must not survive a factory reset";
	EXPECT_TRUE(after.host.empty());
	EXPECT_TRUE(after.proxyHost.empty());
	EXPECT_TRUE(after.authUser.empty());
	EXPECT_FALSE(after.enabled) << "a reset board must come back with the trunk down";
}

// ── The setup page ───────────────────────────────────────────────────────────

TEST_F(TrunkHttpTest, SetupPageIsServedAndCarriesNoConfigData)
{
	ASSERT_TRUE(TrunkConfigStore::save(storedConfig()));
	const std::string resp = httpGet(_port, "/setup/trunk");
	ASSERT_EQ(statusOf(resp), 200);
	const std::string body = bodyOf(resp);

	EXPECT_NE(body.find("SIP Trunk"), std::string::npos);
	// The shell is ungated like "/" precisely because it holds nothing. Every
	// value on it arrives later via the gated /api/trunk.
	EXPECT_EQ(body.find("s3cret-pw"), std::string::npos);
	EXPECT_EQ(body.find("sip.carrier.example"), std::string::npos);
	EXPECT_EQ(body.find("auth-id-9876"), std::string::npos);
}
