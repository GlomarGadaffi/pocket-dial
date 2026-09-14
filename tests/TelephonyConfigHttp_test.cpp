// TelephonyConfigHttp_test.cpp — the HTTP admin surface for the two Part-2
// config tables ported/added onto RequestsHandler: TelephonyApiConfig's
// bounded credential-slot table (GET/PUT/activate) and DidMapping's bounded
// DID -> extension table (GET/PUT/DELETE). Same real-socket-through-HttpServer
// style as AdminHttpGate_test.cpp/DialPlan_test.cpp's HTTP round-trip, since
// these routes live in the same same-origin/session/CSRF gate
// (HttpServer::requireAdmin) as every other mutating admin endpoint.
//
// Covers: the display-safe contract (GET never leaks the plaintext secret,
// only secretSet), the enabled-slot https:// gate surfacing as a 400, the
// out-of-range slot index surfacing as a 400 via setSlot's OWN bound check
// (not a duplicate one in HttpServer), activate flipping exactly one slot's
// "active" flag, DID-mapping's reuse of pbx::isDialTokenSafe + the reserved-
// virtual-extension set (not a new validation rule), the POCKETDIAL_MAX_DID_
// MAPPINGS bound surfacing as a 400, DELETE's idempotency, and the same-
// origin/session/CSRF gate all three new resources sit behind.
//
// Every test redirects TelephonyApiConfig/DidMapping's host-file stores to a
// per-test path via RequestsHandler::setTelephonyStorePathsForTest() (host-
// only) — see that method's comment for why: without it every test in this
// binary would read/write the SAME default "pocketdial_tapi.cfg"/
// "pocketdial_didmap.cfg" file in the process's cwd.

#include <gtest/gtest.h>
#include "HttpServer.hpp"
#include "LoopbackAnchorClient.hpp"
#include "RequestsHandler.hpp"
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
#include <cstdio>
#include <string>
#include <thread>

namespace
{
	// Minimal blocking HTTP request over a raw socket, method-parameterized (the
	// PUT/DELETE routes under test need methods AdminHttpGate_test.cpp's
	// POST/GET-only helpers don't cover). Returns the full raw response (status
	// line + headers + body).
	std::string httpRaw(int port, const std::string& method, const std::string& path,
	                     const std::string& body, const std::string& cookie = "",
	                     const std::string& csrf = "", const std::string& origin = "")
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
		std::string originHeader = origin.empty() ? "" : ("Origin: " + origin + "\r\n");
		std::string req = method + " " + path + " HTTP/1.1\r\n"
			"Host: 127.0.0.1\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n"
			"Content-Type: application/x-www-form-urlencoded\r\n" +
			cookieHeader + csrfHeader + originHeader +
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

	std::string httpGet(int port, const std::string& path, const std::string& cookie = "",
	                     const std::string& origin = "")
	{
		return httpRaw(port, "GET", path, "", cookie, "", origin);
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

	// Logs in with the shipped default credential, then completes initial setup
	// with a real one -- requireAdmin() refuses every other admin-gated route
	// (including the ones under test in this file) while needsInitialSetup()
	// is true, and setLoginCredential() does not invalidate the session it was
	// called through, so the same cookie/csrf pair keeps working afterward.
	// Same pattern as AdminHttpGate_test.cpp's loginAndCompleteSetup(),
	// duplicated here because anonymous-namespace helpers don't cross
	// translation units.
	struct AdminSession { std::string cookie; std::string csrf; };

	AdminSession loginOn(int port)
	{
		AdminSession a;
		std::string loginResp = httpRaw(port, "POST", "/api/admin/login", "username=admin&password=admin");
		EXPECT_EQ(statusOf(loginResp), 200);
		a.cookie = cookieOf(loginResp, "pd_session");
		a.csrf   = csrfOf(loginResp);

		std::string setupResp = httpRaw(port, "POST", "/api/admin/set-credential",
			"username=admin&password=realpassword123", "pd_session=" + a.cookie, a.csrf);
		EXPECT_EQ(statusOf(setupResp), 200);
		return a;
	}

	// One fixture per test: a real RequestsHandler + HttpServer pair on a fresh
	// port, with the two host-file stores redirected to per-test paths so tests
	// never see each other's state (or the repo's own pocketdial_*.cfg, if one
	// happens to exist in cwd).
	class TelephonyConfigHttpTest : public ::testing::Test
	{
	protected:
		void SetUp() override
		{
			const std::string name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
			_tapiPath = "test_http_tapicfg_" + name + ".cfg";
			_didPath  = "test_http_didmap_" + name + ".cfg";
			std::remove(_tapiPath.c_str());
			std::remove(_didPath.c_str());

			AdminAuth::clearCredential();
			_handler = std::make_unique<RequestsHandler>("192.168.4.1", 5060,
				[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
			_handler->setTelephonyStorePathsForTest(_tapiPath, _didPath);

			_port = _nextPort++;
			_server = std::make_unique<HttpServer>("127.0.0.1", _port, nullptr);
			_server->attachHandler(_handler.get());
			_server->start();
			std::this_thread::sleep_for(std::chrono::milliseconds(50));
		}

		void TearDown() override
		{
			_server.reset();
			_handler.reset();
			AdminAuth::clearCredential();
			std::remove(_tapiPath.c_str());
			std::remove(_didPath.c_str());
		}

		int _port = 0;
		std::unique_ptr<RequestsHandler> _handler;
		std::unique_ptr<HttpServer> _server;
		std::string _tapiPath, _didPath;

		static int _nextPort;
	};
	// Ports: this file owns 19100+ (issue #213 — every HTTP test file gets a
	// disjoint block; see CONTRIBUTING_FIRMWARE.md for the full table).
	int TelephonyConfigHttpTest::_nextPort = 19100;
}

// ── Telephony-API credential slots ────────────────────────────────────────────

TEST_F(TelephonyConfigHttpTest, ListStartsAllDefaultUnconfigured)
{
	AdminSession a = loginOn(_port);
	std::string resp = httpGet(_port, "/api/telephony-config", "pd_session=" + a.cookie);
	ASSERT_EQ(statusOf(resp), 200);
	std::string body = bodyOf(resp);
	// 4 slots (TelephonyApiConfig::kSlots), each LOOPBACK/disabled/no secret.
	EXPECT_NE(body.find("\"index\":0"), std::string::npos);
	EXPECT_NE(body.find("\"index\":3"), std::string::npos);
	EXPECT_EQ(body.find("\"index\":4"), std::string::npos);
	EXPECT_NE(body.find("\"secretSet\":false"), std::string::npos);
}

TEST_F(TelephonyConfigHttpTest, PutSlot_NeverLeaksSecretButReportsSecretSet)
{
	AdminSession a = loginOn(_port);
	std::string put = httpRaw(_port, "PUT", "/api/telephony-config/0",
		"enabled=1&baseUrl=https%3A%2F%2Fexample.invalid&clientId=abc123&secret=top-secret-value&routeDn=100",
		"pd_session=" + a.cookie, a.csrf);
	ASSERT_EQ(statusOf(put), 200);
	std::string putBody = bodyOf(put);
	EXPECT_EQ(putBody.find("top-secret-value"), std::string::npos)
		<< "the plaintext secret must never appear in an HTTP response";
	EXPECT_NE(putBody.find("\"secretSet\":true"), std::string::npos);
	EXPECT_NE(putBody.find("\"type\":\"TELEPHONY-API\""), std::string::npos);
	EXPECT_NE(putBody.find("\"clientId\":\"abc123\""), std::string::npos);

	std::string list = httpGet(_port, "/api/telephony-config", "pd_session=" + a.cookie);
	std::string listBody = bodyOf(list);
	EXPECT_EQ(listBody.find("top-secret-value"), std::string::npos);
	EXPECT_NE(listBody.find("\"secretSet\":true"), std::string::npos);
}

TEST_F(TelephonyConfigHttpTest, EmptySecretOnEditKeepsExistingSecret)
{
	AdminSession a = loginOn(_port);
	ASSERT_EQ(statusOf(httpRaw(_port, "PUT", "/api/telephony-config/1",
		"enabled=1&baseUrl=https%3A%2F%2Fexample.invalid&clientId=id1&secret=first-secret&routeDn=100",
		"pd_session=" + a.cookie, a.csrf)), 200);

	// Edit clientId only, secret field empty -> "keep existing" per
	// TelephonyApiConfig::setSlot's keepSecret contract.
	std::string edit = httpRaw(_port, "PUT", "/api/telephony-config/1",
		"enabled=1&baseUrl=https%3A%2F%2Fexample.invalid&clientId=id2&secret=&routeDn=100",
		"pd_session=" + a.cookie, a.csrf);
	ASSERT_EQ(statusOf(edit), 200);
	std::string editBody = bodyOf(edit);
	EXPECT_NE(editBody.find("\"clientId\":\"id2\""), std::string::npos);
	EXPECT_NE(editBody.find("\"secretSet\":true"), std::string::npos);

	ASSERT_TRUE(_handler->getTelephonyConfigSlot(1).secretSet);
}

TEST_F(TelephonyConfigHttpTest, EnabledSlotRequiresHttpsElse400)
{
	AdminSession a = loginOn(_port);
	std::string bad = httpRaw(_port, "PUT", "/api/telephony-config/0",
		"enabled=1&baseUrl=http%3A%2F%2Fexample.invalid&clientId=id&secret=s&routeDn=100",
		"pd_session=" + a.cookie, a.csrf);
	EXPECT_EQ(statusOf(bad), 400);
	EXPECT_FALSE(_handler->getTelephonyConfigSlot(0).enabled)
		<< "a rejected edit must not have applied";

	std::string good = httpRaw(_port, "PUT", "/api/telephony-config/0",
		"enabled=1&baseUrl=https%3A%2F%2Fexample.invalid&clientId=id&secret=s&routeDn=100",
		"pd_session=" + a.cookie, a.csrf);
	EXPECT_EQ(statusOf(good), 200);
	EXPECT_NE(bodyOf(good).find("\"enabled\":true"), std::string::npos);
}

TEST_F(TelephonyConfigHttpTest, OutOfRangeSlotIndexIs400ViaSetSlotsOwnBoundCheck)
{
	AdminSession a = loginOn(_port);
	// TelephonyApiConfig::kSlots == 4, so index 4 is out of range. HttpServer's
	// path parser accepts any digit string; the 400 must come from setSlot()
	// itself (RequestsHandler::setTelephonyConfigSlot -> TelephonyApiConfig::
	// setSlot), not from a duplicated bound check in the HTTP layer.
	std::string resp = httpRaw(_port, "PUT", "/api/telephony-config/4",
		"enabled=0&baseUrl=&clientId=&secret=&routeDn=",
		"pd_session=" + a.cookie, a.csrf);
	EXPECT_EQ(statusOf(resp), 400);
	EXPECT_NE(bodyOf(resp).find("Bad slot index"), std::string::npos) << bodyOf(resp);
}

TEST_F(TelephonyConfigHttpTest, ActivateFlipsExactlyOneSlotsActiveFlag)
{
	AdminSession a = loginOn(_port);
	ASSERT_EQ(statusOf(httpRaw(_port, "PUT", "/api/telephony-config/0",
		"enabled=0&baseUrl=&clientId=&secret=&routeDn=", "pd_session=" + a.cookie, a.csrf)), 200);
	ASSERT_EQ(statusOf(httpRaw(_port, "PUT", "/api/telephony-config/2",
		"enabled=0&baseUrl=&clientId=&secret=&routeDn=", "pd_session=" + a.cookie, a.csrf)), 200);

	std::string act = httpRaw(_port, "POST", "/api/telephony-config/2/activate", "",
	                          "pd_session=" + a.cookie, a.csrf);
	ASSERT_EQ(statusOf(act), 200);
	EXPECT_NE(bodyOf(act).find("\"activeIndex\":2"), std::string::npos);

	std::string list = httpGet(_port, "/api/telephony-config", "pd_session=" + a.cookie);
	std::string body = bodyOf(list);
	// Slot 2's object contains "active":true; every other slot's does not.
	// Locate slot 2's object specifically rather than just counting "true"s.
	size_t idx2 = body.find("\"index\":2");
	ASSERT_NE(idx2, std::string::npos);
	size_t idx2End = body.find('}', idx2);
	EXPECT_NE(body.substr(idx2, idx2End - idx2).find("\"active\":true"), std::string::npos);

	size_t idx0 = body.find("\"index\":0");
	ASSERT_NE(idx0, std::string::npos);
	size_t idx0End = body.find('}', idx0);
	EXPECT_NE(body.substr(idx0, idx0End - idx0).find("\"active\":false"), std::string::npos);
}

TEST_F(TelephonyConfigHttpTest, TestDialSucceedsOnTheActiveSlotThroughTheLoopbackAnchor)
{
	// Issue #165's patch-bay dashboard "Test Dial" action: a connectivity probe,
	// not a real bridged call. Host tests always boot the Loopback anchor
	// (RequestsHandler's constructor picks Loopback whenever no HTTP-configured
	// slot sets a "type" other than the struct default — see TelephonyApiConfig::
	// Slot's default member and HttpServer's PUT handler, which never accepts a
	// "type" form param), so this exercises the real makeCall()/dropCall() pair
	// against LoopbackAnchorClient::lastMakeCallDestination().
	AdminSession a = loginOn(_port);
	ASSERT_EQ(statusOf(httpRaw(_port, "PUT", "/api/telephony-config/1",
		"enabled=1&baseUrl=https%3A%2F%2Fexample.invalid&clientId=id&secret=s&routeDn=rcv2",
		"pd_session=" + a.cookie, a.csrf)), 200);
	ASSERT_EQ(statusOf(httpRaw(_port, "POST", "/api/telephony-config/1/activate", "",
		"pd_session=" + a.cookie, a.csrf)), 200);

	std::string resp = httpRaw(_port, "POST", "/api/telephony-config/1/test", "",
	                           "pd_session=" + a.cookie, a.csrf);
	ASSERT_EQ(statusOf(resp), 200);
	std::string body = bodyOf(resp);
	EXPECT_NE(body.find("\"ok\":true"), std::string::npos) << body;
	EXPECT_NE(body.find("\"participantId\":\"mock-part-123\""), std::string::npos) << body;

	auto* loopback = dynamic_cast<LoopbackAnchorClient*>(_handler->anchorClientForTest());
	ASSERT_NE(loopback, nullptr);
	EXPECT_EQ(loopback->lastMakeCallDestination(), "rcv2")
		<< "the test dial must self-dial the active slot's own routeDn";
}

TEST_F(TelephonyConfigHttpTest, TestDialRefusesANonActiveSlotWithoutCallingTheAnchor)
{
	AdminSession a = loginOn(_port);
	ASSERT_EQ(statusOf(httpRaw(_port, "PUT", "/api/telephony-config/0",
		"enabled=1&baseUrl=https%3A%2F%2Fexample.invalid&clientId=id&secret=s&routeDn=100",
		"pd_session=" + a.cookie, a.csrf)), 200);
	// Slot 0 is configured but never activated -- activeSlot() still names
	// whatever it defaulted to (or nothing), so testing slot 0 must refuse.
	std::string resp = httpRaw(_port, "POST", "/api/telephony-config/0/test", "",
	                           "pd_session=" + a.cookie, a.csrf);
	ASSERT_EQ(statusOf(resp), 200);
	std::string body = bodyOf(resp);
	EXPECT_NE(body.find("\"ok\":false"), std::string::npos) << body;
	EXPECT_NE(body.find("not the active"), std::string::npos) << body;

	auto* loopback = dynamic_cast<LoopbackAnchorClient*>(_handler->anchorClientForTest());
	ASSERT_NE(loopback, nullptr);
	EXPECT_TRUE(loopback->lastMakeCallDestination().empty())
		<< "a refused test-dial must never reach the anchor client at all";
}

TEST_F(TelephonyConfigHttpTest, TestDialRejectsCrossOriginAndRequiresCsrf)
{
	AdminSession a = loginOn(_port);
	ASSERT_EQ(statusOf(httpRaw(_port, "PUT", "/api/telephony-config/1",
		"enabled=1&baseUrl=https%3A%2F%2Fexample.invalid&clientId=id&secret=s&routeDn=rcv2",
		"pd_session=" + a.cookie, a.csrf)), 200);
	ASSERT_EQ(statusOf(httpRaw(_port, "POST", "/api/telephony-config/1/activate", "",
		"pd_session=" + a.cookie, a.csrf)), 200);

	EXPECT_EQ(statusOf(httpRaw(_port, "POST", "/api/telephony-config/1/test", "",
	                           "", "", "http://evil.example")), 403);
	EXPECT_EQ(statusOf(httpRaw(_port, "POST", "/api/telephony-config/1/test", "",
	                           "pd_session=" + a.cookie)), 403);

	auto* loopback = dynamic_cast<LoopbackAnchorClient*>(_handler->anchorClientForTest());
	ASSERT_NE(loopback, nullptr);
	EXPECT_TRUE(loopback->lastMakeCallDestination().empty())
		<< "neither cross-origin rejection above should have placed a call";
}

TEST_F(TelephonyConfigHttpTest, DeleteClearsSlotAndSubsequentGetShowsItCleared)
{
	AdminSession a = loginOn(_port);
	ASSERT_EQ(statusOf(httpRaw(_port, "PUT", "/api/telephony-config/0",
		"enabled=1&baseUrl=https%3A%2F%2Fexample.invalid&clientId=abc123&secret=top-secret-value&routeDn=100",
		"pd_session=" + a.cookie, a.csrf)), 200);
	ASSERT_TRUE(_handler->getTelephonyConfigSlot(0).secretSet);

	std::string del = httpRaw(_port, "DELETE", "/api/telephony-config/0", "",
	                          "pd_session=" + a.cookie, a.csrf);
	ASSERT_EQ(statusOf(del), 200);
	std::string delBody = bodyOf(del);
	EXPECT_EQ(delBody.find("top-secret-value"), std::string::npos);
	EXPECT_NE(delBody.find("\"secretSet\":false"), std::string::npos);

	std::string list = httpGet(_port, "/api/telephony-config", "pd_session=" + a.cookie);
	std::string listBody = bodyOf(list);
	size_t idx0 = listBody.find("\"index\":0");
	ASSERT_NE(idx0, std::string::npos);
	size_t idx0End = listBody.find('}', idx0);
	std::string slot0 = listBody.substr(idx0, idx0End - idx0);
	EXPECT_NE(slot0.find("\"secretSet\":false"), std::string::npos) << slot0;
	EXPECT_NE(slot0.find("\"clientId\":\"\""), std::string::npos) << slot0;
}

TEST_F(TelephonyConfigHttpTest, DeleteOutOfRangeSlotIndexIs400ViaClearSlotsOwnBoundCheck)
{
	AdminSession a = loginOn(_port);
	// TelephonyApiConfig::kSlots == 4, so index 4 is out of range -- same
	// single-source-of-truth bound check as the PUT/out-of-range test above,
	// this time via clearSlot() rather than setSlot().
	std::string resp = httpRaw(_port, "DELETE", "/api/telephony-config/4", "",
	                           "pd_session=" + a.cookie, a.csrf);
	EXPECT_EQ(statusOf(resp), 400);
	EXPECT_NE(bodyOf(resp).find("Bad slot index"), std::string::npos) << bodyOf(resp);
}

TEST_F(TelephonyConfigHttpTest, DeleteSlotRejectsCrossOriginAndRequiresCsrf)
{
	AdminSession a = loginOn(_port);
	ASSERT_EQ(statusOf(httpRaw(_port, "PUT", "/api/telephony-config/0",
		"enabled=1&baseUrl=https%3A%2F%2Fexample.invalid&clientId=id&secret=s&routeDn=100",
		"pd_session=" + a.cookie, a.csrf)), 200);

	EXPECT_EQ(statusOf(httpRaw(_port, "DELETE", "/api/telephony-config/0", "",
	                           "", "", "http://evil.example")), 403);
	// Cookie but no CSRF token -> 403, same contract as every other mutating endpoint.
	EXPECT_EQ(statusOf(httpRaw(_port, "DELETE", "/api/telephony-config/0", "",
	                           "pd_session=" + a.cookie)), 403);
	// Neither cross-origin rejection above should have cleared the slot.
	EXPECT_TRUE(_handler->getTelephonyConfigSlot(0).secretSet);

	EXPECT_EQ(statusOf(httpRaw(_port, "DELETE", "/api/telephony-config/0", "",
	                           "pd_session=" + a.cookie, a.csrf)), 200);
}

TEST_F(TelephonyConfigHttpTest, FactoryResetWipesTelephonyConfigAndDidMapping)
{
	AdminSession a = loginOn(_port);

	// Populate both bounded tables the factory-reset audit found untouched:
	// a live carrier credential slot and a DID -> extension mapping.
	ASSERT_EQ(statusOf(httpRaw(_port, "PUT", "/api/telephony-config/0",
		"enabled=1&baseUrl=https%3A%2F%2Fexample.invalid&clientId=abc123&secret=top-secret-value&routeDn=100",
		"pd_session=" + a.cookie, a.csrf)), 200);
	ASSERT_EQ(statusOf(httpRaw(_port, "PUT", "/api/did-mapping",
		"did=%2B1555&extension=101", "pd_session=" + a.cookie, a.csrf)), 200);
	ASSERT_TRUE(_handler->getTelephonyConfigSlot(0).secretSet);
	ASSERT_EQ(_handler->getDidMappings().size(), 1u);

	// A third table with the same "own NVS namespace, not touched by
	// storage/pbxcfg erases" shape: the CDR call-history ring (cdrlog).
	_handler->recordCallForTest("1001", "1002");
	ASSERT_FALSE(_handler->cdrSnapshotForTest().empty());

	// Trigger factory reset (confirm=ERASE, same admin+CSRF gate as every
	// other mutating route). The HTTP status itself is platform-dependent
	// (501 "not available on desktop" off ESP+WiFi -- see
	// HttpServer::sendApiFactoryReset), but AdminAuth::clearCredential()/
	// DeviceConfig::clearAll() and the Telephony/DID/CDR tables all clear
	// unconditionally BEFORE that platform branch, so the actual wipe is
	// host-testable regardless of the status code returned here.
	httpRaw(_port, "POST", "/api/factory-reset", "confirm=ERASE",
	        "pd_session=" + a.cookie, a.csrf);

	EXPECT_FALSE(_handler->getTelephonyConfigSlot(0).secretSet)
		<< "factory reset must wipe the Telephony-API credential table (tapicfg)";
	EXPECT_TRUE(_handler->getDidMappings().empty())
		<< "factory reset must wipe the DID -> extension table (didmap)";
	EXPECT_TRUE(_handler->cdrSnapshotForTest().empty())
		<< "factory reset must wipe the CDR call-history ring (cdrlog)";
}

TEST_F(TelephonyConfigHttpTest, MutatingRoutesRejectCrossOriginAndRequireCsrf)
{
	AdminSession a = loginOn(_port);

	EXPECT_EQ(statusOf(httpRaw(_port, "PUT", "/api/telephony-config/0", "enabled=0",
	                           "", "", "http://evil.example")), 403);
	EXPECT_EQ(statusOf(httpRaw(_port, "POST", "/api/telephony-config/0/activate", "",
	                           "", "", "http://evil.example")), 403);

	// Cookie but no CSRF token -> 403 (the cookie alone is not enough once
	// provisioned, same contract as every other mutating endpoint).
	EXPECT_EQ(statusOf(httpRaw(_port, "PUT", "/api/telephony-config/0", "enabled=0",
	                           "pd_session=" + a.cookie)), 403);

	// Cookie + CSRF -> 200.
	EXPECT_EQ(statusOf(httpRaw(_port, "PUT", "/api/telephony-config/0",
		"enabled=0&baseUrl=&clientId=&secret=&routeDn=",
		"pd_session=" + a.cookie, a.csrf)), 200);
}

// ── DID -> extension mapping ───────────────────────────────────────────────────

TEST_F(TelephonyConfigHttpTest, DidMappingListStartsEmpty)
{
	AdminSession a = loginOn(_port);
	std::string resp = httpGet(_port, "/api/did-mapping", "pd_session=" + a.cookie);
	ASSERT_EQ(statusOf(resp), 200);
	EXPECT_NE(bodyOf(resp).find("\"mappings\":[]"), std::string::npos) << bodyOf(resp);
}

TEST_F(TelephonyConfigHttpTest, PutAddsMapping_PlusEncodedPlusRoundTrips)
{
	AdminSession a = loginOn(_port);
	// %2B is a literal '+' -- application/x-www-form-urlencoded treats a bare
	// '+' as a space, so a real E.164 DID must percent-encode it (same contract
	// every other form field in this codebase already has via urlDecode()).
	std::string put = httpRaw(_port, "PUT", "/api/did-mapping",
		"did=%2B15551234567&extension=101", "pd_session=" + a.cookie, a.csrf);
	ASSERT_EQ(statusOf(put), 200);
	EXPECT_NE(bodyOf(put).find("\"did\":\"+15551234567\""), std::string::npos) << bodyOf(put);
	EXPECT_NE(bodyOf(put).find("\"extension\":\"101\""), std::string::npos);

	std::string list = httpGet(_port, "/api/did-mapping", "pd_session=" + a.cookie);
	EXPECT_NE(bodyOf(list).find("\"did\":\"+15551234567\""), std::string::npos);
}

TEST_F(TelephonyConfigHttpTest, ReservedAndUnsafeExtensionsAreRejected)
{
	AdminSession a = loginOn(_port);
	EXPECT_EQ(statusOf(httpRaw(_port, "PUT", "/api/did-mapping",
		"did=%2B1555&extension=777", "pd_session=" + a.cookie, a.csrf)), 400);
	EXPECT_EQ(statusOf(httpRaw(_port, "PUT", "/api/did-mapping",
		"did=%2B1555&extension=888", "pd_session=" + a.cookie, a.csrf)), 400);
	EXPECT_EQ(statusOf(httpRaw(_port, "PUT", "/api/did-mapping",
		"did=%2B1555&extension=1a%24", "pd_session=" + a.cookie, a.csrf)), 400)
		<< "'$' is outside pbx::isDialTokenSafe's charset";

	// A real extension still works.
	EXPECT_EQ(statusOf(httpRaw(_port, "PUT", "/api/did-mapping",
		"did=%2B1555&extension=101", "pd_session=" + a.cookie, a.csrf)), 200);
}

TEST_F(TelephonyConfigHttpTest, TableFullRejectsNinthDidButUpdateStillSucceeds)
{
	AdminSession a = loginOn(_port);
	// POCKETDIAL_MAX_DID_MAPPINGS defaults to 8.
	for (int i = 0; i < 8; ++i)
	{
		std::string did = "did=%2B1555000" + std::to_string(i) + "&extension=1" + std::to_string(i);
		ASSERT_EQ(statusOf(httpRaw(_port, "PUT", "/api/did-mapping", did,
			"pd_session=" + a.cookie, a.csrf)), 200) << i;
	}

	// A 9th, genuinely new DID is refused.
	std::string full = httpRaw(_port, "PUT", "/api/did-mapping",
		"did=%2B15559999&extension=199", "pd_session=" + a.cookie, a.csrf);
	EXPECT_EQ(statusOf(full), 400);
	EXPECT_NE(bodyOf(full).find("table full"), std::string::npos) << bodyOf(full);

	// But editing an EXISTING did's extension still succeeds on a full table.
	std::string update = httpRaw(_port, "PUT", "/api/did-mapping",
		"did=%2B15550000&extension=150", "pd_session=" + a.cookie, a.csrf);
	EXPECT_EQ(statusOf(update), 200);
}

TEST_F(TelephonyConfigHttpTest, DeleteIsIdempotentAndRemovesFromList)
{
	AdminSession a = loginOn(_port);
	ASSERT_EQ(statusOf(httpRaw(_port, "PUT", "/api/did-mapping",
		"did=%2B1555&extension=101", "pd_session=" + a.cookie, a.csrf)), 200);

	std::string del1 = httpRaw(_port, "DELETE", "/api/did-mapping", "did=%2B1555",
	                           "pd_session=" + a.cookie, a.csrf);
	EXPECT_EQ(statusOf(del1), 200);

	std::string list = httpGet(_port, "/api/did-mapping", "pd_session=" + a.cookie);
	EXPECT_EQ(bodyOf(list).find("+1555"), std::string::npos);

	// Deleting again (already gone) is still 200, not an error.
	std::string del2 = httpRaw(_port, "DELETE", "/api/did-mapping", "did=%2B1555",
	                           "pd_session=" + a.cookie, a.csrf);
	EXPECT_EQ(statusOf(del2), 200);
}

TEST_F(TelephonyConfigHttpTest, DidMappingMutationsRejectCrossOriginAndRequireCsrf)
{
	AdminSession a = loginOn(_port);

	EXPECT_EQ(statusOf(httpRaw(_port, "PUT", "/api/did-mapping", "did=%2B1555&extension=101",
	                           "", "", "http://evil.example")), 403);
	EXPECT_EQ(statusOf(httpRaw(_port, "DELETE", "/api/did-mapping", "did=%2B1555",
	                           "", "", "http://evil.example")), 403);

	EXPECT_EQ(statusOf(httpRaw(_port, "PUT", "/api/did-mapping", "did=%2B1555&extension=101",
	                           "pd_session=" + a.cookie)), 403);

	EXPECT_EQ(statusOf(httpRaw(_port, "PUT", "/api/did-mapping", "did=%2B1555&extension=101",
	                           "pd_session=" + a.cookie, a.csrf)), 200);
}
