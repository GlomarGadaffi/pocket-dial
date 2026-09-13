// AdminHttpGate_test.cpp — HttpServer's listen socket always accepts
// connections (a real hardware regression: a "dark by default once
// provisioned, DTMF-star-code-to-reopen" gate used to close the socket
// entirely, which meant the dashboard went unreachable ["connection
// refused"] the moment any client registered and the device counted itself
// as provisioned). Removed: the admin-facing session/credential gate
// (requireAdmin, tested in the WebHardening/Registrar suites below) is the
// intended authentication layer, not the raw socket.
//
// Also covers the credential model itself: a shipped default login
// (AdminAuth::kDefaultUsername/kDefaultPassword) that works until
// setLoginCredential() is called, and a separate DTMF admin PIN with no
// default at all (see the AdminAuth-suite tests below).

#include <gtest/gtest.h>
#include "HttpServer.hpp"
#include "RequestsHandler.hpp"
#include "SipMessage.hpp"
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
#include <thread>

namespace
{
	// True iff a TCP connect to 127.0.0.1:port succeeds within the OS's default
	// connect timeout. Used to observe HttpServer's actual listen state from the
	// outside, the same way a real admin browser would.
	bool canConnect(int port)
	{
#if defined(_WIN32) || defined(_WIN64)
		SOCKET s = socket(AF_INET, SOCK_STREAM, 0);
		if (s == INVALID_SOCKET) return false;
#else
		int s = socket(AF_INET, SOCK_STREAM, 0);
		if (s < 0) return false;
#endif
		sockaddr_in addr{};
		addr.sin_family = AF_INET;
		addr.sin_port = htons(static_cast<uint16_t>(port));
		inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
		int rc = connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
#if defined(_WIN32) || defined(_WIN64)
		closesocket(s);
#else
		close(s);
#endif
		return rc == 0;
	}

	// Minimal blocking HTTP POST over a raw socket. Returns the full raw
	// response (status line + headers + body) so callers can extract a
	// Set-Cookie value, or just the status code. `cookie`, if non-empty, is
	// sent as a Cookie header. Used to drive HttpServer's real endpoints
	// end-to-end rather than just AdminAuth directly.
	std::string httpPostRaw(int port, const std::string& path, const std::string& body,
	                        const std::string& cookie = "",
	                        const std::string& csrf = "",
	                        const std::string& origin = "")
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
		std::string req = "POST " + path + " HTTP/1.1\r\n"
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

	// GET counterpart of httpPostRaw. `origin`, when set, exercises the
	// same-origin gate that the read endpoints (/api/pcap and friends) were
	// previously missing.
	std::string httpGetRaw(int port, const std::string& path,
	                       const std::string& cookie = "",
	                       const std::string& origin = "")
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
		std::string originHeader = origin.empty() ? "" : ("Origin: " + origin + "\r\n");
		std::string req = "GET " + path + " HTTP/1.1\r\n"
			"Host: 127.0.0.1\r\n" +
			cookieHeader + originHeader +
			"Connection: close\r\n\r\n";
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

	// Pulls the per-session CSRF token out of the login response body
	// ({"status":"ok","authenticated":true,"csrf":"<32 hex>"}).
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

	int statusOf(const std::string& resp)
	{
		size_t sp1 = resp.find(' ');
		if (sp1 == std::string::npos) return -1;
		size_t sp2 = resp.find(' ', sp1 + 1);
		if (sp2 == std::string::npos) return -1;
		return std::atoi(resp.substr(sp1 + 1, sp2 - sp1 - 1).c_str());
	}

	// Extracts just the VALUE from a "Set-Cookie: name=value; ..." response
	// header, empty if absent.
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

	int httpPostStatus(int port, const std::string& path, const std::string& body)
	{
		return statusOf(httpPostRaw(port, path, body));
	}

}

// ── Boot behavior ────────────────────────────────────────────────────────────

TEST(AdminHttpGate, Boot_Unprovisioned_ListensImmediately)
{
	AdminAuth::clearCredential();
	ASSERT_FALSE(AdminAuth::isProvisioned());

	HttpServer server("127.0.0.1", 18080, nullptr);
	server.start();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));
	EXPECT_TRUE(canConnect(18080));
}

TEST(AdminHttpGate, Boot_Provisioned_StillListensImmediately)
{
	// Regression pin for a real hardware bug: the dashboard used to go dark
	// ("connection refused") the instant a device counted itself provisioned
	// (e.g. any client registering), requiring a DTMF star-code from a specific
	// extension to reopen it. The socket must now accept connections
	// unconditionally; requireAdmin()'s per-route session/credential check is
	// what actually gates admin actions once a client can reach the page.
	AdminAuth::clearCredential();
	ASSERT_TRUE(AdminAuth::setLoginCredential("admin", "realpassword123"));
	ASSERT_TRUE(AdminAuth::isProvisioned());

	HttpServer server("127.0.0.1", 18081, nullptr);
	server.start();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));
	EXPECT_TRUE(canConnect(18081));

	AdminAuth::clearCredential();
}

TEST(AdminHttpGate, SetCredential_DoesNotAffectReachability)
{
	AdminAuth::clearCredential();
	ASSERT_FALSE(AdminAuth::isProvisioned());

	RequestsHandler handler("192.168.4.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	HttpServer server("127.0.0.1", 18083, nullptr);
	server.attachHandler(&handler);
	server.start();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));
	ASSERT_TRUE(canConnect(18083));

	std::string loginResp = httpPostRaw(18083, "/api/admin/login", "username=admin&password=admin");
	ASSERT_EQ(statusOf(loginResp), 200);
	std::string cookie = cookieOf(loginResp, "pd_session");
	std::string csrf = csrfOf(loginResp);
	ASSERT_EQ(statusOf(httpPostRaw(18083, "/api/admin/set-credential",
		"username=admin&password=realpassword123", "pd_session=" + cookie, csrf)), 200);
	ASSERT_TRUE(AdminAuth::isProvisioned());
	EXPECT_TRUE(canConnect(18083));

	AdminAuth::clearCredential();
}

// ─────────────────────────────────────────────────────────────────────────────
// The default login credential + forced initial setup. AdminAuth-level (no
// HTTP round trip needed — see WebHardening below for the HTTP-layer
// enforcement) and the independent DTMF PIN, which has no default at all.
// ─────────────────────────────────────────────────────────────────────────────

TEST(AdminAuth, DefaultCredentialWorksUntilARealOneIsSet)
{
	AdminAuth::clearCredential();
	ASSERT_FALSE(AdminAuth::isProvisioned());
	ASSERT_TRUE(AdminAuth::needsInitialSetup());

	EXPECT_TRUE(AdminAuth::verifyCredential(AdminAuth::kDefaultUsername,
		AdminAuth::kDefaultPassword, "20.0.0.1"));
	EXPECT_FALSE(AdminAuth::verifyCredential(AdminAuth::kDefaultUsername, "wrong", "20.0.0.2"));

	ASSERT_TRUE(AdminAuth::setLoginCredential("boss", "realpassword123"));
	EXPECT_TRUE(AdminAuth::isProvisioned());
	EXPECT_FALSE(AdminAuth::needsInitialSetup());
	EXPECT_FALSE(AdminAuth::verifyCredential(AdminAuth::kDefaultUsername,
		AdminAuth::kDefaultPassword, "20.0.0.3"))
		<< "the default must stop working the instant a real credential is set";
	EXPECT_TRUE(AdminAuth::verifyCredential("boss", "realpassword123", "20.0.0.4"));

	AdminAuth::clearCredential();
	EXPECT_TRUE(AdminAuth::needsInitialSetup())
		<< "factory reset must return the device to the default-credential state";
}

TEST(AdminAuth, SetLoginCredentialRejectsOutOfBoundsFields)
{
	AdminAuth::clearCredential();
	EXPECT_FALSE(AdminAuth::setLoginCredential("", "realpassword123")) << "empty username";
	EXPECT_FALSE(AdminAuth::setLoginCredential("admin", "short")) << "password under the minimum length";
	EXPECT_FALSE(AdminAuth::setLoginCredential("bad user", "realpassword123")) << "whitespace in username";
	EXPECT_FALSE(AdminAuth::isProvisioned()) << "every rejected call above must be a no-op";
	AdminAuth::clearCredential();
}

TEST(AdminAuth, DtmfPinHasNoDefaultAndStaysDisabledUntilSet)
{
	AdminAuth::clearCredential();
	EXPECT_FALSE(AdminAuth::dtmfPinIsSet());
	EXPECT_FALSE(AdminAuth::verifyDtmfPin("0000")) << "no default -- an all-zero guess must not work";
	EXPECT_FALSE(AdminAuth::verifyDtmfPin(""));

	ASSERT_TRUE(AdminAuth::setDtmfPin("4321"));
	EXPECT_TRUE(AdminAuth::dtmfPinIsSet());
	EXPECT_TRUE(AdminAuth::verifyDtmfPin("4321"));
	EXPECT_FALSE(AdminAuth::verifyDtmfPin("0000"));

	AdminAuth::clearCredential();
	EXPECT_FALSE(AdminAuth::dtmfPinIsSet()) << "factory reset must wipe the DTMF PIN too";
}

TEST(AdminAuth, SetDtmfPinRejectsNonDigitsOrOutOfBoundsLength)
{
	AdminAuth::clearCredential();
	EXPECT_FALSE(AdminAuth::setDtmfPin("12a4")) << "letters aren't reachable from a phone keypad";
	EXPECT_FALSE(AdminAuth::setDtmfPin("123")) << "under the minimum length";
	EXPECT_TRUE(AdminAuth::setDtmfPin("123456"));
	AdminAuth::clearCredential();
}

// ─────────────────────────────────────────────────────────────────────────────
// CSRF tokens, the centralised gate, and the security headers.
//
// The same-origin check admits a request with NO Origin header by design (curl,
// native clients and tests/http/test_api.sh send none), so on a provisioned
// device it is the per-session token — rendered into the page, never set as a
// cookie — that actually stops a same-site page from driving mutating calls.
// ─────────────────────────────────────────────────────────────────────────────

namespace
{
	// Log in with the shipped default credential, then immediately complete
	// setup with a real one -- requireAdmin() refuses every other admin-gated
	// route (including the ones under test here) while needsInitialSetup() is
	// true, and setLoginCredential() does not invalidate the session it was
	// called through, so the same cookie/csrf pair keeps working afterward.
	struct AdminSession { std::string cookie; std::string csrf; };

	AdminSession loginAndCompleteSetup(int port)
	{
		AdminSession a;
		std::string loginResp = httpPostRaw(port, "/api/admin/login",
			"username=admin&password=admin");
		EXPECT_EQ(statusOf(loginResp), 200);
		a.cookie = cookieOf(loginResp, "pd_session");
		a.csrf   = csrfOf(loginResp);

		std::string setupResp = httpPostRaw(port, "/api/admin/set-credential",
			"username=admin&password=realpassword123",
			"pd_session=" + a.cookie, a.csrf);
		EXPECT_EQ(statusOf(setupResp), 200);
		return a;
	}
}

TEST(WebHardening, Csrf_MissingToken_Rejected403)
{
	AdminAuth::clearCredential();
	RequestsHandler handler("192.168.4.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	HttpServer server("127.0.0.1", 18090, nullptr);
	server.attachHandler(&handler);
	server.start();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));

	AdminSession a = loginAndCompleteSetup(18090);

	// A valid session but no token: the cookie alone must not be enough.
	std::string resp = httpPostRaw(18090, "/api/ap-security", "regenerate=1",
	                               "pd_session=" + a.cookie);
	EXPECT_EQ(statusOf(resp), 403);

	AdminAuth::clearCredential();
}

TEST(WebHardening, Csrf_WrongToken_Rejected403)
{
	AdminAuth::clearCredential();
	RequestsHandler handler("192.168.4.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	HttpServer server("127.0.0.1", 18091, nullptr);
	server.attachHandler(&handler);
	server.start();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));

	AdminSession a = loginAndCompleteSetup(18091);

	std::string resp = httpPostRaw(18091, "/api/ap-security", "regenerate=1",
	                               "pd_session=" + a.cookie,
	                               "00000000000000000000000000000000");
	EXPECT_EQ(statusOf(resp), 403);

	AdminAuth::clearCredential();
}

TEST(WebHardening, Csrf_ValidToken_Accepted)
{
	AdminAuth::clearCredential();
	RequestsHandler handler("192.168.4.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	HttpServer server("127.0.0.1", 18092, nullptr);
	server.attachHandler(&handler);
	server.start();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));

	AdminSession a = loginAndCompleteSetup(18092);
	ASSERT_EQ(a.csrf.size(), AdminAuth::kCsrfTokenHex);

	std::string resp = httpPostRaw(18092, "/api/ap-security", "regenerate=1",
	                               "pd_session=" + a.cookie, a.csrf);
	EXPECT_EQ(statusOf(resp), 200);

	AdminAuth::clearCredential();
}

TEST(WebHardening, ConfiguringRequiresLoginThenSetupCompletion)
{
	// /api/configuring moves device state on a POST, so it takes the standard
	// admin gate like everything else: no session at all -> 401; a session on
	// the still-default credential -> 403 setup_required; only after
	// completing setup does it succeed. (Supersedes the old
	// Csrf_NotRequiredWhileUnprovisioned/Configuring_GatedOnceProvisioned pair
	// now that there is no more unauthenticated onboarding window at all --
	// the default credential IS the onboarding window.)
	AdminAuth::clearCredential();
	RequestsHandler handler("192.168.4.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	HttpServer server("127.0.0.1", 18093, nullptr);
	server.attachHandler(&handler);
	server.start();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));

	EXPECT_EQ(httpPostStatus(18093, "/api/configuring", ""), 401);

	std::string loginResp = httpPostRaw(18093, "/api/admin/login", "username=admin&password=admin");
	ASSERT_EQ(statusOf(loginResp), 200);
	std::string cookie = cookieOf(loginResp, "pd_session");
	std::string csrf = csrfOf(loginResp);

	EXPECT_EQ(statusOf(httpPostRaw(18093, "/api/configuring", "", "pd_session=" + cookie, csrf)), 403)
		<< "logged in on the default credential, but setup is not complete yet";

	ASSERT_EQ(statusOf(httpPostRaw(18093, "/api/admin/set-credential",
		"username=admin&password=realpassword123", "pd_session=" + cookie, csrf)), 200);

	EXPECT_EQ(statusOf(httpPostRaw(18093, "/api/configuring", "", "pd_session=" + cookie, csrf)), 200);

	AdminAuth::clearCredential();
}

TEST(WebHardening, PcapAndTrace_RejectCrossOrigin)
{
	// Regression: these three served raw SIP bytes — Contact URIs, User-Agent
	// strings and Authorization digests — with a session check but no
	// same-origin check, because each route open-coded its own gate and this one
	// clause was missed. They now go through requireAdmin like everything else.
	AdminAuth::clearCredential();
	RequestsHandler handler("192.168.4.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	HttpServer server("127.0.0.1", 18094, nullptr);
	server.attachHandler(&handler);
	server.start();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));

	// The same-origin check (requireAdmin step 1) runs before the session
	// check, so a cross-origin request is rejected whether or not a session
	// cookie is even presented.
	const std::string evil = "http://evil.example";
	EXPECT_EQ(statusOf(httpGetRaw(18094, "/api/pcap", "", evil)), 403);
	EXPECT_EQ(statusOf(httpGetRaw(18094, "/api/trace", "", evil)), 403);
	EXPECT_EQ(statusOf(httpGetRaw(18094, "/api/diagnostics/pcap", "", evil)), 403);

	// Same-origin (no Origin header at all) reaches the session check next —
	// needs a real, fully-set-up login to get all the way through to the
	// handler and see 200.
	AdminSession a = loginAndCompleteSetup(18094);
	EXPECT_EQ(statusOf(httpGetRaw(18094, "/api/trace", "pd_session=" + a.cookie)), 200);

	AdminAuth::clearCredential();
}

TEST(WebHardening, SecurityHeadersOnEveryResponse)
{
	AdminAuth::clearCredential();
	HttpServer server("127.0.0.1", 18096, nullptr);
	server.start();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));

	// A read endpoint and an error response: the headers are emitted centrally in
	// sendResponseWithHeader, so both must carry them.
	const std::string ok  = httpGetRaw(18096, "/api/status");
	const std::string err = httpGetRaw(18096, "/api/pcap", "", "http://evil.example");

	for (const std::string* r : {&ok, &err})
	{
		EXPECT_NE(r->find("Content-Security-Policy:"), std::string::npos);
		EXPECT_NE(r->find("X-Frame-Options: DENY"), std::string::npos);
		EXPECT_NE(r->find("X-Content-Type-Options: nosniff"), std::string::npos);
		EXPECT_NE(r->find("Cache-Control: no-store"), std::string::npos);
		EXPECT_NE(r->find("Referrer-Policy: same-origin"), std::string::npos);
		// No HSTS: the dashboard is plain HTTP on a LAN appliance, and pinning it
		// would make the host permanently unreachable over http://.
		EXPECT_EQ(r->find("Strict-Transport-Security"), std::string::npos);
	}

	AdminAuth::clearCredential();
}

TEST(WebHardening, LockoutCounterDoesNotResetOnTrip)
{
	// Regression: verifyCredential used to zero the failure counter when the
	// lockout engaged, so every cooldown handed the attacker a fresh window of
	// kMaxFailedAttempts — a steady ~5 guesses/minute for as long as they cared
	// to keep going. The trip count now survives, so each lockout is longer than
	// the last and only a correct credential clears it.
	AdminAuth::clearCredential();
	ASSERT_TRUE(AdminAuth::setLoginCredential("admin", "realpassword123"));

	for (int i = 0; i < AdminAuth::kMaxFailedAttempts; ++i)
	{
		EXPECT_FALSE(AdminAuth::verifyCredential("admin", "000000", "10.0.0.1"));
	}
	EXPECT_TRUE(AdminAuth::isLockedOut("10.0.0.1"));

	// Even the correct credential is refused while the cooldown is engaged.
	EXPECT_FALSE(AdminAuth::verifyCredential("admin", "realpassword123", "10.0.0.1"));

	// ...and a different client is unaffected, which is the point of keying the
	// buckets: one guesser must not lock the real admin out of new logins.
	EXPECT_FALSE(AdminAuth::isLockedOut("10.0.0.2"));
	EXPECT_TRUE(AdminAuth::verifyCredential("admin", "realpassword123", "10.0.0.2"));

	AdminAuth::clearCredential();
}

TEST(WebHardening, GlobalBackstopBoundsSpoofedSourceAddresses)
{
	// Per-client buckets on their own would be a REGRESSION on a shared link:
	// a source address is trivially spoofable, so an attacker who rotates
	// addresses would get a fresh bucket — and a fresh escalation ladder — every
	// five guesses, which is a better position than the single global counter
	// this replaced. The aggregate backstop is what makes per-client accounting
	// safe to have: it bounds the total guess rate regardless of how many
	// identities the attacker invents.
	AdminAuth::clearCredential();
	ASSERT_TRUE(AdminAuth::setLoginCredential("admin", "realpassword123"));

	// Burn the aggregate budget across several distinct "clients". Each one trips
	// its own bucket after kMaxFailedAttempts, so this is exactly the pattern a
	// spoofing attacker would use to sidestep per-client accounting.
	const int clients = AdminAuth::kMaxFailedAttemptsGlobal / AdminAuth::kMaxFailedAttempts;
	for (int c = 0; c < clients; ++c)
	{
		const std::string ip = "10.1.1." + std::to_string(c + 1);
		for (int i = 0; i < AdminAuth::kMaxFailedAttempts; ++i)
		{
			EXPECT_FALSE(AdminAuth::verifyCredential("admin", "000000", ip));
		}
	}

	// A brand-new address, with an empty bucket of its own, is refused anyway.
	EXPECT_TRUE(AdminAuth::isLockedOut("10.9.9.9"));
	EXPECT_FALSE(AdminAuth::verifyCredential("admin", "realpassword123", "10.9.9.9"));

	AdminAuth::clearCredential();
}

TEST(WebHardening, GlobalBackstopSitsWellAboveOrdinaryTypos)
{
	// The backstop must not resurrect the D-3 self-DoS: an operator fumbling
	// their password a handful of times must never lock the whole device. Only
	// that one client's short cooldown may engage.
	ASSERT_GT(AdminAuth::kMaxFailedAttemptsGlobal, AdminAuth::kMaxFailedAttempts);

	AdminAuth::clearCredential();
	ASSERT_TRUE(AdminAuth::setLoginCredential("admin", "realpassword123"));

	for (int i = 0; i < AdminAuth::kMaxFailedAttempts; ++i)
	{
		EXPECT_FALSE(AdminAuth::verifyCredential("admin", "000000", "10.2.2.1"));
	}
	EXPECT_TRUE(AdminAuth::isLockedOut("10.2.2.1"));
	// Everyone else is still free to log in.
	EXPECT_FALSE(AdminAuth::isLockedOut("10.2.2.2"));
	EXPECT_TRUE(AdminAuth::verifyCredential("admin", "realpassword123", "10.2.2.2"));

	AdminAuth::clearCredential();
}

// ─────────────────────────────────────────────────────────────────────────────
// Registrar admission mode + Learn-mode extension onboarding.
//
// Regression context: RequestsHandler::setRegistrarMode() was reachable ONLY
// from unit tests. SIP digest authentication was fully implemented, fully
// tested, and completely unreachable on a shipped device, because nothing in
// production ever wrote the persisted mode. These endpoints are what close that.
// ─────────────────────────────────────────────────────────────────────────────

// loginAndCompleteSetup() (defined above, in the WebHardening section) is
// reused here too: log in with the default credential, then complete initial
// setup, returning a session usable for the rest of the test.

TEST(Registrar, ModeRoundTripsThroughTheDashboard)
{
	AdminAuth::clearCredential();
	RequestsHandler handler("192.168.4.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	HttpServer server("127.0.0.1", 18100, nullptr);
	server.attachHandler(&handler);
	server.start();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));

	AdminSession a = loginAndCompleteSetup(18100);
	ASSERT_FALSE(a.cookie.empty());

	// Ships open: POCKETDIAL_OPEN_REGISTRAR seeds the default, and until now
	// nothing could change it.
	std::string get = httpGetRaw(18100, "/api/registrar", "pd_session=" + a.cookie);
	EXPECT_EQ(statusOf(get), 200);
	EXPECT_NE(get.find("\"mode\":\"open\""), std::string::npos);
	EXPECT_NE(get.find("\"attached\":true"), std::string::npos);

	std::string set = httpPostRaw(18100, "/api/registrar", "mode=learn",
	                              "pd_session=" + a.cookie, a.csrf);
	EXPECT_EQ(statusOf(set), 200);
	EXPECT_NE(set.find("\"mode\":\"learn\""), std::string::npos);
	EXPECT_EQ(handler.getRegistrarMode(), RequestsHandler::RegistrarMode::Learn);

	// And it is readable back, not just accepted.
	get = httpGetRaw(18100, "/api/registrar", "pd_session=" + a.cookie);
	EXPECT_NE(get.find("\"mode\":\"learn\""), std::string::npos);

	AdminAuth::clearCredential();
}

TEST(Registrar, SwitchingToSecureWithNothingSecuredNeedsConfirmation)
{
	// The foot-gun this guards: `secure` digest-challenges every REGISTER. On a
	// device that has never run Learn mode, no extension has a secret, so every
	// phone would fail to register at once — and the operator would have no
	// working handset left to notice with.
	AdminAuth::clearCredential();
	RequestsHandler handler("192.168.4.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	HttpServer server("127.0.0.1", 18101, nullptr);
	server.attachHandler(&handler);
	server.start();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));

	AdminSession a = loginAndCompleteSetup(18101);

	std::string blocked = httpPostRaw(18101, "/api/registrar", "mode=secure",
	                                  "pd_session=" + a.cookie, a.csrf);
	EXPECT_EQ(statusOf(blocked), 409);
	EXPECT_EQ(handler.getRegistrarMode(), RequestsHandler::RegistrarMode::Open)
		<< "a refused switch must not have changed the mode";

	std::string forced = httpPostRaw(18101, "/api/registrar",
	                                 "mode=secure&confirm=LOCKOUT",
	                                 "pd_session=" + a.cookie, a.csrf);
	EXPECT_EQ(statusOf(forced), 200);
	EXPECT_EQ(handler.getRegistrarMode(), RequestsHandler::RegistrarMode::Secure);

	AdminAuth::clearCredential();
}

TEST(Registrar, RejectsUnknownModeAndUnknownDevice)
{
	AdminAuth::clearCredential();
	RequestsHandler handler("192.168.4.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	HttpServer server("127.0.0.1", 18102, nullptr);
	server.attachHandler(&handler);
	server.start();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));

	AdminSession a = loginAndCompleteSetup(18102);

	EXPECT_EQ(statusOf(httpPostRaw(18102, "/api/registrar", "mode=wide-open",
	                               "pd_session=" + a.cookie, a.csrf)), 400);
	EXPECT_EQ(statusOf(httpPostRaw(18102, "/api/registrar/device",
	                               "action=secure&target=aabbccddeeff",
	                               "pd_session=" + a.cookie, a.csrf)), 404);
	EXPECT_EQ(statusOf(httpPostRaw(18102, "/api/registrar/device",
	                               "action=explode&target=1001",
	                               "pd_session=" + a.cookie, a.csrf)), 400);
	EXPECT_EQ(statusOf(httpPostRaw(18102, "/api/registrar/device", "action=secure",
	                               "pd_session=" + a.cookie, a.csrf)), 400);

	AdminAuth::clearCredential();
}

TEST(Registrar, MutatingEndpointsRequireTheCsrfToken)
{
	// The registrar mode is the single most security-relevant setting exposed by
	// the dashboard: flipping it to `open` disables SIP authentication entirely.
	// It must not be reachable with a stolen cookie alone.
	AdminAuth::clearCredential();
	RequestsHandler handler("192.168.4.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	HttpServer server("127.0.0.1", 18103, nullptr);
	server.attachHandler(&handler);
	server.start();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));

	AdminSession a = loginAndCompleteSetup(18103);

	EXPECT_EQ(statusOf(httpPostRaw(18103, "/api/registrar", "mode=open",
	                               "pd_session=" + a.cookie)), 403);
	EXPECT_EQ(statusOf(httpPostRaw(18103, "/api/registrar/device",
	                               "action=forget&target=1001",
	                               "pd_session=" + a.cookie)), 403);

	AdminAuth::clearCredential();
}
