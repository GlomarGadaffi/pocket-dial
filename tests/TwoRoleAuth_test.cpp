// TwoRoleAuth_test.cpp — issue #173: owner/sysop two-role privilege model.
//
// Covers both layers:
//   * AdminAuth-level: authenticate() resolving a Role, setOwnerCredential()'s
//     username-collision guard, sessionRole()/sessionSatisfiesRole()'s
//     no-owner-yet fallback, and lockout keyed by (clientKey, principal) so
//     spraying one principal's password cannot lock the other principal out
//     (neither via the per-client bucket nor the per-principal aggregate
//     backstop).
//   * HTTP-level, driven through a real HttpServer/requireAdmin() exactly
//     like AdminHttpGate_test.cpp's WebHardening suite: owner-vs-sysop
//     gating on each of the three owner-only actions named in #173 (factory
//     reset, config export WITH secrets, OTA upload) -- 403 for sysop once
//     an owner exists, 200/expected-success for owner, and the no-owner-yet
//     fallback that keeps a freshly-upgraded single-credential board's sysop
//     able to reach them until an owner account is created.
//
// Ports: this file owns 18130-18149. See CONTRIBUTING_FIRMWARE.md's table.

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
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <thread>

namespace
{
	// Duplicated raw-socket HTTP helpers -- anonymous-namespace helpers don't
	// cross translation units (same note AdminHttpGate_test.cpp and
	// ApiKillParse_test.cpp both carry).
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
		char buf[1024];
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

	// Logs in with the shipped default credential and completes initial setup
	// with a real sysop credential -- requireAdmin() refuses every gated
	// route except /api/admin/set-credential until that's done.
	AdminSession loginSysop(int port, const std::string& user = "admin",
		const std::string& pass = "realpassword123")
	{
		AdminSession a;
		std::string loginResp = httpRaw(port, "POST", "/api/admin/login",
			"username=admin&password=admin");
		EXPECT_EQ(statusOf(loginResp), 200) << loginResp;
		a.cookie = cookieOf(loginResp, "pd_session");
		a.csrf   = csrfOf(loginResp);

		std::string setupResp = httpRaw(port, "POST", "/api/admin/set-credential",
			"username=" + user + "&password=" + pass, "pd_session=" + a.cookie, a.csrf);
		EXPECT_EQ(statusOf(setupResp), 200) << setupResp;
		return a;
	}

	// Creates the owner account (bootstrapped by the sysop session `sysop`,
	// which must already be past initial setup) and logs in AS that owner,
	// returning a fresh owner session.
	AdminSession bootstrapAndLoginOwner(int port, const AdminSession& sysop,
		const std::string& ownerUser = "owner", const std::string& ownerPass = "ownerpass123")
	{
		std::string setResp = httpRaw(port, "POST", "/api/admin/set-owner-credential",
			"ownerUsername=" + ownerUser + "&ownerPassword=" + ownerPass,
			"pd_session=" + sysop.cookie, sysop.csrf);
		EXPECT_EQ(statusOf(setResp), 200) << setResp;

		AdminSession owner;
		std::string loginResp = httpRaw(port, "POST", "/api/admin/login",
			"username=" + ownerUser + "&password=" + ownerPass);
		EXPECT_EQ(statusOf(loginResp), 200) << loginResp;
		owner.cookie = cookieOf(loginResp, "pd_session");
		owner.csrf   = csrfOf(loginResp);
		return owner;
	}

	// setTelephonyStorePathsForTest()'s per-test file paths (same idiom as
	// TelephonyConfigHttp_test.cpp): FactoryReset_* here calls all the way
	// through to clearAllTelephonyConfig()/clearAllDidMappings(), which
	// without this redirect would read/write the SAME default
	// "pocketdial_tapi.cfg"/"pocketdial_didmap.cfg" files in the build cwd
	// every other unredirected test in this binary does -- exactly the
	// order-dependence trap RequestsHandler.hpp's setTelephonyStorePathsForTest
	// doc comment warns about.
	class TwoRoleAuthTest : public ::testing::Test
	{
	protected:
		void SetUp() override
		{
			const std::string name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
			_tapiPath = "test_tworole_tapicfg_" + name + ".cfg";
			_didPath  = "test_tworole_didmap_" + name + ".cfg";
			std::remove(_tapiPath.c_str());
			std::remove(_didPath.c_str());

			AdminAuth::clearCredential();
			_port = _nextPort++;
			_handler = std::make_unique<RequestsHandler>("192.168.4.1", 5060,
				[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
			_handler->setTelephonyStorePathsForTest(_tapiPath, _didPath);
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
		std::unique_ptr<HttpServer> _server;
		std::unique_ptr<RequestsHandler> _handler;
		std::string _tapiPath, _didPath;
		static int _nextPort;
	};
	int TwoRoleAuthTest::_nextPort = 18130;
}

// ── AdminAuth-level: authenticate(), roles, the collision guard ────────────

TEST(TwoRoleAuthCore, AuthenticateResolvesSysopByDefault)
{
	AdminAuth::clearCredential();
	EXPECT_EQ(AdminAuth::authenticate(AdminAuth::kDefaultUsername, AdminAuth::kDefaultPassword, "1.1.1.1"),
		AdminAuth::Role::Sysop);
	EXPECT_EQ(AdminAuth::authenticate(AdminAuth::kDefaultUsername, "wrong", "1.1.1.2"),
		AdminAuth::Role::None);
	AdminAuth::clearCredential();
}

TEST(TwoRoleAuthCore, AuthenticateResolvesOwnerOnceSet)
{
	AdminAuth::clearCredential();
	ASSERT_TRUE(AdminAuth::setLoginCredential("sysop1", "sysoppass123"));
	ASSERT_TRUE(AdminAuth::setOwnerCredential("boss1", "bosspass123"));

	EXPECT_EQ(AdminAuth::authenticate("sysop1", "sysoppass123", "2.2.2.1"), AdminAuth::Role::Sysop);
	EXPECT_EQ(AdminAuth::authenticate("boss1", "bosspass123", "2.2.2.2"), AdminAuth::Role::Owner);
	EXPECT_EQ(AdminAuth::authenticate("boss1", "wrongpass", "2.2.2.3"), AdminAuth::Role::None);
	AdminAuth::clearCredential();
}

TEST(TwoRoleAuthCore, SetOwnerCredentialRejectsCollisionWithSysopUsername)
{
	AdminAuth::clearCredential();
	ASSERT_TRUE(AdminAuth::setLoginCredential("boss", "sysoppass123"));
	// Same username as the sysop's -- must be refused so the two principals
	// stay distinguishable (see AdminAuth::authenticate()'s principal
	// resolution, which depends on this).
	EXPECT_FALSE(AdminAuth::setOwnerCredential("boss", "ownerpass123"));
	EXPECT_FALSE(AdminAuth::isOwnerProvisioned());
	AdminAuth::clearCredential();
}

TEST(TwoRoleAuthCore, ClearCredentialWipesOwnerToo)
{
	AdminAuth::clearCredential();
	ASSERT_TRUE(AdminAuth::setLoginCredential("sysop2", "sysoppass123"));
	ASSERT_TRUE(AdminAuth::setOwnerCredential("boss2", "bosspass123"));
	ASSERT_TRUE(AdminAuth::isOwnerProvisioned());

	AdminAuth::clearCredential();
	EXPECT_FALSE(AdminAuth::isOwnerProvisioned())
		<< "factory reset must return the device to no-owner state, same as it does for the sysop credential";
	EXPECT_EQ(AdminAuth::authenticate("boss2", "bosspass123", "3.3.3.1"), AdminAuth::Role::None)
		<< "a stale owner credential must not still verify after a wipe";
}

TEST(TwoRoleAuthCore, SessionRoleAndNoOwnerFallback)
{
	AdminAuth::clearCredential();
	ASSERT_TRUE(AdminAuth::setLoginCredential("sysop3", "sysoppass123"));

	std::string sysopToken = AdminAuth::createSession(AdminAuth::Role::Sysop);
	EXPECT_EQ(AdminAuth::sessionRole(sysopToken), AdminAuth::Role::Sysop);

	// No owner yet: a sysop session satisfies an owner-gated need.
	EXPECT_TRUE(AdminAuth::sessionSatisfiesRole(sysopToken, AdminAuth::Role::Owner));
	EXPECT_TRUE(AdminAuth::sessionSatisfiesRole(sysopToken, AdminAuth::Role::Sysop));

	// Once an owner exists, the floor closes: only an Owner session satisfies
	// an Owner-gated need from then on.
	ASSERT_TRUE(AdminAuth::setOwnerCredential("boss3", "bosspass123"));
	EXPECT_FALSE(AdminAuth::sessionSatisfiesRole(sysopToken, AdminAuth::Role::Owner))
		<< "no-owner fallback must close once a real owner exists";
	EXPECT_TRUE(AdminAuth::sessionSatisfiesRole(sysopToken, AdminAuth::Role::Sysop));

	std::string ownerToken = AdminAuth::createSession(AdminAuth::Role::Owner);
	EXPECT_TRUE(AdminAuth::sessionSatisfiesRole(ownerToken, AdminAuth::Role::Owner));
	EXPECT_TRUE(AdminAuth::sessionSatisfiesRole(ownerToken, AdminAuth::Role::Sysop))
		<< "owner is a superset -- an owner session must also satisfy a sysop-level gate";

	AdminAuth::clearCredential();
}

// ── Lockout keyed by (channel, principal) — the core #173 safety property ──

TEST(TwoRoleAuthCore, LockoutIsKeyedByPrincipalNotSharedAcrossRoles)
{
	AdminAuth::clearCredential();
	ASSERT_TRUE(AdminAuth::setLoginCredential("sysop4", "sysoppass123"));
	ASSERT_TRUE(AdminAuth::setOwnerCredential("boss4", "bosspass123"));

	const std::string ip = "4.4.4.1";

	// Spray the SYSOP password from ONE client IP until it locks out.
	for (int i = 0; i < AdminAuth::kMaxFailedAttempts; ++i)
	{
		EXPECT_EQ(AdminAuth::authenticate("sysop4", "wrong", ip), AdminAuth::Role::None);
	}
	EXPECT_TRUE(AdminAuth::isLockedOutForAuth("sysop4", ip));

	// The OWNER principal, from the SAME client IP, must be entirely
	// unaffected -- this is the property the issue names explicitly
	// ("spraying the sysop password can't lock out the owner").
	EXPECT_FALSE(AdminAuth::isLockedOutForAuth("boss4", ip));
	EXPECT_EQ(AdminAuth::authenticate("boss4", "bosspass123", ip), AdminAuth::Role::Owner);

	// And the sysop bucket for that same IP is still locked (a correct OWNER
	// login must not have reset the SYSOP bucket -- separate buckets, not a
	// shared per-client one).
	EXPECT_TRUE(AdminAuth::isLockedOutForAuth("sysop4", ip));
	EXPECT_EQ(AdminAuth::authenticate("sysop4", "sysoppass123", ip), AdminAuth::Role::None);

	AdminAuth::clearCredential();
}

TEST(TwoRoleAuthCore, PerPrincipalGlobalBackstopDoesNotCrossRoles)
{
	// Mirrors WebHardening.GlobalBackstopBoundsSpoofedSourceAddresses, but
	// checks the #173 property: a spoofed-source flood against the SYSOP
	// principal must not engage the OWNER principal's aggregate backstop.
	AdminAuth::clearCredential();
	ASSERT_TRUE(AdminAuth::setLoginCredential("sysop5", "sysoppass123"));
	ASSERT_TRUE(AdminAuth::setOwnerCredential("boss5", "bosspass123"));

	const int clients = AdminAuth::kMaxFailedAttemptsGlobal / AdminAuth::kMaxFailedAttempts;
	for (int c = 0; c < clients; ++c)
	{
		const std::string ip = "5.1.1." + std::to_string(c + 1);
		for (int i = 0; i < AdminAuth::kMaxFailedAttempts; ++i)
		{
			EXPECT_EQ(AdminAuth::authenticate("sysop5", "wrong", ip), AdminAuth::Role::None);
		}
	}
	// The sysop principal's aggregate backstop is now engaged...
	EXPECT_TRUE(AdminAuth::isLockedOutForAuth("sysop5", "5.9.9.9"))
		<< "a brand-new sysop-principal client must be caught by the sysop aggregate backstop";
	// ...but the OWNER principal, from a brand-new client, is untouched.
	EXPECT_FALSE(AdminAuth::isLockedOutForAuth("boss5", "5.9.9.9"));
	EXPECT_EQ(AdminAuth::authenticate("boss5", "bosspass123", "5.9.9.9"), AdminAuth::Role::Owner);

	AdminAuth::clearCredential();
}

// ── HTTP-level: owner-vs-sysop gating on the three named owner-only actions ─

TEST_F(TwoRoleAuthTest, FactoryReset_NoOwnerYet_SysopPermitted)
{
	AdminSession sysop = loginSysop(_port);
	std::string resp = httpRaw(_port, "POST", "/api/factory-reset", "confirm=ERASE",
		"pd_session=" + sysop.cookie, sysop.csrf);
	EXPECT_EQ(statusOf(resp), 200) << resp;
}

TEST_F(TwoRoleAuthTest, FactoryReset_OwnerExists_SysopForbiddenOwnerPermitted)
{
	AdminSession sysop = loginSysop(_port);
	AdminSession owner = bootstrapAndLoginOwner(_port, sysop);

	std::string sysopResp = httpRaw(_port, "POST", "/api/factory-reset", "confirm=ERASE",
		"pd_session=" + sysop.cookie, sysop.csrf);
	EXPECT_EQ(statusOf(sysopResp), 403) << sysopResp;

	std::string ownerResp = httpRaw(_port, "POST", "/api/factory-reset", "confirm=ERASE",
		"pd_session=" + owner.cookie, owner.csrf);
	EXPECT_EQ(statusOf(ownerResp), 200) << ownerResp;
}

TEST_F(TwoRoleAuthTest, ConfigExportWithSecrets_OwnerExists_SysopForbiddenOwnerPermitted)
{
	AdminSession sysop = loginSysop(_port);
	AdminSession owner = bootstrapAndLoginOwner(_port, sysop);

	std::string sysopResp = httpRaw(_port, "POST", "/api/config/export", "password=exportpass123",
		"pd_session=" + sysop.cookie, sysop.csrf);
	EXPECT_EQ(statusOf(sysopResp), 403) << sysopResp;

	std::string ownerResp = httpRaw(_port, "POST", "/api/config/export", "password=exportpass123",
		"pd_session=" + owner.cookie, owner.csrf);
	EXPECT_EQ(statusOf(ownerResp), 200) << ownerResp;
	EXPECT_NE(bodyOf(ownerResp).find("\"secretsEnc\""), std::string::npos) << bodyOf(ownerResp);
}

TEST_F(TwoRoleAuthTest, ConfigExportPlaintext_StaysSysopLevelEvenWithOwnerProvisioned)
{
	// The PLAINTEXT export (no password) is sysop-level per #186/#173 -- only
	// the encrypted secrets block is owner-only.
	AdminSession sysop = loginSysop(_port);
	AdminSession owner = bootstrapAndLoginOwner(_port, sysop);
	(void)owner;

	std::string resp = httpRaw(_port, "GET", "/api/config/export", "",
		"pd_session=" + sysop.cookie);
	EXPECT_EQ(statusOf(resp), 200) << resp;
	EXPECT_EQ(bodyOf(resp).find("\"secretsEnc\""), std::string::npos)
		<< "a plaintext export must never include the encrypted block";
}

TEST_F(TwoRoleAuthTest, OtaUpload_OwnerExists_SysopForbiddenOwnerPassesGate)
{
	AdminSession sysop = loginSysop(_port);
	AdminSession owner = bootstrapAndLoginOwner(_port, sysop);

	const std::string fakeImage = "not-a-real-firmware-image";
	std::string sysopResp = httpRaw(_port, "POST", "/api/ota/upload", fakeImage,
		"pd_session=" + sysop.cookie, sysop.csrf);
	EXPECT_EQ(statusOf(sysopResp), 403) << sysopResp;

	// Owner passes the GATE; the host build has no real flash to write to, so
	// it answers 501 past that point -- see handleOtaUpload's host stub.
	// The property under test is "not 403", i.e. the gate itself admitted the
	// owner session.
	std::string ownerResp = httpRaw(_port, "POST", "/api/ota/upload", fakeImage,
		"pd_session=" + owner.cookie, owner.csrf);
	EXPECT_EQ(statusOf(ownerResp), 501) << ownerResp;
}

TEST_F(TwoRoleAuthTest, SetOwnerCredential_OnceProvisioned_OnlyOwnerMayReplace)
{
	AdminSession sysop = loginSysop(_port);
	AdminSession owner = bootstrapAndLoginOwner(_port, sysop);

	// Sysop can no longer (re)set the owner credential once one exists.
	std::string sysopResp = httpRaw(_port, "POST", "/api/admin/set-owner-credential",
		"ownerUsername=newowner&ownerPassword=newownerpass1",
		"pd_session=" + sysop.cookie, sysop.csrf);
	EXPECT_EQ(statusOf(sysopResp), 403) << sysopResp;

	// The owner may replace their own credential.
	std::string ownerResp = httpRaw(_port, "POST", "/api/admin/set-owner-credential",
		"ownerUsername=newowner&ownerPassword=newownerpass1",
		"pd_session=" + owner.cookie, owner.csrf);
	EXPECT_EQ(statusOf(ownerResp), 200) << ownerResp;
}

// ── DTMF PIN gating (found in review, not in the original issue text) ──────
//
// The DTMF admin menu's *<PIN>999#1 code wipes the entire NVS flash
// (DtmfFeatureCodes.cpp: nvs_flash_erase()) -- including the owner
// credential. Setting the PIN itself must therefore be owner-gated once an
// owner exists, or a sysop could plant a PIN, factory-reset the device via a
// registered phone, and land back on a no-owner board where the fallback
// hands sysop owner powers again -- a sysop-reachable path around the very
// privilege split #173 exists to enforce.

TEST_F(TwoRoleAuthTest, SetDtmfPin_OwnerExists_SysopForbidden)
{
	AdminSession sysop = loginSysop(_port);
	AdminSession owner = bootstrapAndLoginOwner(_port, sysop);
	(void)owner;

	std::string resp = httpRaw(_port, "POST", "/api/admin/set-credential",
		"dtmfPin=111111", "pd_session=" + sysop.cookie, sysop.csrf);
	EXPECT_EQ(statusOf(resp), 403) << resp;
	EXPECT_FALSE(AdminAuth::dtmfPinIsSet())
		<< "a refused set-credential call must not have set the PIN";
}

TEST_F(TwoRoleAuthTest, SetDtmfPin_OwnerExists_OwnerPermitted)
{
	AdminSession sysop = loginSysop(_port);
	AdminSession owner = bootstrapAndLoginOwner(_port, sysop);

	std::string resp = httpRaw(_port, "POST", "/api/admin/set-credential",
		"dtmfPin=111111", "pd_session=" + owner.cookie, owner.csrf);
	EXPECT_EQ(statusOf(resp), 200) << resp;
	EXPECT_TRUE(AdminAuth::dtmfPinIsSet());
}

TEST_F(TwoRoleAuthTest, SetDtmfPin_NoOwnerYet_SysopStillPermitted)
{
	// The no-owner-yet fallback must still let first-boot onboarding set a
	// DTMF PIN before any owner account exists -- this is not a regression
	// of the fix above, it is the same fallback every other owner-gated
	// action already relies on.
	AdminSession sysop = loginSysop(_port);
	std::string resp = httpRaw(_port, "POST", "/api/admin/set-credential",
		"dtmfPin=222222", "pd_session=" + sysop.cookie, sysop.csrf);
	EXPECT_EQ(statusOf(resp), 200) << resp;
	EXPECT_TRUE(AdminAuth::dtmfPinIsSet());
}

// ── Symmetric username-collision guard (found in review) ───────────────────

TEST(TwoRoleAuthCore, SetLoginCredentialRejectsCollisionWithOwnerUsername)
{
	AdminAuth::clearCredential();
	ASSERT_TRUE(AdminAuth::setLoginCredential("firstsysop", "sysoppass123"));
	ASSERT_TRUE(AdminAuth::setOwnerCredential("theowner", "ownerpass123"));

	// A later rename of the sysop identity onto the owner's username must be
	// refused too -- setOwnerCredential() already refuses the other
	// direction; this pins the guard is symmetric.
	EXPECT_FALSE(AdminAuth::setLoginCredential("theowner", "newsysoppass1"));
	AdminAuth::clearCredential();
}

// ── Lockout must not cross the HTTP-login / DTMF-PIN channel boundary ──────

TEST(TwoRoleAuthCore, HttpLoginLockoutDoesNotEngageDtmfPinLockout)
{
	// Regression for a review finding: authenticate() used to reuse
	// verifyCredential's/verifyDtmfPin's SHARED legacy global backstop, so
	// spraying the HTTP login could lock the DTMF menu out (and a
	// successful DTMF PIN entry could silently clear the HTTP spray's
	// accounting). authenticate() now tracks its own per-principal
	// aggregate (AuthState::principalBackstop) instead.
	AdminAuth::clearCredential();
	ASSERT_TRUE(AdminAuth::setLoginCredential("chansysop", "sysoppass123"));
	ASSERT_TRUE(AdminAuth::setDtmfPin("112233"));

	for (int c = 0; c < AdminAuth::kMaxFailedAttemptsGlobal / AdminAuth::kMaxFailedAttempts + 1; ++c)
	{
		const std::string ip = "6.1.1." + std::to_string(c + 1);
		for (int i = 0; i < AdminAuth::kMaxFailedAttempts; ++i)
		{
			AdminAuth::authenticate("chansysop", "wrong", ip);
		}
	}

	// The DTMF PIN channel (unkeyed "" bucket, verifyDtmfPin's own path) must
	// be completely unaffected by that HTTP-login spray.
	EXPECT_FALSE(AdminAuth::isLockedOut(""))
		<< "an HTTP-login spray must not have engaged verifyDtmfPin's lockout";
	EXPECT_TRUE(AdminAuth::verifyDtmfPin("112233"));

	AdminAuth::clearCredential();
}

TEST_F(TwoRoleAuthTest, AdminStatusReportsRoleAndOwnerProvisioned)
{
	AdminSession sysop = loginSysop(_port);
	std::string beforeOwner = httpRaw(_port, "GET", "/api/admin/status", "",
		"pd_session=" + sysop.cookie);
	EXPECT_NE(bodyOf(beforeOwner).find("\"role\":\"sysop\""), std::string::npos) << bodyOf(beforeOwner);
	EXPECT_NE(bodyOf(beforeOwner).find("\"ownerProvisioned\":false"), std::string::npos) << bodyOf(beforeOwner);

	AdminSession owner = bootstrapAndLoginOwner(_port, sysop);
	std::string afterOwner = httpRaw(_port, "GET", "/api/admin/status", "",
		"pd_session=" + owner.cookie);
	EXPECT_NE(bodyOf(afterOwner).find("\"role\":\"owner\""), std::string::npos) << bodyOf(afterOwner);
	EXPECT_NE(bodyOf(afterOwner).find("\"ownerProvisioned\":true"), std::string::npos) << bodyOf(afterOwner);
}
