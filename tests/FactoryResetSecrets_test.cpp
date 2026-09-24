// FactoryResetSecrets_test.cpp — issue #363: a factory reset must leave NO stored
// secret behind.
//
// sendApiFactoryReset() erases store by store and key by key, never a namespace
// wipe, so every store it does not name survives in plaintext flash. #363 found
// two: smtp_pass/gsa_key (EmailConfigStore) and, while enumerating, every
// extension's digest HA1 (SipSecretStore). This file is the ONE place asserting
// that every secret-bearing store is empty after a reset -- each row is set to a
// visibly non-default value first, so an "empty after" cannot pass by never
// having been set. Stores already cleared before #363 (admin credential, trunk
// password, Telephony-API secret) are rows here too, so this test does not lean
// on theirs existing.
//
// Driven through the real route (HttpServer + requireAdmin + confirm=ERASE).
// Ports: this file owns 18240-18249. See CONTRIBUTING_FIRMWARE.md's table.

#include <gtest/gtest.h>
#include "AdminAuth.hpp"
#include "CoreDumpStore.hpp"
#include "EmailConfigStore.hpp"
#include "HttpServer.hpp"
#include "RequestsHandler.hpp"
#include "SipMessage.hpp"
#include "SipSecretStore.hpp"
#include "TelephonyApiConfig.hpp"
#include "TrunkConfigStore.hpp"

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
#include <vector>

namespace
{
	// Duplicated raw-socket helper -- anonymous-namespace helpers don't cross
	// translation units (same note CoreDumpHttp_test.cpp carries).
	std::string httpPost(int port, const std::string& path, const std::string& body,
	                     const std::string& cookie, const std::string& csrf)
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
		std::string req = "POST " + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\n"
			"Cookie: " + cookie + "\r\nX-CSRF: " + csrf + "\r\n"
			"Content-Type: application/x-www-form-urlencoded\r\n"
			"Content-Length: " + std::to_string(body.size()) + "\r\n"
			"Connection: close\r\n\r\n" + body;
		send(s, req.c_str(), static_cast<int>(req.size()), 0);
		std::string resp;
		char buf[512];
		int n;
		while ((n = recv(s, buf, sizeof(buf), 0)) > 0) resp.append(buf, static_cast<size_t>(n));
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

	struct AdminSession { std::string cookie; std::string csrf; };

	// Same shortcut EmailHttp_test.cpp / TrunkConfigHttp_test.cpp use: the login
	// round trip is not what this file tests. It also provisions the admin
	// credential -- one of the secrets the reset must clear.
	AdminSession bypassLogin()
	{
		AdminSession a;
		if (!AdminAuth::setLoginCredential("admin", "realpassword123"))
		{
			ADD_FAILURE() << "setLoginCredential failed";
			return a;
		}
		const std::string token = AdminAuth::createSession();
		a.cookie = "pd_session=" + token;
		a.csrf = AdminAuth::sessionCsrf(token);
		return a;
	}

	std::vector<uint8_t> fakeDump()
	{
		std::vector<uint8_t> img(256, 0x5A);   // "stack bytes"
		img[12] = 0x7F; img[13] = 'E'; img[14] = 'L'; img[15] = 'F';
		return img;
	}

	class FactoryResetSecretsTest : public ::testing::Test
	{
	protected:
		void SetUp() override
		{
			const std::string name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
			_tapiPath = "test_resetsecrets_tapicfg_" + name + ".cfg";
			_didPath  = "test_resetsecrets_didmap_" + name + ".cfg";
			std::remove(_tapiPath.c_str());
			std::remove(_didPath.c_str());
			clearEverything();

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
			clearEverything();
			std::remove(_tapiPath.c_str());
			std::remove(_didPath.c_str());
		}

		static void clearEverything()
		{
			AdminAuth::clearCredential();
			EmailConfigStore::resetForTest();
			TrunkConfigStore::resetForTest();
			SipSecretStore::clearAll();
			CoreDumpStore::setImageForTest({});
		}

		int _port = 0;
		std::unique_ptr<HttpServer> _server;
		std::unique_ptr<RequestsHandler> _handler;
		std::string _tapiPath, _didPath;
		static int _nextPort;
	};
	int FactoryResetSecretsTest::_nextPort = 18240;
}

TEST_F(FactoryResetSecretsTest, NoStoredSecretSurvivesAFactoryReset)
{
	// ── Arrange: every secret-bearing store holds a real-looking secret ──
	EmailConfigStore::Config mail;
	mail.host     = "smtp.mail.example";
	mail.user     = "mailer@example.com";
	mail.pass     = "smtp-s3cret";
	mail.gsaEmail = "svc@project.iam.example";
	mail.gsaKey   = "-----BEGIN PRIVATE KEY-----\nMIIfake\n-----END PRIVATE KEY-----\n";
	mail.caPem    = "-----BEGIN CERTIFICATE-----\nMIIfake\n-----END CERTIFICATE-----\n";
	ASSERT_TRUE(EmailConfigStore::save(mail));

	TrunkConfigStore::Config trunk;
	trunk.host     = "sip.carrier.example";
	trunk.authUser = "auth-id-9876";
	trunk.pass     = "trunk-s3cret";
	trunk.enabled  = true;
	ASSERT_TRUE(TrunkConfigStore::save(trunk));

	ASSERT_TRUE(SipSecretStore::setSecret("501", "ext-501-secret"));
	ASSERT_TRUE(SipSecretStore::setSecret("502", "ext-502-secret"));

	TelephonyApiConfig::Slot slot;
	slot.enabled  = true;
	slot.baseUrl  = "https://pbx.example.com";
	slot.clientId = "client-1";
	slot.secret   = "tapi-s3cret";
	slot.routeDn  = "800";
	ASSERT_EQ(_handler->setTelephonyConfigSlot(0, slot, /*keepSecret=*/false), "");

	CoreDumpStore::setImageForTest(fakeDump());
	const AdminSession s = bypassLogin();

	// Every row really is set, so an "empty after" below cannot pass vacuously.
	ASSERT_FALSE(EmailConfigStore::load().pass.empty());
	ASSERT_FALSE(EmailConfigStore::load().gsaKey.empty());
	ASSERT_FALSE(TrunkConfigStore::load().pass.empty());
	ASSERT_TRUE(SipSecretStore::hasSecret("501"));
	ASSERT_TRUE(_handler->getTelephonyConfigSlot(0).secretSet);
	ASSERT_TRUE(CoreDumpStore::query().present);
	ASSERT_TRUE(AdminAuth::isProvisioned());

	// ── Act ──
	ASSERT_EQ(statusOf(httpPost(_port, "/api/factory-reset", "confirm=ERASE", s.cookie, s.csrf)), 200);

	// ── Assert: nothing secret remains, row by row ──
	const auto mailAfter = EmailConfigStore::load();
	EXPECT_TRUE(mailAfter.pass.empty())   << "SMTP password survived the reset (#363)";
	EXPECT_TRUE(mailAfter.gsaKey.empty()) << "Google service-account PRIVATE KEY survived the reset (#363)";
	EXPECT_TRUE(mailAfter.caPem.empty());
	EXPECT_TRUE(mailAfter.user.empty());
	EXPECT_TRUE(mailAfter.gsaEmail.empty());

	const auto trunkAfter = TrunkConfigStore::load();
	EXPECT_TRUE(trunkAfter.pass.empty())     << "carrier password survived the reset";
	EXPECT_TRUE(trunkAfter.authUser.empty()) << "carrier account id survived the reset";

	EXPECT_FALSE(SipSecretStore::hasSecret("501")) << "an extension's digest HA1 survived the reset (#363)";
	EXPECT_FALSE(SipSecretStore::hasSecret("502"));
	EXPECT_TRUE(SipSecretStore::securedExtensions().empty());

	EXPECT_FALSE(_handler->getTelephonyConfigSlot(0).secretSet) << "Telephony-API client secret survived the reset";

	EXPECT_FALSE(CoreDumpStore::query().present) << "the last coredump (a copy of task stacks) survived the reset";

	EXPECT_FALSE(AdminAuth::isProvisioned()) << "the admin credential survived the reset";
}

TEST(SipSecretStoreClearAll, RemovesEveryExtensionSecret)
{
	SipSecretStore::clearAll();
	ASSERT_TRUE(SipSecretStore::setSecret("601", "a-secret"));
	ASSERT_TRUE(SipSecretStore::setSecret("602", "b-secret"));
	ASSERT_EQ(SipSecretStore::securedExtensions().size(), 2u);

	EXPECT_TRUE(SipSecretStore::clearAll());
	EXPECT_FALSE(SipSecretStore::hasSecret("601"));
	EXPECT_FALSE(SipSecretStore::hasSecret("602"));
	EXPECT_TRUE(SipSecretStore::securedExtensions().empty());
	EXPECT_TRUE(SipSecretStore::clearAll()) << "clearing an already-empty store is not an error";
}
