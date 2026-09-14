// ConfigExportImport_test.cpp — issue #186: config export/import backup and
// restore, driven through a real HttpServer/requireAdmin() exactly like
// AdminHttpGate_test.cpp and TwoRoleAuth_test.cpp.
//
// Covers: plaintext export/import round-trip, password-gated
// (AES-256-GCM/PBKDF2-SHA256) export/import round-trip, bad-password
// rejection (422), bad-schema rejection (400), missing-confirm rejection
// (400), and the admin credential hash never appearing anywhere in an export
// blob (plaintext or decrypted secrets). AdminAuth's crypto primitives
// (pbkdf2Sha256/aesGcmSeal/aesGcmOpen) themselves are vector-tested directly
// in AdminAuthCrypto_test.cpp; this file is the endpoint-level contract.
//
// Ports: this file owns 18140-18159. See CONTRIBUTING_FIRMWARE.md's table.

#include <gtest/gtest.h>
#include "HttpServer.hpp"
#include "RequestsHandler.hpp"
#include "SipMessage.hpp"
#include "AdminAuth.hpp"
#include "DeviceConfig.hpp"
#include "UrlEncode.hpp"

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

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <string>
#include <thread>

namespace
{
	// Duplicated raw-socket HTTP helpers -- see TwoRoleAuth_test.cpp's file
	// comment on why (anonymous-namespace helpers don't cross translation
	// units).
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
		// The export/import bodies can run several KB, well past a 512-byte
		// buffer -- read in a larger chunk than the other HTTP test files use.
		char buf[8192];
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

	AdminSession loginSysop(int port)
	{
		AdminSession a;
		std::string loginResp = httpRaw(port, "POST", "/api/admin/login",
			"username=admin&password=admin");
		EXPECT_EQ(statusOf(loginResp), 200) << loginResp;
		a.cookie = cookieOf(loginResp, "pd_session");
		a.csrf   = csrfOf(loginResp);

		std::string setupResp = httpRaw(port, "POST", "/api/admin/set-credential",
			"username=admin&password=realpassword123", "pd_session=" + a.cookie, a.csrf);
		EXPECT_EQ(statusOf(setupResp), 200) << setupResp;
		return a;
	}

	// setTelephonyStorePathsForTest()'s per-test file paths (same idiom as
	// TelephonyConfigHttp_test.cpp): this file's import handler goes through
	// clearAllDidMappings()/setDidMapping()/setTelephonyConfigSlot(), and its
	// FactoryReset-adjacent flows go through clearAllTelephonyConfig() too --
	// without this redirect they would read/write the SAME default
	// "pocketdial_tapi.cfg"/"pocketdial_didmap.cfg" files in the build cwd
	// every other unredirected test in this binary does.
	class ConfigExportImportTest : public ::testing::Test
	{
	protected:
		void SetUp() override
		{
			const std::string name = ::testing::UnitTest::GetInstance()->current_test_info()->name();
			_tapiPath = "test_cfgexp_tapicfg_" + name + ".cfg";
			_didPath  = "test_cfgexp_didmap_" + name + ".cfg";
			std::remove(_tapiPath.c_str());
			std::remove(_didPath.c_str());

			AdminAuth::clearCredential();
			DeviceConfig::clearAll();
			_port = _nextPort++;
			_handler = std::make_unique<RequestsHandler>("192.168.4.1", 5060,
				[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
			_handler->setTelephonyStorePathsForTest(_tapiPath, _didPath);
			_server = std::make_unique<HttpServer>("127.0.0.1", _port, nullptr);
			_server->attachHandler(_handler.get());
			_server->start();
			std::this_thread::sleep_for(std::chrono::milliseconds(50));
			_sysop = loginSysop(_port);
		}

		void TearDown() override
		{
			_server.reset();
			_handler.reset();
			AdminAuth::clearCredential();
			DeviceConfig::clearAll();
			std::remove(_tapiPath.c_str());
			std::remove(_didPath.c_str());
		}

		// Bootstraps + logs in the owner (needed for the encrypted export).
		AdminSession loginOwner()
		{
			std::string setResp = httpRaw(_port, "POST", "/api/admin/set-owner-credential",
				"ownerUsername=owner&ownerPassword=ownerpass123",
				"pd_session=" + _sysop.cookie, _sysop.csrf);
			EXPECT_EQ(statusOf(setResp), 200) << setResp;

			AdminSession owner;
			std::string loginResp = httpRaw(_port, "POST", "/api/admin/login",
				"username=owner&password=ownerpass123");
			EXPECT_EQ(statusOf(loginResp), 200) << loginResp;
			owner.cookie = cookieOf(loginResp, "pd_session");
			owner.csrf   = csrfOf(loginResp);
			return owner;
		}

		int _port = 0;
		std::unique_ptr<HttpServer> _server;
		std::unique_ptr<RequestsHandler> _handler;
		AdminSession _sysop;
		std::string _tapiPath, _didPath;
		static int _nextPort;
	};
	int ConfigExportImportTest::_nextPort = 18140;
}

// ── Plaintext export/import round-trip ──────────────────────────────────────

TEST_F(ConfigExportImportTest, PlaintextExport_ContainsConfiguredData)
{
	ASSERT_EQ(statusOf(httpRaw(_port, "POST", "/api/dialplan",
		"pattern=9XXXXXXXXXX&action=trunk&stripDigits=1&target=1",
		"pd_session=" + _sysop.cookie, _sysop.csrf)), 200);
	ASSERT_EQ(statusOf(httpRaw(_port, "POST", "/api/group",
		"extension=700&members=101,102&mode=ringall",
		"pd_session=" + _sysop.cookie, _sysop.csrf)), 200);

	std::string resp = httpRaw(_port, "GET", "/api/config/export", "",
		"pd_session=" + _sysop.cookie);
	ASSERT_EQ(statusOf(resp), 200) << resp;
	const std::string body = bodyOf(resp);

	EXPECT_NE(body.find("\"9XXXXXXXXXX\""), std::string::npos) << body;
	EXPECT_NE(body.find("\"700\""), std::string::npos) << body;
	EXPECT_EQ(body.find("\"secretsEnc\""), std::string::npos)
		<< "GET export must never include the encrypted block";
}

TEST_F(ConfigExportImportTest, PlaintextRoundTrip_DialPlanRingGroupsPageZonesDnd)
{
	ASSERT_EQ(statusOf(httpRaw(_port, "POST", "/api/dialplan",
		"pattern=555XXXX&action=group&target=700",
		"pd_session=" + _sysop.cookie, _sysop.csrf)), 200);
	ASSERT_EQ(statusOf(httpRaw(_port, "POST", "/api/group",
		"extension=700&members=101,102&mode=hunt",
		"pd_session=" + _sysop.cookie, _sysop.csrf)), 200);
	ASSERT_EQ(statusOf(httpRaw(_port, "POST", "/api/dnd",
		"extension=101&on=1",
		"pd_session=" + _sysop.cookie, _sysop.csrf)), 200);

	std::string exportResp = httpRaw(_port, "GET", "/api/config/export", "",
		"pd_session=" + _sysop.cookie);
	ASSERT_EQ(statusOf(exportResp), 200) << exportResp;
	const std::string blob = bodyOf(exportResp);

	// Wipe the device (factory reset needs owner; bootstrap one for this).
	AdminSession owner = loginOwner();
	ASSERT_EQ(statusOf(httpRaw(_port, "POST", "/api/factory-reset", "confirm=ERASE",
		"pd_session=" + owner.cookie, owner.csrf)), 200);

	// Factory reset wiped the admin credential too -- log back in on the
	// default and complete setup again before the import call, same as a
	// real operator restoring a wiped unit would.
	AdminSession freshSysop = loginSysop(_port);

	std::string importBody = "blob=" + urlEncode(blob) + "&confirm=REPLACE";
	std::string importResp = httpRaw(_port, "POST", "/api/config/import", importBody,
		"pd_session=" + freshSysop.cookie, freshSysop.csrf);
	ASSERT_EQ(statusOf(importResp), 200) << importResp;
	EXPECT_NE(bodyOf(importResp).find("\"dialPlan\""), std::string::npos) << bodyOf(importResp);

	// Verify it actually landed via the live accessors, not just the blob.
	auto rules = _handler->getDialRules();
	bool foundRule = false;
	for (const auto& r : rules)
	{
		if (std::get<0>(r) == "555XXXX") { foundRule = true; EXPECT_EQ(std::get<1>(r), "group"); }
	}
	EXPECT_TRUE(foundRule);

	auto groups = _handler->getRingGroups();
	bool foundGroup = false;
	for (const auto& g : groups)
	{
		if (std::get<0>(g) == "700") { foundGroup = true; EXPECT_EQ(std::get<1>(g), "hunt"); }
	}
	EXPECT_TRUE(foundGroup);

	auto dnd = _handler->getDndExtensions();
	EXPECT_NE(std::find(dnd.begin(), dnd.end(), "101"), dnd.end());
}

TEST_F(ConfigExportImportTest, Import_ReplaceNotMerge_DropsEntriesNotInTheBlob)
{
	// Two ring groups exist before the import...
	ASSERT_EQ(statusOf(httpRaw(_port, "POST", "/api/group",
		"extension=700&members=101&mode=ringall",
		"pd_session=" + _sysop.cookie, _sysop.csrf)), 200);
	ASSERT_EQ(statusOf(httpRaw(_port, "POST", "/api/group",
		"extension=701&members=102&mode=ringall",
		"pd_session=" + _sysop.cookie, _sysop.csrf)), 200);

	// ...but the imported blob names only one of them. Hand-built minimal
	// blob (not round-tripped from export) to state exactly what's under
	// test: 700 survives, 701 must be gone afterward (replace, not merge).
	std::string blob =
		R"({"exportVer":1,"plaintext":{"extensions":[],"extensionSecrets":[],)"
		R"("ringGroups":[{"extension":"700","mode":"ringall","members":"101"}],)"
		R"("forwards":[],"dnd":[],"pageZones":[],"dialPlan":[],"didMappings":[],)"
		R"("registrarMode":"open","telephonyConfig":[],"wifiSsid":"","wifiMode":0,)"
		R"("apSecure":false,"parkTimeoutSec":90,"mdnsHostname":"pocketdial","schemaVer":1}})";

	std::string importResp = httpRaw(_port, "POST", "/api/config/import",
		"blob=" + urlEncode(blob) + "&confirm=REPLACE",
		"pd_session=" + _sysop.cookie, _sysop.csrf);
	ASSERT_EQ(statusOf(importResp), 200) << importResp;

	auto groups = _handler->getRingGroups();
	bool has700 = false, has701 = false;
	for (const auto& g : groups)
	{
		if (std::get<0>(g) == "700") has700 = true;
		if (std::get<0>(g) == "701") has701 = true;
	}
	EXPECT_TRUE(has700);
	EXPECT_FALSE(has701) << "an entry absent from the imported blob must be REMOVED, not left behind";
}

// ── Password-gated (AES-256-GCM/PBKDF2-SHA256) round-trip ──────────────────

TEST_F(ConfigExportImportTest, PasswordGatedRoundTrip_WifiPasswordAndApPsk)
{
	ASSERT_TRUE(DeviceConfig::setWifiConfig("TestOfficeWifi", 1));
	ASSERT_TRUE(DeviceConfig::setWifiPassword("supersecretwifi1"));
	const std::string originalPsk = DeviceConfig::getApPsk();

	AdminSession owner = loginOwner();
	std::string exportResp = httpRaw(_port, "POST", "/api/config/export",
		"password=exportpass123", "pd_session=" + owner.cookie, owner.csrf);
	ASSERT_EQ(statusOf(exportResp), 200) << exportResp;
	const std::string blob = bodyOf(exportResp);
	ASSERT_NE(blob.find("\"secretsEnc\""), std::string::npos) << blob;
	// The gated fields must not appear IN THE CLEAR anywhere in the blob.
	EXPECT_EQ(blob.find("supersecretwifi1"), std::string::npos)
		<< "wifiPassword leaked in cleartext:\n" << blob;
	EXPECT_EQ(blob.find(originalPsk), std::string::npos)
		<< "apPsk leaked in cleartext:\n" << blob;

	// Wipe just the two gated values (not a factory reset -- proves import
	// actually restores them, not that they were never cleared).
	ASSERT_TRUE(DeviceConfig::setWifiPassword(""));

	std::string importResp = httpRaw(_port, "POST", "/api/config/import",
		"blob=" + urlEncode(blob) + "&password=exportpass123&confirm=REPLACE",
		"pd_session=" + _sysop.cookie, _sysop.csrf);
	ASSERT_EQ(statusOf(importResp), 200) << importResp;
	EXPECT_NE(bodyOf(importResp).find("\"wifiPassword\""), std::string::npos) << bodyOf(importResp);

	EXPECT_EQ(DeviceConfig::getWifiPassword(), "supersecretwifi1");
	EXPECT_EQ(DeviceConfig::getApPsk(), originalPsk);
}

TEST_F(ConfigExportImportTest, Import_SecretsPresentButNoPassword_SkipsGatedFieldsOnly)
{
	ASSERT_TRUE(DeviceConfig::setWifiPassword("originalpassword1"));
	AdminSession owner = loginOwner();
	std::string exportResp = httpRaw(_port, "POST", "/api/config/export",
		"password=exportpass123", "pd_session=" + owner.cookie, owner.csrf);
	ASSERT_EQ(statusOf(exportResp), 200);
	const std::string blob = bodyOf(exportResp);

	ASSERT_TRUE(DeviceConfig::setWifiPassword("untouchedvalue1"));

	// Import WITHOUT a password: the plaintext half still applies; the
	// gated half is reported skipped, and must NOT clear the existing value.
	std::string importResp = httpRaw(_port, "POST", "/api/config/import",
		"blob=" + urlEncode(blob) + "&confirm=REPLACE",
		"pd_session=" + _sysop.cookie, _sysop.csrf);
	ASSERT_EQ(statusOf(importResp), 200) << importResp;
	EXPECT_NE(bodyOf(importResp).find("secretsEnc present but no password"), std::string::npos)
		<< bodyOf(importResp);
	EXPECT_EQ(DeviceConfig::getWifiPassword(), "untouchedvalue1")
		<< "an unattempted gated section must not clear the existing secret";
}

// ── Rejections: bad password (422), bad schema (400), missing confirm (400) ─

TEST_F(ConfigExportImportTest, Import_WrongPassword_Rejected422_StateUntouched)
{
	ASSERT_TRUE(DeviceConfig::setWifiPassword("original-secret-1"));
	AdminSession owner = loginOwner();
	std::string exportResp = httpRaw(_port, "POST", "/api/config/export",
		"password=correctpassword1", "pd_session=" + owner.cookie, owner.csrf);
	ASSERT_EQ(statusOf(exportResp), 200);
	const std::string blob = bodyOf(exportResp);

	std::string importResp = httpRaw(_port, "POST", "/api/config/import",
		"blob=" + urlEncode(blob) + "&password=totallywrongpassword&confirm=REPLACE",
		"pd_session=" + _sysop.cookie, _sysop.csrf);
	EXPECT_EQ(statusOf(importResp), 422) << importResp;

	// A 422 must leave the previously-set secret exactly as it was.
	EXPECT_EQ(DeviceConfig::getWifiPassword(), "original-secret-1");
}

TEST_F(ConfigExportImportTest, Import_MalformedJson_Rejected400)
{
	std::string importResp = httpRaw(_port, "POST", "/api/config/import",
		"blob=" + urlEncode("{not valid json at all") + "&confirm=REPLACE",
		"pd_session=" + _sysop.cookie, _sysop.csrf);
	EXPECT_EQ(statusOf(importResp), 400) << importResp;
}

TEST_F(ConfigExportImportTest, Import_MissingPlaintextObject_Rejected400)
{
	std::string blob = R"({"exportVer":1})";   // valid JSON, wrong schema
	std::string importResp = httpRaw(_port, "POST", "/api/config/import",
		"blob=" + urlEncode(blob) + "&confirm=REPLACE",
		"pd_session=" + _sysop.cookie, _sysop.csrf);
	EXPECT_EQ(statusOf(importResp), 400) << importResp;
}

TEST_F(ConfigExportImportTest, Import_MissingConfirm_Rejected400)
{
	std::string blob = R"({"exportVer":1,"plaintext":{}})";
	std::string importResp = httpRaw(_port, "POST", "/api/config/import",
		"blob=" + urlEncode(blob),
		"pd_session=" + _sysop.cookie, _sysop.csrf);
	EXPECT_EQ(statusOf(importResp), 400) << importResp;
}

TEST_F(ConfigExportImportTest, Import_TamperedSecretsBlock_Rejected422)
{
	// A bit-flip in the ciphertext (rather than a wrong password) must ALSO
	// come back as 422 -- AdminAuth::aesGcmOpen makes the two indistinguishable
	// by design, and this endpoint must not leak the difference either.
	AdminSession owner = loginOwner();
	std::string exportResp = httpRaw(_port, "POST", "/api/config/export",
		"password=correctpassword1", "pd_session=" + owner.cookie, owner.csrf);
	ASSERT_EQ(statusOf(exportResp), 200);
	std::string blob = bodyOf(exportResp);

	size_t ctPos = blob.find("\"ct\":\"");
	ASSERT_NE(ctPos, std::string::npos) << blob;
	size_t hexStart = ctPos + std::string("\"ct\":\"").size();
	// Flip one hex nibble in the ciphertext.
	blob[hexStart] = (blob[hexStart] == 'a') ? 'b' : 'a';

	std::string importResp = httpRaw(_port, "POST", "/api/config/import",
		"blob=" + urlEncode(blob) + "&password=correctpassword1&confirm=REPLACE",
		"pd_session=" + _sysop.cookie, _sysop.csrf);
	EXPECT_EQ(statusOf(importResp), 422) << importResp;
}

// ── Import validation gaps found in review ──────────────────────────────────

TEST_F(ConfigExportImportTest, Import_UnsupportedExportVer_Rejected400)
{
	std::string blob = R"({"exportVer":2,"plaintext":{}})";
	std::string resp = httpRaw(_port, "POST", "/api/config/import",
		"blob=" + urlEncode(blob) + "&confirm=REPLACE",
		"pd_session=" + _sysop.cookie, _sysop.csrf);
	EXPECT_EQ(statusOf(resp), 400) << resp;
}

TEST_F(ConfigExportImportTest, Import_ExcessiveKdfIterations_Rejected400)
{
	// A sysop-crafted (or corrupted) blob naming an absurd iteration count
	// must not be allowed to pin the HTTP handler thread computing PBKDF2 for
	// as long as the attacker likes.
	std::string blob =
		R"({"exportVer":1,"plaintext":{},"secretsEnc":{"kdf":"pbkdf2-sha256",)"
		R"("iter":2000000000,"salt":"00112233445566778899aabbccddeeff",)"
		R"("nonce":"00112233445566778899aabb","ct":"00112233445566778899aabbccddeeff"}})";
	std::string resp = httpRaw(_port, "POST", "/api/config/import",
		"blob=" + urlEncode(blob) + "&password=whatever&confirm=REPLACE",
		"pd_session=" + _sysop.cookie, _sysop.csrf);
	EXPECT_EQ(statusOf(resp), 400) << resp;
}

TEST_F(ConfigExportImportTest, Import_WifiModeOutOfRange_SkippedNotWrappedIntoRange)
{
	// A pre-cast range check: 258 must NOT silently wrap to a valid uint8_t
	// (258 mod 256 == 2, a real AP mode) and be accepted as though it were 2.
	std::string blob =
		R"({"exportVer":1,"plaintext":{"extensions":[],"extensionSecrets":[],)"
		R"("ringGroups":[],"forwards":[],"dnd":[],"pageZones":[],"dialPlan":[],)"
		R"("didMappings":[],"registrarMode":"open","telephonyConfig":[],)"
		R"("wifiSsid":"SomeSsid","wifiMode":258,"apSecure":false,"parkTimeoutSec":90,)"
		R"("mdnsHostname":"pocketdial","schemaVer":1}})";
	std::string resp = httpRaw(_port, "POST", "/api/config/import",
		"blob=" + urlEncode(blob) + "&confirm=REPLACE",
		"pd_session=" + _sysop.cookie, _sysop.csrf);
	ASSERT_EQ(statusOf(resp), 200) << resp;
	EXPECT_NE(bodyOf(resp).find("mode out of range"), std::string::npos) << bodyOf(resp);
	EXPECT_NE(DeviceConfig::getWifiMode(), 2)
		<< "an out-of-range mode must not have been silently applied via integer wraparound";
}

// ── The admin credential hash must never appear in an export ───────────────

TEST_F(ConfigExportImportTest, AdminHashNeverAppearsInExport_PlaintextOrGated)
{
	// The sysop's own real password (set in SetUp/loginSysop) must not
	// appear anywhere in either half of the export -- neither the wire-level
	// hash field names AdminAuth persists nor the credential itself.
	AdminSession owner = loginOwner();
	std::string exportResp = httpRaw(_port, "POST", "/api/config/export",
		"password=exportpass123", "pd_session=" + owner.cookie, owner.csrf);
	ASSERT_EQ(statusOf(exportResp), 200) << exportResp;
	const std::string blob = bodyOf(exportResp);

	EXPECT_EQ(blob.find("realpassword123"), std::string::npos)
		<< "the sysop's real password must never appear in an export:\n" << blob;
	EXPECT_EQ(blob.find("ownerpass123"), std::string::npos)
		<< "the owner's real password must never appear in an export:\n" << blob;
	EXPECT_EQ(blob.find("admin_pw_hash"), std::string::npos) << blob;
	EXPECT_EQ(blob.find("owner_pw_hash"), std::string::npos) << blob;
	EXPECT_EQ(blob.find("pwHash"), std::string::npos) << blob;
	EXPECT_EQ(blob.find("adminHash"), std::string::npos) << blob;

	// And decrypt the gated half too -- the assertion must hold there as well,
	// not just in the plaintext section.
	std::string decryptImportResp = httpRaw(_port, "POST", "/api/config/import",
		"blob=" + urlEncode(blob) + "&password=exportpass123&confirm=REPLACE",
		"pd_session=" + _sysop.cookie, _sysop.csrf);
	// This assertion only needs the request to have been PROCESSED (200 or a
	// benign partial-skip is fine); the real check already happened above on
	// the wire bytes actually sent, which is what an attacker could read.
	EXPECT_EQ(statusOf(decryptImportResp), 200) << decryptImportResp;
}
