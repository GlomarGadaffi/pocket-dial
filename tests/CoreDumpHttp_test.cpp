// CoreDumpHttp_test.cpp — issue #382: reading the panic handler's flash
// coredump back over HTTP, so a panic nobody watched on serial is recoverable
// without esptool (whose resets can park .244 in ROM download mode, #338).
//
// Driven through a real HttpServer/requireAdmin(), like TwoRoleAuth_test.cpp.
// The host has no flash: CoreDumpStore::setImageForTest() stands in for the
// partition, and every test clears it again so no other test sees a "dump".
//
// Ports: this file owns 18230-18239. See CONTRIBUTING_FIRMWARE.md's table.

#include <gtest/gtest.h>
#include "HttpServer.hpp"
#include "RequestsHandler.hpp"
#include "SipMessage.hpp"
#include "AdminAuth.hpp"
#include "CoreDumpStore.hpp"

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
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace
{
	// Duplicated raw-socket HTTP helpers -- anonymous-namespace helpers don't
	// cross translation units (same note TwoRoleAuth_test.cpp carries).
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
		std::string req = method + " " + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\n";
		if (!cookie.empty()) req += "Cookie: " + cookie + "\r\n";
		if (!csrf.empty()) req += "X-CSRF: " + csrf + "\r\n";
		if (method == "POST")
		{
			req += "Content-Type: application/x-www-form-urlencoded\r\n"
			       "Content-Length: " + std::to_string(body.size()) + "\r\n";
		}
		req += "Connection: close\r\n\r\n" + body;
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

	std::string bodyOf(const std::string& resp)
	{
		size_t sep = resp.find("\r\n\r\n");
		return sep == std::string::npos ? std::string() : resp.substr(sep + 4);
	}

	std::string extract(const std::string& resp, const std::string& marker, char end)
	{
		size_t pos = resp.find(marker);
		if (pos == std::string::npos) return "";
		size_t start = pos + marker.size();
		size_t stop = resp.find(end, start);
		return stop == std::string::npos ? std::string() : resp.substr(start, stop - start);
	}

	struct AdminSession { std::string cookie; std::string csrf; };

	AdminSession login(int port, const std::string& user, const std::string& pass)
	{
		std::string r = httpRaw(port, "POST", "/api/admin/login", "username=" + user + "&password=" + pass);
		EXPECT_EQ(statusOf(r), 200) << r;
		return AdminSession{ extract(r, "Set-Cookie: pd_session=", ';'), extract(r, "\"csrf\":\"", '"') };
	}

	// A sysop past initial setup, then an owner bootstrapped by it.
	void provisionBoth(int port, AdminSession& sysop, AdminSession& owner)
	{
		sysop = login(port, "admin", "admin");
		EXPECT_EQ(statusOf(httpRaw(port, "POST", "/api/admin/set-credential",
			"username=admin&password=realpassword123", "pd_session=" + sysop.cookie, sysop.csrf)), 200);
		EXPECT_EQ(statusOf(httpRaw(port, "POST", "/api/admin/set-owner-credential",
			"ownerUsername=owner&ownerPassword=ownerpass123", "pd_session=" + sysop.cookie, sysop.csrf)), 200);
		owner = login(port, "owner", "ownerpass123");
	}

	// Includes NUL and 0xFF, and is longer than one recv() buffer, so a
	// text-mode or truncating path cannot pass by accident. Carries the ELF
	// magic at byte 12, where a real flash image has it.
	std::vector<uint8_t> fakeImage()
	{
		std::vector<uint8_t> img(1500);
		for (size_t i = 0; i < img.size(); ++i) img[i] = static_cast<uint8_t>(i * 7);
		img[0] = 0x00;
		img[1] = 0xFF;
		img[12] = 0x7F; img[13] = 'E'; img[14] = 'L'; img[15] = 'F';
		return img;
	}

	class CoreDumpHttpTest : public ::testing::Test
	{
	protected:
		void SetUp() override
		{
			AdminAuth::clearCredential();
			CoreDumpStore::setImageForTest({});
			_port = _nextPort++;
			_handler = std::make_unique<RequestsHandler>("192.168.4.1", 5060,
				[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
			_server = std::make_unique<HttpServer>("127.0.0.1", _port, nullptr);
			_server->attachHandler(_handler.get());
			_server->start();
			std::this_thread::sleep_for(std::chrono::milliseconds(50));
		}

		void TearDown() override
		{
			_server.reset();
			_handler.reset();
			CoreDumpStore::setImageForTest({});
			AdminAuth::clearCredential();
		}

		int _port = 0;
		std::unique_ptr<HttpServer> _server;
		std::unique_ptr<RequestsHandler> _handler;
		static int _nextPort;
	};
	int CoreDumpHttpTest::_nextPort = 18230;
}

TEST_F(CoreDumpHttpTest, DownloadIsOwnerOnlyAndReturnsTheExactBytes)
{
	AdminSession sysop, owner;
	provisionBoth(_port, sysop, owner);
	const std::vector<uint8_t> img = fakeImage();
	CoreDumpStore::setImageForTest(img);

	EXPECT_EQ(statusOf(httpRaw(_port, "GET", "/api/coredump", "")), 401)
		<< "no session at all";
	EXPECT_EQ(statusOf(httpRaw(_port, "GET", "/api/coredump", "", "pd_session=" + sysop.cookie)), 403)
		<< "a coredump is a copy of task stacks and can hold secrets: owner-only, like export-with-secrets";

	const std::string resp = httpRaw(_port, "GET", "/api/coredump", "", "pd_session=" + owner.cookie);
	ASSERT_EQ(statusOf(resp), 200) << resp.substr(0, 200);
	EXPECT_NE(resp.find("Content-Type: application/octet-stream"), std::string::npos);
	const std::string body = bodyOf(resp);
	ASSERT_EQ(body.size(), img.size());
	EXPECT_EQ(0, std::memcmp(body.data(), img.data(), img.size()))
		<< "the download must be the stored image byte for byte";
}

TEST_F(CoreDumpHttpTest, StreamedDownloadIsExactOnAChunkBoundary)
{
	// The download is streamed in 1 KB chunks (a whole-dump buffer made
	// esp_flash_read() borrow 16 KB of internal DRAM). The 1500-byte image
	// above ends mid-chunk; this one is an exact multiple, where an off-by-one
	// in the chunk loop would drop or repeat the last chunk.
	AdminSession sysop, owner;
	provisionBoth(_port, sysop, owner);
	std::vector<uint8_t> img = fakeImage();
	img.resize(3 * 1024);
	for (size_t i = 1500; i < img.size(); ++i) img[i] = static_cast<uint8_t>(i * 13 + 1);
	CoreDumpStore::setImageForTest(img);

	const std::string resp = httpRaw(_port, "GET", "/api/coredump", "", "pd_session=" + owner.cookie);
	ASSERT_EQ(statusOf(resp), 200);
	EXPECT_NE(resp.find("Content-Length: 3072\r\n"), std::string::npos);
	const std::string body = bodyOf(resp);
	ASSERT_EQ(body.size(), img.size());
	EXPECT_EQ(0, std::memcmp(body.data(), img.data(), img.size()));
}

TEST_F(CoreDumpHttpTest, DownloadFallsBackToSysopOnlyWhileNoOwnerExists)
{
	// Same no-owner-yet fallback as every #173 owner action: a board upgraded
	// from the single-credential era has no owner account, and its sysop must
	// still be able to retrieve a panic. Pinned so "owner-gated" means exactly
	// what AdminAuth::sessionSatisfiesRole() does, no more.
	AdminSession sysop = login(_port, "admin", "admin");
	ASSERT_EQ(statusOf(httpRaw(_port, "POST", "/api/admin/set-credential",
		"username=admin&password=realpassword123", "pd_session=" + sysop.cookie, sysop.csrf)), 200);
	ASSERT_FALSE(AdminAuth::isOwnerProvisioned());
	CoreDumpStore::setImageForTest(fakeImage());

	EXPECT_EQ(statusOf(httpRaw(_port, "GET", "/api/coredump", "", "pd_session=" + sysop.cookie)), 200);
}

TEST_F(CoreDumpHttpTest, StatusReportsPresenceUngatedAndInfoNeedsASession)
{
	AdminSession sysop, owner;
	provisionBoth(_port, sysop, owner);

	std::string status = bodyOf(httpRaw(_port, "GET", "/api/status", ""));
	EXPECT_NE(status.find("\"coredump\":{\"present\":false,\"size\":0}"), std::string::npos) << status;
	EXPECT_EQ(statusOf(httpRaw(_port, "GET", "/api/coredump", "", "pd_session=" + owner.cookie)), 404)
		<< "no dump stored";

	CoreDumpStore::setImageForTest(fakeImage());
	status = bodyOf(httpRaw(_port, "GET", "/api/status", ""));
	EXPECT_NE(status.find("\"coredump\":{\"present\":true,\"size\":1500}"), std::string::npos)
		<< "an unwatched panic must be noticeable without logging in: " << status;

	EXPECT_EQ(statusOf(httpRaw(_port, "GET", "/api/coredump/info", "")), 401);
	const std::string info = httpRaw(_port, "GET", "/api/coredump/info", "", "pd_session=" + sysop.cookie);
	EXPECT_EQ(statusOf(info), 200);
	EXPECT_NE(bodyOf(info).find("\"present\":true"), std::string::npos) << bodyOf(info);
	EXPECT_NE(bodyOf(info).find("\"task\":\"host_test\""), std::string::npos) << bodyOf(info);
}

TEST(CoreDumpStore, StaleBytesWithoutTheElfMagicAreNotADump)
{
	// Measured on .244 (#382): the region the partition now covers held
	// stale, non-0xFF data from an older layout. IDF accepts ANY first word
	// from 4 to the partition size as a dump size; that alone must not make a
	// dump "present".
	uint8_t head[16] = {};
	const uint32_t part = 0x20000;
	head[0] = 0x00; head[1] = 0x10;                    // plausible size word
	EXPECT_FALSE(CoreDumpStore::looksLikeDump(head, sizeof(head), 4096, part))
		<< "no ELF magic at byte 12: stale data, not a dump";

	head[12] = 0x7F; head[13] = 'E'; head[14] = 'L'; head[15] = 'F';
	EXPECT_TRUE(CoreDumpStore::looksLikeDump(head, sizeof(head), 4096, part));
	EXPECT_FALSE(CoreDumpStore::looksLikeDump(head, sizeof(head), part + 1, part))
		<< "a size larger than the partition is never a dump";
	EXPECT_FALSE(CoreDumpStore::looksLikeDump(head, sizeof(head), 15, part))
		<< "too small to even hold the header";
	EXPECT_FALSE(CoreDumpStore::looksLikeDump(head, 8, 4096, part))
		<< "a short read cannot vouch for the magic";
}

TEST_F(CoreDumpHttpTest, StaleRegionReportsNoDumpOverHttp)
{
	AdminSession sysop, owner;
	provisionBoth(_port, sysop, owner);
	std::vector<uint8_t> junk = fakeImage();
	junk[12] = 'E'; junk[13] = 'O'; junk[14] = 'U'; junk[15] = 'T';   // what .244 actually held
	CoreDumpStore::setImageForTest(junk);

	const std::string status = bodyOf(httpRaw(_port, "GET", "/api/status", ""));
	EXPECT_NE(status.find("\"coredump\":{\"present\":false,\"size\":0}"), std::string::npos) << status;
	EXPECT_EQ(statusOf(httpRaw(_port, "GET", "/api/coredump", "", "pd_session=" + owner.cookie)), 404)
		<< "stale flash must never be served as a dump";
}

TEST_F(CoreDumpHttpTest, EraseNeedsTheCsrfTokenAndClearsTheDump)
{
	AdminSession sysop, owner;
	provisionBoth(_port, sysop, owner);
	CoreDumpStore::setImageForTest(fakeImage());

	EXPECT_EQ(statusOf(httpRaw(_port, "POST", "/api/coredump/erase", "", "pd_session=" + sysop.cookie)), 403)
		<< "erasing destroys evidence: a cookie alone must not be enough";
	EXPECT_TRUE(CoreDumpStore::query().present) << "the refused request must not have erased anything";

	const std::string resp = httpRaw(_port, "POST", "/api/coredump/erase", "",
		"pd_session=" + sysop.cookie, sysop.csrf);
	EXPECT_EQ(statusOf(resp), 200) << resp;
	EXPECT_NE(bodyOf(resp).find("\"erased\":true"), std::string::npos) << bodyOf(resp);
	EXPECT_FALSE(CoreDumpStore::query().present);
}
