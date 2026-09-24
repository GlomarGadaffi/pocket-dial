// FirmwareInfo_test.cpp -- issue #411: the build identifies itself.
//
// Before #411 every image said version "1" (ESP-IDF's fallback: git failed
// inside CI's build container) and /api/status carried no version at all, so
// TEST_HARNESS.md §5.3's board-provenance check had nothing to compare. These
// pin the host side of the contract:
//
//   * the stamp is a real one -- never empty, never "1", within the app
//     descriptor's 31 characters, and shaped like `git describe` output;
//   * /api/status carries it as top-level "version" (what tests/run.py reads)
//     AND in the "firmware" block, and the two are the same string;
//   * it is served to an UNAUTHENTICATED caller, because provenance fetches
//     without a session -- a gated field would silently turn provenance off.
//
// The device side (the stamp really reaching the image's app descriptor) is
// tools/ci/check_app_version.py, run against each firmware CI builds.
//
// Ports: this file owns 18190-18199.

#include <gtest/gtest.h>

#include <cstring>
#include <memory>
#include <regex>
#include <string>
#include <thread>

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#define PD_FW_CLOSESOCK(s) closesocket(s)
#else
#include <arpa/inet.h>
#include <csignal>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#define PD_FW_CLOSESOCK(s) close(s)
#endif

#include "AdminAuth.hpp"
#include "FirmwareInfo.hpp"
#include "HttpServer.hpp"

namespace
{
#if !defined(_WIN32) && !defined(_WIN64)
	// Same guard as EmailHttp_test.cpp: an unguarded send() to a closed peer
	// raises SIGPIPE and kills the whole test binary.
	struct SigpipeIgnoreFw { SigpipeIgnoreFw() { std::signal(SIGPIPE, SIG_IGN); } };
	SigpipeIgnoreFw g_sigpipeIgnoreFw;
#endif

	std::string httpGet(int port, const std::string& path)
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
			PD_FW_CLOSESOCK(s);
			return "";
		}
		const std::string req = "GET " + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\n"
		                        "Connection: close\r\n\r\n";
		send(s, req.c_str(), static_cast<int>(req.size()), 0);
		std::string resp;
		char buf[4096];
		int n;
		while ((n = recv(s, buf, sizeof(buf), 0)) > 0) resp.append(buf, static_cast<size_t>(n));
		PD_FW_CLOSESOCK(s);
		return resp;
	}

	std::string bodyOf(const std::string& resp)
	{
		const size_t at = resp.find("\r\n\r\n");
		return at == std::string::npos ? "" : resp.substr(at + 4);
	}

	int statusOf(const std::string& resp)
	{
		const size_t sp1 = resp.find(' ');
		if (sp1 == std::string::npos) return -1;
		return std::atoi(resp.c_str() + sp1 + 1);
	}
}

// ── The stamp itself ─────────────────────────────────────────────────────────

TEST(FirmwareInfo, TheStampIsARealVersionNeverTheIdfFallback)
{
	const std::string v = FirmwareInfo::version();
	EXPECT_FALSE(v.empty());
	EXPECT_NE(v, "1") << "\"1\" is ESP-IDF's fallback when nothing set PROJECT_VER -- "
	                     "exactly the failure #411 fixes";
	EXPECT_LE(v.size(), 31u) << "esp_app_desc_t.version is char[32]; a longer stamp is "
	                            "truncated from the END, which is where -dirty lives";
	EXPECT_EQ(v, POCKETDIAL_FW_VERSION) << "FirmwareInfo must report the stamp CMake chose";
}

TEST(FirmwareInfo, TheStampIsShapedLikeGitDescribeOrSaysUnknown)
{
	// "unknown" is the only non-git value allowed (a build with no git at all).
	// Everything else must be what cmake/FirmwareVersion.cmake can produce:
	//   v1.5.0-beta.2-93-g98cc830     describe, commits since a tag
	//   v1.6.0                        describe, exactly on a tag
	//   98cc830a1b2c                  bare hash (describe too long, or no tags)
	// each optionally followed by -dirty.
	const std::string v = FirmwareInfo::version();
	if (v == "unknown") GTEST_SKIP() << "built without git; nothing to shape-check";
	static const std::regex kShape(
		R"(^(.+-[0-9]+-g[0-9a-f]{7,}|[0-9a-f]{7,40}|[^\s]+)(-dirty)?$)");
	EXPECT_TRUE(std::regex_match(v, kShape)) << "unexpected stamp shape: " << v;
	EXPECT_EQ(v.find_first_of(" \t\r\n\""), std::string::npos)
		<< "a stamp that needs escaping has come from somewhere other than git";
}

TEST(FirmwareInfo, HostIdfAndBuildTimeAreReported)
{
	EXPECT_STREQ(FirmwareInfo::idfVersion(), "host");
	EXPECT_GT(std::strlen(FirmwareInfo::buildDate()), 0u);
	EXPECT_GT(std::strlen(FirmwareInfo::buildTime()), 0u);
}

// ── /api/status ──────────────────────────────────────────────────────────────

namespace
{
	class FirmwareStatusTest : public ::testing::Test
	{
	protected:
		void SetUp() override
		{
			AdminAuth::clearCredential();
			_port = _nextPort++;
			_server = std::make_unique<HttpServer>("127.0.0.1", _port, nullptr);
			_server->start();
			std::this_thread::sleep_for(std::chrono::milliseconds(50));
		}
		void TearDown() override
		{
			_server.reset();
			AdminAuth::clearCredential();
		}
		int _port = 0;
		std::unique_ptr<HttpServer> _server;
		static int _nextPort;
	};
	int FirmwareStatusTest::_nextPort = 18190;
}

TEST_F(FirmwareStatusTest, StatusCarriesTheVersionToAnUnauthenticatedCaller)
{
	// No session, on purpose: this is how tests/run.py's board-provenance check
	// fetches it. If "version" were withheld here, run.py would see an empty
	// value and SKIP the comparison instead of failing it.
	const std::string resp = httpGet(_port, "/api/status");
	ASSERT_EQ(statusOf(resp), 200);
	const std::string body = bodyOf(resp);
	const std::string v = FirmwareInfo::version();

	EXPECT_NE(body.find("\"version\":\"" + v + "\""), std::string::npos)
		<< "top-level \"version\" (what tests/run.py reads) is missing or wrong: " << body;
	EXPECT_NE(body.find("\"firmware\":{\"version\":\"" + v + "\""), std::string::npos)
		<< "the firmware block must carry the SAME string: " << body;
	EXPECT_NE(body.find("\"idf\":\"host\""), std::string::npos) << body;
	EXPECT_EQ(body.find("\"version\":\"1\""), std::string::npos)
		<< "the ESP-IDF fallback must never reach /api/status";
}
