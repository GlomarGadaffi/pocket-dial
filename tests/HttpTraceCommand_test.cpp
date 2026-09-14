// HttpTraceCommand_test.cpp — Issue #32: live SIP tracer for the web terminal.
//
// The terminal's `trace on` / `trace off` command interpreter itself lives in
// src/Helpers/index_html.h (client-side JS) and is not host-testable — it has
// no C++ surface of its own by design: both commands and the pre-existing
// dashboard checkbox funnel into the exact same already-shipped mechanism
// (1.5 s polling of `GET /api/trace`), so there is deliberately no new
// server-side "trace on/off" endpoint or state to unit-test (see the comments
// in index_html.h next to startTrace()/stopTrace()/termExec()).
//
// What *is* new server-side surface worth pinning: prior tests
// (PcapCapture_test.cpp's TraceRecordsReflectSeqDirectionPeerAndText,
// RequestsHandler_pool_test's HandlerDropsPacketsWhilePoolIsStarvedAndRecovers)
// only ever assert against the C++-side accessor (`getTraceRecords()`), never
// against the actual bytes `GET /api/trace` puts on the wire — i.e. never
// through `HttpServer::sendApiTrace`'s `jsonEscape()` call. A real SIP message
// routinely carries a quoted, backslash-escaped digest parameter
// (`Authorization: Digest ... nonce="a\"b"`) as well as literal CRLFs, so this
// test drives a synthetic message with exactly that shape through a *real*
// HttpServer + RequestsHandler pair over a real socket (mirroring
// AdminHttpGate_test.cpp's pattern) and confirms the JSON the client's `trace
// on` command would render round-trips those bytes exactly, rather than
// producing corrupt/truncated JSON a browser's `r.json()` would throw on.
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

	// Minimal blocking HTTP GET over a raw socket. Returns the full raw
	// response (status line + headers + body). `cookie`, when non-empty, is
	// sent as the session cookie -- /api/trace requires a logged-in session
	// now (there is no more "unprovisioned, no session needed" bypass).
	std::string httpGetRaw(int port, const std::string& path, const std::string& cookie = "")
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
		std::string req = "GET " + path + " HTTP/1.1\r\n"
			"Host: 127.0.0.1\r\n" +
			cookieHeader +
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

	// Reverses HttpServer.cpp's jsonEscape() for exactly the escapes it emits
	// (\", \\, \n, \r, \t), starting right after the opening quote of a JSON
	// string value and stopping at the first unescaped ". Used to recover the
	// original raw bytes from a "text":"..." field for a byte-exact comparison,
	// without pulling in a JSON library this codebase doesn't otherwise need.
	std::string jsonUnescapeField(const std::string& body, const std::string& fieldName)
	{
		std::string marker = "\"" + fieldName + "\":\"";
		size_t pos = body.find(marker);
		if (pos == std::string::npos) return "<field not found>";
		pos += marker.size();
		std::string out;
		while (pos < body.size() && body[pos] != '"')
		{
			if (body[pos] == '\\' && pos + 1 < body.size())
			{
				char c = body[pos + 1];
				switch (c)
				{
					case '"':  out += '"';  break;
					case '\\': out += '\\'; break;
					case 'n':  out += '\n'; break;
					case 'r':  out += '\r'; break;
					case 't':  out += '\t'; break;
					default:   out += c;    break;
				}
				pos += 2;
			}
			else
			{
				out += body[pos];
				++pos;
			}
		}
		return out;
	}
}

// Ports: this file owns 18120-18124 (issue #213 — every HTTP test file gets
// a disjoint block; see CONTRIBUTING_FIRMWARE.md for the full table).
TEST(HttpTraceCommand, ApiTraceRoundTripsRawSipTextWithQuotesAndBackslashes)
{
	// /api/trace requires a logged-in session (requireAdmin) -- go straight to
	// AdminAuth for one rather than a full HTTP login round trip, which isn't
	// what this test is about.
	AdminAuth::clearCredential();
	ASSERT_TRUE(AdminAuth::setLoginCredential("admin", "realpassword123"));
	std::string sessionCookie = "pd_session=" + AdminAuth::createSession();

	RequestsHandler handler("192.168.4.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	HttpServer server("127.0.0.1", 18120, nullptr);
	server.attachHandler(&handler);
	server.start();

	// Give the accept loop a moment to come up rather than a fixed sleep before
	// the first probe.
	for (int i = 0; i < 50 && !canConnect(18120); ++i)
	{
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
	ASSERT_TRUE(canConnect(18120));

	// A synthetic REGISTER whose Authorization header carries a backslash-
	// escaped quote inside the nonce, the same shape a real digest challenge
	// response produces (RFC 2617 quoted-string with an escaped DQUOTE).
	sockaddr_in src{};
	src.sin_family = AF_INET;
	src.sin_addr.s_addr = inet_addr("192.168.4.77");
	src.sin_port = htons(5060);
	std::string raw =
		"REGISTER sip:server SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.4.77:5060;branch=z9hG4bKtrc\r\n"
		"From: <sip:101@server>;tag=trc\r\n"
		"To: <sip:101@server>\r\n"
		"Call-ID: trace-cmd-test\r\n"
		"CSeq: 1 REGISTER\r\n"
		"Authorization: Digest username=\"101\", realm=\"pocket-dial\", nonce=\"a\\\"b\"\r\n"
		"Contact: <sip:101@192.168.4.77:5060>;expires=3600\r\n"
		"Content-Length: 0\r\n\r\n";

	handler.handle(RequestsHandler::getMessageFromPool(raw, src));

	std::string resp = httpGetRaw(18120, "/api/trace", sessionCookie);
	ASSERT_NE(resp.find("200"), std::string::npos) << resp;
	ASSERT_NE(resp.find("application/json"), std::string::npos) << resp;

	size_t bodyStart = resp.find("\r\n\r\n");
	ASSERT_NE(bodyStart, std::string::npos);
	std::string body = resp.substr(bodyStart + 4);

	std::string recovered = jsonUnescapeField(body, "text");
	EXPECT_EQ(recovered, raw)
		<< "raw SIP bytes (incl. embedded quote/backslash and CRLFs) must "
		   "survive the /api/trace JSON round trip exactly, since this is the "
		   "same 'text' the terminal's `trace on` command renders verbatim";

	EXPECT_NE(body.find("\"dir\":\"in\""), std::string::npos) << body;
	EXPECT_NE(body.find("\"peer\":\"192.168.4.77:5060\""), std::string::npos) << body;
}
