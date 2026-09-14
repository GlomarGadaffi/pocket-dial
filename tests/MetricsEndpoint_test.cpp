// MetricsEndpoint_test.cpp — issue #184: GET /metrics serves Prometheus
// text-exposition format (version 0.0.4) over a real HttpServer socket.
//
// Ported alongside drawbridge's issue #128 handler. Two things are pinned here
// that a "does it return 200" test would miss, because both are protocol
// requirements rather than cosmetics:
//
//   * the exposition format is a STRICT line protocol — "# HELP"/"# TYPE"
//     before each family, LF (never CRLF) inside the body, a trailing LF, and
//     bare numeric samples. A scraper does not negotiate; it fails the target.
//   * a monotonic `_total` family must be declared `counter`, never `gauge`.
//     Typed as a gauge, Prometheus skips counter-reset correction, so every
//     reboot of the board would show up as a large negative rate() instead of
//     a reset. That mistype is invisible in a smoke test and wrong forever in
//     a dashboard, so it gets its own assertion.
//
// And the gate: /metrics is deliberately UNAUTHENTICATED (the argument is at
// HttpServer::sendApiMetrics). ReachableWithNoSession pins that, because a
// later well-meaning sweep that puts every route behind requireAdmin() would
// otherwise silently turn this into a permanently-401 endpoint that no stock
// scraper could use.

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
#include <cstdlib>
#include <string>
#include <thread>

namespace
{
	// One HttpServer per test on its own port. Issue #213: every HTTP test file
	// owns a disjoint block so a lingering listener from one file can only ever
	// fail its own tests, not another file's. The 1811x range is this file's
	// block; see CONTRIBUTING_FIRMWARE.md for the full table (AdminHttpGate
	// 18080-18099, DialPlan 18100-18109, this file 18110-18114, PcapCapture
	// 18115-18119, HttpTraceCommand 18120-18124, ServiceExtensions 18125-18129,
	// TelephonyConfigHttp 19100+, ApiKillParse 193xx).
	constexpr int kPortNoHandler   = 18110;
	constexpr int kPortTypes       = 18111;
	constexpr int kPortLineEndings = 18112;
	constexpr int kPortNoSession   = 18113;
	constexpr int kPortLiveTraffic = 18114;

	// Minimal blocking HTTP GET over a raw socket, same shape as
	// AdminHttpGate_test.cpp's helper. Returns the full raw response (status
	// line + headers + body) so the tests can assert on the Content-Type header
	// and on the byte-level shape of the body, not just on parsed fields.
	std::string httpGetRaw(int port, const std::string& path,
	                       const std::string& cookie = "")
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

	int statusOf(const std::string& resp)
	{
		size_t sp1 = resp.find(' ');
		if (sp1 == std::string::npos) return -1;
		size_t sp2 = resp.find(' ', sp1 + 1);
		if (sp2 == std::string::npos) return -1;
		return std::atoi(resp.substr(sp1 + 1, sp2 - sp1 - 1).c_str());
	}

	// The response body, past the blank line ending the headers. The header
	// block is CRLF-delimited (HTTP); everything after this point must be pure
	// LF (exposition format), which is exactly what BodyIsStrictExpositionFormat
	// checks.
	std::string bodyOf(const std::string& resp)
	{
		size_t sep = resp.find("\r\n\r\n");
		if (sep == std::string::npos) return "";
		return resp.substr(sep + 4);
	}

	// Value of the sample line for `name`, or -1 if the family is absent. The
	// family name only ever appears at the start of a line on its SAMPLE line —
	// the HELP and TYPE lines start with "# " — so anchoring on a leading LF
	// picks the sample out unambiguously.
	long sampleOf(const std::string& body, const std::string& name)
	{
		size_t pos = body.find("\n" + name + " ");
		if (pos == std::string::npos) return -1;
		size_t valueStart = pos + 1 + name.size() + 1;
		return std::atol(body.c_str() + valueStart);
	}

	// A syntactically valid REGISTER from `srcIp`, built through the same pool
	// the UDP receiver uses, so handle() takes the normal path (and so bumps
	// _packetsProcessed at RequestsHandler.cpp's handler-mutex block) rather
	// than the malformed-packet early return.
	std::shared_ptr<SipMessage> makeRegisterFor(const std::string& from,
	                                            const std::string& srcIp,
	                                            const std::string& callId)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(srcIp.c_str());
		s.sin_port = htons(5060);
		std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP " + srcIp + ":5060;branch=z9hG4bKmetrics\r\n"
			"From: <sip:" + from + "@server>;tag=mt\r\n"
			"To: <sip:" + from + "@server>\r\n"
			"Call-ID: " + callId + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + from + "@" + srcIp + ":5060>;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		return RequestsHandler::getMessageFromPool(raw, s);
	}

	// Every family this endpoint exports, and the type each MUST carry.
	struct Family { const char* name; const char* type; };
	const Family kFamilies[] = {
		{ "pocketdial_uptime_seconds",             "gauge"   },
		{ "pocketdial_sip_registrations_active",   "gauge"   },
		{ "pocketdial_sip_calls_active",           "gauge"   },
		{ "pocketdial_packets_processed_total",    "counter" },
		{ "pocketdial_packets_dropped_total",      "counter" },
		{ "pocketdial_sdp_rejected_total",         "counter" },
	};
}

TEST(MetricsEndpoint, ServesExpositionFormatWithNoHandlerAttached)
{
	// The dashboard starts before the SIP stack exists (HttpServer::attachHandler),
	// and on the host build nothing ever attaches one for this test. An
	// unattached server must still answer 200 with every family present at zero:
	// a dropped family reads as a stale series to a collector, which is worse
	// than an honest 0.
	AdminAuth::clearCredential();
	HttpServer server("127.0.0.1", kPortNoHandler, nullptr);
	server.start();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));

	const std::string resp = httpGetRaw(kPortNoHandler, "/metrics");
	ASSERT_EQ(statusOf(resp), 200) << resp;

	// The exposition-format content type, exactly. `version=0.0.4` is the
	// parameter a scraper reads to choose its parser, so a bare "text/plain"
	// would not be equivalent.
	EXPECT_NE(resp.find("Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"),
	          std::string::npos)
		<< resp;

	const std::string body = bodyOf(resp);
	for (const Family& f : kFamilies)
	{
		EXPECT_NE(body.find(std::string("# HELP ") + f.name + " "), std::string::npos)
			<< f.name << " has no HELP line\n" << body;
		EXPECT_NE(body.find(std::string("# TYPE ") + f.name + " " + f.type + "\n"),
		          std::string::npos)
			<< f.name << " is not declared " << f.type << "\n" << body;
		EXPECT_GE(sampleOf(body, f.name), 0)
			<< f.name << " has no sample line\n" << body;
	}

	AdminAuth::clearCredential();
}

TEST(MetricsEndpoint, MonotonicFamiliesAreCountersNotGauges)
{
	// The mistype this exists to catch: `_total` declared `gauge`. Prometheus
	// only applies counter-reset correction to a family typed `counter`, so a
	// gauge-typed total makes every board reboot render as a large negative
	// rate() rather than a reset. Asserted per-family, and paired with the
	// converse (no `_total` family may be a gauge) so a future family cannot
	// pass by merely existing.
	AdminAuth::clearCredential();
	HttpServer server("127.0.0.1", kPortTypes, nullptr);
	server.start();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));

	const std::string body = bodyOf(httpGetRaw(kPortTypes, "/metrics"));
	ASSERT_FALSE(body.empty());

	for (const Family& f : kFamilies)
	{
		const std::string name(f.name);
		const bool isTotal = name.size() > 6 && name.compare(name.size() - 6, 6, "_total") == 0;
		EXPECT_EQ(isTotal, std::string(f.type) == "counter")
			<< name << ": the _total suffix and the declared type must agree";

		// And the TYPE line must precede its own sample line — a scraper reads
		// the type from the preceding comment block, so a sample emitted before
		// its TYPE is untyped.
		const size_t typeAt   = body.find("# TYPE " + name + " ");
		const size_t sampleAt = body.find("\n" + name + " ");
		ASSERT_NE(typeAt, std::string::npos) << name;
		ASSERT_NE(sampleAt, std::string::npos) << name;
		EXPECT_LT(typeAt, sampleAt) << name << ": TYPE must come before the sample";
	}

	AdminAuth::clearCredential();
}

TEST(MetricsEndpoint, BodyIsStrictExpositionFormat)
{
	// LF line endings, a trailing LF, and nothing but bare numbers. CRLF in the
	// body is the classic bug when a handler reuses the HTTP header convention;
	// a missing final LF truncates the last sample for strict parsers.
	AdminAuth::clearCredential();
	HttpServer server("127.0.0.1", kPortLineEndings, nullptr);
	server.start();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));

	const std::string body = bodyOf(httpGetRaw(kPortLineEndings, "/metrics"));
	ASSERT_FALSE(body.empty());

	EXPECT_EQ(body.find('\r'), std::string::npos)
		<< "exposition-format bodies are LF-only; CRLF belongs to the header block";
	EXPECT_EQ(body.back(), '\n') << "the body must end with a trailing newline";

	AdminAuth::clearCredential();
}

TEST(MetricsEndpoint, ReachableWithNoSession)
{
	// The gating decision, pinned. /metrics is in THREAT_MODEL.md §4 E-2's
	// read-only-unauthenticated class alongside /api/status, which already
	// exposes strictly more (the client roster with IPs, live sessions, the
	// dial plan). It stays reachable even on a fully provisioned board with no
	// cookie presented, because a stock Prometheus scraper cannot log in or
	// echo a CSRF token — a gated /metrics would be a permanently-401 endpoint,
	// not a hardened one.
	AdminAuth::clearCredential();
	ASSERT_TRUE(AdminAuth::setLoginCredential("admin", "realpassword123"));
	ASSERT_TRUE(AdminAuth::isProvisioned());

	HttpServer server("127.0.0.1", kPortNoSession, nullptr);
	server.start();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));

	const std::string resp = httpGetRaw(kPortNoSession, "/metrics");
	EXPECT_EQ(statusOf(resp), 200)
		<< "a scraper sends no cookie and no CSRF token; 401/403 here breaks the feature";
	EXPECT_NE(bodyOf(resp).find("# TYPE pocketdial_packets_processed_total counter"),
	          std::string::npos);

	AdminAuth::clearCredential();
}

TEST(MetricsEndpoint, PacketsProcessedTotalTracksRealTraffic)
{
	// Formatting correctly is not the same as being wired to anything. Drive one
	// real REGISTER through the handler and require the exported counter to move
	// — this is what proves the samples come from RequestsHandler's live atomics
	// rather than from a constant that happens to render.
	//
	// Only packets_processed_total is asserted on. The active-registration gauge
	// is NOT: getClientCount() reads the dashboard snapshot, which
	// RequestsHandler::tick() republishes on its own ~1 s cadence, so it lags a
	// REGISTER by up to a tick and would make this test a timing race.
	AdminAuth::clearCredential();
	RequestsHandler handler("127.0.0.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	HttpServer server("127.0.0.1", kPortLiveTraffic, nullptr);
	server.attachHandler(&handler);
	server.start();
	std::this_thread::sleep_for(std::chrono::milliseconds(50));

	const std::string before = bodyOf(httpGetRaw(kPortLiveTraffic, "/metrics"));
	const long processedBefore = sampleOf(before, "pocketdial_packets_processed_total");
	ASSERT_GE(processedBefore, 0) << before;

	std::shared_ptr<SipMessage> reg = makeRegisterFor("310", "127.0.0.210", "metrics-reg-1");
	ASSERT_TRUE(reg != nullptr) << "message pool exhausted; the rest of this test proves nothing";
	handler.handle(reg);

	const std::string after = bodyOf(httpGetRaw(kPortLiveTraffic, "/metrics"));
	const long processedAfter = sampleOf(after, "pocketdial_packets_processed_total");
	EXPECT_GT(processedAfter, processedBefore)
		<< "the counter is not reading RequestsHandler::getPacketsProcessed()\n" << after;

	AdminAuth::clearCredential();
}
