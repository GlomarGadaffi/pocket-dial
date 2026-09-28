// HttpRouteAlloc_test.cpp -- issue #410 done-when 4: the route allocation gate.
//
// Every route below is served through HttpServer::handleClient() ON THIS
// THREAD (handleClientForTest), so AllocGuard's per-thread count sees exactly
// what the route does. The count starts at the dispatch mark -- after the
// request has been read and parsed -- because request reading is done-when 2
// and still allocates for every route; the gate measures route work only
// (the dispatch table, the handler, the response).
//
// Each route is served twice and measured on the second pass, so first-use
// statics count as init, not per request.
//
// The gate: a route NOT on kAllocatingRoutes must allocate zero. Routes on
// the list still allocate today (#410 lands route by route); the test prints
// every route's count, so a route that has reached zero can be taken off the
// list, which is how the list shrinks to empty.
//
// The allowlist is a first reading of the code. The first host run prints the
// real per-route counts, and the list is corrected to match.
//
// Not exercised, and why:
//   - POST /api/ota/upload, /api/moh/upload: streamed before dispatch (never
//     reach the route table).
//   - GET /api/wifi/scan, POST /api/wifi/connect, /api/wifi/mode_ap: the radio.
//   - POST /api/email/test, telephony-config .../test and .../activate,
//     /api/moh/preview(/stop): network or RTP I/O.
//   - POST /api/factory-reset, /api/coredump/erase, /api/ota/reboot,
//     /api/configuring, /api/config/import, /api/registrar(/device), and
//     /api/admin/{login,logout,set-credential,set-owner-credential}: they
//     wipe, restart or change the credentials/session the pass depends on.

#include <gtest/gtest.h>

#include <cstdio>
#include <iostream>
#include <memory>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "AdminAuth.hpp"
#include "AllocCounter.hpp"
#include "HttpServer.hpp"
#include "RequestsHandler.hpp"

#if !defined(_WIN32) && !defined(_WIN64)   // socketpair(): POSIX host only

#include <sys/socket.h>
#include <unistd.h>

namespace
{
	thread_local std::size_t t_markCount = 0;
	thread_local bool t_marked = false;
	void markDispatch()
	{
		t_markCount = threadHeapAllocCount();
		t_marked = true;
	}

	struct Route
	{
		const char* name;       // how it is reported
		const char* method;
		const char* path;
		const char* body;       // form body for POST/PUT, "" for none
		bool authed;
	};

	const Route kRoutes[] = {
		{"GET /api/status (anonymous)", "GET", "/api/status", "", false},
		{"GET unknown path (404)",      "GET", "/no-such-route", "", false},
		{"GET /",                       "GET", "/", "", true},
		{"GET /index.html",             "GET", "/index.html", "", true},
		{"GET /api/status",             "GET", "/api/status", "", true},
		{"GET /metrics",                "GET", "/metrics", "", false},
		{"GET /api/syslog",             "GET", "/api/syslog", "", true},
		{"GET /setup/email",            "GET", "/setup/email", "", true},
		{"GET /api/email",              "GET", "/api/email", "", true},
		{"GET /setup/trunk",            "GET", "/setup/trunk", "", true},
		{"GET /api/trunk",              "GET", "/api/trunk", "", true},
		{"GET /api/moh",                "GET", "/api/moh", "", true},
		{"GET /api/cdr",                "GET", "/api/cdr", "", true},
		{"GET /api/pcap",               "GET", "/api/pcap", "", true},
		{"GET /api/coredump/info",      "GET", "/api/coredump/info", "", true},
		{"GET /api/coredump",           "GET", "/api/coredump", "", true},
		{"GET /api/trace",              "GET", "/api/trace", "", true},
		{"GET /api/diagnostics/pcap",   "GET", "/api/diagnostics/pcap", "", true},
		{"GET /api/telephony-config",   "GET", "/api/telephony-config", "", true},
		{"GET /api/e911-config",        "GET", "/api/e911-config", "", true},
		{"GET /api/sbc-mode",           "GET", "/api/sbc-mode", "", true},
		{"GET /api/did-mapping",        "GET", "/api/did-mapping", "", true},
		{"GET /api/config/export",      "GET", "/api/config/export", "", true},
		{"GET /api/ap-security",        "GET", "/api/ap-security", "", true},
		{"GET /api/registrar",          "GET", "/api/registrar", "", true},
		{"GET /api/admin/status",       "GET", "/api/admin/status", "", true},
		{"GET /api/ota/status",         "GET", "/api/ota/status", "", true},
		{"POST /api/dnd",               "POST", "/api/dnd", "ext=101&enabled=1", true},
		{"POST /api/voicemail",         "POST", "/api/voicemail", "ext=101&enabled=1", true},
		{"POST /api/forward",           "POST", "/api/forward", "ext=101&type=busy&target=102", true},
		{"POST /api/group",             "POST", "/api/group", "ext=600&members=101,102&mode=ringall", true},
		{"POST /api/dialplan",          "POST", "/api/dialplan", "pattern=6XX&action=group&target=600", true},
		{"POST /api/syslog",            "POST", "/api/syslog", "host=", true},
		{"POST /api/kill",              "POST", "/api/kill", "callId=none", true},
	};

	// Routes that still allocate (see the file comment). Remove a route once its
	// printed count is zero; the list shrinking to empty is #410 done.
	const std::set<std::string> kAllocatingRoutes = {
		"GET /", "GET /index.html", "GET /api/status", "GET /metrics",
		"GET /api/syslog", "GET /setup/email", "GET /api/email", "GET /setup/trunk",
		"GET /api/trunk", "GET /api/moh", "GET /api/cdr", "GET /api/pcap",
		"GET /api/coredump/info", "GET /api/coredump", "GET /api/trace",
		"GET /api/diagnostics/pcap", "GET /api/telephony-config", "GET /api/e911-config",
		"GET /api/sbc-mode", "GET /api/did-mapping", "GET /api/config/export",
		"GET /api/ap-security", "GET /api/registrar", "GET /api/admin/status",
		"GET /api/ota/status", "POST /api/dnd", "POST /api/voicemail", "POST /api/forward",
		"POST /api/group", "POST /api/dialplan", "POST /api/syslog", "POST /api/kill",
	};

	struct RouteBench
	{
		std::unique_ptr<RequestsHandler> handler;
		HttpServer server{"127.0.0.1", 28413, nullptr};   // never start()ed
		std::string cookie;
		std::string csrf;

		RouteBench()
		{
			handler = std::make_unique<RequestsHandler>("10.0.0.1", 5060,
				[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
			server.attachHandler(handler.get());
			AdminAuth::clearCredential();
			EXPECT_TRUE(AdminAuth::setLoginCredential("admin", "gatepassword123"));
			const std::string token = AdminAuth::createSession(AdminAuth::Role::Owner);
			cookie = "pd_session=" + token;
			csrf = AdminAuth::sessionCsrf(token);
			HttpServer::setDispatchMarkForTest(&markDispatch);
		}
		~RouteBench()
		{
			HttpServer::setDispatchMarkForTest(nullptr);
			AdminAuth::clearCredential();
		}

		// Serve one request on THIS thread. Returns the route allocation count
		// (from the dispatch mark to the end), or -1 if dispatch was never reached.
		long serve(const Route& r, std::string* response = nullptr)
		{
			std::string req = std::string(r.method) + " " + r.path + " HTTP/1.1\r\n"
				"Host: 127.0.0.1\r\nOrigin: http://127.0.0.1\r\n";
			if (r.authed) req += "Cookie: " + cookie + "\r\nX-CSRF: " + csrf + "\r\n";
			if (r.body[0])
			{
				req += "Content-Type: application/x-www-form-urlencoded\r\n"
				       "Content-Length: " + std::to_string(std::string(r.body).size()) + "\r\n\r\n" + r.body;
			}
			else
			{
				req += "\r\n";
			}

			int sv[2];
			if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { ADD_FAILURE() << "socketpair"; return -1; }
			::send(sv[1], req.data(), req.size(), MSG_NOSIGNAL);
			::shutdown(sv[1], SHUT_WR);
			std::string got;
			std::thread reader([&] {
				char buf[4096];
				for (ssize_t n; (n = ::recv(sv[1], buf, sizeof(buf), 0)) > 0;) got.append(buf, static_cast<size_t>(n));
			});
			t_marked = false;
			server.handleClientForTest(sv[0]);   // closes sv[0] itself
			const std::size_t end = threadHeapAllocCount();
			reader.join();
			::close(sv[1]);
			if (response) *response = got;
			return t_marked ? static_cast<long>(end - t_markCount) : -1;
		}
	};
}

TEST(HttpRouteAlloc, EveryRouteOffTheAllowlistAllocatesNothing)
{
	RouteBench b;
	for (const Route& r : kRoutes)
	{
		SCOPED_TRACE(r.name);
		b.serve(r);   // warm-up
		std::string resp;
		const long allocs = b.serve(r, &resp);
		std::cout << "[route-alloc] " << r.name << ": " << allocs
		          << " (" << resp.substr(0, resp.find("\r\n")) << ")\n";
		ASSERT_GE(allocs, 0) << r.name << " never reached the route table";
		if (kAllocatingRoutes.count(r.name) == 0)
		{
			EXPECT_EQ(allocs, 0) << r.name << " allocates per request and is not on the allowlist";
		}
		else if (allocs == 0)
		{
			std::cout << "[route-alloc] " << r.name << " is now allocation-free: take it off the allowlist\n";
		}
	}
}

TEST(HttpRouteAlloc, TheGateSeesAnAllocatingRoute)
{
	// Positive control: /metrics still builds its body in an ostringstream, so
	// the gate must count something for it. A gate that counted zero here would
	// pass every route vacuously.
	RouteBench b;
	const Route metrics{"GET /metrics", "GET", "/metrics", "", false};
	b.serve(metrics);
	EXPECT_GT(b.serve(metrics), 0);
}

#endif
