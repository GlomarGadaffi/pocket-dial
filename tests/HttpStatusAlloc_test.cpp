// HttpStatusAlloc_test.cpp -- issue #410 phase 3: GET /api/status, polled
// every second by the dashboard, builds its body in a fixed per-connection
// buffer allocated at construction -- no heap per request.
//
//   1. ZERO ALLOCATION: with every snapshot table populated, and both with and
//      without a session, serving /api/status allocates nothing on the calling
//      thread (AllocGuard). Red on the old ostringstream + vector-copy route.
//   2. REFUSE, DON'T TRUNCATE: a body larger than the buffer is a 500 with no
//      partial JSON, counted in statusRefusals() and reported as
//      httpStatusRefusals on the next status.

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <thread>

#include "AllocCounter.hpp"
#include "HttpServer.hpp"
#include "RequestsHandler.hpp"

#if !defined(_WIN32) && !defined(_WIN64)   // socketpair(): POSIX host only

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

namespace
{
	std::shared_ptr<SipMessage> makeRegister(const std::string& ext)
	{
		const std::string raw =
			"REGISTER sip:server SIP/2.0\r\n"
			"Via: SIP/2.0/UDP 10.0.0.50:5060;branch=z9hG4bKst" + ext + "\r\n"
			"From: <sip:" + ext + "@server>;tag=st" + ext + "\r\n"
			"To: <sip:" + ext + "@server>\r\n"
			"Call-ID: st-reg-" + ext + "\r\n"
			"CSeq: 1 REGISTER\r\n"
			"Contact: <sip:" + ext + "@10.0.0.50:5060>;expires=3600\r\n"
			"Content-Length: 0\r\n\r\n";
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_port = htons(5060);
		inet_pton(AF_INET, "10.0.0.50", &a.sin_addr);
		return RequestsHandler::getMessageFromPool(raw, a);
	}

	struct StatusBench
	{
		std::unique_ptr<RequestsHandler> handler;
		HttpServer server{"127.0.0.1", 28412, nullptr};   // never start()ed

		StatusBench()
		{
			handler = std::make_unique<RequestsHandler>("10.0.0.1", 5060,
				[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
			handler->handle(makeRegister("101"));
			handler->handle(makeRegister("102"));
			handler->setDnd("101", true);
			handler->setVoicemail("102", true);
			handler->setForward("101", "busy", "102");
			handler->setRingGroup("600", "101,102", "ringall");
			handler->tick();
			server.attachHandler(handler.get());
		}

		// Serve /api/status on THIS thread; the socket is drained on another.
		std::string serve(bool authenticated, size_t* allocs = nullptr)
		{
			int sv[2];
			if (::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { ADD_FAILURE() << "socketpair"; return {}; }
			std::string got;
			std::thread reader([&] {
				char buf[4096];
				for (ssize_t n; (n = ::recv(sv[1], buf, sizeof(buf), 0)) > 0;) got.append(buf, static_cast<size_t>(n));
			});
			{
				AllocGuard g;
				server.sendApiStatusForTest(sv[0], authenticated);
				if (allocs) *allocs = g.delta();
			}
			::shutdown(sv[0], SHUT_WR);
			reader.join();
			::close(sv[0]);
			::close(sv[1]);
			return got;
		}
	};
}

TEST(HttpStatusAlloc, ServingStatusAllocatesNothing)
{
	StatusBench b;
	for (bool authed : {false, true})
	{
		SCOPED_TRACE(authed ? "with session" : "anonymous");
		b.serve(authed);   // warm-up: first-use statics (e.g. the IP probe) are init, not per request
		size_t allocs = 1;
		const std::string resp = b.serve(authed, &allocs);
		ASSERT_EQ(resp.rfind("HTTP/1.1 200", 0), 0u) << resp.substr(0, 200);
		EXPECT_NE(resp.find("\"clientCount\":2"), std::string::npos) << resp;
		EXPECT_NE(resp.find("\"members\":\"101,102\""), std::string::npos) << resp;
		EXPECT_EQ(resp.find("\"number\":\"101\"") != std::string::npos, authed) << resp;
		EXPECT_EQ(allocs, 0u);
	}
}

TEST(HttpStatusAlloc, ABodyThatDoesNotFitIsRefusedAndCounted)
{
	StatusBench b;
	b.server.setStatusCapForTest(256);
	const std::string refused = b.serve(true);
	EXPECT_EQ(refused.rfind("HTTP/1.1 500", 0), 0u) << refused;
	EXPECT_EQ(refused.find("\"ip\""), std::string::npos) << "no partial status: " << refused;
	EXPECT_EQ(b.server.statusRefusals(), 1u);

	b.server.setStatusCapForTest(HttpServer::kStatusBufBytes);
	EXPECT_NE(b.serve(false).find("\"httpStatusRefusals\":1,"), std::string::npos);
}

#endif
