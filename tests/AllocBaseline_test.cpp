// AllocBaseline_test.cpp -- MEASUREMENT ONLY (not a gate): per-operation heap
// allocation counts on the SIP task's hot path, for #284 / #462 / #463 / #464.
//
// Prints counts; asserts nothing except that the positive control moved. The
// gates live in the batch PRs. This exists so every batch measures against the
// same numbers, taken the same way.
//
// Method: warm each operation once (pools, vector capacities, session entries),
// then count a second identical operation on the calling thread (AllocGuard is
// per-thread). The test's own send callback appends into a pre-reserved
// vector, so it adds nothing inside the guard.

#include <gtest/gtest.h>

#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

#include "AllocCounter.hpp"
#include "RequestsHandler.hpp"
#include "SipMessage.hpp"

namespace
{
	using Sent = std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>;

	sockaddr_in addrFor(const char* ip)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip);
		s.sin_port = htons(5060);
		return s;
	}

	const char* kA = "192.168.7.50";
	const char* kB = "192.168.7.60";

	std::string reg(const std::string& ext, const char* ip, int cseq)
	{
		return "REGISTER sip:server SIP/2.0\r\n"
		       "Via: SIP/2.0/UDP " + std::string(ip) + ":5060;branch=z9hG4bKr" + ext + std::to_string(cseq) + "\r\n"
		       "From: <sip:" + ext + "@server>;tag=rt" + ext + "\r\n"
		       "To: <sip:" + ext + "@server>\r\n"
		       "Call-ID: reg-" + ext + "\r\n"
		       "CSeq: " + std::to_string(cseq) + " REGISTER\r\n"
		       "Contact: <sip:" + ext + "@" + ip + ":5060>;expires=3600\r\n"
		       "Content-Length: 0\r\n\r\n";
	}

	std::string options(const char* ip, int cseq)
	{
		return "OPTIONS sip:server SIP/2.0\r\n"
		       "Via: SIP/2.0/UDP " + std::string(ip) + ":5060;branch=z9hG4bKo" + std::to_string(cseq) + "\r\n"
		       "From: <sip:500@server>;tag=op500\r\n"
		       "To: <sip:server>\r\n"
		       "Call-ID: opt-500\r\n"
		       "CSeq: " + std::to_string(cseq) + " OPTIONS\r\n"
		       "Content-Length: 0\r\n\r\n";
	}

	// A 200 nothing is waiting for: exercises the whole response dispatch
	// (every response handler's early checks) without a live transaction.
	std::string strayOk(int cseq)
	{
		return "SIP/2.0 200 OK\r\n"
		       "Via: SIP/2.0/UDP 192.168.7.1:5060;branch=z9hG4bKstray" + std::to_string(cseq) + "\r\n"
		       "From: <sip:server>;tag=srv\r\n"
		       "To: <sip:500@server>;tag=ph500\r\n"
		       "Call-ID: stray-ok\r\n"
		       "CSeq: " + std::to_string(cseq) + " OPTIONS\r\n"
		       "Content-Length: 0\r\n\r\n";
	}

	struct Harness
	{
		Sent sent;
		std::string sendBuf;   // the persistent send buffer, as in SipServer
		RequestsHandler handler;
		Harness() : handler("192.168.7.1", 5060,
			[this](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); })
		{
			sent.reserve(4096);
			handler.handle(RequestsHandler::getMessageFromPool(reg("500", kA, 1), addrFor(kA)));
			handler.handle(RequestsHandler::getMessageFromPool(reg("600", kB, 1), addrFor(kB)));
		}
	};

	struct Counts { std::size_t parse, handle, toStrings, sendBuf; };
	constexpr int kWarm = 3;

	// Warm once with cseq, then count with cseq+1.
	template <typename MakeRaw>
	Counts measure(Harness& h, const char* src, MakeRaw make, int cseq)
	{
		// warm-up: several passes, so one-time growth (pool slots, vector and
		// string capacities, spare header-line lists) is all behind us
		for (int w = 0; w < kWarm; ++w)
		{
			auto m = RequestsHandler::getMessageFromPool(make(cseq + w), addrFor(src));
			h.handler.handle(m);
			for (auto& s : h.sent) if (s.second) { s.second->toString(h.sendBuf); }
			h.sent.clear();
		}
		const std::string raw = make(cseq + kWarm);   // built OUTSIDE every guard
		Counts c{};
		std::shared_ptr<SipMessage> m;
		{
			AllocGuard g;
			m = RequestsHandler::getMessageFromPool(raw, addrFor(src));
			c.parse = g.delta();
		}
		{
			AllocGuard g;
			h.handler.handle(m);
			c.handle = g.delta();
		}
		// Send, both ways. OLD: a fresh toString() string per outbound message.
		// NEW (#462): toString(out) into one persistent buffer, which is exactly
		// what SipServer::onHandled now does.
		{
			AllocGuard g;
			for (auto& s : h.sent)
				if (s.second) { std::string out = s.second->toString(); (void)out; }
			c.toStrings = g.delta();
		}
		{
			AllocGuard g;
			for (auto& s : h.sent)
				if (s.second) s.second->toString(h.sendBuf);
			c.sendBuf = g.delta();
		}
		std::printf("  sent %zu message(s)\n", h.sent.size());
		h.sent.clear();
		return c;
	}

	void report(const char* name, const Counts& c)
	{
		std::printf("[alloc-baseline] %-20s parse=%3zu  handle=%3zu  send:toString()=%zu  send:toString(buf)=%zu\n",
		            name, c.parse, c.handle, c.toStrings, c.sendBuf);
	}
}

TEST(AllocBaseline, PositiveControlTheCounterMoves)
{
	static void* volatile sink = nullptr;
	AllocGuard g;
	int* p = new int(1);
	sink = p;
	const std::size_t n = g.delta();
	delete p;
	EXPECT_EQ(n, 1u);
}

TEST(AllocBaseline, PrintHotPathCounts)
{
	Harness h;
	report("REGISTER (refresh)", measure(h, kA, [](int n) { return reg("500", kA, n + 10); }, 1));
	report("OPTIONS", measure(h, kA, [](int n) { return options(kA, n); }, 100));
	report("200 OK (unmatched)", measure(h, kA, [](int n) { return strayOk(n); }, 200));
}
