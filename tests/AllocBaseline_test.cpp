// AllocBaseline_test.cpp -- per-operation heap allocation counts on the SIP task's
// hot path, for #284 / #462 / #463 / #464.
//
// The table (PrintHotPathCounts) is MEASUREMENT ONLY: it prints counts and asserts
// nothing except that the positive control moved. It exists so every batch measures
// against the same numbers, taken the same way.
//
// The Issue862 tests at the end ASSERT. They cover the host-compiled halves of the
// #862 paths: zero heap where the path must not allocate, and no live block left
// behind where it must free what it took (#837's leak got past count-only gates).
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
#include "Syslog.hpp"
#include "TelephonyAnchorLogic.hpp"
#include "TimeSync.hpp"

#include <algorithm>
#include <string_view>

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

// ── #862: the allocations the table above did not cover ─────────────────────────
//
// Three ESP-only call sites now run host-compiled helpers, and these tests drive
// those helpers: the syslog stamp (TimeSync + Syslog), the teardown snapshot of
// call ids (telephony::IdSnapshot) and the token body (telephony::BodyCollector).
// AllocGuard is per thread, so the zero-heap assertions are exact. The live-block
// checks read process-wide totals, which is why they compare for equality only
// around a block of work that runs on this thread alone.

TEST(AllocBaseline, Issue862SyslogStampAndLineTakeNoHeap)
{
	// 1700000000 = 2023-11-14T22:13:20Z: the synced branch, which the host never
	// reaches through rfc3339NowInto() because isSynced() is always false off-device.
	char stamp[timesync::kRfc3339Bytes];
	std::size_t nSynced = 0;
	std::size_t heapSynced = 0;
	{
		AllocGuard g;
		nSynced = timesync::formatNowOrNil(true, 1700000000, stamp, sizeof(stamp));
		heapSynced = g.delta();
	}
	EXPECT_EQ(heapSynced, 0u) << "a 20-character stamp must be built on the stack";
	EXPECT_EQ(std::string(stamp, nSynced), "2023-11-14T22:13:20Z");

	// The unsynced branch, through the entry point the syslog send path calls.
	char nil[timesync::kRfc3339Bytes];
	std::size_t nNil = 0;
	std::size_t heapNil = 0;
	{
		AllocGuard g;
		nNil = timesync::rfc3339NowInto(nil, sizeof(nil));
		heapNil = g.delta();
	}
	EXPECT_EQ(heapNil, 0u);
	EXPECT_EQ(std::string(nil, nNil), "-");

	// A synced stamp inside a finished frame (the buffer form send() writes into).
	char frame[Syslog::kMaxFrameBytes];
	std::size_t nFrame = 0;
	std::size_t heapFrame = 0;
	{
		AllocGuard g;
		nFrame = Syslog::formatFrame(frame, sizeof(frame), Syslog::Severity::Info,
		                             Syslog::kDefaultFacility, "pbx-call", "caller=310", stamp);
		heapFrame = g.delta();
	}
	EXPECT_EQ(heapFrame, 0u);
	EXPECT_EQ(std::string(frame, nFrame).rfind("<134>1 2023-11-14T22:13:20Z - pbx-call", 0), 0u);

	// The whole send() path with a sink configured. Nothing leaves the host, but the
	// frame is built as on the board. The first call sits outside the guard.
	ASSERT_TRUE(Syslog::configure("192.168.7.1"));
	Syslog::send(Syslog::Severity::Info, "pbx-call", "caller=310 callee=210 result=answered");
	std::size_t heapSend = 0;
	{
		AllocGuard g;
		Syslog::send(Syslog::Severity::Info, "pbx-call", "caller=310 callee=210 result=answered");
		heapSend = g.delta();
	}
	ASSERT_TRUE(Syslog::configure(""));   // leave the sink clean for the other tests
	EXPECT_EQ(heapSend, 0u);
}

TEST(AllocBaseline, Issue862TeardownSnapshotTakesNoHeapForIdsThatFit)
{
	// Built outside the guard, so only the snapshot's own work is counted.
	const std::string ids[] = {"1001", "2002", std::string(telephony::kParticipantIdBytes, '7')};
	telephony::IdSnapshot<4, telephony::kParticipantIdBytes> snap;
	std::size_t heap = 0;
	{
		AllocGuard g;
		for (const std::string& id : ids) snap.add(id);
		heap = g.delta();
	}
	EXPECT_EQ(heap, 0u) << "an id of kParticipantIdBytes or fewer is copied inline";
	ASSERT_EQ(snap.size(), 3u);
	for (std::size_t i = 0; i < 3; ++i)
	{
		EXPECT_EQ(std::string(snap.at(i)), ids[i]);
	}
}

TEST(AllocBaseline, Issue862TeardownSnapshotKeepsAnOverlongIdWholeAndFreesIt)
{
	if (!heapLiveTracked()) GTEST_SKIP() << "this C library cannot report block sizes";
	const std::string longId(200, 'x');   // past kParticipantIdBytes: the one case that takes the heap
	std::size_t heap = 0;
	std::size_t n = 0;
	bool same = false;
	const std::size_t blocks0 = heapLiveBlocks();
	const std::size_t bytes0 = heapLiveBytes();
	{
		telephony::IdSnapshot<4, telephony::kParticipantIdBytes> snap;
		snap.add("1001");
		{
			AllocGuard g;
			snap.add(longId);
			heap = g.delta();
		}
		n = snap.size();
		same = snap.at(1) == std::string_view(longId);
	}
	const std::size_t blocks1 = heapLiveBlocks();
	const std::size_t bytes1 = heapLiveBytes();
	EXPECT_GT(heap, 0u) << "the overlong copy must really take the heap, or this proves nothing";
	EXPECT_EQ(n, 2u) << "no id is dropped, however long";
	EXPECT_TRUE(same);
	EXPECT_EQ(blocks1, blocks0) << "the snapshot must free its overlong copy";
	EXPECT_EQ(bytes1, bytes0);
}

// Collects `src` the way readJsonStringField does (512-byte reads) and reports
// what it cost, whether it spilled, and what came back.
static void collectBody(const std::string& src, std::size_t& heap, bool& spilled, std::string& got)
{
	char fixed[telephony::kJsonBodyFixedBytes + 1];
	std::string joined;
	telephony::BodyCollector c(fixed, telephony::kJsonBodyFixedBytes);
	{
		AllocGuard g;
		for (std::size_t off = 0; off < src.size(); off += 512)
		{
			c.append(src.data() + off, std::min<std::size_t>(512, src.size() - off));
		}
		heap = g.delta();
	}
	spilled = c.spilled();
	got = std::string(c.terminated(joined));
}

TEST(AllocBaseline, Issue862TokenBodyThatFitsIsCollectedWithoutTheHeap)
{
	std::string body;
	for (std::size_t i = 0; i < 1500; ++i) body.push_back(static_cast<char>('a' + i % 26));
	const std::string exact(telephony::kJsonBodyFixedBytes, 'z');   // exactly the fixed size: still fits

	std::size_t heap1 = 0, heap2 = 0;
	bool spilled1 = true, spilled2 = true;
	std::string got1, got2;
	collectBody(body, heap1, spilled1, got1);
	collectBody(exact, heap2, spilled2, got2);

	EXPECT_EQ(heap1, 0u);
	EXPECT_FALSE(spilled1);
	EXPECT_EQ(got1, body);
	EXPECT_EQ(heap2, 0u);
	EXPECT_FALSE(spilled2);
	EXPECT_EQ(got2, exact);
}

TEST(AllocBaseline, Issue862TokenBodyThatSpillsIsKeptWholeAndFreed)
{
	if (!heapLiveTracked()) GTEST_SKIP() << "this C library cannot report block sizes";
	std::string body;
	for (std::size_t i = 0; i < 5000; ++i) body.push_back(static_cast<char>('a' + i % 26));

	std::size_t heap = 0;
	std::size_t n = 0;
	bool spilled = false;
	bool same = false;
	const std::size_t blocks0 = heapLiveBlocks();
	const std::size_t bytes0 = heapLiveBytes();
	{
		char fixed[telephony::kJsonBodyFixedBytes + 1];
		std::string joined;
		telephony::BodyCollector c(fixed, telephony::kJsonBodyFixedBytes);
		{
			AllocGuard g;
			for (std::size_t off = 0; off < body.size(); off += 512)
			{
				c.append(body.data() + off, std::min<std::size_t>(512, body.size() - off));
			}
			heap = g.delta();
		}
		spilled = c.spilled();
		n = c.size();
		same = std::string_view(c.terminated(joined)) == std::string_view(body);
	}
	const std::size_t blocks1 = heapLiveBlocks();
	const std::size_t bytes1 = heapLiveBytes();
	EXPECT_GT(heap, 0u) << "the spill must really take the heap, or this proves nothing";
	EXPECT_TRUE(spilled);
	EXPECT_EQ(n, body.size()) << "a body past the fixed size is still whole, never refused";
	EXPECT_TRUE(same);
	EXPECT_EQ(blocks1, blocks0) << "the spilled copy must be freed with the collector";
	EXPECT_EQ(bytes1, bytes0);
}
