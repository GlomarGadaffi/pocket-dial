// Issue #101(A) + #101(E): message-pool backpressure and the handout race.
//
// Two properties are under test here, and they are easy to conflate:
//
//   A. Exhaustion is BOUNDED and RECOVERABLE. Past POCKETDIAL_MSG_POOL live
//      messages getMessageFromPool() refuses -- there is no heap fallback
//      behind the pool since #409 -- and releasing messages restores capacity.
//      That the refusal allocates NOTHING is pinned separately, by the
//      counting-new gate in PoolNoHeapFallback_test.cpp.
//
//   E. Every draw hands out a DISTINCT message. The pool is a process-global
//      static scanned for use_count()==1 from the UDP receive task (off-lock)
//      and the tick task (under _mutex) at once, so the scan-then-take was a
//      data race: both could take the same slot and reset() it concurrently.
//
// NOTE: because the pool is process-global and shared with every other test in
// this binary, each test here must release everything it holds before it ends.
// The scoped vectors below are load-bearing, not style.

#include <gtest/gtest.h>

#include <atomic>
#include <set>
#include <thread>
#include <vector>

#include "PoolConfig.hpp"
#include "RequestsHandler.hpp"

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	sockaddr_in poolAddr()
	{
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_port   = htons(5060);
		::inet_pton(AF_INET, "192.168.4.77", &a.sin_addr);
		return a;
	}

	std::string registerRaw(const std::string& callId)
	{
		return "REGISTER sip:server SIP/2.0\r\n"
		       "Via: SIP/2.0/UDP 192.168.4.77:5060;branch=z9hG4bK" + callId + "\r\n"
		       "From: <sip:101@server>;tag=t" + callId + "\r\n"
		       "To: <sip:101@server>\r\n"
		       "Call-ID: " + callId + "\r\n"
		       "CSeq: 1 REGISTER\r\n"
		       "Contact: <sip:101@192.168.4.77:5060>;expires=3600\r\n"
		       "Content-Length: 0\r\n\r\n";
	}

	// The total this process can ever have in flight at once: the pool itself.
	// (Before #409 this was the pool plus POCKETDIAL_MSG_HEAP_FALLBACK_MAX.)
	constexpr size_t kCeiling = POCKETDIAL_MSG_POOL;

	// The static _messagePool is populated lazily by the first RequestsHandler
	// constructed in the process. A test that draws from the pool without one in
	// existence measures an empty pool and silently proves nothing, so
	// every test here holds one — and does not depend on another test having run
	// first to fill it.
	RequestsHandler makeHandler()
	{
		return RequestsHandler("192.168.4.1", 5060,
			[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	}
}

// Draw until refused, then confirm the refusal is at the documented ceiling and
// that releasing restores capacity.
TEST(RequestsHandlerPool, RefusesPastBoundedFallbackThenRecovers) {
	RequestsHandler handler = makeHandler();   // populates the static pool
	{
		std::vector<std::shared_ptr<SipMessage>> held;
		held.reserve(kCeiling);

		// Well past the ceiling: this must terminate on its own, which is the
		// whole point — the old code would have allocated every time.
		for (size_t i = 0; i < kCeiling * 4; ++i)
		{
			auto msg = RequestsHandler::getMessageFromPool(registerRaw("c" + std::to_string(i)), poolAddr());
			if (!msg) break;
			held.push_back(std::move(msg));
		}

		EXPECT_LE(held.size(), kCeiling)
			<< "handed out more than pool + bounded fallback";
		EXPECT_GE(held.size(), static_cast<size_t>(POCKETDIAL_MSG_POOL))
			<< "refused before even the pool was drawn down";
		EXPECT_EQ(RequestsHandler::getMessageFromPool(registerRaw("over"), poolAddr()), nullptr)
			<< "must keep refusing while everything is still held";
	}

	// Everything released: the fallback deleter must have returned its budget,
	// so the very next draw succeeds again. A leaked counter shows up here.
	auto after = RequestsHandler::getMessageFromPool(registerRaw("recovered"), poolAddr());
	EXPECT_NE(after, nullptr) << "pool did not recover after all references were dropped";
}

// The clone overload draws from the same pool and must refuse the same way,
// rather than falling through to an unbounded allocation.
TEST(RequestsHandlerPool, CloneOverloadHonoursTheSameCeiling) {
	RequestsHandler handler = makeHandler();   // populates the static pool
	auto seed = RequestsHandler::getMessageFromPool(registerRaw("seed"), poolAddr());
	ASSERT_NE(seed, nullptr);
	{
		std::vector<std::shared_ptr<SipMessage>> held;
		for (size_t i = 0; i < kCeiling * 4; ++i)
		{
			auto msg = RequestsHandler::getMessageFromPool(*seed);
			if (!msg) break;
			held.push_back(std::move(msg));
		}
		EXPECT_LE(held.size() + 1, kCeiling);
		EXPECT_EQ(RequestsHandler::getMessageFromPool(*seed), nullptr);
	}
	EXPECT_NE(RequestsHandler::getMessageFromPool(*seed), nullptr);
}

// #101(E): every concurrent draw must yield a distinct message. Under the old
// unsynchronized scan two threads could both see use_count()==1 on one slot and
// both take it — this is the assertion that trips when that happens. It cannot
// prove the race is gone, but it pins the invariant and reproduces the real
// topology (desktop runs a tick thread alongside the receive path, same as the
// device's tick task alongside the UDP task).
TEST(RequestsHandlerPool, ConcurrentDrawsNeverHandOutTheSameMessageTwice) {
	RequestsHandler handler = makeHandler();   // populates the static pool
	constexpr int kThreads = 4;
	constexpr int kPerThread = 6;

	std::vector<std::vector<std::shared_ptr<SipMessage>>> perThread(kThreads);
	std::atomic<bool> go{false};
	std::vector<std::thread> threads;

	for (int t = 0; t < kThreads; ++t)
	{
		threads.emplace_back([&, t] {
			while (!go.load(std::memory_order_acquire)) { /* line them up */ }
			for (int i = 0; i < kPerThread; ++i)
			{
				auto msg = RequestsHandler::getMessageFromPool(
					registerRaw("t" + std::to_string(t) + "-" + std::to_string(i)), poolAddr());
				if (msg) perThread[t].push_back(std::move(msg));
			}
		});
	}
	go.store(true, std::memory_order_release);
	for (auto& th : threads) th.join();

	std::set<const SipMessage*> seen;
	size_t total = 0;
	for (const auto& bucket : perThread)
	{
		for (const auto& msg : bucket)
		{
			++total;
			EXPECT_TRUE(seen.insert(msg.get()).second)
				<< "same SipMessage handed to two concurrent callers";
		}
	}
	EXPECT_EQ(seen.size(), total);
	EXPECT_GT(total, 0u);
	// perThread goes out of scope here, returning everything to the pool.
}

// End to end: with the pool starved, a packet arriving at handle() must be
// dropped cleanly — no crash, no half-built response — and normal service must
// resume once capacity comes back.
TEST(RequestsHandlerPool, HandlerDropsPacketsWhilePoolIsStarvedAndRecovers) {
	RequestsHandler handler("192.168.4.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});

	{
		std::vector<std::shared_ptr<SipMessage>> held;
		for (size_t i = 0; i < kCeiling * 4; ++i)
		{
			auto msg = RequestsHandler::getMessageFromPool(registerRaw("s" + std::to_string(i)), poolAddr());
			if (!msg) break;
			held.push_back(std::move(msg));
		}
		ASSERT_FALSE(held.empty());

		// This is the real inbound shape: SipMessageFactory hands handle() whatever
		// the pool returned, which is nullptr right now. handle() already dropped
		// nulls, so the highest-volume path needed no new code.
		handler.handle(RequestsHandler::getMessageFromPool(registerRaw("starved"), poolAddr()));

		// Nothing was produced, and nothing captured — the packet never existed.
		// Both views of the ring are checked: a bare header (24 bytes, no packet
		// records) pins that no partial capture leaked in either direction, which
		// getTraceRecords().empty() alone would not catch if only the outbound
		// side had been recorded.
		EXPECT_TRUE(handler.getTraceRecords().empty())
			<< "a dropped packet must not reach the capture ring";
		EXPECT_EQ(handler.getPcapCapture().size(), 24u)
			<< "pcap ring must hold nothing but the global header";
	}

	// Capacity restored: the same packet now gets a response.
	auto revived = RequestsHandler::getMessageFromPool(registerRaw("revived"), poolAddr());
	ASSERT_NE(revived, nullptr);
	handler.handle(std::move(revived));

	auto recs = handler.getTraceRecords();
	ASSERT_FALSE(recs.empty()) << "handler stopped responding after pool recovery";
	EXPECT_NE(recs[0].text.find("REGISTER sip:server"), std::string::npos);
}
