// HotPathInPlace_test.cpp -- #462 (#284 batch A): parse, send and drain on the
// SIP task's hot path allocate NOTHING in steady state.
//
// The gate is per unit batch A owns, each 0 after warm-up, per the done-when
// Sonny-OG set on #462. handle() end to end is NOT gated here: it also runs
// batch B's response builders and batch C's _sessions lookup, so "handle()
// == 0" belongs to whichever of #462/#463/#464 lands last (tracked on #284).
// tests/AllocBaseline_test.cpp prints the measured before/after for handle().
//
// Counted with the shared per-thread AllocGuard (#426). Each test's first case
// is a volatile-sink positive control, so a zero is never vacuous.

#include <gtest/gtest.h>

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
#include "SipMessagePool.hpp"

namespace
{
	sockaddr_in addrFor(const char* ip)
	{
		sockaddr_in s{};
		s.sin_family = AF_INET;
		s.sin_addr.s_addr = inet_addr(ip);
		s.sin_port = htons(5060);
		return s;
	}

	// Three real shapes with DIFFERENT header counts and line lengths, as they
	// arrive interleaved on one socket. Built once, outside every guard.
	const std::string kRegister =
		"REGISTER sip:server SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.7.50:5060;branch=z9hG4bKregister0001;rport\r\n"
		"Max-Forwards: 70\r\n"
		"From: <sip:500@server>;tag=rt500abcdef\r\n"
		"To: <sip:500@server>\r\n"
		"Call-ID: reg-500-0123456789abcdef@192.168.7.50\r\n"
		"CSeq: 12 REGISTER\r\n"
		"Contact: <sip:500@192.168.7.50:5060>;expires=3600\r\n"
		"User-Agent: Yealink SIP-T29G 46.86.0.5\r\n"
		"Allow: INVITE, ACK, CANCEL, BYE, NOTIFY, REFER, OPTIONS, INFO, UPDATE\r\n"
		"Content-Length: 0\r\n\r\n";

	const std::string kOptions =
		"OPTIONS sip:server SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.7.50:5060;branch=z9hG4bKopt7\r\n"
		"From: <sip:500@server>;tag=op500\r\n"
		"To: <sip:server>\r\n"
		"Call-ID: opt-500\r\n"
		"CSeq: 7 OPTIONS\r\n"
		"Content-Length: 0\r\n\r\n";

	const std::string kOk =
		"SIP/2.0 200 OK\r\n"
		"Via: SIP/2.0/UDP 192.168.7.1:5060;branch=z9hG4bKstray9\r\n"
		"From: <sip:server>;tag=srv\r\n"
		"To: <sip:500@server>;tag=ph500\r\n"
		"Call-ID: stray-ok\r\n"
		"CSeq: 9 OPTIONS\r\n"
		"Content-Length: 0\r\n\r\n";

	void positiveControl()
	{
		static void* volatile sink = nullptr;
		AllocGuard g;
		int* p = new int(3);
		sink = p;
		const std::size_t n = g.delta();
		delete p;
		sink = nullptr;
		ASSERT_EQ(n, 1u) << "AllocGuard did not see a real allocation: every zero below would be vacuous";
	}
}

// ── rank 1: parse ────────────────────────────────────────────────────────────

TEST(HotPathInPlace, ParsingInterleavedShapesIntoThePoolAllocatesNothing)
{
	positiveControl();

	// The pool hands out the FIRST free slot, so releasing each message before
	// the next parse sends every shape through the SAME slot -- which is what a
	// quiet PBX does. Shapes alternate: a longer REGISTER after a shorter OK is
	// exactly the case where a clear()-and-rebuild parser frees and reallocates.
	// The pool is process-global and only a RequestsHandler normally creates it.
	// Without this the first call falls back to a brand-new heap object every
	// time -- and the test measures the fallback, not the pool.
	sipmsgpool::ensureInitialized();

	const sockaddr_in src = addrFor("192.168.7.50");
	const std::string* order[] = {&kRegister, &kOk, &kOptions, &kRegister, &kOptions, &kOk};

	const SipMessage* slot = nullptr;
	for (int warm = 0; warm < 3; ++warm)
		for (const std::string* raw : order)
			slot = RequestsHandler::getMessageFromPool(*raw, src).get();   // released at once

	std::size_t allocs = 0;
	for (const std::string* raw : order)
	{
		AllocGuard g;
		auto m = RequestsHandler::getMessageFromPool(*raw, src);
		allocs += g.delta();
		ASSERT_TRUE(m && m->isValidMessage()) << "precondition: it really parsed";
		// Precondition: this is the SAME warmed pooled object, not a heap
		// fallback and not a cold slot -- otherwise the zero below means nothing.
		ASSERT_EQ(m.get(), slot) << "precondition: measured the warmed pooled slot";
	}
	EXPECT_EQ(allocs, 0u) << "parsing interleaved REGISTER / 200 / OPTIONS into a warmed pooled "
	                         "slot allocated (#284 rank 1)";
}

TEST(HotPathInPlace, ParsingStillProducesTheSameMessage)
{
	// Byte-identical output is part of the done-when: reusing buffers must not
	// leak a previous message's lines into this one. Parse a LONG message, then
	// a SHORT one into the same slot, and check nothing of the long one survives.
	sipmsgpool::ensureInitialized();   // a heap-fallback object would make this vacuous
	const sockaddr_in src = addrFor("192.168.7.50");
	const SipMessage* slot = nullptr;
	{
		auto longMsg = RequestsHandler::getMessageFromPool(kRegister, src);
		ASSERT_EQ(longMsg->toString(), kRegister);
		slot = longMsg.get();
	}
	auto shortMsg = RequestsHandler::getMessageFromPool(kOk, src);
	ASSERT_EQ(shortMsg.get(), slot) << "precondition: the short message reuses the long one's slot";
	EXPECT_EQ(shortMsg->toString(), kOk) << "a shorter message must not inherit the longer one's lines";
	// Spelled out as well: the lines only the long message had are really gone.
	EXPECT_EQ(shortMsg->toString().find("User-Agent"), std::string::npos);
	EXPECT_EQ(shortMsg->toString().find("Allow:"), std::string::npos);

	// and back to long: every line present, in order, none missing
	auto longAgain = RequestsHandler::getMessageFromPool(kRegister, src);
	EXPECT_EQ(longAgain->toString(), kRegister);
}

TEST(HotPathInPlace, CopyingIntoAPooledSlotAllocatesNothing)
{
	positiveControl();
	// getMessageFromPool(const SipMessage&) -- how every response is started
	// from its request -- goes through operator=, which now uses the same
	// keep-the-buffers path. Held source, released copies: one slot for the
	// source, the next slot reused for every copy.
	sipmsgpool::ensureInitialized();   // see the parse test: else this measures the heap fallback
	const sockaddr_in src = addrFor("192.168.7.50");
	auto reg = RequestsHandler::getMessageFromPool(kRegister, src);
	auto ok  = RequestsHandler::getMessageFromPool(kOk, src);
	const SipMessage* sources[] = {reg.get(), ok.get(), reg.get()};

	const SipMessage* slot = nullptr;
	for (int warm = 0; warm < 3; ++warm)
		for (const SipMessage* s : sources)
			slot = RequestsHandler::getMessageFromPool(*s).get();   // released at once

	std::size_t allocs = 0;
	for (const SipMessage* s : sources)
	{
		AllocGuard g;
		auto copy = RequestsHandler::getMessageFromPool(*s);
		allocs += g.delta();
		ASSERT_TRUE(copy);
		ASSERT_EQ(copy.get(), slot) << "precondition: measured the warmed pooled slot";
		ASSERT_EQ(copy->toString(), s->toString()) << "the copy must be exact";
	}
	EXPECT_EQ(allocs, 0u) << "copying interleaved shapes into a warmed pooled slot allocated";
}

// ── rank 2: send ─────────────────────────────────────────────────────────────

TEST(HotPathInPlace, SerialisingIntoThePersistentSendBufferAllocatesNothing)
{
	positiveControl();
	// SipServer::onHandled() now does exactly this: toString(out) into ONE
	// buffer that lives as long as the server. (SipServer itself is not linked
	// into the host test binary -- it opens real sockets -- so this tests the
	// operation it performs, not the wrapper.)
	const sockaddr_in src = addrFor("192.168.7.50");
	auto reg = RequestsHandler::getMessageFromPool(kRegister, src);
	auto opt = RequestsHandler::getMessageFromPool(kOptions, src);
	auto ok  = RequestsHandler::getMessageFromPool(kOk, src);
	const SipMessage* msgs[] = {opt.get(), reg.get(), ok.get(), reg.get()};

	std::string sendBuf;
	for (const SipMessage* m : msgs) m->toString(sendBuf);   // warm to the largest

	std::size_t allocs = 0;
	for (const SipMessage* m : msgs)
	{
		AllocGuard g;
		m->toString(sendBuf);
		allocs += g.delta();
		ASSERT_EQ(sendBuf, m->toString()) << "the buffer must hold exactly the message";
	}
	EXPECT_EQ(allocs, 0u) << "serialising into the persistent send buffer allocated (#284 rank 2)";
}

// ── rank 5: drain ────────────────────────────────────────────────────────────

TEST(HotPathInPlace, TheEndOfPassDrainAllocatesNothing)
{
	positiveControl();
	// Three messages per pass, as a busy pass might queue. The send callback
	// appends into a PRE-RESERVED vector and the messages are built before the
	// guard, so the only thing counted is the drain cycle itself: queue onto
	// _outbox, drainPassLocked(), flushPass().
	//
	// This is exactly what `auto drained = std::move(_outbox)` got wrong: the
	// moved-from _outbox restarted at zero capacity, so the three push_backs
	// reallocated (1, 2, 4) on every single pass.
	using Out = std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>>;
	Out sent;
	sent.reserve(1024);
	RequestsHandler handler("192.168.7.1", 5060,
		[&sent](const sockaddr_in& a, std::shared_ptr<SipMessage> m) { sent.emplace_back(a, std::move(m)); });

	const sockaddr_in to = addrFor("192.168.7.50");
	auto reg = RequestsHandler::getMessageFromPool(kRegister, to);
	auto opt = RequestsHandler::getMessageFromPool(kOptions, to);
	auto ok  = RequestsHandler::getMessageFromPool(kOk, to);
	const Out batch = {{to, reg}, {to, opt}, {to, ok}};

	// Warm past a FULL cycle of the outbound pcap ring, which the same drain
	// feeds (drainOutboxInto() -> PcapCapture::recordInto()). That ring grows
	// lazily to POCKETDIAL_PCAP_RING_SIZE (16) slots and each slot's string grows
	// until it has held the largest message; with 3 shapes cycling through 16
	// slots the pattern only repeats every lcm(16, 3) = 48 records = 16 passes.
	// Its one-time growth is #416/#436's to remove (preallocate at init), not
	// batch A's: measured, the drain costs 9 allocations over 5 passes when
	// warmed only 3 passes, and 0 once the ring has cycled.
	for (int warm = 0; warm < 20; ++warm)
	{
		handler.drainCycleForTest(batch);
		sent.clear();
	}

	std::size_t allocs = 0;
	for (int pass = 0; pass < 5; ++pass)
	{
		AllocGuard g;
		handler.drainCycleForTest(batch);
		allocs += g.delta();
		ASSERT_EQ(sent.size(), 3u) << "every queued message must still be sent, in order";
		EXPECT_EQ(sent[0].second, reg);
		EXPECT_EQ(sent[2].second, ok);
		sent.clear();
	}
	EXPECT_EQ(allocs, 0u) << "the end-of-pass drain allocated (#284 rank 5)";
}
