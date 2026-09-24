// PoolNoHeapFallback_test.cpp — issue #409: an exhausted pool must never allocate.
//
// desmo's rule is no dynamic allocation on any task after init. Two pools broke
// it by design: when drained, the #101(A) fallbacks heap-allocated a
// SipSdpMessage (message pool) or a SipClient (virtual-peer pool), on the SIP
// task, from internal DRAM -- the resource #328 is short of -- at exactly the
// moment memory was tight. #409 removed both fallbacks; exhaustion now refuses.
//
// This file is the gate. For each pool it takes the pool's capacity, then
// counts heap allocations on THIS thread (AllocGuard, tests/support/AllocCounter)
// across the draws PAST it, and asserts ZERO allocations and nullptr results.
//
// The measured draws are deliberately the first ones past the pool: that is the
// moment the old fallback allocated. Mutation-checked -- restoring either
// fallback in src/ turns its test red ON THE ALLOCATION COUNT, not merely on a
// capacity check. A "delta() == 0" check is also safe under -O3 elision
// (elision can only lower a count; see AllocCounter.hpp).
//
// The refusal logs through a 1-in-100 rate limiter to std::cerr. The loops below
// run past that period, so the logging branch executes inside the guard more
// than once and is covered by the same zero-allocation assertion.

#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "AllocCounter.hpp"
#include "PoolConfig.hpp"
#include "RequestsHandler.hpp"

#if defined(_WIN32) || defined(_WIN64)
#include <WinSock2.h>
#else
#include <arpa/inet.h>
#endif

namespace
{
	sockaddr_in addr()
	{
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_port   = htons(5060);
		::inet_pton(AF_INET, "192.168.4.88", &a.sin_addr);
		return a;
	}

	// Built BEFORE any AllocGuard, so constructing the wire text is never
	// mistaken for the pool allocating.
	const std::string kRegister =
		"REGISTER sip:server SIP/2.0\r\n"
		"Via: SIP/2.0/UDP 192.168.4.88:5060;branch=z9hG4bKnofb\r\n"
		"From: <sip:188@server>;tag=tnofb\r\n"
		"To: <sip:188@server>\r\n"
		"Call-ID: no-fallback-409\r\n"
		"CSeq: 1 REGISTER\r\n"
		"Contact: <sip:188@192.168.4.88:5060>;expires=3600\r\n"
		"Content-Length: 0\r\n\r\n";

	// More draws past the pool than the log sampling period (100), so the
	// logging branch runs more than once inside the guard.
	constexpr int kPastPool = 250;
}

TEST(PoolNoHeapFallback, ExhaustedMessagePoolRefusesWithZeroAllocations)
{
	// The pool is process-global and filled by the first handler constructed.
	RequestsHandler handler("192.168.4.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	const sockaddr_in src = addr();

	// Take the pool's capacity -- and no more, so nothing past it happens
	// outside the guard. (A slot another test still holds just means fewer
	// draws here; the next draw is past the pool either way.)
	std::vector<std::shared_ptr<SipMessage>> held;
	held.reserve(POCKETDIAL_MSG_POOL);   // reserved up front: not counted below
	for (int i = 0; i < POCKETDIAL_MSG_POOL; ++i)
	{
		auto m = RequestsHandler::getMessageFromPool(kRegister, src);
		if (!m) break;
		held.push_back(std::move(m));
	}
	ASSERT_FALSE(held.empty()) << "the pool was never populated -- the test would prove nothing";
	const SipMessage& seed = *held.front();

	size_t handedOut = 0;
	AllocGuard guard;
	for (int i = 0; i < kPastPool; ++i)
	{
		// Results are kept alive only for this iteration; with the fallback
		// restored each one is a fresh heap object, which is what gets counted.
		auto viaView  = RequestsHandler::getMessageFromPool(kRegister, src);
		auto viaClone = RequestsHandler::getMessageFromPool(seed);
		handedOut += (viaView ? 1 : 0) + (viaClone ? 1 : 0);
	}
	const size_t allocs = guard.delta();   // read before any EXPECT formats a message

	EXPECT_EQ(allocs, 0u) << "a draw past the message pool heap-allocated";
	EXPECT_EQ(handedOut, 0u) << "a message was handed out past the pool's capacity";
}

TEST(PoolNoHeapFallback, ExhaustedVirtualPeerPoolRefusesWithZeroAllocations)
{
	RequestsHandler handler("192.168.4.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});

	// Exactly the pool's worth of peers, through the real allocator.
	auto held = handler.exhaustVirtualPeersForTest(POCKETDIAL_VIRTUAL_PEERS);
	ASSERT_FALSE(held.empty()) << "nothing was drawn -- the pool was never exhausted";

	// Each call below makes ONE draw past the pool. Refused, it returns an empty
	// vector and allocates nothing (its label "vpeer-drain" fits std::string's
	// SSO buffer). With the fallback restored, the draw is a `new SipClient`.
	size_t handedOut = 0;
	AllocGuard guard;
	for (int i = 0; i < kPastPool; ++i)
	{
		handedOut += handler.exhaustVirtualPeersForTest(1).size();
	}
	const size_t allocs = guard.delta();

	EXPECT_EQ(allocs, 0u) << "a draw past the virtual-peer pool heap-allocated";
	EXPECT_EQ(handedOut, 0u) << "a peer was handed out past the pool's capacity";
}
