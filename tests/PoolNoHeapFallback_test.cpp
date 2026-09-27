// PoolNoHeapFallback_test.cpp -- issue #409: a spent pool refuses; it never
// falls back to the heap.
//
// #101A gave both engine pools a bounded heap fallback (8 SIP messages, 4
// virtual peers) that ran on the SIP task, in internal DRAM, exactly when that
// memory is scarcest (#328). desmo's rule is no dynamic allocation on the hot
// path, ever. These tests drain each pool and pin two things:
//   1. nothing is handed out past the pool's own depth (on main before #409 the
//      fallback added 8 / 4 more -- that is what makes these red there);
//   2. the refusal itself allocates nothing (counting operator new, #426) and is
//      counted for /api/status.
//
// The message pool is process-global and shared with every other test in this
// binary, so each test releases what it holds before it ends.

#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

#include "PoolConfig.hpp"
#include "RequestsHandler.hpp"
#include "support/AllocCounter.hpp"

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
		::inet_pton(AF_INET, "192.168.40.9", &a.sin_addr);
		return a;
	}

	std::string registerRaw(const std::string& callId)
	{
		return "REGISTER sip:server SIP/2.0\r\n"
		       "Via: SIP/2.0/UDP 192.168.40.9:5060;branch=z9hG4bK" + callId + "\r\n"
		       "From: <sip:101@server>;tag=t" + callId + "\r\n"
		       "To: <sip:101@server>\r\n"
		       "Call-ID: " + callId + "\r\n"
		       "CSeq: 1 REGISTER\r\n"
		       "Contact: <sip:101@192.168.40.9:5060>;expires=3600\r\n"
		       "Content-Length: 0\r\n\r\n";
	}
}

TEST(PoolNoHeapFallback, TheMessagePoolRefusesTheMomentItIsSpentAndAllocatesNothing)
{
	// A handler populates the process-global pool (see RequestsHandler_pool_test).
	RequestsHandler handler("192.168.40.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	const uint64_t refusedBefore = RequestsHandler::getMessagePoolRefusals();
	{
		std::vector<std::shared_ptr<SipMessage>> held;
		held.reserve(POCKETDIAL_MSG_POOL * 4);
		for (size_t i = 0; i < static_cast<size_t>(POCKETDIAL_MSG_POOL) * 4; ++i)
		{
			auto m = RequestsHandler::getMessageFromPool(registerRaw("h" + std::to_string(i)), poolAddr());
			if (!m) break;
			held.push_back(std::move(m));
		}
		EXPECT_LE(held.size(), static_cast<size_t>(POCKETDIAL_MSG_POOL))
			<< "nothing may be handed out past the pool: a heap fallback is back";
		ASSERT_FALSE(held.empty());

		// The first refusal pays the (rate-limited) log line; measure the next.
		const std::string raw = registerRaw("probe");
		ASSERT_EQ(RequestsHandler::getMessageFromPool(raw, poolAddr()), nullptr);
		AllocGuard guard;
		const std::shared_ptr<SipMessage> refused = RequestsHandler::getMessageFromPool(raw, poolAddr());
		const std::size_t allocations = guard.delta();
		EXPECT_EQ(refused, nullptr);
		EXPECT_EQ(allocations, 0u) << "a refusal must not touch the heap";
	}
	EXPECT_GE(RequestsHandler::getMessagePoolRefusals() - refusedBefore, 2u)
		<< "every refusal is counted for /api/status msgPoolRefusals";
}

TEST(PoolNoHeapFallback, TheVirtualPeerPoolRefusesTheMomentItIsSpentAndAllocatesNothing)
{
	RequestsHandler handler("192.168.40.1", 5060,
		[](const sockaddr_in&, std::shared_ptr<SipMessage>) {});
	const uint64_t refusedBefore = handler.getVirtualPeerRefusals();

	auto held = handler.exhaustVirtualPeersForTest();   // ends on one refusal
	EXPECT_LE(held.size(), static_cast<size_t>(POCKETDIAL_VIRTUAL_PEERS))
		<< "nothing may be handed out past the pool: a heap fallback is back";
	ASSERT_FALSE(held.empty());

	AllocGuard guard;
	const auto more = handler.exhaustVirtualPeersForTest();   // refuses at once
	const std::size_t allocations = guard.delta();
	EXPECT_TRUE(more.empty());
	EXPECT_EQ(allocations, 0u) << "a refusal must not touch the heap";
	EXPECT_GE(handler.getVirtualPeerRefusals() - refusedBefore, 2u)
		<< "every refusal is counted for /api/status vpeerPoolRefusals";
}
