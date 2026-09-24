// SipMessagePool.cpp: the static SipMessage pool, extracted verbatim out of
// RequestsHandler (Issue #53 / #101(A) / #101(E)). See SipMessagePool.hpp.
#include "SipMessagePool.hpp"

#include <iostream>

#include "SipSdpMessage.hpp"
#include "PoolConfig.hpp"

namespace sipmsgpool
{
	namespace
	{
		// The static, process-global message pool this file guards. Static
		// because getMessageFromPool() is called by SipMessageFactory, which has
		// no RequestsHandler instance to own it on.
		std::vector<std::shared_ptr<SipMessage>> s_messagePool;

		// ── Message pool synchronization (Issue #101(A) / #101(E)) ──────────────────
		//
		// Leaf lock guarding the static pool above. LEAF means exactly that: nothing
		// inside its critical section may acquire another lock, ever. That is what makes
		// it safe to take whether or not the caller already holds RequestsHandler's
		// _mutex, with no lock ordering to reason about.
		//
		// It is needed because handing a slot out is a check-then-take (scan for
		// use_count()==1, then copy the shared_ptr) over a pool reachable from two
		// tasks at once:
		//
		//   * the UDP receive task (UdpServer.cpp:134) -> SipServer::onNewMessage ->
		//     SipMessageFactory::createMessage -> getMessageFromPool, holding NO lock —
		//     handle() only takes _mutex afterwards, on the already-allocated message;
		//   * the tick task (esp_main.cpp:192, or SipServer::tickLoop on desktop) ->
		//     tick() -> TransactionLayer::sweep -> messageFromPool, under _mutex.
		//
		// Unsynchronized, both could observe use_count()==1 on the same slot and both
		// take it, then reset() it concurrently — two owners writing the same
		// SipMessage, reallocating its strings under each other. _mutex on one side does
		// not help: a lock only excludes other holders of that same lock. Found by the
		// #101(E) audit, fixed here because it lives in the function #101(A) rewrites.
		std::mutex s_msgPoolMutex;

		std::shared_ptr<SipMessage> acquirePooledMessage()
		{
			std::lock_guard<std::mutex> poolLock(s_msgPoolMutex);

			for (auto& msg : s_messagePool)
			{
				if (msg.use_count() == 1)
				{
					// The mutex serializes TAKERS, but the previous owner released this
					// slot outside it — typically on the send path once the drained outbox
					// goes out of scope. use_count() is only an atomic load, so on its own
					// it establishes no happens-before with that releasing thread, and the
					// reset() we are about to authorize reads the message's existing string
					// and vector internals before overwriting them. This fence pairs with
					// the release the refcount decrement performs, so those writes are
					// visible before we hand the slot on.
					std::atomic_thread_fence(std::memory_order_acquire);
					// Copy INSIDE the lock: the copy is what publishes use_count()==2 and
					// so what makes this slot invisible to the other task's scan. Callers
					// initialize it (reset() / operator=) after we return, by which point
					// they own it exclusively — keeping the critical section to a scan.
					return msg;
				}
			}

			// Pool drawn down: REFUSE. There is no heap fallback (#409, desmo's rule:
			// no dynamic allocation on any task after init). The #101A fallback this
			// replaces heap-allocated a SipSdpMessage from internal DRAM -- on the SIP
			// task, under exactly the memory pressure #328 is about -- so "degrading"
			// meant spending the scarcest resource at the worst moment. Callers already
			// treat nullptr as drop-and-let-the-peer-retransmit (see the header).
			// Logged from here rather than the callers so the two getMessageFromPool
			// overloads share one rate-limit counter per pool.
			static std::atomic<std::size_t> msgWarnCount{0};
			logPoolExhausted("SIP Message", msgWarnCount);
			return nullptr;
		}
	}   // namespace

	void logPoolExhausted(const char* poolName, std::atomic<std::size_t>& warnCount)
	{
		// Rate-limited 1-in-100: a flood that drains the pool would otherwise also
		// flood the log pipe. The running total is kept in the message so the sampling
		// does not hide the true magnitude.
		const std::size_t n = warnCount.fetch_add(1, std::memory_order_relaxed) + 1;
		if ((n - 1) % 100 == 0)
		{
			std::cerr << "[WARNING] " << poolName << " pool exhausted ("
				<< n << " total)! Refusing -- no heap fallback.\n";
		}
	}

	void ensureInitialized()
	{
		if (s_messagePool.empty())
		{
			s_messagePool.reserve(POCKETDIAL_MSG_POOL);
			for (int i = 0; i < POCKETDIAL_MSG_POOL; ++i)
			{
				s_messagePool.push_back(std::make_shared<SipSdpMessage>("", sockaddr_in{}));
			}
		}
	}

	std::shared_ptr<SipMessage> getMessageFromPool(std::string_view message, sockaddr_in src)
	{
		std::shared_ptr<SipMessage> msg = acquirePooledMessage();
		if (!msg) return nullptr;   // acquirePooledMessage() already logged the pressure
		msg->reset(message, src);
		return msg;
	}

	std::shared_ptr<SipMessage> getMessageFromPool(const SipMessage& source)
	{
		std::shared_ptr<SipMessage> msg = acquirePooledMessage();
		if (!msg) return nullptr;   // acquirePooledMessage() already logged the pressure
		*msg = source;
		return msg;
	}
}
