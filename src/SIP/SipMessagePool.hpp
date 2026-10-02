#ifndef SIP_MESSAGE_POOL_HPP
#define SIP_MESSAGE_POOL_HPP

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include <lwip/sockets.h>
#elif defined(__linux__)
#include <netinet/in.h>
#elif defined _WIN32 || defined _WIN64
#include <WinSock2.h>
#endif

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string_view>
#include <vector>

class SipMessage;

// The static, process-global SipMessage pool (Issue #53 / #101(A) / #101(E)).
// Extracted verbatim out of RequestsHandler, which owned it as file-scope statics
// before this split — see the lock-ordering essay in the .cpp for why the guarding
// mutex must stay a LEAF (nothing inside its critical section may take another
// lock). RequestsHandler::getMessageFromPool() stays the public entry point
// callers use (SipMessageFactory, the handler table, tests); it forwards here.
namespace sipmsgpool
{
	// Rate-limited (1-in-100) exhaustion logger, shared by every bounded pool in
	// the engine (the message pool here, and RequestsHandler's virtual-peer pool).
	// The running total is kept in the message so sampling does not hide the true
	// magnitude of a flood. Issue #409: a drained pool REFUSES; there is no heap
	// fallback behind it any more, so there is only one pressure signal.
	void logPoolExhausted(const char* poolName, std::atomic<std::size_t>& warnCount);

	// Draws the message pool has refused since boot (Issue #409), for /api/status.
	std::size_t refusedCount();

	// Idempotent prefill of the static pool to POCKETDIAL_MSG_POOL slots. Called
	// once from RequestsHandler's constructor; safe to call from more than one
	// constructor in the same process because it is guarded by an
	// `if (empty())` check, matching the original inline prefill this replaces.
	// Construction is single-threaded (no handler is dispatching yet), so this
	// does not itself need synchronization.
	void ensureInitialized();

	// `rawBytes`/`src`: draw a pool slot and reset() it to hold this wire message.
	// Returns NULL once every slot is in use — check it. Issue #409: a drained
	// pool refuses immediately; nothing is ever allocated past POCKETDIAL_MSG_POOL. The contract for a
	// caller that gets nullptr is to DROP: it cannot answer 503, because building
	// the 503 would need a message out of the same empty pool. SIP over UDP
	// retransmits, so a dropped packet costs latency, not the call.
	// Issue #81: `message` is a view, never copied here — SipMessage::reset()
	// below reads through it once, synchronously, to parse the pooled slot.
	// Issue #105: taking it by view (not by value) also means a caller holding
	// the original wire-received bytes (SipMessageFactory::createMessage, on
	// behalf of SipServer::onNewMessage) keeps them intact after this returns.
	std::shared_ptr<SipMessage> getMessageFromPool(std::string_view message, sockaddr_in src);

	// #838: as above for a datagram off the socket (SipMessageFactory): the slot
	// is filled with SipMessage::resetFromWire(), which keeps at most
	// SipLimits::kMaxHeaderLines header lines. Everything the PBX builds and
	// re-parses itself goes through getMessageFromPool(), which keeps them all.
	std::shared_ptr<SipMessage> getMessageFromWire(std::string_view message, sockaddr_in src);

	// Clones an already-parsed message into a free pool slot via a direct field
	// copy (SipMessage's copy assignment is a plain owned-string/vector copy —
	// no shared buffer to fix up). Used by every response-building call site that
	// used to go through getMessageFromPool(source->toString(), source->getSource()),
	// which paid a full serialize + reparse just to duplicate a message we had
	// already parsed once (issue #76).
	std::shared_ptr<SipMessage> getMessageFromPool(const SipMessage& source);
}

#endif
