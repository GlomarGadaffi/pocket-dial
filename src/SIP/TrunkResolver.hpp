#ifndef TRUNK_RESOLVER_HPP
#define TRUNK_RESOLVER_HPP

#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include <lwip/sockets.h>
#elif defined(__linux__)
#include <netinet/in.h>
#elif defined _WIN32 || defined _WIN64
#include <WinSock2.h>
#endif

// ── Carrier SBC name resolution, off the SIP thread (issue #164) ─────────────
//
// A SIP trunk is configured with an FQDN far more often than a dotted quad, and
// SipTrunk::placeCall() takes an ALREADY-RESOLVED address precisely because the
// resolution cannot happen where the call is placed. This class is the piece
// that closes that gap.
//
// ── Why this exists at all, rather than just calling getaddrinfo ─────────────
//
// **getaddrinfo() is untimed-blocking under ESP-IDF's lwIP.** With core locking
// off (this sdkconfig), it parks on `sys_arch_sem_wait(sem, 0)` -- wait forever,
// no timeout argument anywhere in the path. In practice it returns after the
// per-server DNS timeout, about 7 s, and with three servers configured a failing
// lookup can hold its caller for roughly 21 s.
//
// The SIP thread cannot afford that. It services every registration, every
// re-INVITE, every BYE and drives TransactionLayer::sweep(); blocking it for
// even one DNS timeout drops retransmissions on every call in progress, not
// just the one being placed. SmtpClient.cpp set the precedent here -- its
// blocking network work runs on a dedicated worker task, never inline.
//
// ── Why it caches for itself ─────────────────────────────────────────────────
//
// lwIP has its own DNS cache, and it is not usable for this: it holds **four
// entries globally**, shared with every other name the firmware resolves (NTP,
// the dashboard's outbound calls, SMTP), and it exposes no TTL, so a caller
// cannot tell a fresh answer from a stale one or know when to re-resolve. A
// trunk that silently kept using a carrier's retired SBC address would fail
// every call with no diagnostic. So the answer and its expiry are kept here.
//
// ── Concurrency contract ─────────────────────────────────────────────────────
//
// `resolve()` and `lookup()` are called from the SIP thread and NEVER block.
// The blocking work happens on one worker task. The cache is guarded by a
// mutex held only for the duration of a fixed-size array scan -- never across
// the lookup itself, so the worker cannot stall the SIP thread.
//
// Bounded and allocation-free after construction: a fixed cache, a fixed
// one-deep request slot, and fixed char buffers. Out of room means the request
// is refused, not queued (CONTRIBUTING_FIRMWARE rule 1).
class TrunkResolver
{
public:
	// Small on purpose. A trunk points at one SBC, occasionally a primary and a
	// backup; this is not a general-purpose resolver and should not become one.
	static constexpr size_t kCacheEntries = 4;
	static constexpr size_t kMaxHostBytes = 64;   // matches SipTrunk::Config::host

	// How long an answer is trusted. DNS TTLs are not available through
	// getaddrinfo(), so this is a fixed conservative figure rather than the
	// record's own: long enough that a busy trunk is not re-resolving per call,
	// short enough that a carrier moving an SBC is picked up within the hour.
	static constexpr std::chrono::seconds kTtl{300};

	// A failed lookup is remembered too, and for much less time. Without this a
	// trunk pointed at a bad name re-queues a ~7-21 s resolution on every call
	// attempt and the worker never gets ahead; with it, the failure answers
	// instantly until the negative entry ages out.
	static constexpr std::chrono::seconds kNegativeTtl{30};

	enum class Status : uint8_t
	{
		Hit,        // `out` is a usable address
		Pending,    // a resolution is in flight; ask again shortly
		Failed,     // resolution failed recently and is still cached as failed
		Refused,    // nothing in flight could be started (worker busy, bad input)
	};

	TrunkResolver() = default;
	~TrunkResolver();

	TrunkResolver(const TrunkResolver&)            = delete;
	TrunkResolver& operator=(const TrunkResolver&) = delete;

	// Look a host up WITHOUT blocking and WITHOUT starting any work.
	//
	// A dotted quad is answered directly and never cached -- parsing one is
	// cheaper than a cache scan, and burning a cache slot on a literal would
	// evict a real answer.
	Status lookup(std::string_view host, uint16_t port, sockaddr_in& out,
		std::chrono::steady_clock::time_point now) const;

	// Look up, and if there is no usable answer, START one on the worker task.
	// Still never blocks. Returns Hit when the answer was already cached, so a
	// caller can place its call immediately in the common case.
	Status resolve(std::string_view host, uint16_t port, sockaddr_in& out,
		std::chrono::steady_clock::time_point now);

	// Drop everything. For a config change: the operator has pointed the trunk
	// at a different carrier and the old answer is not merely stale, it is
	// wrong.
	void clear();

	// ── Pure helpers, host-tested ───────────────────────────────────────────

	// "203.0.113.5" -> true and fills `out`. Rejects anything that is not four
	// decimal octets, including the forms inet_addr() accepts and SIP does not
	// ("1.2.3", "0x7f.1", trailing junk) -- a carrier host that happens to
	// parse as a shortened literal must be treated as a NAME, not silently
	// turned into a different address.
	static bool parseDottedQuad(std::string_view s, uint32_t& out);

	// Test/diagnostic. Cheap scans over fixed arrays.
	size_t cachedEntries() const;
	bool   busy() const;

private:
	struct Entry
	{
		char     host[kMaxHostBytes] = {};
		uint32_t ipv4   = 0;       // network byte order
		bool     inUse  = false;
		bool     failed = false;   // a remembered failure, see kNegativeTtl
		std::chrono::steady_clock::time_point expiresAt{};
	};

	// Caller holds _mutex.
	Entry* findLocked(std::string_view host);
	Entry* claimSlotLocked(std::string_view host,
		std::chrono::steady_clock::time_point now);
	void   storeLocked(std::string_view host, uint32_t ipv4, bool failed,
		std::chrono::steady_clock::time_point now);

	// Hand `host` to the worker. Returns false when one is already in flight --
	// a trunk resolving two names at once is not a case worth a second task.
	bool startWorker(std::string_view host);

	// The worker body. ESP-only; on host it is a no-op stub so the cache and
	// state machine stay exercisable off-device.
	static void workerEntry(void* arg);
	void        runResolve();

	mutable std::mutex              _mutex;
	std::array<Entry, kCacheEntries> _cache{};

	// The single in-flight request. One deep: a trunk has one SBC, and a queue
	// here would only let a misconfigured host starve a good one.
	char              _pendingHost[kMaxHostBytes] = {};
	std::atomic<bool> _pending{false};
	std::atomic<bool> _workerRunning{false};
};

#endif // TRUNK_RESOLVER_HPP
