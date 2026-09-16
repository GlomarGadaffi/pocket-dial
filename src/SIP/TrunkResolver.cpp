#include "TrunkResolver.hpp"

#include <cstring>

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
#include <netdb.h>
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "PsramTask.hpp"
#else
#define ESP_LOGW(...) do {} while (0)
#define ESP_LOGI(...) do {} while (0)
#endif

// ─────────────────────────────────────────────────────────────────────────────
//  Pure helpers
// ─────────────────────────────────────────────────────────────────────────────

bool TrunkResolver::parseDottedQuad(std::string_view s, uint32_t& out)
{
	// Deliberately stricter than inet_addr(). That function accepts "1.2.3",
	// "0x7f.0.0.1" and a bare integer, mapping each to SOME address -- so a
	// carrier hostname that happens to match one of those shorthands would be
	// silently turned into an address instead of being resolved as a NAME.
	// Four plain decimal octets, nothing else.
	uint32_t octets[4] = {0, 0, 0, 0};
	size_t   idx = 0;
	size_t   i = 0;

	while (idx < 4)
	{
		if (i >= s.size() || s[i] < '0' || s[i] > '9') return false;

		uint32_t v = 0;
		size_t   digits = 0;
		while (i < s.size() && s[i] >= '0' && s[i] <= '9')
		{
			v = v * 10u + static_cast<uint32_t>(s[i] - '0');
			++i;
			if (++digits > 3) return false;   // "0001" is not an octet
		}
		if (v > 255) return false;
		octets[idx++] = v;

		if (idx < 4)
		{
			if (i >= s.size() || s[i] != '.') return false;
			++i;
		}
	}
	if (i != s.size()) return false;   // trailing junk, e.g. "1.2.3.4:5060"

	out = htonl((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]);
	return true;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Cache
// ─────────────────────────────────────────────────────────────────────────────

TrunkResolver::Entry* TrunkResolver::findLocked(std::string_view host)
{
	for (auto& e : _cache)
	{
		if (e.inUse && host.size() < kMaxHostBytes
			&& std::strncmp(e.host, host.data(), host.size()) == 0
			&& e.host[host.size()] == '\0')
		{
			return &e;
		}
	}
	return nullptr;
}

TrunkResolver::Entry* TrunkResolver::claimSlotLocked(std::string_view host,
	std::chrono::steady_clock::time_point now)
{
	if (Entry* e = findLocked(host)) return e;

	// A free slot, else the most stale one. Evicting the furthest-expired entry
	// rather than the oldest-inserted keeps a live answer in preference to one
	// that is about to be re-resolved anyway.
	Entry* victim = nullptr;
	for (auto& e : _cache)
	{
		if (!e.inUse) { victim = &e; break; }
		if (!victim || e.expiresAt < victim->expiresAt) victim = &e;
	}
	if (!victim) return nullptr;

	// If every slot is still live, the nearest-to-expiry is evicted anyway rather
	// than refusing to cache: correctness does not depend on the cache (entries
	// are revalidated by expiry and a miss simply re-resolves), and refusing
	// would mean a trunk could never learn a new name once four were held.
	// With four slots and one SBC this should not arise at all.
	(void)now;

	*victim = Entry{};
	const size_t n = (host.size() < kMaxHostBytes - 1) ? host.size() : kMaxHostBytes - 1;
	std::memcpy(victim->host, host.data(), n);
	victim->host[n] = '\0';
	victim->inUse = true;
	return victim;
}

void TrunkResolver::storeLocked(std::string_view host, uint32_t ipv4, bool failed,
	std::chrono::steady_clock::time_point now)
{
	Entry* e = claimSlotLocked(host, now);
	if (!e) return;
	e->ipv4      = ipv4;
	e->failed    = failed;
	e->expiresAt = now + (failed ? kNegativeTtl : kTtl);
}

void TrunkResolver::clear()
{
	std::lock_guard<std::mutex> lock(_mutex);
	for (auto& e : _cache) e = Entry{};
}

size_t TrunkResolver::cachedEntries() const
{
	std::lock_guard<std::mutex> lock(_mutex);
	size_t n = 0;
	for (const auto& e : _cache) if (e.inUse) ++n;
	return n;
}

bool TrunkResolver::busy() const
{
	return _pending.load(std::memory_order_acquire);
}

// ─────────────────────────────────────────────────────────────────────────────
//  Lookup
// ─────────────────────────────────────────────────────────────────────────────

TrunkResolver::Status TrunkResolver::lookup(std::string_view host, uint16_t port,
	sockaddr_in& out, std::chrono::steady_clock::time_point now) const
{
	out = sockaddr_in{};
	out.sin_family = AF_INET;
	out.sin_port   = htons(port);

	if (host.empty() || host.size() >= kMaxHostBytes) return Status::Refused;

	// A literal is answered without touching the cache. Parsing four octets is
	// cheaper than scanning, and spending a slot on a literal would evict a real
	// answer for no benefit.
	uint32_t literal = 0;
	if (parseDottedQuad(host, literal))
	{
		out.sin_addr.s_addr = literal;
		return Status::Hit;
	}

	std::lock_guard<std::mutex> lock(_mutex);
	const Entry* e = const_cast<TrunkResolver*>(this)->findLocked(host);
	if (e && e->expiresAt > now)
	{
		if (e->failed) return Status::Failed;
		out.sin_addr.s_addr = e->ipv4;
		return Status::Hit;
	}

	// Expired or absent. If the worker is already on this exact name, say so
	// rather than reporting a miss the caller would react to by re-queueing.
	if (_pending.load(std::memory_order_acquire)
		&& std::strncmp(_pendingHost, host.data(), host.size()) == 0
		&& _pendingHost[host.size()] == '\0')
	{
		return Status::Pending;
	}
	return Status::Refused;
}

TrunkResolver::Status TrunkResolver::resolve(std::string_view host, uint16_t port,
	sockaddr_in& out, std::chrono::steady_clock::time_point now)
{
	const Status s = lookup(host, port, out, now);
	if (s == Status::Hit || s == Status::Pending || s == Status::Failed)
	{
		// Failed is returned as-is rather than retried: the negative entry exists
		// precisely so a bad name does not re-queue a ~7-21 s lookup per call.
		return s;
	}
	return startWorker(host) ? Status::Pending : Status::Refused;
}

// ─────────────────────────────────────────────────────────────────────────────
//  Worker
// ─────────────────────────────────────────────────────────────────────────────

void TrunkResolver::runResolve()
{
	char host[kMaxHostBytes];
	{
		std::lock_guard<std::mutex> lock(_mutex);
		std::memcpy(host, _pendingHost, sizeof(host));
	}

	uint32_t ipv4   = 0;
	bool     failed = true;

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// THE BLOCKING CALL, and the only reason this class has a task at all. Under
	// lwIP with core locking off this parks on sys_arch_sem_wait(sem, 0) -- no
	// timeout -- and returns after the per-server DNS timeout, ~7 s, up to ~21 s
	// with three servers. Nothing here can shorten that; the point is only that
	// the SIP thread is not the one waiting.
	struct addrinfo hints;
	std::memset(&hints, 0, sizeof(hints));
	hints.ai_family   = AF_INET;      // IPv4 only: sockaddr_in throughout
	hints.ai_socktype = SOCK_DGRAM;

	struct addrinfo* res = nullptr;
	if (getaddrinfo(host, nullptr, &hints, &res) == 0 && res)
	{
		for (struct addrinfo* ai = res; ai; ai = ai->ai_next)
		{
			if (ai->ai_family == AF_INET && ai->ai_addr)
			{
				ipv4   = reinterpret_cast<struct sockaddr_in*>(ai->ai_addr)->sin_addr.s_addr;
				failed = false;
				break;
			}
		}
	}
	if (res) freeaddrinfo(res);

	if (failed) ESP_LOGW("TrunkResolver", "resolve failed: %s", host);
	else        ESP_LOGI("TrunkResolver", "resolved %s", host);
#endif

	{
		std::lock_guard<std::mutex> lock(_mutex);
		storeLocked(host, ipv4, failed, std::chrono::steady_clock::now());
	}

	// Clear _pending LAST. While it is set, lookup() reports Pending for this
	// name and resolve() will not start a second worker; clearing it before the
	// answer is stored would let a caller see "not pending, not cached" and
	// queue a duplicate lookup for a name that had just been resolved.
	_pending.store(false, std::memory_order_release);
	_workerRunning.store(false, std::memory_order_release);
}

void TrunkResolver::workerEntry(void* arg)
{
	auto* self = static_cast<TrunkResolver*>(arg);
	self->runResolve();
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	vTaskDelete(nullptr);
#endif
}

bool TrunkResolver::startWorker(std::string_view host)
{
	if (host.empty() || host.size() >= kMaxHostBytes) return false;

	bool expected = false;
	if (!_pending.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
	{
		// Already resolving something. One in flight at a time, by design: a
		// trunk has one SBC, and queueing here would let a misconfigured host
		// starve a good one behind a 21 s timeout.
		return false;
	}

	{
		std::lock_guard<std::mutex> lock(_mutex);
		std::memset(_pendingHost, 0, sizeof(_pendingHost));
		std::memcpy(_pendingHost, host.data(), host.size());
	}

#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	_workerRunning.store(true, std::memory_order_release);
	// 4 KB: getaddrinfo plus a fixed frame, no TLS and no parsing. Priority 4
	// matches SmtpClient's worker -- below the SIP task, because a name lookup
	// must never preempt signalling.
	BaseType_t ok = xTaskCreateWithCaps(&TrunkResolver::workerEntry, "trunk_dns",
		4096, this, 4, nullptr, PD_TASK_STACK_CAPS);
	if (ok != pdPASS)
	{
		ESP_LOGW("TrunkResolver", "could not start resolver task");
		_workerRunning.store(false, std::memory_order_release);
		_pending.store(false, std::memory_order_release);
		return false;
	}
#else
	// Host build: no task, no getaddrinfo. runResolve() stores a failure and
	// clears _pending, so the cache/state machine stays exercisable off-device
	// without the test depending on whatever DNS the build machine has.
	runResolve();
#endif
	return true;
}

TrunkResolver::~TrunkResolver()
{
#if defined(ESP_PLATFORM) || defined(ESP32) || defined(ARDUINO)
	// The worker holds `this`. Destroying the resolver with a lookup in flight
	// would leave that task writing into freed memory, so wait it out. Bounded
	// by the DNS timeout; in practice this object lives as long as the PBX.
	while (_workerRunning.load(std::memory_order_acquire))
	{
		vTaskDelay(pdMS_TO_TICKS(10));
	}
#endif
}
