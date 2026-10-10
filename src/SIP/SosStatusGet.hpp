#ifndef SOS_STATUS_GET_HPP
#define SOS_STATUS_GET_HPP

// ── The 911/933 lane's status GET: allocation contract and bounded claim (#948) ──────────────
// Operator ruling on #948 (2026-10-09). TelephonyAnchorClient.cpp is ESP-only, so the decisions
// live here, dependency-free, and the .cpp passes in esp_http_client, esp_timer and vTaskDelay.
//
//   Allocation contract. The sos lane's status GET may allocate only under a failure contract:
//   a failed allocation, a failed or short read, or a body that does not fit the arena is an
//   error, never partial data. Truncating into a fixed buffer is rejected: a truncated
//   participant list can silently mis-decide the 911's own leg. The caller then takes the
//   conservative route: it never assumes its own leg answered. The std::string the body is
//   handed back in allocates under a std::bad_alloc catch, so that too is an error and not a
//   terminate (exceptions are on, sdkconfig.defaults). The documented exemption from #427 for
//   this GET is what the callers do with the body: the cJSON parse (a NULL return is "no
//   list", the same conservative route) and their own std::string work.
//
//   Bounded claim. The handle is owned through a lock-free claim, never a mutex held across
//   socket I/O. Nothing on the 911 path waits for it: the GET takes the fallback at once, and
//   teardown waits at most kSosClaimBoundUs.
//
//   A 911/933 whose list reads all fail (#349 window) proceeds with no own leg; see unreadOutcome.

#include <atomic>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <new>
#include <string>

#include "TelephonyAnchorLogic.hpp"
#include "Witness.hpp"

namespace telephony
{

// ── Body arena ───────────────────────────────────────────────────────────────

// One block, reserved with the sos handle and freed with it. The allocator is passed in: the
// ESP build uses psram::allocPreferPsram, and a test can refuse the allocation.
class BodyArena
{
public:
	using AllocFn = void* (*)(std::size_t);
	using FreeFn  = void (*)(void*);

	BodyArena() = default;
	BodyArena(const BodyArena&) = delete;
	BodyArena& operator=(const BodyArena&) = delete;
	~BodyArena() { release(); }

	// True when the block is there. A block already reserved is kept, so a handle rebuild or a
	// second GET costs nothing.
	bool reserve(std::size_t cap, AllocFn alloc, FreeFn dealloc)
	{
		if (_p) return true;
		if (cap == 0) return false;
		_p = static_cast<char*>(alloc(cap));
		if (!_p) return false;
		_cap  = cap;
		_free = dealloc;
		return true;
	}

	void release()
	{
		if (_p) _free(_p);
		_p    = nullptr;
		_cap  = 0;
		_free = nullptr;
	}

	char*       data() const { return _p; }
	std::size_t capacity() const { return _cap; }

private:
	char*       _p   = nullptr;
	std::size_t _cap = 0;
	FreeFn      _free = nullptr;
};

// The arena's size, derived, not measured: the repo holds no captured 3CX body. The sos lane reads
// two: GET /callcontrol/{dn}/participants (the larger) and .../devices (about 130 B an object).
//   One participant object: 768 B. Counting the fields the code reads (id, status, party_dn,
//   party_caller_id, party_caller_name, direct_control) and the rest of 3CX's published
//   Participant (device_id, party_dn_type, originated_by_*, referred_by_*, on_behalf_of_*, callid,
//   legid) with every string at its longest, the object is 762 B (about 430 B typical).
//   Objects: two legs for each anchor call (our own and the far leg, both listed) plus
//   kSosSpareLegs for ringing inbound legs and legs not yet removed (AnchorOwnLegs holds 8).
// POCKETDIAL_MAX_ANCHOR_CALLS 4: 16 x 768 = 12288 B. A longer list is an error, not a shorter list.
inline constexpr std::size_t kSosListObjectBytes = 768;
inline constexpr std::size_t kSosSpareLegs       = 8;

constexpr std::size_t sosBodyArenaBytes(unsigned anchorCalls)
{
	return (2 * std::size_t{anchorCalls} + kSosSpareLegs) * kSosListObjectBytes;
}

enum class BodyRead : uint8_t
{
	Ok,
	NoArena,     // no block reserved: nothing was read
	ReadError,   // the transport failed
	Short,       // the body ended before the response said it was complete
	TooBig,      // more body than the arena holds
	AllocFailed, // the std::string the body is handed back in could not allocate
};

inline const char* bodyReadName(BodyRead r)
{
	switch (r)
	{
		case BodyRead::Ok:        return "ok";
		case BodyRead::NoArena:   return "no arena";
		case BodyRead::ReadError: return "read error";
		case BodyRead::Short:     return "short read";
		case BodyRead::TooBig:    return "body over the arena";
		case BodyRead::AllocFailed: return "allocation failed";
	}
	return "?";
}

// One attempt at the whole body. read(char*, int) is esp_http_client_read's contract: bytes
// read, 0 at the end, < 0 on error. complete() is esp_http_client_is_complete_data_received:
// that call returns 0 on a peer FIN before Content-Length bytes arrived (IDF v6.0.1,
// esp_http_client.c:1443-1449), so 0 alone is not the end of the body.
//
// Ok: out holds the whole body. Anything else: out is empty, whatever was read before the
// failure is never shown. Each call starts at zero, so a retry cannot glue its bytes onto an
// earlier attempt's.
//
// Out is a std::string; it is a template parameter only so a test can hand in one whose assign
// throws std::bad_alloc, which a real heap cannot be made to do on demand. The hand-back is the
// one allocation here: a throw is caught, out is left empty, the result is AllocFailed.
template <class ReadFn, class CompleteFn, class Out>
BodyRead readSosBody(const BodyArena& arena, ReadFn&& read, CompleteFn&& complete, Out& out)
{
	out.clear();
	char* const buf = arena.data();
	const std::size_t cap = arena.capacity();
	if (!buf || cap == 0) return BodyRead::NoArena;

	std::size_t len = 0;
	for (;;)
	{
		if (len == cap)
		{
			char probe = 0;   // the block is full: is there more?
			const int n = read(&probe, 1);
			if (n < 0) return BodyRead::ReadError;
			if (n > 0) return BodyRead::TooBig;
			break;
		}
		const std::size_t room = cap - len;
		const int n = read(buf + len, room > static_cast<std::size_t>(INT_MAX) ? INT_MAX : static_cast<int>(room));
		if (n < 0) return BodyRead::ReadError;
		if (n == 0) break;
		len += static_cast<std::size_t>(n);
	}
	if (!complete()) return BodyRead::Short;
	try
	{
		out.assign(buf, len);
	}
	catch (const std::bad_alloc&)
	{
		out.clear();
		return BodyRead::AllocFailed;
	}
	return BodyRead::Ok;
}

// ── Bounded claim ────────────────────────────────────────────────────────────

// 10 ms is the ruling's ceiling for closeSosStatusClient(). A pause is taken only while a whole
// tick still fits, so 8 ms leaves one tick of overshoot and the scheduler's slack under it.
inline constexpr int64_t kSosClaimBoundUs = 8'000;

// What a 911/933 status GET waits for a claim another 911's GET holds: nothing. Rule 5: a 911 is
// never delayed. It takes the fallback (no status read, proceed with no own leg) at once.
inline constexpr int64_t kSosGetClaimBoundUs = 0;

// Take the flag, pausing between tries while another whole step still fits in boundUs.
// False: held by someone else. nowUs() is a microsecond clock; pause() sleeps one step.
template <class NowFn, class PauseFn>
bool claimWithin(std::atomic<bool>& flag, int64_t boundUs, int64_t stepUs, NowFn&& nowUs, PauseFn&& pause)
{
	if (!flag.exchange(true, std::memory_order_acquire)) return true;
	const int64_t startUs = nowUs();
	while (nowUs() - startUs + stepUs <= boundUs)
	{
		pause();
		if (!flag.exchange(true, std::memory_order_acquire)) return true;
	}
	return false;
}

// RAII claim. It releases the flag only if it took it: a claim that failed leaves the other
// holder's flag alone. A null flag claims nothing and counts as held (the ordinary lane).
class SosStatusClaim
{
public:
	template <class NowFn, class PauseFn>
	SosStatusClaim(std::atomic<bool>* flag, int64_t boundUs, int64_t stepUs, NowFn&& nowUs, PauseFn&& pause)
	    : _flag(flag), _held(flag == nullptr || claimWithin(*flag, boundUs, stepUs, nowUs, pause))
	{
	}
	~SosStatusClaim()
	{
		if (_flag && _held) _flag->store(false, std::memory_order_release);
	}
	SosStatusClaim(const SosStatusClaim&) = delete;
	SosStatusClaim& operator=(const SosStatusClaim&) = delete;

	bool held() const { return _held; }

private:
	std::atomic<bool>* _flag;
	bool               _held;
};

// ── Witness ──────────────────────────────────────────────────────────────────

enum class SosFallback : uint8_t { Teardown, Get };

// Counts every fallback; writes a line for the first kLinesPerSite at each site, so a stuck
// handle cannot flood the log for the rest of the boot. No number or credential in a line.
class SosWitness
{
public:
	static constexpr uint32_t kLinesPerSite = 3;

	// True when this one wrote a line.
	bool note(SosFallback site)
	{
		const uint32_t seen = _n[static_cast<std::size_t>(site)].fetch_add(1, std::memory_order_relaxed);
		if (seen >= kLinesPerSite) return false;
		if (site == SosFallback::Teardown)
			PD_WITNESS_W("anchor", "911 status handle: teardown claim not won within the bound, handle and arena left to the in-flight GET (#948)");
		else
			PD_WITNESS_W("anchor", "911 status GET: handle claim held, no status read, the call takes the conservative route (#948)");
		return true;
	}

	uint32_t count(SosFallback site) const { return _n[static_cast<std::size_t>(site)].load(std::memory_order_relaxed); }

private:
	std::atomic<uint32_t> _n[2] = {};
};

// closeSosStatusClient()'s body. freeAll() runs once, under the claim. If the claim is not won
// within the bound nothing is freed: the handle and arena stay owned by the client (the next
// start()'s warm GET reuses them and the next close that wins the claim frees them) and the
// witness records it. False: the fallback was taken.
template <class NowFn, class PauseFn, class FreeFn>
bool closeWithinBound(std::atomic<bool>& flag, int64_t stepUs, NowFn&& nowUs, PauseFn&& pause, FreeFn&& freeAll,
                      SosWitness& witness)
{
	SosStatusClaim claim(&flag, kSosClaimBoundUs, stepUs, nowUs, pause);
	if (!claim.held())
	{
		witness.note(SosFallback::Teardown);
		return false;
	}
	freeAll();
	return true;
}

// ── The #349 window ──────────────────────────────────────────────────────────

// makeCall(): the makecall POST reached 3CX and no response was read. The participant list is
// read every kUnreadAdoptPollMs until it shows our leg or the window closes (unreadMakecallStep).
// readOnce() is one resolveOutboundLeg() read: the leg id, or "" when the read failed or the list
// shows none. keepGoing() is false once the anchor is stopping. onReread(reads) logs.
struct UnreadWindow
{
	std::string ownLeg;
	int         reads = 0;
};

template <class ReadFn, class NowFn, class KeepFn, class RereadFn, class PauseFn>
UnreadWindow readOwnLegWindow(ReadFn&& readOnce, NowFn&& nowUs, KeepFn&& keepGoing, RereadFn&& onReread, PauseFn&& pause)
{
	UnreadWindow w;
	const int64_t startUs = nowUs();
	for (;;)
	{
		w.ownLeg = readOnce();
		++w.reads;
		if (unreadMakecallStep(!w.ownLeg.empty(), nowUs() - startUs) != UnreadMakecallStep::ReadAgain || !keepGoing())
			break;
		onReread(w.reads);
		pause();
	}
	return w;
}

// What makeCall() does when that window ends. Adopt: a leg was listed. Otherwise a 911/933 (the
// operator's #948 ruling) proceeds with no own leg, as the normal path does when it cannot
// resolve one: reconcile does the teardown and the call is not refused with a 503. Any other call
// is still refused. A read that failed (a list over the arena, a short read, the claim held by an
// overlapping 911) is a read that showed no leg.
enum class UnreadOutcome : uint8_t { Adopt, Proceed, Fail };

inline UnreadOutcome unreadOutcome(bool legFound, bool sosLane)
{
	if (legFound) return UnreadOutcome::Adopt;
	return sosLane ? UnreadOutcome::Proceed : UnreadOutcome::Fail;
}

}  // namespace telephony

#endif // SOS_STATUS_GET_HPP
