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
//   A failed status GET is no list: if every read in the #349 window fails, the call is refused
//   (503) as before #948 (see unreadOutcome). The contract adds ways for a read to fail (a list
//   over the arena, a short read, an overlapping 911); each ends the same way.

#include <atomic>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <new>
#include <string>
#include <string_view>

#include "TelephonyAnchorLogic.hpp"
#include "Witness.hpp"

namespace telephony
{

// ── Body arena ───────────────────────────────────────────────────────────────

// One block, reserved with the sos handle and freed with it. The allocator is passed in: the
// ESP build uses psram::allocPreferPsram, and a test can refuse the allocation.
class SosBodyArena
{
public:
	using AllocFn = void* (*)(std::size_t);
	using FreeFn  = void (*)(void*);

	SosBodyArena() = default;
	SosBodyArena(const SosBodyArena&) = delete;
	SosBodyArena& operator=(const SosBodyArena&) = delete;
	// Frees the block without the sos claim. Safe because the owner is destroyed only with no GET
	// in flight: see the note at TelephonyAnchorClient::_sosBody.
	~SosBodyArena() { release(); }

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
BodyRead readSosBody(const SosBodyArena& arena, ReadFn&& read, CompleteFn&& complete, Out& out)
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

// A status GET that did not get the claim and took the fallback. Only a 911's GET counts and
// writes a line: start()'s warm GET (warm) is not a 911, and one lost claim there must not use up
// one of the kLinesPerSite lines a real 911 fallback is entitled to.
inline void noteGetFallback(SosWitness& witness, bool warm)
{
	if (!warm) witness.note(SosFallback::Get);
}

// The largest sos body read this boot (participants and devices both), so the arena can be sized
// from what .244 actually returns instead of the derived figure. A line each time the max grows,
// at most kLinesPerKind per boot; a body over the arena writes its Content-Length (-1: unknown,
// chunked) on its own cap, so the oversize line cannot be starved by the growth lines. Called
// under the sos claim, so one writer at a time.
class SosBodyWitness
{
public:
	static constexpr uint32_t kLinesPerKind = 8;

	// A whole body of `bytes` was read into an arena of arenaBytes. True when it grew the max and a
	// line was written.
	bool noteBody(std::size_t bytes, std::size_t arenaBytes)
	{
		if (bytes <= _max.load(std::memory_order_relaxed)) return false;
		_max.store(bytes, std::memory_order_relaxed);
		if (_growLines.load(std::memory_order_relaxed) >= kLinesPerKind) return false;
		_growLines.fetch_add(1, std::memory_order_relaxed);
		PD_WITNESS_I("anchor", "911 status body: %u B, the largest this boot, in a %u B arena (#948)",
		             static_cast<unsigned>(bytes), static_cast<unsigned>(arenaBytes));
		return true;
	}

	// A body did not fit the arena. contentLength is the response's, or -1 when it did not say.
	bool noteOversize(int64_t contentLength, std::size_t arenaBytes)
	{
		if (_oversizeLines.load(std::memory_order_relaxed) >= kLinesPerKind) return false;
		_oversizeLines.fetch_add(1, std::memory_order_relaxed);
		PD_WITNESS_W("anchor", "911 status body over the %u B arena: content-length %lld B, -1 is unknown (#948)",
		             static_cast<unsigned>(arenaBytes), static_cast<long long>(contentLength));
		return true;
	}

	std::size_t maxBody() const { return _max.load(std::memory_order_relaxed); }
	uint32_t    growLines() const { return _growLines.load(std::memory_order_relaxed); }
	uint32_t    oversizeLines() const { return _oversizeLines.load(std::memory_order_relaxed); }

private:
	std::atomic<std::size_t> _max{0};
	std::atomic<uint32_t>    _growLines{0};
	std::atomic<uint32_t>    _oversizeLines{0};
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

// What makeCall() does when that window ends. Adopt: a leg was listed. Fail: none was, and the call
// is refused (503, NOT ROUTED), for a 911/933 as for any call, exactly as before #948. A read that
// failed (a list over the arena, a short read, the claim held by an overlapping 911) is a read that
// showed no leg. The operator ruled on #948 to keep the 503 here, and on #977 (option 2) that it stays:
// a 911/933 whose every read failed is still refused at the end of the window and adopts nothing. The
// orphan sweep below only looks for a leg 3CX may hold, to drop it.
enum class UnreadOutcome : uint8_t { Adopt, Fail };

inline UnreadOutcome unreadOutcome(bool legFound)
{
	return legFound ? UnreadOutcome::Adopt : UnreadOutcome::Fail;
}

// ── #977: the orphan sweep ───────────────────────────────────────────────────
// Owner ruling on #977 (2026-10-19, option 2). When every participant-list read of the #349 window above
// errors, a 911/933 is refused (503, NOT ROUTED) at the end of that window exactly as unreadOutcome() says:
// no early answer to the caller, and no leg adopted that was never listed. 3CX may nevertheless hold a live
// call to the PSAP that this unit can no longer see. makeCall() arms a sweep before it returns (a few atomic
// stores and a wake: no lock, no I/O, no wait) and tel_maint runs it after: it reads the list again, within
// the same bound as the window, and DROPS the one leg that shows. It never answers, adopts or keys a leg.
//
//   Hold. From the arm until the sweep ends, or the bound passes if that is first, an unmatched upsert is
//   ignored as it is while a makeCall is pending (#888). Without it the orphan's next repeat upsert, in the
//   gap between the 503 and the drop, is promoted to a new inbound call that rings the handsets. It widens
//   #888's window by up to kOrphanSweepWindowUs, on this double failure only. A sweep that finds the leg
//   notes it as ours (AnchorOwnLegs, as a makecall response that names a leg does) BEFORE the hold ends and
//   before the drop goes out, so the orphan's later upserts are not announced either.
//
//   One candidate is dropped. Two or more are not: a list pick can be an unrelated inbound leg, a PSAP
//   callback among them, and dropping that is worse than leaving a leg up. Nothing in the list tells the
//   two apart (classifyListLeg), so the sweep does not guess.

inline constexpr int64_t kOrphanSweepWindowUs = kUnreadAdoptWindowUs;
inline constexpr int     kOrphanSweepPollMs   = kUnreadAdoptPollMs;
static_assert(kOrphanSweepWindowUs <= 5'000'000, "#888: the hold on unmatched upserts lasts as long as the sweep");

// After the #349 window: is there an orphan to look for? Only for a 911/933 whose window ended with no leg
// and in which NO read showed 3CX's list at all (listsRead counts the reads that fetched and parsed it). A
// read that showed a list with no leg is 3CX's answer, as it is on main.
inline bool orphanSweepWanted(bool sosLane, UnreadOutcome outcome, int reads, int listsRead)
{
	return sosLane && outcome == UnreadOutcome::Fail && reads > 0 && listsRead == 0;
}

// What one sweep read says to do. candidates is the number of legs that read listed as candidates
// (resolveOutboundLeg's ListLegCounts::candidates); sinceArmUs is the time from the arm to the end of the read.
enum class OrphanSweepStep : uint8_t { Drop, ReadAgain, GiveUp, Ambiguous };

inline OrphanSweepStep orphanSweepStep(int candidates, int64_t sinceArmUs)
{
	if (candidates == 1) return OrphanSweepStep::Drop;
	if (candidates > 1) return OrphanSweepStep::Ambiguous;
	// The window's own rule (unreadMakecallStep): no read starts once another poll gap would pass the bound.
	if (sinceArmUs + int64_t{kOrphanSweepPollMs} * 1000 < kOrphanSweepWindowUs) return OrphanSweepStep::ReadAgain;
	return OrphanSweepStep::GiveUp;
}

// The hold: the time it lasts to, and the pending-makeCall count the WS classifier sees with it. The
// classifier promotes an unmatched upsert to an inbound call only when that count is 0.
inline int64_t orphanHoldUntil(int64_t armedUs)
{
	return armedUs + kOrphanSweepWindowUs;   // from the arm: a sweep tel_maint is late to cannot stretch it
}

// holdUntilUs 0: no sweep is armed. The hold counts as one pending makeCall when none is, and never changes
// a real count. Only for an id upserted while a makeCall was pending (idSeenInWindow, PendingSeenIds): any other
// id, a PSAP callback among them, is not held, and the default errs toward announcing it (Rule 5).
inline int pendingWithOrphanHold(int outboundPending, int64_t holdUntilUs, int64_t nowUs, bool idSeenInWindow = false)
{
	const bool held = holdUntilUs != 0 && idSeenInWindow && nowUs < holdUntilUs;
	return (held && outboundPending < 1) ? 1 : outboundPending;
}

// The participant ids 3CX upserted while a makeCall was pending (the classifier ignores those, #888), each with
// the WS event number of its FIRST sighting and whether more than one makeCall was pending then (two 911s dialed
// together: whose leg it is cannot be told, so it is never counted as seen). The orphan is one of them, first upserted after the POST that made it
// and no later than the arm (seq in (postSeq, armSeq]). A PSAP callback is not: it is a participant this unit saw
// in no pending window of this 911, so the sweep's hold does not cover it and the sweep never drops it. An id
// first seen at or before the POST (an earlier makeCall's window) or after the arm (a redial's window, whose
// callback or live leg is not the orphan) does not count, however often it is seen again. Fixed size, oldest slot overwritten, an id over Len bytes
// is not recorded; every miss errs toward announcing the leg and not dropping it. Under the client's _mutex.
template <std::size_t N, std::size_t Len>
class PendingSeenIds
{
public:
	void note(std::string_view id, uint64_t seq, int pendingMakeCalls)
	{
		if (id.empty() || id.size() > Len) return;
		for (auto& e : _e)
		{
			if (id == e.id) return;   // the first sighting stands
		}
		Entry& e = _e[_next++ % N];
		std::memcpy(e.id, id.data(), id.size());
		e.id[id.size()] = '\0';
		e.seq           = seq;
		e.multi         = pendingMakeCalls > 1;
	}

	// True when id's first sighting has an event number in (afterSeq, uptoSeq].
	bool seenIn(std::string_view id, uint64_t afterSeq, uint64_t uptoSeq) const
	{
		if (id.empty() || id.size() > Len) return false;
		for (const auto& e : _e)
		{
			if (id == e.id) return !e.multi && e.seq > afterSeq && e.seq <= uptoSeq;
		}
		return false;
	}

	// True when any id's first sighting is in (afterSeq, uptoSeq].
	bool anyIn(uint64_t afterSeq, uint64_t uptoSeq) const
	{
		for (const auto& e : _e)
		{
			if (e.id[0] != '\0' && !e.multi && e.seq > afterSeq && e.seq <= uptoSeq) return true;
		}
		return false;
	}

private:
	struct Entry
	{
		char     id[Len + 1] = {};
		uint64_t seq         = 0;
		bool     multi       = false;   // more than one makeCall was pending at the first sighting
	};
	Entry       _e[N];
	std::size_t _next = 0;
};

enum class OrphanSweepEnd : uint8_t { Dropped, DropFailed, GaveUp, Ambiguous, Stopped, TooLate, NoCandidate, UnslottedLiveEmergency };

// One sweep read: the leg resolveOutboundLeg() picked ("" when the read failed or listed none) and how many
// candidates the list held.
struct OrphanRead
{
	std::string leg;
	int         candidates = 0;
	bool        stranger   = false;   // the pick is not provably the orphan: see readOrphanOnce
	std::string partyDn;              // the pick's party_dn and party_caller_id, as the record carried them
	std::string partyCid;
};

// The digits of s, for comparing a participant's party with the number a 911/933 dialed.
inline std::string digitsOnly(std::string_view s)
{
	std::string d;
	for (const char c : s)
	{
		if (c >= '0' && c <= '9') d.push_back(c);
	}
	return d;
}

// Is the pick's remote party the number this 911/933 dialed? Bench capture of a real 3CX participant record for our
// own outbound leg (PR #1040, 2026-10-21): dn = our DN, party_dn = *777 and party_caller_id = *777, both the DIALED
// number, direct_control = false (a *777 park-type extension). So the dialed number is in party_dn and
// party_caller_id, and either matches. A PSAP callback's party is the PSAP's number, not
// 911/933. A record with no party field proves nothing, and neither does an empty destination.
inline bool partyIsDestination(std::string_view destDigits, std::string_view partyDn, std::string_view partyCid)
{
	if (destDigits.empty()) return false;
	return digitsOnly(partyDn) == destDigits || digitsOnly(partyCid) == destDigits;
}

struct OrphanSweepResult
{
	OrphanSweepEnd end   = OrphanSweepEnd::GaveUp;
	int            reads = 0;
	std::string    leg;   // the leg handed to dropLeg
};

// The sweep. unslotted() is true once any 911/933 makeCall succeeded with no own leg
// (UnslottedRecord): its live leg may be any listed leg, so the sweep ends before a drop. hasCandidate() is false when no leg was upserted in the window (PendingSeenIds::anyIn): the sweep
// then has nothing it may drop, and it ends at once without a read. armedUs is the time makeCall() armed it (the bound runs from there, not from when tel_maint
// got to it). readOnce() -> OrphanRead; nowUs() is a microsecond clock; keepGoing() is false once the
// anchor is stopping; pause() sleeps one poll gap; holdLeg(leg) notes the leg as ours; dropLeg(leg) -> bool
// drops it. The order is the contract: holdLeg, then dropLeg, once each, and only for a single candidate.
template <class ReadFn, class NowFn, class KeepFn, class PauseFn, class HoldFn, class DropFn, class HasCandFn,
          class UnslottedFn>
OrphanSweepResult runOrphanSweep(int64_t armedUs, ReadFn&& readOnce, NowFn&& nowUs, KeepFn&& keepGoing,
                                 PauseFn&& pause, HoldFn&& holdLeg, DropFn&& dropLeg, HasCandFn&& hasCandidate,
                                 UnslottedFn&& unslotted)
{
	OrphanSweepResult r;
	for (;;)
	{
		if (!keepGoing())
		{
			r.end = OrphanSweepEnd::Stopped;
			break;
		}
		if (unslotted())
		{
			r.end = OrphanSweepEnd::UnslottedLiveEmergency;
			break;
		}
		if (r.reads == 0 && !hasCandidate())
		{
			r.end = OrphanSweepEnd::NoCandidate;
			break;
		}
		// tel_maint was busy past the bound (a restart job ahead of this one): the hold has lapsed, so a
		// read now has no hold to protect it. Inside the bound it reads at least once.
		if (r.reads == 0 && nowUs() - armedUs >= kOrphanSweepWindowUs)
		{
			r.end = OrphanSweepEnd::TooLate;
			break;
		}
		const OrphanRead rd = readOnce();
		++r.reads;
		// A pick the makeCall never saw upserted is not the orphan (it may be a PSAP callback): no candidate, never dropped.
			const OrphanSweepStep step = orphanSweepStep(rd.leg.empty() || rd.stranger ? 0 : rd.candidates, nowUs() - armedUs);
		if (step == OrphanSweepStep::Drop)
		{
			if (!keepGoing())   // stopping, or a restart wanted, during the read: no drop that would delay it
			{
				r.end = OrphanSweepEnd::Stopped;
				break;
			}
			if (unslotted())   // one began during the read: its leg may be this pick
			{
				r.end = OrphanSweepEnd::UnslottedLiveEmergency;
				break;
			}
			r.leg = rd.leg;
			holdLeg(r.leg);   // ours before the drop goes out: its upserts are not inbound calls
			r.end = dropLeg(r.leg) ? OrphanSweepEnd::Dropped : OrphanSweepEnd::DropFailed;
			break;
		}
		if (step == OrphanSweepStep::Ambiguous)
		{
			r.end = OrphanSweepEnd::Ambiguous;
			break;
		}
		if (step == OrphanSweepStep::GiveUp)
		{
			r.end = OrphanSweepEnd::GaveUp;
			break;
		}
		pause();
	}
	return r;
}

template <class ReadFn, class NowFn, class KeepFn, class PauseFn, class HoldFn, class DropFn, class HasCandFn>
OrphanSweepResult runOrphanSweep(int64_t armedUs, ReadFn&& readOnce, NowFn&& nowUs, KeepFn&& keepGoing,
                                 PauseFn&& pause, HoldFn&& holdLeg, DropFn&& dropLeg, HasCandFn&& hasCandidate)
{
	return runOrphanSweep(armedUs, readOnce, nowUs, keepGoing, pause, holdLeg, dropLeg, hasCandidate,
	                      [] { return false; });
}

template <class ReadFn, class NowFn, class KeepFn, class PauseFn, class HoldFn, class DropFn>
OrphanSweepResult runOrphanSweep(int64_t armedUs, ReadFn&& readOnce, NowFn&& nowUs, KeepFn&& keepGoing,
                                 PauseFn&& pause, HoldFn&& holdLeg, DropFn&& dropLeg)
{
	return runOrphanSweep(armedUs, readOnce, nowUs, keepGoing, pause, holdLeg, dropLeg, [] { return true; });
}

// A 911/933 makeCall that returned success WITHOUT a resolved own leg (makeCall's "could not resolve own leg id"
// branch) has a live call to the PSAP and no slot: its leg is listed, unslotted, and looks exactly like an orphan.
// ANY such call, whether its POST came before or
// after the sweep's, ends the sweep before a drop: a call with no slot and no media is redialed, and its leg's
// repeat upsert is first seen inside the redial's window, with one makeCall pending, looking just like the orphan.
// The record is sticky until reboot (this unit cannot prove the leg is gone), so the sweep is disabled after this
// rare event; that never drops a live call.
// The record of it, in one place the client and the host tests share. A flag, not a seq: _wsSeq starts at 0 and
// only participant events advance it, so a 911 that is the first call after boot has a POST seq of 0, and a seq
// of 0 must not read as "none".
class UnslottedRecord
{
public:
	// True the first time only (the caller logs once).
	bool note()
	{
		return !_set.exchange(true, std::memory_order_acq_rel);
	}
	bool recorded() const { return _set.load(std::memory_order_acquire); }

private:
	std::atomic<bool> _set{false};
};

// Does the sweep go on? A restart wanted (a WS drop with a stale token, #336) must not wait behind a sweep whose
// reads time out: makeCall refuses 911s while the anchor is down, so the sweep yields at once.
inline bool sweepMayContinue(bool running, bool restartRequested)
{
	return running && !restartRequested;
}

// The armed sweep's state, written by makeCall() and taken by tel_maint. NOT synchronised: the client holds its
// _mutex around arm() and take() (no I/O inside), so a take never pairs one arm's window with another's number.
// The destination is kept as digits, at most kDestDigits (the longest string a std::string holds without a heap
// allocation in libstdc++ is 15 characters).
class OrphanArmSlot
{
public:
	static constexpr std::size_t kDestDigits = 15;
	struct Snapshot
	{
		int64_t  armedUs = 0;
		uint64_t postSeq = 0;
		uint64_t armSeq  = 0;
		char     dest[kDestDigits + 1] = {};
	};

	void arm(int64_t armedUs, uint64_t postSeq, uint64_t armSeq, std::string_view destination)
	{
		_s.armedUs = armedUs;
		_s.postSeq = postSeq;
		_s.armSeq  = armSeq;
		std::size_t n = 0;
		for (const char c : destination)
		{
			if (c >= '0' && c <= '9' && n < kDestDigits) _s.dest[n++] = c;
		}
		_s.dest[n] = '\0';
	}

	// The whole arm at once, and it is spent: false when nothing is armed. postSeq() and armSeq() stay readable.
	bool take(Snapshot& out)
	{
		if (_s.armedUs == 0) return false;
		out         = _s;
		_s.armedUs  = 0;
		return true;
	}

	// A wake with no tel_maint task: nothing will sweep.
	void disarm() { _s.armedUs = 0; }

	uint64_t postSeq() const { return _s.postSeq; }
	uint64_t armSeq() const { return _s.armSeq; }

private:
	Snapshot _s;
};

// One sweep read, with the decisions the ESP arm used to make inline. readList() does the I/O and returns the pick
// and its candidate count (an empty leg when the read failed or listed none); it may throw std::bad_alloc, which
// is a failed read. pendingCount() is the client's pending makeCall count, pendingSinceUs() when the oldest began.
// seen(leg) is PendingSeenIds::seenIn over (postSeq, armSeq].
//   - A makeCall in flight (a redialed 911 among them) has a leg 3CX lists before it keys it, and a lone
//     candidate is dropped: no decision while one is pending, before the read or after it, or if one began and
//     ended during it. The read is an empty one, so the sweep reads again.
//   - A pick not seen in the window, or whose remote party is not the number this 911/933 dialed, is a stranger (it
//     may be a PSAP callback or another call's leg) and is never dropped.
template <class ReadFn, class PendingFn, class SinceFn, class SeenFn>
OrphanRead readOrphanOnce(ReadFn&& readList, PendingFn&& pendingCount, SinceFn&& pendingSinceUs, SeenFn&& seen,
                          std::string_view destDigits)
{
	const int64_t sinceUs = pendingSinceUs();
	if (pendingCount() > 0) return {};
	OrphanRead rd;
	try
	{
		rd = readList();
	}
	catch (const std::bad_alloc&)
	{
		return {};   // a failed read, not a terminate: the ordinary lane rethrows
	}
	if (pendingCount() > 0 || pendingSinceUs() != sinceUs) return {};
	rd.stranger = !rd.leg.empty() && !(seen(rd.leg) && partyIsDestination(destDigits, rd.partyDn, rd.partyCid));
	return rd;
}

// Counts how each sweep ended; writes the first kLinesPerEnd lines of each kind, so a stuck unit cannot flood
// the log. No number or credential in a line.
class OrphanSweepWitness
{
public:
	static constexpr uint32_t kLinesPerEnd = 8;
	static constexpr std::size_t kEnds     = 8;

	// True when this one wrote a line.
	bool noteEnd(OrphanSweepEnd end)
	{
		const uint32_t seen = _n[static_cast<std::size_t>(end)].fetch_add(1, std::memory_order_relaxed);
		if (seen >= kLinesPerEnd) return false;
		switch (end)
		{
			case OrphanSweepEnd::Dropped:
				PD_WITNESS_I("anchor", "911 orphan sweep: the leg left on 3CX was found and dropped (#977)");
				break;
			case OrphanSweepEnd::DropFailed:
				PD_WITNESS_W("anchor", "911 orphan sweep: the leg left on 3CX was found, the drop failed (#977)");
				break;
			case OrphanSweepEnd::GaveUp:
				PD_WITNESS_W("anchor", "911 orphan sweep: no leg listed within the bound, none dropped (#977)");
				break;
			case OrphanSweepEnd::Ambiguous:
				PD_WITNESS_W("anchor", "911 orphan sweep: more than one candidate leg, none dropped (#977)");
				break;
			case OrphanSweepEnd::Stopped:
				PD_WITNESS_W("anchor", "911 orphan sweep: anchor stopping, ended (#977)");
				break;
			case OrphanSweepEnd::TooLate:
				PD_WITNESS_W("anchor", "911 orphan sweep: tel_maint reached it after the bound, nothing read (#977)");
				break;
			case OrphanSweepEnd::UnslottedLiveEmergency:
				PD_WITNESS_W("anchor", "911 orphan sweep: another 911 succeeded with no own leg after this one, its leg may be that live call, none dropped (#977)");
				break;
			case OrphanSweepEnd::NoCandidate:
				PD_WITNESS_W("anchor", "911 orphan sweep: no leg was upserted in the window, nothing to find, no read (#977)");
				break;
		}
		return true;
	}

	// makeCall() armed a sweep and there was no tel_maint task to wake: the hold was taken back.
	bool noteNoWorker()
	{
		const uint32_t seen = _noWorker.fetch_add(1, std::memory_order_relaxed);
		if (seen >= kLinesPerEnd) return false;
		PD_WITNESS_W("anchor", "911 orphan sweep: no tel_maint task, not armed (#977)");
		return true;
	}

	uint32_t count(OrphanSweepEnd end) const { return _n[static_cast<std::size_t>(end)].load(std::memory_order_relaxed); }
	uint32_t noWorker() const { return _noWorker.load(std::memory_order_relaxed); }

private:
	std::atomic<uint32_t> _n[kEnds] = {};
	std::atomic<uint32_t> _noWorker{0};
};


// ── The worker's outbound leg status read (#949 item 1) ──────────────────────
// The tel_wsw worker decides Connected -> Answered from a participant-list read. For a slot that is
// a 911/933 (CallSlot::emergency non-zero) that read takes the sos lane, so it never waits on
// _statusMutex behind another caller's GET. That lane's claim never waits either, so an empty read
// can mean "claim held" or "GET failed", not "the leg is not Connected". Owner ruling (#949,
// 2026-10-20): on an emergency slot an empty or failed read is UNKNOWN. It is not answered and it
// is not the dialing branch; the worker keeps asking.

// Reads per pass on the sos lane, one tick apart. The worker is not makeCall(), so a short re-ask is
// allowed here; past it the pass ends Unknown and the worker re-asks after kEmergencyReaskMs.
inline constexpr int kEmergencyStatusReads = 3;
inline constexpr int kEmergencyReaskMs = 100;

// read(bool sosLane) returns the leg's status, "" on any failure; pause() sleeps one tick.
template <class ReadFn, class PauseFn>
std::string readOutboundLegStatus(bool emergency, ReadFn&& read, PauseFn&& pause)
{
	if (!emergency) return read(false);   // unchanged: one read on the shared lane
	std::string st;
	for (int i = 0; i < kEmergencyStatusReads; ++i)
	{
		st = read(true);
		if (!st.empty()) break;
		if (i + 1 < kEmergencyStatusReads) pause();
	}
	return st;
}

enum class OutboundStep : uint8_t { Answered, Dialing, Unknown };

inline OutboundStep outboundStep(const std::string& status, bool emergency)
{
	if (status == "Connected") return OutboundStep::Answered;
	if (status.empty() && emergency) return OutboundStep::Unknown;
	return OutboundStep::Dialing;
}

}  // namespace telephony

#endif // SOS_STATUS_GET_HPP
