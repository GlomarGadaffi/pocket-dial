# Design: jitter-ring storage and a static ring pool (#946)

Status: Proposed, for vote. Design only: no code, no hardware, nothing posted to GitHub.
Author: BigDog (Claude Sonnet 5.5), 2026-10-09. Source: #940 item 6 (committee 2-1 for "static ring pool at init").

Every `file:line` below was read on `origin/main` 7bcf952f. #946 quotes c4960c7; main is 4 commits
past it. Nothing in this document is measured on a board. Sizes are arithmetic from the code.

## 0. The finding that changes the question

#946 and #940 item 6 assume "one heap ring per call at call setup". On main that is not what the code does.
Every ring has an owner that is built once at boot, and a call only clears it.

| #946 / #940 says | main 7bcf952f says |
|---|---|
| `std::vector<int16_t> _buffer` at PlayoutBuffer.hpp:47 | :55, `std::vector<int16_t, PsramAllocator<int16_t>>`; already so at c4960c7 (#466 PR A, ff443def, #475) |
| MediaBridge.hpp:242, MixBus.hpp:45-46 | MediaBridge.hpp:267, MixBus.hpp:58-59 |
| `MAX_PORTS = 8` (MixBus.hpp:22) | `MAX_PORTS = POCKETDIAL_CONF_LEGS = 4` (MixBus.hpp:27, PoolConfig.hpp:204) |
| ConferenceRoom: 20 ports x 3,200 B = 64 KB | 4 legs. "20 / 64 KB" survives only in the comment at PlayoutBuffer.hpp:49-54 |
| the room is created lazily (also RequestsHandler.hpp:1891-1893) | built in the constructor at boot, RequestsHandler.cpp:240-246 (#479) |
| "#428 #48's PSRAM allocator" is an alternative to a pool | already merged: PsramAllocator.hpp, used at PlayoutBuffer.hpp:55 |

So the committee voted on a premise that is stale. Section 10 puts the vote again with the facts.

## 1. The current allocation (count, sizes, when)

One ring is 1,600 `int16_t` = 3,200 B (PlayoutBuffer.hpp:19), one allocation, made in the constructor
(PlayoutBuffer.cpp:8 -> PsramAllocator.hpp:94-98 -> `heap_caps_malloc`, :57-65).

| Owner | S3 default | Constrained | Declared at |
|---|---|---|---|
| Anchor bridge ring | 4 | 1 | `MediaBridge _mediaBridges[POCKETDIAL_MAX_ANCHOR_CALLS]`, RequestsHandler.hpp:2487; PoolConfig.hpp:293; main/CMakeLists.txt:290 |
| Conference-leg bridge ring (BUS mode, never read) | 4 | 0 | `Leg::bridge`, ConferenceRoom.hpp:160,174; unread: MediaBridge.hpp:30-36, MediaBridge.cpp:362-373, :395-398 |
| MixBus `in` + `out` | 8 | 0 | MixBus.hpp:58-59; ports = 4 (:27) |
| Total | 16 rings = 51,200 B | 1 ring = 3,200 B | constrained: `POCKETDIAL_CONFERENCE=0`, main/CMakeLists.txt:294 |

When: all at boot. `new SipServer` runs once per boot inside `sip_server_task` (esp_main.cpp:266,
esp_main_eth_lan8720.cpp:243, esp_main_display.cpp:433), spawned once (esp_main.cpp:543, lan8720:585,
display:900,943), never deleted. Its RequestsHandler constructor (RequestsHandler.cpp:220) builds
`_mediaBridges` (member) and, if `POCKETDIAL_CONFERENCE`, the room (:245-246).

Placement: PSRAM first; if PSRAM is full the ring lands in internal DRAM and `psram::internalFallbacks()`
counts it (PsramAllocator.hpp:62-65). With no PSRAM (`CONFIG_SPIRAM=n`, sdkconfig.defaults.esp32_constrained:21)
it is internal. If both are exhausted the constructor throws `std::bad_alloc` (PsramAllocator.hpp:97), at boot.

Per call: `startBridge()` runs `_playoutBuffer.clear()` (MediaBridge.cpp:77), a `std::fill`
(PlayoutBuffer.cpp:115-124). `MixBus::attach()` is a CAS (MixBus.cpp:12-25); the tick clears both rings on
Draining->Free (MixBus.cpp:71-77). No ring is allocated or freed after construction. `PlayoutBuffer` has no
other owner in `src/` (grep) and `PsramAllocator<` has no other user than the ring vector.

Not rings, same function: `startBridge()` assigns two `std::string`s (MediaBridge.cpp:78-79). That is
why a whole-`startBridge` allocation test is the wrong test (section 8).

## 2. The goal

No ring allocation after init, on any task (#427). On main this already holds, by construction. What is left:

1. Nothing pins it. A change that constructs a `MediaBridge` or `MixBus` per call would pass today's tests.
2. 12,800 B of rings (4 conference-leg bridges) are allocated and never read. PSRAM on S3, absent on constrained.
3. The boot-time `bad_alloc` path (PSRAM and internal both full) is untested. Boot only; no call exists yet.

## 3. Pool size, with the arithmetic

Demand per consumer: anchor bridge 1 ring; conference leg 2 rings (MixBus in/out). The leg's own bridge ring is dead.

| | A (anchor) | C (conf legs) | Sum A + 2C | Demand-bounded | Bytes (sum) | Saves vs 51,200 B |
|---|---|---|---|---|---|---|
| S3, PSRAM | 4 | 4 | 4 + 8 = 12 | 10 | 38,400 B | 12,800 B (19,200 B only if 10 held) |
| Classic esp32, no PSRAM | 1 | 0 | 1 | 1 | 3,200 B | 0 B |

Demand-bounded (not a hard bound, so option D sizes N = 12): `POCKETDIAL_RTP_TX_POOL = 6` (PoolConfig.hpp:246)
caps started senders, and `startBridge()` fails when its sender cannot start (MediaBridge.cpp:140-148). That gives
4 conference legs (8) plus 2 anchor calls (2) = 10 rings, if tx slots are released as fast as ports are. They need not
be: a leaving port keeps its rings until the next tick (MixBus.cpp:71-77), and I did not show when the tx slot frees.

Even 19,200 B is 0.23% of the S3's 8 MiB PSRAM (docs/HARDWARE.md:32,66). On the classic board the ring is 3,200 B of
~290-320 KB usable internal DRAM (docs/SCALING.md:106,291): 1.1%, and no pool shrinks it. Pool sizing recovers
no memory that matters on either target. The one recoverable item is the 12,800 B of dead PSRAM rings.

## 4. Where the pool lives (if one is built)

- S3: one slab (12 x 3,200 B) from `psram::allocPreferPsram` in the RequestsHandler constructor: PSRAM first,
  counted internal fallback. A BSS-in-PSRAM array is not available: sdkconfig.defaults:53-58 has
  `CONFIG_SPIRAM_USE_MALLOC=y` and no `ALLOW_BSS_SEG_EXTERNAL_MEMORY`.
- Classic esp32: a member array in the owner. Internal DRAM, 3,200 B, visible in the link map.
- Inline variant (option C below): the ring becomes a member of `PlayoutBuffer`, so it rides in its owner's
  allocation. docs/SCALING.md:102-105 says RequestsHandler is above the 16 KB always-internal threshold and so lands in
  PSRAM on S3. Not verified on a board.

## 5. The emergency reserve (Rule 5)

Facts that bound the answer:

- A ring is never the binding resource today. A call also needs a bridge slot, an RTP rx/tx pair, a tx stack
  and a session. Ring count equals bridge count, so a bridge slot implies a ring.
- Rule 5 for bridge slots is #624 pre-emption: `preemptAnchorCallForEmergency()` (RequestsHandler.cpp:4638-4687),
  called once at :5161. Tests: EmergencyRoute_test.cpp:818 (pre-empts a normal call), :840 (never another
  emergency), :861 (a ringing leg holding the only slot).
- Finding, Rule 5, pre-existing, unchanged by any option here: the PSAP-callback path decides after it refuses.
  `routeInboundAnchorCall` drops the inbound when every bridge is busy (RequestsHandler.cpp:5803-5808) or any
  inbound is ringing or up (:5814-5822). It flags the session as an emergency callback only later (:5912-5913).
  No pre-emption is attempted for it. The only production caller is the `Incoming` event handler (:574-576), which
  calls it directly. The callback tests ring it after the 911 has ended (EmergencyRoute_test.cpp:956-966,
  AdminHttpGate_test.cpp:1751); none fills the bridges first. A ring reserve cannot help: the refusal precedes any ring request.

Exact count if a pool is built (option D):

| Target | N | Reserve R | Ordinary ceiling | Emergency ceiling |
|---|---|---|---|---|
| S3 | 12 | 1 | 11 | 12 |
| Classic esp32 | 1 | 0 | 1 | 1, by #624 pre-emption |

- S3, R = 1: ordinary acquirers (anchor and conference) succeed only while `free > R`; an emergency acquirer
  succeeds while `free >= 1`. The reserve bites in one case: a full conference (8) plus 3 ordinary anchor calls (3)
  = 11, and a 4th ordinary anchor call is refused at the ring (503). A 911 still gets ring 12. Variant R = 2
  (ordinary ceiling 10) reserves a second concurrent emergency, and also refuses a 3rd ordinary anchor call there.
- Classic, R = 0: a reserve of 1 makes the only ring emergency-only, so no ordinary anchor call could ever
  start, on a build whose one outside line is the anchor (main/CMakeLists.txt:332-335). The guarantee there is
  pre-emption, as today.
- Emergency with `free == 0` (reserve used by emergencies, rest held by ordinary): fall to #624, which stops a
  victim (its ring returns), then retry once. It never waits. A non-emergency refusal is for non-emergency only.

How it is checked:

1. Compile time: `static_assert(R < N)` on every build that carries ordinary anchor calls.
2. Host property test (section 8): after any Ordinary acquire `free() >= R`; Emergency fails only at `free() == 0`.
3. Runtime: `/api/status` counters `ringsFree`, `ringsMinFree`, `ringsOrdinaryRefused`; one boot line with N, R, bytes.
4. EmergencyRoute_test.cpp:818, :840, :861 keep passing unchanged.

## 6. Borrow and return

Today, with no ring handle: borrow is `acquireFreeAnchorBridge()` (RequestsHandler.cpp:4607-4619) then
`startBridge()` (MediaBridge.cpp:33), or `MixBus::attach()` (MixBus.cpp:12). Return is `stopBridge()`
(MediaBridge.cpp:440, idempotent: returns at once if not `_active`, :444-447), and for MixBus `detach()` plus the
tick reclaim (MixBus.cpp:27-36, :71-79). `stopBridge()` is reached from every teardown path I found (grep of
all call sites): answer unwind (RequestsHandler.cpp:561); the synchronous 555 unwinds for session, virtual-peer
and message pool failures (:5207,:5222,:5242); no-rx-audio and 3CX-dropped-leg release (:5460,:5477); the
dialog-teardown safety net (:8851); the tick sweeps (:10550,:10803); the orphan reap (:11005); room `leave()`
and the room destructor (ConferenceRoom.cpp:158,:60); `~MediaBridge` (MediaBridge.cpp:9-12). A ring that is a
member cannot leak or be returned twice. Not read: whether each of those paths is reached on a WS drop; I did not trace it.

Option D adds a handle: acquire in `startBridge()` after the bus-port check (MediaBridge.cpp:64-75), release on
the two failure branches (:99-106, :140-148) and in `stopBridge()` behind the same `_active` gate. The pool refuses
a double release. New failure mode: `startBridge()` can now fail for want of a ring, on the 911 path. That is what R is for.

## 7. The MixBus in and out rings

Today they are separate objects with a different return owner: `detach()` only flags, the tick reclaims. In
option D they would share the pool but must be taken as a pair (both or none) at `attach()` and returned by the tick
at Draining->Free, never by `stopBridge()`. A port's rings are therefore busy until the next 20 ms tick after the
leg leaves. Conference legs are ordinary: no path sets `MixBus::setEmergency` and the VAD gate is pinned off
(MixBus.hpp:37-41, PoolConfig.hpp:217-231).

## 8. Test plan

Pool logic (D only): a header-only `RingPool<N>`, no ESP includes, in `src/SIP/`, with gtest cases: borrow,
return, exhaustion, Ordinary refused at `free == R`, Emergency taken at `free == R`, Emergency refused only at 0,
double release refused, out-of-range release refused, pair-acquire all-or-nothing, a randomized
acquire/release walk checking the section 5 invariant, and two threads racing the last ring.

Allocation-count test (pins "no ring allocation after init", needed under every option):

- Seam: a host-only call counter in `psram::allocPreferPsram`'s `operator new` branch (PsramAllocator.hpp:70), beside
  `internalFallbacks()`. The only other user is HttpServer.cpp:146; no HTTP server runs in the test.
- Test: build a RequestsHandler (init), read the counter, run 100 cycles of anchor bridge start/stop and 888
  join/leave (reuse the PerCallHeap rig), assert the counter unchanged. Plus: constructing the handler should move
  it by 16 (4 + 4 + 8, expected from the code, not yet run); that number is the pin, and option B moves it to 12.
- Why not `AllocGuard` around `startBridge()`: it also counts the two string assigns (MediaBridge.cpp:78-79) and,
  on a Linux host, the sender's pacer thread creation (ConferenceRoom.hpp:133-142).
- Existing, not enough: PerCallHeap_test.cpp:381-422 (888 join/leave returns live heap to baseline) and
  PsramPlacement_test.cpp:98-118 (host rings go through the counted `operator new`). A ring allocated at
  `startBridge()` and freed at `stopBridge()` would pass both. No anchor-bridge cycle test exists.

## 9. Q7: the 3,200 B default and `resize`

Production never passes a size: the default 1600 is used by `MediaBridge` and `MixBus::Port`. Tests do:
PlayoutBuffer_test.cpp:21-108 uses 40, 80, 160 and 1600; PsramPlacement_test.cpp:109 uses 1600. The only
`resize` is the constructor (PlayoutBuffer.cpp:8). Options C and D keep a runtime `_maxSamples <= 1600` clamp
so those tests compile unchanged. No change to 3,200 B is proposed. Option B gives a BUS-mode bridge a ring of 0
samples. I read that as inert, not as a divide by zero: `write()` clamps `count` to 0 before any `% _maxSamples`
(PlayoutBuffer.cpp:21-26, :35, :43), `read()` underruns into comfort noise (:78-83), and `clear()` fills an empty
range. B must pin that with a test; BUS mode refuses the ring anyway (MediaBridge.cpp:395-398).

## 10. Decision asked (poll)

| | Option | Production change | PSRAM / DRAM effect | Rule 5 risk added |
|---|---|---|---|---|
| A | Record "already met at init"; add the section 8 counter and test | none | none | none |
| B | A, and stop building the 4 never-read conference-leg rings | `MediaBridge` ctor takes a ring size; 0 for legs | S3 -12,800 B PSRAM; classic 0 | none (guard in section 9) |
| C | B, with rings as inline members; rings stop using the allocator (HttpServer.cpp:146 still does) | `PlayoutBuffer` owns a fixed array | S3 same as B; owners grow | none; the boot-time failure moves to the owners' allocations (`new SipServer`, `make_unique<ConferenceRoom>`) |
| D | Shared static pool with borrow/return and reserve R, sized N = 12 | new `RingPool`, handle in `startBridge()` | S3 -12,800 B PSRAM; classic 0 | a new `startBridge()` failure on the 911 path |

Recommended: **A**, which is the committee's (b) as main already has it: a fixed set of rings, allocated once at init.
D adds a new way for a 911 to fail and recovers no memory that matters; B is a free follow-up if the 12,800 B is wanted.
If no one answers, the default is A: it changes nothing, and no ring is allocated on the 911 path after init.

Vote: A / B / C / D, and, only if D, R = 1 or R = 2 on S3. Separately, the operator decides whether the PSAP-callback
finding in section 5 becomes its own issue.
