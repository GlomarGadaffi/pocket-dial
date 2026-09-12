#ifndef POOL_CONFIG_HPP
#define POOL_CONFIG_HPP

// PoolConfig.hpp — compile-time sizing of the SIP registrar's pre-allocated
// object pools (Issue #53 follow-up).
//
// pocket-dial pre-allocates every SipClient, Session and SipMessage up front so
// that the steady-state hot path performs ZERO heap allocations: the per-packet
// cost is bounded and there is no long-run heap fragmentation on the ESP32, which
// has no MMU and a finite, non-compacting heap. The price is that the entire
// budget is paid statically at boot regardless of load, so these caps ARE the
// device's hard concurrency limits. When a pool is exhausted the registrar
// degrades gracefully (REGISTER/INVITE answered with 503 Service Unavailable;
// the message pool falls back to a one-off heap allocation) — it never crashes.
//
// The three knobs below are plain object-like macros guarded by #ifndef so a
// build can override any of them from the command line, e.g.:
//
//     cmake -B build -S . -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS="-DPOCKETDIAL_MAX_CLIENTS=64 -DPOCKETDIAL_MAX_SESSIONS=16"
//
// The client/session defaults reproduce the historical hardcoded values exactly
// (32 clients, 8 sessions). The message-pool default was historically 32 (== client
// count); it is now sized to cover the worst-case broadcast + BLF-NOTIFY burst
// (MAX_CLIENTS + MAX_SUBSCRIPTIONS + headroom, Issue #54) so peak fan-out no longer
// spills into the hot-path heap fallback.
//
// Trade-off in one line: raise these for capacity, lower them to claw back RAM
// on a constrained SoftAP node. See docs/SCALING.md for per-tier recommendations,
// the per-object RAM cost, and what breaks if you 10x them.

// Maximum number of simultaneously REGISTERed SIP endpoints (extensions).
// Bounds the _clientPool. A 6th REGISTER beyond capacity (with no expired slot
// to evict) is answered 503 Service Unavailable.
#ifndef POCKETDIAL_MAX_CLIENTS
#define POCKETDIAL_MAX_CLIENTS 32
#endif

// Maximum number of concurrent call sessions (dialogs). Bounds the _sessionPool.
// RTP media flows peer-to-peer between phones, so a session costs the server only
// signalling/bookkeeping RAM — not bandwidth or DSP. An INVITE that cannot get a
// slot is answered 503 Service Unavailable.
#ifndef POCKETDIAL_MAX_SESSIONS
#define POCKETDIAL_MAX_SESSIONS 8
#endif

// Maximum number of concurrent BLF/presence dialog subscriptions (RFC 6665
// SUBSCRIBE/NOTIFY with the RFC 4235 "dialog" event package). Each slot is a small
// fixed record in a std::array — no heap. A SUBSCRIBE arriving with every slot in
// use is answered 503 Service Unavailable (graceful degradation, never a crash).
// Must stay ≤ POCKETDIAL_MSG_POOL: a single state change can fan one NOTIFY out to
// every subscriber, and bounding subscriptions by the message-pool depth keeps that
// burst allocation-free (it also caps the worst-case NOTIFY burst on the wire).
// Defined BEFORE POCKETDIAL_MSG_POOL because the pool depth is sized from it.
#ifndef POCKETDIAL_MAX_SUBSCRIPTIONS
#define POCKETDIAL_MAX_SUBSCRIPTIONS 16
#endif

// Depth of the shared in-flight SipMessage scratch pool.
//
// The worst-case simultaneous draw happens when a 999 all-page builds one forked
// INVITE per registered client AND refreshSubscriptions() queues one NOTIFY per
// active BLF subscription into the SAME locked critical section before _outbox is
// flushed. Those pooled refs all live at once, so the pool must cover MAX_CLIENTS
// (fan-out) + MAX_SUBSCRIPTIONS (NOTIFY burst), plus a little headroom for the
// inbound request being processed and its direct response(s). Sizing it this way
// keeps the broadcast+NOTIFY peak allocation-free instead of spilling to the
// hot-path heap fallback in getMessageFromPool(). Override to claw back RAM on a
// constrained node.
#ifndef POCKETDIAL_MSG_POOL
#define POCKETDIAL_MSG_POOL (POCKETDIAL_MAX_CLIENTS + POCKETDIAL_MAX_SUBSCRIPTIONS + 4)
#endif

// Issue #101(A): ceiling on the heap fallback taken when the message pool above
// is fully drawn. It used to be unbounded — a sustained retransmit flood could
// churn the heap indefinitely, and on a no-MMU ESP32 the eventual failure mode
// is a bad_alloc out of the middle of the SIP task, not graceful degradation.
//
// This caps messages ALIVE AT ONCE on the fallback path, not a rate: the count
// drops again as each one is released, so a burst is absorbed and only sustained
// over-subscription is refused. Past the cap, getMessageFromPool() returns
// nullptr and the caller drops the packet.
//
// Dropping is the honest answer rather than 503: building a 503 would itself
// need a message out of the very pool that just came up empty. SIP over UDP
// retransmits (RFC 3261 §17 T1 backoff), so a dropped packet costs latency, not
// the call — and shedding load is the point when the server is this far behind.
#ifndef POCKETDIAL_MSG_HEAP_FALLBACK_MAX
#define POCKETDIAL_MSG_HEAP_FALLBACK_MAX 8
#endif

// Same ceiling for the virtual-peer pool (park orbits / BLF presence stand-ins).
// Smaller because a virtual peer is a long-lived per-park-slot object, not a
// per-packet one: needing more than a handful past the pool means the orbit
// table is already full.
#ifndef POCKETDIAL_VPEER_HEAP_FALLBACK_MAX
#define POCKETDIAL_VPEER_HEAP_FALLBACK_MAX 4
#endif

// Maximum number of concurrent server-originated "register beep" dialogs. Each new
// REGISTER fires a brief signaling-only auto-answer INVITE (the phone's intercom
// tone) that is ACK/BYE'd straight back down; this caps how many such short-lived
// outbound UAC dialogs can be in flight at once. Tiny by design — a beep is cosmetic,
// so if every slot is busy a registration simply skips its beep. Each slot is a small
// fixed record (no heap), so this stays cheap even on the constrained node.
#ifndef POCKETDIAL_MAX_BEEPS
#define POCKETDIAL_MAX_BEEPS 4
#endif

// Number of call-park orbit slots (virtual extensions 700, 701, ... 70(N-1), max
// 10). The orbit table itself is a fixed std::array of small records — no heap in
// the hot path, mirroring the pool discipline above. NOTE the real capacity cost
// of a parked call is ONE Session slot out of POCKETDIAL_MAX_SESSIONS: the parked
// dialog stays alive in the session pool for the whole time it sits on the orbit
// (and a retrieve transiently holds a second slot for the retriever's leg). With
// the default 8 sessions, parking more than a few calls will starve new INVITEs
// into 503 — raise MAX_SESSIONS if you raise this.
#ifndef POCKETDIAL_PARK_SLOTS
#define POCKETDIAL_PARK_SLOTS 10
#endif

// Depth of the virtual-peer SipClient pool. The 777 echo, the 440 media-beachhead,
// park (parked/retriever/ring-back legs) all need a transient SipClient that is NOT
// a registered endpoint — historically each was make_shared'd inside the UDP packet
// handler, breaking the zero-heap invariant. They are now drawn from this fixed pool
// and recycled by use_count(). If the pool is momentarily drained the handler falls
// back to a one-off heap SipClient (graceful, never a crash).
#ifndef POCKETDIAL_VIRTUAL_PEERS
#define POCKETDIAL_VIRTUAL_PEERS (POCKETDIAL_MAX_SESSIONS + POCKETDIAL_PARK_SLOTS)
#endif

// How long a call may sit parked before the orbit times out (seconds). On expiry
// tick() rings back the parker (the Referred-By party of the parking INVITE) if
// they are registered, or tears the parked leg down with a BYE otherwise.
#ifndef POCKETDIAL_PARK_TIMEOUT_SEC
#define POCKETDIAL_PARK_TIMEOUT_SEC 90
#endif

// Maximum number of configured paging zones (the 980–989 virtual extensions).
// Bounds the _pageZones map exactly like _ringGroups is bounded; the 98x dial
// range only has ten slots anyway, so this is also the semantic ceiling.
#ifndef POCKETDIAL_MAX_PAGE_ZONES
#define POCKETDIAL_MAX_PAGE_ZONES 10
#endif

// Maximum members per paging zone. A zone page forks one INVITE per registered
// member through the shared message pool, so this cap bounds the transient
// per-page message-pool pressure the same way the 999 all-page is bounded by
// POCKETDIAL_MAX_CLIENTS. splitZoneMembers() clamps to this at config time,
// so an oversized list degrades to the first N members — it never over-forks.
#ifndef POCKETDIAL_ZONE_MEMBER_CAP
#define POCKETDIAL_ZONE_MEMBER_CAP 8
#endif

// Maximum number of dial-plan rules (Issue #69). The rule table is walked
// linearly, in table order, on every INVITE that reaches the dial plan — so this
// cap bounds BOTH the memory the table can occupy and the per-INVITE matching
// work in the SIP packet path. Sixteen rules is comfortably more than a desk PBX
// needs (the whole dial space here is three-digit LAN extensions) while keeping
// the worst-case walk a handful of short string compares. setDialRule() refuses
// a new rule once the table is full (existing rules can still be edited in
// place), and loadPbxConfig() applies the same ceiling when replaying NVS, so a
// blob written by a build with a larger cap can never overflow a smaller one.
#ifndef POCKETDIAL_MAX_DIAL_RULES
#define POCKETDIAL_MAX_DIAL_RULES 16
#endif

// Number of legs the local N-way conference room (virtual extension 888) accepts —
// see ConferenceRoom.hpp and docs/CONFERENCE_MIXER.md. Must be ≤ MixBus::MAX_PORTS (8).
//
// Unlike the peer-to-peer call paths, a conference leg IS server media: it costs one
// Session slot, one RTP receive task, one RTP send task and two MixBus rings (~6 KB)
// per participant, all on top of the room's own mix-tick task. Four legs is a desk-PBX
// meet-me room that comfortably fits the constrained node; raise it only alongside
// POCKETDIAL_MAX_SESSIONS and a look at free heap.
#ifndef POCKETDIAL_CONF_LEGS
#define POCKETDIAL_CONF_LEGS 4
#endif

// Number of concurrent anchor media bridges (the 555 virtual extension --
// docs/FEATURE_ROADMAP.md's "Anchored media" extension point, wired into call
// routing in RequestsHandler). Each bridge owns its own RtpReceiver/RtpSender
// pair, the same per-leg RTP-task cost as a conference leg (POCKETDIAL_CONF_LEGS
// above).
//
// Fixed at 1: LoopbackAnchorClient -- the only AnchorClient implementation this
// project ships -- hands back the SAME fixed mock participant id
// ("mock-part-123") from every makeCall() (see LoopbackAnchorClient.cpp), so a
// second concurrent anchor call would collide with the first on that id, and
// RequestsHandler's single anchor rx-audio callback would feed only whichever
// bridge it finds first, silently starving the other call's audio. Raise this
// only alongside an AnchorClient implementation whose makeCall() hands back a
// distinct participant id per call -- what AnchorClient.hpp's interface expects
// of any real implementation.
#ifndef POCKETDIAL_MAX_ANCHOR_CALLS
#define POCKETDIAL_MAX_ANCHOR_CALLS 1
#endif

// Maximum concurrent RFC 3261 §17 transaction records tracked for retransmit
// timers.  Each InviteClient slot tracks one outgoing INVITE fork (Timer A/B):
// retransmit interval doubles from T1 until a provisional stops it, or Timer B
// (32 s) fires.  Sized to cover MAX_SESSIONS concurrent INVITE dialogs plus
// headroom for forks to hunt-group members.  Pool exhaustion → message still
// sent once (graceful degradation) — it never crashes or blocks.
#ifndef POCKETDIAL_MAX_TRANSACTIONS
#define POCKETDIAL_MAX_TRANSACTIONS (POCKETDIAL_MAX_SESSIONS * 2 + 8)
#endif

#endif
