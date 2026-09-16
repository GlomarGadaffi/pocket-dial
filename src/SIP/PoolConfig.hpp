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

// Number of SERVICE EXTENSION slots (Issue #202) — the alphanumeric pseudo-AORs
// the ENGINE owns rather than a phone: `pbx` (register beep), `moh` (hold-music
// preview), `server` (server-initiated BYE), and the `voicemail`/`attendant` that
// #194/#168 will add. Sizes BOTH the compile-time table in ServiceExtensions.hpp
// and RequestsHandler's parallel array of pre-allocated loopback peer objects, so
// the whole feature's storage is fixed at boot like every pool above it.
//
// Deliberately SEPARATE from POCKETDIAL_MAX_CLIENTS: _clientPool is registration
// capacity and belongs to real handsets. A service must never consume a slot a
// phone could have had, must never show in the dashboard roster as though a
// handset were there, and must never be adoptable in Learn mode — all three fall
// out of the records simply living somewhere else.
//
// Eight is headroom, not a plan: three are seeded and the table is a static_assert
// away from overflowing this. Each unused slot costs one empty ServiceEndpoint
// (a string_view + a bool) and one null shared_ptr.
#ifndef POCKETDIAL_MAX_SERVICES
#define POCKETDIAL_MAX_SERVICES 8
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
// Fixed at 1: LoopbackAnchorClient hands back the SAME fixed mock participant
// id ("mock-part-123") from every makeCall() (see LoopbackAnchorClient.cpp),
// so a second concurrent anchor call on it would collide with the first on
// that id, and RequestsHandler's single anchor rx-audio callback would feed
// only whichever bridge it finds first, silently starving the other call's
// audio. TelephonyAnchorClient (ported from drawbridge) IS an implementation
// whose makeCall()/resolveOutboundLeg() hands back a distinct participant id
// per call -- what AnchorClient.hpp's interface expects of any real
// implementation -- so raising this is safe once that port lands. It is
// deliberately NOT raised in that same pass: more slots multiply socket count
// (see the sdkconfig.defaults CONFIG_LWIP_MAX_SOCKETS note), per-call task-stack
// footprint (12 KB PSRAM x kWsWorkers; 6 KB INTERNAL RAM x N media-rx tasks --
// RtpReceiver.cpp/RtpSender.cpp both use plain xTaskCreatePinnedToCore, not
// PSRAM, despite PsramTask.hpp's name -- corrected here, found while sizing
// POCKETDIAL_MAX_VOICEMAIL_LEGS below, which hits the same tasks), and proving
// the single-call path end-to-end on real hardware is its own verification
// pass before concurrency is added on top.
// RAISED 1 -> 4. Both conditions the paragraph above set for this are now met:
// TelephonyAnchorClient landed (it hands back a distinct participant id per call,
// TelephonyAnchorClient.cpp:418), and the single-call path is hardware-proven --
// an outbound PSTN call completed end to end with two-way audio on the bench.
//
// The loopback objection above is NOT waved away, it is enforced properly:
// AnchorClient::maxConcurrentCalls() lets each provider declare what it can
// actually drive, LoopbackAnchorClient reports 1 because its participant id is a
// constant, and RequestsHandler::anchorCallLimit() takes the min of that and this
// array size. So sizing the arrays for the real trunk can no longer quietly hand
// the mock a concurrency that would silently starve one leg's audio.
//
// 4 rather than more, from drawbridge's hardware validation on this same silicon:
// the ceiling is not sockets or RAM (both lifted -- PSRAM task stacks, 48-entry
// LWIP pool) but the ESP32-S3's SOFTWARE ECDHE. With no ECC accelerator each TLS
// handshake costs roughly a second of CPU and a cold start opens two per call
// (the GET and POST audio streams). Past ~4 simultaneous handshakes both cores
// saturate, the idle tasks starve into the task watchdog, and the surplus calls
// finish handshaking too late to bridge anything. At 4 the calls bridge with no
// playout glitches and the 5th is cleanly refused with 503 rather than accepted
// and dropped. Raising further needs ECC-accel silicon or GET-stream resumption.
#ifndef POCKETDIAL_MAX_ANCHOR_CALLS
#define POCKETDIAL_MAX_ANCHOR_CALLS 4
#endif

// Concurrent OUTBOUND SIP trunk dialogs (issue #164). Two, not four: each trunk
// call also consumes an RtpReceiver/RtpSender relay pair and a message-pool
// slot, and a residential PBX placing three simultaneous PSTN calls is not the
// case worth sizing for. Exceeding it refuses the call rather than queueing --
// see SipTrunk::placeCall().
//
// Its OWN #ifndef, deliberately. This define originally sat inside the anchor
// cap's guard above, which meant any build overriding POCKETDIAL_MAX_ANCHOR_CALLS
// skipped the whole block and never defined this at all -- and SipTrunk.hpp
// declares std::array<Dialog, POCKETDIAL_MAX_TRUNK_CALLS>, so that configuration
// failed to COMPILE. No current build overrides the anchor cap, so CI was green
// and correct and the break was invisible to every configuration it exercises.
// Every cap in this file carries its own guard for exactly this reason; do not
// nest one inside another.
#ifndef POCKETDIAL_MAX_TRUNK_CALLS
#define POCKETDIAL_MAX_TRUNK_CALLS 2
#endif

// Number of concurrent voicemail legs (Issue #246, Stage 3 of #194) -- deposit
// (recording a caller's message) or retrieval (playing one back), never more
// than one call at a time per leg. Each leg owns its own RtpReceiver/RtpSender
// pair, the same per-leg RTP-task cost as a conference leg or anchor bridge
// (POCKETDIAL_CONF_LEGS / POCKETDIAL_MAX_ANCHOR_CALLS above) -- 2 x 6144B of
// task stack in INTERNAL RAM per leg (RtpReceiver.cpp/RtpSender.cpp both use
// plain xTaskCreatePinnedToCore, not PSRAM, despite PsramTask.hpp's name).
//
// Fixed at 2, deliberately small: each leg ALSO holds a PSRAM recording
// buffer sized to the per-message duration cap (see VoicemailLeg.hpp), so
// raising this multiplies BOTH the internal-RAM task-stack cost above and the
// PSRAM buffer cost, on the same 8MB PSRAM pool HoldMusic's clip and the new
// IVR prompt clips already share (docs/HARDWARE.md: 8MB Octal PSRAM on every
// board). 2 covers "someone leaves a message while someone else is
// retrieving theirs" without a real sizing pass against hardware; raise it
// only alongside a fresh look at free PSRAM/internal RAM, the same caution
// POCKETDIAL_MAX_ANCHOR_CALLS's history above already sets a precedent for.
#ifndef POCKETDIAL_MAX_VOICEMAIL_LEGS
#define POCKETDIAL_MAX_VOICEMAIL_LEGS 2
#endif

// Max single voicemail message duration. 90s of 8kHz mu-law (1 byte/sample)
// is 720,000 bytes (~703 KiB) -- long enough for a real message, short
// enough that the full budget below still fits comfortably. Every leg needs
// TWO buffers this size, not one (see VoicemailArchive.hpp's class comment
// for why): the record buffer onCallerRtp() fills live, and a separate
// staging buffer the flush queue copies into at BYE so releaseVoicemailLeg()
// never has to wait for the writer task. Total budget at the defaults above:
// POCKETDIAL_MAX_VOICEMAIL_LEGS (2) x 2 buffers x ~703 KiB =~ 2.75 MiB,
// alongside HoldMusic's ~816 KiB clip, on the 8MB Octal PSRAM every board in
// docs/HARDWARE.md carries. Not yet checked against actual free-PSRAM
// telemetry on hardware -- same caution POCKETDIAL_MAX_ANCHOR_CALLS's own
// history above sets a precedent for; raise/lower alongside a real
// measurement, not by feel.
#ifndef POCKETDIAL_VOICEMAIL_MAX_MESSAGE_SECONDS
#define POCKETDIAL_VOICEMAIL_MAX_MESSAGE_SECONDS 90
#endif
#define POCKETDIAL_VOICEMAIL_MAX_MESSAGE_BYTES (POCKETDIAL_VOICEMAIL_MAX_MESSAGE_SECONDS * 8000)

// Bound on one vmarchive::Source::listMessages() call and on the
// VoicemailMenu's own per-mailbox listing array -- a fixed-size std::array,
// not a growing container, since both run in an RTOS task after init (see
// PoolConfig.hpp's own "no malloc/new after init" convention throughout this
// file). 20 messages is a generous mailbox for a desk extension; a mailbox
// that fills past this simply hides its oldest entries from the menu until
// some are deleted -- it does not refuse new deposits (that's index.csv's
// row count, unbounded on disk, not this in-RAM listing window).
#ifndef POCKETDIAL_VOICEMAIL_MAX_MESSAGES_PER_BOX
#define POCKETDIAL_VOICEMAIL_MAX_MESSAGES_PER_BOX 20
#endif

// Maximum number of DID -> extension inbound routing entries (DidMapping.hpp).
// Bounded exactly like TelephonyApiConfig::kSlots: a fixed std::array, no heap,
// a 9th add fails cleanly ("table full") rather than growing unbounded. Small
// default: a desk PBX sitting behind a Telephony-API anchor typically owns a
// handful of DIDs, not hundreds. Consulted by RequestsHandler::
// routeInboundAnchorCall() (Stage B of the TelephonyAnchorClient port) — an
// empty extensionForDid() lookup still falls back to ring-all, so raising
// this costs table RAM only, no other budget.
#ifndef POCKETDIAL_MAX_DID_MAPPINGS
#define POCKETDIAL_MAX_DID_MAPPINGS 8
#endif

// Maximum concurrent RFC 3261 §17 CLIENT transaction records — requests this
// PBX sent and will retransmit until they are answered.
//
// Each slot tracks either one outgoing INVITE fork (§17.1.1, Timer A/B) or one
// outgoing non-INVITE request (§17.1.2, Timer E/F/K): BYE, CANCEL, NOTIFY,
// REFER, INFO, MESSAGE, SUBSCRIBE, UPDATE. Sized to cover MAX_SESSIONS
// concurrent INVITE dialogs, plus the worst-case BLF NOTIFY fan-out (one NOTIFY
// per subscription when a watched extension changes state, all in flight at
// once), plus headroom for hunt-group forks.
//
// The NOTIFY burst is what drove the +MAX_SUBSCRIPTIONS term: those slots are
// each held for Timer K (T4 = 5 s) after the watcher's 200 OK, or Timer F (32 s)
// if a watcher has gone away silently, so a single busy-lamp change can claim
// MAX_SUBSCRIPTIONS slots at once. Without the term, a BLF burst would evict
// INVITE retransmit coverage — the exact regression #148 was about.
//
// Pool exhaustion → message still sent once (graceful degradation), which is
// precisely the pre-transaction-layer behaviour — it never crashes or blocks.
#ifndef POCKETDIAL_MAX_TRANSACTIONS
#define POCKETDIAL_MAX_TRANSACTIONS \
	(POCKETDIAL_MAX_SESSIONS * 2 + POCKETDIAL_MAX_SUBSCRIPTIONS + 8)
#endif

// Maximum concurrent RFC 3261 §17 SERVER transaction records — responses this
// PBX AUTHORED, kept so that a retransmitted request gets the same answer
// instead of being re-processed, and (for INVITE) retransmitted until ACKed.
//
// Much smaller than the client pool, for two reasons. First, only responses the
// PBX itself authors are tracked at all: an ordinary extension-to-extension call
// has its 200 OK RELAYED from the callee phone, which owns that retransmission
// under its own transaction layer, so those take no slot here. What is left is
// the virtual extensions (777 echo, 888 conference, 555 anchor, park orbits, MoH
// preview), the register beep, and the failure responses the engine mints itself
// (403/404/486/488/503/603). Second, only the methods where re-processing a
// duplicate actually does harm get a non-INVITE server transaction — BYE, CANCEL,
// REFER and UPDATE — while REGISTER, OPTIONS, MESSAGE, INFO and SUBSCRIBE are
// left to be re-processed as before, because they are idempotent enough that a
// 32 s Timer J slot each would cost far more than it buys. (INFO is the close
// call: a duplicated DTMF digit is a real bug, but at one slot per keypress for
// 32 s it would dominate this pool on its own. Tracked separately.)
//
// Same graceful degradation: no free slot → the response is still sent once.
#ifndef POCKETDIAL_MAX_SERVER_TRANSACTIONS
#define POCKETDIAL_MAX_SERVER_TRANSACTIONS (POCKETDIAL_MAX_SESSIONS + 8)
#endif

// Depth of the RFC 4733 DTMF hand-off ring — key presses captured on an RTP
// receive task and waiting to be acted on by the SIP thread.
//
// This is a THREAD BOUNDARY, not a work queue. A telephone-event packet is
// decoded on the media task, but every consumer of a digit (the feature-code
// table, the admin menu, the per-dialog accumulator) assumes the engine's big
// _mutex is held and runs single-threaded on the SIP path. The ring is how a
// press crosses from one to the other: the RTP task memcpy's a fixed record in
// under its own small mutex and returns immediately, never touching _mutex and
// never allocating, so a busy SIP pass can never introduce audio jitter.
//
// Sized for human dialling, not throughput. Digits arrive at a few per second
// at most, and the ring is drained on every SIP packet AND every tick, so more
// than a couple of slots are only ever needed if the SIP thread stalls. Sixteen
// covers the longest feature code several times over. Overflow drops the oldest
// press and counts it (see RequestsHandler::dtmfDigitsDropped) rather than
// blocking the media task — a dropped digit costs one keypress, a blocked RTP
// task costs the call's audio.
#ifndef POCKETDIAL_DTMF_INBOX
#define POCKETDIAL_DTMF_INBOX 16
#endif

// Bytes of each transaction record's retransmit buffer — the serialized message
// held ready to put back on the wire.
//
// 1500 is the Ethernet MTU, which is the practical ceiling for a SIP/UDP
// datagram this engine will emit without fragmenting. A message that does not
// fit is stored truncated, flagged, and NEVER retransmitted (sending a truncated
// SIP message is worse than sending nothing) — sweep() logs once when that
// happens, so lost coverage is visible rather than silent.
//
// This is the dominant term in the layer's RAM cost:
// (MAX_TRANSACTIONS + MAX_SERVER_TRANSACTIONS) × ~1.7 KB. On the default S3R8
// profile that lands in PSRAM along with the rest of RequestsHandler. On a
// no-PSRAM board (sdkconfig.defaults.esp32_constrained) it is internal RAM —
// lower this, or the two pool counts above, for that tier. See docs/SCALING.md.
#ifndef POCKETDIAL_TX_MSG_BYTES
#define POCKETDIAL_TX_MSG_BYTES 1500
#endif

// Issue #163: minimum all-digit length an unprefixed AOR must reach before the
// REGISTER identity guard (pbx::looksLikePstnAor(), PbxConfig.hpp) treats it as
// "looks like a direct PSTN number" rather than an internal extension, and
// refuses the REGISTER. This is a POLICY choice, not a protocol fact — unlike
// the '+' case (unambiguous E.164, refused unconditionally regardless of this
// knob), an unprefixed all-digit string is only ever a *guess* about intent.
//
// Every extension this codebase's own docs/tests actually use is 3-4 digits
// (docs/API.md's "1001"/"1002"/"1003"/"610"/"620" examples, 700-709 park
// orbits, 980-989 page zones) and PoolConfig's own
// POCKETDIAL_MAX_DIAL_RULES comment above describes the whole dial space as
// "three-digit LAN extensions". NANP draws its own line at 7 (a bare local
// number, no area code) and 10 (area code included); a true international
// E.164 number runs 8-15 digits but arrives with a leading '+' and is already
// caught unconditionally, so this knob only ever has to catch a NANP-shaped
// number someone dialed in without the '+'. 7 gives every real extension in
// this deployment a clean 3-4 digit margin while still catching the shortest
// PSTN-shaped string that could plausibly show up unprefixed.
//
// Raise this if a deployment's numbering plan legitimately needs 5-6 digit
// internal extensions; only lower it with a numbering plan that guarantees no
// collision with a shorter PSTN-shaped number.
#ifndef POCKETDIAL_MIN_PSTN_AOR_DIGITS
#define POCKETDIAL_MIN_PSTN_AOR_DIGITS 7
#endif

#endif
