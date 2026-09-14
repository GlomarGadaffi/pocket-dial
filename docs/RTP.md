# Server-Side RTP on Pocket-Dial

> **Status:** Originally a pre-implementation design exploration ("Proposed / exploration.
> No code written yet"). **Server-side RTP has since been built — but not along the path this
> document recommended.** §§0-1 and §3.5 have been rewritten to describe what shipped. The
> cost analysis in §2 and the implementation sketch in §4 are preserved as the
> **pre-implementation estimates they were**, and are labelled as such; they were never
> re-measured against the shipped code.
> **Audience:** An engineer extending the media path, or sizing a deployment.

---

## 0. What actually ships today

The server is no longer media-free. Three virtual extensions terminate media on the board,
and one ordinary call path does not:

| Path | Does the board touch RTP? | Detail |
| :--- | :--- | :--- |
| **Ordinary extension → extension** | **No.** Pure peer-to-peer. | SDP is relayed; the `c=` connection line is **never** rewritten. Only the codec list is narrowed, by `SipMessage::filterAudioCodecs(/*allowWideband=*/true)`. |
| **Hold / resume, blind & attended transfer, ring/hunt groups, pickup** | **No.** | Same property preserved deliberately — see `RequestsHandler.cpp:5449` ("Relay UNTOUCHED"), `CallForker.cpp:49`, `CallPickup.cpp:98`. |
| **Call parked on an orbit** | **Only with music on hold configured — then yes, transmit only.** | **This row changed.** Park used to answer `a=inactive` on the discard port and source nothing. With a MoH clip loaded it answers `sendonly` from the `HoldMusic` port and adds the parked leg to the shared clip stream (`ParkOrbit.cpp:56-75`), so the board transmits to the parked phone for the whole park. One-way only: the parked phone's own audio is not carried, and the retrieve is still an SDP swap back to peer-to-peer. **With no clip loaded — the default — the old `a=inactive` silent hold is used and the board sources nothing.** |
| **`777` echo test** | **No.** | It is an **SDP loopback**: the answer is the caller's own offer handed back (narrowed to PCMU), so the phone streams to its own address. `RequestsHandler.cpp:1228-1293`. A code comment elsewhere in the tree implying the server echoes the audio is wrong. |
| **`440` tone** | **Yes — transmit only.** | `RtpSender` synthesizes a G.711 µ-law tone 20 ms at a time and sends it to the caller. Fixed server port `5062`. **One concurrent stream**; a second dial gets `486 Busy Here`. |
| **`555` anchor bridge** | **Yes — both directions.** | `MediaBridge` pairs an `RtpReceiver`/`RtpSender` with an `AnchorClient`, decoding handset RTP into the anchor and draining the anchor's audio out of a `PlayoutBuffer`. `POCKETDIAL_MAX_ANCHOR_CALLS` = **1** (`PoolConfig.hpp:199-200`). Active on default firmware via the `LoopbackAnchorClient` reference implementation. |
| **`888` meet-me conference** | **Yes — decode, mix, re-encode.** | `ConferenceRoom` owns one `MixBus`; each leg is its own `RtpReceiver`/`RtpSender`/`MediaBridge` trio on a bus port. `POCKETDIAL_CONF_LEGS` = **4** (`PoolConfig.hpp:175-176`), bounded by `MixBus::MAX_PORTS` = 8. No PIN, one global room. |
| **Outbound trunk call** | **Yes — on the handset leg.** | Two legs. Handset ↔ board is ordinary **RTP** through `MediaBridge` in ANCHOR mode, which owns the handset-facing `RtpReceiver`/`RtpSender` pair (`MediaBridge.hpp:15-17`; `startBridge(handsetIp, handsetPort, …)` at `RequestsHandler.cpp:336`, `:2676`). Board ↔ carrier is the AnchorClient's chunked-HTTPS PCM16 stream — **not** RTP and **not** SIP. Same `POCKETDIAL_MAX_ANCHOR_CALLS` = 1 budget as `555`. |

**Codecs on server-terminated legs are PCMU only** — `buildMediaSdp()` emits a literal
`m=audio <port> RTP/AVP 0` (`RequestsHandler.cpp:1536`), and each such leg admits a caller
only if it offers narrowband (`offersSupportedAudio(/*allowWideband=*/false)`, e.g.
`RequestsHandler.cpp:1931`), answering `488 Not Acceptable Here` otherwise. The `777` echo
answer is narrowed by `filterAudioCodecs(/*allowWideband=*/false)`
(`RequestsHandler.cpp:1292`). Relayed peer-to-peer legs admit PCMU, PCMA **and G.722**.

### 0.1 Shipped modules

The proposed `src/Media/` directory was never created; everything landed under `src/SIP/`:

| File | Role |
| :--- | :--- |
| `src/SIP/RtpSender.{hpp,cpp}` | One-way RTP transmit: µ-law encode, tone synthesis, RTP header build, 20 ms pacing task. Optional `FrameProvider` lets a bridge supply frames instead of the tone. |
| `src/SIP/RtpReceiver.{hpp,cpp}` | RTP receive + depacketize into a sink. |
| `src/SIP/PlayoutBuffer.{hpp,cpp}` | The jitter-absorbing ring. Hard ceiling 1600 samples = **200 ms @ 8 kHz**; overrun drops oldest; underrun fills comfort noise. Tracks underruns/overruns. |
| `src/SIP/MixBus.{hpp,cpp}` | The summing junction. Per-port rings, minus-self mix held in int32 and clipped exactly once on the way out. `FRAME` = 160 samples, `MAX_PORTS` = 8. |
| `src/SIP/MediaBridge.{hpp,cpp}` | Anchors one call's LAN RTP to either an `AnchorClient` (ANCHOR mode) or a `MixBus` port (BUS mode). |
| `src/SIP/ConferenceRoom.{hpp,cpp}` | Owns one `MixBus`, the per-leg transport, and the **single** 20 ms mix-tick driver. |

> [!WARNING]
> **No automated test has ever exercised any of this on-target.** The DSP/packetization
> helpers are platform-independent and host-unit-tested, but the UDP socket and the FreeRTOS
> pacing task are `#if defined(ESP_PLATFORM)`-only; off-target they compile to **host stubs**
> (`RtpSender.cpp:589`, `RtpReceiver.cpp:416`). Every green media test in the suite —
> `Rtp_test`, `RtpReceiver_test`, `MediaBridge_test`, `MixBus_test`, `PlayoutBuffer_test`,
> `ConferenceRoom_test` — exercises a stub, not the radio.
>
> There is exactly **one** piece of real-hardware media evidence in the project: an outbound
> trunk call from a Yealink T29 answered by a person **with two-way audio** (2026-09-13). That
> call ran the handset leg through `RtpReceiver` / `RtpSender` / `MediaBridge` / `PlayoutBuffer`
> on a real board, so it is genuine on-target proof of the **anchor-bridge shape** of this
> media stack. It proves nothing about `440` or `888`: the tone sender's standalone path and
> the whole `MixBus` / `ConferenceRoom` mixer have **never been run on hardware at all**.

### 0.2 What is still absent

The document below recommended **Music-on-Hold as Phase 1**. It was not built then, and
recording, relay and announcement injection still have not been. **MoH has since shipped**
(issue #162) — in a narrower form than the plan below imagined, and not as `src/Media/MohPlayer.*`.
Still absent today:

* **Call recording**, **RTP relay / NAT traversal**, **announcement injection**.
* **RTP statistics.** Nothing computes or exposes jitter, loss or MOS. `PlayoutBuffer`'s
  underrun/overrun counters exist but are not surfaced on the dashboard or in any API
  response; `/api/status` carries no media quality fields.
* **999 as a mixer.** `999` is still fork-and-pick — the INVITE goes to every registered
  phone and the **first** to answer wins; the rest are CANCELed (`CallForker.cpp:59-62`).
  The real N-way bridge is the separate `888` meet-me room.

---

## 1. Why P2P remains the default, and what server RTP unlocked

### 1.1 Why ordinary media is peer-to-peer

The device is a registrar + proxy/redirect-ish B2B-light signalling box. When A calls B:

1. A's INVITE (with SDP offering `m=audio <portA> RTP/AVP ...`) reaches the server. The
   server narrows the codec list with `filterAudioCodecs()` and forwards the offer toward B.
2. B answers `200 OK` with its own SDP (`m=audio <portB> ...`). The server narrows and
   forwards it back to A.
3. **The `c=` connection address and `m=` port in each SDP still point at the phones
   themselves.** Once both sides have each other's `IP:port`, they stream RTP directly. The
   server is out of the media path entirely.

This is why `PoolConfig.hpp` can say a `Session` "costs the server only signalling/bookkeeping
RAM — not bandwidth or DSP". A signalling session is ~200 B of state. **The ordinary call path
is fast and light precisely because the server never sees an audio packet** — hold and
transfer relay SDP untouched apart from the codec list, and that is still true of every
ordinary call. **Park is the one feature added since that did not preserve it**: with a
music-on-hold clip loaded the board answers the parked leg `sendonly` from its own port
and transmits to it (`ParkOrbit.cpp:56-75`). The exception is bounded — one direction,
one leg, only while parked, and only when an operator has uploaded a clip.

### 1.2 What server-side RTP bought, and what it did not

| Capability | Status |
| :--- | :--- |
| **Real conferencing / mixing** | **Shipped as `888`** (`ConferenceRoom` + `MixBus`), capped at 4 legs, one global room, no PIN. Note this is a *separate* extension — `999` was **not** converted; it is still fork-and-pick. |
| **Server-sourced audio** | **Shipped as `440`** — a synthesized tone, transmit-only. This is the "media beachhead" the phased plan called Phase 1, but it is a test tone, not music-on-hold. |
| **Bridging to an off-LAN party** | **Shipped as `555`** — `MediaBridge` in ANCHOR mode, one concurrent call. The far side is an `AnchorClient` over HTTPS/WebSocket, **not** an RTP relay and **not** a SIP trunk. |
| **NAT traversal / media relay** | Not built. There is no B2BUA RTP relay and no rewriting of a peer-to-peer call's `c=` line. |
| **Call recording** | Not built. |
| **Music-on-Hold** | **Shipped, for park only** (`HoldMusic.*`, issue #162). A G.711 µ-law 8 kHz mono clip is read off the SD card into PSRAM once at load, then a 20 ms tick reads 160 bytes **once** and `sendto`s the identical payload to every parked listener — one global cursor, so a late joiner lands mid-track as if tuning into a broadcast. No per-leg decode, no `MixBus`, no `RtpSender` instance per listener. Playback is a memcpy: the clip is stored in the wire format. The SD card is deliberately kept out of the media path (sdspi `poll_busy()` busy-spins, and 100–250 ms card GC stalls would be audible dropout on every listener at once). Falls back to silent `a=inactive` hold whenever there is no clip. **A party its own phone puts on hold is unaffected** — that still hears whatever its firmware plays. |
| **Announcement injection** | Not built as a media feature. |
| **DTMF** | Feature codes arrive as SIP INFO. On relayed peer-to-peer legs `telephone-event` simply passes through untouched. On legs the board terminates it is also **decoded**: `RtpReceiver` implements RFC 4733 reception on the negotiated dynamic payload type — 4-byte event parse (`RtpReceiver.cpp:150-166`), event-code→keypad mapping for the 16 DTMF symbols with hook-flash and tone events ignored (`:167-178`, `:448-451`), and press deduplication keyed on the event's RTP timestamp (`:219`), which is the whole difficulty of RFC 4733. |
| **RTP statistics (jitter / loss / MOS)** | Not built (§0.2). |

---

## 2. ESP32-S3 cost analysis — PRE-IMPLEMENTATION ESTIMATES

> [!IMPORTANT]
> **Everything in §2 is an estimate made *before* any media code was written, and it has never
> been re-measured against the shipped `RtpSender` / `MixBus` / `ConferenceRoom`.** The
> unit-economics arithmetic (§2.1) is arithmetic and still correct. The concurrency ceilings
> (§2.4) are educated guesses that were **never validated**; the shipped caps —
> `POCKETDIAL_CONF_LEGS` = 4 and `POCKETDIAL_MAX_ANCHOR_CALLS` = 1 — are the numbers that
> actually bound the firmware, and both were chosen conservatively for reasons documented in
> `PoolConfig.hpp` rather than derived from the table below. Treat §2 as *why the caps are
> low*, not as *what the hardware can do*.

### 2.1 The unit economics of one G.711 stream (arithmetic — still valid)

G.711 at 8 kHz, 20 ms ptime:

```
8000 samples/s × 1 byte/sample × 0.020 s   = 160 bytes audio / packet
+ RTP header (12 B) + UDP (8 B) + IP (20 B) = 200 bytes on the wire / packet
packets per second                          = 1000 ms / 20 ms = 50 pps
payload bitrate                             = 160 B × 50 × 8   = 64 kbit/s
on-the-wire bitrate (one direction)         ≈ 200 B × 50 × 8   = 80 kbit/s
```

So **one RTP stream = 50 pps, ~64 kbit/s payload (~80 kbit/s on the wire), each direction.**
A two-party call is two streams each way. The shipped 20 ms cadence and 160-sample frame
match this exactly (`RtpSender::SAMPLES_PER_PKT` = 160, `MixBus::FRAME` = 160).

### 2.2 Estimated cost of a 2-party relay (never built)

A relay receives a packet on socket A and re-sends it to B (and vice versa). Per two-party
call:

* **Packets:** 50 pps in + 50 pps out, per direction = **~200 pps of relay work**
  (100 in, 100 out) for a single bidirectional call.
* **CPU (estimate):** pure relay (no decode) is `recvfrom` → look up session → rewrite dest →
  `sendto`. The LwIP/socket path is the real cost, not arithmetic. Budgeted conservatively at
  **~30–60 µs of CPU per relayed packet**; at 200 pps that is ~6–12 µs/ms ≈ **0.6–1.2% of one
  core per call**. CPU was not expected to be the binding constraint for pure relay.
* **RAM (estimate):** ~200–400 B/stream without a jitter buffer; add ~480 B–1 KB/stream with a
  60 ms buffer of 160 B frames.
* **Wi-Fi:** **this was identified as the constraint.** Relaying *doubles* airtime: every
  audio packet is received and re-transmitted over the same half-duplex radio. A two-party
  relay ≈ 320 kbit/s of media airtime (4 × 80 kbit/s) plus 802.11 per-frame overhead that
  dwarfs the payload at these tiny frame sizes. Small frames are airtime-expensive.

### 2.3 Estimated cost of an N-party mixer (shipped as `888`, capped at 4)

A mixer must **decode** each incoming stream to 16-bit PCM, **sum** them, **clip** to int16,
**re-encode** G.711, and send each participant the mix-minus-self.

```
per 20 ms frame, N participants:
  N × decode (G.711→PCM)        : 160 table lookups each  → cheap
  build mix bus                 : sum N×160 int16 samples
  per participant: subtract self, clip, encode (PCM→G.711)
  N × sendto                    : N syscalls / 20 ms
```

* **CPU:** arithmetic is trivial (µ-law decode is a LUT). The cost is **syscalls and the
  per-frame deadline**: all N decodes + the mix + N encodes + N `sendto` calls must complete
  **every 20 ms**.
* **Hard limit:** the **20 ms wall clock**. Overrun it and you drop a frame and everyone hears
  a click.
* **Estimated ceiling at the time: ~6–8 mixed participants on a dedicated core.** **The
  shipped cap is 4** (`POCKETDIAL_CONF_LEGS`), and `PoolConfig.hpp:169-177` gives the real
  reason: a conference leg costs one `Session` slot, one RTP receive task, one RTP send task
  and two `MixBus` rings (**~6 KB**) per participant, on top of the room's own mix-tick task.
  Four legs is what comfortably fits the constrained node. Raise it only alongside
  `POCKETDIAL_MAX_SESSIONS` and a look at free heap.

One structural point from the original design **did** survive into the implementation and is
worth keeping visible: **the mix tick is the master clock and there is exactly one of it.**
Each leg's `RtpSender` runs its own 20 ms cadence, so hanging the mix tick off a sender would
give N competing clocks draining the bus N times per frame. `ConferenceRoom::startDriver()`
stands up one dedicated 20 ms driver for the whole room; a leg's sender only ever calls
`MixBus::outputFrame()`.

### 2.4 Estimated concurrency ceilings — NEVER VALIDATED

Per `docs/SCALING.md`, internal DRAM headroom after IDF + Wi-Fi was ~290–320 KB on a plain
ESP32, and the existing pools cost ~37 KB. Two facts were expected to dominate:

1. **IRAM was ~100% used**, so RTP code would have to live in flash-cached paths subject to
   i-cache misses — acceptable at a 20 ms cadence, but the hot loop must not be
   latency-sensitive at the microsecond level. *(This claim was true when written and has not
   been re-checked against the current build.)*
2. **A media session is ~1–2 KB, not the ~200 B of a signalling session.** This held up: the
   shipped figure is ~6 KB of `MixBus` rings per conference leg plus two task stacks.

| Build | Media core available | Relayed 2-party calls | Mixed participants |
| :--- | :--- | :---: | :---: |
| Headless / Ethernet (S3) | Core 0 mostly free | *est.* 4–6 | *est.* 6–8 |
| Display (JC3248W535) | Core 1 = LVGL only; share Core 0 | *est.* 2–3 | *est.* 3–4 |

**These numbers were never measured.** Relay was never built at all, so its column is purely
hypothetical. The mixer shipped with a flat cap of 4 legs on every build. They were bounded
first by Wi-Fi airtime, then by the 20 ms deadline, then by RAM; wired Ethernet builds relax
the airtime constraint substantially.

### 2.5 Latency budget

Server-terminated media adds delay on top of peer-to-peer:

```
P2P one-way:        capture(20) + network + playout         ≈ 40–80 ms typical
Server-terminated:  capture(20) + net→server + server queue
                    + playout buffer + net→peer + playout
                    ≈ 100–180 ms  (estimate)
```

The ITU-T G.114 comfort ceiling is ~150 ms one-way, so every ms of buffer matters. The
shipped `PlayoutBuffer` enforces a **hard 200 ms ceiling** (1600 samples @ 8 kHz) with a
target-depth drain holding steady state far lower — the header records that an earlier 1 s
buffer "let mouth-to-ear delay balloon". This is another reason to **prefer peer-to-peer
whenever possible**, which the ordinary call path still does.

---

## 3. Architecture options as they were evaluated — and what happened

### (a) Pure relay / B2BUA — **not built**

The server would terminate both media legs, rewriting the SDP it sends each phone so `c=`/`m=`
point at the server. Rejected as the default then, and never built since: it doubles airtime
for *every* call including ones that did not need it, adds latency to every call, and has the
biggest blast radius if the media task stalls. **The shipped code never rewrites a
peer-to-peer call's `c=` line.**

### (b) Selective relay — **not built**

Default to P2P and insert the server only when needed (different subnets, unreachable private
`c=`, or a policy flag). Judged the right way to ship relay *if* relay were ever needed. It
was not: the device is primarily a same-LAN intercom and the NAT case has not come up.

### (c) MoH player — **recommended first, never built**

Transmit-only G.711 clip looped from flash/PSRAM to a held phone. This was the document's
headline recommendation. What actually shipped first was the `440` **tone** — the same
transmit-only shape (`RtpSender`), the same "prove the RTP pipe" purpose, but synthesized
rather than played from a stored clip, and not wired to hold signalling. Music-on-hold remains
absent; a held party hears whatever its own firmware plays.

### (d) Conference mixer — **built, but as `888`, not as `999`**

The proposal was to replace fork-and-pick `999` with a true mixer. Instead a **new** virtual
extension `888` was added with its own `MixBus`/`ConferenceRoom`, leaving `999` unchanged as
the all-page broadcast. That is the better outcome: paging and conferencing are different
features and `999`'s fork-and-pick semantics are what an all-page wants.

### 3.5 What the phased plan said, and what actually happened

```
PROPOSED                                    ACTUAL
Phase 1  MoH player + RTP stats scaffolding  →  440 tone (RtpSender). No MoH. No stats.
Phase 2  RTP stats on a receive path         →  RtpReceiver + PlayoutBuffer shipped;
                                                stats never surfaced anywhere.
Phase 3  Selective relay, wired-only         →  Never built. Instead: 555 anchor bridge
                                                (MediaBridge + AnchorClient over HTTPS).
Phase 4  999 conference mixer, gated         →  888 meet-me room (MixBus + ConferenceRoom),
         behind measured headroom               capped at 4 legs. 999 unchanged. The
                                                "measured headroom" gate did not happen —
                                                the cap was chosen from a RAM budget, and
                                                nothing has been measured on-target.
```

The plan's *sequencing instinct* was right — transmit-only first, then receive, then
bridging, then mixing — and that is the order things were built in. Its *feature* predictions
were not: RTP statistics and relay still do not exist, the conference landed on a different
extension, and MoH — the thing the plan put *first* — arrived last of all, years later and
in a different shape (`HoldMusic`, park-only, one shared cursor rather than the per-listener
`MohPlayer` imagined here).

---

## 4. Implementation sketch — AS ORIGINALLY PROPOSED

> [!NOTE]
> This section is the original pre-implementation sketch. The file layout it proposes does
> **not** match the shipped code — see §0.1 for the real module list. It is kept for the
> design reasoning (lock discipline, static allocation, task pinning), most of which the
> implementation did follow.

### 4.1 Where it hooks in

**Proposed:**

```
src/SIP/RequestsHandler.cpp   ← session wiring: start/stop media
src/SIP/SipSdpMessage.*       ← SDP rewrite for server-terminated legs
src/Media/RtpEndpoint.*       ← NEW: UDP RTP socket + packetiser/depacketiser + stats
src/Media/RtpRelay.*          ← NEW: pairs two RtpEndpoints, or fans out
src/Media/MohPlayer.*         ← NEW: transmit-only G.711 clip looper
src/Media/JitterBuffer.*      ← NEW: fixed-depth reordering buffer
```

**Actual:** no `src/Media/` directory; `RtpSender` / `RtpReceiver` / `PlayoutBuffer` /
`MixBus` / `MediaBridge` / `ConferenceRoom` all live in `src/SIP/`. `RtpEndpoint` was split
into separate send and receive classes; `RtpRelay` was never written; `MohPlayer` was never
written *under that name* — the feature shipped as `src/SIP/HoldMusic.{hpp,cpp}`, and
deliberately not as a per-listener player (see §1.2); `JitterBuffer` became `PlayoutBuffer`.

### 4.2 SDP for server-terminated legs

The proposal was a `rewriteMediaTarget(serverIp, allocatedPort)` splice into the existing
`_messageStr`. **What shipped instead** is `RequestsHandler::buildMediaSdp(serverIp, rtpPort,
sendrecv)` (`RequestsHandler.cpp:1521-1540`), which constructs the server's **own** SDP body
from scratch — `m=audio <port> RTP/AVP 0` plus `a=rtpmap:0 PCMU/8000` — rather than rewriting
the caller's. Server RTP ports: `440` uses a fixed `5062` (`RtpSender.cpp`, `SERVER_RTP_PORT`);
conference legs get theirs from `ConferenceRoom::rtpPortFor(callID)`.

### 4.3 Packet path

```
440 tone (transmit only):
  [RtpSender task] every 20 ms:
     synthesize 160 µ-law samples (or pull from a FrameProvider)
     → wrap in RTP (seq++, ts+=160, SSRC) → sendto(caller_ip:port)

555 anchor bridge (both directions):
     RtpReceiver → MediaBridge::onHandsetRtp → decode → AnchorClient::writeAudio()
     AnchorClient rx → MediaBridge::feedRx → PlayoutBuffer → RtpSender's FrameProvider

888 conference (decode / mix / re-encode):
     per leg: RtpReceiver → MediaBridge (BUS mode) → MixBus::inputFrame(port)
     one 20 ms driver tick: MixBus::tick() sums every active port in int32
     per leg: RtpSender pulls MixBus::outputFrame(port) = the sum of every OTHER port,
              clipped exactly once on the way out
```

### 4.4 Buffering

Proposed: a fixed-depth ring of 3–4 frames (60–80 ms), compile-time constant, no dynamic
resize on the hot path. **Shipped as `PlayoutBuffer`**: a 1600-sample (200 ms) hard ceiling
with a target-depth drain, overrun dropping oldest and underrun filling low-amplitude comfort
noise, plus underrun/overrun counters (which nothing reads — §0.2).

### 4.5 Static allocation & threading

Proposed, and largely followed:

* **Bounded pools, not dynamic growth.** Shipped as `POCKETDIAL_CONF_LEGS` (4) and
  `POCKETDIAL_MAX_ANCHOR_CALLS` (1); `RtpSender` and `RtpReceiver` each enforce a one-stream
  cap internally, so a conference leg gets its own pair rather than sharing the `440` sender.
* **No hot-path heap.** Shipped: the tone is synthesized 160 samples at a time into a fixed
  member buffer; nothing is allocated per packet.
* **Dedicated FreeRTOS tasks, pinned.** Shipped: `RtpSender`, `RtpReceiver` and
  `ConferenceRoom`'s driver all use `xTaskCreatePinnedToCore`. On a display build Core 1 is
  LVGL-only and must not be touched.
* **Lock discipline: media packets must never take the SIP `_mutex`.** The media task reads
  the far-end `IP:port` from an immutable per-session snapshot captured at call setup, and
  `sendto` happens on the media task, never inside the registrar lock — the same spirit as the
  existing Outbox pattern.

**Where the proposal was wrong:** a media-pool exhaustion was supposed to "fall back to P2P
gracefully". It does not — the call is refused:

* a second `440` while a tone stream is live → **486 Busy Here** (`RequestsHandler.cpp:1667`);
* a fifth conference leg → **486 Busy Here**, "room full or media failed to start"
  (`RequestsHandler.cpp:1788`);
* a `555` while the single anchor bridge is in use → **503 Service Unavailable** with
  `Retry-After`, deliberately *not* 486, because 486 would mean the called party is busy when
  in fact every bridge slot is (`RequestsHandler.cpp:1956-1962`).

There is no P2P fallback for a server-terminated feature, because these features *are* the
server media — there is no far phone to fall back to.

### 4.6 Interaction with codec enforcement

The proposal assumed `enforceG711()` guaranteed `0 8 101` in every answer, so the packetiser
could be fixed-format with no negotiation logic. **`enforceG711()` is deprecated with no
production callers.** The live guarantee comes from a different place and is narrower: the
server builds its own PCMU-only SDP (`buildMediaSdp()`), and admits a caller onto a
server-terminated leg only if it offers narrowband, answering `488 Not Acceptable Here`
otherwise (`RequestsHandler.cpp:1216`, `:1931`). The practical effect the media layer depends on is the
same — **server-terminated legs are PCMU, 160 B payload, 20 ms** — but relayed peer-to-peer
legs are *not* so constrained: they may negotiate PCMA or G.722 between the phones, and the
media layer never sees them.

### 4.7 Media-path diagrams

```
ORDINARY CALL — peer-to-peer (server out of the media path; still the default):

   Phone A ───── SIP (INVITE/OK) ─────► [ pocket-dial ] ◄───── SIP ───── Phone B
        │                                registrar/proxy                      │
        │                         (narrows codec list; c= untouched)          │
        └──────────────── RTP G.711 (direct, 64 kbit/s ea way) ───────────────┘
                          server NEVER sees these packets


888 CONFERENCE — server terminates every leg:

   Phone A ──RTP──►┌─────────────────────────────────┐◄──RTP── Phone B
                   │           pocket-dial           │
   Phone C ──RTP──►│  RtpReceiver ─► MediaBridge ─►  │◄──RTP── Phone D
                   │         MixBus (int32 sum)      │
                   │  RtpSender  ◄─ minus-self mix ◄─│
                   └─────────────────────────────────┘
                   one 20 ms tick drives the whole room; 4 legs max
                   every packet crosses the radio TWICE (in + out)
```

---

## 5. Risks — as assessed pre-implementation

> These were written before the media code existed. They still read as the right risk list,
> but **none has been validated on-target**, because on-device RTP has never been exercised by
> a test (§0.1).

| Risk | Detail | Mitigation as shipped |
| :--- | :--- | :--- |
| **Wi-Fi half-duplex / airtime (assessed BIGGEST)** | Server-terminated media doubles airtime on a shared half-duplex radio; tiny 200 B frames are airtime-inefficient. Expected to cap concurrency ahead of CPU. | Ordinary calls stay peer-to-peer; server media is confined to opt-in virtual extensions with hard caps (4 conference legs, 1 anchor call, 1 tone stream). Prefer wired builds for conferencing. **Not measured.** |
| **Added latency** | Server-terminated media plus buffering eats the G.114 150 ms budget. | `PlayoutBuffer` hard ceiling 200 ms with a target-depth drain holding steady state lower. **Not measured.** |
| **CPU saturation → glitches** | The 20 ms deadline is hard; mixing is most exposed. | One dedicated pinned mix-tick task per room; legs capped at 4. **Watermark never measured on-target.** |
| **IRAM exhaustion** | IRAM was ~100% used, so the media hot loop runs from flash-cached code subject to i-cache misses. | The per-frame loop is small and branch-light; the 20 ms cadence tolerates cache misses. **Current IRAM headroom not re-checked.** |
| **RAM** | Media sessions are ~1–2 KB each (estimate); shipped conference legs are ~6 KB of rings plus two task stacks. | Small fixed caps. Note there is **no graceful P2P fallback** — the call is simply refused (§4.5). |
| **Security — RTP injection** | An attacker who learns a session's `IP:port`/SSRC can inject forged RTP. The SIP rate limiter does not cover RTP ports. | `440`'s port is **fixed at 5062**, which makes it the easiest target on the box. Validate inbound source against the negotiated peer, check SSRC continuity, and rate-cap per port — **verify against the current `RtpReceiver` before relying on any of this.** |
| **Conflicts with "fast and light"** | The original value proposition was a media-free server. | Preserved where it matters: ordinary calls, hold and transfer are still 100% peer-to-peer. Server media is otherwise confined to features the user must explicitly dial — plus park, which transmits only when an operator has loaded a hold-music clip. |

---

## 6. If you are extending this

1. **Measure something on-target first.** The single largest gap in this document is that
   every performance number in it is an estimate and every media test is a host stub. A real
   4-leg `888` conference on a real board, with a scope on the frame deadline, would be worth
   more than any further design work.
2. **Do not break the peer-to-peer property of the ordinary call path.** It is what makes 8
   concurrent calls fit. Hold and transfer preserved it deliberately; park now breaks it in
   one bounded direction when a hold-music clip is loaded, and anything new should stay at
   least that bounded.
3. ~~**Music-on-hold is still the cheapest unbuilt win**~~ — **built** (issue #162), and not
   via the `RtpSender::FrameProvider` hook this line expected: `HoldMusic` owns its own socket
   and 20 ms task precisely so ten parked callers do not cost ten `RtpSender` instances with
   ten unread receive paths. It covers **park only**; a party its own phone put on hold still
   hears whatever that handset plays.
4. **RTP statistics are nearly free.** `PlayoutBuffer` already counts underruns and overruns;
   nothing surfaces them. Adding them to `/api/status` would give the dashboard its first
   media-quality signal.

**Related:** [CONFERENCE_MIXER.md](CONFERENCE_MIXER.md) ·
[PHONE_COMPATIBILITY.md](PHONE_COMPATIBILITY.md) · [SCALING.md](SCALING.md) ·
[ARCHITECTURE.md](ARCHITECTURE.md)
