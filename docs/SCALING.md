# Scaling & Capacity Planning

How to size the **pocket-dial** SIP registrar for a given board, what it costs in
RAM, and what breaks if you push it too far.

> TL;DR: capacity is set at **compile time** via three macros in
> [`src/SIP/PoolConfig.hpp`](../src/SIP/PoolConfig.hpp). The defaults
> (`32` clients / `8` sessions / **`52`** messages) target a generic Wi-Fi ESP32.
> The message pool is derived, not a literal: `POCKETDIAL_MSG_POOL` defaults to
> `MAX_CLIENTS + MAX_SUBSCRIPTIONS + 4` = 32 + 16 + 4 = **52**
> (`PoolConfig.hpp:69-71`), sized so a `999` all-page fan-out and a BLF `NOTIFY`
> burst in the same locked section cannot spill to the heap. Override it and you
> break that sizing; see §3.
> Bump them with `-D` flags for an S3-with-PSRAM build. See the tier table below
> for ready-to-paste build commands.

## 1. Why RAM is the binding constraint (not CPU or bandwidth)

pocket-dial's default call path is a **signalling-only** SIP server. It registers
endpoints, routes INVITE/BYE/CANCEL, and brokers call setup. It does **not** touch
the audio for an ordinary call:

* **RTP media is peer-to-peer.** Once two phones complete the SDP offer/answer,
  they stream G.711 audio *directly to each other's IP:port*. The ESP32 never
  sees an RTP packet, never transcodes, never mixes. A connected call costs the
  server **zero** ongoing CPU and **zero** media bandwidth. Only the few hundred
  bytes of `Session` bookkeeping that remember who is talking to whom. (The
  capacity model below is about THIS path. `AnchorClient`/`MediaBridge`/`MixBus`
  are an opt-in exception that puts the board in the media path when a fork wires
  them in; see [FEATURE_ROADMAP.md](FEATURE_ROADMAP.md) Non-Goals; they carry their own,
  separate CPU/RAM budget, not accounted for here.)
* **Signalling is bursty and tiny.** A REGISTER or INVITE is a sub-1 KB UDP
  datagram handled in microseconds. Even with aggressive OPTIONS keepalives the
  packet rate per client is a handful per *minute*.

So the question "how many phones / calls can this board host?" reduces almost
entirely to **"how much SRAM can I afford to reserve for pre-allocated pools?"**
That is exactly what the `POCKETDIAL_MAX_*` knobs control.

### Pre-allocation model

All three pools are filled **once, at construction** (Issue #53), and objects are
*recycled* thereafter via `reset()`; the steady-state hot path performs **no heap
allocation**. This is deliberate: the ESP32 heap has no MMU and no compaction, so
a long-running server that mallocs/frees per packet will eventually fragment and
fail an allocation at the worst possible moment. Pre-allocation trades a fixed,
known, up-front RAM cost for **deterministic, fragmentation-free** runtime. The
corollary is that **the pool sizes ARE the device's hard concurrency limits**, and
they are paid for whether the box ever handles one call or its ceiling.

## 2. Per-object RAM cost (the inputs to the budget)

Approximate steady-state footprint per pooled object on a 32-bit Xtensa target
(`sizeof` of the struct + any owned heap buffer + the `shared_ptr` control block).
These are deliberately rounded **up** for allocator overhead, so a real device will
sit a little under these figures.

| Pool object | Dominant members | Owned heap | Budget per slot |
| :--- | :--- | :--- | ---: |
| **`SipClient`** | `std::string` extension (SSO, no heap for short numbers), `sockaddr_in` (16 B), `int`, 3× `steady_clock::time_point` (8 B each) | none (extension fits in SSO) | **~100 B** |
| **`Session`** | `std::string` Call-ID (~32–40 B on heap), 2× `shared_ptr<SipClient>`, `State` enum, `time_point`, broadcast `vector` (empty for normal 1:1 calls) | ~40 B Call-ID | **~200 B** |
| **`SipSdpMessage`** | base `SipMessage`: 12× `string_view` (16 B each ≈ 192 B), SDP adds 6 more + int; plus the owned **`std::string _messageStr`** holding the entire raw SIP+SDP packet | ~0.6–0.9 KB packet buffer | **~1 KB** |
| **`SipTransaction`** | `char msg[POCKETDIAL_TX_MSG_BYTES]` retransmit buffer (1500 B), Call-ID/branch/CSeq-method char arrays (~212 B), `sockaddr_in`, 3× `time_point` | none (the buffer is inline, by design) | **~1.75 KB** |

Reasoning: clients are cheap because an extension like `"1001"` lives in the
string's small-string-optimization buffer (no allocation). Sessions add a heap
Call-ID and a couple of `shared_ptr`s. The message objects dominate the budget:
each one owns a full reusable packet buffer (the SDP body alone is several hundred
bytes), which is precisely why we recycle them instead of reallocating per packet.

### Default static budget (32 / 8 / 52 / 40+16)

```
clients     :  32 × ~100 B  ≈   3.2 KB
sessions    :   8 × ~200 B  ≈   1.6 KB
messages    :  52 × ~1   KB ≈  53.2 KB
transactions:  56 × ~1.75KB ≈  97.6 KB   <-- dominant term
                              ----------
TOTAL                       ≈ ~156 KB static SRAM
```

> **Corrected twice.** An early revision used 32 messages and reported ~37 KB;
> that was fixed to ~58 KB when the derived 52-message default was accounted for
> (`PoolConfig.hpp`). The figure above adds the transaction pools, which did not
> exist at either earlier revision in anything like their current size. If you
> sized a board against **either** older number, re-check it.

**The transaction pools are now the dominant term, ahead of the message pool.**
`sizeof(TransactionLayer)` is **99,912 B** at the defaults, measured, not
estimated; `TxLifecycle.TheLayerStaticFootprintIsVisibleHere` in
`tests/TransactionLayerRfc17_test.cpp` asserts a ceiling on it so the number
cannot drift silently. It breaks down as 40 client slots
(`POCKETDIAL_MAX_TRANSACTIONS`, sized `MAX_SESSIONS*2 + MAX_SUBSCRIPTIONS + 8` so
a full BLF NOTIFY fan-out cannot evict INVITE retransmit coverage) plus 16 server
slots (`POCKETDIAL_MAX_SERVER_TRANSACTIONS`), each carrying an inline 1500-byte
copy of the message it may have to put back on the wire.

That inline buffer is the whole cost and it is deliberate: a transaction must be
able to retransmit after the pooled `SipMessage` it came from has been recycled
into a different call, so it cannot hold a reference. It has to own the bytes.

**On a no-PSRAM board this is internal DRAM and it matters.** The default S3R8
profile has `CONFIG_SPIRAM_USE_MALLOC=y`, and `RequestsHandler` is far larger
than the 16 KB always-internal threshold, so the whole engine, these pools
included, lands in PSRAM. `sdkconfig.defaults.esp32_constrained` sets
`CONFIG_SPIRAM=n`, and on that tier ~156 KB against ~290–320 KB of usable
internal DRAM is no longer a comfortable margin. Note that the `POCKETDIAL_*`
knobs are `-D` compiler flags, **not** Kconfig options, so switching to the
constrained sdkconfig does **not** scale them down on its own; the build has to
pass them. For that tier, start with:

```
-DPOCKETDIAL_MAX_TRANSACTIONS=16 \
-DPOCKETDIAL_MAX_SERVER_TRANSACTIONS=6 \
-DPOCKETDIAL_TX_MSG_BYTES=900
```

which brings the layer to roughly 25 KB. The trade is real and worth stating
plainly: fewer slots means pool exhaustion sheds retransmit tracking sooner (the
message still goes out once, the pre-transaction-layer behaviour), and a smaller
buffer means any message over the limit is stored truncated and never
retransmitted at all. Both degrade loudly rather than silently. Exhaustion logs
`[tx] client pool exhausted` / `[tx] server pool exhausted`, and an oversized
message logs `[tx] message too large to retransmit` naming the method and
Call-ID. 900 bytes comfortably holds a BYE, CANCEL, NOTIFY or a bodiless
response; it will truncate an INVITE carrying a large SDP offer, so check those
logs on a constrained build before trusting the number.

## 3. Hardware tiers

Pick the row that matches your board, paste the build command, done. All three
build the same firmware; only the pool caps differ.

| Tier | Board | `MAX_CLIENTS` | `MAX_SESSIONS` | Msg pool | Static pool RAM | Realistic concurrent calls |
| :--- | :--- | ---: | ---: | ---: | ---: | :--- |
| **Pocket** | Generic ESP32 (Wi-Fi SoftAP) | **32** (default) | **8** (default) | 52 (derived) | **~58 KB** | 6–8 simultaneous calls, ~16 phones (SoftAP-limited) |
| **Office** | ESP32-S3 + 8 MB PSRAM (Guition JC3248W535) | **64** | **24** | 64 | **~90 KB** | ~24 calls, 50+ phones |
| **Rack** | ESP32-S3 + W5500 PoE (wired Ethernet) | **128** | **48** | 128 | **~180 KB** | ~48 calls, 100+ phones |

> The "concurrent calls" column is a *practical* expectation, not just
> `MAX_SESSIONS`: it folds in the network-layer ceilings discussed in §5
> (SoftAP association cap, socket/FD limits). On a wired Rack node the session
> pool, not the network, is the limit; on a Pocket SoftAP node the **16-client
> Wi-Fi association cap** bites long before the 32-client pool does.

### Build commands

#### Pocket (generic ESP32, defaults, nothing to pass)

```sh
# Host build (desktop Linux/Windows) — used for tests/CI
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build

# ESP-IDF firmware
idf.py build
```

#### Office (ESP32-S3 / 8 MB PSRAM, Guition display board)

```sh
# Host build
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CXX_FLAGS="-DPOCKETDIAL_MAX_CLIENTS=64 -DPOCKETDIAL_MAX_SESSIONS=24"

# ESP-IDF firmware
idf.py build -DCMAKE_CXX_FLAGS="-DPOCKETDIAL_MAX_CLIENTS=64 -DPOCKETDIAL_MAX_SESSIONS=24"
```

> **Do not pass `-DPOCKETDIAL_MSG_POOL` here.** Earlier revisions of this block
> added `-DPOCKETDIAL_MSG_POOL=64`, which is *smaller* than the value the default
> derivation produces for `MAX_CLIENTS=64` (64 + 16 + 4 = **84**). Setting it to 64
> silently shrank the pool below the all-page + `NOTIFY` fan-out it is sized for
> (`PoolConfig.hpp:58-71`), the opposite of what the flag looked like it was doing.
> Leave it unset and it tracks `MAX_CLIENTS` automatically.

#### Rack (ESP32-S3 + W5500/PoE wired Ethernet)

```sh
# Host build
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CXX_FLAGS="-DPOCKETDIAL_MAX_CLIENTS=128 -DPOCKETDIAL_MAX_SESSIONS=48"

# ESP-IDF firmware
idf.py build -DCMAKE_CXX_FLAGS="-DPOCKETDIAL_MAX_CLIENTS=128 -DPOCKETDIAL_MAX_SESSIONS=48"
```

> Same note as Office: leave `POCKETDIAL_MSG_POOL` unset. The derivation gives
> 128 + 16 + 4 = **148**, and the `=128` this block used to pass was a reduction.

> PSRAM note (Office/Rack): the ~90–180 KB pool budget fits in *internal*
> SRAM on the S3, so no PSRAM is strictly required for these tiers. PSRAM on the
> Guition board is reserved for the LVGL frame buffers (≈307 KB each, see
> [HARDWARE.md](HARDWARE.md) §2), not for these pools. Keeping SIP state in fast
> internal SRAM avoids PSRAM access latency on the signalling path. If you push
> the message pool into the hundreds you can move *that* pool to PSRAM, but the
> defaults above intentionally stay in internal SRAM.

## 4. Graceful degradation when a pool is exhausted

Running out of a pool is a **defined, recoverable** condition, never a crash or
an out-of-memory abort. Each pool degrades in its own well-behaved way:

* **Client pool full (REGISTER).** `allocateClient()` first tries to reuse an
  existing binding, then a free slot, then **evicts the oldest already-expired
  client**. Only if every slot holds a live registration does it fail, and then
  the registrar replies **`503 Service Unavailable`**. The phone's SIP stack
  retries on its normal REGISTER refresh timer, so a client that arrives after a
  slot frees up simply registers on its next attempt.
* **Session pool full (INVITE / 999 broadcast).** `allocateSession()` returns
  `nullptr` when no slot is free, and every INVITE path answers
  **`503 Service Unavailable`** (see `onInvite()` and the broadcast handler in
  `RequestsHandler.cpp`). The caller hears fast-busy / "service unavailable"
  rather than the call hanging. Existing calls are untouched.
* **Message pool drained: hard stop, no heap.** `getMessageFromPool()` returns
  `nullptr` the moment the pool is empty and logs `"[WARNING] SIP Message pool
  exhausted (N total)! Refusing -- no heap fallback."` (rate-limited to
  1-in-100). There is **no** heap fallback behind the pool: the #101(A) one, and
  its `POCKETDIAL_MSG_HEAP_FALLBACK_MAX` ceiling, were removed by #409 (a build
  that still defines the knob fails at compile time). The call sites in
  `RequestsHandler.cpp` that check it drop the packet and rely on the peer's
  RFC 3261 §17 retransmit. Shedding load is the intended behaviour at that depth,
  but it *does* refuse work. An earlier revision of this bullet said it never
  does. It matters most during a 999 all-page, which transiently needs one message
  per paged target; see §6.

All three counters surface on the dashboard (`getClientCount()`,
`getSessionCount()`, processed/dropped packet counters), so operators can watch
headroom and bump the tier before exhaustion becomes routine.

> Measured (Issue #79): driving registrations from 40 distinct source IPs
> (bypassing the Issue #38 per-IP limiter) against a default-tier host build
> confirmed the client-pool ceiling
> lands exactly at 32, with a clean `503` on the overflow and no crash. The
> session-pool ceiling (8) is real server-side (confirmed via server logs) and
> the ordinary call-setup path 503s cleanly at it, but the `777` echo/diagnostic
> extension does **not** currently surface that 503 to the caller; see Issue
> #115. This was a single-host, host-build measurement (loopback-range source
> IPs, not real distinct hosts), not a real multi-host run against firmware.

> Measured on firmware, multi-host (Issue #79, 2026-09-06): the run above has
> now been repeated against a real board, a LilyGO T-ETH-Elite S3 (W5500,
> `SIP_TRANSPORT=eth`, default 32/8 tier), driven concurrently from **two
> genuinely distinct physical hosts** on the same LAN, so the Issue #38 per-IP
> token bucket is bypassed by having separate buckets rather than by loopback
> aliases:
>
> | source host | attempts | `200` | `503` | p50 latency |
> |---|--:|--:|--:|--:|
> | `192.168.12.110` | 25 | **25** | 0 | 7.3 ms |
> | `192.168.12.161` | 25 | **7** | 18 | 11.8 ms |
> | **total** | 50 | **32** | 18 | — |
>
> The client-pool ceiling lands at **exactly 32** across the two hosts, matching
> `POCKETDIAL_MAX_CLIENTS`, confirming the pool is global, not per-source. Every
> rejection was a clean `503 Service Unavailable`; `packetsDropped` stayed 0, and
> the serial console showed no watchdog, panic, abort or reboot. The board kept
> answering REGISTERs afterwards. A separate single-host run (45 attempts, paced
> under the per-IP limit) reproduced the same 32/13 split with p50 4.6 ms.
>
> Two caveats worth recording. First, the **session** ceiling (8) was *not*
> cleanly demonstrated on firmware: 14 concurrent `777` echo calls returned 11 ×
> `200` and 3 × *no response at all* rather than `503`, the Issue #115 behaviour,
> now confirmed on hardware. Second, sustained registration load makes the
> register-beep INVITE flood the static message pool
> (`[tx] pool exhausted — INVITE sent without retransmit tracking`), which is
> Issue #148; a starved pool silently drops unrelated signalling, so the latency
> figures above should be read as "healthy tier, known beep bug", not as a clean
> bill of health.

## 5. Why the defaults are 32 / 8, and what breaks if you 10× them

**Why 32 clients / 8 sessions?** The default target is a generic ESP32 running a
Wi-Fi **SoftAP** (a small office, a classroom, a pop-up intercom). In that
deployment:

* The ESP-IDF SoftAP **caps associated stations at ~10–16** (`max_connection`,
  hard-limited by the Wi-Fi driver). 32 client slots is already *2×* that ceiling,
  giving comfortable room for stale-binding churn without ever being the limit.
* 8 sessions means up to 8 simultaneous 1:1 calls, well beyond what ~16 phones
  realistically place at once, and an `8 × ~200 B` rounding error in the budget.
* The whole thing fits in **~58 KB** (see §2; the message pool defaults to the derived
  52, not 32), leaving most of internal SRAM for Wi-Fi buffers, the HTTP dashboard, the
  captive-portal DNS, and LVGL.

In short: 32/8 is sized to be *one notch above* the network layer's own ceiling on
the cheapest supported board, so RAM is never wasted and the pool is never the
thing that fails first.

What breaks if you naively 10× to 320 / 80 / 320:

* **Static SRAM exhaustion.** ~370 KB of pools would *exceed the entire usable
  internal DRAM* of a plain ESP32 (~290–320 KB). The firmware would fail to boot
  or starve the Wi-Fi stack. The S3 has more headroom but the message pool still
  dominates. Move it to PSRAM before going this large.
* **Heap fragmentation at boot.** 320 message objects each own a packet buffer;
  allocating them all at startup on a fragmented heap can fail even when *total*
  free bytes look sufficient, because there's no single contiguous run. (The
  `.reserve()` calls in the constructor mitigate the *vector* spine, but not the
  per-object buffers.)
* **FreeRTOS task-stack pressure.** Bigger pools mean larger snapshot vectors and
  longer locked sweeps in `tick()`/`sweepExpired()`; the dashboard/SIP task stacks
  must grow to match, competing for the same SRAM you just spent on pools.
* **File-descriptor / socket limits.** lwIP defaults to a small number of sockets
  (`CONFIG_LWIP_MAX_SOCKETS`, often 10–16). Hundreds of *registered* clients is
  fine (they share one UDP listener), but anything that opens per-peer sockets, or
  the HTTP dashboard under load, hits the FD cap long before 320 clients matters.
* **SoftAP association cap (Pocket tier).** Even with 320 client slots, a Wi-Fi
  SoftAP still won't associate more than ~16 stations. The extra slots are pure
  wasted RAM unless you're on **wired Ethernet** (the Rack tier), which is exactly
  why high client counts belong on the W5500/PoE board, not a SoftAP node.

Rule of thumb: scale clients/sessions to match your *network tier* (SoftAP →
stay near defaults; wired Ethernet → scale up), keep the message pool ≈ the client
count, and watch the dashboard headroom counters. Doubling is routine; 10× needs a
wired board, internal-SRAM math, and probably the message pool in PSRAM.
