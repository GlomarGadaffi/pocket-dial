# pocket-dial — Conference Mix Bus

**The summing junction: design and implementation for N-way audio on the ESP32-S3.**

This document specifies the one operation needed to turn pocket-dial's anchored-media
path (`MediaBridge` + an `AnchorClient` implementation) from a star of isolated 1:1 legs
into an N-way conference bridge: the **mix**. It carries the design, a compiled-and-tested
scalar reference, the concurrency model, and the ESP32-S3 PIE vector kernels (with honest
notes on which instructions are confirmed versus toolchain-verify).

---

## 0. Context and goals

### What existed when this was written

> [!IMPORTANT]
> **§0 is a pre-implementation snapshot and its present tense is now wrong.** The mix bus
> it proposes **shipped** as `MixBus` + `ConferenceRoom` on extension `888` (issue #75) —
> see §7, which is the current-state section. Read §0 as history. Two of its statements
> would actively mislead if taken as current: the board *is* in the media path for `440`,
> `555`, `888`, an outbound trunk call, and a park orbit with music on hold loaded; and
> the "retire the special-case 1:1 logic" goal below **was not met** — ordinary calls are
> still peer-to-peer and never touch `MixBus`, and `MediaBridge` in BUS mode still holds
> exactly one port with `feedRx()` returning `false` (`MediaBridge.cpp:179-184`).

pocket-dial routes phone↔phone calls as **peer-to-peer RTP** — the board is not in the
media path. `MediaBridge` only anchors media for a call routed through an `AnchorClient`
implementation (see `src/SIP/MediaBridge.cpp`). Reading that path (`src/SIP/MediaBridge.cpp`,
`RtpReceiver::mulawDecodeBuffer`, `RtpSender::ulawEncodeBuffer`, `AnchorClient::writeAudio(const int16_t*)`)
reveals the important fact:

> **Linear int16 PCM is already the internal currency at the anchor boundary.** µ-law lives
> only at the LAN/handset rim; the anchor (`writeAudio` / `feedRx`) speaks linear. The PCM
> fabric is built — what's missing is the summing junction.

Today each participant's audio reaches exactly one handset (`MediaBridge::feedRx` → its own
`_playoutBuffer`). It is a **star of 1:1 anchored legs with no summing**. The `999` all-page
is a *fan-out* (same payload → many); a real conference is a *mix*.

### Goal
Add a single `MixBus` that owns the mix tick. Each call attaches a **port** (two `PlayoutBuffer`
rings: leg→bus and bus→leg). Every active port hears the saturated sum of all *other* ports.
`MediaBridge` becomes a thin transport endcap; an ordinary 1:1 call falls out as the **N=2 case**,
so the mixer subsumes the point-to-point path and the special-case 1:1 logic can be retired.
*(This last clause did not happen — see the note at the top of §0. Ordinary calls stayed
peer-to-peer, which is the property the rest of the project is built around, and the anchor
leg is still outside the bus; §7's own caveat says so.)*

### Non-goals
Transcoding (still G.711 at the rim, linear within), and per-codec edges beyond what
`MediaBridge` already does. Wideband (16 kHz) and Opus legs drop onto the same bus as linear
ports — the bus does not care which codec produced a frame.

---

## 1. The summing junction (the math)

An **N−1 mix**: each leg hears everyone *but itself*. The minus-self is not optional — loop a
talker's own audio back and you have built a digital echo chamber with one-frame delay.

Two ways to compute it:

| Formulation | Cost | Where it fits |
|---|---|---|
| **Sum-once-subtract**: `M = Σ inᵢ` once, then `outₚ = M − inₚ` | `2N` ops | Large/variable N. Needs a **wide (int32) accumulator**. |
| **Direct per-port**: `outₚ = Σ_{q≠p} in_q` | `N(N−1)` ops | Small N (≤~6). Pure int16 saturating; **no accumulator, no minus-self**. |

### The one invariant you cannot violate
**Never saturate the running mix.** Sum-once-subtract is only correct if `M` is held in int32
and saturated *exactly once*, at the final per-port output.

Worked counterexample (four legs at +30000, int16):
- **Wrong** — clip `M` to int16 first: `M = sat16(120000) = 32767`; a leg hears
  `32767 − 30000 = 2767` → nearly silent. Broken.
- **Right** — `M` in int32 = `120000`; leg hears `120000 − 30000 = 90000` → `sat16 = 32767`.
  Correct.

Headroom: max magnitude is `N × 32767`, which fits int32 for any sane N (overflow needs
>65536 legs). The direct per-port formulation sidesteps this entirely because it never forms
the all-inclusive sum — that is exactly why it is the natural fit for the confirmed S3 int16
saturating ops (§6).

> The self-test (`tests/MixBus_test.cpp`) asserts both the minus-self result and that the
> loud port hears **32767, not 2767**. Both pass.

---

## 2. Topology

The bus sits **between the decode and encode edges**. `MediaBridge` keeps owning the RTP
sockets and the rim companding; it just rewires its two callbacks at the bus.

```
        handset (µ-law RTP)                          anchor leg (linear)
            │  ▲                                          │  ▲
   decode   │  │  encode                                  │  │
  (mulaw→)  │  │ (→ulaw)                                   │  │  (already linear:
            ▼  │                                           ▼  │   feedRx / writeAudio)
        ┌───────────┐  inputFrame()        inputFrame()  ┌───────────┐
        │  port P   │ ───────────────┐  ┌─────────────── │  port Q   │
        │ in.ring   │                ▼  ▼                │ in.ring   │
        │ out.ring  │ ◀──┐      ┌──────────────┐    ┌──▶ │ out.ring  │
        └───────────┘    │      │   MixBus     │    │    └───────────┘
                         │      │  tick():     │    │
              outputFrame└──────│  Σ int32 →   │────┘outputFrame
                                │  −self → sat │
                                └──────────────┘
                                  one 20 ms clock
```

- **Handset ports** compand at the rim (µ-law ↔ linear), exactly as `MediaBridge` does now.
- **Anchor-leg ports** are already linear (`feedRx`/`writeAudio` take `int16_t*`) → they drop
  straight onto the bus with **no compand at all**.
- The bus sees only int16 frames; the codec edge is somebody else's problem.

---

## 3. The mix tick is the master clock

This is the actual engineering — the arithmetic is trivial; the timing is not.

Every leg arrives on its own RTP/jitter clock. The **per-port input ring absorbs that jitter**,
and a single periodic driver (one timer, or your existing sender cadence — whichever is more
stable on your build) drains **exactly one frame per port in lockstep** each tick. A leg that
is late contributes **zeros for that tick** and the tick moves on; it never blocks waiting on
a straggler.

```
RTP in (jittery) ─▶ [per-port input ring] ─▶ ┐
                                              ├─ mixTick() @ fixed 20 ms ─▶ [output rings] ─▶ encode/RTP out
RTP in (jittery) ─▶ [per-port input ring] ─▶ ┘
```

**Stabilising this loop and making it underrun-tolerant is ~80% of the work.** Treat the tick
cadence as inviolable; everything else slots around it.

---

## 4. Implementation — scalar reference (ships today)

Correct, portable, `-Wall -Wextra`-clean, and the always-on fallback. At ≤8 narrowband ports
the mix is ~64k adds/s — a rounding error on a 240 MHz core. **Write it scalar first;
vectorise only when ports × sample-rate climbs.**

Files (all in `src/SIP/`): `MixBus.hpp`, `MixBus.cpp`, `mix_kernels.h`, `mix_kernels_scalar.cpp`.
The tick:

```cpp
void MixBus::tick()
{
    alignas(16) int16_t frame[MAX_PORTS][FRAME];   // 16-byte aligned for the PIE path
    unsigned char present[MAX_PORTS];

    // (1) Snapshot participation for THIS tick; pull one frame per active port;
    //     reclaim any Draining ports in-band (tick is the SOLE ring-clearer).
    for (int p = 0; p < MAX_PORTS; ++p) {
        State s = _ports[p].state.load(std::memory_order_acquire);
        if (s == State::Draining) {
            _ports[p].in.clear(); _ports[p].out.clear();
            _ports[p].state.store(State::Free, std::memory_order_release);
            present[p] = 0; continue;
        }
        present[p] = (s == State::Active) ? 1 : 0;
        if (present[p] && !_ports[p].in.read(frame[p], FRAME))
            std::memset(frame[p], 0, sizeof frame[p]);   // late leg -> silence this tick
    }

    // (2) Full mix in int32 — NEVER saturate here.            [PIE kernel A]
    mix_accumulate(_mix, frame, present, MAX_PORTS, FRAME);

    // (3) Fan out: each active port hears (mix - self), saturated once. [PIE kernel B]
    for (int p = 0; p < MAX_PORTS; ++p) {
        if (!present[p]) continue;
        alignas(16) int16_t out[FRAME];
        mix_minus_self(out, _mix, frame[p], FRAME);
        _ports[p].out.write(out, FRAME);
    }
}
```

The two kernels behind fixed signatures (scalar body shown; PIE swap in §6):

```cpp
void mix_accumulate(int32_t* mix, const int16_t frame[][MIX_FRAME],
                    const unsigned char* present, int maxPorts, int frameLen) {
    std::memset(mix, 0, sizeof(int32_t) * frameLen);
    for (int p = 0; p < maxPorts; ++p)
        if (present[p])
            for (int i = 0; i < frameLen; ++i)
                mix[i] += frame[p][i];        // int16 promoted to int32 — no saturation
}

void mix_minus_self(int16_t* out, const int32_t* mix, const int16_t* self, int frameLen) {
    for (int i = 0; i < frameLen; ++i) {
        int32_t v = mix[i] - self[i];
        out[i] = (v > 32767) ? 32767 : (v < -32768) ? -32768 : (int16_t)v;
    }
}
```

---

## 5. Concurrency — attach/detach vs the tick

`attach`/`detach` run on SIP signaling threads; the tick runs on its own driver. The hot path
must be lock-free and a leg leaving must never corrupt or silence the others. This is the
**single-active-bridge discipline `MediaBridge` already keeps for one leg, generalised to N.**

### Per-port state machine
```
   ┌────────┐  attach() [CAS]   ┌────────┐  detach() [CAS]   ┌──────────┐
   │  Free  │ ────────────────▶ │ Active │ ────────────────▶ │ Draining │
   └────────┘                   └────────┘                   └──────────┘
        ▲                                                          │
        └──────────────────  tick() reclaims  ◀────────────────────┘
                       (clears rings, stores Free)
```

**The rule:** the tick is the *sole owner of ring teardown*. Reclamation (clear rings → return
to `Free`) happens only inside `tick()`, so no signaling thread ever frees ring state under a
concurrent tick read. This maintains the invariant **"a `Free` slot has empty rings,"** which
is why `attach()` need only flip the flag.

```cpp
int MixBus::attach() {                          // cold path
    for (int p = 0; p < MAX_PORTS; ++p) {
        State expected = State::Free;
        if (_ports[p].state.compare_exchange_strong(
                expected, State::Active,
                std::memory_order_acq_rel, std::memory_order_relaxed))
            return p;                            // rings guaranteed empty by prior reclaim
    }
    return -1;                                  // bus full
}

void MixBus::detach(int port) {                 // non-blocking; tick reclaims later
    State expected = State::Active;
    _ports[port].state.compare_exchange_strong(
        expected, State::Draining,
        std::memory_order_acq_rel, std::memory_order_relaxed);
}
```

- `attach` uses a **CAS** (`Free → Active`) so two signaling threads racing for the same slot
  resolve lock-free; the loser tries the next slot. (A coarse mutex around `attach`/`detach` is
  an acceptable simplification — those paths are cold.)
- `detach` only flips to `Draining` and returns. The next tick clears the rings and publishes
  `Free`. Until then `attach` won't reuse the slot.
- `inputFrame`/`outputFrame` gate on `State::Active`; `PlayoutBuffer` is itself internally
  synchronised for the ring read/write, so the only thing the state flag arbitrates is
  *participation*, not buffer safety.
- **Ordering:** publish-Active and publish-Free are `release`; all readers (`tick`, `inputFrame`,
  `outputFrame`) are `acquire`. The tick snapshots `present[]` at the top, so a port flipping
  mid-tick never tears a frame.

> Verified in `tests/MixBus_test.cpp`: detach a port, tick once, slot returns `Free` and
> re-attaches at the same index.

---

## 6. The PIE vector kernels (drop-in when N × Fs climbs)

**Discipline first:** the scalar path above is the default and is correct. These kernels are a
*transparent swap behind the same signatures*. Do not reach for them until profiling says the
mix loop matters — i.e. many legs, or you move the bus to 16 kHz to fold G.722 in natively.

**ISA honesty:** the ESP32-S3 PIE instruction set is thinly documented. The kernel below uses
**only instructions confirmed real** (`ee.vld.128.ip`, `ee.vadds.s16`, `ee.vst.128.ip` — the
`vadds.s16` pattern is in esp-dsp's `dsps_add_s16_aes3.S` and the S3 TRM extended-instruction
chapter). The int32 path needs ops I will not assert blind — see the caveat box.

### 6a. Small conference (≤5-way): confirmed-ISA, no int32, no minus-self
Pick the **direct per-port** formulation. To give port P "everyone but itself," sum P's
up-to-four peers; never form the all-inclusive sum, so the over-saturation trap cannot occur.
`src/SIP/pie/mix_sum4_s16.S`:

```asm
mix_sum4_s16:                       # out[i] = sat16(a+b+c+d); args a2=out a3..a6=a..d a7=len
    entry   a1, 16
    srai    a7, a7, 3               # frameLen / 8  (128-bit chunks)
    loopnez a7, .Lend               # HW loop; skip if zero
    ee.vld.128.ip q0, a3, 16        # a[0..7]
    ee.vld.128.ip q1, a4, 16        # b[0..7]
    ee.vadds.s16  q0, q0, q1        # sat(a+b)
    ee.vld.128.ip q1, a5, 16        # c
    ee.vadds.s16  q0, q0, q1        # sat(a+b+c)
    ee.vld.128.ip q1, a6, 16        # d
    ee.vadds.s16  q0, q0, q1        # sat(a+b+c+d)
    ee.vst.128.ip q0, a2, 16        # store
.Lend:
    retw.n
```

- A **5-way** conference is `mix_sum4_s16(out_P, peer1, peer2, peer3, peer4, FRAME)` — done.
  Zero-frame any unused slot (one static 16-byte-aligned zero buffer).
- For **>5-way**, chain: mix one group of four into a temp, then `vadds` the next group.
  Saturating sum is a valid mix; saturation is order-dependent at the clip boundary but
  perceptually identical (this is what most production mixers do).
- **Alignment is a hard requirement:** `ee.vld/vst.128` ignore the low 4 address bits. Buffers
  must be 16-byte aligned (`MixBus.cpp` declares the tick frames `alignas(16)`) and `frameLen`
  a multiple of 8. FRAME=160 → 20 iterations, 320 B — both satisfied.
- **One function per `.S` file** (the S3 gotcha — multiple PIE functions in one file misbehave).

### 6b. Large/variable N: int32 sum-once-subtract (parity with scalar)
This matches the scalar reference bit-for-bit, but the vector body needs **int32-lane and
narrowing ops I have not personally confirmed assemble**:

> ⚠️ **VERIFY against the S3 TRM extended-instruction chapter before relying on these:**
> - widen 8×int16 → two regs of 4×int32 (sign-extend),
> - `ee.vadds.s32` / `ee.vsubs.s32` (32-bit-lane add/subtract),
> - saturating narrow int32 → int16 (`ee.srs.*`-family pack-with-saturation).
>
> A confirmed alternative for the **accumulate** is the QACC multiply-by-one trick: preload a
> ones-vector, `ee.zero.qacc`, then `ee.vmulas.s16.qacc` per port accumulates int16 values into
> QACC's 20-bit segments (TRM: "16-bit results accumulated into 16 × 20-bit segments"). 20-bit
> segments give ±524287 of headroom → safe to ~16 narrowband legs. Reading QACC back into int32
> memory for the minus-self step is the part to confirm.
>
> **Until verified, keep the scalar `mix_accumulate`/`mix_minus_self` bodies.** They are correct
> today; crib the vector envelope from esp-dsp (`dsps_add_s16_aes3.S`, `dsps_mulc_s16_ansi.c` /
> `_aes3.S`) when you commit to it. Gate the swap behind `POCKETDIAL_MIXBUS_PIE`.

### 6c. Next honest PIE target — VAD gating
When you want it to *sound* like a conference (not just be correct), gate the mix to ports
that are actually speaking. That drops the noise floor and the clip risk simultaneously, and
the per-frame energy test is **sum-of-squares** — a clean vector MAC (`ee.vmulas.s16.accx`),
which is the same kernel shape as a Goertzel/correlation detector.

---

## 7. Integration with `MediaBridge` (the diff)

**Shipped** (Issue #75). `MediaBridge` gained a BUS mode — `init()` takes an optional `MixBus*`,
and a non-null bus swaps both media callbacks at their far end. `ConferenceRoom`
(`src/SIP/ConferenceRoom.*`) owns one bus, up to `POCKETDIAL_CONF_LEGS` legs of
`{RtpReceiver, RtpSender, MediaBridge}`, and the single 20 ms tick driver; `RequestsHandler`
intercepts the virtual extension **`888`** in `onInvite()` (alongside `777`/`999`/`440`/park) and
joins the caller. The diff as it landed:

| Today (`MediaBridge`) | With the bus |
|---|---|
| RX cb: `mulawDecodeBuffer` → `_anchor->writeAudio` | RX cb: `mulawDecodeBuffer` → `bus.inputFrame(port, pcm, n)` |
| TX cb: `_playoutBuffer.read` → `ulawEncodeBuffer` | TX cb: `bus.outputFrame(port, pcm, n)` → `ulawEncodeBuffer` |
| `startBridge`: wire callbacks | `startBridge`: `port = bus.attach();` then wire |
| `stopBridge`: stop sockets | `stopBridge`: `bus.detach(port);` then stop sockets |
| `feedRx` writes the single playout buffer | BUS mode refuses it — see the caveat below |
| one mutex-guarded single bridge | N ports, one shared bus, one tick driver |

The single tick driver replaces nothing in `MediaBridge`: it is one new periodic task inside
`ConferenceRoom` (Core 0, `RtpSender`'s media priority, on device; a `std::thread` off it).
Deliberately **not** hung off the existing sender cadence — there are N senders and one bus, so
that would be N clocks racing to drain the same rings. `ConferenceRoom::tickOnce()` lets the host
suite step the clock instead of running the driver.

> **Caveat — the anchor leg is still outside the bus.** The row above is the one line of this
> sketch that did not ship as drawn. A bussed `MediaBridge` holds exactly one port, its handset
> leg; `feedRx()` returns `false` in BUS mode rather than writing into a `_playoutBuffer` the
> sender no longer reads. Giving the anchor its own port (and a pump for its return direction) is
> follow-up work. Nothing in the local conference needs it — handset legs alone are enough ports.

---

## 8. Traps (pre-flight checklist)

1. **Never saturate the running mix.** int32 accumulator, clip once at output. (§1; asserted in
   the self-test.)
2. **Lifetime/concurrency.** The `Free → Active → Draining → Free` state machine; tick is the
   sole ring-clearer. (§5.)
3. **New input-direction ring.** A 1:1 `MediaBridge` only buffers anchor→handset today; the
   mixer needs handset→bus buffered too. Same `PlayoutBuffer`, second instance per port.
4. **Alignment.** 16-byte-align every frame buffer; `frameLen % 8 == 0`. Misaligned `ee.vld.128`
   reads the wrong window silently. (§6.)
5. **Frame cadence.** Bus `FRAME` must equal the RTP ptime. Mixed ptimes (G.723.1 = 30 ms,
   G.729 = 10 ms, Opus 2.5–60 ms) need per-port repacketization before the bus — a
   correctness/jitter problem, not a compute one.
6. **Headroom vs. feel.** Naive clip is fine in practice (one or two talkers at once). Add VAD
   gating when you want conference-grade quiet. (§6c.)
7. **Vectorise last.** Scalar ships and is a rounding error at ≤8 narrowband legs. The PIE
   kernels are the easy 5%; the bus topology and master clock are the 95%.

---

## Appendix — files

```
docs/CONFERENCE_MIXER.md          this document
src/SIP/MixBus.hpp                the bus + per-port state machine
src/SIP/MixBus.cpp                attach/detach/tick (compiled, -Wall -Wextra clean)
src/SIP/mix_kernels.h             kernel signatures + POCKETDIAL_MIXBUS_PIE toggle
src/SIP/mix_kernels_scalar.cpp    correct scalar bodies (the default + fallback)
src/SIP/pie/mix_sum4_s16.S        confirmed-ISA saturating int16 sum — NOT on the live
                                  path: MixBus::tick() calls mix_accumulate/mix_minus_self
                                  unconditionally (MixBus.cpp:77,84). The only callers of
                                  mix_sum4_s16 in the tree are tests/MixBus_test.cpp:120,127
src/SIP/MediaBridge.hpp/.cpp      the transport endcap; BUS mode is §7's diff
src/SIP/ConferenceRoom.hpp/.cpp   one bus + N legs + THE single tick driver; extension 888
tests/MixBus_test.cpp             verifies minus-self, no-over-saturation, reclaim (GoogleTest)
tests/ConferenceRoom_test.cpp     the §7 wiring: N legs through the real µ-law rim, a leg
                                  leaving, the tick driver, and the 888 dial intercept
```

The self-test runs as part of the normal host suite:
```bash
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build/tests -C Release --output-on-failure --tests-regex MixBus
```
