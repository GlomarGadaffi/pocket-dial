# pocket-dial — Technical Feature Roadmap

**Status:** Living document | **Last updated:** 2026-09-13 | **Scope:** Engineering / product-capability only

This is a prioritized **engineering** roadmap for pocket-dial: what exists, what is proved,
and what is worth building next. It is grounded in the current source tree. It deliberately
stays inside the project's "fast and light" constraint — every proposal is sized against the
ESP32/ESP32-S3 reality (static memory pools, no MMU or heap compaction, a single UDP
listener, and a media path that is peer-to-peer except where it is explicitly not).

Cross-references:
[ARCHITECTURE.md](ARCHITECTURE.md) ·
[SCALING.md](SCALING.md) ·
[THREAT_MODEL.md](THREAT_MODEL.md) ·
[PROVISIONING.md](PROVISIONING.md) ·
[LEARN_MODE.md](LEARN_MODE.md) ·
[OTA.md](OTA.md) ·
[API.md](API.md) ·
[../README.md](../README.md)

> **Framing — corrected 2026-09-13.** The original framing was that pocket-dial "never
> touches RTP." That is still true of the **ordinary call**, and it is still the single
> fact that decides what is cheap and what is expensive here. It is no longer true of the
> product as a whole, and stating it as a blanket has begun to mislead.
>
> **The peer-to-peer half.** An extension-to-extension call is brokered and then gets out
> of the way: the two phones stream RTP directly to each other and the MCU never sees a
> media packet. Hold and blind/attended transfer all preserve that property — the
> SDP is relayed, and only the codec list is narrowed, never the `c=` line. **Park no
> longer does, unconditionally:** with a music-on-hold clip loaded the board answers the
> parked leg `sendonly` from its own port and streams the clip to it
> (`src/SIP/ParkOrbit.cpp:56-75`), which puts the MCU in the media path one-way for the
> duration of the park. With no clip loaded — the default — park still answers
> `a=inactive` and sources nothing, which is the behaviour this paragraph used to
> describe as unconditional. `777` echo is
> in this half too, despite an in-code comment calling it "server-terminated": it is an
> SDP loopback, answering with the caller's own body so the phone streams to itself
> (`src/SIP/RequestsHandler.cpp:1228`). Nothing on the board carries that audio.
>
> **The media-terminating half, which is now real and shipped.** `440` (tone), `555`
> (anchor bridge) and `888` (conference) put the board in the path: it sends and/or
> receives RTP for them. `888` decodes, mixes and re-encodes. An outbound trunk call
> crosses the board on **both** sides: RTP to and from the handset, chunked-HTTPS PCM16
> to and from the provider, with `MediaBridge` shuttling PCM16 between them — the board
> owns the handset-facing `RtpReceiver`/`RtpSender` pair for the life of that call
> (`src/SIP/MediaBridge.hpp:16`). These are deliberate,
> bounded, individually dialable exceptions — not a removal of the invariant for ordinary
> LAN calls.
>
> The cheap/expensive axis therefore still holds, and is now measurable rather than
> hypothetical: signalling features are bounded by the pre-allocated pools and cost a few
> hundred bytes; media features cost a leg's worth of RTP tasks and rings apiece, which is
> why the conference is capped at 4 legs and the trunk at **one** concurrent call.

---

## 1. Current capabilities (shipped, in the tree today)

### 1.1 Call control and PBX features

| Capability | Notes | Where |
|-----------|-------|-------|
| Registrar + back-to-back call broker | `REGISTER`, `INVITE`, `ACK`, `BYE`, `CANCEL`, `OPTIONS`, provisional/final responses | `src/SIP/RequestsHandler.cpp` |
| **SIP digest auth (RFC 2617)** | Implemented and operable. **The shipped default is `open`** — see §1.4. | `src/Helpers/SipDigest.*`, `src/SIP/Registrar.*` |
| Blind transfer (REFER) | Source-authorized against the dialog's own legs (#133) | `onRefer` |
| Attended transfer (REFER + Replaces, RFC 3891) | Splices B and C, BYEs A out of both, relays a later BYE across the bridge | `onRefer`, `handleTransferOk` |
| Hold / resume | Re-INVITE, relayed untouched so the SDP survives | `onReinvite`, `onOk` |
| RFC 3311 `UPDATE` | | `onUpdate` |
| RFC 4028 session timers | **Passive**: the PBX honours a timer a phone requests, but never requests one itself and never sends `422`/`Min-SE`. | `armSessionTimer` |
| Ring / hunt groups | ring-all or sequential hunt | `CallForker` |
| Call park + retrieve | orbits `700`–`709` (`POCKETDIAL_PARK_SLOTS` = 10) | `ParkOrbit.*` |
| Call pickup | group `*8`, directed `**<ext>`; pickup groups reuse ring-group membership | `CallPickup.*` |
| Paging / intercom | zones `980`–`989`, plus `999` all-page, with auto-answer header injection and race-to-answer | `startPaging`, `startBroadcastFork` |
| Call forward | CFU / CFB / CFNA, per extension | `PbxFeatureConfig` |
| Per-extension DND | | `PbxFeatureConfig` |
| BLF / presence | `SUBSCRIBE`/`NOTIFY`, **`dialog` event package only** (RFC 4235). No `presence`, no `message-summary`/MWI. | `BlfSubscriptions.cpp:132` |
| DTMF via SIP INFO + star codes | `*60`, `*72`, `*73`, `*80`, `*69`, `*11`, plus the `*PIN#code` admin menu | `DtmfFeatureCodes.cpp` |
| Bounded dial plan | ordered `pattern → group\|page\|park\|trunk`, first match wins, cap `POCKETDIAL_MAX_DIAL_RULES` = 16 | `DialPlan.hpp` |
| Inbound DID → extension | literal route-DN match, cap 8; unmapped falls back to ring-all | `DidMapping.*` |
| CDR ring + `GET /api/cdr` | in-memory, bounded, wiped by factory reset | `CdrRing.*` |
| Virtual `777` echo | SDP loopback — **no media on the board** | `RequestsHandler.cpp:1209` |

### 1.2 Media — the part the board actually carries

| Capability | Notes | Where |
|-----------|-------|-------|
| `440` server-sourced tone | board **sends** RTP; `sendonly` SDP | `onMediaInvite` |
| **Music on hold (park only)** | board **sends** RTP. One global clip cursor fanned to every parked leg — the 20 ms tick reads 160 bytes once and `sendto`s the identical payload per listener, so there is no per-leg decode and no `MixBus`. G.711 µ-law 8 kHz mono only (the wire format itself; playback is a memcpy). The clip is read off the SD card into PSRAM **once at load** and the card is then out of the media path entirely. Cap `POCKETDIAL_PARK_SLOTS` listeners. **Falls back to the old silent `a=inactive` hold** when there is no clip, no usable RTP endpoint in the parked party's SDP, or MoH is not running — park never fails because nobody uploaded a WAV. Does **not** apply to phone-initiated hold. | `HoldMusic.*`, `ParkOrbit.cpp:56-75` |
| `888` meet-me conference | board decodes, mixes (`MixBus`, N−1 minus-self summing) and re-encodes. **`POCKETDIAL_CONF_LEGS` = 4**, one global room, **no PIN**, created on first dial-in and then kept alive. | `ConferenceRoom.*`, `MixBus.*` |
| `555` anchor media bridge | board bridges a leg to an `AnchorClient`. **Active on default firmware** via the `Loopback` reference client. | `onAnchorInvite`, `MediaBridge.*` |
| Codec policy | **Relayed peer-to-peer legs admit PCMU, PCMA _and G.722_** (`filterAudioCodecs(allowWideband=true)`). Legs the board terminates itself refuse G.722, and the board's own SDP offers PCMU only. | `SipMessage.cpp:405`, `buildMediaSdp` |
| `enforceG711()` | **Deprecated — zero production callers.** It pinned `m=` to a literal `0 8 101`, inventing PT 101 with no `a=rtpmap`, which pjsip rejects outright. Any "this PBX is G.711-only" statement is stale. | `SipMessage.cpp:260` |
| SDP admission gate | every SDP-bearing message structurally checked before any decoder sees it; capability-negotiation attributes refused (T-7 / the UNISOC T612 RCE class) | `SipMessage::checkSdp` |

### 1.3 Outbound trunking

Outbound calls leave over an **`AnchorClient`**: HTTP/OAuth2, a call-control WebSocket, and
media as chunked-HTTPS PCM16. The shipping real client speaks the **3CX Call Control API**.

Four things follow from that, and each one surprises someone:

- **It is not a SIP trunk.** Nothing in the tree ever *sends* a `REGISTER`, so the box never
  registers to an ITSP and speaks no SIP to a carrier at all.
- **A dial-plan rule with `action=trunk` is the only way out.** No hardcoded `9` prefix, no
  unregistered-destination fallback: with an empty dial plan every outside number is
  answered `404` without leaving the box.
- **`POCKETDIAL_MAX_ANCHOR_CALLS` is 1.** One concurrent outside call.
- **No E.164 normalization exists anywhere.** A rule's strip/prepend is the whole of the
  number transformation.

Credentials live in four slots (`TelephonyApiConfig::kSlots`), one active at a time, edited
through `/api/telephony-config` — see [API.md](API.md).

### 1.4 Security posture

| Control | State |
|---------|-------|
| **Admin login** | **Username + password** (`AdminAuth`), salted/iterated SHA-256, server-side sessions, per-session CSRF token on every mutating route, per-client + aggregate brute-force lockout. Ships as `admin`/`admin` with **forced first-use setup** — every admin route except `set-credential` answers `403 setup_required` until it is replaced. |
| **DTMF admin PIN** | A *separate*, independent numeric secret for the phone-keypad `*PIN#code` menu. **No default**, so that menu is disabled until explicitly configured. Unrelated to the web session. |
| **HTTP reachability** | **The dashboard is always reachable.** The listener opens at construction and stays open. The dark-by-default plane and the `*4887` reopen star-code were **removed** (`de1a36e`); `grantAdminHttpGraceWindow` no longer exists. |
| **Registrar admission** | Three modes — `open` / `learn` / `secure`. Digest auth is real; Learn is TOFU + an ARP-learned MAC lock. **The shipped default is `open`: a fresh board accepts any REGISTER and any INVITE until an operator changes `reg_mode`.** Both halves of that sentence matter. |
| **SoftAP WPA2** | Implemented, **opt-in, default off** (NVS `ap_secure`) so a firmware update never re-pairs a live fleet. Encrypts dashboard, SIP and RTP together. |
| Signalling hardening | per-source-IP token bucket, optional CIDR allowlist, AOR whitelist, bounded parser, SDP admission gate |
| HTTP hardening | same-origin + CSRF, 16 KB body cap, `SO_RCVTIMEO`, no wildcard CORS, central security response headers (CSP, `X-Frame-Options: DENY`, `nosniff`, `no-store`), deliberately no HSTS |
| OTA | dual-slot `ota_0`/`ota_1`, streaming upload, mark-valid-on-healthy-boot rollback. **Unsigned**, admin-gated. |

### 1.5 Platform

Core-pinned tasks (SIP vs HTTP/LVGL); outbox pattern keeping socket syscalls outside the
lock; double-buffered lock-free status snapshot; zero-heap-alloc hot path. Compile-time
pools: `MAX_CLIENTS` 32, `MAX_SESSIONS` 8, `MAX_DIAL_RULES` 16, `MAX_DID_MAPPINGS` 8,
`CONF_LEGS` 4, `MAX_ANCHOR_CALLS` 1, with graceful `503` on exhaustion.
Transports: Wi-Fi SoftAP with captive portal, W5500 / LAN8720 wired Ethernet and PoE,
Guition JC3248W535 touch display (LVGL 8.3). Zero-touch provisioning
(`GET /config/<mac>.cfg`, Yealink key format). Flash-time configuration via the `cfgseed`
partition and the browser flasher. Live SIP tracer (`/api/trace`) and Wireshark-readable
capture (`/api/pcap`). Prometheus-style `GET /metrics`. Dashboard with patch-bay UI and
toolbar modals for dial plan (`F2`), ring groups & forwarding (`F3`), call log (`F4`),
refresh (`F5`), **PBX Settings (`F6`** — hold-music upload, preview and stop**)**, SIP
trace (`F8`) and Wi-Fi (`F9`) (`src/Helpers/index_html.h:330-336`, `:1706-1712`).

---

## 2. What is actually *proved* — read this before trusting §1

§1 is "in the tree and works in test". This section is what has been observed on real
hardware, and it is deliberately short.

| Claim | Evidence |
|-------|----------|
| A real handset registers and calls out | **A Yealink T29 is registered to the bench board and outbound PSTN is verified end to end**: one call rang through to carrier voicemail (answered at 21.2 s) and one was answered by a person, **with two-way audio**. This is the **first real-handset evidence in the project.** |
| Everything else | Host-only — gtest, or `pjsua`/SIPp driven against the **desktop** binary over loopback. |
| On-device RTP | **Never exercised by any test.** The host build's `RtpSender`/`RtpReceiver` are stubs (a Linux-desktop socket path aside), so every green media test exercises a stub, not the ESP32 path. |
| OTA | **Never executed anywhere**, on any board, in any release. |
| Zero-touch provisioning | Implemented, but **inert on a default board**: `GET /config/<mac>.cfg` only serves a MAC in the Learn-mode adopted-device registry, and `open` mode never records one — so on a fresh board it is a structural 404 for every MAC. The Yealink key set has never been confirmed against a physical handset. |

**This table is the roadmap's most load-bearing content.** The highest-value work in the
project right now is not a new feature; it is moving rows out of the bottom half of this
table. See §6.

---

## 3. Open backlog (grouped, prioritized)

Priority key — **P0** = build next (highest leverage or unblocks others); **P1** = soon,
clear value, moderate effort; **P2** = strategic / higher effort / depends on a P0–P1.
Complexity is a t-shirt size for *signalling-side* work unless noted.

Everything the previous revision of this document listed as proposed telephony work —
blind transfer, attended transfer, hold/resume, DND, the dial plan, park, BLF, paging
zones, pickup — **has shipped** and now lives in §1. What remains is below.

### 3.1 Telephony

| Pri | Feature | Rationale | Complexity | Constraints |
|-----|---------|-----------|------------|-------------|
| **P1** | **E.164 normalization** | There is none anywhere. A trunk rule's strip/prepend is the entire number transformation, which works for one national dial habit and breaks on the next. | **S–M** | A bounded normalization table, not a regex engine. Pairs with DID matching, which is also literal-string today. |
| **P1** | **Session timers, active side** | The PBX honours a phone's `Session-Expires` but never requests one and never answers `422`/`Min-SE`. A phone that dies mid-call therefore leaves the session to the orphan sweep rather than a refresh failure. | **M** | Pure signalling; the passive half already parses `refresher=`. |
| **P2** | **Trunk failover / a second concurrent outside call** | `MAX_ANCHOR_CALLS` is 1 and there is no failover between configured slots. Raising it is a media-cost decision, not a signalling one. | **M (media)** | Each extra anchor leg costs an RTP task pair + rings, the same as a conference leg. Measure before raising. |
| **P2** | **Conference rooms with PINs** | One global room, no PIN, cap 4. Multiple rooms means a room table and per-room `MixBus` instances. | **M–L (media)** | Memory-bound: the rings are ~50 KB per room. |
| **P2** | **MWI / `message-summary`** | The BLF machinery only implements the `dialog` event package. MWI is cheap *given* a voicemail store — and there isn't one (§5). | **S** | Meaningless without an external voicemail endpoint to subscribe to. |
| **P2** | **100rel / PRACK** | Not implemented. Matters only for interop with a UAS that requires it. | **M** | No known handset in the bench set needs it. |

### 3.2 Platform / reliability

| Pri | Feature | Rationale | Complexity | Notes |
|-----|---------|-----------|------------|-------|
| **P0** | **Config import / export (backup / restore)** | Still the strongest platform item, and now overdue: the config surface has grown to dial plan, DID map, groups, forwards, DND, registrar roster, telephony slots and Wi-Fi. Rebuilding that by hand on a replacement unit is the realistic failure the project has no answer for. | **M** | Admin-gated `GET /api/config/export` + `POST /api/config/import`. **Never export the telephony secrets in clear** — the whole API is built around `secretSet`, not `secret`. |
| **P1** | **Watchdog / health & self-heal** | No project task subscribes to a watchdog and nothing in `sdkconfig.defaults` configures one, so a wedged SIP or HTTP task is not detected or recovered. Task-level WDT plus heap/stack high-water reporting protects the RT guarantees in [ARCHITECTURE.md](ARCHITECTURE.md) §2 and feeds the OTA `mark-valid` health gate. | **S–M** | IDF Task WDT; surface on `/api/status`. |
| ~~P1~~ **DONE** | **Metrics endpoint** | **Shipped.** `GET /metrics` serves six Prometheus text-format families, all `pocketdial_`-prefixed: `uptime_seconds`, `sip_registrations_active`, `sip_calls_active`, `packets_processed_total`, `packets_dropped_total`, `sdp_rejected_total`. Reads only the relaxed atomics and the snapshot-mutex counts — it never touches `RequestsHandler::_mutex`, which is why `getConferenceLegs()` is deliberately *not* exported. **Ungated**, argued in-place: a stock scraper cannot drive the login/CSRF handshake. | — | `HttpServer.cpp:475`, `sendApiMetrics` at `:1185`; rationale at `:1124-1183`. Listed in [THREAT_MODEL.md](THREAT_MODEL.md) §4 E-2's unauthenticated-read class. |
| **P1** | **Syslog (RFC 5424 over UDP)** — *module written, not wired* | `_logQueue` already buffers under lock and flushes outside it; tee it for fleets with no serial console. **Careful: `src/Helpers/Syslog.{hpp,cpp}` already exists** — a complete, host-unit-tested RFC 5424 frame formatter, compiled into both the firmware (`main/CMakeLists.txt:112`) and the host build. What does *not* exist is any way to reach it: `Syslog.hpp` is included by nothing but its own `.cpp` and `tests/Syslog_test.cpp`, there is no call site on the log drain, no HTTP route and no NVS key for a destination. **It is compiled dead code today — do not report syslog as a shipped feature.** The remaining work is wiring and a config surface, not the protocol. | **S** | One UDP socket, bounded queue, drop-on-full — never block the RT path. |
| **P2** | **NVS schema versioning / migration** | Config keys have accreted across several releases with no `schema_ver`. Pairs with config export. | **M** | Retrofitting this after an export format exists is the expensive order. |
| **P2** | **Multi-AP / mesh / roaming** | Extends coverage past one SoftAP's ~16-station ceiling. Large, and it changes the trust boundary. | **L** | Keep one logical registrar; clients re-REGISTER on roam. |

### 3.3 Security (cross-ref [THREAT_MODEL.md](THREAT_MODEL.md))

| Pri | Item | State / rationale | Complexity |
|-----|------|-------------------|------------|
| **P0** | **Flip the registrar default, or make flipping it unmissable** | Digest auth, Learn mode and the MAC lock are all built — and the shipped default is `open`, so most boards run with none of it. The remaining work is a decision and an onboarding flow, not a protocol. Cheapest real security win available. | **S–M** |
| ~~P0~~ **DONE** | WPA2 on the SoftAP | Shipped, opt-in, default off (NVS `ap_secure`). Encrypts dashboard, SIP *and* RTP in one change. | — |
| ~~P0~~ **DONE** | SIP digest auth (RFC 2617) | Shipped and operable via `/api/registrar` + the `cfgseed` `regMode` field. See the P0 above for what is left. | — |
| ~~P1~~ **DONE** | Per-IP brute-force tracking on login | Shipped, with an aggregate backstop so a spoofed-source attacker cannot buy a fresh escalation ladder per identity. | — |
| **P1** | **Sign the OTA image** | Images are unsigned; the only controls are the admin session and the local link. | **S** (interim gate) / **L** (real signing) |
| **P2** | **Secure Boot v2 + flash encryption + signed OTA** | Durable fix for the physical/supply-chain boundary; encrypts NVS at rest (Wi-Fi password, admin hash, **carrier API secrets** — which now exist and did not when this row was written). One-way eFuse burn, so it needs a secured factory flow. | **L** |
| **P2** | **Optional self-signed HTTPS for the dashboard** | Still not the primary control. Browser-warning UX is bad on a LAN appliance, TLS costs MCU RAM/CPU, and it protects only the dashboard. Documented add-on **on top of** WPA2. | **M** |
| **P2** | **SRTP** | App-layer media encryption. WPA2 already encrypts media at the link layer for far less. Low priority given how little media the board carries. | **L** |

### 3.4 Developer / ops experience

| Pri | Item | Rationale | Complexity |
|-----|------|-----------|------------|
| **P0** | **Exercise the untested paths on hardware** | Per §2: on-device RTP, OTA, and a provisioning fetch by a real handset have never been run. Each is a bench session, not a feature. Doing them is how §1's claims stop being claims. | **S–M** (test) |
| **P1** | **Provisioning dashboard editor** | MAC→ext map, adoption window, capacity meter against `MAX_CLIENTS`, per-MAC token regen. The registrar roster is already surfaced; this is the editing half. | **M** |
| **P1** | **Confirm the Yealink key set against a handset** | The `.cfg` renderer has never been validated by a phone consuming it. A T29 is now on the bench, so this is finally testable. | **S** (test) |
| **P2** | **DHCP Option 66 true zero-touch** | Removes the typed URL. Requires forking the bundled `dhcpserver`; IDF-version-sensitive. | **M–L** |
| **P2** | **Multi-vendor provisioning** (Grandstream / Polycom / Cisco) | Mostly static format strings (~2–4 KB `.text`). Worth doing only after the Yealink renderer is confirmed. | **M** |
| ~~P1~~ **DONE** | Live SIP tracer + PCAP export | Shipped: `/api/trace`, `/api/pcap`, `/api/diagnostics/pcap`, and a trace terminal in the dashboard. | — |
| ~~P1~~ **DONE** | Zero-touch provisioning MVP | Shipped — with the Open-mode caveat in §2. | — |

---

## 4. Suggested sequencing

```
Iteration A  ── Make the claims true (highest leverage, lowest novelty)
  P0  Bench-verify on-device RTP, OTA, and a real provisioning fetch .... §2's bottom half
  P1  Confirm the Yealink .cfg against the T29 now on the bench
      └─ These are test sessions. They gate how much of §1 anyone should trust.

Iteration B  ── Close the default-posture gap
  P0  Registrar default: flip it, or make choosing it unmissable at setup
  P1  Sign the OTA image (or, interim, keep it gated and say so loudly)
      └─ Digest auth already exists. This is onboarding, not cryptography.

Iteration C  ── Ops primitives the config surface has outgrown
  P0  Config import/export ......... dial plan, DID map, groups, telephony slots, Wi-Fi
  P2  NVS schema versioning ........ design in with the export format, not after it
  P1  Watchdog/health, /metrics, syslog ... all ride existing snapshot + log queue

Iteration D  ── Dialling that survives contact with the real world
  P1  E.164 normalization .......... trunk strip/prepend is not a dial plan
  P1  Session timers, active side
  P2  Trunk failover / a second anchor leg (measure the media cost first)

Iteration E+ ── Bigger bets
  P2  Provisioning dashboard editor · DHCP Opt-66 · multi-vendor renderers
  P2  Secure Boot v2 + flash encryption + signed OTA
  P2  Multi-AP/mesh · optional HTTPS · SRTP · conference rooms with PINs
```

**Why this order:**

- **Verification first** because the project just crossed from "tested" to "tested and, in
  one narrow path, *true*". The gap between those two words is now the largest risk in the
  codebase, and closing it costs bench time rather than design.
- **The registrar default before any new hardening** because the expensive part (digest
  auth, Learn mode, the MAC lock) is already built and most boards are not using it. There
  is no cheaper security work available than making an existing control the default.
- **Config export before the config surface grows again.** It was the strongest platform
  item when there was a dial plan to back up; there are now seven tables, plus carrier
  credentials that must never leave the box in clear.
- **E.164 after trunking, not with it.** Trunking works today for one dial habit. Making it
  general is a real feature and deserves its own slice rather than being smuggled into the
  strip/prepend rule.
- **Observability rides existing infrastructure** (snapshot, `_logQueue`, atomic counters),
  so it adds no new locking on the RT path — which is exactly why it stays cheap and stays
  P1 rather than P0.

---

## 5. Explicitly out of scope / non-goals

Ruled out *for technical reasons* — they conflict with the static-pool, minimal-DSP
architecture — or, in a couple of cases, simply absent and not planned.

| Non-goal | Why |
|----------|-----|
| **Voicemail (on-device record/playback)** | Media must traverse, be stored and be transcoded on the device, and flash is not a message store. Scope only as routing to an external SIP voicemail UA. Absent today. |
| **IVR / auto-attendant, music-on-hold, call recording, call queues/ACD** | All of them require the board to hold and source media for the duration of a call, at a scale the deliberate 4-leg conference cap already shows is the ceiling. Absent, and not planned on-MCU. |
| **On-MCU transcoding** | No DSP budget. The engine narrows the codec list and lets the endpoints agree; it does not translate between them. |
| **Time-based routing, follow-me, speed dial, blacklists, barge/whisper/monitor** | Absent. Each is cheap signalling work in isolation; none is built, and the dial plan is deliberately a 16-rule table rather than a rules engine. |
| **CDR export / billing** | The CDR is a bounded in-memory ring read over `GET /api/cdr`. There is no export, no persistence guarantee across a wipe, and no billing model. |
| **Fax / T.38, video** | Absent. T.38 would need a media path with timing guarantees this board does not offer. |
| **Multi-tenancy** | One registrar, one flat extension space, one conference room. Not a gap — a scope boundary. |
| **Special 911 / emergency handling** | **There is none.** A dialled emergency number is an ordinary dial-plan match with no special routing, no location, and no priority over the single outbound anchor slot. Do not deploy this as anyone's only means of calling for help. |
| **TLS/SIPS signalling and SRTP as primary transport security** | On a LAN appliance, self-signed certs trigger browser warnings, cost MCU RAM/CPU, and protect only one leg. WPA2 encrypts dashboard, SIP and RTP together for far less. HTTPS/SRTP remain documented *optional* add-ons (§3.3). |
| **WebRTC NAT traversal (ICE/TURN); TURN relay on-MCU** | Peer-mesh/WebRTC tools, and a TURN *server* would put N relayed media streams on the MCU. |
| **Cloud control plane / remote management** | The device is intentionally self-contained. Note the asymmetry: the *outbound* path deliberately depends on a vendor API, but nothing reaches *in*. |
| **Unbounded dynamic allocation for "scale"** | Capacity is set by static pools by design; "scale up" means picking a tier or a wired board, not removing the pre-allocation that guarantees a fragmentation-free hot path. |
| **DHCP Option 43 multi-vendor provisioning** | Brittle per-vendor TLV encoding; rejected in favour of an Option-66 `dhcpserver` fork. |

> **Removed from this section (2026-06-09 → 2026-09-13):** "on-MCU media mixing /
> conferencing wired into live calls" was listed here as a non-goal *while `MixBus` was
> simultaneously described in §1 as wired up and dialable as `888`*. The §1 description was
> the correct one. On-MCU mixing is shipped, capped at 4 legs, and is an opt-in exception to
> the peer-to-peer default rather than a violation of it. Likewise "wideband / G.722
> negotiation" was listed as a non-goal; relayed peer-to-peer legs **do** admit G.722 today,
> and only the legs the board terminates itself refuse it.

---

## 6. Top 3 recommendations (next-up)

1. **Bench-verify the untested paths** — on-device RTP, an OTA cycle, and a real handset
   fetching its own `.cfg`. The project just produced its first genuine end-to-end evidence
   (a person answered a call, with audio, over a real carrier). Everything else in §1 is
   still host-test confidence, and three bench sessions would convert most of it.
2. **Resolve the registrar default.** Digest auth, Learn mode and the MAC lock are built and
   reachable; the shipped default is `open`, so a fresh board accepts any REGISTER and any
   INVITE. Either change the default or make choosing it an unmissable step of setup — this
   is the cheapest real security improvement left, because the hard half is already done.
3. **Config import/export.** Seven config tables and a set of carrier credentials now live
   in NVS with no supported way to back them up or move them to a replacement unit. Export
   must redact the telephony secrets, which the API's `secretSet`-not-`secret` contract
   already makes natural.

(E.164 normalization is the strongest *telephony* item and the natural fourth: trunking
works today for exactly one dial habit.)
