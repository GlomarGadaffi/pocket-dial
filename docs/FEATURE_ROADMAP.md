# pocket-dial — Technical Feature Roadmap

**Status:** Living document | **Last updated:** 2026-06-09 | **Scope:** Engineering / product-capability only

This is a prioritized **engineering** roadmap for pocket-dial: what exists, what is
landing now, and what is worth building next. It is grounded in the current source tree
and the existing design docs. It deliberately stays inside the project's "fast and light"
constraint — every proposal is sized against the ESP32/ESP32-S3 reality (static memory
pools, no MMU/heap-compaction, peer-to-peer RTP, a single UDP listener).

Cross-references:
[ARCHITECTURE.md](ARCHITECTURE.md) ·
[SCALING.md](SCALING.md) ·
[THREAT_MODEL.md](THREAT_MODEL.md) ·
[PROVISIONING.md](PROVISIONING.md) ·
[OTA.md](OTA.md) ·
[../README.md](../README.md)

> **Framing.** pocket-dial's default call path is a *signalling-only* SIP registrar/proxy: it
> brokers call setup and never touches RTP audio (media is peer-to-peer — see
> [SCALING.md](SCALING.md) §1). That single architectural fact decides what is cheap (anything
> signalling-side, bounded by the pre-allocated pools) and what is expensive (anything that would
> put the MCU in the media path). Every priority below is assigned with that line drawn. An
> **opt-in** exception exists: `AnchorClient`/`MediaBridge`/`TelephonyProvider` (`src/SIP/`) are a
> vendor-neutral extension point for bridging a call to an external audio system, wired into call
> routing as virtual extension `555` against the `Loopback` reference client pocket-dial ships
> (see `src/SIP/TelephonyProvider.hpp`'s class comment for why no real vendor client ships in
> this tree). `MixBus`
> (`src/SIP/MixBus.*`) is a tested N-way mixer, wired as the `888` meet-me conference. Neither
> changes the framing above for the default path — a plain call never puts the MCU in the media
> path; both are there for a fork (or an operator dialing `555`/`888`) that wants to cross that
> line deliberately, on its own terms.

---

## 1. Current capabilities (shipped, in the tree today)

| Area | Capability | Where |
|------|-----------|-------|
| SIP signalling | RFC 3261 registrar + back-to-back call broker: `REGISTER`, `INVITE`, `ACK`, `BYE`, `CANCEL`, `OPTIONS`, and provisional/final responses (`100/180/200/404/480/486/487`) | `src/SIP/RequestsHandler.cpp`, README "Supported SIP Methods" |
| Media | Peer-to-peer G.711 RTP; server never sees audio. `enforceG711()` rewrites SDP to `0 8 101`; `clearBody()` strips ringing SDP for strict-UA interop (Yealink) | `src/SIP/SipMessage.cpp`, README "VoIP Interoperability" |
| Virtual extensions | `777` zero-DSP echo loopback; `999` parallel all-page/intercom with auto-answer header injection, Request-URI/To rewrite, race-to-answer + CANCEL of losers; `440` server-sourced RTP tone; `888` local N-way conference (server-mixed); `555` anchor media bridge (opt-in, bridges to whichever `AnchorClient` the provider registry selected — `Loopback` by default) | `RequestsHandler::startPaging` / `handlePagingAnswer` / `onMediaInvite` / `onConferenceInvite` / `onAnchorInvite` |
| Registration lease | Expiry parsing/capping (`DEFAULT/MAX_EXPIRES` 3600 s), OPTIONS keepalive ping, dead-binding sweep/prune | `parseRequestedExpires`, `sweepExpired`, `maybeSweep` |
| Transports | Wi-Fi SoftAP (+ captive portal), W5500 / LAN8720 wired Ethernet & PoE, Guition JC3248W535 touch display (LVGL 8.3) | `main/esp_main*.cpp`, `main/drivers`, `main/ui` |
| Onboarding | Captive-portal SoftAP, hand-rolled DNS redirect, on-screen join QR, NVS-persisted Wi-Fi mode/SSID/creds | `main/wifi/DnsServer.cpp`, `esp_main_display.cpp` |
| Web dashboard | Select-based, thread-dispatched `HttpServer`; lock-free snapshot status API; mDNS (`pocketdial.local`, `_sip._udp`, `_http._tcp`) | `ARCHITECTURE.md` §4, `src/Helpers/HttpServer.*` |
| Concurrency / RT safety | Core-pinned tasks (SIP vs HTTP/LVGL), outbox pattern (socket syscalls outside lock), double-buffered snapshot, **zero-heap-alloc hot path** | `ARCHITECTURE.md` §2–3 |
| Capacity model | Compile-time pools `POCKETDIAL_MAX_CLIENTS/MAX_SESSIONS/MSG_POOL`; graceful `503` on exhaustion; Pocket/Office/Rack tiers | `src/SIP/PoolConfig.hpp`, [SCALING.md](SCALING.md) |
| Security (signalling) | Per-source-IP token-bucket rate limit, optional CIDR allowlist, AOR input whitelist, bounded parser (header/body boundary) | `allowPacket`, `ipAllowed`, `isValidAor`, `findHeader` |
| Security (HTTP) | Same-origin/CSRF check, 16 KB body cap, `SO_RCVTIMEO`, no wildcard CORS | `ARCHITECTURE.md` §5 |
| Dev / debug | Desktop (Linux/Windows) host build & CI smoke harness; SIP load tester + liveness/HTTP smoke scripts | `main.cpp`, `tests/load/sip_stress.py`, `.smoke/`, `tests/http/test_api.sh` |
| **Admin plane, dark by default** | HTTP is the only admin surface (SSH "sysop terminal" — wolfSSH + the ANSI/TUI hub — **removed**, not hardened). Unreachable on a provisioned device except for a bounded TTL after a source-IP-verified DTMF trigger or a fresh provisioning grace window. Ring groups, call-forward, and DND remain configurable — now over the web dashboard only. | `src/Helpers/HttpServer.*`, `src/SIP/RequestsHandler::onDtmfInfo`, [THREAT_MODEL.md](THREAT_MODEL.md) §5.5. `docs/design/` (TUI design docs) is now historical — describes the removed SSH surface, not current behavior. |
| **PBX call features** | CDR ring, per-extension **DND**, **call-forward** (CFU/CFB/CFNA), **ring groups** (ring-all / hunt), **blind transfer** (REFER), **hold/resume** (re-INVITE + RFC 3311 UPDATE), **session timers** (RFC 4028), **call parking** (orbits `700`-`709`), **paging zones** (`980`-`989`), **BLF/presence** (`SUBSCRIBE`/`NOTIFY`, RFC 4235), DTMF star-codes (`*60/*80/*72/*73/*69/*11`) | `src/SIP/RequestsHandler.cpp`, `CallDetailRecord.hpp`, `PbxConfig.hpp` |
| **Server-mixed conference** | `MixBus` (N−1 minus-self summing junction, int32 accumulator clipped once) wired into `MediaBridge`'s BUS mode and dialable as extension `888`. `ConferenceRoom` owns one bus, `POCKETDIAL_CONF_LEGS` legs, and the single 20 ms mix tick. No anchor/vendor required. | `src/SIP/ConferenceRoom.*`, `src/SIP/MixBus.*`, [CONFERENCE_MIXER.md](CONFERENCE_MIXER.md) |
| **Anchored media (opt-in)** | `AnchorClient`/`MediaBridge`/`TelephonyProvider`/`TelephonyApiConfig` — vendor-neutral building blocks for bridging a call to an external audio system, wired into call routing as virtual extension `555` (`RequestsHandler::onAnchorInvite`). pocket-dial ships only the `Loopback` reference `AnchorClient` — proving the wiring, not real PSTN/vendor connectivity; see `TelephonyProvider.hpp`'s class comment for why no vendor-specific client ships here. | `src/SIP/MediaBridge.*`, `src/SIP/TelephonyProvider.*`, `src/SIP/RequestsHandler.cpp` |

---

## 2. In progress / just-added (Phase 1 + Phase 2)

| Phase | Item | State | Reference |
|-------|------|-------|-----------|
| 1 | **Static memory pools** wired to compile-time macros; per-tier sizing & graceful `503` | Shipped / documented | [SCALING.md](SCALING.md), `PoolConfig.hpp` |
| 1 | **Admin auth** — PIN + salted-iterated SHA-256 (50k rounds), server-side session, lockout, mutating-endpoint gate | Shipped (closes audit SEC-04) | [THREAT_MODEL.md](THREAT_MODEL.md) §S-1/E-1 |
| 1 | **OTA** — dual-slot `ota_0/ota_1`, streaming `/api/ota/upload`, `mark-valid-on-healthy-boot` rollback | Shipped (unsigned; admin-gated) | [OTA.md](OTA.md) |
| 2 | **Dashboard auth + OTA UI** (login, OTA upload/reboot surfaced in CGA UI) | Landing | README, OTA.md §3 |
| 2 | **Operator docs** (scaling tiers, threat model, OTA runbook, provisioning spec) | Landing | this doc's cross-refs |
| 2 | **Zero-touch provisioning** — manual-URL Yealink `.cfg` MVP design (NVS `prov` map, per-MAC token, provisioning window) | Design complete, build-ready, **no code merged** | [PROVISIONING.md](PROVISIONING.md) |
| 2 | **RTP design exploration** | Open question — see Non-Goals §6; media-in-path features remain explicitly out of the fast-path mandate | [SCALING.md](SCALING.md) §1 |

> **Update (2026-06-09):** several items previously listed as *proposed* below have since
> shipped and now appear in §1 — CDR ring, per-extension DND, call-forward (CFU/CFB/CFNA),
> ring/hunt groups, and blind transfer (REFER) — originally surfaced in the SSH "sysop
> terminal" (since removed, 2026-07-15 — see §1's "Admin plane, dark by default" row; these
> features are unaffected and remain reachable via the web dashboard).
> Treat their backlog rows in §3.1 as **done** unless a sub-point says otherwise.

> **Known cross-cutting hazard (flagged in [PROVISIONING.md](PROVISIONING.md) §3.3):** SIP
> auth (P0 below) depends on the per-MAC secret store provisioning writes, and provisioning
> credentials only become load-bearing once SIP digest auth verifies them. Sequence them
> together.

---

## 3. Proposed feature backlog (grouped, prioritized)

Priority key — **P0** = build next (highest leverage or unblocks others); **P1** = soon,
clear value, moderate effort; **P2** = strategic / higher effort / depends on a P0–P1.
Complexity is a t-shirt size for *signalling-side* work unless noted.

### 3.1 Telephony features

| Pri | Feature | Rationale (technical) | Complexity | Notes / constraints |
|-----|---------|----------------------|------------|---------------------|
| **P0** | **Blind transfer (REFER / `302`)** | Highest-value missing call-control primitive; pure signalling (server reissues INVITE to Refer-To target). No media path. Built on the existing session state machine. | **M** | Implement `onRefer`; validate Refer-To as an AOR (reuse `isValidAor`); generate `202 Accepted` + NOTIFY (`sipfrag`). RFC 5589/3515. |
| **P1** | **Call hold / resume** | Re-INVITE with `a=sendonly`/`inactive` SDP. Server just relays the re-INVITE/200; phones renegotiate P2P. Cheap, expected by users. | **S** | Mostly passthrough; ensure `enforceG711()`/`clearBody()` don't corrupt hold SDP. Add a `Session::State::HELD`. |
| **P1** | **Attended (consultative) transfer** | Natural follow-on to blind transfer; uses REFER with Replaces. Still media-free server-side. | **M** | Needs dialog/`Replaces` correlation in the session map; depends on P0 REFER landing first. |
| **P1** | **Per-extension Do-Not-Disturb (DND)** | Small per-`SipClient` flag; `onInvite` short-circuits to `486 Busy Here`. Toggle via dashboard / star-code. Bounded, no new pool. | **S** | One bool on `SipClient`; persist optionally in NVS. Honour existing AOR/virtual-ext reservations. |
| **P1** | **Static dial plan / routing table** | Today routing is "exact AOR match + reserved 777/999." A small compile-time/NVS map enables hunt groups, ring-all aliases, simple prefixes. | **M** | Keep it a bounded lookup table (mirror pool discipline); resolve to existing INVITE path. Reuse the `999` forking engine for ring-groups. |
| **P1** | **Call parking / park-orbit** | Reuses the session machinery: park = move a leg to a virtual "orbit" slot (e.g. `700x`), retrieve = INVITE the orbit. No media held by server. | **M** | Costs one session slot per parked call — document against `MAX_SESSIONS`. |
| **P2** | **BLF / presence (`SUBSCRIBE`/`NOTIFY`, dialog-info)** | Lets desk-phone busy-lamp keys reflect extension state. Server already tracks registration + session state — this exposes it over SIP events. | **L** | New subscription table (bounded pool!) + NOTIFY fan-out; watch message-pool pressure like the `999` page. Pairs well with provisioning (BLF keys are provisionable). |
| **P2** | **Paging zones (multi-zone `999`)** | Generalize the single all-page into named zones (e.g. `981`=floor-1). Extends the proven forking path with a zone→members map. | **M** | Bounded zone table; reuses `startPaging`. Per-zone member cap to bound transient message-pool use. |
| **P2** | **Voicemail** | **Requires media in the path** (record/playback RTP) — breaks the zero-DSP, P2P-media invariant. Only viable as an *external* SIP voicemail UA the box routes to, never on-MCU. | **XL** | Scope as "route to an external VM endpoint," not on-device storage/codec. See Non-Goals §6. |
| **P2** | **Conferencing (mixing)** | True N-way mixing needs an RTP mixer (DSP + media bandwidth) the MCU does not have. | **XL (off-device)** | Only as a relay to an external mixer; on-MCU mixing is a non-goal (§6). |

### 3.2 Platform / reliability

| Pri | Feature | Rationale (technical) | Complexity | Notes |
|-----|---------|----------------------|------------|-------|
| **P0** | **Config import/export (backup/restore)** | Single most-requested ops primitive once admin-auth + provisioning exist: snapshot Wi-Fi mode, dial plan, provisioning map (secrets redacted/encrypted) to a JSON blob; restore on a replacement unit. De-risks every other config feature. | **M** | Admin-gated `GET /api/config/export` + `POST /api/config/import`; reuse same-origin + session gate; never export raw secrets unless flash-encrypted. |
| **P1** | **Watchdog / health & self-heal** | Task-level watchdog + heap/stack high-water reporting; auto-recover a wedged task. Directly protects the RT guarantees in [ARCHITECTURE.md](ARCHITECTURE.md) §2. | **S–M** | Use IDF Task WDT; surface health on `/api/status`; ties into OTA `mark-valid` health gate. |
| **P1** | **Metrics endpoint (Prometheus-style text / SNMP-ish)** | Already counting `packetsProcessed/Dropped`, client/session counts, pool headroom. Expose them in a scrape-friendly format for monitoring/alerting. | **S** | Read-only `/metrics`; reuse the lock-free snapshot — no new locking. |
| **P1** | **Syslog (RFC 5424 over UDP)** | The `_logQueue` already buffers logs under lock and flushes outside it; tee it to a remote syslog collector for fleets without a serial console. | **S** | One UDP socket; bounded queue; drop-on-full (never block the RT path). |
| **P2** | **Multi-AP / mesh / roaming** | Extends coverage beyond one SoftAP's ~16-station cap (the real Pocket-tier ceiling, [SCALING.md](SCALING.md) §5). Significant networking work; clients re-REGISTER on roam. | **L** | Likely ESP-NOW/ESP-WIFI-MESH or a wired-backbone-of-APs model; keep one logical registrar. Honest: large, and changes the trust boundary. |
| **P2** | **NVS schema versioning / migration** | As config grows (provisioning, dial plan, DND), a versioned NVS schema avoids brittle ad-hoc keys and supports config import/export across firmware versions. | **M** | Pairs with P0 config export; define a `schema_ver` key + migration steps. |

### 3.3 Security (cross-ref [THREAT_MODEL.md](THREAT_MODEL.md))

| Pri | Feature | Rationale (technical) | Complexity | Threat-model link |
|-----|---------|----------------------|------------|-------------------|
| ~~P0~~ **DONE** | **WPA2 on the SoftAP** (`WIFI_AUTH_WPA2_PSK`) | **Shipped, opt-in** (NVS `ap_secure`, default off so a live fleet survives the update; dashboard toggle + flash-time `cfgseed`). The single highest-leverage hardening in the whole project: encrypts the *entire* link in one change — dashboard HTTP, SIP signalling, **and** RTP — and gates association so "anyone in range is a peer" stops being the baseline. Closes I-1, I-2, and the cookie-replay vector. | **S** | [THREAT_MODEL.md](THREAT_MODEL.md) §6, §7 P0 (the doc's own top pick) |
| **P0/P1** | **SIP digest auth** (`REGISTER`/`INVITE` challenge) | Stops extension spoofing (S-3) and BYE-based teardown (D-2) *even on a trusted link*. Read-only credential-lookup callback into `RequestsHandler` (no new lock); reuses provisioning's per-MAC secret store as the source of truth. | **M** | [THREAT_MODEL.md](THREAT_MODEL.md) §7 P1; seam designed in [PROVISIONING.md](PROVISIONING.md) §7.3 |
| **P1** | **Per-IP brute-force tracking on `login`** | Replaces the global in-process lockout counter (removes the admin-lockout self-DoS, D-3). | **S** | [THREAT_MODEL.md](THREAT_MODEL.md) §5.2, §7 P1 |
| **P1** | **Sign + gate OTA to local link; session-bind OTA** | OTA images are unsigned today; gate strictly to local link + admin session until signing lands. | **S** (interim) | [OTA.md](OTA.md) §6, [THREAT_MODEL.md](THREAT_MODEL.md) T-5 |
| **P2** | **Secure Boot v2 + flash encryption + signed OTA** | Durable fix for physical/supply-chain boundary: signs firmware (T-5/T-1), encrypts NVS at rest (Wi-Fi pw + admin hash + provisioning secrets, I-3/I-5/T-4). One-way eFuse burn → needs a secured factory flow. | **L** | [THREAT_MODEL.md](THREAT_MODEL.md) §7 P2, [OTA.md](OTA.md) §6 |
| **P2** | **Optional self-signed HTTPS for dashboard** | Still P2, still not the primary control. Documented add-on *on top of* WPA2 only. Browser-warning UX is bad on a LAN appliance and TLS handshakes cost MCU RAM/CPU; not the primary control. | **M** | [THREAT_MODEL.md](THREAT_MODEL.md) §6 (answered "not as primary") |
| **P2** | **SRTP for media** | App-layer media encryption. Heavyweight on the MCU and key-management UX; WPA2 already encrypts media at the link layer for far less. Low priority given the P2P/no-DSP model. | **L** | [THREAT_MODEL.md](THREAT_MODEL.md) I-1 |

### 3.4 Developer / ops experience

| Pri | Feature | Rationale (technical) | Complexity | Issue |
|-----|---------|----------------------|------------|-------|
| **P1** | **Zero-touch provisioning MVP** (manual-URL Yealink `.cfg`) | Build-ready design exists; turns "type a SIP account into every phone" into "paste one URL." Forces G.711/NAT-off/expiry that the engine already assumes. No hot-path or network-stack change. | **M** | #35 / [PROVISIONING.md](PROVISIONING.md) |
| **P1** | **Live SIP tracer (WebSocket)** | Stream SIP signalling to the CRT dashboard for field debugging without a laptop + Wireshark. High diagnostic value. | **M** | #32 |
| **P1** | **PCAP export endpoint** (`/api/diagnostics/pcap`) | Dump a bounded ring buffer of recent SIP packets as PCAP for offline Wireshark analysis. | **S–M** | #33 |
| **P1** | **Provisioning dashboard editor** (MAC→ext map, window toggle, capacity meter vs `MAX_CLIENTS`) | The v3 UI for provisioning; surfaces headroom and the per-MAC token regen. | **M** | [PROVISIONING.md](PROVISIONING.md) §6 v3 |
| **P2** | **DHCP Option 66 true zero-touch** (fork bundled `dhcpserver`) | Removes the typed URL entirely. IDF-version-sensitive fork; documented as a maintained patch. | **M–L** | [PROVISIONING.md](PROVISIONING.md) §1.1, §6 v2 |
| **P2** | **Multi-vendor provisioning** (Grandstream/Polycom/Cisco renderers) | Extends MVP beyond Yealink; mostly static format strings (~2–4 KB `.text`). | **M** | [PROVISIONING.md](PROVISIONING.md) §2.5–2.6 |
| **P2** | **Arduino-IDE build-guard verification** | Confirm `ESP32/ARDUINO/ESP_PLATFORM` macro paths for hobbyist flashing. | **S** | #41 |
| **P2** | **End-to-end hardware validation sweep** (display redraw vs SIP tick latency) | Gate on physical hardware re-connection; verify LVGL redraw doesn't starve the RT loop. | **S** (test) | #44 |

---

## 4. Suggested sequencing (dependency-aware)

The ordering optimizes for **leverage** (one change closing many gaps) and **unblocking**
(security/provisioning are mutually dependent). Each "iteration" is a coherent shippable
slice, not a fixed time box.

```
Iteration A  ── Security foundation (highest leverage)
  P0  WPA2 SoftAP .................. encrypts dashboard+SIP+RTP in one move; gates association
  P0  Config import/export ......... de-risks every later config feature; pairs w/ NVS versioning
  P1  Per-IP login lockout ......... small; removes admin self-DoS; ride alongside WPA2

Iteration B  ── Trusted endpoints (provisioning ⇄ SIP auth, sequenced together)
  P1  Provisioning MVP (Yealink) ... writes per-MAC secret store (PROVISIONING.md)
  P0  SIP digest auth .............. *consumes* that secret store; only now is the secret load-bearing
      └─ DEPENDS ON provisioning's credential store + the OPEN→closed registrar flip

Iteration C  ── Core call control (pure signalling, builds on session machine)
  P0  Blind transfer (REFER) ....... unblocks attended transfer
  P1  Call hold/resume ............. near-passthrough; ship with transfer
  P1  Attended transfer ............ DEPENDS ON REFER (Iteration C step 1)
  P1  Per-extension DND ............ tiny; ride along

Iteration D  ── Observability & ops
  P1  Watchdog/health, /metrics, syslog ... reuse existing snapshot + log queue (no new locks)
  P1  Live SIP tracer (WS) + PCAP export ... field debugging; #32/#33
  P2  Provisioning dashboard editor ........ UI on top of Iteration B

Iteration E+ ── Bigger bets
  ✓   Call parking · BLF/presence · paging zones ........... shipped (tracker #65-67)
  ✓   Dial plan / hunt-group generalization (pattern -> action table) ... shipped (tracker #69)
  P1  Directed call pickup (pickup groups) .................................. tracker #68
  P2  DHCP Opt-66 · multi-vendor provisioning
  P2  Secure Boot v2 + flash encryption + signed OTA  (durable physical/supply-chain fix)
  P2  Multi-AP/mesh · optional HTTPS · SRTP
  P2  Wire MixBus into MediaBridge for local N-way conferencing (opt-in) ............ tracker #75
```

**Why this order:**
- **WPA2 first** because it is the cheapest change with the broadest security payoff
  ([THREAT_MODEL.md](THREAT_MODEL.md) §6) — it retires the dominant open-AP boundary that
  makes nearly every other threat worse, and it does so without per-device certs or MCU TLS cost.
- **Provisioning before/with SIP auth** because they are two halves of one feature: digest
  auth needs a password store, and a provisioned password is meaningless until something
  verifies it ([PROVISIONING.md](PROVISIONING.md) §7.3). Shipping auth without provisioning
  means hand-typing secrets; shipping provisioning without auth means configuring a password
  nothing checks.
- **Config export early** so that as dial plan / DND / provisioning state accrues, operators
  can back up and migrate units — and so NVS schema versioning is designed in, not retrofitted.
- **Transfer/hold/attended** as a block because they share the session state machine and are
  all media-free server-side (cheap, on-mandate). Attended transfer strictly depends on REFER.
- **Observability** rides existing infrastructure (snapshot, `_logQueue`, atomic counters) so
  it adds no new locking on the RT path.

---

## 5. Explicitly out of scope / non-goals (technical only)

These are ruled out *for technical reasons* — they conflict with the zero-DSP, peer-to-peer-media,
static-pool architecture, not for any other reason.

| Non-goal | Why (technical) |
|----------|-----------------|
| **On-MCU media mixing / conferencing wired into live calls** | The scalar mixer (`MixBus`) is implemented and tested — ~64k adds/s at ≤8 narrowband ports, a rounding error on a 240 MHz core (see [CONFERENCE_MIXER.md](CONFERENCE_MIXER.md) §4) — but it is *not* wired into `MediaBridge`'s call path or any dial-plan entry point (tracked: internal tracker #75). Still breaks the "server never touches RTP" invariant for the *default* path ([SCALING.md](SCALING.md) §1) whenever it IS wired in — that's a deliberate, bounded opt-in, not a removal of the invariant for ordinary LAN calls. |
| **On-device voicemail (record/playback)** | Same reason: media must traverse and be stored/transcoded on the device. Scope only as routing to an external SIP voicemail UA. |
| **On-MCU transcoding** | No DSP budget. The engine deliberately *rewrites SDP to G.711 (`0 8 101`)* and forces phones via provisioning rather than transcoding; that is the design, not a gap. |
| **Wideband / Opus / G.722 media negotiation** | The interop strategy is to *lock* to G.711; supporting wideband would reintroduce the codec-mismatch failures `enforceG711()` exists to prevent. |
| **TLS as the primary transport security** | On a LAN appliance, self-signed certs trigger browser warnings, cost MCU RAM/CPU, and only protect the dashboard (not SIP/RTP). WPA2 is the better lever ([THREAT_MODEL.md](THREAT_MODEL.md) §6). HTTPS is a documented *optional add-on* only. |
| **WebRTC NAT traversal (ICE/TURN) · TURN media relay on-MCU** | ICE/TURN are peer-mesh/WebRTC tools, and a TURN *server* would put N relayed media streams on the MCU. Out of scope. |
| **Cloud control plane / remote management** | The device is intentionally self-contained with no cloud dependency; control is local-only (see threat model trust boundaries). |
| **Unbounded dynamic allocation for "scale"** | Capacity is set by static pools by design; "scale up" means picking a tier (or a wired board), not removing the pre-allocation that guarantees a fragmentation-free hot path ([SCALING.md](SCALING.md) §5). |
| **DHCP Option 43 multi-vendor provisioning** | Brittle per-vendor TLV encoding; rejected in favor of an Option-66 `dhcpserver` fork ([PROVISIONING.md](PROVISIONING.md) §1.1). |

---

## 6. Top 3 P0 recommendations (next-up)

1. **WPA2 on the SoftAP** — one small change encrypts the whole link (dashboard + SIP +
   RTP) and gates association, retiring the dominant open-AP boundary that amplifies every
   other threat. Highest leverage-per-effort in the codebase.
2. **SIP digest auth** (sequenced with the **provisioning MVP** that supplies the credential
   store) — closes extension-spoofing and BYE-teardown on the signalling layer; the two are
   interdependent halves of one capability and must land together.
3. **Blind transfer (REFER)** — the highest-value missing call-control primitive, pure
   signalling, built on the existing session state machine, and the prerequisite for attended
   transfer.

(Config import/export is the strongest P0 *platform* item and the natural fourth, de-risking
all later config growth.)

