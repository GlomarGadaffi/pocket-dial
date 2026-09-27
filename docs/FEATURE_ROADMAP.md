# pocket-dial: Technical Feature Roadmap

Status: Living document | Last updated: 2026-09-27 (re-checked against `main` for #401) | Scope: Engineering / product-capability only

This is a prioritized **engineering** roadmap for pocket-dial: what exists, what is proved,
and what is worth building next. It is grounded in the current source tree. It deliberately
stays inside the project's "fast and light" constraint, every proposal is sized against the
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

> **Framing, corrected 2026-09-13.** The original framing was that pocket-dial "never
> touches RTP." That is still true of the **ordinary call**, and it is still the single
> fact that decides what is cheap and what is expensive here. It is no longer true of the
> product as a whole, and stating it as a blanket has begun to mislead.
>
> **The peer-to-peer half.** An extension-to-extension call is brokered and then gets out
> of the way: the two phones stream RTP directly to each other and the MCU never sees a
> media packet. Hold and blind/attended transfer all preserve that property: the
> SDP is relayed, and only the codec list is narrowed, never the `c=` line. **Park no
> longer does, unconditionally:** with a music-on-hold clip loaded the board answers the
> parked leg `sendonly` from its own port and streams the clip to it
> (`src/SIP/ParkOrbit.cpp:64-84`), which puts the MCU in the media path one-way for the
> duration of the park. With no clip loaded (the default), park still answers
> `a=inactive` and sources nothing, which is the behaviour this paragraph used to
> describe as unconditional. `777` echo is
> in this half too, despite an in-code comment calling it "server-terminated": it is an
> SDP loopback, answering with the caller's own body so the phone streams to itself
> (`src/SIP/RequestsHandler.cpp:1755`). Nothing on the board carries that audio.
>
> **The media-terminating half, which is now real and shipped.** `440` (tone), `555`
> (anchor bridge), `888` (conference) and voicemail (deposit on no-answer/busy, retrieval
> on `796`; `src/SIP/VoicemailLeg.hpp`) put the board in the path: it sends and/or
> receives RTP for them. `888` decodes, mixes and re-encodes. An outbound **anchor** trunk
> call crosses the board on **both** sides: RTP to and from the handset, chunked-HTTPS PCM16
> to and from the provider, with `MediaBridge` shuttling PCM16 between them; the board
> owns the handset-facing `RtpReceiver`/`RtpSender` pair for the life of that call
> (`src/SIP/MediaBridge.hpp:17-18`). An outbound **SIP** trunk call (§1.3) crosses it too,
> as a raw RTP relay pair with no PCM16 and no `MediaBridge`
> (`src/SIP/RequestsHandler.cpp:10008-10030`). These are deliberate,
> bounded, individually dialable exceptions, not a removal of the invariant for ordinary
> LAN calls.
>
> The cheap/expensive axis therefore still holds, and is now measurable rather than
> hypothetical: signalling features are bounded by the pre-allocated pools and cost a few
> hundred bytes; media features cost a leg's worth of RTP tasks and rings apiece, which is
> why the conference is capped at 4 legs, the anchor trunk at **four** concurrent calls
> (one on the default loopback provider), the SIP trunk at **two** and voicemail at **two**
> legs (see §1.3 and §1.5).

## 1. Current capabilities (shipped, in the tree today)

### 1.1 Call control and PBX features

| Capability | Notes | Where |
|-----------|-------|-------|
| Registrar + back-to-back call broker | `REGISTER`, `INVITE`, `ACK`, `BYE`, `CANCEL`, `OPTIONS`, provisional/final responses | `src/SIP/RequestsHandler.cpp` |
| **SIP digest auth (RFC 2617)** | Implemented and operable. The shipped default is `learn` (#441) and `open` is retired (#500/#502): Learn challenges Secured devices, Secure every extension; see §1.4. **Not yet airtight:** #507 (an ARP miss admits a Secured extension without digest) and #549/#525 (a credentialed INVITE can be replayed; fix #555 not merged). | `src/Helpers/SipDigest.*`, `src/SIP/Registrar.*` |
| Blind transfer (REFER) | Source-authorized against the dialog's own legs (#133). Moves the **transferee**: a new dialog to the target carries B's media (`RequestsHandler.cpp:6270-6300`), the transferor A is BYEd (`:6474-6485`), and the A–B leg is kept (`:6533-6538`). The old inverted topology (#197) is fixed by #211 and the tests pin the corrected one (`tests/BlindTransfer_test.cpp:7-10`). Unresolvable targets no longer destroy the call (#203, fixed). Remaining: the NOTIFY reports `200` as soon as the INVITE is queued, with no `100 Trying` progress. | `onRefer` |
| Attended transfer (REFER + Replaces, RFC 3891) | Splices B and C, BYEs A out of both, relays a later BYE across the bridge. The hardcoded `CSeq: 100` of #257 was removed by its own fix (#308, per-dialog floors), and #402 replaced those floors with `nextServerCSeq()` (`RequestsHandler.cpp:6149`). Only REFER `?Replaces=` is handled; an INVITE carrying `Replaces` (BLF pickup) is not. | `onRefer`, `handleTransferOk` |
| Hold / resume | Re-INVITE relayed with its **SDP** untouched, so the SDP survives; `Contact` is rewritten on every relayed re-INVITE (#425, `RequestsHandler.cpp:9079-9090`) | `onReinvite`, `onOk` |
| RFC 3311 `UPDATE` | | `onUpdate` |
| RFC 4028 session timers | Passive: the PBX honours a timer a phone requests, but never requests one itself and never sends `422`/`Min-SE`. | `armSessionTimer` |
| Ring / hunt groups | ring-all or sequential hunt | `CallForker` |
| Call park + retrieve | orbits `700`–`709` (`POCKETDIAL_PARK_SLOTS` = 10) | `ParkOrbit.*` |
| Call pickup | group `*8`, directed `**<ext>`; pickup groups reuse ring-group membership | `CallPickup.*` |
| Paging / intercom | zones `980`–`989`, plus `999` all-page, with auto-answer header injection and race-to-answer | `startPaging`, `startBroadcastFork` |
| Call forward | CFU / CFB / CFNA, per extension | `PbxFeatureConfig` |
| Per-extension DND | | `PbxFeatureConfig` |
| BLF / presence | `SUBSCRIBE`/`NOTIFY`, **`dialog` event package only** (RFC 4235); any other package gets `489`. No `presence`, no `message-summary`/MWI. | `BlfSubscriptions.cpp:146-155` |
| Outbound email (SMTP client) | Issue #159 Phase 1: generic SMTP client over `esp_tls` (implicit TLS/STARTTLS/plain-LAN-relay, `AUTH PLAIN`/`LOGIN`/`XOAUTH2`, streaming DATA writer), configured at `/setup/email`. Gmail App Password and Google Workspace service-account (domain-wide delegation, RS256 JWT) paths. Standalone -- its own "Send test message" is the only consumer (`HttpServer.cpp:5150`). On-device voicemail now exists (§1.2), but **nothing emails a voicemail yet** (`SmtpDialogue.hpp:90`: "a later consumer, not built"). | `src/Helpers/SmtpDialogue.*`, `SmtpClient.*`, `GoogleServiceAuth.*`, `EmailConfigStore.*` |
| DTMF star codes | `*60`, `*72`, `*73`, `*80`, `*69`, `*11`, plus the `*PIN#code` admin menu. Digits arrive over **SIP INFO** (RFC 6086) on any call except a voicemail leg (kept away from the star-code parser, `RequestsHandler.cpp:1057-1060`), and over **RFC 4733** telephone-event on a leg the board itself terminates: 888 conference and 555/anchor (`MediaBridge.cpp:112-115`), and the voicemail retrieval leg (`RequestsHandler.cpp:2951-2952`). Not decoded on park legs or the SIP-trunk relay. RFC 4733 cannot work on an ordinary extension-to-extension call: that RTP is peer-to-peer and never reaches this board. | `DtmfFeatureCodes.cpp`, `RtpReceiver::dispatchDtmf` |
| Bounded dial plan | ordered `pattern → group\|page\|park\|trunk`, first match wins, cap `POCKETDIAL_MAX_DIAL_RULES` = 16 | `DialPlan.hpp` |
| **Emergency dialing (#166)** | `911`, `9911` and the `933` test number are intercepted **before** the dial plan and before registrar call-setup policy (`RequestsHandler.cpp:1715-1733`), always routed out through the anchor path (`originateAnchorCall`, never the SIP trunk; `:3739`), answered `503` when no anchor is connected, and trigger the Kari's Law on-site notification (`EmergencyNotifier.*`, configured at `/api/e911-config`). **No location is conveyed to the PSAP, an emergency call does not pre-empt a busy anchor slot, and on a default board the anchor is the loopback simulator** (#521), see §5. | `EmergencyCall.hpp`, `EmergencyNotifier.*` |
| Inbound DID → extension | route-DN match by **E.164 equivalence** (`pbx::e164SameNumber`, #165; `DidMapping.cpp:57-76`), so `+15551234567` and `(555) 123-4567` are the same DID; cap 8; unmapped falls back to ring-all | `DidMapping.*`, `E164.*` |
| CDR ring + `GET /api/cdr` | 32-record ring persisted to NVS (namespace `cdrlog`, `CdrRing.cpp:27`), so it survives a reboot **while the serialized ring stays under NVS's 4,000-byte string cap**: it can reach 4,481 B, and the writer ignores the error, so history silently goes stale (#470, fix #476); on SD builds also appended to a per-day CSV archive `/sdcard/cdr/YYYY-MM-DD.csv` (#194, `CdrArchive.hpp:4-9`). Both are wiped by factory reset. `GET /api/cdr` (JSON, admin-gated) is the only read route; the archive has no download route. | `CdrRing.*`, `CdrArchive.*` |
| Virtual `777` echo | SDP loopback, **no media on the board**; since #304 the echoed answer also drops PCMA | `RequestsHandler.cpp:1755` |

### 1.2 Media: the part the board actually carries

| Capability | Notes | Where |
|-----------|-------|-------|
| `440` server-sourced tone | board **sends** RTP; `sendonly` SDP | `onMediaInvite` |
| **Music on hold (park, held anchor calls, preview)** | board **sends** RTP. One global clip cursor, read off the SD card into PSRAM **once at load** (the card is then out of the media path entirely), G.711 µ-law 8 kHz mono only. Two kinds of consumer: **listeners** — a **parked** leg (`ParkOrbit.cpp:64-84`) and the dashboard **preview** call (`POST /api/moh/preview`) — get the identical 160-byte payload `sendto`'d per listener each 20 ms tick, no per-leg decode, no `MixBus`, cap `POCKETDIAL_PARK_SLOTS`; **taps** — the far side of an **outbound** anchor call a handset puts on hold (#218: `answerAnchorReinvite` → `MediaBridge::setHeld()`, `MediaBridge.cpp:189-210`) — are a separate table (`Tap _taps[POCKETDIAL_MAX_ANCHOR_CALLS]`, `HoldMusic.hpp:302`), decoded µ-law→PCM16 per call (`MediaBridge.cpp:272`) and written with `AnchorClient::writeAudio` (`:278`), not `sendto`. That path runs only for the outbound anchor (`destNum == kAnchorCallExt`, `RequestsHandler.cpp:9038`); a hold on an **inbound** anchored call goes unanswered (#445, fix #449). **Falls back to the old silent `a=inactive` hold** when there is no clip, no usable RTP endpoint in the parked party's SDP, or MoH is not running; park never fails because nobody uploaded a WAV. An ordinary peer-to-peer hold is still relayed untouched and hears nothing from the board (`RequestsHandler.cpp:9076-9091`); a SIP-trunk call refuses a hold re-INVITE with `488`. | `HoldMusic.*`, `ParkOrbit.cpp:64-84`, `MediaBridge::setHeld` |
| **Voicemail (on-device, #246)** | board **sends and receives** RTP. Deposit when a call goes unanswered or finds the extension busy (CFNA/CFB fallback, `RequestsHandler.cpp:2115`, `:5061`); retrieval by dialing **`796`**, with RFC 4733 menu navigation. Each leg owns its own `RtpReceiver`/`RtpSender` pair (`VoicemailLeg.hpp:10-16`), cap `POCKETDIAL_MAX_VOICEMAIL_LEGS` = 2. Messages are WAVs on the SD card (`/sdcard/vm`, `VoicemailArchive.*`), so voicemail exists **only on SD builds**. Managed with `POST /api/voicemail`. No MWI (§1.1 BLF row) and no voicemail-to-email yet. | `VoicemailLeg.*`, `VoicemailArchive.*`, `VoicemailMenu.*` |
| `888` meet-me conference | board decodes, mixes (`MixBus`, N−1 minus-self summing) and re-encodes. **`POCKETDIAL_CONF_LEGS` = 4**, one global room, **no PIN**, created on first dial-in and then kept alive. **Exercised on `.244` (2026-09-27): that run panicked the board** (#498): `MixBus::tick` kept ~2.9 KB of frames on `conf_mix_tick`'s 3,072-byte stack. #499 moved the scratch into `MixBus` members (`MixBus.cpp:53`); it is merged but **not yet re-run on hardware**. The same run's first call left ~139 B of internal heap for the rest of uptime (#524), measured before #475/#480 moved the jitter rings and the rx stacks to PSRAM; re-measure on the next bench run. A quick re-dial got `486` (#513), fixed by #526 (host-tested). | `ConferenceRoom.*`, `MixBus.*` |
| `555` anchor media bridge | board bridges a leg to an `AnchorClient`. **Active on default firmware** via the `Loopback` reference client. | `onAnchorInvite`, `MediaBridge.*` |
| Codec policy | **Relayed peer-to-peer legs admit PCMU, PCMA _and G.722_** (`filterAudioCodecs(allowWideband=true)`). Legs the board terminates itself (777, 440, 888, 555, voicemail) refuse G.722 **and, since #304, PCMA**: they accept PCMU only (`RequestsHandler.cpp:1768`, `2238`, `2454`, `2658`, `2891`, `3925`), because `RtpReceiver` decodes PT 0 only. The board's own SDP offers PCMU (plus telephone-event). **Gaps:** the SIP-trunk path has no such gate, yet answers the handset PCMU-only; and park with MoH answers `makeSendonlySdp`, which is PCMU-only (`SipWireUtil.hpp:99-110`), whatever the parked phone offered (`ParkOrbit.cpp:64-80`). | `SipMessage.cpp:499`, `buildMediaSdp` |
| `enforceG711()` | **Deprecated, zero production callers** (tests only). It pinned `m=` to a literal `0 8 101`, inventing PT 101 with no `a=rtpmap`, which pjsip rejects outright. Any "this PBX is G.711-only" statement is stale. | `SipMessage.cpp:266` |
| SDP admission gate | every SDP-bearing message structurally checked before any decoder sees it; capability-negotiation attributes refused (T-7 / the UNISOC T612 RCE class) | `SipMessage::checkSdp` |

### 1.3 Outbound trunking

Outbound calls leave by one of two paths, chosen in `RequestsHandler::routeTrunkCall()`:
the **SIP trunk** whenever its configuration is valid, otherwise an **`AnchorClient`**
(`RequestsHandler.cpp:9954-9963`).

- **SIP trunk (#164).** `SipTrunk` sends `INVITE`/`ACK`/`BYE` over UDP straight to the
  carrier's SBC and relays RTP raw between the handset and the carrier. Configured at
  `/setup/trunk` and `GET`/`POST /api/trunk` (`HttpServer.cpp:688-709`), applied at boot by
  `applyStoredTrunkConfig()` in every `main/esp_main*.cpp`. Cap
  `POCKETDIAL_MAX_TRUNK_CALLS` = **2** (`PoolConfig.hpp:262`).
- **Anchor client.** HTTP/OAuth2, a call-control WebSocket, and media as chunked-HTTPS
  PCM16. The shipping real client speaks the **3CX Call Control API**.

What surprises people:

- **The SIP trunk never registers and never answers a challenge.** `SipRegistrationClient`
  is compiled but never instantiated, and `SipTrunk` has no `401`/`407` handling
  (`SipTrunk.hpp:126-129`), so only an IP-authenticated carrier works. Server location is a
  plain A-record lookup (`TrunkResolver`): no SRV/NAPTR, UDP only.
- **A dial-plan rule with `action=trunk` is the only way out for an ordinary number.** No
  hardcoded `9` prefix, no unregistered-destination fallback: with an empty dial plan every
  outside number is answered `404` without leaving the box. **Emergency numbers are the
  exception**: they bypass the dial plan entirely (§1.1).
- **`POCKETDIAL_MAX_ANCHOR_CALLS` is 4**, raised from 1 (`PoolConfig.hpp:244`). The
  effective ceiling is `min(provider, 4)` via `RequestsHandler::anchorCallLimit()`
  (`RequestsHandler.cpp:3626-3648`): `LoopbackAnchorClient` declares **1** (constant
  participant id), `TelephonyAnchorClient` declares 4. So **default firmware still gets one
  concurrent anchor call**; a board driving a real 3CX trunk gets four, bounded by software
  ECDHE cost, not RAM.
- **E.164 exists for inbound DIDs only.** `pbx::e164Normalize`/`e164SameNumber` (#165,
  `src/SIP/E164.*`) are used by DID matching. Outbound, a rule's strip/prepend is still the
  whole of the number transformation; the SIP trunk only prefixes `+` when it builds the
  Request-URI (`SipTrunk.cpp:35-42`, whose comment at `:33` wrongly says the number was
  already normalised).

Anchor credentials live in four slots (`TelephonyApiConfig::kSlots`), one active at a time,
edited through `/api/telephony-config`, see [API.md](API.md).

### 1.4 Security posture

| Control | State |
|---------|-------|
| **Admin login** | **Username + password** (`AdminAuth`), salted/iterated SHA-256, server-side sessions, per-session CSRF token on every mutating route, and brute-force lockout with exponential backoff plus an aggregate backstop. **The lockout is per client** since #530: `req.clientIp` is set on every buffered request (`HttpServer.cpp:576`), as it already was for the streaming OTA/MoH upload (`:461`), and the login handler keys its lockout on it (`:4375-4386`). The aggregate backstop is still shared by design, see [THREAT_MODEL.md](THREAT_MODEL.md) D-3. Ships as `admin`/`admin` with forced first-use setup: every admin route except `set-credential` answers `403 setup_required` until it is replaced. |
| **DTMF admin PIN** | A *separate*, independent numeric secret for the phone-keypad `*PIN#code` menu. **No default**, so that menu is disabled until explicitly configured. Unrelated to the web session. |
| **HTTP reachability** | **The dashboard is always reachable.** The listener opens at construction and stays open. The dark-by-default plane and the `*4887` reopen star-code were **removed** (`de1a36e`); `grantAdminHttpGraceWindow` no longer exists. |
| **Registrar admission** | Two modes: `learn` / `secure`; `open` is retired (#500/#502), and a stored retired value boots as Learn. Digest auth is real; Learn is TOFU + an ARP-learned MAC lock. **The shipped default is `learn`** (#441): a fresh board adopts an unknown MAC on its first REGISTER, and an unregistered INVITE caller gets `403` (`RequestsHandler.cpp:1717-1727`). **Learn still admits an INVITE from a Learned (unsecured) extension without a challenge:** Secure challenges every INVITE, and Learn challenges only a device an admin has promoted to Secured (#512, `:1783-1784`). In flight: #503 (bind the INVITE to the caller's registered address). |
| **SoftAP WPA2** | Implemented, **opt-in, default off** (NVS `ap_secure`) so a firmware update never re-pairs a live fleet. Encrypts dashboard, SIP and RTP together. |
| Signalling hardening | per-source-IP token bucket, AOR whitelist, bounded parser, SDP admission gate. **The "optional CIDR allowlist" this row used to list is not a shipped control**: `_allowNet`/`_allowMask` are never assigned, so `ipAllowed()` returns true for every source (`RequestsHandler.cpp:8837-8842`). See [ARCHITECTURE.md](ARCHITECTURE.md) §Rate Limiting. |
| HTTP hardening | same-origin + CSRF, 16 KB body cap, `SO_RCVTIMEO`, no wildcard CORS, central security response headers (CSP, `X-Frame-Options: DENY`, `nosniff`, `no-store`), deliberately no HSTS |
| OTA | dual-slot `ota_0`/`ota_1`, streaming upload, image integrity and chip-ID checks (`422` on refusal), mark-valid-after-boot rollback. **Unsigned**, **owner**-gated (`HttpServer.cpp:460-462`) — but a sysop satisfies Owner while no owner account exists (`AdminAuth.cpp:1388-1400`), which is the default on a fresh or upgraded board, and `POST /api/ota/reboot` is sysop-gated (`:1109-1115`). Mark-valid is a fixed timer after boot, not a health check (see §3.2 Watchdog). |

### 1.5 Platform

Core-pinned SIP, UDP-receive and media tasks (the HTTP accept and connection threads are
unpinned, see [ARCHITECTURE.md](ARCHITECTURE.md) §2); outbox pattern keeping socket syscalls
outside the lock; double-buffered lock-free status snapshot; a hot path built on pre-allocated
pools — **not yet allocation-free**: the message pool and the virtual-peer pool fall back to
the heap when drained (`SipMessagePool.cpp:95-100`, `RequestsHandler.cpp:9722`; #409, with
#434 and the #284 batches in flight). Compile-time
pools (`src/SIP/PoolConfig.hpp`): `MAX_CLIENTS` 32, `MAX_SESSIONS` 8, `MAX_DIAL_RULES` 16,
`MAX_DID_MAPPINGS` 8, `CONF_LEGS` 4, `MAX_ANCHOR_CALLS` **4** (effective 1 on the default
loopback provider), `MAX_TRUNK_CALLS` 2, `MAX_VOICEMAIL_LEGS` 2, with graceful `503` on
exhaustion.
Transports: Wi-Fi SoftAP with captive portal, W5500 / LAN8720 wired Ethernet and PoE,
Guition JC3248W535 touch display (LVGL 8.3). Zero-touch provisioning with **Yealink,
Grandstream, Polycom and Cisco SPA** renderers (#177, `ProvisioningConfig.hpp`), routed by
request path and User-Agent (`GET /config/<mac>.cfg`, `000000000000.cfg`, `cfg<mac>.xml`,
`spa<MAC>.cfg`; #234); none has been confirmed against a physical handset yet (§2).
Flash-time configuration via the `cfgseed` partition and the browser flasher. **Config
backup/restore** (`GET`/`POST /api/config/export`, `POST /api/config/import`, #186): the
readable part is sysop-level; the Wi-Fi password, AP PSK and anchor-slot metadata travel
only in a password-encrypted (PBKDF2 + AES-GCM) `secretsEnc` block that only the owner can
export. Since #484 the per-extension digest HA1s travel only in that block
(`HttpServer.cpp:4757-4771`), and an owner-level import restores them (`:5212-5248`; #482). **NVS schema versioning**
(`schema_ver`, `DeviceConfig::ensureSchemaVersion()`, #181), run before anything else
reads NVS in every entry point. **Task watchdog** set to panic (`sdkconfig.defaults:285`,
#185) with the SIP, UDP-receive, RTP and conference-mix tasks subscribed (#235; the rest are
not, see §3.2); heap and
stack high-water marks on `/api/status`. **Syslog** (RFC 5424 over UDP, `/api/syslog`) on
the three headless builds; the saved host is loaded after `esp_netif_init()`, so it no
longer boot-loops the board (#508, fixed by #511). Live SIP tracer (`/api/trace`) and Wireshark-readable capture
(`/api/pcap`). Prometheus-style `GET /metrics`. Dashboard with patch-bay UI and toolbar
modals for help (`F1`), dial plan (`F2`), ring groups & forwarding (`F3`), call log (`F4`),
refresh (`F5`), **PBX Settings (`F6`)**, hold-music upload, preview and stop, SIP trace
(`F8`) and Wi-Fi (`F9`), plus Admin and Interconnect buttons
(`src/Helpers/index_html.h:378-387`, key handler `:1975-1983`).

## 2. What is actually *proved*: read this before trusting §1

§1 is "in the tree and works in test". This section is what has been observed on real
hardware, and it is deliberately short.

| Claim | Evidence |
|-------|----------|
| A real handset registers and calls out | **A Yealink T29 is registered to the bench board and outbound PSTN is verified end to end**: one call rang through to carrier voicemail (answered at 21.2 s) and one was answered by a person, **with two-way audio**. This is the **first real-handset evidence in the project.** |
| Everything else | Host-only: gtest, or `pjsua`/SIPp driven against the **desktop** binary over loopback. |
| On-device RTP | **No automated test exercises it.** The host build's `RtpSender`/`RtpReceiver` are stubs (a Linux-desktop socket path aside), so every green media test exercises a stub, not the ESP32 path. The one manual T29 trunk call above ran the handset leg through `RtpReceiver`/`RtpSender`/`MediaBridge`/`PlayoutBuffer` on a real board, which proves the **anchor-bridge** shape only ([RTP.md](RTP.md), `docs/RTP.md:58-63`). The `888` mixer **has** run on `.244` (2026-09-27); that run panicked the board (#498), and the fix (#499) is merged but not yet re-run on hardware (see §1.2). MoH has never been *verified* on hardware: the preview call's signalling was seen on the bench (`e20226d`, #206) but its audio was not recorded. `440`, voicemail and the SIP-trunk relay have never run on hardware. |
| OTA | **Proved once, on one board, by hand.** First end-to-end run 2026-09-26 on `.244` (ESP32-S3 Ethernet) with `tools/ota/remote_ota.sh` (#395): refusals (truncated and wrong-chip images, `422`, no reboot), a real `ota_0 → ota_1` that booted pending and marked itself valid, and a rollback probe that the bootloader rolled back ([OTA.md](OTA.md), `docs/OTA.md:16-20`). CI still never runs an OTA. |
| Zero-touch provisioning | Implemented: `GET /config/<mac>.cfg` only serves a MAC in the Learn-mode adopted-device registry (`HttpServer.cpp:605-612`). Learn is now the default (#441), so a phone that has registered once is served; a MAC never seen is still a 404. None of the four vendor renderers (Yealink, Grandstream, Polycom, Cisco SPA) has been confirmed against a physical handset. |

**This table is the roadmap's most load-bearing content.** The highest-value work in the
project right now is not a new feature; it is moving rows out of the bottom half of this
table. See §6.

## 3. Open backlog (grouped, prioritized)

Priority key: **P0** = build next (highest impact or unblocks others); **P1** = soon,
clear value, moderate effort; **P2** = strategic / higher effort / depends on a P0–P1.
Complexity is a t-shirt size for *signalling-side* work unless noted.

Everything the previous revision of this document listed as proposed telephony work,
blind transfer, attended transfer, hold/resume, DND, the dial plan, park, BLF, paging
zones, pickup, **has shipped** and now lives in §1. What remains is below.

### 3.1 Telephony

| Pri | Feature | Rationale | Complexity | Constraints |
|-----|---------|-----------|------------|-------------|
| **P1** | **Outbound E.164 normalization** | Inbound DID matching already uses E.164 equivalence (#165, `E164.*`), but nothing normalizes an **outbound** number: a trunk rule's strip/prepend is the entire transformation, which works for one national dial habit and breaks on the next, and the SIP trunk just prefixes `+`. | **S** | Reuse `pbx::e164Normalize()`, which has no outbound caller yet. A bounded table, not a regex engine. |
| **P1** | **Session timers, active side** | The PBX honours a phone's `Session-Expires` but never requests one and never answers `422`/`Min-SE`. A phone that dies mid-call therefore leaves the session to the orphan sweep rather than a refresh failure. | **M** | Pure signalling; the passive half already parses `refresher=`. |
| **P2** | **Trunk failover** | `MAX_ANCHOR_CALLS` has since been raised to 4, so "a second concurrent outside call" is **done** on a real provider. What remains is **failover between the four configured telephony slots**: there is none: one slot is active at a time and a dead provider is not detected or switched away from. | **M** | Signalling/orchestration, not media; the concurrency half was the media decision and it has been taken. |
| **P2** | **Conference rooms with PINs** | One global room, no PIN, cap 4. Multiple rooms means a room table and per-room `MixBus` instances. | **M–L (media)** | Memory-bound: the rings are ~50 KB per room. |
| **P2** | **MWI / `message-summary`** | The BLF machinery only implements the `dialog` event package. MWI is cheap *given* a voicemail store, and there now is one: on-device voicemail (§1.2, #246). A phone has no lamp or stutter tone for a new message and has to dial `796` to find out. | **S** | SD builds only, since that is where voicemail exists. Rides the existing NOTIFY path, which already has Timer E/F retransmission. |
| **P2** | **100rel / PRACK** | Not implemented. Matters only for interop with a UAS that requires it. | **M** | No known handset in the bench set needs it. |

### 3.2 Platform / reliability

| Pri | Feature | Rationale | Complexity | Notes |
|-----|---------|-----------|------------|-------|
| ~~P0~~ **DONE** | **Config import / export (backup / restore)** | **Shipped (#186).** `GET /api/config/export` and `POST /api/config/import` (`confirm=REPLACE`), `HttpServer.cpp:1006-1060`. The readable part is sysop-level; the Wi-Fi password, AP PSK and the anchor slots' `baseUrl`/`clientId`/`routeDn` travel only in a PBKDF2 + AES-GCM `secretsEnc` block, and exporting it is owner-only. The anchor slot **secret** is never exported (`HttpServer.cpp:4743-4752`), and the **SIP-trunk, SMTP, syslog and E911 config are not exported at all**. **Not restored:** MAC bindings and those unexported settings. The per-extension digest secrets travel only inside `secretsEnc` and an owner-level import restores them (#482, #484). | N/A | Import parses, shape- and `exportVer`-checks and decrypts the whole blob before any setter runs (`schemaVer` is emitted on export but never read on import, `:4726`). |
| **P1** | **Watchdog / health & self-heal**: remaining half | **Mostly shipped.** The Task WDT panics on timeout (`CONFIG_ESP_TASK_WDT_PANIC=y`, `sdkconfig.defaults:285`, #185), and the SIP task (every `main/esp_main*.cpp`), the UDP receiver, the RTP send/receive tasks and the conference mix tick subscribe to it (#235). `/api/status` reports `minFreeHeap`, `resetReason` and per-task stack high-water marks. **Still open:** unsubscribed are the HTTP threads, `moh_tx` (a 20 ms media tick like `conf_mix_tick`, `HoldMusic.cpp:464`), `log_drain`, `cdr_archive`/`cdr_persist`, the `tel_*` anchor tasks, `dns_task` and, on the display build, `lvgl_task`/`status_task`; and the OTA `mark-valid` gate is a fixed timer after boot (`esp_main_eth.cpp:525-533`), not a health check. | **S** | Make mark-valid wait on a real health signal (SIP task ticking, heap floor). |
| ~~P1~~ **DONE** | **Metrics endpoint** | **Shipped.** `GET /metrics` serves eight Prometheus text-format families, all `pocketdial_`-prefixed: `uptime_seconds`, `sip_registrations_active`, `sip_calls_active`, `packets_processed_total`, `packets_dropped_total`, `packets_dropped_invalid_total`, `packets_dropped_rate_total` (#430) and `sdp_rejected_total`. Reads only the relaxed atomics and the snapshot-mutex counts; it never touches `RequestsHandler::_mutex`, which is why `getConferenceLegs()` is deliberately *not* exported. **Ungated**, argued in-place: a stock scraper cannot drive the login/CSRF handshake. | N/A | Route `HttpServer.cpp:617`, `sendApiMetrics` at `:1887`. Listed in [THREAT_MODEL.md](THREAT_MODEL.md) §4 E-2's unauthenticated-read class. |
| ~~**P1**~~ **Shipped** | **Syslog (RFC 5424 over UDP)** | `_logQueue` already buffers under lock and flushes outside it; tee it for fleets with no serial console. `src/Helpers/Syslog.{hpp,cpp}` is a host-unit-tested RFC 5424 frame formatter, compiled into both the firmware (`main/CMakeLists.txt:134`) and the host build, and now wired: included by `main/esp_main.cpp:24`, `esp_main_eth.cpp:68`, `esp_main_eth_lan8720.cpp:67` and `HttpServer.cpp:30`, with a route (`HttpServer.cpp:646`) and a destination in NVS (`syslog_host`). **Shipped in #209.** The tee lives on `LogQueue::setTee()` (which deliberately knows nothing about syslog, so a failing sink cannot take the log path down), the three headless ESP entry points register it at boot (`esp_main.cpp:410`, `esp_main_eth.cpp:643`, `esp_main_eth_lan8720.cpp:435`; the display build does not), and `GET`/`POST /api/syslog` configure the destination. Frames carry a real RFC 3339 timestamp from `timesync::rfc3339Now()`, which returns the RFC 5424 NILVALUE while the clock is unsynced. The 480-byte frame buffer is `static` under the module mutex rather than a stack local -- that spike on the 2048-byte drain task was the original reason this shipped unwired. **Caveat:** off the `eth` build, frames carry the NILVALUE timestamp, because SNTP is started only by `esp_main_eth.cpp:229`. (A saved syslog host used to boot-loop the board, because `Syslog::loadFromNvs()` ran before `esp_netif_init()`; #511 moved it after, e.g. `esp_main_eth.cpp:653` then `:660`. #508.) | **S** | One UDP socket, bounded queue, drop-on-full; never block the RT path. |
| ~~P2~~ **DONE** | **NVS schema versioning / migration** | **Shipped (#181).** `schema_ver` in NVS, `DeviceConfig::kSchemaVersion` (`DeviceConfig.hpp:328`), and `ensureSchemaVersion()` run first thing in every entry point: fresh installs are stamped, unstamped legacy boards adopted as v1, a downgrade is reported loudly and left untouched, and migrations run from a table. The export carries `schemaVer`. | N/A | The first real migration row is #502's `migrateRetireOpenRegistrar` (`DeviceConfig.hpp:336`), the only row; #441's competing `migrateKeepPre397BoardOpen` did not survive the merge. Both were at `kSchemaVersion = 2`. |
| **P2** | **Multi-AP / mesh / roaming** | Extends coverage past one SoftAP's ~16-station ceiling. Large, and it changes the trust boundary. | **L** | Keep one logical registrar; clients re-REGISTER on roam. |

### 3.3 Security (cross-ref [THREAT_MODEL.md](THREAT_MODEL.md))

| Pri | Item | State / rationale | Complexity |
|-----|------|-------------------|------------|
| **P0** | **Flip the registrar default. DONE** | #441 (a fresh board boots Learn) and #502 (`open` retired; Learn is the floor). What is left of the INVITE half is #503 (caller address binding) and the Secured-device challenge Learn already does (#512). | **S–M** |
| ~~P0~~ **DONE** | WPA2 on the SoftAP | Shipped, opt-in, default off (NVS `ap_secure`). Encrypts dashboard, SIP *and* RTP in one change. | N/A |
| ~~P0~~ **DONE** | SIP digest auth (RFC 2617) | Shipped and operable via `/api/registrar` + the `cfgseed` `regMode` field. See the P0 above for what is left. | N/A |
| ~~P1~~ **DONE (#530)** | **Per-IP brute-force tracking on login** | **Wired since #530**: `req.clientIp` is set on every request. Residuals: the per-principal aggregate backstop still lets one address lock the admin out after 20 failures (THREAT_MODEL D-3), and web-login keys can evict the DTMF PIN's bucket (#561). | **S** |
| **P1** | **Sign the OTA image** | Images are unsigned; the only controls are the admin session and the local link. | **S** (interim gate) / **L** (real signing) |
| **P2** | **Secure Boot v2 + flash encryption + signed OTA** | Durable fix for the physical/supply-chain boundary; encrypts NVS at rest (Wi-Fi password, admin hash, **carrier API secrets**, which now exist and did not when this row was written). One-way eFuse burn, so it needs a secured factory flow. | **L** |
| **P2** | **Optional self-signed HTTPS for the dashboard** | Still not the primary control. Browser-warning UX is bad on a LAN appliance, TLS costs MCU RAM/CPU, and it protects only the dashboard. Documented add-on **on top of** WPA2. | **M** |
| **P2** | **SRTP** | App-layer media encryption. WPA2 already encrypts media at the link layer for far less. Low priority given how little media the board carries. | **L** |

### 3.4 Developer / ops experience

| Pri | Item | Rationale | Complexity |
|-----|------|-----------|------------|
| **P0** | **Exercise the untested paths on hardware** | Per §2: `440`, voicemail and the SIP-trunk relay have never run on hardware, MoH audio has never been verified, and no real handset has fetched its own provisioning file. `888` has run once and panicked (#498); its fix (#499) is merged and needs the re-run. OTA has now been run once (#395). Each is a bench session, not a feature. Doing them is how §1's claims stop being claims. | **S–M** (test) |
| **P1** | **Provisioning dashboard editor** | MAC→ext map, adoption window, capacity meter against `MAX_CLIENTS`, per-MAC token regen. The registrar roster is already surfaced; this is the editing half. | **M** |
| **P1** | **Confirm the Yealink key set against a handset** | The `.cfg` renderer has never been validated by a phone consuming it. A T29 is now on the bench, so this is finally testable. | **S** (test) |
| **P2** | **DHCP Option 66 true zero-touch** | Removes the typed URL. Requires forking the bundled `dhcpserver`; IDF-version-sensitive. | **M–L** |
| ~~P2~~ **DONE** | **Multi-vendor provisioning** (Grandstream / Polycom / Cisco SPA) | **Shipped (#177, routing #234)**, ahead of the Yealink confirmation this row said it should wait for. None of the four renderers has been confirmed against a physical handset; see the row above. | N/A |
| ~~P1~~ **DONE** | Live SIP tracer + PCAP export | Shipped: `/api/trace`, `/api/pcap`, `/api/diagnostics/pcap`, and a trace terminal in the dashboard. | N/A |
| ~~P1~~ **DONE** | Zero-touch provisioning MVP | Shipped, with the Open-mode caveat in §2. | N/A |

## 4. Suggested sequencing

```
Iteration A  ── Make the claims true (highest leverage, lowest novelty)
  P0  Bench-verify on-device RTP beyond the anchor bridge, and a real provisioning fetch
      (OTA: done once on hardware, #395) .............................. §2's bottom half
  P1  Confirm the Yealink .cfg against the T29 now on the bench
      └─ These are test sessions. They gate how much of §1 anyone should trust.

Iteration B  ── Close the default-posture gap
  P0  Registrar default: DONE, ships `learn` and `open` is retired (#441, #502)
  DONE Per-client login lockout (#530: clientIp is set on every request)
  P1  Sign the OTA image (or, interim, keep it gated and say so loudly)
      └─ Digest auth already exists. This is onboarding, not cryptography.

Iteration C  ── Ops primitives the config surface has outgrown        (mostly DONE)
  DONE Config import/export (#186) · NVS schema versioning (#181) · /metrics · syslog
  DONE Task watchdog (#185, #235)
  P1   Make OTA mark-valid wait on a health signal, not a 5 s timer

Iteration D  ── Dialling that survives contact with the real world
  P1  Outbound E.164 normalization .. trunk strip/prepend is not a dial plan
  P1  Session timers, active side
  P2  Trunk failover between telephony slots

Iteration E+ ── Bigger bets
  P2  Provisioning dashboard editor · DHCP Opt-66 · multi-vendor renderers
  P2  Secure Boot v2 + flash encryption + signed OTA
  P2  Multi-AP/mesh · optional HTTPS · SRTP · conference rooms with PINs
```

Why this order:

- **Verification first** because the project just crossed from "tested" to "tested and, in
  one narrow path, *true*". The gap between those two words is now the largest risk in the
  codebase, and closing it costs bench time rather than design.
- **The registrar default before any new hardening** because the expensive part (digest
  auth, Learn mode, the MAC lock) was already built. Done: Learn is the default (#441) and
  `open` is retired (#502).
- **Config export before the config surface grows again.** Done (#186), with the carrier
  credentials in a password-encrypted block; what it still cannot restore (MAC bindings)
  is listed in §3.2.
- **Outbound E.164 after trunking, not with it.** Trunking works today for one dial habit.
  The normalizer already exists for inbound DIDs (#165); applying it outbound is a real
  feature and deserves its own slice rather than being smuggled into the strip/prepend rule.
- **Observability rides existing infrastructure** (snapshot, `_logQueue`, atomic counters),
  so it adds no new locking on the RT path, which is exactly why it stays cheap and stays
  P1 rather than P0.

## 5. Explicitly out of scope / non-goals

Ruled out *for technical reasons*: they conflict with the static-pool, minimal-DSP
architecture, or, in a couple of cases, simply absent and not planned.

| Non-goal | Why |
|----------|-----|
| **IVR / auto-attendant, call recording, call queues/ACD** | All of them require the board to hold and source media for the duration of a call, at a scale the deliberate 4-leg conference cap already shows is the ceiling. Absent, and not planned on-MCU. (The voicemail retrieval menu on `796` is the only menu, and it is not a general IVR.) |
| **On-MCU transcoding** | No DSP budget. The engine narrows the codec list and lets the endpoints agree; it does not translate between them. |
| **Time-based routing, follow-me, speed dial, blacklists, barge/whisper/monitor** | Absent. Each is cheap signalling work in isolation; none is built, and the dial plan is deliberately a 16-rule table rather than a rules engine. |
| **CDR export / billing** | The CDR is a 32-record NVS ring read over `GET /api/cdr`, plus, on SD builds, a per-day CSV archive on the card (§1.1). There is no download/export route for the archive, no persistence across a factory reset (both are wiped), and no billing model. |
| **Fax / T.38, video** | Absent. T.38 would need a media path with timing guarantees this board does not offer. |
| **Multi-tenancy** | One registrar, one flat extension space, one conference room. Not a gap, a scope boundary. |
| **E911 location, emergency pre-emption** | Emergency *dialing* exists (§1.1, #166): `911`/`9911`/`933` bypass the dial plan and are always routed out, trigger an on-site notification, and get a `503` rather than a `404` when there is no route. What does **not** exist: **no location is conveyed to the PSAP** (`EmergencyNotifier.hpp:56`), an emergency call **does not pre-empt** a busy anchor slot, and it is routed **only** via the anchor path (`originateAnchorCall`), never the SIP trunk. **On a board with no real anchor provider configured (the default), that anchor is the `LoopbackAnchorClient`, which reports itself connected and simulates an answer** (`LoopbackAnchorClient.cpp:38-42`, `:136-143`), so the emergency call never leaves the box; `tests/EmergencyDialing_test.cpp:218-227` exercises exactly that route (#521). Do not deploy this as anyone's only means of calling for help. |
| **TLS/SIPS signalling and SRTP as primary transport security** | On a LAN appliance, self-signed certs trigger browser warnings, cost MCU RAM/CPU, and protect only one leg. WPA2 encrypts dashboard, SIP and RTP together for far less. HTTPS/SRTP remain documented *optional* add-ons (§3.3). |
| **WebRTC NAT traversal (ICE/TURN); TURN relay on-MCU** | Peer-mesh/WebRTC tools, and a TURN *server* would put N relayed media streams on the MCU. |
| **Cloud control plane / remote management** | The device is intentionally self-contained. Note the asymmetry: the *outbound* path deliberately depends on a vendor API or an ITSP's SIP trunk, but nothing reaches *in*. |
| **Unbounded dynamic allocation for "scale"** | Capacity is set by static pools by design; "scale up" means picking a tier or a wired board, not removing the pre-allocation that guarantees a fragmentation-free hot path. |
| **DHCP Option 43 multi-vendor provisioning** | Brittle per-vendor TLV encoding; rejected in favour of an Option-66 `dhcpserver` fork. |

> **Removed from this section (2026-06-09 → 2026-09-13):** "on-MCU media mixing /
> conferencing wired into live calls" was listed here as a non-goal *while `MixBus` was
> simultaneously described in §1 as wired up and dialable as `888`*. The §1 description was
> the correct one. On-MCU mixing is shipped, capped at 4 legs, and is an opt-in exception to
> the peer-to-peer default rather than a violation of it. Likewise "wideband / G.722
> negotiation" was listed as a non-goal; relayed peer-to-peer legs **do** admit G.722 today,
> and only the legs the board terminates itself refuse it.
>
> **Removed 2026-09-27 (#401):** "Voicemail (on-device record/playback)" and
> "music-on-hold" were listed here while both had shipped: on-device voicemail (#246) and
> MoH on park and on held anchor calls (#162, #218), both in §1.2. "Special 911 / emergency
> handling: there is none" was replaced by what is actually missing, because emergency
> dialing (#166) exists; the do-not-rely-on-it warning stays.

## 6. Top 3 recommendations (next-up)

1. Bench-verify the untested paths: `440`, voicemail, MoH audio, the SIP-trunk relay, and
   a real handset fetching its own `.cfg`; and re-run `888` now that its panic fix has landed
   (#498, #499). OTA has now been proved once on hardware (#395); the rest of §1 is still host-test
   confidence, and a few bench sessions would convert most of it.
2. **Registrar default: resolved.** A fresh board boots Learn (#441), `open` is retired
   (#502), and Learn challenges a Secured device's INVITE (#512). The INVITE half is not
   fully closed: a Learned extension's INVITE is admitted unchallenged, and binding it to
   the caller's registered address is #503.
3. **Make emergency dialing honest on a default board.** A `911` on a board with no real
   anchor provider is answered by the loopback simulator (§5, #521), which is worse than the
   `503` it gets when no anchor is connected at all.

(Config import/export, the previous third item, shipped in #186. Outbound E.164
normalization is the strongest remaining *telephony* item: trunking works today for
exactly one dial habit.)
