# HTTPS for the dashboard (#179): design for vote, no code

Status: Proposed, for vote. Nothing here is built or decided. Baseline: `main` at 7bcf952f (2026-10-09); every `file:line`
is at that commit. `HS.cpp`/`HS.hpp` = `src/Helpers/HttpServer.{cpp,hpp}`, `SD` = `sdkconfig.defaults`,
`TM` = `docs/THREAT_MODEL.md`, `CF` = `CONTRIBUTING_FIRMWARE.md`. "IDF" paths are the local `~/esp/esp-idf-v6.0.1/components/`.

## 1. Problem and the stated use case

The issue: the dashboard is plain HTTP; "some sites need HTTPS for policy". It asks for an opt-in `https_enabled`
NVS key, a self-signed cert generated at first boot and kept in NVS, the fingerprint in `/api/status` for pinning,
HTTP left on, and one PSRAM-backed TLS context, off by default "because of the heap cost". It notes `HttpServer` is
hand-rolled, so this is "a wrapper at the accept/recv layer, not a component swap". The author's 2026-09-14 comment:
this must not be framed as a security fix; TM section 6 (`TM:434-487`) has four standing objections (warning UX,
RAM/CPU, cert provisioning, protects only the dashboard); the honest scope is "wired sites with an HTTPS policy
requirement", because WPA2 is the lever for the SoftAP and the Ethernet builds have no AP (`TM:485-487`). The
2026-10-09 comment: no PR on purpose, committee verdict DEFER (#942), blocker is design (PSRAM task + static pool).

Real:
- **The gap.** No TLS in the server: "zero mbedtls/esp_tls references" (`HS.hpp:66-67`). It is a raw-socket server
  (`HS.cpp:157-194` socket/bind/listen, `:415` accept, `:492-505` thread per connection). Wired builds have no link-layer
  lever (`TM:485-487`), so HTTPS would be their only transport control.
- **What crosses the wire in clear:** the admin login, the `pd_session` cookie (no `Secure` flag, `HS.cpp:5447-5450`),
  the CSRF token, SMTP/telephony config, and the E911 notify list, callback number and location. The E911 settings are
  PII (`HS.cpp:4670`); they are written by `PUT /api/e911-config` (`HS.cpp:1232-1238`), and the form is pinned by
  `tests/DashboardE911Form_test.cpp:11-23`.

Speculative:
- **"Some sites need HTTPS for policy."** No site, no policy text. The open question that decides the option: does that
  policy accept TLS terminated by a proxy in front of the board, or must the device terminate it? (Section 8.)
- **Pinning by fingerprint.** A browser cannot pin a self-signed cert; only an API client can. And a fingerprint read
  from ungated plain-HTTP `/api/status` (`HS.cpp:925`) is circular: whoever can forge the page can forge the digest.
  It needs an out-of-band path, as `ap_psk` has (LVGL screen, serial: `TM:475-476`).
- **"One PSRAM-backed context."** No measurement exists in the tree. PSRAM placement does not address the task stack
  or the CPU cost (section 3 and 5).
- **"Generated at first boot, stored in NVS."** Needs Kconfig the build does not have (section 3) and puts a private key
  in NVS, which is not encrypted (no `NVS_ENCRYPTION`/`FLASH_ENCRYPTION` hits in `SD*` or the docs by grep). Same
  exposure class as `ap_psk`; factory reset must erase it (pattern `src/Helpers/DeviceConfig.hpp:246`).
- **Confidentiality, with "HTTP stays on".** Cookies are scoped by host, not port, and `pd_session` is not `Secure`, so a
  session begun over HTTPS is also sent over plain HTTP. The TM 5.3 replay risk is unchanged until the cookie is
  `Secure`, which splits HTTP and HTTPS into separate sessions (a UX cost). HSTS stays off (`HS.cpp:1619-1621`).
  HTTPS here defends against passive sniffing and nothing stronger.

## 2. Current state on main

- Listener: one socket, `INADDR_ANY`, backlog 8 (`HS.cpp:173-190`). Accept loop on the 8 KB accept thread (`:376-522`).
- Connections: detached `std::thread` each (`:492-505`), stack 4096 B internal (`HS.hpp:72`, set at `HS.cpp:363-366`;
  measured use ~2752 B, `docs/API.md:972`). Global cap 4 (`HS.hpp:99`), per-source cap 3 (`HS.hpp:110`, `HS.cpp:467-476`),
  10 s read deadline (`HS.hpp:111`). The 4 KB figure was fitted to the heap: at the 8 KB default, largest free block
  oscillated 7,924-9,204 B and thread creation failed (`HS.hpp:55-64`).
- Allocation: per request `std::vector<char> buf(4096)` (`HS.cpp:695`) and `std::string raw` (`:714`); 26 on-device
  `std::ostringstream` JSON builders (27 hits, one is host-only, `:1763`). Since #410 the response path is in place:
  head ranges plus body go out in one `sendmsg()` (`HS.cpp:1671-1738`) and `/api/status` uses buffers allocated once
  (`HS.hpp:115-121`, `HS.cpp:144-147`).
- I/O sites a TLS shim must replace: `recv` at `HS.cpp:700/702`, `860/862`, `6511/6513` (the OTA/MoH streaming path);
  `send`/`sendmsg` at `:1725/1732`, `:1745/1747`; plus the `SO_RCVTIMEO`/`SO_SNDTIMEO` helpers (`:297-315`, `:682`).
  `sendmsg` scatter-gather has no TLS equivalent; pieces must be coalesced into records.
- Handlers on those threads write flash: `PUT /api/e911-config` -> `PbxFeatureConfig.cpp:786-820` (`persistE911`),
  Wi-Fi credentials (`HS.cpp:4508-4511`), OTA (`OtaUpdater.cpp`, `esp_ota_write`).
- Auth: `requireAdmin` = same-origin, session, CSRF (`HS.cpp:4278-4313`). `isSameOrigin` strips the scheme
  (`:4177-4181`) and accepts only the device IP, `192.168.4.1`, `pocketdial.local`, `localhost` (`:4195-4203`).
- HTTP cannot be unbound: phone provisioning profiles point at `http://` (`HS.cpp:3268`), the captive-portal redirect is
  `http://192.168.4.1/` (`:904`), `/metrics` is scraped ungated (`:944`).
- mbedTLS: `MBEDTLS_DYNAMIC_BUFFER` and `EXTERNAL_MEM_ALLOC` are on (`SD:220-221`); the note that a 4th concurrent TLS
  context alloc-failed on internal RAM (`mbedtls_ssl_setup -0x008D`, drawbridge #94) is at `SD:211-217`.
- TLS workers already in PSRAM (and they may never flash-write, `PsramTask.hpp:31-37`): `smtp_worker`, 12,288 B, one TLS session in flight (`SmtpClient.cpp:575-579`,
  `SmtpClient.hpp:101-103`); anchor `tel_wsw`, 12,288 B (`TelephonyAnchorClient.cpp:2507-2511`), `tel_prewarm` 6,144 B
  (`:277`). Created by `pd::createTaskPreferPsram` (`src/SIP/PsramTask.hpp:95-113`). The anchor holds 3 persistent TLS
  sockets plus 2 per call slot (`SD:196-199`); slots default to 4 (`src/SIP/PoolConfig.hpp:292-294`; `SD:206-207`
  still says 1, stale). TM section 6 calls HTTPS a "documented optional" layer, not the primary control (`TM:438-443`).

## 3. Memory budget

**Internal DRAM (S3).** Most recent measurement: v1.5.0 release soak, 4.6 h, lowest free internal 110 KB, smallest
idle largest block 53 KB (`CHANGELOG.md:33`; "test rig", dashboard over plain HTTP, no TLS server). Older, on `.244`
at #366/#368, before the PSRAM moves: ~27.7 KB total free, largest block 7.9-9.2 KB, and 8 concurrent connections at 8 KB
stacks took the minimum to 7,412 B, 12 caused DMA allocation failures (`HS.hpp:55-64`, `:85-93`). The number moves
by 4x between eras; the bench must measure the target. Release-soak floors: 16,384 B free, 8,192 B largest block
(`tools/soak/soak_verdict.py:71-72`). Not used: `SCALING.md:106` (290-320 KB, plain ESP32), `BENCHMARKS.md:131-135` (modeled).

**One TLS session.** The sdkconfig notes give a failure, not a byte count: the 4th concurrent context failed on
internal RAM before `DYNAMIC_BUFFER` + `EXTERNAL_MEM_ALLOC` (`SD:211-217`). Bytes are derived, not measured:
- Record buffers: `IN_CONTENT_LEN` 16,384 + `OUT_CONTENT_LEN` 4,096 = 20,480 B. Source: a built S3 `sdkconfig`
  (`~/w/c699-build-heap-poisoning/sdkconfig`, 2026-09-28, an old worktree, not main HEAD); IDF defaults match
  (`mbedtls/Kconfig:209-225`). Browsers do not negotiate smaller fragments, so IN stays 16 KB.
- With `EXTERNAL_MEM_ALLOC`, every mbedTLS allocation is PSRAM-only (`mbedtls/port/esp_mem.c:18-19`).
- Planning figure: **40 KB PSRAM per session** (2x the buffers, for context, handshake and cert chain). Unmeasured.
- Internal cost per session: one TCB (`StaticTask_t` is always internal, `PsramTask.hpp:145`), one lwIP socket (pool of
  48, `SD:209`), TCP rx buffers, and transient AES-GCM DMA descriptors from internal DMA memory per call (IDF
  `mbedtls/port/aes/dma/esp_aes_dma_core.c:459,1091,1264`). By reading the code, not by measurement.
- Stack: no handshake stack figure exists. Every TLS path in the tree gets 12 KB (`SmtpClient.cpp:575-579`,
  `HS.cpp:6735-6741`); the connection thread has 4 KB.

**Pool size.** One session slot to start (section 5): 40 KB + 12 KB stack = ~52 KB PSRAM, 0.6% of 8 MB. Two: ~104 KB.
Matching the plain cap of 4 is ~208 KB (2.5%) but allows 4 simultaneous software handshakes, which the S3 cannot afford.

**Why a static pool is required.** Thread-per-connection (`HS.cpp:492-505`) means each TLS connection creates a task.
- Internal stack: 4 x 12 KB is ~49 KB of the 110 KB lowest-free, and it needs 12 KB contiguous when the largest block was
  7.9-9.2 KB (`HS.hpp:55-64`): the "pthread: Failed to create task!" failure already seen once.
- PSRAM stack for the handler: forbidden, because these threads run NVS and OTA writers (section 2, `PsramTask.hpp:31-37`).
- Static pool: the pump task's stack and TCB are allocated once at boot with `pd::StaticTaskSlot`
  (`PsramTask.hpp:130-166`; a failed allocation leaves TLS off, logged, never a crash); the `ssl_context`, `ssl_config`
  and parsed cert/key are built once at init; sessions are reused with `mbedtls_ssl_session_reset`.
- What "static" does not mean: `CF:18` ("No Dynamic Allocation") is scoped to the `RequestsHandler` path and packet loops.
  `HttpServer` already allocates per request (section 2). This design keeps internal DRAM allocation-free after init
  (slots static, mbedTLS PSRAM-only), but PSRAM is still allocated per handshake and, with `DYNAMIC_BUFFER`
  (`SD:220`; IDF `Kconfig:227-242`), per record. A literal zero needs `DYNAMIC_BUFFER` off, which is global to the SMTP and
  anchor clients. Not proposed. If the vote wants the literal rule, say so.

**Does it close?**
- **ESP32-S3 with PSRAM (S3R8): yes on RAM, conditionally.** PSRAM is ~1% for one slot (the S3 images require 8 MB OPI,
  `SD:14-52`). Internal closes only if the TLS task is a pump with a PSRAM stack, one handshake at a time, and the
  admission gate in section 5 holds. The binding limit is CPU, not memory: software ECDHE is ~1 s per handshake with no
  ECC block, and past ~4 simultaneous handshakes both cores saturate and the task watchdog fires
  (`PoolConfig.hpp:283-291`); `TASK_WDT_PANIC=y` turns that into a reboot (`SD:310`).
- **Classic ESP32 constrained profile: no.** `SPIRAM=n` (`sdkconfig.defaults.esp32_constrained:20-21`); `EXTERNAL_MEM_ALLOC`
  depends on SPIRAM malloc support (IDF `Kconfig:158-160`), so the 20 KB+ buffers would be internal; the internal budget is already
  counted to the byte (`main/CMakeLists.txt:284-289`) and the 4 MB app slot is full (`:298-304`). HTTPS is compiled out there.
- **Cert generation needs new Kconfig.** `MBEDTLS_X509_CREATE_C` is unset in the built S3 config (IDF `Kconfig:392-410`)
  and absent from `SD`; enabling it, plus `X509_CRT_WRITE_C`, adds flash. Use ECDSA P-256, not RSA.

## 4. Options

(a) is not viable as worded. A TLS connection cannot run `handleClient` on a PSRAM stack (flash writers, section 2), and
the 4 KB internal stack cannot be assumed to hold a handshake (every TLS path in the tree gets 12 KB, and `/api/status`
already uses ~2752 B of the 4096). The only workable variant splits the roles, and that variant is (b)-shaped.

| | (a) TLS inside HttpServer | (b) Separate TLS terminator, own port | (c) No board HTTPS, documented proxy |
|---|---|---|---|
| Shape | Pump task owns TLS; `handleClient` reads/writes through a ring-buffer adapter; same accept loop | New `TlsFront`: own listen socket (e.g. 8443), one PSRAM pump task, forwards plaintext to `127.0.0.1:<http port>`; `HttpServer` unchanged | Reverse proxy (Caddy/nginx) on a wired-LAN host with the site's own CA |
| Firmware cost | ~8 edits in the E911-serving path (`HS.cpp:700,860,1732,1745,6511,297-315,682`) + rings + all of (b)'s pump | New file(s) + Kconfig + NVS keys; `HS.cpp` gets one small change (trusted peer header) | None. A docs page |
| Risk | High: every request, including `GET /` and the E911 PUT, goes through new code | Medium: plain path is byte-identical when off; new risk is isolated to the terminator | Low for the board; moves risk to site infra |
| Real cost items | Coalescing `sendmsg` pieces; ring sizing; peer address stays real | 2 lwIP sockets per session; loopback hides the client address (below) | Proxy must rewrite `Host` and `Origin` (below) |
| Dashboard needs | `Secure` cookie on TLS, status fields, UI toggle/fingerprint, API.md + API_TESTS.md (`CF:30`) | Same as (a) | Nothing in firmware if the recipe works; one docs page |
| Trust story | Self-signed: click-through warning (TM objection 1, 3) | Same | Site CA: no warning. Objections 1 and 3 go away |

Costs that apply to (b) and (c) alike:
- **Client address.** Every proxied or looped-back connection reaches `HttpServer` from one address. The per-source cap (3 of 4
  slots; keyed on the `accept()` peer before any byte is read, `HS.cpp:467-476`) and the login brute-force bucket (`:657-676`)
  both collapse: one attacker's failed HTTPS logins lock out every HTTPS user. (b) can re-key only the login bucket, via a peer
  header `HttpServer` trusts only from loopback; `TlsFront` enforces its own per-source limit at its accept (trivial with a
  pool of 1), and `HttpServer` sees TLS as one source, which invariant 3 relies on. (c) can do neither; the proxy must rate-limit.
- **Host and Origin.** `isSameOrigin` has a fixed host list (`HS.cpp:4195-4203`) and the captive check 302s any other
  `Host` to `http://192.168.4.1/` (`:896-904`). A proxy at `dash.example.com` breaks every mutating call until it rewrites
  both headers to a name the device accepts.
- **Cleartext hop.** (c)'s proxy-to-board hop is plain HTTP, acceptable only on a protected segment; :80 stays open unless firewalled.

## 5. Rule 5: dashboard TLS must not hurt an emergency call

Rule 5, as the repo states it in test comments: "nothing may delay or refuse an emergency call"
(`tests/TelephonyAnchorLogic_test.cpp:685-686`). The formal rule text is not in the repo. The dashboard hosts the E911 form, so
two properties are required: the form stays reachable, and TLS never costs the call CPU or RAM.

Invariants for (b), none optional:
1. **Plain HTTP is independent of TLS.** TLS off, cert missing, slot allocation failed, PSRAM exhausted or gate refused: the
   plain listener, `GET /` and `PUT /api/e911-config` behave exactly as today.
2. **No HTTP-to-HTTPS redirect, no `https_only`, no HSTS** (`HS.cpp:1619-1621`). Making the E911 form depend on browser cert
   acceptance would put TLS health in the emergency-config path.
3. **TLS sessions come out of the existing 4-slot cap** (`HS.hpp:99`); they arrive from loopback, so at most 3 of 4
   (`HS.hpp:110`). One slot is always left for plain HTTP.
4. **Cert generation and rotation** run on an ordinary-stack task, never the PSRAM pump (`PD_ASSERT_NOT_PSRAM_STACK()`,
   `PsramTask.hpp:64-72`), lazily on first enable (not at boot), and are refused while an emergency call is live, like
   factory reset and reboot (`HS.cpp:4573`, `:7387`).

**The check that stops a handshake draining internal RAM during a call.** One pure function, `admit(state) -> Admit |
Refuse(reason)`, evaluated on the terminator's accept thread before the slot is claimed and before any handshake bytes are
read, and again between handshake steps (`mbedtls_ssl_handshake_step`; worst-case residual is one crypto step). In order:
1. Flag on and the single slot is free (pool = 1), else refuse `busy`.
2. `hasLiveEmergencyCall()` is false, else refuse `emergency`. Hard, not configurable. It takes the registrar mutex
   (`RequestsHandler.hpp:477-481`), fine at one call per accepted connection, as the HTTP handlers already do; a lock-free
   atomic published by `RequestsHandler` is preferable (`CF:278`) but is a Rule 5 file and a separate reviewed change.
3. Anchor TLS handshakes in flight leave headroom under the ~4-handshake ceiling (`PoolConfig.hpp:283-291`), else refuse
   `cpu`. Needs a counter in `TelephonyAnchorClient` (a second change in Rule 5 code). Until it exists, the first enabled
   build refuses while any call session is live.
4. `freeInternal >= 16,384 + measuredHandshakePeak` and `largestBlock(INTERNAL|DMA) >= 8,192 + measuredHandshakePeak`
   (floors from `soak_verdict.py:71-72`; the peak is a bench output), and PSRAM free >= 2 sessions, else refuse `heap`.

Refusal is a TCP close with no handshake (no 503 inside TLS), counted per reason in `/api/status`. Priority: the pump runs
below the anchor workers and SMTP (prio 4) and SIP (prio 5, `main/esp_main.cpp:543`), at 3, never on core 1 on display builds
(`CF:277`). Established sessions are not torn down when a call starts (HW AES/SHA, small cost); only new handshakes are gated.

## 6. Recommendation

**Recommend (c) now, with (b) as the only on-device shape, built only if a named site requires device-terminated TLS.
Reject (a).** Reasons: the stated use case is wired sites with an HTTPS policy, and those sites run proxies and internal CAs.
(c) gives them a certificate people will not click through, costs no RAM, CPU or flash, and touches no Rule 5 code.
Device-terminated self-signed TLS keeps TM section 6 objections 1 and 3 and buys only passive-sniffing protection while
HTTP stays bound. (b) is designed here so the decision can flip without a new design round.

**Smallest honest first slice.**
- Slice 0 (recommended, docs only): a reverse-proxy recipe (`Host` and `Origin` rewrite, `Secure` cookie flag added at the
  proxy, firewall :80 to the proxy, own rate limits), linked from TM section 6 with "verdict unchanged, optional layer".
- Slice 1 (only if the poll picks (b)): inert plumbing, host-tested. `https_enabled` u8 NVS key, default false, copied from
  `ap_secure` (`DeviceConfig.cpp:54-55`), erased by factory reset; `formatFingerprint(const uint8_t digest[32])` -> `AA:BB:..`
  (takes the digest, so no SHA-256 is needed in the test); `httpsEnabled:false` and `httpsFingerprint:""` in `/api/status`;
  the pure `admit()` with its table test.
- Slice 1 does not do: TLS, cert, key, listener, Kconfig change, or anything an operator can see. Do not land it unless (b) is chosen.

## 7. Test plan

Host-testable (CMake gtest, per `CF:283` onward; HTTP test ports from a new disjoint block, `CF:348`):
1. `admit()` table: emergency live refuses regardless of every other input; each refusal reason alone; slot busy; floors at
   boundary, one below, one above; refusal happens before slot claim.
2. `formatFingerprint`: fixed 32 bytes -> exact 95-character string; all-zero and all-0xFF. `DeviceConfig`: `https_enabled`
   defaults false, round-trips, erased by factory reset (pattern `DeviceConfig_test.cpp:60-76`).
3. Cookie builder: `Secure` iff the connection is TLS; `HttpOnly` and `SameSite=Strict` always.
4. Trusted peer header: honored only from `127.0.0.1`, ignored from any other source; re-keys the login bucket
   (`HS.cpp:657-676`) and nothing else.
5. `isSameOrigin` with an `https://` origin and matching Host passes, wrong host fails (pins the scheme-blind behavior, `HS.cpp:4177-4181`).
6. Invariant 1: flag on and pool refusing, `GET /` and `PUT /api/e911-config` on the plain port still succeed (extends
   `DashboardE911Form_test.cpp`). A static check that the key-persist path calls `PD_ASSERT_NOT_PSRAM_STACK`.
Not host-testable: handshake, PSRAM placement, stack high-water, CPU, browser behavior.

**Bench plan (later, after the poll; S3R8 rig; 933 only, never 911, never over a real trunk):**
- B1 baseline: idle `freeHeapInternal`, `largestFreeBlockInternal`, `freeHeapDma`, `minFreeHeapSpiram` (`docs/API.md:843-850`).
- B2 one session: handshake wall time and CPU, internal and PSRAM delta at handshake and steady state, pump stack
  high-water. This replaces the 40 KB planning figure and the 12 KB stack assumption.
- B3 refusal drill: with a 933 call up, fire handshakes from two hosts; expect only counted refusals, no RTP glitch, no
  watchdog, no reboot, `minFreeHeapInternal` above the soak floor. Repeat with internal heap pinned near 16 KB using the
  ballast fault (`docs/BENCH_PROBE.md:52`, `tools/bench/bench_fault_runner.py:276`).
- B4 soak: >= 4 h with a browser polling `/api/status` over TLS every 2 s; `soak_verdict.py` gates (slope >= -1024 B/h).
- B5 browsers (Chrome, Firefox, Safari click-through; `Secure`/`__Host-` cookies after an accepted warning), first-enable
  keygen time, a power cut during key persist, NVS headroom, factory-reset erase.

## 8. Decision asked (poll)

Question: how should #179 proceed? The question that flips the answer: does a wired site's HTTPS policy accept TLS
terminated by a proxy, or must the device terminate it?
- **A (recommended).** (c) now. Publish the proxy recipe (docs only), keep #179 DEFER post-prod with this document as the
  design of record. Revisit (b) when a named site requires device-terminated TLS.
- **B.** (b) on S3R8 only, post-prod: slice 1, then a bench spike (B2), then the default-off feature. Needs three explicit
  approvals: the Kconfig change (`X509_CREATE_C`), reading `CF:18` as scoped to `RequestsHandler`, and the Rule 5 file
  touches in gate steps 2 and 3.
- **C.** Close #179 as not planned. TM section 6 stands; WPA2 on the SoftAP covers wireless; wired sites get nothing.

## 9. Not verified

- No byte cost for a TLS server session exists in the repo. 20,480 B is arithmetic on build-config values, from an old S3
  worktree config, not main; 40 KB and the 12 KB handshake stack are planning figures.
- The ~1 s software-handshake cost and the ~4-handshake ceiling are the repo's drawbridge-era client-side claim
  (`PoolConfig.hpp:283-291`). Server-side ECDSA P-256 sign + ECDHE on this S3 is not measured.
- 110 KB / 53 KB come from one release soak on an unnamed "test rig" with no TLS server; board model not stated.
- AES-GCM DMA descriptor churn is from reading IDF code, not a heap trace. Browser handling of `Secure`/`__Host-` cookies
  after a cert-warning click-through is untested. NVS headroom (partition 0x6000, `partitions.csv:94`) and the flash cost of
  X509 write support are unmeasured.
- Nothing was built or run; no host test was executed; the slice 0 recipe is not written or tried.
- Doc drift found, not fixed here: `SD:206-207` says anchor slots ship at 1 (`PoolConfig.hpp:292-294` says 4);
  `SCALING.md:102-106` and `:191-197` disagree on whether the pools sit in PSRAM or internal DRAM; `TM` E-2 cites route
  lines `:457`/`:471`, now `HS.cpp:911`/`:925`; `CF:26` cites `HttpServer.cpp:3115-3123` for `sendRedirect`, now `:7417-7426`.
- The #942 committee findings are model-written reviews, not measurements.
