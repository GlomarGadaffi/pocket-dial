# Threat Model: pocket-dial ESP32 SIP PBX

**Date**: 2026-09-13 | **Version**: 2.0 | **Author**: Security Engineering | **Phase**: 1 (production hardening)

This document is a STRIDE-structured threat model for the **pocket-dial** ESP32 SIP PBX
and its HTTP dashboard. It focuses on the locally-reachable attack surface of a small
appliance that, by default, **runs its own open WiFi access point** and an **open SIP
registrar**. It complements the broader `docs/SECURITY_AUDIT.md` (which tracks
CVSS-scored findings) and records the authentication layer that closed the originally
**unauthenticated admin** hole (audit finding SEC-04): every state-changing dashboard
endpoint now requires a login session plus a per-session CSRF token, and the device
refuses to do anything else until the shipped default credential is replaced.

> [!IMPORTANT]
> **Two mechanisms earlier revisions of this document described are GONE.** If you
> half-remember them, this is the correction:
> 1. **There is no dark-by-default HTTP admin plane and no `*4887` DTMF star-code.**
>    The listen socket opens at construction and stays open for the life of the process,
>    regardless of provisioning state (commit `de1a36e`) — the bounded admin-open window,
>    `grantAdminHttpGraceWindow` and `POST /api/admin/keepalive` were all deleted with it.
>    The gate caused a real hardware lockout (the dashboard went "connection refused" the
>    instant a client registered), so **"connection refused" is now always a genuine fault,
>    never an expected security gate.**
> 2. **The admin credential is a username + password, not a PIN, and `POST
>    /api/admin/set-pin` does not exist.** The route is `POST /api/admin/set-credential`.
>    A *separate* numeric DTMF PIN still exists but is only the phone-keypad admin menu's
>    secret (§5.5) — it is not the web credential and has no default.
>
> Source of truth: `src/Helpers/AdminAuth.{hpp,cpp}`, `HttpServer::requireAdmin()`, and
> `docs/API.md` §0.

---

## 1. System Overview

- **Device**: ESP32 / ESP32-S3 microcontroller, single firmware image.
- **Role**: Self-contained SIP PBX — registers SIP extensions, bridges calls, carries
  RTP audio (G.711 / PCMU/PCMA).
- **Transports** (build-time `SIP_TRANSPORT`):
  - `wifi` — device hosts a **SoftAP** (its own WiFi network) and/or joins a station network.
  - `eth` — W5500 Ethernet (PoE); the device is a node on a wired LAN.
  - `display` — SoftAP + local touchscreen UI (LVGL) with captive-portal onboarding.
- **Listening services**:
  | Service | Port | Proto | Purpose |
  |---------|------|-------|---------|
  | HTTP dashboard | 80 (device) / 8080 (host) | TCP | Status, call control, WiFi provisioning, **admin auth** |
  | SIP | 5060 | UDP | Registration, INVITE, OPTIONS, session control |
  | RTP | dynamic | UDP | Media (G.711) |
  | DNS (captive portal) | 53 | UDP | Resolves all names to the device IP during onboarding |

  The HTTP listener is opened in the `HttpServer` constructor and is **never closed or
  conditionally opened** — reachability is not a security control here; `requireAdmin()`
  is (§5.1). On `wifi`/`eth`/`lan8720` builds the *SIP* stack, by contrast, is held down at
  boot until an admin credential is committed; the `display` build deliberately is not
  (§5.1, "up usable, secure later").
- **Persistence**: ESP-IDF **NVS** flash, in two namespaces.
  - `"storage"` — WiFi mode/SSID/password, the SoftAP security flag/passphrase
    (`ap_secure`, `ap_psk`), a captive-portal `decayed` flag, the one-way `provisioned`
    boot flag, and the admin credential: `admin_user`, `admin_pw_salt`, `admin_pw_hash`
    (the web login) plus `admin_pin_salt`, `admin_pin_hash` (the separate DTMF menu PIN).
  - `"pbxcfg"` — PBX config, including the registrar admission mode `reg_mode` and the
    DTMF admin extension `admin_ext` (default `1001`). **`reg_mode` is in `pbxcfg`, not
    `storage`** — mixing the two was issue #151 (§9).
- **Crypto available**: mbedTLS on-device (SHA-256, `esp_random()` hardware CSPRNG). The
  admin module ships its own self-contained SHA-256 so the credential format is identical
  on device and on the host/CI simulator.
- **Data classifications handled**: call control state, WiFi credentials (a secret),
  device-integrity/config, admin credential, per-extension SIP digest secrets (HA1),
  real-time voice media.

### Host vs. device note
The desktop/CI build (`SipServer` binary) is a **developer/test simulator**, not a
production deployment. On host there is no NVS, so the admin credential and sessions live
in process memory for a single run (documented in `AdminAuth.hpp`). The host build's RNG
uses `std::random_device`-seeded `std::mt19937_64`; the device build uses the hardware
CSPRNG `esp_random()`. The trust boundaries below describe the **device**.

---

## 2. Trust Boundaries

```
            (most hostile)                                     (least hostile)
  ┌──────────────────────────┐   ┌───────────────────┐   ┌────────────────────┐
  │  OPEN SoftAP RF link      │   │  Wired/station LAN │   │  Device internals   │
  │  WIFI_AUTH_OPEN — anyone  │──▶│  (eth transport,   │──▶│  firmware, NVS,     │
  │  in radio range can join, │   │   or joined STA    │   │  SIP engine, RAM    │
  │  no link-layer encryption │   │   network)         │   │                     │
  └──────────────────────────┘   └───────────────────┘   └────────────────────┘
            │                              │                        │
            ▼                              ▼                        ▼
   HTTP / SIP / RTP / DNS         HTTP / SIP / RTP            local-only state
```

| # | Boundary | From → To | Current controls |
|---|----------|-----------|------------------|
| TB-1 | **Open SoftAP link (dominant link-layer boundary)** | Any RF-range device → device services | **NONE at link layer by default** — `WIFI_AUTH_OPEN` unless the operator turns on the opt-in WPA2 mode (`ap_secure`, §6). App-layer: same-origin + login session + per-session CSRF token on admin HTTP endpoints. |
| TB-2 | LAN (eth / joined STA) | LAN host → device services | Network is as trusted as the LAN's own segmentation. Same app-layer HTTP controls as TB-1 — but note the **SIP registrar ships OPEN on every build** (§9), so a LAN host needs no credential to register an extension. |
| TB-3 | Browser → HTTP server | Dashboard user → endpoints | `isSameOrigin()` (Origin vs. Host), HttpOnly + `SameSite=Strict` session cookie, no wildcard CORS, request-body cap (16 KB), per-socket recv timeout. |
| TB-4 | HTTP/SIP → NVS | Handlers → flash | Writes gated behind same-origin + session + CSRF (HTTP); salted/iterated admin password and DTMF-PIN hashes; explicit `confirm=ERASE` for factory reset. |
| TB-5 | Physical | Holder of the device → flash/JTAG | **NONE by default** — no flash encryption, no Secure Boot (see roadmap). |

> **The open SoftAP (TB-1) is the dominant *link-layer* boundary and the root of most
> residual risk on the `wifi`/`display` builds.** Anyone within WiFi range can associate
> with no credential and is then a peer on the device's IP network with full reachability
> to HTTP, SIP, RTP and DNS. Every threat below should be read with "the attacker is an
> associated, unauthenticated AP client" as the baseline. The device is **not
> WAN/Internet-exposed by default** (no port forwarding, no cloud component); the
> realistic attacker is local/proximate, not remote.
>
> **The single biggest residual risk on a fresh board of *any* build, however, is the
> OPEN SIP registrar** (§9). Digest auth, Learn mode and the extension↔MAC lock all ship
> and all work, but `reg_mode` defaults to `open`, so out of the box any peer that can
> reach UDP/5060 — over the open AP *or* over a wired LAN, where TB-1 does not apply at
> all — can REGISTER as any extension, place calls, and tear down other people's. The
> HTTP admin plane has no equivalent hole: it is credential-gated from the first boot.
> Turning the registrar off `open` is therefore the one hardening step that every
> deployment needs, ahead of everything else in §7.

---

## 3. Assets

| Asset | Why it matters | Primary threats |
|-------|----------------|-----------------|
| **Call control** (force-disconnect, active sessions) | Denial of phone service; disrupting live calls | Spoofing, Tampering, DoS, EoP |
| **WiFi credentials** (station SSID/password in NVS) | Reusable secret; pivot to the upstream network | Info disclosure, Tampering |
| **Device integrity / config** (mode, factory reset, OTA image) | Bricking, persistent control, supply-chain implant | Tampering, EoP, DoS |
| **Admin access** (login password, session token, CSRF token) | Master key to all mutating actions | Spoofing, brute force, token theft, EoP |
| **DTMF admin PIN** (separate numeric secret, phone keypad only) | Unlocks NTP resync, topology switch, factory reset from any handset | Spoofing, brute force, EoP |
| **Voice media + signaling** (RTP G.711, SIP) | Call confidentiality and privacy | Info disclosure (eavesdrop), Repudiation |

---

## 4. STRIDE Threat Enumeration

Each row: threat → current mitigation → **residual risk**.

### Spoofing
| ID | Threat | Mitigation | Residual risk |
|----|--------|-----------|---------------|
| S-1 | **Unauthenticated admin actions** — any AP/LAN peer POSTs `/api/kill`, `/api/wifi/connect`, `/api/wifi/mode_ap`, `/api/factory-reset`. *(was SEC-04)* | **FIXED, and unconditionally — there is no unprovisioned bypass any more.** Every admin-gated route (mutating routes *and* the sensitive GETs: `/api/pcap`, `/api/trace`, `/api/registrar`, `/api/telephony-config`, `/api/did-mapping`, `/api/ap-security`) requires a valid `pd_session` cookie from the very first boot, else `401`. Mutating routes additionally require the per-session `X-CSRF` token (T-2). The device ships a *known* default login (`admin`/`admin`) purely so the gate can be unconditional, and refuses everything except `POST /api/admin/set-credential` until that default is replaced (§5.1). | The default credential is public, so on a fresh board the real control is *who reaches the dashboard first* — a claim race, not an authentication check (§5.1). Password strength above the enforced 8-character floor is user-chosen. |
| S-2 | Session-cookie forgery / guessing | Token is ≥128-bit (`esp_random()` on device), opaque, validated server-side via constant-time compare; not derived from any user input. | Brute-forcing a 128-bit token over the network is infeasible; theft (S/T-3) is the realistic path. |
| S-3 | SIP identity spoofing (register/INVITE as another extension) | SIP signaling input is validated/bounded (audit SEC-02 mitigated). | **No SIP digest authentication** — on the open AP an attacker can register/INVITE as any extension. Tracked as a SIP-layer gap; out of scope for the HTTP auth change. |

### Tampering
| ID | Threat | Mitigation | Residual risk |
|----|--------|-----------|---------------|
| T-1 | Rewriting WiFi credentials / operating mode via dashboard | Same-origin + admin session + CSRF gate, applied from first boot (no post-provisioning caveat). | The fresh-board credential race (§5.1); physical attacker (T-4). Note `POCKETDIAL_HAS_WIFI` is undefined on the `eth`/`lan8720` builds, so `/api/wifi/*` there is a gated **stub** that changes nothing (issue #167) — don't plan a recovery around it on a wired board. `/api/factory-reset` is **not** split that way (since #189): the wipe, the `200` and the reboot all run on a wired board — only the WiFi-key erase is skipped, since there are none. It remains a usable recovery path on `eth`/`lan8720`. |
| T-2 | **CSRF** — a malicious page on the AP makes the victim's browser fire side-effecting POSTs | `isSameOrigin()` rejects requests whose `Origin` host ≠ `Host`; session cookie is `SameSite=Strict`; no wildcard `Access-Control-Allow-Origin`. A per-session **CSRF token** (128-bit, from `esp_random()`, stored in the session slot) that every mutating request must echo in an `X-CSRF` header. It is rendered into the dashboard document *and* returned by `POST /api/admin/login`, and is never set as a cookie, so a cross-origin page cannot read it even though the browser would attach the cookie for it. Checked centrally in `HttpServer::requireAdmin()`. | A request with **no** `Origin` (curl, native app) is still allowed by design — that is what lets scripts and `tests/http/test_api.sh` work — but it needs **both** the session cookie and a matching token regardless, from the first boot onward, so the Origin check is not load-bearing on its own. |
| T-3 | Request-body / parser abuse (oversized body, split TCP segments) | 16 KB body cap (`413`), `Content-Length` parsing with overflow guard, per-client `SO_RCVTIMEO`. | Low. |
| T-4 | **Physical flash tamper** — rewrite NVS / reflash | None by default. | **High if device is physically obtained**: NVS (incl. WiFi password and admin hash) is readable/writable. Mitigation is Secure Boot v2 + flash encryption (roadmap P2). |
| T-5 | **Firmware / OTA tampering** | OTA **has shipped**: dual-slot (`ota_0`/`ota_1`) with rollback, and the upload route runs through the same `requireAdmin(..., /*needCsrf=*/true)` gate as every other mutating endpoint — session **and** CSRF token, no exemption for the most consequential action the server performs. Images are **not signed**. | **The OTA path has never been executed end to end on any board** — not in CI, not on the bench — so rollback is an untested claim, not an observed behaviour. Treat a field OTA as a first run. Unsigned images mean an attacker who holds a valid admin session gets persistent code execution. **Durable fix: signed images + Secure Boot v2 + flash encryption** (roadmap P2). |
| T-7 | **SDP body abuse on the SIP plane** (CWE-674 class) — a well-formed INVITE / re-INVITE / UPDATE / 200 OK whose SDP `a=` lines are the payload. The UNISOC T612 VoLTE RCE (SSD advisory, 2026) was a normal MMTel video offer carrying `a=acap:1 acap:1 ...`; the modem's RFC 5939 acap decoder recursed once per token until the task stack overflowed into a neighbour. A PBX that relays bodies untouched (this one does, on hold/resume and P2P legs) is also the *delivery vector* for phones that are vulnerable. | **Design rule, pinned in code and tests.** (1) Every SDP body is checked ONCE in `RequestsHandler::handle()` before any decoder or relay — regardless of method or status, and with the MIME type matched case-insensitively — by `SipMessage::checkSdp()`: one flat, zero-heap pass enforcing `SdpLimits` (body ≤ 4 KB, ≤ 256 lines, ≤ 512 B/line, ≤ 40 tokens/line, ≤ 32 formats per `m=`, `a=` names ≤ 32 token chars) and refusing the RFC 5939 / 6871 / 7104 capability-negotiation attributes outright (`acap tcap pcfg acfg creq rmcap omcap mfcap mscap lcfg sescap bcap ccap icap`) because the PBX does not implement them. A violation is a hard error for the whole body: `488 Not Acceptable Here` + `Warning: 399 … "SDP refused: <reason>"` on a request, silent drop (never relayed, never advances a transaction) on a response or ACK; counted in `getSdpRejected()`. (2) The decoders that then run (`applyAudioPolicy`, `getSdpDirection`, `SipSdpMessage`) are flat loops over fixed 128-slot tables — no heap, no `std::function`/callback on the parser task's stack, no handler dispatched from inside another. (3) Recursion is pinned structurally: `tests/tools/check_parser_callgraph.py` compiles the SIP TUs with GCC `-fcallgraph-info` and fails on any cycle or dynamic frame (`checkSdp` is 2 frames / ~200 B). (4) Backstop in `sdkconfig.defaults`: `CONFIG_FREERTOS_WATCHPOINT_END_OF_STACK` (hardware trap on the first write past a task stack) and `CONFIG_COMPILER_STACK_CHECK_MODE_STRONG` (per-frame canary). Tests: `tests/SdpAdmission_test.cpp`, `tests/SipSdpMessage_hardening_test.cpp`. | Low. Attributes the PBX does not read (`candidate`, `fingerprint`, `fmtp` values …) are still relayed verbatim inside the caps; a peer phone's own parser bugs in those are the phone's. `a=csup` is deliberately admitted (advertises support only). |
| T-8 | **TLS server-certificate verification silently disabled fleet-wide** — issue #159 needed `CONFIG_ESP_TLS_SKIP_SERVER_CERT_VERIFY=y` so the SMTP client's documented, opt-in, LAN-relay-only "insecure" toggle can actually take effect on-device (without it, `esp_tls` hard-fails the handshake instead — see `sdkconfig.defaults`'s comment on the symbol). That Kconfig option's own help text says it changes the **default** behaviour of every `esp_tls` client in the firmware image, not just the caller that asked for it: normally a caller that forgets to set `crt_bundle_attach`/`cacert_buf` gets a hard handshake failure (fail-closed, loud); with this symbol on, the same omission instead connects with **no verification at all** (fail-open, silent) — a MITM-able connection to whatever the DNS/routing table currently points at, for anyone who ships that mistake. | **Audited, not structurally prevented.** Every `esp_tls_cfg_t`/`esp_http_client_config_t`/`esp_websocket_client_config_t` consumer in this tree as of 2026-09-14 was greped and confirmed to set `crt_bundle_attach` (or a pinned `cacert_buf`) unconditionally, or to branch on it explicitly the way `SmtpClient.cpp` does for its own opt-in toggle: `GoogleServiceAuth.cpp` (the OAuth2 token-exchange POST — the highest-value target in this PR, since an unverified connection there is a path to a forged access token), `TelephonyAnchorClient.cpp` (WSS + HTTPS, both instances), `SmtpClient.cpp` (two `esp_tls_cfg_t` sites, both correctly gated on `insecureSkipVerify`/`caCertPem`/default-bundle). `OtaUpdater.cpp` has no network client at all (it only writes bytes the dashboard's own HTTP server already received). | **The audit is a snapshot, not a gate.** Nothing in the build catches a *future* `esp_tls`/`esp_http_client`/`esp_websocket_client` caller that omits verification config — it now compiles clean and connects silently unverified instead of failing loudly the way it would have before this symbol was added. `sdkconfig.defaults` carries the re-audit greps inline; every PR that adds a new TLS-consuming client to this tree needs this row re-checked, the same standing caveat D-5 carries for the socket-leak pattern. |

### Repudiation
| ID | Threat | Mitigation | Residual risk |
|----|--------|-----------|---------------|
| R-1 | Admin/call actions are not attributable | Console logging exists; no tamper-evident audit trail; no per-user identity. The credential has a *username* field, but there is exactly **one** credential slot — setting a new username replaces the old one rather than adding an account — so the username is a label, not an identity. | Medium. Acceptable for a single-admin appliance; note that one shared credential (and one shared DTMF PIN) cannot distinguish operators. |

### Information Disclosure
| ID | Threat | Mitigation | Residual risk |
|----|--------|-----------|---------------|
| I-1 | **RTP voice eavesdropping on the open AP** | None at app layer (G.711 is uncompressed, unencrypted). | **High on open SoftAP**: any peer can sniff/replay call audio. The single highest-leverage fix is **WPA2 on the SoftAP** (encrypts the whole link). SRTP would be the app-layer fix but is heavyweight on the MCU. |
| I-2 | **SIP signaling disclosure** (who calls whom, extensions, topology) | None (cleartext SIP). | **High on open SoftAP**; same fix as I-1 (WPA2 link encryption). SIP-over-TLS is the app-layer option but costly on-device. |
| I-3 | WiFi station password recoverable | Stored cleartext in NVS (audit SEC-03). Not exposed over HTTP. | Recoverable by a **physical** attacker (flash read). Fix = flash encryption (P2). |
| I-4 | Verbose error / stack leakage | Endpoints return generic JSON errors; no stack traces or internal paths. | Low. |
| I-5 | Admin credential-hash disclosure | Both secrets — the web login password and the separate DTMF PIN — are stored as **salted, iterated SHA-256** (50k rounds, 128-bit random per-secret salt) in their own NVS keys, and neither is ever returned over HTTP or logged. | Offline cracking requires a **physical NVS read**; the salt defeats rainbow tables and the iteration count slows guessing. The **DTMF PIN is the weak one by construction**: a keypad can only type digits, so it is 4–16 digits and a 4-digit PIN is 10⁴ candidates — trivially crackable offline once flash is read. The login password has an enforced 8-character floor. See §5.2. |

### Denial of Service
| ID | Threat | Mitigation | Residual risk |
|----|--------|-----------|---------------|
| D-1 | Connection/slowloris exhaustion on HTTP | Detached per-connection threads, `SO_RCVTIMEO` (5 s), body cap. | A flood from the open AP can still pressure a constrained MCU. **This row assumes a *flood* is what it takes. On `main` today it is not — see D-5, where a handful of ordinary rejected requests is enough.** |
| D-5 | **Resource exhaustion via the admin plane — what a *rejected* request costs.** E-2 reasons about what an unauthenticated read *discloses*; nothing in this section reasoned about the cost of a request the server refuses. An attacker who cannot authenticate at all can still make the server do work, and still make it allocate. | **Partial, and currently defeated by a bug.** The intended design is that every route in `handleClient()` falls through to the single `closeSocket(clientSock)` at `src/Helpers/HttpServer.cpp:763`, so a refused request costs one short-lived socket and nothing else. Gated routes are written `if (requireAdmin(...)) { ... }` precisely so the false branch reaches that close. **Three routes are written the other way** — `if (!requireAdmin(clientSock, req, false)) return;` at `:493` (`GET /api/moh`), `:500` (`POST /api/moh/preview`) and `:505` (`POST /api/moh/preview/stop`) — and that early `return` jumps straight over the close. The socket is leaked on **every** rejected request, and `requireAdmin()` (`:2079-2125`) rejects on four separate paths: failed same-origin, no/invalid session (`401`), missing CSRF (`403`), and `setup_required` on a board whose default credential has not been replaced (`403`). Rate limiting on the SIP socket does not apply to the HTTP listener. | **High, and reachable with no credential.** Each refused request permanently consumes one lwIP socket; the descriptor table is the whole budget, and the WAN anchor holds persistent TLS sockets out of that same pool. **The bench board's effective budget is unresolved**: `sdkconfig.defaults:165` sets `CONFIG_LWIP_MAX_SOCKETS=48` (the constrained profile, `sdkconfig.defaults.esp32_constrained:43`, sets 8), while [PR #215](https://github.com/GlomarGadaffi/pocket-dial/pull/215)'s write-up cites 16 for the board it measured. The 14-request figure below is the **measurement**, not a derivation from either number — treat the exact threshold as board-dependent and the failure mode as certain. Bench measurement on merged `main` (`e20226d`): unauthenticated requests to `/api/moh` — **request 14 could not connect, 0/60 connections cleanly closed, and `/api/status` went unreachable**, i.e. the board left the network. The board does not recover without a reboot. A fresh board is *more* exposed, not less: before the operator sets a credential every gated route answers `403 setup_required` through the same leaking path. Fixed by [#215](https://github.com/GlomarGadaffi/pocket-dial/pull/215) (converted the three MOH routes to the fall-through form) — **but the pattern was reintroduced afterward**: commit `9356d2d` ("wire up the dead RFC 5424 module") added `GET /api/syslog` and `POST /api/syslog` using the exact `if (!requireAdmin(...)) return;` form #215 had just eliminated, and neither route nor the reintroduction was caught until issue #159's PR noticed it while adding adjacent routes to the same file and fixed both (converted to the fall-through form, same as the rest of `handleClient()`). The durable fix — an RAII socket guard in `handleClient()` so the close cannot depend on each future route author noticing the convention — is still not done; until it is, **treat the HTTP listener as reachable-only-by-trusted-hosts on any board that matters**, and treat every future PR touching this file as needing this row re-checked, not just its own new routes. |
| D-2 | Malicious call teardown (`/api/kill` abuse) | Admin-gated (session + CSRF) from first boot. | The fresh-board credential race (§5.1); **SIP-layer teardown (BYE spoofing) is still trivially possible while the registrar is `open`, which is the default** (S-3, §9). |
| D-3 | Login-lockout used as self-DoS | **NOT retired — this row was wrong.** The per-client bucketing it claims is implemented in `AdminAuth` but **is never actually keyed**, because nothing fills in the key. `HttpServer::handleClient()` computes `peerIp` "for per-client brute-force accounting on `/api/admin/login`" (`HttpServer.cpp:247-263`) but assigns it only to `otaReq.clientIp` (`:330`, the OTA streaming path). `parseRequest()` (`:765-828`) never sets `req.clientIp`, so `sendApiAdminLogin` passes a default-constructed **empty string** to `isLockedOut()` and `verifyCredential()` (`:2720`, `:2729`, `:2732`) — the same unkeyed bucket the DTMF PIN path uses. In effect there is **one global lockout bucket**, so a single guessing client on the link *can* lock the legitimate admin out of new logins, which is exactly the self-DoS this row says was fixed. Pre-existing sessions do stay valid, and only `login` is throttled (`429`) — those two halves are true. | An **aggregate** backstop (20 consecutive failures across all clients, same doubling cooldown, capped at 16 min) still exists by design — without it, address spoofing would buy an attacker a fresh bucket every 5 guesses (§5.2). It is deliberately set far above ordinary fat-fingering, but it *is* shared: the DTMF PIN path has no HTTP peer and so uses the unkeyed bucket, meaning any SIP peer that can reach the admin menu (E-4) can also contribute failures toward that global counter and delay web logins. Bounded, auto-clearing, and cleared outright by any successful login — a nuisance, not a lockout. |
| D-4 | RF jamming / deauth of the SoftAP | None (inherent to WiFi). | Out of scope; physical/RF layer. |

### Elevation of Privilege
| ID | Threat | Mitigation | Residual risk |
|----|--------|-----------|---------------|
| E-1 | Anonymous AP/LAN peer → full admin control | **FIXED**: session (+CSRF) gate on every admin endpoint, unconditional from first boot. There is no "unprovisioned, admit everyone" branch left in `requireAdmin()`. | The fresh-board credential race (§5.1); physical/OTA paths (T-4/T-5). |
| E-2 | Read endpoints leaking privileged actions | **The unauthenticated read surface is larger than this row used to claim, and not all of it was assessed.** Taken from the route table in `HttpServer::handleClient()` (`src/Helpers/HttpServer.cpp:457-755`), the routes that reach a handler with **no** `requireAdmin()` call are: `GET /` (`:457`), `GET /config/<mac>.cfg` (`:461`), `GET /api/status` (`:471`), `GET /metrics` (`:475`), `GET /api/wifi/scan` (`:638`), `GET /api/admin/status` (`:713`) and `GET /api/ota/status` (`:742`). Only the first four of those were ever argued here. The *sensitive* reads are **not** in this class: `/api/pcap`, `/api/trace`, `/api/diagnostics/pcap`, `/api/registrar`, `/api/telephony-config`, `/api/did-mapping`, `/api/ap-security` and `/api/moh` all require a session (they serve raw SIP bytes, credentials-adjacent config, or the AP passphrase in clear). Per endpoint: `/api/admin/status` returns only `{provisioned, needsSetup, authenticated, sessionRemainingSec}` — no secrets. `/metrics` emits six unlabelled aggregate counters and is ungated deliberately, because a Prometheus scraper cannot drive a login/CSRF handshake — the argument is written out at `HttpServer.cpp:1124-1159`. `/api/ota/status` returns partition labels and the pending-image flag. `GET /config/<mac>.cfg` returns a Yealink provisioning file for any MAC in the Learn-mode adopted-device registry — extension number and server IP, but **not** the SIP password (`ProvisioningConfig.hpp:66` emits `account.1.password =` empty). | **No longer "Low".** Two items justify the change. (1) **`/api/cdr` is unauthenticated** (`:508`) and returns caller, callee, start time and duration for every call in the ring — the recent call log of the site, to any host that can reach the board. It was ungated by an in-code analogy to `/api/status` and was never assessed in this row. Filed as [#207](https://github.com/GlomarGadaffi/pocket-dial/issues/207) and **fixed in [PR #215](https://github.com/GlomarGadaffi/pocket-dial/pull/215)** — `/api/cdr` now requires a session, exactly as `/api/trace` does. (2) **`/api/status` disclosed the extension roster with each handset's IP and port** (also fixed in #215: the roster is now withheld from an unauthenticated caller, while `clientCount` and `rosterVisible` remain visible so a client can tell "nobody is registered" from "you may not see who is"; the endpoint itself stays reachable because the login form genuinely needs it), plus every live session's caller/callee/state, the dial plan and the parked-call table. That is precisely the target list for E-4 below, whose mitigation is "set a long PIN" and whose attack needs the admin extension number to put in a spoofed `From:` — this endpoint hands it over. The "dashboard needs it to render the login form" justification is real for `/api/status`'s *existence*, but it does not extend to the roster, and it never applied to `/api/cdr`, `/metrics`, `/api/ota/status` or `/config/<mac>.cfg` at all. `needsSetup: true` still advertises "this board is on `admin`/`admin`" to anyone who asks (§5.1). (3) **#185 added `freeHeap`, `minFreeHeap`, `minFreeHeapSpiram`, `resetReason` and five `stackHwm_*` fields** to this same unauthenticated `/api/status` response. Reassessed here rather than left implicit: these are unlabelled operational numbers — heap byte counts, a boot-reset-cause enum, per-task stack headroom in bytes — carrying no extension number, no peer address, no call content and no credential. They are the same class already argued ungated for `/metrics` above (six unlabelled aggregate counters), not the roster/session/dial-plan class (2) describes. No reassessment of `/api/status`'s gating is needed on their account. **Issue #159 added `GET /setup/email`** to the ungated-shell list, in the same class as `GET /`: the page itself renders no configuration, every field is fetched client-side from `GET /api/email`, which IS gated (session required, and both stored secrets — the AUTH password and the Workspace service-account private key — are redacted to `hasPassword`/`hasGsaKey` booleans, never echoed even to an authenticated caller, matching `TelephonyApiConfig`'s `secretSet` discipline this row already established for E-2's category). |
| E-3 | **SSH sysop terminal as a second, unbounded admin surface** | **REMOVED this phase.** `SshServer`/`Tui` and their wolfSSH transport were deleted entirely rather than further hardened — see §5.5. HTTP is now the only admin surface. | None; the surface no longer exists. |
| E-4 | **Spoofed DTMF admin menu** — an attacker on the local link sends a crafted SIP INFO carrying `*PIN#code` and a `From:` header claiming to be the admin extension, to fire NTP resync (`001`), a topology switch + reboot (`101`), or a **factory reset** (`999` + confirm digit `1`, which runs `nvs_flash_erase()` and restarts). | **The DTMF PIN is the only real gate, and it is the whole gate.** The menu fires only when the `From:` number equals the configured admin extension (`admin_ext`, NVS `pbxcfg`, default `1001`) **and** `AdminAuth::verifyDtmfPin()` accepts the digits between `*` and `#`. The PIN is stored salted + iterated-SHA-256 like the web password, is verified **exactly once per completed code** (so one mistyped entry costs one counted failure, not several), and shares the brute-force lockout machinery (§5.2). Critically, **there is no default DTMF PIN**: `verifyDtmfPin()` returns false without hashing until an operator explicitly sets one, so the entire menu is unreachable on a freshly-flashed or freshly-reset device. A non-admin caller dialing the `*…#…` shape gets `403`. | **Do not assume the source-IP check described in earlier revisions of this document.** It applied to the deleted `*4887` transport-opener and went away with it. As the code stands, *any* SIP INFO whose `Content-Type` is `application/dtmf-relay` reaches the admin parser — no dialog match, no check that the claimed extension is registered, and **no source-IP verification**. A `From:` header is free text, and on the default `open` registrar (§9) nothing stops an attacker asserting the admin extension. So the PIN is load-bearing on its own: **set a long one, and treat a short numeric PIN as a factory-reset button reachable by any peer that can send UDP to port 5060.** Setting `reg_mode` away from `open` does not by itself fix this (the check is on `From:`, not on the registration), but it removes the attacker's easy foothold. |

---

## 5. Detailed Notes on Key Threats

### 5.1 First run: forced credential setup (the old open onboarding window is GONE)
Earlier revisions of this document described a deliberate **first-run gap** — a
factory-fresh device had no admin PIN, so mutating endpoints ran on the same-origin check
alone until a PIN was set. **That window has been removed.** `HttpServer::requireAdmin()`
has no "unprovisioned, admit everyone" branch left; the gate is unconditional from the
very first boot. (The code comment at `HttpServer.cpp`'s session step says exactly this,
and points back here.)

What replaced it is a **shipped default credential plus forced setup**:

1. The device ships with a well-known login, `AdminAuth::kDefaultUsername` /
   `kDefaultPassword` = `admin` / `admin`. Its only purpose is to let the gate be
   unconditional — you must *log in* to do anything, even on a virgin board.
2. While that default still stands, `AdminAuth::needsInitialSetup()` is true and
   `requireAdmin()` refuses **every** admin-gated route — including the gated GETs —
   with `403 {"error":"setup_required"}`. The sole exemption is
   `POST /api/admin/set-credential`, the route that fixes it. Enforced server-side, not
   merely suggested by the dashboard UI.
3. `set-credential` still needs a session **and** a CSRF token, so the flow is
   genuinely: log in with the default → immediately replace it. Passwords are
   `kMinPasswordLength` = 8 chars minimum, 128 max; the username must be 1–32 chars with
   no whitespace or control characters.

**Read the status codes precisely** — the checks run in order, so they are not
interchangeable:

| What the caller has | Result |
|---|---|
| An `Origin` header whose host ≠ `Host` (a missing `Origin` is admitted, by design) | `403 cross-origin request rejected` |
| No valid `pd_session` cookie | `401 authentication required` |
| Session, mutating route, no/incorrect `X-CSRF` | `403 missing or invalid CSRF token` |
| Session **from the default credential**, any route but `set-credential` | `403 setup_required` |

So an anonymous attacker sees `401`, not `setup_required`; `setup_required` is what an
operator sees after logging in with `admin`/`admin`.

**The residual this leaves — state it plainly.** The default credential is published in
the source, the README and this file. On a board that has been powered up but not yet
claimed, the control is not authentication at all: it is a **race to claim**. Whoever
reaches the dashboard first sets the credential and locks everyone else out.
`GET /api/admin/status` reports `needsSetup` unauthenticated, so an attacker can also
*find* unclaimed boards by polling. This is strictly better than the old gap (an attacker
must now take a visible, persistent action — changing the credential — rather than
silently using an open API), but it is not a secret. **Operational guidance: complete
setup on first power-up, before the board is on a shared link; if you inherit a board
that reports `needsSetup: true` and you did not just flash it, wipe it before claiming it
— and prefer a reflash or the DTMF `999` reset over `POST /api/factory-reset`, for the
reason in the first bullet below.**

Two boot-time behaviours interact with this:

- **The SIP stack is held down until a credential is committed** on the `wifi`, `eth` and
  `lan8720` builds: `app_main()` polls `AdminAuth::credentialIsSet()` every 2 s and does
  not start the SIP task until it returns true, rebooting after a 30-minute cap rather
  than spinning forever. So on those builds a never-claimed board is not a working PBX —
  it is a dashboard waiting to be claimed, which bounds what an attacker gains by winning
  the race.
  **But the gate is effectively first-boot-only.** It is skipped whenever the NVS
  `provisioned` flag is set, and that flag is written once, on the first successful
  claim, and is **not** cleared by `POST /api/factory-reset` — neither
  `AdminAuth::clearCredential()` nor `DeviceConfig::clearAll()` touches it. So an
  HTTP factory reset on a wifi/eth/lan8720 board leaves it back on `admin`/`admin`
  **with the SIP stack running**, i.e. in the `display` build's posture, not a virgin
  board's. Only a full NVS erase re-arms the gate — which is what the DTMF `999` factory
  reset does (`nvs_flash_erase()`), and what reflashing does. Treat "I factory-reset it"
  as "the credential is back to the default", not "the board is dark again".
- **The `display` build is deliberately NOT held dark** ("up usable, secure later"): the
  touchscreen onboarding assumes a person standing in front of the device, so SIP comes up
  regardless. On that build the claim race is the only control.
- **The HTTP listener itself is never gated** — see §5.5.

### 5.2 Credential brute force
- **Online**: `verifyCredential()` (web login) and `verifyDtmfPin()` (phone keypad) share
  one accounting path. It counts consecutive failures; after **5** it engages a **60 s**
  lockout during which even a correct credential is refused — `429 Too Many Requests` on
  the HTTP side.
  The counter used to be zeroed the moment the lockout engaged, so every cooldown handed
  the attacker a fresh window of 5 — a steady ~5 guesses/minute for as long as they cared
  to keep going, which walks a 4-digit secret in about a day and a half. The trip count
  now survives the cooldown and each successive lockout doubles
  (`kLockoutMs << min(trips-1, 4)`, capped at 16 minutes). Only a **correct credential**
  clears it.
- **Offline**: a leaked hash (only obtainable via **physical NVS read**) is a salted,
  iterated SHA-256 (50,000 rounds, per-secret 128-bit salt). This defeats precomputation
  and slows guessing. The **login password** has an enforced 8-character floor, which
  makes offline attack expensive; the **DTMF PIN cannot**, because a telephone keypad can
  only send digits — 4 to 16 of them. A 4-digit PIN is 10⁴ candidates and falls instantly
  offline. **Choose a long DTMF PIN** (it is the credential behind a remote factory reset,
  E-4), and note that the real backstop for offline attack is flash encryption (P2).
- **Per-client accounting — BUILT BUT NOT WIRED. Not done.** *(Corrected by audit: this
  bullet, and D-3 with it, claimed a control the login path does not reach.)* `AdminAuth`
  really does keep a fixed table of 8 least-recently-seen-evicted buckets keyed on a client
  string — but **nothing ever supplies the key on the login path**. `handleClient()`
  computes `peerIp` for exactly this purpose (`HttpServer.cpp:247-263`) and then assigns it
  only to `otaReq.clientIp` (`:330`); `parseRequest()` (`:765-828`) never sets
  `req.clientIp`, so `sendApiAdminLogin` passes an empty string (`:2720`, `:2729`, `:2732`).
  Every web-login failure therefore lands in the same unkeyed bucket as the DTMF PIN, and
  **one guessing client on the link can still lock the legitimate admin out** — the D-3
  self-DoS is live, not retired. Read the rest of this bullet as the intended design:
  the key would be for *fairness, not trust*, since a source address is trivially spoofable
  on the shared link,
  and a spoofer only ever buys themselves a fresh bucket. The bucket table is bounded, so a
  flood of distinct addresses recycles records rather than growing memory — accepted on a
  device whose AP holds ten stations. Callers with no HTTP peer (the DTMF admin menu) share
  one unkeyed bucket, which is the old global behaviour.
- **Aggregate backstop (why per-IP alone would have been a downgrade).** Source addresses
  are spoofable on this link, so per-client buckets *by themselves* would hand an attacker a
  fresh bucket and a fresh escalation ladder every 5 guesses — strictly better for them than
  the single global counter it replaced. A second counter therefore runs across **all**
  clients at a much higher threshold (**20** consecutive failures) with the same doubling
  cooldown, bounding the aggregate guess rate no matter how many identities the attacker
  invents. It sits far above ordinary fat-fingering, so a fumbling operator still only trips
  their own short cooldown — which is what keeps D-3 retired. Any successful login clears it.

### 5.3 Session token theft & replay
Tokens are 128-bit, server-side, with a **30-minute *sliding* expiry** — every successful
validation pushes the deadline out by a full TTL so an actively-working admin is not logged
out mid-session — and a fixed-capacity table (8 slots; oldest/expired evicted). *(This
paragraph and `AdminAuth.hpp` both used to describe an **absolute** expiry; the code has
implemented sliding expiry since it was written, and `AdminAuth.hpp` now documents it as
sliding. Sliding is the intended behaviour.)* `GET /api/admin/status` exposes the live
countdown (`sessionRemainingSec`) without sliding it, so the badge is honest rather than
self-refreshing. Each session also carries the per-session CSRF token
described in T-2. Cookie flags: `HttpOnly` (no JS access → blunts XSS exfiltration) and
`SameSite=Strict` (browser won't attach it cross-site → blunts CSRF).
**No `Secure` flag and no TLS**: on plain HTTP over the open AP, a network sniffer can
capture the cookie in transit and **replay** it until expiry. This is the same root cause as
I-1/I-2 and has the same headline fix — **WPA2 on the SoftAP encrypts the cookie in flight**.
Residual: a token has no rotation and no binding to client IP, and because the expiry is
**sliding rather than absolute, a stolen token that the thief keeps exercising at least
once every 30 minutes never expires at all** — there is no absolute cap to fall back on
(§7 P1). Logout (`/api/admin/logout`) and factory reset both destroy sessions immediately,
so an operator who suspects theft has to act rather than wait it out.

### 5.4 Captive-portal / DNS-spoof phishing
In onboarding mode the device answers **all** DNS queries with its own IP (port 53) to
trigger the OS captive-portal prompt. On an open AP an attacker could stand up a competing
portal/AP to phish the WiFi password or the admin login. The same-origin check prevents a
foreign page from driving the *real* device's API, but it cannot stop a user from typing
secrets into a look-alike. Mitigation is again **WPA2** (raises the bar to join/impersonate)
plus user guidance to provision over a trusted link.

### 5.5 The two admin surfaces: an always-listening HTTP plane, and the DTMF keypad menu
There are exactly two ways to administer a running device, and they have separate
credentials. SSH was a third; it is gone.

#### 5.5.1 HTTP — always listening, never a transport gate
**The HTTP listen socket is opened in the `HttpServer` constructor and stays open for the
life of the process, regardless of provisioning state** (commit `de1a36e`). Reachability
is not, and must not be treated as, a security control. `requireAdmin()` (§5.1) is the
control.

> **This replaced a dark-by-default design that was removed, and the removal matters
> operationally.** The earlier build closed the listen socket on a provisioned device and
> reopened it only for a bounded TTL, triggered by a `*4887` DTMF star-code, by a
> provisioning grace window, or by a dashboard "Keep open" button
> (`POST /api/admin/keepalive`). **None of those exist.** The star-code, the grace window,
> `grantAdminHttpGraceWindow`, the keepalive route and `POST /api/admin/set-pin` are all
> deleted — `grep 4887 src/` returns nothing. The gate bricked access in practice: the
> dashboard went "connection refused" the moment any client registered.
> **Consequence for anyone debugging: a refused connection to the dashboard port is now
> ALWAYS a genuine fault** — wrong IP, wrong network, crashed or never-started HTTP task —
> and never an expected security state. Do not go looking for a way to "reopen" it.

What the always-open listener costs, honestly: `/api/admin/login` is permanently reachable
to anyone who can route to the device, so online password guessing is permanently possible.
That is what §5.2's lockout machinery and aggregate backstop are for, and what makes them
load-bearing rather than belt-and-braces. Note the per-client half of that is currently
inert (§5.2, D-3), so the aggregate backstop is carrying this on its own. The dark-plane design bought a smaller exposure
window at the price of an availability failure that made the device unadministrable; the
trade was not worth it.

**SSH removed, not hardened.** `SshServer`/`Tui` and their wolfSSH transport were deleted
outright (E-3). They were a second admin surface with no comparable gate discipline,
listening on port 22 whenever the display transport was built. HTTP is now the only
network admin surface. (Design notes under `docs/design/` describe that removed SSH TUI and
are preserved only as design history.)

#### 5.5.2 The DTMF admin menu — a separate credential, and the one to be careful with
A handset can reach an admin menu by dialing `*<PIN>#<code>` and having the resulting SIP
INFO (`Content-Type: application/dtmf-relay`) relayed to the PBX. The codes are: `001` NTP
resync, `101` topology switch between station and AP mode (**reboots the device**), `200` a
stub, and `999` followed by confirm digit `1` — **factory reset**: `nvs_flash_erase()` then
restart.

The **DTMF PIN is a wholly separate secret from the web login.** Do not conflate them:

|  | Web dashboard | DTMF admin menu |
|---|---|---|
| Credential | username + password (≥8 chars) | numeric PIN, 4–16 digits |
| Default | `admin` / `admin`, forced replacement (§5.1) | **none — the menu is disabled entirely until a PIN is set** |
| Set via | `POST /api/admin/set-credential` (`username=`+`password=`) | the same route's `dtmfPin=` field |
| NVS keys | `admin_user`, `admin_pw_salt`, `admin_pw_hash` | `admin_pin_salt`, `admin_pin_hash` |
| Storage | salted, 50k-iteration SHA-256 | salted, 50k-iteration SHA-256 |
| Rate limiting | *intended* per-client bucket keyed on peer IP — **but the key is never supplied, so this is the unkeyed bucket too** (D-3) | the unkeyed bucket (no HTTP peer), plus the shared aggregate backstop |

Having no default is the important property: `verifyDtmfPin()` returns false without even
hashing while `dtmfPinIsSet()` is false, so a freshly-flashed or freshly-factory-reset
device exposes no remote factory-reset button at all. Setting a DTMF PIN is what *creates*
that surface — it is optional, and a deployment that never uses the keypad menu should
simply never set one.

The PIN is verified exactly once per completed `*PIN#code` (the `#` terminates the PIN so
its length is unambiguous). An earlier implementation looped over every candidate PIN
length, charging several failed attempts to the lockout for one normal admin entry, which
could lock the admin out of both the keypad and the dashboard — the buckets are shared.

**Residual (E-4), and the correction to make if you remember the old design:** the menu's
only checks are `From:` == `admin_ext` and the PIN. There is no source-IP verification —
that check belonged to the removed `*4887` star-code, not to this menu — and no check that
the claimed extension is even registered; any INFO with a DTMF-relay body reaches the
parser. A `From:` header is free text, and the registrar ships `open` (§9), so the PIN is
the entire boundary in front of a remote factory reset. Choose it accordingly.

### 5.6 Cleartext SIP + RTP on the open AP
This is the largest *confidentiality* gap and is **independent of the dashboard auth fix**.
The admin credential protects *control*, not *media*. SIP signaling and G.711 RTP traverse the open
link in cleartext, so any associated peer can record calls and map who-calls-whom. App-layer
fixes (SIP-over-TLS, SRTP) are expensive on a constrained MCU and add key-management UX. The
**link-layer fix (WPA2 on the SoftAP) encrypts everything — dashboard, SIP, and RTP — at
once**, which is why it is the top recommendation below.

---

## 6. The TLS Question (HTTPS for the dashboard) — answered honestly

**Should the dashboard serve HTTPS (self-signed) on the ESP32?**

**Recommendation: not as the primary control. Ship HTTP + the mandatory credential setup
(§5.1) now, and enable WPA2 on the SoftAP as the single highest-leverage *link-layer*
hardening.** Self-signed HTTPS is listed as a *documented optional* future enhancement,
not the headline fix. The four reasons below are unchanged by the auth-model rework — they
are properties of TLS on a constrained LAN appliance, not of whatever credential sits
behind it.

**Why self-signed HTTPS on this device has real downsides:**
1. **Browser trust UX is bad on a LAN appliance.** There is no public CA for `192.168.4.1`
   / `pocketdial.local`, so every visit throws a full-page certificate warning. On a
   no-screen appliance users are trained to "click through" warnings — which *erodes* the
   very trust signal TLS is supposed to provide and habituates users to ignore real warnings.
2. **Constrained-MCU cost.** TLS handshakes (RSA/ECC + the record layer) cost notable RAM and
   CPU on an ESP32 whose HTTP path already runs on a small per-connection thread stack.
   Concurrent TLS sessions can pressure heap and slow the dashboard.
3. **Cert provisioning UX.** A self-signed cert must be generated/stored per device (or a
   shared key baked into firmware — which is worse, a single compromise breaks every unit)
   and rotated; there is no clean trust-on-first-use story for a headless box.
4. **It only protects the dashboard.** HTTPS does nothing for SIP or RTP. The confidentiality
   gaps I-1/I-2 (call audio + signaling eavesdropping) would remain wide open.

**Why WPA2 on the SoftAP is the better lever:**
- It **encrypts the entire RF link** — dashboard HTTP, SIP signaling, *and* RTP media — with
  one change, directly closing I-1, I-2, and the cookie-replay vector in 5.3.
- It **gates association**: an attacker must know the AP passphrase to join at all, which
  removes the "anyone in range is a peer" baseline that powers nearly every threat here.
- It needs **no per-device certificates** and no browser-warning UX; the passphrase can be
  shown on the device screen / printed on a label.
- Trade-off: a WPA2 passphrase must be distributed to legitimate clients, and WPA2-PSK is
  still vulnerable to offline handshake cracking if the passphrase is weak — so pair it with
  a non-trivial passphrase. It is nonetheless a large net improvement over an open AP.

> **Status update.** WPA2 on the SoftAP is now **implemented** (`DeviceConfig::isApSecure()`,
> NVS key `ap_secure`, dashboard toggle at `POST /api/ap-security`, and settable at install
> time from the browser flasher via the `cfgseed` partition). It **defaults to off**: turning
> it on forces every already-associated phone to be re-paired, so it is an explicit operator
> action rather than something a firmware update does to a live fleet. The per-device
> passphrase is generated from `esp_random()` on first access and shown on the LVGL screen,
> over serial, and in the dashboard. This also retired a real bug: the captive-portal
> onboarding AP was already WPA2 but used a hardcoded `"12345678"` identical on every unit
> and published in a public repo, which made its encryption decorative — anyone who captured
> the 4-way handshake could derive the PTK. Self-signed HTTPS remains **not** recommended as
> the primary control, for the four reasons above.

**Net**: HTTP + forced credential setup (§5.1) + WPA2 SoftAP (recommended P0) gives
confidentiality *and* control protection for the whole link. Optionally layer self-signed
HTTPS later for the dashboard if a specific deployment requires app-layer transport
security on top of WPA2 — but do it eyes-open about the warning UX and MCU cost. Note that
WPA2 does nothing for the `eth`/`lan8720` builds, which have no AP at all; there the
trusted-LAN assumption and the registrar mode (§9) carry the whole load.

---

## 7. Prioritized Hardening Roadmap

### P0 — do now / next (highest leverage, low-to-moderate effort)
- **Move the registrar off `open` — NOT DONE, and the top item on a fresh board of any
  build.** Everything needed ships (digest auth, Learn mode, the extension↔MAC lock, a
  dashboard panel, `GET`/`POST /api/registrar`, and the flash-time `cfgseed` route for
  headless boards), but `reg_mode` defaults to `open`, so the protections are opt-in and a
  shipped board has none of them. See §9 and the operator runbook
  [LEARN_MODE.md](LEARN_MODE.md). *Closes S-3/D-2, which nothing else in this list does —
  WPA2 gates who joins the link, but a legitimately-joined peer is still unauthenticated at
  the SIP layer.*
- **WPA2 on the SoftAP — DONE (opt-in).** `WIFI_AUTH_WPA2_PSK` behind the NVS flag
  `ap_secure` (default off for fleet compatibility), with a per-device `esp_random()`
  passphrase surfaced on-screen, over serial, in the dashboard, and settable at flash time.
  *Closes the dominant link-layer boundary once enabled; encrypts dashboard + SIP + RTP.*
  **Operational guidance: turn it on.** See §6 for why the previous hardcoded onboarding PSK
  did not count. Not applicable to the `eth`/`lan8720` builds.
- **Mandatory admin credential — DONE** (username + password, server-side session and
  per-session CSRF token on every admin endpoint, brute-force lockout with exponential
  backoff — **global rather than per-client, see D-3** — forced replacement of the shipped
  default before anything else is permitted, factory reset clears it). §5.1.
- **SSH admin surface removed — DONE.** `SshServer`/`Tui` and wolfSSH deleted rather than
  hardened (E-3). HTTP is the only network admin surface.
- **HTTP dark-by-default transport gate — REMOVED, deliberately.** It is not a pending item
  and should not be reintroduced as written: closing the listen socket on a provisioned
  device made the dashboard unreachable in practice (§5.5). The listener is unconditional;
  the auth layer is the gate.
- **Guidance/UX**: the login password floor is 8 characters, enforced server-side. The
  **DTMF PIN** is the one to lecture users about — it is digits-only, it is what stands in
  front of a remote factory reset (E-4), and a deployment that does not use the keypad menu
  should leave it unset so the surface does not exist at all.

### P1 — soon (meaningful, moderate effort)
- **SIP digest authentication — DONE as code, opt-in in practice.** Challenges REGISTER;
  independent INVITE challenge (`407`) is still a follow-up (§9.1). It only protects
  deployments that actually switch `reg_mode` — hence the P0 item above.
- **Per-client brute-force tracking for `login` — DONE** (replaces the global counter,
  removes the admin-lockout self-DoS in D-3, and stops the cooldown from resetting the
  failure budget; an aggregate backstop bounds address-spoofing). See §5.2.
- **OTA gated behind the admin session — DONE.** The upload route runs through the same
  `requireAdmin()` (session + CSRF) as every other mutating endpoint. Remaining: **image
  signing**, and an actual end-to-end execution — the OTA path, dual-slot rollback
  included, has never been run to completion on hardware (T-5).
- **Session hardening**: the 30-minute expiry is **sliding**, not absolute, so a session
  stays alive as long as it is used — consider a separate absolute cap so a stolen token
  cannot be renewed indefinitely, and consider binding a token to the client association.

### P2 — durable platform hardening (higher effort, strongest guarantees)
- **Secure Boot v2 + flash encryption**: signs the firmware (defeats OTA/boot tampering,
  T-5/T-1) and encrypts NVS at rest (defeats physical recovery of the WiFi password, the
  admin password and DTMF PIN hashes, and the per-extension HA1 bearer credentials —
  I-3/I-5/I-6/T-4). This is the durable fix for the physical and supply-chain boundaries.
- **Signed OTA images** verified against the Secure Boot key.
- **Tamper-evident audit logging** for admin/call actions (addresses R-1) if multi-operator
  attribution becomes a requirement.
- **Optional self-signed HTTPS** for the dashboard, as a documented add-on on top of WPA2
  (see §6), for deployments that mandate app-layer transport security.

---

## 8. Summary

The HTTP admin plane's **unauthenticated-admin** elevation-of-privilege hole (S-1 / E-1 /
audit SEC-04) is closed, and closed *unconditionally*: call control, WiFi/mode changes,
factory reset, OTA and the sensitive reads all require a login session plus a per-session
CSRF token from the first boot, and the device refuses every other admin action until the
shipped default credential is replaced (§5.1). The open-onboarding window that earlier
revisions of this document treated as an accepted risk no longer exists, and neither does
the dark-by-default transport gate that briefly replaced it — the listener is always up,
and the auth layer, not reachability, is the control (§5.5).

Two residual risks dominate what is left, and they are not the same risk:

1. **The SIP registrar ships `open`** — the biggest exposure on a fresh board, and the only
   one that applies to *every* build including the wired ones. Any peer that can reach
   UDP/5060 can register as any extension, place calls and tear down others' (S-3, D-2).
   The fix ships and is one setting away (§9, [LEARN_MODE.md](LEARN_MODE.md)); it is simply
   not the default.
2. **The open SoftAP** (TB-1) — the dominant *link-layer* boundary on the `wifi` and
   `display` builds, leaving call media and signaling eavesdroppable (I-1/I-2) and the
   session cookie replayable (§5.3). **WPA2 on the SoftAP** is opt-in and encrypts the whole
   link in one move.

Physical and firmware-supply-chain risks are durably addressed by **Secure Boot v2 + flash
encryption**; note that OTA, though session-gated, is unsigned and has never been run
end to end (T-5).

---

## 9. The SIP auth surface (digest auth + Learn mode)

> **Status: SHIPPED and now operator-reachable.** This section used to be marked
> "forward-looking … not yet shipped code". That was stale: `SipDigest.{hpp,cpp}`,
> `SipSecretStore.{hpp,cpp}`, the `Registrar::Mode` state machine and its NVS
> persistence are all on `main`, and `Registrar::loadMode()` runs from the
> `RequestsHandler` constructor, so a persisted mode is honoured at boot.
>
> [!CAUTION]
> **A second gap of the same shape is still open, and it is the one that matters now.**
> The mode *setting* is reachable (below), but **the per-extension secret is not**:
> `SipSecretStore::setSecret()`, `generateSecret()` and `clearSecret()`
> (`src/Helpers/SipSecretStore.cpp:171,230,307`) have **zero callers outside the test
> suite** — no HTTP route, no dashboard field, no console, and `cfgseed` cannot carry one.
> So `Registrar::secure()` refuses for want of a secret (`Registrar.cpp:251-256`), no
> device can be marked Secured, and `admitSecure()` rejects every REGISTER as *Extension
> Not Provisioned* (`Registrar.cpp:99-105`).
>
> **Consequence for this section: `secure` mode is not a deployable control today.**
> Everything §9 says about what digest auth closes is true of the *implementation* and
> false of the *deployment* — flipping `reg_mode = 2` locks out the entire fleet instead
> of protecting it, which is exactly what the `409`/`confirm=LOCKOUT` guard below exists
> to prevent. The strongest admission mode that can actually be run is `learn` (TOFU plus
> the ARP MAC lock), whose residual risks are S-4 and E-3 below. See
> [LEARN_MODE.md](LEARN_MODE.md) Step 4.

> **The earlier gap of this shape has been closed.** Until then
> `RequestsHandler::setRegistrarMode()` was called from **tests only** — no HTTP
> endpoint, no dashboard control, nothing in production ever wrote `reg_mode` — so a
> device came up in the compiled-in default (`open`, `#define`d unconditionally at the
> top of `RequestsHandler.hpp`, so a `-U` on the compiler command line could not change
> it either) and stayed there. Every protection below was real, tested, and unreachable.
>
> Two operator paths now write it:
> * **`GET`/`POST /api/registrar`** plus the *Extension Registration & Onboarding* panel
>   in the dashboard, which also lists the adopted roster and exposes Secure / Forget per
>   device (`POST /api/registrar/device`). Switching to `secure` while **no** extension is
>   secured yet is refused with `409` unless `confirm=LOCKOUT` — otherwise one click
>   rejects every phone at once and leaves the operator no working handset.
> * **The flash-time `cfgseed` record** (`regMode`, byte 13), which is the only way to set
>   it on a headless board *before first boot*. **Caveat: this path was broken until
>   v1.4.1.** On v1.3.0 and v1.4.0 the seed wrote `reg_mode` into NVS namespace `storage`
>   while `Registrar::loadMode()` reads `pbxcfg`, so a seeded mode silently did nothing and
>   the board came up `open` regardless ([#151](https://github.com/GlomarGadaffi/pocket-dial/issues/151)). Verify with `GET /api/registrar`
>   rather than assuming the seed took.
>
> The S-3/D-2 registrar gap in §4 is therefore closable in the field now — but note it is
> only *closable*, not closed: the shipped default is still `open`, so it protects
> deployments that actually switch.
>
> It extends the STRIDE analysis above with the new IDs `S-4`, `D-5`, `I-6`, `T-6`, `E-3`
> and continues the residual-risk convention. Cross-refs: [FEATURE_ROADMAP.md](FEATURE_ROADMAP.md)
> §3.3 (SIP digest auth, WPA2), the operator runbook [LEARN_MODE.md](LEARN_MODE.md), and
> [PROVISIONING.md](PROVISIONING.md) §7.3 (the shared per-extension secret store).

The registrar is **open on a shipped board** (`POCKETDIAL_OPEN_REGISTRAR` is the
compiled-in default that `Registrar::loadMode()` falls back to when NVS holds no
`reg_mode`); §4 records this as the S-3/D-2 SIP-layer gap, and §2/§8 name it as the single
biggest residual risk on a fresh board. What follows is the machinery that **closes it once
an operator switches modes** — it is shipped and reachable, not automatic. SIP **digest
authentication** (RFC 2617, MD5 / `qop=auth`) challenges **REGISTER** —
**INVITE is not independently challenged in M1** (it relies on the registration binding an
authenticated REGISTER established; per-INVITE/proxy-auth `407` is a tracked follow-up, see
§9.1). The registrar mode becomes **runtime-selectable** (`open` / `learn` / `secure`);
**Learn mode** adopts an existing fleet trust-on-first-use, keyed by **device MAC** (resolved
from the REGISTER's source IP via the LAN ARP table — phones do not carry MAC in SIP), then
**locks each extension ↔ MAC** once secured. (RFC 8760 SHA-256 digest is not implemented;
MD5 is the wire algorithm, matching the installed-phone fleet — SHA-256 is a hardening item.)

### 9.1 What digest auth closes

| ID | Threat (was) | Mitigation (this phase) | Residual risk |
|----|--------------|-------------------------|---------------|
| S-3 | **SIP identity spoofing** — on the open registrar any peer can REGISTER/INVITE as any extension. *(prior residual risk, §4 Spoofing)* | In `secure` mode every REGISTER is digest-challenged (`401` + `WWW-Authenticate: Digest realm,nonce,qop=auth`); the UA must return `response == MD5(HA1:nonce:nc:cnonce:qop:HA2)`. An extension is registrable only by a party that knows its secret. **This holds even on a trusted link** — it is independent of the WPA2/link fix. | Nonce replay is bounded by a time-window + server-secret nonce with `stale` handling; an attacker who can read the live exchange (open AP, I-2) can attempt replay inside the window — the link fix (WPA2) and a short nonce lifetime are the backstops. Digest is `auth` (not `auth-int`): the message body is not integrity-protected. **Scope (M1): only REGISTER is digest-challenged.** INVITE is not independently authenticated — it trusts the binding an authenticated REGISTER created, so a peer that can forge a request matching a *registered* contact on a trusted L2 is not separately challenged. Independent INVITE challenge (`407 Proxy-Authentication-Required`) is the tracked follow-up; on a hostile L2 the backstop is again WPA2. |
| D-2 | **Malicious call teardown** — BYE/`/api/kill`-style teardown of others' calls; SIP-layer teardown (BYE spoofing) possible without SIP auth. *(prior residual risk, §4 DoS)* | With REGISTER authenticated, an unauthenticated peer can no longer claim an extension's *registration* binding, which raises the bar for impersonating it. Raises BYE-spoofing from "trivial on open AP" to "requires the registered contact or live-session knowledge." | INVITE/BYE are not themselves digest-challenged in M1 (only REGISTER is — see S-3 scope note), so an attacker who can sniff the link (open AP) still observes dialog identifiers (Call-ID/tags) and could attempt in-dialog injection; digest authenticates the *registration*, not every in-dialog request. The link fix (WPA2) closes the observation channel; per-request INVITE auth (`407`) is the tracked follow-up. Tracked alongside S-3. |

### 9.2 New threats introduced by Learn mode

| ID | Threat | Mitigation | Residual risk |
|----|--------|-----------|---------------|
| S-4 | **Learn-mode TOFU adoption window** — while the registrar is in `learn`, an **unknown MAC** that REGISTERs an unclaimed extension is adopted **without verifying** any credential (trust-on-first-use). A stranger on the segment can race to claim an unclaimed extension before the legitimate phone does. | The window is **bounded, admin-initiated, and not a default**: entering `learn` is an explicit action, re-opening is admin-gated, and the operator verifies the adopted roster (MAC · ext · state) before securing (see [LEARN_MODE.md](LEARN_MODE.md) §5). Already-secured devices are digest-enforced even during the window — TOFU applies only to *unknown* MACs. The intended posture is to run the window on a **trusted/WPA2 link**. | **If the window is left open, this is functionally an open registrar for any unclaimed extension.** On an open AP a proximate attacker can both observe the cutover and race a claim. The control is procedural (bound the window, watch the roster, prefer an encrypted link), not cryptographic. **Honest framing:** Learn mode is a deliberate, temporary weakening to enable low-friction cutover — it must not be run as a steady state. |
| E-3 | **MAC-based extension↔MAC lock is trust-the-LAN, not cryptographic** — once an extension is secured, a different MAC claiming it is rejected (`403`/`401`). The MAC is learned from the **ARP table**, and ARP/MAC are spoofable on a hostile L2. | The lock defeats accidental collisions, duplicate-extension misconfig, and casual impersonation on a trusted segment. It composes with digest (a rogue must *also* present a valid digest for a secured extension), so it is defense-in-depth, not the sole gate. | **The lock raises the bar but is not a security boundary on a hostile L2** — an attacker who can spoof a MAC and who knows the secret defeats it. **The real boundary is WPA2 / a trusted LAN** (gating association). State this plainly to operators: MAC-lock ≠ cryptographic device identity. ARP first-packet misses (§Learn-mode timing) also mean the lock binds a beat after first contact, not instantaneously. |

### 9.3 Secret-at-rest (the digest credential store)

| ID | Threat | Mitigation | Residual risk |
|----|--------|-----------|---------------|
| I-6 | **Per-extension digest secret recoverable from flash.** *(Latent: no secret can be written today — see §9's caution. This row describes the exposure once a write path exists.)* Unlike the admin password and DTMF PIN (one-way salted/iterated SHA-256, I-5), digest auth requires the server to **recompute** the response, so the secret store holds **HA1 = MD5(ext:realm:secret)** — a *recoverable-equivalent bearer credential*, not a one-way hash. Anyone who can read HA1 can authenticate as that extension (HA1 is directly usable in the digest computation; the cleartext secret is not even required). | HA1 is never returned over HTTP and never logged. It lives in a **separate NVS store** from `AdminAuth` (mirrors the `prov` per-MAC layout, [PROVISIONING.md](PROVISIONING.md) §5). Offline recovery requires a **physical NVS read** (same precondition as I-3/I-5). | **HA1 is a bearer credential at rest — weaker at-rest than the one-way admin hash by necessity of the protocol.** This *pairs directly with the existing flash-encryption / Secure Boot v2 item* (T-4/I-3/I-5): encrypting NVS at rest is the durable fix and the secret store inherits it. Until flash encryption lands, a physical attacker who reads NVS obtains usable extension credentials. |

### 9.4 Registrar-mode transitions

| ID | Threat | Mitigation | Residual risk |
|----|--------|-----------|---------------|
| T-6 | **Silent registrar downgrade** — a `secure` → `learn`/`open` transition re-opens the registrar (re-enabling TOFU adoption / disabling digest); if it could happen silently or via an unauthenticated path it would erase the whole auth gain. | The registrar mode is an **NVS-backed runtime setting changed only by an explicit admin action** (onboarding wizard / Security screen), gated by the same admin-auth session as other mutating config (S-1/E-1). **No silent downgrade**; the transition is an auditable event. Mode is read at REGISTER time, so a downgrade takes effect deliberately, not by drift. | A physical/flash attacker who can rewrite NVS (T-4) can flip the mode directly — same root cause and same durable fix (flash encryption + Secure Boot). Audit-trail depth is limited by R-1 (no tamper-evident log) — a downgrade is logged to console but not tamper-evidently. |

### 9.5 Net assessment

Digest auth **would retire the long-standing S-3/D-2 SIP-layer gap** and is the
prerequisite for closing the open registrar. It is a real, link-independent control **as
implemented** — but it cannot be turned on: there is no way to set a per-extension secret
(see the caution at the head of §9), so `secure` mode rejects every phone rather than
authenticating it, and S-3/D-2 remain open in practice. **The single highest-leverage SIP
security work in the project is not more protocol — it is one operator-facing write path
for `SipSecretStore::setSecret()`.** The **Learn-mode adoption path trades a bounded window of trust-on-first-use for a
hand-free fleet cutover** — honest, useful, and *temporary*: it must be run admin-initiated,
short, and ideally on an encrypted link, then closed. The **MAC-based lock and the HA1 secret
store both lean on the LAN trust boundary** — the lock is spoofable on a hostile L2 and HA1 is
a bearer credential at rest. Neither changes the headline conclusion of §6/§8: **WPA2 on the
SoftAP** (gates association, encrypts the link) and **Secure Boot v2 + flash encryption**
(protects HA1 and the mode setting at rest) remain the two highest-leverage hardenings, and
the new auth surface composes with — rather than replaces — them.
