# Threat Model: pocket-dial ESP32 SIP PBX

> [!WARNING]
> **STALE as of 2026-09-13 — the auth model this document describes has been replaced,
> and this file has not yet been revised to match.** Two changes since v1.0 below:
> 1. The HTTP listen socket is now **always open** regardless of provisioning state —
>    the "dark by default once provisioned, DTMF `*4887` star-code to reopen" mechanism
>    §5.4/§5.5 and threat E-4 describe no longer exists. It caused a real hardware
>    lockout (dashboard "connection refused" the instant any client registered).
> 2. The admin credential is now a **username + password with a shipped default**
>    (`admin`/`admin`), not a bare PIN, and there is no more "unprovisioned = open,
>    no session needed" window (§5.1's "First-run gap") — every admin-gated action
>    is refused until the default credential is replaced (`setup_required`, enforced
>    server-side). The phone-keypad DTMF admin menu now uses a **separate** numeric
>    PIN with no default at all (disabled until explicitly set), independent of the
>    web login.
>
> Every section below through §5.5, plus threat entries S-1/E-1/E-4/D-3/I-5 and the
> "PIN strength"/"Mandatory admin PIN" recommendations, needs a full revision pass to
> match. Treat this file as historical context for *why* the auth layer exists, not as
> an accurate description of its current mechanics — see `docs/API.md` §0 and
> `docs/SETUP_GUIDE.md` §3 for the current model, and `src/Helpers/AdminAuth.{hpp,cpp}`
> for the source of truth.

**Date**: 2026-06-04 | **Version**: 1.0 | **Author**: Security Engineering | **Phase**: 1 (production hardening)

This document is a STRIDE-structured threat model for the **pocket-dial** ESP32 SIP PBX
and its HTTP dashboard. It focuses on the locally-reachable attack surface of a small
appliance that, by default, **runs its own open WiFi access point**. It complements the
broader `docs/SECURITY_AUDIT.md` (which tracks CVSS-scored findings) and records the
authentication change introduced in this phase: the dashboard's state-changing endpoints
are now gated by an admin PIN + server-side session, closing the previously
**unauthenticated admin** hole (audit finding SEC-04).

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
- **Persistence**: ESP-IDF **NVS** flash, namespace `"storage"`. Stores WiFi mode/SSID/
  password, a captive-portal `decayed` flag, and (new this phase) the admin credential
  (`admin_salt`, `admin_hash`).
- **Crypto available**: mbedTLS on-device (SHA-256, `esp_random()` hardware CSPRNG). The
  admin module ships its own self-contained SHA-256 so the credential format is identical
  on device and on the host/CI simulator.
- **Data classifications handled**: call control state, WiFi credentials (a secret),
  device-integrity/config, admin credential, real-time voice media.

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
| TB-1 | **Open SoftAP link (dominant boundary)** | Any RF-range device → device services | **NONE at link layer** — `WIFI_AUTH_OPEN`. App-layer: same-origin/CSRF check + (new) admin PIN/session on mutating HTTP endpoints. |
| TB-2 | LAN (eth / joined STA) | LAN host → device services | Network is as trusted as the LAN's own segmentation. Same app-layer controls as TB-1. |
| TB-3 | Browser → HTTP server | Dashboard user → endpoints | `isSameOrigin()` (Origin vs. Host), HttpOnly + `SameSite=Strict` session cookie, no wildcard CORS, request-body cap (16 KB), per-socket recv timeout. |
| TB-4 | HTTP/SIP → NVS | Handlers → flash | Writes gated behind same-origin + auth (HTTP); salted/iterated admin hash; explicit `confirm=ERASE` for factory reset. |
| TB-5 | Physical | Holder of the device → flash/JTAG | **NONE by default** — no flash encryption, no Secure Boot (see roadmap). |

> **The open SoftAP (TB-1) is the dominant boundary and the root of most residual risk.**
> Anyone within WiFi range can associate with no credential and is then a peer on the
> device's IP network with full reachability to HTTP, SIP, RTP and DNS. Every threat below
> should be read with "the attacker is an associated, unauthenticated AP client" as the
> baseline. The device is **not WAN/Internet-exposed by default** (no port forwarding, no
> cloud component); the realistic attacker is local/proximate, not remote.

---

## 3. Assets

| Asset | Why it matters | Primary threats |
|-------|----------------|-----------------|
| **Call control** (force-disconnect, active sessions) | Denial of phone service; disrupting live calls | Spoofing, Tampering, DoS, EoP |
| **WiFi credentials** (station SSID/password in NVS) | Reusable secret; pivot to the upstream network | Info disclosure, Tampering |
| **Device integrity / config** (mode, factory reset, OTA image) | Bricking, persistent control, supply-chain implant | Tampering, EoP, DoS |
| **Admin access** (PIN, session token) | Master key to all mutating actions | Spoofing, brute force, token theft, EoP |
| **Voice media + signaling** (RTP G.711, SIP) | Call confidentiality and privacy | Info disclosure (eavesdrop), Repudiation |

---

## 4. STRIDE Threat Enumeration

Each row: threat → current mitigation → **residual risk**.

### Spoofing
| ID | Threat | Mitigation | Residual risk |
|----|--------|-----------|---------------|
| S-1 | **Unauthenticated admin actions** — any AP peer POSTs `/api/kill`, `/api/wifi/connect`, `/api/wifi/mode_ap`, `/api/factory-reset`. *(was SEC-04)* | **FIXED this phase.** Once an admin PIN is provisioned, all four mutating endpoints require a valid `pd_session` cookie (else `401`). Login issues a server-side session token. | Before first provisioning the device is intentionally open (onboarding) — see *First-run gap* below. PIN strength is user-chosen. |
| S-2 | Session-cookie forgery / guessing | Token is ≥128-bit (`esp_random()` on device), opaque, validated server-side via constant-time compare; not derived from any user input. | Brute-forcing a 128-bit token over the network is infeasible; theft (S/T-3) is the realistic path. |
| S-3 | SIP identity spoofing (register/INVITE as another extension) | SIP signaling input is validated/bounded (audit SEC-02 mitigated). | **No SIP digest authentication** — on the open AP an attacker can register/INVITE as any extension. Tracked as a SIP-layer gap; out of scope for the HTTP auth change. |

### Tampering
| ID | Threat | Mitigation | Residual risk |
|----|--------|-----------|---------------|
| T-1 | Rewriting WiFi credentials / operating mode via dashboard | Same-origin + admin session gate (post-provisioning). | First-run gap; physical attacker (T-4). |
| T-2 | **CSRF** — a malicious page on the AP makes the victim's browser fire side-effecting POSTs | `isSameOrigin()` rejects requests whose `Origin` host ≠ `Host`; session cookie is `SameSite=Strict`; no wildcard `Access-Control-Allow-Origin`. **Added this phase:** a per-session **CSRF token** (128-bit, from `esp_random()`, stored in the session slot) that every mutating request must echo in an `X-CSRF` header. It is rendered into the dashboard document and never set as a cookie, so a cross-origin page cannot read it even though the browser would attach the cookie for it. Checked centrally in `HttpServer::requireAdmin()`. | A request with **no** `Origin` (curl, native app) is still allowed by design — that is what lets scripts and `tests/http/test_api.sh` work — but on a provisioned device it now needs **both** the session cookie and a matching token, so the Origin check is no longer load-bearing on its own. |
| T-3 | Request-body / parser abuse (oversized body, split TCP segments) | 16 KB body cap (`413`), `Content-Length` parsing with overflow guard, per-client `SO_RCVTIMEO`. | Low. |
| T-4 | **Physical flash tamper** — rewrite NVS / reflash | None by default. | **High if device is physically obtained**: NVS (incl. WiFi password and admin hash) is readable/writable. Mitigation is Secure Boot v2 + flash encryption (roadmap P2). |
| T-5 | **Firmware / OTA tampering** | OTA is being added by a parallel workstream. | Unsigned OTA = remote persistent compromise. **Durable fix: signed images + Secure Boot v2 + flash encryption** (roadmap). Until then, OTA must be admin-gated and ideally restricted to the local link. |
| T-7 | **SDP body abuse on the SIP plane** (CWE-674 class) — a well-formed INVITE / re-INVITE / UPDATE / 200 OK whose SDP `a=` lines are the payload. The UNISOC T612 VoLTE RCE (SSD advisory, 2026) was a normal MMTel video offer carrying `a=acap:1 acap:1 ...`; the modem's RFC 5939 acap decoder recursed once per token until the task stack overflowed into a neighbour. A PBX that relays bodies untouched (this one does, on hold/resume and P2P legs) is also the *delivery vector* for phones that are vulnerable. | **Design rule, pinned in code and tests.** (1) Every SDP body is checked ONCE in `RequestsHandler::handle()` before any decoder or relay — regardless of method or status, and with the MIME type matched case-insensitively — by `SipMessage::checkSdp()`: one flat, zero-heap pass enforcing `SdpLimits` (body ≤ 4 KB, ≤ 256 lines, ≤ 512 B/line, ≤ 40 tokens/line, ≤ 32 formats per `m=`, `a=` names ≤ 32 token chars) and refusing the RFC 5939 / 6871 / 7104 capability-negotiation attributes outright (`acap tcap pcfg acfg creq rmcap omcap mfcap mscap lcfg sescap bcap ccap icap`) because the PBX does not implement them. A violation is a hard error for the whole body: `488 Not Acceptable Here` + `Warning: 399 … "SDP refused: <reason>"` on a request, silent drop (never relayed, never advances a transaction) on a response or ACK; counted in `getSdpRejected()`. (2) The decoders that then run (`applyAudioPolicy`, `getSdpDirection`, `SipSdpMessage`) are flat loops over fixed 128-slot tables — no heap, no `std::function`/callback on the parser task's stack, no handler dispatched from inside another. (3) Recursion is pinned structurally: `tests/tools/check_parser_callgraph.py` compiles the SIP TUs with GCC `-fcallgraph-info` and fails on any cycle or dynamic frame (`checkSdp` is 2 frames / ~200 B). (4) Backstop in `sdkconfig.defaults`: `CONFIG_FREERTOS_WATCHPOINT_END_OF_STACK` (hardware trap on the first write past a task stack) and `CONFIG_COMPILER_STACK_CHECK_MODE_STRONG` (per-frame canary). Tests: `tests/SdpAdmission_test.cpp`, `tests/SipSdpMessage_hardening_test.cpp`. | Low. Attributes the PBX does not read (`candidate`, `fingerprint`, `fmtp` values …) are still relayed verbatim inside the caps; a peer phone's own parser bugs in those are the phone's. `a=csup` is deliberately admitted (advertises support only). |

### Repudiation
| ID | Threat | Mitigation | Residual risk |
|----|--------|-----------|---------------|
| R-1 | Admin/call actions are not attributable | Console logging exists; no tamper-evident audit trail; no per-user identity (single shared PIN). | Medium. Acceptable for a single-admin appliance; note that a single shared PIN cannot distinguish operators. |

### Information Disclosure
| ID | Threat | Mitigation | Residual risk |
|----|--------|-----------|---------------|
| I-1 | **RTP voice eavesdropping on the open AP** | None at app layer (G.711 is uncompressed, unencrypted). | **High on open SoftAP**: any peer can sniff/replay call audio. The single highest-leverage fix is **WPA2 on the SoftAP** (encrypts the whole link). SRTP would be the app-layer fix but is heavyweight on the MCU. |
| I-2 | **SIP signaling disclosure** (who calls whom, extensions, topology) | None (cleartext SIP). | **High on open SoftAP**; same fix as I-1 (WPA2 link encryption). SIP-over-TLS is the app-layer option but costly on-device. |
| I-3 | WiFi station password recoverable | Stored cleartext in NVS (audit SEC-03). Not exposed over HTTP. | Recoverable by a **physical** attacker (flash read). Fix = flash encryption (P2). |
| I-4 | Verbose error / stack leakage | Endpoints return generic JSON errors; no stack traces or internal paths. | Low. |
| I-5 | Admin hash disclosure | Stored as **salted, iterated SHA-256** (50k rounds, 128-bit random salt), never returned over HTTP. | Offline cracking requires a **physical NVS read**; the salt defeats rainbow tables and the iteration count slows guessing. Still, a short/numeric PIN is brute-forceable offline once flash is read — see *PIN strength*. |

### Denial of Service
| ID | Threat | Mitigation | Residual risk |
|----|--------|-----------|---------------|
| D-1 | Connection/slowloris exhaustion on HTTP | Detached per-connection threads, `SO_RCVTIMEO` (5 s), body cap. | A flood from the open AP can still pressure a constrained MCU. |
| D-2 | Malicious call teardown (`/api/kill` abuse) | Now admin-gated post-provisioning. | First-run gap; SIP-layer teardown (BYE spoofing) still possible without SIP auth (S-3). |
| D-3 | PIN-guess lockout used as self-DoS | Lockout is global/in-process (not per-IP), so an attacker can lock out the legitimate admin for the cooldown (60 s) — **but the device stays usable** because pre-existing sessions remain valid and only `login` is throttled. | Accepted trade-off; **per-IP lockout would be stronger** (see *Brute force*). Cooldown auto-clears (no permanent lock). |
| D-4 | RF jamming / deauth of the SoftAP | None (inherent to WiFi). | Out of scope; physical/RF layer. |

### Elevation of Privilege
| ID | Threat | Mitigation | Residual risk |
|----|--------|-----------|---------------|
| E-1 | Anonymous AP peer → full admin control | **FIXED**: PIN/session gate on all mutating endpoints. | First-run gap; physical/OTA paths (T-4/T-5). |
| E-2 | Read endpoints leaking privileged actions | `/api/status`, `/api/wifi/scan`, `/api/admin/status` are read-only and intentionally unauthenticated (the dashboard needs them to render). `/api/admin/status` returns only booleans (`provisioned`, `authenticated`) — no secrets. | Low. SSID list / status are observable by any AP peer (already visible on an open AP anyway). |
| E-3 | **SSH sysop terminal as a second, unbounded admin surface** | **REMOVED this phase.** `SshServer`/`Tui` and their wolfSSH transport were deleted entirely rather than further hardened — see §5.5. HTTP is now the only admin surface. | None; the surface no longer exists. |
| E-4 | **Spoofed DTMF admin trigger** — an attacker on the local link sends a crafted SIP INFO `*4887` claiming to be the admin extension | Revised: the original design gated this on a PIN embedded in the DTMF sequence (`*<PIN>#010`), but `#` is bound to Send/Call on Yealink and most SIP hardphones, so a PIN+`#` sequence never reaches the DTMF-relay path intact — real hardphones can't dial it. The trigger is now `*4887` (spells HTTP on the keypad), no PIN, and trust shifts entirely to: caller extension == the admin extension, that extension currently registered, **and** the INFO's source IP matches the registration's bound IP (mirrors the existing dialog-source-IP check used for BYE/teardown). A spoofed `From:` header from a different IP is rejected regardless. | Weaker than the original PIN-gated design in one respect: anyone who can register as the admin extension (from the right IP) can open the transport without knowing the PIN — opening still does not bypass PIN/session auth on the endpoints themselves (§5.1–5.3). An attacker who has *also* spoofed the source IP defeats the IP check the same way IP spoofing defeats any IP-based check on the open AP — see §5.5's residual. |

---

## 5. Detailed Notes on Key Threats

### 5.1 The first-run / onboarding gap (by design)
A factory-fresh device has **no admin PIN**. To preserve captive-portal onboarding (and the
existing CI smoke tests, which never set a PIN), the mutating endpoints behave exactly as
before **while unprovisioned**: same-origin gate only, no auth. The instant a PIN is set
(`POST /api/admin/set-pin`), the `401` gate engages. **Operational guidance: set the admin
PIN as the first onboarding step.** A future hardening could auto-provision a random PIN
shown on the device's screen/serial on first boot to eliminate even this window.

### 5.2 PIN brute force
- **Online**: `verifyPin` counts consecutive failures; after **5** it engages a **60 s**
  lockout during which even a correct PIN is refused (`429`).
  **Revised this phase.** The counter used to be zeroed the moment the lockout engaged, so
  every cooldown handed the attacker a fresh window of 5 — a steady ~5 guesses/minute for
  as long as they cared to keep going, which walks a 4-digit PIN in about a day and a half.
  The trip count now survives the cooldown and each successive lockout doubles
  (`kLockoutMs << min(trips-1, 4)`, capped at 16 minutes). Only a **correct PIN** clears it.
- **Offline**: a leaked hash (only obtainable via **physical NVS read**) is a salted,
  iterated SHA-256 (50,000 rounds, per-credential 128-bit salt). This defeats precomputation
  and slows guessing, but a 4-digit numeric PIN is only 10⁴ candidates — trivially crackable
  offline. **PIN strength is the user's responsibility**; recommend ≥6 alphanumeric chars,
  and note that the real backstop for offline attack is flash encryption (P2).
- **Per-client accounting — DONE this phase.** Failures are counted against the HTTP peer
  address in a fixed table of 8 least-recently-seen-evicted buckets, so one guessing client
  can no longer lock the legitimate admin out of new logins (this retires **D-3**). The key
  is for *fairness, not trust*: a source address is trivially spoofable on the shared link,
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
implemented sliding expiry since it was written. Corrected here rather than in the code:
sliding is the intended behaviour.)* Each session also carries the per-session CSRF token
described in T-2. Cookie flags: `HttpOnly` (no JS access → blunts XSS exfiltration) and
`SameSite=Strict` (browser won't attach it cross-site → blunts CSRF).
**No `Secure` flag and no TLS**: on plain HTTP over the open AP, a network sniffer can
capture the cookie in transit and **replay** it until expiry. This is the same root cause as
I-1/I-2 and has the same headline fix — **WPA2 on the SoftAP encrypts the cookie in flight**.
Residual: a token has no rotation/binding to client IP; theft within the 30-min window is
usable. Logout (`/api/admin/logout`) and factory reset both destroy sessions immediately.

### 5.4 Captive-portal / DNS-spoof phishing
In onboarding mode the device answers **all** DNS queries with its own IP (port 53) to
trigger the OS captive-portal prompt. On an open AP an attacker could stand up a competing
portal/AP to phish the WiFi password or the admin PIN. The same-origin check prevents a
foreign page from driving the *real* device's API, but it cannot stop a user from typing
secrets into a look-alike. Mitigation is again **WPA2** (raises the bar to join/impersonate)
plus user guidance to provision over a trusted link.

### 5.5 HTTP admin plane: dark-by-default transport gate + DTMF trigger, SSH removed
Summary of what changed and what it does and does not buy:

- **Before**: once provisioned, the HTTP listen socket accepted connections continuously;
  `/api/*` was gated by PIN/session auth (§5.1–5.3), not by whether the transport was
  reachable at all. SSH (`SshServer`/`Tui`, wolfSSH) was a **second**, separately-wired admin
  surface with no comparable auth-gate discipline, always listening on port 22 whenever the
  display transport was built.
- **After**: SSH is deleted, not hardened — it no longer exists as an attack surface (E-3).
  HTTP is dark by default the instant a device is provisioned. It opens only for a bounded
  TTL (default 10 min, NVS-configurable) after one of three events: (a) a DTMF trigger from
  the registered admin extension, source-IP-verified against that registration (E-4), (b) the
  moment a PIN is first set/changed via the web UI itself (a grace window, so onboarding isn't
  self-defeating — found and fixed during this rollout by exercising the existing
  `tests/http/test_api.sh` CI smoke suite end-to-end, not just new unit tests), or (c) an
  already-authenticated operator clicking "Keep open" in the dashboard (`POST
  /api/admin/keepalive`, gated on a valid `pd_session` cookie — unauthenticated calls get
  `401` and cannot move the deadline), which extends the window by a flat 1 hour so extended
  configuration work doesn't get cut off mid-session. **Opening the transport does not bypass
  PIN/session auth** — §5.1–5.3 apply unchanged once a connection is accepted.
- **What this buys**: an attacker who has NOT compromised a registered handset (or timed
  their attempt to land inside someone else's legitimate open window) cannot even reach
  `/api/admin/login` to attempt PIN brute force (D-3, S-1) — the socket simply refuses the
  connection. This shrinks the PIN-brute-force and session-token-theft (§5.2, §5.3) exposure
  window from "always" to "minutes, gated behind a second factor."
- **Residual, stated honestly**: HTTP is still **plaintext**. During an open window, a
  same-AP attacker can sniff the admin session exactly as described in §5.3 and §5.6 — this
  plan does not add TLS (see §6). It only shrinks *when* that sniffing is possible, not
  whether it's possible during the window. The DTMF trigger's source-IP check is an IP-layer
  control; it does not defend against an attacker who has ALSO achieved IP spoofing on the
  local link (the same limitation every IP-based check in this document shares — see T-2's
  and I-1's WPA2 recommendation as the actual fix for the shared link-layer trust problem).
  The 250ms accept-loop poll interval means the open/close transition is not instantaneous;
  this is a scheduling latency, not a security gap (invariant: fails closed on ambiguity).

- **Residual: PINs provisioned before the `4887`-prefix guard existed (Issue #93)**. The
  DTMF trigger `*4887` is matched the instant the accumulated digit sequence equals that
  string — before the `*PIN#code` admin-menu parser runs. An admin PIN beginning `4887`
  is therefore shadowed: the star-code fires mid-entry, clears the DTMF accumulator, and
  the `*PIN#code` command the admin was actually dialing never completes. `POST
  /api/admin/set-pin` rejects new/changed PINs with that prefix, but a device provisioned
  **before** that guard shipped can still be carrying one, and the guard cannot retroactively
  detect it — the PIN is stored salted+hashed, so there is no way to recover it and check.
  `onDtmfInfo` makes a best-effort, imperfect behavioral detection: if `*4887` just fired for
  the admin extension's dialog and the following digits then shape up as an interrupted
  `*PIN#code` continuation (a `#` followed by 3+ digits, no leading `*` — consistent with the
  admin having kept dialing into the accumulator the star-code just cleared), it logs a
  targeted warning suggesting a PIN rotation. This is a heuristic, not a diagnosis — it can
  both false-negative (an admin who gives up after the first `*4887` fire never triggers it)
  and, in principle, false-positive on an unrelated sequence that happens to fit the same
  shape. **Operators upgrading a device provisioned before this guard existed should rotate
  any admin PIN beginning `4887` via the dashboard (`POST /api/admin/set-pin`) regardless of
  whether the warning ever fires.**

### 5.6 Cleartext SIP + RTP on the open AP
This is the largest *confidentiality* gap and is **independent of the dashboard auth fix**.
The admin PIN protects *control*, not *media*. SIP signaling and G.711 RTP traverse the open
link in cleartext, so any associated peer can record calls and map who-calls-whom. App-layer
fixes (SIP-over-TLS, SRTP) are expensive on a constrained MCU and add key-management UX. The
**link-layer fix (WPA2 on the SoftAP) encrypts everything — dashboard, SIP, and RTP — at
once**, which is why it is the top recommendation below.

---

## 6. The TLS Question (HTTPS for the dashboard) — answered honestly

**Should the dashboard serve HTTPS (self-signed) on the ESP32?**

**Recommendation: not as the primary control. Ship HTTP + a mandatory admin PIN now, and
enable WPA2 on the SoftAP as the single highest-leverage hardening.** Self-signed HTTPS is
listed as a *documented optional* future enhancement, not the headline fix.

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

**Net**: HTTP + mandatory PIN (this phase) + WPA2 SoftAP (recommended P0) gives confidentiality
*and* control protection for the whole link. Optionally layer self-signed HTTPS later for the
dashboard if a specific deployment requires app-layer transport security on top of WPA2 — but
do it eyes-open about the warning UX and MCU cost.

---

## 7. Prioritized Hardening Roadmap

### P0 — do now / next (highest leverage, low-to-moderate effort)
- **WPA2 on the SoftAP — DONE this phase (opt-in).** `WIFI_AUTH_WPA2_PSK` behind the NVS flag
  `ap_secure` (default off for fleet compatibility), with a per-device `esp_random()`
  passphrase surfaced on-screen, over serial, in the dashboard, and settable at flash time.
  *Closes the dominant boundary once enabled; encrypts dashboard + SIP + RTP.* **Operational
  guidance: turn it on.** See §6 for why the previous hardcoded onboarding PSK did not count.
- **Mandatory admin PIN — DONE this phase** (PIN + server-side session on all mutating HTTP
  endpoints; lockout; factory reset clears the credential). Make setting the PIN the first
  onboarding step in the UI/docs.
- **HTTP admin plane dark-by-default + SSH removed — DONE this phase** (see §5.5). The
  transport itself, not just the auth layer, is now unreachable on a provisioned device
  except for a bounded TTL after a source-IP-verified DTMF trigger or a fresh provisioning
  grace window. SSH (`SshServer`/`Tui`, wolfSSH) is deleted, removing the second
  admin surface entirely rather than hardening it further.
- **Guidance/UX**: require a PIN of ≥6 alphanumeric chars; warn against 4-digit numeric PINs.

### P1 — soon (meaningful, moderate effort)
- **SIP authentication** (digest auth on REGISTER/INVITE) to stop extension spoofing and
  BYE-based teardown (S-3, D-2) even on a trusted link.
- **Per-IP brute-force tracking for `login` — DONE this phase** (replaces the global counter,
  removes the admin-lockout self-DoS in D-3, and stops the cooldown from resetting the
  failure budget). See §5.2.
- **Gate OTA behind the admin session** and restrict it to the local link until image
  signing lands.
- **Session hardening**: optional idle timeout in addition to absolute expiry; consider
  binding a token to the client association.

### P2 — durable platform hardening (higher effort, strongest guarantees)
- **Secure Boot v2 + flash encryption**: signs the firmware (defeats OTA/boot tampering,
  T-5/T-1) and encrypts NVS at rest (defeats physical recovery of the WiFi password and admin
  hash, I-3/I-5/T-4). This is the durable fix for the physical and supply-chain boundaries.
- **Signed OTA images** verified against the Secure Boot key.
- **Tamper-evident audit logging** for admin/call actions (addresses R-1) if multi-operator
  attribution becomes a requirement.
- **Optional self-signed HTTPS** for the dashboard, as a documented add-on on top of WPA2
  (see §6), for deployments that mandate app-layer transport security.

---

## 8. Summary

The change shipped in this phase removes the **unauthenticated-admin** elevation-of-privilege
hole (S-1 / E-1 / audit SEC-04): once provisioned, call control and WiFi/mode/factory-reset
require an admin PIN and a server-side session, layered on top of the existing same-origin
defense, while preserving open first-run onboarding and the existing CI smoke tests. The
**dominant residual risk is the open SoftAP** (TB-1), which leaves call media and signaling
eavesdroppable (I-1/I-2) and the session cookie replayable (5.3). The single highest-leverage
next step is **WPA2 on the SoftAP**, which encrypts the whole link in one move; physical and
firmware-supply-chain risks are durably addressed by **Secure Boot v2 + flash encryption**.

---

## 9. The SIP auth surface (digest auth + Learn mode)

> **Status: SHIPPED and now operator-reachable.** This section used to be marked
> "forward-looking … not yet shipped code". That was stale: `SipDigest.{hpp,cpp}`,
> `SipSecretStore.{hpp,cpp}`, the `Registrar::Mode` state machine and its NVS
> persistence are all on `main`, and `Registrar::loadMode()` runs from the
> `RequestsHandler` constructor, so a persisted mode is honoured at boot.
>
> **The gap that made all of it moot has been closed.** Until now
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
>   it on a headless board before first boot.
>
> The S-3/D-2 registrar gap in §4 is therefore closable in the field now — but note it is
> only *closable*, not closed: the shipped default is still `open`, so it protects
> deployments that actually switch.
>
> It extends the STRIDE analysis above with the new IDs `S-4`, `D-5`, `I-6`, `T-6`, `E-3`
> and continues the residual-risk convention. Cross-refs: [FEATURE_ROADMAP.md](FEATURE_ROADMAP.md)
> §3.3 (SIP digest auth, WPA2), the operator runbook [LEARN_MODE.md](LEARN_MODE.md), and
> [PROVISIONING.md](PROVISIONING.md) §7.3 (the shared per-extension secret store).

The registrar is **fully open today** (`POCKETDIAL_OPEN_REGISTRAR`); §4 records this as the
S-3/D-2 SIP-layer gap, explicitly out of scope for the HTTP-auth change. This phase closes
it. SIP **digest authentication** (RFC 2617, MD5 / `qop=auth`) challenges **REGISTER** —
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
| I-6 | **Per-extension digest secret recoverable from flash.** Unlike the admin PIN (one-way salted/iterated SHA-256, I-5), digest auth requires the server to **recompute** the response, so the secret store holds **HA1 = MD5(ext:realm:secret)** — a *recoverable-equivalent bearer credential*, not a one-way hash. Anyone who can read HA1 can authenticate as that extension (HA1 is directly usable in the digest computation; the cleartext secret is not even required). | HA1 is never returned over HTTP and never logged. It lives in a **separate NVS store** from `AdminAuth` (mirrors the `prov` per-MAC layout, [PROVISIONING.md](PROVISIONING.md) §5). Offline recovery requires a **physical NVS read** (same precondition as I-3/I-5). | **HA1 is a bearer credential at rest — weaker at-rest than the one-way admin hash by necessity of the protocol.** This *pairs directly with the existing flash-encryption / Secure Boot v2 item* (T-4/I-3/I-5): encrypting NVS at rest is the durable fix and the secret store inherits it. Until flash encryption lands, a physical attacker who reads NVS obtains usable extension credentials. |

### 9.4 Registrar-mode transitions

| ID | Threat | Mitigation | Residual risk |
|----|--------|-----------|---------------|
| T-6 | **Silent registrar downgrade** — a `secure` → `learn`/`open` transition re-opens the registrar (re-enabling TOFU adoption / disabling digest); if it could happen silently or via an unauthenticated path it would erase the whole auth gain. | The registrar mode is an **NVS-backed runtime setting changed only by an explicit admin action** (onboarding wizard / Security screen), gated by the same admin-auth session as other mutating config (S-1/E-1). **No silent downgrade**; the transition is an auditable event. Mode is read at REGISTER time, so a downgrade takes effect deliberately, not by drift. | A physical/flash attacker who can rewrite NVS (T-4) can flip the mode directly — same root cause and same durable fix (flash encryption + Secure Boot). Audit-trail depth is limited by R-1 (no tamper-evident log) — a downgrade is logged to console but not tamper-evidently. |

### 9.5 Net assessment

Digest auth **retires the long-standing S-3/D-2 SIP-layer gap** and is the prerequisite for
closing the open registrar. It is a real, link-independent
control. The **Learn-mode adoption path trades a bounded window of trust-on-first-use for a
hand-free fleet cutover** — honest, useful, and *temporary*: it must be run admin-initiated,
short, and ideally on an encrypted link, then closed. The **MAC-based lock and the HA1 secret
store both lean on the LAN trust boundary** — the lock is spoofable on a hostile L2 and HA1 is
a bearer credential at rest. Neither changes the headline conclusion of §6/§8: **WPA2 on the
SoftAP** (gates association, encrypts the link) and **Secure Boot v2 + flash encryption**
(protects HA1 and the mode setting at rest) remain the two highest-leverage hardenings, and
the new auth surface composes with — rather than replaces — them.
