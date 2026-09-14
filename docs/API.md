# Pocket-Dial ESP32 Firmware: HTTP REST API Specification

This document provides the formal API specification for the HTTP control interface of the **pocket-dial** firmware. The API handles status reporting, client management, and Wi-Fi onboarding.

> [!NOTE]
> **This catalog is complete as of 2026-09-13.** Every route
> `HttpServer::handleClient()` dispatches appears in §4's table, and every row in
> that table links to a section that specifies it — including the four
> `/api/admin/*` session routes, which used to live only in §0. Source of truth
> for all of it: `src/Helpers/HttpServer.cpp` — the `handleClient()` dispatch
> chain from line 433, plus the `POST /api/ota/upload` interception at line 300
> that is deliberately *not* in that chain.
>
> Everything here was derived by reading the handlers. Where a response string is
> quoted, it is the literal string in a `sendResponse(...)` call. Where a
> parameter is listed, it is a real `getFormParam()` read. Nothing in this
> document is claimed to be hardware-verified unless it names the test that
> covers it (`tests/http/test_api.sh`, whose TC-IDs are cited inline).

---

## 0. Reachability & Admin Session Layer (read this first)

**The HTTP server's TCP listener always accepts connections**, regardless of
provisioning state — there is no socket-level dark/open gate. The device ships
with a well-known default login (username `admin`, password `admin`); every
admin-gated endpoint requires a valid `pd_session` cookie, and until the
operator replaces the default credential (`POST /api/admin/set-credential`),
every admin-gated endpoint **except** `set-credential` itself is refused with
`403 {"error":"setup_required"}` — "force setup on first use," enforced
server-side, not just suggested by the dashboard UI.

A separate, independent numeric **DTMF admin PIN** (phone-keypad `*PIN#code`
menu — NTP resync, topology switch, factory reset) has no default at all and
stays fully disabled until explicitly set via the same `set-credential`
endpoint's `dtmfPin=` field. Threat analysis: `docs/THREAT_MODEL.md` §5.5.

**Admin session endpoints** (all JSON; full specs in §4, linked from each row):

| Endpoint | Method | Auth | Purpose |
| :--- | :--- | :--- | :--- |
| [`/api/admin/status`](#get-apiadminstatus) | `GET` | None | `{provisioned, needsSetup, authenticated, sessionRemainingSec}` for dashboard render. `provisioned`/`needsSetup` are inverses of each other and describe the login credential only. |
| [`/api/admin/set-credential`](#post-apiadminset-credential) | `POST` | Session (+CSRF) | Change the login credential and/or the DTMF PIN. `username=`+`password=` (≥8 chars) must both be provided together to change the login credential; `dtmfPin=` (4-16 digits) alone changes just the DTMF PIN. Reachable even while `needsSetup` is true — it's the one exemption to the setup_required gate. |
| [`/api/admin/login`](#post-apiadminlogin) | `POST` | `username=`+`password=` in body | Verifies against the stored credential, or the default (`admin`/`admin`) if none has been set yet. Issues the `pd_session` cookie (HttpOnly, SameSite=Strict) and the session's CSRF token. Same-origin checked, **no CSRF token required** (there is no session yet to bind one to). Rate-limited with lockout. |
| [`/api/admin/logout`](#post-apiadminlogout) | `POST` | Same-origin only | Destroys the session named by the cookie and expires it client-side. No session or CSRF token required — a forced logout is a nuisance, not a compromise. |

Every state-mutating endpoint (`/api/kill`, `/api/dnd`, `/api/forward`,
`/api/group`, `/api/dialplan`, `/api/wifi/*`, `/api/factory-reset`, OTA upload,
`/api/telephony-config`, `/api/did-mapping`, `/api/admin/set-credential`, ...)
requires both the `pd_session` cookie and the per-session CSRF token — from
the very first login, including while still on the default credential.

### 0.1 The four gates, in the order `requireAdmin()` applies them

`HttpServer::requireAdmin(sock, req, needCsrf)` (`src/Helpers/HttpServer.cpp:1828`)
is the single gate every admin-gated route goes through. It short-circuits on the
first failure, so these are the error bodies you will actually see, in this order:

| # | Check | Applies to | Failure | Body |
| :-: | :--- | :--- | :--- | :--- |
| 1 | Same-origin | Every gated route, **`GET`s included** | `403` | `{"error":"cross-origin request rejected"}` |
| 2 | Valid `pd_session` cookie | Every gated route, `GET`s included | `401` | `{"error":"authentication required"}` |
| 3 | Matching `X-CSRF` header | Only when `needCsrf` is `true` (mutating routes) | `403` | `{"error":"missing or invalid CSRF token"}` |
| 4 | Forced initial setup | Every gated route **except** `POST /api/admin/set-credential` | `403` | `{"error":"setup_required","message":"Change the default admin credential before continuing."}` |

> [!IMPORTANT]
> **Gate 4 is the one that surprises every new integrator.** While the device is
> still on the shipped `admin`/`admin` credential, a correctly authenticated,
> correctly CSRF-tokened request to *any* admin-gated route — including read-only
> `GET`s like `/api/registrar`, `/api/telephony-config` and `/api/pcap` — comes
> back `403 {"error":"setup_required"}`. The only route that works is
> `POST /api/admin/set-credential`. Until you have called it once, the API is
> effectively a two-call API: log in, then set a real credential. Covered by
> `test_api.sh` TC-AUTH-05 (a gated `POST` refused `403` while on the default) and
> TC-AUTH-07/08 (setup completes, `needsSetup` flips to `false`).

> [!NOTE]
> **`curl` needs no special handling for the same-origin check.** `isSameOrigin()`
> returns `true` immediately when the request carries no `Origin` header at all
> (`HttpServer.cpp:1741`) — that is a deliberate decision, not an oversight, so
> that CLI clients, native clients and the CI smoke suite keep working. Gate 1 is a
> browser-only control and cannot stand alone; gates 2-4 are what actually protect
> the device. Verified by `test_api.sh` TC-SEC-01 (no `Origin` header → `200`).

---

## 1. Global Server Settings & Connection Behavior

The HTTP server operates under strict resource constraints and security policies designed to prevent device crashes and malicious manipulation.

### Connection Limits & Socket Policies
* **Protocol**: HTTP/1.1
* **Default Port**: 80 (Overridden to custom port if configured)
* **Socket Timeout (`SO_RCVTIMEO`)**: **5 Seconds**. Connections that do not send data within 5 seconds of connection are forcefully closed.
* **Payload Limit**: **16 KB (16,384 bytes)**. Any request body larger than 16 KB (including large Wi-Fi passwords) is rejected with status `413 Payload Too Large` and the body `{"error":"request body exceeds 16 KB limit"}` (`HttpServer.cpp:405-410`). There are **two** exceptions, both intercepted before this cap is applied and streamed instead: [`POST /api/ota/upload`](#post-apiotaupload) and **`POST /api/moh/upload`**, which carries its own **8 MB** cap (`HttpServer.cpp:2911-2923`) rather than 16 KB. The interception matches either path on the request line (`HttpServer.cpp:314-316`).
* **Request body framing**: `Content-Length` only. There is no `Transfer-Encoding: chunked` support anywhere in the parser — a chunked upload would be read as an opaque body with chunk framing bytes in it. Always send an explicit `Content-Length` (curl does this for you for `-d` and `--data-binary @file`).
* **Concurrency**: one detached thread per accepted connection. If thread creation fails under memory pressure the connection is dropped silently rather than answered (`HttpServer.cpp:218`).

### Global error responses

Two errors come from the request pipeline rather than from any handler, so they can
appear on any path:

| Status | Content-Type | Body | When |
| :--- | :--- | :--- | :--- |
| `413 Payload Too Large` | `application/json` | `{"error":"request body exceeds 16 KB limit"}` | `Content-Length` over 16,384 on any route except the OTA upload. |
| `404 Not Found` | **`text/plain`** | `404 Not Found` | No route in the dispatch chain matched the method+path pair. |

> [!NOTE]
> The fallback `404` is the **only non-JSON error in the API** (`send404()`,
> `HttpServer.cpp:1885`). A client that blindly `JSON.parse()`s every error body
> will throw on an unknown route and on a `/config/<mac>.cfg` miss. `test_api.sh`
> TC-ED-04 asserts the status code but not the content type.
>
> Note also that a *method* mismatch produces this same `404`, not a `405`: there is
> no `Allow` header and no `405 Method Not Allowed` anywhere in the server. `GET
> /api/kill` is a `404`, not a `405`.

### Response Framing Headers
Every API response carries the usual framing headers:
```http
Content-Type: application/json (or text/html for static files)
Content-Length: <byte_count>
Connection: close
```
The **security** headers (CSP, `X-Frame-Options`, `nosniff`, `Cache-Control`,
`Referrer-Policy`) are emitted centrally on every response as well — they are listed in
§2.2, which is the authoritative set.
> [!IMPORTANT]
> **CORS Restrictions**: No `Access-Control-Allow-Origin` headers are sent. Wildcard CORS is prohibited to prevent background malicious browser tabs from reading internal VoIP station mappings.

---

## 2. Security & Same-Origin Verification (CSRF Protection)

To prevent Cross-Site Request Forgery (CSRF) exploits when operating as an open Wi-Fi
network, the server applies Same-Origin Verification to **every gated route** — every
state-mutating endpoint (`/api/kill`, `/api/dnd`, `/api/forward`, `/api/group`,
`/api/dialplan`, `/api/telephony-config/*`, `/api/did-mapping`, `/api/wifi/connect`,
`/api/wifi/mode_ap`, `/api/configuring`, `/api/ap-security`, `/api/registrar*`,
`/api/factory-reset`, the OTA routes and `/api/admin/set-credential`), **and also the
gated reads** (`/api/pcap`, `/api/diagnostics/pcap`, `/api/trace`,
`/api/telephony-config`, `/api/did-mapping`, `/api/registrar`, `/api/ap-security`), plus
`/api/admin/login` and `/api/admin/logout` via `requireSameOrigin()` directly. It is
gate 1 of `HttpServer::requireAdmin()` ([§0.1](#01-the-four-gates-in-the-order-requireadmin-applies-them)),
applied centrally so no route can omit it. Only the genuinely public reads listed in §4
skip it:

1. **Origin Header Scan**: The server parses the HTTP `Origin` header.
2. **Direct/Same-Origin Allow**:
   * If `Origin` is missing (direct browser navigation, local CLI `curl` requests), the transaction is **allowed**.
   * If `Origin` is present, its host and port are extracted and compared directly against the HTTP `Host` header sent by the client.
3. **Cross-Origin Reject**: If the `Origin` host does not match the `Host` header (indicating a background request from a malicious external site), the server rejects the request with **`403 Forbidden`** and the JSON body:
   ```json
   {
     "error": "cross-origin request rejected"
   }
   ```

### 2.1 Per-session CSRF token (`X-CSRF`)

The Origin check above is a **browser-only** control, and it deliberately admits requests
with no `Origin` header at all so that `curl`, native clients and the CI smoke suite keep
working. That gap is closed by a per-session CSRF token — on every device, from the first
login onward:

* A 128-bit token is minted alongside the session at login and stored server-side beside it.
* It is delivered two ways: rendered into the dashboard document, and returned in the login
  response body as `"csrf"`. It is **never** set as a cookie — the browser would attach a
  cookie to a same-site request on its own, so only a value our own page has to read and
  echo back proves where the request came from.
* Every **mutating** request must send it in an `X-CSRF` header. It is checked centrally,
  in `HttpServer::requireAdmin()`, so no endpoint can forget it.

A mutating request with a valid session but a missing or wrong token is rejected with
**`403 Forbidden`**:

```json
{ "error": "missing or invalid CSRF token" }
```

**Exemptions**, and why:

| Endpoint | Why no token |
|----------|--------------|
| `POST /api/admin/login` | There is no session yet, so there is nothing to bind a token to. |
| `POST /api/admin/logout` | A forced logout is a nuisance, not a compromise, and `SameSite=Strict` already blocks it. Requiring a token would strand a user on a stale page. |
| All `GET` endpoints | Reads are not state changes. They are still same-origin checked and, where sensitive, session-gated. |

> **Changed.** Earlier firmware also exempted *every* request made while the device was
> unprovisioned, on the grounds that a factory-fresh device had no session to bind a
> token to. That exemption no longer exists: the device ships with a default credential,
> so there is always a session to log into and always a token to mint. Onboarding
> (`/api/wifi/connect`, `/api/wifi/mode_ap`, `/api/configuring`) now requires logging in
> with `admin`/`admin` and then completing the forced setup first.

### 2.2 Security response headers

Emitted centrally on **every** response (`HttpServer::sendResponseWithHeader`):

| Header | Value |
|--------|-------|
| `Content-Security-Policy` | `default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'` |
| `X-Frame-Options` | `DENY` |
| `X-Content-Type-Options` | `nosniff` |
| `Cache-Control` | `no-store` |
| `Referrer-Policy` | `same-origin` |

The dashboard is one self-contained page with inline `<script>`/`<style>` and no external
origins, which is why the policy can be this tight.

There is deliberately **no** `Strict-Transport-Security`. The dashboard is plain HTTP on a
LAN appliance; pinning HSTS would make the device permanently unreachable over `http://`
with no way for a user to override it.

---

## 3. Captive Portal Redirect Mechanism

When booting into onboarding mode, the device intercepts client browser check domains (e.g. `captive.apple.com`, `connectivitycheck.gstatic.com`) to display the setup screen.

* **Build guard**: the whole mechanism is inside `#if defined(ESP_PLATFORM)`
  (`HttpServer.cpp:415`). **The host/desktop build never redirects**, which is why
  the CI smoke suite can point any `Host` header it likes at `127.0.0.1`.
* **Method**: `GET` only. A `POST`/`PUT`/`DELETE` with a foreign `Host` is dispatched
  normally and answered by its handler (or the fallback `404`), never redirected.
* **Trigger**: a `GET` whose `Host` header does not *contain* any of:
  * `192.168.4.1` (the local SoftAP gateway IP)
  * `localhost`
  * `pocketdial` (mDNS hostname)
  * the server's configured IP.
  These are substring tests, not equality tests. Separately, if the server was
  constructed with the IP `0.0.0.0` (the usual case — it binds `INADDR_ANY`),
  **every** `Host` is treated as local and the redirect never fires at all.
* **Exempt paths**: [`GET /api/status`](#get-apistatus) and
  [`GET /api/wifi/scan`](#get-apiwifiscan) are excluded from the redirect by name,
  so a captive-portal client can still poll state and scan for networks while the
  OS probe is being redirected. No other path is exempt — a foreign-`Host` `GET` to
  `/api/cdr` or `/api/ota/status` *is* redirected.
* **Action**: The server immediately returns a `302 Found` redirect to the captive portal landing page:
  ```http
  HTTP/1.1 302 Found
  Location: http://192.168.4.1/
  Content-Length: 0
  Connection: close
  ```

---

## 4. REST API Endpoint Catalog

> **Reading the "Auth Required" column.** "Gated" means the request goes through
> `HttpServer::requireAdmin()` (`src/Helpers/HttpServer.cpp:1828`) and its four ordered
> checks — spelled out with their exact failure bodies in [§0.1](#01-the-four-gates-in-the-order-requireadmin-applies-them).
> "Gated (+ `X-CSRF`)" is a mutating route (`needCsrf = true`); "Gated" or
> "Gated (no `X-CSRF`)" is a read that still requires same-origin, a session **and**
> completed setup, but no token.
>
> There is **no unprovisioned bypass**. An earlier firmware skipped the session and
> token checks until an admin PIN existed; that window is gone — the device ships with
> a default credential precisely so the gate can be unconditional from first boot.
> Endpoints marked "None" are read-only and intentionally reachable without a session:
> `/`, `/index.html`, `/api/status`, `/api/cdr`, `/metrics`, `/api/wifi/scan`,
> `/api/ota/status`, `/api/admin/status`, `/config/<mac>.cfg` and, since issue #159,
> `/setup/email` (the page SHELL only — every field on it is fetched from the gated
> `GET /api/email`, same split as `/` itself vs. its own gated data endpoints). That is
> the complete list — **`/metrics` was missing from it** until this audit; it is ungated by a
> deliberate decision argued at `HttpServer.cpp:1120-1184` (a Prometheus scraper cannot
> drive the login/CSRF handshake). Everything
> else goes through `requireAdmin()` — except `POST /api/admin/login` and
> `POST /api/admin/logout`, which take `requireSameOrigin()` alone (gate 1 only).

| Endpoint | Method | Security Level | Auth Required | Description |
| :--- | :---: | :---: | :---: | :--- |
| [`/`](#get-) | `GET` | Low | None | Serves the web dashboard HTML interface (also at `/index.html`), with the caller's CSRF token rendered into it. |
| [`/api/admin/status`](#get-apiadminstatus) | `GET` | Low | None | Whether the device is provisioned, whether the caller is authenticated, and the session's remaining TTL. |
| [`/api/admin/login`](#post-apiadminlogin) | `POST` | High | Same-origin only | Exchanges `username`+`password` for a `pd_session` cookie and a CSRF token. |
| [`/api/admin/logout`](#post-apiadminlogout) | `POST` | Low | Same-origin only | Destroys the session named by the cookie and expires it client-side. |
| [`/api/admin/set-credential`](#post-apiadminset-credential) | `POST` | High | Gated (+ `X-CSRF`) | Replaces the admin login credential and/or sets the DTMF PIN. **The only route exempt from the `setup_required` gate.** |
| [`/api/status`](#get-apistatus) | `GET` | Low | None | Retrieves registrar uptime, packet statistics, active extensions, ongoing sessions, and the whole PBX feature configuration. |
| [`/api/kill`](#post-apikill) | `POST` | High | Gated (+ `X-CSRF`) | Forcefully disconnects and de-registers an active SIP extension. |
| [`/api/cdr`](#get-apicdr) | `GET` | Low | Session | Returns the in-memory Call Detail Record ring (most recent calls, newest first). **Gated since #215.** Call metadata -- who called whom, when, for how long -- was previously readable by any host that could reach the board. It was ungated by analogy to `/api/status`, which `THREAT_MODEL.md` section 4 E-2 justifies by what the LOGIN FORM needs; a login form does not need call history. See [THREAT_MODEL.md](THREAT_MODEL.md) §4 E-2. |
| `/metrics` | `GET` | Low | None | Prometheus text format (`text/plain; version=0.0.4`). Six families, all `pocketdial_`-prefixed: `uptime_seconds`, `sip_registrations_active`, `sip_calls_active` (gauges), `packets_processed_total`, `packets_dropped_total`, `sdp_rejected_total` (counters). Always `200`; all-zero when the SIP engine is not yet attached. Ungated by design (`HttpServer.cpp:1120-1184`). **Not** on the captive-portal exempt list, so on a Wi-Fi build a scraper sending a foreign `Host` header gets the portal `302` instead. |
| `/api/moh` | `GET` | Medium | Gated (no `X-CSRF`) | Music-on-hold status: `200 {supported, loaded, seconds, listeners, preview}`, or `503 {"error":"SIP engine not attached yet"}`. |
| `/api/moh/preview` | `POST` | High | Gated (+ `X-CSRF`) | **Places a real call to a handset** to audition the hold clip. Param `extension`. `400` missing extension; `409` "extension is not registered" or "no hold clip loaded — upload one first"; `503`; `200 {"status":"ok","message":"ringing <ext>"}`. |
| `/api/moh/preview/stop` | `POST` | High | Gated (+ `X-CSRF`) | Ends the preview call. `503`, or `200 {"status":"ok"}`. |
| `/api/moh/upload` | `POST` | High | Gated (+ `X-CSRF`) | Streaming upload of the hold clip, **8 MB cap** (not 16 KB). Requires 8 kHz mono µ-law WAV. `411` zero `Content-Length`; `413 "clip exceeds 8 MB"`; `400`; `422` wrong format; `500`; `501` on builds without SD (`PD_ETH_HAS_SD`); `200 {"status":"ok","seconds":N,"bytes":N}`. |
| [`/api/pcap`](#get-apipcap) | `GET` | Medium | Gated (no `X-CSRF`) | Downloads the last `POCKETDIAL_PCAP_RING_SIZE` SIP signaling packets as a `.pcap` (Wireshark-readable). |
| [`/api/diagnostics/pcap`](#get-apidiagnosticspcap) | `GET` | Medium | Gated (no `X-CSRF`) | Alias for `/api/pcap` (Issue #33's originally-requested path) — identical response, same ring, same gate. |
| [`/api/trace`](#get-apitrace) | `GET` | Medium | Gated (no `X-CSRF`) | The same capture ring as JSON, for the dashboard's polling live SIP tracer. |
| [`/config/<mac>.cfg`](#get-configmaccfg) | `GET` | Low | None (MAC is the bearer token) | Yealink auto-provisioning config for an already-adopted device. |
| [`/api/dnd`](#post-apidnd) | `POST` | High | Gated (+ `X-CSRF`) | Sets or clears Do-Not-Disturb on an extension. |
| [`/api/forward`](#post-apiforward) | `POST` | High | Gated (+ `X-CSRF`) | Configures call forwarding (`always`/`busy`/`noanswer`) for an extension. |
| [`/api/group`](#post-apigroup) | `POST` | High | Gated (+ `X-CSRF`) | Creates, updates, or deletes a ring/hunt group. |
| [`/api/dialplan`](#post-apidialplan) | `POST` | High | Gated (+ `X-CSRF`) | Creates, updates, or deletes one dial-plan rule (pattern → action). Params: `pattern`, `action` (`group`\|`page`\|`park`\|`trunk`), `target`, and `stripDigits` (trunk only). Naming an `action` always means create/update; **omitting both `action` and `target` deletes the rule**. A `trunk` rule may carry an empty `target`, which means "strip the digits and prepend nothing". |
| [`/api/telephony-config`](#get-apitelephony-config) | `GET` | Medium | Gated | Lists the four carrier/anchor credential slots. The stored secret is never returned — only `secretSet`. |
| [`/api/telephony-config/<slot>`](#put-apitelephony-configslot) | `PUT` | High | Gated (+ `X-CSRF`) | Writes one credential slot (`enabled`, `baseUrl`, `clientId`, `secret`, `routeDn`). An empty `secret` keeps the stored one. |
| [`/api/telephony-config/<slot>/activate`](#post-apitelephony-configslotactivate) | `POST` | High | Gated (+ `X-CSRF`) | Makes that slot the active provider. |
| [`/api/telephony-config/<slot>/test`](#post-apitelephony-configslottest) | `POST` | High | Gated (+ `X-CSRF`) | **Not read-only** — places a real outbound call to the slot's own route DN and immediately drops it. Active slot only. Read the CAUTION in its section before calling it against anything live. |
| [`/api/telephony-config/<slot>`](#delete-apitelephony-configslot) | `DELETE` | High | Gated (+ `X-CSRF`) | Clears one slot, including its stored secret, without a factory reset. |
| [`/api/did-mapping`](#get-apidid-mapping) | `GET` | Medium | Gated | Lists the inbound DID→extension table. |
| [`/api/did-mapping`](#put-apidid-mapping) | `PUT` | High | Gated (+ `X-CSRF`) | Creates or updates one DID→extension mapping. |
| [`/api/did-mapping`](#delete-apidid-mapping) | `DELETE` | High | Gated (+ `X-CSRF`) | Removes one DID mapping. Idempotent. |
| [`/api/wifi/scan`](#get-apiwifiscan) | `GET` | Low | None | Blocking scan of nearby Wi-Fi APs. Stubbed on `eth`/`lan8720`/desktop (§4.2). |
| [`/api/wifi/connect`](#post-apiwificonnect) | `POST` | High | Gated (+ `X-CSRF`) | Saves Wi-Fi credentials to NVS and schedules a reboot into Station Mode. `501` on `eth`/`lan8720`/desktop (§4.2). |
| [`/api/wifi/mode_ap`](#post-apiwifimode_ap) | `POST` | High | Gated (+ `X-CSRF`) | Sets the device to Standalone Access Point Mode and schedules a reboot. No confirmation parameter. `501` on `eth`/`lan8720`/desktop (§4.2). |
| [`/api/configuring`](#post-apiconfiguring) | `POST` | Low | Gated (+ `X-CSRF`) | Pauses the captive-portal auto-switch-to-Standalone decay while a user is mid-setup. It mutates device state, so it takes the standard gate like every other mutating route — a logged-in, fully-set-up session is required, same as WiFi setup itself. |
| [`/api/factory-reset`](#post-apifactory-reset) | `POST` | High | Gated (+ `X-CSRF`) | Requires `confirm=ERASE`. Wipes the login credential, the DTMF PIN, every session, AP security, the carrier-API credential table, the DID→extension table, the CDR ring, and (Wi-Fi builds only) Wi-Fi/mode NVS, then reboots on any ESP build. Answers `200` on every build. |
| [`/api/ap-security`](#get-apiap-security) | `GET` | Medium | Gated | Reports whether the SoftAP requires WPA2 and returns its passphrase. |
| [`/api/ap-security`](#post-apiap-security) | `POST` | High | Gated (+ `X-CSRF`) | Enables/disables WPA2 on the SoftAP and sets or regenerates the passphrase. Takes effect at the next AP bringup. |
| [`/api/registrar`](#get-apiregistrar) | `GET` | Medium | Gated | Reports the SIP registrar admission mode and the adopted-extension roster. |
| [`/api/registrar`](#post-apiregistrar) | `POST` | High | Gated (+ `X-CSRF`) | Sets the admission mode (`open`/`learn`/`secure`). |
| [`/api/registrar/device`](#post-apiregistrardevice) | `POST` | High | Gated (+ `X-CSRF`) | Secures (MAC-locks + digest-enforces) or forgets one adopted device. |
| [`/api/ota/status`](#get-apiotastatus) | `GET` | Low | None | Reports the running/boot/next OTA partition labels and pending-verify flag. |
| [`/api/ota/upload`](#post-apiotaupload) | `POST` | High | Gated (+ `X-CSRF`) | Streams a firmware image into the inactive OTA slot. ESP-only (`501` on desktop). |
| [`/api/ota/reboot`](#post-apiotareboot) | `POST` | High | Gated (+ `X-CSRF`) | Reboots into the freshly staged OTA image. Simulated (`200`, no-op) on desktop. |
| [`/setup/email`](#get-setupemail) | `GET` | Low | None | Standalone SMTP-configuration page (own document, not part of the `/` SPA). Shell only — no data. |
| [`/api/email`](#get-apiemail) | `GET` | Medium | Gated | Current SMTP configuration. Secrets redacted to `hasPassword`/`hasGsaKey` booleans. |
| [`/api/email`](#post-apiemail) | `POST` | High | Gated (+ `X-CSRF`) | Saves SMTP host/port/mode/auth/credentials. Empty `pass`/`gsaKey`/`caPem` keeps the stored value. |
| [`/api/email/test`](#post-apiemailtest) | `POST` | High | Gated (+ `X-CSRF`) | Sends a real test message and reports the structured `SmtpDialogue::ResultCode` inline. Always `200`; `ok` in the body is the real result. |

---

### 4.1 Establishing a session (run this before any `curl` example below)

Every gated example in this catalog assumes two shell variables, `$SESSION` and
`$CSRF`, plus `$DEV` for the device. This block is the exact flow
`tests/http/test_api.sh` TC-AUTH-04 uses, reduced to the two commands you need:

```bash
DEV=192.168.4.1          # or 127.0.0.1:8080 for the host build

# 1. Log in. On a factory-fresh device the credential is admin/admin.
#    -i so we can read the Set-Cookie header and the body in one go.
LOGIN=$(curl -s -i -X POST "http://$DEV/api/admin/login" \
          -d "username=admin&password=admin")
SESSION=$(printf '%s' "$LOGIN" | sed -n 's/.*pd_session=\([0-9a-f]*\).*/\1/p' | head -n1)
CSRF=$(printf   '%s' "$LOGIN" | sed -n 's/.*"csrf":"\([0-9a-f]*\)".*/\1/p'   | head -n1)

# 2. If the login body said "needsSetup":true, EVERY other gated route will
#    answer 403 setup_required until you replace the default credential.
#    The session and CSRF token survive this call — keep using them.
curl -s -X POST "http://$DEV/api/admin/set-credential" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF" \
     -d "username=admin&password=a-real-password"
```

From here on, a gated read is:

```bash
curl -s "http://$DEV/api/registrar" -b "pd_session=$SESSION"
```

and a gated mutation is:

```bash
curl -s -X POST "http://$DEV/api/dnd" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF" \
     -d "extension=1001&on=1"
```

Three things worth knowing before you paste:

* **No `Origin` header is needed.** `curl` sends none, and the same-origin check
  admits requests without one (§0.1). Do **not** add one unless it matches `Host`
  exactly — a mismatched `Origin` is the one way to make `curl` fail gate 1.
* **All request bodies are `application/x-www-form-urlencoded`**, which is what
  `curl -d` sends by default. **There is no JSON request body anywhere in this API**
  — not on `PUT`, not on `DELETE`, not on the admin routes. Every parameter is read
  with `getFormParam()` (`HttpServer.cpp:1933`), which splits on `&`, matches the key
  only at a parameter boundary, and URL-decodes the value (`+` becomes a space).
  Sending JSON produces no error: every parameter simply reads as empty, and you get
  whichever "missing X parameter" `400` the handler checks for first.
* **Sessions slide.** A session expires 30 minutes after its last *successful
  validation*, not 30 minutes after login (`AdminAuth::kSessionTtlMs`, sliding).
  Any gated request — including a `GET /api/admin/status` poll — pushes the deadline
  out by a full TTL. Only 8 sessions exist at once (`kMaxSessions`), and a 9th login
  **evicts** the least-recently-active one rather than being refused, so log in once
  and reuse `$SESSION` rather than logging in per request.

---

### `GET /`
Serves the retro CGA CRT web interface. `GET /index.html` is the same route and the
same response (`HttpServer.cpp:433`).

Ungated — the page itself is public, because it is inert without a session: it renders
a login form and every panel behind it calls a gated endpoint.

The page is assembled from the flash-resident parts in `src/Helpers/index_html.h`, and
the literal marker `__PD_CSRF__` inside it is replaced with **the calling session's**
CSRF token before the response is sent (`HttpServer::sendHtml`, `HttpServer.cpp:864`).
An unauthenticated load substitutes an empty token, which is correct — there is no
session yet, and the login response carries the token the page then uses without
needing a reload. Scraping the token out of this page is therefore a legitimate
alternative to reading it from the login response, but only if you send the cookie.
The marker itself is gone from the rendered page — it is *replaced*, not annotated — so
grep for the assignment it sits in (`var PD_CSRF="…";`, `index_html.h:766`):

```bash
curl -s "http://$DEV/" -b "pd_session=$SESSION" \
  | sed -n 's/.*var PD_CSRF="\([0-9a-f]*\)".*/\1/p'
```

An unauthenticated fetch returns the same line with an empty string, which is how you
tell "no session" from "wrong session".

* **Request Headers**: None (a `pd_session` cookie, if sent, selects whose CSRF token is rendered)
* **Response Content-Type**: `text/html; charset=utf-8`
* **Response Status Codes**:
  * `200 OK`: Always. There is no failure path — the page is a compiled-in constant.

```bash
curl -s -o dashboard.html -w '%{http_code}\n' "http://$DEV/"
```

---

### `GET /api/admin/status`

The dashboard's first call, and the one read that tells you which of the four gates
you are about to hit. **Ungated** — it has to be reachable before login.

* **Request Headers**: `Cookie: pd_session=…` (optional; without it `authenticated` is `false`)
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`: Always. There is no failure path.

```json
{
  "provisioned": false,
  "needsSetup": true,
  "authenticated": false,
  "sessionRemainingSec": 0
}
```

| Field | Type | Description |
| :--- | :---: | :--- |
| `provisioned` | Boolean | `true` once a **real** (operator-set) login credential is stored. `false` on a factory-fresh device and again immediately after a factory reset, when `admin`/`admin` is what verifies. Describes the login credential only — it says nothing about the DTMF PIN, Wi-Fi, or the registrar. |
| `needsSetup` | Boolean | Exactly `!provisioned`. Emitted separately so the frontend reads as intent rather than a double negative. While this is `true`, gate 4 refuses every admin-gated route except `set-credential`. |
| `authenticated` | Boolean | Whether **this request's** `pd_session` cookie names a live session. |
| `sessionRemainingSec` | Integer | Seconds left on this request's session, `0` when unauthenticated. Derived from `AdminAuth::sessionRemainingMs()` divided by 1000 — so a session with 900 ms left reads `0`, not `1`. |

> [!WARNING]
> **Polling this endpoint keeps the session alive.** The handler calls `isAuthed()`,
> which calls `AdminAuth::validateSession()`, which applies the sliding-expiry push
> (`HttpServer.cpp:2357`). A dashboard polling `/api/admin/status` on a timer will
> never let its own session time out. The narrower thing the source comment means is
> that reading `sessionRemainingSec` adds no *second* slide on top of that one, so
> the number displayed is not distorted beyond what the `isAuthed()` call already
> caused. Earlier revisions of this document claimed the read does not slide the
> expiry at all; that was wrong.

```bash
curl -s "http://$DEV/api/admin/status"
curl -s "http://$DEV/api/admin/status" -b "pd_session=$SESSION"   # with session info
```

Covered by `test_api.sh` TC-AUTH-01 (reachable pre-login, `needsSetup:true`) and
TC-AUTH-08 (`provisioned:true` after setup).

---

### `POST /api/admin/login`

Exchanges a username and password for a session cookie and a CSRF token. This is the
**only** way to obtain either.

Gated by `requireSameOrigin()` alone — not `requireAdmin()`. There is no session yet
to authenticate, and no session to bind a CSRF token to, so gates 2-4 cannot apply.

* **Request Content-Type**: `application/x-www-form-urlencoded`
* **Request Parameters**:
  * `username` (Required): On a factory-fresh device, `admin`.
  * `password` (Required): On a factory-fresh device, `admin`.
* **Response Content-Type**: `application/json`
* **Response Headers (200 only)**: `Set-Cookie: pd_session=<32 hex>; HttpOnly; Path=/; SameSite=Strict`
* **Response Status Codes**:
  * `200 OK`: Credential verified, session created.
  * `401 Unauthorized`: `{"error":"invalid username or password"}`
  * `403 Forbidden`: `{"error":"cross-origin request rejected"}`
  * `429 Too Many Requests`: `{"error":"too many failed attempts; try again later"}` — returned both when the client was *already* locked out (checked before any hashing work) and when this attempt is the one that trips the lockout.
  * `500 Internal Server Error`: `{"error":"failed to create session"}` — `AdminAuth::createSession()` returned an empty token, which happens only when the random-token generator fails (`AdminAuth.cpp:840`). **Not** a "table full" condition; see below.

> [!NOTE]
> **A 9th concurrent login evicts the oldest session rather than failing.** The session
> table is a fixed 8 slots (`kMaxSessions`); `createSession()` takes an unused slot,
> else an expired one, else **the soonest-to-expire live session**, overwriting it
> (`AdminAuth.cpp:848`). The evicted client's next gated request comes back `401`
> with no warning, and because expiry slides, "soonest to expire" is effectively
> "least recently active". This matters for scripted clients that log in per-request
> instead of reusing a session.

```json
{ "status": "ok", "authenticated": true, "needsSetup": true, "csrf": "3f2a…e91c" }
```

`csrf` is the per-session CSRF token, returned here as well as rendered into the
dashboard page so a `fetch()`-based login can start making mutating calls immediately
instead of reloading. `needsSetup` tells the caller whether this login just
authenticated with the default credential — if `true`, route straight to setup,
because everything else is about to return `setup_required`.

**Cookie flags, and what is deliberately absent**: `HttpOnly` (not readable from JS,
so an XSS cannot exfiltrate the token) and `SameSite=Strict` (the browser will not
attach it to cross-site requests). There is **no `Secure` flag** — the dashboard is
plain HTTP on a LAN appliance, and `Secure` would make the cookie unusable. The
cookie value is the session token; the CSRF token is never a cookie, by design.

**Brute-force accounting** is **global, not per-client.** `AdminAuth` implements
per-client buckets and `handleClient()` even derives `peerIp` from `getpeername()` for
them (`HttpServer.cpp:247-263`) — but it stores that only on the OTA request (`:330`).
`parseRequest()` never sets `req.clientIp`, so `sendApiAdminLogin` passes an empty string
(`:2720`, `:2729`, `:2732`) and every failure shares one unkeyed bucket with the DTMF PIN
path. **One guesser can therefore lock the real admin out** — see
[THREAT_MODEL.md](THREAT_MODEL.md) D-3. The thresholds below are real:
`kMaxFailedAttempts` = 5 consecutive failures engage a
`kLockoutMs` = 60 s cooldown, and consecutive lockouts back off exponentially to a
cap of 60 s << 4 ≈ 16 minutes. A separate aggregate backstop
(`kMaxFailedAttemptsGlobal` = 20) bounds the total guess rate across all source
addresses, since addresses are spoofable. *(Keying per-client was meant to stop one
guesser locking the real admin out; as above, the key never arrives, so the aggregate
backstop is carrying this alone.)* The default credential is **not** exempt from any of
this.

```bash
curl -s -i -X POST "http://$DEV/api/admin/login" -d "username=admin&password=admin"
```

Covered by `test_api.sh` TC-AUTH-03 (cross-origin → `403`), TC-AUTH-04 (default
credential → `200` with both cookie and token) and TC-AUTH-11 (5 wrong passwords →
`429`).

---

### `POST /api/admin/logout`

Destroys the session named by the request's `pd_session` cookie and expires the
cookie client-side.

Gated by `requireSameOrigin()` alone, like login. No session and **no CSRF token** are
required: a forced logout is a nuisance rather than a compromise, `SameSite=Strict`
already blocks the cross-site version of it, and requiring a token would strand a user
holding a stale page with no way to get a clean one.

* **Request Headers**: `Cookie: pd_session=…` (optional — a logout with no cookie, or an unknown one, still succeeds)
* **Response Content-Type**: `application/json`
* **Response Headers**: `Set-Cookie: pd_session=; HttpOnly; Path=/; SameSite=Strict; Max-Age=0`
* **Response Status Codes**:
  * `200 OK`: `{"status":"ok"}` — unconditionally, whether or not a session was destroyed.
  * `403 Forbidden`: `{"error":"cross-origin request rejected"}`

```bash
curl -s -i -X POST "http://$DEV/api/admin/logout" -b "pd_session=$SESSION"
```

Covered by `test_api.sh` TC-AUTH-10 (a gated route answers `401` with the
just-logged-out session).

---

### `POST /api/admin/set-credential`

Replaces the admin login credential, sets the DTMF admin PIN, or both. **This is the
route that clears gate 4** — until it has succeeded once with a `username`+`password`,
every other admin-gated route answers `403 {"error":"setup_required"}`.

Fully gated (`requireAdmin(…, needCsrf = true)`), so it needs a session *and* a CSRF
token even during forced initial setup. You get both by logging in with the default
credential first; `requireAdmin()` exempts only this one path from gate 4, not from
gates 1-3.

* **Request Content-Type**: `application/x-www-form-urlencoded`
* **Request Parameters** (all optional individually, but the request must change *something*):
  * `username`: 1-32 characters, no whitespace and no control characters. Must be sent **together with** `password`.
  * `password`: 8-128 characters. Must be sent **together with** `username`.
  * `dtmfPin`: 4-16 **digits**. Independent of the login credential — sending it alone changes only the DTMF PIN. Empty means "leave the DTMF PIN as it is".
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`: `{"status":"ok","provisioned":true,"needsSetup":false}`
  * `400 Bad Request`: `{"error":"username and password must both be provided together"}` — exactly one of the two was sent.
  * `400 Bad Request`: `{"error":"invalid username or password"}` — a field is outside its length bounds, or the username contains whitespace/control characters.
  * `400 Bad Request`: `{"error":"DTMF PIN must be 4-16 digits"}`
  * `400 Bad Request`: `{"error":"nothing to change"}` — neither a credential pair nor a PIN was supplied.
  * `401`/`403`: gates 1-3 as in §0.1.

The session you call this through **stays valid** — changing the credential does not
invalidate it, which is what lets the setup flow (and `test_api.sh` TC-AUTH-07)
continue with the same `$SESSION`/`$CSRF`.

There is deliberately **no default DTMF PIN**, and no way to read one back. The
phone-keypad `*PIN#code` admin menu (NTP resync, topology switch, factory reset) stays
entirely unreachable until a PIN is set here. It is a separate secret from the web
login because a keypad cannot type a username.

> [!NOTE]
> **There is no `/api/admin/set-pin` route**, and there never was one in this
> firmware. Older notes and third-party write-ups describing a PIN-only admin model
> predate the username+password credential; `dtmfPin=` on *this* endpoint is the only
> PIN-setting surface in the HTTP API.

```bash
# Complete forced initial setup (login credential only)
curl -s -X POST "http://$DEV/api/admin/set-credential" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF" \
     -d "username=admin&password=a-real-password"

# Later: set just the DTMF keypad PIN, leaving the login credential alone
curl -s -X POST "http://$DEV/api/admin/set-credential" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF" \
     -d "dtmfPin=482913"
```

Covered by `test_api.sh` TC-AUTH-06 (cross-origin → `403`) and TC-AUTH-07 (completes
setup → `200`).

---

### `GET /api/status`
Returns a detailed JSON object representing the active state of the SIP registration
database, the traffic counters, and the **entire PBX feature configuration**.

This is the richest read in the API and the only one that is both ungated and
complete: DND, call-forward, ring groups, the dial plan and the park orbits are all
readable here without a session. There is no separate `GET` for any of them — the
`POST` routes that write them have no read counterpart, so `/api/status` is how you
read back what you just wrote. It is also exempt from the captive-portal redirect
(§3), so it answers even while every other `GET` is being bounced to the portal.

* **Request Headers**: None
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`: Always. Every field is present on every response; the arrays are
    emitted empty rather than omitted. If the SIP engine has not been attached to the
    dashboard yet (a boot-time transient of a second or two — see
    [`GET /api/registrar`](#get-apiregistrar)'s `attached`), the counters read `0` and
    **every array is empty**, which is indistinguishable from a genuinely idle box.
* **Response Payload JSON Example** (complete — this is the full field set, not an abridgement):
```json
{
  "ip": "192.168.4.1",
  "port": 5060,
  "httpPort": 80,
  "uptime": 14205,
  "packetsProcessed": 10543,
  "packetsDropped": 12,
  "sd": { "present": true, "mounted": true, "capacityMb": 29820 },
  "clients": [
    { "number": "1001", "address": "192.168.4.12:5060" },
    { "number": "1002", "address": "192.168.4.15:5068" }
  ],
  "sessions": [
    { "caller": "1001", "callee": "1002", "state": "Connected", "duration": "03:45" }
  ],
  "dnd": ["1003"],
  "forwards": [
    { "extension": "1001", "always": "", "busy": "1002", "noanswer": "" }
  ],
  "groups": [
    { "extension": "610", "mode": "ringall", "members": "1001,1002,1003" }
  ],
  "dialplan": [
    { "pattern": "2XX", "action": "group", "target": "610", "stripDigits": 0 },
    { "pattern": "9XXXXXXXXXX", "action": "trunk", "target": "1", "stripDigits": 1 }
  ],
  "parkedCalls": [
    { "orbit": "701", "parkedExt": "1002", "parker": "1001", "secondsParked": 18 }
  ]
}
```

```bash
curl -s "http://$DEV/api/status"
```

Covered by `test_api.sh` TC-HP-02 (reachable ungated, schema present).

#### Field Schema Definitions

| Field Name | Type | Description |
| :--- | :---: | :--- |
| `ip` | String | The primary active IP address of the SIP server interface. |
| `port` | Integer | The UDP signaling port. **Always the literal `5060`** — it is hardcoded in the handler (`HttpServer.cpp:951`), not read from configuration, because this codebase has no way to run the SIP listener on another port. Do not treat it as a discovered value. |
| `httpPort` | Integer | The active TCP HTTP port (typically 80). |
| `uptime` | Integer | Time in seconds since the HTTP server initialized. |
| `packetsProcessed` | Integer | Total UDP signaling packets processed by the state machine. |
| `packetsDropped` | Integer | Total UDP signaling packets dropped by rate-limiting or firewall rules. |
| `sd` | Object | microSD state. **Always present**, on every build and transport, so a client never has to distinguish "key missing" from "no card". |
| `sd.present` | Boolean | Whether this *build* has a card slot wired — i.e. was compiled with `PD_ETH_HAS_SD`. True only for `eth` on `PD_ETH_BOARD=elite`; false on `wifi`, `lan8720`, `display`, the Waveshare `eth` board, and the host build. This is a build capability, not a runtime observation. |
| `sd.mounted` | Boolean | Whether a card is actually mounted at `/sdcard` right now. Distinguishing this from `present` matters: `present:true, mounted:false` means the slot exists but the card is missing, unreadable, or **exFAT** (ESP-IDF's FatFs mounts FAT16/FAT32 only, and cards over 32 GB ship exFAT from the factory). |
| `sd.capacityMb` | Integer | Card capacity in MB when mounted; `0` otherwise. |
| `clients` | Array | Array of objects listing active VoIP extensions. |
| `clients[].number` | String | SIP extension number (e.g., `"1001"`). |
| `clients[].address` | String | Client's IP and port (e.g., `"192.168.4.12:5060"`). |
| `sessions` | Array | Array of active SIP communication channels. |
| `sessions[].caller` | String | Extension that initiated the call. |
| `sessions[].callee` | String | Target extension receiving the call. |
| `sessions[].state` | String | Active session state. Exactly one of `Invited`, `Connected`, `Busy`, `Unavailable`, `Cancel`, `Bye`, or `Unknown` for an unmapped enumerator (`sessionStateToString`, `src/SIP/RequestsHandler.cpp:4262`). |
| `sessions[].duration` | String | **A preformatted display string, not a number.** `MM:SS` under an hour, `HH:MM:SS` at or above it, zero-padded either way (`"03:45"`, `"01:02:03"`). The underlying integer seconds is not exposed anywhere — a client that wants arithmetic has to parse this back. |
| `dnd` | Array | Extension numbers (**strings**, not objects) currently in Do-Not-Disturb. |
| `forwards` | Array | Per-extension call-forward targets: `{extension, always, busy, noanswer}`. An unset trigger is an empty string, never `null` or a missing key. |
| `groups` | Array | Ring/hunt groups: `{extension, mode, members}`, where `mode` is `ringall` or `hunt`. |
| `groups[].members` | String | **A comma-joined string, not an array** — e.g. `"1001,1002,1003"` (`pbx::joinMembers`). Split it on `,` client-side. It round-trips: this is exactly the format [`POST /api/group`](#post-apigroup) accepts back. |
| `dialplan` | Array | The dial-plan rule table (Issue #69), **in evaluation order** — first match wins, so this array's order is load-bearing. Unlike the sets above, this one's order is meaningful. |
| `dialplan[].pattern` | String | The dialed-number pattern (see [`POST /api/dialplan`](#post-apidialplan) for the grammar). |
| `dialplan[].action` | String | `group`, `page`, `park`, or `trunk`. |
| `dialplan[].target` | String | The group / paging-zone / park-orbit extension the rule routes to, or — for `trunk` — the string prepended to the dialed number after stripping (possibly empty, meaning "prepend nothing"). |
| `dialplan[].stripDigits` | Number | `trunk` only (Issue #165): leading digits removed from the dialed number before prepending `target`. `0` for every other action. |
| `parkedCalls` | Array | Calls currently sitting on a park orbit: `{orbit, parkedExt, parker, secondsParked}`. Lets a client tell a parked extension apart from an idle or connected one. |

> **Ordering.** `dialplan[]` is the one array whose order carries meaning: it is
> emitted in table order, and the table is evaluated **first match wins**
> (`HttpServer.cpp:1028`). Preserve it. `clients`, `sessions`, `dnd`, `forwards`,
> `groups` and `parkedCalls` are sets — their order is whatever the underlying
> container produced and must not be relied on. There is no way to reorder the dial
> plan through the API; see [`POST /api/dialplan`](#post-apidialplan).
>
> Full shape: `HttpServer::sendApiStatus()`, `src/Helpers/HttpServer.cpp:913`. All
> string values are JSON-escaped, including C0 control bytes as `\u00XX`
> (`jsonEscape`, `HttpServer.cpp:883`).

---

### `POST /api/kill`
Disconnects a specified VoIP station, removing its registration and terminating any active calls involving its extension.

* **Requires Same-Origin Check**: Yes
* **Requires `pd_session` cookie**: Always (see §0)
* **Request Content-Type**: `application/x-www-form-urlencoded`
* **Request Parameters**:
  * `extension` (Required): The registration extension number to disconnect.
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`: Request accepted. See the note below on what this does *not* tell you.
  * `400 Bad Request`: `{"error":"missing extension parameter"}` — the body contains no `extension=`, or the value after it is empty.
  * `401`/`403`: gates 1-4 as in §0.1.

> [!NOTE]
> **Corrected — this endpoint now parses like every other one.** Earlier revisions of
> this document warned that `sendApiKill()` was the one handler that did *not* use
> `getFormParam()`: that it did a bare `body.find("extension=")`, swallowed extra
> parameters into the value, never URL-decoded, and accepted `myextension=1001` as
> `extension=1001`. **All four of those behaviours were removed in issue #191.**
> `sendApiKill()` now calls `getFormParam(body, "extension")`
> (`HttpServer.cpp:1294`), which enforces an `&` token boundary, stops at the next
> `&`, and URL-decodes. So extra parameters are fine, `%2A` decodes to `*`, and a body
> carrying only `myextension=1001` answers `400` rather than killing extension 1001.
> Do not write a client against the old contract.

> [!NOTE]
> **`200` means "the request was well-formed", not "an extension was disconnected".**
> `RequestsHandler::forceDisconnect()` walks the client pool, releases the first
> matching registration and returns nothing; an extension that is not registered is a
> no-op. The response echoes back whatever string you sent either way. Read
> [`GET /api/status`](#get-apistatus)'s `clients[]` to confirm the registration is
> actually gone.

#### Request Example (Form URL-Encoded)
```http
POST /api/kill HTTP/1.1
Host: 192.168.4.1
Origin: http://192.168.4.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 14

extension=1001
```

#### Response Example (200 OK)
```json
{
  "status": "ok",
  "disconnected": "1001"
}
```

#### Response Example (400 Bad Request)
```json
{
  "error": "missing extension parameter"
}
```

```bash
curl -s -X POST "http://$DEV/api/kill" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF" \
     -d "extension=1001"
```

Covered by `test_api.sh` TC-SEC-01/02/03 (the same-origin matrix), TC-AUTH-02/05/09
(the session/setup/CSRF gates) and TC-ED-02 (empty body → `400`).

---

### 4.2 Build-dependent routes — read before using `/api/wifi/*`

Three routes are compiled against `POCKETDIAL_HAS_WIFI`, which
`main/CMakeLists.txt:134` defines for **every transport except `eth` (W5500) and
`lan8720`** — the two pure-Ethernet builds, which have no Wi-Fi radio at all. On those
builds, and on the host/desktop build, the `#else` stub answers instead of the real
implementation. This is Issue #167, and the stub messages all say *"on desktop"*
regardless of whether you are on a desktop or on Ethernet hardware.

`/api/factory-reset` is listed below too, but it is **not** one of those three: it is
fully functional on every build. Only its Wi-Fi NVS key erase is transport-gated, and a
wired board has no such keys to erase. It answers `200` everywhere and reboots on every
ESP transport. (Before #189 it did belong in that set, and was the worst member of it —
it performed the whole wipe and *then* answered `501`.)

A second, **different** guard — `ESP_PLATFORM` — covers the OTA routes. It is defined
on *every* ESP transport including `eth`/`lan8720`, so OTA works on Ethernet boards
even though Wi-Fi does not. Do not conflate the two.

| Route | Guard | On `eth` / `lan8720` / desktop |
| :--- | :--- | :--- |
| [`GET /api/wifi/scan`](#get-apiwifiscan) | `POCKETDIAL_HAS_WIFI` | `200` with `{"networks":[], "note":"WiFi scan not available on desktop"}` |
| [`POST /api/wifi/connect`](#post-apiwificonnect) | `POCKETDIAL_HAS_WIFI` | `501` `{"error":"WiFi connect not available on desktop"}` (after the `ssid` check) |
| [`POST /api/wifi/mode_ap`](#post-apiwifimode_ap) | `POCKETDIAL_HAS_WIFI` | `501` `{"error":"WiFi mode select not available on desktop"}` |
| [`POST /api/factory-reset`](#post-apifactory-reset) | `POCKETDIAL_HAS_WIFI` *(Wi-Fi NVS keys only)* | Fully real everywhere: `200` on every build, and every ESP build reboots. Only the four Wi-Fi NVS keys and the captive-portal wording are transport-specific. |
| [`POST /api/ota/upload`](#post-apiotaupload) | `ESP_PLATFORM` | Real on `eth`/`lan8720`; `501` only on desktop |
| [`POST /api/ota/reboot`](#post-apiotareboot) | `ESP_PLATFORM` | Real on `eth`/`lan8720`; simulated `200` only on desktop |

Nothing in the API reports which guard a given board was built with. The closest
signal is [`GET /api/ota/status`](#get-apiotastatus)'s `otaSupported`, and that tracks
`ESP_PLATFORM` — it is `true` on an Ethernet board whose `/api/wifi/*` routes are all
stubs. There is no `POCKETDIAL_HAS_WIFI` equivalent to probe; the only reliable test is
to call `/api/wifi/scan` and look for the `note` field.

---

### `GET /api/wifi/scan`
Runs a Wi-Fi network scan and returns the results. **Ungated** — it has to work during
captive-portal onboarding, before any session exists, and it is one of the two paths
exempt from the captive-portal redirect (§3).

* **Build**: `POCKETDIAL_HAS_WIFI` only — see §4.2.
* **Request Headers**: None
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`
  * `500 Internal Server Error`: `{"error":"WiFi scan start failed","code":<esp_err_t>}` — `esp_wifi_scan_start()` refused. `code` is the raw numeric `esp_err_t`.

> [!WARNING]
> **This is a blocking scan, and it leaves the radio in `AP+STA`.** The handler calls
> `esp_wifi_scan_start(&cfg, true)` — the `true` is `block`, so the HTTP request is
> held for the full scan (seconds, `show_hidden` enabled) on one of the server's
> connection threads. And if the radio was in `WIFI_MODE_AP` it is switched to
> `WIFI_MODE_APSTA` to scan and **is never switched back**
> (`HttpServer.cpp:1966`). Being ungated, this is reachable by anything on the AP.

#### Response Example (200 OK - ESP32 Platform)
```json
{
  "networks": [
    {
      "ssid": "Office-Main-5G",
      "rssi": -65,
      "encryption": "WPA2"
    },
    {
      "ssid": "Guest-Open",
      "rssi": -82,
      "encryption": "OPEN"
    }
  ]
}
```
| Field | Type | Description |
| :--- | :---: | :--- |
| `ssid` | String | The SSID as reported by the driver. Hidden networks are included (`show_hidden` is set), and their SSID is an empty string. |
| `rssi` | Integer | Signal strength in dBm (negative). |
| `encryption` | String | Exactly one of `OPEN`, `WEP`, `WPA`, `WPA2`, `WPA/WPA2`, `WPA2 Enterprise`, `WPA3`, `WPA2/WPA3`. Any auth mode outside that switch falls through to `OPEN` (`HttpServer.cpp:1997`) — treat `OPEN` as "open *or* unrecognised", not as a guarantee. |

> [!NOTE]
> On a build without `POCKETDIAL_HAS_WIFI` — the `eth`/`lan8720` Ethernet firmwares as
> well as the desktop build — this endpoint returns `200` with
> `{"networks":[], "note":"WiFi scan not available on desktop"}`. The presence of the
> `note` key is the only way to tell a stubbed build from a board that genuinely sees
> no networks. See §4.2.

```bash
curl -s "http://$DEV/api/wifi/scan"
```

---

### `POST /api/wifi/connect`
Configures the device to operate in **Wi-Fi Station Mode**, saving the SSID and password to flash, and triggers a system reboot.

* **Requires Same-Origin Check**: Yes
* **Requires `pd_session` cookie**: Always (see §0)
* **Request Content-Type**: `application/x-www-form-urlencoded`
* **Request Parameters**:
  * `ssid` (Required): SSID of the target network.
  * `password` (Optional): Password of the target network.
* **Build**: `POCKETDIAL_HAS_WIFI` only — see §4.2.
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`: Credentials committed to NVS (namespace `storage`, keys `wifi_mode`/`wifi_ssid`/`wifi_pass`), reboot scheduled ~1 s out so the response flushes first.
  * `400 Bad Request`: `{"error":"missing ssid parameter"}`. Checked **before** the build guard, so it is the response on every build.
  * `401`/`403`: gates 1-4 as in §0.1.
  * `413 Payload Too Large`: body over 16 KB (`test_api.sh` TC-ED-01 uses this route for that check).
  * `501 Not Implemented`: `{"error":"WiFi connect not available on desktop"}` on a build without `POCKETDIAL_HAS_WIFI` — including the `eth`/`lan8720` Ethernet firmwares.

> [!NOTE]
> An empty `password` is accepted and stored as an empty string (an open network);
> only `ssid` is required. The NVS write is best-effort: if `nvs_open()` fails, nothing
> is stored, the response is still `200`, and the device still reboots — into its
> previous mode. There is no way to tell from the response that this happened.

#### Request Example
```http
POST /api/wifi/connect HTTP/1.1
Host: 192.168.4.1
Origin: http://192.168.4.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 35

ssid=My-Home-WiFi&password=secure123
```

#### Response Example (200 OK)
```json
{
  "status": "ok",
  "message": "WiFi credentials saved. Rebooting to Station Mode..."
}
```

```bash
curl -s -X POST "http://$DEV/api/wifi/connect" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF" \
     --data-urlencode "ssid=My Home WiFi" \
     --data-urlencode "password=secure123"
```

`--data-urlencode` rather than `-d`, because an SSID or passphrase containing `&`, `=`
or `+` would otherwise be mis-split or mis-decoded by `getFormParam()`.

Covered by `test_api.sh` TC-ED-01 (16 KB body → `413`) and TC-ED-03 (missing `ssid` →
`400`).

---

### `POST /api/wifi/mode_ap`
Sets the operational mode of the device back to **Standalone Access Point Mode**, saving the setting to NVS flash, and triggers a system reboot.

* **Requires Same-Origin Check**: Yes
* **Requires `pd_session` cookie**: Always (see §0)
* **Build**: `POCKETDIAL_HAS_WIFI` only — see §4.2.
* **Request Headers**: None. **No request parameters at all** — the body is ignored.
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`: `wifi_mode=2` committed to NVS, reboot scheduled ~1 s out.
  * `401`/`403`: gates 1-4 as in §0.1.
  * `501 Not Implemented`: `{"error":"WiFi mode select not available on desktop"}` on a build without `POCKETDIAL_HAS_WIFI` — including the `eth`/`lan8720` Ethernet firmwares.

Unlike `/api/wifi/connect`, this endpoint has **no confirmation parameter** and no
precondition check: any authenticated, fully-set-up session can reboot the device into
AP mode with an empty POST. The stored station credentials are not erased — only
`wifi_mode` changes — so `/api/wifi/connect` is not needed again to go back.

#### Response Example (200 OK)
```json
{
  "status": "ok",
  "message": "Operational mode set to Standalone AP. Rebooting..."
}
```

```bash
curl -s -X POST "http://$DEV/api/wifi/mode_ap" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF"
```

---

### `GET /api/registrar`

Reports how a `REGISTER` is admitted, and which phones have been adopted.

```json
{
  "attached": true,
  "mode": "learn",
  "devices": [
    { "mac": "805ec079c37f", "extension": "1001", "state": "secured", "online": true },
    { "mac": "805ec079c380", "extension": "1002", "state": "learned",  "online": false }
  ]
}
```

* `attached` — `false` when the SIP engine has not been bound to the dashboard yet. The
  HTTP server starts before the registrar exists and the main loop attaches the handler
  once it does (`main/esp_main_eth.cpp:424`). **It is not always a "boot-time transient
  of a second or two".** On the `eth` build the SIP task is not started at all until an
  admin credential exists (`main/esp_main_eth.cpp:587-631` waits on
  `AdminAuth::credentialIsSet()` before `xTaskCreatePinnedToCore(&sip_server_task, …)`),
  so on a freshly flashed or freshly factory-reset board `attached` stays `false`
  indefinitely — until someone completes first-run setup. Treat a persistent
  `attached:false` as "setup not finished", not as a hung registrar. `mode` reads
  `"unknown"` and `devices` is empty meanwhile. Every
  other endpoint that reads registrar state behaves the same way — empty datasets, not
  failures.
* `mode` — `open`, `learn` or `secure` (see `POST` below).
* `state` — `learned` (adopted on first contact, not yet enforced) or `secured`
  (MAC-locked and digest-enforced for its extension).
* `online` — volatile registration state; never persisted.

> **Why this endpoint exists.** SIP digest authentication has been implemented and tested
> for some time, but `setRegistrarMode()` was called from **unit tests only** — nothing in
> production ever wrote the persisted `reg_mode`, so every device came up in the
> compiled-in `open` default and stayed there regardless of what the docs claimed. This
> and the flash-time `cfgseed` field are what make it operable.

* **Auth**: Gated read — same-origin, session and completed setup, **no** `X-CSRF`.
* **Response Status Codes**:
  * `200 OK`: Always, including the `"attached":false` transient above.
  * `401`/`403`: gates 1, 2 and 4 as in §0.1.

```bash
curl -s "http://$DEV/api/registrar" -b "pd_session=$SESSION"
```

### `POST /api/registrar`

| Param | Values | Effect |
| :--- | :--- | :--- |
| `mode` | `open` \| `learn` \| `secure` | Required. The admission policy. |
| `confirm` | `LOCKOUT` | Only consulted when switching to `secure`; see below. |

* **`open`** — every `REGISTER` is accepted with no credential. The shipped default. Any
  endpoint on the link can register as any extension and tear down calls with a spoofed
  `BYE`. Fine for a lab; not for a shared link.
* **`learn`** — trust-on-first-use. An unknown MAC registering an unclaimed extension is
  adopted and locked to it, while already-secured devices stay digest-enforced. A
  deliberate, **temporary** weakening to adopt an existing fleet — bound the window, review
  the roster, then move on. Run it on a trusted/WPA2 link.
* **`secure`** — every `REGISTER` is digest-challenged; an extension is registrable only by
  a party that knows its secret.

Switching to `secure` while **no** extension is yet `secured` is refused with `409`:

```json
{ "error": "no extensions are secured yet; switching to secure now would reject every phone. Adopt them in learn mode first, or resend with confirm=LOCKOUT to override." }
```

That transition would otherwise reject every handset at once, leaving no working phone to
notice with. Resend with `confirm=LOCKOUT` to override — the same shape as
`/api/factory-reset`'s `confirm=ERASE`.

Responds with the same body as the `GET`.

* **Request Content-Type**: `application/x-www-form-urlencoded`
* **Response Status Codes**:
  * `200 OK`: Mode set. Body is the `GET`'s `{attached, mode, devices}` shape.
  * `400 Bad Request`: `{"error":"mode must be one of: open, learn, secure"}` — `mode` missing or not one of the three. The check is exact and case-sensitive.
  * `401`/`403`: gates 1-4 as in §0.1.
  * `409 Conflict`: the no-secured-devices guard above.
  * `503 Service Unavailable`: `{"error":"SIP engine not attached yet"}` — unlike the `GET`, which reports `"attached":false` and `200`, the `POST` refuses outright rather than accepting a mode it cannot apply.

```bash
# Move to trust-on-first-use so phones get adopted
curl -s -X POST "http://$DEV/api/registrar" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF" \
     -d "mode=learn"

# Later, lock it down (add confirm=LOCKOUT only if nothing is secured yet)
curl -s -X POST "http://$DEV/api/registrar" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF" \
     -d "mode=secure"
```

### `POST /api/registrar/device`

| Param | Values | Effect |
| :--- | :--- | :--- |
| `action` | `secure` \| `forget` | Required. |
| `target` | 12-hex MAC, or an extension | Required. An extension resolves to the device currently bound to it. |

`secure` promotes a `learned` device to `secured`. `forget` drops the adoption record
entirely — in `learn` mode the phone is re-adopted on its next registration, which is the
way to re-home an extension to different hardware.

* **Request Content-Type**: `application/x-www-form-urlencoded`
* **Response Status Codes**:
  * `200 OK`: Body is the `GET`'s `{attached, mode, devices}` shape.
  * `400 Bad Request`: `{"error":"missing target (a 12-hex MAC or an extension)"}` — `target` is checked first, before `action`.
  * `400 Bad Request`: `{"error":"action must be one of: secure, forget"}`
  * `401`/`403`: gates 1-4 as in §0.1.
  * `404 Not Found`: `{"error":"no adopted device matches that MAC or extension"}` — JSON, unlike the plain-text fallback `404` in §1.
  * `503 Service Unavailable`: `{"error":"SIP engine not attached yet"}`

```bash
curl -s -X POST "http://$DEV/api/registrar/device" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF" \
     -d "action=secure&target=805ec079c37f"

curl -s -X POST "http://$DEV/api/registrar/device" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF" \
     -d "action=forget&target=1001"
```

> **The MAC lock is not a cryptographic boundary.** It is learned from the ARP table, and
> ARP/MAC are spoofable on a hostile L2. It defeats accidental collisions and casual
> impersonation and composes with digest auth as defence in depth — it is not a substitute
> for it. See [THREAT_MODEL.md](THREAT_MODEL.md) §9.2 E-3.

### `GET /api/ap-security`

Reports the SoftAP's security setting and its passphrase.

```json
{ "secure": false, "psk": "DD9T4GZKQ4AHY5KGRZP8" }
```

* `secure` — `true` when the standalone SoftAP comes up `WIFI_AUTH_WPA2_PSK`. **Defaults
  to `false`**: enabling WPA2 forces every already-associated phone to be re-paired, so it
  is an explicit operator action rather than something a firmware update does to a live
  fleet.
* `psk` — the device's own passphrase, generated from the hardware CSPRNG on first access
  and stored in NVS. 20 characters from an alphabet with no ambiguous glyphs (no `0`/`O`,
  `1`/`I`/`L`, `U`), because it gets read off a small LCD or a serial log and retyped into
  a desk phone.

Returning the passphrase in clear to an authenticated admin is deliberate — on the
headless `eth`/`wifi` builds this response is the only way to learn it, and it is exactly
what the operator needs in order to re-associate the phones.

* **Auth**: Gated read — same-origin, session and completed setup, **no** `X-CSRF`.
* **Response Status Codes**:
  * `200 OK`: Always. `DeviceConfig` has no failure path here; the passphrase is generated on first access if none exists.
  * `401`/`403`: gates 1, 2 and 4 as in §0.1.

```bash
curl -s "http://$DEV/api/ap-security" -b "pd_session=$SESSION"
```

Note that this route is **not** `POCKETDIAL_HAS_WIFI`-guarded: it reads and writes
`DeviceConfig` state, which exists on every build. On an `eth`/`lan8720` board it will
happily report and change an AP passphrase for a SoftAP that board never brings up.

### `POST /api/ap-security`

Form-encoded. All parameters optional; omitted ones are left unchanged.

| Param | Values | Effect |
| :--- | :--- | :--- |
| `secure` | `1`/`true`/`0`/`false` | Enable or disable WPA2 on the standalone SoftAP. |
| `psk` | 8-63 printable ASCII | Set the passphrase explicitly. Rejected with `400` if out of range, leaving the stored value untouched. |
| `regenerate` | `1`/`true` | Replace the passphrase with a freshly generated one. |

Responds with the same body as the `GET`. **The radio is not restarted**: doing so would
drop the client that just made the request — losing the response, and the passphrase it
still has to display — and would tear down live calls. The change lands at the next AP
bringup.

* **Response Status Codes**:
  * `200 OK`: Body is the `GET`'s `{secure, psk}` shape, reflecting the new state.
  * `400 Bad Request`: `{"error":"passphrase must be 8-63 printable ASCII characters"}` — validated **before** anything is changed, so a rejected passphrase cannot leave the AP half-configured.
  * `401`/`403`: gates 1-4 as in §0.1.

Order of operations within one request: `psk` is validated and applied first, then
`regenerate` (which overwrites whatever `psk` just set), then `secure`. Sending both
`psk` and `regenerate=1` therefore discards your passphrase — send one or the other.

```
POST /api/ap-security HTTP/1.1
Host: 192.168.4.1
Content-Type: application/x-www-form-urlencoded
X-CSRF: 3f2a...e91c

secure=1&psk=DD9T4GZKQ4AHY5KGRZP8
```

```bash
# Turn WPA2 on with a passphrase of your own
curl -s -X POST "http://$DEV/api/ap-security" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF" \
     -d "secure=1&psk=DD9T4GZKQ4AHY5KGRZP8"

# Or roll a fresh device-generated one and read it back in the response
curl -s -X POST "http://$DEV/api/ap-security" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF" \
     -d "regenerate=1"
```

### `GET /api/cdr`
Returns the in-memory Call Detail Record ring (most recent calls first). Read-only, ungated — same reachability posture as `/api/status`.

* **Request Headers**: None
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`
* **Response Payload JSON Example**:
```json
[
  {
    "caller": "1001",
    "callee": "1002",
    "startMs": 1723180800000,
    "ageSec": 42,
    "duration": 37,
    "result": "answered"
  }
]
```

The response is a **bare JSON array**, not an object with a wrapper key — unlike
`/api/telephony-config` (`{"slots":[…]}`) and `/api/did-mapping` (`{"mappings":[…]}`).
An empty ring is `[]`. The ring holds `POCKETDIAL_CDR_RECORDS` = **32** entries
(`src/SIP/CallDetailRecord.hpp:19`), newest first, and is cleared by
[`POST /api/factory-reset`](#post-apifactory-reset).

#### Field Schema Definitions

| Field Name | Type | Description |
| :--- | :---: | :--- |
| `caller` | String | Extension that initiated the call. |
| `callee` | String | Target extension. |
| `startMs` | Integer | Call start time on the server's steady-clock basis (not wall-clock; no RTC is guaranteed on-device). Comparable only against other values from the same boot — it is meaningless as an absolute timestamp and resets on reboot. |
| `ageSec` | Integer | Seconds since the call started, derived from the same steady-clock basis as `startMs`. This is the field to use for "how long ago"; `startMs` is not convertible to a date. |
| `duration` | Integer | Call length in seconds. |
| `result` | String | How the call ended. Exactly one of `answered`, `busy`, `cancelled`, `unavailable`, `failed` — `cdrResultToString()`, `src/SIP/CallDetailRecord.hpp:32`. `failed` is also the fallback for an unmapped enumerator. |

> [!WARNING]
> **`result` is never `"completed"`.** Earlier revisions of this document used that
> value in the example above; no such string exists in the firmware. A client
> switching on `"completed"` matches nothing — the answered case is `"answered"`.

```bash
curl -s "http://$DEV/api/cdr"
```

---

### `GET /api/pcap`
Downloads a classic libpcap file of the most recent SIP signaling packets, ready to open directly in Wireshark. Both directions are captured (packets the server received and packets it sent); **RTP/media is never included** — the capture ring is fed from the SIP socket only.

For an ordinary extension-to-extension call that also means there is nothing to miss: the board relays signalling and the two phones stream RTP directly to each other, so no media ever reaches it. That is not true of every call. The board terminates media itself on `440` (tone), `555` (anchor bridge) and `888` (conference). An outbound trunk call crosses it on **both** sides — RTP to and from the handset, chunked-HTTPS PCM16 to and from the provider, with `MediaBridge` shuttling PCM16 between the two. None of that appears here either — this endpoint captures SIP, not media, whoever is carrying it. (`777` is an SDP loopback: the phone streams to its own address, so there is genuinely no media leg on the board — see `src/SIP/RequestsHandler.cpp:1228`.)

Captured packets are synthesized into a minimal Ethernet+IPv4+UDP frame around the exact SIP bytes (dummy MAC addresses — the server has no real link-layer information — but real source/destination IP:port), so Wireshark's SIP dissector decodes them exactly as it would a real capture. Timestamps are relative to the server's monotonic clock, not wall-clock (no RTC is guaranteed on the device — same basis as `/api/cdr`'s `startMs`).

Only packets that pass structural validation and the per-source-IP rate limiter (Issue #38) are captured — this is a signaling-research aid, not a wire-level DoS forensics tool. The ring is bounded (`POCKETDIAL_PCAP_RING_SIZE`, default 64); older packets are dropped as new ones arrive.

* **Auth**: Fully gated — the dispatch chain calls `requireAdmin(sock, req, /*needCsrf=*/false)` (`HttpServer.cpp:467`), so gates 1, 2 and 4 all apply. **The same-origin check is applied**; what this route skips is only the CSRF token, because it is a read.
* **Request Headers**: `Cookie: pd_session=…` (required)
* **Response Content-Type**: `application/vnd.tcpdump.pcap`
* **Response Headers**: `Content-Disposition: attachment; filename="pocket-dial.pcap"`
* **Response Status Codes**:
  * `200 OK`: Always — an empty/never-populated ring still returns a valid (headers-only) `.pcap`.
  * `401 Unauthorized`: `{"error":"authentication required"}` — note this is a JSON body on an endpoint that otherwise serves binary.
  * `403 Forbidden`: cross-origin, or `setup_required` while still on the default credential.

> [!NOTE]
> **Correction.** Earlier revisions of this document said this route has "no
> same-origin check". It does — `requireAdmin()` runs `requireSameOrigin()` first for
> every gated route, reads included. The comment inside `sendApiPcap()`
> (`HttpServer.cpp:1125`) that says otherwise describes the handler in isolation and
> is stale with respect to the dispatch chain that calls it. The reasoning it gives
> (a file download is not a state change, and `SameSite=Strict` already blocks
> cross-site cookie replay) is sound; it just is not what the code does.

```bash
curl -s -o pocket-dial.pcap -b "pd_session=$SESSION" "http://$DEV/api/pcap"
```

---

### `GET /api/diagnostics/pcap`

A second route to the exact same handler as [`GET /api/pcap`](#get-apipcap) — the path
Issue #33's original feature request asked for. It is a real route rather than an HTTP
redirect so that `curl -o dump.pcap http://<device>/api/diagnostics/pcap` works without
`-L`, and because there is no second capture mechanism to point at: `sendApiPcap()`
reads the same `PcapCapture` ring either way (`HttpServer.cpp:480`).

**Identical in every respect** — same response body, same `Content-Type`, same
`Content-Disposition`, same `requireAdmin(…, needCsrf=false)` gate, same status codes.
Use whichever path you prefer; neither is deprecated.

```bash
curl -s -o pocket-dial.pcap -b "pd_session=$SESSION" "http://$DEV/api/diagnostics/pcap"
```

---

### `GET /api/trace`
Returns the same capture ring as `/api/pcap`, as JSON, for the dashboard's live SIP tracer panel. Returns the **whole current ring on every call** rather than an incremental "since" delta — the ring is small (`POCKETDIAL_PCAP_RING_SIZE`, default 64) and this is meant to be polled every second or two on a LAN, so re-sending it is cheap and the server doesn't need to track any per-client polling state. The client filters to `seq` values it hasn't already rendered.

* **Auth**: Fully gated, `needCsrf = false` — same gate as `/api/pcap` (gates 1, 2 and 4; no token), because it is the same underlying data.
* **Request Headers**: `Cookie: pd_session=…` (required)
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`: A bare JSON array; `[]` when the ring is empty.
  * `401 Unauthorized`: `{"error":"authentication required"}`
  * `403 Forbidden`: cross-origin, or `setup_required`.
* **Response Payload JSON Example**:
```json
[
  {
    "seq": 42,
    "tsUs": 1723180800123456,
    "dir": "in",
    "peer": "192.168.1.50:5060",
    "text": "INVITE sip:101@192.168.4.1 SIP/2.0\r\n..."
  }
]
```

#### Field Schema Definitions

| Field Name | Type | Description |
| :--- | :---: | :--- |
| `seq` | Integer | Monotonic capture sequence number, never reused (even across ring eviction) — use it as a client-side high-water mark. |
| `tsUs` | Integer | Capture time in microseconds on the server's monotonic clock (not wall-clock; no RTC is guaranteed on the device). |
| `dir` | String | `"in"` for a packet the server received, `"out"` for one it sent. |
| `peer` | String | The other party's `"ip:port"`. |
| `text` | String | The raw SIP message bytes, exactly as captured — JSON-escaped, including any C0 control byte as `\u00XX`, so a malformed-but-tolerated packet cannot break `JSON.parse()` (`jsonEscape`, `HttpServer.cpp:883`; regression-tested in `tests/JsonEscape_test.cpp`). |

```bash
curl -s -b "pd_session=$SESSION" "http://$DEV/api/trace"
```

---

### `GET /config/<mac>.cfg`
Zero-touch phone auto-provisioning (Issue #35). `<mac>` is 12 lowercase hex characters, e.g. `GET /config/805ec079c37f.cfg`. Returns a Yealink auto-provisioning config (`#!version:1.0.0.1` plain-text `key = value` format, not XML) for the extension that MAC is adopted as, if any. Point a phone's "Auto Provision Server URL" at `http://<device-ip>/config/` (Yealink templates the filename with the phone's own MAC).

Only serves configs for MACs already in the Registrar's adopted-device registry (Learn or Secure mode — see `docs/LEARN_MODE.md`/`Registrar.hpp`), so this covers **re**-provisioning (factory reset, handset swap, config refresh) rather than a phone's very first-ever contact: that first REGISTER is what gets a MAC adopted in the first place, and still needs the phone told its own extension number by some other means (typically typed once on the handset, or carried over from a previous config). Every subsequent boot can fetch this URL and get the account/server/codec settings back with no typing.

> [!IMPORTANT]
> **On a default board this endpoint is a 404 for every MAC.** The shipped registrar
> mode is `open` (see [`POST /api/registrar`](#post-apiregistrar)), and `open` never
> records a device — only Learn mode adopts, and only Secure mode keeps what Learn
> adopted. So zero-touch provisioning is implemented and reachable, but it is inert
> until an operator moves the registrar to `learn` and lets the phones register once.
> That is a configuration prerequisite, not a bug, and it is the single thing most
> likely to make this endpoint look broken.

Intentionally **not session-gated** — a booting phone has no way to present a session cookie. The MAC is the only credential this endpoint checks: it's drawn from a 2^48 space and only ever served for a MAC that's already adopted, so guessing is impractical, and both an unknown MAC and a not-yet-adopted one return the same `404` (no distinguishing information). The HTTP listener is always open (§0), so a phone can always reach the URL; whether it gets a config back depends only on adoption.

The config never carries a working SIP password: `Registrar`/`SipSecretStore` only ever store `HA1 = MD5(ext:realm:secret)`, a one-way hash — the server never has the plaintext to hand out, even for a device that requires one (Secure mode, or a Learn-mode device individually promoted via `secure()`). For those, the config still provisions everything else and adds a comment noting the admin has to set the password by hand on the handset.

**The path shape is checked before any lookup, and it is strict**
(`isProvisioningConfigPath`, `HttpServer.cpp:1166`). The path must be exactly
`/config/` + **12 characters** + `.cfg`, and each of those 12 must be in `[0-9a-f]` —
**lowercase only**. `GET /config/805EC079C37F.cfg` fails the shape test and falls
through to the generic dispatch `404` (plain text, §1) without the registry ever being
consulted; so does an 11- or 13-character MAC, and so does a MAC with separators.
Lowercase your MAC before you ask. Yealink handsets template the filename with their
own MAC in lowercase, which is why the firmware only accepts that form.

* **Request Headers**: None
* **Response Content-Type**: `text/plain`
* **Response Status Codes**:
  * `200 OK`: MAC is adopted; config body returned.
  * `404 Not Found`: `<mac>` isn't in the adopted-device registry; **or** the path doesn't match the `/config/<12 lowercase hex>.cfg` shape at all; **or** the config builder refused the extension (a CR/LF in it — Issue #107 — produces a miss rather than a partial config). All three are the same plain-text `404 Not Found`, deliberately indistinguishable.

```bash
# Note the lowercase MAC — uppercase is a 404 before the lookup even runs
curl -s "http://$DEV/config/805ec079c37f.cfg"
```

#### Response Example (200 OK)
```
#!version:1.0.0.1
# Auto-generated by pocket-dial for extension 101. Issue #35.
account.1.enable = 1
account.1.label = 101
account.1.display_name = 101
account.1.auth_name = 101
account.1.user_name = 101
account.1.password =
account.1.sip_server.1.address = 192.168.4.1
account.1.sip_server.1.port = 5060
account.1.sip_server.1.transport_type = 0
account.1.nat.udp_update_enable = 0
account.1.codec.1.enable = 1
account.1.codec.1.payload_type = PCMU
account.1.codec.1.priority = 1
account.1.codec.2.enable = 1
account.1.codec.2.payload_type = PCMA
account.1.codec.2.priority = 2
```

> [!NOTE]
> **This key set has never been confirmed against a physical handset.** The names and
> syntax follow Yealink's long-stable, widely-documented auto-provisioning key set, and
> a real Yealink T29 has since been registered to a bench board — but by hand, not by
> fetching this file. Treat the rendered config as best-effort until a handset is
> actually provisioned from it.

---

### `POST /api/dnd`
Sets or clears Do-Not-Disturb on a registered extension.

* **Requires Same-Origin Check**: Yes
* **Requires `pd_session` cookie**: Always (see §0)
* **Request Content-Type**: `application/x-www-form-urlencoded`
* **Request Parameters**:
  * `extension` (Required): The extension to set DND on. Must not be `777` (echo test), `999` (all-page broadcast) or `555` (anchor media bridge) — none of the three is a real endpoint (`HttpServer.cpp:1222`).
  * `on` (Optional): `1`, `true`, or `on` enables DND; **anything else disables it** — including omitting the parameter, `0`, `yes`, `TRUE` and `ON`. The comparison is exact and case-sensitive, so `on=True` turns DND **off**.
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`
  * `400 Bad Request`: `{"error":"missing extension parameter"}`
  * `400 Bad Request`: `{"error":"cannot set DND on a virtual extension"}` — `extension` is `777`, `999` or `555`.
  * `401`/`403`: gates 1-4 as in §0.1.

> [!NOTE]
> **`200` is an echo of the request, not a confirmation it was stored.**
> `RequestsHandler::setDnd()` returns `void`; the config layer below it logs and drops
> anything it will not accept, and the handler has already sent `200` by then. The one
> case that matters here is the table cap: a **new** extension is refused once
> `POCKETDIAL_MAX_CLIENTS` = **32** extensions are already in DND
> (`PbxFeatureConfig.cpp:28`), silently, with a `200`. Turning DND off frees the slot.
> Read [`GET /api/status`](#get-apistatus)'s `dnd[]` back to confirm.
>
> Unlike forward and group below, the DND config layer applies **no** reserved-extension
> check of its own, so `888` (the meet-me conference) is not refused anywhere and DND
> on it is genuinely stored — an asymmetry, not a documented feature.

#### Response Example (200 OK)
```json
{
  "status": "ok",
  "extension": "1001",
  "dnd": true
}
```

```bash
# Enable
curl -s -X POST "http://$DEV/api/dnd" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF" \
     -d "extension=1001&on=1"

# Disable (any value that is not 1/true/on, including omitting `on` entirely)
curl -s -X POST "http://$DEV/api/dnd" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF" \
     -d "extension=1001&on=0"
```

---

### `POST /api/forward`
Configures call forwarding for an extension.

* **Requires Same-Origin Check**: Yes
* **Requires `pd_session` cookie**: Always (see §0)
* **Request Content-Type**: `application/x-www-form-urlencoded`
* **Request Parameters**:
  * `extension` (Required): The extension to configure. Must not be `777`, `999` or `555` (`HttpServer.cpp:1261`).
  * `trigger` (Required): Exactly one of `always`, `busy`, `noanswer`. Case-sensitive.
  * `target` (Optional): The extension to forward to. **Empty clears the rule for that trigger** — that is the only way to unset one.
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`
  * `400 Bad Request`: `{"error":"missing extension or trigger parameter"}`
  * `400 Bad Request`: `{"error":"trigger must be always|busy|noanswer"}`
  * `400 Bad Request`: `{"error":"cannot forward a virtual extension"}` — `extension` is `777`, `999` or `555`.
  * `401`/`403`: gates 1-4 as in §0.1.

> [!NOTE]
> **`200` is an echo, not a confirmation** (same contract as `/api/dnd`). Two cases
> are refused *below* the HTTP layer and still answer `200`:
> `extension=888` (the meet-me conference — the HTTP layer does **not** reject it, but
> `PbxFeatureConfig::setForwardLocked` does, `PbxFeatureConfig.cpp:99`), and a **new**
> extension once `POCKETDIAL_MAX_CLIENTS` = **32** extensions already have forwards.
> `target` gets no charset validation at this layer at all. Read
> [`GET /api/status`](#get-apistatus)'s `forwards[]` back to confirm.

#### Response Example (200 OK)
```json
{
  "status": "ok",
  "extension": "1001",
  "trigger": "busy",
  "target": "1002"
}
```

```bash
# Forward 1001 to 1002 when busy
curl -s -X POST "http://$DEV/api/forward" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF" \
     -d "extension=1001&trigger=busy&target=1002"

# Clear that same rule (empty target)
curl -s -X POST "http://$DEV/api/forward" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF" \
     -d "extension=1001&trigger=busy&target="
```

---

### `POST /api/group`
Creates, updates, or deletes a ring/hunt group.

* **Requires Same-Origin Check**: Yes
* **Requires `pd_session` cookie**: Always (see §0)
* **Request Content-Type**: `application/x-www-form-urlencoded`
* **Request Parameters**:
  * `extension` (Required): The group's own extension number. Must not be `777`, `999` or `555` (`HttpServer.cpp:1293`).
  * `members` (Optional): Member extensions separated by **commas or any whitespace** — `pbx::splitMembers` treats both as separators and skips runs of them, so `1001,1002 1003` and `1001, 1002,1003` parse identically (`src/SIP/PbxConfig.hpp:107`). **An empty or whitespace-only list deletes the group.** At most `POCKETDIAL_MAX_CLIENTS` = 32 members are parsed; the rest of the string is ignored silently.
  * `mode` (Optional): `ringall` (the default when omitted or empty) or `hunt`. Case-sensitive.
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`
  * `400 Bad Request`: `{"error":"missing extension parameter"}`
  * `400 Bad Request`: `{"error":"cannot use a reserved extension as a group"}` — `extension` is `777`, `999` or `555`.
  * `400 Bad Request`: `{"error":"mode must be ringall|hunt"}`
  * `401`/`403`: gates 1-4 as in §0.1.

> [!NOTE]
> **`200` is an echo, not a confirmation** (same contract as `/api/dnd`). Refused below
> the HTTP layer, still `200`: `extension=888` (the meet-me conference — rejected by
> `PbxFeatureConfig::setRingGroup`, `PbxFeatureConfig.cpp:163`, but **not** by the HTTP
> layer), and a **new** group once `POCKETDIAL_MAX_CLIENTS` = **32** groups exist.
> The response echoes your raw `members` string verbatim, *not* the parsed list — read
> [`GET /api/status`](#get-apistatus)'s `groups[]` to see what was actually stored (as
> a comma-joined string).

#### Response Example (200 OK)
```json
{
  "status": "ok",
  "extension": "700",
  "mode": "ringall",
  "members": "1001,1002,1003"
}
```

```bash
# Create/update ring group 610
curl -s -X POST "http://$DEV/api/group" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF" \
     -d "extension=610&members=1001,1002,1003&mode=ringall"

# Delete it (empty member list)
curl -s -X POST "http://$DEV/api/group" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF" \
     -d "extension=610&members="
```

---

### `POST /api/dialplan`
Creates, updates, or deletes one rule in the dial plan (Issue #69) — the bounded,
ordered `pattern → action` table that generalizes ring groups into LAN routing.

It is also **the only route to an outside line.** There is no hardcoded `9` prefix and
no "unrecognised destination falls through to the trunk" behaviour: with an empty dial
plan, every outside number is answered `404` without the call ever leaving the box. A
`trunk` rule is what creates outbound dialling.

**Upsert vs. delete.** Naming an `action` **always** means create/update. **Omitting
both `action` and `target` deletes** the rule with that pattern. The two are separate
signals on purpose: a `trunk` rule may legitimately carry an empty `target` (that is
how you say "strip N digits and prepend nothing"), so an empty target alone can no
longer mean "delete" — it used to, which made the request that creates a strip-only
trunk rule byte-identical to the request that deletes it (`HttpServer.cpp:1354-1358`).
A non-trunk action with an empty target is now refused `400` rather than silently
deleting the rule the operator was editing.

Rules are evaluated **in table order, first match wins**. A pattern already in the
table is edited **in place**, keeping its evaluation position; a new pattern is
appended to the end. To reorder, delete a rule and re-add it. An edit replaces the
rule's action, target **and** `stripDigits` together — an earlier build kept the first
insert's strip count forever, which silently misdialled every edited trunk rule. The
table is hard-capped at `POCKETDIAL_MAX_DIAL_RULES` (**16** by default, see
`src/SIP/PoolConfig.hpp:163`); once it is full a *new* pattern is rejected server-side
(logged, still `200`), while existing rules stay editable.

The plan is consulted **after** every reserved virtual extension — `777` (echo), `999`
(all-page), the `980`–`989` paging zones, `440` (tone), `888` (conference), `555`
(anchor bridge) and the `700`–`70N` park orbits — and after a direct ring-group
extension lookup, and **before** call-forwarding / DND / ordinary extension lookup
(`src/SIP/RequestsHandler.cpp:1410`). So a rule can only capture a number that would
otherwise have reached the ordinary extension lookup — no rule, not even a catch-all
`*`, can shadow the echo test, a park retrieval, or a configured group extension.
**A dialed number that matches no rule routes exactly as it did before the dial plan
existed.**

**Pattern grammar** (deliberately tiny — no regex):

| Token | Meaning |
| :--- | :--- |
| digits / letters / `#` / `*` | Match themselves, literally. |
| `X` or `x` | Match exactly one digit (`0`–`9`). |
| a **trailing** `*` | Match the rest of the dialed number, including nothing at all (prefix match). |

A `*` anywhere but the last character is a **literal** `*`, because star-codes
(`*8` group pickup, `*69` last-caller, `*60`/`*80`/`*73`) are real dialable strings on
this device. Examples: `601` (exact),
`6XX` (any three-digit number starting with 6), `6*` (any number starting with 6),
`*` (catch-all), `*8` (the literal star-code).

* **Requires Same-Origin Check**: Yes
* **Requires `pd_session` cookie**: Always (see §0)
* **Request Content-Type**: `application/x-www-form-urlencoded`
* **Request Parameters**:
  * `pattern` (Required): The rule's dialed-number pattern, and its key in the table. May contain only letters, digits, `#` and `*`. Must not be `777`, `999`, `440` or `555` — those are routed before the dial plan, so such a rule could never fire (`HttpServer.cpp:1346`).
  * `action` (Optional, default `group` when a `target` is given): `group` (ring/hunt group), `page` (paging zone), `park` (park orbit), or `trunk` (outbound access through the configured anchor/telephony provider — Issue #165). **Naming any action means upsert.**
  * `target` (Optional): The extension the action routes to — a ring-group extension for `group`, a `980`–`989` zone for `page`, a `700`–`70N` orbit for `park` — or, for `trunk`, the digit string **prepended** to the dialed number after stripping. A `trunk` rule may leave it **empty**, meaning "prepend nothing"; every other action requires it. **Omitting `action` *and* `target` together deletes the rule with that pattern.**
  * `stripDigits` (Optional, `trunk` only, default `0`): how many leading digits to remove from the dialed number before prepending `target`. Must fit the pattern: for a fixed-length pattern (no trailing `*`) it cannot exceed the pattern's length; a prefix pattern (trailing `*`) is instead checked against the *actual* dialed number at call time, and a rule that no longer fits answers `404` rather than placing a truncated number.
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`
  * `400 Bad Request`: `pattern` missing, `pattern`/`target` contains a character outside `[0-9A-Za-z#*]`, `pattern` is a reserved extension, `action` is not `group`/`page`/`park`/`trunk`, `target` is empty on a non-`trunk` action, the `target` is the wrong shape for the action (`page` must name a `980`–`989` zone, `park` a park orbit), or `stripDigits` is not a small non-negative integer that fits the pattern.
  * `401 Unauthorized` / `403 Forbidden`: as above.

> [!NOTE]
> A rule whose target no longer resolves — a group or zone deleted after the rule
> was written, a `trunk` rule whose `stripDigits` no longer fits the dialed number,
> or no anchor/telephony provider currently connected — is answered `404 Not Found`
> at dial time rather than falling through, so a stale rule fails visibly instead of
> silently ringing whichever real extension happens to share the dialed digits.

**`trunk` example**: dialing `9` + 11 digits, stripping the `9` and prepending `1`
so `93057673260` reaches the configured trunk as `13057673260`:
```
pattern=9XXXXXXXXXX&action=trunk&target=1&stripDigits=1
```
"Strip 1, prepend nothing" is `pattern=9XXXXXXXXXX&action=trunk&target=&stripDigits=1` —
legal precisely because `action` is present.

The transformed number is placed as an outbound call through whichever
telephony-API slot is currently active ([`GET /api/telephony-config`](#get-apitelephony-config)),
using the same origination path virtual extension `555` uses
(`RequestsHandler::originateAnchorCall()`), so it requires that provider to actually be
connected.

> **This is not a SIP trunk.** The outbound path is an `AnchorClient` — HTTP/OAuth2 plus
> a call-control WebSocket, with media as chunked-HTTPS PCM16 — and the shipping real
> client speaks the 3CX Call Control API. Nothing in the tree ever *sends* a `REGISTER`,
> so the board never registers to an ITSP and speaks no SIP to a carrier at all.
> `POCKETDIAL_MAX_ANCHOR_CALLS` is **4** (`src/SIP/PoolConfig.hpp:221`), and the effective
> limit is `min(provider, 4)` — the default `LoopbackAnchorClient` declares 1, so a stock
> board still gets one outside call
> at a time, and a second attempt is refused rather than queued.

`target` is charset-limited the same as every other dial-plan token
(`[0-9A-Za-z#*]`) — a bare national number like `1` works with most US trunks.
There is **no E.164 normalization anywhere in the firmware**: what the rule
produces is exactly what the provider is asked to dial, `+` included or not.

#### Request Example (Form URL-Encoded)
```http
POST /api/dialplan HTTP/1.1
Host: 192.168.4.1
Origin: http://192.168.4.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 35

pattern=2XX&action=group&target=610
```

#### Response Example (200 OK)
```json
{
  "status": "ok",
  "pattern": "2XX",
  "action": "group",
  "target": "610",
  "stripDigits": 0
}
```

`stripDigits` is **always** present in the response, `0` for every non-`trunk` action
(`HttpServer.cpp:1426`). The response is an echo of the accepted request, so on a
delete it reads back `"action":""`, `"target":""`, `"stripDigits":0`.

> [!NOTE]
> **`200` is an echo, not a confirmation.** `RequestsHandler::setDialRule()` returns
> `void` and the config layer logs-and-drops what it refuses. The case that bites is
> the table cap: once `POCKETDIAL_MAX_DIAL_RULES` = **16** rules exist, a *new* pattern
> is dropped with a log line and a `200` (`PbxFeatureConfig.cpp:358`). Existing rules
> stay editable. Read [`GET /api/status`](#get-apistatus)'s `dialplan[]` back — it is
> also the only way to see the evaluation order you now have.

```bash
# Route 2XX to ring group 610
curl -s -X POST "http://$DEV/api/dialplan" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF" \
     -d "pattern=2XX&action=group&target=610"

# Outside line: dial 9 + 11 digits, strip the 9, prepend 1
curl -s -X POST "http://$DEV/api/dialplan" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF" \
     -d "pattern=9XXXXXXXXXX&action=trunk&target=1&stripDigits=1"

# Strip 1, prepend nothing — legal ONLY because `action` is named
curl -s -X POST "http://$DEV/api/dialplan" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF" \
     -d "pattern=9XXXXXXXXXX&action=trunk&target=&stripDigits=1"

# Delete the rule: pattern alone, NEITHER action nor target
curl -s -X POST "http://$DEV/api/dialplan" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF" \
     -d "pattern=2XX"
```

> [!IMPORTANT]
> **It is the emptiness of the *values* that decides, not the presence of the keys.**
> `getFormParam()` returns an empty string both for a parameter that was omitted and
> for one sent with an empty value, so the server cannot tell them apart:
> `pattern=2XX`, `pattern=2XX&target=` and `pattern=2XX&action=&target=` are all the
> same request and all delete the rule. An upsert therefore requires a **non-empty**
> `action` or a **non-empty** `target`. The "strip N, prepend nothing" trunk rule is
> expressible only because `action=trunk` is non-empty while `target=` is empty —
> which is exactly the case that would be lost if the delete keyed on `target` alone
> (`HttpServer.cpp:1354-1358`).

---

### `GET /api/telephony-config`

Lists the carrier/anchor credential slots — the outbound side of the box. There are
exactly `TelephonyApiConfig::kSlots` = **4** of them (`src/SIP/TelephonyApiConfig.hpp:35`),
and at most one is active at a time.

```json
{
  "slots": [
    {
      "index": 0,
      "type": "TELEPHONY-API",
      "enabled": true,
      "implemented": true,
      "active": true,
      "baseUrl": "https://pbx.example.com",
      "clientId": "pocketdial",
      "routeDn": "8000",
      "secretSet": true
    }
  ]
}
```

| Field | Type | Description |
| :--- | :---: | :--- |
| `index` | Integer | The slot's position, and the `<slot>` path segment for the mutating routes below. |
| `type` | String | `LOOPBACK` (the built-in reference client) or `TELEPHONY-API` (a real provider). Exact spellings — `telephonyProviderName()`, `src/SIP/TelephonyProvider.cpp:3`. |
| `enabled` | Boolean | Operator's on/off switch for the slot. An enabled real slot must be fully configured — see the `PUT` below. |
| `implemented` | Boolean | Whether a client for this provider type is actually compiled in. |
| `active` | Boolean | `true` for the one slot the anchor path currently originates through. |
| `baseUrl` | String | Provider API base URL. Must be `https://` on an enabled real slot. |
| `clientId` | String | OAuth2 client identifier. |
| `routeDn` | String | The provider-side DN this box owns. Outbound calls originate from it; inbound calls to it are what [`/api/did-mapping`](#get-apidid-mapping) routes. |
| `secretSet` | Boolean | Whether a secret is stored. **The secret itself is never returned by any endpoint**, by design (`telephonySlotJson`, `HttpServer.cpp:1490`). |

> **What this is not.** These slots do not describe a SIP trunk. The client speaks
> HTTP/OAuth2 plus a call-control WebSocket, with media as chunked-HTTPS PCM16, and the
> shipping real client targets the **3CX Call Control API**. The firmware never sends a
> `REGISTER` of its own, so the box does not register to an ITSP and speaks no SIP to a
> carrier. Reaching a trunk also requires a dial-plan rule with `action=trunk`
> ([`POST /api/dialplan`](#post-apidialplan)) — there is no `9`-prefix default.

* **Auth**: Gated read — same-origin, session and completed setup, **no** `X-CSRF`. Read-gated rather than public (unlike `/api/status`) because this is credential-adjacent configuration.
* **Response Status Codes**:
  * `200 OK`: Always. `{"slots":[]}` if the SIP engine has not been attached yet — an empty array, not an error.
  * `401`/`403`: gates 1, 2 and 4 as in §0.1.

```bash
curl -s "http://$DEV/api/telephony-config" -b "pd_session=$SESSION"
```

---

### `PUT /api/telephony-config/<slot>`

Writes one slot. `<slot>` is the decimal index from the `GET`. Form-encoded.

| Param | Values | Effect |
| :--- | :--- | :--- |
| `enabled` | `1`/`true`/`on` | Enables the slot. **Omitting it disables the slot** — this is a full replace, not a merge. |
| `baseUrl` | ≤ 128 chars | Provider API base URL. |
| `clientId` | ≤ 64 chars | OAuth2 client id. |
| `secret` | ≤ 64 chars | OAuth2 client secret. **An empty value means "keep the stored secret"**, so a slot can be edited without re-typing it. |
| `routeDn` | ≤ 64 chars | The DN this box owns on the provider. |

`type` is deliberately **not** a parameter: this endpoint only ever configures a real
(`TELEPHONY-API`) provider. `LOOPBACK` is the internal default and is never set through
the API (`HttpServer::sendApiTelephonyConfigSet`).

An **enabled** real slot is validated as actually dialable, and refused `400` otherwise
(`TelephonyApiConfig::setSlot`): the base URL must start `https://`, and `routeDn`,
`clientId` and an effective secret must all be non-empty. A blank route DN in particular
used to be accepted and is the one misconfiguration nothing downstream can report — the
control WebSocket carries no DN, so the board comes up "connected" and every call posts
to `.../callcontrol//makecall`, which reads in the field as "the API was hit but no call
happened". A **disabled** slot is free to be an incomplete draft.

**`<slot>` path shape**: `parseTelephonyConfigSlotPath` (`HttpServer.cpp:1436`) accepts
1-9 decimal digits with no trailing segment. Anything else — a negative number, a
non-digit, a trailing slash — does not match the route at all and falls through to the
plain-text dispatch `404` (§1) rather than a JSON error. A well-formed but out-of-range
index (`4` and up; there are 4 slots, indices `0`-`3`) *does* match, and is rejected by
`TelephonyApiConfig::setSlot` with `400 {"error":"Bad slot index"}` — range-checking
lives in exactly one place in the codebase, deliberately.

* **Response Status Codes**:
  * `200 OK`: Slot written. Body is `{"status":"ok","slot":{…}}` with the same slot shape as the `GET`.
  * `400 Bad Request`: the body carries the literal reason from `TelephonyApiConfig::setSlot` — one of `{"error":"Bad slot index"}`, `{"error":"Unknown provider type"}`, `{"error":"Base URL too long"}` (over 128), `{"error":"Field too long"}` (`clientId`/`secret`/`routeDn` over 64), `{"error":"Enabled slot needs an https:// base URL"}`, `{"error":"Enabled slot needs a route DN"}`, `{"error":"Enabled slot needs a client ID"}`, `{"error":"Enabled slot needs a client secret"}`, or an NVS failure (`{"error":"NVS open failed"}` / `{"error":"NVS write failed"}` on device, `{"error":"config file open failed"}` on host).
  * `401`/`403`: gates 1-4 as in §0.1.

> [!NOTE]
> If the SIP engine is not attached yet, this endpoint **echoes the request back as
> `200` without persisting anything** (`HttpServer.cpp:1563`) — the same convention
> `/api/forward` and `/api/group` use. The echoed `slot` object is built from what you
> sent, so it looks like a successful write. Check
> [`GET /api/registrar`](#get-apiregistrar)'s `attached` first if you are scripting
> against a just-booted device.

```bash
curl -s -X PUT "http://$DEV/api/telephony-config/0" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF" \
     --data-urlencode "enabled=1" \
     --data-urlencode "baseUrl=https://pbx.example.com" \
     --data-urlencode "clientId=pocketdial" \
     --data-urlencode "secret=s3cr3t" \
     --data-urlencode "routeDn=8000"

# Edit the DN without re-typing the secret (empty secret = keep the stored one)
curl -s -X PUT "http://$DEV/api/telephony-config/0" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF" \
     -d "enabled=1&baseUrl=https://pbx.example.com&clientId=pocketdial&secret=&routeDn=8001"
```

Note the second form still has to resend `enabled`, `baseUrl`, `clientId` and
`routeDn`: only `secret` has the "empty means keep" carve-out. Everything else is a
full replace, and omitting `enabled` silently disables the slot.

---

### `POST /api/telephony-config/<slot>/activate`

Makes that slot the one the outbound anchor path uses.

> [!IMPORTANT]
> **A reboot is required before the new slot is actually live.** Provider selection is
> boot-time-only — the running `_anchorClient` was chosen at startup and activation only
> changes the persisted choice. Until the board restarts, the previously-active slot is
> still the one placing calls, and
> [`POST /api/telephony-config/<slot>/test`](#post-apitelephony-configslottest) will
> refuse the newly-activated slot with *"this slot is not the active one — activate it
> and reboot first"* (`RequestsHandler::testDialSlot`).

* **Request Parameters**: none — the body is ignored; the slot is the path segment.
* **Response Status Codes**:
  * `200 OK`: `{"status":"ok","activeIndex":0}`
  * `400 Bad Request`: `{"error":"Bad slot index"}`, or an NVS/persist failure string from `TelephonyApiConfig::setActiveSlot`.
  * `401`/`403`: gates 1-4 as in §0.1.

> [!NOTE]
> **Index `4` is accepted and means "no slot active".** `setActiveSlot` admits
> `kNoActiveSlot`, which equals `kSlots` = `4` (`TelephonyApiConfig.cpp:184`), so
> `POST /api/telephony-config/4/activate` persists "nothing active" and answers
> `{"status":"ok","activeIndex":4}`. Index `5` and up are rejected `400`. This is
> observed in the source and is the only way to deactivate all slots through the API;
> nothing in the dashboard offers it, and it is not otherwise documented.
>
> If the SIP engine is not attached, the handler skips the call entirely and still
> answers `{"status":"ok","activeIndex":<n>}` having persisted nothing.

```bash
curl -s -X POST "http://$DEV/api/telephony-config/0/activate" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF"
```

---

### `POST /api/telephony-config/<slot>/test`

> [!CAUTION]
> **This endpoint is not read-only. It places a real outbound call.**
> Despite the name, `POST .../test` is not a dry run, a ping, or a config check. It
> calls `AnchorClient::makeCall()` against the slot's own `routeDn` through the live
> provider connection and then immediately calls `dropCall()` on the resulting leg
> (`RequestsHandler::testDialSlot`, `src/SIP/RequestsHandler.cpp:4583`). Against a
> production PBX or carrier that means a real origination: it may ring a real DN,
> appear in the provider's CDRs, and — depending on the provider — be billable. Do not
> call it casually, do not put it in a health-check loop, and do not fire it at a
> production slot to "see if the API is up". Use
> [`GET /api/telephony-config`](#get-apitelephony-config) for that; it touches nothing.

The dashboard Interconnect module's **Test Dial**. A connectivity probe, not a bridged
call: no session, no `MediaBridge`, no caller. It is a mutating action and takes the
full gate (`requireAdmin(…, needCsrf = true)`).

Refuses any slot that is not the currently-active one — only that slot has a live,
boot-selected anchor client behind it, so testing another would either exercise the
wrong connection or silently no-op.

* **Request Parameters**: none — the body is ignored.
* **Response Status Codes**:
  * `200 OK`: **always**, success or failure. Success lives in the body's `ok` field, because a failed probe is a normal diagnostic result rather than an HTTP error.
  * `401`/`403`: gates 1-4 as in §0.1 — these *are* real HTTP errors and are the only non-`200`s this route produces.

```json
{ "ok": true, "participantId": "42" }
```
```json
{ "ok": false, "error": "no anchor client connected" }
```

| Body | Meaning |
| :--- | :--- |
| `{"ok":true,"participantId":"<id>"}` | The call was placed **and then dropped**. `<id>` is the provider's id for the leg. This is the clean success. |
| `{"ok":true,"participantId":""}` | **The call was placed and was NOT dropped.** The firmware only calls `dropCall()` `if (!ownLeg.empty())` (`RequestsHandler.cpp:4616`), so an empty id means `makeCall()` reported success but did not hand back a controllable leg — there was nothing to hang up with. Treat this as a warning, not a success: the origination happened and the firmware has no handle on it. What the provider then does with that leg is provider-side and not observable from here. |
| `{"ok":false,"error":"this slot is not the active one — activate it and reboot first"}` | The requested slot is not `activeSlot()`. Provider selection is boot-time-only. |
| `{"ok":false,"error":"no anchor client connected"}` | No `_anchorClient`, or it reports not connected. Nothing was dialled. |
| `{"ok":false,"error":"anchor declined makeCall"}` | The provider refused the origination. Nothing is left up. |
| `{"ok":false,"error":"no handler attached"}` | The SIP engine has not bound to the dashboard yet — see [`GET /api/registrar`](#get-apiregistrar)'s `attached`. |

```bash
# Only do this against a slot you are willing to have place a real call
curl -s -X POST "http://$DEV/api/telephony-config/0/test" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF"
```

---

### `DELETE /api/telephony-config/<slot>`

Clears one slot, including its stored secret, so an operator can remove a credential
without a full factory reset.

* **Request Parameters**: none — the body is ignored; the slot is the path segment. (This is a `DELETE` with **no** JSON body, unlike [`DELETE /api/did-mapping`](#delete-apidid-mapping), which does take a form parameter.)
* **Response Status Codes**:
  * `200 OK`: `{"status":"ok","slot":{…}}` with the now-empty slot in the `GET`'s shape.
  * `400 Bad Request`: `{"error":"Bad slot index"}` (or an NVS failure string) — the bound check lives in `TelephonyApiConfig::clearSlot`, not here.
  * `401`/`403`: gates 1-4 as in §0.1.

If the SIP engine is not attached, the handler skips the clear and returns `200` with a
default-constructed (empty) slot view — the same "looks like it worked" caveat as the
`PUT` above.

```bash
curl -s -X DELETE "http://$DEV/api/telephony-config/0" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF"
```

---

### `GET /api/did-mapping`

The inbound half: which extension an incoming call to a given DID should ring.

```json
{ "mappings": [ { "did": "8000", "extension": "1001" } ] }
```

The table is bounded at `POCKETDIAL_MAX_DID_MAPPINGS` = **8**
(`src/SIP/PoolConfig.hpp:211`).

> **`did` is matched as a literal string against the provider's route DN**, not parsed as
> a phone number. There is no E.164 normalization and no suffix matching anywhere in the
> firmware (`RequestsHandler.cpp:2388`). Enter exactly the DN string the provider
> presents. An inbound call whose DN matches no mapping — or maps to an extension that is
> not currently registered — falls back to ringing **every** registered extension.

* **Auth**: Gated read — same-origin, session and completed setup, **no** `X-CSRF`.
* **Response Status Codes**:
  * `200 OK`: Always. `{"mappings":[]}` when empty or when the SIP engine is not attached.
  * `401`/`403`: gates 1, 2 and 4 as in §0.1.

```bash
curl -s "http://$DEV/api/did-mapping" -b "pd_session=$SESSION"
```

---

### `PUT /api/did-mapping`

Creates or updates one mapping. Form-encoded.

* **Request Parameters**:
  * `did` (Required): The literal route DN. Max 32 characters, and must not contain CR, LF or `=` — the persisted record is `=`-delimited, so a smuggled separator would corrupt the table on the next load (`DidMapping::fieldValid`). Otherwise unrestricted: a leading `+` is allowed here, unlike dial-plan tokens.
  * `extension` (Required): The extension to ring. Max 32 characters, and only letters, digits, `#` and `*` — the same charset gate `/api/dialplan` applies to a pattern or target.
* **Response Status Codes**:
  * `200 OK`: `{"status":"ok","did":"8000","extension":"1001"}`
  * `400 Bad Request`, with the literal body: `{"error":"missing did or extension parameter"}`; `{"error":"extension may contain only letters, digits, '#' and '*'"}`; `{"error":"cannot map a DID to a virtual/reserved extension"}` (`777`, `999`, `555`, `888` or `440` — none is a real endpoint a DID could usefully ring); or one of `DidMapping::setMapping`'s own strings — `{"error":"DID required"}`, `{"error":"Extension required"}`, `{"error":"Field too long"}` (over 32 characters), `{"error":"Field contains a control character"}`, `{"error":"DID mapping table full"}`. Updating an existing DID never consumes a slot, so it succeeds even on a full table.
  * `401`/`403`: gates 1-4 as in §0.1.

Note the `PUT` verb. This is one of only three non-`GET`/`POST` routes in the API (the
other two are `PUT`/`DELETE /api/telephony-config/<slot>`), and the body is still
form-encoded, not JSON.

```bash
curl -s -X PUT "http://$DEV/api/did-mapping" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF" \
     --data-urlencode "did=+13055550100" \
     --data-urlencode "extension=1001"
```

`--data-urlencode` matters here: a DID with a leading `+` sent through plain `-d` would
be decoded back into a space by `getFormParam()`'s `urlDecode`.

---

### `DELETE /api/did-mapping`

Removes one mapping. Form-encoded, parameter `did`. **Idempotent** — removing a DID that
was never mapped is still `200`, so there is nothing to branch on client-side.

* **Response Status Codes**:
  * `200 OK`: `{"status":"ok","did":"8000"}`
  * `400 Bad Request`: `{"error":"missing did parameter"}`
  * `401`/`403`: gates 1-4 as in §0.1.

```bash
curl -s -X DELETE "http://$DEV/api/did-mapping" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF" \
     --data-urlencode "did=+13055550100"
```

`curl -X DELETE` does not send a body unless you give it one — `--data-urlencode` (or
`-d`) is what makes this work, and `curl` sets the `Content-Type` and `Content-Length`
for you.

---

### `POST /api/configuring`
Tells the device a user is actively working through setup, pausing the captive-portal watchdog that would otherwise auto-switch the device back to Standalone AP mode. It mutates device state, so it takes the standard gate — same-origin, a `pd_session` cookie and an `X-CSRF` token — like every other mutating route (`HttpServer.cpp:606`).

* **Requires Same-Origin Check**: Yes
* **Requires `pd_session` cookie**: Always (see §0)
* **Request Parameters**: none — the body is ignored.
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`: Always. The handler only sets a flag; it cannot fail.
  * `401`/`403`: gates 1-4 as in §0.1.

The flag it sets (`g_decayHold`) is **one-way and in-memory**: there is no
"stop configuring" endpoint and no timeout. It is released only by a reboot, which
both `/api/wifi/connect`, `/api/wifi/mode_ap` and `/api/factory-reset` schedule. The
flag is linked into every transport, but only the display build's decay watchdog ever
reads it — on `eth`/`wifi` builds this endpoint succeeds and changes nothing
observable.

#### Response Example (200 OK)
```json
{
  "status": "ok",
  "message": "Setup mode held — auto-switch to Standalone paused."
}
```

The em dash arrives on the wire as the six-character JSON escape `\u2014`, not as raw
UTF-8 bytes (`HttpServer.cpp:2089`), so this particular response body is pure ASCII.

Do not generalise from that. The API uses **both** encodings for the same character:
`jsonEscape()` only escapes bytes below `0x20`, so anything ≥ `0x80` passes through
untouched — and the `/test` failure string *"this slot is not the active one — activate
it and reboot first"* (`src/SIP/RequestsHandler.cpp:4595`) carries a **raw UTF-8** em
dash. Any conformant JSON parser handles both; a byte-comparison against an expected
string will not.

```bash
curl -s -X POST "http://$DEV/api/configuring" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF"
```

---

### `POST /api/factory-reset`
Clears the login credential, the DTMF PIN, **all live sessions**, the AP security
settings (`ap_secure`/`ap_psk`/`cfgseed_gen`), the carrier-API credential table
(`tapicfg`), the DID→extension table (`didmap`), the CDR call-history ring (`cdrlog`),
and — on Wi-Fi builds — the Wi-Fi/mode NVS state, returning the device to its
default-credential/needs-initial-setup state, then reboots.

> [!IMPORTANT]
> **What a "factory reset" does *not* clear.** The wipe list above is the complete one;
> the PBX feature configuration survives it untouched. Specifically, everything you can
> see in [`GET /api/status`](#get-apistatus)'s `dnd[]`, `forwards[]`, `groups[]` and
> `dialplan[]` — and the **adopted-device registry** that
> [`GET /api/registrar`](#get-apiregistrar)'s `devices[]` lists and that
> [`GET /config/<mac>.cfg`](#get-configmaccfg) serves from — lives in the `pbxcfg` NVS
> namespace under its own keys, and nothing in this handler erases them. A reset board
> comes back up asking for initial setup with its whole dial plan, ring groups,
> forwards and phone roster intact.
>
> The registrar *admission mode* (`pbxcfg` key `reg_mode`) **is** cleared, by
> `DeviceConfig::clearAll()` — deliberately and specifically, because a board switched
> to `secure` before any extension was secured rejects every `REGISTER` and locks the
> operator out, and this is the documented rescue (Issue #188; `DeviceConfig.cpp:697`).
> So the mode resets while the roster it applies to does not.
>
> The source comment at `HttpServer.cpp:2110-2117` refers to `"storage"/"pbxcfg"`
> erases "above"/"below" that do not exist in the handler; read the code, not the
> comment.

* **Requires Same-Origin Check**: Yes
* **Requires `pd_session` cookie**: Always (see §0)
* **Build**: only the *Wi-Fi NVS erase* is `POCKETDIAL_HAS_WIFI`-guarded. The wipe, the `200` and the reboot are not: the reboot is guarded on `ESP_PLATFORM`, so every ESP transport restarts. See §4.2.
* **Request Content-Type**: `application/x-www-form-urlencoded`
* **Request Parameters**:
  * `confirm` (Required): Must be the literal string `ERASE`, case-sensitive. Guards against an accidental/stray POST wiping the device.
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`: Everything cleared. On Wi-Fi builds the Wi-Fi NVS keys are erased too; on
    every ESP build a reboot is scheduled ~1 s out. The `message` field differs by build
    (captive portal / dashboard / restart the process) but the status does not.
  * `400 Bad Request`: `{"error":"factory reset requires confirm=ERASE"}` — checked **first**, before anything is touched, so a request without it is genuinely harmless.
  * `401`/`403`: gates 1-4 as in §0.1.

> [!IMPORTANT]
> **The response arrives on a connection that is already logged out.**
> `AdminAuth::clearCredential()` wipes the session table (`AdminAuth.cpp:958`),
> including the session that made this request, so the `200` is the last thing that
> session will ever be told. There is no follow-up call to confirm with — treat the
> `200` itself as the record that the wipe completed.
>
> After the reboot the board comes back unprovisioned: the credential is the default
> again, gate 4 (`setup_required`) applies, and on `wifi`/`eth`/`lan8720` the SIP
> registrar stays down until a new admin credential is committed.

<details>
<summary>Historical: this endpoint used to report failure after succeeding (fixed, #189)</summary>

Before #189, only the `POCKETDIAL_HAS_WIFI` arm answered `200`. Every other build —
including the `eth` and `lan8720` firmwares that ship on real hardware — fell through to
`501 {"error":"factory reset not available on desktop"}`, **after** the unconditional
wipes had already cleared the credential, the carrier OAuth secret, the DID table and
the CDR ring. Those builds also never rebooted, leaving the device reset in flash but
still running the old configuration in RAM.

If you are reading logs or a runbook from before that fix: a `501` from this endpoint
recorded a *completed* destructive reset, not a no-op.

</details>

#### Response Examples (200 OK — the `message` is what varies by build)

Wi-Fi builds:
```json
{
  "status": "ok",
  "message": "Factory reset. Rebooting to captive-portal setup..."
}
```

`eth` / `lan8720` builds — reboot straight back to the dashboard, which will report
`needsSetup:true`:
```json
{
  "status": "ok",
  "message": "Factory reset. Rebooting — the dashboard will ask you to create a new admin login."
}
```

Host/desktop build — the wipe completes, but there is no firmware to restart:
```json
{
  "status": "ok",
  "message": "Factory reset. Restart the process to complete."
}
```

```bash
curl -s -X POST "http://$DEV/api/factory-reset" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF" \
     -d "confirm=ERASE"
```

---

### `GET /api/ota/status`
Read-only OTA introspection — which partition is running/booting/staged next, and whether the currently running image is still pending its post-update validation. No secrets, so it is reachable pre-auth like `/api/status`.

* **Request Headers**: None
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`
* **Response Payload JSON Example**:
```json
{
  "running": "ota_0",
  "boot": "ota_0",
  "next": "ota_1",
  "pendingVerify": false,
  "otaSupported": true,
  "error": ""
}
```

#### Field Schema Definitions

| Field Name | Type | Description |
| :--- | :---: | :--- |
| `running` | String | Partition label of the image currently executing. |
| `boot` | String | Partition label the bootloader will boot next. |
| `next` | String | Partition label a new OTA upload would target. |
| `pendingVerify` | Boolean | `true` if the running image has not yet called `markValid()` (anti-rollback window; see `docs/OTA.md`). |
| `otaSupported` | Boolean | Tracks `ESP_PLATFORM`, so it is `true` on **every** ESP transport including the Ethernet builds, and `false` only on the host/desktop build. It does **not** track `POCKETDIAL_HAS_WIFI` — a board reporting `otaSupported:true` may still have every `/api/wifi/*` route stubbed (§4.2). |
| `error` | String | Reserved for a future error surface; currently the literal `""` on every response (`HttpServer.cpp:2623`). Do not branch on it. |

```bash
curl -s "http://$DEV/api/ota/status"
```

Covered by `test_api.sh` TC-OTA-01 (reachable ungated, schema present).

---

### `POST /api/ota/upload`
Streams a firmware image body directly into the inactive OTA slot. **Not routed through the normal 16 KB-buffered body path** — a firmware image is multi-megabyte, so `handleClient()` detects this path on the request line and hands off to a streaming reader before the usual `Content-Length` cap is applied. **ESP-only.**

* **Requires Same-Origin Check**: Yes
* **Requires `pd_session` cookie**: Always (see §0)
* **Request Content-Type**: raw firmware binary (no particular `Content-Type` is enforced)
* **Request Headers**:
  * `Content-Length` (Required): Non-zero. Parsed without the normal 16 KB cap, clamped to a 32 MB ceiling (larger than any 16 MB flash layout the firmware supports) to bound the work the server will do for a malformed value.
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK` (ESP32): Image staged into the inactive slot; reboot required to run it.
  * `400 Bad Request`: Body was incomplete or a flash write failed mid-stream.
  * `401 Unauthorized` / `403 Forbidden`: as above.
  * `411 Length Required`: `Content-Length` missing or `0`.
  * `422 Unprocessable Entity`: The image was fully received but failed validation (e.g. bad magic byte / signature).
  * `500 Internal Server Error`: OTA slot could not be opened, or activation failed after a valid image was written.
  * `501 Not Implemented` (desktop only — `ESP_PLATFORM`, not `POCKETDIAL_HAS_WIFI`, so this route is real on `eth`/`lan8720`): `{"error":"OTA only available on device"}`. The body is still drained so the client's upload completes cleanly rather than being reset mid-stream. The host build deliberately does **not** simulate success, so CI cannot mistake it for a real update.

> [!IMPORTANT]
> **This route is dispatched before the normal route table**, by a string probe on the
> request line inside `handleClient()` (`HttpServer.cpp:300-353`), which is why it is
> absent from the `if`/`else` chain. Two consequences: the whole header block must
> arrive in the **first `recv()`** (4 KB — true of any real client, since only the body
> is large), and the auth gate is applied to a request parsed from the header block
> alone. It is the full `requireAdmin(…, needCsrf = true)` gate — flashing firmware is
> the most consequential thing this server does.

#### Response Example (200 OK, ESP32)
```json
{
  "status": "ok",
  "bytes": 1548032,
  "rebootRequired": true,
  "nextPartition": "ota_1",
  "message": "image staged; POST /api/ota/reboot to boot it"
}
```

```bash
curl -s -X POST "http://$DEV/api/ota/upload" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF" \
     --data-binary @build/pocket-dial.bin
```

`--data-binary @file` (not `-d @file`) — `-d` strips newlines and would corrupt the
image. `curl` sets `Content-Length` from the file size, which is what the streaming
reader needs; there is no chunked-transfer fallback (§1).

Covered by `test_api.sh` TC-OTA-02 (cross-origin → `403`), TC-OTA-03 (a 32 KB body
streams past the 16 KB buffered cap — a `413` there would mean the streaming bypass
regressed) and TC-OTA-04 (`Content-Length: 0` → `411`).

---

### `POST /api/ota/reboot`
Reboots into the image staged by a prior `/api/ota/upload`. **ESP32**: refuses if there is no pending image (the boot and running partitions already match). **Desktop**: always returns a simulated success without exiting the process, so the smoke-test harness keeps running.

* **Requires Same-Origin Check**: Yes
* **Requires `pd_session` cookie**: Always (see §0)
* **Build**: `ESP_PLATFORM`-guarded, so it is real on `eth`/`lan8720` and simulated only on the host build — see §4.2.
* **Request Headers**: None. **No request parameters and no confirmation token** — unlike `/api/factory-reset`, an empty authenticated POST reboots the device. The `409` guard below is the only thing standing between a stray POST and a reboot.
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`: Reboot scheduled ~1 s out (ESP) or simulated (desktop).
  * `401`/`403`: gates 1-4 as in §0.1.
  * `409 Conflict` (ESP): `{"error":"no pending OTA image to boot into"}` — the boot partition already equals the running one, i.e. nothing was staged.

#### Response Example (200 OK, ESP32)
```json
{
  "status": "ok",
  "message": "rebooting into the new image..."
}
```

#### Response Example (200 OK, desktop)
```json
{
  "status": "ok",
  "simulated": true,
  "message": "reboot is a no-op on the desktop build"
}
```

The `"simulated":true` key is present **only** on the desktop response; a real ESP
reboot response omits it entirely. That is the one reliable way to tell the two apart.

```bash
curl -s -X POST "http://$DEV/api/ota/reboot" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF"
```

Covered by `test_api.sh` TC-OTA-05 (cross-origin → `403`), TC-OTA-06 (`200` or `409`
same-origin) and TC-OTA-07 (the desktop stub must not exit the process).

---

### `GET /setup/email`

Issue #159 (Phase 1). Serves the standalone SMTP-configuration page (own top-level
document, **not** part of the `/` dashboard SPA — see `index_html.h`'s `PD_HTML_8`).
The shell alone discloses nothing; every field it renders is fetched client-side from
`GET /api/email` below, which IS gated. Same ungated-shell class as `GET /` itself
(§4 E-2 in `docs/THREAT_MODEL.md`).

* **Auth**: None — ungated, deliberately (see above).
* **Response Status Codes**: `200 OK` always.

### `GET /api/email`

Current SMTP configuration, **with both secrets redacted to a boolean**: `hasPassword`
and `hasGsaKey` report whether a value is stored, never the value itself. This is the
same discipline `TelephonyApiConfig`'s `view()`/`secretSet` uses, for the same reason —
issue #207's class of bug (an unauthenticated OR merely-authenticated read handing back a
credential nothing legitimately needs to display) has bitten this project twice already
(`/api/cdr`, the extension roster in `/api/status`).

```json
{
  "host": "smtp.gmail.com",
  "port": 465,
  "mode": "tls",
  "auth": "plain",
  "user": "bot@example.com",
  "from": "bot@example.com",
  "to": "ops@example.com",
  "gsaEmail": "",
  "hasPassword": true,
  "hasGsaKey": false,
  "insecure": false,
  "hasCaPem": false
}
```

* `mode` — `tls` (implicit, port 465 by default) \| `starttls` (port 587 by default) \|
  `plain` (port 25, **LAN-relay only** — see `insecure` below and
  `docs/THREAT_MODEL.md`).
* `auth` — `none` \| `plain` \| `login` \| `xoauth2-sa` (Google Workspace service-account
  domain-wide delegation — `gsaEmail`/the stored `gsaKey` are used, `user`/`pass` are not).
* `insecure` — skips TLS certificate verification entirely (`MBEDTLS_SSL_VERIFY_NONE` —
  see `sdkconfig.defaults`'s `CONFIG_ESP_TLS_SKIP_SERVER_CERT_VERIFY` comment). Defaults
  `false`. **Never enable this against a real mail provider** — it exists for a LAN relay
  with a self-signed or absent certificate only.
* **Auth**: Gated read — same-origin, session and completed setup, **no** `X-CSRF` (same
  class as `/api/syslog`, `/api/registrar`: infrastructure detail, not public dashboard
  data).
* **Response Status Codes**: `200 OK` always (an unconfigured device reports every field
  at its zero value); `401`/`403` as in §0.1.

```bash
curl -s "http://$DEV/api/email" -b "pd_session=$SESSION"
```

### `POST /api/email`

| Param | Values | Effect |
| :--- | :--- | :--- |
| `host` | hostname | SMTP server. |
| `port` | `1`-`65535` | Optional — defaults by `mode` (465/587/25) when omitted or empty. |
| `mode` | `tls` \| `starttls` \| `plain` | Optional, keeps the stored value if omitted; `400` if present and not one of the three. |
| `auth` | `none` \| `plain` \| `login` \| `xoauth2-sa` | Optional, keeps the stored value if omitted; `400` if present and not one of the four. |
| `user` | string | `AUTH PLAIN`/`AUTH LOGIN` username. |
| `pass` | string | `AUTH PLAIN`/`AUTH LOGIN` secret. **Submitted empty means "keep the stored password"** — this endpoint never re-displays a real secret for the client to diff against, so there is no other way to express "unchanged" (mirrors `PUT /api/telephony-config/<slot>`'s `secret` field). Explicitly *clearing* a stored secret (as opposed to replacing it with a new one) is not supported in Phase 1 — use a factory reset. |
| `from` | address | Envelope/header `From:`. |
| `to` | address(es) | Default recipient(s) for a test send with no explicit `to`; comma-separated for multiple. |
| `gsaEmail` | address | Service-account email (domain-wide delegation `iss`). |
| `gsaKey` | PEM | Service-account private key. **Same "empty = keep stored" rule as `pass`.** Stored as an NVS *blob* (not `nvs_set_str`) — a real RSA key PEM can exceed the ~4000 byte `nvs_set_str` cap. |
| `caPem` | PEM | Optional custom server CA. Empty = use the built-in `esp_crt_bundle`. Same "empty = keep stored" rule, and also stored as a blob. |

`gsaKey`/`caPem` are large-ish PEM text and go through `POST`'s ordinary **16 KB whole-body
cap** (§1's payload limit) like every other field on this route — there is no streaming
exception here the way OTA/MOH upload get one. A 2048-bit RSA key PEM percent-encoded is
comfortably under that; a very large custom CA chain submitted alongside a large key in the
same request could approach it. Submit them in separate saves if that ever matters.
| `insecure` | `1`/`on` \| absent | Skip TLS certificate verification. See the `GET`'s field description. Absent/anything else = `false`. |

Responds with the same redacted shape as the `GET` (`config` key).

* **Request Content-Type**: `application/x-www-form-urlencoded`
* **Response Status Codes**:
  * `200 OK`: `{"status":"ok","config":{...}}`.
  * `400 Bad Request`: invalid `mode`/`auth`/`port`.
  * `401`/`403`: gates 1-4 as in §0.1.
  * `500 Internal Server Error`: NVS persistence failed (ESP only).

```bash
# Gmail App Password preset, filled by the /setup/email page's dropdown
curl -s -X POST "http://$DEV/api/email" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF" \
     --data-urlencode "host=smtp.gmail.com" --data-urlencode "port=465" \
     --data-urlencode "mode=tls" --data-urlencode "auth=plain" \
     --data-urlencode "user=you@gmail.com" --data-urlencode "pass=xxxxxxxxxxxxxxxx" \
     --data-urlencode "from=you@gmail.com" --data-urlencode "to=ops@example.com"
```

### `POST /api/email/test`

Sends a real test message through the SMTP client and reports the structured result
inline — this **is** the "Send test message" button and the dashboard terminal's
`email test <addr>` command; there is no separate code path for either. Runs through
`SmtpClient::sendAndWait()`, i.e. the same bounded single-worker send queue a future
voicemail-to-email consumer would use — never more than one send in flight, and never on
a SIP thread (the HTTP per-connection thread blocks here, up to ~20 s, which costs that
thread alone).

| Param | Values | Effect |
| :--- | :--- | :--- |
| `to` | address(es) | Optional — falls back to the stored default `to` if omitted. |

```json
{ "ok": true, "resultCode": 0, "smtpReplyCode": 250, "error": "" }
```

* `resultCode` — `SmtpDialogue::ResultCode` as an integer (`0` = `Ok`); see
  `src/Helpers/SmtpDialogue.hpp` for the full enum. Present on both success and failure so
  the dashboard/terminal can show *which step* failed (`GreetingRejected`,
  `AuthRejected`, `RcptToRejected`, `Timeout`, ...), not just "failed".
  `1` = `InvalidConfig`, `2` = `ConnectFailed`, `3` = `TlsFailed`, `4` = `GreetingRejected`,
  `5` = `EhloRejected`, `6` = `AuthNotSupported`, `7` = `AuthRejected`,
  `8` = `MailFromRejected`, `9` = `RcptToRejected`, `10` = `DataRejected`,
  `11` = `MessageRejected`, `12` = `Timeout`, `13` = `TransportError`.
* `smtpReplyCode` — the server's last numeric SMTP reply, `0` if none was ever received.
* `error` — human-readable detail: the server's own text where there was a reply, or a
  local reason (e.g. "server did not advertise STARTTLS") where there wasn't.
* **Always responds `200`** with `ok:false` on failure (no host configured, no recipient,
  connect/auth/relay failure, timeout, ...) — a failed test send is an expected, common
  outcome to report inline, not a server error. `500`/`503` are not used here.
* **Request Content-Type**: `application/x-www-form-urlencoded`
* **Response Status Codes**:
  * `200 OK`: Always (see above); `ok` in the body is the real result.
  * `401`/`403`: gates 1-4 as in §0.1.

```bash
curl -s -X POST "http://$DEV/api/email/test" \
     -b "pd_session=$SESSION" -H "X-CSRF: $CSRF" \
     --data-urlencode "to=you@example.com"
```

**Bench-unverified** (host-testable subset only — see `tests/SmtpDialogue_test.cpp`,
`tests/GoogleServiceAuth_test.cpp`, `tests/EmailHttp_test.cpp`): real delivery via Gmail
App Password, Workspace service-account XOAUTH2, and the `insecure`/custom-CA paths have
not been exercised against a real mail provider or a real device. See the issue #159 PR
for the full list.

---

## 5. What this API does not have

Stated explicitly, because each of these has cost someone time:

* **No JSON request bodies.** Every parameter on every route — `POST`, `PUT` and
  `DELETE` alike — is `application/x-www-form-urlencoded`, read by `getFormParam()`.
  A JSON body is not rejected; it is simply parsed as zero parameters.
* **No `405 Method Not Allowed`, no `Allow` header, no `OPTIONS` handler.** A wrong
  method is a plain-text `404` (§1). CORS preflight cannot succeed, which is
  intentional — there are no CORS headers either.
* **No pagination, filtering or `?query` parameters anywhere.** `parseRequest()` strips
  the query string before routing (`HttpServer.cpp:731`), so `?since=…` on `/api/trace`
  or `/api/cdr` is silently discarded rather than honoured. Every list route returns
  its whole bounded table every time.
* **No `GET` counterpart for DND, call-forward, ring groups, the dial plan or park
  orbits.** [`GET /api/status`](#get-apistatus) is the read path for all of them.
* **No HTTPS, no `Strict-Transport-Security`, no `Secure` cookie flag.** Plain HTTP on
  a LAN appliance by design — see `docs/THREAT_MODEL.md`.
* **No API versioning and no server-side version field.** Nothing in any response
  identifies the firmware build or transport; `/api/ota/status`'s partition labels are
  the closest thing available.

Related documents: `docs/API_TESTS.md` (the test-by-test walkthrough of
`tests/http/test_api.sh`), `docs/THREAT_MODEL.md` (why the gates are shaped this way),
`docs/OTA.md`, `docs/LEARN_MODE.md`, `docs/PROVISIONING.md`.
