# Pocket-Dial Firmware: Systematic HTTP API Test Plan

This document defines the systematic test suite and validation plan for the HTTP REST API of the **pocket-dial ESP32 firmware**.

This plan ensures that all management endpoints function correctly under standard workloads, handle malformed parameters safely, validate boundaries, reject malicious cross-origin requests, and refuse mutations that cannot prove they came from the device's own dashboard.

> Source of truth for every route and every gate: [`API.md`](API.md) and
> `src/Helpers/HttpServer.cpp` (`handleClient()` dispatch, `requireAdmin()`).
> Where this plan and the code disagree, the code is right — fix the plan.

> [!WARNING]
> **STALE as of 2026-09-13.** This plan's §0 and its PIN-provisioning test cases
> describe two mechanisms that no longer exist: the "dark by default, DTMF `*4887`
> reopens it" HTTP transport gate, and the bare-PIN admin credential (`/api/admin/set-pin`,
> `pin=` form param). The HTTP listener is now always open, and the admin credential is a
> username + password with a shipped default (`admin`/`admin`) via `/api/admin/set-credential`
> — see [`API.md`](API.md) §0 for the current model. `tests/http/test_api.sh` has been
> updated to match (its own header comment documents the new suite ordering); this plan
> document has not yet had the equivalent full revision pass.

---

## 🚦 0. Before You Test Anything: Provisioned vs Unprovisioned

Almost every surprise in this suite comes from one distinction, so establish it first.

| | **Unprovisioned** (no admin PIN set) | **Provisioned** (admin PIN set) |
|---|---|---|
| TCP listener | Always listening | **Dark** except inside a bounded open window |
| `pd_session` cookie | Not required | Required on every gated endpoint |
| `X-CSRF` header | Not required | Required on every **mutating** gated endpoint |
| A plain `curl` with no headers | Works | `401`, then `403` once you add the cookie |

### 0.1 The listener is dark by default once a PIN exists

Once an admin PIN is provisioned the TCP listener itself is closed except within a
bounded open window (default 600 s), granted by a DTMF `*4887` from the registered admin
extension, by a successful `POST /api/admin/set-pin`, or extended by
`POST /api/admin/keepalive`. See [API.md §0](API.md#0-reachability--admin-session-layer-read-this-first).

> [!IMPORTANT]
> A tester who sets a PIN and then gets **connection refused** on port 80 is looking at
> the dark gate working correctly, not at a bug. Open a window before running any
> provisioned-device test case below.

### 0.2 What this meant for `tests/http/test_api.sh`

The smoke suite runs its Admin Auth block **last**, on purpose: that block is what sets a
PIN, and setting a PIN flips every mutating endpoint from "open" to "session + token
required". Everything before it runs against an unprovisioned target, where no session
exists and therefore no CSRF token is demanded. That ordering is load-bearing — the
comment block at the top of `test_api.sh` says so, and reordering the suites breaks it.

**That is true of most of the file, but not all of it, and the difference cost a red CI
run.** `TC-AUTH-07` deliberately provisions first and then POSTed `/api/kill` with only
the `pd_session` cookie, so it started returning `403
{"error":"missing or invalid CSRF token"}`. The suite (now **30 tests**) was corrected:
login captures the response *body* as well as the headers and extracts the `csrf` field —
`curl -i` with a blank-line split rather than `-D` to a temp file, so there is nothing to
clean up and it keeps working under a curl whose filesystem view differs from the shell's
— and `TC-AUTH-07` became two cases:

* **07a** — cookie **alone** is refused with `403`. This is the case worth having: it is
  the entire point of the token, given that the same-origin check deliberately admits
  requests with no `Origin` header.
* **07b** — cookie **plus** `X-CSRF` succeeds with `200`.

The rule that generalises: **any recipe that provisions first must capture the token from
the login response and send it.** §2 shows how; the smoke suite and
[OTA.md §3.2](OTA.md) use the same `sed` extraction.

---

## 🔒 1. The Three-Layer Gate (Same-Origin → Session → CSRF)

Every gated route funnels through one function, `HttpServer::requireAdmin(sock, req, needCsrf)`.
It applies three checks **in this order**, and the first one to fail is the response you get:

```
                              [Incoming HTTP Request]
                                        │
                    ┌───────────────────▼───────────────────┐
                    │ 1. Same-origin                        │
                    │    Origin absent  -> allow (curl, CI) │
                    │    Origin host == Host header -> allow│
                    └───────────────────┬───────────────────┘
                              fail ──> 403 {"error":"cross-origin request rejected"}
                                        │
                    ┌───────────────────▼───────────────────┐
                    │ 2. Session (skipped if unprovisioned) │
                    │    valid pd_session cookie?           │
                    └───────────────────┬───────────────────┘
                              fail ──> 401 {"error":"authentication required"}
                                        │
                    ┌───────────────────▼───────────────────┐
                    │ 3. CSRF (mutating requests only, and  │
                    │    only once a session exists)        │
                    │    X-CSRF matches the session token?  │
                    └───────────────────┬───────────────────┘
                              fail ──> 403 {"error":"missing or invalid CSRF token"}
                                        │
                                    [Handler runs]
```

> [!WARNING]
> **There are now two different `403` responses.** Asserting on the status code alone can
> no longer tell a cross-origin rejection from a CSRF rejection, and a test that only
> checks `403` will pass for the wrong reason. **Assert on the JSON body.**

### 1.1 Why the Origin check is not enough on its own

The same-origin check deliberately **allows** a request with no `Origin` header, because
that is what `curl`, native clients, and this repository's own smoke suite send. That
gap — a same-site page riding the victim's cookie — is closed on a provisioned device by
a per-session CSRF token:

* A 128-bit token is minted with the session at login.
* It is returned in the login response body as `"csrf"` and rendered into the dashboard
  document. It is **never** a cookie — a browser would attach a cookie to a cross-site
  request on its own, so only a value our own page had to read and echo back proves
  where the request came from.
* Checked centrally in `requireAdmin()`, so no route can forget it.

### 1.2 Safe-origin matrix (unchanged behaviour, layer 1 only)

1. **Direct request (`curl`, address-bar navigation):** no `Origin` header. **Allow.**
2. **Same-origin request (the dashboard):** `Origin: http://192.168.4.1` matches
   `Host: 192.168.4.1`. **Allow.**
3. **Cross-origin request:** `Origin: http://malicious.com` vs `Host: 192.168.4.1`.
   **Reject `403`**, `{"error":"cross-origin request rejected"}`.

> [!WARNING]
> `Access-Control-Allow-Origin` (CORS) headers are intentionally omitted. Wildcard CORS
> would bypass CSRF safety bounds.

### 1.3 CSRF exemptions, and why

| Endpoint / state | Why no token |
|---|---|
| `POST /api/admin/login` | No session exists yet, so there is nothing to bind a token to. |
| `POST /api/admin/logout` | A forced logout is a nuisance, not a compromise; `SameSite=Strict` already blocks it, and requiring a token would strand a user on a stale page. |
| Any request while **unprovisioned** | A factory-fresh device has no session. Demanding a token would make the device unclaimable and break captive-portal onboarding. |
| All `GET` endpoints | Reads are not state changes. They are still same-origin checked and, where sensitive, session-gated. |

---

## 🔑 2. The Login Preamble Every Provisioned-Device Test Needs

Capture the cookie **and** the token in one step. This is the same pattern
[OTA.md §3.2](OTA.md) uses; keep the two in step.

```bash
DEVICE=http://192.168.4.1          # or http://pocketdial.local
JAR=cookies.txt

# Log in: the cookie proves who you are, the token proves the request came from
# something that was told the token rather than from a page riding your cookie.
LOGIN=$(curl -s -c "$JAR" \
     -H "Origin: $DEVICE" \
     -X POST --data "pin=YOUR_PIN" \
     "$DEVICE/api/admin/login")
# -> {"status":"ok","authenticated":true,"csrf":"3f2a...e91c"}

CSRF=$(printf '%s' "$LOGIN" | sed -n 's/.*"csrf":"\([0-9a-f]*\)".*/\1/p')
[ -n "$CSRF" ] || { echo "login failed: $LOGIN" >&2; exit 1; }
```

Every mutating request below then carries three things — the cookie, the `Origin`, and
the token:

```bash
curl -s -b "$JAR" \
     -H "Origin: $DEVICE" \
     -H "X-CSRF: $CSRF" \
     -X POST --data "extension=101" \
     "$DEVICE/api/kill"
```

Drop the `-H "X-CSRF: $CSRF"` and you get:

```json
{"error":"missing or invalid CSRF token"}
```

with status `403`. That is the single most common failure when running a pre-existing
script against current firmware.

> [!NOTE]
> `POST /api/admin/login` on a device with **no PIN set** returns `409 Conflict`
> `{"error":"no admin PIN set; call /api/admin/set-pin first"}` — not `401`.

---

## 📡 3. Endpoint Specifications & JSON Schemas

### 3.1 GET `/` or `/index.html`
Serves the CGA CRT web dashboard. On a provisioned device the page also carries the
session's CSRF token, which is how the dashboard's own `fetch()` calls satisfy layer 3.
* **Request:** `GET /`
* **Response:** `200 OK`
* **Content-Type:** `text/html; charset=utf-8`

### 3.2 GET `/api/status`
Fetches a read-only snapshot of the registrar, call sessions, and system metrics. Ungated.
* **Request:** `GET /api/status`
* **Response:** `200 OK`, `application/json`
* **Schema:**
  ```json
  {
    "ip": "192.168.4.1",
    "port": 5060,
    "httpPort": 80,
    "uptime": 345,
    "packetsProcessed": 104,
    "packetsDropped": 0,
    "clients": [
      { "number": "101", "address": "192.168.4.20:5061" }
    ],
    "sessions": [
      { "caller": "101", "callee": "102", "state": "Connected", "duration": "02:15" }
    ]
  }
  ```

### 3.3 POST `/api/kill`
Administratively disconnects a registered extension and terminates its calls.
* **Request:** `POST /api/kill`
* **Content-Type:** `application/x-www-form-urlencoded`
* **Parameters:** `extension=XXXX` (e.g. `extension=101`)
* **Headers (provisioned):** `Cookie: pd_session=…` **and** `X-CSRF: <token>`
* **Response (Success):** `200 OK`
  ```json
  {"status":"ok","disconnected":"101"}
  ```
* **Response (Missing parameter):** `400 Bad Request`
  ```json
  {"error":"missing extension parameter"}
  ```
* **Response (No session, provisioned):** `401 Unauthorized`
  ```json
  {"error":"authentication required"}
  ```
* **Response (Session but no/wrong token):** `403 Forbidden`
  ```json
  {"error":"missing or invalid CSRF token"}
  ```
* **Response (Cross-origin):** `403 Forbidden`
  ```json
  {"error":"cross-origin request rejected"}
  ```

### 3.4 GET `/api/wifi/scan`
Triggers an active Wi-Fi channel scan and returns visible networks. Ungated.
* **Response (ESP32):** `200 OK`
  ```json
  {
    "networks": [
      { "ssid": "Office_WiFi", "rssi": -65, "encryption": "WPA2" },
      { "ssid": "Guest_AP",    "rssi": -80, "encryption": "OPEN" }
    ]
  }
  ```
* **Response (Desktop):** `200 OK`
  ```json
  {"networks":[], "note":"WiFi scan not available on desktop"}
  ```

### 3.5 POST `/api/wifi/connect`
Configures network credentials, saves them to NVS, and restarts in Station mode.
* **Content-Type:** `application/x-www-form-urlencoded`
* **Parameters:** `ssid=SSID_NAME&password=WIFI_PASSWORD`
* **Headers (provisioned):** cookie **and** `X-CSRF`
* **Response (ESP32):** `200 OK`
  ```json
  {"status":"ok","message":"WiFi credentials saved. Rebooting to Station Mode..."}
  ```
* **Response (Missing SSID):** `400 Bad Request` `{"error":"missing ssid parameter"}`
* **Response (Desktop):** `501 Not Implemented` `{"error":"WiFi connect not available on desktop"}`

### 3.6 POST `/api/wifi/mode_ap`
Sets operational mode back to Standalone AP and reboots. Cookie **and** `X-CSRF` when provisioned.
* **Response (ESP32):** `200 OK`
  ```json
  {"status":"ok","message":"Operational mode set to Standalone AP. Rebooting..."}
  ```
* **Response (Desktop):** `501 Not Implemented` `{"error":"WiFi mode select not available on desktop"}`

### 3.7 POST `/api/configuring`
Pauses the captive-portal auto-switch-to-Standalone decay while a user is mid-setup.

**This route previously had no gate at all.** It now takes the standard `requireAdmin()`
gate with `needCsrf = true`, like every other mutating route. Because the captive portal
only ever calls it while the device is unprovisioned — where the session and token checks
are skipped — onboarding behaviour is unchanged; what changed is that it can no longer be
poked by a third party on a provisioned device.

### 3.8 GET `/api/pcap`, `/api/diagnostics/pcap`, `/api/trace`
Diagnostic capture ring: the first two as a Wireshark-readable `.pcap`, the third as JSON
for the dashboard's live tracer. All three are `GET`, so they take same-origin **plus a
session once provisioned**, and no CSRF token.

**These three previously had no same-origin check** — before `e631fc2` `/api/pcap` called
`isAuthed()` directly and never consulted the `Origin` header. They now go through `requireAdmin()`
like everything else, which is worth an explicit regression case (TC-SEC-06 below): a
capture ring is signalling metadata — who called whom, from which address — and was
readable by any page that could reach the device.

### 3.9 GET `/api/ap-security`
Reports the SoftAP security setting and its passphrase. Gated (session once provisioned).

```json
{ "secure": false, "psk": "DD9T4GZKQ4AHY5KGRZP8" }
```

* `secure` — `true` when the standalone SoftAP comes up `WIFI_AUTH_WPA2_PSK`. **Defaults
  to `false`**; the shipped posture is still an open AP. Enabling WPA2 forces every
  associated phone to be re-paired, so it is an explicit operator action.
* `psk` — generated from the hardware CSPRNG on first access and stored in NVS. 20
  characters from an alphabet with no ambiguous glyphs (no `0`/`O`, `1`/`I`/`L`, `U`).

Returning the passphrase in clear to an authenticated admin is deliberate: on the
headless `eth`/`wifi` builds this response is one of the few ways to learn it.

### 3.10 POST `/api/ap-security`
Form-encoded; all parameters optional, omitted ones unchanged. Cookie **and** `X-CSRF`.

| Param | Values | Effect |
|---|---|---|
| `secure` | `1`/`true`/`0`/`false` | Enable or disable WPA2 on the standalone SoftAP. |
| `psk` | 8–63 printable ASCII | Set the passphrase explicitly. `400` if out of range, leaving the stored value untouched. |
| `regenerate` | `1`/`true` | Replace the passphrase with a freshly generated one. |

Responds with the same body as the `GET`. **The radio is not restarted** — doing so would
drop the client that just made the request, losing the response and the passphrase it
still has to display, and would tear down live calls. The change lands at the next AP
bringup, so a test must reboot (or re-bring-up the AP) before asserting on the radio.

### 3.11 GET `/api/registrar`
Reports the SIP registrar admission mode and the adopted-extension roster. Gated.

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

* `attached` — `false` when the SIP engine has not been bound to the dashboard yet (an
  unprovisioned device holds SIP dark until a credential exists). **A normal transient
  state, not a failure**; `mode` reads `"unknown"` and `devices` is empty. A test that
  asserts `mode == "open"` on a fresh boot will flake against this — assert on
  `attached` first.
* `mode` — `open`, `learn` or `secure`.
* `state` — `learned` (adopted on first contact, not yet enforced) or `secured`
  (MAC-locked and digest-enforced for its extension).
* `online` — volatile registration state; never persisted.

### 3.12 POST `/api/registrar`
Sets the admission mode. Cookie **and** `X-CSRF`.

| Param | Values | Effect |
|---|---|---|
| `mode` | `open` \| `learn` \| `secure` | Required. |
| `confirm` | `LOCKOUT` | Only consulted when switching to `secure`. |

`open` is the shipped default: every `REGISTER` is accepted with no credential.
`learn` is trust-on-first-use and a deliberate, **temporary** weakening for adopting an
existing fleet. `secure` digest-challenges every `REGISTER`.

Switching to `secure` while **no** extension is yet `secured` is refused with `409`:

```json
{ "error": "no extensions are secured yet; switching to secure now would reject every phone. Adopt them in learn mode first, or resend with confirm=LOCKOUT to override." }
```

Resend with `confirm=LOCKOUT` to override — the same shape as `/api/factory-reset`'s
`confirm=ERASE`. Responds with the same body as the `GET`.

### 3.13 POST `/api/registrar/device`
Secures or forgets one adopted device. Cookie **and** `X-CSRF`.

| Param | Values | Effect |
|---|---|---|
| `action` | `secure` \| `forget` | Required. |
| `target` | 12-hex MAC, or an extension | Required. An extension resolves to the device currently bound to it. |

`secure` promotes a `learned` device to `secured`. `forget` drops the adoption record —
in `learn` mode the phone is re-adopted on its next registration, which is how you re-home
an extension to different hardware. `404` if no adopted device matches. Responds with the
same body as the `GET`.

> The MAC lock is **not** a cryptographic boundary — it is learned from the ARP table, and
> ARP/MAC are spoofable on a hostile L2. Test it as defence in depth, not as authentication.

---

## 🧾 4. Security Response Headers (assert on every response)

`HttpServer::sendResponseWithHeader` emits these centrally, so a single missing header is
a global regression and is cheap to assert once per suite. The one response that does not
go through it is the captive-portal `302` from `sendRedirect()`, which writes a bare
redirect to the socket — do not assert the headers on that path:

| Header | Value |
|---|---|
| `Content-Security-Policy` | `default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'` |
| `X-Frame-Options` | `DENY` |
| `X-Content-Type-Options` | `nosniff` |
| `Cache-Control` | `no-store` |
| `Referrer-Policy` | `same-origin` |

```bash
curl -sD - -o /dev/null "$DEVICE/api/status" | grep -iE \
  'content-security-policy|x-frame-options|x-content-type-options|cache-control|referrer-policy'
```

There is deliberately **no** `Strict-Transport-Security`, and asserting its absence is
worth a case: the dashboard is plain HTTP on a LAN appliance, and pinning HSTS would make
the device permanently unreachable over `http://` with no way for a user to override it.

---

## 🧪 5. Systematic Test Matrix

Execute the following against a running device. Cases marked **(P)** require a
provisioned device with an open admin window and the §2 login preamble already run.

### Happy Path Tests
* **TC-HP-01 (Get Dashboard):** GET `/` → `200 OK`, HTML matching `CGA_INDEX_HTML`.
* **TC-HP-02 (Get System Status):** GET `/api/status` → `200 OK` and a valid JSON map of
  system metrics, pre-allocated client snapshots, and active sessions.
* **TC-HP-03 (Kill Active Extension) (P):** POST `/api/kill` with `extension=101`, cookie
  and `X-CSRF` → `200 OK`, `{"status":"ok","disconnected":"101"}`. Sessions involving
  `101` are immediately swept.
* **TC-HP-04 (Scan WiFi):** GET `/api/wifi/scan` → switches to `APSTA`, then `200 OK`
  with SSIDs, RSSI values, and encryption metrics.

### Edge Case & Boundary Validation Tests
* **TC-ED-01 (Payload Too Large):** POST a body larger than 16 KB (16,384 bytes) to
  `/api/wifi/connect` → `413 Payload Too Large`,
  `{"error":"request body exceeds 16 KB limit"}`, connection closes. Note
  `/api/ota/upload` is **exempt** — it is streamed, not buffered, so a multi-MB image
  must not return `413`.
* **TC-ED-02 (Missing Kill Parameter) (P):** POST `/api/kill` with an empty body, cookie
  and valid token → `400 Bad Request`, `{"error":"missing extension parameter"}`.
  The `400` proves the gate was passed *before* validation — order matters.
* **TC-ED-03 (Missing Connect Parameters) (P):** POST `/api/wifi/connect` with
  `password=12345678` → `400 Bad Request`, `{"error":"missing ssid parameter"}`.
* **TC-ED-04 (URL-Encoded Values Parsing) (P):** POST `/api/wifi/connect` with
  `ssid=Office+AP%21&password=pass`. Verify the stored credential decodes to `Office AP!`.
* **TC-ED-05 (AP passphrase bounds) (P):** POST `/api/ap-security` with a 7-character
  `psk` → `400`, and a follow-up `GET /api/ap-security` still returns the **previous**
  passphrase. A rejected write must not clear the stored value.
* **TC-ED-06 (Registrar lockout guard) (P):** With no extension in state `secured`, POST
  `/api/registrar` with `mode=secure` → `409` and the quoted body above. Repeat with
  `mode=secure&confirm=LOCKOUT` → `200` and `"mode":"secure"`. **Restore `mode=open`
  afterwards** or every later SIP case in the run is digest-challenged.
* **TC-ED-07 (Registrar unknown device) (P):** POST `/api/registrar/device` with
  `action=secure&target=ffffffffffff` → `404`.

### Same-Origin Tests (gate layer 1)
* **TC-SEC-01 (Direct Request — No Origin Header):** POST `/api/kill` via `curl` with no
  `Origin`. **Unprovisioned:** `200 OK`. **Provisioned:** `401` without a cookie — the
  missing `Origin` is still allowed, it is the session that stops you.
* **TC-SEC-02 (Same-Origin Request) (P):** POST `/api/kill` with `Host: 192.168.4.1`,
  `Origin: http://192.168.4.1`, cookie and token → `200 OK`.
* **TC-SEC-03 (Cross-Origin Block):** POST `/api/kill` with `Host: 192.168.4.1` and
  `Origin: http://malicious-website.com` → `403 Forbidden`,
  `{"error":"cross-origin request rejected"}`. Assert the **body** — see TC-SEC-05.

### Session & CSRF Tests (gate layers 2 and 3) — provisioned only
* **TC-SEC-04 (No session):** POST `/api/kill` on a provisioned device with no cookie →
  `401 Unauthorized`, `{"error":"authentication required"}`.
* **TC-SEC-05 (Cookie without token):** POST `/api/kill` with a valid `pd_session` cookie
  but **no** `X-CSRF` header → `403 Forbidden`,
  `{"error":"missing or invalid CSRF token"}`. Repeat with a token that is valid-looking
  but belongs to no session — same result. This case and TC-SEC-03 both return `403`;
  the assertion **must** be on the JSON body.
* **TC-SEC-06 (Diagnostics are gated):** GET `/api/pcap`, `/api/diagnostics/pcap` and
  `/api/trace` on a provisioned device with no cookie → `401` on all three. Then with a
  cookie and **no** token → `200` on all three, because they are `GET`s and take no CSRF
  token. Regression case for the previously-missing gate.
* **TC-SEC-07 (`/api/configuring` is gated):** POST `/api/configuring` on a provisioned
  device with no cookie → `401`; with a cookie but no `X-CSRF` → `403` (it is a mutating
  route, `needCsrf = true`). On an **unprovisioned** device → success with no headers at
  all, so the captive-portal flow is unaffected.
* **TC-SEC-08 (Logout needs no token):** POST `/api/admin/logout` with only the cookie →
  succeeds. A subsequent `/api/kill` with the same cookie → `401`.
* **TC-SEC-09 (Headers present):** Assert the five headers of §4 on at least one `GET`,
  one `POST` success, and one error response, and assert `Strict-Transport-Security` is
  **absent**.

### Login Rate-Limiting Tests
* **TC-RL-01 (Per-client lockout):** From one client, POST `/api/admin/login` with a wrong
  PIN. Attempts 1–4 return `401 Unauthorized`, `{"error":"invalid PIN"}`. The **5th**
  attempt (`AdminAuth::kMaxFailedAttempts`) engages the lockout inside `verifyPin()` and
  the handler's post-verify re-check turns that same response into `429 Too Many
  Requests`, `{"error":"too many failed attempts; try again later"}` — the 5th wrong PIN
  is a `429`, not a `401`. Every attempt after it, **including one with the correct
  PIN**, is `429` until the cooldown expires. Cooldown starts at 60 s (`kLockoutMs`).
* **TC-RL-02 (Exponential backoff):** Repeat TC-RL-01 after the cooldown expires. Each
  consecutive lockout doubles the wait — `kLockoutMs << min(trips-1, kMaxLockoutShift)`,
  capped by `kMaxLockoutShift = 4` at 16 minutes per client. Only a **correct** PIN
  resets the trip count.
* **TC-RL-03 (Aggregate backstop):** Across *different* clients, accumulate
  `kMaxFailedAttemptsGlobal = 20` failures. A fresh client with an empty bucket of its
  own is then locked out too — this is what stops an attacker who rotates source
  addresses from buying an unbounded guess rate. A correct PIN clears the aggregate state
  as well.

> [!CAUTION]
> **Do not hammer `/api/admin/login` in a load test.** The lockout is per-client with
> exponential backoff *and* an aggregate backstop across all clients, so a brute-force
> loop now locks the whole bench out — including you, at the correct PIN — for up to 16
> minutes, and each further round doubles it. Budget wall-clock time for TC-RL-02/03, or
> run them last.
>
> **To get unstuck: reboot.** The attempt buckets and the aggregate counters live in
> `AuthState`, a function-local static — only `admin_salt` and `admin_hash` are persisted
> to NVS. Power-cycling the device (or restarting the host `SipServer` process) clears
> every lockout without touching the PIN. A factory reset is not needed.

### Concurrent Stress Tests
* **TC-ST-01 (Rapid Dashboard Status Polling):**
  * **Action:** Fire 50 requests per second against `/api/status` for 60 seconds while an
    active SIP call is running on Core 1.
  * **Expected:**
    * All HTTP status requests return successfully.
    * No connection stalls occur.
    * **Crucially:** SIP call audio remains smooth, and no signalling UDP packets are
      dropped on Core 1 (verifying that snapshotting prevents thread blocking).
  * **Note:** `/api/status` is a `GET` and ungated, so this runs without a session. Do
    **not** substitute a mutating endpoint here — see TC-RL-01.

---

## 🖥️ 6. Host Test Suite

The gtest suite that backs all of the above is **310 test cases** (by static count of
`TEST`/`TEST_F` in `tests/*.cpp`). The same three commands CI runs, from a WSL shell:

```bash
unset IDF_PATH                                        # see below
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build/tests --output-on-failure
```

`IDF_PATH` must be unset because the root `CMakeLists.txt` branches on it: with the
variable defined it includes `$ENV{IDF_PATH}/tools/cmake/project.cmake` and configures an
ESP-IDF cross-build, and the host tests are never generated. The `--test-dir build/tests`
is not optional either — testing is enabled only inside the `tests/` subdirectory, so the
CTest set lives there and not at the build root.

Run it from WSL rather than natively on Windows: several suites open real sockets, which
triggers firewall authorisation prompts on a native run.

### 6.1 The `AdminHttpGate_test` trap

If you add a case to `tests/AdminHttpGate_test.cpp` that **provisions a PIN**, it must
construct a real `RequestsHandler` and attach it. Verbatim from the file:

> A real `RequestsHandler` is required: once a PIN exists the listen socket is dark by
> default and only opens inside an admin-open window, which set-pin grants. Without the
> handler the test measures a refused connection rather than the gate.

A test written without it fails for a reason that looks nothing like the thing it is
testing: you get a connection error, not a `401`/`403`, and the gate logic under test is
never reached.
