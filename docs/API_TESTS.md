# Pocket-Dial Firmware: Systematic HTTP API Test Plan

This document defines the systematic test suite and validation plan for the HTTP REST API of the **pocket-dial ESP32 firmware**.

This plan ensures that all management endpoints function correctly under standard workloads, handle malformed parameters safely, validate boundaries, reject malicious cross-origin requests, and refuse mutations that cannot prove they came from the device's own dashboard.

> Source of truth for every route and every gate: [`API.md`](API.md) and
> `src/Helpers/HttpServer.cpp` (`handleClient()` dispatch at lines 433-711,
> `requireAdmin()` at 1828-1876). Where this plan and the code disagree, the code is
> right — fix the plan.

---

## 🚦 0. Before You Test Anything: the shipped-default credential

Almost every surprise in this suite comes from one distinction — and it is **not** the old
"provisioned vs unprovisioned" split, which no longer exists.

The device ships with a well-known default login, `admin`/`admin`
(`AdminAuth::kDefaultUsername`/`kDefaultPassword`). There is no window in which the API is
open to anyone: the session gate is unconditional from the very first boot, and the default
credential is what makes that possible (`HttpServer.cpp:1839-1851`). Until an operator
replaces it, **every** admin-gated route except the one that replaces it is refused.

| | **Default credential** (`needsSetup:true`) | **Setup complete** (`needsSetup:false`) |
|---|---|---|
| TCP listener | Always listening | Always listening |
| Ungated routes | Work | Work |
| `pd_session` cookie | Required on every gated endpoint | Required on every gated endpoint |
| `X-CSRF` header | Required on every **mutating** gated endpoint | Required on every **mutating** gated endpoint |
| Any other gated route, even a `GET` | **`403 {"error":"setup_required"}`** | Works |
| `POST /api/admin/set-credential` | Works (the sole exemption) | Works |

Read the state with one ungated request:

```bash
curl -s http://192.168.4.1/api/admin/status
# -> {"provisioned":false,"needsSetup":true,"authenticated":false,"sessionRemainingSec":0}
```

### 0.1 The listener is never dark

Earlier revisions of this plan described a "dark by default once a PIN exists, DTMF `*4887`
reopens it" transport gate, plus a `POST /api/admin/keepalive` window extension. **All of
that was removed.** `grep -rn 4887 src/` returns nothing, `grantAdminHttpGraceWindow` no
longer exists, and `tests/AdminHttpGate_test.cpp` exists specifically to pin the socket as
unconditionally accepting (`AdminHttpGate.Boot_Provisioned_StillListensImmediately`,
`AdminHttpGate.SetCredential_DoesNotAffectReachability`). A test that expects *connection
refused* anywhere is testing a mechanism that is gone.

The admin credential is likewise **not** a PIN and `POST /api/admin/set-pin` does not
exist. A separate numeric **DTMF PIN** does exist, for the phone-keypad `*PIN#code` admin
menu only; it has no default and is set through `dtmfPin=` on
`POST /api/admin/set-credential`.

### 0.2 Ungated routes — the only things a test can hit with no headers at all

From the dispatch (`HttpServer.cpp:433-711`):

| Route | Why it is ungated |
|---|---|
| `GET /`, `GET /index.html` | The dashboard shell; the login form has to render |
| `GET /api/status` | Read-only metrics snapshot |
| `GET /api/cdr` | Read-only call-detail ring |
| `GET /api/wifi/scan` | Onboarding needs it before a session exists |
| `GET /api/admin/status` | Tells the page whether to show the login form |
| `GET /api/ota/status` | Partition labels + pending flag; no secrets |
| `GET /config/<mac>.cfg` | A booting phone has no cookie. The 12-lowercase-hex MAC is the only credential, and only an **adopted** MAC is served |
| `POST /api/admin/login`, `POST /api/admin/logout` | Same-origin checked, but no session/CSRF — there is nothing to bind a token to |

Everything else goes through `requireAdmin()`.

### 0.3 What this means for `tests/http/test_api.sh`

The smoke suite (**27 test cases**) runs its Admin Auth block **first**, and that ordering is
load-bearing — the opposite of the ordering an older revision of this plan described. The
comment block at the top of `test_api.sh` says why: every other suite needs the
`$SESSION`/`$CSRF` that block establishes, and needs setup to already be complete, because
`requireAdmin()` refuses everything otherwise.

Its sequence: `TC-AUTH-01` asserts `needsSetup:true` pre-login → `02` a mutating call with
no session is `401` → `03` cross-origin login is `403` → `04` login with `admin`/`admin`
returns a cookie **and** a CSRF token → `05` a mutating call while `needsSetup` is still
true is `403 setup_required` → `06` cross-origin `set-credential` is `403` → `07` completes
setup as `admin`/`realpassword123` **reusing the same session** → `08` status now reports
`provisioned:true, needsSetup:false` → `09` the cookie **alone**, without `X-CSRF`, is still
`403`. The Auth Mechanics suite (`TC-AUTH-10`/`11`) runs **last** because it logs out and
deliberately trips the brute-force lockout.

> [!IMPORTANT]
> **`test_api.sh` leaves the target provisioned as `admin`/`realpassword123`, and locked
> out for ≥60 s.** Any manual testing after a run must use that password, and must wait out
> the `429`. Run it against a scratch board or the host build.

---

## 🔒 1. The Four-Layer Gate

Every gated route funnels through one function, `HttpServer::requireAdmin(sock, req, needCsrf)`.
It applies four checks **in this order**, and the first one to fail is the response you get:

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
                    │ 2. Session  (UNCONDITIONAL — there is │
                    │    no unprovisioned bypass)           │
                    │    valid pd_session cookie?           │
                    └───────────────────┬───────────────────┘
                              fail ──> 401 {"error":"authentication required"}
                                        │
                    ┌───────────────────▼───────────────────┐
                    │ 3. CSRF (mutating requests only)      │
                    │    X-CSRF matches the session token?  │
                    └───────────────────┬───────────────────┘
                              fail ──> 403 {"error":"missing or invalid CSRF token"}
                                        │
                    ┌───────────────────▼───────────────────┐
                    │ 4. Forced setup                       │
                    │    needsInitialSetup() &&             │
                    │    path != /api/admin/set-credential  │
                    └───────────────────┬───────────────────┘
                              fail ──> 403 {"error":"setup_required"}
                                        │
                                    [Handler runs]
```

> [!WARNING]
> **There are now THREE different `403` responses.** Asserting on the status code alone
> cannot tell a cross-origin rejection from a CSRF rejection from a forced-setup rejection,
> and a test that only checks `403` will pass for the wrong reason. **Assert on the JSON
> body.**

Note the ordering of layers 3 and 4: a mutating call on a default-credential device with no
CSRF token returns the **CSRF** error, not `setup_required`. A gated `GET` on the same
device returns `setup_required`, because there is no CSRF check on a `GET` to fail first.

### 1.1 Why the Origin check is not enough on its own

The same-origin check deliberately **allows** a request with no `Origin` header, because
that is what `curl`, native clients, and this repository's own smoke suite send. That
gap — a same-site page riding the victim's cookie — is closed by a per-session CSRF token:

* A 128-bit token is minted with the session at login (`AdminAuth::kCsrfTokenHex`).
* It is returned in the login response body as `"csrf"` and rendered into the dashboard
  document. It is **never** a cookie — a browser would attach a cookie to a cross-site
  request on its own, so only a value our own page had to read and echo back proves
  where the request came from.
* Checked centrally in `requireAdmin()`, so no route can forget it.

### 1.2 Safe-origin matrix (layer 1 only)

1. **Direct request (`curl`, address-bar navigation):** no `Origin` header. **Allow.**
2. **Same-origin request (the dashboard):** `Origin: http://192.168.4.1` matches
   `Host: 192.168.4.1`. **Allow.**
3. **Cross-origin request:** `Origin: http://malicious.com` vs `Host: 192.168.4.1`.
   **Reject `403`**, `{"error":"cross-origin request rejected"}`.

> [!WARNING]
> `Access-Control-Allow-Origin` (CORS) headers are intentionally omitted. Wildcard CORS
> would bypass CSRF safety bounds.

### 1.3 CSRF exemptions, and why

| Endpoint | Why no token |
|---|---|
| `POST /api/admin/login` | No session exists yet, so there is nothing to bind a token to. |
| `POST /api/admin/logout` | A forced logout is a nuisance, not a compromise; `SameSite=Strict` already blocks it, and requiring a token would strand a user on a stale page. |
| All `GET` endpoints | Reads are not state changes. The gated ones are still same-origin checked, session-gated, and subject to layer 4. |

There is **no** "unprovisioned device is exempt" row any more. `POST /api/admin/set-credential`
is exempt from layer **4**, not from layers 1-3: it still requires a session and a CSRF
token, obtained by first logging in with the default credential.

---

## 🔑 2. The Login Preamble Every Test Needs

Capture the cookie **and** the token in one step, then complete setup if the device has not
had it done. This is the same pattern [OTA.md §3.2](OTA.md) and
[TROUBLESHOOTING.md](TROUBLESHOOTING.md#403-on-an-api-call-that-used-to-work) use; keep them
in step.

```bash
DEVICE=http://192.168.4.1          # or http://pocketdial.local
JAR=cookies.txt
USER=admin
PASS=admin                         # a factory-fresh target; use the real one otherwise

# Log in: the cookie proves who you are, the token proves the request came from
# something that was told the token rather than from a page riding your cookie.
LOGIN=$(curl -s -c "$JAR" \
     -H "Origin: $DEVICE" \
     -X POST --data "username=$USER&password=$PASS" \
     "$DEVICE/api/admin/login")
# -> {"status":"ok","authenticated":true,"needsSetup":true,"csrf":"3f2a...e91c"}

CSRF=$(printf '%s' "$LOGIN" | sed -n 's/.*"csrf":"\([0-9a-f]*\)".*/\1/p')
[ -n "$CSRF" ] || { echo "login failed: $LOGIN" >&2; exit 1; }

# If needsSetup is true, complete setup NOW — every case below returns
# 403 setup_required otherwise. The session survives the change, so the same
# $JAR/$CSRF keep working and no second login is needed.
case "$LOGIN" in *'"needsSetup":true'*)
  curl -s -b "$JAR" -H "Origin: $DEVICE" -H "X-CSRF: $CSRF" \
       -X POST --data "username=admin&password=realpassword123" \
       "$DEVICE/api/admin/set-credential"
  # -> {"status":"ok","provisioned":true,"needsSetup":false}
esac
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

Drop the `-H "X-CSRF: $CSRF"` and you get `403 {"error":"missing or invalid CSRF token"}` —
the single most common failure when running a pre-existing script against current firmware.

> [!NOTE]
> `POST /api/admin/login` against a device that has never been set up does **not** return
> `409`. It authenticates the shipped default and returns `200` with
> `"needsSetup":true`. A wrong credential returns
> `401 {"error":"invalid username or password"}` (`HttpServer.cpp:2456-2458`).

---

## 📡 3. Endpoint Specifications & JSON Schemas

### 3.1 GET `/` or `/index.html`
Serves the CGA CRT web dashboard. Ungated. Once logged in, the page also carries the
session's CSRF token, which is how the dashboard's own `fetch()` calls satisfy layer 3.
* **Request:** `GET /`
* **Response:** `200 OK`
* **Content-Type:** `text/html; charset=utf-8`

The top bar now exposes Dial Plan (F2), Groups (F3), Call Log (F4) and SIP Trace (F8) as
modals alongside Refresh / WiFi / Admin / Interconnect / Help. Anything those modals write
goes through the ordinary gated routes below — there is no privileged path from the page.

### 3.2 GET `/api/status`
Fetches a read-only snapshot of the registrar, call sessions, and system metrics. Ungated.
* **Request:** `GET /api/status`
* **Response:** `200 OK`, `application/json`
* **Schema** (abridged — see `HttpServer::sendApiStatus`):
  ```json
  {
    "ip": "192.168.4.1",
    "port": 5060,
    "httpPort": 80,
    "uptime": 345,
    "packetsProcessed": 104,
    "packetsDropped": 0,
    "clients":  [ { "number": "101", "address": "192.168.4.20:5061" } ],
    "sessions": [ { "caller": "101", "callee": "102", "state": "Connected", "duration": "02:15" } ],
    "dnd":      [ "103" ],
    "forwards": [ { "extension": "101", "always": "", "busy": "102", "noanswer": "" } ],
    "groups":   [ { "extension": "600", "mode": "ring", "members": "101,102" } ],
    "dialplan": [ { "pattern": "9X.", "action": "trunk", "target": "", "stripDigits": 1 } ],
    "parkedCalls": [ { "orbit": "701", "parkedExt": "102", "parker": "101", "secondsParked": 12 } ]
  }
  ```

### 3.3 GET `/api/cdr`
Read-only Call Detail Records ring. **Ungated**, like `/api/status` — a test must not expect
a `401` here.

### 3.4 POST `/api/kill`
Administratively disconnects a registered extension and terminates its calls.
* **Content-Type:** `application/x-www-form-urlencoded`
* **Parameters:** `extension=XXXX`
* **Headers:** `Cookie: pd_session=…` **and** `X-CSRF: <token>`
* **Response (Success):** `200 OK` `{"status":"ok","disconnected":"101"}`
* **Missing parameter:** `400` `{"error":"missing extension parameter"}`
* **No session:** `401` `{"error":"authentication required"}`
* **Session but no/wrong token:** `403` `{"error":"missing or invalid CSRF token"}`
* **Cross-origin:** `403` `{"error":"cross-origin request rejected"}`
* **Default credential still in place:** `403` `{"error":"setup_required"}`

### 3.5 GET `/api/wifi/scan`
Triggers an active Wi-Fi channel scan and returns visible networks. Ungated.
* **Response (Wi-Fi build):** `200 OK` `{"networks":[{"ssid":"Office_WiFi","rssi":-65,"encryption":"WPA2"}]}`
* **Response (desktop / no-Wi-Fi build):** `200 OK` `{"networks":[], "note":"WiFi scan not available on desktop"}`

### 3.6 POST `/api/wifi/connect`
Configures network credentials, saves them to NVS, and restarts in Station mode.
* **Parameters:** `ssid=SSID_NAME&password=WIFI_PASSWORD`
* **Headers:** cookie **and** `X-CSRF`
* **Response (Wi-Fi build):** `200 OK` `{"status":"ok","message":"WiFi credentials saved. Rebooting to Station Mode..."}`
* **Missing SSID:** `400` `{"error":"missing ssid parameter"}`
* **Response (no-Wi-Fi build):** `501` `{"error":"WiFi connect not available on desktop"}`

### 3.7 POST `/api/wifi/mode_ap`
Sets operational mode back to Standalone AP and reboots. Cookie **and** `X-CSRF`.
* **Response (Wi-Fi build):** `200 OK` `{"status":"ok","message":"Operational mode set to Standalone AP. Rebooting..."}`
* **Response (no-Wi-Fi build):** `501` `{"error":"WiFi mode select not available on desktop"}`

> [!IMPORTANT]
> "No-Wi-Fi build" is **not** just the desktop build. The `eth` and `lan8720` transports do
> not define `POCKETDIAL_HAS_WIFI` (`main/CMakeLists.txt:133-136`), so on a wired board
> `/api/wifi/connect` and `/api/wifi/mode_ap` take their `#else` branch and answer `501` —
> despite the message saying "desktop" (issue #167). A hardware test matrix must branch on
> transport, not on host-vs-device.
>
> `/api/factory-reset` used to be in that list and no longer is: since #189 it answers
> `200` on every build and reboots on every ESP build, with only the Wi-Fi NVS key erase
> still transport-gated.

### 3.8 POST `/api/configuring`
Pauses the captive-portal auto-switch-to-Standalone decay while a user is mid-setup. Takes
the full `requireAdmin()` gate with `needCsrf = true` (`HttpServer.cpp:606-618`), like every
other mutating route. **It is no longer exempt on a fresh device** — an older revision of
this plan said onboarding was unaffected because unprovisioned requests skipped the gate;
that bypass is gone, so the portal must log in with the default credential first.

### 3.9 GET `/api/pcap`, `/api/diagnostics/pcap`, `/api/trace`
Diagnostic capture ring: the first two as a Wireshark-readable `.pcap`, the third as JSON
for the dashboard's live tracer. All three are `GET`, so they take same-origin plus a
session, and no CSRF token — but they are still subject to layer 4.

**These three previously had no same-origin check** — before `e631fc2` `/api/pcap` called
`isAuthed()` directly and never consulted the `Origin` header. They now go through
`requireAdmin()` like everything else, which is worth an explicit regression case
(TC-SEC-06): a capture ring is signalling metadata — who called whom, from which address —
and was readable by any page that could reach the device.

### 3.10 GET `/api/ap-security`
Reports the SoftAP security setting and its passphrase. Gated.

```json
{ "secure": false, "psk": "DD9T4GZKQ4AHY5KGRZP8" }
```

* `secure` — `true` when the standalone SoftAP comes up `WIFI_AUTH_WPA2_PSK`. **Defaults
  to `false`**; the shipped posture is an open AP. Enabling WPA2 forces every associated
  phone to be re-paired, so it is an explicit operator action.
* `psk` — generated from the hardware CSPRNG on first access and stored in NVS. 20
  characters from an alphabet with no ambiguous glyphs (no `0`/`O`, `1`/`I`/`L`, `U`).

Returning the passphrase in clear to an authenticated admin is deliberate: on the
headless `eth`/`wifi` builds this response is one of the few ways to learn it.

### 3.11 POST `/api/ap-security`
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

### 3.12 GET `/api/registrar`
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

* `attached` — `false` when the SIP engine has not been bound to the dashboard yet. On a
  `wifi`/`eth`/`lan8720` device this is not merely a transient: such a board runs **no SIP
  task at all** until a credential has been committed (`main/esp_main_eth.cpp:465-496`), so
  `attached` stays `false` for as long as setup is outstanding. (The `display` build has no
  such gate — `main/esp_main_display.cpp:799-806`.) A test that asserts `mode == "open"` on
  a fresh boot will flake against this — assert on `attached` first.
* `mode` — `open`, `learn` or `secure`. **`open` is the shipped default.**
* `state` — `learned` (adopted on first contact, not yet enforced) or `secured`
  (MAC-locked and digest-enforced for its extension).
* `online` — volatile registration state; never persisted.

### 3.13 POST `/api/registrar`
Sets the admission mode. Cookie **and** `X-CSRF`.

| Param | Values | Effect |
|---|---|---|
| `mode` | `open` \| `learn` \| `secure` | Required. |
| `confirm` | `LOCKOUT` | Only consulted when switching to `secure`. |

`open` is the shipped default: every `REGISTER` and every `INVITE` is accepted with no
credential. `learn` is trust-on-first-use and a deliberate, **temporary** weakening for
adopting an existing fleet. `secure` digest-challenges every `REGISTER` **and** every
`INVITE` (`RequestsHandler::onInvite()` → `Registrar::admitSecure()`,
`src/SIP/RequestsHandler.cpp:1195-1206`).

Switching to `secure` while **no** extension is yet `secured` is refused with `409`:

```json
{ "error": "no extensions are secured yet; switching to secure now would reject every phone. Adopt them in learn mode first, or resend with confirm=LOCKOUT to override." }
```

Resend with `confirm=LOCKOUT` to override — the same shape as `/api/factory-reset`'s
`confirm=ERASE`. Responds with the same body as the `GET`.

> [!NOTE]
> **Corrected — a factory reset *does* clear `reg_mode` now.** Earlier revisions of this
> box warned that `POST /api/factory-reset` would not undo `mode=secure`, because
> `DeviceConfig::clearAll()` erased `reg_mode` from the `storage` namespace while the
> registrar keeps it in `pbxcfg`. **That was a real bug and it was fixed in issue #188**:
> `clearAll()` now calls `eraseRegistrarMode()` (`DeviceConfig.cpp:698`), which opens
> `pbxcfg`, and the comment at `:693-697` records exactly this. [API.md](API.md)'s
> factory-reset section already stated it correctly. Restoring `mode=open` in the same run
> is still good hygiene, but a reset is no longer a way to strand the board. Still not
> exercised on hardware.

### 3.14 POST `/api/registrar/device`
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

### 3.15 POST `/api/dialplan`
Upserts or deletes one first-match-wins dial-plan rule (`HttpServer::sendApiDialPlan`).
Cookie **and** `X-CSRF`.

| Param | Values | Effect |
|---|---|---|
| `pattern` | letters, digits, `#`, `*` | Required — the rule key. Editing an existing pattern keeps its position; a new one is appended. |
| `action` | `group` \| `page` \| `park` \| `trunk` | Omitted **and** `target` omitted ⇒ delete. Naming an action always means upsert. |
| `target` | letters, digits, `#`, `*` | The group/zone/orbit extension, or — for `trunk` — the digits prepended after stripping. |
| `stripDigits` | integer | `trunk` only: leading digits removed before prepending `target`. |

Cases worth pinning:

* **A `trunk` rule may carry an EMPTY `target`** — that is how you express "strip N digits
  and prepend nothing", and it is otherwise inexpressible. Any other action with an empty
  target is `400 {"error":"only a trunk rule may have an empty target (it means prepend nothing)"}`.
* **Deleting therefore requires an empty `action` *and* an empty `target`.** Sending
  `action=trunk&target=` is an upsert, not a delete.
* Reserved patterns `777`, `999`, `440`, `555` are refused `400`.
* `page` targets must be `980`–`989`; `park` targets must be a park orbit (`700`–`709`).

> [!NOTE]
> **Reaching an outbound trunk requires such a rule.** There is no hardcoded `9` prefix and
> no "unknown destination falls through to the trunk" behaviour — with an empty dial plan,
> every outside number is answered `404` without leaving the box. Outbound goes over the
> AnchorClient (HTTP/OAuth2 + call-control WebSocket + chunked-HTTPS PCM16), **not** a SIP
> trunk: nothing in the tree ever sends a `REGISTER`, so the device never registers to an
> ITSP. `POCKETDIAL_MAX_ANCHOR_CALLS` is `4`; the effective limit is `min(provider, 4)` and
> the default loopback provider declares 1, so a stock board allows one concurrent outside
> call and a real trunk four. No E.164
> normalization exists anywhere.

### 3.16 GET `/config/<mac>.cfg`
Zero-touch provisioning, Yealink key format. Ungated by design — a booting phone has no
session cookie, and the MAC is the credential.

* The MAC in the path must be **12 lowercase hex characters**.
* The file is served **only** for a MAC already in the Learn-mode adopted-device registry.
* **Open mode never records devices**, so on a default (`open`) board this route is a
  structural `404` for every MAC. A test that expects a `200` must first put the registrar
  into `learn` and let a phone (or a test fixture) be adopted.
* **The Yealink key set has never been confirmed against a physical handset.** Treat a
  `200` as "the route served bytes", not as "a phone would accept them".

---

## 🧾 4. Security Response Headers (assert on every response)

`HttpServer::sendResponseWithHeader` emits these centrally (`HttpServer.cpp:796-802`), so a
single missing header is a global regression and is cheap to assert once per suite.
**Correction: there is no exempt path.** Earlier revisions said the captive-portal `302`
from `sendRedirect()` hand-rolled a bare redirect and told you not to assert headers on it.
`sendRedirect()` now routes through `sendResponseWithHeader` (`HttpServer.cpp:3122`) — the
hand-rolled version was the bug, and its own comment records the fix. **Assert the headers
on the `302` too**; it is a regression if they are missing:

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

Execute the following against a running device. Every case marked **(A)** requires the §2
login preamble — including setup completion — to have run first.

### Happy Path Tests
* **TC-HP-01 (Get Dashboard):** GET `/` → `200 OK`, HTML matching `CGA_INDEX_HTML`.
* **TC-HP-02 (Get System Status):** GET `/api/status` → `200 OK` and a valid JSON map of
  system metrics, client snapshots, and active sessions. No headers needed.
* **TC-HP-03 (Kill Active Extension) (A):** POST `/api/kill` with `extension=101`, cookie
  and `X-CSRF` → `200 OK`, `{"status":"ok","disconnected":"101"}`. Sessions involving
  `101` are immediately swept.
* **TC-HP-04 (Scan WiFi):** GET `/api/wifi/scan` → on a Wi-Fi build, switches to `APSTA`
  then `200 OK` with SSIDs; on `eth`/`lan8720`/host, `200 OK` with an empty list.
* **TC-HP-05 (Call log):** GET `/api/cdr` with **no** headers → `200 OK`. Regression case
  for the route being ungated like `/api/status`.

### Forced-Setup Tests (gate layer 4)
* **TC-SET-01 (Fresh device reports itself):** GET `/api/admin/status` on a never-set-up
  target → `200`, `{"provisioned":false,"needsSetup":true,…}`. No headers.
* **TC-SET-02 (Default credential authenticates):** POST `/api/admin/login` with
  `username=admin&password=admin` → `200`, a `pd_session` cookie, and a body containing both
  `"csrf"` and `"needsSetup":true`. **Not** `409`.
* **TC-SET-03 (Everything else is refused):** With that session and its token, POST
  `/api/kill` → `403 {"error":"setup_required"}`. Repeat with a gated **GET**
  (`/api/registrar`) → also `403 setup_required`, proving layer 4 applies to reads too.
* **TC-SET-04 (The one exemption works):** POST `/api/admin/set-credential` with
  `username=admin&password=realpassword123`, same cookie and token → `200`,
  `{"status":"ok","provisioned":true,"needsSetup":false}`. The **same** session must still
  work afterwards — `setLoginCredential()` does not invalidate the session it was called
  through.
* **TC-SET-05 (Validation):** `password=short` → `400 {"error":"invalid username or password"}`;
  `username=` alone → `400 {"error":"username and password must both be provided together"}`;
  an empty body → `400 {"error":"nothing to change"}`. A rejected call must leave the
  stored credential unchanged.
* **TC-SET-06 (DTMF PIN is separate):** POST `/api/admin/set-credential` with
  `dtmfPin=1234` alone → `200`. A 3-digit or non-numeric PIN → `400 {"error":"DTMF PIN must
  be 4-16 digits"}`. Setting it must not alter the login credential, and not setting it must
  leave the `*PIN#code` menu unreachable.

### Edge Case & Boundary Validation Tests
* **TC-ED-01 (Payload Too Large):** POST a body larger than 16 KB (16,384 bytes) to
  `/api/wifi/connect` → `413 Payload Too Large`,
  `{"error":"request body exceeds 16 KB limit"}`, connection closes. Note
  `/api/ota/upload` is **exempt** — it is streamed, not buffered, so a multi-MB image
  must not return `413`.
* **TC-ED-02 (Missing Kill Parameter) (A):** POST `/api/kill` with an empty body, cookie
  and valid token → `400 Bad Request`, `{"error":"missing extension parameter"}`.
  The `400` proves the gate was passed *before* validation — order matters.
* **TC-ED-03 (Missing Connect Parameters) (A):** POST `/api/wifi/connect` with
  `password=12345678` → `400 Bad Request`, `{"error":"missing ssid parameter"}`.
* **TC-ED-04 (URL-Encoded Values Parsing) (A):** POST `/api/wifi/connect` with
  `ssid=Office+AP%21&password=pass`. Verify the stored credential decodes to `Office AP!`.
* **TC-ED-05 (AP passphrase bounds) (A):** POST `/api/ap-security` with a 7-character
  `psk` → `400`, and a follow-up `GET /api/ap-security` still returns the **previous**
  passphrase. A rejected write must not clear the stored value.
* **TC-ED-06 (Registrar lockout guard) (A):** With no extension in state `secured`, POST
  `/api/registrar` with `mode=secure` → `409` and the quoted body above. Repeat with
  `mode=secure&confirm=LOCKOUT` → `200` and `"mode":"secure"`. **Restore `mode=open`
  explicitly afterwards** — every later SIP case is otherwise digest-challenged, and on real
  hardware a factory reset will not undo it (§3.13).
* **TC-ED-07 (Registrar unknown device) (A):** POST `/api/registrar/device` with
  `action=secure&target=ffffffffffff` → `404`.
* **TC-ED-08 (Dial-plan empty trunk target) (A):** POST `/api/dialplan` with
  `pattern=9X.&action=trunk&target=&stripDigits=1` → `200` (a legal "strip 1, prepend
  nothing" rule). The same with `action=group&target=` → `400`. Then POST
  `pattern=9X.` alone (no `action`, no `target`) → the rule is **deleted**.
* **TC-ED-09 (Reserved dial-plan patterns) (A):** `pattern=777` → `400 {"error":"cannot use
  a reserved extension as a dial-plan pattern"}`. Same for `999`, `440`, `555`.
* **TC-ED-10 (Provisioning config 404s in open mode):** GET `/config/805ec079c37f.cfg` on a
  default (`open`) board → `404`, because open mode records no adopted devices. Uppercase or
  short MACs must also `404`, not `500`.

### Same-Origin Tests (gate layer 1)
* **TC-SEC-01 (Direct Request — No Origin Header) (A):** POST `/api/kill` via `curl` with no
  `Origin`, cookie and token → `200 OK`. Without the cookie → `401` — the missing `Origin`
  is still allowed, it is the session that stops you.
* **TC-SEC-02 (Same-Origin Request) (A):** POST `/api/kill` with `Host: 192.168.4.1`,
  `Origin: http://192.168.4.1`, cookie and token → `200 OK`.
* **TC-SEC-03 (Cross-Origin Block):** POST `/api/kill` with `Host: 192.168.4.1` and
  `Origin: http://malicious-website.com` → `403 Forbidden`,
  `{"error":"cross-origin request rejected"}`. Assert the **body** — see TC-SEC-05.

### Session & CSRF Tests (gate layers 2 and 3)
* **TC-SEC-04 (No session):** POST `/api/kill` with no cookie → `401 Unauthorized`,
  `{"error":"authentication required"}`. This holds on a factory-fresh device too — there
  is no unprovisioned bypass to regression-test for any more.
* **TC-SEC-05 (Cookie without token) (A):** POST `/api/kill` with a valid `pd_session`
  cookie but **no** `X-CSRF` header → `403 Forbidden`,
  `{"error":"missing or invalid CSRF token"}`. Repeat with a token that is valid-looking
  but belongs to no session — same result. This case, TC-SEC-03 and TC-SET-03 all return
  `403`; the assertion **must** be on the JSON body.
* **TC-SEC-06 (Diagnostics are gated) (A):** GET `/api/pcap`, `/api/diagnostics/pcap` and
  `/api/trace` with no cookie → `401` on all three. Then with a cookie and **no** token →
  `200` on all three, because they are `GET`s and take no CSRF token. Regression case for
  the previously-missing gate.
* **TC-SEC-07 (`/api/configuring` is gated) (A):** POST `/api/configuring` with no cookie →
  `401`; with a cookie but no `X-CSRF` → `403` (it is a mutating route, `needCsrf = true`).
  On a device still on the default credential it is `403 setup_required` — the old
  "unprovisioned onboarding is exempt" behaviour is **gone**, so a captive-portal test must
  log in first.
* **TC-SEC-08 (Logout needs no token) (A):** POST `/api/admin/logout` with only the cookie →
  succeeds. A subsequent `/api/kill` with the same cookie → `401`.
* **TC-SEC-09 (Headers present):** Assert the five headers of §4 on at least one `GET`,
  one `POST` success, and one error response, and assert `Strict-Transport-Security` is
  **absent**.
* **TC-SEC-10 (Session slide):** ~~GET `/api/admin/status` does **not** itself slide the
  expiry.~~ **This expectation is wrong and must not be asserted.** `sendApiAdminStatus`
  calls `isAuthed()` (`HttpServer.cpp:2639`) → `AdminAuth::validateSession()`, which pushes
  `expiresAtMs` forward (`AdminAuth.cpp:909`). So polling `/api/admin/status` **does** keep
  the session alive, and a dashboard that polls it for a countdown will never see the
  session expire. [API.md](API.md) already carries this correction; this line did not.
  Assert the opposite: two reads 2 s apart both return `sessionRemainingSec` near 1800.

### Login Rate-Limiting Tests
* **TC-RL-01 (Per-client lockout):** From one client, POST `/api/admin/login` with a wrong
  password. Attempts 1–4 return `401 Unauthorized`,
  `{"error":"invalid username or password"}`. The **5th** attempt
  (`AdminAuth::kMaxFailedAttempts`) engages the lockout inside `verifyCredential()` and the
  handler's post-verify re-check turns that same response into `429 Too Many Requests`,
  `{"error":"too many failed attempts; try again later"}` — the 5th wrong password is a
  `429`, not a `401` (`HttpServer.cpp:2446-2459`). Every attempt after it, **including one
  with the correct password**, is `429` until the cooldown expires. Cooldown starts at 60 s
  (`kLockoutMs`).
* **TC-RL-02 (Exponential backoff):** Repeat TC-RL-01 after the cooldown expires. Each
  consecutive lockout doubles the wait — `kLockoutMs << min(trips-1, kMaxLockoutShift)`,
  capped by `kMaxLockoutShift = 4` at 16 minutes per client. Only a **correct** login
  resets the trip count.
* **TC-RL-03 (Aggregate backstop):** Across *different* clients, accumulate
  `kMaxFailedAttemptsGlobal = 20` failures. A fresh client with an empty bucket of its
  own is then locked out too — this is what stops an attacker who rotates source
  addresses from buying an unbounded guess rate. A correct login clears the aggregate state
  as well.
* **TC-RL-04 (Shared bucket with the DTMF PIN):** `AdminAuth::verifyDtmfPin()` accounts
  against the unkeyed `""` bucket (`AdminAuth.hpp:135-139`). A suite that exercises both
  surfaces must expect them to lock each other out.

> [!CAUTION]
> **Do not hammer `/api/admin/login` in a load test.** The lockout is per-client with
> exponential backoff *and* an aggregate backstop across all clients, so a brute-force
> loop locks the whole bench out — including you, at the correct password — for up to 16
> minutes, and each further round doubles it. Budget wall-clock time for TC-RL-02/03, or
> run them last.
>
> **To get unstuck: reboot.** The attempt buckets and the aggregate counters live in
> `AuthState`, a function-local static — only the credential hashes are persisted to NVS.
> Power-cycling the device (or restarting the host `SipServer` process) clears every lockout
> without touching the credential. A factory reset is not needed.

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

The gtest suite that backs all of the above is **506 test cases** (static count of
`TEST`/`TEST_F`/`TEST_P` in `tests/*.cpp`; the 416 previously quoted here was stale by 90).
The same three commands CI runs, from a WSL shell:

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

### 6.1 What the host suite does **not** cover

State this plainly before quoting the pass count at anyone:

* **`RtpSender.cpp` and `RtpReceiver.cpp` compile to host stubs.** Every green media test
  exercises a stub, not real RTP. On-device RTP has never been exercised by a test.
* **OTA has never been executed anywhere** — not on hardware, not in CI.
* The interop suites (`tests/interop/`, pjsua/SIPp) run against the **desktop** binary on
  loopback, not against a board.
* The only real-handset evidence in the project is recent and narrow: a Yealink T29
  registered to the bench board, and outbound PSTN verified end to end — one call rang
  through to carrier voicemail (answered at 21.2 s) and one was answered by a person with
  two-way audio. That is the first real-handset evidence there has been; everything else in
  this plan is host-only.

### 6.2 The `AdminHttpGate_test` trap

The trap here has **inverted** since the previous revision of this plan. It used to be
"provision a PIN without attaching a `RequestsHandler` and the listener goes dark, so you
measure a refused connection instead of the gate." That mechanism is gone — the socket is
unconditional, and `AdminHttpGate_test.cpp`'s header comment now exists to document its
removal.

The current trap: **any case that touches a gated route must call
`loginAndCompleteSetup()` first** (`tests/AdminHttpGate_test.cpp:393-414`). A case that only
logs in with the default credential gets `403 {"error":"setup_required"}` from every route
under test, which looks nothing like the thing being tested. The helper exists precisely so
that never has to be rediscovered:

> Log in with the shipped default credential, then immediately complete setup with a real
> one — `requireAdmin()` refuses every other admin-gated route (including the ones under
> test here) while `needsInitialSetup()` is true, and `setLoginCredential()` does not
> invalidate the session it was called through, so the same cookie/csrf pair keeps working
> afterward.

Remember to `AdminAuth::clearCredential()` at the end of a case that sets one — the
credential is a process-wide static on host, so a leftover one leaks into the next test.
