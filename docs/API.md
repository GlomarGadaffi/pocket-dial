# Pocket-Dial ESP32 Firmware: HTTP REST API Specification

This document provides the formal API specification for the HTTP control interface of the **pocket-dial** firmware. The API handles status reporting, client management, and Wi-Fi onboarding.

> [!NOTE]
> The admin session endpoints (`/api/admin/*`) are specified in §0 above, not
> repeated in the §4 catalog below. Source of truth for every route:
> `src/Helpers/HttpServer.cpp` (`handleClient()` dispatch).

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

**Admin session endpoints** (all JSON; mutating ones are Same-Origin + CSRF checked):

| Endpoint | Method | Auth | Purpose |
| :--- | :--- | :--- | :--- |
| `/api/admin/status` | `GET` | None | `{provisioned, needsSetup, authenticated, sessionRemainingSec}` for dashboard render. `provisioned`/`needsSetup` are inverses of each other and describe the login credential only. `sessionRemainingSec` is the live countdown on the caller's own session; reading it deliberately does **not** slide the session's expiry, so the badge is honest rather than self-refreshing. |
| `/api/admin/set-credential` | `POST` | Session (+CSRF) | Change the login credential and/or the DTMF PIN. `username=`+`password=` (≥8 chars) must both be provided together to change the login credential; `dtmfPin=` (4-16 digits) alone changes just the DTMF PIN. Reachable even while `needsSetup` is true — it's the one exemption to the setup_required gate. |
| `/api/admin/login` | `POST` | `username=`+`password=` in body | Verifies against the stored credential, or the default (`admin`/`admin`) if none has been set yet. Issues the `pd_session` cookie (HttpOnly, SameSite=Strict) and the session's CSRF token. Rate-limited with lockout. |
| `/api/admin/logout` | `POST` | Session | Invalidates the session cookie. |

Every state-mutating endpoint (`/api/kill`, `/api/dnd`, `/api/forward`,
`/api/group`, `/api/dialplan`, `/api/wifi/*`, `/api/factory-reset`, OTA upload,
`/api/telephony-config`, `/api/did-mapping`, `/api/admin/set-credential`, ...)
requires both the `pd_session` cookie and the per-session CSRF token — from
the very first login, including while still on the default credential.

---

## 1. Global Server Settings & Connection Behavior

The HTTP server operates under strict resource constraints and security policies designed to prevent device crashes and malicious manipulation.

### Connection Limits & Socket Policies
* **Protocol**: HTTP/1.1
* **Default Port**: 80 (Overridden to custom port if configured)
* **Socket Timeout (`SO_RCVTIMEO`)**: **5 Seconds**. Connections that do not send data within 5 seconds of connection are forcefully closed.
* **Payload Limit**: **16 KB (16,384 bytes)**. Any request body larger than 16 KB (including large Wi-Fi passwords) is rejected with status `413 Payload Too Large`.

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

To prevent Cross-Site Request Forgery (CSRF) exploits when operating as an open Wi-Fi network, the server implements strict Same-Origin Verification on **every** state-mutating endpoint — `/api/kill`, `/api/dnd`, `/api/forward`, `/api/group`, `/api/dialplan`, `/api/telephony-config/*`, `/api/did-mapping`, `/api/wifi/connect`, `/api/wifi/mode_ap`, `/api/configuring`, `/api/ap-security`, `/api/registrar*`, `/api/factory-reset`, the OTA routes and `/api/admin/set-credential`. The check is applied centrally in `HttpServer::requireAdmin()`, so no route can omit it:

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

* **Trigger**: Any HTTP `GET` request where the `Host` header does not contain:
  * `192.168.4.1` (the local SoftAP gateway IP)
  * `localhost`
  * `pocketdial` (mDNS hostname)
  * The current DHCP-assigned IP address.
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
> `HttpServer::requireAdmin()` (`src/Helpers/HttpServer.cpp:1828`), which applies four
> checks in order: same-origin; a valid `pd_session` cookie; for mutating requests a
> matching `X-CSRF` token; and the forced-setup gate, which refuses everything except
> `POST /api/admin/set-credential` with `403 {"error":"setup_required"}` while the
> device is still on the default `admin`/`admin` credential.
>
> There is **no unprovisioned bypass**. An earlier firmware skipped the session and
> token checks until an admin PIN existed; that window is gone — the device ships with
> a default credential precisely so the gate can be unconditional from first boot.
> Endpoints marked "None" are read-only and intentionally reachable without a session.

| Endpoint | Method | Security Level | Auth Required | Description |
| :--- | :---: | :---: | :---: | :--- |
| [`/`](#get-) | `GET` | Low | None | Serves the web dashboard HTML interface. |
| [`/api/status`](#get-apistatus) | `GET` | Low | None | Retrieves registrar uptime, packet statistics, active extensions, and ongoing sessions. |
| [`/api/kill`](#post-apikill) | `POST` | High | Gated (+ `X-CSRF`) | Forcefully disconnects and de-registers an active SIP extension. |
| [`/api/cdr`](#get-apicdr) | `GET` | Low | None | Returns the in-memory Call Detail Record ring (most recent calls, newest first). |
| [`/api/pcap`](#get-apipcap) | `GET` | Medium | Gated (same-origin + session) | Downloads the last `POCKETDIAL_PCAP_RING_SIZE` SIP signaling packets as a `.pcap` (Wireshark-readable). |
| [`/api/diagnostics/pcap`](#get-apipcap) | `GET` | Medium | Gated (same-origin + session) | Alias for `/api/pcap` (Issue #33's originally-requested path) — identical response, same ring, same gate. |
| [`/api/trace`](#get-apitrace) | `GET` | Medium | Gated (same-origin + session) | The same capture ring as JSON, for the dashboard's polling live SIP tracer. |
| [`/config/<mac>.cfg`](#get-configmaccfg) | `GET` | Low | None (MAC is the bearer token) | Yealink auto-provisioning config for an already-adopted device. |
| [`/api/dnd`](#post-apidnd) | `POST` | High | Gated (+ `X-CSRF`) | Sets or clears Do-Not-Disturb on an extension. |
| [`/api/forward`](#post-apiforward) | `POST` | High | Gated (+ `X-CSRF`) | Configures call forwarding (`always`/`busy`/`noanswer`) for an extension. |
| [`/api/group`](#post-apigroup) | `POST` | High | Gated (+ `X-CSRF`) | Creates, updates, or deletes a ring/hunt group. |
| [`/api/dialplan`](#post-apidialplan) | `POST` | High | Gated (+ `X-CSRF`) | Creates, updates, or deletes one dial-plan rule (pattern → action). Params: `pattern`, `action` (`group`\|`page`\|`park`\|`trunk`), `target`, and `stripDigits` (trunk only). Naming an `action` always means create/update; **omitting both `action` and `target` deletes the rule**. A `trunk` rule may carry an empty `target`, which means "strip the digits and prepend nothing". |
| [`/api/telephony-config`](#get-apitelephony-config) | `GET` | Medium | Gated | Lists the four carrier/anchor credential slots. The stored secret is never returned — only `secretSet`. |
| [`/api/telephony-config/<slot>`](#put-apitelephony-configslot) | `PUT` | High | Gated (+ `X-CSRF`) | Writes one credential slot (`enabled`, `baseUrl`, `clientId`, `secret`, `routeDn`). An empty `secret` keeps the stored one. |
| [`/api/telephony-config/<slot>/activate`](#post-apitelephony-configslotactivate) | `POST` | High | Gated (+ `X-CSRF`) | Makes that slot the active provider. |
| [`/api/telephony-config/<slot>/test`](#post-apitelephony-configslottest) | `POST` | High | Gated (+ `X-CSRF`) | Connectivity probe: places and immediately drops a real call to the slot's own route DN. Active slot only. |
| [`/api/telephony-config/<slot>`](#delete-apitelephony-configslot) | `DELETE` | High | Gated (+ `X-CSRF`) | Clears one slot, including its stored secret, without a factory reset. |
| [`/api/did-mapping`](#get-apidid-mapping) | `GET` | Medium | Gated | Lists the inbound DID→extension table. |
| [`/api/did-mapping`](#put-apidid-mapping) | `PUT` | High | Gated (+ `X-CSRF`) | Creates or updates one DID→extension mapping. |
| [`/api/did-mapping`](#delete-apidid-mapping) | `DELETE` | High | Gated (+ `X-CSRF`) | Removes one DID mapping. Idempotent. |
| [`/api/wifi/scan`](#get-apiwifiscan) | `GET` | Low | None | Triggers a scan of nearby Wi-Fi APs and returns their SSIDs and signal strengths. |
| [`/api/wifi/connect`](#post-apiwificonnect) | `POST` | High | Gated (+ `X-CSRF`) | Saves Wi-Fi credentials to NVS and schedules an ESP32 system reboot into Station Mode. |
| [`/api/wifi/mode_ap`](#post-apiwifimode_ap) | `POST` | High | Gated (+ `X-CSRF`) | Sets the device to Standalone Access Point Mode and schedules a system reboot. |
| [`/api/configuring`](#post-apiconfiguring) | `POST` | Low | Gated (+ `X-CSRF`) | Pauses the captive-portal auto-switch-to-Standalone decay while a user is mid-setup. It mutates device state, so it takes the standard gate like every other mutating route — a logged-in, fully-set-up session is required, same as WiFi setup itself. |
| [`/api/factory-reset`](#post-apifactory-reset) | `POST` | High | Gated (+ `X-CSRF`) | Wipes the login credential, the DTMF PIN, the carrier-API credential table, the DID→extension table, the CDR call-history ring, and Wi-Fi/mode NVS state, then reboots to captive-portal setup. ESP-only (`501` on desktop — the underlying wipes still run and are host-testable). |
| [`/api/ap-security`](#get-apiap-security) | `GET` | Medium | Gated | Reports whether the SoftAP requires WPA2 and returns its passphrase. |
| [`/api/ap-security`](#post-apiap-security) | `POST` | High | Gated (+ `X-CSRF`) | Enables/disables WPA2 on the SoftAP and sets or regenerates the passphrase. Takes effect at the next AP bringup. |
| [`/api/registrar`](#get-apiregistrar) | `GET` | Medium | Gated | Reports the SIP registrar admission mode and the adopted-extension roster. |
| [`/api/registrar`](#post-apiregistrar) | `POST` | High | Gated (+ `X-CSRF`) | Sets the admission mode (`open`/`learn`/`secure`). |
| [`/api/registrar/device`](#post-apiregistrardevice) | `POST` | High | Gated (+ `X-CSRF`) | Secures (MAC-locks + digest-enforces) or forgets one adopted device. |
| [`/api/ota/status`](#get-apiotastatus) | `GET` | Low | None | Reports the running/boot/next OTA partition labels and pending-verify flag. |
| [`/api/ota/upload`](#post-apiotaupload) | `POST` | High | Gated (+ `X-CSRF`) | Streams a firmware image into the inactive OTA slot. ESP-only (`501` on desktop). |
| [`/api/ota/reboot`](#post-apiotareboot) | `POST` | High | Gated (+ `X-CSRF`) | Reboots into the freshly staged OTA image. Simulated (`200`, no-op) on desktop. |

---

### `GET /`
Serves the retro CGA CRT web interface.

* **Request Headers**: None
* **Response Content-Type**: `text/html; charset=utf-8`
* **Response Status Codes**:
  * `200 OK`: File successfully transmitted.

---

### `GET /api/status`
Returns a detailed JSON object representing the active state of the SIP registration database and traffic statistics.

* **Request Headers**: None
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`
* **Response Payload JSON Example**:
```json
{
  "ip": "192.168.4.1",
  "port": 5060,
  "httpPort": 80,
  "uptime": 14205,
  "packetsProcessed": 10543,
  "packetsDropped": 12,
  "clients": [
    {
      "number": "1001",
      "address": "192.168.4.12:5060"
    },
    {
      "number": "1002",
      "address": "192.168.4.15:5068"
    }
  ],
  "sessions": [
    {
      "caller": "1001",
      "callee": "1002",
      "state": "Connected",
      "duration": "03:45"
    }
  ]
}
```

#### Field Schema Definitions

| Field Name | Type | Description |
| :--- | :---: | :--- |
| `ip` | String | The primary active IP address of the SIP server interface. |
| `port` | Integer | The active UDP signaling port (typically 5060). |
| `httpPort` | Integer | The active TCP HTTP port (typically 80). |
| `uptime` | Integer | Time in seconds since the HTTP server initialized. |
| `packetsProcessed` | Integer | Total UDP signaling packets processed by the state machine. |
| `packetsDropped` | Integer | Total UDP signaling packets dropped by rate-limiting or firewall rules. |
| `clients` | Array | Array of objects listing active VoIP extensions. |
| `clients[].number` | String | SIP extension number (e.g., `"1001"`). |
| `clients[].address` | String | Client's IP and port (e.g., `"192.168.4.12:5060"`). |
| `sessions` | Array | Array of active SIP communication channels. |
| `sessions[].caller` | String | Extension that initiated the call. |
| `sessions[].callee` | String | Target extension receiving the call. |
| `sessions[].state` | String | Active session state: `Invited`, `Connected`, `Busy`, `Unavailable`, `Cancel`, `Bye`. |
| `sessions[].duration` | String | Active call length formatted as `MM:SS` or `HH:MM:SS`. |
| `dnd` | Array | Extension numbers (strings) currently in Do-Not-Disturb. |
| `forwards` | Array | Per-extension call-forward targets: `{extension, always, busy, noanswer}`. An unset trigger is an empty string. |
| `groups` | Array | Ring/hunt groups: `{extension, mode, members}`, where `mode` is `ringall` or `hunt` and `members` is a comma-joined list. |
| `dialplan` | Array | The dial-plan rule table (Issue #69), **in evaluation order** — first match wins, so this array's order is load-bearing. Unlike the sets above, this one's order is meaningful. |
| `dialplan[].pattern` | String | The dialed-number pattern (see [`POST /api/dialplan`](#post-apidialplan) for the grammar). |
| `dialplan[].action` | String | `group`, `page`, `park`, or `trunk`. |
| `dialplan[].target` | String | The group / paging-zone / park-orbit extension the rule routes to, or — for `trunk` — the string prepended to the dialed number after stripping (possibly empty, meaning "prepend nothing"). |
| `dialplan[].stripDigits` | Number | `trunk` only (Issue #165): leading digits removed from the dialed number before prepending `target`. `0` for every other action. |
| `parkedCalls` | Array | Calls currently sitting on a park orbit: `{orbit, parkedExt, parker, secondsParked}`. Lets a client tell a parked extension apart from an idle or connected one. |

> The example above is abridged — `dnd`, `forwards`, `groups`, `dialplan` and
> `parkedCalls` are always present (as empty arrays when unset). Full shape:
> `HttpServer::sendApiStatus()`, `src/Helpers/HttpServer.cpp:913`.

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
  * `200 OK`: Target extension disconnected.
  * `400 Bad Request`: Parameter `extension` is missing or empty.
  * `401 Unauthorized`: The request carries no valid `pd_session` cookie.
  * `403 Forbidden`: Same-Origin verification failed.

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

---

### `GET /api/wifi/scan`
Triggers an immediate background Wi-Fi network scan. On ESP32, this temporarily sets the radio to `AP+STA` mode to complete the scan.

* **Request Headers**: None
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`
  * `500 Internal Server Error`: Background scan driver failed to launch.

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
> [!NOTE]
> On desktop platforms (Windows/Linux development builds), the endpoint returns:
> `{"networks":[], "note":"WiFi scan not available on desktop"}`

---

### `POST /api/wifi/connect`
Configures the device to operate in **Wi-Fi Station Mode**, saving the SSID and password to flash, and triggers a system reboot.

* **Requires Same-Origin Check**: Yes
* **Requires `pd_session` cookie**: Always (see §0)
* **Request Content-Type**: `application/x-www-form-urlencoded`
* **Request Parameters**:
  * `ssid` (Required): SSID of the target network.
  * `password` (Optional): Password of the target network.
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`: Credentials stored, reboot scheduled.
  * `400 Bad Request`: Parameter `ssid` is missing.
  * `401 Unauthorized`: The request carries no valid `pd_session` cookie.
  * `403 Forbidden`: Same-Origin verification failed.

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

---

### `POST /api/wifi/mode_ap`
Sets the operational mode of the device back to **Standalone Access Point Mode** (`esp32-sipserver`), saving settings to NVS flash, and triggers a system reboot.

* **Requires Same-Origin Check**: Yes
* **Requires `pd_session` cookie**: Always (see §0)
* **Request Headers**: None
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`: Storage committed, reboot scheduled.
  * `401 Unauthorized`: The request carries no valid `pd_session` cookie.
  * `403 Forbidden`: Same-Origin verification failed.

#### Response Example (200 OK)
```json
{
  "status": "ok",
  "message": "Operational mode set to Standalone AP. Rebooting..."
}
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
  once it does (`main/esp_main_eth.cpp:310`), so this is a boot-time transient of a
  second or two, not an error; `mode` reads `"unknown"` and `devices` is empty. Every
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

### `POST /api/registrar/device`

| Param | Values | Effect |
| :--- | :--- | :--- |
| `action` | `secure` \| `forget` | Required. |
| `target` | 12-hex MAC, or an extension | Required. An extension resolves to the device currently bound to it. |

`secure` promotes a `learned` device to `secured`. `forget` drops the adoption record
entirely — in `learn` mode the phone is re-adopted on its next registration, which is the
way to re-home an extension to different hardware.

`404` if no adopted device matches. Responds with the same body as the `GET`.

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

```
POST /api/ap-security HTTP/1.1
Host: 192.168.4.1
Content-Type: application/x-www-form-urlencoded
X-CSRF: 3f2a...e91c

secure=1&psk=DD9T4GZKQ4AHY5KGRZP8
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
    "result": "completed"
  }
]
```

#### Field Schema Definitions

| Field Name | Type | Description |
| :--- | :---: | :--- |
| `caller` | String | Extension that initiated the call. |
| `callee` | String | Target extension. |
| `startMs` | Integer | Call start time on the server's steady-clock basis (not wall-clock; no RTC is guaranteed on-device). |
| `ageSec` | Integer | Seconds since the call started, derived from the same steady-clock basis as `startMs`. |
| `duration` | Integer | Call length in seconds. |
| `result` | String | Outcome of the call (e.g. `"completed"`). |

---

### `GET /api/pcap`
Downloads a classic libpcap file of the most recent SIP signaling packets, ready to open directly in Wireshark. Both directions are captured (packets the server received and packets it sent); **RTP/media is never included** — the capture ring is fed from the SIP socket only.

For an ordinary extension-to-extension call that also means there is nothing to miss: the board relays signalling and the two phones stream RTP directly to each other, so no media ever reaches it. That is not true of every call. The board terminates media itself on `440` (tone), `555` (anchor bridge) and `888` (conference). An outbound trunk call crosses it on **both** sides — RTP to and from the handset, chunked-HTTPS PCM16 to and from the provider, with `MediaBridge` shuttling PCM16 between the two. None of that appears here either — this endpoint captures SIP, not media, whoever is carrying it. (`777` is an SDP loopback: the phone streams to its own address, so there is genuinely no media leg on the board — see `src/SIP/RequestsHandler.cpp:1228`.)

Captured packets are synthesized into a minimal Ethernet+IPv4+UDP frame around the exact SIP bytes (dummy MAC addresses — the server has no real link-layer information — but real source/destination IP:port), so Wireshark's SIP dissector decodes them exactly as it would a real capture. Timestamps are relative to the server's monotonic clock, not wall-clock (no RTC is guaranteed on the device — same basis as `/api/cdr`'s `startMs`).

Only packets that pass structural validation and the per-source-IP rate limiter (Issue #38) are captured — this is a signaling-research aid, not a wire-level DoS forensics tool. The ring is bounded (`POCKETDIAL_PCAP_RING_SIZE`, default 64); older packets are dropped as new ones arrive.

* **Requires `pd_session` cookie**: Always (see §0). No same-origin check — this is a plain file download, not a state-mutating action, and `SameSite=Strict` on the session cookie already prevents a cross-site page from riding an admin's session to reach it.
* **Request Headers**: None
* **Response Content-Type**: `application/vnd.tcpdump.pcap`
* **Response Headers**: `Content-Disposition: attachment; filename="pocket-dial.pcap"`
* **Response Status Codes**:
  * `200 OK`: Always — an empty/never-populated ring still returns a valid (headers-only) `.pcap`.
  * `401 Unauthorized`: The request carries no valid `pd_session` cookie.

`GET /api/diagnostics/pcap` is a second route to this exact same handler — the path Issue #33's original feature request asked for — kept as a route rather than a redirect so `curl -o dump.pcap http://<device>/api/diagnostics/pcap` works without `-L`. Identical response, ring, and gate; use whichever path you like.

---

### `GET /api/trace`
Returns the same capture ring as `/api/pcap`, as JSON, for the dashboard's live SIP tracer panel. Returns the **whole current ring on every call** rather than an incremental "since" delta — the ring is small (`POCKETDIAL_PCAP_RING_SIZE`, default 64) and this is meant to be polled every second or two on a LAN, so re-sending it is cheap and the server doesn't need to track any per-client polling state. The client filters to `seq` values it hasn't already rendered.

* **Requires `pd_session` cookie**: Always (see §0). Same sensitivity/gate as `/api/pcap` — it's the same underlying data.
* **Request Headers**: None
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`
  * `401 Unauthorized`: The request carries no valid `pd_session` cookie.
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
| `text` | String | The raw SIP message bytes, exactly as captured. |

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

* **Request Headers**: None
* **Response Content-Type**: `text/plain`
* **Response Status Codes**:
  * `200 OK`: MAC is adopted; config body returned.
  * `404 Not Found`: `<mac>` isn't in the adopted-device registry (or the path doesn't match the `/config/<12 hex>.cfg` shape at all).

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
  * `extension` (Required): The extension to set DND on. Must not be `777` (echo) or `999` (broadcast) — DND cannot be applied to the virtual extensions.
  * `on` (Optional): `1`, `true`, or `on` enables DND; anything else (including omitted or `0`) disables it.
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`
  * `400 Bad Request`: `extension` is missing, or is `777`/`999`.
  * `401 Unauthorized` / `403 Forbidden`: as above.

#### Response Example (200 OK)
```json
{
  "status": "ok",
  "extension": "1001",
  "dnd": true
}
```

---

### `POST /api/forward`
Configures call forwarding for an extension.

* **Requires Same-Origin Check**: Yes
* **Requires `pd_session` cookie**: Always (see §0)
* **Request Content-Type**: `application/x-www-form-urlencoded`
* **Request Parameters**:
  * `extension` (Required): The extension to configure. Must not be `777` or `999`.
  * `trigger` (Required): One of `always`, `busy`, `noanswer`.
  * `target` (Optional): The extension to forward to. Empty clears the rule for that trigger.
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`
  * `400 Bad Request`: `extension` or `trigger` missing, `trigger` not one of the three values, or `extension` is `777`/`999`.
  * `401 Unauthorized` / `403 Forbidden`: as above.

#### Response Example (200 OK)
```json
{
  "status": "ok",
  "extension": "1001",
  "trigger": "busy",
  "target": "1002"
}
```

---

### `POST /api/group`
Creates, updates, or deletes a ring/hunt group.

* **Requires Same-Origin Check**: Yes
* **Requires `pd_session` cookie**: Always (see §0)
* **Request Content-Type**: `application/x-www-form-urlencoded`
* **Request Parameters**:
  * `extension` (Required): The group's own extension number. Must not be `777` or `999`.
  * `members` (Optional): Comma/space-separated member extensions. An empty list deletes the group.
  * `mode` (Optional): `ringall` (default) or `hunt`.
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`
  * `400 Bad Request`: `extension` missing, `extension` is `777`/`999`, or `mode` is not `ringall`/`hunt`.
  * `401 Unauthorized` / `403 Forbidden`: as above.

#### Response Example (200 OK)
```json
{
  "status": "ok",
  "extension": "700",
  "mode": "ringall",
  "members": "1001,1002,1003"
}
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
> `POCKETDIAL_MAX_ANCHOR_CALLS` is **1** (`src/SIP/PoolConfig.hpp:199`): one outside call
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
Content-Length: 36

pattern=2XX&action=group&target=610
```

#### Response Example (200 OK)
```json
{
  "status": "ok",
  "pattern": "2XX",
  "action": "group",
  "target": "610"
}
```

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

* **Response Status Codes**:
  * `200 OK`: Slot written. Body is `{"status":"ok","slot":{…}}` with the same slot shape as the `GET`.
  * `400 Bad Request`: Slot index out of range, a field over its length cap, or an enabled slot missing a required field. The body carries the specific reason.
  * `401 Unauthorized` / `403 Forbidden`: as above.

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

* **Response Status Codes**:
  * `200 OK`: `{"status":"ok","activeIndex":0}`
  * `400 Bad Request`: Slot index out of range, or the slot cannot be activated.
  * `401 Unauthorized` / `403 Forbidden`: as above.

---

### `POST /api/telephony-config/<slot>/test`

The dashboard Interconnect module's **Test Dial**. A connectivity probe, not a bridged
call: it self-dials the active slot's own `routeDn` through the anchor client and drops
it immediately (`HttpServer.cpp:1598`). It **does** place a real call at the provider,
so it is a mutating action and takes the full gate.

Refuses any slot that is not the currently-active one — only that slot has a live,
boot-selected anchor client behind it.

Always answers `200`; success lives in the body, because a failed probe is a normal
diagnostic result rather than an HTTP error:

```json
{ "ok": true, "participantId": "42" }
```
```json
{ "ok": false, "error": "no anchor client connected" }
```

`participantId` is the provider's id for the leg that was just placed and dropped, and
may be an empty string if the provider returned none. The failure `error` is one of
*"this slot is not the active one — activate it and reboot first"*, *"no anchor client
connected"*, *"anchor declined makeCall"*, or *"no handler attached"* (the SIP engine has
not bound to the dashboard yet — see [`GET /api/registrar`](#get-apiregistrar)'s
`attached`).

---

### `DELETE /api/telephony-config/<slot>`

Clears one slot, including its stored secret, so an operator can remove a credential
without a full factory reset. Responds `{"status":"ok","slot":{…}}` with the now-empty
slot, or `400` if the index is out of range.

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

---

### `PUT /api/did-mapping`

Creates or updates one mapping. Form-encoded.

* **Request Parameters**:
  * `did` (Required): The literal route DN. Max 32 characters, and must not contain CR, LF or `=` — the persisted record is `=`-delimited, so a smuggled separator would corrupt the table on the next load (`DidMapping::fieldValid`). Otherwise unrestricted: a leading `+` is allowed here, unlike dial-plan tokens.
  * `extension` (Required): The extension to ring. Max 32 characters, and only letters, digits, `#` and `*` — the same charset gate `/api/dialplan` applies to a pattern or target.
* **Response Status Codes**:
  * `200 OK`: `{"status":"ok","did":"8000","extension":"1001"}`
  * `400 Bad Request`: `did` or `extension` missing; `extension` outside `[0-9A-Za-z#*]`; `extension` is one of the reserved virtual extensions `777`, `999`, `555`, `888` or `440` (none of them is a real endpoint a DID could usefully ring); a field over 32 characters or containing CR, LF or `=`; or the table is full and this is a new DID. Updating an existing DID never consumes a slot, so it succeeds even on a full table.
  * `401 Unauthorized` / `403 Forbidden`: as above.

---

### `DELETE /api/did-mapping`

Removes one mapping. Form-encoded, parameter `did`. **Idempotent** — removing a DID that
was never mapped is still `200`, so there is nothing to branch on client-side.

* **Response Status Codes**:
  * `200 OK`: `{"status":"ok","did":"8000"}`
  * `400 Bad Request`: `did` missing.
  * `401 Unauthorized` / `403 Forbidden`: as above.

---

### `POST /api/configuring`
Tells the device a user is actively working through setup, pausing the captive-portal watchdog that would otherwise auto-switch the device back to Standalone AP mode. It mutates device state, so it takes the standard gate — same-origin, a `pd_session` cookie and an `X-CSRF` token — like every other mutating route (`HttpServer.cpp:606`).

* **Requires Same-Origin Check**: Yes
* **Requires `pd_session` cookie**: Always (see §0)
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`
  * `401 Unauthorized` / `403 Forbidden`: as above.

#### Response Example (200 OK)
```json
{
  "status": "ok",
  "message": "Setup mode held — auto-switch to Standalone paused."
}
```

---

### `POST /api/factory-reset`
Clears the login credential, the DTMF PIN, all live sessions, the carrier-API credential table (`tapicfg`), the DID→extension table (`didmap`), the CDR call-history ring (`cdrlog`), and Wi-Fi/mode NVS state, returning the device to its default-credential/needs-initial-setup captive-portal state, then reboots. **ESP-only** for the reboot — returns `501` on the desktop build (no reboot to perform, and the process must keep running for the test harness), but every wipe above runs unconditionally before that platform check, so it is fully host-testable.

* **Requires Same-Origin Check**: Yes
* **Requires `pd_session` cookie**: Always (see §0)
* **Request Content-Type**: `application/x-www-form-urlencoded`
* **Request Parameters**:
  * `confirm` (Required): Must be the literal string `ERASE`. Guards against an accidental/stray POST wiping the device.
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK` (ESP32): Credential and NVS state cleared, reboot scheduled.
  * `400 Bad Request`: `confirm` is missing or not `ERASE`.
  * `401 Unauthorized` / `403 Forbidden`: as above.
  * `501 Not Implemented` (desktop): Factory reset is not available off-device.

#### Response Example (200 OK, ESP32)
```json
{
  "status": "ok",
  "message": "Factory reset. Rebooting to captive-portal setup..."
}
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
| `otaSupported` | Boolean | `false` on the desktop build (no ESP32 partition table). |
| `error` | String | Reserved for a future error surface; currently always `""`. |

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
  * `501 Not Implemented` (desktop): OTA is not available off-device. The body is still drained so the client's upload completes cleanly rather than being reset mid-stream.

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

---

### `POST /api/ota/reboot`
Reboots into the image staged by a prior `/api/ota/upload`. **ESP32**: refuses if there is no pending image (the boot and running partitions already match). **Desktop**: always returns a simulated success without exiting the process, so the smoke-test harness keeps running.

* **Requires Same-Origin Check**: Yes
* **Requires `pd_session` cookie**: Always (see §0)
* **Request Headers**: None
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`: Reboot scheduled (ESP32) or simulated (desktop).
  * `401 Unauthorized` / `403 Forbidden`: as above.
  * `409 Conflict` (ESP32): No pending OTA image to boot into.

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
