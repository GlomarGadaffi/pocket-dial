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
| `/api/admin/status` | `GET` | None | `{provisioned, needsSetup, authenticated}` booleans for dashboard render. `provisioned`/`needsSetup` are inverses of each other and describe the login credential only. |
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

### Security Response Headers
Every API response returned by the server includes the following HTTP headers:
```http
Content-Type: application/json (or text/html for static files)
Content-Length: <byte_count>
Connection: close
```
> [!IMPORTANT]
> **CORS Restrictions**: No `Access-Control-Allow-Origin` headers are sent. Wildcard CORS is prohibited to prevent background malicious browser tabs from reading internal VoIP station mappings.

---

## 2. Security & Same-Origin Verification (CSRF Protection)

To prevent Cross-Site Request Forgery (CSRF) exploits when operating as an open Wi-Fi network, the server implements strict Same-Origin Verification on all state-mutating endpoints (`/api/kill`, `/api/wifi/connect`, `/api/wifi/mode_ap`):

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
working. On a **provisioned** device that gap is closed by a per-session CSRF token:

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
| Any request while **unprovisioned** | A factory-fresh device has no session. Demanding a token would make the device unclaimable and would break captive-portal onboarding. |
| All `GET` endpoints | Reads are not state changes. They are still same-origin checked and, where sensitive, session-gated. |

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
> `HttpServer::requireAdmin()`: same-origin, plus — once the device is provisioned — a
> valid `pd_session` cookie, plus (for mutating requests) a matching `X-CSRF` token.
> While the device is **unprovisioned** the session and token checks are skipped so
> onboarding remains possible (§2.1). Endpoints marked "None" are read-only and
> intentionally reachable without a session.

| Endpoint | Method | Security Level | Auth Required | Description |
| :--- | :---: | :---: | :---: | :--- |
| [`/`](#get-) | `GET` | Low | None | Serves the web dashboard HTML interface. |
| [`/api/status`](#get-apistatus) | `GET` | Low | None | Retrieves registrar uptime, packet statistics, active extensions, and ongoing sessions. |
| [`/api/kill`](#post-apikill) | `POST` | High | Gated (+ `X-CSRF`) | Forcefully disconnects and de-registers an active SIP extension. |
| [`/api/cdr`](#get-apicdr) | `GET` | Low | None | Returns the in-memory Call Detail Record ring (most recent calls, newest first). |
| [`/api/pcap`](#get-apipcap) | `GET` | Medium | Gated (same-origin + session once provisioned) | Downloads the last `POCKETDIAL_PCAP_RING_SIZE` SIP signaling packets as a `.pcap` (Wireshark-readable). |
| [`/api/diagnostics/pcap`](#get-apipcap) | `GET` | Medium | Gated (same-origin + session once provisioned) | Alias for `/api/pcap` (Issue #33's originally-requested path) — identical response, same ring, same gate. |
| [`/api/trace`](#get-apitrace) | `GET` | Medium | Gated (same-origin + session once provisioned) | The same capture ring as JSON, for the dashboard's polling live SIP tracer. |
| [`/config/<mac>.cfg`](#get-configmaccfg) | `GET` | Low | None (MAC is the bearer token) | Yealink auto-provisioning config for an already-adopted device. |
| [`/api/dnd`](#post-apidnd) | `POST` | High | Gated (+ `X-CSRF`) | Sets or clears Do-Not-Disturb on an extension. |
| [`/api/forward`](#post-apiforward) | `POST` | High | Gated (+ `X-CSRF`) | Configures call forwarding (`always`/`busy`/`noanswer`) for an extension. |
| [`/api/group`](#post-apigroup) | `POST` | High | Gated (+ `X-CSRF`) | Creates, updates, or deletes a ring/hunt group. |
| [`/api/dialplan`](#post-apidialplan) | `POST` | High | Gated (+ `X-CSRF`) | Creates, updates, or deletes one dial-plan rule (pattern → action). |
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
| `dialplan` | Array | The dial-plan rule table (Issue #69), **in evaluation order** — first match wins, so this array's order is load-bearing. |
| `dialplan[].pattern` | String | The dialed-number pattern (see [`POST /api/dialplan`](#post-apidialplan) for the grammar). |
| `dialplan[].action` | String | `group`, `page`, or `park`. |
| `dialplan[].target` | String | The group / paging-zone / park-orbit extension the rule routes to. |

---

### `POST /api/kill`
Disconnects a specified VoIP station, removing its registration and terminating any active calls involving its extension.

* **Requires Same-Origin Check**: Yes
* **Requires `pd_session` cookie**: Once the device is provisioned (see §0)
* **Request Content-Type**: `application/x-www-form-urlencoded`
* **Request Parameters**:
  * `extension` (Required): The registration extension number to disconnect.
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`: Target extension disconnected.
  * `400 Bad Request`: Parameter `extension` is missing or empty.
  * `401 Unauthorized`: Device is provisioned and the request carries no valid session.
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
* **Requires `pd_session` cookie**: Once the device is provisioned (see §0)
* **Request Content-Type**: `application/x-www-form-urlencoded`
* **Request Parameters**:
  * `ssid` (Required): SSID of the target network.
  * `password` (Optional): Password of the target network.
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`: Credentials stored, reboot scheduled.
  * `400 Bad Request`: Parameter `ssid` is missing.
  * `401 Unauthorized`: Device is provisioned and the request carries no valid session.
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
* **Requires `pd_session` cookie**: Once the device is provisioned (see §0)
* **Request Headers**: None
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`: Storage committed, reboot scheduled.
  * `401 Unauthorized`: Device is provisioned and the request carries no valid session.
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

* `attached` — `false` when the SIP engine has not been bound to the dashboard yet (an
  unprovisioned device holds SIP dark until a credential exists). A normal transient
  state, not an error; `mode` reads `"unknown"` and `devices` is empty.
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
Downloads a classic libpcap file of the most recent SIP signaling packets, ready to open directly in Wireshark. Both directions are captured (packets the server received and packets it sent); RTP/media is never included — pocket-dial brokers RTP peer-to-peer and never relays it, so there is nothing server-side to capture for a call's media.

Captured packets are synthesized into a minimal Ethernet+IPv4+UDP frame around the exact SIP bytes (dummy MAC addresses — the server has no real link-layer information — but real source/destination IP:port), so Wireshark's SIP dissector decodes them exactly as it would a real capture. Timestamps are relative to the server's monotonic clock, not wall-clock (no RTC is guaranteed on the device — same basis as `/api/cdr`'s `startMs`).

Only packets that pass structural validation and the per-source-IP rate limiter (Issue #38) are captured — this is a signaling-research aid, not a wire-level DoS forensics tool. The ring is bounded (`POCKETDIAL_PCAP_RING_SIZE`, default 64); older packets are dropped as new ones arrive.

* **Requires `pd_session` cookie**: Once the device is provisioned (see §0). No same-origin check — this is a plain file download, not a state-mutating action, and `SameSite=Strict` on the session cookie already prevents a cross-site page from riding an admin's session to reach it.
* **Request Headers**: None
* **Response Content-Type**: `application/vnd.tcpdump.pcap`
* **Response Headers**: `Content-Disposition: attachment; filename="pocket-dial.pcap"`
* **Response Status Codes**:
  * `200 OK`: Always — an empty/never-populated ring still returns a valid (headers-only) `.pcap`.
  * `401 Unauthorized`: Device is provisioned and the request carries no valid session.

`GET /api/diagnostics/pcap` is a second route to this exact same handler — the path Issue #33's original feature request asked for — kept as a route rather than a redirect so `curl -o dump.pcap http://<device>/api/diagnostics/pcap` works without `-L`. Identical response, ring, and gate; use whichever path you like.

---

### `GET /api/trace`
Returns the same capture ring as `/api/pcap`, as JSON, for the dashboard's live SIP tracer panel. Returns the **whole current ring on every call** rather than an incremental "since" delta — the ring is small (`POCKETDIAL_PCAP_RING_SIZE`, default 64) and this is meant to be polled every second or two on a LAN, so re-sending it is cheap and the server doesn't need to track any per-client polling state. The client filters to `seq` values it hasn't already rendered.

* **Requires `pd_session` cookie**: Once the device is provisioned (see §0). Same sensitivity/gate as `/api/pcap` — it's the same underlying data.
* **Request Headers**: None
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`
  * `401 Unauthorized`: Device is provisioned and the request carries no valid session.
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

Only serves configs for MACs already in the Registrar's adopted-device registry (Learn or Secure mode — see `docs/SCALING.md`/`Registrar.hpp`), so this covers **re**-provisioning (factory reset, handset swap, config refresh) rather than a phone's very first-ever contact: that first REGISTER is what gets a MAC adopted in the first place, and still needs the phone told its own extension number by some other means (typically typed once on the handset, or carried over from a previous config). Every subsequent boot can fetch this URL and get the account/server/codec settings back with no typing.

Intentionally **not session-gated** — a booting phone has no way to present a session cookie. The MAC is the only credential this endpoint checks: it's drawn from a 2^48 space and only ever served for a MAC that's already adopted, so guessing is impractical, and both an unknown MAC and a not-yet-adopted one return the same `404` (no distinguishing information). Like every other endpoint, it's still subject to the dark-by-default transport gate (§0) — the HTTP plane has to actually be open (e.g. via the DTMF trigger) for a phone to reach it, exactly as OTA upload requires.

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
> Not verified against a physical Yealink handset in this session — the key names/syntax above follow Yealink's long-stable, widely-documented auto-provisioning key set, but treat as best-effort until confirmed on real hardware.

---

### `POST /api/dnd`
Sets or clears Do-Not-Disturb on a registered extension.

* **Requires Same-Origin Check**: Yes
* **Requires `pd_session` cookie**: Once the device is provisioned (see §0)
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
* **Requires `pd_session` cookie**: Once the device is provisioned (see §0)
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
* **Requires `pd_session` cookie**: Once the device is provisioned (see §0)
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

Rules are evaluated **in table order, first match wins**. A pattern already in the
table is edited **in place**, keeping its evaluation position; a new pattern is
appended to the end. To reorder, delete a rule and re-add it. The table is hard-capped
at `POCKETDIAL_MAX_DIAL_RULES` (**16** by default, see `src/SIP/PoolConfig.hpp`);
once it is full a *new* pattern is rejected server-side (logged, still `200`), while
existing rules stay editable.

The plan is consulted **after** every reserved virtual extension (`777`, `999`,
`440`, the `980`–`989` paging zones, the `700`–`70N` park orbits) and after a direct
ring-group extension lookup, and **before** call-forwarding / DND / ordinary
extension lookup. So a rule can only capture a number that would otherwise have
reached the ordinary extension lookup — no rule, not even a catch-all `*`, can
shadow the echo test, a park retrieval, or a configured group extension. **A dialed
number that matches no rule routes exactly as it did before the dial plan existed.**

**Pattern grammar** (deliberately tiny — no regex):

| Token | Meaning |
| :--- | :--- |
| digits / letters / `#` / `*` | Match themselves, literally. |
| `X` or `x` | Match exactly one digit (`0`–`9`). |
| a **trailing** `*` | Match the rest of the dialed number, including nothing at all (prefix match). |

A `*` anywhere but the last character is a **literal** `*`, because star-codes
(`*8`, `*4887`) are real dialable strings on this device. Examples: `601` (exact),
`6XX` (any three-digit number starting with 6), `6*` (any number starting with 6),
`*` (catch-all), `*8` (the literal star-code).

* **Requires Same-Origin Check**: Yes
* **Requires `pd_session` cookie**: Once the device is provisioned (see §0)
* **Request Content-Type**: `application/x-www-form-urlencoded`
* **Request Parameters**:
  * `pattern` (Required): The rule's dialed-number pattern, and its key in the table. May contain only letters, digits, `#` and `*`. Must not be `777`, `999` or `440` — those are routed before the dial plan, so such a rule could never fire.
  * `action` (Optional, default `group`): `group` (ring/hunt group), `page` (paging zone), or `park` (park orbit).
  * `target` (Optional): The extension the action routes to — a ring-group extension for `group`, a `980`–`989` zone for `page`, a `700`–`70N` orbit for `park`. **An empty `target` deletes the rule with that pattern.**
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`
  * `400 Bad Request`: `pattern` missing, `pattern`/`target` contains a character outside `[0-9A-Za-z#*]`, `pattern` is a reserved extension, `action` is not `group`/`page`/`park`, or the `target` is the wrong shape for the action.
  * `401 Unauthorized` / `403 Forbidden`: as above.

> [!NOTE]
> A rule whose target no longer resolves — a group or zone deleted after the rule
> was written — is answered `404 Not Found` at dial time rather than falling
> through, so a stale rule fails visibly instead of silently ringing whichever real
> extension happens to share the dialed digits.

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

### `POST /api/configuring`
Tells the device a user is actively working through setup, pausing the captive-portal watchdog that would otherwise auto-switch the device back to Standalone AP mode. No same-origin gate — the action is harmless (it only extends a grace window, and cannot mutate credentials or network state).

* **Request Headers**: None
* **Response Content-Type**: `application/json`
* **Response Status Codes**:
  * `200 OK`

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
* **Requires `pd_session` cookie**: Once the device is provisioned (see §0)
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
* **Requires `pd_session` cookie**: Once the device is provisioned (see §0)
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
* **Requires `pd_session` cookie**: Once the device is provisioned (see §0)
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
