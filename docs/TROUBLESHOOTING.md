# Troubleshooting Runbook

Symptom → likely cause → fix. Work top-down within each section. Where a fact comes from
the firmware or another doc, it is cited so you can verify.

Quick references: [SETUP_GUIDE.md](SETUP_GUIDE.md) ·
[PHONE_COMPATIBILITY.md](PHONE_COMPATIBILITY.md) · [HARDWARE_SELECTION.md](HARDWARE_SELECTION.md) ·
[API.md](API.md) · [OTA.md](OTA.md) · [LEARN_MODE.md](LEARN_MODE.md) ·
[THREAT_MODEL.md](THREAT_MODEL.md)

> [!IMPORTANT]
> **What a board out of the box actually looks like — check this before triaging anything.**
> * **The dashboard is always reachable on port 80.** The HTTP listener accepts
>   unconditionally, on every build and in every provisioning state. There is no
>   dark-by-default management plane and no DTMF star-code to reopen one — both were
>   removed. *Connection refused* on port 80 is now always a genuine fault
>   ([API.md §0](API.md); pinned as a regression by
>   `tests/AdminHttpGate_test.cpp`, `AdminHttpGate.Boot_Provisioned_StillListensImmediately`).
> * **The admin credential is a username + password**, not a PIN, and the device **ships
>   with `admin`/`admin`** (`AdminAuth::kDefaultUsername`/`kDefaultPassword`). Until you
>   replace it via `POST /api/admin/set-credential`, every admin-gated route — gated `GET`s
>   included — answers `403 {"error":"setup_required"}`
>   (`HttpServer::requireAdmin()`, `src/Helpers/HttpServer.cpp:1864-1873`). See
>   [Everything returns 403 setup_required](#everything-returns-403-setup_required).
> * **A separate numeric DTMF PIN** exists for the phone-keypad admin menu (`*PIN#code`).
>   It has **no** default, so that menu is unreachable until one is explicitly set. It is
>   unrelated to the web session.
> * **On a `wifi`, `eth` or `lan8720` board that has never been set up, SIP does not start
>   at all** until a credential is committed (`main/esp_main.cpp:375`,
>   `main/esp_main_eth.cpp:468-496`, `main/esp_main_eth_lan8720.cpp:424`). A dead port 5060
>   with a live port 80 is that gate, not a fault — see
>   [Phone won't register](#phone-wont-register-timeout-or-401). The **`display`** build
>   deliberately has no such gate and starts SIP unconditionally
>   (`main/esp_main_display.cpp:799-806`).
> * **The registrar ships in `open` mode**: any phone may REGISTER and any INVITE is
>   accepted, with no SIP authentication. Digest auth is fully implemented (RFC 2617) but
>   it is *off* until an operator moves the registrar to `learn` or `secure`.
> * The SoftAP is **open** by default, the dashboard is **plain HTTP**, and OTA images are
>   **unsigned**. All three are deliberate defaults, not oversights.

---

## Access-point not visible

**Symptom:** The `esp32-sipserver` Wi-Fi network does not appear in your client's Wi-Fi list.

| Cause | Fix |
| :--- | :--- |
| Device not powered / still booting | Confirm power (USB-C or PoE). Watch the serial monitor (`idf.py monitor`) for `wifi_init_softap finished. SSID:esp32-sipserver` (`main/esp_main.cpp`). |
| This is a **wired Ethernet** build | `SIP_TRANSPORT=eth` boards have **no SoftAP** — they join your wired LAN. Reach the dashboard at the device's LAN IP / `pocketdial.local` (see [HARDWARE_SELECTION.md](HARDWARE_SELECTION.md)). |
| Device is in **Station mode** | If Wi-Fi was configured to join an existing network (`/api/wifi/connect`), it is a client, not an AP. Factory-reset to return to AP/onboarding (see [Forgot the admin password](#forgot-the-admin-password)). |
| Display build sitting in onboarding | The display variant's onboarding AP is **`My-Ap`**, not `esp32-sipserver` (`ONBOARDING_SSID`, `main/esp_main_display.cpp`). Look for `My-Ap`. |
| 2.4 GHz only | The ESP32 SoftAP is 2.4 GHz, channel 1. Ensure your client shows 2.4 GHz networks. |

> The network being *visible but locked* is a different problem — see the next section.

---

## Can't join the Wi-Fi network any more

**Symptom:** `esp32-sipserver` (or `My-Ap`) is in the list but your client asks for a
password, or rejects the one you have.

The SoftAP can be **WPA2-PSK** instead of open. It is **off by default** and stays off
across a firmware update — someone turned it on, or it was set at flash time.

| Cause | Fix |
| :--- | :--- |
| AP security was enabled | Read the passphrase off the device (table below) and join with it. Confirm the setting with `GET /api/ap-security` → `{"secure":true,"psk":"…"}` ([API.md](API.md#get-apiap-security)), or the boot log line `SoftAP SSID:esp32-sipserver … auth:WPA2-PSK` (`main/esp_main.cpp`). |
| The passphrase was rotated | Rotating drops every associated client. Read the current value again — the old one is gone and is not recoverable. |
| It was set by the browser flasher | The flash-time `cfgseed` record can carry the passphrase. Whoever flashed the board has it. |
| Wrong/ambiguous characters typed | The generated passphrase is 20 chars from an alphabet with **no** `0`, `O`, `1`, `I`, `L` or `U` (`DeviceConfig.hpp`). If you read a `0` or a `1` off a screen, it is an `O`-lookalike misread — recheck. |
| Display build's onboarding AP | **`My-Ap` is WPA2 too**, using the same per-device passphrase (`wifi_init_softap(ONBOARDING_SSID, g_apPsk, false)`, `main/esp_main_display.cpp`). It is shown on the LVGL onboarding screen next to the SSID. It is no longer the old hardcoded `12345678`. |

**Where the passphrase is** — the device generates its own, per unit; there is no factory
default and nothing is baked into the image ([SETUP_GUIDE.md](SETUP_GUIDE.md#turning-on-access-point-security-wpa2)):

| Build | Where it appears |
|-------|------------------|
| `display` | On the LVGL screen during captive-portal onboarding |
| `wifi` (headless) | Serial boot log: `INFRA: SoftAP passphrase (WPA2): …` (`idf.py monitor`) |
| Any | `GET /api/ap-security` / the dashboard's *Wi-Fi Access Point Security* panel, once logged in as admin |
| Any | The browser flasher, if it was set at flash time |

> [!WARNING]
> On a headless `wifi` board with AP security on, no admin password you remember, and
> nobody on the AP, the only ways back are a **serial console** (the passphrase is logged
> at every boot) or a **re-flash**. Read the passphrase before you need it.

The `eth` build has no SoftAP at all, so none of this applies to it.

---

## Captive portal won't open

**Symptom:** You joined `My-Ap` (display build) but no setup page appears.

| Cause | Fix |
| :--- | :--- |
| Never actually associated | `My-Ap` is **WPA2**, keyed with the device's own generated passphrase shown on the onboarding screen (`main/esp_main_display.cpp`). If your client silently failed to join, there is no portal to open — see [Can't join the Wi-Fi network](#cant-join-the-wi-fi-network-any-more). |
| OS captive-portal prompt missed | Manually browse to `http://192.168.4.1/`. The device returns a `302` redirect to the portal for any off-host request ([API.md §3](API.md)). |
| The 5-minute decay window elapsed | The portal has a **300 s decay watchdog** (`CAPTIVE_DECAY_SECONDS`, `main/esp_main_display.cpp`): with no confirmed config it reboots into Standalone AP. Re-join **`esp32-sipserver`** and use `http://192.168.4.1`. |
| `401`/`403` from `POST /api/configuring` | That route is now gated like every other mutating route (`HttpServer.cpp:606-618`). The portal's "I'm still configuring" hold needs a logged-in session — log in with `admin`/`admin` and complete setup first. |
| Browser cached HTTPS / HSTS | Use a fresh `http://` URL (not `https://`), or try a private window. The dashboard is HTTP only. |
| DNS not redirecting | The onboarding DNS responder answers all names with the device IP (port 53). If your client uses DNS-over-HTTPS, type the IP `192.168.4.1` directly. |

---

## Phone won't register (timeout or 401)

**Symptom:** The SIP client never reaches "registered", times out, or shows an error.

| Cause | Fix |
| :--- | :--- |
| **Nothing at all on port 5060, on a `wifi`/`eth`/`lan8720` board you have never set up** | **The boot provisioning gate.** `app_main()` starts the HTTP dashboard immediately but holds the SIP task down until an admin credential is committed — serial log `[boot] device unprovisioned — SIP stack held dark until credential committed` (`main/esp_main.cpp:375`, `main/esp_main_eth.cpp:468-496`, `main/esp_main_eth_lan8720.cpp:424`). Log in at `http://<device>/` with `admin`/`admin`, complete setup, and watch for `[boot] credential set — unblocking SIP stack`. The wait is bounded: 30 minutes with no credential and the board reboots to retry. **The `display` build has no such gate** — it is deliberately "up usable, secure later" and starts SIP unconditionally (`main/esp_main_display.cpp:799-806`), so on a display board a dead 5060 is a real fault. |
| Wrong server/port/transport | Server `192.168.4.1`, port `5060`, transport **UDP** (the engine is UDP-only). See [PHONE_COMPATIBILITY.md](PHONE_COMPATIBILITY.md). |
| Not on the device's network | Confirm the phone has a `192.168.4.x` lease (SoftAP) or can reach the device's LAN IP (wired). |
| TCP/TLS selected | Switch the client to **UDP**. There is no TCP/TLS listener, and no SIPS/TLS signalling of any kind. |
| Using a reserved extension | `777` (echo), `440` (tone), `555` (anchor bridge), `888` (conference), `999` (all-page), `700`–`709` (park orbits) and `980`–`989` (paging zones) are intercepted by the PBX before an INVITE ever reaches a registered client. The REGISTER itself is not refused, so the phone may look "registered" while being uncallable. Pick another (e.g. `1001`). |
| `503 Service Unavailable` on REGISTER | The client pool is full. `allocateClient()` evicts the oldest *expired* binding, else returns `503`; the phone retries on its refresh timer. Raise the tier ([SCALING.md §4](SCALING.md)). |
| Client pruned after registering | The registrar prunes a client after ~15 s of silence if it ignores the `OPTIONS` keepalive sent every 5 s (`RequestsHandler.cpp`). Enable the phone's keep-alive / answer-OPTIONS option. |
| Rate-limited (packets dropped) | The SIP UDP path uses a per-source-IP token bucket (burst 40, 20 pkt/s sustained). A flooding or misconfigured client gets packets dropped; watch `packetsDropped` on `/api/status` ([ARCHITECTURE.md §5](ARCHITECTURE.md)). |
| Registrar is in `secure` mode | Every `REGISTER` is digest-challenged and this phone has no secret, or its MAC does not match the one the extension is locked to. See [All phones stopped registering at once](#all-phones-stopped-registering-at-once). |
| Registrar is in `learn` mode and the extension is already claimed | Learn mode locks an extension to the first MAC that claims it. A second phone on the same extension is refused. `POST /api/registrar/device` with `action=forget` releases the adoption so the new hardware can claim it ([API.md](API.md#post-apiregistrardevice)). |

> [!NOTE]
> **What a `401` on REGISTER means depends on the registrar mode.** Check it first:
> `GET /api/registrar` returns `{"mode":"open"|"learn"|"secure", …}` ([API.md](API.md#get-apiregistrar)).
> That `GET` needs a session (and completed setup), but no `X-CSRF`.
> * **`open`** (the shipped default) — there is no SIP authentication at all, so a `401`
>   is *not* from pocket-dial. It is almost always the phone's own account dialog, or,
>   separately, the **HTTP admin** gate (`/api/admin/*`), a different subsystem.
> * **`learn`** — already-secured devices are digest-challenged; unknown MACs are adopted
>   on first contact without a credential.
> * **`secure`** — a `401` with `WWW-Authenticate: Digest …` is real SIP digest auth
>   (RFC 2617, MD5). The phone needs the extension's secret set on the handset.
>
> In `secure` mode **INVITE is digest-challenged too**, not just REGISTER
> (`RequestsHandler::onInvite()` calls `Registrar::admitSecure()`,
> `src/SIP/RequestsHandler.cpp:1195-1206`). In-dialog requests (BYE, re-INVITE, REFER) are
> not independently challenged; they are instead checked against the dialog's known leg
> addresses — see [Calls drop unexpectedly](#calls-drop-unexpectedly).

---

## All phones stopped registering at once

**Symptom:** Every handset drops to "not registered" simultaneously, with no power, cabling
or Wi-Fi change. New registrations are refused.

**Almost always:** someone switched the SIP registrar to **`secure`** before any extension
had been adopted and secured. In `secure` mode every `REGISTER` is digest-challenged, and a
fleet that has never been through `learn` mode has no secrets to answer with — so all of
them fail at once ([LEARN_MODE.md](LEARN_MODE.md) §1).

**Confirm it** (a `GET`, so no `X-CSRF` — but it *is* session-gated, so log in first and
reuse the cookie jar; the recipe is in
[403 on an API call that used to work](#403-on-an-api-call-that-used-to-work)):

```bash
curl -s -b "$JAR" http://192.168.4.1/api/registrar
# -> {"attached":true,"mode":"secure","devices":[]}
```

An empty (or all-`learned`) `devices` array with `"mode":"secure"` is the diagnosis. A bare
`curl` with no cookie returns `401` here — that is the admin gate, not a clue about the
registrar.

**Recover.** This is now a comfortable recovery, not a race: the dashboard is always
reachable, so you have as long as you need.

1. **Put the registrar back.** Log in, then:
   ```bash
   curl -s -b "$JAR" -H "Origin: $DEVICE" -H "X-CSRF: $CSRF" \
        -X POST --data "mode=learn" "$DEVICE/api/registrar"
   ```
   Let the phones re-adopt, verify the roster, secure them individually
   (`POST /api/registrar/device`, `action=secure`), *then* go back to `secure`.
2. **If you cannot log in either** (lost password on top of the lockout), see
   [Forgot the admin password](#forgot-the-admin-password) — that path is a re-flash.

> [!IMPORTANT]
> **Corrected: `POST /api/factory-reset` *does* clear `reg_mode`.** Earlier revisions of
> this box said it did not — that the erase was issued on the `storage` namespace while
> the registrar reads `pbxcfg`. That was a real bug and it was **fixed in
> [#188](https://github.com/GlomarGadaffi/pocket-dial/issues/188)**:
> `DeviceConfig::clearAll()` now calls `eraseRegistrarMode()` (`DeviceConfig.cpp:698`),
> which opens `pbxcfg` — the same namespace `Registrar::loadMode()` reads — and the
> comment at `DeviceConfig.cpp:685-697` records exactly this. Note the erase sits
> *outside* the `storage` block on purpose, so it runs whether or not `storage` opened.
> This file already stated the corrected behaviour further down, in the factory-reset
> section; the two disagreed. **Source-verified; still not exercised on hardware.**
>
> `POST /api/registrar mode=open` remains the lighter-touch fix and is still the first
> thing to try — it changes one setting instead of wiping the box.
>
> Factory reset also **re-arms the flash-time seed.** Dropping `cfgseed_gen` means the next
> boot re-applies whatever the browser flasher wrote — which can include `regMode`
> (`DeviceConfig::applyFlashSeed()`). A board *seeded* `secure` comes back `secure` after
> both a factory reset and a bare NVS erase. To clear the seed you must re-flash it, or
> erase its sector (`erase_region 0xFFF000 0x1000` on the 16 MB layout). An NVS erase
> (`erase_region 0x9000 0x6000`) clears *every* namespace, `pbxcfg` included, so that path
> does return the registrar to `open`.

> [!TIP]
> **This is what the `409` guard is for.** `POST /api/registrar` with `mode=secure` while no
> extension is yet `secured` is refused:
> `{"error":"no extensions are secured yet; switching to secure now would reject every phone…"}`
> That is the firmware stopping you from doing exactly this, not a bug. Only override with
> `confirm=LOCKOUT` when you know a secured handset already exists.

---

## One-way or no audio

**Symptom:** The call connects (rings, answers) but you hear nothing, or only one side
hears audio.

> [!NOTE]
> **A codec mismatch is no longer a silent-audio symptom.** An INVITE whose SDP offers
> nothing this PBX will carry is now refused up front with
> `488 Not Acceptable Here` and `Warning: 304 <ip> "No compatible audio codec
> (PCMU/PCMA/G722)"` (`RequestsHandler::onInvite()`, `src/SIP/RequestsHandler.cpp:1177-1187`).
> If signalling *completed* and audio is dead, look past the codec.

What the media path actually is, because it decides where to look:

* An **ordinary extension-to-extension call is peer-to-peer**. The board relays the SDP but
  never touches the RTP — the phones stream directly to each other. Hold and transfer keep
  that property: only the codec list is narrowed, the `c=` connection line is never
  rewritten.
* **A call parked on an orbit is the exception.** With a music-on-hold clip loaded the board
  answers the parked leg `sendonly` from its own port and streams the clip to it, so board-side
  capture *will* show RTP for a parked call. With no clip loaded (the default) park answers
  `a=inactive` and the board sends nothing — which is also what you will see if the clip
  failed to load, so "parked caller hears silence" is a MoH-configuration symptom, not a
  media-path fault.
* **`777` (echo) also touches no RTP** — it is an SDP loopback, so the phone streams to
  itself. That makes it a test of *that one phone's* media path, not of the board's.
* **`440` (tone), `555` (anchor bridge) and `888` (conference) are server-terminated** — the
  board really does send and/or receive RTP for those.

| Cause | Fix |
| :--- | :--- |
| NAT/STUN/ICE enabled on the phone | For a peer-to-peer leg, media is **phone-to-phone on one L2 segment**. NAT traversal rewrites the SDP connection address and breaks direct RTP. Turn STUN/ICE/rport **off**. |
| Client isolation on the AP | RTP is phone-to-phone; if SoftAP client isolation were enabled, stations couldn't reach each other and audio would fail (see [PROVISIONING.md §4.4](PROVISIONING.md) caveat). |
| Firewall between phones (wired) | On a wired LAN, ensure the segment allows station-to-station UDP for the RTP port range. |
| Codec narrowing on a relayed leg | Relayed peer-to-peer legs keep the endpoint's own payload list and order, dropping only what the PBX won't carry: **PCMU, PCMA and G.722** survive, plus `telephone-event` (`SipMessage::filterAudioCodecs()`, `src/SIP/SipMessage.hpp:101-110`). A G.722-capable pair negotiates wideband on their own. |
| Wideband offered to a server-terminated leg | The server-terminated extensions are **PCMU-only**. A caller offering nothing but G.722 gets `488` from those specifically, even though the same offer is fine for a two-phone call — the `777` gate spells the reasoning out at `RequestsHandler.cpp:1208-1228`. |
| A doc or script telling you to force "G.711 only" | Stale advice. `enforceG711()` still exists in `SipMessage.cpp` but has **no production callers** — it is deprecated, and its old blanket `0 8 101` rewrite is exactly the malformed-answer bug the current code avoids. Do not restrict handsets to µ-law/a-law on its account. |
| Verify with `777` | Dial **`777`**: if echo works but a two-party call does not, the problem is between the two phones (NAT/isolation/firewall). If `777` itself is silent, it is that phone's own RTP path — the board is not in it. |

---

## Calls drop unexpectedly

**Symptom:** Established calls hang up on their own.

| Cause | Fix |
| :--- | :--- |
| Keepalive prune | A phone that stops answering `OPTIONS` is pruned after ~15 s (`RequestsHandler.cpp`); its calls end. Keep the phone's keep-alive on and Wi-Fi signal adequate. |
| Wi-Fi association lost | On a SoftAP node, a weak link drops the station. Check RSSI / reduce range. |
| Session pool exhausted | New INVITEs get `503` when the session pool is full; existing calls are untouched. Raise the tier ([SCALING.md §4](SCALING.md)). |
| Outbound trunk call ended at ~60 s of ringing with `480` | Not a fault. An outbound call through the anchor client gets its own no-answer window (`ANCHOR_NO_ANSWER_TIMEOUT`, 60 s) rather than the 20 s internal-extension constant, and the teardown answers **`480 Temporarily Unavailable`**, not `503`. |
| Admin force-disconnect | `POST /api/kill` de-registers an extension and tears down its calls ([API.md](API.md)). Check whether someone used the dashboard's kill control. |
| Spoofed BYE | A forged teardown from **off the call path** is now rejected `403`: a BYE for an established dialog must arrive from one of the call's leg IPs (`RequestsHandler::onBye()`'s `isDialogSourceAuthorized()` guard, `src/SIP/RequestsHandler.cpp:2918-2928`). What that does *not* stop is a peer who can source packets from a leg's address — on an open AP in `open` mode that is still reachable, so WPA2 on the SoftAP remains the real fix. In-dialog requests are not digest-challenged even in `secure` mode. |

---

## Dashboard unreachable

**Symptom:** `http://192.168.4.1` (or `pocketdial.local`) does not load.

| Cause | Fix |
| :--- | :--- |
| **Connection refused** | **A real fault now.** The listener accepts unconditionally in every provisioning state — there is no dark/open gate and nothing to "reopen". Check you are at the right IP and that nothing on your machine is filtering port 80. (`http_dashboard` is a FreeRTOS **task name** — on `eth`/`lan8720` only; the `wifi` build calls it `http_server_task` — and neither is printed at boot, so do not wait for a log line.) |
| Wrong scheme | Use **`http://`**, not `https://` — the dashboard is plain HTTP ([API.md §1](API.md)). There is deliberately **no** HSTS header, so a browser that once cached HTTPS for this host will not have been pinned by us ([API.md §2.2](API.md)). |
| mDNS not resolving | Browse to the raw IP `192.168.4.1` (SoftAP) or the device's LAN IP (wired). |
| Not joined to the device network | Re-check Wi-Fi association / DHCP lease. If the AP is now WPA2, see [Can't join the Wi-Fi network](#cant-join-the-wi-fi-network-any-more). |
| Slow-client / Slowloris timeout | The HTTP worker enforces a 5 s `SO_RCVTIMEO` and closes idle sockets ([ARCHITECTURE.md §4](ARCHITECTURE.md)); reload the page. |
| `413 Payload Too Large` | A request body over **16 KB** is rejected ([API.md §1](API.md)). Don't paste oversized Wi-Fi passwords. |
| `403 cross-origin request rejected` | A state-changing POST whose `Origin` host ≠ `Host` is blocked. Use the dashboard directly, or send a matching `Origin` from CLI ([API.md §2](API.md)). |
| `403 setup_required` | The board is still on `admin`/`admin`. See [the next section](#everything-returns-403-setup_required). |
| `403 missing or invalid CSRF token` | A **third** distinct 403 — see [403 on an API call that used to work](#403-on-an-api-call-that-used-to-work). |
| `401 authentication required` on a control action | You have no valid `pd_session`. Log in via `POST /api/admin/login` first ([SETUP_GUIDE.md §3](SETUP_GUIDE.md)). |
| `429` on login | Brute-force lockout — and it escalates. See [429 on login](#429-on-login) below. |
| Page renders but panels are blank | `GET /` and `/api/status` are ungated, as are `/api/cdr`, `/metrics`, `/api/wifi/scan`, `/api/admin/status`, `/api/ota/status` and `GET /config/<mac>.cfg`. `/api/pcap`, `/api/trace`, `/api/registrar`, `/api/telephony-config`, `/api/did-mapping` and `/api/moh` all need a session. A logged-out browser gets a rendered shell with `401`s underneath — the **PBX Settings** panel (`F6`) is one of them, since `/api/moh` is gated. |

---

## Everything returns `403 setup_required`

**Symptom:** You can load the page and you are logged in, but every action — including
read-only ones like `GET /api/registrar` — comes back:

```json
{ "error": "setup_required", "message": "Change the default admin credential before continuing." }
```

**This is forced first-use setup, working as designed.** The device ships with a well-known
default login so the dashboard is usable out of the box, and `HttpServer::requireAdmin()`
refuses everything except the one route that fixes that, until it is fixed
(`src/Helpers/HttpServer.cpp:1864-1873`). `GET /api/admin/status` tells you where you stand
without a session at all:

```bash
curl -s http://192.168.4.1/api/admin/status
# -> {"provisioned":false,"needsSetup":true,"authenticated":false,"sessionRemainingSec":0}
```

**Fix — log in with the default, then replace it:**

```bash
DEVICE=http://192.168.4.1
JAR=cookies.txt

LOGIN=$(curl -s -c "$JAR" -H "Origin: $DEVICE" \
     -X POST --data "username=admin&password=admin" "$DEVICE/api/admin/login")
CSRF=$(printf '%s' "$LOGIN" | sed -n 's/.*"csrf":"\([0-9a-f]*\)".*/\1/p')
[ -n "$CSRF" ] || { echo "login failed: $LOGIN" >&2; exit 1; }

curl -s -b "$JAR" -H "Origin: $DEVICE" -H "X-CSRF: $CSRF" \
     -X POST --data "username=admin&password=CHANGE-THIS-PASSWORD" \
     "$DEVICE/api/admin/set-credential"
# -> {"status":"ok","provisioned":true,"needsSetup":false}
```

- The password must be **≥ 8 characters** (`AdminAuth::kMinPasswordLength`); the username
  is 1–32 characters with no whitespace or control characters. A rejected pair returns
  `400 {"error":"invalid username or password"}` and changes nothing.
- `username` and `password` must be sent **together**; sending one alone is
  `400 {"error":"username and password must both be provided together"}`.
- The **session survives the credential change** — the same `$JAR`/`$CSRF` keep working,
  no second login needed.
- The optional `dtmfPin=` field (4–16 digits) sets the *separate* phone-keypad admin PIN.
  It has no default and the `*PIN#code` menu stays disabled until you set one. Sending
  `dtmfPin=` alone changes only that.

---

## `403` on an API call that used to work

**Symptom:** A `curl` recipe or script returns:

```json
{ "error": "missing or invalid CSRF token" }
```

with status `403`. The session cookie is fine — the request is missing the second half of
the gate.

**Cause.** Every **mutating** request has to echo a per-session **CSRF token** in an
`X-CSRF` header, checked centrally in `HttpServer::requireAdmin()` so no endpoint can skip
it ([API.md §0](API.md), [THREAT_MODEL.md](THREAT_MODEL.md) T-2). The `Origin` check
deliberately still admits requests with **no** `Origin` header at all — that is what keeps
`curl` and CI working — so the token is what actually proves the request came from
something that was *told* the token, rather than from a page that merely rode your cookie.

**Fix.** Capture the token from the login response and send it on every mutating call. The
login response body carries it as `"csrf"`:

```bash
DEVICE=http://192.168.4.1          # or http://pocketdial.local
JAR=cookies.txt

# 1) Log in: this returns BOTH the pd_session cookie and the session's CSRF token.
LOGIN=$(curl -s -c "$JAR" \
     -H "Origin: $DEVICE" \
     -X POST --data "username=admin&password=YOUR_PASSWORD" \
     "$DEVICE/api/admin/login")
# -> {"status":"ok","authenticated":true,"needsSetup":false,"csrf":"3f2a...e91c"}

CSRF=$(printf '%s' "$LOGIN" | sed -n 's/.*"csrf":"\([0-9a-f]*\)".*/\1/p')
[ -n "$CSRF" ] || { echo "login failed: $LOGIN" >&2; exit 1; }

# 2) Any mutating call now carries cookie + Origin + token.
curl -s -b "$JAR" -H "Origin: $DEVICE" -H "X-CSRF: $CSRF" \
     -X POST --data "extension=1001" "$DEVICE/api/kill"
```

The same three headers apply to `/api/dnd`, `/api/forward`, `/api/group`, `/api/dialplan`,
`/api/configuring`, `/api/wifi/connect`, `/api/wifi/mode_ap`, `/api/factory-reset`,
`/api/ap-security`, `/api/registrar`, `/api/registrar/device`, `/api/admin/set-credential`,
the `/api/telephony-config` and `/api/did-mapping` writes, and the OTA endpoints
([OTA.md §3.2](OTA.md) has the OTA-specific walk-through).

**When you do *not* need it:**

| Case | Why |
| :--- | :--- |
| `POST /api/admin/login` | No session exists yet to bind a token to. Same-origin checked only. |
| `POST /api/admin/logout` | Requiring one would strand a user on a stale page. Same-origin checked only. |
| Every `GET` | Reads are not state changes. The gated ones still need a session. |

There is **no longer** an "unprovisioned device needs no headers" exemption. The session
gate is unconditional from the first boot — that is what the shipped default credential
exists for (`HttpServer.cpp:1839-1851`).

> [!TIP]
> **Four rejections, four different problems, and the JSON body is what tells them apart:**
> `401 {"error":"authentication required"}` — no/expired session, log in.
> `403 {"error":"cross-origin request rejected"}` — `Origin` host ≠ `Host`.
> `403 {"error":"setup_required"}` — still on `admin`/`admin`.
> `403 {"error":"missing or invalid CSRF token"}` — session valid, token missing.
> Asserting on the status code alone cannot distinguish the three `403`s.

---

## `429` on login

**Symptom:** `POST /api/admin/login` returns `429 {"error":"too many failed attempts; try
again later"}` — sometimes even with the correct password, and sometimes for someone who
has not typed a wrong one at all.

Two counters can produce it (`AdminAuth.hpp:60-82`, [THREAT_MODEL.md §5.2](THREAT_MODEL.md)):

| Counter | Threshold | Cooldown |
| :--- | :--- | :--- |
| ~~**Per-client** — keyed on the HTTP peer address, 8 LRU buckets~~ **Effectively GLOBAL — see the note below the table.** | **5** consecutive failures (`kMaxFailedAttempts`) | 60 s (`kLockoutMs`), **doubling on each successive lockout**, capped at ~16 min (`kMaxLockoutShift = 4`) |
| **Aggregate backstop** — across *all* clients | **20** consecutive failures (`kMaxFailedAttemptsGlobal`) | Same doubling ladder, also up to ~16 min; locks out **everyone** |

What will surprise you:

- **The "per-client" bucket is not actually per-client.** `AdminAuth` implements per-client
  buckets and `HttpServer::handleClient()` even computes `peerIp` for them
  (`HttpServer.cpp:247-263`), but that value is only ever stored on the OTA request
  (`:330`). `parseRequest()` never populates `req.clientIp`, so `sendApiAdminLogin` hands
  `isLockedOut()` and `verifyCredential()` an **empty string** (`:2720`, `:2729`, `:2732`)
  and every failure — web login and DTMF PIN alike — lands in the one unkeyed bucket. **In
  practice there is a single global lockout**, so one guesser on the link can lock the real
  admin out after five wrong passwords, which is exactly what the per-client design was
  meant to prevent. Plan recovery around that (power-cycle clears it; see below), and see
  [THREAT_MODEL.md](THREAT_MODEL.md) D-3.
- **The cooldown does not reset the failure budget.** The trip count survives it, so a
  second lockout is 2 min, a third 4 min, and so on. Repeatedly retrying while locked out
  does not extend it, but each fresh set of 5 wrong passwords does.
- **Only a correct login clears it** — both counters.
- **The phone-keypad DTMF PIN shares the same bucket table.** `verifyDtmfPin()` uses the
  unkeyed `""` bucket, so hammering the `*PIN#` menu can lock out the web login and vice
  versa.
- **You can be locked out by someone else.** The aggregate counter sits far above ordinary
  fat-fingering, so hitting it without guessing means something on the link is hammering
  `/api/admin/login`.

**Fix:** wait it out — it always auto-clears and never permanently locks the device.
Existing sessions keep working throughout; only `login` is throttled, so another browser
still logged in is your fastest route back in. Failing that, **power-cycle**: the attempt
buckets live in a process-local static, not NVS, so a reboot clears every lockout without
touching the credential.

---

## Forgot the admin password

There is **no password recovery** — the password is stored only as a salted, iterated
SHA-256 hash (`AdminAuth.cpp`; NVS keys `admin_user` / `admin_pw_salt` / `admin_pw_hash`,
with the DTMF PIN separately in `admin_pin_salt` / `admin_pin_hash`). The path back to a
usable device is a **factory reset**, which clears the login credential *and* the DTMF PIN
and returns the board to the `admin`/`admin` default with `needsSetup` true again.

**If you still hold a valid session** (a browser somewhere is still logged in), use the
dashboard's **Factory Reset** button. That page already has the session's CSRF token
rendered into it — from the CLI you would have to log in again to obtain one, and logging in
needs the password you have lost.

The equivalent call, for when you *do* have the password and just want it scripted:

```bash
DEVICE=http://192.168.4.1
JAR=cookies.txt

LOGIN=$(curl -s -c "$JAR" -H "Origin: $DEVICE" \
     -X POST --data "username=admin&password=YOUR_PASSWORD" "$DEVICE/api/admin/login")
CSRF=$(printf '%s' "$LOGIN" | sed -n 's/.*"csrf":"\([0-9a-f]*\)".*/\1/p')

curl -s -b "$JAR" -H "Origin: $DEVICE" -H "X-CSRF: $CSRF" \
     -X POST --data "confirm=ERASE" \
     "$DEVICE/api/factory-reset"
# -> {"status":"ok","message":"Factory reset. Rebooting to captive-portal setup..."}
```

What a factory reset actually clears (`HttpServer::sendApiFactoryReset`,
`src/Helpers/HttpServer.cpp:2092-2150`):

- The `confirm=ERASE` token is **required** — without it the endpoint returns
  `400 {"error":"factory reset requires confirm=ERASE"}`.
- `AdminAuth::clearCredential()` — the login credential, the DTMF PIN, and all live
  sessions.
- `DeviceConfig::clearAll()` — `ap_secure`, `ap_psk`, `cfgseed_gen`, and `reg_mode`. The
  `reg_mode` erase used to go to the `storage` namespace instead of the `pbxcfg` one the
  registrar actually uses, so the admission mode survived a factory reset and a board left
  in `secure` could not be rescued without USB. Fixed in #188 — the write and the erase now
  go through `writeRegistrarMode()` / `eraseRegistrarMode()`, so the namespace is named in a
  single place.
- Via the handler: the Telephony-API credential slots (`tapicfg`), the DID→extension table
  (`didmap`) and the CDR call-history ring (`cdrlog`). These live in their own NVS
  namespaces and would otherwise survive.
- The Wi-Fi keys `wifi_mode` / `wifi_ssid` / `wifi_pass` / `decayed` — **only on a build
  that has Wi-Fi**, since `eth` / `lan8720` deliberately do not define
  `POCKETDIAL_HAS_WIFI` (`main/CMakeLists.txt:133-136`) and have no radio settings to
  erase. This is the only transport-specific part of the route.
- **Then a reboot, on every ESP build.** The restart is guarded on `ESP_PLATFORM`, not on
  the transport, so wired boards reboot too. Until #189 it was guarded on the transport:
  a wired board performed the whole wipe, then answered `501 {"error":"factory reset not
  available on desktop"}` and never rebooted. If you are reading an older capture, that
  `501` recorded a *completed* reset.
- **The boot provisioning gate does NOT re-engage.** *(Corrected — this bullet previously
  said the opposite, and it matters: it is the difference between a reset board that is
  dark and one that is answering SIP.)* The gate is a **persisted latch**, not an in-RAM
  flag: it reads the `storage`/`provisioned` **u8** key (`main/esp_main.cpp:346-358`, and
  the same block in `esp_main_eth.cpp:587-598` / `esp_main_eth_lan8720.cpp:401-412`) and
  writes it once a credential is committed (`esp_main.cpp:384-392`). **Nothing in the
  reset path erases it** — `"provisioned"` appears only in `main/`, never in
  `DeviceConfig::clearAll()` or `AdminAuth::eraseCredentialLocked()`. The earlier bullet
  confused `AuthState::provisioned` (an in-RAM field in `AdminAuth.cpp`) with the NVS key
  of the same name. So a factory-reset board comes back **on the default `admin`/`admin`
  credential with the SIP stack already running** — it does not re-enter the hold. Treat a
  reset board as live and claim its credential immediately. A bare NVS erase
  (`erase_region 0x9000 0x6000`) *does* drop the latch and restore virgin behaviour.
- **It re-applies the flash-time seed.** Dropping `cfgseed_gen` is deliberate — "factory"
  means *as flashed*, not *as hardcoded* (`DeviceConfig.hpp`). If the browser flasher wrote
  an AP passphrase, a Wi-Fi mode or a registrar mode into `cfgseed`, the next boot applies
  them again.

There is one non-network path back: if a **DTMF admin PIN** was set, dialling
`*<PIN>#9991` from the admin extension performs `nvs_flash_erase()` + restart
(`src/SIP/DtmfFeatureCodes.cpp:155-180`). That needs the admin extension registered and the
DTMF PIN known — neither is true by default, since there is no default DTMF PIN.

**Otherwise: recover physically — re-flash over USB/JTAG,** or erase NVS
(`esptool.py -p COM3 erase_region 0x9000 0x6000`). A full reflash returns the device to the
default-credential state; note that `idf.py erase-flash` wipes NVS entirely, and even a
plain `idf.py flash` may leave NVS in an inconsistent state across a partition migration,
so **treat it as a clean slate and re-onboard** ([OTA.md §5.1](OTA.md)). After reflashing,
completing the forced setup is the first step ([SETUP_GUIDE.md §3](SETUP_GUIDE.md)).

> [!TIP]
> Choose a password you will remember but that is still ≥8 characters
> ([THREAT_MODEL.md §5.2](THREAT_MODEL.md)). There is no "reset link."

---

## OTA update fails or rolls back

**Symptom:** A firmware push via `/api/ota/upload` errors, or the device reverts to the
previous firmware after rebooting. Full reference: [OTA.md](OTA.md).

> [!NOTE]
> **OTA has never actually been executed on hardware** — not on the bench, not in CI. The
> failure modes below are read off the implementation and the ESP-IDF contract, not off a
> run. Treat a first OTA as an experiment, with serial attached.

| Code / behavior | Cause | Fix |
| :--- | :--- | :--- |
| `401` | The request has no/invalid `pd_session`. | Log in first (`/api/admin/login`), reuse the cookie jar ([OTA.md §3.2](OTA.md)). |
| `403 setup_required` | The board is still on the `admin`/`admin` default. | Complete setup first — see [Everything returns 403 setup_required](#everything-returns-403-setup_required). |
| `403 cross-origin request rejected` | `Origin` host ≠ `Host`. | Send a matching `Origin` header, or omit it. |
| `403 missing or invalid CSRF token` | The request has a session but no `X-CSRF` header. A pre-existing OTA script hits this. | Capture `"csrf"` from the login response and send it ([OTA.md §3.2](OTA.md), and [403 on an API call that used to work](#403-on-an-api-call-that-used-to-work)). |
| `411` | Missing/zero `Content-Length`. | Use `--data-binary @build/SipServer.bin` so curl sets the length. |
| `400` | Upload truncated / socket closed mid-stream / flash write failed. | Re-upload on a stable link; the boot partition is unchanged, the device keeps running the current image ([OTA.md §4.2](OTA.md)). |
| `422` | `esp_ota_end()` rejected the image (bad magic / corrupt / not a valid app). | Verify you uploaded the correct `build/SipServer.bin`; rebuild. |
| `500` | `esp_ota_begin` / `set_boot_partition` failed. | Check device logs; retry. |
| `501` | This is the **host/desktop** build — OTA is device-only. | Run OTA against real hardware ([OTA.md §3.4](OTA.md)). |
| **Boots the OLD image after reboot** | **Anti-rollback** restored the previous slot because the new image did not reach `markValid()` (it crashed/boot-looped during startup). This is the safety net working — no bricking. | Inspect serial logs for the boot-loop cause, fix the image, re-upload. The device confirms a healthy image only after a few seconds of stable operation ([OTA.md §4](OTA.md), `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y`). |
| Power lost during write | The slot is partially written but never activated; `otadata` still points at the running slot, so the next boot is the old image. | Simply re-upload to retry ([OTA.md §4.2](OTA.md)). |

> [!IMPORTANT]
> OTA images are **unsigned** today and the upload is gated only by the admin session +
> CSRF + same-origin check. **Replace the default credential** and **restrict OTA to the
> local link** ([OTA.md §6](OTA.md), [THREAT_MODEL.md](THREAT_MODEL.md) T-5).

---

## Display blank or garbled (Guition JC3248W535 variant)

**Symptom:** The 3.5" touch panel is dark, shows noise, or never renders the UI.

| Cause | Fix |
| :--- | :--- |
| Missing I2C pull-ups on the touch bus | Many JC3248W535 clones omit them; add **4.7 kΩ pull-ups** on `TOUCH_SDA` (GPIO 4) and `TOUCH_SCL` (GPIO 8) to 3.3 V, or the panel/touch init can time out and crash ([HARDWARE.md §9A](HARDWARE.md)). |
| Wrong build / not the display target | Build with `idf.py -D SIP_TRANSPORT=display build` ([README.md](../README.md)). A Wi-Fi-only build does not drive the panel. |
| PSRAM not in Octal mode | The two 307.2 KB LVGL frame buffers need **8 MB Octal PSRAM @ 80 MHz** (`MALLOC_CAP_SPIRAM`). Octal PSRAM and `qio` flash mode are set via `sdkconfig.defaults`; a mismatched config exhausts internal SRAM ([HARDWARE.md §2](HARDWARE.md)). |
| Backlight off | `TFT_BL` is GPIO 1, **active-high** (high = on). A dark-but-alive panel can be a backlight wiring issue ([HARDWARE.md §2](HARDWARE.md)). |
| Headless fallback engaged | If the display panel fails to initialize, the firmware falls back to headless operation — SIP and the HTTP dashboard still work; reach it over the network while you debug the panel. |

> [!NOTE]
> The display is optional to operation. Even with a dead panel, the device still runs the
> SIP registrar and serves the HTTP dashboard — manage it from a browser
> ([HARDWARE_SELECTION.md §3](HARDWARE_SELECTION.md)).

---

## Still stuck? Collect this before asking for help

- `GET /api/status` output (uptime, `packetsProcessed`, `packetsDropped`, `clients`,
  `sessions`) — ungated, [API.md](API.md).
- `GET /api/admin/status` — `{provisioned, needsSetup, authenticated, sessionRemainingSec}`.
  Ungated, and `needsSetup` is usually the answer.
- `GET /api/registrar` (`mode` and the adopted-device roster) and `GET /api/ap-security`
  (`secure`, and whether a passphrase is set) — both need a session **and** completed setup.
  **Redact the `psk` before pasting it anywhere.**
- The exact status code **and JSON body** of the failing request — `401`,
  `403 cross-origin`, `403 setup_required` and `403 missing or invalid CSRF token` are four
  different problems.
- Serial monitor log around the failure (`idf.py monitor`) — in particular the
  `[boot] device unprovisioned …` / `[boot] credential set …` lines.
- Board model and `SIP_TRANSPORT` build used ([HARDWARE_SELECTION.md](HARDWARE_SELECTION.md)).
- The exact phone model/firmware and its codec/transport settings
  ([PHONE_COMPATIBILITY.md](PHONE_COMPATIBILITY.md)).
