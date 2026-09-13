# Troubleshooting Runbook

Symptom → likely cause → fix. Work top-down within each section. Where a fact comes from
the firmware or another doc, it is cited so you can verify.

Quick references: [SETUP_GUIDE.md](SETUP_GUIDE.md) ·
[PHONE_COMPATIBILITY.md](PHONE_COMPATIBILITY.md) · [HARDWARE_SELECTION.md](HARDWARE_SELECTION.md) ·
[API.md](API.md) · [OTA.md](OTA.md) · [LEARN_MODE.md](LEARN_MODE.md) ·
[THREAT_MODEL.md](THREAT_MODEL.md)

> [!WARNING]
> **STALE as of 2026-09-13**: every section below mentioning "the dashboard went dark,"
> `*4887`, or a bare admin **PIN** describes two mechanisms that have been removed. The
> HTTP listener is now always open (no transport-level dark/open gate exists to
> troubleshoot), and the admin credential is a username + password with a shipped
> default (`admin`/`admin`, `/api/admin/set-credential`) rather than a bare PIN — see
> [API.md](API.md) §0 and [SETUP_GUIDE.md](SETUP_GUIDE.md) §3 for the current model.
> The lockout mechanics (brute-force cooldown, escalating backoff) are unchanged and
> those sections remain accurate.

> [!NOTE]
> **v1.3.0 changed three operator-visible things.** If a
> recipe here does not match your device, check which you are running.
> * Mutating API calls now need an **`X-CSRF` header** — see
>   [403 on an API call that used to work](#403-on-an-api-call-that-used-to-work).
> * The SoftAP can be **WPA2** — see [Can't join the Wi-Fi network](#cant-join-the-wi-fi-network-any-more).
> * The SIP registrar has **selectable admission modes** — see
>   [All phones stopped registering at once](#all-phones-stopped-registering-at-once).
>
> All three are **opt-in**. A device flashed from the `v1.3.0-pre-alpha` release, or one on
> `main` that nobody has configured, still has an **open** access point, an **`open`**
> registrar, plain **HTTP**, and **unsigned** OTA.

---

## Access-point not visible

**Symptom:** The `esp32-sipserver` Wi-Fi network does not appear in your client's Wi-Fi list.

| Cause | Fix |
| :--- | :--- |
| Device not powered / still booting | Confirm power (USB-C or PoE). Watch the serial monitor (`idf.py monitor`) for `wifi_init_softap finished. SSID:esp32-sipserver` (`main/esp_main.cpp`). |
| This is a **wired Ethernet** build | `SIP_TRANSPORT=eth` boards have **no SoftAP** — they join your wired LAN. Reach the dashboard at the device's LAN IP / `pocketdial.local` (see [HARDWARE_SELECTION.md](HARDWARE_SELECTION.md)). |
| Device is in **Station mode** | If Wi-Fi was configured to join an existing network (`/api/wifi/connect`), it is a client, not an AP. Factory-reset to return to AP/onboarding (see [Forgot the admin PIN](#forgot-the-admin-pin)). |
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
> On a headless `wifi` board with AP security on, no admin PIN you remember, and nobody
> on the AP, the only ways back are a **serial console** (the passphrase is logged at every
> boot) or a **re-flash**. Read the passphrase before you need it.

The `eth` build has no SoftAP at all, so none of this applies to it.

---

## Captive portal won't open

**Symptom:** You joined `My-Ap` (display build) but no setup page appears.

| Cause | Fix |
| :--- | :--- |
| Never actually associated | `My-Ap` is **WPA2**, keyed with the device's own generated passphrase shown on the onboarding screen (`main/esp_main_display.cpp`). If your client silently failed to join, there is no portal to open — see [Can't join the Wi-Fi network](#cant-join-the-wi-fi-network-any-more). |
| OS captive-portal prompt missed | Manually browse to `http://192.168.4.1/`. The device returns a `302` redirect to the portal for any off-host request ([API.md §3](API.md)). |
| The 5-minute decay window elapsed | The portal has a **300 s decay watchdog** (`CAPTIVE_DECAY_SECONDS`, `main/esp_main_display.cpp`): with no confirmed config it reboots into Standalone AP. Re-join **`esp32-sipserver`** and use `http://192.168.4.1`. |
| Browser cached HTTPS / HSTS | Use a fresh `http://` URL (not `https://`), or try a private window. The dashboard is HTTP only. |
| DNS not redirecting | The onboarding DNS responder answers all names with the device IP (port 53). If your client uses DNS-over-HTTPS, type the IP `192.168.4.1` directly. |

---

## Phone won't register (timeout or 401)

**Symptom:** The SIP client never reaches "registered", times out, or shows an error.

| Cause | Fix |
| :--- | :--- |
| Wrong server/port/transport | Server `192.168.4.1`, port `5060`, transport **UDP** (the engine is UDP-only). See [PHONE_COMPATIBILITY.md](PHONE_COMPATIBILITY.md). |
| Not on the device's network | Confirm the phone has a `192.168.4.x` lease (SoftAP) or can reach the device's LAN IP (wired). |
| TCP/TLS selected | Switch the client to **UDP**. There is no TCP/TLS listener. |
| Using extension `777`/`999` | These are reserved virtual extensions; pick another (e.g. `1001`). |
| `503 Service Unavailable` on REGISTER | The client pool is full. `allocateClient()` evicts the oldest *expired* binding, else returns `503`; the phone retries on its refresh timer. Raise the tier ([SCALING.md §4](SCALING.md)). |
| Client pruned after registering | The registrar prunes a client after ~15 s of silence if it ignores the `OPTIONS` keepalive sent every 5 s (`RequestsHandler.cpp`). Enable the phone's keep-alive / answer-OPTIONS option. |
| Rate-limited (packets dropped) | The SIP UDP path uses a per-source-IP token bucket (burst 40, 20 pkt/s sustained). A flooding or misconfigured client gets packets dropped; watch `packetsDropped` on `/api/status` ([ARCHITECTURE.md §5](ARCHITECTURE.md)). |
| Registrar is in `secure` mode | Every `REGISTER` is digest-challenged and this phone has no secret, or its MAC does not match the one the extension is locked to. See [All phones stopped registering at once](#all-phones-stopped-registering-at-once). |
| Registrar is in `learn` mode and the extension is already claimed | Learn mode locks an extension to the first MAC that claims it. A second phone on the same extension is refused. `POST /api/registrar/device` with `action=forget` releases the adoption so the new hardware can claim it ([API.md](API.md#post-apiregistrardevice)). |

> [!NOTE]
> **What a `401` on REGISTER means depends on the registrar mode.** Check it first:
> `GET /api/registrar` returns `{"mode":"open"|"learn"|"secure", …}` ([API.md](API.md#get-apiregistrar)).
> (that `GET` needs a session on a provisioned device, but no `X-CSRF`).
> * **`open`** (the shipped default) — there is no SIP authentication at all, so a `401`
>   is *not* from pocket-dial. It is almost always the phone's own account dialog, or,
>   separately, the **HTTP admin** gate (`/api/admin/*`), a different subsystem.
> * **`learn`** — already-secured devices are digest-challenged; unknown MACs are adopted
>   on first contact without a credential.
> * **`secure`** — a `401` with `WWW-Authenticate: Digest …` is real SIP digest auth
>   (RFC 2617, MD5). The phone needs the extension's secret set on the handset.
>
> Only `REGISTER` is digest-challenged; INVITE is not independently challenged
> ([THREAT_MODEL.md §9.1](THREAT_MODEL.md)).

---

## All phones stopped registering at once

**Symptom:** Every handset drops to "not registered" simultaneously, with no power, cabling
or Wi-Fi change. New registrations are refused.

**Almost always:** someone switched the SIP registrar to **`secure`** before any extension
had been adopted and secured. In `secure` mode every `REGISTER` is digest-challenged, and a
fleet that has never been through `learn` mode has no secrets to answer with — so all of
them fail at once ([LEARN_MODE.md](LEARN_MODE.md) §1).

**Confirm it:**

```bash
# GET, so no X-CSRF needed — but on a provisioned device it IS session-gated,
# so log in first and reuse the cookie jar (recipe in the CSRF section below).
curl -s -b "$JAR" http://192.168.4.1/api/registrar
# -> {"attached":true,"mode":"secure","devices":[]}
```

An empty (or all-`learned`) `devices` array with `"mode":"secure"` is the diagnosis. A bare
`curl` with no cookie returns `401` here — that is the admin gate, not a clue about the
registrar.

**Recover — in this order, because the options expire:**

1. **If the dashboard still answers, act now.** Put the registrar back into `learn` (or
   `open`) before the HTTP open window closes. Full recipe in
   [403 on an API call that used to work](#403-on-an-api-call-that-used-to-work) — the
   short form, with `$JAR`/`$CSRF` already in hand:
   ```bash
   curl -s -b "$JAR" -H "Origin: $DEVICE" -H "X-CSRF: $CSRF" \
        -X POST --data "mode=learn" "$DEVICE/api/registrar"
   ```
   Let the phones re-adopt, verify the roster, secure them individually
   (`POST /api/registrar/device`, `action=secure`), *then* go back to `secure`.
2. **If HTTP is dark**, reopen it with the `*4887` DTMF trigger — but this needs the admin
   extension to be **currently registered**, which in `secure` mode it is not. This path is
   usually already gone by the time you notice.
3. **Otherwise it is a USB recovery.** Erase NVS over serial
   (`esptool.py -p COM3 erase_region 0x9000 0x6000`) or re-flash. See the caveats below.

> [!IMPORTANT]
> **`POST /api/factory-reset` does not reopen the registrar.** It clears the admin
> credential, the Wi-Fi keys and `ap_secure`/`ap_psk`/`cfgseed_gen` — `reg_mode` is not in
> that list (`HttpServer::sendApiFactoryReset`). And because it drops `cfgseed_gen`, the
> next boot **re-applies the flash-time seed**, which can carry `regMode` and the AP
> passphrase (`DeviceConfig::applyFlashSeed()`). A board seeded `secure` by the browser
> flasher comes back `secure` after both a factory reset and a bare NVS erase. To clear the
> seed as well you must re-flash it, or erase its sector
> (`erase_region 0xFFF000 0x1000` on the 16 MB layout).

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

| Cause | Fix |
| :--- | :--- |
| **Codec mismatch (most common)** | pocket-dial does not transcode; it rewrites SDP to `0 8 101` (`enforceG711()`). If a phone offers only Opus/G.722/G.729, there is no common codec → no audio. **Restrict every client to G.711 µ-law + a-law** ([PHONE_COMPATIBILITY.md §1](PHONE_COMPATIBILITY.md)). |
| NAT/STUN/ICE enabled on the phone | Media is **peer-to-peer on one L2 segment**. NAT traversal rewrites the SDP connection address and breaks direct RTP. Turn STUN/ICE/rport **off**. |
| Client isolation on the AP | RTP is phone-to-phone; if SoftAP client isolation were enabled, stations couldn't reach each other and audio would fail (see [PROVISIONING.md §4.4](PROVISIONING.md) caveat). |
| Firewall between phones (wired) | On a wired LAN, ensure the segment allows station-to-station UDP for the RTP port range. |
| Verify with `777` | Dial **`777`** (echo): if echo works but a two-party call does not, the problem is between the two phones (NAT/isolation/firewall), not the codec. If `777` itself is silent, it is the codec/RTP on that one phone. |

---

## Calls drop unexpectedly

**Symptom:** Established calls hang up on their own.

| Cause | Fix |
| :--- | :--- |
| Keepalive prune | A phone that stops answering `OPTIONS` is pruned after ~15 s (`RequestsHandler.cpp`); its calls end. Keep the phone's keep-alive on and Wi-Fi signal adequate. |
| Wi-Fi association lost | On a SoftAP node, a weak link drops the station. Check RSSI / reduce range. |
| Session pool exhausted | New INVITEs get `503` when the session pool is full; existing calls are untouched. Raise the tier ([SCALING.md §4](SCALING.md)). |
| Admin force-disconnect | `POST /api/kill` de-registers an extension and tears down its calls ([API.md](API.md)). Check whether someone used the dashboard's kill control. |
| Spoofed BYE (open AP) | On an open AP with the registrar in `open` mode, a peer can inject a `BYE` (`THREAT_MODEL.md` D-2). `secure` mode raises the bar — an attacker can no longer claim the registration binding — but in-dialog requests are still not themselves digest-challenged ([THREAT_MODEL.md §9.1](THREAT_MODEL.md)), so the link-layer fix (WPA2 on the SoftAP) is still the real one. |

---

## Dashboard unreachable

**Symptom:** `http://192.168.4.1` (or `pocketdial.local`) does not load.

| Cause | Fix |
| :--- | :--- |
| **Connection refused a few minutes after you set a PIN** | **Working as designed.** Once provisioned, the HTTP listener itself is closed except inside a bounded open window (default **600 s**). See [The dashboard went dark after I set a PIN](#the-dashboard-went-dark-after-i-set-a-pin) below. |
| Wrong scheme | Use **`http://`**, not `https://` — the dashboard is plain HTTP ([API.md §1](API.md)). There is deliberately **no** HSTS header, so a browser that once cached HTTPS for this host will not have been pinned by us ([API.md §2.2](API.md)). |
| mDNS not resolving | Browse to the raw IP `192.168.4.1` (SoftAP) or the device's LAN IP (wired). |
| Not joined to the device network | Re-check Wi-Fi association / DHCP lease. If the AP is now WPA2, see [Can't join the Wi-Fi network](#cant-join-the-wi-fi-network-any-more). |
| Slow-client / Slowloris timeout | The HTTP worker enforces a 5 s `SO_RCVTIMEO` and closes idle sockets ([ARCHITECTURE.md §4](ARCHITECTURE.md)); reload the page. |
| `413 Payload Too Large` | A request body over **16 KB** is rejected ([API.md §1](API.md)). Don't paste oversized Wi-Fi passwords. |
| `403 cross-origin request rejected` | A state-changing POST whose `Origin` host ≠ `Host` is blocked. Use the dashboard directly, or send a matching `Origin` from CLI ([API.md §2](API.md)). |
| `403 missing or invalid CSRF token` | A **different** 403 — see the next section. |
| `401` on a control action | A PIN is provisioned and you have no valid `pd_session`. Log in via `/api/admin/login` first ([SETUP_GUIDE.md §3](SETUP_GUIDE.md)). |
| `429` on login | Brute-force lockout — and it now **escalates**. See [429 on login](#429-on-login) below. |
| Page renders but panels are blank | The page itself (`GET /`) and `/api/status` are ungated, but `/api/pcap`, `/api/trace` and `/api/registrar` need a session. A logged-out browser gets a rendered shell with `401`s underneath. |

---

## 403 on an API call that used to work

**Symptom:** A `curl` recipe or script that worked before now returns, on a **provisioned**
device:

```json
{ "error": "missing or invalid CSRF token" }
```

with status `403`. The session cookie is fine — the request is missing the second half of
the gate.

**Cause.** Every **mutating** request now has to echo a per-session **CSRF token** in an
`X-CSRF` header, checked centrally in `HttpServer::requireAdmin()` so no endpoint can skip
it ([API.md §2.1](API.md), [THREAT_MODEL.md](THREAT_MODEL.md) T-2). The `Origin` check
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
     -X POST --data "pin=YOUR_PIN" \
     "$DEVICE/api/admin/login")
# -> {"status":"ok","authenticated":true,"csrf":"3f2a...e91c"}

CSRF=$(printf '%s' "$LOGIN" | sed -n 's/.*"csrf":"\([0-9a-f]*\)".*/\1/p')
[ -n "$CSRF" ] || { echo "login failed: $LOGIN" >&2; exit 1; }

# 2) Any mutating call now carries cookie + Origin + token.
curl -s -b "$JAR" -H "Origin: $DEVICE" -H "X-CSRF: $CSRF" \
     -X POST --data "extension=1001" "$DEVICE/api/kill"
```

The same three headers apply to `/api/dnd`, `/api/forward`, `/api/group`, `/api/dialplan`,
`/api/wifi/connect`, `/api/wifi/mode_ap`, `/api/factory-reset`, `/api/ap-security`,
`/api/registrar`, `/api/registrar/device`, and the OTA endpoints
([OTA.md §3.2](OTA.md) has the OTA-specific walk-through).

**When you do *not* need it** ([API.md §2.1](API.md)):

| Case | Why |
| :--- | :--- |
| `POST /api/admin/login` | No session exists yet to bind a token to. |
| `POST /api/admin/logout` | Requiring one would strand a user on a stale page. |
| Any request on an **unprovisioned** device | No PIN → no session → no token. This is why the first-run flow and the CI smoke suite still work. |
| Every `GET` | Reads are not state changes. |

> [!TIP]
> Getting `401 {"error":"authentication required"}` instead? That is the session, not the
> token — log in first. Getting `403 {"error":"cross-origin request rejected"}`? That is
> the `Origin` header, not the token. The three failures are distinct and the JSON body
> tells you which one you hit.

---

## The dashboard went dark after I set a PIN

**Symptom:** The dashboard worked during setup, then a few minutes later the browser says
*connection refused* — not a `401`, not a timeout. `ping` still answers and calls still
work.

**This is the dark-by-default admin transport, working as designed.** Once an admin PIN
exists, the HTTP **listening socket** is closed except inside a bounded open window
(default **600 s**), so there is nothing to connect to. SIP, RTP and the phones are
unaffected — only the management plane is dark ([API.md §0](API.md),
[THREAT_MODEL.md §5.5](THREAT_MODEL.md)).

The window opens on exactly three events:

| Trigger | How |
| :--- | :--- |
| **DTMF star-code** | From the **admin extension** (default `1001`, NVS `pbxcfg`/`admin_ext`), while it is **registered**, dial **`*4887`**. The SIP INFO's source IP must match that registration's bound IP. |
| **Provisioning grace** | A successful `POST /api/admin/set-pin` opens the same window — this is why setup itself is not self-defeating. |
| **Keep-alive** | While logged in, the dashboard's *Keep open* control (`POST /api/admin/keepalive`) extends the window by a flat **1 hour**. Use it before starting long configuration work. |

**Recovery:** dial `*4887` from the admin extension and reload the dashboard.

> [!IMPORTANT]
> Opening the transport does **not** bypass the PIN — you still log in normally once the
> socket accepts you.

> [!WARNING]
> `*4887` needs the admin extension to be **registered**. If registration is broken —
> notably a registrar switched to `secure` with nothing adopted — this recovery path is
> gone too, and you are down to USB. See
> [All phones stopped registering at once](#all-phones-stopped-registering-at-once).
> Related: an admin PIN beginning `4887` is shadowed by this star-code; new PINs with that
> prefix are rejected, but a device provisioned before that guard shipped may still carry
> one — rotate it ([THREAT_MODEL.md §5.5](THREAT_MODEL.md)).

---

## `429` on login

**Symptom:** `POST /api/admin/login` returns `429 {"error":"too many failed attempts; try
again later"}` — sometimes even with the correct PIN, and sometimes for someone who has not
typed a wrong PIN at all.

Two counters can produce it (`AdminAuth.hpp`, [THREAT_MODEL.md §5.2](THREAT_MODEL.md)):

| Counter | Threshold | Cooldown |
| :--- | :--- | :--- |
| **Per-client** — keyed on the HTTP peer address, 8 least-recently-seen-evicted buckets | **5** consecutive failures | 60 s, **doubling on each successive lockout**, capped at ~16 min |
| **Aggregate backstop** — across *all* clients | **20** consecutive failures | Same doubling ladder, also up to ~16 min; locks out **everyone** |

What changed, and what will surprise you:

- **The cooldown no longer resets the failure budget.** The trip count survives the
  cooldown, so a second lockout is 2 min, a third 4 min, and so on. Repeatedly retrying
  while locked out does not extend it, but each fresh set of 5 wrong PINs does.
- **Only a correct PIN clears it** — both counters. There is no other reset short of a
  reboot.
- **You can be locked out by someone else.** The aggregate counter is deliberately set far
  above ordinary fat-fingering, so if you hit it without guessing, something on the link is
  hammering `/api/admin/login`.

**Fix:** wait it out — it always auto-clears, and it never permanently locks the device.
Existing sessions keep working throughout; only `login` is throttled. If you have another
browser still logged in, use it rather than waiting.

---

## Forgot the admin PIN

There is **no PIN recovery** — the PIN is stored only as a salted, iterated SHA-256 hash
(`AdminAuth.cpp`). The path back to a usable device is a **factory reset**, which clears
the admin credential and Wi-Fi config and reboots into onboarding/AP mode.

**If you still hold a valid session** (a browser somewhere is still logged in), use the
dashboard's **Factory Reset** button. That page already has the session's CSRF token
rendered into it — from the CLI you would have to log in again to obtain one, and logging in
needs the PIN you have lost.

The equivalent call, for when you *do* have the PIN and just want it scripted:

```bash
DEVICE=http://192.168.4.1
JAR=cookies.txt

# A mutating call needs cookie + Origin + the session's CSRF token (see the CSRF section).
LOGIN=$(curl -s -c "$JAR" -H "Origin: $DEVICE" \
     -X POST --data "pin=YOUR_PIN" "$DEVICE/api/admin/login")
CSRF=$(printf '%s' "$LOGIN" | sed -n 's/.*"csrf":"\([0-9a-f]*\)".*/\1/p')

curl -s -b "$JAR" -H "Origin: $DEVICE" -H "X-CSRF: $CSRF" \
     -X POST --data "confirm=ERASE" \
     "$DEVICE/api/factory-reset"
# -> {"status":"ok","message":"Factory reset. Rebooting to captive-portal setup..."}
```

- The `confirm=ERASE` token is **required** — without it the endpoint returns
  `400 {"error":"factory reset requires confirm=ERASE"}` (`HttpServer::sendApiFactoryReset`).
- Without `X-CSRF` you get `403 {"error":"missing or invalid CSRF token"}` instead —
  see [403 on an API call that used to work](#403-on-an-api-call-that-used-to-work).
- Factory reset erases `admin_salt`/`admin_hash` (clearing the PIN and all sessions), the
  Wi-Fi keys (`wifi_mode`, `wifi_ssid`, `wifi_pass`, `decayed`), and
  `ap_secure`/`ap_psk`/`cfgseed_gen`, then reboots.
- **It does not clear `reg_mode`.** A registrar left in `secure`/`learn` stays there across
  a factory reset.
- **It re-applies the flash-time seed.** Dropping `cfgseed_gen` is deliberate — "factory"
  means *as flashed*, not *as hardcoded* (`DeviceConfig.hpp`). If the browser flasher wrote
  an AP passphrase, a Wi-Fi mode or a registrar mode into `cfgseed`, the next boot applies
  them again.
- The dashboard's **Factory Reset** button performs the same call (`index_html.h`).

**If you have no valid session** (PIN lost and not logged in anywhere): the gated
`/api/factory-reset` will return `401`. Recover physically — **re-flash over USB/JTAG**.
A full reflash returns the device to the unprovisioned/open state; note that
`idf.py erase-flash` wipes NVS entirely, and even a plain `idf.py flash` may leave NVS in
an inconsistent state across the partition migration, so **treat it as a clean slate and
re-onboard** ([OTA.md §5.1](OTA.md)). After reflashing, set a new PIN as the first step
([SETUP_GUIDE.md §3](SETUP_GUIDE.md)).

> [!TIP]
> Choose a PIN you will remember but that is still ≥6 alphanumeric chars
> ([THREAT_MODEL.md §5.2](THREAT_MODEL.md)). There is no "reset link."

---

## OTA update fails or rolls back

**Symptom:** A firmware push via `/api/ota/upload` errors, or the device reverts to the
previous firmware after rebooting. Full reference: [OTA.md](OTA.md).

| Code / behavior | Cause | Fix |
| :--- | :--- | :--- |
| `401` | A PIN is provisioned but the request has no/invalid `pd_session`. | Log in first (`/api/admin/login`), reuse the cookie jar ([OTA.md §3.2](OTA.md)). |
| `403 cross-origin request rejected` | `Origin` host ≠ `Host`. | Send a matching `Origin` header, or omit it. |
| `403 missing or invalid CSRF token` | Provisioned device; the request has a session but no `X-CSRF` header. A pre-existing OTA script hits this. | Capture `"csrf"` from the login response and send it ([OTA.md §3.2](OTA.md), and [403 on an API call that used to work](#403-on-an-api-call-that-used-to-work)). |
| `411` | Missing/zero `Content-Length`. | Use `--data-binary @build/SipServer.bin` so curl sets the length. |
| `400` | Upload truncated / socket closed mid-stream / flash write failed. | Re-upload on a stable link; the boot partition is unchanged, the device keeps running the current image ([OTA.md §4.2](OTA.md)). |
| `422` | `esp_ota_end()` rejected the image (bad magic / corrupt / not a valid app). | Verify you uploaded the correct `build/SipServer.bin`; rebuild. |
| `500` | `esp_ota_begin` / `set_boot_partition` failed. | Check device logs; retry. |
| `501` | This is the **host/desktop** build — OTA is device-only. | Run OTA against real hardware ([OTA.md §3.4](OTA.md)). |
| **Boots the OLD image after reboot** | **Anti-rollback** restored the previous slot because the new image did not reach `markValid()` (it crashed/boot-looped during startup). This is the safety net working — no bricking. | Inspect serial logs for the boot-loop cause, fix the image, re-upload. The device confirms a healthy image only after a few seconds of stable operation ([OTA.md §4](OTA.md), `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y`). |
| Power lost during write | The slot is partially written but never activated; `otadata` still points at the running slot, so the next boot is the old image. | Simply re-upload to retry ([OTA.md §4.2](OTA.md)). |

> [!IMPORTANT]
> OTA images are **unsigned** today and the upload is gated only by the admin PIN +
> same-origin check. **Always set a PIN** and **restrict OTA to the local link**
> ([OTA.md §6](OTA.md), [THREAT_MODEL.md](THREAT_MODEL.md) T-5).

---

## Display blank or garbled (Guition JC3248W535 variant)

**Symptom:** The 3.5" touch panel is dark, shows noise, or never renders the UI.

| Cause | Fix |
| :--- | :--- |
| Missing I2C pull-ups on the touch bus | Many JC3248W535 clones omit them; add **4.7 kΩ pull-ups** on `TOUCH_SDA` (GPIO 4) and `TOUCH_SCL` (GPIO 8) to 3.3 V, or the panel/touch init can time out and crash ([HARDWARE.md §9A](HARDWARE.md)). |
| Wrong build / not the display target | Build with `idf.py -D SIP_TRANSPORT=display build` ([README.md](../README.md#jc3248w535en-smart-display)). A Wi-Fi-only build does not drive the panel. |
| PSRAM not in Octal mode | The two 307.2 KB LVGL frame buffers need **8 MB Octal PSRAM @ 80 MHz** (`MALLOC_CAP_SPIRAM`). Octal PSRAM and `qio` flash mode are set via `sdkconfig.defaults`; a mismatched config exhausts internal SRAM ([HARDWARE.md §2](HARDWARE.md), README display note). |
| Backlight off | `TFT_BL` is GPIO 1, **active-high** (high = on). A dark-but-alive panel can be a backlight wiring issue ([HARDWARE.md §2](HARDWARE.md)). |
| Headless fallback engaged | If the display panel fails to initialize, the firmware is designed to fall back to headless operation (README "Robust Concurrency & Headless Fallback") — SIP and the HTTP dashboard still work; reach it over the network while you debug the panel. |

> [!NOTE]
> The display is optional to operation. Even with a dead panel, the device still runs the
> SIP registrar and serves the HTTP dashboard — manage it from a browser
> ([HARDWARE_SELECTION.md §3](HARDWARE_SELECTION.md)).

---

## Still stuck? Collect this before asking for help

- `GET /api/status` output (uptime, `packetsProcessed`, `packetsDropped`, `clients`,
  `sessions`) — [API.md](API.md).
- `GET /api/admin/status` (`provisioned` / `authenticated` booleans).
- `GET /api/registrar` (`mode` and the adopted-device roster) and `GET /api/ap-security`
  (`secure`, and whether a passphrase is set) — both need a session on a provisioned
  device. **Redact the `psk` before pasting it anywhere.**
- The exact status code **and JSON body** of the failing request — `401`, `403 cross-origin`
  and `403 missing or invalid CSRF token` are three different problems.
- Serial monitor log around the failure (`idf.py monitor`).
- Board model and `SIP_TRANSPORT` build used ([HARDWARE_SELECTION.md](HARDWARE_SELECTION.md)).
- The exact phone model/firmware and its codec/transport settings
  ([PHONE_COMPATIBILITY.md](PHONE_COMPATIBILITY.md)).
