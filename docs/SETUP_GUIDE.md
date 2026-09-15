# First-Time Setup Guide

This guide takes a freshly flashed **pocket-dial** device from power-on to a working
test call. It assumes a Wi-Fi SoftAP build (the default standalone Access Point mode);
notes call out where the wired-Ethernet and touch-display variants differ.

If you have not flashed firmware yet, do that first, see the build instructions in
[../README.md](../README.md#run-it-on-an-esp32-s3) and, for updating an already-flashed device,
[OTA.md](OTA.md). This document picks up **after** the firmware is on the board.

What you will do:

1. [Power on and join the device's Wi-Fi](#1-power-on-and-join-the-device)
2. [Open the dashboard](#2-open-the-dashboard)
3. [Log in and complete setup (do this first)](#3-log-in-and-complete-setup-first)
4. [Register a softphone or IP phone](#4-register-a-phone)
5. [Make a test call (777 echo, then 999 all-page)](#5-make-a-test-call)
6. [Quick-start checklist](#6-quick-start-checklist)

## 1. Power on and join the device

When a standalone Wi-Fi build boots, it spawns its own **open** access point and runs an
internal DHCP server. The SIP registrar binds to `192.168.4.1:5060` and the HTTP
dashboard to `192.168.4.1:80`.

| Setting | Value | Source |
| :--- | :--- | :--- |
| SoftAP SSID | `esp32-sipserver` | `main/esp_main.cpp` (`EXAMPLE_ESP_WIFI_SSID`) |
| Security | Open, no password | `WIFI_AUTH_OPEN` (`main/esp_main.cpp`) |
| Channel | 1 | `EXAMPLE_ESP_WIFI_CHANNEL` |
| Max associated stations | 10 | `EXAMPLE_MAX_STA_CONN` |
| Gateway / server IP | `192.168.4.1` | DHCP server default |
| Hostname (mDNS) | `pocketdial.local` | `mdns_hostname_set("pocketdial")` in **`src/SIP/SipServer.cpp:33-35`** (not `main/esp_main.cpp`). **It is not advertised before setup on a wired board**: mDNS starts in the `SipServer` constructor, and `SipServer` is only constructed *after* the credential gate on `wifi`/`eth`/`lan8720` (`main/esp_main.cpp:365-397`). On an unprovisioned wired unit your only route to the dashboard is the IP from the router's DHCP table. The `display` build registers mDNS during onboarding and is the exception. |

Steps:

1. Power the board over USB-C (or PoE on a wired board).
2. On your laptop or phone, open Wi-Fi settings and join **`esp32-sipserver`**. No
   password is required *unless* access-point security has been switched on (below).
3. Wait for your client to receive a DHCP lease (an address in the `192.168.4.x` range).

> [!IMPORTANT]
> The SoftAP is **open by default**: anyone in radio range can join, and the dashboard,
> SIP signalling and call audio all cross that link in the clear. Log in and replace
> the default admin credential immediately (step 3), then **turn access-point security on**, it is the single most
> effective hardening available on this device, because it encrypts all three at once.
> See [THREAT_MODEL.md](THREAT_MODEL.md) §6.

> [!IMPORTANT]
> **On the `wifi`, `eth` and `lan8720` builds the SIP registrar does not start until
> you complete step 3.** The boot task reads the provisioning flag, logs
> `[boot] device unprovisioned — SIP stack held dark until credential committed`,
> and polls every 2 seconds; the dashboard is up the whole time (that is how you
> provision), but **no phone can register until the admin credential is replaced**.
> If nothing is committed within 30 minutes the board reboots and starts the wait
> over; a restart mid-setup is designed behaviour, not a crash. Do step 3 before
> step 4, not after.
>
> The `display` build is **not** gated this way: it boots into its normal network
> role and brings SIP up regardless of provisioning state.

### Turning on access-point security (WPA2)

It is off by default on purpose: switching it on forces every phone already
associated with the access point to be re-paired, so it is never done to a live fleet
by a firmware update. Enable it deliberately, in one of two ways:

* From the dashboard: *Admin / Security & Firmware* → *Wi-Fi Access Point Security*.
  Tick the box and save. The change takes effect the next time the access point starts.
* At flash time: the [browser flasher](https://glomargadaffi.github.io/pocket-dial/flasher/)
  can write the setting and the passphrase directly to the board. This is the easiest
  route for the headless `esp32s3-wifi` variant. (The `esp32s3-eth` build has no SoftAP
  at all; it is a node on your wired LAN, so access-point security does not apply to it.)

**Finding the passphrase.** The device generates its own, per unit; there is no
factory default, and nothing is baked into the firmware image. It is 20 characters from
an alphabet with no ambiguous glyphs (`23456789ABCDEFGHJKMNPQRSTVWXYZ`, no `0`/`O`, no
`1`/`I`/`L`, and no `U`), so it survives being
read off a screen and retyped into a desk phone. Read it from whichever applies:

| Build | Where the passphrase appears |
|-------|------------------------------|
| `display` | On the LVGL screen during captive-portal onboarding |
| `wifi` (headless) | Logged over serial at boot (`idf.py monitor`) |
| `eth` | Not applicable, this build has no SoftAP |
| Any | The dashboard panel above, once logged in as admin |
| Any | The browser flasher, if you set it at flash time |

You can rotate it from the same dashboard panel. Write the new one down **before**
restarting the access point; rotating it drops every associated phone.

### Variant: captive-portal onboarding (touch-display build)

The Guition JC3248W535 display build can boot into a **captive-portal onboarding** mode
that brings up a separate setup AP named **`My-Ap`** (`ONBOARDING_SSID` in
`main/esp_main_display.cpp`) and shows a join QR code on screen. When you join, the
device redirects all web traffic to its setup page so you can either join an existing
Wi-Fi network (Station mode) or stay in Standalone AP mode.

> [!NOTE]
> The portal's choices are state-changing, so they take the same admin gate as
> everything else: `POST /api/wifi/connect`, `POST /api/wifi/mode_ap` and
> `POST /api/configuring` all run through `requireAdmin`, and all return
> `403 {"error":"setup_required"}` while the board is still on `admin`/`admin`.
> Log in and replace the credential (step 3) first. The two calls that still work
> before setup completes are `POST /api/admin/login` (which does not go through
> `requireAdmin` at all, it only checks same-origin) and
> `POST /api/admin/set-credential` (the one path the `setup_required` refusal
> exempts; it still needs the session cookie and CSRF token the login just handed
> you).

> [!NOTE]
> The onboarding portal has a **5-minute decay watchdog** (`CAPTIVE_DECAY_SECONDS = 300`
> in `main/esp_main_display.cpp`): if no configuration is confirmed within five minutes,
> the device reboots into Standalone AP mode (`esp32-sipserver`) on its own. If your
> portal disappears, just re-join `esp32-sipserver` and continue from step 2.

### Variant: wired Ethernet / PoE

Wired builds are nodes on your wired LAN and obtain an
address via DHCP (with static fallback). There is no SoftAP; reach the dashboard at the
device's LAN IP or at `pocketdial.local`. See [HARDWARE_SELECTION.md](HARDWARE_SELECTION.md)
for board specifics.

> [!NOTE]
> These builds compile **without** `POCKETDIAL_HAS_WIFI` (`main/CMakeLists.txt`), so
> the Wi-Fi routes are compiled out to a stub that answers
> `501 {"error":"... not available on desktop"}` (issue #167).
> `POST /api/wifi/connect` and `POST /api/wifi/mode_ap` do nothing here: there is
> no Wi-Fi fallback into an `eth` board. If it drops off the wired LAN, recovery is
> the serial console or a USB reflash, not a rescue AP.
>
> `POST /api/factory-reset` is **not** in that set: it is fully real on a wired
> board. It clears the admin credential and DTMF PIN, `DeviceConfig`, the
> Telephony-API slots, the DID table and the CDR ring, answers `200`, and reboots.
> The board comes back unprovisioned and holds SIP down until you commit a new
> admin credential, exactly like a virgin board.
>
> Before #189 this route was the trap in that set: it did the whole reset and then
> fell into the `501` arm without rebooting. If you are working from an older
> capture or runbook, read that `501` as a *completed* reset, not a no-op.

## 2. Open the dashboard

Open a browser on the joined client and navigate to:

```
http://192.168.4.1
```

or, where mDNS resolves:

```
http://pocketdial.local
```

You should see the retro CGA dashboard. It renders live data from
[`GET /api/status`](API.md#get-apistatus): the server IP/port, uptime, processed/dropped
packet counters, the list of registered extensions, and any active call sessions.

**The dashboard is always reachable.** The HTTP listener opens when the server is
constructed and stays open for the life of the process, in every provisioning
state: there is nothing to unlock, open, or dial first. (Firmware built before
commit `de1a36e` did go dark once a PIN was set, reopened by a `*4887` DTMF
star-code; that mechanism was **removed** and no longer exists in `src/`. If a
colleague or an older runbook tells you to dial in to open the port, they are
describing deleted firmware.) So a refused connection or a timeout here is
always a real fault: wrong address, wrong network, or a board that has not
finished booting. See
[TROUBLESHOOTING.md](TROUBLESHOOTING.md#dashboard-unreachable).

## 3. Log in and complete setup (first)

> [!IMPORTANT]
> **Log in and replace the default credential before doing anything else.**
> The device ships with a well-known default login (username `admin`,
> password `admin`), precisely so this step doesn't require any out-of-band
> secret. Every state-changing endpoint requires a valid, authenticated
> session, and until you replace the default credential, the server refuses
> everything else with `403 {"error":"setup_required"}`: "force setup on
> first use," enforced by the firmware itself, not just suggested by the
> dashboard (see [API.md §0](API.md#0-reachability--admin-session-layer-read-this-first)).

Every admin-gated route requires a valid `pd_session` cookie (else `401`), and
**mutating** routes additionally require the session's CSRF token in an `X-CSRF`
header (else `403`):

* Mutating (cookie + `X-CSRF`): `/api/kill`, `/api/dnd`, `/api/forward`,
  `/api/group`, `/api/dialplan`, `/api/wifi/connect`, `/api/wifi/mode_ap`,
  `/api/configuring`, `/api/factory-reset`, `POST /api/ap-security`,
  `POST /api/registrar`, `/api/registrar/device`, the `/api/telephony-config`
  and `/api/did-mapping` writes, the music-on-hold routes (`POST /api/moh/preview`,
  `POST /api/moh/preview/stop`, `POST /api/moh/upload`), and the OTA endpoints
  (`/api/ota/upload`, `/api/ota/reboot`).
* Read-gated (cookie only, no CSRF): `GET /api/ap-security`,
  `GET /api/registrar`, `GET /api/telephony-config`, `GET /api/did-mapping`,
  `GET /api/pcap`, `GET /api/trace`, `GET /api/diagnostics/pcap`, `GET /api/moh`.
* Ungated, readable before you log in: `GET /`, `GET /api/status`,
  `GET /api/cdr`, `GET /metrics`, `GET /api/wifi/scan`, `GET /api/ota/status`,
  `GET /config/<mac>.cfg`, and `GET /api/admin/status` (which is how the dashboard
  decides whether to show you the login form or the setup form). Note `/api/cdr`
  hands over the recent call log and `/api/status` the extension roster with each
  handset's IP:port, see [THREAT_MODEL.md](THREAT_MODEL.md) §4 E-2.

The forced-setup refusal sits on top of all of that: while `admin`/`admin` is
still in place, **every one of the gated routes above (the read-only `GET`s
included) returns `403 {"error":"setup_required"}`**, no matter that you have a
valid session. `POST /api/admin/set-credential` is the only exemption.

### Log in and complete setup from the dashboard

Use the admin/security control on the dashboard. It opens on a login form;
logging in with the default `admin`/`admin` credential immediately routes to
a forced setup form (new username, new password, and an optional DTMF admin
PIN) that nothing else on the dashboard is usable until you submit.

### Log in and complete setup from the command line

```bash
DEVICE=http://192.168.4.1     # or http://pocketdial.local

# 1. Log in with the shipped default credential.
LOGIN=$(curl -s -i -H "Origin: $DEVICE" \
     -X POST --data "username=admin&password=admin" \
     "$DEVICE/api/admin/login")
SESSION=$(echo "$LOGIN" | sed -n 's/.*pd_session=\([0-9a-fA-F]*\).*/\1/p' | head -1)
CSRF=$(echo "$LOGIN" | sed -n 's/.*"csrf":"\([0-9a-fA-F]*\)".*/\1/p' | head -1)

# 2. Complete setup: replace the login credential, optionally set a DTMF PIN.
curl -s -H "Origin: $DEVICE" -H "Cookie: pd_session=$SESSION" -H "X-CSRF: $CSRF" \
     -X POST --data "username=YOUR_USERNAME&password=YOUR_PASSWORD&dtmfPin=YOUR_DTMF_PIN" \
     "$DEVICE/api/admin/set-credential"
# -> {"status":"ok","provisioned":true,"needsSetup":false}
```

Credential rules and behavior, from `src/Helpers/AdminAuth.{hpp,cpp}` and the threat model:

| Property | Value |
| :--- | :--- |
| Password minimum length | 8 characters (`kMinPasswordLength`); shorter returns `400` |
| Username | 1-32 chars, no whitespace/control characters (`kMinUsernameLength`/`kMaxUsernameLength`) |
| DTMF admin PIN | Optional, 4-16 digits (`kMinDtmfPinLength`/`kMaxDtmfPinLength`); no default: the phone-keypad `*PIN#code` menu stays fully disabled until one is set |
| Storage | Salted, iterated SHA-256, 50,000 rounds, 128-bit random salt per secret (NVS keys `admin_user`/`admin_pw_salt`/`admin_pw_hash` for the login credential, `admin_pin_salt`/`admin_pin_hash` for the DTMF PIN, independent, so clearing/rotating one never touches the other) |
| Brute-force lockout | 5 consecutive failed logins → 60-second lockout (`429`), doubling on each repeat lockout to a 16-minute cap (`kLockoutMs << kMaxLockoutShift`). Keyed **per client address** (8 least-recently-seen buckets), so ordinary fat-fingering by one client does not lock out another; a correct credential clears that client's counter. There is also an aggregate backstop: 20 failures across *all* clients trips the same escalating lockout globally (`kMaxFailedAttemptsGlobal`), so a determined attacker rotating source addresses can still stall logins. Counters are RAM-only; a power cycle clears them without touching the stored credential. |
| Session token | ≥128-bit opaque, `HttpOnly` + `SameSite=Strict` cookie, 30-minute sliding expiry |

> [!TIP]
> The hash is salted and iterated, but a short or common password is still
> guessable if an attacker ever obtains the flash contents physically. **Use a
> real, unique password**, this is exactly what the forced-setup step exists
> to make you do instead of leaving `admin`/`admin` in place.

You can verify auth state any time with the read-only endpoint
`GET /api/admin/status`, which returns `{provisioned, needsSetup, authenticated}`
booleans; `provisioned`/`needsSetup` describe the login credential only (the
DTMF PIN has no equivalent status field; query `dtmfPinIsSet()`'s effect
indirectly by whether `*PIN#code` DTMF actions work).

## 4. Register a phone

pocket-dial is a SIP registrar. Any SIP client, a softphone app or a hardware IP phone,
registers against it with these settings:

| Field | Value | Notes |
| :--- | :--- | :--- |
| SIP server / registrar / proxy | `192.168.4.1` | Or the device's LAN IP on wired builds; `pocketdial.local` where mDNS resolves |
| Port | `5060` | UDP signaling port |
| Transport | **UDP** | The engine only speaks UDP |
| Username / Auth ID / extension | your choice, e.g. `1001` | The registrar keys clients by this extension (AOR) |
| Password | (any / blank) | The registrar **ships in `open` mode**, which accepts every REGISTER without a challenge, so whatever you type here is ignored. SIP digest auth *does* exist: `learn` (trust-on-first-use, MAC-locked) and `secure` (digest required for every provisioned extension) are selectable via `POST /api/registrar` once you are logged in. The mode is stored as `reg_mode` in NVS namespace **`pbxcfg`**. See [THREAT_MODEL.md](THREAT_MODEL.md) S-3 |
| Codec | **PCMU, PCMA and G.722** between two phones; **PCMU only** on legs the board terminates (`440`, `555`, `888`, hold music) | The server does **not** rewrite your codec list: `filterAudioCodecs(allowWideband=true)` only *drops* payloads it won't carry, keeping each phone's own preference order and payload numbering, so two G.722-capable handsets negotiate wideband between themselves. `telephone-event` passes through. (Earlier revisions of this table said the server rewrites SDP to a literal `0 8 101` via `enforceG711()`. That function has **no callers left** (`src/SIP/SipMessage.cpp:260` is dead code), and the literal rewrite it did was itself a bug: it advertised payload 101 with no `a=rtpmap`, which pjsip rejects outright.) |
| Registration expiry | up to `3600` s | `DEFAULT_EXPIRES`/`MAX_EXPIRES`; higher requests are capped to 3600 |

> [!IMPORTANT]
> **Do not reuse the extensions `777` or `999`.** They are reserved virtual extensions
> (echo test and all-page broadcast, see step 5).

Steps:

1. Open your SIP client and create a new account/identity.
2. Enter server `192.168.4.1`, port `5060`, transport **UDP**.
3. Choose an extension (e.g. `1001`) as the username.
4. Restrict the codec list to **G.711 µ-law and a-law** (disable Opus, G.722, G.729).
5. Save. The client should show "registered".
6. Confirm on the dashboard: the extension appears in the `clients` list of
   [`GET /api/status`](API.md#get-apistatus).

Register a **second** extension (e.g. `1002`) on another client so you can place a real
call later. Per-client walkthroughs and known quirks are in
[PHONE_COMPATIBILITY.md](PHONE_COMPATIBILITY.md).

> [!NOTE]
> The registrar pings each registered client with a SIP `OPTIONS` keepalive every 5
> seconds and prunes a client after ~15 seconds of silence (`RequestsHandler.cpp`). A
> phone that does not answer OPTIONS may be dropped from the registrar.

> [!TIP]
> **If nothing registers at all** on a `wifi`, `eth` or `lan8720` build, check that
> you finished step 3 first. Those builds hold the SIP stack down until an admin
> credential is committed; port 5060 is simply not listening yet, while the
> dashboard on port 80 answers normally. `idf.py monitor` shows
> `[boot] waiting for admin credential...` every couple of seconds when this is
> what is happening.

## 5. Make a test call

### 5a. Echo test: dial `777`

`777` is a built-in echo loopback. When an endpoint dials `777`, the server answers
`200 OK` using **the caller's own SDP connection info**, so the phone streams its audio
back to its own receive port, a zero-DSP hardware echo test (`RequestsHandler::onInvite`).

1. From a registered phone, dial **`777`**.
2. The call connects immediately. Speak, you should hear your own voice echoed back.
3. Hang up.

If you hear nothing, your audio path (codec/RTP) is the suspect, see
[TROUBLESHOOTING.md](TROUBLESHOOTING.md#one-way-or-no-audio).

### 5b. All-page broadcast: dial `999`

`999` is a parallel intercom/all-page. Dialing it forks the INVITE to **every other
registered extension** at once, injecting auto-answer headers; the first device to answer
`200 OK` is connected and the rest are cancelled (`RequestsHandler` broadcast handler).

1. Make sure at least one **other** extension is registered (e.g. `1002` from step 4).
2. From one phone, dial **`999`**.
3. Every other registered phone is paged simultaneously. When one answers, it is bridged
   to the caller and the others stop ringing.

### 5c. Direct extension-to-extension call

1. From `1001`, dial `1002` (the second extension you registered).
2. The callee rings; answer it.
3. Audio (RTP) flows **peer-to-peer** directly between the two phones; the device only
   brokers signaling (see [ARCHITECTURE.md](ARCHITECTURE.md) and [SCALING.md](SCALING.md)).
4. The active call appears in the `sessions` list on the dashboard.

## 6. Quick-start checklist

- [ ] Firmware flashed (see [README.md](../README.md#run-it-on-an-esp32-s3) / [OTA.md](OTA.md)).
- [ ] Powered on; joined Wi-Fi SSID **`esp32-sipserver`** (open), or completed the
      `My-Ap` captive portal on the display build.
- [ ] Dashboard reachable at `http://192.168.4.1` (or `http://pocketdial.local`).
- [ ] Logged in with the default credential (`admin`/`admin`) and completed setup
      via `/api/admin/set-credential` (real username + password ≥8 chars).
- [ ] Logged in with the new credential (`/api/admin/login`) before using any gated control.
- [ ] (`wifi`/`eth`/`lan8720` only) Confirmed the SIP stack came up **after** setup;
      it is held down until the credential is committed, so this must precede the
      registration steps below.
- [ ] First softphone/IP phone registered: server `192.168.4.1:5060`, **UDP**, **G.711**,
      extension e.g. `1001`.
- [ ] Second extension registered (e.g. `1002`).
- [ ] Dialed **`777`**, heard echo.
- [ ] Dialed **`999`**, other phones paged.
- [ ] Placed a direct `1001 → 1002` call, two-way audio.

Next: [PHONE_COMPATIBILITY.md](PHONE_COMPATIBILITY.md) ·
[HARDWARE_SELECTION.md](HARDWARE_SELECTION.md) ·
[TROUBLESHOOTING.md](TROUBLESHOOTING.md) · [SCALING.md](SCALING.md)
