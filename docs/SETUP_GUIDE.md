# First-Time Setup Guide

This guide takes a freshly flashed **pocket-dial** device from power-on to a working
test call. It assumes a Wi-Fi SoftAP build (the default standalone Access Point mode);
notes call out where the wired-Ethernet and touch-display variants differ.

If you have not flashed firmware yet, do that first — see the build instructions in
[../README.md](../README.md#building--testing) and, for updating an already-flashed device,
[OTA.md](OTA.md). This document picks up **after** the firmware is on the board.

**What you will do:**

1. [Power on and join the device's Wi-Fi](#1-power-on-and-join-the-device)
2. [Open the dashboard](#2-open-the-dashboard)
3. [Log in and complete setup (do this first)](#3-log-in-and-complete-setup-first)
4. [Register a softphone or IP phone](#4-register-a-phone)
5. [Make a test call (777 echo, then 999 all-page)](#5-make-a-test-call)
6. [Quick-start checklist](#6-quick-start-checklist)

---

## 1. Power on and join the device

When a standalone Wi-Fi build boots, it spawns its own **open** access point and runs an
internal DHCP server. The SIP registrar binds to `192.168.4.1:5060` and the HTTP
dashboard to `192.168.4.1:80`.

| Setting | Value | Source |
| :--- | :--- | :--- |
| SoftAP SSID | `esp32-sipserver` | `main/esp_main.cpp` (`EXAMPLE_ESP_WIFI_SSID`) |
| Security | Open — no password | `WIFI_AUTH_OPEN` (`main/esp_main.cpp`) |
| Channel | 1 | `EXAMPLE_ESP_WIFI_CHANNEL` |
| Max associated stations | 10 | `EXAMPLE_MAX_STA_CONN` |
| Gateway / server IP | `192.168.4.1` | DHCP server default |
| Hostname (mDNS) | `pocketdial.local` | `mdns_hostname_set("pocketdial")` |

**Steps:**

1. Power the board over USB-C (or PoE on a wired board).
2. On your laptop or phone, open Wi-Fi settings and join **`esp32-sipserver`**. No
   password is required *unless* access-point security has been switched on (below).
3. Wait for your client to receive a DHCP lease (an address in the `192.168.4.x` range).

> [!IMPORTANT]
> The SoftAP is **open by default** — anyone in radio range can join, and the dashboard,
> SIP signalling and call audio all cross that link in the clear. Log in and replace
> the default admin credential immediately (step 3), then **turn access-point security on** — it is the single most
> effective hardening available on this device, because it encrypts all three at once.
> See [THREAT_MODEL.md](THREAT_MODEL.md) §6.

### Turning on access-point security (WPA2)

It is **off by default on purpose**: switching it on forces every phone already
associated with the access point to be re-paired, so it is never done to a live fleet
by a firmware update. Enable it deliberately, in one of two ways:

* **From the dashboard** — *Admin / Security & Firmware* → *Wi-Fi Access Point Security*.
  Tick the box and save. The change takes effect the next time the access point starts.
* **At flash time** — the [browser flasher](https://glomargadaffi.github.io/pocket-dial/flasher/)
  can write the setting and the passphrase directly to the board. This is the easiest
  route for the headless `esp32s3-wifi` variant. (The `esp32s3-eth` build has no SoftAP
  at all — it is a node on your wired LAN — so access-point security does not apply to it.)

**Finding the passphrase.** The device generates its own, per unit — there is no
factory default, and nothing is baked into the firmware image. It is 20 characters from
an alphabet with no ambiguous glyphs (no `0`/`O`, no `1`/`I`/`L`), so it survives being
read off a screen and retyped into a desk phone. Read it from whichever applies:

| Build | Where the passphrase appears |
|-------|------------------------------|
| `display` | On the LVGL screen during captive-portal onboarding |
| `wifi` (headless) | Logged over serial at boot (`idf.py monitor`) |
| `eth` | Not applicable — this build has no SoftAP |
| Any | The dashboard panel above, once logged in as admin |
| Any | The browser flasher, if you set it at flash time |

You can rotate it from the same dashboard panel. Write the new one down **before**
restarting the access point — rotating it drops every associated phone.

### Variant: captive-portal onboarding (touch-display build)

The Guition JC3248W535 display build can boot into a **captive-portal onboarding** mode
that brings up a separate setup AP named **`My-Ap`** (`ONBOARDING_SSID` in
`main/esp_main_display.cpp`) and shows a join QR code on screen. When you join, the
device redirects all web traffic to its setup page so you can either join an existing
Wi-Fi network (Station mode) or stay in Standalone AP mode.

> [!NOTE]
> The onboarding portal has a **5-minute decay watchdog** (`CAPTIVE_DECAY_SECONDS = 300`
> in `main/esp_main_display.cpp`): if no configuration is confirmed within five minutes,
> the device reboots into Standalone AP mode (`esp32-sipserver`) on its own. If your
> portal disappears, just re-join `esp32-sipserver` and continue from step 2.

### Variant: wired Ethernet / PoE

W5500/LAN8720 builds (`SIP_TRANSPORT=eth`) are nodes on your wired LAN and obtain an
address via DHCP (with static fallback). There is no SoftAP; reach the dashboard at the
device's LAN IP or at `pocketdial.local`. See [HARDWARE_SELECTION.md](HARDWARE_SELECTION.md)
for board specifics.

---

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

If the page does not load, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md#dashboard-unreachable).

---

## 3. Log in and complete setup (first)

> [!IMPORTANT]
> **Log in and replace the default credential before doing anything else.**
> The device ships with a well-known default login — username `admin`,
> password `admin` — precisely so this step doesn't require any out-of-band
> secret. Every state-changing endpoint requires a valid, authenticated
> session, and until you replace the default credential, the server refuses
> everything else with `403 {"error":"setup_required"}` — "force setup on
> first use," enforced by the firmware itself, not just suggested by the
> dashboard (see [THREAT_MODEL.md](THREAT_MODEL.md) §5.1).

The following state-changing endpoints require a valid `pd_session` cookie
(else they return `401`) and, once logged in, a valid CSRF token (else `403`):
`/api/kill`, `/api/wifi/connect`, `/api/wifi/mode_ap`, `/api/factory-reset`,
`/api/telephony-config`, `/api/did-mapping`, and the OTA endpoints
(`/api/ota/upload`, `/api/ota/reboot`).

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
| DTMF admin PIN | Optional, 4-16 digits (`kMinDtmfPinLength`/`kMaxDtmfPinLength`); **no default** — the phone-keypad `*PIN#code` menu stays fully disabled until one is set |
| Storage | Salted, iterated SHA-256 — 50,000 rounds, 128-bit random salt per secret (NVS keys `admin_user`/`admin_pw_salt`/`admin_pw_hash` for the login credential, `admin_pin_salt`/`admin_pin_hash` for the DTMF PIN — independent, so clearing/rotating one never touches the other) |
| Brute-force lockout | 5 consecutive failed logins → 60-second lockout (`429`); auto-clears on a correct credential |
| Session token | ≥128-bit opaque, `HttpOnly` + `SameSite=Strict` cookie, 30-minute sliding expiry |

> [!TIP]
> The hash is salted and iterated, but a short or common password is still
> guessable if an attacker ever obtains the flash contents physically. **Use a
> real, unique password** — this is exactly what the forced-setup step exists
> to make you do instead of leaving `admin`/`admin` in place.

You can verify auth state any time with the read-only endpoint
`GET /api/admin/status`, which returns `{provisioned, needsSetup, authenticated}`
booleans — `provisioned`/`needsSetup` describe the login credential only (the
DTMF PIN has no equivalent status field; query `dtmfPinIsSet()`'s effect
indirectly by whether `*PIN#code` DTMF actions work).

---

## 4. Register a phone

pocket-dial is a SIP registrar. Any SIP client — a softphone app or a hardware IP phone —
registers against it with these settings:

| Field | Value | Notes |
| :--- | :--- | :--- |
| SIP server / registrar / proxy | `192.168.4.1` | Or the device's LAN IP on wired builds; `pocketdial.local` where mDNS resolves |
| Port | `5060` | UDP signaling port |
| Transport | **UDP** | The engine only speaks UDP |
| Username / Auth ID / extension | your choice, e.g. `1001` | The registrar keys clients by this extension (AOR) |
| Password | (any / blank) | There is **no SIP digest authentication** today — the registrar accepts the REGISTER on the open link. See [THREAT_MODEL.md](THREAT_MODEL.md) S-3 |
| Codec | **G.711 only** — µ-law (PCMU, payload 0) and a-law (PCMA, payload 8), plus telephone-event (101) | The server rewrites SDP to `0 8 101` via `enforceG711()` |
| Registration expiry | up to `3600` s | `DEFAULT_EXPIRES`/`MAX_EXPIRES`; higher requests are capped to 3600 |

> [!IMPORTANT]
> **Do not reuse the extensions `777` or `999`.** They are reserved virtual extensions
> (echo test and all-page broadcast — see step 5).

**Steps:**

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

---

## 5. Make a test call

### 5a. Echo test — dial `777`

`777` is a built-in echo loopback. When an endpoint dials `777`, the server answers
`200 OK` using **the caller's own SDP connection info**, so the phone streams its audio
back to its own receive port — a zero-DSP hardware echo test (`RequestsHandler::onInvite`).

1. From a registered phone, dial **`777`**.
2. The call connects immediately. Speak — you should hear your own voice echoed back.
3. Hang up.

If you hear nothing, your audio path (codec/RTP) is the suspect — see
[TROUBLESHOOTING.md](TROUBLESHOOTING.md#one-way-or-no-audio).

### 5b. All-page broadcast — dial `999`

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
3. Audio (RTP) flows **peer-to-peer** directly between the two phones — the device only
   brokers signaling (see [ARCHITECTURE.md](ARCHITECTURE.md) and [SCALING.md](SCALING.md)).
4. The active call appears in the `sessions` list on the dashboard.

---

## 6. Quick-start checklist

- [ ] Firmware flashed (see [README.md](../README.md#building--testing) / [OTA.md](OTA.md)).
- [ ] Powered on; joined Wi-Fi SSID **`esp32-sipserver`** (open) — or completed the
      `My-Ap` captive portal on the display build.
- [ ] Dashboard reachable at `http://192.168.4.1` (or `http://pocketdial.local`).
- [ ] Logged in with the default credential (`admin`/`admin`) and completed setup
      via `/api/admin/set-credential` (real username + password ≥8 chars).
- [ ] Logged in with the new credential (`/api/admin/login`) before using any gated control.
- [ ] First softphone/IP phone registered: server `192.168.4.1:5060`, **UDP**, **G.711**,
      extension e.g. `1001`.
- [ ] Second extension registered (e.g. `1002`).
- [ ] Dialed **`777`** — heard echo.
- [ ] Dialed **`999`** — other phones paged.
- [ ] Placed a direct `1001 → 1002` call — two-way audio.

**Next:** [PHONE_COMPATIBILITY.md](PHONE_COMPATIBILITY.md) ·
[HARDWARE_SELECTION.md](HARDWARE_SELECTION.md) ·
[TROUBLESHOOTING.md](TROUBLESHOOTING.md) · [SCALING.md](SCALING.md)
