# Over-The-Air (OTA) Firmware Updates

Phase-1 production hardening adds OTA firmware updates to pocket-dial on the
ESP32-S3. This document covers the partition layout, how to build and push an
update, the rollback strategy, the one-time migration from the old single-app
layout, and the security posture.

> TL;DR: dual-OTA (`ota_0` / `ota_1`) on the 16 MB flash, an admin-gated
> streaming upload endpoint (`POST /api/ota/upload`), explicit reboot
> (`POST /api/ota/reboot`), and mark-valid-on-healthy-boot rollback. Images are
> **not signed yet**: OTA is gated behind an admin **username + password**
> session plus a per-session CSRF token, and should be restricted to the local
> link until Secure Boot v2 lands (see [THREAT_MODEL.md](THREAT_MODEL.md)).

> [!CAUTION]
> **The dual-slot OTA flow with rollback has never been executed end to end on
> real hardware.** Nothing below has been proven on a device. Specifically:
>
> - **The only OTA code CI ever executes is the HTTP wrapper on the host build**,
>   where there is no flash. (CI does *compile* the firmware in an ESP-IDF matrix
>   job, but it never runs those images.)
>   `tests/http/test_api.sh` TC-OTA-03 asserts the upload returns
>   **`501`** (it never writes a byte to a partition), and TC-OTA-06/07 assert
>   that the reboot endpoint is a **deliberate no-op** whose only check is that
>   the host process is *still alive* afterwards. So CI proves the routing, the
>   auth gate and the streaming bypass of the 16 KB body cap. It proves nothing
>   about `esp_ota_write`, `esp_ota_end`, `esp_ota_set_boot_partition`, the
>   bootloader's `PENDING_VERIFY` handling, or rollback.
> - **The release workflow ships firmware with no test step at all.**
>   `.github/workflows/release.yml` is build → stage → publish; there is no job
>   between compiling an image and attaching it to a release.
> - The partition-table guard in `ci.yml` checks `partitions.csv` *as text*. It
>   confirms the layout has not regressed to single-slot; it does not flash
>   anything.
>
> **Consequence for a fleet update:** the first real exercise of this path will
> be on your hardware. Do the first update on **one** device that you can
> physically reach with a USB cable, and confirm the whole cycle (upload →
> reboot → healthy boot → `markValid()` in the log, see §4.1) before touching a
> second. The rollback described in §4 is the designed behaviour of
> `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE`, not an observed one on this project.

## 1. Partition layout

### 1.1 The new table (`partitions.csv`)

```
# Name,     Type, SubType,  Offset,    Size
nvs,        data, nvs,      0x9000,    0x6000
otadata,    data, ota,      0xf000,    0x2000
phy_init,   data, phy,      0x11000,   0x1000
ota_0,      app,  ota_0,    0x20000,   0x600000
ota_1,      app,  ota_1,    0x620000,  0x600000
```

### 1.2 Rationale

| Partition | Offset | Size | Why |
|-----------|--------|------|-----|
| `nvs`     | `0x9000`  | `0x6000` (24 KB) | **Byte-identical to the previous single-`factory` layout.** Holds WiFi creds plus, in namespace `storage`, the admin login credential (`admin_user`, `admin_pw_salt`, `admin_pw_hash`) and the *separate* phone-keypad DTMF PIN (`admin_pin_salt`, `admin_pin_hash`). Kept at the same offset/size so the data stays layout-compatible across the migration. **Do not move or resize.** |
| `otadata` | `0xf000`  | `0x2000` (8 KB)  | Two 4 KB sectors (the required size). Records which slot is active and the per-slot rollback/validation state. |
| `phy_init`| `0x11000` | `0x1000` (4 KB)  | RF calibration blob (unchanged role; shifted up to make room for `otadata`). |
| `ota_0`   | `0x20000` | `0x600000` (6 MB)| First app slot. |
| `ota_1`   | `0x620000`| `0x600000` (6 MB)| Second app slot (A/B partner). |

Arithmetic / alignment checks:

- `nvs` ends at `0x9000 + 0x6000 = 0xf000` → `otadata` starts there. ✅
- `otadata` ends at `0xf000 + 0x2000 = 0x11000` → `phy_init` starts there. ✅
- App partitions **must be 64 KB-aligned** on the ESP32-S3 (MMU flash-mapping
  granularity). `0x20000` and `0x620000` are both multiples of `0x10000`. ✅
- `ota_1` ends at `0x620000 + 0x600000 = 0xC20000`, well within the 16 MB
  (`0x1000000`) device, about **3.875 MB of flash left free** at the top for
  future partitions (e.g. a SPIFFS/LittleFS data partition or a coredump
  partition). ✅
- Each 6 MB slot is ~4× the current ~1.5 MB display image, generous headroom
  for UI growth without re-partitioning (which would force another full
  reflash).

`sdkconfig.defaults` already points the build at this file:

```ini
CONFIG_PARTITION_TABLE_CUSTOM=y
CONFIG_PARTITION_TABLE_CUSTOM_FILENAME="partitions.csv"
```

### 1.3 Rollback Kconfig

Added to `sdkconfig.defaults`:

```ini
CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y
```

This is the **single canonical symbol** for the anti-rollback / app-validation
workflow in ESP-IDF v5.x. (There is no separate `CONFIG_APP_ROLLBACK_ENABLE` in
mainline IDF; that name does not exist as a Kconfig option, so it is
intentionally not added.) With this enabled, a freshly activated OTA image boots
in the `PENDING_VERIFY` state and is **rolled back to the previous slot on the
next reset unless the running app confirms a healthy boot** (see §4).

## 2. Building

OTA is an on-device feature. The ESP-IDF build produces the image you upload.

```bash
# (one-time) point at your ESP-IDF v6.0+ install (v5.x fails at configure — see ONBOARDING.md)
. $IDF_PATH/export.sh

# Pick the transport you ship; the display build is the large one (~1.5 MB).
idf.py -D SIP_TRANSPORT=display set-target esp32s3
idf.py -D SIP_TRANSPORT=display build

# The OTA image is the application binary:
#   build/SipServer.bin
```

The desktop/host build (`cmake -B build -S . && cmake --build build`) compiles
the same `OtaUpdater` and HTTP endpoints, but with stubs: there is no flash
to write, so the host cannot perform a real update (see §3.4).

## 3. Pushing an update

### 3.1 Endpoints

| Method & path           | Auth                                   | Behaviour |
|-------------------------|----------------------------------------|-----------|
| `POST /api/ota/upload`  | full admin gate (session + CSRF)       | **Streaming.** Writes the request body into the inactive slot, validates, and stages it for boot. |
| `GET  /api/ota/status`  | none (read-only, no secrets)           | JSON: running / boot / next partition, inProgress flag, pending-verify flag, `otaSupported`. |
| `POST /api/ota/reboot`  | full admin gate (session + CSRF)       | Reboots into the staged image (device) / no-op simulation (host). |

The two mutating endpoints use the **exact same gate** as the existing mutating
endpoints (`/api/kill`, `/api/wifi/*`, `/api/factory-reset`), one shared
`HttpServer::requireAdmin(sock, req, /*needCsrf=*/true)`, which applies **four**
checks in this order:

1. **Same-origin.** A request carrying an `Origin` header must match an allowed
   local host; a request with **no** `Origin` at all (curl, native tooling, the
   smoke suite) is admitted by design: the `Origin` check is a browser-only
   control and is not what protects the endpoint. Failure ⇒
   `403 {"error":"cross-origin request rejected"}`.
2. **Session.** A valid `pd_session` cookie is required **unconditionally**.
   Failure ⇒ `401 {"error":"authentication required"}`.
3. **CSRF.** The mutating routes additionally require the session's token in an
   `X-CSRF` header. Failure ⇒
   `403 {"error":"missing or invalid CSRF token"}`.
4. **Forced initial setup.** While the device still stands on the factory-default
   `admin`/`admin` credential, every admin-gated route *except*
   `POST /api/admin/set-credential` is refused ⇒
   `403 {"error":"setup_required"}`.

> [!IMPORTANT]
> **There is no "unprovisioned device, so OTA is open" state, and there never is
> again.** Earlier firmware admitted these endpoints on same-origin alone until
> an admin PIN was set; **that bypass was removed.** The device now ships with a
> default login credential precisely so the session check can be unconditional
> from the very first boot, and check 4 then refuses OTA outright until that
> default is replaced. A fresh board cannot be flashed over the air until
> *someone* has logged in as `admin`/`admin` and committed a real credential,
> and whoever does that first owns the device. The fresh-device window did not
> vanish; it changed from "ungated" to "first-come-first-owns" (see §6).
>
> Note the ordering: **CSRF (check 3) runs before the setup check (check 4)**. On
> a factory-fresh device a script that logs in but sends no `X-CSRF` header gets
> the CSRF `403`, *not* `setup_required`: the message names the first failure,
> not the only problem.

`/api/ota/upload` is **not** subject to the 16 KB request body cap; it is
intercepted before the buffered path and streamed (a firmware image is >1.5 MB).

`GET /api/ota/status` is genuinely ungated (no origin check, no session): it
reports only partition labels and the pending-verify flag.

### 3.2 Curl walk-through

Prerequisite: the device must already have a real admin credential. If it is
still on the factory default `admin`/`admin`, every step after login returns
`403 {"error":"setup_required"}`; replace the default first (dashboard, or
`POST /api/admin/set-credential` with `username=`/`password=` form fields, which
itself needs a session and a CSRF token from a default-credential login).

```bash
DEVICE=http://192.168.4.1          # or http://pocketdial.local
JAR=cookies.txt

# 1) Log in with the admin USERNAME + PASSWORD to obtain a pd_session cookie AND
#    the session's CSRF token. Every mutating request needs BOTH: the cookie
#    proves who you are, the token proves the request came from something that
#    was told the token rather than from a page that merely rode your cookie.
#    The Origin header is optional for a script (a request with no Origin is
#    admitted); it is shown here so the recipe also works pasted into a browser
#    context.
LOGIN=$(curl -s -c "$JAR" \
     -H "Origin: $DEVICE" \
     -X POST --data "username=YOUR_USER&password=YOUR_PASS" \
     "$DEVICE/api/admin/login")
# -> {"status":"ok","authenticated":true,"needsSetup":false,"csrf":"3f2a...e91c"}
#
# Wrong credentials -> 401 {"error":"invalid username or password"}, and repeated
# failures trip the (global) lockout -> 429 {"error":"too many failed attempts;
# try again later"}. A stale script still POSTing "pin=..." sends no username at
# all, so it fails this way and will lock its own source address out.
# "needsSetup":true means the login succeeded against the DEFAULT credential —
# fix that before going further or step 3 returns 403 setup_required.

CSRF=$(printf '%s' "$LOGIN" | sed -n 's/.*"csrf":"\([0-9a-f]*\)".*/\1/p')
[ -n "$CSRF" ] || { echo "login failed: $LOGIN" >&2; exit 1; }

# 2) Inspect current OTA state (optional).
curl -s "$DEVICE/api/ota/status"
# -> {"running":"ota_0","boot":"ota_0","next":"ota_1","pendingVerify":false,"otaSupported":true,"error":""}

# 3) Stream the new firmware into the inactive slot.
#    Content-Length is set automatically by --data-binary @file.
curl -s -b "$JAR" \
     -H "Origin: $DEVICE" \
     -H "X-CSRF: $CSRF" \
     -H "Content-Type: application/octet-stream" \
     -X POST --data-binary @build/SipServer.bin \
     "$DEVICE/api/ota/upload"
# -> {"status":"ok","bytes":1543210,"rebootRequired":true,"nextPartition":"ota_1",
#     "message":"image staged; POST /api/ota/reboot to boot it"}

# 4) Reboot into the new image.
curl -s -b "$JAR" \
     -H "Origin: $DEVICE" \
     -H "X-CSRF: $CSRF" \
     -X POST "$DEVICE/api/ota/reboot"
# -> {"status":"ok","message":"rebooting into the new image..."}
```

> [!NOTE]
> **Two separate migrations will break an old script here.**
> 1. **The login body changed.** A script that posts `pin=YOUR_PIN` authenticates
>    nothing: the handler reads `username` and `password` form fields, so the
>    attempt fails with `401` and counts toward the lockout.
> 2. **The `X-CSRF` header is required.** A script written against an earlier
>    firmware sends the cookie but no token and gets
>    `403 {"error":"missing or invalid CSRF token"}` on the upload and reboot
>    steps. Capture the token from the login response as shown above.
>
> A script that skipped login entirely because the device was "unprovisioned"
> now gets `401 {"error":"authentication required"}`, see below.

Note the gate on these endpoints is **four** checks, not two: same-origin, then
the session cookie, then the per-session CSRF token on the mutating ones (§2.1 of
[API.md](API.md)), then the forced-setup refusal while the default credential
stands. A recipe that sends only the cookie gets `403`.

**There is no longer a "skip the login on a fresh device" shortcut.** Earlier
firmware let the upload through on same-origin alone until an admin PIN was
provisioned; **that unprovisioned bypass was deleted.** The session check is now
unconditional, so an unauthenticated upload gets `401` on any device in any
state, and a device still on the default `admin`/`admin` additionally gets
`403 setup_required`, meaning a factory-fresh board is *not* OTA-flashable at
all until an operator commits a real credential. The old "an open AP with an
ungated OTA endpoint" exposure is closed by construction (see §6).

### 3.3 Upload response codes

| Code | Meaning |
|------|---------|
| `200` | Image written, validated, and staged. `rebootRequired:true`. |
| `401` | No/invalid `pd_session` cookie: `{"error":"authentication required"}`. Unconditional; there is no unprovisioned exemption. |
| `403` | `{"error":"cross-origin request rejected"}`: an `Origin` header was sent and did not match an allowed local host. |
| `403` | `{"error":"missing or invalid CSRF token"}`: session is valid but `X-CSRF` was absent or stale. |
| `403` | `{"error":"setup_required"}`: the device is still on the default `admin`/`admin`; change it via `POST /api/admin/set-credential` first. |
| `411` | Missing or zero `Content-Length` (the stream size is required). |
| `400` | Upload truncated / socket closed early, or a flash write failed mid-stream. |
| `422` | `esp_ota_end()` rejected the image (bad magic / corrupt / not a valid app). |
| `500` | `esp_ota_begin` / `esp_ota_set_boot_partition` failed. |
| `501` | Host build only: OTA is not available off-device. |

### 3.4 Host (desktop) build behaviour

The host binary is for development and CI smoke tests; it has no flash.

- `POST /api/ota/upload` drains the request body (bounded by `Content-Length`
  and the existing 5 s per-socket receive timeout, so it never hangs) and
  returns **`501 {"error":"OTA only available on device"}`**. We deliberately
  return 501 rather than a simulated `200` so a real update can never be
  confused with the host stub in tooling/CI.
- `GET /api/ota/status` returns valid JSON with placeholder partition labels
  (`"running":"host"`, …) and `"otaSupported":false`.
- `POST /api/ota/reboot` returns `200 {"status":"ok","simulated":true,…}` and
  **does not exit the process** (the smoke-test suite keeps running).

## 4. Rollback strategy & failure handling

**Strategy: mark-valid-on-healthy-boot.** It is the simplest sound scheme and
is what `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y` is built for.

1. `POST /api/ota/upload` writes the image to the inactive slot and, on success,
   calls `esp_ota_set_boot_partition()`: the slot is now the boot choice but is
   marked `PENDING_VERIFY`.
2. `POST /api/ota/reboot` restarts the device into that slot.
3. On the **next** boot the bootloader sees `PENDING_VERIFY`. The application
   must affirm it is healthy by calling
   `esp_ota_mark_app_valid_cancel_rollback()` (exposed as
   `OtaUpdater::markValid()`), which flips the slot to `VALID`.
4. If the new image **crashes or boot-loops before** calling `markValid()`, the
   bootloader **automatically rolls back** to the previously valid slot on the
   subsequent reset. No bricking.

### 4.1 Integration in firmware `app_main` (wired in)

The application confirms a healthy boot from each firmware entry point's
`http_server_task`, all four: `main/esp_main.cpp`, `esp_main_eth.cpp`,
`esp_main_eth_lan8720.cpp`, and `esp_main_display.cpp`. After the SIP engine and
HTTP dashboard are up, the task waits **5 seconds** of stable operation
(`otaSettleSec >= 5` in each file), then confirms the image:

```cpp
#include "OtaUpdater.hpp"
// ... in the dashboard task's steady-state loop, after the servers are up:
if (OtaUpdater::isPendingVerify()) {
    OtaUpdater::markValid();   // confirm this image; cancel the pending rollback
}
```

The "few seconds of healthy operation" gate means a freshly OTA'd image that
crashes or boot-loops during startup never reaches `markValid()`, so the
bootloader rolls it back to the previous slot on the next reset. The check is
cheap and idempotent (`isPendingVerify()` is `false` on a normal boot), so it is
a no-op except immediately after an OTA.

> **Health-gate scope:** the confirmation runs in the normal operating path
> (the path a configured device follows after an OTA reboot). The display
> build's first-run *captive-onboarding* path does not confirm; that path is
> not reachable as a post-OTA boot of a configured device. A stricter health
> signal (e.g. confirm only after the first successful SIP REGISTER) is a
> possible future refinement.

### 4.2 Other failure modes

| Failure | Behaviour |
|---------|-----------|
| Upload truncated (Wi-Fi drop mid-stream) | `esp_ota_write` stream ends short → handler `abort()`s the session, returns `400`. The boot partition is unchanged; the device keeps running the current image. |
| Corrupt image | `esp_ota_end()` returns `ESP_ERR_OTA_VALIDATE_FAILED` → `422`. Slot not activated. |
| Power loss during write | The slot is partially written but never activated; `otadata` still points at the running slot. Next boot is the old image. Re-upload to retry. |
| New image boot-loops | Anti-rollback restores the previous slot; the image is only confirmed after a healthy boot reaches `markValid()` (§4.1). |

## 5. Migration from the single-`factory` layout

The previous table had one `factory` app partition at `0x10000` size `0x400000`.
Moving to dual-OTA **changes the partition table itself**, which the running
firmware cannot rewrite from inside an OTA. Therefore:

> **A one-time, full reflash over USB/JTAG is required to migrate a device from
> the old single-`factory` layout to the new dual-OTA layout.** After that,
> updates are OTA.

```bash
. $IDF_PATH/export.sh
idf.py -D SIP_TRANSPORT=display set-target esp32s3
idf.py -D SIP_TRANSPORT=display build
idf.py -p /dev/ttyUSB0 flash      # writes bootloader + new partition table + app to ota_0
```

### 5.1 NVS / re-onboarding caveat

`nvs` is kept at the **identical** offset (`0x9000`) and size (`0x6000`), so its
contents are *layout-preserved*. **However**, a full migration flash often erases
the whole chip depending on the method used:

- `idf.py flash` writes only the bootloader, partition table, and app; it does
  **not** explicitly erase `nvs`, so creds *may* survive.
- `idf.py erase-flash` (or a factory programming jig) **wipes everything**,
  including `nvs`.

Because the safe assumption differs per tool and the partition table offsets for
everything *after* `nvs` have shifted, treat the migration as a clean slate:

> After migrating a device to the dual-OTA layout, **re-onboard it**: reconnect
> WiFi and **set the admin username and password again** (and the DTMF PIN, if
> you use the phone-keypad admin menu). Do not assume the old WiFi password or
> credential carried over.

A wiped `nvs` returns the device to the factory-default `admin`/`admin` with
forced first-use setup, which has a consequence worth planning for on a fleet
migration:

> On the **wifi**, **eth** and **lan8720** builds the SIP stack is **held down at
> boot until an admin credential is committed** through the web dashboard. A
> freshly migrated board will come up with the dashboard reachable but **no SIP
> service at all**, logging `device unprovisioned — SIP stack held dark until
> credential committed`, and `/api/registrar` will answer `{"attached":false,
> "mode":"unknown","devices":[]}`. That is the designed state, not a fault.
> The wait is bounded: the board **reboots itself to retry after 30 minutes**
> (`kMaxCredentialWaitSec = 1800`, identical in all three builds), so a board
> that keeps restarting every half hour after migration usually means nobody has
> finished onboarding it, not that the image is bad.
> The **display** build is deliberately *not* gated this way: it boots straight
> into its normal network role ("up usable, secure later") and onboards from the
> screen.

## 6. Security

**Today, OTA images are unsigned and unencrypted.** The only controls on the
upload path are:

- the **admin session** gate: a username + password login that mints a
  `pd_session` cookie, enforced **unconditionally** on every device in every
  state, with a brute-force lockout (`429`) on the login route (**global, not
  per-client**, see [THREAT_MODEL.md](THREAT_MODEL.md) D-3);
- the **per-session CSRF token** (`X-CSRF`) on the mutating routes; and
- the **same-origin** check, which constrains browsers only (a request with no
  `Origin` header is admitted, so this is defence in depth, not the gate).

That means anyone who (a) is on the local link and (b) holds the admin username
and password can flash arbitrary firmware. This matches threats **T-5
(firmware/OTA tampering)** and **E-1** in
[THREAT_MODEL.md](THREAT_MODEL.md), which already anticipated this workstream.

**What changed since this document was first written:** the gate used to be an
admin *PIN* that was only enforced "once provisioned", which left a fresh device
with an open AP and an ungated OTA endpoint, a genuine remote
persistent-compromise vector. **That model is gone.** The credential is now a
username + password, the session check is unconditional, and forced first-use
setup refuses OTA outright until the default `admin`/`admin` is replaced, so
there is no longer an **unauthenticated** path to OTA on any device in any state.

**A first-run window does still exist, though, and it is different from the old
one.** Because the factory default is a *published* credential, anyone with
link-layer reach to an unclaimed device can log in as `admin`/`admin`, commit
their own credential, and then flash it. The race is first-come-first-owns
(THREAT_MODEL §5.1), not an open door, but it is a race, so **provision on the
bench, not on the deployed link.**

The numeric PIN that still exists is
the **DTMF PIN** for the phone-keypad admin menu (`*PIN#code`: NTP resync, WiFi
topology switch, factory reset); it has no default, is unrelated to the web
session, and **unlocks no HTTP and no OTA**.

Operational guidance until signing lands:

- **Replace the default `admin`/`admin` credential on every device before it
  leaves the bench.** The firmware forces this before it will accept an OTA, but
  the default is a published credential: a device left on it is one the first
  person to reach it will claim and own.
- Choose a real password: the login route is always reachable (the dashboard
  listener is always bound, see §6.1), so the credential and the lockout are the
  whole HTTP-plane defence.
- **Restrict OTA to the local link** (the device is a LAN appliance; do not
  expose `/api/ota/*` to the internet).
- Verify the image you push (e.g. compare a hash of `build/SipServer.bin`
  against your build artifact) before uploading.
- **Update one reachable device first.** This path has never been run end to end
  on hardware (see the CAUTION at the top of this document).

### 6.1 The dashboard is always reachable

Some older notes describe a "dark by default" HTTP listener that stayed unbound
on a provisioned device and was opened only inside a bounded admission window,
via a `*4887` DTMF star code, a fresh-provisioning grace period, or an
authenticated keepalive. **All of that was removed.** There is no star code, no
grace window, and no keepalive endpoint; `HttpServer`'s constructor opens the
listen socket immediately and it stays open. `requireAdmin()` is the only admin
gate.

For an operator this matters in one practical way: **"connection refused" on the
dashboard port is now always a genuine fault** (a crashed or unbooted device, a
wrong address, or a network problem) and never an expected security state to be
cleared with a star code. Do not go hunting for a way to "reopen" the web UI on a
device that is simply not answering.

Roadmap (durable fix, see [THREAT_MODEL.md](THREAT_MODEL.md) §roadmap, P2):

- Secure Boot v2: the bootloader verifies an RSA/ECDSA signature on the app,
  so only images signed with your private key will boot.
- Flash encryption: protects NVS (WiFi password, admin hash) and the app
  against a physical flash read (threats T-4 / I-3).
- Signed OTA images: `esp_ota_*` verifies the image signature against the
  Secure Boot key on write, closing the unsigned-OTA gap above.

These are intentionally **out of scope** for Phase-1 (they require key
management, a secured factory-provisioning flow, and burning eFuses, a one-way
operation), but the partition layout and rollback workflow shipped here are
forward-compatible with all three.

## 7. File map (what this change touched)

| File | Change |
|------|--------|
| `partitions.csv` | Single `factory` → dual-OTA (`otadata` + `ota_0` + `ota_1`); `nvs` unchanged. |
| `sdkconfig.defaults` | `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y`. |
| `src/Helpers/OtaUpdater.{hpp,cpp}` | Portable wrapper over the ESP-IDF `app_update` API; host stubs. |
| `src/Helpers/HttpServer.{hpp,cpp}` | Streaming `/api/ota/upload` interception + `/api/ota/status` + `/api/ota/reboot`. |
| `main/CMakeLists.txt` | Added `OtaUpdater.cpp` to `SRCS` and `app_update` to `REQUIRES`. |
| `docs/OTA.md` | This document. |
