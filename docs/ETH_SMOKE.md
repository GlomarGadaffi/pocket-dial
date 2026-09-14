# W5500 Ethernet bring-up & smoke test

End-to-end "is this board alive and on the network?" runbook for the wired-Ethernet
(`SIP_TRANSPORT=eth`) firmware. Written against the **LilyGO T-ETH-ELITE S3** (the default
`eth` board) but applies to any W5500 board — just pick the pin map with `PD_ETH_BOARD`
(see [HARDWARE_SELECTION.md](HARDWARE_SELECTION.md)).

Unlike the Wi-Fi/display SoftAP builds, a wired board joins **your existing LAN** and pulls
a DHCP lease, so your dev machine reaches it over the normal network — you do **not** have
to drop your Wi-Fi to talk to it. That makes this smoke loop much simpler than the display
board's captive-AP dance.

> Reusable scripts live in `.smoke/`: `capture.py` (bounded serial boot capture) and
> `sip_probe.py` (UDP SIP REGISTER/OPTIONS probe). Both use only `pyserial`/stdlib, which
> ship in the ESP-IDF Python env.

> [!IMPORTANT]
> **On a freshly flashed board the HTTP step comes BEFORE the SIP step, and it is not
> optional.** `app_main()` holds the SIP task down until an admin credential has been
> committed (`main/esp_main_eth.cpp:468-496` — `[boot] device unprovisioned — SIP stack
> held dark until credential committed`, then a poll on `AdminAuth::credentialIsSet()`).
> The HTTP dashboard is launched first and unconditionally, precisely so you can do that
> (`esp_main_eth.cpp:466`). So on a virgin board:
> * port 80 answers immediately — the listener **always** accepts, there is no
>   socket-level dark/open gate any more ([API.md §0](API.md), and
>   `tests/AdminHttpGate_test.cpp` pins it as a regression);
> * port 5060 does **not** answer, and that is the gate working, not a fault;
> * after 30 minutes with no credential the board reboots and re-arms the same wait
>   (`kMaxCredentialWaitSec`, `esp_main_eth.cpp:473`).
>
> The `eth` build has **no SoftAP**, so SoftAP WPA2 (`ap_secure`) is not a factor on these
> boards. The registrar admission mode is.

---

## 0. Prerequisites

- ESP-IDF env sourced in the shell (this machine: `. 'C:\esp\v6.0.1\esp-idf\export.ps1'`).
- Board powered + connected:
  - **USB-C** to the dev machine (for flashing + serial), **and**
  - **RJ45** into a switch/router on the same LAN as your machine (or PoE — the Elite is
    802.3af Class 0; a PoE switch powers it without USB, but you still want USB for serial).
- **PoE + USB at the same time is safe on the T-ETH-ELITE *with the OTG SW set to OFF*.**
  Per the board schematic, a P-FET (AO3401A) automatically disconnects USB VBUS from the
  5 V rail when PoE power is present and blocks back-feed toward the USB host; the OTG
  switch is the only path that drives 5 V *out* of the USB-C port (it exists to power OTG
  peripherals from PoE). So: OTG SW **OFF** whenever a computer is on the USB port —
  matching LilyGO's own instruction. Use an active **802.3af/at** source only; never a
  passive PoE injector.
- Target already set to `esp32s3` (the Elite/Waveshare are S3 parts).

## 1. Find the serial port

Plug in over USB-C and identify the new port.

```powershell
# PowerShell — list COM ports before/after plugging in to spot the new one
[System.IO.Ports.SerialPort]::GetPortNames()
# or, with IDF env sourced:
python -m serial.tools.list_ports -v
```

The Elite enumerates as the ESP32-S3 native USB-CDC (or a CH343/CP210x UART, depending on
the OTG-switch position). Note the port as `COMx` below. If it doesn't appear for flashing,
hold **BOOT**, tap **RST**, release BOOT to force download mode (and check the OTG switch).

## 2. Build

```powershell
# Default = LilyGO T-ETH-ELITE S3 pin map
idf.py -B build_eth_elite -D SIP_TRANSPORT=eth build
# Waveshare instead:  -D SIP_TRANSPORT=eth -D PD_ETH_BOARD=waveshare
```

CMake prints the selected map at configure time:
`SipServer transport: W5500 Ethernet — board: elite`.

## 3. Flash

```powershell
idf.py -B build_eth_elite -p COMx -D SIP_TRANSPORT=eth flash
```

(Plain `flash` preserves NVS — it only writes bootloader/partition-table/ota_data/app.)

## 4. Capture the boot log → confirm link + IP

`idf.py monitor` is interactive and hard to bound; use the capture script for a hands-off
window instead. Connect the Ethernet cable **before** (or during) the capture.

```powershell
python .smoke\capture.py COMx 25 .smoke\boot_eth_elite.txt
```

In the captured log, confirm three things in order:

1. **Pin map compiled in** (proves the right board was selected):
   ```
   W5500 board: LilyGO T-ETH-ELITE S3 — SCLK=48 MISO=47 MOSI=21 CS=45 INT=14 RST=-1 @ 40 MHz
   ```
2. **Link up** (PHY sees the cable):
   ```
   SipServerETH: Ethernet link UP
   ```
3. **DHCP lease** (the part you need for the next steps):
   ```
   SipServerETH: IP:      192.168.x.y
   SipServerETH: Gateway: 192.168.x.1
   ```

Record the IP as `<BOARD_IP>`.

Then read one more line, because it decides whether §5 or §6 is your next step:

```
[boot] device unprovisioned — SIP stack held dark until credential committed
```

* **Present** → the board has never had an admin credential committed. Do §5 now; SIP will
  not answer until you do.
* **Absent** → the board is past the boot gate (NVS key `provisioned`) and SIP is already
  running. §5 and §6 can be done in either order. Note that this flag is a **latch**:
  `POST /api/factory-reset` does not clear it (`HttpServer::sendApiFactoryReset` erases the
  credential, the Wi-Fi keys, `ap_secure`/`ap_psk`/`cfgseed_gen` and the telephony/DID/CDR
  namespaces — not `provisioned`, and **not** the registrar mode either, see
  [TROUBLESHOOTING.md](TROUBLESHOOTING.md#all-phones-stopped-registering-at-once)), so a
  factory-reset board comes back on the default credential but with SIP **up**. Only a full
  NVS erase re-arms the boot gate.

Two optional lines are worth noting if you see them:

* `[boot] applied flash-time cfgseed` — the board carries a `cfgseed` record written by the
  browser flasher and has just applied it to NVS. On an `eth` board the seed's AP/STA fields
  are meaningless, but `regMode` is not: a board seeded `regMode=2` comes up with the SIP
  registrar in **`secure`** mode. Read step 6 accordingly. The line's **absence is normal**
  — a board flashed before `cfgseed` existed, or one whose seed generation was already
  applied, prints nothing.
* An NVS init error early in the log — the firmware erases and re-inits NVS on
  `ESP_ERR_NVS_NO_FREE_PAGES` / `NEW_VERSION_FOUND`, which also clears `cfgseed_gen` and so
  re-arms the flash-time seed on the next boot (`DeviceConfig::applyFlashSeed()`). It also
  clears `provisioned`, so the boot gate above comes back.

## 5. HTTP dashboard smoke — the management surface, and forced setup

The eth build serves the HTTP dashboard on **port 80**, on every boot, provisioned or not.

```powershell
curl.exe -s -o NUL -w "HTTP %{http_code}\n" http://<BOARD_IP>/
# -> HTTP 200
```

`GET /` is ungated and so are `/api/status`, `/api/cdr`, `/metrics`, `/api/wifi/scan`,
`/api/admin/status`, `/api/ota/status` and `GET /config/<mac>.cfg`
(`HttpServer::handleClient()` dispatch, `src/Helpers/HttpServer.cpp:457-755`).
`/metrics` is a useful extra smoke read on a wired board — it answers `200` with six
`pocketdial_*` families as soon as HTTP is up, all-zero until the SIP engine attaches.
A quick posture read costs one request:

```powershell
curl.exe -s http://<BOARD_IP>/api/admin/status
# -> {"provisioned":false,"needsSetup":true,"authenticated":false,"sessionRemainingSec":0}
```

`"needsSetup":true` means the board is still on the shipped default login
(`admin`/`admin`, `AdminAuth::kDefaultUsername`/`kDefaultPassword`) and
`HttpServer::requireAdmin()` will refuse **every** other admin-gated route — GETs
included — with `403 {"error":"setup_required"}` until you replace it
(`HttpServer.cpp:1864-1873`). Do that now; the SIP stack is waiting on it.

<a name="login-recipe"></a>
```bash
DEVICE=http://<BOARD_IP>
JAR=cookies.txt

# 1) Log in. On a board that has never been set up this is the shipped default.
LOGIN=$(curl -s -c "$JAR" -H "Origin: $DEVICE" \
     -X POST --data "username=admin&password=admin" \
     "$DEVICE/api/admin/login")
# -> {"status":"ok","authenticated":true,"needsSetup":true,"csrf":"3f2a...e91c"}

CSRF=$(printf '%s' "$LOGIN" | sed -n 's/.*"csrf":"\([0-9a-f]*\)".*/\1/p')
[ -n "$CSRF" ] || { echo "login failed: $LOGIN" >&2; exit 1; }

# 2) If the login said needsSetup:true, replace the default credential before
#    anything else. Password >= 8 chars (AdminAuth::kMinPasswordLength).
curl -s -b "$JAR" -H "Origin: $DEVICE" -H "X-CSRF: $CSRF" \
     -X POST --data "username=admin&password=CHANGE-THIS-PASSWORD" \
     "$DEVICE/api/admin/set-credential"
# -> {"status":"ok","provisioned":true,"needsSetup":false}

# The session and its CSRF token survive the credential change, so "$JAR"/"$CSRF"
# keep working — no second login needed.
```

Every **mutating** call from here on carries three things: the cookie, a matching `Origin`
(or none at all — `curl` sending no `Origin` is deliberately allowed), and `X-CSRF`.
This is the same recipe [TROUBLESHOOTING.md](TROUBLESHOOTING.md#403-on-an-api-call-that-used-to-work)
and [API_TESTS.md §2](API_TESTS.md) use; keep them in step.

> [!NOTE]
> The optional `dtmfPin=` field on the same `set-credential` call sets the **separate**
> numeric PIN for the phone-keypad admin menu (`*PIN#code`). It has no default and the
> menu stays entirely unreachable until you set one — it is not the web login and setting
> one is not required to finish setup.

Seconds after the credential lands you should see, in a still-running serial capture:

```
[boot] credential set — unblocking SIP stack
```

Optionally run the shared HTTP smoke suite against it (takes a bare `IP` or `host:port`,
defaults to the device AP if omitted — so pass the board's LAN IP explicitly):

```bash
tests/http/test_api.sh <BOARD_IP>
```

> [!WARNING]
> **`test_api.sh` sets a real admin credential and leaves it set.** Its first suite logs in
> with `admin`/`admin` and completes setup as `admin` / `realpassword123`
> (`tests/http/test_api.sh:222`) — every later run, and every manual `curl` afterwards, must
> use that password, not the default. Its **last** suite (`TC-AUTH-11`) deliberately fails
> five logins to trip the brute-force lockout, so the board answers `429` on
> `/api/admin/login` for at least 60 s after the run finishes; that is the suite passing,
> not a fault. Run it on a scratch board you are willing to erase, and factory-reset or
> `erase_region 0x9000 0x6000` afterwards. 27 test cases, and the ordering in its header
> comment is load-bearing — the auth suite runs **first** now, because nothing else works
> without the session it establishes.

## 6. SIP smoke — the signaling stack is alive

From the dev machine (same LAN), poke the registrar. **Any** SIP status line back
(`200 OK`, `401 Unauthorized`, `403 Forbidden`) means the UDP receiver + parser + handler
are all working — that's a pass.

```powershell
python .smoke\sip_probe.py <BOARD_IP> 5060
# -> [probe] RESPONSE to REGISTER ...: SIP/2.0 200 OK
# -> [probe] RESULT: ALIVE   (exit 0)
```

> [!NOTE]
> **Which status you get depends on the registrar mode, and all of them are a pass.**
> * **`open`** — the shipped default. There is no SIP authentication at all, so the probe's
>   REGISTER for extension `9001` is simply accepted: `200 OK`. It really does take a client
>   slot; the registrar prunes it after ~15 s of not answering `OPTIONS`.
> * **`learn`** — an unknown MAC claiming an unclaimed extension is adopted on first
>   contact, so the probe is also likely to be answered `200 OK`.
> * **`secure`** — every `REGISTER` is digest-challenged (RFC 2617), so the probe can never
>   reach `200 OK`. `401` is the answer and it is still a pass for *this* test: it proves
>   the stack parses and answers. It does **not** prove a real handset can register.
>
> Check the mode with `curl -s -b "$JAR" http://<BOARD_IP>/api/registrar` — a read-only
> `GET` that needs no `X-CSRF`, but it **is** session-gated and refuses with
> `403 {"error":"setup_required"}` until §5 is done, so run §5 first.

> [!NOTE]
> **`NO RESPONSE` on a board you have not set up yet is expected, not a fault** — see the
> boot gate in §4. Finish §5 and re-run the probe.

---

## Pass criteria

| # | Check | Pass signal |
|---|---|---|
| 1 | Correct pin map | `W5500 board: LilyGO T-ETH-ELITE S3 …` in boot log |
| 2 | PHY link | `Ethernet link UP` |
| 3 | DHCP | `IP: 192.168.x.y` |
| 4 | HTTP dashboard | `curl` returns `200` on `GET /` on port 80. *Connection refused* is **always** a fail — the listener is unconditional |
| 5 | Forced setup completes | `POST /api/admin/set-credential` → `200 {"needsSetup":false}`, and the serial log prints `[boot] credential set — unblocking SIP stack` |
| 6 | SIP stack | `sip_probe.py` prints `RESULT: ALIVE` (any SIP status line — `200`, `401` or `403`) |

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| No `Ethernet link UP` at all | Cable/switch dead, or wrong SPI pin map — recheck the `W5500 board:` line matches your hardware. On a breadboard, keep SPI leads <5 cm (the W5500 bus runs at **40 MHz** — `esp_main_eth.cpp:113`, and the boot line above prints it); see [HARDWARE.md §9B](HARDWARE.md). |
| Link UP but no `IP:` | No DHCP server on that LAN segment, or the lease is slow. Set `USE_STATIC_IP 1` (+ the `STATIC_IP/GATEWAY/NETMASK` defines) at the top of `main/esp_main_eth.cpp` and reflash to bypass DHCP. |
| `sip_probe.py` → `NO RESPONSE`, but HTTP answers | Almost always the boot provisioning gate: the board has no admin credential yet and the SIP task has not been started (`esp_main_eth.cpp:587-631`). Do §5, watch for `[boot] credential set — unblocking SIP stack`, re-probe. |
| `sip_probe.py` → `NO RESPONSE` and HTTP is also dead | Wrong IP, a firewall on the dev machine, or you're not on the same subnet. Ping `<BOARD_IP>` first. |
| The board reboots every ~30 minutes and nothing is configured | The provisioning wait is bounded: no credential within `kMaxCredentialWaitSec` (1800 s) and it restarts to retry (`esp_main_eth.cpp:473-482`). Complete §5. |
| Board never enumerates for flashing | OTG-switch position / native-USB; BOOT-hold + RST tap to enter download mode. |
| Wrong board's pins compiled | You passed (or defaulted) the wrong `PD_ETH_BOARD`. Rebuild; the `W5500 board:` boot line is the ground truth. |
| `curl` says **connection refused** on port 80 | A real fault. The HTTP listener accepts unconditionally on every build and every provisioning state — there is no dark/open gate to reopen (`tests/AdminHttpGate_test.cpp`, `AdminHttpGate.Boot_Provisioned_StillListensImmediately`). Check the board is at the IP you think it is, that `http_dashboard` started in the serial log, and that nothing on the dev machine is filtering port 80. |
| `403 {"error":"setup_required"}` from any admin route | The board is still on the `admin`/`admin` default. Complete §5's `set-credential` step; nothing else — not even gated `GET`s — is permitted first (`HttpServer.cpp:1864-1873`). |
| `403 {"error":"missing or invalid CSRF token"}` from a script | A mutating call needs the per-session `X-CSRF` header. Capture `"csrf"` from the `POST /api/admin/login` response ([API.md §0](API.md), worked example in §5 above and [OTA.md §3.2](OTA.md)). Read-only checks are unaffected. |
| `401 {"error":"invalid username or password"}` on login | Wrong credential. If someone has run `test_api.sh` against this board, the password is `realpassword123`, not `admin`. |
| `POST /api/factory-reset` answers `501` on this board | **Stale firmware.** Fixed in #189 — a current build answers `200` and reboots on every ESP transport. If you see a `501` here, the board is running pre-#189 firmware, and that `501` means the wipe *completed* without a reboot: power-cycle it yourself, then redo first-use setup. |
| `429` on `/api/admin/login` | Brute-force lockout: 5 failures (**counted globally, not per client** — `req.clientIp` is never populated on the login path, so every failure shares one bucket; see [THREAT_MODEL.md](THREAT_MODEL.md) D-3), 20 aggregate, cooldown doubling from 60 s to ~16 min and cleared only by a **correct login** (`AdminAuth.hpp:60-82`, [THREAT_MODEL.md §5.2](THREAT_MODEL.md)). Wait it out, or power-cycle — the counters are in-process only. |
| A real handset gets `401` forever, though `sip_probe.py` passes | The registrar is in `secure` mode (possibly seeded at flash time via `cfgseed`'s `regMode`, which works from v1.4.1 — on v1.3.0/v1.4.0 rule that out, see [#151](https://github.com/GlomarGadaffi/pocket-dial/issues/151)) and this phone has no digest secret — and **cannot be given one**: nothing in the firmware calls `SipSecretStore::setSecret()`, so `secure` mode rejects every handset rather than authenticating it (see [LEARN_MODE.md](LEARN_MODE.md) Step 4). In `secure` mode INVITE is challenged too, not just REGISTER. Check `GET /api/registrar`; recovery is in [TROUBLESHOOTING.md](TROUBLESHOOTING.md#all-phones-stopped-registering-at-once). |
| Settings you cleared come back after a reboot | The `cfgseed` partition re-applies at boot whenever `cfgseed_gen` is missing — which a factory reset or an NVS erase deliberately makes true. Erase the seed too: `esptool.py -p COMx erase_region 0xFFF000 0x1000` (16 MB layout only). |

**Related:** [HARDWARE.md §5](HARDWARE.md) (Elite pinout) · [HARDWARE_SELECTION.md](HARDWARE_SELECTION.md) · [TROUBLESHOOTING.md](TROUBLESHOOTING.md) · [API.md](API.md) · [THREAT_MODEL.md](THREAT_MODEL.md)
