# ESP32 Pocket-Dial Firmware: Field Incident Playbook

This document serves as the authoritative production-grade field operation and incident playbook for the pocket-dial ESP32 / ESP32-S3 firmware. It is intended for field engineers, system administrators, and core firmware maintainers to diagnose, isolate, secure, and recover devices suffering from field anomalies.

> [!WARNING]
> **STALE as of 2026-09-13 in every section discussing "dark by default"/the `*4887`
> DTMF trigger, or a bare admin PIN.** Both mechanisms have been removed: the HTTP
> listener is now always open (there is no transport-level dark/open gate to
> troubleshoot at all — "Dashboard refuses connections" below has a different root
> cause now, most likely a genuinely dead process or network issue, not an expired
> admin-open window), and the admin credential is a username + password with a
> shipped default (`admin`/`admin`) rather than a bare PIN — see `docs/API.md` §0 and
> `docs/SETUP_GUIDE.md` §3 for the current model. This playbook has not yet had the
> full revision pass to match; treat any procedure below that mentions `*4887`,
> "dark by default," or `/api/admin/set-pin` as describing removed behavior.

> [!IMPORTANT]
> **Establish which posture the device is in before you triage.** v1.3.0 and newer add three
> opt-in controls that change how the device answers you, and **all three default to off**.
> One `curl` tells you where you stand:
> ```bash
> curl -s http://192.168.4.1/api/admin/status   # {"provisioned":true|false,"authenticated":…}
> ```
> * `provisioned:true` → mutating calls need a session **and** an `X-CSRF` header (§4.6),
>   and the HTTP listener is **dark except inside an open window** (§6).
> * SoftAP may be **WPA2** (`GET /api/ap-security`, once logged in) — you may not be able
>   to join at all.
> * The SIP registrar may be **`learn`/`secure`** (`GET /api/registrar`, once logged in) —
>   phones may be refused by design (§4.3).
>
> Both of those `GET`s are session-gated on a provisioned device (no `X-CSRF` needed);
> `/api/admin/status` and `/api/status` are not.
>
> A device flashed from `v1.3.0-pre-alpha`, or one on `main` that nobody configured, has
> none of this: open AP, `open` registrar, plain HTTP, unsigned OTA.

---

## 🛠 Quick Reference Matrix

Use this matrix for rapid triage based on visible device indicators and active diagnostic symptoms:

| Scenario / Symptom | Primary Indicators | Probable Root Cause | Instant Recovery Action |
| :--- | :--- | :--- | :--- |
| **API call rejected `403`** | • `{"error":"missing or invalid CSRF token"}`<br>• Script/`curl` that worked before | • Provisioned device now requires the per-session `X-CSRF` header | • Capture `"csrf"` from the login response, resend with `-H "X-CSRF: …"` (§4.6) |
| **Dashboard refuses connections** | • *Connection refused*, not `401`/timeout<br>• Started minutes after a PIN was set<br>• SIP + calls unaffected | • Dark-by-default admin transport; open window expired | • Dial `*4887` from the **registered** admin extension; then *Keep open* (§6) |
| **Login returns `429`** | • `{"error":"too many failed attempts…"}`<br>• Correct PIN also refused | • Per-client lockout (5 fails) or aggregate backstop (20 fails), **escalating** | • Wait it out — cooldown doubles per trip, caps ~16 min; only a correct PIN clears it (§4.7) |
| **Whole fleet de-registers at once** | • Every handset "not registered"<br>• `GET /api/registrar` → `"mode":"secure"`, empty roster | • Registrar switched to `secure` before any extension was adopted/secured | • `POST /api/registrar mode=learn` **while HTTP is still open**; re-adopt, secure, then re-switch (§4.3) |
| **Cannot join the SoftAP** | • Client prompts for a password<br>• Boot log `auth:WPA2-PSK` | • AP security enabled (dashboard or flash-time seed) | • Read the per-device passphrase from serial / LVGL / `GET /api/ap-security` (§7) |
| **Watchdog Reset** | • Boot loops with `TG0WDT_SYS_RST`<br>• Logs showing `Task watchdog got triggered` | • Thread starvation on Core 1<br>• Infinite loop in SIP message parser | • Increase TWDT timeout in sdkconfig<br>• Add `vTaskDelay` yields in parsing loops |
| **NVS / Credential Corruption** | • Core boot loops on `nvs_flash_init()` failure<br>• Constant boot loop back to factory SoftAP | • Flash sector wear-out<br>• Brownout mid-write (incomplete `nvs_commit`) | • Programmatic partition format on error<br>• Force sector erase with `esptool.py` |
| **SIP Engine Deadlock** | • SIP endpoints unregisterable (5060 dead)<br>• HTTP Dashboard running on Core 0 (80/8080 active) | • Recursive locking of `RequestsHandler::_mutex`<br>• Lock-order inversion in paging | • Trigger CPU crash dump / JTAG stack trace<br>• Hard power cycle or remote API restart |
| **Session Pool Exhaustion** | • Device returns `503 Service Unavailable`<br>• Dashboard shows active sessions stuck at limit | • Unreleased sessions from ended calls<br>• Memory leak or failed cleanup after bye/cancel | • Trigger remote reboot via HTTP API<br>• Confirm the slot-recycling `Session::release()` path is present (§4.1) |
| **AOR Injection Attempts** | • Console logs show `Invalid character in Address of Record`<br>• SIP client receives `400 Bad Request` | • Exploit attempt injecting bad chars into From/To AOR<br>• Malformed third-party network scans | • Input sanitized automatically. Monitor logs<br>• Restrict network CIDR range |
| **Scanner Bucket DoS** | • Device logs drop packets from scanning IPs<br>• Metrics display high `packetsDropped` value | • Distributed botnets scanning port 5060<br>• Overflow of rate bucket lookup table | • Rate-limiter caps tables automatically at 256<br>• Standard auto-cleanup sweeps old IPs |
| **OTA Failure / Rollback** | • Device boots old firmware after OTA update<br>• Bootloader prints `Rollback triggered...` | • Missing `esp_ota_mark_app_valid_cancel_rollback`<br>• Network dropout mid-stream | • Verify OTA validation timing<br>• Flash known working binary to active slot |

---

## 1. Watchdog Resets (Task & Hardware WDT)

ESP32 chips feature both a **Hardware Watchdog Timer (WDT)** in the Timer Group and a **Task Watchdog Timer (TWDT)** managed by FreeRTOS. A watchdog reset indicates that the CPU has been occupied continuously by a high-priority task without yielding control to the system idle tasks or lower-priority routines.

```
       ┌─────────────────────────────────────────────────────────┐
       │     SipServer Loop / UDP Receive Task (Priority 5)      │
       └────────────────────────────┬────────────────────────────┘
                                    │  Parses incoming SIP packet
                                    ▼
       ┌─────────────────────────────────────────────────────────┐
       │     Infinite Parsing / Processing Loop (No yields)      │
       └────────────────────────────┬────────────────────────────┘
                                    │  Fails to call vTaskDelay()
                                    ▼
       ┌─────────────────────────────────────────────────────────┐
       │      Idle Task Starved (CPU Core 0/1 pinned @ 100%)     │
       └────────────────────────────┬────────────────────────────┘
                                    │  WDT counter expires
                                    ▼
       ┌─────────────────────────────────────────────────────────┐
       │        Task Watchdog Triggered (Panic / Reboot)        │
       └─────────────────────────────────────────────────────────┘
```

### 🔍 Detection & Symptoms
1. **Serial Console Logs:** Look for the signature panic message:
   ```text
   E (12345) task_wdt: Task watchdog got triggered. The following tasks did not reset the watchdog in time:
   E (12345) task_wdt:  - IDLE1 (CPU 1)
   E (12345) task_wdt: Tasks currently running:
   E (12345) task_wdt: CPU 0: http_server_task
   E (12345) task_wdt: CPU 1: sip_server_task
   ```
2. **Reset Reason Check:** Upon reboot, the bootloader logs the reset reason. If `esp_reset_reason_t` is called, it returns `ESP_RST_WDT`.
3. **Register Stack Dumps:**
   ```text
   Guru Meditation Error: Core  1 panic'ed (Interrupt wdt timeout on CPU1).
   Core  1 register dump:
   PC      : 0x400d54c8  PS      : 0x00060034  A0      : 0x400d5a1c  A1      : 0x3ffd5480
   ```

### 🔬 Diagnosis Procedure
To map raw hex addresses (like `PC : 0x400d54c8`) back to the specific line of C++ code causing the deadlock or lockup, use the ESP-IDF toolchain's backtrace decoder:

```bash
# For Standard ESP32 (Xtensa)
xtensa-esp32-elf-addr2line -pfia -e build/SipServer.elf 0x400d54c8 0x400d5a1c

# For ESP32-S3 (Xtensa-S3)
xtensa-esp32s3-elf-addr2line -pfia -e build/SipServer.elf 0x400d54c8 0x400d5a1c
```

> [!NOTE]
> Ensure that the `.elf` binary used for decoding matches the exact compiler build running on the target device; otherwise, line offsets will be misaligned.

### 🛡️ Recovery & Prevention
* **Insert Cooperative Yields:** Ensure that every high-priority loop, especially inside `UdpServer::receiveLoop` or the SIP engine's `RequestsHandler::tick()`, yields control.
  ```cpp
  // Force a task block to allow IDLE task execution and watchdog feeding
  vTaskDelay(pdMS_TO_TICKS(1)); 
  ```
* **Adjust WDT Parameters:** If complex multi-party paging or intense network scanning requires more overhead, increase the task watchdog timer duration inside `sdkconfig` via:
  ```text
  CONFIG_ESP_TASK_WDT_TIMEOUT_S=15
  ```

---

## 2. NVS & Credential Corruption

The device uses Non-Volatile Storage (NVS) inside the `"storage"` namespace to save Wi-Fi SSID, passphrases, and modes. Incomplete flash operations during sudden power interruptions (brownouts) or flashing sector wear-out can lead to a corrupted partition.

> [!IMPORTANT]
> **NVS now holds the security posture too, so erasing it is a policy change, not just a
> network reset.** Beyond `wifi_mode` / `wifi_ssid` / `wifi_pass` / `decayed`, the same
> namespace carries `admin_salt` + `admin_hash` (the admin PIN), `ap_secure` + `ap_psk`
> (SoftAP WPA2), `reg_mode` (registrar admission mode) and `cfgseed_gen`; the admin
> extension lives in namespace `pbxcfg`, key `admin_ext`. An NVS erase therefore
> **re-opens the access point, clears the PIN and returns the HTTP plane to
> always-listening** — which is what makes it a recovery tool, and also what makes it a
> deliberate act.

```
                    ┌────────────────────────────┐
                    │      Device Power-On       │
                    └─────────────┬──────────────┘
                                  │
                                  ▼
                    ┌────────────────────────────┐
                    │     nvs_flash_init()       │
                    └─────────────┬──────────────┘
                                  │
               ┌──────────────────┴──────────────────┐
        Success│                                     │Error (Pages Corrupted)
               ▼                                     ▼
┌────────────────────────────┐         ┌────────────────────────────┐
│   Load saved Wi-Fi Mode    │         │     nvs_flash_erase()      │
│   and register SIP client  │         └─────────────┬──────────────┘
└────────────────────────────┘                       │ Re-init
                                                     ▼
                                       ┌────────────────────────────┐
                                       │     nvs_flash_init()       │
                                       └─────────────┬──────────────┘
                                                     │
                                                     ▼
                                       ┌────────────────────────────┐
                                       │    Load Default Standalone │
                                       │    SoftAP Mode Configuration│
                                       └────────────────────────────┘
```

### 🔍 Detection & Symptoms
1. **Crash Loops:** The firmware crashes and restarts indefinitely at boot-time with error logs from `app_main`:
   ```text
   E (450) app_main: NVS Initialization Failed: ESP_ERR_NVS_NO_FREE_PAGES (0x110d)
   ```
2. **Loss of Connection Parameters:** The device boots into the default Standalone AP (`esp32-sipserver`), failing to connect to the previously configured local Station Wi-Fi network, despite no user configuration changes.

### 🔬 Diagnosis Procedure
* Monitor serial output during device initialization.
* Look for errors associated with NVS key retrieval, specifically `nvs_open` or `nvs_get_str` returning `ESP_ERR_NVS_NOT_FOUND` (0x1102).

### 🛡️ Recovery & Prevention
To resolve a hard NVS corruption or partition block lockup, execute an explicit NVS partition erase using `esptool.py`.

#### Step 1: Locate the NVS Partition Address
Check your partition table (usually at `0x8000`). The NVS partition is at offset `0x9000`,
size `0x6000` (24 KB), and is **byte-identical across every layout in this repo**
(`partitions.csv` 16 MB, `partitions_4mb.csv`) — it is deliberately never moved or resized.

#### Step 2: Manually Erase the NVS Sector
```bash
# Clean NVS sector ONLY (retains core application and partition table)
esptool.py -p COM3 -b 460800 erase_region 0x9000 0x6000
```

> [!IMPORTANT]
> **An NVS erase does not always clear the security posture — the `cfgseed` partition can
> put it straight back.** On the 16 MB layout, one 4 KB sector at `0xFFF000` (`cfgseed`,
> subtype `0x41`) holds a 256-byte record written by the browser flasher at install time,
> carrying the SoftAP WPA2 passphrase, `wifi_mode`, the registrar `regMode`, and upstream
> STA credentials. `DeviceConfig::applyFlashSeed()` reads it once at boot and applies it
> **whenever the stored `cfgseed_gen` is missing or differs** — so a freshly-erased NVS
> re-applies the seed by design. If you erase NVS to recover from a locked-down posture and
> the board comes back locked down, erase the seed too:
> ```bash
> esptool.py -p COM3 -b 460800 erase_region 0xFFF000 0x1000
> ```
> The firmware **only ever reads** this partition; the flasher is the sole writer. Boards
> flashed before `cfgseed` existed, and the 4 MB constrained layout, simply have no such
> partition — `applyFlashSeed()` returns `false` silently. That is the normal case, not an
> error.

> [!WARNING]
> If `erase_region` does not resolve the loop, the entire flash chip must be cleared to eliminate persistent bad partition tables. Use the following command with caution, as it will wipe all active firmware partitions:
> ```bash
> esptool.py -p COM3 erase_flash
> ```

#### Programmatic Fallback (C++ Safeguard)
Verify that `app_main` implements the standard Espressif auto-erase safeguard (present in `esp_main.cpp`):
```cpp
esp_err_t ret = nvs_flash_init();
if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_ERROR_CHECK(nvs_flash_erase());
    ret = nvs_flash_init();
}
ESP_ERROR_CHECK(ret);
```

---

## 3. SIP Engine Deadlocks & Thread-Safe Logging

The post-refactor `RequestsHandler` manages a concurrent snapshot-based dashboard structure. An architectural deadlock occurs if recursive operations or lock-order inversion locks `RequestsHandler::_mutex` permanently, starving SIP execution.

### 🔍 Detection & Symptoms
1. **Partial Responsiveness:** The HTTP dashboard is fully active on Core 0 (`http://192.168.4.1:80` returns the CGA CRT interface instantly), but the metrics showing active sessions, registered extensions, and processed packet counts remain frozen.
2. **SIP Protocol Silent Drop:** Active SIP phone endpoints show `No Registration` or timeout with status `408 Request Timeout` on port `5060` (UDP).
3. **Task Monitor Frozen:** Serial console logs do not show `UdpServer` or `RequestsHandler::tick` processing notices.

### 🔬 Diagnosis Procedure
If JTAG or an GDB debugger is connected, attach to the target chip to view running backtraces:

```text
(gdb) thread apply all bt
...
Thread 2 (sip_server_task):
#0  vPortPlaceOnEventList (pxEventList=0x3ffd5a20, xTicksToWait=4294967295) at tasks.c:3120
#1  xQueueSemaphoreTake (xQueue=0x3ffd5a10, xTicksToWait=4294967295) at queue.c:1530
#2  std::mutex::lock (this=0x3ffd31b4) at mutex.cpp:45
#3  RequestsHandler::handle (this=0x3ffd3110, request=...) at RequestsHandler.cpp:115
```

> [!IMPORTANT]
> The `std::mutex` provided by the ESP-IDF toolchain is a **non-recursive** mutex (wraps a standard FreeRTOS binary semaphore). If a function holding the lock attempts to call another member function that also requests the lock (e.g., calling `sweepExpired()` within another locked method without passing lock ownership), the task will immediately **self-deadlock**.

### 🔒 Core Thread-Safe Buffered Logging (Issue #57B)
To avoid deadlocks arising from raw, synchronous console output operations (`std::cout`/`std::cerr`) stalling inside locked sections under intense concurrency:
* **The Safeguard:** The engine utilizes a thread-safe, private queue `_logQueue` and helper `queueLog()` to store logging strings while inside locked sections.
* **The Resolution:** All log statements inside `handle()`, `tick()`, and `forceDisconnect()` are queued under lock, and only output to the standard serial console *after* releasing `_mutex` completely, freeing up other threads immediately.

### 🛡️ Recovery & Prevention
1. **Emergency Remote Restart:** Since the HTTP task on Core 0 is unaffected, use the fallback-mode API to trigger a remote software restart. On a **provisioned** device this needs a session cookie **and** the session's CSRF token (§4.6) — the bare `curl` that used to appear here now returns `401`, then `403`:
   ```bash
   DEVICE=http://192.168.4.1
   JAR=cookies.txt

   LOGIN=$(curl -s -c "$JAR" -H "Origin: $DEVICE" \
        -X POST --data "pin=YOUR_PIN" "$DEVICE/api/admin/login")
   CSRF=$(printf '%s' "$LOGIN" | sed -n 's/.*"csrf":"\([0-9a-f]*\)".*/\1/p')
   [ -n "$CSRF" ] || { echo "login failed: $LOGIN" >&2; exit 1; }

   curl -s -b "$JAR" -H "Origin: $DEVICE" -H "X-CSRF: $CSRF" \
        -X POST "$DEVICE/api/wifi/mode_ap"
   # -> {"status":"ok","message":"Operational mode set to Standalone AP. Rebooting..."}
   ```
   On an **unprovisioned** device the original one-liner still works — there is no session to present.

   > If the connection is *refused* rather than answered, the HTTP plane is dark, not dead. See §6.
2. **Locking Safeguard Best Practices:**
   * Never invoke external/callback functions while holding `_mutex`!
   * Copy necessary registrar state into local stack frames using `RegistrarSnapshot` copy structures before running extensive parsing or dispatch operations.
   * If a method needs to be called both internally (with lock held) and externally, split it into a public locked wrapper and a private unlocked implementation (typically suffixed with `_Unformatted` or `_NoLock`).

---

## 4. Resource Allocation & Security Safeguards (Issues #54-#59)

The firmware is reinforced against remote attacks, memory leaks, and exhaustion exploits via specific C++ logic guards implemented in Issues #54 through #59.

### 4.1 💾 Session Pool Exhaustion (Issue #54)
* **Symptom:** Endpoints cannot establish new calls and receive `503 Service Unavailable`, but the dashboard shows 0 active calls.
* **Root Cause:** Saturated static memory pool allocation. The SIP engine pre-allocates up to 32 `SipClient` slots and 8 `Session` slots. If a session is closed but not properly dereferenced/released, the slot is leaked.
* **C++ Safety Guard:** The system implements a robust slot-recycling `.release()` method on the `Session` class, clearing core pointers (`_src`, `_dest`, `_inviteMessage`, `_pendingTargets`, and `_callID`). 
* **Automatic Reclamation:** On call termination (`endCall()`, `sweepExpired()`, or `forceDisconnect()`), `.release()` is explicitly triggered on active session objects. The allocation method (`allocateSession()`) automatically sweeps the pre-allocated `_sessionPool` to reclaim slot keys that are no longer actively mapped in `_sessions`.

### 4.2 🛡️ Address of Record (AOR) Input Injection (Issue #55)
* **Symptom:** Remote endpoints send malicious headers containing non-alphanumeric or command symbols, trying to hijack parsing or configuration logic.
* **Root Cause:** Missing input bounds checks.
* **C++ Safety Guard:** The function `RequestsHandler::isValidAor()` strictly checks Address of Record strings in incoming `REGISTER` and `INVITE` requests. It enforces a strict whitelist containing only alphanumeric characters and standard delimiters: `.`, `-`, `_`, `+`. Malformed inputs are rejected immediately with a `400 Bad Request` packet, preventing any buffer or parsing anomalies.

### 4.3 ⚙️ Registrar Admission Mode — mass de-registration

* **Symptom:** Every handset drops to "not registered" at the same moment. No power, cabling or Wi-Fi change. New registrations are refused; calls in progress are not torn down.
* **Root Cause:** The registrar was switched to **`secure`** before any extension had been adopted and secured. In `secure` mode every `REGISTER` is digest-challenged (RFC 2617, MD5) and a fleet that never went through `learn` has no secret to answer with — so all of them fail at once.

> [!NOTE]
> **This is no longer a compile-time flag.** Earlier revisions of this playbook described a
> `#define POCKETDIAL_OPEN_REGISTRAR` build guard. That define was unconditional and nothing
> outside the unit tests ever wrote the persisted `reg_mode`, so every device came up `open`
> and stayed there ([THREAT_MODEL.md §9](THREAT_MODEL.md)). The mode is now an NVS-backed
> **runtime** setting with three values and three operator paths.

| Mode | Admission | Where it comes from |
| :--- | :--- | :--- |
| `open` | No SIP authentication. **The shipped default.** | Compiled-in default; `POST /api/registrar mode=open` |
| `learn` | Trust-on-first-use: an unknown MAC claiming an unclaimed extension is adopted and locked to it; already-secured devices stay digest-enforced. **Temporary, by design.** | Dashboard *Extension Registration & Onboarding* panel; `POST /api/registrar` |
| `secure` | Every `REGISTER` digest-challenged; extension ↔ MAC locked. | As above, or the flash-time `cfgseed` record (`regMode`, byte 13) — the only way to set it on a headless board before first boot. **Requires v1.4.1+**: on v1.3.0/v1.4.0 that field wrote to the wrong NVS namespace and did nothing ([#151](https://github.com/GlomarGadaffi/pocket-dial/issues/151)) |

**Triage:**
```bash
# GET → no X-CSRF needed, but it IS session-gated on a provisioned device: log in
# first (§4.6) and reuse the jar. Without a cookie you get 401, not the mode.
curl -s -b "$JAR" http://192.168.4.1/api/registrar
# -> {"attached":true,"mode":"secure","devices":[]}
```
An empty (or all-`learned`) roster with `"mode":"secure"` confirms it. `"attached":false`
with `"mode":"unknown"` is a normal transient — the SIP engine is not bound yet.

**Recovery, in strict order — the options expire:**

1. **While HTTP is still reachable, revert immediately.** Every minute spent diagnosing may cost you the window (§6).
   ```bash
   curl -s -b "$JAR" -H "Origin: $DEVICE" -H "X-CSRF: $CSRF" \
        -X POST --data "mode=learn" "$DEVICE/api/registrar"
   ```
   Then let the phones re-adopt, verify the roster, promote each device
   (`POST /api/registrar/device` with `action=secure`), and only then return to `secure`.
2. **If HTTP is dark**, the `*4887` DTMF trigger needs the admin extension to be
   **registered** — which in `secure` mode it is not. This path is normally already gone.
3. **Otherwise recover over USB**: erase NVS (`erase_region 0x9000 0x6000`), and the
   `cfgseed` sector too if the board was seeded (§2).

> [!IMPORTANT]
> **`POST /api/factory-reset` does not clear `reg_mode`** (`HttpServer::sendApiFactoryReset`
> erases the admin credential, the Wi-Fi keys and `ap_secure`/`ap_psk`/`cfgseed_gen` — not
> the registrar mode), and it re-arms the flash-time seed. Do not reach for it expecting the
> registrar to reopen.

> [!TIP]
> **The `409` is a guard, not a fault.** `POST /api/registrar mode=secure` while no extension
> is yet `secured` is refused with
> `{"error":"no extensions are secured yet; switching to secure now would reject every phone…"}`.
> Overriding with `confirm=LOCKOUT` is how the incident above happens. Only use it when a
> secured handset demonstrably exists.

**Residual, stated plainly:** the extension↔MAC lock is learned from the ARP table and is
spoofable on a hostile L2 — it composes with digest auth as defence in depth, it is not a
cryptographic device identity ([THREAT_MODEL.md §9.2](THREAT_MODEL.md) E-3). Only `REGISTER`
is challenged; INVITE is not independently authenticated in M1.

### 4.4 🚫 Distributed Scanner Memory Exhaustion (Issue #58)
* **Symptom:** Memory exhaustion crashes under intense external scanner traffic (port sweeps).
* **Root Cause:** Unbounded allocation of rate-limiting buckets keyed by IP inside the `_rateBuckets` map.
* **C++ Safety Guard:** Two strict protections mitigate this:
  1. `RequestsHandler::tick()` sweeps old rate-limit entries (unused for >60 seconds) out of the map.
  2. `allowPacket()` enforces a hard ceiling of `MAX_BUCKETS = 256` concurrently monitored IPs. Once hit, scanning packets from any newly detected foreign IPs are dropped automatically to shield CPU and heap resources.

### 4.5 ✂️ Whole-Message Header Mutations (Issue #59)
* **Symptom:** Media stream (audio/video) metadata inside the SDP body is corrupted or stripped when the SIP engine rewrites message headers.
* **Root Cause:** Standard header replacement functions searching across the entire packet string rather than isolating the header block.
* **C++ Safety Guard:** Implemented `SipMessage::findHeader()` which parses the boundary boundary limit `\r\n\r\n` (or `\n\n`) and restricts substring searches strictly within the `[0, headerLimit)` range. This isolates header modifications from SDP body segments, ensuring reliable codecs and payload bindings.

### 4.6 🎫 Per-session CSRF token — `403` on a call that used to work

* **Symptom:** `403 Forbidden` with body `{"error":"missing or invalid CSRF token"}` on a **provisioned** device. The session cookie is valid; the request is missing the second half of the gate.
* **Root Cause:** Every **mutating** request must now echo a per-session 128-bit CSRF token in an **`X-CSRF`** header, checked centrally in `HttpServer::requireAdmin()` so no route can skip it. The `Origin` check deliberately still admits requests with no `Origin` header at all — which is what keeps `curl` and the CI smoke suite working — so the token, not the Origin, is the load-bearing control ([API.md §2.1](API.md), [THREAT_MODEL.md](THREAT_MODEL.md) T-2).
* **Instant Recovery:** capture `"csrf"` from the login response body and resend.

```bash
DEVICE=http://192.168.4.1
JAR=cookies.txt

LOGIN=$(curl -s -c "$JAR" -H "Origin: $DEVICE" \
     -X POST --data "pin=YOUR_PIN" "$DEVICE/api/admin/login")
# -> {"status":"ok","authenticated":true,"csrf":"3f2a...e91c"}

CSRF=$(printf '%s' "$LOGIN" | sed -n 's/.*"csrf":"\([0-9a-f]*\)".*/\1/p')
[ -n "$CSRF" ] || { echo "login failed: $LOGIN" >&2; exit 1; }

# Reuse "$JAR" + "$CSRF" on every mutating call for the life of the session.
curl -s -b "$JAR" -H "Origin: $DEVICE" -H "X-CSRF: $CSRF" \
     -X POST --data "extension=1001" "$DEVICE/api/kill"
```

**Distinguish the three rejections before you change anything** — they are different problems:

| Status + body | Meaning | Action |
| :--- | :--- | :--- |
| `401 {"error":"authentication required"}` | No / expired `pd_session` | Log in |
| `403 {"error":"cross-origin request rejected"}` | `Origin` host ≠ `Host` | Send a matching `Origin`, or omit it |
| `403 {"error":"missing or invalid CSRF token"}` | Session valid, token absent/wrong | Add `X-CSRF` |

**Exempt** (no token needed): `POST /api/admin/login`, `POST /api/admin/logout`, every `GET`,
and **every request on an unprovisioned device** — a factory-fresh box has no session, so
demanding a token would make it unclaimable.

Sessions carry a **30-minute sliding** expiry; each successful validation pushes the deadline
out, so a working operator is not logged out mid-incident. A re-login mints a **new** token —
re-capture it, do not reuse the old one.

### 4.7 ⏱ Login lockout (`429`) — now escalating

* **Symptom:** `POST /api/admin/login` → `429 {"error":"too many failed attempts; try again later"}`, sometimes with the **correct** PIN, sometimes for an operator who never typed a wrong one.
* **Root Cause:** two independent counters (`AdminAuth.hpp`, [THREAT_MODEL.md §5.2](THREAT_MODEL.md)):

| Counter | Trips at | Cooldown |
| :--- | :--- | :--- |
| **Per-client** — keyed on the HTTP peer address, 8 LRU buckets | 5 consecutive failures | 60 s, **doubling per successive trip**, capped ~16 min |
| **Aggregate backstop** — across all clients | 20 consecutive failures | Same doubling ladder, also up to ~16 min; locks out **everyone** |

* **What changed:** the trip count **survives the cooldown**. It used to reset, handing an attacker a fresh budget of 5 every minute. Now the second lockout is 2 min, the third 4 min, and only a **correct PIN** clears either counter.
* **Instant Recovery:** wait — it always auto-clears and never permanently locks the device. Pre-existing sessions stay valid throughout; only `login` is throttled, so a browser still logged in elsewhere is your fastest route back in. Hitting the aggregate counter without guessing means something on the link is hammering `/api/admin/login` — treat that as an incident in its own right.
* **Note:** the per-client key is for *fairness, not trust* — a source address is trivially spoofable on a shared link. That is precisely why the aggregate backstop exists.

---

## 5. Over-The-Air (OTA) Failures & Rollbacks

OTA updates use dual application partitions (`ota_0` and `ota_1`) along with a dedicated `otadata` control partition. This configuration ensures that if a newly flashed firmware fails, the system automatically rolls back to the previous stable partition.

```
       ┌─────────────────────────────────────────────────────────┐
       │             Initialize OTA Update Sequence              │
       └────────────────────────────┬────────────────────────────┘
                                    │  Stream binary via Wi-Fi/ETH
                                    ▼
       ┌─────────────────────────────────────────────────────────┐
       │        Write Binary to Secondary Partition (ota_1)       │
       └────────────────────────────┬────────────────────────────┘
                                    │  Finish stream and verify hash
                                    ▼
       ┌─────────────────────────────────────────────────────────┐
       │     Set Boot Partition to ota_1 & Trigger reboot        │
       └────────────────────────────┬────────────────────────────┘
                                    │  esp_restart()
                                    ▼
       ┌─────────────────────────────────────────────────────────┐
       │              Bootloader Starts ota_1 app                │
       └────────────────────────────┬────────────────────────────┘
                                    │
                  ┌─────────────────┴─────────────────┐
        Success within 30s?                 Failure / Watchdog Crash?
                  ▼                                   ▼
┌───────────────────────────────────┐       ┌───────────────────────────────────┐
│  Call ota_mark_app_valid()        │       │ Bootloader detects crash / panic   │
│  State: ESP_OTA_IMG_VALID         │       │ State: ESP_OTA_IMG_INVALID        │
│  Firmware update committed!       │       │ Rollback boot partition to ota_0  │
└───────────────────────────────────┘       └───────────────────────────────────┘
```

### 🔍 Detection & Symptoms
1. **Automatic Rollovers:** After performing an OTA firmware update, the device boots but continues to display the old version string on the CGA HTTP dashboard.
2. **Boot Logs Rollback Signature:** The serial console displays the following bootloader notifications:
   ```text
   I (520) esp_image: Verifying image signature...
   I (545) esp_ota_ops: Partition ota_1 has pending rollback state.
   W (550) esp_ota_ops: Diagnostics failed or app crashed before validating. Rolling back...
   I (562) esp_ota_ops: Setting active partition to ota_0. Rebooting...
   ```

### 🔬 Diagnosis Procedure
* Connect to the serial port during boot.
* Run `esp_ota_get_state_partition()` to check the active state.
  * `ESP_OTA_IMG_NEW` (Flashed, unverified)
  * `ESP_OTA_IMG_PENDING_VERIFY` (Booted, awaiting validation)
  * `ESP_OTA_IMG_VALID` (Committed stable)
  * `ESP_OTA_IMG_INVALID` (Rollback candidate)

### 🛡️ Recovery & Prevention
To bypass rollback logic and manually recover a device stuck in a corrupted OTA state, use direct flash operations via `esptool.py` to restore partition state:

```bash
# Step 1: Clear the OTA selection table (forces the bootloader back to the first app slot)
esptool.py -p COM3 -b 460800 erase_region 0xf000 0x2000

# Step 2: Manually flash a verified stable SipServer binary directly to partition ota_0
esptool.py -p COM3 -b 460800 write_flash 0x20000 build/SipServer.bin
```

> [!IMPORTANT]
> **Verify these offsets against the partition table you actually flashed** before running
> either command — writing an app image to the wrong offset lands it on `phy_init` or NVS.
> Both layouts in this repo agree on the addresses above:
>
> | Partition | Offset | Size (16 MB `partitions.csv`) | Size (4 MB `partitions_4mb.csv`) |
> | :--- | :--- | :--- | :--- |
> | `nvs` | `0x9000` | `0x6000` | `0x6000` (byte-identical, never moved) |
> | `otadata` | `0xf000` | `0x2000` | `0x2000` |
> | `phy_init` | `0x11000` | `0x1000` | `0x1000` |
> | `ota_0` | `0x20000` | `0x600000` | `0x1E0000` |
> | `ota_1` | `0x620000` / `0x200000` | `0x600000` | `0x1E0000` |
> | `prompts` | `0xC20000` | `0x3DF000` | — |
> | `cfgseed` | `0xFFF000` | `0x1000` | — |
>
> Earlier revisions of this playbook printed `0xd000` for `otadata` and `0x10000` for
> `ota_0`; neither has ever matched this project's tables. Adding `cfgseed` shrank
> `prompts` from `0x3E0000` to `0x3DF000` and changed nothing below it, so app/nvs/otadata
> offsets are stable in both directions and an OTA never rewrites the partition table at
> all.

#### Verification API Call
Ensure your firmware contains the following safety pattern immediately after ensuring successful Wi-Fi connection and SIP initialization:
```cpp
#include "esp_ota_ops.h"

void verify_firmware_on_boot() {
    const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t ota_state;
    
    if (esp_ota_get_state_partition(running, &ota_state) == ESP_OK) {
        if (ota_state == ESP_OTA_IMG_PENDING_VERIFY) {
            // Check essential service states (SIP ports bound, Wi-Fi OK)
            if (g_sipServer != nullptr) {
                ESP_LOGI("OTA", "Self-diagnostics passed. Marking app as valid!");
                esp_ota_mark_app_valid_cancel_rollback();
            } else {
                ESP_LOGE("OTA", "Diagnostics failed. System will roll back on reboot.");
                esp_ota_mark_app_invalid_rollback_and_reboot();
            }
        }
    }
}
```

> [!NOTE]
> Pushing an image over the network (`POST /api/ota/upload`, `POST /api/ota/reboot`) goes
> through the same gate as every other mutating endpoint: same-origin, session, **and
> `X-CSRF`** (§4.6). A pre-existing OTA script gets `403 {"error":"missing or invalid CSRF
> token"}`. The full worked recipe is in [OTA.md §3.2](OTA.md). OTA images remain
> **unsigned** — the upload is gated by the admin PIN and the transport window, nothing
> more ([THREAT_MODEL.md](THREAT_MODEL.md) T-5).

---

## 6. Locked Out of the Management Plane

The HTTP admin plane is **dark by default on a provisioned device**: the TCP listener itself
is closed, so an operator sees *connection refused* rather than `401`. SIP, RTP and live
calls are untouched — only management is unreachable ([API.md §0](API.md),
[THREAT_MODEL.md §5.5](THREAT_MODEL.md)).

### 🔍 Detection & Symptoms
1. `curl` returns `Connection refused` / `Failed to connect`, **not** an HTTP status.
2. It began minutes after an admin PIN was set or changed.
3. The device otherwise answers: SIP registrations hold, `777` echo works, ICMP replies.
4. An **unprovisioned** device never does this — it listens unconditionally so it can be claimed at all.

### 🔬 Diagnosis Procedure
* Confirm the device is alive on another plane first — `python .smoke/sip_probe.py <IP> 5060`, or simply place a call. A dark HTTP plane plus a live SIP plane is the signature.
* If you can reach HTTP at all, `GET /api/admin/status` → `{"provisioned":true,…}` confirms the gate is armed.

### 🛡️ Recovery — the three ways the window opens

| Trigger | Procedure | Window |
| :--- | :--- | :--- |
| **DTMF star-code** | From the **admin extension** (default `1001`; NVS namespace `pbxcfg`, key `admin_ext`), **while it is registered**, dial **`*4887`**. The SIP INFO's source IP must match that registration's bound IP. | default 600 s |
| **Provisioning grace** | A successful `POST /api/admin/set-pin` opens the same window — which is why onboarding is not self-defeating. | default 600 s |
| **Keep-alive** | While authenticated, the dashboard's *Keep open* control (`POST /api/admin/keepalive`, session-gated) extends it. | +3600 s |

**Field procedure:** dial `*4887` from the admin handset → load the dashboard → log in →
click *Keep open* **before** starting any long work. The accept loop polls at 250 ms, so the
transition is not instantaneous; wait a beat before declaring it failed.

> [!WARNING]
> **Opening the transport does not bypass the PIN.** Once a connection is accepted, the
> session and CSRF gates apply unchanged.

> [!IMPORTANT]
> **The escalation trap.** `*4887` requires the admin extension to be **registered**. If
> registration itself is broken — most commonly a registrar switched to `secure` with
> nothing adopted (§4.3) — there is no network path back at all, and recovery is USB: erase
> NVS (`erase_region 0x9000 0x6000`) and, on a seeded board, the `cfgseed` sector too (§2).
> Also note that a PIN beginning `4887` is shadowed by this star-code; new PINs with that
> prefix are rejected, but a device provisioned before that guard shipped may still carry
> one — rotate it via `POST /api/admin/set-pin`.

> [!NOTE]
> The SSH sysop terminal (`SshServer`/`Tui`, wolfSSH, port 22) was **deleted**, not
> hardened. If a runbook or a colleague tells you to "just SSH in", that surface no longer
> exists on any build.

---

## 7. Access-Point Security (WPA2) — cannot associate

The SoftAP can come up `WIFI_AUTH_WPA2_PSK` instead of open. It is **off by default** and a
firmware update never turns it on — enabling it forces every associated phone to be
re-paired, so it is always a deliberate operator action, from the dashboard or the flash-time
seed ([THREAT_MODEL.md §6](THREAT_MODEL.md), `DeviceConfig.hpp`).

### 🔍 Detection & Symptoms
1. The SSID is visible but the client prompts for a password, or rejects the one on file.
2. Boot log: `INFRA: SoftAP SSID:esp32-sipserver channel:1 auth:WPA2-PSK  DHCP server active`.
3. On the display build, the `My-Ap` **onboarding** AP is WPA2 **unconditionally** — it no longer uses the old hardcoded `12345678` — while the standalone AP follows the `ap_secure` flag like every other build. Both use the same per-device passphrase (`main/esp_main_display.cpp`).

### 🛡️ Recovery — read the passphrase
There is **no factory default and nothing baked into the image**: each unit generates its
own 20-character passphrase from the hardware CSPRNG, over an alphabet with no ambiguous
glyphs (no `0`/`O`, `1`/`I`/`L`, `U`) so it survives being read off an LCD and retyped.

| Build | Where it appears |
| :--- | :--- |
| `display` | On the LVGL onboarding screen, beside the SSID |
| `wifi` (headless) | Serial boot log: `INFRA: SoftAP passphrase (WPA2): …` — deliberate; a serial cable is already inside the physical trust boundary |
| Any | `GET /api/ap-security` → `{"secure":true,"psk":"…"}`, or the dashboard's *Wi-Fi Access Point Security* panel, once logged in |
| Any | The browser flasher, if it was written at flash time |

Change it with `POST /api/ap-security` (`secure`, `psk`, `regenerate`; needs `X-CSRF`). **The
radio is not restarted** — doing so would drop the client that just made the request, losing
the response and the passphrase it still has to display, and would tear down live calls. The
change lands at the next AP bringup. Write a rotated passphrase down **before** restarting.

The `eth` build has no SoftAP; none of this applies to it.

> [!WARNING]
> On a headless board with AP security on, no remembered PIN, and nobody associated, the
> only routes in are a **serial console** (the passphrase is logged every boot) or a
> **re-flash**. Capture the passphrase before you need it.
