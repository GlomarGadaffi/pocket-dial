# Pocket-Dial Firmware Onboarding Guide
### Zero-to-Flashing in Under 30 Minutes

Welcome to the pocket-dial ESP32 firmware project! This guide will take you from a clean machine to a fully compiled and flashed firmware, with a functioning HTTP dashboard running on your target development board.

## Prerequisites & Tools

Before you begin, install the required toolchain and platform dependencies based on your operating system:

### 1. Hardware Drivers
Ensure you have installed the correct USB-to-UART bridge drivers for your target board:
* Silicon Labs CP210x: [Download CP210x VCP Drivers](https://www.silabs.com/developers/usb-to-uart-bridge-vcp-drivers) (Common on standard ESP32 DevKits)
* WCH CH340 / CH341: [Download CH340 Drivers](http://www.wch-ic.com/downloads/CH341SER_EXE.html) (Common on low-cost S3 boards, displays, and clone devkits)

### 2. ESP-IDF Toolchain (v6.0 or later; v5.x will not configure)
The firmware requires **ESP-IDF v6.0+**. This is a hard floor, not a recommendation:
`main/CMakeLists.txt:19-24` raises a CMake `FATAL_ERROR` on anything below v6.0, so a v5.x
toolchain fails at configure time before a single file is compiled. Both
`.github/workflows/ci.yml` and `release.yml` build on **v6.0.1**.
*(Earlier revisions of this page said v5.1.2 / v5.2.1 were "fully certified". They are not
usable at all. A v5.2.1 pin is what silently broke the v1.3.0-pre-alpha release run.)*
* Windows installation: Download and run the [ESP-IDF Offline Installer](https://dl.espressif.com/dl/esp-idf/) (select version `6.0.1`).
* Linux/macOS installation: Follow the [Espressif Standard Shell Setup Guide](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/get-started/linux-macos-setup.html).

## Step 1: Environment Activation

To load the correct compilers (`xtensa-esp32-elf-gcc`, `xtensa-esp32s3-elf-g++`), build utilities (`cmake`, `ninja`), and target tools (`esptool.py`, `idf.py`) into your current shell session:

### Windows (PowerShell)
```powershell
# Open PowerShell and run the export script generated during installer setup
. ~\esp\esp-idf\export.ps1
```

### Linux / macOS
```bash
# Source the export script in your active terminal
. $HOME/esp/esp-idf/export.sh
```

> [!TIP]
> If activation is successful, running `idf.py --version` should output `ESP-IDF v6.0.x`.
> Anything below v6.0 will stop with the `FATAL_ERROR` from `main/CMakeLists.txt`.

## Step 2: Clone & Configure

1. Clone the repository and submodules:
   ```bash
   git clone --recursive https://github.com/GlomarGadaffi/pocket-dial.git
   cd pocket-dial
   ```

2. Select your target chip architecture:
   The firmware supports multiple physical boards. Tell the build system which chip you are compiling for:
   ```bash
   # For classic ESP32 devboards (e.g. NodeMCU, LilyGO T-Internet-COM)
   # NOTE: the Waveshare ESP32-S3-ETH is an S3 board — use esp32s3 for it.
   idf.py set-target esp32

   # For ESP32-S3 boards (e.g. Guition AXS15231B Display, LilyGO T-ETH-Lite)
   idf.py set-target esp32s3
   ```

## Step 3: Select Your Hardware Transport Layer

The firmware is designed with a highly modular physical layer. Define your transport configuration at compile-time by passing the `-D SIP_TRANSPORT` parameter to `idf.py`:

```
                           ┌───────────────────────────┐
                           │      Build Entrypoint     │
                           └─────────────┬─────────────┘
                                         │
                 ┌───────────────────────┼───────────────────────┐
                 ▼                       ▼                       ▼
      -D SIP_TRANSPORT=wifi    -D SIP_TRANSPORT=eth    -D SIP_TRANSPORT=display
                 │                       │                       │
                 ▼                       ▼                       ▼
    ┌─────────────────────────┐  ┌─────────────────────────┐  ┌─────────────────────────┐
    │     Wi-Fi SoftAP Mode   │  │   W5500 PoE Ethernet    │  │   AXS15231B Touch screen │
    │     (esp_main.cpp)      │  │   (esp_main_eth.cpp)    │  │ (esp_main_display.cpp)  │
    └─────────────────────────┘  └─────────────────────────┘  └─────────────────────────┘
```

| Transport Parameter | Target Board Description | Primary Entrypoint File |
| :--- | :--- | :--- |
| `wifi` | Broad support. Starts a Standalone Access Point named `esp32-sipserver` | `main/esp_main.cpp` |
| `eth` *(Default)* | **W5500 only** (LilyGO T-ETH-Elite S3 default, or Waveshare ESP32-S3-ETH with `-D PD_ETH_BOARD=waveshare`; the two pin maps are entirely different and the wrong one reset-loops the board) | `main/esp_main_eth.cpp` |
| `lan8720` | **A separate transport, not part of `eth`.** Classic ESP32 + LAN8720 RMII PHY; hard-errors unless `IDF_TARGET == esp32` | `main/esp_main_eth_lan8720.cpp` |
| `display` | Guition AXS15231B **3.5" 320x480** LCD, pins graphics to Core 1 and SIP on Core 0 | `main/esp_main_display.cpp` |

Choose **ONE** of the following compilation commands matching your physical hardware setup:

```bash
# Option A: Build for Standalone Wi-Fi (Any standard ESP32 or S3 Board)
idf.py -D SIP_TRANSPORT=wifi build

# Option B: Build for Ethernet (PoE / Wired W5500 setup)
idf.py -D SIP_TRANSPORT=eth build

# Option C: Build for Guition Touch Display (Requires AXS15231B with LVGL)
idf.py -D SIP_TRANSPORT=display build
```

## Step 4: Security Customizations (Issues #54-#59)

Before compiling, configure security settings according to your environment's posture:

### 1. Closed Mode vs. Open Mode Authentication (Issue #56)
By default, the SIP engine starts in **Open Mode** for rapid bench-testing and hobbyist setups. If you are deploying the firmware in a production or shared corporate network environment, you must switch the system to **Closed Mode** to block unauthorized traffic.
> [!CAUTION]
> **This is not a build knob and editing that `#define` does nothing.** Earlier revisions
> told you to comment out `POCKETDIAL_OPEN_REGISTRAR` in `src/SIP/RequestsHandler.hpp`. That
> macro is **unconditional** and only seeds the boot *default*; the header's own comment at
> `RequestsHandler.hpp:4-15` says in as many words: *"Do not document this as a build knob;
> it is not one."*

* To enable Closed Mode: the registrar admission mode is a **runtime** setting,
  persisted in NVS as `reg_mode` in the `pbxcfg` namespace. Change it with
  `POST /api/registrar` (`mode=learn` or `mode=secure`) from a logged-in dashboard session,
  or seed it at flash time through the `cfgseed` record. See
  [LEARN_MODE.md](LEARN_MODE.md) for the cutover procedure.
* Effect: in `learn`, an unknown MAC is adopted trust-on-first-use and then locked to
  that MAC; in `secure`, every `REGISTER` **and** `INVITE` is digest-challenged.
* Before you plan on `secure`: read [LEARN_MODE.md](LEARN_MODE.md) Step 4 first. There
  is currently no way to set a per-extension SIP secret, so `secure` rejects every phone
  rather than protecting them, and `POST /api/registrar mode=secure` refuses with `409`
  unless you override it. `learn` is the strongest mode that can actually be deployed today.

### 2. Address of Record (AOR) Sanitization Safeguard (Issue #55)
The engine whitelists and sanitizes SIP Address of Record (AOR) segments during inbound packet parsing. 
* Only alphanumeric characters and the characters `.`, `-`, `_`, `+`, **`*` and `#`** are
  allowed (`RequestsHandler.cpp:5968-5977`). The last two matter: without them the star and
  pound feature codes (`*8` group pickup, `**<ext>` directed pickup, the `*PIN#` admin menu)
  would not be dialable.
* Malformed injection strings or script probes are instantly intercepted and rejected with a `400 Bad Request` packet, preventing potential parsing or configuration hijacking attempts.

### 3. Distributed Scanner Denial-of-Service Defense (Issue #58)
The system prevents flash/memory exhaustion exploits by network scanners via two mechanisms:
* Old rate-limit tracking buckets (inactive for >60 seconds) are automatically swept from memory during the tick process.
* The number of concurrent tracking source IPs is restricted to a hard cap of `MAX_BUCKETS = 256`. Scanning packets exceeding this limit are silently dropped to safeguard device stability.

## Step 5: Flash the Board

Connect your development board using a high-quality USB-C/micro-USB cable. Identify the serial port assigned to your device:
* Windows: Open Device Manager and check `Ports (COM & LPT)` (e.g., `COM3`, `COM12`).
* Linux: Run `ls /dev/ttyUSB*` or `ls /dev/ttyACM*` (e.g., `/dev/ttyUSB0`).
* macOS: Run `ls /dev/cu.usbserial*` or `ls /dev/cu.usbmodem*`.

Flash the compiled firmware binaries and partition tables directly to the flash memory of your board, and start the serial monitor:

```bash
# Replace 'COM3' or '/dev/ttyUSB0' with your actual port address
idf.py -p COM3 flash monitor
```

> [!IMPORTANT]
> If the flashing utility times out while trying to connect, hold down the physical **BOOT / FLASH** button on the development board, press and release the **EN / RST** button, then release the BOOT button to force the chip into ROM bootloader mode before running the command.

## Step 6: Manual HTTP API Verification

Once flashing completes, the device boots and the serial monitor will show logging status. If running in **Wi-Fi SoftAP** or **Display** mode:

1. Connect to the Network: On your laptop or phone, connect to the Wi-Fi network named
   **`esp32-sipserver`**. It is **open by default** (no password). If access-point security
   has been enabled (from the dashboard, or at flash time via the browser flasher), you will
   need the device's own generated WPA2 passphrase instead; see
   [SETUP_GUIDE.md](SETUP_GUIDE.md#turning-on-access-point-security-wpa2) for where to read it.
2. Retrieve Server IP: The SoftAP gateway IP defaults to **`192.168.4.1`**.

You can now manually query and control the firmware using standard terminal commands or by navigating your browser to `http://192.168.4.1/`.

### 1. Get Live System Status (Uptime, Registered Clients, and Sessions)
Retrieves system metrics and registered SIP extensions.

#### Command
```bash
curl -s http://192.168.4.1/api/status
```

#### Expected JSON Output
```json
{
  "ip": "192.168.4.1",
  "port": 5060,
  "httpPort": 80,
  "uptime": 45,
  "packetsProcessed": 12,
  "packetsDropped": 0,
  "clients": [
    {
      "number": "100",
      "address": "192.168.4.2:5060"
    }
  ],
  "sessions": []
}
```

### 2. Scan Local Wi-Fi Networks
Triggers an active network scan and returns reachable SSID lists, their signal strength, and encryption types.

#### Command
```bash
curl -s http://192.168.4.1/api/wifi/scan
```

#### Expected JSON Output
```json
{
  "networks": [
    {
      "ssid": "HQ-Office-WiFi",
      "rssi": -65,
      "encryption": "WPA2"
    },
    {
      "ssid": "Guest-Zone",
      "rssi": -82,
      "encryption": "WPA2"
    }
  ]
}
```

### 3. Connect Device to a Client Wi-Fi Network
Saves credentials into the `"storage"` NVS namespace, changes operating mode to station, and initiates an automatic system restart.

> [!IMPORTANT]
> **This route is admin-gated. An unauthenticated call returns `401`.**
> `POST /api/wifi/connect` goes through `requireAdmin(..., needCsrf=true)`
> (`HttpServer.cpp:642-648`), so it needs a `pd_session` cookie **and** a matching
> `X-CSRF` header. Earlier revisions of this page showed the bare call below without
> either. Log in first, keep the cookie, and echo the CSRF token the login returns.
> See [API.md §0.1](API.md).

#### Command
```bash
# 1. Log in; keep the cookie jar. The response body carries the CSRF token.
curl -c jar.txt -X POST \
     -H "Origin: http://192.168.4.1" \
     -d "username=admin&password=YOUR_PASSWORD" \
     http://192.168.4.1/api/admin/login

# 2. Now the real call, with the session cookie and the token.
curl -b jar.txt -X POST \
     -H "Origin: http://192.168.4.1" \
     -H "X-CSRF: <token from the login response>" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "ssid=HQ-Office-WiFi&password=MySecurePassword" \
     http://192.168.4.1/api/wifi/connect
```

#### Expected Response
```json
{
  "status": "ok",
  "message": "WiFi credentials saved. Rebooting to Station Mode..."
}
```

### 4. Force Disconnect an Active Call Extension (admin session + CSRF)
Sends a disconnect command to terminate the session of a rogue or deadlocked extension.

> [!IMPORTANT]
> **Matching `Origin`/`Host` headers are not sufficient.** Earlier revisions described
> this route as protected by "Same-Origin protection" alone, and showed a `curl` with
> only those two headers. It runs the full `requireAdmin(..., needCsrf=true)` chain
> (`HttpServer.cpp:482-488`, gate body at `:2079-2127`): same-origin, **then** a valid
> `pd_session` cookie, **then** a matching `X-CSRF` token, **then** the forced-setup
> check. Without a session it returns `401 {"error":"authentication required"}`.

#### Command
```bash
# Reuses the cookie jar and CSRF token from the login in §3.
curl -b jar.txt -X POST \
     -H "Origin: http://192.168.4.1" \
     -H "X-CSRF: <token from the login response>" \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "extension=100" \
     http://192.168.4.1/api/kill
```

#### Expected Response
```json
{
  "status": "ok",
  "disconnected": "100"
}
```

## IDF Monitor Shortcuts

When viewing the console logs inside `idf.py monitor`, use these keyboard shortcuts to manage your session:

* `Ctrl + ]`: Exit the serial monitor and return to your terminal shell.
* `Ctrl + T` then `Ctrl + R`: Toggle the RST pin of the board to trigger a hardware reboot.
* `Ctrl + T` then `Ctrl + L`: Toggle hex logging output (displays raw serial packets).
* `Ctrl + T` then `Ctrl + H`: Display help menu showing all console monitor controls.
