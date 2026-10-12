# Pocket-Dial ESP32 Firmware: Contributing and Build Guide

This guide covers the ESP-IDF toolchain, building and flashing the firmware, checking a flashed board with softphones and the REST API, and the checks CI runs on pull requests.

## 1. Development Toolchain Prerequisites

The firmware builds with ESP-IDF, and that is the only supported firmware toolchain. CI builds with it on pull requests, the release workflow ships its output, and the browser flasher serves firmware built with it.

There is no Arduino (`.ino`) build. The repository has no `sketches/` directory (see issues #41 and #143).

### ESP-IDF Environment Setup
1. Install **ESP-IDF v6.0 or newer**. `main/CMakeLists.txt` fails at configure time below v6.0. Components such as `esp_driver_ledc` were split out of the monolithic `driver` component after v5.2, so older toolchains cannot build this project. CI pins **v6.0.1**. Follow the [Espressif Installation Guide](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/get-started/index.html).
2. Set up the environment (Windows PowerShell example):
   ```powershell
   . $HOME\esp\esp-idf\export.ps1
   ```
3. Verify the compiler installation:
   ```bash
   xtensa-esp32s3-elf-gcc --version
   ```

## 2. Compiling and Flashing

### Compiling and flashing with the ESP-IDF CLI
1. Open a terminal in the repository root.
2. Select your hardware chip target (`esp32s3` for displays and S3-ETH, `esp32` for the classic LAN8720 boards):
   ```bash
   idf.py set-target esp32s3
   ```
3. Open menuconfig to check the partition scheme, serial speeds, and octal PSRAM settings:
   ```bash
   idf.py menuconfig
   ```
4. Build the application. **Pass the transport explicitly.** A bare `idf.py build` uses the default `SIP_TRANSPORT=eth`, which is set in `main/CMakeLists.txt`. That default is W5500 on S3-only GPIOs. It is never the right build for a classic-ESP32 LAN8720 board. It also starts no SoftAP, so the `192.168.4.1` walkthrough below does not apply to it.
   ```bash
   idf.py -D SIP_TRANSPORT=wifi build      # SoftAP — matches the walkthrough below
   idf.py -D SIP_TRANSPORT=eth build       # W5500; add -D PD_ETH_BOARD=waveshare if needed
   idf.py -D SIP_TRANSPORT=lan8720 build   # classic ESP32 + LAN8720 RMII
   idf.py -D SIP_TRANSPORT=display build   # Guition JC3248W535
   ```
5. Flash the binary and open the serial monitor. Replace `COM3` with your local port:
   ```bash
   idf.py -p COM3 flash monitor
   ```

## 3. Local Testing and Validation

Once the board is flashed and running, test it with the steps below.

### A. Connecting softphones
Connect two software SIP clients, such as MicroSIP, Linphone, or Zoiper, to the board's IP address.

1. Find the server IP in the serial output or on the on-screen display.
   - SoftAP mode: the default gateway is `192.168.4.1`.
   - Station/DHCP mode: use the leased IP, for example `192.168.1.145`.
2. Configure each softphone account.
   - Domain or registrar: `<device_ip>:5060`, for example `192.168.4.1:5060`.
   - Username or extension: set user 1 to `1001` and user 2 to `1002`.
   - Password: leave it blank. The registrar's default mode is `learn`, so an unclaimed extension registers without a credential. SIP digest authentication exists, and the registrar's `learn` and `secure` modes are selected at runtime. In `secure` mode, enter the password provisioned for the extension. See [LEARN_MODE.md](LEARN_MODE.md) and [THREAT_MODEL.md](THREAT_MODEL.md) §9.
   - Protocol: set the transport to **UDP**.
3. Place a call by dialing `1002` from `1001`. The status display should update to show:
   - `Invited` (ringing)
   - `Connected` (active)
4. Test the special extensions.
   - Echo test (`777`): dial `777` from any extension and speak into the microphone. The server answers with a loopback of the caller's own SDP offer, so the phone hears its own voice through its own RTP address. That shows the phone can reach its own RTP address and that a codec survived negotiation. It does not test the board's RTP. Dial `440` for that.
   - Intercom and broadcast paging (`999`): dial `999` from an extension. The server invites every other registered extension with auto-answer headers. The first one to answer takes the page, and the server cancels the rest. For a real N-way bridge, dial `888`.

### B. Dashboard REST API verification
Check the web dashboard and its security barriers with `curl` or a web browser.

1. Fetch the registrar status:
   ```bash
   curl -i http://192.168.4.1/api/status
   ```
   Check that `packetsProcessed` increases with each registration or call.

2. Check same-origin rejection. Send a simulated cross-origin POST that tries to disconnect an extension:
   ```bash
   curl -i -X POST -H "Origin: http://malicious-site.com" -H "Host: 192.168.4.1" --data "extension=1001" http://192.168.4.1/api/kill
   ```
   Confirm that the server returns `403 Forbidden` with the cross-origin error payload.

3. Check the payload size limit. Send a request body over 16 KB to simulate a buffer-flooding attack:
   ```bash
   curl -i -X POST -H "Content-Length: 20000" --data-binary @/path/to/large_file.txt http://192.168.4.1/api/wifi/connect
   ```
   Confirm that the connection closes immediately or that the server returns `413 Payload Too Large`.

## 4. Continuous Integration Checks

CI runs the checks below on pull requests. The workflow is `.github/workflows/ci.yml`.

- **Static analysis.** `cppcheck` (`warning,performance`) is blocking. The step "Run Static Analysis (cppcheck)" fails the job on any unsuppressed finding. The `clang-tidy` step over `src/**` ("Static Analysis (clang-tidy over src/**)") is non-blocking (`continue-on-error: true`). It warns when its diagnostic count differs from its baseline. The step "Static Analysis (clang-tidy safety subset, blocking ratchet)" is blocking. It runs six checks that map to MISRA C++:2023 rules, each with its own baseline, and fails when a count differs from its baseline in either direction. This is not a conformance claim.
- **Compiler warnings.** Neither `ci.yml` nor the root `CMakeLists.txt` sets `-Werror`. The root `CMakeLists.txt` passes `-Wall -Wextra -Wpedantic`. The ESP-IDF build still turns some warnings into errors. `main/CMakeLists.txt` demotes some of them for individual files, and `sdkconfig.defaults` notes that under `-Werror=cpp` a `#warning` is a hard error. So a new warning can still fail the ESP-IDF build.
- **Host tests.** The GoogleTest suite runs under `ctest` (step "Run Unit Test Suite (GoogleTest via CTest)"). The HTTP smoke script `tests/http/test_api.sh` runs against the host `SipServer` binary on the runner (step "Execute HTTP API Smoke Suite (host)"). That job spawns no container. The script checks field presence itself. It does not validate responses against `docs/API.md`.
- **Cross-compilation.** The ESP-IDF matrix job ("Build Firmware (ESP-IDF Matrix)") builds for `esp32` and `esp32s3` with ESP-IDF v6.0.1. CI also runs a partition-table guard (step "Verify Partition Table (dual-OTA layout guard)"), a heap-poisoning build, and a Waveshare build.
- **Coding rules.** No CI step greps for banned calls such as `strcpy`. The clang-tidy safety subset checks for raw `malloc` calls, recursion, unused return values, and uninitialised members and locals. The other rules in [CONTRIBUTING_FIRMWARE.md](../CONTRIBUTING_FIRMWARE.md) are enforced by review. Do not rely on CI to catch them.
