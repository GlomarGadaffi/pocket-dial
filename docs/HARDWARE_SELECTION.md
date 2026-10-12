# Hardware Selection Guide

This guide maps the supported **pocket-dial** boards to connectivity, display, memory, and realistic capacity, so you can pick one for your deployment. Specifications come from [HARDWARE.md](HARDWARE.md) (pinouts, BOM, wiring) and [SCALING.md](SCALING.md) (capacity tiers); read those for the full detail.

## 1. Comparison table

pocket-dial is a signaling-only SIP server. RTP audio flows peer-to-peer between phones and never touches the board, so capacity is bound almost entirely by the RAM reserved for the connection pools, not by CPU or bandwidth (see [SCALING.md](SCALING.md) §1). The board you pick mostly determines your network tier, meaning how many phones can associate, and whether you get a screen.

| Board | Connectivity | Display | SoC / PSRAM | Flash | SCALING tier | Realistic capacity |
| :--- | :--- | :---: | :--- | :--- | :--- | :--- |
| **Generic ESP32 / ESP32-S3 dev board** | Wi-Fi SoftAP (open or WPA2) | No | ESP32 or ESP32-S3 (PSRAM optional) | varies | **Pocket** (defaults 32/8/52, ~58 KB) | 6–8 calls, ~16 phones (SoftAP-limited) |
| **Guition JC3248W535** | Wi-Fi SoftAP + captive portal | **Yes** (3.5" 320×480 IPS capacitive touch, AXS15231B, QSPI) | ESP32-S3R8, 8 MB Octal PSRAM | 16 MB QSPI | **Office** (64/24/64, ~90 KB) | ~24 calls, 50+ phones |
| **LilyGO T-ETH-ELITE S3 (W5500, PoE)** (*default `eth`*) | **Wired Ethernet + PoE** (W5500 SPI, 802.3af) | No | ESP32-S3-WROOM-1, 8 MB PSRAM | 16 MB + microSD | **Rack** (128/48/128, ~180 KB) | ~48 calls, 100+ phones |
| **Waveshare ESP32-S3-ETH (W5500, PoE)** | **Wired Ethernet + PoE** (W5500 SPI) | No | ESP32-S3R8 | — | **Rack** (128/48/128, ~180 KB) | ~48 calls, 100+ phones |
| **LilyGO T-ETH-Lite (W5500)** | **Wired Ethernet** (W5500 SPI). Not buildable yet; see section 2 | No | ESP32-S3, 8 MB PSRAM | 16 MB + SD/TF slot | **Rack** | ~48 calls, 100+ phones |
| **LilyGO T-POE-Pro (LAN8720)** | **Wired Ethernet + PoE** (LAN8720 RMII, internal MAC) | No | ESP32-WROVER-E | — | **Rack** | ~48 calls, 100+ phones |

A few notes on the table:

- "Display" means a native on-device LVGL UI (status, scrolling SIP log, captive portal QR). All boards still serve the full HTTP dashboard over the network, whether or not they have a screen.
- The SCALING tier sets the compile-time pool caps. All targets build the same firmware; only the `POCKETDIAL_MAX_*` macros differ. The defaults (Pocket) apply unless you pass a tier's `-D` flags. See [SCALING.md §3](SCALING.md) for the exact build commands.
- "Realistic capacity" accounts for network-layer ceilings, not just `MAX_SESSIONS`. On a Wi-Fi SoftAP node the station-association cap binds first. On a wired node the session pool is the limit.

## 2. Connectivity in depth

### Wi-Fi SoftAP (generic ESP32 / ESP32-S3, Guition display)

- The board hosts its own access point `esp32-sipserver` on channel 1, with an internal DHCP server. The registrar binds `192.168.4.1:5060` (`main/esp_main.cpp`, [HARDWARE.md §7](HARDWARE.md)). The access point is open unless a WPA2 passphrase is set.
- The SoftAP is configured for 10 associated stations (`EXAMPLE_MAX_STA_CONN = 10`). The ESP-IDF Wi-Fi driver caps associations at roughly 10–16 regardless of how large you set the client pool ([SCALING.md §5](SCALING.md)). This is why the Pocket tier stays near the defaults. Extra client slots on a SoftAP are wasted RAM.
- Best for: self-contained pop-up intercoms, classrooms, small offices, or any place with no existing network. No router required.

### Wired Ethernet / PoE (LilyGO T-ETH-ELITE W5500, Waveshare W5500, LilyGO T-ETH-Lite W5500, LilyGO T-POE-Pro LAN8720)

- The board is a node on your wired LAN. It gets an address by DHCP, with a static fallback. There is no station-association ceiling, so the SIP session pool, not the network, is the limit. That is why high client counts belong on a wired board (Rack tier).
- W5500 boards use an external Wiznet MAC/PHY over SPI. LAN8720 boards use the ESP32's internal Ethernet MAC over RMII. See [HARDWARE.md §3–6](HARDWARE.md) for exact pinouts and bus speeds. The W5500 runs at 40 MHz on the T-ETH-ELITE, its hardware-verified maximum through the S3 GPIO matrix. The chip itself supports up to 80 MHz on IOMUX-routed boards.
- The two W5500 boards that build, the T-ETH-ELITE and the Waveshare ESP32-S3-ETH, differ only in their SPI pin map. Pick yours at build time with `-D PD_ETH_BOARD=elite` (default) or `=waveshare`.
- The LilyGO T-ETH-Lite is not a build option yet. Its pin map is in [HARDWARE.md §4](HARDWARE.md) but is not wired into the build. Any other `PD_ETH_BOARD` value stops the CMake configure step with a fatal error.
- PoE is available on the LilyGO T-ETH-ELITE (802.3af Class 0), the Waveshare ESP32-S3-ETH, and the LilyGO T-POE-Pro. A single RJ45 carries both data and power. The LilyGO T-ETH-Lite is W5500 wired Ethernet without onboard PoE.
- Best for: permanent installs, racks, deployments with more than ~16 phones, or where you want power and data on one cable.

## 3. Display: yes or no

Only the **Guition JC3248W535** has a screen: a 3.5" 320×480 IPS capacitive touch panel driven by the AXS15231B controller over QSPI, with a battery-voltage ADC on GPIO 5 ([HARDWARE.md §2](HARDWARE.md)). It runs the native LVGL CGA-style switchboard UI and shows the captive-portal join QR code on first boot.

- The display build uses one 307.2 KB, 16-bit frame buffer (320 × 480 × 2 bytes) in PSRAM. That is why this board needs the 8 MB Octal PSRAM part. The buffer is not double-buffered. The flush copies it out in bands through a small internal DMA-capable buffer, because the SPI master cannot DMA directly from PSRAM. The SIP pools stay in internal SRAM ([SCALING.md §3 PSRAM note](SCALING.md)).
- Every other board is headless but fully usable via the HTTP dashboard from any browser on the network.

## 4. PSRAM and memory

- Generic ESP32 and ESP32-S3: PSRAM is optional. The Pocket tier's pools (about 58 KB; the message pool is the derived 52, see [SCALING.md](SCALING.md) §2) still fit in the roughly 290–320 KB of usable internal DRAM on a plain ESP32.
- Guition and other S3 boards: PSRAM is present (8 MB), but it is not required for the SIP pools. The exception is the display build, where it holds the LVGL frame buffer. Keeping SIP state in internal SRAM avoids PSRAM access latency on the signaling path ([SCALING.md §3](SCALING.md)).
- Do not naively 10× the pool macros. The pools would then exceed a plain ESP32's internal DRAM and fail to boot or starve the Wi-Fi stack. Scale clients and sessions to your network tier, keep the message pool roughly equal to the client count, and watch the dashboard headroom counters. See [SCALING.md §5](SCALING.md).

## 5. Power and wiring notes

From [HARDWARE.md §9](HARDWARE.md):

- Touch I2C pull-ups (Guition display): ensure 4.7 kΩ pull-ups on `TOUCH_SDA` (GPIO 4) and `TOUCH_SCL` (GPIO 8) to 3.3 V. Many JC3248W535 clones omit these, causing I2C timeouts and panel-init crashes.
- High-frequency SPI Ethernet routing (W5500 boards): keep SPI traces shorter than 5 cm, bundle ground alongside `SCK`/`MOSI`, and expect crosstalk on the 40 MHz clock if lines are loosely jumpered on a breadboard.
- PoE: the LilyGO T-ETH-ELITE, Waveshare ESP32-S3-ETH, and LilyGO T-POE-Pro accept power over the RJ45. The LilyGO T-ETH-Lite and Wi-Fi boards are USB-C powered.
- Backlight (Guition display): `TFT_BL` is on GPIO 1, active-high (high = backlight on).

For exact GPIO maps, bus assignments, and the BOM, see [HARDWARE.md](HARDWARE.md). This guide summarizes on purpose; that document is the source of truth for pinouts.

## 6. Pick X if you need Y

| If you need… | Pick |
| :--- | :--- |
| The cheapest, simplest standalone box; no existing network | **Generic ESP32 / ESP32-S3** (Wi-Fi SoftAP, Pocket tier) |
| A local screen, touch UI, and on-device status display | **Guition JC3248W535** (Office tier) |
| More than ~16 phones, or a permanent rack install | A **wired Ethernet** board (Rack tier) |
| Power and data on a single cable | **LilyGO T-ETH-ELITE** (default), **Waveshare ESP32-S3-ETH**, or **LilyGO T-POE-Pro** (PoE) |
| A Raspberry-Pi-style 40-pin header + PoE + microSD on an S3 | **LilyGO T-ETH-ELITE S3** (W5500) |
| Maximum concurrent calls (~48) | Any **Rack-tier** wired board, built with the Rack `-D` flags |
| A throwaway or pop-up intercom you can carry | **Generic ESP32** SoftAP node |

## 7. Build targets

Each transport is selected at build time with `SIP_TRANSPORT`, plus the optional tier macros. The exact commands are in the [README quick start](../README.md#on-a-board) and [SCALING.md §3](SCALING.md). In short:

- Wi-Fi SoftAP: `idf.py -D SIP_TRANSPORT=wifi build`. Do not use the bare `idf.py build`. `SIP_TRANSPORT` defaults to `eth` (`main/CMakeLists.txt:6-7`), so a plain build produces Ethernet firmware with no SoftAP.
- Touch display: `idf.py -D SIP_TRANSPORT=display build`.
- Wired Ethernet / PoE: `idf.py -D SIP_TRANSPORT=eth build`. This defaults to the LilyGO T-ETH-ELITE S3 pin map. For the Waveshare board, add `-D PD_ETH_BOARD=waveshare`. The boot log prints the active board name and pin map (`W5500 board: …`), so you can confirm the right map is compiled in.
- LAN8720 Ethernet (`lan8720`, classic ESP32 only): run `idf.py set-target esp32`, then `idf.py -D SIP_TRANSPORT=lan8720 build`. CMake stops at configure time on any other target.

To raise the capacity tier, append the `-DCMAKE_CXX_FLAGS="-DPOCKETDIAL_MAX_CLIENTS=…"` flags from [SCALING.md §3](SCALING.md).

Related: [SETUP_GUIDE.md](SETUP_GUIDE.md) · [PHONE_COMPATIBILITY.md](PHONE_COMPATIBILITY.md) · [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
