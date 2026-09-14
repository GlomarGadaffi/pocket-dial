# Pocket-Dial ESP32 Firmware: Hardware Configuration Guide

This document defines the official hardware specifications, pin mappings, wiring diagrams, and Bills of Materials (BOM) for the supported microcontrollers and smart display boards running the **pocket-dial** firmware.

---

## 1. Supported Hardware Boards Overview

The **pocket-dial** firmware is designed to compile across multiple hardware targets. It supports two primary product configurations:
1. **Interactive Smart Displays**: Running an on-screen LVGL UI with real-time log scrolling, status fields, and a captive portal.
2. **Headless PoE Signalling Servers**: Compact, high-throughput, power-over-ethernet SIP servers designed for high packet-processing reliability.

Because developers deploy these on different target setups depending on hardware availability, the configuration is managed via preprocessor pin-defines and target SDK configs.

---

## 2. Guition JC3248W535 Smart Display (3.5" Black LCD)

The Guition JC3248W535 is an all-in-one Smart Display powered by an ESP32-S3. It includes a 3.5" high-resolution screen, a capacitive touchscreen, and a built-in battery ADC voltage divider.

```
       ┌────────────────────────────────────────────────────────┐
       │                                                        │
       │                   Guition JC3248W535                   │
       │                   320 x 480 QSPI TFT                   │
       │                      (AXS15231B)                       │
       │                                                        │
       └────────────────────────────────────────────────────────┘
          │ TFT SCK=47                │ I2C SDA=4
          │ TFT CS=45                 │ I2C SCL=8
          │ QSPI TFT Lines            │ (no INT/RST routed —
          │ [21, 48, 40, 39, 38=TE]   │  touch is polled)
          ▼                           ▼
      ┌────────────────────────────────────────────────────────┐
      │                      ESP32-S3R8                        │
      │        (8MB Octal PSRAM + 16MB QSPI Flash Chip)        │
      └────────────────────────────────────────────────────────┘
                       │ GPIO 5 (ADC1_CH4)
                       ▼
                 [ Battery divider ]
```

### Pin Assignments
* **Display Interface**: QSPI (Quad SPI) Panel Bus
* **Touch Controller**: AXS15231B via standard I2C Bus 0

| Hardware Pin Name | ESP32-S3 GPIO | Signal Type | Description |
| :--- | :---: | :---: | :--- |
| `TFT_CS` | **GPIO 45** | Output | Display SPI Chip Select |
| `TFT_SCK` | **GPIO 47** | Output | Display SPI Clock |
| `TFT_D0` | **GPIO 21** | Output / IO | QSPI Data Line 0 |
| `TFT_D1` | **GPIO 48** | Output / IO | QSPI Data Line 1 |
| `TFT_D2` | **GPIO 40** | Output / IO | QSPI Data Line 2 |
| `TFT_D3` | **GPIO 39** | Output / IO | QSPI Data Line 3 |
| `TFT_BL` | **GPIO 1** | Output | LED Backlight Control (High = Backlight ON) |
| `TOUCH_SDA` | **GPIO 4** | Bidirectional | Touch Controller I2C SDA (Pull-up Required) |
| `TOUCH_SCL` | **GPIO 8** | Output | Touch Controller I2C SCL (Pull-up Required) |
| `TOUCH_RST` | **not routed** | — | **Corrected.** The AXS15231B on this board has no reset line brought out; the driver is initialised with `rst = GPIO_NUM_NC` (`main/esp_main_display.cpp:59-64`). |
| `TOUCH_INT` | **not routed** | — | **Corrected.** No touch interrupt either — `int = GPIO_NUM_NC`, and **touch is polled**. |

> [!CAUTION]
> **GPIO 11 and 12 are the microSD CMD/CLK lines on this board, not touch pins.** Earlier
> revisions of this table assigned them to `TOUCH_INT`/`TOUCH_RST`; the code comment at
> `main/esp_main_display.cpp:59-64` records that as a mis-assignment it had to undo. Wiring
> a touch panel to 11/12 on the strength of the old table would collide with the SD slot —
> see §2's microSD note.
| `BATTERY_ADC` | **GPIO 5** | Analog Input | Voltage Divider ADC channel (Simulated or ADC1_CH4) |

> [!TIP]
> **PSRAM Configuration**: This board uses an ESP32-S3R8 chip containing 8MB of Octal PSRAM. In `sdkconfig`, PSRAM **must** be enabled in Octal mode at 80MHz, and LVGL double-frame buffers (320 * 480 * 2 bytes = 307.2 KB each) must be allocated in `MALLOC_CAP_SPIRAM` to prevent internal SRAM exhaustion.

### microSD (Issue #80 — pinout research)

The board's microSD slot is **SD_MMC (SDIO), 1-bit mode only** — CLK/CMD/D0 are the
only lines broken out (D1–D3 aren't wired, which is fortunate: on this board they'd
land on GPIO 48/40/39, the QSPI panel's `TFT_D1`/`TFT_D2`/`TFT_D3`). Not SPI mode.

| Signal | ESP32-S3 GPIO |
| :--- | :---: |
| `SD_MMC_CLK` | **GPIO 12** |
| `SD_MMC_CMD` | **GPIO 11** |
| `SD_MMC_D0`  | **GPIO 13** |

**Sources** (three independent, all agreeing): the vendor's own Arduino demo bundle
(`NorthernMan54/JC3248W535EN`, `.../Demo_Arduino/DEMO_PIC/pincfg.h`:
`SD_MMC_CLK`/`SD_MMC_CMD`/`SD_MMC_D0` = 12/11/13); the `GlomarGadaffi/jc3248-display-
driver` bring-up repo's `main/board.h` + `docs/Pinout-and-Hardware.md` (same three
pins, documented as "verified against the board's own pinout sheet"); and this
repo's own `main/esp_main_display.cpp` comment (added in `17459fa`, hardware-flashed
on COM4), which independently arrived at GPIO 11/12 being the microSD CMD/CLK lines
while fixing an unrelated touch-pin mis-assignment.

**Conflict check against this table**: clean. GPIO 11/12/13 don't collide with
`TFT_*` (45/47/21/48/40/39/1/38 — note **GPIO 38 is `TFT_TE`**, the tearing-effect line,
which §2's pin table omits), `TOUCH_*` (4/8 — the touch IC has no INT/RST routed), or
`BATTERY_ADC` (5).

**Still open** (needs the physical board — this is the issue's blocker, narrowed but
not closed):
- The vendor spec sheet (`JC3248W535C_I_Y`) describes the TF card interface as
  *"reserve[d]"* and its labeled rear-connector photo shows no SD slot at all
  (Boot, Reset, Type-C, battery/power JSTs, 8P IO, HC1.0 4P, Speak — no card slot).
  Whether the slot is actually populated on a given unit needs a look at the board.
- `pincfg.h` and the sibling repo disagree with this repo's touch pin comment on one
  unrelated line (`TOUCH_PIN_NUM_INT` 3 vs. this board's documented NC) — a reminder
  that these are a close but not necessarily identical board revision, so a
  continuity check (multimeter, slot pads to GPIO 12/11/13) before wiring is still
  the safer first step, per the issue.

---

## 3. Waveshare ESP32-S3-ETH + PoE Module

An industrial, ultra-compact ESP32-S3 board with a built-in PoE module and a high-performance W5500 SPI Ethernet controller.

```
       ┌──────────────────┐
       │     RJ45 PoE     │
       └────────┬─────────┘
                │
                ▼
       ┌──────────────────┐             ┌──────────────────┐
       │   W5500 MAC/PHY  │<─── SPI ───>│    ESP32-S3R8    │
       └──────────────────┘             └──────────────────┘
         SCLK: GPIO 13                    SCLK: SPI2_SCLK
         MISO: GPIO 12                    MISO: SPI2_MISO
         MOSI: GPIO 11                    MOSI: SPI2_MOSI
         CS:   GPIO 14                    CS:   SPI2_CS
         INT:  GPIO 10                    INT:  GPIO Pin Interrupt
         RST:  GPIO 9                     RST:  GPIO output
```

### Pin Assignments
* **Ethernet Controller**: Wiznet W5500 MAC/PHY
* **SPI Host Device**: `SPI2_HOST` (FSPI)
* **Bus Speed**: **40 MHz**. Not 36, and **80 MHz hard-fails** with `ESP_ERR_TIMEOUT` at
  driver install. The GPSPI divides an 80 MHz source by integers, so any request in
  40-79 lands on 40 actual — and the old "36" quietly ran at 26.7
  (`main/esp_main_eth.cpp:113-117`).

> [!CAUTION]
> **This table was wrong until this audit, and the wrong values do not fail softly.**
> Earlier revisions listed SCLK 12 / MISO 13 / CS 10 / INT 14 and no reset line — SCLK
> and MISO transposed, CS and INT transposed. That map does not merely fail to link:
> `esp_eth_driver_install()` returns `ESP_ERR_TIMEOUT`, the `ESP_ERROR_CHECK` in
> `eth_init_w5500()` aborts the boot, and **the board sits in a reset loop with no
> network to diagnose it over** (108 consecutive `rst:0xc` in one capture). Corrected on
> hardware in [#155](https://github.com/GlomarGadaffi/pocket-dial/issues/155); the values
> below are `main/esp_main_eth.cpp:84-91` and are the ones actually running on this board.

| Signal Name | ESP32-S3 GPIO | Bus Signal | Description |
| :--- | :---: | :---: | :--- |
| `W5500_SCLK_GPIO` | **GPIO 13** | SPI2 SCLK | SPI Serial Clock |
| `W5500_MISO_GPIO` | **GPIO 12** | SPI2 MISO | SPI Master Input Slave Output |
| `W5500_MOSI_GPIO` | **GPIO 11** | SPI2 MOSI | SPI Master Output Slave Input |
| `W5500_CS_GPIO` | **GPIO 14** | SPI2 CS | SPI Chip Select (Active Low) |
| `W5500_INT_GPIO` | **GPIO 10** | Input | W5500 Hardware Interrupt Pin |
| `W5500_RST_GPIO` | **GPIO 9** | Reset | Waveshare **does** wire a real reset line (the Elite does not) |

> [!IMPORTANT]
> **This board is not the default build.** `PD_ETH_BOARD` defaults to `elite`
> (`main/CMakeLists.txt:37-39`), whose pin map is completely different. Building for a
> Waveshare board without `-D PD_ETH_BOARD=waveshare` flashes the Elite map and produces
> exactly the reset loop described above. There is also **no Waveshare variant in any
> release artifact** — the browser flasher's `esp32s3-eth` image is the T-ETH-Elite — so
> this board must be built from source.

---

## 4. LilyGO T-ETH-Lite W5500 (ESP32-S3 Target)

A widely used dev board featuring an integrated SD/TF card slot, 16MB flash, and 8MB PSRAM, coupled with a W5500 SPI Ethernet controller.

### Pin Assignments
* **Ethernet Controller**: Wiznet W5500 MAC/PHY
* **SPI Host Device**: Default hardware SPI

| Signal Name | ESP32-S3 GPIO | Description |
| :--- | :---: | :--- |
| `W5500_SCLK` | **GPIO 10** | SPI Clock |
| `W5500_MISO` | **GPIO 11** | SPI MISO |
| `W5500_MOSI` | **GPIO 12** | SPI MOSI |
| `W5500_CS` | **GPIO 9** | SPI Chip Select (CS) |
| `W5500_INT` | **GPIO 13** | Hardware Interrupt Pin |
| `W5500_RST` | **GPIO 14** | Hardware Reset Pin |

---

## 5. LilyGO T-ETH-ELITE S3 (W5500, PoE) — default `eth` board

The current default Ethernet target. An ESP32-S3-WROOM-1 carrier board (16 MB flash,
8 MB PSRAM) pairing a W5500 SPI Ethernet controller with onboard 802.3af PoE and a
40-pin Raspberry-Pi-compatible header (T-ETH ELite Shield compatible). A microSD slot
shares a second SPI bus. This is a **different board from the T-ETH-Lite** above — the
W5500 pin map is not the same, so build it with `-D PD_ETH_BOARD=elite` (the default).

```
       ┌──────────────────┐
       │   RJ45 PoE 802.3af│  (Class 0, input 36–57 V)
       └────────┬─────────┘
                │
                ▼
       ┌──────────────────┐             ┌──────────────────────┐
       │   W5500 MAC/PHY  │<─── SPI ───>│  ESP32-S3-WROOM-1     │
       └──────────────────┘             │  (16MB flash/8MB PSRAM)│
         SCLK: GPIO 48                   └──────────────────────┘
         MISO: GPIO 47
         MOSI: GPIO 21
         CS:   GPIO 45
         INT:  GPIO 14
         RST:  not wired (-1)
```

### Pin Assignments
* **Ethernet Controller**: Wiznet W5500 MAC/PHY
* **SPI Host Device**: `SPI2_HOST` (FSPI)
* **Bus Speed**: 40 MHz — the hardware-verified maximum for this board. The Elite's
  W5500 pins route through the S3 GPIO matrix (not IOMUX), and the GPSPI divides its
  80 MHz source by integers: 80 MHz hard-fails (`ESP_ERR_TIMEOUT` at driver install),
  and anything requested between 40 and 79 lands on 40 actual.
* **W5500 SPI address (`ETH_ADDR`)**: `1` (fixed internal address; not a GPIO)

| Signal Name | ESP32-S3 GPIO | Bus Signal | Description |
| :--- | :---: | :---: | :--- |
| `W5500_SCLK_GPIO` | **GPIO 48** | SPI2 SCLK | SPI Serial Clock |
| `W5500_MISO_GPIO` | **GPIO 47** | SPI2 MISO | SPI Master Input Slave Output |
| `W5500_MOSI_GPIO` | **GPIO 21** | SPI2 MOSI | SPI Master Output Slave Input |
| `W5500_CS_GPIO` | **GPIO 45** | SPI2 CS | SPI Chip Select (Active Low) |
| `W5500_INT_GPIO` | **GPIO 14** | Input | W5500 Hardware Interrupt Pin |
| `W5500_RST_GPIO` | **-1 (Unused)** | Reset | Not wired to a GPIO; reset via SPI soft command |

microSD/TF slot — a **separate SPI bus** (`SPI3_HOST`; the W5500 owns `SPI2_HOST`), so the
card and Ethernet never contend. Mounted at `/sdcard` (FATFS) during `eth` boot on this
board; `GET /api/status` reports `sd.{present,mounted,capacityMb}`.

> [!IMPORTANT]
> These four GPIOs are **Elite-only**. On the Waveshare ESP32-S3-ETH the very same pins
> (9–14) are that board's W5500 `SCLK`/`MISO`/`MOSI`/`CS`/`INT`/`RST`, so driving a card
> there would fight the Ethernet controller. `main/CMakeLists.txt` links the SD stack and
> defines `PD_ETH_HAS_SD` for `PD_ETH_BOARD=elite` alone. A card must be **FAT32** —
> ESP-IDF's FatFs does not mount exFAT, which is how cards >32 GB ship from the factory.

| Signal Name | ESP32-S3 GPIO |
| :--- | :---: |
| `SD_MISO` | **GPIO 9** |
| `SD_MOSI` | **GPIO 11** |
| `SD_SCLK` | **GPIO 10** |
| `SD_CS` | **GPIO 12** |

> [!NOTE]
> The W5500 `SCLK`/`MISO`/`MOSI`/`CS` pins (48/47/21/45) overlap the GPIO numbers the
> Guition display uses for its QSPI TFT bus (§2) — harmless, because those are different
> boards with different firmware builds, but don't cross-wire the two pin maps.

> [!IMPORTANT]
> **PoE + USB power coexistence.** The Elite's PoE front end is an isolated 802.3af PD
> module (DP9900M-5V) with a polyfused 5 V output. A P-FET (AO3401A) between USB VBUS and
> the 5 V rail switches off automatically when PoE power is present and its body diode
> blocks back-feed into the USB host, so **simultaneous PoE + USB-serial is safe with the
> OTG SW OFF**. The OTG switch's sole job is to back-feed the PoE 5 V to the USB-C
> connector (to power OTG peripherals) — leave it **OFF** whenever a computer is attached,
> and only power the board from active 802.3af/at equipment (no passive injectors).

---

## 6. LilyGO T-POE-Pro LAN8720 (ESP32-WROVER-E Target)

A legacy ESP32-WROVER-E board with Power-over-Ethernet (PoE) and RMII-based LAN8720 Ethernet. It leverages the native ESP32 internal MAC.

```
       ┌──────────────────┐
       │     RJ45 PoE     │
       └────────┬─────────┘
                │
                ▼
       ┌──────────────────┐             ┌──────────────────┐
       │    LAN8720 PHY   │<─── RMII ──>│  ESP32 Internal  │
       └──────────────────┘             │  Ethernet MAC    │
         MDC:  GPIO 23                  └──────────────────┘
         MDIO: GPIO 18
         CLK:  GPIO 0 (OUT)
         PWR:  GPIO 4 (driven HIGH)
```

### Pin Assignments
* **Ethernet PHY**: LAN8720 (RMII Mode)
* **PHY Address**: `0`
* **Reference Clock Mode**: `EMAC_CLK_OUT` on **GPIO 0** (50 MHz clock generated by the
  ESP32). Not GPIO 17 — **GPIO 0 is the only RMII CLK-OUT capable pad on the classic
  ESP32** (`main/esp_main_eth_lan8720.cpp:178-182`; under IDF v6 this is a plain int GPIO
  number, the `EMAC_APPL_CLK_OUT_GPIO` enum is gone).

| Signal Name | ESP32 GPIO | RMII Signal | Description |
| :--- | :---: | :---: | :--- |
| `ETH_MDC_PIN` | **GPIO 23** | MDC | Management Data Clock |
| `ETH_MDIO_PIN` | **GPIO 18** | MDIO | Management Data Input/Output |
| `LAN8720_POWER_GPIO` | **GPIO 4** | PHY enable | PHY power-enable, driven **HIGH** before init — not GPIO 5 and not active-low |
| `LAN8720_PHY_RST_GPIO` | **-1 (unmanaged)** | PHY_RST | No dedicated PHY reset is driven. `config.h`'s `NRST=5` is believed to be the **4G modem** reset on this board, not the LAN8720's — which is where the old "GPIO 5, active-low" entry came from |
| RMII CLK | **GPIO 0** | CLK_OUT | 50 MHz reference clock output |

---

## 7. Generic Standalone AP (Wi-Fi Only)

For developers lacking Ethernet or smart displays, the firmware compiles onto any standard ESP32 / ESP32-S3 Development Board (e.g., ESP32-WROOM-32D, ESP32-S3-DevKitC-1).

* **Wi-Fi Mode**: SoftAP
* **Broadcast SSID**: `esp32-sipserver`
* **Network Password**: Open (WIFI_AUTH_OPEN) or configurable via NVS.
* **Fallback IP Gateway**: `192.168.4.1`

---

## 8. Bill of Materials (BOM) Estimates

The following table provides estimated BOM specifications for assembling a physical **pocket-dial** station.

| Component Name | Description | Manufacturer Part Number | Quantity | Est. Unit Price (USD) |
| :--- | :--- | :--- | :---: | :---: |
| **Guition Smart Display** | ESP32-S3 3.5" black display board (320x480) with case | Guition JC3248W535 | 1 | $14.50 |
| **PoE Ethernet Module** | ESP32-S3 core board with W5500 SPI Ethernet and PoE RJ45 | Waveshare ESP32-S3-ETH | 1 | $18.90 |
| **PoE Ethernet + RPi-header board** | ESP32-S3-WROOM-1 board, W5500 SPI Ethernet, 802.3af PoE, 40-pin header, microSD (**default `eth` board**) | LilyGO T-ETH-ELITE S3 | 1 | $21.90 |
| **Ethernet Dev Board** | ESP32-S3 LilyGO board with W5500 SPI Ethernet | LilyGO T-ETH-Lite S3 | 1 | $15.50 |
| **RMII Ethernet Board** | ESP32-Wrover board with LAN8720 RMII Ethernet | LilyGO T-POE-Pro | 1 | $19.90 |
| **Battery Divider Resistors** | 100kΩ 1% and 220kΩ 1% resistors for battery ADC divider | Generic | 1 set | $0.10 |
| **USB-C Data Cable** | High-speed data cable for flashing and serial monitoring | Generic | 1 | $2.00 |

---

## 9. Assembly & Wiring Guidelines

### A. Touch I2C Pull-Up Requirements
On boards where the touch controller (AXS15231B) is connected, ensure that **4.7kΩ pull-up resistors** are soldered between:
* `TOUCH_SDA` (GPIO 4) and 3.3V power rails.
* `TOUCH_SCL` (GPIO 8) and 3.3V power rails.
Many JC3248W535 display clones omit these, resulting in I2C timeouts and immediate panel initialization crashes.

### B. High-Frequency SPI Ethernet Routing
If breadboarding the Waveshare or LilyGO W5500 SPI interfaces:
* Keep SPI line paths **shorter than 5 cm** to prevent clock skew.
* Ground lines should be bundled alongside high-speed clock signals (`SCK` and `MOSI`) to shield against EMI.
* High-speed SPI clock lines running at 36 MHz will experience significant crosstalk if unshielded or loosely jumpered.
