# Browser flasher

`index.html` is a single, dependency-free page that installs pocket-dial onto
an ESP32-S3 board over USB, using the [Web Serial API][webserial] to drive
[esptool-js][esptool-js] entirely inside the browser. It is served from GitHub
Pages at:

**<https://glomargadaffi.github.io/pocket-dial/flasher/>**

Nothing is uploaded anywhere. The page fetches firmware images from this
repository's GitHub Releases and writes them to the board from the user's own
machine.

## Requirements

* **Chrome, Edge, or Opera on desktop.** Web Serial exists nowhere else, not
  Firefox, not Safari, not any mobile browser. The page detects this and shows
  an explanation instead of a broken UI.
* **HTTPS or `localhost`.** Web Serial requires a secure context. GitHub Pages
  is HTTPS; for local testing serve over `http://localhost`.
* **No other program holding the serial port.** `idf.py monitor`, PuTTY, the
  Arduino IDE, and VS Code serial terminals all take exclusive ownership of a
  COM port on Windows. The page says so up front and translates the resulting
  error into that advice.

## How it works

1. **Connect.** `navigator.serial.requestPort()`, then a `Transport`, then an `ESPLoader`.
   `loader.main()` syncs with the ROM bootloader, identifies the chip, uploads
   the flasher stub, and raises the baud rate to 921600. Everything afterwards
   runs on that one connection.

2. **Report what's installed.** The page reads `esp_app_desc_t` back out of
   both OTA slots (app partition + `0x20`, i.e. `0x20020` for `ota_0` and
   `0x620020` for `ota_1`) and `otadata` at `0xf000` to say which slot is
   live. That yields the project name (`SipServer`) and version of whatever is
   on the board. It does **not** identify the variant (the firmware doesn't
   stamp its transport into the descriptor), so the user always picks the
   board. Every published build is ESP32-S3, so a non-S3 chip gets a warning
   pointing at the from-source `lan8720` build.

3. **Fetch releases from this site, not from the GitHub API.** One call to
   `../firmware/index.json` populates the picker; the newest non-pre-release is
   selected by default. An empty list and network errors are explained states
   that steer the user to the local-file panel.

   > **Why not the API?** It used to be `api.github.com/.../releases`, with each
   > image fetched from its asset's `browser_download_url`. **A browser cannot do
   > that.** Those URLs 302 to `release-assets.githubusercontent.com`, and
   > neither the redirect nor the final response sets
   > `Access-Control-Allow-Origin`, so every download fails CORS. The API itself
   > *is* CORS-enabled, so listing releases worked and only the downloads failed;
   > the page looked healthy right up until someone pressed **Flash** (#138).
   >
   > `release.yml` now copies each release's images into `docs/firmware/<tag>/`
   > and regenerates `docs/firmware/index.json`, so everything the page fetches
   > is same-origin and CORS never applies. Nothing on the flash path touches
   > github.com; the only API-shaped thing left is the "view release" link,
   > which is constructed from the tag and is cosmetic.
   >
   > The GitHub Release is still the source of truth and still carries every
   > asset, including the host binary, `partitions.csv` and `SHA256SUMS`. Pages
   > holds only the subset the page downloads. See
   > [`docs/firmware/README.md`](../firmware/README.md).

4. **Resolve the images.** Two release layouts are understood:

   * **`manifest.json`** (preferred; written by `.github/workflows/release.yml`):

     ```json
     {
       "version": "v1.4.0",
       "variants": {
         "esp32s3-eth": {
           "name": "esp32s3-eth",
           "flash": { "size": "16MB", "mode": "dio", "freq": "80m" },
           "parts": [
             { "offset": 0,      "file": "bootloader-esp32s3-eth.bin",       "role": "bootloader",      "size": 20000 },
             { "offset": 32768,  "file": "partition-table-esp32s3-eth.bin",  "role": "partition-table", "size": 3072 },
             { "offset": 61440,  "file": "ota_data_initial-esp32s3-eth.bin", "role": "ota-data",        "size": 8192 },
             { "offset": 131072, "file": "SipServer-esp32s3-eth.bin",        "role": "app",             "size": 950000 }
           ],
           "cfgseed_offset": 16773120
         }
       }
     }
     ```

     Offsets are decimal. `role` is what lets *App only* mode pick its two
     parts without hardcoding `0xf000`/`0x20000` in the page.

     `cfgseed_offset` (`0xFFF000`) is the address of the settings-seed
     partition. It is deliberately *not* in `parts`: that blob is generated in
     the browser, not published in the release. Only its address comes from the
     manifest, read by `release.yml` out of the published
     `partition-table-<variant>.bin` so a partition move follows automatically.
     A manifest without the key, or a convention-layout release, means the
     build predates the feature; the page falls back to the `CFGSEED_OFFSET`
     constant and logs a warning that the firmware will ignore the seed.

   * **Bare naming convention** (v1.2.0 and earlier): `bootloader-<id>.bin`,
     `partition-table-<id>.bin`, `SipServer-<id>.bin`, with offsets and flash
     mode taken from `flasher_args-<id>.json` when it's attached. Those
     releases ship no `ota_data_initial.bin`; the page synthesises it (8 KB of
     `0xFF`, which tells the bootloader to boot `ota_0`). The hand-cut
     `v1.3.0-pre-alpha` names are matched too.

   Variant ids (`esp32s3-eth`, `esp32s3-display`, `esp32s3-wifi`) are the
   `<chip>-<transport>` tag the release workflow uses; `VARIANTS` in
   `index.html` and the matrix in `release.yml` must stay in sync.

5. **Flash.** Every image is downloaded *before* the first byte is written.
   `writeFlash` runs with `eraseAll: false` by default, which is what preserves
   NVS (saved Wi-Fi, admin PIN, extensions), and with `compress: true`. An
   *Erase the whole chip first* checkbox flips `eraseAll` on for the
   single-`factory` → dual-OTA migration described in `FLASHING.md`.

6. **Reset.** `loader.after("hard_reset", usingUsbOtg)`, choosing the USB-OTG
   reset path when `transport.getPid()` matches `loader.USB_JTAG_SERIAL_PID`
   (native USB-Serial-JTAG) and DTR/RTS otherwise (USB-UART bridge).

## Flash modes

| Mode | Writes | When |
| ---- | ------ | ---- |
| **Full flash** | bootloader `0x0`, partition table `0x8000`, otadata `0xf000`, app `0x20000` | First install, and after any partition-table or bootloader change |
| **App only** | otadata `0xf000`, app `0x20000` | Upgrading firmware already on the board, the same regions the OTA path touches |

Both modes additionally write `cfgseed` at `0xFFF000` **only** when the
flash-time configuration panel is opted into; see below.

There is also a **Flash your own build** panel: a file input per region with
an editable offset, for people building locally who don't want to install a
toolchain's flasher.

## Flash-time configuration (the `cfgseed` seed)

*Set Wi-Fi, AP security and SIP registrar mode while flashing* is a collapsed panel in step 3 that
writes a 256-byte settings record to the `cfgseed` partition at `0xFFF000`. The
firmware reads it once at boot, copies the flagged fields into NVS, records the
record's `gen` counter, and ignores the partition until a newer `gen` appears
(`src/Helpers/DeviceConfig.hpp`, which holds the authoritative wire format;
keep the two in lockstep).

It exists mainly for the headless `esp32s3-eth` and `esp32s3-wifi` builds: they
have no screen, so this page is the only place a human ever sees a generated AP
passphrase.

**Opt-in, and off by default.** The panel is governed by *Apply these settings
to the board*, unchecked on load. While it is unchecked the flasher writes
**nothing** to `cfgseed` (the partition is not in the flash plan at all), so
reflashing a board you already configured never clobbers its passphrase, Wi-Fi
mode, or upstream credentials. The panel says so; so does this paragraph,
because it is the property most worth not breaking.

**Every control has a "Leave as is" position**, and only controls moved off it
set their `has-*` flag in the record. This is not politeness: a plain on/off
checkbox for AP security would mean someone opting in purely to set STATION
mode also writes `has-ap-secure` with the value `0`, silently reopening a board
that had WPA2 on, and with a fresh `gen`, so the firmware would really apply
it.

**Turning WPA2 on is a breaking change**, called out in a warning next to the
toggle: every phone, ATA, and laptop already associated with the open access
point has to be re-paired with the new passphrase. *Generate* produces 20
characters from `23456789ABCDEFGHJKMNPQRSTVWXYZ` (no `0`/`O`, `1`/`I`/`L`, `U`)
by rejection-sampled `crypto.getRandomValues`, matching
`DeviceConfig::kPskAlphabet`. Passphrases are validated to 8–63 printable ASCII
characters, the WPA2 bounds the firmware enforces. Selecting *WPA2* with an
empty box generates one rather than letting the firmware pick a value that only
ever reaches the serial log. After a successful flash the passphrase is shown
in the result notice with a **Copy** button and echoed into the log.

**SIP registrar mode** is the one setting here that is not about Wi-Fi, and it
is in this panel because there is nowhere else to put it: digest auth is fully
implemented in the firmware, but nothing outside the unit tests has ever
written the `reg_mode` NVS key (no HTTP endpoint, no dashboard control), so a
device comes up in the compiled-in default and stays there. A dashboard control
is being added in parallel; until it ships, this page is the only way to set
the mode on a headless board before first boot. The compiled-in default is
`open`, so on a never-configured board *Leave as is* means open.

- open (byte `0`): any endpoint on the network registers as any extension,
  no credential. Fine for a bench, lab, or classroom; not for a shared link.
- learn (`1`): trust-on-first-use. Unknown devices are adopted and locked
  to their extension by MAC, while already-secured ones are digest-enforced. A
  deliberate, *temporary* weakening for adopting an existing phone fleet: it
  must not be left on as a steady state and should be run on a trusted or WPA2
  link. Selecting it reveals a warning that says so, and the flash log records
  it.
- secure (`2`): every REGISTER is digest-challenged; an extension is
  registrable only by a party that knows its secret. An extension with no
  stored secret is rejected outright with *Extension Not Provisioned*
  (`Registrar::admitSecure`), so provision before switching a live system over.

**The record's version was deliberately not bumped** when `regMode` was added
at byte 13 behind `kSeedHasRegMode` (bit 5). Each field is gated by its own
flag and every reader ignores flags it does not recognise, so old firmware
skips bit 5 and applies the rest, and new firmware reading an older record
leaves `reg_mode` alone. Bumping the version would have made older firmware
reject the whole record. Future fields go in the reserved space behind a new
flag bit, the same way.

**Older boards.** A board flashed from a release whose partition table predates
`cfgseed` has no such partition; the firmware skips the seed silently, which is
the designed behaviour and not an error. A **Full flash** self-heals it in one
go: the new partition table and the seed are written in the same operation, so
the board comes up already knowing about `cfgseed` and reads the seed on that
first boot. *App only* does not rewrite the partition table, so a seed written
in that mode lands on a layout that does not declare the partition and is
ignored until a full flash. The panel says this too.

## Local development

```powershell
python -m http.server 8000
# then open http://localhost:8000/docs/flasher/
```

esptool-js is imported as an ES module from jsDelivr at a **pinned exact
version** (`0.6.1`). Bump it deliberately: `FlashOptions.fileArray[].data` is
a `Uint8Array` in 0.6.x, and the API has changed shape across releases.

`docs/.nojekyll` disables Jekyll for the Pages build so nothing in the
JavaScript is mistaken for Liquid templating.

[webserial]: https://developer.mozilla.org/docs/Web/API/Web_Serial_API
[esptool-js]: https://github.com/espressif/esptool-js
