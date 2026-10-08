# pocket-dial

<p align="center">
  <img src="https://img.shields.io/badge/Platform-ESP32--S3-00A9FF?style=for-the-badge" alt="ESP32-S3" />
  <img src="https://img.shields.io/badge/SIP-PBX-4A90E2?style=for-the-badge" alt="SIP PBX" />
  <img src="https://img.shields.io/badge/C%2B%2B-17-00599C?style=for-the-badge" alt="C++17" />
  <img src="https://img.shields.io/badge/License-Apache%202.0-3A7A3A?style=for-the-badge" alt="Apache 2.0" />
</p>

A self-contained SIP PBX that runs entirely on an ESP32-S3 — no router, no server, no cloud.

Register phones, call each other, dial out through a carrier, and use the same C++17 engine as a desktop binary for local testing and development.

## Why pocket-dial?

Most PBXs are built for racks, cloud stacks, or dedicated Linux servers. pocket-dial is different:

- runs on a single ESP32-S3
- handles SIP registration and call control locally
- lets phones talk directly to each other for extension-to-extension calls
- keeps the board out of the media path unless it needs to participate
- works as a real appliance, not a VM or hosted service

That design is what makes a small embedded board practical for a PBX.

## Features

- extension-to-extension calling
- blind and attended transfer
- hold, resume, call park, paging, and ring groups
- call forwarding and DND per extension
- dial-plan based routing
- cloud media anchors and programmable telephony for outside lines (3CX, Apidaze)
- web dashboard for setup, monitoring, and diagnostics
- desktop build for local simulation and testing

## Quick start

### Run locally on your laptop

```bash
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
./build/SipServer --ip 127.0.0.1 --port 5060 --web 8080
```

Then open:

- http://127.0.0.1:8080

Register two softphones at:

- `sip:127.0.0.1:5060`
- extension `1001` and `1002`

Try these built-in features:

- `777` — echo test
- `999` — page every registered phone

### Flash to an ESP32-S3

Use the browser flasher:

https://glomargadaffi.github.io/pocket-dial/flasher/

Or build with ESP-IDF directly:

```bash
idf.py set-target esp32s3
idf.py -D SIP_TRANSPORT=eth build
idf.py -p /dev/ttyUSB0 -D SIP_TRANSPORT=eth flash monitor
```

### Supported hardware variants

| Variant | Hardware | Best use |
|---|---|---|
| `eth` | W5500 or LAN8720 wired Ethernet | office / PoE / best-tested path |
| `wifi` | generic ESP32-S3 + SoftAP | portable, no cabling |
| `display` | Guition JC3248W535 | wallboard / touchscreen UI |
| `lan8720` | classic ESP32 + LAN8720 | older hardware |

## How it works

The project is built around a simple idea: keep the PBX lightweight and fast.

- signaling is handled by the board
- extension-to-extension RTP usually flows directly between phones
- the same C++17 codebase runs on embedded and desktop targets
- the dashboard exposes setup, call state, and operational diagnostics

This is why an ESP32-class device can run a PBX without a separate server.

## Project status

The project is in active development and includes real SIP behavior, embedded firmware targets, desktop testing, and admin tooling.

Hardware and interoperability are documented in the repo, and the docs are the best place to review current limitations and supported scenarios.

## Documentation

- [docs/SETUP_GUIDE.md](docs/SETUP_GUIDE.md)
- [docs/HARDWARE.md](docs/HARDWARE.md)
- [docs/FLASHING.md](docs/FLASHING.md)
- [docs/API.md](docs/API.md)
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)
- [docs/FEATURE_ROADMAP.md](docs/FEATURE_ROADMAP.md)
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)

## Security and deployment notes

pocket-dial is designed as a local appliance, and the project documents its assumptions and risks in detail.

- dashboard access is protected by credentials
- SIP handling includes validation and rate-limiting controls
- the project intentionally documents what it does and does not do
- security expectations are covered in the docs

## Repository layout

```text
.
├── CMakeLists.txt
├── README.md
├── docs/
├── main/
├── test/
├── tools/
├── LICENSE
├── LICENSE-MIT
├── NOTICE
├── .github/
└── ...
```

## Contributing

Contributions are welcome. If you want to help:

1. build and run the desktop binary locally
2. test on physical hardware or SIP clients
3. improve the docs or compatibility notes
4. open an issue with logs, reproduction steps, or a proposed fix

## License

This project is licensed under the Apache License 2.0.

The project retains the MIT-licensed upstream attribution from the original forked codebase, as documented in the repository files.

---

<p align="center">
  <strong>pocket-dial</strong> — a compact SIP PBX built for the ESP32-S3.
</p>
