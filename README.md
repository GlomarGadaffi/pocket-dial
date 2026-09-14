# pocket-dial

**A working telephone exchange on a microcontroller.**

Point SIP desk phones, ATAs or softphones at an ESP32-S3 and they can call each
other — extensions, transfer, hold, park, page, hunt groups, busy-lamp keys. Add a
dial-plan rule and they can call the outside world. No router, no server, no cloud.

The same C++17 engine compiles to a desktop binary, so you can run the whole PBX on
your laptop before you own the hardware.

```
┌──────────┐        SIP signalling        ┌───────────────┐
│ Yealink  │◄───────────────────────────►│  pocket-dial  │
│   1001   │                              │   ESP32-S3    │
└────┬─────┘                              └───────┬───────┘
     │                                            │ (outside calls only)
     │         RTP audio, peer-to-peer            ▼
     └──────────────────────────────────►  ┌─────────────┐
               ┌──────────┐                │   carrier   │
               │ Grandstr │                └─────────────┘
               │   1002   │
               └──────────┘
```

For an ordinary extension-to-extension call the board brokers the setup and then
gets out of the way — the phones stream audio directly to each other and the
microcontroller never sees an RTP packet. That single design choice is why a
240 MHz chip with 512 KB of RAM can run a phone system at all.

---

## Status

Outbound calling to the public phone network is **verified on real hardware**: a
Yealink T29 registered to a bench board placed a call that rang through to carrier
voicemail, and a second that was answered with two-way audio.

That is also the honest limit of the hardware evidence. One handset model, one
board, one carrier. Everything else in the test suite is host-side: 506 GoogleTest
cases plus real-SIP-stack interop (pjsua, SIPp) against the **desktop** binary.
On-device RTP has no automated coverage — `RtpSender`/`RtpReceiver` compile to host
stubs, so the green media tests exercise stubs, not silicon. OTA has never been
exercised end to end. See [docs/PHONE_COMPATIBILITY.md](docs/PHONE_COMPATIBILITY.md)
for what has actually been tried.

---

## Try it in two minutes, no hardware

```bash
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
./build/SipServer --ip 127.0.0.1 --port 5060 --web 8080
```

Open **http://127.0.0.1:8080**, point two softphones (Linphone, Zoiper, MicroSIP)
at `sip:127.0.0.1:5060` as extensions `1001` and `1002`, and call each other.
Dial `777` for an echo test, `999` to page every phone at once.

The dashboard is a patch-bay: every registered extension is a jack, lit by state,
with cords showing ring-group membership.

## Run it on an ESP32-S3

No toolchain required — flash a release from Chrome or Edge at
**<https://glomargadaffi.github.io/pocket-dial/flasher/>**. Plug the board in over
USB, pick your variant, click Flash.

Or build it:

```bash
idf.py set-target esp32s3
idf.py -D SIP_TRANSPORT=eth build          # W5500 / LAN8720 wired Ethernet
idf.py -p /dev/ttyUSB0 -D SIP_TRANSPORT=eth flash monitor
```

| `SIP_TRANSPORT` | Hardware | Use case |
|---|---|---|
| `eth` | W5500 or LAN8720 wired Ethernet | Office, PoE — the best-tested path |
| `wifi` | Generic ESP32-S3 + SoftAP | Portable, no cabling |
| `display` | Guition JC3248W535 (LVGL touch) | Wallboard with an on-screen UI |
| `lan8720` | Classic ESP32 + LAN8720 | Older hardware |

Low on RAM? `-D SIP_CONSTRAINED=1` trims features to fit a classic ESP32.

Full instructions: **[docs/SETUP_GUIDE.md](docs/SETUP_GUIDE.md)** ·
**[docs/HARDWARE.md](docs/HARDWARE.md)** · **[docs/FLASHING.md](docs/FLASHING.md)**

---

## What it does

### Call control
Blind transfer (REFER — **see the caveat below**) · attended transfer (REFER with
Replaces) · hold and resume
· RFC 3311 UPDATE (answered; advertised on `OPTIONS` only) · RFC 4028 session
timers (passive) · call park to orbits `700`–`709` · group pickup `*8` and
directed pickup `**<ext>` · ring groups (ring-all or sequential hunt) · call
forward on always / busy / no-answer · per-extension DND · paging zones
`980`–`989` and `999` all-page · busy-lamp-field presence (`SUBSCRIBE`/`NOTIFY`,
RFC 4235 dialog events) · DTMF star codes over SIP INFO.

Three of those need an asterisk before you design around them:

- **Blind transfer currently moves the wrong party.** On a `REFER` the PBX sends `BYE`
  to the party being transferred and re-INVITEs the **transferor** to the target
  (`RequestsHandler.cpp:4459`, `:4471`). For the commonest real shape — a receptionist
  transferring an inbound caller — the customer is hung up on and the receptionist is
  dialled through to the target, while the receptionist's phone reports success. This is
  [#197](https://github.com/GlomarGadaffi/pocket-dial/issues/197); a fix is in flight.
  Attended transfer and call forwarding are not affected — both move the correct leg.

- **Session timers are passive.** The board honours a `Session-Expires` a phone
  asks for and drops the call when it lapses, but it never requests one itself and
  never answers `422`/`Min-SE`. It deliberately leaves `timer` out of its
  `Supported` header, because RFC 4028 §5–6 make `Min-SE` handling and the `422`
  mandatory for anything that claims the extension. A phone that asks for no timer
  gets no dead-peer detection from the board.
- **UPDATE is answered, but only advertised on `OPTIONS`.** `onUpdate` handles
  both the bodiless session-timer refresh and an SDP re-offer. The board lists
  `UPDATE` in the `Allow` header of its `OPTIONS` response — the one place it
  advertises its own capabilities — while the `180`/`200` that set up an ordinary
  call are relayed from the far phone and carry *that* phone's `Allow` instead.
  RFC 3311 §5.1 lets a phone send `UPDATE` only once it has seen it advertised, so
  this path belongs to phones that poll `OPTIONS` or that send it unprompted.

### Routing
A bounded, ordered dial plan maps a dialled pattern to an action:

```
9XXXXXXXXXX  →  trunk       strip 1, prepend 1     outside line
6XX          →  group       600                    ring group
5*           →  page        981                    paging zone
```

`X` matches one digit; a trailing `*` matches the rest. First match wins. Rules are
evaluated **after** the reserved feature extensions, so a catch-all can never
shadow the echo test or a park orbit. Edit them from the dashboard's **Dial Plan**
button, or `POST /api/dialplan`.

> **The dial plan is the only route to an outside line.** There is no hardcoded `9`
> prefix and no "unknown number goes to the trunk" fallback. A board with an empty
> dial plan answers `404` to every outside number without ever reaching the carrier.

### Reserved extensions
| | |
|---|---|
| `777` | Echo test — your phone streams to itself; the board touches no audio |
| `999` | Page every registered phone, race to answer |
| `440` | Server-generated test tone |
| `888` | Meet-me conference, up to 4 legs, mixed on the board |
| `555` | Bridge to an external audio system (see Outside lines) |
| `700`–`709` | Park orbits |
| `980`–`989` | Paging zones |

### Admin
A web dashboard (always reachable, username + password, forced setup on first
boot), call-detail records, live SIP tracing with `.pcap` export, a **PBX Settings**
panel (`F6`) for uploading and previewing the hold-music clip, dual-slot OTA
updates with rollback, a Prometheus-style **`GET /metrics`** endpoint, and
zero-touch phone provisioning over `GET /config/<mac>.cfg`.

> Not every read endpoint is behind the login. `/api/status`, `/api/cdr`,
> `/metrics`, `/api/ota/status`, `/api/wifi/scan`, `/api/admin/status` and
> `GET /config/<mac>.cfg` all answer without a session — see
> [THREAT_MODEL.md §4 E-2](docs/THREAT_MODEL.md). `/api/cdr` in particular hands
> the recent call log to any host that can reach the board.

---

## Audio: what touches the board, and what doesn't

This distinction matters more than any feature list, so it gets its own section.

| Call type | Does the board carry audio? |
|---|---|
| Extension → extension | **No.** Direct phone-to-phone RTP, including on hold and transfer |
| Call sitting on a park orbit | **Only if music on hold is configured** — see below |
| `777` echo test | **No.** The SDP is looped back; the phone streams to itself |
| `440` tone | Yes — the board generates and sends it |
| `888` conference | Yes — decodes, mixes and re-encodes every leg |
| `555` / outside lines | Yes — the board bridges audio to the external system |

**Park is the one exception that moved.** Historically a parked caller heard literal
silence: the board answered `a=inactive` on the discard port and sourced nothing. With
a music-on-hold clip loaded it instead answers `sendonly` from its own port and streams
the clip to the parked phone, so for the duration of the park the board *is* in the
media path — one-way, board→phone only, and only for the parked leg. With no clip
loaded, which is the default, park falls back to the old silent `a=inactive` hold and
the board still sources nothing. Phone-initiated hold is unaffected either way: that
SDP is relayed untouched.

Codecs on peer-to-peer legs: **PCMU, PCMA and G.722** — the board narrows the offer
to what it can broker and otherwise leaves the phones to negotiate. Legs the board
terminates itself are PCMU-only.

There is no transcoding, and none is planned. See [docs/RTP.md](docs/RTP.md).

---

## Outside lines

pocket-dial reaches the public network through a **call-control API**, not a SIP
trunk. The shipping client speaks the 3CX Call Control API: OAuth2, a WebSocket for
call control, and PCM16 audio over chunked HTTPS. Configure it under
**Interconnect** on the dashboard, then point a dial-plan `trunk` rule at it.

Two consequences worth knowing before you plan around it:

- **The box never registers to an ITSP.** Nothing in the tree sends a SIP `REGISTER`
  as a client, so it cannot connect to a generic SIP carrier today. That is
  [#164](https://github.com/GlomarGadaffi/pocket-dial/issues/164).
- **One outside call at a time on default firmware — up to four with a real trunk.**
  `POCKETDIAL_MAX_ANCHOR_CALLS` is **4** (it was raised from 1 once the 3CX client landed
  and the single-call path was proven on the bench). The effective ceiling is
  `min(provider, 4)`: the `LoopbackAnchorClient` that ships by default declares **1**,
  because its participant id is a constant, so a stock board still gets one. The 3CX
  `TelephonyAnchorClient` declares 4 — the limit there is the ESP32-S3's software ECDHE,
  not RAM or sockets. The fifth call is refused `503`.

There is also no E.164 normalisation anywhere — `+15551234567`, `15551234567` and
`5551234567` are three different destinations to the dial plan and the call log.

---

## Security

The device is an appliance on a local link, so the defences are layered rather than
perimeter-based. [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) is candid about what
each one does and does not buy.

**Read this first:** the registrar ships in **open** mode. A freshly flashed board
accepts any `REGISTER` and any `INVITE` from anything that can reach it. SIP digest
authentication is fully implemented and there are two stricter modes — `learn`
(trust-on-first-use, then lock each extension to its MAC) and `secure` (digest
required) — but you must turn one on. See [docs/LEARN_MODE.md](docs/LEARN_MODE.md).

What is on by default:

- **Username + password on the dashboard**, with forced credential setup on first
  boot, brute-force lockout with exponential backoff, server-side sessions and CSRF
  tokens. (The lockout is currently **global, not per-client** — the per-IP key is
  computed but never reaches the login path, so one guesser can lock out the real
  admin. See [THREAT_MODEL.md](docs/THREAT_MODEL.md) D-3.)
- **SDP admission gate** — every SDP body is structurally checked before any
  decoder runs or it is relayed onward
- **Per-source-IP rate limiting** on the SIP socket (token bucket, burst 40 / 20 pps
  sustained, checked before any header is parsed)
- **No SSH surface** — the second admin plane was deleted rather than hardened

Optional: **WPA2 on the SoftAP**, which encrypts the dashboard, SIP signalling and
RTP in one move. It is off by default so a firmware update cannot strand phones
already associated with an open AP.

Not TLS. On a LAN appliance, self-signed certificates train users to click through
warnings, cost MCU RAM and CPU on a device carrying real-time audio, and protect
only the dashboard — not SIP or RTP. The reasoning is in
[THREAT_MODEL.md §6](docs/THREAT_MODEL.md).

---

## What it deliberately does not do

No voicemail, no IVR or auto-attendant, no call recording, no queues or ACD, no
time-based routing, no MWI, no fax, no video, no multi-tenancy.

Music on hold *was* on that list and no longer is: a G.711 clip on the SD card now
plays to calls sitting on a park orbit (one global cursor, every parked caller hearing
the same point in the track). It covers **park only** — a call a phone puts on hold
itself is still relayed peer-to-peer and hears whatever that handset generates.

Most of these need the board to sit in the audio path for *ordinary* calls, which
is the one thing the architecture is built to avoid. Some are simply unbuilt. The
distinction — and which side of it each feature falls on — is in
[docs/FEATURE_ROADMAP.md](docs/FEATURE_ROADMAP.md).

---

## Capacity

Compile-time pools, sized per tier. Exhaustion degrades gracefully to `503` rather
than failing unpredictably.

| Tier | Extensions | Concurrent calls | Conference legs | Board |
|---|---|---|---|---|
| Pocket | 8 | 2 | — | Classic ESP32, 4 MB flash, `SIP_CONSTRAINED` |
| Office | 32 | 8 | 4 | ESP32-S3, 16 MB flash — the default |
| Rack | 128+ | 32+ | 8 | Desktop build |

Details and the reasoning behind the numbers: [docs/SCALING.md](docs/SCALING.md). Need more
Wi-Fi phones than one SoftAP's ~10–16-station ceiling holds? See
[docs/SOFTAP_SCALE.md](docs/SOFTAP_SCALE.md) for the deployment options and why mesh isn't
one of them yet.

---

## How it works inside

- **[ARCHITECTURE.md](docs/ARCHITECTURE.md)** — the concurrency model: core-pinned
  tasks, an outbox pattern that keeps socket syscalls outside the lock, a
  double-buffered snapshot so the dashboard never blocks signalling, and a
  zero-heap-allocation hot path
- **[RTP.md](docs/RTP.md)** — the media bridge, G.711 codecs, and what the board
  does and doesn't carry
- **[SCALING.md](docs/SCALING.md)** — where the ceilings are and why
- **[SOFTAP_SCALE.md](docs/SOFTAP_SCALE.md)** — scaling a Wi-Fi deployment past one
  SoftAP's station cap: the mesh-vs-wired-backbone decision
- **[THREAT_MODEL.md](docs/THREAT_MODEL.md)** — STRIDE analysis and the residual risks
- **[API.md](docs/API.md)** — every HTTP endpoint
- **[CONTRIBUTING.md](docs/CONTRIBUTING.md)** — build, test and PR workflow

---

## Licence

Apache License 2.0 for all work since the fork. pocket-dial began as a fork of
[BarGabriel/SipServer](https://github.com/BarGabriel/SipServer) (MIT); that
licence is preserved in [LICENSE-MIT](LICENSE-MIT) and the attribution in
[NOTICE](NOTICE).
