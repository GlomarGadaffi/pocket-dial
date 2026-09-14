# Phone Compatibility & Registration

How to register SIP clients — softphones and hardware IP phones — against **pocket-dial**.
Every client uses the same core settings; this document gives per-client field mappings,
documents known interoperability quirks, and provides a "tested configuration" table.

For the end-to-end first call, see [SETUP_GUIDE.md](SETUP_GUIDE.md). For board choice, see
[HARDWARE_SELECTION.md](HARDWARE_SELECTION.md). For the registrar's admission modes, see
[LEARN_MODE.md](LEARN_MODE.md).

---

## 1. Universal settings (every client)

| Field | Value |
| :--- | :--- |
| SIP server / registrar / domain / proxy | `192.168.4.1` (SoftAP) — or the device's LAN IP on wired builds; `pocketdial.local` where mDNS resolves |
| Port | `5060` |
| Transport | **UDP only** — the engine does not speak TCP, TLS or SIPS |
| Username / Auth ID / extension | your choice, e.g. `1001` (see the reserved list below) |
| Password | **depends on the registrar mode — see §1.1.** On a factory-default board (Open mode) any value or blank registers. |
| Audio codec | **G.711** µ-law (PCMU, `0`) / a-law (PCMA, `8`) always; **G.722** (`9`) between two phones that both offer it. DTMF telephone-event (any payload number, `101` by convention) passes through |
| Registration expiry | ≤ `3600` s (`MAX_EXPIRES`, `RequestsHandler.cpp:48` — the registrar caps higher values to 3600 and floors anything under 30 s) |
| NAT / STUN / ICE / rport | **off** — ordinary call media is peer-to-peer on one L2 segment; NAT traversal only adds latency and failure modes |

### 1.1 SIP passwords: digest auth ships, but the shipped default is Open

The registrar has **three runtime modes** (`Registrar.hpp:26-31`), selected at runtime and
persisted in NVS as `reg_mode` — change it from the dashboard (`POST /api/registrar`) or at
flash time via the `cfgseed` record. Full detail in [LEARN_MODE.md](LEARN_MODE.md).

| Mode | What a REGISTER has to prove | Password on the phone |
| :--- | :--- | :--- |
| **Open** — *the shipped default* (`RequestsHandler.hpp:536-537`) | Nothing. Every REGISTER is accepted, every INVITE routed. | Any value, or blank. |
| **Learn** | Trust-on-first-use: an unknown MAC is adopted and accepted unverified; a device you later promote to *Secured* must present a digest, and its extension is MAC-locked against spoofing (`Registrar.cpp:137-200`). | Blank until you promote the device; then the password you set. |
| **Secure** | RFC 2617 digest auth for every provisioned extension (`Registrar::admitSecure`, `SipDigest.cpp`). | Required, must match. |

> [!WARNING]
> **A fresh board is wide open.** SIP digest authentication is fully implemented, but it is
> **not on by default** — an out-of-the-box unit accepts any REGISTER from any device on the
> link and routes any INVITE. Moving to Learn or Secure mode is a deliberate operator action.
> See [THREAT_MODEL.md](THREAT_MODEL.md).

> [!NOTE]
> The server never stores a plaintext SIP secret — only `HA1 = MD5(ext:realm:secret)`
> (`SipSecretStore.cpp`). Whoever sets a password is the only party who ever holds it.

### 1.2 Codecs: what actually gets negotiated

pocket-dial does **not** transcode. What it does depends on whether the call is relayed
peer-to-peer or terminated on the board:

* **Relayed peer-to-peer legs** (ordinary extension-to-extension calls, hold, transfer,
  ring/hunt groups, pickup — and park when no hold-music clip is loaded) admit
  **PCMU, PCMA and G.722**. Each phone's own
  offer/answer is relayed with its preference order and payload numbering intact;
  `SipMessage::filterAudioCodecs(/*allowWideband=*/true)` only *drops* payloads the PBX
  won't carry (`RequestsHandler.cpp:3269`, `CallForker.cpp:49`, `ParkOrbit.cpp:117`).
  Two G.722-capable phones therefore negotiate wideband between themselves.
* **Server-terminated legs** (`440` tone, `555` anchor bridge, `888` conference) are
  **PCMU-only**: `buildMediaSdp()` emits a literal `m=audio <port> RTP/AVP 0`
  (`RequestsHandler.cpp:1536`), and each of those paths admits a caller only if it offers
  narrowband — `offersSupportedAudio(/*allowWideband=*/false)`, e.g. the anchor gate at
  `RequestsHandler.cpp:1931`. The `777` echo *answer* is narrowed the same way, with
  `filterAudioCodecs(/*allowWideband=*/false)` (`RequestsHandler.cpp:1292`).
* A phone offering **nothing** the PBX will carry (Opus/G.729-only) gets a clean
  **488 Not Acceptable Here** rather than an answer advertising payloads it never offered —
  at the relay-level gate (`RequestsHandler.cpp:1177`, wideband allowed) and again, more
  narrowly, on each server-terminated leg (`:1216`, `:1931`).

> [!IMPORTANT]
> **Keep G.711 (PCMU at minimum) enabled on every client.** G.722 is a bonus that works
> phone-to-phone; G.711 is what every server-terminated feature speaks. You do *not* need to
> disable G.722 — leaving it on costs nothing and buys wideband on internal calls.

> [!NOTE]
> `SipMessage::enforceG711()` still exists in the tree but has **no production callers** —
> it is deprecated. Any older doc describing a blanket "the server rewrites every answer to
> `0 8 101`" is describing removed behaviour.

### 1.3 Reserved extensions — never assign these to a phone

| Code | What it is |
| :--- | :--- |
| `777` | Echo test (SDP loopback — see §4) |
| `999` | All-page broadcast |
| `440` | Server tone stream (server-sourced RTP) |
| `555` | Anchored-media bridge (`kAnchorCallExt`, `RequestsHandler.cpp:72`) |
| `888` | Meet-me conference (`ConferenceRoom::EXT`) |
| `700`–`709` | Call-park orbits (`ParkOrbit.hpp:18`) |
| `980`–`989` | Paging zones |
| `*8`, `**<ext>` | Group pickup / directed pickup |

---

## 2. Softphones

### Linphone (desktop / mobile)

1. Settings → Account → add a SIP account manually.
2. SIP address: `sip:1001@192.168.4.1`.
3. SIP proxy / transport: `192.168.4.1:5060`, **UDP**.
4. Disable "outbound proxy" and any ICE/STUN/TURN under network settings.
5. Audio codecs: enable **PCMU** and **PCMA** (G.722 optional); disable Opus/speex/G.729.

### Zoiper

1. Add account → manual configuration → SIP.
2. Domain / host: `192.168.4.1`, username `1001`, transport **UDP**.
3. Under Codecs, keep **G.711 u-law / a-law** (G.722 optional); drop everything else.
4. Disable STUN/rport in network settings.

### MicroSIP (Windows)

1. Menu → Add Account.
2. SIP server: `192.168.4.1`, Username `1001`, Domain `192.168.4.1`, transport **UDP**.
3. Codecs: select **PCMU** and **PCMA** (G.722 optional).

### Groundwire / Acrobits

1. Add SIP account (generic SIP).
2. Server `192.168.4.1`, port `5060`, username `1001`, transport **UDP**.
3. In advanced/codec settings, keep **G.711**; turn ICE/STUN **off**.

---

## 3. Hardware IP phones

Configure hardware desk phones manually through their web UI (server, port, codec,
transport as above), then read [PROVISIONING.md](PROVISIONING.md) — pocket-dial *does* ship
an auto-provisioning endpoint (`GET /config/<mac>.cfg`, Yealink key format), but it only
serves a MAC already in the Learn-mode adopted-device registry, so it cannot bootstrap a
phone that has never registered. It re-provisions phones you already brought up by hand.

### Yealink (e.g. T2x / T4x series)

- Account → Register: Server Host `192.168.4.1`, Port `5060`, Transport **UDP**,
  Register Name / User Name `1001`.
- Codec: keep **PCMU** and **PCMA** in the enabled list (G.722 optional); remove
  Opus/G.729.
- NAT: set NAT Traversal = Disabled, rport = Disabled, STUN = Disabled.

> [!NOTE]
> **Register beep.** On a *new* binding (not a lease refresh) the server sends the phone a
> short intercom auto-answer INVITE so it plays its own tone, then tears the call back down
> (`RegisterBeeper.cpp`). This is signalling only — the server sources no RTP for it. The
> Call-Info / Alert-Info / P-Auto-Answer headers that make this work were written against
> Yealink's auto-answer behaviour.

### Grandstream (e.g. GXP / GRP series)

- Account → General: SIP Server `192.168.4.1`, SIP Transport **UDP**, SIP User ID `1001`,
  Authenticate ID `1001`.
- Audio codecs: preferred vocoder list = **PCMU** then **PCMA** (G.722 optional).
- Disable STUN and "Use NAT IP".

### Cisco (SPA / MPP series)

- Ext 1 → Proxy and Registration: Proxy `192.168.4.1`, Transport **UDP**.
- Subscriber Information: User ID `1001`.
- Audio Configuration: preferred codec **G711u** / **G711a**; turn off ICE/STUN.

### Polycom / Poly

- Configure the SIP registrar address `192.168.4.1:5060`, transport **UDPOnly**, line
  address/auth user `1001`.
- Codec preferences: enable **G711_Mu** and **G711_A**.

---

## 4. Behavior to expect after registration

- The registrar pings each registered client with a SIP `OPTIONS` keepalive **every 5 s**
  (`RequestsHandler.cpp:5109`) and prunes a client after **15 s** of silence
  (`sweepExpired`, `RequestsHandler.cpp:4163`). Leave each phone's "answer OPTIONS /
  keep-alive" behavior at its default (on).
- A registered extension appears in the `clients` array of
  [`GET /api/status`](API.md#get-apistatus); an active call appears in `sessions`.
- If the client pool is full, a new REGISTER receives `503 Service Unavailable`; the phone
  retries on its next refresh ([SCALING.md §4](SCALING.md)).
- **Provisional responses from the callee are relayed as-is.** A `180 Ringing` that a callee
  sends with an SDP body is forwarded with that body intact — `onRinging` hands it straight
  to `endHandle` (`RequestsHandler.cpp:2770-2786`). The only bodiless `180`s are the ones the
  server *generates* itself (the `777` echo leg, the broadcast/hunt fan-out in
  `CallForker.cpp:90`), which never had a body to begin with.

  > Earlier revisions of this document claimed the server "strips the SDP body from every
  > `180 Ringing` it forwards" as a Yealink early-media workaround. **No such strip exists in
  > the code.** If you hit a ringing hang or early-media loop on a strict terminal, disable
  > early media on the *calling* phone; do not expect the server to intervene.

### Where the audio actually goes

| Call type | RTP path |
| :--- | :--- |
| Ordinary extension → extension | **Peer-to-peer.** The board never touches the media; only SDP is relayed, and the `c=` line is never rewritten. |
| Hold / resume, blind & attended transfer, ring/hunt groups, pickup | **Peer-to-peer** — same property preserved; only the codec list is narrowed. |
| Call parked on an orbit | **Peer-to-peer only while no hold-music clip is loaded.** With a clip loaded the board answers the parked leg `sendonly` from its own port and transmits G.711 µ-law to it for the duration of the park (`ParkOrbit.cpp:56-75`); with no clip it answers `a=inactive` and sources nothing. Retrieve returns the call to peer-to-peer either way. A handset that cannot accept a `sendonly` answer on a re-INVITE will show this as a park-specific fault. |
| `777` echo test | **Peer-to-peer — to itself.** The answer is an SDP loopback of the caller's own offer, so the phone streams to its own address. The board sources and receives *no* RTP. (A stale code comment elsewhere implies otherwise; the loopback at `RequestsHandler.cpp:1228-1293` is authoritative.) |
| `440` tone | **Server-terminated.** The board opens an RTP socket and sends a synthesized µ-law tone (`RtpSender.cpp`). One concurrent stream. |
| `555` anchor bridge | **Server-terminated.** The board sends *and* receives RTP and bridges it to an `AnchorClient`. `POCKETDIAL_MAX_ANCHOR_CALLS` = 1. |
| `888` conference | **Server-terminated.** The board decodes, mixes and re-encodes every leg (`MixBus`, `ConferenceRoom`). Capped at `POCKETDIAL_CONF_LEGS` = 4, no PIN, one global room. |
| Outbound trunk call | **Server-terminated, two legs.** Your handset ↔ the board is ordinary **RTP** (a SIP phone speaks nothing else) through `MediaBridge`. The board ↔ carrier leg is the AnchorClient's chunked-HTTPS PCM16 stream — **not** SIP and **not** RTP, so the board never registers to an ITSP. Reaching a trunk at all requires a dial-plan rule with `action=trunk`; there is no "9" prefix and no fallback. See [FEATURE_ROADMAP.md §1.3](FEATURE_ROADMAP.md) and [`POST /api/dialplan`](API.md#post-apidialplan). |

---

## 5. Quick verification per client

1. Register the client; confirm it shows "registered".
2. Confirm the extension appears on the dashboard (`/api/status` → `clients`).
3. Dial **`777`** — you should hear your own voice. **This does not prove the board's RTP**:
   `777` is an SDP loopback, so all it proves is that the phone can reach its own RTP
   address and that a codec survived negotiation.
4. Dial **`440`** — you should hear a steady tone. *This* is the step that proves the board
   can source RTP to your phone.
5. With a second extension registered, dial it directly — confirm two-way audio (proves the
   peer-to-peer path).
6. Dial **`999`** — confirm other registered phones are paged. Note that `999` is a
   fork-and-pick broadcast: the INVITE goes to every registered phone and the **first** to
   answer wins; the rest are CANCELed (`CallForker.cpp:59-62`). For a genuine N-way bridge,
   dial **`888`**.

If any step fails, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md) (registration timeouts,
one-way/no audio, call drops).

---

## 6. Tested configuration

**One handset has ever been tested against real hardware.** Everything else in this table is
a known-good *baseline configuration*, not a test result — the rest of the project's test
evidence is host-only (gtest, plus pjsua/SIPp against the desktop binary on loopback). Fill
in rows as you validate your own fleet; leave a cell blank rather than guessing.

| Client | Type | Firmware/Version | Server:Port | Transport | Extension | Codecs enabled | Register | 777 echo | 999 page | Direct call | Outbound trunk | Notes |
| :--- | :--- | :--- | :--- | :---: | :--- | :--- | :---: | :---: | :---: | :---: | :---: | :--- |
| **Yealink T29** | IP phone | not recorded | bench board | UDP | not recorded | PCMU (by construction — not recorded) | **PASS** | not tested | not tested | not tested | **PASS** (two-way audio) | The only handset ever tested. See below. |
| Linphone | Softphone | | `192.168.4.1:5060` | UDP | | PCMU, PCMA | | | | | | baseline config only |
| Zoiper | Softphone | | `192.168.4.1:5060` | UDP | | PCMU, PCMA | | | | | | baseline config only |
| MicroSIP | Softphone | | `192.168.4.1:5060` | UDP | | PCMU, PCMA | | | | | | baseline config only |
| Groundwire | Softphone | | `192.168.4.1:5060` | UDP | | PCMU, PCMA | | | | | | baseline config only |
| Yealink (other models) | IP phone | | `192.168.4.1:5060` | UDP | | PCMU, PCMA | | | | | | baseline config only |
| Grandstream | IP phone | | `192.168.4.1:5060` | UDP | | PCMU, PCMA | | | | | | baseline config only |
| Cisco | IP phone | | `192.168.4.1:5060` | UDP | | G711u, G711a | | | | | | baseline config only |
| Polycom/Poly | IP phone | | `192.168.4.1:5060` | UDP | | G711_Mu, G711_A | | | | | | UDPOnly transport; baseline config only |

### What the Yealink T29 result actually covers (2026-09-13)

A real Yealink T29 was registered to the bench board and **outbound PSTN was verified end to
end**: one call rang through to carrier voicemail (answered at 21.2 s) and one was answered
by a person with **two-way audio**. That is the first real-handset evidence in the project's
history.

What it **does** prove, beyond registration and the trunk itself: the handset leg of that call
ran through `RtpReceiver` / `RtpSender` / `MediaBridge` / `PlayoutBuffer` on a real board, so
the **handset-facing RTP path is verified on-target for the anchor-bridge shape**. That is the
only on-target media evidence the project has.

What it does **not** cover, and what nobody should read into it:

* The internal features (`777`, `999`, `888`, `440`, `555`, park, transfer, pickup, BLF) were
  not exercised on that handset. In particular, **`440` and `888` have never been run on
  hardware at all** — the `MixBus` conference mixer is entirely unproven on-target.
* **No automated test has ever exercised on-device RTP.** `RtpSender.cpp` and `RtpReceiver.cpp`
  compile to **host stubs** off-target (`RtpSender.cpp:589`, `RtpReceiver.cpp:416`), so every
  green media test in the suite exercises a stub, not the radio. The rest of the suite is
  host-only too: gtest, plus pjsua/SIPp driven against the **desktop** binary on loopback.
* OTA has never been executed anywhere.
* The Yealink provisioning key set in [PROVISIONING.md](PROVISIONING.md) has still never been
  confirmed against a physical handset.

**Related:** [SETUP_GUIDE.md](SETUP_GUIDE.md) · [LEARN_MODE.md](LEARN_MODE.md) ·
[PROVISIONING.md](PROVISIONING.md) · [HARDWARE_SELECTION.md](HARDWARE_SELECTION.md) ·
[TROUBLESHOOTING.md](TROUBLESHOOTING.md) · [API.md](API.md)
