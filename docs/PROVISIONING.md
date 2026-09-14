# Phone Auto-Provisioning

**Issue:** #35
**Status:** **Shipped.** `GET /config/<mac>.cfg` is implemented and served by every build
(`HttpServer.cpp:437-445`, `:1166-1206`; renderer in `src/SIP/ProvisioningConfig.hpp`).
**Format:** Yealink plain-text auto-provisioning keys (`key = value`). Yealink only.
**Never confirmed against a physical handset** — the key names follow Yealink's long-stable,
widely-documented auto-provisioning key set, but no real phone has ever consumed this file.

> [!IMPORTANT]
> **Read §0.1 before planning a deployment around this.** The endpoint only serves a MAC that
> is already in the Learn-mode adopted-device registry, and a device can only enter that
> registry by *successfully registering* while the board is in Learn mode. On a
> factory-default board — which ships in **Open** mode, and Open mode never records devices —
> every MAC is a structural `404`. This is **not** zero-touch bootstrap. It is
> re-provisioning of phones you already brought up by hand.

An earlier revision of this document was a forward-looking design spec headed *"Phase-1
design (build-ready). No code merged yet."* That header was false by the time it was read:
the endpoint shipped, but at a different URL, with a different file body, and without most of
the surrounding machinery the spec described. §§1-5 below now describe **what exists**.
[§6](#6-original-design-not-implemented) preserves the parts of the original design that were
never built, clearly marked as such, because the analysis in them is still sound.

---

## 0. What actually ships

A desk phone fetches `http://<board-ip>/config/<mac>.cfg` and gets a Yealink config that
sets its SIP account, server, transport and codec list. pocket-dial generates the file on the
fly from the extension that MAC last registered as.

* **One route:** `GET /config/<mac>.cfg`. Not session-gated — a booting phone has no session
  cookie to present (`HttpServer.cpp:439-441`).
* **No new storage.** There is no `prov` NVS namespace. The MAC→extension mapping *is* the
  registrar's adopted-device table, NVS namespace `pbxcfg`, key `devices`
  (`Registrar.hpp:123-126`).
* **No admin CRUD.** There are no `/api/provision/*` endpoints. The only device-management
  routes are `GET /api/registrar`, `POST /api/registrar` (set mode) and
  `POST /api/registrar/device` with `action=secure|forget` (`HttpServer.cpp:642-660`).
  **There is no `adopt` action** — see §0.1.
* **No password in the file.** See §4. This is the single biggest divergence from the
  original design's threat model.
* **No DHCP option, no token, no provisioning window, no auto-assign, no Grandstream/Polycom
  /Cisco renderer, no TLS.**

### 0.1 The real limitation: a phone must register before it can be provisioned

`sendConfigCfg()` calls `RequestsHandler::findProvisioningInfo(mac)`, which walks
`Registrar::adoptedDevices()` and returns `std::nullopt` — a `404` — for any MAC that is not
in it (`RequestsHandler.cpp:4406-4433`).

The **only** code path that inserts into that registry is `Registrar::admitLearn()`, on a
successful REGISTER, in Learn mode, when ARP could resolve the source IP to a MAC
(`Registrar.cpp:167-186`). Specifically:

* **Open mode never records devices** — `markOnline()` documents this explicitly
  (`Registrar.hpp:77-78`). Open is the shipped default (`RequestsHandler.hpp:536-537`).
* **Secure mode** requires a valid digest to admit a REGISTER at all, and `admitSecure()`
  does not adopt.
* Even in Learn mode, a **first-packet ARP miss** accepts the REGISTER but defers the lock
  and adopts nothing; the *next* REGISTER (by which time the 200 OK + beep + OPTIONS have
  populated the ARP cache) is the one that adopts (`Registrar.cpp:145-153`).

So the working order of operations is:

1. Put the board in **Learn** mode (`POST /api/registrar`, or the `cfgseed` record at flash
   time — see [LEARN_MODE.md](LEARN_MODE.md)).
2. Configure the phone's SIP account **by hand** far enough to register.
3. Let it register (possibly twice, per the ARP note above). It is now adopted.
4. *Now* `GET /config/<mac>.cfg` returns a config for it.

That makes this feature useful for **fleet re-provisioning, config drift correction and
factory-reset recovery** — a phone that has been wiped still has its MAC, so it can pull its
line back — but it cannot configure a phone that has never spoken to the board.

### 0.2 MAC format is strict

`isProvisioningConfigPath()` (`HttpServer.cpp:1166-1180`) accepts the path only if it is
**exactly** `/config/` + 12 characters + `.cfg`, where every one of the 12 is `0-9` or
**lowercase** `a-f`. Uppercase hex, separators (`:` `-` `.`), a short MAC or a long one all
fail the shape check and fall through to the router's `404`. There is no normalization step —
what the phone puts in the URL must already be 12 lowercase hex digits.

---

## 1. Discovery — how a phone finds pocket-dial

A factory-fresh SIP phone has no idea pocket-dial exists. Three standard mechanisms exist for
it to learn a provisioning-server URL. This analysis still holds, and its conclusion is still
the shipped behaviour: **the URL is typed in by hand.**

### 1.1 DHCP Option 66 / Option 43 (the "real" zero-touch path) — NOT implemented

Enterprise phones request a provisioning URL via DHCP:

* **Option 66** (`TFTP server name`, RFC 2132) — historically a TFTP host, but every major
  vendor accepts an `http://host/path` string here.
* **Option 43** (`Vendor-Specific Information`) — sub-option encoded, vendor-specific.
  Cisco/Polycom use it; encoding differs per vendor. More fragile.
* **Option 160** — Polycom/Poly's dedicated provisioning-URL option.

**The ESP-IDF feasibility constraint.** pocket-dial's SoftAP runs the bundled ESP-IDF
`dhcpserver` component (`esp_netif_dhcps_start()`, `main/esp_main.cpp:134`). The server-side
option API, `esp_netif_dhcps_option()`, exposes only a fixed, small enum of option IDs
(subnet mask, DNS, router solicitation, requested IP, lease time, retry time, vendor class
identifier, vendor-specific info).

So:

* **Option 66 is NOT settable through the public API.** There is no `ESP_NETIF_*` enum for
  code 66. Serving it requires either patching/forking the `dhcpserver` component, or
  disabling the built-in DHCP server and shipping a minimal responder of our own (we already
  ship a hand-rolled DNS server in `main/wifi/DnsServer.cpp`, so the pattern exists).
* **Option 43 IS settable** via `ESP_NETIF_VENDOR_SPECIFIC_INFO`, but the payload must be a
  raw vendor TLV blob and each vendor decodes it differently. One blob that satisfies Yealink
  *and* Grandstream *and* Cisco simultaneously is brittle and firmware-version sensitive.
* **Option 160** is likewise not in the enum.

> **Standing decision:** if DHCP discovery is ever built, do it by **forking the bundled
> `dhcpserver` to inject Option 66** (single clean string, widest vendor support), not by
> abusing Option 43. None of this has been built.

### 1.2 mDNS — advertised, but not a provisioning-discovery path

pocket-dial advertises mDNS (`SipServer.cpp:33-38`, `main/esp_main_display.cpp:901-904`):

```c
mdns_hostname_set(POCKETDIAL_HOSTNAME);          // -> pocketdial.local
mdns_service_add(NULL, "_sip",  "_udp", port,     NULL, 0);
mdns_service_add(NULL, "_http", "_tcp", httpPort, NULL, 0);
```

Both `mdns_service_add()` calls pass `NULL, 0` for the TXT slot — there is **no `provurl` TXT
record**, and adding one was never done. The practical value of mDNS here is that an installer
can type `http://pocketdial.local/config/<mac>.cfg` instead of memorizing the IP. Commercial
desk phones do not auto-provision from mDNS.

### 1.3 Manual URL — what ships

Every phone's web UI has an "auto-provisioning / config server URL" field. An installer
enters `http://192.168.4.1/config/<mac>.cfg` (or the `pocketdial.local` form) and the phone
fetches on next reboot / "Auto Provision Now". This needs only the HTTP endpoint — no DHCP
fork, no firmware-stack changes. Combined with §0.1, the installer is typing that URL into a
phone they have *already* configured by hand, so the marginal effort saved is real but
modest: it is the codec/NAT/expiry/line block that gets standardized, not the bootstrap.

---

## 2. The endpoint

### 2.1 URL scheme

```
GET /config/{mac}.cfg     # Yealink key=value. The only route that exists.
```

`{mac}` is 12 **lowercase** hex digits, no separators (§0.2). Yealink substitutes its own MAC
into a `$MAC.cfg` URL template.

Vendor is implicit: there is one renderer. `User-Agent` is not read and not used for routing.

### 2.2 Request handling

`sendConfigCfg(sock, mac)` (`HttpServer.cpp:1182-1206`):

1. `findProvisioningInfo(mac)` — walks the adopted-device registry under the engine `_mutex`.
   Miss → `404`.
2. Re-validates the adopted extension against `isValidAor()` as defence in depth: the `.cfg`
   interpolates the extension into `key = value\r\n` lines, so a CR/LF in it would inject
   config lines nobody wrote (Issue #107). Fails closed → `404`
   (`RequestsHandler.cpp:4414-4426`).
3. Resolves the server IP the same way `/api/status` does; SIP port is hardcoded `5060`
   (this codebase does not support a non-default SIP listen port).
4. `provisioning::yealinkConfigFor(ext, ip, 5060, authRequired)`. If the builder refuses
   (its own CR/LF backstop), that is a `404`, never a `200` with an empty body.
5. `200 OK`, `text/plain`.

`authRequired` is true when the device has been promoted to `DeviceState::Secured`, or the
registrar is in Secure mode (`RequestsHandler.cpp:4427-4428`). It changes only the comment
block in the file — see §2.4.

### 2.3 What the config forces

| Setting | Value | Why |
| :--- | :--- | :--- |
| SIP server / proxy | active board IP : `5060` | The registrar address. Port is not configurable. |
| Transport | UDP (`transport_type = 0`) | The engine only speaks UDP. |
| Extension (label / display / auth / user name) | the AOR this MAC last registered as | Comes straight from the adopted-device record. |
| Auth password | **blank** | The server has no plaintext secret to hand out (§4). |
| Codec | PCMU (priority 1), PCMA (priority 2) | Two codecs are enabled and prioritized; the file does not disable others. |
| NAT | `nat.udp_update_enable = 0` | Media on ordinary calls is peer-to-peer on one L2 segment. |

> [!NOTE]
> The renderer's own comments still justify the codec choice by reference to
> `enforceG711()`. That function is **deprecated with no production callers**; the live
> behaviour is `filterAudioCodecs()`, which admits PCMU/PCMA/**G.722** on relayed
> peer-to-peer legs and PCMU only on server-terminated ones. See
> [PHONE_COMPATIBILITY.md §1.2](PHONE_COMPATIBILITY.md). The generated file is therefore
> *conservative*, not *required*: leaving G.722 enabled on the handset would also work for
> internal calls.
>
> Note also what the file does **not** set: registration expiry (the registrar caps to 3600 s
> regardless) and the `telephone-event` payload type are left at the phone's defaults.

### 2.4 The actual response

**Request** (phone → pocket-dial, on boot / "Auto Provision Now"):

```http
GET /config/805ec079c37f.cfg HTTP/1.1
Host: 192.168.4.1
User-Agent: Yealink SIP-T46S 66.86.0.15
Accept: */*
Connection: close
```

**Response** — MAC `805ec079c37f` adopted as extension `1001`, registrar in Open or Learn
mode (`authRequired = false`):

```http
HTTP/1.1 200 OK
Content-Type: text/plain
Connection: close

#!version:1.0.0.1
# Auto-generated by pocket-dial for extension 1001. Issue #35.
account.1.enable = 1
account.1.label = 1001
account.1.display_name = 1001
account.1.auth_name = 1001
account.1.user_name = 1001
account.1.password = 
account.1.sip_server.1.address = 192.168.4.1
account.1.sip_server.1.port = 5060
account.1.sip_server.1.transport_type = 0
account.1.nat.udp_update_enable = 0
account.1.codec.1.enable = 1
account.1.codec.1.payload_type = PCMU
account.1.codec.1.priority = 1
account.1.codec.2.enable = 1
account.1.codec.2.payload_type = PCMA
account.1.codec.2.priority = 2
```

When `authRequired` is true, three comment lines are inserted after the `# Auto-generated`
line and nothing else changes:

```
# This extension requires a SIP password pocket-dial cannot provision
# automatically (only a one-way hash of it is stored server-side) --
# set account.1.password by hand on this handset before it can register.
```

Notes:
* `transport_type = 0` is Yealink's enum for UDP.
* The `#!version` line must be the first line for Yealink firmware to accept the file.
* Every line is CRLF-terminated.
* **Unverified:** these key names have never been tested against a real Yealink. Treat a
  successful fetch as evidence the *server* works, not that the *phone* accepted it.

---

## 3. Extension assignment

There is one mode, and it is not configurable: **the extension is whatever that MAC last
successfully registered as.** `admitLearn()` adopts `{mac, ext, Learned}` on first sight and
keeps the extension in sync if the phone later re-registers under a different AOR
(`Registrar.cpp:188-194`).

Consequences:

* **There is no way to pre-assign an extension to a MAC.** No admin endpoint accepts a
  MAC→extension pair (§0). To move a phone to a different extension you change it on the
  phone and let it re-register; the registry follows.
* **The registry is bounded by `POCKETDIAL_MAX_CLIENTS`** (32 by default) — `admitLearn()`
  refuses a new MAC with "Device Table Full" past that, so a flood of distinct MACs cannot
  grow the heap without limit (`Registrar.cpp:171-178`). Because the registry is bounded by
  the *same* constant as the client pool, the original design's "you can pre-map 50 phones
  against a 32-slot pool" scenario does not arise here.
* **Reserved virtual extensions** (`777`, `999`, `440`, `555`, `888`, `700`-`709`,
  `980`-`989`) are handled before ordinary routing, so a phone that registers as one of them
  is shadowed by the feature. The registry does not refuse them; the router simply never
  reaches the registration. Do not assign them.
* **`forget` re-arms adoption.** `POST /api/registrar/device` with `action=forget` removes the
  record; a later REGISTER in Learn mode re-learns it (`Registrar.hpp:83-85`).

---

## 4. Security — what the config actually exposes

The original design was written around the assumption that the provisioning file carries a
live SIP password in cleartext, and built four layers of control around that assumption. **The
shipped file carries no password**, which changes the threat entirely.

### 4.1 Why there is no password in the file

`Registrar`/`SipSecretStore` only ever store **HA1 = MD5(ext:realm:secret)** — a one-way
hash. The server never holds the plaintext secret, so it has nothing to provision with even
when one is required. `yealinkConfigFor()` therefore always emits
`account.1.password = ` (blank) and, when the device needs a password, emits a comment
telling the admin to type it in by hand (`ProvisioningConfig.hpp:26-33`, `:56-59`, `:66`).

This is the right trade: it means an auto-provisioning fetch is **not** a credential
disclosure, and the rest of the original design's mitigations (per-MAC URL token, timed
provisioning window, HTTP Basic on the fetch) are not load-bearing and were not built.

### 4.2 What an unauthorized fetch does disclose

Not nothing. A successful fetch tells the requester:

* that this MAC is an adopted device on this board,
* **which extension it is** — useful for targeting an INVITE, or (on an Open-mode board) for
  registering as that extension yourself,
* the board's active IP and SIP port,
* whether that extension requires digest auth (the comment block is a one-bit oracle for
  "this device is Secured / the registrar is in Secure mode").

### 4.3 The controls that actually exist

1. **Adopted-MAC allowlist.** No record ⇒ `404`. The attack surface is exactly the set of
   MACs that have registered in Learn mode.
2. **The MAC is the only credential**, and it is a 2^48 space — not guessable, but also not
   secret: anyone on the same L2 segment can read it off the wire. The in-code comment at
   `HttpServer.cpp:442-444` frames this correctly as "an unrelated prober learns nothing by
   guessing", which is true of a remote prober and false of a local sniffer.
3. **Uniform `404`.** Bad MAC shape, unknown MAC, bad AOR and a refused render all return the
   same `404` with no body distinction (`HttpServer.cpp:1186-1204`).
4. **Link-layer.** WPA2 on the SoftAP is implemented (NVS `ap_secure`, dashboard toggle, or
   set at flash time from the browser flasher) with a per-device generated passphrase — see
   [THREAT_MODEL.md](THREAT_MODEL.md) and
   [SETUP_GUIDE.md](SETUP_GUIDE.md#turning-on-access-point-security-wpa2). It defaults to
   **off** for fleet compatibility. Turning it on is what removes the passive sniffer;
   **provision over a secured link.**

### 4.4 Transport

Provisioning is served over **plain HTTP**. `HttpServer` is a plain TCP socket with no TLS,
and desk phones ship their own CA stores and frequently fail on self-signed certs without a
manual trust step — which would defeat the point. Closing the open AP (§4.3 item 4) is the
higher-leverage change and it ships today.

### 4.5 Not a security feature

Auto-provisioning configures a phone. It does not authenticate one, and on a default (Open)
board nothing authenticates one. Do not describe it as a security control.

---

## 5. Sequence — boot → fetch cfg → REGISTER → call

```
 PHONE (Yealink)          ESP32-S3 pocket-dial
   @ MAC                     SoftAP/Eth + HTTP(:80) + SIP(:5060/UDP)
      |                                  |
      |  (0) MANUAL bring-up: installer types the SIP account into the phone's
      |      web UI by hand, and the board is switched to Learn mode.
      |      (Without this, step 3 is a 404 forever — §0.1.)
      |                                  |
      |  (1) Associate / link up         |
      |--------------------------------->|
      |  (2) DHCP DISCOVER / OFFER / ACK |  standard options only; no Option 66
      |<-------------------------------->|
      |                                  |
      |  (3) REGISTER sip:1001@...:5060  |  admitLearn(): ARP -> MAC
      |--------------------------------->|  first-packet ARP miss? accept, adopt
      |   200 OK (expires<=3600)         |  NOTHING; next REGISTER adopts.
      |<---------------------------------|  adopt {mac, "1001", Learned} -> NVS
      |   + register beep INVITE         |  (signalling only, no server RTP)
      |                                  |
      |  (4) GET /config/<mac>.cfg       |  URL typed by the installer.
      |--------------------------------->|--+ shape check: /config/ + 12 lowercase
      |                                  |  | hex + .cfg, else 404
      |                                  |  | findProvisioningInfo(mac) in the
      |                                  |  | adopted-device registry, else 404
      |                                  |  | isValidAor(ext) re-check, else 404
      |   200 OK  text/plain             |<-+ yealinkConfigFor(ext, ip, 5060, auth)
      |   account.1.* = ...              |     password field BLANK
      |<---------------------------------|
      |                                  |
      |  (5) (phone applies cfg, may reboot once, re-registers)
      |                                  |
      |  ...OPTIONS keepalive every 5s ->|  prune after 15s quiet
      |<- - - 200 OK - - - - - - - - - --|
      |                                  |
      |  (6) INVITE sip:1002@...         |  onInvite(): relayed peer-to-peer;
      |--------------------------------->|  filterAudioCodecs(allowWideband=true)
      |   180 (relayed as-is), 200 + SDP |  narrows the codec list only --
      |<---------------------------------|  the c= line is NEVER rewritten
      |  (7) ACK                         |
      |--------------------------------->|
      |                                  |
      |  (8) RTP audio <== peer-to-peer, phone<->phone, NOT via the board ==>
      |                                  |
      |  (9) BYE / 200 OK                |
      |<-------------------------------->|
```

---

## 6. Original design, NOT implemented

Everything below was specified in the Phase-1 design and **never built**. It is retained
because the analysis is still sound and because anyone extending provisioning will re-derive
it otherwise. Nothing in this section describes current behaviour.

### 6.1 Routes that do not exist

```
GET /provision/{mac}.cfg      # superseded by GET /config/{mac}.cfg
GET /provision/{mac}.xml      # Grandstream / Polycom — never built
GET /provision/{mac}.boot     # Polycom master bootstrap — never built
GET /provision/{mac}.cisco    # Cisco SPA/MPP — never built
POST   /api/provision/map     # admin MAC->extension mapping — never built
DELETE /api/provision/map
POST   /api/provision/window  # timed provisioning window — never built
POST   /api/provision/reset
GET    /api/provision/list
```

### 6.2 Storage that does not exist

An NVS namespace `prov` with per-MAC keys `e_<mac8>` / `s_<mac8>` / `t_<mac8>` / `v_<mac8>`
plus globals `auto_assign`, `range_lo`, `range_hi`, `next_ext`, `window_until`, `count`,
`basic_user`, `basic_pass`.

The load-bearing constraint behind that layout is still true and worth keeping: **NVS keys are
capped at 15 characters**, so a full 12-hex MAC plus a prefix is tight. The shipped code
sidesteps it entirely by serializing the whole device table into one `pbxcfg`/`devices` blob
(`Registrar::persistDevices()`).

### 6.3 Mechanisms that were designed and dropped

* **Per-MAC URL token** (`/provision/{mac}-{token}.cfg`) to defeat URL enumeration.
* **Timed provisioning window** (`prov.window_until`): outside it, all provisioning `404`s.
  The design's "single biggest open question" was whether this should default open or closed.
  Moot — the endpoint is always open, and §4.1 removed the credential it was protecting.
* **HTTP Basic on the fetch URL** (`http://user:pass@host/...`), rejected for MVP, never
  added as an opt-in either.
* **Sequential auto-assign** of extensions from a configured range to unknown MACs.
* **Per-MAC secret generation and storage.** The shipped design stores HA1 only (§4.1).
* **mDNS TXT `provurl` hint.** One line, never added (§1.2).
* **SoftAP client isolation** as a provisioning control. The caveat that killed it still
  applies and is worth remembering: **peer-to-peer RTP between phones requires
  station-to-station traffic**, so blanket client isolation would break ordinary calls.

### 6.4 Stale cross-references in the original design

* It described the codec lock in terms of `SipMessage::enforceG711()` rewriting every answer
  to `0 8 101`. That function is deprecated with no production callers; see §2.3.
* It described the registrar as gated by a compile-time `POCKETDIAL_OPEN_REGISTRAR` mode and
  a future "SEC-04 SIP-auth work". SIP digest auth **shipped**; the mode is a **runtime**
  setting (`reg_mode` in NVS, `POST /api/registrar`), and the `POCKETDIAL_OPEN_REGISTRAR`
  symbol is unconditionally defined and merely seeds the boot default —
  `RequestsHandler.hpp:6-9` says in as many words *"Do not document this as a build knob; it
  is not one."*
* It flagged that `RequestsHandler`'s constructor hardcoded `32`/`8` instead of using the
  `POCKETDIAL_MAX_CLIENTS` / `POCKETDIAL_MAX_SESSIONS` macros. Those macros are live now —
  `Registrar` bounds its own device table with `POCKETDIAL_MAX_CLIENTS`
  (`Registrar.cpp:173`, `:349`). Check `PoolConfig.hpp` and [SCALING.md](SCALING.md) for the
  current caps rather than trusting the literals quoted in the old text.

---

**Related:** [PHONE_COMPATIBILITY.md](PHONE_COMPATIBILITY.md) · [LEARN_MODE.md](LEARN_MODE.md) ·
[THREAT_MODEL.md](THREAT_MODEL.md) · [API.md](API.md) · [SCALING.md](SCALING.md)
