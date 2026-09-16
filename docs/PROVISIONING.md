# Phone Auto-Provisioning

Issue: #35, #177 (multi-vendor renderers), #178 (DHCP Option 66)
Status: **Shipped, Yealink only, live.** `GET /config/<mac>.cfg` is implemented and served
by every build (`HttpServer.cpp:437-445`, `:1166-1206`; renderer in
`src/SIP/ProvisioningConfig.hpp`).
Format: Yealink plain-text auto-provisioning keys (`key = value`) on the live route.
Never confirmed against a physical handset: the key names follow Yealink's long-stable,
widely-documented auto-provisioning key set, but no real phone has ever consumed this file.

**Issue #177 status: renderers shipped, wiring not.** `ProvisioningConfig.hpp` now also builds
Grandstream, Polycom (two-file) and Cisco SPA/Linksys/Sipura configs, plus
`detectVendorFromUserAgent()` / `renderProvisioningConfigForUserAgent()` to pick one, all pure,
all host-tested (`tests/ProvisioningConfig_test.cpp`). **None of it is reachable over HTTP yet.**
The live route still calls `yealinkConfigFor()` unconditionally, regardless of what phone asks.
See [§2.5](#25-multi-vendor-renderers-issue-177-not-yet-wired) for what exists, what's missing
to wire it up, and how confident to be in each vendor's field names.

**Issue #178 status: SoftAP injection not achievable in this repo without a much larger change;
wired-LAN path is a config recipe, not code.** See [§1.1](#11-dhcp-option-66--option-43-the-real-zero-touch-path-not-implemented).

> [!IMPORTANT]
> **Read §0.1 before planning a deployment around this.** The endpoint only serves a MAC that
> is already in the Learn-mode adopted-device registry, and a device can only enter that
> registry by *successfully registering* while the board is in Learn mode. On a
> factory-default board, which ships in **Open** mode, and Open mode never records devices,
> every MAC is a structural `404`. This is **not** zero-touch bootstrap. It is
> re-provisioning of phones you already brought up by hand.

An earlier revision of this document was a forward-looking design spec headed *"Phase-1
design (build-ready). No code merged yet."* That header was false by the time it was read:
the endpoint shipped, but at a different URL, with a different file body, and without most of
the surrounding machinery the spec described. §§1-5 below now describe **what exists**.
[§6](#6-original-design-not-implemented) preserves the parts of the original design that were
never built, clearly marked as such, because the analysis in them is still sound.

## 0. What actually ships

A desk phone fetches `http://<board-ip>/config/<mac>.cfg` and gets a Yealink config that
sets its SIP account, server, transport and codec list. pocket-dial generates the file on the
fly from the extension that MAC last registered as.

* One route: `GET /config/<mac>.cfg`. Not session-gated, because a booting phone has no session
  cookie to present (`HttpServer.cpp:439-441`).
* **No new storage.** There is no `prov` NVS namespace. The MAC→extension mapping *is* the
  registrar's adopted-device table, NVS namespace `pbxcfg`, key `devices`
  (`Registrar.hpp:123-126`).
* **No admin CRUD.** There are no `/api/provision/*` endpoints. The only device-management
  routes are `GET /api/registrar`, `POST /api/registrar` (set mode) and
  `POST /api/registrar/device` with `action=secure|forget` (`HttpServer.cpp:642-660`).
  **There is no `adopt` action**; see §0.1.
* **No password in the file.** See §4. This is the single biggest divergence from the
  original design's threat model.
* **No DHCP option, no token, no provisioning window, no auto-assign, no TLS.**
* **Grandstream/Polycom/Cisco renderers exist (Issue #177) but nothing routes to them.** See
  [§2.5](#25-multi-vendor-renderers-issue-177-not-yet-wired).

### 0.1 The real limitation: a phone must register before it can be provisioned

`sendConfigCfg()` calls `RequestsHandler::findProvisioningInfo(mac)`, which walks
`Registrar::adoptedDevices()` and returns `std::nullopt`, a `404`, for any MAC that is not
in it (`RequestsHandler.cpp:4406-4433`).

The **only** code path that inserts into that registry is `Registrar::admitLearn()`, on a
successful REGISTER, in Learn mode, when ARP could resolve the source IP to a MAC
(`Registrar.cpp:167-186`). Specifically:

* Open mode never records devices: `markOnline()` documents this explicitly
  (`Registrar.hpp:77-78`). Open is the shipped default (`RequestsHandler.hpp:536-537`).
* **Secure mode** requires a valid digest to admit a REGISTER at all, and `admitSecure()`
  does not adopt.
* Even in Learn mode, a **first-packet ARP miss** accepts the REGISTER but defers the lock
  and adopts nothing; the *next* REGISTER (by which time the 200 OK + beep + OPTIONS have
  populated the ARP cache) is the one that adopts (`Registrar.cpp:145-153`).

So the working order of operations is:

1. Put the board in **Learn** mode (`POST /api/registrar`, or the `cfgseed` record at flash
   time, see [LEARN_MODE.md](LEARN_MODE.md)).
2. Configure the phone's SIP account **by hand** far enough to register.
3. Let it register (possibly twice, per the ARP note above). It is now adopted.
4. *Now* `GET /config/<mac>.cfg` returns a config for it.

That makes this feature useful for **fleet re-provisioning, config drift correction and
factory-reset recovery** (a phone that has been wiped still has its MAC, so it can pull its
line back), but it cannot configure a phone that has never spoken to the board.

### 0.2 MAC format is strict

`isProvisioningConfigPath()` (`HttpServer.cpp:1166-1180`) accepts the path only if it is
**exactly** `/config/` + 12 characters + `.cfg`, where every one of the 12 is `0-9` or
**lowercase** `a-f`. Uppercase hex, separators (`:` `-` `.`), a short MAC or a long one all
fail the shape check and fall through to the router's `404`. There is no normalization step;
what the phone puts in the URL must already be 12 lowercase hex digits.

## 1. Discovery: how a phone finds pocket-dial

A factory-fresh SIP phone has no idea pocket-dial exists. Three standard mechanisms exist for
it to learn a provisioning-server URL. This analysis still holds, and its conclusion is still
the shipped behaviour: **the URL is typed in by hand.**

### 1.1 DHCP Option 66 / Option 43 (the "real" zero-touch path): NOT implemented

Enterprise phones request a provisioning URL via DHCP:

* Option 66 (`TFTP server name`, RFC 2132): historically a TFTP host, but every major
  vendor accepts an `http://host/path` string here.
* Option 43 (`Vendor-Specific Information`): sub-option encoded, vendor-specific.
  Cisco/Polycom use it; encoding differs per vendor. More fragile.
* Option 160: Polycom/Poly's dedicated provisioning-URL option.

**The ESP-IDF feasibility constraint (Issue #178) is now confirmed by reading the SDK source,
not just the header surface.** pocket-dial's SoftAP and (when it runs its own DHCP server on
the wired side) Ethernet builds both use the bundled ESP-IDF `dhcpserver` component
(`esp_netif_dhcps_start()`, `main/esp_main.cpp:135`, `main/esp_main_eth.cpp:619`, line numbers
as of commit `78b399b`; they drift). Verified against an ESP-IDF **v6.0.2** checkout (CI pins v6.0.1; the "no case for 66" finding
below is structural and very unlikely to be version-specific, but "114 is supported"
specifically might not hold on 6.0.1; re-check if that distinction ever matters):

* **`esp_netif_dhcps_option()`** (`components/esp_netif/lwip/esp_netif_lwip.c`) takes an
  `esp_netif_dhcp_option_id_t`, a closed enum: subnet mask, DNS, router-solicitation flag,
  requested-IP pool, lease time, retry time, vendor class identifier, vendor-specific info, and
  (new since the original version of this doc was written) **Captive-Portal URI, RFC 8910,
  option 114**, `ESP_NETIF_CAPTIVEPORTAL_URI`. There is no `TFTP_SERVER_NAME` / option-66
  entry in this enum.
* Underneath that, **`dhcps_option_info()` / `dhcps_set_option_info()`**
  (`components/lwip/apps/dhcpserver/dhcpserver.c`), the actual per-option storage, has a
  `switch` over exactly the same closed set (`IP_ADDRESS_LEASE_TIME`, `REQUESTED_IP_ADDRESS`,
  `ROUTER_SOLICITATION_ADDRESS`, `DOMAIN_NAME_SERVER`, `SUBNET_MASK`, `CAPTIVEPORTAL_URI`). An
  unrecognized `op_id`, option 66 included, hits `default: break;` and the function returns
  `NULL`/does nothing. **There is no field in `struct dhcps_t` to hold an option-66 value at
  all** (compare `dhcps_captiveportal_uri`, which exists specifically for option 114 and
  nothing else).
* **The one documented extension hook doesn't help either.** `LWIP_HOOK_DHCPS_POST_STATE`
  (`dhcpserver.h`'s own doc comment) fires on `pmsg_dhcps`, the just-parsed **inbound** request,
  immediately after `parse_msg()` and before `send_offer()`/`send_ack()` build a brand-new
  **outbound** message from scratch. A hook here can inspect what the phone asked for; it
  cannot append bytes to what the server sends back.

So: **there is no public, or even internal-but-reachable, way to put option 66 into a SoftAP
DHCP OFFER/ACK without changing `dhcpserver.c` itself.** That file lives inside the `lwip`
component of the ESP-IDF SDK, not in this repository. The only ways to actually ship this are:

1. **Fork the `lwip` component** via `EXTRA_COMPONENT_DIRS` (a project-local directory named
   `lwip` shadows the SDK's own) and add a `dhcps_captiveportal_uri`-shaped field/case for
   option 66 in `send_offer()`/`send_ack()`. This is a fork of an entire IDF component to
   change one function in one file inside it. It is large, and it has to be kept in sync with SDK
   upgrades by hand.
2. **Stop using the built-in DHCP server and ship a minimal one of our own**, the same pattern
   `main/wifi/DnsServer.cpp` already uses for DNS. Full control over every option, but a new
   UDP server to write, test and keep correct (lease tracking, retransmits, the states
   `dhcpserver.c` already handles), a materially bigger undertaking than "add one option."

Both are out of scope for a change confined to `main/esp_main.cpp` / `main/esp_main_eth.cpp`;
scoping this work to those two files (per Issue #178's own text) was, in hindsight, scoping it
to something that cannot be done in those two files. **Neither has been built.** Issue #178
stays open for the SoftAP/Ethernet-DHCP-server case specifically; see
[§1.1a](#11a-wired-lan-with-your-own-dhcp-server-works-today-configure-it-there) for the case
that *is* actionable today.

* **Option 43 IS settable** via `ESP_NETIF_VENDOR_SPECIFIC_INFO`, but the payload must be a
  raw vendor TLV blob and each vendor decodes it differently. One blob that satisfies Yealink
  *and* Grandstream *and* Cisco simultaneously is brittle and firmware-version sensitive.
* **Option 160** is likewise not in the enum.

> Standing decision (unchanged by the #178 investigation): if SoftAP-side DHCP discovery is
> ever built, do it by **forking `lwip`'s `dhcpserver.c` to inject Option 66** (single clean
> string, widest vendor support) or by replacing the DHCP server outright, not by abusing
> Option 43. Pick the fork if IDF-upgrade churn on one file is acceptable; pick the from-scratch
> responder if it isn't. Neither is a small change; budget it as its own issue, not a follow-up
> bullet.

### 1.1a Wired LAN with your own DHCP server: works today, configure it there

When phones sit on a wired LAN behind a *site's own* DHCP server (a router, `dnsmasq`, ISC
`dhcpd`, a Windows Server DHCP role, a pfSense/OPNsense box, …) rather than pocket-dial's own
SoftAP, none of §1.1's ESP-IDF constraint applies, because that server is not pocket-dial's code, and
setting Option 66 on it is ordinary DHCP-server administration, not a firmware change:

| DHCP server | How to set Option 66 |
| :--- | :--- |
| `dnsmasq` | `dhcp-option=66,"http://<board-ip>/config/"` in `dnsmasq.conf` |
| ISC `dhcpd` | `option tftp-server-name "http://<board-ip>/config/";` in the relevant `subnet`/`host` block |
| Windows Server DHCP | Scope Options, then **066 Boot Server Host Name**, set to the same URL string |
| pfSense/OPNsense | Services → DHCP Server → the interface's **TFTP Server** field |
| MikroTik RouterOS | `/ip dhcp-server option add name=opt66 code=66 value="'http://<board-ip>/config/'"`, then attach it to the DHCP server's option set |

Point it at `http://<board-ip>/config/` (a directory, not a specific `.cfg` file) and let each
phone append its own filename the way its firmware already does.

**Be honest with the installer about what actually 200s once the phone fetches that URL.**
Today, only one shape reaches a working response:

* A **Yealink** phone requesting `<mac>.cfg` (its own MAC, 12 lowercase hex, no separators),
  **and only if that MAC is already in the Learn-mode adopted-device registry** (§0.1). Every
  other phone, on every vendor, gets a `404`:
  * Grandstream's `cfg<mac>.xml`, Polycom's `<mac>-phone.cfg` / `000000000000.cfg`, and Cisco
    SPA's `spa<model>.cfg` all fail `isProvisioningConfigPath()`'s shape check before
    `findProvisioningInfo()` is ever called, see [§2.5](#25-multi-vendor-renderers-issue-177-not-yet-wired).
  * Even a Yealink phone 404s if its MAC has never registered while the board was in Learn mode
    (§0.1). Option 66 only gets the phone to *ask*; it does not make the board *know* the
    phone yet.

So Option 66 alone does not deliver zero-touch bootstrap for a fleet with mixed vendors, or for
any vendor before the multi-vendor wiring in §2.5 is finished. It does remove the one manual
step §1.3 describes (typing the URL into the phone's web UI) for Yealink phones that have
already registered once. Set expectations with whoever is deploying this accordingly.

### 1.2 mDNS: advertised, but not a provisioning-discovery path

pocket-dial advertises mDNS (`SipServer.cpp:33-38`, `main/esp_main_display.cpp:901-904`):

```c
mdns_hostname_set(POCKETDIAL_HOSTNAME);          // -> pocketdial.local
mdns_service_add(NULL, "_sip",  "_udp", port,     NULL, 0);
mdns_service_add(NULL, "_http", "_tcp", httpPort, NULL, 0);
```

Both `mdns_service_add()` calls pass `NULL, 0` for the TXT slot; there is **no `provurl` TXT
record**, and adding one was never done. The practical value of mDNS here is that an installer
can type `http://pocketdial.local/config/<mac>.cfg` instead of memorizing the IP. Commercial
desk phones do not auto-provision from mDNS.

### 1.3 Manual URL: what ships

Every phone's web UI has an "auto-provisioning / config server URL" field. An installer
enters `http://192.168.4.1/config/<mac>.cfg` (or the `pocketdial.local` form) and the phone
fetches on next reboot / "Auto Provision Now". This needs only the HTTP endpoint, no DHCP
fork, no firmware-stack changes. Combined with §0.1, the installer is typing that URL into a
phone they have *already* configured by hand, so the marginal effort saved is real but
modest: it is the codec/NAT/expiry/line block that gets standardized, not the bootstrap.

## 2. The endpoint

### 2.1 URL scheme

```
GET /config/{mac}.cfg            # Yealink key=value (or auto-dispatched by User-Agent)
GET /config/cfg{mac}.xml         # Grandstream XML
GET /config/{mac}-phone.cfg      # Polycom per-phone XML
GET /config/000000000000.cfg     # Polycom master/generic XML
GET /config/spa{mac}.cfg         # Cisco SPA macro-expanded flat-profile XML ($MA)
GET /config/spa{model}.cfg       # Cisco SPA model-keyed (Profile_Rule bootstrap)
```

`{mac}` is 12 **lowercase** hex digits, no separators (§0.2).
When requesting `{mac}.cfg`, `User-Agent` is used to detect vendor (Grandstream, Polycom, Cisco SPA, or Yealink fallback). When requesting vendor-specific filename shapes, the vendor format is served directly.

### 2.2 Request handling

`sendConfigCfg(sock, mac)` (`HttpServer.cpp:1182-1206`):

1. `findProvisioningInfo(mac)` walks the adopted-device registry under the engine `_mutex`.
   Miss → `404`.
2. Re-validates the adopted extension against `isValidAor()` as defence in depth: the `.cfg`
   interpolates the extension into `key = value\r\n` lines, so a CR/LF in it would inject
   config lines nobody wrote (Issue #107). The same recheck also refuses an adopted extension
   that is reserved, emergency, or PSTN-shaped (`pbx::isReservedOrPstnAor()`, Issue #163); the
   REGISTER-time identity guard onRegister() applies is not the only gate provisioning depends
   on. Either failure closes → `404` (`RequestsHandler.cpp::findProvisioningInfo`).
3. Resolves the server IP the same way `/api/status` does; SIP port is hardcoded `5060`
   (this codebase does not support a non-default SIP listen port).
4. `provisioning::yealinkConfigFor(ext, ip, 5060, authRequired)`. If the builder refuses
   (its own CR/LF backstop), that is a `404`, never a `200` with an empty body.
5. `200 OK`, `text/plain`.

`authRequired` is true when the device has been promoted to `DeviceState::Secured`, or the
registrar is in Secure mode (`RequestsHandler.cpp:4427-4428`). It changes only the comment
block in the file; see §2.4.

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

Response: MAC `805ec079c37f` adopted as extension `1001`, registrar in Open or Learn
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
* Unverified: these key names have never been tested against a real Yealink. Treat a
  successful fetch as evidence the *server* works, not that the *phone* accepted it.

### 2.5 Multi-vendor renderers (Issues #177, #234): wired

`src/SIP/ProvisioningConfig.hpp` builds four vendor configs (`yealinkConfigFor()`,
`grandstreamConfigFor()`, `polycomPhoneConfigFor()` / `polycomBaseConfigFor()`, and
`ciscoSpaConfigFor()`), plus vendor detection and dispatch (`detectVendorFromUserAgent()`,
`renderProvisioningConfigForUserAgent()`). All four are wired into the live HTTP server
(`src/Helpers/HttpServer.cpp`) via Issue #234:

1. **User-Agent is captured** in `HttpServer::HttpRequest::userAgent` during `parseRequest()`
   and passed to `renderProvisioningConfigForUserAgent()` when `{mac}.cfg` is fetched.
2. **Path-shape check (`isProvisioningConfigPath`)** accepts:
   - Yealink/fallback: `/config/<mac>.cfg`
   - Grandstream: `/config/cfg<mac>.xml`
   - Polycom per-phone: `/config/<mac>-phone.cfg`
   - Polycom master: `/config/000000000000.cfg`
   - Cisco SPA macro: `/config/spa<mac>.cfg` (expanded `$MA`)
   - Cisco SPA model: `/config/spa<model>.cfg` (resolves via ARP if known, or serves `<Profile_Rule>` bootstrap redirect)
3. **Polycom master file** (`000000000000.cfg`) routes directly to `polycomBaseConfigFor()`
   before any device registry lookup.

**Renderer-by-renderer confidence** (all four share the CR/LF injection guard from Issue #107,
and the three XML ones additionally XML-escape the extension. That escaping is defence in depth,
not a fix for a reachable bug: the live route re-validates with `isValidAor()`, which admits only
alnum + `.-_+*#`, so `&` cannot reach a renderer today, but the renderers are pure functions with
no validation of their own, and a future less-filtered caller would otherwise emit malformed XML):

| Vendor | Structure | Field names |
| :--- | :--- | :--- |
| Yealink | N/A (plain text) | Long-stable, widely documented; **never tested against real hardware** (§2.4). |
| Grandstream | **Confirmed** against Grandstream's own [SIP Device Provisioning Guide](https://blog.grandstream.com/hubfs/Grandstream_Feb_2021/Pdf/gs_provisioning_guide_public.pdf) example (`<gs_provision version="1">` → `<mac>` → `<config version="1">` wrapping one `<PNNN>value</PNNN>` element per field, not a `"PNNN = value"` text-line shape). | P271/P270 confirmed against that same guide's example (numeric Active flag / string account name). P36 = SIP Authenticate ID and P34 = SIP Authenticate Password (an earlier draft had these two reversed, caught in review of PR #224, which would have handed the phone the extension as its password and an empty auth ID). The rest (P34/P35/P36/P47/P57/P58) come from a secondary [Grandstream P-Codes reference](https://support.ispsupplies.com/portal/en/kb/articles/grandstream-p-codes-31-10-2019) that **actively disagrees** with other secondary sources found during this change on which P-number means what; P-value assignments are documented per device generation, not universally. Confirm against the target model's own P-Value guide before deploying. P47 folds in a non-default port as `ip:port` rather than using a separate port field. Grandstream's own SIP-Server field is documented as taking address *and* port together, and there is no reliably-sourced separate port P-number. |
| Polycom | Two-file scheme (`polycomBaseConfigFor()` / `polycomPhoneConfigFor()`) cross-confirmed against multiple independent third-party UC Software config examples. | `reg.1.address`/`label`/`displayName`/`auth.userId`/`auth.password`/`server.1.address` cross-confirmed the same way. `reg.1.server.1.port`, `reg.1.server.1.transport` and `voice.codecPref.G711_Mu`/`G711_A` are standard, widely-cited UC Software parameter names, not independently re-confirmed for this change. The base file's `<APPLICATION>` element/attributes are likewise standard-but-unconfirmed, and deliberately omits `APP_FILE_PATH` (pocket-dial hosts no Polycom firmware image; whether a phone tolerates that omission is a hardware question). |
| Cisco SPA / Linksys / Sipura | **Confirmed** against Cisco's own [SPA100/200-series Provisioning Guide](https://www.cisco.com/c/dam/en/us/td/docs/voice_ip_comm/csbpvga/spa100-200/provisioning/guide/SPA100-200_Provisioning.pdf): `<flat-profile>` root, trailing-underscore line-numbered tags (`Line_Enable_1_`, `Proxy_1_`, `User_ID_1_`, `Auth_ID_1_`, `Password_1_`), `G711u`/`G711a` codec value strings, and the `Proxy_1_` field folding address and port together (the guide's own worked example: `192.168.2.100:6060`). | `Use_Auth_ID_1_` is the standard field name from the same product family's admin-UI-derived naming convention, not independently re-confirmed in that specific guide. |

None of the four has been tested against a real handset of any vendor.

## 3. Extension assignment

There is one mode, and it is not configurable: **the extension is whatever that MAC last
successfully registered as.** `admitLearn()` adopts `{mac, ext, Learned}` on first sight and
keeps the extension in sync if the phone later re-registers under a different AOR
(`Registrar.cpp:188-194`).

Consequences:

* **There is no way to pre-assign an extension to a MAC.** No admin endpoint accepts a
  MAC→extension pair (§0). To move a phone to a different extension you change it on the
  phone and let it re-register; the registry follows.
* The registry is bounded by `POCKETDIAL_MAX_CLIENTS` (32 by default): `admitLearn()`
  refuses a new MAC with "Device Table Full" past that, so a flood of distinct MACs cannot
  grow the heap without limit (`Registrar.cpp:171-178`). Because the registry is bounded by
  the *same* constant as the client pool, the original design's "you can pre-map 50 phones
  against a 32-slot pool" scenario does not arise here.
* **Reserved and emergency extensions** (`777`, `999`, `440`, `555`, `888`, `911`, `933`) are
  refused outright by `onRegister()`'s identity guard (`pbx::isReservedOrPstnAor()`, Issue
  #163) with a `403`, before the registrar-mode branch runs at all, so the registry never adopts
  one of these names in ANY mode, Learn included. Before #163 this section described a
  weaker property ("shadowed by routing, not actually refused") that let a phone squat on
  `911` with zero indication anything was wrong; that gap is what #163 closed. An AOR that is
  `+`-prefixed (E.164) or otherwise looks like a direct-dial PSTN number (long, all-digit,
  `POCKETDIAL_MIN_PSTN_AOR_DIGITS`, `PoolConfig.hpp`) is refused the same way. The park-orbit
  (`700`-`709`) and page-zone (`980`-`989`) *ranges* are a separate mechanism (dial-plan
  routing intercepts those, per the original note) and are unaffected by this guard.
  Do not assign any of the above.
* **Not yet guarded: `admitLearn()`'s own re-sync branch.** If a MAC already adopted under one
  extension re-REGISTERs under a different AOR, `admitLearn()` updates the stored extension to
  match (`Registrar.cpp:188-194`), but `onRegister()`'s identity guard runs *before*
  `admitLearn()` is ever reached, so in practice a resync can never carry a reserved/emergency/
  PSTN-shaped AOR either. There is no independent check inside `admitLearn()` itself; it relies
  entirely on the caller's gate. Tracked as a possible defense-in-depth follow-up, not a known
  bypass.
* **`forget` re-arms adoption.** `POST /api/registrar/device` with `action=forget` removes the
  record; a later REGISTER in Learn mode re-learns it (`Registrar.hpp:83-85`).

## 4. Security: what the config actually exposes

The original design was written around the assumption that the provisioning file carries a
live SIP password in cleartext, and built four layers of control around that assumption. **The
shipped file carries no password**, which changes the threat entirely.

### 4.1 Why there is no password in the file

`Registrar`/`SipSecretStore` only ever store **HA1 = MD5(ext:realm:secret)**, a one-way
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
* which extension it is: useful for targeting an INVITE, or (on an Open-mode board) for
  registering as that extension yourself,
* the board's active IP and SIP port,
* whether that extension requires digest auth (the comment block is a one-bit oracle for
  "this device is Secured / the registrar is in Secure mode").

### 4.3 The controls that actually exist

1. **Adopted-MAC allowlist.** No record ⇒ `404`. The attack surface is exactly the set of
   MACs that have registered in Learn mode.
2. The MAC is the only credential, and it is a 2^48 space: not guessable, but also not
   secret: anyone on the same L2 segment can read it off the wire. The in-code comment at
   `HttpServer.cpp:442-444` frames this correctly as "an unrelated prober learns nothing by
   guessing", which is true of a remote prober and false of a local sniffer.
3. **Uniform `404`.** Bad MAC shape, unknown MAC, bad AOR and a refused render all return the
   same `404` with no body distinction (`HttpServer.cpp:1186-1204`).
4. **Link-layer.** WPA2 on the SoftAP is implemented (NVS `ap_secure`, dashboard toggle, or
   set at flash time from the browser flasher) with a per-device generated passphrase; see
   [THREAT_MODEL.md](THREAT_MODEL.md) and
   [SETUP_GUIDE.md](SETUP_GUIDE.md#turning-on-access-point-security-wpa2). It defaults to
   **off** for fleet compatibility. Turning it on is what removes the passive sniffer;
   **provision over a secured link.**

### 4.4 Transport

Provisioning is served over **plain HTTP**. `HttpServer` is a plain TCP socket with no TLS,
and desk phones ship their own CA stores and frequently fail on self-signed certs without a
manual trust step, which would defeat the point. Closing the open AP (§4.3 item 4) is the
change with the bigger payoff, and it ships today.

### 4.5 Not a security feature

Auto-provisioning configures a phone. It does not authenticate one, and on a default (Open)
board nothing authenticates one. Do not describe it as a security control.

## 5. Sequence: boot → fetch cfg → REGISTER → call

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
      |                                  |  | isValidAor(ext) + reserved/emergency/
      |                                  |  | PSTN-shaped re-check, else 404
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

## 6. Original design, NOT implemented

Everything below was specified in the Phase-1 design and **never built**. It is retained
because the analysis is still sound and because anyone extending provisioning will re-derive
it otherwise. Nothing in this section describes current behaviour.

### 6.1 Routes that do not exist

```
GET /provision/{mac}.cfg      # superseded by GET /config/{mac}.cfg
GET /provision/{mac}.xml      # Grandstream / Polycom — content renderer exists (§2.5), route doesn't
GET /provision/{mac}.boot     # Polycom master bootstrap — content renderer exists (§2.5), route doesn't
GET /provision/{mac}.cisco    # Cisco SPA/MPP — content renderer exists (§2.5), route doesn't
POST   /api/provision/map     # admin MAC->extension mapping — never built
DELETE /api/provision/map
POST   /api/provision/window  # timed provisioning window — never built
POST   /api/provision/reset
GET    /api/provision/list
```

The exact filenames above are illustrative, not what a real phone requests; see §2.5 for the
actual per-vendor filenames (`cfg<mac>.xml`, `<mac>-phone.cfg` / `000000000000.cfg`,
`spa<model>.cfg`) and the three concrete gaps between "the renderer exists" and "the route
exists."

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
  Moot: the endpoint is always open, and §4.1 removed the credential it was protecting.
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
  symbol is unconditionally defined and merely seeds the boot default;
  `RequestsHandler.hpp:6-9` says in as many words *"Do not document this as a build knob; it
  is not one."*
* It flagged that `RequestsHandler`'s constructor hardcoded `32`/`8` instead of using the
  `POCKETDIAL_MAX_CLIENTS` / `POCKETDIAL_MAX_SESSIONS` macros. Those macros are live now;
  `Registrar` bounds its own device table with `POCKETDIAL_MAX_CLIENTS`
  (`Registrar.cpp:173`, `:349`). Check `PoolConfig.hpp` and [SCALING.md](SCALING.md) for the
  current caps rather than trusting the literals quoted in the old text.

Related: [PHONE_COMPATIBILITY.md](PHONE_COMPATIBILITY.md) · [LEARN_MODE.md](LEARN_MODE.md) ·
[THREAT_MODEL.md](THREAT_MODEL.md) · [API.md](API.md) · [SCALING.md](SCALING.md)
