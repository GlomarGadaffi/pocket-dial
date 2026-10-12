# Phone Auto-Provisioning

The board serves a phone its SIP account as a vendor config file over HTTP, so an installer does not have to type it into each handset by hand.

Issues #35, #177 (multi-vendor renderers), #178 (DHCP Option 66), #234 (multi-vendor wiring) and #826 (SIP Plug-and-Play and zero-touch) cover this work. The route `GET /config/<mac>.cfg` is served by every build (`HttpServer.cpp:1126-1134`). It returns a Yealink, Grandstream, Polycom, Cisco SPA or snom config, chosen by the requested filename and, for `<mac>.cfg`, by the phone's User-Agent (§2.1). The Yealink file is plain text (`key = value`). The other vendors' files are XML. The renderers live in `src/SIP/ProvisioningConfig.hpp` and are host-tested (`tests/ProvisioningConfig_test.cpp`). The Yealink key names follow Yealink's long-stable, widely documented auto-provisioning key set, but no real Yealink phone has consumed the file. Only the snom path has been run against a handset (§1.4). See [§2.5](#25-multi-vendor-renderers-issues-177-234-wired) for each renderer and how confident to be in its field names.

Issue #178 has two halves. The SoftAP case needs a larger change than this repo makes, so it stays open ([§1.1](#11-dhcp-option-66--option-43-the-real-zero-touch-path-not-implemented)). The wired-LAN case is a DHCP-server recipe, not code ([§1.1a](#11a-wired-lan-with-your-own-dhcp-server-works-today-configure-it-there)).

Read §0.1 before planning a deployment around this. The endpoint only serves a MAC that is already in the Learn-mode adopted-device registry, or one that a zero-touch window assigns (§3.1). A device enters the registry by registering successfully while the board is in Learn mode. On a factory-default board, which ships in Learn mode (#502), a MAC gets a `404` until that phone has registered, unless a window is open. Outside a window this is not zero-touch bootstrap. It is re-provisioning of phones you already brought up by hand.

[Section 6](#6-original-design-not-implemented) keeps the parts of the original Phase-1 design that were never built, marked as such, because the analysis in them is still sound. Sections 1 to 5 describe what exists.

## 0. What actually ships

A desk phone fetches `http://<board-ip>/config/<mac>.cfg` and gets a Yealink config that sets its SIP account, server, transport and codec list. pocket-dial generates the file on the fly from the extension that MAC was adopted as (#820: a later REGISTER for another AOR never changes it). The other vendors' files are generated the same way from their own filenames (§2.1).

* One route, `GET /config/...`, matching the seven filename shapes in §2.1. Not session-gated, because a booting phone has no session cookie to present (`HttpServer.cpp:1126-1134`).
* **No new storage.** There is no `prov` NVS namespace. The MAC→extension mapping *is* the registrar's adopted-device table, NVS namespace `pbxcfg`, key `devices` (`Registrar.hpp:324-326`).
* **No separate admin CRUD for provisioning.** There are no `/api/provision/*` endpoints. The device-management routes are `GET /api/registrar`, `POST /api/registrar` (set mode), `POST /api/registrar/device` with `action=secure|forget`, and `POST /api/registrar/forget-learned` (`HttpServer.cpp:1618-1667`). The zero-touch window has its own pair, `GET` and `POST /api/zero-touch` (§3.1). **There is no `adopt` action**; see §0.1.
* **No password in the file.** See §4. This is the single biggest divergence from the original design's threat model.
* **No DHCP option, no URL token, no TLS.** A timed zero-touch window can assign an extension to an unknown MAC (§3.1).
* **Grandstream, Polycom, Cisco SPA and snom configs are served too,** selected by filename shape and User-Agent. See §2.5 and, for snom, §1.4.

### 0.1 The real limitation: a phone must register before it can be provisioned

`sendProvisioningResponse()` calls `RequestsHandler::findProvisioningInfo(mac)`, which walks `Registrar::adoptedDevices()` and returns `std::nullopt`, a `404`, for any MAC that is not in it (`RequestsHandler.cpp:9670`). A zero-touch assignment (§3.1) can add the row first.

The adoption path is `Registrar::admitLearn()` (`Registrar.cpp:360`). It runs on a successful REGISTER, in Learn mode, when ARP can resolve the source IP to a MAC. The zero-touch window is the only other code path that adds a row. Specifically:

* Open mode, which never recorded devices, is retired (#500). Learn is the shipped default (`Registrar.cpp:43`).
* **Secure mode** requires a valid digest to admit a REGISTER at all, and `admitSecure()` does not adopt.
* Even in Learn mode, a **first-packet ARP miss** accepts the REGISTER but defers the lock and adopts nothing. The *next* REGISTER, by which time the 200 OK + beep + OPTIONS have populated the ARP cache, is the one that adopts (`Registrar.cpp:454-456`).

So the working order of operations is:

1. Put the board in **Learn** mode (`POST /api/registrar`, or the `cfgseed` record at flash time, see [LEARN_MODE.md](LEARN_MODE.md)).
2. Configure the phone's SIP account **by hand** far enough to register.
3. Let it register (possibly twice, per the ARP note above). It is now adopted.
4. *Now* `GET /config/<mac>.cfg` returns a config for it.

That makes this feature useful for **fleet re-provisioning, config drift correction and factory-reset recovery** (a phone that has been wiped still has its MAC, so it can pull its line back). Outside a zero-touch window (§3.1), it cannot configure a phone that has never registered with the board.

### 0.2 MAC format is strict

`isProvisioningConfigPath()` (`HttpServer.cpp:3516`) delegates to `parseProvisioningPath()` (`HttpServer.cpp:3432`), which recognises seven filename shapes (§2.1). For the Yealink shape, the path must be `/config/` + 12 characters + `.cfg`, and every one of the 12 must be `0-9` or **lowercase** `a-f`. Uppercase hex, separators (`:` `-` `.`), a short MAC or a long one all fail the shape check and fall through to the router's `404`. There is no normalization step.

The other MAC-keyed shapes use the same 12-lowercase-hex rule, with one exception. snom alone accepts upper or lower case, because a snom's own `{mac}` template expands to uppercase. The lookup then uses the lowercase form.

## 1. Discovery: how a phone finds pocket-dial

A factory-fresh SIP phone has no idea pocket-dial exists. Three standard mechanisms exist for
it to learn a provisioning-server URL. This analysis still holds, and its conclusion is still
the shipped behaviour: **the URL is typed in by hand.**

### 1.1 DHCP Option 66 / Option 43 (the "real" zero-touch path): Not implemented

Enterprise phones request a provisioning URL via DHCP:

* Option 66 (`TFTP server name`, RFC 2132): historically a TFTP host, but every major
  vendor accepts an `http://host/path` string here.
* Option 43 (`Vendor-Specific Information`): sub-option encoded, vendor-specific.
  Cisco/Polycom use it; encoding differs per vendor. More fragile.
* Option 160: Polycom/Poly's dedicated provisioning-URL option.

**The ESP-IDF feasibility constraint (Issue #178) was confirmed by reading the SDK source, not just the header surface.** pocket-dial's SoftAP and (when it runs its own DHCP server on the wired side) Ethernet builds both use the bundled ESP-IDF `dhcpserver` component (`esp_netif_dhcps_start()`, `main/esp_main.cpp:161`, `main/esp_main_eth.cpp:766`; line numbers drift, so search for the call). The check used an ESP-IDF **v6.0.2** checkout. CI pins v6.0.1 (`.github/workflows/ci.yml`). The finding that there is no case for option 66 is structural and very unlikely to be version-specific. The "114 is supported" part might not hold on 6.0.1, so re-check that if the distinction ever matters:

* **`esp_netif_dhcps_option()`** (`components/esp_netif/lwip/esp_netif_lwip.c`) takes an
  `esp_netif_dhcp_option_id_t`, a closed enum: subnet mask, DNS, router-solicitation flag,
  requested-IP pool, lease time, retry time, vendor class identifier, vendor-specific info, and
  **Captive-Portal URI, RFC 8910, option 114**, `ESP_NETIF_CAPTIVEPORTAL_URI`. There is no `TFTP_SERVER_NAME` / option-66
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

Both are out of scope for a change confined to `main/esp_main.cpp` and `main/esp_main_eth.cpp`, which is the scope Issue #178's text gives. Neither can be done in those two files. **Neither has been built.** Issue #178 stays open for the SoftAP and Ethernet-DHCP-server case specifically. See [§1.1a](#11a-wired-lan-with-your-own-dhcp-server-works-today-configure-it-there) for the case that *is* actionable today.

* **Option 43 is settable** via `ESP_NETIF_VENDOR_SPECIFIC_INFO`, but the payload must be a
  raw vendor TLV blob and each vendor decodes it differently. One blob that satisfies Yealink
  *and* Grandstream *and* Cisco simultaneously is brittle and firmware-version sensitive.
* **Option 160** is likewise not in the enum.

Standing decision: if SoftAP-side DHCP discovery is ever built, do it by **forking `lwip`'s `dhcpserver.c` to inject Option 66** (single clean string, widest vendor support) or by replacing the DHCP server outright, not by abusing Option 43. Pick the fork if IDF-upgrade churn on one file is acceptable; pick the from-scratch responder if it isn't. Neither is a small change, so budget it as its own issue, not a follow-up bullet.

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

Point it at `http://<board-ip>/config/` (a directory, not a specific `.cfg` file) and let each phone append its own filename the way its firmware already does.

**What the installer should expect.** Option 66 only gets a phone to ask. The board answers with a config only when it knows the phone's MAC:

* A phone whose MAC is in the adopted-device registry (§0.1), or which a zero-touch window assigns (§3.1), gets a config in the shape of its own vendor: Yealink `<mac>.cfg`, Grandstream `cfg<mac>.xml`, Polycom `<mac>-phone.cfg`, Cisco SPA `spa<mac>.cfg` or snom `snom<mac>.xml` (§2.1). Polycom's `000000000000.cfg` and Cisco SPA's `spa<model>.cfg` are answered without adoption (§2.1).
* Any other request gets a `404`. That includes a phone whose MAC has never registered while the board was in Learn mode, when no window is open (§0.1).

So Option 66 alone does not bootstrap a phone the board has not seen, except through a zero-touch window (§3.1). It does remove the one manual step §1.3 describes (typing the URL into the phone's web UI) for phones that have already registered once. Set expectations with whoever is deploying this accordingly.

### 1.2 mDNS: advertised, but not a provisioning-discovery path

The SIP build advertises mDNS as follows (`SipServer.cpp:104-107`):

```c
mdns_hostname_set(POCKETDIAL_HOSTNAME);          // -> pocketdial.local
mdns_service_add(NULL, "_sip",  "_udp", port,     NULL, 0);
mdns_service_add(NULL, "_http", "_tcp", httpPort, NULL, 0);
```

The display build differs. It sets the literal hostname `pocketdial` and advertises only `_http` on port 80, with no `_sip` (`main/esp_main_display.cpp:976-979`).

Both `mdns_service_add()` calls in the SIP build pass `NULL, 0` for the TXT slot. There is **no `provurl` TXT
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

### 1.4 SIP Plug-and-Play (Issue #826): discovery shipped, answers limited to known phones

A factory-fresh phone with PnP on multicasts a `SUBSCRIBE` to `224.0.1.75:5060` with
`Event: ua-profile;profile-type="device";vendor=…;model=…;version=…` and its MAC in the
From user (`MAC%3a0004132E08B4`). A server answers `200 OK`, then a `NOTIFY` with
`Content-Type: application/url` whose body is the URL the phone stores and fetches. Unlike
Option 66 (§1.1), this needs no DHCP server change: only a socket.

**What ships:**

* `PnpProfile` (`src/SIP/PnpProfile.{hpp,cpp}`) parses the request and writes the 200 and
  the NOTIFY. Pure; host-tested (`tests/PnpProfile_test.cpp`).
* `PnpResponder` (`src/SIP/PnpResponder.{hpp,cpp}`) holds the policy and a 16-slot table
  of phones heard. `SipServer::pollPnp()` feeds it from the board's 1 s SIP loop: a
  non-blocking socket bound to the **group address** (never `0.0.0.0`, which could take
  the main SIP socket's unicast traffic in lwIP) and joined with `IP_ADD_MEMBERSHIP`.
  Replies go out through the main SIP socket. No task of its own; no allocation per
  datagram (`PnpResponder.DatagramPathAllocatesNothing`).
* **Mode**, persisted as NVS `pbxcfg`/`pnp_mode`, set with `POST /api/pnp`:

| Mode | Socket | Records phones | Answers |
| :--- | :--- | :--- | :--- |
| `off` (default) | closed | no | no |
| `discover` | open | yes | no |
| `provision` | open | yes | only a **snom or Yealink** whose MAC is **adopted** (§0.1) with an extension that passes the same AOR/identity gates as `findProvisioningInfo()`, or (zero-touch window open, §3.1) one that would be assigned an extension right now |

  Off by default because the first answer wins: an always-on responder would capture any
  PnP phone on a LAN shared with another PBX. A phone this board cannot serve gets
  silence, so another server can still answer it: a phone handed a URL that 404s stores
  it anyway and stops looking.
* Only sources on the board's own subnet are recorded or answered; the NOTIFY goes to the
  datagram's source address only; replies are token-bucketed (4, one back every 2 s); a
  phone gets at most one NOTIFY per 30 s, though a retransmitted SUBSCRIBE still gets its
  200 (same To tag, derived from the Call-ID).
* **URL handed out:** snom: `http://<ip>/config/snom<mac>.xml` (snom fetches it as given);
  Yealink: `http://<ip>/config/` (the phone appends its own `<mac>.cfg`). The MAC is
  lowercased, so it passes §0.2's shape check. Other vendors are listed but not answered.

Zero-touch assignment of an extension to a phone that has never registered (Issue #826 part B) is covered in §3.1. Without an open window, `provision` re-provisions known phones (factory-reset recovery), and `discover` shows what is on the network.

**Bench, 2026-10-02 on `.195` (Waveshare W5500), snom370 8.7.5.48 at `.155`:**

* **Board receive: works.** `/api/pnp` showed the group socket open (`listening`, no errno,
  netmask `255.255.255.0`), and datagrams sent to `224.0.1.75:5060` from another LAN host
  were counted. The W5500 blocks IPv4 multicast by default (`W5500_SMR_MAC_BLOCK_MCAST`),
  but lwIP's IGMP join reaches it through esp-netif's MAC-filter callback and unblocks it.
* **Answer path: works.** A replay of the snom's real SUBSCRIBE was parsed, listed and
  answered (200 + NOTIFY), and `/config/snom<mac>.xml` served the 1001 config.
* **The snom accepts the file.** Pointed at that URL, it logged `code: 200`, "found xml
  style settings" and "last prov successful:1"; line 1 stayed registered. It also asks for
  `<url-stem>-<MAC>.xml` (snom's per-MAC companion file) and a firmware page under the
  same directory; both 404 here, harmlessly.
* **What a snom actually sends** (its own SIP trace): source port **1053**, not 5060; a Via
  with `rport` and no `branch`; Request-URI host `lan`. Five SUBSCRIBEs 0.5 s apart, then
  it gives up and moves to its next setting server, so an answer must come within ~2.5 s.
  The 1 s poll fits, but not by much. `tests/PnpProfile_test.cpp` carries the capture.
* **Not yet seen end to end:** the snom's own multicast never reached the board on this
  LAN, though another host's did. Something on the path between the phone and the board
  (a switch with IGMP snooping, or a bridge) drops it. Check the network before blaming
  the board: `/api/pnp`'s `rx.datagrams` stays 0 when nothing arrives.

## 2. The endpoint

### 2.1 URL scheme

```
GET /config/{mac}.cfg            # Yealink key=value (or auto-dispatched by User-Agent)
GET /config/cfg{mac}.xml         # Grandstream XML
GET /config/{mac}-phone.cfg      # Polycom per-phone XML
GET /config/000000000000.cfg     # Polycom master/generic XML
GET /config/spa{mac}.cfg         # Cisco SPA macro-expanded flat-profile XML ($MA)
GET /config/spa{model}.cfg       # Cisco SPA model-keyed (Profile_Rule bootstrap)
GET /config/snom{mac}.xml        # snom XML (Issue #826); {mac} may be upper or lower case
```

`{mac}` is 12 **lowercase** hex digits, no separators (§0.2). The exception is snom, which accepts upper or lower case.

When requesting `{mac}.cfg`, `User-Agent` is used to detect the vendor (Grandstream, Polycom, Cisco SPA, snom, or Yealink fallback). When requesting a vendor-specific filename shape, that vendor's format is served directly.

### 2.2 Request handling

`sendProvisioningResponse(sock, req)` (`HttpServer.cpp:3522`) handles a request as follows:

1. The path is parsed by `parseProvisioningPath()` (`HttpServer.cpp:3432`). The Polycom master file (`000000000000.cfg`) returns `polycomBaseConfigFor()` directly, with no registry lookup. The Cisco SPA model-keyed shape (`spa<model>.cfg`) resolves the requesting host's MAC through ARP. If that gives a config, it is served. Otherwise the response is a `<Profile_Rule>` bootstrap, which is also a `200`.
2. For every MAC-keyed shape, `findProvisioningInfo(mac)` walks the adopted-device registry under the engine `_mutex` (`RequestsHandler.cpp:9670`). If there is no record, a zero-touch assignment (§3.1) may add one, and the lookup runs again. A miss is a `404`.
3. `findProvisioningInfo()` re-validates the adopted extension against `isValidAor()` as defence in depth. The config interpolates the extension into `key = value\r\n` lines, so a CR/LF in it would inject config lines nobody wrote (Issue #107). The same recheck refuses an adopted extension that is reserved, emergency or PSTN-shaped (`pbx::isReservedOrPstnAor()`, Issue #163). The REGISTER-time identity guard in `onRegister()` is not the only gate provisioning depends on. Either failure closes to a `404`.
4. The server IP is the board's active IP, or the primary local IP when `_ip` is `0.0.0.0`. The SIP port is hardcoded `5060`, because this codebase does not support a non-default SIP listen port. Grandstream, Polycom, Cisco SPA and snom paths each call their own renderer with the adopted extension. A Yealink path calls `renderProvisioningConfigForUserAgent()`, which picks a renderer from the User-Agent and falls back to Yealink (§2.5). An empty render is a `404`, never a `200` with an empty body.
5. `200 OK`. The content type is `text/plain` for Yealink and `application/xml` for the other vendors.

`authRequired` is true when the device has been promoted to `DeviceState::Secured`, or the registrar is in Secure mode (`RequestsHandler.cpp:9698`). In the Yealink file it changes only the comment block; see §2.4.

### 2.3 What the config forces

| Setting | Value | Why |
| :--- | :--- | :--- |
| SIP server / proxy | active board IP : `5060` | The registrar address. Port is not configurable. |
| Transport | UDP (`transport_type = 0`) | The engine only speaks UDP. |
| Extension (label / display / auth / user name) | the AOR this MAC was adopted as | Comes straight from the adopted-device record, which a later REGISTER for another AOR never changes (#820). |
| Auth password | **blank** | The server has no plaintext secret to hand out (§4). |
| Codec | PCMU (priority 1), PCMA (priority 2) | Two codecs are enabled and prioritized; the file does not disable others. |
| NAT | `nat.udp_update_enable = 0` | Media on ordinary calls is peer-to-peer on one L2 segment. |

The renderer's own comments still justify the codec choice by reference to `enforceG711()`. That function is **deprecated with no production callers**. The live behaviour is `filterAudioCodecs()`, which admits PCMU, PCMA and **G.722** on relayed peer-to-peer legs, and PCMU only on server-terminated ones (see [PHONE_COMPATIBILITY.md §1.2](PHONE_COMPATIBILITY.md)). The generated file is therefore *conservative*, not *required*: leaving G.722 enabled on the handset would also work for internal calls.

The file also does **not** set registration expiry (the registrar caps it to 3600 s regardless) or the `telephone-event` payload type. Those stay at the phone's defaults.

### 2.4 The actual response

**Request** (phone → pocket-dial, on boot / "Auto Provision Now"):

```http
GET /config/805ec079c37f.cfg HTTP/1.1
Host: 192.168.4.1
User-Agent: Yealink SIP-T46S 66.86.0.15
Accept: */*
Connection: close
```

Response: MAC `805ec079c37f` adopted as extension `1001`, registrar in Learn
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

`src/SIP/ProvisioningConfig.hpp` builds four vendor configs (`yealinkConfigFor()`, `grandstreamConfigFor()`, `polycomPhoneConfigFor()` / `polycomBaseConfigFor()`, and `ciscoSpaConfigFor()`), plus vendor detection and dispatch (`detectVendorFromUserAgent()`, `renderProvisioningConfigForUserAgent()`). All four are wired into the live HTTP server (`src/Helpers/HttpServer.cpp`) via Issue #234. The snom renderer, `snomConfigFor()`, is wired via Issue #826 (§1.4).

1. **User-Agent is captured** in `HttpServer::HttpRequest::userAgent` during `parseRequest()` and passed to `renderProvisioningConfigForUserAgent()` when `{mac}.cfg` is fetched.
2. **Path-shape check (`parseProvisioningPath`)** accepts:
   - Yealink/fallback: `/config/<mac>.cfg`
   - Grandstream: `/config/cfg<mac>.xml`
   - Polycom per-phone: `/config/<mac>-phone.cfg`
   - Polycom master: `/config/000000000000.cfg`
   - Cisco SPA macro: `/config/spa<mac>.cfg` (expanded `$MA`)
   - Cisco SPA model: `/config/spa<model>.cfg` (resolves via ARP if known, or serves `<Profile_Rule>` bootstrap redirect)
   - snom: `/config/snom<mac>.xml` (either case, Issue #826)
3. **Polycom master file** (`000000000000.cfg`) routes directly to `polycomBaseConfigFor()` before any device registry lookup.

**Renderer-by-renderer confidence** (all four share the CR/LF injection guard from Issue #107,
and the three XML ones additionally XML-escape the extension. That escaping is defence in depth,
not a fix for a reachable bug: the live route re-validates with `isValidAor()`, which admits only
alnum + `.-_+*#`, so `&` cannot reach a renderer today, but the renderers are pure functions with
no validation of their own, and a future less-filtered caller would otherwise emit malformed XML):

| Vendor | Structure | Field names |
| :--- | :--- | :--- |
| Yealink | N/A (plain text) | Long-stable, widely documented; **never tested against real hardware** (§2.4). |
| Grandstream | **Confirmed** against Grandstream's own [SIP Device Provisioning Guide](https://blog.grandstream.com/hubfs/Grandstream_Feb_2021/Pdf/gs_provisioning_guide_public.pdf) example (`<gs_provision version="1">` → `<mac>` → `<config version="1">` wrapping one `<PNNN>value</PNNN>` element per field, not a `"PNNN = value"` text-line shape). | P271/P270 confirmed against that same guide's example (numeric Active flag / string account name). P36 = SIP Authenticate ID and P34 = SIP Authenticate Password. Reversing these two would hand the phone the extension as its password and an empty auth ID. The rest (P34/P35/P36/P47/P57/P58) come from a secondary [Grandstream P-Codes reference](https://support.ispsupplies.com/portal/en/kb/articles/grandstream-p-codes-31-10-2019) that **actively disagrees** with other secondary sources found during this change on which P-number means what; P-value assignments are documented per device generation, not universally. Confirm against the target model's own P-Value guide before deploying. P47 folds in a non-default port as `ip:port` rather than using a separate port field. Grandstream's own SIP-Server field is documented as taking address *and* port together, and there is no reliably-sourced separate port P-number. |
| Polycom | Two-file scheme (`polycomBaseConfigFor()` / `polycomPhoneConfigFor()`) cross-confirmed against multiple independent third-party UC Software config examples. | `reg.1.address`/`label`/`displayName`/`auth.userId`/`auth.password`/`server.1.address` cross-confirmed the same way. `reg.1.server.1.port`, `reg.1.server.1.transport` and `voice.codecPref.G711_Mu`/`G711_A` are standard, widely-cited UC Software parameter names, not independently re-confirmed for this change. The base file's `<APPLICATION>` element/attributes are likewise standard-but-unconfirmed, and deliberately omits `APP_FILE_PATH` (pocket-dial hosts no Polycom firmware image; whether a phone tolerates that omission is a hardware question). |
| Cisco SPA / Linksys / Sipura | **Confirmed** against Cisco's own [SPA100/200-series Provisioning Guide](https://www.cisco.com/c/dam/en/us/td/docs/voice_ip_comm/csbpvga/spa100-200/provisioning/guide/SPA100-200_Provisioning.pdf): `<flat-profile>` root, trailing-underscore line-numbered tags (`Line_Enable_1_`, `Proxy_1_`, `User_ID_1_`, `Auth_ID_1_`, `Password_1_`), `G711u`/`G711a` codec value strings, and the `Proxy_1_` field folding address and port together (the guide's own worked example: `192.168.2.100:6060`). | `Use_Auth_ID_1_` is the standard field name from the same product family's admin-UI-derived naming convention, not independently re-confirmed in that specific guide. |

None of the four has been tested against a real handset of any vendor.

## 3. Extension assignment

An adopted MAC gets the extension it was adopted as. `admitLearn()` adopts `{mac, ext, Learned}` on first sight, and a later REGISTER under a different AOR never changes it (#820; see the re-sync bullet below). The only other way an extension is assigned is a zero-touch window (§3.1), which gives the next free extension in a range to an unknown MAC.

Consequences:

* **There is no way to pre-assign an extension to a MAC.** No admin endpoint accepts a
  MAC→extension pair (§0). To move a phone to a different extension, change it on the
  phone, **forget its row** by MAC (the **Forget** button on its row of the dashboard
  roster, or `POST /api/registrar/device` with `action=forget&target=<MAC>`), then let it
  re-register: it is adopted afresh on the new extension. The registry does not follow on
  its own; see the re-sync bullet below and [LEARN_MODE.md](LEARN_MODE.md) §6.
* The registry is bounded by `POCKETDIAL_MAX_CLIENTS` (32 by default), so a flood of distinct MACs cannot grow the heap without limit. When it is full, `admitLearn()` evicts an unlocked Learned row to admit a new MAC. It prefers an offline row and then the oldest, and an unclaimed zero-touch row (§3.1) goes first (`oldestEvictable()`, `Registrar.cpp:187`). It refuses with "Device Table Full" only when no row is evictable, that is, when every row is locked or Secured (`Registrar.cpp:476-486`). Because the registry is bounded by the *same* constant as the client pool, the original design's "you can pre-map 50 phones against a 32-slot pool" scenario does not arise here.
* **Reserved and emergency extensions** (`777`, `999`, `440`, `555`, `888`, `911`, `933`, `796` and `997`, and any emergency dial code) are refused outright by `onRegister()`'s identity guard (`pbx::isReservedOrPstnAor()`, Issue #163, `PbxConfig.hpp:322`) with a `403`. The guard runs before the registrar-mode branch, so Learn and Secure refuse these names identically, and the registry never adopts one of them in any mode. An AOR that is `+`-prefixed (E.164) or otherwise looks like a direct-dial PSTN number (long, all-digit, `POCKETDIAL_MIN_PSTN_AOR_DIGITS`, `PoolConfig.hpp`) is refused the same way. The park-orbit (`700`-`709`) and page-zone (`980`-`989`) *ranges* are a separate mechanism (dial-plan routing intercepts those) and are unaffected by this guard. Do not assign any of the above.
* **No re-sync branch (#820).** A MAC already adopted under one extension that REGISTERs under a different AOR keeps its stored extension. The other AOR is admitted as TOFU, and an unlocked MAC is marked shared. A REGISTER never rewrites the stored extension, so a REGISTER with a phone's source IP forged cannot change the extension this endpoint serves to that phone. A phone moved to another extension by hand, without its row being forgotten, gets its old extension back from its `.cfg`, and it holds no claim on the new one: another device that registers the new extension twice, at least 30 s apart, locks it, and the phone then gets `403` there. desmo accepted this residual on 2026-10-04 (#852). **Forget the phone's row when you move it** (above). The roster's State column and `GET /api/registrar` show that row as `shared` (it was unlocked) or `locked` (#882).
* **`forget` re-arms adoption.** `POST /api/registrar/device` with `action=forget` removes the record (`Registrar::forget()`, `Registrar.cpp:698`). A later REGISTER in Learn mode re-learns it.

### 3.1 Zero-touch assignment (Issue #826 part B)

An admin opens a window with `POST /api/zero-touch` (`open=1&lo=2001&hi=2099&minutes=30`).
While it is open, a config fetch for an **unknown** MAC is handed the next free extension in
the range, and the phone registers as it. Everything else on this page is unchanged: a known
MAC still gets the extension it last registered as.

**Who gets one.** A fetch on any MAC-keyed path (`<mac>.cfg`, `cfg<mac>.xml`,
`<mac>-phone.cfg`, `spa<mac>.cfg`, `snom<mac>.xml`) assigns only when **all** of these hold:

* the window is open (it closes itself after `minutes`, 1-120; a reboot closes it too, since
  it is never persisted);
* the registrar is in **Learn** mode (Secure needs a password the board cannot provision, §4.1);
* the TCP peer's **ARP entry is the requested MAC**, so a fetch can only claim the fetching
  host's own MAC (an ARP miss refuses);
* the #515 adoption token bucket has a token (4, one back every 15 s, shared with Learn);
* fewer than **4 unclaimed** rows exist, and the table has room or an evictable row;
* a free extension exists in `lo`-`hi`.

Every refusal is the same `404` as an unknown MAC (§4.3). `GET /api/zero-touch` says why
instead: `free` (extensions assignable right now; a dial-plan pattern that swallows the range
shows as 0), `lastRefusal` and `refusals`. PnP's `provision` mode (§1.4)
answers an unknown MAC only when the same checks pass at that moment, so a phone is never
pointed at a URL that 404s.

**Which extension.** The lowest number in the range that no device row holds, nothing is
registered as, and nothing routes elsewhere: reserved, emergency and PSTN-shaped numbers, page
zones (980-989), park orbits (700-709), ring-group pilots, and anything the dial plan matches
(`RequestsHandler::isRoutedElsewhere()`); and nothing that already **belongs to someone**:
voicemail or DND on, a forward set, a DID mapped to it, or a stored SIP secret
(`hasExtensionState()`). `lo` and `hi` are 3-6 digits, no leading zero,
`lo <= hi`, fewer than 500 apart.

**The row.** An assignment is an ordinary Learned row, created **locked**, so another MAC
registering that extension is refused (`Extension Locked To Another Device`), and
**assigned** (unclaimed) until its MAC first registers. An unclaimed row is evicted before
any other row, so unauthenticated fetches can never fill the table with rows nothing may
evict. The cap counts only rows from the **current** window, and opening a new window drops
every row an earlier one left unclaimed: phones that fetched and never registered cannot hold
zero-touch shut. (A late one is not lost: its extension is free again, so its REGISTER is
adopted by ordinary Learn.) A row is claimed only when its phone registers **that**
extension. The same MAC always gets the same extension. `/api/registrar` shows
`"assigned": true` until the phone registers. "Forget learned" clears unclaimed rows too.
The flag is bit 2 of the persisted row flags; firmware older than #826 reads it as a plain
locked row.

**Not allocation-free.** An assignment adds a map node and rewrites the NVS device blob, like
any Learn adoption. It happens once per phone, on the HTTP task.

## 4. Security: what the config actually exposes

The original design was written around the assumption that the provisioning file carries a
live SIP password in cleartext, and built four layers of control around that assumption. **The
shipped file carries no password**, which changes the threat entirely.

### 4.1 Why there is no password in the file

`Registrar`/`SipSecretStore` only ever store **HA1 = MD5(ext:realm:secret)**, a one-way hash. The server never holds the plaintext secret, so it has nothing to provision with even when one is required. `yealinkConfigFor()` therefore always emits `account.1.password = ` (blank) and, when the device needs a password, emits a comment telling the admin to type it in by hand (`ProvisioningConfig.hpp:101-108`, `:129-131`, `:138`).

This is the right trade: it means an auto-provisioning fetch is **not** a credential disclosure. The per-MAC URL token and HTTP Basic on the fetch were not built, and they are not load-bearing. The timed window (§3.1) is not a credential control either. It only limits which unknown MACs can be given an extension.

### 4.2 What an unauthorized fetch does disclose

Not nothing. A successful fetch tells the requester:

* that this MAC is an adopted device on this board,
* which extension it is. That is useful for targeting an INVITE, or for registering as that extension yourself. Under Learn, an extension is locked only from its phone's next registration at least 30 s after its first (#440, #515). The lock is checked against the ARP entry for the REGISTER's source address, so spoofing the phone's MAC or its source IP on the same LAN passes it. A Secured extension also needs its SIP password.
* the board's active IP and SIP port,
* whether that extension requires digest auth (the comment block is a one-bit oracle for
  "this device is Secured / the registrar is in Secure mode").

### 4.3 The controls that actually exist

1. **Adopted-MAC allowlist.** No record ⇒ `404`, with one exception. While a zero-touch window is open (§3.1), a fetch for an unknown MAC is assigned an extension only if the requesting host's ARP entry is that MAC and fewer than four unclaimed rows exist. Outside a window, the attack surface is exactly the set of MACs that have registered in Learn mode. During a window it also includes the fetching host's own MAC.
2. The MAC is the only credential, and it is a 2^48 space: not guessable, but also not secret: anyone on the same L2 segment can read it off the wire. A remote prober learns nothing by guessing. A local sniffer does.
3. **Uniform `404`.** Bad MAC shape, unknown MAC, bad AOR and a refused render all return the same `404` with no body distinction (`sendProvisioningResponse()`, `HttpServer.cpp:3522`).
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

Auto-provisioning configures a phone. It does not authenticate one, and on a default (Learn)
board nothing authenticates its first REGISTER. Do not describe it as a security control.

## 5. Sequence: boot → fetch cfg → REGISTER → call

The sequence for a Yealink phone, from boot to a call:

```mermaid
sequenceDiagram
    participant P as Yealink phone
    participant B as pocket-dial ESP32-S3
    Note over P,B: SoftAP or Ethernet, HTTP on port 80, SIP on 5060 UDP
    Note over P,B: (0) Manual bring-up. The installer types the SIP account into the phone's web UI by hand, and the board is switched to Learn mode. Without this, step 3 is a 404 forever (§0.1).
    P->>B: (1) Associate and link up
    P->>B: (2) DHCP DISCOVER, OFFER and ACK (standard options only, no Option 66)
    P->>B: (3) REGISTER sip:1001@...:5060
    Note right of B: admitLearn() maps the source IP to a MAC through ARP. On a first-packet ARP miss it accepts and adopts nothing, so the next REGISTER adopts. It adopts (mac, 1001, Learned) to NVS.
    B-->>P: 200 OK (expires at most 3600)
    B->>P: Register beep INVITE (signalling only, no server RTP)
    P->>B: (4) GET /config/mac.cfg (URL typed by the installer)
    Note right of B: Shape check: /config/ + 12 lowercase hex + .cfg, else 404. findProvisioningInfo(mac) in the adopted-device registry, else 404. isValidAor(ext) plus the reserved, emergency and PSTN-shaped re-check, else 404.
    B-->>P: 200 OK, text/plain, account.1 settings, password field blank
    Note over P: (5) Phone applies the config, may reboot once, and re-registers.
    loop Every 5 s
        P->>B: OPTIONS keepalive
        B-->>P: 200 OK
    end
    Note over P,B: The board prunes the phone after 15 s quiet.
    P->>B: (6) INVITE sip:1002@...
    Note right of B: onInvite() relays the call peer to peer. filterAudioCodecs(allowWideband=true) narrows the codec list only. The c= line is never rewritten.
    B-->>P: 180 (relayed as-is), 200 + SDP
    P->>B: (7) ACK
    Note over P,B: (8) RTP audio flows phone to phone, not via the board
    P->>B: (9) BYE
    B-->>P: 200 OK
```

## 6. Original design, not implemented

The items below were specified in the Phase-1 design and were **never built**. They are kept because the analysis is still sound and anyone extending provisioning would otherwise re-derive it. Nothing in this section describes current behaviour.

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

The exact filenames above are illustrative, not what a real phone requests. The filenames that ship are listed in §2.1 (`cfg<mac>.xml`, `<mac>-phone.cfg`, `000000000000.cfg`, `spa<model>.cfg`, `snom<mac>.xml`). The timed window that shipped is `POST /api/zero-touch` (§3.1), not `/api/provision/window`.

### 6.2 Storage that does not exist

An NVS namespace `prov` with per-MAC keys `e_<mac8>` / `s_<mac8>` / `t_<mac8>` / `v_<mac8>`
plus globals `auto_assign`, `range_lo`, `range_hi`, `next_ext`, `window_until`, `count`,
`basic_user`, `basic_pass`.

The load-bearing constraint behind that layout is still true and worth keeping: **NVS keys are
capped at 15 characters**, so a full 12-hex MAC plus a prefix is tight. The shipped code
sidesteps it entirely by serializing the whole device table into one `pbxcfg`/`devices` blob
(`Registrar::persistDevices()`).

### 6.3 Mechanisms that were designed and dropped

The timed window and sequential auto-assign from the original design shipped in a different form. See §3.1. The mechanisms below were dropped.

* **Per-MAC URL token** (`/provision/{mac}-{token}.cfg`) to defeat URL enumeration.
* **HTTP Basic on the fetch URL** (`http://user:pass@host/...`), rejected for MVP, never added as an opt-in either.
* **Per-MAC secret generation and storage.** The shipped design stores HA1 only (§4.1).
* **mDNS TXT `provurl` hint.** One line, never added (§1.2).
* **SoftAP client isolation** as a provisioning control. The caveat that killed it still
  applies and is worth remembering: **peer-to-peer RTP between phones requires
  station-to-station traffic**, so blanket client isolation would break ordinary calls.

### 6.4 Stale cross-references in the original design

* It described the codec lock in terms of `SipMessage::enforceG711()` rewriting every answer
  to `0 8 101`. That function is deprecated with no production callers; see §2.3.
* It described the registrar as gated by a compile-time `POCKETDIAL_OPEN_REGISTRAR` mode and a future "SEC-04 SIP-auth work". SIP digest auth **shipped**. The mode is a **runtime** setting (`reg_mode` in NVS, `POST /api/registrar`), chosen at boot by `Registrar::chooseBootMode()` when none is stored. The `POCKETDIAL_OPEN_REGISTRAR` #define is gone (see the header comment in `RequestsHandler.hpp`).
* It said `RequestsHandler`'s constructor hardcoded `32` and `8` instead of using the `POCKETDIAL_MAX_CLIENTS` and `POCKETDIAL_MAX_SESSIONS` macros. The macros are in use now. `Registrar` bounds its own device table with `POCKETDIAL_MAX_CLIENTS` (`Registrar.cpp:476`). Check `PoolConfig.hpp` and [SCALING.md](SCALING.md) for the current caps.

Related: [PHONE_COMPATIBILITY.md](PHONE_COMPATIBILITY.md) · [LEARN_MODE.md](LEARN_MODE.md) ·
[THREAT_MODEL.md](THREAT_MODEL.md) · [API.md](API.md) · [SCALING.md](SCALING.md)
