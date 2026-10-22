# pocket-dial vs 3CX Pi SBC: gap matrix

Purpose: show what a pocket-dial fork would still need for 1:1 parity with the 3CX SBC (Pi build).

## Read this first

- pocket-dial "SBC mode" is **not** an SBC. It is a toggle plus a route slot. A dial-plan miss on a number with no local registration becomes a synthetic `*` to Trunk rule at call time (CallForker.cpp:395-423, PbxFeatureConfig.hpp:133-156 [host]). "Trunk" is the SIP trunk if one is configured, otherwise the 3CX anchor (RequestsHandler.cpp:13247-13273).
- The board talks to 3CX through the **Call Control API** (HTTPS plus WebSocket, OAuth2 client credentials), not through the 3CX SBC tunnel. 3CX sees one source DN, not one registration per phone.
- All pocket-dial cites are origin/main `de61ba14`. Evidence tags: [hw] seen on hardware, [host] host tests only, [unv] code reading or unverified.
- **SBC mode has no recorded bench verification.** The repo evidence is host tests (tests/DialPlan_test.cpp:1009-1214). The one hardware result for the anchor is a Yealink T29 completing an outbound PSTN call with two-way audio on a bench board (CHANGELOG.md:884-886, 1031-1034).
- Status values:
  - **parity**: same or better user-visible behaviour, with at least host-test evidence.
  - **partial**: some of it exists, or it exists by a different mechanism.
  - **missing**: not built, as far as the pocket-dial report shows. A note starting "(not grepped)" means the status rests on the report not mentioning the feature; origin/main was not searched. Those rows are also listed under open questions and are left out of the "does not do" copy.
  - **blocked**: needs the 3CX tunnel protocol or another 3CX-private interface. Nothing more is said about it here, and no route around it is proposed.
- Table A lists pocket-dial gaps that are not on the 3CX feature list but follow from it, so they have no 3CX citation.

Source codes are those of the 3CX report: D1 `3cx.com/docs/3cx-tunnel-session-border-controller/`, D2 Pi install guide, D3 SBC HA cluster, D4 firewall configuration, D5 IP phones, D6 recommended hardware, R1 V20 change log, B1-B7 3CX blog posts, T2-T15 community threads. Full URLs are in the first report. Community threads are partner or user posts unless noted.

## Matrix (one row per 3CX SBC feature)

| # | 3CX SBC behaviour (citation) | pocket-dial today (file:line) | Status | Note |
|---|---|---|---|---|
| **Connectivity** | | | | |
| 1 | Software service on the local network, including RFC 1918 LANs, that connects IP phones to a cloud or remote 3CX [D1, D2]. | A firmware appliance on the LAN. Phones register to the board and the board calls 3CX through the Call Control API (RequestsHandler.cpp:575-579; TelephonyAnchorClient.cpp:1104) [host]. | partial | Same place in the network, different mechanism. The board is a small local phone system with an uplink. |
| 2 | Combines all SIP signalling and RTP from one site and delivers it to 3CX through the tunnel on port 5090, UDP and TCP [D1, D4]. | No tunnel. Toward 3CX it uses HTTPS REST plus a WebSocket for events and chunked HTTPS POST/GET for PCM audio (TelephonyAnchorClient.cpp:1359-1377, 3821-3852) [host]. | blocked | Needs the 3CX tunnel protocol, which is a 3CX-private interface. |
| 3 | PBX HTTPS port (443, 5001 or custom) open for presence and provisioning [D4]. | HTTPS to the configured `baseUrl` for token, Call Control and stream calls (TelephonyAnchorLogic.hpp:297-299) [host]. No presence or provisioning traffic to 3CX. | partial | The HTTPS dependency is the same. The presence and provisioning use is absent (see rows 14 and 20). |
| 4 | Outbound only: no port forwarding at the SBC site if outbound is not blocked [T4, T5, T6; partner posts]. | Every 3CX flow is board-initiated outbound TLS (ADR-002:64, 102) [unv]. | partial | Nothing was tested through CGNAT. NAT keepalives and hole-punching are unconfirmed on the 3CX side and unmeasured here. |
| 5 | Local SIP endpoints reach the SBC on UDP 5060 by default [T2, partner]. | SIP over plain UDP (ARCHITECTURE.md:322-326). The default port is not stated in the report. | partial | Transport matches. Port to be confirmed. |
| 6 | SBC-to-PBX link is encrypted; Options > Security lets you choose TLS or TCP [T7, Community Manager and a user]. | Toward 3CX: TLS (HTTPS and WSS). Toward phones: SIP is plain UDP, no TLS signalling, no SRTP (THREAT_MODEL.md:349) [unv]. | partial | The uplink is encrypted. The LAN side is not. No TLS-or-TCP choice exists. |
| 7 | SBC updated to the latest TLS suite in 2020 [B4]. V16 needed a valid non-self-signed PBX certificate [B1]; V20 applicability unconfirmed. | Certificates are checked against the IDF CA bundle only. No custom CA or pin option, so a private-CA 3CX would not verify (TelephonyAnchorClient.cpp:1382, 2527). | partial | Public-CA 3CX works. A 3CX with a private CA does not. |
| 8 | Docs recommend disabling SIP ALG; the 3CX Firewall Checker verifies the setup [D4]. | Nothing in the report. | missing | (not grepped) Likely a documentation item only. |
| 9 | Tunnel is "up 24x7 unless there's a connection drop at either end" [T8, MVP]. Reconnect timing and backoff unconfirmed. | WS ping 20 s, pong timeout 20 s, auto-reconnect every 5 s (TelephonyAnchorClient.cpp:1392-1396). Any WS disconnect tears down every live outside call (:3318-3324) [host]. Token refresh runs 10 min before expiry (:2112-2128). | partial | Reconnect exists. Live calls do not survive a flap. 3CX behaviour on a drop is unconfirmed. |
| 10 | Auto-restart on service failure; the SBC waits for an IP address before initialising [B1, B2]. | `start()` runs only at boot and in the stale-token restart job (RequestsHandler.cpp:610, 635, 650; TelephonyAnchorClient.cpp:2506). A failed `start()` leaves the anchor dead; the "will retry" log at :2508 has nothing behind it. No anchor-offline reboot found [unv]. | missing | From code reading, not reproduced: if 3CX is down at boot, the anchor may stay down until reboot. Wait-for-IP behaviour is not in the report. |
| 11 | QoS implemented on the SBC in V20 builds [B7, T9]. | Nothing in the report. | missing | (not grepped) |
| 12 | Failover to an alternate PBX address: unconfirmed, a user asked and got no staff answer [T10]. | Four telephony slots, one active. No failover between them (FEATURE_ROADMAP.md:195). A slot change needs a reboot (RequestsHandler.cpp:10101-10107). | missing | 3CX side unconfirmed, so this may not be a parity gap. |
| 13 | HA cluster: two same-OS Debian/Raspbian nodes, floating LAN IP, active-passive on crmsh/Pacemaker; optional Ping Resource with up to three targets; failover notifications; active calls lost on failover; not available for Windows [D3, B4, T10]. | Single board. No clustering or second-board failover in the report. | missing | (not grepped) origin/main was not searched for clustering. Notifications are covered in row 30. |
| **Phone handling** | | | | |
| 14 | Phones are provisioned by choosing the SBC as the connection option when adding the phone in the PBX [D2, D5]. | Phones are provisioned by the board itself: `GET /config/<mac>.cfg` for MACs already adopted or inside a timed zero-touch window (RequestsHandler.cpp:9670; PROVISIONING.md:368-391). | partial | The local equivalent exists. The PBX-side "connection option = SBC" step does not. |
| 15 | PnP: the phone broadcasts, 3CX lists it under PnP Phones, you assign an extension [D5]. | Multicast `224.0.1.75` SUBSCRIBE with a NOTIFY URL, modes off/discover/provision, snom and Yealink only, off by default (SipServer.cpp:244; PROVISIONING.md:159-190). | partial | On the `.195` bench the board answered and a snom accepted the file, but the phone's own multicast never reached the board [hw]. |
| 16 | RPS (vendor redirect) and DHCP option 66 are other provisioning methods; whether they pass through the SBC is unconfirmed [D5]. | DHCP option 66/43 is not implemented; use your own DHCP server (PROVISIONING.md:55, 109). RPS is not mentioned. | missing | 3CX pass-through unconfirmed. |
| 17 | Manual phones use the SBC IP and port as SIP server plus an auth ID and password [D5]. | Phones register to the board; default registrar mode is Learn (trust on first use, keyed on MAC from ARP) (Registrar.cpp:43, 360; LEARN_MODE.md:31, 41-69) [host]. The file carries no password (PROVISIONING.md:417-429). | partial | Secure mode is not deployable: nothing in `src/` calls `SipSecretStore::setSecret` or `generateSecret`, and secrets arrive only via owner-gated config import (LEARN_MODE.md:121-128). Learn locks only Secured rows and is same-L2 only. |
| 18 | Phones register to the PBX, not locally; internal calls need the PBX [T11, staff; T12]. | Phones register to the board. There is no upstream SIP registration of phones (Registrar.cpp:43). 3CX sees one source DN (TelephonyAnchorClient.cpp:387-399). | missing | Whether per-phone registration to 3CX is possible without the tunnel is not established by either report, so this is not claimed as blocked. See open questions. |
| 19 | Phone behind an SBC uses HTTPS and the FQDN; a local phone uses HTTP and the local IP [T2, staff, 2019]. | HTTP is plaintext on the LAN. No FQDN or HTTPS provisioning for remote phones in the report (ARCHITECTURE.md:238-239). Learn is same-L2 only (LEARN_MODE.md:48-50). | missing | A remote-site phone cannot be adopted or locked. |
| 20 | BLF at 10 per device [D6]; presence over the PBX HTTPS port [D4]. | 16 BLF subscriptions in total on the full build (constrained value not given in the report), local only (PoolConfig.hpp). 3CX phone-state sync (BLF, MWI, status) is not built. | missing | At 32 phones, 16 total is well under 10 per phone. |
| 21 | Phone families are not listed for dedicated SBCs; per-vendor support unconfirmed [D5]. | Renderers for Yealink, Grandstream, Polycom, Cisco SPA and snom (HttpServer.cpp:1134, 3432, 3522). Only snom is confirmed on a handset (2026-10-02) [hw]. A Yealink T29 completed an outbound anchor call [hw]. | partial | One handset model of evidence (CHANGELOG.md:361-364). |
| 22 | Router phones (SBC built into Fanvil, Snom or Yealink models); keep to 2-3 phones behind one [D1, D5, T8]. | No such concept. | missing | The fork is a separate appliance, not phone firmware. |
| 23 | Local phones call each other directly (stated for router phones only; unconfirmed for the dedicated SBC) [D5]. | Extension-to-extension media is peer-to-peer RTP; the board never carries it (SCALING.md:22-25) [host]. | partial | 3CX side unconfirmed, so parity cannot be asserted. |
| 24 | Capacity: up to 50 or up to 100 devices per x86 host at 10 BLFs each; a 2019 test ran 40 phones on a Pi 3B+ [D6, B3]. | Full build: 32 registered clients, 8 call sessions, 4 anchor calls. Constrained: 8, 4, 1 (PoolConfig.hpp:292-293; main/CMakeLists.txt:279-295). The anchor limit is TLS handshake cost, not RAM (TelephonyAnchorClient.hpp:60-68). | partial | 32 clients is about two-thirds of the smaller 3CX tier (50), and 4 anchor calls is the binding limit. Constrained build has no conference, no multicast paging, no MWI. |
| **Survivability** | | | | |
| 25 | No local calling when the PBX is unreachable: the SBC unregisters and the phones go with it [T11, staff 2023; T14, Nick Galea 2023]. | Extension-to-extension, intercom, paging, local voicemail and hold music need no 3CX (ADR-002:108) [host]. | parity | Better than 3CX here. Outside calls still need 3CX. |
| **Management** | | | | |
| 26 | Add the SBC in the PBX (Voice & Chat > + Add SBC), pick the machine type, get a Provisioning URL and Authentication Key ID, enter both on the host [D1, D2]. | Operator enters baseUrl, clientId, secret and routeDn into one of four slots through the dashboard or `/api/telephony-config` (HttpServer.cpp:1394-1434; TelephonyApiConfig.hpp:20-31, 78-90). | blocked | The PBX-side Add SBC flow and its key are 3CX-private. The local slot form exists. |
| 27 | One-line installer on the Pi (`3cxsbc.zip` script) [D2]. | Firmware image with dual-slot OTA and bootloader rollback (OTA.md:1-20). | partial | Different delivery model. |
| 28 | SBC editor with settings and push configuration (V20 Update 7 Alpha); SBC version shown in editor; warning on department change [R1]. | Dial Plan modal holds the SBC toggle and route dropdown (index_html.h:445-459, 1220-1230) [unv: no browser test]. `GET/PUT /api/sbc-mode` is admin plus CSRF (HttpServer.cpp:1451-1467, 4244-4303). | blocked | Push config from the PBX console is 3CX-private. Local editing exists. The `route` parameter only calls `setActiveSlot()`; the outbound path never reads it. |
| 29 | Remote SBC update and reconfiguration from the PBX console [B1; D3 Admin Console > System > Updates]. | OTA is pushed to the board, not pulled from the PBX: `POST /api/ota/upload` (owner), `/api/ota/status`, `/api/ota/reboot` (HttpServer.cpp:923-936, 1717-1727). Proved once on `.244`, 2026-09-26 [hw]. Images are unsigned (OTA.md:8-11). | blocked | Console-driven update needs the 3CX management channel. |
| 30 | Per-SBC status, system and connection stats, and email notifications to the console; drops under 1 minute send nothing in Update 5 [B1, T9; D3 for HA failover notifications]. | Nothing reaches the 3CX console. The on-site notifier exists for the 911 case only (RequestsHandler.cpp:4780-4870). | blocked | Console visibility and 3CX email alerts are 3CX-private. |
| 31 | Local status, stats and logs; logs carry timestamps; verbose logging costs performance; tunnel log is in the support bundle [B2, B3, T15]. | `/api/status`, `/metrics`, `/api/syslog` (RFC 5424 over UDP), `/api/cdr`, `/api/trace`, `/api/pcap`, `/api/coredump` (HttpServer.cpp:1136-1349; Syslog.hpp:4). Status reports `emergencyRoute` (HttpServer.cpp:2482-2490). | partial | Broad local surface. Whether status shows live anchor connection state is unconfirmed. |
| 32 | Service control: `3cxsbc status`; a running process does not mean the tunnel is up. Start/stop/restart commands unconfirmed [T15]. | `/api/ota/reboot` and `/api/status`. | partial | The "process up, uplink dead" case is what row 10 describes. |
| 33 | Update cadence: weekly check, 3 AM restart removed; HA nodes reboot one at a time [B2, D3]. | Manual OTA only in the report. | missing | (not grepped) Standalone V20 update behaviour is unconfirmed on the 3CX side. |
| **Security** | | | | |
| 34 | SBC authenticates with Authentication Key ID plus Provisioning URL; HA nodes share the key; rotation unconfirmed [D1, D2, D3]. | OAuth2 client credentials, `POST {base}/connect/token`; token refresh 10 min before expiry (TelephonyAnchorClient.cpp:2112-2128). Secret is plaintext in NVS namespace `tapicfg` unless flash encryption is on (TelephonyApiConfig.hpp:20-24). | partial | Authenticates, but by a different credential, stored in the clear by default. |
| 35 | ACL and firewall rules limiting the 3CX host to sensitive subnets are the administrator's job [D4]. | No CIDR allowlist: `_allowNet` is inert (ARCHITECTURE.md:329). Rate limit 40-packet burst, 20 pps per source, 256 buckets (ARCHITECTURE.md:322-326). | partial | Same responsibility on the admin, but the fork cannot enforce a source allowlist itself. |
| **Hardware** | | | | |
| 36 | Platforms: Raspberry Pi 5 (4 or 8 GB), Windows 10 / Server 2016+, Debian ISO. Static IP, 24/7, wired Ethernet only on the Pi [D1, D2]. | ESP32-S3 W5500 Ethernet (LilyGO T-ETH-ELITE S3, Waveshare ESP32-S3-ETH), JC3248W535 display, Wi-Fi, and a classic ESP32 LAN8720 constrained build (HARDWARE.md:5-21; main/CMakeLists.txt:1-7, 31-37). | missing | No Pi, Windows or Debian build. The constrained build is anchor-only, 4 MB, and refuses `SIP_OUTSIDE_LINE=trunk` (main/CMakeLists.txt:337-352). |

### Table A: pocket-dial gaps that follow from the above (not on the 3CX feature list, so no 3CX citation)

| # | Why it matters | pocket-dial today (file:line) | Status | Note |
|---|---|---|---|---|
| A1 | Media from phones reaches 3CX. | The board terminates the handset RTP and is the SDP endpoint (RequestsHandler.cpp:529, 6224). PCMU only on these legs; PCMA and G.722 get 488 (:5162-5178). | partial | The media GET stream was unproven on a live tenant in the rc.1 list (CHANGELOG.md:361, #518). Later fixes exist (#932). |
| A2 | Handset DTMF during an outside call (menus, PINs). | No path found. The anchor interface has no send-DTMF and the 3CX API has no such verb (AnchorClient.hpp:49-95; docs/3cxAPI+Webhooks.md:19-28) [unv]. | missing | No grep path found; not tested on a call. |
| A3 | Each phone has its own caller ID and DID. | Outbound `makecall` carries only the destination (TelephonyAnchorClient.cpp:387-399). Inbound is one route DN, one call at a time (RequestsHandler.cpp:5848-5856), one DID literal (:5865-5870). With no mapping it rings every extension (:5886-5895). | missing | No per-extension caller ID, no per-extension DID. |
| A4 | Emergency calls. | 911/933 route only through the 3CX anchor. With it down: `503 Emergency Call Not Routable` plus an on-site notifier "NOT ROUTED" (RequestsHandler.cpp:4780-4870, 13100-13103; CHANGELOG.md:350-352) [host]. No fallback, by operator decision. | missing | 911 does not survive 3CX loss. An unmatched outside number with the anchor down gets 404 (CallForker.cpp:474-499) [host]. |
| A5 | Inbound PSTN while 3CX is down. | Nothing arrives; there is no local ring and no cache (WS event source only). | missing | No mitigation in the fork. |

## Tally

36 matrix rows plus 5 in Table A.

- Matrix: parity 1 (row 25); partial 18 (rows 1, 3, 4, 5, 6, 7, 9, 14, 15, 17, 21, 23, 24, 27, 31, 32, 34, 35); missing 12 (rows 8, 10, 11, 12, 13, 16, 18, 19, 20, 22, 33, 36); blocked 5 (rows 2, 26, 28, 29, 30). 1 + 18 + 12 + 5 = 36.
- Table A: partial 1 (A1); missing 4 (A2, A3, A4, A5).

## What the fork can promise now (parity rows only)

Only one row qualifies, and it is host-tested, not bench-tested.

- With the 3CX uplink down, phones on the same board can still call each other, use intercom, paging, local voicemail and hold music, because none of those need 3CX (row 25, ADR-002:108 [host]). The 3CX SBC does not offer local calling in an outage.

Nothing else should be promised as "same as the 3CX SBC". SBC mode itself has no recorded bench verification.

## What the profile should say it does not do

Suggested UI copy. It covers confirmed missing and blocked rows and Table A. Lines resting on code reading or untested paths say so. Rows marked "(not grepped)" are left out.

- This is not a 3CX SBC. The board is a small local phone system that places and receives outside calls through the 3CX Call Control API. It does not use the 3CX SBC tunnel.
- Phones register to this board, not to 3CX. 3CX sees one calling identity, not each phone. There is no per-phone caller ID or per-phone DID, and inbound calls arrive on one number, one at a time.
- Outside calls and emergency calls need 3CX. If the uplink is down, outside calls fail. **911 and 933 cannot be placed**; the phone gets "Emergency Call Not Routable" and the on-site notifier fires. Do not rely on this device alone for emergency calling.
- Outside calls use G.711 u-law (PCMU) only. Digits pressed during an outside call (menus, PINs) are not known to reach 3CX; this has not been tested.
- Live outside calls end if the 3CX connection drops. Recovery after a failed start has not been shown and may need a reboot; this comes from code reading and has not been reproduced.
- It cannot be added, updated, monitored or alerted from the 3CX admin console. Updates are uploaded to the board by hand. Nothing appears in 3CX status or email notifications.
- No 3CX BLF, presence or message-waiting sync. Local BLF is limited to 16 subscriptions.
- No failover between 3CX addresses.
- Capacity is 32 phones and 4 simultaneous 3CX calls (8 phones and 1 call on the constrained build). It runs only on the listed ESP32 boards.
- Phones on other subnets cannot be adopted or locked. Provisioning is plain HTTP on the LAN. DHCP option 66 is not supported.
- Phone-side SIP is unencrypted UDP with no SRTP, and there is no source allowlist. A 3CX behind a private CA will not verify.
- Per-phone secrets cannot yet be generated on the device, so Secure registration is not deployable today.
- Only one handset model (Yealink T29) is confirmed on an outside call, and only snom has accepted a provisioning file on hardware.

## Open questions

3CX side (unconfirmed in the first report)

1. Is the 5090 tunnel TCP or UDP, and what exactly is multiplexed over it? [D1, B6, T7]
2. NAT keepalives and hole-punching behaviour; reconnect timing and backoff [T8].
3. Failover to an alternate PBX address [T10].
4. Do RPS and DHCP option 66 pass through the SBC? [D5]
5. Which phone families are supported on the dedicated SBC? Does the dedicated SBC (not only router phones) allow direct local phone-to-phone calls? [D5]
6. Are 50 and 100 devices hard caps? [D6, T13]
7. V20 menu names for SBC status and monitoring; SBC log path and level names; QoS details [B1, B7, T9].
8. Standalone V20 update behaviour; start, stop and restart commands [B2, D3, T15].
9. Does the valid non-self-signed PBX certificate requirement still hold in V20? [B1]
10. Key or password rotation, any tunnel password, and current Pi 3 and Pi 4 support [D1, D2, B7].
11. Conflict in T2 on whether a local phone and an SBC phone share the same configuration.
12. Can a phone register to 3CX per-extension without the tunnel? Neither report says. Decides whether row 18 stays missing or becomes blocked.

pocket-dial side

13. Does `start()` really never retry after a failed start (TelephonyAnchorClient.cpp:196-203, 246-282, 2506-2508), and does any path carry handset DTMF to 3CX? Both are code reading, not reproduced or tested.
14. Does the board work through CGNAT? Nothing tested.
15. SBC mode bench status. The repo has host tests only. A memory note says `.244` ran SBC mode "registered to 3CX" on 2026-09-30, but the anchor does not register by SIP, so it is unknown whether that run used the anchor or a generic SIP trunk. The dashboard toggle also has no browser test cited (index_html.h:445-459, 1220-1230).
16. Is the media GET stream proven on a live tenant (#518)? It is in the rc.1 gaps (CHANGELOG.md:361) and absent from the v1.5.1 gaps (CHANGELOG.md:23-27).
17. Do the Yealink, Grandstream, Polycom and Cisco SPA renderers work on physical handsets (FEATURE_ROADMAP.md:173)? Why did the snom's multicast never reach the board on the `.195` LAN (PROVISIONING.md:197-218)?
18. Rows marked "(not grepped)" (SIP ALG guidance, QoS, HA or clustering, scheduled updates), the default SIP port, wait-for-IP behaviour, and whether `/api/status` exposes live anchor connection state: all rest on the pocket-dial report not mentioning them. Search origin/main before turning any of them into copy.
19. Cites are origin/main `de61ba14`; local main is 45 commits behind and `docs/REALITY_CHECK.md` is not on origin/main. Re-check line numbers before quoting them.
