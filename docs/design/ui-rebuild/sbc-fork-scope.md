# pocket-dial SBC fork: scope (2026-10-16)

Merges: architecture (owner, authoritative on shape), 3cx-sbc-doc, 3cx-api-surface (wins on API capability), sbc-state-machines (wins on pocket-dial today), sbc-gap-matrix.

Cites. 3CX: `repo/path:line` under `scratchpad\3cx-src\` (SVC = call-control-service-example, SDK = call-control-sdk-ts, XT = xapi-tutorial). Every pocket-dial `file:line` is **(re-check)** in every table: matrix cites were taken on local main, 45 commits off origin/main `de61ba14` (its header wrongly says origin/main); state-machines cites `a26afa65`, used where both cover a fact.

## 1. What the fork is

The fork delivers **outcome parity** with the 3CX Pi SBC, not tunnel parity. Phones sit on a LAN box and register to it over SIP (local registrar). Extensions, status and BLF live in 3CX and follow the 3CX user. The box reaches 3CX only through Call Control (HTTPS plus WebSocket) and XAPI (OData); sync machines turn 3CX state into SIP NOTIFY and `/api/status` fields. It is **not** a 3CX SBC: no tunnel (port 5090, unpublished), no upstream phone registration, no presence in the 3CX console, no voicemail-lamp sync (no API).

## 2. 3CX-side prerequisites

1. **Licence.** Enterprise licence (3CX docs: 8SC or larger) for both Call Control and XAPI; the token endpoint refuses the credential otherwise (SVC/README.md:16; XT/README.md:16-17). Programmable Extensions needs V20 Update 10 (the swagger pins 20.0.10.1479, XT/swagger.yaml:6).
2. **One Service Principal** (Admin > Integrations > API) with **Call Control enabled and XAPI enabled**, plus a group and role for XAPI that can read Users (XT/README.md:7-12; flags XT/swagger.yaml:25437-25457). A token is refused unless at least one flag is on (SVC/src/auth.ts:28-30).
3. **The site's DNs assigned to the SP.** The SP sees its own DN plus assigned DNs; any other DN answers 403 and pushes nothing (SVC/README.md:19-21,244). Remote BLF covers only assigned DNs. If extensions change, an `appChanged` event fires (SVC/src/client.ts:41).
4. **Single active token — VERIFIED 2026-10-17 on <tenant>.3cx.us (SP `<sp-dn>`, client_credentials).** Issuing a second token immediately invalidated the first (`/Users` with token A → 401 once token B existed; B → 200). Both tokens reported `expires_in: 3600`. So **firmware has exactly one token owner**, the anchor client; the XAPI poller and every sync machine borrow it and never request their own. One token served both `/xapi/v1` (GET and PATCH) and `/callcontrol` (+ the WS handshake) in the same run, so one SP token covers both scopes. **Operational hazard:** any script or second device that requests a token with a board's SP credentials kills that board's live anchor session; give scripts their own SP.
5. **A PBX FQDN with a public-CA certificate.** Firmware verifies against the IDF CA bundle only, with no custom CA or pin (`TelephonyAnchorClient.cpp:1382,2527`, re-check), so a private-CA PBX fails Call Control and XAPI HTTPS alike.
6. **The SP's RoutePoint DN for audio.** Streams exist only for the app's own RoutePoint DN, not for extension legs (SDK/README.md:95-102). Audio is raw PCM16 8 kHz mono, two one-way HTTP streams per participant (SVC/README.md:251-252; SDK/src/audio/streams.ts:122-133).

## 3. Sync machines

Rules (CONTRIBUTING_FIRMWARE.md): all HTTPS (token, `GET /callcontrol`, XAPI polls) runs in the anchor client's task, never in SIP packet handling or under the engine `_mutex`. The packet path reads fixed arrays. No heap after init; bounded pools fail closed; cadences are per-machine constants on the 1 Hz `tick()`. 3CX documents no rate limit, which is not the same as none.

| Machine | 3CX source (event or poll, endpoint, cite) | Local output | Exists today (re-check) | Status | Size | Packet-path note |
|---|---|---|---|---|---|---|
| **Call state relay** | **Event.** WS `wss://<pbx>/callcontrol/ws`; Upsert/Remove/DTMF on `/callcontrol/{dn}/participants/{id}`; events carry no state, so GET the entity (SVC/README.md:163-181; SDK/src/state/call-state-store.ts:96-117). REST actions drop/answer/divert/routeto/transferto/makecall (SVC/README.md:216-229). Status enum includes `Hold`/`Held`, but **no hold/resume action** (SVC/README.md:233-234). | INVITE/BYE to phones, `MediaBridge` audio, 3CX REST answer/drop/makecall; UI call legs | `TelephonyAnchorClient.cpp:2933,3090,3113`; `RequestsHandler.cpp:5697-5834` (one inbound call at a time :5731); cap 4 (`PoolConfig.hpp:274`) | exists | large | Remaining gaps: hold, multi-call, flap survival. Media on its own TLS streams; unchanged |
| **Remote BLF** | **Event + seed.** Same WS: Upsert/Remove on `/callcontrol/{dn}/participants/{id}` (idle/ringing/busy from leg status) and `/callcontrol/{dn}/devices/{device_id}` (registered/unregistered), **SP-assigned DNs only**. On each Upsert, re-GET the entity (SVC/README.md:177-182). Seed with `GET /callcontrol`; **re-seed after every reconnect**, events are not replayed (SVC/README.md:125-127). Derived (INFERRED): no dialog-level detail, no pickup eligibility. Non-assigned DN = 403, show unknown. | dialog-info NOTIFY via the existing emitter; new `/api/status` per-DN remote state | Local half: `BlfSubscriptions.cpp:62-104,106-186,354-371`, 16 slots (`PoolConfig.hpp:55`). Remote half absent: a watched 3CX-only DN reads idle forever (`validAor` checks characters only, :206-209). Two gates: path shape must be exactly `/callcontrol/{dn}/participants/{id}` (`TelephonyAnchorLogic.hpp:184-194`), which also drops `devices/...` events, and `dn == _sourceDn` (`TelephonyAnchorClient.cpp:2925`) | partial | small (participants first; the devices half is larger, `device_id` is a SIP Contact URI that can contain "/", SVC/src/types.ts:107-108) | Fixed array DN-to-token; BLF code ORs it with session state. **Needs both gate changes**, leaving the `_sourceDn` call path untouched |
| **Profile status, read** | **Poll.** XAPI `GET /xapi/v1/Users` with `$select=Number,CurrentProfileName` (XT/swagger.yaml:21217,23257); by number `getUserByNumber`, number OData-quoted (XT/auth.ts:7-9). Also `User.IsRegistered` (:23330). No push event exists for profile status (XT section 5). | `/api/status` per-extension profile name; UI. No NOTIFY (presence draws 489, `BlfSubscriptions.cpp:194-204`) | none. Local DND is separate: `HttpServer.cpp:1143,3419`, `DtmfFeatureCodes.cpp:356-372`, not persisted | new | small | Poll in anchor task into a fixed array; mirror only, no change to ring behaviour. Cadence constant (30 s is my proposal, from no source; tune after the probe) |
| **Profile status, write** | `PATCH /Users({Id})` exists (XT/swagger.yaml:20777-20781; body `Pbx.User` includes `CurrentProfileName`). The swagger has no `readOnly` annotations; no spec exercises it; a 2024 community thread says PATCH does not change it. **Writable: UNVERIFIED.** `/MyUser` is for user tokens, not an SP (INFERRED). | local DND/status action calls PATCH | none | new | large | One-shot request from the anchor task, never from the SIP handler; echo only after the next poll confirms |
| **Remote MWI** | **No API.** XAPI has per-user voicemail settings only (XT/swagger.yaml:23439-23442); no message list, unread count or MWI field in any repo or doc. | none | Local MWI is owner-only, RAM-only, off in the constrained build (`BlfSubscriptions.cpp:265-281`; `main/CMakeLists.txt:309`) | no API | n/a | Not startable |
| **Registration / survivability** | **Event + poll.** WS drop/reconnect and `devices` Upserts; `User.IsRegistered`; token endpoint. | 401/403/503, lease, `/api/status`, annunciator tiles | Registrar and link supervisor exist (`RequestsHandler.cpp:92-94,8880-8975`; `TelephonyAnchorClient.cpp:1064,1118-1138`). `isConnected()` is WS-only (:327-330). **Policy undefined.** Known defect: `Registrar` `online` flag stale after lease lapse (`markOnline(false)` only at :1479) | partial | large | Link-health model beyond `isConnected()`; no HTTPS in the sweep |

**Conflicts resolved.** (a) Profile status: state-machines says no API; the swagger shows `CurrentProfileName` on `Pbx.User`, so readable by poll, writable unverified. (b) Participant status: state-machines lists three values; the SVC enum adds `Hold`/`Held` (whether the PBX emits them for a phone-initiated hold is unverified). (c) Remote BLF: no dedicated BLF API, but the WS covers SP-assigned DNs. (d) Call-state relay: "partial" in state-machines, **exists** here, gaps in section 4. (e) The shared extension-status record has no owner yet (question 7).

## 4. Reliability gaps that gate the product

Evidence: **hw** = seen on hardware, **host** = host tests only, **code** = code reading, not reproduced. Blocking means blocks the first release. All cites are re-check. Unprefixed line numbers are `TelephonyAnchorClient.cpp` (anchor) or `RequestsHandler.cpp` (RH). Emergency routing is not a gap; see 4a.

| Gap | Evidence | Blocks first release? | Action |
|---|---|---|---|
| WS flap kills every live call (`TelephonyAnchorClient.cpp:2865`; reconnect 5 s, matrix row 9) | host | No for call survival (second release). **Yes for BLF re-seed on reconnect** | Re-seed on reconnect in release 1 |
| Anchor `start()` never retries after a failed boot start (anchor:196-203,246-282,2506-2508) | code | **Yes.** A BLF product that stays dead until reboot is unacceptable | Reproduce with 3CX down at boot, then fix |
| One DN and one DID literal (RH:5848-5870); the one-call bound itself is decided (4a) | code | No | Copy line |
| PCMU only; PCMA and G.722 get 488 (RH:5162-5178) | code (Yealink T29 outbound call seen on hw with PCMU) | No | Copy line |
| #518: GET stream 403 on every one of 240 attempts on .244 (anchor:3659-3665); unresolved. The API doc offers an explanation (INFERRED): streams exist only on the SP's own RoutePoint DN (SDK/README.md:95-102) | hw (failure), hw once (2026-09-13 two-way audio, `CHANGELOG.md:1021-1034`) | Not for BLF/profile. **Yes for any "calls work" claim** | Verify RoutePoint DN path; do not say media is verified |
| Token lifetime: code uses JWT `exp - iat` with a 50 min fallback and calls OAuth `expires_in` of 60 s wrong (anchor:124-172); 3CX docs and SVC say 3600 (SVC/README.md:152) | **VERIFIED 2026-10-17: real token response `expires_in: 3600`** (probe-out/token.json) | **Yes** for the XAPI poller design | Fix the comment and the fallback; renew at ~50 min, never while media is live |
| Profile status (`User.CurrentProfileName`): read AND write | **VERIFIED 2026-10-17: GET 200; PATCH → 204, read-back matched, restored (probe-out/patch.json)** | No — it is the green light for the profile-status machine (poll + PATCH) | Design the poll cadence; `$top` max is 100 |
| Remote BLF scope: `/callcontrol` lists the SP's own DN plus assigned extensions (`<sp-dn>`, `200`, `001`); WS handshake 101 on the SP token; **participant status values still unverified** (0 frames in 30 idle s) | verified / unverified | No for the first release design; yes before claiming BLF states | Listen on the WS during a call on an assigned DN (owner to place it) |
| `POCKETDIAL_MSG_POOL=8` (constrained, `main/CMakeLists.txt:276`) vs `MAX_SUBSCRIPTIONS=16`, against the comment "must stay <= MSG_POOL" (`PoolConfig.hpp:50-53`) | code | **Yes on the constrained build**, before remote subscribers are added | Resolve first |

| `/api/status` exposes no anchor-link state (`AnchorClient::isConnected()` is WS-only and not surfaced), so the UI's alarm bar and annunciator cannot show "anchor down"; the ANCHOR tile is omitted in the UI passes (brief §7b, 2026-10-17 decision) | code | **Yes**: the SBC profile's MAIN must show API WS / XAPI / sync-machine state per `sbc-fork-architecture.md`; needs a small, bounded status field per channel (no heap, written from the anchor task outside `_mutex`) | First release |

## 4a. Decided behaviours (not gaps)

The matrix filed emergency routing as "missing" only because the Pi SBC does not carry 911 at all. These are owner-decided.

- **911 in SBC mode goes out the SBC path** (the anchor route). It is not held back or treated differently from other outside calls. Evidence that SBC mode leaves emergency dialling unchanged: repo-root test configs `test_dialplan_tapicfg_SbcModeDoesNotChangeEmergencyDialingBehavior.cfg` and the `SbcModeNeverReachesReservedExtensions` config (host tests).
- **Unroutable emergency call** (that path is down, i.e. 3CX unreachable): SIP 503 with `Warning: 399` and no `Retry-After`, per RFC 4497 section 8.3.1 (BCP 117) and RFC 3398 section 7.2.4.1. A 404 would be a false statement (RFC 3261 section 21.4.5). Verified.
- The Kari's Law on-site notification fires regardless of route.
- Dispatchable location is handled upstream by the PSAP broker, not by the box.
- In SBC mode the "E911 not configured" banner is expected: 3CX carries the E911 duty.
- Authority: `docs/AUDIT-LEGAL-E911-COMPLIANCE.md` and the #166 PRs (#241, #242), cited per the owner, not re-checked.
- **One outside line (#731)** is a bound chosen under the reliability rule: exhaustion degrades by refusal, never by allocation. Confirmed deliberate by the owner.

## 5. Blocked (needs 3CX-private interfaces)

No route around any of these is proposed. XAPI's `/Sbcs` objects are management metadata of 3CX-provisioned SBCs (XT/swagger.yaml:18046-18230); do not read them as a way into rows 26-30 (INFERRED).

| Matrix row | 3CX behaviour | Why blocked |
|---|---|---|
| 2 | Tunnel combining all SIP and RTP to 3CX on port 5090 | Tunnel protocol unpublished |
| 26 | Add SBC in the PBX; Provisioning URL plus Authentication Key ID | The tunnel client that would consume the key is unpublished (XAPI does expose `/Sbcs` and `ProvisionLink`, but only for 3CX's own SBC) |
| 28 | Push configuration from the PBX console | `Pbx.PushConfig` targets 3CX's own SBC client; no published client to receive it |
| 29 | Remote update and reconfiguration from the console | Management channel is 3CX-private |
| 30 | Per-SBC status, stats and email alerts in the console | Console reporting is 3CX-private |

## 6. Honest UI copy (SBC profile)

R = reused, C = changed, N = new. Placeholders: "N seconds" (line 7) and "unknown / last known" (line 8).

1. R. This is not a 3CX SBC. The board is a small local phone system that places and receives outside calls through the 3CX Call Control API. It does not use the 3CX SBC tunnel.
2. C. Phones register to this board, not to 3CX. 3CX sees one calling identity, not each phone. There is no per-phone caller ID or per-phone DID, and inbound calls arrive on one number, one at a time.
3. C. Outside calls and emergency calls go out through 3CX. If the uplink is down, outside calls fail, and an emergency call is refused with SIP 503 ("Emergency Call Not Routable") while the on-site notifier fires. 3CX carries the E911 duty in this mode; the "E911 not configured" banner is expected.
4. C. Outside calls use G.711 u-law (PCMU) only. The 3CX API has no send-DTMF action, and digits pressed during an outside call are not known to reach 3CX; this is untested.
5. R. Live outside calls end if the 3CX connection drops. Recovery after a failed start has not been shown and may need a reboot (code reading, not reproduced).
6. R. It cannot be added, updated, monitored or alerted from the 3CX admin console. Updates are uploaded by hand. Nothing appears in 3CX status or email notifications.
7. C (replaces "No 3CX BLF, presence or message-waiting sync"). **Ships only if the probe confirms** the WS behaviour. BLF lamps and profile status follow 3CX only for extensions assigned to this board's Service Principal, and show idle, ringing or busy only. Profile status is read-only and refreshes every N seconds. **Message-waiting lamps do not follow 3CX voicemail.** Local BLF is limited to 16 subscriptions.
8. N. **Placeholders until decided.** When 3CX is unreachable, remote lamps show [unknown / last known: decision pending] and local calls between phones on this board keep working.
9. R. No failover between 3CX addresses.
10. R. Capacity is 32 phones and 4 simultaneous 3CX calls (8 phones and 1 call on the constrained build). It runs only on the listed ESP32 boards.
11. R. Phones on other subnets cannot be adopted or locked. Provisioning is plain HTTP on the LAN. DHCP option 66 is not supported.
12. R. Phone-side SIP is unencrypted UDP with no SRTP, and there is no source allowlist. A 3CX behind a private CA will not verify.
13. R. Per-phone secrets cannot yet be generated on the device, so Secure registration is not deployable today.
14. R. Only one handset model (Yealink T29) is confirmed on an outside call, and only snom has accepted a provisioning file on hardware.

## 7. Order of work

**First release:**
1. Settle the owner-PBX probe (question 1). Small, gates the rest.
2. Fix `start()` recovery; resolve MSG_POOL vs MAX_SUBSCRIPTIONS; fix the stale `online` flag and the stale comment at `RequestsHandler.cpp:1226-1229`.
3. Decide the survivability policy (question 6). Decision only; implementation of the link-health model may follow.
4. Relax the WS entity gate; build remote BLF (fixed-array overlay, `GET /callcontrol` seed and re-seed).
5. Profile-status read (XAPI poll into a fixed array).
6. SBC profile UI: MAIN annunciator tiles for API WS, XAPI and each sync machine (nominal grey; P2 when a poll is stale; P1 when the WS is down), last-sync well per machine in seconds, and the copy in section 6.

**Second release:** profile-status write (only after the `$metadata` probe shows `CurrentProfileName` writable), WS-flap call survival, per-extension DID/caller ID if wanted. Multi-call inbound is NOT a release item: one outside line (#731) is a chosen bound (§4a); lifting it would be a separate owner decision against the reliability rule, not a feature in a queue.

**Never:** MWI sync (no API), the tunnel (private), anything in section 5.

## 8. Open questions

| # | Side | Question |
|---|---|---|
| 1 | 3CX | **Owner's-PBX probe, first.** One session settles: (a) `GET /xapi/v1/$metadata` and a PATCH of a test user's `CurrentProfileName` (writable? any voicemail-count field?); (b) WS Upserts for SP-assigned DNs, the `status` values seen for idle, ringing, busy and phone-initiated hold; (c) a real token response (`expires_in`, whether a new token kills the old, one token for both scopes) |
| 2 | 3CX | Which XAPI role or group rights ("See Presence", `AllowToChangePresence`, XT/swagger.yaml:30651-30663) does the SP need to read other users' profile? |
| 3 | 3CX | Is the #518 403 simply "streams are RoutePoint-only"? Was the 2026-09-13 two-way audio on a RoutePoint leg? (pocket-dial confirms from its own logs) |
| 4 | 3CX | Do API calls count against `AntiHackingSettings` throttling (XT/swagger.yaml:30596-30648)? Sets the safe poll cadence |
| 5 | pocket-dial | Does `start()` truly never retry after a failed start? (code reading, not reproduced) |
| 6 | pocket-dial | **Owner decision:** survivability policy. With 3CX down, do remote lamps show unknown, last known or idle; what stays up |
| 7 | pocket-dial | Who owns the shared extension-status record (DND, forwards, BLF token, remote overlay, profile)? Decide before profile sync |
| 8 | pocket-dial | Remote-DN capacity: how many monitored DNs fit in the overlay and the 16 BLF slots, on both builds |
| 9 | pocket-dial | SBC mode has no recorded bench verification (host tests only). Did the .244 "registered to 3CX" run on 2026-09-30 use the anchor or a SIP trunk? |
| 10 | pocket-dial | Re-check all file:line cites on origin/main; search the "(not grepped)" rows (SIP ALG, QoS, HA, scheduled updates) and whether `/api/status` exposes live anchor state before any becomes copy |
| 11 | pocket-dial | A private-CA PBX will not verify (matrix row 7 and matrix Q9, not moot for the API HTTPS). Add a custom-CA or pin option, or require a public CA? |
| 12 | pocket-dial | Not hardware-verified: 4-call concurrency, inbound carrier calls, CGNAT, non-snom provisioning renderers, snom multicast on .195 |

Dropped as moot (tunnel and upstream registration are out of scope): matrix questions 1-12 except certificates (kept as 11); state-machines question 8.
