# pocket-dial codebase map — for a web UI replacement that keeps backend + API

Merged from six haiku subsystem maps (sip-core, http-auth-ui, config-provisioning, transports-main, media-anchors-trunk, tests-tools-ci, docs-state). Line numbers are from those reads; treat them as approximate and re-grep before quoting. Items the scouts did not read are marked as such in section 6.

## 1. Shape of the system

pocket-dial is an ESP32 SIP PBX firmware with a host (desktop) build for tests. One pre-allocated, mutex-guarded SIP core (`src/SIP/RequestsHandler`, a god class that owns extracted engines: TransactionLayer, CallForker, CallPickup, ParkOrbit, BlfSubscriptions, DtmfFeatureCodes, CdrRing) sits behind a UDP receiver task and a 1 Hz `tick()` pump that runs every sweep. Outside-line PSTN goes only through cloud "anchors" (3CX call control, Apidaze) behind the `AnchorClient` seam; the SIP trunk code exists but ships compiled out. Emergency 911/933 is classified before any policy. A hand-rolled HTTP server (`src/Helpers/HttpServer.cpp`, one `handleClient()` if/else route chain of ~90 `requireAdmin` sites) serves a JSON API plus the whole SPA, embedded as eight raw-string parts in `index_html.h`. Config lives in NVS (`storage` and the shared `pbxcfg` namespace), phones are adopted by MAC in Learn mode and provisioned from `/config/<mac>.cfg` unauthenticated, and firmware ships via dual-slot OTA. Four board variants (`main/esp_main*.cpp`: WiFi SoftAP, W5500 eth, LAN8720, LVGL display) wire the same core with different task/core placement. Governance is a GoogleTest suite with a test-count floor, an HTTP smoke script, pjsua/baresip interop, cppcheck/clang-tidy baselines, and a 500-line PR cap.

## 2. Subsystems, key files, entry points

| Subsystem | Key files | Entry points |
|---|---|---|
| SIP core | `src/SIP/RequestsHandler.{hpp,cpp}` (engines as members: `_blf`, `_txLayer`, `_park`, `_cdr`, `_dtmf`, `_forker`, `_pickup`); `TransactionLayer.hpp` (RFC 3261 §17, four machines, two pools); `CallForker.hpp`; `CallPickup.hpp`; `ParkOrbit.cpp`; `BlfSubscriptions.cpp`; `DtmfFeatureCodes.cpp`; `CdrRing.hpp` (NVS ring, writer task); `Registrar.hpp`; `PoolConfig.hpp` (caps, `#ifndef`-overridable) | `RequestsHandler::tick()` ~:10213 (1 Hz pump; order: clear `_outbox`, sweepSpliceTxns, drainDtmfInbox, sweepExpired, anchor tick, `_txLayer.sweep`, sweepSessionTimers, `_blf.sweepExpired`, `_park.sweep`, `_sipTrunk.sweep`); `sweepExpired()` ~:8880; `sweepSessionTimers()` ~:11827; `sweep*ForTest` hooks `RequestsHandler.hpp:633-660`; `RequestsHandler::handle` runs inline in `udp_receiver_task` (`src/Helpers/UdpServer.cpp`) |
| HTTP server, auth, SPA | `src/Helpers/HttpServer.{hpp,cpp}`; `src/Helpers/AdminAuth.hpp` (session, CSRF, Owner/Sysop roles); `src/Helpers/index_html.h` (`PD_HTML_0..7`, parts table `CGA_INDEX_HTML_PARTS` ~:2548); `tools/check_string_literal_caps.py` | `handleClient()` ~:648 (deadline read, peer IP, route chain); `requireAdmin()` ~:4278; `hasValidAdminSession()` ~:4270; `isSameOrigin()` ~:4172; `POST /api/admin/set-credential` ~:1472; `POST /api/admin/login` ~:1492; `/api/status` ~:942 |
| Config, provisioning, OTA | `src/Helpers/DeviceConfig.cpp` (NVS `storage`: `ap_secure`, `ap_psk`, `cfgseed_gen`); `src/SIP/PbxPersist.hpp` (NVS `pbxcfg`, tab/newline blobs); `src/SIP/PbxConfig.hpp:212-330` (reserved extensions); `src/SIP/PbxFeatureConfig.cpp:564-1060`; `src/SIP/Registrar.hpp` (Mode, DeviceState, `admitLearn()` ~:139, `kAdoptBurst`); `src/SIP/ProvisioningConfig.hpp` (Yealink/Grandstream/Polycom/Cisco/snom renderers); `src/Helpers/OtaUpdater.hpp`; `docs/OTA.md`; `docs/LEARN_MODE.md`; `docs/PROVISIONING.md` | `GET /config/*` branch `HttpServer.cpp:915-924` + path classifier ~:3123-3200; `/api/config/export` ~:1336; `/api/config/import` ~:1373; `/api/configuring` ~:118,1315; `/api/ota/reboot`; `OtaUpdater::begin()` ~:57 |
| Board entry points / transports | `main/CMakeLists.txt` (`SIP_TRANSPORT` = eth default, lan8720, display, else WiFi SoftAP); `main/esp_main.cpp` (SoftAP); `main/esp_main_eth.cpp` (W5500); `main/esp_main_eth_lan8720.cpp`; `main/esp_main_display.cpp` (LVGL); `main/ui/ui.{cpp,h}` (`ui.h:57` status snapshot POD); `main/wifi/DnsServer.cpp`; `main/HeapLeakProbe.cpp`; `main.cpp` + root `CMakeLists.txt` (host `SipServer` target, `-w/--web` default 8080) | `sip_server` task core 1 prio 5 8 KB (`esp_main.cpp:543`, `esp_main_eth.cpp:828`, `lan8720.cpp:585`); display variant: `lvgl_task` core 1 ~:827, sip/http core 0 ~:900-944, `status_task` core 0 ~:986; `log_drain` core 0; host `main()` `main.cpp:9` |
| Media, anchors, trunk, emergency | `src/SIP/AnchorClient.hpp` (pure virtual: start/stop/makeCall/answerCall/dropCall/writeAudio/tick/isConnected); `TelephonyAnchorClient.hpp` (3CX); `ApidazeAnchorClient.hpp`; `LoopbackAnchorClient.hpp` (test); `SipTrunk.hpp`; `TrunkResolver.hpp`; `src/Helpers/TrunkConfigStore.hpp`; `RtpSender.hpp`/`RtpReceiver.hpp`/`RtpTaskSlots.hpp`; `MediaBridge.cpp` (false on bus full → 486/503); `DialPlan.hpp`; `EmergencyCall.hpp`; `EmergencyNotifier.cpp` | `RequestsHandler::isEmergencyTraffic` ~:4863; INVITE emergency yield ~:942-994; E911 config gate ~:309-314 (warning only); `originateAnchorCall`; `kAnchorNoTrunk` ~:4640; `AnchorClient::makeCall` `AnchorClient.hpp:67` |
| Tests, tools, CI | `tests/` (~96 gtest files, googletest 1.14.0, C++17, `EXPECTED_MIN_TESTS` + `tests/min_tests.d/`); `tests/http/test_api.sh` (30 TC ids); `tests/interop/{interop.py,run_interop.sh,ci_setup.sh}`; `tools/ci/` (`run_cppcheck.sh`, `run_clang_tidy_safety.sh`, `check_app_version.py`, `check_no_bench_probe.py`, `task_stack_gate.py`, `app_slot_margin.py`); `tools/check_string_literal_caps.py`; workflows `ci.yml`, `ci-glolab.yml`, `interop.yml`, `commit-hygiene.yml`, `release.yml`; `CONTRIBUTING_FIRMWARE.md`; `docs/API_TESTS.md`; `docs/TEST_HARNESS.md`; `docs/THREAT_MODEL.md` | `tests/CMakeLists.txt`; `tests/http/test_api.sh`; `tests/interop/run_interop.sh`; `ci.yml:210` and `ci-glolab.yml:193` call the static-analysis scripts |
| Docs of record | `docs/FEATURE_ROADMAP.md` (§1 shipped, §2 proved-on-hardware :186-197, §3 backlog); `docs/SECURITY_AUDIT.md` (SEC-01..04, corrections :18-47); `docs/REALITY_CHECK.md` (stale 2026-06 scorecard, banner :4-46); `docs/AUDIT-LEGAL-E911-COMPLIANCE.md`; `CHANGELOG.md` (known gaps :17-21 v1.5.1, :349-361 rc.1); `docs/HARDWARE.md` | read `SECURITY_AUDIT.md:18-47` and `CHANGELOG.md` known-gaps first |

## 3. Invariants and rules that constrain any change

Governance (`CONTRIBUTING_FIRMWARE.md`, repo memory):
- **No heap allocation in the packet path, and no new heap after init.** This covers HTTP handlers too: a handler must not allocate per request. (`CONTRIBUTING_FIRMWARE.md:18`; embedded rules.)
- **Gate by fall-through, not early return.** `requireAdmin()` writes 401/403 and returns false; `handleClient()` has a single `closeSocket(clientSock)` at the end, so a route that `return`s early skips it. Use the fall-through form (`CONTRIBUTING_FIRMWARE.md:25`; `HttpServer.cpp:964-966`).
- **500 modified lines per PR** (`CONTRIBUTING_FIRMWARE.md:11`). No workflow enforces it; honor system.
- **String-literal caps for `index_html.h`.** MSVC C2026: raw part <= 16384 B, ordinary <= 16383 B, run <= 65535 B. CI is Linux-only and never sees the overflow; run `tools/check_string_literal_caps.py` explicitly (it has `--selftest`). Any new UI must be re-split into parts under the cap and the `CGA_INDEX_HTML_PARTS` table updated.
- **Core pinning.** Non-display variants: SIP on core 1 (prio 5, 8 KB), HTTP and log_drain on core 0. Display variant: SIP and HTTP on core 0, LVGL on core 1. `sip_server_task` is the only SIP-path task on the TWDT. Host build has no pinning, so placement/watchdog bugs show only on hardware.
- **Test-count floor:** `EXPECTED_MIN_TESTS` base + `tests/min_tests.d/` contributions; add a contribution file, never edit the base. clang-tidy safety checks fail on any count above baseline.
- **No `Claude-Session` commit trailer** (`commit-hygiene.yml`).
- **Task names truncate to 15 chars** (`udp_receiver_ta`); stack HWM reporting keys on the truncated name (`HttpServer.cpp:1988, :2519`).

SIP core:
- Every engine assumes the caller holds `RequestsHandler::_mutex`.
- `tick()` self-throttles to 1 Hz; every sweep timeout is accurate only to about one second.
- Pools are hard caps with no heap fallback (Issue 409): 32 clients, 8 sessions, 16 BLF subscriptions, 4 register beeps, message pool = MAX_CLIENTS + MAX_SUBSCRIPTIONS + 4 = 52. Drained client/session pool → 503; drained message pool → drop (counted in `msgPoolRefusals`); transaction pool drained → one-shot send without tracking. A parked call costs one session slot. `MAX_SUBSCRIPTIONS <= MSG_POOL`.
- Issue 533: a mid-call client is exempt from keepalive pruning.

Auth (`HttpServer.cpp:4281-4337`):
- `requireAdmin` gate order is fixed: same-origin → session (401) → CSRF on mutating routes only (403) → `setup_required` until the default credential changes (403, only `/api/admin/set-credential` exempt) → Owner role (403).
- A missing `Origin` header is admitted by design; the Origin check is browser-only and CSRF is the control that closes the gap. Reads that disclose but do not act (`hasValidAdminSession`, `/api/status`, `/metrics`) stay ungated.

Config/provisioning:
- `/config/<mac>.cfg` is unauthenticated by design; the MAC is the credential, served only for adopted MACs or the fixed master/bootstrap names. Provisioning output never contains the SIP password (HA1 only).
- Reserved identities (911/933/555/440/777/888/999, 796 voicemail, 700-709 park, 980-989 page zones, 997 multicast page) are refused by one helper for REGISTER and every config validator (`PbxConfig.hpp:246-282`).
- `pbxcfg` keys cap at 15 chars; records are tab/newline delimited, so AOR charset must exclude those.
- Registrar mode byte 0 (retired open) maps to Learn. OTA rewrites one app slot; partition table changes only by serial flash.

Emergency:
- 911/933/`urn:service:sos` classified ahead of DialPlan, DND, CFNA; they pass gates that block everything else. E911-not-configured is a warning, never a block.

## 4. Everything UI-relevant

**Transport.** HTTP on port 80 on the ESP (`HTTP_DASHBOARD_PORT`), 8080 on the host (`main.cpp:17`, `-w/--web`). Host-header checks accept the local IP, the mDNS hostname (`POCKETDIAL_HOSTNAME`, exposed in status JSON ~:5818) or `localhost` (~:4195). Request read is under a single deadline (#529). The SPA is one page assembled from `PD_HTML_0..7` at request time; the parts stay in flash.

**Auth model.**
- Session: cookie or session token (`sessionToken` ~:4246). Roles: Owner and Sysop (`AdminAuth.hpp`). A Sysop session satisfies Owner-only routes while no owner credential exists (~:4326-4331).
- CSRF: per-session token, echoed by `POST /api/admin/login` (~:2660); the current SPA reads it via `sessionCsrf` (~:7003-7029). Send it on every mutating route.
- Login is brute-force limited per peer IP (~:657-676).
- First-boot flow: until the default credential is changed every gated route answers 403 `setup_required` (with a message) except `POST /api/admin/set-credential`.
- Status codes to handle: 401 authentication required; 403 cross-origin rejected / missing or invalid CSRF / `setup_required` / owner privilege required; 503 from pool exhaustion on the SIP side (not HTTP).

**State the server exposes.**
- `GET /api/status` — ungated; returns session info and the extension roster only when the caller is authenticated (~:925-939, 2351-2363). Fields noted by the scouts: `msgPoolRefusals`, `vpeerPoolRefusals`, task stack HWM fields (~:2519, 2544), `coredump.supported`, hostname. The full schema is in `docs/API_TESTS.md`; not re-derived here.
- `GET /metrics` — ungated by design.
- `GET|POST /api/config/export` (can include secrets with a password, `HttpServer.hpp:475-481`), `POST /api/config/import` (form-encoded `blob=JSON`) — admin. Export does not cover SIP trunk, SMTP, syslog or E911 config (`FEATURE_ROADMAP.md` 3.2).
- `POST /api/configuring` — pauses the auto-switch to Standalone.
- `POST /api/ota/reboot` — OTA reboot (`docs/OTA.md:10`).
- `GET /config/*` — provisioning, unauthenticated, not a UI route.
- Anchor health: `AnchorClient::isConnected()`, WS-only for 3CX (reports the websocket, not call capability).
- CDR: NVS ring, writer task; silently stale past 4000 B (#470).
- Display variant: `ui.h:57` POD snapshot copied by `status_task` each tick; that LVGL UI is separate from the web SPA.

**Polling.** Nothing in the scouts' reads shows push (no WebSocket/SSE route was found). `tick()` is 1 Hz, so no counter changes faster than that; poll `/api/status` at >= 1 s. Keep polling off the brute-force path (never re-POST login on a timer). Request reads are deadline-bounded.

**Limits the UI must respect.** 32 clients, 8 sessions (park uses one), 16 BLF subscriptions, 4 register beeps; 15-char `pbxcfg` keys; no tab/newline in AORs; reserved extension ranges above; SPA part cap 16384 B raw per part; no per-request heap in any handler you add; one `closeSocket` per request (fall-through gate).

**Contract the UI is tested against.** `tests/http/test_api.sh` (30 TC ids), `docs/API_TESTS.md` (four-layer gate, login preamble, endpoint schemas). A replacement UI should leave that script green.

## 5. Unverified or deliberately undone — the UI must not present these as done

- **Hardware evidence is one handset (Yealink T29), one board, one carrier.** Anchor bridge only.
- **On-device RTP has no automated test**: `RtpSender`/`RtpReceiver` are host stubs; media tests exercise stubs.
- **A live 911/933 route has never been proved on hardware** (`FEATURE_ROADMAP.md:83`). The legal audit says "Compliant" but defers to operator config. The SBC-mode "E911 not configured" banner is expected.
- **SIP trunk is compiled out** (`POCKETDIAL_HAS_TRUNK=0`); outside line is anchors only. `_sipTrunk.sweep` is in `tick()` but the feature is shelved. Trunk failover unbuilt.
- **3CX anchor has no hold/resume**; `isConnected()` is WS-only.
- **OTA**: proved once by hand (2026-09-26); CI never runs the dual-slot rollback flow. OTA image signing, Secure Boot v2, flash encryption: not done.
- **Unbuilt/unproven**: 100rel/PRACK, MWI, outbound E.164 normalization, session-timer refresher side, PIN-protected conference rooms.
- **Vendor provisioning renderers**: Yealink marked not hardware-verified; `ProvisioningConfig.hpp:27-33` says the vendor renderers are not wired to `/config` while `docs/PROVISIONING.md:414` says wired and the classifier exists. Trust the code.
- **Learned-extension INVITE** may still be unchallenged (`FEATURE_ROADMAP.md` 3.3 vs `SECURITY_AUDIT.md:34`); Learned extensions are takeable from any MAC (Learn locks only Secured).
- **Security**: no re-audit since 2026-09-13; `REALITY_CHECK.md` is a stale 2026-06 scorecard (criterion 3 falsified on hardware) and its line anchors predate the RequestsHandler split.
- **Config export** omits trunk, SMTP, syslog, E911.
- **CDR ring** can silently go stale past 4000 B (#470).
- **Park with MoH streams RTP from the board**; parked legs are no longer peer-to-peer.
- **Stale docs**: `THREAT_MODEL.md` D-5 cites early-return MoH routes at `:493/:500/:505` that grep no longer finds; `TEST_HARNESS.md` §0 says interop is not in CI, but `interop.yml` exists; `ArpLookup.cpp:101` cites `/config` behaviour, verify against `HttpServer.cpp:3123`. Local `ISSUES.md` numbers are not GitHub numbers.
- **Soak**: v1.5.0 soak was 4.6 h on the test rig.
- **Display-variant core placement** (SIP on core 0) may be a leftover; unverified.

## 6. Open questions

1. `isSameOrigin` body (~:4172-4200) was not read in full; exact Host-header rules are unverified.
2. Not audited: whether every mutating route passes `needCsrf=true`. A new UI should test each POST for a 403 without the token.
3. No WebSocket/SSE push was found, but no scout grepped for one; confirm before designing around polling.
4. The mDNS responder was not located (not in `HttpServer*`); grep `mdns` across `src` and `main`.
5. Where `udp_receiver_task` is spawned in the ESP build was not found.
6. `tests/EXPECTED_MIN_TESTS` references `tests/tools/check_test_count.py`, which is not under `tests/tools`; who runs the floor gate?
7. Is the 500-line PR rule enforced anywhere, or honor-system only?
8. Is `THREAT_MODEL.md` D-5 still accurate after the MoH route changes?
9. Not read: `admitLearn()` and the MAC-lock path in `Registrar.cpp`, `sendProvisioningResponse`, the OTA handler in `HttpServer.cpp`, `docs/LEARN_MODE.md:15-54`, `RegistrarLearnLock_test.cpp`, `LearnLockMinAge_test.cpp`. Does `DeviceConfig` read `cfgseed` every boot or only first boot?
10. Exact site that returns 503 for an unroutable 911 was not located (~:4790-4800 or `CallForker.cpp:332`). Apidaze wiring and RTP internals read from headers only.
11. `pbxcfg` namespace is shared by `PbxPersist`, `EmailConfigStore`, `TrunkConfigStore`, `Syslog`; has anyone checked for key collisions?
12. Is `REALITY_CHECK.md` to be retired or re-scored? Is the display variant's core-0 SIP pinning intentional (git blame)?
13. `docs/API_TESTS.md` endpoint schemas were not opened; the `/api/status` field list in §4 is partial.
