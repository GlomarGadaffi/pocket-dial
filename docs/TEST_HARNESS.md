# pocket-dial Test Harness — Specification

Status: DRAFT for crew review (2026-09-20).
Scope: one entrypoint that runs every existing verification layer against either the
**host** build or a **board**, plus a hardware-in-the-loop (HIL) job on the glolab runner.
Nothing here replaces a script that already works.

## 0. What exists today (measured on `d92fd2d`, not copied from docs)

| Layer | Where | Runs in CI? | Target |
|---|---|---|---|
| GoogleTest suite, 96 files / 1191 cases, one ctest target `sip_parser_tests` | `tests/` | yes (ci.yml, ci-glolab.yml) | host |
| HTTP API smoke, 30 TC ids | `tests/http/test_api.sh` | yes (host); manual on board | both |
| pjsua/baresip interop, 11 scenarios | `tests/interop/interop.py` | **no** | host only (spawns `SipServer`) |
| SIPp, 7 XML scenarios | `tests/sipp/run_sipp.sh` | **no** | host only (spawns `SipServer`) |
| Load / pool ceilings | `tests/load/sip_stress.py` | **no** | either (takes an IP) |
| Call-graph / VLA guard (THREAT_MODEL T-7) | `tests/tools/check_parser_callgraph.py` | **no** | source |
| Office smoke, 10 scenarios, real RTP | `.smoke/office_smoke.py <ip>` | **no** | board |
| Serial capture, SIP liveness, NVS provisioning | `.smoke/capture.py`, `sip_probe.py`, `gen_provision_nvs.py` | **no** | board |
| Firmware build matrix (5 legs) + heap_debug + heap_trace + waveshare | `ci.yml` | yes | compile only |

Gaps the harness closes: there is no runner script at all; nothing beyond gtest and
`test_api.sh` is automated; the glolab self-hosted runner never touches a board;
interop and SIPp cannot address a remote PBX; there is no sanitizer build and no soak;
`ci.yml` uploads no firmware artifacts (only `release.yml` does); the host binary has no
graceful shutdown, so every driver kills it.

## 1. Design principles

1. **Wrap, don't replace.** Every subcommand is a thin driver over a script that already
   exists. No new test framework.
2. **One target abstraction.** `--target host` spawns `SipServer`; `--target board=<ip>`
   addresses a running device and never spawns. Each layer declares which targets it
   supports.
3. **Provenance before assertions.** A board run is invalid until the harness proves the
   board is running the binary it thinks it is.
4. **Nothing destructive by default.** Reboot, factory reset, `/api/kill`, lockout
   exercises and flashing require an explicit flag, and config is snapshotted around them.
5. **Evidence is a file.** Every run writes a self-describing results directory.
6. **The harness participates in the crew's hardware mutex; it does not replace it.**

## 2. Entry point

```
tests/run.py <suite> [--target host|board=<ip>] [--profile default|heap_trace|heap_debug|constrained]
                     [--out <dir>] [--allow-destructive] [--only a,b] [--json]
```

| Suite | Wraps | host | board | Notes |
|---|---|---|---|---|
| `unit` | cmake + ctest | ✔ | – | `--gtest_filter` passthrough, sharding (§6) |
| `api` | `tests/http/test_api.sh` | ✔ | ✔ | see §5.4 step 3 for board safety |
| `interop` | `tests/interop/interop.py` | ✔ | after P1 | needs the remote-target change (§4) |
| `sipp` | `tests/sipp/run_sipp.sh` | ✔ | after P1 | same |
| `load` | `tests/load/sip_stress.py` | ✔ | ✔ | already takes an IP |
| `callgraph` | `tests/tools/check_parser_callgraph.py` | source | – | free to add to CI today |
| `sanitize` | cmake `-fsanitize=address,undefined` + ctest | ✔ | – | new job (§6) |
| `board-flash` | esptool over glolab SSH | – | ✔ | §5.2 |
| `board-provenance` | `/api/status` + boot banner vs build stamp | – | ✔ | §5.3, runs before every board suite |
| `board-smoke` | `capture.py` + `sip_probe.py` + `test_api.sh` + `office_smoke.py` | – | ✔ | §5.4 |
| `board-soak` | `/api/status` heap sampler | – | ✔ | §5.5 |
| `anchor` | 3CX Call Control tier | – | bench only | §5.6, credentials-gated |
| `all` | every suite the target supports | ✔ | ✔ | |

Exit code: 0 all pass, 1 any FAIL, 2 harness error (target unreachable, provenance
mismatch, lock held). SKIP never fails the run but is always listed.

Results directory (`--out`, default `tests/.results/<utc-timestamp>-<target>-<sha>/`):

```
manifest.json      target, sha, git describe, profile, host, start/end, per-suite verdicts
<suite>/           each wrapped script's own logs, verbatim
serial.log         board runs: full capture, see §5.1
status-*.json      every /api/status the harness read, timestamped
```

`--json` prints `manifest.json` to stdout for CI step summaries.

## 3. Host tier

Runs on ubuntu-latest, on the glolab runner, and under WSL on a dev box.

- `unit`: the unchanged three commands (`unset IDF_PATH; cmake -B; cmake --build; ctest`).
  The harness takes a **per-host lock** (`flock` on `/tmp/pd-host-tests.lock`) because the
  HTTP suites bind fixed port blocks 18080–19399 (CONTRIBUTING_FIRMWARE §5) and two
  concurrent runs collide. Plumbing a port base through the 13 HTTP test files removes
  the lock; that is P2.
- `api`: identical to the CI step today; the harness owns spawn, poll and `kill -9` of
  `SipServer`.
- `interop`, `sipp`: unchanged on host. Both need pjsua and sipp provisioned on glolab
  without sudo (`apt-get download` + `dpkg -x`; pjsua from source with
  `PJMEDIA_HAS_VIDEO 1`, or attended transfer can never send its REFER).
- `callgraph`: add to `ci.yml` and `ci-glolab.yml` as a blocking step. Exit 1 = cycle or
  dynamic frame, exit 2 = TU failed to compile.
- `sanitize`: new `ci.yml` job, ASan + UBSan, warn-only for two weeks to establish a
  baseline, then blocking.

## 4. Remote-target change for interop and SIPp (P1)

Both harnesses launch `SipServer --ip 127.0.0.1` as a subprocess and bind each UA to its
own `127.0.0.x`. For `--target board=<ip>`:

- Skip the spawn. Registrar = `<ip>:5060`, web = `<ip>:80`.
- UAs bind to the runner's LAN address (glolab is on the same 192.168.12.x as `.244`) on
  distinct ports; the `127.0.0.x` trick goes. All UAs then share one per-source-IP token
  bucket (~40 burst / 20 pkt/s, `RequestsHandler::allowPacket`); scenarios stay under it,
  and `load` keeps using `--source-ips`.
- Test extensions stay 601–605. They avoid the real Yealink on 1001, park orbits 700–709,
  page zones 980–989 and the literal service extensions.
- `heap_telemetry` already discriminates host vs device via `resetReason == "n/a"`; on a
  board it asserts a real reason and non-zero heap fields.
- pjsua/baresip assertions never depended on the PBX being local; they are unchanged.

## 5. Board tier (HIL)

### 5.1 Fixed facts the harness encodes

- Board `.244` = 192.168.12.244, LilyGO T-ETH-ELITE S3 (`SIP_TRANSPORT=eth`,
  `PD_ETH_BOARD=elite`), USB-CDC on glolab at
  `/dev/serial/by-id/usb-Espressif_USB_JTAG_serial_debug_unit_E0:72:A1:CC:1C:04-if00`.
  Always open by-id, never by `ttyACMn`.
- A physical power-cycle re-enumerates USB and kills any open reader. Serial capture is a
  **reopen loop**, written to a file **on glolab** (`stty 115200 raw -hupcl` + `setsid cat`),
  then copied. Never stream a burst through a live ssh pipe (it loses whole lines).
- Opening the port may pulse DTR/RTS and produce a reboot-looking banner (#327). A reset
  is real only if the capture contains a panic trace or `dmesg` shows re-enumeration. The
  harness checks both before flagging one.
- `ESP_LOGx` drops silently above ~100 lines/s (16-deep LogQueue). Any assertion on bulk
  output (heap dumps, tables) counts **indexed lines** (`k/N`) and reports missing
  indices, never "looks complete".
- The register beep fires only on a brand-new binding, so the Yealink re-registering
  after a fresh boot is part of the smoke. `Timer B expired` and `pool exhausted` are
  asserted absent over the whole capture, never a tail.
- `POST /api/telephony-config/<n>/test` is makeCall then immediate dropCall. It proves
  token + REST reachability, nothing about bridge or hold.

### 5.2 `board-flash`

Input: a firmware bundle from a `build-esp-idf` CI artifact (esp32s3/eth, chosen
profile), never built on the runner. Steps:

1. Acquire the board lock (§5.7).
2. scp the bundle to glolab `/tmp/pd244_flash/<sha>/`, verify `SHA256SUMS`.
3. Pre-flash: read `/api/status`, record the current version stamp, save
   `POST /api/config/export` to the results dir.
4. `esptool --chip esp32s3 --port <by-id> --no-stub --after no_reset write_flash 0x20000 app.bin`.
   App-only by default; `--full` writes bootloader + partitions + app; `--nvs <img>`
   writes a `gen_provision_nvs.py` image at 0x9000. glolab's working esptool is 5.4.0
   (the venv at `~claude-agent/esptool-venv`, which ran the 2026-09-27 recovery in #338),
   not 4.7.0. The underscore spellings and `--no-stub` above are what `tests/run.py`
   sends; they date from Debian's packaged 4.7.0, which has no S3 stub JSON.
   **`--after no_reset` is mandatory.** Issue #338 (open) shows that esptool's hard,
   watchdog and RTS resets can park this board in ROM download mode until someone
   presses RST or power-cycles it. Switching power cannot do that remotely: `.244` is
   PoE-fed, so a USB VBUS cycle leaves it running (tested 2026-09-24, uptime kept
   climbing), and its PoE switch is unmanaged. The reset after a flash must come from a
   GPIO relay or open-drain MOSFET from glolab on `.244`'s EN (reset) line, which is a
   P0 hardware dependency (§8). Until it exists, `board-flash` is dispatch-only with a
   human at the bench, and the physical RST button is the only guaranteed recovery.
   **Safe reboot until then:** hold DTR false so GPIO0 stays high, then pulse RTS; the
   ROM boots from flash instead of the download loader. `.smoke/capture.py` does exactly
   this; the bench's `pd_serial.py --reset` on glolab holds DTR false the same way (#384).
   One data point, not proof: on 2026-09-27 esptool 5.4.0
   `--before no-reset --after hard-reset`, with DTR false, took `.244` out of the ROM
   loader into the app (#338).
5. Reset (EN low), start capture, poll `/api/status` up to 60 s.
6. Run `board-provenance`. Mismatch = exit 2, board left as-is, lock released with a
   CHECK-IN stating what is on it.

### 5.3 `board-provenance`

Runs before every board suite, not just after flashing. Passes when three sources agree
on the stamp from `git describe --tags --always` of the built commit:

- the `/api/status` version string;
- the boot banner in the serial capture;
- a `grep -a` of the flashed `app.bin`, which catches a stale artifact.

It also records `resetReason` from the first Heartbeat; a Heartbeat line without
`ResetReason` is a pre-#340 build and fails provenance outright.

### 5.4 `board-smoke`

Ordered, each step a verdict:

1. Boot capture. **The reboot counts as destructive**: the Yealink on 1001 is a real
   handset in use, so without `--allow-destructive` this step attaches to the running
   board and asserts only from that point. Checks: link up, IP acquired, SD mounted, zero
   `ERROR`/panic lines across the whole file.
2. `sip_probe.py <ip>` → `RESULT: ALIVE`.
3. `test_api.sh <ip>`. **As written the script is not board-safe**: it assumes the
   shipped `admin`/`admin`, and its final auth block logs out and deliberately trips
   brute-force lockout, which `SERVER_PID` does not gate (it only gates TC-OTA-07 and
   TC-FR-01..03). Board mode needs a credential source from the runner environment
   (`PD_BOARD_ADMIN_PIN`) and the lockout, factory-reset and OTA-reboot cases moved
   behind `--allow-destructive`, with config export before and import after.
4. Yealink 1001 registered in `/api/status` within 90 s of boot; no `Timer B expired`,
   no `pool exhausted` anywhere in the capture.
5. `office_smoke.py <ip>`, all 10 scenarios as sub-verdicts.
6. `interop --target board` (after P1).
7. Final `/api/status` snapshot; internal-heap `largest` must be ≥ 50% of its post-boot
   value. Placeholder threshold until `board-soak` gives a baseline.

### 5.5 `board-soak`

`tests/run.py board-soak --target board=<ip> --minutes N --interval 30 [--calls every M]`
samples the 8 heap fields + 5 `stackHwm_*` fields from `/api/status`, optionally places
a test-dial call every M minutes, and writes a CSV. Verdict is a slope test on internal
`free` and `largest` against an idle baseline. The #328 confirmation (largest
27628 → 1132 in 13 idle minutes) was this by hand; it becomes a number the crew can
quote. Profiles matter: `heap_trace` builds are for the #331 periodic dump (but no boot
of that build has reached t=360 s yet, #374, so its 360/900 s and periodic dumps are
unreachable today), and only a `default` build is a valid target for the #328/#330
zero-alloc proof.

### 5.6 `anchor` (3CX Call Control, bench only)

Credentials come from the runner environment (`PD_ANCHOR_TENANT`,
`PD_ANCHOR_CLIENT_ID`, `PD_ANCHOR_CLIENT_SECRET`), never the repo. Cases: token fetch,
test-dial round-trip, WS connect plus one re-auth after token rotation (#343; a live
tenant cannot be forced to expire a token, so this is either a soak longer than the token
lifetime or a mock anchor endpoint), GET-stream reopen after a dropped read (#350).
Hold/resume is **not** automatable: 3CX Call Control has no hold primitive (#333), and
bridge behaviour needs a real far-end leg. Those stay a manual script with a results
template. Never in PR CI.

### 5.7 Board mutex and crew convention

The crew's rule is broadcast CHECK-OUT / CHECK-IN with a stated expiry. The harness
joins it rather than replacing it:

- Takes `flock /var/lock/pd244.lock` on glolab for the whole run; exits 2 if held,
  printing the holder's manifest (who, sha, started, expiry).
- A human hold is a `/var/lock/pd244.hold` file the harness never overrides.
- The CI job uses `concurrency: glolab-board-244` (not per-SHA) so two pushes queue.
- Posts a CHECK-OUT comment on the night's Discussion thread before touching the board
  ("harness run <sha>, expiry <start+45 min>") and a CHECK-IN after, stating the
  firmware left on the board.

### 5.8 CI wiring

Today `ci.yml` uploads no firmware artifacts, and `ci-glolab.yml` fires on the same push,
so a cross-workflow download would race the IDF matrix. Two P0 changes:

- The esp32s3/eth leg plus the `build-heap-trace` and `build-heap-debug` jobs gain an
  `upload-artifact` step for their flash bundles.
- A new job `hil-244` lives in `ci.yml` itself: `needs: build-esp-idf`,
  `runs-on: [self-hosted, glolab]`, `if: github.ref == 'refs/heads/main'`, plus
  `workflow_dispatch` inputs `profile` and `allow_destructive`. The existing
  `build-and-test-host-glolab` job in `ci-glolab.yml` is untouched.

Steps:

1. `actions/download-artifact` the esp32s3/eth bundle for the profile from this run.
2. `tests/run.py board-flash --target board=192.168.12.244 --profile <p>`
3. `tests/run.py board-smoke --target board=192.168.12.244`
4. Upload the results dir as an artifact; `manifest.json` becomes the step summary. On
   failure the serial capture is the first thing linked.

Fork PRs never reach this job because of the `main`-only condition; the self-hosted
runner still never checks out PR code.

## 6. Host-side improvements riding along

- Register gtest per-file with `gtest_discover_tests()` so ctest can shard and retry, and
  a red run names the file. The `sip_parser_tests` target name stays.
- `sanitize` job as in §3.
- `callgraph` into both host workflows.
- ci-glolab gains `interop` and `sipp` (host target) once pjsua/sipp are provisioned.

## 7. Phasing

| Phase | Deliverable | Why first |
|---|---|---|
| P0 | `tests/run.py` with `unit`, `api`, `callgraph`, `board-flash`, `board-provenance`, `board-smoke`; artifact uploads + `hil-244` job; lock + Discussion CHECK-OUT/IN; remote EN-line reset for `.244` | ends hand-typed bench passes and "is it the latest build" questions |
| P1 | remote-target `interop` and `sipp`; both in ci-glolab for host | real SIP stacks against the real board |
| P2 | `board-soak`, `sanitize`, port-base plumbing (drop the host lock), `anchor` tier, `constrained` profile leg | measurement and hardening |

## 8. Open questions for the crew

1. Any objection to the harness posting on the Discussion thread under its own name?
2. `hil-244` on every `main` push, or dispatch-only until it has run clean ten times?
   Every-push mode also assumes `.244` is not doubling as a phone in use, since flash
   and reboot drop live calls.
3. A remote reset for `.244` (GPIO relay or open-drain MOSFET from glolab on its EN
   line) is a P0 hardware dependency because of #338. A smart plug or USB power switch
   will not do: the board is PoE-fed and its PoE switch is unmanaged (§5.2). Without the
   EN line, unattended flashing is a job that pages a human.
4. The 50% fragmentation tripwire in §5.4 step 7 is a placeholder until `board-soak`
   gives a baseline.
5. A second board means a `--board <name>` registry (ip, by-id path, variant, phone
   extension); one-file change when it arrives.

## 9. P0 status (what PR #360 actually delivers)

Honest delta between this spec and the first implementation, so the doc is not wrong on
day one. Update this table as items land.

| Spec item | State in #360 |
|---|---|
| `tests/run.py` with `unit`, `api`, `callgraph`, `load`, `sanitize`, `board-*`, `anchor`, `all`; results dir + `manifest.json` | done |
| `interop`, `sipp` on host | done; on board `interop` reports SKIP (no remote mode yet, §4) |
| `test_api.sh` board safety | done: `PD_BOARD_ADMIN_PIN`, lockout behind `--allow-destructive`, factory reset only ever with `SERVER_PID` (host) |
| Board lock + hold file (§5.7) | done for every board suite; Discussion CHECK-OUT/IN posts not yet |
| `board-provenance` | `/api/status` version vs `git describe` + `resetReason` only; no boot banner, no binary grep. A version mismatch is **WARN**, not FAIL, until `board-flash` runs before `board-smoke` (#338), so expect a green `hil-244` with a WARN verdict in the manifest |
| `board-smoke` | provenance (recorded), `sip_probe`, `test_api.sh`, `office_smoke.py`, final heap snapshot; no serial capture, no Yealink/Timer B check |
| `board-flash` | esptool `--after no_reset` + config export; no import, no post-flash reset (#338), dispatch-only with a human present |
| `board-soak` | fixed 1 min / 10 s sampler to CSV, no slope verdict |
| `anchor` | credential presence check only |
| CI | firmware bundles uploaded (eth, heap_trace); callgraph step blocking in both host workflows (its first run found #361, fixed in #364); `hil-244` is `workflow_dispatch`-only and runs `board-smoke` without flashing |
| Not started | remote-target interop/SIPp (P1), serial capture, `gtest_discover_tests`, sanitizer CI job, port-base plumbing, Discussion posts |

`board-smoke` still runs `office_smoke.py` unconditionally: DND and forward toggles, a
`POST /api/group`, and the 999 page to every registered phone. Dispatch-only fixed the
trigger, not the behaviour. Whoever dispatches `hil-244` or runs `board-smoke` by hand
owes the CHECK-OUT broadcast; the harness does not post to the Discussion yet.

Prerequisite before the first `hil-244` dispatch: the repo secret `PD_BOARD_ADMIN_PIN`
(the `.244` dashboard password for user `admin`) must exist, or every run fails at
TC-AUTH-04 and cascades.

## 10. Anchor scenarios (`sip_stress.py --scenario <name>`, #384)

`tests/load/anchor_scenarios.py` runs one named scenario against a rig's anchored outside
line and computes its own verdict. Its self-test is `tests/tools/test_anchor_scenarios.py`
(fakes on loopback only). Hardware results are posted on the issues; the first `x4_cancel_ringing`
run (#379) is why its timing, below, changed.

**Closure rule** (desmo's approval, [#384](https://github.com/GlomarGadaffi/pocket-dial/issues/384#issuecomment-5966736679), verbatim):

> The closure rule: a milestone-4 issue closes only when a named scenario in the repo runs on a provenance-checked image (the release stamp, or that commit's `-probe` stamp), its pre-registered path-exercised counter is >= 1 (else the run is INVALID), the script, not a person, computes PASS, and the redacted manifest and log are posted on the issue. A human decision (a re-scope, an approval) is linked as a comment and is never itself the reason to close.

**Scenarios and their pre-registered counters.** A counter is a regex over the board's
syslog. A run whose counter is 0 is INVALID, never PASS.

| Scenario | For | Run | Counter | PASS also needs |
|---|---|---|---|---|
| `x4_cancel_ringing` | #370 (a), #681, #379 (row X4) | 30 calls, 6101 → the designated far end, CANCEL swept 0.6-1.4 s after the ringing reference (see CANCEL timing below), each ≤ 30 s (worst case 25.4 s) | `rx554_window`: `startRxIfNeeded: rx task for <leg> still exiting -- not restarting yet (#554)` or `… had exited -- restarting (#554)` | every call ends 487 (#548), or is a legal 2xx-before-CANCEL race (RFC 3261 §9.1: ACKed, BYEd, counted apart); each initiated leg dropped exactly once; no second rx task on a leg without a #554 restart; no INVITE at 6101 or 6104 except the register beep; no reboot, reset-reason change or coredump change. A call with no ringing reference within 8 s is CANCELled at the timeout and is INVALID (counted); two in a row stop the run, after the drop window (`drop_wait_s`, 5 s) so the last leg's drop line still reaches the capture (#892). A call with no reference whose own leg's GET audio stream opened (`get_open` or `first_chunk` for that leg) is **diverted** (voicemail or another answering service): its own bucket and INVALID reason, and two in a row stop the run naming the diversion (#893) |
| `x379_cancel_before_leg` | #379, #681 | up to 10 calls, 6101 → the designated far end, CANCEL 0.3-0.8 s after the INVITE (before the makecall response, so before the 3CX leg exists), each ≤ 30 s (worst case 23.8 s) | `initiated`: `Successfully initiated call to … (own leg <leg>)` | every call ends 487; the leg is dropped exactly once after its own-leg line (`Successfully dropped participant <leg>`), and no drop fails; no `Inbound call on DN …: participant <leg>` line for that leg; no INVITE at 6101 or 6104 except the register beep (UA and `/api/pcap`); no reboot, reset-reason change or coredump change. A call whose own-leg line came before its CANCEL, or never came, is INVALID (the race was not run). No probe needed |
| `x349_unread_makecall` | #349 | 1 call, 6101 → the far end with `makecall_read_fail` armed, hung up 10 s after the INVITE (≤ 20 s) | `bench_makecall_read_fail`: `BENCHFAULT makecall_read_fail fired` | the probe's `fired` ≥ 1; one `… adopting the call instead of failing it (#349)` line; no INVITE at 6101 or 6104 but the register beep (UA and `/api/pcap`), which also stops the run; no `ORPHANED` and no `makeCall request failed` line; the leg dropped once at hangup (syslog only); sessionCount back to baseline |
| `x379_never_opened` | #379 (PR1) | 1 call, 6101 (Contact `;line=pd6101`) → the far end with `get_status=404` (a 404 is "not ready yet" and keeps the whole budget; a 403 gives up early, #902) and `get_max_attempts=12`, ≤ 30 s | `get_budget_spent`: `GET stream … attempt 12/12` | both faults' `fired` ≥ 1; attempt lines count to `/12`; the board drops the leg once on its own after the spent budget, before any `endCall` of the call (MediaNeverOpened); exactly one BYE at 6101, matching Call-ID and tags, at its registered Contact, answered 200 (UA and `/api/pcap`). A give-up by the transport or rebuild branch is INVALID, with its drop count recorded (#384 S6) |
| `x518_403_clean_giveup` | #518, #379, #902 | the same run with `get_status=403` | `get_403_failfast_902`: `GET stream: HTTP 403 on 6 consecutive attempts for /callcontrol/<dn>/participants/<leg>/stream -- giving up now, not at attempt 12 (#902)` | everything `x379_never_opened` needs, but the give-up is the fail-fast line (6 consecutive 403s, counted before the answer too since #932), not the spent budget; the `GET stream refused (HTTP 403) for …` line (`get_refused_403`, #518) for that leg is still required. Two outcomes are valid (#937): the give-up comes after the answer (one BYE at 6101, as `x379`), or, usually, before it, about 3 s after dial: a final 503 to the caller, no BYE, one drop, `endCall … reason=anchor dropped the leg before it connected` and the `anchor dropped a ringing outbound leg` line (#880). No fail-fast line (the 12 attempts were spent instead) is INVALID; the fail-fast on `x379` (a 404) is a FAIL |
| `x279_degraded_bye` | #279 (Connected variant) | 1 answered call, 6101 sends RTP (Contact `;line=pd6101`); `post_stream_fail` armed 1.5 s after its POST stream opens; the BYE due within 3 s | `degraded_endcall`: `endCall <Call-ID> reason=anchor audio write failure` | `fired` ≥ 1; exactly one BYE at 6101, matching Call-ID and tags, Request-URI = its registered Contact with its parameters, answered 200; the leg dropped once (syslog only); sessionCount back to baseline; a re-INVITE on the dead dialog gets 481 |
| `x952_token_age_held` | #952, #945 | 1 answered call (voicemail counts), 6101 sends RTP (Contact `;line=pd6101`), held `--hold-s` seconds (default 330; it must exceed 300, the old 5-minute token margin, and is at most 900) after `token_age` fires. `token_age` is armed once the call's POST stream is open (`--arm-at mid-call`, the default). `--arm-at before-call` arms it before the INVITE, where `makeCall()` refreshes the aged token at origination, so nothing is aged under a live stream. `--runs` held calls (default 1), at most `--run-cap` (default 1, ceiling 3). The call cap is the hold plus 30 s. The INVITE waits up to 45 s for the far end, or its voicemail, to answer (the agent's default 16 s would CANCEL a far end still ringing toward voicemail), then CANCELs | `bench_token_age`: `BENCHFAULT token_age fired` | `fired` ≥ 1 (the run gives up at once, with no long hold, if it does not fire within 5 s); the call answered with its POST stream open and still up past the old margin; a BYE answered 200 (the harness's, or the PBX's at 6101's registered Contact if it ended past the margin); each leg dropped once; sessionCount back to baseline. A call that ends within the margin is INVALID. **It reports, it does not judge the refresh**: per run the hold reached and the token witnesses below counted from when the token was aged, in `manifest.json` (`summary`) and `run.log`. On main nothing refreshes a token mid-call (`ensureToken()`'s only caller is `makeCall()`, before any stream opens), so by the code the expected counts are `bench_token_age=1` and zeros; anything else is the finding. Needs an `--approval-url` in `LONG_HOLD_APPROVALS` (below) |
| `x888_ws_upsert` | #888 | three synthetic upserts through `handleWsEvent()` with `ws_upsert` armed once per case (1 an unknown participant, no call; 2 the same while 6101's one call to the far end rings; 3 our own leg, no call); case 2 is CANCELled 0.5 s after the fire (one short ring, call cap 1, ≤ 30 s). 911, 933, 113, 1001 and any emergency number are refused as the far end before anything is armed or dialled | `bench_ws_upsert`: `BENCHFAULT ws_upsert fired` | `fired` = 3; each case's branch logs **exactly one** witness line for its own synthetic part id (`pdb-u<case>-<n>`): `Upset dropped, work item not queued` (1), `Upset absorbed while an outbound is in flight` (2), `Upset dropped as own leg with no outbound slot` (3). A branch with 0 lines is INVALID for that case, never PASS; a second line, or a line in another branch for the same upsert, is a FAIL; a synthetic participant in an `Inbound call on DN` line is a FAIL. The call ends 487 (CANCEL answered 200) or, if the far end answered first, is BYEd; the leg is dropped once; no INVITE at 6101 or 6104 but the register beep. One line per case and a summary are printed |
| `h947_http_load` | #947, for #410 | idle, dashboard and dashboard-call runs, `--repeats` (3) of each, at most `--run-cap` (9) runs in all; only dashboard-call rings: 6101 → the designated far end, one call per run held `hold_s` (24 s, inside the 30 s cap), never put on SIP hold; `--call-mode ringing` (default: the far end rings and is not answered, a CANCEL at the window's end) or `answered` | `initiated` (INVALID if 0 when a call was placed) | `answered`: a call that answers and ends once (a harness BYE answered 200, one drop, sessionCount back to baseline); `ringing`: a 180 Ringing seen, the window held for `hold_s`, one CANCEL as it closes answered 200, the INVITE ended 487, no BYE, one drop, sessionCount back to baseline (no 180 is INVALID; a far end that answers anyway is held and BYEd as in `answered`); every dashboard path answers 200 at least once (else INVALID: its handler never ran; a path only the per-source cap refused with 503 is not held against it); no uptime drop inside a run (a reboot is a FAIL); at least one probe answered per run; no panic line; the usual S1/phantom/coredump checks. A slow or refused (503) answer is a measurement, not a failure |

**HTTP under load (`h947_http_load`, #947 for #410).** `tests/load/http_load.py` holds the traffic, the
percentiles and the summary; its self-test is `tests/tools/test_http_load.py`. Every run: a `before` read of
`/api/status`, the dashboard's pollers (the `setInterval` block of `index_html.h`: status 2 s, cdr 5 s,
admin/status 15 s, ota/status 15 s, and with a panel open trace 1.5 s, moh 3 s), a sequential probe of
`GET /api/status` (the #410 `.244` recipe, 200 back to back by default), a burst of concurrent
`GET /api/status` (4 clients by default; the board serves 2 per source and refuses the rest with 503), the rest of
the window, an `after` read. `idle` polls the always-on four; `dashboard` all six; `dashboard-call` all six
with one held call. The pollers send the admin session (a logged-in dashboard's `fetch()` does; cdr, trace and
moh answer 401 without one and never run their handler); the probe and the burst do not. The scenario starts
no `status_logger.sh` (a second poller is load on the thing measured). Runs go lightest first, `--repeats` of
a mode before the next mode, because both watermarks only fall.

What it reads, from `/api/status` as `sendApiStatus` writes it on main: `freeHeapInternal` (a gauge, so its
per-run min and max are the swing), `minFreeHeapInternal` and `stackHwm_http_conn` (since boot, never rise:
a run shows a low-water only if it went below every earlier run, so the summary prints each run's
before and after), `httpConnWorstRoute`, `httpPerSourceRefusals`, `httpReadDeadlineDrops`,
`httpStatusRefusals`, `uptime`. **Not emitted, so never reported:** a peak or active-connection count
(`_activeConnections` has only `activeConnectionsForTest()`), the global 503-busy count (stderr, at powers of
two), a per-request thread cost. Peak concurrency is therefore the harness's own: the most served requests
(any answer but 503) in flight at once from the one address it runs on, which is at most the per-source cap.
It is printed twice per run: `polls` (the dashboard's own traffic alone, where "an open dashboard reaches the
per-source cap by itself" would show) and `all` (with the harness's probe, burst, reads and S1 checkpoints), with
the 503 counts split the same way.
During a call the S1 checkpoint (`GET /api/did-mapping` and an authed status) is skipped while the burst holds
every slot and tried again, up to 3 times, after a 503; a probe or poll landing on the same instant can still
clash. A reboot is a FAIL inside a run or between two runs (the watchdog `status_logger.sh` used to be the
only check for it). A SIP reply time during the burst (#947 item 3) is not measured. p50 and p99 are nearest-rank
(`sorted[ceil(p·n/100) − 1]`, integers); p99 of fewer than 100 samples is the maximum and the summary says so.
`stackHwm_http_conn` is the smallest free stack any connection thread has had, of `kHttpConnStackBytes`
(4096); the summary prints the lowest reading with the log line it came from (`http-load.jsonl`) and the route
that produced it. A reading within an hour of boot is flagged (#405): re-read after hours of use.

**Call mode** (`--call-mode`, default `ringing`). A far end that only rings (a 180, never answered) was INVALID
before this flag: the agent's own 16 s INVITE bound CANCELled it before the window ran at all. It is a valid
`dashboard-call` in `ringing` mode: the INVITE waits on a thread for `hold_s + 2` s (the agent's
`invite(invite_timeout=)`, the call cap still 30 s), the dashboard window runs on the run's thread for `hold_s`
from the INVITE, and the CANCEL goes at the planned hold, INVITE + `hold_s`, not when the window's teardown ends
(its pollers can sit in a 5 s request on a slow board, and the ring must not outlast the hold); or at once if the
window is cut short: a phantom, a signal, a lapsed pin. There is no dialog, so no BYE (RFC 3261 s9.1); the far side must answer the CANCEL 200 and the
INVITE 487 (s9.2), else a FAIL. The call is valid only with a 180 Ringing seen before the window closed and the
window held for the planned hold (`http_load.ringing_call`; the reason is on the run's summary line and in the
verdict: `| call ringing: valid, 180 Ringing at +6 ms, window held 24.0 s, CANCEL at +24020 ms answered 200,
INVITE ended 487, no BYE`, or `INVALID, no 180 Ringing seen ...`). A final before the planned hold (486, 503,
a 487 nobody asked for) is INVALID, since the ring did not last the hold; the syslog (for the pre-answer drop,
`anchor dropped a ringing outbound leg`) says who ended it. **The 180 is the PBX's own local ringback**,
sent at INVITE time (see CANCEL timing below): it does not show the far phone alerting; the `initiated` path
counter and the one drop line are the only evidence of the anchored leg. A 200 in ringing mode is the answered
case: the window still runs to `hold_s`, then the harness BYEs. `answered` is the previous behaviour, unchanged:
the far end must answer, else INVALID. The ring is bounded the same either way: one INVITE,
`hold_s` (24 s) plus the CANCEL round trip, and at worst `hold_s` + 2 s (the CANCEL's own backstops: +1 s if the
window overruns, +2 s if no provisional ever arrives), inside the 30 s cap; the ring gate refuses 911, 933, 113,
1001 and the rest before the INVITE in both modes.

Ring OK is per run with a cap. `--run-cap` (default 9, at most 30) bounds the runs in all: modes × repeats past
it is refused before anything is sent, and the run loop takes one budget unit per run and stops at the cap.
Only `dashboard-call` rings, once a run, and `calls` follows the plan (at most 10). The far end carries every
refusal above (911/933 anywhere in it, 112, 113, 999, 1001-1003, PBX numbers), and the ring itself checks it
again just before the INVITE. Evidence adds `http-load.jsonl` (every request and every status reading, raw)
and `http-summary.txt`.

**CANCEL timing.** 3CX's makecall response took 1.8-3.2 s on a real tenant (Stray's corrections on
[#379](https://github.com/GlomarGadaffi/pocket-dial/issues/379#issuecomment-5985894096) and
[#681](https://github.com/GlomarGadaffi/pocket-dial/issues/681#issuecomment-5985894278) withdraw the rest of
that first report), so a CANCEL timed from the INVITE always lands before the 3CX leg exists.
`x4_cancel_ringing` times it from a ringing reference instead. The PBX's 180 is local ringback sent at
INVITE time, before the 3CX call is requested (`RequestsHandler.cpp`, `originateAnchorCall`), and no 183 or
early RTP follows, so no SIP message says the far leg rings. The reference is the first syslog line
`Upset <leg> -> control leg <leg> status '<not Connected>'` for a leg this INVITE started: 3CX lists our leg
and it is not yet Connected, which the firmware itself calls ringing (#667). It does not prove the far phone
is alerting. No reference within 8 s: the call is CANCELled at the timeout and is INVALID; a refusal first (a
503) is still a FAIL. `x379_cancel_before_leg` keeps the old timing on purpose.

**A person's phone as the far end makes x4 unreliable** (#893). On `1446405a` desmo's cell diverted repeat
calls to voicemail: the far end's audio opened at once, no `Dialing` upsert came, and runs stopped on
diverted calls with gaps of 12 s (x4's default `gap_s`) and 60 s alike. The diversion is a property of the
far end's state, not of this harness. The reliable fix is an automated far end (a non-owner 3CX extension
answered by a harness UA), which needs desmo and the tenant; until then a diverted run is INVALID, not a
firmware finding.

**Probe scenarios** (`x349`, `x379`, `x518`, `x279`, `x952`, `x888`) drive the bench probe image
([BENCH_PROBE.md](BENCH_PROBE.md)). On top of the preconditions below, `--expect-version` must be
a `-probe` stamp, and the admin login must be the owner when an owner credential exists
(`PD_BOARD_ADMIN_USER`). Each run reads `/api/bench/fault` before and after, and arms only its
pre-registered faults: never for an emergency far end, and never while the probe reports an
emergency. It disarms every fault and releases the ballast in a `finally`, then reads the counters
back. If anything is still armed or held, if a fault shows `fired: 0`, or if an emergency touched the
probe, the run is INVALID. Syslog carries `esp_log` lines only. RequestsHandler's `queueLog()`
lines go to stdout (#533/#603), so the counters use the `endCall … reason=` and anchor-client lines.
`get_max_attempts=12` puts the worst-case handset BYE at about 25 s. That is 50-400 ms of backoff,
then 500 ms per attempt, plus a TLS reconnect of up to 1.3 s per attempt once the forced 403 closes
a real 200, so it fits the 30 s call cap. The Held variant of `x279` and `x350`/`x336` are not
registered.

**Path witnesses.** One `esp_log` line per fixed path (`src/SIP/Witness.hpp`: `ESP_LOGx` on the board,
a list a host test reads on the host), each registered in `LOG_COUNTERS` so a scenario can pre-register
it as its path counter. No witness carries a number, a URI user or a credential.
`tests/tools/test_anchor_scenarios.py` (`WitnessSampleTest`) checks every regex below against the line
the firmware formats.

| Counter | Line (regex) | Path |
|---|---|---|
| `adopted_349` | `but 3CX has our leg (\S+) .*adopting the call instead of failing it \(#349\)` | #903: an unread makecall response reconciled to our own leg |
| `orphaned_349` | `a call may be ORPHANED on 3CX \(#349/#328\)` | #903: no response and no reconcilable leg after every re-read |
| `adopt_reread_349` | `makeCall: no leg listed yet \(list status=-?\d+, read (\d+):` | #903: one adopt re-read that found no leg yet, with what the list held |
| `e911_notify_uri` | `e911: notify MESSAGE Request-URI: (registered Contact\|bare \(no Contact stored\))` | #904 review: a 911/933 notify MESSAGE addressed at the phone's registered Contact (or the bare form when none is stored) |
| `trunk_final_tag_896` | `trunk: final (\d+) To-tag differs from the early dialog's: the final's defines it \(#896\)` | #896: a forking carrier's final (the PSAP's 200 for a 911) defines the dialog its ACK and BYE use |
| `sdp_gate_yield_897` | `SDP gate yielded '([^']+)' for a trunk answer to our emergency INVITE \(#897\)` | #897: a PSAP's 1xx/200 that trips any checkSdp() verdict is ACKed and connects instead of being dropped |
| `anchor_drop_ringing_880` | `anchor dropped a ringing outbound leg: final 503 to the caller, no BYE(, NOT ROUTED sent)? \(#880\)` | #880: CallEvent::Dropped on a ringing outbound anchored call (a 911 also gets one NOT ROUTED) |
| `e911_not_routed` | `e911: NOT ROUTED correction: (.+)` | #879/#880: every NOT ROUTED correction (trunk refusal or timeout, anchor drop, trunk answer exits, early carrier BYE) |
| `trunk_911_exempt_889` | `trunk: 911/933 dialog held past its no-answer bound: a provisional came, no PBX-side timeout \(#712, #889\)` | #712/#889: a trunk 911/933 that drew a provisional is not timed out; once per dialog |
| `stray_final_890` | `trunk: final (\d+) after the call was answered ignored \(#890\)` | #890: a carrier final after the 2xx is ignored, the call stays up |
| `beep_uri_856` | `beep: register beep Request-URI: (registered Contact\|bare \(no Contact stored\))` | #856: which form the register beep's Request-URI took |
| `upset_ignored_pending_888` | `Upset ignored while (\d+) makeCall\(s\) pending \(oldest (-?\d+) ms old\): nin=\d+ active=\d+ part=\S+: 3CX does not repeat a Connected one \(#888\)` | #888: an upsert ignored while a makeCall was pending (nin is 0 here by construction; active = outbound slots with a call; part = the upsert's participant id). The pending age shows the window. Not rate-limited: bounded by the pending window. ESP-only |
| `upset_absorbed_inflight_888` | `Upset absorbed while an outbound is in flight: nin=(\d+) pending=(\d+) active=(\d+) part=(\S+) own=(\S+) seen=(\d+) \(#888\)` | #888: an unmatched upsert mapped to an in-flight outbound leg (nin >= 1), so a route-point inbound or PSAP callback would be taken as that far leg. `own` is the in-flight leg's id: distinct from `part` means the far leg has its own partId. Rate: one sighting per upsert, per partId the first and every 16th (`seen`), with a 256-line cap per boot shared by the #888 witnesses other than the pending one (`witness_cap_888` marks it). An upsert that is also unqueued is logged once, as `upset_dropped_unqueued_888`. ESP-only |
| `upset_dropped_own_leg_888` | `Upset dropped as own leg (?:with no outbound slot\|at the worker re-check): nin=(\d+) pending=(\d+) active=(\d+) part=(\S+) seen=(\d+) \(#888\)` | #888: an unmatched upsert dropped as one of our own legs with no outbound slot (#379), in handleWsEvent or at the worker re-check. Same rate limit. ESP-only |
| `upset_dropped_unqueued_888` | `Upset dropped, work item not queued: nin=(\d+) pending=(\d+) active=(\d+) part=(\S+) seen=(\d+) \(#888\)` | #888: an unmatched upsert whose work item was not queued (queue full or no allocation) for at least one of its legs, so it was lost before the worker. One sighting per upsert, after the leg loop. Same rate limit. ESP-only |
| `witness_cap_888` | `witness cap reached: no further #888 witness lines this boot` | #888: the 256-line per-boot cap on the absorbed, own-leg and unqueued witnesses was hit; logged once per boot, then those witnesses stay silent until reboot. ESP-only |
| `e911_degraded_kept_906` | `e911: audio to the anchor keeps failing on a connected 911/933: kept up, not hung up \(#906\)` | #906: the degraded-audio sweep kept a connected 911/933 up and told the notify list (once per call) |
| `get_403_failfast_902` | `GET stream: HTTP 403 on (\d+) consecutive attempts for /callcontrol/<dn>/participants/([^/\s]+)/stream -- giving up now, not at attempt (\d+) \(#902\)` | #902/#932: 6 consecutive 403s, before the answer or after it, gave up an ordinary outbound leg early (MediaNeverOpened follows). ESP-only |
| `cdr_callee_dialed_901` | `CDR callee is the dialed number \((anchor reap\|anchor audio write failure)\) \(#901\)` | #901: the degraded (audio write failure) and reaped anchor teardowns write the dialed number as the CDR callee |
| `bench_token_age` | `BENCHFAULT token_age fired` | #952: the probe aged the token (`BenchProbe.cpp`, `fire()`); `x952`'s path counter |
| `token_refresh_near_expiry` | `Access token near expiry \S+ refreshing` | #952: `ensureToken()` refetched a token within 5 minutes of expiry with no stream live (only at `makeCall()`). The dash is U+2014 on the board |
| `token_refresh_deferred_live` | `Token near expiry but media streams active \S+ deferring refresh` | #952: `ensureToken()` found the token near expiry while a stream was live and kept it (reached only by a `makeCall()` while another call is up). U+2014 dash |
| `token_retrieved` | `Retrieved access token \(len=\d+, lifetime=(\d+)s\)` | #952: a token fetch succeeded; group 1 is the lifetime in seconds |
| `token_fetch_failed` | `Token (?:request returned HTTP -?\d+\|failed to write body: -?\d+\|HTTP connection failed to open: )` | #952: a token fetch failed |
| `ws_restart_stale_token` | `WS disconnected/errored with an expiring token \S+ requesting anchor restart to refresh it` | #336/#952: the websocket dropped while the token read as expiring, so the anchor restarts (stop/start) to refetch it. U+2014 dash |
| `ctrl_request_884` | `ctrl request: attempt (\d+) (reused\|resumed\|cold) in (\d+) ms \(#884\)` | #884: one line per successful control request (drop or answer) saying whether it rode an open socket (`reused`, no connect event), reconnected on the kept handle in 400 ms or less (`resumed`) or paid a full handshake (`cold`: a fresh handle, or a connect above 400 ms, which is the repo's cut and a timing heuristic, not proof of resumption). Group 3 is the elapsed ms. After #884 a `reused` is a bug. A failed attempt logs `Control request failed ... on attempt N` instead. ESP-only |

The six `bench_token_age` … `ws_restart_stale_token` rows are existing `esp_log` lines on main, not
`Witness.hpp` witnesses; `tests/tools/test_anchor_witness_wiring.py` checks each one's format string in
`TelephonyAnchorClient.cpp` and `BenchProbe.cpp`. The #862 witnesses (`token_maint_refresh_862`,
`token_maint_skip_862`, `token_sos_live_fetch_862`, `token_sos_401_fetch_862` and the rest) are not emitted
on main, so they are not registered or counted here; add each one, with its wiring test, when the code that
emits it lands. The two `token_sos_*_862` lines fire only on a 911/933 POST answered 401, which no scenario
here dials, so `x952` could never count them.

**Safety preconditions.** Each one is refused before anything is sent (exit 2), except
the S1 pin and the far-end check, which are made against the board:

- a discussion #428 CHECK-OUT link whose expiry covers the run;
- `--approval-url` is one of the recorded approvals (`APPROVALS`: the #384 comment above and
  discussions/451 18621141) or `EXTRA_APPROVALS`;
- the far end comes from a 0600 file (`PD_ANCHOR_FAR_END_FILE`) or from `PD_ANCHOR_FAR_END`,
  never from argv. It is refused if it holds 911 or 933 anywhere, or is 112, 113, 999, an owner
  extension (1001, 1002, 1003, 113, plus `PD_OWNER_EXTS`), a test UA or a PBX service number;
- **a held call** (`x952`): the recorded approvals allow about 30 s a call, so `--approval-url` must be in
  `LONG_HOLD_APPROVALS`, which is empty until desmo's OK for a call that long is recorded and a reviewed PR
  adds its link (an old approval never covers it, and a held approval covers no other scenario).
  `--hold-s` must be finite, over 300 s and at most 900 s; `--runs` may not exceed `--run-cap` (1 by default,
  at most 3). The flags are refused on every other scenario. The ceiling of 30 s a call (`MAX_CALL_S`) is
  unchanged for them. The far end is refused like any other: 911, 933, 113 and 1001 included. Immediately
  before every INVITE the probe's `emergencyLive` is read again (it covers a 911/933 and a session in a
  PSAP-callback window, BENCH_PROBE.md), and a live one stops the run INVALID. The scenario never dials one;
- the board is `.195` or `.244`, and the admin PIN comes from `PD_BOARD_ADMIN_PIN`;
- `--expect-version` names the image (the provenance the closure rule needs); the board's
  `/api/status` version must match it, or the run is INVALID before the first call;
- the test UAs are 6101-6104 only, and 6104 is the phantom detector;
- the S1 pin: a DID row maps the active anchor slot's route DN to 6104, and the authenticated
  roster shows 6104 at this run's own address. It is checked before the first call, between
  calls and while idle. A lapse stops the run as INVALID, because a lapsed pin falls back to
  ring-all.
- the far end must not route back into this board: a far end equal to the active slot's route DN, or to
  the DID or the extension of any `/api/did-mapping` row (compared as numbers, E.164-equivalent), is
  INVALID before the first packet and again if a row appears between calls. The board exposes its route
  DN and its DID rows, not the tenant's own inbound numbers, so a far end that is one of those cannot be
  caught here, and every phantom verdict says it is a firmware finding only if the far end cannot route
  back. Confirm the far end first.
- **RING-REQUIRED**: until the far end is confirmed automated, a run against real 3CX needs
  desmo's OK for that run. The script prints this but does not enforce it.

**Evidence.** With `--set-syslog`, the board's syslog points at the run's UDP listener
(default port 5514), and the old setting is restored afterwards. `/api/pcap` is pulled after
every call, because the ring holds 16 messages. Every text output is redacted, including the
far end, the PIN, the session and the tenant host. The pcap is masked at the same length and
still holds LAN addresses, so never post it.

Exit codes match `run_soak.py`: 0 PASS, 1 FAIL, 2 refused, 3 INVALID, 4 ABORTED.
