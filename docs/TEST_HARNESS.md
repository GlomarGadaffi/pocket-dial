# pocket-dial Test Harness — Specification

Status: DRAFT for crew review (2026-09-20).
Scope: one entrypoint that runs every existing verification layer against either the
**host** build or a **board**, plus a hardware-in-the-loop (HIL) job on the glolab runner.
Nothing here replaces a script that already works.

## 0. What exists today (measured on `d92fd2d`, not copied from docs)

| Layer | Where | Runs in CI? | Target |
|---|---|---|---|
| GoogleTest suite, 95 files / 1191 cases, one ctest target `sip_parser_tests` | `tests/` | yes (ci.yml, ci-glolab.yml) | host |
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
   writes a `gen_provision_nvs.py` image at 0x9000. glolab is esptool 4.7.0 (underscore
   arg names, no S3 stub JSON, hence `--no-stub`).
   **`--after no_reset` is mandatory.** Issue #338 (open) shows that esptool's hard,
   watchdog and RTS resets can park this board in ROM download mode until someone
   power-cycles it. The reset after a flash must come from a remotely switchable power
   path, which is a P0 hardware dependency (§8). Until it exists, `board-flash` is
   dispatch-only with a human at the bench.
5. Power-cycle, start capture, poll `/api/status` up to 60 s.
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
quote. Profiles matter: `heap_trace` builds are for the #331 periodic dump, and only a
`default` build is a valid target for the #328/#330 zero-alloc proof.

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
| P0 | `tests/run.py` with `unit`, `api`, `callgraph`, `board-flash`, `board-provenance`, `board-smoke`; artifact uploads + `hil-244` job; lock + Discussion CHECK-OUT/IN; remote power-cycle for `.244` | ends hand-typed bench passes and "is it the latest build" questions |
| P1 | remote-target `interop` and `sipp`; both in ci-glolab for host | real SIP stacks against the real board |
| P2 | `board-soak`, `sanitize`, port-base plumbing (drop the host lock), `anchor` tier, `constrained` profile leg | measurement and hardening |

## 8. Open questions for the crew

1. Any objection to the harness posting on the Discussion thread under its own name?
2. `hil-244` on every `main` push, or dispatch-only until it has run clean ten times?
   Every-push mode also assumes `.244` is not doubling as a phone in use, since flash
   and reboot drop live calls.
3. Remote power-cycle for `.244` (smart plug or relay reachable from glolab) is a P0
   hardware dependency because of #338. Without it, unattended flashing is a job that
   pages a human.
4. The 50% fragmentation tripwire in §5.4 step 7 is a placeholder until `board-soak`
   gives a baseline.
5. A second board means a `--board <name>` registry (ip, by-id path, variant, phone
   extension); one-file change when it arrives.
