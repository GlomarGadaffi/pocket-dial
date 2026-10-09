# Bench probe image (`POCKETDIAL_ANCHOR_BENCH_PROBE`)

Issue #384, harness hook H1. A bench-only firmware image that injects one-shot
faults into the 3CX anchor client and holds a controlled amount of internal DRAM,
so a rig scenario can drive the paths behind #349, #279, #336, #518, #379 and the
pressure runs for #350/#370 on purpose instead of waiting for them.

**Never ship it. Never leave it on a rig.** Every run that flashes it ends by
putting a release image back, and CHECK-IN (#428) verifies the board reports a
release stamp again. That check is the operator's job.

## Building it

```
idf.py -D SIP_TRANSPORT=eth -D POCKETDIAL_ANCHOR_BENCH_PROBE=1 set-target esp32s3
idf.py -D SIP_TRANSPORT=eth -D POCKETDIAL_ANCHOR_BENCH_PROBE=1 build
```

- Configure prints a `CMake Warning` naming the probe image.
- Configure **fails** unless `SIP_TRANSPORT=eth` and `SIP_CONSTRAINED` is unset.
- The version stamp ends in `-probe` (`<describe>-probe`, or `<describe>-probe-dirty`;
  the short-hash form when the describe would not fit 31 characters). So
  `tools/ci/check_app_version.py --repo` and `tools/soak/run_soak.py` can never accept
  a probe image as this checkout's release candidate.
- Use a separate build directory (`-B build-probe`): the option stays in that
  directory's `CMakeCache.txt`.
- For #350 pressure runs, add `-DSDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.heap_debug"`
  (COMPREHENSIVE poisoning) to both commands.

A release build carries none of it: every probe line in `src/` and `main/` sits under
`#if defined(POCKETDIAL_ANCHOR_BENCH_PROBE) && defined(ESP_PLATFORM)`, and
`src/SIP/BenchProbe.cpp` compiles to nothing without it. Two checks hold that:

- `tools/ci/check_no_bench_probe.py <build-dir>` fails if the app image contains
  `BENCHFAULT` or `/api/bench/fault`, if the cache has the option on, or if the
  stamp carries `-probe`. The ESP build matrix in `ci.yml` and every `release.yml` build run it.
- `tests/tools/test_bench_probe_release.py` checks the source on any host: probe
  lines only under the guard, the CMake refusals present, no workflow passing the option.

## The API

Only on the probe image. Owner-gated like `/api/coredump` (a session cookie from
`POST /api/admin/login`; never put a credential in a URL or a log). A `POST` is
CSRF-checked (the session's `X-CSRF` header). Bodies are form-encoded.

| Request | Effect |
|---|---|
| `GET /api/bench/fault` | the counters (below) |
| `POST fault=<name>` | arm that fault, one-shot |
| `POST fault=<name>&value=<n>` | arm a fault that takes a value |
| `POST fault=disarm` | disarm every fault |
| `POST ballast=<bytes>[&deadman=<s>]` | hold DRAM until free internal heap is at most `<bytes>` |
| `POST ballast=release` | release the ballast now |

Answers: `200` with the counters; `400` for an unknown fault or a bad value; `409`
while an emergency call is live, or when a ballast is already held; `503` when the
dead-man timer cannot be created.

## Faults

Each is **one-shot**: arming it once makes it fire once, and each firing logs one
line `BENCHFAULT <name> fired` and bumps its `fired` counter. `fired` is the
scenario's "path exercised" counter: a run whose fault shows `fired: 0` is INVALID.

| Name | Value | Where it fires | Effect | Serves |
|---|---|---|---|---|
| `makecall_read_fail` | none | `makeCall()`, after a POST that reached 3CX succeeded | the response is dropped: `success=false`, `status=-1`, no body, `requestSent=true`. This is what an unread response leaves, so the #349 reconcile path runs. | #349 |
| `get_status` | 400-599 | the next outbound call's GET stream (the leg `makeCall()` claimed) | every real answer on that stream reads as `<value>`; a real 200 is closed unread (its body is the live audio and would never drain). Transport failures stay real. | #518, #379 |
| `get_max_attempts` | 1-240 | the same GET stream | its attempt budget becomes `<value>`, so a refusal give-up and MediaNeverOpened fit a short call | #518, #379 |
| `post_stream_fail` | none | the next `writeAudio()` on any live POST stream | `shutdown()` of that stream's socket: that write and every later one fails until the bridge gives up | #279 |
| `token_age` | none | the anchor's next tick, if it holds a token | the token's obtained-at stamp moves back one lifetime, so `tokenExpiringSoon()` is true | #336 |
| `ws_upsert` | 1-3, the case | the anchor's next tick at which the case can happen ([below](#ws_upsert-888)) | one synthetic WS upsert goes through `handleWsEvent()`, the function a 3CX frame takes, to reach one #888 witness branch on purpose | #888 |

Notes:

- `makecall_read_fail` acts in `makeCall()` on what `httpPostBody()` returned, not inside
  `httpPostBody()`. That function does not know the destination, so it cannot apply
  the emergency rule. `makeCall()` receives the same values either way.
- Do not hold ballast while `makecall_read_fail` is armed: if the reconcile list GET
  then fails too, the call is the #349 ORPHAN variant (a live billable leg on 3CX),
  which the approval excludes.
- `get_status` and `get_max_attempts` apply only to an outbound leg that `makeCall()`
  claimed. An inbound call, including a PSAP callback, is never the forced one.
- After a `get_status` 200 is closed, the next attempt reconnects and pays a TLS
  handshake. Size `get_max_attempts` for a short call: about 20-40 attempts.
- **`ws_drop` is not implemented.** `esp_websocket_client` (1.8.0) has no documented
  way to drop the transport and keep the library's own reconnect, which is the
  DISCONNECTED/ERROR path #336 needs. `esp_websocket_client_stop()` and `_close()`
  end the client, cannot run from its event handler, and expose no socket. Variant A
  of `x336_ws_reauth` needs another way to cut the WS (for example, at the network).

**Validity:** app-level faults are **not** evidence for #350. That bug lives in
mbedTLS's failed-read state, and only ballast or a real network fault reaches it.

### `ws_upsert` (#888)

`POST fault=ws_upsert&value=<case>` arms one injection. On the anchor's next 1 Hz tick at which the case
can happen (`TelephonyAnchorClient::benchWsUpsert()`, on the SIP task, where `token_age` runs), the probe
builds the frame `{"event":{"event_type":0,"entity":"/callcontrol/<dn>/participants/<id>","attached_data":{}}}`
with `<dn>` the anchor's source DN, and hands it to `handleWsEvent()` as a text frame. The JSON parse, the DN
check, `parseParticipantEntity()` and the classification are the real ones, not a copy. The participant id is
the probe's own, `pdb-u<case>-<n>` (`n` counts injections since boot), so a witness line says which upsert made
it (`part=pdb-u2-3`) and is the first sighting of its id, which is the one that logs.

| Case | Waits for | The upsert | Branch it reaches | Witness line it makes |
|---|---|---|---|---|
| 1 | no outbound slot, no makeCall pending | an unknown participant, no call | the work item is **not queued** | `Upset dropped, work item not queued: nin=0 pending=0 active=0 part=pdb-u1-<n> seen=1 (#888)` |
| 2 | an unanswered outbound leg in flight (`nin >= 1`): the makecall response has named the leg | an unknown participant while that leg rings | **absorbed**: mapped to the in-flight leg | `Upset absorbed while an outbound is in flight: nin=1 pending=0 active=1 part=pdb-u2-<n> own=<leg> seen=1 (#888)` |
| 3 | no outbound slot, no makeCall pending | a participant registered as our own leg | the **own-leg** drop (#379) | `Upset dropped as own leg with no outbound slot: nin=0 pending=0 active=0 part=pdb-u3-<n> seen=1 (#888)` |

- **A case that cannot happen yet waits, still armed.** It is never forced: a case 2 armed with no call in
  flight fires when a call is, and a case 1 or 3 armed during an outbound call fires after it. `fired` counts
  injections, so a case that never became possible shows `fired` unchanged and the scenario calls it INVALID.
- **Case 1 and the enqueue.** The work queue has no failure a probe can drive without also starving the
  workers (they drain it at once). So `enqueueWsWork()` refuses a work item whose participant is a `pdb-u` id
  and whose control leg is that participant itself, which is what an unknown participant with no call maps
  to, and answers false after freeing the item: the same `delete item; return false` a full queue takes. The
  `xQueueSend` failure itself is not exercised. The same rule means a synthetic participant is never queued as
  an inbound call, the one thing that would ring the route DN's phones, even if the call in case 2 ends between
  the tick's check and the classification (the upsert then reads "not queued" and the case is INVALID, not a
  ring). Case 2's item is queued, mapped to the in-flight leg: the worker runs its status check on that leg
  (one extra participant-list GET on the real call), as it does for any upsert.
- **Case 3 and the own-leg table.** The id is noted in `_ownLegs` (#379) before the injection and released
  after it, with the next WS event number, as 3CX's Remove does. It occupies one of the table's 8 entries
  for those microseconds and may displace the oldest real one, so it waits for an idle anchor.
- **Counters.** `faults.ws_upsert.fired` (injections), `.emergencySkips`, and the top-level `refusedArms` and
  `emergencyDisarms`, as for every fault. Logs: `BENCHFAULT ws_upsert armed (value <case>)`, then on the tick
  `BENCHFAULT ws_upsert fired` and `BENCHFAULT ws_upsert case <case>: injecting part=<id>`, then the witness
  line. If the 256-line per-boot witness cap was already reached there is no witness line (`witness cap
  reached`), and the case reads INVALID.
- **Refusal (rule 5, the same policy as every fault).** Arming while an emergency is live is answered `409`,
  counted in `refusedArms` and logged `BENCHFAULT ws_upsert arm refused: emergency call live`. A fire site
  reached while an emergency is live, or for an emergency destination, injects nothing, disarms every fault,
  counts `emergencySkips` and logs `BENCHFAULT ws_upsert refused: emergency call, every fault disarmed`.
  An emergency that begins while it is armed disarms it at once (`every fault disarmed: emergency call`).
  The harness also refuses 911, 933, 113 and 1001 as the far end, and any emergency number in any form,
  before it arms or dials.
- **One ring (case 2).** The scenario `x888_ws_upsert` places **one** call to the designated far end, arms
  before the INVITE, and CANCELs 0.5 s after the `BENCHFAULT ws_upsert fired` line (or at 10 s if it never
  comes), so the far end rings once and briefly. Its call cap is 1. Cases 1 and 3 place no call. It counts
  the witness line of each case by the exact text above and the case's part id; a case with 0 lines is
  INVALID, never PASS. Far end only: no owner extension, no test UA, no service number.

## Ballast

`ballast=<bytes>` takes `heap_caps_malloc(MALLOC_CAP_INTERNAL | MALLOC_CAP_DMA)`
blocks (4 KB, halving on fragmentation down to 64 B, at most 256 blocks) until
`heap_caps_get_free_size(MALLOC_CAP_INTERNAL)` is at most `<bytes>`.

- The floor is 8192: a lower target is refused.
- The dead-man (`deadman`, 1-600 s, default 120) releases the ballast by itself, on
  an `esp_timer`, with the SIP tick as a backstop. There is no ballast without a dead-man.
- A second arm while one is held is refused; release it first.
- The counters report what was actually held and the free heap after: fragmentation
  can stop short of the target.
- Ballast can starve unrelated tasks. That is the point, and why the dead-man exists.

## Rule 5: 911 and 933 come first

- **No arming during an emergency.** Nothing arms, and no ballast is taken, while
  any 911/933 session (or PSAP callback window session) is live. The answer is `409`.
- **No firing for an emergency.** A fault never fires for a destination that
  `pbx::classifyEmergencyDial()` marks emergency, or while any emergency session is
  live. Reaching a fault site in either case disarms **every** fault and counts an
  `emergencySkips` for that fault.
- **Everything stops at once.** An emergency stops the probe immediately, from any
  of three sources:
  - `Session::setEmergency(true)`, which covers every caller;
  - a 911/933 `makeCall()`, at its first line before any I/O;
  - the once-a-second session level.

  Stopping disarms every fault, drops the GET claim, releases the ballast
  (`released.emergency`) and undoes a `token_age` that no token fetch has replaced.
  Undoing it keeps `ensureToken()` from refetching ahead of the 911.
- **A fill in progress gives way.** A ballast fill checks the emergency gate before
  every block, and gives everything back if an emergency appears mid-fill.

None of this has been exercised with a real emergency call, and it must not be.
The host tests pin the decisions (`tests/BenchProbeLogic_test.cpp`).

## Counters

```json
{"image":"anchor-bench-probe","emergencyLive":false,"refusedArms":0,"emergencyDisarms":0,
 "faults":{"makecall_read_fail":{"armed":false,"value":0,"fired":1,"emergencySkips":0}, "...": {}},
 "ballast":{"held":true,"bytes":204800,"blocks":50,"target":65536,"deadmanS":120,
            "released":{"api":0,"deadman":0,"emergency":0},"refusedEmergency":0},
 "freeInternal":65410}
```

The counters live in RAM and reset at boot.

## Not verified

Written and host-tested without a board: no rig, no 3CX, no phone. The ESP glue
(`src/SIP/BenchProbe.cpp` and the `#if` blocks) has only been compiled. Every
scenario's first run is also the first run of the probe on hardware.

`ws_upsert` and `x888_ws_upsert` (#888) are newer still: the probe arm (`benchWsUpsert()`, the `enqueueWsWork()`
refusal, the `tick()` call) was syntax-checked with the release build's compile flags plus
`-DPOCKETDIAL_ANCHOR_BENCH_PROBE=1`, never linked into a probe image, and its stack use on the SIP task is
unmeasured. The scenario has run only against the fake board in `tests/tools/test_anchor_scenarios.py`
(`X888Test`), whose `ws_upsert` is a model of this section, not the firmware.
