# Bench probe image (`POCKETDIAL_ANCHOR_BENCH_PROBE`)

Issue #384, harness hook H1. A bench-only firmware image that injects one-shot
faults into the 3CX anchor client and holds a controlled amount of internal DRAM,
so a rig scenario can drive the paths behind #349, #279, #336, #518, #379 and the
pressure runs for #350/#370 on purpose instead of waiting for them.

**Never ship it. Never leave it on a rig.** Every run that flashes it ends by
putting a release image back, and CHECK-IN (#428) verifies the board reports a
release stamp again. That check is the operator's job.

A second, unrelated bench option, `POCKETDIAL_HTTP_DRAM_ACCOUNT` (#410, #328), is described
at the end: [HTTP DRAM accounting](#http-dram-accounting-pocketdial_http_dram_account).

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

## HTTP DRAM accounting (`POCKETDIAL_HTTP_DRAM_ACCOUNT`)

Issues #410 and #328. A bench-only reading, not a fix. Under HTTP load alone `.244`'s
`minFreeHeapInternal` fell from 31567 B to 475 B (#947), and nothing said which part of the
HTTP path held the bytes. This build option adds one field to `GET /api/status`,
`httpDramAccount`, that does. Release behaviour is unchanged: the option defaults to `0`
(`src/SIP/PoolConfig.hpp`), every line it adds sits under `#if POCKETDIAL_HTTP_DRAM_ACCOUNT`
in `src/Helpers/HttpServer.cpp`, and with it off the field is absent
(`HttpStatusAlloc.TheStatusKeyListIsPinned...` pins the key list of the response).

### Building it

Take the board's usual release build line and add the option; use a separate build directory,
because the cache keeps it:

```
idf.py -B build-acct -D SIP_TRANSPORT=<the board's transport> [-D PD_ETH_BOARD=<board>] \
       -D POCKETDIAL_HTTP_DRAM_ACCOUNT=1 set-target <esp32s3 | esp32>
idf.py -B build-acct -D SIP_TRANSPORT=<the board's transport> [-D PD_ETH_BOARD=<board>] \
       -D POCKETDIAL_HTTP_DRAM_ACCOUNT=1 build
```

- Not tied to a transport or to `SIP_CONSTRAINED`, unlike the anchor probe above. Configure
  prints a `CMake Warning` naming the image.
- The version stamp is **not** changed, so `tools/ci/check_app_version.py` and the soak runner
  would accept this image as a release candidate. The field is how you tell: a release image has
  no `httpDramAccount`. Flash a release image back when the run is over.
- The host equivalent is `-DCMAKE_CXX_FLAGS=-DPOCKETDIAL_HTTP_DRAM_ACCOUNT=1`.
- For the lwIP pool counters (`memp` below) add the overlay, the way the constrained profile
  adds its own, and start from a **fresh** build directory (a directory that already has an
  `sdkconfig` keeps its old values and the overlay is not applied):

  ```
  idf.py -B build-acct -D SIP_TRANSPORT=<...> -D POCKETDIAL_HTTP_DRAM_ACCOUNT=1 \
         -DSDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.accounting" set-target esp32s3
  ```

  `sdkconfig.defaults.accounting` is one line, `CONFIG_LWIP_STATS=y`. lwIP only keeps per-pool
  counts when `MEMP_STATS` is 1, its default is `(MEMP_MEM_MALLOC == 0)` and IDF builds with
  `MEMP_MEM_MALLOC=1`, and IDF's Kconfig has no switch for it, so the top-level `CMakeLists.txt`
  (for lwIP) and `main/CMakeLists.txt` (for `HttpServer.cpp`, which must agree on the struct
  layout) add `MEMP_STATS=1` themselves, under the same option and only when `CONFIG_LWIP_STATS`
  is on. Without the overlay the image still builds, `memp` reads `null`, a `CMake Warning` says
  so, and every other probe is unaffected. A release image lists neither the overlay nor the
  define: its sdkconfig and its lwIP objects are not touched by this option.

### What it reports

`httpDramAccount` is the last key of the `/api/status` object. `now` is what is held at the
moment of the read, `hwm` the most that consumer has held since boot, `atPeak` what it held at
the moment the **total** last set a new high. Everything is bytes except `conns`.

| Consumer | What is counted, and where |
|---|---|
| `taskStack` | `HttpServer::kHttpConnStackBytes` (4096) for every connection thread from just before `std::thread` is created until its lambda ends (`acceptLoop()`). |
| `reqBuf` | The 4096 B read buffer of `handleClient()`, while that request is in flight, if it is in internal RAM. A connection slot's buffer in PSRAM (#410: the normal case on a PSRAM board) counts 0; a slot that spilled into internal RAM, or the per-request heap buffer a slot without one falls back to, counts 4096. |
| `reqRaw` | The `std::string raw` copy of the request, by capacity, after each `append` (a small string lives inside the object and counts 0). |
| `reqParsed` | The heap capacity of the parsed `HttpRequest` strings. `body` is a second copy of the request body. |
| `respBody` | A response body built on the heap, from the moment `sendResponseWithHeader()` has it until the send is done. Not counted: a body inside a leased buffer (`/api/status`, `/metrics`, the registrar roster: allocated once at boot), a flash literal, or a block in PSRAM. |
| `total` | Every row above added up, as `now` and as `hwm`. **`total.hwm` is the most the HTTP path ever held at once.** The rows' own `hwm` values peak at different instants and do not add up to it. |
| `respBodyMax` | The largest single body counted in `respBody`. |
| `conns` | Connection threads: `now` and the most ever alive at once. The board does not report this anywhere else (#947). |
| `spawnFailures` | `connection thread spawn failed` events (stderr only until now). Non-zero means the heap floor was reached. |

Counts are blocks the code asked for, by capacity; allocator overhead per block is not in them.
A body, string or buffer is counted only if it is in internal RAM at the moment of counting
(`esp_ptr_internal()`); the thread stacks are assumed internal (the `esp_pthread` default) and
the code does not check. The filter exists on the device only: on the host every body outside
the leased buffers counts, flash literals included, so a host number says nothing about DRAM.
On the device a body formatted into a stack buffer is internal and counts, and those bytes are
also inside `taskStack`, so `total` can read a few hundred bytes high.

`respBody` is taken where a finished body is handed to `sendResponseWithHeader()`, not where the
roughly thirty `std::ostringstream` response builders allocate. It is a lower bound for what the
builders held.

### The probes: the share the rows above cannot see

The consumers above are holds the code makes. The rest of the drop is elastic and held by the
heap, the task layer and lwIP, so these members are **readings**: each `{"n","last","min","max"}`
is a gauge of the values sampled (n of them), not a hold that was added up. They sit inside the
`httpDramAccount` object after `spawnFailures`; `/api/status` gains no top-level key.

| Member | What it reads | Device or host |
|---|---|---|
| `heap.free`, `heap.largest` | `heap_caps_get_free_size()` and `heap_caps_get_largest_free_block()`, both `MALLOC_CAP_INTERNAL \| MALLOC_CAP_8BIT`, sampled by the accept thread 50 times a second, when a connection thread has been created, when one ends and at every `/api/status` read (beside the route's other heap figures). `largest.min` is the fragmentation floor that the point reading `largestFreeBlockInternal` cannot show. `free.min` is never below `minFreeHeapInternal`, which IDF tracks continuously. | device; host `n` is 0 |
| `connCreate` | Internal bytes the heap lost across creating one connection thread: free before minus free after `std::thread`, in the accept thread. That is the stack **plus** the TCB, the pthread and `std::thread` state: `taskStack` counts only `kHttpConnStackBytes`. Allocations other tasks make in that instant are included, so `min` is the best estimate; `min - 4096` is what `taskStack` misses per connection. | device |
| `tasks` | `uxTaskGetNumberOfTasks()`, sampled with the heap. | device |
| `tcp.pcbs`, `tcp.httpPcbs` | Active TCP control blocks, all and on the HTTP port. | device |
| `tcp.queuedBytes`, `tcp.httpQueuedBytes` | The bytes written to sockets and not yet acknowledged: the sum over pcbs of `TCP_SND_BUF - snd_buf`, all and on the HTTP port. A send **copies** the response into heap pbufs and keeps them until the peer acknowledges, whatever the source buffer's region. Read on the lwIP thread (`tcpip_api_call`) by the accept thread, 50 times a second. Needs no lwIP statistics. | device |
| `tcp.queuedBufs` | The pbufs in those queues (`snd_queuelen`). | device |
| `memp` | An array, one row per lwIP pool ever drawn from: its `name`, `used` now, `max` (lwIP's own high-water, unlike the gauges), `err` (draws that failed), element `size`, and `bytesNow`/`bytesMax` as used or max times size (the pools' maxima peak at different instants). **`null` unless the image was built with the overlay** (see Building it). | device |

Notes on reading them:

- `tcp.*` gauges hold the value **at a sampling instant**, every 20 ms, so `max` is a lower bound for
  the true peak of the queues. A page load keeps the queues full for far longer than that; a short
  burst can be missed.
- The samples are taken on the **accept thread** (8 KB stack), never on a connection thread: some routes
  are down to about 470 B of the `http_conn` thread's 4096 B stack (#405) and the lwIP call needs more
  than that. The accept loop's `select()` wait is 20 ms instead of 250 ms in this image to give the
  sampling rate; a status read shows what was sampled at most 20 ms before.
- Not in `memp`: `PBUF_RAM`, i.e. every TCP send segment, which `MEM_LIBC_MALLOC` takes straight from
  the heap (and there is no `lwip_stats.mem` either). That is why `tcp.queuedBytes` exists.
- Not read: the receive side. A pcb's receive window is advertised space, not held memory; data
  waiting for the application sits in the netconn's mailbox, which no pcb field sizes.
- Cost: 50 times a second the accept thread does a `tcpip_api_call` (a message to the lwIP thread
  and a wait) and walks the heap. It is a bench image: `/api/status` is also about 2.5 KB longer,
  which a no-PSRAM profile's 16 KB buffer may not take with an office-sized roster (then a counted
  500, never a truncated body).
- Per-task attribution: `connCreate` and the existing `stackHwm_http_conn` cover the HTTP threads.
  The `tel_*` tasks are created at boot, before any load, so their stacks are in `F0` and not in the
  drop; `tasks.max - tasks.min` says whether anything else was created during the run (more than the
  HTTP threads would mean yes). FreeRTOS keeps no per-task heap figure, so a task that allocates from
  the heap while running cannot be attributed here.

### Reading it on `.244`

`minFreeHeapInternal` and every `hwm` are since boot and only ever fall, so compare windows, not
instants:

1. Reboot, wait for the phones to register, and let the board go idle. Read `/api/status` once
   and write down `freeHeapInternal` (`F0`), `minFreeHeapInternal` (`M0`) and `httpDramAccount`.
   The request that reads it is itself in flight, so `conns.now` is at least 1 (and `reqBuf.now` is 4096 only if its read buffer is in internal RAM, see the `reqBuf` row).
2. Run the #961/#947 harness (idle, then dashboard), or `for i in $(seq 4); do curl ... & done`.
3. Read `/api/status` again: `minFreeHeapInternal` (`M1`) and `httpDramAccount`.
4. If `M1 < M0` the run set a new low-water mark, and `F0 - M1` is how far internal DRAM fell
   from where it stood. Set it against `total.hwm`:
   - `total.hwm` close to `F0 - M1`: the counted consumers are the drop. `atPeak` says which of
     them held it.
   - `total.hwm` well short: the difference is in the list below, and `spawnFailures` says whether
     the floor was hit.
5. Per consumer: `taskStack.hwm / 4096` is the peak connection threads, and each live connection
   costs at least `4096` (the stack), plus `4096` for a read buffer that is in internal RAM
   (`reqBuf` row), before any request text. Before #410 moved the read buffer to PSRAM, with
   `kMaxConcurrentConnections` at 4 that was `4096 + 4096` each, 32768 B, more than the 31567 B
   low-water mark at the first read in #947. That is arithmetic from the code, a candidate to
   confirm or reject with the reading, not a finding.

### The lwIP share, and choosing a fix

After #974 moved the read buffer to PSRAM the `.244` bench read `reqBuf` 0 and an accounted peak
of 16930 B, but the drop under load was 38.4 KB: about 21.5 KB unaccounted (it was 5.4 KB). The
probes above exist to name that share. This section is the **candidate** and what to read to
confirm it; the numbers are arithmetic from the code and the config, not readings.

**Candidate.** A socket send copies the response into heap pbufs and holds them until the peer
acknowledges (`tcp_write` with `TCP_WRITE_FLAG_COPY`). Each connection can queue up to
`CONFIG_LWIP_TCP_SND_BUF_DEFAULT` = 5760 B, four 1440 B segments, each with about 80 B of pbuf,
header room and `tcp_seg` around it: about 1.06 B of heap per queued byte, 6.1 KB for a full queue.
The dashboard document is sent in place from flash but still goes through that queue at the pace
the peer acknowledges, so four browsers loading it hold four full queues for the whole load:
4 x 6.1 = about 24 KB at the peak, the size of the unaccounted share. Each connection also costs
what `connCreate` reads beyond its 4096 B stack (the TCB and pthread state) and about 0.7 KB of
`tcp_pcb`, `netconn`, mailbox and semaphore (the `memp` rows size the pools).

**Read after the harness run**, in one `/api/status`: `tcp.httpQueuedBytes.max`, `tcp.queuedBufs.max`,
`memp` (`TCP_SEG`, `PBUF_REF/ROM`, `NETCONN`, `TCP_PCB` `bytesMax`), `connCreate.min`, `heap.largest.min`,
`conns.hwm`, `httpPerSourceRefusals` and the busy refusals in the log.

**Proposals** (none applied: no default changes in this change):

| Option | Expected saving at the four-connection peak | Costs | Pick it when the bench shows |
|---|---|---|---|
| Smaller send buffer: `CONFIG_LWIP_TCP_SND_BUF_DEFAULT` 5760 to 2880 (the constrained profile's value), with `CONFIG_LWIP_TCP_WND_DEFAULT` left alone | Up to 4 x (5760 - 2880) x 1.06 = 12.2 KB, but only what was queued: about 1.06 x (`httpQueuedBytes.max` - min(`httpQueuedBytes.max`, 11520)) | Throughput of large downloads (two segments in flight; the document and `/api/coredump`, not the polled JSON); no concurrency lost | `tcp.httpQueuedBytes.max` near 4 x 5760 = 23040 (say 17 KB or more): the queues are the eater |
| Connection cap 4 to 3 (`kMaxConcurrentConnections`) | One connection's whole cost: `connCreate.min` (about 4.7 KB if it reads the TCB at about 600 B) + a full queue 6.1 KB + 0.7 KB = about 11.5 KB | The fourth concurrent request is refused 503, and `kMaxConnectionsPerSource` falls from 3 to 2: a browser's third parallel connection is refused | `conns.hwm` is 4 only briefly, `httpPerSourceRefusals` reads 0 under the real dashboard load at cap 4, and the busy-refusal log is empty |
| Both | 4 x (4.7 + 6.1 + 0.7) = 46 KB to 3 x (4.7 + 3.1 + 0.7) = 25.4 KB, about 20.6 KB | The two costs above | The first row's condition holds and the second row's saving alone is not enough |
| Neither | none | | `tcp.httpQueuedBytes.max` is small (under about 8 KB) while the unaccounted share is still large: the queues are not it. Read `heap.largest.min` and `tasks` next and look at the response builders' transients (`std::ostringstream` plus `str()`, see below); do not change either knob on this evidence |

### What it cannot see

- The task control block, the `esp_pthread` entry and the `std::thread` state of every connection,
  one by one. Together they are `connCreate.min - 4096` per connection.
- Stacks and TCBs of finished threads. A FreeRTOS task frees them when the idle task reaps it,
  after `taskStack.now` has already dropped, so under load internal DRAM can stay low while the
  counters read zero.
- lwIP: the pools and the TCP send queues are read by `memp` and `tcp` (above). Not read: data
  waiting in a netconn's receive mailbox, the mailboxes and semaphores themselves (FreeRTOS
  objects, not lwIP pools) and `PBUF_RAM` other than the TCP send queues.
- The Ethernet driver's TX/RX buffers and the SPI DMA bounce buffer #328 is about.
- Transients inside a request: `parseRequest()`'s per-header `line`/`hName`/`hVal`, `getFormParam()`
  and `jsonEscape()` strings, the OTA/MoH branch's `otaReq`, and the `std::ostringstream` stream
  buffer a route fills before it hands over the body (a route that ends in `json.str()` holds
  that buffer and the `str()` copy at the same moment, so about twice its `respBody`).
- The 4096 B `std::vector<uint8_t>` chunk `streamBody()` holds during an OTA or MoH upload. It
  exists only while one is running, not on the dashboard path.
- Per-block allocator overhead, including `CONFIG_HEAP_POISONING_LIGHT`'s.
- The leased `/api/status` buffers: standing from boot, so already out of the numbers above. On
  a no-PSRAM profile they are internal DRAM (2 x 16384); `memory.psramFallbacks` says if a PSRAM
  board had to take them from internal.
- Everything that is not HTTP (SIP, RTP, TLS, the display), which draws on the same heap.

### Not verified

Host-tested (`HttpDramAccount_test.cpp`, built with the option on and off), and
`HttpServer.cpp` was compiled on its own with the ESP32-S3 toolchain (esp-15.2.0, flags of an
existing `eth` build tree): with the option off the object is byte-identical to `origin/main`'s;
with it on, code grows by 2653 B and `.bss` by 84 B, and `-fstack-usage` gives `handleClient()`
448 -> 496 B and `sendResponseWithHeader()` 240 -> 256 B. Not done: a link or a full image
(so no app-slot margin for the option-on image), the classic-ESP32 / `lan8720` and
`SIP_CONSTRAINED` profiles, any run on a board, and the first reading on `.244`.

The probes (this section's second half) add to that:

- Host-tested: the gauge, the TCP queue arithmetic, the `memp` row and where the JSON lands
  (`HttpDramAccount_test.cpp`, six tests, built with the option on and off). The device readers
  (`heap_caps`, `tcp_active_pcbs` through `tcpip_api_call`, `lwip_stats.memp`) cannot run on the host.
- With the option off nothing changes: `HttpServer.cpp` compiled for the ESP32-S3 is identical to
  `origin/main`'s once the DWARF is stripped (the full objects differ only in line tables, which the
  guarded code shifts), `-fstack-usage` frames are the same, and the generated `sdkconfig` of a
  fresh `idf.py reconfigure` is identical to `origin/main`'s.
- With the option on and the overlay, `sdkconfig` differs from the option-off one by the single line
  `CONFIG_LWIP_STATS=y`; `MEMP_STATS=1` reaches lwIP's and `main`'s compile commands and, without
  the overlay, neither (the configure prints the warning). lwIP's `memp.c` and `stats.c` compile with
  `MEMP_STATS=1` under `MEMP_MEM_MALLOC`, and fail with `'MEMP_STATS' redefined` if it is set
  without `LWIP_STATS`, which is why the CMake sets it only when `CONFIG_LWIP_STATS` is on.
- A full option-on ESP32-S3 `eth` image builds and links (`SipServer.bin` 2302448 B in a 6 MB app
  slot, 63% free; the option-on image of #973 was 2297136 B).
- Not done: any run on a board, so no `memp`, `tcp` or `connCreate` value has been read; every number
  in the fix table above is arithmetic. The accept loop's 20 ms `select()` and the `tcpip_api_call`
  every 20 ms have not been timed.
