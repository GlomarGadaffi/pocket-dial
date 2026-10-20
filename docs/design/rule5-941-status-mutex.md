# Design: the ordinary status lane's lock across socket I/O, on the 911/933 and PSAP-callback paths (#941, #949)

Status: Proposed, for vote. Design only: no code, no tests, no hardware, nothing posted to GitHub. This document does not claim a fix.

Read at `origin/main` 046e7277 (v1.6.0 evidence commit). `TA.cpp` = src/SIP/TelephonyAnchorClient.cpp. Line numbers drift; each claim names the function.

Labels used throughout: **[read]** = verified by reading the code at 046e7277. **[inferred]** = reasoning from the code or from ESP-IDF behaviour not in this checkout. **[unmeasured]** = needs a board. Nothing here was measured; the #941 thread's own rule is "reproduce and measure each hold before any fix".

## 1. What #941 says, and what main already does

#941's claim: `makeCall` waits on `_statusMutex` across a status HTTP read, through `resolveDevice` and `resolveOutboundLeg`.

- **[read] The makeCall half is already fixed on main.** `httpGetBody(url, body, status, sosLane, warm)` takes `_statusMutex` only `if (!sosLane)`: `std::unique_lock ... defer_lock`, then `if (!sosLane) statusLock.lock();`. A 911/933 drives `_sosStatusClient` under a lock-free atomic claim (`SosStatusClaim`, `kSosGetClaimBoundUs = 0`, SosStatusGet.hpp), so it never waits: a busy claim returns an error and `makeCall` takes the conservative route. `makeCall` computes `sosLane = classifyEmergencyDial(destination).isEmergency` and passes it to both `resolveDevice(sosLane)` call sites and to the `httpGetBody` inside `resolveOutboundLeg`. Landed in #976 (squash 6154ae80, "Part of #941"). #955, the first attempt, is closed.
- **[read] `makeCall` has no other `_statusMutex` wait for a 911/933.** It skips `ensureToken()` for an emergency (`sosDial`: the cached token goes out at once; the only inline fetch is the no-token case on the 911 arena). `httpPostBody` uses a fresh client and takes no lock. The 401 retry reads slot `getMutex` with `try_to_lock` only.
- **[read] What #941 still covers is the ordinary lane.** The other `httpGetBody` callers, the same `_statusMutex`, the same I/O-under-lock, but not reached from `makeCall`. These are #949's sites 1 and 2, and they are the real remaining Rule 5 exposure. The existing test (tests/tools/test_anchor_sos_status_lane.py) is a source-text pin of the makeCall wiring; it says in its own docstring that the anchor is ESP-only. It does not exercise a wait.

So the recommendation is to retitle the remaining work, not to re-fix `makeCall` (section 6).

## 2. What holds the lock, and for how long

**[read]** Holder: `httpGetBody` on the ordinary lane (`sosLane == false`). It takes `_statusMutex` at entry (after copying the bearer under `_mutex`) and holds it to function return, across: `esp_http_client_open` (TCP connect + TLS, or a resumed handshake), `esp_http_client_fetch_headers`, the drain loop `while (esp_http_client_read(...) > 0)` into a `std::vector<char>`, and, on failure, `cleanup` and a second attempt (`for attempt < 2`). The handle is `_statusClient`, built by `makeAuthedClient` with `config.timeout_ms = 2000`.

**[read]** Other `_statusMutex` takers: `closeStatusClient()` (lock, `esp_http_client_cleanup`, no I/O; stop path). Nothing else.

**[read]** Ordinary-lane callers of `httpGetBody` (all contend for the one mutex):

| Caller | Task | Why it runs |
|---|---|---|
| `getLegStatus` | WS worker `tel_wsw` (kWsWorkers = POCKETDIAL_MAX_ANCHOR_CALLS, up to 4 concurrent) | every outbound upset that is not `fullyUp`; the Connected-to-Answered decision |
| `getParticipantCaller` | WS worker | an inbound upset with empty `w.callerId`, before the Incoming event is announced |
| `reconcileParticipantId` | `tel_drop` via `dropCall("")` | the rare registration-miss path only |
| `reconcileTaskTrampoline` | `tel_maint` | the outbound-wedge watchdog, at most once per 5 s |
| `warmStatusConnection` | `start()` | boot only |

**Duration.** The code supplies a per-operation timeout of 2000 ms and nothing that bounds the whole function. From that:

- Nominal **[inferred, unmeasured]**: a resumed open is "~100-150 ms" per the code comments, then headers and a short body: low hundreds of ms.
- Open fails twice: 2 x 2000 = **~4 s** **[inferred]** (the connect/handshake timeout is `timeout_ms`; a multi-step TLS handshake could exceed it in total because the timeout is per socket operation, not per handshake).
- Open succeeds, headers or a read stall at 2 s, retry also stalls: 2 x (2 s headers + 2 s read) = **~8 s** **[inferred]**; with a slow open on each attempt up to **~12 s**.
- A peer that trickles bytes just under 2 s apart never times out and has no cap: the loop ends only on EOF. **Unbounded in principle [inferred]**; bounded in practice by the 3CX response size and the 512 B chunk.
- Queueing multiplies it: with four workers plus `tel_maint` and `tel_drop` all on one mutex, the last waiter pays the sum. Four stalled holders in line is ~16-48 s on paper **[inferred]**. `std::mutex` on FreeRTOS gives no fairness or timeout.

For comparison, a 911 call's own Rule 5 budget elsewhere is `kSosTokenBudgetUs` (token) and an 8 ms close bound; a status wait of seconds is far outside either.

## 3. Which 911 / 933 / PSAP-callback paths can still wait behind it

**[read]** unless marked.

1. **911/933 outbound, Connected-to-Answered.** After `makeCall` returns and the far leg connects, Telephony sends upserts, and the WS worker runs `getLegStatus(controlLeg)` (outbound branch, `if (!fullyUp)`) on the ordinary lane, `sosLane` not passed. Only on "Connected" does it open the POST stream and fire `CallEvent::Answered`. This is an ordinary-lane wait on a 911 leg: the answer signal, and the media POST that depends on it, are delayed by whatever holds `_statusMutex`. A failed GET returns "" and the Connected branch is not taken, so a miss also delays or misreports it until the next upset (~750 ms repeat, per the code comments). The worker has no emergency flag at this point; the slot does (`slot.emergency`), so the information exists. #949 site 1.
2. **Inbound PSAP callback.** The inbound branch calls `getParticipantCaller(controlLeg)` before `evCb(Incoming)` when `w.callerId` is empty. Code comments say attached_data is "often null" on a route point **[read]**, so on a callback the Incoming event (the ring) waits for a status GET and for `_statusMutex`. Also `startMediaStreams` follows. Whether a 911 callback in practice arrives with an empty callerId is **[unmeasured]**. #949 site 2. Note a callback is by definition not classifiable from `destination`, so the `sosLane` flag cannot be taken from the dial string; it would have to come from the callback matcher.
3. **Second concurrent 911.** Not the mutex but the same lane's design: a second 911 GET while the first holds `_sosStatusBusy` gets an immediate error (`kSosGetClaimBoundUs = 0`), and `makeCall` proceeds without an own leg. Intentional (#948), noted so no fix here relaxes it.
4. **`reconcile` watchdog and `dropCall("")`**: ordinary lane, can hold `_statusMutex` while a 911 worker (1) waits. They are contenders, not victims; no 911 waits on them directly except via the mutex.
5. **Not `_statusMutex`, same family (#949 sites 3 and 4; out of scope here but they bound the benefit):** the emergency no-slot `dropCall` takes `_ctrlMutex` across `performCtrl` I/O (shared with `tel_drop` and `answerCall`); `ensureToken()` is skipped for a 911 so site 4 does not apply to the 911's own `makeCall` on main **[read]** (it applies to ordinary calls, and to `mediaStreamsLive()`'s `getMutex` read, which is a pointer read). I did not re-derive the "rx task holds getMutex across `makeAuthedClient`" claim of #949 site 4; it is **not verified here**.

Not on the list: 911 `makeCall` itself (section 1); `httpPostBody` (fresh handle, no lock); `fetchToken` on the Emergency lane (own arena).

## 4. Options

All keep the 911 lane (`_sosStatusClient` + claim) as it is.

**A. Emergency flag through `getLegStatus` / `getParticipantCaller`; reuse the sos lane.** The worker already has `slot.emergency` (set by `makeCall` before the slot's upserts matter). Pass `sosLane = slot.emergency != 0` to `getLegStatus`; for a callback, pass a flag from the PSAP-callback matcher to `getParticipantCaller`. The existing lane gives lock-free, never-waits behaviour and a bounded arena.
- Cost: small diff (two parameters, two call sites). Reuses reviewed machinery.
- Risk: the sos lane returns an error when its claim is busy (e.g. two 911 legs, or a leg's GET while `makeCall`'s is in flight): the Answered decision then misses until the next upset. That is the "conservative route" and is only a delay of ~750 ms, but it is a delay, and it is new on the Answered path **[inferred]**. The arena (`sosBodyArenaBytes(MAX_ANCHOR_CALLS)` = (2 x calls + spare legs) x per-leg bytes) must hold the whole participant list; an over-size list is an error (#948 `TooBig`), so a busy DN with many participants could never read. Callback detection source is unspecified (open question 1).

**B. `try_to_lock` with a bounded wait on `_statusMutex` for emergency callers, ordinary lane handle.** Same pattern as #862.
- Cost: small; no new handle.
- Risk: a failed try means no status read at all while the holder is mid-I/O for up to seconds, so it is worse than A for the common case (an ordinary GET happens to be in flight during a 911 answer), and it does nothing for the 911 waiting while the holder is slow: it just gives up. It also shares one TLS handle between lanes, so even a successful try may be preceded by the other lane's reconnect state. Not recommended alone.

**C. Snapshot-under-lock, I/O unlocked, for the ordinary lane: give every GET its own handle (a small pool or per-worker handle) and drop `_statusMutex` as an I/O lock.**
- Cost: highest. N more TLS handles; each holds a mbedTLS context. The code comments say the point of the single shared handle (#107) was that one resumed open (~100-150 ms) beats N concurrent cold ECDHEs on a crypto-bound core; per-worker handles bring back the contention for CPU and also 4 x ~RAM per handle on a build whose free-heap readings are the operator's gate in the #941 thread.
- Risk: heap and the "no heap after init" rule (handles would have to be created at start); a larger TLS footprint on classic esp32; benefit goes to ordinary-call latency too, which is not Rule 5.

**D. Bound the hold itself.** Cap whole-function time for the ordinary lane (a deadline passed to each timeout, as `armTokenOpTimeout` does for tokens) and one attempt for a lane that serves a worker.
- Cost: small; precedent exists in `opTimeoutMs`.
- Risk: it changes ordinary-call behaviour (fewer retries on a stale handle), and it bounds, rather than removes, the wait: still seconds. Useful as a complement, not an answer.

## 5. Recommendation

**A, plus D as a follow-up if the bench shows the ordinary-lane holds are long.** A is the only option that removes the 911 from the lock at no new heap, and the lane it reuses is already reviewed (#948). B is a trap (gives up instead of getting through). C is a different project (ordinary latency, heap), and the #941 thread already gates any status-lock change on the classic-esp32 free-heap readings.

Before choosing A, answer two things the code does not say:
1. How does the anchor recognise a PSAP callback? If it cannot at the point `getParticipantCaller` runs, A covers only outbound legs, and the callback needs either a hard-wired skip of the lookup when the caller field is empty (announce first, enrich later) or a different design. The announce-first variant removes the callback's dependency on any status GET.
2. Does the sos arena hold the largest participant list a DN can have? A `TooBig` on the Answered path would turn a wait into a miss.

## 6. The first red test

The anchor client is ESP-only (the existing test says so), so the red test needs a seam, as SosStatusGet.hpp already is one. First red, in this order:

1. **Host gtest in tests/SosStatusGet_test.cpp (or a sibling) that reproduces the wait.** A thread takes a `std::mutex` and sleeps 300 ms (the stand-in for a status GET in flight). The call under test is the lane-selection helper used by `getLegStatus` for a given slot. Assert, on one run: (a) emergency=true returns within 20 ms and reports "lane busy" or "read", never blocks; (b) emergency=false still waits for the holder and returns its result (positive control, so the test is not only an absence); (c) the wall time of (a) is checked against the 300 ms hold, with the count of returns, not just "didn't hang". **Red today:** `getLegStatus` has no emergency parameter, so the first run is a characterization test of the current policy (always lock): (a) measures roughly the holder's remaining time (about 300 ms) and the assertion `elapsed < 20 ms` fails. That failure is the recorded red.
2. **Source pin** (Python, like test_anchor_sos_status_lane.py): `getLegStatus` and `getParticipantCaller` take a lane flag; the Answered-path call site passes `slot.emergency`. Weak on its own (text), so only with (1).
3. Do not assert only "no `lock_guard` on `_statusMutex`": that is already true of `httpGetBody` on the sos branch and would pass today.

## 7. What needs a hardware bench

All **[unmeasured]**; the #941 thread asks for a reproduction per site before a fix.
- Wall time of an ordinary `httpGetBody` on a resumed handle, a stale handle, and a cold handle, on both the S3 and the classic esp32; and under contention from 4 workers plus `tel_maint`. This replaces every figure in section 2.
- Whether a 911 outbound's `getLegStatus` ever actually queues behind another GET in a real call sequence (does the watchdog or another worker overlap the Answered moment?).
- Whether the participant list for a 911 can exceed the sos arena.
- Whether a real PSAP callback arrives with an empty `callerId` (decides whether site 2 is real).
- The classic-esp32 free-heap readings the #941 thread names as the gate for any change here.

No 911/933 is to be dialled for any of this; use a non-emergency number to reproduce the lock hold and a host test for the 911 branching.

## 8. Not verified

- The IDF behaviour behind the 2 s timeout (per operation, per handshake step) was not read in an IDF tree; section 2's multipliers depend on it.
- #949's sites 3 and 4 (`dropCall` under `_ctrlMutex`, `getMutex` across `makeAuthedClient` in the rx task) were read only as far as stated in section 3.
- Whether any caller I did not list (e.g. in `tick()`) reaches `httpGetBody` on the ordinary lane while a call is up. I listed every `httpGetBody` call site found by grep.
