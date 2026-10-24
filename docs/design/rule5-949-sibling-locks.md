# Design: Rule 5 sibling lock holds on the 911 and PSAP-callback paths (#949)

This document records, for each hold #949 lists, who holds which lock across what I/O, how long the code allows that to last, which emergency path waits behind it, what a fix would cost, and what the first red test is.

Status: Proposed, for vote. Design only: no source, no tests, no hardware. Hold 1 was fixed on main by #1088 after this was written; holds 2 and 3 are not fixed.

Source of the issue: #949, found during #941. Operator rule (comment on #949, 2026-10-09): reproduce each hold and measure its wall time before any fix.

## 0. How to read this

Read against `origin/main` at commit fe447968 (`ci: reject the noreply attribution address in commits (#1106)`). `TA.cpp` = `src/SIP/TelephonyAnchorClient.cpp`, `RH.cpp` = `src/SIP/RequestsHandler.cpp`. Line numbers are from that commit; the issue's numbers (taken at c4960c74) have drifted by up to ~1,000 lines, mostly because #941/#948 landed since.

Every claim carries a tag:

- **[verified]** read in the code at fe447968, quoted or cited by line.
- **[inferred]** follows from the code plus a property of ESP-IDF or the board that was not re-read here, or from arithmetic.
- **[not measured]** a duration. No number here is a wall time off a board. The issue's own first step is a reproduction that measures; nothing below replaces it.

Timeout fact used throughout [verified]: `makeAuthedClient` sets `config.timeout_ms = 2000` (TA.cpp:2895), with the comment "2 seconds timeout to bound blocking calls". That is a per-blocking-operation bound in `esp_http_client`, not a deadline over a whole request. A request is connect, TLS handshake, write, header read, body read; the code puts no overall budget on it. The "worst case" figures below are therefore an upper envelope built from that 2 s per phase **[inferred]**, not a limit the code enforces.

Build fact [verified]: `POCKETDIAL_MAX_ANCHOR_CALLS` defaults to 4 (PoolConfig.hpp:293) and one ESP build block sets it to 1 (main/CMakeLists.txt:296). `kWsWorkers` equals it (TelephonyAnchorClient.hpp:443), so on that build there is exactly one `tel_wsw` worker and every WS work item queues behind the one before it.

## 1. Verdict table

| # | Hold in #949 | Holds on main? | Section |
|---|---|---|---|
| 1 | `getLegStatus` under `_statusMutex` on a WS worker (911 Connected to Answered) | No. Fixed by #1088: `getLegStatus(legId, bool sosLane)` is TA.cpp:1896 and the worker call at :3512 passes the lane. The shared-lane lock is TA.cpp:1605-1606 | 2 |
| 2 | Inbound PSAP callback: `getParticipantCaller` / `getLegStatus` under `_statusMutex` | Yes for `getParticipantCaller` (TA.cpp:3465). `getLegStatus` is the outbound branch only, so it is item 1, not item 2 | 3 |
| 3 | Emergency no-slot branch: `dropCall()` takes `_ctrlMutex` across `performCtrl` I/O | Yes (TA.cpp:699, :850, :2975) | 4 |
| 4 | `ensureToken()` takes `slot.getMutex`, which the rx task holds across `makeAuthedClient()` | **No. Dropped for the 911 path.** | 5 |

The issue names no further holds ("and any others listed" in the task brief resolves to the four above). Section 6 lists two neighbours found while reading; they are candidates, not claims.

## 2. Hold 1: the 911's Answered transition waits on `_statusMutex` (fixed by #1088)

Fixed on main. #1088 gave `getLegStatus` a lane parameter and the `tel_wsw` worker passes it (section "What fixed it"). The paragraphs below describe the hold as it stood before that change, with line numbers moved to fe447968 where the code still exists.

**Lock.** `_statusMutex` (TelephonyAnchorClient.hpp:319). Taken in `httpGetBody` at TA.cpp:1605-1606 [verified]: `std::unique_lock<std::mutex> statusLock(_statusMutex, std::defer_lock); if (!sosLane && !fresh) statusLock.lock();`. It is held to the end of the function, so across `esp_http_client_open`, `fetch_headers`, the body read, and on failure `esp_http_client_cleanup` plus a rebuilt second attempt (TA.cpp:1627-1735) [verified].

**What fixed it.** #941/#948: an emergency `makeCall` passes `sosLane=true` to `resolveDevice` and `resolveOutboundLeg` and drives `_sosStatusClient` under a lock-free claim (TA.cpp:410-412, :1604-1610) [verified]. #1088: `getLegStatus(const std::string& legId, bool sosLane)` is TA.cpp:1896 and forwards the lane to `httpGetBody(url, body, &status, sosLane)` at TA.cpp:1906. The worker reads the slot's `emergency` flag (TA.cpp:3502) and calls `telephony::readOutboundLegStatus(emergency, ... getLegStatus(controlLeg, sosLane) ...)` at TA.cpp:3511-3512 (`readOutboundLegStatus` is SosStatusGet.hpp:811) [verified]. Before #1088 `getLegStatus` took only `legId` and always used the shared lane, so #941 covered `makeCall` and nothing after it.

**Holder.** Any other caller of the non-sos `httpGetBody` [verified by grep of the callers]: another `tel_wsw` pass (`getLegStatus`, `getParticipantCaller`), `reconcileParticipantId` from `dropCall`'s registration-miss path and from the reconcile task, an ordinary `makeCall`'s `resolveDevice`, `warmStatusConnection`, and `closeStatusClient` (which takes the mutex around `esp_http_client_cleanup`, TA.cpp:3095-3102). With one worker the holder can also be an earlier item in the same worker's queue (inbound caller lookup, hold 2) **[inferred]**; that is queue wait, not mutex wait, with the same effect.

**Waiter on an emergency path (before #1088).** The 911's `tel_wsw` pass, outbound branch: `getLegStatus(controlLeg)` with no lane, now the call at TA.cpp:3511-3512, then a Connected status fires `CallEvent::Answered` (TA.cpp:3524-3558) [verified]. The slot is known to be a 911 at that point: `outboundActive` and `emergency` are stored in the same `_mutex` section in `makeCall` (TA.cpp:676-688), and the worker reads `outbound` only after seeing `outboundActive` true (TA.cpp:3416-3422) [verified]. What waits is the Answered signal: the engine's Answered handler (RH.cpp:521) starts the media bridge and re-arms the ring timer as an ACK deadline (RH.cpp:603), and the comment at RH.cpp:5713 says the 200 OK to the caller "follows later from the CallEvent::Answered callback" [verified at the cited lines].

**Worst case (before #1088).** One holder GET: two attempts, each connect + TLS (2 s per blocking step), header read 2 s, body read 2 s per `esp_http_client_read` [inferred]: an envelope of roughly 6 s per attempt, 12 s for both. The waiter then pays its own GET on top (about 100 to 150 ms resumed, per the comment at TA.cpp:1573-1577, **[not measured]**; up to the same envelope on a failing link). With k queued holders the wait multiplies. **[not measured]**

**Why it is a Rule 5 problem and not just latency.** A 911 whose Answered fires late leaves the caller without its 200 OK and the media bridge unstarted while the PSAP may already be on the line (RH.cpp:521, :5713) **[inferred from those comments]**. Before #1088, if the shared lane's GET failed or returned "", the worker took the dialing branch and did not fire Answered at all until the next upset. On main an empty read on an emergency slot is Unknown: the worker flags `upsetPending` and re-asks after `kEmergencyReaskMs` (TA.cpp:3563-3578; SosStatusGet.hpp, `outboundStep`) [verified]. The comment at TA.cpp:3308 says Telephony repeats the upset about every 750 ms; the comments at TA.cpp:707 and :3854-3859 (#888) say 3CX "does not repeat a Connected one". The comments disagree, so whether a missed Connected is recovered is **unknown** and is a bench question.

**Fix options.**

- **A (landed in #1088). Give `getLegStatus` a lane parameter and have the worker pass `true` when the slot's `emergency` number is non-zero.** Reuses #941's handle, #948's claim and arena, no new lock, no new socket. Cost: (a) a signature change on a function with callers in `tel_wsw`, `tick`-side paths and tests; (b) the sos claim never waits (`kSosGetClaimBoundUs = 0`, SosStatusGet.hpp:187), so when a second 911's `makeCall` GET or a previous pass holds it the worker gets "" and must decide what that means. The decision is the real cost of A: a one-shot "" must not be read as "not Connected" for an emergency slot. The operator ruled on 2026-10-20 (comment above `readOutboundLegStatus`, SosStatusGet.hpp): on an emergency slot an empty or failed read is Unknown. The worker reads up to `kEmergencyStatusReads` (3) times one tick apart, then re-asks after `kEmergencyReaskMs` (100 ms) through the single-flight `upsetPending` loop. (c) The sos arena is sized for 16 participants on a 4-slot build, `sosBodyArenaBytes(POCKETDIAL_MAX_ANCHOR_CALLS)` (TelephonyAnchorClient.hpp:343; SosStatusGet.hpp:100); a longer list is a `TooBig` error and no status read, which for the worker means the same "" case.
- **B. `try_lock` the shared mutex for an emergency slot, else skip.** Smaller, but a skipped read is the same missed-Connected case, and it forfeits the warm resumed session. Not recommended.
- **C. Take the status from the upset payload instead of the list.** Rejected: the list is the authority because the upset's own id can be the far leg and a specific-id read 403s (issue #40; comment at TA.cpp:3507-3508).

## 3. Hold 2: the inbound PSAP callback's ring waits on a caller lookup under `_statusMutex`

**Lock and holder.** Same `_statusMutex`, same holders as hold 1, through `getParticipantCaller` (TA.cpp:1934-1969), which calls the non-sos `httpGetBody` (TA.cpp:1947) [verified].

**Waiter.** The `tel_wsw` pass for an inbound leg, inbound branch: `if (caller.empty()) caller = getParticipantCaller(controlLeg);` at TA.cpp:3465, and only after it returns does `evCb(CallEvent::Incoming ...)` run (TA.cpp:3468-3472) [verified]. The comment at TA.cpp:3461-3463 says the WS event's `attached_data` is "often null on a route point", so the lookup is the common case, not the rare one. The handler's `Incoming` branch is `routeInboundAnchorCall` (RH.cpp:621-625), which rings the extensions; so a PSAP callback's ring starts only after this GET returns [verified].

**What the lookup is for.** Display only. `routeInboundAnchorCall` uses `callerId` solely as `callerDisplay`, defaulting to "PSTN" (RH.cpp:6308); whether the call is emergency is decided from the ring targets through `isEmergencyCallback(t->getNumber())` (RH.cpp:6264), not from the caller [verified]. This is what makes a fix safe: nothing about routing or classification depends on the GET.

**Why the anchor cannot just pick the sos lane.** At this point the worker does not know the leg is a callback: the callback window is per dialing extension (EmergencyCall.hpp:130-162), evaluated by the handler on the ring targets, and the anchor has no handle on it [verified]. Sending every inbound lookup to the sos handle would make an ordinary inbound call able to hold the 911's single-flight claim, which inverts the bug **[inferred]**.

**Worst case.** Contended: the holder's envelope (hold 1) plus this lookup's own. Uncontended: this lookup's own GET alone, about 100 to 150 ms resumed, ~1 s cold on the S3 per the code's comments, up to the 12 s envelope on a failing link, all **[not measured]**. Note the delay is paid even with no contention, which hold 1 does not.

**Fix options.**

- **A (recommended). Fire `Incoming` first with the caller the WS event carried (often empty, so "PSTN"), then resolve the caller and deliver it as a late update.** The ring is no longer behind any I/O. Cost: a new event or a setter on the session for a late caller (AnchorClient.hpp interface, LoopbackAnchorClient, the handler's event switch at RH.cpp:521-635), and the display may show "PSTN" for the first ring. It touches the anchor contract, so it is the largest of the four diffs here.
- **B. Skip the lookup while any extension is inside a callback window.** Needs the handler to hand the anchor a predicate; the anchor has none today. Smaller than A but adds a cross-module dependency, and a callback to an extension outside the window still waits.
- **C (stopgap). Replace the lock with a `try_lock` and proceed with "" on contention.** Removes the contended wait only. The uncontended own-GET delay stays, and under contention the display is "PSTN". Not sufficient alone.

## 4. Hold 3: the emergency no-slot branch's `dropCall` waits on `_ctrlMutex`

**Lock.** `_ctrlMutex` (TelephonyAnchorClient.hpp:303), taken at the top of `performCtrl` after the token snapshot (TA.cpp:2975) and held through up to two `esp_http_client_perform` calls, a possible `makeAuthedClient`, and the cleanup between attempts (TA.cpp:2975-3043) [verified]. Also taken by `warmCtrlConnection` (through `performCtrl`) and `closeCtrlClient` (TA.cpp:3085-3092).

**Waiter.** The 911's own `tel_sos` thread. `asyncMakeCall(..., emergency=true)` posts to `kLaneSos` (RH.cpp:5783; :6077 names the three lanes tel_ctl, tel_drop, tel_sos) [verified]. In `makeCall`, if `startRxIfNeeded` returns false for 4 s (`kEmergencySlotWaitUs = 4'000'000`, RxRestart.hpp:80, polled every 100 ms), the branch at TA.cpp:695-702 calls `dropCall(ownLeg)` and then returns false [verified]. The caller sees the 503 and the notify list sees NOT ROUTED only after `dropCall` returns.

**Holder.** `tel_drop` running another leg's `dropCall` (`asyncDropCall`, RH.cpp:5799-5810), `tel_ctl` running `answerCall` for an inbound call (TA.cpp:886-948), the warm-up, or `closeCtrlClient` [verified]. All are on other lanes by design (the lane split is RH.cpp:6077), but they share this one mutex.

**What the delay costs.** Two things, both of Rule 5 type "delay": the refusal of the 911 (the 503 and the NOT ROUTED notice) and the drop of the ringing PSAP leg, which #712 says is otherwise never reaped. Which of the two is worse depends on what the operator wants to guarantee first; the code orders them: drop, then fail **[verified]**. `dropCall` itself also does `stopMediaStreams(partId)` first (TA.cpp:837), which for a leg that has no slot is cheap **[inferred]**.

**Worst case.** The holder's `performCtrl`: two attempts, each connect + TLS + write + read, 2 s per phase, plus a cold handshake of about 1 s of CPU on the S3 when the handle was rebuilt [inferred]; roughly 12 s envelope **[not measured]**. Then this drop's own `performCtrl`, the same envelope, in the failing case. Queued holders add.

**Reach.** The no-slot branch is a rare path (all slots busy for 4 s with a 911). On the one-slot build it is reached by a 911 placed while another call holds the only slot, which is the build where the case is least rare **[inferred from main/CMakeLists.txt:296]**. The same `_ctrlMutex` also gates the ordinary hangup drop of a 911 leg through `tel_drop`, behind an `answerCall`; that is a neighbour (section 6), not this branch.

**Fix options.**

- **A (recommended). Do not call `performCtrl` on the 911's thread in this branch. Record the leg in fixed storage (`telephony::IdSnapshot`, as used by `stopAllMediaStreams`, no heap) and let `tick()` or `tel_drop` drain it.** The 911 fails at once; the orphan leg is dropped within about a second of the mutex freeing. Cost: a new member and a drain step in `tick()`; a lost drop becomes a lingering ringing leg for one more tick; the overflow case (more orphans than slots) needs a defined answer (the table can be sized to `POCKETDIAL_MAX_ANCHOR_CALLS`, since orphans are bounded by it).
- **B. Hand the drop to the handler:** leave `ownLegOut` set on this failure so the handler's failure path calls `asyncDropCall` (the `tel_drop` lane, which `postTelCtl` reaches without blocking, RH.cpp:6106-6111). Smaller in the anchor, but it changes what a non-empty `ownLegOut` means on a false return: today the engine binds a session to it (TA.cpp:630 "let the engine bind this call's session now"). A contract change; a reviewer must check every reader.
- **C. A second control handle for emergencies with its own lock-free claim (the #941 shape).** Mirrors precedent but costs another TLS socket on a board where the LWIP pool is already short (#94, TA.cpp:825) and another warm-up. Not recommended for a branch this rare.

## 5. Hold 4: dropped for the 911 path

#949 says `ensureToken()` takes `slot.getMutex`, which the rx task holds across `makeAuthedClient()`, "on every makeCall, so every 911 pays for it". Three things in the code at fe447968 contradict that, and I drop the item for the 911 path.

1. **A 911 does not call `ensureToken()`.** The only call site is `else { ensureToken(); }` at TA.cpp:396, under `if (sosDial) { ... } else`. A 911/933 goes through `sosFirstStep(haveCachedToken())` and, with a cached token, straight to the POST (TA.cpp:386-392) [verified; this is #862/#945]. `mediaStreamsLive()` has exactly two callers: `ensureToken` (TA.cpp:1416) and the maintenance refresh (TA.cpp:2431); neither is on a 911's call path [verified by grep].
2. **The rx task's hold is not socket I/O.** The two `makeAuthedClient` calls under `_getMutex` (TA.cpp:4499-4504, :4518-4529) are `esp_http_client_init`, which allocates and does not connect; the comment at TA.cpp:4513-4516 says so ("esp_http_client_init() allocates, it does not connect, so this is not a blocking network call under the lock"). I did not re-read ESP-IDF to confirm, so that part is **[inferred]** from the comment and IDF's documented behaviour. The code's own 2 s timeouts are never reached under that lock.
3. **The one 911-side reader of `getMutex` cannot wait.** The `sosRetryOn401` first lambda reads `s.getMutex` with `std::try_to_lock` (TA.cpp:503-504) [verified].

**Residual, not a 911 wait.** The rx task does hold `_getMutex` across `esp_http_client_close` + `esp_http_client_cleanup` in `teardownGetClient` (TA.cpp:4448-4456) and `recreateGetClient` (TA.cpp:4518-4529). Closing a TLS connection can write a close_notify, so that hold can touch the socket **[inferred]**. The waiters are `mediaStreamsLive` (maintenance and ordinary calls: not 911) and `stopMediaStreams`' brief `shutdown(fd)` section (TA.cpp:4315-4321) on the **same** slot. The latter is the only emergency-adjacent reader: a 911 hangup tearing down its own slot while its rx task is mid-recreate. It is bounded by close I/O, is not what #949 describes, and I did not trace it. Candidate for its own issue if the operator wants it, with a reproduction first.

Nothing to fix, no red test, no bench for #949 item 4. If the operator disagrees, the claim to test is "a 911 `makeCall` is delayed by `slot.getMutex`", and a positive control would be a stalled rx task holding that mutex while a 911 originates.

## 6. Neighbours seen, not claimed

- **`_ctrlMutex` on a 911's ordinary hangup.** `tel_drop` dropping a 911 leg takes the same mutex as `answerCall` and the warm-up. Same shape as hold 3, different caller **[inferred]**. Not in #949.
- **Head-of-line blocking in the single `tel_wsw` queue.** On the one-slot build a 911's upset waits behind any earlier work item (an inbound caller lookup, hold 2). Fixing holds 1 and 2 removes most of it **[inferred]**.

## 7. Recommended order

1. **Hold 3.** Smallest, self-contained, no change to an event contract, and it is the one whose wait is on the 911's own thread. Option A.
2. **Hold 1.** Done: #1088 landed option A, with the operator's ruling that an empty read on an emergency slot is Unknown.
3. **Hold 2.** Largest, because it touches the anchor event contract (option A). Option C is not enough alone; if the contract change is unwanted, B with the handler predicate is the fallback.
4. **Hold 4.** Nothing.

Each lands as its own PR, red test first. They do not share code beyond holds 1 and 2 both using the sos lane's claim.

## 8. First red test per item

`TelephonyAnchorClient.cpp` is ESP-only, so the repo's convention is a unittest that pins the wiring (tests/tools/test_anchor_sos_status_lane.py, test_anchor_sos_status_bounded.py) plus a gtest for any logic pulled into a header (SosStatusGet_test.cpp, floor listed in tests/min_tests.d/948-sos-status-bounded.txt). The tests below follow that. Each needs a positive assertion beside the absence, per the red-first gate. None is written here.

| Hold | First red test | Red today because | Positive control |
|---|---|---|---|
| 1 | Fixed by #1088: `tests/tools/test_anchor_leg_status_sos_lane.py` pins the wiring and `OutboundLegStatus_test.cpp` covers the Unknown step | Was red on `getLegStatus(const std::string&)` having no lane and the worker call passing none; now `getLegStatus(legId, bool sosLane)` is TA.cpp:1896 and the worker call at :3512 passes it | Ordinary callers (`reconcile`, `getParticipantCaller`, a non-emergency slot) still reach the `_statusMutex` path. Plus a gtest for the pure "what does a claim-held "" mean for an emergency slot" step, which the operator ruled on 2026-10-20 (Unknown) and #1088 shipped |
| 2 | Same file: in the inbound branch `evCb(... Incoming ...)` precedes the caller lookup in source order and the lookup is still performed | Today `getParticipantCaller` (TA.cpp:3465) comes before `Incoming` (:3470) | The lookup still happens, and `routeInboundAnchorCall` still defaults to "PSTN" on an empty id |
| 3 | `tests/tools/test_anchor_emergency_noslot_drop.py`: the `all %d call slots busy` emergency block contains no `dropCall(` / `performCtrl(` and does record the leg in fixed storage; a drain site exists and reaches `performCtrl`. Plus a gtest for the fixed table (add, drain, overflow) | The block calls `dropCall(ownLeg)` directly (TA.cpp:699) | The leg is still dropped (the drain calls `performCtrl` with the drop URL), and `return false` / `ownLegOut->clear()` are unchanged |
| 4 | none | the item does not hold | n/a |

A structural pin shows the wiring is as intended. It does not show a wait is gone. The operator's rule is a measured reproduction of each hold, and that cannot be written on a host: the stalled-peer wait is real I/O.

## 9. Which need a hardware bench

All three live holds need one for the measurement the operator asked for; none needs it for the red test above. Bench rules from the repo brief apply: the .244 board only, by-id port, nothing dialed to 911 or 933, nothing sent to the PSTN trunk host. Reproductions below use a non-emergency analogue where the hold is on a shared lane, and the emergency-only condition is checked by code reading.

| Hold | What the bench must show | Needs |
|---|---|---|
| 1 | Wall time from a stalled shared-lane GET to the outbound leg's Answered event, on a leg whose slot has the emergency number set. The slot flag can only be set by a real 911 `makeCall`, so the whole emergency condition is not benchable without dialing one; the shared-lane wait is, on an ordinary outbound leg (same code path, `emergency` only changes the lane since #1088) | A way to stall a status GET (3CX peer delay or a fault in the bench-probe build; I did not verify whether docs/BENCH_PROBE.md already has a slow-GET fault) **[not verified]** |
| 2 | Wall time from an inbound upset (empty `attached_data`) to `Incoming`, with the shared lane idle and with it held. The callback window itself is host-testable and needs nothing | Same stall; an inbound call from a test line |
| 3 | `makeCall` return time when `tel_drop` / `answerCall` holds `_ctrlMutex`. The no-slot branch needs a 911, so the bench can show only the `_ctrlMutex` wait through a non-emergency `dropCall`, not the branch itself; the branch is read, not run | A stalled control POST |

What stays unproven even after the bench: the 911-only branches (hold 1 emergency slot, hold 3 no-slot) cannot be exercised without dialing 911, which the rules forbid. The red tests pin their wiring; the lane behaviour is shown on non-emergency analogues and by reading.

## 10. What this document does not do

It does not change source or tests, claim holds 2 and 3 fixed, or measure any duration. The envelopes in sections 2 to 4 are arithmetic from a 2 s per-phase timeout and will be replaced by the reproduction numbers.
