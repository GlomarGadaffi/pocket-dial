# #888: an inbound or PSAP callback during a pending makeCall

Status: design only. No fix is claimed. No source or test changed. Everything below was read on
`origin/main` at fe447968 (symbols, with a few line numbers that drift).

Rule 5 context: nothing may gate, delay, refuse or misreport a 911/933 or a PSAP callback. A PSAP
callback after a 911 arrives as an ordinary route-point inbound on the anchor's source DN.

## 1. The code path (proven by reading)

`TelephonyAnchorClient::handleWsEvent`, the `TEL_EV_UPSET` branch, classifies an upsert whose
participant id matches no `CallSlot` (`slotForLocked(partId) == nullptr`) and is not a held own leg
(`telephony::inboundAnnounceAllowed`). It calls `countOutboundLocked`, which returns `nin` (outbound
slots keyed and not yet answered) and reads `pending` (`_outboundPending`). The table:

| nin | pending | result |
|---|---|---|
| 0 | 0 | `controlLegs = {partId}`: a new INBOUND. Worker allocs a slot, `evCb(Incoming)`. |
| 0 | >0 | **IGNORED** (`ignoredPending`). Nothing queued, nothing replayed. Logs the #888 witness. `pending` is the real makeCall count, or 1 under the #977 orphan hold (below). |
| 1 | 0 | absorbed: re-check the in-flight outbound leg, NOT `partId`. |
| >=1 | >0, or >=2 | ambiguous: re-check every in-flight leg, NOT `partId`. |

`_outboundPending` is incremented at the top of `makeCall` (before the POST, `PendingDec` RAII) and
decremented when `makeCall` returns. So the window is the whole of `makeCall` (TA.cpp:359-364 to its return): token work, the
POST (1.8-3.2 s measured on .244), `resolveOutboundLeg`, the list-read loop on an unread response
(bounded by `kUnreadAdoptWindowUs` = 4 s), and for a 911/933 the `emergencySlotRetryContinues`
wait for a slot. For one 911/933 failure #977 extends it past the return, by up to 4 s.

#977 adds a second source of `pending`. `countOutboundLocked` (TA.cpp:3622) computes it with
`telephony::pendingWithOrphanHold` (SosStatusGet.hpp:422, called at TA.cpp:3642-3644). The hold
exists on one path only: a 911/933 whose #349 list-read window ended with no read showing 3CX's
list (`orphanSweepWanted`, SosStatusGet.hpp:394). `makeCall` then arms an orphan sweep before it
returns false (TA.cpp:621-623; `armOrphanSweep`, TA.cpp:2443), because 3CX may hold a live call to
the PSAP that the unit cannot see. `armOrphanSweep` sets `_orphanHoldUntilUs` to the arm time plus
`kOrphanSweepWindowUs` (4 s, equal to `kUnreadAdoptWindowUs`; TA.cpp:2450, SosStatusGet.hpp:387).
While that deadline has not passed and no makeCall is pending, `pendingWithOrphanHold` reports 1,
so the (0, >0) row applies after `makeCall` has returned. The hold ends at the first of: the sweep
ending (`HoldEnd`, TA.cpp:2500-2505), the sweep finding and noting the leg (TA.cpp:2553), or the
4 s bound. It covers only an id first upserted while a makeCall was pending, between the POST and
the arm (`_pendingSeen.seenIn`, TA.cpp:3644). So it adds no id to the set #888 already ignores: it
lengthens how long those ids' repeat upserts are ignored, by up to 4 s past the return, on this
double failure only. Any other id, such as a PSAP callback that first appears after the return, sees
the real count and rings (Rule 5). A held id is still not queued or replayed, and its `ignoredPending`
witness line reports an age measured from the last real makeCall.

After the window closes, only two things could still find the ignored participant, and neither does:

- The #743/#349 re-check at the end of `makeCall` is queued with `controlLeg = partId = ownLeg`. It
  rechecks the outbound's own leg, never the ignored one.
- The reconcile watchdog (`reconcileTaskTrampoline`) GETs `/participants` but only tears down slots
  whose leg is absent. It has no path that creates an inbound.

So if 3CX sends that upsert once, the board never rings for it. The existing code comments say the
same ("Telephony does not repeat a Connected one").

## 2. The wider window (also proven by reading, and larger than the issue says)

The issue frames 1-3 s. The `nin >= 1` rows are the same loss with a much longer window. Once
`makeCall` has keyed the outbound's slot (`outboundActive` set, `outboundAnswered` false), an
unmatched inbound upsert is **absorbed**: mapped to the outbound's leg, which the worker re-checks
with a status GET. The inbound's own `partId` is dropped. That lasts until the outbound answers or
ends. A ringing 911 is never reaped (#712) and the ringing grace is 120 s (issue #888 comment of
2026-10-09, and the 2026-10-09 review of option A). So the loss window for a Connected-once inbound
is up to ~120 s, not 1-3 s, whenever an outbound is ringing. The pending-only reading understates it.

## 3. Can a callback be lost? Two separate questions

**Proven by reading:** an unmatched upsert during the window is discarded without being held, and no
later code path re-derives it from `/participants`. If 3CX sends exactly one such upsert, it is lost.

**Depends on 3CX behaviour nobody here has verified:**
1. Does 3CX send only one upsert for a route-point inbound that is Connected from the start? The
   "does not repeat a Connected upsert" premise exists only as code comments (#100 era, and the
   #743 comment). `docs/3cxAPI+Webhooks.md` documents event types and says an upsert is "entity added
   or updated" but gives no repeat cadence; `ADR-002` does not cover it. A route-point inbound
   normally passes through a ringing/Dialing state first, which 3CX does repeat (~750 ms), and that
   would heal the loss. The loss needs the inbound to be Connected at its first upsert.
2. Does a route-point inbound carry `direct_control: true`? Unknown. It matters only to the
   list-fallback path, not to the classifier above.
3. When an outbound is placed, does 3CX surface its far leg on the source DN as its own participant
   with a distinct `partId`, and which field separates it from a route-point inbound? This is the
   fact that decides whether a replay can tell the two apart (see option A's rejected review).

Net: loss is possible by the code; likelihood is unmeasured. The issue's PLAUSIBLE label stands.
`x888_ws_upsert` case 2 exercises only the `nin >= 1` absorbed branch. It has no case for
`pending > 0` with `nin == 0` (the 1-3 s window), so that branch is still unwitnessed on a board.

## 4. Options

### A. Hold and replay (the 2026-10-09 default; reference branch `fix/888-pending-makecall-window`, 0d20a3e5, no PR)

Hold up to ~8 unmatched ids (bounded, no heap after init) when ignored or absorbed. When the window
closes, re-run each through the classifier.

- Cost: a small fixed ring in `TelephonyAnchorLogic.hpp` plus the classifier moved there. Moderate diff.
- Risk, from the Sonnet review: the in-flight half delays a genuine inbound or PSAP callback until the
  ringing outbound resolves (up to 120 s). Closing the window at `makeCall` return does not help,
  because at that moment `nin == 1` and the replay absorbs it again. Replaying only the pending
  half (`nin == 0`) is safe but leaves section 2 open. Also risks a false ring of the handset for the
  PBX's own far leg when the makecall failed or the leg was list-adopted. That is a ring on a leg that
  carries silence, and the 2026-10-09 comment accepted it under Rule 5.
- Needs the distinguishing field (3.3) to be safe for the in-flight half.

### B. Reconcile by `/participants` GET when the window closes

At `makeCall` return, and again when an outbound answers or ends, run one list GET of the source DN
and enqueue any controllable participant that has no slot, is not a held own leg, and is not the far
leg of a live outbound. Nothing is held; 3CX's own state is the authority, as `resolveOutboundLeg`
already does for the unread-response case.

- Cost: one extra blocking TLS GET per makeCall on a worker (the status GET already exists, so no new
  parser), plus the filter. Needs a maint/worker slot, so it competes with the 911 lane (#862/#945).
  It must be off the 911/933 critical path: run after the POST and slot keyed, never before.
- Risk: the same far-leg versus inbound ambiguity, but resolved from live data rather than guessed.
  Fires on every outbound whether or not an inbound arrived (cost with no benefit in the common case).
  A snapshot taken at one instant still misses an inbound that arrives and ends between snapshots, but
  that call is also gone for the user.
- Healing by listing also covers the case where 3CX does repeat nothing at all.

### C. Do not ignore: classify by the participant's own fields instead of by counts

Replace "ignore while pending" with a decision from the upsert and one status GET of `partId`
itself (does `party_dn` equal our source DN, is it a route-point leg, is the `entity` path ours).
Hold nothing.

- Cost: a status GET per unmatched upsert during the window; needs the field from 3.3.
- Risk: the classification is a guess until the bench says which field is reliable. Blocking GETs on
  the WS-event path are not allowed (the work already moved to workers for #43), so it is a worker job.

### D. No behaviour change, instrumentation only (current state)

The #888 witness lines are already on main (ignored while pending, dropped as own leg, absorbed,
work item not queued, with `nin`, `pending`, `active` and the 256-line cap). The `ws_upsert` probe
fault and `x888_ws_upsert` scenario exist. Cost: none. Risk: the loss, if real, stays.

## 5. Recommendation

Stay on D until the capture below answers 3.1 and 3.3, then build **B** (reconcile), not A. Reasons:
B takes 3CX's state as the authority, so it needs no held-id ring and does not delay a callback
behind a ringing outbound the way A's in-flight half does (the Rule 5 objection). It covers both the
1-3 s window and the longer absorbed window, since it is triggered by outbound events, not by the
ignored upsert. C is attractive only if the capture shows a reliable per-participant field. If the
capture shows 3CX does repeat the Connected upsert, close #888 as not an issue and keep the witness.
If it shows a route-point inbound is Connected from its first upsert and sent once, B becomes
required before v1.7.0 ships anything that depends on callbacks during outbound calls.

Rule 5 constraints for any of A, B, C: the check must never gate or delay `makeCall` for a 911/933,
must run after the POST, must not hold `_mutex` over a GET, must not allocate after init, and must
never suppress an Incoming event for a leg that is not provably our own far leg. When in doubt, ring.

## 6. First red test

`TelephonyAnchorClient` is a host stub (`#if !defined(ESP_PLATFORM)` arm), so a real "fake anchor"
cannot drive `handleWsEvent` on the host. The classifier is inline in that function. The first
step is therefore to lift the decision, with no behaviour change, into `TelephonyAnchorLogic.hpp` as a
pure function, e.g. `classifyUnmatchedUpsert(nin, pending, ownLeg) -> {Inbound, IgnorePending,
RecheckInflight, OwnLeg}`, called from `handleWsEvent`. Then in `tests/TelephonyAnchorLogic_test.cpp`:

1. Pin current behaviour (green): `(nin=0, pending=0) -> Inbound`; `(0, 1) -> IgnorePending`;
   `(1, 0) -> RecheckInflight`.
2. The red test, for the chosen fix (written first, run, output recorded before the fix):
   a fake anchor model owning an `OwnLegs` table and a counter pair, fed this sequence: `makeCall`
   begins (`pending=1`), a Connected upsert for unknown id `P` arrives, `makeCall` returns
   (`pending=0`, slot keyed so `nin=1`), then the outbound's own re-check runs. Assert positively
   that `P` is eventually delivered as an Incoming event exactly once (count == 1, via a hook, not
   occurrence), and that the outbound's own leg is not announced as an inbound (count == 0 for it).
   On today's code the count for `P` is 0, so the test fails on an assertion about a positive
   outcome, not on absence alone.
3. A second red for the longer window: same, but `P` arrives while the outbound rings (`nin=1,
   pending=0`). Fails today the same way (absorbed, count 0).
4. Rule 5 pair: a 911/933 makeCall must never be delayed by the replay or reconcile, asserted on the
   pure scheduling decision (the check runs only after the POST step), plus an emergency-exempt case.

If B is chosen, the test target is the pure filter `shouldAdoptListed(participants, slots, ownLegs,
inflightFarLegs)`, with the same two scenarios expressed as a list snapshot.

## 7. What a board capture would settle (harness only)

Run on bigdog with the existing probe and harness only (`docs/BENCH_PROBE.md`, `x888_ws_upsert`
scenario family). Never dial 911, 933, 113 or 1001; the harness already refuses these. No credentials in
logs, repo or command line. Far end only, one brief ring per case.

Capture, per scenario, the full WS frame stream with timestamps, and a `/participants` listing taken
at the start and end of the pending window:

1. **Does 3CX repeat a Connected upsert?** Place a route-point inbound from the harness to the anchor's
   DN while no outbound is pending. Record how many upserts 3CX sends for that participant and their
   status field at each. Settles 3.1 directly and stops the "premise is code comments" problem.
2. **The window itself.** Start an outbound makeCall from the harness, and during the 1-3 s POST send
   a route-point inbound. Record whether the inbound's first upsert is Connected, whether it is sent
   again, and whether the witness line `Upset ignored while N makeCall(s) pending` fires. That is the
   branch with no probe case today.
3. **The far-leg identity.** In the same capture, list `/participants` when the outbound rings: does the
   far leg appear on the source DN as a separate participant with its own `partId`, and which field
   (`party_dn`, `direct_control`, `entity`, call id, `status`) differs from the route-point inbound's.
   Settles 3.2 and 3.3 and decides between A, B and C.
4. **The longer window.** Repeat (2) while the outbound is already ringing (`nin=1`) and read the
   `absorbed` witness line plus whether the inbound is ever delivered.

A capture of only one repeat cadence (1) is enough to decide whether to close the issue.

## 8. Not covered here

No hardware, no 3CX, no bigdog run was done for this document. Nothing about 3CX's repeat behaviour is
verified. Sections 1 and 2 are source reading only. Related: #816, #883, #379, #743, #349, #712, #862.
