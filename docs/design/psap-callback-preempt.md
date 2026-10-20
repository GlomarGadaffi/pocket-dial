# Design: an inbound PSAP callback pre-empts one non-emergency call (#967)

Status: Implemented. Host tests are written but have not been run by the author; nothing is bench-verified.

Decision: desmo, 2026-10-19, option A (pre-empt), posted on #967. It supersedes his 2026-10-09 "no pre-emption yet".

Rule 5: nothing may gate, delay, refuse or misreport a 911/933 or a PSAP callback.

## 1. The gap

An inbound anchor call is the anchor's `CallEvent::Incoming`, handled by `RequestsHandler::routeInboundAnchorCall`. It refused the call for two reasons, both checked before it knew whether the call was a PSAP callback (#659):

1. Every media bridge was busy (`allBridgesBusy()`). `POCKETDIAL_MAX_ANCHOR_CALLS` is 4 by default and 1 on a `SIP_CONSTRAINED` build, so one live anchor call is enough there.
2. Another anchor inbound was already ringing or up. This applies on every build, limit 4 included.

A callback to an extension inside its 30 minute window was dropped like any other call. The outbound side already had the answer: #624 ends one non-emergency anchored call for a 911/933 that finds the anchor full (`preemptAnchorCallForEmergency`).

## 2. The options

| | Option | Cost |
|---|---|---|
| A | Pre-empt: end one non-emergency anchored call and route the callback, as #624 does | Only a call that stands in the callback's way is ended, and only while some extension is inside its window. Under ring-all that is effectively global (section 3) |
| B | Reserve: refuse ordinary anchor calls while any extension is in its window | On a limit 1 build this blocks every ordinary anchor call for 30 minutes after any 911/933 dial, 933 included |
| C | Keep dropping, record a known Rule 5 gap | None, and the gap stays |

Chosen: A. Sub-rulings: the callback may also end another anchor inbound that is ringing or up ("drop 2"); only non-emergency calls are ever ended.

## 3. What was built

`routeInboundAnchorCall` now gathers its targets first, so `isEmergencyCallback()` is known before either refusal. A call that is not a callback is refused exactly as before, with the same log lines. A callback that would be refused calls `preemptAnchorCallForPsapCallback()`; if that returns true the callback is routed in the same call, and if false it is dropped as before, with one extra error-level log line.

`endAnchorCallForPreempt()` is the teardown #624 already had, moved out unchanged except that the outbox and the reason are parameters: a 503 or CANCEL while the victim still rings, else a BYE, then `endCall()`. #624 passes `_outbox`; the callback passes `_asyncOutbox`, because it runs on the anchor's event task and the SIP thread clears `_outbox` at the start of its next pass. Sending on `_outbox` here would end the victim locally and leave its phone off hook on a dead call.

### What flags a callback

With no DID mapping, which is the default ring-all, the call is a callback if ANY registered extension is inside its window. So for 30 minutes after any extension dials 911 or the 933 test, an inbound PSTN call that finds the anchor busy, or another inbound live, may end a live ordinary call. On a limit 1 build one 933 test dial plus one live ordinary call is enough. The flagging is #659's and was already there; ending a call because of it is what is new. A DID mapping narrows it to the mapped extension.

### Victim rule

Let `inbounds` be the anchor inbound sessions not in Bye, and `busy` be `allBridgesBusy()`. If neither applies there is nothing in the way and no call is ended. Otherwise the victim is the first anchor session that is not in Bye, is not an emergency call, and:

- is that inbound, when one is in the way (`inbounds` is 1); and
- holds a bridge, when the bridges are the blocker.

Both conditions apply when both reasons do. The victim is chosen before anything is ended. If no session qualifies, or `inbounds` is above 1, nothing is ended and the callback is dropped as before. After the victim is ended `allBridgesBusy()` is read again, and a callback is routed only if it is false.

| Situation | Result |
|---|---|
| Bridges full (limit 1), held by a non-emergency call | That call is ended (BYE to its phone, far leg dropped), the callback is routed at once |
| Another inbound ringing, no bridge | That inbound is ended (CANCEL to every ringing fork, far leg dropped), the callback is routed |
| Another inbound up, holding the bridge | That inbound is ended (BYE to the phone that answered), the callback is routed |
| The live anchor call is an emergency call (the original 911 still up, or an earlier callback) | Nothing is ended; the callback is dropped as today. Known limit, section 5 |
| The call is not a callback | Dropped as today, nothing is ended |

## 4. Rule 5

- Not delayed. The pre-emption runs inline, inside the same `_mutex` hold the event callback already has, and the callback is routed in that call. Nothing waits for the victim's far leg to be dropped.
- No lock held across I/O. The victim's far-leg drop is posted to the `tel_drop` lane (`asyncDropCall`, a non-blocking queue push, as #624 and every teardown on this path do). Its phone's 503, CANCEL or BYE is queued on `_asyncOutbox` and goes out with the SIP thread's next pass. `endCall()` calls `MediaBridge::stopBridge()`, the same local teardown `anchorDroppedLocked` runs on this thread: no network I/O.
- No new allocation path. The two scans walk `_sessions` and `_mediaBridges` in place. The teardown allocates what #624's does (pooled SIP messages). The one new cost: the target list (`std::vector` of `shared_ptr`) is now built before a busy or second-inbound refusal as well, where it used to be built only after both passed.
- Only non-emergency calls are ended. An emergency call is never a victim.

## 5. Known limits and hazards

- **Live emergency call.** With the original 911 still up and holding the only bridge (limit 1), or an earlier callback still ringing or up, the callback is dropped as before and an error-level line is logged. The ruling forbids ending an emergency call. On a build with a higher limit the same holds when every bridge is held by emergency calls, or when the inbound in the way is an emergency call. Pinned by two host tests.
- **One victim.** A ringing ordinary inbound (no bridge) together with a bridge held by another call needs two calls ended. The ruling says one, so nothing is ended and the callback is dropped as before. Pinned by a host test.
- **Phones ring with no bridge.** The pre-emption frees a slot, but a callback that rings is not guaranteed a bridge when its phone answers. Where the code prevents it: when the bridges are the blocker, the victim must hold one, so a bridge is free when the callback is routed, and the free bridge is checked again before routing. Where it does not, as before this change:
  - An outbound call that is ringing (no bridge yet) is not a reason to refuse an inbound, so it is not ended. If it is answered before the callback's phone, it takes the bridge, and the callback's answer finds none (`onInboundAnchorOk` hangs up both legs, "inbound bridge failed"). On a limit 1 build this window is the ringing time of that call.
  - If the virtual-peer or session pool is exhausted after the victim was ended, the callback is dropped by the existing pool-exhaustion refusal and the victim is already gone. Ending the victim frees one of each, so this needs the pools to be nearly full for other reasons.
  - The provider's own call slot is released when the `tel_drop` job completes, not when the victim is ended. The callback already holds its slot at the provider (it arrived as `Incoming`), so this does not gate it.
- **No ordinary-call fix.** An ordinary inbound call is refused under the same two conditions as before. Only a callback pre-empts.
- Not changed: a callback still sends no `notifyEmergency()`; that is a separate gap and not part of #967.

## 6. Tests

`tests/EmergencyRoute_test.cpp`, section G (`EmergencyCallback`). Each asserts the wire after `tick()`, so a victim left off hook fails the test.

| Test | Pins |
|---|---|
| `InboundPsapCallbackWhileBridgesAreFullPreEmptsTheHoldAndIsRouted` | Bridges full: the hold gets a BYE and is gone, the callback is an emergency inbound session that rings both phones |
| `InboundPsapCallbackPreEmptsAnOrdinaryInboundCallThatIsStillRinging` | "Drop 2", ringing: forks cancelled, callback rings |
| `InboundPsapCallbackPreEmptsAnOrdinaryInboundCallThatIsUpAndHoldsTheBridge` | "Drop 2", up: BYE to the phone that answered, callback rings |
| `InboundPsapCallbackNeverEndsTheLiveNineOneOneAndIsDroppedAsBefore` | Live 911: untouched, callback dropped |
| `InboundPsapCallbackNeverEndsAnEarlierCallbackStillRinging` | Earlier callback: untouched, callback dropped |
| `InboundPsapCallbackThatOneEndedCallCannotMakeRoomForEndsNothing` | Ringing inbound plus held bridge: nothing ended |
| `InboundOrdinaryCallWhileBridgesAreFullIsStillDropped` | A call that is not a callback is still dropped |

The host anchor holds one call, so the "drop 2" tests reach the state the way a larger build would: the window is closed while the ordinary call rings and reopened for the callback (`ageEmergencyCallbacksForTest`).

Not verified: nothing was run on a board or in a host build when this was written. The async tel_drop path is covered only through the Loopback anchor's synchronous drop.
