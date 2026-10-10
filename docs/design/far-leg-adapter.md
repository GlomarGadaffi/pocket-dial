# Far-leg adapter: design for #691, #692, #693

Status: proposed, for vote. Nothing here is decided, and no code changes with this file.
Author: BigDog (Claude Sonnet 5.5). Written 2026-10-09 against origin/main 7bcf952f.
Every file:line is on 7bcf952f. The issues cite d210d21, and most of those lines have moved.
`RH` = src/SIP/RequestsHandler.cpp, `RH.hpp` = its header, `TAC` = src/SIP/TelephonyAnchorClient.{hpp,cpp}.
(The rest of docs/design/ is retired SSH-terminal design history. This file is unrelated to it.)

## 1. The problem

A 3CX call has two legs: the handset's SIP dialog and a far leg that lives on 3CX. The handset side is a
`Session` keyed by Call-ID. The far leg has no record of its own. Its state is inferred, path by path, from
three places: flags and a participant id on the Session (Session.hpp:433,450,453-454), whether a MediaBridge
exists (RH:8831-8909), and a set of per-slot fields in the transport (section 2). A teardown path must know
which of them it can see, and must also remember to mark the leg released, or the leg is dropped twice
(RH:8883-8891; eight sites set the mark). Every #379 hole came from this. #380 closed both known orderings with
targeted checks (#381 body), so none of the three issues fixes a live bug; the model underneath is unchanged and
the inference keeps growing: the grep #693 defines gives 30 lines on d210d21 and 38 on main. The trunk's far leg
(`SipTrunk`) is the other shape: keyed by the handset Call-ID, one state per call, `placeCall`/`hangup` safe in
every state. The issues give the anchor the same per-call record in three steps: outbound behind a build flag
(#691), inbound (#692), delete the old path (#693). This file says what that means on today's main, what it
costs, what it must not touch (911, 933, PSAP callbacks), and asks for a vote.

## 2. Current state on main

### 2.1 Where the far leg lives

| Fact | Where it is | Cite |
|---|---|---|
| Interface | `AnchorClient`, keyed by participant id: `makeCall(dest, ownLegOut*)`, `answerCall(id)`, `dropCall(id)`; events Ringing, Answered, Dropped, Dtmf, Incoming, MediaNeverOpened | AnchorClient.hpp:32,67,71,74 |
| Providers | Loopback and Telephony are registered. `ApidazeAnchorClient` is a header; only tests/AudioSocket_test.cpp:3 includes it | RH:346-347 |
| Build flag | `POCKETDIAL_ANCHOR_FARLEG` does not exist (no hit anywhere in the tree). Nearest precedents: HAS_ANCHOR/HAS_TRUNK, TRUNK_INBOUND, constrained defines | PoolConfig.hpp:317-322,335-337; main/CMakeLists.txt:272-309,321-349 |
| Outbound entries | 555 via `onAnchorInvite`; dial-plan Trunk rule via `routeTrunkCall`; **911/933 via `routeEmergencyCall`**. All three call the same `originateAnchorCall` | RH:4694,13095,4791,5024 |
| Sync arm | Loopback only; `makeCall` under `_mutex` | RH:5163-5275 |
| Async arm (3CX) | capacity check, session, a 911 job posted before the session is published, 180, ordinary job | RH:5283-5352 (911 job :5310) |
| Dispatch | `asyncMakeCall` heap-allocates a `TelCtlJob` and posts it to lane sos (emergency) or ctl; drops go to lane drop. Three lanes since #657 | RH:5396-5423 (`new` :5400, lane :5409); RH.hpp:2162-2190 |
| Worker | `runTelCtl`: `makeCall` off `_mutex` :5609, bind :5631 (via :5357), orphan drop when bind misses :5633-5648 | RH:5592-5653 |
| Events | callback installed only when `!anchorIsSynchronous()`. Handles Answered, Incoming, Dropped, MediaNeverOpened. Ringing has no branch, and TAC never emits Ringing (only Loopback does) | RH:468,472,572,578,582; LoopbackAnchorClient.cpp:132 |
| Teardown | `endCall` anchor block: drop via bridge, else via the session's participant id, gated on the released flag. 17 `asyncDropCall` callers, 15 direct `makeCall`/`dropCall`/`answerCall` lines (none outside RH) | RH:8831-8909 |
| Released-flag sites | 5457 5475 6237 6505 6658 10525 10552 10805 | RH |
| Inbound, transport | `Incoming` is fired from a classifier that calls a participant "ours" iff `slot.outboundActive` | TAC.cpp:2674-2692,2740 |
| Inbound, engine | `routeInboundAnchorCall` (forks, `setEmergency` from the callback window :5912), `onInboundAnchorOk` -> `asyncAnswerCall` | RH:5784-5933,6084-6268,6255,5573 |
| Inbound teardown | all busy :6495-6509, all unavailable :6648-6662, no answer :10513-10525, 3CX Dropped :5482-5513, bridge failed :6229-6240. Not in #692's list: 911 pre-emption :4638-4686, MediaNeverOpened :5445, degraded-audio sweep :10752-10805, orphan-bridge reap :10975-11003, six drops before any session exists :5799-5906 | RH |
| Transport state | per slot: `outboundActive`, `outboundAnswered`, `ringing`, `ownLegHeld`, `farPartId`, `inboundSignaledPartId`, `getFailFast`; per handler: `_outboundPending`, `_ownLegs`. ESP-only | TAC.hpp:93,173-180,214,218,228; AnchorWedge.hpp:24 |
| Hold | already recorded: `Session::State::Held` and `MediaBridge::setHeld` | RH:11460,11468 |

### 2.2 Premises in the issues that have moved

| Issue text | On main |
|---|---|
| "line numbers on d210d21" | Shifted by thousands; examples: event callback :405 is :468, `routeInboundAnchorCall` :4712 is :5784, `answerAnchorReinvite` :9517 is :11420 |
| 30 branch lines (#693 command) | **38**: 20 `isAnchor()`, 27 `isAnchorInbound()`, 9 both. Run on 7bcf952f |
| Per-call `new MakeCallArg` replaced by a fixed slot | Gone. It is `new TelCtlJob` from the #657 pool (RH:5400,5433,5586). A slot array does not remove it unless it also replaces the pool, which this design does not do |
| The worker is ESP-only; #379 cannot be driven on the host | False since #657/#713. The host runs the pool (RH.hpp:2207-2219); `forceAsyncAnchorForTest` (:517) and `holdTelCtlForTest` (:541) drive #379 Case A with a real worker and count drops through `LoopbackAnchorClient::dropCallCount()` (TelCtlPool_test.cpp:211). The comments at AnchorRouting_test.cpp:249,285 are stale. **Still undrivable on the host: events.** The callback stays unwired under `forceAsyncAnchorForTest` (RH.hpp:513-515) |
| Constrained build has "about 1.5 KB free (#689)" | Predates #731/#933, which compile `SipTrunk` out of the constrained build (main/CMakeLists.txt:321-349). #938 reports 168,752 B free on 3ee4aa6d. Not re-measured here |
| "State { Free, Trying, Proceeding, Confirmed, Terminating }" | `SipTrunk::State` has a sixth value, `Cancelling` (SipTrunk.hpp:181) |
| #942 as the committee verdict "design first, sequenced" | #942 covers #174, #168, #160, #179, #180, #208 and names none of these three. The design-first block is glomar-51's 2026-10-09 comment on each issue |
| "Most of those branches disappear" (#381) | About 16 of 38 (next table) |

### 2.3 The 38 branch lines, by what they decide (my reading, three lines of context each)

| Bucket | Lines | n |
|---|---|---|
| Find the far leg (lookup by flag or participant id) | 484 495 4650 5362 5451 5473 5816 10752 10967 10990 | 10 |
| Who owns the drop (teardown ownership) | 6495 6648 8767 10465 10513 10532 | 6 |
| Which near-leg dialog role we play (UAC to the handset on inbound, UAS on outbound) | 1793 1976 4664 5482 6299 6391 6753 6844 7208 7485 10848 10904 11553 11746 | 14 |
| Exclude anchored sessions from a feature (relay, splice, transfer) | 2097 7281 7756 7757 8022 | 5 |
| CDR direction | 8768 10937 10939 | 3 |

Only the first two buckets are far-leg state. The other 22 describe the handset's dialog or a feature exclusion
and stay under any adapter. #693's "each is removed or stays with a comment" is right; "most disappear" is not.

## 3. The shelving question

What the issues borrow from `SipTrunk` is a shape: a fixed array of per-call slots, a state per slot, the handset
Call-ID as key, and a `hangup` that is safe in every state. Not code. `SipTrunk` is a shelved line (desmo,
2026-10-07: milestone 11 parks #919 #874 #873 #618 #175; the #381 direction-update comment of 2026-10-08;
ADR-002, Accepted). On the constrained build it is absent: `HAS_TRUNK=0`, zero trunk calls, and SipTrunk.hpp:640-781
is a stub (PoolConfig.hpp:326-330; ADR-002:78-85). Two decisions follow, and both are in this design:

1. `AnchorFarLeg` includes no `SipTrunk` header and reuses no `SipTrunk` type. It names its own states (below);
   "Trying" and "Proceeding" are SIP transaction words, and 3CX never evented a ring.
2. The key is the handset Call-ID, not the anchor id. ADR-002:51 writes `hangup(anchorCallId)`. While `makeCall` is
   in flight no anchor id exists, and that window is #379 Case A. The participant id is an attribute bound at
   completion. ADR-002's `IAnchorProvider` is not in code (no hit); the interface is `AnchorClient`. Putting the
   handset Call-ID into `makeCall` (ADR-002:50) is a provider-API change this design neither needs nor includes.

**Case 1: the trunk line stays shelved (the planning assumption).** Is #691 still worth it? Its payoff does not
depend on `SipTrunk`. It buys exactly-once, call-keyed teardown for the only outside line on a constrained build,
deterministic host tests for the Answered/Dropped/MediaNeverOpened orderings (the part TelCtlPool-style tests
cannot reach), and a seat for a second anchor's lifecycle that is not derived from participant ids (Apidaze is a
header only today). It does not buy a bug fix, bytes (not before #693), or any new behaviour. What changes in the
issues: drop "SipTrunk-shaped" from the titles and bodies, keep the flag compile-time, and take no dependency on
`SipTrunk`. Cost in this case: the change touches `originateAnchorCall`, which carries 911.

**Case 2: the trunk line is un-shelved.** Then both shapes are live again and the epic's original aim returns: one
listener and one state vocabulary for both. That convergence should wait until a carrier can test it (#919 #874
#873 #618 are what is parked); designing the shared interface now would fix the shape of a line we cannot
exercise. Nothing in #691-#693 changes. A follow-up "converge `AnchorFarLeg` and `SipTrunk` listeners" issue is
filed then. The constrained build is unaffected (#933 refuses a trunk there at configure time).

In neither case does #691's value hinge on the trunk. What the shelving changes is vocabulary and the absence of
a second consumer.

## 4. Design

### 4.0 Shared core

`AnchorFarLeg` (new, src/SIP/AnchorFarLeg.hpp, header-only). **Decide-only:** no I/O, no lock of its own, called
only under `RequestsHandler::_mutex`. Each method updates a slot and returns what the engine should do; the engine
keeps doing the I/O on the existing #657 lanes. So the lanes (sos included), lock-hold rules (CONTRIBUTING_FIRMWARE
1.B) and "no socket call under `_mutex`" stay exactly as today, and tests need no threads.

- Slot: `state`, `callID[128]` (SipLimits::kMaxCallIdLine is 127, SipMessage.hpp:70, enforced at SipMessage.cpp:945,
  so any Call-ID the engine accepts fits and `placeCall` cannot fail on length), `part[N]`, a leak-guard timestamp.
  No destination (the job carries it) and no emergency field until step E. About 190 B a slot, no per-call heap.
- Slot count: `POCKETDIAL_MAX_ANCHOR_CALLS + kTelCtlWorkers + kTelCtlDepth`, the same arithmetic as `kTelDropDepth`
  (RH.hpp:2185-2186): a caller that hangs up while its `makeCall` is queued or running keeps its slot until the
  worker returns (TelCtlPool_test.cpp:217). Legs 3CX holds are bounded by the transport's own slot count
  (TAC.cpp:606), unbound ones by the job queue (RH:5409). Admission stays where it is today (RH:5283-5292 and the
  post); `allBridgesBusy` counts only bridged calls (RH:4597-4605,4635), not ringing ones. By this sizing
  `placeCall` returning false is unreachable unless a slot leaked.
- States: `Free`, `Placing` (`makeCall` queued or running; no anchor id yet), `Abandoned` (hangup arrived while
  Placing; drop on completion), `Ringing` (id bound, no Answered), `Up`. There is no Terminating: `dropCall` is
  fire-and-forget on the drop lane (result ignored, RH:5596), so there is no transaction to wait on, and a slot
  held for the drop would cost capacity (constrained: 1 call).
- Methods: `placeCall(callID)`; `onPlaced(callID, ok, leg)`; `hangup(callID)`; `onAnswered(leg)`;
  `onRemoteDropped(leg)`; `sweep(now)`. All but the first return an `Action`: `None` or `Drop(leg)`.
- Invariant, enforced by the state machine instead of a flag spread over eight sites: `Drop(leg)` is returned at
  most once per leg. `hangup` in Placing -> Abandoned (no drop yet); `onPlaced(ok)` in Abandoned -> `Drop(leg)`, Free;
  `hangup` in Ringing/Up -> `Drop`, Free; `onRemoteDropped` -> Free and never `Drop`; any call on Free -> `None`.
  So 3CX's Dropped racing our hangup is at most one drop in either order (Dropped first: slot Free, later hangup
  is `None`; hangup first: slot Free, later Dropped finds no slot).
- `sweep` is a leak guard only. The call-level deadline stays the Session ring timer (RH:5322, tick :10532). It
  frees a slot stuck in Placing/Abandoned past a bound (set by measuring the worker's TLS timeout in the #691 PR;
  not measured here). A leaked slot is the new failure mode: today a missed transition leaves a stale flag, with
  fixed slots it also leaks capacity.
- **Change to #691 (D).** The issue has `sweep` drop a slot past its deadline and report `onFailed(408)`. On a
  ringing 911/933 that is forbidden: no PBX-side no-answer bound applies (#712, RH:10469-10470,
  AnchorRouting_test.cpp:1695). (D) is rewritten to test the leak guard; the 408 listener callback is not built.
  The listener (`onRinging`/`onAnswered`/`onFailed`/`onRemoteBye`) is also not built: the engine calls the
  adapter, and `Action` carries the result, which removes a callback re-entering `_mutex`.

### 4.1 #691: outbound, behind `POCKETDIAL_ANCHOR_FARLEG`

**Step 0, before the flag (an amendment).** The issue's wiring list (`onAnchorInvite`, `endCall`, Answered/Dropped)
misses the other outbound drop sites: tick no-answer (RH:10532-10552), degraded sweep (:10804), MediaNeverOpened
(:5457-5462), orphan-bridge reap (:11002-11003), worker orphan (:5647). At flag 1 each would drop without telling the
adapter, and `endCall`'s `hangup` would drop again. So first, at flag 0 and with no behaviour change, replace the
`asyncDropCall(part); setAnchorLegReleased();` pairs (6236 6504 6657 10524 10551 10804, and 5457/5462) with one
helper, `releaseFarLeg(Session&)`, plus a no-drop form for :5475 (3CX already dropped it). Flag 1 then changes one
function body, not six sites. The existing suite is the net. Step 0 pays off on its own (poll option C).

| | |
|---|---|
| Files | AnchorFarLeg.hpp (new); RH `originateAnchorCall` async arm :5283-5352, `runTelCtl` Make :5608-5652, event callback :472/:578/:582, `endCall` :8831-8909, the helper; RH.hpp (member, test hooks); PoolConfig.hpp; tests/CMakeLists.txt; tests/AnchorFarLeg_test.cpp; tests/min_tests.d/<N>-anchor-farleg-outbound.txt |
| Wiring (flag 1) | `placeCall` before the job is posted (false -> `refuseBeforeDispatch`); `runTelCtl` calls `onPlaced` in place of `bindOutboundParticipant`, and a `Drop(leg)` replaces :5633-5648; `endCall` calls `hangup(callID)` and posts `Drop` on the drop lane; Answered/Dropped call `onAnswered`/`onRemoteDropped` |
| Behaviour, flag 0 | None from the flag: new code is `#if`-ed out and the Loopback sync arm :5163-5275 is untouched. Step 0 does change default-build code, so it states its own measured delta, and #691's "0 B" is measured against main after step 0 |
| Behaviour, flag 1 | Ordinary (non-emergency) 3CX outbound only. Emergency bypasses the adapter at the `emergency` local (RH:5086). The Answered-before-bind fallback (RH:491-502) is left alone: a slot in Placing has no leg id to hold an early Answered against |
| Flag | Compile-time, own `#ifndef` in PoolConfig.hpp, never nested (note at :302-309), default 0; the S3 bench image builds 1. Runtime toggle: not recommended (section 7) |
| Rollback | Flag off, or revert. No NVS, no wire change, no data migration |

### 4.2 #692: inbound

| | |
|---|---|
| Files | RH `routeInboundAnchorCall` :5784-5933, `onInboundAnchorOk` :6229-6255, the busy/unavailable/no-answer/Dropped sites through the helper; RH.hpp; tests/min_tests.d/<N>-anchor-farleg-inbound.txt |
| Wiring (flag 1) | After the session exists and `setEmergency` is computed (:5909-5913), if not emergency: `adoptInbound(callID, part)` -> `Ringing`. `answer(callID)` returns `Answer(part)` once -> `asyncAnswerCall`. Every teardown goes through the helper. Pre-session drops (:5799-5906) stay a bare drop of the participant: no slot exists |
| Duplicate guard | `ownsParticipant(part)`, both directions, checked at the top. It does not cover #349's window (origination in flight, id not bound): the transport covers that, because it sets `outboundActive` inside `makeCall` (TAC.cpp:596). A slot-based guard cannot, since the id reaches the engine only after `makeCall` returns |
| Latent finding (reading only) | RH:5814-5822 treats any live inbound session as "a call is already in progress" and drops `participantId`. If the same participant were announced twice, that drops the live call's leg. The transport announces once per slot (TAC.hpp:179), so it is latent. #692's red-first plan already asks flag 0 to settle this; if confirmed, fix it first as its own small change (ignore, do not drop) |
| Behaviour, flag 0 | None |
| Rollback | Flag off, or revert |

### 4.3 Step E (new) and #693

911/933 and PSAP callbacks bypass the adapter in #691 and #692, and #693 deletes the path they use. So they move
first, as step E, with its own vote (section 5). Without it the sequence cannot end.

| | Step E: emergency onto the adapter | #693: delete the old path |
|---|---|---|
| Files | AnchorFarLeg.hpp (emergency field; `sweep` skips it; reclaim a stale slot before refusing); RH `emergency` guards :5086, :5909-5913; golden-trace test; floor file | RH (direct calls, helper, `_anchorLegReleased`); PoolConfig.hpp (flag removed); tests; floor file. TAC and AnchorWedge.hpp only if (c) is overruled |
| Behaviour | Flag 1 only: 911/933 and callbacks use the adapter and must be indistinguishable from legacy (section 5). Flag 0 unchanged | **The default build changes**: it becomes what flag 1 carried after #692 and step E. Nothing new, but the flag-0 path is gone |
| Flag | The same one | Deleted |
| Rollback | Flag off, or revert | Revert only: it removes the flag-0 fallback, so it lands after #692 and step E pass a bench soak |

- (a) The flag and the direct calls: the executor (sync arm and lane posts) sits behind the helper. Rulings needed
  for the exceptions to "engine never calls `makeCall`/`dropCall`/`answerCall` directly": `testDialSlot`
  (RH:9947,9953; session-less probe, deliberately outside `_mutex`), the Loopback sync arm (:5190-5243), and the
  sync arms of `asyncDropCall`/`asyncAnswerCall`/`endCall`/orphan reap (:5430,5580,8843,8901,11002). Proposal: the
  probe stays direct with a comment; the rest move.
- (b) Session bookkeeping: delete `_anchorLegReleased` only. `isAnchor`/`isAnchorInbound` are dialog role (22 of 38
  lines, 2.3) and stay; the participant id stays until the adapter lookup replaces its readers.
- (c) **Recommend dropping as written.** The transport's fields (2.1) are facts about HTTP and WebSocket streams,
  set inside `makeCall` (TAC.cpp:596). An engine-published mirror would arrive after `makeCall` returns, which is
  after the window the classifier needs (#349), so it cannot replace `outboundActive`. It would also have the WS task
  read engine-owned state: the wrong dependency direction. The transport already tells the engine what it knows
  (Answered, Dropped, MediaNeverOpened). So: one record per layer, engine -> transport never. #693's count (23
  lines in TAC.cpp, 2 in AnchorWedge.hpp) still holds, and nothing is deleted there.
- (d) `Held` in the adapter: **recommend dropping** until a reader exists. Session and MediaBridge already record it
  (RH:11460,11468); an unread third copy is speculative. BLF/presence is out of scope (#381).
- Constrained build: with 168,752 B reported free, "net negative" is no longer a byte constraint. Keep "the PR
  states the measured delta" (tools/ci/app_slot_margin.py: fail < 32 KiB, warn < 64 KiB).

## 5. Rule 5: 911, 933 and PSAP callbacks take today's path

"Today's path" means: classified first (RH:2322-2337, before anything configurable, #166, #834); bare number
(RH:4746); `makeCall` posted to the sos lane (RH:5409) before the session is published (:5310, #878), so a refusal
before dispatch can still fall back to the trunk and nothing else may; exempt from the ring reap (:10469), the
degraded-audio sweep (:10769), MediaNeverOpened (:5452) and RTP inactivity (:10919); able to pre-empt (:4638);
NOT ROUTED on an anchor drop (:5524-5543). The adapter holds no reference to `SipTrunk` and never calls
`placeSipTrunkCall`. **The bench cannot prove any of this:** the harness refuses to dial 911 or 933
(tests/load/anchor_scenarios.py:115,329-344). The evidence below is host-side.

| Slice | What could change | Exact check |
|---|---|---|
| Step 0 | The helper alters a drop on a 911 leg | Whole host suite unchanged. Named: AnchorRouting_test.cpp:476,1118,1695; E911Notify :1709; EmergencyRoute :818,840,861,888 |
| #691 | A 911/933 enters the adapter at flag 1 | (1) A counter `farLegSlotsTakenForTest()` (every slot allocation ever, `placeCall` plus `adoptInbound`; not active slots) stays 0 across the emergency suites at flag 1. (2) The pass set of these suites is identical at flag 0 and 1: `EmergencyRoute.*`, `EmergencyCallback.*`, `E911Notify.*`, `TelCtlPool` :256,275,300. (3) Mutation: remove the `emergency` guard and (1) goes red. (4) Flag-0 free bytes from app_slot_margin.py equal before and after |
| #692 | A PSAP callback takes an adapter slot, or a 911 pre-empting a ringing inbound call leaks one | (1) With the callback window open (EmergencyRoute_test.cpp:956 setup) the same counter stays 0 at flag 1 and the forks, ring-all and reap exemption match flag 0. (2) EmergencyRoute_test.cpp:888 passes at both flags, and after the pre-empt the slot count is 0 with exactly one drop |
| Step E | The adapter path differs from the legacy one | A golden-trace test: one fixed 911, 933 and callback scenario, run under `forceAsyncAnchorForTest` at flag 0 and 1, comparing lane, job kind, wire messages, notifications, drop count and tick outcomes. Plus the whole list above, plus: `sweep` skips emergency slots (a new emergency field on the slot), and an emergency `placeCall` reclaims a stale slot before refusing. Own vote |
| #693 | Deleting the legacy path removes an exemption | Step E's golden trace becomes the permanent test; the flag-0 duplicates removed are named in the PR |

## 6. Test plan

**Host (this is what can be proven).**
- `AnchorFarLeg_test.cpp`: the bare class, no engine, no threads, every count from a hook. (A) hangup in Placing then
  `onPlaced(ok)`: one `Drop`, slot Free, no event. (B) bound, hangup before Answered: one `Drop`. (C) Dropped vs
  hangup in both orders: at most one `Drop`. (D) the leak guard frees a stuck slot and does not 408. (E) a 127-character
  Call-ID fits; every slot taken returns false; a second `onPlaced` and a hangup on an unknown id are `None`.
  Red-first against stub bodies, as the issues ask; mutation: Placing -> Free instead of Abandoned turns (A) red.
- Engine tests at flag 1: a second **build directory** with the define (`tests/CMakeLists.txt:44-831` is one ~800-line
  source list, so a second target would duplicate it). Every flag-1 engine test runs under `forceAsyncAnchorForTest`
  and asserts that counter is above 0. This matters: the host default is the synchronous Loopback arm, which
  never reaches the adapter, so **"AnchorRouting_test passes at flag 0 and flag 1" (#691) is vacuous as written.**
- The callback is unwired under `forceAsyncAnchorForTest` (RH.hpp:513-515), so tests call the adapter's completion
  and event entries through test hooks, as `anchorDroppedForTest` (RH.hpp:928) does.
- Drops are counted through `LoopbackAnchorClient::dropCallCount()` (LoopbackAnchorClient.hpp:64), never log lines.
- Per PR: floor file (tests/min_tests.d/README.md), zero new `cert-err33-c` / member-init warnings (in-class
  initialisers), full WSL host suite.

**Bench (needs hardware and a ring; operator-arbitrated; not run for this file).**
- #691: flag-0 and flag-1 images side by side on .244. tests/load/anchor_scenarios.py `x4` (CANCEL about 1 s into
  ringing), `x379` (CANCEL during `makeCall`), `x349`. Each CANCEL gets a 487, exactly one "Successfully dropped
  participant" and one 3CX "Participant Remove", and 3CX lists 0 legs after. `tests/run.py board-smoke` green on both.
- #692: inbound runs for each teardown the bench can trigger (handset BYE, no answer, 3CX Dropped; busy and
  unavailable need phones set to refuse). Same counts. #693: the same on the final image.
- Ordinary numbers only. Never 911 or 933.

## 7. Decision asked

The discriminator is not the trunk (section 3: the payoff does not depend on it). It is whether to accept touching
`originateAnchorCall`, the one path 911 uses, for a structural gain with no open bug behind it, and how much to
commit in advance.

- **A. Keep the sequence, amended.** Step 0, #691, #692, step E, #693, each with its own bench run. Authorizes all
  of it now. Cost: five PRs and a change to the 911 path in step E.
- **B. Approve step 0 and #691 now; re-poll before #692.** The re-poll uses #691's bench result and the measured drop
  of far-leg inference. #692, step E and #693 stay open in milestone 10 with their own votes. Cost: a second vote.
  Resting state if it stops there: with the flag at its default 0, the adapter is bench-only code and production
  stays on the legacy path. Putting ordinary outbound calls on the adapter in production needs a separate vote
  line, **B2: flip the default to 1 after #691's bench run.** B2 changes default-build behaviour for ordinary
  outbound calls; it then leaves one path per call class (ordinary outbound on the adapter, inbound and emergency
  on legacy) and the flag becomes a rollback lever. Without B2 the outcome is two shapes plus a flag.
- **C. Park all three.** Retitle to drop "SipTrunk-shaped", keep them in milestone 10, file step 0 alone as a small
  issue, reopen when a second anchor is registered. Cost: the per-call record never lands, and each new teardown
  path keeps adding a flag site and a branch.

**Recommendation: B.** It is cheap to reverse (flag, no data), the step 0 helper pays off alone, and it does not
close work whose payoff the trunk never carried. It declines to pre-authorize #692 and #693 because their issues
overstate their reward (16 of 38 branches, 2.3; the transport fields stay, 4.3c; `Held` is already recorded, 4.3d)
and because step E is a Rule 5 decision that deserves its own vote. A becomes right if a double-drop or orphaned leg
shows up after step 0 lands; C becomes right if the bench for #691 is not available soon. B2 is not part of this
vote: it is asked after the bench run.

Sub-decisions, with the default I assume: the flag stays compile-time (a runtime toggle would put both paths in one
image, make the flag-0 "unchanged" claim untestable, and put a field-flippable switch on the 911 path; #933 chose
configure-time refusal over a runtime path for the same reason; the 168 KB free reading removes the byte argument,
not this one); the class keeps the name `AnchorFarLeg`; (c) and (d) of #693 are dropped.

## 8. Not verified

- Nothing was built or run: no host build, no tests, no firmware build, no bench. Every claim is from reading
  7bcf952f and the issues as they stood on 2026-10-09.
- 168,752 B free on the constrained build is copied from #938 (3ee4aa6d), not re-measured. "About 1.5 KB" is from #691.
- I found no committee write-up for #691-#693. #942 does not cover them; the design-first block is glomar-51's comments.
- The 16/22 split in 2.3 is my reading of each line, not a tool output. The counts 38, 17, 15 and 8 are greps.
- The latent duplicate-Incoming drop (4.2) is from reading RH:5814-5822; not reproduced.
- "TAC never emits Ringing" is a grep for `CallEvent::Ringing` over src.
- Slot sizes `part[N]` and the leak-guard bound are not measured. `callID[128]` comes from `kMaxCallIdLine`.
- The ESP-only transport (`CallSlot`, the classifier) was not exercised; the argument in 4.3(c) is from TAC.cpp:596
  and :2674-2692.
- Whether #349 and #370 are fully closed is taken from #381's text.
