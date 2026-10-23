# endHandle routing audit (see #1050)

Read-only audit of every `RequestsHandler::endHandle(` call site on `origin/main`
(`de367648`, 2026-10-20), plus the other places that pick a destination for an
in-dialog message from a registered extension number, a source address or a
pooled client instead of stored per-leg state. No source or test change ships
with this document.

**How to read the evidence.** Each claim is marked one of:

- **read** - established by reading the code at the cited line, not run.
- **proven** - a throwaway host test (not committed) asserted the correct
  behaviour and failed on `de367648`. Reproducers are described in section 4;
  the tests ran in a private WSL build (Release, own build tree).
- **inferred** - follows from read code, no run. Not to be quoted as a defect
  without a red test.

The task text said "about 40 sites". There are **25 call sites**; the other
`endHandle(` hits in the file are 14 comments and the definition at 9616. `CallForker.cpp` only mentions it in a
comment (the call was moved off it).

## 1. What endHandle does, and the two facts everything else hangs on

`endHandle(destNumber, msg)` (RequestsHandler.cpp:9616) does `findClient(destNumber)`,
a linear scan of `_clientPool` comparing `getNumber()`. Found: retarget the
Request-URI, strip credentials, mark it a relay (#424 exemption) and queue it to
the pooled client's stored address. Not found: clone the message, make it a 404
and send it to the message's own source.

Two properties matter more than the 404:

1. **The pool slot is the identity.** `Session::_src` / `_dest` are
   `shared_ptr<SipClient>` to the registrar's pool slots (`Session.hpp:479`).
   `unregisterClient()` (RequestsHandler.cpp:9390) calls `SipClient::release()`,
   which clears `_number` and `_contactUri` but **not** the address
   (SipClient.cpp:29). An explicit `REGISTER ... Expires: 0` (onRegister, line
   ~1587) does this with **no `endCall()` for that extension's sessions**
   (`sweepExpired()` and `forceDisconnect()` do end them first; the explicit
   de-REGISTER does not). Every session that held the slot now reports number
   `""`, and the next registrant takes the slot (`allocateClient` hands out the *first free* slot, so
   it takes over only when the released slot is the first free one, as in A2 and A9)
   and silently becomes that call's src or dest. Proven (A2, A9).
2. **`findClient("")` matches a free slot.** `""` equals the number of every
   unused slot, so `endHandle(session->getSrc()->getNumber(), ...)` on a
   released slot is routed to the first free slot's stale address, not a 404.
   (read; the proven cases hit the reused-slot variant instead.)

The #424 no-reply guard turns a 404 minted by `endHandle` for a *response* or an
*ACK* into a silent drop (seen in the logs of A3 and A11). So "falls to the 404
branch" for those messages means "dropped, nobody told", not "caller sees 404".

## 2. The 25 endHandle call sites

Verdict key: OK, SUSPECT (reachable wrong-peer/404 by reading, not proven),
DEFECT (proven by a throwaway test, or unambiguous by reading with a reproducer).
"Dest by" says how the destination is determined: **reg/From** = registry lookup
of the message's From user; **reg/To**; **session-src** = `session->getSrc()->getNumber()`
then registry lookup (pooled-slot identity).

| # | Line | Function | Message / CSeq method | Owner leg | Dest by | After transfer / fork / dereg / dest change | Existing tests | Verdict |
|---|------|----------|----------------------|-----------|---------|---------------------------------------------|----------------|---------|
| 1 | 2007 | onCancel | CANCEL request, CSeq CANCEL | caller's INVITE tx, relayed to the ringing callee | reg/To (the CANCEL's To = the number the caller dialled) | **CFU/CFB/CFNA forward: To is the original callee, the ringing leg is the forward target. CANCEL goes to the wrong peer (proven A1); the target keeps ringing until the ring timer.** Original callee answers 481. Dereg of the dialled callee: 404 to the CANCEL's source. | FinalFailureRelay cancel tests (direct call, no forward); GroupInDialog `RingGroupCancelWhileRinging` (broadcast branch, not this line); none for a forwarded call | **DEFECT** (proven) |
| 2 | 2157 | onReqTerminated | 487, CSeq INVITE | callee's final on caller's INVITE | reg/From | state set to Cancel first; caller gone => #424 drops the 404. Forward leg keeps caller's From. | FinalFailureRelay 487/cancel set (`TheCalleesRequestTerminatedEnds...`) | OK |
| 3 | 2247 | onFinalFailure, hunt exhausted | final (4xx-6xx), CSeq INVITE | hunt member's refusal, caller leg | **session-src** | caller de-registered/slot reused: routed to `""`'s first free slot or to the new registrant (same mechanism as #22) | FinalFailureRelay `AHuntMemberRefusal...` (happy path) | SUSPECT (mechanism proven at #22) |
| 4 | 2255 | onFinalFailure, all ring-all targets refused | same | caller leg | session-src | same | FinalFailureRelay `RingAllFailsTheCallerOnlyWhenTheLastMemberRefuses` (happy path) | SUSPECT |
| 5 | 2268 | onFinalFailure, ordinary relayed call | final, CSeq INVITE | callee's final on caller's INVITE | reg/From, guarded by `findClient(From).has_value()` just above | the 404 branch cannot fire; after CFU the From is still the caller | FinalFailureRelay `CalleeRefusalIsRelayed...`, `ACalleeRefusalThatCrossesTheCallersCancel...` | OK |
| 6 | 2299 | onFinalFailure, final to a relayed re-INVITE | 491/488 etc., CSeq INVITE | the *requesting* leg of a hold/resume | source address picks src or dest, then **re-resolves that client's number** via reg | peer is found by address, then looked up again by number: if the slot was released/reused in between, wrong peer or `""`. Two legs sharing an address pick `dest` always. | FinalFailureRelay `A491ToARelayedReInvite...` | SUSPECT |
| 7 | 2917 | onInvite, DND 480 | 480, CSeq INVITE | caller's new INVITE | reg/From (caller resolved at 2387, same pass) | cannot miss; #497 already refuses an INVITE whose source is not the registered address (log seen in A6), so reg address == source | none found that pins the DND 480 route; A6 (proven OK) | OK |
| 8 | 2931 | onInvite, unknown callee 404 | 404, CSeq INVITE | caller | reg/From | same | none found for this branch (A6 covers the same lookup) | OK |
| 9 | 2948 | onInvite, no SDP 400 | 400, CSeq INVITE | caller | reg/From | same | none direct for this branch | OK |
| 10 | 2960 | onInvite, session pool 503 | 503, CSeq INVITE | caller | reg/From | same | none found for this branch | OK |
| 11 | 3022 | onInvite, the relay | INVITE request | caller's INVITE to callee | reg/To; `called` resolved at 2922 | cannot miss | `FinalFailureRelay.CalleeRefusalIsRelayedToTheCallerAndItsAckReachesTheCallee` | OK |
| 12 | 6641 | onTrying | 100, CSeq INVITE | callee's 100 to caller | reg/From | no blind-transfer-leg (`isBlindXferLeg`) or transfer-bridge claim, unlike onRinging (6771): the PBX-as-UAC leg's 100 is relayed to the *transferee* (From impersonates it) under a Call-ID it never held; attended splice re-INVITE's 100 goes to the dropped transferor. Harmless 100, but it is the exact leak onRinging closes. | none for blind/attended legs (NoReplyToResponse covers beep/park only) | SUSPECT (inferred) |
| 13 | 6810 | onRinging | 180, CSeq INVITE | callee's 180 to caller | reg/From | beep, MoH, trunk, inbound anchor, blind leg, broadcast all intercepted before it | Forward100rel, FinalFailureRelay | OK |
| 14 | 6880 | onBusy, hunt exhausted | 486, CSeq INVITE | caller leg | session-src | as #3 | FinalFailureRelay hunt | SUSPECT |
| 15 | 6891 | onBusy, all targets busy | 486, CSeq INVITE | caller leg | session-src | as #3 | FinalFailureRelay `RingAllFailsTheCallerWhenEveryMember...` | SUSPECT |
| 16 | 6972 | onBusy, ordinary | 486, CSeq INVITE | callee's final | reg/From | CFB handled above via To (#256); dereg of caller: silent | CallForwardBusy | OK |
| 17 | 7034 | onUnavailable, hunt exhausted | 480, CSeq INVITE | caller leg | session-src | as #3 | FinalFailureRelay | SUSPECT |
| 18 | 7045 | onUnavailable, all unavailable | 480, CSeq INVITE | caller leg | session-src | as #3 | FinalFailureRelay | SUSPECT |
| 19 | 7071 | onUnavailable, ordinary | 480, CSeq INVITE | callee's final | reg/From | as #16 | FinalFailureRelay (480 via ring-all); AnchorRouting 480 tests | OK |
| 20 | 7541 | onBye fall-through | BYE request, CSeq BYE | whatever the To names | reg/To | reached when no session exists, or when From matches neither session leg number (any released/reused slot). **A BYE for a Call-ID the PBX does not hold is relayed to the registered To extension instead of 481 (proven A10).** `isDialogSourceAuthorized` waves a no-session BYE through as "harmless". | GroupInDialog BYE tests (session present) | **DEFECT** (proven, low impact) |
| 21 | 7631 | onOk, 2xx while state Cancel | 2xx to INVITE crossing the CANCEL | callee's answer to caller | reg/From | 2xx still relayed so the caller can ACK+BYE; CANCEL 200s absorbed above | FinalFailureRelay `A2xxThatCrossesTheCancel...` | OK |
| 22 | 7768 | onOk, ring-group/page/hunt winner | 200, CSeq INVITE | winning member's answer to caller | **session-src** | caller de-registered, another phone takes the slot: **the new registrant receives the answer (proven A9: "Session Created between 404 and 402", 200 to 404)**. Caller released and slot free: routed by `""` to a free slot. | GroupInDialog, BroadcastHoldResume (live caller) | **DEFECT** (proven) |
| 23 | 7832 | onOk, 200 without SDP | 400 clone of the callee's 200, CSeq INVITE | callee | reg/To (resolved at 7798) | target is right (the callee), outcome is not: the clone carries the caller's Via so the callee should discard it, it is `markRelay`'d so the #424 guard does not stop it, the caller gets **no final response at all** (INVITE timer), and `endCall` follows. Read; not run. | none | SUSPECT (inferred) |
| 24 | 7873 | onOk, ordinary 200 | 200, CSeq INVITE | callee's answer to caller | reg/From for the send; **callee identity is `findClient(To)` with no source check** | any host can answer a ringing call: a 200 from .99 with the ringing Call-ID and `To: 402` is accepted, sets dest=402, connects the session and is relayed to the caller (proven A7). Caller dereg first: session connected with src `""`, the 404 is dropped by #424, callee neither told nor BYE'd (A3, log `Session Created between  and 402`). | `FinalFailureRelay.CalleeRefusalIsRelayedToTheCallerAndItsAckReachesTheCallee` (live phones; nothing covers the hijack) | **DEFECT** (proven) |
| 25 | 7973 | onAck | ACK request, CSeq ACK | caller's ACK to callee | reg/To | after CFU/CFB the 200's To is the target, so it follows; callee de-registered: 404 minted, dropped by #424 (A11 passes), ACK lost, session stays | FinalFailureRelay `...ItsAckReachesTheCallee`, GroupInDialog ACK | OK |

Totals: 4 DEFECT (1, 20, 22, 24), 9 SUSPECT (3, 4, 6, 12, 14, 15, 17, 18, 23), 12 OK. Of
the suspects, six (3, 4, 14, 15, 17, 18) are the same `session-src` mechanism
proven at 22; 6, 12 and 23 are separate.

## 3. Other places that route by number, address or pooled client

| Where | Mechanism | Verdict / evidence |
|-------|-----------|--------------------|
| onBye generic far leg (~7470) | `From == src->getNumber()` / `dest->getNumber()` picks the far leg, then `buildServerBye(farLeg->getNumber(), farLeg->getAddress())` | **DEFECT, proven A2**: 401<->402 connected, 401 de-REGISTERs, 403 registers into the freed slot, 402 hangs up: the server BYE goes to 403's address. |
| `sweepExpired`, `forceDisconnect` involvement scans (9468, 9690) | session involvement by `getNumber()`; `release()` must run last (forceDisconnect's comment says so) | OK for those paths; but the explicit de-REGISTER skips them (section 1). |
| CFNA/no-answer reap (11183-11257) | `calleeExt = fwdInvite ? getForwardLegTarget() : invite->getToNumber()`, `findClient(calleeExt)` | **DEFECT, proven A5**: stale `_forwardInvite/_forwardTarget` from an earlier forwarded call on the same pooled Session (section 6). |
| onReinvite (12242), onUpdate (12453), onOk re-INVITE/UPDATE 200 (7673) | sender identified by `sameAddress(source, src/dest address)`, peer is the other | OK (read). Both legs on one address => peer always `dest`. Unknown source ignored silently. |
| onBye transfer bridge (7357) | `mine = wasTransferorSrc ? dest : src`, `sameAddress(source, mine)` | read: OK; see section 5. |
| `isBroadcastCallerRequest` (86; used by onCancel 1937, onBye 7285, onAck 7938) | `From == src->getNumber()` | SUSPECT: same pooled-slot identity as 22 (read). |
| onOk broadcast winner (7720) | `findClientByAddress(source)` | two registrations on one ip:port => first match wins (read). |
| onOk ordinary (7798) | `findClient(To)` | DEFECT (row 24). |
| `buildServerBye` (12961) | request URI from `findClient(destExt)` if address matches, else address form | OK. |
| sweepSessionTimers (12690), forceDisconnect (9772, 9789) | BYE to `src` with `(dialogTo, dialogFrom)` and to `dest` with `(dialogFrom, dialogTo)`, assuming src is the UAC and dest is in the *same* dialog | **DEFECT, proven A8** for a park retrieve: see section 5.2. |
| onRefer (8009) | transferor = `findClient(From)` | covered by ReferSourceAuth_test; not re-audited. |

## 4. Reproducers (each proven unless stated)

All use `RequestsHandler::handle()` end to end, registrations from 192.168.50.20-.24.
Throwaway tests were not committed.

- **A1 CANCEL after CFU (site 1).** Register 401, 402, 403. `setForward("402","always","403")`.
  401 INVITE to 402 (INVITE is forked to 403). 401 CANCEL (To 402). Expected a
  CANCEL to 403; actual a CANCEL to 402 (the original callee), none to 403.
- **A2 BYE to a stranger (onBye generic).** 401 calls 402, 402 answers, 401 ACKs.
  401 `REGISTER Expires: 0`. 403 registers (takes the freed slot). 402 sends BYE.
  Expected no BYE to 403; actual a `BYE sip:403@...` to 403's address.
- **A9 Ring-group answer to a stranger (site 22).** `setRingGroup("600","402,403","ringall")`.
  401 INVITE to 600. 401 de-REGISTERs. 404 registers (takes the slot). 402 answers
  200. Log: `Session Created between 404 and 402`; the 200 is delivered to 404.
- **A3 Caller de-registers while ringing (site 24).** 401 calls 402; 401
  de-REGISTERs; 402 answers 200. Log `Session Created between  and 402`; the
  callee's 200 is turned into a 404 that the #424 guard drops (`refused a reply to a
  response`). Nobody BYEs 402; the session stays Connected with an empty src. The
  assertion I wrote (no 404 to the callee) *passed*, so this is **observed
  behaviour, not a failed assertion**.
- **A7 Answer from a third address (site 24).** 401 calls 402 (.21). A `200 OK`
  from .99 with the same Call-ID, `To: <sip:402@server>;tag=...` and an SDP.
  Expected ignored; actual connected and relayed to 401.
- **A10 BYE for an unknown dialog (site 20).** 401, 402 registered. BYE from .99,
  From 401 To 402, Call-ID `nosuch-1`. Expected 481; actual `BYE sip:402@...` sent to 402.
- **A5 Stale forward leg after Session recycling (section 6).** CFU 402->403. 401
  calls 402; 403 answers; 401 BYEs; 403 200s the BYE (slot released). 401 then
  calls 404 (registered, no forward). Arm the ring timer in the past, `tick()`.
  Expected CANCEL to 404; actual CANCEL to 403 (`no answer after ring time, no
  forward -- 403`) and none to 404, which keeps ringing.
- **A8 Admin kills a park retriever (section 5.2).** 401 INVITE 700 (park), 403
  INVITE 700 (retrieve), `forceDisconnect("403")`, `tick()`. Expected a BYE to 401
  carrying the park Call-ID (`pk1`); actual a BYE to 401 carrying the retriever's
  Call-ID (`pk2`), a dialog 401 never saw. The test asserted only the BYE Call-ID. That the park session `pk1` is not ended is **read**, not run.
- **A4 Session::reset leaks (section 6).** Unit level: `setForwardLeg`,
  `setCancelledLegExt`, `markDegradedReported()`, then `reset()`. After reset
  `getForwardLegTarget()` is still `"403"`, `getCancelledLegExt()` still `"403"`,
  and `markDegradedReported()` returns `false` instead of `true`.
- **A6 (cleared).** INVITE From 401 sent from .99 to an unknown number: refused
  403 to the sender (#497), not a 404 to the real 401. Sites 7-10 stand.
- **A11 (cleared).** Callee de-registers, caller ACKs: the 404 is dropped by #424.
  Site 25 stands.

### Reproducers for the SUSPECT rows (none run)

- **Rows 3, 14, 17 (hunt exhausted).** Register 401, 402. `setRingGroup("600","402","hunt")`.
  401 INVITE 600. 401 `REGISTER Expires: 0`. 404 registers (takes the freed slot).
  402 refuses (603 at 2247, 486 at 6880, 480 at 7034). Expected: nothing
  delivered to 404. Predicted: the final goes to 404 (`endHandle(src number)`).
- **Rows 4, 15, 18 (ring-all, everyone refused).** Same, members `402,403`
  `ringall`, both refuse with 603 / 486 / 480. Predicted: the last refusal goes to 404.
- **Row 6.** 401 and 402 connected. 401 sends a hold re-INVITE (relayed to 402).
  401 de-REGISTERs; 403 takes the slot. 402 answers 491 from .21. The source matches
  `dest`, so the peer is `src` (now 403) and `endHandle("403")` delivers the 491 to 403.
- **Row 12.** 401 and 402 connected; 401 blind-REFERs to 403. 403 answers the
  PBX's INVITE with `100 Trying` (CSeq INVITE, the leg's Call-ID). onTrying has no
  blind-leg claim, so it is relayed `endHandle(From)` to the transferee 402.
- **Row 23.** 401 calls 402; 402's 200 OK carries no SDP. Predicted: 401 gets
  nothing, 402 receives a 400 it discards, the session is ended.
- **Fork-loser 200 (section 7).** Ring-all 600 = 402,403. 402 answers 200; before
  the CANCEL lands, 403's 200 arrives. Predicted: no ACK and no BYE to 403.

## 5. Following one BYE through four paths (addendum 1)

BYE builder: `buildServerBye(destExt, destAddr, callId, from, to, cseq)`. The
destination *number* and *address* come from a pooled `SipClient`; From/To are
whatever dialog headers the caller of the builder picks. Session stores one pair,
`_dialogFrom` / `_dialogTo`, and **their meaning is set by whoever wrote them**.

### 5.1 Pickup (CallPickup::complete)

Two sessions, two Call-IDs, linked by `peerCallID`. Ringing session X: src=original
caller A (UAC), dest=picker P; `dialogFrom = invite From`, `dialogTo = A's To +
PBX tag`. Picker session Y: src=P, dest=A; `dialogFrom = P's From`, `dialogTo =
P's To + PBX tag`. Both orientation "src is the UAC, dialogFrom is src's side".

- BYE from A (on X): onBye `peerCallID` branch (7436): `notify = Y.getSrc()` = P,
  `buildServerBye(P number, P address, Y id, Y.dialogTo, Y.dialogFrom)`. Right
  party, right dialog. (read)
- BYE from P (on Y): `notify = X.getSrc()` = A, X's headers. Right. (read)
- Identity used: pooled `src` slot for both number and address. Wrong party only
  through the slot aliasing of section 1 (inferred; same mechanism as A2).
- Not safe: session-timer/forceDisconnect treat `dest` as in the *same* dialog.
  X.dest = P, so a timer or kill BYE to P carries X's Call-ID, which P never held
  (481). Pickup does not arm session timers, so only forceDisconnect reaches
  it; it also visits Y, so each phone still gets one correct BYE plus one stray.
  (read)

### 5.2 Park ring-back and retrieve (ParkOrbit.cpp)

`rb->setDialogHeaders(data->getTo(), data->getFrom())` (ParkOrbit.cpp:363) stores
the ring-back session's headers **reversed on purpose**: the PBX is the UAC of
that dialog, so `dialogFrom` holds the parker's To (its tag) and `dialogTo` holds
the PBX's From (PBX tag), and the shared `(dialogTo, dialogFrom) -> (From, To)`
order of onBye yields a correct BYE. The field names are not role-neutral; `Session`
carries `isParkUac()` only so *some* readers can invert, and several do not.

- Parked party hangs up: `rb.getSrc()` = the parker, BYE `(rb.dialogTo,
  rb.dialogFrom)` = From PBX, To parker. Correct. Parker hangs up (BYE on
  rbCallID): `notify = parked.getSrc()`, parked's headers (`From=PBX+tag`,
  `To=parked party`). Correct. (read; ParkOrbit_test `RingbackAnswerCaptures...` pins the swap)
- **Wrong dialog (proven A8).** `allocVirtualPeer(slot.parkedExt, slot.parkedAddr)`
  gives the stand-in the parked party's **real number and address**, so
  `destIsVirtual` in forceDisconnect/sweepSessionTimers (which tests dest
  *number* against 777/440/888/555) does not exclude it. A kill of the retriever
  BYEs the parked phone on the retrieve session's Call-ID (it holds only the
  park Call-ID), and the park session itself is not "involved" (its src is the
  parked party, not 403), so it is never ended. The ring-back session's
  dest BYE additionally carries From=parker, To=PBX, inverted (read, not run). The session
  timer sweep cannot reach park-spliced sessions (grant=false), so only the admin
  path is exposed.

### 5.3 Attended and blind transfer

`src`/`dest` keep the original participants: they do not name who survives.
`_isTransferBridge`, `_wasTransferorSrc` (default `true`), `_blindXferLeg`
and `_transferorCseqAtRefer` say how to read them.

- Surviving party is `wasTransferorSrc() ? dest : src` at 7355, 7373, 8479, 8865,
  9015, 13045 (six sites). Header orientation flips with the same flag at
  7401-7403, 8283-8286, 8891-8893, 9018-9020.
- onBye on a bridge half (7347-7420): `mine = wasTransferorSrc ? dest : src`
  must equal the BYE's source address, else the BYE is from the dropped
  transferor and is answered and ignored. Then BYE to `survivor` of the **peer**
  using the peer's `wasTransferorSrc` and `(peerAHdr, peerOtherHdr)`. Address
  used: `survivor->getAddress()` of a pooled slot. Correct while the flag is
  right and the slot is not released. (read)
- `_wasTransferorSrc` is not cleared by `reset()` or `release()` (default `true`,
  set at 8363, 8366, 8673, 8947). Every reader is gated on `isTransferBridge()` /
  a peer link, so a stale value is only read after being rewritten. (read: no
  reachable stale read found.)
- Blind leg (`isBlindXferLeg`): the PBX is UAC; its own 100 Trying is not
  claimed in onTrying (row 12).

### 5.4 Anchor teardown

Identity fields: `_anchorParticipantId` (upstream leg), `_anchorLegReleased`
(far leg already dropped; read by endCall so a dropped leg is not dropped twice),
`_anchorInbound` (direction).

- Outbound (handset is src, PBX is UAS): BYE to `getSrc()` with
  `(From=<dialed>@PBX;tag=local, To=invite From)` (anchorDroppedLocked ~5874) or
  `(dialogTo, dialogFrom)`. endAnchorCallForPreempt: `handset = src`, `(dTo, dFrom)`.
- Inbound (handset is dest, PBX is UAC): `handset = getDest()`, `(dFrom, dTo)`
  (opposite order, endAnchorCallForPreempt) or hand-built from `getRemoteTag()`
  and `getLocalTag()` (anchorDroppedLocked ~5819). `endCall`'s src/dest
  arguments are swapped by direction (`inbound ? farLeg : phone`).
- `_anchorParticipantId` is copied before `endCall` because `release()` clears it
  (endAnchorCallForPreempt comment). Address used: pooled handset slot. Can a BYE
  reach the wrong party? Only through slot aliasing (a de-registered/reused
  handset); direction is correctly flagged. (read)

Summary: no path was found that addresses the wrong party in steady state. Every
path is exposed to the pooled-slot aliasing of section 1, and the session-timer /
force-disconnect pair is wrong for any session whose `dest` is a cross-dialog or
virtual stand-in that carries a real extension number (park). Orientation is
re-derived by hand at ~12 `buildServerBye` sites.

## 6. Session reuse and release (addenda 2-4)

**Recycling is real.** `allocateSession` (RequestsHandler.cpp:11873) reuses the
first pool slot whose Call-ID is empty or absent from `_sessions`, and calls
`Session::reset(callID, src)`. `endCall` ends a call with `release()`.

**Fields `reset()` does not touch** (compared against the member list): `_forwardInvite`,
`_forwardTarget`, `_cancelledLegExt`, `_degradedReported`, `_ringDeadline`,
`_rtpMarkA/B/At`, `_wasTransferorSrc`, `_transferorCseqAtRefer`. Plus `_startTime`
(rewritten), `_disposition` (reset clears it).

- **`_forwardInvite` / `_forwardTarget`** (set by `CallForker::redirectInvite`,
  CallForker.cpp:196, i.e. every CFU/CFB/CFNA forward that creates a session).
  Read in the ring-expiry reap (RequestsHandler.cpp:11183-11190): `fwdInvite = ...;
  calleeExt = fwdInvite ? getForwardLegTarget() : invite->getToNumber()`. A later
  plain call recycled into that slot sees a non-null stale `fwdInvite`, so the
  reap CANCELs the *old* forward target and logs/ends the call with the old
  extension, while the real callee is never CANCELled. **Proven (A5).** The slot
  also pins the old SipMessage pool entry until overwritten.
- **`_cancelledLegExt`** is cleared only at RequestsHandler.cpp:2093. If the
  cancelled callee's 487 never arrives (lost, or the call ends first) the value
  persists into the next call on the slot, and `onReqTerminated` (2085-2095) then
  ACKs and swallows a genuine 487 from that extension instead of relaying it.
  The field is proven stale by A4 (unit); the end-to-end 487 swallow is inferred.
- **`_degradedReported`** (#906, Rule 5 relevant): `markDegradedReported()`
  returns false once set, and nothing resets it. A4 **proves** only that the flag survives `reset()`. That a later degraded
  911/933 on a recycled slot is then never reported follows from reading
  RequestsHandler.cpp:11341 (`!markDegradedReported()` => `continue`); it was not
  run end to end. It is the most serious stale field (Rule 5: a degraded
  emergency call goes unreported).
- `_wasTransferorSrc`, `_transferorCseqAtRefer`: always written before read
  (section 5.3); `_rtpMark*`: guarded by `_rtpWatchArmed`, which reset clears.

**What `release()` leaves live** (the member list minus its body): `_disposition`,
`_startTime`, `_isVoicemail`, `_isToneCall`, `_voicemailLegSlot`, `_voicemailPurpose`,
`_voicemailDeadline(Armed)`, `_isTrunk`, `_trunkRelaySlot`, `_isEmergency`,
`_emergencyNumber`, `_echoDialog`, `_prack*`, `_fwd*`, `_rtpWatchArmed`, `_rtpMark*`,
`_degradedReported`, `_forwardInvite/_forwardTarget`, `_ringDeadline`,
`_cancelledLegExt`, `_wasTransferorSrc`, `_transferorCseqAtRefer`. The
documented reason is only voicemail and trunk (endCall reads
`ending->isVoicemail()`, `getVoicemailLegSlot()`, `isTrunk()`, `getTrunkRelaySlot()`
after `release()`). The rest survive by omission. Readers after release: endCall
(above); nothing else was found, but the aliasing hazard is real in the other
direction: callers that hold a `shared_ptr<Session>` across `endCall` see the
*released* object (the CFNA reap copies `ringTag` first for that reason).

**`setState(Connected)` before the `_dest` check.** `_state` is assigned, then
the dest check only logs (Session.cpp). Every `setState(Connected)` caller was
checked (RequestsHandler 589, 2683, 3264, 3493, 3602, 3935, 4149, 5583, 6590,
7747, 7862, 8809, 8939, 12301, 12501, 13963, 14371; CallPickup 124, 133;
ParkOrbit 132, 189, 364): all set a dest first, or are Held->Connected (which
returns before the check), or restore an existing Connected session. No
caller reaches it with a null dest (13963 and 14371 traced too: the trunk-inbound path sets the handset at 13868, the outbound trunk path sets `dummyTrunk` at 14166). `_src->getNumber()` in the same log line is
unguarded, which only matters if a future caller passes a null src.

## 7. Fork matching (CallForker)

- `buildInviteFork` copies the caller's INVITE (`getMessageFromPool(*invite)`) and
  rewrites Request-URI, To, Contact and codec list. **It does not mint a fresh Via
  branch**: the PBX adds no Via of its own, so every fork leg carries the caller's
  branch, Call-ID, CSeq and From. The only per-leg discriminators on the wire
  are the To URI and the source address.
- Response matching is therefore mixed: provisionals on a broadcast session are
  dropped (onRinging, onTrying); 486/480 and finals use `removePendingTarget(
  ToNumber)` (#803, FinalFailureRelay covers it); the first 200 uses
  `findClientByAddress(source)` while the session is Invited. Winner/loser: the
  winner becomes `dest`; every other pending target gets a CANCEL built per
  target (To rewritten); the losers' 487 is ACKed in onReqTerminated because the
  session is broadcast; a CFNA-cancelled leg is recognised by
  `setCancelledLegExt(number)` plus `ToNumber ==` (2085).
- Gap (inferred, not run): a loser whose 200 crosses the winner's. After the
  session is Connected the loser's 200 matches neither leg address, so
  `peer` stays null and the broadcast branch returns because state != Invited
  (7650-7710). It gets **neither an ACK nor a BYE**; it believes it is in a call
  and retransmits the 200 until its timer. Needs a red test with two members
  answering back to back.
- Two members behind one ip:port: `findClientByAddress` picks the first.

## 8. Required closing items

**(a) Count by verdict (25 endHandle sites):** DEFECT 4 (rows 1, 20, 22, 24),
SUSPECT 9 (3, 4, 6, 12, 14, 15, 17, 18, 23), OK 12. Outside the table: DEFECT, proven
at the onBye generic far leg (A2), the CFNA reap (A5), the session-timer and
force-disconnect BYE for park (A8), and Session::reset (A4); inferred: fork-loser 200.

**(b) Would a leg-identity refactor remove repeated inference or only move code?**
Both, split by pattern. Repeated inferences seen:

1. *Sender by source address* ("peer = sameAddress(source, src) ? dest : ..."):
   onReinvite, onUpdate, onOk re-INVITE 200, onFinalFailure 2295, onBye bridge,
   `isDialogSourceAuthorized`. Six copies.
2. *Sender by From number* (`From == src->getNumber()`): onBye far leg,
   `isBroadcastCallerRequest` x3, the involvement scans in `sweepExpired` /
   `forceDisconnect`. Six-plus copies.
3. *Orientation by header* (`endHandle(From)` for "to the caller",
   `endHandle(To)` for "to the callee"): 18 of 25 sites.
4. *Re-look-up of a client already in hand* (`endHandle(src->getNumber())`,
   `endHandle(peer->getNumber())`): rows 3, 4, 6, 14, 15, 17, 18, 22.
5. *Surviving party by flag* (`wasTransferorSrc ? dest : src`): six sites.
6. *Dialog-header orientation by hand* (swap or not at each `buildServerBye`):
   about 12 sites; park, anchor in/out, pickup and transfer each differ.

A leg object that carries `{number snapshot, address snapshot, own Call-ID, own
tags, own From/To as sent, role}` removes 1-4 and fixes the aliasing outright
(a released slot cannot rename a call). It only moves 5 and 6 unless the leg also
stores its own dialog headers in as-sent orientation so the BYE builder takes a
leg and nothing else; if headers stay on Session, those two patterns just migrate.

**(c) Ranked suspects to turn into red tests.** Milestones: v1.7.0 is teardown / wrong
leg; v1.8.0 is memory pressure.

1. *(v1.7.0, Rule 5 applies)* A de-registered caller's call must never be routed to
   another phone, and a live 911/933 must stay up (`sweepExpired` exempts
   emergencies on purpose, #712). Two fix shapes: end the extension's calls
   through `endCall()` with the same emergency exemption, or do not free or
   rename a pool slot that a session still holds. Reds: A2, A9, A3.
2. *(v1.7.0, Rule 5)* `Session::reset` must clear `_degradedReported`, so a
   later degraded 911/933 on a recycled slot is reported again (A4 unit red; add
   the end-to-end through the `degradedEmergencyCallIds` loop).
3. *(v1.7.0 and v1.8.0)* `Session::reset` clears `_forwardInvite`, `_forwardTarget`,
   `_cancelledLegExt` (A4); end-to-end A5. v1.8.0 because a stale `_forwardInvite`
   pins a SipMessage pool entry on every recycled slot.
4. *(v1.7.0)* CANCEL after CFU/CFB/CFNA reaches the forward target (A1).
5. *(v1.7.0)* forceDisconnect of a park retriever BYEs the parked phone on its own
   Call-ID and ends the park session (A8, second half read only).
6. *(v1.7.0)* An INVITE 200 only counts from the callee's leg (A7).
7. *(v1.7.0)* A BYE with no session is answered 481, not relayed (A10).
8. *(v1.7.0)* A fork loser whose 200 crosses the winner's gets ACK+BYE (section 7).
9. *(v1.7.0)* Hunt/ring-all exhausted and all-refused answer the caller after the
   caller's slot changed (rows 3, 4, 14-18); row 6 likewise.
10. *(v1.7.0)* 200 without SDP: the caller gets a final (row 23). 100 Trying on a
    blind/attended leg is not relayed (row 12).

**(d) Relation to the Call-ID-keyed session map.** `_sessions` maps one Call-ID to
one `Session`, and a `Session` is one call with two *numbers*, not two legs.
That is the forcing function: (1) fork legs (and CFU/CFNA legs) share the
caller's Call-ID, branch, CSeq and From, so a response can only be tied to a leg by
the To number or the source address; (2) spliced dialogs have *different* Call-IDs
with `src/dest` crossing between them, so `peerCallID` plus a per-role flag has
to say which side is which; (3) `src`/`dest` are pointers into the registrar
pool, not snapshots, so identity follows the slot, not the call; (4) there is one
`_dialogFrom/_dialogTo` pair whose orientation depends on `isParkUac`,
`wasTransferorSrc`, `isAnchorInbound` and the writer's convention; (5) there is
no per-leg state (tag, branch, address, CSeq), so "who sent this" is rebuilt per
handler from number or address. Keying by Call-ID is correct for the transaction
layer; the missing piece is a leg beneath it.
