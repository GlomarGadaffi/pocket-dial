# endHandle routing audit (see #1050)

Audit of every `RequestsHandler::endHandle(` call site, written against `origin/main`
`de367648` (2026-10-20) and **re-verified on main `fe447968` on 2026-10-24**. It also covers the other places that pick a destination for an
in-dialog message from a registered extension number, a source address or a
pooled client instead of stored per-leg state. No source or test change ships
with this document. Every line reference below is a line on `fe447968`; the
verdicts and the "proven" claims are the ones made against `de367648`, and each
finding carries a **Status on main** that says what the 2026-10-24 re-check found.

**Status values.** FIXED by #N (merged, code cited) - OPEN as #N (filed, not fixed; reproducer re-run on main and red) -
OK now (the cause is gone, reproducer re-run and green) - STILL SUSPECT (not reproduced).

**How to read the evidence.** Each claim is marked one of:

- **read** - established by reading the code at the cited line, not run.
- **proven** - a throwaway host test (not committed) asserted the correct
  behaviour and failed on `de367648`. Reproducers are described in section 4;
  the tests ran in a private WSL build (Release, own build tree). On 2026-10-24
  the same reproducers were rebuilt as host tests on `fe447968` (Release, a fresh
  build tree, `Audit1077.*`, 15 tests: 7 green, 8 red) and each result is
  recorded where the reproducer is described. A "red on main" is a test that
  asserted the correct behaviour and failed on `fe447968`.
- **inferred** - follows from read code, no run. Not to be quoted as a defect
  without a red test.

The task text said "about 40 sites". There are **25 call sites**; the other
`endHandle(` hits in the file are comments and the definition at 9887. `CallForker.cpp` only mentions it in a
comment (the call was moved off it).

## 1. What endHandle does, and the two facts everything else hangs on

`endHandle(destNumber, msg)` (RequestsHandler.cpp:9887) does `findClient(destNumber)`,
a linear scan of `_clientPool` comparing `getNumber()`. Found: retarget the
Request-URI, strip credentials, mark it a relay (#424 exemption) and queue it to
the pooled client's stored address. Not found: clone the message, make it a 404
and send it to the message's own source.

Two properties matter more than the 404:

1. **The pool slot is the identity.** `Session::_src` / `_dest` are
   `shared_ptr<SipClient>` to the registrar's pool slots (`Session.hpp:479-480`).
   `SipClient::release()` clears `_number` and `_contactUri` but **not** the address
   (SipClient.cpp:29-33). On `de367648` an explicit `REGISTER ... Expires: 0`
   (onRegister, RequestsHandler.cpp:1590-1593 into `unregisterClient()`) released the
   slot with **no `endCall()` for that extension's sessions**, so every session that
   held the slot reported number `""` and the next registrant (`allocateClient` hands out
   the *first free* slot) silently became that call's src or dest (A2, A9).
   **FIXED by #1094** (b84b8327): `unregisterClient()` (RequestsHandler.cpp:9505-9532) now
   runs `endClientCalls()` (9627-9763, which finishes every matched session through
   `endCall()`) before `release()` (9528), as `sweepExpired()` (9825-9828) and
   `forceDisconnect()` (10088) already did. A live 911/933 or PSAP callback is the
   exemption: the de-register only lapses the lease (`expireLease()`, 9517-9524) and keeps
   the binding, so no emergency session ever sits on a renamed slot. The three
   `release()` sites are the only ones; each ends the sessions first. The
   pointer-into-the-pool design is unchanged; only the path that released a slot under a
   live session is gone. Re-run on main: A2, A9, A3 and the six session-src SUSPECT rows are green, and each
   asserts the positive evidence (the session is gone right after the de-register,
   and the survivors got their CANCEL/BYE).
2. **`findClient("")` matches a free slot.** `""` equals the number of every
   unused slot, so `endHandle(session->getSrc()->getNumber(), ...)` on a
   released slot would be routed to the first free slot's stale address, not a 404.
   (read.) Still true of `findClient`; since #1094 it is reachable only if some future path
   releases a slot under a live session. `endClientCalls()` guards its own side
   (`if (extension.empty()) return;`, 9637).

The #424 no-reply guard turns a 404 minted by `endHandle` for a *response* or an
*ACK* into a silent drop (seen in the logs of A3 and A11 on `de367648`). So "falls to the 404
branch" for those messages means "dropped, nobody told", not "caller sees 404".

## 2. The 25 endHandle call sites

Verdict key (as of `de367648`): OK, SUSPECT (reachable wrong-peer/404 by reading, not proven),
DEFECT (proven by a throwaway test, or unambiguous by reading with a reproducer). The last
column is the **Status on main `fe447968`**. "Dest by" says how the destination is determined: **reg/From** = registry lookup
of the message's From user; **reg/To**; **session-src** = `session->getSrc()->getNumber()`
then registry lookup (pooled-slot identity).

| # | Line | Function | Message / CSeq method | Owner leg | Dest by | After transfer / fork / dereg / dest change | Existing tests | Verdict (de367648) | Status on main fe447968 |
|---|------|----------|----------------------|-----------|---------|---------------------------------------------|----------------|---------|------|
| 1 | 2016 | onCancel | CANCEL request, CSeq CANCEL | caller's INVITE tx, relayed to the ringing callee | reg/To on `forwarded ? getForwardLegTarget() : To` | On `de367648` the destination was the CANCEL's To = the number the caller dialled, so after a CFU/CFB/CFNA forward the CANCEL went to the original callee (answered 481) and the forward target kept ringing until the ring timer (proven A1). Now `forwarded` selects the forward target (2016). Dereg of the dialled callee: 404 to the CANCEL's source. | `CancelAfterForward_test.cpp` (forwarded and unforwarded); FinalFailureRelay cancel tests; GroupInDialog `RingGroupCancelWhileRinging` (broadcast branch, not this line) | **DEFECT** (proven) | **FIXED by #1082** (1326d231, `RequestsHandler.cpp:2013-2016`). Residual: a stale `_forwardInvite` on a recycled Session would misroute this CANCEL (first item of #1121; section 6). |
| 2 | 2166 | onReqTerminated | 487, CSeq INVITE | callee's final on caller's INVITE | reg/From | state set to Cancel first; caller gone => #424 drops the 404. Forward leg keeps caller's From. | FinalFailureRelay 487/cancel set (`TheCalleesRequestTerminatedEnds...`) | OK | OK (line re-pointed, not re-run) |
| 3 | 2256 | onFinalFailure, hunt exhausted | final (4xx-6xx), CSeq INVITE | hunt member's refusal, caller leg | **session-src** | caller de-registered/slot reused: was routed to `""`'s first free slot or to the new registrant (same mechanism as 22) | FinalFailureRelay `AHuntMemberRefusal...` (happy path) | SUSPECT (mechanism proven at 22) | **OK now.** `R3_14_17` run on main (603/486/480): the de-register ends the hunt session and 0 messages reach the new registrant. Cause removed by #1094; the `endHandle(src->getNumber())` lookup itself is unchanged. |
| 4 | 2264 | onFinalFailure, all ring-all targets refused | same | caller leg | session-src | same | FinalFailureRelay `RingAllFailsTheCallerOnlyWhenTheLastMemberRefuses` (happy path) | SUSPECT | **OK now.** `R4_15_18` run on main: session gone after the de-register, both refusals produce 0 messages to the new registrant. |
| 5 | 2277 | onFinalFailure, ordinary relayed call | final, CSeq INVITE | callee's final on caller's INVITE | reg/From, guarded by `findClient(From).has_value()` just above | the 404 branch cannot fire; after CFU the From is still the caller | FinalFailureRelay `CalleeRefusalIsRelayed...`, `ACalleeRefusalThatCrossesTheCallersCancel...` | OK | OK (line re-pointed, not re-run) |
| 6 | 2308 | onFinalFailure, final to a relayed re-INVITE | 491/488 etc., CSeq INVITE | the *requesting* leg of a hold/resume | source address picks src or dest, then **re-resolves that client's number** via reg | peer is found by address, then looked up again by number: if the slot was released/reused in between, wrong peer or `""`. Two legs sharing an address pick `dest` always (read, still true). | FinalFailureRelay `A491ToARelayedReInvite...` | SUSPECT | **OK now** for slot reuse: `R6` run on main (hold re-INVITE relayed, requester de-registers, 403 takes the slot, 402 answers 491): session gone after the de-register, 0 messages to 403. **STILL SUSPECT** for the shared-address case (read, not reproduced). |
| 7 | 2934 | onInvite, DND 480 | 480, CSeq INVITE | caller's new INVITE | reg/From (caller resolved earlier in the same pass) | cannot miss; #497 already refuses an INVITE whose source is not the registered address (log seen in A6), so reg address == source | none found that pins the DND 480 route; A6 (proven OK) | OK | OK (line re-pointed, not re-run) |
| 8 | 2948 | onInvite, unknown callee 404 | 404, CSeq INVITE | caller | reg/From | same | none found for this branch (A6 covers the same lookup) | OK | OK (line re-pointed, not re-run) |
| 9 | 2965 | onInvite, no SDP 400 | 400, CSeq INVITE | caller | reg/From | same | none direct for this branch | OK | OK (line re-pointed, not re-run) |
| 10 | 2977 | onInvite, session pool 503 | 503, CSeq INVITE | caller | reg/From | same | none found for this branch | OK | OK (line re-pointed, not re-run) |
| 11 | 3039 | onInvite, the relay | INVITE request | caller's INVITE to callee | reg/To; `called` resolved in the same pass | cannot miss | `FinalFailureRelay.CalleeRefusalIsRelayedToTheCallerAndItsAckReachesTheCallee` | OK | OK (line re-pointed, not re-run) |
| 12 | 6739 | onTrying | 100, CSeq INVITE | callee's 100 to caller | reg/From | no blind-transfer-leg (`isBlindXferLeg`) or transfer-bridge claim, unlike onRinging (6813; blind-leg claim at 6869): the PBX-as-UAC leg's 100 is relayed to the *transferee* (From impersonates it) under a Call-ID it never held; attended splice re-INVITE's 100 goes to the dropped transferor. Harmless 100, but it is the exact leak onRinging closes. | none for blind/attended legs (NoReplyToResponse covers beep/park only) | SUSPECT (inferred) | **OPEN as #1124. `R12` run on main: after a blind REFER 401 -> 402 => 403, 403's `100 Trying` on the PBX's INVITE leg is sent to 402 (1 message, expected 0). Attended-splice half not run. Rule 5: none; the fix must leave the emergency paths alone. |
| 13 | 6908 | onRinging | 180, CSeq INVITE | callee's 180 to caller | reg/From | beep, MoH, trunk, inbound anchor, blind leg, broadcast all intercepted before it | Forward100rel, FinalFailureRelay | OK | OK (line re-pointed, not re-run) |
| 14 | 6978 | onBusy, hunt exhausted | 486, CSeq INVITE | caller leg | session-src | as 3 | FinalFailureRelay hunt | SUSPECT | **OK now** (as 3; `R3_14_17`, 486). |
| 15 | 6989 | onBusy, all targets busy | 486, CSeq INVITE | caller leg | session-src | as 3 | FinalFailureRelay `RingAllFailsTheCallerWhenEveryMember...` | SUSPECT | **OK now** (as 4; `R4_15_18`, 486). |
| 16 | 7070 | onBusy, ordinary | 486, CSeq INVITE | callee's final | reg/From | CFB handled above via To (#256); dereg of caller: silent | CallForwardBusy | OK | OK (line re-pointed, not re-run) |
| 17 | 7132 | onUnavailable, hunt exhausted | 480, CSeq INVITE | caller leg | session-src | as 3 | FinalFailureRelay | SUSPECT | **OK now** (as 3; `R3_14_17`, 480). |
| 18 | 7143 | onUnavailable, all unavailable | 480, CSeq INVITE | caller leg | session-src | as 3 | FinalFailureRelay | SUSPECT | **OK now** (as 4; `R4_15_18`, 480). |
| 19 | 7169 | onUnavailable, ordinary | 480, CSeq INVITE | callee's final | reg/From | as 16 | FinalFailureRelay (480 via ring-all); AnchorRouting 480 tests | OK | OK (line re-pointed, not re-run) |
| 20 | 7656 | onBye fall-through | BYE request, CSeq BYE | whatever the To names | reg/To | On `de367648` it was reached when no session exists, or when From matches neither session leg number, and relayed a BYE for a Call-ID the PBX does not hold to the registered To extension instead of 481 (proven A10). Now a BYE with no session, a registered To, no trunk/beep ownership and no emergency traffic is answered 481 (7629-7642). `isDialogSourceAuthorized` still waves a no-session BYE through as "harmless" (12976-12984). | `ByeUnknownDialog_test.cpp`; GroupInDialog BYE tests (session present) | **DEFECT** (proven, low impact) | **FIXED by #1083** (7660f4e6, `RequestsHandler.cpp:7629-7642`). A10 re-run on main is green: 481 to the sender, 0 BYE to the registered To. **Rule 5:** `!isEmergencyTraffic(*data)` keeps an emergency BYE for an unknown dialog on the old A10 relay path. This is read but untested: `ByeUnknownDialog_test.cpp` has no emergency case. A BYE for an existing session whose From matches neither leg still reaches this line (read, not run). The fail-open `isDialogSourceAuthorized` is item 2 of #1121. |
| 21 | 7746 | onOk, 2xx while state Cancel | 2xx to INVITE crossing the CANCEL | callee's answer to caller | reg/From | 2xx still relayed so the caller can ACK+BYE; CANCEL 200s absorbed above | FinalFailureRelay `A2xxThatCrossesTheCancel...` | OK | OK (line re-pointed, not re-run) |
| 22 | 7883 | onOk, ring-group/page/hunt winner | 200, CSeq INVITE | winning member's answer to caller | **session-src** | On `de367648` a de-registered caller's slot taken by another phone made the new registrant receive the answer (proven A9: "Session Created between 404 and 402", 200 to 404); a released, free slot was routed by `""` to a free slot. The `endHandle(session->getSrc()->getNumber())` lookup is unchanged. | GroupInDialog, BroadcastHoldResume (live caller) | **DEFECT** (proven) | **FIXED by #1094** (b84b8327, `RequestsHandler.cpp:9505-9532`, `9627-9763`). A9 re-run on main is green: the de-register CANCELs both ringing members (1 each), the session is gone, and 402's later 200 sends 0 messages to 404. |
| 23 | 7947 | onOk, 200 without SDP | 400 clone of the callee's 200, CSeq INVITE | callee | reg/To (resolved at 7913) | target is right (the callee), outcome is not: the clone carries the caller's Via so the callee should discard it, it is `markRelay`'d so the #424 guard does not stop it, the caller gets **no final response at all** (INVITE timer), and `endCall` follows. | none | SUSPECT (inferred) | **OPEN as #1125. `R23` run on main: after 402's 200 without SDP, 0 finals reach 401 and 1 `400 Bad Request` goes to 402 (expected 1 and 0); the session ends ("SDP parse error"). Rule 5: only if a peer-to-peer emergency callee answers without SDP. The #1030 branch right below (7951-7975) already answers the caller 502 and is the shape to copy. |
| 24 | 7988 | onOk, ordinary 200 | 200, CSeq INVITE | callee's answer to caller | reg/From for the send; **callee identity is `findClient(To)` at 7913 with no source check** | any host can answer a ringing call: a 200 from .99 with the ringing Call-ID and `To: 402` is accepted, sets dest=402, connects the session and is relayed to the caller (proven A7). The second half of the row (caller de-registers first: session connected with src `""`, 404 dropped by #424, callee not told) is gone since #1094: the session ends at the de-register and the callee is CANCELled (A3 green on main). | `FinalFailureRelay.CalleeRefusalIsRelayedToTheCallerAndItsAckReachesTheCallee` (live phones; nothing covers the hijack) | **DEFECT** (proven) | **OPEN as #1120.** Re-run on main, both branches red: `A7` (ordinary: 1 `200 OK` relayed to 401 and state Connected; expected 0 and Invited) and `A7b` (ring group answered by a registered non-member: state Connected, expected Invited; the accept is `findClientByAddress` at 7835). **Rule 5:** #1120 states that the address check must not drop a genuine emergency or PSAP-callback answer. |
| 25 | 8088 | onAck | ACK request, CSeq ACK | caller's ACK to callee | reg/To | after CFU/CFB the 200's To is the target, so it follows; callee de-registered: 404 minted, dropped by #424 (A11 passes), ACK lost, session stays | FinalFailureRelay `...ItsAckReachesTheCallee`, GroupInDialog ACK | OK | OK (line re-pointed, not re-run) |

Totals on `de367648`: 4 DEFECT (1, 20, 22, 24), 9 SUSPECT (3, 4, 6, 12, 14, 15, 17, 18, 23), 12 OK. Of
the suspects, six (3, 4, 14, 15, 17, 18) were the same `session-src` mechanism
proven at 22; 6, 12 and 23 were separate.

**Totals on `fe447968`:** DEFECT rows: 3 FIXED (1 by #1082, 20 by #1083, 22 by #1094) and 1 OPEN (24, #1120).
SUSPECT rows: 7 OK now (3, 4, 14, 15, 17, 18 and 6 for slot reuse), 2 OPEN as new issues (12 as #1124, 23 as #1125); the
shared-address case of 6 stays STILL SUSPECT. The 12 OK rows were re-pointed to the new lines and not re-run.

## 3. Other places that route by number, address or pooled client

| Where | Mechanism | Verdict / evidence | Status on main fe447968 |
|-------|-----------|--------------------|------|
| onBye generic far leg (7573-7620) | `From == src->getNumber()` / `dest->getNumber()` picks the far leg (7578-7580), then `buildServerBye(farLeg->getNumber(), farLeg->getAddress())` (7599) | **DEFECT, proven A2**: 401<->402 connected, 401 de-REGISTERs, 403 registers into the freed slot, 402 hangs up: the server BYE goes to 403's address. | **FIXED by #1094** (`RequestsHandler.cpp:9505-9532`). A2 re-run on main is green: the de-register sends exactly 1 BYE to 402 and ends the session, and 402's later BYE sends 0 messages to 403. |
| `sweepExpired`, `forceDisconnect` involvement scans (9766-9830, 9959-10090) | session involvement by `getNumber()`; `release()` must run last (forceDisconnect's comment says so) | OK for those paths; but the explicit de-REGISTER skipped them (section 1). | OK, and the de-REGISTER now takes the same route (**#1094**). |
| CFNA/no-answer reap (11487-11584) | `calleeExt = fwdInvite ? getForwardLegTarget() : invite->getToNumber()` (11494), `findClient(calleeExt)` | **DEFECT, proven A5**: stale `_forwardInvite/_forwardTarget` from an earlier forwarded call on the same pooled Session (section 6). | **OPEN as #1121 (item 1)**: same stale field, same fix (clear it in `Session::reset()`), but #1121 names only the CANCEL reader (2013-2016); this reader is a second one. A5 re-run on main is red: after the reap the CANCEL goes to 403 (1) and none to 404 (0), log `no answer after ring time, no forward -- 403`. |
| onReinvite (12634), onUpdate (12776), onOk re-INVITE/UPDATE 200 (7788-7792) | sender identified by `sameAddress(source, src/dest address)`, peer is the other | OK (read). Both legs on one address => peer always `dest`. Unknown source ignored silently. | OK (read, not re-run) |
| onBye transfer bridge (7440-7525) | `mine = wasTransferorSrc ? dest : src` (7453), `sameAddress(source, mine)` (7455) | read: OK; see section 5. | OK (read, not re-run) |
| `isBroadcastCallerRequest` (86; used by onCancel 1943, onBye 7383, onAck 8053) | `From == src->getNumber()` | SUSPECT: same pooled-slot identity as 22 (read). | **OK now** (read, not run): the only path that released a slot under a live session is gone (#1094). |
| onOk broadcast winner (7835) | `findClientByAddress(source)` | two registrations on one ip:port => first match wins (read). It also accepts the 200 from any registered client, not only a pending target: **A7b is red on main** (state Connected, expected Invited). | **OPEN as #1120** (ring-group branch). The shared ip:port case is STILL SUSPECT (read). |
| onOk ordinary (7913) | `findClient(To)` | DEFECT (row 24). | **OPEN as #1120** |
| `buildServerBye` (13429) | request URI from `findClient(destExt)` if address matches, else address form | OK. | OK (line re-pointed, not re-run) |
| sweepSessionTimers (13081; BYEs at 13161-13166), forceDisconnect (10043, 10060) | BYE to `src` with `(dialogTo, dialogFrom)` and to `dest` with `(dialogFrom, dialogTo)`, assuming src is the UAC and dest is in the *same* dialog | **DEFECT, proven A8** for a park retrieve: see section 5.2. | **OPEN as #1123. A8 re-run on main is red. **Rule 5:** `forceDisconnect` already refuses an extension on an emergency call (10003-10016, `/api/kill` answers 409); the fix must keep that refusal. |
| onRefer (8114) | transferor = `findClient(From)` | covered by ReferSourceAuth_test; not re-audited. | not re-audited |

## 4. Reproducers (each proven unless stated)

All use `RequestsHandler::handle()` end to end, registrations from 192.168.50.20-.24.
Throwaway tests were not committed. Each item ends with **On main**, the result of the
same reproducer rebuilt on `fe447968` (2026-10-24). The positive evidence (the call actually
ended, the survivor actually got its BYE/CANCEL) is asserted next to every green absence.

- **A1 CANCEL after CFU (site 1).** Register 401, 402, 403. `setForward("402","always","403")`.
  401 INVITE to 402 (INVITE is forked to 403). 401 CANCEL (To 402). Expected a
  CANCEL to 403; actual a CANCEL to 402 (the original callee), none to 403.
  **On main:** green (it is `CancelAfterForward_test.cpp`, added by #1082).
- **A2 BYE to a stranger (onBye generic).** 401 calls 402, 402 answers, 401 ACKs.
  401 `REGISTER Expires: 0`. 403 registers (takes the freed slot). 402 sends BYE.
  Expected no BYE to 403; actual a `BYE sip:403@...` to 403's address.
  **On main:** green. The de-register sends exactly 1 `BYE sip:402` and the session is gone; 402's BYE then sends 0 messages to 403.
- **A9 Ring-group answer to a stranger (site 22).** `setRingGroup("600","402,403","ringall")`.
  401 INVITE to 600. 401 de-REGISTERs. 404 registers (takes the slot). 402 answers
  200. Log: `Session Created between 404 and 402`; the 200 is delivered to 404.
  **On main:** green. The de-register CANCELs 402 and 403 (1 each), the session is gone, and 402's 200 sends 0 messages to 404.
- **A3 Caller de-registers while ringing (site 24).** 401 calls 402; 401
  de-REGISTERs; 402 answers 200. Log `Session Created between  and 402`; the
  callee's 200 is turned into a 404 that the #424 guard drops (`refused a reply to a
  response`). Nobody BYEs 402; the session stays Connected with an empty src. The
  assertion I wrote (no 404 to the callee) *passed*, so this is **observed
  behaviour, not a failed assertion**.
  **On main:** green. The de-register CANCELs 402 (1) and ends the session; there is no Connected session with an empty caller. What 402's late 200 (crossing the CANCEL) gets back was not asserted.
- **A7 Answer from a third address (site 24).** 401 calls 402 (.21). A `200 OK`
  from .99 with the same Call-ID, `To: <sip:402@server>;tag=...` and an SDP.
  Expected ignored; actual connected and relayed to 401.
  **On main:** red (#1120). 1 `200 OK` is relayed to 401 and the session is Connected; expected 0 and Invited.
  The ring-group variant (A7b: group 600 = 402,403, a registered non-member 404 sends the 200) is red too: state Connected, expected Invited.
- **A10 BYE for an unknown dialog (site 20).** 401, 402 registered. BYE from .99,
  From 401 To 402, Call-ID `nosuch-1`. Expected 481; actual `BYE sip:402@...` sent to 402.
  **On main:** green (it is `ByeUnknownDialog_test.cpp`, added by #1083): 1 `481` to .99, 0 `BYE sip:` to 402.
- **A5 Stale forward leg after Session recycling (section 6).** CFU 402->403. 401
  calls 402; 403 answers; 401 BYEs; 403 200s the BYE (slot released). 401 then
  calls 404 (registered, no forward). Arm the ring timer in the past, `tick()`.
  Expected CANCEL to 404; actual CANCEL to 403 (`no answer after ring time, no
  forward -- 403`) and none to 404, which keeps ringing.
  **On main:** red, same output (CANCEL to 403: 1, to 404: 0).
- **A8 Admin kills a park retriever (section 5.2).** 401 INVITE 700 (park), 403
  INVITE 700 (retrieve), `forceDisconnect("403")`, `tick()`. Expected a BYE to 401
  carrying the park Call-ID (`pk1`); actual a BYE to 401 carrying the retriever's
  Call-ID (`pk2`), a dialog 401 never saw. The test asserted only the BYE Call-ID.
  **On main:** red, and now run to the end: 403 gets `BYE ... [pk2]` (right), 401 gets `BYE ... [pk2]` (wrong; 0 BYEs on `pk1`), and `getSession("pk1")` is still present afterwards, so the park session is **not** ended (the doc said this was read only; it is now run).
- **A4 Session::reset leaks (section 6).** Unit level: `setForwardLeg`,
  `setCancelledLegExt`, `markDegradedReported()`, then `reset()`. After reset
  `getForwardLegTarget()` is still `"403"`, `getCancelledLegExt()` still `"403"`,
  and `markDegradedReported()` returns `false` instead of `true`.
  **On main:** red, identical: `getForwardLegTarget()` `"403"`, `getForwardLegInvite()` non-null, `getCancelledLegExt()` `"403"`, `markDegradedReported()` false.
- **A6 (cleared).** INVITE From 401 sent from .99 to an unknown number: refused
  403 to the sender (#497), not a 404 to the real 401. Sites 7-10 stand. (Not re-run.)
- **A11 (cleared).** Callee de-registers, caller ACKs: the 404 is dropped by #424.
  Site 25 stands. (Not re-run.)

### Reproducers for the SUSPECT rows (run on main on 2026-10-24)

- **Rows 3, 14, 17 (hunt exhausted).** Register 401, 402. `setRingGroup("600","402","hunt")`.
  401 INVITE 600. 401 `REGISTER Expires: 0`. 404 registers (takes the freed slot).
  402 refuses (603 at 2256, 486 at 6978, 480 at 7132). Expected: nothing
  delivered to 404. Predicted: the final goes to 404 (`endHandle(src number)`).
  **On main:** green for 603, 486 and 480: the session is gone right after the de-register and 0 messages reach 404. OK now.
- **Rows 4, 15, 18 (ring-all, everyone refused).** Same, members `402,403`
  `ringall`, both refuse with 603 / 486 / 480. Predicted: the last refusal goes to 404.
  **On main:** green for all three: session gone after the de-register, 0 messages to 404. OK now.
- **Row 6.** 401 and 402 connected. 401 sends a hold re-INVITE (relayed to 402).
  401 de-REGISTERs; 403 takes the slot. 402 answers 491 from .21. The source matches
  `dest`, so the peer is `src` (now 403) and `endHandle("403")` delivers the 491 to 403.
  **On main:** green: session gone after the de-register, 0 messages to 403. OK now.
- **Row 12.** 401 and 402 connected; 401 blind-REFERs to 403. 403 answers the
  PBX's INVITE with `100 Trying` (CSeq INVITE, the leg's Call-ID). onTrying has no
  blind-leg claim, so it is relayed `endHandle(From)` to the transferee 402.
  **On main:** red: the 100 is relayed to 402 (1 message, expected 0). STILL BROKEN.
- **Row 23.** 401 calls 402; 402's 200 OK carries no SDP. Predicted: 401 gets
  nothing, 402 receives a 400 it discards, the session is ended.
  **On main:** red, as predicted: 0 finals to 401, 1 `400 Bad Request` to 402, session ended. STILL BROKEN.
- **Fork-loser 200 (section 7).** Ring-all 600 = 402,403. 402 answers 200; before
  the CANCEL lands, 403's 200 arrives. Predicted: no ACK and no BYE to 403.
  Not re-run (not one of the findings re-checked on 2026-10-24); still inferred.

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

- BYE from A (on X): onBye `peerCallID` branch (7426-7463): `notify = Y.getSrc()` = P,
  `buildServerBye(P number, P address, Y id, Y.dialogTo, Y.dialogFrom)`. Right
  party, right dialog. (read)
- BYE from P (on Y): `notify = X.getSrc()` = A, X's headers. Right. (read)
- Identity used: pooled `src` slot for both number and address. Wrong party only
  through the slot aliasing of section 1, which #1094 closed for the de-register path (read; the mechanism is the one A2 showed).
- Not safe: session-timer/forceDisconnect treat `dest` as in the *same* dialog.
  X.dest = P, so a timer or kill BYE to P carries X's Call-ID, which P never held
  (481). Pickup does not arm session timers, so only forceDisconnect reaches
  it; it also visits Y, so each phone still gets one correct BYE plus one stray.
  (read, not run; same defect as A8)

### 5.2 Park ring-back and retrieve (ParkOrbit.cpp)

`rb->setDialogHeaders(data->getTo(), data->getFrom())` (ParkOrbit.cpp:361) stores
the ring-back session's headers **reversed on purpose**: the PBX is the UAC of
that dialog, so `dialogFrom` holds the parker's To (its tag) and `dialogTo` holds
the PBX's From (PBX tag), and the shared `(dialogTo, dialogFrom) -> (From, To)`
order of onBye yields a correct BYE. The field names are not role-neutral; `Session`
carries `isParkUac()` only so *some* readers can invert, and several do not.

- Parked party hangs up: `rb.getSrc()` = the parker, BYE `(rb.dialogTo,
  rb.dialogFrom)` = From PBX, To parker. Correct. Parker hangs up (BYE on
  rbCallID): `notify = parked.getSrc()`, parked's headers (`From=PBX+tag`,
  `To=parked party`). Correct. (read; ParkOrbit_test `RingbackAnswerCaptures...` pins the swap)
- **Wrong dialog (proven A8, red on main).** `allocVirtualPeer(slot.parkedExt, slot.parkedAddr)`
  (ParkOrbit.cpp:145, 349) gives the stand-in the parked party's **real number and address**, so
  `destIsVirtual` in forceDisconnect (10053-10057) tests dest *number* against 777/440/888/555
  and does not exclude it; sweepSessionTimers (13125-13132) has the same number test. A kill of the retriever
  BYEs the parked phone on the retrieve session's Call-ID (it holds only the
  park Call-ID), and the park session itself is not "involved" (its src is the
  parked party, not 403), so it is never ended: **A8 on main shows both** (BYE to 401 on `pk2`, `pk1` still a session afterwards).
  The ring-back session's dest BYE additionally carries From=parker, To=PBX, inverted
  (read, not run). The session timer sweep cannot reach park-spliced sessions (grant=false),
  so only the admin path is exposed.

### 5.3 Attended and blind transfer

`src`/`dest` keep the original participants: they do not name who survives.
`_isTransferBridge`, `_wasTransferorSrc` (default `true`), `_blindXferLeg`
and `_transferorCseqAtRefer` say how to read them.

- Surviving party is `wasTransferorSrc() ? dest : src` at 7453, 7471, 8594, 8980, 9130, 13513
  (six sites; 8594 reads the dropped side, the inverse). Header orientation flips with the same flag at
  7498-7499, 9006-9008, 9133-9135 and 13526-13527.
- onBye on a bridge half (7440-7525): `mine = wasTransferorSrc ? dest : src`
  must equal the BYE's source address, else the BYE is from the dropped
  transferor and is answered and ignored. Then BYE to `survivor` of the **peer**
  using the peer's `wasTransferorSrc` and `(peerAHdr, peerOtherHdr)`. Address
  used: `survivor->getAddress()` of a pooled slot. Correct while the flag is
  right and the slot is not released. (read)
- `_wasTransferorSrc` is not cleared by `reset()` or `release()` (default `true`,
  set at 8478, 8481, 8788, 9062). Every reader is gated on `isTransferBridge()` /
  a peer link, so a stale value is only read after being rewritten. (read: no
  reachable stale read found.)
- Blind leg (`isBlindXferLeg`): the PBX is UAC; its own 100 Trying is not
  claimed in onTrying (row 12, red on main).

### 5.4 Anchor teardown

Identity fields: `_anchorParticipantId` (upstream leg), `_anchorLegReleased`
(far leg already dropped; read by endCall so a dropped leg is not dropped twice),
`_anchorInbound` (direction).

- Outbound (handset is src, PBX is UAS): BYE to `getSrc()` with
  `(From=<dialed>@PBX;tag=local, To=invite From)` (anchorDroppedLocked, 5949-5957) or
  `(dialogTo, dialogFrom)`. endAnchorCallForPreempt (4984; BYE at 5010): `handset = src`, `(dTo, dFrom)`.
- Inbound (handset is dest, PBX is UAC): `handset = getDest()`, `(dFrom, dTo)`
  (opposite order, endAnchorCallForPreempt) or hand-built from `getRemoteTag()`
  and `getLocalTag()` (anchorDroppedLocked, 5886-5894). `endCall`'s src/dest
  arguments are swapped by direction (`inbound ? farLeg : phone`).
- `_anchorParticipantId` is copied before `endCall` because `release()` clears it
  (endAnchorCallForPreempt comment). Address used: pooled handset slot. Can a BYE
  reach the wrong party? Only through slot aliasing (a de-registered/reused
  handset), which #1094 closed for the de-register path; direction is correctly flagged. (read)

Summary: no path was found that addresses the wrong party in steady state. Every
path was exposed to the pooled-slot aliasing of section 1 (closed for the de-register path by #1094), and the session-timer /
force-disconnect pair is wrong for any session whose `dest` is a cross-dialog or
virtual stand-in that carries a real extension number (park; still open, A8). Orientation is
re-derived by hand at ~12 `buildServerBye` sites.

## 6. Session reuse and release (addenda 2-4)

**Recycling is real.** `allocateSession` (RequestsHandler.cpp:12187) reuses the
first pool slot whose Call-ID is empty or absent from `_sessions`, and calls
`Session::reset(callID, src)`. `endCall` ends a call with `release()`.

**Fields `reset()` does not touch** (compared against the member list, `Session.cpp:15-87`, on `fe447968`): `_forwardInvite`,
`_forwardTarget`, `_cancelledLegExt`, `_degradedReported`, `_ringDeadline`,
`_rtpMarkA/B/At`, `_wasTransferorSrc`, `_transferorCseqAtRefer`. Plus `_startTime`
(rewritten), `_disposition` (reset clears it).

- **`_forwardInvite` / `_forwardTarget`** (set by `CallForker::redirectInvite`,
  CallForker.cpp:196, i.e. every CFU/CFB/CFNA forward that creates a session).
  Read in the ring-expiry reap (RequestsHandler.cpp:11487-11494): `fwdInvite = ...;
  calleeExt = fwdInvite ? getForwardLegTarget() : invite->getToNumber()`. A later
  plain call recycled into that slot sees a non-null stale `fwdInvite`, so the
  reap CANCELs the *old* forward target and logs/ends the call with the old
  extension, while the real callee is never CANCELled. **Proven (A5), red on main.** It is also read by
  `onCancel` (2013-2016, `forwarded = !getForwardLegTarget().empty()`) and by `endClientCalls` (9677-9690), so
  the same stale target misroutes a CANCEL and a de-register's CANCEL. The slot
  also pins the old SipMessage pool entry until overwritten.
  **Status: OPEN as #1121 (item 1)**; A5 and A4 are its red tests, and the tick() reap is a second reader to add to its wording.
- **`_cancelledLegExt`** is cleared only at RequestsHandler.cpp:2102. If the
  cancelled callee's 487 never arrives (lost, or the call ends first) the value
  persists into the next call on the slot, and `onReqTerminated` (2094-2104) then
  ACKs and swallows a genuine 487 from that extension instead of relaying it.
  The field is proven stale by A4 (unit, red on main); the end-to-end 487 swallow is inferred.
  **Status: OPEN as #1122.
- **`_degradedReported`** (#906, Rule 5 relevant): `markDegradedReported()`
  returns false once set, and nothing resets it. A4 **proves** only that the flag survives `reset()`
  (red on main). That a later degraded
  911/933 on a recycled slot is then never reported follows from reading
  RequestsHandler.cpp:11645 (`!markDegradedReported()` => `continue`); it was not
  run end to end. It is the most serious stale field (Rule 5: a degraded
  emergency call goes unreported).
  **Status: OPEN as #1122**.
- `_wasTransferorSrc`, `_transferorCseqAtRefer`: always written before read
  (section 5.3); `_rtpMark*`: guarded by `_rtpWatchArmed`, which reset clears.

**What `release()` leaves live** (the member list minus its body, `Session.cpp:155-201`): `_disposition`,
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
*released* object (the CFNA reap copies `ringTag` first for that reason, 11485).

**`setState(Connected)` before the `_dest` check.** `_state` is assigned, then
the dest check only logs (Session.cpp:101-110). Every `setState(Connected)` caller was
checked (RequestsHandler 589, 2700, 3281, 3511, 3620, 3953, 4167, 5642, 6688,
7862, 7977, 8924, 9054, 12769, 12969, 14433, 14841; CallPickup 129, 138;
ParkOrbit 132, 189, 364): all set a dest first, or are Held->Connected (which
returns before the check), or restore an existing Connected session. No
caller reaches it with a null dest (14433 and 14841 traced too: the trunk-inbound path sets the handset at 14338, the outbound trunk path sets `dummyTrunk` at 14636). The caller list has the same 17 RequestsHandler call sites as on `de367648`, moved; the check was not repeated on 2026-10-24. `_src->getNumber()` in the same log line is
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
  `findClientByAddress(source)` while the session is Invited (7835). Winner/loser: the
  winner becomes `dest`; every other pending target gets a CANCEL built per
  target (To rewritten); the losers' 487 is ACKed in onReqTerminated because the
  session is broadcast; a CFNA-cancelled leg is recognised by
  `setCancelledLegExt(number)` plus `ToNumber ==` (2098-2099).
- Gap (inferred, not run): a loser whose 200 crosses the winner's. After the
  session is Connected the loser's 200 matches neither leg address, so
  `peer` stays null and the broadcast branch returns because state != Invited
  (7827-7885). It gets **neither an ACK nor a BYE**; it believes it is in a call
  and retransmits the 200 until its timer. Needs a red test with two members
  answering back to back. (Status: not re-checked on 2026-10-24.)
- Two members behind one ip:port: `findClientByAddress` picks the first.

## 8. Required closing items

**(a) Count by verdict (25 endHandle sites), on `de367648`:** DEFECT 4 (rows 1, 20, 22, 24),
SUSPECT 9 (3, 4, 6, 12, 14, 15, 17, 18, 23), OK 12. Outside the table: DEFECT, proven
at the onBye generic far leg (A2), the CFNA reap (A5), the session-timer and
force-disconnect BYE for park (A8), and Session::reset (A4); inferred: fork-loser 200.

**Status on `fe447968`:** FIXED: rows 1 (#1082), 20 (#1083), 22 (#1094), and A2 (#1094). OPEN: row 24 (#1120);
the stale forward fields behind A5 and the CANCEL reader (#1121 item 1). OK now: rows 3, 4, 14, 15, 17, 18 and 6 for slot reuse. OPEN: row 12 (#1124), row 23 (#1125), A8 (#1123),
and `Session::reset()` leaving `_cancelledLegExt` and `_degradedReported` set. STILL SUSPECT: row 6 on a shared address,
the fork-loser 200, and the end-to-end 487 swallow and degraded-report miss that A4 only proves at the field.

**(b) Would a leg-identity refactor remove repeated inference or only move code?**
Both, split by pattern. Repeated inferences seen:

1. *Sender by source address* ("peer = sameAddress(source, src) ? dest : ..."):
   onReinvite, onUpdate, onOk re-INVITE 200, onFinalFailure 2304, onBye bridge,
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
(#1094 removed the one path that released a slot under a live session, so patterns 1-4 are
now latent rather than reachable by the de-register; the refactor argument is unchanged.)

**(c) Ranked suspects to turn into red tests.** Milestones: v1.7.0 is teardown / wrong
leg; v1.8.0 is memory pressure. Status on `fe447968` in brackets.

1. *(v1.7.0, Rule 5 applies)* A de-registered caller's call must never be routed to
   another phone, and a live 911/933 must stay up (`sweepExpired` exempts
   emergencies on purpose, #712). Two fix shapes: end the extension's calls
   through `endCall()` with the same emergency exemption, or do not free or
   rename a pool slot that a session still holds. Reds: A2, A9, A3.
   **[FIXED by #1094, first shape, emergency exemption kept (`expireLease()`).]**
2. *(v1.7.0, Rule 5)* `Session::reset` must clear `_degradedReported`, so a
   later degraded 911/933 on a recycled slot is reported again (A4 unit red; add
   the end-to-end through the `degradedEmergencyCallIds` loop).
   **[OPEN as #1122.]**
3. *(v1.7.0 and v1.8.0)* `Session::reset` clears `_forwardInvite`, `_forwardTarget`,
   `_cancelledLegExt` (A4); end-to-end A5. v1.8.0 because a stale `_forwardInvite`
   pins a SipMessage pool entry on every recycled slot.
   **[forward fields: OPEN as #1121 item 1; `_cancelledLegExt`: OPEN as #1122, same issue as item 2.]**
4. *(v1.7.0)* CANCEL after CFU/CFB/CFNA reaches the forward target (A1). **[FIXED by #1082.]**
5. *(v1.7.0)* forceDisconnect of a park retriever BYEs the parked phone on its own
   Call-ID and ends the park session (A8, second half now run). **[OPEN as #1123.]**
6. *(v1.7.0)* An INVITE 200 only counts from the callee's leg (A7). **[OPEN as #1120.]**
7. *(v1.7.0)* A BYE with no session is answered 481, not relayed (A10). **[FIXED by #1083; the emergency exemption is read but untested: an emergency BYE for an unknown dialog keeps the old A10 relay path.]**
8. *(v1.7.0)* A fork loser whose 200 crosses the winner's gets ACK+BYE (section 7). **[not re-checked; still inferred, no issue.]**
9. *(v1.7.0)* Hunt/ring-all exhausted and all-refused answer the caller after the
   caller's slot changed (rows 3, 4, 14-18); row 6 likewise. **[OK now: cause removed by #1094.]**
10. *(v1.7.0)* 200 without SDP: the caller gets a final (row 23). **[OPEN as #1125.]** 100 Trying on a
    blind/attended leg is not relayed (row 12). **[OPEN as #1124.]**

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
