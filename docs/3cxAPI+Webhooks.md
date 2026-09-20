# 3CX Call Control API + WebSocket Events

Reference for the **anchor leg** — the non-SIP side of the B2BUA, where
`TelephonyAnchorClient` talks to 3CX. Everything below was verified against
3CX's own published documentation and its reference implementation on
**2026-09-18**; sources and method are at the bottom, and anything inferred
rather than read is marked as such.

> **The headline, because it explains a whole class of bug:**
> **The Call Control API has no hold, no resume, no mute and no park — and no
> `Held` participant status.** Hold is a SIP dialog state with no counterpart
> on this leg. The board cannot signal it downstream; it can only *disguise* it.

---

## 1. Endpoint surface

```
GET  /callcontrol                                            all DNs + participants + devices
     /callcontrol/ws                                         WebSocket (events + requests)
     /callcontrol/{dn}
     /callcontrol/{dn}/devices
     /callcontrol/{dn}/devices/{deviceid}
POST /callcontrol/{dn}/devices/{deviceid}/makecall
POST /callcontrol/{dn}/makecall
     /callcontrol/{dn}/participants
     /callcontrol/{dn}/participants/{id}
     /callcontrol/{dn}/participants/{id}/stream               PCM audio
POST /callcontrol/{dn}/participants/{id}/{action}             the control verbs
```

## 2. The complete set of participant actions

`{action}` takes exactly these values. There are no others.

| action | what it does | constraint that matters |
|---|---|---|
| `drop` | drop participation in the call | no parameters |
| `answer` | answer | **only** for participants supporting `direct_control` (uaCSTA) or RoutePoint participants |
| `divert` | replace a **ringing** participant with a new destination | **fails if the participant is already connected** |
| `routeto` | add alternative routes for an existing participant | works on connected *or* ringing; participant keeps its own participation until delivery succeeds |
| `transferto` | transfer | **only** for a connected (talking) participant |

### The one place "hold" appears in the entire documentation

Inside `transferto`'s description:

> *"The other party **will be put on hold** for the time of transfer attempt.
> The participant will be replaced on success, or will be **returned to the
> call if transfer fails**."*

So 3CX **does** hold internally — it is simply not exposed as a primitive. The
only reachable path to it is beginning a transfer and not completing it.

**That is a hack, not a design, and it is noted here so nobody has to
rediscover it.** It changes call state, it depends on failure-path behaviour,
and `transferto` is only valid on a connected participant. Treat "disguise the
hold locally" as the supported approach and this as a curiosity.

## 3. Participant statuses

From 3CX's reference client (`cc-component-lib/src/constants.ts`):

```
PARTICIPANT_STATUS_CONNECTED = "Connected"
PARTICIPANT_STATUS_DIALING   = "Dialing"
PARTICIPANT_STATUS_RINGING   = "Ringing"
```

**Three states. No held, no parked, no muted.** A participant the PBX is
holding on our behalf still reads `Connected`.

## 4. WebSocket — `/callcontrol/ws`

The WebSocket is **not** a replacement for the REST calls. It is a
bidirectional channel that can carry requests *and* is the only source of
real-time events. 3CX explicitly supports using it purely as an event channel
while continuing to use HTTP for actions, and warns that WebSocket messages
have a size limit, so it suits small event payloads rather than bulk data.

### Application → server (`WebSocketRequest`)

| field | meaning |
|---|---|
| `RequestID` | app-generated, used to match the response |
| `Path` | same paths as HTTP, e.g. `/callcontrol`, `/callcontrol/{dn}`, `/callcontrol/{dn}/participants/{id}` |
| `RequestData` | required for actions (`makecall`, `divert`, …), optional for GETs |

### Server → application (`WebSocketResponse`)

`RequestID`, `Path`, `StatusCode` (an HTTP status), `Response` (body, shape
depends on path).

### Events (`ExternalCallFlowAppHookEvent`)

```
ExternalCallFlowAppHookEvent {
    EventType  = <enum>
    Entity     = the path the event concerns, e.g. /callcontrol/{dn}/participants
    AttachedData = WebSocketResponse
}
```

| EventType | name | meaning |
|---|---|---|
| `0` | Upsert | entity added **or updated** |
| `1` | **Remove** | **entity has been removed** |
| `2` | DTMFstring | DTMF from the remote party |
| `4` | Response | response to a request sent over the WebSocket |

DTMF events only arrive for calls belonging to the application itself (between
the application DN and its remote party).

> **Documentation defect, flagged deliberately.** The same page writes
> `EventType=0` in the struct example, then `EventType=5 (ENUM)` in the prose
> immediately below, while the enum table lists only `0, 1, 2, 4`. **There is
> no 5 and no 3.** Trust the table; do not write a `case 5:`.

### Why this matters to us

**There is no "held" event and no "held" status**, so a participant that our
board has put on hold produces no downstream state change at all. Conversely,
an `EventType=1 Remove` on a participant entity means 3CX has genuinely
removed that participant — it is not a hold, a pause, or a transient.

That is the event behind `AnchorClient::CallEvent::Dropped` in
`RequestsHandler.cpp`, which calls `stopBridge()` and tears the session down.
When diagnosing a call that vanished, **the WebSocket event log is the
authority**, not the SIP side.

## 5. Consequences for this project

1. **Hold on an anchored leg can only ever be a local disguise.** Keep the
   participant `Connected` and keep feeding `/stream`, so the PBX never
   observes anything unusual. `MediaBridge::setHeld()` does exactly this by
   routing hold music to the anchor. There is nothing to signal and nothing to
   negotiate.
2. **`divert` is not a hold fallback.** It is documented to fail on a connected
   participant.
3. **A missing bridge is not the same as a missing dialog.** `answerAnchorReinvite()`
   answers a 481 when no `MediaBridge` matches the Call-ID, treating media state
   as proof of dialog existence. A held call legitimately has no active media
   and a perfectly live dialog. See the hold/resume issue for where that bites.
4. **`answer` will not work on an ordinary participant.** It requires
   `direct_control`/uaCSTA or a RoutePoint.
5. **Events are the only way to learn a participant went away**, and they arrive
   solely on the WebSocket. Anything that drops that socket loses the ability to
   notice a dropped call.

## 6. Configuration REST API

`https://www.3cx.com/docs/configuration-rest-api/` is a **separate** API for
provisioning and configuration (extensions, trunks, settings). It is not call
control and contains **no** hold/resume/park/mute either — checked, zero hits.
Do not go looking there for a call-state primitive.

---

## Sources and method

| source | used for |
|---|---|
| `https://www.3cx.com/docs/call-control-api/` | WebSocket model, `ExternalCallFlowAppHookEvent`, EventType enum |
| `https://www.3cx.com/docs/call-control-api-endpoints/` | endpoint paths, action table, the `transferto` hold sentence |
| `https://www.3cx.com/docs/configuration-rest-api/` | confirming the absence of call-state verbs |
| `https://github.com/3cx/call-control-examples` | `PARTICIPANT_CONTROL_*` and `PARTICIPANT_STATUS_*` constants |

Method, since "the API has no hold" is a claim about an **absence** and those
are easy to get wrong:

- All three doc pages were fetched raw and stripped to text locally rather than
  summarized, because a summarizing fetch truncated them and would have made an
  absence unprovable.
- `hold|unhold|resume|park|mute` was grepped across all three (~65 000
  characters of text). **One hit**, the `transferto` sentence quoted above.
- The same terms were grepped across every source file in 3CX's reference
  repo. **Zero hits.**

An absence found by two independent routes — official docs and the vendor's own
client — is about as strong as this gets without a live PBX to interrogate. If
a future 3CX version adds a hold verb, this file is wrong and should be
re-verified the same way rather than trusted.
