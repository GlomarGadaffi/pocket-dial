# 3CX public API surface (from github.com/3cx repos, shallow clones, read only)

Clones: `C:\Users\desmo\AppData\Local\Temp\claude\C--Users-desmo\4845dcb2-339e-4a78-8576-cc4b91c75e34\scratchpad\3cx-src\<repo>\`
Citations are `repo/path:line` relative to that folder. Nothing was built or run.
Repos and versions seen: `call-control-sdk-ts` = @3cx/call-control-sdk 0.1.10, Node >= 24 (package.json:3,46); `xapi-tutorial` swagger = XAPI, `x-pbx-version: 20.0.10.1479` (swagger.yaml:6); the other three package.json files are all `1.0.0` placeholders (call-control-examples has no version field), so no useful API version pin exists in them.
Shorthand: SDK = call-control-sdk-ts; SVC = call-control-service-example; EX = call-control-examples; AG = agentic-call-control; XT = xapi-tutorial.
Tags: FACT = stated/visible in code. INFERRED = my reading, not stated. UNVERIFIED = repo claims it, nothing in the repo proves it.

---

## 1. Call Control API

### Base paths
- REST root is `https://<pbx>/callcontrol` (no `/api` or version segment). FACT: SVC/README.md:11-12 ("two public endpoints: /connect/token and /callcontrol"), SVC/src/client.ts:341-343, SDK/src/actions/call-control-api.ts:25-67, EX/server/src/services/ExternalApi.service.ts:148.
- Resources: `GET /callcontrol` (all DNs), `GET /callcontrol/{dn}`, `/callcontrol/{dn}/devices`, `/callcontrol/{dn}/participants[/{id}]`. FACT: SVC/src/client.ts:374-398; entity list SVC/README.md:177-178.
- The base URL is the PBX management FQDN (SVC/.env.example:1-2).

### Auth
- Token endpoint `POST {pbx}/connect/token`, OAuth2 `grant_type=client_credentials`, `client_id` = the Service Principal's DN number (may be alphanumeric), `client_secret` = secret shown once at creation. FACT: SVC/README.md:25-28,142-149; SVC/src/auth.ts:66-80; SDK/src/auth/token-store.ts:40-52.
- Body encoding differs by repo. SVC uses `application/x-www-form-urlencoded` (SVC/src/auth.ts:67-77). SDK and EX use multipart FormData (SDK/src/auth/token-store.ts:40-51; EX/server/src/services/ExternalApi.service.ts:125-136). INFERRED: the PBX accepts both encodings (each repo ships code that uses one; nothing was run here, and no repo states a preference).
- SDK sends `scope=mcp xapi` (SDK/src/auth/token-store.ts:42; asserted in SDK/test/token-store.test.ts:54). SVC and EX send no scope. SVC documents the response as `{access_token, token_type:"Bearer", expires_in:3600, scope:"..."}` (SVC/README.md:152; type with `pbx_version`, optional `refresh_token`: SVC/src/types.ts:9-17). INFERRED: 3600 s is the example value shown, not a guaranteed constant.
- Lifetime/refresh: no refresh_token flow is used anywhere. Clients just re-POST client credentials. SDK renews `expires_in - 60 s` early (SDK/src/auth/token-store.ts:5,54-55); SVC renews 60 s early with a 30 s floor (SVC/src/auth.ts:4,102); on HTTP 401 both drop the token and retry once (SDK/src/auth/axios-client.ts:49-57; SVC/src/client.ts:356-360). WS handshake 401 triggers a refresh and reconnect (SDK/src/websocket/connection.ts:76-90).
- Token errors come back as HTTP 400 with JSON `error` (`invalid_client`, `access_denied`, `invalid_scope`), not 401 (SVC/README.md:155-156; SVC/src/auth.ts:84-96).
- Header on every call: `Authorization: Bearer <token>` (SDK/src/auth/axios-client.ts:27-31).
- Another WS auth path exists: a one-time `?ticket=` query parameter for browsers. Mentioned only in a comment, with no issuing endpoint anywhere in the five repos (SVC/src/client.ts:136-138). UNVERIFIED as to how to obtain a ticket.

### WebSocket
- URL `wss://<pbx>/callcontrol/ws`, header `Authorization: Bearer <token>`. FACT: SVC/README.md:160-161, SVC/src/client.ts:133-142, SDK/src/client.ts:92-94, EX/server/src/services/ExternalApi.service.ts:66-68.
- SDK builds `wss://` unconditionally from `pbxBase` host+port (SDK/src/client.ts:92-94).
- Heartbeat: SDK pings every 5 s and terminates if no pong within 10 s (SDK/src/websocket/connection.ts:22-23,58-68). Reconnect backoff default 5 s doubling, cap 120 s, `maxReconnects` default Infinity (SDK/src/websocket/connection.ts:36-40,122-144; SDK/README.md:49-65). SVC reconnects 1 s doubling, cap 30 s (SVC/src/client.ts:195).
- Frames are UTF-8 JSON text. Push envelope: `{"sequence":42,"event":{"event_type":0,"entity":"/callcontrol/100/participants/5120"}}` (SVC/README.md:163-165; SVC/src/types.ts:51-68; SDK/src/types.ts:89-96).
- `event_type` is a number: 0 Upsert, 1 Remove, 2 DTMFstring (`attached_data.dtmf_input`), 3 PromptPlaybackFinished (`attached_data.prompt_id`), 4 Response (reply to a request made over the socket). FACT: SVC/README.md:167-175; SVC/src/types.ts:27-38. The SDK only knows 0-3 (SDK/src/types.ts:81-86).
- `entity` is one of `/callcontrol`, `/callcontrol/{dn}`, `/callcontrol/{dn}/devices/{device_id}`, `/callcontrol/{dn}/participants/{id}` (SVC/README.md:177-178). SVC dispatches these to `appChanged`, `dnChanged`, `deviceChanged`, `participantChanged`, `dtmf`, `promptFinished` (SVC/src/client.ts:34-56,256-294).
  - `appChanged` fires when "the app registration itself changed (DN list edited, permissions revoked)" (SVC/src/client.ts:41).
  - `device_id` is the SIP Contact URI and may contain "/" (SVC/src/types.ts:107-108; SVC/src/client.ts:270-271).
- Events carry no state. An Upsert only means "GET the entity again" (SVC/README.md:180-181). SDK does exactly this: `api.get(entity)` per Upsert (SDK/src/state/call-state-store.ts:96-117). Remove for a participant means the leg ended (SVC/README.md:172).
- `sequence` is "monotonic per app, a gap means events were dropped" (SVC/README.md:182-183). SDK says the PBX "restarts sequence numbering per session" and resets its tracker on each (re)connect (SDK/src/state/call-state-store.ts:39-45; SDK/src/client.ts:101-102). Events missed while disconnected are not replayed; re-read `GET /callcontrol` after reconnect (SVC/README.md:125-127).
- What is pushed: only changes to the app registration, DNs, DN devices (registered SIP contacts), call participants, DTMF, prompt-finished. FACT per the entity list above. No entity type for user profile status, presence, voicemail, or queue state exists in any event handler or doc in the five repos.
- WS also accepts requests: `{"RequestID":"888-1","Path":"callcontrol/100/participants/5120/drop","RequestData":{}}`. The reply is an `event_type 4` event whose `attached_data` is `{RequestID, Path, StatusCode, Response}`. Field names are PascalCase and case-sensitive (SVC/README.md:199-214; SVC/src/types.ts:70-90; SVC/src/client.ts:304-333). The SDK does not use this path (REST only).

### Data model (REST)
- `GET /callcontrol` returns `DnInfo[]`: `{dn, type, devices[{dn, device_id, user_agent}], participants[...]}`. `type` is "Extension, Queue, RingGroup, RoutePoint, ..." (SVC/src/types.ts:172-179). The sample output shows `100 (Wextension)` and `apiexample (Wroutepoint)` (SVC/README.md:77-78).
- Participant fields: `id, status, dn, party_caller_name, party_dn, party_caller_id, party_did, party_dn_type, device_id, direct_control, originated_by_dn/type, referred_by_dn/type, on_behalf_of_dn/type, callid, legid, participant_uid, participant_attached_data, caller_attached_data` (SVC/src/types.ts:124-148; SDK/src/types.ts:41-66). The array inside DnInfo is a reduced subset (SVC/src/types.ts:150-170).
- Participant `status` values: `Undefined, Dialing, Ringing, Connected, Hold, Held` (SVC/README.md:233-234; SVC/src/types.ts:112-118). `Dialing` = we initiated, `Ringing` = the other side initiated. No direction field (SVC/README.md:111-116).
- Visibility: a Service Principal sees only its own DN plus DNs assigned to it; anything else answers 403 (SVC/README.md:19-21,244). SDK splits events into own-DN (`participant*`) vs assigned extensions (`extensionParticipant*`) (SDK/README.md:67-93).

### Participant actions (REST `POST /callcontrol/{dn}/participants/{id}/{action}`)
| Action | Notes | Source |
|---|---|---|
| `drop` | hang up leg | SVC/README.md:222 |
| `answer` | route points always; extensions only if `direct_control` (uaCSTA); multi-device extensions have one leg per device, answer the `direct_control` leg | SVC/README.md:223; SDK/README.md:126-127 |
| `divert` | only while `Ringing` inbound; `destination` required; `reason` optional | SVC/README.md:224; SDK/README.md:140 |
| `routeto` | adds a route, "succeeds only if answered"; `timeout` seconds, default 180; valid Ringing or Connected | SVC/README.md:225; SVC/src/types.ts:97-99; SDK/README.md:141-142 |
| `transferto` | blind transfer, replaces the leg's party with `destination` | SVC/README.md:226 |
| `attach_participant_data` / `attach_party_data` | body `attacheddata`, keys MUST start with `public_` or the PBX rejects with 422; party data is not pushed over WS, call `refresh()` | SVC/README.md:227; SDK/README.md:163-196 |
| `cancel_stream_queue` | drops audio queued on the PBX for the outgoing stream | SDK/src/actions/call-control-api.ts:56-67 |
| `playprompt` | answers 501 (not implemented) | SVC/README.md:253 |
- "Any other action name comes back as 422" (SVC/README.md:229). SDK's typed method list is exactly drop, answer, divert, routeto, transferto, attach_participant_data, attach_party_data (SDK/src/types.ts:163-170); it has a generic `controlParticipant(id, method, body)` for unwrapped future actions (SDK/src/client.ts:292-308).
- Destination strings: plain DN ("101") or structured `{Type}.{DN}.{External}` with types None, VoiceMail, Extension, Queue, RingGroup, IVR, External, Fax, Boomerang, Deflect, RoutePoint (SDK/src/types.ts:113-152). Voicemail transfer = destination `VoiceMail.<dn>.` (SDK/src/participant.ts:183-193).
- makecall: `POST /callcontrol/{dn}/makecall {destination}`. The PBX rings the DN's registered device(s) first, so this is third-party call setup (SVC/src/client.ts:402-419). Device-specific: `POST /callcontrol/{dn}/devices/{device_id}/makecall` (SVC/src/client.ts:422-424; EX/server/src/services/ExternalApi.service.ts:255-269). 200 = DN had exactly one device, `result` holds the new leg; 202 = several devices, `result` may be null; 422 = no registered device or invalid state (SVC/README.md:22-23,242-246). `attacheddata` is ignored by makecall (SVC/README.md:120-122).
- Result body for all actions: `{finalstatus: Success|Rejected|Failed, reason, reasontext, result}` (SVC/README.md:236-238; SVC/src/types.ts:181-190). Status codes: 403 DN not assigned, 404 no such device/leg, 422, 424 PBX rejected (SVC/README.md:240-247).
- Blocking calls: `/makecall /transferto /routeto /divert` may block until the target leg reaches a final state (minutes); client-side abort does not cancel the action on the PBX (SDK/src/auth/axios-client.ts:10-19,37-39). Default HTTP timeout 30 s otherwise (SDK/src/auth/axios-client.ts:24).
- No "attach/detach audio" action exists. Audio is a separate stream endpoint (section 2). A DTMF event (type 2) exists; there is no send-DTMF action in any repo.

### Hold / resume: confirmed absent as an action
- FACT: no hold/resume/unhold method anywhere in the SDK (SDK/src/types.ts:163-170; SDK/README.md:218-244 table) or SVC action table (SVC/README.md:216-229, which also says unknown actions return 422). A whole-tree token census (`\w*(hold|held)\w*`, all files, no cap) finds hold-related tokens only in: the status enum `Hold, Held` (SVC/README.md:233-234; SVC/src/types.ts:117-118); XAPI's group setting `CallHandlingFlags.HoldCall` (XT/swagger.yaml:33428-33432, used by Pbx.Group.CallHandlingMode at XT/swagger.yaml:24135-24138); MusicOnHold/OnHoldFile settings in XAPI (media played to a held caller, configuration only); a unit-test fixture that feeds the SDK a status string `'OnHold'` (SDK/test/client.test.ts:143,147,163,164; note `OnHold` is not in the documented enum, so it is a test string, not evidence of a wire value); and prose ("please hold", "holds the digits").
- CORRECTION to prior notes: the status values `Hold`/`Held` DO exist in the participant status enum. What is absent is any API action to put a call on hold or resume. Whether the PBX emits `Hold`/`Held` when a phone itself holds is not shown by any repo (UNVERIFIED). The SDK treats `status` as a free string and only special-cases `Connected` (SDK/src/types.ts:43; SDK/src/state/call-state-store.ts:7,107).

### Extension (monitored DN) limits
- No audio and no DTMF for extension calls; only for the app's own RoutePoint DN. Transfer/Drop yes; Divert Ringing-inbound only; RouteTo Ringing or Connected; Answer only with `direct_control`; Attach data yes (SDK/README.md:95-143; participant.ts guard SDK/src/participant.ts:245-254).
- Extension `participantConnected`-style event fires only when the extension answers; ringing is visible via `extensionParticipantUpdated` with `status === "Ringing"` (SDK/README.md:104-124).
- A RoutePoint auto-answers inbound calls (SDK/README.md:104-107).

---

## 2. Audio streaming

- Transport: plain HTTP on the participant resource, not WebSocket. FACT: SVC/README.md:251-252 ("raw octet-stream API ... `GET`/`POST /callcontrol/{dn}/participants/{id}/stream`").
  - Receive (PBX to app): `GET .../stream`, `responseType: stream`, long-lived (SDK/src/audio/streams.ts:13-23). EX does the same (EX/server/src/services/ExternalApi.service.ts:220-227).
  - Send (app to PBX): `POST .../stream` with `Content-Type: application/octet-stream` and `Transfer-Encoding: chunked`, body is a never-ending PassThrough (SDK/src/audio/streams.ts:122-133; EX/server/src/services/ExternalApi.service.ts:157-213).
  - The SDK disables the HTTP timeout for any URL containing `/stream` (SDK/src/auth/axios-client.ts:6-8,37-39).
- Direction: two independent one-way HTTP streams per participant, so two-way audio = one GET plus one POST. INFERRED from the verbs plus SDK usage (`getAudioStream()` for caller audio, `getAudioWriter()` for audio to the caller, SDK/README.md:27-37). Per participant id, own RoutePoint DN only (SDK/README.md:95-102).
- Format: SDK docs say "PCM 8kHz 16-bit mono" (SDK/README.md:27,36; SDK/src/client.ts:156; SDK/src/participant.ts:119). Byte order is little-endian: INFERRED, since the SDK debug helper reads samples with `readInt16LE` (SDK/src/audio/pcm-debug.ts:1-8) and AG resamplers use `readInt16LE/writeInt16LE` (AG/examples/openai-realtime/src/callcontrol/audio-utils.ts:2-14,34-44). EX feeds STT with `LINEAR16` at 8000 Hz and TTS with `LINEAR16` 8000 Hz (EX/server/src/services/AiIntegrationExample/AiIntegration.service.ts:47,58-59) and writes mono 8 kHz WAV prompts (EX/server/src/services/App.service.ts:76-82). A whole-tree token census over all five clones (no include filter, no line cap, .git/.yarn/lockfiles excluded; regex `\w*(mulaw|ulaw|alaw|g\.?711|pcm[au])\w*`) finds only `G711ToT38Fallback` (a fax setting, XT/swagger.yaml:27359) and the `peakPcmAmplitude` helper names. No mulaw/alaw/PCMU/PCMA anywhere, so the REST audio stream is documented only as linear PCM.
- Frame/pacing (outbound): SDK sends 320-byte chunks (20 ms at 8 kHz, 16 bit, mono), paced by a 20 ms loop; pads a short tail with zeros; when idle writes a 320-byte silence chunk every tick as keep-alive (SDK/src/audio/streams.ts:8-9,145-178; SDK/src/audio/types.ts:4). `clear()` drops the local buffer for barge-in; `cancel_stream_queue` is the heavier PBX-side flush (SDK/src/audio/streams.ts:188-190; SDK/src/actions/call-control-api.ts:56-67).
- Inbound chunk size: not framed by the SDK. Chunks are whatever HTTP delivers; EX batches 50 chunks before STT (EX/server/src/services/CustomIVRAppExample/CustomIVRApp.service.ts:383-388).
- Reconnect: if the POST session ends (HTTP 200 or error) the SDK reopens it with 250 ms doubling backoff (cap 2 s) and keeps buffered PCM (SDK/src/audio/streams.ts:10-11,34-40,76-98).
- "Attaching" audio to a call is implicit: the call just has to be a participant on the app's own DN (e.g. someone dials the RoutePoint, or the app makes a call from its own DN, `makeCall` default `from` = appId, SDK/src/client.ts:237-250). The only calls where the app is in the media path are its own-DN legs (SDK/README.md:95-102).
- Providers: AG bridges to OpenAI (24 kHz, triplicate/decimate resample), xAI ("native 8 kHz"), Gemini, Qwen (AG/README.md:70-75; AG/examples/openai-realtime/README.md:85; AG/examples/alibaba-qwen-realtime/src/providers/qwen-realtime.ts:46,61).

---

## 3. XAPI (xapi-tutorial)

- Base `https://<pbx>/xapi/v1`, OData v4-style service ("This OData service is located at /xapi/v1", XT/swagger.yaml:4; basePath XT/auth.ts:41). Spec is OpenAPI 3.0.4 (XT/swagger.yaml:1); the client is generated (XT/src/xapi/api.ts, ~79k lines) via `yarn gen` (XT/CLAUDE.md:13,27).
- Auth: same `/connect/token` client credentials (XT/auth.ts:18-33), multipart FormData with client_id/client_secret/grant_type; no scope sent. Cached until `expires_in` with a lock (XT/auth.ts:35-50; note: no early-renewal margin). Swagger security scheme: OAuth2 client_credentials with tokenUrl `/connect/token` and `scopes: {}`, plus authorization-code + PKCE (`openid profile email offline_access`) for user authentication (XT/swagger.yaml:40913-40930).
- Setup on the PBX: Admin > Integrations > API, create client, tick "XAPI Access Enabled", "Select group and desired role" (XT/README.md:7-12). Enterprise license required (XT/README.md:16-17; XT/CLAUDE.md:41).
- Concurrency claim (UNVERIFIED by anything else in the repos): "the PBX only allows one active access token at a time" and tests must run with `-i` (XT/CLAUDE.md:25,39; XT/README.md:39).

### User profile status / forwarding profiles
- `Pbx.User` has `CurrentProfileName` (nullable string, XT/swagger.yaml:23257) and navigation property `ForwardingProfiles[]` (XT/swagger.yaml:23298-23302). `Pbx.ForwardingProfile` fields: `Name, CustomName, CustomMessage, BlockPushCalls, RingMyMobile, AcceptMultipleCalls, OfficeHoursAutoQueueLogOut, DisableRingGroupCalls, NoAnswerTimeout, AvailableRoute{NoAnswerAllCalls, BusyAllCalls, NotRegisteredAllCalls, NoAnswer/Busy/NotRegistered Internal/External Destination}, AwayRoute{AllHoursInternal, AllHoursExternal, External, Internal}, Id` (XT/swagger.yaml:31042+; example values XT/swagger.yaml:40045-40085). `ForwardingExceptions[]` (ExtensionRule) also on User (XT/swagger.yaml:23293-23297).
- READ: `GET /Users` (ListUser XT/swagger.yaml:21217), `GET /Users({Id})` (20733), `GET /Users({Id})/ForwardingProfiles` (the only verb on that path, 20342-20397), and `$select`/`$expand` params are supported on collections. Lookup by number: `getUserByNumber` (XT/swagger.yaml:20129; XT/src/users.spec.ts:43-47; number must be OData-quoted via `odataParamEncoder`, XT/auth.ts:7-9).
- SET: `PATCH /Users({Id})` (UpdateUser, XT/swagger.yaml:20777-20781). Its body is `Pbx.User`, which includes `CurrentProfileName` and `ForwardingProfiles`. The swagger contains no `readOnly` annotation at all (grep count 0), so whether `CurrentProfileName` is writable via PATCH cannot be told from these repos (UNVERIFIED). No spec file touches `CurrentProfileName` or `ForwardingProfiles`; `users.spec.ts` only updates `Number` and `Groups` (XT/src/users.spec.ts:49-103).
- `/MyUser` (GET + PATCH, XT/swagger.yaml:8315-8368) and `/MyUser/ForwardingProfiles` (GET only, 8415-8460) act on the token's own user. INFERRED: that is meaningful for user tokens (auth-code + PKCE), not for a service principal, which has no user.
- Group right `AllowToChangePresence` exists on `Pbx.Rights` (XT/swagger.yaml:30651-30663). INFERRED: that gates users changing their own presence/profile; the "role" picked at API-client creation (XT/README.md:11; example role name `users` at XT/src/users.spec.ts:92) probably maps onto these rights.
- Impersonation: the only mention is a test that POSTs `http://localhost:5004/webclient/api/MyPhone/session` with the XAPI bearer token and body `{name:"AI", version:"0.1", isHuman:false, impersonate:"110"}` and asserts nothing (XT/src/impersonate.spec.ts:8-20). Service Principals also carry `MyPhoneEnabled` (XT/swagger.yaml:25448-25450) and SVC says a token needs at least one of Call Control, XAPI, MyPhone permissions (SVC/src/auth.ts:28-30). INFERRED, not documented: MyPhone + impersonate is the route to act as a user. The MyPhone API itself is not described in these repos.
- Queue state: `User.QueueStatus` enum `LoggedOut | LoggedIn` (XT/swagger.yaml:23402-23405,33536-33541). `User.IsRegistered` boolean (XT/swagger.yaml:23330).

### Presence / extension state of others
- Polling only. FACT-by-absence: no WebSocket, SignalR, subscribe, SSE or webhook construct in XAPI swagger (grep: the only "Webhook" is a trunk-messaging field, XT/swagger.yaml:30731), no event type in Call Control for presence (section 1).
- Pollable state: `GET /ActiveCalls` (`Id, Caller, Callee, Status, LastChangeStatus, EstablishedAt, ServerNow`, XT/swagger.yaml:10-54,38262-38270) plus `POST /ActiveCalls({Id})/Pbx.DropCall` (55-82); `SipDevices.Online` (XT/swagger.yaml:29790-29792, list only, XT/src/phones.spec.ts:12-17); `User.IsRegistered`; `User.CurrentProfileName`; `User.QueueStatus`. `Pbx.Peer` (the DN list) has only Id, Name, Number, Type, Tags, Hidden, MemberOf, no status (XT/swagger.yaml:24354-24384). INFERRED: `CurrentProfileName` for other users is readable by list/get, so it can be polled.
- Presence-named settings that exist (config flags, not state feeds): group `Rights.ShowMyPresence`, `ShowMyPresenceOutside`, `AllowToChangePresence` (XT/swagger.yaml:30661,30696-30699); `ADUsersSyncConfiguration.SetTeamsPresence` (XT/swagger.yaml:32280); `GoogleUserSync.UseCalendarEventsAsPresence` (XT/swagger.yaml:33197); Microsoft365 `AuthorizePresence/TestPresence/DeauthorizePresence` actions (XT/swagger.yaml:7652-7689). A whole-tree census for `mwi|unread|messages waiting|voicemail count|presence|subscribe` finds nothing else (no Call Control or SDK mention of presence at all).
- XAPI has a call action too: `POST /Users/Pbx.MakeCall {dn, destination, contact, testCall}` returning a CallControlResultResponse with a `Pbx.CallParticipant` (XT/swagger.yaml:20989-21028, 31449+). `Users({Id})/Pbx.SetMonitorStatus {days}` exists (XT/swagger.yaml:21029-21054, 40820-40833); semantics not described.

### Voicemail / MWI
- Per-user voicemail settings only: `VMEnabled, VMPIN, VMEmailOptions, VMDisablePinAuth, VMPlayCallerID, VMPlayMsgDateTime` (XT/swagger.yaml:23439-23442; example 37391-37396), global `/VoicemailSettings` (21309) and bulk delete `DeleteAllUserVoicemails` (21362). There is no message list, message count, unread count or MWI field. A whole-tree, case-insensitive census for mwi, unread, messages waiting, voicemail count, newvoicemail finds nothing in any of the five clones.
- Call Control only offers voicemail as a transfer/route/divert destination (SDK/src/participant.ts:183-193).

### Devices / SBC ("via SBC")
- Management objects only. `/Sbcs` list/create and `/Sbcs({Name})` get/update/delete plus `Pbx.PushConfig` (XT/swagger.yaml:18046-18230). `Pbx.Sbc` fields: Name (key, max 12 chars), DisplayName, Password, Group, LogLevel, LogSize, AudioPort, `Security` (enum ref Pbx.Security, XT/swagger.yaml:25375-25378; example value `TCP`, 38161; enum members not read), PassiveServerIsEnabled, PassiveServer, `Connection` (XSBCConnection: Calls, Cpu, Disk, ElapsedTime, Latency, Memory, RegisteredPhones, UdpActive, Up; XT/swagger.yaml:32146-32181), HasConnection, LocalIPv4, PublicIP, ProvisionLink, PhoneMAC, PhoneUserId, Version (XT/swagger.yaml:25314+, example 38152-38172).
- Per-device SBC attribution: `DeviceInfos.ViaSBC` + `SbcName` (XT/swagger.yaml:29748-29762); `PhoneRegistrar.SbcName/SbcDisplayName/ProvType` (example XT/swagger.yaml:37487-37490); `POST /Users/Pbx.GetPhoneRegistrars {macs[]}` (20621-20658). `User.BlockTunnel` boolean (XT/swagger.yaml:23244 region, example 37425) and `NetworkSettings.TunnelPort` (XT/swagger.yaml:25551).
- Registering a device: no REST call registers a SIP device. Phones are provisioned (`Pbx.GenerateProvLink()`, `Pbx.Regenerate`, `Pbx.ReprovisionPhone`, `/DeviceInfos({Id})/Pbx.Provision`, XT/swagger.yaml:20707, 20398, 20683, 4335). SIP registration itself is a SIP-level act not described here.

---

## 4. Rate limits, concurrency, scopes/roles, licensing

- Rate limits: none stated for the API. Whole-tree census (`\w*(rate.?limit|throttl)\w*`, all files, no cap) finds only an OpenAI event name `rate_limits.updated` (AG/examples/openai-realtime/src/providers/openai-realtime.ts:353) and XAPI's `AntiHackingSettings.ThrottlePeriodLength` / `MaxRequestPerPeriod` / `HackChallengeRequests` (XT/swagger.yaml:30596-30648; an admin-configured anti-hacking setting object, `/AntiHackingSettings` at 701; its relation to API clients is not stated, so UNVERIFIED whether API calls count against it). `grep -w 429` hits only SVG path data in cc-component-lib; no `Retry-After` string anywhere; no 429 handling in any client. The only client-side bound is the 30 s axios timeout (SDK/src/auth/axios-client.ts:24).
- Concurrency:
  - Call Control: the SDK collapses simultaneous token fetches into one (SDK/src/auth/token-store.ts:15,31-33; SDK/test/token-store.test.ts:61; SVC/src/auth.ts:38-39,55-57). No documented cap on WS connections, audio streams or calls.
  - XAPI: "only one access token active at a time" (XT/CLAUDE.md:25,39; XT/README.md:39). UNVERIFIED. INFERRED risk: if true, one Service Principal's token shared across Call Control and XAPI (SDK requests `scope=mcp xapi`, SDK/src/auth/token-store.ts:42) or two processes with the same credentials could invalidate each other. Not tested in these repos.
  - Many legs per call: makecall rings every registered device, one participant each, grouped by `callid` (SVC/README.md:105-110).
- Scopes/roles/permissions:
  - Service Principal flags: `CallControlEnabled`, `XAPIEnabled`, `MyPhoneEnabled` (XT/swagger.yaml:25437-25457; example 38202-38205). A token is refused (`access_denied`) unless at least one of Call Control, XAPI, MyPhone is on (SVC/src/auth.ts:28-30, SVC/README.md:17-19).
  - Call Control access is restricted to the SP's own DN plus explicitly assigned DNs, else 403 (SVC/README.md:19-21,244). EX setup lists "Specify additional extensions you want to monitor" (EX/README.MD:13).
  - XAPI role is chosen by group and role at client creation (XT/README.md:11). Group `Rights` flags are in XT/swagger.yaml:30651+.
  - Token `scope` the SDK requests: `mcp xapi` (the MCP server is `{pbxBase}/mcp`, SDK/src/client.ts:358-361; MCP over Streamable HTTP with the same bearer, AG/packages/mcp/src/mcp-client.ts:12-21).
- Licensing: 3CX Enterprise license required for Call Control (SVC/README.md:16; EX/README.MD:18-19, which also says "and CFD access") and for XAPI (XT/README.md:16-17; XT/CLAUDE.md:41). "The token endpoint refuses call control credentials otherwise" (SVC/README.md:16). Call Control additionally requires the DN to have a registered SIP device for makecall (SVC/README.md:22-23). Nothing about per-API-client, per-call or per-stream license counts (UNVERIFIED either way).

---

## 5. Not present in any of these repos

- Profile status change events (Available/Away/DND/Out of office/custom): no WS entity or push of any kind for it; polling `Users.CurrentProfileName` over XAPI is the only visible read, and a documented way to SET it for another user is not shown (PATCH `Users({Id})` accepts the property by schema, but no repo exercises it).
- A subscribe-to-extension-state primitive (BLF subscription / SUBSCRIBE-NOTIFY equivalent): none. But for DNs assigned to the Service Principal, the Call Control WebSocket DOES push Upserts for `/callcontrol/{dn}/participants/{id}` (status Ringing/Connected/Hold/Held, Remove when the leg ends) and for `/callcontrol/{dn}/devices/{device_id}` (SIP contact appears/disappears, i.e. registration changes) (SVC/README.md:177-178; SVC/src/client.ts:256-294; SDK/README.md:67-93,129-137). INFERRED: from those two streams a client can derive idle/ringing/busy plus registered/unregistered for those assigned DNs only. Dialog-level BLF detail (e.g. which line, call-pickup eligibility) is not provided. For any DN not assigned to the SP the answer is 403 and nothing is pushed. Everything else is poll-only: `GET /ActiveCalls`, `SipDevices.Online`, `User.IsRegistered`. `User.Blfs` is a string property with no documented meaning (XT/swagger.yaml:23240).
- MWI / voicemail message counts: nothing. No message list, no unread count, no subscribe.
- SBC / tunnel protocol: nothing about the 3CX SBC-to-PBX wire protocol, tunnel port protocol, or SIP registration "via SBC". Only management metadata (`/Sbcs`, `ViaSBC`, `TunnelPort`, `BlockTunnel`).
- Hold/resume action, send-DTMF action, consult/attended transfer, conference/merge, mute, recording control on a live call: not in the participant action set.
- Audio for non-RoutePoint (extension) legs: not available by design (SDK/README.md:95-102).
- Any documented rate limit, WS connection cap, or `Retry-After` handling.
- Docs for the MyPhone/`webclient` API, WebSocket `?ticket=` issuance, and the `Pbx.SetMonitorStatus` semantics.
