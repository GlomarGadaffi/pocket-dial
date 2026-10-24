# Demarcation: who is responsible for what (emergency calling and anchor deployment)

This page says where pocket-dial's responsibility ends and the deployer's begins. It records owner decisions from [#1046](https://github.com/GlomarGadaffi/pocket-dial/issues/1046) (2026-10-20). It is not legal advice and not a legal conclusion. Legal review still applies; see [Open questions for counsel](#open-questions-for-counsel).

Read it with [ADR-002 section 5](ADR-002-PROGRAMMABLE-MEDIA-ANCHOR.md), the [E911 compliance self-assessment](AUDIT-LEGAL-E911-COMPLIANCE.md) and the [threat model](THREAT_MODEL.md).

## Summary

- Pocket-dial is firmware that you deploy. The administrator who deploys it owns the deployment, including emergency calling.
- A 911 or 933 call leaves only through the configured anchor (Telephony API) route. When that route is down or does not exist, the call is answered `503 Emergency Call Not Routable` and the on-site notification is raised. There is no fallback route, and no SIP trunk carries 911 or 933.
- The administrator registers the service profile and the dispatchable location (ERL) with the anchor or carrier provider and owns that registration. The firmware does not register it for them.
- Public deployment is not supported.

## Assumption this page rests on (owner position, not a legal conclusion)

The owner's position is that a pocket-dial deployment is not a multi-line telephone system (MLTS) in the Kari's Law sense, because there is no ITSP interconnect: the firmware has no carrier trunk of its own for emergency calls, and nothing leaves via the anchor except what the administrator has configured on the anchor provider's side. That is a position the project holds, not a finding. A regulator or court may read it differently, and facts in your deployment (for example, a carrier trunk you add on the PBX side) can change the answer. Legal review still applies. The firmware behaves the same either way: it implements direct dialing and on-site notification whether or not the law applies to you.

## Who is responsible for what

| Party | Responsible for |
| --- | --- |
| Firmware project (pocket-dial) | The behaviour listed under "What the firmware does" below, and documenting its limits. Nothing about your registration, address data, carrier contract or the legal status of your deployment. |
| Administrator (the deployer) | Everything about the deployment: choosing to enable an anchor path and accepting the limitations, registering the service profile and ERL with the provider, keeping that data correct, setting the on-site notification targets, testing, staffing the notification point, who may use the system, and compliance with the law that applies to them. |
| Carrier / anchor provider (for example the 3CX or CPaaS operator) | Accepting and routing the emergency call it is handed, its own E911 registry and PSAP interconnect, and its own service terms. Pocket-dial does not control any of that. |
| PSAP | Receiving the call and dispatching. The PSAP may call back; the firmware only protects the callback path on the extension (below). |

## Duties and owner

| Duty | Owner |
| --- | --- |
| Accept the limitations before an anchor path is enabled (default No) | Administrator |
| Register the service profile / dispatchable location (ERL) with the provider | Administrator |
| Keep the registered address and callback number correct | Administrator |
| Provision an emergency-capable route on the anchor | Administrator, with the provider |
| Set the on-site notification list (`notifyExts`) and keep someone watching it | Administrator |
| Keep the system off the public Internet | Administrator |
| Test the setup without placing real emergency calls | Administrator |
| Classify 911 and 933 before any dial plan, including the `9911` habit | Firmware |
| Answer 503 and notify when there is no route | Firmware |
| Hold the PSAP callback window open on the extension | Firmware |
| Refuse an emergency number as a slot's route DN, so a slot test cannot dial it | Firmware |
| Route the call and carry it to the PSAP | Provider |
| Decide whether the deployment is an MLTS and what law applies | Administrator, with counsel |

## What the firmware does

Each item was checked against the source on `main`.

- Detects `911` and `933` before dial-plan rules, and treats a single leading `9` (`9911`) as `911`. `pbx::classifyEmergencyDial` in `src/SIP/EmergencyCall.hpp`; routing in `RequestsHandler::routeEmergencyCall` in `src/SIP/RequestsHandler.cpp`.
- Offers the call only to a provider that places real calls. `telephonyProviderPlacesRealCalls` admits only the 3CX provider type, so `emergencyRoute()` is `Anchor` on such a board and `None` on any other (a far-side board, a loopback simulator). The provider is chosen at boot.
- Never falls back. The code has no SIP-trunk path for 911/933. If the anchor is not connected, or refuses before dispatch, or no route exists, the handset gets `503 Emergency Call Not Routable` with a `Warning: 399` header that names the reason, and no `Retry-After`.
- Logs the attempt before routing, and queues the on-site notification (`notifyEmergency`) after the response or call leg is enqueued. The notification says whether the call was routed, and reports "not routed" when the anchor refused. If `notifyExts` is empty, SIP notification is off (`PUT /api/e911-config`, see [API.md](API.md)).
- Marks the call so the RTP-inactivity reaper does not hang it up, and opens a 30-minute PSAP callback window for the calling extension (`kEmergencyCallbackWindow`).
- Requires an explicit acceptance to enable or activate an anchor slot (#1073, PR #1078). The API refuses with `409` naming `acceptLimitations` unless the request carries the current acceptance version. The dashboard dialog is titled "Enable anchor calling? Default: NO". The acceptance stores the version, the accepting session's role and the time, and each enable asks again. The dialog says: not for public deployment, E911 has limits, and the deployment is the administrator's.
- Refuses an emergency number as a slot's route DN, so the slot test-dial cannot place a real emergency call (#1047).
- Shows the state: `emergencyRoute` in `/api/status`, and a dashboard banner when the route is `none`.

## What the firmware does not guarantee

- That a 911 call reaches a PSAP. It hands the call to the anchor; the anchor and carrier decide the rest.
- That the PSAP receives a correct address or callback number. The firmware does not register, store or validate the service profile or ERL.
- That the on-site notification is seen. It is a SIP message and an alert to the configured extensions; if nobody is there, nobody is told. It does not delay the call.
- Any emergency calling on a board with no emergency route, or while the anchor is down. The caller must use another phone.
- Any emergency calling over a SIP trunk, or over a fallback of any kind.
- That the acceptance is legal consent. It is a recorded acknowledgement by an admin session, with a timestamp that is 0 until the board has synced its clock.
- The legal status of your deployment.

## Test-call guidance

Do not dial 911 or 933 as part of automated tests, bench runs, CI, load tests or demos. Project tests exercise the emergency path with host unit tests that never reach a carrier.

To check your own setup without a live emergency call:

1. Confirm the registration with your anchor or carrier provider through that provider's own process, and ask them how they want testing done. Use only the method the provider documents.
2. Check the board: `emergencyRoute` in `/api/status` should read `anchor`, and the dashboard should show no "911 ROUTE NONE" banner.
3. Check `GET /api/e911-config` lists the extensions that should be notified, and that someone is watching them.
4. Check that `GET /api/telephony-config` shows your anchor slot enabled with `acceptanceMissing` false.

Any live test of an emergency number is the administrator's decision, made with the provider and, where required, the PSAP. This project does not instruct it.

## Open questions for counsel

1. Is a deployment with an anchor but no carrier trunk of its own an MLTS under 47 CFR 9.16, or an interconnected VoIP service under Part 9 for the party that runs the anchor? Does the answer change when the anchor is a hosted PBX?
2. Which party holds the dispatchable-location duty (RAY BAUM'S Act) when the administrator registers the ERL with a provider, and what does the administrator owe the provider?
3. Does answering `503` and notifying on-site satisfy what is owed when no route exists, or must a deployment have a route?
4. Is a recorded acceptance by an admin session, with no named user and a possibly unsynced clock, adequate evidence of responsibility? Should the dialog text be reviewed?
5. How should a deployment that pairs this firmware with a separately operated carrier trunk document its demarcation?
6. What notice, if any, is owed to end users that emergency calling has these limits?
