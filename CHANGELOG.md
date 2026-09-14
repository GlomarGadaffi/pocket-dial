# Changelog

## Unreleased (on main, in no published release) — 2026-09-13

The admin plane was rebuilt and the box learned to call outside. Those are the two
headline changes, and they are related: a dashboard nobody could reach was fine while
every feature lived on the LAN, and became untenable the moment the only route to an
outside line was a dial-plan rule that could only be written from that dashboard.

This is also the first time any of it has been proved on a real telephone. Every
release before this one was verified on the host test suite, on `pjsua`/SIPp against
the desktop binary, and on a bench board answering its own synthetic clients. A Yealink
T29 is now registered to the bench board and an outbound call has completed to the
public network with two-way audio.

**Breaking for scripts and for anything written against a PIN.** The admin login is a
username and password, `POST /api/admin/set-pin` is gone, and there is no longer any
window in which an unprovisioned device admits unauthenticated requests.

### Security — the admin credential is a username and password, with forced first-use setup

`AdminAuth` was PIN-only. A 4-to-16-digit number is what you can type on a phone
keypad, and the web dashboard inherited it for no better reason than that the DTMF
admin menu needed one. The two uses have nothing in common — a keypad cannot type a
username, and a browser has no reason to be limited to digits — so they are now two
independent secrets.

- `setLoginCredential()`/`verifyCredential()` (username + password, salted and iterated
  SHA-256, the same brute-force lockout machinery as before) replace
  `setPin()`/`verifyPin()`. `isProvisioned()` now means "a real, non-default credential
  has been set", and `needsInitialSetup()` is its named complement.
- **The device ships with `admin`/`admin`**, on purpose, so that the gate in front of
  every admin action can be unconditional from the very first boot. The old model had
  to admit unauthenticated requests until a PIN existed, which is a window; a known
  default is not a secret, but it is a credential, and it lets the window close.
- That default is then forced out of use server-side: `requireAdmin()` refuses every
  admin-gated route except `POST /api/admin/set-credential` with
  `403 {"error":"setup_required"}` until it is replaced. Enforced in the gate, not
  suggested by the dashboard — a client that skips the UI gets the same answer.
- The phone-keypad DTMF admin menu (`*PIN#code` — NTP resync, topology switch, factory
  reset) keeps its own numeric secret via `setDtmfPin()`/`verifyDtmfPin()`, and
  **deliberately has no default**: it stays disabled until explicitly set. A default
  there would let `*0000#9991` factory-reset a freshly flashed box from any phone on
  the link.
- `requireAdmin()` drops the "unprovisioned devices skip the session check" bypass
  entirely. Wi-Fi onboarding, `/api/configuring`, OTA, the telephony/DID/dial-plan
  endpoints and factory-reset are now gated identically, with no special-cased
  onboarding exemption. `POST /api/admin/login` takes `username=`+`password=` and no
  longer answers `409` when nothing is provisioned, because the default always
  verifies.

Verified: 389 host tests (0 failures, 2 pre-existing Windows-only skips), including new
coverage for the default credential, its removal the instant a real one is set, and the
DTMF PIN's no-default behaviour; the full `tests/http/test_api.sh` suite (32/32) live
against the host binary, reordered so admin auth runs first — there is no longer a "run
everything while unprovisioned" window for test ordering to exploit. Confirmed on the
T-ETH-Elite bench board end to end: default login works, `setup_required` blocks
`/api/kill` until setup completes, and factory reset returns the board to the
default-credential state.

### Fixed — the dashboard must always be reachable, not dark by default

This is the correction most likely to matter to someone holding an older document.

The HTTP listener used to close once a device was provisioned, and the documented way
back in was to dial `*4887` from the extension the firmware happened to consider the
admin (default `1001`), from the same network segment, with a phone already registered.
Found on real hardware: flashing a fresh build to an ESP32-S3 that already had a PIN in
NVS left the dashboard answering "connection refused" on port 80 the moment any client
registered. That is a worse failure mode than the credential exposure the gate was
meant to prevent, and it bought nothing over the session and CSRF checks already
sitting in front of every mutating endpoint.

The listen socket now opens unconditionally at construction and stays open for the
process lifetime. `requireAdmin()`'s per-route session + CSRF check is unchanged and
remains the actual gate on admin actions.

Removed as dead weight once the socket gate was gone: **the `*4887` star-code handler**
and its Issue #93 shadowed-PIN warning, the admin-HTTP grace-window atomics and TTL in
`RequestsHandler`, the authenticated "Keep open (1h)" dashboard button and its
`/api/admin/keepalive` endpoint, and `set-pin`'s now-pointless "PIN must not begin with
4887" reservation. The broader `*PIN#code` DTMF admin menu is untouched. **There is no
longer any star-code that reopens the HTTP plane, because there is nothing to reopen** —
any instruction to recover a board that way describes firmware that no longer exists.

`tests/AdminHttpGate_test.cpp`'s 14-test dark-gate/DTMF-trigger suite is replaced by 3
tests pinning the new invariant: the socket accepts connections immediately, stays
reachable once provisioned, and setting a credential does not change that. Confirmed
live on a T-ETH-Elite: "connection refused" on every probe before, HTTP 200 on every
probe after, across boot and a real client registering and re-registering, with
`GET /api/telephony-config` still correctly requiring authentication.

### Added — outbound trunk access as a dial-plan action

A dial-plan rule can now carry `action=trunk`: `9XXXXXXXXXX` with `stripDigits=1` and
`target=1` turns a dial of `93057673260` into `13057673260` and places it as a real
outbound call through the currently-configured anchor provider — the same origination
core virtual extension `555` uses, extracted into
`RequestsHandler::originateAnchorCall()` and reached from `CallForker::routeDialPlan()`
through a new `PbxEnv::routeTrunkCall()`.

Two things about this are worth stating plainly, because the word "trunk" invites the
wrong mental model:

- **It is not a SIP trunk.** The outbound path is an `AnchorClient` — HTTP/OAuth2, a
  call-control WebSocket, and media as chunked-HTTPS PCM16 — and the shipping real
  client speaks the 3CX Call Control API. Nothing in the tree ever *sends* a `REGISTER`,
  so the box never registers to an ITSP and speaks no SIP to a carrier at all.
- **A rule is the only way out.** There is no hardcoded `9` prefix and no
  unregistered-destination fallback. With an empty dial plan, every outside number is
  answered `404` without leaving the box. `POCKETDIAL_MAX_ANCHOR_CALLS` is 1, so one
  outside call at a time. There is no E.164 normalization anywhere: what the rule
  produces is exactly what the provider is asked to dial.
  *(Superseded later in this same unreleased window: the macro was raised to **4**
  once `TelephonyAnchorClient` landed and the single-call path was proven on the
  bench. The effective limit is `min(provider, 4)`, and the default
  `LoopbackAnchorClient` still declares 1 — so a stock board is unchanged, but a
  board on a real trunk now carries four. See `PoolConfig.hpp:221`.)*

Three teardown bugs surfaced with it, all fixed here: `onCancel()`, `onBye()` and
`onAck()` recognized an anchor call by the literal string `"555"` parsed off the wire,
but a trunk call's CANCEL/BYE/ACK carries the dialed digits instead. Left alone, hanging
up a trunk call would have answered `404` instead of tearing down, leaking both the
`MediaBridge` and the live carrier leg. All three now recognize the session by
`isAnchor()`.

### Fixed — three silent defects between the dial plan and the trunk

Found while working out why an outbound 3CX call reached the provider's API and never
placed a call. All three are silent: nothing logs, nothing errors, the dashboard shows
a healthy box.

1. **`DialPlan::upsert()` dropped `stripDigits` on an edit.** It copied only action and
   target when the pattern already existed, so the strip count kept its first-insert
   value forever — and `persistDialPlan()` wrote that stale value to NVS, where it
   survived a reboot. Re-POSTing a pattern was the only way to edit a rule, so fixing a
   typo in a trunk target silently reverted its strip: a rule saved as strip 1 / prepend
   1 and later edited would dial `193057673260` instead of `13057673260`.
2. **"Strip N, prepend nothing" could not be expressed.** The delete signal was an empty
   `target`, which made the request that *creates* a strip-only trunk rule
   byte-identical to the request that *deletes* it. That shape is not exotic — it is
   exactly what this trunk wants (a bare `substr(1)`, no prepend), so the one digit
   format known to work was the one format pocket-dial could not store. **The delete
   signal is now an empty `action` *and* an empty `target`; naming an action always
   means upsert.** Every existing delete call site already passes `("pattern","","")`,
   so nothing changes for them, and a non-trunk action with an empty target is now
   refused outright rather than quietly deleting the rule being edited.
3. **An enabled trunk slot could be saved with a blank route DN.** `setSlot()` checked
   field lengths and the `https://` prefix and nothing else. A blank route DN is the one
   misconfiguration nothing downstream can report: `isConnected()` is WebSocket state
   only and the control socket carries no DN, so the board boots "connected", every
   `makeCall` posts to `.../callcontrol//makecall`, and the provider is genuinely
   reached and answers non-2xx. In the field that reads as "the API was hit but no call
   happened". An enabled non-Loopback slot now requires a route DN, a client ID and a
   secret; the secret check honours `keepSecret` so editing a saved slot still works,
   and disabled slots stay free to be incomplete drafts.

Each fix has a regression test, and each test was verified to **fail** against the
unfixed code before being kept — including the observable that mattered most, that a
blank-`routeDn` slot came back with `view().enabled == true`. 408 host tests pass.

### Added — the dashboard is a patch bay, and the dial plan finally has an editor

The dashboard was a brass-and-amber "operator rail" skin over a text list. It is now the
literal patch-bay switchboard it was always describing: five semantic jack states
(idle / ringing / active / parked / alert) classified from real `/api/status` data,
ring-group membership drawn as coloured cords between jacks instead of a text list, a
live packet-counter sparkline, and a header badge showing the real web-session countdown
next to a clearly separate note about the independent DTMF phone-menu channel.
Per-call detail moved from the cords into the jack modal's Peer/Duration fields. The old
accent theme-cycler is removed outright as incompatible with a fixed semantic palette.

Three small backend pieces exist to feed it honestly rather than letting the page invent
values:

- `GET /api/status` now emits `parkedCalls` (`{orbit, parkedExt, parker, secondsParked}`),
  already computed by `ParkOrbit::snapshotRows()` but never surfaced — needed to tell a
  parked jack from an idle or a connected one.
- `GET /api/admin/status` now emits `sessionRemainingSec`, via a new read-only
  `AdminAuth::sessionRemainingMs()` that does **not** itself slide the session's expiry.
  A countdown that refreshed the thing it was counting would never expire.
- `POST /api/telephony-config/{slot}/test` — a connectivity probe, not a bridged call.
  It self-dials the active slot's own route DN and drops it immediately, deliberately
  outside `_mutex` because a real provider's `makeCall()`/`dropCall()` are blocking TLS
  round trips that must never stall SIP packet handling for the whole device. It refuses
  any slot that is not the currently-active one, since only that slot has a live,
  boot-selected anchor client.

Then **Dial Plan, Groups, Call Log and SIP Trace became top-bar buttons** — alongside
Refresh, WiFi, Admin, Interconnect and Help, with F2/F3/F4/F8 joining the existing
F1/F5/F9 and Escape closing all nine — leaving `<main>` as just the patch bay. The three
existing modules moved into overlays with every control id preserved, so their render
functions kept working untouched.

**The dial-plan editor is new, and its absence was not cosmetic.** The dial plan is the
only route to an outside trunk, so a box with no rule `404`s every outside number
without ever reaching the anchor — and until now the only way to see or fix that was to
POST to the API by hand. The editor lists the rules from `/api/status`, renders each as
`9XXXXXXXXXX → trunk → strip 1, prepend 1` with a Delete button, hides the strip field
for non-trunk actions, and refuses an empty target on a non-trunk rule with an explicit
message rather than submitting it — an empty target used to be the delete signal, so
saving one would have destroyed the rule being edited.

The page is split across 8 `PD_HTML_N[]` raw-string parts (~12 KB each). This is not
arbitrary: a single string literal past ~16 KB breaks the host build on MSVC, and adding
the dial-plan modal pushed `PD_HTML_1` to 17,233 bytes. Reassembly was verified
byte-identical.

### Fixed — an outbound call was reaped after 20 s, and answered 503 when it was

Confirmed on the bench board with a real Yealink and a real trunk, not reasoned about.
Dialling `9`+NXXNXXXXXX placed a real call and the callee's mobile rang — and about 19 s
in, the log said `anchor call reaped (no answer)` and the handset got a final response,
a few seconds before carrier voicemail would have picked up.

`originateAnchorCall` armed the ring timer with `pbx::kNoAnswerTimeout`, which is
documented as how long an unanswered leg rings before the no-answer action fires (a CFNA
forward, or advancing to the next hunt-group member) — an **internal-extension** number.
The anchor path inherited it when the zombie reaper landed and nothing ever argued 20 s
was a correct PSTN window. It is not: a US mobile rings 25-30 s before voicemail
answers, and the clock starts when the *handset's* INVITE is accepted, before the ~1 s
`makeCall` round trip and before the provider has begun dialling. A new
`ANCHOR_NO_ANSWER_TIMEOUT` of **60 s** is used at the one outbound-anchor arm site; the
other three arm sites — CFNA, the inbound-anchor fork and the hunt-group ring — keep
`kNoAnswerTimeout` deliberately.

It stays finite on purpose. The anchor's reconcile watchdog only tears down legs that
have *vanished* from the DN, so the SIP ring timer is the sole backstop for a leg the
provider still lists but that never progresses, and an unbounded window would pin the
single `POCKETDIAL_MAX_ANCHOR_CALLS` slot. It is not re-armed on provider progress
either: the status reported is our own control leg's, which sits at "Dialing" right
through far-end alerting, so there is no alerting signal to key off.

Separately, the reap answered **503 Service Unavailable**, which is what the Yealink
displayed. A far end that rang and was not picked up is a no-answer, not a server fault.
On this very path 503 already means something else — capacity refusal — while the
sibling no-answer teardown (hunt-group exhaustion) already answers 480. A UAS 503 also
invites upstream failover and blacklisting behaviour that a plain no-answer must never
trigger. It is now **480 Temporarily Unavailable**; the true-failure 503s are untouched.

### Fixed — the register-beep transaction storm (#148)

Carried as a known issue by both v1.4.0 and v1.4.1, and now closed. On a fresh boot the
T29 re-registered, never answered the beep INVITE, and one Call-ID produced 23
`[tx] Timer B expired` lines plus `[tx] pool exhausted` within about 60 s. Both halves
are fixed: duplicate INVITEs for a Call-ID/branch are deduped rather than each claiming
a slot, and the slot is actually freed on teardown. `TransactionLayer::freeForCallId()`
had exactly one caller, `endCall()` — and a beep dialog has no `Session`, living instead
in `RegisterBeeper`'s own Call-ID-keyed table, so it never reached `endCall` and every
beep teardown dropped the dialog while its transaction kept retransmitting for the rest
of its 32 s Timer B window. A new `PbxEnv::freeTransactionsForCallId` routes all four
`RegisterBeeper` terminal paths through a `releaseDialog()` that frees the transaction
before clearing the slot — order matters, since clearing first loses the Call-ID.

New `tests/TransactionLayer_test.cpp` covers the dedupe, that distinct branches still
get their own slots, the RFC retransmit schedule and provisional stop, and that
`freeForCallId` silences a slot at once. Two new `RegisterBeeper` tests assert the
transaction is released on both the abandoned and completed paths, and that it is **not**
released during the RFC 3261 §9.1 CANCEL race window (#98), where a raced 200 OK must
still match. The dedupe test was verified to fail against the unfixed code. 414 host
tests pass.

### Fixed — factory reset wipes the call-history ring too

Found live: a board's dashboard showed an old call from a prior deployment, surviving an
app-only reflash because the CDR lives in its own NVS namespace (`cdrlog`) — untouched
by the factory-reset path that had just been fixed to wipe `TelephonyApiConfig` and
`DidMapping`. Same root cause, third namespace. Caller/callee history is at least as
sensitive as the carrier credentials that fix already covered. `CdrRing::clearAll()` and
`RequestsHandler::clearAllCallHistory()` are now wired into `sendApiFactoryReset()`
alongside the existing wipes.

### Fixed — factory reset reported failure after wiping the device (#189)

Third defect in the same handler, and the one an operator would actually be hurt by.

Every destructive call in `sendApiFactoryReset()` is unconditional, but the `200` and the
reboot were inside `#if defined(POCKETDIAL_HAS_WIFI)` — which `eth` and `lan8720` do not
define, because those boards have no radio. So on the firmwares that ship on real
hardware, `confirm=ERASE` cleared the admin credential, the DTMF PIN, `DeviceConfig`, the
carrier OAuth client_id/client_secret, the DID table and the CDR ring, and then answered
`501 {"error":"factory reset not available on desktop"}` without rebooting.

An error naming a platform the operator is not on reads as "nothing happened" — and the
response is the only signal they get, since `clearCredential()` destroys the very session
that made the request. There is no authenticated follow-up call to check with.

Only the Wi-Fi NVS key erase is genuinely radio-specific and stays gated on the transport
(`nvs.h` is included under that flag alone). The reboot moves to `ESP_PLATFORM`, matching
the rule the OTA path in the same file already followed: a restart exists on every ESP
transport, not just the radio ones. Every build now answers `200`, because every build
completed the work; only the follow-up instruction differs.

`tests/http/test_api.sh` gains three cases — the host build's behaviour changes from
`501` to `200`, which is the one part of this a host test can observe.

Two documents also claimed the boot gate does not re-engage after a reset, because a
`provisioned` latch in NVS is never erased. That was never true: `provisioned` is an
in-RAM flag, and the gate reads `storage`/`admin_pw_hash`, which is exactly the key the
reset erases. A reset board does come back unprovisioned.

### Hardware — the first real-handset evidence in this project

Worth recording separately, because it changes what the rest of the test suite means.

A Yealink T29 is registered to the bench board, and **outbound PSTN is verified end to
end**: one call rang through to carrier voicemail, answered at 21.2 s — which is what
made the 20 s reap above visible, and what the 60 s window exists to survive — and one
call was answered by a person, **with two-way audio**.

Everything else in the suite remains host-only: gtest, or `pjsua`/SIPp driven against
the **desktop** binary over loopback. **On-device RTP has never been exercised by any
test** — the host build's `RtpSender`/`RtpReceiver` are stubs (a Linux-desktop socket
path aside), so every green media test exercises a stub rather than the ESP32 path.
**OTA has never been executed anywhere**, on any board, in any release.

### Documentation

`docs/API.md` is corrected to the model above: the always-open listener, the
username/password credential and its forced setup, the removal of the unprovisioned
bypass, full sections for the previously-undocumented `/api/telephony-config` and
`/api/did-mapping` routes, and the dial-plan rule table's real upsert/delete semantics.
Any document that still describes an admin **PIN** login, a dark HTTP plane, or a
`*4887` recovery code is stale and describes firmware that no longer exists.

### Known issues

- **#146** — the `Via` `received=` parameter is stamped with the server's own IP instead
  of the sender's, contrary to RFC 3261 §18.2.1. Confirmed on hardware. Unchanged.
- **The shipped registrar default is still `open`.** SIP digest auth (RFC 2617) is
  implemented and Learn mode's TOFU + ARP MAC-lock works, but a fresh board accepts any
  `REGISTER` and any `INVITE` until an operator changes `reg_mode`. Nothing in this
  release changes that default.
- **Zero-touch provisioning is inert on a default board.** `GET /config/<mac>.cfg` is
  implemented, but it only serves a MAC in the Learn-mode adopted-device registry, and
  `open` mode never records one — so on a fresh board it is a structural 404 for every
  MAC. The Yealink key set has still never been confirmed against a physical handset.


## [v1.4.1] — 2026-09-07

A single-bug patch release. It makes the flash-time registrar mode actually
work — the one thing v1.4.0 claimed and did not deliver.

Nothing else changes. Upgrading is an OTA or a reflash.

### Fixed — flash-time registrar mode reached the wrong NVS namespace (#151)

`DeviceConfig::applyFlashSeed()` wrote the `cfgseed` record's `regMode` to NVS
namespace `storage`, alongside every other field of the seed.
`Registrar::loadMode()` reads `reg_mode` from `pbxpersist::kNvsNamespace`, which
is `pbxcfg`. The value was written, committed, and never read.

So the `regMode` field did nothing, on every release that shipped it. That
matters more than a typo normally would, because `docs/LEARN_MODE.md`,
`docs/INCIDENT_PLAYBOOK.md` and `DeviceConfig.hpp` all described it as *the only*
way to put a **headless** `esp32s3-eth` / `esp32s3-wifi` board into `learn` or
`secure` before first boot — and once such a board is provisioned its HTTP admin
plane is dark, leaving only the unreliable `*4887` star-code. A headless board
was effectively stuck in the `open` default with no supported way out.

It stayed invisible through v1.3.0 because a second, unrelated bug sat in front
of it: the release workflow's byte-swapped partition magic (fixed in `e559368`,
shipped in v1.4.0) meant `cfgseed_offset` was never emitted, so the browser
flasher never wrote a seed at all and this line never got the chance to fail.
Fixing the outer bug is what exposed the inner one — v1.4.0 is the release that
made the failure reachable, not the release that introduced it.

**The fix** is to open a second NVS handle on `pbxcfg` for this one key. The
namespace literal still has to be duplicated — `DeviceConfig` is compiled into
the host test suite and into the pure-Ethernet transports, and must not pull in
any `src/SIP` header — so `DeviceConfig::kRegistrarNvsNamespace` is now a named
header constant, and `tests/DeviceConfig_test.cpp` `static_assert`s it against
`pbxpersist::kNvsNamespace`. Renaming either one now fails the build.

That guard is a compile-time assertion rather than a test because there is
nothing to run: `applyFlashSeed()` is inside `#if defined(ESP_PLATFORM)` and
compiles out entirely on the host build, which is exactly why two releases went
out with a silently inert feature and a green test suite. Verified in both
directions — the assertion fires on a deliberately mismatched constant, and the
322-test host suite passes with it restored.

### How the diagnosis was pinned down

On a LilyGO T-ETH-Elite S3 running the **published v1.4.0** `esp32s3-eth`
artifact, flash-erased, with a valid `cfgseed` record at `0xFFF000` carrying only
`kSeedHasRegMode` and `regMode = 1`:

- Reading NVS back off the chip showed `reg_mode = 1` and `cfgseed_gen`
  committed — under `storage`. So the seed was found, validated and applied; the
  value simply landed somewhere the registrar does not look.
- The registrar stayed in `open`: three REGISTERs produced `New Client: 1001`
  and **neither** of the two lines `admitLearn()` emits unconditionally on a
  first REGISTER from an unknown MAC.
- Writing `reg_mode` under `pbxcfg` instead — same board, same binary, nothing
  else changed — produced `Learn: adopted device e45f01654516 as ext 1001` with
  zero ARP misses.

One board, one binary, one variable, which isolates the fault to the namespace
and nothing else. That evidence was gathered by writing NVS directly, so it
proves the diagnosis rather than this release's own seed path.

### End-to-end, on this release's artifact

Confirmed separately against the published v1.4.1 `esp32s3-eth` binary (sha256
matching `SHA256SUMS`), flash-erased, driven by a `cfgseed` record alone with no
direct NVS write:

```
reg_mode = 1  in namespace 'pbxcfg' (index 2)
Learn: adopted device e45f01654516 as ext 1001
```

Same board, same seed bytes, same offset, on v1.4.0: `New Client: 1001` and no
Learn line at all. So v1.4.1 is the first release on which the documented
headless route — pick a registrar mode in the flasher, flash, boot — does
anything at all. Full run on #151.

### Known issues

Unchanged from v1.4.0: **#146** (`Via` `received=` carries the server's own IP,
RFC 3261 §18.2.1) and **#148** (register-beep INVITE retransmission flood
exhausting the message pool — **fixed on main, in no published release**).


## [v1.4.0] — 2026-09-06

Two days after v1.3.0, and small. It is a minor bump rather than a patch because
two of the changes alter what the firmware does rather than how it is built: a
call transfer can no longer be forged from off-path, and zero-touch provisioning
works on Ethernet builds for the first time. A supported build path is also
removed.

Nothing here changes configuration or breaks an existing deployment. Upgrading is
an OTA or a reflash.

### Security — REFER is gated on the dialog's own source IPs (#133)

`onRefer` authenticated nothing about *where* a REFER came from. Any host that
could reach the signalling port and learn or guess a live Call-ID could transfer
a call in progress to a destination of its choosing: the victim's dialog would be
re-INVITEd away with no participation from either real party. `Replaces` widened
it — a REFER could name a second dialog the sender was not a leg of, splicing two
unrelated calls together.

Both paths now check the request's source against the addresses of the dialog's
own legs (`isDialogSourceAuthorized`) and answer **403 Forbidden** when it is not
one of them. The referred dialog and the `Replaces` target are checked
separately, so neither can be used to reach the other. In-dialog transfer from a
real leg is unaffected. Three regression tests cover the forged, legitimate and
`Replaces`-crossing cases (`tests/ReferSourceAuth_test.cpp`).

### Fixed — zero-touch provisioning on Ethernet builds (#103)

`ArpLookup::pdLookupMac()` probed `WIFI_AP_DEF` and `WIFI_STA_DEF` and nothing
else. An Ethernet build has no Wi-Fi netif at all, so both handles came back null
and every lookup returned "not found" — which `admitLearn()` reads as a benign
first-packet cache miss, deferring the MAC-lock to the next REGISTER, which could
never resolve either. On the whole `SIP_TRANSPORT=eth` family the device registry
therefore stayed permanently empty and `GET /config/<mac>.cfg` returned 404 for
every phone, silently, because the miss path is a non-error by design. `ETH_DEF`
is now in the probe chain.

The long-standing hypothesis for this bug was a MAC *format* mismatch between the
registry key and the URL. That was wrong — both sides go through
`ArpLookup::toHex12()` and do agree — but the feature was still completely
broken, because there was never a key to compare.

Verified on a LilyGO T-ETH-Elite S3 (W5500), flash-erased between runs: before
the fix, `ARP miss, deferring MAC-lock` on 4 of 4 REGISTERs with an empty
registry; after it, `Learn: adopted device e45f01654516 as ext 1001` and zero
misses. The adopted key is exactly the 12-lowercase-hex form the URL parser
yields. **The `GET /config/<mac>.cfg` 200 was not itself re-observed** — a
provisioned board closes its HTTP plane by design, and the DTMF star-code that
reopens it would not fire from the test client — so that last hop is inferred
from the key matching, not measured. Full write-up in #147.

### Fixed — the browser flasher can seed flash-time configuration

The release workflow's manifest generator walks the partition table looking for
the `cfgseed` entry, and compared each record's magic against `0xAA50`. The
on-disk bytes are `AA 50`, which read back through a little-endian `uint16` is
`0x50AA` — so the check failed on entry 0, the walk stopped immediately, and
`cfgseed_offset` was silently omitted from every manifest ever generated. The
flasher reads a missing `cfgseed_offset` as "this release predates flash-time
configuration" and warns, so Wi-Fi mode, AP security and passphrase could never
be written at flash time despite the partition existing in `partitions.csv`.

Fixed in `e559368`, which also backfilled the already-published v1.3.0 manifest
rather than re-cutting that tag — the images were always fine, only the field was
missing. v1.4.0 is the first release whose manifest carries it natively.

Verified on hardware after the tag was cut: the seed is written, found and applied
— an NVS dump off a board shows `cfgseed_gen` and the seeded values committed. The
Wi-Fi mode, AP security and passphrase fields work. **The registrar-mode field of
the same panel does not**, for an unrelated second reason found by that same test:
it is written to NVS namespace `storage` while the registrar reads `pbxcfg`
(#151, **fixed in v1.4.1**). That had never worked on any release, and was not a
v1.4.0 regression —
v1.4.0 is simply the first release in which the seed reaches the firmware at all,
which is what made it visible.

### Removed — the Arduino sketch path (#144)

`sketches/` is gone. It was a second, parallel build of the same firmware that
nothing verified, and it had been broken since 2026-06-01: `4e35566` changed
`HttpServer`'s third constructor parameter from a reference to a pointer, the
sketches were last touched three days earlier, and all five stopped compiling.
Nobody noticed for three months.

This is a deliberate removal, not a cleanup of something that could never work —
with arduino-cli 1.5.2 and ESP32 Arduino Core 3.3.11, a one-character fix gets
three of the five building for `esp32:esp32:esp32s3`. The other two need a
third-party display library and an unresolved LAN8720 Ethernet issue (#41, #143).
Keeping them meant carrying a second toolchain in CI and in the contributor docs
for a path nothing shipped from.

ESP-IDF is now the only supported toolchain. `docs/CONTRIBUTING.md` loses its two
Arduino sections and its ESP-IDF prerequisite is corrected: it claimed "v5.1 or
newer", but `fb29f14` made `main/CMakeLists.txt` a hard configure-time
`FATAL_ERROR` below **v6.0**, so the documented toolchain could not build the
project at all.

### Documentation

- `docs/SCALING.md` gains the first concurrency measurement taken on firmware
  with two genuinely distinct source hosts rather than on the host harness: 50
  offered calls, exactly 32 accepted and 18 rejected with 503, `packetsDropped:
  0`, no watchdog. It confirms the call pool is **global, not per-source** (#79).
- The `TROUBLESHOOTING.md` and `INCIDENT_PLAYBOOK.md` banners described the three
  opt-in hardening controls as "newer than the last release" and on "current
  `main`". They shipped in v1.3.0; the banners now say so. Both still note
  correctly that a device flashed from `v1.3.0-pre-alpha` has none of them.

### Also

Two test-only fixes for flakes that were real but harness-side, both found by
sampling as independent processes under CPU oversubscription rather than with
`--gtest_repeat` (which under-samples anything seeded once per process):
`ConferenceRoom`/`MediaBridge` now stop the RTP pacer before a test drains a leg
by hand — 29 failures in 400 runs before, 0 after (#135) — and
`InviteAdmission_test` matches the `SIP/2.0 403` status line rather than a bare
`403` anywhere in the message, 3 in 400 before, 0 after (#136).

### Known issues

Two confirmed bugs are open against this release and are **not** fixed in it:

- **#146** — the `Via` `received=` parameter is stamped with the server's own IP
  instead of the sender's, contrary to RFC 3261 §18.2.1. Confirmed on hardware.
  It misdirects responses to a sender behind NAT.
- **#148** (**fixed on main, in no published release**) — the register-beep INVITE
  retransmits roughly 55 times in 8 seconds
  and continues after its own CANCEL. A SIP endpoint that does not answer it (a
  486 suffices) will drive the board's message pool to exhaustion, after which
  unrelated signalling is dropped silently. This mostly bites synthetic test
  clients, but any phone that ignores the beep will trigger it.
- **#151** (**fixed in v1.4.1**) — the `cfgseed` `regMode` field is written to NVS
  namespace `storage` while `Registrar::loadMode()` reads `pbxcfg`, so flash-time
  registrar mode had never worked on any release. `docs/LEARN_MODE.md`, `docs/INCIDENT_PLAYBOOK.md`
  and `DeviceConfig.hpp` all describe it as the only way to move a **headless**
  board off `open` before first boot; it is not, and a provisioned board's HTTP
  plane is dark, so there is currently no reliable route. The dashboard and
  `POST /api/registrar` paths are unaffected — they use `pbxcfg` on both sides.


## [v1.3.0] — 2026-09-04

The first release since v1.2.0 (June 2026), 134 commits back. v1.2.0
was a SIP registrar and proxy; v1.3.0 is a small PBX with an admin plane you can
lock down.

Nothing here breaks an existing deployment: the SSH/TUI admin surface removed
below never shipped in a release, and every hardening feature is opt-in and off
by default. Upgrading is an OTA or a reflash.

### Highlights

**It behaves like a PBX now.** Blind *and* attended transfer (REFER with
`Replaces`, RFC 3891 — consult, then splice the two parties and drop out); call
park and retrieve on orbits 700–709; call pickup, group (`*8`) and directed
(`**<ext>`); ring/hunt groups on a bounded pattern→action dial plan; per-extension
call-forward (always, on busy, on no-answer) and do-not-disturb; paging zones
980–989; a conference mixer and a real Linux media path on extension 440.

**Security is opt-in but it exists.** SIP digest auth (RFC 2617) with a Learn
mode that adopts an existing phone fleet; WPA2 on the SoftAP, which encrypts the
dashboard, SIP signalling *and* call audio together; an admin PIN with
server-side sessions and CSRF tokens on every mutating endpoint; a dark-by-default
HTTP admin plane that does not even listen on a provisioned device; an SDP
admission gate that structurally checks every body before a decoder sees it. The
second admin plane (SSH/TUI) was deleted rather than hardened.

**Operability.** Zero-touch phone provisioning via `GET /config/<mac>.cfg`; a
live SIP tracer in the dashboard and at `GET /api/trace`; a Wireshark-readable
capture at `GET /api/pcap`; flash-time configuration written by the browser
flasher into a `cfgseed` partition, so Wi-Fi mode, AP security and the
passphrase are set without rebuilding.

**Browser flasher.** Install any variant over USB from
https://glomargadaffi.github.io/pocket-dial/flasher/ with no toolchain. Firmware
for this release is served from the project site itself rather than from the
Release's assets — a browser cannot fetch those, because GitHub serves release
downloads without CORS headers (#138).

### Fixed

Beyond the entry below, this release carries a long tail of SIP correctness and
robustness work: pool-exhaustion paths that abandoned half-mutated calls, a
CANCEL that claimed success after failing to build, hold/resume 200 OKs that
never reached the peer leg, a doubled Call-ID on the park-retrieve re-INVITE, a
BLF regression in `forEachSessionInvolving`, CR/LF injection into provisioning
`.cfg` files, RTP SSRC/sequence seeding moved off `std::rand`, and an lwIP UDP
mailbox too small to absorb signalling bursts. See the git log between `v1.2.0`
and this tag for the full list.

### Added — Attended transfer via REFER + Replaces (#131)

- Ported drawbridge's `e594914` ("Phase C-2 — attended transfer via REFER +
  Replaces") to pocket-dial. A transferor (A) with two active P2P calls — A-B
  and a consult call A-C — sends REFER on the A-B dialog with a `Replaces`
  URI parameter naming the A-C dialog (RFC 3891). `RequestsHandler::onRefer`
  now recognizes this and splices B and C together directly: cross
  re-INVITEs carry each leg's SDP to the other, A is BYE'd out of both
  dialogs, and the two sessions are linked as a transfer bridge
  (`Session::isTransferBridge`/`getPeerCallID`) so a later BYE from either B
  or C relays to the other instead of reaching the now-departed A
  (`RequestsHandler::onBye`'s new transfer-bridge branch, which must run
  before the pre-existing Issue #68/#127 generic peerCallID branch). The
  splice's own re-INVITE 200 OKs are intercepted and ACKed directly
  (`RequestsHandler::handleTransferOk`, called from `onOk` before the
  generic session lookup) so they never reach the generic relay, which would
  otherwise forward them toward A.

  Most of the supporting `Session` scaffolding this needed
  (`_remoteSdp`/`getRemoteSdp`/`setRemoteSdp`, `_isTransferBridge`) was
  already present as unused fields from an earlier partial port — this PR
  wires it up rather than adding it from scratch. `onOk`'s SDP/dialog-header
  capture for it turned out to already be in place too.

  A can be either side (caller or callee) of either dialog — the
  "receptionist" case (B calls A, A consults C) is just as valid as A
  originating both calls. The splice derives which side A is on
  independently per dialog and picks the other party's client, SDP (via
  `getInviteMessage()->getBody()` when A is the callee, since
  `getRemoteSdp()` is always "the callee's SDP" and would otherwise return
  A's own answer), and dialog-header From/To orientation accordingly, rather
  than assuming A is always the caller. `Session` gained
  `wasTransferorSrc()`/`setWasTransferorSrc()` (mirroring the existing
  `isParkUac()` pattern) so `onBye`'s transfer-bridge relay can find the
  correct surviving peer and header orientation for a session whose original
  A-orientation is otherwise unrecoverable by the time a later BYE arrives.

  `siphdr::urlDecode` (new, `SipHeaderUtil.hpp`) percent-decodes the
  `Replaces=` URI parameter before parsing its `;`-separated pieces, so a
  `%3B`-encoded separator inside the SIP-URI-embedded value doesn't get cut
  at the wrong point. A `Replaces` value that decodes to something
  containing a control character (e.g. a `%0D%0A`-smuggled CRLF) is treated
  as malformed and declined (603) rather than silently falling through to a
  blind transfer.

  New coverage in `tests/AttendedTransfer_test.cpp`: the splice's accepted
  response and crossed re-INVITEs, the re-INVITE-OK-intercepted-not-relayed
  behavior, post-splice BYE relay, an unresolvable `Replaces` declining
  cleanly, and two orientation regressions found by adversarial review
  before this PR — B-calls-A-then-A-consults-C, and both legs A-as-callee —
  which the initial port got backwards (it unconditionally assumed A was the
  caller of both dialogs). `.smoke/office_smoke.py`'s "Attended transfer"
  scenario (A-as-caller only) also passes, 11/11 overall.

  Known gaps, not fixed here: #133 (`onRefer` has no source-authorization
  check, same as blind transfer); the splice's SDP/dialog-header presence
  check can't detect a leg that's on HOLD at consult time (documented
  in-code, not exercised by any test); RFC 3891 §3's `from-tag`/`to-tag`
  MUST-match against the `Replaces` target dialog is not enforced (the bare
  Call-ID is matched, tags are parsed by office_smoke's own construction but
  not validated) — neither drawbridge's source nor this port do this
  matching; worth its own follow-up if it matters in practice.

### Fixed — ConferenceRoom test: RtpSender's real Linux pacer thread raced synchronous playout-buffer assertions (#135)

- Found while adding the above: `ConferenceRoom.AnchorModeIsUnchangedByTheBusRewiring`
  intermittently failed depending on the test binary's link layout, unrelated to
  its own test bodies ever running. Root cause: `RtpSender.cpp`'s Linux-desktop
  branch (`#elif defined(__linux__)`, Issue #82) is not the inert host stub the
  test file's own header comment claimed — on this build (WSL defines
  `__linux__`) it spawns a real `std::thread` the instant `startBridge()`
  succeeds, racing the test's own direct calls into the same buffer. Fixed by
  stopping that thread right after `startBridge()` succeeds, before driving the
  buffer by hand. See `tests/ConferenceRoom_test.cpp` and issue #135 for the full
  mechanism.

## Unreleased (fix/issue-128-blind-transfer-teardown) - 2026-09-04

### Fixed — Blind transfer: the dropped party never received a BYE (#128)

- `RequestsHandler::onRefer`'s blind-transfer path already tore down the
  transferor's original session via `endCall()` before driving the fresh
  INVITE to the transfer target (drawbridge's earlier fix for the reverse
  ordering bug, already present here) — but `endCall()` is pure local
  bookkeeping (session/pool/CDR release); it never puts a packet on the wire.
  The OTHER party on that dialog (the one the transfer drops, not the
  transferor) was never told the call ended, so its phone sat on a call the
  server itself already considered over.

  Fixed by sending that party an explicit BYE before `endCall()` erases the
  session. REFER is itself an in-dialog request on the SAME dialog it's
  transferring out of, so `data->getFrom()`/`getTo()` already carry that
  dialog's tags exactly — no dependency on `Session::getDialogFrom()`/
  `getDialogTo()`, which `armSessionTimer()` only populates when RFC 4028
  Session-Expires was negotiated. Works regardless of which side of the
  original call sent the REFER (the transferor can be either the original
  caller or callee) by comparing both `Session::getSrc()`/`getDest()` against
  the transferor's own number and BYE-ing whichever one isn't it.

  New coverage in `tests/BlindTransfer_test.cpp` drives a full call through
  connect and blind transfer, and asserts the dropped party receives a BYE
  for the correct Call-ID (not just that the transfer target gets an
  INVITE) — the host-testable regression, since
  `.smoke/office_smoke.py`'s "Blind transfer" scenario (which originally
  caught this) isn't wired into CI.

## Unreleased (fix/issue-127-park-retrieve-bye-relay) - 2026-09-04

### Fixed — Park retrieve: BYE from either leg was never relayed to the other (#127)

- `ParkOrbit::onInvite` created both the parked leg's session (at park time) and
  the retriever's session (at retrieve time) without ever calling
  `Session::setDialogHeaders()` — so `RequestsHandler::onBye`'s peerCallID
  cross-dialog relay branch (the same one Issue #68 call pickup uses) always
  found an empty `getDialogFrom()`/`getDialogTo()` and silently skipped
  building the peer-addressed BYE. `peerCallID` itself was set correctly on
  both legs; only the dialog-header half of the contract was missing, which is
  why the retriever's own BYE was still answered 200 OK (its own dialog ended
  fine) while the formerly-parked party's phone was left hanging on a dead
  call.

  Fixed by capturing each leg's own dialog `From`/`To` (with the server's own
  to-tag) at the point each session is created, mirroring the convention
  `CallPickup::complete()` already established. The ring-back-timeout leg
  (`Session::isParkUac()`) has the same gap but is a server-UAC-role dialog
  needing swapped header capture — out of scope here; the `onBye` comment
  where the relay lives now says so explicitly.

  New coverage in `tests/ParkOrbit_test.cpp` pins that both legs' dialog
  headers and `peerCallID` are set after a retrieve — the host-testable
  regression, since `.smoke/office_smoke.py`'s "Call park + retrieve" scenario
  (which originally caught this) isn't wired into CI.

## Unreleased (on main, in no published release) - 2026-09-03

### Security — SoftAP WPA2, CSRF tokens, and a centralised admin gate

Context: this started as an evaluation of a proposal to port
ESP32_AdBlocker_Reborn's mandatory-HTTPS web GUI onto pocket-dial. That proposal was
declined on its headline item — `docs/THREAT_MODEL.md` §6 and
`docs/FEATURE_ROADMAP.md` already record self-signed HTTPS as *not* the primary control
for a LAN appliance, and it would have protected only the dashboard while leaving SIP
and RTP in the clear. The link-layer and app-layer fixes it displaced are what landed
instead.

**SoftAP WPA2 (docs/THREAT_MODEL.md §6, FEATURE_ROADMAP P0)**

- `WIFI_AUTH_WPA2_PSK` on the standalone access point, gated by the new NVS flag
  `ap_secure` and **defaulting to off**. Turning it on forces every already-associated
  phone to be re-paired, so it is an explicit operator action, never something a
  firmware update does to a live fleet. Encrypts the dashboard, SIP signalling and RTP
  media at once — the confidentiality gap I-1/I-2 that no amount of dashboard TLS
  would have closed.
- Per-device passphrase generated from `esp_random()` on first access and stored in NVS
  (`ap_psk`): 20 characters over a 30-symbol alphabet with no ambiguous glyphs
  (no `0`/`O`, `1`/`I`/`L`, `U`), because it gets read off a small LCD or a serial log
  and retyped into a desk phone. Drawn by rejection sampling, not `byte % 30`.
- **Fixes a real bug**: the captive-portal onboarding AP was already `WPA_WPA2_PSK` but
  used `#define ONBOARDING_PASS "12345678"` — identical on every unit and published in
  this repo, so anyone who captured the 4-way handshake could derive the PTK. Its
  encryption was decorative.
- `main/esp_main.cpp` previously copied a passphrase into the AP config and then
  discarded it by forcing `WIFI_AUTH_OPEN`; the field was dead code.
- New `GET`/`POST /api/ap-security` to report, toggle and rotate it, plus a dashboard
  panel. The radio is deliberately not restarted on save — that would drop the client
  reading the passphrase and tear down live calls; the change lands at the next AP
  bringup.

**Flash-time configuration (new `cfgseed` partition)**

- `partitions.csv` gains `cfgseed` (data, subtype 0x41, 4 KB at `0xFFF000`), carved out
  of the reserved `prompts` region. `nvs`, `otadata`, `phy_init`, `ota_0` and `ota_1`
  keep their exact offsets, per that file's own contract.
- The browser flasher can write a 256-byte fixed-layout record (Wi-Fi mode, AP security,
  passphrase, optional upstream credentials, CRC-32) which the firmware applies to NVS
  once on boot, keyed by a generation counter so a reboot never re-clobbers later
  changes. Opt-in per flash and defaulting to "leave the device alone", so a plain
  reflash cannot silently reset a configured board.
- A seed blob rather than an NVS image on purpose: generating a valid NVS partition in
  JavaScript means reimplementing page headers, entry-state bitmaps and CRCs, and
  writing it at `0x9000` would destroy the saved Wi-Fi credentials and admin PIN.
- **Absent partition is the normal case, not an error** — an OTA update does not rewrite
  the partition table, so this firmware runs on boards flashed before `cfgseed` existed,
  and on the 4 MB constrained layout. `applyFlashSeed()` returns false silently.

**Centralised admin gate — closes two holes**

- The same-origin/auth block was copy-pasted at roughly fifteen routes. Two had been
  missed: `POST /api/configuring` had **no gate at all** (waived in a comment as
  "harmless" despite mutating device state), and `/api/pcap`, `/api/trace` and
  `/api/diagnostics/pcap` had **no same-origin check** while serving raw SIP message
  bytes including `Authorization` digests. All routes now go through one
  `HttpServer::requireAdmin()`.

**Per-session CSRF tokens (T-2)**

- 128-bit token minted with each session, rendered into the dashboard document and
  returned in the login response — never set as a cookie, since the browser would attach
  a cookie to a same-site request on its own. Required in an `X-CSRF` header on every
  mutating request.
- The same-origin check still admits a request with no `Origin` header (that is what
  lets `curl`, native clients and `tests/http/test_api.sh` work), so the token is what
  actually closes the CSRF gap on a provisioned device.
- Exempt, with reasons documented in `docs/API.md` §2.1: login (no session yet), logout
  (a forced logout is a nuisance, not a compromise, and `SameSite=Strict` already blocks
  it), and anything while unprovisioned (no session exists; demanding one would make the
  device unclaimable and break onboarding).
- **Breaking change for scripts**: `docs/OTA.md`'s curl workflow now captures the token
  from the login response and sends it on the upload and reboot steps. A script written
  against earlier firmware gets `403` on a provisioned device.

**Brute-force lockout (§5.2, retires D-3)**

- `verifyPin` used to zero the failure counter the moment the lockout engaged, handing
  the attacker a fresh window of five after every cooldown — a steady ~5 guesses/minute
  indefinitely, which walks a 4-digit PIN in about a day and a half. The trip count now
  survives and each successive lockout doubles (capped at 16 minutes). Only a correct
  PIN clears it.
- Failures are counted per client address in a bounded, least-recently-seen-evicted
  table, so one guessing client can no longer lock the legitimate admin out of new
  logins.
- Per-client accounting *alone* would have been a regression — source addresses are
  spoofable, so rotating them would buy a fresh bucket and a fresh escalation ladder
  every five guesses. An aggregate backstop (20 failures across all clients, same
  doubling) bounds the total guess rate regardless of how many identities are invented,
  and sits far enough above ordinary typos not to reintroduce the self-DoS.

**Security response headers**

- Emitted centrally in `sendResponseWithHeader`, so no endpoint can omit them: CSP
  (`default-src 'none'` plus the inline script/style the single-page dashboard needs),
  `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`,
  `Referrer-Policy: same-origin`.
- Deliberately **no HSTS**: the dashboard is plain HTTP on a LAN appliance, and pinning
  it would make the device permanently unreachable over `http://` with no user override.

**SIP registrar mode + extension onboarding — making digest auth reachable**

The larger finding behind this section: **SIP digest authentication was fully implemented,
fully tested, and completely unreachable on a shipped device.** `SipDigest`,
`SipSecretStore`, the `Registrar::Mode` state machine and its NVS persistence are all on
`main`, and `Registrar::loadMode()` runs at boot — but `RequestsHandler::setRegistrarMode()`
was called from **unit tests only**. No HTTP endpoint, no dashboard control, nothing in
production ever wrote `reg_mode`. Every device came up in the compiled-in `open` default
(any phone may register as any extension, with no credential) and stayed there.
`POCKETDIAL_OPEN_REGISTRAR` is `#define`d unconditionally at `RequestsHandler.hpp:5`, so
the `-UPOCKETDIAL_OPEN_REGISTRAR` build-flag workaround that had been documented could not
work either. `docs/LEARN_MODE.md` described selecting the mode from a "Security screen"
that did not exist.

- **`GET /api/registrar`** — the admission mode plus the adopted-extension roster
  (`{attached, mode, devices:[{mac, extension, state, online}]}`). `attached:false` when
  the SIP engine is not bound yet, which is a normal transient state on an unprovisioned
  device rather than an error.
- **`POST /api/registrar`** — sets `open` / `learn` / `secure`. Switching to `secure` while
  **no** extension is yet secured is refused with `409` unless `confirm=LOCKOUT`: that
  transition digest-challenges every `REGISTER` at once, so on a device that has never run
  Learn mode it rejects every phone and leaves the operator no working handset to notice
  with. Mirrors the existing `confirm=ERASE` convention on `/api/factory-reset`.
- **`POST /api/registrar/device`** — `action=secure|forget`, `target=<12-hex MAC or
  extension>`. `secure` promotes a first-seen device to MAC-locked + digest-enforced;
  `forget` drops the record so a later `REGISTER` re-adopts it, which is how an extension
  is re-homed to different hardware.
- **Dashboard panel** *Extension Registration & Onboarding*: the mode selector and the
  roster with per-device Secure / Forget. Roster cells are written with `textContent` —
  the MAC and extension arrive off the wire from a phone and are never interpolated as HTML.
- **Flash-time `regMode`** in the `cfgseed` record (byte 13, flag bit 5), settable from the
  browser flasher. This is the only way to set the mode on a headless board before first
  boot. `kSeedVersion` was deliberately **not** bumped: each field is gated by its own flag
  and readers ignore unknown flags, so old firmware skips bit 5 and applies the rest, and
  new firmware reading an old record leaves `reg_mode` alone. Bumping the version would
  instead have made older firmware reject the whole record.

Honest scope: this makes the S-3/D-2 registrar gap **closable in the field**, not closed.
The shipped default is still `open`, so it protects deployments that actually switch. The
MAC lock is learned from the ARP table and is spoofable on a hostile L2 — defence in depth
alongside digest auth, not a substitute for it.

**Display: the AP passphrase reaches the glass**

On the touchscreen build the standalone-AP path called `ui_set_onboarding_mode(false)`, so
with WPA2 enabled the generated passphrase went to the serial log and nowhere else — on the
one build with a screen. It is now shown on the display. Relatedly, `main/ui/ui.h` still
carried `const char* pass = "12345678"` as a **default argument**: dead, but it was the
exact literal removed above, sitting ready to be reintroduced. The defaults are gone
(`nullptr`, with a guard in `ui.cpp`), and that header's comment no longer tells readers
configuration is "SSH-only afterward" — the SSH surface was deleted a phase ago.

**Documentation corrections**

- `AdminAuth.hpp` and `THREAT_MODEL.md` §5.3 both described a 30-minute *absolute*
  session expiry; the code has always implemented *sliding* expiry. Corrected in the
  docs — sliding is the intended behaviour.
- A comment in `HttpServer.cpp` claimed a ~3 KB pthread stack; `sdkconfig.defaults` has
  set 8192 for some time.

**Tests**

- Host suite 289 → 306. New coverage for CSRF (missing/wrong/valid token, and that it is
  *not* demanded while unprovisioned), the newly-gated endpoints, the security headers,
  the lockout counter surviving a trip, per-client isolation, and the aggregate backstop.
- New `tests/DeviceConfig_test.cpp`: default-off, generation, persistence, rotation, and
  the WPA2 length/charset bounds that stop a typo from bringing the AP up open.
- Note `tests/AdminHttpGate_test.cpp` cases that provision a PIN must attach a real
  `RequestsHandler` — otherwise the dark-by-default gate closes the listen socket and the
  test measures a refused connection instead of the gate.

## Unreleased (feat/sdp-negotiation-invite-auth) - 2026-09-01

### Security — SDP admission gate (docs/THREAT_MODEL.md T-7)

- Every SDP-bearing SIP message is now structurally checked once, in
  `RequestsHandler::handle()`, before any decoder runs and before it can be
  relayed to a peer phone — initial INVITE, re-INVITE, UPDATE, ACK and every
  response alike. `SipMessage::checkSdp()` is one flat, allocation-free pass
  that enforces `SdpLimits` (body ≤ 4 KB, ≤ 256 lines, ≤ 512 bytes per line,
  ≤ 40 tokens per line, ≤ 32 formats per `m=` line, `a=` names ≤ 32 token
  characters) and refuses the RFC 5939 / 6871 / 7104 capability-negotiation
  attributes (`acap tcap pcfg acfg creq rmcap omcap mfcap mscap lcfg sescap bcap
  ccap icap`) outright, since this PBX does not implement them. A violation is a
  hard error for the whole body: requests get `488 Not Acceptable Here` with a
  `Warning: 399 <ip> "SDP refused: <reason>"`, responses and ACKs are dropped
  (never relayed, never advance a transaction). New counter
  `RequestsHandler::getSdpRejected()`. Motivated by the UNISOC T612 VoLTE RCE
  (CWE-674: an `a=acap` decoder recursing per token until the modem stack
  overflowed) — a body this PBX used to relay verbatim to the held party.
- The SDP MIME type is now matched case-insensitively (`Application/SDP` is
  SDP to a phone, so it is SDP to the gate).
- `applyAudioPolicy` (the relay codec policy behind `filterAudioCodecs` /
  `offersSupportedAudio`) rewritten heap-free: per-payload-type facts live in
  fixed 128-slot tables and the `m=` format list in a fixed array; the
  `std::function` line callback is gone, so the parser task's stack holds no
  function pointer on this path. Behaviour is unchanged (existing
  `SdpNegotiate` tests) and now pinned as zero-allocation by a counting
  `operator new` in `tests/SdpAdmission_test.cpp`.
- `sdkconfig.defaults`: `CONFIG_FREERTOS_WATCHPOINT_END_OF_STACK=y` (hardware
  trap on the first write past any task stack) and
  `CONFIG_COMPILER_STACK_CHECK_MODE_STRONG=y` (per-frame canaries) as the
  backstop for the day a future change reintroduces stack-proportional parsing.
- New `tests/tools/check_parser_callgraph.py`: compiles the SIP translation
  units with GCC `-fcallgraph-info=su` / `-fstack-usage` and fails on any
  recursion cycle or dynamic stack frame in project code (run under Linux/WSL).
  Current state: 656 functions, no cycles, no dynamic frames; `checkSdp` is two
  frames deep.
- Tests: `tests/SdpAdmission_test.cpp` (14 cases, unit + through `handle()`:
  the literal T612 payload on an INVITE, a re-INVITE and a 200 OK; every
  capneg attribute; each structural cap; a codec-rich ICE/DTLS offer still
  forwarded) and `tests/SipSdpMessage_hardening_test.cpp`.

## Unreleased (issue-33-pcap-dump-endpoint) - 2026-08-28

### Added — `GET /api/diagnostics/pcap` (#33)

- Added `GET /api/diagnostics/pcap`, the path Issue #33's feature request
  actually asked for. It's a second route to the exact same `sendApiPcap()`
  handler `GET /api/pcap` already uses (shipped in `607bd91`, hardened for
  wire-byte fidelity by #105) — same bounded `PcapCapture` ring, same session
  gate, same `application/vnd.tcpdump.pcap` response with a
  `Content-Disposition: attachment` header — so no second capture mechanism
  and no new allocation path were introduced. A real 24-byte libpcap global
  header (magic `0xa1b2c3d4`, `LINKTYPE_ETHERNET`) followed by one 16-byte
  record header + synthesized Ethernet/IPv4/UDP frame per captured packet, so
  `curl -o dump.pcap http://<device>/api/diagnostics/pcap` opens directly in
  Wireshark without following a redirect.
- `docs/API.md`'s endpoint catalog and `/api/pcap` section now note the alias.
- New test in `tests/PcapCapture_test.cpp`,
  `ApiDiagnosticsPcapServesValidGlobalHeaderAndOneRecordOverRealSocket`: drives
  a real `HttpServer` + `RequestsHandler` pair over an actual TCP socket,
  captures a REGISTER, then fetches the new endpoint and checks the actual
  bytes on the wire — global header magic/linktype, and the first record's
  `incl_len`/`orig_len` agreement, frame-fits-in-body, and verbatim SIP payload.

## Unreleased (issue-74-broadcast-hold) - 2026-08-28

### Fixed — Hold/resume on broadcast (ring-group) calls silently discarded (#74)

- `RequestsHandler::onOk`'s mid-dialog re-INVITE relay (the block that forwards
  a hold/resume `200 OK` to the opposite leg once a session is `Connected` or
  `Held`) explicitly excluded broadcast/ring-group sessions with
  `!isBroadcast()`. Since the broadcast-specific block below it only runs the
  first-answer connect path when `state == Invited`, a hold/resume `200 OK`
  arriving in `Connected`/`Held` state matched neither branch and was silently
  dropped — the offer reached the held leg fine (`onReinvite` never checked
  `isBroadcast()`), but the answer never made it back, so the re-INVITE
  transaction timed out client-side and the phone reported hold as failed.

  Fixed by dropping the `!isBroadcast()` restriction: once a broadcast session
  is `Connected`, `getSrc()`/`getDest()` name exactly the two live legs (the
  original caller and the one target that answered) the same way a unicast
  session's do, so the same source-address peer lookup now relays a
  hold/resume `200 OK` for either. The `#69b` non-destructive guard
  (`state == Invited` gating the connect/cancel path) is unaffected — it and
  the relay block above it are disjoint on session state.

  New coverage in `tests/BroadcastHoldResume_test.cpp` drives a full 999
  broadcast call end-to-end through connect → hold → resume and asserts the
  relay actually reaches the held leg's peer (not just that nothing crashes),
  while also pinning `#69b`: exactly one `CANCEL` is ever sent to the losing
  fork target across the whole hold/resume sequence.

## Unreleased (issue-69-dial-plan) - 2026-08-28

### Added — Dial-plan / hunt-group generalization (#69)

- **`src/SIP/DialPlan.hpp`** (new, pure/header-only, same shape as `PbxConfig.hpp`):
  a bounded, ordered `pattern → action` rule table. Each rule maps a dialed number
  to one of the three actions already on `main` — ring/hunt **group**, **page**
  zone (#66), or **park** orbit (#65). (#68's directed pickup is not merged and is
  deliberately absent; adding it later is one enum value and one dispatch arm.)

- **Pattern grammar** — deliberately tiny, no regex: literal characters, `X`/`x`
  for exactly one digit, and a *trailing* `*` for a prefix match. A `*` in any
  other position is a **literal** `*`, because star-codes (`*8`, `*4887`) are real
  dialable strings here. Rules are evaluated **in table order, first match wins** —
  order is the operator's, not a specificity heuristic — and editing an existing
  pattern updates it in place rather than moving it to the end.

- **No behavior change when nothing matches.** The plan is consulted *after* every
  reserved virtual extension (`777`, `999`, `980`–`989`, `440`, `700`–`70N`) and
  after the direct ring-group lookup, and *before* CFU/DND/extension lookup, so a
  rule can only capture a number that would otherwise have reached the ordinary
  extension lookup. Not even a catch-all `*` can shadow the echo test, a park
  retrieval, or a configured group. An unmatched number routes exactly as before.

- **Bounded**: `POCKETDIAL_MAX_DIAL_RULES` (default **16**, `src/SIP/PoolConfig.hpp`)
  caps both the table's memory and the per-INVITE linear walk. Enforced inside
  `DialPlan::upsert()` so the HTTP setter and the NVS replay both inherit it; a full
  table stays editable, since an upsert on an existing pattern is not growth.

- **Admin config surface**: `POST /api/dialplan` (`pattern` / `action` / `target`;
  an empty `target` deletes) behind the same same-origin + `pd_session` gate as
  `/api/group`, with the table echoed back in `GET /api/status` under `dialplan` in
  evaluation order. NVS-persisted under key `dplan`, in table order. Documented in
  `docs/API.md` (endpoint catalog, endpoint section, and status field schema).

- **Refactor, no functional change**: `onInvite()`'s 98x page-zone and ring-group
  bodies were lifted verbatim into `RequestsHandler::routePageZone()` /
  `routeRingGroup()` so the built-in dial codes and the dial plan share one
  implementation. `routeRingGroup()` takes the group extension *explicitly* rather
  than reading it off the INVITE's To-number — under a dial rule those differ, and
  `Session::setGroupExt()` feeds the hunt-exhausted CDR and the no-answer Contact.

- **Hardening**: pattern and target are charset-validated (`[0-9A-Za-z#*]`) at
  config time in both `setDialRule()` and the HTTP handler, because the persisted
  record is tab/newline delimited and a smuggled separator would corrupt every rule
  after it on reload. `777`/`999`/`440` are refused as literal patterns (they route
  before the plan, so such a rule could never fire). A matched rule whose target no
  longer resolves answers `404` rather than falling through — a stale rule must not
  silently ring whichever real extension shares the dialed digits.

- **Tests**: `tests/DialPlan_test.cpp` (32 new) — grammar; precedence from both
  directions (exact-first wins, *and* wildcard-first shadows the exact rule below
  it, the property a "sort most-specific-first" refactor would quietly delete); the
  cap through both the pure class and `setDialRule`/`getDialRules`; fallthrough
  driven through `handle()` against a *populated* table; dispatch into each of the
  three actions; the stale-target `404`; and a real-socket round-trip of
  `POST /api/dialplan` through `HttpServer`. Full host suite **233/233**.

## Unreleased (issue-75-mixbus-conference) - 2026-08-28

Local N-way conferencing: `MixBus` is wired into `MediaBridge` and dialable.
Full host suite: 216/216 passing; cppcheck 2.21.0 clean; ESP-IDF `esp32s3`/`eth`
firmware build clean.

### Added — `MixBus` wired into `MediaBridge`, conference extension `888` (#75)

- **`MediaBridge` BUS mode.** `init()` takes an optional `MixBus*`. With a bus,
  the two media callbacks swap at their far end: decoded handset µ-law goes to
  `MixBus::inputFrame()` instead of `AnchorClient::writeAudio()`, and the sender
  pulls `MixBus::outputFrame()` — the saturated sum of every *other* port —
  instead of draining `_playoutBuffer`. `startBridge()` claims the port with
  `attach()` before opening any socket (a full bus fails with nothing to unwind);
  every later failure path and `stopBridge()` `detach()` it, non-blocking, so the
  mix tick reclaims the rings and the remaining legs are never disturbed. The
  callback bodies moved out of their lambdas into named `onHandsetRtp()` /
  `fillHandsetTx()` members so the host suite can drive the real code path (on
  host `RtpReceiver`/`RtpSender::start()` are stubs that never invoke a callback).
  Passing no bus keeps the historical 1:1 anchor behaviour unchanged; in BUS mode
  `feedRx()` now returns `false` rather than writing into a buffer nothing reads
  (giving the anchor leg its own port is follow-up work, see CONFERENCE_MIXER.md §7).

- **`ConferenceRoom`** (`src/SIP/ConferenceRoom.*`): one `MixBus`,
  `POCKETDIAL_CONF_LEGS` (default 4) legs of `{RtpReceiver, RtpSender,
  MediaBridge}`, and **exactly one** 20 ms mix-tick driver — a Core-0 FreeRTOS
  task at `RtpSender`'s media priority on device, a `std::thread` off it. Not hung
  off a leg's sender cadence: N senders against one bus would be N clocks racing to
  drain the same rings. `tickOnce()` steps the clock for tests.

- **Virtual extension `888`**, intercepted in `onInvite()` alongside
  `777`/`999`/`440`/`700`–`709`. The server answers 200 OK advertising *that leg's*
  RTP receive port with a `sendrecv` SDP (`buildMediaSdp()` gained a direction
  flag; `440` stays `sendonly`) and joins the caller — N callers dialing `888` are
  N legs of one conference. Ordering mirrors the 440 path (#115): join → session →
  message pool → publish, unwinding the leg on any earlier failure. A dial past the
  cap gets 486 Busy Here and consumes no session slot. `endCall()` releases the leg,
  making it the single teardown point for BYE, CANCEL, session-timer expiry and the
  orphan sweep; `888` also joins the reserved list forwards and ring groups may not
  shadow. The room is created on first dial-in and then kept alive (its rings are
  ~50 KB, and churning the tick task under live legs is the race `Draining` exists
  to avoid).

- **`tests/ConferenceRoom_test.cpp`** (15 tests): 3- and 4-leg mixes end-to-end
  through the real µ-law rim (expectations round-tripped through G.711, not
  hardcoded sums), the over-saturation counterexample asserted through the bridges,
  a leg leaving mid-conference, port reclaim/reuse, the room cap and
  one-leg-per-Call-ID, proof the tick driver actually ticks, and the `888` intercept
  driven through a real `RequestsHandler` (including a hold re-INVITE, declined 488).

- `onReinvite()`/`onUpdate()`'s virtual-leg guard now covers `888` alongside `777`:
  a conference leg's session "dest" carries the *caller's own* address, so relaying a
  hold offer would send the phone its own re-INVITE back. Declined 488 instead.

- `RequestsHandler::getConferenceLegs()` exposes the live leg count.
  `POCKETDIAL_CONF_LEGS` added to `PoolConfig.hpp`. The PIE vector path
  (`POCKETDIAL_MIXBUS_PIE`, `src/SIP/pie/`) is untouched and still opt-in.

## Unreleased (issue-68-call-pickup) - 2026-08-28

### Added — Directed (`**<ext>`) and group (`*8`) call pickup (#68)

- New virtual dial codes, intercepted in `onInvite` alongside the existing
  700-709 park orbits and 980-989 page zones: `*8` answers the **oldest**
  ringing call among the picker's ring-group co-members; `**<ext>` answers a
  **named** extension's ringing call. Both are restricted to the picker's own
  pickup group — pickup groups are **reused ring-group membership**
  (`setRingGroup`/`getRingGroups`), not a new config table: two extensions are
  pickup-eligible for each other iff they're both members of the same ring
  group (see `PbxConfig.hpp`'s `isGroupPickupCode`/`directedPickupTarget` doc
  comment for the rationale).
- Picking up a call completes the caller's still-open INVITE transaction with
  the picker's SDP as the answer, answers the picker's own INVITE with the
  caller's original SDP, and CANCELs every other still-ringing fork of that
  call (the whole target, not just one leg, for a ring-all/hunt group pickup).
  The two resulting dialogs (different Call-IDs) are bridged via
  `Session::peerCallID`, whose relay `onBye()` now actually implements
  (reusing #72's empty-From/To guard so a session with no captured dialog
  headers is skipped rather than sent a malformed BYE) — previously set by
  `ParkOrbit`'s retrieve/ring-back paths but never wired up, so a hangup on
  either bridged leg now also cleans up Park's retrieved-call session
  bookkeeping (CDR, pool slot) instead of leaking it; Park doesn't capture
  dialog headers yet, so its bridged peer still doesn't get a wire BYE.
- Race handling: `onOk()` now drops a late 200 OK from a call's
  already-superseded (CANCELed) fork instead of resurrecting/stealing an
  already-connected session — a CANCEL and a 2xx can legally cross on the
  wire. Whichever side answers first wins; the other gets `486 Busy Here` (no
  ringing call to pick up) or is CANCELed, never both.
- `RequestsHandler::onInvite`'s direct (non-group) call path now always
  retains the original INVITE on its `Session` (previously only when a
  conditional forward was configured) — needed so pickup can tell which
  extension a direct call is ringing without answering it first.
- New tests: `tests/CallPickup_test.cpp` (directed pickup, group pickup
  picking the oldest ringing call, the race in both directions, the
  cross-dialog BYE bridge teardown, and a Park-retrieve BYE confirming the
  #72-style guard prevents a malformed empty-header BYE) and
  `tests/Pbx_test.cpp` (the pure `isGroupPickupCode`/`directedPickupTarget`
  parsers).

## Unreleased (issue-106-104-108-112-misc-bugs) - 2026-08-19

Four small, independently-filed correctness bugs plus one CI hygiene fix,
bundled into one PR per the triage bucket. Full host suite: 196/196 passing
(WSL/Linux — see Verification).

### Fixed — BLF `forEachSessionInvolving` drops the Callee leg on a self-call (#106)

- `RequestsHandler::forEachSessionInvolving()` (the production `PbxEnv`
  implementation) used an `if (isSrc) ... else if (isDest) ...` chain, a
  regression from commit `f0446d9`'s refactor away from independent flags. When
  a session's src *and* dest are both the watched extension (an extension
  calling itself, or a hunt/ring group where the caller is also a member), the
  `else if` meant only the Caller role ever fired — `BlfSubscriptions::
  computeDialogState` never saw the Callee leg, so a watcher's dialog-info XML
  reported the wrong role/state for that dialog. Restored to two independent
  `if`s so both roles fire when both match — matching the pre-`f0446d9`
  behavior where the visitor received both flags at once.

- `tests/FakePbxEnv.hpp`'s `forEachSessionInvolving()` (the test double every
  `BlfSubscriptions`/`RegisterBeeper`/`ParkOrbit` host test drives) carried the
  identical bug, since it was written to mirror the production method. Fixed
  identically.

  `RequestsHandler::forEachSessionInvolving()` itself is a private `PbxEnv`
  override (`RequestsHandler` privately inherits `PbxEnv`) and so isn't
  directly host-testable in isolation; the fake mirrors it exactly and is
  covered by two new tests in `tests/BlfSubscriptions_test.cpp`: one asserts
  the callback fires twice (once per `DialogRole`) for a self-call session,
  the other drives the real `BlfSubscriptions::computeDialogState` end-to-end
  through the fake and confirms a ringing self-call reports the higher-ranked
  Callee leg (`early`/`recipient`) rather than getting stuck on the
  lower-ranked Caller leg (`trying`/`initiator`) — which is exactly the
  externally-observable symptom the `else if` bug produced.

### Fixed — `RegisterBeeper::sweep` claims "cancelled" when the CANCEL was never built (#104)

Real-hardware evidence (see the issue's comment thread): a LilyGO T-ETH-Elite
S3 logged `"Register beep: no answer from 321, cancelled"` immediately
alongside `"[tx] pool exhausted — INVITE sent without retransmit tracking"` —
i.e. `buildCancel()` failing under the exact message-pool pressure Issue
#101(A) bounds, not a hypothetical.

- `sweep()`'s `AwaitingInviteOk` branch unconditionally logged `"cancelled"`
  and advanced to `AwaitingCancelDone` even when `buildCancel(i)` returned
  `nullptr` (pool exhausted). `AwaitingCancelDone` means "a CANCEL is in
  flight, keep matching this Call-ID for a raced 200 OK" — asserting that when
  no CANCEL went out is both a misleading log during exactly the flood an
  operator would be reading it in, and leaves the dialog in a half-cancelled
  limbo state that nothing ever revisits (the phone was never actually
  CANCELled, and the dialog no longer looks like it needs to be).

  Now: on `buildCancel()` failure the dialog stays in `AwaitingInviteOk` with a
  short (1s) deadline, logs a distinct "cancel build failed — will retry"
  message, and the next `sweep()` tick retries — succeeding once pool pressure
  eases, at which point it follows the original cancelled/`AwaitingCancelDone`
  path unchanged.

- Per the issue's own caution ("don't leave it stuck forever either"): added a
  bounded retry count (`BeepDialog::cancelRetries`, capped at
  `RegisterBeeper::kMaxCancelRetries` = 5). If pool pressure hasn't eased after
  five consecutive retry ticks, `sweep()` gives up and frees the slot outright
  (logged as an error) instead of retrying indefinitely under sustained
  exhaustion — the phone simply rings out on its own INVITE timeout instead of
  ever being CANCELled, which is strictly better than pinning a beeper slot
  forever.

  Covered by two new tests in `tests/RegisterBeeper_test.cpp`: one forces
  `buildCancel()` to fail once (via a new `FakePbxEnv::messagePoolAvailable`
  toggle, matching the existing `sessionPoolAvailable` pattern) and asserts the
  log/state behavior plus a successful retry once the pool recovers; the other
  forces ten consecutive failures and asserts sweep gives up and frees the slot
  rather than retrying forever.

### Fixed — `RtpSender` SSRC/sequence/timestamp seeded from `std::rand()` (#108)

- RFC 3550 §3 wants the RTP SSRC genuinely random so colliding streams can be
  told apart, and the initial sequence/timestamp random so a receiver can
  detect restarts. The host/Linux `rand32()` used `std::rand()` — a single
  process-wide stream, shared and correlated across every caller, which is the
  opposite of what SSRC randomness needs. Replaced with a `thread_local
  std::mt19937` seeded from `std::random_device`, one generator per thread
  rather than one shared global stream. The ESP branch is unchanged
  (`esp_random()`, the hardware RNG, was already correct).

- **Destructor join, investigated and found already correct on `main`:** the
  issue flagged "no destructor is visible in the patch" (referring to commit
  `af5fd24`'s Linux media path). `~RtpSender()` does exist — it predates
  `af5fd24` (added with the original media feature, commit `119ca84`) and was
  carried through unchanged — and its non-ESP branch unconditionally calls
  `stop("")`. On Linux, `stop()` sets `_stopRequested` and **joins
  `_senderThread` synchronously** before returning (see `stop()`'s own
  comment), so a joinable `std::thread` is never left running when the object
  is destroyed; on the plain host stub there is no real thread to join at all.
  No code change was needed for this half — only a comment update, since the
  destructor's comment still called it a "host stub" after `af5fd24` gave the
  same code path a real Linux thread to join. Verified directly: built and ran
  the host test suite under WSL/Linux (`__linux__`, the real thread path, not
  the Windows host-stub one) with a new test that starts a stream and lets the
  `RtpSender` destruct without calling `stop()` first — the process completes
  cleanly rather than calling `std::terminate()`. New test in `tests/Rtp_test.cpp`.

### Fixed — cppcheck version floats with `ubuntu-latest`; scope grew during verification (#112)

- **The suppression half is landed here; the version-pin half needs a
  follow-up push.** This session's `gh` token lacks the `workflow` OAuth
  scope GitHub requires to push a change under `.github/workflows/`, so the
  `ci.yml` diff that actually pins cppcheck to 2.21.0 (built from its own
  tagged source — no official Linux binary, and pip's `cppcheck` package is
  an unrelated 1.5.1-vintage wrapper — cached by version via `actions/cache`
  so a version bump is deliberate, not a runner-image surprise) could not be
  pushed to this branch. It's fully written and verified (see below) and sits
  on the local `backup-with-ci-workflow-change` branch; someone with that
  scope needs to cherry-pick it onto this PR (or push that branch and merge
  it) before this issue is truly closed. Until then CI keeps running the
  floating apt 2.13.0, which is a no-op with respect to every suppression
  below (2.13.0 reports none of these findings), so nothing regresses in the
  meantime — the pin is additive, not a prerequisite for the rest of this PR.

- **The issue's own count was verified and found incomplete.** The issue
  documented exactly 4 findings 2.21.0 has that 2.13.0 doesn't. To pin
  responsibly this needed verifying on the real toolchain rather than trusted
  at face value, so both versions were built from source and run **twice**:
  once on this Windows sandbox's cross-compiled cppcheck (caught the
  discrepancy) and once on a real Linux build via WSL Debian (gcc 14, matching
  the actual `ubuntu-latest` job) to rule out a Windows-build artifact.
  Confirmed on Linux: 2.13.0 finds **zero** issues on `main`; 2.21.0 finds
  **13**, across six categories, not four. The other nine are the identical
  false-positive shape as the issue's own `SipStatus.cpp` example — plain
  aggregates cppcheck now flags per-scalar-member (`uninitMemberVarNoCtor`)
  even though every construction site brace-initializes or immediately
  overwrites the field before any read — plus a third, previously-unreported
  `ESP_IDF_VERSION_VAL` `syntaxError` site and one `performance` finding.
  Pinning to 2.21.0 without addressing all thirteen would have made the pin
  itself the next red-CI surprise, so all thirteen are resolved here:

  - **The two `syntaxError` findings the issue asked to investigate "for
    real"** (`main/esp_main_eth.cpp:36`, `main/esp_main_eth_lan8720.cpp:43`,
    both `#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(...)`) — plus a third,
    identical, previously-unreported instance found during verification
    (`src/SIP/RequestsHandler.cpp:3734`, inside the DTMF NTP-resync
    handler) — are **not** a real parse defect: `esp_idf_version.h` is a real
    ESP-IDF header that a genuine `idf.py` build (Job 2 of this workflow)
    resolves fine. The host lint job's include path (`-I src/Helpers -I
    src/SIP -I main`) has no ESP-IDF tree on it, so cppcheck can't expand
    `ESP_IDF_VERSION_VAL` and aborts that `#if`. Suppressed with inline
    `// cppcheck-suppress syntaxError` comments at each site (verified this
    scopes to just that line and doesn't blind cppcheck to the rest of the
    file — confirmed with a standalone repro before applying), rather than
    the issue's suggested whole-file `--suppress=syntaxError:<path>`, which
    would have silenced *any* future syntax error anywhere in
    `RequestsHandler.cpp` — the codebase's largest, most-frequently-changed
    file, and precisely the "dangerous" outcome the issue was warning about,
    just from the flag rather than from the finding itself.
  - **`SipStatus.cpp:11` `uninitMemberVarNoCtor`** (and, found during
    verification, the same struct's `code` field at line 9 — cppcheck flags
    each scalar member individually, not once per struct): `StatusEntry` is a
    deliberate plain aggregate; its only instance, the constexpr
    `kStatusTable`, brace-initializes every field. Suppressed inline with the
    issue's own rationale.
  - **`main/wifi/DnsServer.cpp:113,141` `dangerousTypeCast`**: the standard
    BSD-sockets `(struct sockaddr *)&x` idiom for `bind()`/`recvfrom()`.
    Suppressed inline with the issue's own rationale.
  - **`src/SIP/PcapCapture.hpp` `uninitMemberVarNoCtor` ×6**
    (`TraceRecord::seq/tsUs/outbound`, `Entry::seq/outbound/tsUs`, found during
    verification, not in the issue): `TraceRecord`'s one construction site
    brace-initializes every field; `Entry`'s one populator (`recordInto()`)
    assigns every field immediately after the `emplace_back()`/slot-reuse that
    default-constructs it, before any read. Suppressed inline.
  - **`src/SIP/RequestsHandler.hpp` `uninitMemberVarNoCtor` ×2**
    (`ProvisioningInfo::authRequired`, `RateBucket::tokens`, found during
    verification): both are always fully brace-initialized or immediately
    overwritten at their one construction site each
    (`findProvisioningInfo()`'s return; `_rateBuckets[ip] = {40.0, now}`).
    Suppressed inline.
  - **`src/SIP/AnchorClient.hpp` `uninitMemberVarNoCtor` ×1** (`CallEvent::
    type`, found during verification): every `CallEvent` construction site in
    `LoopbackAnchorClient.cpp` brace-initializes all four fields. Suppressed
    inline.
  - **`src/SIP/RequestsHandler.hpp:160` `performance: returnByReference`**
    (`getAdminExt()`, found during verification) — deliberately **declined**,
    not applied: `_adminExt` is mutated by `saveAdminExt()`/`loadAdminExt()`
    from call paths that don't share a lock with this getter (callers read it
    off the SIP thread, e.g. the dashboard/HTTP plane). Returning by value at
    least hands the caller an independent copy the instant this call returns;
    returning `const std::string&` as suggested would additionally let that
    reference dangle/tear if a concurrent save reallocates the string while
    the caller still holds it — strictly worse, not a free performance win.
    Suppressed inline with that rationale.

### Verification

Full host suite built and run on **two** toolchains for this bucket, since
issue #112's own build was cross-verified on real Linux (see above) and the
Windows sandbox's Smart App Control policy (enterprise code-integrity
enforcement, unrelated to this change) began blocking execution of freshly-
linked, unsigned test binaries partway through this session:

- **Windows, MSVC 19.44 (Visual Studio 17 2022)**: for #106 and #104,
  temporarily reverted just the production fix (`RequestsHandler.hpp`,
  `RegisterBeeper.cpp`, and the `forEachSessionInvolving()` half of
  `FakePbxEnv.hpp`) with the new tests left in place, confirming all three new
  tests fail against the pre-fix behavior, then restored the fix and confirmed
  they pass. Full suite (171 pre-existing + new tests) passing on the fixed
  tree, prior to the Smart App Control block described below.
- **WSL Debian, gcc 14.2.0** (matches the CI runner's OS/toolchain family):
  configured, built, and ran the fixed tree's full suite — **196/196
  passing**, including the `RtpSender` destructor test running the real
  `__linux__` `std::thread` path (not the Windows host-stub no-op path, which
  would have proven nothing about the join fix).
- **Windows, MSVC 19.44 (Visual Studio 17 2022)**: built clean through
  `RegisterBeeper.cpp`, `RequestsHandler.hpp`/`.cpp`, `RtpSender.cpp`,
  `AnchorClient.hpp`, `PcapCapture.hpp`, `SipStatus.cpp`, and all touched test
  files with no new warnings; test *execution* is currently blocked on this
  machine by Smart App Control (`CodeIntegrity` event log:
  "did not meet the Enterprise signing level requirements") for any
  freshly-rebuilt, unsigned `sip_parser_tests.exe` — confirmed unrelated to
  these changes (the already-built `SipServer.exe` runs fine; only newly
  re-linked test binaries are affected) and not something fixable from within
  this session.
- **cppcheck 2.21.0**, built from source on both a Windows cross-compile and a
  real WSL/Linux build, run against the final tree with the workflow's exact
  invocation: `EXIT=0`, zero findings, on both.
## Unreleased (issue-41-80-verification) - 2026-08-19

Verification pass on two "verification needed" tracker issues, neither of which had
a committed bug repro. No firmware code changed — see the linked GitHub comments for
the full writeups.

### Docs

- `docs/HARDWARE.md` §2 (Guition JC3248W535): added the microSD pin table
  (Issue #80's blocker). SD_MMC (SDIO) 1-bit mode, CLK/CMD/D0 = GPIO 12/11/13,
  cross-referenced against the vendor's own Arduino demo `pincfg.h`, the sibling
  `jc3248-display-driver` bring-up repo, and this repo's own hardware-verified
  `esp_main_display.cpp` comment (three independent sources, all agreeing) — and
  checked for GPIO conflicts against the panel/touch/battery pins already in the
  table (none found). Left open: whether the physical slot is populated on a given
  board (the vendor spec sheet calls it "reserved" and its rear-connector photo
  shows no slot), so no `esp_vfs_fat_*` mounting code was written against this —
  see the GitHub comment on #80 for the recommended next step (a continuity probe).

- Issue #41 (Arduino IDE platform-detection guards): re-audited every `#if`/`#ifdef`
  touched by the original change (`src/Helpers/UdpServer.hpp/.cpp`,
  `src/SIP/RequestsHandler.hpp`, `src/SIP/SipClient.hpp`, `src/SIP/SipMessage.hpp`)
  plus the guards a prior audit (see `ISSUES.md`) already fixed elsewhere
  (`SipMessage.hpp`, `TelephonyApiConfig.cpp`). No new bug found: the
  `#undef INADDR_NONE` in `SipClient.hpp`/`SipMessage.hpp` is preprocessor-scoped to
  the translation unit that includes it (confirmed nothing in `src/`, `main/`, or
  `sketches/` reads `INADDR_NONE` afterward), and `SipServer.cpp`'s
  `#if defined(ARDUINO) ... #elif defined(ESP_PLATFORM)` mDNS-header selection
  correctly prioritizes `ARDUINO` (needed because Arduino-ESP32 3.x builds through
  the IDF build system and can define both). Host build re-verified clean
  (`cmake --build`, no warnings); `ctest` could not be executed in this environment
  (a Device Guard / application-control policy blocks running newly-built,
  unsigned executables here — confirmed with the exact toolchain-build binary, not
  a stale cache). Arduino IDE / `arduino-cli` compile and physical-hardware runtime
  test remain unverified, as before — full details posted as a GitHub comment on
  #41 rather than duplicated here.
## Unreleased (issue-105-111-81-network-build) - 2026-08-19

Three network/build-correctness issues found by code review, bundled as one
themed pass: a signaling-capture fidelity bug (#105), a build-system footgun
(#111), and a per-packet allocation on the SIP receive hot path (#81).

### Fixed — `/api/pcap` inbound capture stored re-serialized SIP, not wire bytes (#105)

- `RequestsHandler::handle()`'s inbound capture point called
  `request->toString()` — a re-serialization of the **parsed** message — not the
  bytes `recvfrom()` actually delivered. `SipMessage::toString()` always writes
  CRLF line endings and rejoins the parsed pieces; it does not restore whatever
  line-ending convention or malformed-but-tolerated layout the wire bytes
  actually used, so a bare-LF message, a compact-header form (`v:`/`f:`/`t:`/
  `i:`), or a blank line the parser silently drops (SEC-02 tolerance) all
  captured differently than what arrived. The outbound side was never affected —
  those messages are server-minted, so `toString()` genuinely is the wire bytes.
- `handle()` now takes an optional `std::string_view rawBytes` and, when the
  caller has wire bytes to offer, writes them into the pcap ring slot verbatim
  instead of calling `toString()`. `SipServer::onNewMessage()` is the only
  production caller and always supplies it — the received bytes flow through
  `SipMessageFactory::createMessage()` and `RequestsHandler::getMessageFromPool()`
  by view (see #81 below) with nothing copying or discarding them before they
  reach the capture point. Every pre-existing `handle(msg)` call site (all of
  `tests/`) keeps compiling unchanged and keeps its old `toString()`-based
  capture, since `rawBytes` defaults to empty.
- `docs/API.md`'s "exact SIP bytes" claim for `/api/pcap` (and `/api/trace`'s
  "raw SIP message bytes, exactly as captured") is now actually true for both
  directions in production — no qualification needed, no doc change required.
- Covered by 2 new tests in `tests/PcapCapture_test.cpp`: one fixture with
  bare-LF endings and compact headers where `toString()` demonstrably
  re-serializes to different bytes (asserting the capture equals the *original*
  raw text, not the re-render), and one confirming the no-`rawBytes` fallback
  still matches pre-#105 behavior exactly.

### Fixed — `SIP_TRANSPORT=lan8720` on a non-esp32 target failed ~1400 objects into the build instead of at configure time (#111)

- LAN8720 drives the classic ESP32's **internal EMAC** — ESP32-S3 and every
  other target has no internal EMAC, so the combination cannot work at runtime
  either. Nothing in `main/CMakeLists.txt` rejected it up front: the
  `lan8720` branch selected `esp_main_eth_lan8720.cpp` and added
  `REQUIRES espressif__lan87xx` based on `SIP_TRANSPORT` alone, with no target
  guard, while `main/idf_component.yml`'s component-manager rule (`target ==
  esp32`) correctly declined to fetch the PHY driver on any other target — so
  the eventual failure was a missing header 1400+ objects into the build,
  reading like an ESP-IDF version mismatch rather than an unsupported
  target/transport pairing.
- `main/CMakeLists.txt`'s `lan8720` branch now checks `IDF_TARGET` (the same
  CMake cache variable the component manager's own `target ==` rule resolves
  against, set well before component registration — confirmed against
  `esp-idf/tools/cmake/targets.cmake`) and fails with `message(FATAL_ERROR ...)`
  at configure time when it isn't `"esp32"`, naming `SIP_TRANSPORT=eth` (W5500)
  as the alternative. Turns the repro in the issue into a one-line configure
  error instead of a confusing compile failure.
- Verified in isolation: a standalone `cmake -P` script reproducing the exact
  `if(NOT IDF_TARGET STREQUAL "esp32")` guard fails immediately for
  `IDF_TARGET=esp32s3` and passes through cleanly for `IDF_TARGET=esp32`. A full
  `idf.py` configure run was not exercised (no activated ESP-IDF environment in
  this session) — the shipped `esp32` LAN8720 path and every other
  `SIP_TRANSPORT` branch are untouched by this change.

### Changed — zero-allocation network ingestion, `UdpServer` → `RequestsHandler` (#81)

- `UdpServer::receiveLoop()` heap-allocated a `std::string` copy of every
  incoming packet's bytes before the parser or message pool ever saw them —
  `_onNewMessageEvent(std::string(buffer, bytesReceived), ...)`. Whether that
  allocation actually bought anything downstream depended on the exact shape of
  the call chain: an earlier pass through this issue found that, as of `main`
  at the time, everything below `onNewMessage` already took the string **by
  value** and moved it through unconditionally with nothing intercepting in
  between — so swapping the event to `std::string_view` would only have
  *relocated* the same one allocation, not removed it, and flagged the change
  as not worth the risk on that basis.
- The #105 fix above changes that basis: `SipMessageFactory::createMessage()`
  and `RequestsHandler::getMessageFromPool()` now take the message **by
  reference** (so `SipServer::onNewMessage()` can still hand the original bytes
  to `handle()` afterwards), and `SipMessage::reset()` already only ever reads
  through its `message` parameter — `splitMessage()` copies what it needs
  (`substr` into the owned `_startLine`/`_headerLines`/`_body`) and nothing
  retains the parameter itself. With that in place, the chain below
  `receiveLoop()` is reference-only end to end, so the original allocation had
  no downstream consumer left to justify it.
- `UdpServer::OnNewMessageEvent` is now
  `std::function<void(std::string_view, sockaddr_in)>`, `receiveLoop()` passes
  a `string_view` over its own stack-local receive buffer (unchanged
  allocation-wise — still per-task, still not `static`, so no shared-buffer race
  between instances is introduced), and every link in the chain
  (`SipServer::onNewMessage`, `SipMessageFactory::createMessage`,
  `RequestsHandler::getMessageFromPool`, `SipMessage::reset`/`splitMessage`) was
  updated to pass the view through rather than an owned string. Every consumer
  that needs the bytes to outlive the call already copies them out
  synchronously before returning — `splitMessage()` into the parsed message,
  and the #105 pcap-capture line into the ring slot — so nothing holds the view
  past the single synchronous call chain `receiveLoop()` → ... → `handle()`
  that produced it.
- Scoped deliberately smaller than the alternative the earlier pass floated
  (moving the Issue #38 rate-limit admission check out of `RequestsHandler::
  handle()` to skip allocation for rejected packets before parsing): that would
  have meant duplicating or relocating defense-in-depth admission logic away
  from the one function every test in the suite calls directly
  (`handler.handle(msg)`), which is a defense-in-depth regression risk this
  change does not take on. `handle()`'s existing rate-limit/validity checks are
  untouched.
- Host-level functional coverage of the actual `UdpServer`/`SipServer` socket
  layer remains a pre-existing gap (noted in the original issue discussion) —
  not added here to keep this change scoped to the data-plumbing types it
  actually touches, which host tests already cover in `RequestsHandler.cpp`/
  `SipMessage.cpp` (the pool/parse layer every one of these views ultimately
  flows into). Left as a good follow-up.

### Verification

- Host suite: **193/193** passing (191 before this work; 2 new tests added for
  #105). Full rebuild of the production `SipServer.exe` target (which is what
  actually compiles `UdpServer.cpp`/`SipServer.cpp`/`SipMessageFactory.cpp` —
  `tests/CMakeLists.txt` does not link those three) succeeds clean with MSVC,
  confirming the `string_view` plumbing type-checks end to end.
- Not covered: ESP-IDF device build (no activated `idf.py` environment this
  session — see #111's verification note above) and an on-hardware/real-socket
  run of the `UdpServer` receive path.
## Unreleased (issue-79-multi-source-load-test) - 2026-08-25

Addresses Issue #79 (partial): tooling landed and a real measurement was taken
on one host; a genuine multi-host run is still open (see below).

### Summary

Root cause of #79 not being previously measurable: `tests/load/sip_stress.py`
gave every virtual UA the OS's single default source address, so no single-box
run could ever push past `RequestsHandler::allowPacket`'s per-source-IP token
bucket (Issue #38's DoS protection — confirmed by reading it that the bucket
key, `_rateBuckets`'s `unordered_map<uint32_t, RateBucket>`, is the raw
`sockaddr_in::sin_addr.s_addr` with **no port**, so any genuinely distinct IP
draws its own bucket).

- Added `--source-ips` (explicit comma list), `--source-ip-base` +
  `--source-ip-count` (auto-generate `<base>2..<base>N+1`), and `--hold-ms`
  (keep an echo call open between ACK and BYE so concurrent calls actually
  overlap a Session-pool slot instead of each completing before the next
  INVITE lands) to `tests/load/sip_stress.py`. Every UA now binds its own
  socket to its assigned source IP; with none of the new flags passed, behavior
  is unchanged (single implicit source, exactly today's script).
- Ran it for real against the **host build** (`SipServer.exe`, default
  `POCKETDIAL_MAX_CLIENTS=32`/`POCKETDIAL_MAX_SESSIONS=8`) on **one Windows
  machine**, using 32–40 distinct `127.0.0.x` source addresses — Windows
  treats the whole `127.0.0.0/8` block as loopback with no configuration
  needed (unlike Linux, which by default only brings up `127.0.0.1`). This is
  a real bypass of the per-IP limiter (confirmed above the key is IP-only), but
  it is **not** a multi-host run: one NIC, one kernel network stack, one
  process under test — see `tests/load/STRESS_FINDINGS.md` for exactly what it
  does and doesn't validate.
- **Measured: client-pool ceiling is exactly 32**, with a clean `503` on the
  8 overflow REGISTERs and no crash/hang — the general graceful-degradation
  claim in `docs/SCALING.md` §4 is now backed by an actual run, not just code
  reading.
- **Measured: the session pool does cap at 8 server-side** (confirmed via
  server logs, `Session Created between <ext> and 777` appeared exactly 8
  times across 16 concurrent held-open echo calls), **but the `777`
  echo-test path never returns the 503 that behavior should produce** — all
  16 calls got `200 OK` from the caller's point of view, because
  `RequestsHandler::onInvite`'s `777` branch (`RequestsHandler.cpp` ~line 755)
  enqueues the `180`/`200` responses *before* calling `allocateSession()`, and
  silently skips the session bookkeeping (no log line either) if that returns
  `nullptr`. This is a real, independently-diagnosed defect in the `777`
  diagnostic path specifically — the ordinary call-to-call INVITE path a few
  hundred lines down correctly gates on `allocateSession()` first and 503s
  cleanly. Filed as **#115**, not fixed in this change (out of scope for a
  load-test-tooling issue — the fix needs a trace of what a BYE against an
  untracked Call-ID currently does, which belongs with the fix, not the
  measurement).

### Docs

- `tests/load/STRESS_FINDINGS.md`: new "Issue #79" section with the exact
  commands run, the exact output, the `_rateBuckets.size() >= 256` fail-safe
  noted as a ceiling on how far this technique scales, the OPTIONS-keepalive
  pruning timing trap observed when scripting back-to-back runs, and an
  explicit "what a real multi-host run still needs" list (separate physical/VM
  hosts or real netns addresses, the actual ESP32 firmware — not just the
  shared host-build C++ logic — and real network conditions).
- `docs/SCALING.md` §4: pointer note summarizing the measured ceilings and
  linking to STRESS_FINDINGS.md and #115.

No concurrency numbers are reported for anything not actually run above; the
production-capacity question (real hosts, real firmware, real network) remains
open per the issue's own framing.

---

## Unreleased (issue-32-terminal-trace-command) - 2026-08-24

Closes Issue #32.

### Summary

The tracker entry stayed open after `GET /api/trace` + the dashboard's polling
"SIP Trace" checkbox panel shipped (see the existing Issue #32 entry further
down this file), because the literal ask — a `trace on`/`trace off`
**command** typed into the terminal, not a checkbox — was never built, and
`ISSUES.md`'s description had drifted (it still said "using WebSockets," which
was the original proposal, not what shipped). This change adds the command
surface without adding a second live-update mechanism:

- `src/Helpers/index_html.h`: a `pd>` command-line prompt under the SIP Trace
  card. `trace on` / `trace off` / `help` are parsed by a small `termExec()`
  interpreter that calls the *same* `startTrace()`/`stopTrace()` functions the
  pre-existing checkbox already drove — both paths still funnel through one
  1.5 s poll of `/api/trace`. Command echoes render into the same trace-screen
  the packets stream into and share its existing 200-block client-side DOM
  cap, so typing commands can't grow memory/DOM usage unbounded any more than
  the packet stream already could. The checkbox keeps working unchanged.
  Verified end to end against the real host build in a real browser: `trace
  on` streams live REGISTER/INVITE traffic as raw ASCII into the terminal,
  `trace off` stops it, an unrecognized command echoes `unknown command: ...`,
  and the checkbox and terminal commands stay in sync in both directions.
- `src/Helpers/index_html.h`'s giant `CGA_INDEX_HTML` raw-string literal had to
  be split one more time (`R"html2(...)html2" R"html2a(...)html2a"`) — MSVC
  caps a single narrow string literal at ~16 KB, and the JS added here pushed
  the existing `html2` segment over that limit (`error C2026: string too big,
  trailing characters truncated`, which does not fail the build, it silently
  drops page content — caught by rebuilding and noticing the compiler warning,
  not by any test). No content changed, only where one literal boundary falls.
- `tests/HttpTraceCommand_test.cpp` (new): the command interpreter itself is
  pure client-side JS with no C++ surface by design (see the comment beside
  `termExec()`), so this instead pins the data path both the checkbox and the
  new commands consume — a real `HttpServer` + `RequestsHandler` pair over a
  real socket, fed a synthetic SIP message with an escaped quote/backslash in
  an `Authorization` header (the shape a real digest challenge response
  produces), asserting the exact bytes `GET /api/trace` puts on the wire
  round-trip through `jsonEscape()`/JSON-parsing intact. Prior tests
  (`PcapCapture_test.cpp`, `RequestsHandler_pool_test.cpp`) only ever asserted
  against the C++-side `getTraceRecords()` accessor, never the actual response
  body a browser's `trace on` would receive.

### Verification

- Host suite: **192/192** passing, including the new
  `HttpTraceCommand.ApiTraceRoundTripsRawSipTextWithQuotesAndBackslashes`.
- Manual: built and ran the real `SipServer.exe` + dashboard, drove real SIP
  traffic at it, and exercised `trace on`/`trace off`/an unknown command from
  the terminal input in a real browser session.

---
## Unreleased (issue-115-777-session-pool) - 2026-08-28

### Fixed — 777 echo-test INVITE answers 200 OK even when the Session pool is full (#115)

- Found while executing #79's multi-source-IP load test: driving 16 concurrent
  `777` SDP-loopback echo calls against `POCKETDIAL_MAX_SESSIONS=8` produced
  exactly 8 `Session Created` log lines but **16/16 200 OK** at the client — 8
  calls were never tracked server-side yet still looked successful.

  `RequestsHandler::onInvite`'s `destNumber == "777"` branch built and
  enqueued the `180 Ringing` / `200 OK` responses **unconditionally**, and
  only afterward called `allocateSession()`. When the session pool was
  already full, `allocateSession()` returned `nullptr` and the bookkeeping
  `if` body was simply skipped — but the caller had already gotten its
  `200 OK`, with no `_sessions` entry ever created to back it. The ordinary
  call-to-call INVITE path (`RequestsHandler.cpp` ~line 1009) already got
  this right: `allocateSession()` first, `503 Service Unavailable` before
  any success response is built.

  Fixed by reordering the `777` branch to match: `allocateSession()` runs
  first; on `nullptr` it now sends a real `SIP/2.0 503 Service Unavailable`
  (same shape as the hunt-group path's 503 — sent directly to
  `data->getSource()`, since `777` is a virtual extension, not a registered
  client looked up by number) and returns before building anything.

  Both `180`/`200` messages are then drawn from the message pool **before**
  `_sessions.emplace()` + `setState(Connected)` run, not after — mirroring the
  comment on the `440` media path's own `allocateSession()` gate ("the OK is
  drawn before the session is published... past `_sessions.emplace()` +
  `Connected` there is no clean way back"). Publishing the session first and
  drawing messages after would trade the original bug for a smaller one: a
  message-pool refusal mid-branch would abandon a `Connected` session with no
  `180`/`200` ever sent, and the retransmission guard a few lines above this
  branch would then silently drop the caller's retry for that Call-ID.
  Refusing before either mutation leaves nothing behind: `allocateSession()`
  already reset the pooled `Session`'s Call-ID via `reset()`, but since it was
  never published to `_sessions`, the next `allocateSession()` call treats
  that slot as free again (its scan matches any slot whose Call-ID isn't a
  key in `_sessions`).

- **BYE-for-untracked-Call-ID traced before landing the fix, per the issue's
  own requirement.** `RequestsHandler::onBye`'s `777` branch unconditionally
  replies `200 OK` and calls `endCall()` regardless of whether a session was
  found — the spoofed-teardown authorization check is skipped when there's
  no session to authorize against, but nothing downstream assumes one
  exists. `endCall()` is fully defensive against an unknown Call-ID:
  `_dtmfState.erase`/`_txLayer.freeForCallId`/`_park.freeForCallId`/
  `_rtpSender.stop` are no-ops for an ID they don't hold, `_sessions.erase`
  returning 0 skips the CDR record and disconnect log, and the
  `_sessionPool` scan finds no match to release. A BYE for a Call-ID that
  was correctly refused with a 503 under this fix is therefore already
  handled sanely — 200 OK, silent no-op teardown, no crash, no phantom CDR —
  and nothing else in the codebase leaves a session referenced without a
  corresponding `_sessions` entry, so this fix introduces no new
  inconsistency for the BYE path to trip over.

  New test in `tests/Invite777SessionPool_test.cpp`: drives a real
  `RequestsHandler` through `handle()`, fills every `POCKETDIAL_MAX_SESSIONS`
  slot with ordinary calls (checked live via `getSession()` — the
  dashboard's `getSessionCount()`/`getClientCount()` only refresh their
  snapshot inside `tick()`, not synchronously per packet, so they can't
  observe mid-`handle()` state), then sends a `777` INVITE and asserts the
  response is `503` with no `200`/`180`, and that no `_sessions` entry was
  created for the refused Call-ID or disturbed for the pre-existing ones.
  Confirmed the test fails against the pre-fix code
  (`saw503=false, saw200=true, saw180=true`) before confirming it passes
  against the fix.

### Verification

- Host suite: **192/192 passing** (Windows, MSVC 19.44, Release), including
  the new `Invite777SessionPool` test.
- The new test was run against the reverted (pre-fix) `RequestsHandler.cpp`
  and confirmed to fail with the exact pre-fix symptom (false `200 OK` +
  `180 Ringing`, no `503`) before the fix was restored and the suite
  re-confirmed green.

## Unreleased (issue-101-closeout) - 2026-08-17

Closes Issue #101: items **A**, **B**, **D** and **E** are fixed, **C** is
formally declined and recorded as such.

### Fixed — data race in the message-pool handout (#101(E), found by the audit)

- `findFreePoolSlot()` scanned the **static** `_messagePool` for `use_count()==1`
  and then copied the `shared_ptr` — a check-then-take with no synchronization,
  reachable concurrently from two tasks: the UDP receive task
  (`UdpServer.cpp:134` → `SipServer::onNewMessage` →
  `SipMessageFactory::createMessage` → `getMessageFromPool`), which holds **no
  lock** because `handle()` only takes `_mutex` afterwards on the
  already-allocated message; and the tick task (`esp_main.cpp:192`, or
  `SipServer::tickLoop` on desktop) via `TransactionLayer::sweep`, under
  `_mutex`.

  Both could observe `use_count()==1` on the same slot and both take it, then
  `reset()` it concurrently — two owners writing one `SipMessage` and
  reallocating its strings under each other. Holding `_mutex` on one side does
  not help: a lock only excludes other holders of that same lock. It fires under
  exactly the load that item A exists to harden against.

  Fixed with a dedicated **leaf** mutex around the scan-and-take (nothing inside
  its critical section may take another lock, so it is safe regardless of whether
  the caller already holds `_mutex`). Message initialization stays outside the
  critical section, which is by then exclusively owned. The fallback deleter is
  documented as never taking that mutex — the last reference can drop while it is
  held, so a locking deleter could self-deadlock.

### Fixed — pool-exhaustion backpressure (#101(A))

- `getMessageFromPool()` and `allocateVirtualPeer()` fell back to **unbounded**
  heap allocation once their pools were drawn down. Both now allow a bounded
  number of heap fallbacks alive at once — `POCKETDIAL_MSG_HEAP_FALLBACK_MAX` (8)
  and `POCKETDIAL_VPEER_HEAP_FALLBACK_MAX` (4) in `PoolConfig.hpp` — tracked by
  an atomic in-flight counter that the `shared_ptr` deleter decrements, and
  return `nullptr` past that. It is a ceiling on concurrent use, not a rate, so a
  burst is absorbed and only sustained over-subscription is refused.

  On refusal the contract is **drop, not 503**: building a 503 would need a
  message out of the very pool that just came up empty, so `allocateSession()`'s
  reject-and-503 pattern is not available here. SIP over UDP retransmits
  (RFC 3261 §17), so a dropped packet costs latency rather than the call. The
  allocation is also exception-balanced — see the comments; the ownership rules
  around a throwing `shared_ptr` constructor are easy to get wrong in both
  directions.

- 67 call sites updated (55 `getMessageFromPool` in `RequestsHandler.cpp`, 12
  `messageFromPool` across the decomposed machines), with the failure action
  matched to context: `return` in void handlers, `continue` in fork/sweep loops
  so one refusal skips a target rather than aborting a broadcast, and `nullptr`
  propagation out of builders. Resources are acquired before state is mutated, so
  a refusal never leaves a half-built session — the ordering discipline Issue #71
  established for the park path.

  Two things kept that from being 67 hand-written checks. `enqueue()` now drops a
  null centrally, covering every inline `enqueue(addr, messageFromPool(...))` and
  guaranteeing `drainOutbox()` — which dereferences every entry — never sees one.
  And the highest-volume path needed **no** new code: `createMessage()` already
  returned `nullopt` on null and `handle()` already dropped it, so an inbound
  packet that cannot be represented is discarded at the earliest possible point.

- `BlfSubscriptions` no longer records `lastState`/`version` when the NOTIFY it
  just built was refused. Banking a state that was never sent would suppress the
  retry and strand that watcher's busy-lamp until the target's state changed
  *again*; leaving it untouched means the next `refresh()` retries.

### Declined — `maybeTrack()` duplication (#101(C))

- Re-examined and deliberately **not** changed, matching the original call. The
  four blocks each copy a different `string_view` into a different fixed `char[]`
  member and share only their shape; folding them into a helper trades four
  obvious bounds-safe copies for one indirection, on the retransmit path, for no
  behavioral gain. Recorded in `ISSUES.md` so it is not re-litigated.

### Fixed — PcapCapture allocation under the caller's lock (#101(D))

- The ring no longer pops and pushes. Once full it overwrites the oldest entry in
  place and recycles that entry's buffer, so the steady-state capture path
  allocates nothing; it still grows lazily, so a quiet node never pays for slots
  it has not used. Readers now walk from the ring head, since storage order stops
  matching capture order after a wrap.
- `recordInto()` hands the slot's buffer to the caller and a new
  `SipMessage::toString(std::string&)` serializes straight into it, removing the
  per-packet temporary that both capture sites built *before* `record()` even
  copied it. Worth doing properly because capture is unconditional — there is no
  enable flag, so this ran on every inbound and outbound message under `_mutex`.

### Verification

- Host suite: **188/188** passing (168 before this work). The new tests are
  mutation-verified — with each fix reverted in turn they fail, including the two
  that initially did not: same-shape SDP bodies let stale offsets land on correct
  text, and assigning two `SipSdpMessage` lvalues does not reproduce the pool's
  base-subobject assignment.
- Device: all seven edited translation units compile clean for ESP32-S3
  (`xtensa-esp32s3-elf-g++`) under `-Wall -Wextra`, and the full `idf.py build`
  links for the esp32s3 target.
- Not covered: no on-hardware or QEMU run. The concurrency fix in particular is
  argued from the code and pinned by a host-thread test; it has not been observed
  under real dual-task load on a device.

### #101(E) audit — remaining findings, all clean

- **Endianness / packed structs**: `RtpSender::buildRtpHeader` writes every
  multi-byte RTP field byte-by-byte in big-endian and `RtpReceiver` parses the
  same way — no packed structs, no buffer-to-header casts, so no strict-aliasing
  exposure and no host-endianness assumption. `SipWireUtil.hpp` is clean.
- **Blocking calls on the retransmit-timer path**: `sweep()` does no socket I/O
  (sends are deferred to the outbox and drained after unlock, per Issue #51), no
  NVS, no sleep, and already null-checked its pool draw.
- **Watchdog starvation**: every long-lived loop blocks or yields each iteration
  — `recvfrom()` with `SO_RCVTIMEO` in both receive loops, `vTaskDelayUntil` /
  `sleep_until` in the RTP send loops, `vTaskDelay` backoff in the bind-retry
  loops. No spin-waits.

---

## Unreleased (issue-101-B-sdp-parse-cache) - 2026-08-17

Issue #101 item **B**.

### Fixed

- `SipSdpMessage`: the six SDP accessors re-parsed the entire body on every
  call — `getRtpPort()` alone walked it twice, and call setup touches several
  of them per INVITE. They now share one single-pass parse, cached until the
  body changes (Issue #101.B).

- `SipMessage`: added a private `_bodyGen` counter, bumped by every `_body`
  mutation (`reset()`, `setBody()`, `clearBody()`, `enforceG711()`) and
  published to derived classes as `bodyGeneration()`. This is what makes the
  cache above safe on a **pooled** message: `RequestsHandler` recycles the same
  `SipSdpMessage` objects across unrelated calls via `reset()` and
  `*msg = source`, so a cache keyed on a plain valid/dirty flag would serve the
  previous call's `c=`/`m=` lines to the next call — wrong media endpoint, not
  merely a stale read.

  The cache stores `(offset, length)` spans rather than `string_view`s, so the
  copy used by the pool's `*msg = source` recycle stays correct instead of
  leaving the destination pointing into the source's body. This preserves the
  "no `string_view` to fix up after a copy" property `SipMessage` already
  documents.

- `SipMessage::operator=` is no longer `= default`: it now copies every member
  except `_bodyGen`, which it advances instead. The pool assigns through a base
  reference — `getMessageFromPool(const SipMessage&)` does `*msg = source` on a
  `shared_ptr<SipMessage>`, so only the `SipMessage` subobject is assigned and a
  derived class's cache is left untouched. With the generation copied, the
  destination's stale cache could match the incoming generation and be treated
  as fresh. Bumping keeps the counter a strictly per-object timeline, so
  "recorded generation == current generation" can only ever mean "parsed from
  exactly these bytes". Implicit move operations were already suppressed (both
  copy operations were previously user-declared as `= default`), so this is not
  a change in value-category behavior.

- `SipSdpMessage::operator=` is likewise hand-written, for the same reason one
  level down: the implicit one advanced this object's body generation through
  the base operator and then overwrote its *cache* generation with the source's,
  crossing two objects' private counters. When those collided, a stale cache
  read as current against a body it was never parsed from. Assignment now drops
  the cache instead of copying it. The copy *constructor* stays defaulted and is
  correct as-is — it takes both counters from the same object, so a fresh cache
  stays fresh and a stale one stays stale.

### Testing

- New `tests/SipSdpMessage_cache_test.cpp` (13 tests): accessor parity with the
  old per-call parse, and cache invalidation across every body-mutation path,
  including both pool-recycle paths and both assignment defects above. Verified
  by mutation — with the invalidation deliberately disabled, 8 of them fail.

  Three of these only got teeth after being rewritten, and the failure modes are
  worth knowing about. First, the two SDP bodies the tests switch between must
  differ in line *length*, not just in content: with same-shape bodies the stale
  offsets landed on the new body's correct text and the invalidation tests
  passed against a knowingly broken cache. Second, a test that assigns one
  `SipSdpMessage` lvalue to another does NOT reproduce the pool's assignment —
  that one goes through a `SipMessage&` and assigns only the base subobject.
  Third, the derived-assignment defect is a *collision* between two counters, so
  that test sweeps a range of prior-mutation counts on both objects instead of
  hardcoding the one pair that happens to line up today.
- Full host suite: 180/180 passing (168 before this change).
- Device build: all seven edited translation units compile clean for ESP32-S3
  under `-Wall -Wextra`, and the full `idf.py build` links (see the closeout
  section above).
## Unreleased (issue-107-provisioning-crlf) - 2026-08-17

Closes Issue #107. Defense in depth around the zero-touch provisioning config
served by `GET /config/<mac>.cfg` (Issue #35, commit `b79570c`).

### Fixed — config-line injection via the provisioned extension (#107)

- `provisioning::yealinkConfigFor()` interpolates the extension into
  `key = value\r\n` lines. An extension carrying a CR or LF would have appended
  config keys nobody wrote — `account.1.password` being the interesting one —
  to the file the handset parses. The builder now refuses outright (returns an
  empty config) when the extension contains CR or LF, and `sendConfigCfg()`
  treats an empty build as a 404 rather than serving a 200 with an empty body.

- `RequestsHandler::findProvisioningInfo()` re-checks the adopted extension
  against `isValidAor()` before handing it to the builder, so provisioning
  fails closed instead of depending on a gate three call layers away.

**Reachability, since the issue left it open:** not reachable today. Every path
that writes `DeviceRecord::extension` is downstream of `onRegister()`'s
`isValidAor()` check — `admitLearn()`'s adopt (`Registrar.cpp:177`) and
re-extension (`:189`) paths both are — and that charset (alnum plus `. - _ + * #`)
excludes CR/LF. The remaining writer, `loadDevices()` (`:348`), restores from an
NVS blob whose own field/record delimiters are tab/newline, so a CR/LF-bearing
extension could not have round-tripped through it either. Both guards are
therefore backstops, not a live-hole patch: they keep the property local to the
code that depends on it, for future callers wiring in less-trusted input.

Deliberately *not* narrowed to `[0-9A-Za-z]` as the issue suggested — that
would silently mangle `*55`, `+15551234`, and the rest of the AOR charset the
registrar already accepts. Only CR/LF, the actual injection vector, is rejected.

Covered by 3 new tests in `tests/ProvisioningConfig_test.cpp`
(mutation-verified: with the guard removed the injected
`account.1.password = hunter2` line appears 5x in the served config).
Full host suite: 171/171 passing.

## Unreleased (post-100-review-followups) - 2026-08-09

A pass through `src/SIP` following a laziness/reuse-discipline review plus an
embedded-firmware hardware-risk review run after PR #100. See Issue #101 for
the items found but deliberately not fixed here (pool-exhaustion backpressure
redesign, `SipSdpMessage` re-parse caching, `PcapCapture` alloc-under-lock,
and an incomplete firmware audit of the RTP/wire-format files).

### Fixed

- `RequestsHandler.cpp`: consolidated 10 hand-rolled `inet_ntop` +
  IP:port-formatting blocks onto the existing `sipwire::addrToIpPort()`
  helper, which the file already included and used correctly once but had
  re-derived by hand 10 more times as it grew.

- `RequestsHandler.cpp`: consolidated 3 duplicate To-header `;tag=` splice
  blocks onto a new `siphdr::appendTagFrom()` helper in `SipHeaderUtil.hpp`.

- Rate-limited (1-in-100) the `SIP Message pool exhausted` /
  `Virtual-peer pool exhausted` warning logs, previously an unthrottled
  `stderr` write per occurrence — a flood that exhausts the pool would
  otherwise also flood the log/serial pipe. The underlying unbounded
  heap-fallback behavior itself is unchanged and tracked as Issue #101.

- Host build (MSVC): defined `NOMINMAX` for the non-IDF CMake branch.
  `Registrar::noteChange()`'s `std::max(...)` call was colliding with
  `windows.h`'s `max()` macro, breaking the host build MSVC gates on
  independent of this review. Full host suite: 168/168 passing.

## Unreleased (tracker-followups) - 2026-08-04

A pass through the open issue tracker: small hardening/perf fixes, docs
catch-up, and a few feature requests, each on its own commit.

### Fixed

- Raised `CONFIG_LWIP_UDP_RECVMBOX_SIZE` (6 → 32) and set
  `CONFIG_LWIP_TCPIP_RECVMBOX_SIZE=32` in `sdkconfig.defaults` to absorb
  bursts of simultaneous SIP packets from one source, which previously
  overran the lwIP receive mailbox and were dropped before the SIP task ever
  saw them (Issue #78, `tests/load/STRESS_FINDINGS.md` finding #1). The
  RAM-constrained profile keeps its own smaller value.

- `RegisterBeeper`: `sweep()` no longer frees a beep dialog's slot in the same
  pass it sends the CANCEL. RFC 3261 §9.1 lets the phone's 200 OK race an
  in-flight CANCEL past the point the CANCEL had any effect; freeing
  immediately meant that raced answer was unrecognized (a beep dialog has no
  `Session`) and never got ACKed or BYEd. The dialog now moves to
  `AwaitingCancelDone` — a state the enum already declared but nothing ever
  entered — for a bounded 5 s window in which `handleOk()` still matches it,
  then frees on either a raced answer being handled or the window elapsing
  with nothing further (Issue #98).

- `onDtmfInfo`: best-effort behavioral detection for a `4887`-prefixed admin
  PIN provisioned before `POST /api/admin/set-pin` started rejecting that
  prefix (Issue #93). The `*4887` HTTP-open star-code matches the instant the
  accumulated sequence equals it — before the `*PIN#code` parser runs — so a
  PIN beginning `4887` is shadowed and can never complete over DTMF. If the
  star-code fires and the admin's next digits then shape up as an interrupted
  `*PIN#code` continuation (`#` + 3+ digits, no leading `*`), a targeted
  warning is logged suggesting a PIN rotation. Imperfect by construction — the
  PIN is salted+hashed, so this can only be inferred behaviorally, never
  confirmed. See `docs/THREAT_MODEL.md` §5.5 for the residual-risk writeup.

### Added

- `GET /api/pcap` (Issue #33): downloads the last `POCKETDIAL_PCAP_RING_SIZE`
  (default 64) SIP signaling packets as a classic libpcap file, ready to open
  in Wireshark. Both directions are captured through the two choke points
  every packet already passes through — `handle()` for inbound,
  `drainOutbox()` for outbound — so no call site needed to remember to
  record anything. RTP/media is out of scope by construction: pocket-dial
  brokers it peer-to-peer and never relays it, so there's nothing server-side
  to capture. Each entry is synthesized into a minimal Ethernet+IPv4+UDP
  frame (dummy MACs, real IP:port) around the exact captured bytes so
  Wireshark's SIP dissector decodes it like a real capture. Session-gated
  (no same-origin check — it's a download, not a mutation). New
  `src/SIP/PcapCapture.hpp` (host-tested ring + serializer).

- `GET /api/trace` + a "SIP Trace" dashboard panel (Issue #32): a live-ish SIP
  signaling tracer for the web dashboard, reusing `#33`'s capture ring rather
  than adding a second one. The tracker/roadmap framed this as a WebSocket
  push stream, but the HTTP server has no WebSocket support today (RFC 6455
  framing, the Sec-WebSocket-Accept handshake, frame masking — none of it
  exists), so building that from scratch felt like too large and too
  security-adjacent an addition for a tracker sweep. Implemented as polling
  instead: the dashboard's toggle starts a 1.5 s poll of `/api/trace` (JSON,
  the same ring as `/api/pcap`, monotonic `seq` per entry) and appends
  whatever it hasn't already rendered, capped client-side at 200 blocks so a
  long-running session doesn't grow the DOM without bound. Verified end to
  end: built and ran the real server, drove real SIP traffic at it, and
  checked the rendered dashboard in a real (Playwright) browser.

- `GET /config/<mac>.cfg` (Issue #35): zero-touch Yealink auto-provisioning
  for already-adopted devices — point a phone's provisioning URL at
  `/config/` and it gets its account/server/codec settings back with no
  manual entry. Covers **re**-provisioning (factory reset, handset swap)
  rather than a device's very first contact, since a MAC has to already be
  in the Registrar's adopted-device registry (Learn/Secure mode) to be
  served — the first-ever REGISTER is what gets it adopted, and still needs
  the phone told its extension by some other means. Never carries a working
  password: `SipSecretStore` only stores a one-way HA1 hash, so a
  Secure-mode (or individually `secure()`'d) device's config flags that the
  admin has to set the password by hand instead of silently omitting it.
  Deliberately not session-gated (a booting phone has no session cookie) —
  the MAC itself (2^48 space, only served if already adopted) plus the
  existing dark-by-default transport gate are the protection. New
  `src/SIP/ProvisioningConfig.hpp` (pure, host-tested config builder). Not
  verified against physical Yealink hardware.

- Linux desktop build now sources real RTP media for extension 440 (Issue
  #82's concrete named gap: `RtpSender`'s `#else` branch was a no-op stub on
  every non-ESP platform, so 440 connected but produced no audio on Linux).
  New `#elif defined(__linux__)` path mirrors the ESP implementation
  one-for-one (`std::thread` + `sleep_until` pacing in place of the FreeRTOS
  task + `vTaskDelayUntil`), with one deliberate divergence: `stop()` joins
  the sender thread synchronously rather than the ESP path's fire-and-forget
  poll, since the existing host test suite (`Rtp_test.cpp`) requires
  `isActive()` to be false the instant `stop()` returns, and `std::thread`
  has no equivalent to poll instead. Bounded to one 20ms pacing tick, and
  only on the 440 diagnostic-tone teardown path — real calls' RTP is
  peer-to-peer and never touches `RtpSender`. Verified against the actual
  built binary: real RTP packets at the correct cadence, clean teardown with
  zero packets after BYE, no deadlock between `stop()`'s join and the
  sender thread's own cleanup lock. The ARMv7 musl cross-compile toolchain
  file this issue also asked for already landed in a prior commit
  (`cmake/armv7-linux-musleabihf.cmake`); the rayhunter Orbic installer
  integration and actual ARM hardware verification remain out of scope
  here (different repo / no hardware in this session).

### Docs

- `docs/API.md` §4 now specifies `/api/cdr`, `/api/dnd`, `/api/forward`,
  `/api/group`, `/api/configuring`, `/api/factory-reset`, `/api/ota/status`,
  `/api/ota/upload`, and `/api/ota/reboot` — request/response schemas, status
  codes, and auth requirements, sourced from `HttpServer::handleClient()`'s
  dispatch table. Also added the missing `401`/session notes to `/api/kill`
  and the two Wi-Fi mutation endpoints, which gained the session gate after
  their original specs were written (Issue #94).

## Unreleased (sip-decomposition-followups) - 2026-08-03

Review follow-ups on the SIP engine decomposition. Host-verified (145/145
GoogleTest, up from 131 — the park, register-beep and BLF machines had no host
coverage at all, which is how the wire defects below survived a green suite).

### Fixed — malformed headers on server-minted requests

`SipMessage::getCallID()` / `getTo()` / `getFrom()` return the **full header
line**, not the bare value. Four hand-built request paths treated them as bare
values and re-stamped the header name on top. All predate the decomposition
(they came in with the `b3cf191` protocol backport) and were carried through it
untouched:

- **Park retrieve re-INVITE** shipped `Call-ID: Call-ID: x@host`, so the parked
  phone could not match the request to its dialog and media never renegotiated.
- **Register beep** matched dialogs by comparing the bare Call-ID it generated
  against the full header line — a comparison that could never succeed. An
  answered beep was therefore never ACKed and never BYEd, and five seconds later
  `sweep()` sent a CANCEL for an INVITE that already had a final response
  (illegal per RFC 3261 §9.1). Its ACK also emitted `To: To: <...>`.
- **REFER progress NOTIFY** (RFC 3515 §2.4.5) emitted `From: To: ...`,
  `To: From: ...` and `Call-ID: Call-ID: ...`.

### Changed — shared plumbing instead of per-machine copies

- `SipWireUtil.hpp` owns `addrToIpPort()` and the `a=inactive` hold offer, which
  had been pasted into ParkOrbit, RegisterBeeper and BlfSubscriptions (each with
  its own socket-include block, none with a Windows branch — `inet_ntop` needs
  `ws2tcpip.h`, so those files could not build on MSVC).
- `BlfSubscriptions` drops its three private header parsers for the shared
  `siphdr::stripHeaderName` and a new `SipMessage::getEvent()` accessor. The old
  event-package scanner re-serialised the whole message and matched any line
  named `o` — which is also the SDP origin line's name.
- `ParkOrbit::consumeParkChanged()` mirrors `Registrar::consumeDevicesChanged()`,
  so the dashboard mirror is polled once per packet instead of being a duty each
  mutating call site had to remember. Paths that never signalled at all
  (`sweep()`, `freeForCallId()` via `endCall`) now do.
- `PbxEnv::sessionsView()` (a reference to `RequestsHandler`'s whole `_sessions`
  map) is replaced by `forEachSessionInvolving()`, keeping the session table's
  representation private.
- `RequestsHandler::drainOutbox()` is the single point messages leave the outbox
  by, so RFC 3261 §17 retransmit registration is structural rather than a scan
  duplicated at each flush site.
- Registrar registry changes are now classified: an online-flag flip patches the
  snapshot rows in place instead of rebuilding the vector and two strings per
  device, which is what a post-reboot registration storm would otherwise cost.

### Removed

- `handleTransferOk()` and `_transferPendingAcks` — unreachable since they were
  introduced; no commit ever added an entry to the list, so the lookup always
  failed and `onOk()` paid a wasted call on every 200 OK.

## Unreleased (sip-engine-decomposition) - 2026-08-03

Structural refactor, behavior-neutral by design. Host-verified (131/131 GoogleTest).

### Changed — RequestsHandler decomposed into discrete state machines

The ~6,200-line RequestsHandler monolith interleaved several independent state
machines behind one mutex. Each now lives in its own class, wired to the shared
engine infrastructure through the narrow `PbxEnv` interface (outbox enqueue,
message pool, deferred log, server identity, registration/session tables). All
of them keep the fixed-slot, no-heap-growth pools and the caller-holds-`_mutex`
convention of the code they were extracted from.

- **`TransactionLayer`** — RFC 3261 §17 INVITE client transactions
  (Timer A retransmit, Timer B timeout, RFC 6026 Timer L absorb).
- **`Registrar`** — REGISTER admission policy (Open/Learn/Secure), digest
  challenge/verify, and the Learn-mode TOFU + MAC-lock adopted-device registry
  (NVS-persisted). The device online flag now lives in the registry record;
  the dashboard snapshot is a plain mirror refreshed via a dirty flag.
- **`RegisterBeeper`** — the register-beep outbound UAC dialog machine
  (auto-answer INVITE → ACK → BYE, CANCEL on timeout).
- **`ParkOrbit`** — call parking: orbit slots 700..70N, park/retrieve SDP swap,
  ring-back on timeout, park sweep.
- **`BlfSubscriptions`** — RFC 6665/4235 BLF watcher dialogs: SUBSCRIBE gate,
  202 + immediate NOTIFY, change-detection NOTIFYs, expiry sweep.

`RequestsHandler` remains the call engine (INVITE routing, forks/groups/hunt,
forwarding, transfer, session timers, CDR, DTMF admin menu) and the thin
dispatcher that owns `_mutex`, the outbox flush and the dashboard snapshot.
Shared helpers moved to `PbxPersist.hpp` (NVS blob format) and
`SipHeaderUtil.hpp` (tag/header-name parsing). Public API unchanged
(`RegistrarMode`/`AdoptedDevice` are now aliases into `Registrar`).

## Unreleased (admin-http-only) - 2026-07-16

Admin-plane hardening: the HTTP dashboard becomes the only admin surface and goes
dark by default on a provisioned device. Host-verified (130/130 GoogleTest).

### Changed — dark-by-default HTTP admin plane

- **Transport gate**: on a provisioned device the HTTP listener is closed by default.
  `HttpServer`'s bind/listen moved out of the constructor into
  `openListenSocket()`/`closeListenSocket()`; the accept loop re-evaluates the gate
  every ~250 ms and fails closed. An unprovisioned device still listens immediately
  (onboarding needs the web UI before any credential exists).
- **DTMF trigger `*4887`** (spells HTTP on the keypad, no PIN): opens the dashboard
  for a bounded TTL (default 600 s), gated on caller extension == admin extension
  (default now `1001`), that extension currently registered, and the SIP INFO's
  source IP matching the registration's bound IP.
- **Provisioning grace window**: a successful `POST /api/admin/set-pin` grants the
  same TTL window, so first-run onboarding isn't cut off the instant provisioning
  flips the gate on.
- **`POST /api/admin/keepalive`** (authenticated): extends the open window by 1 hour;
  surfaced as a "Keep open (1h)" dashboard button.
- **Admin PINs may not begin `4887`** (reserved for the star-code): a PIN with that
  prefix would be shadowed mid-entry by the trigger and could never drive the DTMF
  admin menu. Enforced at set-pin; previously-provisioned PINs are unaffected (see
  ISSUES.md).

### Removed — SSH sysop terminal

- `SshServer`/`Tui` and the wolfSSH transport are **deleted, not hardened** — the
  second, separately-wired admin surface no longer exists (THREAT_MODEL.md E-3/§5.5).
  Removes wolfSSL/wolfSSH from `main/idf_component.yml` and all build wiring; the
  `docs/design/` TUI design folder is retained as historical reference only.

### Fixed

- Removed dead `persistAdminHttpTtl()` (no runtime path ever changed the TTL).
- Stale comments claiming the admin extension defaults to `101` (actual: `1001`).

## Unreleased (anchor-bridge-port) - 2026-06-30

Lands the previously-prepared `sip-backport` branch (below) onto `main`, relicenses
the project, and ports the vendor-agnostic media-anchor architecture and conference
mixer from the project's commercial sibling. Build: zero errors. Tests: all passing
(host; ESP-IDF firmware build pending verification).

### License

- **Relicensed MIT → Apache 2.0.** The original BarGabriel/SipServer MIT notice is
  preserved verbatim in `LICENSE-MIT` (not erased); `NOTICE` documents the dual
  heritage; `LICENSE` is now Apache 2.0 for everything contributed since the fork.
  README's companion-projects link corrected to point at the actual upstream
  (it pointed at the vendored resiprocate stack instead).

### Added — vendor-agnostic anchored media (opt-in, not wired into call routing)

- **`MediaBridge`** (`src/SIP/MediaBridge.cpp/hpp`): RTP↔`AnchorClient` glue. Already
  vendor-neutral as authored (depends only on the abstract `AnchorClient` interface) —
  ported with comment genericization only (no logic changes): stripped prose that named
  a specific commercial transport (HTTP GET/POST stream framing, internal issue-number
  references) in favor of generic anchor-interface language.
- **`TelephonyProvider` / `TelephonyApiConfig`** (`src/SIP/`): provider registry/factory
  + credential-slot table. `TelephonyProviderType` trimmed to ship only `Loopback` — no
  unimplemented vendor enumerators. The registry pattern is the extension point for a
  fork's own connector.
- **`RtpSender::FrameProvider`**: additive optional pull-callback (default `nullptr`,
  existing 440-tone callers unaffected) so `MediaBridge` can feed real audio into the
  sender instead of the synthesized test tone. Also adds the encode-side
  `ulawEncodeBuffer` mirror of the existing `RtpReceiver::mulawDecodeBuffer` (was
  missing; `MediaBridge` needs it).
- **`MixBus`** (`src/SIP/MixBus.cpp/hpp`, `mix_kernels*`, `pie/mix_sum4_s16.S`): N-way
  conference audio mixer — int32 accumulate, saturate exactly once on output,
  lock-free per-port attach/detach/tick lifecycle. Scalar reference is the default;
  the ESP32-S3 PIE vector kernels are opt-in behind `POCKETDIAL_MIXBUS_PIE`. See
  `docs/CONFERENCE_MIXER.md`. Ships standalone and tested, not yet wired into
  `MediaBridge` (tracked: `ISSUES.md` #75) — explicitly NOT a call-routing change.

### Added — tests

- `tests/MediaBridge_test.cpp`: lifecycle/identity bookkeeping, `feedRx` →
  `PlayoutBuffer`, and an end-to-end run through a real `LoopbackAnchorClient` wired
  the way a future caller would wire any `AnchorClient`'s single rx callback.
- `tests/MixBus_test.cpp`: minus-self mixing, no-over-saturation on loud legs,
  attach/detach/reclaim lifecycle, `mix_sum4_s16` primitive (ported from the original
  standalone self-test as GoogleTest cases).

### Fixed

- `ISSUES.md`: issues #65/#66/#67 (call park, paging zones, BLF) were still marked
  "planned" despite being implemented by the sip-backport landing — flipped to shipped.
- `ISSUES.md` Non-Goals: the prior blanket "no server-side media bridging" / "no
  telephony-provider connectors" language predated this pass and would have
  contradicted the shipped (but unwired) code above. Rewritten to the real boundary:
  no vendor connector *implementations*, no PSTN/trunk origination *policy*, no
  `RequestsHandler` call-routing wiring — all a fork's own decision, not built here.
- `main/CMakeLists.txt`: the ESP-IDF firmware SRCS list was missing
  `PlayoutBuffer.cpp` even after the sip-backport landing (it lists sources
  explicitly, unlike the host build's glob) — firmware build was silently
  incomplete. Added, along with the new files above.
- `docs/FEATURE_ROADMAP.md`, `CLAUDE.md`: reconciled the signalling-only framing and
  current-capabilities table with what's actually shipped (the backport features were
  never added to either after landing).

---

## Unreleased (sip-backport) - 2026-06-23

Full SIP protocol feature backport into the engine. Build: zero errors (one
pre-existing `inet_addr` deprecation warning on MSVC, pre-existing). Tests: all
passing.

### Added — SIP protocol

- **RFC 3261 §17 transaction layer** (`RequestsHandler.cpp`): `SipTransaction` pool, Timer A
  retransmit with exponential back-off, Timer B 32 s timeout; `sweepTransactions()` runs
  each tick; `freeTxsForCallId()` cleans up on teardown. Outgoing INVITEs are
  auto-registered on every `handle()` / `tick()` pass.
- **RFC 4028 session timers** (`RequestsHandler.cpp`): `armSessionTimer()` called on call
  connect; `sweepSessionTimers()` sends server-originated BYE to both legs on expiry.
  Server is always refresher (UAS policy).
- **RFC 3311 mid-dialog UPDATE** (`onUpdate()`): relay SDP-bearing UPDATE to the peer leg;
  bodiless UPDATE responds `200 OK` and resets the session timer.
- **RFC 3261 §12.2 mid-dialog re-INVITE** (`onReinvite()`): hold (`a=sendonly`/`inactive`)
  sets `Session::State::Held`; resume restores `Connected`. CDR talk-time preserved across
  hold/resume. 200 OK relay in `onOk()` via `sameAddress()` peer lookup.
- **Call parking** (`onParkInvite`, `handleParkOk`, `parkSweep`, `startParkRingback`, …):
  virtual orbit extensions 700–709; park with `a=inactive` hold SDP; SDP-swap retrieve;
  ring-back on timeout with configurable orbit; bridged BYE relay on teardown.
- **Paging zones** (`onInvite`, `findPageZone`, `setPageZone`, `getPageZones`, `persistPageZones`):
  extensions 980–989; intercom auto-answer fork via `startBroadcastFork()`; NVS persistence
  under key `"pzones"`; mirrored into `_snapshot.pageZones` for the dashboard.
- **BLF / presence** (`onSubscribe`, `refreshSubscriptions`, `sweepSubscriptions`,
  `buildDialogInfoXml`, `computeDialogState`, `buildDialogNotify`): RFC 6665 SUBSCRIBE /
  NOTIFY with RFC 4235 dialog-info+xml body; 489 Bad Event for unsupported packages; change
  detection on every `handle()` pass; terminal NOTIFY on subscription expiry.
- **`isDialogSourceAuthorized()`**: rejects forged BYE / CANCEL from off-path addresses
  (issue #46); wired into `onBye()` and `onCancel()`.
- **`AnchorClient` interface** (`src/SIP/AnchorClient.hpp`): abstract class for external
  audio systems; `makeCall`, `writeAudio`, `AudioRxCallback`, `dropCall`, lifecycle.
- **`LoopbackAnchorClient`** (`src/SIP/LoopbackAnchorClient.cpp/hpp`): reference
  implementation; echoes audio back to the caller; useful as a smoke test and as a
  starting template for SIP trunk / recorder / AI pipeline integrations.
- **`PlayoutBuffer`** (`src/SIP/PlayoutBuffer.cpp/hpp`): adaptive jitter buffer (200 ms
  ceiling, comfort-noise underrun fill, overrun drop-oldest); used by AnchorClient paths.
- **Virtual peer pool** (`_virtualPeerPool`): pre-allocated `POCKETDIAL_VIRTUAL_PEERS`
  `SipClient` shared_ptrs; `allocateVirtualPeer()` recycles by use-count; park and BLF
  use this pool instead of heap-allocating per-call.
- **File-scope static helpers**: `sameAddress()`, `parkTagOf()`, `stripHeaderName()`;
  forward-declared at top of `RequestsHandler.cpp`.
- **`SipMessageTypes`**: `UPDATE`, `SUBSCRIBE`, `BAD_EVENT` constants.

### Added — tests

- `tests/PageZone_test.cpp`: `isPageZoneExt`, `splitZoneMembers`, `joinMembers`
  round-trip and cap tests.
- `tests/PlayoutBuffer_test.cpp`: write/read, underrun/overrun, clear, null-guard,
  target-depth tests.
- `tests/AnchorClient_test.cpp`: `LoopbackAnchorClient` lifecycle, `makeCall` event
  delivery, audio loopback, `dropCall` Dropped event.
- `tests/CMakeLists.txt`: added `PlayoutBuffer.cpp`, `LoopbackAnchorClient.cpp`, and
  the three new test files.

### Fixed (code-review pass — all confirmed during sip-backport review)

- **Broadcast re-INVITE hold triggered first-answer connect path** (`onOk`): the guard
  `state != Connected` was also true for `Held`, so a hold 200 OK re-overwrote the
  established dest and cancelled already-gone pending targets. Changed guard to
  `state == Invited`. (#69)
- **tick()-originated INVITE forks had no Timer A/B coverage** (`tick()`): added the
  same `classifyTxType`/`registerTx` outbox scan that exists in `handle()`, so park
  ring-back, hunt-group next-ring, and CFNA redirect are all registered for RFC 3261
  §17 retransmit. (#70)
- **Park retrieve slot cleared on session-pool exhaustion** (`onParkInvite`): moved
  `allocateSession` before queuing the 200 OK and sending the re-INVITE; returns 503
  and leaves the slot intact if the pool is exhausted. (#71)
- **`sweepSessionTimers` emitted malformed BYE when dialog-To was empty**: added
  `!dTo.empty()` guard to both BYE paths. (#72)
- **`Held` state CDR-logged as Failed with zero duration** (`recordCdr`): added
  `Session::State::Held` to the `Connected`/`Bye` `CdrResult::Answered` case. (#73)
- **`sendParkReinvite` emitted bare Call-ID token** (missing `"Call-ID: "` label):
  single-character fix; RFC 3261 §20.8 violation — phones rejected or dropped the
  retrieve re-INVITE. (part of #68 work)
- **`getPrimaryLocalIP()` called under `_mutex`** in 7 new functions: resolved once at
  construction into `_localIp`; all 20+ `(_serverIp == "0.0.0.0") ? getPrimaryLocalIP()
  : _serverIp` sites replaced. Eliminates a socket/connect syscall from the packet hot
  path. CLAUDE.md §"No blocking I/O under the registrar lock". (#67 follow-on)

### Fixed (pre-existing)

- `onBye` and `onCancel`: spoofed-teardown guard (`isDialogSourceAuthorized`).
- `onCancel`: park-orbit CANCEL now tears down the orbit slot and refreshes the
  dashboard snapshot; paging zone CANCEL now forks correctly (was only handling `999`).
- `onBye`: paging zone BYE now forks correctly (was only handling `999`).
- `onOk`: `handleParkOk` / `handleTransferOk` intercepts added before the session
  lookup; re-INVITE 200 OK relay (hold/resume) added; `setDialogHeaders` +
  `setRemoteSdp` + `armSessionTimer` called on call connect.
- `.gitignore`: `docs/` removed from exclusion list; `LINEAGE.md` and scratch artefacts
  remain excluded.

---

## Unreleased (fix/code-review-hardening) - 2026-06-10

Code-review pass across the cross-platform SIP engine (`src/`) and all four ESP-IDF
entry points (`main/`). Engine changes verified on the host build: clean compile,
113/113 GoogleTest cases, and the `tests/http/test_api.sh` smoke suite. Firmware
changes are compile-gated by the CI ESP-IDF matrix.

### Fixed — engine (`src/`)
- **CRITICAL `getFormParam` token-boundary collision** (`Helpers/HttpServer.cpp`):
  the form parser matched a key as a bare substring, so `getFormParam("…&on=1", "on")`
  could match the `n=` inside `extension=…` and return the wrong value — silently
  **inverting `POST /api/dnd`** when `extension` preceded `on`. Now anchors each match
  to a real parameter boundary (start-of-body or after `&`).
- **`_dummyClient` shared mutable state** (`SIP/RequestsHandler.cpp`): the echo (`777`),
  media (`440`) and `*11`/`*69` star-code paths all reset and shared one
  `_dummyClient`, so a second concurrent virtual call overwrote the first session's
  destination identity. Each dummy session now owns its own `SipClient`; the shared
  member is removed.
- **`440` media answered before the RTP stream started** (`SIP/RequestsHandler.cpp`):
  `onMediaInvite` sent `200 OK` before `RtpSender::start()`, so a socket/task failure
  left the caller in a silently-answered call. Now starts RTP first (→ `500` on
  failure), allocates the session (→ `503` + stream stop if the pool is full), and only
  then sends `200 OK`.
- **Rate limiting serialized on the main registrar mutex** (`SIP/RequestsHandler.cpp`):
  every packet — including ones from already-blocked IPs — took the global `_mutex`
  before being dropped. Per-source admission now runs under a dedicated `_rateMutex`
  *before* `_mutex`, so a flood can't serialize against legitimate signaling.
- **Nonce tag was MD5(secret‖msg), length-extension forgeable** (`Helpers/SipDigest.cpp`):
  replaced with a proper HMAC-MD5 (RFC 2104) over the timestamp.
- **Admin session had no sliding expiry** (`Helpers/AdminAuth.cpp`): an active admin was
  logged out at the absolute TTL mid-session; `validateSession` now extends the deadline
  on each successful check.
- **Port-blind same-origin check** (`Helpers/HttpServer.cpp`): `isSameOrigin` stripped
  ports before comparing; it now also requires the Origin/Host ports to match when both
  are explicitly present.
- Removed the dead no-op `registerClient()` hook and made `setCallState()` return `void`
  (its result was always ignored).

### Fixed — firmware (`main/`)
- **CRITICAL cross-core `g_sipServer` data race** (all four entry points —
  `esp_main.cpp`, `esp_main_eth.cpp`, `esp_main_eth_lan8720.cpp`, `esp_main_display.cpp`):
  the pointer was published by the SIP task and polled by the HTTP/status tasks as a
  plain `SipServer*` with no barrier (stale-null / half-built-object read; hoistable
  poll). Now `std::atomic<SipServer*>` with release-store / acquire-load.
- **CRITICAL DnsServer data race + use-after-free** (`wifi/DnsServer.cpp`/`.hpp`):
  `_running`/`_socketFd` are now `std::atomic`; `stop()` closes the socket once
  (single-owner `exchange`) and joins `dns_task` via an exit semaphore before returning,
  so the object can't be destroyed out from under a running task. Added a 500 ms
  `SO_RCVTIMEO` so the loop observes `_running` without depending on close-unblocks-recv.
- **CRITICAL unbounded `g_sipServer` poll hangs the display dashboard**
  (`esp_main_display.cpp`): `http_server_task` spun forever if the SIP server failed to
  construct (e.g. OOM). Now bounded (~30 s) then self-exits with an error log.
- **HIGH unbounded provisioning spin** (`esp_main.cpp`, `esp_main_eth.cpp`,
  `esp_main_eth_lan8720.cpp`): the "wait for admin credential" loop could hang forever
  with no watchdog; now capped at 30 min, then `esp_restart()` to retry cleanly.
- **HIGH `esp_restart()` racing concurrent flash writes** (`esp_main_display.cpp`):
  the captive-decay reboot now calls `esp_wifi_stop()` to quiesce the radio first.
- **MEDIUM deprecated `esp_event_handler_register`** (`esp_main_eth.cpp`,
  `esp_main_eth_lan8720.cpp`): switched to `esp_event_handler_instance_register` (no
  more duplicate-handler risk on a re-init path), matching the wifi/display builds.
- **MEDIUM ISR-unsafe log hook** (`esp_main_display.cpp`): `screen_log_vprintf` is
  installed via `esp_log_set_vprintf` and can run in ISR context; it now dispatches
  `xQueueSendFromISR` when `xPortInIsrContext()`.
- **LOW** discarded `esp_eth_new_netif_glue`/`esp_netif_attach` returns (eth builds),
  leaked STA/ETH event groups on the failure/fallback paths, and a missing erase/
  wear-leveling contract comment on the raw `prompts` partition (`partitions.csv`).

### CI
- Switched the firmware build matrix to **ESP-IDF v6.0.1 only** — the managed
  components (espressif/w5500, espressif/lan87xx, wolfSSL/wolfSSH) and the source
  guards have moved to the v6 APIs, so the old v5.1.2/v5.2.1 legs no longer build.
  Excluded the meaningless `esp32 + eth` leg (the W5500 default pin maps use
  ESP32-S3-only GPIOs — internal-EMAC Ethernet on the classic ESP32 is the separate
  `lan8720` transport). All three esp32s3 transports (display, eth, wifi) were verified
  building locally on v6.0.1 with these changes (`SipServer.bin` generated for each).
- Suppressed a pre-existing cppcheck `unknownMacro` false-positive on
  `main/ui/ui.cpp` (the LVGL `LV_SYMBOL_RIGHT` glyph macro — cppcheck can't see
  LVGL's headers). This had been failing the host CI job since the Learn-mode
  display work landed; the suppression is scoped to `unknownMacro` on that one file
  so genuine warnings there still fire.
- Cleared the five pre-existing cppcheck `performance` findings that had also been
  failing the host job (real fixes, not suppressions): `SipDigest.cpp` nonce split now
  uses `string_view::substr` instead of pointer/length construction; `SipSecretStore.cpp`
  trims the NVS buffer via `resize(len-1)` + move instead of copying through `c_str()`;
  two `Tui.cpp` self-prefix `substr` assignments became `resize()`; and
  `RequestsHandler::startBroadcastFork` takes its `targets` vector by const reference.
  Host build + GoogleTest suite re-verified green.

### Deliberately not changed (reviewed, declined)
- **RTP task core affinity**: the media TX/RX tasks stay on Core 0 — on the display
  build LVGL owns Core 1, and the existing comments make the placement a deliberate
  choice so the 20 ms RTP cadence isn't stolen by full-screen LVGL blits. Moving them
  would *create* the contention the design avoids.
- **`_messagePool` static storage**: `getMessageFromPool` is a static method called by
  `SipMessageFactory` (which has no handler instance), so the pool must stay static; the
  feared "dangling on handler destruction" doesn't occur (static storage outlives any
  instance).
- **pthread default stack for wolfSSH**: already handled — wolfSSH runs in its own
  explicit 24 KB FreeRTOS task, not a `std::thread` (see `sdkconfig.defaults`).
- A handful of hardware-verified display-timing / PSRAM-routing items were left as-is to
  avoid regressing the validated panel path; see the review notes.

## v1.2.0 - 2026-06-04

Production-hardening + feature release. Verified end-to-end on a JC3248W535
display board (ESP-IDF v5.3.5): builds, flashes, boots, joins Wi-Fi as a client,
serves the dashboard, and handles SIP registration/calls at single-digit-ms
latency.

### Added
- **Admin authentication**: PIN + server-side session layer (salted, iterated
  SHA-256; HttpOnly cookie; brute-force lockout). Dashboard Security panel
  (set-PIN / login / logout) gating every state-changing control. `THREAT_MODEL.md`.
- **OTA firmware updates**: dual-OTA partition table, streaming `/api/ota/upload`
  (bypasses the 16 KB body cap), anti-rollback confirmation on healthy boot, and
  a dashboard Firmware-Update panel. `OTA.md`.
- **Configurable SIP memory pools** (`PoolConfig.hpp`) with 3 documented hardware
  tiers. `SCALING.md`.
- **PBX features**: Call Detail Records (`GET /api/cdr`) and per-extension
  Do-Not-Disturb (`POST /api/dnd`, 480-on-INVITE).
- **Operator docs**: Setup, Hardware-Selection, Phone-Compatibility, Troubleshooting;
  plus server-side RTP design (`RTP.md`) and a technical feature roadmap.
- **SIP load/stress suite** (`tests/load/`) + on-device findings; CI now runs the
  unit suite, a partition-table guard, and a tag-triggered release workflow.

### Fixed
- **Display STA-mode watchdog**: coalesce/rate-limit the on-screen log so a log
  flood can't pin Core 1 on full-screen repaints (task-WDT eliminated).
- **Dashboard unreachable in STATION mode**: the HTTP accept loop's `std::thread`
  had a 3 KB pthread stack that `sendApiStatus` overflowed on-device; raised to
  8 KB and bound the listener to `INADDR_ANY` (robust across AP/STA + DHCP changes).

## Unreleased (fix/esp-idf-ci-failures) - 2026-06-03

### Fixed
- Isolate `esp_wifi` requirement in `main/CMakeLists.txt` to only `wifi` and `display` transport components, ensuring the `eth` transport compiles without wifi dependencies.
- Add `cppcheck` suppressions in `.github/workflows/ci.yml` for third-party QR code files (`qrcode.c` and `qrcode.h`).
- Support compiling under ESP-IDF v6.0+ locally by adding version-conditional CMake target dependencies for the split GPIO and SPI drivers, and adding conditional registry dependency for W5500 Ethernet driver (`espressif/w5500`).
- Resolve application binary partition overflow on local debug configuration by changing the default partition table setting to `CONFIG_PARTITION_TABLE_SINGLE_APP_LARGE=y` (1.5MB).


## Unreleased (fix/cppcheck-warnings) - 2026-06-03

### Fixed
- Resolve cppcheck static analysis warnings and style issues:
  - Initialize `bytesReceived` in `src/Helpers/UdpServer.cpp` to avoid potential use of an uninitialized variable.
  - Add `main/host_compat.h` to provide guarded host-side `MACSTR` / `MAC2STR` macros so host builds and static analysis can process Wi‑Fi event logging without defining ESP-IDF headers.
  - Replace C-style cast with `reinterpret_cast` for `sockaddr` in `main/wifi/DnsServer.cpp` to satisfy cppcheck style checks.

Commit: https://github.com/GlomarGadaffi/pocket-dial/commit/825354bf88afd1fcd965c7ab743999ce10b9e919

### Notes
- `host_compat.h` only defines macros when they are not already defined, so ESP-IDF builds remain unaffected.
- This change targets CI cleanliness and static analysis; runtime behavior on ESP32 devices is unchanged.
