# Federation design for #174: site-to-site peer bridging

Status: PROPOSED, for vote. No code, no PR. Part of #174.
Every file:line is at main `7bcf952f`. Abbreviations: RH = src/SIP/RequestsHandler, CF = src/SIP/CallForker.cpp,
DP = src/SIP/DialPlan.hpp, PC = src/SIP/PoolConfig.hpp, REG = src/SIP/Registrar.cpp, SRC = src/SIP/SipRegistrationClient,
TRK = src/SIP/SipTrunk, PFC = src/SIP/PbxFeatureConfig.cpp, HS = src/Helpers/HttpServer.cpp, EC = src/SIP/EmergencyCall.hpp,
EDT = tests/EmergencyDialing_test.cpp.

## 1. Problem and use cases

The issue: two units, same LAN or a VPN/WireGuard tunnel ("known routable IPs, no STUN/ICE/TURN"), let extensions on
one dial extensions on the other by prefix. Model: B REGISTERs to A; A's DialPlan sends `peer_prefix` to B's Contact; B
delivers locally. Asked for: a UAC REGISTER shared with #164, NVS `peer_uri/user/pass/prefix`, a Peer dial action,
`/api/peers`. It is ported from drawbridge #152. Desmo, 2026-10-09: keep, design first, no PR until agreed.

| Use case in the issue | Verdict | Why |
|---|---|---|
| Multi-site | Hypothetical; the only one the model fits | A VPN/WireGuard link implies two buildings. No site, phone count or call count appears in the issue or its comments. |
| Capacity pooling on one LAN | Hypothetical, and partly served | The cap is a build flag (`-DPOCKETDIAL_MAX_CLIENTS=64`, PC:19, PC:34-36, docs/SCALING.md:164). Two boards give up to 64 phones (62-63 if a peer takes a pool slot). A cross-board call holds a session at both ends (inferred) out of 8 per board (PC:43), so calls do not pool. |
| Primary/standby | Hypothetical, and not delivered by this model | "B registers to A" gives A a route to B. A's phones still register only to A, so nothing fails over, and nothing replicates extensions, secrets or the dial plan. That needs a phone-side secondary registrar plus config sync. Recommend striking it from #174. |

No use case names a deployment. The honest framing is "if a second site appears".

## 2. Current state on main

| Piece | Where | State |
|---|---|---|
| Registrar pool | PC:35 (32; 8 on the constrained build, main/CMakeLists.txt:318); RH.cpp:258-261; `allocateClient` RH.cpp:11194-11229 | Full pool answers 503 (PC:12-14). The Registrar device table has the same cap (REG:475). |
| Dial plan | DP:73-79 `{RingGroup, PageZone, ParkOrbit, Trunk}`; DP:86-92 `DialRule`; 16 rules (PC:192) | Evaluated after the emergency classifier (RH.cpp:2322, then RH.cpp:2751). Dispatch is the switch at CF:429-484 with no default, so an unlisted action falls to the 404 at CF:486-500. Action names: DP:99-118, validated twice (HS:3578-3624, PFC:430-474), replayed from NVS (PFC:643-657). |
| UAC REGISTER class | SRC.hpp; host tests tests/SipRegistrationClient_test.cpp | **It is wired, once.** SipTrunk owns the only instance (TRK.hpp:624), SipTrunk.cpp:1588-1618 drives it, RH.cpp:10426-10438 ticks it when the trunk config is valid. One `SipTrunk` exists (RH.hpp:2523; 55 `_sipTrunk` references). The "not wired" comments are stale (SRC.hpp:9-10, main/CMakeLists.txt:167-171). |
| Shelved trunk | #164 closed (per #942) | `SipTrunk` compiles out when `POCKETDIAL_HAS_TRUNK=0` (PC:317-330), which the constrained build sets (main/CMakeLists.txt:332-341). |
| Inbound by source IP | RH.cpp:2259-2277, `isTrunkSbcSource` RH.cpp:13101-13110 | Delivers only to a DID-mapped, registered extension (RH.cpp:13122-13146). The DID table holds 8 (PC:418-420). |
| Secret handling | `trunk_pass` plaintext in NVS (src/Helpers/TrunkConfigStore.cpp:60,84) | Kept out of getters (TRK.hpp:152-167), out of the plaintext backup (HS:5769-5771), wiped by factory reset (HS:4640-4655). The registrar side stores HA1 only (src/Helpers/SipSecretStore.hpp:10-16). |

Missing (zero hits repo-wide for `peer_uri|peer_user|peer_pass|peer_prefix|api/peers|federat|DialActionType::Peer`):
- **A peer dial action.**
- **Peer identity.** Nothing marks a registered AOR as a peer; every pool entry is a phone (RH.cpp:2615-2621).
- **Peer credentials.** No NVS keys. A per-extension HA1 slot exists (extension name at most 11 chars, SipSecretStore.hpp:41).
- **An INVITE that keeps the dialed digits.** `buildInviteFork` sets Request-URI and To to the target's registered AOR
  (CF:35-36), so it and `redirectInvite` (CF:150-196) both lose them. B reads the To user, then the Request-URI user (RH.cpp:13114-13119).
- **A non-trunk UAC**, and **a re-register signal**: `start()` is a no-op while Registered and `stop()` does not
  de-register (SRC.hpp:209-219).

## 3. Options

### 3.0 What a peer costs if it lives in the client pool (Options 1, and 2 if so built)
- 1 of 32 `_clientPool` slots (3.1%); 1 of 8 on the constrained build (12.5%). `SipClient` is ~100 B (docs/SCALING.md:60, a doc figure).
- 1 row in the 32-row device table (REG:475). Whether a routed source gets a row (no ARP, so no MAC, REG:393-394) is unverified.
- Every 999 all-page forks an INVITE to it (RH.cpp:2609-2621), one message-pool slot per page.
- OPTIONS ping every 5 s (RH.cpp:11032), pruned after 15 s of silence even with a valid lease (RH.cpp:9034, 9079), calls included.
  B answers OPTIONS from anyone (RH.cpp:1712-1725), so the ping works.
- Default Learn mode (REG:106) is trust-on-first-use and never locks a routed source (REG:393-394). The peer must be pre-provisioned
  Secured; a Secured extension is digest-enforced even in Learn (REG:413-416).
- PC:146-157 already argues service endpoints must not sit in this pool (roster, Learn adoption, capacity).
- Alternative: a dedicated one-record peer table. 0 slots, but a new branch on the REGISTER path, the most security-sensitive code here.

### Option 1: as filed
B registers into A's pool. A to B forwards to B's binding. B to A needs B to place an INVITE to A with digest, so
a trunk-style UAC.
- Slots: 1 at A (A has 31 phones, B 32: 63 total). Credential: plaintext `peer_pass` on B, HA1 at A.
- B-side UAC: a second `SipTrunk` (55 references to touch) or generalising it to N. Either way 2 concurrent calls (PC:310-312),
  PCMU-only raw relay (RH.cpp:13142), absent on constrained builds, and it re-opens the trunk line that was shelved (main/CMakeLists.txt:321-323, 339-340).

### Option 2: mutual registration, thin link
Each unit REGISTERs to the other. A new `PeerLink` wraps one `SipRegistrationClient`. Every call in both directions is
"forward the INVITE to the peer's address"; no INVITE UAC and no `SipTrunk`.
- Slots: 0 with a dedicated peer record, 1 per unit in the pool (62 phones total). Credential: two secrets, each unit holds one plaintext and one HA1.
- B-side UAC: `PeerLink` ticks from the site that ticks the trunk (RH.cpp:10426-10438); `tick()` returns bytes and touches no
  socket (SRC.hpp:17-30). ~3 KB by summing field sizes (SRC.hpp:64-313; not measured). Needs a "binding lost" re-arm API.

### Option 3: static peer, IP-pinned, no registration
The peer is a dotted-quad host:port in NVS (the issue already assumes known IPs). Both directions forward to it; inbound is
accepted by source IP, as the trunk does (RH.cpp:13101-13110). Liveness by a periodic OPTIONS probe.
- Slots: 0 (64 phones total). Credential: none. B-side UAC: none. Touches nothing on the REGISTER path.
- Gives up: a moving peer address, digest authentication, and "registration-based" in the title.

### 3.1 The credential on an open LAN (Options 1 and 2)
- At rest: plaintext in NVS like `trunk_pass`, readable from flash; no flash encryption or Secure Boot by default (docs/THREAT_MODEL.md:99, 157).
  Three tests, each already a precedent for the trunk: no getter returns it, the backup keeps it out of plaintext, factory reset wipes it.
- On the wire: UDP digest, no SRTP (#180 dropped per #942). A sniffer gets challenge/response pairs and can guess a weak MD5 secret
  offline. A generated 24-char secret (~138 bits, SipSecretStore.hpp:43-47) cannot be. Generate it; never accept a typed one.
- Theft buys: registering as the peer, which receives every call sent to the peer prefix, and placing calls into that site.
- Option 3 has nothing to steal but trusts the source IP, forgeable on an open LAN: the same strength as the shipped caller binding
  (RH.cpp:2371) and SBC pin. Over WireGuard the source IP is key-bound (a WireGuard property, not checked here).

### 3.2 Liveness (Options 1 and 2)
A prunes at 15 s. `SipRegistrationClient` refreshes at 90% of the granted lease (SRC.cpp:566): 3240 s at the 3600 s default
(SRC.hpp:81). A 20 s outage can leave the peer unreachable for up to 54 minutes. Needs a lease of 60 s or less and a binding-lost re-arm.

### 3.3 Media
The issue says "phone-to-phone when reachable, else MediaBridge". MediaBridge cannot carry DTMF (TRK.hpp:26-42); the relay that exists is
the raw RTP relay: 2 pairs (PC:310-312, RH.cpp:12985-12991), shared with PSTN trunk calls. So the first slice has no relay, and
cross-site audio works only when the phone subnets can reach each other.

## 4. Rule 5: 911 and 933 never reach a peer

Statement: 911, 933, 9911 and 9933 are never sent to a peer, and no peer pattern can capture them.

- **C1, exists, runs first.** `classifyEmergencyDial(destNumber)` at RH.cpp:2322 is an exact match on those four strings
  (EC:93-128) and returns into `routeEmergencyCall` before the dial plan at RH.cpp:2751. Even a catch-all `*` never sees them
  (RH.cpp:2741-2750; EDT:303).
- **C2, new, config time.** The three entry points (HS:3578-3624, PFC:430-474, NVS replay PFC:643-657) refuse a Peer rule where
  `peerPatternCapturesEmergency(p)`: `dialPatternMatches(p, s)` for any `s` in the four, built from `kEmergencyNumber`,
  `kEmergencyTestNumber` and `kTrunkAccessDigit` (EC:67-71), not literals. Refused: `*`, `9*`, `XXX`, `9XX`, `9XXX`, `X11`.
  Accepted: `8*`, `8XX`. Cost: no catch-all peer.
- **C3, new, same validators.** Peer rules carry `stripDigits` 0 and no prepend (PFC:474 already zeroes it for non-Trunk);
  the target is a peer name, never digits. So the digits a peer receives are the digits C1 cleared. The hole would be a transform:
  both emergency mirrors are Trunk-only (CF:367, RH.cpp:5014). **Hard stop: any later slice that adds a transform extends both in the same PR.**
- **C4, new, dispatch backstop.** The Peer arm runs `classifyEmergencyDial` on the exact digits it would send. A positive is
  never sent; it diverts to `routeEmergencyCall` as `routeTrunkCall` does (RH.cpp:13082-13088). Unreachable by C1 and C3; kept for
  the reason RH.cpp:13075-13081 gives.
- **G1, B side, open, not decided here.** Trace (by reading): an INVITE from the peer, To `911`, From equal to one of B's registered
  extensions (both sites have a 101). It skips the trunk-inbound catch (RH.cpp:2272), finds the caller (RH.cpp:2257, 2279), hits
  the emergency branch (RH.cpp:2322), and routes as B's 101 dialing 911 under B's location. The source check sits after it by design
  (#454; EDT:234-248). Federation did not create this, but a peer link gives it a named source. The first branch of
  `isPsapCallbackTo` is also source-blind (RH.cpp:4984-4988). Any B-side slice is blocked on desmo's answer to poll 2.

## 5. Recommendation

**Option 3 first, Option 2 as the upgrade if a moving address or authentication is proven needed, Option 1 dropped.**
- The stated network is known, routable IPs; static fits it. Registration's gains (moving address, digest, liveness) are not in any stated requirement.
- 0 slots, 0 credentials, 0 UAC, and the registrar is untouched.
- The Peer action, the inbound filter and the digit-keeping INVITE builder are common to every option, so Option 2 later only changes where the address comes from.
- Option 1 needs a second `SipTrunk`, a 2-call cap, and the shelved line.

**Slice 1: A side, no network, host-testable.** `DialActionType::Peer` in DP; name/parse (DP:99-118); `peerPatternCapturesEmergency`;
C2 and C3 in the three validators; a Peer case in the CF:429-484 switch carrying C4; tests. `peer` parses only under
`POCKETDIAL_PEER` (default 0; host tests 1), so no shipped build can create a rule that can only answer 404 (CF:486-500).
It does not: send anything to a peer, REGISTER, store a host or credential, accept a peer INVITE, relay media, or add `/api/peers`.
Its value is that the Rule 5 gate exists and is tested before any code can send. Not worth merging alone unless slice 2 is wanted.

**Slice 2: static peer, both directions.** Needs a named site and G1. Adds `peer_host/port/prefix` (and an enable flag), the digit-keeping INVITE
builder, an inbound path that delivers only to a registered, non-reserved local extension and never reaches the dial plan (so a peer can
never dial out the trunk or 555), a 503 when the peer is down, OPTIONS probe, and `/api/peers` (`requireAdmin`; CONTRIBUTING_FIRMWARE.md:24-30:
`needCsrf`, fall-through gate, central response path, docs/API.md and API_TESTS.md in the same PR). **Slice 3 (optional):** Option 2.
Federation is a non-constrained feature: PC:332-334 says that slot has ~1.5 KB left, so gate it off there.

## 6. Test plan

Host-testable (names follow EDT):
- DP: `Peer` name/parse round trip; unknown names still rejected; `peerPatternCapturesEmergency` table (refuse `*`, `9*`, `XXX`, `9XX`, `9XXX`, `X11`, `911`, `9933`; accept `8*`, `8XX`, `801`).
- PFC: HTTP, `setDialRule` and NVS replay each refuse a capturing pattern and force `stripDigits` 0; a hand-edited blob cannot smuggle one.
- CF/RH, with a loopback peer: with `8*` and a catch-all Peer rule, dialing 911/933/9911/9933 produces zero bytes to the peer and the existing emergency answer (cf. EDT:303, EDT:349 expects 503 with no trunk).
- Inbound (slice 2): peer-source INVITE to 911/933/9911/9933 follows poll 2's answer; to 777/999/888/555/440/796/997 is refused; to an unknown ext is 404;
  to a registered ext rings; with SBC mode on and a `*` Trunk rule, nothing reaches the trunk. A third address with peer headers is refused (cf. TrunkInbound_test.cpp:285, 378-383).
- Digit-keeping builder: To and Request-URI user equal the dialed digits.
- Credentials (Option 2 only): GET omits it, backup omits it, factory reset wipes it. `SipRegistrationClient` is already host-tested; `PeerLink` adds fake-clock re-arm tests.

Bench (hardware, operator allocates boards). For Rule 5 steps: no trunk, no anchor and no emergency-notification recipients on either
unit (an unrouted 933 still fires `notifyEmergencyNotRouted`, RH.cpp:13049-13061, TEST-tagged), 933 only and never 911, and desmo's go-ahead before any dial:
1. Both directions: two-way audio, RFC 4733 DTMF, hold/resume, BYE from each side, a call past the session timer.
2. Media: phone subnets routed (direct) versus tunnel-only (shows whether a relay is needed).
3. Faults: 20 s link drop idle and mid-call; peer reboot; peer IP change. Record time to recover.
4. Rule 5 on the wire: pcap both units while a phone on A dials 933 with `8*` configured. Expect 503 from A and zero packets to B's 5060.
5. Load: 8 local calls plus a peer call; compare `msgPoolRefusals` and free heap/PSRAM before and after.
6. Abuse: sipp from a third host spoofing the peer IP at B with To 555/999/888. Expect refusals, no session. A spoofed 933 follows poll 2's
   answer (today it routes as an emergency call under a matching From, G1), so run it only after that answer.

## 7. Decision asked

**Poll 1, direction.**
- (a) Static peer first (Option 3); registration only if a moving address or authentication is proven needed. **Recommended.**
- (b) Registration from the start (Option 2).
- (c) Stop at this document until a second site is named; merge nothing.

**Poll 2, gate for any B-side code (desmo only).** A peer-sourced INVITE to 911/933 with a From matching a B extension routes as that
extension's emergency call today (#454).
- (i) Leave it; the peer is no worse than any LAN host.
- (ii) Refuse it when the source is a configured peer. A peer never legitimately sends one (C1), so no real call is lost, but it is the first
  exception to "911 is never gated". **Recommended, but it moves the Rule 5 line, so it is his call.**

## 8. Not verified

- Nothing was built or run; every claim is from reading source at `7bcf952f`. The G1 trace is by reading, not by a test.
- drawbridge #152 was not read (other repo).
- Whether a routed peer takes a Registrar device-table row; whether the ordinary call path forwards SDP untouched for an off-subnet Contact.
- Two sessions per cross-board call is inferred. RAM: ~100 B per `SipClient` is SCALING.md's figure; ~3 KB for `PeerLink` is my sum of fields; neither measured.
- The "~1.5 KB left" on the constrained slot is a code comment's claim (PC:333). Flash headroom elsewhere is unchecked.
- WireGuard's source-IP binding is from general knowledge, not this repo.
