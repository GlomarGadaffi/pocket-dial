# Design: an ingress filter below lwIP for source authenticity and flow membership (#1050)

This note proposes a small filter that runs on each received Ethernet frame, before lwIP builds a pbuf. It holds packet-level facts the SIP layer cannot establish for itself: who actually sent a frame, whether it belongs to a live flow, and which flows must never be starved. It also says what stays in the SIP layer, how the filter keeps Rule 5 safe, and how to stage it.

Status: Proposed, for vote. Design only: no source, no tests, no hardware. Nothing here is measured on a board.

Rule 5, as this note uses it: nothing may gate, delay, refuse or misreport a 911/933 call or a PSAP callback.

## 0. How to read this

Read against `origin/main` at aba88d46. `RH.cpp` = `src/SIP/RequestsHandler.cpp`, `RH.hpp` = `src/SIP/RequestsHandler.hpp`. Prior art outside this repo is `ESP32_AdBlocker_Reborn` at 35d72d0; `AB:` below means that repo.

Tags:

- **[verified]** read in the code at the cited line.
- **[inferred]** follows from the code plus a property of ESP-IDF that was not run here.
- **[unverified]** not checked. Section 12 collects these.

## 1. Why this exists

Every source-address check in `RequestsHandler` assumes a UDP source IP cannot be forged:

- `sameAddress()` compares IP and port (RH.cpp:12456-12459) [verified].
- `isDialogSourceAuthorized()` compares the source IP against the two leg IPs of a dialog (RH.cpp:12982-13008) [verified].
- The per-source limiter is keyed by source IP: `allowPacket()` (RH.cpp:12372-12402), the registered-source slots (`RateSource`, RH.hpp:3336-3355), and #1114's reserved slots and emergency budget [verified].

On a LAN that assumption is false. Any host on the segment can put any IPv4 source address in a UDP datagram. #1114's own residual notes say so: a spoofer forging a registered handset's IP drains that handset's own budget. The SIP layer cannot fix this, because by the time `handle()` runs, the Ethernet header is gone and the only identity left is the claimed IP (RH.cpp:932).

The existing IPv4 guard has the same blind spot. `LWIP_HOOK_IP4_INPUT` (`main/pd_lwip_hooks.c`, wired by CMakeLists.txt:26-33) runs on all four variants, but it sees the IP header only. It can judge frame shape (`Ip4InputGuard.h`), not who sent the frame [verified].

An L2 filter sees the frame's real source MAC. That is the one extra fact that makes the checks above checkable.

What an L2 filter does not do: it does not authenticate anything cryptographically. A host that copies both the IP and the MAC of a phone defeats it. The goal is narrower: stop a host that only changes the IP field from being charged as the real device. Section 8 lists the cases where it cannot help.

## 2. Invariants only L2 and L3 can hold

These are facts about packets, not about calls.

1. **Source authenticity.** An IP to MAC binding (and optionally the UDP source port) is learned when a REGISTER authenticates. A later frame whose source IP matches a fresh binding but whose source MAC does not is unbound: it may be a forger or a replaced device, and L2 cannot tell which (section 4, rule 1).
2. **Flow membership.** The 5-tuples (proto, remote IP, remote port, local IP, local port) of live dialog legs and of negotiated media. A frame can be classified as belonging to a live flow without parsing SIP.
3. **Ingress priority.** The tuples of a live 911 or 933 call or PSAP callback (callback window: EmergencyCall.hpp:130-162), on the handset side and on the provider side, get a reserved path that a flood on other tuples cannot starve (section 7 gives the two ways to build it). While an extension's callback window is open, its bound IP counts as an emergency IP even before a callback arrives.
4. **Egress.** Egress frames are cross-checked against the flow table, as defence in depth. On the Ethernet variants every media frame already funnels through `EthAccess::transmitL2()` (EthAccess.hpp:31) and `l2rtp::EgressChannel`, so the check has one place to live [verified]. The Wi-Fi variants send media with `sendto()` (RtpSender.cpp:525, :728) and would check in the sender instead [verified]. A miss is counted; stages 1 to 3 never refuse an egress frame.

## 3. What stays in the SIP layer

The SIP layer decides identity and method authorization within a source that is already legitimate at the packet level: who this extension is, and whether it may use this method on this dialog. None of that can move below lwIP, because it needs parsed headers, dialog state and the registrar.

Recommendation: one authorization gate at the top of `handle()`, after the admission block (RH.cpp:960-974) and before handler dispatch (RH.cpp:1177). One authorization point is easier to keep correct than many. A single gate:

- takes the parsed message and the source, plus the L2 verdict when one exists;
- answers one question: may this source use this method on this dialog;
- is the app-layer partner of the L2 filter. L2 says "this frame really came from the device bound to that IP". The gate says "that device may do this".

The gate is not part of this note's staging. It is listed so the two halves are designed together: once L2 vouches for the source, the gate can use that fact.

## 4. Proven or defer

This is the Rule 5 safeguard. The filter has two outcomes for a frame: act on a verdict it can prove, or hand the frame to the normal path unchanged. The SIP layer's admission decision stays authoritative for everything the filter cannot prove from the Ethernet, IP and UDP headers alone, because L2 does not parse SIP.

Rules:

1. **A MAC mismatch means unbound, never forged.** A frame whose source IP has a fresh binding but whose source MAC differs is treated as coming from an unbound source: it is counted as `mismatch`, charged to the shared unbound budget in the filter's shadow accounting, and deferred to the SIP layer. After a DHCP reassignment, the new device's first 911 INVITE carries a mismatched MAC; it must be treated exactly as any unregistered source's 911 INVITE is today, so it is never dropped on that evidence. The source stays unbound until a fresh authenticated REGISTER rebinds it.
2. **A missing or stale entry always defers.** No binding, an expired one, a binding flagged as router-learned, a full table, an unreadable snapshot: all defer to the slow path, which behaves exactly as it does today.
3. **Nothing that is, or may be, emergency traffic is dropped by any L2 rule.** No L2 rule drops a frame from a bound source, a frame matching a live 911, 933 or PSAP-callback tuple, a frame from or to an IP with an emergency flow or an open callback window, or any frame to the SIP port that the filter has not parsed as something else. The one exception is the CIDR allowlist, which refuses the same frames today in the same way (stage 3); it is not evidence-based. Everything else is prioritised, counted, or deferred.
4. **Every L2 drop is counted on `/api/status`.** The precedent is `ip4Guard` (HttpServer.cpp:2536-2544, counters from `pd_ip4_guard_counts()`, pd_lwip_hooks.c:21-26) [verified]. Defers and would-drops are counted too, by reason, so a bench run can say what the filter would have done.
5. **A frame that could refresh a binding is never dropped on a mismatch.** A replaced phone keeps its IP, has a new MAC, and must be able to re-register. A REGISTER from a mismatched MAC defers; the SIP layer authenticates it and, on success, rebinds.
6. **L2 has no bucket authority.** Bucket exhaustion never causes an L2 drop. The filter keeps shadow counters and marks, and the SIP layer's own admission decision stays the only one that refuses a frame for rate. The allowlist is the one policy test both sides run, from one shared pure function.

### 4.1 Prior art: the AdBlocker L2 hook

`ESP32_AdBlocker_Reborn` already runs an L2 hook on its W5500 build. Pocket-dial adopts these five rules from it.

| Rule | Where it is stated | What it says |
|---|---|---|
| The hook never blocks | AB:main/blocklist.c:1218-1222; AB:main/blocklist.h:109-114; AB:main/dns_sink.cpp:1449-1451 | The hook-side verdict takes its lock with a zero wait (AB:main/blocklist.c:1231) and defers when it cannot. |
| It returns a proven verdict or defers | AB:main/blocklist.h:101-114; AB:main/dns_sink.cpp:1381-1388, :1730-1736, :1876-1879; AB:main/dns_sink.cpp:1832 | Every `break` hands the frame to lwIP unchanged. Table busy, a reload underneath the walk, and "cannot classify" are all defers, each counted separately. |
| One verdict function serves the hook and the socket path | AB:main/blocklist.h:125, :213-215; AB:main/blocklist.c:1279; AB:main/dns_sink.cpp:1666-1669 | The bool wrapper, the socket path and the hook share one ranked verdict, and one qname parser. The comments name the hand-copied ladder as the defect this removed. |
| IRAM only, never touching flash | AB:main/dns_sink.cpp:1671-1676, :1714; AB:main/domain.c:6-11, :27-30, :90-95 | The callback is `IRAM_ATTR`, and so is every function it reaches, because esp_eth calls it through a stored pointer. |
| The ring drops and counts, and never blocks | AB:main/dns_sink.cpp:1415-1420, :1449-1455, :1503 | A full log ring drops the entry and bumps a counter. The hook never waits on the consumer. |

Two further points from the AdBlocker hook apply here. It reads the frame's own lengths and refuses to guess (AB:main/dns_sink.cpp:1738-1753). And it installs itself after the netif exists (AB:main/dns_sink.cpp:1988), which pocket-dial must also do (section 5).

Pocket-dial already has the same shape for the IPv4 guard: the decision is a pure, host-tested function (`pd_ip4_input_verdict()`, Ip4InputGuard.h:58) and the hook file "only applies it" (pd_lwip_hooks.c:1-5). `tools/check_lwip_ip4_hook.cmake` fails the build if lwIP's object does not reference the hook [verified]. The L2 filter should copy that structure: a pure verdict header that the host suite pins branch by branch, a thin applier, and a build-time check that the hook is wired.

## 5. Per-variant hooks

`ci.yml` builds the four `esp_main*.cpp` variants through `SIP_TRANSPORT` (`build-esp-idf`, matrix entries `wifi`, `eth`, plus the `display` and `lan8720` include legs; ci.yml:597-640) [verified]. `main/CMakeLists.txt:30-89` maps each value to its source file [verified].

| Variant | Link layer | Hook | Evidence |
|---|---|---|---|
| `esp_main_eth.cpp` (`SIP_TRANSPORT=eth`) | W5500 over SPI, MACRAW. Boards: LilyGO T-ETH-ELITE S3 and Waveshare ESP32-S3-ETH | `esp_eth` input-path hook | esp_main_eth.cpp:132, :146, :390, :401, :710, :716; main/CMakeLists.txt:30-36; sdkconfig.defaults:87-88, :207 |
| `esp_main_eth_lan8720.cpp` (`lan8720`) | Internal EMAC plus LAN87xx PHY on the classic ESP32. Board: LilyGO T-Internet-COM | `esp_eth` input-path hook (same API) | esp_main_eth_lan8720.cpp:216, :232, :238, :243, :500, :506; main/CMakeLists.txt:59-81 |
| `esp_main.cpp` (`wifi`) | Wi-Fi, SoftAP or STA | netif or lwIP input hook | esp_main.cpp:121, :124, :157 (AP); :192, :195, :228 (STA); main/CMakeLists.txt:241-245 |
| `esp_main_display.cpp` (`display`) | Wi-Fi, SoftAP or STA, on the Guition JC3248W535 | netif or lwIP input hook | esp_main_display.cpp:378, :393 (AP); :401, :407 (STA); :879; main/CMakeLists.txt:82-87 |

Notes, in order of how much they matter.

- **The two Ethernet hooks are one API.** `esp_eth_update_input_path()` or its `_info` variant (`esp_eth_driver.h:276-304`) installs a callback that receives the raw frame before any pbuf exists. W5500 and EMAC differ in the RX context that calls it (an SPI-driven driver task for W5500, a DMA-driven one for EMAC), not in the hook [inferred]. The driver's mediator falls back both ways: `eth_stack_input()` uses the info variant if only that is registered, and `eth_stack_input_info()` uses the plain one (`esp_eth.c:101-124`), and the netif glue itself registers the `_info` form (`esp_eth_netif_glue.c:69`) [verified]. Either variant therefore works on both MACs; use the plain one.
- **Install order matters.** The netif glue installs its own input path inside `esp_netif_attach()` (`esp_eth_netif_glue.c:69`), so the hook must be installed after `esp_netif_attach` (esp_main_eth.cpp:716; esp_main_eth_lan8720.cpp:506) or it is overwritten [verified]. `git diff v6.0.1 HEAD` over `esp_eth.c`, `esp_eth_netif_glue.c` and `esp_eth_driver.h` in the local ESP-IDF checkout is empty, so CI's v6.0.1 matches [verified]. The hook forwards a deferred frame with `esp_netif_receive()`, as the glue does (AB:main/dns_sink.cpp:1913). What the hook does not forward it must free; the glue frees with `free()` (`esp_eth_netif_glue.c:46-49`).
- **A frame is already allocated.** `Ip4InputGuard.h:12-17` records that W5500, EMAC and the Wi-Fi driver all allocate the frame's own length before any hook runs. An L2 drop frees early; it does not avoid the driver's RX allocation. Only the driver's ring depth bounds that. The filter therefore reduces what a flood costs lwIP and the SIP task, and does not by itself prevent memory pressure at the driver [verified from the comment].
- **Wi-Fi is the weak case.** Neither Wi-Fi variant has an esp_eth handle. The existing lwIP IPv4 hook sees no Ethernet header. Two ways to get the source MAC are open: a netif-level input wrapper installed on the STA or AP netif, or `esp_wifi_internal_reg_rxcb()` (`esp_private/wifi.h:248`, a private header). The second is early but unsupported API. Choosing between them is open question 1. Until it is answered, the Wi-Fi variants get the stage 1 counters from the lwIP hook that already exists, and no source binding.
- **SoftAP is the strongest Wi-Fi case.** The ESP is the only L2 hop, so the MAC the radio reports is the sender's. In STA mode, phones behind a router arrive with the router's MAC (section 8).
- **Two variants have no Wi-Fi at all.** `eth` and `lan8720` do not define `POCKETDIAL_HAS_WIFI` (main/CMakeLists.txt:241-245), so the L2 filter is the only path there [verified].
- **The sdkconfigs do not name the EMAC.** `sdkconfig.defaults` names the W5500 (`:87-88`) and nothing for the internal EMAC; the code and `CMakeLists.txt` select it [verified].

## 6. Where the binding comes from

The binding is learned from the frame's own source MAC at the hook.

The hook sees every frame's source MAC. It records, in the frame-verdict ring (section 9), the MAC of any SIP-port frame that begins with a REGISTER request line, together with the frame's identity: source IP, source port, IP identification and UDP checksum. When the SIP layer authenticates a REGISTER, it looks up the ring entry for that exact datagram and binds the source IP to the MAC of the frame that carried it, then arms the entry. It never binds to "the last MAC seen" for an IP, because a later frame from another host could race that value. If no ring entry matches (the ring was full, or the entry was overwritten), nothing is armed and the next REGISTER tries again. A binding that no authenticated REGISTER has armed is never used to drop.

Refresh: each authenticated REGISTER re-arms the binding and resets its age. An entry that has not been refreshed within the registration's granted expiry is stale and defers.

## 7. Ingress priority

The hardest piece, and the one this note does not settle. SIP signaling arrives on one UDP socket (created at `src/Helpers/UdpServer.cpp:45`, bound at :76, receive buffer sized at :65 through `udprcvbuf::set()`, UdpRcvBuf.hpp), received by one task (`UdpServer.cpp:151`) [verified]. Anything admitted at L2 shares that socket's receive buffer and that task. So "a reserved path" means one of two things.

- **Option A: watermark shedding.** At L2, count frames queued toward the SIP socket (or use the receive buffer's state). Above a watermark, shed non-emergency traffic at L2. Emergency tuples and bound registered sources are never shed. Cheap and stateless, but "reserved" is only as good as the watermark; it still shares the queue.
- **Option B: a side ring.** The hook copies emergency-tuple frames into a small fixed ring that the SIP task drains first. A real reserved path, but it needs a second consumer path in the SIP task, and the frame must not be delivered twice.

Both keep rules 2 and 3 of section 4: neither ever drops an emergency frame. Option A is the stage-1 default. Option B is open question 2.

An emergency call's first INVITE has no tuple yet. It is protected the way #1114 already protects it at the SIP layer: a registered, bound source keeps its own bucket and emergency budget. At L2 that is the reserved slot for a bound source, not a flow match.

## 8. Failure modes and mitigations

| Failure | What happens | Mitigation |
|---|---|---|
| **Routed or remote handset.** The frame's source MAC is the router's, for every host behind it. | One MAC would be bound to many IPs. A "mismatch" would be meaningless. | When the learned MAC is the gateway's (`EthAccess::getLocalIpInfo()`, EthAccess.hpp:36), or one MAC is bound to more than one IP, the entry is flagged router-learned and always defers. The same holds for any source off the local subnet (an on-link test against the interface subnet). |
| **DHCP reassignment, or a replaced phone.** A stale binding: same IP, new MAC (or the reverse). | The real phone is treated as unbound for a while. | Re-arm on every authenticated REGISTER (section 6). REGISTER from a mismatched MAC always defers (rule 5). A mismatch is never a drop on the SIP port, and stage 2 is a defer-and-count period before stage 3 arms anything. Entries expire at the registration's expiry. |
| **Wi-Fi roaming.** A station keeps its MAC across a roam, so the binding survives. | The stale case is a lease change after roaming to another subnet. | The same mitigation as DHCP: a new lease means a new REGISTER, which re-arms. In SoftAP the ESP is the only L2 hop, so the binding is strongest there. |
| **TLS and TCP.** | The filter cannot read inside TLS, and TCP flows have no per-packet SIP meaning. | Only tuples apply: the filter can say a TCP segment belongs to a known flow, and nothing about its content. No TLS or TCP drops are proposed. |
| **The state-copy update window.** The SIP task writes binding and flow tables while the hook reads them. | A torn read could look like a mismatch. | Two banks and a sequence number. The writer fills the inactive bank, then flips an index with release ordering. The hook reads the index, reads the bank, re-reads the index, and defers if it changed or was odd. Any window resolves to defer, never to drop. This is the same pattern as AB:main/blocklist.c:1248, which re-reads the snapshot pointer after the walk. |
| **Table full.** | A source with no slot. | Defers. Never evicts an armed entry for an unarmed one. |
| **A host that copies IP and MAC.** | Passes. | Out of scope. A MAC can be spoofed too. The filter only helps against a changed IP field. |
| **Hook latency.** | The hook runs in the driver's RX context. | It must stay allocation-free, lock-free, and bounded: a handful of table compares per frame. No measurement exists (section 12). |

## 9. Memory

No heap after init. Every table is fixed at build time and sized from the pools the code already has. All of it is internal DRAM: the hook runs in the RX path and the AdBlocker rule is that its scratch stays internal (AB:main/dns_sink.cpp:1411-1413). None of it goes to PSRAM.

| Table | Entries | Bytes each | Total | Basis |
|---|---|---|---|---|
| Binding (two banks) | 32 x 2 | 28 | 1,792 B | `POCKETDIAL_MAX_CLIENTS` = 32 (PoolConfig.hpp:34-35). Fields: IP 4, MAC 6, port 2, state 1, flags 1, pad 2, refresh time 4, two counters. Two banks for the update window |
| Flow (two banks) | 64 x 2 | 16 | 2,048 B | Four legs per session (two SIP, two media) x `POCKETDIAL_MAX_SESSIONS` = 8 (PoolConfig.hpp:42-43) is 32; the rest covers anchor media (the anchor allows 4 calls, two LAN sockets each) and paging, MoH and conference legs. Fields: remote IP 4, remote port 2, local port 2, proto 1, kind 1, emergency flag 1, pad 1, expiry 4 |
| Shadow source counters | 256 | 12 | 3,072 B | Mirrors the 256-entry cap of `_rateBuckets` (RH.hpp:3306; RH.cpp:12388-12394) [verified]. The filter's copy is fixed and heap-free. Fields: IP 4, last-seen time 4, shadow tokens 2 (fixed point), pad 2 |
| Shadow bound-source counters | 32 | 24 | 768 B | Mirrors `RateSource` (RH.hpp:3336-3355): ordinary and emergency shadow bucket per registered source |
| Frame-verdict ring | 32 | 20 | 640 B | One entry per recorded frame: source IP 4, source port 2, IP identification 2, UDP checksum 2, source MAC 6, verdict 1, flags 1, pad 2. Single producer (the hook), single consumer (the SIP receive task) |
| Counters | about 16 | 4 | 64 B | Drops and defers by reason |

Total: about 8.4 KB of internal DRAM, 0 B PSRAM. For scale, `DmaFramePool` is about 3.3 KB (DmaFramePool.hpp:32). The constrained 4 MB build (`sdkconfig.defaults.esp32_constrained`) has the least DRAM, and its free DRAM at the point the tables are allocated was not measured here [unverified]. If it is tight, stage 1 alone is about 3.9 KB and stage 2 adds the rest.

Concurrency, with no locks in the hook. The hook writes three things: the shadow counters (sole writer; relaxed 32-bit atomic increments, read by the `/api/status` handler with relaxed loads, as `pd_ip4_guard_counts()` does); the frame-verdict ring (single producer, single consumer: head and tail indices with release stores and acquire loads, a full ring drops the new entry and counts it, as the AdBlocker ring does, AB:main/dns_sink.cpp:1444-1455); and nothing else. The SIP receive task is the ring's only consumer and reads it for two purposes: the REGISTER MAC at arming (section 6) and the per-frame verdict at admission (stage 3). The SIP task is the sole writer of the binding table, the flow table with its emergency flags and callback-window IPs, and the allowlist pair (net, mask); the hook reads them through the two-bank scheme in section 8 and defers on any change. The SIP layer's own authoritative buckets stay under `_rateMutex` and are never read by the hook.

## 10. A staged plan

Each stage has an exit test. Rule 5 means no 911 or 933 is ever dialed on a board (#1050's release gates); every emergency-reserve exit test is a host test. Bench exit tests use ordinary calls under a spoofed flood, with the counters read from `/api/status`. No stage arms a drop until the stage before it has run in count-only mode and passed its exit test.

### Stage 1: shadow accounting below lwIP (count and mark only)

Mirror the CIDR allowlist (`ipAllowed()`, RH.cpp:12207-12212) and the per-source budgets (`allowPacket()`, RH.cpp:12372-12402, `takeToken()`, RH.cpp:12361) below lwIP, as shadow accounting. For each IPv4 UDP frame to the SIP port, the hook computes what the allowlist and a shadow bucket would have decided, increments a counter, and defers. It drops nothing and changes no outcome. The SIP layer's admission decision (RH.cpp:960-974) stays the only one that refuses a frame.

This is deliberately weaker than moving the limiter. The admission decision has rescues that run after the bucket is consulted, and an L2 drop on bucket exhaustion would refuse frames before those rescues, including the first 911 INVITE from an unregistered source when the table is full. Moving the limiter would need SIP parsing at L2 to tell that traffic apart. That is out of scope here: it puts a parser in the RX context with no heap, and the parser would have to track the SIP layer's classification exactly or the two would diverge. Open question 3 asks whether it is ever worth it.

What stage 1 buys: the first real data on what an L2 filter would see (flood shape, per-source rates, would-be allowlist refusals), and the table and hook plumbing that stages 2 and 3 need.

On the Ethernet variants this is the esp_eth hook. On the Wi-Fi variants it runs where the IPv4 hook already runs, with no MAC.

Exit test:

- host: the shared pure verdict header returns defer for every bucket state, including a drained bucket, a full 256-entry table, and a first 911 INVITE from an unregistered source (a table-driven test over all inputs);
- host: a test fails the build if the hook's applier has any drop path in this stage;
- bench, both Ethernet boards: ordinary call, 440 cap, and a UDP flood from a second host at a rate that today triggers the limiter: the call stays up, and the shadow would-drop count agrees with the SIP layer's own rate-drop count over the run to within a stated tolerance, which the stage fixes before the run;
- bench: a 24-hour soak with normal traffic and zero L2 drops.

### Stage 2: source binding in defer-and-count mode only

Add the frame-verdict ring, the binding table, the REGISTER arm and refresh, and the two-bank update. The filter never drops on a mismatch. It counts mismatches (`mismatch`) by reason: mismatch, router-learned, stale, table full. A mismatch is recorded as a verdict on that one frame in the ring; no per-source mismatch state is kept.

Exit test:

- host: arm from the REGISTER frame's own MAC, refresh, expiry, rebind on a new MAC; a second host's frame between the REGISTER and its authentication does not change the bound MAC; a ring miss arms nothing; a torn read (writer interrupted mid-update) defers; router-learned and off-link sources always defer; a mismatched 911 INVITE is deferred and charged as an unbound source;
- bench: a soak of at least 24 hours on each Ethernet board with the phones and a router-behind handset in normal use. `mismatch` for a legitimate device must be 0, or every nonzero case explained. Replace a phone and change a DHCP lease during the soak, and record each case.

### Stage 3: arm the narrow drops after the bench data

Two drops, both behind a stored switch that defaults off, both counted:

- the allowlist test, which already refuses the same frames in the SIP layer today, so the outcome is unchanged and only the cost moves;
- media-port frames, dropped only when ALL of these hold: (a) the frame's full 5-tuple matches a live flow whose emergency flag is clear; (b) no emergency flow, and no open callback window, exists for that source IP; (c) the source IP's binding is armed, fresh, on-link and not router-learned; (d) the source MAC differs from that binding. In every other case the frame defers. Routed handsets, roaming handsets, and a provider's media after a MAC change therefore all defer. A frame to the SIP port is never dropped on a mismatch (section 4, rule 1).

Stage 3 also lets admission see a per-frame verdict. For a SIP-port frame whose source MAC differs from its armed binding, the hook records a `mismatch` verdict in the frame-verdict ring, keyed by the frame's identity. Admission looks up the datagram it holds; if it finds the entry it charges that one frame to the shared unbound budget instead of the bound handset's own, and consumes the entry. No state is kept per source, so one spoofed frame cannot move the real handset's later frames onto the shared budget. If the entry is absent, admission charges as it does today. This keeps a spoofer from draining a registered handset's budget.

Exit test:

- host: every rule in section 4 as a test, including "a stale entry defers", "REGISTER from a new MAC defers", "a mismatched 911 INVITE is not dropped", "an emergency tuple is never dropped", and "a PSAP-callback leg, and traffic from an extension whose callback window is open, is never dropped"; plus one table-driven test per condition (a) to (d) above showing that clearing any one of them defers;
- bench: a second host forges a registered phone's IP; the real phone's budget is untouched and its calls are unaffected; then replace the phone: it re-registers and works without a manual step;
- the stage-2 soak's `mismatch` data shows 0 unexplained cases on the SHA being armed.

A bench PASS counts only for the SHA it ran on (#1050 rule 5 of the ledger).

## 11. Open questions

1. **Wi-Fi source MAC.** Is a netif-level wrapper enough, or is `esp_wifi_internal_reg_rxcb()` needed? The second is a private header and may change between IDF releases.
2. **Reserved path.** Option A (watermark shedding) or option B (a side ring) for emergency frames? Option B costs a second path in the SIP task.
3. **Moving the limiter.** Is there any version of an L2 rate drop that is safe without SIP parsing at L2? If not, the limiter stays in the SIP layer for good and L2's value is the allowlist, the binding and the media-port drop.
4. **Media ingress.** Should a frame to a media port that matches no live flow be dropped? It is not tied to any binding evidence, so it would break rule 1. It may belong with the table-full and stale rules instead.
5. **Provider tuples.** A provider's tuples for an emergency call are known only after the trunk dialog exists. Is the trunk peer's address (already latched in `publishTrunkPeer()`, RH.cpp:12271) enough for the early frames, or does the trunk need its own reserved slot?
6. **IPv6.** The filter is IPv4 only. IPv6 frames defer. Is that acceptable on the Wi-Fi variants?
7. **Hook cost.** The latency budget of the RX callback on the W5500 SPI task and on the EMAC task is unmeasured.

## 12. What this note did not verify

- The EMAC build against `sdkconfig.defaults`: the file names the W5500 only.
- Free DRAM on the constrained build when the tables would be allocated.
- Any timing of the hook on a board.
- That a monotonic tick read is safe to call from the RX context on every variant (the AdBlocker hook avoids flash; this was not checked for the timer read).
