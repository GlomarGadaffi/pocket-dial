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
- `isDialogSourceAuthorized()` compares the source IP against the two leg IPs, port-agnostic, and fails open when a leg is missing (RH.cpp:12982-13008) [verified].
- The per-source limiter is keyed by source IP: `allowPacket()` (RH.cpp:12372-12402), the registered-source slots (`RateSource`, RH.hpp:3336-3355), and #1114's reserved slots and emergency budget [verified].
- #1120 adds an answer check that compares a responder's address with the address its extension registered from.

On a LAN that assumption is false. Any host on the segment can put any IPv4 source address in a UDP datagram. #1114's own residual notes say so: a spoofer forging a registered handset's IP drains that handset's own budget. The SIP layer cannot fix this, because by the time `handle()` runs, the Ethernet header is gone and the only identity left is the claimed IP (RH.cpp:932).

The existing IPv4 guard has the same blind spot. `LWIP_HOOK_IP4_INPUT` (`main/pd_lwip_hooks.c`, wired by CMakeLists.txt:26-33) runs on all four variants, but it sees the IP header only. It can judge frame shape (`Ip4InputGuard.h`), not who sent the frame [verified].

An L2 filter sees the frame's real source MAC. That is the one extra fact that makes the checks above checkable.

What an L2 filter does not do: it does not authenticate anything cryptographically. A host that copies both the IP and the MAC of a phone defeats it. The goal is to remove cheap, blind forgery by a host that only changes the IP field. Section 8 lists the cases where it cannot help.

## 2. Invariants only L2 and L3 can hold

These are facts about packets, not about calls.

1. **Source authenticity.** An IP to MAC binding (and optionally the UDP source port) is learned when a REGISTER authenticates. A later frame whose source IP matches a fresh binding but whose source MAC does not is forged, or came from a replaced device. Which of the two is a stale-binding question (section 6).
2. **Flow membership.** The 5-tuples (proto, remote IP, remote port, local IP, local port) of live dialog legs and of negotiated media. A frame can be classified as belonging to a live flow without parsing SIP.
3. **Ingress priority.** The tuples of a live 911 or 933 call, on the handset side and on the provider side, get a reserved path that a flood on other tuples cannot starve (section 7 gives the two ways to build it).
4. **Egress.** Media is sent only to tuples a dialog negotiated. On the Ethernet variants every media frame already funnels through `EthAccess::transmitL2()` (EthAccess.hpp:31) and `l2rtp::EgressChannel`, so the check has one place to live [verified]. The Wi-Fi variants send media with `sendto()` (RtpSender.cpp:525, :728) and need the check in the sender instead [verified].

## 3. What stays in the SIP layer

The SIP layer decides identity and method authorization within a source that is already legitimate at the packet level: who this extension is, whether it may use this method on this dialog, whether a response is an answer this dialog expects. None of that can move below lwIP, because it needs parsed headers, dialog state and the registrar.

Recommendation: one authorization gate at the top of `handle()`, after the admission block (RH.cpp:960-974) and before handler dispatch (RH.cpp:1177), so that method authorization is stated once and not re-implemented in each `on*` handler. Today the checks are spread over many sites that each call `sameAddress` or `isDialogSourceAuthorized` directly (grep both names in RH.cpp) [verified]. A single gate:

- takes the parsed message and the source, plus the L2 verdict when one exists;
- answers one question: may this source use this method on this dialog;
- is the app-layer partner of the L2 filter. L2 says "this frame really came from the device bound to that IP". The gate says "that device may do this".

The gate is not part of this note's staging. It is listed so the two halves are designed together: once L2 vouches for the source, the gate can stop treating IP equality as the whole identity.

## 4. Proven or defer

This is the Rule 5 safeguard. The filter has two outcomes for a frame: act on a proven verdict, or hand the frame to the normal path unchanged.

Rules:

1. **L2 drops only packets proven forged.** "Proven" means all of: the source IP has a binding; the binding was armed by an authenticated REGISTER and has not expired; the frame's source MAC differs from the bound MAC; the bound MAC is not a gateway or router MAC; the packet is not a REGISTER (see rule 5); the tuple is not in the emergency set. Anything less is not proof.
2. **A missing or stale entry always defers.** No binding, an expired one, a binding flagged as router-learned, a full table, an unreadable snapshot: all defer to the slow path, which behaves exactly as it does today.
3. **Emergency tuples are only ever prioritised, never dropped, at L2.** A frame that matches a live 911 or 933 tuple, or whose source is a registered handset's bound source, is never dropped by the forgery rule. Shedding of other traffic may protect it; nothing at L2 may refuse it.
4. **Every L2 drop is counted on `/api/status`.** The precedent is `ip4Guard` (HttpServer.cpp:2536-2544, counters from `pd_ip4_guard_counts()`, pd_lwip_hooks.c:21-26) [verified]. Defers are counted too, by reason, so a bench run can say what the filter would have done.
5. **A frame that could refresh a binding is never dropped for a mismatch.** A replaced phone keeps its IP, has a new MAC, and must be able to re-register. If its REGISTER were dropped, the binding could never refresh and the filter would lock the phone out. REGISTER from a mismatched MAC defers; the SIP layer authenticates it and, on success, rebinds.
6. **Drops follow the SIP layer's own verdict.** For anything L2 does that the SIP layer also does today (section 10, stage 1), both call the same verdict function with the same inputs, so the two cannot disagree.

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

- **The two Ethernet hooks are one API.** `esp_eth_update_input_path()` or its `_info` variant (`esp_eth_driver.h:276-304` in the local ESP-IDF checkout) installs a callback that receives the raw frame before any pbuf exists. W5500 and EMAC differ in the RX context that calls it (an SPI-driven driver task for W5500, a DMA-driven one for EMAC), not in the hook [inferred]. The plain variant is the portable choice; the `_info` variant is only invoked if the MAC supplies extra info (header comment, `esp_eth_driver.h:287`), and which MACs do was not checked [unverified].
- **Install order matters.** The netif glue installs its own input path inside `esp_netif_attach()` (`esp_eth_netif_glue.c:69`, local checkout), so the hook must be installed after `esp_netif_attach` (esp_main_eth.cpp:716; esp_main_eth_lan8720.cpp:506) or it is overwritten [verified in the IDF source; [unverified] for v6.0.1 exactly, since the local checkout is v6.0.2-838 and CI pins v6.0.1]. The hook forwards a deferred frame with `esp_netif_receive()`, as the glue does (AB:main/dns_sink.cpp:1913). What the hook does not forward it must free; the glue frees with `free()` (`esp_eth_netif_glue.c:46-49`).
- **A frame is already allocated.** `Ip4InputGuard.h:12-17` records that W5500, EMAC and the Wi-Fi driver all allocate the frame's own length before any hook runs. An L2 drop frees early; it does not avoid the driver's RX allocation. Only the driver's ring depth bounds that. The filter therefore reduces what a flood costs lwIP and the SIP task, and does not by itself prevent memory pressure at the driver [verified from the comment].
- **Wi-Fi is the weak case.** Neither Wi-Fi variant has an esp_eth handle. The existing lwIP IPv4 hook sees no Ethernet header. Two ways to get the source MAC are open: a netif-level input wrapper installed on the STA or AP netif, or `esp_wifi_internal_reg_rxcb()` (`esp_private/wifi.h:248`, a private header). The second is early but unsupported API. Choosing between them is open question 1. Until it is answered, the Wi-Fi variants get stage 1 (stateless, IP only) from the lwIP hook that already exists, and no source binding.
- **SoftAP is the strongest Wi-Fi case.** The ESP is the only L2 hop, so the MAC the radio reports is the sender's. In STA mode, phones behind a router arrive with the router's MAC (section 8).
- **Two variants have no Wi-Fi at all.** `eth` and `lan8720` do not define `POCKETDIAL_HAS_WIFI` (main/CMakeLists.txt:241-245), so the L2 filter is the only path there [verified].
- **The sdkconfigs do not name the EMAC.** `sdkconfig.defaults` names the W5500 (`:87-88`) and nothing for the internal EMAC; the code and `CMakeLists.txt` select it [verified]. A change would need no new Kconfig, but should be checked on a bench board [unverified].

## 6. Where the binding comes from

The binding is learned from the frame's own source MAC at the hook, not from the ARP cache.

- `ArpLookup::pdLookupMac()` is a single non-blocking probe of lwIP's ARP table and returns `nullopt` on a miss (ArpLookup.hpp:12-19, :51) [verified]. The registrar already defers on a miss (Registrar.cpp:405, :456; RH.cpp:1586) [verified].
- The ARP table is itself populated from unauthenticated frames. A forged IP to MAC mapping is cheap to plant there.
- The hook has no miss: every frame carries its source MAC.

So: the hook records, per source IP, the last-seen MAC and port in a small observation slot. When the SIP layer authenticates a REGISTER, it publishes "this IP is bound to the MAC the hook last saw for the REGISTER's source" and arms the entry. The authenticated REGISTER arms; the hook only supplies the MAC. A binding that no authenticated REGISTER has armed is never used to drop.

Refresh: each authenticated REGISTER re-arms the binding and resets its age. An entry that has not been refreshed within the registration's granted expiry is stale and defers.

## 7. Ingress priority

The hardest piece, and the one this note does not settle. SIP signaling arrives on one UDP socket (`UdpServer.cpp:67, :76`), received by one task (`UdpServer.cpp:151`) [verified]. Anything admitted at L2 shares that socket's receive buffer and that task. So "a reserved path" means one of two things.

- **Option A: watermark shedding.** At L2, count frames queued toward the SIP socket (or use the receive buffer's state). Above a watermark, shed non-emergency traffic at L2. Emergency tuples and bound registered sources are never shed. Cheap and stateless, but "reserved" is only as good as the watermark; it still shares the queue.
- **Option B: a side ring.** The hook copies emergency-tuple frames into a small fixed ring that the SIP task drains first. A real reserved path, but it needs a second consumer path in the SIP task, and the frame must not be delivered twice.

Both keep rules 2 and 3 of section 4: neither ever drops an emergency frame. Option A is the stage-1 default. Option B is open question 2.

An emergency call's first INVITE has no tuple yet. It is protected the way #1114 already protects it at the SIP layer: a registered, bound source keeps its own bucket and emergency budget. At L2 that is the reserved slot for a bound source, not a flow match.

## 8. Failure modes and mitigations

| Failure | What happens | Mitigation |
|---|---|---|
| **Routed or remote handset.** The frame's source MAC is the router's, for every host behind it. | One MAC would be bound to many IPs. A "mismatch" would be meaningless. | When the learned MAC is the gateway's (`EthAccess::getLocalIpInfo()`, EthAccess.hpp:36), or one MAC is bound to more than one IP, the entry is flagged router-learned and always defers. The same holds for any source off the local subnet (`ArpLookup::pdIsOnLink()`, ArpLookup.hpp:56). |
| **DHCP reassignment, or a replaced phone.** A stale binding: same IP, new MAC (or the reverse). | A drop of the real phone's traffic. | Re-arm on every authenticated REGISTER (section 6). REGISTER from a mismatched MAC always defers (rule 5). Before any drop is armed there is a defer-and-count period (stage 2). Entries expire at the registration's expiry. |
| **Wi-Fi roaming.** A station keeps its MAC across a roam, so the binding survives. | The stale case is a lease change after roaming to another subnet. | The same mitigation as DHCP: a new lease means a new REGISTER, which re-arms. In SoftAP the ESP is the only L2 hop, so the binding is strongest there. |
| **TLS and TCP.** | The filter cannot read inside TLS, and TCP flows have no per-packet SIP meaning. | Only tuples apply: the filter can say a TCP segment belongs to a known flow, and nothing about its content. No TLS or TCP drops are proposed. |
| **The state-copy update window.** The SIP task writes binding and flow tables while the hook reads them. | A torn read could look like a mismatch. | Two banks and a sequence number. The writer fills the inactive bank, then flips an index with release ordering. The hook reads the index, reads the bank, re-reads the index, and defers if it changed or was odd. Any window resolves to defer, never to drop. This is the same pattern as AB:main/blocklist.c:1248, which re-reads the snapshot pointer after the walk. |
| **Table full.** | A source with no slot. | Defers. Never evicts an armed entry for an unarmed one. |
| **A host that copies IP and MAC.** | Passes. | Out of scope. A MAC can be spoofed too. This filter only removes blind IP forgery. |
| **Hook latency.** | The hook runs in the driver's RX context. | It must stay allocation-free, lock-free, and bounded: a handful of table compares per frame. No measurement exists (section 12). |

## 9. Memory

No heap after init. Every table is fixed at build time and sized from the pools the code already has. All of it is internal DRAM: the hook runs in the RX path and the AdBlocker rule is that its scratch stays internal (AB:main/dns_sink.cpp:1411-1413). None of it goes to PSRAM.

| Table | Entries | Bytes each | Total | Basis |
|---|---|---|---|---|
| Binding (two banks) | 32 x 2 | 28 | 1,792 B | `POCKETDIAL_MAX_CLIENTS` = 32 (PoolConfig.hpp:34-35). Fields: IP 4, MAC 6, port 2, state 1, flags 1, pad 2, refresh time 4, two counters. Two banks for the update window |
| Flow (two banks) | 64 x 2 | 16 | 2,048 B | Four legs per session (two SIP, two media) x `POCKETDIAL_MAX_SESSIONS` = 8 (PoolConfig.hpp:42-43) is 32; the rest covers anchor media (the anchor allows 4 calls, two LAN sockets each) and paging, MoH and conference legs. Fields: remote IP 4, remote port 2, local port 2, proto 1, kind 1, emergency flag 1, pad 1, expiry 4 |
| Source buckets | 256 | 12 | 3,072 B | Replaces `_rateBuckets`, an `unordered_map` capped at 256 that allocates on insert (RH.hpp:3306; RH.cpp:12388-12394) [verified]. Fields: IP 4, last-refill time 4, tokens 2 (fixed point), pad 2 |
| Reserved bound-source buckets | 32 | 24 | 768 B | Mirrors `RateSource` (RH.hpp:3336-3355): ordinary and emergency bucket per registered source |
| Counters | about 16 | 4 | 64 B | Drops and defers by reason |

Total: about 7.7 KB of internal DRAM, 0 B PSRAM. For scale, `DmaFramePool` is about 3.3 KB (DmaFramePool.hpp:32). The constrained 4 MB build (`sdkconfig.defaults.esp32_constrained`) has the least DRAM, and its free DRAM at the point the tables are allocated was not measured here [unverified]. If it is tight, stage 1 alone is about 3.8 KB and stage 2 adds the rest.

The bucket table is single-writer (the hook). The binding and flow tables are written by the SIP task and read by the hook, hence two banks. The counters are `__atomic` relaxed increments, as in `pd_ip4_guard_counts()`.

## 10. A staged plan

Each stage has an exit test. Rule 5 means no 911 or 933 is ever dialed on a board (#1050's release gates); every emergency-reserve exit test is a host test. Bench exit tests use ordinary calls under a spoofed flood, with the counters read from `/api/status`.

### Stage 1: stateless pre-filtering, with an emergency reserve

Move the CIDR allowlist (`ipAllowed()`, RH.cpp:12207-12212) and the per-source buckets (`allowPacket()`, RH.cpp:12372-12402, `takeToken()`, RH.cpp:12361) below lwIP, behind a pure verdict header shared by the hook and by `handle()`. The emergency reserve is the bound-source slots and emergency budget of #1114, moved with them. Frames that match nothing the filter can classify defer.

On the Ethernet variants this is the esp_eth hook. On the Wi-Fi variants it runs where the IPv4 hook already runs, with no MAC.

Exit test:

- host: the shared verdict header is called from both sides and a table-driven test pins that they agree on every input; a reserved source with a drained bucket is never refused; with the 256-entry table full, a registered source is still admitted; `/api/status` counts every drop;
- host: a test that fails the build if a drop path exists that does not increment a counter;
- bench, both Ethernet boards: ordinary call, 440 cap, and a UDP flood from a second host at a rate that today triggers the limiter: the call stays up, the L2 drop counter rises, the `handle()`-side drop counter does not.

### Stage 2: source binding in defer-and-count mode only

Add the observation slots, the binding table, the REGISTER arm and refresh, and the two-bank update. The filter never drops on a mismatch. It counts what it would have dropped (`wouldDrop`), by reason: mismatch, router-learned, stale, table full.

Exit test:

- host: arm, refresh, expiry, rebind on a new MAC; a torn read (writer interrupted mid-update) defers; router-learned and off-link sources always defer;
- bench: a soak of at least 24 hours on each Ethernet board with the phones and a router-behind handset in normal use. `wouldDrop` for a legitimate device must be 0, or every nonzero case explained. Replace a phone and change a DHCP lease during the soak, and record each case.

### Stage 3: arm forgery drops after the bench data

Arm the drop for proven-forged frames only (section 4, rule 1), per source, behind a stored switch that defaults off. A drop is counted. An emergency tuple and a bound source's REGISTER are never dropped.

Exit test:

- host: every rule in section 4 as a test, including "a stale entry defers", "REGISTER from a new MAC defers", and "an emergency tuple is never dropped by the forgery rule";
- bench: a second host forges a registered phone's IP; the forged frames are dropped and counted, the real phone's budget is untouched, and the real phone's calls are unaffected. Then replace the phone: it re-registers and works without a manual step;
- a stage-2 soak's `wouldDrop` data shows 0 unexplained cases on the SHA being armed.

A bench PASS counts only for the SHA it ran on (#1050 rule 5 of the ledger).

## 11. Open questions

1. **Wi-Fi source MAC.** Is a netif-level wrapper enough, or is `esp_wifi_internal_reg_rxcb()` needed? The second is a private header and may change between IDF releases.
2. **Reserved path.** Option A (watermark shedding) or option B (a side ring) for emergency frames? Option B costs a second path in the SIP task.
3. **Double accounting.** Once the buckets live at L2, does `handle()` keep a backstop bucket at a higher threshold, or trust the L2 verdict? A backstop is safer but charges a frame twice.
4. **Media ingress.** Should a frame to a media port that matches no live flow be dropped? It is not "proven forged", so it would break rule 1 as written. It may belong with the table-full and stale rules instead.
5. **Egress refusal.** Should an unknown media destination be refused for non-emergency calls? The proposal is count-only in stages 1 and 2. Emergency media is never refused.
6. **Provider tuples.** A provider's tuples for an emergency call are known only after the trunk dialog exists. Is the trunk peer's address (already latched in `publishTrunkPeer()`, RH.cpp:12271) enough for the early frames, or does the trunk need its own reserved slot?
7. **Dual-stack and ARP.** The filter is IPv4 only. IPv6 frames defer. Is that acceptable on the Wi-Fi variants?
8. **Hook cost.** The latency budget of the RX callback on the W5500 SPI task and on the EMAC task is unmeasured.

## 12. What this note did not verify

- Whether W5500 and EMAC MACs supply the extra info the `_info` input path needs (section 5).
- That the local ESP-IDF checkout (v6.0.2-838) matches CI's v6.0.1 for `esp_netif_attach` and the input-path API.
- The EMAC build against `sdkconfig.defaults`: the file names the W5500 only.
- Free DRAM on the constrained build when the tables would be allocated.
- Any timing of the hook on a board.
- That a monotonic tick read is safe to call from the RX context on every variant (the AdBlocker hook avoids flash; this was not checked for the timer read).
