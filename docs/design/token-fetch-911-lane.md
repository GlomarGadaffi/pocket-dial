# Design: heap-free token fetch on the 911 lane, the rest of fetchToken (#951)

Status: Proposed, for vote. Design only: no code, no hardware, nothing posted to GitHub.
Author: BigDog (Claude Sonnet 5.5), 2026-10-09. Follows the #945 rulings and the #948 contract (arena, failure contract, 10 ms bound).

Two code bases, and every claim says which:

- **[main]** = `origin/main` 7bcf952f. It has **no 911 lane**: no arena, no sos scope, no background refresh.
- **[branch]** = `origin/fix/862-hot-path-allocs` 79e0133f (#945, draft, DO NOT MERGE). The arena, the three token
  lanes and the 911 path below exist only there. Paths: `TA.cpp` = src/SIP/TelephonyAnchorClient.cpp, `TAL.hpp` = src/SIP/TelephonyAnchorLogic.hpp.
- **Rule for line numbers: an unmarked `TA.cpp` or `TAL.hpp` number is [branch] 79e0133f; a [main] number is marked.**
  TA.cpp differs by about 200 lines between the two. IDF and config numbers are the same on both (config files are not on the branch diff).

Nothing here is measured on a board. IDF facts were read in `/home/glomar/esp/esp-idf` (v6.0.2; the code comments cite v6.0.1).

## 1. When the 911 lane fetches a token [branch]

- [main] every `makeCall` calls `ensureToken()` (TA.cpp:383, :1069-1099), which can run `fetchToken()` inline (:1098).
- [branch] a 911/933 `makeCall` has two fetch cases, both inline on its own task, on the 911/933 arena:
  1. No cached token: `sosFirstStep(haveCachedToken()) == FetchThenPost` (TA.cpp:340-343; TAL.hpp:1109). A cached token,
     even past expiry, is POSTed at once (#945 ruling A).
  2. Its POST drew a 401: one bounded fetch, one retry (TA.cpp:443-467, fetch at :458; #945 ruling B and the revised
     ruling 1: no skip while another 911 is live).
- **Finding: case 1 looks unreachable.** `makeCall` returns false unless `_running && _connected` (TA.cpp:296-304).
  `_connected` needs the WS, which needs `start()`, whose first fetch must succeed (TA.cpp:190-196, ordinary lane). `_bearerHeader`
  is assigned at one place (TA.cpp:1117-1118, grep of every use) and never cleared. So a 911 that reaches the token step already has a token.
  Not proven (I traced no restart race); ruling A keeps the branch as defence. Effect: the real inline fetch is the 401 retry.
- The off-path half of option (b) is already built: `tel_maint` wakes the maintenance lane, which refreshes at 10 minutes
  before expiry (TAL.hpp:848, :890-914; TA.cpp:2053-2084). Host-tested; ESP side is compile-checked only (#945 body).

## 2. What still allocates in fetchToken on the 911 lane [branch, TA.cpp:997-1183]

Already not allocating on this lane: the body read (arena, TA.cpp:2644-2692; main's vector and cJSON at TA.cpp:2446-2480 are what #945
replaces), the lane claim (atomic flag, TAL.hpp:923-950), the install gate (TAL.hpp:1074-1082).

| # | Allocation | Where | Size | When |
|---|---|---|---|---|
| 1 | `tokenUrl`, `clientId`, `clientSecret` copies, and the `_baseUrl + "/connect/token"` temporary | TA.cpp:1034-1041 | url <= 142 B, id, secret <= 64 B each (TelephonyApiConfig.hpp:36-37) | every fetch (heap above 15 B) |
| 2 | `esp_http_client_init`: client struct, tx buffer, rx buffer, URL strings | TA.cpp:1043, :2377-2411 (rx 4096 at :2386, tx 1024 from :1043); IDF esp_http_client.c:858, :1001-1002, :1232-1298 | 5,120 B of buffers + struct | every fetch |
| 3 | `set_header("Content-Type")` | TA.cpp:1050; esp_http_client.c:414-421 (allocation inside `http_header_set` not read) | small | every fetch |
| 4 | form body: two `urlEncode` temporaries + concatenation | TA.cpp:1056-1057; UrlEncode.hpp:13-37 | <= 439 B (40 + 3x64 + 15 + 3x64) | every fetch |
| 5 | TLS: `esp_tls_init` (calloc) and the mbedtls handshake, per new connection | TA.cpp:1079; IDF transport_ssl.c:112-118; freed at :332-345 | **not measured** | every fetch (new connection) |
| 6 | `_accessToken.assign`, `_bearerHeader.assign/append` | TA.cpp:1116-1118, under `_mutex` (:1111) | token length | only when capacity is short |
| 7 | JWT lifetime decode: payload substr, decoded vector, json text | TA.cpp:1120 -> TAL.hpp:134, :138, :144, under `_mutex` | 3 allocations | every fetch |
| 8 | `wsHeaders` string, then `esp_websocket_client_set_headers` copies it | TA.cpp:1126, :1155 | <= 4,120 B | every fetch while the WS is up |

Row 7 is pinned by tests/TelephonyAnchorLogic_test.cpp:177-197 [branch] (`EXPECT_LE(heap, 3u)`). Row 6: `_accessToken` is read
only inside `fetchToken` (grep: TA.cpp:1116-1122), so the copy can go. With `CONFIG_MBEDTLS_DYNAMIC_BUFFER=y` (sdkconfig.defaults:220)
mbedtls allocates its record buffers per record, so TLS reads and writes may allocate even on an open connection (mbedtls port not read).

Same lane, outside this issue: the 911's makecall POST builds a fresh client every call (`httpPostBody`, TA.cpp:1474-1486), as do
the device GET and the `postData`/`respBody` strings (TA.cpp:378-399). A heap-free `fetchToken` does not make the 911 lane heap-free.

## 3. The options

**(a) A persistent `esp_http_client` per lane** (the issue's option a), created at init, the way #948 describes `_sosStatusClient`.
- Removes rows 2 and 3, and row 1 and 4 if URL and body are built once at `init()` into fixed buffers.
- Does not remove row 5. `esp_http_client_close()` destroys the TLS context (esp_http_client.c:1911-1919 -> transport_ssl.c:339), and
  the next `open` runs `esp_tls_init` and the handshake again (transport_ssl.c:112-118). Only a connection kept open avoids that, which
  means not calling `close` on success (TA.cpp:1174), taking one of 8 sockets on the constrained build (sdkconfig.defaults.esp32_constrained:46),
  and reconnecting when 3CX has dropped it. 3CX's idle timeout is unknown to me.
- `set_url` and `set_header` allocate on every call (esp_http_client.c:1232-1298, :414): set them once at init, never per fetch.
- Upside that is not heap: the saved TLS session lives in the handle (esp_http_client.c:1675-1676), so a persistent
  handle can resume (about 1 RTT) where a fresh client pays the software ECDHE, about a second on the S3 (TA.cpp:2389-2397, PoolConfig.hpp:283-291).
- Hazard: a timed-out read can leave bytes on a kept-alive connection. Contract: any error closes the connection and marks the handle
  dirty; a response's bytes never reach the next fetch. #948's "rebuild with `esp_http_client_init` on the 911's own path" must not run
  here: the 911 uses the best token it has, and `tel_maint` rebuilds the handle off the lane. (I did not read the #941 branch; this is from #948's text.)

**(b) Off-path pre-fetch only** (the issue's option b). As built, it cannot remove the 401 fetch, **if** a new grant revokes the old token.
That is what the code assumes (TAL.hpp:806-808; main TA.cpp:1076-1079) and what the operator calls unverified, to be decided by #952
(#945, 10:05Z and 10:37Z). If it holds, no spare token can be staged, and after a 401 the cached token is known bad (#945 ruling B), so
removing the inline fetch means a certain NOT ROUTED, which the revised ruling 1 rejected. If #952 shows a grant does not revoke live
bearers, a token staged off-path could serve the retry and (b) would remove the inline fetch. Either way (b) can also wake the
maintenance lane on a 401 seen by any non-911 lane, so a revoked token is replaced before a 911 meets it. That is host-testable.

**(c) (b) extended, plus our own allocations removed, with (a) deferred.** Slice 1, no hardware: rows 1, 4, 6, 7, 8 gone (fixed
`char` buffers filled at `init()`; the JWT segment decoded into a fixed buffer, falling back to `kTokenFallbackLifetimeUs` when it does not
fit; `_accessToken` dropped; the WS header update moved to `tel_maint` behind a flag). Decode and header build leave `_mutex`.
Slice 2, only after the heap readings: (a) for the 911 lane. TLS and IDF internals stay the one named exemption, under the #948 failure contract.

**(d) Stop at #945.** Document rows 1-8 as the exemption. No code.

## 4. Rule 5 constraints, and where each is met

| Constraint | Met today [branch] | What a change must keep |
|---|---|---|
| 911 never waits on a non-911 fetch for more than 10 ms | The 911/933 lane has its own arena; its claim is one atomic try and never calls the sleep callback (TAL.hpp:933-950). | A persistent handle is the lane's own, with its own atomic claim; a lost claim returns at once. Never share `_ctrlClient` (TA.cpp:2479): dropCall uses it. |
| Never refuses because a fresh token could not be fetched | `fetchToken` returns false and `makeCall` goes on with `_bearerHeader` (TA.cpp:340-345, :1043-1048). A 401 whose fetch fails falls to #880. | A dead handle returns false. No inline rebuild, no wait. Say plainly: for the 401 case a failed fetch means NOT ROUTED, so this is not heap-proof. |
| Never uses partial data | `collect` leaves `size() == 0` on anything but Ok (TAL.hpp:735-741); `checkToken` wants a JWT shape (TAL.hpp:674); `installIfNewer` (TAL.hpp:1080). | Static buffers are written only after the whole response is accepted; a failed install leaves the old token and header intact. |

Remaining waits are not fetch waits. `fetchToken` takes the shared `_mutex` at TA.cpp:1037 and :1111, and the install at :1111 runs the
decode and two string assigns inside it; any 911 `makeCall` that needs `_mutex` (TA.cpp:353) can queue behind a non-911 install. That
is the #949 dependency (four lock holds, reproduce and time first). Slice 1 shortens that hold. CPU contention with another lane's
handshake is not a lock; it is bounded by `kSosTokenBudgetUs` = 3 s (TAL.hpp:1166), after which the 911 goes on with the token it has.

## 5. Heap budget (modelled; nothing here is a reading)

| Item | Bytes | Basis |
|---|---|---|
| Three token arenas, already on the branch | 3 x 4,108 = 12,324 | TAL.hpp:824-825 ("about 12.3 KB on the 32-bit ESP32") |
| #948 persistent status handle | 5,000 to 6,000 | #948's estimate, unmeasured |
| Slice 1: `tokenUrl` 143 + encoded body 440 | 583 | caps TelephonyApiConfig.hpp:36-37 |
| Slice 1: `_bearerHeader` reserved to the arena limit | 4,103 | `kTokenBodyBytes` 4,096 (TAL.hpp:635) + "Bearer " |
| Slice 1: `_accessToken` dropped | minus its capacity | token length, unmeasured |
| Slice 2: client buffers | 5,120 + struct + session | 4,096 + 1,024; the struct and session are unmeasured |
| Slices 1 and 2, added | about 9,800 | 583 + 4,103 + 5,120 |
| Permanent total, 911 token and status lanes | about 27,600 | 12,324 + 5,500 + 9,806 |

The #945 body says two arenas and 8.2 KB; the branch head has three arenas (the maintenance lane was added after), so that figure is stale.
Share of the classic board: 27.6 KB against ~290-320 KB usable internal DRAM (docs/SCALING.md:106,291) is 8.6 to 9.5%, before the TLS
transient, which is the largest unknown. On the S3 the static buffers ride in the RequestsHandler allocation (PSRAM, docs/SCALING.md:102-105,
unverified), but the persistent client's buffers are IDF mallocs under the 16 KB threshold, so they are internal DRAM (PsramAllocator.hpp:6-11).

Readings required before slice 2 (#948 ruling 3, #945 ruling 4): free heap and internal minimum free at boot, after `start()`, and after
10 token cycles. The S3 bench (.244) can read the chip-independent parts. The classic reading needs a classic board; none is known on the
rig (#945, operator, 08:48Z). The token length is already logged ("Retrieved access token (len=", TA.cpp:1159): read it off a bench log
before choosing the 4,096 B cap.

## 6. Test plan

Host (the repo's `AllocGuard` counts C++ `operator new` only, tests/support/AllocCounter.hpp:13-19, so it proves our code, never IDF or TLS):
1. Slice 1 as a host-compilable header with an injected transport, TAL.hpp style: request build, JWT decode, install into fixed buffers.
   `AllocGuard::delta() == 0` over build + decode + install. Replaces the `<= 3` pin at TelephonyAnchorLogic_test.cpp:177-197 with `== 0`.
2. Caps: a 64-character id and secret of all-reserved bytes encode to 439 B; 65 is refused. The cap is enforced upstream
   (TelephonyApiConfig.cpp:90-96) but `init()` does not check (TA.cpp:148-159), so slice 1 must, and a test pins it. Token 4,096 B
   accepted, 4,097 B refused with the old token kept. A JWT payload larger than the decode buffer gives the fallback lifetime, not a failure.
3. Each failure branch returns false with the token and header unchanged: init null, open, write, non-200, arena full, read timeout, budget
   spent, install older, claim lost. For the lost claim the sleep callback is never invoked and the fake clock does not move (the 10 ms bound).
4. Slice 2 as a state machine with an injected transport: Closed, Open, Dirty. Any error moves to Dirty and the next fetch reconnects; no
   byte of a prior response survives; a claim lost at teardown returns inside the bound (#948 ruling 2).
5. The 401 trigger from a non-911 lane (option b extended): a 401 on dropCall or status wakes the maintenance job; a 911 in flight blocks it.

On a board (operator, not done here): the three heap readings; witness lines `token_sos_*_862` counted; a 911 with a revoked token on .244.

## 7. Decision asked (poll)

| | Option | Production change | Hardware first? |
|---|---|---|---|
| a | Persistent client on the 911 lane, plus static buffers | slices 1 and 2 | yes, three readings |
| b | Pre-fetch only, as built, plus a refresh on any 401 | small, host-testable | no |
| c | b extended + slice 1 now; slice 2 only after the readings | slice 1, then maybe 2 | slice 2 only |
| d | Stop at #945; name rows 1-8 as the exemption | none | no |

Recommended: **c**. Slice 1 removes every allocation we own, shortens the `_mutex` hold, and needs no board. Slice 2 costs about 5.1 KB
permanent to save a transient of the same size, leaves the TLS allocations (row 5) in place, and serves a fetch that, by section 1,
is the 401 retry. Its real benefit is a faster resumed handshake, which needs a measurement. No default is named here: the recorded
operator default for a 911 path is no lock across I/O and no allocation (#940 notes), which favours slice 1 of c over d, but the choice is the operator's.

Also asked: (i) drop `_accessToken` and cap `_bearerHeader` at 4,103 B, or read the token length first? (ii) Name TLS and IDF internals
as the single exemption under the #948 failure contract? (iii) Refresh on any 401 seen off the 911 lane: yes or no? (iv) Open a separate
issue for the 911 makecall POST's fresh client (TA.cpp:1486)?
