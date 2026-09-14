# Pocket-Dial Firmware: Performance Benchmarks & Methodology

> [!CAUTION]
> ## Every number in sections 1–4 of this document is MODELLED. None of it was measured.
>
> These are desk estimates written on 2026-06-01 (commit `8be61da`) before any board
> was in the loop. They are **projections**, not benchmarks, despite the column headers
> and the confident tone. Section 5 is a test plan that **was never executed as written**.
>
> **Where real measurements exist, they live in
> [`tests/load/STRESS_FINDINGS.md`](../tests/load/STRESS_FINDINGS.md)** (display build on a
> live JC3248W535, post-fix commit `b04ecac`, 2026-06-04; plus a host-build multi-source-IP
> run for Issue #79). **Those measurements contradict this document in two places and
> falsify one of its PASS verdicts outright.** Each affected table below carries an inline
> correction box. Where the two disagree, the measurement wins.
>
> | | |
> |---|---|
> | Written | 2026-06-01, commit `8be61da` — entirely modelled |
> | Banner + correction boxes added | 2026-09-13, HEAD `fbad51b` |
> | Re-modelled or re-measured since? | **No.** The projections have not been revised; the real numbers were simply never folded back in. |
>
> Treat the tables as *budgets someone once proposed*, useful for sizing arguments and
> for seeing what the design intended — not as evidence about how the firmware behaves.

This document outlines the performance benchmark plan, theoretical resource models, and live-board physical testing methodologies for the post-refactor **pocket-dial ESP32 firmware**. 

Since pocket-dial is deployed across multiple hardware form factors (headless SoftAP modules, W5500 Ethernet boards, and smart-display units running high-frequency graphics), this document establishes rigorous resource budgets and measurement guidelines rather than assuming a single physical board setup.

> [!NOTE]
> **Reading the measurements against these models.** Every on-device number that exists
> was taken on **Target B (the ESP32-S3 smart display)** in STATION mode. That build's
> core map is the *opposite* of the §2 model below: on the display build SIP and HTTP run
> on Core 0 while `lvgl_task` is pinned to Core 1. So the display measurements bound what
> the *display* build does; Targets A and C have never been profiled at all.

---

## 💾 1. Theoretical Resource Models (ESP32 Targets)

Here, we model the memory and latency footprints on the three primary production target boards:
1. **Target A: Headless ESP32-WROOM-32E** (Dual-core, 240MHz Xtensa D0WDQ6, 520 KB internal SRAM, no PSRAM).
2. **Target B: ESP32-S3 Smart Display (JC3248W535)** (Dual-core, 240MHz Xtensa LX7, 512 KB SRAM, 2 MB external PSRAM, running LVGL graphics).
3. **Target C: ESP32-W5500 Ethernet Gateway** (Headless gateway utilizing wired SPI Ethernet, dual-core, 520 KB internal SRAM).

---

## 🧵 2. Task Stack Allocations & Watermark Estimates

In FreeRTOS, the "stack high-water mark" is the minimum amount of free stack space (in bytes) that has remained unused since the task was created. If this value approaches zero, a stack overflow is imminent, which triggers an immediate CPU panic.

The post-refactor tasks are allocated generous stacks, resulting in highly secure margins.

### Stack Allocations vs. Projected Watermark Estimates

> [!WARNING]
> **The "HTTP client thread" row below was falsified on hardware.** Every figure in
> that row is a projection, and the projection was wrong in the direction that matters.
>
> On a live S3 display board in STA mode the HTTP server accepted TCP connections and
> then **RST them without responding**. Root cause, from
> [`tests/load/STRESS_FINDINGS.md`](../tests/load/STRESS_FINDINGS.md): `sendApiStatus`
> **overflowed the ~3 KB default pthread stack on-device**. Moving the 4 KB read buffer
> to the heap — the entire argument of the subsection immediately below — did *not*
> keep the thread under the default limit, because the read buffer was never the only
> thing on that stack. The projected "1,450 bytes peak / 1,622 free / **PASS**" never
> happened.
>
> The real fix was to stop relying on the default at all:
> `CONFIG_PTHREAD_TASK_STACK_SIZE_DEFAULT=8192`
> ([`sdkconfig.defaults:68`](../sdkconfig.defaults#L68)), plus binding `INADDR_ANY`
> (commit `b04ecac`, 2026-06-04). Any current build inherits the 8 KB pthread stack;
> the "~3,072 *Default*" figure in the table is no longer the shipped configuration.
>
> The other three rows have **never been measured** — the §5 Phase 1 `vTaskList`
> procedure was not run, so no real high-water mark exists for any task on any board.

| Task Name | Core | Allocated Stack (Bytes) | Projected Peak Stack Usage (Bytes) | Projected High-Water Mark (Free Bytes) | Technical Risk Analysis & Design Details |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **`sip_server_task`** | Core 1 | 8,192 | 3,840 | 4,352 | Handles the 1Hz ticking engine, keeps alive, and sweeps expired clients. Low risk of recursion or heavy frames. |
| **`udp_receiver_task`**| Core 1 | **16,384** | 4,200 | *(projection stale)* | **High-activity path.** Processes and parses incoming SIP string structures inline. **The 8 KB figure this row used to carry is wrong and was wrong in practice too**: 8 KB caused a stack-overflow panic on this task, and it was raised to 16,384 at `UdpServer.cpp:145-152`. The peak/high-water projections beside it were computed against the old allocation and were never re-derived. |
| **`http_server_task`** | Core 0 | 8,192 | 2,800 | 5,392 | Executes the non-blocking accept loop using `select()`. Light and secure as handling is delegated. |
| **HTTP client thread** | Core 0 | ~3,072 *Default* | 1,450 | 1,622 | Each active HTTP socket runs in a detached `pthread`. **PASS due to heap shift of 4 KB read buffer.** |

### 💡 Why HTTP Client Threads Do Not Overflow pthread Defaults

> [!CAUTION]
> **This subsection's conclusion is false as stated, and is kept only as the record of
> what was believed in June 2026.** They *did* overflow the pthread default — see the
> correction box above. The heap-shift described here is real and still in the code
> ([`HttpServer.cpp:271`](../src/Helpers/HttpServer.cpp#L271)), and it was a necessary
> change; it just was not a *sufficient* one. The claim that it "keeps the stack
> footprint below the default pthread limits" is the specific sentence hardware
> disproved. Builds now raise the default to 8192 instead of fitting under ~3 KB.

In the original design, allocating a stack-local buffer like `char buf[4096]` inside the HTTP connection handler would immediately exceed the ~3 KB default pthread stack limit allocated by the ESP-IDF RTOS layer, causing a silent stack overflow or memory corruption.

In the post-refactor design (`HttpServer.cpp:141-144`), we shift the buffer to the heap:
```cpp
std::vector<char> buf(4096, 0);
```
By allocating the vector, the 4,096 bytes are allocated from the **system heap** rather than the POSIX thread's stack. The thread stack itself only holds the vector's control structure (24 bytes on Xtensa), keeping the stack footprint to less than 1.5 KB and comfortably below the default pthread limits!

---

## 📦 3. Heap Memory Footprint Estimates

The ESP32 possesses a unified SRAM map, but internal memory is divided into Instruction RAM (IRAM) and Data RAM (DRAM). Free heap memory is DRAM available to the user.

We estimate heap consumption across three key operating states:

### Heap Consumption Models per Target State

> [!NOTE]
> **Modelled. One data point exists and the model was pessimistic.** The only real heap
> figure recorded on hardware is "~200 KB free" on the S3 display build
> ([`tests/load/STRESS_FINDINGS.md`](../tests/load/STRESS_FINDINGS.md), in the discussion
> of raising the lwIP mailbox sizes) — against the 120 KB projected for that target in
> the table below. That is a single observation under unstated conditions, so it does not
> replace the row; it only shows the estimate was conservative rather than optimistic.
> The State 1 / 2 / 3 deltas, the fragmentation grades, and Targets A and C have never
> been measured. The §5 Phase 2 `heap_caps_*` procedure was not run.
>
> Note also that the pool sizes quoted below as literal 32 / 8 are now compile-time
> knobs — `POCKETDIAL_MAX_CLIENTS` / `POCKETDIAL_MAX_SESSIONS`
> ([`src/SIP/PoolConfig.hpp`](../src/SIP/PoolConfig.hpp)) — which default to those same
> values. A build that raises them moves every number in this section.

```
  [State 1: Idle Baseline] ──> Pre-allocates static pools (~10 KB DRAM overhead)
            │
            ├──> [State 2: Active HTTP Polling] ──> Transient heap allocation (~4-6 KB DRAM, fast release)
            │
            └──> [State 3: Active SIP Call] ────> Steady-state memory footprint unchanged (Static pool reuse!)
```

| Target Board | State 1: Idle Baseline (No Clients Registered) | State 2: HTTP status Polling (CGA Dashboard Active) | State 3: Active SIP Call (2 Registered, 1 Call) | Heap Fragmentation Hazard Level |
| :--- | :---: | :---: | :---: | :---: |
| **Headless ESP32-WROOM** | 280 KB Free | 274 KB Free *(Transient)* | 279 KB Free | **Low** (Steady-state dynamic allocations eliminated via pooling) |
| **ESP32-S3 Smart Display**| 120 KB Free *(Graphics RAM consumed)*| 114 KB Free *(Transient)* | 119 KB Free | **Medium** (LVGL UI rendering and SIP engine share internal DRAM) |
| **ESP32-W5500 Ethernet** | 260 KB Free *(Ethernet buffers occupied)*| 254 KB Free *(Transient)* | 259 KB Free | **Low** (Stable socket handling outside signaling loop) |

### 🔍 Breakdown of State Calculations
1. **State 1 (Idle Baseline):**
   * Static pools are pre-allocated in `RequestsHandler::RequestsHandler`:
     * `_clientPool`: $32 \times \text{std::shared\_ptr<SipClient>} \approx 4.1\text{ KB}$
     * `_sessionPool`: $8 \times \text{std::shared\_ptr<Session>} \approx 2.2\text{ KB}$
     * Total pool footprint: $\approx 6.3\text{ KB}$ (plus basic vector overhead and static strings).
   * Total static overhead is a flat $\approx 10\text{ KB}$, providing known bounds.
2. **State 2 (Active HTTP Status Polling):**
   * Handled inside `HttpServer::sendApiStatus`.
   * Allocates a JSON response stream, temporary string formatting, and a heap vector for client readings:
     * 4 KB client read buffer (`buf` vector)
     * $\approx 1-2\text{ KB}$ string buffer for JSON payload generation.
   * This results in a transient $\approx 6\text{ KB}$ dip in free heap. **Crucially, this is immediately deallocated** when `handleClient` terminates and closes the socket, causing zero permanent fragmentation.
3. **State 3 (Active SIP Call):**
   * Reuses already allocated pool items from `_clientPool` and `_sessionPool`.
   * **Zero additional dynamic memory is allocated** for clients or sessions.
   * Minimal transient allocations ($< 1\text{ KB}$) occur in lwIP buffers and `SipMessage` parsing, returning free memory immediately to State 1 levels. This prevents the severe fragmentation failures identified in Issue #53.

---

## ⚡ 4. HTTP API Request Latencies

We model request processing latencies based on the network and storage activities required for each HTTP endpoint.

> [!WARNING]
> **Measured latencies exist for two of these endpoints and both are roughly an order of
> magnitude worse than projected.** From
> [`tests/load/STRESS_FINDINGS.md`](../tests/load/STRESS_FINDINGS.md) — S3 display build,
> live board, single source, paced ~10 req/s, post-fix (`b04ecac`, 2026-06-04):
>
> | Endpoint | Projected here | **Actually measured** | Ratio |
> |---|---|---|---|
> | `GET /api/status` | 3–8 ms | **150 ms** | ~20–50× slower |
> | `GET /` (dashboard) | 10–25 ms | **~6 s** (84 KB, one-time) | ~250–600× slower |
> | `GET /api/cdr` | *not modelled* | 17 ms | — |
>
> The `/api/status` figure is the important one, because the `[!NOTE]` under this table
> argues from first principles that it "is exceptionally low (<8 ms) because it reads
> from the pre-compiled `_snapshot`". The snapshot architecture is real and does bypass
> the signalling mutex — but it is not what dominates the response time on-device, so
> the architectural argument does not license the number. **Do not quote "<8 ms" as a
> characteristic of this firmware.**
>
> The `GET /` figure is additionally *stale in the optimistic direction*: it was measured
> at 84 KB, and the dashboard has since grown the Dial Plan / Groups / Call Log / SIP
> Trace modals (`fbad51b`, 2026-09-13). It has not been re-measured since that growth.
>
> For comparison, the SIP path *was* fast and roughly in line with expectations in the
> same run: REGISTER p50 8.6 ms / p95 25.8 ms / max 121 ms (20/20 OK), and a `777` echo
> call p50 13.3 ms / p95 19.9 ms (5/5 OK). Nothing in the SIP rows of this document was
> modelled, so there is nothing there to contradict — but it is the reason the stress
> findings conclude "the SIP engine itself is healthy" while the HTTP plane was not.
>
> No endpoint has ever been measured under the "10 Clients Poll" column's conditions.

| HTTP Endpoint | HTTP Method | Expected Latency (Normal Load) | Expected Latency (10 Clients Poll) | Processing Bottleneck & Hardware Activity |
| :--- | :---: | :---: | :---: | :--- |
| **`GET /`** | GET | 10–25 ms | 15–40 ms | Reading static index HTML from flash or embedded header (`CGA_INDEX_HTML`). |
| **`GET /api/status`** | GET | 3–8 ms | 10–25 ms | Low latency due to reading pre-built snapshot under `_snapshotMutex`. Completely bypasses SIP `_mutex`. |
| **`POST /api/kill`** | POST | 5–12 ms | 12–30 ms | Erases elements from the active client map and triggers a snapshot rebuild during the next `tick()`. |
| **`GET /api/wifi/scan`**| GET | 1,500–2,800 ms| 1,500–3,000 ms| **High Latency.** Switch to `APSTA` mode and block while the Wi-Fi transceiver scans all channels. |
| **`POST /api/wifi/connect`**| POST | 15–35 ms | 20–50 ms | Writes SSID & password to NVS flash, returns response, and triggers restart after 1 second. |
| **`POST /api/wifi/mode_ap`**| POST | 10–25 ms | 15–45 ms | Writes AP Standalone configuration to NVS, returns response, and restarts. |

> [!NOTE]
> The `/api/status` response latency is exceptionally low ($<8\text{ ms}$) because it reads from the pre-compiled `_snapshot` structure. It does not block on active UDP processing or lock the core SIP engine.
>
> ~~*(Superseded — measured at 150 ms on hardware. See the correction box above. The
> snapshot decoupling is real; the latency claim it was used to justify is not.)*~~

---

## 📈 5. Live-Board Measurement Methodology (Test Plan)

> [!IMPORTANT]
> **This test plan was never executed as written.** No `vTaskList` watermark run
> (Phase 1), no `heap_caps_*` baseline/stress/call sweep (Phase 2), and no `curl -w`
> latency capture (Phase 3) was ever performed against these procedures. It remains a
> perfectly good plan and is kept for that reason — but nothing in sections 1–4 was
> validated by it.
>
> What was actually run instead, and what it produced, is
> [`tests/load/sip_stress.py`](../tests/load/sip_stress.py) →
> [`tests/load/STRESS_FINDINGS.md`](../tests/load/STRESS_FINDINGS.md). That harness
> measures SIP register/call latency and samples `GET /api/status` for server-side
> counters; it does not measure stacks or heap. If you are picking this up, the
> highest-value unexecuted work here is **Phase 1** — there is still no real high-water
> mark for any task on any board, and the one time a stack limit was tested in anger
> (the pthread default) the model was wrong.

To validate these theoretical estimates on physical hardware, the QA/testing team must execute the following step-by-step physical measurement protocols on live boards.

### Phase 1: Task Stack Watermark Testing
To measure the actual stack high-water mark on a running ESP32:
1. Compile the firmware with `CONFIG_FREERTOS_USE_TRACE_FACILITY=y` and `CONFIG_FREERTOS_USE_STATS_FORMATTING_FUNCTIONS=y` enabled in `sdkconfig` via `idf.py menuconfig`.
2. Add a diagnostic task or high-frequency timer in your main program that prints task diagnostics every 5 seconds:
   ```cpp
   void diagnostic_task(void *pvParameters) {
       char buffer[512];
       while (1) {
           vTaskList(buffer);
           printf("Task Name\tState\tPrio\tStack\tNum\tCore\n");
           printf("%s\n", buffer);
           vTaskDelay(pdMS_TO_TICKS(5000));
       }
   }
   ```
3. Look at the `Stack` column in the output. The number returned represents the **minimum free stack space remaining (high-water mark)** in 32-bit words (or bytes, depending on compiler configuration). Ensure no task falls below **1,024 bytes** during active call processing or rapid dashboard reloading.

### Phase 2: Heap Footprint & Fragmentation Monitoring
To monitor heap stability and detect dynamic leaks:
1. Periodically query the native ESP-IDF heap caps APIs during different execution phases:
   * **Total Free Heap:** `heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT)`
   * **Minimum Free Heap Ever (System Watermark):** `heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT)`
   * **Largest Free Block (Fragmentation Indicator):** `heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT)`
2. **Setup State Test Steps:**
   * **Step A (Baseline):** Boot the device. Wait 10 seconds. Query the values.
   * **Step B (Stress Polling):** Initiate 10 concurrent requests polling `/api/status` using a tool like Apache Bench (`ab`):
     ```bash
     ab -n 500 -c 10 http://192.168.4.1/api/status
     ```
     During execution, observe the Largest Free Block. If it drops continuously and does not recover back to the Baseline size post-test, a memory leak or severe fragmentation is present.
   * **Step C (Call Stress):** Register 10 SIP client extensions (e.g., using MicroSIP or softphone simulators). Initiate multiple simultaneous intercom calls and group paging broadcasts (extension `999`). Check the Baseline heap before, during, and after the call. The post-call heap size must match the pre-call heap size exactly, verifying that the Static Pool recycler successfully cleaned up the session slots.

### Phase 3: HTTP API Latency Measurement
To record the exact network response times:
1. Save the following curl format file as `curl-format.txt`:
   ```text
       time_namelookup:  %{time_namelookup}s\n
          time_connect:  %{time_connect}s\n
       time_appconnect:  %{time_appconnect}s\n
      time_pretransfer:  %{time_pretransfer}s\n
         time_redirect:  %{time_redirect}s\n
    time_starttransfer:  %{time_starttransfer}s\n
                       ----------\n
            time_total:  %{time_total}s\n
   ```
2. Execute curl queries against the running device over Wi-Fi/Ethernet:
   ```bash
   curl -w "@curl-format.txt" -o /dev/null -s http://192.168.4.1/api/status
   ```
3. Record `time_total` (total round-trip duration). Repeat this under load (e.g., while actively making SIP calls) to confirm the snapshotting architecture prevents network-layer latency spikes.
