# Pocket-Dial Firmware: PR & Coding Standards Policy

This document establishes the mandatory code quality, memory safety, and performance standards for all firmware contributions to **pocket-dial**. All Pull Requests (PRs) must strictly comply with these rules to pass the automated gating pipelines and peer reviews.

---

## 1. Quality Control & PR Lifecycle Rules

### A. Maximum Diff Size Restrictions
To maintain thorough peer reviews, keep your code changes small and focused:
* **The Rule**: A single Pull Request must not contain more than **500 lines of modified code** (excluding auto-generated files, assets, or markdown documentation).
* **Rationale**: Large PRs hide bugs, increase lock contention on developer review cycles, and complicate rollback strategies.
* **Exceptions**: Major upstream refactoring campaigns may exceed this limit but require pre-approval from the lead architect.

### B. Required Review Checklist
Before any PR can be merged into `main`, it must receive at least **two approvals** from senior firmware maintainers verifying the following checklist:

- [ ] **No Dynamic Allocation**: Code executed within the `RequestsHandler` path or any network packet loop contains zero dynamic allocations.
- [ ] **Bounds-Checked Strings**: All string copy or formatting tasks utilize `strlcpy` or `snprintf` with explicit size boundaries.
- [ ] **Lock Hold Duration**: Mutex acquisitions inside signaling paths are kept short. Slow disk or socket I/O are never executed inside a locked scope.
- [ ] **Checked Returns**: All NVS flash, driver registrations, and socket syscall return codes are explicitly checked and handled.
- [ ] **No Unchecked Pointers**: Any pointer dereferencing has been pre-verified against `nullptr` (particularly in fallback/onboarding modes).
- [ ] **Core Affinity Alignment**: Pinned tasks match the dual-core topology and do not unbalance Core 0/1 workloads.
- [ ] **Gated HTTP Routes**: Every new route in `HttpServer::handleClient()` passes through `requireAdmin()`, with `needCsrf = true` for anything that mutates state. No route implements its own origin, session, or token check.
- [ ] **Central Response Path**: Buffered responses go out through `sendResponseWithHeader()` so the security headers (CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Cache-Control`, `Referrer-Policy`) are emitted. New code does not write a response to the socket directly — the captive-portal `302` in `sendRedirect()` is the sole existing exception, and it should not gain company.
- [ ] **Partition Contract Intact**: `nvs`, `otadata`, `phy_init`, `ota_0` and `ota_1` keep their exact offsets and sizes in `partitions.csv`. Moving any of them breaks OTA compatibility with every deployed board.
- [ ] **`cfgseed` Stays Read-Only**: No firmware code calls `esp_partition_write()` or `esp_partition_erase_range()` on `cfgseed`. The browser flasher is its only writer.
- [ ] **Seed Format In Lockstep**: A change to the seed record in `src/Helpers/DeviceConfig.hpp` is mirrored in `docs/flasher/index.html` in the same PR.
- [ ] **Docs Ship With The Change**: A new or re-gated endpoint updates `docs/API.md` and `docs/API_TESTS.md`; a partition or flash-procedure change updates `docs/FLASHING.md`.

---

## 2. Security-Sensitive Areas

Three parts of this firmware have a single correct implementation and a
tempting-looking wrong one. Reviewers should treat a diff touching any of them as
requiring a second look.

### The HTTP gate is one function, not a per-route habit

`HttpServer::requireAdmin(sock, req, needCsrf)` applies same-origin → session →
CSRF in that order, and it is the only place any of those three checks belongs.
The reason is empirical: `POST /api/configuring` shipped with no gate at all, and
`/api/pcap`, `/api/trace` and `/api/diagnostics/pcap` shipped with no same-origin
check, precisely because each route was expected to remember on its own. Route
handlers must contain no auth logic.

The same-origin check deliberately admits a request with **no** `Origin` header —
that is what `curl`, native clients and `tests/http/test_api.sh` send — so it is a
browser-only control and cannot stand alone. The per-session `X-CSRF` token is
what closes that gap on a provisioned device. Do not "simplify" the Origin check
to reject missing origins; it would break the smoke suite and the captive portal
without adding anything the token does not already cover.

### The seed record is append-only, and the version does not move

`regMode` was added at byte 13 behind `kSeedHasRegMode` (bit 5) **without**
bumping `kSeedVersion`, and that was the point: every field is gated by its own
`has-*` flag and every reader ignores flags it does not recognise, so old
firmware skips the new bit and applies the rest, and new firmware reading an
older record leaves the field alone. Bumping the version would have made older
firmware reject the whole record.

Add future fields the same way — in the reserved space, behind a new flag bit —
and never repurpose an existing bit. Also keep the "unwritten partition reads as
`0xFF` and must be silently ignored" property: an absent or blank `cfgseed` is
the normal case on OTA-updated boards and on the 4 MB constrained layout, not an
error to report.

### Defaults stay conservative

The shipped posture is an **open** SoftAP, an **`open`** SIP registrar, plain
HTTP, and unsigned OTA. WPA2 on the SoftAP (`ap_secure`) and the `learn`/`secure`
registrar modes are opt-in, because each of them breaks an already-deployed fleet
the moment it is turned on. A PR that flips one of these defaults is a
breaking change and needs to be argued as one, not slipped in as a hardening
tidy-up.

---

## 3. Prohibited Patterns & Technical Antipatterns

The following code patterns are strictly prohibited. The CI static analysis pipeline will flag and reject any commits containing these blocks.

### 🔴 Prohibited Pattern 1: Dynamic Allocation in Real-Time Path
Do not allocate memory on the heap within high-frequency loops or signaling pathways.

```cpp
/* ─────────────────────────── BAD: PROHIBITED ─────────────────────────── */
void RequestsHandler::onInvite(std::shared_ptr<SipMessage> data) {
    // VIOLATION: Heap allocation inside the UDP packet handling loop!
    auto newSession = std::make_shared<Session>(data->getCallID(), srcClient);
    _sessions[data->getCallID()] = newSession;
}

/* ─────────────────────────── GOOD: MANDATORY ─────────────────────────── */
void RequestsHandler::onInvite(std::shared_ptr<SipMessage> data) {
    // CORRECT: Recycle pre-allocated memory from the static session pool
    auto newSession = allocateSession(data->getCallID(), srcClient);
    if (!newSession) {
        sendResponse(503, "Service Unavailable");
        return;
    }
    _sessions.emplace(data->getCallID(), newSession);
}
```

---

### 🔴 Prohibited Pattern 2: Unbounded String Copy (strcpy / sprintf)
Using unbounded string copy commands introduces buffer overflow vulnerabilities.

```cpp
/* ─────────────────────────── BAD: PROHIBITED ─────────────────────────── */
void saveCredentials(const char* ssid, const char* pass) {
    wifi_config_t wifi_config;
    // VIOLATION: Stack buffer overflow if inputs exceed 32 or 64 bytes!
    strcpy((char*)wifi_config.ap.ssid, ssid);
    strcpy((char*)wifi_config.ap.password, pass);
}

/* ─────────────────────────── GOOD: MANDATORY ─────────────────────────── */
void saveCredentials(const char* ssid, const char* pass) {
    wifi_config_t wifi_config = {};
    // CORRECT: Copy with strict bounds limits
    strlcpy((char*)wifi_config.ap.ssid, ssid, sizeof(wifi_config.ap.ssid));
    strlcpy((char*)wifi_config.ap.password, pass, sizeof(wifi_config.ap.password));
}
```

---

### 🔴 Prohibited Pattern 3: Blocking Socket Calls Inside Mutex Locks
Never execute blocking network, file system, or flash operations while holding the primary registrar lock.

```cpp
/* ─────────────────────────── BAD: PROHIBITED ─────────────────────────── */
void RequestsHandler::handle(std::shared_ptr<SipMessage> request) {
    std::lock_guard<std::mutex> lock(_mutex);
    
    // VIOLATION: Holding registrar mutex while calling a blocking network syscall!
    // This can stall the entire signaling thread for milliseconds.
    sendto(_socket, response.c_str(), response.size(), 0, &dest, sizeof(dest));
}

/* ─────────────────────────── GOOD: MANDATORY ─────────────────────────── */
void RequestsHandler::handle(std::shared_ptr<SipMessage> request) {
    std::vector<std::pair<sockaddr_in, std::shared_ptr<SipMessage>>> localOutbox;
    {
        std::lock_guard<std::mutex> lock(_mutex);
        // CORRECT: Buffer generated responses into a local outbox inside the lock
        _outbox.emplace_back(dest, std::move(response));
        localOutbox = std::move(_outbox);
    }
    
    // CORRECT: Fire socket syscalls outside the lock context
    for (auto& event : localOutbox) {
        _onHandled(event.first, std::move(event.second));
    }
}
```

---

### 🔴 Prohibited Pattern 4: Unchecked System Return Codes
Ignoring return codes of critical systems (such as NVS flash, drivers, or network operations) will lead to hard-to-debug device states.

```cpp
/* ─────────────────────────── BAD: PROHIBITED ─────────────────────────── */
void setupNetworkMode() {
    nvs_handle_t nvs_handle;
    nvs_open("storage", NVS_READONLY, &nvs_handle);
    // VIOLATION: wifi_mode retains uninitialized stack garbage if key is missing!
    uint8_t wifi_mode;
    nvs_get_u8(nvs_handle, "wifi_mode", &wifi_mode);
    nvs_close(nvs_handle);
}

/* ─────────────────────────── GOOD: MANDATORY ─────────────────────────── */
void setupNetworkMode() {
    nvs_handle_t nvs_handle;
    uint8_t wifi_mode = 0; // CORRECT: Safe default initializer
    
    if (nvs_open("storage", NVS_READONLY, &nvs_handle) == ESP_OK) {
        // CORRECT: Check each return code and apply safe fallback on error
        if (nvs_get_u8(nvs_handle, "wifi_mode", &wifi_mode) != ESP_OK) {
            wifi_mode = 0; // AP onboarding fallback
        }
        nvs_close(nvs_handle);
    } else {
        wifi_mode = 0; // AP onboarding fallback
    }
}
```

---

## 4. Concurrency & Task Affinity Directives

1. **Keep lvgl_task Isolated**: Under no circumstances should non-UI networking or file I/O operations be dispatched onto Core 1 on display-enabled hardware configurations.
2. **Utilize Double-Buffered Getters**: Any state data required by the HTTP server or display tasks from the registrar must be queried via snapshotted APIs (`getActiveClients()`, `getActiveSessions()`). Do not introduce raw mutex sharing across Core 0 and Core 1.
3. **Interrupt Service Routines (ISRs)**: ISR handlers must strictly avoid blocking calls, standard RTOS queue inserts, or any console print operations. Only `FromISR` suffix functions (e.g. `xQueueSendFromISR`) are permitted inside hardware interrupts.

---

## 5. Host Test Suite

The gtest suite under `tests/` is the gate every PR clears before hardware is
touched. It is currently **521 cases** by static count of `TEST`/`TEST_F` in
`tests/*.cpp`, of which **519 run on Linux/WSL** — which is the number CI
enforces and the number to quote in a commit message.

The gap is not drift. `DidMapping_test.cpp` and `TelephonyApiConfig_test.cpp`
each carry a `#if !defined(_WIN32) ... #else ... #endif` pair around their
persistence tests, because `persist()` is in-memory only under `_WIN32` (no
POSIX permission model, so the host fallback refuses to write a world-readable
file). The POSIX arms hold 3 and 2 real cases; each Windows arm holds one
`GTEST_SKIP` placeholder. So a POSIX host compiles out 2 and runs **519**, and
Windows compiles out 5 and runs **516**. A static grep always reads 521.

The same three commands CI runs, from a WSL shell:

```bash
unset IDF_PATH                                        # see below
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build/tests --output-on-failure
```

* **Unset `IDF_PATH` first.** The root `CMakeLists.txt` branches on it: with the
  variable defined it includes `$ENV{IDF_PATH}/tools/cmake/project.cmake` and
  configures an ESP-IDF cross-build, so the host tests are never generated.
* **`--test-dir build/tests` is required.** Testing is enabled only inside the
  `tests/` subdirectory, so the CTest set lives there, not at the build root.
* **Run it from WSL, not natively.** Several suites open real sockets; running
  them on Windows triggers firewall authorisation prompts.
* Keep the count in this section current when you add or remove cases.

### 🔴 The `AdminHttpGate_test` trap

Any new case in `tests/AdminHttpGate_test.cpp` that **provisions a PIN** must
construct a real `RequestsHandler` and attach it. From the file's own comment:

> A real `RequestsHandler` is required: once a PIN exists the listen socket is
> dark by default and only opens inside an admin-open window, which set-pin
> grants. Without the handler the test measures a refused connection rather than
> the gate.

The failure this produces looks nothing like the thing under test — you get a
connection error instead of the `401`/`403` you were asserting on, and the gate
logic is never reached. Copy the setup from an existing provisioning case rather
than writing a fresh one.
