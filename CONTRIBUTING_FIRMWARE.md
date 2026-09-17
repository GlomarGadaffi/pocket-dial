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
- [ ] **Gated HTTP Routes**: Every new route in `HttpServer::handleClient()` passes through `requireAdmin()`, with `needCsrf = true` for anything that mutates state. No route implements its own origin, session, or token check. *(This is the policy, not a description of the current tree: `/`, `/config/<mac>.cfg`, `/api/status`, `/metrics`, `/api/wifi/scan`, `/api/admin/status`, `/api/ota/status` and `/setup/email` are deliberately ungated, and login/logout call `requireSameOrigin()` directly. Each exception is argued in [THREAT_MODEL.md](docs/THREAT_MODEL.md) §4 E-2 — adding a new one means updating E-2 in the same PR.)*
- [ ] **Gate by falling through, never by early `return`**: write the gate as `if (requireAdmin(...)) { ... }`, **not** `if (!requireAdmin(...)) return;`. The route chain in `handleClient()` ends in a single `closeSocket(clientSock)`, and an early `return` jumps straight over it — leaking a socket on every rejected request. Three MoH routes shipped with the early-return form and 14 unauthenticated requests took a board off the network ([THREAT_MODEL.md](docs/THREAT_MODEL.md) D-5).
- [ ] **Central Response Path**: Buffered responses go out through `sendResponseWithHeader()` so the security headers (CSP, `X-Frame-Options`, `X-Content-Type-Options`, `Cache-Control`, `Referrer-Policy`) are emitted. New code does not write a response to the socket directly — there are **no exceptions left** — `sendRedirect()`'s captive-portal `302` used to hand-roll its own response, that was the bug, and it now routes through `sendResponseWithHeader()` too (`HttpServer.cpp:3115-3123`). Keep it that way.
- [ ] **Partition Contract Intact**: `nvs`, `otadata`, `phy_init`, `ota_0` and `ota_1` keep their exact offsets and sizes in `partitions.csv`. Moving any of them breaks OTA compatibility with every deployed board.
- [ ] **`cfgseed` Stays Read-Only**: No firmware code calls `esp_partition_write()` or `esp_partition_erase_range()` on `cfgseed`. The browser flasher is its only writer.
- [ ] **Seed Format In Lockstep**: A change to the seed record in `src/Helpers/DeviceConfig.hpp` is mirrored in `docs/flasher/index.html` in the same PR.
- [ ] **Docs Ship With The Change**: A new or re-gated endpoint updates `docs/API.md` and `docs/API_TESTS.md`; a partition or flash-procedure change updates `docs/FLASHING.md`.

### C. Working Directory Convention (Multi-Agent / Multi-Contributor Sessions)

If more than one contributor (human or agent) may be working against this
repository at the same time, keep the **primary/shared clone on `main`** at
all times and do branch work in a **separate git worktree** per branch
(`git worktree add <path> <branch>`), not by checking a topic branch out
directly in the shared clone. Two contributors' sessions can otherwise race
on the same working directory — one switching branches out from under the
other mid-task — with no error, just confusing, silent-later failures
(a build or `git add` quietly operating on the wrong branch). This applies
regardless of tooling; if your environment doesn't support git worktrees or
doesn't have access to this convention ahead of time, at minimum push your
branch to origin frequently so it is never at risk even if someone else's
tooling doesn't know to look for it in a worktree.

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

touched. It is currently **799 cases** by static count of `TEST`/`TEST_F` in
`tests/*.cpp`, of which **796 run on Linux/WSL** — which is the number CI
enforces and the number to quote in a commit message. (This count merges
issue #159's SMTP-client/JWT/HTTP suites with #186/#173's config-export and
two-role suites, both landing around the same time — re-measured after the
merge rather than carried forward from either PR alone.)

The gap is not drift, though the exact size of it is worth re-deriving rather
than trusting the last committed sentence: `DidMapping_test.cpp` and
`TelephonyApiConfig_test.cpp` each carry a `#if !defined(_WIN32) ... #else
... #endif` pair around their persistence tests (`persist()` is in-memory
only under `_WIN32`), and `GoogleServiceAuthCrypto_test.cpp` (issue #159)
carries a `find_package(OpenSSL)`-conditional split — five real RS256 tests
when OpenSSL is present (the case measured here), one `GTEST_SKIP` when it
is not. A POSIX/WSL host with OpenSSL present runs **796** of the **799**
statically-counted cases; a Windows-native build's exact count was not
re-measured in this pass (its `_WIN32` persistence-test gap alone was 5 as
of the previous measurement, before either the OpenSSL split or this PR's
own test files existed) — re-verify it there before quoting a number.

Quote a number you MEASURED. Every count in this file has been wrong at least
once because someone carried forward the previous one — 310, then 506, then
521 — and a stale figure in the contributing guide teaches every future commit
message to be wrong too.

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
* **OpenSSL is optional, and only affects one thing.** Issue #159 added RS256
  JWT signing for the Workspace service-account path; on the host build that
  uses OpenSSL's `EVP_DigestSign` (the device uses mbedTLS, and IDF ships only
  `mbedtls/private/*` headers, so there is no shared backend). CI's Linux
  runner gets it from `libssl-dev`, and most Linux/WSL dev images already have
  it.

  If CMake cannot find it you get a `-- OpenSSL not found` status line at
  configure, **not** an error: the build still configures, still compiles, and
  still runs every test but the five `GoogleServiceAuthCrypto` ones, which
  compile out in favour of a single `GTEST_SKIP` so the missing coverage shows
  up in the ctest log rather than passing for green. The JWT header/claims
  construction — where the escaping and exact-shape bugs would actually live —
  is pure string work and is covered either way.

  To get the full set: `apt install libssl-dev` (Debian/Ubuntu/WSL),
  `brew install openssl` (macOS), or `vcpkg install openssl:x64-windows` plus
  `-DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake` (Windows/
  MSVC). This was briefly `find_package(OpenSSL REQUIRED)`, which meant a
  Windows host build could not configure **at all** — worth knowing if you hit
  a `Could NOT find OpenSSL` error on an older checkout.
* Keep the count in this section current when you add or remove cases.

### HTTP test ports: pick from a disjoint block, never a bare literal

Every test file that opens a real `HttpServer` binds a **fixed TCP port block
that no other test file uses.** This was not always true (issue #213): six
ports were each bound by two or three different files, and a listener that
outlived its test — an orphaned process from a killed run, two worktrees
running the suite at once, `TIME_WAIT` — failed an unrelated file's tests with
a message that named the port, not the actual cause. Two separate agents lost
time to this before finding the orphan rather than a real regression.

Current allocation:

| Block | File |
| :-- | :-- |
| `18080`-`18099` | `AdminHttpGate_test.cpp` |
| `18100`-`18109` | `DialPlan_test.cpp` |
| `18110`-`18114` | `MetricsEndpoint_test.cpp` |
| `18115`-`18119` | `PcapCapture_test.cpp` |
| `18120`-`18124` | `HttpTraceCommand_test.cpp` |
| `18125`-`18129` | `ServiceExtensions_test.cpp` |
| `18130`-`18139` | `TwoRoleAuth_test.cpp` |
| `18140`-`18159` | `ConfigExportImport_test.cpp` |
| `18160`-`18169` | `EmailHttp_test.cpp` (auto-incrementing `_nextPort`) |
| `18170`-`18179` | `ProvisioningConfig_test.cpp` (auto-incrementing `_nextPort`) |
| `18200`-`18229` | `SmtpDialogue_test.cpp` (fake SMTP server, raw sockets — not HttpServer, but still claims its own block; ~17 scripted-server tests via auto-incrementing `g_nextPort`, sized with headroom. Originally claimed 18130-18159 — renumbered here, at merge time, when that turned out to collide with the two rows above it, which claimed the same "next free block" independently and landed first. See #159's PR for the story; the lesson is in `SmtpDialogue_test.cpp`'s own header comment.) |
| `19100`+ | `TelephonyConfigHttp_test.cpp` (auto-incrementing `_nextPort`) |
| `193xx` | `ApiKillParse_test.cpp` (auto-incrementing `_nextPort`) |

**Adding a new HTTP test file:** claim the next unused `181xx`/`182xx`
ten-port block (or extend an existing file's block if you're adding tests to
it), add a row to this table, and drop a one-line comment at the top of the
file naming the block. Prefer the auto-incrementing `_nextPort` pattern
(`ApiKillParse_test.cpp`, `TelephonyConfigHttp_test.cpp`) over a fresh set of
bare literals when the file has more than a couple of `HttpServer` instances —
it removes the "did I reuse a number" question entirely.

### ~~The `AdminHttpGate_test` trap~~ — removed, and this section described deleted behaviour

This section used to warn that provisioning a PIN made the listen socket "dark by
default" until an admin-open window was granted, and quoted that as "the file's own
comment". **None of that is true any more, and the quoted comment is not in the file.**
The dark-by-default management plane and the `*4887` star-code that reopened it were
deleted — `grep 4887 src/` returns nothing — and `tests/AdminHttpGate_test.cpp:1-5` now
says the opposite: **the listen socket always accepts**, in every provisioning state, and
`AdminHttpGate.Boot_Provisioned_StillListensImmediately` pins that as a regression test.

There is also no PIN-based admin login left to provision: the web credential is a username
and password, and the separate DTMF PIN is unrelated to the HTTP plane.

A refused connection on port 80 is therefore a genuine fault, in a test or on a board.
