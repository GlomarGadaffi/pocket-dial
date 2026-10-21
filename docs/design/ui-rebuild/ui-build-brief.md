# pocket-dial web UI rebuild — build brief

Worktree: `C:\Users\desmo\w\pd-ui-rebuild` (branch `feat/ui-rebuild`, base origin/main de61ba14). WSL path: `/mnt/c/Users/desmo/w/pd-ui-rebuild`.
Backend and API are unchanged. Only the embedded page, one generator tool, and the tests that pin the page change.

Inputs to read first:
- API contract: `C:\Users\desmo\AppData\Local\Temp\claude\C--Users-desmo\4845dcb2-339e-4a78-8576-cc4b91c75e34\scratchpad\fresh\api-contract.md` (route table, auth rules, section→route map in §6, "no API: omit" list).
- Codebase map: `...\scratchpad\fresh\pocket-dial-map.md` (what is unverified; do not pretend it is done).
- Visual source: `...\scratchpad\fresh\primitives.html` — copy its `:root` token block (light + both dark blocks), font stacks, top bar, dense nav, hairline and row-height rules. System font stacks only. No web fonts, no CDN, no external anything: the board serves this offline.
- Current page, for behaviour only: `src/Helpers/index_html.h` in the worktree. Do not copy its markup or CSS.

## 1. Source layout (new)

```
web/
  index.html            shell: <!DOCTYPE>, head, top bar, nav, <main> with one <section id="sec-<name>" hidden> per section, footer, then the JS include order
  app.css               all CSS (inlined by the generator)
  app/00-core.js        helpers below; auth; poll loop; toasts; confirm; banners
  app/10-overview.js … app/90-console.js   one file per section, same number as its fragment
  sections/10-overview.html … sections/90-console.html   the inner markup of each <section>
  manifest.txt          ordered list of files the generator concatenates
```
Sections, in nav order (file numbers fixed so agents never collide):
10 overview, 20 extensions, 30 devices, 40 trunks-numbers, 50 routing, 60 call-handling, 70 audio, 80 security (incl. E911), 85 maintenance, 90 console.

The generator inlines everything into ONE document: `<style>` from app.css, each section fragment inside its `<section>`, then one `<script>` with the JS files in manifest order. Relative URLs only. No `alert/confirm/prompt`; use `ui.confirm`.

## 2. Generator: `tools/gen_index_html.py`

- `python tools/gen_index_html.py` writes `src/Helpers/index_html.h`; `--check` exits 1 if the written file would differ (CI uses this).
- Keeps, byte for byte, from the existing header: the top comment block through `struct HtmlPart {...};`, and everything from the `// Issue #159 (SMTP client)` comment above `PD_HTML_8` through `)html9";` (the two standalone pages). Then writes the SPA parts and the array.
- Splits the SPA into `static const char PD_HTML_N[] =\nR"htmlN(` … `)htmlN";` parts, each ≤ 16000 bytes of content (384 bytes under the 16384 cap, so the checker's 512-byte "tight" warning is the only thing that may fire). Distinct delimiter per part. Prefer splitting at a newline. The `__PD_CSRF__` marker must appear exactly once in the SPA and must never straddle a part.
- Emits `CGA_INDEX_HTML_PARTS[]` listing `{PD_HTML_N, sizeof(PD_HTML_N) - 1}` for the SPA parts only (never 8 or 9), then `CGA_INDEX_HTML_PART_COUNT` and `#endif // INDEX_HTML_H`, same shape as today.
- LF line endings in and out. Fails loudly if any source contains `)html` followed by a digit and `"` (would end a raw literal early).
- Unit test `tests/tools/test_gen_index_html.py` (unittest, like `tests/tools/test_http_load.py`): round-trip, cap, marker-not-straddled, delimiter uniqueness, preserved-8-and-9 regions.
- After generating, `python tools/check_string_literal_caps.py` must pass.

## 3. Core API the sections code against (app/00-core.js owns these; sections only call them)

```js
function $(id)                                   // document.getElementById
function httpMethod(method, path, body)          // fetch wrapper: credentials "same-origin"; X-CSRF header on non-GET; body as x-www-form-urlencoded string;
                                                 // reads text first then JSON; 401 → session ended (show login); 403 → reload prompt; 409 → ui.confirm then resend with confirm=LOCKOUT; 429 → lockout message
function post(path, body) / put(path, body) / del(path, body)   // via httpMethod; AdminHttpGate_test requires factoryReset/startApMode/holdConfigMode/otaReboot to call post("/api/..."), never fetch() directly
function setMsg(id,txt,cls){ … }                 // writes text into #id; sets role: cls==="err" ? "alert" : "status"  (pinned by DashboardA11yText_test, exact source: setAttribute("role",cls==="err"?"alert":"status"))
                                                 // on load: querySelectorAll(".msg[id]").forEach(function(e){e.setAttribute("role","status");})  (pinned, keep verbatim)
ui.toast(text, kind)                             // persistent region, never hidden; kind err uses role=alert
ui.confirm(title, line, actionLabel) → Promise<bool>   // modal, red confirm button named for the action; Esc/Cancel resolves false
store.signal(v) / store.effect(fn)               // ~30-line signal store; status is a signal every section may subscribe to
poll.register(path, ms, fn, always)              // see §5; core owns the setInterval lines
adminState = { needsSetup, loggedIn, role, csrf }
nav.show(name)                                   // sets [aria-current], unhides #sec-<name>; hash #<name> deep-links
```
While `adminState.needsSetup` is true, only the setup form renders. Gate Owner-only controls on `adminState.role` (OTA upload, factory reset, coredump download, media-tx, encrypted export/import) and provide a set-owner-credential form in Security (today's UI lacks one).

## 3a. Patterns borrowed from ESP32_AdBlocker_Reborn (owner's call, 2026-10-16)

1. CSRF in one place: a `submit` listener that appends `csrf=` to every POST form's action, and a `window.fetch` wrapper that adds the `X-CSRF` header to every non-GET. Sections never set the header themselves. `httpMethod` still owns the 401/403/409/429 handling.
2. Poll only while visible, patch in place: the poll loop pauses on `visibilitychange` hidden and resumes (with one immediate poll) on visible. Renders patch existing elements; never replace a container that holds a form or a focused input.
3. Section memory: current section in `location.hash` AND `sessionStorage` (try/catch), so it survives a reload or a navigation that drops the fragment.

## 4. Pinned by tests — keep these names and sentences verbatim

Function signatures (tests slice bodies from `function name(args){` to the next `\n}\n`, so every top-level function is written exactly `function name(a,b){` with no spaces and ends with a line that is just `}`):
`fetchStatus(){`, `fetchAdminStatus(){`, `fetchCdr(){`, `fetchE911(){`, `applyE911(d){`, `applyEmergencyRoute(d){`, `renderBoard(d){`, `updateRail(d){`, `renderRegistrar(`, `renderWifi(nets){`, `setMsg(id,txt,cls){`, `factoryReset(){`, `startApMode(){`, `holdConfigMode(){`, `otaReboot(){`, `httpMethod(`.

Element ids: `e911-exts`, `e911-callback`, `e911-location`, `e911-save` (markup must contain `id="e911-save" disabled`), `e911-msg`, `e911-banner`, `<span id="e911-banner-text">`, `e911-route-banner` (its opening tag must contain `display:none`), `<div class="e911" id="setup-banner" role="alert"`, `reg-roster-note`.

Exact source fragments:
- `fetch("/api/e911-config"` and `put("/api/e911-config"`; the page must NOT contain the text `PUT /api/e911-config`.
- In fetchE911: `$("e911-save").disabled=false` on success; in its `.catch(`: `$("e911-save").disabled=true` and `setMsg("e911-msg"`.
- Default E911 banner sentence contains: `A 911 call still routes out, but nobody on site is`. applyE911 references `$("e911-banner-text")`, `d.emergencyRoute==="anchor"`, the text `3CX anchor`, `t._def===undefined`, and the string `e911-banner`; there is a comment `/* #167` after the applyE911 body. applyE911 must hide the E911 banner when `d.emergencyRoute==="none"` (the route banner stands up instead). No `e911-unverified-banner`, no `trunk-unverified`.
- fetchStatus body calls `applyE911(d)` and `applyEmergencyRoute(d)`; page contains `d.emergencyRoute==="none"`.
- renderBoard contains `d.rosterVisible===false`, `' registered. Log in to see them.'`, `d.clientCount===1?' phone'`. updateRail reads `d.clientCount`. fetchCdr checks `r.status===401` and shows `Log in to view the call log`.
- fetchAdminStatus: `adminState.needsSetup=!!d.needsSetup`; must not contain `.catch(function(){})`; contains `setupBanner(adminState.needsSetup?`, `SIP stays off until a real admin login is set`, `Could not read admin status: `.
- Learn hint (Extensions): `<strong>Learn</strong> adopts an unknown phone on first contact` … inside the same `<div>`: `locks the extension to that device on its next registration`, `another subnet`, `if no other phone claimed it first`. Must NOT contain `so nobody else can take it over` or `only locked to that device once an admin secures it`.
- renderRegistrar reads `x.locked` and `x.shared` and writes state cells containing `\u00b7 locked`, `\u00b7 shared`, `\u00b7 unlocked`. The `reg-roster-note` div contains `<strong>locked</strong>`, `<strong>shared</strong>`, `a NAT router, or a phone moved while unlocked`.
- renderWifi: rows are `createElement("button");row.type="button"` with `row.className="wifi-net"`; never `createElement("div");row.className="wifi-net"`.
- factoryReset confirm text mentions every one of: admin login, DTMF PIN, carrier trunk, Telephony API, SIP password, call forwards, E911, DID mappings, call history, voicemail, saved Wi-Fi, cannot be undone. Must NOT contain `erases saved Wi-Fi config and reboots`.
- CSRF: `var PD_CSRF="__PD_CSRF__";` exactly once in the whole SPA.

## 5. Poll table (pinned by tests/load/http_load.py and tests/tools/test_http_load.py)

Core emits these exact substrings:
`setInterval(fetchStatus,2000)`, `setInterval(fetchCdr,5000)`, `setInterval(fetchAdminStatus,15000)`, `fetchOtaStatus();},15000)`, `setInterval(pollTrace,1500)`, `fetchMohStatus();},3000)`, and `fetch("/api/status"`, `fetch("/api/cdr"`, `fetch("/api/admin/status"`, `fetch("/api/ota/status"`, `fetch("/api/trace"`, `fetch("/api/moh"`.
Trace polls only while trace is on; MOH polls only while the Audio section is shown. The drift test currently pins the MOH guard as `$("pbx-modal").classList.contains("show"))fetchMohStatus()`; the integrator replaces that ONE assertion in `tests/tools/test_http_load.py` with the new guard expression. Nothing else in the harness changes.

## 6. Sections → routes

Each section reads its row in api-contract.md §6 and wires every route listed there. Features in the "no API: omit" list are not built and not stubbed. Mark nothing as verified that the codebase map lists as unverified (on-device RTP, OTA rollback, live 911, signing). E911 form is editable (the API exists: GET/PUT /api/e911-config) — that is different from the mockup's read-only row.

## 7. Style and size

Dense operator console: 12–13 px sans chrome, monospace only for extensions, MACs, IPs, timestamps, timers, badges, keybindings. 1 px hairlines, zero radius, rows 24–28 px, no shadows. Both themes via the token blocks. Phone width 400 px: no horizontal page scroll. prefers-reduced-motion stops every animation. Status = glyph + word, never colour alone. Keyboard: nav items reachable, `aria-current`, disabled controls use `aria-disabled` and stay focusable, live regions persistent. Size (revised 2026-10-16 after measuring flash headroom: 4 MB display image leaves ~280 KB, eth/wifi ~900 KB, 16 MB slots 4 MB+): target ≤ 160 KB generated SPA, hard stop 200 KB. Do not cut features to hit the target; tighten code instead (the first build's JS was ~120 KB for work the old page did in ~95 KB).

## 7a. STRICT UI CONSTRAINTS (owner's, 2026-10-16; these override §7 and the primitives.html source where they differ)

1. ZERO border-radius. Every corner 0px, controls included.
2. NO floating cards with gaps. Panes share a 1px solid border grid: `border-collapse: collapse` on tables, 0px margin between panes, adjacent panes share one hairline.
3. Palette is SOLID HEX ONLY, single dark theme (drop the light/dark token switching for this page; keep `color-scheme: dark`): `#0a0a0a` void (page), `#1a1a1a` panel, `#ffb000` amber (action, focus, current), `#00ff66` phosphor (ok/online/live), `#d0d0d0` text. Add only what is needed from the same family: a dim text (`#8a8a8a`), a hairline (`#333333`), an alarm red (`#ff3b30`) for alarm/error only. NO Tailwind slate/indigo (`#0f172a`, `#6366f1`), NO `backdrop-filter`, NO `rgba()`/translucent backgrounds anywhere.
4. Max padding inside any data cell: `4px 8px`. Rows as dense as the text allows.
5. NO pill badges, NO rounded toggles (checkboxes/radios are square native or 1px-bordered squares), NO CSS transitions or animations: state changes are 0ms. (The reduced-motion rule becomes moot; keep the blink for the terminal cursor only if it is a step animation and stops under prefers-reduced-motion.)
6. NO large `<h2>`/`<h3>` inside boxes. Group with `<fieldset>`/`<legend>` or a top-border inlaid label (small uppercase sans on the top hairline).
7. All numeric data, IPs, ports, MACs, timestamps, timers and SIP states: monospace with `font-variant-numeric: tabular-nums`.

Contrast with this palette: #d0d0d0 on #1a1a1a ≈ 10:1, #ffb000 on #0a0a0a ≈ 11:1, #00ff66 on #0a0a0a ≈ 15:1, #8a8a8a on #1a1a1a ≈ 4.6:1 (dim text only at ≥ 12 px). Status still = glyph + word, never colour alone.

## 7b. ISA-101 HMI CONSTRAINTS (owner's, 2026-10-16; SUPERSEDES §7a wherever they differ)

Geometry: 0 border-radius everywhere; zero-gap shared-wall grid (`gap:0`, collapsed 1px hairlines, panels lock like rack gear); max padding 4px 6px in any cell or container; no hero, no centred marketing layout. Fixed viewport: a persistent 28–32px **Unacknowledged Alarm Banner** locked at the top (lists active off-normal states from /api/status and /api/admin/status: needsSetup, emergencyRoute none, anchor down, pool refusals, OTA pending; an `[ ACK ]` control clears it client-side in sessionStorage until the state changes) and a **Function-Key Bar** locked at the bottom.

Function keys: browsers reserve F5, F11, F12, so the bar is `F1 MAIN · F2 EXT · F3 TRUNKS · F4 ROUTES · F6 CALLS · F7 AUDIO · F8 SEC · F9 MAINT · F10 LIVE`. Devices becomes a sub-tab inside EXT. Alt+digit remains as a silent fallback. preventDefault only on the keys the bar claims.

Colour physics (colour by exception): nominal state is grayscale only — chassis `#121212`, panel face `#1c1c1c`, grid lines `#333333`, nominal text `#a0a0a0`, dim text `#666666`. Green is NOT used for online/registered/OK; nominal is grey. Saturated colour only for off-normal or live traffic: P1 critical/fault (trunk down, pool exhausted, 5xx, emergency route none) = solid `#ff2200` fill with black bold text or inverted `[ ◆ FAULT ]`; P2 warning/degraded (retransmits, 4xx, OTA pending, needsSetup) = solid `#ffaa00` fill with black text; active call / off-hook / RTP = `#00aaff` cyan border or inverted cyan block. No rgba/hsla/opacity/backdrop-filter. No Tailwind slate/indigo, no gradients except the hazard stripe below.

Typography: numbers, IPs, ports, MACs, SIP states, timers, memory counters in a strict monospace stack with `font-variant-numeric: tabular-nums`. Every live metric sits in a **sunken readout well**: `background:#050505; border-top:1px solid #000; border-left:1px solid #000; border-right:1px solid #3a3a3a; border-bottom:1px solid #3a3a3a;` value right-aligned inside, engineering unit (`ms`, `B`, `pkts`, `calls`) in `#666` immediately outside to the right. No h1/h2/h3 inside boxes: `<fieldset>`/`<legend>` or top-border inlaid headers in 10px uppercase monospace, `letter-spacing:.08em` (silkscreen).

Components: **Annunciator panel** replaces KPI cards — a tight 1×8 or 2×6 grid of fault tiles at the top of MAIN (`HEAP`, `POOL`, `SIP BIND`, `ANCHOR`, `E911`, `NTP`, `OTA`, `WDT`, `SETUP`, `NVS`); nominal tiles `#181818` bg with `#5c5c5c` text (deliberately dim; ≈2.9:1 is a conscious exception, and every tile's state is also stated in page text), faulted tiles trip to full `#ffaa00` or `#ff2200` with a 1px inner border and black text. **No emojis, no SVG icon sets**; every state = ASCII/geometric glyph + word: `[ · IDLE ]`, `[ ▲ TX/RTP ]`, `[ ▲ WARN ]`, `[ ◆ FAULT ]`. **Controls**: no transition/animation except `steps(1)` hard blink on an unacknowledged P1; buttons have 1px bevels (light `#3a3a3a` top/left, dark `#000` bottom/right) that invert at 0ms on `:active`; destructive actions (`REBOOT`, `FACTORY RESET`, `NVS WIPE`, `DROP ALL`) are two-stage `[ ARM ]` → `[ EXEC ]`, the armed state showing a 45° `#ffaa00`/`#000` hazard-stripe border (`repeating-linear-gradient`, solid stops), and EXEC disarms after 10 s. **Mimic bus lines**: where a signal path exists (`WAN UDP:5060` → `SIP CORE` → `EXT MATRIX`; `TRUNK/ANCHOR` → `ROUTES` → `EXT`), join the panels with literal 1–2px orthogonal CSS borders instead of floating them.

Shared theme: rewrite `shared-theme.css` to this section; both products inline the same file. The mockup artifacts are not in scope for this pass.

Decisions added 2026-10-17 after the first §7b check (these are the rule, not suggestions):
- **Message fills.** Solid P1/P2 fills on `.msg` are reserved for device-fault messages (a failed save that leaves state inconsistent, a refused OTA, a lost anchor). Routine progress ("Uploading…", "Scanning…"), permission text and input validation stay grey, with a bracketed glyph + word.
- **Data tables are exempt from the well rule.** Cells inside a `<table>` render numbers as plain monospace tabular-nums; the sunken well is for standalone live readouts (status strip, KPI readouts, metrics pages, detail panes). Every standalone well still carries its unit outside in `#666`; clock-format durations use the unit `h:m:s`.
- **DND** is an operator setting, not off-normal: grey `[ · DND ]` chip inside the jack. Amber only for faults.
- **OTA in progress** is P2 (`[ ▲ UPDATING ]`), never cyan. Cyan is ringing / active / RTP only; the packet sparkline is grey at zero delta and cyan only while traffic flows.
- **Faulted tiles**: the `.p1`/`.p2` class goes on the chip as well as the tile so the text is black on the fill. The inner 1px border is `outline:1px solid #000; outline-offset:-2px`, never `box-shadow`.
- **Anchor-down alarm**: `/api/status` carries no anchor-link field today, so the annunciator omits the ANCHOR tile and the alarm bar omits it. Recorded as a backend gap for the SBC profile (`fresh/sbc-fork-scope.md` §4), which needs `AnchorClient::isConnected()` exposed anyway. No backend change in the UI passes.
- **Destructive = ARM→EXEC everywhere**, including "turn on WPA2" (every phone re-joins) and AdBlocker OTA apply. The armed label is `[ EXEC ] <action>` in red; the first stage is `[ ARM ] <action>`.
- **No pictogram controls**: Upload / Play / Stop are words. The toast dismiss control is the word DISMISS, not ×.
- **ARM→EXEC is the button itself, not a dialog** (decided 2026-10-17 after the second check): a destructive control is ONE button. First press: it becomes `.armed` with the hazard border and reads `[ EXEC ] <action>` in red; a 10 s timer disarms it back to `[ ARM ] <action>`; second press within the window fires the request. No `#confirm-dlg` for destructive actions (the dialog stays only for the 409 `confirm=LOCKOUT` resend, where the server asks the question). Core provides one helper, `ui.arm(button, label, onExec)`, and every destructive trigger (forget, forget-all, clear slot, delete rule/group/mapping, regenerate PSK, WPA2 on, reboot, import, factory reset, erase coredump, AP mode) uses it. Factory reset keeps its pinned consequence sentence as the button's `aria-describedby` text, visible beside it.
- **Toast kinds**: permission text, session expiry and progress ("Rebooting…") are grey chips with glyph + word; `p1` only for device faults; `p2` only for off-normal device state.
- **Wells hold numbers only.** A well is a number plus a unit span. SBC mode, firmware partition, verify state and the CDR summary are `.st` chips or plain text, never wells.
- **History rows are not current faults.** Past Unavailable/Failed calls in any log or table render as grey chips with glyph + word, no fill.
- **Maintenance OTA row** matches the MAIN tile: `[ ▲ UPDATING ]` with `p2` while in progress.
- **Page title** is not an `<h1>` inside the boxed bar; it is the inlaid label.
- **One theme source**: `app.css` = shared-theme.css verbatim + one labelled product block; the AdBlocker's `ADB_THEME_RAW` = the same file. Any base-rule delta lives in the product block, never edited in the shared copy.

## 9. SBC profile (owner's, 2026-10-16; queued after the ISA-101 pass)

Build profile, not a fork: CMake option `POCKETDIAL_PROFILE_SBC` (default OFF) in `main/CMakeLists.txt`, passed as a compile definition, like the existing POCKETDIAL_* flags. UI-only in this pass; the backend is untouched.

Manifest gets `@unless MACRO` (inverse of `@if`): the generator wraps the part and its array entry in `#if !defined(MACRO) || !defined(ESP_PLATFORM)`, so host builds and tests still carry the whole page. Mark with `@unless POCKETDIAL_PROFILE_SBC`: 50-routing, 60-call-handling, 61-paging, 70-audio, and the DID-mapping sub-fragment of 40-trunks-numbers (split it into 41-did.{html,js} the way Wi-Fi was split). The shell builds nav and the F-key bar from the sections present in the DOM, renumbering F-keys over F1–F4, F6–F10 in nav order; a missing `#sec-*` is never an error.

SBC-specific copy, compile-guarded with the STRICT form `@only POCKETDIAL_PROFILE_SBC` (added 2026-10-17: `@only MACRO` emits `#if defined(MACRO)` with NO host fallback, so the lab's desktop/host build never carries product-profile copy; `@if` keeps the `|| !defined(ESP_PLATFORM)` fallback and stays reserved for hardware features such as Wi-Fi and paging whose code the host tests must cover; `@unless` keeps its fallback). Host-side coverage of the SBC copy comes from the generator's own unit test (it preprocesses the header with and without the macro and asserts the strings' presence/absence), not from shipping the copy to the host page. In a tiny 05-sbc.{html,js}: top-bar product string `POCKET-DIAL SBC`; Trunks & numbers titled `3CX`; the E911 annunciator tile reads `[ · E911 VIA 3CX ]` when `emergencyRoute==="anchor"` (the default banner text stays as pinned); the verify well on MAIN shows `SBC mode: host-tested only` until a hardware record exists (#201 merged, never bench-verified). Sections kept: MAIN, EXT (no per-extension forwarding/DND controls under the profile: hide them with the same guard), 3CX (anchor slot, Activate, Test dial, SBC mode on + route slot), SEC, MAINT, LIVE.

Verification: generator `--check`, caps checker, unit tests with a guarded-and-unless test, host suite green, and a compile of the header with `-DPOCKETDIAL_PROFILE_SBC=1 -DESP_PLATFORM=1` through the host compiler as a preprocess-only pass (`g++ -E -DPOCKETDIAL_PROFILE_SBC -DESP_PLATFORM -x c++ src/Helpers/index_html.h`) to prove the excluded parts vanish and the CSRF marker survives; report the SBC image's SPA bytes.

## 8. Verification (integrator)

1. `python tools/gen_index_html.py && python tools/check_string_literal_caps.py && python -m unittest tests/tools/test_gen_index_html.py tests/tools/test_http_load.py`
2. Host build + tests in WSL (IDF_PATH must be unset there): `wsl -e bash -c "cd /mnt/c/Users/desmo/w/pd-ui-rebuild && cmake -B build-wsl -G 'Unix Makefiles' -DCMAKE_BUILD_TYPE=Release && cmake --build build-wsl --target sip_parser_tests -j8 && ./build-wsl/tests/sip_parser_tests --gtest_filter='Dashboard*:HttpStaticPages*:AdminHttpGate*:EmergencyRoute*'"` then the full suite. Build dirs stay inside the worktree; never touch the shared clone or other worktrees.
3. Desktop smoke: `./build-wsl/SipServer --ip 127.0.0.1 --port 5060 --web 8080` (or the host target's actual name), then curl `/` and confirm one substituted marker and Content-Length matches.
4. No git commit, no push. Leave the worktree dirty for review.
5. **Page-boot smoke (added 2026-10-17 after a missing `)` in 50-routing.js shipped through three "ALL GREEN" integrations).** Core's init ends with `document.documentElement.setAttribute("data-booted","1")` (only reached if the whole script block parsed and ran). With the desktop server running, from Windows: `"C:\Program Files\Google\Chrome\Application\chrome.exe" --headless=new --disable-gpu --virtual-time-budget=4000 --dump-dom http://127.0.0.1:<web>/ > dom.html` and the step passes only if `dom.html` contains `data-booted="1"`. Also run it once after the factory login (pass the session cookie via `--header`? not supported: instead log in through a tiny Python script that fetches `/` with the cookie and compare the anonymous DOM against the authenticated one for the `data-booted` marker; the anonymous boot is the gate). A served page without the marker is a FAILED integration regardless of the test suite. No Node exists on this box or in WSL; headless Chrome is the JS parser.
