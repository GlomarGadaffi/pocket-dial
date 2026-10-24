# pocket-dial SSH TUI — plan (one TUI, glotui + littlessh, in-process)

Status: PLAN. Nothing here is built. glotui/littlessh have never run on a board (glossh README:11). The old `docs/design/` folder is historical and describes a deleted surface; this plan takes its keyboard idea and wizard, not its palette or screen list. The screen list mirrors the rebuilt web UI (ui-build-brief.md §7b) so an operator learns one map.

Scope: `main/` gains one component `tui/` (glotui + littlessh vendored as IDF components, one backend, no wolfSSH). The TUI is a third reader of the engine beside `tick()` and the HTTP handlers. Backend/API untouched. Gated by `POCKETDIAL_TUI` (default OFF) so the 4 MB display image is unaffected; the SBC profile (`POCKETDIAL_PROFILE_SBC`) removes sections exactly as the web manifest does.

## 1. Screen map and key paths

One key number means the same thing as a function key or a bare digit (the web bar skips F5, so the digit row skips 5; F10 = `0`). The owner's `3→1→A` chord idea is honoured as the mechanism: **digit → digit → letter, typeahead, never Enter**. Because the section order now mirrors the web F-key bar, the literal chord for "add a block of extensions" is `2 1 A` (EXT → Extensions tab → Add). Every screen: `?` help overlay (returns to origin), `Esc` back, `Ctrl-L` repaint, `L` logout from MAIN.

| Key / F-key | Section | Sub-tabs (digit) | Letter actions (typeahead) | SBC profile |
|---|---|---|---|---|
| `1` / F1 | MAIN | — | `A` ack alarm bar, `F` freeze, `C` clear | kept |
| `2` / F2 | EXT | `1` Extensions, `2` Devices | `A` add (range `101-124`, cap check), `S` secret, `F` forget, `D` DND, `W` forward | kept; `D`/`W` hidden |
| `3` / F3 | TRUNKS (SBC: `3CX`) | `1` Trunk/anchor, `2` DID | `E` edit, `T` test dial, `V` activate | kept, DID tab removed |
| `4` / F4 | ROUTES | `1` Emergency, `2` Rules | `E` edit, `D` delete | removed |
| `6` / F6 | CALLS | `1` Active, `2` CDR (ring 32), `3` Groups/IVR/Paging | `Enter` detail, `X` drop (ARM→EXEC) | removed |
| `7` / F7 | AUDIO | `1` Codecs, `2` MOH | `P` play, `S` stop (words, not glyphs) | removed |
| `8` / F8 | SEC | `1` Admin, `2` E911, `3` Learn/lock | `P` PIN, `K` SSH on/off, `O` owner credential, `X` factory reset (ARM→EXEC) | kept |
| `9` / F9 | MAINT | `1` OTA, `2` NVS, `3` About | `R` reboot, `N` NVS wipe, `U` upload (words) | kept |
| `0` / F10 | LIVE | `1` Trace, `2` Event log | `F` freeze, `C` clear, `↑↓` scroll | kept |

Within a table: `↑↓` row, `Tab`/`←→` tab, `Enter` open, `Space` toggle. In a text field: bare `Esc` always cancels (accessibility.md:379). Modals are the ARM→EXEC button itself, not a dialog: first press re-labels the field `[ EXEC ] <action>` with a hazard border (`▓▒` stripe in the 16-colour tier, `##` in mono), 10 s disarm, second press fires.

F-key decoding: `ESC O P..S` (F1-F4) and `ESC [ 1 5 ~`… `ESC [ 2 1 ~` (F5-F10). glotui's `gt_keys_t` is a 16-byte pending-escape buffer with a 2-tick lone-ESC timeout (glotui.c:598-626); whether it already emits F-key codes is **unverified** — if not, the decoder gains six cases, nothing else changes.

## 2. Layouts

Rows are fixed-purpose; the body is the only region that grows. The annunciator omits ANCHOR (no field in `/api/status`, §7b decision list), so nine tiles.

**80×24 (minimum, no horizontal scroll):**

```
POCKET-DIAL v1.5  MAIN                                      ext 12/32  18:14:22   row 1  title
[·HEAP] [·POOL] [·SIP ] [·E911] [·NTP ] [·OTA ] [·WDT ] [·SETUP] [·NVS ]        row 2  annunciator
ALARM  none                                                             [A] ACK  row 3  alarm line
                                                                                 rows 4-23 body (20)
HEAP FREE [  142,112] B   LARGEST [   65,536] B   CALLS [ 1] /8   RTT [  23] ms
...
F1MAIN F2EXT F3TRNK F4RTE F6CALL F7AUD F8SEC F9MNT F10LIVE  ?HELP           L    row 24 F-key bar
```

**132×50:** same rows 1-3 and 50; tiles expand to `[ · HEAP ]` / `[ ◆ HEAP FAULT ]` with the word; body rows 4-49 (46) split into two `gt_view`s: left 88 cols (table), right 44 cols (detail pane / wells). F-bar labels use full words. The canvas is clipped to 132×50 (`gt_resize` grows only); anything larger is centred by `ox/oy`. Below 80×24 the screen shows only the resize notice (bbs.c:936).

| Region | 80×24 | 132×50 | Rule |
|---|---|---|---|
| Title | r1 | r1 | product · section · caps `ext N/32 · N/8 calls` · clock; `POCKET-DIAL SBC` under the profile |
| Annunciator | r2, 9 tiles ≤ 8 cols | r2, tiles with state word | nominal `·` default fg; P2 `▲` yellow bg/black; P1 `◆` red bg/black; mono = inverse video |
| Alarm line | r3 | r3 | lists off-normal: setup, E911 route none, pool refusals, OTA pending; `A` acks (RAM flag, cleared when state changes) |
| Body | r4-23 | r4-49, two views | wells: `LABEL [  value] unit`, value right-aligned in a bracketed field, unit outside in dim; tables plain tabular |
| F-key bar | r24 | r50 | current section in inverse; never scrolls |

Colour tier: 16-colour palette through `gt_set_palette` ANSI-16 mapping; nominal = default fg, dim = dark grey (`DIM` only on chrome), P1 = red bg, P2 = yellow bg, active call/RTP = cyan. `TERM=dumb` or `-mono` → A11Y-1 static mode: no SGR at all, states by glyph + word, selection line spoken as `▸ <row text>` (A11Y-2). Every state is also text somewhere on the screen; the tiles' dim nominal is the one deliberate exception, as in the web.

## 3. Rendering budget and byte-rate caps

Every tick and every keystroke draws the whole screen into the back buffer; `gt_flush` sends only the diff (glotui.c:487-519). No `ESC[2J` except the one `full` flush at PIN→first screen and on `Ctrl-L`/resize.

| Item | Figure | Source |
|---|---|---|
| Tick | 1 Hz (`tick_ms=1000`), all screens; LIVE/CALLS too | matches web poll of 2 s; no 15 fps effects, no art pacing |
| Back+front buffers | 15,360 B at 80×24; 52,800 B at 132×50; growth peak 68,160 B | glotui.c:228-233 |
| `struct gt` incl. 3,072 B out buffer | ~3.3 KB | glotui.c:14,157 |
| littlessh session | ~25.5 KB, one calloc, reused | littlessh.c:169-180 |
| Task stack | 16 KB (BBS uses 12 KB with an 896 B frame on it; pocket-dial snapshots are static, see §4) | main.c:178 |
| Per-tick diff, steady MAIN | target ≤ 512 B (clock + a few wells); hard cap 4,000 B = one `lssh_write` chunk | littlessh.c:1577 |
| Worst case, full repaint 132×50 | ≈ 6,600 glyphs + SGR ≈ 10-20 KB → 3-5 packets of ≤ 4,000 B | drawbridge measured ~20 KB |
| Byte-rate cap | 8 KB/s rolling average; a tick that would exceed it is skipped (frame stays, state catches up next tick). Art-style 96 KB/s cap is not used | bbs.c:945-952 pattern |
| Inbound | 1 KB/packet, 2 KB per `on_data`; keys during `in_render` queued in `pending[64]` | littlessh.c:185,188; bbs.c:86-90 |
| Idle | `recv_timeout_ms` 10 min → logout (drawbridge had none) | littlessh.h:55 |
| Login | 60 s deadline, `auth_max_tries=3`, password = admin PIN, user free-form | littlessh.c:1119,1864 |

Heap rule: pocket-dial forbids heap after init and its free DRAM is already tight (#328). So `gt_new`/`gt_resize` at accept time is **not acceptable as-is**: the plan allocates one 132×50 cell pair + `struct gt` + the littlessh session at boot (PSRAM when present, else DRAM, ≈ 82 KB) and needs a `gt_new_static(cells, cap)` entry in glotui — a small upstream change, listed in §8.

## 4. Engine access and locking

Rule: the TUI reads exactly what the equivalent HTTP route handler reads, under the lock that handler takes, into a **static, fixed-size snapshot** owned by the TUI task. Copy, release, then render and flush. **The TUI task never holds the engine mutex across `gt_flush`/`lssh_write`** — `lssh_write` can pump up to 256 packets waiting for the peer window (littlessh.c:1577-1611), which would stall `tick()` and the SIP path behind a slow terminal. Mutations are the same `set*` calls the route handlers make, taken under the same lock, never from inside a render.

| Snapshot (static struct) | Mirrors route | Lock | Size cap | Refresh |
|---|---|---|---|---|
| status: heap, pool, SIP bind, E911, NTP, OTA, WDT, setup, NVS, counters | `/api/status` | engine mutex | ≤ 512 B | every tick |
| admin: needsSetup, role, csrf unused | `/api/admin/status` | AdminAuth lock | ≤ 64 B | every 15 ticks |
| roster: ext, state, locked/shared, IP | `/api/status` roster | engine mutex (registrar) | 32 × 48 B | every tick while EXT/MAIN shown |
| calls | `/api/status` calls | engine mutex (call table) | 8 × 64 B | every tick |
| CDR ring | `/api/cdr` | CDR ring lock | 32 × 64 B | every 5 ticks while CALLS shown |
| trace/event tail | `/api/trace`, log ring | log ring lock | one screen of lines, ≤ 46 × 132 B | every tick while LIVE shown and not frozen |
| config: trunks, routes, audio, E911 | their GET routes | config mutex | per-section struct | on section entry and after a write |
| heap_caps_get_info, esp_timer | none | none | — | every tick |

Snapshot copies are bounded by the per-row caps above, so a lock hold is a memcpy, not a string build. Writes (`set*`) return a status the TUI shows as a grey `[ · SAVED ]` chip or, for a failed save that leaves state inconsistent, a P1 message fill (web §7b "message fills").

## 5. What drawbridge's Tui.cpp gives, and what is dropped

| Keep (re-expressed on glotui) | Drop |
|---|---|
| Screen enum + router with `_helpReturn` help overlay | raw ANSI `put()`, `clearScreen()`-per-keystroke, `home()` overwrite repaints (glotui diff replaces all) |
| `isEntryScreen()` guard: digits/F-keys ignored in editors and confirms | `std::string` row building (709 refs) and per-render `std::vector` snapshot copies |
| PIN / secret / trunk-secret never echoed; mask glyph; 4-10 digits | wolfSSH backend and the 440-line duplicated provider block |
| Monitor `F` freeze / `C` clear; `P` unbound | three near-identical 30-case key switches (one dispatch table) |
| Factory reset two-stage → becomes ARM→EXEC in place | BRASS/PHOSPHOR theme toggle, `:drawbridge`/`:operator` palette, GuidedHub |
| `TERM=dumb` static mode, mono tier with zero SGR (A11Y-1) | per-session `_termCols` singleton (size lives in the per-session struct) |
| String-sink test harness; `hasColorSgr`; size clamp tests | "no idle logout" (idle logout added) |
| Provider `std::function` wiring, one copy | `Tab` cycling of sections (digits/F-keys do that; `Tab` stays for sub-tabs) |
| `.smoke/` paramiko + `pyte` frame capture, with assertions added | FirstRun `1/2/3` free-order screen (the wizard is linear and resumable) |

## 6. Onboarding wizard

Forced when `needsSetup` is true (same gate as the web's setup form), resumable from an NVS step marker, no Welcome replay on resume. Each step is one screen with the same chrome (rows 1-3, 24); the alarm line shows `▲ SETUP REQUIRED` throughout.

| Step | Content | Writes |
|---|---|---|
| `[0/5]` Welcome | nameplate, "Patching you through…", `Enter` | — |
| `[1/5]` Network | Client/DHCP vs SoftAP; current IP shown as a well | network mode |
| `[2/5]` Admin login | credential set exactly as the web setup form does (this is the SSH password from now on); never echoed | AdminAuth |
| `[3/5]` Admin extension | one extension, default 100 | registrar |
| `[4/5]` First extensions | range `101-124`; predictive `▲ EXCEEDS CAP 32` before apply; SBC profile adds an optional 3CX anchor slot line | registrar / trunk |
| `[5/5]` Handoff | card: `pocketdial.local`, `ssh` line, `1` → MAIN, "place a call, watch CALLS go cyan" | clears setup marker |

If any step still needs a host toolchain (`gen_provision_nvs.py`), the wizard has failed its brief.

## 7. Honesty copy

- MAINT › About: `TUI: host-tested only — no board record` until a bench record exists; `SBC mode: host-tested only` under the profile (#201 merged, never bench-verified), mirroring the web MAIN verify chip.
- Annunciator has no ANCHOR tile; About states `anchor link state not reported by firmware` (backend gap, `sbc-fork-scope.md` §4).
- Caps shown ambiently in the title (`ext 12/32 · 1/8 calls`) and predictively in EXT add.
- No "voicemail in v2" line (voicemail shipped, #246). No "trunk sweep" claims (#355: unwired).
- OTA rollback, on-device RTP and live 911 are not marked verified anywhere in the TUI (codebase map).
- Past Failed/Unavailable calls in CDR render as grey chips, never as a current fault.

## 8. Unverified, and the first bench test

Unverified: glotui and littlessh on any ESP board; F-key sequences through `gt_keys_feed`; the 1-4 KB/s steady-state claim; `gt_resize` after mbedTLS is up; 16 KB task stack with PSA SHA; whether pocket-dial's free DRAM takes ≈ 82 KB without PSRAM (eth/wifi variants); the `gt_new_static` change; SyncTERM/PuTTY rendering of `▲ ◆ ·` in CP437 vs UTF-8 input modes; pocket-dial lock names for the table in §4 (taken from the route handlers at implementation time, not from this plan).

First bench test (after CHECK-OUT of .244 on the board, no power pulls):
1. Record free DRAM, largest free block and the image size before flashing; flash the `POCKETDIAL_TUI=ON` upstream variant.
2. From Windows OpenSSH in an 80×24 window: `ssh -p 2222 admin@<ip>`; expect PIN prompt, then MAIN with nine tiles and the F-bar. Record free DRAM after accept; compare with step 1 (budget ≈ 82 KB + stack).
3. Idle 60 s on MAIN; count bytes with `ssh -vvv` channel stats or a Wireshark TCP byte counter; expect ≤ 1 KB/s.
4. Register one phone, place a call: the CALLS row and the title cap go cyan/`1/8` within one tick; drop it; CDR row appears grey.
5. Resize the terminal to 132×50; expect the two-view body, no `ESC[2J` storm (byte count stays under 20 KB for the resize), no alloc failure in the log.
6. Chord `2 1 A`, add `101-104`, confirm the phones register; then `8 3 X` twice with a 10 s gap to prove ARM disarms without firing.
7. Repeat step 2 with `TERM=dumb`: zero SGR bytes on the wire.
Pass = every step recorded in a comment on the tracking issue with the numbers; no "clean" claims from a tail slice.
