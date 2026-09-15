# pocket-dial. TUI Information Architecture (SSH Sysop Terminal)

> **Phase-A deliverable (UX Architect).** Reads from and stays consistent with
> [`00-brief.md`](00-brief.md) (canonical), [`brand.md`](brand.md) (name treatment, banner,
> status lexicon, voice), and [`personas.md`](personas.md) (Task Inventory §3 = coverage
> checklist; design implications D1–D13). Grounded in the firmware that actually ships:
> `src/SIP/PbxConfig.hpp`, `PoolConfig.hpp`, `CallDetailRecord.hpp`, and the CLASS feature-code +
> DTMF-admin handlers in `src/SIP/RequestsHandler.cpp`.
>
> This file owns: the master hub, the full v1 screen tree, the global keybinding scheme,
> the panel/tab interaction model, and the SSH-first onboarding wizard. Downstream:
> [`tui-style.md`](tui-style.md) (UI Designer) renders these screens in full ANSI;
> [`walkthrough.md`](walkthrough.md) walks the flows.


## 0. IA principles (the load-bearing rules every screen obeys)

These translate the brief's hard constraints and the personas' design implications (D1–D13) into
architecture. Every decision below traces to one of them.

1. **Stable 3-zone geometry, 80×24 floor (D13).** Every screen is `title bar / body / key-hint
   footer`. Row 1 = title bar (`POCKET-DIAL vX.Y  [MODE]  HH:MM:SS`). Rows 2–22/23 = body. Bottom
   row = footer (live hotkeys + theme label). No horizontal scroll; extra columns are a bonus.
2. **The hub is a typeahead, not a menu walk (D1).** Single-key hub hotkeys fire *without* Enter and
   *without* waiting for a redraw, so `3 → 1 → A` is one fluid keystroke run. Hotkeys are stable and
   global within a context so muscle memory survives.
3. **Esc-to-back is universal and non-destructive (D7).** Esc backs out one level without saving;
   from the hub, Esc is a no-op (you're home). There is exactly one back semantics, everywhere.
4. **`?` help on every screen (D3).** Scoped to the current screen, overlaid, Esc-dismissed. No task
   requires an external manual.
5. **State = glyph + label, color last (D11).** Every status uses the brand status lexicon
   (`brand.md` §4.5). The label is authoritative; the glyph reinforces; color is the removable third
   layer. Screens are fully legible in monochrome.
6. **Batch beats modal (D2).** The marquee provisioning path is a range field, not N dialogs.
7. **Guard dangerous surfaces, don't hide them (D9).** `[A!]` actions (delete, reboot, network-mode
   switch, factory reset) are visible but gated behind a confirm dialog with consequence text and a
   safe default.
8. **Real features only.** Every screen maps to a shipping firmware capability. No trunks, FXO/FXS,
   queues, conferencing, voicemail (v2), or SD card appears anywhere.
9. **Embedded redraw discipline.** Live screens (`[1]` monitor, hub footer counters) repaint cell
   ranges via cursor positioning at ~1 Hz, never full-screen clears (brief §6).


## 1. The master HUB (landing screen)

After auth (banner → PIN), the hub is home. It is the brief's numbered command matrix, reconciled to
pocket-dial's real feature set. `[6] ADDONS` from the brief's example matrix is **renamed `[6] ABOUT`**
, pocket-dial ships no add-on/plugin surface, and an empty "ADDONS" menu would violate the honesty
clause (`brand.md` §6.10). ABOUT carries the firmware/build/license/scaling facts an installer reads.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ POCKET-DIAL v3.0      [ SYSTEM MANAGEMENT ]                         18:14:22   │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                                │
│     [1] SYSTEM MONITOR        [2] NETWORK          [3] PBX CONFIG              │
│     [4] SECURITY              [5] REPORTS/LOGS     [6] ABOUT                   │
│                                                                                │
│     [R] REBOOT     [L] LOGOUT                                                   │
│                                                                                │
│   ● 4 ONLINE   ○ 1 UNREACH    ·    1/8 calls    ·    ext 12/32    ·   AP mode  │
│                                                                                │
│   Select an option: _                                                          │
│                                                                                │
├──────────────────────────────────────────────────────────────────────────────┤
│ [1-6] Go  [R] Reboot  [L] Logout  [?] Help            Theme: BRASS ▸           │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Hub anatomy**
- Title bar (row 1): brand spine. `[ SYSTEM MANAGEMENT ]` is the contextual mode; the clock is
  `HH:MM:SS`, repainted in place each second (no full clear).
- Matrix (body): six numbered destinations + two single-key system actions (`[R]`, `[L]`). Keys
  are unique first-characters so typeahead never collides.
- Ambient headroom line (D12): the live one-liner surfaces the two hard ceilings *before* anyone
  hits a 503, registration tally (`● ONLINE`/`○ UNREACH` glyph+label), `n/8 calls`, `ext n/32`, and
  network mode. This row repaints ~1 Hz like the monitor.
- Prompt: `Select an option: _`, a single keystroke dispatches; no Enter required (D1).
- Footer: the always-visible key-hint line, ending in the **theme label** (`Theme: BRASS ▸` /
  `Theme: PHOSPHOR ▸`) so the active theme is named, never read by hue (`brand.md` §5).

**Hub destinations → personas → Task-Inventory coverage** (personas §3):

| Key | Destination | Primary persona | Covers (personas §3) |
|----|-------------|-----------------|----------------------|
| `1` | SYSTEM MONITOR | Both | M1–M4 (live matrix, roster, vitals, ring-test) |
| `2` | NETWORK | Installer (Admin views) | N1, N2 `[A!]` |
| `3` | PBX CONFIG | Both | E1–E6, G1–G6, F1–F6, V1–V3 |
| `4` | SECURITY | Both | O2/S1 (PIN), S2 (SSH), S-factory-reset |
| `5` | REPORTS/LOGS | Admin | R1–R4 |
| `6` | ABOUT | Installer | hardware/build honesty, caps, license |
| `R` | REBOOT `[A!]` | Both | N3 |
| `L` | LOGOUT | Both | S3 |
| `?` | HELP (overlay) | Both | S4 (global) |


## 2. Full screen tree (v1)

Legend: `│├└` tree edges · `(hotkey)` single-key entry · `[A!]` guarded/destructive ·
`◇` modal/overlay · `⟳` live ~1 Hz refresh · `→ Task IDs` map to personas §3.

```
SSH CONNECT
│
├─ LOGIN BANNER  (brand.md §3 — front door; firmware sshd greeting)
│   └─ PIN PROMPT  → O2/S1 verify (AdminAuth, 50k-round SHA-256, never echo)
│
├─ ◇ FIRST-RUN WIZARD  (forced on un-provisioned box; §5 below)   → O1–O6
│   └─ on completion → HUB
│
└─ HUB  [ SYSTEM MANAGEMENT ]   ·  Esc = no-op (home)  ·  ? = help overlay
    │
    ├─(1) SYSTEM MONITOR  ⟳  [ MONITOR ]                            → M1–M4
    │   │   Single live wallboard; cursor-positioned cell repaint, no full clear.
    │   ├─ Live call matrix     CH · EXT · DEST · DUR · CODEC · STATUS   → M1
    │   ├─ Registration roster  ● ONLINE / ○ UNREACH per extension       → M2
    │   ├─ Hardware vitals      CPU/mem bars · uptime · pool n/8 calls    → M3
    │   ├─(C) Clear stale rows
    │   ├─(F) Freeze/unfreeze refresh   (pause the 1 Hz repaint to read)
    │   └─ (ring-test is "place a call, watch it light up" — no sub-screen) → M4
    │
    ├─(2) NETWORK            [ NETWORK ]                            → N1–N2
    │   ├─ Status panel  mode · IP · SSID · pocketdial.local · link/DHCP  → N1
    │   └─(M) Switch network mode  [A!]  SoftAP(2) ↔ Client(1)             → N2
    │         └─ ◇ Confirm: "Mode switch drops Wi-Fi for ~Ns. [y/N]"
    │             (wifi_mode NVS toggle 1↔2; same op as DTMF *PIN#101)
    │
    ├─(3) PBX CONFIG        [ PBX CONFIG ]   ← tabbed panel (§4)
    │   │   Tab strip:  Extensions │ Ring Groups │ Forwards/DND │ IVR │ Features
    │   │   [←/→] move tab · [Tab] next tab · keys below are per-tab
    │   │
    │   ├─ TAB · Extensions   (default tab)                          → E1–E6, F1
    │   │   ├─ Roster table  EXT · NAME · ● ONLINE/○ UNREACH · DND · FWD  → E1
    │   │   ├─(A) Add…  ◇ submenu: single | range                         → E2/E3
    │   │   │     ├─ ◇ Add single   number + PIN + name                   → E2
    │   │   │     └─ ◇ Add range    101-124 + PIN policy + opt. group     → E3
    │   │   │           └─ pre-apply cap check  "Pool after 36/32 ⚠"     → E6
    │   │   ├─(Enter) Edit row  ◇ PIN / display name                      → E4
    │   │   ├─(D) Delete  [A!]  ◇ confirm (warns group membership)        → E5
    │   │   └─(F) Features for row → jumps to Forwards/DND focused on ext  → F1–F5
    │   │
    │   ├─ TAB · Ring Groups                                         → G1–G6
    │   │   ├─ Group list  NAME · MODE · #members · ⚠ integrity flag      → G1/G6
    │   │   ├─(A) Add group  ◇ name → member-pick → mode                  → G2
    │   │   ├─(Enter) Edit group  ◇ editor:                               → G3/G4
    │   │   │     ├─ Mode: (•) Ring everyone  ( ) One at a time           → G3
    │   │   │     ├─ Members: checklist from extension roster             → G2
    │   │   │     └─ Hunt order / per-member timeout (Hunt mode only)     → G4
    │   │   └─(D) Delete group  [A!]  ◇ confirm (members detach)          → G5
    │   │
    │   ├─ TAB · Forwards/DND   (per-extension call features)        → F1–F5
    │   │   ├─ Feature table  EXT · DND · CFU → · CFB → · CFNA →          → F1–F4
    │   │   ├─(Space) Toggle DND on focused ext  → badge flips live       → F1
    │   │   └─(Enter) Edit forwards ◇  Always / Busy / No-answer targets  → F2–F5
    │   │         └─ blank a field = clear that forward                   → F5
    │   │
    │   ├─ TAB · IVR   (minimal: DTMF menu → prompt/route; NO queues)→ V1–V3
    │   │   ├─ Digit map  0-9/*/# → action (ring ext | ring group | prompt)→ V1
    │   │   ├─(Enter) Edit digit  ◇ pick action + target/prompt           → V1/V2
    │   │   ├─ Greeting prompt  pick from on-flash prompts partition      → V2
    │   │   └─(T) Set as answer point / test the digit map                → V3
    │   │
    │   └─ TAB · Features  (read-only star-code reference card)      → F6
    │       └─ The CLASS codes the *phones* dial (verified vs firmware):
    │            *60 DND on · *80 DND off · *72<ext> Forward-all on
    │            *73 Forward-all off · *69 Last caller · *11 Echo test
    │
    ├─(4) SECURITY          [ SECURITY ]                            → O2,S1,S2,S4
    │   ├─(P) Change admin PIN  ◇ old → new → confirm (never echoed)      → S1
    │   ├─(K) SSH access  authorized key + PIN-login policy               → S2
    │   ├─ Session info  who/where logged in · sessions logged to CDR
    │   └─(X) Factory reset  [A!]  ◇ double-confirm (wipes config+PIN)
    │         (returns the box to the first-run wizard state)
    │
    ├─(5) REPORTS/LOGS      [ REPORTS ]   ← two views, [Tab] switches → R1–R4
    │   ├─ VIEW · Recent Calls (CDR)   newest-first ring of 32            → R1–R3
    │   │   ├─ Row  TIME · FROM → TO · RESULT(glyph+word) · TALK          → R2/R3
    │   │   │     RESULT ∈ {✓ answered · ⊘ busy · … cancelled ·
    │   │   │               ○ unreachable · ▲ failed}  (real CdrResult)   → R2
    │   │   └─(Enter) Call detail  ◇ full record (start, duration, ids)   → R3
    │   └─ VIEW · Event Log tail   live system log (queueLog)             → R4
    │
    ├─(6) ABOUT             [ ABOUT ]
    │   └─ Honesty card: "This is an ESP32-S3" · FW vX.Y.Z · build ·
    │       caps (32 extensions / 8 concurrent calls) · "voicemail in v2" ·
    │       license · host/MAC.   (no config here — read-only)
    │
    ├─(R) REBOOT  [A!]  ◇ Confirm "REBOOT now? phones drop for ~8s. [y/N]" → N3
    │
    ├─(L) LOGOUT  → closes the SSH session cleanly (logged to CDR)        → S3
    │
    └─(?) HELP OVERLAY  (global; context-scoped; Esc dismisses)           → S4
```

### 2.1 Why each branch exists (and what it deliberately omits)

- **`[3]` is a single tabbed panel, not five hub entries.** Extensions / Ring Groups / Forwards-DND /
  IVR / Features are *tabs* of one PBX-CONFIG panel (the brief's ncurses tab strip), so the brief's
  `3 → 1 → A` (PBX-CONFIG → first tab → Add) is one keystroke run with no intermediate menu. The tab
  strip replaces the brief's example `Extensions │ Trunks │ Routes │ IVR │ Voicemail` with **real
  tabs**: `Trunks` and `Routes` are dropped (no trunking/routing), `Voicemail` is dropped (v2);
  `Ring Groups`, `Forwards/DND`, and a `Features` reference are added because those are what ships.
- **Forwards/DND is its own tab** rather than buried per-row, because it is Dana's day-2
  bread-and-butter (F1–F5) and deserves a flat table where DND toggles and three forward targets are
  visible at a glance. The Extensions tab's `(F)` key cross-links to it focused on the selected ext.
- **Features tab is read-only.** Star codes are dialed on the *phones*, not configured here; the tab
  is a reference card so Dana can answer "what do I dial to turn off forwarding?" (`*73`). Listing the
  real, firmware-verified codes (not invented ones) honors the honesty clause.
- **`[5]` has two views (CDR + Event Log)** under one hub key because both answer "what happened?"
, the CDR for calls (R1–R3), the log tail for system events (R4). `[Tab]` flips between them.
- **Factory reset lives in `[4]` SECURITY**, not NETWORK, because it is a credential/identity-wiping
  act; it is `[A!]` double-confirmed and dumps you back into the first-run wizard, closing the loop.
- **Reboot and Logout stay on the hub** (`[R]`/`[L]`) exactly as the brief specifies, system-level
  acts that should be reachable from home in one key.


## 3. Global keybinding scheme

One scheme, learned once, true everywhere (D10: experts chain it, beginners read it off the footer).
Keys are grouped by scope. **Single-key hub hotkeys never need Enter** (D1); panel navigation uses
arrows/Enter/Tab; Esc always backs out one level (D7).

### 3.1 Global (work on every screen)

| Key | Action | Notes |
|-----|--------|-------|
| `?` | Context help overlay | Scoped to current screen; `Esc` dismisses. Never leaves the screen. |
| `Esc` | Back out one level | Non-destructive; discards unsaved edits in a dialog. No-op on the hub. |
| `Ctrl-L` | Redraw screen | Recovers from line noise on a serial console; full repaint. |
| `L` | Logout | From the hub only (panels use `Esc` to return home first). |

### 3.2 Hub (typeahead, single keystroke, no Enter)

| Key | Action |
|-----|--------|
| `1` | SYSTEM MONITOR |
| `2` | NETWORK |
| `3` | PBX CONFIG |
| `4` | SECURITY |
| `5` | REPORTS/LOGS |
| `6` | ABOUT |
| `R` | REBOOT `[A!]` (opens confirm) |
| `L` | LOGOUT |
| `T` | Toggle theme BRASS ↔ PHOSPHOR (footer label updates) |

> `T` (theme) is a hub-level toggle so it is always one Esc + one key away from any screen, and the
> footer's theme label updates immediately, the only "preference" in the product.

### 3.3 List / table panels (Extensions, Ring Groups, Forwards/DND, CDR, roster)

| Key | Action |
|-----|--------|
| `↑` / `↓` | Move row selection |
| `PgUp` / `PgDn` | Page through long lists (32-deep CDR, full roster) |
| `Enter` | Open / edit the selected row (modal) |
| `Tab` / `←` `→` | Switch tab (in `[3]`) or view (in `[5]`) |
| `A` | Add (new extension / group / etc.) |
| `D` | Delete selected `[A!]` (opens confirm) |
| `Space` | Toggle the row's binary state (DND on/off; member in/out of a group) |
| `/` | Filter/jump-to (type an extension number to seek) |
| `Esc` | Back to parent panel / hub |

### 3.4 Forms / editors / wizard steps (field-based dialogs)

| Key | Action |
|-----|--------|
| `Tab` / `↓` | Next field |
| `Shift-Tab` / `↑` | Previous field |
| `Space` | Toggle a radio/checkbox option |
| `←` / `→` | Move within a radio group / between `< Apply > < Cancel >` buttons |
| `Enter` | Apply / advance to next wizard step |
| `Esc` | Cancel without saving / previous wizard step |
| `Backspace` | Edit the focused text field |

### 3.5 Confirm dialogs (`[A!]` destructive)

| Key | Action |
|-----|--------|
| `←` / `→` | Choose between buttons (safe default pre-selected) |
| `Enter` | Confirm the highlighted choice |
| `y` / `n` | Shortcut for inline `[y/N]` prompts (`N` is the safe default) |
| `Esc` | Cancel (equivalent to choosing the safe default) |

### 3.6 Live monitor `[1]`

| Key | Action |
|-----|--------|
| `F` | Freeze / unfreeze the ~1 Hz refresh (read a moment without it moving) |
| `C` | Clear stale / torn-down rows from the matrix |
| `Esc` | Back to hub |

> Reserved-but-unused (honesty): the brief's monitor example shows `[P] PCAP`. pocket-dial ships
> no on-device packet capture (no SD card, RTP is peer-to-peer), so **`P` is not bound**, listing a
> key that does nothing would violate the honesty clause. The monitor footer shows only real keys.

### 3.7 Footer contract (how keys are always discoverable. D10)

Every screen's footer lists **only the keys live on that screen**, left-to-right by frequency, and
always ends with the theme label. Examples:

```
Hub:        [1-6] Go  [R] Reboot  [L] Logout  [?] Help            Theme: BRASS ▸
Ext table:  [↑/↓] Select  [Enter] Edit  [A] Add  [D] Del  [Esc] Back  [?] Help  · BRASS
Monitor:    [F] Freeze  [C] Clear  [Esc] Main  [?] Help                       · BRASS
Confirm:    [←/→] Choose  [Enter] Confirm  [Esc] Cancel
```


## 4. Panel & tab interaction model

The brief's two interaction archetypes, the **hub** (single-key launcher) and the **ncurses config
panel** (tab strip + data table + action buttons), are the only two body layouts. Everything is one
or the other, which is what keeps the geometry stable (D13) and the keys consistent (D10).

### 4.1 The tabbed config panel (used by `[3]` PBX CONFIG)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ POCKET-DIAL v3.0      [ PBX CONFIG ]                                18:14:22   │
├──────────────────────────────────────────────────────────────────────────────┤
│  Extensions │ Ring Groups │ Forwards/DND │ IVR │ Features                     │  ← tab strip
│ ═══════════                                                                    │  ← active underline
│  EXT   NAME          STATE         DND   FWD                                   │  ← column header
│  101   Maria         ● ONLINE      ·     ·                                     │
│  102   Sam           ● ONLINE      ⊘     ↳ 205                                 │  ← selected row
│  103   Lee           ○ UNREACH     ·     ·                                     │
│  104   Front Desk    ● ONLINE      ·     ↳ vmbox(v2 n/a)                       │
│  …                                                              ext 12/32      │  ← headroom (D12)
├──────────────────────────────────────────────────────────────────────────────┤
│ [←/→] Tabs  [↑/↓] Select  [Enter] Edit  [A] Add  [D] Del  [Esc] Back  · BRASS │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Model rules**
- **Tab strip = horizontal mode switch.** `[←]/[→]` or `[Tab]/[Shift-Tab]` move the active tab; the
  active tab is marked by an underline **and its name** (never highlight color alone. D11). Tabs do
  not scroll horizontally; all five fit in 80 cols.
- **One data table per tab.** `[↑]/[↓]` move row selection (a `▸`/inverse marker pairs with position,
  so selection is legible in mono). `[Enter]` opens the row's editor as a centered modal.
- **Action verbs are keys, not on-screen buttons to mouse.** `A`dd / `D`elete / `Enter`(edit) are the
  table verbs; the footer names them. Inside editor *dialogs*, on-screen `< Apply > < Cancel >`
  buttons exist and are reached with `←/→`, because forms benefit from a visible commit affordance.
- **Headroom is ambient (D12).** The cap (`ext 12/32`) sits bottom-right of the table body, not in an
  error, you see the ceiling approaching before you hit the 503.
- Esc semantics: in a table, `Esc` → hub. In an editor modal opened from a table, `Esc` → back to
  the table (discarding edits). One level at a time, always.

### 4.2 Modal editors (Add/Edit dialogs)

A modal is a centered box over the dimmed panel. It is a **form** (§3.4 keys): `Tab` between fields,
`Space` toggles options, `Enter` applies, `Esc` cancels. Modals are used for: add-single-extension,
add-range, edit-extension, group editor, forward editor, IVR digit editor, PIN change. Destructive
modals (`[A!]`) add a consequence line and a safe-default button (§4.3).

### 4.3 Confirm dialog (the single guarded-action pattern. D7/D9)

Every `[A!]` action funnels through one confirm pattern: a `▲` glyph, the action in plain words, a
consequence sentence, and two buttons with the **safe choice pre-selected**.

```
┌─ Confirm ──────────────────────────────────────────────┐
│  ▲ ALERT   Delete extension 103 (Lee)?                  │
│                                                         │
│  Lee is a member of ring group "sales" and will be     │
│  removed from it. This cannot be undone.                │
│                                                         │
│        < Delete >          [ Keep, go back ]           │  ← safe default focused
├─────────────────────────────────────────────────────────┤
│ [←/→] Choose   [Enter] Confirm   [Esc] Cancel           │
└─────────────────────────────────────────────────────────┘
```

The same shell wraps reboot (`REBOOT now? phones drop for ~8s. [y/N]`), network-mode switch, and
factory reset (which double-confirms). Copy follows `brand.md` §4.1: fact, consequence, safe default;
blame the input not the user; no exclamation marks.

### 4.4 The two-view panel (used by `[5]` REPORTS/LOGS and the wizard's review)

`[5]` is a table-panel variant with **no tab strip** but a `[Tab]`-toggled view selector named in the
title area (`Recent Calls ◂▸ Event Log`). Same row/scroll keys as §3.3. This keeps "two related
read-only views under one hub key" from needing a second hub slot.


## 5. SSH-first onboarding wizard

The wizard is the heart of the redesign: it **replaces the entire `gen_provision_nvs.py` →
`nvs_partition_gen.py` → `esptool write_flash 0x9000` toolchain ritual** over SSH in one sitting (D5).
It is **forced** on an un-provisioned box (no usable default state exists. O1), **linear, numbered,
and resumable** (D3): an interrupted install resumes at the last completed step, because each step
persists to NVS as it is applied. It uses the form keys (§3.4); `Enter` advances, `Esc` steps back,
and there is a visible step counter so the installer always knows how far they are.

### 5.1 Step sequence

```
FIRST-RUN WIZARD  (forced; resumable)            → personas §3.1 O1–O6
│
├─ [0/5]  Welcome / "Patching you through…"
│         What this does · how long (~3 min) · "Esc backs out, your work is saved"
│
├─ [1/5]  NETWORK MODE                                                  → O3, O4
│         (•) Join my network (Wi-Fi client, DHCP)   ( ) Standalone hotspot (SoftAP)
│         → on Client: pick SSID + passphrase; confirm DHCP lease
│         → on SoftAP: show the SSID/passphrase phones will join
│         Confirms reachable identity: pocketdial.local · IP/SSID  (wifi_mode 1|2)
│
├─ [2/5]  ADMIN PIN                                                     → O2
│         Set master PIN · enter twice · never echoed
│         (AdminAuth salted 50 000-round SHA-256 — the artifact's hash, done on-box)
│         Strength/length hint inline; this PIN gates SSH login + DTMF admin menu.
│
├─ [3/5]  ADMIN EXTENSION                                              → (sets _adminExt)
│         The extension that owns the box (gets the DTMF *PIN#code admin menu).
│         number + PIN + name.  Pre-fills as the first roster entry.
│
├─ [4/5]  FIRST EXTENSIONS  (the batch — the marquee step)             → O5, E3, E6
│         Range ....... [ 101-124        ]  (24 extensions)
│         PIN policy .. (•) Random per-ext  ( ) Same PIN  ( ) Match number
│         Add all to group [ sales ▾ ]  (optional)
│         Pre-apply cap check:  "Pool after 25/32 — OK"  /  "37/32 ⚠ EXCEEDS CAP"
│         (one keypress provisions the block — never N dialogs)
│
└─ [5/5]  DONE · HANDOFF CARD                                          → O6
          Summary the installer reads to the admin and/or prints:
            HOST · pocketdial.local   ADDR · 192.168.1.50
            ADMIN PIN · (set)         EXTENSIONS · 24 provisioned (101-124)
            What Dana can touch: extensions, DND, forwards, groups, reports
            What's guarded: network mode, delete, reboot, factory reset
          → < Finish > drops into the HUB, with [1] MONITOR one key away so the
            ring-test (M4) is the immediate next act: "place a call, watch it light up."
```

### 5.2 Wizard interaction rules

- **Resumable (D3).** Each step commits to NVS on `Enter`. If the SSH session drops mid-install, the
  next connect re-enters the wizard at the first incomplete step, never from zero.
- **Esc steps back, never forward, never destroys.** From `[0/5]` Esc is a no-op (you cannot escape
  setup on an un-provisioned box, there is nothing usable behind it). This is the one place Esc does
  not reach the hub, because there is no hub yet.
- **Numbered + footer-guided (D10).** Every step shows `[n/5]` and a footer:
  `[Tab] Field  [Enter] Next  [Esc] Back  [?] Help`. Help is per-step.
- **Cap is predictive (D12), not punitive.** Step 4's range field shows the post-apply pool count and
  flags `⚠ EXCEEDS CAP` *before* apply, so the installer corrects the range instead of meeting a 503.
- **Ends in evidence (D4).** Finishing the wizard lands on the hub adjacent to the live monitor, so
  the installer's acceptance test (ring a phone, watch the matrix and the `● ONLINE` dots) is the
  natural next keystroke, the handoff closes on proof, not hope.

### 5.3 Wizard ⇄ steady-state mapping (no orphan screens)

Every wizard step has a permanent home in the hub so day-2 edits use the *same* screens (D10, one
mental model, two speeds). Nothing learned in the wizard is thrown away:

| Wizard step | Permanent home | Re-entry |
|-------------|----------------|----------|
| [1] Network mode | `[2]` NETWORK → `(M)` switch `[A!]` | change SSID / mode later |
| [2] Admin PIN | `[4]` SECURITY → `(P)` change PIN | rotate the PIN |
| [3] Admin extension | `[3]` PBX CONFIG · Extensions | edit like any extension |
| [4] First extensions | `[3]` PBX CONFIG · Extensions `(A)` | add more, single or range |
| [5] Handoff card | `[6]` ABOUT | re-read host/build/caps anytime |


## 6. Coverage matrix, every Task-Inventory item has a home

Cross-checked against `personas.md` §3 (the authoritative checklist). Every task lands on exactly one
primary screen; cross-links noted. No task is unmapped; no screen lacks a task.

| Task | Where it lives | Notes |
|------|----------------|-------|
| O1 forced first-run | Wizard (forced on un-provisioned box) | §5 |
| O2 admin PIN | Wizard [2/5] → `[4]` SECURITY `(P)` | salted 50k-round hash, on-box |
| O3 network mode | Wizard [1/5] → `[2]` NETWORK `(M)` | wifi_mode 1↔2 |
| O4 reachable identity | Wizard [1/5] + `[2]` status | pocketdial.local / IP / SSID |
| O5 block provision | Wizard [4/5] → `[3]` Ext `(A)` range | the marquee batch |
| O6 handoff card | Wizard [5/5] → `[6]` ABOUT | what's safe / what's guarded |
| E1 list w/ live state | `[3]` Extensions table | ● ONLINE / ○ UNREACH |
| E2 add single | `[3]` Extensions `(A)`→single | isValidAor |
| E3 add range | `[3]` Extensions `(A)`→range | bulk over `_clientPool` |
| E4 edit | `[3]` Extensions `(Enter)` | PIN / name |
| E5 delete `[A!]` | `[3]` Extensions `(D)` + confirm | frees pool slot |
| E6 cap (32) | pre-apply check + hub `ext n/32` | never a silent 503 |
| G1 list groups | `[3]` Ring Groups table | mode + members |
| G2 create / pick members | `[3]` Ring Groups `(A)` | checklist from roster |
| G3 mode plain-language | group editor radios | "Ring everyone"/"One at a time" |
| G4 hunt order/timeout | group editor (Hunt mode) | per-member sequence |
| G5 edit/delete `[A!]` | `[3]` Ring Groups `(Enter)`/`(D)` | confirm on delete |
| G6 integrity warning | `⚠ NOT AN EXTENSION` in list/editor | member-validation |
| F1 DND toggle | `[3]` Forwards/DND `(Space)` | badge flips live |
| F2 CFU always | Forwards/DND editor | ForwardConfig::always |
| F3 CFB busy | Forwards/DND editor | ForwardConfig::busy |
| F4 CFNA no-answer | Forwards/DND editor | ForwardConfig::noAnswer |
| F5 clear forwards | blank a field in editor | empty = unset |
| F6 star-code reference | `[3]` Features tab (read-only) | real codes only (§6.1) |
| V1 DTMF digit map | `[3]` IVR tab | digit → action |
| V2 pick prompt | `[3]` IVR | on-flash prompts partition |
| V3 set/test answer point | `[3]` IVR `(T)` |, |
| M1 live call matrix | `[1]` MONITOR ⟳ | ≤8 sessions |
| M2 registration roster | `[1]` MONITOR | ● ONLINE / ○ UNREACH |
| M3 hardware vitals | `[1]` MONITOR | CPU/mem/uptime/pool n/8 |
| M4 ring-test | `[1]` MONITOR (place a call) | installer acceptance test |
| R1 browse recent calls | `[5]` Recent Calls | ring of 32, newest-first |
| R2 outcome in words | `[5]` row RESULT column | real CdrResult (§6.2) |
| R3 caller/callee/time/dur | `[5]` `(Enter)` detail | CallDetailRecord fields |
| R4 event/log tail | `[5]` Event Log view | queueLog |
| N1 network status | `[2]` NETWORK | mode/IP/SSID/link |
| N2 mode switch `[A!]` | `[2]` NETWORK `(M)` + confirm | wifi_mode toggle |
| N3 reboot `[A!]` | hub `[R]` + confirm | phones drop ~8s |
| S1 change PIN | `[4]` SECURITY `(P)` | salted hash |
| S2 SSH access | `[4]` SECURITY `(K)` | key / PIN policy |
| S3 logout | hub `[L]` | clean session close |
| S4 `?` help everywhere | global overlay | every screen |
| (cross-cutting) Esc-back, footer, confirm-on-destructive, glyph+label | global (§0, §3) | every screen |

### 6.1 Star-code reference (Features tab), verified against firmware

These are the **only** codes the firmware's CLASS handler actually implements
(`src/SIP/RequestsHandler.cpp`); the Features tab lists exactly these, no invented ones:

| Code | Action | Firmware |
|------|--------|----------|
| `*60` | Do-Not-Disturb **on** for the caller's extension | SCR enable → `_dnd` |
| `*80` | Do-Not-Disturb **off** | SCR disable |
| `*72<ext>` | Forward-all **on** to `<ext>` (4+ digits) | CFU enable → `_forwards.always` |
| `*73` | Forward-all **off** | CFU disable |
| `*69` | Speak last caller's extension | CDR lookup → echo 777 |
| `*11` | Echo loopback (line test) | RTP reroute → 777 |

> Admin-only DTMF menu (caller must be the admin extension): `*<PIN>#001` NTP resync,
> `*<PIN>#101` network-mode toggle. Documented in `[4]` SECURITY help, not the public Features card.

### 6.2 CDR result vocabulary, corrected to the real enum

`personas.md` §3.7 lists outcomes as "answered / busy / no-answer / cancelled / failed", but the
shipping `CdrResult` enum (`src/SIP/CallDetailRecord.hpp`) is **`Answered · Busy · Cancelled ·
Unavailable · Failed`** with `cdrResultToString` emitting the literal words below. The `[5]` Recent
Calls view uses the firmware strings (glyph + label, never color alone), so the UI never claims a
state the firmware doesn't write:

| CdrResult | Word (firmware) | Glyph + label (brand §4.5) |
|-----------|-----------------|----------------------------|
| Answered | `answered` | `✓ answered` |
| Busy | `busy` | `⊘ busy` |
| Cancelled | `cancelled` | `… cancelled` |
| Unavailable | `unavailable` | `○ unavailable` |
| Failed | `failed` | `▲ failed` |


## 7. Consistency check (brand §6.1 + brief §6)

```
[x] Name cased correctly: POCKET-DIAL in title bars/banner, pocketdial.local in hosts
[x] Title bar on every screen: POCKET-DIAL vX.Y  [MODE]  HH:MM:SS  (3-zone geometry)
[x] Every status = glyph + label (brand §4.5 lexicon); color never alone
[x] Always-visible key-hint footer ending in theme label (BRASS/PHOSPHOR)
[x] '?' help reachable on every screen; Esc backs out one level, consistently
[x] Fits 80×24, no horizontal scroll; all box glyphs have ASCII fallbacks (brand §3.3)
[x] Single-key hub hotkeys fire without Enter (D1); 3→1→A is one keystroke run
[x] Batch-provision range field is the marquee path (D2), not N dialogs
[x] All [A!] actions (delete/reboot/mode-switch/factory-reset) gated by confirm (D7/D9)
[x] Real features only — no trunks/FXO/queues/voicemail-v1/SD; Features & CDR verified vs firmware
[x] Hard caps surfaced ambiently (hub ext n/32, n/8) and predictively (pre-apply check) (D12)
[x] Wizard replaces gen_provision_nvs.py end-to-end over SSH (D5); resumable (D3); ends in proof (D4)
```


## 8. Open IA questions (hand-offs to downstream agents)

- **`[5]` two-view vs. two hub keys.** I model Recent-Calls + Event-Log as `[Tab]`-toggled views under
  one hub key to conserve the 6-slot matrix. If usability testing (personas §6.2) shows admins miss
  the log, promote it, the hub has room before `[6]`.
- **IVR scope rendering.** The IVR is deliberately "DTMF menu → ring/prompt", no queues. UI Designer
  should ensure the digit-map screen visually reads as *one shallow menu*, not a tree, to avoid
  implying IVR-tree capability we don't ship (brand bans "IVR-tree", say "menu").
- **Theme toggle key (`T`).** Placed at the hub for global reach; UI Designer confirms it doesn't
  collide with any panel hotkey (it doesn't, panels reach theme via Esc-to-hub-then-`T`).
- **SSH-key vs PIN handoff (S2).** Open per personas §6. IA reserves `[4]`→`(K)` for both; final
  policy (key required vs PIN sufficient for Dana) is a research/security decision, not an IA one.


*UX Architect · pocket-dial 3.x redesign · grounded in `src/SIP/{PbxConfig,PoolConfig,*
*CallDetailRecord}.hpp` + the CLASS/DTMF handlers in `RequestsHandler.cpp`; consistent with*
*`00-brief.md`, `brand.md`, and `personas.md`.*
