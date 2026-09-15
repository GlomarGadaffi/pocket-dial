# pocket-dial: ANSI Visual System & Screen Mockups (SSH Sysop Terminal)

> **Phase-A deliverable (UI Designer).** Renders the screens defined in
> [`tui-ia.md`](tui-ia.md) in full 16-color ANSI, using the identity, status lexicon, and ASCII
> fallback map locked in [`brand.md`](brand.md), the constraints in [`00-brief.md`](00-brief.md),
> and the **exact on-device RGB** in `main/ui/ui.cpp` (lines 39–64, the `PALETTES[]` struct).
>
> **This file owns:** (1) the 16-color ANSI mapping for **BRASS** and **PHOSPHOR** (role → xterm
> index → SGR code, every role paired with a glyph/label so state never relies on color alone);
> (2) a reusable **ANSI component library** drawn in box-drawing glyphs; (3) a faithful **80×24
> ANSI mockup of every screen** in the IA.
>
> Reading the mockups: the box-drawing art *is* the spec. Where a cell would be tinted, the
> color role is named in a `‹role›` annotation in the prose beside the mockup. The glyph carries
> the meaning, the color only decorates (brand §4.5). Every screen is ≤ 80 columns and ≤ 24 rows.

## 0. Design constraints this file is built to satisfy

Pulled forward from the brief and brand so the visual system is checkable against them:

- **80×24 floor**, no horizontal scroll. Every mockup below is exactly **80 columns** of frame
  (cols 1–80) and **24 rows** (row 1 title bar · rows 2–23 body · row 24 footer).
- **16-color ANSI only**, degrading to monochrome. The palette maps to the xterm-16 indices
  (0–15) so it survives PuTTY, OpenSSH, and a `TERM=vt100` serial console.
- **State is never color alone.** Every status renders as **glyph + LABEL**; color is the third,
  removable layer (brand §4.5). The mockups are legible with all SGR stripped.
- **Embedded redraw discipline.** Live cells (clock, headroom line, monitor matrix/vitals) are
  repainted by cursor positioning at ~1 Hz. The mockups mark these **`⟳ live cells`** regions so
  the renderer knows what to move-cursor-and-overwrite vs. what is static chrome.
- **One name, three casings.** `POCKET-DIAL` in title bars/banner, `pocketdial.local` in hosts.

## 1. The 16-color ANSI mapping (BRASS + PHOSPHOR)

### 1.1 How the on-device RGB maps to xterm-16

The device palette (`ui.cpp`) is true 24-bit RGB. The TUI must run in a **16-color** terminal, so
each on-device color is mapped to the **nearest xterm-16 index** that preserves the brand
intent (charcoal board, brass rails, one hot lamp, rationed red). Where the literal nearest index
would muddy the brass/charcoal read, we pick the index that keeps the *role contrast* (e.g. brass
text must out-contrast the panel) and note it.

The terminal's own palette decides the final pixel; we target the **standard xterm/VGA** 16-color
values. The mapping is by **semantic role**, not by raw hue, so a sysop's theme toggle reads as a
change of bench lighting, not a different product.

### 1.2 BRASS theme (default): amber lamps on a charcoal board

`ui.cpp` BRASS RGB → xterm-16 role:

| Role (semantic) | On-device RGB (`ui.cpp`) | xterm-16 index · name | SGR (fg / bg) | Paired glyph + label (state, never color alone) |
|---|---|---|---|---|
| **board bg** | `#161412` near-black charcoal | `0` black | bg `40` | — (the board; chrome sits on it) |
| **panel face** | `#28241E` recessed brown-charcoal | `0` black (dim) | bg `40` | — (recessed tile; framed by brass) |
| **brass rail / border** | `#B08438` brass | `3` yellow (dim) | fg `33` | the frame glyphs `╔═╗║╚╝├┤` themselves |
| **brass text** | `#D6B26E` warm brass | `3` yellow | fg `33` | all body labels / column headers |
| **bright brass / header** | `#F5D696` bright brass | `11` bright-yellow | fg `93` | section titles, `[ MODE ]`, selected-tab name |
| **accent (live lamp)** | `#FFB020` amber | `11` bright-yellow | fg `93` / bg `103` | `●`+`ONLINE`, `◆`+`ACTIVE`, `◆`+`READY` |
| **jack empty / dim** | `#1E1B17` dark recessed | `8` bright-black (grey) | fg `90` | `○`+`UNREACH` (dim, never red) |
| **DND ring** | `#FFB020` amber | `11` bright-yellow | fg `93` | `⊘`+`DND` |
| **alert / destructive** | `#C84028` ember-red | `1` red | fg `31` / bg `41` | `▲`+`ALERT`, `[A!]` actions only |

### 1.3 PHOSPHOR theme (alt): green phosphor lamps on a charcoal board

`ui.cpp` PHOSPHOR RGB → xterm-16 role. **Same chrome, same red, same amber DND**; only the live
lamp accent and the text tint shift green (the bench-lighting change):

| Role (semantic) | On-device RGB (`ui.cpp`) | xterm-16 index · name | SGR (fg / bg) | Paired glyph + label |
|---|---|---|---|---|
| **board bg** | `#10140F` charcoal | `0` black | bg `40` | — |
| **panel face** | `#1C241C` recessed | `0` black (dim) | bg `40` | — |
| **brass rail / border** | `#96823C` dim brass | `3` yellow (dim) | fg `33` | frame glyphs (rails stay brass, brand §5) |
| **phosphor text** | `#AAD296` green-grey | `2` green | fg `32` | all body labels / column headers |
| **bright phosphor / header** | `#D2F0BE` bright green | `10` bright-green | fg `92` | section titles, `[ MODE ]`, selected tab |
| **accent (live lamp)** | `#40FF60` green phosphor | `10` bright-green | fg `92` / bg `102` | `●`+`ONLINE`, `◆`+`ACTIVE`, `◆`+`READY` |
| **jack empty / dim** | `#16201C` dark recessed | `8` bright-black (grey) | fg `90` | `○`+`UNREACH` (dim) |
| **DND ring** | `#FFB020` amber (kept!) | `11` bright-yellow | fg `93` | `⊘`+`DND` (amber in BOTH themes, `ui.cpp` L61) |
| **alert / destructive** | `#DC4632` ember-red | `1` red | fg `31` / bg `41` | `▲`+`ALERT`, `[A!]` only |

Why DND stays amber in PHOSPHOR: `ui.cpp` line 61 keeps the DND ring amber in the phosphor
palette. Cross-theme consistency of a status color is itself a brand signal (brand §5), and it
prevents DND from colliding with the green "live" accent.

### 1.4 The full SGR cheat-sheet (what the renderer emits)

```
RESET ALL ............. ESC[0m
BOLD / bright ......... ESC[1m
DIM ................... ESC[2m       (used to recess the panel face vs. the rail)
UNDERLINE ............. ESC[4m       (active tab underline — pairs with the tab NAME)
REVERSE / inverse ..... ESC[7m       (selected table row — pairs with the ▸ marker)

                          BRASS                       PHOSPHOR
brass/green text ...... ESC[33m  (yellow)          ESC[32m  (green)
bright header ......... ESC[93m  (br-yellow)       ESC[92m  (br-green)
live LAMP accent ...... ESC[93m  (br-yellow)       ESC[92m  (br-green)
DND amber ............. ESC[93m  (br-yellow)       ESC[93m  (br-yellow — kept amber)
dim / UNREACH ......... ESC[90m  (br-black/grey)   ESC[90m  (br-black/grey)
alert / destructive ... ESC[31m  (red)             ESC[31m  (red)
board background ...... ESC[40m  (black)           ESC[40m  (black)
```

> Renderer rule: wrap *only* the glyph+label of a status in its accent SGR, then `ESC[0m`.
> Never tint a whole row by state. A `--no-color` client or `TERM=dumb` gets the same glyphs and
> labels with every SGR stripped, and loses nothing (proven in §1.5).

### 1.5 Monochrome degradation (the proof the color is removable)

The same hub, every SGR stripped, every box glyph dropped to its ASCII fallback (brand §3.3 map:
`╔╗╚╝═║`→`+ + + + = |`, `├┤`→`+ +`, `─`→`-`, `●`→`(*)`, `○`→`( )`, `◆`→`<*>`, `⊘`→`[/]`,
`↳`→`->`, `▲`→`/!\`, `·`→`.`, `▸`→`>`). No information is lost: the labels carry it:

```
+------------------------------------------------------------------------------+
| POCKET-DIAL v3.0      [ SYSTEM MANAGEMENT ]                         18:14:22  |
+------------------------------------------------------------------------------+
|                                                                              |
|     [1] SYSTEM MONITOR        [2] NETWORK          [3] PBX CONFIG             |
|     [4] SECURITY              [5] REPORTS/LOGS     [6] ABOUT                  |
|                                                                              |
|     [R] REBOOT     [L] LOGOUT                                                 |
|                                                                              |
|   (*) 4 ONLINE   ( ) 1 UNREACH    .   1/8 calls   .   ext 12/32   .  AP mode  |
|                                                                              |
|   Select an option: _                                                        |
|                                                                              |
+------------------------------------------------------------------------------+
| [1-6] Go  [R] Reboot  [L] Logout  [?] Help            Theme: BRASS >          |
+------------------------------------------------------------------------------+
```

Firmware selects glyph table + SGR on/off from `TERM` (and an explicit `--no-color`/serial flag).
Every mockup in §3 below is shown in its **box-drawing** form; each has this guaranteed fallback.

## 2. ANSI component library

Reusable parts. Every screen in §3 is assembled from these. Dimensions are quoted for the 80-wide
frame. Each component states its **glyph+label contract** and its **`⟳ live` vs static** nature.

### 2.1 Title bar (row 1): the brand spine

`POCKET-DIAL vX.Y   [ MODE ]   HH:MM:SS` inside the top frame rule. The clock (`HH:MM:SS`) is the
only **`⟳ live`** cell on this row, repainted in place each second, never a full clear.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ POCKET-DIAL v3.0      [ MODE ]                                      HH:MM:SS   │   ‹border›, ‹MODE›=bright header, ‹clock›=brass ⟳
├──────────────────────────────────────────────────────────────────────────────┤
```

- `POCKET-DIAL v3.0` ‹brass text›, `[ MODE ]` ‹bright header›, clock ‹brass text, ⟳ live›.
- `[ MODE ]` ∈ `{ SYSTEM MANAGEMENT, MONITOR, NETWORK, PBX CONFIG, SECURITY, REPORTS, ABOUT,
  FIRST-RUN }`, the contextual mode from the IA.

### 2.2 Key-hint footer (row 24): always visible, ends in the theme label

Lists **only the keys live on this screen**, left-to-right by frequency, and **always ends in the
named theme label** (`Theme: BRASS ▸` / `Theme: PHOSPHOR ▸`) so the active theme is read by label,
never by hue (brand §5). The `▸` is brand chrome, not state.

```
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│ [↑/↓] Select  [Enter] Edit  [A] Add  [D] Del  [Esc] Back  [?] Help  · BRASS ▸ │   ‹border›, keys ‹brass›, theme label ‹bright header›
└──────────────────────────────────────────────────────────────────────────────┘
```

### 2.3 Status chip: `[ ONLINE ]` / `[ UNREACH ]` (glyph + label, color last)

The atomic state primitive. Drawn as **glyph + LABEL**, optionally bracketed as a chip in tables.
The label is authoritative; the glyph reinforces; color decorates. From brand §4.5 + IA §6.2:

```
  ● ONLINE     ‹accent lamp›      registered / up / connected        mono: (*) ONLINE
  ○ UNREACH    ‹dim grey›         down / not registered (NOT red)    mono: ( ) UNREACH
  ◐ RINGING    ‹bright header›    ringing / in setup                 mono: (~) RINGING
  ◆ ACTIVE     ‹accent lamp›      active media (call up)             mono: <*> ACTIVE
  ⊘ DND        ‹amber, both thm›  do-not-disturb                     mono: [/] DND
  ↳ FWD        ‹brass text›       forwarded                          mono: ->  FWD
  ▲ ALERT      ‹red, rationed›    destructive / fault                mono: /!\ ALERT
```

CDR result chips (IA §6.2, real `CdrResult` enum, no invented states):

```
  ✓ answered   ‹accent›    ⊘ busy   ‹amber›    … cancelled ‹brass›
  ○ unavailable ‹dim›      ▲ failed ‹red›
```

Chip form in a column (fixed 11-wide cell so the colon column never jitters):

```
  [ ● ONLINE ]   [ ○ UNREACH ]   [ ◐ RINGING ]   [ ◆ ACTIVE ]
```

### 2.4 Numbered hub matrix: the typeahead launcher

Six numbered destinations + two single-key system keys (`R`/`L`) that **fire without Enter** (IA
§1, D1). Numbers and system letters are unique first-characters so typeahead never collides.

```
     [1] SYSTEM MONITOR        [2] NETWORK          [3] PBX CONFIG
     [4] SECURITY              [5] REPORTS/LOGS     [6] ABOUT

     [R] REBOOT     [L] LOGOUT
```

- `[n]` bracket digits ‹bright header›, destination names ‹brass text›.
- `[R] REBOOT` is an `[A!]` key: its glyph in help/confirm is `▲`; on the hub it reads plainly and
  the *consequence* lives in the confirm dialog (§2.8), not here.

### 2.5 Tab strip: horizontal mode switch (PBX Config)

Active tab marked by an **underline rule AND its name** (never highlight color alone, D11). All
five tabs fit in 80 cols. `[←/→]` or `[Tab]` moves the active tab.

```
  Extensions │ Ring Groups │ Forwards/DND │ IVR │ Features
  ══════════                                                       ‹active underline under the live tab name›
```

- Inactive tab names ‹brass text›; the active tab name ‹bright header› **and** carries the `═══`
  underline directly beneath it. Separators `│` ‹border›.
- Reports `[5]` uses the **two-view** variant (no strip): a `[Tab]`-named selector instead:
  `Recent Calls ◂▸ Event Log` (the live view name ‹bright header›, the other ‹dim›).

### 2.6 Data table: column header + selectable rows + status chips

`[↑/↓]` move the selection. The selected row pairs an **inverse field with a `▸` marker** so it is
legible in monochrome (selection is position + glyph, not color). Headroom cap sits bottom-right of
the body (D12).

```
  EXT   NAME          STATE         DND   FWD
  101   Maria         ● ONLINE      ·     ·
▸ 102   Sam           ● ONLINE      ⊘ DND ↳ 205           ‹selected: ▸ marker + reverse video›
  103   Lee           ○ UNREACH     ·     ·
  104   Front Desk    ● ONLINE      ·     ·
  …                                                  ext 12/32        ‹headroom, brass; ⟳ if live›
```

- Column header row ‹bright header›. Status cells use §2.3 chips. `·` = "none" ‹dim› (mono `.`).
- `▸` selection marker ‹bright header›; the selected row body is rendered `ESC[7m` reverse.

### 2.7 Action-button row + verb keys

Table verbs are **keys named in the footer** (`A`dd / `D`elete / `Enter`=edit), not on-screen
buttons to mouse. Inside *form dialogs*, on-screen buttons exist and are reached with `←/→`:

```
        < Apply >        [ Cancel ]                ‹focused button = reverse + < >; unfocused = [ ]›
```

- Focused button: `< Apply >` rendered `ESC[7m` reverse with the angle brackets.
- Unfocused button: `[ Cancel ]` plain ‹brass text›. Safe/cancel default pre-focused in `[A!]` flows.

### 2.8 Modal / confirm dialog: the single guarded-action pattern

A centered box over the dimmed panel. The confirm shell carries a `▲ ALERT` glyph+label, the action
in plain words, a consequence sentence, and two buttons with the **safe choice pre-focused** (IA
§4.3). Copy follows brand §4.1 (fact · consequence · safe default; no exclamation marks).

```
        ┌─ Confirm ──────────────────────────────────────────────┐
        │  ▲ ALERT   Delete extension 103 (Lee)?                  │   ‹▲ ALERT = red glyph+label›
        │                                                        │
        │  Lee is a member of ring group "sales" and will be     │
        │  removed from it. This cannot be undone.               │
        │                                                        │
        │            < Delete >        [ Keep, go back ]         │   ‹safe default focused = reverse›
        ├────────────────────────────────────────────────────────┤
        │ [←/→] Choose   [Enter] Confirm   [Esc] Cancel          │
        └────────────────────────────────────────────────────────┘
```

Plain (non-destructive) editor modals use the same box without the `▲ ALERT` line; their buttons
are `< Apply >  [ Cancel ]`.

### 2.9 Live-call matrix: the monitor's hero (`⟳ live cells`)

The BBS-glow call table. Repainted ~1 Hz by overwriting the **cell ranges** (CH/EXT/DEST/DUR/CODEC/
STATUS), never a full clear (brief §6). Each row's STATUS uses §2.3 chips.

```
  CH  EXT   DEST          DUR      CODEC   STATUS
  ──  ────  ────────────  ───────  ──────  ─────────────
  1   101   → 102          02:14   PCMU    ◆ ACTIVE          ‹STATUS + DUR = ⟳ live cells›
  2   104   → grp:sales    00:07   PCMU    ◐ RINGING
  3   —     —              —       —       ○ idle
  …
```

- Header rule ‹border›; `→` direction arrow ‹brass›; `DUR` ticks every second ‹brass, ⟳›.
- A torn-down row shows `· stale` until `[C]` clears it (IA §3.6). Idle channels read `○ idle`.

### 2.10 Vitals bars: CPU / mem (`⟳ live cells`)

10-cell block-glyph bars; the filled run is ‹accent lamp›, the empty run ‹dim›. The **numeric label
to the right is authoritative** (the bar is the reinforcing glyph, color last, even here).

```
  CPU   [██████░░░░]  61%        ‹fill=accent, empty=dim, % = brass, ⟳ live›
  MEM   [███░░░░░░░]  34%  (PSRAM 2.7/8.0 MB)
  POOL  [██░░░░░░░░]  2/8 calls
  UP    4d 02:17:50                                ‹⟳ live›
```

Block ramp for partial cells (when sub-10% resolution helps): `░▒▓█`. ASCII fallback bar:
`[######....] 61%` (mono map `█`→`#`, `░`→`.`).

### 2.11 Progress / step indicator (wizard): `[n/5]` + dot rail

The wizard step counter pairs a numeric `[n/5]` (authoritative) with a dot rail (reinforcing):

```
  STEP [2/5]   ●──●──◍──○──○        ‹done=●accent, current=◍bright, todo=○dim; [n/5] = brass›
               net  pin  ADMIN  ext  done
```

Mono: `[2/5]  (*)-(*)-(O)-( )-( )`. The `[n/5]` label is the source of truth.

### 2.12 Vertical scrollbar gutter (long lists)

For the 32-deep CDR / full roster, a single-column gutter on the right edge of the body shows a
proportional thumb (`█`) over a track (`│`). Pairs with `PgUp/PgDn` in the footer:

```
  …row…                                                                         █   ‹thumb=brass›
  …row…                                                                         │
  …row…                                                                         │
```

## 3. Full 80×24 ANSI mockups (every screen in the IA)

Each is exactly 80 columns wide and 24 rows tall (row 1 title / rows 2–23 body / row 24 footer),
except the **login banner**, which is the firmware `sshd` greeting (brand §3, ≤78-wide frame with
the `login:` line appended). Color is annotated in prose; the glyphs carry the meaning.

### 3.1 LOGIN BANNER + PIN (the front door)

The canonical banner from brand §3.2, exactly as locked, followed by the PIN prompt the firmware
appends. Frame + nameplate ‹border/brass›; `◆ READY` lamp ‹accent + the word READY + the ◆ glyph›.

```
 ╔════════════════════════════════════════════════════════════════════════════╗
 ║                                                                            ║
 ║     ____   ___   ____ _  _______ _____      ____  ___    _    _             ║
 ║    |  _ \ / _ \ / ___| |/ / ____|_   _|    |  _ \|_ _|  / \  | |            ║
 ║    | |_) | | | | |   | ' /|  _|   | |_____ | | | || |  / _ \ | |           ║
 ║    |  __/| |_| | |___| . \| |___  | |_____|| |_| || | / ___ \| |___        ║
 ║    |_|    \___/ \____|_|\_\_____| |_|      |____/|___/_/   \_\_____|        ║
 ║                                                                            ║
 ║   ◖▌  S Y S O P   T E R M I N A L  ▐◗     single-board SIP PBX             ║
 ║ ──────────────────────────────────────────────────────────────────────── ║
 ║   HOST · «pocketdial.local»            ◆ READY — operator on duty          ║
 ║   ADDR · «192.168.1.50»  ·  «AA:BB:CC:DD:EE:FF»                            ║
 ║   FW   · POCKET-DIAL «v3.0.0»  ·  up «4d 02:17»                            ║
 ║ ──────────────────────────────────────────────────────────────────────── ║
 ║   Authorized sysops only. All sessions are logged to the CDR.             ║
 ║   Press  ?  any time for help.   Esc backs out.   This is an ESP32-S3.    ║
 ║                                                                            ║
 ╚════════════════════════════════════════════════════════════════════════════╝
 login: sysop
 PIN: ••••••  ◂ never echoed (shown here as bullets only for the mockup)
```

- The `«guillemets»` are runtime fields the firmware fills (host/ip/mac/fw/uptime).
- `PIN:` is never echoed: the firmware reads it silently; the `••••••` is illustrative only.
- On a wrong PIN, the operator-terse error (brand §4.6) reprints in place: `PIN rejected. Try
  again.` It blames the input, states the fix, no exclamation mark. After N tries: a back-off notice.
- Mono fallback is brand §3.3 verbatim (`+===+`, `[*] READY`, `[#] SYSOP TERMINAL`).

### 3.2 MASTER HUB `[ SYSTEM MANAGEMENT ]`: the typeahead launcher

Faithful to IA §1. The headroom line and clock are the only **`⟳ live`** cells.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ POCKET-DIAL v3.0      [ SYSTEM MANAGEMENT ]                         18:14:22 │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│     [1] SYSTEM MONITOR        [2] NETWORK          [3] PBX CONFIG            │
│     [4] SECURITY              [5] REPORTS/LOGS     [6] ABOUT                 │
│                                                                              │
│     [R] REBOOT     [L] LOGOUT                                                │
│                                                                              │
│   ● 4 ONLINE   ○ 1 UNREACH    ·    1/8 calls    ·    ext 12/32    ·   AP mode│
│                                                                              │
│   (◉)─▶ Select an option: _                                                  │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│ [1-6] Go  [R] Reboot  [L] Logout  [T] Theme  [?] Help          Theme: BRASS ▸│
└──────────────────────────────────────────────────────────────────────────────┘
```

- `[ SYSTEM MANAGEMENT ]` ‹bright header›; `[1]…[6]` digits ‹bright header›, names ‹brass›.
- Headroom line (`⟳ live`): `● 4 ONLINE` ‹accent›, `○ 1 UNREACH` ‹dim›, counts ‹brass›. Repaints
  ~1 Hz alongside the clock. Both are cursor-positioned cell overwrites, never a full clear.
- `(◉)─▶` is the brand prompt sigil (brand §3.4); it is chrome, never changes color to signal state.
- Esc is a **no-op** here (home). `T` toggles theme; the footer label flips `BRASS ▸ ↔ PHOSPHOR ▸`.

### 3.3 `[1]` SYSTEM MONITOR `[ MONITOR ]`: the live wallboard (`⟳`)

The BBS-glow screen: live-call matrix (§2.9) + registration roster + vitals bars (§2.10). Redraws
~1 Hz by cell-range overwrite. `[F]` freezes the refresh; `[C]` clears stale rows. **`[P]` is NOT
bound** (no on-device PCAP, IA §3.6 honesty note); the footer shows only real keys.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ POCKET-DIAL v3.0      [ MONITOR ]                                   18:14:25 │
├──────────────────────────────────────────────────────────────────────────────┤
│  LIVE CALLS                                       1/8 active   ·  ⟳ 1 Hz     │
│  CH  EXT   DEST            DUR     CODEC   STATUS                            │
│  ──  ────  ──────────────  ──────  ─────  ───────────────                    │
│   1  101   → 102            02:14   PCMU   ◆ ACTIVE                          │
│   2  104   → grp:sales      00:07   PCMU   ◐ RINGING                         │
│   3   —    —                  —       —    ○ idle                            │
│   4   —    —                  —       —    ○ idle                            │
│                                                                              │
│  ROSTER   ● 4 ONLINE  ○ 1 UNREACH                VITALS                      │
│  101 Maria      ● ONLINE     104 Front Desk ● ONLINE    CPU [██████░░░░] 61% │
│  102 Sam        ● ONLINE     105 Lobby      ● ONLINE    MEM [███░░░░░░░] 34% │
│  103 Lee        ○ UNREACH    106 Warehouse  ⊘ DND       UP  4d 02:17:50      │
│                                                                              │
│  Patching you through…   place a call on any phone to watch it light up.     │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│ [F] Freeze  [C] Clear  [Esc] Main  [?] Help                    Theme: BRASS ▸│
└──────────────────────────────────────────────────────────────────────────────┘
```

- `⟳ 1 Hz` badge ‹brass› signals the live region; when `[F]` frozen, it reads `❚❚ FROZEN` ‹dim›.
- Matrix STATUS/DUR cells are the `⟳ live` overwrite zone; the ROSTER state chips repaint on
  registration change; the VITALS bars + `UP` clock repaint each second.
- `Patching you through…` is the sanctioned boot/flavor line (brand §4.4) doubling as the M4
  ring-test hint: the installer's acceptance test is "place a call, watch the matrix light up."

### 3.4 `[2]` NETWORK `[ NETWORK ]`: status + guarded mode switch

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ POCKET-DIAL v3.0      [ NETWORK ]                                   18:15:02 │
├──────────────────────────────────────────────────────────────────────────────┤
│  NETWORK STATUS                                                              │
│  ──────────────                                                              │
│   Mode ......... ◆ STANDALONE HOTSPOT (SoftAP)        wifi_mode 2            │
│   SSID ......... pocketdial-setup                                            │
│   Passphrase ... shown to joining phones on the wallboard                    │
│   Host ......... pocketdial.local                                            │
│   Address ...... 192.168.4.1   ·   AA:BB:CC:DD:EE:FF                         │
│   Link ......... ● UP   ·   DHCP server ● ON   ·   4 leases                  │
│                                                                              │
│   To put pocket-dial on your office network instead, switch to               │
│   Client mode below. Phones re-register after the link comes back.           │
│                                                                              │
│   [M] Switch network mode  [A!]   →  Client (join Wi-Fi, DHCP)               │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│ [M] Mode switch  [Esc] Back  [?] Help                          Theme: BRASS ▸│
└──────────────────────────────────────────────────────────────────────────────┘
```

- `◆ STANDALONE HOTSPOT` mode line ‹accent + label›; `● UP`/`● ON` ‹accent›. `[A!]` flags the
  guarded action; pressing `M` opens the confirm in §3.13.

### 3.5 `[3]` PBX CONFIG · **Extensions** tab `[ PBX CONFIG ]`

The default tab. Tab strip (§2.5) + roster table (§2.6). `3 → 1 → A` lands here and `A` opens Add.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ POCKET-DIAL v3.0      [ PBX CONFIG ]                                18:15:20 │
├──────────────────────────────────────────────────────────────────────────────┤
│  Extensions │ Ring Groups │ Forwards/DND │ IVR │ Features                    │
│  ══════════                                                                  │
│  EXT   NAME            STATE         DND     FWD                             │
│  ───   ─────────────   ───────────   ─────   ──────────                      │
│  101   Maria           ● ONLINE      ·       ·                               │
│▸ 102   Sam             ● ONLINE      ⊘ DND   ↳ 205                           │
│  103   Lee             ○ UNREACH     ·       ·                               │
│  104   Front Desk      ● ONLINE      ·       ↳ grp:sales                     │
│  105   Lobby           ● ONLINE      ·       ·                               │
│  106   Warehouse       ⊘ DND         ⊘ DND   ·                               │
│  107   Maria (cell)    ○ UNREACH     ·       ·                               │
│                                                                  ext 12/32   │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│ [←/→]Tabs [↑/↓]Sel [Enter]Edit [A]Add [D]Del [/]Find [Esc]Back    · BRASS ▸  │
└──────────────────────────────────────────────────────────────────────────────┘
```

- Active tab `Extensions` ‹bright header› + `═══` underline. Selected row `▸ 102` reverse video.
- `● ONLINE` ‹accent›, `○ UNREACH` ‹dim›, `⊘ DND` ‹amber›, `↳ FWD` ‹brass›. `·`=none ‹dim›.
- `ext 12/32` headroom ‹brass›, bottom-right of the body (D12); the cap is visible before a 503.

#### 3.5.1 Add submenu (`A` → single | range)

```
        ┌─ Add extension ────────────────────────┐
        │  How many?                             │
        │     ▸ < Single >     [ Range (batch) ] │   ‹focused = reverse›
        ├────────────────────────────────────────┤
        │ [←/→] Choose  [Enter] Next  [Esc] Cancel│
        └────────────────────────────────────────┘
```

#### 3.5.2 Add single: modal form (§2.2/2.8 plain editor)

```
        ┌─ Add extension · single ───────────────────────────┐
        │  Number .... [ 108        ]   3–6 digits, unique   │
        │  Name ...... [ Shipping    ]                       │
        │  PIN ....... [ ••••        ]   never echoed         │
        │                                                    │
        │  Pool after this:  13/32 — OK                      │   ‹OK = brass; ⚠ EXCEEDS CAP = red if over›
        │                                                    │
        │              < Apply >        [ Cancel ]           │
        ├────────────────────────────────────────────────────┤
        │ [Tab] Field  [Enter] Apply  [Esc] Cancel  [?] Help │
        └────────────────────────────────────────────────────┘
```

#### 3.5.3 Add range: the marquee batch (D2 / E3)

```
        ┌─ Add extensions · range (batch) ───────────────────┐
        │  Range ........ [ 101-124      ]   = 24 extensions │
        │  PIN policy ... (•) Random per-ext                 │
        │                 ( ) Same PIN  [ ____ ]             │
        │                 ( ) Match number                   │
        │  Add to group . [ sales ▾ ]   (optional)           │
        │                                                    │
        │  Pool after this:  25/32 — OK                      │   ‹if over: 37/32 ⚠ EXCEEDS CAP ‹red››
        │                                                    │
        │              < Provision >    [ Cancel ]           │
        ├────────────────────────────────────────────────────┤
        │ [Tab] Field  [Space] Pick  [Enter] Apply  [Esc] Back│
        └────────────────────────────────────────────────────┘
```

- One keypress on `< Provision >` provisions the whole block, never N dialogs (D2). The cap check
  is predictive: `⚠ EXCEEDS CAP` ‹red glyph+label› shows *before* apply if the range overflows
  the 32-slot pool, so the installer trims the range instead of meeting a 503 (D12 / E6).

### 3.6 `[3]` PBX CONFIG · **Ring Groups** tab

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ POCKET-DIAL v3.0      [ PBX CONFIG ]                                18:15:41 │
├──────────────────────────────────────────────────────────────────────────────┤
│  Extensions │ Ring Groups │ Forwards/DND │ IVR │ Features                    │
│               ═══════════                                                    │
│  NAME           MODE              MEMBERS   STATUS                           │
│  ────────────   ───────────────   ───────   ────────────────                 │
│▸ sales          Ring everyone     3         ● OK                             │
│  support        One at a time      4         ⚠ 1 NOT AN EXTENSION            │
│  warehouse      Ring everyone     2         ● OK                             │
│                                                                              │
│   Mode reads in plain language: "Ring everyone" (RingAll) /                  │
│   "One at a time" (Hunt). Open a group to set members and order.             │
│                                                                              │
│                                                                              │
│                                                                  groups 3    │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│ [←/→] Tabs  [↑/↓] Sel  [Enter] Edit  [A] Add  [D] Del  [Esc] Back   · BRASS ▸│
└──────────────────────────────────────────────────────────────────────────────┘
```

- `● OK` ‹accent›; `⚠ 1 NOT AN EXTENSION` ‹red glyph + label› is the G6 integrity flag: a member
  number that no longer maps to a real extension. Mode is plain-language (G3), never "RingAll/Hunt".

#### 3.6.1 Ring Group editor: modal (mode radios + member checklist + hunt order)

```
        ┌─ Edit ring group · sales ──────────────────────────────┐
        │  Name ..... [ sales        ]                           │
        │  Mode ..... (•) Ring everyone   ( ) One at a time      │   ‹radio: (•) selected›
        │                                                        │
        │  Members          (Space toggles)     Hunt order       │
        │   [x] 101 Maria                          1             │   ‹order column live only in Hunt mode›
        │   [x] 104 Front Desk                     2             │
        │   [x] 105 Lobby                          3             │
        │   [ ] 102 Sam                            —             │
        │   [ ] 200 (unknown)   ⚠ NOT AN EXTENSION               │   ‹red flag inline›
        │                                                        │
        │              < Apply >        [ Cancel ]               │
        ├────────────────────────────────────────────────────────┤
        │ [Tab] Field [Space] Toggle [↑/↓] Member [Enter] Apply  │
        └────────────────────────────────────────────────────────┘
```

- In **Ring everyone** mode the `Hunt order` column greys to `—` ‹dim› (order is irrelevant); in
  **One at a time** it shows the live sequence (G4). The integrity flag repeats inline so the sysop
  cannot save a phantom member silently.

#### 3.6.2 Add Ring Group: CREATE modal (the new-group flow, mirrors §3.6.1)

> Closes **walkthrough F3** (the "Add ring group" create-task had no rendered modal; only the
> §3.6.1 *Edit* modal existed; anxious Dana froze at `[3]→Ring Groups→A`). This is the IA's
> promised `(A) Add group ◇ name → mode → member-pick → hunt order` create flow (`tui-ia.md` §2,
> G2). It reuses §3.6.1 geometry **verbatim** (same 58-wide box, same keys, same footer) so there
> is no new interaction to learn. The only differences are the title, an **empty name field**,
> **zero members checked**, and the live `(0 selected)` counter that ticks up as the sysop picks.

The fresh box: name empty, mode pre-set to the safe default (`(•) Ring everyone`), **no members
checked**, Hunt-order column greyed `—`, and the live selection counter reads `(0 selected)`:

```
        ┌─ Add ring group ───────────────────────────────────────┐
        │  Name ..... [ _            ]   3–20 chars, unique      │   ‹empty field, cursor at col 1›
        │  Mode ..... (•) Ring everyone   ( ) One at a time      │   ‹radio: (•) selected = safe default›
        │                                                        │
        │  Members  (0 selected)  (Space toggles)   Hunt order   │   ‹live count ‹brass›; header ‹bright››
        │   [ ] 101 Maria          ● ONLINE           —          │   ‹state chip = §2.3; order greyed in Ring-all›
        │   [ ] 104 Front Desk     ● ONLINE           —          │
        │   [ ] 105 Lobby          ● ONLINE           —          │
        │   [ ] 102 Sam            ● ONLINE           —          │
        │   [ ] 103 Lee            ○ UNREACH          —          │   ‹offline ≠ invalid: dim, never red›
        │                                                        │
        │  Pick the extensions to ring. Order shows only in      │
        │  "One at a time" mode.                                 │
        │                                                        │
        │              < Create >       [ Cancel ]               │   ‹< Create > focused = reverse›
        ├────────────────────────────────────────────────────────┤
        │ [Tab] Field [Space] Toggle [↑/↓] Member [Enter] Create │
        └────────────────────────────────────────────────────────┘
```

After the sysop names it `frontline`, picks 3, and switches to One-at-a-time, the counter reads
`(3 selected)`, the checked rows show `[x]`, and the **Hunt order column comes alive** (G4):

```
        ┌─ Add ring group ───────────────────────────────────────┐
        │  Name ..... [ frontline   ]   3–20 chars, unique       │
        │  Mode ..... ( ) Ring everyone   (•) One at a time      │   ‹Hunt selected → order column live›
        │                                                        │
        │  Members  (3 selected)  (Space toggles)   Hunt order   │
        │   [x] 101 Maria          ● ONLINE           1          │   ‹order = pick sequence ‹brass››
        │   [x] 104 Front Desk     ● ONLINE           2          │
        │   [x] 105 Lobby          ● ONLINE           3          │
        │   [ ] 102 Sam            ● ONLINE           —          │
        │   [ ] 103 Lee            ○ UNREACH          —          │
        │                                                        │
        │  One at a time: callers hunt 1→2→3 until one answers.  │
        │                                                        │
        │              < Create >       [ Cancel ]               │
        ├────────────────────────────────────────────────────────┤
        │ [Tab] Field [Space] Toggle [↑/↓] Member [Enter] Create │
        └────────────────────────────────────────────────────────┘
```

- Distinct from §3.6.1 Edit: title `Add ring group` (no `· sales` suffix), an empty `[ _ ]`
  name field with the cursor, **zero** members checked on entry, and the action button reads
  **`< Create >`** (not `< Apply >`) so the sysop knows this *makes* a row rather than mutating one.
- Empty / fresh-box case (no groups exist yet, no members picked): the box still renders fully.
  The member checklist is the **live extension roster** (always ≥1: the admin ext from wizard `[3/5]`),
  every box `[ ]`, the counter `(0 selected)` ‹dim when 0›, Hunt column all `—`. There is never an
  empty-list dead-end. If the operator presses `< Create >` with **0 members**, an inline guard
  prints in the helper zone: `Pick at least one extension to ring. ▲ no members` ‹red glyph+label›.
  It blames the input, states the fix, no exclamation mark (brand §4.1); the group is not created.
- Mode → Hunt-order coupling (G4): in `(•) Ring everyone` the Hunt-order column greys to `—`
  ‹dim› (order is irrelevant, every member rings at once). Toggling to `(•) One at a time` lights
  the column with the **pick sequence** (1,2,3…) ‹brass›; re-ordering follows the check order, so the
  first box ticked is hunt position 1. This mirrors §3.6.1 exactly (G3/G4): one model, two entry
  points (D10), create here, edit there.
- Integrity (G6): the checklist is built from real roster entries, so a phantom member cannot be
  *added* here (unlike Edit, which may inherit a stale `⚠ NOT AN EXTENSION` row). `○ UNREACH` members
  are legal (offline is dim, not red); only a number with **no extension** would flag red, and the
  create list never offers one.
- On `< Create >`: the modal closes back to the Ring Groups table (§3.6) with the new row
  `frontline · One at a time · 3 · ● OK`, and the helper zone shows a transient
  `✓ Ring group "frontline" created (3 members)` ‹brass› line for ~2 s (a *line*, not a modal,
  nothing to dismiss; closes walkthrough F10's reassurance ask).
- Keys (identical to §3.6.1): `[Tab]` cycles Name → Mode → checklist → buttons; `[Space]`
  toggles the focused member (or the mode radio); `[↑/↓]` move within the checklist; `[←/→]` move
  between the radio options and between the two buttons; `[Enter]` = Create; `[Esc]` cancels with no
  write (D7). `[Backspace]` edits the Name field. The footer names exactly these keys, keyboard-only.

### 3.7 `[3]` PBX CONFIG · **Forwards/DND** tab: Dana's day-2 surface

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ POCKET-DIAL v3.0      [ PBX CONFIG ]                                18:16:03 │
├──────────────────────────────────────────────────────────────────────────────┤
│  Extensions │ Ring Groups │ Forwards/DND │ IVR │ Features                    │
│                             ════════════                                     │
│  EXT   NAME            DND     CFU (all)→   CFB (busy)→   CFNA (no-ans)→     │
│  ───   ─────────────   ─────   ──────────   ───────────   ─────────────      │
│  101   Maria           ·       ·            ·             ·                  │
│▸ 102   Sam             ⊘ DND   ↳ 205        ·             ↳ 104              │
│  103   Lee             ·       ·            ·             ↳ grp:sales        │
│  104   Front Desk      ·       ·            ·             ·                  │
│  106   Warehouse       ⊘ DND   ·            ·             ·                  │
│                                                                              │
│   Press [Space] to flip DND on the selected row — the badge changes live.    │
│   Press [Enter] to set the three forward targets. Blank a field to clear it. │
│                                                                  ext 12/32   │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│ [←/→] Tabs [↑/↓] Sel [Space] DND [Enter] Forwards [Esc] Back     · BRASS ▸   │
└──────────────────────────────────────────────────────────────────────────────┘
```

- `⊘ DND` ‹amber›; `↳ 205` forward targets ‹brass›. `Space` flips the selected row's DND badge
  live (F1). `·`=unset ‹dim›.

#### 3.7.1 Forward editor: modal (the three CLASS forwards, F2–F5)

```
        ┌─ Forwards · ext 102 (Sam) ─────────────────────────────┐
        │  Do-Not-Disturb ....... [x] on   (Space toggles)       │   ‹⊘ DND amber when on›
        │                                                        │
        │  Forward ALL calls .... [ 205        ]   *72 / CFU     │
        │  Forward when BUSY .... [            ]   CFB           │   ‹blank = cleared›
        │  Forward NO-ANSWER .... [ 104        ]   CFNA          │
        │                                                        │
        │  Leave a field blank to clear that forward.            │
        │                                                        │
        │              < Apply >        [ Cancel ]               │
        ├────────────────────────────────────────────────────────┤
        │ [Tab] Field  [Backspace] Edit  [Enter] Apply  [Esc] Back│
        └────────────────────────────────────────────────────────┘
```

#### 3.7.2 Forward-to-GROUP: target picker (a forward target may be a RING GROUP)

> Closes **walkthrough F4** (the IA implies ring groups are legal forward targets: the Extensions
> table renders `↳ grp:sales` (§3.5) and the IVR digit map routes to `ring group` (`tui-ia.md` §2,
> V1), yet §3.7.1 only ever showed **single-extension** targets, so "point the front desk at the
> group" had no rendered, reachable affordance). This extends §3.7.1: each of CFU/CFB/CFNA becomes a
> **picker** that lists extensions **and** ring groups, locking **CFU-to-group** as the canonical
> meaning of "point an extension at a group."

The forward field changes from a bare number input to a **picker** marked with a `▾` affordance.
Here ext 104 (Front Desk) forwards ALL calls to the `frontline` group created in §3.6.2:

```
        ┌─ Forwards · ext 104 (Front Desk) ──────────────────────┐
        │  Do-Not-Disturb ....... [ ] off  (Space toggles)       │   ‹⊘ DND amber only when on›
        │                                                        │
        │  Forward ALL calls .... [ grp:frontline      ▾ ]       │   ‹picker: exts + groups; ▾ = openable›
        │  Forward when BUSY .... [                    ▾ ]       │   ‹blank = cleared›
        │  Forward NO-ANSWER .... [ 104                ▾ ]       │
        │                                                        │
        │  A target can be an extension or a ring group.         │   ‹answers "can I put a group here?"›
        │  Leave a field blank to clear that forward.            │
        │                                                        │
        │              < Apply >        [ Cancel ]               │
        ├────────────────────────────────────────────────────────┤
        │ [Tab] Field [Space] Open [↑/↓] Pick [Enter] Apply [Esc]│
        └────────────────────────────────────────────────────────┘
```

**`[Space]` on the focused field opens the combined target list**: extensions first, then a ruled
`RING GROUPS` section, so the two target *types* are read by label, never conflated. `▸` marks the
selection (reverse video, §2.6); `[↑/↓]` move, `[Enter]` picks, `[Esc]` closes the list unchanged:

```
        ┌─ Forward ALL → pick a target ──────────────────────────┐
        │  EXTENSIONS                                            │   ‹section label ‹bright header››
        │    101 Maria            ● ONLINE                       │   ‹state chip = §2.3›
        │    102 Sam              ● ONLINE                       │
        │    104 Front Desk       ● ONLINE                       │
        │    105 Lobby            ● ONLINE                       │
        │  ── RING GROUPS ───────────────────────────────────    │   ‹ruled divider ‹border››
        │  ▸ grp:frontline        Ring everyone · 3              │   ‹selected: ▸ marker + reverse›
        │    grp:sales            One at a time · 4              │
        │    grp:warehouse        Ring everyone · 2              │
        │    — (clear this forward)                              │   ‹explicit blank = unset, §3.7.1 F5›
        ├────────────────────────────────────────────────────────┤
        │ [↑/↓] Pick   [Enter] Choose   [Esc] Keep current       │
        └────────────────────────────────────────────────────────┘
```

- How the `↳ grp:sales` table indicator is produced (the §3.5 / tui-ia link): picking a `grp:`
  row writes that group as the field's target. The Extensions and Forwards/DND tables then render the
  stored CFU/CFB/CFNA target with the **`↳ FWD` glyph + the `grp:<name>` token**, exactly the
  `↳ grp:sales` cell already shown on ext 104 in §3.5 and the `↳ grp:sales` CFNA cell on ext 103 in
  §3.7. The token is `grp:` + the group name so a group target is **visually distinct from a bare
  extension** (`↳ 205` is an extension; `↳ grp:sales` is a group): one glyph, two readable target
  types, no color needed. Picking an extension row writes the bare number and the cell reads `↳ 205`.
- Canonical meaning locked (F4): "point the front desk at the group" = **CFU (Forward ALL) →
  grp:<name>**. The picker makes that path *reachable*, not merely *displayable*; the helper line
  "A target can be an extension or a ring group" pre-answers the exact uncertainty that stalled the
  anxious admin.
- Cross-link (one model, two doors, D10): the Ring Groups screen (§3.6) carries a one-key
  **`[F] Make an ext ring this group`** verb that jumps straight here with `Forward ALL → grp:<this>`
  pre-filled, so the task finishes from *either* the group screen or the Forwards/DND screen. The
  footer on §3.6 already lists list-panel verbs; `[F]` slots beside them.
- Integrity and honesty: the list offers only **real** extensions and **real** groups (no invented
  targets, brand §6.8); a group flagged `⚠ NOT AN EXTENSION` internally (a stale member, G6) still
  forwards fine. The forward points at the *group*, not its members. `○ UNREACH` extension targets
  are legal (dim, never red): you may forward to a phone that is currently offline.
- Non-destructive (D9): setting a forward is **not** an `[A!]` action, no confirm dialog; the
  reassurance is the visible `↳ grp:frontline` value that appears on the row after `< Apply >`
  (walkthrough F14: reserve `▲ ALERT` strictly for delete/reboot/mode/reset). `[Esc]` backs out one
  level, non-destructive (D7).
- Keys: `[Tab]` moves DND → CFU → CFB → CFNA → buttons; `[Space]` opens the focused picker (or
  toggles DND on the DND row); inside the list `[↑/↓]` move and `[Enter]` chooses; `[Enter]` on the
  form = Apply; `[Esc]` cancels. The footer names exactly these keys, keyboard-only, 80×24, no
  horizontal scroll, with the standard ASCII fallback for `▾ ▸ ↳ ── ●○ │` (brand §3.3 map).

### 3.8 `[3]` PBX CONFIG · **IVR** tab: minimal DTMF menu (NO queues)

Renders as **one shallow menu**, not a tree (IA §8: never imply IVR-tree capability we don't ship).
A flat digit map: each digit → one action (ring ext | ring group | play prompt).

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ POCKET-DIAL v3.0      [ PBX CONFIG ]                                18:16:25 │
├──────────────────────────────────────────────────────────────────────────────┤
│  Extensions │ Ring Groups │ Forwards/DND │ IVR │ Features                    │
│                                            ═══                               │
│  Answer point .. ext 100 (Front Desk menu)        [T] set / test             │
│  Greeting ...... welcome.wav   (on-flash prompts: 2 of 24 used)              │
│                                                                              │
│  DIGIT   ACTION                  TARGET                                      │
│  ─────   ────────────────────    ─────────────────                           │
│▸  1      Ring group              grp:sales                                   │
│   2      Ring extension          104 Front Desk                              │
│   3      Play prompt             hours.wav                                   │
│   0      Ring extension          100 Operator                                │
│   *      — (unset)               —                                           │
│   #      — (unset)               —                                           │
│                                                                              │
│   One menu, one level deep — DTMF digit to action. No call queues.           │
│                                                                              │
│                                                                              │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│ [←/→] Tabs [↑/↓] Sel [Enter] Edit [T] Set/Test [Esc] Back        · BRASS ▸   │
└──────────────────────────────────────────────────────────────────────────────┘
```

- The explicit "One menu, one level deep … No call queues." line honors the brand ban on
  queue/IVR-tree language and the brief's no-queues scope.

#### 3.8.1 IVR digit editor: modal

```
        ┌─ Digit  1 ─────────────────────────────────────────┐
        │  When the caller presses 1, do:                    │
        │     (•) Ring a group     [ sales ▾ ]               │   ‹radio + dependent picker›
        │     ( ) Ring extension   [ ___ ]                   │
        │     ( ) Play a prompt    [ ____.wav ▾ ]            │
        │     ( ) Nothing (unset)                            │
        │                                                    │
        │              < Apply >        [ Cancel ]           │
        ├────────────────────────────────────────────────────┤
        │ [↑/↓] Action  [Space] Pick  [Enter] Apply  [Esc] Back│
        └────────────────────────────────────────────────────┘
```

### 3.9 `[3]` PBX CONFIG · **Features** tab: read-only star-code card (F6)

Lists the **only** codes the firmware's CLASS handler implements (IA §6.1). No invented codes.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ POCKET-DIAL v3.0      [ PBX CONFIG ]                                18:16:48 │
├──────────────────────────────────────────────────────────────────────────────┤
│  Extensions │ Ring Groups │ Forwards/DND │ IVR │ Features                    │
│                                                  ════════                    │
│  STAR CODES  —  dial these from any registered phone (read-only reference)   │
│  ─────────────────────────────────────────────────────────────────────────   │
│   *60          Do-Not-Disturb ON   (for the dialing extension)               │
│   *80          Do-Not-Disturb OFF                                            │
│   *72<ext>     Forward-all ON to <ext>                                       │
│   *73          Forward-all OFF                                               │
│   *69          Speak the last caller's extension                             │
│   *11          Echo test (line check)                                        │
│                                                                              │
│   These are dialed on the phones, not set here. To change forwarding from    │
│   the terminal, use the Forwards/DND tab.                                    │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│ [←/→] Tabs  [Esc] Back  [?] Help                               Theme: BRASS ▸│
└──────────────────────────────────────────────────────────────────────────────┘
```

### 3.10 `[4]` SECURITY `[ SECURITY ]`

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ POCKET-DIAL v3.0      [ SECURITY ]                                  18:17:10 │
├──────────────────────────────────────────────────────────────────────────────┤
│  ADMIN ACCESS                                                                │
│  ────────────                                                                │
│   Master PIN .... ● SET   (salted 50,000-round SHA-256, on-box)              │
│   Admin ext ..... 100 Operator   (owns the DTMF *PIN#code menu)              │
│   SSH login ..... PIN required   ·   authorized key: ○ none                  │
│                                                                              │
│   SESSION                                                                    │
│   ───────                                                                    │
│   You ........... sysop @ 192.168.4.23   ·   since 18:02:41                  │
│   Logging ....... all SSH sessions are recorded to the CDR                   │
│                                                                              │
│   [P] Change admin PIN      [K] SSH access / key      [X] Factory reset [A!] │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│ [P] PIN  [K] SSH key  [X] Reset  [Esc] Back  [?] Help          Theme: BRASS ▸│
└──────────────────────────────────────────────────────────────────────────────┘
```

- `● SET` ‹accent›; `○ none` ‹dim›. `[X] Factory reset [A!]` is double-confirmed (IA §2) and dumps
  the box back into the first-run wizard.

#### 3.10.1 Change PIN: modal (S1; never echoed)

```
        ┌─ Change admin PIN ─────────────────────────────────┐
        │  Current PIN ... [ ••••••     ]   never echoed      │
        │  New PIN ....... [ ••••••     ]   4–10 digits        │
        │  Confirm ....... [ ••••••     ]                      │
        │                                                    │
        │  Strength: ●●●○○  fair — longer is stronger.        │   ‹reinforced by word "fair", not color alone›
        │                                                    │
        │              < Apply >        [ Cancel ]           │
        ├────────────────────────────────────────────────────┤
        │ [Tab] Field  [Enter] Apply  [Esc] Cancel  [?] Help │
        └────────────────────────────────────────────────────┘
```

### 3.11 `[5]` REPORTS/LOGS: two views (`[Tab]` flips), `[ REPORTS ]`

#### 3.11.1 VIEW · Recent Calls (CDR): newest-first ring of 32

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ POCKET-DIAL v3.0      [ REPORTS ]                                   18:17:33 │
├──────────────────────────────────────────────────────────────────────────────┤
│  VIEW:  Recent Calls ◂▸ Event Log      (newest first · ring of 32)         █ │
│  TIME      FROM → TO              RESULT          TALK                     │ │
│  ────────  ───────────────────   ─────────────   ──────                    │ │
│▸ 18:14:09  101 → 102             ✓ answered      02:14                     │ │
│  18:11:50  104 → grp:sales       ✓ answered      00:48                     │ │
│  18:09:02  103 → 105             ⊘ busy          —                         │ │
│  18:05:31  101 → 200             ○ unavailable   —                         │ │
│  18:01:18  106 → 104             … cancelled     —                         │ │
│  17:58:44  105 → 101             ▲ failed        —                         │ │
│  17:52:10  102 → 106             ✓ answered      11:37                     │ │
│  17:40:55  104 → 101             ✓ answered      00:22                     │ │
│                                                                  32/32     │ │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│ [Tab] Event Log [↑/↓] Sel [Enter] Detail [PgUp/Dn] Page [Esc] Back · BRASS ▸ │
└──────────────────────────────────────────────────────────────────────────────┘
```

- `Recent Calls ◂▸ Event Log` view selector ‹active=bright header, other=dim›. RESULT chips use the
  real `CdrResult` vocabulary (IA §6.2): `✓ answered` ‹accent›, `⊘ busy` ‹amber›, `… cancelled`
  ‹brass›, `○ unavailable` ‹dim›, `▲ failed` ‹red›. Right gutter = scrollbar (§2.12).

#### 3.11.2 CDR detail: modal (R3)

```
        ┌─ Call detail ──────────────────────────────────────┐
        │  Started .... 2026-06-08 18:14:09                  │
        │  From ....... 101 Maria                            │
        │  To ......... 102 Sam                              │
        │  Result ..... ✓ answered                           │
        │  Talk time .. 02:14   (setup 00:03)                │
        │  Codec ...... PCMU                                 │
        │  Call-ID .... 7f3a…b201                            │
        ├────────────────────────────────────────────────────┤
        │ [↑/↓] Records  [Esc] Back  [?] Help                │
        └────────────────────────────────────────────────────┘
```

#### 3.11.3 VIEW · Event Log tail (R4)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ POCKET-DIAL v3.0      [ REPORTS ]                                   18:17:55 │
├──────────────────────────────────────────────────────────────────────────────┤
│  VIEW:  Recent Calls ◂▸ Event Log   (live tail)                    ⟳ 1 Hz    │
│  ────────────────────────────────────────────────────────────────────────    │
│  18:17:40  REGISTER   ext 102 Sam      ● ONLINE   from 192.168.4.31          │
│  18:17:12  CALL       101 → 102        ◆ ACTIVE   codec PCMU                 │
│  18:16:58  DND        ext 106          ⊘ DND on                              │
│  18:15:33  NET        wifi_mode=2      ● SoftAP up   192.168.4.1             │
│  18:14:09  CDR        101 → 102        ✓ answered  02:14                     │
│  18:11:02  REGISTER   ext 103 Lee      ○ UNREACH  (lease expired)            │
│  18:02:41  AUTH       sysop login      ● OK        from 192.168.4.23         │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│ [Tab] Recent Calls  [↑/↓] Scroll  [Esc] Back  [?] Help         Theme: BRASS ▸│
└──────────────────────────────────────────────────────────────────────────────┘
```

- Each event pairs a glyph+label state chip with the fact; the tail repaints ~1 Hz at the top
  (`⟳ live`), older lines scroll down.

### 3.12 `[6]` ABOUT `[ ABOUT ]`: the honesty card

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ POCKET-DIAL v3.0      [ ABOUT ]                                     18:18:14 │
├──────────────────────────────────────────────────────────────────────────────┤
│   ▌▐ POCKET-DIAL ▐▌  · sysop terminal ·                                      │
│   single-board SIP PBX — operator on duty                                    │
│   ──────────────────────────────────────────────────────────────────────     │
│   Hardware .... ESP32-S3 · Guition JC3248W535 · 8 MB PSRAM · 16 MB flash     │
│   Firmware .... POCKET-DIAL v3.0.0   ·   build 2026-06-08                    │
│   Host ........ pocketdial.local   ·   AA:BB:CC:DD:EE:FF                     │
│   Capacity .... 32 extensions   ·   2–8 concurrent calls                     │
│   Voicemail ... arrives in v2 (needs an RTP record path)                     │
│   Storage ..... on-device flash only — no SD card                            │
│   License ..... see LICENSE in the source tree                               │
│                                                                              │
│   This is an ESP32-S3. It does what it says, and says what it does.          │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│ [Esc] Back  [?] Help                                           Theme: BRASS ▸│
└──────────────────────────────────────────────────────────────────────────────┘
```

- States real limits plainly (honesty clause, brand §6.10): caps, "voicemail in v2", "no SD card".

### 3.13 CONFIRM DIALOG: guarded actions (reboot / mode switch / factory reset)

The one shell wraps every `[A!]` action. Three instances, same skeleton, copy per brand §4.1:

**Reboot** (hub `[R]`, N3):

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ POCKET-DIAL v3.0      [ SYSTEM MANAGEMENT ]                         18:18:30 │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│         ┌─ Confirm ──────────────────────────────────────────────┐           │
│         │  ▲ ALERT   REBOOT now?                                  │          │
│         │                                                        │           │
│         │  Phones drop for ~8 seconds while the board restarts.   │          │
│         │  Calls in progress will end.                            │          │
│         │                                                        │           │
│         │            < Reboot >        [ Stay up ]               │           │
│         ├────────────────────────────────────────────────────────┤           │
│         │ [←/→] Choose   [Enter] Confirm   y/N   [Esc] Cancel    │           │
│         └────────────────────────────────────────────────────────┘           │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│ [←/→] Choose  [Enter] Confirm  [Esc] Cancel                    Theme: BRASS ▸│
└──────────────────────────────────────────────────────────────────────────────┘
```

- `▲ ALERT` ‹red glyph+label›; `[ Stay up ]` is the **safe default, pre-focused** (reverse). Inline
  `y/N` shortcut with `N` safe. Mode-switch and factory-reset reuse this exact box; factory reset
  **double-confirms** (a second identical dialog: "Type the PIN to confirm wipe").

### 3.14 HELP OVERLAY: global, context-scoped (`?` on every screen)

Drawn over the dimmed current screen; `Esc` dismisses back to it. Lists **only this screen's** keys.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ POCKET-DIAL v3.0      [ PBX CONFIG ]                                18:18:52 │
├──────────────────────────────────────────────────────────────────────────────┤
│        ┌─ Help · Extensions tab ────────────────────────────────────┐        │
│        │  ←/→ ........ switch tab (Extensions…Features)              │       │
│        │  ↑/↓ ........ move row selection                           │        │
│        │  Enter ...... edit the selected extension                  │        │
│        │  A .......... add an extension (single or a range/batch)   │        │
│        │  D .......... delete selected  [guarded — confirms first]  │        │
│        │  / .......... jump to an extension number                  │        │
│        │  Space ...... toggle DND on the selected row               │        │
│        │  Esc ........ back to the hub                              │        │
│        │  ? .......... this help        Ctrl-L ... redraw screen    │        │
│        │                                                            │        │
│        │  State key:  ● ONLINE  ○ UNREACH  ⊘ DND  ↳ FWD  ▲ ALERT    │        │
│        └────────────────────────────────────────────────────────────┘        │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│ [Esc] Close help                                               Theme: BRASS ▸│
└──────────────────────────────────────────────────────────────────────────────┘
```

- The footer **state key** restates the glyph+label lexicon so the operator can decode any screen
  without leaving it, reinforcing "label is authoritative, color is removable."

## 4. First-run onboarding wizard: every step (forced, resumable)

The wizard uses the form keys (IA §3.4): `Enter` advances, `Esc` steps back, `[n/5]` + dot rail
(§2.11) shows progress. From `[0/5]`, `Esc` is a no-op (nothing usable behind it). `[ FIRST-RUN ]`
is the mode in the title bar throughout.

### 4.0 `[0/5]` Welcome: "Patching you through…"

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ POCKET-DIAL v3.0      [ FIRST-RUN ]                                 09:00:02 │
├──────────────────────────────────────────────────────────────────────────────┤
│  STEP [0/5]   ◍──○──○──○──○                                                  │
│               WELCOME                                                        │
│  ──────────────────────────────────────────────────────────────────────      │
│                                                                              │
│   Patching you through…                                                      │
│                                                                              │
│   This is a fresh pocket-dial. We'll set it up over the next five steps —    │
│   network, admin PIN, the admin extension, your first extensions, and a      │
│   handoff card. About 3 minutes.                                             │
│                                                                              │
│   Esc backs out a step; your work is saved as you go. If the session drops,  │
│   reconnect and you'll resume right where you left off.                      │
│                                                                              │
│                              < Begin >                                       │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│ [Enter] Begin  [?] Help                                        Theme: BRASS ▸│
└──────────────────────────────────────────────────────────────────────────────┘
```

### 4.1 `[1/5]` Network mode (O3/O4)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ POCKET-DIAL v3.0      [ FIRST-RUN ]                                 09:00:31 │
├──────────────────────────────────────────────────────────────────────────────┤
│  STEP [1/5]   ●──◍──○──○──○                                                  │
│               net   PIN  admin  ext  done                                    │
│  ──────────────────────────────────────────────────────────────────────      │
│   How should pocket-dial get on the network?                                 │
│                                                                              │
│     (•) Join my network        Wi-Fi client, gets an IP by DHCP              │
│     ( ) Standalone hotspot     SoftAP — phones join pocket-dial directly     │
│                                                                              │
│   SSID ......... [ office-wifi        ]                                      │
│   Passphrase ... [ ••••••••••         ]   never echoed                       │
│                                                                              │
│   Reachable as:  pocketdial.local   ·   IP assigned after join               │
│                                                                              │
│                         < Next >        [ Back ]                             │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│ [Tab] Field  [Space] Pick  [Enter] Next  [Esc] Back  [?] Help  Theme: BRASS ▸│
└──────────────────────────────────────────────────────────────────────────────┘
```

- Radio `(•)`/`( )` pairs the dot with the label (never selection-by-color). Picking **Standalone
  hotspot** swaps the SSID/passphrase fields for "AP creds the phones will join" (shown, not typed).

### 4.2 `[2/5]` Admin PIN (O2)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ POCKET-DIAL v3.0      [ FIRST-RUN ]                                 09:01:05 │
├──────────────────────────────────────────────────────────────────────────────┤
│  STEP [2/5]   ●──●──◍──○──○                                                  │
│               net   PIN  admin  ext  done                                    │
│  ──────────────────────────────────────────────────────────────────────      │
│   Set the master PIN. It gates SSH login here and the DTMF admin menu.       │
│                                                                              │
│   PIN ......... [ ••••••     ]   4–10 digits, never echoed                   │
│   Confirm ..... [ ••••••     ]                                               │
│                                                                              │
│   Strength: ●●●○○  fair — longer is stronger.                                │
│                                                                              │
│   Stored as a salted 50,000-round SHA-256 hash, computed on the box. The     │
│   PIN itself is never written to flash and never shown again.                │
│                                                                              │
│                         < Next >        [ Back ]                             │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│ [Tab] Field  [Enter] Next  [Esc] Back  [?] Help               Theme: BRASS ▸ │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 4.3 `[3/5]` Admin extension (sets `_adminExt`)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ POCKET-DIAL v3.0      [ FIRST-RUN ]                                 09:01:48 │
├──────────────────────────────────────────────────────────────────────────────┤
│  STEP [3/5]   ●──●──●──◍──○                                                  │
│               net   PIN  admin  ext  done                                    │
│  ──────────────────────────────────────────────────────────────────────      │
│   The admin extension owns the box and gets the DTMF *PIN#code menu.         │
│   It becomes your first roster entry.                                        │
│                                                                              │
│   Number ..... [ 100        ]   3–6 digits, unique                           │
│   Name ....... [ Operator    ]                                               │
│   PIN ........ [ ••••        ]   the SIP register PIN for this phone         │
│                                                                              │
│   This phone can dial  *PIN#001 (resync clock)  and  *PIN#101 (network mode).│
│                                                                              │
│                         < Next >        [ Back ]                             │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│ [Tab] Field  [Enter] Next  [Esc] Back  [?] Help               Theme: BRASS ▸ │
└──────────────────────────────────────────────────────────────────────────────┘
```

### 4.4 `[4/5]` First extensions: the marquee batch (O5/E3/E6)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ POCKET-DIAL v3.0      [ FIRST-RUN ]                                 09:02:30 │
├──────────────────────────────────────────────────────────────────────────────┤
│  STEP [4/5]   ●──●──●──●──◍                                                  │
│               net   PIN  admin  ext  done                                    │
│  ──────────────────────────────────────────────────────────────────────      │
│   Provision a block of extensions in one pass.                               │
│                                                                              │
│   Range ......... [ 101-124      ]   = 24 extensions                         │
│   PIN policy .... (•) Random per-ext  ( ) Same PIN [____]  ( ) Match number  │
│   Add all to ... [ sales ▾ ]   ring group (optional)                         │
│                                                                              │
│   Pool after this:  25/32 — OK                                               │
│   ┄ widen the range past the cap and this flips to:  37/32 ⚠ EXCEEDS CAP     │
│                                                                              │
│                      < Provision block >    [ Back ]                         │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│ [Tab]Field [Space]Pick [Enter]Provision [Esc]Back [?]Help    Theme: BRASS ▸  │
└──────────────────────────────────────────────────────────────────────────────┘
```

- `Pool after this: 25/32 — OK` ‹brass› is the **predictive** cap (D12/E6); over-cap it reads
  `37/32 ⚠ EXCEEDS CAP` ‹red glyph+label› *before* apply. One keypress on `< Provision block >`
  provisions all 24, never 24 dialogs (D2).

### 4.5 `[5/5]` Done · handoff card (O6)

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ POCKET-DIAL v3.0      [ FIRST-RUN ]                                 09:03:11 │
├──────────────────────────────────────────────────────────────────────────────┤
│  STEP [5/5]   ●──●──●──●──●                                                  │
│               net   PIN  admin  ext  DONE                                    │
│  ──────────────────────────────────────────────────────────────────────      │
│   ◆ READY — operator on duty.   Hand this card to the day-2 admin:           │
│                                                                              │
│     HOST ........ pocketdial.local        ADDR ...... 192.168.1.50           │
│     ADMIN PIN ... ● SET (not shown)       EXT ........ 24 (101-124) + 100    │
│                                                                              │
│   Admin can touch:  extensions · DND · forwards · ring groups · reports      │
│   Guarded (confirms):  network mode · delete · reboot · factory reset        │
│                                                                              │
│   Next: press Finish, then [1] Monitor, place a call, watch it light up.     │
│                                                                              │
│                              < Finish >                                      │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│ [Enter] Finish → Hub  [Esc] Back  [?] Help                     Theme: BRASS ▸│
└──────────────────────────────────────────────────────────────────────────────┘
```

- `◆ READY` ‹accent + label›. `< Finish >` drops into the hub (§3.2) with `[1] MONITOR` one key
  away so the ring-test (M4) is the natural next act: "the handoff closes on proof, not hope."

## 5. PHOSPHOR theme: the same board under green bench-light

Themes are not redrawn screens; they re-tint the **same geometry**. Below is the hub (§3.2) under
PHOSPHOR to show the change is bench-lighting only: identical glyphs/labels/layout, the **live lamp
accent shifts green** (`●`/`◆`), text tints green, **brass rails stay brass**, **DND stays amber**,
**red stays red**, and the footer **names** the theme (`PHOSPHOR ▸`), never read by hue.

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ POCKET-DIAL v3.0      [ SYSTEM MANAGEMENT ]                         18:14:22   │   ‹text→green, rails→brass›
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│     [1] SYSTEM MONITOR        [2] NETWORK          [3] PBX CONFIG            │
│     [4] SECURITY              [5] REPORTS/LOGS     [6] ABOUT                 │
│                                                                              │
│     [R] REBOOT     [L] LOGOUT                                                │
│                                                                              │
│   ● 4 ONLINE   ○ 1 UNREACH    ·    1/8 calls    ·    ext 12/32    ·   AP mode   │   ‹● now green-phosphor›
│                                                                              │
│   (◉)─▶ Select an option: _                                                  │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
│                                                                              │
├──────────────────────────────────────────────────────────────────────────────┤
│ [1-6] Go  [R] Reboot  [L] Logout  [T] Theme  [?] Help        Theme: PHOSPHOR ▸ │   ‹label names the theme›
└──────────────────────────────────────────────────────────────────────────────┘
```

> A sysop pressing `T` sees the footer label flip `BRASS ▸ → PHOSPHOR ▸` and the lamps go amber→green.
> The bench lighting changed, not the product. Because every status is still glyph+label, the
> screen is identical in meaning the instant the color changes (and in monochrome, identical period).

## 6. Renderer contract (what firmware emits, for the implementer)

A compact spec so the C++ renderer (over the SSH PTY) produces these screens deterministically:

1. **Capability probe.** On connect, read `TERM`. Three tiers:
   - `xterm`/`xterm-256color`/`putty`/`screen` → **box-drawing + 16-color SGR** (full mockups).
   - color-capable but `TERM=vt100`/ambiguous → 16-color SGR + ASCII fallback glyphs.
   - `TERM=dumb`/`--no-color`/serial → **ASCII fallback glyphs, no SGR** (the §1.5 form).
2. **Glyph table is one indirection.** Keep a `GLYPHS[tier]` table (`●○◆⊘↳▲◐✓…─│┌┐└┘├┤═║◉▌▐◖◗▸◍`)
   → ASCII (`(*) ( ) <*> [/] -> /!\ (~) v . - | + + + + + + = | (o) | | [ ] > (O)`). Draw from the
   table, never inline a glyph; that is what makes the mono degradation free.
3. **SGR is wrapped, never spanned.** Emit `ESC[<role>m` immediately before a status glyph+label and
   `ESC[0m` immediately after. Frame chrome gets the border role once per line. Never tint a row.
4. **Live cells are cursor-positioned.** The clock (row 1), hub headroom line, monitor matrix
   STATUS/DUR cells, vitals bars + `UP`, and the event-log head are repainted by
   `ESC[<row>;<col>H` + overwrite at ~1 Hz. **No `ESC[2J` full clear** in steady state (brief §6).
   `[F]` freeze halts these writes; `Ctrl-L` is the only full repaint (line-noise recovery).
5. **Selection = reverse + marker.** Selected table row: `ESC[7m` over the row body **and** a `▸`
   in the gutter; active tab: `═══` underline rule **and** the bright-header tab name. Both pairings
   survive SGR-stripping (the marker/underline remain), satisfying "never color alone."
6. **Theme is a palette swap, not a layout.** `T` swaps the BRASS↔PHOSPHOR SGR role table (§1.2/1.3)
   and rewrites the footer theme label; geometry and glyphs are byte-identical. DND amber and alert
   red are theme-invariant by design (§1.3 note).
7. **80×24 budget is enforced.** The renderer clips to 80 cols; any line that would exceed wraps to
   a `…` ellipsis on that field, never a horizontal scroll. Modals are centered within the body box.

## 7. Consistency check (brand §6.1 + brief §6, applied to this file)

```
[x] Name cased correctly: POCKET-DIAL in title bars/banner, pocketdial.local in hosts
[x] Title bar on every screen: POCKET-DIAL v3.0  [MODE]  HH:MM:SS  (3-zone geometry)
[x] Every status = glyph + LABEL (brand §4.5 lexicon); color is the removable 3rd layer (§1.5 proof)
[x] Always-visible key-hint footer ending in the named theme label (BRASS ▸ / PHOSPHOR ▸)
[x] '?' help overlay drawn for every screen (§3.14); Esc backs out one level; no-op on the hub
[x] Every screen ≤ 80 cols / ≤ 24 rows; banner ≤ 78-wide frame; no horizontal scroll
[x] Every box glyph has an ASCII fallback (§1.5 map + §6.2 table); mono degradation is lossless
[x] Single-key hub hotkeys fire without Enter; 3→1→A lands on Extensions with [A] = Add open
[x] Batch range field is the marquee path (§3.5.3, §4.4) with a PREDICTIVE cap check, not N dialogs
[x] All [A!] actions funnel through the one confirm shell (§2.8/§3.13) with a safe default focused
[x] Real features only — no trunks/FXO/queues/voicemail-v1/SD; star codes & CDR verified vs firmware
[x] Live surfaces marked ⟳ and repainted by cursor positioning at ~1 Hz, never full clears (§6.4)
[x] BRASS default + PHOSPHOR alt mirror ui.cpp RGB; brass rails + amber DND + red are theme-invariant
[x] Flavor budget respected: only "operator on duty" (§4.5 banner/handoff) + "Patching you through…"
```

*UI Designer · pocket-dial 3.x redesign · ANSI visual system mapped from `main/ui/ui.cpp`*
*PALETTES[] to xterm-16; renders every screen in [`tui-ia.md`](tui-ia.md); consistent with*
*[`00-brief.md`](00-brief.md) and [`brand.md`](brand.md). Owns: color mapping, component library,*
*full 80×24 mockups, and the renderer contract for the firmware implementer.*
