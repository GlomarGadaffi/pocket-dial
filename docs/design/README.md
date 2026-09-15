# pocket-dial. Design System Index (SSH Sysop Terminal)

> **⚠️ HISTORICAL, describes a removed surface.** The SSH sysop terminal and its ANSI TUI
> were deleted from pocket-dial (see `docs/THREAT_MODEL.md` §5.5: the admin plane is now
> HTTP-only and dark by default). This folder is preserved as design history, the width
> discipline, glyph lexicon, and accessibility rules remain good reference material, but
> nothing in it describes current firmware behavior.

> **Phase-A design sprint · Design-system index & locked decisions.** pocket-dial is a self-contained
> SIP PBX on a single ESP32-S3 (Guition JC3248W535, 3.5" 320×480 touch display). The redesign reframes
> it as an SSH-first "sysop terminal": all configuration happens over a retro telco/BBS ANSI TUI
> reached by SSH, the 3.5" touchscreen becomes a **passive live-status wallboard**, and the entire
> surface renders at a **80×24 minimum in 16-color ANSI that degrades cleanly to monochrome**, state
> is **never signalled by color alone** (every status is glyph + label + color, in that order of
> authority). This file is the entry point for the ten Phase-A deliverables, the single linked table of
> contents, and the **locked-decisions** block every downstream doc, mockup, and firmware string must
> obey. When in doubt, the canonical brief ([`00-brief.md`](00-brief.md)) wins; this README only indexes
> and reconciles it.


## Table of contents

| # | Doc | Owner role | What it locks |
|---|-----|------------|---------------|
| 0 | [`00-brief.md`](00-brief.md) | (canonical) | Product, mission, scope, constraints, palette source, deliverables map |
| 1 | [`personas.md`](personas.md) | UX Researcher | Installer (Rivera) + Admin (Dana) personas, JTBD, **Task Inventory §3** (coverage checklist), design implications D1–D13 |
| 2 | [`brand.md`](brand.md) | Brand Guardian | Name treatment, ASCII logo, **SSH login banner**, voice & tone, **status lexicon §4.5**, consistency rules |
| 3 | [`tui-ia.md`](tui-ia.md) | UX Architect | Master hub, **full screen tree**, **global keybinding scheme**, panel/tab model, **onboarding wizard** |
| 4 | [`tui-style.md`](tui-style.md) | UI Designer | **16-color BRASS/PHOSPHOR mapping**, ANSI component library, **full 80×24 mockups of every screen**, renderer contract |
| 5 | [`narrative.md`](narrative.md) | Visual Storyteller | Boot / first-run / live-"glow" experiential beats, timing & motion |
| 6 | [`whimsy.md`](whimsy.md) | Whimsy Injector | Opt-in retro-BBS delight: Tier-0 micro-moments, Tier-1 ambient, easter eggs, the whimsy toggle |
| 7 | [`walkthrough.md`](walkthrough.md) | Persona Walkthrough | Cognitive walkthrough of onboarding (Rivera) + a ring-group task (Dana); **prioritized friction log (F1–F15)** |
| 8 | [`accessibility.md`](accessibility.md) | Accessibility Auditor | Color-blind audit, **STATIC screen-reader mode**, spoken selection, 80×24 legibility, keyboard-trap audit |
| 9 | [`imagery.md`](imagery.md) | Image Prompt Engineer | The three real bitmaps: 320×480 splash, onboarding QR card, README hero, prompts + inclusive review |

Reading order for a newcomer: brief → personas (the *why*) → brand (the *voice*) → tui-ia (the *map*) → tui-style (the *pixels*) → narrative/whimsy (the *feel*) → walkthrough/accessibility (the *audit*) → imagery (the *bitmaps*).


## LOCKED DECISIONS

These four blocks are the protected core. A change to any of them is a design change requiring a review against `brand.md` §6.1; downstream docs cross-reference these, they do not redefine them.

### 1. Product name, one name, three casings (`brand.md` §1.1)

| Context | Form | Where |
|---|---|---|
| Prose / sentences | `pocket-dial` | "phones register to pocket-dial" |
| Title-case proper noun | `Pocket-Dial` | headings, artifact names |
| ASCII logo / banner / title bars | `POCKET-DIAL` | the operator-board lockup |
| Hostname / mDNS / URLs / configs | `pocketdial` | `pocketdial.local`, NVS keys |
| Code identifiers / macros | `POCKETDIAL_*` / `pocketdial` | `POCKETDIAL_MAX_CLIENTS` |

Descriptor line: **`SYSOP TERMINAL` · *single-board SIP PBX***. Contextual mode (title bar): `[ SYSTEM MANAGEMENT ]` (and `[ MONITOR ]`, `[ NETWORK ]`, `[ PBX CONFIG ]`, `[ SECURITY ]`, `[ REPORTS ]`, `[ ABOUT ]`, `[ FIRST-RUN ]`). Version string `vMAJOR.MINOR` in human surfaces; the redesign ships under the **3.x** line. Banned: `PocketDial`, `Pocket Dial`, `MyPBX`, `PD-PBX`, sub-brands. Tagline budget is exactly two flavor lines: `operator on duty` and `Patching you through…`.

### 2. Palette. BRASS (default) + PHOSPHOR (alt), mirroring `main/ui/ui.cpp` `PALETTES[]`

Two themes, same product, "a change of bench lighting, not a different product." Brass is the chrome; the lamp is the accent; red is rationed to destructive/alert; **DND stays amber in both themes** (`ui.cpp` L61). 16-color xterm mapping owned by `tui-style.md` §1.

| Role | BRASS RGB | PHOSPHOR RGB | xterm-16 → SGR |
|---|---|---|---|
| board bg | `#161412` | `#10140F` | `0` black → `40` |
| panel face | `#28241E` | `#1C241C` | `0` black (dim chrome only) → `40` |
| brass rail / border | `#B08438` | `#96823C` | `3` yellow → `33` |
| text | `#D6B26E` | `#AAD296` | BRASS `3`→`33` / PHOS `2`→`32` |
| highlight / header | `#F5D696` | `#D2F0BE` | BRASS `11`→`93` / PHOS `10`→`92` |
| **accent, live lamp** | `#FFB020` amber | `#40FF60` green | BRASS `11`→`93` / PHOS `10`→`92` |
| dim / UNREACH | `#1E1B17` | `#16201C` | `8` grey → `90` |
| **DND ring** (both themes) | `#FFB020` amber | `#FFB020` amber | `11` → `93` |
| **alert / destructive** | `#C84028` | `#DC4632` | `1` red → `31` |

**Status lexicon (`brand.md` §4.5, never color alone; label authoritative, glyph reinforces, color removable):**

```
● ONLINE   ○ UNREACH   ◐ RINGING   ◆ ACTIVE   ⊘ DND   ↳ FWD   ▲ ALERT   ◆ READY
CDR results:  ✓ answered   ⊘ busy   … cancelled   ○ unavailable   ▲ failed
ASCII fallback:  ●→(*)  ○→( )  ◐→(~)  ◆→<*>  ⊘→[/]  ↳→->  ▲→/!\   ╔╗╚╝═║→+ + + + = |   ─→-
```

### 3. Keybinding scheme, one scheme, learned once (`tui-ia.md` §3)

| Scope | Keys |
|---|---|
| **Global (every screen)** | `?` context help (Esc-dismiss) · `Esc` back one level, non-destructive (no-op on hub) · `Ctrl-L` redraw |
| **Hub typeahead** (single key, **no Enter**, `3→1→A` is one fluid run) | `1` Monitor · `2` Network · `3` PBX Config · `4` Security · `5` Reports/Logs · `6` About · `R` Reboot `[A!]` · `L` Logout · `T` Theme toggle |
| **List/table panels** | `↑/↓` select · `PgUp/PgDn` page · `Enter` edit · `Tab` `←/→` switch tab/view · `A` add · `D` delete `[A!]` · `Space` toggle binary · `/` filter/jump · `Esc` back |
| **Forms / wizard steps** | `Tab`/`↓` next field · `Shift-Tab`/`↑` prev · `Space` toggle radio/checkbox · `←/→` move in radio / between buttons · `Enter` apply/advance · `Esc` cancel/prev step · `Backspace` edit text |
| **Confirm dialogs `[A!]`** | `←/→` choose (safe default pre-focused) · `Enter` confirm · `y/n` inline shortcut (`N` safe) · `Esc` cancel = safe default |
| **Live monitor `[1]`** | `F` freeze/unfreeze 1 Hz refresh · `C` clear stale rows · `Esc` back. **`P` is NOT bound** (no on-device PCAP, honesty). |

Every screen carries the 3-zone spine: title bar (`POCKET-DIAL vX.Y  [MODE]  HH:MM:SS`) / body / always-visible key-hint footer ending in the **named theme label** (`Theme: BRASS ▸` / `Theme: PHOSPHOR ▸`). Selection = `▸` marker + reverse video (never color alone). Live cells repaint ~1 Hz by cursor positioning, never full clears.

### 4. Full screen inventory (v1)

```
SSH CONNECT
├─ LOGIN BANNER  (firmware sshd greeting; ◆ READY lamp)
│   └─ PIN PROMPT  (AdminAuth 50k-round SHA-256, never echoed)
├─ ◇ FIRST-RUN WIZARD  (forced on un-provisioned box; resumable; replaces gen_provision_nvs.py)
│   ├─ [0/5] Welcome — "Patching you through…"
│   ├─ [1/5] Network mode (Client/DHCP vs SoftAP)
│   ├─ [2/5] Admin PIN
│   ├─ [3/5] Admin extension
│   ├─ [4/5] First extensions — the marquee BATCH range (predictive cap check)
│   └─ [5/5] Done · handoff card → Hub
└─ HUB  [ SYSTEM MANAGEMENT ]   (typeahead launcher; Esc = no-op)
    ├─(1) SYSTEM MONITOR  ⟳   live-call matrix · roster · vitals · ring-test  [F]reeze [C]lear
    ├─(2) NETWORK             status · [M] switch mode [A!]
    ├─(3) PBX CONFIG          tabbed: Extensions │ Ring Groups │ Forwards/DND │ IVR │ Features
    │     ├─ Extensions       list · [A] add (single | range) · [Enter] edit · [D] del [A!] · [F]→Forwards
    │     ├─ Ring Groups      list · [A] add · [Enter] edit (mode radios + member checklist) · [D] del [A!]
    │     ├─ Forwards/DND     DND toggle + CFU/CFB/CFNA forward editor
    │     ├─ IVR              flat DTMF digit map → ring ext | ring group | play prompt (NO queues)
    │     └─ Features         read-only star-code reference (*60 *80 *72 *73 *69 *11)
    ├─(4) SECURITY            [P] change PIN · [K] SSH access · session info · [X] factory reset [A!]
    ├─(5) REPORTS/LOGS        two views ([Tab]): Recent Calls (CDR ring of 32) ◂▸ Event Log tail
    ├─(6) ABOUT               honesty card: hardware · firmware · caps (32 ext / 8 calls) · "voicemail in v2"
    ├─(R) REBOOT [A!]   ◇ confirm
    ├─(L) LOGOUT
    └─(?) HELP OVERLAY  (global, context-scoped)
   Cross-cutting overlays: ◇ confirm dialog (one shell for all [A!]) · ◇ modal editors · ? help overlay
```

Hard caps surfaced as design objects (not error states): 32 extensions / 8 concurrent calls, shown ambiently (hub `ext 12/32 · 1/8 calls`) and predictively (pre-apply cap check). The 3.88 MB on-flash `prompts` partition backs IVR; **no SD card** anywhere.


## Reconciled decisions (where docs differed, these are the rulings)

These were inconsistencies across the upstream docs; they are resolved here so engineering reads one answer. See the **Inconsistencies** field of the Phase-A checkpoint for the full list and rationale.

1. **Hub slot 6 = `ABOUT`, not `ADDONS`.** The brief's example matrix shows `[6] ADDONS`; pocket-dial ships no add-on surface, so `tui-ia.md` renames it `[6] ABOUT` (honesty clause). **`ABOUT` is canonical.**
2. **CDR result vocabulary = the real `CdrResult` enum.** `personas.md` §3.7 said "answered / busy / no-answer / cancelled / failed"; the shipping enum is **`Answered · Busy · Cancelled · Unavailable · Failed`** (`tui-ia.md` §6.2). **The firmware enum wins;** there is no "no-answer" state.
3. **Two missing modals must be drawn before build.** `tui-ia.md` promises an **Add-ring-group create** modal and a **forward-to-group** affordance that `tui-style.md` never rendered (`walkthrough.md` F3/F4). The walkthrough supplies provisional mockups; UI Designer owns finalizing them. **Open for engineering.**
4. **First-boot banner needs an un-provisioned branch.** The banner asks for a PIN that only exists after wizard `[2/5]` (`walkthrough.md` F1). The two-state banner (`◆ READY — UNPROVISIONED · first SSH session starts setup`) is the ruling. **Open for engineering.**
5. **Accessibility adds renderer constraints, not geometry changes.** STATIC screen-reader mode and spoken selection (`accessibility.md` A11Y-1/-2) are **mandatory** and gate "accessible." They change the renderer, not a single mockup.


*Design Lead · pocket-dial 3.x redesign · index + locked decisions for the Phase-A sprint. Canonical*
*source: [`00-brief.md`](00-brief.md). Palette source of truth: `main/ui/ui.cpp` `PALETTES[]`.*
