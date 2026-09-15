# pocket-dial Redesign. Shared Design Brief (canonical)

> This is the single source of truth for the Phase-A design sprint. Every design agent reads
> this first and stays consistent with the decisions, vocabulary, palette, and constraints below.
> Deliverables land beside this file under `docs/design/`.

## 1. Product & mission

**pocket-dial** is a self-contained SIP PBX that runs on a single **ESP32-S3** (Guition JC3248W535,
3.5" 320×480 capacitive touch display, 8 MB PSRAM, 16 MB flash). No router, no SIP trunk, no cloud, 
phones register to it and call each other; RTP audio flows peer-to-peer.

**The redesign reframes pocket-dial as an SSH-first "sysop terminal" PBX.** The owner is unsatisfied
with today's onboarding and touchscreen config. The new vision: **all configuration happens over a
gorgeous ANSI/TUI terminal reached by SSH**, a retro telco/BBS "sysop" hub. The touchscreen stops
being a config surface and becomes a **passive live-status wallboard**.

## 2. Target users & workload

- **SOHO / SMB.** 2–8 concurrent calls, ~1000+ minutes/month.
- Two personas to design for: the **installer** (provisions the box once, fast) and the **day-2 admin**
  (a non-specialist office manager / prosumer who occasionally edits extensions, ring groups, forwards).
- Efficiency north-star (from the owner's vision): *"once you memorize the keys (3 → 1 → A) you provision
  a block of extensions or reroute in three seconds flat."* Keyboard-first, no mouse, no page loads.

## 3. Feature scope

- v1 (this redesign): SSH TUI sysop terminal; SSH-first onboarding wizard; **ring groups** (RingAll +
  Hunt, already implemented in firmware); **minimal IVR** (DTMF menu → prompt playback, NO queues);
  call-forward / DND / blind-transfer / star-codes (already implemented); CDR/reports view; live call
  monitor; **display → passive monitor**. DHCP + mDNS (`pocketdial.local`) already work.
- v2 (later): voicemail (needs a new RTP record path).
- Out of scope: call queues, conferencing/mixing, transcoding, SD card (everything fits on-device
  flash, there is a 3.88 MB unused `prompts` partition; do NOT design around an SD card).

## 4. Reference aesthetic (capture the vibe, don't copy verbatim)

The owner loves the classic telco-management terminal look. Touchstones to evoke:

- A **master command hub** landing screen, a numbered menu matrix:
  `[1] SYSTEM MONITOR  [2] NETWORK  [3] PBX CONFIG  [4] SECURITY  [5] REPORTS/LOGS  [6] ADDONS`
  with `[R] REBOOT` / `[L] LOGOUT`, a title bar (`PRODUCT vX.Y   [SYSTEM MANAGEMENT]   18:14:22`),
  and a `Select an option:` prompt.
- An **ncurses-style config panel** with a top tab strip
  (`Extensions │ Trunks │ Routes │ IVR │ Voicemail`), a data table of rows with `[ ONLINE ]`/`[ UNREACH ]`
  status chips, and `< Edit >  < Delete >  < Apply >` action buttons; footer hints
  `[←/→] Tabs  [↑/↓] Select  [Enter] Modify`.
- A **live-refreshing call monitor** ("BBS door glow") that redraws ~1/sec with ANSI: trunk status dots
  (● connected / ○ down), a live call matrix (CH / EXT / DEST / DURATION / CODEC / STATUS), and hardware
  vitals bars (`CPU [██████░░░░] 30%`, uptime, mem). Footer: `[C] Clear  [P] PCAP  [ESC] Main`.
- Box-drawing frames (`┌─┐│└┘├┤`), block/bar glyphs (`█░▌▐▀▄●○`), tasteful retro flourishes.

We are **not** married to "MyPBX", to FreePBX/Yeastar nomenclature, or to features we don't ship
(trunks/FXO/queues). Keep the *aesthetic and the speed*; map screens to pocket-dial's real feature set.

## 5. Existing visual language, harmonize the TUI with these themes

The on-device UI already ships two operator-board palettes (`main/ui/ui.cpp`). The TUI's 16-color ANSI
mapping must feel like the same product. Exact RGB:

**BRASS (default)**, deep charcoal board, warm brass rails, amber lamps:
- bg `#161412` · panel `#28241E` · border/brass `#B08438` · text `#D6B26E` · highlight `#F5D696`
- accent (live lamp) amber `#FFB020` · DND ring amber `#FFB020` · alert/destructive ember-red `#C84028`

**PHOSPHOR (alt)**, charcoal board, dim-brass rails, green phosphor lamps:
- bg `#10140F` · panel `#1C241C` · border `#96823C` · text `#AAD296` · highlight `#D2F0BE`
- accent (live lamp) green `#40FF60` · DND amber `#FFB020` · alert `#DC4632`

Design the ANSI TUI with selectable **BRASS** and **PHOSPHOR** themes mirroring these, mapped to the
16-color xterm palette (and degrade gracefully on a no-color terminal).

## 6. Hard constraints (non-negotiable)

- Transport: rendered over SSH (standard clients: OpenSSH, PuTTY, paramiko). Also reachable on the
  device's serial console. Assume a VT100/xterm-class terminal.
- **Minimum geometry: 80×24.** Must be fully usable at 80×24; may use extra space if available but never
  require it. No horizontal scrolling.
- **16-color ANSI only** for portability; must degrade to monochrome. **Never signal state by color
  alone**, pair every color with a glyph/label (accessibility + color-blind safety).
- **Keyboard-only.** Single-key hotkeys for the hub; arrow/Enter/Esc/Tab for panels; a global, always-
  visible key-hint footer; `?` for help on every screen; consistent Esc-to-back.
- Embedded reality: no heavy redraw storms (the live monitor redraws ~1 Hz via cursor positioning,
  not full clears). Latency-tolerant. The renderer is plain strings, cheap.
- **Display screen = passive monitor only.** No touch configuration in the redesign; the screen shows the
  live wallboard + brand + `pocketdial.local` + "SSH here to configure" + a QR to the host.

## 7. Deliverables map (who writes what)

| Agent | File | Deliverable |
|---|---|---|
| UX Researcher | `docs/design/personas.md` | Installer + admin personas, JTBD, task inventory, design implications |
| Brand Guardian | `docs/design/brand.md` | Identity/name treatment, ASCII logo, SSH login banner, voice & tone, consistency rules |
| UX Architect | `docs/design/tui-ia.md` | Master IA: hub, full screen tree, global keybindings, SSH-first onboarding wizard flow |
| UI Designer | `docs/design/tui-style.md` | ANSI component library, BRASS/PHOSPHOR 16-color mapping, full ANSI mockups of every screen |
| Visual Storyteller | `docs/design/narrative.md` | Boot/first-run narrative + the live "glow" console concept |
| Whimsy Injector | `docs/design/whimsy.md` | Retro-BBS delight pass: flourishes, the register-beep moment, opt-in easter eggs |
| Persona Walkthrough | `docs/design/walkthrough.md` | Cognitive walkthrough of onboarding + one real provisioning task; friction log |
| Accessibility Auditor | `docs/design/accessibility.md` | TUI a11y guardrails: color-blind palette, screen-reader-over-SSH, 80×24 legibility |
| Image Prompt Engineer + Inclusive Visuals | `docs/design/imagery.md` | (reduced role) 320×480 splash art, onboarding QR card, README hero, prompts + inclusive review |

## 8. Working agreements

- Stay consistent with the **product name, palette, keybinding scheme, and screen inventory** established
  by the foundation/architecture docs, cross-reference them, don't reinvent.
- Show, don't tell: include real ANSI/box-drawing mockups, not prose descriptions of mockups.
- Everything must be buildable on an ESP32-S3 over SSH at 80×24. If a delight idea costs real resources,
  mark it opt-in.
