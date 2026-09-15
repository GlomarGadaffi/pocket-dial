# pocket-dial. Brand & Identity (SSH Sysop Terminal)

> **Brand Guardian deliverable.** Reads from `docs/design/00-brief.md` (canonical) and the on-device
> palette in `main/ui/ui.cpp`. Defines the product identity for the SSH-first sysop terminal: name
> treatment, ASCII logo, the SSH login banner (first thing shown on connect), voice & tone, and the
> consistency rules every downstream design doc and string must obey.
>
> One-line essence: **a brass-and-phosphor operator board you reach by SSH.**


## 1. Product name & treatment

The product name is **pocket-dial**. It does not change for the redesign, the redesign reframes the
*surface* (SSH terminal, passive wallboard), not the product. The name already appears across firmware,
README, mDNS (`pocketdial.local`), and CI, so we standardize, we do not rename.

### 1.1 Canonical spellings (use exactly these, no new variants)

| Context | Form | Example / where |
|---|---|---|
| Prose, sentences, README body | `pocket-dial` (lowercase, hyphen) | "phones register to pocket-dial" |
| Title-case label, proper noun in headings | `Pocket-Dial` | "Pocket-Dial Setup", artifact names |
| ASCII logo / login banner / title bars | `POCKET-DIAL` (caps) | the operator-board lockup |
| Hostname / mDNS / URLs / configs | `pocketdial` (one word, no hyphen) | `pocketdial.local`, NVS keys |
| Code identifiers / macros | `POCKETDIAL_*`, `pocketdial` | `POCKETDIAL_OPEN_REGISTRAR` |

**Never** introduce: `PocketDial`, `Pocket Dial` (space), `pocket dial`, `PD-PBX`, `MyPBX`, marketing
sub-brands, or version-specific names. There is one product, one name, three casings.

### 1.2 The descriptor (sub-title / role line)

pocket-dial needs a short role descriptor that sets the "sysop terminal" frame the moment you connect.
The locked descriptor is:

> **SYSOP TERMINAL** · *single-board SIP PBX*

- In the banner and hub title bar, render the bracketed mode the brief already established:
  `[SYSTEM MANAGEMENT]`. The descriptor `SYSOP TERMINAL` is the *brand* line; `[SYSTEM MANAGEMENT]`
  is the *contextual mode* line. Both appear in the banner; only the mode appears in panel title bars.
- Tagline (optional flavor, banner only, see §4.4): **"Operator on duty."**

### 1.3 Version string

Format: `vMAJOR.MINOR` in human surfaces (e.g. `v3.0`); full `vMAJOR.MINOR.PATCH` only in logs/CDR/about.
The redesign ships under the **3.x** line. The title-bar pattern from the brief is canonical:

```
POCKET-DIAL v3.0   [SYSTEM MANAGEMENT]   18:14:22
```


## 2. ASCII-art logo

Two lockups. **Both are ≤ 80 columns** and built only from characters safe over a VT100/xterm SSH session
and on the serial console. State is **never** carried by color here (it is decorative chrome), so the logo
degrades perfectly to monochrome.

### 2.1 Primary lockup, operator-board nameplate (used in the login banner)

11 lines tall, 64 columns wide. The double rule evokes a brass rail; the `◖◗` are panel lamps; the
sub-rule carries the descriptor. This is the canonical logo, when in doubt, use this one.

```
   ____   ___   ____ _  _______ _____      ____  ___    _    _
  |  _ \ / _ \ / ___| |/ / ____|_   _|    |  _ \|_ _|  / \  | |
  | |_) | | | | |   | ' /|  _|   | |_____ | | | || |  / _ \ | |
  |  __/| |_| | |___| . \| |___  | |_____|| |_| || | / ___ \| |___
  |_|    \___/ \____|_|\_\_____| |_|      |____/|___/_/   \_\_____|
 ╔══════════════════════════════════════════════════════════════╗
 ║ ◖▌ S Y S O P   T E R M I N A L ▐◗   single-board SIP PBX      ║
 ╚══════════════════════════════════════════════════════════════╝
```

### 2.2 Compact lockup, one-line wordmark (title bars, narrow contexts, README inline)

For places the full nameplate is too tall (panel headers, 80×24 screens with little vertical room):

```
▌▐ POCKET-DIAL ▐▌  · sysop terminal ·
```

### 2.3 Icon glyph, the "jack" mark (favicon-scale, splash corner, wallboard)

A single-cell-ish brand mark suggesting a patch-panel jack / dial. Use where one or two cells is all you
get (e.g. the on-device wallboard corner, the prompt sigil):

```
(◉)   ← the jack-dot
```

Prompt sigil derived from the mark (see §3.4): `(◉)─▶`


## 3. The SSH login banner (first thing shown on connect)

This is the single most important brand surface: it is the **front door**. It must (a) confirm you reached
the right box, (b) set the retro-telco "operator board" tone instantly, (c) fit 80×24 with room to spare
for the login prompt the SSH server appends below it, and (d) never imply state by color alone.

### 3.1 Layout rules for the banner

- Width: ≤ 78 columns of content inside a 78-wide frame (leaves margin at 80).
- Height: 18 content lines; SSH/console appends the `login:`/`Password:` prompt underneath, staying
  inside 24 rows on a fresh connection.
- Composition order: brass top rail → nameplate logo → descriptor sub-rule → identity block
  (host / addr / version / build) → a one-line "house rules" notice → brass bottom rail.
- **Identity block** is *generated at runtime* from the device, placeholders below in `«guillemets»`
  are filled by firmware (`«host»`, `«ip»`, `«mac»`, `«fw»`, `«uptime»`). Keep field labels fixed-width
  so the colon column aligns regardless of value length.
- Color: frame + nameplate in brass/border color; the `◆ READY` lamp pairs amber/green color **with
  the word READY and a ◆ glyph** so monochrome and color-blind users read identical meaning.

### 3.2 The banner (canonical, BRASS theme intent)

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
 login: _
```

### 3.3 Monochrome / no-color rendering (degradation proof)

The exact same glyphs carry all meaning; only the brass tint is gone. `◆ READY` still reads as ready.
This is what a `TERM=vt100` serial console or a `--no-color` client sees, no information is lost:

```
 +============================================================================+
 |     ____   ___   ____ _  _______ _____      ____  ___    _    _             |
 |    |  _ \ / _ \ / ___| |/ / ____|_   _|    |  _ \|_ _|  / \  | |            |
 |    | |_) | | | | |   | ' /|  _|   | |_____ | | | || |  / _ \ | |           |
 |    |  __/| |_| | |___| . \| |___  | |_____|| |_| || | / ___ \| |___        |
 |    |_|    \___/ \____|_|\_\_____| |_|      |____/|___/_/   \_\_____|        |
 |   [#]  SYSOP TERMINAL    single-board SIP PBX                              |
 | -------------------------------------------------------------------------- |
 |   HOST . pocketdial.local           [*] READY -- operator on duty          |
 |   ADDR . 192.168.1.50  .  AA:BB:CC:DD:EE:FF                                |
 |   FW   . POCKET-DIAL v3.0.0  .  up 4d 02:17                                |
 | -------------------------------------------------------------------------- |
 |   Authorized sysops only. All sessions are logged to the CDR.              |
 |   Press ? any time for help.  Esc backs out.  This is an ESP32-S3.         |
 +============================================================================+
 login: _
```

> Box-drawing → ASCII fallback map (firmware picks per `TERM`): `╔╗╚╝═║` → `+ + + + = |`,
> `◆`→`[*]`, `◖▌ ▐◗`→`[#]`, `·`→`.`, `─`→`-`.

### 3.4 Post-login prompt sigil

After auth, before the hub draws, the brand persists as the **prompt sigil** built from the jack mark:

```
(◉)─▶
```

Mono fallback: `(o)->`. The sigil is brand, not state, it never changes color to signal anything.


## 4. Voice & tone

pocket-dial talks like a **calm, competent night-shift switchboard operator** who has run this board for
years: terse, exact, faintly retro, never cute at the user's expense. It respects that the day-2 admin is
not a telecom engineer, and that the installer is in a hurry.

### 4.1 Voice characteristics

- **Operator-terse.** Short, declarative, scannable. The brief's north-star is "reroute in three seconds";
  prose must not slow that down. Status first, explanation second.
  *Yes:* `Ext 204 saved. Ring group SALES updated (3 members).`
  *No:* `We've gone ahead and successfully saved your changes to the extension!`
- **Telco-literate, plain-spoken.** Use real PBX nouns (extension, ring group, hunt, blind transfer,
  star code, CDR) but never invent jargon or import FreePBX/Yeastar terms we don't ship (no "trunks,"
  "queues," "DAHDI"). Map every word to a feature we actually have.
- **Retro, with restraint.** The *chrome* is loud (brass rails, lamps, BBS glow); the *copy* is quiet.
  Flavor lives in fixed places (the banner tagline, the boot line, opt-in easter eggs) not in error
  messages or field labels.
- **Honest about the hardware.** "This is an ESP32-S3." We do not pretend to be a rack appliance. Limits
  (2–8 calls, no voicemail in v1, no SD card) are stated plainly, never hidden.
- **Quietly confident, never alarmist.** Even destructive prompts stay level: `REBOOT now? phones drop
  for ~8s. [y/N]` — fact, consequence, safe default.

### 4.2 Tone by context

| Context | Tone | Example |
|---|---|---|
| Banner / boot | warm, ceremonial (one beat of flavor) | `◆ READY — operator on duty` |
| Hub / navigation | crisp, telegraphic | `Select an option:` |
| Field help / hints | helpful, neutral | `Extension number — 3 to 6 digits, must be unique.` |
| Success confirms | brief, past-tense, concrete | `Saved. 6 extensions provisioned.` |
| Warnings (destructive) | level, consequence + safe default | `Delete ring group SALES? 3 members detach. [y/N]` |
| Errors | blame the input, not the user; say the fix | `Ext 204 already exists. Pick another number.` |
| Empty states | inviting, points to the next key | `No ring groups yet. Press [A] to add one.` |

### 4.3 Words we use / words we ban

- Use: extension, ring group, ring-all, hunt, forward, DND, blind transfer, star code, CDR, sysop,
  board, lamp, online/unreachable, monitor.
- Avoid / ban: trunk, FXO/FXS, queue, conference, IVR-tree (say "menu"), "user" (say "extension" or
  "sysop"), "click"/"tap" (it's keyboard-only, say "press"), exclamation marks in errors, emoji,
  "oops/uh-oh/whoops," "please" as filler, vendor names.

### 4.4 The two sanctioned flavor lines

To keep retro charm from leaking into functional copy, flavor is *budgeted* to exactly two strings:

1. Banner tagline: **`operator on duty`** (lowercased after the `◆ READY —`).
2. Boot/first-frame line (handed to Visual Storyteller): **`Patching you through…`**

Anything beyond these two is an opt-in easter egg owned by `docs/design/whimsy.md`, not core copy.

### 4.5 Status vocabulary (must pair color WITH glyph + label, non-negotiable)

Per the brief, state is never color alone. The canonical status lexicon, every screen uses these exact
glyph+label pairs so the brand reads identically in 16-color, monochrome, and to color-blind users:

| State | Glyph | Label | Color intent (BRASS / PHOSPHOR) | Mono |
|---|---|---|---|---|
| up / registered / connected | `●` | `ONLINE` | amber `#FFB020` / green `#40FF60` | `(*)` |
| down / unreachable | `○` | `UNREACH` | dim text (no red) | `( )` |
| ringing / in setup | `◐` | `RINGING` | highlight brass | `(~)` |
| active call | `◆` | `ACTIVE` | accent lamp | `<*>` |
| DND | `⊘` | `DND` | amber ring `#FFB020` | `[/]` |
| forwarded | `↳` | `FWD` | text | `->` |
| alert / destructive | `▲` | `ALERT` | ember-red `#C84028` / `#DC4632` | `/!\` |

> Rule: the **label** is authoritative; the glyph reinforces it; color is the third, removable layer.


## 5. Color & theme identity (mapping the board to 16-color ANSI)

The on-device palettes (`main/ui/ui.cpp`) are the brand's "true colors." The TUI mirrors them in the
xterm-16 space; exact RGB stays in `docs/design/tui-style.md` (UI Designer owns the mapping table). The
brand-level rules:

- Two themes, same product: **BRASS** (default, amber lamps) and **PHOSPHOR** (alt, green lamps).
  Same charcoal board, same brass rails, only the lamp accent (and a few tints) differ. A sysop toggling
  themes must feel they changed the *bench lighting*, not the product.
- **Brass is the chrome; the lamp is the accent.** Frames, rails, nameplate = brass/border tone. The
  single hot accent (amber or green) is reserved for *live* things: the `◆ READY` lamp, active-call dots,
  the live monitor's pulse. Don't spend the accent on decoration.
- **Red is rationed.** Ember-red (`#C84028` / `#DC4632`) means destructive/alert **only** (reboot,
  delete, ALERT). Never use red for emphasis or headers.
- **DND stays amber in both themes** (it is amber in PHOSPHOR too, see `ui.cpp` line 61). Consistency
  across themes is itself a brand signal.
- **Color is always the *third* layer.** Glyph + label first; color decorates. See §4.5.

### Theme signature (how a sysop knows which theme is live, without color)

The active theme is named in the hub footer/status as a label, never by hue alone:

```
… [T] Theme: BRASS ▸ …      … [T] Theme: PHOSPHOR ▸ …
```


## 6. Consistency rules (the guardrails downstream docs must honor)

These bind the UX Architect, UI Designer, Visual Storyteller, Whimsy Injector, and any string in firmware.

1. **One name, three casings** (§1.1). No new variants, no sub-brands, ever.
2. **The banner is the front door** (§3). Any change to it is a brand change, keep nameplate, descriptor,
   identity block order, and the `◆ READY` lamp. Runtime fields use `«guillemets»` placeholders.
3. **80×24 is the floor.** The banner ≤ 78 cols / ≤ 23 rows incl. the appended `login:`. Logos ≤ 80 cols.
   Anything wider is a bug, not a flourish.
4. **State = glyph + label, color last** (§4.5). No screen, no exception. This is accessibility *and*
   brand, it is what makes the board legible on a serial console.
5. Every screen carries the brand spine: a title bar (`POCKET-DIAL vX.Y  [MODE]  HH:MM:SS`), an
   always-visible key-hint footer, `?` help, and Esc-to-back. The footer always shows the theme label.
6. **Flavor is budgeted to two lines** (§4.4) plus opt-in easter eggs. Functional copy stays operator-terse.
7. **Box-drawing must have an ASCII fallback** (§3.3 map). If a glyph has no fallback, don't use it.
8. **Use real feature nouns only** (§4.3). If we don't ship it (trunks, queues, voicemail-in-v1), it does
   not appear in any string, label, menu, or mockup.
9. **Brass chrome, rationed accent, rationed red** (§5). The lamp and the red each mean one thing.
10. **Honesty clause.** Surfaces may state real limits plainly ("This is an ESP32-S3", "2–8 calls",
    "voicemail arrives in v2"). Never imply capabilities we don't have.

### 6.1 Quick brand checklist (paste into any new screen review)

```
[ ] Name cased correctly for context (prose/title/banner/host/code)
[ ] Title bar present: POCKET-DIAL vX.Y  [MODE]  HH:MM:SS
[ ] Every status = glyph + label (+ optional color), never color alone
[ ] Footer key-hints visible + theme label shown
[ ] '?' help reachable, Esc backs out
[ ] Fits 80×24, no horizontal scroll, ASCII fallback exists for box glyphs
[ ] Copy is operator-terse; no banned words; flavor within the 2-line budget
[ ] Red used only for destructive/alert; accent lamp only for live state
```


## 7. Asset inventory (what this brand provides downstream)

| Asset | Where it lives | Consumer |
|---|---|---|
| Primary nameplate logo (§2.1) | this file | login banner, splash, README hero |
| Compact wordmark (§2.2) | this file | panel title bars, narrow contexts |
| Jack icon `(◉)` + prompt sigil `(◉)─▶` (§2.3/3.4) | this file | wallboard corner, shell prompt |
| Full SSH login banner + mono fallback (§3.2/3.3) | this file → firmware `sshd` banner | every SSH connect |
| Status lexicon (§4.5) | this file | UI Designer, every screen, firmware strings |
| Voice & tone + word list (§4) | this file | all copy, all docs, firmware messages |
| Theme identity rules (§5) | this file (RGB table → tui-style.md) | UI Designer |
| Consistency rules + checklist (§6) | this file | all Phase-A agents, code review |


**Brand Guardian** · pocket-dial 3.x redesign · brass/phosphor operator board
Status: identity locked for Phase A. Banner ready to wire into the SSH server greeting.
Protection: name treatment, banner composition, and status-lexicon are the protected core, 
changes require a brand review against the §6.1 checklist.
