# pocket-dial: Accessibility Guardrails (SSH Sysop TUI)

> **Phase-A deliverable (Accessibility Auditor).** Audits the TUI defined in
> [`tui-ia.md`](tui-ia.md) and rendered in [`tui-style.md`](tui-style.md) against the
> non-negotiables in [`00-brief.md`](00-brief.md) §6 and the device palette in `main/ui/ui.cpp`
> (lines 39–64). It does **not** redraw screens. It constrains how the locked screens render so
> the product is usable by color-blind operators, screen-reader-over-SSH operators, low-vision
> operators at 80×24, and keyboard-only operators with no escape hatch but the keyboard.
>
> This file owns: (1) the color-blind-safe treatment of BRASS/PHOSPHOR with a per-state
> glyph/label audit proving **no state is color-only**; (2) screen-reader-over-SSH behavior:
> reading order, announced labels, and a **STATIC mode** that kills the 1 Hz cursor-jump churn;
> (3) 80×24 legibility + focus-visibility rules; (4) keyboard-trap avoidance.
>
> **Standard applied.** A TUI is not a web page, so WCAG 2.2 SC numbers are cited *by analogy*
> where the intent transfers (1.4.1 Use of Color, 1.3.1 Info & Relationships, 2.1.2 No Keyboard
> Trap, 2.4.3 Focus Order, 2.4.7 Focus Visible, 4.1.3 Status Messages, 1.4.10 Reflow,
> 3.3.x error identification). The terminal *is* the assistive-tech surface; "screen reader" means
> a software AT (NVDA/JAWS/Orca/VoiceOver) reading the SSH client window, or a refreshable Braille
> display, or `TERM=dumb` line output piped to one.

## 0. Audit verdict (read this first)

**Conformance (by-analogy WCAG 2.2 AA): PARTIALLY CONFORMS, 2 BLOCKING issues, 4 serious.**
The glyph+label discipline locked in brand §4.5 / style §1.5 is genuinely excellent and clears the
single biggest TUI accessibility trap (color-only state). The monochrome proof in style §1.5 is real
and lossless. **But** two things will lock out real users today:

- **A11Y-1 (BLOCKING):** the steady-state 1 Hz cursor-positioned live redraw (style §6.4) makes the
  Monitor, hub headroom line, clock, and Event-Log tail *unusable* with a screen reader; every
  repaint either re-announces or yanks the AT review cursor. There is no static mode. **Must add one.**
- **A11Y-2 (BLOCKING):** reverse-video-only is proposed as a *fallback-survivable* selection cue, but
  AT does **not** announce `ESC[7m`. A blind operator on the Extensions table cannot tell which row
  Enter/D will act on. The `▸` marker saves the sighted-mono case but not the AT case: selection
  must be **announced as text**, not just inverted.

Everything else is a tightening, not a teardown. Details and fixes below; the blocking set is the
`risks` array of the return schema.

## 1. Color-blind-safe treatment of BRASS & PHOSPHOR

### 1.1 The good news, stated precisely

The design never encodes state in hue alone: it pairs every state with a glyph **and** a word,
and the UI Designer's §1.5 proof renders the whole hub with all SGR stripped and all box glyphs
ASCII-folded with zero information loss. That satisfies the analog of **WCAG 1.4.1 (Use of Color)**
and is the correct architecture. This audit's job is to verify the *pairing is complete and
collision-free*, including the cases the §1.5 proof did not exercise (RINGING, the CDR result set,
the `·`/`○` dim pair, the `⚠` integrity flag).

### 1.2 Per-state audit: every lamp/chip, both themes

Columns: the locked SGR (from style §1.2/1.3), the glyph, the label, the **mono/ASCII** form (the
only thing AT and `TERM=dumb` actually receive), and the **verdict**. A state PASSES color-blind +
AT only if it is distinguishable **with the SGR column deleted**.

| State | BRASS SGR | PHOSPHOR SGR | Glyph→ASCII | Label | Distinct w/o color? | Verdict |
|---|---|---|---|---|---|---|
| ONLINE / up | `93` br-yellow | `92` br-green | `●`→`(*)` | `ONLINE` | glyph+word unique | **PASS** |
| UNREACH / down | `90` grey | `90` grey | `○`→`( )` | `UNREACH` | glyph+word unique | **PASS** |
| RINGING | `93` br-yellow | `92` br-green | `◐`→`(~)` | `RINGING` | glyph+word unique | **PASS** (see C1) |
| ACTIVE (media) | `93` br-yellow | `92` br-green | `◆`→`<*>` | `ACTIVE` | glyph+word unique | **PASS** |
| READY (banner/lamp) | `93` br-yellow | `92` br-green | `◆`→`<*>` | `READY` | shares `◆` with ACTIVE | **PASS** (word disambiguates) |
| DND | `93` amber (both) | `93` amber (both) | `⊘`→`[/]` | `DND` | glyph+word unique | **PASS** |
| FWD | `33` brass | `32` green | `↳`→`->` | `FWD`/`205` | glyph+word unique | **PASS** |
| ALERT / destructive | `31` red | `31` red | `▲`→`/!\` | `ALERT` | glyph+word unique | **PASS** |
| integrity flag | `31` red | `31` red | `⚠`→ **(see A11Y-4)** | `NOT AN EXTENSION` / `EXCEEDS CAP` | word unique | **PASS on word, FAIL on glyph fallback** |
| none / unset | `90` grey | `90` grey | `·`→`.` | (none) | **glyph only, no word** | **WEAK** (see C2) |
| idle channel | `90` grey | `90` grey | `○`→`( )` | `idle` | collides w/ UNREACH glyph | **PASS** (word disambiguates) |
| CDR ✓ answered | `93`/`92` | `92` | `✓`→ **(see A11Y-4)** | `answered` | word unique | **PASS on word** |
| CDR ⊘ busy | `93` amber | `93` amber | `⊘`→`[/]` | `busy` | shares `⊘` w/ DND | **PASS** (word + context) |
| CDR … cancelled | `33` brass | `32` green | `…`→`...` | `cancelled` | word unique | **PASS** |
| CDR ○ unavailable | `90` grey | `90` grey | `○`→`( )` | `unavailable` | shares `○` w/ UNREACH | **PASS** (word disambiguates) |
| CDR ▲ failed | `31` red | `31` red | `▲`→`/!\` | `failed` | shares `▲` w/ ALERT | **PASS** (word disambiguates) |

Headline result: every state carries an authoritative **word**, so all states survive total color
loss. Glyph re-use (`◆` ACTIVE/READY, `○` UNREACH/idle/unavailable, `⊘` DND/busy, `▲` ALERT/failed)
is **safe only because the label is mandatory and authoritative**, which it is. This is the
load-bearing rule; the findings below protect it.

### 1.3 Color-collision findings (these do NOT break color-blind safety, but constrain the renderer)

The design's own SGR table collapses several *distinct* states onto one xterm index. That is fine for
color-blind users (the glyph+word carries it), but it means **color adds zero disambiguation for
these**, so the renderer must never be tempted to drop the glyph/word "because the color shows it."

- **C1: BRASS triple-collision on bright-yellow `93`.** `● ONLINE`, `◐ RINGING`, `◆ ACTIVE` *and*
  `⊘ DND` (amber) all emit `93` in BRASS. Four operational states, one color. A red-green color-blind
  operator and a fully-sighted operator see the *same* yellow for all four. Guardrail: the glyph
  and word are the *only* signal here; the renderer MUST emit both for all four; "lamp is lit"
  (bright vs dim) is the *only* thing color conveys in BRASS, never *which* lamp. Document this so no
  future "optimization" tints RINGING differently and creates a color-only distinction that fails in
  PHOSPHOR/mono. (PHOSPHOR has the same collapse on `92` plus amber `93` for DND.)
- **C2: the dim-grey `90` pair: `· none` vs `○ UNREACH` vs `idle`.** All three are grey, and `· none`
  has no label at all: it is a bare glyph (`·`→`.` in mono). A Braille/AT user reading the
  Forwards/DND table hears "dot" or a literal period in four columns and must infer "unset." See **C2
  fix** in §2.4 (announce `·` as the word "none"/"unset" in AT mode).

### 1.4 Contrast: the part a 16-color TUI cannot self-certify, and what to do about it

A terminal app does not control its own pixels; the SSH *client's* palette does. So we cannot
assert a 4.5:1 ratio the way a web app can; PuTTY's "yellow" is the user's configured yellow. Three
real legibility hazards follow from the locked mapping, with concrete mitigations:

- **K1: brass text = xterm `3` (yellow), DIM, on black.** Style §1.2 maps body brass text to
  `fg 33` and recesses the panel with `ESC[2m` DIM. **Dim yellow on black is the single worst-tested
  combo across terminal default palettes** (many themes render `2;33` as a muddy olive ~2.5:1).
  Guardrail: DIM (`ESC[2m`) is permitted **only on box-drawing chrome and the panel face**, and
  is **forbidden on any text the operator must read** (labels, values, headers, footer keys). Body
  brass text is plain `33`, never `2;33`. This keeps the readable layer at the terminal's full-bright
  foreground.
- **K2: `90` bright-black ("grey") for UNREACH / dim / none.** On a pure-black bg some terminals
  render `90` near-invisible. UNREACH is a *state operators must notice* (a phone is down). It is
  already carried by glyph+word, so it never *disappears*, but it must be *findable*. Guardrail:
  UNREACH/idle/none rows keep full-bright frame chrome around them; never put a `90`-grey value on a
  `40`-black bg with no adjacent bright structure. The §1.5 mono form (where `90` becomes plain
  default-fg) is the safety net and must remain a supported tier.
- **K3: selected row reverse video (`ESC[7m`).** Reverse swaps fg/bg, so a selected `90`-grey "none"
  becomes black-on-grey (readable), but a selected `31`-red "ALERT" becomes black-on-red, which on
  some palettes drops below 3:1. Guardrail: the `▸` marker + the trailing label are the selection
  signal; do not rely on the reverse field for legibility of any red value. (And see A11Y-2: reverse
  is invisible to AT entirely.)
- **K4: Forced-Colors / high-contrast / Braille.** Some operators run the terminal in a forced
  mono/high-contrast scheme, or read it on a Braille line where SGR is simply gone. The §1.5 proof
  shows this already works **for layout**. The remaining gap is the live cells (A11Y-1) and selection
  (A11Y-2), handled below.

Net contrast verdict: the design is contrast-*safe* in principle (it degrades to a mono tier that
relies on no color at all) but contrast-*fragile* in the colored tiers because of the dim-yellow and
bright-black choices. The K1/K2 guardrails remove the fragility without changing a single mockup.

## 2. Behavior under a screen reader over SSH

### 2.1 The core conflict (A11Y-1, BLOCKING)

The brief (§6) and style §6.4 mandate the "BBS glow": the clock, hub headroom line, Monitor call
matrix, vitals bars, and Event-Log tail are repainted **~1 Hz by `ESC[<row>;<col>H` + overwrite**,
deliberately *not* full clears. This is correct for the embedded/bandwidth goal and beautiful for a
sighted operator. **It is hostile to every screen reader.** AT software watches the terminal cell
buffer; a 1 Hz in-place overwrite triggers one of two failure modes, both bad:

1. The AT treats changed cells as new content and **re-announces** them, so the operator hears
   "ACTIVE… 02:14… ACTIVE… 02:15… ACTIVE… 02:16…" forever, a verbal machine-gun that buries every
   other announcement and makes the screen impossible to review.
2. The AT does **not** announce them but the screen's "live" repaint **moves the terminal cursor**
   every second, which **yanks the AT review cursor** out from under the operator mid-read.

This is the TUI analog of **WCAG 4.1.3 (Status Messages)** failing in the *opposite* direction: not
"changes go unannounced" but "everything is announced, constantly, with no way to be quiet."

**FIX: a STATIC / screen-reader mode (mandatory).** A session-level mode, distinct from `[F] Freeze`
(which only pauses the matrix on the Monitor screen):

- Trigger (three ways, any one): (a) automatic when `TERM=dumb` or the SSH env advertises no
  cursor addressing; (b) an explicit `--static` / `screenreader` login option and a hub toggle (a new
  single-key, e.g. `S`, named in help, *not* on the hub typeahead row to avoid colliding with the
  six destinations); (c) persisted per-session so a reconnect resumes static.
- Behavior: suppress all unsolicited repaints. No clock tick, no headroom tick, no matrix
  overwrite, no vitals animation, no Event-Log auto-tail. The screen is drawn **once** and only
  changes in response to a keypress.
- Refresh on demand, not on a timer: a single key (reuse `Ctrl-L` "redraw," already global per IA
  §0) repaints the *current* live snapshot. The footer in static mode reads
  `… [Ctrl-L] Refresh  · STATIC` so the operator knows the screen is frozen-by-design and how to pull
  fresh data. The `⟳ 1 Hz` badge becomes `❚❚ STATIC` (glyph+word, never color).
- Live data still reachable: static mode does not hide the call matrix; it stops it from
  *moving*. Up/Down still walk the rows; the operator reads the snapshot, presses `Ctrl-L` when they
  want a newer one. This is the standard "give me a stable surface, let me ask for updates" AT
  pattern, and it costs the firmware nothing (it already has the render-once path for `Ctrl-L`).

This mode is the single most important accessibility addition in this document. Without it, a blind
sysop can configure the box (the static config screens are fine) but **cannot monitor it**, and
"watch it light up" is the product's own acceptance test (style §3.3, M4).

### 2.2 Reading order (linearization): what the AT reads top-to-bottom

A screen reader reads the cell buffer **left-to-right, top-to-bottom**. The 3-zone geometry (title /
body / footer, every screen) gives a clean linear order **by construction**, a real strength
of the locked IA. Audited order per archetype:

- Hub: title (`POCKET-DIAL v3.0  [ SYSTEM MANAGEMENT ]  HH:MM:SS`) → the six numbered
  destinations in reading order → `[R] [L]` → headroom line → prompt → footer. A first-time AT user
  hears the whole launcher in one pass. **PASS.** *Guardrail:* the title-bar clock is the first live
  cell read on every screen; in static mode it must not re-fire; render it once.
- Table panels (Extensions etc.): tab strip → column header row → rows top-to-bottom → headroom →
  footer. The column-header row is read **before** the data, which is exactly the WCAG 1.3.1 intent
  (header context precedes cells). **PASS for order. FAIL for cell association**, see §2.4.
- Modals/confirm: the dialog is drawn *centered over a dimmed body*. The AT does **not** know the
  body is "dimmed/inert"; dimming is a visual `ESC[2m`, invisible to AT. So the AT will read the
  **stale background screen first, then the dialog**, and the operator may act on the wrong layer.
  **A11Y-3 (serious)**, fix in §2.5.

### 2.3 Announced labels: does the AT have words to read?

Because every control is **text** (`[1] SYSTEM MONITOR`, `< Apply >`, `[ Cancel ]`, `[x] on`,
`(•) Random per-ext`), the AT reads a *meaningful label for every actionable element* with no extra
work; there is no icon-only button, no unlabeled control. This clears the analog of **WCAG 4.1.2
(Name, Role, Value)** for the *name* dimension better than most GUIs manage. Residual gaps:

- **Role is implicit.** The AT reads `< Apply >` as the literal string "< Apply >", not "Apply,
  button." A new AT user may not know `< >` means *focused button* vs `[ ]` *unfocused*. This is
  acceptable for a sysop tool (the convention is learnable and the help overlay teaches it) but the
  **help overlay must state the convention in words** (see §2.6).
- Radios/checkboxes: `(•)`/`( )` and `[x]`/`[ ]` are read as those literal glyphs. In mono they
  become `(*)`/`( )` and `[x]`/`[ ]`. An AT user can learn this, but the **help overlay's state key
  must include the form-control glyphs**, not just the status lexicon (style §3.14 currently lists
  only `● ○ ⊘ ↳ ▲`). Add: `(•) selected · ( ) not · [x] on · [ ] off · < > focused · [ ] button`.

### 2.4 Selection & cell association in tables (A11Y-2 BLOCKING + C2)

**A11Y-2 (BLOCKING).** The locked selection cue is "`ESC[7m` reverse video **and** a `▸` marker"
(style §2.6, §6.5). The `▸` survives SGR-stripping for a *sighted mono* user, good. But **AT does
not announce reverse video, and a leading `▸` in column 0 is easily skipped** when the operator
arrow-reads by cell or jumps by word. A blind operator on the Extensions table cannot reliably tell
which of seven rows `[Enter]`/`[D]` will hit. Since `D` is a guarded *delete*, **this is a
data-loss-adjacent ambiguity**, hence blocking.

FIX (selection must be spoken):
- On every Up/Down, the renderer **emits the selected row's identity as a short spoken line** in a
  fixed, AT-reachable place: reuse the prompt/status line, e.g. write
  `Selected: ext 102 Sam, ONLINE, DND on, forward 205` to the line above the footer (the same line
  the hub uses for its prompt). This is a **status-message announcement** the AT reads on change
  (WCAG 4.1.3 done right), and it gives the operator the row's full state in words before they act.
- Keep the `▸` marker and reverse video for sighted users; they are additive. The spoken line is the
  AT path; the marker is the mono-sighted path; reverse is the colored-sighted path. Three cues, one
  truth, none color-only.
- In **static/AT mode**, this selection line is *the* feedback channel and must update on every
  Up/Down keypress (a keypress-driven change is solicited, so re-announcing is correct, unlike the
  unsolicited 1 Hz churn).

C2 fix (the bare `·`): the "none/unset" glyph `·` (mono `.`) has no word. In AT/static mode the
renderer must substitute the word: a `·` cell is announced as **`none`** (or `unset` in the Forwards
context). Cheap: the glyph table (style §6.2) already centralizes glyph→ASCII; add a glyph→**word**
column for the AT tier so `·`→`none`, `○`→`UNREACH`, `●`→`ONLINE`, etc. The word table *is* the AT
rendering.

### 2.5 Modals over a "dimmed" body (A11Y-3, serious)

Visual dimming (`ESC[2m` on the background) is invisible to AT, so the inert background reads as live
content and the dialog's modality is lost. Fix:
- When a modal is open, the renderer should **announce the dialog title and first line first** by
  positioning the cursor into the dialog and writing a brief lead-in the AT will catch (e.g. the
  centered `┌─ Confirm ─┐` line carries the word `Confirm`, and the `▲ ALERT` line states the action).
  The confirm shell already front-loads `▲ ALERT  REBOOT now?`, good; ensure it is the **first**
  text written when the modal opens so it is what the AT speaks on open.
- In static/AT mode, opening a modal should **redraw only the dialog region** and the operator is told
  (footer) `[Esc] Cancel`, the safe default. Esc-cancels-to-safe-default is already the spec (IA
  §4.3); that is exactly the AT-friendly escape (see §4).
- Do **not** rely on the background dim to communicate "you can't touch this"; the *keyboard* already
  enforces it (background keys are inert while the modal owns input). The keyboard enforcement is the
  real modality; the dim is decoration. This is fine as long as input truly routes to the modal.

### 2.6 The banner & ASCII-art logo under AT (minor, but call it out)

The login banner (style §3.1, brand §3.2) is a multi-line **FIGlet-style ASCII-art `POCKET-DIAL`**.
A screen reader will read it as gibberish ("underscore underscore space slash underscore…") for
~6 lines before reaching anything useful. Guardrail: the banner must include a **plain-text
product line the AT hits first or immediately after** (it already does: `SYSOP TERMINAL · single-board
SIP PBX`, and the `HOST · pocketdial.local` block). Recommend the firmware, when it detects
`TERM=dumb`/static/AT, **suppress the ASCII-art block entirely** and lead with the plain identity
block + `login:`. The art is pure decoration (brand confirms the sigil "is brand, not state"). The
PIN prompt must remain reachable; see §4.3.

### 2.7 Summary table: screen-reader behavior per screen

| Screen | Reading order | Live-cell churn | AT verdict (after fixes) |
|---|---|---|---|
| Banner + PIN | art (suppress in AT) → identity → `login:`/`PIN:` | clock only | PASS w/ §2.6 + §4.3 |
| Wizard `[0–5/5]` | step rail → prompt → fields → buttons → footer | none (form) | **PASS** (best screens for AT) |
| Hub | title → 6 dests → R/L → headroom → prompt → footer | clock + headroom | PASS w/ STATIC (§2.1) |
| Monitor | title → matrix → roster → vitals → footer | **matrix+vitals+clock** | **FAIL w/o STATIC** (A11Y-1) |
| Network | title → status lines → `[M]` → footer | none | PASS |
| PBX tabs (all) | tab strip → header → rows → headroom → footer | none (static tables) | PASS w/ selection-speak (A11Y-2) |
| Security | title → access lines → session → keys → footer | none | PASS |
| Reports · Recent | view selector → header → rows → footer | none | PASS w/ A11Y-2 |
| Reports · Event Log | view selector → tail lines → footer | **auto-tail 1 Hz** | **FAIL w/o STATIC** (A11Y-1) |
| Confirm / modals | (dimmed bg) → dialog | none | PASS w/ §2.5 |
| Help overlay | dialog body → footer | none | PASS |

## 3. 80×24 legibility & focus visibility

### 3.1 Geometry is compliant, verified

Every mockup in style §3 is exactly 80×24 with the 3-zone split and **no horizontal scroll**
(brief §6, the analog of **WCAG 1.4.10 Reflow**, content reflows/clips, never side-scrolls). The
renderer contract §6.7 clips to 80 cols and ellipsizes overflowing fields. **PASS.** Specific checks:

- **No information below the fold.** 24 rows is the floor; nothing essential lives off-screen. The
  headroom cap, footer keys, and theme label are all on-screen at all times. **PASS.**
- **Tab strip fits.** `Extensions │ Ring Groups │ Forwards/DND │ IVR │ Features` measures ≤ 80. **PASS.**
- **Footer key-hints fit at 80.** Several footers are *dense* (e.g. Extensions:
  `[←/→]Tabs [↑/↓]Sel [Enter]Edit [A]Add [D]Del [/]Find [Esc]Back  · BRASS ▸`). It fits, but it is at
  the legibility edge for low-vision operators who zoom their terminal font (fewer columns visible per
  glance, more eye-travel). L1 (minor): acceptable because `?` help restates every key in a roomy
  vertical list. The footer is the *reminder*, the help overlay is the *reference*. Keep `?` exhaustive.

### 3.2 Low-vision / terminal-zoom (the TUI form of WCAG 1.4.4 Resize Text)

A TUI cannot offer a zoom control; the operator zooms the **SSH client font**, which reduces visible
columns/rows. Because the design *requires* 80×24, a low-vision operator who zooms past the point where
80 columns fit will get the client's own reflow/scroll, which the design can't control. Guardrails:
- Never push content to exactly column 80; the mockups already keep a right margin (frame at col 80,
  content ends ≤ 78). This gives the operator's terminal a 1-2 col safety margin. **PASS**, preserve it.
- The **single-key hub typeahead** (1-6, R, L, T) is the low-vision win: the operator need not *read*
  the screen to navigate the hub. Muscle memory + the spoken/visible single key gets them there. The
  IA's "memorize 3→1→A" efficiency goal **is** an accessibility feature. Reinforce in help.

### 3.3 Focus visibility (WCAG 2.4.7 analog): the weak spot

In a GUI, focus is one ring. In this TUI, "focus" appears in **four different visual languages**, and
a low-vision or cognitively-loaded operator must learn all four:

1. Table row selection: `▸` marker + reverse video.
2. Form button focus: `< Apply >` angle-brackets + reverse, vs `[ Cancel ]` plain.
3. Form field focus: the cursor sits in `[ 108_ ]`, with no other marker.
4. Radio/checkbox selection: `(•)` / `[x]`, which is *state*, not *focus*; a focused-but-unchosen
   radio looks identical to an unfocused-but-unchosen one.

**F1 (serious): form-field focus is under-marked.** Tabbing between `Number / Name / PIN` fields, the
*only* focus cue is the terminal text cursor's position. On a slow SSH link or a client that hides the
cursor, the operator cannot tell which field is hot. Fix: give the focused field a non-color
marker: a `▸` in the field's left gutter (mirroring table selection) **and/or** brighten the field's
label to bright-header. So `▸ Number .... [ 108_ ]` reads as focused in mono and to AT (the `▸`
precedes the field label, which the AT speaks). This makes the four focus languages share one glyph
(`▸` = "here"), which is also a consistency win.

**F2 (minor): radio focus vs selection conflation.** In a radio group, the operator needs to know
*which option the cursor is on* (focus) separately from *which is chosen* (`(•)`). Fix: when a
radio group has focus, mark the **focused option** with the same `▸` gutter glyph; `(•)`/`( )` stays
the chosen-state. So focused-but-unchosen = `▸ ( ) Standalone hotspot`; chosen = `(•)`. Spoken as
"on Standalone hotspot, not selected" by AT once the `▸` is present.

**F3 (good, keep): selection in tables already pairs marker+reverse.** With A11Y-2's spoken line
added, table focus is the *best* of the four. Bring the other three up to it by adopting the `▸`
gutter glyph everywhere a cursor can land. One focus glyph, every surface.

### 3.4 Motion / flicker (WCAG 2.3.1 Three Flashes; 2.2.2 Pause/Stop/Hide)

- The 1 Hz repaint is slow enough to never approach a seizure threshold (3 Hz). **PASS on 2.3.1.**
- But **2.2.2 (Pause/Stop/Hide auto-updating content)** requires a way to *stop* moving content. Today
  only the Monitor has `[F] Freeze`; the **hub headroom line, the title clock, and the Event-Log tail
  auto-update with no stop control.** STATIC mode (§2.1) is the global Pause/Stop/Hide and closes
  this, another reason it is mandatory, not optional. Any *whimsy* animation (register-beep glow,
  cursor sparkle from `whimsy.md`) **must** be suppressed in static/reduced-motion mode and must be
  opt-in per the brief.

## 4. Keyboard-trap avoidance (WCAG 2.1.2)

A keyboard-only operator (every operator here, there is no mouse) must be able to **leave any state
using the keyboard alone**. Audit of every place focus can land:

### 4.1 The Esc invariant is the anti-trap, verified

IA §0/D7 locks **"Esc backs out exactly one level, everywhere, non-destructively,"** and the hub is
the single terminus (Esc = no-op at home, because there is nowhere up). This is a *correct, complete*
anti-trap design: from any screen, repeated Esc walks the operator to the hub and stops. **PASS**,
this is the model to keep. Verified per surface:

| Surface | Exit key(s) | Lands on | Trap? |
|---|---|---|---|
| Hub | `L` logout / `1-6` go | (home / dest) | No (Esc is a deliberate no-op, not a trap; you *are* home) |
| Any panel | `Esc` | Hub | No |
| Table → modal editor | `Esc` | parent panel | No |
| Confirm dialog | `Esc` / `n` | caller, **safe default** | No |
| Wizard step | `Esc` | previous step | No |
| Wizard `[0/5]` | `Esc` = no-op | (stays) | **See T1** |
| Help overlay | `Esc` | the screen beneath | No |
| Form field (text) | `Tab`/`Esc` | next field / cancel | No |

### 4.2 The two real trap risks

- **T1 (by design, but verify it's escapable *off-box*).** Wizard `[0/5]` makes Esc a no-op: you
  **cannot escape first-run setup** because nothing usable exists behind it (IA §3.4). This is
  *intentional and correct*, but it means an operator who cannot complete setup (forgot Wi-Fi creds)
  has **no keyboard exit except completing or disconnecting the SSH session.** That is acceptable
  (disconnecting is a clean exit and the box persists progress), but the wizard must state it: the
  `[0/5]` screen already says "Esc backs out, your work is saved"; for AT clarity, also name the real
  escape: *"To stop, close the SSH session; you'll resume here."* Not a trap (SSH disconnect is always
  available), but the operator must be told the keyboard won't escape this one screen.
- **T2 (the genuine latent trap): modal focus must not strand.** Every modal's footer advertises
  `[Esc] Cancel`, and Esc maps to the safe default. Guardrail (must-verify in firmware): input
  while a modal is open MUST route to the modal, and **Esc MUST be honored from *every* field inside
  it**, including mid-edit in a text field. The classic terminal trap is "a text input swallows Esc
  (treats it as the start of an escape sequence) and the operator is stuck typing." The renderer's key
  decoder must distinguish a lone `Esc` (cancel) from `Esc[`-prefixed arrow sequences with a short
  timeout, so a bare Esc keypress always cancels. **This is the one place to test hardest.**

### 4.3 PIN entry under AT: the silent-field trap (serious)

The PIN is **never echoed** (banner, wizard `[2/5]`, change-PIN modal), correct for security. But a
**screen-reader user gets no feedback that a keypress registered** (no echoed char to announce, and
"never echoed" usually means *nothing* is sent). The operator types blind with no confirmation, can't
tell if a key was dropped on a laggy SSH link, and may not know the cursor is even in the field.
This is the analog of an unlabeled, silent password field. Fix:
- Echo a masking glyph per keystroke (`•`, mono `*`), *not* the digit. The mockups already show
  `••••••`; make that a *real per-keypress echo of a mask*, so the AT announces "bullet" / "star" on
  each key and the operator hears that input registered, **without** leaking the PIN. This is the
  standard accessible-password pattern (mask, don't suppress).
- Announce field entry: when focus lands on a PIN field, the label (`PIN`, `Confirm`, `Current PIN`)
  precedes the field so the AT speaks it (already true in the mockups; keep the label immediately
  left of the field).
- On reject, the terse error (`PIN rejected. Try again.`) is plain text the AT reads. **PASS**, keep
  it on its own line so it is announced as a status change (4.1.3).

### 4.4 No dead-end keys

Verified there is **no key that consumes focus without an advertised exit**: every screen's footer
ends in the live keys + theme label, `?` is always present, `Esc` is always present (or a documented
no-op), and `Ctrl-L` redraws to recover from any rendering corruption (IA §0), which doubles as the
"my screen got into a weird state" keyboard recovery. **PASS.**

## 5. The guardrail checklist (paste into the renderer's review gate)

```
COLOR-BLIND / USE-OF-COLOR
[x] Every state = glyph + WORD; word is authoritative (verified §1.2, all 17 states)
[ ] (A11Y-4) ⚠ ✓ … have ASCII fallbacks in the glyph table (⚠→/!\ or [!], ✓→[ok]/y, …→...)
[x] No color-only distinction anywhere; BRASS `93` carries 4 states — glyph/word mandatory (C1)
[ ] (C2) bare `·` none/unset announced as the WORD "none" in AT/word table
[ ] (K1) DIM (ESC[2m) used ONLY on chrome/panel, NEVER on readable text
[ ] (K2) UNREACH/none `90`-grey never isolated on black with no bright structure adjacent

SCREEN READER OVER SSH
[ ] (A11Y-1 BLOCKING) STATIC mode: suppress ALL 1 Hz repaints; refresh on Ctrl-L only
[ ] (A11Y-2 BLOCKING) Selection SPOKEN as a text line on every Up/Down (not reverse-video only)
[ ] (A11Y-3) Modal announces its title/▲ALERT line FIRST on open; bg dim is decoration only
[x] Reading order is title→body→footer linear on every screen (3-zone geometry)
[ ] (§2.6) Suppress ASCII-art banner block in AT/dumb tier; lead with plain identity + login
[ ] (§2.3) Help overlay state-key includes FORM glyphs: (•) ( ) [x] [ ] < > [ ]

80x24 LEGIBILITY & FOCUS
[x] Every screen 80x24, no horizontal scroll, content ends <= col 78 (margin preserved)
[ ] (F1) Focused FORM FIELD marked with ▸ gutter glyph (not cursor-position alone)
[ ] (F2) Focused RADIO/CHECKBOX option marked with ▸ (focus) separate from (•)/[x] (state)
[x] One focus glyph `▸` adopted across table rows, buttons, fields, radios (consistency)
[ ] (2.2.2) STATIC mode is the global Pause/Stop/Hide for ALL auto-updating cells
[ ] Whimsy/motion suppressed under static/reduced-motion; opt-in only

KEYBOARD TRAP
[x] Esc backs out one level everywhere; hub = terminus; no dead-end key (IA D7)
[ ] (T2) Bare Esc cancels from inside EVERY text field (Esc vs Esc[-seq disambiguated by timeout)
[ ] (T1) Wizard [0/5] names the real exit ("close the SSH session; you'll resume")
[ ] (4.3) PIN echoes a MASK glyph per keystroke (mask, don't suppress) so AT confirms input
```

## 6. Cross-references & ownership

- Owns: the AT/word-rendering tier (glyph→word table), STATIC-mode behavior spec, the focus-glyph
  unification (`▸` everywhere), and the contrast guardrails (K1/K2). These are *constraints on the
  renderer*, layered on the UI Designer's mockups without changing a single screen's geometry.
- Defers to `tui-style.md` for the canonical glyph set, SGR mapping, and mockups (this file
  audits them, does not restate them) and `tui-ia.md` for the Esc/keyboard model (verified, not
  redesigned). The persona doc (§422-424) flags this audit as the joint owner of the monochrome /
  color-blind-sim / screen-reader spot-check; this file is that spot-check, made normative.
- Hands to the firmware implementer: the §5 checklist is the review gate; the four BLOCKING/serious
  items (A11Y-1, A11Y-2, A11Y-3, F1/4.3) gate "accessible," not just "renders."

*Accessibility Auditor · pocket-dial 3.x redesign · audits `tui-style.md` + `tui-ia.md` against*
*`00-brief.md` §6 and `main/ui/ui.cpp` PALETTES[]. Conformance: PARTIALLY CONFORMS, 2 blocking*
*(STATIC mode; spoken selection), 4 serious. Glyph+label architecture is sound; live-redraw and*
*reverse-only selection are the blockers. No mockup geometry changes required; renderer constraints only.*
