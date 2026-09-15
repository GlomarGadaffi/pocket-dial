# pocket-dial: Retro-BBS Delight Pass (Whimsy, opt-in)

> **Phase-A deliverable (Whimsy Injector).** Reads from and stays subordinate to
> [`00-brief.md`](00-brief.md) (canonical constraints), [`brand.md`](brand.md) (voice, the
> **two-line flavor budget** in §4.4, the status lexicon §4.5, ASCII-fallback map §3.3),
> [`tui-ia.md`](tui-ia.md) (keybindings, reserved-but-unused keys), and
> [`tui-style.md`](tui-style.md) (component library, renderer contract §6).
>
> This file owns the third flavor tier only. `brand.md` §4.4 budgets *core* copy to exactly two
> sanctioned lines, `operator on duty` and `Patching you through…`, and then says: *"Anything
> beyond these two is an opt-in easter egg owned by `docs/design/whimsy.md`."* That is this file. The
> delight here is the **night-shift operator's brass-and-phosphor charm**, kept off the critical path:
> every flourish is **skippable, resource-free, and never slows a fast operator**.
>
> One-line essence: **charm lives in the chrome and the corners, never in the keystroke path.**

## 0. The whimsy contract (the rules every flourish below obeys)

These are non-negotiable guardrails. If a delight idea fails any one, it does not ship.

1. **Speed is sacred (brief §3, IA D1).** Nothing here adds a keystroke, a confirm, a redraw stall,
   or a frame of latency to the muscle-memory path. `3 → 1 → A` must feel identical whether whimsy is
   on or off. Flourishes ride **idle time** (no input) or **moments that already pause** (connect,
   apply-commit, logout), never the input loop.
2. **Resource-free (brief §8).** No new partition, no audio file, no timer the scheduler must service,
   no PSRAM allocation that competes with RTP. Every effect is a handful of pre-built ANSI strings the
   renderer already knows how to emit (style §6.2 glyph table): bytes, not cycles. Animations reuse
   the **existing ~1 Hz cursor-positioned cell repaint** (style §6.4); they never add a second tick.
3. **80×24 and 16-color, still the floor.** Every flourish fits the existing geometry, has an ASCII
   fallback (brand §3.3), and carries zero meaning in color: strip the SGR and the charm is still
   visible as glyphs, or it harmlessly vanishes without losing information.
4. **Voice stays in character (brand §4).** Operator-terse even when warm. No emoji, no exclamation
   marks in errors, no "oops/whoops", no "click/tap", no vendor names, no invented features. A
   night-shift switchboard operator is *dry*, not zany. Charm is a raised eyebrow, never a wink at the
   user's expense.
5. **Opt-in and remembered.** All non-default whimsy sits behind a single toggle (`§6`), stored in one
   NVS byte. Default ships **Tier-0 only** (the always-on, invisible-cost micro-moments). The louder
   tiers are off until a sysop asks. An installer in a hurry never sees a thing they didn't summon.
6. **Honesty clause holds (brand §6.10).** A flourish may be playful but may never *imply a capability
   we don't ship*. No fake "dialing…" for features that don't exist; no decorative trunk lamps; no
   "queue position 3". Charm decorates real state only.

```
WHIMSY TIERS (what's on by default)
  Tier 0  ALWAYS ON   zero-cost micro-moments — connect beat, register-beep,
                      Apply-thunk, logout sign-off. Indistinguishable from polish. (§1)
  Tier 1  OPT-IN      ambient idle flourishes — lamp shimmer, scanline idle,
                      uptime milestones. Ride existing 1 Hz repaint. (§3)
  Tier 2  EASTER EGG  hidden, summoned by command, self-dismissing. Never discoverable
                      by accident, never on the keystroke path. (§4)
```

## 1. Tier-0 micro-moments (always on; they read as polish, not whimsy)

Three moments in the product **already pause**. The operator is waiting on the box, not the box on
the operator. Tier-0 dresses exactly those pauses. Each is a fixed string (or a ≤3-frame sequence on
the existing 1 Hz tick); none adds a keystroke; all are in voice.

### 1.1 The connect beat: "Patching you through…" earns its keep

`brand.md` §4.4 hands `Patching you through…` to the boot/first-frame. Whimsy's job is to make that
single beat *land* without stalling auth. The PIN prompt is already a pause (the operator is typing);
we use the **one frame** between banner-drawn and PIN-accepted, and we never delay the prompt.

On a correct PIN, in the ~0 ms before the hub paints, one line clears in place:

```
 PIN: ••••••
 Patching you through…  ◆ line is yours.
```

- `Patching you through…` is the sanctioned line (brand §4.4); `◆ line is yours.` is the Tier-0
  charm: operator-terse, telco-literate, a switchboard operator handing you the board. ‹`◆` accent
  lamp + the words carry it; mono `<*> line is yours.`›
- It paints **after** auth succeeds, replacing the PIN echo region, and is overwritten the instant the
  hub draws. Zero added latency: it occupies a frame that was already blank.
- **Wrong PIN** never gets charm. The error stays strictly brand §4.6: `PIN rejected. Try again.`
  Whimsy never decorates a failure (rule §0.4, §0.6).

### 1.2 The register-beep: acknowledging a phone coming online

The brief's reference aesthetic is the "BBS door glow"; the most satisfying retro beat is the
**terminal bell on a real event**. When an extension transitions `○ UNREACH → ● ONLINE` while a sysop
is watching the Monitor or the Event Log, the renderer emits a single `BEL` (`\a`, one byte) paired
with the roster chip already flipping:

```
  103 Lee        ○ UNREACH  →  103 Lee        ● ONLINE   ⟲ registered      ‹BEL on the flip›
```

- The `BEL` is the "register-beep": the operator's board acknowledging a jack lighting up. It rides
  the **registration-change repaint that already happens** (style §6.4); it is not a new event source.
- `⟲ registered` is a transient 1-tick annotation that decays on the next repaint (it does **not**
  persist in the chip; the persistent state is the lexicon `● ONLINE`). Mono: `(o) registered`.
- Strictly rate-limited and gated: at most one `BEL` per second total (a 24-phone power-up storm
  beeps *once*, not 24 times), only when a human is on the Monitor/Event-Log surface, and **muted
  during `[F]` freeze**. A bell during a 3 a.m. unattended session would be noise, not charm, so
  there is no session, no bell. Off entirely in Tier-0-mute (§6) for quiet rooms.
- Honesty: the bell fires only on a **real** SIP REGISTER the firmware accepted, never on a retry,
  never speculatively (rule §0.6).

### 1.3 The Apply-thunk: a satisfying commit acknowledgement

Every modal editor ends in `< Apply >`. Today it closes silently. Tier-0 gives the commit a
**one-line, past-tense, concrete receipt** that flashes in the table's status region for ~1 tick then
settles into the normal headroom line. This is the "register-beep" feeling for config: a mechanical
*thunk* of a lever thrown.

```
  …extensions table…
  ✓ Saved.  6 extensions provisioned (101-106).            ext 18/32      ‹‹✓›=accent, 1 tick›
```

- Copy follows brand §4.2 success tone exactly: *brief, past-tense, concrete*, `Saved. 6 extensions
  provisioned.` The only whimsy is the **`✓` glyph + a single steady beat** before it fades to the
  ambient `ext n/32`. No animation loop, no spinner, no delay before the table is usable again.
- The line is non-blocking: the operator can start the next keystroke immediately; the receipt
  decays on its own on the next 1 Hz repaint. A fast operator never waits for it (rule §0.1).
- Destructive applies (delete, reboot) get the **plain** receipt, no `✓` flourish: `Ring group sales
  deleted. 3 members detached.` Charm is rationed away from consequence (brand §4.2, rule §0.4).

#### The "thunk" ramp (opt-in, Tier-1, see §3)

If a sysop wants the commit to *feel* mechanical, Tier-1 adds a **single** sub-second glyph ramp on
the `< Apply >` button as it commits: a lever throw, drawn on the existing tick, then gone:

```
   < Apply >   →   < ▸pply >   →   < ✓ done >        (3 frames, ~300 ms, then button closes)
```

Mono: `< Apply > → < >pply > → < + done >`. Still no added keystroke; the button was going to close
anyway. Off by default (it costs three repaints the fast path doesn't need).

### 1.4 The logout sign-off: closing the board for the night

`[L]` Logout already closes the SSH session cleanly (logged to the CDR, IA S3). Tier-0 prints one
sign-off line into the dying session, the operator clocking off:

```
  Session closed.  4d 02:19 on the board · logged to CDR.   Board's yours next shift.
```

- Operator-terse, faintly retro, honest (it states the real uptime and the real CDR log). `Board's
  yours next shift.` is the single charm beat, a night-shift hand-off, never cute. ‹all brass; no
  color carries meaning›. Mono is byte-identical (no box glyphs).
- It prints **after** the session-close is committed, so it cannot delay logout. If the transport is
  already gone, the line is simply dropped, never retried, never buffered (rule §0.1).

## 2. Tasteful ANSI flourishes (chrome, not content)

These live in the **decorative chrome** the brand already paints (frames, rails, the nameplate),
where brand §2 already says state is *never* carried, so they degrade perfectly and cost nothing in
meaning. They are drawn once, with the screen, not animated (unless promoted to Tier-1 §3).

### 2.1 The brass corner-rivets: a nameplate detail

The login banner's frame can carry four **rivet** glyphs at the inner corners, a machined-brass
detail that reads instantly as "operator equipment", costs four cells, and vanishes cleanly to ASCII.
This is a *static* flourish (drawn with the banner, brand §3.2), not an animation:

```
 ╔═◦════════════════════════════════════════════════════════════════════════◦═╗
 ║                                                                            ║
 ║   …nameplate logo (brand §2.1, unchanged)…                                 ║
 ║                                                                            ║
 ╚═◦════════════════════════════════════════════════════════════════════════◦═╝
```

- `◦` rivet ‹border/brass›: pure chrome, no state. Mono fallback: `o` (e.g. `+=o===…===o=+`), or
  dropped entirely on `TERM=dumb` with no loss. The nameplate, descriptor, identity block, and the
  `◆ READY` lamp are **untouched**. This is a frame detail, brand-reviewed against §6.1 as decoration
  only. (Banner stays ≤ 78-wide; the rivets sit inside the existing frame, no width added.)

### 2.2 The prompt sigil's "ready" idle: the lamp is alive (Tier-1)

The hub prompt sigil `(◉)─▶` (brand §3.4) is brand chrome. On the hub, while **idle** (no key for
≥ N seconds), Tier-1 lets the jack-dot do a *very* slow two-frame breathe on the existing 1 Hz tick:
the board's pilot lamp, lit and waiting:

```
   (◉)─▶ Select an option: _          ‹breathe›          (◎)─▶ Select an option: _
```

- Two frames only (`◉ ↔ ◎`), swapped at most every few seconds, **only when idle**, and **frozen the
  instant a key is pressed** (so a fast operator's sigil is rock-steady, rule §0.1). It reuses the
  hub's existing headroom/clock repaint; no new tick. Mono: `(o) ↔ (O)`, or static if glyphs absent.
- It is **chrome, not state** (brand §3.4 forbids the sigil signaling anything by color): the breathe
  is monochrome-safe motion, never a color change. Off in Tier-0.

### 2.3 Vitals bars: the "glow" sweep on the live monitor (Tier-1)

The Monitor's vitals bars (style §2.10) already repaint each second. Tier-1 can give the **filled run
only** a one-cell highlight that walks left→right on the existing tick (the "BBS door glow" the brief
names) without changing the authoritative number:

```
  CPU   [██▓███░░░░]  61%        ‹the ▓ is the glow cell, walks the FILLED run each tick›
```

- The numeric label `61%` stays authoritative (style §2.10); the glow is a *reinforcing* shimmer on
  cells that are already being repainted, so it adds **zero** extra writes. It never touches the empty
  run, never changes the fill count, never implies a value. Mono: the `▓` reads as `#` like the rest
  (`[##X###....]` → indistinguishable), i.e. it harmlessly disappears. Frozen under `[F]`.
- Strictly Tier-1: a glowing bar is delightful on an attended wallboard and pointless on an idle one,
  so it is off until summoned.

### 2.4 Theme-toggle flourish: the bench-lamp swap (Tier-0, free)

`T` already swaps BRASS↔PHOSPHOR (style §6.6). Tier-0 lets the footer theme label carry a one-glyph
"lamp" that matches the new accent the instant it flips, reinforcing the bench-lighting metaphor
(brand §5), with a glyph, never hue alone:

```
  … Theme: BRASS ▸ ☼      (press T)      … Theme: PHOSPHOR ▸ ☼      ‹same glyph, accent re-tints›
```

- The `☼` lamp glyph is identical in both themes (it is chrome); only its accent color follows the
  theme. Because the **word** `BRASS`/`PHOSPHOR` is already authoritative (brand §5, "named by
  label, never hue"), the glyph is pure reinforcement and the swap is legible in mono (`* BRASS` /
  `* PHOSPHOR`). This is the one Tier-0 flourish on the keystroke path, and it costs exactly the
  footer rewrite that `T` already does: zero added cost (rule §0.2).

## 3. Tier-1 ambient flourishes (opt-in; ride the existing 1 Hz tick)

Tier-1 is the "I run this board and I like it pretty" tier. Everything here is **off by default**,
rides the repaint the screen already does, freezes under input/`[F]`, and is brand-reviewed as
chrome. Collected for the implementer:

| Flourish | Surface | Cost | Rule it obeys |
|---|---|---|---|
| Sigil breathe `◉↔◎` (§2.2) | Hub, idle only | reuses headroom repaint | freezes on keypress |
| Vitals glow sweep `▓` (§2.3) | Monitor vitals | reuses vitals repaint | freezes on `[F]` |
| Apply-thunk ramp (§1.3) | any modal commit | 3 repaints, button was closing anyway | not on fast path |
| Uptime milestones (§3.1) | Monitor `UP` line | one extra string at a threshold | once, then gone |
| Idle scanline (§3.2) | any screen, deep idle | one rule-line repaint | vanishes on keypress |

### 3.1 Uptime milestones: the operator notices a long shift

The Monitor's `UP 4d 02:17:50` line already ticks. When uptime **crosses** a round milestone, Tier-1
appends a single transient, honest, dry annotation for one repaint, then it's gone:

```
  UP  7d 00:00:01   · one week on the board, no dropped shift.       ‹1 tick, then plain again›
```

- Thresholds are sparse (1d, 7d, 30d, 100d) so it is a rare grace note, not chatter. Copy is honest
  (it *is* the real uptime) and operator-dry: no confetti, no "Congrats". Mono byte-identical.
- It never blocks, never beeps, decays on the next second's repaint. A milestone hit during `[F]`
  freeze is simply skipped (no backlog).

### 3.2 The deep-idle scanline: the board hums to itself

After a long idle (no input for minutes) on any non-live screen, Tier-1 may run a single faint
**scanline** down one of the existing frame rules, a CRT phosphor sweep, on the slow tick, which
vanishes the instant any key is pressed:

```
  ├──────────────────────────────────────────────────────────────────────────────┤
  ├───────────────▒──────────────────────────────────────────────────────────────┤   ‹one ▒ cell, walks the rule, idle only›
  ├──────────────────────────────────────────────────────────────────────────────┤
```

- One cell (`▒`) on an **already-static rule**, repainted slowly, monochrome-safe (mono: it reads as
  part of the `-` rule, i.e. invisible). It touches **chrome only** (a frame rule carries no state),
  never the body, never a live cell. The keystroke path is untouched: first key kills it and repaints
  the clean rule. This is the "screensaver" of a board that is bored, not broken, and it is the most
  opt-in thing in the doc.

## 4. Easter eggs (opt-in, resource-free, never on the keystroke path)

Easter eggs are **summoned, not stumbled into**. None is bound to a single key that could collide with
the typeahead hub or a panel verb (IA §3). Each is a *typed hidden command* at a prompt that already
accepts text, or a deliberate key *sequence*, so a fast operator never triggers one by accident, and
none consumes a real hotkey. All are self-dismissing on `Esc` and cost only pre-built strings.

### 4.1 The hidden command: `:operator` (the night-shift card)

The hub prompt (`Select an option: _`) accepts a single keystroke for `1-6/R/L/T` (typeahead, IA §1).
A leading **colon** `:` shifts it into a tiny hidden command line (the colon is unused by the hub;
no typeahead destination starts with it, so it never collides and never slows the single-key path).
`:operator` ⏎ overlays a dismissible "operator-on-duty" card, pure flavor, real facts:

```
        ┌─ Operator on duty ─────────────────────────────────────┐
        │                                                        │
        │     (◉)  the night-shift switchboard is open.          │   ‹jack mark, chrome›
        │                                                        │
        │   Calls patched this shift .... 47                     │   ‹real CDR count›
        │   Longest hold ................ 11:37  (102 → 106)     │   ‹real CDR fact›
        │   Board uptime ................ 4d 02:19               │   ‹real uptime›
        │   Lamp .......................... BRASS                 │   ‹real theme›
        │                                                        │
        │   "Quiet board. Good board."                           │   ‹the one charm line›
        ├────────────────────────────────────────────────────────┤
        │ [Esc] Back to the board                                │
        └────────────────────────────────────────────────────────┘
```

- **Every number is real** (CDR count, longest talk-time from the ring of 32, true uptime, active
  theme), honesty clause intact (rule §0.6). The only invented bytes are the title and the closing
  line `"Quiet board. Good board."`, operator-dry, in voice (brand §4.1).
- It is a **standard modal** (style §2.8 shell, no `▲ ALERT`), `Esc`-dismissed, drawn over the dimmed
  hub. It costs one overlay render and a CDR read the box already does for Reports. No timer, no loop.
- Discoverability: hinted **only** in the `:` command's own mini-help (`:help` lists `:operator`,
  `:about`, `:theme phosphor`), never on the footer, never in the keystroke hint line. You find it by
  being curious at the prompt, exactly the BBS-sysop spirit.

### 4.2 The `:` command line: a power-user nicety that doubles as the egg surface

The same hidden `:` line gives genuine power users a tiny typed-command affordance without adding
hotkeys (so it earns its place beyond charm):

```
   (◉)─▶ Select an option: :_
         :help            list these commands
         :operator        the night-shift card (§4.1)
         :theme phosphor  set theme by name (same as T, but explicit)
         :theme brass
         :about           jump to [6] ABOUT
         :monitor /:net /:pbx /:sec /:reports   jump like the number keys
```

- This is opt-in and invisible: a sysop who never types `:` never sees it; the single-key
  typeahead (`3 → 1 → A`) is utterly unchanged because no destination begins with `:` (rule §0.1).
- It is resource-free: a tiny string-prefix dispatch over commands that already exist. `:theme
  phosphor` calls the exact `T` path (style §6.6); `:monitor` calls the `1` path. No new capability;
  honesty intact (rule §0.6). `Esc` or `Backspace`-to-empty exits the command line back to typeahead.

### 4.3 The Konami sequence: the "all lamps" self-test (opt-in, harmless)

The classic `↑ ↑ ↓ ↓ ← → ← → b a` sequence, entered **on the hub only**, runs a 2-second, purely
visual lamp self-test: every status glyph in the lexicon lights once across the headroom line,
then the hub repaints clean. It is the board "testing its bulbs", a sysop's wink that also *proves
the glyph table renders* (a genuinely useful side effect):

```
   ● ONLINE  ○ UNREACH  ◐ RINGING  ◆ ACTIVE  ⊘ DND  ↳ FWD  ▲ ALERT  ✓ ✗      ‹2 s, then gone›
   all lamps nominal · BRASS                                                   ‹dry one-liner›
```

- Cannot collide: the sequence is arrow/letter keys that on the hub are otherwise no-ops or, for
  `a`/`b`, lowercase (the hub's real keys are `1-6/R/L/T`, uppercase/digit), so the matcher only ever
  fires on the *exact full sequence* and a single stray arrow does nothing (rule §0.1). It is
  hub-only, never in a panel where arrows mean selection.
- Resource-free and honest: it paints the lexicon glyphs the renderer already has (style §6.2),
  states `all lamps nominal` (true, it just rendered them), touches no config, and self-dismisses.
  The `▲ ALERT` glyph appearing here is clearly a *bulb test*, framed by "all lamps nominal", so it
  never reads as a real alert (rule §0.6). Off in Tier-0-mute.

### 4.4 The `*11` echo-test easter-egg note (firmware-honest cross-link)

`*11` (echo test, IA §6.1) is a **real** firmware feature dialed from a phone. The Features tab
(style §3.9) lists it plainly. The only whimsy permitted here is a single dry line in the **Features
tab `?` help** (not the card itself): *"`*11`: talk to yourself; the board listens."* This is a
switchboard-operator aside that decorates a real feature without inventing one (rule §0.6). It is
help-overlay copy, never on a primary surface, and trivially removable.

## 5. What we deliberately did NOT do (the anti-whimsy list)

Restraint is the brand (brand §4.1: "the chrome is loud, the copy is quiet"). Rejected ideas, and why:

- **No spinners/throbbers on the fast path.** A spinner on `< Apply >` by default would tax the
  keystroke path and the 1 Hz budget for nothing. It was demoted to opt-in Tier-1 (§1.3) at most.
- **No ASCII-art splash between screens.** A transition animation violates "no full clears in steady
  state" (style §6.4) and slows navigation. The only art is the *static* login nameplate (brand §2.1).
- **No "fun" error copy.** Errors stay brand §4.6: blame the input, state the fix, no exclamation, no
  "oops". `Ext 204 already exists. Pick another number.` is the whole personality budget for errors.
- **No emoji, no color-only delight.** Every flourish has a glyph and an ASCII fallback; none means
  anything in hue alone (brief §6, brand §4.5). A color-blind or serial-console sysop sees the same
  board.
- **No fake telephony.** No decorative "trunk", "queue position", "dialing…", or voicemail-blink;
  every banned/unshipped feature stays invisible (brand §6.8, honesty clause). Lamps light on **real**
  registrations and **real** calls only.
- **No unsolicited sound at 3 a.m.** The register-beep is gated to an *attended* session and rate-
  limited (§1.2); an unattended board is silent. Delight that annoys is a defect.
- **No persistent gamification.** No streaks, badges, XP, or "you've provisioned 100 extensions"
  nags. The `:operator` card (§4.1) is *pull*, never *push*: you ask for it; it never interrupts.

## 6. The whimsy toggle (one NVS byte, opt-in, remembered)

All non-default delight is governed by a single setting so a sysop owns the vibe and an installer in a
hurry is never surprised. It lives in `[4]` SECURITY (it is a session/box preference, alongside the
theme metaphor), not a new hub slot (IA conserves the 6-matrix). Three states:

```
        ┌─ Console feel ─────────────────────────────────────────┐
        │  Delight level (cosmetic only — never affects calls):  │
        │     ( ) Off       silent board · Tier-0 muted too      │   ‹quiet rooms / serial›
        │     (•) Standard  Tier-0 micro-moments (default)       │   ‹register-beep, receipts›
        │     ( ) Lively    + Tier-1 ambient (sigil, glow, idle) │   ‹attended wallboard›
        │                                                        │
        │  Easter eggs are always available at the : prompt.     │   ‹§4 — pull, not push›
        │                                                        │
        │              < Apply >        [ Cancel ]               │
        ├────────────────────────────────────────────────────────┤
        │ [↑/↓] Level  [Enter] Apply  [Esc] Cancel  [?] Help     │
        └────────────────────────────────────────────────────────┘
```

- **Default = Standard** (Tier-0): the register-beep, the Apply receipt, the connect beat, the logout
  sign-off, the theme-lamp glyph. These read as *polish*; nobody calls them whimsy.
- **Off** mutes even Tier-0 (no `BEL`, no charm lines), for a silent room, a `TERM=dumb` serial
  console, or a sysop who wants the board stone-faced. The product is **100% functional** at Off.
- **Lively** adds the Tier-1 ambient set (§3) for someone running pocket-dial as a literal wallboard.
- Easter eggs (§4) are independent of the level: they are pull-only (you type `:` or the
  sequence), so they cost nothing until summoned and need no toggle. They honor Off only for the
  *involuntary* beep in the Konami self-test.
- **One byte of NVS**, read once at session start. No per-frame branch on the fast path: the renderer
  resolves the level at connect and picks the string table; the keystroke loop never re-checks it.

## 7. Consistency check (brand §6.1 + brief §6, applied to this file)

```
[x] Name cased correctly: POCKET-DIAL in chrome, pocketdial.local in hosts; no new variants/sub-brands
[x] Every flourish keeps the brand spine intact — title bar / footer / '?' / Esc-back all untouched
[x] Every status still glyph + LABEL; no flourish signals anything by color alone (mono-proofed inline)
[x] Fits 80×24; banner rivets sit inside the ≤78 frame; no flourish adds width or a horizontal scroll
[x] Every added glyph (◦ ◎ ▓ ▒ ☼ ⟲ ✓) has an ASCII fallback or harmlessly vanishes on TERM=dumb
[x] Speed sacred: nothing adds a keystroke/confirm/stall to 3→1→A; flourishes ride idle or existing pauses
[x] Resource-free: no partition/audio/PSRAM/new tick; reuses the existing 1 Hz cursor-repaint only
[x] Voice in character: operator-terse, no emoji, no '!' in errors, no click/tap, no vendor names
[x] Honesty clause: lamps light on REAL registrations/calls only; no fake trunk/queue/dialing/voicemail
[x] Flavor budget respected: brand's two core lines untouched; ALL extra charm is opt-in egg/Tier (§0.5)
[x] Skippable & remembered: one NVS byte (§6); default = Tier-0 polish; Off makes the board stone-faced
[x] Easter eggs are PULL not PUSH (typed ':' / deliberate sequence); never collide with typeahead/verbs
```

*Whimsy Injector · pocket-dial 3.x redesign · the third flavor tier brand §4.4 reserves for this file.*
*Charm lives in the chrome and the corners, never in the keystroke path; every beat is skippable,*
*resource-free, monochrome-safe, and in the voice of a calm night-shift switchboard operator.*
