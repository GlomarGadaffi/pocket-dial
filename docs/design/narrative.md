# pocket-dial: Experiential Narrative (Boot · First-Run · the Live "Glow")

> **Phase-A deliverable (Visual Storyteller).** This file tells the *story* of using pocket-dial
> over SSH: how it feels to connect, how it feels to provision a fresh box, and how the 1 Hz live
> monitor reads as **alive without being noisy**. It is the connective tissue between the locked
> docs; it does **not** re-spec screens. It cross-references:
> [`00-brief.md`](00-brief.md) (constraints), [`brand.md`](brand.md) (voice, banner, flavor budget),
> [`tui-ia.md`](tui-ia.md) (navigation, wizard flow), [`tui-style.md`](tui-style.md) (the exact
> 80×24 mockups, the 16-color mapping, the renderer contract), and the on-device palette in
> `main/ui/ui.cpp` lines 39–64.
>
> What this file owns: the experiential beats and their *timing/motion*. The connect-to-banner-to-hub
> sequence as a felt sequence; the first-run story as a 3-minute narrative arc; and the "glow"
> console concept (motion, focus, restraint) with concrete ANSI cursor-positioning sketches.
>
> Reading the sketches: where a beat is a *motion*, I show the literal escape bytes the renderer
> emits (`ESC` = `0x1B`). These are illustrative of the felt result, consistent with the renderer
> contract in [`tui-style.md §6`](tui-style.md); the mockups there remain the authoritative geometry.

## 0. The character on duty (whose story this is)

Every product has a narrator. Ours is the night-shift switchboard operator: calm, competent,
status-first, telco-literate, faintly retro, **never cute at the user's expense** (brand voice). The
whole experience is staged as *being patched through to a board that is already awake and already
working.* The sysop isn't booting a gadget; they're **relieving the operator at the switchboard.**

Three feelings, in order, are the entire emotional arc, and they map one-to-one onto the three
acts of this document:

| Act | Beat | The feeling we engineer | The line that earns it |
|---|---|---|---|
| **I. Connect** | SSH → banner → hub | *"It was already running. I just walked up to it."* | `◆ READY — operator on duty` |
| **II. First-run** | fresh box → provisioned | *"That was fast, and I always knew where I stood."* | `Patching you through…` |
| **III. Live glow** | the 1 Hz monitor | *"It's alive, calls light up, but it isn't shouting."* | `place a call on any phone to watch it light up` |

The flavor budget is **exactly two sanctioned lines** (brand §4.4): the banner tagline
`operator on duty` and the boot line `Patching you through…`. This narrative spends only those
two. Every other felt beat is carried by *motion, focus, and restraint*, not by extra copy.
That discipline is itself the brand: the chrome glows, the prose stays quiet.

## ACT I: THE CONNECT SEQUENCE (SSH → banner → hub)

### I.1 The story in one paragraph

The sysop types `ssh sysop@pocketdial.local`. There is one held beat, the dark before the lamp,
then the **banner blooms once, whole**, like a switchboard's nameplate lighting up. The `◆ READY`
lamp is already lit: the board didn't wake *for* them, it was **already on duty**. They type the
PIN (never echoed), and the screen doesn't *transition* so much as the operator **steps aside and
hands them the board**. The hub appears with the clock already ticking and the headroom line
already counting live phones. The unmistakable read: *I joined something that was already running.*

### I.2 The beats, with timing and motion

```
  t      EVENT                         WHAT THE SYSOP FEELS                 MOTION
  ────   ───────────────────────────   ──────────────────────────────────   ─────────────────────────
  0.0s   ssh sysop@pocketdial.local    intent — "walk up to the board"      (their keystroke)
  0.0s   TCP + SSH handshake           the held beat — dark before lamp     no output yet
  ~0.3s  sshd capability probe (TERM)  (invisible) picks glyph+color tier   §6.1 renderer contract
  ~0.3s  BANNER prints once, whole     the nameplate lights — ◆ READY      single write, top→bottom
  ~0.3s  login: sysop  /  PIN: _       "it's expecting me"                  cursor parks at PIN
  …      sysop types PIN (silent)      authority, not ceremony              no echo (brand §4.6)
  +0.1s  PIN accepted                  the operator steps aside             clear → paint hub once
  +0.1s  HUB appears, clock LIVE       "I'm holding the board now"          clock + headroom already ⟳
```

The two engineered feelings here are **"already on"** and **"handed over."** Neither needs a word
beyond the banner's sanctioned `operator on duty`.

### I.3 The banner blooms: print discipline (the "already on" feeling)

The banner is the firmware `sshd` greeting locked verbatim in [`brand.md §3.2`](brand.md) and
re-shown in [`tui-style.md §3.1`](tui-style.md). The *story* lives in how it arrives:

- One write, whole. The banner is emitted as a single top-to-bottom block, with no animation and no
  typewriter reveal. A switchboard nameplate doesn't fade up; it's *lit when you look at it.* The
  bloom is the read of the whole frame landing at once.
- The lamp is already lit. `◆ READY — operator on duty` (‹accent + glyph + label›) is in the
  banner the instant it prints. The board is not "starting"; it **was on duty before you connected.**
  This is the single most important beat in Act I and it costs zero motion.
- The runtime fields fill from the box. `«pocketdial.local»`, `«192.168.1.50»`, `«…MAC…»`,
  `«v3.0.0»`, `«up 4d 02:17»` are guillemet slots the firmware substitutes. The uptime line quietly
  proves *"already running for four days,"* reinforcing "already on duty" with a fact, not a flourish.

```
 ╔════════════════════════════════════════════════════════════════════════════╗
 ║   ◖▌  S Y S O P   T E R M I N A L  ▐◗     single-board SIP PBX             ║
 ║ ──────────────────────────────────────────────────────────────────────── ║
 ║   HOST · «pocketdial.local»            ◆ READY — operator on duty          ║   ◀ lamp already lit
 ║   FW   · POCKET-DIAL «v3.0.0»  ·  up «4d 02:17»                            ║   ◀ uptime = quiet proof
 ╚════════════════════════════════════════════════════════════════════════════╝
 login: sysop
 PIN: _                                    ◀ never echoed; cursor parks here, waiting
```

(Full banner + the ≤78-wide frame + ASCII fallback are owned by [`tui-style.md §3.1`](tui-style.md)
and [`brand.md §3`](brand.md); this narrative does not redraw them.)

### I.4 The PIN: authority without ceremony

The PIN is read silently (brand §4.6, *never echoed*). The felt beat is quiet competence: no
"●●●●●●" theater, no progress spinner. On a wrong PIN the operator-terse correction reprints **in
place**: it blames the input, states the fix, no exclamation mark:

```
 PIN: _
 PIN rejected. Try again.                 ◀ in place; the input is wrong, never "you" (brand §4.6)
```

After repeated failures, the back-off notice stays level and factual (e.g. `Too many tries. Wait
30s.`). The operator is firm, not scolding. The emotional contract: **the board trusts you the
moment you prove it; it never performs distrust.**

### I.5 The handover: the cut to the hub (the "handed over" feeling)

This is the one place Act I uses a real screen *clear*. It is justified: we are **changing scenes**,
from front-door to operator's chair. After the cut, the hub
([`tui-style.md §3.2`](tui-style.md)) is painted **once**, and then *only the live cells move*. The
clock and the headroom line are already ⟳ ticking, so the very first frame of the hub already feels
*inhabited*, not loaded.

```
  PIN accepted
    │
    ├─ ESC[2J ESC[H            ◀ the ONE justified full clear: scene change, front-door → chair
    ├─ paint hub frame + menu  ◀ static chrome, written once
    └─ start ⟳ loop:           ◀ from now on, NOTHING full-clears in steady state (brief §6)
         ESC[1;69H "18:14:22"            ◀ clock cell, repainted each second
         ESC[9;5H  "● 4 ONLINE  ○ 1 …"   ◀ headroom line, repainted on change
```

The narrative payoff: the hub's clock is **already advancing** and the headroom already reads
`● 4 ONLINE ○ 1 UNREACH · 1/8 calls · ext 12/32` the instant it appears. The sysop didn't open a
dead menu; they **took a live seat.** Esc is a no-op here (this is home); the story has no "back"
because there is nothing behind the operator's chair.

### I.6 Why this sequence carries the brand

- **"Already on duty"** is a *timing* decision (banner blooms whole, lamp pre-lit, uptime shown), not
  a copy decision. It honors the flavor budget.
- **The single justified clear** (I.5) is the only full-screen wipe the whole product allows itself
  outside of `Ctrl-L`; everywhere else is cursor-positioned cell repaint (renderer contract §6.4).
  Restraint with the clear *is* the embedded-reality story.
- **Theme is invisible to this act.** Whether BRASS or PHOSPHOR, the banner blooms identically; only
  the lamp's hue differs, and the footer names the theme by label downstream. The bench lighting is
  set; the board is the same board.

## ACT II: THE FIRST-RUN STORY (a fresh box, provisioned in ~3 minutes)

### II.1 The story in one paragraph

A brand-new pocket-dial has no PIN, no extensions, nothing behind the front door. So the first
connection doesn't drop you into the hub. The operator says, literally, **`Patching you through…`**,
and walks you through five steps in about three minutes: get on the network, set the master PIN,
name the admin extension, **provision a whole block of phones in one keypress**, and take a handoff
card. The arc is *empty → equipped → proven*. The closing beat isn't "Finish"; it's **"now place a
call and watch it light up,"** so the installer's last act is **proof, not hope.**

### II.2 The arc (the dot rail IS the story spine)

The wizard's `[n/5]` + dot rail ([`tui-style.md §2.11`](tui-style.md)) is not just a progress
widget; it's the **visible spine of the narrative.** Each filled dot is a beat completed; the
sysop always knows *which act they're in* and *how many remain.* The rail is the operator's promise
("five steps, about three minutes") rendered as a glyph the eye tracks left-to-right.

```
  [0/5]  ◍──○──○──○──○     WELCOME            "Patching you through…"  — the curtain up
  [1/5]  ●──◍──○──○──○     net                get on the network
  [2/5]  ●──●──◍──○──○     PIN                lock the front door
  [3/5]  ●──●──●──◍──○     admin              name the operator's own phone
  [4/5]  ●──●──●──●──◍     ext   ◀ MARQUEE    provision the whole block in one pass
  [5/5]  ●──●──●──●──●     DONE               handoff card → "go watch it ring"
   done=● accent · current=◍ bright · todo=○ dim · [n/5] numeric label is authoritative
```

The exact step screens are owned by [`tui-style.md §4.0–4.5`](tui-style.md). This narrative tells
**how each beat is meant to *feel*,** and where the emotional weight sits.

### II.3 Step-by-step: the felt beats

**`[0/5]` Welcome, the curtain up.** The screen leads with the sanctioned boot line:

```
   Patching you through…
   This is a fresh pocket-dial. We'll set it up over the next five steps —
   network, admin PIN, the admin extension, your first extensions, and a
   handoff card. About 3 minutes.
   Esc backs out a step; your work is saved as you go. If the session drops,
   reconnect and you'll resume right where you left off.
```

The feeling: **a competent guide, not a setup wizard.** Two reassurances are load-bearing: *"about
3 minutes"* (bounded effort) and *"your work is saved … resume right where you left off"* (an SSH
session over a flaky office Wi-Fi *will* drop; the operator promises the work survives it). This is
the honesty clause as comfort: the box names its own fragility and covers for it.

**`[1/5]` Network, the one consequential fork.** Join-my-network vs. standalone-hotspot is the only
branch in the story, and the screen pairs each radio with its plain-language consequence
(`Wi-Fi client, gets an IP by DHCP` / `SoftAP, phones join pocket-dial directly`). The felt beat:
**a decision made with eyes open**, not a toggle whose meaning you discover later.

**`[2/5]` PIN, locking the front door.** Entered twice, never echoed, with a `Strength: ●●●○○ fair`
meter whose **word** is authoritative (color is the removable layer). The reassuring fact,
*"salted 50,000-round SHA-256, computed on the box … never written to flash,"* is the honesty
clause turned into trust: the operator tells you exactly what it does with your secret.

**`[3/5]` Admin extension, the operator's own phone.** This is the extension that *owns the box* and
gets the DTMF `*PIN#code` menu. Felt beat: **claiming the chair.** It quietly becomes the first
roster entry, so by the end of step 3 the board already has one real phone on it.

**`[4/5]` First extensions, THE MARQUEE BEAT.** This is the emotional and demonstrational peak of
the entire product (the owner's north-star: *"3→1→A … three seconds flat"*). The installer types a
range, `101-124`, picks a PIN policy, optionally drops them all in a ring group, and provisions
**twenty-four phones with one keypress.** The screen earns its drama with a **predictive cap line**
that updates as you widen the range:

```
   Range ......... [ 101-124      ]   = 24 extensions
   Pool after this:  25/32 — OK
   ┄ widen the range past the cap and this flips to:  37/32 ⚠ EXCEEDS CAP   ◀ BEFORE you apply
```

The felt beat is **mastery without anxiety.** The "wow" is the single keypress that creates a block;
the *trust* is that the box told you `⚠ EXCEEDS CAP` *before* you hit a 503, so you trim the range
instead of meeting a wall. Speed and honesty in the same frame: this is the screen the demo opens on.

**`[5/5]` Done, the handoff that closes on proof.** The lamp lights: `◆ READY — operator on duty`
(the banner tagline returns, closing the loop). The card splits the world into **what the day-2 admin
can touch** vs. **what's guarded**, so the installer hands over a box whose blast radius is already
explained. And the last instruction is the whole thesis of the redesign:

```
   Next: press Finish, then [1] Monitor, place a call, watch it light up.
```

`< Finish >` drops into the hub with `[1] MONITOR` one keystroke away. **The handoff closes on proof,
not hope**: the installer's acceptance test is built into the last frame of onboarding: ring a
phone, see it light up the matrix. Act II ends by pointing straight at Act III.

### II.4 The motion of resumability (the felt safety net)

The "your work is saved" promise is a *motion* story, not just copy. When a dropped SSH session
reconnects, the operator doesn't restart the curtain. It **re-paints the step you were on**, dots
intact:

```
  (session drops mid-[3/5])
    reconnect → banner → PIN
    │
    └─ NO "[0/5] Welcome" replay        ◀ the story doesn't rewind
       paint [3/5] admin, dot rail ●──●──●──◍──○ restored, fields you'd filled still present
```

Felt beat: **the operator remembered where we were.** This is the single most reassuring motion in
Act II and it is invisible until you need it, which is exactly when it matters most.

## ACT III: THE LIVE "GLOW" CONSOLE (how the 1 Hz monitor feels alive)

### III.1 The concept in one paragraph

The System Monitor ([`tui-style.md §3.3`](tui-style.md)) is the soul of the retro aesthetic: the
**"BBS-door glow."** It must feel *alive*: calls light up, durations tick, a phone rings and you see
it. But it runs on an **ESP32-S3 over SSH at 1 Hz**, so "alive" cannot mean "busy." The design rule
is three words, motion, focus, restraint, and the craft is making *one cell changing per second*
read as a living switchboard rather than a frozen table. The glow is **earned by what *doesn't* move.**

### III.2 The three principles, made concrete

#### MOTION: only the live things move, and they move *in place*

The screen is split into **static chrome** (frame, headers, labels, roster names) and **`⟳ live`
cells** (clock, the per-call DUR/STATUS, vitals bars, the `UP` clock). Every second, the renderer
**cursor-positions to each live cell and overwrites just that span**, never a row tint, never a
clear (renderer contract §6.4). The eye is drawn to the handful of glyphs that change because
*everything around them is rock-steady.*

```
  ── the ⟳ loop, once per second (ESC = 0x1B) ───────────────────────────────────
  ESC[1;69H  "18:14:25"                       ◀ title-bar clock cell
  ESC[7;33H  "02:14"                           ◀ CH1 DUR — ticks; only these 5 bytes change
  ESC[7;43H  "◆ ACTIVE"                        ◀ CH1 STATUS chip (steady while up)
  ESC[8;43H  "◐ RINGING"                       ◀ CH2 STATUS — the call that just came in
  ESC[16;57H "[██████░░░░] 61%"                ◀ CPU vitals bar
  ESC[18;57H "4d 02:17:50"                     ◀ UP clock
  (no ESC[2J anywhere — steady state never full-clears)
```

The felt result: a phone rings somewhere in the office and **`◐ RINGING` appears on channel 2**
while channel 1's duration **counts up**, two tiny motions on an otherwise still board. That
stillness is what makes the two motions read as *a switchboard catching a call*, not a UI refreshing.

#### FOCUS: the live-call matrix is the hero; everything else is context

Reading order is engineered top-down: **LIVE CALLS** matrix first (the hero), then the **ROSTER**
(who's reachable), then **VITALS** (the box's pulse). The hottest information, *a call is happening
right now*, sits at the top where the eye lands, and the `◆ ACTIVE` / `◐ RINGING` lamps are the only
accent-colored glyphs in motion, so **color literally follows the live call down the matrix.**

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  LIVE CALLS                                       1/8 active   ·  ⟳ 1 Hz     │   ◀ HERO — eye lands here
│   1  101   → 102            02:14   PCMU   ◆ ACTIVE            ◀ accent lamp, ticking DUR
│   2  104   → grp:sales      00:07   PCMU   ◐ RINGING          ◀ the call that just lit up
│   3   —    —                  —       —    ○ idle             ◀ dim; restful, not empty-scary
│  ROSTER   ● 4 ONLINE  ○ 1 UNREACH                VITALS       │   ◀ context, below the hero
│  Patching you through…   place a call on any phone to watch it light up.     │   ◀ the invitation
└──────────────────────────────────────────────────────────────────────────────┘
```

The `Patching you through…` line does double duty: it's the sanctioned boot flavor *and* the
M4 ring-test hint, *place a call, watch it light up.* On a fresh-from-onboarding board with no
calls yet, this line is the **invitation to prove the box works**, turning an empty matrix from a
dead screen into *a board waiting for its first call.* (Idle channels read `○ idle` ‹dim›, not red,
quiet, not alarmed.)

#### RESTRAINT: the glow is in what *holds still*

The hardest part of "alive" is **not over-animating.** Restraint is enforced four ways:

1. **1 Hz, hard.** No sub-second flicker; durations tick on whole seconds. A board that updated 10×/s
   would read as *anxious*, not alive, and would hammer the PTY. One beat per second is a **pulse.**
2. **`[F] Freeze`: the operator can stop time.** Pressing `F` halts every ⟳ write; the badge flips
   `⟳ 1 Hz → ❚❚ FROZEN` ‹dim› so the sysop can read a torn matrix without it sliding under them. The
   *label* announces the freeze; the motion stopping confirms it. This is restraint as a **feature.**
3. **`[C] Clear`: stale rows decay, they don't vanish.** A torn-down call lingers as `· stale`
   until the sysop clears it (IA §3.6), so a call that *just ended* doesn't blink out of existence
   mid-glance. History fades on the operator's command, never under their eyes.
4. **`Ctrl-L` is the only full repaint.** Reserved for serial-console line-noise recovery (renderer
   contract §6.4). In normal operation the board **never** wipes itself; the glow's steadiness *is*
   the absence of clears.

### III.3 The "alive" moment, frame by frame

The signature beat, *a call comes in and you watch it land*, across three one-second frames. Only
the marked cells are rewritten; everything else is byte-identical from frame to frame:

```
  FRAME @ 18:14:25                              FRAME @ 18:14:26                 Δ
  ──────────────────────────────────────        ────────────────────────         ───────────────
   1  101 → 102      02:14  PCMU  ◆ ACTIVE        1 101 → 102  02:15 … ◆ ACTIVE    DUR 02:14→02:15
   2  104 → grp:sales 00:07 PCMU  ◐ RINGING       2 104 → 105   00:00 … ◆ ACTIVE   RINGING→ANSWERED
   3   —   —            —     —    ○ idle          3  —   —        —    —  ○ idle    (unchanged)
  ── 18:14:25 → :26: CH1 DUR +1s; CH2 hunt-group picks ext 105, RINGING → ACTIVE, DUR resets ──
```

The story the sysop reads in two seconds: *channel 1 keeps talking; the call that was ringing the
sales group just got answered, by extension 105, and started its own clock.* No notification, no
sound, no toast. **The board simply showed them the truth, one cell at a time.** That is the glow.

### III.4 The wallboard echo (the screen tells the same story, passively)

The on-device 3.5" display is now a **passive wallboard** (brief §6): it shows the same live read
with no input. The two surfaces tell **one story in two registers:** the sysop's SSH monitor is the
*operator's console* (interactive, deep), the wall display is the *room's glance* (ambient, shallow).
Both glow on the same 1 Hz pulse, both pair glyph+label so a color-blind glance or a monochrome
serial console loses nothing. The brand promise, *operator on duty*, is legible from across the
room and from inside the terminal, simultaneously.

## 4. The brand thread, pulled through all three acts

Every beat above is traceable to a locked rule. The narrative invents no new voice, only sequences
the existing one:

```
[x] Flavor budget = exactly two lines: "operator on duty" (Act I banner, Act II handoff) and
    "Patching you through…" (Act II curtain, Act III ring-test invite). NOTHING else spends flavor.
[x] State is never color alone — every felt beat (◆ ACTIVE, ◐ RINGING, ⚠ EXCEEDS CAP, ●●●○○ fair)
    pairs glyph + LABEL; the motion/label carries the story, color is the removable third layer.
[x] Embedded reality is a STORY beat, not just a constraint: the single justified clear (I.5), the
    1 Hz pulse, [F] Freeze, decaying-not-vanishing stale rows — restraint is the glow.
[x] Voice = calm night-shift operator: "already on duty," "patched through," "watch it light up,"
    errors that blame the input ("PIN rejected. Try again."), honesty as comfort ("work is saved").
[x] One name, three casings: POCKET-DIAL (banner), pocketdial.local (host), pocket-dial (prose).
[x] Theme is bench-lighting only — Act I/II/III feel identical under BRASS or PHOSPHOR; the lamp's
    hue changes, the story does not; the footer names the active theme by label, never by hue.
[x] The arc closes on proof, not hope: onboarding's last frame points at the monitor; the monitor's
    idle line invites the first call. Act II hands off directly into Act III.
```

*Visual Storyteller · pocket-dial 3.x redesign · the experiential narrative for boot, first-run, and*
*the live glow. Sequences the voice locked in [`brand.md`](brand.md), the flow in [`tui-ia.md`](tui-ia.md),*
*and the exact geometry/motion contract in [`tui-style.md`](tui-style.md). Constraints per [`00-brief.md`](00-brief.md).*
