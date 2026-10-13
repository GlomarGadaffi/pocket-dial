# pocket-dial: Cognitive Walkthrough & Prioritized Friction Log (SSH Sysop Terminal)

This file runs a qualitative cognitive walkthrough of the SSH-first onboarding wizard (Rivera, the installer) and one day-2 task (Dana, the admin): *"create a 3-member ring group and point the front desk extension at it."* It stays consistent with [`00-brief.md`](00-brief.md), [`personas.md`](personas.md) (Rivera and Dana, Task Inventory §3), [`tui-ia.md`](tui-ia.md) (hub, screen tree, keys, wizard), and [`tui-style.md`](tui-style.md) (the ANSI mockups this walkthrough steps through).

The method is the classic Lewis & Wharton four-question cognitive walkthrough, run per step: **(1)** will the user try to achieve the right effect? **(2)** Will they notice the action is available? **(3)** Will they associate the action with the effect? **(4)** Will they see progress after acting? Each step also logs the **persona's inner monologue** (raw, first-person, no UX jargon) and an **analyst note** that maps the friction to a framework principle (LIFT factor, Fogg M·A·P, or Cialdini) and to a fix the IA/UI should adopt.

This is a qualitative simulation, not statistical evidence: n=0 live users, and the box is pre-launch. Findings are strong hypotheses to validate, not proven facts. `personas.md` §6 lists the 5-user test that turns these into measurements; this doc is that test's cheap first pass. Confidence is **high** where the friction is structural (a missing screen, or an ambiguous label that the IA itself flags as open) and **medium** where it is emotional framing.

## 0. Walkthrough setup: the two cognitive profiles

| | **Rivera** (Installer) | **Dana** (Day-2 Admin) |
|---|---|---|
| Mental model | "Terminal-native. I chain keys from muscle memory. Don't make me read." | "Web-app fluent, terminal-terrified. I follow on-screen prompts and the footer." |
| Decision style | Quick decider; trusts the box if basics are met | Extensive checker; needs visible confirmation each step |
| Attachment tendency | Secure-with-deadline (forgiving *if* it's fast) | **Anxious** (needs reassurance at every step; fears breaking the phones) |
| Primary fear | Burning site-time; leaving a fault behind that becomes a callback | Touching the wrong thing and killing everyone's phones, visibly, her fault |
| Trust triggers | Real registration state; a ring test that lights up | Plain-language labels; "this confirms before it does anything"; one-Esc undo |
| Success | Unbox → provisioned → ring test passes → clean handoff → back in the van | Named task done, *seen to be done*, nothing else changed |
| Contact threshold | n/a (no contact; this is the tool) | Would abandon to "call the installer" the moment she feels lost with no `?` answer |

Two device contexts assumed per the brief: Rivera on a rugged laptop (PuTTY/OpenSSH over the
SoftAP or Ethernet); Dana on an office laptop with a PuTTY desktop shortcut Rivera left, reaching
`pocketdial.local`. Minimum geometry **80×24**, **BRASS** default theme.

## Part A: INSTALLER ONBOARDING (Rivera, O1–O6 + the ring-test)

The acceptance criterion for the whole flow is the brief's own: it must replace
`gen_provision_nvs.py` + `nvs_partition_gen.py` + `esptool write_flash 0x9000` end-to-end over SSH
in one sitting (D5), and end in evidence: a ring test that lights up the live matrix (D4/M4).

### Pre-arrival (Phase 0): the relevance contract

> **Rivera (monologue):** "Eleven boxes on the van. I plug into this one, SSH to whatever it answers
> on, and I want a config surface in seconds, not a Python script, not a flash ritual like last
> time. If I have to open a manual on a customer site I've already lost."

Relevance contract: within ~10 s of connect, Rivera must see (a) that he's reached the right
box, (b) that it's *unconfigured and wants setup* (not a dead prompt), and (c) the first action.
The banner (`tui-style.md` §3.1) + forced wizard (§4) is the delivery vehicle.

### Step A1: SSH connect → banner → PIN  (O1; `tui-style.md` §3.1)

Sees: the ASCII nameplate banner, `HOST · pocketdial.local`, `◆ READY — operator on duty`,
`login: sysop`, `PIN: ` (never echoed).

**Q1 right effect?** Yes: Rivera wants in; the banner says he's at the right box.
**Q2 notice the action?** Yes: `login:`/`PIN:` are unambiguous.
**Q3 associate action→effect?** Partially. **On a factory-fresh box, what credential?** The banner says "Authorized sysops only," and the wizard's PIN step (`[2/5]`) is where the DTMF admin PIN is set. The firmware ships a default web login, `admin` / `admin`, that is enforced until changed (`src/Helpers/AdminAuth.hpp`), but the front door as drawn never names it, and the DTMF admin PIN has no default. So at the very first connect the prompt asks for a secret whose value is not stated.

> **Rivera (monologue):** "It's asking me for a PIN. I haven't *set* a PIN, this is box number one
> out of the carton. Is it a default? Is it printed on a sticker? Is it blank-and-press-enter? I'm
> not seeing it told to me, and I'm not going to guess three times and get locked out on site."

Analyst note: friction (high). LIFT:Anxiety↑, Clarity↓. The IA (`tui-ia.md` §2) shows `PIN PROMPT → O2/S1 verify` *before* `FIRST-RUN WIZARD`, but the wizard is where the DTMF admin PIN is *born* (`[2/5]`). The first-boot front door therefore asks for a secret with no stated value. The only credential that exists before setup is the shipped default web login, and the mockups never show the *un-provisioned* banner state. Fogg: Ability↓ (the prompt blocks with no satisfiable input as drawn). This is the single biggest gate on the installer's "first 10 seconds."

Fix (the IA/UI should adopt): the setup card should state the shipped default login (`admin` / `admin`, changed on first use) in `imagery.md`'s QR/setup card, so Rivera isn't guessing. The banner should say the box is unprovisioned, for example `◆ READY — UNPROVISIONED · first SSH session starts setup`. On first use the session changes the default login before any other admin action, because `AdminAuth` refuses every other admin action until the default is replaced. The DTMF admin PIN is then set in `[2/5]`, as now.

### Step A2: `[0/5]` Welcome / "Patching you through…"  (`tui-style.md` §4.0)

Sees: `STEP [0/5]` + dot rail `◍──○──○──○──○`, "Patching you through…", the 5-step preview,
"Esc backs out a step; your work is saved," `< Begin >`, footer `[Enter] Begin  [?] Help`.

Q1–Q4: yes on all four. This screen is excellent for the installer: it *names the whole arc* (network,
PIN, admin ext, extensions, handoff), sets a time budget ("~3 min"), and pre-answers the resume
question. The dot rail + `[n/5]` give a progress promise before any work.

> **Rivera (monologue):** "Five steps, three minutes, resumable if my SSH drops. Good, that's the
> whole ritual replaced right there. `< Begin >`."

Analyst note: strength. LIFT:Clarity↑, Anxiety↓. Cialdini:Commitment: the numbered rail is a
small-yes ladder; seeing `[0/5]` of a *finite* `5` makes the whole job feel bounded. Fogg: a clean
Spark (motivation is already high; the screen just lowers perceived effort). Keep verbatim.

Minor (low): the `[?] Help` is offered but a confident installer won't press it; fine. The one
thing missing is a "**~3 min** assumes you know your Wi-Fi SSID/passphrase and your extension
range" pre-flight nudge, so Rivera gathers credentials before step 1 rather than stalling on it.

### Step A3: `[1/5]` Network mode  (O3/O4; `tui-style.md` §4.1)

Sees: radios `(•) Join my network` / `( ) Standalone hotspot`, `SSID [office-wifi]`,
`Passphrase [••••]`, `Reachable as: pocketdial.local · IP assigned after join`, `< Next > [ Back ]`,
footer `[Tab] Field [Space] Pick [Enter] Next [Esc] Back`.

**Q1 right effect?** Yes: network-first is the correct order.
**Q2 notice?** Yes: radios are glyph-paired.
**Q3 associate?** Partially. Two real installer snags:

1. **The default is `(•) Join my network`, but Rivera is connected over the SoftAP** to *do* this
   setup. If he picks "Join my network," types the office SSID, and the box switches to client
   mode, **his SoftAP link drops and the SSH session dies mid-wizard.** The screen says "IP assigned
   after join" but never warns "you will lose this connection; reconnect at `pocketdial.local`."

   > **Rivera (monologue):** "Wait, I'm *on* the hotspot right now. If I flip it to client mode, do
   > I lose this session? Does it come back on `pocketdial.local` on the office LAN, or do I have to
   > go re-find it? The screen doesn't tell me what happens to *me*."

2. **No "test / did it actually join?" feedback.** "IP assigned after join" is a promise, not a
   confirmation. The installer's whole ethos (`personas.md` JTBD) is *prove it on-site*. If the
   passphrase is wrong, when does he find out: here, or three steps later when nothing registers?

Analyst note: friction (high for #1, medium for #2). LIFT:Anxiety↑ (#1 is a session-suicide
risk), Clarity↓. The resumability promise from `[0/5]` *partly* saves #1 (reconnect resumes), but
only if Rivera knows where to reconnect. Fogg: Ability↓: a correct action (join the LAN) has a
hidden catastrophic side effect (lose the pipe you're operating through).

Fix: (a) When "Join my network" is chosen **while connected over SoftAP**, show an inline
consequence line *before* `< Next >`: `↳ This drops your hotspot link. Reconnect at
pocketdial.local (or the new IP shown on the wallboard).` Pair it with the `↳` glyph, not color.
(b) Add a post-join confirmation beat: after Enter, show `Joining office-wifi… ● LINK UP ·
192.168.1.50` (or `▲ join failed — check passphrase`) *before* advancing to `[2/5]`, so a bad
passphrase fails *here*, at the cheapest possible moment, not at the ring test. This makes O4
("confirm reachable identity") a *verified* fact, not a printed hope.

### Step A4: `[2/5]` Admin PIN  (O2; `tui-style.md` §4.2)

Sees: `PIN [••••••]`, `Confirm [••••••]`, `Strength: ●●●○○ fair — longer is stronger`, the
"salted 50,000-round SHA-256, computed on the box… never written to flash" reassurance, `< Next >`.

Q1–Q4: yes on all four, and this is a **standout strength for the installer persona specifically**.

> **Rivera (monologue):** "*This* is the line I came for: 'salted 50,000-round SHA-256, computed on
> the box.' That's the exact hash I used to compute by hand in that Python script and flash to
> 0x9000. It's doing it for me, on the box, over SSH. That's the whole reason this redesign exists."

Analyst note: strength (the redesign's thesis, made visible). Cialdini:Authority: naming the
real algorithm signals competence to a terminal-native who'd otherwise distrust a "wizard." LIFT:
Anxiety↓ for the security-conscious installer. The strength meter pairs `●●●○○` with the word
"fair" (never color alone, good, consistent with D11).

Minor (low): the strength meter says "longer is stronger," and the field hints in `tui-style.md` §3.10.1 and §4.2 say "4–16 digits," matching the DTMF admin PIN range (`src/Helpers/AdminAuth.hpp`: `kMinDtmfPinLength` = 4, `kMaxDtmfPinLength` = 16). Not a blocker, but the `[?]` help here should state the policy plainly so Rivera doesn't fight the field. The digits-only charset is enforced by `dtmfPinValid` in `src/Helpers/AdminAuth.cpp`, which is the charset the `*<PIN>#` DTMF menu needs.

### Step A5: `[3/5]` Admin extension  (`tui-style.md` §4.3)

Sees: `Number [100]`, `Name [Operator]`, `PIN [••••]` ("the SIP register PIN for this phone"),
the note "This phone can dial `*PIN#001` (resync clock) and `*PIN#101` (network mode)."

**Q1 right effect?** Yes.
**Q2 notice?** Yes.
**Q3 associate?** Partially. **Two PINs, two paragraphs apart, both called "PIN."** Step `[2/5]` set the
*master/admin* PIN (gates SSH + the DTMF admin menu). Step `[3/5]` now asks for a *different* PIN,
the SIP register secret for extension 100. A terminal-native will parse it; but even Rivera has to
stop and re-read to be sure he's not re-entering the master PIN.

> **Rivera (monologue):** "PIN again? … no, *this* one's the SIP register PIN for the phone on
> desk 100. Different thing from the admin PIN I just set. OK. Mild trap, but I see it."

Analyst note: friction (medium). LIFT:Clarity↓. The collision is a label problem: "PIN" means
two different secrets in adjacent steps. Fogg: a small Ability tax (re-read to disambiguate).

Fix: rename per scope. `[2/5]` field becomes **"Master PIN"** (or "Admin login PIN"); `[3/5]` field becomes
**"Extension PIN"** / "SIP register PIN." The IA already distinguishes them conceptually; the
*labels* should carry that distinction so no one conflates the box's master credential with a
phone's registration secret. (This same collision recurs in the Add-single modal `tui-style.md`
§3.5.2 and the Forward editor; standardize the term "Extension PIN" everywhere a SIP secret is set.)

### Step A6: `[4/5]` First extensions (the marquee batch)  (O5/E3/E6; `tui-style.md` §4.4)

Sees: `Range [101-124] = 24 extensions`, `PIN policy (•) Random per-ext ( ) Same PIN ( ) Match
number`, `Add all to [sales ▾] ring group (optional)`, `Pool after this: 25/32 — OK`, the predictive
over-cap line, `< Provision block > [ Back ]`.

Q1–Q4: yes on all four for the **batch** itself. This is the highest-impact screen in the product and
it lands. One range field, one keypress, 24 phones; the cap is **predictive** (`25/32 — OK` flips to
`37/32 ⚠ EXCEEDS CAP` *before* apply). This is exactly D2/D12, and it is the single thing that turns
the afternoon-long `gen_provision_nvs.py` ritual into seconds.

> **Rivera (monologue):** "`101-124`, random PINs, done, one keypress for the whole block, and it's
> already telling me 25 of 32 before I commit. This is the part that earns the redesign. *This* is
> 'three seconds flat.'"

But two real-job snags:

1. **`Add all to [sales ▾]` references a group that doesn't exist yet.** On a fresh box there are
   **zero ring groups**; the wizard never created one. The `▾` picker on a virgin box is empty (or
   shows a phantom "sales" placeholder copied from the mockup). An installer who *wants* the new
   block in a group has to either skip it here and build the group later (`[3]→Ring Groups→Add`,
   Part B below) or the field has to offer **"+ new group…"** inline. As drawn, it implies a group
   exists when none does.

   > **Rivera (monologue):** "'Add all to sales,' there *is* no sales group, this box is empty. Is
   > it going to *make* one? Or is this dropdown just empty and I move on? If I want these 24 in a
   > pod I guess I do it after."

2. **Where's the PINs output?** "Random per-ext" is the right default for security, but the
   installer has to **hand every phone its PIN** to register it. If the PINs are random and never
   shown/exported, Rivera can't provision the actual handsets. The handoff card (`[5/5]`) shows
   "EXT 24 (101-124)" but **no credentials list**, and there's no SD card / file export (brief).

   > **Rivera (monologue):** "Random PINs, great, but I have to type each phone's PIN *into each
   > phone*. Where do I read 24 random PINs? If they're only in the box and never shown, I've got 24
   > dead handsets and no way to register them."

Analyst note: friction (high for #2, medium for #1). #2 is a **task-completion blocker**, not
cosmetic: O5's success condition is "extensions provisioned" but provisioning a *phone* needs its
PIN, and the redesign deliberately removed the file-based flow (no SD, no CSV export). LIFT:
Anxiety↑↑ (Rivera can't finish the job), Fogg: Ability↓ (the prompt to register a phone has no
discoverable credential). #1 is a Clarity/Relevance gap (a control referencing a not-yet-existing
object).

Fix:
- **#2 (must-fix):** make "Match number" PIN policy the *prominent, recommended* default for fast
  provisioning, since it gives a known, derivable secret per phone with no list to carry, and when
  "Random per-ext" is chosen, the **handoff card (`[5/5]`) must render the per-extension PIN list
  on-screen** (it's read once, over the operator's own authenticated SSH session, then never shown
  again, same trust model as the master PIN message). Optionally print to the SSH scrollback so
  PuTTY's "copy all" captures it. Without *some* path from "random PIN" to "the installer can read
  it once," the random option is unusable on-site.
- #1: the `Add all to [ … ▾]` picker should offer **`( ) none` (default) / `+ create group "…"`**
  on a box with no groups, so it never implies a phantom group. Better: drop the optional-group
  field from the wizard entirely (groups are Dana's day-2 surface; keep the wizard linear) and let
  Part B own group creation.

### Step A7: `[5/5]` Done · handoff card  (O6; `tui-style.md` §4.5)

Sees: `◆ READY — operator on duty`, the card (HOST/ADDR/ADMIN PIN ● SET/EXT counts), "Admin can
touch: …" vs "Guarded (confirms): …", "Next: press Finish, then [1] Monitor, place a call, watch it
light up," `< Finish >`.

Q1–Q4: yes on all four, a strong close. It tees up the **ring test** as the literal next keystroke (D4),
and it *scopes Dana's authority in plain words*, which is exactly the anxious-admin reassurance
Part B will need. Naming "Guarded (confirms): network mode · delete · reboot · factory reset" is a
small-but-real trust gift to the installer (he can tell Dana "you can't break it") and to Dana.

> **Rivera (monologue):** "Card's all here, host, IP, PIN set, 24 extensions, and a one-line
> 'what Dana can/can't touch.' Finish, hit `1`, ring a desk phone, watch it light the matrix. If it
> lights, I'm back in the van."

Analyst note: strength. Cialdini:Authority + Commitment; LIFT:Clarity↑, Anxiety↓ for *both*
personas (it pre-writes the handoff script). The **only** gap is the one inherited from A6: the card
shows extension *counts* but, for "Random per-ext," **no credentials**, so the card is the natural
home for the PIN list fix above. Also: the card is ephemeral (SSH screen). A line like "↳ screenshot
or copy this card now, it isn't stored" would match the installer's "evidence, not hope" need and
pairs with the QR/setup-card in `imagery.md`.

### Step A8: The ring test  (M4; `tui-style.md` §3.3, hub §3.2)

Sees: Finish → hub → `1` → `[ MONITOR ]`: the live-call matrix, `ROSTER ● ONLINE/○ UNREACH`,
vitals, and the flavor line "Patching you through… place a call on any phone to watch it light up."

Q1–Q4: yes on all four; this is the acceptance test done right. Rivera places a call; CH 1 flips to
`◆ ACTIVE`, the roster dot for the calling ext shows `● ONLINE`. *Evidence.*

> **Rivera (monologue):** "There it is: channel 1, `◆ ACTIVE`, ext 101 online. It works. Done.
> Hand Dana the card, tell her [1] is 'is it OK?' and [5] is 'why didn't it ring?'. Van."

Analyst note: strength (closes the loop the brief demanded). D4 satisfied. **One residual
friction (medium):** the monitor only proves the *one phone Rivera tested* is online. With 24
provisioned and random PINs (A6/#2), the roster will show a wall of `○ UNREACH` until each handset
is registered with its PIN, which loops straight back to "where do I read the PINs?" The ring test
*surfaces* the A6 gap rather than causing it, but it's where Rivera will *feel* it: "23 phones say
UNREACH and I don't have their PINs."

### Part A verdict: Installer onboarding

Replaces the toolchain ritual (D5): yes. On-box hash, batch range, SSH-only. Thesis delivered.

Three-seconds-flat batch (D2): yes. §4.4 is the marquee win; the predictive cap is exemplary.

Ends in evidence (D4): yes. The §3.3 ring test closes on a lit matrix.

Would Rivera trust the box on-site: yes, with two must-fixes (the first-boot credential path, A1; the random-PIN readout, A6). Without them he can connect but cannot finish.

Top 3 strengths:

1. The [2/5] on-box salted-hash line: Cialdini:Authority; it answers the installer's exact pain.
2. The [4/5] batch range and predictive cap: LIFT:Clarity/Anxiety, D2/D12. The redesign's core win.
3. The [5/5] handoff card scoping Dana's authority: Cialdini:Authority, LIFT:Anxiety↓ for both.

Top 3 weaknesses:

1. The first-boot credential path (A1): the front door asks for a PIN with no stated value, and the shipped default login is not named. It blocks the first 10 seconds.
2. Random-PIN provisioning with no credential readout (A6, #2): it blocks finishing the job.
3. "Join my network" can kill the SSH session it runs over (A3): a silent session-suicide risk.

The moment Rivera almost left: A1, "asks for a PIN I never set" (before the wizard even starts).
The moment Rivera was most engaged: A4, "salted 50,000-round SHA-256, computed on the box."

## Part B: DAY-2 TASK (Dana): "create a 3-member ring group and point the front desk extension at it"

This is the brief's `[3] → [Ring Groups] → A` task, plus a second leg ("point the front desk at
it") whose meaning is genuinely ambiguous in the current IA, which is itself the headline finding.
Dana's profile: **anxious**, terminal-terrified, prompt-following, terrified of breaking the phones.

### Pre-arrival (Phase 0): Dana's mental state and the relevance contract

> **Dana (monologue):** "The boss said 'make the front desk ring the whole sales pod.' I have the
> PuTTY shortcut Rivera left taped to the monitor. I'm already nervous, it's a black terminal, not
> a web page. I just need to do the one thing, see that it worked, and not touch anything else."

Relevance contract for Dana: every screen must (a) say where she is, (b) name the keys (footer),
(c) offer `?`, and (d) make the destructive path *confirm*. The IA promises all four; the question
this walkthrough answers is whether the *task* threads cleanly through them.

### Step B1: Login → hub  (`tui-style.md` §3.2)

Sees: banner → PIN (she has the master PIN on Rivera's card) → hub: the `[1]…[6]` matrix,
`[R] REBOOT [L] LOGOUT`, the ambient headroom line, `Select an option: _`, footer
`[1-6] Go … [?] Help  Theme: BRASS ▸`.

**Q1 right effect?** Partially. Dana's task is "ring group." The hub shows `[3] PBX CONFIG`, but **nothing
on the hub says the words "ring group."** Dana doesn't know "PBX." She knows "make sales ring
together."

> **Dana (monologue):** "Six options. 'System Monitor,' 'Network,' 'PBX Config,' 'Security,'
> 'Reports,' 'About.' … Which one is 'make a group of phones ring'? 'PBX Config' *sounds* technical
> and scary. I'd guess that, but I'm not sure, and I don't want to open the wrong scary thing."

**Q2 notice?** Yes: the numbers are clear. **Q3 associate?** Partially: "PBX Config" → "ring group" is a
domain-knowledge leap Dana may not make. **Q4 progress?** Yes: pressing `3` clearly enters something.

Analyst note: friction (medium). LIFT:Relevance↓: the hub label set is *protocol-named* ("PBX
CONFIG") at the exact altitude where D6 ("name the task, not the protocol") most needs to hold, and
it's the top of Dana's funnel. Fogg: Motivation is fine (she's been told to do it) but the Prompt
is mistargeted: the right door isn't labeled in her vocabulary. `personas.md` D6 mandates office
language; the hub is the one screen that stayed in PBX language. (Defensible, it's the sysop
landing, but it's Dana's first decision and her highest-anxiety one.)

Fix: keep `[3] PBX CONFIG` (installer/brand consistency) but add a one-line sub-label under
the matrix or in the headroom zone that translates: e.g. on hover/selection, the prompt area could
read `[3] PBX CONFIG: extensions, ring groups, forwards, DND`. Cheaper still: the `?` help on the
hub (which exists) must list, in plain words, "to make phones ring as a group → [3]." Validate
whether Dana finds `[3]` unaided in the 5-user test (`personas.md` §6); this is the cleanest single
metric for D6 at the hub.

### Step B2: `[3]` PBX CONFIG lands on **Extensions** tab  (`tui-style.md` §3.5)

Sees: the tab strip `Extensions │ Ring Groups │ Forwards/DND │ IVR │ Features` with `Extensions`
underlined+bright, the roster table, footer `[←/→]Tabs [↑/↓]Sel [Enter]Edit [A]Add [D]Del …`.

**Q1 right effect?** Yes: she sees `Ring Groups` *named in the tab strip*, and **this is where D6 pays
off.** The word she's looking for is on screen.

> **Dana (monologue):** "Oh, there's a tab that literally says 'Ring Groups.' That's me. How do I
> get to it… the footer says `[←/→] Tabs`. Right arrow."

**Q2 notice the tab-switch action?** Yes: footer names `[←/→] Tabs`. **Q3 associate?** Yes. **Q4
progress?** Partially: minor. When she arrows right, does the **whole screen** confirm the switch, or just
the underline move? The underline+bright-name pairing (D11) is correct, but an anxious user benefits
from the *table content* visibly changing too (it does: different columns). Fine.

Analyst note: strength (D6 delivered) with a low snag. LIFT:Relevance↑: the tab strip is the
moment Dana's plain-language goal meets a plain-language control. The one **low** friction: she
landed on **Extensions** and must *discover* she needs to *switch tabs*; there's no "you are here,
your task is one tab right" cue. The footer's `[←/→] Tabs` is discoverable but generic. Acceptable;
the tab name does the heavy lifting.

### Step B3: Switch to **Ring Groups** tab → press `A` to add  (G2; `tui-style.md` §3.6)

Sees: the Ring Groups table: `NAME · MODE · MEMBERS · STATUS`, rows `sales / support /
warehouse`, footer `… [A] Add [D] Del …`, the helper line "Open a group to set members and order."

**Q1 right effect?** Yes: she wants a *new* group; `[A] Add` is footer-named.
**Q2 notice?** Yes.
**Q3 associate `A`→"create a group"?** Yes: "Add" is plain.
**Q4 progress?** No, as the design stood when this pass read it. **The gap was that the create flow had no rendered modal.** The IA (`tui-ia.md` §2) describes `(A) Add group ◇ name → member-pick → mode`, but `tui-style.md` drew no "Add ring group" creation modal. The only ring-group modal drawn (§3.6.1) is titled **"Edit ring group · sales"**; it *edits an existing* group. The create flow (name it, then pick members, then mode) was unspecified in pixels. For an anxious, prompt-following admin, "the screen I was promised isn't drawn" is exactly the moment she freezes.

> **Dana (monologue):** "I pressed `A` for Add. … Now what? Does it ask me to *name* the group
> first? Does it drop me into an empty editor? The examples I half-remember all showed *editing*
> 'sales,' which already exists. I don't have a 'sales' yet, I'm *making* one. I don't know what
> screen I'm supposed to be looking at."

Analyst note: friction (high, missing screen). This was the headline finding for Part B: the marquee admin create-task (`3→1→A` reframed for groups) had no rendered create modal, although the IA promised one. LIFT:Clarity↓↓, Anxiety↑↑. Fogg: Ability↓ (no visible next state). Cialdini: Commitment was broken, because the small-yes ladder had a missing rung exactly at "begin creating."

**Status: resolved.** `tui-style.md` §3.6.2 now renders the Add ring group create modal: name, mode, and an empty member checklist, with the §3.6.1 geometry. The mockup below is the one this walkthrough asked for and is kept as the original proposal.

Fix (must-fix for the UI Designer): render the **Add-ring-group modal** explicitly, as a single
form that does name → mode → member checklist in one screen (mirroring §3.6.1 but titled "Add ring
group" with an empty name field and zero members checked). Reuse the §3.6.1 geometry verbatim so
there's no new interaction to learn. The *only* difference is the title and that nothing is
pre-selected. Concretely, the missing screen should look like:

```
        ┌─ Add ring group ───────────────────────────────────────┐
        │  Name ..... [ frontline   ]   3–20 chars, unique       │
        │  Mode ..... (•) Ring everyone   ( ) One at a time      │
        │                                                        │
        │  Members          (Space toggles)     Hunt order       │
        │   [ ] 101 Maria                          —             │
        │   [ ] 104 Front Desk                     —             │
        │   [ ] 105 Lobby                          —             │
        │   [ ] 102 Sam                            —             │
        │                                                        │
        │  Pick 3 to ring together. Hunt order shows only in     │
        │  "One at a time" mode.                                  │
        │                                                        │
        │              < Create >       [ Cancel ]               │
        ├────────────────────────────────────────────────────────┤
        │ [Tab] Field [Space] Toggle [↑/↓] Member [Enter] Create │
        └────────────────────────────────────────────────────────┘
```

This closes the IA-promised `name → member-pick → mode` into one anxious-admin-safe form, with the
same keys as the edit modal (D10: one model, two speeds).

### Step B4: Pick the 3 members + mode  (G2/G3; modeled on `tui-style.md` §3.6.1)

Sees (after B3 is fixed): the member checklist; `Space` toggles `[ ]`→`[x]`; the mode radios in
plain language "Ring everyone" / "One at a time."

**Q1 right effect?** Yes: "pick 3 of these people to ring."
**Q2 notice?** Yes: footer `[Space] Toggle`.
**Q3 associate?** Yes. D6 shines here: "Ring everyone (RingAll) / One at a time (Hunt)" in plain
words is exactly what `personas.md` G3 demanded; Dana never meets the word "fan-out."
**Q4 progress?** Yes: each `Space` flips a visible `[x]`; the member counter (the table's `MEMBERS`
column will read `3`) confirms.

> **Dana (monologue):** "Check Maria, check Front Desk, check Lobby, three little `[x]`s, I can see
> them. 'Ring everyone,' yes, all at once, that's what the boss wants. This part actually feels
> safe; I can *see* what I picked."

Analyst note: strength (D6/G3 delivered). LIFT:Clarity↑, Anxiety↓. Cialdini:Commitment: the
One medium snag, now closed in `tui-style.md` §3.6.2: the brief says *"create a 3-member"* group, so the form has to confirm the count. The create modal shows a live `(0 selected)` counter that becomes `(3 selected)` beside the Members header, so the "3-member" requirement is *seen*, not counted by hand.
integrity rule: if she checks a member that's `○ UNREACH`, that's *fine* (offline ≠ invalid), but if
the firmware later flags `⚠ NOT AN EXTENSION` (G6) she needs to know that's a *different, fixable*
thing; keep those two states visually distinct (dim vs red), as §3.6.1 already does.

### Step B5: Apply / Create the group  (G2; confirm of success)

Sees: `< Create >` (focused) → Enter → back to the Ring Groups table, now with a new row
`frontline · Ring everyone · 3 · ● OK`.

Q1–Q4: yes, yes, yes, partially. The new row *is* the confirmation (Q4), and it's a good one: `● OK` + member
count `3` proves it took. **But anxious Dana wants a beat of explicit success**, not just "a new row
appeared." A transient line, `✓ Ring group "frontline" created (3 members)`, in the helper zone
for ~2 s would convert "I think it worked?" into "it worked."

> **Dana (monologue):** "It went back to the list and there's my 'frontline,' 3 members, '● OK.'
> … I *think* that's good? '● OK' sounds good. I wish it had *said* 'created.'"

Analyst note: friction (low). LIFT:Anxiety↓ opportunity. The glyph+label `● OK` is honest and
D11-correct; the missing piece was an *event acknowledgement* for the anxious persona, and `tui-style.md` §3.6.2 now shows a transient `✓ Ring group "frontline" created (3 members)` line for about 2 s. Fogg:Signal:
a tiny post-action confirmation toast. Cheap, high reassurance-per-byte. (Keep it a *line*, not a
modal; Dana shouldn't have to dismiss anything to continue.)

### Step B6: "Point the front desk extension at it": THE AMBIGUOUS LEG

This is the second half of the task, and **the IA does not have one obvious home for it**, which is
the most important *design* finding in this walkthrough, because Dana will interpret "point the front
desk at the group" in at least three different ways, and the current screens support them
inconsistently:

**Interpretation (i): Forward the front desk *to* the group.** Front desk ext 104 should send its
calls to `grp:frontline`. Home: **Forwards/DND tab → Forward editor** (`tui-style.md` §3.7.1).

> **Dana (monologue):** "'Point the front desk at the group,' so when someone calls the front desk,
> it should ring the group? That's… forwarding? Let me look at Forwards/DND."

Blocker, as the editor stood when this pass read it: the Forward editor (§3.7.1) fields are `Forward ALL calls [205]`, `BUSY [ ]`, `NO-ANSWER [104]`, and every example shows **a single extension number**. It was unspecified whether a forward target may be a ring-group name (`frontline`). The Extensions table (§3.5) does show `↳ grp:sales` as a forward value on ext 104, so groups looked legal, but nothing showed how to enter one (type the name? pick from a list? is `grp:` a required prefix?). Dana is stranded between "the table says it's possible" and "the editor doesn't show me how."

**Status: resolved.** `tui-style.md` §3.7.2 draws a forward-target picker that lists extensions and ring groups, makes CFU-to-group the canonical path, and shows `grp:frontline` selected (F4).

**Interpretation (ii): make the group the IVR answer point** so the "front desk" *line* rings the
pod. Home: **IVR tab** (`tui-style.md` §3.8). But that's a different mental model (a phone-menu),
overkill for "front desk rings sales," and Dana won't reach for it.

**Interpretation (iii): add the front desk *as a member* of the group.** Home: back in the group
editor (B4). This is "front desk is *part of* the pod," not "front desk *points to* the pod,"
arguably the *opposite* of the boss's intent, but a plausible misread.

**Q1 right effect?** No: Dana can't form a single confident intent because the phrase maps to three
screens. **Q2 notice?** Partially: no screen is *labeled* "point an extension at a group." **Q3 associate?**
No, broken: the most likely correct screen (Forward editor) doesn't visibly accept a group target.
**Q4 progress?** n/a (she may not act, or act on the wrong screen).

Analyst note: friction (high, IA gap + label/affordance gap). This was the deepest finding. LIFT:Clarity↓↓, Relevance↓. The task the brief itself names ("point the front desk at it") had no unambiguous, rendered path, and the likely-correct path (forward-to-group) had an unproven affordance: could a forward field hold a group? Cialdini:Commitment was broken at the "finish the job" rung. For an anxious admin this is abandon-and-call-the-installer territory. `tui-style.md` §3.7.2 now draws both the path and the picker.

Fix (must-fix; spans IA + UI):
1. **Decide and document the canonical meaning** of "point an extension at a group." The firmware
   evidence (`↳ grp:sales` appears as a *forward* value in §3.5) says the intended path is
   **CFU = forward-all to a group**. Lock that.
2. **Make the Forward editor accept a group as a first-class target.** Change the field affordance
   from a bare number input to a picker that lists extensions *and* groups, e.g.
   `Forward ALL calls .... [ grp:frontline ▾ ]` with the `▾` opening a combined list (`102 Sam`,
   `104 Front Desk`, `grp:frontline`, `grp:sales`). Then the §3.5 table value `↳ grp:sales` is
   *reachable*, not just *displayable*. Render this modal explicitly:

```
        ┌─ Forwards · ext 104 (Front Desk) ──────────────────────┐
        │  Do-Not-Disturb ....... [ ] off  (Space toggles)       │
        │                                                        │
        │  Forward ALL calls .... [ grp:frontline      ▾ ]       │   ← picker: exts + groups
        │  Forward when BUSY .... [                    ▾ ]       │
        │  Forward NO-ANSWER .... [                    ▾ ]       │
        │                                                        │
        │  Targets can be an extension or a ring group.          │
        │  Leave blank to clear that forward.                    │
        │                                                        │
        │              < Apply >        [ Cancel ]               │
        ├────────────────────────────────────────────────────────┤
        │ [Tab] Field [Space] Pick [Enter] Apply [Esc] Back      │
        └────────────────────────────────────────────────────────┘
```
3. **Cross-link from the group, too.** In the Ring Groups table/editor, offer a one-key
   "Make an extension ring this group" affordance that jumps to the Forward editor for a chosen ext
   with `Forward ALL → grp:<this>` pre-filled, so Dana can finish from *either* the group screen or
   the forwards screen (D10: one model reachable two ways), and the brief's literal task has a
   literal button.
4. **Plain-language the helper copy.** In the Forward editor, the line "Targets can be an extension
   or a ring group" directly answers Dana's "wait, can I even put a group here?", the exact
   uncertainty that stalls her.

### Step B7: See it worked / back out safely

Sees (after B6 fix): Forward editor `< Apply >` → Extensions/Forwards table now shows ext 104
`CFU (all)→ ↳ grp:frontline`. Esc → tab → Esc → hub.

**Q4 progress?** Yes: the `↳ grp:frontline` value on 104's row is the proof. Esc-to-back (D7) lets
anxious Dana retreat one safe level at a time.

> **Dana (monologue):** "Front desk row now says '↳ grp:frontline.' That's it, calls to the front
> desk ring my new group. I'll press Esc a couple times to get home, and I didn't have to confirm
> anything scary because I didn't delete anything. … Did I? No, adding a forward isn't destructive.
> Good."

Analyst note: strength (once B3/B6 are fixed). Esc-to-back + glyph-paired table value give the
anxious admin a clean retreat and visible proof. One low note: Dana *expected* a confirm and was
relieved there wasn't one. This is correct (forwards aren't `[A!]`), but it confirms that the
**absence** of a confirm is itself reassuring information. Don't over-confirm non-destructive
actions; reserve the `▲ ALERT` dialog strictly for delete/reboot/mode/reset (D9), so its appearance
*means something* when Dana does eventually hit it.

### Part B verdict: Dana / ring-group task

Plain-language naming (D6): strong where rendered. The "Ring Groups" tab, "Ring everyone / one at a time," and the member checklist carry the redesign's empathy.

Task completable unaided: on the design as this pass read it, no. Two rendered-screen gaps blocked it: the Add-group create modal (B3) and the "point at group" path (B6). `tui-style.md` §3.6.2 and §3.7.2 now draw both screens, so the gaps are closed on paper; the 5-user test has to confirm the fix.

Anxious-admin safety (D7/D9): strong. Esc-to-back, glyph and label state, and guarded destructive actions all hold. The success acknowledgement that B5 asked for is now drawn in §3.6.2.

Would Dana finish without calling Rivera: as the pass read it, probably not (she stalls at B3 or B6). With §3.6.2 and §3.7.2 in place, likely yes, pending the 5-user test.

Top 3 strengths:

1. The "Ring Groups" tab and plain-language mode (B2, B4): LIFT:Relevance/Clarity, D6/G3. The heart of the empathy promise, delivered.
2. The member checklist as reversible small yeses (B4): Cialdini:Commitment, ideal for anxiety.
3. Esc-to-back, and non-destructive adds that do not confirm (B7): LIFT:Anxiety↓, D7/D9.

Top 3 weaknesses:

1. The Add-ring-group create modal was not rendered (B3). High. Closed in `tui-style.md` §3.6.2.
2. "Point the front desk at the group" had no canonical screen, and forward-to-group was an unproven affordance (B6). High; this was the deepest IA gap. Closed in `tui-style.md` §3.7.2.
3. The hub label "PBX CONFIG" is protocol-named at Dana's highest-anxiety first decision (B1). Medium. Open.

The moment Dana almost left: B3, "I pressed Add and don't know what screen I'm supposed to see."
The moment Dana was most engaged: B4, "three little [x]s, I can see what I picked; this feels safe."

## 1. Prioritized friction log (the deliverable)

Every item ties to a **step**, a **persona reaction**, a **framework principle**, and a concrete
**fix the IA/UI should adopt**. Priority = (blocks task? × persona-anxiety × how often it recurs).
**P0** = blocks task completion. **P1** = high-friction, near-miss. **P2** = polish / reassurance.

### P0: Blockers (a persona cannot finish the named job)

| # | Step | Persona | Friction | Framework | Fix the IA/UI should adopt |
|---|------|---------|----------|-----------|----------------------------|
| **F1** | A1 | Rivera | **The first-boot front door asks for a PIN with no stated value.** The shipped default web login (`admin` / `admin`) is enforced until changed, but the front door as drawn never names it, and the DTMF admin PIN has no default. | LIFT:Anxiety↑, Clarity↓ · Fogg:Ability↓ | Show the shipped default login on the setup card (`imagery.md`). On first use, change it before any other admin action (`AdminAuth` enforces this). Set the DTMF admin PIN in `[2/5]`, as now. |
| **F2** | A6, A7 | Rivera | **"Random per-ext" PINs are never shown/exported** (no SD, no CSV), so the installer can't register the 24 handsets. O5 "provisioned" is true for the box, false for the phones. | LIFT:Anxiety↑↑ · Fogg:Ability↓ | Make **"Match number"** the prominent recommended policy (derivable secret, nothing to carry). When "Random" is chosen, **render the per-ext PIN list on the `[5/5]` handoff card** (read-once over the operator's own SSH session, same trust model as the master-PIN message) and let SSH scrollback capture it. |
| **F3** | B3 | Dana | **The Add-ring-group *create* modal is not rendered** anywhere in `tui-style.md`; only an *Edit* modal exists. The marquee admin create-task (`3→Ring Groups→A`) has no pixels; anxious Dana freezes. | LIFT:Clarity↓↓, Anxiety↑↑ · Fogg:Ability↓ · Cialdini:Commitment (broken rung) | **Resolved** in `tui-style.md` §3.6.2. Original proposal: render the **"Add ring group"** modal (B3 mockup above): name → mode → empty member checklist, **reusing §3.6.1 geometry verbatim** (only the title + empty state differ). Same keys as edit (D10). |
| **F4** | B6 | Dana | **"Point the front desk at the group" has no canonical screen**, and the most likely path (Forward-all → group) has an unproven affordance: the Forward editor (§3.7.1) shows only single-extension targets, yet the Extensions table shows `↳ grp:sales`. Dana is stranded between "table says possible" and "editor won't let me." | LIFT:Clarity↓↓, Relevance↓ · Cialdini:Commitment (broken) | **Resolved** in `tui-style.md` §3.7.2 (CFU-to-group is the canonical meaning). Original proposal: lock CFU-to-group as the canonical meaning. Change the Forward editor target from a bare number to a **picker listing extensions AND groups** (`[ grp:frontline ▾ ]`), render that modal (B6 mockup), add helper copy "Targets can be an extension or a ring group," and add a **"Make an extension ring this group"** cross-link from the Ring Groups screen that pre-fills the Forward editor. |

### P1: High friction / near-miss (task completes but with stall, risk, or likely error)

| # | Step | Persona | Friction | Framework | Fix |
|---|------|---------|----------|-----------|-----|
| **F5** | A3 | Rivera | **"Join my network" can silently kill the SSH session it runs over** (he's on the SoftAP doing setup). No "you'll lose this link; reconnect at pocketdial.local" warning. | LIFT:Anxiety↑ · Fogg:Ability↓ | Inline consequence line when "Join my network" is picked over SoftAP: `↳ This drops your hotspot link. Reconnect at pocketdial.local or the new IP on the wallboard.` (glyph-paired, not color). |
| **F6** | A3 | Rivera | **No post-join verification.** "IP assigned after join" is a promise, not a confirmation; a wrong Wi-Fi passphrase fails silently and surfaces three steps later at the ring test. | LIFT:Clarity↓ · Fogg:feedback gap | Add a confirmation beat after Enter: `Joining office-wifi… ● LINK UP · 192.168.1.50` or `▲ join failed — check passphrase`, *before* advancing. Makes O4 a verified fact. |
| **F7** | A5, A6, §3.5.2 | Rivera | **"PIN" labels two different secrets** (master PIN in `[2/5]` vs. SIP register PIN in `[3/5]`/Add modals). Re-read tax; conflation risk. | LIFT:Clarity↓ | Rename by scope everywhere: **"Master PIN"** (login/admin) vs **"Extension PIN"** (SIP register). Standardize across wizard + Add-single + Forward modals. |
| **F8** | A6 | Rivera | **`Add all to [sales ▾]` references a ring group that doesn't exist on a fresh box**, implying a phantom group. | LIFT:Relevance↓, Clarity↓ | Offer `( ) none` (default) / `+ create group "…"` when no groups exist, or **drop the optional-group field from the wizard** (keep it linear; groups are Dana's surface, Part B). |
| **F9** | B1 | Dana | **Hub label "PBX CONFIG" is protocol-named** at Dana's first and highest-anxiety decision; "ring group" is nowhere on the hub. D6 ("name the task, not the protocol") lapses at the funnel top. | LIFT:Relevance↓ · Fogg:Prompt mistargeted | Add a translating sub-label/selection hint (`[3] PBX CONFIG: extensions, ring groups, forwards, DND`) and ensure hub `?` help maps plain tasks → keys ("make phones ring as a group → [3]"). |

### P2: Polish / reassurance (no task failure; raises confidence, especially for anxious Dana)

| # | Step | Persona | Friction | Framework | Fix |
|---|------|---------|----------|-----------|-----|
| **F10** | B5 | Dana | New group appears in the list but there's **no explicit "created" acknowledgement**; anxious user wants a beat of confirmed success, not just "a row appeared." | LIFT:Anxiety↓ · Fogg:Signal | **Resolved** in `tui-style.md` §3.6.2. Original proposal: transient helper-zone line `✓ Ring group "frontline" created (3 members)` for ~2 s. A *line*, not a modal (nothing to dismiss). |
| **F11** | B4 | Dana | The task says **"3-member"** but the form has **no live selected-count**; Dana counts `[x]`s by hand. | LIFT:Clarity↓ | **Resolved** in `tui-style.md` §3.6.2 (live `(0 selected)` and `(3 selected)` counters). Original proposal: add `(3 selected)` live counter beside the Members header. |
| **F12** | A2 | Rivera | `[0/5]` is excellent but doesn't pre-flight the **prerequisites** ("have your Wi-Fi SSID/passphrase and extension range ready"). | LIFT:Clarity↑ opportunity | One line on `[0/5]`: "Have ready: your Wi-Fi name + password, and the extension number range." |
| **F13** | A7 | Rivera | Handoff card is **ephemeral** (SSH screen); nothing says "capture this now." | LIFT:Anxiety↓ | Add `↳ copy or screenshot this card now, it isn't stored`; pair with the printed QR/setup card (`imagery.md`). |
| **F14** | B7 | Dana | Dana **expected a confirm** on the forward and was relieved there wasn't one. Correct, but confirms that **over-confirming** would erode the signal value of the real `▲ ALERT`. | LIFT:Anxiety (calibration) · D9 | Keep confirms strictly for `[A!]` (delete/reboot/mode/reset). Do **not** add confirms to non-destructive adds/edits; the dialog's rarity is what makes it meaningful. |
| **F15** | B2 | Dana | Lands on **Extensions**, must discover she needs to switch tabs; no "your task is one tab right" cue. | LIFT:Clarity↓ (minor) | Acceptable as-is; if testing shows stalls, a faint "↳ for groups, press → to Ring Groups" hint in the helper zone. |

## 2. Cross-cutting patterns this walkthrough surfaced

Recurring shapes worth carrying into future screens (memory for the next walkthrough):

1. **"Rendered ≠ specified" is a real risk in this doc set.** The IA described flows that the UI doc did not draw when this pass read it: the Add-group create modal (F3) and the forward-to-group affordance (F4). Both are now drawn in `tui-style.md` §3.6.2 and §3.7.2. The most damaging friction in Part B was not a bad screen; it was a **missing** screen the IA promised. Pattern: every IA verb (`A`dd, `D`elete, edit) on every panel needs a rendered modal, not just a one-line tree entry. A coverage check ("every `(A)`/`(Enter)`/`(D)` in §2 has a §3 mockup") would have caught F3 and F4 mechanically.

2. **First-run front doors need an explicit default-credential branch** (F1). The firmware ships a default web login, `admin` / `admin`, that is enforced until changed: `AdminAuth` refuses every other admin action until the default is replaced (`src/Helpers/AdminAuth.hpp`; `needsInitialSetup()` at `src/Helpers/AdminAuth.cpp:1192-1202`). The DTMF admin PIN is the opposite case: it has no default and is set during setup. A front door that needs a secret from setup must show an un-provisioned state. The web route `/api/factory-reset` erases the AdminAuth password hashes and the DTMF PIN (`src/Helpers/FactoryReset.hpp`), so a reset returns the box to that default state. Whether the `[4] SECURITY → Factory reset` screen, which the IA says "dumps back to the wizard," calls that route was not checked in this pass.

3. **Plain-language naming (D6) holds *inside* panels but lapses at the *hub*** (F9). The empathy
   that makes "Ring everyone / one at a time" delightful (B4) is absent at "PBX CONFIG" (B1), the
   exact top-of-funnel where the anxious persona most needs it. Pattern: audit D6 at *every
   altitude*, not just leaf forms; the funnel entrance matters most.

4. **The installer's job extends past "the box is configured" to "the phones can register"** (F2).
   A provisioning UI that creates extensions but hides their credentials has completed *its* model
   of the task, not the *installer's*. Pattern: trace each task to the persona's real
   end-state (a ringing phone), not the system's (a config row).

5. **Anxious users read the *absence* of a confirm as information** (F14). Reserve the `▲ ALERT`
   dialog strictly for `[A!]`; every spurious confirm on a safe action devalues the real one. The
   design already gets this right; protect it.

6. **For the anxious persona, "it worked" must be *said*, not merely *true*** (F10). A correct
   glyph+label end-state (`● OK`) satisfies the analyst and the installer; the anxious admin also
   needs a transient *event* acknowledgement. Cheap, high reassurance-per-byte, line-not-modal.

## 3. What this walkthrough validates vs. what still needs live users

Per `personas.md` §6, this is the cheap first pass; it **measures D3/D6/D10** as the plan intends.

- **Confirmed strong (high confidence, structural):** the batch-provision marquee (A6), the on-box
  hash trust line (A4), the handoff card's authority-scoping (A7), the ring test as evidence (A8),
  and plain-language group mode + member checklist (B4). These are the redesign's thesis and they
  hold.
- **Confirmed gaps at the time of the pass (high confidence, missing or ambiguous artifacts):** F1 (first-boot credential path, now reframed against the shipped default login), F3 (missing Add-group modal, now drawn in `tui-style.md` §3.6.2), and F4 (no canonical "point at group" path, now drawn in §3.7.2). These are *artifact gaps*, not opinions; they are verifiable by inspecting the doc set.
- **Needs the 5-user test to resolve (medium confidence, emotional/contextual):** F9 (does Dana
  actually fail to find `[3]` from "ring group"?), F7 (does the PIN-label collision cause real
  errors or just a pause?), F2's chosen fix (is on-screen PIN readout acceptable to security-minded
  installers, or do they demand SSH-key handoff per `personas.md` §6 open question?). The success
  metrics in `personas.md` §6.2 (block-provision < 3 min; add/edit unaided with `?` ≤ once) are the
  measurements that turn these mediums into highs.

This file is the Persona Walkthrough Specialist's cognitive walkthrough of the onboarding wizard (Rivera) and of the create-ring-group, point-the-front-desk task (Dana). It is grounded in [`personas.md`](personas.md) (Rivera and Dana, Task Inventory §3), [`tui-ia.md`](tui-ia.md) (screen tree, keys, wizard), and [`tui-style.md`](tui-style.md) (the rendered ANSI mockups stepped through). It is a qualitative simulation, not statistical evidence: strong hypotheses for the §6 five-user validation in `personas.md`.
