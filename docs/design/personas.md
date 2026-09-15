# pocket-dial Redesign. Personas, Jobs-to-be-Done & Task Model

> **Phase-A deliverable (UX Researcher).** Reads from and stays consistent with
> [`00-brief.md`](00-brief.md): product name **pocket-dial**, the BRASS/PHOSPHOR palette,
> the hub matrix (`[1] SYSTEM MONITOR  [2] NETWORK  [3] PBX CONFIG  [4] SECURITY  [5] REPORTS/LOGS  [6] ADDONS`),
> the keyboard-first single-key/Esc-to-back scheme, and the v1 feature scope.
> The efficiency north-star is the brief's own: **`3 → 1 → A` provisions or reroutes in three seconds flat.**
>
> Downstream agents (UX Architect, UI Designer, Persona Walkthrough) should treat the
> **Task Inventory** (§3) as the authoritative coverage checklist for the TUI screen tree.


## 0. How these personas were grounded

These are evidence-based personas, not invented archetypes. They are triangulated from three
sources actually present in this repo, so every task in the inventory maps to a real firmware
capability rather than a wish:

1. **The config schema the firmware exposes**, `src/SIP/PbxConfig.hpp` (ring/hunt groups,
   the three forward triggers `CFU/CFB/CFNA`, member lists), `src/SIP/RequestsHandler.*`
   (per-extension DND map, feature codes like `*55` as dialable AORs, the DTMF admin menu,
   blind-transfer via `Refer-To`), `src/SIP/CallDetailRecord.hpp` (the 32-deep CDR ring with
   five result states), and `src/SIP/PoolConfig.hpp` (the **hard caps: 32 extensions / 8
   concurrent sessions**, these are real ceilings the TUI must surface, not hide).
2. **The onboarding the redesign is replacing**, `.smoke/gen_provision_nvs.py`: today a working
   box requires hand-running a Python script that recomputes a 50 000-round salted SHA-256 PIN
   hash, generating an NVS CSV, running `nvs_partition_gen.py`, and `esptool write_flash 0x9000`.
   **This artifact is the persona pain made literal.** The installer persona's entire reason to
   exist is to never do that again.
3. **The owner's vision in the brief**, the `3 → 1 → A` "three seconds flat" north-star and the
   reframe from touchscreen-config to SSH-first sysop terminal.

> **Research confidence.** This is a synthetic-but-grounded persona pass (n=0 live interviews;
> a hard constraint of a pre-launch embedded redesign). Confidence is *high* on tasks and pain
> points (firmware- and artifact-derived, not opinion) and *medium* on emotional/contextual
> framing. §6 lists the three validation studies that would raise the latter to high; the
> Persona Walkthrough agent (`walkthrough.md`) performs the first cheap pass.


## 1. Persona A, "Rivera," the Installer

```
┌─ PERSONA A ─────────────────────────────────────────── pocket-dial ─┐
│  RIVERA  ·  Field Installer / IT-VAR Technician                      │
│  "I have eleven of these on the van today. Don't make me think."     │
└─────────────────────────────────────────────────────────────────────┘
```

### Demographics & context
- Role: Field technician for a small voice/data integrator (a VAR). Installs and hands off
  small phone systems; rarely returns to the same site.
- Tech proficiency: High and *specific*. Lives in a terminal. Comfortable with SSH, `ssh-keygen`,
  PuTTY, subnetting, and reading a `tcpdump`. **Not** a SIP-stack developer and **not** a
  pocket-dial expert, learns each product's quirks on the job and forgets them between sites.
- Devices: A rugged laptop (Windows + PuTTY, or macOS + OpenSSH) tethered to the box by Ethernet
  or its SoftAP. Sometimes a phone over the SoftAP captive portal as a fallback.
- Frequency of use: Intense and bursty. Touches pocket-dial for **20–40 minutes once per site**,
  provisions 4–24 extensions, then never logs in again. The day-2 admin owns it after that.

### What "good" looks like for Rivera
The whole job is **time-on-site**. Every minute is margin. The win condition is: *unbox → on the
network → all extensions provisioned → ring test passes → admin credentials handed over →
back in the van*, with zero documentation lookups and zero firmware-flashing rituals. The
`.smoke/gen_provision_nvs.py` flow is everything Rivera hates: it is slow, error-prone, requires
a workstation toolchain, and turns a 30-minute job into an afternoon.

### Goals
- Primary: Provision a block of extensions correctly the first time, fast, from memory.
- Primary: Prove it works before leaving (a real ring test, visible registration state).
- Secondary: Set up the day-2 admin so the handoff is clean and the admin can't break the box.
- Secondary: Lock the box down (change the default PIN, set the admin's SSH key/PIN, confirm
  the SoftAP isn't left wide open) without reading a security manual.

### Jobs-to-be-Done (JTBD)
- *When I arrive at a site with a new box, I want to reach a working config surface within seconds
  of plugging in, so I don't burn site-time on toolchains or flashing.*
- *When I provision a block of extensions, I want to define them in one fast batch and not one
  modal-dialog-per-phone, so 24 phones doesn't mean 24 page-loads.*
- *When I think I'm done, I want the system to show me what's still wrong (unregistered phones, a
  ring group pointing at a nonexistent extension), so I find faults on-site, not on a callback.*
- *When I hand off, I want to set the admin's credentials and confidently say "this is all you'll
  ever need to touch," so I'm not the site's permanent phone-support line.*

### Frustrations with the status quo (verbatim-style, drawn from the artifact)
> "To make the box *usable* I had to run a Python script that recomputes a 50,000-round hash, build
>  an NVS image, and `esptool write_flash 0x9000`. On a customer site. From the van."
> "I never know if a phone is actually registered until someone complains a week later."
> "Touchscreen config means I'm hunched over a 3.5-inch panel poking a soft keyboard for an hour."


## 2. Persona B, "Dana," the Day-2 Admin

```
┌─ PERSONA B ─────────────────────────────────────────── pocket-dial ─┐
│  DANA  ·  Office Manager / Accidental Phone Admin (non-specialist)   │
│  "I just need to send the front desk to voicemail— wait, no... DND." │
└─────────────────────────────────────────────────────────────────────┘
```

### Demographics & context
- Role: Office manager / operations lead at a 6–30 person SOHO/SMB. Owns the phone system
  *by default*, not by training. The phone system is maybe 2% of the job.
- Tech proficiency: **Non-specialist.** Competent with web apps and spreadsheets; a terminal is
  unfamiliar territory. Will follow a printed "How to SSH in" card the installer left taped to the
  box. Does **not** know SIP, does not know what a "ring group fan-out mode" is in the abstract, and
  will be intimidated by anything that looks like a Linux config file.
- Devices: An office laptop. Reaches the box at `pocketdial.local` (mDNS already works) using
  whatever SSH client Rivera set up, usually a desktop shortcut to PuTTY or the OS terminal.
- Frequency of use: **Rare and reactive.** Logs in a handful of times a month, almost always to
  respond to an event: a new hire needs an extension, someone's going on leave, the boss wants calls
  to ring the whole sales pod, "why didn't my phone ring?"

### What "good" looks like for Dana
**Confidence and reversibility.** Dana needs to accomplish a small, named task, see plainly that it
worked, and trust that nothing else changed. Dana is *terrified of breaking the phones*, a dead
phone system is a visible, embarrassing, business-stopping failure. The TUI must feel less like a
router admin page and more like a labeled control panel where every control says what it does, every
destructive action confirms, and "back out without saving" is always one Esc away.

### Goals
- Primary: Complete one specific, named change (add an extension, toggle DND, edit a ring group,
  set a forward) and *see confirmation it took effect*.
- Primary: Never feel lost. Always know where I am, what keys do what, and how to get out.
- Secondary: Answer "is the phone system OK right now?" at a glance, and "why didn't a call
  connect?" from the call log, without help.
- Anti-goal: Dana must **not** be able to brick the box. Hard caps, network mode, and security
  settings should be visible but guarded; the everyday surface should be the safe surface.

### Jobs-to-be-Done (JTBD)
- *When a new person starts, I want to add their extension by following obvious on-screen prompts,
  so I don't have to remember a procedure or call the installer.*
- *When someone is out, I want to flip their phone to Do-Not-Disturb or forward it, and clearly see
  the badge change, so I trust it actually happened.*
- *When the boss says "make sales ring as a group," I want to pick the people from a list, choose
  ring-all vs. one-at-a-time in plain language, and apply, without knowing the word "fan-out."*
- *When someone says "my call dropped," I want to look at a recent-calls list that tells me what
  happened in words (busy / no-answer / cancelled), so I can answer them myself.*
- *Whenever I'm unsure, I want a `?` that explains this exact screen, so I never feel stranded in a
  terminal.*

### Frustrations & fears
> "I'm scared that if I touch the wrong thing, nobody's phone works and it's my fault."
> "Last admin tool was a wall of fields with no labels. I didn't know which were safe to change."
> "Don't make me read documentation to add one extension."


## 3. Task Inventory, the complete surface the TUI must cover

This is the authoritative coverage checklist. Every task maps to (a) a firmware capability that
exists today, (b) the hub destination from the brief's matrix, and (c) the owning persona(s).
**I = Installer (Rivera), A = Admin (Dana).** Tasks marked **[A!]** are admin tasks that touch
guarded surfaces, they must be reachable but protected by confirmation/scoping.

### 3.1 Onboarding & first-run (Installer-owned, runs once)
| # | Task | Persona | Hub home | Firmware anchor |
|---|------|---------|----------|-----------------|
| O1 | First SSH connection → forced first-run wizard (no usable default state) | I | (wizard) | replaces `gen_provision_nvs.py` |
| O2 | Set the master admin PIN (salted/iterated, never echo) | I | wizard → `[4]` | `AdminAuth::hashPin` (50k-round SHA-256) |
| O3 | Choose network mode: Standalone SoftAP vs. join existing LAN (DHCP) | I | wizard → `[2]` | `wifi_mode` 1=CLIENT / 2=AP |
| O4 | Confirm reachable identity (`pocketdial.local` mDNS, IP, SoftAP SSID) | I | wizard → `[2]` | mDNS + DHCP already work |
| O5 | Provision a **block** of extensions in one batch (range + PINs) | I | wizard → `[3]` | `_clientPool`, cap 32 |
| O6 | Hand-off summary card: creds, host, what the admin can/can't touch | I | wizard end |, |

### 3.2 Extensions (Both)
| # | Task | Persona | Hub home | Firmware anchor |
|---|------|---------|----------|-----------------|
| E1 | List extensions with live `[ ONLINE ]`/`[ UNREACH ]` registration state | I, A | `[3]` PBX CONFIG · Extensions | registrar snapshot |
| E2 | Add a single extension (number + auth PIN) | I, A | `[3]` Extensions | REGISTER / AOR validation (`isValidAor`) |
| E3 | Add a contiguous **range** of extensions at once | I | `[3]` Extensions | bulk over `_clientPool` |
| E4 | Edit an extension (PIN / display name) | A | `[3]` Extensions |, |
| E5 | Delete an extension | **[A!]** | `[3]` Extensions | frees a pool slot |
| E6 | See/handle the cap: 32 extensions; a 33rd is refused (503), surfaced as a clear "pool full" state, never a silent failure | I, A | `[3]` Extensions | `POCKETDIAL_MAX_CLIENTS`, 503 |

### 3.3 Ring groups (Both)
| # | Task | Persona | Hub home | Firmware anchor |
|---|------|---------|----------|-----------------|
| G1 | List ring groups + their members and mode | A | `[3]` PBX CONFIG · Ring Groups | `RingGroup` |
| G2 | Create a ring group; pick members from the extension list | A | `[3]` Ring Groups | `splitMembers`/`joinMembers` |
| G3 | Choose fan-out mode in plain language: "Ring everyone" (RingAll) vs. "One at a time" (Hunt) | A | `[3]` Ring Groups | `GroupMode::RingAll/Hunt` |
| G4 | Reorder hunt members / set per-member timeout | A | `[3]` Ring Groups | Hunt sequence |
| G5 | Edit / delete a ring group | **[A!]** | `[3]` Ring Groups |, |
| G6 | Integrity warning: group references a deleted/nonexistent extension | I, A | `[3]` Ring Groups | member-validation |

### 3.4 Per-extension call features (Admin-owned, the day-2 bread-and-butter)
| # | Task | Persona | Hub home | Firmware anchor |
|---|------|---------|----------|-----------------|
| F1 | Toggle **DND** for an extension; badge flips visibly | A | `[3]` Extensions / feature row | `setDnd`, `_dnd` map |
| F2 | Set **Call-Forward Always** (CFU) target | A | `[3]` feature row | `ForwardConfig::always` |
| F3 | Set **Forward-on-Busy** (CFB) target | A | `[3]` feature row | `ForwardConfig::busy` |
| F4 | Set **Forward-on-No-Answer** (CFNA) target | A | `[3]` feature row | `ForwardConfig::noAnswer` |
| F5 | Clear any/all forwards for an extension | A | `[3]` feature row | empty string = unset |
| F6 | Reference the **star-codes** the phones dial (e.g. `*55`-style feature codes) | A | `[3]` IVR/Features ref | feature codes are dialable AORs |

### 3.5 Minimal IVR (Admin-owned, simple)
| # | Task | Persona | Hub home | Firmware anchor |
|---|------|---------|----------|-----------------|
| V1 | Define a DTMF menu: digit → action (ring an extension/group, play a prompt) | A | `[3]` PBX CONFIG · IVR | DTMF collector state machine |
| V2 | Pick a prompt to play (from on-flash `prompts` partition, **no queues, no SD**) | A | `[3]` IVR | 3.88 MB `prompts` partition |
| V3 | Set the IVR as the answer point / test the digit map | A | `[3]` IVR |, |

### 3.6 Live monitoring (Both. Installer for ring-test, Admin for "is it OK?")
| # | Task | Persona | Hub home | Firmware anchor |
|---|------|---------|----------|-----------------|
| M1 | Live call matrix (CH / EXT / DEST / DURATION / CODEC / STATUS), ~1 Hz refresh | I, A | `[1]` SYSTEM MONITOR | session snapshot, ≤8 sessions |
| M2 | Registration roster: who is `● ONLINE` / `○ UNREACH` right now | I, A | `[1]` MONITOR | registrar snapshot |
| M3 | Hardware vitals: CPU/mem bars, uptime, session-pool usage (n/8) | I, A | `[1]` MONITOR | `8` session cap visible |
| M4 | Installer ring-test confirmation: place a test call, watch it light up the matrix | I | `[1]` MONITOR | end-to-end proof |

### 3.7 Reports / CDR (Admin-owned, self-service "why didn't it ring?")
| # | Task | Persona | Hub home | Firmware anchor |
|---|------|---------|----------|-----------------|
| R1 | Browse recent calls (newest-first ring of 32) | A | `[5]` REPORTS/LOGS | CDR ring buffer |
| R2 | Read each call's outcome in words: answered / busy / no-answer / cancelled / failed | A | `[5]` REPORTS/LOGS | `CdrResult` (5 states) |
| R3 | See caller, callee, start time, talk duration per call | A | `[5]` REPORTS/LOGS | `CallDetailRecord` fields |
| R4 | Read the live event/system log tail | I, A | `[5]` REPORTS/LOGS | `queueLog` |

### 3.8 Network & system (Installer-owned; Admin views, rarely edits)
| # | Task | Persona | Hub home | Firmware anchor |
|---|------|---------|----------|-----------------|
| N1 | View network status: mode, IP, SSID, `pocketdial.local`, link/DHCP | I, A | `[2]` NETWORK | DHCP + mDNS |
| N2 | Switch network mode (SoftAP ↔ client) | **[A!]** / I | `[2]` NETWORK | `wifi_mode` toggle 1↔2 |
| N3 | Reboot the box | **[A!]** / I | `[R]` REBOOT (hub) | `[R] REBOOT` in brief |

### 3.9 Security & session (Both)
| # | Task | Persona | Hub home | Firmware anchor |
|---|------|---------|----------|-----------------|
| S1 | Change the admin PIN | I, A | `[4]` SECURITY | `AdminAuth` salted hash |
| S2 | Manage SSH access (authorized key / PIN policy) for admin handoff | I | `[4]` SECURITY | SSH server |
| S3 | Log out cleanly | I, A | `[L]` LOGOUT (hub) | `[L] LOGOUT` in brief |
| S4 | `?` context help, available on **every** screen | I, A | global | brief hard constraint |

### 3.10 Cross-cutting tasks that exist on *every* screen
- **`?` help** scoped to the current screen (hard constraint).
- **Esc-to-back** returns to the parent / hub consistently (hard constraint).
- **Always-visible key-hint footer** showing the live hotkeys (hard constraint).
- **Confirm-on-destructive** for every `[A!]` task (delete, reboot, mode-switch).
- **State-by-glyph-and-label**, never color alone (e.g. `● ONLINE` / `○ UNREACH`, `[DND]`).


## 4. Design Implications, making provisioning feel "three seconds flat"

These are the research-backed requirements the brief's north-star (`3 → 1 → A`) imposes on a
keyboard-first SSH terminal. Each is written as a directive for the downstream IA/UI agents, with
the persona it serves.

### 4.1 Speed for Rivera, the muscle-memory machine

**D1. The hub is a typeahead, not a menu walk.** Single-key hotkeys must compose without waiting
for redraws, so `3` `1` `A` is one fluid keystroke run, *the same `3→1→A` the brief promises.*
The hub never demands Enter to confirm a single-key choice. Mockup of the landing hub:

```
┌──────────────────────────────────────────────────────────────────────────────┐
│ pocket-dial v3.0      [ SYSTEM MANAGEMENT ]                         18:14:22   │
├──────────────────────────────────────────────────────────────────────────────┤
│                                                                                │
│     [1] SYSTEM MONITOR        [2] NETWORK         [3] PBX CONFIG               │
│     [4] SECURITY              [5] REPORTS/LOGS    [6] ADDONS                   │
│                                                                                │
│     [R] REBOOT   [L] LOGOUT                                                     │
│                                                                                │
│   ● 4 online  ○ 1 unreach   ·   1/8 calls   ·   ext 12/32   ·   AP mode        │
│                                                                                │
│   Select an option: _                                                          │
├──────────────────────────────────────────────────────────────────────────────┤
│ [1-6] Go  [R] Reboot  [L] Logout  [?] Help                                     │
└──────────────────────────────────────────────────────────────────────────────┘
```

**D2. Batch beats modal.** Rivera provisions a *block*, so the marquee path is a range entry, not
N single-add dialogs. One field accepts `101-124`, one accepts a PIN policy, one keypress applies
all 24. This is the single most valuable speed decision in the product. Mockup:

```
┌─ PBX CONFIG ▸ Extensions ▸ Add Range ──────────────────────────────────────────┐
│                                                                                 │
│   Range ......... [ 101-124         ]   (24 extensions)                         │
│   PIN policy .... (•) Random per-ext   ( ) Same PIN   ( ) Match number          │
│   Ring group .... [ sales            ▾]  (optional: add all to a group)         │
│                                                                                 │
│   This will create 24 extensions. Pool after:  36/32  ⚠ EXCEEDS CAP            │
│   ► Adjust range — only 20 slots free (12/32 used).                            │
│                                                                                 │
│           < Apply >        < Cancel >                                           │
├─────────────────────────────────────────────────────────────────────────────────
│ [Tab] Field  [Space] Toggle  [Enter] Apply  [Esc] Back  [?] Help                │
└─────────────────────────────────────────────────────────────────────────────────
```
Note how the cap (`POCKETDIAL_MAX_CLIENTS=32`) is surfaced *before* apply with a glyph (`⚠`) and a
label, never a post-hoc 503, turning a firmware limit into a guided correction.

**D3. No documentation lookups, ever.** Every screen carries its own keys (footer) and its own
explanation (`?`). The "three seconds flat" only holds if Rivera never alt-tabs to a manual. The
first-run wizard is linear, numbered, and resumable, so an interrupted install picks up where it
left off.

**D4. Prove-it-works is a first-class task, not an afterthought.** The live monitor (`M4`) is the
installer's acceptance test. Place a call, watch the matrix light up at ~1 Hz, see registration dots
flip green-with-`●`. The handoff ends in evidence, not hope.

**D5. The wizard *replaces the toolchain ritual outright.*** O1–O6 must do, over SSH in one sitting,
everything `gen_provision_nvs.py` + `nvs_partition_gen.py` + `esptool write_flash` does today.
If a single first-run step still requires a host toolchain, the redesign has failed its core promise.

### 4.2 Confidence for Dana, the safe, legible control panel

**D6. Name the task, not the protocol.** Labels speak office, not SIP. "Ring everyone" / "One at a
time" instead of RingAll/Hunt; "Send my calls to…" instead of CFU. Dana picks members from a *list*,
never types a CSV. Mockup of the ring-group editor in plain language:

```
┌─ PBX CONFIG ▸ Ring Groups ▸ Edit "sales" ──────────────────────────────────────┐
│                                                                                 │
│   When someone calls this group, it should…                                     │
│       (•) Ring everyone at once          ( ) Ring one person at a time          │
│                                                                                 │
│   Members          ┌─────────────────────────────────────────┐                  │
│    [x] 101 Maria   │  ● 101 Maria      ONLINE                 │                  │
│    [x] 102 Sam     │  ● 102 Sam        ONLINE                 │                  │
│    [ ] 103 Lee     │  ○ 103 Lee        UNREACH                │                  │
│    [x] 107 (gone)  │  ⚠ 107            NOT AN EXTENSION       │ ◄ fix this       │
│                    └─────────────────────────────────────────┘                  │
│                                                                                 │
│           < Apply >    < Cancel >    < Delete group >                            │
├─────────────────────────────────────────────────────────────────────────────────
│ [↑/↓] Member  [Space] Add/Remove  [Enter] Apply  [Esc] Back  [?] Help            │
└─────────────────────────────────────────────────────────────────────────────────
```

**D7. Every change is visible and reversible.** A toggle (DND) shows its new state *immediately and
glyphically*; a destructive action (`[A!]`: delete, reboot, mode-switch) always confirms; Esc always
backs out without saving. Dana's core fear ("I'll break the phones") is answered by making the safe
path the default and the dangerous path explicit. Confirmation mockup:

```
┌─ Confirm ──────────────────────────────────────────────┐
│  ⚠  Delete extension 103 (Lee)?                         │
│                                                         │
│  Lee is a member of ring group "sales" and will be     │
│  removed from it. This cannot be undone.                │
│                                                         │
│        < Delete >            < Keep, go back >          │
├─────────────────────────────────────────────────────────
│ [←/→] Choose   [Enter] Confirm   [Esc] Cancel           │
└─────────────────────────────────────────────────────────
```

**D8. Answer "is it OK?" and "why didn't it ring?" without help.** The monitor gives the at-a-glance
health read; the CDR view (`R1–R3`) renders each outcome in plain words tied to the five `CdrResult`
states, so Dana self-serves the most common support question. Mockup of the report row:

```
┌─ REPORTS/LOGS ▸ Recent Calls ──────────────────────────────────── 32 of 32 ───┐
│  TIME      FROM   →  TO     RESULT        TALK                                  │
│  18:02:14  101    →  205    ✓ answered    04:12                                 │
│  17:58:40  101    →  sales  ✗ no-answer   --:--                                 │
│  17:51:09  204    →  101    ⊘ busy        --:--                                 │
│  17:44:22  103    →  102    … cancelled   --:--                                 │
├─────────────────────────────────────────────────────────────────────────────────
│ [↑/↓] Scroll  [Enter] Detail  [Esc] Main  [?] Help                              │
└─────────────────────────────────────────────────────────────────────────────────
```
Each result pairs a glyph (`✓ ✗ ⊘ …`) with a word, satisfying "never color alone."

**D9. Guard the dangerous surfaces, don't hide them.** Network-mode switch, delete, and reboot are
visible (Dana shouldn't feel walls), but gated behind confirmation and clear consequence text. The
everyday surface (extensions, DND, forwards, groups, reports) is the *safe* surface by construction.

### 4.3 Cross-cutting implications for *both* personas

**D10. One mental model, two speeds.** The same screens serve Rivera (fast, keyboard-driven, knows
the keys) and Dana (deliberate, prompt-following, reads the footer). Achieve this with: single-key
hotkeys that power users chain *and* an always-visible footer that beginners read, the footer is the
training wheels the expert ignores. No "advanced mode" fork; just consistent, discoverable keys.

**D11. Status is glyph-first, color-second, always.** Per the hard constraint, every state pairs a
shape/label with color: `● ONLINE` / `○ UNREACH`, `[DND]`, `⚠ EXCEEDS CAP`, `✓/✗/⊘`. This serves the
mono-terminal degrade path, color-blind users, *and* Dana's need to read state literally. The
Accessibility Auditor (`accessibility.md`) owns the exhaustive glyph table; this is the persona-side
requirement that motivates it.

**D12. Surface the real ceilings (32 ext / 8 calls) as design objects, not error states.** Because
the pools are hard caps that 503 on overflow, the TUI must show headroom *ambiently* (hub footer:
`ext 12/32`, `1/8 calls`) and *predictively* (D2's pre-apply cap check), so neither persona ever
discovers a limit by hitting it.

**D13. Consistent geometry at 80×24.** Every mockup above fits the minimum geometry with a stable
3-zone layout (**title bar / body / key-hint footer**) so muscle memory (Rivera) and orientation
(Dana) both survive across screens. No horizontal scroll; extra columns are a bonus, never required.


## 5. Task-to-persona-to-screen traceability (summary)

| Hub destination | Primary persona | Marquee tasks | Why it exists |
|---|---|---|---|
| First-run wizard | Installer | O1–O6 | Kills the `gen_provision_nvs.py` ritual; "three seconds" starts here |
| `[3]` PBX CONFIG | Both | E*, G*, F*, V* | The product's substance: extensions, groups, forwards, IVR |
| `[1]` SYSTEM MONITOR | Both | M1–M4 | Installer's ring-test proof; Admin's "is it OK?" |
| `[5]` REPORTS/LOGS | Admin | R1–R4 | Self-service "why didn't it ring?" |
| `[2]` NETWORK | Installer | N1–N3 | Reachability + mode; guarded for Admin |
| `[4]` SECURITY | Both | S1–S4 | PIN/SSH; clean handoff; `?` everywhere |


## 6. Validation plan (to raise medium-confidence framing to high)

Three lightweight studies, ordered by cost, that the team should run before/at launch:

1. **Cognitive walkthrough (free, internal).** Owned by the Persona Walkthrough agent
   (`walkthrough.md`): step Rivera through O1–O6 + a ring-test, and Dana through "add an extension"
   and "make sales ring as a group." Friction log feeds back into the IA. *Measures D3, D6, D10.*
2. **5-user unmoderated usability test (low cost).** 3 installer-profile + 2 office-manager-profile
   participants over SSH. Success metrics: installer block-provision (O5) **< 3 min**, time-to-first-
   keystroke after connect **< 10 s**; admin add-extension (E2) and ring-group edit (G2/G3) completed
   **unaided** with `?` used ≤ once. Target: 4/5 task success, SUS ≥ 75. *Validates the north-star.*
3. **Accessibility & degrade pass (low cost).** Render every screen in monochrome and with a
   color-blind-sim filter; confirm no task relies on color (D11). Run a screen-reader-over-SSH spot
   check. Owned jointly with the Accessibility Auditor (`accessibility.md`).

> Key open questions for live research: Does Dana trust an SSH terminal at all, or does the
> printed "how to connect" card need to live in the box's splash/QR (see `imagery.md`)? Is the
> 32-extension cap ever a real ceiling for the SMB target, or comfortably above the 8–30-seat
> reality? Does the installer want SSH-key handoff or is a PIN sufficient for the day-2 admin (S2)?


*UX Researcher · pocket-dial Phase-A design sprint · grounded in firmware (`src/SIP/*`),*
*the legacy provisioning artifact (`.smoke/gen_provision_nvs.py`), and `00-brief.md`.*
