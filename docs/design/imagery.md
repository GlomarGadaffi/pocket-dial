# pocket-dial: Raster Imagery Specs & Generation Prompts

> Agent: Image Prompt Engineer + Inclusive Visuals (reduced role).
> Why reduced: pocket-dial is a *pure-ANSI/TUI* product. The SSH terminal, login banner, hub,
> panels, and live monitor are **text, not pictures**. They are owned by
> [`brand.md`](brand.md) / [`tui-style.md`](tui-style.md) and are **not** raster assets. This file
> covers only the three places a real bitmap exists:
>
> | # | Asset | Surface | Canvas | Render path |
> |---|---|---|---|---|
> | 1 | **On-device SPLASH / boot art** | 3.5" passive wallboard (LVGL) | **320 × 480 px, portrait** | drawn on the panel; lives in flash |
> | 2 | **Onboarding QR "card"** | same display, first-run | **320 × 480 px, portrait** | LVGL layout + 99×99 QR canvas |
> | 3 | **README / marketing hero** | GitHub / web, not on-device | **2400 × 1350 px (16:9)** | external render, ships in repo |
>
> Everything here inherits the locked brand from [`00-brief.md`](00-brief.md) §5 and
> [`brand.md`](brand.md): name **pocket-dial**, tagline *operator on duty*, the **BRASS** (default) /
> **PHOSPHOR** (alt) palettes, the jack mark `(◉)`, and the flavor budget (only *operator on duty*
> and *Patching you through…* spend charm). No new copy, no new colors, no sub-brands.

## 0. Shared palette tokens (single source of truth)

Pulled verbatim from `main/ui/ui.cpp` `PALETTES[]` and `00-brief.md` §5. Every prompt and spec below
references these by name so the splash, the card, and the hero read as **one product**.

### BRASS (default): deep charcoal board, warm brass rails, amber lamps
| Token | Hex | RGB | Role |
|---|---|---|---|
| `BRASS.bg` | `#161412` | 22,20,18 | board background (near-black warm charcoal) |
| `BRASS.panel` | `#28241E` | 40,36,30 | recessed panel / tile face |
| `BRASS.border` | `#B08438` | 176,132,56 | brass rails / frame / nameplate |
| `BRASS.text` | `#D6B26E` | 214,178,110 | brass label text |
| `BRASS.highlight` | `#F5D696` | 245,214,150 | bright brass / headers |
| `BRASS.accent` | `#FFB020` | 255,176,32 | **the lamp** (live/lit only) |
| `BRASS.alert` | `#C84028` | 200,64,40 | destructive / alert only |

### PHOSPHOR (alt): charcoal board, dim-brass rails, green phosphor lamps
| Token | Hex | RGB | Role |
|---|---|---|---|
| `PHOS.bg` | `#10140F` | 16,20,15 | board background |
| `PHOS.panel` | `#1C241C` | 28,36,28 | recessed panel |
| `PHOS.border` | `#96823C` | 150,130,60 | dim-brass rails / frame |
| `PHOS.text` | `#AAD296` | 170,210,150 | phosphor label text |
| `PHOS.highlight` | `#D2F0BE` | 210,240,190 | bright phosphor |
| `PHOS.accent` | `#40FF60` | 64,255,96 | **the lamp** (live/lit only) |
| `PHOS.alert` | `#DC4632` | 220,70,50 | destructive / alert only |

Locked discipline (from brand.md): *brass is the chrome, the lamp is the accent.* Frames, rails,
and nameplate are `border`; the single hot accent (`accent`) is reserved for **live things**; `alert`
red is rationed to destructive/alert only. State is never color alone: every status is glyph +
LABEL, the label authoritative, the glyph reinforcing, color the removable third layer.

## 1. ON-DEVICE SPLASH / BOOT ART: 320 × 480, portrait

### 1.1 Purpose & viewing reality
Shown for the ~3–6 s while firmware boots, *before* the wallboard goes live; the brand's first
physical impression. **Viewing distance is arms-length-to-across-the-room at 3.5".** That dictates a
**single large legible focal element** (the wordmark + jack mark), generous negative space, and
**no fine texture that turns to mush** at 320×480 on a glossy IPS panel.

### 1.2 Hard technical constraints (this is an ESP32-S3)
- **Exact canvas: 320 px wide × 480 px tall, portrait.** Matches `lv_obj_set_size(main_container,320,480)`.
- **Must ship in flash** (16 MB, but the wallboard shares it). Two viable encodings:
  - **Preferred: drawn in LVGL primitives** (rects, lines, label with the embedded font), ~0 image
    bytes, recolors for free per theme, crisp at native res. This is the **default deliverable**.
  - Fallback: a single **flat-color PNG/`LV_IMG_CF_TRUE_COLOR`** ≤ ~24 KB. If raster, it must be a
    *flat vector-style* render (no photographic grain) so it compresses and stays sharp.
- **No per-tick repaint** (`ui.cpp:192`, "Discrete state changes only"): the splash is drawn once,
  then replaced by the wallboard. No animation budget assumed beyond an optional single lamp fade.
- **Two theme variants required** (BRASS + PHOSPHOR), identical geometry, only token swaps. The panel's
  `disp_on_off` inversion footgun (per device memory) means **never rely on subtle near-black
  separation**: keep the board bg and panel a clear ≥2-step value apart.

### 1.3 Layout spec (ASCII wireframe of the 320×480 frame)
```
 320 px wide
┌────────────────────────────────────┐  ← 0px   border rail, 2px, BRASS.border
│                                    │
│            (◉)                     │  ← ~70px  jack mark, ~64px, BRASS.accent ring
│                                    │           on BRASS.panel disc
│   ████  ████  ████ █ █ ████ ████   │  ← ~150px POCKET-DIAL wordmark, BRASS.highlight
│   █  █ █  █ █    █ █ █    █  █      │           (LVGL label, large mono font)
│   ████  ████  ████ ███  ████  ██   │
│                                    │
│   ┌──────────────────────────┐    │  ← ~250px hairline sub-rule, BRASS.border
│   │  SYSOP TERMINAL          │    │           descriptor, BRASS.text, letter-spaced
│   └──────────────────────────┘    │
│                                    │
│        single-board SIP PBX        │  ← ~310px BRASS.text, smaller
│                                    │
│                                    │
│   ◆ Patching you through…          │  ← ~430px ONE lamp + the sanctioned boot line,
│                                    │           BRASS.accent diamond + BRASS.text
└────────────────────────────────────┘  ← 480px  border rail
```
Focal hierarchy: jack mark `(◉)` leads to the POCKET-DIAL wordmark, then SYSOP TERMINAL, then
*single-board SIP PBX*, then the boot line. Exactly **one** charm line (`Patching you through…`,
sanctioned by the flavor budget).
- **The only lit element is the `(◉)` ring and the `◆` lamp**, both in `accent`. Everything else is
  `border` / `text` / `highlight`. This obeys "the lamp is the accent."
- The wordmark + descriptor are color-independent: they carry 100% of meaning in pure value; on a
  washed-out or color-shifted panel the splash still reads. No status is encoded here, so no
  glyph/label pairing is *required*, but the `◆` before the boot line keeps the house style.

### 1.4 Generation prompt: BRASS variant
> Use only if rendering a raster fallback. Platform-agnostic; tuned for Flux / SDXL / Midjourney.

```
A flat vector-style boot splash for a retro telco "sysop terminal", portrait 320x480,
deep warm charcoal background (#161412). Centered top: a glowing brass-amber patch-panel
jack icon — a filled circle inside a ring, amber (#FFB020) on a slightly lighter charcoal
disc (#28241E). Below it, a bold blocky monospace wordmark "POCKET-DIAL" in bright brass
(#F5D696). Under that, a thin brass hairline rule (#B08438) and the letter-spaced label
"SYSOP TERMINAL" in warm brass (#D6B26E), then smaller text "single-board SIP PBX". Near
the bottom, a small amber diamond followed by "Patching you through…" in warm brass.
A 2px brass frame around the whole panel. Clean, minimal, high-contrast, no photographic
texture, no gradients except a soft glow on the amber jack, perfectly legible at small
size on a 3.5 inch IPS screen. Vintage operator switchboard mood, 1980s telco equipment.
--ar 2:3 --style raw
NEGATIVE: photorealism, skin, faces, people, busy texture, noise, drop shadows,
3D bevels, lens flare, watermark, gradient background, rainbow colors, red except none.
```

### 1.5 Generation prompt: PHOSPHOR variant
Identical geometry; swap tokens: board `#10140F`, jack/lamp **green `#40FF60`**, rails `#96823C`,
wordmark `#D2F0BE`, descriptor `#AAD296`. Same NEGATIVE list.
```
…same composition as BRASS… background deep charcoal-green (#10140F); the jack icon and
bottom diamond glow phosphor green (#40FF60); wordmark in pale phosphor (#D2F0BE);
"SYSOP TERMINAL" and sub-text in green (#AAD296); thin dim-brass rule and 2px frame
(#96823C). Green CRT monochrome-phosphor mood. --ar 2:3 --style raw
```

### 1.6 Acceptance checklist
- [ ] Wordmark reads "POCKET-DIAL" (one hyphen, all-caps) at 320×480, legible at 3.5".
- [ ] Exactly one lit accent color in frame; rails/text are brass/`border`, not accent.
- [ ] BRASS and PHOSPHOR variants are geometry-identical, token-swapped only.
- [ ] Survives value-only (grayscale) rendering, no meaning lost.
- [ ] No photographic grain; flat enough to draw in LVGL primitives or compress < 24 KB.
- [ ] Only flavor line present is `Patching you through…`; no extra copy.

## 2. ONBOARDING QR "CARD": 320 × 480, portrait

### 2.1 Purpose
First-run / "how do I configure this?" screen on the device. The redesign is SSH-first: the box has
no touch config, so the screen's job is to **hand the installer to the terminal**. The card shows brand
+ host + one instruction + the QR. (Today `ui.cpp:586,813` renders a `WIFI:` QR into a 99×99 canvas via
the `qrcode` lib at `ECC_LOW`, version 4; this card keeps that exact render path, only the payload and
chrome change.)

### 2.2 QR payload (locked)
- Encode an `ssh://` URI to the host, not Wi-Fi creds:
  `ssh://sysop@pocketdial.local` (firmware substitutes the live host/IP if mDNS is unresolved).
- Keep **`ECC_LOW`, version 4** to fit the existing 99×99 canvas buffer; the URI above is short enough.
  If a longer payload is ever needed, bump version and the canvas size together. Do **not** silently
  overflow the 99×99 buffer (`ui.cpp:584`).
- Quiet zone: the QR module render must keep ≥4-module white margin (`draw_qr` already paints a
  white field). Scanners need it.

### 2.3 Layout spec (ASCII wireframe)
```
 320 px wide
┌────────────────────────────────────┐  ← border rail, BRASS.border
│  (◉) POCKET-DIAL      ◆ READY      │  ← ~24px header: jack mark + wordmark (left),
│ ────────────────────────────────── │           ◆ READY lamp+label (right). hairline.
│                                    │
│           ┌──────────────┐         │  ← ~90px  QR on a WHITE field (scanner needs it),
│           │ ▛▀▌ ▐▀▜ ▛▀▀  │         │           the 99×99 canvas, centered, white quiet
│           │ ▌▞▖  ▟▄  ▐▙▖ │         │           zone. The ONLY white in the layout.
│           │ ▙▄▌ ▐▄▟ ▙▄▄  │         │
│           └──────────────┘         │
│                                    │
│      SSH here to configure         │  ← ~250px the instruction, BRASS.highlight, centered
│                                    │
│   ┌──────────────────────────┐    │  ← ~290px panel block, BRASS.panel face, brass border
│   │ HOST · pocketdial.local  │    │           monospace, colon column aligned
│   │ ADDR · 192.168.1.50      │    │
│   │ USER · sysop             │    │
│   └──────────────────────────┘    │
│                                    │
│  Scan, or: ssh sysop@…             │  ← ~410px fallback for no-camera installers, BRASS.text
│  ◆ operator on duty                │  ← ~445px the sanctioned tagline lamp, BRASS.accent
└────────────────────────────────────┘  ← border rail
```
- **`◆ READY` keeps the brand's glyph+label+color triad** (brand.md §3.1): the word READY is
  authoritative, `◆` reinforces, amber is removable. A monochrome panel still reads "READY".
- **QR is on the one white field in the whole product**, intentionally: scanners require high contrast,
  it is functional, not decorative, so it is exempt from the brass-only chrome rule.
- Two strings carry the job: `SSH here to configure` (instruction) and the `ssh sysop@…` fallback,
  so an installer **without** a QR-scanning camera is never stuck. Honesty/keyboard-first voice: "SSH",
  not "scan to connect"; no "tap".
- One sanctioned flavor line: `operator on duty`. Nothing else spends charm.
- PHOSPHOR variant: same geometry; rails/border become `PHOS.border`, instruction becomes
  `PHOS.highlight`, the `◆ READY` / `◆ operator on duty` lamps become `PHOS.accent` green. **QR stays
  black-on-white in both themes**: never tint a QR, tinting breaks scanners and the contrast guarantee.

### 2.4 Generation prompt (reference layout; the card is built in LVGL, not generated)
> This card is **drawn on-device** (it needs the live host/IP and a real QR). The prompt below is only
> for producing a *design comp / README figure*, not the shipped asset.
```
A flat retro telco onboarding card, portrait 320x480, deep warm charcoal (#161412) with a
2px brass frame (#B08438). Top row: a small amber jack icon (◉) and the wordmark
"POCKET-DIAL" in pale brass (#F5D696) on the left; an amber diamond with "READY" on the
right. Center: a crisp black-and-white QR code on a clean white card with a wide white
quiet-zone margin. Below the QR, centered bright-brass text "SSH here to configure". Under
it, a recessed darker panel (#28241E) with monospace lines "HOST · pocketdial.local",
"ADDR · 192.168.1.50", "USER · sysop" in warm brass (#D6B26E), colon column aligned.
Near the bottom: "Scan, or: ssh sysop@pocketdial.local" and an amber diamond with
"operator on duty". Vintage operator-switchboard equipment mood, flat vector style, high
contrast, perfectly legible at 3.5 inches. --ar 2:3 --style raw
NEGATIVE: photorealism, people, faces, busy texture, gradients (except faint amber glow),
3D bevels, colored QR code, tinted QR, low-contrast QR, watermark, exclamation marks.
```

### 2.5 Acceptance checklist
- [ ] QR encodes `ssh://sysop@pocketdial.local` (or live host), **ECC_LOW v4 ≤ 99×99 buffer**.
- [ ] QR is **pure black-on-white with ≥4-module quiet zone** in **both** themes (never tinted).
- [ ] `SSH here to configure` present; `ssh sysop@…` text fallback present for no-camera case.
- [ ] `◆ READY` and `◆ operator on duty` keep glyph+label, readable in grayscale.
- [ ] Host/Addr/User block is monospace, colon-aligned, fed from live device state.
- [ ] Says "SSH", never "tap/click/scan-to-connect"; one flavor line only.

## 3. README / MARKETING HERO: 2400 × 1350 (16:9)

### 3.1 Purpose
The repo's front-door image and any web/marketing use. Goal: **sell the "sysop terminal" aesthetic and
the embedded reality in one frame** (a single small board lighting up a glowing amber/green terminal).
Honest: it is a *single ESP32-S3 + a 3.5" screen*, not a rack. The hero should feel like a **night-shift
operator's bench**, not a data center.

### 3.2 Constraints
- **2400 × 1350 px, 16:9** (downscales cleanly to GitHub's ~1280-wide social card; keep the focal
  subject within the centered 1280×640 safe area).
- One hero composition, both palettes optional. BRASS is the canonical hero.
- The on-screen content must be real product: the actual ANSI hub or live monitor from
  `tui-style.md`, not invented UI. Inclusive-visuals note in §4 governs any hands/people in frame.

### 3.3 Composition spec
```
2400 × 1350 (16:9)            [ centered 1280×640 = social-card safe area ]
┌──────────────────────────────────────────────────────────────────────────┐
│  dark workshop bokeh, warm charcoal, faint brass glow                      │
│                                                                            │
│        ╔══════ amber CRT/terminal, ANSI hub on screen ══════╗              │
│        ║ POCKET-DIAL v3.0  [SYSTEM MANAGEMENT]   18:14:22    ║              │
│        ║ [1] MONITOR  [2] NETWORK  [3] PBX CONFIG …          ║   ← real    │
│        ║ ◆ ACTIVE  ◐ RINGING   CPU [██████░░░░] 30%          ║     ANSI    │
│        ╚═════════════════════════════════════════════════════╝              │
│                                                                            │
│   [ small ESP32-S3 board + 3.5" wallboard glowing (◉) in the foreground ]   │
│                                                                            │
│   POCKET-DIAL · SYSOP TERMINAL — single-board SIP PBX (lower-third, brass)  │
└──────────────────────────────────────────────────────────────────────────┘
```
Subject: the tiny board + its 3.5" wallboard (showing the §1 splash or the live monitor) in the
foreground; a warm amber terminal/CRT behind it showing the **real ANSI hub**. Story = *small box,
big operator energy.*
Lighting: single warm key from the screens (the lamp is the light source), deep falloff into
charcoal, chiaroscuro / neon-noir on a workbench. Shallow depth of field, the board tack-sharp,
background bokeh.
- **Lower-third title** in brass: `POCKET-DIAL · SYSOP TERMINAL — single-board SIP PBX`. No marketing
  superlatives, no exclamation marks (voice rule).

### 3.4 Generation prompt: hero (BRASS, canonical)
```
A moody product hero photograph, 16:9, of a tiny single-board computer (ESP32-S3) with a
small 3.5-inch portrait IPS screen, sitting on a dark workbench. The little screen glows
with a retro amber telco interface showing a glowing patch-panel jack icon and the
wordmark "POCKET-DIAL". Behind it, slightly out of focus, an amber-phosphor terminal/CRT
displays a vintage ANSI sysop menu with box-drawing borders and a "[SYSTEM MANAGEMENT]"
title bar in warm brass-amber text on deep charcoal. Single warm amber key light coming
from the screens, deep shadow falloff into near-black warm charcoal, neon-noir / nighttime
switchboard-operator mood. Shot on 85mm, f/1.8, shallow depth of field, the board tack
sharp with creamy bokeh background. Color palette: deep charcoal (#161412), warm brass
(#B08438), amber lamp glow (#FFB020). Premium, editorial, technical, restrained — like a
1980s telco equipment ad reshot today. 8k, commercial quality.
--ar 16:9 --style raw
NEGATIVE: rack of servers, data center, blue/cyan tech glow, cluttered desk, busy cables,
phones, people unless intentional, cartoon, lens dirt, heavy bloom, rainbow RGB lighting,
text errors, gibberish on screen, exclamation marks, watermark, logos other than POCKET-DIAL.
```
PHOSPHOR alt: swap amber for phosphor green `#40FF60`, board bg `#10140F`, rails `#96823C`, "green
CRT" mood; otherwise identical.

### 3.5 Acceptance checklist
- [ ] Subject reads as **one small board + 3.5" screen**, not a rack/data-center (honesty clause).
- [ ] On-screen content is the **real** ANSI hub/monitor, spelled correctly, brass-on-charcoal.
- [ ] Single warm light source = the screens; chiaroscuro falloff; shallow DoF.
- [ ] BRASS canonical; PHOSPHOR is a clean token swap.
- [ ] Lower-third title exact: `POCKET-DIAL · SYSOP TERMINAL — single-board SIP PBX`. No hype, no "!".
- [ ] Focal subject inside the centered 1280×640 social-card safe area.

## 4. Inclusive-visuals review (the few human-facing surfaces)

pocket-dial's product surfaces are **text + one icon + one QR**, so the inclusive-visuals footprint is
small but real. Guardrails:

- **No people are required anywhere.** The product story is the board + the terminal. If the **hero**
  (§3) ever shows a human (hands on a keyboard, an operator at the bench), follow:
  - Skin/representation: if hands appear, vary skin tone across marketing sets; never default to a
    single tone. Prefer **hands at a keyboard** over faces: it centers the *keyboard-first* promise and
    sidesteps tokenism. No gendered/"hacker in a hoodie" cliché.
  - No surveillance/menace framing (no dark-hacker tropes). The voice is a *calm night-shift
    operator*, not an intruder. Warm, competent, mundane-expert.
- **Accessibility carries into raster** (mirrors [`accessibility.md`](accessibility.md)):
  - Every status glyph in any rendered image keeps its **label** (`◆ READY`, `◆ ACTIVE`), never a bare
    colored dot. Validated against the brief's "never color alone" rule.
  - The splash/card must pass a grayscale check: convert to luminance; all text must still separate
    from background ≥ value-step the panel uses. (Guards the `disp_on_off` inversion footgun.)
  - QR contrast is **non-negotiable black-on-white**, the single most accessibility-sensitive bitmap;
    never themed, never tinted, always with quiet zone.
- Honest representation: marketing must not imply trunks, queues, conferencing, a rack, an SD card,
  or voicemail-in-v1 (brief §3, honesty clause). Show only what ships: extensions, ring groups, IVR,
  forward/DND/transfer/star-codes, CDR, live monitor.

## 5. Asset register (hand-off summary)

| Asset | Canvas | Themes | Ship path | Owner of final pixels |
|---|---|---|---|---|
| Splash / boot art | 320×480 | BRASS + PHOSPHOR | LVGL primitives (preferred) or ≤24 KB flat PNG in flash | firmware (UI Designer wires it) |
| Onboarding QR card | 320×480 | BRASS + PHOSPHOR (QR mono in both) | LVGL layout + 99×99 QR canvas, live payload | firmware (`ui.cpp` draw_qr path) |
| README / hero | 2400×1350 | BRASS canonical (+PHOSPHOR alt) | PNG/WebP in `/docs` or repo root | repo (external render) |

Out of scope (text, not raster): login banner, hub, all config panels, live monitor, help screens,
owned by `brand.md` / `tui-style.md`. Do not generate these as images.

## Inclusive review

> Reviewer: Inclusive Visuals Specialist. This section does not replace the prompts in §1 through §4;
> it tightens them. The existing §4 guardrails are correct in spirit but under-specified for the way
> foundational image models actually fail. Below: (a) where bias would creep in, (b) drop-in tightened
> prompt language, (c) a reusable negative library, (d) a review gate. Apply these fragments on top of
> the prompts already written; do not rewrite the originals.

### IR.1 Bias surface assessment (what these prompts will actually trigger)

pocket-dial's human footprint is genuinely tiny. **The splash (§1) and the QR card (§2) contain no
people and must stay that way.** The only place a person can appear is the **README hero (§3)**, and only
behind the `people unless intentional` clause. That single conditional is the entire risk surface, plus
the cross-cutting "AI weirdness" risk on every screen (gibberish script, warped hardware, false UI).

| Surface | Person risk | Real model-failure mode to pre-empt |
|---|---|---|
| §1 Splash | none (people negative-prompted) | invented gibberish text near the wordmark; rainbow/2nd accent leak |
| §2 QR card | none | **tinted/warped QR** (accessibility-critical), invented extra glyph rows |
| §3 Hero | **optional human** | clone faces, single default skin tone, "hacker in a hoodie", menace lighting, extra fingers on the keyboard, gibberish on the CRT, wrong board form-factor |

The verdict: the safest hero ships **with no person at all** (board + terminal only), which §3 already
supports. *If* a human is added, it must be **hands at a keyboard, never a face/figure**, and must carry
the tightened language in IR.2. A face/figure in this product is over-reach and reintroduces exactly the
tokenism §4 warns against, so we constrain the *only* sanctioned human depiction to anonymous,
competent hands.

### IR.2 Tightened hero language: the "hands at the keyboard" variant (append to §3.4)

> Use **only** if the hero includes a human. Append this block to the §3.4 BRASS prompt (and the PHOSPHOR
> swap). It replaces the vague `people unless intentional` with an explicit, dignified, non-stereotyped
> human spec. Faces and full figures remain **out**.

```
[OPTIONAL HUMAN — HANDS ONLY]: If a person is shown, show ONLY a pair of adult hands resting
on or typing at a normal mechanical keyboard in the foreground, framed from mid-forearm down,
no face and no torso in frame. The hands are relaxed and competent, mid-keystroke, doing
ordinary work — not clutching, not hovering "hacker" style. Natural, realistic hands with
exactly five fingers each, correct proportions, plausible knuckles and nails, no rings/logos.
Even, warm key light on the hands from the screen; calm night-shift-operator mood, not
secretive or menacing. Skin tone is unremarked and natural; across a marketing set, vary skin
tone, hand size, and age (include visibly older hands with natural texture) so no single
default tone or age recurs. A subtle mobility aid in the deep background (e.g. a cane hooked on
the bench, or the armrest of a supportive chair) is welcome but never the subject and never
glitched. The keyboard is a real, ordinary keyboard with consistent, correctly-spaced keycaps.
```

Why each clause is load-bearing (memory of how the models fail):
- *"hands… no face… no torso"* removes the entire face-tokenism / "clone diverse crowd" failure mode at
  the source; you cannot stereotype a face you do not render. Also reinforces the *keyboard-first* promise.
- *"exactly five fingers each, correct proportions"*: Flux/SDXL/Midjourney still mangle hands; naming the
  count and proportions measurably reduces six-finger / fused-knuckle artifacts.
- *"unremarked and natural… vary across a set"* defeats both the **default-tone bias** (models trend to
  one tone) **and** the **over-correction failure** (a model told to be "diverse" in one image produces a
  tokenized, posed result). The fix is set-level variance, not in-frame quota.
- *"include visibly older hands"*: age is the most-omitted axis in tech imagery; calling it out prevents
  the perpetual-25-year-old default.
- *"mobility aid… never the subject and never glitched"*: disability representation must be incidental and
  dignified, and **video/photo models warp canes/wheels** when they are foregrounded; keeping it in the
  deep background renders it cleanly and avoids inspiration-porn framing.
- *"calm night-shift operator, not secretive or menacing"* directly cancels the "dark hacker in a hoodie"
  archetype the prompt's noir lighting could otherwise pull toward.

### IR.3 Reusable inclusive + anti-artifact negative library (apply to ALL §1–§3 prompts)

Append these to the existing NEGATIVE lines. They are grouped so each prompt takes the relevant rows; the
**Universal** block goes on every prompt (splash, card, hero).

```
[NEGATIVE · UNIVERSAL — every prompt]:
gibberish text, fake/garbled letterforms, invented non-Latin glyphs, misspelled wordmark,
extra UI rows, false menu items, rainbow or second accent color, RGB gamer lighting,
watermark, signature, brand logos other than POCKET-DIAL.

[NEGATIVE · HUMAN — only if a person is shown (§3)]:
faces, portraits, full figures, torsos, eye contact, posed model, stock-photo smile,
"hacker in a hoodie", hooded figure, balaclava, mask, surveillance/menace mood, dark-web
aesthetic, six fingers, extra fingers, missing fingers, fused fingers, deformed hands,
mangled knuckles, claw hands, doll-like skin, plastic skin, uniform/cloned identical people,
single default skin tone across a set, exoticizing or "ethnic-themed" lighting, costume or
cultural props used as decoration, inspiration-porn framing of a mobility aid, glitched or
floating wheelchair/cane/prosthetic, all-young-adult cast.

[NEGATIVE · QR — §2 card only]:
colored QR, tinted QR, gradient QR, low-contrast QR, QR without quiet zone, blurred QR,
QR with embedded logo, distorted/warped QR modules.

[NEGATIVE · HARDWARE — §3 hero only]:
server rack, data center, blade servers, multiple boards, laptop, smartphone, desktop tower,
blue/cyan tech glow, cluttered cables.
```

### IR.4 Cultural-neutrality + honesty notes (refines §4, does not replace it)

- **Culturally neutral by construction.** pocket-dial carries **no culturally-specific imagery, script,
  symbol, flag, or motif**, and must not acquire one by hallucination. The wordmark is the only text;
  everything else that *looks* like text in a render is a defect (see Universal negative). This sidesteps
  the "gibberish foreign script" and "invented cultural symbol" failure modes entirely: the correct number
  of cultural symbols in this product is **zero**.
- **No geography to get wrong.** The hero is a *workbench at night*, deliberately placeless: no skyline,
  no national context, no "office in [city]" anchoring. This is intentional: it removes the architectural-
  accuracy / "exoticized locale" risk class instead of trying to render it correctly.
- **The lamp is the only warmth, not a person.** The emotional center is the glowing screen, not a human
  subject, which is *why* the hero reads as inclusive: it does not ask any one demographic to "be" the
  product. Keep it that way; a human is an optional accent, never the hero's meaning.
- Honesty (carries from §4): no rack, trunk, queue, SD card, conferencing, or voicemail-in-v1 implied
  in any frame; the on-CRT content is the **real** ANSI hub/monitor from `tui-style.md`, spelled correctly.

### IR.5 Inclusive review gate (run before any hero with a human ships)

A render passes only if **all** are true; any failure is a re-prompt, not a touch-up.

- [ ] **No face / no figure.** If a human is present, it is hands-only, mid-forearm-down, no torso, no eyes.
- [ ] Hands are anatomically correct: five fingers per hand, plausible proportions, no extra/fused/
      missing digits, no plastic/doll skin.
- [ ] **No archetype.** No hoodie/hacker/menace/surveillance framing; mood is calm competent night-shift.
- [ ] **Set-level variance.** Across the marketing set, skin tone, hand size, and **age** visibly vary; no
      single default tone and no all-young cast.
- [ ] **Mobility aid (if any) is incidental and clean**: background, unglitched, not inspiration-porn.
- [ ] **No gibberish / no invented script / no cultural prop.** Only correct copy is the POCKET-DIAL
      wordmark and the real ANSI UI; zero cultural symbols (correct count is zero).
- [ ] **QR is pure black-on-white** with quiet zone, untinted, undistorted (guards the §2 card).
- [ ] Grayscale pass: convert to luminance; every label still separates from background; every status
      stays glyph + label, never a bare colored dot (mirrors §4 + `accessibility.md`).
- [ ] Honesty pass: no rack/trunk/queue/SD/voicemail implied; on-screen UI is real and correctly spelled.

### IR.6 What did NOT need changing (so the next agent doesn't "fix" it)

- §1 Splash and §2 QR card are **correctly people-free**; do **not** add humans to them for "warmth."
- The §4 guardrails (skin-tone variance, no-menace, glyph+label, QR contrast, honesty) are **right** and are
  *extended* here, not overruled.
- The **default, recommended hero is still person-free** (board + terminal). IR.2 is an *opt-in* path with
  guardrails, not an instruction to add a person.
