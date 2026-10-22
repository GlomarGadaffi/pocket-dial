# Shared console theme

File: `shared-theme.css`, 6,991 bytes (6.8 KiB), UTF-8, ASCII only. Written to ui-build-brief §7b (ISA-101 HMI), which supersedes §7a. Both products inline the same file unchanged.

## What it is

- **Grey when nominal, colour by exception.** No green token. P1 critical/fault is a solid `#ff2200` fill with black bold text. P2 warning/degraded is a solid `#ffaa00` fill with black text. Live traffic (active call, off-hook, RTP) is a `#00aaff` cyan border.
- **Geometry.** Zero border-radius everywhere. Panes share 1px `#333333` hairlines, with negative margins on `.pane` and collapsed borders on `table`. Cells and containers pad at most `4px 6px`. A fixed 30px alarm bar sits at the top and a fixed 32px F-key bar at the bottom. The body padding (30px / 32px) clears them; it is a spacer, not a cell.
- **Type.** 12px system sans for chrome. `--f-mono` with tabular-nums for numbers, IPs, ports, MACs, timers and SIP states. Silkscreen labels (`legend`, `.lbl`) are 10px uppercase mono, letter-spacing .08em.
- **Readouts.** `.well` is the sunken `#050505` well with the specified bevel borders. The value is right-aligned mono. `.unit` sits outside to the right in `#666666`.
- **Annunciator.** `.annunciator` is a 5-column grid with shared hairlines. Nominal `.tile` is `#181818` with `#5c5c5c` text. `.tile.p1` and `.tile.p2` trip to full fills with a solid 1px inner ring (`box-shadow: inset 0 0 0 1px #000`).
- **Status.** `.st` styles only. The markup supplies the literal bracketed glyph and word: `[ · IDLE ]`, `[ ▲ TX/RTP ]` (`.st.live`), `[ ▲ WARN ]` (`.p2`), `[ ◆ FAULT ]` (`.p1`). CSS adds no pseudo-element content.
- **Controls.** Buttons have 1px light/dark bevels that invert at 0 ms on `:active`. `.btn-arm.armed` shows the 45° hazard stripe as a border-image. `.btn-exec` is the final stage. `.p1.unack` blinks with `steps(1)` between solid red and black/red; reduced-motion stops it.
- **Mimic lines.** `.bus-h` and `.bus-v` are 2px orthogonal `#666666` lines; `.live` makes them cyan.
- **Navigation.** `.nav` rows and `.tabs` use an inverse fill for the current item. `.kv` rows stack under 480px. `.toast` is a persistent sticky region, with `.p1` / `.p2` variants, that sits above the F-key bar.
- No drop shadows (apart from the tile ring), translucency, backdrop filter, or motion other than the blink. The only gradient is the hazard stripe.

## Contrast

Computed with the WCAG 2.x relative-luminance formula, from the colours in the file. Pass thresholds: 4.5:1 for text, 3:1 for non-text.

| Text | Background | Ratio | Result | Where |
|---|---|---|---|---|
| #a0a0a0 | #121212 | 7.16 | pass | body, links, nav rows, kbd |
| #a0a0a0 | #1c1c1c | 6.52 | pass | alarm bar, panes, buttons, th, legend, lbl, toast, st |
| #a0a0a0 | #050505 | 7.79 | pass | well value, inputs |
| #a0a0a0 | #333333 | 4.83 | pass | button and nav hover (lowest passing text pair) |
| #121212 | #a0a0a0 | 7.16 | pass | :active invert, current nav, tabs, F-key current |
| #000000 | #ff2200 | 5.48 | pass | P1 fills, btn-exec, tile.p1 |
| #000000 | #ffaa00 | 11.00 | pass | P2 fills, tile.p2 |
| #ff2200 | #000000 | 5.48 | pass | blink off-phase |
| #ffaa00 | #1c1c1c | 8.93 | pass | armed button text |
| #ffaa00 | #333333 | 6.62 | pass | armed button hover |
| #666666 | #1c1c1c | 2.97 | **fail** | `.unit`; disabled controls (exempt) |
| #5c5c5c | #181818 | 2.66 | **exception** | nominal annunciator tile |

Non-text pairs:

| Colour | Background | Ratio | Result | Where |
|---|---|---|---|---|
| #00aaff | #121212 | 7.31 | pass | live border, live bus |
| #00aaff | #1c1c1c | 6.65 | pass | live border on a panel |
| #666666 | #121212 | 3.26 | pass | bus lines |
| #3a3a3a | #1c1c1c | 1.50 | below 3:1 | button bevel; the label carries the control |
| #333333 | #121212 | 1.48 | below 3:1 | hairlines; decorative separators |

**The lowest passing text pair is #a0a0a0 on #333333 at 4.83:1.**

**Deliberate exception: the nominal tile (#5c5c5c on #181818) is 2.66:1, not the approximately 2.9:1 in the brief.** It fails both 4.5:1 and 3:1, and this is intended. §7b makes nominal tiles recede so that faults stand out. Each tile's state is also stated in text, and a faulted tile trips to a full P1 or P2 fill. No information depends on the dim text.

Also below 4.5:1, and needs an owner decision: `#666666` on `#1c1c1c` is 2.97:1. §7b mandates `#666666` for `.unit`, so units on panels fail AA. Disabled controls are exempt. Options: accept this for units, or set units to `--text`.

## Inlining

1. **pocket-dial:** the file is the first block of `web/app.css`, verbatim. The page needs `<meta charset="utf-8">` before the `<style>`.
2. **AdBlocker:** one C string literal per CSS line, wrapped as `"<line>\n"`. Regenerate from the file; do not hand-edit. Both products are updated in the same change.

Constraints checked on the final file: ASCII only, no backslashes, no double quotes. There are seven `%` signs: `width:100%` (2), `height:100%` (1), and four keyframe stops (`0%,49%`, `50%,100%`). Any printf-style formatting must double all seven.

## Not expressible in CSS

- The 10 s auto-disarm of EXEC, and the two-stage ARM/EXEC state.
- ACK on the alarm bar (client-side, in sessionStorage, until the state changes).
- F-key `preventDefault` and the Alt+digit fallback.
- Applying `.p1.unack` to an unacknowledged P1. The blink exists only when the class is present.
- The bracketed status text itself, which is markup.
- Which faults appear on the alarm bar.
- The "no hero, no centred layout" rule. CSS does not enforce it.

Layout note: the annunciator uses 5 columns for 10 tiles (2×5). A 1×8 or 2×6 grid cannot fill 10 tiles evenly, and a short last row would break the shared hairlines. At 400px, the nine F-key labels truncate.
