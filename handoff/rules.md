You own ONE file (given below). Edit only that file. Do not edit anything else,
do not run git add/commit/push, do not touch src/, main/, tests/, tools/, .github/ or root files.

== Step 1: findings ==
Your findings are in message 2, under your file's heading (===FILE ...===). Each has
line, severity, category, claim, evidence and fix. Treat them as claims to CHECK, not orders.
For each one: open the code it cites, confirm or refute it yourself, and then:
- confirmed: fix the text (minimal, accurate; describe what the code does now);
- refuted: leave the text, and record the claim and the reason under rejected;
- the code itself looks wrong relative to an explicit stated requirement: still document
  what the code does now, and record it under needs_decision (do not change code).
Docs describe the code as it is. Never change code to match a doc.
Where a doc quotes a hand-typed number that drifts (test counts, route counts), replace it
with the command that measures it, or with a pointer to the tool that does (for example
tests/tools/check_test_count.py if it exists). Do not restate the number.

== Step 2: pinned strings (do this BEFORE editing) ==
Tests assert exact text in docs. Find them: grep -rn "<your file basename>" tests tools
(Python tests read docs at runtime; C++ tests usually only mention docs in comments).
Known: docs/API.md is asserted by tests/tools/test_dialplan_emergency_alias_doc.py (exact
sentences, flattened whitespace), tests/tools/test_media_tx_instrument.py (the "| `mediaTx` |"
row and the "> **Task-Watchdog coverage" note), and tests/tools/test_didmap_staging_wiring.py
(the "| [`/api/did-mapping`]" PUT and DELETE rows containing "staged" and "#986", and the text
"`didMappings`"). Any string a test asserts must survive EXACTLY, with its table row shape.
If a finding would change a pinned string, do not change it; say so under needs_decision.

== Step 3: restyle (skip if FIX_ONLY) ==
The target is the house style used by README.md and the project site: plain Markdown.
- One H1 with the title, then a one- or two-sentence purpose line, then sections (H2/H3).
- Plain, direct sentences. No emoji, no badges, no ALL-CAPS labels, no decorative banners.
- Decorative GitHub alerts ("> [!IMPORTANT]") become plain paragraphs. Keep a warning only
  where it carries real safety or data-loss content, as a bold lead-in ("**Warning:** ...").
- Remove revision-history narration ("Earlier revisions said...", "Corrected.", "was X, now Y",
  "this replaced..."). Git history keeps it. Keep issue numbers that identify current behaviour
  (for example "(#441)"); drop ones that only narrate a change.
- Add at most two Mermaid diagrams, and only where the file already describes a flow, a
  sequence, a state machine, a topology or a decision path, and the diagram makes the text
  clearer. Each diagram must match the prose exactly. Use ```mermaid fences.
- Keep every table, command, config key, NVS key, port, dial code, HTTP route, default,
  code span and issue number that is still true. Tables that tests pin keep their row shape.
- Keep verbatim code blocks byte-for-byte. Keep all relative links, and make sure each
  still resolves.
- Long files (API.md, tui-style.md, walkthrough.md, THREAT_MODEL.md, PROVISIONING.md,
  INCIDENT_PLAYBOOK.md, API_TESTS.md, TROUBLESHOOTING.md, OTA.md): restyle section by
  section with Edit. Do not rewrite a 300-line-plus file in one Write.
- Before you start, list the file's code spans and issue numbers (grep -o). After you finish,
  check that nothing disappeared except what a confirmed finding removed. Record any other
  loss in dropped_content; there should be none.

== Step 4: validate (required) ==
Run: node validate.js (message 1) <your file>
It renders every Mermaid block, checks relative links, and checks code fences. It must
print "ok":true. Fix anything it reports and rerun. Set validator_ok accordingly.
For docs/flasher/index.html (FIX_ONLY), also load it headless and confirm no page errors.

Return the JSON per the schema. Be exact about counts; findings_examined must equal the
number of audit findings you were given.