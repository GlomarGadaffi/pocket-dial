=== FILE docs/design/00-brief.md (3 findings) ===
- line 32 [medium/stale] CLAIM: Lists voicemail as 'v2 (later) ... (needs a new RTP record path)', i.e. not in v1 and not built.
  EVIDENCE: CHANGELOG.md:49, in the '## v1.5.0-rc.1 - 2026-10-02' section (line 36), reads 'Per-extension voicemail, deposit and retrieval MVP (#261; #246)'. main/CMakeLists.txt:202-207 compiles src/SIP/VoicemailLeg.cpp, VoicemailArchive.cpp and VoicemailMenu.cpp into the firmware. src/SIP/PoolConfig.hpp:393-407 defines voicemail caps; src/SIP/RequestsHandler.cpp:3941-4039 runs the voicemail menu.
  FIX: State voicemail as a shipped MVP (#246) and drop the 'needs a new RTP record path' premise, or explicitly scope the redesign's voicemail UI out.
- line 3 [medium/stale] CLAIM: Calls itself the 'single source of truth' and makes the SSH-first sysop TUI the v1 deliverable (line 28: 'v1 (this redesign): SSH TUI sysop terminal').
  EVIDENCE: The SSH TUI was deleted: docs/THREAT_MODEL.md:354 'SSH was a third; it is gone', :383 'SSH removed, not hardened'; CHANGELOG.md:2949 '### Removed - SSH sysop terminal'. README.md:3-7 carries a HISTORICAL banner for this exact surface; the brief has none.
  FIX: Add the same historical banner to the brief, or rewrite sections 1, 3 and 6 for the non-SSH reality.
- line 66 [medium/wrong-fact] CLAIM: PHOSPHOR board background is #10140F, described as 'pulled verbatim' from ui.cpp PALETTES[] (also README.md:61, imagery.md:39, :124, :127, :281).
  EVIDENCE: main/ui/ui.cpp:51 is LV_COLOR_MAKE(16, 20, 16) = #101410, not (16,20,15) = #10140F. The other PHOSPHOR values match the source.
  FIX: Change #10140F to #101410 in all five places, or change ui.cpp and say so.
=== FILE docs/design/README.md (5 findings) ===
- line 116 [medium/wrong-fact] CLAIM: ABOUT honesty card copy reads 'voicemail in v2'.
  EVIDENCE: Same evidence as the brief finding: voicemail is in v1.5.0-rc.1 (CHANGELOG.md:49) and compiled in (main/CMakeLists.txt:202-207). The card would tell operators a shipped feature is absent.
  FIX: Make the card state the shipped voicemail MVP (#246), or reword it to 'voicemail UI deferred'.
- line 67 [medium/wrong-fact] CLAIM: PHOSPHOR 'dim / UNREACH' is #16201C.
  EVIDENCE: main/ui/ui.cpp:57 (PHOSPHOR jack_empty) is LV_COLOR_MAKE(22, 28, 22) = #161C16. The BRASS value #1E1B17 matches ui.cpp:45 exactly, so only the PHOSPHOR value is wrong.
  FIX: Use #161C16.
- line 132 [medium/stale] CLAIM: Says tui-style.md 'never rendered' the Add-ring-group create modal and the forward-to-group affordance (walkthrough F3/F4) and marks this 'Open for engineering'.
  EVIDENCE: docs/design/tui-style.md:624 is '3.6.2 Add Ring Group: CREATE modal' and :757 is '3.7.2 Forward-to-GROUP: target picker'. Both are rendered.
  FIX: Mark item 3 resolved and point to tui-style sections 3.6.2 and 3.7.2.
- line 57 [low/wrong-fact] CLAIM: 'DND stays amber in both themes (ui.cpp L61)'. brand.md:259 says 'see ui.cpp line 61'.
  EVIDENCE: ui.cpp:61 is the closing '};' of PALETTES[]. The DND entries are ui.cpp:46 (BRASS) and :58 (PHOSPHOR). The claim itself is correct.
  FIX: Cite ui.cpp:46 and ui.cpp:58 in both places.
- line 15 [low/wrong-fact] CLAIM: 'The entry point for the ten Phase-A deliverables'.
  EVIDENCE: Index rows 1 to 9 are nine deliverables; row 0 is the brief. The brief's section 7 deliverables table lists nine.
  FIX: Change to 'nine Phase-A deliverables'.
=== FILE docs/design/accessibility.md (5 findings) ===
- line 67 [medium/dead-link] CLAIM: The integrity-flag and CDR-answered rows say 'see A11Y-4' for their glyph fallbacks (also line 70; checklist item at line 416).
  EVIDENCE: A11Y-4 is never defined. The file defines only A11Y-1 to A11Y-3, and every A11Y-4 hit is a reference.
  FIX: Add the A11Y-4 section with the glyph-to-ASCII fallback table, or inline the fallbacks.
- line 415 [low/inconsistent] CLAIM: Checklist says 'verified section 1.2, all 17 states'.
  EVIDENCE: The section 1.2 table (lines 59-74) has 16 state rows.
  FIX: Change to 16 states, or add the missing row.
- line 24 [low/inconsistent] CLAIM: Verdict reads '2 BLOCKING issues, 4 serious'.
  EVIDENCE: Only three items are labelled serious: A11Y-3 (line 190), F1 (line 318) and section 4.3 (line 387). The closing summary (line 459) lists the serious set as A11Y-3 and F1/4.3.
  FIX: Correct the count to 3, or label the fourth serious item.
- line 452 [low/wrong-fact] CLAIM: 'The persona doc (section 422-424) flags this audit as the joint owner of the monochrome / color-blind-sim / screen-reader spot-check.'
  EVIDENCE: That text is at docs/design/personas.md:415-417 (section 6, validation plan, item 3). Lines 422-424 are open research questions.
  FIX: Cite personas.md section 6, item 3 (lines 415-417).
- line 318 [low/inconsistent] CLAIM: Uses F1, F2, F3 for accessibility focus findings (also lines 326 and 332).
  EVIDENCE: docs/design/walkthrough.md uses F1 to F15 for friction items, and README.md:32 indexes that set, including F3/F4 at README.md:132. The same IDs mean different things across the two docs.
  FIX: Rename the accessibility items (for example AF1 to AF3).
=== FILE docs/design/brand.md (5 findings) ===
- line 194 [medium/wrong-fact] CLAIM: Says the box has 'no voicemail in v1' (also line 287 bans 'voicemail-in-v1' from strings and line 291 says 'voicemail arrives in v2').
  EVIDENCE: Same as the brief finding: voicemail ships in v1.5.0-rc.1 (CHANGELOG.md:49) and is compiled in (main/CMakeLists.txt:202-207). The honesty clause at brand.md:291 says 'never imply capabilities we don't have', and these lines state the reverse.
  FIX: Restate the voicemail status to match shipped firmware in lines 194, 287 and 291.
- line 25 [low/stale] CLAIM: Lists POCKETDIAL_OPEN_REGISTRAR as a live code-identifier example in the canonical spelling table.
  EVIDENCE: src/SIP/RequestsHandler.hpp:10 says 'registrar is retired (#500). The old POCKETDIAL_OPEN_REGISTRAR #define ...'. No live definition exists at 7bcf952f.
  FIX: Use POCKETDIAL_MAX_CLIENTS (src/SIP/PoolConfig.hpp:35) as the example.
- line 60 [low/wrong-fact] CLAIM: The login-banner nameplate is '11 lines tall, 64 columns wide'.
  EVIDENCE: The block at lines 64-71 is 8 lines. Its rows measure 62 to 67 columns.
  FIX: Correct to 8 lines and at most 67 columns, or redraw the nameplate.
- line 125 [low/inconsistent] CLAIM: The SSH login banner is a fixed-width box that fits the 78-column rule (lines 102 and 279).
  EVIDENCE: Rows 125 and 129 measure 77 columns. Rows 118, 119 and 122 measure 80. The frame is 79 including a leading space. Lines 102 and 279 cap the banner at 78 columns.
  FIX: Pad every row to one width of at most 78 columns.
- line 162 [low/inconsistent] CLAIM: ASCII fallback maps the diamond glyph to [*] (also used in the mono banner at line 151).
  EVIDENCE: brand.md:4.5 maps ACTIVE to <*>; tui-style.md section 1.5 maps the diamond to <*>; README.md:76 maps it to <*>; accessibility.md:63 maps READY to <*>.
  FIX: Use <*> in line 162 and line 151, or record the split as intentional.
=== FILE docs/design/far-leg-adapter.md (3 findings) ===
- line 55 [low/unverifiable] CLAIM: '#938 reports 168,752 B free on 3ee4aa6d' (repeated at lines 201 and 283).
  EVIDENCE: Commit d268707 cites #938, but the figure 168,752 does not appear anywhere in the repo at 7bcf952f.
  FIX: Cite the issue comment URL for the figure.
- line 57 [low/unverifiable] CLAIM: #942 is the committee verdict 'design first, sequenced', and the design-first block is glomar-51's 2026-10-09 comment.
  EVIDENCE: No commit or file in the repo references #942 (git log and grep both return nothing). This is GitHub-only.
  FIX: Mark these as GitHub-sourced and link them.
- line 198 [low/unverifiable] CLAIM: '#693's count (23 lines in TAC.cpp, 2 in AnchorWedge.hpp) still holds'.
  EVIDENCE: The #693 grep is not in the repo. A field-name grep over src/SIP/TelephonyAnchorClient.cpp returns 72 lines and over src/SIP/AnchorWedge.hpp returns 6, so the 23/2 figure depends on a pattern the reader cannot reproduce.
  FIX: Quote the exact #693 grep pattern next to the counts.
=== FILE docs/design/federation.md (0 findings) ===
(no findings; restyle only)
=== FILE docs/design/https-dashboard.md (2 findings) ===
- line 60 [low/wrong-fact] CLAIM: isSameOrigin 'accepts only the device IP, 192.168.4.1, pocketdial.local, localhost'.
  EVIDENCE: src/Helpers/HttpServer.cpp:4201 also accepts 127.0.0.1.
  FIX: Add 127.0.0.1 to the list, and to the section 7 item 5 test.
- line 83 [low/unverifiable] CLAIM: The 20,480 B TLS record-buffer figure is from ~/w/c699-build-heap-poisoning/sdkconfig; IDF paths are ~/esp/esp-idf-v6.0.1/components/ (line 5).
  EVIDENCE: Both paths are outside the repo and cannot be checked from this checkout. The doc itself says the sdkconfig is from an old worktree, not main.
  FIX: Cite a committed path, or mark the figure as off-repo.
=== FILE docs/design/imagery.md (4 findings) ===
- line 172 [medium/inconsistent] CLAIM: Locked card and splash copy is 'SSH here to configure' with an 'ssh sysop@...' fallback (also lines 188, 204, 217).
  EVIDENCE: The SSH server was deleted (docs/THREAT_MODEL.md:354; CHANGELOG.md:2949), and README.md:3-7 calls the folder historical. The firmware already shows 'SSH HERE TO CONFIGURE' on the reach strip (main/ui/ui.cpp:77 comment, :516 label), so a stale instruction is on the shipped display.
  FIX: Decide whether an SSH entry point returns. If not, change this copy and flag ui.cpp:516 as a stale user-facing string.
- line 67 [low/wrong-fact] CLAIM: Quotes the comment 'Discrete state changes only' at ui.cpp:192 as the reason there is no per-tick repaint.
  EVIDENCE: That phrase does not appear in main/ui/ui.cpp. The nearest comment is ui.cpp:169 ('discrete, and ui_update_* only touches objects whose content actually changed'). ui.cpp:192 is 'if (state == UI_CALL_ACTIVE) {'.
  FIX: Cite ui.cpp:169 and quote it exactly.
- line 146 [low/wrong-fact] CLAIM: 'Today ui.cpp:586,813 renders a WIFI: QR into a 99x99 canvas' and the buffer overflow guard is at 'ui.cpp:584' (line 155).
  EVIDENCE: At HEAD (identical to 7bcf952f for this file), ui.cpp:586 is blank, :813 is a PIN-grouping loop and :584 is 'apply_theme();'. The WIFI payload is ui.cpp:367, the qrcode_initText ECC_LOW v4 encoder is :342, and the 99x99 onboarding buffer and canvas are :633 and :639.
  FIX: Cite ui.cpp:342, :367, :633 and :639 instead.
- line 70 [low/unverifiable] CLAIM: 'The panel's disp_on_off inversion footgun (per device memory)' (repeated at line 308).
  EVIDENCE: The claim rests on 'device memory' and is not traceable to any file in the repo.
  FIX: Cite the source of the footgun, or drop the claim.
=== FILE docs/design/narrative.md (3 findings) ===
- line 62 [low/dead-link] CLAIM: PIN never-echo rule is cited as brand section 4.6 (also lines 101 and 107).
  EVIDENCE: docs/design/brand.md has section headings only up to 4.5 and contains no never-echo or PIN rule.
  FIX: Point these cites at the section that states the rule, or add the rule to brand.md and cite that.
- line 72 [low/unverifiable] CLAIM: The login banner is described as the firmware sshd greeting.
  EVIDENCE: grep for sshd, libssh or dropbear across src/, main/, sdkconfig.defaults* and CMakeLists.txt finds nothing; the banner and PIN strings do not appear in src/ or main/.
  FIX: Describe the banner as a planned redesign surface, or cite the code that emits it.
- line 10 [low/wrong-fact] CLAIM: The on-device palette is cited as main/ui/ui.cpp lines 39-64.
  EVIDENCE: ui.cpp PALETTES[] spans lines 36-62 (struct opens at 36 and closes at 62); lines 63-64 are globals.
  FIX: Cite lines 36-62.
=== FILE docs/design/personas.md (7 findings) ===
- line 213 [medium/wrong-fact] CLAIM: Call outcomes are listed as answered / busy / no-answer / cancelled / failed, and the D8 mockup shows no-answer (line 356).
  EVIDENCE: src/SIP/CallDetailRecord.hpp:23-30 defines Answered, Busy, Cancelled, Unavailable, Failed; cdrResultToString returns unavailable (line 39). tui-ia.md section 6.2 already uses the correct vocabulary.
  FIX: Replace no-answer with unavailable in R2 and in the D8 mockup.
- line 5 [low/inconsistent] CLAIM: Hub matrix is shown with [6] ADDONS (also line 258), which conflicts with the IA.
  EVIDENCE: docs/design/tui-ia.md lines 46-49 rename [6] ADDONS to [6] ABOUT, and tui-style.md section 3.2 uses ABOUT.
  FIX: Use [6] ABOUT here, or note that ADDONS is the brief's original name.
- line 20 [low/wrong-fact] CLAIM: src/SIP/RequestsHandler.* is said to hold the per-extension DND map.
  EVIDENCE: The _dnd map is declared in src/SIP/PbxFeatureConfig.hpp:221; RequestsHandler.hpp has no _dnd member.
  FIX: Cite src/SIP/PbxFeatureConfig.hpp:221 for the DND map.
- line 158 [low/wrong-fact] CLAIM: Firmware anchor AdminAuth::hashPin for the admin PIN hash.
  EVIDENCE: No symbol named hashPin exists in src/ or main/. The hashing helper is hashSecret, defined at src/Helpers/AdminAuth.cpp:562.
  FIX: Replace the anchor with AdminAuth::hashSecret.
- line 198 [low/stale] CLAIM: The prompts partition is described as 3.88 MB.
  EVIDENCE: partitions.csv prompts row sets offset 0xC40000 and size 0x3BF000 (about 3.75 MiB), after the coredump partition took 128 KB (issue 382 note in the same file). docs/design/00-brief.md line 34 repeats the stale 3.88 MB figure.
  FIX: Update to 0x3BF000 (about 3.75 MiB) here and in the brief.
- line 228 [low/inconsistent] CLAIM: Task S2 names firmware anchor SSH server, and section 0 (lines 16-17) says every task maps to an existing firmware capability.
  EVIDENCE: No SSH server exists in src/, main/ or sdkconfig.defaults*; the wizard and SSH TUI are not in firmware either.
  FIX: Mark S2 and the wizard anchors as planned redesign work rather than existing firmware.
- line 162 [low/broken-markdown] CLAIM: Firmware-anchor cells end with a stray comma cell (the pipes read |, |) on lines 162, 170, 181 and 199.
  EVIDENCE: Rows O6, E4, G5 and V3 each have an extra cell containing a comma.
  FIX: Make those cells empty or a dash.
=== FILE docs/design/ring-pool.md (3 findings) ===
- line 21 [medium/wrong-fact] CLAIM: The PSRAM allocator is attributed to issues '#428 #48'.
  EVIDENCE: gh api repos/GlomarGadaffi/pocket-dial/issues/48 returns 'RequestsHandler Mutex Lock Contention under Status Polling', which is unrelated. Issue 428 returns 404.
  FIX: Cite the correct issue for the PSRAM allocator, or drop the reference (PsramAllocator.hpp is in-tree).
- line 56 [low/dead-link] CLAIM: Issue #427 is cited for no ring allocation after init.
  EVIDENCE: gh api repos/GlomarGadaffi/pocket-dial/issues/427 returns 404.
  FIX: Correct the number or name the repository where the issue lives.
- line 16 [low/unverifiable] CLAIM: Commit ff443def is cited for the #466 PR A change.
  EVIDENCE: git cat-file on ff443def fails in the local clone, so the hash could not be checked. The 7bcf952f citations in the doc do verify.
  FIX: Fetch origin and confirm the hash.
=== FILE docs/design/token-fetch-911-lane.md (4 findings) ===
- line 38 [medium/wrong-fact] CLAIM: The token URL cap is 142 B (row 1), and section 5 uses tokenUrl = 143 B (line 102).
  EVIDENCE: src/SIP/TelephonyApiConfig.hpp:36 at commit 7bcf952f sets kMaxUrlLen = 128, and the same file's line 37 sets kMaxFieldLen = 64. The config file is not on the branch diff, so the cap is the same on the branch.
  FIX: Use the 128 B cap: tokenUrl becomes 129 B and the slice-1 total 583 B needs recomputing.
- line 102 [low/inconsistent] CLAIM: Section 5 uses an encoded form body of 440 B, while row 4 (line 41) and the test plan (lines 124-125) use 439 B for the same bound.
  EVIDENCE: Row 4 states the bound as 40 + 3x64 + 15 + 3x64 = 439 B.
  FIX: Use 439 B in section 5 and recompute the total.
- line 9 [low/stale] CLAIM: The branch origin/fix/862-hot-path-allocs at 79e0133f is described as #945, draft, DO NOT MERGE.
  EVIDENCE: Commit 79e0133f and the branch are absent from the local clone. gh api shows issue/PR 945 is closed, not a draft.
  FIX: Recheck the PR state and branch head before the vote.
- line 14 [low/unverifiable] CLAIM: IDF facts were read in /home/glomar/esp/esp-idf (v6.0.2), and every unmarked TA.cpp or TAL.hpp line number refers to the branch.
  EVIDENCE: The IDF path is absent in this environment, and the branch is not in the clone. Only the main-tagged citations verify (TA.cpp:383, :1069, :1098 and the 1074-1080 revocation comment at 7bcf952f).
  FIX: State that branch and IDF line numbers were not re-verified, or attach the IDF tree.
=== FILE docs/design/tui-ia.md (5 findings) ===
- line 171 [medium/wrong-fact] CLAIM: The Session info panel says sessions are logged to CDR, and logout (line 190) is logged to CDR.
  EVIDENCE: src/SIP/CallDetailRecord.hpp:22 and :45 describe the CDR as a record of one completed call; there is no session log in firmware.
  FIX: Remove the session claim, or specify a separate session log.
- line 527 [medium/inconsistent] CLAIM: The admin DTMF menu lists only codes 001 and 101, and the factory reset in section 2 (line 172) is said to be double-confirmed in [4] SECURITY.
  EVIDENCE: src/SIP/DtmfFeatureCodes.cpp:402-410 implements *PIN#999 factory reset with a single confirm digit '1' and an emergency-call guard. This DTMF reset path is undocumented in the IA.
  FIX: Document the *PIN#999 path and its single-digit confirm, or make the DTMF path meet the double-confirm rule.
- line 516 [low/wrong-fact] CLAIM: The CLASS and DTMF-admin handlers are said to live in src/SIP/RequestsHandler.cpp (also lines 7-8 and 580).
  EVIDENCE: The star-code handlers for *60, *80, *73, *69, *11 and *72 are in src/SIP/DtmfFeatureCodes.cpp (around lines 228-356). The admin codes 001, 101, 200 and 999 are at lines 359-410. RequestsHandler.cpp only has comments on these codes.
  FIX: Cite src/SIP/DtmfFeatureCodes.cpp.
- line 179 [low/inconsistent] CLAIM: The CDR result shown is 'unreachable'.
  EVIDENCE: Section 6.2 (line 543) and src/SIP/CallDetailRecord.hpp:28 and :39 use 'unavailable'.
  FIX: Use 'unavailable' in the screen tree.
- line 495 [low/broken-markdown] CLAIM: The V3 row in the coverage matrix has a stray comma cell (|, |).
  EVIDENCE: Line 495 ends with an extra cell containing a comma.
  FIX: Empty the cell.
=== FILE docs/design/tui-style.md (16 findings) ===
- line 362 [medium/wrong-fact] CLAIM: The banner says All sessions are logged to the CDR (also line 932: all SSH sessions are recorded to the CDR).
  EVIDENCE: src/SIP/CallDetailRecord.hpp:45 says 'One completed call'; the CDR records calls only.
  FIX: Reword, or specify a separate session log.
- line 1228 [medium/wrong-fact] CLAIM: The PIN is described as 4-10 digits (also line 954).
  EVIDENCE: src/Helpers/AdminAuth.hpp:51-52 sets kMinDtmfPinLength = 4 and kMaxDtmfPinLength = 16. Line 1226 says this PIN also gates the DTMF admin menu.
  FIX: Match the 4-16 digit firmware range, or change the firmware cap.
- line 69 [low/wrong-fact] CLAIM: PHOSPHOR hex values are wrong: board bg #10140F (line 69) should be #101410, and jack empty #16201C (line 75) should be #161C16.
  EVIDENCE: main/ui/ui.cpp:51 is LV_COLOR_MAKE(16, 20, 16) and ui.cpp:57 is LV_COLOR_MAKE(22, 28, 22).
  FIX: Correct both hex values.
- line 79 [low/wrong-fact] CLAIM: The PHOSPHOR DND amber is cited as ui.cpp L61 (lines 76 and 79), and the palette is cited as lines 39-64 (line 6).
  EVIDENCE: The PHOSPHOR DND entry is ui.cpp:58. PALETTES[] spans lines 36-62.
  FIX: Cite ui.cpp:58 and lines 36-62.
- line 339 [low/unverifiable] CLAIM: The login banner is described as the firmware sshd greeting.
  EVIDENCE: No SSH server or banner string exists in src/, main/ or sdkconfig.defaults*.
  FIX: Describe the banner as a planned redesign surface.
- line 360 [low/inconsistent] CLAIM: The banner shows POCKET-DIAL v3.0.0, but brand.md section 1.3 says human-facing surfaces use vMAJOR.MINOR (v3.0) and the full PATCH form only in logs, CDR and about.
  EVIDENCE: Firmware version is derived from git describe (cmake/FirmwareVersion.cmake), and CHANGELOG.md's latest release is v1.5.1.
  FIX: Show v3.0 in the banner, and note that the 3.x line is the redesign target.
- line 372 [low/dead-link] CLAIM: The operator-terse PIN error is cited as brand section 4.6.
  EVIDENCE: brand.md has no section 4.6.
  FIX: Re-point the cite (same as narrative.md line 62).
- line 846 [low/inconsistent] CLAIM: The IVR answer point is labelled ext 100 (Front Desk menu).
  EVIDENCE: Extension 100 is Operator at line 854, line 926 and section 4.3 line 1259.
  FIX: Rename the answer-point label to Operator, or change the extension.
- line 799 [low/inconsistent] CLAIM: The sales ring group is shown as Ring everyone, 3 members in section 3.6 (line 578), but as One at a time, 4 in the forward picker (line 799).
  EVIDENCE: Lines 578 and 799 disagree on mode and member count.
  FIX: Align the two mockups.
- line 976 [low/inconsistent] CLAIM: The CDR row shows 18:14:09 101 to 102 answered 02:14 (also the event log at line 1028).
  EVIDENCE: The monitor at 18:14:25 (line 426) shows the same 101 to 102 call ACTIVE with DUR 02:14, which means it started about 18:12:11.
  FIX: Align the times and durations across the screens.
- line 499 [low/inconsistent] CLAIM: The Extensions FWD column shows ext 104 with grp:sales and ext 103 with none (lines 498-499).
  EVIDENCE: The Forwards/DND table (lines 719-720) shows ext 103 with CFNA grp:sales and ext 104 with no forwards.
  FIX: Align forward state across the two screens.
- line 1172 [low/inconsistent] CLAIM: The welcome copy says Esc backs out a step.
  EVIDENCE: Section 4 intro (line 1153) and tui-ia.md section 5.2 say Esc is a no-op at [0/5]. The same copy appears in narrative.md line 188 and walkthrough.md line 88.
  FIX: Change the copy to match the no-op rule.
- line 403 [low/inconsistent] CLAIM: The hub footer lists [T] Theme (also line 1370).
  EVIDENCE: docs/design/tui-ia.md line 66 and the section 3.7 footer contract omit T.
  FIX: Align the footer lists.
- line 268 [low/broken-markdown] CLAIM: Modal right borders are off by one column (lines 268, 526, 536, 560, 753, 882, 953 and 954).
  EVIDENCE: Measured with east-asian widths: these lines end one column away from their top border.
  FIX: Pad each line to the modal width.
- line 482 [low/dead-link] CLAIM: Pressing M opens the confirm in section 3.13.
  EVIDENCE: Section 3.13 draws only the reboot confirm. The mode-switch and factory-reset confirms are described in text only.
  FIX: Draw the mode-switch confirm in section 3.13.
- line 1060 [low/unverifiable] CLAIM: Capacity is listed as 2-8 concurrent calls.
  EVIDENCE: src/SIP/PoolConfig.hpp:43 sets POCKETDIAL_MAX_SESSIONS 8, and main/CMakeLists.txt:279 sets 4 for the constrained build. No floor of 2 was found; brand.md:194 also says 2-8.
  FIX: Cite the source of the floor of 2, or correct the range.
=== FILE docs/design/walkthrough.md (5 findings) ===
- line 388 [medium/stale] CLAIM: The walkthrough says tui-style.md renders no Add ring group create modal (also lines 404-406 and 614).
  EVIDENCE: docs/design/tui-style.md section 3.6.2 (lines 624-705) renders that modal and says it closes walkthrough F3.
  FIX: Mark F3 resolved and cite section 3.6.2.
- line 489 [medium/stale] CLAIM: The walkthrough says the Forward editor accepts only single extensions and no group picker exists (also lines 515-524 and 615).
  EVIDENCE: docs/design/tui-style.md section 3.7.2 (lines 757-833) draws the extension and group picker and says it closes F4.
  FIX: Mark F4 resolved and cite section 3.7.2.
- line 65 [medium/wrong-fact] CLAIM: A fresh box has no PIN yet, so the front door asks for a credential that does not exist (chicken-and-egg; also lines 74, 302 and 612).
  EVIDENCE: src/Helpers/AdminAuth.hpp:14-21 and :53-59 ship a default web login admin/admin that is accepted until changed (needsInitialSetup). isProvisioned() at about :183-187 is defined on that basis. Only the DTMF PIN has no default.
  FIX: Reframe F1 against the existing default-credential gate, and rework the proposed fix.
- line 465 [low/stale] CLAIM: F10 says there is no created acknowledgement, and F11 says there is no live selected-count (lines 452-453, 463-466, 631-632).
  EVIDENCE: docs/design/tui-style.md shows the (0 selected) and (3 selected) counters (lines 631 and 658) and the transient created line (lines 699-700).
  FIX: Mark F10 and F11 resolved.
- line 158 [low/wrong-fact] CLAIM: A PIN capped at 10 digits is treated as the premise for a weak-secret concern.
  EVIDENCE: src/Helpers/AdminAuth.hpp:52 sets kMaxDtmfPinLength = 16.
  FIX: Correct the premise, and fix the 4-10 hint in tui-style.md.
=== FILE docs/design/whimsy.md (3 findings) ===
- line 140 [low/wrong-fact] CLAIM: The logout sign-off says logged to CDR (also line 136).
  EVIDENCE: src/SIP/CallDetailRecord.hpp:45 says the CDR records one completed call.
  FIX: Drop the CDR claim, or specify a session log.
- line 77 [low/dead-link] CLAIM: The wrong-PIN error is cited as brand section 4.6 (also line 366).
  EVIDENCE: brand.md has no section 4.6.
  FIX: Re-point the cite.
- line 386 [low/inconsistent] CLAIM: The Console feel toggle is said to live in [4] SECURITY.
  EVIDENCE: The [4] tree in docs/design/tui-ia.md lines 168-173 and the section 3.10 mockup in tui-style.md lines 917-944 have no such entry.
  FIX: Add the toggle to both screen specs.