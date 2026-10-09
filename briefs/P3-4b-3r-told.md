# P3-4b-3r-told: the owner's last text about a finding matches its state

Board section: Phase 3: the agentic loops. Part of P3-4b ([P3-4b.md](P3-4b.md)); SPEC LOOP-9, LOOP-7, CH-15. Written 2026-10-09 from the #585 (P3-4b-3r-pass) and #586 (P3-4b-3r-fuzz) review records.

**Package:** P3-4b-3r-told, carrying P3-4b-3r-text. Both change what the owner is told when a LOOP-7 finding clears and returns. Both edit the same functions: the close paths' cleared lines and `Report`'s return text in `broker/loops`, and loop7's `Digest`. Split, they would conflict line by line.

**Tier A** (`broker/loops`, `broker/loop7`; closure evidence and owner alerts): strongest model, L3 with a threat check, UX and Potency lenses, a separate Security section. Runs on CI.

**Dependencies, all merged:** P3-4b-3r-pass (#585, c9f7be1), and P3-4b-3r-fuzz (#586, 982e317), whose `CloseTarget` is one of the close paths.

**Parallel work.** P3-4b-3h-r2 edits `CloseTarget`'s refusal and producer check in `loops/report.go`, drops or ignores `Closure.Produced`, and adds `Finding`/`Record` fields in `loops/secure.go`. Both packages edit `loops/hang_test.go` (fixtures that set `Produced`) and loops `ASSUMPTIONS.md`. Build after 3h-r2 merges, and write the flap helper's `CloseTarget` adapter against the contract it leaves; if this package goes first, 3h-r2 rebases onto the adapter. P3-4b-4c-dedupe edits `Guard.batch` and `Guard.Digest` in `secure.go` and keys on final line text, which this package's "It is back: " lead changes; whoever merges second reruns both packages' tests. P3-4b-3r-env-r1 edits a different row of `reviews/security/README.md`.

## Goal

A finding that flaps never leaves the owner on a text that disagrees with its state. "Back" is texted only after a heard "Cleared", every close path keeps that rule, and the digest lines LOOP-7 adds give a next step.

## IDs

LOOP-9 (the owner is told, and told when it ends; plain words with a step) and CH-15 (unsolicited texts are paced and held in quiet hours; requirement 5). Tests carry `REQ: LOOP-9`, and requirement 5's `urgent` test also `CH-15`.

## Sources

- 3r-told:
  - #586 L3 point 4 (comment 6080281635, release). Take a target with an overrun and a stall finding both open and texted. When the stall closes, `clearedLinesLocked` sends no line, because the overrun holds the hang key. `ToldCleared` is still set for the stall, so a return within `ReText` is texted although the owner never heard "Cleared". `Pass` has the same behaviour (`secure.go` around line 517).
  - #585 L3 point 2 (comment 6080035604).
  - #585 Security (comment 6080054697): `ToldCleared` has no restart test; the `json:"-"` mutant passes the package today.
  - Security README row "A 'Cleared' or return text disagrees with the finding's state". This is its second PR (#585, #586), so the flap-sequence helper is owed by OPERATING §4's recurring-findings rule.
- 3r-text: #585 UX, comments 6079171873 and 6080002750. The text calls are UX's; the suggested wordings below are theirs.

## Requirements (each with a failing test first)

1. **One close routine for every path** (3r-told). `Pass`, `CloseTarget`, `Resolve` and `runProbe` each decide which closed records get a cleared line and which are marked `ToldCleared`; `Pass` and `CloseTarget` already copy the same condition. Move the decision into one locked helper that all four call. Suggested shape: `closeTextLocked(closed []Record) []string`, which:
   - takes the closed records;
   - applies the `rec.Texted && (!rec.Again || paused)` gate;
   - calls `clearedLinesLocked`;
   - sets `ToldCleared` only for unpaused records whose key produced a line in this call.

   `clearedLinesLocked` returns the keys it said, or the records. A record whose line was suppressed by an open texted or `Again` finding with the same key is not marked. Two records closed together with one key share the line, and both are marked.

   Tests:
   - the #586 case through `CloseTarget`: the stall closes while the overrun is open, then returns within `ReText`, and is not texted (fails on main);
   - the same shape through `Pass`, with two findings sharing a plain name (fails on main);
   - a record whose line was said is marked, and its return is texted.
2. **The flap-sequence helper** (3r-told; Security README recurring kind). Write one test helper that drives a finding through a close path and asserts the texts after each step:
   - alert;
   - cleared;
   - return within `ReText`;
   - move between two details;
   - a restart, using `reopen`, at each point.

   Run it for `Pass`, `Resolve`, `runProbe` and `CloseTarget`. Each path has a small adapter that reports, closes and re-reports its kind of finding. Where the helper fails on a path, fix it through requirement 1's routine. List each fixed path in the PR as a blocker found by the new check.

   Today S39 says `Resolve` and `runProbe` do not set `ToldCleared`. If a resolved crash input that returns within `ReText` is then silent after "Cleared", that is the kind this row exists for: fix it here.
3. **`ToldCleared` survives a restart** (3r-told). Add `r.reopen(t)` between the clear and the return in `TestPausedAndFlapping`, or in the helper. With `ToldCleared` tagged `json:"-"`, the test fails.
4. **The return after "Cleared" says so** (3r-text). A texted return whose `told` was set leads with "It is back: " before the finding's usual text, so it does not repeat the first alert word for word. An `Again` line in the digest keeps its "Again: " lead. Tests:
   - the return text starts with the lead;
   - a first alert does not;
   - the lens test's no-identifier and step rules still hold for the led text.
5. **A texted return's clearing is texted once** (3r-text). Today, after a texted return, its own clearing goes to the digest only, so the owner's last text says the finding is open after it closed. Text that clearing once, through the same "Cleared: …" line, and do not set `ToldCleared` for it. A further return within `ReText` is then an untexted `Again`, digest only. A flap therefore costs at most alert, cleared, back, cleared per `ReText`, four texts where today it is three, and the owner's last text is always true.

   The extra "Cleared" is an unsolicited non-urgent text, so it goes through CH-15's pacing and quiet-hours path like any other: it goes through `Notify` with `urgent` false, so the owner channel's CH-15 pacing and quiet hours apply to it downstream. Test that the extra "Cleared" is sent with `urgent` false. Check that the sink `agentosd` wires to `Notify` paces non-urgent loops texts; if it does not, that is a finding (a release row against the sink), not a change here.

   Record the new bound in S39. UX offered a digest-only "Cleared again: …" instead. That is an open lens tension, recorded in `reviews/arbitration/2026-10-09-pr613.md`; OPERATING §4 settles it in the batched screen, not here. The builder builds the text route through CH-15's path, notes the tension on the PR's Findings line as open arbitration, and the screen's record decides; if it picks the digest, requirement 5 becomes the digest-only line.

   Tests: the full sequence's texts, in order, through the helper for `Pass` and `CloseTarget`; a third return within `ReText` is untexted.
6. **LOOP-7's digest lines give a step and do not repeat each other** (3r-text). In loop7 F14's `Digest`:
   - "Loop 2: my fuzz self-tests have not run for N days." gains the tail "I keep trying.";
   - "Loop 2: one of my fuzz self-tests cannot run." gains "The fix comes with an update.";
   - while the cannot-run line shows, the not-run line is suppressed. Both describe the same stall, and the broken one carries the more useful step.

   Tests:
   - `TestFindingTextsNameNoIdentifiersAndNeverAlarmWithoutAStep` is extended to the two digest lines. It lives in `loops`; drive loop7's `Digest` from a loop7 test that calls the same rule, or export the rule's checker for both;
   - with both conditions true, only the cannot-run line shows (fails on main).

   "Fuzz self-tests" as jargon is LATER P3-4b-3r-pass l4. Do not change it here.
7. **Records.** loops S39 (the one routine, which paths set `ToldCleared`, the new flap bound, the "It is back" lead); loop7 F14 (the tails, the suppression); the Security README row: its check is now the helper, owner this package, and the kind moves under "Checks that replaced findings".

## Threat check

- A false all-clear: the owner's last text says cleared while the finding is open. Requirement 1 keeps a suppressed line from marking; requirement 2 runs every path.
- The opposite, a last text that says open after it closed (requirement 5).
- A flap that texts without bound (requirement 5's bound and its test).
- A restart dropping the told mark and making a return silent (requirement 3).
- An owner text with an identifier or no step (requirements 4 and 6 extend the lens test).

## Scope

- `broker/loops/secure.go`: `Pass`'s close loop, `Report`'s return text, `clearedLinesLocked` and its new routine, `clearedLine` only if the lead belongs there.
- `broker/loops/report.go` (`CloseTarget` and `Resolve`, their close lines only) and `broker/loops/probe.go` (`runProbe`'s close lines only).
- Their tests: `secure_test.go`, `hang_test.go` and `ownertext_test.go`, plus a new helper file `flap_test.go` if it reads better.
- `broker/loops/ASSUMPTIONS.md` (S39).
- `broker/loop7/loop7.go` (`Digest` only), `loop7_test.go`, and `ASSUMPTIONS.md` (F14).
- `reviews/security/README.md` (one row).

**Estimate:** ~95k. Checkpoint at 50k: requirements 1 to 3 green.
