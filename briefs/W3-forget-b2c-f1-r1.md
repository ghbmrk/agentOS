# W3-forget-b2c-f1-r1: A restored item 1 forget still retrying is told done, STATUS shows item 1 retries, and a restore purges the digest queue again

Board section: Integration: wiring merged packages into the box. Follows W3-forget-b2c-f1 (#602, d575ff6); SPEC CAP-3. Edits `broker/cmd/agentosd/forget.go` and `learn.go` after f1.

**Sources:**
- L3 on #559, release 2 (ASSUMPTIONS R4): the owner was told `forgetNotSaved` ("will text you when it's done"); a restore then replays the forget silently, so the promise is never kept. Security 4a P2 on #559: "owe the done text from a restored item 1 entry whose goal the live owed file lacks."
- L3 on #602 (6081697930): the split to r1 is item 1's restore-path done text; the item 1 replay lives in learn.go's restored-forget handling; the STATUS line for item 1 retries is the f1 brief's "raise as a finding".
- UX U4 on #602: build r1 next, with a test that the promised `forgetNotSaved` done text arrives after a restore.
- Security 1 on #602 (6081701263, release): the boot-time replay of a restored forget log tombstones each goal (learn.go `openLearning`) but does not ask the digest queue to forget it again (`digestBox.forget` / `q.Forget`); pre-existing since #592.

**Requirement IDs** (the builder confirms each against SPEC.md and writes the failing test first):
- **CAP-3** (SPEC): a forgotten task is gone from every store, across a restore too, and the owner is not left waiting on a promise that is silently not kept.
- **UX-182-3** (UX lens on #182; not a SPEC ID): a text promised or owed is sent, after a restart or restore too, through the owed path (`done`).
- **CH-12** (SPEC.md:178): the STATUS line follows CH-12's exception lines: a count, no task words.
- **R1A** (restore owes the done text): when `openLearning` replays a restored forget log entry for item 1 that was logged while its forget was still retrying (no `Agent`, no `Since`: the entry `Execute`, `retry` and `finishOwed` append before any done text), whose goal the restored learn dir neither tombstoned nor owes, it owes that goal's done text before it tombstones it. `finishOwed` then tells it once the owner channel is up, with the existing `doneLater` text, verbatim (no new wording). Test: a forget cut off while retrying (owner told `forgetNotSaved`), then a restore from a backup taken before it; after the next open and attach the owner gets exactly one done text.
- **R1B** (told once): a restored entry the restored learn dir already tombstoned or owes, or one logged by a forget that was told done at once (it has a `Since`), is not owed again by the restore; the next boot, which re-reads the same restored log, does not tell it again. Tests: the next boot after R1A's sends nothing; a tombstoned-in-backup entry and a `Since` entry send nothing.
- **R1C** (STATUS line for item 1 retries): while an item 1 forget is still retrying in this process (`retry`, or `purgeLater` for the digest step), STATUS shows one line with a count only, wired into `cfg.Notes` as item 2's `Note` is. It goes when none is retrying. Test: the line appears while retry fails, holds no task word, and is gone once the forget is done.
- **R1D** (digest purge on restore): at attach, every goal a restored forget log holds is asked of the digest queue again (`ownerForget.digest`), each boot; a refusal is held by the digest box itself (its kept `forgets`). Test: a restored log's goals reach `digest` at `finishOwed`, including one whose done text is not owed.

**Design constraints:**
- No new done text: R1A reuses `doneLater` verbatim (the L1 wording row W3-forget-b2c-f1-w is out of scope). R1C's line is the one new text; it reuses `forgetNotSaved`'s words and `carryNote`'s form, and goes through the UX lens.
- Owed before the tombstone, as `Execute` does, so a crash between the two still tells it.
- A retry-path forget that finished before the restore is told done a second time: the lesser harm next to a missing one (`paid`); record it in ASSUMPTIONS.md.

**Not in this package:** the wording row W3-forget-b2c-f1-w (`errNoLineage` text, a restored take-back count note); LATER W3-forget-b2c-f1 l1–l6; item 2's restore path (done in f1); `broker/recovery` and the forget log's format.

**Tests (write first, each with a `REQ:` marker):** R1A–R1D as above; the existing forget, owed, carry and restore tests still pass; `-race` over the new tests.

**Scope:** `broker/cmd/agentosd/forget.go` (`retry`, `purgeLater`, `finishOwed`, the notes, the struct fields they need), `broker/cmd/agentosd/learn.go` (`openLearning`'s restored-forget loop and owed-file opening, the `cfg.Notes` line), a new test file `broker/cmd/agentosd/forget_restore_item1_test.go`, `broker/cmd/agentosd/ASSUMPTIONS.md`, and this brief and the BOARD row. Nothing else.

**Gate:** tier A (`python3 tools/risk_tier.py broker/cmd/agentosd/forget.go` prints A): L3 on the strongest model with a threat check, Security re-sign at the final head. Lenses: Security and UX (one new STATUS line).

**Threat check to answer in the PR:** can a restore tell done for a forget whose tombstone did not hold; can the restore's owe or the STATUS line leak task words; can one forget be told done twice across the restore replay and a restart (beyond the accepted retry-finished case); does a restored goal stay in the digest queue?

**PR:** carries `Defect: W3-forget-b2c-f3` (the silent restore of a retrying forget, ASSUMPTIONS R4, is in its merged code); the digest gap (pre-existing since #592) is named in Findings. Findings line as OPERATING §2. Builder model: strongest (tier A).

**Estimate:** under 90k tokens (checkpoint 70k).
