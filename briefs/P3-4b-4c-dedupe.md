# P3-4b-4c-dedupe: each distinct finding line is said once, with its count

Board section: Phase 3: the agentic loops. Part of P3-4b-4c ([P3-4b-4c.md](P3-4b-4c.md#p3-4b-4c-corpus)); SPEC LOOP-9. Written 2026-10-09 from the #589 (P3-4b-4c-corpus) UX record.

**Package:** P3-4b-4c-dedupe alone. Release row; Mark may demote it to later.

**Tier A** (`broker/loops`, owner alerts): strongest model, L3 with a threat check, UX and Potency lenses, a separate Security section. Runs in CI's `broker` job.

**Dependencies, all merged:** P3-4b-4c-corpus (#589, e587276).

**Parallel work.** P3-4b-3r-told (queued; it carries P3-4b-3r-text) overlaps in `broker/loops`:
- It sets `ToldCleared` only for records whose key produced a line, in `Pass` and `CloseTarget`.
- It adds the flap-sequence test helper, run by `Pass`, `Resolve`, `runProbe` and `CloseTarget`.
- Its requirement 4 (from 3r-text) gives a texted return an "It is back: " lead, which changes line text. This package keys on the final line text, so a return and its first alert stay distinct.
- Its requirement 5 texts one extra "Cleared" through `Notify`.
- Both packages edit `ownertext_test.go` and loops `ASSUMPTIONS.md`.

Keep the dedupe inside `Guard.batch` and `Guard.Digest`, not at their call sites (`Pass`, `Resolve`, `CloseTarget`, `runProbe`), so the two packages meet only in tests and records. Whoever merges second rebases, reruns both packages' tests, and runs told's flap helper over a deduped batch. P3-4b-3r-pass, which edits `Pass` (the caller of `batch` at `secure.go:580`), merged as #585 (c9f7be1). Its branch `pkg/P3-4b-3r-pass-pass-close` is that merged head, so it is no live overlap.

## Goal

When many findings produce the same owner line, the owner sees that line once with how many it covers, in the text and in the digest. They never see ten identical lines that push real ones out of the digest's cap.

## IDs

LOOP-9 (the owner is told in plain words with a step). Tests carry `REQ: LOOP-9`.

## Sources

- #589 UX, comment 6079707103. A weakened corpus check misses every item. `CorpusProbe.Run` makes one finding per item (`Subject` is the item ID), but the owner line names only the check. The result is ten identical "My self-test of the code filter failed: …" lines across the text and MORE.
- Code today:
  - `Guard.batch(lines)` (`secure.go`) packs lines into `textBudget` and stores the overflow for MORE. It has no dedupe. Its callers are `Pass`, `Resolve`, `CloseTarget` and `runProbe`.
  - `Guard.Digest` sorts High first and caps at `digestCap` (3), then adds "And N more security findings: …". Ten identical lines take all three slots.
  - `clearedLinesLocked` already says a cleared line once per check and plain name (S39). The alert side is the gap.

## Requirements (each with a failing test first)

1. **`batch` says each distinct line once.**
   - Collapse identical final line strings, in first-seen order, before packing.
   - A line that stood for N > 1 findings carries the count in plain words. Suggested: a suffix ` (N times)`, or for a corpus line, a wording `plainname.go` gives, such as "on N test items". Pick the wording with the UX lens test's rules: no identifiers, a step kept.
   - The count is of findings, not of texts.
   - Tests:
     - ten corpus misses on one check give one line with the count, and no MORE (fails on main);
     - two different lines both appear;
     - a single line is unchanged, with no count;
     - the MORE overflow, with duplicates removed first, still holds every distinct line.
2. **The digest dedupes before its cap.**
   - In `Guard.Digest`, group open-finding items by their final text, including the "Again: " lead and waiting suffix, before sorting and capping.
   - Carry the count as in requirement 1.
   - "And N more" counts distinct lines left out, not findings.
   - Tests:
     - ten identical High lines plus two others: the digest shows all three distinct lines and no "And N more" (fails on main);
     - the cap still applies to distinct lines.
3. **The lens test covers the counted forms.** Extend `TestFindingTextsNameNoIdentifiersAndNeverAlarmWithoutAStep` with a counted line from `batch` and one from the digest.
4. **Records.**
   - A new loops ASSUMPTIONS row, next free S number: identical owner lines are said once with a count, in the text and the digest. Write down the key, the final line text, and why it is not the check and detail: two findings with one text are one thing to the owner.
   - Point S45 at it if S45's "one owner text" needs the link.

## Threat check

- Dedupe hiding a distinct finding. The key is the full final text, so two lines that differ in any word both show (requirement 1's test).
- A count that leaks an identifier, such as an item ID (requirement 3).
- The digest cap still crowding out a real finding (requirement 2).

## Scope

`broker/loops/secure.go` (`batch`, `Digest`, and a shared helper if both use one), `broker/loops/plainname.go` (only for a count wording), `secure_test.go`, `ownertext_test.go`, and `ASSUMPTIONS.md` (one new row).

**Estimate:** ~55k. Checkpoint at 30k: requirement 1 green.
