# CHG-legacy-revert-journal: a legacy lifecycle's forget or settings revert is journaled (OP-11)

Board row: issue #1995. Source: release finding from the L3 (point 3) and Security (point 1) reviews of PR #1990 (CHG-forget-revert-journal). Class: release. Tier: A (`broker/change/`). Row #1999 (proposal entries with no matching approval request) is separate; not built here. Builder: strongest model. Usage estimate: 50k tokens, checkpoint at 40k.

**Why (facts, verified at main 544b1ce).** C37's migration (`migrateLocked`) moved a pre-journal state's adoptions into Content with their lifecycle in the body's `legacy` field, and replay starts such an adoption from it. #1990 made forget and settings reverts journal intents and migrates a top-level `reverted` in a body, but `legacy.reverted` = `forgotten` or `settings` is still read from the body on every start and never journaled. A body replaced or restored without the field brings the adoption back as active.

## Requirement (from SPEC.md)

- **OP-11** "No component keeps its own durable lifecycle, receipts or recovery rule beside the journal."
- **SM-AD-2** (audit): every adoption transition, revert included, is a journal intent; replay reads none of the lifecycle from the body.

Package IDs:
- **LRJ-1** A body whose `legacy.reverted` is `forgotten` or `settings`, on an adoption the journal leaves active, is owed once at `Attach` (one journaled revert), and the body is put again without `reverted`, keeping the rest of `legacy`.
- **LRJ-2** After that, a body restored without the field, or with it, still replays as reverted, and the revert is not journaled twice.
- **LRJ-3** The debt is saved before the body loses the field (a failed save keeps it in the body and the next start migrates it); a legacy revert of any other why stays legacy lifecycle and is not journaled.

**Acceptance tests** (`broker/change/legacy_revert_journal_test.go`): LRJ-1, LRJ-2: `TestLegacyForgetRevertIsJournaled`, `TestLegacySettingsRevertIsJournaled`. LRJ-3: `TestLegacyRevertMigrationSurvivesAFailedSave`, `TestLegacyOtherRevertStaysInTheBody`.

## Design

In replay, a loaded `legacy` with an owed why moves into the same `tail` map the top-level body revert uses, and is cleared from `legacy`. The existing migration then owes it when the journal leaves the adoption active, saves the debt, and re-puts the body. Every body that held such a revert is re-put, owed or not, so no copy of the revert stays on disk.

## Scope

`broker/change/adoption_journal.go`, `broker/change/legacy_revert_journal_test.go` (new), `broker/change/ASSUMPTIONS.md`, `briefs/CHG-legacy-revert-journal.md`. **Guard files:** none.

## Out of scope

Row #1999. The rest of the `legacy` lifecycle (no journal intent exists for those pre-journal transitions).

## Done

CI green; LRJ-1..3 covered by tests carrying `REQ: OP-11, SM-AD-2` and their ID.
