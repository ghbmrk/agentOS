# MUT-simplify-kernel-recent: s.recent records only irreversible steps

Board row: #6281 (tier A, lane:primary, class:release); also closes #6307 (the same dead branch, coordinator comment 7070592405 on #6307). Source: Lens note on #6279. Usage estimate: 40k tokens.

## Requirement
- **KRN-8 duplicate guard state:** `State.complete` records a step's fingerprint in `s.recent` only when its verb is irreversible, the only steps `repeats` (kernel.go) checks. `undo` then has no reversible-step entry to delete, so its `delete(s.recent[...])` branch and the two MUTANTS-EQUIVALENT records #6279 wrote for it go. Behaviour is unchanged: replaying a log reaches the same admit and next decisions.

## Scope (files)
- In scope: `broker/kernel/state.go`, `broker/kernel/MUTANTS-EQUIVALENT`, `broker/kernel/ASSUMPTIONS.md` (row MIG-2-f), a new `broker/kernel/zrecent_internal_test.go`, this brief.
- Out of scope: every other file.

**Guard files:** none.

## Acceptance tests
**Acceptance tests:** `broker/kernel/zrecent_internal_test.go::TestRecentHoldsOnlyIrreversibleEffects` (fails if `complete` records a reversible step, or stops recording an irreversible one; kills the negation and the removal of the new `if`); `broker/kernel/state_fold_test.go::TestAnUndoneShapeIsNovelAgain` and the repeat and replay tests in `broker/kernel` keep passing unchanged.
