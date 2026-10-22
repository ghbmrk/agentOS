# KRN-unsent2: follow-ups to the cancel refund

Work item: #2744. Tier A.

## Goal

1. **A later charge stays when an earlier step is refunded.** `TestACancelledUnsentStepFreesItsUse` gains a lost step charged after the unsent one, on the same key. A refund that dropped every charge from the cancelled dispatch on (`>=`) now fails it.
2. **The trust in `notdone` is named.** After a cancel, a probe's `notdone` gives the step's use back. That answer is the clerk's word, and it may free cap on a key other clerks share. ASSUMPTIONS KRN-calls now says so.
3. **A step no clerk can run is never charged.** A step whose clerk the kernel was not booted with was logged as dispatched (charged), then failed. Its plan is now cancelled (`no-clerk`) before any dispatch is logged. Failure path: the owner grants a key for a clerk that is not running, and each plan under it spends a use or a cap that nothing used.

## Scope

- `broker/kernel/kernel.go`, `calls_test.go` and `ASSUMPTIONS.md`.
- `briefs/KRN-unsent2.md`.

**Guard files:** none.

## Acceptance tests

- KRN-8: `broker/kernel/calls_test.go::TestACancelledUnsentStepFreesItsUse`.
- KRN-7: `broker/kernel/calls_test.go::TestAStepForAnUnknownClerkIsNotCharged`.

## Estimate

About 10k tokens, single session.
