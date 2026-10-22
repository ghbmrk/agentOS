# KRN-unsent: a cancelled step that never acted gives its charge back

Work items: #2707 (its later item 5) and #2657 (UX item 1). Tier A.

## Goal

1. **A cancel refunds a step that never acted.** A step is charged to its plan's keys at its first dispatch. When the step is cancelled while it is known not to have acted, the fold now takes that charge off the ledger. "Known not to have acted" means one of three cases: its plan is cancelled while the step is unsent or waiting to be redone, its unsent answer arrives after the cancel, or a probe proves it not done after the cancel. Failure path: a $500 payment under a $500 daily cap reaches no clerk, so it is unsent. The owner cancels it, then plans it again, and the new plan is refused at the cap although nothing was paid.
2. **A step that may have acted keeps its charge.** An unknown or parked step of a cancelled plan stays charged until a probe proves it not done (KRN-8: a cancel never settles an effect that may have happened).
3. **RETRY never loses a parked step (#2657 UX 1).** A RETRY that a STOP or a revoke would refuse now is itself refused (`ErrRetryRefused`, no entry), and the step stays parked. Before, the RETRY was accepted and the redo then cancelled the plan, so the step left STATUS although it may have acted. If the STOP or revoke comes after the RETRY, the cancel puts the retried step back to parked, still charged and listed. A retried step may have acted before it parked until a probe finds it not done, so goal 1's refund never applies to it.

Out of scope:
- `failed` keeps its charge, as before.
- The other #2707 items:
  - Items 1 and 3 are owner text (sub B).
  - Item 2 is held while the host lane works in `clerk/run`.
  - Item 4 is the KEY-3 sub-key design, which is later.
- The other #2657 items:
  - The inbox double check is in `clerk/inbox` (mail lane).
  - UX 2 and 3 and Potency 1 are owner text, or STATUS fields for sub B's renderer.
  - The sim's reach and RETRY injection are later.

## Scope

- `broker/kernel/state.go`, `kernel.go`, `calls_test.go`, `kernel_test.go` and `ASSUMPTIONS.md`.
- `briefs/KRN-unsent.md`.

**Guard files:** none.

## Acceptance tests

- KRN-8, CH-11: `broker/kernel/kernel_test.go::TestRetryRunsTheKeyChecksAgain` (a RETRY under a STOP or a revoke is refused and the step stays parked; one narrowed after the RETRY returns the step to parked, charged; a retried step a probe finds not done is refunded at cancel).
- KRN-8: `broker/kernel/calls_test.go::TestAnUnsentStepCancels`. Its cases are a cancel of an unsent step, an unsent answer after a cancel, a STOP before the send, an unknown step that is cancelled (keeps its charge), and that step later probed not done.

## Estimate

About 15k tokens, single session.
