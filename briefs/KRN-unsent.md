# KRN-unsent: a cancelled step that never acted gives its charge back

Work item: #2707 (its later item 5). Tier A.

## Goal

1. **A cancel refunds a step that never acted.** A step is charged to its plan's keys at its first dispatch. When the step is cancelled while it is known not to have acted, the fold now takes that charge off the ledger. "Known not to have acted" means one of three cases: its plan is cancelled while the step is unsent or waiting to be redone, its unsent answer arrives after the cancel, or a probe proves it not done after the cancel. Failure path: a $500 payment under a $500 daily cap reaches no clerk, so it is unsent. The owner cancels it, then plans it again, and the new plan is refused at the cap although nothing was paid.
2. **A step that may have acted keeps its charge.** An unknown or parked step of a cancelled plan stays charged until a probe proves it not done (KRN-8: a cancel never settles an effect that may have happened).

Out of scope:
- `failed` keeps its charge, as before.
- The other #2707 items:
  - Items 1 and 3 are owner text (sub B).
  - Item 2 is held while the host lane works in `clerk/run`.
  - Item 4 is the KEY-3 sub-key design, which is later.

## Scope

- `broker/kernel/state.go`, `broker/kernel/calls_test.go` and `broker/kernel/ASSUMPTIONS.md`.
- `briefs/KRN-unsent.md`.

**Guard files:** none.

## Acceptance tests

- KRN-8: `broker/kernel/calls_test.go::TestAnUnsentStepCancels`. Its cases are a cancel of an unsent step, an unsent answer after a cancel, a STOP before the send, an unknown step that is cancelled (keeps its charge), and that step later probed not done.

## Estimate

About 15k tokens, single session.
