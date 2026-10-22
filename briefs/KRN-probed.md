# KRN-probed: a covered submit whose answer was lost still gets its STATUS line

Work item: #2727 (its release item). Tier A.

## Goal

1. **A probe answers a `kernel.Result`.** `kernel.Clerk.Probe` returns a `Result` instead of a bare outcome. Its `Outcome` is `done`, `notdone` or `unknown`, as before. `Covered` carries a covered submit's STATUS line when the probe finds it done. Failure path: the clerk sends Place order under a task approval and the socket drops the answer. Reconciliation proves the step done through `step.probed`, which carried only the outcome, so `State.Covered` never listed the line (CLK-3).
2. **The kernel bounds and folds it.** `Kernel.Answer` drops a probed line that `shown()` refuses before it is logged. The fold sets the step's line on a probed `done`, as it does on a result.
3. **The wire carries it.** The out-of-process clerk's probe answer carries `covered`.
4. **The browser clerk remembers it.** `Probe` gives the line again for a submit `Do` saw succeed.

Out of scope:
- The other #2727 items: joined emoji in `unseen`, and the owner's reply to `ErrAnchor` (sub B).

## Scope

- `broker/kernel/` (with `sim/`).
- `broker/clerk/`: the mail and exit clerks, `inbox`, and `run`'s wire and loop. These are signature adaptations only.
- `broker/browser/clerk.go`: the signature, plus the remembered line.
- Those packages' tests.
- `briefs/KRN-probed.md`.
- Two cosmetic fixes from the #2729 reviews: `broker/kernel/meter_test.go` and `briefs/KRN-reserve.md`.

**Guard files:** none (no new package).

## Acceptance tests

- CLK-3:
  - `broker/kernel/calls_test.go::TestAProbedSubmitGetsItsCoveredLine`
  - `broker/clerk/run/run_test.go::TestACoveredLineCrossesTheSocket` (its "probed" case)
  - `broker/browser/task_test.go::TestOneTapCoversTheTasksSubmits` (the probe gives the line again)

## Estimate

About 40k tokens, single session.
