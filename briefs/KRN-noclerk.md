# KRN-noclerk: the owner can see a no-clerk cancel, and RETRY checks the clerk

Work item: #2747 (items 1, 2 and 4, plus the item 3 wording on a line this change edits anyway). Tier A.

## Goal

1. **A cancelled plan keeps why it was cancelled.** The fold keeps a cancel's code and detail on the plan (`PlanState.Cancel`, `CancelDetail`): `owner`, a key refusal, or `no-clerk` with the clerk's name. Failure path: a clerk is not running, and every plan for it is cancelled `no-clerk`. The state shows only `cancelled`, the same as an owner cancel, so sub B's STATUS renderer cannot tell the owner which clerk to start.
2. **The test names the cause.** `TestAStepForAnUnknownClerkIsNotCharged` checks that the plan is cancelled `no-clerk` with the clerk's name.
3. **RETRY checks that the step's clerk is booted.** A RETRY for a missing clerk is refused (`ErrRetryRefused`, no entry), and the step stays parked. Failure path: the owner retries a parked step after the clerk is gone. The RETRY is accepted and then cancels the plan, and the plan's later steps are lost.

Out of scope (later): #2747 item 5, a test for resending an unsent step whose clerk is missing after a reboot. That path is correct by reading.

## Scope

- `broker/kernel/state.go`, `kernel.go`, `calls_test.go`, `kernel_test.go` and `ASSUMPTIONS.md`.
- `briefs/KRN-noclerk.md`.

**Guard files:** none.

## Acceptance tests

- KRN-7, OWN-17: `broker/kernel/calls_test.go::TestAStepForAnUnknownClerkIsNotCharged`.
- KRN-8, CH-11: `broker/kernel/kernel_test.go::TestRetryRefusesAMissingClerk`.

## Estimate

About 10k tokens, single session.
