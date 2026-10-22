# KRN-refail: a failed redo parks again

Work item: #2742 (item 8, kernel step). Tier A.

## Goal

A step that RETRY sent again ended `failed` when the redo answered `failed`, and so dropped out of STATUS. The send before the redo may have acted, and only the kernel knows the step was retried. Failure path: a probe whose view is past `maxCall` is made `unknown` so the step parks (#2742 item 8, host lane); the owner's RETRY sends the same oversized view, `remote.do` answers `failed`/`too-large`, and a step that may have paid or sent ends `failed` with no line in STATUS.

Fix: a redo's `failed` (any detail) parks the step again, charged and listed, with the clerk's detail, for the owner to retry or cancel. A first send's `failed` still fails the plan. Keying on the outcome rather than on the `too-large` detail keeps the rule at one place: a redo's failure never says the earlier send did not act.

## Scope

- `broker/kernel/state.go`, `kernel_test.go` and `ASSUMPTIONS.md`.
- `briefs/KRN-refail.md`.

**Guard files:** none.

## Acceptance tests

- KRN-8: `broker/kernel/kernel_test.go::TestARetriedStepThatFailsParksAgain`.

## Estimate

About 5k tokens, single session.
