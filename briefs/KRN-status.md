# KRN-status: STATUS carries the RETRY tier's facts and the plan's cancel, and joined emoji are shown

Work items: #2657 (Potency 1 and UX 2) and #2740 (item 1). Tier A.

## Goal

1. **STATUS gives the facts the RETRY tier is judged on (CH-10, CH-11).** Each `Unsettled` entry now carries three facts, taken from the plan's own normalized step: the step's `Amount`, `Money` (true when its verb takes an amount, which always means the high tier), and its `Recipient`.
   - Failure path: the owner channel answers RETRY from the STATUS entries it reads over the kernel socket. Those entries held only the verb and clerk, so a payment's retry could not be held to the high tier that CH-11 requires.
2. **STATUS says a cancelled plan's step has no next step.** Each entry now carries the plan's status and its cancel code and detail (#2750).
   - Failure path: a parked step of a cancelled plan stays listed, as KRN-8 requires while it may have acted. Nothing in the entry said that nothing more will be tried, or why.
3. **A joined emoji no longer hides a covered line.** `unseen` now lets through the two joiners, U+200D (emoji sequences) and U+200C (Persian and Indic shaping). Every other format character is still refused, which is the default-deny choice. That includes bidi controls, invisible spaces (U+200B, U+2060) and tag characters, which can hide text from the owner.
   - Failure path: a "Place order 👨‍👩‍👧" button's submit was sent but never listed (CLK-3).

Out of scope:
- The sim injecting RETRY (#2657 Potency 2). It is later, because it has no failure path: the unit tests cover RETRY.
- Wording STATUS for the owner. That is sub B's renderer.

## Scope

- `broker/kernel/state.go`, `calls_test.go`, `kernel_test.go` and `ASSUMPTIONS.md`.
- `briefs/KRN-status.md`.

**Guard files:** none.

## Acceptance tests

- CH-10, CH-11: `broker/kernel/kernel_test.go::TestStatusCarriesTheRetryTierFacts`
- KRN-8: `broker/kernel/kernel_test.go::TestStatusListsUnsettledSteps`, which checks the plan status and the cancel code.
- CLK-3: `broker/kernel/calls_test.go::TestAProbedSubmitGetsItsCoveredLine`, with these cases: joined (listed), and zwsp and tag (not listed).

## Estimate

About 15k tokens, single session.
