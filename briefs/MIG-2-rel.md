# MIG-2-rel: kernel and clerk release items

Work items: #2551 (release findings from #2550), #2620 (parked steps), #2619 (exit lens items; the remainder), and two plan-route egress cases from #1756 and #1763. Tier A. One PR.

## Goal

Close the failure paths these issues name, at the enforcement point and failing closed:

1. **Clerk clock (#2551 item 1).** The clerk judges holds, token lives and Retry-After on its own clock. A request carries no time. Failure path: a kernel clock that runs ahead releases a held irreversible step early.
2. **Dispatch confirmed from the log (#2551 item 2).** The clerk reads the step's first dispatch and hold from the log's view, which answers only for a step in flight and names the plan the log admitted. A request carries only the plan and step index. Failure path: a forged dispatch sequence undercounts the key's uses, or another plan signed under a logged id runs.
3. **Facts required (#2551 round 2).** Every clerk judges claims with its own facts, and `Check` refuses at a clerk without them. Failure path: the planner's content or label claim is taken as given.
4. **The sim runs the real clerk (#2551 item 5)** and adds a kernel clock that runs ahead of the clerk's (item 6). The rest of item 6 (reorder, full disk, clock back) and items 3, 4 and 7 are already on main, with the tests listed below.
5. **STATUS and RETRY (#2620).** `State.Status` lists every unknown and parked step with the clerk's last detail and whether it can be retried. `Kernel.Retry` re-dispatches a parked step of a live plan under its own idempotency key, after the same checks as any dispatch. It is a widening, so it anchors. Failure path: a step parked after a restart is a dead end with no owner action.
6. **#2619 remainder.** Every item is on main through #2623, #2637 and #2642, or deferred to #2633 as class:later. This PR closes #2619 with that map.
7. **Egress cases (#1756 item 1, #1763 item 2)** as rows in docs/migration/cases.md §6c, each with its clerk test.

Out of scope: #2631 (class:later). The "require a limit on root derivations" decision is a separate PR after #2581, since it touches `key.go`. Also out: #2551 item 8 (owner or clerk sourcing for bounded arguments), per-task spend across plans, and canonicalizing values. Each needs the owner channel or the real clerk (#2526) and stays open on #2551.

## Scope

`broker/kernel/` (not `key/`), `broker/clerk/`, `briefs/MIG-2-rel.md`, `docs/migration/cases.md`.

**Guard files:** none (no new package).

## Acceptance tests

- KRN-8, CH-11, OWN-16: `broker/kernel/kernel_test.go::TestStatusListsUnsettledSteps` (an unknown or parked step missing from STATUS), `::TestRetryRedispatchesAParkedStep` (a parked step that cannot run again, a retry that keeps the old check count, a replay that differs), `::TestRetryRunsTheKeyChecksAgain` (a retry that runs past a revoke or STOP), `::TestRetryRefusesAStepThatIsNotParked` (a retry of an unknown, done, missing or cancelled step), `::TestUnanchoredRetryDoesNotSurviveReboot` (an unconfirmed retry that acts after a restart).
- CLK-2, KEY-8: `broker/kernel/kernel_test.go::TestClerkKeepsTheHoldWhenTheKernelClockRunsAhead` (a hold released on the kernel's clock).
- CLK-2, KRN-8: `broker/clerk/clerk_test.go::TestClerkRefusesAStepTheLogDoesNotHaveInFlight` (an undispatched or settled step, or a twin plan under a logged id, that runs).
- KEY-2, CLK-2: `broker/clerk/clerk_test.go::TestClerkWithoutFactsRefuses` (claims taken as given).
- EVL-1: `broker/kernel/sim/sim_test.go::TestSweepFaultsTakeEffect` (the hostile kernel clock never reaching a hold), `::TestMutantsAreCaught` and `::TestSweepHoldsInvariants`, with the world on `clerk.Mail`.
- Already on main: `TestUndoKeepsTheDuplicateGuardOfAnIrreversibleStep` (item 3), `TestOwnerActionsAnchorThemselves` (item 4), `TestLogTamperTruncationForkTorn` asserting `ErrFork` (item 7), `TestFingerprintDoesNotCollideAcrossArgumentBoundaries` and `TestEmptyDeclaredArgumentRejectsThePlan` (round 3).

## Estimate

About 120k tokens, single session.
