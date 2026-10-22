# KRN-tidy: kernel follow-ups with a failure path

Work items: #2613 item 13, #2670 items 3 and 5, #2705, and #2707 items 6, 8, 9 and 11. Tier A.

## Goal

1. **No pool admission on a broken log (#2613 item 13).** `AdmitPool` refuses with `log-broken`, as `AdmitSpend` does. Failure path: a pool call is admitted after a widening whose anchor failed.
2. **An anchor is never cut off by an owner action (#2670 item 3).** `Unenroll` refuses a hardware key (`ErrAnchor`), and the fold ignores a logged one. Failure path: one forged owner message cuts off a hardware key and locks the owner out until recovery.
3. **A narrowing renewal is live at once (#2670 item 5).** A renewal whose limits are within the old key's (`key.Limits.Within`) skips the hold, like a same-limit one. One that drops or loosens a limit still waits. Failure path: the owner narrows a clerk key at renewal and the clerk stops for a day.
4. **STATUS lists covered submits (#2705, CLK-3).** `kernel.Result.Covered` carries a covered submit's fixed-wording line from the clerk, across the clerk socket, into the step's result entry. `State.Covered(now)` lists the lines sent within `TaskTimeout`, oldest first. A line that is not one bounded, valid line (`MaxShown`) is dropped. Failure path: one tap releases two submits and the owner sees neither.
5. **Tests and wording from the #2703 reviews (#2707 items 6, 8, 9, 11).** A refused call sent again logs nothing. Two sites' approvals are each found by site. An approval numbered ahead of `Taps` is refused. The `MaxUnsentWait` comment gives the right count.

Out of scope:
- Spend reservations (#2613 item 1).
- Sim enrollment (#2670 item 2).
- The schema version (#2670 item 4).
- Owner-side wording (#2670 item 6, #2707 items 1, 3 and 10).

## Scope

`broker/kernel/` (including `key/`), `broker/clerk/` (tests), `broker/clerk/run/wire.go`, `briefs/KRN-tidy.md`.

**Guard files:** none (no new package).

## Acceptance tests

- KRN-5: `broker/kernel/spend_test.go::TestAnUnanchoredReserveDropBreaksTheLogAndAdmitsNoSpend`
- KEY-4, D-146: `broker/kernel/grant_test.go::TestAnAnchorIsNotCutOff`, `::TestOnlyASameOrNarrowerRenewalIsLiveAtOnce`, `broker/kernel/key/key_test.go::TestWithin`
- CLK-3: `broker/kernel/calls_test.go::TestStatusListsCoveredSubmits`, `broker/clerk/run/run_test.go::TestACoveredLineCrossesTheSocket`, `broker/clerk/clerk_test.go::TestClerkReadsATaskApprovalOnItsOwnClock`, `broker/kernel/task_test.go::TestATaskApprovalCannotBeReplayed`
- KRN-7: `broker/kernel/calls_test.go::TestADispatchStoppedSinceCallsIsNotSent`

## Estimate

About 60k tokens, single session.
