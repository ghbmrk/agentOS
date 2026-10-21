# KRN-task: a task is a log entry, and a key serves one task

Work item: #2692, the kernel half of #2676(b) (CLK-3 "One approval per task", D-147; Mark's tap at 13:53:46Z), built to the KRN-5 "Tasks" text in #2691. Tier A.

## Goal

1. **Tasks in the log.** `Kernel.OpenTask(now, id, until)` logs `task.opened`, with `TaskTimeout` (24 hours) as the default timeout. `EndTask` logs the end at the final result, or when the planner's run ends without one. STOP and the timeout also end a task. An ended task never comes back. Failure path: a planner keeps a task, and what it holds, alive forever.
2. **A key serves one task.** `key.LimitTask(id)` is a caveat like any other, and a second task caveat loosens. `Admit` refuses a plan whose key's task is not live. A rejected plan, a failed step or a cancel leaves the task open for re-plans, and an admitted plan's steps and their reconciliation outlive it. Failure path: a plan moves to another task, or runs in an ended one.
3. **The task approval lives inside the task.**
   - `ApproveTask` logs one enrolled passkey's co-signature over `TaskHash(task, site, held request)`. It anchors, as a widening.
   - It ends with the task, and cutting off its passkey ends it at once.
   - A clerk reads it through `TaskApproved`, on its own clock and against its own anchors.
   - Failure path: a lost phone's approval, or another task's, covers a request.

Out of scope:
- The browser clerk's use of the approval (#2675, #2676(b)).
- The kernel's narrow-only sub-key that adds the task caveat (KEY-3); the ASSUMPTIONS row KRN-task covers the interim.
- Moving the per-task spend cap and hand-off items onto tasks.

## Scope

`broker/kernel/`, `broker/clerk/` (a test), `briefs/KRN-task.md`.

**Guard files:** none (no new package).

## Acceptance tests

- KRN-5: `broker/kernel/task_test.go::TestATaskRunsItsPlansAndRePlans`, `::TestATaskKeyServesOnlyALiveTask`, `::TestEachEndEndsTheTask`, `::TestAnAdmittedPlanOutlivesItsTask`
- CLK-3, KEY-4: `broker/kernel/task_test.go::TestCuttingOffTheSignerEndsTheApproval`
- CLK-2, CLK-3: `broker/clerk/clerk_test.go::TestClerkReadsATaskApprovalOnItsOwnClock`

## Estimate

About 80k tokens, single session.
