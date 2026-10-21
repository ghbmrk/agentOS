# KRN-task: a task is a log entry, and a key serves one task

Work item: #2692, the kernel half of #2676(b) (CLK-3 "One approval per task", D-147; Mark's tap at 13:53:46Z), built to the KRN-5 "Tasks" text in #2691. Tier A.

## Goal

1. **Tasks in the log.** `Kernel.OpenTask(now, id)` logs `task.opened`. The fold sets the task's time and its timeout, `TaskTimeout` (24 hours, KRN-5's default) later. `EndTask` logs the end at the final result, or when the planner's run ends without one. STOP and the timeout also end a task. An ended task never comes back. Failure path: a planner keeps a task, and what it holds, alive forever.
2. **A key serves one task.** `key.LimitTask(id)` is a caveat like any other, and a second task caveat loosens. `Admit` refuses a plan whose key's task is not live. A rejected plan, a failed step or a cancel leaves the task open for re-plans, and an admitted plan's steps and their reconciliation outlive it. Failure path: a plan moves to another task, or runs in an ended one.
3. **Task approvals live inside the task, one per site.**
   - `ApproveTask` logs one enrolled passkey's co-signature over `TaskHash(task, site, held request)`. It anchors, as a widening.
   - A later approval for the same site replaces the earlier one, since CLK-3 asks again after a card fill; another site's is held beside it.
   - Each ends with the task, and cutting off its passkey ends it at once.
   - Its `At` is the fold's time of the entry, so the clerk can order its own fills against the tap (CLK-3).
   - A clerk reads the approval for the request's site through `TaskApproved`, on its own clock and against its own anchors. The clerk process's view (`broker/clerk/run/wire.go`) carries the chain's task as of the call.
   - Failure path: a lost phone's approval, or another task's, covers a request.

Out of scope:
- The browser clerk's use of the approval (#2675, #2676(b)).
- The kernel's narrow-only sub-key that adds the task caveat (KEY-3); the ASSUMPTIONS row KRN-task covers the interim.
- The owner's setting of the task timeout (#2696: lowering by text, raising as a KEY-4 widening).
- Moving the per-task spend cap and hand-off items onto tasks.

## Scope

`broker/kernel/`, `broker/clerk/` (a test), `broker/clerk/run/wire.go` (the view carries the task), `briefs/KRN-task.md`.

**Guard files:** none (no new package).

## Acceptance tests

- KRN-5: `broker/kernel/task_test.go::TestATaskRunsItsPlansAndRePlans`, `::TestATaskKeyServesOnlyALiveTask`, `::TestEachEndEndsTheTask`, `::TestAnAdmittedPlanOutlivesItsTask`
- CLK-3, KEY-4: `broker/kernel/task_test.go::TestCuttingOffTheSignerEndsTheApproval`, `::TestATaskHoldsOneApprovalPerSite`
- KRN-7: `broker/kernel/task_test.go::TestAnUnanchoredTaskApprovalDoesNotSurvive`
- CLK-2, CLK-3: `broker/clerk/clerk_test.go::TestClerkReadsATaskApprovalOnItsOwnClock`, `broker/clerk/run/run_test.go::TestViewCarriesTheChainsTask`

## Estimate

About 80k tokens, single session.
