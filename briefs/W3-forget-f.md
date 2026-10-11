# W3-forget-f: LATER follow-ups to the forget packages

Board section: Integration: wiring merged packages into the box.

**Precondition:** W3-forget-b2, W3-forget-b2b, W3-forget-b1 (all merged).

**Owner:** coordinator thread, 2026-10-09.

**Deviation from D-048:** D-048 holds LATER rows until the first release. On 2026-10-09 the coordinator, at its user's request, started the LATER rows nothing blocks. This package does not merge until the owner confirms that exception.

## Rows taken

| Row | What | Requirement | Acceptance test |
|---|---|---|---|
| W3-forget-b2b f1 | Security 327-1: work done between `agentBackWithoutAsking`'s `worked()` check and `takeBack(approved=false)` is rolled back unasked. `Reach.TakeBack` re-checks `Work` under `r.run` when not approved and refuses with `ErrWorked`. | CAP-3 | `recalltool`: `TestCAP3ATakeBackNotApprovedRechecksTheWork`; `TestCAP3ATakeBackNotApprovedLosesNoConcurrentWork` (agent on its own goroutine, run under `-race`) |
| W3-forget-b2b e | An approved `TakeBack` that finds an unfinished reset from the same time returns without a mark, so once Retry finishes the reset a later boot takes back again. It now marks the take-back done (an owed mark would make Retry repeat the reset). | CAP-3 | `TestCAP3AnApprovedTakeBackOnAnUnfinishedResetIsMarked` |
| W3-forget-b2 f1 | A forget that lands after the proposal reached the owner, while the job still runs, requeues without counting the ask, so forgets could ask past `MaxAsks`. The ask is now counted as when the forget lands after the job; the rebuild still runs at once. | CAP-3, LOOP-3 | `loops`: `TestAForgetAfterTheProposalReachedTheOwnerCountsTheAsk` |
| W3-forget-b2 f2 | A job forgotten before it began still called `propose`/`Build` with a cancelled ctx. It now returns `ErrRequeued` first. | CAP-3, LOOP-3 | `TestAForgetBeforeTheBuildStartsRequeuesIt` (builds counted) |
| W3-forget-b2 f3 | No test covered the post-build `goneSinceLocked` disjunct. | CAP-3, LOOP-3 | `TestAForgetAfterAPreemptionStillRequeues` (fails with the disjunct removed) |
| W3-forget-b1 f5 | The "copy holds its key" check looked for hex, but JSON writes `[]byte` as base64. It now looks for every key raw, hex and base64, and for any field beyond the log's own. | CAP-3, A8 | `recovery`: `TestForgetLogAppendIsAuthenticatedAndAnchored` |

## Rows left in LATER.md

Each row's fix lives in files that open PRs change (#425 and #457 change `cmd/agentosd/forget.go`; #457 changes `agent.go`; #462 and #434 change `change/digest.go`):

- W3-forget-b2b q: the notice text and `resumeAgent` are in `forget.go`.
- W3-forget-b2b w: `resumeAgent` is in `forget.go`. The row also says to fold it into the not-saved release row.
- W3-forget-b2c l1 (both rows): the owed text is in `forget.go` and the agent STATUS line is in `agent.go`. A STATUS-only change in `recalltool/service.go` would fix half.
- W3-forget-b2c l2: the evidence is in `forget.go`, the rendering in `change/digest.go`.

## File scope

`broker/recalltool/reach.go`, `broker/recalltool/takeback_test.go`, `broker/recalltool/ASSUMPTIONS.md`, `broker/loops/loop1.go`, `broker/loops/requeue_test.go`, `broker/loops/ASSUMPTIONS.md`, `broker/recovery/forgetlog_test.go`, `LATER.md`, `BOARD.md` (this row), this brief.
