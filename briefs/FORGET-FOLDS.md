# FORGET-FOLDS: a forget drops the machine's held tool-result bodies (CAP-3)

Board row: issue #1848. Source: external static review, filed 2026-10-15. Class: release. Tier: see the PR (`tools/risk_tier.py`). Builder: Sonnet 5.5. Usage estimate: 40k tokens, checkpoint at 30k.

**Why (facts, verified at main 303a820).** Recall results over `fold.Max` are held in full by `fold.Store` (`broker/guest/mcp.go`). `folds.Drop` runs only in `Plane.close(forget=true)`, at destroy. `ForgetSince` -> `forgetMachine` -> `Services.Open` is idempotent and only requeues, so the held bodies survive the rollback, though the memory that could name their IDs is gone.

## Requirement (from SPEC.md)

- **CAP-3** (SPEC.md:400): every projection and cache is rebuilt without the subject.

Package IDs:
- **FORGET-FOLDS-1** `ForgetSince` tells the services of each machine it rolls back that the machine was reset, even when the reset itself fails; machines of other lineages are not told.
- **FORGET-FOLDS-2** The guest plane drops the machine's held results on that notice and keeps its socket and inbox: `result_read` fails afterward for the dropped ID, other machines' results stay, and the machine keeps serving.

**Acceptance tests:**
- FORGET-FOLDS-1: `TestForgetSinceResetsTheMachinesServices` (`broker/vm/forget_test.go`).
- FORGET-FOLDS-2: `TestResultReadFailsAfterAForgetReset` (`broker/guest/tools_test.go`).

## Design (recommendation)

An optional `vm.Resetter` interface (`Reset(id)`) beside `Services`, called from `forgetMachine` under the machine's lock. `guest.Plane` implements it as `folds.Drop(id)`. Chosen over changing `Open` (its idempotent contract is documented) and over a new method on `Services` (breaks every implementer).

## Scope

`broker/vm/vm.go`, `broker/vm/forget.go`, `broker/vm/forget_test.go`, `broker/vm/services_test.go`, `broker/guest/plane.go`, `broker/guest/tools_test.go`, `briefs/FORGET-FOLDS.md`. **Guard files:** none.

## Out of scope

A late in-flight `Hand` that lands after the reset (the issue's "not shown" case).

## Done

CI green; FORGET-FOLDS-1 and -2 covered by tests carrying `REQ:` with their IDs.
