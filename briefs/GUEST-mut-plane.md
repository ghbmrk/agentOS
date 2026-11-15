# GUEST-mut-plane: kill the old mutgate survivors in the guest plane

Board row: issue #5748. Class: release (from #5621 item 4). Tier: A (`broker/guest`). Builder: strongest model. Usage estimate: 120k tokens, checkpoint at 90k.

**Why.** #5621 item 4 removes the dead `managed_tree` exemption from `broker/guest`. That diff only deletes non-test lines, so mutgate targets every covered line of the package, and #5611's run (job 132081393112 of run 43448235668) found 129 old statement-deletion survivors. Four rows clear them by file group before the removal lands; this row is group **plane**: 42 lines of `broker/guest/plane.go` (170, 185, 186, 191, 192, 206, 210, 227, 229, 232, 239, 243, 258, 259, 286, 288, 312, 313, 352, 363, 398, 410, 415, 416, 417, 442, 574, 586, 595, 608, 609, 610, 629, 636, 637, 638, 639, 654, 655, 680, 685, 692).

## Requirement

No SPEC ID; serves the mutgate invariant (a covered statement that a test does not check fails the gate, `tools/mutgate.py`).

- **GUEST-mut-plane-a** For each line above, a test fails when its statement is deleted, or the PR body carries `Mutant-equivalent: broker/guest/plane.go:<line> <reason>` where no test the rules below allow can tell.

Rules: plain `Test` funcs appended to `broker/guest/plane_test.go`; no new import, type, method or helper outside a test func, and no edit to an existing declaration (a changed helper makes every guest test a mutgate target). The tests reach no MCP, owner or goal route where a plane one serves, so their mutgate targets stay in the plane as far as `New`, `Open`, `Close` and `Shutdown` allow.

## Acceptance tests

**Acceptance tests:** GUEST-mut-plane-a: `broker/guest/plane_test.go::TestPlaneMutNew*`, `::TestPlaneMutOpen*`, `::TestPlaneMutClose*`, `::TestPlaneMutHandler*`, `::TestPlaneMutDeadline*`, `::TestPlaneMutStep*`, `::TestPlaneMutBucket*`, `::TestPlaneMutLimitListener*`; each fails when one listed statement is deleted. Proof: a local `tools/mutgate.py run` and `delete` on the branch shows every listed line KILLED or waived, and CI's `mutgate` job passes.

## Scope

`broker/guest/plane_test.go` (appended funcs only), this brief. `broker/guest/links_test.go` is GUEST-mut-store's (#5747, D-111).

## Cross-group lines

The new tests call `New`, `Open` and `Close`, so mutgate also targets the store and inbox lines those run. Old survivors among them are cleared here, since the other groups' rows come after this one: `owner.go` 107, 112, 113, 228, 236, 237, 240, 241 are killed by `TestPlaneMutInbox*` (taken off GUEST-mut-owner, #5749), and `store.go` 78 and 79 are waived as equivalent (`readNoFollow("")` fails with ENOENT, which `openStore` treats as an empty store, the same store the early return gives).

## Done

CI green, `mutgate` included; every listed line killed or waived with a reason a reviewer can check.
