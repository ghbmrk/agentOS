# GUEST-mut-owner: kill the old mutgate survivors in the guest owner channel

Board row: issue #5749. Class: release (from #5621 item 4). Tier: A (`broker/guest`). Builder: strongest model. Usage estimate: 80k tokens (`briefs/GUEST-bridge-tree-dead-fu.md`), checkpoint at 60k.

**Why.** #5621 item 4 removes the dead `managed_tree` exemption from `broker/guest`, which makes mutgate target every covered line of the package; #5611's run (job 132081393112 of run 43448235668) found old statement-deletion survivors there. This row is group **owner**: 33 lines of `broker/guest/owner.go` (107, 112, 113, 127, 143, 146, 164, 203, 208, 209, 228, 236, 237, 240, 241, 266, 291, 302, 305, 308, 314, 328, 341, 351, 352, 358, 359, 361, 363, 365, 368, 371, 390). GUEST-mut-plane (#5748, #5760) already killed 107, 112, 113, 228, 236, 237, 240 and 241.

## Requirement

No SPEC ID; serves the mutgate invariant (a covered statement that a test does not check fails the gate, `tools/mutgate.py`).

- **GUEST-mut-owner-a** For each line above, a test fails when its statement is deleted, or the PR body carries `Mutant-equivalent: broker/guest/owner.go:<line> <reason>` where no test the rules below allow can tell.

Rules (`briefs/GUEST-bridge-tree-dead-fu.md`, "Rules for each kill row"): plain `Test` funcs appended to `broker/guest/outbox_test.go`; no new import, type, method or helper outside a test func, and no edit to an existing declaration. Survivors of other groups on the new tests' target lines are cleared here too.

## Acceptance tests

**Acceptance tests:** GUEST-mut-owner-a: `broker/guest/outbox_test.go::TestOwnerMut*`; each fails when one listed statement is deleted. Proof: a local deletion pass with `tools/mutgate.py`'s own `deletion_sites`/`build_mutant` over every target site, and CI's `mutgate` job passes.

## Scope

`broker/guest/outbox_test.go` (appended funcs only), this brief.

## Done

CI green, `mutgate` included; every listed line killed or waived with a reason a reviewer can check.
