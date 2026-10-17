# VM-preempt-successor: a preemption reaches the life admission picked, never a same-ID successor

Board section: Security and architecture review. Work item: #2144 (follow-up of VM-destroy-retire r3, #2135).

**Goal.** `admission.Controller.Admit` picks Experiment victims under its lock, drops the lock, then calls `Preempter.Preempt(id)`. `vm.Manager.Preempt` looks the ID up afresh, so a victim destroyed after the pick and replaced by a new machine under its ID has the successor killed and recorded `Preempted`, though admission (since #1707) keeps the successor counted. The successor is stopped for a preemption that was never decided for it (RES-2).

Fix:
1. `admission.Request` gains `Instance`, which admission only passes back. A new optional interface `admission.LifePreempter` (`Preempter` plus `PreemptInstance(id, instance)`) is called for a victim admitted with an Instance; otherwise `Preempt(id)` as before.
2. `vm.Manager.admit` sets `Instance: mc.Instance` (the per-life identity from #1561). `Manager.PreemptInstance` refuses with `ErrUnknown`, before setting anything, a machine whose Instance differs; `Preempt(id)` stays for direct callers.
3. agentosd's `preempter` forwards `PreemptInstance`, with a compile-time `admission.LifePreempter` assertion so a wrapper cannot silently fall back to preempting by ID.

An optional interface rather than a changed `Preempter`, because a dozen test and production preempters implement it; the assertion covers the one production wrapper.

**Requirement IDs:** RES-2.

**Acceptance tests:**
- `broker/vm/preemptsuccessor_test.go`: `TestRES2PreemptSparesASameIDSuccessorStartedAfterThePick` (the successor stays Running, its guest alive, counted by admission with its own Instance), `TestRES2PreemptInstanceChecksTheLife`.
- `broker/admission/life_test.go`: `TestRES2VictimIsPreemptedByItsLife`, `TestRES2StaleLifeRefusalLeavesTheSuccessorCounted`, `TestRES2PreemptByIDWithoutALife`.

**Scope:** `broker/admission/admission.go`, `broker/admission/life_test.go` (new), `broker/admission/ASSUMPTIONS.md`, `broker/vm/vm.go`, `broker/vm/fake_test.go`, `broker/vm/lockcheck_test.go`, `broker/vm/preemptsuccessor_test.go` (new), `broker/vm/ASSUMPTIONS.md`, `broker/cmd/agentosd/main.go`, this brief. Tier A. Avoids the lines #2064 changes in vm.go and destroy_test.go, and the lines #2015 changes in main.go.

**Dependencies:** #2143, #2135 (merged). **Usage estimate:** small (one field, one interface, one check, five tests).
