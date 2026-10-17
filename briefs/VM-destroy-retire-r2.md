# VM-destroy-retire r2: a pre-lineage snapshot stays in its original lineage after its ID is replaced

Board section: Security and architecture review (2026-10-08). Work item: #1660. From VM-destroy-retire (#1561, PR #1575), Security S-R1 in the #1575 delta review 3.

**Goal.** `lineageSnaps` (`broker/vm/forget.go`) attributes a snapshot recorded before lineages (`Lineage == ""`) to the lineage of the machine *currently* holding its machine ID. Once that holder is destroyed and the ID taken by a machine of another lineage, `ForgetSince` of the original lineage misses the snapshot, so CAP-3 erasure can leave data behind. Fix: for a `""`-lineage snapshot, also match `lineage == s.Machine`, the lineage load gives a pre-lineage machine (`vm.go`, load). Fail-safe: it only widens what a forget erases.

**Requirement IDs:** CAP-3.

**Acceptance tests:** CAP-3: `broker/vm/forget_test.go::TestCAP3ForgetSinceErasesPreLineageSnapshotAfterIDReplaced` (a `""`-lineage snapshot, its pre-lineage holder destroyed and replaced under the same ID by a machine of another lineage; `ForgetSince` of the original lineage, the machine ID, erases it from the table and disk).

**Scope:** `broker/vm/forget.go`, `broker/vm/forget_test.go`, `broker/vm/ASSUMPTIONS.md` (V26), this brief. Not `broker/vm/vm.go` (#1659 owns it). Tier A.

**Dependencies:** none. **Usage estimate:** small (one function, one test).
