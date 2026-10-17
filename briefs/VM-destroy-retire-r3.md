# VM-destroy-retire r3: a same-ID successor admitted while its predecessor yields is never left uncounted

Board section: Security and architecture review (2026-10-08). Work item: #1707. From VM-destroy-retire (#1561, PR #1575), Security 4a R1.

**Goal.** `admission.Controller.Admit` (`broker/admission/admission.go`) marks its victims `yielding`, calls `Preempt(id)` without its lock, then relocks and calls `removeLocked(id)` for each victim that yielded. If the victim's entry leaves `running` in that window (its machine is destroyed, or Preempt finds it gone and releases it) and a new request with the same ID is admitted before Admit relocks, `removeLocked(id)` deletes the successor's entry: the successor runs uncounted and later admissions cut into the headroom (RES-2). Worker IDs are deterministic, so a guest can aim at the window.

Fix: each admission gets a number, recorded per running ID. Admit records the number of each victim it picks and, at relock, removes a victim only if the entry under its ID still carries that number; its own reservation is given back the same way. A successor admitted under the victim's ID carries a new number, so it stays counted. Chosen over refusing a yielding ID: the refusal breaks `broker/vm`'s `TestRES2PreemptOfADestroyedVictimKeepsTheSuccessorCounted`, which already requires a same-ID create during the preemption to succeed and stay counted.

**Requirement IDs:** RES-2.

**Acceptance tests:** RES-2: `broker/admission/admission_test.go::TestRES2SameIDSuccessorDuringYieldIsNeverUncounted` (a Preempter that releases the victim and admits a request with its ID before returning nil; after Admit returns, the successor was admitted and is still in `Snapshot().Running` with its own request, and free memory counts both it and the preempting request). Fails on main: the successor is admitted and then removed.

**Scope:** `broker/admission/admission.go`, `broker/admission/admission_test.go`, `broker/admission/ASSUMPTIONS.md` (new), this brief. Tier A.

**Dependencies:** none. **Usage estimate:** small (one map, two guarded removals, one test).
