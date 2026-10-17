# Admission controller: assumptions

Each row is a reading of the spec, or a property the code relies on, that a
reviewer may want to change.

| # | Assumption | Spec basis | If it changes |
|---|---|---|---|
| 1 | `Admit` is the only path into `running`, and every admission takes a new number from `gen` under the lock, so a number identifies one admission of one ID. | RES-2 | A second path into `running` must also set `gens`, or a victim's relock could remove its entry (#1707). |
| 2 | A victim that leaves the books while it yields (destroyed, or released by Preempt) may have a same-ID successor admitted before Admit relocks; that successor is admitted, not refused, and stays counted. | RES-2; `broker/vm` `TestRES2PreemptOfADestroyedVictimKeepsTheSuccessorCounted` | If same-ID reuse during a yield should be refused instead, the refusal belongs in Admit's duplicate check and the vm test changes. |
| 3 | A uint64 admission counter does not wrap in a broker's lifetime. | none | A wrap could make an old victim's number match a successor's; reset or widen the counter. |
