# VM-tests: lock-check hardening and create's failure-tail order

Board section: Devices, hardware and image (SPEC §13-14). Work items: #1710 (L3 and Security later on #1575) and #1712 (Potency P3 on #1575). Triage: batch 2 package B2-13.

**Requirements:** RES-2 (V38: a handle is good for one machine's life).

1. #1712: a failed create releases its admission before it leaves the table. A destroy and same-ID create run between the two steps make a successor that keeps its admission and its table entry; swapping the steps (with a raw `Admit.Release`) fails a test.
2. #1710 item 1: a function holding a machine handle that names an exported `Manager` method (call, method value or method expression), or after taking the handle indexes `Manager.machines` or names an unexported by-ID resolver (derived: `get`, `take`, `labelOf`, `preempt`, ...), fails a check unless allowlisted with a reason, so a by-ID call after a handle check (L3 B2's DeleteFiles shape) is caught.
3. #1710 item 2: any selection of a machine's `mu` other than as the receiver of a direct `Lock`, `TryLock` or `Unlock` call, and any use of `lockEndingExec` other than calling it, fails the lock check, as does an `unsafe` or `reflect` import; package-level func literals are read too.

**Scope:** broker/vm/vm.go (a test seam between the two steps, no behaviour change, no new imports), broker/vm/destroy_test.go, broker/vm/lockcheck_test.go, broker/vm/ASSUMPTIONS.md (V38 note).

**Acceptance tests:** RES-2: `TestRES2CreateFailureTailLeavesASameIDSuccessorAlone` (destroy_test.go); `TestHandlePathsActOnlyThroughTheHandle`, `TestMachineLockOnlyThroughLockLive` and `TestLockChecksCatchPlantedEvasions` (lockcheck_test.go).

**Gate:** Tier A (broker/vm): L3 with an explicit threat check.
