# P1-4-killfail: a failed VM kill is not a stop

Board section: Phase 1 (P1-4 rows). Owner-approved finding 9 of the 2026-10-11 code-inspection review on main 75d68c4 (project Questions thread).

**Defect: P1-4.** `stopRuntime` (broker/vm/vm.go) set a Running machine Stopped even when the runtime or cgroup kill failed, though it kept the disk committed because the guest was not known dead. A later `Preempt` then saw a machine that was not Running, took the "admitted but not started" branch and returned nil, so admission (RES-2) treated the guest as dead and handed its memory reservation to the next machine while the guest could still be running. The same failure let a failed parking stop (worker.go) and a failed rollback or rebuild release the machine's admission.

Fix: on a failed kill, `stopRuntime` leaves the state unchanged, so a Running guest stays Running and counted, and a retried preemption kills again or returns the error. `restartHeld` no longer forces Stopped after a failed kill, and `Rollback`, `Rebuild` and `Resume` keep the admission of a machine still Running. A lockless preemption whose kill succeeded records the machine Preempted even if the later runtime cleanup fails (L3 B1 on #1043).

**Requirements:** RES-1, RES-2. No new IDs.

**Scope:** `broker/vm/vm.go`, `broker/vm/sleep.go` (comment), `broker/vm/preempt_test.go`, `broker/vm/fake_test.go`, `broker/vm/ASSUMPTIONS.md`, `BOARD.md`, this brief.

**Acceptance:** with a kill that fails without killing, a retried `Preempt` returns an error and a foreground `Create` that needs the memory is refused; once the kill works, the retry kills the guest and records it Preempted. A rollback or rebuild whose kill fails keeps the admission. Both tests fail before the change. PR body carries `Defect: P1-4`.

**Needs:** —

## Delivery

Builder model: strongest model (risk tier A: `broker/vm`). Builder ends at push and CI; review and merge are the coordinator's. Estimate/checkpoint: 60k tokens, not a ceiling (OPERATING §5).
