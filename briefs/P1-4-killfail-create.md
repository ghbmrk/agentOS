# P1-4-killfail-create: a failed cleanup kill keeps the guest's admission

Board section: Phase 1 (P1-4 rows), work item #1130. Follow-up of P1-4-killfail (#1043): release finding from its reviews.

**Defect: P1-4.** P1-4-killfail made a failed kill leave a Running guest Running and admitted, but three cleanup paths still drop the admission after an ignored or failed kill: (a) `create` and `Fork` call `stopRuntime` on a guest `startFrom` launched, ignore its error, and `release` the memory (vm.go `create`, Fork's start loop); (b) the `restartHeld` half-start (Rollback, Rebuild, Resume) releases memory when `startFrom` launched the guest and then failed before Running and the cleanup kill also failed; (c) Fork's undo ignores `Destroy` errors for forks already started and releases their admission. `Merge`'s restart of its destination releases the admission the same way, even of a destination still Running. In each case admission (RES-2) hands the memory to the next machine while the guest may still run.

Fix: each path checks the cleanup kill. On failure it keeps the machine's admission (and its record, so a later Destroy or Preempt can retry the kill) and returns the error; only a confirmed kill releases memory.

**Requirements:** RES-1, RES-2. No new IDs.

**Scope:** `broker/vm/vm.go`, `broker/vm/preempt_test.go`, `broker/vm/fake_test.go`, `broker/vm/diskquota_test.go` (its failed-creation test reused the unkilled machine's ID), `broker/vm/ASSUMPTIONS.md`, this brief.

**Acceptance:** with a kill that fails without killing, each of a failed Create cleanup, a failed Fork cleanup, a restartHeld half-start after startFrom (Rollback, Rebuild, Resume, Merge), and a Fork undo whose Destroy errors keeps the guest's admission, so a foreground `Create` needing that memory is refused. The tests live in `broker/vm/preempt_test.go` and fail before the change. PR body carries `Defect: P1-4`.

**Acceptance tests:** RES-2: `broker/vm/preempt_test.go::TestRES2FailedCreateCleanupKillKeepsTheAdmission`, `TestRES2FailedForkCleanupKillKeepsTheAdmission`, `TestRES2FailedForkUndoDestroyKeepsTheAdmission`, `TestRES2HalfStartWithFailedKillKeepsTheAdmission` (rollback, rebuild, resume) and `TestRES2MergeHalfStartWithFailedKillKeepsTheAdmission`.

**Needs:** P1-4-killfail (merged).

## Delivery

Builder model: strongest model (risk tier A: `broker/vm`). Builder ends at push and CI; review and merge are the coordinator's. Estimate/checkpoint: 60k tokens, not a ceiling (OPERATING §5).
