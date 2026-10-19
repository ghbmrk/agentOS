# SEC-backs-append-latch: a failed recall append never damages the next line

Board section: Recall. Work item: #2461. Defect: W3-forget-reach-r2 (back-marks side file, `backs.jsonl`). **Tier A** (`broker/recall`).

**Why / failure path.** `recall.FileStore.Append` (`broker/recall/store.go`) leaves the bytes of a failed write in place. The next append joins onto that torn line, and `OpenProvenanceWithBacks` skips the joined line at restart. So: rollback counter inert, first back mark's side append is partial, second back mark's side append succeeds onto the torn tail, primary is repaired for the first mark only, reopen: the second back mark is gone and that rollback repeats (CAP-3, RCH-2).

**Requirements:**
- SEC-BAL-1: a failed append (write error or sync error) is cut back to the file's size before the append, and synced, so the next append starts on a clean line.
- SEC-BAL-2: if that cut or its sync fails, the store refuses every later append until a `Rewrite` succeeds or the store is reopened.

**Acceptance tests:** (REQ: SEC-BAL-1, SEC-BAL-2)
- `broker/recall/backs_append_test.go::TestBackMarkAfterAPartialSideAppendSurvivesARestart` (Mark's regression; mutants: no cut, latch only).
- `broker/recall/append_test.go::TestFailedAppendIsCutBack` (SEC-BAL-1; mutants: no cut, cut to 0).
- `::TestFailedSyncIsCutBack` (SEC-BAL-1; mutant: cut only on a write error).
- `::TestUncutAppendRefusesAppendsUntilRewrite` (SEC-BAL-2; mutant: no latch on a failed cut).
- `::TestUnsyncedCutRefusesAppends` (SEC-BAL-2; mutant: no latch on a failed cut sync).

**Out of scope.** `recall.DirStore` segments and `journal` appends (their own repair paths).

**Scope:** `broker/recall/store.go`, `export_test.go`, `append_test.go`, `backs_append_test.go`, `broker/recall/ASSUMPTIONS.md` (SEC-backs-append-latch-1), this brief.

**Usage estimate:** 60k tokens; checkpoint at 45k.
