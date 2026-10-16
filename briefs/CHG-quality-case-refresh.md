# CHG-quality-case-refresh: a goal's revised verdict updates its regression cases (OP-7)

Board row: issue #1973. Source: release finding from SM-adoption-journal-b (R6b, OP-7 trigger). Class: release. Tier: A (`broker/change/suite.go`). Split (G1 freeze): the Harvest half (`broker/loops/` is a frozen-import in tools/g1_scope.txt) is #1983, which carries QCR-4 and QCR-5's implicit clause; until it lands, Harvest still keeps the first case, so this package's supersede is reachable only through `AddTaskCase` callers that offer a revision. Builder: strongest model. Usage estimate: 90k tokens, checkpoint at 70k.

**Why (facts, verified at main b96fb72).** `Pipeline.addCase` (`broker/change/suite.go`) answers an existing case ID with `ErrDuplicate`, and `Harvester.Harvest` (`broker/loops/harvest.go`) returns early once a case was added ("the suite keeps the first") and ignores `ErrDuplicate`. So when the owner revises a task's verdict (YES, then UNDO), the journal carries the new verdict and the SM-AQ-1 trigger (`quality_trigger.go`) re-evaluates the adoptions learned from that goal, but against the case outcome recorded before the revision: an adoption that regressed only on the revised task is kept. Harvest also records the verdict in the journal before it touches the case, so a trigger pass between the two (or a crash between them) scores on the stale case and then remembers the new verdict, and the adoption is never due again.

## Requirement (from SPEC.md)

- **OP-7** "A later revision supersedes the earlier one, and every reader (held-out suites CHG-1, adoption, ...) uses the latest revision; no reader keeps the first verdict. A revision that changes a verdict re-evaluates every adoption whose evidence included that goal (§11), and an adoption that no longer qualifies is reverted."
- **CHG-2** "Changing suites, graders, or adoption policy is an owner-approved intent". Growth from owner outcomes is the suite's defined input (`AddTaskCase` doc); removing a case needs approval.

Package IDs:
- **QCR-1** An owner's later outcome on a task supersedes that task's case in place: same ID, same split, new outcome and reference. The suite does not shrink, and no owner approval is asked. A restated outcome changes nothing.
- **QCR-2** The re-evaluation the revision triggers scores against the revised case: an adoption that regresses only on the revised task is reverted.
- **QCR-3** The trigger never settles on a stale case: while a due goal's own case disagrees with its latest verdict, its adoptions are neither re-evaluated nor marked evaluated; once the case is revised they are due again at once.
- **QCR-5** A revision cannot overwrite another case or weaken an owner's: a security case or another task's case under the ID is a conflict; an outcome that disagrees with the journal's verdict is refused (CHG-1); an implicit acceptance never supersedes an owner's case in the suite.

**Acceptance tests:**
- QCR-1: `TestRevisedOutcomeSupersedesCase` (`broker/change/quality_case_test.go`).
- QCR-2: `TestRecheckScoresTheRevisedCase` (same file).
- QCR-3: `TestTriggerWaitsForTheCaseRefresh` (same file).
- QCR-5: `TestRevisionCannotOverwriteAnotherCase` (`broker/change/quality_case_test.go`).

## Design (recommendation)

1. Supersede in place, no removal (the cheapest route that meets OP-7 without CHG-2 approval). `AddTaskCase` keeps its provenance check: the case's outcome must match the journal's latest owner verdict on its task. When the ID already holds a task case of the same task and class with the same input, the new outcome and reference replace the old ones in one save; restated outcome changes nothing. Same ID means same split, so a held-out case stays held out. Retiring the case was rejected: it is a removal (CHG-2) and shrinks the held-out set.
2. The trigger gate: `RecheckQuality` defers a due adoption (retry later, nothing remembered) while any case whose `Task` is one of its goals disagrees with that goal's latest verdict, for one `QualityRetry` at most, so a case that never comes (a crash between the verdict and the case) delays the re-evaluation rather than blocking it. A successful supersede clears the trigger's retry wait so the re-evaluation runs on the next pass.
3. (Split to #1983, not built here.) Harvest drops its "keeps the first" early return: a later action on an already-added intent goes to `AddTaskCase`, wakes the scheduler, and an owner case clears the implicit mark. An implicit acceptance on an intent that already holds an owner case returns before recording anything.

## Scope

`broker/change/suite.go`, `broker/change/quality_trigger.go`, `broker/change/pipeline.go` (one memory-only field), `broker/change/quality_case_test.go` (new), `broker/change/ASSUMPTIONS.md`, `briefs/CHG-quality-case-refresh.md`. **Guard files:** none.

## Out of scope

An explicit revision number on `journal.Quality` (#1927). Attention (CAP-6) and STATUS readers of OP-7.

## Done

CI green; QCR-1..3 and QCR-5 covered by tests carrying `REQ: OP-7` and their ID.
