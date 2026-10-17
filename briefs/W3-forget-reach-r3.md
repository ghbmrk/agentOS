# W3-forget-reach-r3: test that `judgeAgent` drops a `Taking` entry when recall holds no take-back (mutant N13)

Board row: W3-forget-reach-r3. Source: Security 4a R2 on #569 (N13 in Security's numbering, N12 in L3's; L3 classed it later). Class: release. Tier: A. Builder: strongest model. Estimate: 35k tokens, checkpoint 25k.

**Why (facts, verified at main 8676ac9).** `judgeAgent` (`broker/cmd/agentosd/forget.go:1016-1040`) calls `f.paid(g)` for `st == recalltool.TakeBackNone`: nothing was taken back, so the owed entry goes and the journal runs item 2 again. A crash after the owe and before `MarkTakeBack(false)` reaches this branch after restart; no test does, so removing the `TakeBackNone` case survives.

**Requirement:** CAP-3 and UX-182-3 (an owed text is not kept for a take-back that never happened, and the take-back itself is not lost). Package ID **W3-forget-reach-r3-1**: after a simulated crash between the owe and `MarkTakeBack(false)`, once recall opens no `Taking` entry remains and item 2 is re-run by the journal.

**Acceptance tests:**
- W3-forget-reach-r3-1: `broker/cmd/agentosd/forget_owed_test.go::TestForgetItem2CrashAfterOweBeforeTakeBackLeavesNoEntry`: save an owed `Agent`+`Taking` entry, fake `TakeBackOf` returns `TakeBackNone`, run `resumeAgent`; assert the entry is gone, no done text sent, and the journal's item 2 runs once. Mutants that must fail it: delete the `TakeBackNone` case; call `tellAgent` there.

**Scope:** `broker/cmd/agentosd/forget_owed_test.go`, this brief (`forget.go` only if the test shows a defect).
**Dependencies:** share files with W3-forget-reach-r1 and -r5: one session, in order r1, r3, r5.
**Out of scope:** the Security/L3 numbering difference; other reach-r* rows.
**Done:** CI green; test passes; both mutants fail it.
