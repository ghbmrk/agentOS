# W3-forget-reach-r1: test the `owing` guard in `judgeAgent` (mutant N11)

Board row: W3-forget-reach-r1 (Integration section). Source: L3 R1 on #569 (W3-forget-reach). Class: release. Tier: A (`tools/risk_tier.py` prints A for the scope below). Builder: strongest model. Estimate: 40k tokens, checkpoint 30k.

**Why (facts, verified at main 8676ac9).** `judgeAgent` (`broker/cmd/agentosd/forget.go:1016`) skips any goal whose `f.owing[g]` is set, so `resumeAgent` does not judge an item 2 that `agentBack` is still carrying between its owe and its `takeBack`. No test runs `resumeAgent` in that window, so deleting the `mine` check survives (mutant N11).

**Requirement:** CAP-3 ("an agent that read it is rolled back"; the owner is told done once, only when true). Package ID **W3-forget-reach-r1-1**: `resumeAgent` run while an `agentBack` for the same goal is between owe and `takeBack` neither tells done nor drops the entry; the entry is judged after `agentBack` finishes.

**Acceptance tests:**
- W3-forget-reach-r1-1: `broker/cmd/agentosd/forget_owed_test.go::TestForgetItem2ResumeDuringAnAgentBackIsNotJudged`: a fake `work` blocks `TakeBack` on a channel and its `TakeBackOf` returns `TakeBackNone` during the blocked window (the real state before `MarkTakeBack(false)`); run `resumeAgent` while it blocks; assert no `tellAgent` and the owed entry still present; release, assert exactly one done text. Mutant that must fail it: remove the `mine` check in `judgeAgent`.

**Scope:** `broker/cmd/agentosd/forget_owed_test.go` (test only; production change only if the test shows a real race, then `forget.go` `judgeAgent`), this brief.
**Dependencies:** none merged-pending; shares `forget.go` and `forget_owed_test.go` with W3-forget-reach-r3 and -r5, so build them in one session or in sequence (D-111).
**Out of scope:** the other W3-forget-reach-r* rows.
**Done:** CI green; the test passes; the mutant fails it, reported in the PR.
