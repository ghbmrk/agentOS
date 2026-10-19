# CH11-stop-hint-tests: cover the STOP hint's full reach on reactions

Board section: Human-native texting (spec #2157, D-127). Follow-up of CH11-stop-hint-reaction (#2264, PR #2355), from the review findings on that PR (combined at 0008d533, findings 1 to 4; combined delta at 41a64591, findings 1 and 2).

**Why.** After #2355 merged onto main's `tell` flag, the hint reaches the cut form and the CAP-3 forgotten-agent-text form, but the tests covered only the closed unlisted form. Failure path: a change that drops the near-miss branch, spends the window before the lead-in test, puts the hint after the read-as-reaction line, or stops carrying the lead-in on the cut or CAP-3 path passes the suite. O42 in `broker/owner/ASSUMPTIONS.md` still says a STOP-led reaction misses the hint.

**Requirements:** CH-11; CH-15 (one hourly quiet window); CAP-3 (a forgotten reply never reaches the agent).

**Change.** Tests only, plus the O42 sentence. No code change.

**Acceptance tests:** `broker/owner/reaction_stophint_reach_test.go::TestNearMissLedReactionGetsTheStopHintFirst`, `::TestOtherLeadInLeavesTheStopHintWindowUnspent`, `::TestStopLedCutFormGetsTheStopHint`, `::TestStopLedFormOnAForgottenReplyGetsTheStopHint`, `::TestListedFormAfterADeletionLeavesTheStopHintWindowUnspent`.

**Guard files:** none.

**Out of scope.** The hint's wording (finding 5 on #2355) is shared with daemon B4's near-miss path, so it is left for a separate change. The `HintQuiet` length gap is on unchanged lines.

**Scope:** `broker/owner/reaction_stophint_reach_test.go`, `broker/owner/ASSUMPTIONS.md`, this brief.

**Usage estimate:** 20k tokens.
