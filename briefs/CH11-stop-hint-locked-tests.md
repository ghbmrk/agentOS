# CH11-stop-hint-locked-tests: pin the STOP hint's order on the locked path

Board section: Human-native texting (spec #2157, D-127). Follow-up of CH11-stop-hint-tests (PR #2453), from its later findings (Security finding 1; combined findings 1 to 3). Later items filed as #2465 (hint wording) and #2466 (`HintQuiet` length).

**Why.** The locked reply reuses the unlocked reply list, so the hint comes before the read-as-reaction line in both cases today. But the only locked test checks the closed STOP-led form, and it doesn't check order. Failure path: if the locked path is ever split off and drops or reorders the hint for the cut or forgotten-reply form, the suite still passes. Separately, `TestOtherLeadInLeavesTheStopHintWindowUnspent` would still pass if the `Cancel` reaction fell back to chat.

**Requirements:** CH-11; CH-15; CAP-3.

**Change.** Tests only. No code change.

**Acceptance tests:** `broker/owner/reaction_stophint_reach_test.go::TestLockedStopLedCutFormGetsTheStopHintFirst`, `::TestLockedStopLedFormOnAForgottenReplyGetsTheStopHintFirst`, `::TestOtherLeadInLeavesTheStopHintWindowUnspent`.

**Guard files:** none.

**Scope:** `broker/owner/reaction_stophint_reach_test.go`, this brief.

**Usage estimate:** 15k tokens.
