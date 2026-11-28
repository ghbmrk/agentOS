# TIM-1-interval-fu-b: agentosd's STATUS time check line moves to the interval

Board section: Defects and later findings on surviving packages. Work item #5279 (release items from #5215's reviews, split from #5216). #5216 (PR #5754) added `clock.Status.IntervalLine`; #5751 deletes `Status.Line`, `Guard.Now`, `ErrRestricted` and `Status.Restricted` once callers have moved.

**Problem:** SPEC TIM-1 (#5215) removed the restricted mode: time is an interval, widenings wait for its start, narrowings fire at its end, and STATUS lists each move a wide interval delays with its lift (LOG-8). `broker/cmd/agentosd/questions.go` still builds STATUS's time check line from `Status.Line` ("Time check: restricted since …") and, with no guard open, says "time-sensitive checks restricted". STATUS so names a mode SPEC no longer has.

**Requirements:** TIM-1, LOG-8.
1. `clockLine` returns `Status.IntervalLine` for every state but agreement, which stays "" (UX-98-1).
2. With no guard open, the line names no restricted mode: it says the clock is unconfirmed and agents' questions wait for it (they open only after the guard, #1246).
3. agentosd's tests no longer read `Status.Restricted`, so #5751 can delete it.

**Not built here, each its own release row:**
- Issue item 2 (CLK-7 `PLAN <plan> ON` reply after `PLAN <plan> OFF` withdrew consent): the box has no `PLAN` control word yet (`broker/owner`, `broker/control` and agentosd parse none; agentosd's plan `Consent` is the constant false, ASSUMPTIONS PS3), so there is no reply to change. The reply requirement moves to the row that adds the `PLAN` control words.
- The #5401 note (STATUS says why a hold runs long when the reading was wide at its start): the kernel's `Wide` reading flag does not exist yet; the wording follows #5401.

**Scope:** `broker/cmd/agentosd/questions.go`, `questions_test.go`, a new `zz_tim1_interval_line_test.go`, `ASSUMPTIONS.md`, this brief.

**Acceptance tests:** `broker/cmd/agentosd/zz_tim1_interval_line_test.go`: `TestTIM1StatusLineIsTheInterval`, `TestTIM1NoGuardLineNamesNoRestrictedMode`; the updated `TestClockLineOnlyForExceptions`, `TestTheClockGuardOutlivesAQuestionStoreFailure` and `TestQuestionsRunInAgentosd` keep passing.

**Tier / gate:** tier A (`broker/cmd/agentosd`): L3 on the strongest model, the tier's lens screen and a separate Security accept.

**Usage estimate:** one session.
