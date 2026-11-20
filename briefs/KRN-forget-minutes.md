# KRN-forget-minutes: a Forget ask at a reading narrower than 10 minutes promises the true time left

Work item: #5938 (release item R3 of #5937, from its L3 and Potency reviews). Tier A.

## Goal

An ask at a reading `w` ms wide (`w < ForgetAskFor`) lapses `ForgetAskFor − w` of true time after it is sent, since `ForgetReply` refuses once `Latest` reaches `Earliest + ForgetAskFor`; the text still says "within 10 minutes" (TIM-1, CH-12). `AskForget` renders the time left rounded down, in minutes and under a minute in seconds, and refuses with `ErrForgetClock` under one second. `ErrForgetClock`'s wording and R5 (HOST-1b time sync) stay with #5938's later part, waiting on #5391 and #5757.

## Scope

`broker/kernel/forget.go`, `broker/kernel/erase_test.go`, `broker/kernel/ASSUMPTIONS.md`, `briefs/KRN-forget-minutes.md`.

**Guard files:** none (no new package).

## Acceptance tests

- TIM-1, CH-12: `broker/kernel/erase_test.go::TestTIM1AForgetAskNamesTheTimeLeft` (each width's text names the time left rounded down, a YES inside that promise is taken however the reading moved, and under a second left the ask is refused)
- TIM-1, CH-12, LOG-4: `::TestTIM1AWideReadingRefusesAForgetAsk` and `::TestTIM1AForgetAskLapsesOnLatest` still pass; their "just under" cases ask with a second left, since 1 ms is now refused.

## Estimate

About 40k tokens, single session.
