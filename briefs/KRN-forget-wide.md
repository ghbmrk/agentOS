# KRN-forget-wide: a FORGET ask that a wide clock reading has already lapsed says so instead of asking

Work item: #5886 (release item 2 of #5811, from the #5810 reviews). Tier A.

## Goal

`AskForget` sets an ask's lapse at `Earliest + ForgetAskFor` and `ForgetReply` refuses once `Latest` reaches it (TIM-1, LOG-4). A reading at least `ForgetAskFor` wide has lapsed the ask before it is sent, so the owner would be told to reply within 10 minutes to an ask no reply can satisfy (CH-12). `AskForget` instead refuses with `ErrForgetClock`, whose text is the owner's text naming the cause and the step, and leaves no ask waiting. Live once #5391 passes the TIM-1 guard's reading as `KernelConfig.Clock`; the kernel reads `At(now)` today.

## Scope

`broker/kernel/forget.go`, `broker/kernel/erase_test.go`, `broker/kernel/ASSUMPTIONS.md`, `broker/kernel/proc/kernelsock.go` (the new sentinel crosses the socket by its text), `briefs/KRN-forget-wide.md`.

**Guard files:** none (no new package).

## Acceptance tests

- TIM-1, CH-12: `broker/kernel/erase_test.go::TestTIM1AWideReadingRefusesAForgetAsk` (a reading `ForgetAskFor` wide or wider refuses with the text and no ask waits; just under it, the ask is taken)
- TIM-1, LOG-4: `broker/kernel/erase_test.go::TestTIM1AForgetAskLapsesOnLatest` still passes; its first case asks at a reading just under `ForgetAskFor` wide, since a wider one is now refused.

## Estimate

About 40k tokens, single session.
