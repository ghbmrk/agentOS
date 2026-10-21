# KRN-calls: no kernel lock across a clerk call, and a clerk that is down sends nothing

Work items: #2700 items 1 and 2 (release items from the #2687 reviews; they land before MIG-4-run slice 3). Tier A.

## Goal

1. **Clerk calls outside the kernel's lock (KRN-7, OWN-18).**
   - `Kernel.Calls(now)` logs holds, cancels and dispatches, and returns the clerk calls now due, each once until it is answered.
   - `Kernel.Answer(now, call, result)` logs the answer.
   - `Tick` is the same two steps over the in-process clerks.
   - `Kernel.Send` checks each dispatch again just before it goes out: a STOP, revoke or cancel logged since `Calls` cancels it unsent, and a pause leaves it unsent.
   - The kernel process (`broker/clerk/run`) takes the calls under its lock. For each call it makes that check and takes the view under the lock, makes the call without it, and logs the answer under it again.
   - Failure path: STOP waits up to five minutes behind a hung provider.
2. **A clerk that is down sends nothing (KRN-7, OWN-17).**
   - A dispatch that reached no clerk is `unsent`. STATUS lists it with its clerk, and it is sent again under the same idempotency key, charged once, after `UnsentWait`, doubling at each attempt up to `MaxUnsentWait`.
   - A probe that reached no clerk is `unreached` and counts no check.
   - Failure paths: an unreachable clerk fails the plan without telling the owner, or a clerk down for about 13 minutes parks every step it had in flight with a false "may happen twice" warning.

Out of scope: #2700 items 3 to 6 (view size, LANES seam, socket field tests).

## Scope

`broker/kernel/`, `broker/clerk/run/` (`kernel.go`, `wire.go`, tests), `briefs/KRN-calls.md`.

**Guard files:** none (no new package).

## Acceptance tests

- KRN-7, OWN-18: `broker/clerk/run/run_test.go::TestStopReturnsWhileAClerkCallHangs`, `::TestAStopWhileACallHangsSendsNothingAfterIt`, `broker/kernel/calls_test.go::TestADispatchStoppedSinceCallsIsNotSent`
- KRN-7, OWN-17: `broker/kernel/calls_test.go::TestAnUnsentStepIsSentAgainAfterItsWait`, `::TestAnUnsentStepCancels`, `::TestTheUnsentWaitBacksOff`
- KRN-8, OWN-17: `broker/kernel/calls_test.go::TestAnUnreachedProbeCountsNoCheck`, `::TestAnUnsentStepBlocksTheSameEffect`

## Estimate

About 60k tokens, single session.
