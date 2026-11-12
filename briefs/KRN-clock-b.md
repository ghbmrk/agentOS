# KRN-clock-b: the kernel reads time as a reading and never backward

Board section: Migration to the capability kernel (D-139). Work item #5147, part b (part a, `broker/clock` off `broker/durable`, merged as #5175).

**Problem:** the kernel process's clock is raw wall time (`kernelmain.go`), `Log.Append` takes any time, and an expiry is checked against each call's `now` and never logged, so a clock stepped back revives an expired key (KEY-7) and a step forward ends a hold early (KEY-8). `Tick` fixes `now` for the whole tick, so `Send`'s last check can run minutes stale.

**Requirements:** TIM-1, KEY-7, KEY-8, KEY-4, KRN-5. The kernel decides on a `Reading` (earliest and latest credible time): widenings wait for `Earliest`, narrowings fire on `Latest`. Each reading is floored at the log's last entry; the log refuses an entry before the last. Each entry carries its reading (`At`, `Late`) and Rederive re-derives timed decisions at it and fails decreasing times. A kernel booted on a clock reads it afresh at each decision, `Send` included. The kernel package does not import `broker/clock`. The kernel process carries its time forward from the log's last entry on the monotonic clock, so a start behind the log neither revives a key nor stops time.

**Scope:** `broker/kernel` (clock wiring: `clock.go`, `log.go`, `kernel.go`, `rederive.go` and the methods that take time), `broker/kernel/key/authorize.go` (`Context.Late`), `broker/kernel/proc` (`kernel.go`, `kernelmain.go`), `broker/kernel/sim`, their tests and ASSUMPTIONS, `image/ASSUMPTIONS.md` (I10), and the tests of other packages that logged a grant before an earlier entry (`browser`, `clerk/model`, `cmd/agentosd`), which the floor now refuses.

**Acceptance tests:** `broker/kernel/rederive_test.go`: `TestTIM1ClockStepBackRevivesNoKey` (the issue's probe ends `rejected` for both plans; times ordered; Rederive fails decreasing times; `Append` refuses one), `TestTIM1ReadingDecidesBothWays` (expiry by `Latest`, hold by `Earliest`; Rederive fails an admission past expiry by the logged `Late` and a dispatch from a hold whose logged `At` is before its due), `TestTIM1SendReadsTheClockAfresh` (a dispatch whose key expires while an earlier call hangs is answered unsent). `broker/kernel/proc/anchor_test.go`: `TestTIM1AStartBehindTheLogCarriesItsTimeForward`. `broker/kernel/sim/judge_test.go`: `TestNoReadingKernelFailsBothClockInvariants`, and the sweep holds both new invariants with clock steps back and disagreements in the op mix.

**Out of scope:** a second time source inside the kernel's sandbox and linking the TIM-1 guard (`broker/clock`) into the kernel process: the kernel's unit has no network and no modem, so the guard there has no source to compare (see the PR's Findings); the guard's state file (#5195); `broker/clock` follow-ups (#5216).

**Tier / gate:** tier A (`broker/kernel`): L3 on the strongest model, the tier's lens screen and a separate Security accept. Trusted lines grow; the ceiling (D-310) needs Mark's raise.

**Usage estimate:** one session.
