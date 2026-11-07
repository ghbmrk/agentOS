# KEY-9-reach-b1: wire the worth table's settled values into grants and the hold

Board section: Owner channel and approvals (SPEC §10). Work item #4999, split under its own scope: b1 is items 2 (wire the price) with Mark's values; items 1 (graph reach over declarations), 3 (grows-then-narrows) and 4 (FRM-key worth term) are the follow-up.

**Values** (Mark, 2026-11-07, issue comment 6705669120): a rank-3 widening needs P4, holds as drafted in #5004; each step is priced by what that step reaches, a grant at its key's worth; device verbs are not safety by default; uncapped money only at a bare root.

**Requirements:** KEY-9 (part b1), KEY-8, KEY-4. `actuate` reaches none and `present` data; a new grant worth rank 3 needs the co-sign (two passkeys, one an anchor); an irreversible step's hold adds `HoldExtra` of its own verb's worth, except a step the owner approved one by one.

**Scope:** `broker/kernel/key/worth.go`, `worth_test.go`; `broker/kernel/cosign.go`, `state.go` (one line), `kernel.go` (the hold), `worth_test.go`, `kernel_test.go`, `ASSUMPTIONS.md`; `broker/clerk/check/check.go`, `broker/kernel/sim/sim.go`, `broker/clerk/inbox/cmd/slice/run.go` (the same window); `broker/clerk/run/clerk_test.go`; this brief.

**Acceptance tests:** `kernel/key/worth_test.go`: `TestEveryVerbsReachIsPinned` (device rows), `TestStepHoldIsPricedByItsOwnVerb`. `kernel/worth_test.go`: `TestARankThreeGrantNeedsTheHardwareKey`, `TestAHeldStepWaitsItsOwnWorth`.

**Tier / gate:** tier A (trusted base): L3 and a separate Security accept.
