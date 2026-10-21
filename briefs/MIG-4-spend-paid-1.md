# MIG-4-spend-paid-1: pin the call-time pool window

Release follow-up of MIG-4-spend-paid (#2656), issue #2662. Tier A (`broker/clerk/model`), test only.

**Goal.** When a provider's pool reading carries no reset time, the clerk sets the reset time to the call time plus `kernel.PoolWindowMS`. Nothing tested the value the ledger receives, so passing the raw reading's reset time instead went undetected. With that mutant, an outage between the call and the log's recovery made the cooldown longer than the declared window.

**Requirement IDs:** RES-5.

**Acceptance tests:** `broker/clerk/model/model_test.go::TestOwedReadingKeepsTheWindowFromTheCall`: a reading with no reset time, owed through an outage and recorded later, carries `reset_at` = call time + window, and the pool reopens then. It fails if the ledger gets the raw `u.Pool.ResetAt`.

**Out of scope.** #2662's later note (telling a refused reading from a write failure) needs a typed refusal from `kernel.ReadPool` and belongs to the kernel lane.

**Declared scope:** `broker/clerk/model/model_test.go`, this brief.

**Guard files:** none.

**Usage estimate:** 30k tokens.
