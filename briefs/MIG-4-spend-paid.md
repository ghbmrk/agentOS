# MIG-4-spend-paid: keep paid replies, meter reported usage

Follow-up of MIG-4-spend (#2581), from #2613 items 7 and 10 (the adapter part). Tier A (`broker/clerk/model`).

**Goal.** A model call the owner paid for is never thrown away for a bookkeeping failure that is not about its spend, and a provider's own usage figure is always what is metered.

1. **Item 7.** After a call is metered, a `ReadPool` the log refuses no longer withholds the reply. The refused reading (a figure outside 0..1000, or a lower reading on a pool the owner closed mid-call by raising the reserve) is recorded as a full pool at the provider's reset time, since a reading can only narrow. A reading the log cannot write is owed like unrecorded spend: the reply is returned, the clerk makes no further call until the log records it, and the retry writes the provider's own figure (full only if refused). An owed reading whose reset time (or the declared window, when the provider gave none) has passed is dropped. A failed meter still applies the call's reading.
2. **Item 10, adapter part.** The `Provider` contract says when an adapter returns `ErrNotSent` (no byte written) and when it reports a zero (an unbilled error). The clerk meters a `Reported` figure whatever the error, `ErrNotSent` included (#2581 Security round-4 point 3). No adapter exists in `broker/clerk/model` yet; the adapters and one test per case come with the wiring step (#2613 items 3 and 10, Step C).

**Requirement IDs:** LOG-7, RES-5, CLK-7.

**Acceptance tests** (all in `broker/clerk/model/model_test.go`):
- `TestPaidReplyIsKeptWhenItsPoolReadingIsRefused`: a bad figure and a reserve raised mid-call both keep the reply and record the pool full; fails if the reply is withheld or the reading is dropped.
- `TestUnrecordedPoolReadingShutsTheClerkUntilTheLogRecords`: with the log unable to write readings, the reply is kept, the next call is refused, and once the log recovers the provider's own figure is recorded and the pool stays open; fails if the reading is not owed or is recorded as full.
- `TestOwedReadingPastItsResetIsDropped`: a reading owed past its reset time (or past the window when it had none) is not recorded once the log recovers; fails if the stale reading is written or the window is not set at the call.
- `TestPoolReadingIsAppliedWhenTheMeterFails`: a failed meter still closes the pool its reading filled; fails if the reading is skipped on a meter failure.
- `TestReportedUsageIsMeteredEvenWithErrNotSent`: a figure reported with `ErrNotSent` is metered as `provider`; fails if `ErrNotSent` alone skips the meter.

**Out of scope.** Items 1, 2, 4, 8, 9, 11, 12 (kernel, Kernel and clerk hardening lane); items 3 and the wiring part of 10 (Step C delete); items 5 and 6 (owner text, which `clerk/model` does not hold).

**Declared scope:** `broker/clerk/model/model.go`, `broker/clerk/model/model_test.go`, `broker/clerk/model/ASSUMPTIONS.md`, this brief.

**Guard files:** none (no package added or linked; `clerk/model` already imports `broker/kernel` in its tests and the constant `kernel.PoolFull` and `kernel.PoolWindowMS` constants are not core write paths).

**Usage estimate:** 80k tokens.
