# KRN-reserve: a metered call reserves its worst case until it is settled

Work item: #2613 item 1 (concurrent admission). Tier A. It is stacked on KRN-tidy (#2723).

## Goal

1. **Admission reserves.** `AdmitSpend` logs the call's worst case as `model.reserved` and returns `Admitted{Plan, Seq}`. The reservation counts against every cap until `Meter(now, admitted, ...)` settles it with what was used. Failure path: two clerks, or two calls of one clerk, are admitted against the same remaining budget and together overspend a cap.
2. **Settlement is exact and once.** `Meter` charges the key and scopes the call was admitted under, from its reservation, so usage after a revoke or the plan's end is still recorded. A second settlement, or one citing another plan's admission, is refused (`ErrNotAdmitted`). A reservation survives a restart in the log. One never settled stays charged at its worst case.
3. **A busy cap is not an exhausted one.** A call refused only because calls still in flight fill a cap is `in-flight`, and the model clerk does not hold the plan for it. A call that cannot fit even once they settle is refused by the cap and holds the plan, as before.
4. **The model clerk calls the provider without its lock.** The lock covers only its owed log writes. A request that never left settles at 0.

Out of scope:
- A timeout that settles an admission left open by a dead clerk.
- The kernel process's socket for the metering side (MIG-4-run slice 3).

## Scope

`broker/kernel/`, `broker/clerk/model/`, `broker/clerk/inbox/reader_test.go` (its test ledger's signatures), `briefs/KRN-reserve.md`.

**Guard files:** none (no new package).

## Acceptance tests

- LOG-7: `broker/kernel/meter_test.go::TestAdmissionsReserveTheirWorstCase`, `::TestUsageOfARevokedKeyIsRecorded`, `::TestUsageOverAnAdmissionIsStillRecorded`
- KRN-1, LOG-7: `broker/clerk/model/model_test.go::TestConcurrentCallsShareNoBudget`, `::TestRequestThatNeverLeftMetersNothing`

## Estimate

About 50k tokens, single session.
