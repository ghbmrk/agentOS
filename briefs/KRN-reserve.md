# KRN-reserve: a metered call reserves its worst case until it is settled

Work item: #2613 item 1 (concurrent admission), with #2670 item 4 (KRN-schema: `key.issued` v2) and #2670 item 2 (the sim enrolls and cuts off a phone) folded in. Tier A. It is stacked on KRN-tidy (#2723) and adapts #2717's meter socket, which merged first.

## Goal

1. **Admission reserves.** `AdmitSpend` logs the call's worst case as `model.reserved` and returns `Admitted{Plan, Seq}`. The reservation counts against every cap until `Meter(now, admitted, ...)` settles it with what was used. Failure path: two clerks, or two calls of one clerk, are admitted against the same remaining budget and together overspend a cap.
2. **Settlement is exact and once.** `Meter` charges the key and scopes the call was admitted under, from its reservation, so usage after a revoke or the plan's end is still recorded. A second settlement, or one citing another plan's admission, is refused (`ErrNotAdmitted`). A reservation survives a restart in the log. One never settled stays charged at its worst case.
3. **A busy cap is not an exhausted one.** A call refused only because calls still in flight fill a cap is `in-flight`, and the model clerk does not hold the plan for it. A call that cannot fit even once they settle is refused by the cap and holds the plan, as before.
4. **The model clerk calls the provider without its lock.** The lock covers only its owed log writes. A request that never left settles at 0.

5. **The meter socket carries the admission** (#2717 merged first). `admitspend` answers the `Admitted`, `meter` settles by its sequence, and `ErrNotAdmitted` crosses as itself. A retry of a settlement whose answer was lost after it landed is refused as already settled, which the clerk counts as recorded. docs/LANES.md names the new signatures, as the frozen seam requires.
6. **KRN-schema.** `key.issued` moves to version 2, so a pre-batch log is refused, not misread.
7. **Sim.** The sim enrolls a phone, has it renew and narrow clerk keys and cuts it off; the world judges a cut-off phone's later grants, its grants in their hold and its narrowings from its own record.

Out of scope:
- A timeout that settles an admission left open by a dead clerk.
- The kernel process's socket for the metering side (MIG-4-run slice 3).

## Scope

`broker/kernel/` (with `sim/`), `broker/clerk/model/`, `broker/clerk/run/` (the meter socket's rows, its client and its ASSUMPTIONS), `broker/clerk/inbox/reader_test.go` (its test ledger's signatures), `docs/LANES.md` (the frozen seam's metering signatures; a gate file), `briefs/KRN-reserve.md`.

**Guard files:** none (no new package).

## Acceptance tests

- LOG-7: `broker/kernel/meter_test.go::TestAdmissionsReserveTheirWorstCase`, `::TestASettlementChargesTheKeyItWasAdmittedUnder`, `::TestARefusalNamesTheCapSettledUsageExhausts`, `::TestUsageOverAnAdmissionIsStillRecorded`
- LOG-7: `broker/clerk/model/model_test.go::TestALostSettlementIsRecordedOnce`, `::TestAFirstSettlementRefusedIsNotRecorded`; `broker/clerk/run/kernelsock_test.go::TestEverySocketCallIsTheDirectCall`
- KRN-1: `broker/kernel/kernel_test.go::TestEntryTypesAreClosed` (a v1 `key.issued` is refused)
- D-146: `broker/kernel/sim/sim_test.go::TestSweepHoldsInvariants`, `::TestSweepFaultsTakeEffect` (`CutRefused`, `CutCancelled`)
- KRN-1, LOG-7: `broker/clerk/model/model_test.go::TestConcurrentCallsShareNoBudget`, `::TestRequestThatNeverLeftMetersNothing`

## Estimate

About 50k tokens, single session.
