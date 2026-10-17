# CAP-11-plan-fu3: per-lineage concurrency cap for provider runs

Board row: issue #1878. Source: PR #1864 delta review R4 (Security #9, L3 #12). Class: release. Tier: A (`broker/provagent`, `broker/workers`). Builder: strongest model. Usage estimate: 45k tokens, checkpoint at 35k.

**Why (verified at main).** `Runner.admit` (`broker/provagent/run.go:408`) caps concurrent runs per provider at `PerPool` (default `DefaultPerPool` = 2, RES-5), counted in `r.running[d.ID]`, and `TestConcurrentRunsAreCappedPerProvider` (`run_test.go:734`) covers it. The row's per-pool half is therefore done. What is missing is the per-lineage cap: `Request` carries no lineage, and one lineage can take both provider slots and starve the others. Failure path: one agent lineage looping `provider_run` holds the provider's two slots, so every other lineage gets `route-busy` for as long as it runs.

## Requirements

- **RES-5** (SPEC.md:628) default of 2 concurrent runs per pool and per lineage.
- **LIN-1** `provagent.Request` carries the caller's lineage (`Lineage string`, filled by `providerTool` from the calling tool's lineage). A run with an empty lineage is refused with the closed reason `failed` before a slot is taken, so no run is uncapped.
- **LIN-2** `admit` refuses with `RouteBusy` when the lineage already has `PerLineage` runs admitted and not ended (default 2, `Runner.PerLineage`, zero is the default), on any provider; the guest sees the existing `route-busy` line ("try again later, or use another route"), so no new closed reason is added.
- **LIN-3** A run that finishes, fails or is refused after admission releases both its provider slot and its lineage slot (the `release` path that already frees the provider slot).
- **LIN-4** The provider cap still holds: three lineages each starting one run against one provider are admitted twice and refused once.

**Acceptance tests** (`broker/provagent/run_test.go`; each carries `REQ: RES-5`):
- LIN-1: `TestRunWithoutLineageIsRefusedBeforeASlot`.
- LIN-2: `TestConcurrentRunsAreCappedPerLineage` (one lineage, two providers or one: the third run is `route-busy`, a different lineage is admitted).
- LIN-3: `TestFinishedRunFreesItsLineageSlot` (table: ok, timed-out, failed, refused-after-admit).
- LIN-4: `TestProviderCapHoldsAcrossLineages`.

**Revert mutants** (each turns a test red): count the lineage after the provider cap passes but never release it; key the count on the provider instead of the lineage; skip the empty-lineage check.

## Design (recommendation)

A `lineages map[string]int` beside `running`, both guarded by `r.mu` and changed in the same lock hold in `admit` and its release, so the two counts cannot drift. The cap is checked before the probe bookkeeping so a refused call neither takes a slot nor stamps `probed`.

## Assumptions

The tool layer knows the caller's lineage (`broker/workers` tools take it today: `Workers(lineage)`, `CreateWorker(ctx, id, lineage, ...)`).

## Out of scope

Journal wiring (#1876), changing the provider cap, an owner setting for either cap.

## Scope

`broker/provagent/run.go`, `broker/provagent/run_test.go`, `broker/workers/provider.go`, `broker/workers/provider_test.go`, `broker/cmd/agentosd/main.go` (the `providerTool` adapter passes the lineage), `broker/provagent/ASSUMPTIONS.md`, `briefs/CAP-11-plan-fu3.md`.

## Done

CI green; LIN-1 to LIN-4 covered by the acceptance tests.
