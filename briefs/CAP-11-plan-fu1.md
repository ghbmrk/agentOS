# CAP-11-plan-fu1: wire the OP-8 Journal into agentosd's provider runner

Board row: issue #1876. Source: PR #1864 delta review R4 (Security #9, L3 #9). Class: release. Tier: A (`broker/cmd/agentosd`, `broker/provagent`). Builder: strongest model. Usage estimate: 60k tokens, checkpoint at 45k.

**Why (verified at main).** `providerRunner` (`broker/cmd/agentosd/main.go:1144`) builds a `provagent.Runner` with no `Journal` (comment at l.1140: "Journal (OP-8 meter and charge) is unwired"; provagent `ASSUMPTIONS.md` P10). `Runner.Run` calls the journal only when it is non-nil (`broker/provagent/run.go:221`), so a provider run is neither metered nor charged, and nothing says so. Failure path: a run completes, and the owner's per-machine spend meter shows nothing for it.

## Requirements

- **OP-8** (SPEC.md:396) model spend is metered by originating agent machine and charged to that machine's task reservation or rolling cap. The `Event` (`Provider, TaskClass, Outcome, ResultBytes, Elapsed`) carries metadata only, never the brief or result.
- **PJ-1** agentosd's provider runner always has a non-nil `Journal`. Each finished run (any outcome, refusals after admission included; a refusal before admission is not journaled) writes one journal entry through the engine's journal, with the fields of `Event`, the caller's machine (or `unattributed`), and no brief, result or CLI output.
- **PJ-2** (amended after #2291 rewrote OP-8) The journal entry is the plan run's metering: one entry per admitted run, under the originating machine, with its outcome and wall time. A plan run is never charged to or refused by the spend meter (`broker/meter`): OP-8 meters a plan run as runs, wall time and plan quota with zero spend, bounded by the run's wall clock and machine limits (RES-2) and the pool's reserve (RES-5), so a charge against the meter's call and money caps would refuse runs, block the machine's API calls and prompt the owner for a spend limit though nothing was spent. A run with no caller machine is journaled as `unattributed`, not refused.
- **PJ-3** A runner built with a nil `Journal` is visible: `Run` logs once through `Logf` that provider runs are unmetered. It is not silent.

**Acceptance tests:**
- PJ-1: `TestProviderRunnerHasJournal`, `TestProviderRunWritesOneEntryWithNoBrief` and `TestProviderRunIsJournaledUnderTheCallerMachine` (`broker/cmd/agentosd/providerjournal_test.go`; canary brief and result text must not appear in the entry), and `TestRefusalBeforeAdmissionIsNotJournaled` and `TestAdmittedRunIsJournaledOnceWithItsMachine` (`broker/provagent/run_test.go`).
- PJ-2: `TestPlanRunIsNeverRefusedOrCountedBySpendMeter` (same file; many runs from one machine all run, each journaled once, and the journal wiring takes no meter).
- PJ-3: `TestNilJournalRunLogsUnmetered` (`broker/provagent/run_test.go`).

## Design (recommendation)

A small `providerJournal` adapter in `broker/cmd/agentosd/providerjournal.go` taking the engine journal, set as `r.Journal` in `providerRunner`. Request carries no machine ID today: add `Machine string` to `provagent.Request` and `workers.ProviderRequest` (filled from `caller.machine`, `broker/workers/workers.go:232`; lineage is #1878's field) so the entry has an owner; the adapter journals an empty machine as `unattributed`.

## Assumptions

No per-run unit is added to `broker/meter`: the journal entry is the run's record, and a plan run's spend is zero (OP-8).

## Out of scope

Build order: #1878 (`Lineage`) first, then this brief adds `Machine` beside it in the same request types. Pool quota readings (#1856, done), the reserve setting (#1891 item 6), per-lineage cap (#1878), credential redaction (#1879).

## Scope

`broker/cmd/agentosd/main.go`, `broker/cmd/agentosd/providerjournal.go`, `broker/cmd/agentosd/providerjournal_test.go`, `broker/provagent/run.go`, `broker/provagent/run_test.go`, `broker/provagent/ASSUMPTIONS.md` (P10 wording), `broker/workers/provider.go` and its test (the `Machine` field), `briefs/CAP-11-plan-fu1.md`.

## Done

CI green; PJ-1 to PJ-3 covered by the acceptance tests, which carry `REQ: OP-8`.
