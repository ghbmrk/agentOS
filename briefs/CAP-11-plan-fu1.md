# CAP-11-plan-fu1: wire the OP-8 Journal into agentosd's provider runner

Board row: issue #1876. Source: PR #1864 delta review R4 (Security #9, L3 #9). Class: release. Tier: A (`broker/cmd/agentosd`, `broker/provagent`). Builder: strongest model. Usage estimate: 60k tokens, checkpoint at 45k.

**Why (verified at main).** `providerRunner` (`broker/cmd/agentosd/main.go:1144`) builds a `provagent.Runner` with no `Journal` (comment at l.1140: "Journal (OP-8 meter and charge) is unwired"; provagent `ASSUMPTIONS.md` P10). `Runner.Run` calls the journal only when it is non-nil (`broker/provagent/run.go:221`), so a provider run is neither metered nor charged, and nothing says so. Failure path: a run completes, and the owner's per-machine spend meter shows nothing for it.

## Requirements

- **OP-8** (SPEC.md:396) model spend is metered by originating agent machine and charged to that machine's task reservation or rolling cap. The `Event` (`Provider, TaskClass, Outcome, ResultBytes, Elapsed`) carries metadata only, never the brief or result.
- **PJ-1** agentosd's provider runner always has a non-nil `Journal`. Each finished run (any outcome, refusals after admission included; a refusal before admission is not journaled or charged) writes one journal entry through the engine's journal, with the fields of `Event` and no brief, result or CLI output.
- **PJ-2** Each run is charged to the originating machine's meter through the OP-8 path that `modelroute` uses for calls (`broker/meter`), as one call and zero tokens: `meter.Start(machine, 0, 0)` before the run, `Call.Done(0)` after it (`meter.Limits` holds only `Calls` and `Tokens`, so there is no wall-time unit). In broker-held plan mode the charge is the run, not tokens (RES-5: plan quota is a pool, not OP-8 token spend). A machine at its call cap is refused before the run starts: `Start` returns `ErrExhausted` (OP-8, SPEC.md:396, "egress refuses further calls"), the runner returns `Refused` and never reaches admission or the VM. A refusal made before `Start` (bad request, unknown provider) is not charged. The builder adds a `Runner.Admit func(machine string) (done func(), err error)` hook called first in `Run`, set by the adapter to wrap `Start`/`Done`, and records the choice in ASSUMPTIONS.
- **PJ-3** A runner built with a nil `Journal` is visible: `Run` logs once through `Logf` that provider runs are unmetered. It is not silent.

**Acceptance tests:**
- PJ-1: `TestProviderRunnerHasJournal` and `TestProviderRunWritesOneEntryWithNoBrief` (`broker/cmd/agentosd/providerjournal_test.go`; canary brief and result text must not appear in the entry).
- PJ-2: `TestProviderRunChargesTheCallerMachine` and `TestProviderRunRefusedAtMachineCap` (same file; the second asserts the VM is never started).
- PJ-3: `TestNilJournalRunLogsUnmetered` (`broker/provagent/run_test.go`).

## Design (recommendation)

A small `providerJournal` adapter in `broker/cmd/agentosd/providerjournal.go` taking the engine journal and the meter, set as `r.Journal` in `providerRunner`. Request carries no machine ID today: add `Machine string` to `provagent.Request` and `workers.ProviderRequest` (filled from `caller.machine`, `broker/workers/workers.go:232`; lineage is #1878's field) so the charge has an owner; the adapter refuses to charge an empty machine and journals it as `unattributed`.

## Assumptions

The meter's charge call and unit are as in `broker/meter/meter.go`; if no per-call unit fits a plan run, the builder stops and escalates before inventing one (a decision for Mark, OP-5).

## Out of scope

Build order: #1878 (`Lineage`) first, then this brief adds `Machine` beside it in the same request types. Pool quota readings (#1856, done), the reserve setting (#1891 item 6), per-lineage cap (#1878), credential redaction (#1879).

## Scope

`broker/cmd/agentosd/main.go`, `broker/cmd/agentosd/providerjournal.go`, `broker/cmd/agentosd/providerjournal_test.go`, `broker/provagent/run.go`, `broker/provagent/run_test.go`, `broker/provagent/ASSUMPTIONS.md` (P10 wording), `broker/workers/provider.go` and its test (the `Machine` field), `briefs/CAP-11-plan-fu1.md`.

## Done

CI green; PJ-1 to PJ-3 covered by the acceptance tests, which carry `REQ: OP-8`.
