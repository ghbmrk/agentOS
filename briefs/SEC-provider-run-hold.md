# SEC-provider-run-hold: a provider command that reaches Exec after STOP runs until the reaper's tick (OP-6)

Board section: Backlog refill. Issue #2534. Defect: SEC-stop-provider-run.

The follow-up SEC-stop-provider-run (#2535) left out of scope. `EndCommands` now ends `pw-` commands, but a provider command carries no `Hold`, so one that reaches `vm.Manager.Exec` after STOP (the agent CLI, or the result read after it) runs until the reaper's next `EndCommands` tick, up to 5 s (Security review of #2535). A run that STOP ends then answers `failed`, whose text tells the guest to shorten the brief or use another route, when no route runs under STOP (Potency and UX reviews of #2535). The reaper's log line counts only worker commands (L3 review of #2535).

**Requirement:** OP-6 ("nothing new starts now"). Each command a provider run execs carries the owner's STOP as `vm.Command.Hold`, so one reaching Exec after STOP is refused at once (`vm.ErrHeld`). A run asked for under STOP is refused before admission: no slot, seed or worker. A run that STOP held or ended answers the closed reason `stopped`, which is final under CAP-9 (no fallback route) and tells the guest to wait for the owner's RESUME.

**Approach:** `workers.ProviderRequest` and `provagent.Request` gain `Hold func() bool`. `provider_run` sets it to the worker tools' `Stopped`; agentosd's `providerTool` copies it across (ARC-2: workers still links no provagent). `provagent.Runner.run` checks it before admission, sets it on the CLI command and the result read, and maps an Exec error under STOP to `stopped`. `provagent.Stopped` joins `Reasons()` and not `FallsBack`; workers gets its guest text. The reaper's log line reads "worker and provider commands".

**Acceptance tests:** OP-6: `TestARunUnderStopStartsNothing`, `TestBothRunCommandsCarryTheOwnersStop`, `TestACLIEndedByStopIsStopped`, `TestAResultReadHeldByStopIsStopped`, `TestAnExecErrorWithoutStopIsStillFailed` (broker/provagent/stop_test.go); `TestProviderRunCarriesTheOwnersStop`, `TestAStoppedRunSaysWaitNotAnotherRoute` (broker/workers/provider_test.go); `TestProviderToolCarriesTheOwnersStop` (broker/cmd/agentosd/providerjournal_test.go). `TestEveryProviderReasonHasAGuestText` keeps the two reason lists one.

**Scope:** broker/provagent/gate.go, broker/provagent/run.go, broker/provagent/run_test.go, broker/provagent/stop_test.go, broker/provagent/ASSUMPTIONS.md, broker/workers/provider.go, broker/workers/provider_test.go, broker/cmd/agentosd/main.go, broker/cmd/agentosd/providerjournal_test.go, broker/vm/ASSUMPTIONS.md, briefs/SEC-provider-run-hold.md.

**Needs:** SEC-stop-provider-run (#2535, merged).

**Gate:** lenses (security, tier A)
