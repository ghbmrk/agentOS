# SEC-stop-provider-run: STOP does not end a provider run in flight (OP-6)

Board section: Backlog refill. Issue #2481. Defect: SEC-failed-stop-latch.

Raised by the Security review of #2464 as a later item. While STOP holds, the reaper (`reapWorkers`, every 5 s) calls `vm.Manager.EndCommands`, which cancels only `wk-` commands. A provider run's worker is `pw-`, so its agent CLI keeps executing after STOP until it finishes or hits its 30-minute wall. `provider_run` itself is already refused at start under STOP (`workers.go`, `errStartStopped`); only the run in flight is missed.

**Requirement:** OP-6 ("nothing new starts now"; work in flight ends). `EndCommands` ends every command in flight in a `wk-` or `pw-` machine, the two kinds `Exec` runs commands in. An ended provider command reports an error, so `provagent.Runner` returns `failed` and destroys the worker, as for any Exec error. The agent machine and other machines are untouched (Exec cannot run in them).

**Approach:** in `broker/vm/worker.go`, `EndCommands` skips only machines that are neither `WorkerPrefix` nor `ProviderPrefix`. The reaper already runs on the worker tools' STOP gate (SEC-failed-stop-latch), so no wiring changes. No `agentosd/main.go` change.

**Acceptance tests:** OP-6: `TestEndCommandsEndsAProviderRunInFlight` (broker/vm/providerworker_test.go): a command in flight in a `pw-` worker is ended by `EndCommands`, reports an error, and the worker stays Running (Destroy is the runner's).

**Not in scope (follow-up, class:later):** giving provider commands a `Hold` on the STOP gate, so one queued after STOP is refused at once instead of ended at the next reaper tick (at most 5 s). It needs a field on `workers.ProviderRequest` and `provagent.Request` copied through the adapter in `agentosd/main.go`, which waits on #2513.

**Scope:** broker/vm/worker.go, broker/vm/providerworker_test.go, broker/vm/ASSUMPTIONS.md, briefs/SEC-stop-provider-run.md.

**Needs:** —

**Gate:** lenses (security, tier A)
