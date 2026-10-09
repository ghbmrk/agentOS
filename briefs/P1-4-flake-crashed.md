# P1-4-flake-crashed: any failed runsc exec with runsc's own stderr is runsc's failure

Board section: Phase 1 (P1-4 rows). Row **P1-4-flake-crashed** alone. Tier A: `broker/vm/gvisor`.

## Why

From [Security 4a on #547](../reviews/security/2026-10-09-pr547.md), point 2 (release). `gvisor.Exec` (`broker/vm/gvisor/gvisor.go`, after `cmd.Wait`) decides whether an exec is runsc's failure with

```go
crashed := errors.As(err, &exit) && len(runscErr.bytes()) > 0 && (exit.ExitCode() == 2 || ctx.Err() != nil)
```

The exit-code and context terms are redundant. runsc's own fd 2 carries only runsc's text: the guest's stderr is a separate pipe passed with `--pass-fd 3:2` (SR2-3n; `broker/vm/ASSUMPTIONS.md` V32). They also leave a gap. Suppose runsc is killed by something other than Exec's context after it has begun writing a trace, for example a cgroup OOM kill or a signal from outside. It then exits -1 while `ctx.Err() == nil`. `crashed` is false, `size(logs[0])` is 0 because a panic writes no `--log` line, and the pid file is set. So Exec returns the guest's output and exit code -1 as a result, and the trace never reaches `exec.log`. Security found no guest path to cause this, so it is not a regression, but a runsc failure is answered as the guest's output and leaves no trace for the owner's monitor.

Fix, as Security proposed:

```go
crashed := err != nil && len(runscErr.bytes()) > 0
```

`exit` stays declared, because the result path below still reads it.

## Requirements

**CAP-8** (a worker's exec answers either its own result or a failure, never runsc's text as the guest's) and **RES-4** (the gvisor runner's per-exec isolation and logs, as on #391 and #547). No new IDs. The tests carry `REQ: CAP-8, RES-4`, like `panic_test.go`.

## Behaviour after the change

| runsc's exit | runsc's own stderr | Context | Before | After |
|---|---|---|---|---|
| 2 | text | alive or ended | failure, logged | same |
| -1, killed by Exec at the deadline | text | ended | failure, logged | same |
| **-1, killed by another process** | **text** | **alive** | **result, exit -1, not logged** | **`ErrExecFailed`, no output, logged** |
| **any other non-zero** (e.g. 1) with no `--log` line | **text** | **alive** | **result, not logged** | **`ErrExecFailed`, no output, logged** |
| `ErrWaitDelay` (pipes held past `ExecWaitDelay`) | text | alive | output with `ErrWaitDelay`, not logged | `ErrExecFailed`, no output, logged |
| any non-zero | empty | alive | result (the guest's exit code) | same |
| -1, killed at the deadline | empty | ended | partial output plus the context's error (`TimedOut`, V34) | same |
| 0 (`err == nil`) | text | — | result | same: kept by `err != nil` (Security's formula). Whether runsc ever writes there on success is the runsc-recheck row's question (P1-4-flake-runsc-recheck), not this one |

The guest exiting 2, or writing a panic trace to its own stderr, stays a result: `TestGuestExitTwoWithoutPanicIsAResult` and `TestGuestPanicTextIsAResult` must keep passing unchanged.

## Scope

- `broker/vm/gvisor/gvisor.go`: the `crashed` line and its comment block. Shorten the comment to the one rule: runsc's stderr is only runsc's (SR2-3n), so any failed exec with text on it is runsc's failure.
- `broker/vm/gvisor/panic_test.go`
- `broker/vm/gvisor/testdata/fakerunsc.sh`: new cases and their header lines.
- `broker/vm/ASSUMPTIONS.md`: V32's sentence "Exec treats as runsc's failure an exit 2, or any exit once its context ended, with anything on runsc's own stderr" becomes "any failed exec with anything on runsc's own stderr". Add to V34 that a kill from outside is the same failure.
- `BOARD.md`: the row's state.
- This brief.

No other package changes. `vm.Manager` already maps `ErrExecFailed` and the context's error.

## Tests first

Add the fake cases, then the tests. Show each new test failing at main and cite its message in the PR. Then make the one-line change.

| Test | Fake case | Context | Expect | Fails at main because |
|---|---|---|---|---|
| `TestRunscKilledFromOutsideAfterTraceAnswersNoOutput` | `oompanic`: writes the guest's "guest out\n", then a panic trace to runsc's stderr, then `kill -KILL $$` | `context.Background()` | error `ErrExecFailed`, empty `ExecResult`, `wantPanicLogged` | exit -1 with a live context reads as a result with `ExitCode` -1 |
| `TestRunscTextOnAnyFailedExitAnswersNoOutput` | `exit1text`: writes guest output, then one line to runsc's stderr with no `--log` line, then exits 1 | `context.Background()` | `ErrExecFailed`, no output, that line in `exec.log` | exit 1 is not 2 and the context is alive, so the result is returned |
| `TestGuestNonZeroExitWithoutRunscTextIsAResult` (control) | an existing quiet case that exits non-zero, or `exit1quiet` | `context.Background()` | a result with the guest's exit code and output; nothing logged | passes at main; it must keep passing (guards against withholding every non-zero exit) |

Use the same helpers as the existing tests in `panic_test.go`: `fakeRunsc` and `wantPanicLogged`. No wall-clock timing is needed, since the context never ends. Use `kill -KILL $$` from the fake itself, not a timer.

All existing tests in `broker/vm/gvisor` must keep passing unchanged, in particular `TestRunscPanicKilledAtTheDeadlineAnswersNoOutput`, `TestDeadlineWithoutRunscTextKeepsPartialOutput`, `TestGuestWritesCannotHideRunscTrace` and `TestGuestFillerKeepsRunscTraceInLog`. Run `go test ./vm/gvisor -race -count=50` from `broker/`.

## Threat check for the reviewer

- **Can a guest now withhold its own output?** Only by causing runsc to write to runsc's fd 2. The guest's fd 2 is a separate pipe (V32). The worst case is loss, not leak: V34 already accepts this for the deadline case.
- **Can a runsc failure still read as a result?** List every path where `err != nil` and `runscErr` is non-empty and confirm each one now withholds. `err == nil` with text is deliberately left as is (see the table).
- **Is anything new logged?** Only runsc's own stderr, clipped to 16 KiB, into the broker-held `exec.log` (0600), as today. No guest bytes are logged.

## Acceptance

- The two new tests fail at main and pass at the head. The control passes at both.
- `go test ./vm/gvisor -race -count=50` passes.
- CI is green.
- The PR body carries no `Defect:` line. Security filed this as a gap and not a regression: #547's code was correct for the cases it cited.

## Delivery

- **Builder model:** the strongest model, because this is risk tier A (`broker/vm/gvisor`).
- **Review:** L3 on the strongest model with the threat check above, then the lens screen with its own Security section (OPERATING §3–4).
- **Method:** write the failing tests first, then the smallest change. One package per session.
- **Before the PR:** run `python3 tools/risk_tier.py --git origin/main HEAD`.
- **Estimate/checkpoint:** 45k tokens, not a ceiling (OPERATING §5). The change is one line plus tests, so a diff that grows past the fake, the tests, the comment and V32/V34 is a scope signal: stop and escalate.
