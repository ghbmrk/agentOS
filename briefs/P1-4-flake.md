# P1-4-flake: Exec's deadline panic race and the CI fuzz step's deadline race

Board section: Phase 1 (P1-4 rows). Covers rows P1-4-flake and P1-4-flake-fuzz in one PR (coordinator, 2026-10-09).

**Defect: P1-4.** Two CI tests fail intermittently; "flake" is not a root cause, so each is root-caused and fixed, and no test is skipped or loosened.

1. `broker/vm/gvisor` `TestRunscPanicAtTheDeadlineAnswersNoOutput` (#503, comment 6074344893): at its 100ms deadline `Exec` returned an error with the guest's "guest out\n". On a slow runner the fake runsc had not exited 2 when the context ended, so Exec's `Cancel` killed it (exit -1) and `crashed`, which required exit 2, was false. Two cases follow. (a) Killed before runsc wrote anything: a plain deadline, where partial output with the context's error is the designed contract (`vm.Manager.Exec` answers it as `TimedOut`, CAP-8); only the test's timing assumption is wrong. (b) Killed after runsc wrote its panic trace: a code defect against Security S1 on #391 (a runsc panic at the deadline answers no output), and the trace was not logged. Fix: runsc's own stderr carries only runsc's text (SR2-3n), so any of it on an exit at or after the context's end is runsc's failure; the tests end the context at a mark the fake creates, not at a wall-clock deadline.
2. `modemlink` `FuzzInbound` in ci.yml's fixed-time fuzz step (`-fuzztime 20s`) failed once on #537 with a bare `context deadline exceeded` at the deadline and no input written. Not a slow input nor startup cost: Go 1.26's `internal/fuzz` coordinator wakes on the `-fuzztime` deadline context and calls `stop(ctx.Err())`, which it suppresses only when the error equals its child context's error; a parent's `Done` closes before its children are cancelled, so the run can fail with that error. Fix: bound the CI step by an execution count (`-fuzztime 600000x`), which sets no deadline.

**Requirements:** CAP-8, RES-4 (gvisor Exec), LOOP-7 (fuzz step). No new IDs.

**Scope:** `broker/vm/gvisor/gvisor.go`, `broker/vm/gvisor/panic_test.go`, `broker/vm/gvisor/testdata/fakerunsc.sh`, `broker/vm/ASSUMPTIONS.md`, `broker/loop7/ASSUMPTIONS.md`, `.github/workflows/ci.yml`, `BOARD.md`, this brief.

**Acceptance:** a test for case (b) fails before the code change and passes after; the deadline tests no longer depend on timing; `go test ./vm/gvisor -run 'Panic|Deadline' -count=200 -race` passes under CPU load; repeated count-bound `FuzzInbound` runs pass. PR body carries `Defect: P1-4`.

**Needs:** —

## Delivery

Builder model: strongest model (risk tier A: `broker/vm/gvisor`). Write the failing test first, then the smallest change; one package per session. Run `python3 tools/risk_tier.py --git origin/main HEAD` before opening the PR. Estimate/checkpoint: 60k tokens, not a ceiling (OPERATING §5).
