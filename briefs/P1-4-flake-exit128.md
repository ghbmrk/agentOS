# P1-4-flake-exit128: `TestCorpusReplayInAMachine` fails once with `runsc exec` exit 128 and the test hides why

Board section: Phase 1 (P1-4 rows). Row **P1-4-flake-exit128** alone. Tier A: `broker/vm/gvisor` (`risk_tier.py` rates the fix's Scope files A).

## Why

`TestCorpusReplayInAMachine` (`broker/vm/gvisor/corpus_test.go`) failed once each on two PRs, in the `machines` job, step "Machine tests as root", and passed on rerun:

| PR | Head | Run / job | Result |
|---|---|---|---|
| #588 | 92f6dc4 | 37917574895 / 113777400982 (attempt 1) | `corpus_test.go:512: archive control: corpus probe: alert patterns: exit status 128`, after 12.38 s; attempt 2 (113782947671) green |
| #584 | 2d82669 | 37916371154 / 113773439257 | same line; head 06ef2b0 (run 37918493548) green |

The sibling `TestCorpusReplayThroughTheGuestPlane` passed in the same run. #588's builder suspects load, since #588 adds `./loop7` to the same parallel `go test` as `./vm/...`; #584 does not add it, so that cannot be the whole story. #588's L3 classed it "not attributable, own row".

## Diagnosis

Facts, from the code at pinned runsc release-20260928.0 and the CI log:

1. **128 is runsc's own fatal exit, not a guest exit code.** `runsc exec` reaches `util.Fatalf` (exit 128; message to runsc's stderr and the `--log` file) on three paths: "loading container failed: …", "parsing process spec: …" and "failure to start child exec process" (detach). Its ordinary failures use `util.Errorf` (exit 1). A guest process returning 128 is possible but the corpus probe does not.
2. **The test throws the message away.** It builds `x.run` from `r.rt.cmd(...).Output()` and discards `ExitError.Stderr`, with no `--log`. The only evidence is "exit status 128". The trigger is therefore **unproven**: the logs cannot distinguish a failed container load from a spec parse or a child-start failure.
3. **The test bypasses `Runtime.Exec`**, so none of Exec's protection applies (runsc stderr kept apart by `--pass-fd 3:2`, `exec.log`, `ErrExecFailed`). Through Exec at main, a runsc 128 with text on its stderr and a live context is answered as a **result with `ExitCode` 128**, indistinguishable from a guest exit 128 (`crashed` requires exit 2 or an ended context). P1-4-flake-crashed (#591) closes that (`err != nil && len(runscErr) > 0`).

Hypotheses (not facts), in the order the evidence would test them: (a) container load fails under contention (state read while another runsc in the same `--root` writes it; rigs use their own `StateDir`, so cross-rig sharing is unlikely); (b) the sandbox is slow or briefly unresponsive under CPU or memory pressure and the exec's child start fails; (c) the 12 s elapsed time points to a failure after the machine ran for a while, not at once, which favours (b). Load from `./loop7` is at most an aggravator. No retry is justified yet: nothing shows the failure is documented as transient, and a retry would hide a real fatal.

## Requirements

**CAP-8** (an exec answers the worker's own result or a failure, never runsc's text as the guest's) and **RES-4** (inherited citation for `exec.log` bounds, as P1-4-flake-crashed). No new IDs. Tests carry `REQ: CAP-8, RES-4`.

## Proposed fix (recommendation; three steps, in this order)

1. **Make the failure self-diagnosing.** In `TestCorpusReplayInAMachine`, run the raw `runsc exec` with its stderr captured and a `--log` file, and on `*exec.ExitError` return an error that carries the exit code, the last 2 KiB of runsc's stderr and the last lines of its `--log`. Synthetic data only; clip before printing. This alone turns the next occurrence into a diagnosis. Alternative if simpler: route the call through `Runtime.Exec` so it gets `exec.log` for free, after #591 lands; keep the raw path only if Exec's `--pass-fd` changes what the corpus probe sees (check, and say so in the PR).
2. **Deterministic reproduction of the classification.** Add a `fatal128` case to `testdata/fakerunsc.sh`: writes the pid file, then a `Fatalf`-style line to its stderr, exits 128. New test in `panic_test.go`: `Runtime.Exec` answers `ErrExecFailed`, no output, line in `exec.log`; a control `TestGuestExit128WithoutRunscTextIsAResult` (quiet fake, exit 128, guest output) stays a result. The first test **fails at main** (answers a result with `ExitCode` 128) and passes once #591 is merged, so this row **depends on P1-4-flake-crashed**; do not duplicate its `crashed` change here.
3. **Decide on load after evidence, not before.** Do not edit `.github/workflows/ci.yml` in this row. If the captured stderr from step 1 shows resource exhaustion or contention, open a release row to serialise the machine tests (`-p 1` for `./vm/...` or its own `go test` line, ahead of `./loop7`); #588 is not touched meanwhile. No retry unless runsc documents the failure as transient and the retry logs every attempt.

## Scope

- `broker/vm/gvisor/corpus_test.go`: step 1 only (error carries runsc's stderr and log tail).
- `broker/vm/gvisor/panic_test.go` and `broker/vm/gvisor/testdata/fakerunsc.sh`: step 2.
- `broker/vm/ASSUMPTIONS.md`: add a row (next free V number) saying a runsc `Fatalf` exit 128 is runsc's failure and that the corpus test now reports its stderr; consider column: "a guest exit 128 with runsc silent stays a result".
- `BOARD.md`: the row's state. This brief.

No production code changes in this row (`gvisor.go` belongs to P1-4-flake-crashed). Not touched: PRs #584, #588 and the P3-4b-* rows; `ci.yml`.

## Tests first

| Test | Fails at main because |
|---|---|
| `TestRunscFatalExit128AnswersNoOutput` (fake `fatal128`, `context.Background()`, pid written first) | exit 128 with a live context reads as a result with `ExitCode` 128 |
| `TestGuestExit128WithoutRunscTextIsAResult` (control) | passes at main and head; guards against withholding every 128 |
| corpus test's error carries stderr: provoke with a fake runsc that prints a line and exits 128 through the same helper, assert the line is in the error | today only "exit status 128" |

Use `fakeRunsc` and `wantPanicLogged` as the existing tests. No wall-clock timing decides an outcome. Run `go test ./vm/gvisor -race -count=50` from `broker/`.

## Threat check for the reviewer

- Test-only and fake-only changes; no production path moves. The captured stderr is runsc's own text from synthetic corpus runs, clipped, printed only in a test failure.
- A guest exit 128 must not become a failure: the control pins it.

## Findings

- release: this row (diagnosis cannot be proven from today's logs).
- release (conditional): serialise machine tests, only if step 1's evidence shows contention.
- later: none.

## Acceptance

- `TestRunscFatalExit128AnswersNoOutput` fails at main and, with #591 merged, passes; the control passes at both.
- On the next 128, the CI log names runsc's reason.
- The existing `broker/vm/gvisor` tests pass unchanged.

## Delivery

Builder: Sonnet-class pilot would do it, but tier A: strongest model (CLAUDE.md pilot rule). Estimate ~60k tokens; checkpoint at 90k.
