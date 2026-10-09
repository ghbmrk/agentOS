# P1-4-flake-exit128: `TestCorpusReplayInAMachine` fails once with `runsc exec` exit 128 and the test hides why

Board section: Phase 1 (P1-4 rows). Row **P1-4-flake-exit128** alone. Tier A: `broker/vm/gvisor` (`risk_tier.py` rates the fix's Scope files A).

## Why

`TestCorpusReplayInAMachine` (`broker/vm/gvisor/corpus_test.go`) failed once each on two PRs, in the `machines` job, step "Machine tests as root", and passed on rerun:

| PR | Head | Run / job | Result |
|---|---|---|---|
| #588 | 92f6dc4 | 37917574895 / 113777400982 (attempt 1) | `corpus_test.go:512: archive control: corpus probe: alert patterns: exit status 128`, after 12.38 s; attempt 2 (113782947671) green |
| #584 | 2d82669 | 37916371154 / 113773439257 | same line; head 06ef2b0 (run 37918493548) green |
| #569 | b2722e22 | 37921983285 / 113791913781 | `corpus_test.go:512: clean run: {Found:[] Checked:[]} corpus probe: alert patterns: exit status 128`, after 9.87 s: the same call, but in the **clean-run** phase, not the archive control |

The sibling `TestCorpusReplayThroughTheGuestPlane` passed in the same run. #588's builder suspects load, since #588 adds `./loop7` to the same parallel `go test` as `./vm/...`. #584 does not add it, and #569's changed files (broker/cmd/agentosd, broker/recalltool, BOARD.md, LATER.md) neither add `./loop7` nor touch `ci.yml`; `ci.yml` at main has no `./loop7`. So **one of three occurrences** can involve `./loop7`; it cannot explain the flake. Load in the `machines` job generally (the ~dozen packages run in parallel) stays a hypothesis; the failure hits two different corpus phases, so it is not tied to one step of the test. #588's L3 classed it "not attributable, own row".

## Diagnosis

Facts, from the code at pinned runsc release-20260928.0 and the CI log:

1. **128 is runsc's own fatal exit, not a guest exit code.** `runsc exec` reaches `util.Fatalf` (exit 128; message to runsc's stderr and the `--log` file) on three paths: "loading container failed: …", "parsing process spec: …" and "failure to start child exec process" (detach). Its ordinary failures use `util.Errorf` (exit 1). A guest process returning 128 is possible but the corpus probe does not.
2. **The test throws the message away.** It builds `x.run` from `r.rt.cmd(...).Output()` and discards `ExitError.Stderr`, with no `--log`. The only evidence is "exit status 128". The trigger is therefore **unproven**: the logs cannot distinguish a failed container load from a spec parse or a child-start failure.
3. **The test bypasses `Runtime.Exec`**, so none of Exec's protection applies (`--log`, `exec.log`, `ErrExecFailed`, runsc's stderr kept apart by `--pass-fd 3:2`). **Through Exec at main a real runsc `Fatalf` is already a failure**: Exec passes `--log=` (`gvisor.go:278`) and `Fatalf` writes a `--log` line, so `size(logs[0]) > 0` withholds the output and logs it (`gvisor.go:325`); a fatal before the pid write ("loading container failed") is the `!started` path, also a failure. So the 128 would not have read as a guest result had the test used Exec; the gap is only that the raw call keeps none of this.

Hypotheses (not facts), in the order the evidence would test them: (a) container load fails under contention (state read while another runsc in the same `--root` writes it; rigs use their own `StateDir`, so cross-rig sharing is unlikely); (b) the sandbox is slow or briefly unresponsive under CPU or memory pressure and the exec's child start fails; (c) the 12 s elapsed time points to a failure after the machine ran for a while, not at once, which favours (b). Load from `./loop7` is at most an aggravator. No retry is justified yet: nothing shows the failure is documented as transient, and a retry would hide a real fatal.

## Requirements

**CAP-8** (an exec answers the worker's own result or a failure, never runsc's text as the guest's) and **RES-4** (inherited citation for `exec.log` bounds, as P1-4-flake-crashed). No new IDs. The pinning tests carry `REQ: CAP-8, RES-4` as regression guards of behaviour true at main (they cover those IDs, they do not claim a defect); no requirement ID here is asserted false at main under real runsc behaviour.

## Proposed fix (recommendation; three steps, in this order)

1. **Make the failure self-diagnosing.** In `TestCorpusReplayInAMachine`, run the raw `runsc exec` with its stderr captured and a `--log` file, and on `*exec.ExitError` return an error that carries the exit code, the last 2 KiB of runsc's stderr and the last lines of its `--log`. Synthetic data only; clip before printing. This alone turns the next occurrence into a diagnosis. Keep the raw path for this row. Routing the probe through `Runtime.Exec` changes `--cwd /`, `--user 0:0` and `--pass-fd 3:2` relative to the raw call, so it is a separate row, accepted only if the full corpus replay results are identical on both paths; this row does not take it on.
2. **Pin the classification (passes at main).** Add a `fatal128` case to `testdata/fakerunsc.sh` that fails as real runsc's `Fatalf` does: it writes the pid file, then calls `fail "loading container failed: …" 128`, which writes the `--log` JSON line and stderr (the header's runsc behaviour). New test in `panic_test.go`: `Runtime.Exec` answers `ErrExecFailed`, no output, line in `exec.log`; control `TestGuestExit128WithoutRunscTextIsAResult` (quiet fake, guest exit 128, guest output) stays a result. Both **pass at main**: they are pinning tests, not fails-at-main tests, and carry no "fails at main" claim. This step has **no dependency on P1-4-flake-crashed** (#591), whose scenario (runsc text with no `--log` line) is different.
3. **Decide on load after evidence, not before.** Do not edit `.github/workflows/ci.yml` in this row. If the captured stderr from step 1 shows resource exhaustion or contention, open a release row to serialise the machine tests (`-p 1` for `./vm/...` or its own `go test` line, ahead of `./loop7`); #588 is not touched meanwhile. No retry unless runsc documents the failure as transient and the retry logs every attempt.

## Scope

- `broker/vm/gvisor/corpus_test.go`: step 1 only (error carries runsc's stderr and log tail).
- `broker/vm/gvisor/panic_test.go` and `broker/vm/gvisor/testdata/fakerunsc.sh`: step 2.
- `broker/vm/ASSUMPTIONS.md`: add a row (next free V number) saying a runsc `Fatalf` exit 128 is runsc's failure and that the corpus test now reports its stderr; consider column: "a guest exit 128 with runsc silent stays a result".
- `BOARD.md`: the row's state. This brief.

No production code changes in this row (`gvisor.go` belongs to P1-4-flake-crashed, which this row no longer depends on). Not touched: PRs #584, #588 and the P3-4b-* rows; `ci.yml`.

## Tests first

| Test | At main |
|---|---|
| `TestRunscFatalExit128AnswersNoOutput` (fake `fatal128` via `fail`, `context.Background()`, pid written first) | **passes** (pinning): `ErrExecFailed`, no output, line in `exec.log` |
| `TestGuestExit128WithoutRunscTextIsAResult` (control) | passes; guards against withholding every 128 |
| corpus helper's error carries runsc's stderr and log tail (fake runsc that prints a line and exits 128 through the same helper; assert the line is in the error) | **fails**: today only "exit status 128" |

Only the third is false at main; the first two document what Exec already does. Use `fakeRunsc` and `wantPanicLogged` as the existing tests. No wall-clock timing decides an outcome. Run `go test ./vm/gvisor -race -count=50` from `broker/`.

## Threat check for the reviewer

- Test-only and fake-only changes; no production path moves. The captured stderr is runsc's own text from synthetic corpus runs, clipped, printed only in a test failure.
- A guest exit 128 must not become a failure: the control pins it.

## Findings

- release: this row (diagnosis cannot be proven from today's logs).
- release: route the corpus probe through `Runtime.Exec`; pass criterion identical corpus replay results on both paths (not in this row; L3 on #594, point 3).
- release (conditional): serialise machine tests, only if step 1's evidence shows contention.
- later: none.

## Acceptance

- The corpus-helper test fails at main and passes at the head; the two Exec pinning tests pass at both.
- On the next 128, the CI log names runsc's reason.
- The existing `broker/vm/gvisor` tests pass unchanged.

## Delivery

Builder: Sonnet-class pilot would do it, but tier A: strongest model (CLAUDE.md pilot rule). Estimate ~60k tokens; checkpoint at 90k.
