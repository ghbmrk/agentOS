# P1-4-flake-ci: fuzz runs bounded by counts, timed by measured rates, capped by a timeout

Board section: Phase 1 (P1-4 rows). Covers rows **P1-4-flake-soak** and **P1-4-flake-counts** in one PR (coordinator, 2026-10-09): both change how a fuzz target is run, and one small tool serves both workflows.

## Why

From #547 (P1-4-flake-fuzz, merged c0eb06e) and its records: [Security 4a](../reviews/security/2026-10-09-pr547.md) point 1, [Potency](../reviews/potency/2026-10-09-pr547.md) points 1–3; LATER.md `P1-4-flake l1`–`l3`.

1. **Soak (P1-4-flake-soak).** `soak.yml`'s fuzz job runs each of 18 targets with `-fuzztime "$FUZZTIME"` (default 3h). A duration bound can end in a bare `context deadline exceeded` with no input written: the `internal/fuzz` coordinator stops on the `-fuzztime` deadline with `ctx.Err()` and suppresses it only when it equals its child context's error (briefs/P1-4-flake.md item 2; the race is long-standing, not specific to Go 1.26, LATER `l2`). Every soak run of 18 targets rolls that die 18 times and opens a "Soak failures" issue for nothing. #547 fixed only ci.yml.
2. **Counts (P1-4-flake-counts).** ci.yml now runs each of five targets for `-fuzztime 600000x`. That matched 20 s only for `modemlink:FuzzInbound`; `sockets:FuzzFrames` ran it in about 6 s, so it gets a third of its former fuzzing. The figure was never measured on CI. And a count has no wall-clock cap: a target that slows or hangs is stopped only by `go test`'s default 10 m `-timeout` or the job's 30 m limit (Potency 2, LATER `l3`).

## Requirement

**LOOP-7** (fuzzing of the broker sockets and the credentialed-browser action protocol; the soak matrix covers the other untrusted-input parsers under the same loop). No new IDs. The tests below carry `REQ: LOOP-7`.

## Design (decided; the builder may deviate only with a reason in the PR)

One tool, `tools/fuzzrun.py`, runs one target for a **time budget** made of **count-bound chunks**, and both workflows call it. It never passes a duration to `-fuzztime`, so the deadline race cannot occur; equal time per target comes back without a hand-kept count table that drifts as decoders change.

```
python3 ../tools/fuzzrun.py --pkg ./sockets --target FuzzFrames --budget 20s [--chunk 10m]
```

- **Chunks.** Run `go test <pkg> -run '^$' -fuzz '^<target>$' -fuzztime <N>x -timeout <T>` repeatedly. The first chunk is a small calibration count (e.g. 20000x). Each later chunk's N is the measured rate × min(remaining budget, `--chunk`), at least 1. Rate = executions ÷ the chunk's wall-clock time (startup included, so it errs short). Stop starting chunks once the budget is spent. Go keeps interesting inputs in `$GOCACHE/fuzz`, so later chunks continue from what earlier ones found.
- **Loud hang.** Each chunk runs with go test's `-timeout` and a subprocess timeout a little above it (process group killed). Both are **proportional**: `2.5 × E + G`, where E is the chunk's expected time (its N ÷ the last measured rate) and G a fixed grace for the build (`--grace`, default 2m). The factor makes a chunk whose rate has halved, which fuzzing does as the corpus grows, still pass, so the deadline flake is not swapped for a timeout flake. The calibration chunk has no rate yet: its cap is `2.5 × min(budget, --chunk) + G`, the same as a full chunk's, so it fails only for a target slower than `C ÷ (2.5 × min(budget, --chunk))` executions per second (with C = 20000 and ci.yml's 20 s, 400/s; #547 measured 30000/s and up). A chunk that overruns fails the run with a message naming the package, target and chunk, never a silent pass.
- **Failure.** A non-zero `go test` exit stops at once with that exit status; its output (the crasher path go prints) passes through unchanged, and nothing deletes `testdata/fuzz/`, so soak's "Keep crashers" step still works.
- **Log.** After each chunk, one line: `fuzzrun <pkg>:<target> chunk <k>: <N> execs in <s>s (<rate>/s)`; at the end a total line, also appended to `$GITHUB_STEP_SUMMARY` when set. This is the "log CI's exec/s" the row asks for.
- **Budget syntax.** Seconds or a Go-style duration of `h`/`m`/`s` parts (`3h`, `90s`, `1h30m`); anything else is an error before go runs. soak.yml keeps its `fuzztime` input name and its "at most 5h" limit.
- **Bounds.** A chunk ends by its timeout at the latest, so a run lasts at most the budget plus one chunk's cap. With `--chunk 10m` that is 5 h + 2.5 × 10 m + 2 m = 327 m for soak's 5 h maximum, under its 345 m job limit; a last chunk whose rate has halved takes 20 m and passes. Drop soak's single `-timeout 330m`. ci.yml uses `--budget 20s` per target (the pre-#547 time); `--chunk` defaults to the budget.
- **Why not per-target fixed counts plus `timeout`** (what the row literally says): the counts go stale with every decoder change and someone must re-measure; self-calibration measures every run and logs the figures instead. If the builder finds the calibration chunk's startup distorts the 20 s budget badly (rate off by more than 2x against the later chunks on CI), fall back to a per-target count table in ci.yml derived from the logged rates, still run through the tool for the timeout and the log line.

Reuse: Python stdlib only (`subprocess`, `time`, `re`, `argparse`), like the other `tools/*.py`; no new dependency.

## Scope

- `tools/fuzzrun.py` (new), `tests/test_fuzzrun.py` (new)
- `tests/test_workflows.py` (add the workflow check below)
- `.github/workflows/ci.yml` (the fuzz step and its comment), `.github/workflows/soak.yml` (the fuzz step)
- `tools/ASSUMPTIONS.md` (rows for fuzzrun: the coordinator race it avoids, the `$GOCACHE/fuzz` continuity it rests on, the rate estimate and the overrun bound)
- `LATER.md` (close `P1-4-flake l2` and `l3`; amend `l1`, below), `BOARD.md` (the two rows' state), this brief

**Out of scope:** `broker/loop7/ASSUMPTIONS.md`. Its F6 ("runs 20 s per CI run") and F8 ("600000x, about what 20s ran") go stale with this change, but that file is tier A (`tools/risk_tier.py`), and a wording fix there would make this whole package tier A. Amend LATER `l1` to say F6/F8 are reworded by the next package that touches `broker/loop7`, pointing to `tools/ASSUMPTIONS.md`. No Go code changes.

Risk tier: **C** (tools outside the tier-A prefixes, tests, workflows, BOARD/LATER). Run `python3 tools/risk_tier.py --git origin/main HEAD` before the PR; if it prints A, a path outside this scope crept in.

## Tests first

Write each test in `tests/test_fuzzrun.py` against a fake `go` (a small Python script put first on `PATH` in a temp dir) that records its argv to a file and, by an environment variable, passes after sleeping a given time per execution, fails with exit 1 and a crasher line, or hangs. Each must fail before the tool exists or before the behaviour is added. Use small budgets (well under a second per chunk) so the suite stays fast.

| Test | Shows |
|---|---|
| no duration ever | Every recorded `-fuzztime` argument matches `^\d+x$`, for a budget that needs several chunks. (The soak regression.) |
| chunks fill the budget | With a fake rate, total wall time is at least the budget and at most budget + one chunk's cap; the second chunk's N ≈ rate × chunk. |
| slowdown is not a hang | The fake's per-execution time doubles after chunk 1 (its rate halves): the run passes, with no timeout message. (Fails against a timeout of E + G.) |
| rate is logged | Stdout has one `fuzzrun ... execs in ... (.../s)` line per chunk and a total; with `GITHUB_STEP_SUMMARY` set to a temp file, the total line is appended there. |
| hang is loud | The fake hangs, once in the calibration chunk and once in a later chunk: each time the tool exits non-zero within 2.5 × E + G + a small margin, with a message naming package, target and chunk. |
| failure stops | The fake fails on chunk 2: exit status non-zero, no chunk 3 recorded, the fake's crasher line on output. |
| budget parsing | `20s`, `3h`, `1h30m`, `90` accepted; `3 hours`, `-1s`, `` refused before any go call. |

Add to `tests/test_workflows.py`: no workflow passes `-fuzztime` a value other than `\d+x` (so a duration bound cannot return), and every `go test ... -fuzz` in a workflow runs through `tools/fuzzrun.py`. That is the check replacing this kind of finding; name it in the PR so the Potency lens README can list it.

Then the workflows: ci.yml's loop calls the tool with `--budget 20s` for the same five targets and keeps `|| exit 1`; soak.yml's fuzz step calls it with `--budget "$FUZZTIME" --chunk 10m`, keeping the `tee` to `fuzz.log`. Reword the ci.yml comment: no "Go 1.26's coordinator" (LATER `l2`), no unmeasured "about what 20s ran" (`l1`).

## Acceptance

- `python -m unittest discover -s tests` passes; the new tests fail at main (cite one failure message in the PR).
- CI on the PR is green, and the fuzz step's log shows a rate line for each of the five targets; quote the five rates (trimmed) in the PR body. Those figures replace "600000x took 6–20 s" in any later wording.
- soak.yml is not run on the PR (it takes hours). Show it is well-formed by the workflow test and, if the builder can do so without a permission prompt, one `workflow_dispatch` run on the branch with `fuzztime: 2m`; otherwise say it was not run.
- No `Defect:` line: #547's ci.yml change was a correct fix; this extends it. BOARD rows P1-4-flake-soak and P1-4-flake-counts move to merged with the PR.

## Delivery

Builder: tier C, so a Sonnet-class session under the pilot (CLAUDE.md, Budget); name the model in the PR's Budget section. Tests first, one package per session. Estimate/checkpoint: 70k tokens, not a ceiling (OPERATING §5). Escalate if the fake-`go` timing tests cannot be made deterministic after two attempts (the usual cause is a margin too tight for a loaded runner: widen margins, never retry the test).
