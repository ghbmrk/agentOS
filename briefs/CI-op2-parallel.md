# CI-op2-parallel: Cap the OP-2 model step's parallelism

Board section: Harness and operating model.

**Problem:** the broker-checks step "OP-2 same-effect model at its full bounds, without -race (journal A19)" was killed with exit 143 twice on #2195 (run 39050118387), most likely runner memory: `TestOP2SameEffectModel` runs five configurations as parallel subtests, `go test` defaults `-parallel` to GOMAXPROCS (4 on `ubuntu-latest`), and each search keeps every level's nodes live.

**Requirements:** no new IDs; A19's model bounds stay as the test states them and no step is dropped or skipped (`tests/test_ci_split.py::test_the_broker_checks_keep_their_steps` still holds).

**Scope:** `.github/workflows/ci.yml` (that one step) and `tests/test_ci_split.py`. No change to `broker/journal/**`. Open #2234 touches `tests/test_workflows.py` and `records.yml`, not these files.

**Acceptance:** a new `test_ci_split.py` test fails first (the step has no `-parallel 2`), then passes once the step carries `-parallel 2`; the other tests in `tests/test_ci_split.py` pass. The step's `-run` pattern, `-timeout 20m` and `./journal` stay as they are. Reproducing the exit-143 kill needs the runner; the PR's own CI run of the step is the evidence, with the step's duration noted against the 20m timeout.

**Tier / gate:** C by path, but `.github/` makes `tools/premerge.py --needs-mark` print `mark` (D-125): reviews first, then a Merge card for Mark.

## Delivery

Builder model: Sonnet 5.5 (tier C pilot). Estimate/checkpoint: 6k tokens, not a ceiling (OPERATING §5). Run `python3 tools/risk_tier.py --git origin/main HEAD` before opening the PR.
