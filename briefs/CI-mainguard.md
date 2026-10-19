# CI-mainguard: a green run on main means main builds

Board section: CI. Work item: #2323. Evidence: 24 failed `ci` runs of main's last 100 (2026-10-16/17); merge skew (`netjoin.NewJoiner`, `RequestEach`) hidden by path-filtered green runs. **Mark-gate** (`.github/` is a D-125 PR): needs the Security accept at an equal head and, until D-137 lands, Mark's line naming the PR and head.

**Why / failure path.** CI-PATHS (#1817) skips broker jobs on commits that do not touch `broker/`, and the run still reports success. A docs-only PR merging after a skewed broker merge shows green while the broker build is broken; the next broker PR's author debugs a failure that is not theirs. Invariant: main's latest green run means main builds (CLAUDE.md "Done = CI green").

**Decision boundary.** The merge queue (#2292, MQ-wire) tests the merged result before it lands and fixes the cause; it is Mark's call and not this package. This package is option 2: detect, cheaply.

**Requirements:**
- MG-1: on `push` to main, `ci.yml` runs every job whatever the path filters say; PR runs keep the filters.
- MG-2: `tools/ci_scope.py` and `scope.yml` give the same filtered result on `pull_request` as today (no PR run changes).
- MG-3: the required checks and their names are unchanged, so branch protection keeps working.

**Acceptance tests:** (REQ: MG-1..MG-3)
- `tests/test_ci_scope.py::WiringTest::test_push_to_main_runs_every_job` parses `ci.yml` and asserts each filtered job's condition is true on `push` (mutant: remove the push clause from one job).
- `tests/test_ci_scope.py::ScopeTest::test_pull_request_scope_unchanged` (MG-2; existing cases kept).
- `tests/test_ci_scope.py::WiringTest::test_required_check_names_unchanged` (MG-3).

**Out of scope.** Merge queue wiring; HOTFIX-main (#2263).

**Scope:** `.github/workflows/ci.yml`, `.github/workflows/scope.yml` (only if needed), `tools/ci_scope.py`, `tests/test_ci_scope.py`, this brief.

**Usage estimate:** 40k tokens. Run `tools/risk_tier.py` and `tools/premerge.py --needs-mark` before the PR; hand off to the DECISIONS session for the merge.
