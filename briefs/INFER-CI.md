# INFER-CI: run `broker/infer/...` in CI's machines job

Board section: Harness and operating model. Work item: #2284. Follow-up of INFER-SVC (#2217), first PR. **Tier A** (`.github/`; Mark-gate): Security and combined reviews, strongest-model build; armed at the last accept under D-137, no Mark line. **Order:** waits for #2285 (INFER-SVC), which creates `broker/infer/`, and runs after CI-mainguard (#2323): both edit `ci.yml` and `tests/test_ci_scope.py` (D-111).

**Why.** Serves INF-1 (`TestServiceRunsInInferenceLeaf`) and the OOM case (`TestServiceOOMStaysInLeaf`) in `broker/infer/supervise/supervise_test.go`. Both need a delegated cgroup and skip without one. The machines job in `ci.yml` is the only job with delegation and does not list `./infer/...`. Failure path: a change that starts the service outside the inference leaf, or lets an OOM escape it, passes CI with both tests skipped (a false pass).

**Requirements:**
- INFER-CI-1: the machines job's package list includes `./infer/...`.
- INFER-CI-2: in that job the two tests run, not skip: the step pipes `go test -json` into `tools/require_ran.py`, which exits 1 when a named test has no `pass` event (skip, missing or fail).

**Acceptance tests:** (REQ: INFER-CI-1, INFER-CI-2)
- `tests/test_ci_scope.py::WiringTest::test_machines_job_lists_infer` parses `ci.yml` (mutant: remove the entry).
- `tests/test_require_ran.py::test_skip_fails` (INFER-CI-2): feed `require_ran.py` a `go test -json` stream where `TestServiceRunsInInferenceLeaf` has a `skip` event; exit code 1 (mutant: count `skip` as pass). Also `test_missing_fails` and `test_pass_succeeds`.
- `WiringTest::test_machines_step_uses_require_ran` parses `ci.yml`: the infer step names both tests (mutant: drop the pipe).
- The PR body shows the machines job log with both tests passing.

**Out of scope.** Other packages' coverage in the machines job.

**Scope:** `.github/workflows/ci.yml`, `tests/test_ci_scope.py`, `tools/require_ran.py`, `tests/test_require_ran.py`, this brief.

**Usage estimate:** 35k tokens, checkpoint at 35k.
