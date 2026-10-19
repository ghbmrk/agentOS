# INFER-CI: run `broker/infer/...` in CI's machines job

Board section: Harness and operating model. Work item: #2284. Follow-up of INFER-SVC (#2217), first PR. **Mark-gate** (`.github/` is a D-125 PR): needs the Security accept at an equal head and Mark's line naming the PR and head until D-137 lands.

**Why.** Serves INF-1 (`TestServiceRunsInInferenceLeaf`) and the OOM case (`TestServiceOOMStaysInLeaf`) in `broker/infer/supervise/supervise_test.go`. Both need a delegated cgroup and skip without one. The machines job in `ci.yml` is the only job with delegation and does not list `./infer/...`. Failure path: a change that starts the service outside the inference leaf, or lets an OOM escape it, passes CI with both tests skipped (a false pass).

**Requirements:**
- INFER-CI-1: the machines job's package list includes `./infer/...`.
- INFER-CI-2: in that job the two tests run, not skip.

**Acceptance tests (REQ: INFER-CI-1, INFER-CI-2):**
- `tests/test_ci_scope.py::WiringTest::test_machines_job_lists_infer` parses `ci.yml` (mutant: remove the entry).
- The PR body shows the machines job log with both tests passing, not skipped.

**Out of scope.** Other packages' coverage in the machines job.

**Scope:** `.github/workflows/ci.yml`, `tests/test_ci_scope.py`, this brief. Do not run beside CI-mainguard (same file, D-111).

**Usage estimate:** 25k tokens. Hand off to the DECISIONS session for the merge.
