# CI-par: Run the checks job's Python unit-test modules in parallel

Board section: Harness and operating model. Work item #4304.

**Problem:** the checks job's "Unit tests" step runs the 71 `tests/test*.py` modules one after another, each under `strace` (CI-PATHS), and takes 17.8 min (p50 of 90 runs, 2026-10-31) on a 4-vCPU runner, the longest step in ci.yml. Main's runner pool is capped, so every runner-minute it holds also delays every other queued job.

**Requirements:** no new IDs. CI-PATHS still holds: each module runs in its own process tree under `strace -f -y` and writes one `<module>.trace` that `tests/records_audit.py` reads; a failed or unrun module fails the step.

**Scope:** `.github/workflows/ci.yml` (the "Unit tests" step only), `tools/unit_tests.py` (new), `tests/test_unit_tests.py` (new), `tests/test_ci_scope.py` (its assertion on that step). Audit numbers go to the PR body and the project's files, not the repo.

**Acceptance tests:** `tests/test_unit_tests.py` (every module runs once with its own trace path, a failed or missing module fails the run, output is grouped per module, SERIAL modules run alone) and `test_full_unit_tests_audit_record_reads_against_the_records_step` in `tests/test_ci_scope.py`.

**Acceptance:** the PR's own CI run shows the step green with every module's trace audited, and its duration against the serial baseline.

**Tier / gate:** A by `tools/risk_tier.py` (`.github/`); gate-file PR, so L3 plus a separate Security accept (D-137).
