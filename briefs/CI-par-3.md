# CI-par-3: Split test_image across the runner's cores inside its one strace tree

Board section: Harness and operating model. Work item #4332. Follows CI-par (#4304, PR #4308).

**Problem:** after #4308 the checks job's "Unit tests" step takes 12.4 min, and `tests/test_image.py` is the floor: about 10 min when it shares the runner, 205 s of tests run alone. One class, DiffOracleTest, is 92 s of it (two tests, 51 s and 40 s), so a split by class still floors near half the module.

**Requirements:** no new IDs. CI-PATHS still holds unchanged: each module writes exactly one `<module>.trace` from one strace tree whose first process exits last, and `tests/records_audit.py` reads it as before. A module named in `tools/unit_tests.py`'s `SPLIT` runs as one parent process under strace that forks worker processes; each worker takes the next test from a shared counter, so the slowest single test, not the slowest class, sets the floor. Every test of the module runs exactly once; a failed test, a test that did not run, a lost worker or an empty module fails the module.

**Scope:** `tools/unit_tests.py`, `tests/test_unit_tests.py`, `tools/ASSUMPTIONS.md` (one appended row), this brief. No `.github/` change: ci.yml's step already calls `tools/unit_tests.py`.

**Acceptance tests:** in `tests/test_unit_tests.py`: `test_a_split_module_runs_under_one_strace_into_its_own_trace` (the command for a SPLIT module keeps the strace prefix and one trace path); `test_split_runs_every_test_once_across_workers` (each test of a synthetic module runs exactly once, in more than one worker process); `test_split_fails_on_a_failed_test`, `test_split_fails_when_a_worker_is_lost` and `test_split_fails_on_an_empty_module` (each returns nonzero); `test_split_trace_is_one_finished_tree` (under real strace, the one trace shows the module's own file opened and passes `records_audit.finished`); `test_split_modules_exist`.

**Acceptance:** the PR's own CI run shows the step green, every module's trace audited, and its duration against #4308's 12.4 min.

**Tier / gate:** C by `tools/risk_tier.py`; not a gate-file PR. L3 accept and green CI.
