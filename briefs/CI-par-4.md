# CI-par-4: Fold the scope job into the jobs that skip on records-only changes

Board section: Harness and operating model. Work item #4336. Follows CI-par (#4304, PR #4308).

**Problem:** under the account's fixed 20-job cap every job queues about the same, 26 to 46 min p50 (audit, #4304). `scope` is a 5-second job that every `ci`, `assurance` and `vulncheck` run queues for before any other job of the run can start, so each run waits one extra full queue turn.

**Requirements:** no new IDs. CI-docs, CIMG-a/b/c (CI-mainguard) and CI-PATHS hold unchanged. No workflow has a `scope` job or `needs: scope`; `.github/workflows/scope.yml` is gone. `.github/actions/scope`, a composite action of one shell step with scope.yml's logic (the base copy of `tools/ci_scope.py`; full on any error), runs as the second step of `checks`, each `broker-race` shard, and the `assurance` and `vulncheck` jobs, after a `fetch-depth: 0` checkout. Every later step of those jobs runs unless its output is exactly `true`, except the checks job's document steps and its records-only step, and main-only, `always()` and schedule-only steps. ci.yml passes `push: full`, so a push to main runs every step. `broker-checks`, `machines` and `hostcheck` run in full on every change (their root steps may not carry an `if:`, `tools/root_tests.py`); `broker` needs only the split jobs. Required check names are unchanged.

**Scope:** `.github/actions/scope/action.yml` (new), `.github/workflows/{ci,assurance,vulncheck,word-budget}.yml`, `.github/workflows/scope.yml` (deleted), `tests/test_ci_scope.py`, `tests/test_workflows.py` (the mutants step comparison), `tests/records_audit.py` (the records step's `if:` text), `tools/ASSUMPTIONS.md` (D30 and CI-root-go-2 wording, one appended row), this brief.

**Acceptance tests:** in `tests/test_ci_scope.py`: `test_no_job_waits_for_a_scope_job`, `test_scope_action_answers_records_only_for_an_exact_records_change` and `test_scope_action_fails_safe` (the action's own script run on a test-merge repository), `test_pull_request_scope_unchanged`, `test_push_to_main_runs_every_job`, `test_assurance_and_vulncheck_skip_only_on_records`, `test_ci_skips_only_on_records_and_checks_always_runs`, `test_required_check_names_unchanged`.

**Acceptance:** the PR's own CI run shows every ci job starting with no scope job before it, and green.

**Tier / gate:** gate-file PR (`.github/`): L3, a separate Security accept (D-137) and the tier's lens screen.
