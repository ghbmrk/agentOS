# CI-rerun-fresh-fu: close the trusted-base rerun gaps left by #5223

Board section: Defects and later findings on surviving packages. Work item #5224, release findings from the reviews of #5223 (CI-rerun-fresh, #5222). Serves D-310 rule 2: a trusted-base check measured on an older main goes stale.

**Requirements (local ID CI-rerun-fresh-fu):**
1. A push time that is empty, null or not a `YYYY-MM-DDTHH:MM:SSZ` timestamp turns the job red (Security 6 on #5223: an empty one skipped every run).
2. A run whose job started after the push counts as fresh only if every job passed; a run that failed, timed out or was cancelled is rerun (L3 6 on #5223).
3. A jobs JSON with no `jobs` key, or a null one, turns the job red and names the PR (L3 7 on #5223).
4. The push trigger lists the paths the check reads (`paths:`), replacing the bot-file ignore list: 17 of 83 non-bot first-parent pushes 11-07 to 11-10 changed none of them and still reran every open PR. A test fails if either base-copy tool names a path literal, or tools/old_core.txt a directory, outside the list.

**Scope:** `.github/workflows/trusted-base-rerun.yml`, `tests/test_trusted_base.py`, `tools/ASSUMPTIONS.md` (the CI-ceiling-fall row), this brief.

**Acceptance tests:** `tests/test_trusted_base.py`: `test_empty_or_malformed_push_time_fails_closed`, `test_reruns_a_run_that_started_after_the_push_but_did_not_pass`, `test_jobs_json_without_jobs_fails_closed`, `test_runs_only_on_a_push_to_a_path_the_check_reads`, `test_rerun_workflow_matches_its_pin`.

**Tier / gate:** tier A, gate file (`.github/`): L3, the lens screen and a separate Security accept (D-137).
