# CI-rerun-fresh: rerun only trusted-base runs that read an older main

Board section: Harness and operating model. Work item #5222. Defect in CI-ceiling-fall (#5174, #5179).

**Problem:** `trusted-base-rerun.yml` waits for a run still queued or in progress and reruns it when it completes. A job checks out main's live tip when it starts, so a run that started after the push already measured the new main. #5203's run 42727562333 queued 17 to 33 minutes per attempt, longer than the gap between pushes to main, and each green attempt was rerun seconds after it passed (11 attempts, armed for 2.5 hours). Pushes of only bot-written files (BOARD.md, METRICS.md, TRACE.md; 14 of 81 first-parent pushes 11-08 to 11-10) rerun everything too.

**Requirements (local ID CI-rerun-fresh):**
1. A completed run is rerun unless every job of it started after this rerun run's `created_at`. A run with no start time, or a job list that cannot be read, is treated as stale (rerun, or the job goes red).
2. The push trigger ignores BOARD.md, METRICS.md and TRACE.md. Each is written only by its bot workflow, and neither tools/trusted_base.py nor tools/claims.py reads it.
3. Every other behaviour of CI-ceiling-fall stays: every push that changes anything else reruns every open PR whose run read an older main.

**Follow-up (not here):** skip pushes that change no path any measure reads (tools/ASSUMPTIONS.md CI-ceiling-fall row).

**Scope:** `.github/workflows/trusted-base-rerun.yml`, `tests/test_trusted_base.py`, `tools/ASSUMPTIONS.md` (the CI-ceiling-fall row), this brief.

**Acceptance tests:** `tests/test_trusted_base.py`: `test_skips_a_run_that_started_after_the_push`, `test_ignores_only_bot_written_files_no_measure_reads`, `test_failures_turn_the_job_red`, `test_reruns_every_open_pr_waiting_for_one_in_progress`, `test_rerun_workflow_matches_its_pin`.

**Tier / gate:** tier A, gate files (`.github/`): L3 and a separate Security accept (D-137).
