# CI-ceiling-fall: re-measure open PRs when main grows

Board section: Harness and operating model. Work item #5174. Folds #4982 items 1 and 2.

**Problem (D-310 rule 2):** `trusted-base` measures a PR against main as of the event's `base.sha`. N open PRs that each fit headroom H stay green after the first of them merges, so main can land up to (N-1)·H over `tools/ceilings.txt` with no red check; main went over 58,895 this way.

**Requirements (local ID CI-ceiling-fall):**
1. The PR check checks out the base branch's live tip (`base.ref`), so any rerun measures the PR merged onto main as it is then.
2. On every push to main, a new workflow reruns the newest trusted-base run on every open PR into main, waiting for one still in progress; a refused rerun or failed listing marks the job red. It reruns on every push, not only on growth: a push that shrinks main can still raise another PR's merged measure (L3 on #5179). It runs only on pushes to main, checks out nothing, and has `actions: write` and `pull-requests: read` only.
3. (Folded into 2 after L3 on #5179: the `remeasure` short-cut was unsound and is gone.)
4. #4982 item 1: a test with main under the ceiling and the PR over it expects `cut head - ceiling`. Item 2: "cut 1 line" / "cut 1 word".

**Residual:** PRs that merge within one rerun's latency can still land together; main is then over and the existing rule stops growth. A strict up-to-date rule or merge queue (ruleset, Mark's change) closes it fully.

**Scope:** `tools/trusted_base.py`, `tests/test_trusted_base.py`, `.github/workflows/trusted-base.yml`, `.github/workflows/trusted-base-rerun.yml` (new), `tools/ASSUMPTIONS.md` (one row), this brief. `tools/ceilings.txt` and `decisions/D-310.md` (#4982 item 3) stay with #5156.

**Acceptance tests:** `tests/test_trusted_base.py`: `test_crossing_from_under_names_the_gap_to_the_ceiling`, `test_over_the_ceiling_a_pr_may_not_grow_but_may_stay`, `test_main_that_grows_turns_an_earlier_pass_red`, `test_main_that_shrinks_can_still_turn_an_earlier_pass_red`, `test_rerun_workflow_matches_its_pin`, `test_reruns_every_open_pr_waiting_for_one_in_progress`, `test_failures_turn_the_job_red`, `test_pin_catches_mutations`.

**Tier / gate:** tier A, gate files (`.github/`, `tools/trusted_base.py`): L3 and a separate Security accept (D-137).
