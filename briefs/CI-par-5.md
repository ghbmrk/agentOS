# CI-par-5: Drop the `broker` aggregator job; require the split jobs directly

Board section: Harness and operating model. Work item #4338. Follows CI-par-4 (#4336, PR #4337).

**Problem:** the required `broker` check is a 0-second job that waits for `broker-race` (3 shards) and `broker-checks`, then queues for a runner of its own: 16 min p50 and 123 min p90 under the 20-job cap. It finishes last in 88 of 150 runs (audit, #4304).

**Requirements:** no new IDs. CI-docs, CI-par-4, CIMG-a/b/c and CI-PATHS hold unchanged. ci.yml has no `broker` job and no job has `needs:`. Main's ruleset requires `broker-race (0)`, `broker-race (1)`, `broker-race (2)` and `broker-checks` in place of `broker` (Mark's change, #4340). Every other job id and the shard values are unchanged.

**Order:** the ruleset swap goes live first; this PR may be reviewed and accepted before it but is not armed or merged until it is (comment 6558188748 on #4338). Merged first, every PR waits on a `broker` check that never reports.

**Scope:** `.github/workflows/ci.yml`, `tests/test_ci_scope.py`, `tests/test_ci_split.py`, `tools/ASSUMPTIONS.md` (D30's wording), this brief.

**Acceptance tests:** `tests/test_ci_scope.py`: `test_required_check_names_unchanged`, `test_ci_skips_only_on_records_and_checks_always_runs`, `test_push_to_main_runs_every_job`; `tests/test_ci_split.py`: `test_no_broker_aggregator_job`.

**Acceptance:** the PR's own CI run is green with no `broker` check run, and main's ruleset lists the four split checks and not `broker` before merge.

**Tier / gate:** gate-file PR (`.github/`): L3, a separate Security accept (D-137) and the tier's lens screen.
