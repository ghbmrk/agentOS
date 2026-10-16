# STALE-1: Flag work items whose PR merged but whose state label is still open

Board section: Harness and operating model. Source: Questions-thread recommendation 1 (2026-10-16), approved by Mark. Tier: C. Builder: Sonnet. Usage estimate: 60k tokens.

**Why.** Four `queued` rows (CONV-3, CONV-5, CI-FLAKE-SETTLE, CI-FLAKE-MODEMAT) were started on 2026-10-16 and were already done on main; each cost a fresh session to find out, because the issue labels were stale. `tools/board.py` already notes the disagreement on stderr in workflow logs, where nobody reads it.

## Requirements

- **STALE-1-1** `board.py stale --repo o/r` lists each open work item whose state is queued, building, in review or escalated and whose ID-named PR merged while no open PR names it.
- **STALE-1-2** With `--comment` it posts one comment per issue and merged PR (marker `<!-- board-stale: #N -->`), saying to set `state:merged` or name the follow-up. It never relabels, closes or fails the run.
- **STALE-1-3** `.github/workflows/stale-labels.yml` runs it after each push to main, daily, and on dispatch, with `issues: write` and no write to contents; it checks out main only.

**Acceptance tests:** STALE-1-1 `tests/test_board.py::StaleLabelTest::test_a_merged_pr_on_an_open_row_is_flagged`; STALE-1-2 `test_flagging_changes_nothing_and_exits_zero`, `test_comment_is_posted_once_per_issue_and_pr`; STALE-1-3 `test_workflow_comments_with_the_issue_token_only`.

## Acceptance

`tests/test_board.py::StaleLabelTest` (REQ-marked); CI green.

## Scope

`tools/board.py`, `tests/test_board.py`, `.github/workflows/stale-labels.yml`, `briefs/STALE-1.md`, `tools/ASSUMPTIONS.md` or the package's `ASSUMPTIONS.md`.
