# PREMERGE-stale: the `premerge` status, not the job, is the gate

Board row: issue #1946 (release finding from the Security review of PR #1944, PREMERGE-wire). Tier A; touches `.github/`, so it merges only on Mark's approval of the PR at its head (D-125).

## Requirements (local IDs, no SPEC row)

- **PREMERGE-stale-a.** A `failure` verdict (`no-verdict`, `fix-list`, a stale head) posts `premerge: failure` and leaves the `premerge-gate` job green. Reason: the gate is the `premerge` status, not the job; comment-time runs attach to main's head, so a red `no-verdict` run there reads as main breaking, and the push-time red run sits on the PR head after the accept. The job's colour was not what refused arming on #1984/#1987 (L3 on #1992): GitHub arms only a PR that cannot merge yet, and with `premerge` not required those accepted heads were already mergeable. `premerge` became a required status on main on 2026-10-17 (#1994), which is what makes an accepted head armable: it cannot merge until the rerun posts `success`. If the status is already `success` when the arm is tried, the PR is mergeable and the pinned direct merge (`expectedHeadSha`) is the route.
- **PREMERGE-stale-b.** Once the head SHA is read and validated, any error exit posts `premerge: failure` before the job ends red (#1946: a rerun that dies after a fix-list must not leave the head's earlier `success` standing). A failed final POST is retried once as `failure` by the same trap.
- Residual (unchanged, named in #1946): if the first `pulls` API read fails there is no head to post to; the job goes red and the head keeps whatever it had.

## Acceptance tests

**Acceptance tests:** PREMERGE-stale-a `tests/test_workflows.py::PremergeRunTest::test_failure_verdict_posts_failure_but_job_passes`, `test_same_posts_success`; PREMERGE-stale-b `test_error_after_head_known_posts_failure`, `test_error_before_head_known_fails_the_job`; both `WorkflowTest::test_premerge_status_is_pinned` (the line pin and its mutation edits). `PremergeRunTest` runs the workflow's own script with `gh`, `git`, `python3` and `jq` stubbed.

## Scope

`.github/workflows/premerge.yml`, `tests/test_workflows.py`, `tools/ASSUMPTIONS.md` (D36), this brief.
