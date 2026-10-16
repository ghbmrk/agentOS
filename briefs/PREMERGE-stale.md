# PREMERGE-stale: the `premerge` status, not the job, is the gate

Board row: issue #1946 (release finding from the Security review of PR #1944, PREMERGE-wire). Tier A; touches `.github/`, so it merges only on Mark's approval of the PR at its head (D-125).

## Requirements (local IDs, no SPEC row)

- **PREMERGE-stale-a.** A `failure` verdict (`no-verdict`, `fix-list`, a stale head) posts `premerge: failure` and leaves the `premerge-gate` job green. Reason: the push-time run's check run sits on the PR head, while comment-time reruns attach to main's head, so a red push-time job outlives the later accept and GitHub refuses auto-merge on the accepted head (seen on #1984 and #1987, which then had to be merged directly).
- **PREMERGE-stale-b.** Once the head SHA is read and validated, any error exit posts `premerge: failure` before the job ends red (#1946: a rerun that dies after a fix-list must not leave the head's earlier `success` standing). A failed final POST is retried once as `failure` by the same trap.
- Residual (unchanged, named in #1946): if the first `pulls` API read fails there is no head to post to; the job goes red and the head keeps whatever it had.

## Acceptance tests

`tests/test_workflows.py`: `PremergeRunTest` (runs the workflow's own script with `gh`, `git`, `python3` and `jq` stubbed) and `WorkflowTest.test_premerge_status_is_pinned` (the line pin and its mutation edits).

## Scope

`.github/workflows/premerge.yml`, `tests/test_workflows.py`, `tools/ASSUMPTIONS.md` (D33), this brief.
