# MAIN-PROT-3: a bot PR passes premerge only with output its own main run made

Work item: #757 (tier A, gate files). Source: L3 and Security 4a on #713 f1 ([record](../reviews/security/2026-10-10-pr713.md)); D-250 Security read #4486 (batch 3). Serves D-091 and OPERATING §7: only reviewed or bot-generated changes reach main.

**Failure path:** anyone who can push pushes `bot/trace` (or `bot/metrics`, `bot/board`) with a hand-edited generated file. The diff is the right file, so `premerge --bot` passed it with no review.

**Why not the earlier design (a `bot/**` ruleset, 2026-10-17):** it needs Mark's admin step, the bot pushes as Mark's login (`BOT_PR_TOKEN` is set: every `bot/trace` and `bot/board` push in the repository activity log is `ghbmrk`), so the ruleset would block the bot, and an Actions-app bypass still admits any branch workflow's `GITHUB_TOKEN`. Git author and committer are free text and the bot pushes unsigned, so "every commit is the bot's" proves nothing. Regenerating the file in the gate covers TRACE.md only: `metrics.py` and `board.py` read the live API.

**Design (code only, no admin step):** prove the content by the run that made it. Each writer workflow uploads its output as an artifact from the read-only generate job and commits that artifact's bytes with a `Bot-Run: <run id>` trailer. On a same-repo `bot/*` PR, premerge.yml (base copy, `pull_request_target`) reads the trailer, fetches that run and its newest unexpired artifact named for the branch, and `premerge.py --bot` passes only when the run is the bot's own workflow file, on a main trigger (`schedule`, `workflow_dispatch`, `push`), as its first attempt (a rerun of an old run would mint a fresh artifact of old output), in its own repository, at a commit main contains, and the artifact holds exactly the one file, byte-equal to the head's. A workflow at a main commit is reviewed code, and only a run's own jobs can upload its artifacts, so neither a hand push nor a branch workflow can produce a passing pair.

**Requirement IDs** (PLAN.md tooling; no SPEC ID):
- **BP-1 (content is the run's).** `--bot` reports `bot-unproven output` unless the artifact zip has one member, named for the bot's file, byte-equal to the head's copy.
- **BP-2 (the run is main's).** `--bot` reports `bot-unproven run` for another workflow path, a non-main trigger or a fork's run, and `run-not-on-main` for a head sha main does not contain; `--bot` without a run or artifact reports `no-run`, and the gate prints `bot-unproven no-run` or `no-output` when the trailer or artifact is missing.
- **BP-3 (the gate wires it, fail closed).** premerge.yml fetches the run the trailer names and its artifact with `actions: read`; a missing or malformed trailer, a missing artifact or a failed read posts `failure` without calling `--bot`.
- **BP-4 (the writers provide it).** trace.yml and metrics.yml pass their output to the commit job as an artifact (like board.yml), and all three commit with the `Bot-Run` trailer.

**Acceptance tests:**
- BP-1, BP-2: `tests/test_premerge.py::PremergeTest::test_bot_gate_needs_the_bots_own_run`, `::test_bot_gate`.
- BP-3: `tests/test_workflows.py::PremergeRunTest::test_bot_pr_fetches_its_writer_run_and_artifact`, `::WorkflowTest::test_premerge_status_is_pinned`.
- BP-4: `tests/test_workflows.py` existing workflow tests (`test_board_crosses_jobs_as_an_artifact`, `test_bot_token_jobs_run_in_the_bot_environment`), and the first bot PR after merge reaching `premerge` `success` (`bot`).

**Scope:** `tools/premerge.py`, `tests/test_premerge.py`, `tests/test_workflows.py`, `.github/workflows/{premerge,trace,metrics,board}.yml`, this brief.

**Residuals:** (a) a stale but genuine output can be replayed while its first-attempt artifact lives (2 days for trace and metrics, 1 for board): an older bot result, never a hand-written one; the next run supersedes it. A rerun of a bot run produces a PR that fails `premerge` until the next scheduled or dispatched run. (b) Who may post the `premerge` status (#1943) is out of scope. (c) A bot PR whose artifact expired before it merged posts `failure` on a rerun until the next bot run rebuilds it.

**Tier and merge:** tier A, gate files: Security accept in its own comment plus combined, UX and Potency at an equal head (D-137).

## Assumptions

| # | Assumption | Basis | If it changes |
|---|---|---|---|
| 1 | Only a run's own jobs can upload artifacts to it; a rerun reruns the workflow file at the run's own commit. | Actions artifacts are written with the run-scoped runtime token | The proof weakens to "some job could write here"; move to signed attestations. |
| 2 | The Actions run API's `path` is the workflow file that ran (a reusable-workflow caller reports its own path), and `head_sha` is the commit whose workflow file ran. | GitHub REST docs; trace.yml runs on main show `.github/workflows/trace.yml` | `--bot` rejects every run (`run`), which fails closed; adjust the match. |
| 3 | `upload-artifact` v4 zips a single-file path as one member named after the file. | action docs; board.yml's commit job reads `board/BOARD.md` | `--bot` reports `output`; adjust the member name. |
