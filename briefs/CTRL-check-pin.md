# CTRL-check-pin: main's required checks come only from the GitHub Actions app

Work item: #1345 (class:release; Security on PR #1303, originally CTRL-lane-gate r1; kept by D-126, which closed r2, r4 and `-require` with the Codex lane). Serves OPERATING §7: a PR merges only when CI actually passed its required checks. Related, not in scope: PREMERGE-source #1943 (who may post the `premerge` status).

**Failure path:** any write token on Mark's login (every agent session pushes as that login) calls `POST /repos/ghbmrk/agentOS/statuses/<sha>` with context `checks`, `broker`, `machines` or `hostcheck` and state `success`. Those contexts carry no `integration_id` in ruleset `main-checks` (24845174), so the status satisfies the requirement and a red PR merges. Live state read 2026-10-17: only `premerge` carries `integration_id: 15368`; `strict_required_status_checks_policy` is `false`; `g1-freeze` is not required (the older copy in the project files lists it, so it was removed or never applied).

**Requirement IDs** (PLAN.md tooling; no SPEC ID):
- **PIN-1 (desired state is in the repo).** `.github/rulesets/main-checks.json` holds the ruleset as it should be: the live rules plus `integration_id: 15368` on `checks`, `broker`, `machines` and `hostcheck`; `premerge` unchanged; `bypass_actors: []`; no new required context, no change to `strict_required_status_checks_policy`.
- **PIN-2 (a pin cannot block every merge).** Each required context in the file is the name of a job (its `name:`, else its key) in a workflow under `.github/workflows/` that runs on `pull_request`, except `premerge`, which is the commit status `premerge.yml` posts. A context no workflow can produce fails the test (it would block all merges).
- **PIN-3 (every context but `premerge` is pinned).** A required context without `integration_id: 15368` fails the test, except `premerge`, whose pin is kept as live.

**Acceptance tests:**
- PIN-1: `tests/test_ruleset_main_checks.py::RulesetTest::test_file_pins_the_four_ci_contexts_and_keeps_premerge` (fails on main: the file does not exist).
- PIN-2: `::test_every_required_context_is_a_real_job_or_the_premerge_status` (catches a renamed job, a typo in the file, a pinned `g1-freeze` with no required-job workflow).
- PIN-3: `::test_an_unpinned_context_fails` (feeds a copy of the file with one pin dropped; the test must report that context).

**Scope:** `.github/rulesets/main-checks.json` (new), `tests/test_ruleset_main_checks.py` (new, stdlib `unittest`, text-parses workflows like `tests/test_workflows.py`), this brief. Not `tools/ASSUMPTIONS.md`; the assumptions are below. Not the live ruleset: applying it is the admin step below, outside the PR.

**Admin step (Mark, after merge; one command):** `gh api -X PUT repos/ghbmrk/agentOS/rulesets/24845174 --input .github/rulesets/main-checks.json`. Then verify on a throwaway PR: post `state=success, context=checks` to its head with the API; `mergeStateStatus` must stay `BLOCKED` while the real `checks` run is red (the original failure path). If the pin ever blocks a real PR, `PUT` the previous body back (kept in the PR description).

**Not in this package:** a same-name check run from a PR's own `pull_request` workflow (the branch supplies its own `ci.yml`; the pin cannot see it; parity, accepted in #1943). Requiring `g1-freeze` or `lane-gate` (a new requirement is Mark's separate decision; the file mirrors live). The `lane-gate.yml` removal (D-126 item 4, filed `class:later`).

**Tier and merge:** tier A (`.github/`): Security plus L3 on the strongest model. Mark-only (D-125): `python3 tools/premerge.py --needs-mark` prints `mark`; nobody arms it, and Decisions posts Mark's card at the accepted head.

**Guard files:** none. `tests/test_workflows.py` pins workflow text and is only read, never edited. **Dependencies:** none. **Usage estimate:** small, under 60k tokens.

## Assumptions

| # | Assumption | Basis | If it changes |
|---|---|---|---|
| 1 | `integration_id: 15368` is the GitHub Actions app, and a check run from a `pull_request` job satisfies it. | The live `premerge` entry carries it; the first review of #1303 named it | The throwaway-PR check above fails; keep the old body and reopen. |
| 2 | The file can mirror live because the ruleset API returns the same shape it accepts after removing read-only fields (`id`, `source`, `_links`, timestamps). | `gh api repos/ghbmrk/agentOS/rulesets/24845174` read 2026-10-17 | The `PUT` rejects it; the builder trims the file and says which field. |
| 3 | Dropping `g1-freeze` from the live ruleset was deliberate. | Live state; no board row asks for it | If not, one-line question to Mark, a separate PR. |
