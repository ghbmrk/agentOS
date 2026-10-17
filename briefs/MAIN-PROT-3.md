# MAIN-PROT-3: only the Actions app can write the generated-file bot branches

Work item: #757 (BOARD: release; the issue label reads `class:later`, fix the label when the PR opens). Source: L3 and Security 4a on #713 f1 ([record](../reviews/security/2026-10-10-pr713.md)). Serves D-091 and OPERATING §7: only reviewed or bot-generated changes reach main.

**Failure path (from the review, still open):** a writer pushes to the open `bot/trace` (or `bot/metrics`, `bot/board`, `bot/records`) branch after the bot armed auto-merge, and it merges with no review under the bot's name.

**State on main (checked 2026-10-17, main 59618fd):** the diff half is done. `premerge.yml` runs on `pull_request_target` from the base commit and, for a same-repo `bot/*` branch, runs `premerge.py --bot`, which passes only when the diff is that bot's one generated file (`tools/premerge.py:101-166`; `tests/test_premerge.py:335-379`); live ruleset `main-checks` requires `premerge`. Open: (a) nothing stops a writer pushing a branch named `bot/trace` with a hand-edited `TRACE.md`: the diff is the right file, and its content is unreviewed and not the bot's; (b) the `premerge` status itself is postable by the shared login (#1943, out of scope here).

**Design (a recommendation; the decision boundary is Mark's):** the control must live on main's side. Chosen: a `bot/**` branch ruleset whose creation, update and deletion bypass is the Actions app only. A required check that "every commit is the bot's" is rejected: git author and committer are free text, and the bot pushes unsigned, so the check would pass a forged commit. A byte-for-byte regeneration check is rejected for now: `trace.py` is deterministic but `metrics.py` reads the API, so it covers one of four branches.

**Requirement IDs** (PLAN.md tooling; no SPEC ID):
- **BP-1 (desired state is in the repo).** `.github/rulesets/bot-branches.json`: `target: branch`, `enforcement: active`, `conditions.ref_name.include: ["refs/heads/bot/**"]`, rules `creation`, `update`, `deletion` and `non_fast_forward`, `bypass_actors` exactly one entry: Integration `15368`, `bypass_mode: always`.
- **BP-2 (coverage cannot drift).** Every key of `BOT` in `tools/premerge.py` and every `BRANCH: bot/...` a workflow under `.github/workflows/` pushes matches the ruleset's include pattern; a new bot branch outside `bot/**` fails the test.
- **BP-3 (the bot can still work).** `trace.yml`, `metrics.yml`, `board.yml` and `records.yml` push with `GITHUB_TOKEN` or the `BOT_PR_TOKEN || github.token` expression; the test reads each and fails if a workflow's push token expression is anything else (a PAT is a user, not the app, and would be blocked).

**Acceptance tests:**
- BP-1: `tests/test_ruleset_bot_branches.py::RulesetTest::test_file_restricts_bot_refs_to_the_actions_app` (fails on main: no file; also a copy with a second bypass actor or `bypass_mode: pull_request` must be reported).
- BP-2: `::test_every_bot_branch_in_premerge_and_the_workflows_is_covered` (adds `bot/zz` to a copy of the workflow text; must report it).
- BP-3: `::test_bot_workflows_push_only_with_the_actions_token` (catches a PAT-only token expression).

**Scope:** `.github/rulesets/bot-branches.json` (new), `tests/test_ruleset_bot_branches.py` (new), this brief. Not `tools/premerge.py` (read only), not the four bot workflows, not `tools/ASSUMPTIONS.md`.

**Admin step (Mark, after merge; one command):** `gh api -X POST repos/ghbmrk/agentOS/rulesets --input .github/rulesets/bot-branches.json`. Verify: `git push origin HEAD:refs/heads/bot/zz-probe` as Mark's login is rejected; the next daily `trace` run still opens its PR. Roll back: delete the ruleset in Settings, Rules. **If the repo secret `BOT_PR_TOKEN` is set, the bot pushes as Mark's login, not the app, and this ruleset would block it: Mark checks Settings, Secrets first and the apply waits until it is removed or a GitHub App replaces it.**

**Not in this package:** who may post the `premerge` status (#1943); CTRL-check-pin (separate file, no overlap); content-regeneration checks for `bot/trace`.

**Tier and merge:** tier A (`.github/`): Security plus L3 on the strongest model, threat check below. Mark-only (D-125): nobody arms it.

**Threat check to answer in the PR:** can any non-app login still update `bot/**`; can a branch named `bot/x` outside the pattern reach main unreviewed; does the bypass cover a force-push from the app (the bot rebuilds the branch each run); what happens to a deleted bot branch when auto-merge is armed.

**Guard files:** none. **Dependencies:** MAIN-PROT-2 (merged). **Usage estimate:** small, under 60k tokens.

## Assumptions

| # | Assumption | Basis | If it changes |
|---|---|---|---|
| 1 | A ruleset bypass actor of type Integration 15368 covers pushes made with `GITHUB_TOKEN`. | GitHub rulesets docs, bypass list; unproven on this repo | The probe push in the admin step shows it; the next `trace` run fails and the ruleset is deleted. |
| 2 | The repo is a user account, so team and org-admin bypass types are unavailable. | `ghbmrk` is a user login | Another bypass type would be a cleaner pin; revisit. |
| 3 | `BOT_PR_TOKEN` is unset. | `trace.yml` falls back to `github.token` and warns when auto-merge is unavailable; the secret itself is unreadable from here | See the bold line above. |
