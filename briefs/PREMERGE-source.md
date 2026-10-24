# PREMERGE-source: only the premerge App can post a `premerge` status that counts

Board row: issue #1943 (release finding from PREMERGE-wire, #1860; evidence in its comments 6220373240 and 6227335932). Tier A; touches `.github/`, so it is a gate-file PR and needs the separate Security accept (D-137).

## Requirements (local IDs, no SPEC row)

- **PREMERGE-source-a.** `premerge.yml` posts the `premerge` status with an installation token of a dedicated GitHub App, minted from a key held in the `premerge` environment, whose deployment branches are main only. A `pull_request_target` or `issue_comment` run has ref main and gets the key; a branch's own `pull_request` workflow, or the base copy of a PR into another branch, does not. With the ruleset pinning `premerge` to that App, a status posted by any other source counts for nothing. Until the App is configured (`vars.PREMERGE_APP_CLIENT_ID` unset) the post falls back to `github.token`, so this merges before the settings change without blocking any PR.
- **PREMERGE-source-b.** A run whose PR base is not `main` posts `failure` (`base-not-main`), so a head accepted against an attacker's base branch (comment runs use main's workflow for any PR) cannot carry `success` into a PR to main.
- Out of scope: the `--bot` opener route (issue comment 6220373240 item 2) closed with `bot/records` (cut 4, #2234); the remaining bot branches change only their own generated file. The four unpinned contexts (CTRL-lane-gate r1b) take the same pin once the App exists.

## Acceptance tests

**Acceptance tests:** PREMERGE-source-a `tests/test_workflows.py::PremergeRunTest::test_status_is_posted_with_the_app_token`; PREMERGE-source-b `PremergeRunTest::test_base_other_than_main_fails`; both `WorkflowTest::test_premerge_status_is_pinned` (line pin and mutation edits).

## Needs Mark (settings, after merge)

Create the App (statuses write only, installed on this repo), the `premerge` environment (deployment branches: main; no reviewers) holding secret `PREMERGE_APP_KEY` (environment, never repo, secret) and variable `PREMERGE_APP_CLIENT_ID`, check one PR's `premerge` status shows the App, then pin `premerge` in ruleset `main-checks` to the App's id.

## Scope

`.github/workflows/premerge.yml`, `tests/test_workflows.py`, `tools/ASSUMPTIONS.md` (PREMERGE-source-1), this brief.
