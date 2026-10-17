# CTRL-lane-gate: make the codex lane gate block a merge, and state what it rests on

Board rows: issues #1345 (r1), #1346 (r2), #1348 (r4), under the umbrella #1344 (CTRL-lane-gate-require). Source: Security, L3 and Potency on PR #1303. Class: release. Tier: A (`.github/workflows/`, `tools/risk_tier.py`). Builder: strongest model. Usage estimate: 60k tokens, checkpoint at 45k.

**Why (facts, verified at main eed5253 and the live ruleset, 2026-10-17).**
- `main-checks` (ruleset 24845174, read 2026-10-17 from `GET /repos/ghbmrk/agentOS/rulesets/24845174`) requires `checks`, `broker`, `machines`, `hostcheck` with no `integration_id`, and `premerge` pinned to GitHub Actions (`integration_id: 15368`). `lane-gate` is not required, so a red lane gate does not block a merge (#1344).
- The four unpinned contexts can be satisfied by `POST /repos/ghbmrk/agentOS/statuses/<sha>` from any token with repo write; every lane pushes as the same login (R1).
- R4 throwaway PR #1582 (results in #1344, comment 6169321649): the real `lane-gate` run (`pull_request_target`) attaches to the PR head and failed; a `pull_request` workflow in the PR with a job named `lane-gate` attached a second, passing `lane-gate` check run to the same head, from the same app. The session's credential pushed a file under `.github/workflows/` without error, so the shared login has the `workflow` scope. Whether a ruleset honours the passing duplicate was not tested (needs `lane-gate` required).
- The same reasoning applies to the required `premerge` status: a `pull_request` workflow with `statuses: write` posts as GitHub Actions too, so the 15368 pin does not tell it apart. D28 states this risk only as "no one posting a `premerge` status by hand".
- D26 (`tools/ASSUMPTIONS.md`), the `lane-gate.yml` header and LANES.md's Paths bullet still say a PR "cannot delete, skip or loosen the gate" and "CI enforces this". Both claims are false today.
- The gate keys the lane on the `pkg/codex-` stem or a `CX-` title (D26); a Codex PR with neither is not gated (R2).

## Package IDs

- **CTRL-lane-gate-r1a** A codex-lane PR rated above tier C cannot pass the required `premerge` status: the base copy of `premerge.yml` runs the base `tools/risk_tier.py` lane check on the PR's diff, head branch and title (all from the API, as the job already reads them) before `premerge.py`, and posts `failure` with the lane message when it fails. Fail closed on any error. This uses the check main already requires and pins, so it needs no ruleset change. `lane-gate.yml` stays as the visible, named signal (smaller diff; its pinned-form tests stay); its header says the blocking copy is in `premerge.yml`.
- **CTRL-lane-gate-r1b** (Mark's ruleset action, not code) `checks`, `broker`, `machines` and `hostcheck` in `main-checks` are pinned to GitHub Actions (`integration_id: 15368`), so a hand-posted status from the shared login cannot satisfy them. Nothing else in the ruleset changes.
- **CTRL-lane-gate-r4** D26, D28, the `lane-gate.yml` and `premerge.yml` headers and LANES.md's Paths bullet state the guarantee as conditional: the gate and the `premerge` status hold only while every lane that can push to this repo is trusted not to add a workflow that posts a same-name check or status, which today means every lane, since all push as one login with the `workflow` scope. Drop "a PR cannot … skip the gate" and "CI enforces this" until R2 lands.
- **CTRL-lane-gate-r2** (after Mark's decision) If Mark gives the Codex lane its own GitHub identity, `lane_of` also keys on the PR author login (`github.event.pull_request.user.login`, or `.user.login` from the API in `premerge.yml`), D26 is updated, and the identity's token has no Workflows permission, which closes R4 for that lane. If Mark keeps the shared login, r2 closes with D26's conditional wording from r4 as the record.

**Acceptance tests:**
- CTRL-lane-gate-r1a: `tests/test_workflows.py::test_premerge_runs_the_lane_gate` (new): the `premerge.yml` step runs `python3 -I tools/risk_tier.py --git … --pr-branch … --pr-title …` from the base checkout before `premerge.py`, from API values not the event, and a failing lane check leaves `state=failure`; catches a premerge that skips or ignores the lane check. Existing `tests/test_risk_tier.py::test_lane_gate_holds_codex_prs_to_tier_c` keeps covering the classifier.
- CTRL-lane-gate-r1b: none: a ruleset setting; checked by `GET /repos/ghbmrk/agentOS/rulesets/24845174` listing the four contexts with `integration_id: 15368` and `premerge` unchanged.
- CTRL-lane-gate-r4: none: records and comments only.
- CTRL-lane-gate-r2: `tests/test_risk_tier.py` cases for the author key (a codex-login PR on a `claude/` stem with a non-`CX-` title is in the lane; any other login on those names is not), only if Mark chooses a separate identity.

## Scope

`.github/workflows/premerge.yml`, `.github/workflows/lane-gate.yml` (header comment only), `.github/workflows/ci.yml` (the line-156 comment only), `tests/test_workflows.py`, `tools/ASSUMPTIONS.md` (D26, D28), `docs/LANES.md` (Paths bullet), `briefs/CTRL-lane-gate.md`. For r2 only: `tools/risk_tier.py`, `tests/test_risk_tier.py`. **Guard files:** none.

## Dependencies and conflict guard

- D-111: open PR #1992 (PREMERGE-stale) changes `.github/workflows/premerge.yml` and `tests/test_workflows.py`. Build after it merges or closes, on its result.
- r1b and r2 are Mark's: the ruleset edit needs admin, and the identity is his choice. The build does not wait on them; r2's code lands in a follow-up PR if he picks a separate identity.
- Merge: every file under `.github/` and `docs/LANES.md` makes this PR Mark-only (`premerge.py --needs-mark`, D-125).

## Out of scope

Moving any gate into a GitHub App, and the `premerge` status's own forgeability beyond recording it (a `later` finding unless a lane is ever untrusted).

## Done

CI green; r1a covered by its test; r4's wording in place; r1b verified from the ruleset API or recorded as Mark's pending action on #1344; r2 recorded with Mark's answer. Then #1345, #1346, #1348 and #1344 close.
