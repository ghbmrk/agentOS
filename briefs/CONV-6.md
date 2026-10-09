# CONV-6: Turn recurring finding kinds into checks

Board section: Harness and operating model. Decision: D-085; CLAUDE.md reviewer rule ("a kind of finding seen on a second PR becomes a lint rule, test or CI check"). Tier: per check (`tools/risk_tier.py`; a check in `tools/depaudit*` or `tools/canary*` is tier A and hands off). Builder: Sonnet (PILOT-S) for B/C. Usage estimate: 120k tokens; one check per PR.

**Why.** The lens READMEs list five recurring kinds with no check yet; each recurs as review findings and follow-up rows.

## Requirements

- **CONV-6-1** Sweep `reviews/` records dated 2026-10-07 or later for finding kinds seen on two or more PRs; add any missing to the matching lens README's "Recurring kinds" table.
- **CONV-6-2** For each recurring kind whose owner package has not started, build the check named in the README (lint rule, test or CI step), with a test that fails on a synthetic instance of the kind and passes on main.
- **CONV-6-3** Move each built kind to "Checks that replaced findings" with its check and package ID.
- **CONV-6-4** Briefs written after a check lands list the remaining recurring kinds for their area as acceptance criteria (OPERATING §5).

## Acceptance

Each check has a `REQ:` marked test; CI green; the lens README rows are moved in the same PR as the check.

## Scope

`reviews/*/README.md`, `tools/doclint.py`, the test files of the area each check covers (named in that PR), `tests/`.
