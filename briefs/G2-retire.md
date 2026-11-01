# G2-retire: delete the G2 scope freeze

Source: Mark, "A, retire the freeze" on Decisions 8 card cmsg_01R91wiieBzMSvPKFsAJVvuKJDWtBhdEt62BCTwsh3PznR (D-306). Tier: A (gate files). Usage estimate: 60k tokens.

**Why.** Since D-128 a PR may touch only `tools/g1_scope_g2.txt` paths until A4, A5, A9 and A14 pass on a VM. D-198 and the other standing exemptions cover most work, so the freeze now mostly costs an `exempt-pr` companion PR, with its own Security accept, per change, plus list amends that `GoImportsTest` forces whether the freeze is on or off. Setting `freeze off` would leave that drift test and the premerge step running against a list that gates nothing (the G1-retire lesson, #2986), so the gate is deleted. G2 focus comes from dispatch order. D-098's `frozen` rows are a separate rule and stay.

## Requirements

- **G2-retire-1** `tools/g1_scope.py`, `tools/g1_scope_g2.txt`, `tests/test_g1_scope.py` and `.github/workflows/g1-freeze.yml` are deleted; premerge's gate no longer runs a freeze step or fetches the timeline only that step read, and no longer reruns on `g1-freeze`.
- **G2-retire-2** Every other premerge, lane-gate, tier and list-reader check is unchanged: the premerge pins, its fail-closed run tests, `risk_tier` tiers and the list-reader cases still pass for every remaining file.
- **G2-retire-3** The records name no deleted path as live: OPERATING §3, §5 and §7, PLAN.md, handoff/CURRENT.md, DECISIONS.md (D-306 supersedes D-128's G2 part and D-198) and tools/ASSUMPTIONS.md (D34 retired).

**Acceptance tests:** G2-retire-1 `tests/test_workflows.py::WorkflowTest::test_premerge_status_is_pinned` and `PremergeRunTest`; G2-retire-2 the rest of `tests/test_workflows.py`, `tests/test_premerge.py`, `tests/test_risk_tier.py`, `tests/test_ci_scope.py`, `tests/test_list_readers.py`; G2-retire-3 `tools/doclint.py`.

**Guard files:** none

## Scope

`tools/g1_scope.py`, `tools/g1_scope_g2.txt`, `tests/test_g1_scope.py`, `.github/workflows/g1-freeze.yml` (all deleted), `.github/workflows/premerge.yml`, `.github/workflows/ci.yml`, `tools/premerge.py`, `tools/risk_tier.py`, `tools/ci_scope.py`, `tools/ASSUMPTIONS.md`, `tests/test_workflows.py`, `tests/test_premerge.py`, `tests/test_risk_tier.py`, `tests/test_ci_scope.py`, `tests/test_list_readers.py`, `docs/OPERATING.md`, `PLAN.md`, `handoff/CURRENT.md`, `DECISIONS.md`, `briefs/G2-retire.md`.
