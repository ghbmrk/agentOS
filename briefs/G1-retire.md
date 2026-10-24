# G1-retire: delete the passed G1 gate's freeze list

Source: the vestigial-debt sweep (Mark, 2026-10-24 11:38Z: "Do a sweep for vestigial tech debt also. Relics of old systems that are now redundant"). Tier: A (gate file). Usage estimate: 40k tokens.

**Why.** G1 passed and its freeze has been off since D-128 (2026-10-17), but `tools/g1_scope.txt` stayed in `tools/g1_scope.py`'s `GATES`. `GoImportsTest` still required it to name every package the G1 binaries import, so ports kept amending a list that gates nothing: six commits since D-128, for example 2e9cda4 ("name broker/kernel in the G1 list"). G2's list, its freeze and its checks stay as they are.

## Requirements

- **G1-retire-1** `GATES` holds only G2, and `tools/g1_scope.txt` is deleted. A stray file of that name is never read.
- **G1-retire-2** Every remaining check still runs against G2: path checks, exempt-pr lines, the time exemption, fail-closed behaviour and the import coverage of G2's binaries.

**Acceptance tests:** G1-retire-1 `tests/test_g1_scope.py::ListTest::test_only_g2_is_left_and_it_is_on`, `CheckTest::test_a_pr_must_pass_every_gate`; G1-retire-2 the rest of `tests/test_g1_scope.py`, plus `tests/test_risk_tier.py`, `tests/test_premerge.py` and `tests/test_workflows.py`.

**Guard files:** none

## Scope

`tools/g1_scope.py`, `tools/g1_scope.txt` (deleted), `tests/test_g1_scope.py`, `tests/test_risk_tier.py`, `tests/test_premerge.py`, `.github/workflows/g1-freeze.yml`, `briefs/G1-retire.md`.
