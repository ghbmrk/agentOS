# MUT-tierA: mutation testing on tier A packages

Board row: issue #1814. Class: release. Tier: B (tools and tests only; `tools/risk_tier.py` prints the tier). Builder: Sonnet 5.5. Usage estimate: 60k tokens, checkpoint at 45k. Mark's approval: cmsg_01R63S2yrPkq32thy8WQCuvD4ZhaF7R66ou9htfU82KqqA.

**Why.** REQ markers can claim coverage the tests do not give (the "inflated REQ markers" blocker on #1705). A mutation tool shows covered code whose tests do not check it.

## Requirement

Serves the trace and coverage invariant (CLAUDE.md "Done": every brief ID is covered by a passing test). No SPEC ID.

Package IDs:
- **MUT-tierA-a** `tools/mutgate.py packages` lists the tier-A broker packages from `tools/risk_tier.py`'s lists (one source of truth).
- **MUT-tierA-b** `run` runs gremlins (reused, not built) once per package and writes one JSON file per package; `report` prints the surviving (LIVED) mutants per package.
- **MUT-tierA-c** `gate` fails a diff that adds a `REQ:` marker under `broker/<pkg>/` and adds a line of a non-test `.go` file in that package where a LIVED mutant sits.
- **MUT-tierA-d** a survivor on a line the diff did not add, in another package, or in a test file does not fail the gate.

## Acceptance tests

**Acceptance tests:**
- MUT-tierA-a: `tests/test_mutgate.py::Gate::test_tier_a_packages_are_tier_a`
- MUT-tierA-b: `tests/test_mutgate.py::Gate::test_survivors_reads_lived_only_and_nested_package_names`, `::test_report_and_cli`
- MUT-tierA-c: `tests/test_mutgate.py::Gate::test_live_mutant_on_added_line_in_claimed_package_fails`
- MUT-tierA-d: `tests/test_mutgate.py::Gate::test_no_marker_no_claim`, `::test_survivor_on_untouched_line_or_other_package_passes`, `::test_survivor_in_a_test_file_is_not_counted`

## Scope

`tools/mutgate.py`, `tests/test_mutgate.py`, `tools/ASSUMPTIONS.md` (one appended row), this brief.

## Out of scope

Wiring `gate` into a CI workflow (`.github/` is tier A and Mark-only); a release finding names it. Replacing part of the tier-B review (the issue's "Later").

## Done

CI green; the four IDs covered by the tests above; one real `run` on a tier-A package reported in the PR.
