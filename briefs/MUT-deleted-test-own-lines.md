# MUT-deleted-test-own-lines: a diff's changed tests widen its targets even beside an added line

Board section: Defects and later findings on surviving packages. Work item #5762, a release finding on #5761 (GUEST-mut-store). Tier A gate file (`tools/premerge.py --needs-mark` prints `mark`): the separate Security accept is owed. Defect in REV-PROOF-mut (#4908).

**Requirement:** MUT-tierA (a PR's changes leave no line its tests run unchecked; #1814, #4908). Local ID **MUT-deleted-test-own-lines**: a package's target lines are the lines the diff adds to its non-test `.go` files *plus*, whenever the diff changes or deletes a `_test.go` file there, the lines the changed tests cover (every covered line when `changed_tests` is `None`).

**The gap.** `targets_for` (and `run`, `plan`, `decide`) used the diff's own non-test lines and read the changed tests only when there were none. A PR deleting the only test that kills a mutant, plus one trivial non-test line (a comment counts), targeted that line alone and passed.

**Measured at the base too (Security 6881170289 and L3 6881201591 on #5770).** A weakened test (`t.Skip`, an early `return`, `//go:build never`, a deleted sole test, a new `TestMain` running nothing) covers nothing at the head, so `plan` also runs the base's version of the changed tests (every base test when the head side is every test) on a `git archive` of the merge base, moves those lines to the head's through the diff, and records them as the record's `base` part. They are targets, and a NOT COVERED mutant on one fails the gate. This also closes #5753 (a helper edit beside a comment line).

**Decision taken here (L3 ruled it correct on #5770).** Widen on any test change, not only on a deletion. An added `t.Skip()` or early `return` weakens a test with no deleted line, so a deletion-only rule keeps the same hole. Cost: a PR that changes source and tests now also mutates what its changed tests run; one that adds a new test file, or edits a helper or header, mutates every covered line of the package (as a test-only diff already does). `plan` sizes the shards; past the matrix limit it names the remedy (split the PR).

**Build.** `tests_changed` and `union` helpers; `targets_for`, `run`, `plan` and `decide` use the union whenever `tests_changed`; the coverage record still holds only the covered lines and is required beside added lines; the summary caption names both parts.

**Scope:** `tools/mutgate.py`, `tests/test_mutgate.py` (the issue's `tools/test_mutgate.py` is this file), `tools/ASSUMPTIONS.md` (one row), this brief. Fixtures whose PR commit added a vestigial `// REQ:` test file (no longer needed since #4908) drop it, or add their tests in the base commit, so they keep testing own-line targets.

**Out of scope:** none beyond the scope list.

**Acceptance tests:**
- MUT-deleted-test-own-lines: `tests/test_mutgate.py::TestOnly::test_a_deleted_test_widens_the_targets_beside_an_added_line`, `::test_a_weakened_test_fails_on_the_lines_its_base_version_ran`, `::test_a_helper_edit_beside_an_added_line_widens_to_every_covered_line`, `::test_base_side_lines_of_a_diff`, `::test_targets_for_unions_own_lines_with_changed_tests_coverage`

**Done:** CI green; both tests pass and fail on the base's `mutgate.py`.
