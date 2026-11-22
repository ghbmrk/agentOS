# PREMERGE-replay-inputs-gate: every input to premerge's replay is a gate file

Work item: #6444 (class:release, from the Security review of #6418, comment 7061304905; row #6375). Serves the invariant that a PR cannot weaken the merge gate on L3 alone (#2438, D-137).

**Requirement IDs:** none in SPEC.md (PLAN.md tooling). The brief's own item:
- **PREMERGE-replay-inputs-gate.** The tree files `git merge-tree` reads during premerge's replay are gate files, by class: `.gitattributes` at any depth (merge-tree, run in a checkout of the base, applies each directory's attributes, and a `merge=` line decides whether a conflict replays clean, so which heads read `same`) and the root `.gitmodules` (merge-ort locates a submodule through it). `tools/premerge.py` names the class once (`REPLAY_INPUTS`) and folds it into `MARK_PATHS`, so `--needs-mark` prints `mark` for a PR changing one. The other names git reads in a tree (`.gitignore`, `.mailmap`) shape no merge and are listed as such (`NOT_REPLAY_INPUTS`); a test fails on any tracked file of a git-read name in neither class.

**Acceptance tests:** PREMERGE-replay-inputs-gate `tests/test_premerge.py::PremergeTest::test_every_replay_input_is_a_gate_file` (a nested `.gitattributes` changes the replay; the class and its near misses; every tracked git-read name is classed; fails on main with `[] != ['.gitattributes']`). The existing `mark_paths` tests keep passing.

**Scope:** `tools/premerge.py`, `tests/test_premerge.py`, `tools/ASSUMPTIONS.md` (PREMERGE-replay-inputs-1), this brief.

**Tier and merge:** tier A (premerge.py is a merge gate) and a gate-file PR: L3 plus a separate Security accept (D-137).

**Guard files:** none. **Dependencies:** #6418 and #6453 (merged). **Usage estimate:** small, one session.
