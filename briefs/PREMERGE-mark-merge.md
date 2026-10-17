# PREMERGE-mark-merge: `--needs-mark` sees what the merge changes

Work item: #2138 (class:release, from the Security review of #2133 at head 77393e6). Serves D-125 and OPERATING §7: `tools/premerge.py --needs-mark` prints `mark` for every PR whose merge changes a Mark-only path.

**Requirement IDs:** none in SPEC.md (PLAN.md tooling). The brief's own items:
- **MM-1 (criss-cross).** `--needs-mark` lists the files of merge-base..head and also the files the merge itself changes on base (`git diff <base> $(git merge-tree --write-tree <base> <head>)`), so a PR whose merge reverts base's copy of a Mark-only file prints `mark` even when `git merge-base` picks a base where head's copy is unchanged.
- **MM-2 (conflict fails closed).** A conflicted merge-tree does not crash the gate or drop the file: its tree keeps conflict markers, so the conflicted file reads as changed.
- **MM-3 (`.claude` symlink).** `.claude` at any depth counts with or without a trailing path (`(?:.*/)?\.claude(?:/.*)?`), so a PR adding `broker/.claude -> ../cfg` prints `mark`; `.claudex`, `x.claude` and `.claude.bak` stay agent-mergeable.

**Acceptance tests:**
- MM-1: `tests/test_premerge.py::PremergeTest::test_cli_needs_mark_sees_a_revert_made_by_a_criss_cross_merge` (the #2138 repro: two merge bases, the merge reverts main's CLAUDE.md; fails on main with `agent`).
- MM-2: `tests/test_premerge.py::PremergeTest::test_cli_needs_mark_sees_a_mark_file_the_merge_resolves_in_conflict` (PR and main both edit CLAUDE.md; catches a merge-tree exit 1 raising or dropping the file).
- MM-3: `tests/test_premerge.py::PremergeTest::test_cli_needs_mark_sees_a_claude_symlink` (symlink repro plus the pattern's near misses; fails on main with `agent`).
- The existing `--needs-mark` and `mark_paths` tests keep passing (empty range and second positional stay exit 2).

**Scope:** `tools/premerge.py`, `tests/test_premerge.py`, this brief. Not `tools/ASSUMPTIONS.md` (open in #1992, #2164, #2168, #2209); the assumptions are below instead.

**Tier and merge:** tier A (premerge.py is a merge gate): Security plus L3. Mark-only (D-125): the PR touches premerge.py, so it is never armed at accept; once reviews accept and CI is green, Decisions posts Mark's card at that head.

**Guard files:** none. **Dependencies:** none (G1 allow list covers `tools/`). **Usage estimate:** small, one session.

## Assumptions

| # | Assumption | Basis | If it changes |
|---|---|---|---|
| 1 | GitHub's merge of a PR equals `git merge-tree --write-tree <base> <head>` for the files it changes (merge commit; squash and rebase land the same tree when clean). | Git 2.38 merge-ort, already required by premerge.py | A merge method that lands a different tree needs its own range. |
| 2 | The union is a superset of the old file list, so no PR that printed `mark` before prints `agent` now. | `names(merge-base, head)` is kept unchanged | None. |
| 3 | A conflicted PR cannot merge on GitHub, so listing a conflicted non-Mark file is harmless; listing a conflicted Mark file is the safe side. | GitHub refuses a conflicted merge | None. |
