# PROC-waste: fewer review sessions and delta reviews

Work item: #4040. From Mark's waste sweep (2026-10-30) and his "A, one thread, fresh subagent" tap on the review-merge card (Decisions 8, 2026-10-30), recorded as D-246.

**Requirement IDs:** none in SPEC.md (PLAN.md process and tooling). The brief's own items:
- **PW-1 (one review thread).** The L3 session of a PR spawns the UX and Potency screen as a fresh-context subagent that never sees L3's reasoning and posts its own lens verdicts. Security stays a separate fresh session. Delta re-reviews take the same shape. OPERATING §4 (stage 4 row, lens checklist) and the reviewer skill.
- **PW-2 (brief in build PR).** A brief may be its build PR's first commit (OPERATING §5 Brief).
- **PW-3 (decision renumber).** `premerge.py` reads as `same` a DECISIONS.md main-merge in which the reviewed rows appended at main's spot differ from the reviewed commit only in their first-cell IDs, with main's rows verbatim, no duplicate ID, and no other file the PR changes naming an old ID as a word.
- **PW-4 (allowlist merge).** `premerge.py` reads as `same` a `*_allow.txt` whose lines, as a multiset, are main's plus the lines the reviewed commit added less those it removed, in any order, with the same mode.

**Acceptance tests:**
- PW-1, PW-2: none: wording only; `tools/word_budget.py` keeps the process set from growing and `tools/doclint.py` checks OPERATING references.
- PW-3: `tests/test_premerge.py::PremergeTest::test_decisions_reviewed_row_renumbered_past_mains_is_same_unless_cited` (both orders same; a PR file still citing the old ID, now main's row, is changed). `test_decisions_resolution_that_edits_drops_or_adds_a_row_is_changed` keeps text edits and renumbered main rows changed.
- PW-4: `tests/test_premerge.py::PremergeTest::test_allowlist_conflict_kept_both_sides_is_same_in_any_order`, `test_allowlist_resolution_that_adds_drops_or_keeps_a_removed_line_is_changed` (a kept removed line, a dropped main line, an extra line, a duplicate), `test_a_list_not_named_allow_keeps_line_order`.

**Scope:** `tools/premerge.py`, `tests/test_premerge.py`, `docs/OPERATING.md`, `.claude/skills/agentos-reviewer/SKILL.md`, `DECISIONS.md` (D-246), this brief.

**Tier and merge:** gate files (premerge.py, OPERATING, `.claude/`): L3 plus a separate Security accept (D-137).

**Guard files:** none. **Dependencies:** none. **Usage estimate:** small, one session.

## Assumptions

| # | Assumption | Basis | If it changes |
|---|---|---|---|
| PW-a1 | Every `*_allow.txt` checker reads its entries as an unordered set of lines. | `pathops_lint_test.go` and `tools/netguardcheck.py` match each line on its own. | A file whose order matters is renamed off the pattern. |
| PW-a2 | A renumbered decision's only references live in the PR's own files or its body. | Rows cite each other by ID; the merge gates read base-tree rows only. | A gate that reads head-tree IDs re-checks the renumber. |
