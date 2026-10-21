# BOARD-INTAKE-wf: an intake check comments on a malformed work-item issue

Work item: #2668 (fix 2 of #1780; fix 1 merged as #1807). The ID drops the `CX-` prefix the issue was filed with: the lane gate reads `CX-` as the Codex lane, which is tier C only. Board section: Harness and operating model. Tier: A (`.github/`). Builder: Opus. Usage estimate: 80k tokens.

**Why.** `board.yml` failed from 2026-10-12 to 2026-10-15 on malformed work-item issues, so BOARD.md was dark for three days. Since #1807 one render names every bad issue, but only in a workflow log nobody reads. The filer should hear it on the issue, at filing time.

## Requirements

- **INTAKE-1** `board.py intake --repo o/r --issue N` judges issue N with the same checks `render` runs (`row_of`, `issue_id`, duplicate ID, section and cell count against BOARD.md), by rendering the live work items and keeping the problems that name `issue #N`. An issue that is not an open, collaborator-opened work item has no problems.
- **INTAKE-2** It keeps at most one intake comment on the issue, found by the marker `<!-- board-intake -->` on a comment by `github-actions[bot]`: posted when problems appear, edited in place when they change, left alone when unchanged, and deleted when the issue is well formed. A comment by anyone else that carries the marker is never edited or deleted. It exits 0 when the comment is in its right state.
- **INTAKE-3** `.github/workflows/intake.yml` runs it on `issues: [opened, edited, labeled, unlabeled]` for a collaborator's issue that carries `work-item` or just lost it, with `contents: read` and `issues: write` only, main's checkout without credentials, one run at a time per issue. The only event value it reads is the issue number, through `env`; no issue text reaches a shell, and no other workflow file changes.

**Acceptance tests:**
- INTAKE-1 `tests/test_board.py::IntakeCommentTest::test_problems_are_the_ones_render_names_for_this_issue` (an issue judged by different checks than render, or blamed for another issue's problem) and `::test_an_issue_that_is_not_a_work_item_has_no_problems` (a stale comment left on an unlabelled or outsider issue).
- INTAKE-2 `::test_a_malformed_issue_gets_one_comment_naming_every_problem`, `::test_the_comment_is_edited_in_place_then_removed_when_fixed` (one comment per event, or a comment that outlives the fix), `::test_a_comment_by_anyone_else_is_never_touched` (a marker in a human comment that steers the bot into editing or deleting it).
- INTAKE-3 `tests/test_workflows.py::WorkflowTest::test_intake_is_pinned` (a widened trigger or permission, or issue text interpolated into the shell) and `::test_intake_check_catches_each_reported_edit`.

## Scope

`tools/board.py`, `tests/test_board.py`, `tests/test_workflows.py`, `.github/workflows/intake.yml`, `briefs/BOARD-INTAKE-wf.md`, `tools/ASSUMPTIONS.md`.

**Guard files:** none (no new package).

Out of scope: changing `render`'s checks or messages; `board.yml`.
