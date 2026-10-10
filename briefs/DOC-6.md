# DOC-6: BOARD state follows merges automatically

Board section: Owner-benefit review (2026-10-09). Finding from the 2026-10-09 owner-benefit review (point 4): BOARD said P2-1 was "in review (#41)" after #41 merged, and IMG-1, UPD-b3 and HOST-1a part 2 stayed "blocked on P2-1". 31 BOARD rows are `in review` at 9b4bf8a; nothing checks them against GitHub. Mark's choice, 2026-10-09: **the post-merge workflow may commit to main, as `trace.yml` does.**

**Tier:** A (`.github/workflows/`, under RT-1; until RT-1 merges, declare A by hand). Strongest model. About 50k tokens.

**Needs:** DOC-5 (it shares the BOARD parsing). RT-1 is not required.

## Today

- BOARD state cells name PRs in several forms: `in review (#41)`, `in review (#626; tier A)`, `merged (#355)`, `merged (1355d27; #437)`, `merged 82817bb (#562)`, `merged (#431 a52a678)`. Some `in review` rows name no PR.
- `trace.yml` runs on `push` to main. It generates in a read-only job, then commits in a separate `contents: write` job as github-actions[bot] with `git pull --rebase origin main && git push origin HEAD:main`. A push with GITHUB_TOKEN starts no new workflow runs.
- PR-gate CI uses a shallow clone, so it cannot see merge history. This check belongs after merge.

## Requirements (local IDs)

- **DOC-6a, a flip tool.** `tools/boardsync.py` takes BOARD.md plus a map of PR number to state (merged with SHA, closed unmerged, open). It rewrites only rows whose state starts `in review` and names exactly one PR:
  - merged: `merged (#N)` (the rest of the old note is dropped only if it was the PR reference);
  - closed unmerged: left unchanged and listed for the coordinator (closing is not dropping).
  - It also rewrites `blocked on <ID>` to nothing in rows whose `<ID>` it just flipped, and lists those rows.
  - It is pure: no network. Its output is idempotent.
- **DOC-6b, the workflow.** `.github/workflows/boardsync.yml` runs on `pull_request: closed` (merged) and daily. A read-only job queries the PRs named by `in review` rows (GITHUB_TOKEN, `pull-requests: read`) and runs the tool. A separate `contents: write` job commits BOARD.md as github-actions[bot] the same way `trace.yml` does. It commits only when BOARD.md changed, with a message listing the rows flipped. Pin actions by SHA as the other workflows do.
- **DOC-6c, report what it won't decide.** The job summary lists closed-unmerged PRs, `in review` rows with no PR number, and unblocked rows, so the coordinator sees them without reading BOARD.
- **DOC-6d, no rule change for PRs.** CLAUDE.md is unchanged. Builders still set their own row; this only catches the flip after merge. Note in OPERATING §7's merge step that the flip is automatic (one line).

## Tests (written first)

- `tests/test_boardsync.py`:
  - each PR-reference form above, as merged, open and closed;
  - a row with two PR numbers is left alone and listed;
  - idempotence;
  - unblocking is limited to rows naming the flipped ID.
- The workflow is checked by an `actionlint`-style parse if one is already in CI; otherwise by a test that loads the YAML and asserts the permission split (read-only generate job, write only in the commit job).

## Scope

`tools/boardsync.py`, `tests/test_boardsync.py`, `.github/workflows/boardsync.yml`, `docs/OPERATING.md` (§7, one line), `tools/ASSUMPTIONS.md`.

## Not in scope

Writing PR-state changes other than merged. Opening rows for PRs with no row.
