# CONV-0: Convergence measures, daily metrics, ledger staleness

Board section: Harness and operating model. Decision: D-085. Tier C (`tools/metrics.py`, `tools/doclint.py`, `.github/workflows/metrics.yml`, tests). Builder: Sonnet (PILOT-S). Usage estimate: 60k tokens.

**Why.** D-085's guard and targets need numbers no tool produces today: open inventory, follow-up inflation, idle time, and the two revert signals. The only spend data is LEDGER.md, last read 2026-10-04.

## Requirements

- **CONV-0-1** `tools/metrics.py` adds weekly columns: open BOARD rows (queued + building + in review + escalated); follow-up rows added (IDs ending `-f<N>`, `-r<N>` or `-l<N>`, or rows whose package text says "(release" and cites a review); follow-up rows per PR merged; promotions from later to release (a BOARD row added that week whose text cites a LATER.md line); `Defect:` lines (existing); open PRs untouched over 48 hours, excluding drafts listed under "Held" in briefs/CODEX-1.md. Each column is computed from git and the GitHub data the tool already fetches; a column that cannot be computed in `--raw` mode prints `n/a`, never 0.
- **CONV-0-2** METRICS.md shows each new column's baseline (mean of the two weeks before 2026-10-09) and marks a week red when promotions or `Defect:` lines exceed it; two red weeks in a row print the line "D-085 guard tripped: revert the release-class rule (decisions/D-085.md)".
- **CONV-0-3** `.github/workflows/metrics.yml` runs daily (keep the existing weekly run's permissions and main-only rule).
- **CONV-0-4** When LEDGER.md's newest reading is over 36 hours old at run time, METRICS.md's first line says so with its date.
- **CONV-0-5** `tools/doclint.py`: a BOARD row added on or after 2026-10-10 whose state text contains `release` must name an acceptance test or invariant (a token matching a SPEC requirement ID, `Invariant`, or `Test[A-Z]\w+`). Older rows are exempt.

## Acceptance

Each ID has a test in `tests/test_metrics.py` or `tests/test_doclint.py` with a `REQ:` marker, using synthetic BOARD/LEDGER fixtures. `python3 tools/doclint.py` passes on main's current files. Recurring kinds: the "brief's declared scope omits forced test files" kind (reviews/potency/README.md) applies; declared scope above includes both test files.

## Scope

`tools/metrics.py`, `tools/doclint.py`, `.github/workflows/metrics.yml`, `tests/test_metrics.py`, `tests/test_doclint.py`, `METRICS.md` (regenerated only).
