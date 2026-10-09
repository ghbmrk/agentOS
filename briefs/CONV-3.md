# CONV-3: Triage the open PR inventory

Board section: Harness and operating model. Decision: D-085 (48-hour idle limit). Tier C (records only). Builder: Sonnet (PILOT-S). Usage estimate: 80k tokens.

**Why.** 186 PRs were open on 2026-10-09: 136 drafts, 103 untouched since before 2026-10-08. Each costs every later session a look.

## Requirements

- **CONV-3-1** Every open PR is classed: **merge-ready** (green, accepted L3, no conflict), **finish** (a BOARD row in `building` or `in review` owns it and work is under 48 hours old), **parts bin** (listed as held in briefs/CODEX-1.md, or stacked on one: never closed, CODEX-1), **superseded** (its change is on main, or another PR or merged row replaced it; name which), or **stale** (none of the above, idle over 48 hours).
- **CONV-3-2** The PR adds `docs/conv-3-triage.md`: one table row per open PR with number, title, class, owning BOARD row, and one-line reason.
- **CONV-3-3** The close list (superseded + stale) is posted as question Q3 in docs/MARK-QUEUE.md. Nothing is closed by this package; L1 closes after Mark's yes, with branches kept.
- **CONV-3-4** BOARD rows owned by a stale PR return to `queued` (PR number kept in the row text).

## Acceptance

Every open PR at the run's start appears exactly once in the table (the PR states the count and the query used). No CODEX-1 held draft is classed superseded or stale. `python3 tools/doclint.py` passes.

## Scope

`docs/conv-3-triage.md` (new, add to README documents table), `docs/MARK-QUEUE.md`, `BOARD.md`, `README.md`.
