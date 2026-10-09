# CONV-2: Re-audit open BOARD rows against the release test

Board section: Harness and operating model. Decision: D-085. Tier C (BOARD.md, LATER.md only). Builder: Sonnet (PILOT-S); judgement calls go to the PR for L1. Usage estimate: 100k tokens; split by BOARD section across sessions if needed.

**Why.** On 2026-10-09, 238 BOARD rows were open and 183 of them were never audited against release/later. 80 of 83 review follow-up rows were unmerged. D-085 narrowed the release class; the existing inventory has to be measured against it once.

## Requirements

- **CONV-2-1** Every row in state `queued` or `escalated` is classed under OPERATING §2 as amended by D-085: it stays `queued` only if it names the acceptance test or invariant it serves and one failure path (add them to the row if the source review gives them); otherwise it moves to LATER.md as one line (tag `recheck` when unsure) and its BOARD state becomes `dropped (later, D-085)`.
- **CONV-2-2** Follow-up rows on follow-up rows (depth 2 or more, e.g. DEP-3-r*, DEP-6-r1, DEP-8-r1, SR3-4-f*) are `later` unless the row is a false pass on assurance tooling or an exploit path on a broker path.
- **CONV-2-3** Rows in `building` with no PR number (17 on 2026-10-09) return to `queued` unless a branch with commits exists; rows `building` or `in review` are not reclassed here (their PRs carry the decision).
- **CONV-2-4** No tier-A security finding on a broker path moves to later, and no row is deleted.

## Acceptance

The PR lists, per BOARD section: rows kept, rows moved to later (with LATER.md line), rows reset to queued. `python3 tools/doclint.py` passes. L3 (fresh session) samples 20 moved rows and confirms none is a false pass, exploit path or blocker on a cited ID.

## Scope

`BOARD.md`, `LATER.md`.
