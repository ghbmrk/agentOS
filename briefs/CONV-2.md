# CONV-2: Re-audit open BOARD rows against the release test and the G1/G2 test

Board section: Harness and operating model. Decisions: D-086, D-098. Tracked under issue #752. Tier C (BOARD.md, LATER.md only). Builder: Sonnet (PILOT-S); judgement calls go to the PR for L1. Usage estimate: 100k tokens; split by BOARD section across sessions if needed.

**Why.** On 2026-10-09, 238 BOARD rows were open and 183 of them were never audited against release/later. 80 of 83 review follow-up rows were unmerged. D-086 narrowed the release class; D-098 then asked that every queued row be re-filed against a G1 or G2 test (LATER line FRZ-refile). Both ask for a pass over the same rows, so this brief absorbs FRZ-refile: one inventory and evidence pass applies both tests to each row.

**Current count.** On main at 116b4b8 (2026-10-12), 223 rows are `queued` and none is `escalated` (counted with `tools/metrics.py` `board_states`). 30 of them are already frozen under D-098 (`queued (frozen until G2, LATER FRZ-x, D-098)`). Recount on the PR's base before starting and put that count in the PR.

**Not a deferral rule.** Consolidating the two passes changes only how the work is done. It does not by itself authorize deferring any feature: a row moves to LATER only by failing the tests in CONV-2-1 and CONV-2-5 below, row by row, with the evidence recorded.

## Requirements

- **CONV-2-1** Every row in state `queued` or `escalated` is classed under OPERATING §2 as amended by D-086: it stays `queued` only if it names the acceptance test or invariant it serves and one failure path (add them to the row if the source review gives them); otherwise it moves to LATER.md as one line (tag `recheck` when unsure) and its BOARD state becomes `dropped (later, D-086)`.
- **CONV-2-2** Follow-up rows on follow-up rows (depth 2 or more, e.g. DEP-3-r*, DEP-6-r1, DEP-8-r1, SR3-4-f*) are `later` unless the row is a false pass on assurance tooling or an exploit path on a broker path.
- **CONV-2-3** Rows in `building` with no PR number (17 on 2026-10-09) return to `queued` unless a branch with commits exists; rows `building` or `in review` are not reclassed here (their PRs carry the decision).
- **CONV-2-4** No tier-A security finding on a broker path moves to later, and no row is deleted.
- **CONV-2-5** (D-098, absorbs FRZ-refile) In the same pass, every row CONV-2-1 keeps also names the G1 or G2 acceptance test it serves (G1 = A1; G2 = A4, A5, A9, A14; SPEC §15). A row that serves neither moves to LATER.md as one line tagged `recheck`, and its BOARD state becomes `dropped (later, D-098)`. CONV-2-4 still wins: a tier-A security finding on a broker path stays queued and the PR says so. A row already frozen under D-098 keeps its state and its FRZ line; the inventory records it as such.
- **CONV-2-6** One inventory and evidence pass, tracked under issue #752. Every work-item ID present at the start appears in the PR's inventory with its outcome; none is dropped from the record.

## Acceptance

The PR lists, per BOARD section: rows kept (with the A-test or invariant, the failure path and the G1 or G2 test), rows moved to later (with the LATER.md line and which test it failed, D-086 or D-098), rows reset to queued, and frozen rows left as they are. It gives the start count and the end count of `queued` and `escalated` rows and the commit counted. `python3 tools/doclint.py` and `python3 tools/board.py check` pass. L3 (a fresh session, independent of the builder) samples 20 moved rows and confirms none is a false pass, exploit path, tier-A broker security finding or blocker on a cited ID. The PR claims no measured usage or token savings.

## Scope

`BOARD.md`, `LATER.md`.
