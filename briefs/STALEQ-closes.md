# STALEQ-closes: stalequeued counts a merged PR as finishing a row only when it closes the row's issue

Board section: Harness and operating model. Source: coordinator relay 2026-10-17 (INFER-SVC #2217 via #2223, S8-W1-box-fu1 #1898 via #1899, FUZZ-broker #1813 via #2149 were flagged done and are not). Tier: C. Builder: Sonnet. Usage estimate: 40k tokens.

**Why.** `tools/stalequeued.py` treats an ID-prefixed title or a `Record:` line as proof the row is done. A prep PR, a title that shares a prefix, or a partial PR with follow-ups all match, so a dispatcher skips live rows.

## Requirements

- **STALEQ-1** A merged PR finishes a row when its body has `Closes|Fixes|Resolves #N` (any case, with or without a colon) for the row's own issue number N (`#N1` is not `#N`). The report line says `closes`.
- **STALEQ-2** A merged PR that only names the package (ID-prefixed title or `Record:` line) is reported as `maybe` with the reason shown (`maybe: title match, does not close #N`), never as done.
- **STALEQ-3** An open PR that names the package still suppresses the row, as before. Exit stays 0 and the tool still only GETs.

**Acceptance tests:** `tests/test_stalequeued.py`: STALEQ-1 `test_closing_reference_finishes_the_row`, `test_closing_reference_is_for_this_issue_only`; STALEQ-2 `test_name_only_matches_are_maybe_with_reason` (INFER-SVC, S8-W1-box-fu1, FUZZ-broker shapes); STALEQ-3 `test_main_prints_rows_and_only_reads`.

## Scope

`tools/stalequeued.py`, `tests/test_stalequeued.py`, this brief.

## Done

CI green; the tests above pass.
