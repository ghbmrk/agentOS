# MUT-wipe-lint: a lint that each derived key buffer in broker/recovery is wiped

Board row: #5865 (tier B, lane:primary, class:release). Source: Security's accept on #5857 (comment 6898822296). Usage estimate: 30k tokens.

## Requirement
- **CRED-1 wipe lint:** in the non-test .go files of `broker/recovery`, a local assigned from `hkdf(...)`, `random(...)` or a `decrypt` call is passed to `wipe(name)` or `defer wipe(name)` later in the same function, or returned as a bare operand. Mutation testing cannot see a dropped wipe, so `defer wipe(k)` deleted after an HKDF passes every test and mutgate (#5857).

## Design
- A token pass in `tools/srclint.py` (`wipe_problems`), run on the files under `WIPE_DIRS`. It reuses srclint's tokenizer; no new component.
- A finding has the kind `wipe:FUNC:VAR`. An allow line in `tools/srclint_allow.txt` names that kind and a reason; a kind no longer found is stale, as for the other kinds.
- Existing sites: the sites #5857 names (backupPrivate, ensureMACKey, newSeed) are wiped and pass. Six sites hold public or non-secret bytes and get allow entries with reasons (bundle.go, confirm.go, forgetlog.go, owner.go, rotate.go).
- Bound, stated in the docstring: a buffer held in a field, a composite literal or a call argument, a wipe of the wrong buffer, and a wipe behind a branch are not seen.

## Scope (files)
- In scope: `tools/srclint.py`, `tools/srclint_allow.txt`, `tests/test_srclint.py`, this brief.
- Out of scope: any `broker/` file (old core, frozen); other vault-side packages (add to `WIPE_DIRS` when a row names one); `tools/ASSUMPTIONS.md`.

## Acceptance tests
**Acceptance tests:** `test_wipe_lint_fails_a_dropped_defer_wipe` (fixture without `defer wipe(k)` fails), `test_main_is_clean` (the current tree passes), `test_wipe_lint_passes_a_wiped_or_returned_buffer`, `test_wipe_lint_sees_random_and_decrypt_and_other_names_only`, `test_wipe_lint_wipe_in_another_function_does_not_count`, `test_wipe_lint_a_buffer_inside_a_returned_call_is_not_returned`, `test_wipe_allow_line_names_function_and_variable`.
