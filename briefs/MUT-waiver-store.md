# MUT-waiver-store: keep accepted Mutant-equivalent proofs in a statement-keyed record

Board section: Defects and later findings on surviving packages. Work item #5776, a release finding on #5743 (CLK-run-signin-ctx, L3 delta 6882556829). Tier A gate file: the separate Security accept is owed.

**Requirement:** MUT-tierA (#1814, #4908). Local ID **MUT-waiver-store**: a deletion mutant a reviewer has accepted as equivalent once does not fail a later PR's mutgate run, and a waiver never applies to a statement it was not written for.

**Build.** `broker/<pkg>/MUTANTS-EQUIVALENT`, one JSON entry per proof, keyed by file, enclosing declaration, the statement's own lines, the code line before it, and occurrence i of n (see `RECORD` in `tools/mutgate.py`). `verify` and `gate` resolve each claimed package's entries at the head and fail on a stale one; body lines still work. `mutgate.py waive FILE --accepted '#PR'` writes body-format lines into records; `mutgate.py records` resolves them. The 27 #5743 proofs move into `broker/clerk/run/MUTANTS-EQUIVALENT`, written at #5743's reviewed head eefb2848.

**Scope:** `tools/mutgate.py`, `tests/test_mutgate.py`, `tools/ASSUMPTIONS.md` (one row), `broker/clerk/run/MUTANTS-EQUIVALENT`, this brief.

**Out of scope:** #5779's items.

**Acceptance tests:**
- MUT-waiver-store: `tests/test_mutgate.py::Record::test_a_record_entry_waives_its_site_with_no_body_line`, `::test_an_entry_follows_its_statement_when_lines_move_above_it`, `::test_an_edited_or_deleted_statement_is_stale`, `::test_a_stale_entry_fails_the_gate`, `::test_twins_are_told_apart_by_occurrence`, `::test_a_multi_line_statement_is_keyed_by_every_line_of_its_own_syntax`, `::test_a_malformed_or_linked_record_fails`, `::test_the_clerk_run_record_holds_the_5743_proofs`, `::test_every_record_in_the_repository_resolves`

**Done:** CI green; the tests pass, and fail on the base's `mutgate.py`.
