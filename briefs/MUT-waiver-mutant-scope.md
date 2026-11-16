# MUT-waiver-mutant-scope: a waiver waives the one mutant it proves

Board section: Defects and later findings on surviving packages. Work item #5792, a release finding from Security on #5774 (comment 6889268267), the same class as seen on #5780. Tier A gate file: the separate Security accept is owed.

**Requirement:** MUT-tierA (#1814, #4908), REV-PROOF-mut. Local ID **MUT-waiver-mutant-scope**: a `Mutant-equivalent:` body line or a `MUTANTS-EQUIVALENT` record entry waives only the mutant it proves. A line with several mutants in a waiver's scope (#5774's `broker/clerk/run/mail.go:144`, three CONDITIONALS_BOUNDARY mutants) no longer lets one proof waive the others.

**Build.** A waiver is keyed (path, line, kind, col). A record entry always names its kind and may name `col`, the mutant's column as the result gives it. A body line may name both, as `Mutant-equivalent: <path>:<line>[:<col>][:<KIND>] <reason>`. A waiver matches each mutant of the result on its line whose kind and column it names or leaves open. It waives a mutant only when that mutant is the only one it matches, whatever the other mutants' verdicts. One that matches several waives none of them, and the gate and the summary name each such waiver with the columns and kinds that would tell its mutants apart (`covering`, `violations`, `decide`, `summary` in `tools/mutgate.py`). `waive` writes `col` and the kind from a body line, and refuses a column past the end of its line or a kind that differs from `--mutant`. `records` prints `path:line:col` for an entry that names a column. The four clerk/run entries on `mail.go:103` and `:144`, both lines with several comparisons, gain their column in a follow-up PR, the column of the `>= 0` and `< 0` they prove (102 and 113, gremlins' `OpPos` column), because the gate runs the base's `tools/mutgate.py`, which refuses a record key it does not know. Their reasons are unchanged.

**Scope:** `tools/mutgate.py`, `tests/test_mutgate.py`, `tools/ASSUMPTIONS.md` (one row), `broker/clerk/run/MUTANTS-EQUIVALENT` (`col` on four entries, follow-up PR), this brief.

**Out of scope:** #5779's items (the NOT COVERED rule scope is the pending mutgate decision). A `Mutant-uncovered:` alias is also out of scope.

**Acceptance tests:**
- MUT-waiver-mutant-scope: `tests/test_mutgate.py::MutantScope::test_a_two_comparison_line_with_one_proved_mutant_fails_on_the_other` (the issue's test: one proved mutant and one live one on a two-comparison line, and the gate fails), `::test_the_body_line_names_a_column_and_kind`, `::test_verify_waives_only_the_named_mutant`, `::test_a_record_entry_with_a_column_waives_that_mutant_only`, `::test_a_record_column_is_a_positive_integer`, `::test_the_clerk_run_entries_on_two_comparison_lines_name_their_column` (follow-up PR), and the existing `Record` and `Equivalent` tests.

**Done:** CI green. The tests pass, and the first test fails on the base's `mutgate.py`.
