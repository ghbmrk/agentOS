# MUT-record-deps-audit: every record entry that cites an outside declaration names it in deps, and a lint keeps it so

Board row: #6499 (tier A, lane:primary, class:release). Source: L3 on #6498 (comment 7072616648). Usage estimate: 120k tokens.

## Requirement
- **MUT-record-deps-audit:** a `MUTANTS-EQUIVALENT` entry whose reason names, as code, a top-level declaration of its own package other than its own declaration carries that name in `deps` (MUT-record-deps, #6282), so an edit to the cited declaration stales the proof. Without it, an edit to `parseTracking` (or any such declaration) leaves the proof false while `records` resolves it with rc 0.

## Design
- `cited_names(reason)`: the identifiers a reason names as code: inside a backtick span, followed by `(` or `{`, or shaped as code (an uppercase letter, digit or `_` after the first character). A dotted `X.Y` names the method `X.Y`, else `X` alone; `Y` is a member (field, foreign method, imported name), never a package name. A `name.go` is a file, not a name. Plain lowercase prose words (`read`, `call`, `pair`) are not citations.
- `undeclared_deps(pkg, entries, decls)`: for each entry, each cited name declared in a non-test `.go` file of its package by a declaration other than the entry's own, with no dep naming it. Problems name the `waive --dep broker/<pkg>/<file>:<name>` to add.
- `record_waivers` (so `gate`, `verify` and `records`) fails on each; `waive` refuses to write a new entry that cites one without the `--dep`.
- Audit: every entry the lint flags on main is re-recorded with `waive --dep`, `--accepted` its original PR and its reason unchanged, so `accepted` still names the review that read the proof. Entries whose reason names an outside declaration only in prose were read by hand; those found resting on one are re-recorded the same way and listed in the PR.
- Bound (docstring): a citation in plain prose, one to another package, or to the standard library is not seen; review still reads each reason against its `deps` (MUT-record-deps-1).

## Scope (files)
- In scope: `tools/mutgate.py`, `tests/test_mutgate.py`, `tools/ASSUMPTIONS.md` (one row), every `broker/**/MUTANTS-EQUIVALENT`, this brief.
- Out of scope: any `.go` file; the gate workflow.

## Acceptance tests
**Acceptance tests:** `tests/test_mutgate.py::RecordDepsLint::test_an_entry_citing_another_function_without_deps_fails_and_with_its_dep_passes`, `::test_waive_refuses_a_cited_name_without_its_dep`, `::test_prose_members_files_and_the_own_declaration_are_not_citations`, `::test_a_dep_in_any_file_declaring_the_name_satisfies_it`, `::test_a_helper_in_the_entry_s_own_file_is_cited`, `::test_a_package_file_the_lister_cannot_read_fails_the_record`, `Record::test_every_record_in_the_repository_resolves`.

**Done:** CI green; the tests pass, and the first two fail on the base's `mutgate.py`.
