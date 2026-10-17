# DOCLINT-accept: doclint's acceptance-tests check

Work item: #1839 (tier C). Scope: tools/doclint.py, tests/test_doclint.py, tools/brief_acceptance_baseline.txt. The trusted-base copy fix touches .github/workflows/ci.yml, which is Mark-gated, so it is a separate PR.

**Acceptance tests:**
- `tests/test_doclint.py::LintTest::test_acceptance_heading_and_short_marker_forms_are_recognised`: `## Acceptance tests` and `**Acceptance:**` count.
- `tests/test_doclint.py::LintTest::test_empty_heading_or_short_marker_fails`: an empty heading or short marker is reported.
- `tests/test_doclint.py::LintTest::test_empty_marker_before_an_unrelated_list_item_is_empty`: a sibling `**Label:**` field after an empty marker is not content.
- `tests/test_doclint.py::LintTest::test_table_or_plain_text_under_the_marker_is_not_empty`: a table or text directly under the marker is not reported empty.
- `tests/test_doclint.py::LintTest::test_main_files_pass`: the baseline drops the entries the new forms now satisfy.
