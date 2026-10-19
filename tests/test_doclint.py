"""Tests for tools/doclint.py, the operating-document consistency check (BOARD row DOC-2).

No SPEC requirement IDs: PLAN.md tooling, not SPEC.md behaviour. DOC-7 requirement IDs
(briefs/DOC-7.md) are claimed below. The BOARD and LATER rules (DOC-5, CONV-0-5) were retired with
the generated board (SIM-repo-2b): BOARD.md is rendered from work-item issues by tools/board.py.
All data is synthetic.

REQ: DOC7-1, DOC7-2, DOC7-3, DOC7-4, DOC7-5, ASSUMPTIONS-ID-1, ASSUMPTIONS-ID-2, ASSUMPTIONS-ID-3
"""
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import doclint  # noqa: E402

GOOD = {
    "README.md": "# X\n\n## Documents\n\n| File |\n|---|\n| [BOARD.md](BOARD.md) |\n| [CLAUDE.md](CLAUDE.md) |\n"
                 "| [docs/OPERATING.md](docs/OPERATING.md) |\n\n## Other\n\n[NOTES.md](NOTES.md)\n",
    "BOARD.md": "# BOARD\n\n| ID | Package | Needs | State |\n|---|---|---|---|\n"
                "| A-1 | [a](briefs/A-1.md) | — | in review (#1) |\n",
    "CLAUDE.md": "Rules. See OPERATING §2–3 and docs/OPERATING.md §1.\n",
    "docs/OPERATING.md": "# OPERATING\n\n## 1. One\n\n## 2. Two\n\n## 3. Three\n",
    "briefs/A-1.md": "# A-1\n\n**Acceptance tests:** A-1: tests/test_a.py::test_x\n",
}

WITH_DECISIONS = GOOD["README.md"].replace("| [CLAUDE.md](CLAUDE.md) |\n", "| [CLAUDE.md](CLAUDE.md) |\n| [DECISIONS.md](DECISIONS.md) |\n")


class LintTest(unittest.TestCase):
    def lint(self, **changes):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            for name, text in {**GOOD, **changes}.items():
                if text is not None:
                    (root / name).parent.mkdir(parents=True, exist_ok=True)
                    (root / name).write_text(text)
            return doclint.lint(root)

    def test_consistent_documents_pass(self):
        self.assertEqual(self.lint(), [])

    def test_readme_must_list_every_document_and_only_existing_ones(self):
        got = self.lint(**{"LATER.md": "x", "docs/LANES.md": "x", "CLAUDE.md": None})
        self.assertEqual(got, ["README.md: Documents table does not list LATER.md",
                               "README.md: Documents table does not list docs/LANES.md",
                               "README.md: Documents table links missing CLAUDE.md"])

    def test_links_outside_the_documents_section_do_not_count(self):
        self.assertEqual(self.lint(**{"NOTES.md": "x"}), ["README.md: Documents table does not list NOTES.md"])

    def test_mnt_path_in_a_rule_file(self):
        self.assertEqual(self.lint(**{"CLAUDE.md": "ok\nsee /mnt/project-files/x.md\n"}),
                         ["CLAUDE.md:2: /mnt path; cite a repository file instead"])

    def test_operating_reference_to_a_missing_section(self):
        self.assertEqual(self.lint(**{"CLAUDE.md": "OPERATING §2–4 and OPERATING.md § 9\n"}),
                         ["CLAUDE.md:1: OPERATING §4 does not exist", "CLAUDE.md:1: OPERATING §9 does not exist"])

    def test_brief_over_the_size_cap(self):
        got = self.lint(**{"briefs/A-1.md": "**Acceptance tests:** none: x\n" + "x" * (4 * doclint.BRIEF_TOKENS)})
        self.assertEqual(got, ["briefs/A-1.md: ~20007 tokens, over the 20000 cap; split the package"])

    # DOC-4: per-file review records and unique assumption IDs

    def test_new_record_without_a_record_line(self):
        got = self.lint(**{"reviews/ux/2026-10-09-pr400.md": "# UX\n\nVerdict: accept\n"})
        self.assertEqual(got, ["reviews/ux/2026-10-09-pr400.md: no complete `Record:` line; needs `PR #N` or `PR none`, `package <ID>`, `head <7–40 lowercase hex>` (or `main <hex>`), e.g. `Record: PR #400 · package DOC-4 · head a74ee45`"])

    def test_record_line_with_a_missing_field(self):
        for line in ("Record: PR #400 · package CH-1", "Record: package CH-1 · head abc1234",
                     "Record: PR #400 · head abc1234", "Record: PR #400 · package CH-1 · head xyz"):
            got = self.lint(**{"reviews/security/2026-10-09-pr400.md": f"# S\n\n{line}\n"})
            self.assertEqual(len(got), 1, line)

    def test_complete_records_pass(self):
        files = {"reviews/ux/2026-10-09-pr400.md": "# UX\n\nRecord: PR #400 · package CH-1 · head abc1234\n",
                 "reviews/combined/2026-10-10-bundle.md":
                     "# C\n\nRecord: PRs #1 #2 · packages A-1, B-2 · heads abc1234, def5678 · main 0123456\n",
                 "reviews/security/2026-10-11-review.md": "# S\n\nRecord: PR none · package SR3 · head 7b753eb\n"}
        self.assertEqual(self.lint(**files), [])

    def test_older_files_readmes_and_other_directories_are_exempt(self):
        files = {"reviews/ux/2026-10-08-pr1.md": "# old\n", "reviews/ux/README.md": "# lens\n",
                 "notes/2026-10-09-note.md": "x"}
        self.assertEqual(self.lint(**files), [])

    def test_duplicate_assumption_id(self):
        text = "# A\n\n| ID | Assumption |\n|---|---|\n| X-U1 | a |\n| X-U2 | b |\n| X-U1 | c |\n"
        self.assertEqual(self.lint(**{"broker/x/ASSUMPTIONS.md": text}),
                         ["broker/x/ASSUMPTIONS.md:7: duplicate ID X-U1 (first on line 5)"])

    def test_distinct_assumption_ids_pass(self):
        text = "| ID | Assumption |\n|---|---|\n| X-U1 | a |\n| X-U2 | b |\n"
        self.assertEqual(self.lint(**{"broker/x/ASSUMPTIONS.md": text}), [])

    def test_hash_header_tables_and_other_tables_are_checked_only_by_id(self):
        text = "| # | A |\n|---|---|\n| P-1 | a |\n| P-1 | b |\n\n| Item | Size |\n|---|---|\n| x-y | 1 |\n| x-y | 2 |\n"
        self.assertEqual(self.lint(**{"broker/x/ASSUMPTIONS.md": text}),
                         ["broker/x/ASSUMPTIONS.md:4: duplicate ID P-1 (first on line 3)"])

    # ASSUMPTIONS-ID: package-scoped row IDs

    def test_bare_new_assumption_id_is_rejected(self):
        text = "| # | A |\n|---|---|\n| D35 | a |\n| 7 | b |\n| PKG-1 | c |\n| PKG-x-a | d |\n"
        got = self.lint(**{"tools/ASSUMPTIONS.md": text})
        self.assertEqual([g.split(" row ID ")[1].split(" ")[0] for g in got], ["D35", "7"])

    def test_legacy_bare_ids_are_allowed(self):
        text = "| # | A |\n|---|---|\n| D35 | a |\n"
        self.assertEqual(self.lint(**{"tools/ASSUMPTIONS.md": text,
                                      "tools/assumptions_legacy_ids.txt": "tools/ASSUMPTIONS.md D35\n"}), [])

    def test_legacy_list_covers_every_bare_id_on_main(self):
        import assumptions_ids
        self.assertEqual(list(assumptions_ids.check(ROOT, assumptions_ids.assumption_files(ROOT))), [])

    def test_parallel_packages_never_share_an_id(self):
        base = "| # | A |\n|---|---|\n| PKG-0-1 | x |\n"
        scoped = base + "| PKG-A-1 | a |\n| PKG-B-1 | b |\n"
        bare = base + "| D37 | a |\n"
        self.assertEqual(self.lint(**{"tools/ASSUMPTIONS.md": scoped}), [])
        self.assertEqual(len(self.lint(**{"tools/ASSUMPTIONS.md": bare})), 1)

    def test_legacy_list_may_not_grow(self):
        import assumptions_ids
        with tempfile.TemporaryDirectory() as d:
            (pathlib.Path(d) / "tools").mkdir()
            (pathlib.Path(d) / "tools/assumptions_legacy_ids.txt").write_text("# c\nf D1\nf D37\n")
            got = list(assumptions_ids.growth(d, "# c\nf D1\n"))
        self.assertEqual(len(got), 1)
        self.assertIn("f D37", got[0])
        self.assertEqual(list(assumptions_ids.growth(ROOT, (ROOT / "tools/assumptions_legacy_ids.txt").read_text())), [])

    def test_duplicate_decision_id(self):
        text = "# D\n\n| ID | Date | Status | Decision | Source |\n|---|---|---|---|---|\n" \
               "| D-001 | x | active | a | m |\n| D-claude2-001 | x | active | b | m |\n| D-001 | x | active | c | m |\n"
        self.assertEqual(self.lint(**{"DECISIONS.md": text, "README.md": WITH_DECISIONS}), ["DECISIONS.md:7: duplicate ID D-001 (first on line 5)"])

    def test_per_team_sections_with_distinct_ids_pass(self):
        text = "| ID | Decision |\n|---|---|\n| D-001 | a |\n\n## claude2\n\n| ID | Decision |\n|---|---|\n| D-claude2-001 | b |\n"
        self.assertEqual(self.lint(**{"DECISIONS.md": text, "README.md": WITH_DECISIONS}), [])

    # DOC-7: records sweep

    def test_record_without_pr_or_package_may_cite_a_main_commit(self):
        files = {"reviews/security/2026-10-09-sweep.md": "# S\n\nRecord: PR none · package none · main 0123abc\n"}
        self.assertEqual(self.lint(**files), [])

    def test_record_head_must_be_lowercase_hex(self):
        got = self.lint(**{"reviews/ux/2026-10-09-pr1.md": "# U\n\nRecord: PR #1 · package A-1 · head ABC1234\n"})
        self.assertEqual(len(got), 1)
        self.assertIn("lowercase hex", got[0])

    def test_scratch_note_without_a_date_is_exempt_only_outside_lens_directories(self):
        self.assertEqual(self.lint(**{"notes/pr500.md": "x"}), [])

    def test_non_readme_lens_file_needs_a_dated_name(self):
        got = self.lint(**{"reviews/ux/pr500.md": "# U\n"})
        self.assertEqual(got, ["reviews/ux/pr500.md: lens record names start `YYYY-MM-DD-`"])

    def test_record_line_must_follow_the_title(self):
        text = "# U\n\nVerdict: accept\n\nRecord: PR #1 · package A-1 · head abc1234\n"
        got = self.lint(**{"reviews/ux/2026-10-09-pr1.md": text})
        self.assertEqual(len(got), 1)
        self.assertIn("directly under the title", got[0])

    def test_record_line_may_follow_a_title_that_follows_the_verdict(self):
        text = "Verdict: accept\n\n# U\n\nRecord: PR #1 · package A-1 · head abc1234\n"
        self.assertEqual(self.lint(**{"reviews/ux/2026-10-09-pr1.md": text}), [])

    def test_new_lens_directory_is_checked(self):
        got = self.lint(**{"reviews/ops/2026-10-09-pr1.md": "# O\n"})
        self.assertEqual(len(got), 1)
        self.assertIn("reviews/ops/2026-10-09-pr1.md", got[0])

    def test_untracked_scratch_record_is_not_checked_in_a_git_repo(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            for name, text in GOOD.items():
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_text(text)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            subprocess.run(["git", "add", "-A"], cwd=root, check=True)
            (root / "reviews/ux").mkdir(parents=True)
            (root / "reviews/ux/2026-10-09-scratch.md").write_text("# scratch\n")
            self.assertEqual(doclint.lint(root), [])

    DECISIONS = ("# DECISIONS\n\n| ID | Date | Status | Decision | Source |\n|---|---|---|---|---|\n"
                 "| D-001 | 2026-10-04 | active | %s | Mark |\n")

    LISTED = {"README.md": GOOD["README.md"].replace("| [CLAUDE.md]", "| [DECISIONS.md](DECISIONS.md) |\n| [CLAUDE.md]")}

    def test_decision_cell_over_300_characters_needs_a_resolving_link(self):
        long = "x" * 301
        got = self.lint(**{"DECISIONS.md": self.DECISIONS % long, **self.LISTED})
        self.assertEqual(got, ["DECISIONS.md: D-001: Decision cell is 301 characters; keep it to 300 or link decisions/D-001.md (D-056)"])
        linked = self.DECISIONS % (long + " ([full](decisions/D-001.md))")
        self.assertEqual(self.lint(**{"DECISIONS.md": linked, "decisions/D-001.md": "# D-001\n", **self.LISTED}), [])
        self.assertEqual(self.lint(**{"DECISIONS.md": linked, **self.LISTED}),
                         ["DECISIONS.md: D-001: links missing decisions/D-001.md"])

    def test_short_decision_passes_and_escaped_pipes_do_not_split_cells(self):
        text = self.DECISIONS % "a \\| b"
        self.assertEqual(self.lint(**{"DECISIONS.md": text, **self.LISTED}), [])

    def test_brief_with_its_own_state_line(self):
        got = self.lint(**{"briefs/A-1.md": "# A-1\n\n**State:** building\n**Acceptance tests:** none: docs\n"})
        self.assertEqual(got, ["briefs/A-1.md:3: `**State:**` line; state lives on the work-item issue"])

    # REQ: FIRST-PASS
    def test_brief_without_acceptance_tests_fails(self):
        got = self.lint(**{"briefs/A-1.md": "# A-1\n\nGoal.\n"})
        self.assertEqual(got, ["briefs/A-1.md: no `**Acceptance tests:**` line; name each ID's test up front, or `none: <why>`"])

    def test_brief_in_the_baseline_may_lack_acceptance_tests(self):
        self.assertEqual(self.lint(**{"briefs/A-1.md": "# A-1\n", "tools/brief_acceptance_baseline.txt": "A-1.md\n"}), [])

    # REQ: FIRST-PASS
    def test_baselined_brief_that_has_its_line_must_leave_the_baseline(self):
        got = self.lint(**{"tools/brief_acceptance_baseline.txt": "A-1.md\n"})
        self.assertEqual(got, ["tools/brief_acceptance_baseline.txt: A-1.md now has its acceptance tests; delete the entry (the baseline only shrinks)"])

    # REQ: FIRST-PASS
    def test_baseline_entry_for_a_missing_brief_fails(self):
        got = self.lint(**{"tools/brief_acceptance_baseline.txt": "A-1.md\nGone.md\n"})
        self.assertEqual([g for g in got if "Gone.md" in g],
                         ["tools/brief_acceptance_baseline.txt: Gone.md has no brief; delete the entry (the baseline only shrinks)"])

    # REQ: FIRST-PASS
    def test_empty_acceptance_line_fails(self):
        for text in ("# A-1\n\n**Acceptance tests:**\n", "# A-1\n\n**Acceptance tests:**   \n",
                     "# A-1\n\n**Acceptance tests:**\t\n", "# A-1\n\n**Acceptance tests:**\n\nGoal.\n",
                     "# A-1\n\n- **Acceptance tests:**\n- **Goal:** x\n"):
            self.assertEqual(self.lint(**{"briefs/A-1.md": text}),
                             ["briefs/A-1.md: empty `**Acceptance tests:**` line; name each ID's test, or `none: <why>`"])

    # REQ: FIRST-PASS
    def test_acceptance_tests_as_a_list_pass(self):
        for text in ("# A-1\n\n**Acceptance tests:**\n- `tests/x.py::a`: catches y\n",
                     "# A-1\n\n**Acceptance tests:**\n\n* `tests/x.py::a`\n",
                     "# A-1\n\n**Acceptance tests:**\n1. `tests/x.py::a`\n",
                     "# A-1\n\n- **Acceptance tests:**\n  - `tests/x.py::a`\n"):
            self.assertEqual(self.lint(**{"briefs/A-1.md": text}), [], text)

    # REQ: FIRST-PASS
    def test_acceptance_heading_and_short_marker_forms_are_recognised(self):
        for text in ("# A-1\n\n## Acceptance tests\n\n- `tests/x.py::a`\n",
                     "# A-1\n\n## Acceptance tests\n\nPlain text naming `tests/x.py::a`.\n",
                     "# A-1\n\n**Acceptance:** `tests/x.py::a`\n",
                     "# A-1\n\n**Acceptance:**\n- `tests/x.py::a`\n"):
            self.assertEqual(self.lint(**{"briefs/A-1.md": text}), [], text)

    # REQ: FIRST-PASS
    def test_empty_heading_or_short_marker_fails(self):
        for text in ("# A-1\n\n## Acceptance tests\n\n## Next\n- `x`\n", "# A-1\n\n## Acceptance tests\n",
                     "# A-1\n\n**Acceptance:**\n"):
            self.assertEqual(len(self.lint(**{"briefs/A-1.md": text})), 1, text)

    # REQ: FIRST-PASS
    def test_empty_marker_before_an_unrelated_list_item_is_empty(self):
        for text in ("# A-1\n\n**Acceptance tests:**\n\n- **Scope:** tools/x.py\n",
                     "# A-1\n\n**Acceptance tests:**\n\n**Scope:** tools/x.py\n"):
            self.assertEqual(self.lint(**{"briefs/A-1.md": text}),
                             ["briefs/A-1.md: empty `**Acceptance tests:**` line; name each ID's test, or `none: <why>`"], text)

    # REQ: FIRST-PASS
    def test_table_or_plain_text_under_the_marker_is_not_empty(self):
        for text in ("# A-1\n\n**Acceptance tests:**\n| ID | Test |\n|---|---|\n| A-1 | tests/x.py::a |\n",
                     "# A-1\n\n**Acceptance tests:**\n\n| ID | Test |\n|---|---|\n",
                     "# A-1\n\n**Acceptance tests:**\nEach ID is covered by tests/x.py.\n"):
            self.assertEqual(self.lint(**{"briefs/A-1.md": text}), [], text)

    # REQ: FIRST-PASS
    def test_baselined_brief_with_a_listed_acceptance_test_must_leave_the_baseline(self):
        got = self.lint(**{"briefs/A-1.md": "# A-1\n\n**Acceptance tests:**\n- `tests/x.py::a`\n",
                           "tools/brief_acceptance_baseline.txt": "A-1.md\n"})
        self.assertEqual(got, ["tools/brief_acceptance_baseline.txt: A-1.md now has its acceptance tests; delete the entry (the baseline only shrinks)"])

    def test_base_baseline_without_a_value_is_a_usage_error(self):
        r = subprocess.run([sys.executable, str(ROOT / "tools/doclint.py"), "--base-baseline"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertIn("usage: doclint.py", r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    # REQ: FIRST-PASS
    def test_baseline_growth_against_the_base_copy(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "tools").mkdir()
            (root / "tools/brief_acceptance_baseline.txt").write_text("A-1.md\nB-2.md\n")
            base = root / "base.txt"
            base.write_text("A-1.md\n")
            self.assertEqual(list(doclint.baseline_growth(root, base)),
                             ["tools/brief_acceptance_baseline.txt: B-2.md is new in the baseline; the baseline only shrinks, so name the brief's acceptance tests instead"])
            base.write_text("A-1.md\nB-2.md\nC-3.md\n")
            self.assertEqual(list(doclint.baseline_growth(root, base)), [])

    def test_main_files_pass(self):
        self.assertEqual(doclint.lint(ROOT), [])


class AssumptionsUnionMerge(unittest.TestCase):
    """ASSUMPTIONS-MERGE: two PRs appending a row to one table merge locally; doclint flags a clash."""

    def git(self, cwd, *args):
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                       cwd=cwd, check=True, capture_output=True)

    def test_appended_rows_merge_and_duplicate_id_is_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / ".gitattributes").write_text((ROOT / ".gitattributes").read_text())
            f = root / "ASSUMPTIONS.md"
            f.write_text("| # | Assumption |\n|---|---|\n| X-U1 | a |\n")
            self.git(d, "init", "-q", "-b", "main")
            self.git(d, "add", "-A")
            self.git(d, "commit", "-qm", "base")
            self.git(d, "checkout", "-qb", "pr")
            f.write_text(f.read_text() + "| X-U2 | from pr |\n")
            self.git(d, "commit", "-qam", "pr")
            self.git(d, "checkout", "-q", "main")
            f.write_text(f.read_text() + "| X-U2 | from main |\n")
            self.git(d, "commit", "-qam", "main")
            self.git(d, "checkout", "-q", "pr")
            self.git(d, "merge", "-q", "--no-edit", "main")
            self.assertEqual(f.read_text().count("| X-U2 |"), 2)
            self.assertEqual(list(doclint.assumption_ids(root, ["ASSUMPTIONS.md"])),
                             ["ASSUMPTIONS.md:5: duplicate ID X-U2 (first on line 4)"])


if __name__ == "__main__":
    unittest.main()
