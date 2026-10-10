"""Tests for tools/doclint.py, the operating-document consistency check (BOARD row DOC-2).

No SPEC requirement IDs: PLAN.md tooling, not SPEC.md behaviour. DOC-7 requirement IDs
(briefs/DOC-7.md) are claimed below; CONV0Test claims the CONV-0 brief's IDs (briefs/CONV-0.md).
All data is synthetic.

REQ: DOC7-1, DOC7-2, DOC7-3, DOC7-4, DOC7-5, DOC5-a, DOC5-b, DOC5-c, DOC5-d
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
    "briefs/A-1.md": "# A-1\n",
}


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

    def test_board_state_outside_the_enum(self):
        board = GOOD["BOARD.md"].replace("in review (#1)", "reviewing")
        self.assertEqual(self.lint(**{"BOARD.md": board}),
                         ["BOARD.md: A-1: state 'reviewing' does not start with one of "
                          "queued, building, in review, merged, escalated, dropped"])

    def test_board_links_a_missing_brief(self):
        self.assertEqual(self.lint(**{"briefs/A-1.md": None}), ["BOARD.md: A-1: links missing briefs/A-1.md"])

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
        got = self.lint(**{"briefs/A-1.md": "x" * (4 * doclint.BRIEF_TOKENS + 4)})
        self.assertEqual(got, ["briefs/A-1.md: ~20001 tokens, over the 20000 cap; split the package"])

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
        text = "# A\n\n| ID | Assumption |\n|---|---|\n| U1 | a |\n| U2 | b |\n| U1 | c |\n"
        self.assertEqual(self.lint(**{"broker/x/ASSUMPTIONS.md": text}),
                         ["broker/x/ASSUMPTIONS.md:7: duplicate ID U1 (first on line 5)"])

    def test_distinct_assumption_ids_pass(self):
        text = "| ID | Assumption |\n|---|---|\n| U1 | a |\n| U2 | b |\n"
        self.assertEqual(self.lint(**{"broker/x/ASSUMPTIONS.md": text}), [])

    def test_hash_header_tables_and_other_tables_are_checked_only_by_id(self):
        text = "| # | A |\n|---|---|\n| 1 | a |\n| 1 | b |\n\n| Item | Size |\n|---|---|\n| x | 1 |\n| x | 2 |\n"
        self.assertEqual(self.lint(**{"broker/x/ASSUMPTIONS.md": text}),
                         ["broker/x/ASSUMPTIONS.md:4: duplicate ID 1 (first on line 3)"])


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
        got = self.lint(**{"briefs/A-1.md": "# A-1\n\n**State:** building\n"})
        self.assertEqual(got, ["briefs/A-1.md:3: `**State:**` line; BOARD.md is the only record of state"])


HEAD = "| ID | Package | Needs | State |\n|---|---|---|---|\n"


class CONV0Test(unittest.TestCase):
    """REQ CONV-0-5 (a BOARD row added on or after 2026-10-10 whose state says `release`
    must name an acceptance test or invariant)."""
    ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid", "PATH": "/usr/bin:/bin"}

    def repo(self, history, spec="Requirements DEP-1 and CRED-4 are normative.\n"):
        """history: [(commit date, BOARD.md rows added)]; returns lint problems for the final tree."""
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            git = lambda *a, date: subprocess.run(["git", "-C", d, *a], check=True, capture_output=True,
                                                 env={**self.ENV, "GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date})
            git("init", "-q", "-b", "main", date="2026-10-01T00:00:00-04:00")
            readme = GOOD["README.md"].replace("| [BOARD.md](BOARD.md) |", "| [BOARD.md](BOARD.md) |\n| [SPEC.md](SPEC.md) |")
            for name, text in {**GOOD, "README.md": readme, "SPEC.md": spec}.items():
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_text(text)
            rows = ""
            for date, add in history:
                rows += add
                (root / "BOARD.md").write_text(HEAD + "| A-1 | [a](briefs/A-1.md) | — | in review (#1) |\n" + rows)
                git("add", ".", date=date)
                git("commit", "-qm", "x", date=date)
            return doclint.lint(root)

    def test_new_release_row_without_a_test_or_invariant_is_flagged(self):
        got = self.repo([("2026-10-10T09:00:00-04:00", "| N-1 | thing (release, tier A) | — | queued (release) |\n")])
        self.assertEqual(len(got), 1)
        self.assertIn("BOARD.md: N-1", got[0])
        self.assertIn("acceptance test or invariant", got[0])

    def test_new_release_row_naming_a_spec_id_invariant_or_test_passes(self):
        rows = ("| N-1 | thing (release; CRED-4) | — | queued |\n"
                "| N-2 | thing | — | queued (release, Invariant 3) |\n"
                "| N-3 | thing (release, TestNoThirdPersonSelfReference) | — | queued |\n")
        self.assertEqual(self.repo([("2026-10-10T09:00:00-04:00", rows)]), [])

    def test_a_token_that_is_not_a_spec_id_does_not_count_and_the_row_id_is_ignored(self):
        rows = ("| DEP-1 | thing (release, A9, UX3-1) | — | queued |\n")
        self.assertEqual(len(self.repo([("2026-10-10T09:00:00-04:00", rows)])), 1)

    def test_older_rows_are_exempt_and_only_the_adding_commit_counts(self):
        row = "| O-1 | old (release, tier A) | — | queued (release) |\n"
        self.assertEqual(self.repo([("2026-10-09T23:00:00-04:00", row),
                                    ("2026-10-12T09:00:00-04:00", "| N-2 | plain | — | queued |\n")]), [])

    def test_a_row_merged_in_from_main_keeps_the_date_it_first_landed(self):
        # REQ: CONV-0-5. A branch that merges main must not date main's older rows by the merge commit.
        row = "| O-1 | old (release, tier A) | — | queued (release) |\n"
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            def git(*a, date):
                subprocess.run(["git", "-C", d, *a], check=True, capture_output=True,
                               env={**self.ENV, "GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date})
            git("init", "-q", "-b", "main", date="2026-10-01T00:00:00-04:00")
            readme = GOOD["README.md"].replace("| [BOARD.md](BOARD.md) |", "| [BOARD.md](BOARD.md) |\n| [SPEC.md](SPEC.md) |")
            for name, text in {**GOOD, "README.md": readme, "SPEC.md": "x\n"}.items():
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_text(text)
            board = HEAD + "| A-1 | [a](briefs/A-1.md) | — | in review (#1) |\n"
            (root / "BOARD.md").write_text(board)
            git("add", ".", date="2026-10-01T00:00:00-04:00")
            git("commit", "-qm", "base", date="2026-10-01T00:00:00-04:00")
            git("checkout", "-qb", "feat", date="2026-10-01T00:00:00-04:00")
            (root / "note.txt").write_text("n")
            git("add", ".", date="2026-10-11T09:00:00-04:00")
            git("commit", "-qm", "feat", date="2026-10-11T09:00:00-04:00")
            git("checkout", "-q", "main", date="2026-10-09T09:00:00-04:00")
            (root / "BOARD.md").write_text(board + row)
            git("add", ".", date="2026-10-09T09:00:00-04:00")
            git("commit", "-qm", "row", date="2026-10-09T09:00:00-04:00")
            git("checkout", "-q", "feat", date="2026-10-12T09:00:00-04:00")
            git("merge", "-q", "--no-ff", "-m", "merge main", "main", date="2026-10-12T09:00:00-04:00")
            self.assertEqual(doclint.lint(root), [])

    def test_rows_that_do_not_say_release_are_not_checked(self):
        self.assertEqual(self.repo([("2026-10-11T09:00:00-04:00", "| N-1 | the first release needs it | — | queued |\n")]), [])

    def test_no_git_history_skips_the_check(self):
        # The fixture directory used by the other tests is not a git repository.
        board = GOOD["BOARD.md"] + "| N-1 | thing (release) | — | queued (release) |\n"
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            for name, text in {**GOOD, "BOARD.md": board}.items():
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_text(text)
            self.assertEqual(doclint.lint(root), [])



README = GOOD["README.md"].replace("| [BOARD.md](BOARD.md) |\n", "| [BOARD.md](BOARD.md) |\n| [LATER.md](LATER.md) |\n")


class Doc5Test(unittest.TestCase):
    """DOC-5: BOARD and LATER contradictions."""
    lint = LintTest.lint

    LATER = ("# LATER\n\n| ID | Needed for | Note |\n|---|---|---|\n{rows}\n"
             "| ID | Why it can wait |\n|---|---|\n| Z-9 | fine |\n")

    def later(self, rows, merged="merged"):
        board = GOOD["BOARD.md"].replace("in review (#1)", merged) + "| B-2 | b | — | queued |\n"
        return self.lint(**{"BOARD.md": board, "LATER.md": self.LATER.format(rows=rows),
                            "README.md": README})

    def test_later_row_for_a_merged_board_row(self):
        self.assertEqual(self.later("| A-1 | x | y |"),
                         ["LATER.md: A-1: the BOARD row is merged; remove the LATER row"])
        self.assertEqual(self.later("| A-1 | x | y |", merged="dropped"),
                         ["LATER.md: A-1: the BOARD row is dropped; remove the LATER row"])

    def test_later_row_sharing_an_open_board_id_passes(self):
        self.assertEqual(self.later("| B-2 | x | y |", merged="merged"), [])

    def test_later_finding_suffix_is_not_checked_against_the_parent(self):
        self.assertEqual(self.later("| A-1 l1 | x | y |"), [])

    def test_later_second_table_is_checked_too(self):
        later = "# LATER\n\n| ID | Why it can wait |\n|---|---|\n| A-1 | x |\n"
        board = GOOD["BOARD.md"].replace("in review (#1)", "merged")
        self.assertEqual(self.lint(**{"BOARD.md": board, "LATER.md": later,
                                      "README.md": README}),
                         ["LATER.md: A-1: the BOARD row is merged; remove the LATER row"])

    def test_no_board_row_claim_while_a_row_exists(self):
        got = self.later("| B-2 l1 | B-2 has no board row | y |")
        self.assertEqual(got, ["LATER.md: B-2 has a BOARD row but the text says it has no board row"])
        got = self.lint(**{"BOARD.md": GOOD["BOARD.md"] + "\nNote: A-1 has no row of its own.\n"})
        self.assertEqual(got, ["BOARD.md: A-1 has a BOARD row but the text says it has no board row"])

    def test_no_board_row_claim_for_an_absent_id_passes(self):
        self.assertEqual(self.later("| Q-1 | Q-1 has no board row | y |"), [])

    def test_duplicate_board_ids(self):
        board = GOOD["BOARD.md"] + "| A-1 | [a](briefs/A-1.md) | — | queued |\n"
        self.assertEqual(self.lint(**{"BOARD.md": board}), ["BOARD.md: duplicate row ID A-1"])

    def test_blocked_on_a_merged_row(self):
        board = (GOOD["BOARD.md"] + "| B-2 | b | — | merged (#2) |\n"
                 "| C-3 | c | — | queued (blocked on B-2; lane x) |\n"
                 "| D-4 | d | — | queued (blocked on mail wiring) |\n"
                 "| E-5 | e | — | queued (blocked on A-1) |\n")
        self.assertEqual(self.lint(**{"BOARD.md": board}),
                         ["BOARD.md: C-3: blocked on B-2, which is merged"])


    def test_main_files_pass(self):
        self.assertEqual(doclint.lint(ROOT), [])


if __name__ == "__main__":
    unittest.main()
