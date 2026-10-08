"""Tests for tools/doclint.py, the operating-document consistency check (BOARD row DOC-2).

No requirement IDs: PLAN.md tooling, not SPEC.md behaviour. All data is synthetic.
"""
import pathlib
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


if __name__ == "__main__":
    unittest.main()
