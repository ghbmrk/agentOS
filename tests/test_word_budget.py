"""Tests for tools/word_budget.py, the shrink-only budget of SPEC.md and the process docs (D-152).

No SPEC requirement IDs: process tooling, not SPEC.md behaviour. All data is synthetic.
"""
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))
import word_budget  # noqa: E402

DECISIONS = "| ID | Date | Status | Decision | Source |\n|---|---|---|---|---|\n" \
            "| D-7 | 2026-10-23 | active | more words for #42 | Mark |\n| D-8 | 2026-10-23 | superseded | x #42 | Mark |\n" \
            "| D-9 | 2026-10-23 | active | words for #420 and #4 | Mark |\n"


class CountTest(unittest.TestCase):
    def test_sets_take_the_named_docs_and_every_role_skill(self):
        got = word_budget.sets(["SPEC.md", "CLAUDE.md", "docs/OPERATING.md", "README.md",
                                ".claude/skills/a/SKILL.md", ".claude/skills/a/notes.md",
                                ".claude/skills/a/b/SKILL.md"])
        self.assertEqual(got, {"spec": ["SPEC.md"],
                               "process": ["CLAUDE.md", "docs/OPERATING.md", ".claude/skills/a/SKILL.md"]})

    def test_a_word_is_a_run_of_non_whitespace(self):
        self.assertEqual(word_budget.words("a  b\n— `c d`\t|"), 6)

    def test_tree_counts_read_only_the_members(self):
        # Synthetic tree, not the repository: a test that opens a record must run on ci.yml's
        # records-only step (tests/records_audit.py), and tree_counts opens only the members.
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            for path, text in {"SPEC.md": "a b c", "CLAUDE.md": "a", "docs/OPERATING.md": "a b",
                               ".claude/skills/x/SKILL.md": "a", ".claude/skills/x/notes.md": "a b c d",
                               "reviews/l3/README.md": "a b c d"}.items():
                (root / path).parent.mkdir(parents=True, exist_ok=True)
                (root / path).write_text(text)
            self.assertEqual(word_budget.tree_counts(root), {"spec": 3, "process": 4})


class CheckTest(unittest.TestCase):
    base = {"spec": 100, "process": 50}

    def test_equal_or_smaller_passes(self):
        ok, _ = word_budget.check(self.base, {"spec": 100, "process": 40}, "", DECISIONS)
        self.assertTrue(ok)

    def test_growth_fails_without_a_waiver(self):
        ok, lines = word_budget.check(self.base, {"spec": 100, "process": 51}, "", DECISIONS)
        self.assertFalse(ok)
        self.assertIn("grew process", lines[-1])

    def test_cuts_in_one_set_do_not_pay_for_the_other(self):
        ok, _ = word_budget.check(self.base, {"spec": 10, "process": 51}, "", DECISIONS)
        self.assertFalse(ok)

    def test_waiver_must_name_an_active_decision_that_names_the_pr(self):
        # #2945: an active row is not enough; it has to name this PR, so a standing row
        # (D-152 itself, say) cannot waive an unrelated PR's growth.
        head = {"spec": 120, "process": 50}
        self.assertTrue(word_budget.check(self.base, head, "Body.\nWord-budget: D-7\n", DECISIONS, 42)[0])
        self.assertFalse(word_budget.check(self.base, head, "Word-budget: D-7", DECISIONS, 43)[0])
        self.assertFalse(word_budget.check(self.base, head, "Word-budget: D-7", DECISIONS)[0])
        self.assertFalse(word_budget.check(self.base, head, "Word-budget: D-8", DECISIONS, 42)[0])
        self.assertFalse(word_budget.check(self.base, head, "Word-budget: D-9", DECISIONS, 42)[0])
        self.assertTrue(word_budget.check(self.base, head, "Word-budget: D-9", DECISIONS, 420)[0])
        self.assertFalse(word_budget.check(self.base, head, "Word-budget: D-10", DECISIONS, 42)[0])
        self.assertFalse(word_budget.check(self.base, head, "See Word-budget: D-7 inline", DECISIONS, 42)[0])


class GitTest(unittest.TestCase):
    def test_compares_two_commits(self):
        with tempfile.TemporaryDirectory() as d:
            git = lambda *a: subprocess.run(["git", "-C", d, *a], check=True, capture_output=True)
            git("init", "-q")
            git("config", "user.email", "t@example.invalid")
            git("config", "user.name", "t")
            root = pathlib.Path(d)
            (root / ".claude/skills/x").mkdir(parents=True)
            (root / "SPEC.md").write_text("one two three")
            (root / "CLAUDE.md").write_text("a b")
            (root / "DECISIONS.md").write_text(DECISIONS)
            git("add", "-A")
            git("commit", "-qm", "base")
            (root / ".claude/skills/x/SKILL.md").write_text("c")
            # The PR adds its own waiver row: it does not count, the base's rows do (#2945).
            (root / "DECISIONS.md").write_text(DECISIONS + "| D-11 | 2026-10-24 | active | more words for #42 | Mark |\n")
            git("add", "-A")
            git("commit", "-qm", "head")
            tool = pathlib.Path(word_budget.__file__)
            env = lambda pr: {"PATH": "/usr/bin:/bin", **({"PR_NUMBER": pr} if pr else {})}
            run = lambda *a, pr="42": subprocess.run([sys.executable, "-I", str(tool), *a], cwd=d, capture_output=True,
                                                     text=True, env=env(pr))
            grew = run("--git", "HEAD~1", "HEAD")
            self.assertEqual(grew.returncode, 1, grew.stdout + grew.stderr)
            self.assertIn("process: 2 -> 3 words (+1)", grew.stdout)
            (root / "body.md").write_text("Word-budget: D-7\n")
            self.assertEqual(run("--git", "HEAD~1", "HEAD", "--body-file", "body.md").returncode, 0)
            self.assertEqual(run("--git", "HEAD~1", "HEAD", "--body-file", "body.md", pr="").returncode, 1)
            self.assertEqual(run("--git", "HEAD~1", "HEAD", "--body-file", "body.md", pr="43").returncode, 1)
            (root / "body.md").write_text("Word-budget: D-11\n")
            self.assertEqual(run("--git", "HEAD~1", "HEAD", "--body-file", "body.md").returncode, 1)
            self.assertEqual(run("--git", "HEAD", "HEAD~1").returncode, 0)

    def test_the_workflow_counts_the_merge_not_a_stale_tip(self):
        # A branch forked before main changed CLAUDE.md. Its tip still has the old text, so
        # comparing the tip with main reads main's later edit as the branch's own: a false
        # fail when main shrank, a hidden growth when main grew. The test merge is right.
        wf = (pathlib.Path(__file__).resolve().parent.parent / ".github/workflows/word-budget.yml").read_text()
        refs = re.search(r'word_budget\.py" --git (\S+) (\S+) ', wf).groups()
        self.assertEqual(refs, ("HEAD^1", "HEAD"))
        self.assertIn("PR_NUMBER: ${{ github.event.pull_request.number }}", wf)
        tool = pathlib.Path(word_budget.__file__)
        for main_edit, branch_edit, want in (("a b c d", None, 0),        # main shrank, branch idle
                                             ("x " * 20, "e f g", 1)):    # main grew, branch grew
            with tempfile.TemporaryDirectory() as d:
                git = lambda *a: subprocess.run(["git", "-C", d, *a], check=True, capture_output=True)
                root = pathlib.Path(d)
                git("init", "-q", "-b", "main")
                git("config", "user.email", "t@example.invalid")
                git("config", "user.name", "t")
                (root / "CLAUDE.md").write_text("a b c d e f g h")
                (root / "AGENTS.md").write_text("a b")
                (root / "DECISIONS.md").write_text(DECISIONS)
                git("add", "-A")
                git("commit", "-qm", "fork point")
                git("checkout", "-qb", "branch")
                (root / "LATER.md").write_text("unrelated")
                if branch_edit:
                    (root / "AGENTS.md").write_text(branch_edit)
                git("add", "-A")
                git("commit", "-qm", "branch")
                git("checkout", "-q", "main")
                (root / "CLAUDE.md").write_text(main_edit)
                git("commit", "-qam", "main moves on")
                git("merge", "-q", "--no-ff", "-m", "test merge", "branch")
                run = lambda *a: subprocess.run([sys.executable, "-I", str(tool), "--git", *a], cwd=d,
                                                capture_output=True, text=True)
                got = run(*refs)
                self.assertEqual(got.returncode, want, got.stdout + got.stderr)
                self.assertEqual(run("HEAD^1", "HEAD^2").returncode, 1 - want, "the tip comparison was right here")


if __name__ == "__main__":
    unittest.main()
