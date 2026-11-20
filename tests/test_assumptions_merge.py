"""Tests for tools/assumptions_merge.py, the ASSUMPTIONS.md merge driver that merges rows by ID (#6316).

No requirement IDs: PLAN.md tooling, not SPEC.md behaviour. All data is synthetic.
"""
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import assumptions_merge  # noqa: E402
import premerge  # noqa: E402
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _nogit_bg import setUpModule, tearDownModule  # noqa: E402,F401

HEAD = "# Assumptions\n\n| ID | Assumption |\n|---|---|\n| E-1 | one |\n"
TAIL = "\nProse after the table.\n"


def git(cwd, *args, check=True):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                          cwd=cwd, check=check, capture_output=True, text=True)


class DriverTest(unittest.TestCase):
    def setUp(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.r = pathlib.Path(d.name, "r")
        git(d.name, "init", "-q", "-b", "main", "r")
        (self.r / "tools").mkdir()
        shutil.copy(ROOT / "tools/assumptions_merge.py", self.r / "tools")
        shutil.copy(ROOT / ".gitattributes", self.r)
        self.write(HEAD + "| L-1 | edge old |\n| L-2 | two |\n" + TAIL)
        self.commit("base")
        assumptions_merge.install(self.r)

    def write(self, text, name="ASSUMPTIONS.md"):
        (self.r / name).write_text(text)

    def read(self):
        return (self.r / "ASSUMPTIONS.md").read_text()

    def commit(self, msg):
        git(self.r, "add", "."), git(self.r, "commit", "-qm", msg)
        return git(self.r, "rev-parse", "HEAD").stdout.strip()

    def merge(self, mine, main):
        """The PR writes `mine` rows, main writes `main` rows, main is merged into the PR: (reviewed, main, merge)."""
        git(self.r, "checkout", "-q", "-b", "pr")
        self.write(HEAD + mine + TAIL)
        reviewed = self.commit("pr")
        git(self.r, "checkout", "-q", "main")
        self.write(HEAD + main + TAIL)
        tip = self.commit("main")
        git(self.r, "checkout", "-q", "pr")
        return reviewed, tip, git(self.r, "merge", "--no-edit", "main", check=False)

    def same_in_ci(self, reviewed, tip):
        """premerge's reading in this clone and in a clone without the driver, as CI's is."""
        ci = pathlib.Path(self.r.parent, "ci")
        git(self.r.parent, "clone", "-q", "--no-local", str(self.r), "ci")
        self.addCleanup(shutil.rmtree, ci)
        return premerge.compare(self.r, reviewed, "HEAD", tip), premerge.compare(ci, reviewed, "origin/pr", tip)

    def test_install_sets_the_driver_once(self):
        assumptions_merge.install(self.r)
        attrs = (self.r / ".git/info/attributes").read_text()
        self.assertEqual(attrs.count("ASSUMPTIONS.md merge=assumptions"), 1)
        self.assertEqual(git(self.r, "config", "merge.assumptions.driver").stdout.strip(), assumptions_merge.DRIVER)
        self.assertEqual(git(self.r, "check-attr", "merge", "ASSUMPTIONS.md").stdout.strip(),
                         "ASSUMPTIONS.md: merge: assumptions")
        self.assertEqual(git(self.r, "check-attr", "merge", "MUTANTS-EQUIVALENT").stdout.strip(),
                         "MUTANTS-EQUIVALENT: merge: union", "only ASSUMPTIONS.md moves off the union")

    def test_install_keeps_other_attributes(self):
        attrs = self.r / ".git/info/attributes"
        attrs.write_text("*.bin binary")  # no final newline
        assumptions_merge.install(self.r)
        self.assertEqual(attrs.read_text(), "*.bin binary\nASSUMPTIONS.md merge=assumptions\n")

    def test_a_row_the_pr_edited_beside_a_main_append_is_kept_once(self):
        # #6238, #6032: the union kept `edge old` and `edge new`; doclint failed after the push.
        reviewed, tip, out = self.merge("| L-1 | edge old |\n| L-2 | two new |\n",
                                        "| L-1 | edge old |\n| L-2 | two |\n| B-1 | bak |\n")
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertEqual(self.read(), HEAD + "| L-1 | edge old |\n| L-2 | two new |\n| B-1 | bak |\n" + TAIL)
        self.assertEqual(self.same_in_ci(reviewed, tip), ([], []))

    def test_a_row_main_edited_beside_a_pr_append_takes_mains_version(self):
        reviewed, tip, out = self.merge("| L-1 | edge old |\n| L-2 | two |\n| P-1 | mine |\n",
                                        "| L-1 | edge old |\n| L-2 | two main |\n")
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertEqual(self.read(), HEAD + "| L-1 | edge old |\n| P-1 | mine |\n| L-2 | two main |\n" + TAIL)
        self.assertEqual(self.same_in_ci(reviewed, tip), ([], []))

    def test_rows_both_sides_append_are_kept_pr_first(self):
        reviewed, tip, out = self.merge("| L-1 | edge old |\n| L-2 | two |\n| P-1 | mine |\n",
                                        "| L-1 | edge old |\n| L-2 | two |\n| B-1 | bak |\n")
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertEqual(self.read(), HEAD + "| L-1 | edge old |\n| L-2 | two |\n| P-1 | mine |\n| B-1 | bak |\n" + TAIL)
        self.assertEqual(self.same_in_ci(reviewed, tip), ([], []))

    def test_rows_deleted_on_one_side_stay_deleted(self):
        reviewed, tip, out = self.merge("| L-2 | two |\n| P-1 | mine |\n", "| L-1 | edge old |\n| B-1 | bak |\n")
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertEqual(self.read(), HEAD + "| P-1 | mine |\n| B-1 | bak |\n" + TAIL)
        self.assertEqual(self.same_in_ci(reviewed, tip), ([], []))

    def test_one_id_appended_on_both_sides_stops_the_merge_and_a_renumber_reads_same(self):
        reviewed, tip, out = self.merge("| L-1 | edge old |\n| L-2 | two |\n| L-3 | mine |\n",
                                        "| L-1 | edge old |\n| L-2 | two |\n| L-3 | main |\n")
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("row ID L-3 twice", out.stdout + out.stderr)
        self.assertIn("| L-3 | mine |", out.stdout + out.stderr)
        self.assertEqual(self.read(), HEAD + "| L-1 | edge old |\n| L-2 | two |\n| L-3 | mine |\n| L-3 | main |\n" + TAIL)
        self.write(self.read().replace("| L-3 | mine |", "| L-4 | mine |"))
        self.commit("renumber")
        self.assertEqual(self.same_in_ci(reviewed, tip), ([], []))

    def test_a_row_changed_on_both_sides_or_changed_and_deleted_is_a_conflict(self):
        for mine, main in (("| L-1 | edge pr |\n| L-2 | two |\n", "| L-1 | edge main |\n| L-2 | two |\n| B-1 | b |\n"),
                           ("| L-2 | two |\n| P-1 | mine |\n", "| L-1 | edge main |\n| L-2 | two |\n"),
                           ("| L-1 | edge pr |\n| L-2 | two |\n| P-1 | p |\n", "| L-2 | two |\n")):
            with self.subTest(mine=mine, main=main):
                self.setUp()
                _, _, out = self.merge(mine, main)
                self.assertNotEqual(out.returncode, 0)
                self.assertIn("conflict markers", out.stdout + out.stderr)
                text = self.read()
                self.assertIn("<<<<<<< ours\n", text)
                self.assertIn("||||||| base\n| L-1 | edge old |\n", text)
                self.assertIn(">>>>>>> theirs\n", text)

    def test_a_hunk_with_a_line_that_is_no_row_is_a_conflict(self):
        git(self.r, "checkout", "-q", "-b", "pr")
        self.write(HEAD + "| L-1 | edge new |\n| L-2 | two |\n" + "\nPR prose.\n")
        self.commit("pr")
        git(self.r, "checkout", "-q", "main")
        self.write(HEAD + "| L-1 | edge old |\n| L-2 | two |\n" + "\nMain prose.\n")
        self.commit("main")
        git(self.r, "checkout", "-q", "pr")
        out = git(self.r, "merge", "--no-edit", "main", check=False)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("<<<<<<< ours\nPR prose.\n||||||| base\nProse after the table.\n=======\nMain prose.\n>>>>>>> theirs\n",
                      self.read())

    def test_a_clone_without_the_driver_still_merges_by_union(self):
        (self.r / ".git/info/attributes").unlink()
        _, _, out = self.merge("| L-1 | edge old |\n| L-2 | two new |\n", "| L-1 | edge old |\n| L-2 | two |\n| B-1 | b |\n")
        self.assertEqual(out.returncode, 0)
        self.assertEqual(self.read().count("| L-2 |"), 2, "the union keeps both; doclint is the backstop there")


class ResolveTest(unittest.TestCase):
    def test_resolve(self):
        r = lambda *sides: assumptions_merge.resolve(*([f"| {x} |\n".encode() for x in s] for s in sides))
        rows = lambda *xs: [f"| {x} |\n".encode() for x in xs]
        self.assertEqual(r(["A-1 | new"], ["A-1 | old"], ["A-1 | old", "B-1 | b"]), rows("A-1 | new", "B-1 | b"))
        self.assertEqual(r(["A-1 | old", "P-1 | p"], ["A-1 | old"], ["A-1 | new"]), rows("P-1 | p", "A-1 | new"))
        self.assertEqual(r(["A-1 | x"], ["A-1 | old"], ["A-1 | x"]), rows("A-1 | x", "A-1 | x"), "a duplicate is caught later")
        self.assertIsNone(r(["A-1 | x"], ["A-1 | old"], ["A-1 | y"]))
        self.assertIsNone(r([], ["A-1 | old"], ["A-1 | y"]))
        self.assertIsNone(r(["A-1 | x"], ["A-1 | old"], []))
        self.assertEqual(r([], ["A-1 | old"], []), [])
        self.assertIsNone(assumptions_merge.resolve([b"prose\n"], [], [b"| A-1 |\n"]))

    def test_duplicates_read_tables_only(self):
        text = b"| ID | A |\n|---|---|\n| A-1 | x |\n| A-1 | y |\n\n| A-1 | outside |\n| ID | B |\n|---|---|\n| B-1 | z |\n"
        self.assertEqual(assumptions_merge.duplicates(text), {"A-1": ["| A-1 | x |", "| A-1 | y |"]})
        self.assertEqual(assumptions_merge.duplicates(b"| ID |\n|---|\n| A-1 |\n| A-2 |\n| A-1 |\n"),
                         {"A-1": ["| A-1 |", "| A-1 |"]})

    def test_usage(self):
        self.assertEqual(assumptions_merge.main([]), 2)


if __name__ == "__main__":
    unittest.main()
