"""Tests for tools/record_merge.py, the record-file merge driver that merges lines by key (#6316, #6358).

No requirement IDs: PLAN.md tooling, not SPEC.md behaviour. All data is synthetic.
"""
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import record_merge  # noqa: E402
import premerge  # noqa: E402
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _nogit_bg import setUpModule, tearDownModule  # noqa: E402,F401

RECORD = "broker/k/MUTANTS-EQUIVALENT"


def entry(stmt, reason="proof"):
    """One synthetic MUTANTS-EQUIVALENT entry (tools/mutgate.py RECORD), keyed by `stmt`."""
    return json.dumps({"file": "k.go", "mutant": "STATEMENT_DELETION", "func": "F", "decl": "0" * 64, "stmt": [stmt],
                       "at": 0, "after": "x := 1", "occurrence": [1, 1], "reason": reason, "accepted": "#1"}) + "\n"


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
        shutil.copy(ROOT / "tools/record_merge.py", self.r / "tools")
        shutil.copy(ROOT / ".gitattributes", self.r)
        self.write(HEAD + "| L-1 | edge old |\n| L-2 | two |\n" + TAIL)
        self.commit("base")
        record_merge.install(self.r)

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
        record_merge.install(self.r)
        attrs = (self.r / ".git/info/attributes").read_text()
        self.assertEqual(attrs.count("ASSUMPTIONS.md merge=records"), 1)
        self.assertEqual(attrs.count("MUTANTS-EQUIVALENT merge=records"), 1)
        self.assertEqual(git(self.r, "config", "merge.records.driver").stdout.strip(), record_merge.DRIVER)
        for name in ("ASSUMPTIONS.md", "broker/k/MUTANTS-EQUIVALENT"):
            self.assertEqual(git(self.r, "check-attr", "merge", name).stdout.strip(), f"{name}: merge: records")
        self.assertEqual(git(self.r, "check-attr", "merge", "README.md").stdout.strip(), "README.md: merge: unspecified")

    def test_install_keeps_other_attributes(self):
        attrs = self.r / ".git/info/attributes"
        attrs.write_text("*.bin binary")  # no final newline
        record_merge.install(self.r)
        self.assertEqual(attrs.read_text(), "*.bin binary\nASSUMPTIONS.md merge=records\nMUTANTS-EQUIVALENT merge=records\n")

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

    def test_a_row_both_sides_added_word_for_word_is_kept_once(self):
        # #6358: an identical duplicate is a no-op, in the driver as in doclint and premerge.
        reviewed, tip, out = self.merge("| L-1 | edge old |\n| L-2 | two |\n| S-1 | shared |\n| P-1 | mine |\n",
                                        "| L-1 | edge old |\n| L-2 | two |\n| B-1 | bak |\n| S-1 | shared |\n")
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertEqual(self.read(), HEAD + "| L-1 | edge old |\n| L-2 | two |\n| S-1 | shared |\n| P-1 | mine |\n"
                         "| B-1 | bak |\n" + TAIL)
        self.assertEqual(self.same_in_ci(reviewed, tip), ([], []))

    def merge_records(self, base, mine, main):
        """merge() for broker/k/MUTANTS-EQUIVALENT: entries `base`, then the PR's `mine` and main's `main`."""
        top = "# Mutant-equivalent proofs for broker/k.\n"
        (self.r / "broker/k").mkdir(parents=True)
        self.write(top + base, RECORD)
        self.commit("record")
        git(self.r, "checkout", "-q", "-b", "pr")
        self.write(top + mine, RECORD)
        reviewed = self.commit("pr")
        git(self.r, "checkout", "-q", "main")
        self.write(top + main, RECORD)
        tip = self.commit("main")
        git(self.r, "checkout", "-q", "pr")
        return reviewed, tip, git(self.r, "merge", "--no-edit", "main", check=False)

    def test_an_entry_both_sides_added_word_for_word_is_kept_once(self):
        # #6265, #6279, #6321 and #6032 carried one proof of `lapse`; whichever merged later dropped its copy.
        a, m, p, s = (entry(x) for x in ("a()", "m()", "p()", "s()"))
        reviewed, tip, out = self.merge_records(a, a + p + s, a + m + s)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertEqual((self.r / RECORD).read_text().count('"s()"'), 1)
        self.assertEqual(self.same_in_ci(reviewed, tip), ([], []))

    def test_an_entry_edited_beside_a_shared_append_keeps_the_edit_and_one_copy(self):
        a, s = entry("a()"), entry("s()")
        reviewed, tip, out = self.merge_records(a, entry("a()", "proof, edited") + s, a + entry("m()") + s)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        text = (self.r / RECORD).read_text()
        self.assertEqual((text.count('"s()"'), text.count('"a()"'), text.count("proof, edited")), (1, 1, 1))
        self.assertEqual(self.same_in_ci(reviewed, tip), ([], []))

    def test_two_proofs_of_one_mutant_stop_the_merge_and_print_both(self):
        mine, main = entry("s()", "the PR's proof"), entry("s()", "main's proof")
        reviewed, tip, out = self.merge_records("", entry("p()") + mine, entry("m()") + main)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("one mutant proved twice, keep one proof", out.stdout + out.stderr)
        for line in (mine, main):
            self.assertIn(line.strip(), out.stdout + out.stderr)
            self.assertIn(line, (self.r / RECORD).read_text())

    def test_an_entry_changed_on_both_sides_is_a_conflict(self):
        a = entry("a()")
        _, _, out = self.merge_records(a, entry("a()", "pr") + entry("p()"), entry("a()", "main") + entry("m()"))
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("conflict markers", out.stdout + out.stderr)
        self.assertIn("<<<<<<< ours\n", (self.r / RECORD).read_text())

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
        r = lambda *sides: record_merge.resolve(*([f"| {x} |\n".encode() for x in s] for s in sides))
        rows = lambda *xs: [f"| {x} |\n".encode() for x in xs]
        self.assertEqual(r(["A-1 | new"], ["A-1 | old"], ["A-1 | old", "B-1 | b"]), rows("A-1 | new", "B-1 | b"))
        self.assertEqual(r(["A-1 | old", "P-1 | p"], ["A-1 | old"], ["A-1 | new"]), rows("P-1 | p", "A-1 | new"))
        self.assertEqual(r(["A-1 | x"], ["A-1 | old"], ["A-1 | x"]), rows("A-1 | x", "A-1 | x"), "a duplicate is caught later")
        self.assertIsNone(r(["A-1 | x"], ["A-1 | old"], ["A-1 | y"]))
        self.assertIsNone(r([], ["A-1 | old"], ["A-1 | y"]))
        self.assertIsNone(r(["A-1 | x"], ["A-1 | old"], []))
        self.assertEqual(r([], ["A-1 | old"], []), [])
        self.assertIsNone(record_merge.resolve([b"prose\n"], [], [b"| A-1 |\n"]))
        e = lambda *xs: [entry(x).encode() for x in xs]
        k = record_merge.entry_key
        self.assertEqual(record_merge.resolve(e("p()"), [], e("m()"), key=k), e("p()", "m()"))
        self.assertIsNone(record_merge.resolve(e("p()") + [b"# a comment\n"], [], e("m()"), key=k))
        self.assertEqual(k(entry("s()", "one").encode()), k(entry("s()", "another").encode()), "the proof is no key")
        self.assertIsNone(k(b"# a comment\n"))
        self.assertIsNone(k(b"[1]\n"))

    def test_once_drops_only_word_for_word_repeats_of_keyed_lines(self):
        text = b"| ID |\n|---|\n| A-1 | x |\n| A-1 | x |\n| A-1 | y |\n\n| ID |\n|---|\n"
        self.assertEqual(record_merge.once(text), b"| ID |\n|---|\n| A-1 | x |\n| A-1 | y |\n\n| ID |\n|---|\n",
                         "a second table's header and separator are no rows")
        rec = b"# c\n" + entry("a()").encode() + b"# c\n\n" + entry("a()").encode() + entry("a()", "other").encode()
        self.assertEqual(record_merge.once(rec, "broker/k/MUTANTS-EQUIVALENT"),
                         b"# c\n" + entry("a()").encode() + b"# c\n\n" + entry("a()", "other").encode())
        self.assertEqual(list(record_merge.duplicates(rec, "broker/k/MUTANTS-EQUIVALENT").values()),
                         [[entry("a()").strip(), entry("a()", "other").strip()]])

    def test_duplicates_read_tables_only(self):
        text = b"| ID | A |\n|---|---|\n| A-1 | x |\n| A-1 | y |\n\n| A-1 | outside |\n| ID | B |\n|---|---|\n| B-1 | z |\n"
        self.assertEqual(record_merge.duplicates(text), {"A-1": ["| A-1 | x |", "| A-1 | y |"]})
        self.assertEqual(record_merge.duplicates(b"| ID |\n|---|\n| A-1 | x |\n| A-2 |\n| A-1 | y |\n| A-1 | x |\n"),
                         {"A-1": ["| A-1 | x |", "| A-1 | y |"]})
        self.assertEqual(record_merge.duplicates(b"| ID |\n|---|\n| A-1 |\n| A-2 |\n| A-1 |\n"), {},
                         "a row repeated word for word is one row (#6358)")

    def test_a_file_merge_file_refuses_is_a_failure_and_ours_is_untouched(self):
        # Security on #6341 (comment 7043047435): a NUL byte made merge-file fail; the driver wrote an empty file, exit 0.
        with tempfile.TemporaryDirectory() as d:
            paths = [pathlib.Path(d, n) for n in ("o", "a", "b")]
            texts = [b"| ID |\n|---|\n| A-1 |\n", b"| ID |\n|---|\n| A-1 \0|\n", b"| ID |\n|---|\n| A-2 |\n"]
            for p, t in zip(paths, texts):
                p.write_bytes(t)
            self.assertEqual(record_merge.main([str(p) for p in paths] + ["ASSUMPTIONS.md"]), 1)
            self.assertEqual(paths[1].read_bytes(), texts[1])
        self.assertEqual(record_merge.merge(texts[0], texts[1], texts[2]), (None, False))

    def test_usage(self):
        self.assertEqual(record_merge.main([]), 2)


if __name__ == "__main__":
    unittest.main()
