"""Tests for tools/lookup.py: next-id, ci-why and conflicts.

No requirement IDs: PLAN.md tooling, not SPEC.md behaviour. All data is synthetic.
"""
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import lookup  # noqa: E402


def git(cwd, *args):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                          cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def commit(cwd, files, msg):
    for name, text in files.items():
        p = pathlib.Path(cwd, name)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    git(cwd, "add", "-A")
    git(cwd, "commit", "-q", "-m", msg)
    return git(cwd, "rev-parse", "HEAD")


TABLE = "| ID | Date |\n|---|---|\n| D-1 | x |\n| D-2 | x |\n| D-300 | x |\nSee D-999 in prose.\n"


class NextIdTest(unittest.TestCase):
    def test_table_rows_only(self):
        self.assertEqual(lookup.table_ids(TABLE), {1, 2, 300})
        self.assertEqual(lookup.table_ids("| C2-4 | x |\n| D-5 | x |\n", "C2"), {4})

    def test_decision_files(self):
        self.assertEqual(lookup.file_ids(["decisions/D-7.md", "decisions/README.md", "decisions/D-8.txt"]), {7})

    def test_claims_and_collisions(self):
        added, dup = lookup.claims({1, 2}, {10: {1, 2, 3}, 11: {1, 3, 4}, 12: {2}})
        self.assertEqual(added, {10: {3}, 11: {3, 4}, 12: set()})
        self.assertEqual(dup, {3: [10, 11]})

    def test_next_free_counts_open_claims(self):
        self.assertEqual(lookup.next_free({1, 2}, {10: {5}}), 6)
        self.assertEqual(lookup.next_free(set(), {}), 1)

    def test_range_keeps_to_a_lanes_block(self):
        held = {1, 250, 262, 300, 305}
        self.assertEqual(lookup.next_free(held, {7: {263}}, 248, 299), 264)
        self.assertEqual(lookup.next_free(held, {}, 300), 306)
        self.assertEqual(lookup.next_free(held, {}, 400), 400)
        with self.assertRaises(lookup.Failed):
            lookup.next_free({248, 249}, {}, 248, 249)
        self.assertEqual(lookup.parse_range("248-299"), (248, 299))

    def test_tree_ids_reads_head_tree(self):
        with tempfile.TemporaryDirectory() as d:
            git(d, "init", "-q")
            base = commit(d, {"DECISIONS.md": TABLE}, "base")
            head = commit(d, {"DECISIONS.md": TABLE + "| D-301 | y |\n", "decisions/D-302.md": "z"}, "pr")
            self.assertEqual(lookup.tree_ids(d, base), {1, 2, 300})
            self.assertEqual(lookup.tree_ids(d, head), {1, 2, 300, 301, 302})


GO_LOG = """\
2026-10-31T10:00:00.1234567Z === RUN   TestOK
2026-10-31T10:00:00.1234567Z --- PASS: TestOK (0.00s)
2026-10-31T10:00:01.0000000Z --- FAIL: TestSeal (0.01s)
2026-10-31T10:00:01.0000000Z     seal_test.go:42: got 3, want 4
2026-10-31T10:00:01.0000000Z     seal_test.go:43: second line
2026-10-31T10:00:01.0000000Z     --- FAIL: TestSeal/sub (0.00s)
2026-10-31T10:00:01.0000000Z         seal_test.go:50: sub failed
2026-10-31T10:00:01.0000000Z FAIL
2026-10-31T10:00:01.0000000Z FAIL\tgithub.com/x/broker/seal\t0.2s
2026-10-31T10:00:01.0000000Z ok  \tgithub.com/x/broker/other\t0.1s
2026-10-31T10:00:02.0000000Z ##[error]Process completed with exit code 1.
"""

PY_LOG = """\
test_a (tests.test_x.T.test_a) ... ok
test_b (tests.test_x.T.test_b) ... FAIL
======================================================================
FAIL: test_b (tests.test_x.T.test_b)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "tests/test_x.py", line 9, in test_b
    self.assertEqual(1, 2)
AssertionError: 1 != 2

======================================================================
ERROR: test_c (tests.test_x.T.test_c)
----------------------------------------------------------------------
Traceback (most recent call last):
  File "tests/test_x.py", line 12, in test_c
    open("missing")
FileNotFoundError: [Errno 2] No such file or directory: 'missing'

----------------------------------------------------------------------
Ran 3 tests in 0.01s

FAILED (failures=1, errors=1)
"""


class CiWhyTest(unittest.TestCase):
    def test_go_failures_with_messages(self):
        self.assertEqual(lookup.why(GO_LOG.splitlines()), [
            "--- FAIL: TestSeal (0.01s)",
            "    seal_test.go:42: got 3, want 4",
            "    seal_test.go:43: second line",
            "    --- FAIL: TestSeal/sub (0.00s)",
            "        seal_test.go:50: sub failed",
            "FAIL",
            "FAIL\tgithub.com/x/broker/seal\t0.2s",
            "##[error]Process completed with exit code 1.",
        ])

    def test_context_caps_message_lines(self):
        self.assertEqual(lookup.why(GO_LOG.splitlines(), context=1)[:2],
                         ["--- FAIL: TestSeal (0.01s)", "    seal_test.go:42: got 3, want 4"])

    def test_unittest_headers_with_exception_line(self):
        self.assertEqual(lookup.why(PY_LOG.splitlines()), [
            "FAIL: test_b (tests.test_x.T.test_b)",
            "    AssertionError: 1 != 2",
            "ERROR: test_c (tests.test_x.T.test_c)",
            "    FileNotFoundError: [Errno 2] No such file or directory: 'missing'",
        ])

    def test_clean_log_has_no_lines(self):
        self.assertEqual(lookup.why(["ok  \tpkg\t0.1s", "PASS", "Ran 3 tests in 0.1s", "OK"]), [])


class ConflictsTest(unittest.TestCase):
    def test_merge_tree_names_conflicted_paths(self):
        with tempfile.TemporaryDirectory() as d:
            git(d, "init", "-q", "-b", "main")
            base = commit(d, {"a.txt": "1\n", "b.txt": "1\n"}, "base")
            git(d, "checkout", "-q", "-b", "pr")
            clean = commit(d, {"b.txt": "1\n2\n"}, "touches b only")
            bad = commit(d, {"a.txt": "pr\n"}, "edits a")
            git(d, "checkout", "-q", "main")
            commit(d, {"a.txt": "main\n"}, "main edits a")
            self.assertEqual(lookup.conflicted(d, clean, "main"), [])
            self.assertEqual(lookup.conflicted(d, bad, "main"), ["a.txt"])
            self.assertEqual(lookup.conflicted(d, base, "main"), [])


if __name__ == "__main__":
    unittest.main()
