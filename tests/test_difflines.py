"""Tests for tools/difflines.py: blocker citations must land on lines the PR's diff changes (OPERATING §2, §4).

Not SPEC IDs, so no REQ marker.
"""
import contextlib
import io
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

TOOLS = pathlib.Path(__file__).resolve().parent.parent / "tools"
sys.path.insert(0, str(TOOLS))
import difflines  # noqa: E402


def git(cwd, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                   cwd=cwd, check=True, capture_output=True)


class DiffLines(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = pathlib.Path(self.tmp.name)
        git(self.dir, "init", "-q", "-b", "main")
        (self.dir / "a.txt").write_text("".join(f"line{i}\n" for i in range(1, 11)))
        (self.dir / "gone.txt").write_text("x\n")
        git(self.dir, "add", ".")
        git(self.dir, "commit", "-q", "-m", "base")
        git(self.dir, "checkout", "-q", "-b", "pr")
        text = (self.dir / "a.txt").read_text().splitlines(keepends=True)
        text[2] = "changed3\n"          # line 3 changed
        del text[6]                     # old line 7 deleted: head lines 6 and 7 border it
        text.append("added\n")         # new last line, head line 10
        (self.dir / "a.txt").write_text("".join(text))
        (self.dir / "new.txt").write_text("n1\nn2\n")
        (self.dir / "gone.txt").unlink()
        git(self.dir, "add", "-A")
        git(self.dir, "commit", "-q", "-m", "pr")
        self.cwd = os.getcwd()
        os.chdir(self.dir)

    def tearDown(self):
        os.chdir(self.cwd)
        self.tmp.cleanup()

    def run_tool(self, *cites):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = difflines.main(["difflines.py", "--base", "main", "--head", "pr", *cites])
        return code, out.getvalue().split("\n")[:-1]

    def test_changed_added_and_new_file_lines_are_in_diff(self):
        code, out = self.run_tool("a.txt:3", "a.txt:10", "new.txt:2")
        self.assertEqual(code, 0)
        self.assertEqual(out, ["in-diff a.txt:3", "in-diff a.txt:10", "in-diff new.txt:2"])

    def test_untouched_line_is_unchanged_and_fails(self):
        code, out = self.run_tool("a.txt:3", "a.txt:1")
        self.assertEqual(code, 1)
        self.assertEqual(out, ["in-diff a.txt:3", "unchanged a.txt:1"])

    def test_lines_bordering_a_deletion_are_in_diff(self):
        self.assertEqual(self.run_tool("a.txt:6", "a.txt:7")[0], 0)
        self.assertEqual(self.run_tool("a.txt:5")[0], 1)

    def test_deleted_file_counts_as_in_diff(self):
        self.assertEqual(self.run_tool("gone.txt:1"), (0, ["in-diff gone.txt:1"]))

    def test_untouched_file_is_unchanged(self):
        (self.dir / "other.txt").write_text("o\n")
        self.assertEqual(self.run_tool("other.txt:1"), (1, ["unchanged other.txt:1"]))

    def test_bad_citation_is_usage_error(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(difflines.main(["difflines.py", "a.txt"]), 2)
            self.assertEqual(difflines.main(["difflines.py"]), 2)


if __name__ == "__main__":
    unittest.main()
