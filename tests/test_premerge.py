"""Tests for tools/premerge.py, the reviewed-diff equals merged-diff check (parallel-merge design, section 4 item 9).

No requirement IDs: PLAN.md tooling, not SPEC.md behaviour. All data is synthetic.
"""
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import premerge  # noqa: E402


def git(cwd, *args):
    return subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
                          cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


class PremergeTest(unittest.TestCase):
    def setUp(self):
        self._d = tempfile.TemporaryDirectory()
        self.addCleanup(self._d.cleanup)
        self.r = pathlib.Path(self._d.name)
        git(self.r, "init", "-q", "-b", "main")
        self.write("a.txt", "".join(f"line {i}\n" for i in range(30)))
        self.write("b.txt", "b\n")
        git(self.r, "add", "."), git(self.r, "commit", "-qm", "base")

    def write(self, name, text):
        (self.r / name).write_text(text)

    def commit(self, msg):
        git(self.r, "add", "."), git(self.r, "commit", "-qm", msg)
        return git(self.r, "rev-parse", "HEAD")

    def pr(self):
        git(self.r, "checkout", "-q", "-b", "pr")
        self.write("a.txt", self.read("a.txt").replace("line 2\n", "line two\n"))
        return self.commit("pr")

    def read(self, name):
        return (self.r / name).read_text()

    def check(self, reviewed, head="HEAD"):
        return premerge.compare(self.r, reviewed, head, "main")

    def test_same_head_is_same(self):
        reviewed = self.pr()
        self.assertEqual(self.check(reviewed), [])

    def test_main_merged_in_far_from_the_hunks_is_same(self):
        reviewed = self.pr()
        git(self.r, "checkout", "-q", "main")
        self.write("a.txt", self.read("a.txt").replace("line 25\n", "line 25 main\n"))
        self.commit("main moves")
        git(self.r, "checkout", "-q", "pr")
        git(self.r, "merge", "-q", "--no-edit", "main")
        self.assertEqual(self.check(reviewed), [])

    def merge_main_after(self, edit):
        git(self.r, "checkout", "-q", "main")
        edit()
        self.commit("main moves")
        git(self.r, "checkout", "-q", "pr")
        git(self.r, "merge", "-q", "--no-edit", "main")

    def test_main_merged_in_next_to_a_hunk_is_same(self):
        # #1580, #1592: a base change in the PR hunk's context lines read as `changed`.
        reviewed = self.pr()
        self.merge_main_after(lambda: self.write("a.txt", self.read("a.txt").replace("line 4\n", "line 4 main\n")))
        self.assertEqual(self.check(reviewed), [])

    def test_main_merged_in_then_a_pr_line_changed_is_changed(self):
        reviewed = self.pr()
        self.merge_main_after(lambda: self.write("a.txt", self.read("a.txt").replace("line 4\n", "line 4 main\n")))
        self.write("a.txt", self.read("a.txt").replace("line two\n", "line 2 again\n"))
        self.commit("after the accept")
        self.assertEqual(self.check(reviewed), ["a.txt"])

    def test_main_merged_in_then_a_pr_hunk_moved_is_changed(self):
        # Same added lines at another place: equal +/- lines, different merged file.
        git(self.r, "checkout", "-q", "-b", "pr")
        self.write("a.txt", self.read("a.txt").replace("line 3\n", "line 3\ndeny()\n"))
        reviewed = self.commit("pr")
        self.merge_main_after(lambda: self.write("b.txt", "b main\n"))
        self.write("a.txt", self.read("a.txt").replace("line 3\ndeny()\n", "line 3\n").replace("line 20\n", "line 20\ndeny()\n"))
        self.commit("move the call")
        self.assertEqual(self.check(reviewed), ["a.txt"])

    def test_a_merge_resolution_that_edits_a_pr_line_is_changed(self):
        reviewed = self.pr()
        git(self.r, "checkout", "-q", "main")
        self.write("a.txt", self.read("a.txt").replace("line 2\n", "line 2 main\n"))
        self.commit("main conflicts")
        git(self.r, "checkout", "-q", "pr")
        pr_text = git(self.r, "show", "pr:a.txt") + "\n"
        merge = subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "merge", "-q", "main"],
                               cwd=self.r, capture_output=True, text=True)
        self.assertNotEqual(merge.returncode, 0, "the merge was meant to conflict")
        git(self.r, "rev-parse", "-q", "--verify", "MERGE_HEAD")
        self.write("a.txt", pr_text.replace("line two\n", "line 2 main\n"))
        self.commit("resolve to main's line")
        self.assertEqual(self.check(reviewed), ["a.txt"])

    def test_a_side_branch_merged_in_is_changed(self):
        reviewed = self.pr()
        git(self.r, "checkout", "-q", "-b", "side", "main")
        self.write("c.txt", "side\n")
        self.commit("side")
        git(self.r, "checkout", "-q", "pr")
        git(self.r, "merge", "-q", "--no-edit", "side")
        self.assertEqual(self.check(reviewed), ["c.txt"])

    def test_main_moving_on_unmerged_is_same(self):
        reviewed = self.pr()
        self.merge_main_after(lambda: self.write("a.txt", self.read("a.txt").replace("line 4\n", "line 4 main\n")))
        git(self.r, "checkout", "-q", "main")
        self.write("a.txt", self.read("a.txt").replace("line 1\n", "line 1 later\n"))
        self.commit("main moves again")
        git(self.r, "checkout", "-q", "pr")
        self.assertEqual(self.check(reviewed), [])

    def test_a_later_push_names_the_changed_file(self):
        reviewed = self.pr()
        self.write("b.txt", "b changed\n")
        self.commit("after the accept")
        self.assertEqual(self.check(reviewed), ["b.txt"])

    def test_an_indentation_only_push_that_flips_a_decision_is_changed(self):
        # Reported 2026-10-10: patch-id ignores whitespace, so this read as `same`.
        git(self.r, "checkout", "-q", "-b", "pr")
        self.write("auth.py", "def allowed(user):\n    ok = False\n    if user.admin:\n        log(user)\n        ok = True\n    return ok\n")
        reviewed = self.commit("pr: only admins")
        self.write("auth.py", self.read("auth.py").replace("        ok = True\n", "    ok = True\n"))
        self.commit("dedent: everyone allowed")
        self.assertEqual(self.check(reviewed), ["auth.py"])

    def test_a_whitespace_only_change_is_changed(self):
        reviewed = self.pr()
        self.write("a.txt", self.read("a.txt").replace("line two\n", "line  two\n"))
        self.commit("spacing")
        self.assertEqual(self.check(reviewed), ["a.txt"])

    def test_a_binary_change_is_changed(self):
        git(self.r, "checkout", "-q", "-b", "pr")
        (self.r / "blob.bin").write_bytes(b"\x00\x01deny")
        reviewed = self.commit("pr")
        (self.r / "blob.bin").write_bytes(b"\x00\x01allow")
        self.commit("later")
        self.assertEqual(self.check(reviewed), ["blob.bin"])

    def test_cli_exit_codes(self):
        reviewed = self.pr()
        run = lambda: subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--base", "main", reviewed],
                                     cwd=self.r, capture_output=True, text=True)
        ok = run()
        self.assertEqual((ok.returncode, ok.stdout.strip()), (0, "same"))
        self.write("b.txt", "x\n")
        self.commit("later")
        bad = run()
        self.assertEqual((bad.returncode, bad.stdout.split()), (1, ["changed", "b.txt"]))


if __name__ == "__main__":
    unittest.main()
