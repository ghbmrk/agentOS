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

    def test_mark_press_merge_paths(self):
        for f in ("CLAUDE.md", "docs/OPERATING.md", ".claude/settings.json", ".github/workflows/ci.yml",
                  "tools/risk_tier.py", "tools/premerge.py", "tools/ci_scope.py", "tools/ci_scope_x.py",
                  "tools/g1_scope.py", "tools/g1_scope.txt", "reviews/l3/README.md", "docs/LANES.md"):
            self.assertEqual(premerge.mark_paths([f]), [f], f)
        for f in ("tools/records.py", "reviews/l3/2026-10-15-pr1.md", "README.md", "docs/OTHER.md", "src/claude/x.go"):
            self.assertEqual(premerge.mark_paths([f]), [], f)

    def test_mark_paths_cover_agent_config_and_tier_inputs(self):
        # Security R3 on #1824: MCP config, other teams' rules, nested CLAUDE files, and the
        # core list tools/risk_tier.py reads to set tiers.
        self.assertTrue((ROOT / "broker/core/core.txt").is_file())
        self.assertIn("core.txt", (ROOT / "tools/risk_tier.py").read_text())
        for f in (".mcp.json", "AGENTS.md", "CLAUDE.local.md", "broker/CLAUDE.md", "a/b/CLAUDE.local.md",
                  "broker/core/core.txt"):
            self.assertEqual(premerge.mark_paths([f]), [f], f)
        # PREMERGE-paths (#1835): nested config, the tests that pin merge gates, and newline-bearing paths.
        for f in ("sub/AGENTS.md", "sub/.mcp.json", "sub/.claude/settings.json", "a/b/.claude/x", "tests/test_premerge.py",
                  "tests/test_risk_tier.py", "tests/test_risk_tier_custody.py", "tests/test_workflows.py",
                  "tests/test_ci_scope.py", "tests/test_g1_scope.py", "x\n/.claude/y", ".github/a\nb", "tools/premerge.py"):
            self.assertEqual(premerge.mark_paths([f]), [f], repr(f))
        for f in ("CLAUDE.md\n", "tools/premerge.py\n", "tests/test_records.py", "x/.claudex/y"):
            self.assertEqual(premerge.mark_paths([f]), [], repr(f))
        for f in ("broker/core/core.go", "docs/AGENTS.md.bak", "XCLAUDE.md", "a/CLAUDE.md/x.go", "x.mcp.json"):
            self.assertEqual(premerge.mark_paths([f]), [], f)

    def test_cli_needs_mark(self):
        git(self.r, "checkout", "-q", "-b", "pr")
        run = lambda: subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--needs-mark", "--base", "main"],
                                     cwd=self.r, capture_output=True, text=True)
        self.write("b.txt", "x\n")
        self.commit("code")
        ok = run()
        self.assertEqual((ok.returncode, ok.stdout.strip()), (0, "agent"))
        (self.r / "CLAUDE.md").write_text("rules\n")
        self.commit("rules")
        bad = run()
        self.assertEqual((bad.returncode, bad.stdout.split()), (1, ["mark", "CLAUDE.md"]))

    def test_cli_needs_mark_in_any_position(self):
        git(self.r, "checkout", "-q", "-b", "pr")
        (self.r / "sub").mkdir()
        self.write("sub/CLAUDE.md", "rules\n")
        self.commit("nested rules")
        for argv in (["--needs-mark", "--base", "main"], ["--base", "main", "--needs-mark"],
                     ["--base", "main", "HEAD", "--needs-mark"]):
            r = subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), *argv],
                               cwd=self.r, capture_output=True, text=True)
            self.assertEqual((r.returncode, r.stdout.split()), (1, ["mark", "sub/CLAUDE.md"]), argv)

    def test_check_gate(self):
        import json
        git(self.r, "checkout", "-q", "-b", "pr")
        self.write("b.txt", "x\n")
        sha = self.commit("code")
        c = lambda verdict, sha, at, who="OWNER", pr=7, mark="<!-- record: l3 -->": {
            "author_association": who, "created_at": at,
            "body": f"Verdict: {verdict}\n# t\nRecord: PR #{pr} · package X-1 · head {sha[:7]}\n{mark}\n"}
        def run(comments, head="HEAD"):
            f = pathlib.Path(self._d.name + ".comments.json")
            self.addCleanup(lambda: f.unlink(missing_ok=True))
            f.write_text(json.dumps(comments))
            r = subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--check", str(f), "7", "--base", "main", head],
                               cwd=self.r, capture_output=True, text=True)
            return r.returncode, r.stdout.split()
        self.assertEqual(run([c("accept", sha, "1")]), (0, ["same"]))
        self.assertEqual(run([]), (1, ["no-verdict"]))
        # untrusted author, other PR, no L3 marker: none counts
        for bad in (c("accept", sha, "1", who="NONE"), c("accept", sha, "1", pr=8), c("accept", sha, "1", mark="")):
            self.assertEqual(run([bad]), (1, ["no-verdict"]))
        # a later fix-list supersedes the accept
        self.assertEqual(run([c("accept", sha, "1"), c("fix-list", sha, "2")]), (1, ["not-accepted"]))
        # a push after the accept reads as changed; a delta accept at the new head clears it
        self.write("b.txt", "y\n")
        new = self.commit("later")
        self.assertEqual(run([c("accept", sha, "1")]), (1, ["changed", "b.txt"]))
        self.assertEqual(run([c("accept", sha, "1"), c("accept", new, "2")]), (0, ["same"]))


if __name__ == "__main__":
    unittest.main()
