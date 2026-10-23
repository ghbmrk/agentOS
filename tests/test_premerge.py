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

    def test_assumptions_renumbering_only_is_same_but_text_edit_is_changed(self):
        rows = "| N1 | first | basis |\n| N2 | second | basis |\n"
        git(self.r, "checkout", "-q", "main")
        self.write("ASSUMPTIONS.md", "| # | A |\n|---|---|\n" + rows)
        self.commit("assumptions")
        reviewed = self.pr()
        self.write("ASSUMPTIONS.md", self.read("ASSUMPTIONS.md") + "| N3 | mine | basis |\n")
        reviewed = self.commit("pr row")
        self.write("ASSUMPTIONS.md", self.read("ASSUMPTIONS.md").replace("| N3 |", "| N4 |"))
        self.commit("renumbered")
        self.assertEqual(self.check(reviewed), [])
        self.write("ASSUMPTIONS.md", self.read("ASSUMPTIONS.md").replace("mine", "changed"))
        self.commit("text edit")
        self.assertEqual(self.check(reviewed), ["ASSUMPTIONS.md"])

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
                  "tools/g1_scope.py", "tools/g1_scope.txt", "docs/LANES.md", "tools/trace.py", "tools/old_core.txt",
                  # #2438: this gate's own tests and the lens rules need the Security accept too.
                  "tests/test_premerge.py", "tests/test_premerge_lens.py", "reviews/l3/README.md",
                  "reviews/security/README.md", "reviews/ux/README.txt"):
            self.assertEqual(premerge.mark_paths([f]), [f], f)
        # The other gate tests stay as narrowed on Mark's "Narrow only" (2026-10-16).
        for f in ("tools/records.py", "reviews/l3/2026-10-15-pr1.md", "README.md", "docs/OTHER.md", "src/claude/x.go",
                  "reviews/README.md", "reviews/a/b/README.md", "tests/x/test_premerge.py", "tests/test_risk_tier.py",
                  "tests/test_ci_scope.py", "tests/test_g1_scope.py", "tests/test_workflows.py", "tests/test_merge_queue.py",
                  "tests/test_lane.py"):
            self.assertEqual(premerge.mark_paths([f]), [], f)

    def test_mark_paths_cover_agent_config_and_tier_inputs(self):
        # Security R3 on #1824: MCP config, other teams' rules, nested CLAUDE files, and the
        # core list tools/risk_tier.py reads to set tiers.
        self.assertTrue((ROOT / "broker/core/core.txt").is_file())
        self.assertIn("core.txt", (ROOT / "tools/risk_tier.py").read_text())
        for f in (".mcp.json", "AGENTS.md", "CLAUDE.local.md", "broker/CLAUDE.md", "a/b/CLAUDE.local.md",
                  "broker/core/core.txt"):
            self.assertEqual(premerge.mark_paths([f]), [f], f)
        # PREMERGE-paths (#1835): nested config and newline-bearing paths.
        for f in ("sub/AGENTS.md", "sub/.mcp.json", "sub/.claude/settings.json", "a/b/.claude/x",
                  "x\n/.claude/y", ".github/a\nb", "tools/premerge.py"):
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

    def test_cli_needs_mark_rejects_a_second_positional(self):
        # `--needs-mark origin/main pr` read origin/main as the head and printed `agent` for any PR.
        git(self.r, "checkout", "-q", "-b", "pr")
        self.write("CLAUDE.md", "rules\n")
        self.commit("rules")
        r = subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--needs-mark", "main", "pr"],
                           cwd=self.r, capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertNotIn("agent", r.stdout.split())

    def test_cli_needs_mark_rejects_an_empty_range(self):
        # `--needs-mark origin/main` read origin/main as the head: base..base is empty and printed `agent`.
        git(self.r, "checkout", "-q", "-b", "pr")
        self.write("CLAUDE.md", "rules\n")
        self.commit("rules")
        git(self.r, "update-ref", "refs/remotes/origin/main", "main")
        r = subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--needs-mark", "origin/main"],
                           cwd=self.r, capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertNotIn("agent", r.stdout.split())

    def needs_mark(self, head="pr"):
        r = subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--needs-mark", "--base", "main", head],
                           cwd=self.r, capture_output=True, text=True)
        return r.returncode, r.stdout.split()

    def test_cli_needs_mark_sees_a_revert_made_by_a_criss_cross_merge(self):
        # #2138: with two merge bases, `git merge-base` picked the one where the head's CLAUDE.md was
        # unchanged, so a PR whose merge reverts main's CLAUDE.md printed `agent`.
        self.write("CLAUDE.md", "v0\n")
        m0 = self.commit("m0")
        git(self.r, "checkout", "-q", "-b", "side")
        self.write("CLAUDE.md", "v1\n")
        m2 = self.commit("m2")
        git(self.r, "checkout", "-q", "main")
        self.write("b.txt", "m1\n")
        m1 = self.commit("m1")
        git(self.r, "checkout", "-q", "-b", "pr", m1)
        git(self.r, "merge", "-q", "--no-edit", m2)
        self.write("CLAUDE.md", "v0\n")
        self.write("a.txt", "pr\n")
        git(self.r, "add", "."), git(self.r, "commit", "-q", "--amend", "--no-edit")
        git(self.r, "checkout", "-q", "main")
        git(self.r, "merge", "-q", "--no-edit", m2)
        self.assertEqual(len(git(self.r, "merge-base", "--all", "main", "pr").split()), 2, m0)
        merged = git(self.r, "merge-tree", "--write-tree", "main", "pr")
        self.assertEqual(git(self.r, "show", f"{merged}:CLAUDE.md"), "v0")  # the merge reverts main's v1
        self.assertEqual(self.needs_mark(), (1, ["mark", "CLAUDE.md"]))

    def test_cli_needs_mark_sees_a_mark_file_the_merge_resolves_in_conflict(self):
        # #2138: a conflicted merge-tree keeps its markers, so the conflicted file still reads as changed.
        git(self.r, "checkout", "-q", "-b", "pr")
        self.write("CLAUDE.md", "pr\n")
        self.commit("pr rules")
        git(self.r, "checkout", "-q", "main")
        self.write("CLAUDE.md", "main\n")
        self.commit("main rules")
        self.assertEqual(self.needs_mark(), (1, ["mark", "CLAUDE.md"]))

    def test_cli_needs_mark_sees_a_claude_symlink(self):
        # #2138: `.claude/` needed a slash, so `broker/.claude -> ../cfg` plus cfg/settings.json printed `agent`.
        git(self.r, "checkout", "-q", "-b", "pr")
        (self.r / "cfg").mkdir()
        (self.r / "broker").mkdir()
        self.write("cfg/settings.json", "{}\n")
        (self.r / "broker/.claude").symlink_to("../cfg")
        self.commit("linked settings")
        self.assertEqual(self.needs_mark(), (1, ["mark", "broker/.claude"]))
        for f in (".claude", "a/.claude", "a/.claude/x"):
            self.assertEqual(premerge.mark_paths([f]), [f], f)
        for f in (".claudex", "a/.claude.bak", "a/x.claude", ".claude\n"):
            self.assertEqual(premerge.mark_paths([f]), [], repr(f))

    def test_check_gate(self):
        import json
        git(self.r, "checkout", "-q", "-b", "pr")
        self.write("b.md", "x\n")  # top-level *.md: tier C, so no lens screen is owed
        sha = self.commit("code")
        c = lambda verdict, sha, at, who="OWNER", pr=7, mark="<!-- record: l3 -->": {
            "author_association": who, "created_at": at, "updated_at": at,
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
        # an edited verdict is never an accept and still supersedes the earlier one; only a fresh comment replaces it
        edited = lambda x: {**x, "updated_at": "9"}
        self.assertEqual(run([edited(c("accept", sha, "1"))]), (1, ["not-accepted"]))
        self.assertEqual(run([c("accept", sha, "1"), edited(c("fix-list", sha, "2"))]), (1, ["not-accepted"]))
        self.assertEqual(run([edited(c("accept", sha, "1")), c("accept", sha, "2")]), (0, ["same"]))
        missing = {k: v for k, v in c("accept", sha, "1").items() if k != "updated_at"}
        self.assertEqual(run([missing]), (1, ["not-accepted"]))
        self.assertEqual(run([{**c("accept", sha, "1"), "updated_at": "1"}]), (0, ["same"]))
        # a later fix-list supersedes the accept
        self.assertEqual(run([c("accept", sha, "1"), c("fix-list", sha, "2")]), (1, ["not-accepted"]))
        # a push after the accept reads as changed; a delta accept at the new head clears it
        self.write("b.md", "y\n")
        new = self.commit("later")
        self.assertEqual(run([c("accept", sha, "1")]), (1, ["changed", "b.md"]))
        self.assertEqual(run([c("accept", sha, "1"), c("accept", new, "2")]), (0, ["same"]))

    def test_check_gate_spec_needs_nothing_extra(self):
        # D-137 supersedes D-130: a SPEC.md change merges on its accepts alone, with no Transcribes: line.
        # SPEC.md is tier B, so those are L3 plus the combined pass (#2644), which one comment may carry.
        import json
        git(self.r, "checkout", "-q", "-b", "pr")
        self.write("SPEC.md", "spec\n")
        sha = self.commit("spec")
        f = pathlib.Path(self._d.name + ".comments.json")
        self.addCleanup(lambda: f.unlink(missing_ok=True))
        def run(mark):
            f.write_text(json.dumps([{"author_association": "OWNER", "created_at": "1", "updated_at": "1",
                "body": f"Verdict: accept\n# t\nRecord: PR #7 · package X-1 · head {sha[:7]}\n{mark}\n"}]))
            r = subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--check", str(f), "7", "--base", "main"],
                               cwd=self.r, capture_output=True, text=True)
            return r.returncode, r.stdout.split()
        self.assertEqual(run("<!-- record: l3 -->"), (1, ["needs-lens", "combined"]))
        self.assertEqual(run("<!-- record: combined -->"), (0, ["same"]))

    def test_check_gate_files_need_a_separate_security_accept(self):
        # D-137: a PR touching a --needs-mark path also needs the newest trusted Security verdict, in a comment
        # without an l3/combined marker, to accept a head whose diff equals this one.
        import json
        git(self.r, "checkout", "-q", "-b", "pr")
        (self.r / "docs").mkdir()
        self.write("docs/OPERATING.md", "rules\n")
        sha = self.commit("gate")
        rec = lambda v, head, marks, who="OWNER", at="1", pr=7: {"author_association": who, "created_at": at, "updated_at": at,
            "body": f"Verdict: {v}\n# t\nRecord: PR #{pr} · package X-1 · head {head[:7]}\n{marks}"}
        l3 = rec("accept", sha, "<!-- record: combined -->\n", at="0")
        sec = lambda v="accept", head=sha, **k: rec(v, head, "<!-- record: security -->\n", **k)
        def run(comments):
            f = pathlib.Path(self._d.name + ".comments.json")
            self.addCleanup(lambda: f.unlink(missing_ok=True))
            f.write_text(json.dumps(comments))
            r = subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--check", str(f), "7", "--base", "main"],
                               cwd=self.r, capture_output=True, text=True)
            return r.returncode, r.stdout.split()
        need = (1, ["needs-security", "docs/OPERATING.md"])
        self.assertEqual(run([l3]), need)
        self.assertEqual(run([l3, sec()]), (0, ["same"]))
        # untrusted author, other PR, fix-list, unknown head: none counts
        self.assertEqual(run([l3, sec(who="NONE")]), need)
        self.assertEqual(run([l3, sec(pr=8)]), need)
        self.assertEqual(run([l3, sec("fix-list")]), need)
        self.assertEqual(run([l3, sec(head="0" * 40)]), need)
        # an edited Security accept is not an accept, and an edited Security fix-list still supersedes an earlier accept
        self.assertEqual(run([l3, {**sec(), "updated_at": "9"}]), need)
        self.assertEqual(run([l3, sec(at="1"), {**sec("fix-list", at="2"), "updated_at": "9"}]), need)
        self.assertEqual(run([l3, {**sec(at="1"), "updated_at": "9"}, sec(at="2")]), (0, ["same"]))
        # one comment carrying both markers is one review: it counts as the L3 accept, not the Security one
        both = rec("accept", sha, "<!-- record: security -->\n<!-- record: combined -->\n")
        self.assertEqual(run([both]), need)
        # a later Security fix-list supersedes the accept; a later accept clears it
        self.assertEqual(run([l3, sec(at="1"), sec("fix-list", at="2")]), need)
        self.assertEqual(run([l3, sec("fix-list", at="1"), sec(at="2")]), (0, ["same"]))
        # main merged in after the accept: the Security accept carries
        git(self.r, "checkout", "-q", "main")
        self.write("b.txt", "main\n")
        self.commit("main moves")
        git(self.r, "checkout", "-q", "pr")
        git(self.r, "merge", "-q", "--no-edit", "main")
        self.assertEqual(run([l3, sec()]), (0, ["same"]))
        # a push after the Security accept: the L3 delta accept alone is not enough
        self.write("docs/OPERATING.md", "looser rules\n")
        new = self.commit("later")
        self.assertEqual(run([l3, sec(), rec("accept", new, "<!-- record: combined -->\n", at="2")]), need)
        self.assertEqual(run([l3, sec(), rec("accept", new, "<!-- record: combined -->\n", at="2"),
                              sec(head=new, at="3")]), (0, ["same"]))

    def test_bot_gate(self):
        # PREMERGE-wire (#1860): the generated-file bot PRs carry no L3 verdict, so `--bot` passes
        # them only when the branch is a known bot branch and the diff is that bot's file alone.
        git(self.r, "checkout", "-q", "-b", "pr")
        def run(ref):
            r = subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--bot", ref, "--base", "main"],
                               cwd=self.r, capture_output=True, text=True)
            return r.returncode, r.stdout.split()
        self.assertEqual(run("bot/trace"), (1, ["not-bot"]))  # empty change
        self.write("TRACE.md", "t\n")
        self.commit("trace")
        self.assertEqual(run("bot/trace"), (0, ["bot"]))
        for ref in ("bot/metrics", "bot/board"):  # another bot's file
            self.assertEqual(run(ref), (1, ["not-bot", "TRACE.md"]), ref)
        # not a bot branch; bot/records went with records.yml (#2235)
        for ref in ("pkg/x", "bot/trace2", "xbot/trace", "bot/trace/x", "bot/records"):
            self.assertEqual(run(ref), (1, ["not-bot"]), ref)
        self.write("b.txt", "x\n")
        self.commit("smuggled code")
        self.assertEqual(run("bot/trace"), (1, ["not-bot", "b.txt"]))

    def test_bot_gate_records_is_gone(self):
        # #2235: records.yml was its only writer, so a bot/records branch of new review files is hand-made and needs a verdict.
        self.assertNotIn("bot/records", premerge.BOT)
        git(self.r, "checkout", "-q", "-b", "pr")
        (self.r / "reviews/security").mkdir(parents=True)
        self.write("reviews/security/2026-10-15-pr2.md", "fabricated\n")
        self.commit("records")
        r = subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--bot", "bot/records", "--base", "main"],
                           cwd=self.r, capture_output=True, text=True)
        self.assertEqual((r.returncode, r.stdout.split()), (1, ["not-bot"]))

    def lens_run(self, comments):
        import json
        f = pathlib.Path(self._d.name + ".comments.json")
        self.addCleanup(lambda: f.unlink(missing_ok=True))
        f.write_text(json.dumps(comments))
        r = subprocess.run([sys.executable, str(ROOT / "tools/premerge.py"), "--check", str(f), "7", "--base", "main"],
                           cwd=self.r, capture_output=True, text=True)
        return r.returncode, r.stdout.split()

    @staticmethod
    def rec(v, head, marks, who="OWNER", at="1", pr=7):
        return {"author_association": who, "created_at": at, "updated_at": at,
                "body": f"Verdict: {v}\n# t\nRecord: PR #{pr} · package X-1 · head {head[:7]}\n{marks}"}

    def test_check_gate_tier_a_needs_ux_and_potency(self):
        # PREMERGE-lens (#2644): #2628 and #2632 were tier A and merged on L3 and Security alone.
        git(self.r, "checkout", "-q", "-b", "pr")
        (self.r / "image").mkdir()
        self.write("image/build.sh", "true\n")
        sha = self.commit("tier A")
        self.assertEqual(premerge.lenses_owed(["image/build.sh"]), ["ux", "potency"])
        l3 = self.rec("accept", sha, "<!-- record: l3 -->\n", at="0")
        ux = lambda v="accept", head=sha, **k: self.rec(v, head, "<!-- record: ux -->\n", **k)
        pot = lambda v="accept", head=sha, **k: self.rec(v, head, "<!-- record: potency -->\n", **k)
        run = self.lens_run
        self.assertEqual(run([l3]), (1, ["needs-lens", "ux,potency"]))
        self.assertEqual(run([l3, ux()]), (1, ["needs-lens", "potency"]))
        self.assertEqual(run([l3, pot()]), (1, ["needs-lens", "ux"]))
        self.assertEqual(run([l3, ux(), pot()]), (0, ["same"]))
        # one comment carrying both markers covers both lenses
        both = self.rec("accept", sha, "<!-- record: ux -->\n<!-- record: potency -->\n")
        self.assertEqual(run([l3, both]), (0, ["same"]))
        # untrusted, other PR, fix-list, edited, unknown head, superseded: none counts
        for bad in (ux(who="NONE"), ux(pr=8), ux("fix-list"), {**ux(), "updated_at": "9"}, ux(head="0" * 40)):
            self.assertEqual(run([l3, bad, pot()]), (1, ["needs-lens", "ux"]), bad)
        self.assertEqual(run([l3, ux(at="1"), ux("fix-list", at="2"), pot()]), (1, ["needs-lens", "ux"]))
        # a marker that is not on its own line is not a marker
        inline = self.rec("accept", sha, "see <!-- record: ux --> above\n")
        self.assertEqual(run([l3, inline, pot()]), (1, ["needs-lens", "ux"]))
        # main merged in after the accepts: they carry; a later push needs fresh lens accepts
        git(self.r, "checkout", "-q", "main")
        self.write("b.txt", "main\n")
        self.commit("main moves")
        git(self.r, "checkout", "-q", "pr")
        git(self.r, "merge", "-q", "--no-edit", "main")
        self.assertEqual(run([l3, ux(), pot()]), (0, ["same"]))
        self.write("image/build.sh", "false\n")
        new = self.commit("later")
        l3new = self.rec("accept", new, "<!-- record: l3 -->\n", at="2")
        self.assertEqual(run([l3, ux(), pot(), l3new]), (1, ["needs-lens", "ux,potency"]))
        self.assertEqual(run([l3, ux(), pot(), l3new, ux(head=new, at="3"), pot(head=new, at="3")]), (0, ["same"]))

    def test_check_gate_lens_comes_before_security(self):
        # A tier-A gate-file PR owes both; the lens screen is reported first, then the Security accept.
        git(self.r, "checkout", "-q", "-b", "pr")
        (self.r / "tools").mkdir()
        self.write("tools/premerge.py", "x\n")
        sha = self.commit("gate")
        l3 = self.rec("accept", sha, "<!-- record: l3 -->\n", at="0")
        lens = self.rec("accept", sha, "<!-- record: ux -->\n<!-- record: potency -->\n")
        self.assertEqual(self.lens_run([l3]), (1, ["needs-lens", "ux,potency"]))
        self.assertEqual(self.lens_run([l3, lens]), (1, ["needs-security", "tools/premerge.py"]))
        sec = self.rec("accept", sha, "<!-- record: security -->\n", at="2")
        self.assertEqual(self.lens_run([l3, lens, sec]), (0, ["same"]))

    def test_lenses_owed_by_tier(self):
        owed = premerge.lenses_owed
        self.assertEqual(owed(["b.md", "docs/x.md"]), [])  # tier C
        self.assertEqual(owed(["SPEC.md"]), ["combined"])  # tier B
        self.assertEqual(owed(["b.txt", "b.md"]), ["combined"])  # unmatched path: B
        self.assertEqual(owed(["image/build.sh", "SPEC.md"]), ["ux", "potency"])  # highest tier wins
        # D-086: a tier-A diff confined to assurance tooling owes potency only
        for files in (["tools/depaudit.py"], ["tools/canary.py", "tests/test_canary.py"], ["assurance/dep-targets.json"],
                      ["tools/risk_tier.py", "tests/test_risk_tier_custody.py"]):
            self.assertEqual(owed(files), ["potency"], files)
        for files in (["tools/canary.py", "image/build.sh"], ["tools/canary.py", "b.md"], ["tools/premerge.py"]):
            self.assertEqual(owed(files), ["ux", "potency"], files)


if __name__ == "__main__":
    unittest.main()
