"""Pins the PreToolUse hook .claude/hooks/gh_shape.py (OPERATING §7).

A call that a gh allow rule lets skip the permission ask skips it only in its exact shape;
any other call a rule matches goes to the ask.
"""
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
HOOK = ROOT / ".claude/hooks/gh_shape.py"
spec = importlib.util.spec_from_file_location("gh_shape", HOOK)
gh_shape = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gh_shape)

R = "repos/ghbmrk/agentOS"
SHA = "a2c003f2" + "0" * 32
GOOD = [
    f"gh api -X PUT {R}/pulls/2518/ccr/auto_merge -f merge_method=merge",
    f"gh api -X DELETE {R}/pulls/2518/ccr/auto_merge",
    f"gh api -X PUT {R}/pulls/2518/merge -f merge_method=merge -f sha={SHA}",
    f"gh api -X POST {R}/issues/2525/labels -f labels[]=state:building",
    f"gh api -X DELETE {R}/issues/2525/labels/state:queued",
    f"gh api -X POST {R}/issues/7/labels -f labels[]=recheck",
]
# Exact draft-comment shapes: they pass only when draft_problem finds the file a lens draft for that PR.
DRAFT_GOOD = [
    f"gh api -X POST {R}/issues/5113/comments -F body=@/mnt/project-files/lens-drafts/5113.md",
    f"gh api -X POST {R}/issues/5113/comments -F body=@/mnt/project-files/lens-drafts/5113.md --jq .id",
]
BAD = [
    f"gh api -X PUT {R}/pulls/1/ccr/auto_merge -f merge_method=merge -F merge_method=squash",
    f"gh api -X PUT {R}/pulls/1/ccr/auto_merge -f merge_method=merge --input /tmp/x.json",
    f"gh api -X PUT {R}/pulls/1/merge -f merge_method=merge -f sha={SHA} -X PATCH",
    f"gh api -X PUT {R}/pulls/1/merge -f merge_method=merge -f sha=abc123",
    f"gh api -X PUT {R}/pulls/1/merge -f merge_method=merge -f sha={SHA.upper()}",
    f"gh api -X PUT {R}/pulls/1/merge -f merge_method=merge -f sha=@{SHA}",
    f"gh api -X PUT {R}/pulls/x/ccr/auto_merge -f merge_method=merge",
    f"gh api -X PUT {R}/pulls/0/ccr/auto_merge -f merge_method=merge",
    f"gh api -X PUT {R}/pulls/1 -f title=x {R}/pulls/1/ccr/auto_merge -f merge_method=merge",
    f"gh api -X DELETE {R}/pulls/1/ccr/auto_merge; rm -rf x",
    f"gh api -X DELETE {R}/pulls/1/ccr/auto_merge && gh api -X DELETE {R}/git/refs/heads/main",
    f"gh api -X DELETE {R}/pulls/$(cat n)/ccr/auto_merge",
    f"gh api -X DELETE {R}/issues/1/labels/x -X PATCH -f state=closed",
    f"gh api -X DELETE {R}/issues/1/labels/../comments/5",
    f"gh api -X DELETE {R}/issues/1/labels/x\ngh api -X DELETE {R}/issues/1/comments/5",
    f"gh api -X POST {R}/issues/1/labels -f labels[]=x -f body=forged",
    f"gh api -X POST {R}/issues/1/labels -f labels[]=@/etc/passwd",
    f"gh api -X POST {R}/issues/1/labels -f labels[]='state:in review'",
    f"gh api -X POST {R}/issues/1/labels -f labels[]=x -F labels[]=@f",
    f"gh api  -X DELETE {R}/pulls/1/ccr/auto_merge",
    f"cd /tmp && gh api -X DELETE {R}/pulls/1/ccr/auto_merge",
    f"gh api -X POST {R}/issues/1/labels -f labels[]=tier:A",
    f"gh api -X DELETE {R}/issues/1/labels/state:in%20review",
    f"gh api -X PUT {R}/pulls/1/merge -f merge_method=merge -f sha=$(git rev-parse HEAD)",
    f'grep -n "gh api -X DELETE {R}/pulls/.*/ccr/auto_merge" docs/OPERATING.md',
    f"gh api -X POST {R}/issues/1/comments -F body=@/mnt/project-files/lens-drafts/../x.md",
    f"gh api -X POST {R}/issues/1/comments -F body=@/mnt/project-files/lens-drafts/1.md -F x=@/etc/passwd",
    f"gh api -X POST {R}/issues/1/comments -F body=@/mnt/project-files/lens-drafts/1.txt",
    f"gh api -X POST {R}/issues/1/comments -F body=@/mnt/project-files/lens-drafts/1.md -X PATCH",
    f"gh api -X POST {R}/issues/1/comments -F body=@/mnt/project-files/lens-drafts/1.md --jq .body",
    f"gh api -X POST {R}/issues/1/comments -f body=@/mnt/project-files/lens-drafts/1.md",
]
HEAD = "050f8f4987529ca389134b0ddf50d027738d0496"
LENS_DRAFT = f"Verdict: accept\nRecord: PR #7 · package X · head {HEAD}\n<!-- record: ux -->\n<!-- record: potency -->\n\nBody.\n"
# Quoting, escaping and case the allow matcher might strip before it matches: still guarded.
EVASIONS = [
    f'gh api -X PUT "{R}/pulls/12/merge" -f merge_method=merge -f sha={SHA} -F body=@/etc/passwd',
    f"gh api -X 'PUT' {R}/pulls/1/ccr/auto_merge -f merge_method=merge -F x=@f",
    "gh api -X PUT repos/ghbmrk/agent''OS/pulls/1/ccr/auto_merge -f merge_method=merge --input f",
    "gh api -X PUT re\\pos/ghbmrk/agentOS/pulls/1/ccr/auto_merge -f merge_method=merge --input f",
    "gh api -X PUT repos/ghbmrk/agentOS/pulls/1/ccr/auto_\\\nmerge -f merge_method=merge --input f",
    "gh api -X put REPOS/GHBMRK/AGENTOS/pulls/1/ccr/auto_merge -f merge_method=merge --input f",
    "gh api -X PUT $'repos/ghbmrk/agentOS/pulls/1/ccr/auto_merge' -f merge_method=merge --input f",
    "gh api -X PUT repos/ghbmrk/agent$'OS'/pulls/1/ccr/auto_merge -f merge_method=merge --input f",
]
# Longer than the hook scans: a gh call this long goes to the ask, anything else passes (#2562).
LONG = 8 * 1024 + 1
PASS = ["ls -la", f"gh api {R}/pulls/1", "git push -u origin pkg/x", f"gh api {R}/issues/1/labels"]


def run_hook(event):
    out = subprocess.run([sys.executable, str(HOOK)], input=json.dumps(event),
                         capture_output=True, text=True, check=True).stdout
    return json.loads(out)["hookSpecificOutput"]["permissionDecision"] if out else None


class GhShapeHookTest(unittest.TestCase):
    def test_rules_are_the_gh_allow_rules_in_settings(self):
        settings = json.loads((ROOT / ".claude/settings.json").read_text())
        gh = [r[5:-1] for r in settings["permissions"]["allow"] if r.startswith("Bash(gh ")]
        self.assertEqual(gh, gh_shape.RULES)

    def test_hook_is_wired_for_every_bash_call(self):
        settings = json.loads((ROOT / ".claude/settings.json").read_text())
        # The first PreToolUse entry; tests/test_close_guard_hook.py pins the whole block.
        self.assertEqual(settings["hooks"]["PreToolUse"][0], {"matcher": "Bash", "hooks": [{
            "type": "command",
            "command": 'python3 "$CLAUDE_PROJECT_DIR/.claude/hooks/gh_shape.py"'
                       ' || { echo "gh_shape hook failed" >&2; exit 2; }'}]})

    def test_hook_command_blocks_when_the_hook_cannot_run(self):
        settings = json.loads((ROOT / ".claude/settings.json").read_text())
        command = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        done = subprocess.run(["sh", "-c", command], input="{}", capture_output=True, text=True,
                              env={"PATH": "/usr/bin:/bin", "CLAUDE_PROJECT_DIR": "/nonexistent"})
        self.assertEqual(done.returncode, 2)
        self.assertIn("gh_shape hook failed", done.stderr)

    def test_every_rule_has_a_good_example_and_every_good_example_is_guarded(self):
        for rule in gh_shape._RULE_RES:
            self.assertTrue(any(rule.search(c) for c in GOOD + DRAFT_GOOD), rule.pattern)
        for c in GOOD + DRAFT_GOOD:
            self.assertTrue(gh_shape.guarded(c), c)

    def test_exact_shapes_pass(self):
        for c in GOOD:
            self.assertIsNone(gh_shape.decide(c), c)
            self.assertIsNone(run_hook({"tool_name": "Bash", "tool_input": {"command": c}}), c)

    def test_draft_shapes_pass_only_for_a_lens_draft_of_that_pr(self):
        for c in DRAFT_GOOD:
            self.assertTrue(gh_shape.exact(c), c)
            with mock.patch.object(gh_shape, "draft_problem", return_value=None) as check:
                self.assertIsNone(gh_shape.decide(c), c)
            check.assert_called_once_with("5113", "/mnt/project-files/lens-drafts/5113.md")
            with mock.patch.object(gh_shape, "draft_problem", return_value="no"):
                self.assertIsNotNone(gh_shape.decide(c), c)
        # Another PR's draft on this issue goes to the ask before the file is read.
        other = f"gh api -X POST {R}/issues/1/comments -F body=@/mnt/project-files/lens-drafts/5128.md"
        self.assertTrue(gh_shape.exact(other))
        with mock.patch.object(gh_shape, "draft_problem", return_value=None):
            self.assertIn("not the draft for issue 1", gh_shape.decide(other))
        # With no draft file, the real hook asks.
        missing = f"gh api -X POST {R}/issues/9999999/comments -F body=@/mnt/project-files/lens-drafts/9999999.md"
        self.assertEqual(run_hook({"tool_name": "Bash", "tool_input": {"command": missing}}), "ask")

    def test_draft_problem_reads_only_a_plain_lens_draft(self):
        with tempfile.TemporaryDirectory() as tmp:
            real = os.path.realpath(tmp)
            drafts = os.path.join(real, "lens-drafts")
            os.mkdir(drafts)
            draft = os.path.join(drafts, "7.md")

            def check(text):
                with open(draft, "w") as f:
                    f.write(text)
                with mock.patch.object(gh_shape, "DRAFTS_REAL", drafts):
                    return gh_shape.draft_problem("7", draft)

            self.assertIsNone(check(LENS_DRAFT))
            self.assertIsNone(check(LENS_DRAFT.replace("<!-- record: potency -->\n", "")))
            for bad in (
                LENS_DRAFT.replace("ux", "l3"),
                LENS_DRAFT.replace("ux", "combined"),
                LENS_DRAFT.replace("ux", "security"),
                LENS_DRAFT + "<!-- record: security -->\n",
                LENS_DRAFT + "<!--record:l3-->\n",
                LENS_DRAFT.replace("PR #7", "PR #8"),
                LENS_DRAFT + f"Record: PR #8 · package X · head {HEAD}\n",
                LENS_DRAFT.replace("Verdict: accept\n", "Note\nVerdict: accept\n"),
                LENS_DRAFT.replace("<!-- record: ux -->\n<!-- record: potency -->\n", "") + "<!-- record: ux -->\n",
                f"Verdict: accept\nRecord: PR #7 · package X · head {HEAD}\n",
                "Verdict: accept\n" + "x" * gh_shape.MAX_DRAFT,
            ):
                self.assertIsNotNone(check(bad), bad[:120])
            # A link in place of the draft, or of a directory on its path, goes to the ask.
            canary = os.path.join(real, "canary.txt")
            with open(canary, "w") as f:
                f.write(LENS_DRAFT)
            os.remove(draft)
            os.symlink(canary, draft)
            with mock.patch.object(gh_shape, "DRAFTS_REAL", drafts):
                self.assertIn("link", gh_shape.draft_problem("7", draft))
            os.remove(draft)
            linked = os.path.join(real, "linked")
            os.symlink(drafts, linked)
            with open(draft, "w") as f:
                f.write(LENS_DRAFT)
            with mock.patch.object(gh_shape, "DRAFTS_REAL", os.path.join(linked, "")[:-1]):
                self.assertIn("link", gh_shape.draft_problem("7", os.path.join(linked, "7.md")))
            # A path that resolves elsewhere, a missing draft and a directory go to the ask.
            with mock.patch.object(gh_shape, "DRAFTS_REAL", drafts):
                self.assertIsNotNone(gh_shape.draft_problem("7", canary))
                self.assertIn("missing", gh_shape.draft_problem("8", os.path.join(drafts, "8.md")))
                os.mkdir(os.path.join(drafts, "9.md"))
                self.assertIsNotNone(gh_shape.draft_problem("9", os.path.join(drafts, "9.md")))
                # A FIFO goes to the ask without blocking the hook.
                os.mkfifo(os.path.join(drafts, "10.md"))
                self.assertIsNotNone(gh_shape.draft_problem("10", os.path.join(drafts, "10.md")))

    def test_an_error_in_the_draft_check_goes_to_the_ask(self):
        import io
        c = DRAFT_GOOD[0]
        out = io.StringIO()
        with mock.patch.object(gh_shape, "draft_problem", side_effect=RuntimeError("boom")), \
                mock.patch.object(sys, "stdin", io.StringIO(json.dumps(
                    {"tool_name": "Bash", "tool_input": {"command": c}}))), \
                mock.patch.object(sys, "stdout", out):
            gh_shape.main()
        self.assertEqual(json.loads(out.getvalue())["hookSpecificOutput"]["permissionDecision"], "ask")

    def test_guarded_calls_off_shape_go_to_the_ask(self):
        for c in BAD + EVASIONS:
            self.assertTrue(gh_shape.guarded(c), c)
            self.assertIsNotNone(gh_shape.decide(c), c)
            self.assertEqual(run_hook({"tool_name": "Bash", "tool_input": {"command": c}}), "ask", c)

    def test_unguarded_calls_pass_through(self):
        for c in PASS:
            self.assertIsNone(run_hook({"tool_name": "Bash", "tool_input": {"command": c}}), c)
        self.assertIsNone(run_hook({"tool_name": "Read", "tool_input": {"file_path": "/x"}}))

    def test_long_gh_commands_go_to_the_ask(self):
        pad = "x" * LONG
        for c in (f"gh api {R}/pulls/1 # {pad}", f"echo {pad}; g''h api {R}/pulls/1"):
            self.assertIsNotNone(gh_shape.decide(c), c[:40])
            self.assertEqual(run_hook({"tool_name": "Bash", "tool_input": {"command": c}}), "ask")
        self.assertIsNone(run_hook({"tool_name": "Bash", "tool_input": {"command": f"echo {pad}"}}))

    def test_long_commands_without_gh_api_pass(self):
        # #2720: "gh" alone (high, through, github) no longer sends a long command to the ask.
        prose = ("The high road through github is thoughtful. " * 250)[:LONG]
        for c in (f"echo '{prose}'", f"cat > notes.md <<'EOF'\n{prose}\nEOF"):
            self.assertGreater(len(c), gh_shape.MAX_SCAN)
            self.assertIsNone(gh_shape.decide(c), c[:40])
            self.assertIsNone(run_hook({"tool_name": "Bash", "tool_input": {"command": c}}))
        for c in (f"echo '{prose}'; g''h api {R}/pulls/1", f"echo '{prose}'; GH\\\n  API {R}/x",
                  f"echo '{prose}'; g\"h\" $'api' {R}/x"):
            self.assertIsNotNone(gh_shape.decide(c), c[-30:])
            self.assertEqual(run_hook({"tool_name": "Bash", "tool_input": {"command": c}}), "ask")
        self.assertIn("characters", gh_shape.decide(f"echo '{prose}'; gh api x"))

    def test_a_huge_command_is_decided_fast(self):
        import time
        c = "gh api -X PUT " + f"{R}/pulls/1/ccr/auto_merge " * 50000
        start = time.monotonic()
        self.assertIsNotNone(gh_shape.decide(c))
        self.assertLess(time.monotonic() - start, 5)

    def test_hook_asks_on_bad_input(self):
        out = subprocess.run([sys.executable, str(HOOK)], input="not json",
                             capture_output=True, text=True, check=True).stdout
        self.assertEqual(json.loads(out)["hookSpecificOutput"]["permissionDecision"], "ask")


if __name__ == "__main__":
    unittest.main()
