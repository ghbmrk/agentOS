"""Pins the PreToolUse hook .claude/hooks/gh_shape.py (OPERATING §7).

A call that a gh allow rule lets skip the permission ask skips it only in its exact shape;
any other call a rule matches goes to the ask.
"""
import importlib.util
import json
import pathlib
import subprocess
import sys
import unittest

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
]
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
        self.assertEqual(settings["hooks"], {"PreToolUse": [{"matcher": "Bash", "hooks": [{
            "type": "command",
            "command": 'python3 "$CLAUDE_PROJECT_DIR/.claude/hooks/gh_shape.py"'
                       ' || { echo "gh_shape hook failed" >&2; exit 2; }'}]}]})

    def test_hook_command_blocks_when_the_hook_cannot_run(self):
        settings = json.loads((ROOT / ".claude/settings.json").read_text())
        command = settings["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        done = subprocess.run(["sh", "-c", command], input="{}", capture_output=True, text=True,
                              env={"PATH": "/usr/bin:/bin", "CLAUDE_PROJECT_DIR": "/nonexistent"})
        self.assertEqual(done.returncode, 2)
        self.assertIn("gh_shape hook failed", done.stderr)

    def test_every_rule_has_a_good_example_and_every_good_example_is_guarded(self):
        for rule in gh_shape._RULE_RES:
            self.assertTrue(any(rule.search(c) for c in GOOD), rule.pattern)
        for c in GOOD:
            self.assertTrue(gh_shape.guarded(c), c)

    def test_exact_shapes_pass(self):
        for c in GOOD:
            self.assertIsNone(gh_shape.decide(c), c)
            self.assertIsNone(run_hook({"tool_name": "Bash", "tool_input": {"command": c}}), c)

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
