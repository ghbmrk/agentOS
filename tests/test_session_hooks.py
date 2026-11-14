"""Pins tools/session_hooks.py (#5692, #5702 L3 blocker 1).

REQ: EVL-5
A session that starts outside the checkout loads the close guard from the user's settings.
"""
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import session_hooks  # noqa: E402

GUARD = f"{ROOT}/.claude/hooks/close_guard.py"


class SessionHooksTest(unittest.TestCase):
    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.settings = self.dir / ".claude/settings.json"

    def test_installs_the_close_guard_with_absolute_paths(self):
        merged = session_hooks.install(self.settings)
        project = json.loads((ROOT / ".claude/settings.json").read_text())["hooks"]["PreToolUse"][1]
        self.assertEqual(merged, {"hooks": {"PreToolUse": [{"matcher": project["matcher"], "hooks": [{
            "type": "command",
            "command": f'[ -f "{GUARD}" ] || exit 0; python3 "{GUARD}"'
                       ' || { echo "close_guard hook failed" >&2; exit 2; }'}]}]}})
        self.assertEqual(json.loads(self.settings.read_text()), merged)

    def test_keeps_other_settings_and_is_idempotent(self):
        self.settings.parent.mkdir(parents=True)
        other = {"matcher": "", "hooks": [{"type": "command", "command": "~/.claude/other.sh"}]}
        self.settings.write_text(json.dumps({"model": "x", "hooks": {"PreToolUse": [other], "Stop": [other]}}))
        once = session_hooks.install(self.settings)
        twice = session_hooks.install(self.settings)
        self.assertEqual(once, twice)
        self.assertEqual(twice["model"], "x")
        self.assertEqual(twice["hooks"]["Stop"], [other])
        self.assertEqual(twice["hooks"]["PreToolUse"][0], other)
        self.assertEqual(len(twice["hooks"]["PreToolUse"]), 2)

    def run_installed(self, event, root):
        session_hooks.install(self.settings, root)
        command = json.loads(self.settings.read_text())["hooks"]["PreToolUse"][-1]["hooks"][0]["command"]
        # Started from another directory, with no project directory pointing at the checkout.
        return subprocess.run(["sh", "-c", command], input=json.dumps(event), capture_output=True, text=True,
                              cwd=self.dir, env={"PATH": "/usr/bin:/bin", "CLAUDE_PROJECT_DIR": str(self.dir)})

    def test_installed_command_denies_a_cited_close_from_outside_the_checkout(self):
        root = pathlib.Path(tempfile.mkdtemp())
        (root / ".claude/hooks").mkdir(parents=True)
        (root / ".claude/settings.json").write_text((ROOT / ".claude/settings.json").read_text())
        (root / ".claude/hooks/close_guard.py").write_text(pathlib.Path(GUARD).read_text())
        (root / "assurance").mkdir()
        (root / "assurance/vulncheck.json").write_text(json.dumps({"accepted": [{"id": "V", "issue": 5660}]}))
        event = {"tool_name": "mcp__github__issue_write",
                 "tool_input": {"owner": "ghbmrk", "repo": "agentOS", "issue_number": 5660, "state": "closed"}}
        out = self.run_installed(event, root)
        self.assertEqual(json.loads(out.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")
        # A checkout without the hook file passes, so a stale container never blocks every call.
        (root / ".claude/hooks/close_guard.py").unlink()
        out = self.run_installed(event, root)
        self.assertEqual((out.returncode, out.stdout), (0, ""))
        # A hook file that cannot run fails closed, as the project entry does.
        (root / ".claude/hooks/close_guard.py").write_text("raise SystemExit(1)\n")
        out = self.run_installed(event, root)
        self.assertEqual(out.returncode, 2)

    def test_cli_writes_the_named_file(self):
        done = subprocess.run([sys.executable, str(ROOT / "tools/session_hooks.py"), "--settings", str(self.settings)],
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn(GUARD, self.settings.read_text())


if __name__ == "__main__":
    unittest.main()
