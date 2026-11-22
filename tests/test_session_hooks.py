"""Pins tools/session_hooks.py (#5692, #5702 L3 blocker 1).

REQ: EVL-5
A session that starts outside the checkout loads the close guard from the user's settings, and
`--check` says loudly when a session runs without it (ENV-session-hooks-unloaded, #6413).
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
MARK = '{ mkdir -p "%s" && : > "%s/${CLAUDE_CODE_SESSION_ID:-unknown}"; } 2>/dev/null; '


class SessionHooksTest(unittest.TestCase):
    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.settings = self.dir / ".claude/settings.json"
        self.marks = self.dir / "marks"

    def test_installs_the_close_guard_with_absolute_paths(self):
        merged = session_hooks.install(self.settings, marks=self.marks)
        mark = MARK % (self.marks, self.marks)
        project = json.loads((ROOT / ".claude/settings.json").read_text())["hooks"]["PreToolUse"][1]
        self.assertEqual(merged, {"hooks": {"PreToolUse": [{"matcher": project["matcher"], "hooks": [{
            "type": "command",
            "command": f'[ -f "{GUARD}" ] || exit 0; {mark}python3 "{GUARD}"'
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

    def run_installed(self, event, root, session="s1"):
        session_hooks.install(self.settings, root, self.marks)
        command = json.loads(self.settings.read_text())["hooks"]["PreToolUse"][-1]["hooks"][0]["command"]
        # Started from another directory, with no project directory pointing at the checkout.
        return subprocess.run(["sh", "-c", command], input=json.dumps(event), capture_output=True, text=True,
                              cwd=self.dir, env={"PATH": "/usr/bin:/bin", "CLAUDE_PROJECT_DIR": str(self.dir),
                                                 "CLAUDE_CODE_SESSION_ID": session})

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

    def check(self, session="s1", start="/home/user"):
        return session_hooks.check(self.settings, ROOT, self.marks, session, start)

    def test_check_fails_loudly_until_the_guard_has_run_in_this_session(self):
        code, says = self.check()
        self.assertEqual(code, 1)
        self.assertIn("not installed", says)
        self.assertIn("setup script", says)
        session_hooks.install(self.settings, marks=self.marks)
        code, says = self.check()
        # Installed after this session started (a preloaded spare reads its settings first): not loaded.
        self.assertEqual(code, 1)
        self.assertIn("not loaded in this session", says)
        out = self.run_installed({"tool_name": "Bash", "tool_input": {"command": "true"}}, ROOT)
        self.assertEqual((out.returncode, out.stdout), (0, ""))
        self.assertEqual(self.check()[0], 0)
        # Another session's mark does not count.
        self.assertEqual(self.check(session="s2")[0], 1)
        # No session id: it cannot tell, which is not a pass.
        self.assertEqual(self.check(session="")[0], 2)

    def test_check_reads_a_stale_or_edited_entry_as_not_installed(self):
        session_hooks.install(self.settings, marks=self.marks)
        settings = json.loads(self.settings.read_text())
        settings["hooks"]["PreToolUse"][-1]["hooks"][0]["command"] += " || true"
        self.settings.write_text(json.dumps(settings))
        code, says = self.check()
        self.assertEqual(code, 1)
        self.assertIn("not installed", says)

    def test_check_passes_a_session_started_in_the_checkout(self):
        # There the project's own settings.json loads the hook.
        self.assertEqual(self.check(session="", start=str(ROOT))[0], 0)

    def test_cli_check_exit_codes(self):
        env = {"PATH": "/usr/bin:/bin", "CLAUDE_CODE_SESSION_ID": "s9", "CLAUDE_PID": "0"}
        run = lambda: subprocess.run([sys.executable, str(ROOT / "tools/session_hooks.py"), "--settings",
                                      str(self.settings), "--marks", str(self.marks), "--check"],
                                     capture_output=True, text=True, env=env)
        done = run()
        self.assertEqual(done.returncode, 1)
        self.assertIn("close_guard", done.stderr)
        session_hooks.install(self.settings, marks=self.marks)
        (self.marks / "s9").parent.mkdir(parents=True, exist_ok=True)
        (self.marks / "s9").write_text("")
        done = run()
        self.assertEqual(done.returncode, 0, done.stderr)

    def test_cli_writes_the_named_file(self):
        done = subprocess.run([sys.executable, str(ROOT / "tools/session_hooks.py"), "--settings", str(self.settings)],
                              capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn(GUARD, self.settings.read_text())


if __name__ == "__main__":
    unittest.main()
