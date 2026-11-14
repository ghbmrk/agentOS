"""Pins the PreToolUse hook .claude/hooks/close_guard.py (VULN-accept-close-guard, #5692).

REQ: EVL-5
A session's close of an issue that assurance/vulncheck.json cites is denied, because the close
withdraws the acceptance and fails image-vulncheck on every PR until the queued reopen runs.
"""
import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
HOOK = ROOT / ".claude/hooks/close_guard.py"
spec = importlib.util.spec_from_file_location("close_guard", HOOK)
close_guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(close_guard)

R = "repos/ghbmrk/agentOS"


def tree(issues):
    """A temporary checkout with a config citing `issues`, and no git."""
    d = pathlib.Path(tempfile.mkdtemp())
    (d / "assurance").mkdir()
    (d / "assurance/vulncheck.json").write_text(json.dumps(
        {"accepted": [{"id": f"V{n}", "issue": n} for n in issues]}))
    return d


def bash(c):
    return {"tool_name": "Bash", "tool_input": {"command": c}}


def mcp(num, state="closed", tool="mcp__github__issue_write", owner="ghbmrk", repo="agentOS"):
    return {"tool_name": tool, "tool_input": {"method": "update", "owner": owner, "repo": repo,
                                              "issue_number": num, "state": state}}


class CloseGuardTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tree([5660])

    def verdict(self, event):
        v = close_guard.decide(event, self.root)
        return v and v[0]

    def test_cited_closes_are_denied(self):
        # #5660 was closed by a merge cleanup through the MCP issue tool (#5692).
        for e in (mcp(5660), mcp(5660, tool="mcp__github__update_issue"), mcp(5660, owner="GHBMRK", repo="agentos"),
                  bash("gh issue close 5660"), bash("gh issue close '#5660' --reason completed"),
                  bash("gh issue close -c done 5660"), bash("gh issue close 5692; gh issue close 5660"),
                  bash("gh issue close https://github.com/ghbmrk/agentOS/issues/5660"),
                  # gh's repository flag goes before the subcommand too (#5702 Security 1).
                  bash("gh issue -R ghbmrk/agentOS close 5660"), bash("gh issue --repo=ghbmrk/agentOS close 5660"),
                  bash(f"gh api -X PATCH {R}/issues/5660 -f state=closed"),
                  bash(f"echo hi && gh api -X PATCH {R}/issues/5660 -f state=closed -f state_reason=completed"),
                  bash(f"curl -X PATCH https://api.github.com/{R}/issues/5660 -d '{{\"state\": \"closed\"}}'")):
            self.assertEqual(self.verdict(e), "deny", e)
        reason = close_guard.decide(mcp(5660), self.root)[1]
        self.assertIn("#5660 (1 record(s))", reason)
        self.assertIn("state:merged", reason)

    def test_uncited_closes_and_other_calls_pass(self):
        for e in (mcp(5692), mcp(5660, state="open"), mcp(5660, repo="other"),
                  {"tool_name": "mcp__github__issue_write", "tool_input": {"method": "update", "owner": "ghbmrk",
                                                                          "repo": "agentOS", "issue_number": 5660,
                                                                          "labels": ["state:merged"]}},
                  bash("gh issue close 5692"), bash(f"gh api -X PATCH {R}/issues/5692 -f state=closed"),
                  bash(f"gh api {R}/issues?state=closed"), bash("gh issue list --state closed"),
                  bash(f"gh api -X POST {R}/issues/5660/labels -f labels[]=state:merged"),
                  bash(f"gh api -X POST {R}/issues/5660/comments --input body.json"),
                  bash("git status"), {"tool_name": "Read", "tool_input": {"file_path": "/x"}}):
            self.assertIsNone(close_guard.decide(e, self.root), e)

    def test_unreadable_close_target_asks(self):
        # The body of an --input call on an issue, and GraphQL's closeIssue, are not read (#5702 Security 2).
        for e in (bash(f"gh api -X PATCH {R}/issues/5660 --input body.json"),
                  bash(f"echo '{{\"state\":\"closed\"}}' | gh api -X PATCH {R}/issues/5692 --input -"),
                  bash("gh api graphql -f query='mutation{closeIssue(input:{issueId:\"I_x\"}){clientMutationId}}'"),
                  bash('gh issue close "$N"'), bash('gh issue close 5692 && gh issue close "$N"'), bash("gh issue close"), mcp("5660"), mcp(None)):
            self.assertEqual(self.verdict(e), "ask", e)

    def test_unreadable_close_asks_only_where_run(self):
        # VULN-close-guard-cmdpos (#5705): `gh issue close` with no readable number inside data, such
        # as a commit message, closes nothing and must not stall an unattended session at the ask.
        for c in ('git commit -m "docs: run gh issue close N only after cited"',
                  "git commit -m \"$(cat <<'EOF'\nfix: guard\n\ngh issue close N only after cited\nEOF\n)\"",
                  "echo gh issue close N", "> gh issue close $N", "grep -n 'gh issue close' tools/x.py 2>&1 | head",
                  'git commit -m "don\'t run gh issue close N"', "cat <<'EOF' > n.md\ngh issue close N\nEOF",
                  "grep -rn 'gh issue close' .", "printf '%s\\n' 'gh issue close \"$N\"; echo'"):
            self.assertIsNone(close_guard.decide(bash(c), self.root), c)
        # A cited number at every command position, and in a string a nested shell runs, denies.
        for c in ("bash -c 'gh issue close 5660'", 'sh -c "echo x; gh issue close 5660"',
                  "bash -c $'gh issue close 5660'", "bash -c $'echo x\\ngh issue close 5660'",
                  'bash -c "bash -c \'gh issue close 5660\'"', 'ssh host "cd x && gh issue close 5660"',
                  "GH_TOKEN=x gh issue close 5660", "sudo -u u gh issue close 5660", "env -i gh issue close 5660",
                  "xargs -n1 gh issue close <<< 5660 && gh issue close 5660", "/usr/bin/gh issue close 5660",
                  "(gh issue close 5660)", "echo $(gh issue close 5660)", "echo `gh issue close 5660`",
                  "x | gh issue close 5660", "false || gh issue close 5660", "echo hi\ngh issue close 5660",
                  "2>/dev/null gh issue close 5660", "> log gh issue close 5660", "{ gh issue close 5660; }",
                  "if true; then gh issue close 5660; fi", "gh issue -Rghbmrk/agentOS close 5660",
                  "gh issue close 5660 'unterminated", "cat <<EOF\n$(gh issue close 5660)\nEOF",
                  "git commit -m \"x; gh issue close 5660\"", "grep 'gh issue close 5660' x",
                  "bash <<'EOF'\ngh issue close 5660\nEOF", "cat <<'EOF'\nnotes\nEOF\ngh issue close 5660",
                  # A literal cited number denies wherever it stands, wrapper known or not.
                  "echo gh issue close 5660", "retry gh issue close 5660", "find . -exec gh issue close 5660 \\;"):
            self.assertEqual(self.verdict(bash(c)), "deny", c)
        for c in ("bash -c 'gh issue close \"$N\"'", "sudo gh issue close", "xargs gh issue close",
                  "bash <<'EOF'\ngh issue close \"$N\"\nEOF", "ssh h 'cd x && gh issue close $N'",
                  "sudo -u u bash -c \"bash -c 'gh issue close \\$N'\"", "nice -n 5 gh issue close $N",
                  "find . -exec gh issue close $N \\;"):
            self.assertEqual(self.verdict(bash(c)), "ask", c)

    def test_origin_main_records_also_guard(self):
        # A checkout older than a new record still guards it: origin/main's file counts too.
        d = tree([])
        git = ["git", "-C", str(d), "-c", "user.name=t", "-c", "user.email=t@example.invalid"]
        subprocess.run(git + ["init", "-q"], check=True)
        (d / "assurance/vulncheck.json").write_text(json.dumps({"accepted": [{"id": "V", "issue": 77}]}))
        subprocess.run(git + ["add", "-A"], check=True)
        subprocess.run(git + ["commit", "-qm", "x"], check=True)
        subprocess.run(git + ["update-ref", "refs/remotes/origin/main", "HEAD"], check=True)
        (d / "assurance/vulncheck.json").write_text(json.dumps({"accepted": []}))
        self.assertEqual(close_guard.decide(mcp(77), d)[0], "deny")
        # A record in both the working tree and origin/main counts once (#5702 L3 R1).
        (d / "assurance/vulncheck.json").write_text(json.dumps({"accepted": [{"id": "V", "issue": 77}]}))
        self.assertIn("#77 (1 record(s))", close_guard.decide(mcp(77), d)[1])

    def test_hook_process_output(self):
        def run(event, root):
            env = {"PATH": "/usr/bin:/bin"}
            hook = root / ".claude/hooks/close_guard.py"
            hook.parent.mkdir(parents=True, exist_ok=True)
            hook.write_text(HOOK.read_text())
            return subprocess.run([sys.executable, str(hook)], input=json.dumps(event), capture_output=True,
                                  text=True, env=env, timeout=30)
        out = run(mcp(5660), self.root)
        self.assertEqual(json.loads(out.stdout)["hookSpecificOutput"]["permissionDecision"], "deny")
        self.assertEqual(run(mcp(5692), self.root).stdout, "")
        broken = tree([])
        (broken / "assurance/vulncheck.json").write_text("{not json")
        out = run(mcp(5660), broken)
        self.assertEqual(json.loads(out.stdout)["hookSpecificOutput"]["permissionDecision"], "ask")
        self.assertEqual(run(bash("git status"), broken).stdout, "")

    def test_cited_matches_vulncheck(self):
        sys.path.insert(0, str(ROOT / "tools"))
        import vulncheck
        recs = [{"issue": 7}, {"issue": 7}, {"issue": 8}, {}, {"issue": "7"}]
        for n in (7, 8, 9):
            self.assertEqual(close_guard.cited(recs, n), vulncheck.cited(recs, n))

    def test_hook_block_is_pinned(self):
        settings = json.loads((ROOT / ".claude/settings.json").read_text())
        self.assertEqual(settings["hooks"], {"PreToolUse": [
            {"matcher": "Bash", "hooks": [{
                "type": "command",
                "command": 'python3 "$CLAUDE_PROJECT_DIR/.claude/hooks/gh_shape.py"'
                           ' || { echo "gh_shape hook failed" >&2; exit 2; }'}]},
            {"matcher": "Bash|mcp__github__issue_write|mcp__github__update_issue", "hooks": [{
                "type": "command",
                "command": 'python3 "$CLAUDE_PROJECT_DIR/.claude/hooks/close_guard.py"'
                           ' || { echo "close_guard hook failed" >&2; exit 2; }'}]}]})

    def test_hook_command_blocks_when_the_hook_cannot_run(self):
        settings = json.loads((ROOT / ".claude/settings.json").read_text())
        command = settings["hooks"]["PreToolUse"][1]["hooks"][0]["command"]
        done = subprocess.run(["sh", "-c", command], input="{}", capture_output=True, text=True,
                              env={"PATH": "/usr/bin:/bin", "CLAUDE_PROJECT_DIR": "/nonexistent"})
        self.assertEqual(done.returncode, 2)
        self.assertIn("close_guard hook failed", done.stderr)


if __name__ == "__main__":
    unittest.main()
