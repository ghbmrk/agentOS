"""Pins the narrowness of the gh allow rules in .claude/settings.json (OPERATING §7).

The arm, disarm and pinned-merge calls may skip the permission ask, nothing else on gh does.
"""
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent

GH_RULES = {
    "Bash(gh api -X PUT repos/ghbmrk/agentOS/pulls/*/ccr/auto_merge -f merge_method=merge)",
    "Bash(gh api -X DELETE repos/ghbmrk/agentOS/pulls/*/ccr/auto_merge)",
    "Bash(gh api -X PUT repos/ghbmrk/agentOS/pulls/*/merge -f merge_method=merge -f sha=*)",
}
MCP_RULES = {"mcp__github__enable_pr_auto_merge", "mcp__github__disable_pr_auto_merge"}


class ClaudeSettingsTest(unittest.TestCase):
    def allow(self):
        return json.loads((ROOT / ".claude/settings.json").read_text())["permissions"]["allow"]

    def test_gh_rules_are_only_the_pinned_calls(self):
        for rule in self.allow():
            if rule.startswith("Bash(gh"):
                self.assertIn(rule, GH_RULES)

    def test_no_wildcard_after_the_endpoint_but_the_sha(self):
        # A trailing ` *` would let a caller add -f/-F/--input fields or a second -X to an allowed call.
        for rule in GH_RULES:
            self.assertFalse(rule.endswith(" *)"), rule)

    def test_mcp_rules_are_only_auto_merge(self):
        for rule in self.allow():
            if rule.startswith("mcp__"):
                self.assertIn(rule, MCP_RULES)


if __name__ == "__main__":
    unittest.main()
