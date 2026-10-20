"""Pins the permissions block of .claude/settings.json (OPERATING §7).

The allow rules only save a permission ask; the required premerge status is the merge gate.
Any change to the block, wider or not, fails here and so needs its own reviewed PR.
"""
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent

PERMISSIONS = {
    "allow": [
        "Bash(git commit:*)",
        "Bash(git push:*)",
        "Bash(gh api -X PUT repos/ghbmrk/agentOS/pulls/*/ccr/auto_merge -f merge_method=merge)",
        "Bash(gh api -X DELETE repos/ghbmrk/agentOS/pulls/*/ccr/auto_merge)",
        "Bash(gh api -X PUT repos/ghbmrk/agentOS/pulls/*/merge -f merge_method=merge -f sha=*)",
    ]
}


class ClaudeSettingsTest(unittest.TestCase):
    def test_permissions_are_exactly_the_pinned_block(self):
        settings = json.loads((ROOT / ".claude/settings.json").read_text())
        self.assertEqual(settings.get("permissions"), PERMISSIONS)


if __name__ == "__main__":
    unittest.main()
