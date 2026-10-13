"""CX-name-case: reject new capitalized product text while old exclusions are swept.

The baseline records hashes of existing lines, not permission for more occurrences.
It can shrink as open PRs and peer-owned paths are corrected. Paths, identifiers,
historical quotations and generated records retain their existing spelling.
"""
import collections
import hashlib
import json
import pathlib
import re
import subprocess
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
BASELINE = pathlib.Path(__file__).with_name("product_name_baseline.json")
OLD_NAME = "Agent" + "OS"
PATTERN = re.compile(r"(?<![A-Za-z0-9_])" + OLD_NAME + r"(?![A-Za-z0-9_])")


def fingerprints(text):
    return collections.Counter(
        hashlib.sha256(line.encode()).hexdigest()
        for line in text.splitlines() if PATTERN.search(line)
    )


class ProductNameTest(unittest.TestCase):
    def test_new_product_text_fails(self):
        baseline = fingerprints("# " + OLD_NAME)
        self.assertTrue(fingerprints("New " + OLD_NAME) - baseline)

    def test_duplicate_legacy_line_fails(self):
        line = "# " + OLD_NAME
        self.assertTrue(fingerprints(line + "\n" + line) - fingerprints(line))

    def test_correct_name_and_identifiers_pass(self):
        self.assertFalse(fingerprints("agentOS " + OLD_NAME + "Box"))

    def test_deleting_legacy_text_passes(self):
        self.assertFalse(fingerprints("agentOS") - fingerprints(OLD_NAME))

    def test_tracked_text_has_no_new_capitalized_product_name(self):
        baseline = json.loads(BASELINE.read_text())
        paths = subprocess.check_output(
            ["git", "ls-files", "-z"], cwd=ROOT
        ).decode().split("\0")
        failures = []
        for name in paths:
            if not name:
                continue
            try:
                text = (ROOT / name).read_text()
            except (OSError, UnicodeError):
                continue
            extra = fingerprints(text) - collections.Counter(baseline.get(name, {}))
            if extra:
                failures.append(name)
        self.assertEqual(failures, [], "Use agentOS in new product text: " + ", ".join(failures))


if __name__ == "__main__":
    unittest.main()
