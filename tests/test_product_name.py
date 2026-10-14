"""CX-name-case: reject new capitalized product text while old exclusions are swept.

Only lines a branch adds are checked (merge base with origin/main). The baseline records hashes of existing lines, not permission for more occurrences.
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


def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True)


def whole_tree():
    out = {}
    for name in git("ls-files", "-z").stdout.decode().split("\0"):
        try:
            out[name] = (ROOT / name).read_text() if name else ""
        except (OSError, UnicodeError):
            continue
    return out


def added_lines():
    """Added lines per file since the merge base with origin/main; None if unavailable."""
    base = git("merge-base", "HEAD", "origin/main")
    if base.returncode:
        return None
    diff = git("diff", "-U0", "--no-color", base.stdout.decode().strip(), "HEAD")
    if diff.returncode:
        return None
    out, name = {}, None
    for line in diff.stdout.decode(errors="replace").splitlines():
        if line.startswith("+++ "):
            name = line[6:] if line.startswith("+++ b/") else None
        elif name and line.startswith("+"):
            out[name] = out.get(name, "") + line[1:] + "\n"
    return out


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

    def test_changed_lines_have_no_new_capitalized_product_name(self):
        """Only lines this branch adds count: drift arriving from main is not its fault.

        Baseline still absolves moved legacy lines. Without origin/main (shallow
        checkout) the whole tree is checked against the baseline instead.
        """
        baseline = json.loads(BASELINE.read_text())
        added = added_lines()
        if added is None:
            added = whole_tree()
        failures = [
            name for name, text in added.items()
            if fingerprints(text) - collections.Counter(baseline.get(name, {}))
        ]
        self.assertEqual(failures, [], "Use agentOS in new product text: " + ", ".join(failures))


if __name__ == "__main__":
    unittest.main()
