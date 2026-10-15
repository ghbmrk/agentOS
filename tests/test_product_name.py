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


def read_text(name):
    try:
        return (ROOT / name).read_text()
    except (OSError, UnicodeError):
        return ""


def whole_tree():
    return {n: read_text(n) for n in git("ls-files", "-z").stdout.decode().split("\0") if n}


def added_lines():
    """Added lines per file since the merge base with origin/main.

    None when there is no usable branch diff (no origin/main, HEAD is the merge
    base as on main itself, or an empty diff): the caller then checks the whole tree.
    """
    base = git("merge-base", "HEAD", "origin/main")
    head = git("rev-parse", "HEAD")
    if base.returncode or head.returncode or base.stdout == head.stdout:
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
    return out or None


def violations(baseline, added, texts):
    """Files over their baseline. A file the branch adds old-name text to is counted
    whole, so a duplicate of an allowlisted line still fails; other files are ignored.
    added None means no branch diff: every file is counted."""
    names = texts if added is None else [n for n, t in added.items() if fingerprints(t)]
    return [
        n for n in names
        if fingerprints(texts[n]) - collections.Counter(baseline.get(n, {}))
    ]


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

    def test_added_duplicate_of_baseline_line_fails(self):
        line = "# " + OLD_NAME
        baseline = {"a.md": dict(fingerprints(line))}
        added = {"a.md": line + "\n"}
        self.assertEqual(violations(baseline, added, {"a.md": line + "\n" + line}), ["a.md"])
        self.assertEqual(violations(baseline, None, {"a.md": line}), [])

    def test_drift_in_untouched_file_ignored_on_branch_only(self):
        texts = {"drift.md": "# " + OLD_NAME, "b.md": "agentOS"}
        self.assertEqual(violations({}, {"b.md": "agentOS\n"}, texts), [])
        self.assertEqual(violations({}, None, texts), ["drift.md"])

    def test_no_branch_diff_checks_whole_tree(self):
        # On main the merge base is HEAD, so added_lines() must not report an empty diff.
        if git("rev-parse", "HEAD").stdout == git("rev-parse", "origin/main").stdout:
            self.assertIsNone(added_lines())

    def test_tracked_text_has_no_new_capitalized_product_name(self):
        """Only files this branch adds old-name text to are counted: drift arriving from
        main is not its fault. Without a branch diff the whole tree is checked."""
        baseline = json.loads(BASELINE.read_text())
        added = added_lines()
        texts = whole_tree() if added is None else {n: read_text(n) for n in added}
        failures = violations(baseline, added, texts)
        self.assertEqual(failures, [], "Use agentOS in new product text: " + ", ".join(failures))


if __name__ == "__main__":
    unittest.main()
