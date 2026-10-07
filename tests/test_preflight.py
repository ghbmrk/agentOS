import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))
import preflight as pf  # noqa: E402

# Split so this file does not itself claim coverage.
MARK = "RE" "Q:"


BODY = """
## Trace
| Requirement ID | Test | Result |
|---|---|---|
| OP-1 | tests/t.py | pass |
| `HW-5a` | broker/t_test.go | pass |

## Defect
"""

BODY_EMPTY = """
## Trace
| Requirement ID | Test | Result |
|---|---|---|
|  |  |  |
"""


class PreflightTest(unittest.TestCase):
    def test_parses_trace_table_only(self):
        self.assertEqual(pf.trace_ids(BODY), ["OP-1", "HW-5a"])
        self.assertEqual(pf.trace_ids(BODY_EMPTY), [])
        self.assertEqual(pf.trace_ids("OP-9 is mentioned but not tabulated"), [])
        self.assertEqual(pf.trace_ids(""), [])

    def test_known_and_marked(self):
        known = {"OP-1", "OP-9", "HW-5a"}
        self.assertEqual(pf.check(["OP-1"], known, {"OP-1"}, set(), []), [])
        self.assertEqual(pf.check(["OP-1"], known, set(), {"OP-1"}, []), [])
        errs = pf.check(["OP-9"], known, set(), set(), [])
        self.assertEqual(len(errs), 1)
        self.assertIn("OP-9", errs[0])
        errs = pf.check(["NO-1"], known, set(), set(), [])
        self.assertIn("not a requirement ID", errs[0])

    def test_private_key_line_fails(self):
        header = "-----BEGIN " + "RSA PRIVATE KEY-----"
        errs = pf.check([], {"OP-1"}, set(), set(), ["note", header])
        self.assertTrue(errs)

    def test_event_body(self):
        d = pathlib.Path(tempfile.mkdtemp())
        (d / "ev.json").write_text(json.dumps({"pull_request": {"body": BODY}}))
        self.assertEqual(pf.body_from_event(d / "ev.json"), BODY)

    def test_cli_git(self):
        d = pathlib.Path(tempfile.mkdtemp())
        env = os.environ.copy()
        env.update({
            "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
            "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com",
        })
        def git(*a):
            subprocess.check_call(["git", *a], cwd=d, env=env)

        git("init", "-q")
        (d / "SPEC.md").write_text("- **OP-1** one\n- **OP-9** nine\n")
        (d / "tests").mkdir()
        (d / "tests/old.py").write_text("# " + MARK + " OP-1\n")
        git("add", ".")
        git("commit", "-q", "-m", "base")
        base = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=d, text=True).strip()
        (d / "tests/new.py").write_text("# " + MARK + " OP-9\n")
        git("add", ".")
        git("commit", "-q", "-m", "add")
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=d, text=True).strip()
        body = d / "pr.md"
        body.write_text("## Trace\n| Requirement ID | Test | Result |\n|---|---|---|\n| OP-9 | tests/new.py | pass |\n")
        rc = subprocess.call(
            [sys.executable, str(pathlib.Path(pf.__file__)),
             "--body-file", str(body), "--diff-base", base, "--diff-head", head, "--root", str(d)],
            cwd=d,
        )
        self.assertEqual(rc, 0)
        body.write_text("## Trace\n| Requirement ID | Test | Result |\n|---|---|---|\n| OP-9 | missing | pass |\n| NO-1 | x | fail |\n")
        # Reset the new file's marker so OP-9 is not in the diff, and it is not on the base.
        (d / "tests/new.py").write_text("# nothing\n")
        git("add", ".")
        git("commit", "-q", "-m", "drop marker")
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=d, text=True).strip()
        rc = subprocess.call(
            [sys.executable, str(pathlib.Path(pf.__file__)),
             "--body-file", str(body), "--diff-base", base, "--diff-head", head, "--root", str(d)],
            cwd=d,
        )
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
