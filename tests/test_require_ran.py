"""Tests for tools/require_ran.py: named tests must pass in a `go test -json` stream.

REQ: INFER-CI-2
No SPEC requirement IDs: CI tooling (briefs/INFER-CI.md). All data is synthetic.
"""
import io
import json
import pathlib
import subprocess
import sys
import unittest
from contextlib import redirect_stdout

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import require_ran  # noqa: E402

PKG = "agentos/broker/infer/supervise"
LEAF, OOM = "TestServiceRunsInInferenceLeaf", "TestServiceOOMStaysInLeaf"


def stream(*events):
    lines = []
    for test, action in events:
        ev = {"Action": action, "Package": PKG}
        if test:
            ev["Test"] = test
        lines.append(json.dumps(ev))
        lines.append(json.dumps({"Action": "output", "Package": PKG, "Test": test,
                                 "Output": f"--- {action.upper()}: {test}\n"}))
    return "\n".join(lines) + "\n"


def run(text, *names):
    p = subprocess.run([sys.executable, str(ROOT / "tools" / "require_ran.py"), *names],
                       input=text, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


class RequireRanTest(unittest.TestCase):
    def test_pass_succeeds(self):
        code, out, err = run(stream((LEAF, "run"), (LEAF, "pass"), (OOM, "run"), (OOM, "pass"),
                                    (None, "pass")), LEAF, OOM)
        self.assertEqual(code, 0, err)
        self.assertIn(f"--- PASS: {LEAF}", out)  # the log still reads like go test -v

    def test_skip_fails(self):
        code, _, err = run(stream((LEAF, "run"), (LEAF, "skip"), (OOM, "run"), (OOM, "pass")),
                           LEAF, OOM)
        self.assertEqual(code, 1)
        self.assertIn(LEAF, err)

    def test_missing_fails(self):
        # A renamed or deleted test leaves no events at all.
        code, _, err = run(stream((OOM, "run"), (OOM, "pass"), (None, "pass")), LEAF, OOM)
        self.assertEqual(code, 1)
        self.assertIn(f"{LEAF}: no pass", err)

    def test_fail_fails(self):
        code, _, _ = run(stream((LEAF, "run"), (LEAF, "fail"), (OOM, "pass")), LEAF, OOM)
        self.assertEqual(code, 1)

    def test_any_other_skip_fails(self):
        code, _, err = run(stream((LEAF, "pass"), (OOM, "pass"), ("TestServiceHasNoNetwork", "skip")),
                           LEAF, OOM)
        self.assertEqual(code, 1)
        self.assertIn(f"{PKG}.TestServiceHasNoNetwork: skipped", err)

    def test_subtest_pass_is_not_the_test(self):
        code, _, _ = run(stream((f"{LEAF}/case", "pass"), (OOM, "pass")), LEAF, OOM)
        self.assertEqual(code, 1)

    def test_garbage_and_no_names_fail(self):
        self.assertEqual(run("not json\n" + stream((LEAF, "pass")), LEAF)[0], 1)
        self.assertEqual(run("[1]\n" + stream((LEAF, "pass")), LEAF)[0], 1)
        self.assertEqual(run(stream((LEAF, "pass")))[0], 2)

    def test_check_returns_problems(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(require_ran.check(stream((LEAF, "pass")).splitlines(), [LEAF]), [])
            self.assertEqual(len(require_ran.check([], [LEAF, OOM])), 2)


if __name__ == "__main__":
    unittest.main()
