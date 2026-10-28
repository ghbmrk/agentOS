"""Tests for tools/require_ran.py: named tests must pass in a `go test -json` stream.

REQ: INFER-CI-2
No SPEC requirement IDs: CI tooling (briefs/INFER-CI.md; --gated and --named-skips-only: CI-root-go-2,
#3541). All data is synthetic.
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
import root_tests  # noqa: E402

PKG = "github.com/ghbmrk/agentos/broker/infer/supervise"
LEAF, OOM = "TestServiceRunsInInferenceLeaf", "TestServiceOOMStaysInLeaf"
QLEAF, QOOM = f"{PKG}.{LEAF}", f"{PKG}.{OOM}"


def stream(*events, pkg=PKG):
    lines = []
    for test, action in events:
        ev = {"Action": action, "Package": pkg}
        if test:
            ev["Test"] = test
        lines.append(json.dumps(ev))
        lines.append(json.dumps({"Action": "output", "Package": pkg, "Test": test,
                                 "Output": f"--- {action.upper()}: {test}\n"}))
    return "\n".join(lines) + "\n"


def run(text, *names):
    p = subprocess.run([sys.executable, str(ROOT / "tools" / "require_ran.py"), *names],
                       input=text, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


class RequireRanTest(unittest.TestCase):
    def test_pass_succeeds(self):
        code, out, err = run(stream((LEAF, "run"), (LEAF, "pass"), (OOM, "run"), (OOM, "pass"),
                                    (None, "pass")), QLEAF, QOOM)
        self.assertEqual(code, 0, err)
        self.assertIn(f"--- PASS: {LEAF}", out)  # the log still reads like go test -v

    def test_skip_fails(self):
        code, _, err = run(stream((LEAF, "run"), (LEAF, "skip"), (OOM, "run"), (OOM, "pass")),
                           QLEAF, QOOM)
        self.assertEqual(code, 1)
        self.assertIn(LEAF, err)

    def test_missing_fails(self):
        # A renamed or deleted test leaves no events at all.
        code, _, err = run(stream((OOM, "run"), (OOM, "pass"), (None, "pass")), QLEAF, QOOM)
        self.assertEqual(code, 1)
        self.assertIn(f"{QLEAF}: no pass", err)

    def test_fail_fails(self):
        code, _, _ = run(stream((LEAF, "run"), (LEAF, "fail"), (OOM, "pass")), QLEAF, QOOM)
        self.assertEqual(code, 1)

    def test_any_other_skip_fails(self):
        code, _, err = run(stream((LEAF, "pass"), (OOM, "pass"), ("TestServiceHasNoNetwork", "skip")),
                           QLEAF, QOOM)
        self.assertEqual(code, 1)
        self.assertIn(f"{PKG}.TestServiceHasNoNetwork: skipped", err)

    def test_subtest_pass_is_not_the_test(self):
        code, _, _ = run(stream((f"{LEAF}/case", "pass"), (OOM, "pass")), QLEAF, QOOM)
        self.assertEqual(code, 1)

    def test_garbage_and_no_names_fail(self):
        self.assertEqual(run("not json\n" + stream((LEAF, "pass")), QLEAF)[0], 1)
        self.assertEqual(run("[1]\n" + stream((LEAF, "pass")), QLEAF)[0], 1)
        self.assertEqual(run(stream((LEAF, "pass")))[0], 2)
        self.assertEqual(run(stream((LEAF, "pass")), LEAF)[0], 2)  # a name needs its package

    def test_same_name_in_another_package_is_not_the_test(self):
        other = stream((LEAF, "pass"), pkg="github.com/ghbmrk/agentos/broker/infer")
        code, _, err = run(other + stream((OOM, "pass")), QLEAF, QOOM)
        self.assertEqual(code, 1)
        self.assertIn(f"{QLEAF}: no pass", err)

    def test_package_level_skip_is_not_a_test_skip(self):
        # A package with no test files ends in a skip event with no Test.
        none = stream((None, "skip"), pkg="github.com/ghbmrk/agentos/broker/infer/notests")
        code, _, err = run(none + stream((LEAF, "pass"), (OOM, "pass"), (None, "pass")), QLEAF, QOOM)
        self.assertEqual(code, 0, err)
        # ...but a skipped package never passes the names it holds.
        code, _, err = run(stream((None, "skip")), QLEAF, QOOM)
        self.assertEqual(code, 1)
        self.assertIn(f"{QOOM}: no pass", err)

    def test_check_returns_problems(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(require_ran.check(stream((LEAF, "pass")).splitlines(), [QLEAF]), [])
            self.assertEqual(len(require_ran.check([], [QLEAF, QOOM])), 2)


class GatedTest(unittest.TestCase):
    """CI-root-go-2 (#3541): a whole-package root run names every root-gated test it holds."""

    def test_gated_names_every_root_gated_test_of_the_packages(self):
        gated = root_tests.gated_names(["./infer/..."])
        self.assertIn(QLEAF, gated)
        self.assertIn(f"{PKG}.TestServiceHasNoNetwork", gated)
        only_two = stream((LEAF, "pass"), (OOM, "pass"), (None, "pass"))
        code, _, err = run(only_two, "--gated", "./infer/...")
        self.assertEqual(code, 1)
        self.assertIn(f"{PKG}.TestServiceHasNoNetwork: no pass", err)
        everything = "".join(stream((n.rsplit(".", 1)[1], "pass")) for n in gated)
        self.assertEqual(run(everything, "--gated", "./infer/...")[0], 0)
        self.assertEqual(run(everything, QLEAF, "--gated", "./infer/...")[0], 0)

    def test_gated_with_no_root_gated_test_is_an_error(self):
        # An empty name list would pass anything, so a pattern that names nothing fails the step.
        self.assertEqual(run(stream((LEAF, "pass")), "--gated", "./no/such/package")[0], 2)
        self.assertEqual(run(stream((LEAF, "pass")), "--gated")[0], 2)
        self.assertEqual(run(stream((LEAF, "pass")), QLEAF, "--gated", "./no/such/package")[0], 2)

    def test_named_skips_only(self):
        other = stream((LEAF, "pass"), ("TestQuota/ext4", "skip"), ("TestQuota", "pass"))
        self.assertEqual(run(other, QLEAF)[0], 1)
        self.assertEqual(run(other, "--named-skips-only", QLEAF)[0], 0)
        sub = stream((f"{LEAF}/case", "skip"), (LEAF, "pass"))
        code, _, err = run(sub, "--named-skips-only", QLEAF)
        self.assertEqual(code, 1)
        self.assertIn(f"{QLEAF}/case: skipped", err)
        self.assertEqual(run(stream((LEAF, "skip")), "--named-skips-only", QLEAF)[0], 1)


if __name__ == "__main__":
    unittest.main()
