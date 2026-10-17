"""tools/mutgate.py: the REQ-claim gate over gremlins results (MUT-tierA, #1814).

Gremlins itself is not run: the gate reads its JSON, so fixtures stand in for it.
"""
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import mutgate  # noqa: E402

DIFF = """\
diff --git a/broker/hint/hint.go b/broker/hint/hint.go
--- a/broker/hint/hint.go
+++ b/broker/hint/hint.go
@@ -10,0 +11,2 @@ func f() {
+\tif x > 1 {
+\t}
diff --git a/broker/hint/hint_test.go b/broker/hint/hint_test.go
--- a/broker/hint/hint_test.go
+++ b/broker/hint/hint_test.go
@@ -1,0 +2 @@
+// REQ: CRED-1
"""
LIVE = {"hint": [("hint.go", 11, "CONDITIONALS_BOUNDARY"), ("hint.go", 40, "CONDITIONALS_NEGATION")]}


class Gate(unittest.TestCase):
    def test_live_mutant_on_added_line_in_claimed_package_fails(self):
        self.assertEqual(
            mutgate.violations(DIFF, LIVE),
            [("hint", "broker/hint/hint.go", 11, "CONDITIONALS_BOUNDARY")],
        )

    def test_no_marker_no_claim(self):
        self.assertEqual(mutgate.violations(DIFF.replace("REQ:", "NOTE:"), LIVE), [])

    def test_survivor_on_untouched_line_or_other_package_passes(self):
        self.assertEqual(mutgate.violations(DIFF, {"hint": [("hint.go", 40, "X")]}), [])
        self.assertEqual(mutgate.violations(DIFF, {"mail": [("hint.go", 11, "X")]}), [])

    def test_survivor_in_a_test_file_is_not_counted(self):
        self.assertEqual(mutgate.violations(DIFF, {"hint": [("hint_test.go", 2, "X")]}), [])

    def test_added_lines_follow_hunk_numbers(self):
        added, marked = mutgate.added_lines(DIFF)
        self.assertEqual(added["broker/hint/hint.go"], {11, 12})
        self.assertEqual(marked, {"broker/hint/hint_test.go"})

    def test_survivors_reads_lived_only_and_nested_package_names(self):
        with tempfile.TemporaryDirectory() as d:
            data = {"files": [{"file_name": "a.go", "mutations": [
                {"type": "T", "status": "LIVED", "line": 3},
                {"type": "T", "status": "KILLED", "line": 4}]}]}
            (pathlib.Path(d) / "vm__gvisor.json").write_text(json.dumps(data))
            self.assertEqual(mutgate.survivors(d), {"vm/gvisor": [("a.go", 3, "T")]})
            self.assertEqual(mutgate.package_of("broker/vm/gvisor/a.go"), "vm/gvisor")

    def test_tier_a_packages_are_tier_a(self):
        pkgs = mutgate.tier_a_packages()
        self.assertIn("netguard", pkgs)
        self.assertNotIn("quota", pkgs)

    def test_report_and_cli(self):
        with tempfile.TemporaryDirectory() as d:
            (pathlib.Path(d) / "hint.json").write_text(json.dumps(
                {"files": [{"file_name": "h.go", "mutations": [{"type": "T", "status": "LIVED", "line": 9}]}]}))
            r = subprocess.run([sys.executable, str(ROOT / "tools" / "mutgate.py"), "report", d],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0)
            self.assertIn("hint: 1 surviving", r.stdout)
            self.assertIn("h.go:9 T", r.stdout)


if __name__ == "__main__":
    unittest.main()
