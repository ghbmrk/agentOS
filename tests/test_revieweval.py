"""Tests for tools/revieweval.py and the review-noise and rounds-by-head parts of tools/metrics.py.

REQ: REVIEW-eval-1, REVIEW-eval-2, REVIEW-eval-3, REVIEW-eval-4
All data is synthetic.
"""
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import metrics  # noqa: E402
import test_metrics  # noqa: E402
import revieweval as ev  # noqa: E402

FIX = """--- a/a.go
+++ b/a.go
@@ -10,4 +10,3 @@ func f
 ctx
-bad1
-bad2
 ctx
@@ -30,2 +29,3 @@
 ctx
+added
 ctx
--- a/new.go
+++ b/new.go
@@ -0,0 +1,2 @@
+x
+y
"""


class EvalTest(unittest.TestCase):
    def test_expected_ranges_are_old_side_lines_of_the_fix(self):  # REQ: REVIEW-eval-1
        got = ev.expected_ranges(FIX)
        self.assertEqual(got["a.go"], [(11, 12), (30, 30)])
        self.assertEqual(got["new.go"], [(1, 1)])

    def test_case_scoring(self):  # REQ: REVIEW-eval-1
        case = {"kind": "defect", "expected": {"a.go": [[11, 12]]}}
        self.assertEqual(ev.score_case(case, [{"file": "a.go", "line": 12, "class": "blocker"}]),
                         {"caught": True, "false_blockers": 0})
        self.assertEqual(ev.score_case(case, [{"file": "a.go", "line": 40}]),
                         {"caught": False, "false_blockers": 1})
        clean = {"kind": "clean"}
        self.assertEqual(ev.score_case(clean, [{"file": "a", "line": 1, "class": "later"}]),
                         {"caught": None, "false_blockers": 0})
        self.assertEqual(ev.score_case(clean, [{"file": "a", "line": 1, "class": "blocker"}])["false_blockers"], 1)

    def test_build_pairs_fix_pr_with_the_pr_that_introduced_the_defect(self):  # REQ: REVIEW-eval-1
        pulls = [{"number": 5, "title": "CRED-1: store", "body": "", "merged": True, "reviewed_head": "abc1234"},
                 {"number": 9, "title": "CRED-1-f1: fix", "body": "Defect: CRED-1\n", "merged": True},
                 {"number": 6, "title": "OTHER-1: clean", "body": "", "merged": True}]
        diffs = {"intro:5": "diff5", "fix:9": FIX, "intro:6": "diff6"}
        cases, defective = ev.build_cases(pulls, diffs)
        self.assertEqual([(c["id"], c["head"], c["diff"]) for c in cases], [("pr5-fix9", "abc1234", "diff5")])
        self.assertEqual(defective, [5])
        self.assertEqual(ev.add_clean(pulls, diffs, [6], defective)[0]["id"], "pr6-clean")
        with self.assertRaises(SystemExit):
            ev.add_clean(pulls, diffs, [5], defective)

    def test_change_is_kept_only_when_the_score_rises(self):  # REQ: REVIEW-eval-2
        old = {"caught": 3, "false_blockers": 2}
        self.assertTrue(ev.keep(old, {"caught": 4, "false_blockers": 2}))
        self.assertTrue(ev.keep(old, {"caught": 3, "false_blockers": 1}))
        self.assertFalse(ev.keep(old, dict(old)))
        self.assertFalse(ev.keep(old, {"caught": 4, "false_blockers": 3}))
        self.assertFalse(ev.keep(old, {"caught": 2, "false_blockers": 0}))

    def test_runner_and_cli_round_trip(self):  # REQ: REVIEW-eval-2
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            case = {"id": "x", "kind": "defect", "diff": "d", "expected": {"a.go": [[1, 2]]}}
            (d / "x.json").write_text(json.dumps(case))
            cmd = "cat >/dev/null; echo '[{\"file\":\"a.go\",\"line\":2,\"class\":\"blocker\"}]'"
            out = d / "s.json"
            self.assertEqual(ev.main(["score", "--cases", str(d), "--cmd", cmd, "--out", str(out)]), 0)
            self.assertEqual(json.loads(out.read_text())["caught"], 1)


class NoiseAndRoundsTest(unittest.TestCase):
    def test_noise_lines(self):  # REQ: REVIEW-eval-3
        body = "Finding blocker: fixed\n- Finding blocker: wrong, reviewer misread\nFinding later: didn't matter\nFinding nit: fixed\n"
        self.assertEqual(metrics.noise([body]),
                         [("blocker", "fixed"), ("blocker", "wrong"), ("later", "didn't-matter")])

    def test_metrics_line_gives_share_of_blockers_not_fixed(self):  # REQ: REVIEW-eval-3
        raw = test_metrics.raw_fixture()
        raw["pulls"][1]["noise"] = [("blocker", "fixed"), ("blocker", "wrong"), ("later", "wrong")]
        self.assertIn("Blockers not fixed (review noise, `wrong`, `intentional` or `didn't-matter`): 50% (1/2)",
                      metrics.render(metrics.compute(raw), raw))

    def test_rounds_count_distinct_reviewed_heads(self):  # REQ: REVIEW-eval-4
        a = "Verdict: fix-list\n# t\nRecord: PR #1 · package X · head abc1234"
        b = "Verdict: accept\n# L3 t\nRecord: PR #1 · package X · head def5678"
        sec = "Verdict: accept\n# Security\nRecord: PR #1 · package X · head def5678"
        again = "Verdict: accept\nRecord: PR #1 · package X · head def5678901234"
        self.assertEqual(metrics.count_rounds([a, b, sec, again]), 2)
        self.assertEqual(metrics.count_rounds(["Verdict: accept", "Verdict: accept (L3)"]), 2)

    def test_collect_counts_rounds_by_head_and_reads_builder_finding_lines(self):  # REQ: REVIEW-eval-4, REVIEW-eval-3
        def api(repo, path, token):
            if path.startswith("pulls?"):
                return [{"number": 7, "merged_at": "2026-10-05T01:00:00Z", "body": ""}] if "page=1&" in path + "&" else []
            if path.startswith("pulls/7/reviews"):
                return [{"body": "Verdict: fix-list\nCause: defect\nL3 head abc1234", "submitted_at": "1", "author_association": "OWNER"},
                        {"body": "Verdict: accept\nL3 head def5678", "submitted_at": "2", "author_association": "OWNER"},
                        {"body": "Verdict: accept\nL3 security head def5678", "submitted_at": "3", "author_association": "OWNER"}]
            if path.startswith("issues/7/comments"):
                return [{"body": "L3 fixed it.\nFinding blocker: fixed", "created_at": "2", "author_association": "OWNER"}] if "page=1&" in path + "&" else []
            if path.startswith("actions/runs?"):
                return {"workflow_runs": []}
            raise AssertionError(path)

        orig = metrics._api
        metrics._api = api
        try:
            pulls, _ = metrics.collect_github("o/r", None)
        finally:
            metrics._api = orig
        self.assertEqual((pulls[0]["verdicts"], pulls[0]["rounds"]), (["fix-list", "accept", "accept"], 2))
        self.assertEqual(pulls[0]["noise"], [("blocker", "fixed")])


if __name__ == "__main__":
    unittest.main()
