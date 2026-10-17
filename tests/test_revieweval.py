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

INTRO = """diff --git a/a.go b/a.go
--- a/a.go
+++ b/a.go
@@ -1,2 +1,2 @@
+x
"""

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

    def test_stored_diff_respells_old_product_name_keeping_line_length(self):  # REQ: REVIEW-eval-1
        old = "Agent" + "OS"
        out = ev.respell("+# " + old + " docs\n+" + old + "Box\n")
        self.assertEqual(out, "+# agentOS docs\n+" + old + "Box\n")

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

    def test_later_findings_never_catch(self):  # REQ: REVIEW-eval-2
        case = {"kind": "defect", "expected": {"a.go": [[11, 12]]}}
        spam = [{"file": "a.go", "line": n, "class": c} for n in range(1, 60) for c in ("later", "release")]
        self.assertEqual(ev.score_case(case, spam), {"caught": False, "false_blockers": 0})

    def test_build_pairs_fix_pr_with_the_pr_that_introduced_the_defect(self):  # REQ: REVIEW-eval-1
        pulls = [{"number": 5, "title": "CRED-1: store", "body": "", "merged_at": "2026-10-01", "reviewed_head": "abc1234"},
                 {"number": 9, "title": "CRED-1-f1: fix", "body": "Defect: CRED-1\n", "merged_at": "2026-10-03"},
                 {"number": 6, "title": "OTHER-1: clean", "body": "", "merged_at": "2026-10-02"}]
        diffs = {"intro:5": INTRO, "fix:9": FIX, "intro:6": "diff6"}
        cases, defective = ev.build_cases(pulls, diffs)
        self.assertEqual([(c["id"], c["head"], c["diff"]) for c in cases], [("pr5", "abc1234", INTRO)])
        self.assertEqual(defective, [5])
        self.assertEqual([c["id"] for c in ev.pick_clean(pulls, diffs, 3)], ["pr6-clean"])

    def test_fix_pairs_only_with_prs_merged_before_it(self):  # REQ: REVIEW-eval-1
        pulls = [{"number": 5, "title": "CRED-1: store", "body": "", "merged_at": "2026-10-01"},
                 {"number": 9, "title": "CRED-1-f1: fix", "body": "Defect: CRED-1\n", "merged_at": "2026-10-03"},
                 {"number": 12, "title": "CRED-1: later rework", "body": "", "merged_at": "2026-10-09"},
                 {"number": 7, "title": "CRED-1: reopened", "body": "", "merged_at": None}]
        diffs = {"intro:5": INTRO, "intro:12": "x", "intro:7": "d7", "fix:9": FIX}
        cases, _ = ev.build_cases(pulls, diffs)
        self.assertEqual([c["intro_pr"] for c in cases], [5])

    def test_one_case_per_intro_and_only_files_the_intro_touches(self):  # REQ: REVIEW-eval-2
        fix2 = "--- a/a.go\n+++ b/a.go\n@@ -40,2 +40,1 @@\n ctx\n-bad3\n"
        elsewhere = "--- a/other.go\n+++ b/other.go\n@@ -1,2 +1,1 @@\n ctx\n-bad\n"
        pulls = [{"number": 5, "title": "CRED-1: store", "body": "", "merged_at": "2026-10-01"},
                 {"number": 9, "title": "CRED-1-f1: fix", "body": "Defect: CRED-1\n", "merged_at": "2026-10-03"},
                 {"number": 10, "title": "CRED-1-f2: fix", "body": "Defect: CRED-1\n", "merged_at": "2026-10-04"},
                 {"number": 11, "title": "CRED-1-f3: fix", "body": "Defect: CRED-1\n", "merged_at": "2026-10-05"}]
        diffs = {"intro:5": INTRO, "fix:9": FIX, "fix:10": fix2, "fix:11": elsewhere}
        cases, defective = ev.build_cases(pulls, diffs)
        self.assertEqual(len(cases), 1)
        self.assertEqual(cases[0]["fix_prs"], [9, 10])  # fix 11 touches no file of the intro
        self.assertEqual(sorted(cases[0]["expected"]), ["a.go"])
        both = [{"file": "a.go", "line": 11, "class": "blocker"}, {"file": "a.go", "line": 41, "class": "blocker"}]
        self.assertEqual(ev.score_case(cases[0], both), {"caught": True, "false_blockers": 0})
        self.assertEqual(ev.build_cases(pulls[:2] + pulls[3:], {"intro:5": INTRO, "fix:9": elsewhere, "fix:11": elsewhere}), ([], []))

    def test_change_is_kept_only_when_the_score_rises(self):  # REQ: REVIEW-eval-2
        def sc(caught, false):
            return {"caught": caught, "false_blockers": false, "score": caught - false, "case_set": "s"}
        old = sc(3, 2)
        self.assertTrue(ev.keep(old, sc(4, 2)))
        self.assertTrue(ev.keep(old, sc(3, 1)))
        self.assertFalse(ev.keep(old, sc(3, 2)))
        self.assertFalse(ev.keep(old, sc(4, 3)))
        self.assertFalse(ev.keep(old, sc(2, 0)))
        self.assertFalse(ev.keep(old, sc(9, 9)))

    def test_noise_cannot_win_and_case_sets_must_match(self):  # REQ: REVIEW-eval-2
        cases = [{"id": "a", "kind": "defect", "diff": "d", "expected": {"a.go": [[1, 1]]}},
                 {"id": "b", "kind": "clean", "diff": "d"}]
        quiet = ev.summarize([ev.score_case(cases[0], []), ev.score_case(cases[1], [])], cases)
        loud = [{"file": "a.go", "line": n, "class": "blocker"} for n in range(1, 30)]
        noisy = ev.summarize([ev.score_case(cases[0], loud), ev.score_case(cases[1], loud)], cases)
        self.assertFalse(ev.keep(quiet, noisy))
        other = ev.summarize([], cases[:1])
        with self.assertRaises(ev.CaseSetMismatch):
            ev.keep(quiet, other)

    def test_runner_and_cli_round_trip(self):  # REQ: REVIEW-eval-2
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            case = {"id": "x", "kind": "defect", "diff": "d", "expected": {"a.go": [[1, 2]]}}
            (d / "x.json").write_text(json.dumps(case))
            cmd = "cat >/dev/null; echo '[{\"file\":\"a.go\",\"line\":2,\"class\":\"blocker\"}]'"
            out = d / "s.json"
            self.assertEqual(ev.main(["score", "--cases", str(d), "--cmd", cmd, "--out", str(out)]), 0)
            self.assertEqual(json.loads(out.read_text())["caught"], 1)
            self.assertEqual(ev.main(["compare", str(out), str(out)]), 1)
            other = d / "o.json"
            other.write_text(json.dumps({**json.loads(out.read_text()), "case_set": "different"}))
            self.assertEqual(ev.main(["compare", str(out), str(other)]), 2)  # not the discard code

    def test_build_writes_the_corpus_from_saved_pr_data(self):  # REQ: REVIEW-eval-1
        pulls = [{"number": 5, "title": "CRED-1: store", "body": "", "merged_at": "2026-10-01", "reviewed_head": "abc1234"},
                 {"number": 9, "title": "CRED-1-f1: fix", "body": "Defect: CRED-1\n", "merged_at": "2026-10-03"},
                 {"number": 6, "title": "OTHER-1: clean", "body": "", "merged_at": "2026-10-02"}]
        diffs = {"intro:5": INTRO, "fix:9": FIX, "intro:6": "diff6"}
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            (d / "p.json").write_text(json.dumps({"pulls": pulls, "diffs": diffs}))
            self.assertEqual(ev.main(["build", "--pulls", str(d / "p.json"), "--out", str(d / "c"), "--clean", "1"]), 0)
            self.assertEqual(sorted(f.name for f in (d / "c").glob("*.json")), ["pr5.json", "pr6-clean.json"])


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
        # an earlier SHA in the prose is not the reviewed head; the Record line is
        prose = "Verdict: accept\n# t\nDelta from head abc1234 to def5678\nRecord: PR #1 · package X · head def5678"
        self.assertEqual(metrics.review_head(prose), "def5678")
        self.assertEqual(metrics.count_rounds([a, prose]), 2)

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
