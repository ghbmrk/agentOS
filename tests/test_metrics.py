"""Tests for tools/metrics.py, the L4 metrics harness (PLAN.md §2 L4, §5).

No SPEC requirement IDs: PLAN.md tooling, not SPEC.md behaviour. The CONV-0 classes claim the
brief's IDs (briefs/CONV-0.md). All data is synthetic.
"""
import datetime as dt
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))
import metrics  # noqa: E402

TZ = dt.timezone(dt.timedelta(hours=-4))


def at(s):
    return dt.datetime.fromisoformat(s).replace(tzinfo=TZ) if "+" not in s and "Z" not in s else dt.datetime.fromisoformat(s.replace("Z", "+00:00"))


class WeekTest(unittest.TestCase):
    def test_week_starts_sunday_0600_local(self):
        # 2026-10-04 is a Sunday.
        self.assertEqual(metrics.week_start(at("2026-10-04T06:00"), TZ), at("2026-10-04T06:00"))
        self.assertEqual(metrics.week_start(at("2026-10-04T05:59"), TZ), at("2026-09-27T06:00"))
        self.assertEqual(metrics.week_start(at("2026-10-10T23:00"), TZ), at("2026-10-04T06:00"))
        # A UTC timestamp is converted before flooring: 09:30Z is 05:30 local.
        self.assertEqual(metrics.week_start(at("2026-10-04T09:30:00Z"), TZ), at("2026-09-27T06:00"))


class ParseTest(unittest.TestCase):
    def test_verdict_from_heading_or_verdict_line(self):
        self.assertEqual(metrics.verdict("## L3 review and lens gate: fix-list (head 4b0)\n\nbody accept"), "fix-list")
        self.assertEqual(metrics.verdict("**L3 re-review @ e42, plus x. Verdict: accept. This merges.**"), "accept")
        self.assertEqual(metrics.verdict("Verdict: **reject**"), "reject")
        self.assertIsNone(metrics.verdict("LGTM, nice work"))
        self.assertIsNone(metrics.verdict(""))

    def test_cause_line(self):
        self.assertEqual(metrics.cause("Verdict: fix-list\nCause: brief-gap\n- point"), "brief-gap")
        self.assertEqual(metrics.cause("Verdict: reject\n**Cause:** Spec-gap"), "spec-gap")
        self.assertIsNone(metrics.cause("Verdict: fix-list\nbecause: defect is mid-line"))
        self.assertIsNone(metrics.cause("Cause: other"))
        self.assertIsNone(metrics.cause(None))

    def test_defect_lines(self):
        body = "## Defect\nDefect: P1-3\nDefect: P1-4, P2-7\nnot a Defect: X"
        self.assertEqual(metrics.defects(body), ["P1-3", "P1-4", "P2-7"])
        self.assertEqual(metrics.defects(None), [])
        # The template's placeholder comment does not count.
        self.assertEqual(metrics.defects("<!-- Defect: <package ID> -->"), [])

    def test_board_states(self):
        board = (
            "| ID | Package | Needs | State |\n|---|---|---|---|\n"
            "| P1-1 | Journal | Cloud | merged |\n"
            "| P1-2 | Broker | P1-1 | In review |\n"
            "| S5 | Browser | x | building: fixture suite passes |\n"
            "| P1-9 | Thing | x | escalated |\n"
            "| S1 | Boot | Mark | test kit ready; waiting |\n"
            "\n| Date | Decision |\n|---|---|\n| 2026-10-04 | no state column |\n"
        )
        self.assertEqual(
            metrics.board_states(board),
            {"P1-1": "merged", "P1-2": "in review", "S5": "building", "P1-9": "escalated", "S1": "other"},
        )

    def test_ledger_readings_and_phases(self):
        ledger = (
            "## Calibration readings (from Mark's usage screen)\n\n"
            "| Date (local) | Session window | Weekly, all models | Weekly, Fable only | Note |\n|---|---|---|---|---|\n"
            "| 2026-10-04 10:58 | 44% (resets in 51 min) | 14% | 11% | a |\n"
            "| 2026-10-04 19:50 | 22% | 23% | 11% | b |\n\n"
            "## Phase allocation (share of total)\n\n| Phase | Share | Spent |\n|---|---|---|\n"
            "| P0 | 10% | ≤ 0.23 WAU |\n| P1 | 25% | — |\n"
        )
        self.assertEqual(
            metrics.ledger_readings(ledger),
            [
                {"at": "2026-10-04T10:58", "all": 14.0, "fable": 11.0},
                {"at": "2026-10-04T19:50", "all": 23.0, "fable": 11.0},
            ],
        )
        self.assertEqual(metrics.ledger_phases(ledger), [["P0", "10%", "≤ 0.23 WAU"], ["P1", "25%", "—"]])

    def test_trace_covered(self):
        self.assertEqual(metrics.trace_covered("# TRACE\n\nCovered: 53 / 144 requirement IDs\n"), 53)
        self.assertIsNone(metrics.trace_covered("no header"))


def raw_fixture():
    return {
        "now": "2026-10-12T12:00:00+00:00",
        "tz_hours": -4,
        "trace": [
            {"at": "2026-10-04T12:00:00-04:00", "covered": 10},
            {"at": "2026-10-05T12:00:00-04:00", "covered": 30},  # week 1: +30 from 0
            {"at": "2026-10-11T12:00:00-04:00", "covered": 40},  # week 2: +10
        ],
        "board": [
            {"at": "2026-10-04T12:00:00-04:00", "states": {"A": "in review", "B": "building"}},
            {"at": "2026-10-06T12:00:00-04:00", "states": {"A": "merged", "B": "escalated"}},
            {"at": "2026-10-11T12:00:00-04:00", "states": {"A": "merged", "B": "in review", "C": "merged", "D": "merged"}},
        ],
        "readings": [
            {"at": "2026-10-03T10:58", "all": 95.0, "fable": 40.0},  # week before
            {"at": "2026-10-04T10:58", "all": 14.0, "fable": 11.0},
            {"at": "2026-10-09T18:00", "all": 60.0, "fable": 20.0},  # week 1, elapsed 5.5 d
            {"at": "2026-10-11T07:00", "all": 3.0, "fable": 0.0},  # week 2
        ],
        "phases": [["P0", "10%", "x"]],
        "pulls": [
            {"number": 1, "merged_at": "2026-10-05T10:00:00Z", "body": "", "verdicts": ["fix-list", "accept"],
             "causes": ["brief-gap"]},
            {"number": 2, "merged_at": "2026-10-06T10:00:00Z", "body": "", "verdicts": ["accept"]},
            {"number": 3, "merged_at": "2026-10-06T11:00:00Z", "body": "", "verdicts": []},
            {"number": 4, "merged_at": "2026-10-11T20:00:00Z", "body": "Defect: A", "verdicts": ["accept"]},
            {"number": 5, "merged_at": None, "body": "Defect: C", "verdicts": ["reject"]},
        ],
        "runs": [
            {"workflow": "ci", "sha": "a", "at": "2026-10-05T10:00:00Z", "conclusions": ["success"]},
            {"workflow": "ci", "sha": "b", "at": "2026-10-05T11:00:00Z", "conclusions": ["failure", "success"]},
            {"workflow": "ci", "sha": "c", "at": "2026-10-05T12:00:00Z", "conclusions": ["failure"]},
            {"workflow": "ci", "sha": "c", "at": "2026-10-05T13:00:00Z", "conclusions": ["cancelled"]},
            {"workflow": "ci", "sha": "d", "at": "2026-10-11T13:00:00Z", "conclusions": ["success"]},
        ],
    }


class ComputeTest(unittest.TestCase):
    def setUp(self):
        self.weeks = {w["week"]: w for w in metrics.compute(raw_fixture())}

    def test_one_row_per_plan_week_with_data(self):
        self.assertEqual(sorted(self.weeks), ["2026-09-27", "2026-10-04", "2026-10-11"])

    def test_requirements_and_usage_per_requirement(self):
        w1 = self.weeks["2026-10-04"]
        self.assertEqual(w1["reqs"], 30)
        self.assertEqual(w1["usage_all"], 60.0)
        self.assertEqual(w1["usage_fable"], 20.0)
        self.assertAlmostEqual(w1["usage_per_req"], 2.0)
        # Pace: the 60% reading came 5.5 days into a 7-day week, so on-pace was ~78.6%.
        self.assertAlmostEqual(w1["pace"], 100 * (5 * 24 + 12) / (7 * 24), places=3)
        w2 = self.weeks["2026-10-11"]
        self.assertEqual(w2["reqs"], 10)
        self.assertAlmostEqual(w2["usage_per_req"], 0.3)
        # The week before has a reading but no covered requirements: no ratio, not a divide error.
        self.assertIsNone(self.weeks["2026-09-27"]["usage_per_req"])

    def test_first_pass_acceptance_counts_only_merged_prs_with_a_verdict(self):
        w1 = self.weeks["2026-10-04"]
        self.assertEqual((w1["first_pass_ok"], w1["first_pass_n"]), (1, 2))
        self.assertEqual(w1["no_verdict"], [3])

    def test_review_rounds_count_every_verdict_on_judged_prs(self):
        # #1 took fix-list then accept, #2 accept; #3 has no verdict and is left out.
        self.assertEqual(self.weeks["2026-10-04"]["rounds"], 3)

    def test_escalation_rate_is_cumulative_and_counts_past_escalations(self):
        self.assertEqual((self.weeks["2026-10-04"]["escalated"], self.weeks["2026-10-04"]["reviewed"]), (1, 2))
        # B left escalated, but it was escalated once; C and D reached merged.
        self.assertEqual((self.weeks["2026-10-11"]["escalated"], self.weeks["2026-10-11"]["reviewed"]), (1, 4))

    def test_causes_tally_judged_prs_and_tolerate_old_data(self):
        self.assertEqual(self.weeks["2026-10-04"]["causes"], ["brief-gap"])
        # #4 has no "causes" key (collected before causes were parsed).
        self.assertEqual(self.weeks["2026-10-11"]["causes"], [])

    def test_defects_count_merged_prs_only(self):
        self.assertEqual(self.weeks["2026-10-11"]["defects"], ["A"])
        self.assertEqual(self.weeks["2026-10-04"]["defects"], [])

    def test_flake_is_mixed_success_and_failure_on_one_commit(self):
        w1 = self.weeks["2026-10-04"]
        # a: clean; b: failed then passed on rerun (flake); c: failure + cancelled (not a flake).
        self.assertEqual((w1["flaky"], w1["runs"]), (1, 3))


class RenderTest(unittest.TestCase):
    def test_render_is_deterministic_and_keeps_old_values_for_expired_data(self):
        raw = raw_fixture()
        first = metrics.render(metrics.compute(raw), raw)
        self.assertIn("# METRICS (generated by tools/metrics.py", first)
        self.assertIn("| 2026-10-04 |", first)
        self.assertEqual(first, metrics.render(metrics.compute(raw), raw, first))
        # Actions runs past GitHub's retention vanish; the recorded value stays.
        raw["runs"] = []
        again = metrics.render(metrics.compute(raw), raw, first)
        row = lambda md: next(l for l in md.splitlines() if l.startswith("| 2026-10-04 |"))
        self.assertEqual(row(again), row(first))
        self.assertIn("1/3", row(again))
        self.assertIn("| brief-gap 1 |", row(first))

    def test_rows_recorded_before_the_causes_column_keep_their_frozen_cells(self):
        raw = raw_fixture()
        first = metrics.render(metrics.compute(raw), raw)
        # Drop the last column, as METRICS.md looked before it existed.
        old = "\n".join(l.rsplit(" |", 2)[0] + " |" if l.startswith("| 2026-") else l for l in first.splitlines())
        raw["runs"].append({"workflow": "ci", "sha": "e", "at": "2026-10-06T10:00:00Z", "conclusions": ["failure", "success"]})
        later = metrics.render(metrics.compute(raw), raw, old)
        row = next(l for l in later.splitlines() if l.startswith("| 2026-10-04 |"))
        self.assertIn("1/3", row)
        self.assertTrue(row.endswith("| — |"))

    def test_rows_recorded_with_fewer_columns_keep_their_frozen_cells(self):
        # METRICS.md on main predates the last three columns.
        raw = raw_fixture()
        first = metrics.render(metrics.compute(raw), raw)
        old = "\n".join(l.rsplit(" |", 4)[0] + " |" if l.startswith("| 2026-") else l for l in first.splitlines())
        raw["runs"].append({"workflow": "ci", "sha": "e", "at": "2026-10-06T10:00:00Z", "conclusions": ["failure", "success"]})
        later = metrics.render(metrics.compute(raw), raw, old)
        row = next(l for l in later.splitlines() if l.startswith("| 2026-10-04 |"))
        self.assertIn("1/3", row)


class FreezeTest(unittest.TestCase):
    def test_closed_week_keeps_recorded_api_cells_but_to_date_rows_recompute(self):
        raw = raw_fixture()
        first = metrics.render(metrics.compute(raw), raw)
        row = lambda md, wk: next(l for l in md.splitlines() if l.startswith(f"| {wk}"))
        # Late data for closed week 2026-10-04 (an extra flake) does not rewrite it.
        raw["runs"].append({"workflow": "ci", "sha": "e", "at": "2026-10-06T10:00:00Z", "conclusions": ["failure", "success"]})
        later = metrics.render(metrics.compute(raw), raw, first)
        self.assertIn("1/3", row(later, "2026-10-04"))
        # The current week was recorded "(to date)", so it still recomputes.
        raw["runs"].append({"workflow": "ci", "sha": "f", "at": "2026-10-11T14:00:00Z", "conclusions": ["failure", "success"]})
        later = metrics.render(metrics.compute(raw), raw, first)
        self.assertIn("50% (1/2)", row(later, "2026-10-11"))


class CollectTest(unittest.TestCase):
    def test_runs_listing_is_unfiltered_paged_and_skips_unfinished_runs(self):
        calls = []
        runs = [{"id": i, "name": "ci", "head_sha": f"s{i}", "created_at": "2026-10-05T00:00:00Z",
                 "status": "completed", "conclusion": "success", "run_attempt": 1,
                 "head_repository": {"full_name": "o/r"}} for i in range(150)]
        runs[0]["status"], runs[0]["conclusion"] = "in_progress", None
        runs[1]["run_attempt"] = 2

        def api(repo, path, token):
            calls.append(path)
            if path.startswith("pulls?"):
                return [{"number": 7, "merged_at": "2026-10-05T01:00:00Z", "body": ""},
                        {"number": 6, "merged_at": "2026-09-01T01:00:00Z", "body": ""}] if "page=1&" in path + "&" else []
            if path.startswith("pulls/7/reviews"):
                return [{"body": "## Lens review: fix-list", "submitted_at": "1", "author_association": "OWNER"},
                        {"body": "**L3 review. Verdict: accept.**", "submitted_at": "2", "author_association": "OWNER"}]
            if path.startswith("pulls/6/reviews"):
                return []
            if path.startswith("actions/runs?"):
                page = int(path.rsplit("page=", 1)[1])
                return {"workflow_runs": runs[(page - 1) * 100: page * 100]}
            if path == "actions/runs/1/attempts/1":
                return {"conclusion": "failure"}
            raise AssertionError(path)

        orig = metrics._api
        metrics._api = api
        try:
            pulls, got = metrics.collect_github("o/r", None)
            calls_all = list(calls)
            calls.clear()
            # Since a cutoff: older runs end the paging and old PRs' reviews are not fetched.
            for i, r in enumerate(runs):
                r["created_at"] = "2026-10-05T00:00:00Z" if i < 50 else "2026-09-01T00:00:00Z"
            pulls2, got2 = metrics.collect_github("o/r", None, since="2026-10-04T10:00:00Z")
        finally:
            metrics._api = orig
        self.assertEqual(len(got2), 49)
        self.assertNotIn("pulls/6/reviews?per_page=100&page=1", calls)
        self.assertEqual(sorted(p["number"] for p in pulls2 if p["verdicts"] is None), [6])
        self.assertEqual([c for c in calls if c.startswith("actions/runs?")], ["actions/runs?per_page=100&page=1"])
        calls = calls_all
        listing = [c for c in calls if c.startswith("actions/runs?")]
        # GitHub caps filtered listings at 1,000 results, so no filter may be passed.
        self.assertEqual(listing, ["actions/runs?per_page=100&page=1", "actions/runs?per_page=100&page=2"])
        self.assertEqual(len(got), 149)
        self.assertEqual(next(r for r in got if r["sha"] == "s1")["conclusions"], ["failure", "success"])
        # Only the L3 review counts as a verdict.
        self.assertEqual(next(p for p in pulls if p["number"] == 7)["verdicts"], ["accept"])


class TrustTest(unittest.TestCase):
    """Security review 2, finding 8: on a public repository anyone can post a review or run
    a fork's CI, so only collaborators' reviews and this repository's own runs count."""

    def test_only_collaborator_reviews_and_own_runs_count(self):
        own = {"full_name": "o/R"}
        fork = {"full_name": "stranger/r"}
        runs = [{"id": 1, "name": "ci", "head_sha": "a", "created_at": "2026-10-05T00:00:00Z", "status": "completed",
                 "conclusion": "success", "run_attempt": 1, "head_repository": own},
                {"id": 2, "name": "ci", "head_sha": "a", "created_at": "2026-10-05T00:01:00Z", "status": "completed",
                 "conclusion": "failure", "run_attempt": 1, "head_repository": fork},
                {"id": 3, "name": "ci", "head_sha": "b", "created_at": "2026-10-05T00:02:00Z", "status": "completed",
                 "conclusion": "failure", "run_attempt": 1, "head_repository": None}]

        def api(repo, path, token):
            if path.startswith("pulls?"):
                return [{"number": 7, "merged_at": "2026-10-05T01:00:00Z", "body": ""}] if "page=1&" in path + "&" else []
            if path.startswith("pulls/7/reviews"):
                return [{"body": "L3 review. Verdict: reject.\nCause: scope", "submitted_at": "1", "author_association": "NONE"},
                        {"body": "L3 review. Verdict: reject.", "submitted_at": "2", "author_association": "CONTRIBUTOR"},
                        {"body": "L3 review. Verdict: fix-list.\nCause: defect", "submitted_at": "3", "author_association": "OWNER"},
                        {"body": "L3 review. Verdict: accept.", "submitted_at": "4", "author_association": "COLLABORATOR"},
                        {"body": "L3 review. Verdict: accept.", "submitted_at": "5", "author_association": "MEMBER"}]
            if path.startswith("actions/runs?"):
                return {"workflow_runs": runs} if path.endswith("page=1") else {"workflow_runs": []}
            raise AssertionError(path)

        orig = metrics._api
        metrics._api = api
        try:
            pulls, got = metrics.collect_github("o/r", None)
        finally:
            metrics._api = orig
        self.assertEqual(pulls[0]["verdicts"], ["fix-list", "accept", "accept"])
        self.assertEqual(pulls[0]["causes"], ["defect"])
        # The fork's failure on the same commit would read as a flake; a run with no head
        # repository (deleted fork) is not known to be this repository's.
        self.assertEqual([(r["sha"], r["conclusions"]) for r in got], [("a", ["success"])])


class SinceTest(unittest.TestCase):
    def test_cutoff_follows_the_last_closed_recorded_week(self):
        raw = raw_fixture()
        md = metrics.render(metrics.compute(raw), raw)
        # 2026-10-04 is the last closed week; 2026-10-11 is "(to date)". 10-11 06:00 UTC-4 = 10:00Z.
        self.assertEqual(metrics._since(md, TZ), "2026-10-11T10:00:00Z")
        self.assertIsNone(metrics._since(None, TZ))
        # Old PRs (verdicts not collected) are not reported as missing a verdict.
        raw["pulls"][2]["verdicts"] = None
        self.assertEqual(sum((w["no_verdict"] for w in metrics.compute(raw)), []), [])


class GitHistoryTest(unittest.TestCase):
    def test_reads_trace_and_board_from_first_parent_history(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
                   "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid", "PATH": "/usr/bin:/bin"}
            git = lambda *a, date="2026-10-05T12:00:00-04:00": subprocess.run(
                ["git", "-C", d, *a], check=True, capture_output=True,
                env={**env, "GIT_AUTHOR_DATE": date, "GIT_COMMITTER_DATE": date})
            git("init", "-q", "-b", "main")
            (root / "TRACE.md").write_text("Covered: 3 / 9 requirement IDs\n")
            (root / "BOARD.md").write_text("| ID | Package | State |\n|---|---|---|\n| P1-1 | J | building |\n")
            git("add", ".")
            git("commit", "-qm", "one")
            (root / "TRACE.md").write_text("Covered: 5 / 9 requirement IDs\n")
            git("commit", "-qam", "two", date="2026-10-06T12:00:00-04:00")
            trace, board = metrics.git_history(root, "HEAD")
            self.assertEqual([t["covered"] for t in trace], [3, 5])
            self.assertEqual(trace[1]["at"], "2026-10-06T12:00:00-04:00")
            self.assertEqual(board, [{"at": "2026-10-05T12:00:00-04:00", "states": {"P1-1": "building"}, "flags": {}}])


def conv_raw():
    """Synthetic data for D-085's convergence columns. Local time is UTC-4, so the baseline
    windows are 2026-09-25..10-02 and 10-02..10-09 (the two weeks before 2026-10-09)."""
    return {
        "now": "2026-10-20T12:00:00+00:00", "tz_hours": -4, "trace": [], "readings": [],
        "phases": [["P0", "10%", "x"]], "runs": [],
        "board": [
            {"at": "2026-09-28T12:00:00-04:00", "states": {"A": "merged"}, "flags": {}},
            {"at": "2026-10-05T12:00:00-04:00", "states": {"A": "merged", "B": "queued", "B-f1": "queued"},
             "flags": {"B-f1": "f"}},
            {"at": "2026-10-07T12:00:00-04:00",
             "states": {"A": "merged", "B": "queued", "B-f1": "queued", "C": "queued"}, "flags": {"B-f1": "f", "C": "p"}},
            {"at": "2026-10-12T12:00:00-04:00",
             "states": {"A": "merged", "B": "building", "B-f1": "in review", "C": "escalated", "D": "queued", "E": "queued", "F": "dropped"},
             "flags": {"B-f1": "f", "C": "p", "D": "f", "E": "p", "F": "fp"}},
            {"at": "2026-10-19T12:00:00-04:00",
             "states": {"A": "merged", "B": "merged", "B-f1": "merged", "C": "merged", "D": "queued", "E": "queued", "F": "dropped", "G": "queued"},
             "flags": {"B-f1": "f", "C": "p", "D": "f", "E": "p", "F": "fp", "G": "p"}},
        ],
        "pulls": [
            {"number": 1, "merged_at": "2026-09-30T10:00:00Z", "body": "", "verdicts": ["accept"]},
            {"number": 2, "merged_at": "2026-10-06T10:00:00Z", "body": "Defect: A", "verdicts": ["accept"]},
            {"number": 3, "merged_at": "2026-10-13T10:00:00Z", "body": "", "verdicts": ["accept"]},
            {"number": 4, "merged_at": "2026-10-14T10:00:00Z", "body": "", "verdicts": ["accept"]},
            {"number": 10, "merged_at": None, "state": "open", "draft": False, "updated_at": "2026-10-17T00:00:00Z", "body": ""},
            {"number": 11, "merged_at": None, "state": "open", "draft": True, "updated_at": "2026-10-01T00:00:00Z", "body": ""},
            {"number": 12, "merged_at": None, "state": "open", "draft": True, "updated_at": "2026-10-01T00:00:00Z", "body": ""},
            {"number": 13, "merged_at": None, "state": "open", "draft": False, "updated_at": "2026-10-01T00:00:00Z", "body": ""},
            {"number": 14, "merged_at": None, "state": "open", "draft": False, "updated_at": "2026-10-20T00:00:00Z", "body": ""},
            {"number": 15, "merged_at": None, "state": "closed", "draft": False, "updated_at": "2026-10-01T00:00:00Z", "body": ""},
        ],
        "held": [11, 13],
    }


class ConvergenceColumnsTest(unittest.TestCase):
    # REQ: CONV-0-1
    def setUp(self):
        self.raw = conv_raw()
        self.weeks = {w["week"]: w for w in metrics.compute(self.raw)}

    def test_flags_mark_follow_up_ids_release_follow_ups_and_promotions(self):
        board = (
            "| ID | Package | Needs | State |\n|---|---|---|---|\n"
            "| DEP-3-r1 | fix (release, tier A; L3 on #562 point 1) | x | building |\n"
            "| SR3-4-f4 | y | x | queued |\n"
            "| P3-4b-env-l1 | y | x | queued |\n"
            "| X-1 | thing (release, tier A; Security 4a point 1) | x | queued |\n"
            "| X-2 | thing (release, tier A; spec A4) | x | queued |\n"
            "| X-3 | promotes LATER SR3-4f-2 l4 (release) | x | queued |\n"
            "| X-4 | Which rows the first release needs is LATER.md. | x | queued |\n"
            "| X-5 | plain | x | queued |\n"
        )
        self.assertEqual(metrics.board_flags(board), {
            "DEP-3-r1": "f", "SR3-4-f4": "f", "P3-4b-env-l1": "f", "X-1": "f", "X-3": "p"})

    def test_open_rows_count_queued_building_in_review_escalated(self):
        # Week of 10-11 ends with B building, B-f1 in review, C escalated, D and E queued; A merged, F dropped.
        self.assertEqual(self.weeks["2026-10-11"]["open_rows"], 5)
        self.assertEqual(self.weeks["2026-10-18"]["open_rows"], 3)

    def test_follow_ups_and_promotions_count_rows_first_seen_that_week(self):
        w = self.weeks["2026-10-11"]
        self.assertEqual((w["followups"], w["promotions"]), (2, 2))  # D, F follow-ups; E, F promotions
        self.assertEqual(self.weeks["2026-10-04"]["followups"], 1)
        self.assertEqual(self.weeks["2026-10-04"]["promotions"], 1)
        self.assertEqual(self.weeks["2026-10-18"]["promotions"], 1)
        self.assertEqual(self.weeks["2026-10-18"]["followups"], 0)

    def test_follow_ups_per_merged_pr(self):
        self.assertEqual(self.weeks["2026-10-11"]["merged"], 2)
        self.assertAlmostEqual(self.weeks["2026-10-11"]["followups_per_pr"], 1.0)
        self.assertIsNone(self.weeks["2026-10-18"]["followups_per_pr"])  # no PR merged: not 0

    def test_stale_open_prs_skip_held_drafts_only(self):
        # #10 untouched 3.5 days; #11 held draft (excluded); #12 unheld draft; #13 held but not a draft;
        # #14 fresh; #15 closed.
        self.assertEqual(self.weeks["2026-10-18"]["stale"], [10, 12, 13])
        self.assertIsNone(self.weeks["2026-10-11"]["stale"])  # only knowable at run time

    def test_columns_that_cannot_be_computed_print_n_a_never_zero(self):
        raw = conv_raw()
        for snap in raw["board"]:
            del snap["flags"]
        for p in raw["pulls"]:
            for k in ("state", "draft", "updated_at"):
                p.pop(k, None)
        del raw["held"]
        md = metrics.render(metrics.compute(raw), raw)
        row = next(l for l in md.splitlines() if l.startswith("| 2026-10-18"))
        cells = [c.strip() for c in row.strip("|").split("|")]
        i = metrics.COLUMNS.index
        for col in ("Follow-up rows added", "Follow-ups per merged PR", "Promotions later to release", "Stale PRs (48 h)"):
            self.assertEqual(cells[i(col)], "n/a", col)
        self.assertEqual(cells[i("Open BOARD rows")], "3")


class BaselineAndGuardTest(unittest.TestCase):
    # REQ: CONV-0-2
    def render(self, raw):
        return metrics.render(metrics.compute(raw), raw)

    def test_baseline_is_the_mean_of_the_two_weeks_before_the_decision(self):
        base = metrics.baseline(conv_raw())
        self.assertAlmostEqual(base["promotions"], 0.5)   # 0 and 1
        self.assertAlmostEqual(base["defects"], 0.5)      # 0 and 1
        self.assertAlmostEqual(base["followups"], 0.5)
        self.assertIsNone(base["stale"])                  # a point-in-time figure with no history
        md = self.render(conv_raw())
        self.assertIn("## Baseline", md)
        self.assertRegex(md, r"\| Promotions later to release \| 0\.5 \|")

    def test_windows_before_the_first_board_commit_count_as_zero_not_unknown(self):
        raw = conv_raw()
        raw["board"] = raw["board"][3:]  # history starts after the baseline windows
        base = metrics.baseline(raw)
        self.assertEqual((base["open_rows"], base["followups"], base["promotions"]), (0, 0, 0))

    def test_week_above_baseline_is_red_and_two_in_a_row_trip_the_guard(self):
        md = self.render(conv_raw())
        row = lambda wk: next(l for l in md.splitlines() if l.startswith(f"| {wk}"))
        self.assertIn("2 red", row("2026-10-11"))   # promotions 2 > 0.5
        self.assertIn("1 red", row("2026-10-18"))   # promotions 1 > 0.5
        self.assertNotIn("red", row("2026-10-04"))  # the decision's own week is not judged
        self.assertIn("D-085 guard tripped: revert the release-class rule (decisions/D-085.md)", md)

    def test_one_red_week_or_a_gap_does_not_trip_the_guard(self):
        raw = conv_raw()
        raw["board"][-1]["flags"].pop("G")
        raw["board"][-1]["flags"]["F"] = "f"   # the last week adds no promotion
        md = self.render(raw)
        self.assertIn("2 red", next(l for l in md.splitlines() if l.startswith("| 2026-10-11")))
        self.assertNotIn("guard tripped", md)

    def test_defects_above_baseline_are_red_too(self):
        raw = conv_raw()
        for n in (3, 4):
            raw["pulls"][n - 1]["body"] = "Defect: A\nDefect: B"
        md = self.render(raw)
        self.assertIn("(A, A, B, B) red", next(l for l in md.splitlines() if l.startswith("| 2026-10-11")))


class LedgerStaleTest(unittest.TestCase):
    # REQ: CONV-0-4
    def first_line(self, now, readings):
        raw = conv_raw()
        raw["now"], raw["readings"] = now, readings
        return metrics.render(metrics.compute(raw), raw).splitlines()[0]

    def test_reading_over_36_hours_old_is_named_on_the_first_line(self):
        # 2026-10-04 19:50 local is 23:50Z; 36 h later is 10-06 11:50Z.
        line = self.first_line("2026-10-06T12:00:00+00:00", [{"at": "2026-10-04T19:50", "all": 23.0, "fable": 11.0}])
        self.assertIn("LEDGER.md", line)
        self.assertIn("2026-10-04 19:50", line)
        self.assertIn("36 hours", line)

    def test_fresh_reading_or_exactly_36_hours_leaves_the_heading_first(self):
        r = [{"at": "2026-10-04T19:50", "all": 23.0, "fable": 11.0}]
        self.assertTrue(self.first_line("2026-10-06T11:50:00+00:00", r).startswith("# METRICS"))
        self.assertTrue(self.first_line("2026-10-05T12:00:00+00:00", r).startswith("# METRICS"))

    def test_newest_reading_counts_and_no_reading_is_stale(self):
        r = [{"at": "2026-10-04T10:00", "all": 1.0, "fable": 0.0}, {"at": "2026-10-09T10:00", "all": 2.0, "fable": 0.0}]
        self.assertTrue(self.first_line("2026-10-10T10:00:00+00:00", r).startswith("# METRICS"))
        self.assertIn("no reading", self.first_line("2026-10-10T10:00:00+00:00", []))


class HeldAndCollectTest(unittest.TestCase):
    # REQ: CONV-0-1
    def test_held_drafts_come_from_the_held_table_only(self):
        text = ("## Queue\n\n| Item | Draft |\n|---|---|\n| X | #1 |\n\n"
                "## Held (draft stays open)\n\n| Item | Draft | Why held |\n|---|---|---|\n"
                "| A | #405 | note #9 |\n| B | #387, #390 | stack |\n| C | #263→#435 stack, incl. #274 | x |\n| D | own drafts | y |\n\n"
                "## After\n\n| Item | Draft |\n|---|---|\n| Z | #2 |\n")
        self.assertEqual(metrics.held_drafts(text), [263, 274, 387, 390, 405, 435])

    def test_collected_pulls_carry_state_draft_and_update_time(self):
        def api(repo, path, token):
            if path.startswith("pulls?"):
                return [{"number": 7, "state": "open", "draft": True, "updated_at": "2026-10-05T00:00:00Z",
                         "merged_at": None, "body": None}] if "page=1&" in path + "&" else []
            if path.startswith("actions/runs?"):
                return {"workflow_runs": []}
            raise AssertionError(path)
        orig = metrics._api
        metrics._api = api
        try:
            pulls, _ = metrics.collect_github("o/r", None)
        finally:
            metrics._api = orig
        self.assertEqual((pulls[0]["state"], pulls[0]["draft"], pulls[0]["updated_at"]), ("open", True, "2026-10-05T00:00:00Z"))


class GitFlagsTest(unittest.TestCase):
    # REQ: CONV-0-1
    def test_history_snapshots_carry_flags(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            env = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
                   "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid", "PATH": "/usr/bin:/bin"}
            subprocess.run(["git", "-C", d, "init", "-q", "-b", "main"], check=True, capture_output=True, env=env)
            (root / "BOARD.md").write_text("| ID | Package | Needs | State |\n|---|---|---|---|\n| P-1-r1 | J | x | queued |\n")
            subprocess.run(["git", "-C", d, "add", "."], check=True, capture_output=True, env=env)
            subprocess.run(["git", "-C", d, "commit", "-qm", "one"], check=True, capture_output=True, env=env)
            _, board = metrics.git_history(root, "HEAD")
            self.assertEqual(board[0]["flags"], {"P-1-r1": "f"})


class WorkflowTest(unittest.TestCase):
    # REQ: CONV-0-3
    def test_runs_daily_from_main_only_with_the_same_permissions(self):
        text = (pathlib.Path(__file__).resolve().parent.parent / ".github/workflows/metrics.yml").read_text()
        crons = [l.split('"')[1] for l in text.splitlines() if l.strip().startswith("- cron:")]
        self.assertEqual(len(crons), 1)
        minute, hour, dom, month, dow = crons[0].split()
        self.assertEqual((dom, month, dow), ("*", "*", "*"))  # every day, not Sundays only
        self.assertIn("workflow_dispatch:", text)
        self.assertIn("if: github.ref == 'refs/heads/main'", text)
        self.assertEqual(text.count("contents: write"), 1)  # only the commit job writes
        self.assertIn("pull-requests: read", text)
        self.assertIn("actions: read", text)


if __name__ == "__main__":
    unittest.main()
