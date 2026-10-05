"""Tests for tools/metrics.py, the L4 metrics harness (PLAN.md §2 L4, §5).

No requirement IDs: PLAN.md tooling, not SPEC.md behaviour. All data is synthetic.
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
            {"number": 1, "merged_at": "2026-10-05T10:00:00Z", "body": "", "verdicts": ["fix-list", "accept"]},
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

    def test_escalation_rate_is_cumulative_and_counts_past_escalations(self):
        self.assertEqual((self.weeks["2026-10-04"]["escalated"], self.weeks["2026-10-04"]["reviewed"]), (1, 2))
        # B left escalated, but it was escalated once; C and D reached merged.
        self.assertEqual((self.weeks["2026-10-11"]["escalated"], self.weeks["2026-10-11"]["reviewed"]), (1, 4))

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
            self.assertEqual(board, [{"at": "2026-10-05T12:00:00-04:00", "states": {"P1-1": "building"}}])


if __name__ == "__main__":
    unittest.main()
