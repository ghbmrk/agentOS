"""Tests for tools/board.py: work items as GitHub issues, BOARD.md generated from them
(SIM-repo-1 and SIM-repo-2, briefs/SIM.md; tools/board_migrate.py ran once and was deleted).

No SPEC requirement IDs: process tooling (CLAUDE.md, OPERATING). All data is synthetic.
"""
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import board  # noqa: E402
from metrics import STATES  # noqa: E402

# The live docs/LANES.md names whichever teams exist today; these tests pin a synthetic one.
import re  # noqa: E402
board.LANE = re.compile(r"\blane (teamb)\b")

BOARD = """# BOARD

Intro prose.

## Harness

Section prose.

| ID | Package | Needs | State |
|---|---|---|---|
| A-1 | [Pilot](briefs/A-1.md) | — | building (C; lane teamb) |
| A-2 | [Done](briefs/A-2.md) | A-1 | merged (#1) |
| A-3 | [Spec diff](briefs/A-3.md) | — | queued (B; Mark approves) |

## Wiring

| ID | Wiring | Precondition | Owner | State |
|---|---|---|---|---|
| W-1 | Wire it (release, tier A, L3 on #9) | A-1 | coordinator | in review (#12) |
| W-2 | Gone | — | — | dropped (folded into W-1) |
| W-3 | Stuck | A-3 | — | escalated |

Exit prose: a → b.
"""

LIVE = BOARD.replace("| A-2 | [Done](briefs/A-2.md) | A-1 | merged (#1) |\n", "") \
            .replace("| W-2 | Gone | — | — | dropped (folded into W-1) |\n", "")


def issues(text=BOARD):
    """The planned issues, numbered in board order as the migration creates them."""
    return [dict(i, number=n) for n, i in enumerate(board.plan(text), start=100)]


def opened(items, by="OWNER"):
    """Issues as GitHub returns them: with the opener's association to the repository."""
    return [dict(i, author_association=by) for i in items]


def github(items, prs=()):
    def fetch(path):
        if path.startswith("/repos/o/r/issues"):
            return items
        if path.startswith("/repos/o/r/pulls"):
            return list(prs)
        raise AssertionError(path)
    return fetch


class SchemaTest(unittest.TestCase):
    def test_label_schema_covers_every_state_doclint_accepts(self):
        self.assertEqual({board.state_label(s) for s in STATES},
                         {name for name in board.LABELS if name.startswith("state:")})
        for kind in ("state:", "tier:", "class:", "lane:", "gate:"):
            self.assertTrue(any(name.startswith(kind) for name in board.LABELS), kind)
        self.assertIn(board.MARKER, board.LABELS)
        for name in board.LABELS:
            self.assertLessEqual(len(name), 50, name)  # GitHub's label name limit

    def test_labels_index_the_row(self):
        by_id = {board.issue_id(i): set(i["labels"]) for i in issues()}
        self.assertEqual(by_id["A-1"], {board.MARKER, "state:building", "tier:C", "lane:teamb"})
        self.assertEqual(by_id["A-3"], {board.MARKER, "state:queued", "tier:B", "lane:primary", "gate:mark"})
        self.assertEqual(by_id["W-1"], {board.MARKER, "state:in review", "tier:A", "lane:primary", "class:release"})
        self.assertEqual(by_id["W-3"], {board.MARKER, "state:escalated", "lane:primary"})

    def test_plan_holds_only_live_rows(self):
        self.assertEqual([board.issue_id(i) for i in issues()], ["A-1", "A-3", "W-1", "W-3"])


class RoundTripTest(unittest.TestCase):
    def test_generated_board_equals_the_live_rows_of_the_source(self):
        self.assertEqual(board.render(BOARD, issues()), LIVE)
        self.assertEqual(board.live(BOARD), LIVE)

    def test_todays_board_round_trips(self):
        text = (ROOT / "BOARD.md").read_text()
        self.assertEqual(board.render(text, issues(text)), board.live(text))

    def test_an_escaped_pipe_stays_inside_its_cell(self):
        text = BOARD.replace("[Pilot](briefs/A-1.md)", "[Pilot `a\\|b`](briefs/A-1.md)")
        self.assertEqual(board.render(text, issues(text)), board.live(text))
        self.assertEqual(board.rows(text)[0]["cells"][0], "[Pilot `a\\|b`](briefs/A-1.md)")

    def test_state_comes_from_the_label(self):
        planned = issues()
        a1 = next(i for i in planned if board.issue_id(i) == "A-1")
        a1["labels"] = [x for x in a1["labels"] if not x.startswith("state:")] + ["state:in review"]
        self.assertIn("| A-1 | [Pilot](briefs/A-1.md) | — | in review (C; lane teamb) |", board.render(BOARD, planned))

    def test_an_issue_marked_terminal_leaves_the_board(self):
        planned = issues()
        planned[0]["labels"] = [x for x in planned[0]["labels"] if not x.startswith("state:")] + ["state:merged"]
        self.assertNotIn("| A-1 | [Pilot]", board.render(BOARD, planned))

    def test_rows_follow_issue_number_within_their_section(self):
        planned = issues()
        a1, a3 = planned[0], planned[1]
        a1["number"], a3["number"] = a3["number"], a1["number"]
        out = board.render(BOARD, planned)
        self.assertLess(out.index("| A-3 |"), out.index("| A-1 |"))
        self.assertLess(out.index("| A-1 |"), out.index("## Wiring"))

    def test_bad_issues_are_refused(self):
        def broken(change):
            planned = issues()
            change(planned[0])
            with self.assertRaises(ValueError):
                board.render(BOARD, planned)
        broken(lambda i: i.update(labels=[x for x in i["labels"] if not x.startswith("state:")]))
        broken(lambda i: i["labels"].append("state:queued"))
        broken(lambda i: i.update(body="no block"))
        broken(lambda i: i.update(body=i["body"].replace('"section": "Harness"', '"section": "Nowhere"')))
        broken(lambda i: i.update(body=i["body"].replace('"cells": [', '"cells": ["extra", ')))
        planned = issues()
        planned.append(dict(planned[0], number=999))
        with self.assertRaises(ValueError):  # two issues for one ID
            board.render(BOARD, planned)

    def test_a_board_row_block_that_is_not_an_object_is_refused(self):
        for block in ("[1, 2]", '"text"', "3", "null"):
            planned = issues()
            planned[0]["body"] = f"x\n\n```board-row\n{block}\n```\n"
            with self.assertRaisesRegex(ValueError, "issue #100: board-row block"):
                board.render(BOARD, planned)

    def test_body_text_cannot_leave_its_cell(self):
        def refused(field, value):
            planned = issues()
            block = board.BLOCK.search(planned[0]["body"])
            data = json.loads(block.group(1))
            if field == "cells":
                data["cells"][0] = value
            elif field == "all cells":
                data["cells"] = value
            else:
                data[field] = value
            planned[0]["body"] = planned[0]["body"].replace(block.group(1), json.dumps(data))
            with self.assertRaises(ValueError, msg=repr(value)):
                board.render(BOARD, planned)
        fake = " (C) |\n| A-9 | Fake | — | in review (#1)"
        refused("rest", fake)  # an injected row
        for brk in ("\n", "\r", " ", "\x85"):
            refused("cells", f"a{brk}b")
        refused("cells", "a | b")
        refused("rest", " | extra")
        refused("cells", 7)
        refused("cells", ["nested"])
        refused("rest", None)
        refused("section", ["Harness"])
        refused("all cells", {"x": ["[Pilot](briefs/A-1.md)", "—"]})

    def test_source_with_a_bad_state_or_two_tables_in_a_section_is_refused(self):
        with self.assertRaises(ValueError):
            board.plan(BOARD.replace("escalated |", "parked |"))
        two = BOARD.replace("## Wiring\n\n", "")
        with self.assertRaises(ValueError):
            board.plan(two)


class PullRequestTest(unittest.TestCase):
    def test_pr_state_disagreements_are_reported(self):
        prs = [{"number": 20, "title": "A-1: pilot", "state": "open", "merged_at": None},
               {"number": 21, "title": "A-10: other", "state": "open", "merged_at": None},
               {"number": 22, "title": "W-3 fix", "state": "closed", "merged_at": "2026-10-10T00:00:00Z"}]
        notes = board.pr_notes(issues(), prs)
        self.assertEqual(notes, [
            "A-1: state building but PR #20 is open",
            "W-1: state in review but no open PR names it",
            "W-3: state escalated but PR #22 merged",
        ])


class StaleLabelTest(unittest.TestCase):
    """REQ: STALE-1-1, STALE-1-2, STALE-1-3, STALE-1-4"""

    PRS = [{"number": 22, "title": "W-3: fix", "state": "closed", "merged_at": "2026-10-10T00:00:00Z"},
           {"number": 23, "title": "A-3: spec", "state": "closed", "merged_at": "2026-10-11T00:00:00Z"},
           {"number": 24, "title": "A-3: follow-up", "state": "open", "merged_at": None},
           {"number": 25, "title": "A-1: abandoned", "state": "closed", "merged_at": None}]

    def run_stale(self, *args, comments=(), prs=None):
        posted = []

        def fetch(path, method="GET", payload=None):
            if method == "POST":
                posted.append((path, payload["body"]))
                return {}
            if path.endswith("/comments"):
                return list(comments)
            if path.startswith("/repos/o/r/issues"):
                return opened(issues())
            if path.startswith("/repos/o/r/pulls"):
                want = path.partition("state=")[2]
                every = list(self.PRS if prs is None else prs)
                return [p for p in every if want == "all" or p["state"] == want]
            raise AssertionError(path)
        out = io.StringIO()
        with redirect_stdout(out):
            code = board.main(["stale", "--repo", "o/r", *args], read=lambda: BOARD, fetch=fetch)
        return code, out.getvalue(), posted

    def test_a_merged_pr_on_an_open_row_is_flagged(self):
        found = board.stale(issues(), self.PRS)
        # W-3 (escalated) is flagged; A-3 is not, because another A-3 PR is still open; A-1's PR never merged.
        self.assertEqual([(i["title"][:3], p["number"]) for i, p in found], [("W-3", 22)])

    def test_malformed_issue_is_skipped_and_named_not_fatal(self):
        bad = {"number": 999, "title": "no row block", "labels": [{"name": "work-item"}], "body": "x",
               "author_association": "OWNER"}
        err = io.StringIO()
        with redirect_stderr(err):
            found = board.stale([bad, *issues()], self.PRS)
        self.assertEqual([p["number"] for _, p in found], [22])
        self.assertIn("issue #999", err.getvalue())

    def test_newest_merged_pr_is_named(self):
        prs = [{"number": 31, "title": "W-3: new", "state": "closed", "merged_at": "2026-10-12T00:00:00Z"},
               {"number": 22, "title": "W-3: old", "state": "closed", "merged_at": "2026-10-10T00:00:00Z"}]
        self.assertEqual([p["number"] for _, p in board.stale(issues(), prs)], [31])

    def test_flagging_changes_nothing_and_exits_zero(self):
        code, out, posted = self.run_stale()
        self.assertEqual((code, posted), (0, []))
        self.assertIn("W-3 (#", out)
        self.assertIn("state escalated but PR #22 merged", out)

    def test_comment_is_posted_once_per_issue_and_pr(self):
        code, _, posted = self.run_stale("--comment")
        self.assertEqual((code, len(posted)), (0, 1))
        path, body = posted[0]
        self.assertTrue(path.endswith("/comments"))
        self.assertIn(board.STALE_MARK.format(22), body)
        self.assertIn("state:merged", body)
        again = self.run_stale("--comment", comments=[{"body": body}])
        self.assertEqual(again[2], [])
        # A later merged PR on the same row is a new fact and is flagged again.
        later = self.PRS + [{"number": 30, "title": "W-3: more", "state": "closed", "merged_at": "2026-10-12T00:00:00Z"}]
        self.assertEqual(len(self.run_stale("--comment", comments=[{"body": body}], prs=later)[2]), 1)

    def test_a_named_follow_up_clears_the_flag_until_a_newer_pr_merges(self):
        note = {"body": board.FOLLOWUP_MARK.format(22) + "\nStill owed: part b, #40.",
                "author_association": "OWNER", "user": {"login": "ghbmrk"}}
        code, out, posted = self.run_stale("--comment", comments=[note])
        self.assertEqual((code, out, posted), (0, "", []))
        # The marker names one PR: a later merged PR is a new fact and is flagged again.
        later = self.PRS + [{"number": 30, "title": "W-3: more", "state": "closed", "merged_at": "2026-10-12T00:00:00Z"}]
        _, out, posted = self.run_stale("--comment", comments=[note], prs=later)
        self.assertIn("PR #30 merged", out)
        self.assertEqual(len(posted), 1)
        self.assertIn(board.FOLLOWUP_MARK.format(30), posted[0][1])

    def test_only_a_collaborator_clears_the_flag(self):
        mark = board.FOLLOWUP_MARK.format(22)
        for who in ({"author_association": "NONE", "user": {"login": "outsider"}},
                    {"author_association": "CONTRIBUTOR", "user": {"login": "outsider"}},
                    # the bot's own notice quotes the marker
                    {"author_association": "MEMBER", "user": {"login": board.BOT}},
                    {}):
            _, out, _ = self.run_stale(comments=[dict(who, body=mark)])
            self.assertIn("PR #22 merged", out, who)

    def test_workflow_comments_with_the_issue_token_only(self):
        wf = (ROOT / ".github" / "workflows" / "stale-labels.yml").read_text()
        self.assertIn("board.py stale --repo", wf)
        self.assertIn("issues: write", wf)
        self.assertNotIn("contents: write", wf)
        self.assertNotIn("pull_request_target", wf)


class TransitionTest(unittest.TestCase):
    """BOARD-transition-relation: merged is final, and merged needs a merged PR."""

    MERGED = [{"number": 22, "title": "W-3: fix", "state": "closed", "merged_at": "2026-10-10T00:00:00Z"}]
    OPEN = [{"number": 24, "title": "W-3: fix", "state": "open", "merged_at": None}]

    def test_relation(self):
        legal = [("queued", "building", False), ("building", "in review", False), ("escalated", "queued", False),
                 ("in review", "dropped", False), (None, "queued", False), ("merged", "merged", False),
                 ("in review", "merged", True), (None, "merged", True)]
        illegal = [("merged", "queued", True), ("merged", "dropped", False), ("merged", None, True),
                   ("in review", "merged", False), (None, "merged", False)]
        for prev, new, pr in legal:
            self.assertIsNone(board.transition_problem(prev, new, pr), (prev, new, pr))
        for prev, new, pr in illegal:
            self.assertIsNotNone(board.transition_problem(prev, new, pr), (prev, new, pr))

    def test_only_an_event_touching_merged_can_fail(self):
        # CI-issue-runs-coalesce: board.yml runs the transition job only when the event's label is
        # state:merged or the issue holds it at the event; every other state event is skipped and takes
        # no runner. That filter is exact only while no other edge can fail, which this pins.
        others = [s for s in STATES if s != "merged"]
        for s in others:
            for extra in [None, *others]:
                held = [f"state:{x}" for x in {s, extra} if x]
                for action in ("labeled", "unlabeled"):
                    now = held if action == "labeled" else [h for h in held if h != f"state:{s}"]
                    self.assertIsNone(board.report_transition(self.fetcher(now, []), "o/r", 7, f"state:{s}", action),
                                      (s, extra, action))

    def fetcher(self, held, prs, title="W-3: fix", comments=(), calls=None, search=None):
        item = {"number": 7, "title": title, "labels": [{"name": n} for n in ["work-item", *held]]}
        calls = [] if calls is None else calls

        def fetch(path, method="GET", payload=None):
            calls.append((method, path, payload))
            if path == "/repos/o/r/issues/7":
                return item
            if path.startswith("/search/issues?q="):
                # The search answers merged PRs only (is:merged), as GitHub's does.
                return search or {"items": [{"number": p["number"], "title": p["title"],
                                             "pull_request": {"merged_at": p["merged_at"]}} for p in prs if p["merged_at"]]}
            if path == "/repos/o/r/pulls?state=all":
                return list(prs)
            if path == "/repos/o/r/issues/7/comments" and method == "GET":
                return list(comments)
            if method == "POST":
                return {"id": 9}
            if method in ("PATCH", "DELETE"):
                return {}
            raise AssertionError(path)
        return fetch

    def judge(self, label, action, held, prs):
        return board.report_transition(self.fetcher(held, prs), "o/r", 7, label, action)

    def test_events(self):
        # Adding merged beside the old label, or removing merged, are the two shapes a relabel takes.
        self.assertIsNone(self.judge("state:merged", "labeled", ["state:in review", "state:merged"], self.MERGED))
        self.assertIn("merged PR", self.judge("state:merged", "labeled", ["state:in review", "state:merged"], self.OPEN))
        self.assertIn("merged PR", self.judge("state:merged", "labeled", ["state:merged"], []))
        self.assertIn("final", self.judge("state:queued", "labeled", ["state:merged", "state:queued"], self.MERGED))
        self.assertIn("final", self.judge("state:merged", "unlabeled", ["state:queued"], self.MERGED))
        self.assertIn("final", self.judge("state:merged", "unlabeled", [], self.MERGED))
        self.assertIsNone(self.judge("state:queued", "unlabeled", ["state:building"], []))
        # Add merged, then remove the old label (the order `gh issue edit --add-label --remove-label`
        # emits): the removal reads old -> merged and needs the merged-PR fact too (L3 on #5972).
        self.assertIsNone(self.judge("state:in review", "unlabeled", ["state:merged"], self.MERGED))
        self.assertIn("merged PR", self.judge("state:in review", "unlabeled", ["state:merged"], self.OPEN))
        self.assertIsNone(self.judge("class:release", "labeled", ["state:merged"], []))

    def test_each_problem_names_the_labels_that_restore_the_prior_state(self):
        # #5989 item 2: the message says the fix, and the row ID the merged-PR search used.
        fix = "To fix, restore the prior label: "
        self.assertEqual(self.judge("state:queued", "labeled", ["state:merged", "state:queued"], []),
                         "issue #7: state:merged is final; it cannot change to state:queued. " + fix + "remove `state:queued`.")
        self.assertTrue(self.judge("state:merged", "unlabeled", ["state:queued"], [])
                        .endswith(fix + "remove `state:queued`, add `state:merged`."))
        self.assertTrue(self.judge("state:merged", "unlabeled", [], []).endswith(fix + "add `state:merged`."))
        self.assertEqual(self.judge("state:merged", "labeled", ["state:in review", "state:merged"], []),
                         "issue #7: state:merged needs a merged PR whose title starts with the row ID, and none is"
                         " merged (searched for row ID `W-3`). " + fix + "remove `state:merged`.")
        self.assertTrue(self.judge("state:in review", "unlabeled", ["state:merged"], [])
                        .endswith(fix + "remove `state:merged`, add `state:in review`."))
        self.assertTrue(self.judge("state:merged", "labeled", ["state:merged"], []).endswith(fix + "remove `state:merged`."))

    def test_the_merged_pr_is_found_by_one_search_for_the_row_id(self):
        # #5989 item 4: a legal edge into merged costs one search, no page through every PR.
        calls = []
        fetch = self.fetcher(["state:in review", "state:merged"], self.MERGED, calls=calls)
        self.assertIsNone(board.report_transition(fetch, "o/r", 7, "state:merged", "labeled"))
        self.assertEqual([c[1] for c in calls], ["/repos/o/r/issues/7",
                         "/search/issues?q=repo%3Ao%2Fr%20is%3Apr%20is%3Amerged%20in%3Atitle%20%22W-3%22"])
        # A search hit only counts when its title starts with the row ID: W-30 and "Revert W-3" are other PRs.
        others = [{"number": 30, "title": "W-30: other", "merged_at": "2026-10-10T00:00:00Z"},
                  {"number": 31, "title": "Revert W-3: fix", "merged_at": "2026-10-10T00:00:00Z"}]
        self.assertIn("merged PR", self.judge("state:merged", "labeled", ["state:merged"], others))

    def test_a_search_miss_reads_every_merged_pr(self):
        # #6060 item 1: the search answers at most 100 best-match hits, and its index can trail the
        # merge; a miss falls back to the paged PR list before any problem is reported.
        calls = []
        fetch = self.fetcher(["state:merged"], [], calls=calls)
        self.assertIn("merged PR", board.report_transition(fetch, "o/r", 7, "state:merged", "labeled"))
        self.assertEqual([c[1] for c in calls][1:], ["/search/issues?q=repo%3Ao%2Fr%20is%3Apr%20is%3Amerged%20in%3Atitle%20%22W-3%22",
                                                     "/repos/o/r/pulls?state=all"])
        hit = {"title": "W-3x: other", "pull_request": {"merged_at": "2026-10-10T00:00:00Z"}}
        capped = {"total_count": 150, "items": [hit] * 100}  # 100 of 150 hits, none of them the row's PR
        many = [{"number": n, "title": "W-3x: other", "state": "closed", "merged_at": "2026-10-10T00:00:00Z"}
                for n in range(150)] + self.MERGED
        fetch = self.fetcher(["state:in review", "state:merged"], many, search=capped)
        self.assertIsNone(board.report_transition(fetch, "o/r", 7, "state:merged", "labeled"))
        # The index has not caught up: the live list still finds the merge.
        lagging = self.fetcher(["state:merged"], self.MERGED, search={"total_count": 0, "items": []})
        self.assertIsNone(board.report_transition(lagging, "o/r", 7, "state:merged", "labeled"))

    def test_a_restore_keeps_the_state_labels_the_change_did_not_touch(self):
        # #6060 item 2: undo only the illegal edge; an issue that held two state labels keeps both.
        fix = "To fix, restore the prior label: "
        self.assertTrue(self.judge("state:merged", "labeled", ["state:building", "state:in review", "state:merged"], [])
                        .endswith(fix + "remove `state:merged`."))
        self.assertTrue(self.judge("state:merged", "unlabeled", ["state:building", "state:queued"], [])
                        .endswith(fix + "remove `state:building`, add `state:merged`."))

    def run_cli(self, held, prs, title="W-3: fix", comments=(), comment=True, label="state:merged"):
        calls, err = [], io.StringIO()
        fetch = self.fetcher(held, prs, title, comments, calls)
        argv = ["transition", "--repo", "o/r", "--issue", "7", "--label", label, "--action", "labeled"]
        with redirect_stderr(err):
            code = board.main(argv + (["--comment"] if comment else []), read=lambda: BOARD, fetch=fetch)
        return code, err.getvalue(), [c for c in calls if c[0] != "GET"]

    def test_cli_exit_code(self):
        self.assertEqual(self.run_cli(["state:merged"], self.MERGED, comment=False), (0, "", []))
        code, err, writes = self.run_cli(["state:merged"], [], comment=False)
        self.assertEqual((code, writes), (1, []))
        self.assertIn("board: issue #7: state:merged needs a merged PR", err)

    def test_a_malformed_title_prints_a_board_line(self):
        # #5989 item 3: no traceback; intake already comments on the title, so no comment here.
        code, err, writes = self.run_cli(["state:merged"], self.MERGED, title="no row id")
        self.assertEqual((code, writes), (1, []))
        self.assertEqual(err, "board: issue #7: title 'no row id' does not start with '<ID>: '\n")
        # An edge that needs no search judges it anyway.
        self.assertEqual(self.run_cli(["state:queued"], [], title="no row id", label="state:queued")[:2], (0, ""))

    def test_an_illegal_edge_keeps_one_comment_on_the_issue(self):
        # #5989 item 1: the issue, where agents read, carries the problem; a red run alone reached only the actor.
        code, err, writes = self.run_cli(["state:merged"], [])
        problem = err[len("board: "):].rstrip("\n")
        self.assertEqual(code, 1)
        self.assertEqual(writes, [("POST", "/repos/o/r/issues/7/comments", {"body": board.transition_comment(problem)})])
        body = writes[0][2]["body"]
        self.assertTrue(body.startswith(board.TRANSITION_MARK + "\n"))
        self.assertIn("```text\n" + problem + "\n```", body)
        mine = {"id": 5, "user": {"login": board.BOT}, "body": body}
        self.assertEqual(self.run_cli(["state:merged"], [], comments=[mine])[2], [])  # same problem: no write
        old = dict(mine, body=board.TRANSITION_MARK + "\nolder problem")
        self.assertEqual(self.run_cli(["state:merged"], [], comments=[old])[2],
                         [("PATCH", "/repos/o/r/issues/comments/5", {"body": body})])
        # Someone else's marker steers nothing: the bot posts its own.
        theirs = dict(mine, user={"login": "someone"})
        self.assertEqual([w[0] for w in self.run_cli(["state:merged"], [], comments=[theirs])[2]], ["POST"])
        self.assertEqual(self.run_cli(["state:merged"], self.MERGED)[2], [])  # legal: nothing posted

    def test_two_concurrent_runs_leave_one_comment(self):
        # #6060 item 3: each label event runs on its own, so two runs can both find no comment and
        # post. The run whose post is newer sees the older one, deletes its own and edits the older.
        bot = {"user": {"login": board.BOT}}
        listed = iter([[], [dict(bot, id=4, body=board.TRANSITION_MARK + "\nother problem"),
                            dict(bot, id=9, body=board.TRANSITION_MARK)]])
        writes = []

        def fetch(path, method="GET", payload=None):
            if method == "GET":
                return next(listed)
            writes.append((method, path, payload))
            return {"id": 9}
        board.post_transition(fetch, "o/r", 7, "issue #7: p.")
        body = {"body": board.transition_comment("issue #7: p.")}
        self.assertEqual(writes, [("POST", "/repos/o/r/issues/7/comments", body),
                                  ("DELETE", "/repos/o/r/issues/comments/9", None),
                                  ("PATCH", "/repos/o/r/issues/comments/4", body)])
        # The older run sees only its own comment, or a newer one, and keeps its own.
        listed = iter([[], [dict(bot, id=9, body=body["body"]), dict(bot, id=12, body=body["body"])]])
        writes.clear()
        board.post_transition(fetch, "o/r", 7, "issue #7: p.")
        self.assertEqual([w[0] for w in writes], ["POST"])


class IntakeProblemsTest(unittest.TestCase):
    """CX-BOARD-INTAKE: one run names every malformed work-item issue; render --repo lists them on the board."""

    def malformed(self):
        a, b, c, d, e = (dict(i, author_association="OWNER") for i in issues()[:1] * 5)
        for n, i in enumerate((a, b, c, d, e), start=200):
            i["number"] = n
        a["labels"] = [x for x in a["labels"] if not x.startswith("state:")]  # no state label
        b["labels"] = [x for x in b["labels"] if not x.startswith("state:")] + ["state:review"]  # unknown
        c["body"] = "no block"
        d["title"] = "untitled"
        e["body"] = e["body"].replace('"section": "Harness"', '"section": "Nowhere"')
        return [a, b, c, d, e]

    def test_render_collects_every_problem(self):
        with self.assertRaises(board.Malformed) as ctx:
            board.render(BOARD, self.malformed())
        got = ctx.exception.problems
        self.assertEqual(len(got), 5, got)
        for n in range(200, 205):
            self.assertEqual(sum(f"#{n}" in p for p in got), 1, got)

    def test_duplicate_id_and_cell_count_are_reported_together(self):
        planned = issues()
        dup = dict(planned[0], number=999)
        wide = dict(planned[1], number=998, body=planned[1]["body"].replace('"cells": [', '"cells": ["extra", '))
        wide["title"] = "A-9: wide"
        with self.assertRaises(board.Malformed) as ctx:
            board.render(BOARD, [*planned, dup, wide])
        text = str(ctx.exception)
        self.assertIn("issue #999: a second issue for A-1", text)
        self.assertIn("issue #998: ", text)

    def test_render_lists_every_malformed_issue_on_the_board_and_still_renders(self):
        # One malformed issue used to fail every board.yml run, so BOARD.md kept a stale copy
        # (emptied by #2799) for two days; now the good rows render and the bad issues are named.
        skeleton = BOARD + board.GENERATED + "\n"
        items = opened(issues(skeleton)) + [dict(i, author_association="OWNER") for i in self.malformed()]
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = board.main(["render", "--repo", "o/r"], read=lambda: skeleton, fetch=github(items))
        rendered = out.getvalue()
        self.assertEqual(code, 0, err.getvalue())
        self.assertTrue(rendered.startswith(LIVE + board.GENERATED + "\n\n" + board.UNRENDERED + "\n"), rendered)
        listed = rendered.split("```text\n")[1].split("```")[0].splitlines()
        self.assertEqual([p.split(":")[0] for p in listed], [f"issue #{n}" for n in range(200, 205)])
        self.assertEqual(len([x for x in err.getvalue().splitlines() if x.startswith("board: issue #")]), 5)
        # Each render replaces the list: rendering the rendered board gives it back, and once
        # the issues are fixed the list goes.
        self.assertEqual(board.render(rendered, items, listed=True), rendered)
        self.assertEqual(board.render(rendered, opened(issues(skeleton)), listed=True), LIVE + board.GENERATED + "\n")
        # check --repo compares the committed file, list included, with the live issues; plain
        # check and the strict render ignore the list.
        for text, want in ((rendered, 0), (LIVE + board.GENERATED + "\n", 1)):
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                code = board.main(["check", "--repo", "o/r"], read=lambda: text, fetch=github(items))
            self.assertEqual(code, want)
        self.assertEqual(board.live(rendered), LIVE + board.GENERATED + "\n")
        with self.assertRaises(board.Malformed):
            board.render(skeleton, items)


class IntakeCommentTest(unittest.TestCase):
    """BOARD-INTAKE-wf (#2668): a malformed work item hears it on its issue, once.
    REQ: INTAKE-1, INTAKE-2"""

    def items(self):
        planned = opened(issues())
        bad = dict(planned[0], number=300, title="untitled", body="no block")
        bad["labels"] = [x for x in bad["labels"] if not x.startswith("state:")]
        dup = dict(planned[1], number=301)  # a second issue for A-3
        return [*planned, bad, dup]

    def run_intake(self, number, items=None, comments=()):
        calls, comments = [], [dict(c) for c in comments]

        def fetch(path, method="GET", payload=None):
            if method != "GET":
                calls.append((method, path, payload and payload["body"]))
                return {}
            if path == f"/repos/o/r/issues/{number}/comments":
                return comments
            if path.startswith("/repos/o/r/issues?"):
                return self.items() if items is None else items
            raise AssertionError(path)
        out = io.StringIO()
        with redirect_stdout(out):
            code = board.main(["intake", "--repo", "o/r", "--issue", str(number)],
                              read=lambda: BOARD + board.GENERATED + "\n", fetch=fetch)
        self.assertEqual(code, 0)
        return calls

    def bot(self, body, id=7, login=board.BOT):
        return {"id": id, "body": body, "user": {"login": login}}

    def test_problems_are_the_ones_render_names_for_this_issue(self):
        items = self.items()
        with self.assertRaises(board.Malformed) as ctx:
            board.render(BOARD, items)
        for n in (300, 301):
            got = board.intake_problems(BOARD, items, n)
            self.assertEqual(got, [p for p in ctx.exception.problems if p.startswith(f"issue #{n}: ")])
            self.assertTrue(got)
        self.assertEqual(len(board.intake_problems(BOARD, items, 300)), 1)  # render stops at the state label
        self.assertIn("a second issue for A-3", board.intake_problems(BOARD, items, 301)[0])
        # The first A-3 issue is well formed; the duplicate's problem is the duplicate's.
        self.assertEqual(board.intake_problems(BOARD, items, items[1]["number"]), [])
        # Issue #30's problems are not issue #300's.
        self.assertEqual(board.intake_problems(BOARD, [dict(items[-2], number=30)], 3), [])

    def test_a_duplicate_blames_the_newer_issue_in_githubs_order(self):
        # GitHub lists issues newest first; the older issue is the first for its ID.
        calls = self.run_intake(301, items=list(reversed(self.items())))
        self.assertEqual([c[:2] for c in calls], [("POST", "/repos/o/r/issues/301/comments")])
        self.assertIn("a second issue for A-3 (first is #", calls[0][2])
        self.assertEqual(self.run_intake(self.items()[1]["number"], items=list(reversed(self.items()))), [])

    def test_a_malformed_issue_gets_one_comment_naming_every_problem(self):
        wide = dict(opened(issues())[0], number=302, title="A-9: wide")
        wide["body"] = wide["body"].replace('"cells": [', '"cells": ["extra", ')
        calls = self.run_intake(302, items=[*opened(issues()), wide])
        self.assertEqual([c[:2] for c in calls], [("POST", "/repos/o/r/issues/302/comments")])
        body = calls[0][2]
        self.assertTrue(body.startswith(board.INTAKE_MARK))
        self.assertIn("issue #302: 3 middle cells, its table has 2", body)
        self.assertIn("```text\nissue #302: ", body)
        self.assertIn("its table has 2\n```\n", body)  # the fence closes after the last problem

    def test_the_comment_is_edited_in_place_then_removed_when_fixed(self):
        first = self.run_intake(300)[0][2]
        self.assertEqual(self.run_intake(300, comments=[self.bot(first)]), [])  # unchanged: no call
        stale = self.bot(board.INTAKE_MARK + "\nold problems")
        self.assertEqual(self.run_intake(300, comments=[stale]),
                         [("PATCH", "/repos/o/r/issues/comments/7", first)])
        # A race left two: the extra goes, the first is kept.
        self.assertEqual(self.run_intake(300, comments=[self.bot(first), self.bot(first, id=8)]),
                         [("DELETE", "/repos/o/r/issues/comments/8", None)])
        fixed = opened(issues())[0]["number"]
        self.assertEqual(self.run_intake(fixed, comments=[self.bot(first)]),
                         [("DELETE", "/repos/o/r/issues/comments/7", None)])

    def test_an_issue_that_is_not_a_work_item_has_no_problems(self):
        # Unlabelled or closed issues are not in the open work-item list; outsiders are dropped.
        outsider = [dict(i, author_association="NONE") for i in self.items()]
        for items in ([], outsider):
            with redirect_stderr(io.StringIO()):
                self.assertEqual(self.run_intake(300, items=items, comments=[self.bot("x " + board.INTAKE_MARK)]),
                                 [("DELETE", "/repos/o/r/issues/comments/7", None)])

    def test_a_comment_by_anyone_else_is_never_touched(self):
        human = self.bot(board.INTAKE_MARK + " quoted by a person", id=5, login="someone")
        calls = self.run_intake(300, comments=[human])
        self.assertEqual([c[:2] for c in calls], [("POST", "/repos/o/r/issues/300/comments")])
        fixed = opened(issues())[0]["number"]
        self.assertEqual(self.run_intake(fixed, comments=[human, {"id": 6, "body": board.INTAKE_MARK}]), [])
        # The same bot posts STALE-1's notices; without the marker they are not the intake comment.
        stale = self.bot(board.stale_comment("A-1", "building", {"number": 22}), id=9)
        self.assertEqual(self.run_intake(fixed, comments=[stale]), [])
        self.assertEqual([c[:2] for c in self.run_intake(300, comments=[stale])],
                         [("POST", "/repos/o/r/issues/300/comments")])

    def run_sweep(self, number, items, comments, held=(), touched=(), runs=("2026-11-23T17:00:00Z",), seen=None):
        """board.py intake --sweep with `comments` per issue, the search answering `held`, the REST
        list since the last sweep answering `touched`, and `runs` the successful intake runs' times."""
        calls = []
        seen = [] if seen is None else seen

        def fetch(path, method="GET", payload=None):
            if method != "GET":
                calls.append((method, path, payload and payload["body"]))
                return {}
            m = re.fullmatch(r"/repos/o/r/issues/(\d+)/comments", path)
            if m:
                return [dict(c) for c in comments.get(int(m.group(1)), [])]
            if path == f"/repos/o/r/issues?state=open&labels={board.MARKER}":
                return items
            if path.startswith("/repos/o/r/issues?state=all&since="):
                seen.append(path.split("since=", 1)[1])
                return [{"number": n} for n in touched] + [{"number": 998, "pull_request": {}}]
            if path == "/repos/o/r/actions/workflows/intake.yml/runs?status=success":
                return {"workflow_runs": [{"created_at": t} for t in runs]}
            if path.startswith("/search/issues?q="):
                self.assertIn("in%3Acomments", path)
                self.assertIn(board.urllib.parse.quote(f'"{board.INTAKE_PHRASE}"', safe=""), path)
                return {"items": [{"number": n} for n in held] + [{"number": 999, "pull_request": {}}]}
            raise AssertionError(path)
        with redirect_stdout(io.StringIO()):
            code = board.main(["intake", "--repo", "o/r", "--issue", str(number), "--sweep"],
                              read=lambda: BOARD + board.GENERATED + "\n", fetch=fetch)
        self.assertEqual(code, 0)
        return calls

    def test_a_fixed_issue_the_search_has_not_indexed_is_cleared(self):
        # L3 on #6623: run A comments on X; X is fixed (run B queued); an event on Y queues C, which
        # replaces B; C runs before the search index holds A's comment. X was updated after the last
        # finished sweep, so the REST list since then names it and C clears the false comment.
        clean = opened(issues())
        x, y = clean[0]["number"], clean[1]["number"]
        first = board.intake_comment(["old"])
        self.assertEqual(self.run_sweep(y, clean, {x: [self.bot(first, id=71)]}, held=[], touched=[x, y]),
                         [("DELETE", "/repos/o/r/issues/comments/71", None)])

    def test_the_window_starts_at_the_newest_finished_sweep(self):
        # The bound is the newest successful run's creation less SKEW; with none, INTAKE_FALLBACK back.
        clean = opened(issues())
        seen = []
        self.run_sweep(clean[0]["number"], clean, {}, runs=("2026-11-23T16:00:00Z", "2026-11-23T17:00:00Z"), seen=seen)
        self.assertEqual(seen, ["2026-11-23T16:55:00Z"])
        self.assertEqual(board.sweep_since(lambda p: {"workflow_runs": []}, "o/r", board._epoch("2026-11-23T17:00:00Z")),
                         "2026-11-22T15:55:00Z")

    def test_a_sweep_reaches_every_issue_a_replaced_run_would_have(self):
        # CI-issue-runs-coalesce: intake.yml keeps one running sweep and the newest pending one, so a
        # burst's other runs are cancelled. The survivor comments on every issue render blames (#300,
        # #301) and clears the stale comment the search finds (#5, fixed since), whichever issue
        # triggered it; the triggering issue is always read, and a PR hit is never touched.
        first = board.intake_comment(["old"])
        self.assertIn(board.INTAKE_PHRASE, first)
        fixed = opened(issues())[0]["number"]
        calls = self.run_sweep(fixed, self.items(), {5: [self.bot(first, id=70)], fixed: [self.bot(first, id=71)]},
                               held=[5])
        self.assertEqual(sorted(c[:2] for c in calls),
                         [("DELETE", "/repos/o/r/issues/comments/70"), ("DELETE", "/repos/o/r/issues/comments/71"),
                          ("POST", "/repos/o/r/issues/300/comments"), ("POST", "/repos/o/r/issues/301/comments")])
        posted = {c[1]: c[2] for c in calls if c[0] == "POST"}
        self.assertIn("issue #300: ", posted["/repos/o/r/issues/300/comments"])
        self.assertNotIn("issue #301: ", posted["/repos/o/r/issues/300/comments"])
        # A second sweep over the same final state changes nothing.
        done = {300: [self.bot(posted["/repos/o/r/issues/300/comments"], id=80)],
                301: [self.bot(posted["/repos/o/r/issues/301/comments"], id=81)]}
        self.assertEqual(self.run_sweep(fixed, self.items(), done, held=[300, 301]), [])

    def test_a_sweep_on_a_clean_board_changes_nothing(self):
        clean = opened(issues())
        self.assertEqual(self.run_sweep(clean[0]["number"], clean, {}), [])

    def test_the_bot_is_the_actions_login(self):
        # The login GITHUB_TOKEN comments as; the fixtures above build on board.BOT, so pin it here.
        self.assertEqual(board.BOT, "github-actions[bot]")

    def test_a_delete_with_no_body_returns_none(self):
        class Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        original, board.urllib.request.urlopen = board.urllib.request.urlopen, lambda req: Response(b"")
        try:
            self.assertIsNone(board.call("req"))
        finally:
            board.urllib.request.urlopen = original


class CliTest(unittest.TestCase):
    def run_tool(self, *args, text=BOARD):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = board.main(list(args), read=lambda: text)
        return code, out.getvalue(), err.getvalue()

    def test_check_passes_on_a_board_that_round_trips(self):
        self.assertEqual(self.run_tool("check")[0], 0)

    def test_check_fails_naming_a_row_that_does_not_round_trip(self):
        code, _, err = self.run_tool("check", text=BOARD.replace("| — | queued", "|  —  | queued"))
        self.assertEqual(code, 1)
        self.assertIn("A-3", err)

    def test_render_from_github_uses_issues_and_prs(self):
        def fetch(path):
            if path.startswith("/repos/o/r/issues"):
                return opened(issues()) + [{"number": 5, "title": "a pull", "labels": [], "body": "", "pull_request": {}}]
            if path.startswith("/repos/o/r/pulls"):
                return [{"number": 20, "title": "A-3: spec", "state": "open", "merged_at": None}]
            raise AssertionError(path)
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = board.main(["render", "--repo", "o/r"], read=lambda: BOARD, fetch=fetch)
        self.assertEqual((code, out.getvalue()), (0, LIVE))
        self.assertIn("A-3: state queued but PR #20 is open", err.getvalue())

    def run_repo(self, *args, text, items, prs=()):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = board.main([*args, "--repo", "o/r"], read=lambda: text, fetch=github(items, prs))
        return code, out.getvalue(), err.getvalue()

    def test_only_collaborators_issues_place_rows(self):
        fake = board.issue({"id": "X-1", "section": "Harness", "cells": ["Fake", "—"],
                                    "state": "queued", "rest": ""})
        for by in ("NONE", "CONTRIBUTOR", "FIRST_TIME_CONTRIBUTOR", "FIRST_TIMER", None):
            outsider = dict(fake, number=999, author_association=by)
            code, out, err = self.run_repo("render", text=BOARD, items=opened(issues()) + [outsider])
            self.assertEqual((code, out), (0, LIVE), by)
            self.assertIn("issue #999: ignored, not opened by a collaborator", err)
        for by in board.COLLABORATORS:
            code, out, _ = self.run_repo("render", text=BOARD, items=opened(issues()) + opened([dict(fake, number=999)], by))
            self.assertIn("| X-1 | Fake |", out, by)

    def test_an_empty_issue_listing_is_refused_not_rendered(self):
        # #2799: GitHub answered one board.yml run with no issues, and the empty board it
        # rendered replaced every row on main.
        generated = LIVE.replace("Intro prose.", board.GENERATED + "\n\nIntro prose.")
        for command in ("render", "check"):
            code, out, err = self.run_repo(command, text=generated, items=[])
            self.assertEqual((code, out), (1, ""), command)
            self.assertIn("listed no open work-item issues", err)

    def test_render_out_rewrites_its_own_skeleton_in_place(self):
        # #6500: `render --repo R > BOARD.md` truncates BOARD.md before render reads it; --out
        # reads the skeleton first, then replaces the file whole.
        generated = LIVE.replace("Intro prose.", board.GENERATED + "\n\nIntro prose.")
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d, "BOARD.md")
            path.write_text(BOARD.replace("Intro prose.", board.GENERATED + "\n\nIntro prose."))
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = board.main(["render", "--repo", "o/r", "--out", str(path)],
                                  read=path.read_text, fetch=github(opened(issues())))
            self.assertEqual((code, out.getvalue()), (0, ""), err.getvalue())
            self.assertEqual(path.read_text(), generated)
            self.assertIn("| A-1 | [Pilot](briefs/A-1.md) |", path.read_text())
            self.assertEqual(sorted(p.name for p in pathlib.Path(d).iterdir()), ["BOARD.md"])
            # Plain render writes there too, and a failed render leaves the file as it was.
            code = board.main(["render", "--out", str(path)], read=lambda: BOARD)
            self.assertEqual((code, path.read_text()), (0, board.render(BOARD, issues())))
            with redirect_stderr(io.StringIO()):
                code = board.main(["render", "--repo", "o/r", "--out", str(path)], read=lambda: BOARD, fetch=github([]))
            self.assertEqual((code, path.read_text()), (1, board.render(BOARD, issues())))

    def test_out_is_refused_outside_render(self):
        # #6548: a flag either acts or is refused; `check --out BOARD.md` once exited as a plain
        # check and looked as if it had rewritten the board.
        for command in ("check", "archive", "stale", "intake", "transition"):
            err = io.StringIO()
            with redirect_stderr(err), self.assertRaises(SystemExit) as e:
                board.main([command, "--repo", "o/r", "--out", "BOARD.md"], read=lambda: BOARD,
                           fetch=github(opened(issues())))
            self.assertEqual(e.exception.code, 2, command)
            self.assertIn("--out is for render only", err.getvalue())

    def test_emit_documents_that_out_becomes_a_new_file(self):
        # #6548: os.replace gives FILE a new inode, so a symlink becomes a regular file.
        self.assertIn("new file", board.emit.__doc__)
        self.assertIn("symlink", board.emit.__doc__)

    def test_render_refuses_a_skeleton_with_no_table(self):
        # What the shell leaves for `render > BOARD.md` to read: render fails instead of emitting
        # a board with every row gone.
        for text in ("", "# BOARD\n\nIntro prose.\n"):
            for args in (("render",), ("render", "--repo", "o/r")):
                out_, err_ = io.StringIO(), io.StringIO()
                with redirect_stdout(out_), redirect_stderr(err_):
                    code = board.main(list(args), read=lambda: text, fetch=github(opened(issues())))
                self.assertEqual((code, out_.getvalue()), (1, ""), (args, text))
                self.assertIn("no table", err_.getvalue())

    def test_check_names_the_in_place_render_command(self):
        generated = LIVE.replace("Intro prose.", board.GENERATED + "\n\nIntro prose.")
        edited = generated.replace("| A-1 | [Pilot](briefs/A-1.md) | — | building", "| A-1 | [Pilot](briefs/A-1.md) | — | in review")
        _, _, err = self.run_repo("check", text=edited, items=opened(issues(generated)))
        self.assertIn("render --repo o/r --out BOARD.md", err)
        self.assertNotIn("> BOARD.md", err)

    def test_check_repo_compares_a_generated_board_with_the_live_issues(self):
        generated = LIVE.replace("Intro prose.", board.GENERATED + "\n\nIntro prose.")
        self.assertEqual(self.run_repo("check", text=generated, items=opened(issues(generated)))[0], 0)
        # A hand edit that round-trips through its own planned issues, which plain check accepts,
        # fails against the live issues.
        edited = generated.replace("| A-1 | [Pilot](briefs/A-1.md) | — | building", "| A-1 | [Pilot](briefs/A-1.md) | — | in review")
        self.assertEqual(self.run_tool("check", text=edited)[0], 0)
        code, _, err = self.run_repo("check", text=edited, items=opened(issues(generated)))
        self.assertEqual(code, 1)
        self.assertIn("differs from the live issues", err)
        self.assertIn("+| A-1 | [Pilot](briefs/A-1.md) | — | building", err)
        # An issue the committed file lacks fails too, and an outsider's issue cannot pass or fail it.
        extra = board.issue({"id": "X-1", "section": "Harness", "cells": ["New", "—"], "state": "queued", "rest": ""})
        self.assertEqual(self.run_repo("check", text=generated, items=opened(issues(generated) + [dict(extra, number=999)]))[0], 1)
        self.assertEqual(self.run_repo("check", text=generated,
                                       items=opened(issues(generated)) + opened([dict(extra, number=999)], "NONE"))[0], 0)

    def test_a_board_cannot_drop_the_generated_line_its_base_carries(self):
        # Generated-ness comes from the base branch: a PR that deletes the line and hand-edits a
        # row would otherwise fall back to the round trip and pass.
        generated = LIVE.replace("Intro prose.", board.GENERATED + "\n\nIntro prose.")
        dropped = LIVE.replace("| A-1 | [Pilot](briefs/A-1.md) | — | building", "| A-1 | [Pilot](briefs/A-1.md) | — | in review")
        self.assertEqual(self.run_tool("check", text=dropped)[0], 0)
        with tempfile.TemporaryDirectory() as d:
            base, plain = pathlib.Path(d, "base.md"), pathlib.Path(d, "plain.md")
            base.write_text(generated)
            plain.write_text(LIVE)
            code, _, err = self.run_repo("check", "--base", str(base), text=dropped, items=opened(issues(generated)))
            self.assertEqual(code, 1)
            self.assertIn("drops the GENERATED line", err)
            self.assertEqual(self.run_repo("check", "--base", str(base), text=generated, items=opened(issues(generated)))[0], 0)
            # Before the migration, and when the PR adds the line, the base does not constrain it.
            self.assertEqual(self.run_repo("check", "--base", str(plain), text=BOARD, items=[])[0], 0)
            self.assertEqual(self.run_repo("check", "--base", str(plain), text=generated, items=opened(issues(generated)))[0], 0)

    def test_board_workflow_and_ci_recognise_the_generated_line(self):
        workflow = (ROOT / ".github" / "workflows" / "board.yml").read_text()
        needle = workflow.split("grep -qF '")[1].split("'")[0]
        self.assertTrue(board.GENERATED.startswith(needle))
        # Both take generated-ness from the base: ci.yml from the PR's base (or main for
        # bot/board), board.yml from main before the push.
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
        self.assertIn('board.py check --repo "$GITHUB_REPOSITORY" --base', ci)
        self.assertIn("HEAD^1:BOARD.md", ci)
        self.assertIn('git show "$BEFORE:BOARD.md"', workflow)
        self.assertIn("github.event.before", workflow)

    def test_check_repo_before_the_migration_is_the_round_trip(self):
        self.assertEqual(self.run_repo("check", text=BOARD, items=[])[0], 0)
        self.assertEqual(self.run_repo("check", text=BOARD.replace("| — | queued", "|  —  | queued"), items=[])[0], 1)

    def test_committed_board_passes_check(self):
        run = subprocess.run([sys.executable, str(ROOT / "tools" / "board.py"), "check"],
                             cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)


def board_step_script():
    """ci.yml's live-issues step, as the runner's default `bash -e` would run it."""
    lines = (ROOT / ".github" / "workflows" / "ci.yml").read_text().split("\n")
    start = lines.index("        run: |", next(i for i, l in enumerate(lines) if "BOARD.md rows equal the live" in l)) + 1
    end = next(i for i in range(start, len(lines)) if lines[i].strip() and not lines[i].startswith("          "))
    return "\n".join(l[10:] for l in lines[start:end]) + "\n"


class BotRaceTest(unittest.TestCase):
    """BOARD-bot-race (#3745): bot/board skips only the live comparison; human PRs keep it."""

    def run_step(self, event, ref="refs/pull/7/merge", head_ref="", head_repo=""):
        with tempfile.TemporaryDirectory() as d:
            stubs = pathlib.Path(d)
            # git: BOARD.md changed, any `show` prints a base; python: record the argv.
            for name, body in (("git", '#!/bin/sh\n[ "$1" = diff ] && exit 1\necho "show $2" >> "$STUBS/calls"\n'),
                               ("python", '#!/bin/sh\necho "$*" >> "$STUBS/calls"\n')):
                (stubs / name).write_text(body)
                (stubs / name).chmod(0o755)
            (stubs / "run.sh").write_text(board_step_script())
            env = {"PATH": "%s:/usr/bin:/bin" % d, "STUBS": d, "RUNNER_TEMP": d, "GITHUB_EVENT_NAME": event,
                   "GITHUB_REF": ref, "GITHUB_REPOSITORY": "o/r", "HEAD_REF": head_ref, "HEAD_REPO": head_repo}
            proc = subprocess.run(["bash", "-e", str(stubs / "run.sh")], env=env, cwd=d,
                                  capture_output=True, text=True, timeout=30)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            return (stubs / "calls").read_text().splitlines()

    def test_only_this_repositorys_bot_board_skips_the_live_comparison(self):
        base = "--base %s/base-BOARD.md"
        bot_pr = self.run_step("pull_request", head_ref="bot/board", head_repo="o/r")
        self.assertEqual(bot_pr[0], "show HEAD^1:BOARD.md")
        self.assertTrue(bot_pr[1].startswith("tools/board.py check --base "), bot_pr)
        dispatched = self.run_step("workflow_dispatch", ref="refs/heads/bot/board")
        self.assertEqual(dispatched[0], "show origin/main:BOARD.md")
        self.assertTrue(dispatched[1].startswith("tools/board.py check --base "), dispatched)
        # A human PR, a fork's bot/board and a look-alike branch keep the full check.
        for head_ref, head_repo in (("pkg/1-x", "o/r"), ("bot/board", "fork/r"), ("bot/board2", "o/r"), ("", "")):
            calls = self.run_step("pull_request", head_ref=head_ref, head_repo=head_repo)
            self.assertTrue(calls[1].startswith("tools/board.py check --repo o/r --base "), (head_ref, calls))

    def test_a_lagging_bot_board_passes_but_keeps_the_generated_guard(self):
        generated = LIVE.replace("Intro prose.", board.GENERATED + "\n\nIntro prose.")
        # One issue opened after the render: the bot's board lacks its row.
        extra = board.issue({"id": "X-1", "section": "Harness", "cells": ["New", "—"], "state": "queued", "rest": ""})
        live = opened(issues(generated) + [dict(extra, number=999)])
        dropped = LIVE.replace("| A-1 | [Pilot](briefs/A-1.md) | — | building", "| A-1 | [Pilot](briefs/A-1.md) | — | in review")
        with tempfile.TemporaryDirectory() as d:
            base = pathlib.Path(d, "base.md")
            base.write_text(generated)
            # (1) the bot's check (no --repo) passes the lagging board;
            self.assertEqual(CliTest.run_tool(self, "check", "--base", str(base), text=generated)[0], 0)
            # (2) it still fails a board that drops the GENERATED line;
            code, _, err = CliTest.run_tool(self, "check", "--base", str(base), text=dropped)
            self.assertEqual(code, 1)
            self.assertIn("drops the GENERATED line", err)
            # (3) a human PR's check (--repo) fails the same lagging board.
            code, _, err = CliTest.run_repo(self, "check", "--base", str(base), text=generated, items=live)
            self.assertEqual(code, 1)
            self.assertIn("differs from the live issues", err)


class FreezeTest(unittest.TestCase):
    """D-098: a frozen row carries the `frozen` label, and check --repo fails when they disagree."""
    FROZEN = "queued (frozen until G2, LATER FRZ-fuzz, D-098)"

    def test_a_frozen_row_carries_the_frozen_label(self):
        self.assertIn("frozen", board.LABELS)
        row = {"id": "F-1", "section": "Harness", "cells": ["Fuzz it (release)", "—"], "state": "queued",
               "rest": self.FROZEN[len("queued"):]}
        self.assertIn("frozen", board.issue(row)["labels"])
        self.assertIn("class:release", board.issue(row)["labels"])
        self.assertNotIn("frozen", board.issue(dict(row, rest=""))["labels"])

    def test_check_repo_fails_when_the_frozen_label_and_the_state_disagree(self):
        text = LIVE.replace("Intro prose.", board.GENERATED + "\n\nIntro prose.") \
                   .replace("| — | queued (B; Mark approves) |", f"| — | {self.FROZEN} |")
        items = opened(issues(text))
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            self.assertEqual(board.main(["check", "--repo", "o/r"], read=lambda: text, fetch=github(items)), 0)
        for drop, add in ((["frozen"], []), ([], ["frozen"])):
            drifted = [dict(i, labels=[x for x in i["labels"] if x not in drop] + (add if "A-1" in i["title"] else []))
                       for i in items]
            err = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(err):
                self.assertEqual(board.main(["check", "--repo", "o/r"], read=lambda: text, fetch=github(drifted)), 1)
            self.assertIn("frozen", err.getvalue())


class ArchiveTest(unittest.TestCase):
    """D23: once the base's board is generated, the archives are frozen and the retired files stay gone."""

    def run_archive(self, base, changed=(), present=()):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            (root / "base.md").write_text(base)
            for name in present:
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_text("x")
            err = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(err):
                code = board.main(["archive", "--base", str(root / "base.md"), "--changed", *changed],
                                  read=lambda: "", root=root)
            return code, err.getvalue()

    def test_archives_are_frozen_once_the_base_is_generated(self):
        generated = board.GENERATED + "\n" + LIVE
        self.assertEqual(self.run_archive(generated, ["BOARD.md", "tools/x.py"])[0], 0)
        for path in board.ARCHIVED:
            code, err = self.run_archive(generated, ["BOARD.md", path])
            self.assertEqual(code, 1, path)
            self.assertIn(path, err)
        for path in board.RETIRED:
            code, err = self.run_archive(generated, present=[path])
            self.assertEqual(code, 1, path)
            self.assertIn(path, err)

    def test_before_the_migration_the_archive_check_is_inert(self):
        self.assertEqual(self.run_archive(LIVE, list(board.ARCHIVED), present=board.RETIRED)[0], 0)

    def test_ci_runs_the_archive_check_on_every_pull_request(self):
        ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
        self.assertIn("board.py archive --base", ci)
        self.assertIn("git diff --no-renames --name-only HEAD^1 HEAD", ci)


class RateLimitTest(unittest.TestCase):
    def test_wait_follows_the_response(self):
        self.assertEqual(board.rate_limit_wait(403, {"retry-after": "30"}, 0), 30)
        self.assertEqual(board.rate_limit_wait(429, {"retry-after": "5"}, 0), 5)
        self.assertEqual(board.rate_limit_wait(403, {"x-ratelimit-remaining": "0", "x-ratelimit-reset": "1100"}, 1000), 101)
        self.assertEqual(board.rate_limit_wait(429, {}, 0), 60)
        self.assertIsNone(board.rate_limit_wait(403, {}, 0))  # a permission refusal is not retried
        self.assertIsNone(board.rate_limit_wait(404, {"retry-after": "1"}, 0))

    def test_call_retries_a_rate_limited_request_then_returns(self):
        import email.message
        import urllib.error

        def refused(code, **headers):
            msg = email.message.Message()
            for k, v in headers.items():
                msg[k.replace("_", "-")] = v
            return urllib.error.HTTPError("https://api.github.com/x", code, "limited", msg, io.BytesIO(b"{}"))

        class Response(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        answers = [refused(403, retry_after="7"), refused(429, retry_after="2"), Response(b'{"ok": 1}')]

        def urlopen(req):
            a = answers.pop(0)
            if isinstance(a, Exception):
                raise a
            return a
        slept = []
        original, board.urllib.request.urlopen = board.urllib.request.urlopen, urlopen
        try:
            with redirect_stderr(io.StringIO()):
                self.assertEqual(board.call("req", sleep=slept.append, now=lambda: 0), {"ok": 1})
                answers[:] = [refused(403)]
                with self.assertRaises(urllib.error.HTTPError):
                    board.call("req", sleep=slept.append, now=lambda: 0)
                answers[:] = [refused(429, retry_after="1")] * 3
                with self.assertRaises(urllib.error.HTTPError):
                    board.call("req", sleep=slept.append, now=lambda: 0, tries=3)
        finally:
            board.urllib.request.urlopen = original
        self.assertEqual(slept, [7, 2, 1, 1])

    def test_a_write_sends_its_payload_as_json(self):
        # GitHub answers a POST without a JSON content type with 415 (seen on the first --apply).
        import os
        from unittest import mock
        sent = []
        with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "canary-not-a-token"}), \
                mock.patch.object(board, "call", lambda req: sent.append(req) or {}):
            board.github("/repos/o/r/labels", "POST", {"name": "decision"})
            board.github("/repos/o/r/issues/comments/7", "DELETE")
        self.assertEqual(sent[0].get_header("Content-type"), "application/json")
        self.assertEqual(json.loads(sent[0].data), {"name": "decision"})
        self.assertIsNone(sent[1].data)  # a DELETE sends no body

    def test_a_get_of_one_object_returns_it_through_the_real_github(self):
        # report_transition loads one issue; paging must not turn its JSON object into a list of keys
        # (Security on #5972). A state-label event then runs end to end through board.github.
        import os
        from unittest import mock
        issue = {"number": 7, "title": "X-1: a row", "labels": [{"name": "state:merged"}, {"name": "state:queued"}]}
        def call(req):
            return issue if "/issues/7?" in req.full_url else []
        with mock.patch.dict(os.environ, {"GITHUB_TOKEN": "canary-not-a-token"}), \
                mock.patch.object(board, "call", call):
            self.assertEqual(board.github("/repos/o/r/issues/7"), issue)
            self.assertIn("issue #7", board.report_transition(board.github, "o/r", 7, "state:queued", "labeled"))


if __name__ == "__main__":
    unittest.main()
