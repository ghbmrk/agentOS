"""Tests for tools/board.py and tools/board_migrate.py: work items as GitHub issues, BOARD.md
generated from them (SIM-repo-1 and SIM-repo-2, briefs/SIM.md).

No SPEC requirement IDs: process tooling (CLAUDE.md, OPERATING). All data is synthetic.
"""
import io
import json
import pathlib
import subprocess
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import board  # noqa: E402
import board_migrate  # noqa: E402
from metrics import STATES  # noqa: E402

BOARD = """# BOARD

Intro prose.

## Harness

Section prose.

| ID | Package | Needs | State |
|---|---|---|---|
| A-1 | [Pilot](briefs/A-1.md) | — | building (C; lane claude2) |
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
        self.assertEqual(by_id["A-1"], {board.MARKER, "state:building", "tier:C", "lane:claude2"})
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
        self.assertIn("| A-1 | [Pilot](briefs/A-1.md) | — | in review (C; lane claude2) |", board.render(BOARD, planned))

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

    def test_board_workflow_and_ci_recognise_the_generated_line(self):
        workflow = (ROOT / ".github" / "workflows" / "board.yml").read_text()
        needle = workflow.split("grep -qF '")[1].split("'")[0]
        self.assertTrue(board.GENERATED.startswith(needle))
        self.assertIn("board.py check --repo", (ROOT / ".github" / "workflows" / "ci.yml").read_text())

    def test_check_repo_before_the_migration_is_the_round_trip(self):
        self.assertEqual(self.run_repo("check", text=BOARD, items=[])[0], 0)
        self.assertEqual(self.run_repo("check", text=BOARD.replace("| — | queued", "|  —  | queued"), items=[])[0], 1)

    def test_committed_board_passes_check(self):
        run = subprocess.run([sys.executable, str(ROOT / "tools" / "board.py"), "check"],
                             cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(run.returncode, 0, run.stderr)


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


class MigrateTest(unittest.TestCase):
    def test_dry_run_is_the_default_and_writes_nothing(self):
        calls = []
        out = io.StringIO()
        with redirect_stdout(out):
            code = board_migrate.main([], read=lambda: BOARD, api=lambda *a: calls.append(a))
        self.assertEqual((code, calls), (0, []))
        self.assertIn("dry run: 4 issues", out.getvalue())
        self.assertIn("round trip: ok", out.getvalue())
        self.assertIn("4 notifications, one per issue", out.getvalue())

    def test_apply_creates_labels_then_issues_in_board_order_and_skips_existing(self):
        calls, paused = [], []
        live = {i["title"].split(":")[0]: dict(i, number=n) for n, i in enumerate(board.plan(BOARD), start=1)}
        repo = [live["A-3"]]

        def api(method, path, payload=None):
            calls.append((method, path, payload))
            if method == "GET" and path.startswith("/repos/o/r/labels"):
                return [{"name": "state:queued"}]
            if method == "GET" and path.startswith("/repos/o/r/issues"):
                return opened(sorted(repo, key=lambda i: i["number"]))
            if method == "POST" and path == "/repos/o/r/issues":
                repo.append(live[payload["title"].split(":")[0]])
            return {}
        out = io.StringIO()
        with redirect_stdout(out):
            code = board_migrate.main(["--apply", "--repo", "o/r"], read=lambda: BOARD, api=api, pause=paused.append)
        self.assertEqual(code, 0)
        self.assertIn("read back: every live row has one issue", out.getvalue())
        self.assertEqual(paused, [1, 1])  # between the three new issues
        made = [c[2]["name"] for c in calls if c[:2] == ("POST", "/repos/o/r/labels")]
        self.assertNotIn("state:queued", made)
        self.assertEqual(set(made) | {"state:queued"}, set(board.LABELS))
        created = [c[2]["title"].split(":")[0] for c in calls if c[:2] == ("POST", "/repos/o/r/issues")]
        self.assertEqual(created, ["A-1", "W-1", "W-3"])
        first_issue = next(n for n, c in enumerate(calls) if c[:2] == ("POST", "/repos/o/r/issues"))
        self.assertTrue(all(c[:2] != ("POST", "/repos/o/r/labels") for c in calls[first_issue:]))

    def test_apply_fails_when_the_issues_do_not_read_back_as_the_board(self):
        def api(method, path, payload=None):
            if method == "GET" and path.startswith("/repos/o/r/issues"):
                return []  # nothing reads back: the creates did not land, or not as collaborator issues
            return [] if method == "GET" else {}
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as err:
            code = board_migrate.main(["--apply", "--repo", "o/r"], read=lambda: BOARD, api=api, pause=lambda s: None)
        self.assertEqual(code, 1)
        self.assertIn("do not render BOARD.md's live rows", err.getvalue())

    def test_apply_needs_a_repo(self):
        with redirect_stderr(io.StringIO()):
            self.assertEqual(board_migrate.main(["--apply"], read=lambda: BOARD, api=lambda *a: None), 2)


if __name__ == "__main__":
    unittest.main()
