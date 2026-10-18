"""Tests for tools/stalequeued.py: queued rows whose package a merged PR already names.

REQ: STALEQ-1, STALEQ-2, STALEQ-3
No SPEC requirement IDs: process tooling (CLAUDE.md, OPERATING). All data is synthetic.
"""
import io
from contextlib import redirect_stderr
import json
import pathlib
import sys
import unittest
from contextlib import redirect_stdout

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import stalequeued  # noqa: E402


def issue(number, row_id, state="queued"):
    block = json.dumps({"section": "S", "cells": ["pkg", "tier C"], "rest": ""})
    return {"number": number, "title": f"{row_id}: text", "author_association": "OWNER",
            "labels": [{"name": "work-item"}, {"name": f"state:{state}"}],
            "body": f"```board-row\n{block}\n```"}


def pr(number, title="x", body="", state="closed", merged="2026-10-17T00:00:00Z"):
    return {"number": number, "title": title, "body": body, "state": state, "merged_at": merged}


ISSUES = [issue(1, "AB-1"), issue(2, "AB-1-b"), issue(3, "CD-2"), issue(4, "EF-3", "building"),
          issue(5, "GH-4"), issue(6, "IJ-5")]
PRS = [pr(10, "AB-1: build it"),                                   # title prefix -> AB-1
       pr(11, "CD-2: fix things"),                                 # title prefix -> CD-2
       pr(12, "EF-3: x"),                                          # EF-3 is building, not queued
       pr(13, "Other", "Record: PR #13 · package GH-4 · head abc"),  # body record line -> GH-4
       pr(14, "IJ-5: more", state="open", merged=None),            # open PR names IJ-5 ...
       pr(15, "IJ-5: first"),                                      # ... so merged #15 is not stale
       pr(16, "Prose only", "see AB-1-bx and package AB-1-bx"),  # near-miss tokens
       pr(17, "CD-2: abandoned", merged=None)]


class StaleQueuedTest(unittest.TestCase):
    def test_flags_only_queued_rows_a_merged_pr_names(self):
        found = [(i["title"].split(":")[0], p["number"], how)
                 for i, p, how in stalequeued.stale_queued(ISSUES, PRS)]
        self.assertEqual(found, [("AB-1", 10, "title"), ("CD-2", 11, "title"), ("GH-4", 13, "body")])

    def test_a_pr_that_only_mentions_the_id_does_not_name_it(self):
        for title in ("Brief for AB-1", "BOARD: add AB-1 row (queued)", "Fix things (AB-1)"):
            self.assertIsNone(stalequeued.names(pr(1, title), "AB-1"), title)
        self.assertIsNone(stalequeued.names(pr(1, "x", "builds on package AB-1 and more"), "AB-1"))
        self.assertIsNone(stalequeued.stale_queued([issue(1, "AB-1")], [pr(2, "Brief for AB-1")]) or None)

    def test_docs_only_pr_with_id_prefixed_title_is_not_a_build(self):
        docs = {"briefs/AB-1.md", "BOARD.md", "SPEC.md", "docs/x.md"}
        self.assertEqual(stalequeued.stale_queued([issue(1, "AB-1")], [pr(2, "AB-1: brief")],
                                                  lambda p: sorted(docs)), [])
        self.assertEqual(len(stalequeued.stale_queued([issue(1, "AB-1")], [pr(2, "AB-1: build")],
                                                      lambda p: ["briefs/AB-1.md", "spikes/a.py"])), 1)

    def test_id_match_is_a_whole_token(self):
        self.assertIsNone(stalequeued.names(pr(1, "AB-1-b: x"), "AB-1"))
        self.assertIsNone(stalequeued.names(pr(1, "XAB-1: x"), "AB-1"))
        self.assertEqual(stalequeued.names(pr(1, "x", "Record: PR #1 · package AB-1 · head abc"), "AB-1"), "body")

    def test_newest_merged_pr_is_named(self):
        prs = [pr(20, "AB-1: old", merged="2026-10-10T00:00:00Z"), pr(21, "AB-1: new")]
        self.assertEqual(stalequeued.stale_queued([issue(1, "AB-1")], prs)[0][1]["number"], 21)

    def test_malformed_issue_is_skipped_and_named_not_fatal(self):
        bad = {"number": 999, "title": "AB-1: x", "labels": [{"name": "work-item"}], "body": "no block",
               "author_association": "OWNER"}
        err = io.StringIO()
        with redirect_stderr(err):
            found = stalequeued.stale_queued([bad, *ISSUES], PRS)
        self.assertEqual(len(found), 3)
        self.assertIn("issue #999", err.getvalue())

    def test_main_prints_rows_and_only_reads(self):
        calls = []

        def fetch(path, method="GET", payload=None):
            calls.append(method)
            if path.endswith("/files"):
                return [{"filename": "tools/a.py"}]
            return ISSUES if path.startswith("/repos/o/r/issues") else PRS
        out = io.StringIO()
        with redirect_stdout(out):
            code = stalequeued.main(["--repo", "o/r"], fetch=fetch)
        self.assertEqual(code, 0)
        self.assertEqual(out.getvalue().splitlines(),
                         ["AB-1 (#1): maybe: title match, does not close #1 (PR #10)",
                          "CD-2 (#3): maybe: title match, does not close #3 (PR #11)",
                          "GH-4 (#5): maybe: body match, does not close #5 (PR #13)"])
        self.assertEqual(set(calls), {"GET"})

    def test_closing_reference_finishes_the_row(self):
        for body in ("Closes #1", "fixes: #1.", "Resolved #1 and more"):
            found = stalequeued.stale_queued([issue(1, "AB-1")], [pr(2, "Unrelated", body)])
            self.assertEqual([(p["number"], how) for _, p, how in found], [(2, "closes")], body)
        out = io.StringIO()
        with redirect_stdout(out):
            stalequeued.main(["--repo", "o/r"], fetch=lambda path, **k: (
                [{"filename": "docs/x.md"}] if path.endswith("/files") else
                [issue(1, "AB-1")] if path.startswith("/repos/o/r/issues") else [pr(2, "Unrelated", "Closes #1")]))
        self.assertEqual(out.getvalue().strip(), "AB-1 (#1): closed by PR #2")

    def test_closing_reference_is_for_this_issue_only(self):
        for body in ("Closes #12", "Closes #2", "see #1", "Closes ghbmrk/other#1"):
            self.assertEqual(stalequeued.stale_queued([issue(1, "AB-1")], [pr(2, "Unrelated", body)]), [], body)

    def test_name_only_matches_are_maybe_with_reason(self):
        # prep PR (INFER-SVC), look-alike title (S8-W1-box-fu1), partial with follow-ups (FUZZ-broker)
        items = [issue(2217, "INFER-SVC"), issue(1898, "S8-W1-box-fu1"), issue(1813, "FUZZ-broker")]
        prs = [pr(2223, "INFER-SVC: G2 allow-list prep", "Refs #2217"),
               pr(1899, "S8-W1-box-fu1: other task", "Closes #1899"),
               pr(2149, "FUZZ-broker: first slice", "Part of #1813; follow-ups #2238")]
        found = stalequeued.stale_queued(items, prs)
        self.assertEqual({p["number"]: how for _, p, how in found}, {2223: "title", 1899: "title", 2149: "title"})
        self.assertNotIn("closes", {how for _, _, how in found})


if __name__ == "__main__":
    unittest.main()
