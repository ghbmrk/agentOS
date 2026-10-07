import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))
import next as nxt  # noqa: E402


TRACE = """
| ID | Covered by |
|---|---|
| OP-1 | `broker/journal/engine_test.go` |
| OP-9 | — |
| HW-5a | `broker/tpmseal/tpmseal_test.go` |
| OSS-12 | - |
"""

BOARD = """
| ID | Package | Needs | State |
|---|---|---|---|
| P1-1 | Journal | — | in review |
| ADP-8 | Mismatch check against a demo | — | queued, unblocked |
| UPD-b | First boot | UPD-a | queued, blocked on UPD-a |
| P3-4b | In-sandbox adversarial tests | P3-4 | deferred (Mark) |
| S1 | Screenless boot | hardware | test kit ready |
"""


class NextTest(unittest.TestCase):
    def test_uncovered(self):
        self.assertEqual(nxt.uncovered(TRACE), ["OP-9", "OSS-12"])

    def test_actionable_skips_blocked_and_deferred(self):
        text = nxt.report(TRACE, BOARD)
        self.assertIn("ADP-8:", text)
        self.assertNotIn("UPD-b", text)
        self.assertNotIn("P3-4b", text)
        self.assertIn("In review: 1.", text)
        self.assertIn("Uncovered (2): OP-9 OSS-12", text)

    def test_later_row_wins(self):
        board = BOARD + "| P1-1 | Journal | — | merged |\n"
        text = nxt.report(TRACE, board)
        self.assertIn("In review: 0.", text)

    def test_real_repo_parses(self):
        root = pathlib.Path(__file__).resolve().parent.parent
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = nxt.main(["--root", str(root)])
        self.assertEqual(rc, 0)
        out = buf.getvalue()
        self.assertIn("Uncovered (", out)
        self.assertIn("In review:", out)
        self.assertIn("Queued, not blocked or deferred", out)
        self.assertGreater(int(out.split("Uncovered (")[1].split(")")[0]), 0)


if __name__ == "__main__":
    unittest.main()
