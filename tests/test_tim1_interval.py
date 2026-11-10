"""TIM-1: SPEC.md reads time as an interval, never as a mode.

The testable content is the spec text itself (D-082). A time-due widening (a hold's
or a limit's end) waits on the interval's start, a narrowing fires on its end, and LOG-8 has no clock reason, so a
wrong clock can only make the box more cautious. Outside readers send only while the
whole interval sits the margin inside a slot window, and STATUS shows each move a wide
interval delays.
"""
# REQ: TIM-1, LOG-8
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent

TIM1 = [
    "Time is an interval from network time, cross-checked against modem carrier time, "
    "widened by drift and disagreement.",
    "A time-due move that widens (a hold's or limit's end) waits until the interval's start passes it, "
    "and one that narrows (an expiry, a permitting window's end) fires at its end, "
    "each logged before steps due then (LOG-8).",
]
READER = "the kernel sends only while its interval (TIM-1) lies the margin inside a window"
LOG8_STATUS = "STATUS lists each reason in force, and each move a wide interval (TIM-1) delays, with its scope and lift"


def lines():
    return (ROOT / "SPEC.md").read_text().splitlines()


def bullet(prefix):
    for n, line in enumerate(lines(), 1):
        if line.lstrip().startswith(prefix):
            return n, re.sub(r"\s+", " ", line)
    raise AssertionError(f"SPEC.md has no {prefix!r} bullet")


def log8_table():
    ls = lines()
    n = next(i for i, l in enumerate(ls, 1) if l.startswith("- **LOG-8** "))
    rows = []
    for l in ls[n:]:
        if not l.strip():
            if rows:
                break
            continue
        if not l.lstrip().startswith("|"):
            break
        rows.append(re.sub(r"\s+", " ", l.strip()))
    return n, "\n".join(rows)


class Interval(unittest.TestCase):
    def check_tim1(self, t, n):
        body = re.sub(r"^- \*\*TIM-1\*\* ", "", t)
        self.assertEqual(re.split(r"(?<=[.;])\s+", body), TIM1,
                         f"SPEC.md:{n} TIM-1 no longer reads time as a widening interval "
                         "with holds on its start and narrowings on its end")

    def check_table(self, t, n):
        reasons = []
        for r in t.splitlines()[2:]:
            cell = re.sub(r"\([^)]*\)", "", r.split("|")[1])
            reasons += [x.strip() for x in re.split(r",|\band\b", cell) if x.strip()]
        self.assertTrue(reasons, f"SPEC.md:{n} LOG-8 table has no reasons")
        self.assertFalse([x for x in reasons if "clock" in x],
                         f"SPEC.md:{n} LOG-8 has a clock pause reason again; TIM-1's interval replaces it")

    def check_status(self, t, n):
        self.assertIn(LOG8_STATUS, t, f"SPEC.md:{n} STATUS no longer shows a move a wide interval delays")

    def check_reader(self, t, n):
        self.assertIn(READER, t, f"SPEC.md:{n} outside readers no longer send by the whole time interval")

    def test_tim1_interval(self):
        n, t = bullet("- **TIM-1** ")
        self.check_tim1(t, n)

    def test_no_clock_reason(self):
        n, t = log8_table()
        self.check_table(t, n)

    def test_status_shows_delays(self):
        n, t = bullet("- **LOG-8** ")
        self.check_status(t, n)

    def test_reader_uses_interval(self):
        n, t = bullet("- **Outside readers**")
        self.check_reader(t, n)

    def test_mutations_fail(self):
        cases = [
            (lambda: bullet("- **TIM-1** "), self.check_tim1, [
                ("interval's start passes", "interval's end passes"),
                ("fires at its end", "fires at its start"),
                ("move that widens", "move that narrows"),
                ("(a hold's or limit's end) waits until the interval's start passes it, and one that narrows (an expiry,",
                 "(a hold's end) waits until the interval's start passes it, and one that narrows (an expiry, a limit's end,"),
                ("widened by drift and disagreement", "paused by large disagreements"),
                ("each logged before steps due then", "each logged after the step"),
                ("(LOG-8).", "(LOG-8). Large disagreements pause time-sensitive checks."),
            ]),
            (log8_table, self.check_table, [
                ("| box |", "| clock | the clocks agreeing |\n| box |"),
                ("| lockout |", "| lockout, clock |"),
                ("| lockout |", "| lockout and clock skew |"),
            ]),
            (lambda: bullet("- **LOG-8** "), self.check_status, [
                (", and each move a wide interval (TIM-1) delays,", ""),
                ("each move a wide interval", "each hold a wide interval"),
            ]),
            (lambda: bullet("- **Outside readers**"), self.check_reader, [
                ("only while its interval (TIM-1) lies", "while its clock (TIM-1) lies"),
            ]),
        ]
        for get, check, muts in cases:
            n, t = get()
            for old, new in muts:
                self.assertIn(old, t, old)
                with self.assertRaises(AssertionError, msg=old):
                    check(t.replace(old, new), n)


if __name__ == "__main__":
    unittest.main()
