"""CLK-7c: SPEC.md states how consent for an unconfirmed plan route is asked.

The testable content is the spec text itself (D-082). **Use the defaults** never
records consent; consent is a high-tier widening and a log entry; the low-tier code
never stands in for it; a notice-paused route refuses `PLAN <plan> ON`. Since LOG-8
the pause reasons and their lifts are one table, so the rung and lift checks read its rows.
Ported from the CRED-5 consent test when SPEC v1.0 retired CRED-5 (Appendix A).
"""
# REQ: CLK-7, CH-10, CH-11, ONB-9, LOG-8
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def find(pred, what):
    for n, line in enumerate((ROOT / "SPEC.md").read_text().splitlines(), 1):
        if pred(line):
            return n, re.sub(r"\s+", " ", line)
    raise AssertionError(f"SPEC.md has no {what}")


def unconfirmed():
    return find(lambda l: l.lstrip().startswith("- **Unconfirmed:**"), "CLK-7 unconfirmed bullet")


def control():
    return find(lambda l: l.lstrip().startswith("- **Control.**"), "CLK-7 control bullet")


def ch11():
    return find(lambda l: l.startswith("- **CH-11** "), "'- **CH-11**' bullet")


def step6():
    return find(lambda l: l.startswith("6. **Connect AI:**"), "§8.1 step 6")


def onb9():
    return find(lambda l: l.startswith("- **ONB-9** "), "'- **ONB-9**' bullet")


def log8():
    return find(lambda l: l.startswith("- **LOG-8** "), "'- **LOG-8**' bullet")


def clauses(t):
    """The sentences and semicolon clauses of a bullet, so a check can match one whole."""
    return re.split(r"(?<=[.;])\s+", re.sub(r"^\s*- \*\*[^*]+\*\*\s*", "", t))


def reasons(row):
    """A table row's reasons: its first cell split on commas and "and", asides dropped."""
    cell = re.sub(r"\([^)]*\)", "", row.split("|")[1])
    return [x.strip() for x in re.split(r",|\band\b", cell) if x.strip()]


def log8_table():
    lines = (ROOT / "SPEC.md").read_text().splitlines()
    n = next(i for i, l in enumerate(lines, 1) if l.startswith("- **LOG-8** "))
    rows = []
    for l in lines[n:]:
        if not l.strip():
            if rows:
                break
            continue
        if not l.lstrip().startswith("|"):
            break
        rows.append(re.sub(r"\s+", " ", l.strip()))
    return n, "\n".join(rows)


class Consent(unittest.TestCase):
    def check_unconfirmed(self, t, n):
        self.assertIn("never by **Use the defaults**", t,
                      f"SPEC.md:{n} CLK-7 no longer keeps consent out of Use the defaults")
        self.assertIn("or later with a code-generator code on the owner page", t,
                      f"SPEC.md:{n} CLK-7 later consent no longer takes the code-generator code")
        self.assertIn("Consent is a widening (KEY-4) at the high tier (CH-10)", t,
                      f"SPEC.md:{n} CLK-7 no longer names consent's tier")
        self.assertIn("An unconfirmed route carries the consent reason (LOG-8) unless consent stands.", clauses(t),
                      f"SPEC.md:{n} CLK-7 lets an unconfirmed route run before consent")

    def check_control(self, t, n):
        self.assertIn("`PLAN <plan> ON` lifts the owner and login reasons (P1, LOG-8), never consent or a notice;",
                      clauses(t),
                      f"SPEC.md:{n} CLK-7 PLAN ON lifts consent or a notice, or more than owner and login")
        self.assertIn("`PLAN <plan> OFF` (CH-11), by text or on the Wi-Fi page, pauses a plan route at any time "
                      "with no code, and on an unconfirmed route withdraws consent.", clauses(t),
                      f"SPEC.md:{n} CLK-7 PLAN OFF no longer withdraws consent on an unconfirmed route")
        self.assertIn("Consent and its withdrawal are log entries", t,
                      f"SPEC.md:{n} CLK-7 consent is no longer logged")

    def check_table(self, t, n):
        self.assertIn("| consent | consent (P3) |", t,
                      f"SPEC.md:{n} LOG-8 lets a rung below P3 lift the consent reason")
        rows = [r for r in t.splitlines() if r.startswith("| ") and not r.startswith("| Reason ")]
        consent_rows = [r for r in rows if "consent" in reasons(r)]
        self.assertEqual(len(consent_rows), 1,
                         f"SPEC.md:{n} LOG-8 lets another table row lift the consent reason")
        self.assertIn("| notice | an update |", t,
                      f"SPEC.md:{n} LOG-8 lets something other than an update lift a notice")
        self.assertIn("| stop | RESUME with a texted code (P1) |", t,
                      f"SPEC.md:{n} LOG-8 no longer names RESUME's code")

    def check_ch11(self, t, n):
        self.assertIn("`PLAN <plan> OFF` pauses one and `PLAN <plan> ON` is its resume command (CLK-7)", t,
                      f"SPEC.md:{n} CH-11 no longer lists the plan route commands")
        self.assertIn("A RESUME lifts only the stop reason, and its reply names any other in force with its lift (LOG-8).", t,
                      f"SPEC.md:{n} CH-11 RESUME lifts more than STOP, or no longer names the other reasons' lifts")

    def check_step6(self, t, n):
        self.assertIn("outside **Use the defaults**, which never records consent", t,
                      f"SPEC.md:{n} step 6 lets Use the defaults record consent")
        self.assertIn("asked right after its sign-in, as its own question", t,
                      f"SPEC.md:{n} step 6 no longer places the ask after sign-in")
        self.assertIn("tapping it leaves that plan unused until the owner agrees", t,
                      f"SPEC.md:{n} step 6 no longer leaves the plan unused on Use the defaults")
        self.assertIn("except ChatGPT until you agree below", t,
                      f"SPEC.md:{n} step 6 'plans first' line is not corrected for an unconsented plan")

    def check_onb9(self, t, n):
        self.assertIn('"ChatGPT plan paused until you say yes. Reply PLAN ChatGPT ON to agree."', t,
                      f"SPEC.md:{n} ONB-9 lost the paused-until-yes line")
        self.assertIn("A paused plan's line names its reason and its lift (LOG-8)", t,
                      f"SPEC.md:{n} ONB-9 no longer names the lift, so a notice-paused plan may offer PLAN ON")

    def test_use_the_defaults_never_records_consent(self):
        for get, check in [(step6, self.check_step6), (unconfirmed, self.check_unconfirmed)]:
            n, t = get()
            check(t, n)

    def test_consent_tier_log_and_notice_pause(self):
        n, t = control()
        self.check_control(t, n)
        n, t = log8_table()
        self.check_table(t, n)

    def test_resume_command_named(self):
        n, t = ch11()
        self.check_ch11(t, n)

    def test_onb9_line(self):
        n, t = onb9()
        self.check_onb9(t, n)

    def test_mutations_fail(self):
        cases = [
            (unconfirmed, self.check_unconfirmed, [
                ("at the high tier (CH-10)", "at the low tier (CH-10)"),
                ("never by **Use the defaults**", "or by **Use the defaults**"),
                ("unless consent stands", "until consent stands"),
                ("unless consent stands", "until it is used"),
                ("unless consent stands.", "unless consent stands, and on an unconfirmed route records consent."),
            ]),
            (control, self.check_control, [
                ("owner and login reasons", "owner, login and consent reasons"),
                ("never consent or a notice", "never a notice"),
                ("or a notice;", "or a notice, and on an unconfirmed route records consent;"),
                ("withdraws consent.", "withdraws consent until the next `PLAN <plan> ON`."),
                ("withdraws consent", "keeps consent"),
                ("are log entries", "are kept in memory"),
            ]),
            (log8_table, self.check_table, [
                ("| consent | consent (P3) |", "| consent | consent (P1) |"),
                ("| notice | an update |", "| notice | `PLAN … ON` |"),
                ("RESUME with a texted code (P1)", "RESUME"),
                ("| owner, login |", "| owner, login, consent |"),
                ("| owner, login |", "| owner, login and consent |"),
                ("| owner, login |", "| owner, login, consent (P1) |"),
            ]),
            (ch11, self.check_ch11, [
                ("lifts only the stop reason", "lifts every reason"),
                (" with its lift (LOG-8)", " (LOG-8)"),
            ]),
            (step6, self.check_step6, [
                ("which never records consent", "which also records consent"),
                ("except ChatGPT until you agree below, ", ""),
            ]),
            (onb9, self.check_onb9, [
                ("paused until you say yes", "in use"),
                ("names its reason and its lift", "names its reason"),
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
