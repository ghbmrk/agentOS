"""CLK-7c: SPEC.md states how consent for an unconfirmed plan route is asked.

The testable content is the spec text itself (D-082). **Use the defaults** never
records consent; consent is a high-tier widening and a log entry; the low-tier code
never stands in for it; a notice-paused route refuses `PLAN <plan> ON`.
Ported from the CRED-5 consent test when SPEC v1.0 retired CRED-5 (Appendix A).
"""
# REQ: CLK-7, CH-10, CH-11, ONB-9
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


class Consent(unittest.TestCase):
    def check_unconfirmed(self, t, n):
        self.assertIn("never by **Use the defaults**", t,
                      f"SPEC.md:{n} CLK-7 no longer keeps consent out of Use the defaults")
        self.assertIn("or later with a code-generator code on the owner page", t,
                      f"SPEC.md:{n} CLK-7 later consent no longer takes the code-generator code")
        self.assertIn("Consent is a widening (KEY-4) at the high tier (CH-10)", t,
                      f"SPEC.md:{n} CLK-7 no longer names consent's tier")
        self.assertIn('"ChatGPT plan paused until you say yes; using your other routes meanwhile."', t,
                      f"SPEC.md:{n} CLK-7 lost the paused-until-yes line")

    def check_control(self, t, n):
        self.assertIn("the low-tier code never stands in for it", t,
                      f"SPEC.md:{n} CLK-7 lets the low-tier code stand in for consent")
        self.assertIn("It applies to a route the owner paused, whose consent they withdrew or have not yet given, "
                      "or whose login was refused", t,
                      f"SPEC.md:{n} CLK-7 PLAN ON no longer applies to a route awaiting first consent")
        self.assertIn("A route paused by a terms re-read, a security notice or a changed warning refuses "
                      "`PLAN <plan> ON` until an update brings it back", t,
                      f"SPEC.md:{n} CLK-7 lets a notice-paused route be resumed")
        self.assertIn("Pause, consent and withdrawal take effect before the next run, are log entries", t,
                      f"SPEC.md:{n} CLK-7 consent is no longer logged")

    def check_ch11(self, t, n):
        self.assertIn("`PLAN <plan> OFF` pauses one and `PLAN <plan> ON` is its resume command (CLK-7)", t,
                      f"SPEC.md:{n} CH-11 no longer lists the plan route commands")
        self.assertIn('("Not stopped. To turn your ChatGPT plan back on, reply PLAN ChatGPT ON.")', t,
                      f"SPEC.md:{n} CH-11 bare RESUME no longer names the route command")
        self.assertIn("when the owner paused that route, withdrew or has not yet given its consent, or had its login "
                      "refused; for a route a security notice paused it replies with that route's STATUS line instead;", t,
                      f"SPEC.md:{n} CH-11 bare RESUME names PLAN ON for a notice-paused route")

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
        self.assertIn('"ChatGPT plan paused until you say yes; using your other routes meanwhile. '
                      'Reply PLAN ChatGPT ON to agree."', t,
                      f"SPEC.md:{n} ONB-9 lost the paused-until-yes line")
        self.assertIn("A plan a security notice paused (CLK-7) offers no reply command; its line says only an update "
                      "brings it back", t,
                      f"SPEC.md:{n} ONB-9 offers PLAN ON for a notice-paused plan")

    def test_use_the_defaults_never_records_consent(self):
        for get, check in [(step6, self.check_step6), (unconfirmed, self.check_unconfirmed)]:
            n, t = get()
            check(t, n)

    def test_consent_tier_log_and_notice_pause(self):
        n, t = control()
        self.check_control(t, n)

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
            ]),
            (control, self.check_control, [
                ("the low-tier code never stands in for it", "the low-tier code stands in for it"),
                ("refuses `PLAN <plan> ON`", "accepts `PLAN <plan> ON`"),
                ("whose consent they withdrew or have not yet given,", "whose consent they withdrew,"),
                ("are log entries", "are kept in memory"),
            ]),
            (ch11, self.check_ch11, [
                ("reply PLAN ChatGPT ON.", "reply RESUME."),
                ("replies with that route's STATUS line instead", "replies with that route's command too"),
            ]),
            (step6, self.check_step6, [
                ("which never records consent", "which also records consent"),
                ("except ChatGPT until you agree below, ", ""),
            ]),
            (onb9, self.check_onb9, [
                ("paused until you say yes", "in use"),
                ("offers no reply command; its line says only an update brings it back",
                 "says reply PLAN ChatGPT ON"),
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
