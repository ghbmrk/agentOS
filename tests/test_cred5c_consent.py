"""CRED-5c: SPEC.md states how consent for an unconfirmed broker-held plan route is asked.

The package is a spec-diff; the testable content is the spec text itself (D-082).
**Use the defaults** never records consent; the ask's tier, journal record, resume
command, mid-life digest line and ONB-9 line are named.
"""
# REQ: CRED-5, CH-10, CH-11, ONB-9
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent


def lines():
    return (ROOT / "SPEC.md").read_text().splitlines()


def find(pred, what):
    for n, line in enumerate(lines(), 1):
        if pred(line):
            return n, re.sub(r"\s+", " ", line)
    raise AssertionError(f"SPEC.md has no {what}")


def broker_held():
    return find(lambda l: l.lstrip().startswith("- **Broker-held.**"), "CRED-5 broker-held bullet")


def ch11():
    return find(lambda l: l.startswith("- **CH-11** "), "'- **CH-11**' bullet")


def step6():
    return find(lambda l: l.startswith("6. **Connect AI:**"), "§8.1 step 6")


def onb9():
    return find(lambda l: l.startswith("- **ONB-9** "), "'- **ONB-9**' bullet")


DEFAULTS_NEVER = r"outside \*\*Use the defaults\*\*, which never records consent"


class Consent(unittest.TestCase):
    def check_cred5(self, t, n):
        self.assertIn("giving consent is a new grant, a high-risk intent (CH-10)", t,
                      f"SPEC.md:{n} CRED-5 no longer names consent's CH-10 tier")
        self.assertRegex(t, r"never by \*\*Use the defaults\*\*",
                         f"SPEC.md:{n} CRED-5 no longer keeps consent out of Use the defaults")
        self.assertIn("it takes the code-generator code on the owner page (CH-3, CH-10)", t,
                      f"SPEC.md:{n} CRED-5 later consent no longer takes the code-generator code")
        self.assertIn("Consent and its withdrawal are journal records (OP-11)", t,
                      f"SPEC.md:{n} CRED-5 consent is no longer journaled")
        self.assertIn('"ChatGPT plan paused until you say yes; using your other routes meanwhile."', t,
                      f"SPEC.md:{n} CRED-5 lost the mid-life digest line")
        self.assertIn("`PLAN <plan> ON` (CH-11), not RESUME", t,
                      f"SPEC.md:{n} CRED-5 no longer names the resume command")
        self.assertIn("the low-tier code never stands in for it", t,
                      f"SPEC.md:{n} CRED-5 lets the low-tier code stand in for consent")
        self.assertIn("it applies to a route the owner paused, whose consent they withdrew or have not yet given, "
                      "or whose login was refused", t,
                      f"SPEC.md:{n} CRED-5 PLAN ON no longer applies to a route awaiting first consent")
        self.assertIn("A route a security notice paused (below) counts as withdrawn on that box: "
                      "`PLAN <plan> ON` refuses it", t,
                      f"SPEC.md:{n} CRED-5 lets a notice-paused route be resumed")

    def check_ch11(self, t, n):
        self.assertIn("`PLAN <plan> OFF` pauses one and `PLAN <plan> ON` is its resume command (CRED-5)", t,
                      f"SPEC.md:{n} CH-11 no longer lists the plan route commands")
        self.assertRegex(t, r"A bare RESUME while nothing is halted but a plan route is paused replies "
                            r"with that route's command \(\"Not stopped\. To turn your ChatGPT plan back on, "
                            r"reply PLAN ChatGPT ON\.\"\)",
                         f"SPEC.md:{n} CH-11 bare RESUME no longer names the route command")
        self.assertIn("when the owner paused that route, withdrew or has not yet given its consent, or had its login refused; "
                      "for a route a security notice paused it replies with that route's STATUS line instead;", t,
                      f"SPEC.md:{n} CH-11 bare RESUME names PLAN ON for a notice-paused route")

    def check_step6(self, t, n):
        self.assertRegex(t, DEFAULTS_NEVER,
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
        self.assertIn('A plan a security notice paused (CRED-5) offers no reply command; its line says only an update '
                      'brings it back ("ChatGPT plan stopped by a security notice; only an update brings it back.")', t,
                      f"SPEC.md:{n} ONB-9 offers PLAN ON for a notice-paused plan")

    def test_use_the_defaults_never_records_consent(self):
        n, t = step6()
        self.check_step6(t, n)
        n, t = broker_held()
        self.check_cred5(t, n)

    def test_consent_tier_and_journal(self):
        n, t = broker_held()
        self.check_cred5(t, n)

    def test_resume_command_named(self):
        n, t = ch11()
        self.check_ch11(t, n)

    def test_onb9_line(self):
        n, t = onb9()
        self.check_onb9(t, n)

    def test_mutations_fail(self):
        cases = [
            (broker_held, self.check_cred5, [
                ("a high-risk intent (CH-10)", "a low-risk intent (CH-10)"),
                ("never by **Use the defaults**", "or by **Use the defaults**"),
                ("are journal records (OP-11)", "are kept in memory"),
                ("the low-tier code never stands in for it", "the low-tier code stands in for it"),
                ("`PLAN <plan> ON` refuses it", "`PLAN <plan> ON` resumes it"),
                ("whose consent they withdrew or have not yet given,", "whose consent they withdrew,"),
            ]),
            (ch11, self.check_ch11, [
                ("reply PLAN ChatGPT ON", "reply RESUME"),
                ("replies with that route's STATUS line instead", "replies with that route's command too"),
                ("withdrew or has not yet given its consent,", "withdrew its consent"),
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
