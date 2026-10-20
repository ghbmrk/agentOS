"""KRN-2t: SPEC.md's KRN-2 text names the trusted base and claims no containment.

KRN-2 is a scope statement; the testable content is the sentence itself (D-082).
Ported from the CRED-2 test when SPEC v1.0 retired CRED-2 (Appendix A).
"""
# REQ: KRN-2
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
MEMBERS = ["the kernel", "the clerks", "the enforcer (STO-4)", "the firmware and TPM", "host kernel",
           "hypervisor", "the sandboxes it runs", "processes in them that read credentials", "the CLI process"]


def krn2():
    for n, line in enumerate((ROOT / "SPEC.md").read_text().splitlines(), 1):
        if line.startswith("- **KRN-2** "):
            return n, line
    raise AssertionError("SPEC.md has no '- **KRN-2**' bullet")


class TrustedBase(unittest.TestCase):
    def check(self, text, line_no):
        flat = re.sub(r"\s+", " ", text)
        for m in MEMBERS:
            self.assertIn(m, flat, f"SPEC.md:{line_no} KRN-2 no longer names '{m}'")
        self.assertIn("CLK-4", flat, f"SPEC.md:{line_no} KRN-2 no longer ties scanning to CLK-4")
        self.assertRegex(flat, r"(?i)tripwire, not containment of a compromised credential reader",
                         f"SPEC.md:{line_no} KRN-2 scanning is no longer a tripwire without containment")
        self.assertIn("the spec claims no such containment", flat,
                      f"SPEC.md:{line_no} KRN-2 no longer disclaims containment (D-082)")
        self.assertRegex(flat, r"(?i)compromise of that base is out of scope",
                         f"SPEC.md:{line_no} KRN-2 no longer puts base compromise out of scope")

    def test_names_every_trusted_base_member(self):
        n, t = krn2()
        self.check(t, n)

    def test_mutations_fail(self):
        n, t = krn2()
        for old, new in [("the firmware and TPM", "the bootloader"),
                         ("the enforcer (STO-4)", "the router"),
                         ("is a tripwire, not containment", "is containment"),
                         ("the spec claims no such containment", "the spec claims containment"),
                         ("Compromise of that base is out of scope", "Compromise of that base is in scope")]:
            self.assertIn(old, t)
            with self.assertRaises(AssertionError, msg=old):
                self.check(t.replace(old, new), n)


if __name__ == "__main__":
    unittest.main()
