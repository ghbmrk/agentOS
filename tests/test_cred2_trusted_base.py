"""CRED-2t: SPEC.md's CRED-2 text states the trusted base and claims no containment.

CRED-2 is a scope statement; the testable content is the sentence itself (D-082).
"""
# REQ: CRED-2
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
MEMBERS = ["host kernel", "hypervisor", "firmware", "broker",
           "credentialed-executor sandboxes", "processes in them that read credentials"]


def cred2():
    for n, line in enumerate((ROOT / "SPEC.md").read_text().splitlines(), 1):
        if line.startswith("- **CRED-2** "):
            return n, line
    raise AssertionError("SPEC.md has no '- **CRED-2**' bullet")


class TrustedBase(unittest.TestCase):
    def check(self, text, line_no):
        flat = re.sub(r"\s+", " ", text)
        for m in MEMBERS:
            self.assertIn(m, flat, f"SPEC.md:{line_no} CRED-2 no longer names '{m}'")
        self.assertRegex(flat, r"(?i)tripwire, not containment of a compromised credential reader",
                         f"SPEC.md:{line_no} CRED-2 scanning is no longer a tripwire without containment")
        self.assertIn("the spec claims no such containment", flat,
                      f"SPEC.md:{line_no} CRED-2 no longer disclaims containment (D-082)")
        self.assertRegex(flat, r"(?i)compromise of that base is out of scope",
                         f"SPEC.md:{line_no} CRED-2 no longer puts base compromise out of scope")

    def test_names_every_trusted_base_member(self):
        n, t = cred2()
        self.check(t, n)

    def test_scanning_is_tripwire_not_containment(self):
        n, t = cred2()
        self.assertIn("CRED-7", t, f"SPEC.md:{n} CRED-2 no longer ties scanning to CRED-7")
        self.check(t, n)

    def test_compromise_of_base_out_of_scope(self):
        n, t = cred2()
        self.check(t, n)

    def test_mutations_fail(self):
        n, t = cred2()
        for old, new in [("firmware", "bios"),
                         ("is a tripwire, not containment", "is containment"),
                         ("the spec claims no such containment", "the spec claims containment"),
                         ("Compromise of that base is out of scope", "Compromise of that base is in scope")]:
            self.assertIn(old, t)
            with self.assertRaises(AssertionError, msg=old):
                self.check(t.replace(old, new), n)


if __name__ == "__main__":
    unittest.main()
