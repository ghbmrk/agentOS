"""A unit's root step is counted in the trusted core (KEY-9-reach-inbound-wiring, #5678; KRN-2, D-310).

A `+` command runs with full privileges. When it runs one of agentOS's Go binaries (broker/cmd/<name>,
installed as /usr/lib/agentos/<name>), that binary must be a `root cmd/<name>` line of
tools/trusted_core.txt, so tools/trusted_base.py measures what root runs and a change to it needs a
core-scoped review. The owner page's root step was agentos-localui -admit-port1, which the measure did not
see; it is now agentos-port1.
"""
# REQ: KRN-2
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
UNIT_DIRS = (ROOT / "broker", ROOT / "image/mkosi/mkosi.extra/usr/lib/systemd/system")
PAGE_UNIT = ROOT / "broker/cmd/agentos-localui/agentos-localui.service"


def roots(text):
    return {m.group(1) for m in re.finditer(r"^root\s+(\S+)\s*$", text, re.M)}


def root_steps(text):
    """The agentOS binaries a unit's `+` commands run, by name."""
    text = text.replace("\\\n", " ")
    out = []
    for line in text.splitlines():
        m = re.match(r"\s*Exec\w+\s*=\s*([-@:!+]*)\s*(\S+)", line)
        if m and "+" in m.group(1):
            b = re.fullmatch(r"/usr/lib/agentos/([\w.-]+)", m.group(2))
            if b and (ROOT / "broker/cmd" / b.group(1)).is_dir():
                out.append(b.group(1))
    return out


def uncounted(text, core):
    return [b for b in root_steps(text) if "cmd/" + b not in core]


class RootStepsAreCounted(unittest.TestCase):
    core = roots((ROOT / "tools/trusted_core.txt").read_text())

    def units(self):
        for d in UNIT_DIRS:
            for p in sorted(d.rglob("*")):
                if p.suffix in (".service", ".conf") and p.is_file() and "testdata" not in p.parts:
                    yield p

    def test_every_root_step_is_a_root_of_the_core(self):
        for p in self.units():
            with self.subTest(p.relative_to(ROOT)):
                self.assertEqual(uncounted(p.read_text(), self.core), [])

    def test_the_page_root_step_is_agentos_port1(self):
        self.assertEqual(root_steps(PAGE_UNIT.read_text()), ["agentos-port1"])
        self.assertIn("netguard/port1", self.core)

    def test_the_old_line_fails(self):
        old = "[Service]\nExecStartPre=+/usr/lib/agentos/agentos-localui -admit-port1 -port1-file /run/agentos-localui/port1\n"
        self.assertEqual(uncounted(old, self.core), ["agentos-localui"])
        self.assertEqual(uncounted(old.replace("=+", "=-+"), self.core), ["agentos-localui"])
        self.assertEqual(uncounted(old.replace("=+", "="), self.core), [])


if __name__ == "__main__":
    unittest.main()
