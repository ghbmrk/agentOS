"""A21 in QEMU (#3117): the host side of ci_boot.sh's slice boot, without QEMU.

The guest's run script is taken from ci_boot.sh itself and run here over the requests
image/slice_boot.py writes, with the native slice binary standing in for the guest's; the check
must pass that run and fail a guest that changed, dropped or mislabelled an outcome.
"""
# REQ: EVL-2
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "image"))
import slice_boot  # noqa: E402

CI_BOOT = (ROOT / "image" / "ci_boot.sh").read_text()


def run_script():
    m = re.search(r"^slice_run\(\) \{\n\tcat <<'EOS'\n(.*?)^EOS\n\}", CI_BOOT, re.M | re.S)
    return m.group(1)


class SliceBoot(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="slice-boot-")
        share = os.path.join(cls.tmp, "in")
        cls.out = os.path.join(cls.tmp, "out")
        os.makedirs(os.path.join(share, "req"))
        os.makedirs(cls.out)
        slice_boot.native.SliceBinary.build()
        shutil.copy(slice_boot.native.SliceBinary.exe, os.path.join(share, "slice"))
        cls.n = slice_boot.requests(os.path.join(share, "req"), ("",))
        script = run_script().replace("/run/agentos-slice/in", share).replace("/run/agentos-slice/out", cls.out)
        cls.console = subprocess.run(["sh", "-c", script], capture_output=True, text=True, check=True).stdout

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)
        if slice_boot.native.SliceBinary.tmp:
            shutil.rmtree(slice_boot.native.SliceBinary.tmp, ignore_errors=True)

    def outcome(self, i=0):
        return sorted(p for p in os.listdir(self.out) if p.endswith(".1.json"))[i]

    def test_guest_run_passes(self):
        self.assertIn("agentos-slice: DONE requests=%d failed=0" % self.n, self.console)
        self.assertEqual(slice_boot.check(self.out, ("",)), {})

    def test_changed_outcome_fails(self):
        p = os.path.join(self.out, self.outcome())
        keep = open(p, "rb").read()
        try:
            o = json.loads(keep)
            o["owner_taps"] = list(o.get("owner_taps", [])) + ["approve-key"]
            open(p, "w").write(json.dumps(o))
            self.assertNotEqual(slice_boot.check(self.out, ("",)), {})
        finally:
            open(p, "wb").write(keep)

    def test_missing_or_unreadable_outcome_fails(self):
        p = os.path.join(self.out, self.outcome(1))
        keep = open(p, "rb").read()
        try:
            for bad in (None, b"not json", b"[]"):
                if bad is None:
                    os.remove(p)
                else:
                    open(p, "wb").write(bad)
                with self.subTest(bad=bad):
                    self.assertIn("*", slice_boot.check(self.out, ("",))["synthetic"])
        finally:
            open(p, "wb").write(keep)

    def test_outcome_counts_only_for_its_request(self):
        """Swapping two requests' outcomes fails: an outcome is read by its request's digest."""
        a, b = (os.path.join(self.out, self.outcome(i)) for i in (0, 1))
        ka, kb = open(a, "rb").read(), open(b, "rb").read()
        try:
            open(a, "wb").write(kb)
            open(b, "wb").write(ka)
            self.assertNotEqual(slice_boot.check(self.out, ("",)), {})
        finally:
            open(a, "wb").write(ka)
            open(b, "wb").write(kb)

    def test_failure_lines_are_one_printable_line(self):
        self.assertEqual(slice_boot.printable("x\n::error::y\x1b[0m"), "x?::error::y?[0m")

    def test_unit_has_no_network_and_runs_on_every_kernel_or_clerk_change(self):
        self.assertIn(r"PrivateNetwork=yes\n", CI_BOOT)
        wf = (ROOT / ".github" / "workflows" / "image.yml").read_text()
        for path in ("broker/kernel/**", "broker/clerk/**", "evals/slice-inbox/**",
                     "tests/test_slice_inbox_slice.py"):
            self.assertEqual(wf.count('- "%s"' % path), 2, path)
        self.assertIn('SLICE="$RUNNER_TEMP/slice"', wf)


if __name__ == "__main__":
    unittest.main()
