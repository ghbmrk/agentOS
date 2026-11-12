#!/usr/bin/env python3
"""Tests for the enforcer's boot self-check (mkosi.extra/usr/lib/agentos-enforcer/health), run against
a fake root (ENFORCER_HEALTH_ROOT): its rp_filter loop (#4810, #5120)."""
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

HEALTH = pathlib.Path(__file__).resolve().parent / "mkosi/mkosi.extra/usr/lib/agentos-enforcer/health"


class Health(unittest.TestCase):
    """REQ: NET-2, HW-16. The self-check reads rp_filter on every key under /proc/sys/net/ipv4/conf and
    fails the boot unless each is 0: the kernel uses the larger of "all" and the interface's value."""

    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        self.put("usr/share/agentos-enforcer/release-root.json", "{}")
        self.put("sys/class/watchdog/watchdog0/state", "active")
        self.put("proc/sys/kernel/core_pattern", "|/usr/bin/false")
        self.put("proc/sys/fs/suid_dumpable", "0")
        self.put("proc/swaps", "Filename Type Size Used Priority\n")
        for k in ("all", "default", "enp1s0"):
            self.rpf(k, "0")

    def put(self, rel, text):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text + "\n")

    def rpf(self, name, val):
        self.put("proc/sys/net/ipv4/conf/%s/rp_filter" % name, val)

    def run_health(self):
        r = subprocess.run(["sh", str(HEALTH)], capture_output=True, text=True,
                           env={"PATH": os.environ["PATH"], "ENFORCER_HEALTH_ROOT": str(self.root)})
        return r.returncode, r.stdout.strip()

    def test_all_zero_passes_and_names_interfaces(self):
        code, out = self.run_health()
        self.assertEqual(code, 0, out)
        self.assertIn("rp_filter=0:all,default,enp1s0 ", out + " ")

    def test_card_at_2_fails_and_is_named(self):
        self.rpf("enp1s0", "2")
        self.assertEqual(self.run_health(), (1, "enforcer-health: FAIL rp_filter is not 0 on enp1s0"))

    def test_all_at_1_fails(self):
        self.rpf("all", "1")
        self.assertEqual(self.run_health(), (1, "enforcer-health: FAIL rp_filter is not 0 on all"))

    def test_no_conf_entries_fails_on_the_glob(self):
        # No entry: the shell leaves the glob itself, which names no readable file, and the check fails.
        shutil.rmtree(self.root / "proc/sys/net/ipv4/conf")
        (self.root / "proc/sys/net/ipv4/conf").mkdir()
        self.assertEqual(self.run_health(), (1, "enforcer-health: FAIL rp_filter is not 0 on *"))


if __name__ == "__main__":
    unittest.main()
