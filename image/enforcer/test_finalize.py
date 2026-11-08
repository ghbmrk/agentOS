#!/usr/bin/env python3
"""Tests for the enforcer's tree check (mkosi/mkosi.finalize): the core dump settings (#4459)."""
import importlib.machinery
import importlib.util
import pathlib
import shutil
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
MK = HERE / "mkosi"
_loader = importlib.machinery.SourceFileLoader("enforcer_finalize", str(MK / "mkosi.finalize"))
fin = importlib.util.module_from_spec(importlib.util.spec_from_loader("enforcer_finalize", _loader))
_loader.exec_module(fin)

NODUMP = "usr/lib/sysctl.d/99-enforcer-nodump.conf"


class NoDump(unittest.TestCase):
    """REQ: NET-2. A crashed radio stack writes no core to a file: the image's sysctl.d sends every
    dump to a helper that discards it, and the tree check refuses a tree where anything undoes that."""

    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        (self.root / "var/lib/dpkg").mkdir(parents=True)
        (self.root / "var/lib/dpkg/status").write_text("")
        for rel in ("usr/lib/systemd/system-preset/50-enforcer.preset", "usr/lib/modprobe.d/enforcer-off.conf", NODUMP):
            (self.root / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(MK / "mkosi.extra" / rel, self.root / rel)

    def put(self, rel, text):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def refusals(self):
        return [v for v in fin.violations(self.root) if "sysctl" in v]

    def test_shipped_tree_passes(self):
        self.assertEqual(fin.violations(self.root), [])
        vals, _ = fin.sysctls(self.root)
        self.assertEqual(vals["kernel/core_pattern"], "|/usr/bin/false")
        self.assertEqual(vals["fs/suid_dumpable"], "0")

    def test_kernel_default_refused(self):
        # No file: the kernel keeps its relative "core", written into the stack's run directory.
        (self.root / NODUMP).unlink()
        self.assertEqual(len(self.refusals()), 2)

    def test_override_refused(self):
        for name, line in (("zz-late.conf", "kernel.core_pattern = core\n"),
                           ("zz-late.conf", "kernel/core_pattern=/run/radio/core.%p\n"),
                           ("zz-late.conf", "/kernel//core_pattern=core\n"),
                           ("zz-late.conf", "-kernel.core_pattern\n"),
                           ("zz-late.conf", "kernel.core_*=core\n"),
                           ("zz-late.conf", "fs.suid_dumpable=2\n"),
                           ("zz-late.conf", "x=1\rkernel.core_pattern=core\n")):
            with self.subTest(line=line):
                self.put("usr/lib/sysctl.d/" + name, line)
                self.assertEqual(len(self.refusals()), 1, self.refusals())
                (self.root / "usr/lib/sysctl.d" / name).unlink()

    def test_masked_in_etc_refused(self):
        # A same-named file higher up replaces the shipped one.
        self.put("etc/sysctl.d/99-enforcer-nodump.conf", "")
        self.assertEqual(len(self.refusals()), 2)

    def test_link_refused(self):
        self.put("var/tmp/x.conf", "kernel.core_pattern=|/usr/bin/false\n")
        (self.root / "etc/sysctl.d").mkdir(parents=True)
        (self.root / "etc/sysctl.d/10-x.conf").symlink_to("/var/tmp/x.conf")
        self.assertIn("sysctl.d: etc/sysctl.d/10-x.conf is a link", self.refusals())

    def test_comments_and_earlier_files_do_not_count(self):
        self.put("usr/lib/sysctl.d/10-early.conf", "kernel.core_pattern=core\n")
        self.put("etc/sysctl.d/zz-note.conf", "# kernel.core_pattern=core\n; fs.suid_dumpable=2\n")
        self.assertEqual(self.refusals(), [])


if __name__ == "__main__":
    unittest.main()
