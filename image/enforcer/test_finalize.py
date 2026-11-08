#!/usr/bin/env python3
"""Tests for the enforcer's tree check (mkosi/mkosi.finalize): the core dump settings (#4459), the
reverse-path filter and the blocked modules left out of the image (#4810)."""
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
RPF = "usr/lib/sysctl.d/99-enforcer-rpfilter.conf"
# What systemd's own sysctl.d/50-default.conf says about rp_filter (upstream, as Debian ships it).
DEFAULT_50 = ("net.ipv4.conf.default.rp_filter = 2\nnet.ipv4.conf.*.rp_filter = 2\n"
              "-net.ipv4.conf.all.rp_filter\n")


class Tree(unittest.TestCase):
    """A tree holding the image's preset, module blocks and sysctl.d files, and systemd's 50-default."""

    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root)
        (self.root / "var/lib/dpkg").mkdir(parents=True)
        (self.root / "var/lib/dpkg/status").write_text("")
        for rel in ("usr/lib/systemd/system-preset/50-enforcer.preset", "usr/lib/modprobe.d/enforcer-off.conf", NODUMP, RPF):
            (self.root / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(MK / "mkosi.extra" / rel, self.root / rel)
        self.put("usr/lib/sysctl.d/50-default.conf", DEFAULT_50)

    def put(self, rel, text):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)


class NoDump(Tree):
    """REQ: NET-2. A crashed radio stack writes no core to a file: the image's sysctl.d sends every
    dump to a helper that discards it, and the tree check refuses a tree where anything undoes that."""

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


class RpFilter(Tree):
    """REQ: NET-2, HW-16. The WAN leases (#4810): the kernel's reverse-path filter, which would drop
    the WAN's DHCP answers before the ruleset's rpf chain sees them, is 0 on "all", "default" and every
    interface once systemd-sysctl has read sysctl.d in its order, over systemd's 50-default.conf."""

    def refusals(self):
        return [v for v in fin.violations(self.root) if "rp_filter" in v]

    def test_shipped_tree_passes(self):
        self.assertEqual(fin.violations(self.root), [])
        vals, _ = fin.sysctls(self.root)
        for k in fin.RPF:
            self.assertEqual(vals[k], "0", k)

    def test_50_default_alone_refused(self):
        # Without the image's file, "all" is left alone and default and every interface are 2.
        (self.root / RPF).unlink()
        self.assertEqual(self.refusals(), [
            "sysctl.d sets net.ipv4.conf.*.rp_filter to 2; rp_filter must be 0",
            "sysctl.d sets net.ipv4.conf.all.rp_filter to None; rp_filter must be 0",
            "sysctl.d sets net.ipv4.conf.default.rp_filter to 2; rp_filter must be 0"])

    def test_unset_refused(self):
        # The kernel's own default is 0, but the image must say so: nothing set is refused.
        (self.root / RPF).unlink()
        (self.root / "usr/lib/sysctl.d/50-default.conf").unlink()
        self.assertEqual(len(self.refusals()), 3)

    def test_override_refused(self):
        for name, line in (("zz-late.conf", "net.ipv4.conf.*.rp_filter = 2\n"),
                           ("zz-late.conf", "net.ipv4.conf.all.rp_filter=1\n"),
                           ("zz-late.conf", "net/ipv4/conf/default/rp_filter=2\n"),
                           ("zz-late.conf", "-net.ipv4.conf.default.rp_filter\n"),
                           ("zz-late.conf", "-net.ipv4.conf.*.rp_filter\n"),
                           ("zz-late.conf", "net.ipv4.conf.enp1s0.rp_filter=2\n"),
                           ("zz-late.conf", "net.ipv4.conf.en*.rp_filter=1\n"),
                           ("zz-late.conf", "net.*.conf.*.rp_filter=2\n"),
                           ("zz-late.conf", "net.ipv4.con[^x].*.rp_*=2\n"),
                           ("zz-late.conf", "x=1\rnet.ipv4.conf.wan0.rp_filter=1\n"),
                           ("00-early.conf", "net.ipv4.conf.wan0.rp_filter=2\n")):
            with self.subTest(name=name, line=line):
                self.put("usr/lib/sysctl.d/" + name, line)
                self.assertEqual(len(self.refusals()), 1, self.refusals())
                (self.root / "usr/lib/sysctl.d" / name).unlink()

    def test_masked_in_etc_refused(self):
        self.put("etc/sysctl.d/99-enforcer-rpfilter.conf", "")
        self.assertEqual(len(self.refusals()), 3)

    def test_replaced_and_unrelated_keys_pass(self):
        # An earlier file's same glob is replaced; other keys and other families are not rp_filter.
        self.put("usr/lib/sysctl.d/10-early.conf", "net.ipv4.conf.*.rp_filter=2\n")
        self.put("etc/sysctl.d/zz-x.conf", "# net.ipv4.conf.all.rp_filter=1\nnet.ipv4.conf.all.forwarding=1\n"
                 "net.ipv6.conf.all.rp_filter=1\nnet.ipv4.conf.all.arp_filter=1\n")
        self.assertEqual(self.refusals(), [])


class BlockedModules(Tree):
    """REQ: NET-2. Wi-Fi and USB storage cannot load: their modules are not in the image, since the
    modprobe.d block alone let cfg80211 load once a network card was present (#4810)."""

    KDIR = "usr/lib/modules/6.12.0-1-amd64/kernel/"

    def refusals(self):
        return [v for v in fin.violations(self.root) if v.startswith("module ")]

    def test_kept_modules_pass(self):
        for rel in ("drivers/net/virtio_net.ko.xz", "drivers/net/ethernet/intel/igc/igc.ko.xz", "net/wireless_x.ko"):
            self.put(self.KDIR + rel, "")
        self.assertEqual(fin.violations(self.root), [])

    def test_each_blocked_module_refused(self):
        for rel in ("net/wireless/cfg80211.ko.xz", "net/mac80211/mac80211.ko.zst", "drivers/usb/storage/usb-storage.ko",
                    "drivers/usb/storage/uas.ko.xz", "updates/usb_storage.ko"):
            with self.subTest(rel=rel):
                self.put(self.KDIR + rel, "")
                self.assertEqual(self.refusals(), ["module %s is installed" % (self.KDIR + rel)])
                (self.root / self.KDIR / rel).unlink()


if __name__ == "__main__":
    unittest.main()
