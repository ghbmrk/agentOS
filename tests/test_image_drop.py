"""VULN-debian (#2919): the image purges packages the box does not need (image/mkosi/drop.py).

Each dropped package is a hard dependency of one the box keeps, so dpkg purges it with
--force-depends; the files that linked it go too, and the build fails if any ELF file under usr
still names a library a dropped package shipped. The scan's records for a dropped source go, since
a record that matches no finding fails the scan."""
# REQ: EVL-5
import importlib.util
import json
import os
import pathlib
import struct
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_image import MK, ROOT  # noqa: E402

spec = importlib.util.spec_from_file_location("drop", MK / "drop.py")
drop = importlib.util.module_from_spec(spec)
spec.loader.exec_module(drop)

BASE = 0x400000


def elf(needed, e_type=3, machine=62, cls=2, strtab_at=None):
    """A minimal ELF file: one PT_LOAD over the whole file, a PT_DYNAMIC naming NEEDED."""
    strtab = b"\0"
    offs = []
    for n in needed:
        offs.append(len(strtab))
        strtab += n.encode() + b"\0"
    str_off = 64 + 2 * 56
    dyn_off = str_off + len(strtab) + (-(str_off + len(strtab)) % 8)
    tags = [(1, o) for o in offs] + [(5, BASE + str_off if strtab_at is None else strtab_at), (0, 0)]
    dyn = b"".join(struct.pack("<qQ", t, v) for t, v in tags)
    size = dyn_off + len(dyn)
    ident = b"\x7fELF" + bytes((cls, 1, 1)) + bytes(9)
    head = struct.pack("<16sHHIQQQIHHHHHH", ident, e_type, machine, 1, 0, 64, 0, 0, 64, 56, 2, 64, 0, 0)
    load = struct.pack("<IIQQQQQQ", 1, 5, 0, BASE, BASE, size, size, 0x1000)
    dynamic = struct.pack("<IIQQQQQQ", 2, 6, dyn_off, BASE + dyn_off, BASE + dyn_off, len(dyn), len(dyn), 8)
    body = head + load + dynamic + strtab
    return body + bytes(dyn_off - len(body)) + dyn


class DynamicTest(unittest.TestCase):
    def test_reads_needed(self):
        self.assertEqual(drop.dynamic(elf(["libbluetooth.so.3", "libc.so.6"])), ["libbluetooth.so.3", "libc.so.6"])
        self.assertEqual(drop.dynamic(elf([])), [])

    def test_other_files_are_not_read(self):
        for data in (elf(["x.so"], e_type=1), elf(["x.so"], machine=183), elf(["x.so"], cls=1), b"#!/bin/sh\n" * 10):
            self.assertIsNone(drop.dynamic(data))

    def test_a_string_table_outside_the_file_is_refused(self):
        with self.assertRaises(ValueError):
            drop.dynamic(elf(["x.so"], strtab_at=0x10))


class NeededTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def put(self, rel, data):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return p

    def test_a_file_that_links_a_dropped_library_fails(self):
        self.put("usr/lib/x86_64-linux-gnu/NetworkManager/1.52.1/libnm-device-plugin-bluetooth.so",
                 elf(["libbluetooth.so.3", "libglib-2.0.so.0"]))
        self.put("usr/sbin/NetworkManager", elf(["libglib-2.0.so.0"]))
        self.put("usr/lib/modules/x.ko", elf(["libbluetooth.so.3"], e_type=1))
        self.put("usr/share/doc/readme", b"libbluetooth.so.3")
        os.symlink("NetworkManager", self.root / "usr/sbin/nm-link")
        out = drop.needed_violations(str(self.root), {"libbluetooth.so.3"})
        self.assertEqual(out, ["usr/lib/x86_64-linux-gnu/NetworkManager/1.52.1/libnm-device-plugin-bluetooth.so: "
                               "needs libbluetooth.so.3, which a dropped package shipped"])
        self.assertEqual(drop.needed_violations(str(self.root), {"libnewt.so.0.52"}), [])

    def test_an_unreadable_dynamic_section_fails(self):
        self.put("usr/bin/odd", elf(["x.so"], strtab_at=0x10))
        self.assertIn("unreadable dynamic section", drop.needed_violations(str(self.root), set())[0])

    def test_a_removed_unit_loses_its_enablement_link(self):
        unit = self.put("usr/lib/systemd/system/dpkg-db-backup.timer", b"[Timer]\n")
        wants = self.root / "etc/systemd/system/timers.target.wants"
        wants.mkdir(parents=True)
        os.symlink("/usr/lib/systemd/system/dpkg-db-backup.timer", wants / "dpkg-db-backup.timer")
        os.symlink("/usr/lib/systemd/system/other.timer", wants / "other.timer")
        with mock.patch.object(drop, "FILES", ("usr/lib/systemd/system/dpkg-db-backup.timer",)):
            self.assertEqual(drop.remove_files(str(self.root)), [])
        self.assertFalse(unit.exists() or os.path.lexists(wants / "dpkg-db-backup.timer"))
        self.assertTrue(os.path.lexists(wants / "other.timer"))

    def test_files_go_and_a_stale_pattern_fails(self):
        a = self.put("usr/bin/nmtui", b"x")
        b = self.put("usr/bin/nmtui-edit", b"x")
        with mock.patch.object(drop, "FILES", ("usr/bin/nmtui*", "usr/lib/gone.so")):
            out = drop.remove_files(str(self.root))
        self.assertFalse(a.exists() or b.exists())
        self.assertEqual(out, ["usr/lib/gone.so: matches nothing; drop.py's FILES is stale"])

    def test_shipped_names_only_libraries(self):
        listed = ["/.", "/usr/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu/libbluetooth.so.3.19.15",
                  "/usr/lib/x86_64-linux-gnu/libbluetooth.so.3", "/usr/share/doc/libbluetooth3/copyright"]
        self.assertEqual(drop.shipped(listed), {"libbluetooth.so.3.19.15", "libbluetooth.so.3"})

    def test_main_purges_then_checks(self):
        calls = []

        def run(argv, **kw):
            calls.append(argv)
            return mock.Mock(stdout="/usr/lib/x86_64-linux-gnu/libnewt.so.0.52\n")

        self.put("usr/bin/whiptail", elf(["libnewt.so.0.52"]))
        with mock.patch.object(drop.subprocess, "run", run), mock.patch.object(drop, "FILES", ()):
            self.assertEqual(drop.main(str(self.root)), 1)
        self.assertEqual(calls[0][:3], ["mkosi-chroot", "dpkg-query", "-L"])
        self.assertEqual(calls[1][:4], ["mkosi-chroot", "dpkg", "--purge", "--force-depends"])
        self.assertEqual(calls[2][:5], ["mkosi-chroot", "dpkg", "--purge", "--force-depends", "--force-remove-essential"])
        self.assertEqual(set(calls[0][3:]), set(drop.DROP))
        self.assertEqual(set(calls[1][4:]), set(drop.DROP) - set(drop.ESSENTIAL))
        self.assertEqual(calls[2][5:], list(drop.ESSENTIAL))

    def test_main_fails_on_a_script_a_dropped_program_runs(self):
        def run(argv, **kw):
            return mock.Mock(stdout="/usr/bin/perl\n/bin/tar\n")

        self.put("usr/sbin/odd", b"#!/usr/bin/perl -w\nprint 1;\n").chmod(0o755)
        with mock.patch.object(drop.subprocess, "run", run), mock.patch.object(drop, "FILES", ()), \
                mock.patch.object(drop, "PERL_TOOLS", {}):
            self.assertEqual(drop.main(str(self.root)), 1)
            (self.root / "usr/sbin/odd").unlink()
            self.assertEqual(drop.main(str(self.root)), 0)

    def test_essential_packages_are_dropped(self):
        self.assertTrue(set(drop.ESSENTIAL) <= set(drop.DROP))
        self.assertEqual({drop.DROP[p][0] for p in ("tar", "diffutils", "perl-base")}, {"tar", "diffutils", "perl"})

    def test_efivar_goes_with_mokutil_and_shim_stays(self):
        # shim-unsigned is the only package of source shim the scan sees, but the box boots shim's
        # code from shim-signed (and its helpers), whose source differs: dropping shim-unsigned would
        # hide the advisory while the code it names still runs first at boot.
        self.assertEqual({drop.DROP[p][0] for p in ("mokutil", "libefivar1t64")}, {"mokutil", "efivar"})
        self.assertNotIn("shim", {src for src, _ in drop.DROP.values()})

    def test_sqlite_goes_with_lastlog2_and_tirpc_with_ss(self):
        # libsqlite3-0 is linked only by liblastlog2-2, liblastlog2-2 only by lslogins, and
        # libtirpc3t64 only by ss; util-linux keeps its other packages, so its records stay (PARTIAL).
        self.assertEqual({drop.DROP[p][0] for p in ("libsqlite3-0", "libtirpc3t64", "libtirpc-common")},
                         {"sqlite3", "libtirpc"})
        self.assertEqual(drop.DROP["liblastlog2-2"][0], "util-linux")
        self.assertIn("usr/bin/ss", drop.FILES)
        self.assertIn("usr/bin/lslogins", drop.FILES)
        self.assertEqual(set(drop.PARTIAL), {"liblastlog2-2"})

    def test_shadow_goes_with_its_tools_and_bzip2_with_dpkg_deb(self):
        # passwd and login.defs are shadow's only packages in the image; useradd, userdel and usermod
        # are libsemanage2's only users, and libsemanage2 and dpkg-deb are libbz2's (traced in trixie
        # with the image's own package list). adduser only drives useradd, so its perl goes too.
        self.assertEqual({drop.DROP[p][0] for p in ("passwd", "login.defs")}, {"shadow"})
        self.assertEqual({drop.DROP[p][0] for p in ("libsemanage2", "libsemanage-common", "libsepol2", "libbz2-1.0")},
                         {"libsemanage", "libsepol", "bzip2"})
        self.assertIn("adduser", drop.DROP)
        self.assertNotIn("adduser", drop.PERL_TOOLS)
        self.assertIn("usr/bin/dpkg-deb", drop.FILES)
        self.assertTrue({"shadow", "bzip2"}.isdisjoint(drop.DROP[p][0] for p in drop.PARTIAL))


class InterpreterTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)

    def put(self, rel, data, mode=0o755):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        p.chmod(mode)

    def test_reads_the_interpreter(self):
        self.assertEqual(drop.interpreter(b"#!/usr/bin/perl -w\n"), "/usr/bin/perl")
        self.assertEqual(drop.interpreter(b"#! /bin/sh\n"), "/usr/bin/sh")
        self.assertEqual(drop.interpreter(b"#!/usr/bin/env -S LC_ALL=C perl -T\n"), "perl")
        self.assertEqual(drop.interpreter(b"#!/bin/env\n"), "")
        self.assertIsNone(drop.interpreter(b"\x7fELF"))

    def test_programs_are_usr_paths_under_bin(self):
        listed = ["/.", "/bin/tar", "/usr/sbin/rmt-tar", "/usr/lib/mime/packages/tar", "/usr/share/doc/tar"]
        self.assertEqual(drop.programs(listed), {"/usr/bin/tar", "/usr/sbin/rmt-tar"})

    def test_a_script_a_dropped_program_runs_fails(self):
        self.put("usr/bin/a", b"#!/usr/bin/perl\n")
        self.put("usr/sbin/b", b"#!/usr/bin/env perl\n")
        self.put("usr/lib/c", b"#!/bin/perl\n")
        self.put("usr/bin/ok", b"#!/bin/sh\nperl -e 1\n")
        self.put("usr/share/d", b"no shebang perl")
        self.put("usr/share/perl5/M.pm", b"#!/usr/bin/perl\n", mode=0o644)
        os.symlink("a", self.root / "usr/bin/link")
        self.assertEqual(drop.interpreter_violations(str(self.root), {"/usr/bin/perl"}), [
            "usr/bin/a: runs /usr/bin/perl, which a dropped package shipped",
            "usr/lib/c: runs /usr/bin/perl, which a dropped package shipped",
            "usr/sbin/b: runs perl, which a dropped package shipped",
        ])
        self.assertEqual(drop.interpreter_violations(str(self.root), {"/usr/bin/tar"}), [])

    def test_an_allowed_package_keeps_its_scripts_and_a_stale_one_fails(self):
        self.put("usr/sbin/adduser", b"#! /usr/bin/perl -T\n")
        self.put("usr/bin/linux-version", b"#!/usr/bin/perl\n")
        info = self.root / "var/lib/dpkg/info"
        info.mkdir(parents=True)
        (info / "adduser.list").write_text("/.\n/usr\n/usr/sbin/adduser\n")
        (info / "linux-base.list").write_text("/bin/linux-version\n")
        self.assertEqual(drop.interpreter_violations(str(self.root), {"/usr/bin/perl"}, {"adduser": "", "linux-base": ""}), [])
        self.assertEqual(drop.interpreter_violations(str(self.root), {"/usr/bin/perl"}, {"adduser": "", "debconf": ""}), [
            "usr/bin/linux-version: runs /usr/bin/perl, which a dropped package shipped",
            "debconf: owns no script a dropped program runs; drop.py's PERL_TOOLS is stale",
        ])

    def test_owners_reads_dpkg_lists(self):
        info = self.root / "var/lib/dpkg/info"
        info.mkdir(parents=True)
        (info / "libc6:amd64.list").write_text("/usr/lib/x86_64-linux-gnu/libc.so.6\n")
        (info / "tar.list").write_text("/bin/tar\n")
        self.assertEqual(drop.owners(str(self.root)), {"/usr/lib/x86_64-linux-gnu/libc.so.6": "libc6", "/usr/bin/tar": "tar"})


class WiringTest(unittest.TestCase):
    def test_postinst_drops_before_it_copies_the_status_file(self):
        text = (MK / "mkosi.postinst").read_text()
        self.assertLess(text.index('python3 "$SRCDIR/drop.py" "$BUILDROOT"'), text.index("dpkg-status"))
        self.assertTrue(os.access(MK / "drop.py", os.X_OK))

    def test_no_record_accepts_a_dropped_source(self):
        records = json.loads((ROOT / "assurance/vulncheck.json").read_text())["accepted"]
        gone = {src for p, (src, _) in drop.DROP.items() if p not in drop.PARTIAL}
        self.assertTrue(set(drop.PARTIAL) <= set(drop.DROP))
        self.assertTrue({drop.DROP[p][0] for p in drop.PARTIAL}.isdisjoint(gone))
        self.assertEqual([r["id"] for r in records if r.get("where") == "image" and r["package"] in gone], [])


if __name__ == "__main__":
    unittest.main()
