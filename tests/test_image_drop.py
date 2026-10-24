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
        self.assertEqual(set(calls[0][3:]), set(drop.DROP))
        self.assertEqual(set(calls[1][4:]), set(drop.DROP))


class WiringTest(unittest.TestCase):
    def test_postinst_drops_before_it_copies_the_status_file(self):
        text = (MK / "mkosi.postinst").read_text()
        self.assertLess(text.index('python3 "$SRCDIR/drop.py" "$BUILDROOT"'), text.index("dpkg-status"))
        self.assertTrue(os.access(MK / "drop.py", os.X_OK))

    def test_no_record_accepts_a_dropped_source(self):
        records = json.loads((ROOT / "assurance/vulncheck.json").read_text())["accepted"]
        gone = {src for src, _ in drop.DROP.values()}
        self.assertEqual([r["id"] for r in records if r.get("where") == "image" and r["package"] in gone], [])


if __name__ == "__main__":
    unittest.main()
