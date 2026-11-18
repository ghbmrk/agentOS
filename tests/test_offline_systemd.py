"""image/offline_systemd.py built_tree(): the checks that run over the built tree read /usr through
dm-verity against the boot entry's usrhash= (#4825), so a /usr rewritten after finish_image verified it
cannot pass them.

REQ: UPD-1a
"""
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "image"))
import finish_image  # noqa: E402
import offline_systemd  # noqa: E402

V = "0.1"
HASH = "ab" * 32
ENTRY = "title agentOS\nlinux /vmlinuz\noptions usrhash=%s quiet\n" % HASH
TABLE = {"sectorsize": 512, "partitions": [{"type": finish_image.ROOT_GUID.upper(), "start": 2048, "size": 100}]}


class BuiltTree(unittest.TestCase):
    def setUp(self):
        self.out = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.out, True)
        for f in ("agentos_%s.raw", "agentos_%s.usr.raw", "agentos_%s.usr-verity.raw"):
            (self.out / (f % V)).write_bytes(b"")
        (self.out / ("agentos_%s.conf" % V)).write_text(ENTRY)
        self.calls = []
        self.fail_on = None
        self.mkd = []

        def run(argv, check=False):
            self.calls.append(list(argv))
            if self.fail_on and argv[0] == self.fail_on[0] and self.fail_on[1] in argv:
                raise subprocess.CalledProcessError(1, argv)
            return subprocess.CompletedProcess(argv, 0)

        real_mkdtemp = tempfile.mkdtemp

        def mkdtemp(**kw):
            d = real_mkdtemp(**kw)
            self.mkd.append(d)
            self.addCleanup(shutil.rmtree, d, True)
            return d
        for p in (mock.patch.object(offline_systemd.subprocess, "run", side_effect=run),
                  mock.patch.object(offline_systemd.finish_image, "partition_table", return_value=TABLE),
                  mock.patch.object(offline_systemd.tempfile, "mkdtemp", side_effect=mkdtemp)):
            p.start()
            self.addCleanup(p.stop)

    def name(self):
        return pathlib.Path(self.mkd[0]).name

    def test_usr_is_mounted_from_the_verity_device_opened_against_usrhash(self):
        root, usr, cmdline, cleanup = offline_systemd.built_tree(self.out, V)
        n = self.name()
        self.assertIn(["veritysetup", "open", str(self.out / ("agentos_%s.usr.raw" % V)), n,
                       str(self.out / ("agentos_%s.usr-verity.raw" % V)), HASH], self.calls)
        self.assertIn(["mount", "-t", "erofs", "-o", "ro", "/dev/mapper/" + n, str(usr)], self.calls)
        # usr.raw itself is never mounted: only the mapped device, whose every read dm-verity checks.
        usr_raw = str(self.out / ("agentos_%s.usr.raw" % V))
        self.assertFalse([c for c in self.calls if c[0] == "mount" and usr_raw in c])
        self.assertLess(self.calls.index(next(c for c in self.calls if c[0] == "veritysetup")),
                        self.calls.index(next(c for c in self.calls if "/dev/mapper/" + n in c)))
        self.assertIn("usrhash=" + HASH, cmdline)
        self.calls.clear()
        cleanup()
        self.assertEqual(self.calls, [["umount", str(usr)], ["veritysetup", "close", n], ["umount", str(root)]])

    def test_an_entry_without_usrhash_mounts_nothing(self):
        (self.out / ("agentos_%s.conf" % V)).write_text("title agentOS\noptions quiet\n")
        with self.assertRaises(SystemExit) as e:
            offline_systemd.built_tree(self.out, V)
        self.assertIn("usrhash", str(e.exception))
        self.assertEqual(self.calls, [])

    def test_a_missing_hash_tree_mounts_nothing(self):
        (self.out / ("agentos_%s.usr-verity.raw" % V)).unlink()
        with self.assertRaises(SystemExit) as e:
            offline_systemd.built_tree(self.out, V)
        self.assertIn("hash tree", str(e.exception))
        self.assertEqual(self.calls, [])

    def test_a_refused_open_unmounts_root_and_raises(self):
        self.fail_on = ("veritysetup", "open")
        with self.assertRaises(subprocess.CalledProcessError):
            offline_systemd.built_tree(self.out, V)
        root = str(pathlib.Path(self.mkd[0]) / "root")
        self.assertEqual(self.calls[-1], ["umount", root])
        self.assertFalse([c for c in self.calls if c[:2] == ["mount", "-t"]])

    def test_a_refused_usr_mount_closes_the_verity_device(self):
        self.fail_on = ("mount", "erofs")
        with self.assertRaises(subprocess.CalledProcessError):
            offline_systemd.built_tree(self.out, V)
        n = self.name()
        self.assertEqual(self.calls[-2:], [["veritysetup", "close", n],
                                           ["umount", str(pathlib.Path(self.mkd[0]) / "root")]])


if __name__ == "__main__":
    unittest.main()
