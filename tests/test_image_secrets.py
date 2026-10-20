"""IMG-1 (#914): the built disk holds no private key and no Owner Card outside /usr slot A, and the
boot test attaches a host disk that the box never writes (HW-1, ONB-2).

Kept apart from tests/test_image.py, which several open PRs edit (D-111)."""
# REQ: HW-1, ONB-2
import importlib.machinery
import importlib.util
import os
import pathlib
import re
import tempfile
import time
import unittest
import unittest.mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
IMG = ROOT / "image"
ESP = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
ROOTFS = "4f68bce3-e8cd-4db1-96e7-fbcaf984b709"
USR, USR_VERITY = "8484680c-9521-48c6-9c11-b0720656f69e", "77ff5f63-e7b6-4633-acf4-1565b864c0e6"

# Synthetic canaries, assembled here so no scanner sees a key in this file. Neither is a real key.
PEM = ("-----BEGIN " + "PRIVATE KEY-----\n" + "Q0FOQVJZ" * 8 + "\n-----END " + "PRIVATE KEY-----\n").encode()
AGE = ("AGE-SECRET-" + "KEY-1" + "QQQQ" * 14 + "QQ").encode()
# The same key JSON-escaped, as a provider credential file stores it (a literal backslash-n).
PEM_JSON = ('{"private_key": "' + PEM.decode().replace("\n", "\\n") + '"}').encode()
CARD = ("firstboot-" + "card.json").encode()


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


finish = load("finish_image_secrets", IMG / "finish_image.py")

# Sectors: the ESP, /usr slot A and its verity, slot B and its verity, root. 1 MiB each.
MB = 2048
TABLE = {"sectorsize": 512, "partitions": [
    {"start": 1 * MB, "size": MB, "type": ESP.upper(), "name": "esp"},
    {"start": 2 * MB, "size": MB, "type": USR.upper(), "name": "agentos_1.0"},
    {"start": 3 * MB, "size": MB, "type": USR_VERITY.upper(), "name": "agentos_1.0_verity"},
    {"start": 4 * MB, "size": MB, "type": USR.upper(), "name": "_empty"},
    {"start": 5 * MB, "size": MB, "type": USR_VERITY.upper(), "name": "_empty"},
    {"start": 6 * MB, "size": MB, "type": ROOTFS.upper(), "name": "root"},
]}
PART = {p["name"] if p["name"] != "_empty" else "slot b %d" % i: p["start"] * 512
        for i, p in enumerate(TABLE["partitions"])}


class SecretScanTest(unittest.TestCase):
    def disk(self, d, writes):
        """A sparse 8 MiB disk with each (offset, bytes) written."""
        path = pathlib.Path(d) / "disk.raw"
        with open(path, "wb") as f:
            f.truncate(8 << 20)
            for off, data in writes:
                f.seek(off)
                f.write(data)
        return str(path)

    def test_a_clean_disk_passes(self):
        # REQ: HW-1
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(finish.secret_violations(self.disk(d, [(PART["root"], b"ok")]), TABLE), [])

    def test_a_key_or_card_outside_usr_slot_a_is_refused(self):
        # REQ: HW-1
        for where in ("esp", "slot b 3", "slot b 4", "root"):
            for what, data in (("private key", PEM), ("private key", PEM_JSON), ("age secret key", AGE),
                               ("Owner Card", CARD)):
                with self.subTest(where=where, what=what), tempfile.TemporaryDirectory() as d:
                    off = PART[where] + 4096 + 17
                    bad = finish.secret_violations(self.disk(d, [(off, data)]), TABLE)
                    # The offset is where the key starts, past any JSON around it.
                    self.assertEqual(bad, ["%s at byte %d" % (what, off + max(data.find(b"-----"), 0))])
                    # The report names the kind and place, never the bytes.
                    self.assertNotIn(data.decode()[:20], " ".join(bad))
        with tempfile.TemporaryDirectory() as d:
            # Before the first partition and after the last too: the whole disk is scanned.
            self.assertEqual(len(finish.secret_violations(self.disk(d, [(0, PEM), ((8 << 20) - 200, AGE)]), TABLE)), 2)

    def test_usr_slot_a_is_left_to_the_verity_hash(self):
        # REQ: HW-1
        # /usr is package content, checked against usrhash and compared across runners: libcrypto
        # and test keys in node_modules are not the owner's secrets.
        with tempfile.TemporaryDirectory() as d:
            img = self.disk(d, [(PART["agentos_1.0"] + 100, PEM + CARD), (PART["agentos_1.0_verity"] + 9, AGE)])
            self.assertEqual(finish.secret_violations(img, TABLE), [])

    def test_a_bare_header_is_not_a_key(self):
        # REQ: HW-1
        # libcrypto and gpg carry the header strings alone; only a header with a key body counts.
        header = ("-----BEGIN " + "PRIVATE KEY-----").encode()
        with tempfile.TemporaryDirectory() as d:
            img = self.disk(d, [(PART["root"], header + b"\0" * 64), (PART["esp"], header + b"\n%s\n"),
                                (PART["root"] + 4096, header + b"\\n%s\\n")])
            self.assertEqual(finish.secret_violations(img, TABLE), [])

    def test_a_run_of_escaped_breaks_without_a_body_fails_fast(self):
        # REQ: HW-1
        # A body line holds no backslash, so each escaped break ends a line in one place only and a
        # header followed by many of them is rejected in linear time, not by the job timeout.
        header = ("-----BEGIN " + "PRIVATE KEY-----").encode()
        with tempfile.TemporaryDirectory() as d:
            img = self.disk(d, [(PART["root"], header + b"\\n" * 200)])
            start = time.monotonic()
            self.assertEqual(finish.secret_violations(img, TABLE), [])
            self.assertLess(time.monotonic() - start, 1.0)

    def test_a_key_across_a_chunk_boundary_is_found_once(self):
        # REQ: HW-1
        with tempfile.TemporaryDirectory() as d, \
                unittest.mock.patch.multiple(finish, SCAN_CHUNK=1 << 16, SCAN_OVERLAP=4096):
            off = PART["root"] + (1 << 16) - 20
            self.assertEqual(finish.secret_violations(self.disk(d, [(off, PEM)]), TABLE),
                             ["private key at byte %d" % off])

    def test_a_changed_layout_scans_the_whole_disk(self):
        # REQ: HW-1
        # Without exactly slot A's two partitions nothing is skipped, and the change is reported.
        table = {"sectorsize": 512, "partitions": [p for p in TABLE["partitions"] if p["name"] != "agentos_1.0"]}
        with tempfile.TemporaryDirectory() as d:
            bad = finish.secret_violations(self.disk(d, [(PART["agentos_1.0"] + 5, CARD)]), table)
        self.assertIn("found 1", bad[0])
        self.assertEqual(bad[1:], ["Owner Card at byte %d" % (PART["agentos_1.0"] + 5)])

    def test_main_refuses_a_disk_with_a_secret(self):
        # REQ: HW-1
        # finish_image.main() runs the scan on the built disk and stops the release.
        calls = []

        def secrets(img, table):
            calls.append((img, table))
            return ["private key at byte 7"]

        class Proc:
            @staticmethod
            def check_output(*a, **k):
                return "::/loader/entries/a.conf\n"

            @staticmethod
            def run(*a, **k):
                return None

        with tempfile.TemporaryDirectory() as d, \
                unittest.mock.patch.multiple(finish, subprocess=Proc, esp_offset=lambda img: 0,
                                             counted_entry=lambda src, v: ("a+3.conf", "entry"),
                                             esp_violations=lambda paths, text: [],
                                             cmdline_violations=lambda text: [],
                                             swap_violations=lambda parts, text: [],
                                             partition_table=lambda img: {"partitions": []},
                                             quota_violations=lambda img, table, text: [],
                                             secret_violations=secrets):
            with self.assertRaises(SystemExit) as e:
                finish.main(d, "1.0")
        self.assertIn("HW-1", str(e.exception.code))
        self.assertIn("byte 7", str(e.exception.code))
        self.assertEqual(calls, [(str(pathlib.Path(d) / "agentos_1.0.raw"), {"partitions": []})])


class HostDiskBootTest(unittest.TestCase):
    """ONB-2: the box never mounts or writes a disk that is not its boot drive."""

    def setUp(self):
        self.sh = (IMG / "ci_boot.sh").read_text()

    def test_the_first_boot_attaches_a_host_disk(self):
        # REQ: ONB-2, HW-1
        m = re.search(r"\nhost_disk\(\) \{\n(.*?)\n\}\n", self.sh, re.S)
        self.assertIsNotNone(m, "ci_boot.sh defines host_disk")
        body = m.group(1).lower()
        # A host's usual partitions: an ESP (which drive-id must not take for the box's), a data
        # partition, swap and a Linux filesystem, each holding a canary.
        for guid in (ESP, "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7", "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f",
                     "0fc63daf-8483-4772-8e79-3d69d8477de4"):
            self.assertIn(guid, body)
        self.assertIn("mkswap", body)
        self.assertIn("mkfs.ext4", body)
        self.assertRegex(self.sh, r'\n\s*PROBE=[^\n]* boot "\$W/console\.log" "\$D" "\$H"\n')

    def test_the_host_disk_is_unchanged_after_the_boot(self):
        # REQ: ONB-2
        before = self.sh.index('host_before=$(sha256sum <"$H")')
        boot = self.sh.index('boot "$W/console.log" "$D" "$H"')
        after = self.sh.index('[ "$(sha256sum <"$H")" = "$host_before" ]')
        self.assertLess(before, boot)
        self.assertLess(boot, after)
        self.assertIn("MISS host disk unchanged", self.sh[after:after + 200])
        self.assertIn("fail=1", self.sh[after:after + 200])


if __name__ == "__main__":
    unittest.main()
