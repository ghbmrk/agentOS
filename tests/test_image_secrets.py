"""IMG-1 (#914): the built disk holds no private key and no Owner Card outside /usr slot A, and the
boot test attaches a host disk that the box never writes (HW-1, ONB-2).

Kept apart from tests/test_image.py, which several open PRs edit (D-111)."""
# REQ: HW-1, ONB-2
import importlib.machinery
import importlib.util
import os
import pathlib
import re
import subprocess
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
# A JSON encoder that also escapes the slash (PHP's json_encode by default), with a / in the
# first body line's first 40 characters, so that line must be read past as an escaped one.
PEM_SLASH = ('{"private_key": "' + ("-----BEGIN " + "PRIVATE KEY-----\n" + "Q0/OQVJZ" * 8 + "\n" +
             "Q0FOQVJZ" * 8 + "\n-----END " + "PRIVATE KEY-----\n").replace("/", "\\/").replace("\n", "\\n")
             + '"}').encode()
CARD = ("firstboot-" + "card.json").encode()
# The key indented under its header: a YAML block scalar, and a JSON value pretty-printed in an object.
PEM_YAML = ("key: |\n  -----BEGIN " + "PRIVATE KEY-----\n  " + "Q0FOQVJZ" * 8 + "\n  -----END " + "PRIVATE KEY-----\n").encode()
PEM_JSON_INDENT = ('{"private_key": "-----BEGIN ' + 'PRIVATE KEY-----\\n    ' + "Q0FOQVJZ" * 8 + '\\n"}').encode()


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
            for what, data in (("private key", PEM), ("private key", PEM_JSON), ("private key", PEM_SLASH),
                               ("private key", PEM_YAML), ("private key", PEM_JSON_INDENT),
                               ("age secret key", AGE), ("Owner Card", CARD)):
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
            for run in (b"\\n", b"\\/\\n", b" \n", b"\t\n", b" " * 15 + b"\n"):
                img = self.disk(d, [(PART["root"], header + run * 200)])
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
        self.assertIn("expected /usr slot A's two partitions", bad[0])
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


class SlotATest(unittest.TestCase):
    """HW-1: slot A's disk ranges equal the verified split files, and /usr holds no key but the allowed."""

    SIZE = MB * 512

    def build(self, d, data=b"", tree=b"", disk_writes=()):
        """A disk whose slot A holds DATA and its verity TREE (at the partition starts), and the
        split files holding the same bytes; disk_writes are (offset, bytes) added on the disk only."""
        d = pathlib.Path(d)
        img = d / "disk.raw"
        with open(img, "wb") as f:
            f.truncate(8 << 20)
            for part, blob in (("agentos_1.0", data), ("agentos_1.0_verity", tree)):
                f.seek(PART[part])
                f.write(blob)
            for off, blob in disk_writes:
                f.seek(off)
                f.write(blob)
        (d / "usr.raw").write_bytes(data)
        (d / "usr-verity.raw").write_bytes(tree)
        return str(img), d / "usr.raw", d / "usr-verity.raw"

    def check(self, d, allowed=frozenset(), **kw):
        img, data, tree = self.build(d, **kw)
        return finish.slot_a_violations(img, TABLE, data, tree, allowed)

    def test_matching_ranges_and_no_key_pass(self):
        # REQ: HW-1
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(self.check(d, data=b"erofs" * 1000, tree=b"tree" * 100), [])

    def test_a_key_in_usr_fails_unless_its_hash_is_allowed(self):
        # REQ: HW-1
        import hashlib
        with tempfile.TemporaryDirectory() as d:
            bad = self.check(d, data=b"x" * 100 + PEM)
            self.assertEqual(len(bad), 1)
            self.assertIn("private key in usr.raw at byte 100", bad[0])
            digest = hashlib.sha256(finish.SLOT_A_PATTERNS[0][1].search(PEM).group()).hexdigest()
            self.assertIn(digest, bad[0])
            self.assertNotIn(PEM.decode()[:30], bad[0])
            self.assertEqual(self.check(d, {("private key", digest)}, data=b"x" * 100 + PEM), [])
            # The card's names are the box's own (agentosd carries them), and a key in the
            # verity tree's file is not content.
            self.assertEqual(self.check(d, data=CARD * 3, tree=PEM), [])

    def test_a_new_key_beside_an_allowed_one_still_fails(self):
        # REQ: HW-1
        import hashlib
        other = PEM.replace(b"Q0FOQVJZ", b"Q0FOQVJa")
        digest = hashlib.sha256(finish.SLOT_A_PATTERNS[0][1].search(PEM).group()).hexdigest()
        with tempfile.TemporaryDirectory() as d:
            bad = self.check(d, {("private key", digest)}, data=PEM + b"\0" * 64 + other)
        self.assertEqual(len(bad), 1)

    def test_a_key_across_a_chunk_boundary_is_found_once(self):
        # REQ: HW-1
        with tempfile.TemporaryDirectory() as d, \
                unittest.mock.patch.multiple(finish, SCAN_CHUNK=1 << 16, SCAN_OVERLAP=4096):
            bad = self.check(d, data=b"x" * ((1 << 16) - 20) + PEM)
        self.assertEqual(len(bad), 1)

    def test_a_key_starting_in_the_overlap_is_left_to_the_next_chunk(self):
        # REQ: HW-1
        # The first read runs on past its chunk by the overlap; a match that starts there is the next
        # chunk's, so it is reported once.
        with tempfile.TemporaryDirectory() as d, \
                unittest.mock.patch.multiple(finish, SCAN_CHUNK=1 << 16, SCAN_OVERLAP=4096):
            bad = self.check(d, data=b"x" * ((1 << 16) + 100) + PEM)
        self.assertEqual(len(bad), 1)

    def test_a_disk_range_that_differs_from_the_split_file_fails(self):
        # REQ: HW-1
        with tempfile.TemporaryDirectory() as d:
            bad = self.check(d, data=b"a" * 1000, tree=b"t" * 1000, disk_writes=[(PART["agentos_1.0"] + 700, b"Z")])
            self.assertEqual(bad, ["disk differs from usr.raw at byte 700"])
            bad = self.check(d, data=b"a" * 1000, tree=b"t" * 1000,
                             disk_writes=[(PART["agentos_1.0_verity"] + 999, b"Z")])
            self.assertEqual(bad, ["disk differs from usr-verity.raw at byte 999"])

    def test_data_in_the_slack_after_the_split_file_fails(self):
        # REQ: HW-1
        # The verity partition is larger than its hash tree; nothing hashes what follows it.
        with tempfile.TemporaryDirectory() as d:
            bad = self.check(d, data=b"a" * 1000, tree=b"t" * 1000,
                             disk_writes=[(PART["agentos_1.0_verity"] + 5000, b"payload")])
            self.assertEqual(len(bad), 1)
            self.assertIn("after usr-verity.raw", bad[0])
            self.assertEqual(self.check(d, data=b"a" * 1000, tree=b"t" * 1000), [])

    def test_a_file_larger_than_its_partition_fails(self):
        # REQ: HW-1
        with tempfile.TemporaryDirectory() as d:
            img, data, tree = self.build(d, data=b"a", tree=b"t")
            data.write_bytes(b"a" * (self.SIZE + 1))
            bad = finish.slot_a_violations(img, TABLE, data, tree, frozenset())
        self.assertIn("does not fit", bad[0])

    def test_without_slot_as_two_partitions_it_is_reported(self):
        # REQ: HW-1
        table = {"sectorsize": 512, "partitions": [p for p in TABLE["partitions"] if p["name"] != "agentos_1.0"]}
        with tempfile.TemporaryDirectory() as d:
            img, data, tree = self.build(d)
            self.assertEqual(finish.slot_a_violations(img, table, data, tree, frozenset()),
                             ["expected /usr slot A's two partitions"])

    def test_main_checks_slot_a_after_verifying_usr(self):
        # REQ: HW-1
        src = (IMG / "finish_image.py").read_text()
        self.assertLess(src.index("    verify_usr(data, tree, roothash)\n"), src.index("    bad = slot_a_violations("))

    def test_the_shipped_allowlist_parses(self):
        # REQ: HW-1
        allowed = finish.slot_a_allowed()
        for kind, digest in allowed:
            self.assertIn(kind, [k for k, _ in finish.SLOT_A_PATTERNS])
            self.assertRegex(digest, r"^[0-9a-f]{64}$")


class ForeignDisksTest(unittest.TestCase):
    """ONB-2, HW-8: the guest reports every mount or swap on a disk other than the boot disk."""

    SCRIPT = IMG / "mkosi/mkosi.extra/usr/lib/agentos/foreign-disks"

    def run_script(self, mounts, swaps="", chains=None, root="/dev/vda3", namespaces=None, real_b=False):
        """Runs the script on a stand-in /proc. mounts and swaps are space-separated sources; a mount
        word NAME@MAJ:MIN names its device number, any other /dev name gets one of 252:N and any other
        word (tmpfs, a 9p share) major 0. namespaces is a list of further mount lists, each its own
        process's mountinfo; chains maps a /dev name to its lsblk -s lines ("NAME TYPE"). Unless real_b,
        every /dev swap name counts as a block device."""
        chains = chains or {}
        nums = {}

        def mm(word):
            name, _, num = word.partition("@")
            if num:
                nums[name] = num
            elif name not in nums:
                nums[name] = ("252:%d" if name.startswith("/dev/") else "0:%d") % (len(nums) + 1)
            return nums[name]

        lines = lambda words: "".join("echo '%s'\n" % w for w in words.split())

        def stub(t, name, body):
            (t / name).write_text("#!/bin/sh\n" + body)
            (t / name).chmod(0o755)

        with tempfile.TemporaryDirectory() as t:
            t = pathlib.Path(t)
            proc = t / "proc"
            for pid, ms in enumerate([mounts] + list(namespaces or []), 1):
                (proc / str(pid)).mkdir(parents=True)
                (proc / str(pid) / "mountinfo").write_text("".join(
                    "%d 1 %s / /m%d rw - ext4 %s rw\n" % (i, mm(m), i, m.partition("@")[0])
                    for i, m in enumerate(ms.split(), 1)))
            (proc / "swaps").write_text("Filename Type Size Used Priority\n" +
                                        "".join("%s partition 1 0 -2\n" % w for w in swaps.split()))
            stub(t, "findmnt", "echo %s\n" % mm(root))
            stub(t, "readlink", 'echo "$2"\n')
            keyed = dict(chains)
            keyed.update({"/dev/block/" + nums[d]: out for d, out in chains.items() if d in nums})
            stub(t, "lsblk", 'case "$3" in\n%s*) exit 1 ;; esac\n' % "".join(
                "%s) %s;;\n" % (dev, lines("\n".join(ln.replace(" ", "_") for ln in out)).replace("_", " "))
                for dev, out in keyed.items()))
            script = self.SCRIPT.read_text()
            if not real_b:
                script = script.replace('[ -b "$d" ]', "true")
            env = dict(os.environ, PATH="%s:%s" % (t, os.environ["PATH"]), AGENTOS_PROC=str(proc))
            return subprocess.run(["sh", "-c", script], env=env, capture_output=True, text=True).stdout.strip()

    BOOT = {"/dev/vda3": ["/dev/vda3 part", "/dev/vda disk"], "/dev/vda1": ["/dev/vda1 part", "/dev/vda disk"],
            "/dev/mapper/usr": ["/dev/mapper/usr dm", "/dev/vda4 part", "/dev/vda disk", "/dev/vda5 part", "/dev/vda disk"]}

    def test_only_the_boot_disk_reads_none(self):
        # REQ: HW-8, ONB-2
        out = self.run_script("/dev/vda3 /dev/vda1 /dev/mapper/usr tmpfs proc 9p-share systemd-1", chains=self.BOOT)
        self.assertEqual(out, "foreign=none")

    def test_a_read_only_mount_of_a_host_partition_is_listed(self):
        # REQ: HW-8, ONB-2
        chains = dict(self.BOOT, **{"/dev/vdb1": ["/dev/vdb1 part", "/dev/vdb disk"]})
        self.assertEqual(self.run_script("/dev/vda3 /dev/vdb1", chains=chains), "foreign=/dev/vdb1")

    def test_a_swap_on_a_host_disk_is_listed(self):
        # REQ: HW-8, ONB-2
        chains = dict(self.BOOT, **{"/dev/vdb3": ["/dev/vdb3 part", "/dev/vdb disk"]})
        self.assertEqual(self.run_script("/dev/vda3", swaps="/dev/vdb3", chains=chains), "foreign=/dev/vdb3")

    def test_a_loop_device_is_listed(self):
        # REQ: HW-8, ONB-2
        chains = dict(self.BOOT, **{"/dev/loop0": ["/dev/loop0 loop"]})
        self.assertEqual(self.run_script("/dev/vda3 /dev/loop0", chains=chains), "foreign=/dev/loop0")

    def test_a_mount_in_another_namespace_is_listed(self):
        # REQ: HW-8, ONB-2
        chains = dict(self.BOOT, **{"/dev/vdb1": ["/dev/vdb1 part", "/dev/vdb disk"]})
        self.assertEqual(self.run_script("/dev/vda3", namespaces=["/dev/vda3 /dev/vdb1"], chains=chains),
                         "foreign=/dev/vdb1")

    def test_a_listing_without_the_root_source_is_unknown_not_none(self):
        # REQ: HW-8, ONB-2
        # A mount listing that cannot be read leaves no root source in it; that must not read as none.
        self.assertEqual(self.run_script("", chains=self.BOOT), "foreign=unknown")

    def test_a_block_mount_whose_source_is_not_under_dev_is_listed(self):
        # REQ: HW-8, ONB-2
        # mount(2) takes any path as the source; the device number says what is mounted.
        chains = dict(self.BOOT, **{"/run/hostdisk": ["/dev/vdb1 part", "/dev/vdb disk"]})
        self.assertEqual(self.run_script("/dev/vda3 /run/hostdisk@252:90", chains=chains), "foreign=/dev/vdb1")
        self.assertEqual(self.run_script("/dev/vda3 dev/vdb1@252:90", chains={
            "dev/vdb1": ["/dev/vdb1 part", "/dev/vdb disk"], **self.BOOT}), "foreign=/dev/vdb1")

    def test_a_mount_with_an_anonymous_device_number_is_listed_by_its_source(self):
        # REQ: HW-8, ONB-2
        # btrfs reports major 0 and names the real device only as its source.
        chains = dict(self.BOOT, **{"/dev/vdb1": ["/dev/vdb1 part", "/dev/vdb disk"]})
        self.assertEqual(self.run_script("/dev/vda3 /dev/vdb1@0:50", chains=chains), "foreign=/dev/vdb1")

    def test_a_swap_source_that_is_not_a_block_device_is_listed(self):
        # REQ: HW-8, ONB-2
        # Neither name is a block device here (/dev/null is a character device), so both are foreign.
        chains = dict(self.BOOT, **{"/dev/null": ["/dev/null disk"]})
        self.assertEqual(self.run_script("/dev/vda3", swaps="/dev/null", chains=chains, real_b=True),
                         "foreign=/dev/null")

    def test_a_device_lsblk_cannot_read_is_unknown_not_none(self):
        # REQ: HW-8, ONB-2
        self.assertEqual(self.run_script("/dev/vda3 /dev/vdb1", chains=self.BOOT), "foreign=unknown")
        self.assertEqual(self.run_script("/dev/vda3", chains={}), "foreign=unknown")

    def test_boot_report_prints_the_line_and_ci_reads_it_on_both_boots(self):
        # REQ: HW-8, ONB-2
        report = (IMG / "mkosi/mkosi.extra/usr/lib/agentos/boot-report").read_text()
        self.assertIn('echo "agentos-disks: $(/usr/lib/agentos/foreign-disks 2>/dev/null || echo foreign=unknown)"', report)
        sh = (IMG / "ci_boot.sh").read_text()
        # Exactly one line of each kind, reading foreign=none: a "none" line cannot hide a listing.
        self.assertIn('disks_none "$W/console.log" "agentos-disks:"', sh)
        self.assertIn('disks_none "$W/console-e2e.log" "agentos-disks:"', sh)
        self.assertIn('disks_none "$W/console-e2e.log" "agentos-disks-end:"', sh)
        unit = (IMG / "e2e/agentos-e2e.service").read_text()
        self.assertIn("ExecStartPost=/bin/sh -c 'echo \"agentos-disks-end: $(/usr/lib/agentos/foreign-disks)\"'", unit)
        self.assertRegex(sh, r'UNTIL="agentos-e2e: DONE[^\n]* boot "\$W/console-e2e\.log" "\$W/e2e\.raw" "\$H2"\n')
        self.assertIn("MISS host disk unchanged (e2e boot)", sh)


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
