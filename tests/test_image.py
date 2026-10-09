# Tests for the device image build (P2-1): the build-time tree check, the release manifest,
# the counted boot entry, the boot health check, and the image's static configuration.
# The image itself is built and booted under Secure Boot by .github/workflows/image.yml.
# REQ: HW-1, HW-5, UPD-1, UPD-1a
import base64
import configparser
import importlib.machinery
import importlib.util
import os
import re
import pathlib
import socket
import stat
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
IMG = ROOT / "image"
MK = IMG / "mkosi"


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


check = load("image_check", MK / "mkosi.finalize")
finish = load("image_finish", IMG / "finish_image.py")


def ini(path):
    # systemd and mkosi files repeat keys and use bare multi-line values.
    p = configparser.ConfigParser(strict=False, interpolation=None, delimiters=("=",))
    p.optionxform = str
    p.read(path)
    return p


def write(root, rel, text="", mode=0o644):
    f = root / rel
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(text)
    f.chmod(mode)
    return f


class TreeCheckTest(unittest.TestCase):
    """HW-1: the image holds no per-install secret; V15: no socket files."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.tmp.name)
        write(self.root, "etc/machine-id", "uninitialized\n")
        write(self.root, "etc/hostname", "agentos\n")
        write(self.root, "usr/lib/agentos/agentosd", "\x7fELF", 0o755)
        (self.root / "var/lib/agentos").mkdir(parents=True)

    def tearDown(self):
        self.tmp.cleanup()

    def test_clean_tree_passes(self):
        self.assertEqual(check.violations(self.root), [])

    def test_empty_machine_id_passes(self):
        write(self.root, "etc/machine-id", "")
        self.assertEqual(check.violations(self.root), [])

    def test_baked_machine_id(self):
        write(self.root, "etc/machine-id", "0123456789abcdef0123456789abcdef\n")
        self.assertIn("etc/machine-id", " ".join(check.violations(self.root)))

    def test_generated_secret_files(self):
        for rel in ("var/lib/systemd/random-seed", "var/lib/systemd/credential.secret",
                    "etc/ssh/ssh_host_ed25519_key", "etc/ssl/private/ssl-cert-snakeoil.key",
                    "var/lib/dbus/machine-id"):
            with self.subTest(rel=rel):
                f = write(self.root, rel, "x")
                self.assertTrue(any(rel in v for v in check.violations(self.root)))
                f.unlink()

    def test_owner_state_must_not_ship(self):
        write(self.root, "etc/agentos/agentosd.env", "AGENTOS_OWNER=+15550100\n")
        self.assertIn("etc/agentos", " ".join(check.violations(self.root)))
        (self.root / "etc/agentos/agentosd.env").unlink()
        (self.root / "etc/agentos").rmdir()
        write(self.root, "var/lib/agentos/journal.log", "{}")
        self.assertIn("var/lib/agentos", " ".join(check.violations(self.root)))

    def test_credstore_and_other_key_formats(self):
        write(self.root, "etc/credstore.encrypted/agentos.token", "x")
        write(self.root, "etc/backup/key.asc", "-----BEGIN PGP PRIVATE KEY BLOCK-----\n")
        write(self.root, "var/lib/age/key.txt", "AGE-SECRET-KEY-1SYNTHETICCANARY\n")
        v = " ".join(check.violations(self.root))
        for rel in ("etc/credstore.encrypted/agentos.token", "etc/backup/key.asc", "var/lib/age/key.txt"):
            self.assertIn(rel, v)

    def test_private_key_content(self):
        # A synthetic header only: no real key material in the repository.
        write(self.root, "etc/something/key.pem", "-----BEGIN PRIVATE KEY-----\nAAAA\n")
        write(self.root, "root/.ssh/id", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n")
        v = " ".join(check.violations(self.root))
        self.assertIn("etc/something/key.pem", v)
        self.assertIn("root/.ssh/id", v)

    def test_public_material_under_usr_share_is_not_scanned(self):
        write(self.root, "usr/share/doc/pkg/example.pem", "-----BEGIN PRIVATE KEY-----\n")
        self.assertEqual(check.violations(self.root), [])

    def test_socket_file_anywhere(self):
        p = self.root / "usr/lib/agentos/images/openclaw/run/agentos/broker.sock"
        p.parent.mkdir(parents=True)
        with socket.socket(socket.AF_UNIX) as s:
            s.bind(str(p))
        self.assertTrue(stat.S_ISSOCK(os.lstat(p).st_mode))
        self.assertIn("broker.sock", " ".join(check.violations(self.root)))

    def test_main_exits_nonzero_on_violation(self):
        write(self.root, "var/lib/systemd/random-seed", "x")
        r = subprocess.run([str(MK / "mkosi.finalize")], env=dict(os.environ, BUILDROOT=str(self.root)),
                           capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("random-seed", r.stdout + r.stderr)


ENTRY = """title Debian GNU/Linux 13 (trixie)
version 6.12.48+deb13-amd64
sort-key debian
options console=tty0 console=ttyS0 rw quiet usrhash=%s
linux /debian/6.12.48+deb13-amd64/linux
initrd /debian/6.12.48+deb13-amd64/initrd
"""
H = "ab" * 32


class ReleaseTest(unittest.TestCase):
    """UPD-1a: a release is the /usr verity root hash plus its boot entry; UPD-1: entries are counted."""

    def test_entry_is_counted_and_titled(self):
        name, text = finish.counted_entry(ENTRY % H, "7", tries=3)
        self.assertEqual(name, "agentos_7+3.conf")
        self.assertIn("title AgentOS\n", text)
        self.assertIn("version 7\n", text)
        self.assertIn("usrhash=%s" % H, text)
        self.assertEqual(text.count("title "), 1)

    def test_entry_without_usrhash_is_refused(self):
        with self.assertRaises(ValueError):
            finish.counted_entry(ENTRY.replace(" usrhash=%s", "") % (), "7", tries=3)

    def test_manifest_binds_hash_and_entry(self):
        name, text = finish.counted_entry(ENTRY % H, "7", tries=3)
        m = finish.manifest("7", H, name, text, {"agentos_7.usr.raw": "11" * 32})
        self.assertEqual(m["version"], "7")
        self.assertEqual(m["usrhash"], H)
        self.assertEqual(m["boot_entry"]["name"], "agentos_7.conf")
        self.assertEqual(len(m["boot_entry"]["sha256"]), 64)
        self.assertEqual(m["files"], {"agentos_7.usr.raw": "11" * 32})

    def test_manifest_records_the_boot_payload(self):
        name, text = finish.counted_entry(ENTRY % H, "7", tries=3)
        boot = {"debian/6.12.48+deb13-amd64/linux": "22" * 32, "debian/6.12.48+deb13-amd64/initrd": "33" * 32}
        self.assertEqual(finish.boot_files(text), list(reversed(sorted(boot))))
        self.assertEqual(finish.manifest("7", H, name, text, {}, boot)["boot"], boot)

    def test_loader_conf_has_no_editor_or_enrollment(self):
        # F1: with the editor on, anyone at the keyboard could drop usrhash= or add init=/bin/sh.
        lines = finish.LOADER_CONF.splitlines()
        self.assertIn("timeout 0", lines)
        self.assertIn("editor no", lines)
        self.assertIn("secure-boot-enroll off", lines)

    def test_esp_allowlist(self):
        name, text = finish.counted_entry(ENTRY % H, "7", tries=3)
        clean = ["EFI/BOOT/BOOTX64.EFI", "EFI/BOOT/grubx64.efi", "EFI/BOOT/mmx64.efi",
                 "EFI/systemd/systemd-bootx64.efi", "loader/loader.conf", "loader/entries.srel",
                 "loader/entries/" + name, "debian/6.12.48+deb13-amd64/linux", "debian/6.12.48+deb13-amd64/initrd"]
        self.assertEqual(finish.esp_violations(clean, text), [])
        planted = clean + ["loader/random-seed", "loader/credentials/agentos.cred", "debian/other/initrd",
                           "loader/entries/debian-6.12.conf"]
        self.assertEqual(finish.esp_violations(planted, text),
                         ["debian/other/initrd", "loader/credentials/agentos.cred",
                          "loader/entries/debian-6.12.conf", "loader/random-seed"])

    def test_build_drops_debian_boot_files_and_seed_from_esp(self):
        # HW-1: the ESP is built from /efi and /boot (00-esp.conf). Debian's kernel package leaves
        # vmlinuz-, config- and System.map- in /boot, and bootctl install writes loader/random-seed,
        # which would ship identical on every drive. mkosi.conf's RemoveFiles drops them; mkosi
        # v24.3 runs it after copying the kernel to /usr/lib/modules and before the entry is installed.
        k = "6.12.111+deb13-amd64"
        pats = ini(MK / "mkosi.conf")["Content"]["RemoveFiles"].split()
        name, text = finish.counted_entry(ENTRY % H, "7", tries=3)
        with tempfile.TemporaryDirectory() as t:
            r = pathlib.Path(t)
            for f in ("efi/EFI/BOOT/BOOTX64.EFI", "efi/EFI/systemd/systemd-bootx64.efi", "efi/loader/loader.conf",
                      "efi/loader/entries.srel", "efi/loader/random-seed", "boot/vmlinuz-" + k,
                      "boot/config-" + k, "boot/System.map-" + k, "usr/lib/modules/%s/vmlinuz" % k):
                write(r, f, "x")
            for pat in pats:
                for f in r.glob(pat.lstrip("/")):
                    f.unlink()
            self.assertTrue((r / "usr/lib/modules" / k / "vmlinuz").exists())
            esp = sorted(str(f.relative_to(r / d)) for d in ("efi", "boot") for f in (r / d).rglob("*") if f.is_file())
            self.assertEqual(finish.esp_violations(esp, text), [], esp)

    def test_verify_usr_fails_when_veritysetup_refuses(self):
        with tempfile.TemporaryDirectory() as t:
            b = pathlib.Path(t)
            stub(b, "veritysetup", "exit 1")
            old = os.environ["PATH"]
            os.environ["PATH"] = "%s:%s" % (b, old)
            try:
                with self.assertRaises(ValueError):
                    finish.verify_usr("d", "t", H)
                stub(b, "veritysetup", '[ "$1" = verify ] && [ "$4" = "%s" ]' % H)
                finish.verify_usr("d", "t", H)
            finally:
                os.environ["PATH"] = old

    def test_manifest_refuses_a_mismatched_entry(self):
        name, text = finish.counted_entry(ENTRY % H, "7", tries=3)
        with self.assertRaises(ValueError):
            finish.manifest("7", "cd" * 32, name, text, {})


def stub(d, name, body):
    write(d, name, "#!/bin/sh\n" + body + "\n", 0o755)


class HealthTest(unittest.TestCase):
    """UPD-1: boot-complete (and so blessing the entry) waits on this check."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = pathlib.Path(self.tmp.name)
        self.bin, self.lib, self.root = t / "bin", t / "lib", t / "root"
        stub(self.bin, "veritysetup", 'echo "/dev/mapper/usr is active and is in use."; echo "  type:        VERITY";'
                                      ' echo "  status:      verified"; echo "  root hash:   %s"' % H)
        self.findmnt("/dev/mapper/usr", "ro,relatime")
        stub(self.lib, "agentosd", "exit 0")
        stub(self.lib, "drive-id", "exit 0")
        stub(self.lib, "runsc", 'echo "runsc version release-20260928.0"')
        (self.lib / "images/openclaw/opt/openclaw").mkdir(parents=True)
        write(self.lib, "guest/launch.json", "{}")
        write(self.root, "proc/cmdline", "console=ttyS0 rw quiet usrhash=%s\n" % H)
        ev = self.root / "sys/firmware/efi/efivars"
        ev.mkdir(parents=True)
        (ev / "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c").write_bytes(b"\x06\x00\x00\x00\x01")

    def findmnt(self, source, options):
        stub(self.bin, "findmnt", 'case "$2" in SOURCE) echo "%s" ;; *) echo "%s" ;; esac' % (source, options))

    def tearDown(self):
        self.tmp.cleanup()

    def run_health(self):
        env = dict(os.environ, PATH="%s:%s" % (self.bin, os.environ["PATH"]),
                   AGENTOS_LIB=str(self.lib), AGENTOS_HEALTH_ROOT=str(self.root))
        return subprocess.run(["sh", str(MK / "mkosi.extra/usr/lib/agentos/health")], env=env,
                              capture_output=True, text=True)

    def test_pass(self):
        r = self.run_health()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("agentos-health: PASS", r.stdout)
        self.assertIn("secure_boot=on", r.stdout)

    def test_secure_boot_off_is_reported_not_failed(self):
        (self.root / "sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c").write_bytes(
            b"\x06\x00\x00\x00\x00")
        r = self.run_health()
        self.assertEqual(r.returncode, 0)
        self.assertIn("secure_boot=off", r.stdout)

    def test_fail_cases(self):
        cases = {
            "usr not verity": lambda: stub(self.bin, "veritysetup", "exit 4"),
            "usr writable": lambda: self.findmnt("/dev/mapper/usr", "rw,relatime"),
            "usr not from verity device": lambda: self.findmnt("/dev/sda3", "ro,relatime"),
            "usr is another release": lambda: write(self.root, "proc/cmdline", "usrhash=%s\n" % ("cd" * 32)),
            "entry names no release": lambda: write(self.root, "proc/cmdline", "rw quiet\n"),
            "launch.json missing": lambda: (self.lib / "guest/launch.json").unlink(),
            "boot drive ambiguous": lambda: stub(self.lib, "drive-id", "echo 'agentos-drive-id: FAIL'; exit 1"),
            "broker missing": lambda: (self.lib / "agentosd").unlink(),
            "broker broken": lambda: stub(self.lib, "agentosd", "exit 2"),
            "runsc broken": lambda: stub(self.lib, "runsc", "exit 1"),
            "guest image missing": lambda: (self.lib / "images/openclaw/opt/openclaw").rmdir(),
        }
        for name, breakit in cases.items():
            with self.subTest(name):
                self.tearDown()
                self.setUp()
                breakit()
                r = self.run_health()
                self.assertEqual(r.returncode, 1, name)
                self.assertIn("agentos-health: FAIL", r.stdout)


class FallbackTest(unittest.TestCase):
    """UPD-1 (L3 blockers on #41): a failed health check reboots into the next counted try, with no
    owner action; at no tries left it reboots into the previous release if the drive has one, and
    stays up otherwise."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = pathlib.Path(self.tmp.name)
        self.bin, self.root, self.log = t / "bin", t / "root", t / "systemctl.log"
        (self.root / "sys/firmware/efi/efivars").mkdir(parents=True)
        stub(self.bin, "systemctl", 'echo "$*" >>"%s"' % self.log)

    def tearDown(self):
        self.tmp.cleanup()

    def run_fallback(self, entry=None, entries=None):
        efivars = self.root / "sys/firmware/efi/efivars"
        if entry is not None:
            (efivars / "LoaderBootCountPath-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
             ).write_bytes(b"\x06\x00\x00\x00" + ("\\loader\\entries\\%s\0" % entry).encode("utf-16le"))
        if entries is not None:
            # systemd-boot lists entry IDs (file names without the counter) NUL-separated, in UTF-16.
            (efivars / "LoaderEntries-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
             ).write_bytes(b"\x06\x00\x00\x00" + "".join(e + "\0" for e in entries).encode("utf-16le"))
        env = dict(os.environ, PATH="%s:%s" % (self.bin, os.environ["PATH"]), AGENTOS_HEALTH_ROOT=str(self.root))
        r = subprocess.run(["sh", str(MK / "mkosi.extra/usr/lib/agentos/fallback")], env=env,
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return r.stdout, self.log.read_text() if self.log.exists() else ""

    def test_reboots_while_tries_are_left(self):
        for entry in ("agentos_7+2-1.conf", "agentos_7+1-2.conf", "agentos_7+3.conf"):
            with self.subTest(entry):
                self.log.unlink(missing_ok=True)
                out, calls = self.run_fallback(entry)
                self.assertEqual(calls, "reboot\n")
                self.assertIn("rebooting", out)

    def test_reboots_into_the_previous_release_with_no_tries_left(self):
        # systemd-boot sorts a +0 entry last, so the reboot boots the other release (no default is set).
        out, calls = self.run_fallback("agentos_7+0-3.conf",
                                       ["agentos_8.conf", "agentos_7.conf", "auto-reboot-to-firmware-setup"])
        self.assertEqual(calls, "reboot\n")
        self.assertIn("rebooting into the previous release", out)

    def test_stays_up_with_no_tries_left_and_no_other_release(self):
        for entries in (["agentos_7.conf", "auto-reboot-to-firmware-setup"], None):
            with self.subTest(entries):
                out, calls = self.run_fallback("agentos_7+0-3.conf", entries)
                self.assertEqual(calls, "")
                self.assertIn("staying up", out)

    def test_stays_up_on_an_entry_with_no_counter(self):
        for entry in ("agentos_7.conf", None):
            with self.subTest(entry):
                out, calls = self.run_fallback(entry, ["agentos_8.conf", "agentos_7.conf"])
                self.assertEqual(calls, "")
                self.assertIn("staying up", out)


ESP_GUID = "9bb3f5ba-ad2b-4857-929b-cc8ff3ed410c"


class DriveIdTest(unittest.TestCase):
    """HW-1, HW-5 (L3 MUST on #41): every drive starts with the image's partition GUIDs, so boot is
    bound to the drive only while one partition carries the booted ESP's GUID; each drive then gets
    its own GUIDs."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = pathlib.Path(self.tmp.name)
        self.bin, self.root, self.log = t / "bin", t / "root", t / "sfdisk.log"
        ev = self.root / "sys/firmware/efi/efivars"
        ev.mkdir(parents=True)
        (ev / "LoaderDevicePartUUID-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f").write_bytes(
            b"\x06\x00\x00\x00" + (ESP_GUID.upper() + "\0").encode("utf-16le"))
        for name, n in (("vda1", 1), ("vda6", 6), ("vdb1", 1), ("vdb6", 6)):
            write(self.root, "sys/class/block/%s/partition" % name, "%d\n" % n)
        write(self.root, "proc/sys/kernel/random/uuid", "0f0e0d0c-0b0a-4908-8706-050403020100\n")
        self.disks(("vda1 vda " + ESP_GUID, "vda2 vda aaaaaaaa-0000-4000-8000-000000000002",
                    "vda6 vda bbbbbbbb-0000-4000-8000-000000000006"))
        self.root_on("/dev/vda6")
        stub(self.bin, "sfdisk", 'echo "$*" >>"%s"' % self.log)
        stub(self.bin, "sync", 'echo "sync $*" >>"%s"' % self.log)

    def disks(self, partitions):
        lines = ["vda  ", "vdb  "] + list(partitions) + ["usr vda2 ", "usr vda3 "]
        stub(self.bin, "lsblk", "cat <<'E'\n%s\nE" % "\n".join(lines))

    def root_on(self, dev):
        stub(self.bin, "findmnt", 'echo "%s"' % dev)

    def tearDown(self):
        self.tmp.cleanup()

    def run_id(self, mode):
        env = dict(os.environ, PATH="%s:%s" % (self.bin, os.environ["PATH"]), AGENTOS_HEALTH_ROOT=str(self.root))
        return subprocess.run(["sh", str(MK / "mkosi.extra/usr/lib/agentos/drive-id"), mode], env=env,
                              capture_output=True, text=True)

    def sfdisk_calls(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_check_passes_on_one_drive(self):
        r = self.run_id("check")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.sfdisk_calls(), [])

    def test_check_fails_when_another_disk_carries_the_esp_guid(self):
        self.disks(("vda1 vda " + ESP_GUID, "vda6 vda bbbbbbbb-0000-4000-8000-000000000006",
                    "vdb1 vdb " + ESP_GUID, "vdb6 vdb bbbbbbbb-0000-4000-8000-000000000006"))
        r = self.run_id("check")
        self.assertEqual(r.returncode, 1)
        self.assertIn("agentos-drive-id: FAIL 2 partitions", r.stdout)

    def test_check_fails_when_root_is_on_another_disk(self):
        self.root_on("/dev/vdb6")
        self.disks(("vda1 vda " + ESP_GUID, "vdb6 vdb bbbbbbbb-0000-4000-8000-000000000006"))
        r = self.run_id("check")
        self.assertEqual(r.returncode, 1)
        self.assertIn("not on the boot drive", r.stdout)

    def test_check_fails_without_the_loader_variable(self):
        next((self.root / "sys/firmware/efi/efivars").iterdir()).unlink()
        self.assertEqual(self.run_id("check").returncode, 1)

    def test_check_fails_on_an_unreadable_loader_variable(self):
        # An empty GUID must not match the rows lsblk prints with no PARTUUID (disks, dm devices).
        next((self.root / "sys/firmware/efi/efivars").iterdir()).write_bytes(b"\x06\x00\x00\x00")
        r = self.run_id("check")
        self.assertEqual(r.returncode, 1)
        self.assertIn("unreadable", r.stdout)

    def test_assign_gives_the_drive_its_own_guids(self):
        r = self.run_id("assign")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        u = "0f0e0d0c-0b0a-4908-8706-050403020100"
        nr = "--no-reread --no-tell-kernel"
        self.assertEqual(self.sfdisk_calls(), ["%s --disk-id /dev/vda %s" % (nr, u),
                                               "%s --part-uuid /dev/vda 1 %s" % (nr, u),
                                               "%s --part-uuid /dev/vda 6 %s" % (nr, u),
                                               "sync -f %s/var/lib/agentos/drive-id" % self.root])
        self.assertTrue((self.root / "var/lib/agentos/drive-id").exists())

    def test_assign_writes_nothing_when_the_check_fails(self):
        self.disks(("vda1 vda " + ESP_GUID, "vda6 vda bbbbbbbb-0000-4000-8000-000000000006",
                    "vdb1 vdb " + ESP_GUID))
        r = self.run_id("assign")
        self.assertEqual(r.returncode, 1)
        self.assertEqual(self.sfdisk_calls(), [])
        self.assertFalse((self.root / "var/lib/agentos/drive-id").exists())


class ConfigTest(unittest.TestCase):
    def test_drive_gets_its_own_guids_once_after_a_blessed_boot(self):
        u = ini(MK / "mkosi.extra/usr/lib/systemd/system/agentos-drive-id.service")
        self.assertIn("boot-complete.target", u["Unit"]["Requires"])
        self.assertIn("systemd-bless-boot.service", u["Unit"]["After"])
        self.assertEqual(u["Unit"]["ConditionPathExists"], "!/var/lib/agentos/drive-id")
        self.assertEqual(u["Service"]["ExecStart"], "/usr/lib/agentos/drive-id assign")
        preset = (MK / "mkosi.extra/usr/lib/systemd/system-preset/50-agentos.preset").read_text()
        self.assertIn("enable agentos-drive-id.service", preset)
        self.assertIn("fdisk", ini(MK / "mkosi.conf")["Content"]["Packages"].split())
        report = ini(MK / "mkosi.extra/usr/lib/systemd/system/agentos-boot-report.service")
        self.assertIn("agentos-drive-id.service", report["Unit"]["After"])

    def test_a_try_that_never_reaches_health_reboots(self):
        # L3 blocker 2 on #41 (UPD-1): a kernel panic reboots, and emergency or rescue mode, in the
        # initrd or the host, runs the fallback first. The default initrd has no mkosi.extra, so the
        # drop-ins come as systemd.unit-dropin credentials on the command line, which both read.
        args = ini(MK / "mkosi.conf")["Content"]["KernelCommandLine"].split()
        self.assertIn("panic=10", args)
        creds = dict(a.split("=", 1)[1].split(":", 1) for a in args
                     if a.startswith("systemd.set_credential_binary="))
        for unit in ("emergency.service", "rescue.service"):
            with self.subTest(unit):
                d = configparser.ConfigParser(interpolation=None)
                d.read_string(base64.b64decode(creds["systemd.unit-dropin." + unit]).decode())
                cmd = d["Service"]["ExecStartPre"]
                self.assertTrue(cmd.startswith("-bash -c '") and cmd.endswith("'"), cmd)
                with tempfile.TemporaryDirectory() as t:
                    t = pathlib.Path(t)
                    log, fallback = t / "log", t / "fallback"
                    stub(t, "systemctl", 'echo "systemctl $*" >>"%s"' % log)
                    script = cmd[len("-bash -c '"):-1].replace("/usr/lib/agentos/fallback", str(fallback))
                    env = dict(os.environ, PATH="%s:%s" % (t, os.environ["PATH"]))
                    subprocess.run(["bash", "-c", script], env=env, check=True)  # initrd: no fallback
                    self.assertEqual(log.read_text(), "systemctl reboot\n")
                    log.unlink()
                    stub(t, "fallback", 'echo "fallback" >>"%s"' % log)
                    subprocess.run(["bash", "-c", script], env=env, check=True)  # host: tries-aware
                    self.assertEqual(log.read_text(), "fallback\n")

    def test_broker_runs_only_on_the_boot_drive(self):
        u = ini(MK / "mkosi.extra/usr/lib/systemd/system/agentosd.service")
        self.assertEqual(u["Service"]["ExecStartPre"], "/usr/lib/agentos/drive-id check")

    def test_nothing_writes_the_hardware_clock(self):
        # L3 SHOULD on #41 (HW-8, HOST-1b): timesyncd's sync turns on the kernel's 11-minute RTC
        # update. chrony with rtcsync off comes with HOST-1b; until then the image has no time sync.
        self.assertNotIn("systemd-timesyncd", ini(MK / "mkosi.conf")["Content"]["Packages"].split())
        preset = (MK / "mkosi.extra/usr/lib/systemd/system-preset/50-agentos.preset").read_text()
        self.assertNotIn("timesyncd", preset)

    def test_secure_boot_chain_is_distribution_signed(self):
        # HW-5: Microsoft-signed shim -> Debian-signed systemd-boot -> Debian-signed kernel.
        c = ini(MK / "mkosi.conf")
        self.assertEqual(c["Content"]["Bootloader"], "systemd-boot")
        self.assertEqual(c["Content"]["ShimBootloader"], "signed")
        self.assertEqual(c["Content"]["UnifiedKernelImages"], "no")
        pk = c["Content"]["Packages"].split()
        for p in ("shim-signed", "systemd-boot-efi-amd64-signed", "linux-image-amd64"):
            self.assertIn(p, pk)
        self.assertNotIn("SecureBootKey", c["Content"])

    def test_reproducibility_inputs_are_pinned(self):
        c = ini(MK / "mkosi.conf")
        self.assertRegex(c["Distribution"]["Mirror"], r"^https://snapshot\.debian\.org/archive/debian/\d{8}T\d{6}Z/?$")
        self.assertRegex(c["Output"]["Seed"], r"^[0-9a-f-]{36}$")
        b = (IMG / "build.sh").read_text()
        self.assertIn("SOURCE_DATE_EPOCH", b)
        self.assertIn("-trimpath", b)

    def test_snapshot_sources_outlive_their_valid_until(self):
        # The pinned snapshot's Release files expire a week after the timestamp; apt must still read
        # them (signatures checked), while live security.debian.org keeps the expiry check.
        mirror = ini(MK / "mkosi.conf")["Distribution"]["Mirror"].rstrip("/")
        text = (MK / "mkosi.pkgmngr/etc/apt/sources.list.d/mkosi.sources").read_text()
        stanzas = [dict(l.split(": ", 1) for l in s.splitlines() if l and not l.startswith("#"))
                   for s in text.split("\n\n")]
        stanzas = [s for s in stanzas if s]
        snap = [s for s in stanzas if s["URIs"].rstrip("/") == mirror]
        live = [s for s in stanzas if s["URIs"].rstrip("/") != mirror]
        self.assertEqual(len(snap), 1)
        self.assertEqual(snap[0]["Suites"].split(), ["trixie", "trixie-updates"])
        self.assertEqual(snap[0]["Check-Valid-Until"], "no")
        self.assertEqual([s["Suites"] for s in live], ["trixie-security"])
        self.assertNotIn("Check-Valid-Until", live[0])
        for s in stanzas:
            self.assertEqual(s["Signed-By"], "/usr/share/keyrings/debian-archive-keyring.gpg")
            self.assertNotIn("Trusted", s)

    def test_ab_usr_slots(self):
        # UPD-1: two equal /usr slots plus verity, so an update writes the idle one.
        parts = [ini(f)["Partition"] for f in sorted((MK / "mkosi.repart").glob("*.conf"))]
        usr = [p for p in parts if p["Type"] == "usr"]
        ver = [p for p in parts if p["Type"] == "usr-verity"]
        self.assertEqual(len(usr), 2)
        self.assertEqual(len(ver), 2)
        for group in (usr, ver):
            self.assertEqual(group[0]["SizeMinBytes"], group[0]["SizeMaxBytes"])
            self.assertEqual({g["SizeMaxBytes"] for g in group}, {group[0]["SizeMaxBytes"]})
            self.assertEqual(group[1]["Label"], "_empty")
            self.assertNotIn("Minimize", group[0])
        self.assertEqual(parts[-1]["Type"], "root")

    def test_root_grows_to_fill_the_drive(self):
        p = ini(MK / "mkosi.extra/usr/lib/repart.d/50-root.conf")["Partition"]
        self.assertEqual(p["Type"], "root")
        self.assertEqual(p["GrowFileSystem"], "yes")

    def test_health_gates_boot_complete(self):
        u = ini(MK / "mkosi.extra/usr/lib/systemd/system/agentos-health.service")
        self.assertIn("boot-complete.target", u["Unit"]["Before"])
        self.assertEqual(u["Install"]["RequiredBy"], "boot-complete.target")
        # UPD-1 (L3 blocker on #41): a failed or hung check reboots into the next try.
        self.assertEqual(u["Unit"]["OnFailure"], "agentos-fallback.service")
        self.assertIn("TimeoutStartSec", u["Service"])
        f = ini(MK / "mkosi.extra/usr/lib/systemd/system/agentos-fallback.service")
        self.assertEqual(f["Service"]["ExecStart"], "/usr/lib/agentos/fallback")
        preset = (MK / "mkosi.extra/usr/lib/systemd/system-preset/50-agentos.preset").read_text()
        self.assertIn("enable agentos-health.service", preset)

    def test_root_is_locked(self):
        self.assertEqual(ini(MK / "mkosi.conf")["Content"]["RootPassword"], "hashed:!")

    def test_broker_flags_exist(self):
        # MUST 1 on #41: a flag agentosd lacks makes it exit at start and loop on restart.
        src = (ROOT / "broker/cmd/agentosd").glob("*.go")
        defined = set()
        for f in src:
            defined |= set(re.findall(r'flag\.\w+\([^,]+,\s*"([\w-]+)"', f.read_text()))
        exe = ini(MK / "mkosi.extra/usr/lib/systemd/system/agentosd.service")["Service"]["ExecStart"]
        used = re.findall(r"(?:^|\s)-([a-z][\w-]*)", exe)
        self.assertTrue(used)
        self.assertEqual(sorted(set(used) - defined), [])

    def test_broker_starts_when_onboarding_writes_its_settings(self):
        p = ini(MK / "mkosi.extra/usr/lib/systemd/system/agentosd.path")
        self.assertEqual(p["Path"]["PathExists"], "/etc/agentos/agentosd.env")
        self.assertEqual(p["Path"]["Unit"], "agentosd.service")
        preset = (MK / "mkosi.extra/usr/lib/systemd/system-preset/50-agentos.preset").read_text()
        self.assertIn("enable agentosd.path", preset)

    def test_broker_waits_for_onboarding(self):
        u = ini(MK / "mkosi.extra/usr/lib/systemd/system/agentosd.service")
        self.assertEqual(u["Unit"]["ConditionPathExists"], "/etc/agentos/agentosd.env")
        self.assertIn("/usr/lib/agentos/agentosd", u["Service"]["ExecStart"])


if __name__ == "__main__":
    unittest.main()
