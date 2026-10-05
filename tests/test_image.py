# Tests for the device image build (P2-1): the build-time tree check, the release manifest,
# the counted boot entry, the boot health check, and the image's static configuration.
# The image itself is built and booted under Secure Boot by .github/workflows/image.yml.
# REQ: HW-1, HW-5, HW-8, UPD-1, UPD-1a
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

    def test_host_clock_and_disk_tools_must_not_ship(self):
        # HW-8: hwclock, timesyncd, timedated, LVM, MD-RAID and udisks.
        for rel in ("usr/sbin/hwclock", "usr/lib/udev/rules.d/85-hwclock.rules", "usr/lib/systemd/systemd-timesyncd",
                    "usr/lib/systemd/systemd-timedated", "usr/sbin/lvm", "usr/sbin/mdadm",
                    "usr/lib/udev/rules.d/69-lvm.rules", "usr/lib/udev/rules.d/63-md-raid-arrays.rules",
                    "usr/lib/udev/rules.d/80-udisks2.rules", "usr/lib/udev/rules.d/69-bcache.rules",
                    "usr/lib/udev/rules.d/60-zfs.rules", "usr/lib/udev/rules.d/64-md-raid-assembly.rules"):
            with self.subTest(rel):
                f = write(self.root, rel, "x")
                v = check.violations(self.root)
                self.assertEqual(len(v), 1, v)
                self.assertIn("HW-8", v[0])
                f.unlink()

    def test_chrony_must_not_write_the_rtc(self):
        write(self.root, "usr/sbin/chronyd", "\x7fELF", 0o755)
        self.assertIn("missing", " ".join(check.violations(self.root)))
        write(self.root, "etc/chrony/chrony.conf", "server a iburst nts\n")
        self.assertEqual(check.violations(self.root), [])
        write(self.root, "etc/chrony/chrony.conf", "server a iburst nts\nrtcsync\n")
        self.assertIn("rtcsync", " ".join(check.violations(self.root)))
        shipped = (MK / "mkosi.extra/etc/chrony/chrony.conf").read_text()
        write(self.root, "etc/chrony/chrony.conf", shipped)
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

    def test_empty_machines_mount_point_may_ship(self):
        # mkosi applies tmpfiles.d at build, so the machines volume's empty mount point is there.
        (self.root / "var/lib/agentos/machines").mkdir(parents=True)
        self.assertNotIn("var/lib/agentos", " ".join(check.violations(self.root)))
        write(self.root, "var/lib/agentos/machines/m1/rootfs", "x")
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
        self.lsblk({"/dev/vda6": "/dev/vda", "/dev/vda7": "/dev/vda"})
        stub(self.lib, "agentosd", "exit 0")
        stub(self.lib, "runsc", 'echo "runsc version release-20260928.0"')
        (self.lib / "images/openclaw/opt/openclaw").mkdir(parents=True)
        write(self.lib, "guest/launch.json", "{}")
        write(self.root, "proc/cmdline", "console=ttyS0 rw quiet usrhash=%s\n" % H)
        ev = self.root / "sys/firmware/efi/efivars"
        ev.mkdir(parents=True)
        (ev / "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c").write_bytes(b"\x06\x00\x00\x00\x01")

    def findmnt(self, source, options, machines=("/dev/vda7", "xfs", "rw,nosuid,nodev,relatime,prjquota")):
        msrc, mfs, mopts = machines
        stub(self.bin, "findmnt", 'case "$2 $3" in "SOURCE /usr") echo "%s" ;; "OPTIONS /usr") echo "%s" ;;'
             ' "SOURCE /") echo /dev/vda6 ;; "SOURCE /var/lib/agentos/machines") [ -n "%s" ] || exit 1; echo "%s" ;;'
             ' "FSTYPE /var/lib/agentos/machines") echo "%s" ;; "OPTIONS /var/lib/agentos/machines") echo "%s" ;;'
             ' *) exit 1 ;; esac' % (source, options, msrc, msrc, mfs, mopts))
        self.usr = (source, options)

    def lsblk(self, parents):
        stub(self.bin, "lsblk", 'case "$3" in %s esac' % " ".join('%s) echo %s ;;' % kv for kv in parents.items()))

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
            "broker missing": lambda: (self.lib / "agentosd").unlink(),
            "broker broken": lambda: stub(self.lib, "agentosd", "exit 2"),
            "runsc broken": lambda: stub(self.lib, "runsc", "exit 1"),
            "guest image missing": lambda: (self.lib / "images/openclaw/opt/openclaw").rmdir(),
            "machines not mounted": lambda: self.findmnt(*self.usr, machines=("", "", "")),
            "machines not xfs": lambda: self.findmnt(*self.usr, machines=("/dev/vda7", "ext4", "rw,nosuid,nodev,prjquota")),
            "machines without quotas": lambda: self.findmnt(*self.usr, machines=("/dev/vda7", "xfs", "rw,nosuid,nodev,noquota")),
            "machines without nodev": lambda: self.findmnt(*self.usr, machines=("/dev/vda7", "xfs", "rw,nosuid,prjquota")),
            "machines without nosuid": lambda: self.findmnt(*self.usr, machines=("/dev/vda7", "xfs", "rw,nodev,prjquota")),
            "machines on no disk": lambda: self.lsblk({}),
            "machines on another disk": lambda: self.lsblk({"/dev/vda6": "/dev/vda", "/dev/vdb1": "/dev/vdb"}) or
                self.findmnt(*self.usr, machines=("/dev/vdb1", "xfs", "rw,nosuid,nodev,prjquota")),
        }
        for name, breakit in cases.items():
            with self.subTest(name):
                self.tearDown()
                self.setUp()
                breakit()
                r = self.run_health()
                self.assertEqual(r.returncode, 1, name)
                self.assertIn("agentos-health: FAIL", r.stdout)


class ConfigTest(unittest.TestCase):
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


INITRD = MK / "mkosi.initrd"
LOADER_VAR = "sys/firmware/efi/efivars/LoaderDevicePartUUID-4a67b082-0a4c-41cf-b6c7-440b29bb8c4f"
ESP_A, ROOT_A, ESP_B = ("11111111-0000-4000-8000-%012d" % i for i in (1, 2, 3))
RELEASE = "a1a1a1a1-0000-4000-8000-000000000001"


class DriveIDsTest(unittest.TestCase):
    """Security MUST on #41 (and I1, I2 on the plan): every drive starts with the same IDs
    (Seed=), so the initrd refuses a boot that another drive's IDs could steer, and gives a
    fresh drive IDs of its own, on the boot drive only."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = pathlib.Path(self.tmp.name)
        self.bin, self.root, self.log = t / "bin", t / "root", t / "log"
        self.log.write_text("")
        self.loader(ESP_A)
        # vda: the boot drive (ESP, /usr release, empty slot, root); vdb: another disk.
        self.disks = {"/dev/vda": "a0a0a0a0-0000-4000-8000-00000000000a", "/dev/vdb": "b0b0b0b0-0000-4000-8000-00000000000b"}
        self.parts = [("/dev/vda1", "/dev/vda", ESP_A, "esp"),
                      ("/dev/vda2", "/dev/vda", RELEASE, "agentos_7"),
                      ("/dev/vda4", "/dev/vda", "22222222-0000-4000-8000-000000000004", "_empty"),
                      ("/dev/vda6", "/dev/vda", ROOT_A, "root-x86-64"),
                      ("/dev/vdb1", "/dev/vdb", ESP_B, "esp"),
                      ("/dev/vdb2", "/dev/vdb", RELEASE, "agentos_7")]
        for n in range(1, 7):
            write(self.root, "sys/class/block/vda%d/partition" % n, "%d\n" % n)
        self.rootdev = "/dev/vda6"
        for tool in ("sfdisk", "e2fsck", "tune2fs", "fatlabel"):
            stub(self.bin, tool, 'echo "%s $*" >> %s' % (tool, self.log))
        stub(self.bin, "udevadm", "exit 0")

    def tearDown(self):
        self.tmp.cleanup()

    def loader(self, uuid):
        f = self.root / LOADER_VAR
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(b"\x06\x00\x00\x00" + uuid.upper().encode("utf-16-le") + b"\x00\x00")

    def run_ids(self):
        # lsblk -rnpo NAME,TYPE,PKNAME,PTUUID,PARTUUID,PARTLABEL: empty fields collapse in raw mode.
        rows = ["%s disk %s" % (d, g.upper()) for d, g in self.disks.items()]
        rows += ["%s part %s %s %s %s" % (n, d, self.disks[d], u.upper(), l) for n, d, u, l in self.parts]
        stub(self.bin, "lsblk", "cat <<'T'\n%s\nT" % "\n".join(rows))
        stub(self.bin, "systemctl", 'case "$1" in show) echo "%s" ;; *) echo "systemctl $*" >> %s ;; esac'
             % (self.rootdev, self.log))
        env = dict(os.environ, PATH="%s:%s" % (self.bin, os.environ["PATH"]),
                   AGENTOS_DRIVE_ROOT=str(self.root), AGENTOS_DRIVE_HOLD="0")
        r = subprocess.run(["bash", str(INITRD / "mkosi.extra/usr/lib/agentos/drive-ids")], env=env,
                           capture_output=True, text=True)
        return r, self.log.read_text()

    def assertRefused(self, r, log):
        self.assertEqual(r.returncode, 1)
        # I2: one fixed console line, the reason only in the journal (stderr), nothing written.
        self.assertEqual(r.stdout, "agentos-drive: FAIL another drive carries this drive's IDs; unplug it and start again\n")
        self.assertTrue(r.stderr.strip())
        self.assertEqual(log, "")

    def test_seed_disk_guid_is_the_one_repart_derives(self):
        # systemd-repart: HMAC-SHA256 keyed by the seed over "disk-uuid", first half as a v4 UUID.
        # finish_image.py checks the built image's GUID against the same constant.
        import hmac, hashlib, uuid
        seed = uuid.UUID(ini(MK / "mkosi.conf")["Output"]["Seed"])
        b = bytearray(hmac.new(seed.bytes, b"disk-uuid", hashlib.sha256).digest()[:16])
        b[6], b[8] = (b[6] & 0x0F) | 0x40, (b[8] & 0x3F) | 0x80
        script = (INITRD / "mkosi.extra/usr/lib/agentos/drive-ids").read_text()
        self.assertIn("SEED_DISK=%s\n" % uuid.UUID(bytes=bytes(b)), script)
        self.assertEqual(finish.seed_disk(), str(uuid.UUID(bytes=bytes(b))))
        finish.check_seed_disk(finish.seed_disk().upper())
        with self.assertRaises(ValueError):
            finish.check_seed_disk("00000000-0000-4000-8000-000000000000")

    def test_unique_drive_boots_unchanged(self):
        r, log = self.run_ids()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("agentos-drive: ok disk=/dev/vda", r.stdout)
        self.assertEqual(log, "")

    def test_two_drives_with_the_boot_esp_id_are_refused(self):
        self.parts[4] = ("/dev/vdb1", "/dev/vdb", ESP_A, "esp")
        self.assertRefused(*self.run_ids())

    def test_another_drive_with_this_drives_root_id_is_refused(self):
        self.parts.append(("/dev/vdb6", "/dev/vdb", ROOT_A, "root-x86-64"))
        self.assertRefused(*self.run_ids())

    def test_another_drive_with_this_disk_guid_is_refused(self):
        self.disks["/dev/vdb"] = self.disks["/dev/vda"]
        self.assertRefused(*self.run_ids())

    def test_the_same_release_on_another_drive_is_fine(self):
        # /usr is chosen by usrhash= and checked by dm-verity, not by ID: equal IDs are expected.
        r, _ = self.run_ids()
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_root_on_another_drive_is_refused(self):
        self.parts.append(("/dev/vdb6", "/dev/vdb", "33333333-0000-4000-8000-000000000006", "root-x86-64"))
        self.rootdev = "/dev/vdb6"
        self.assertRefused(*self.run_ids())

    def test_no_loader_variable_or_no_matching_partition_is_refused(self):
        self.loader("99999999-0000-4000-8000-000000000009")
        self.assertRefused(*self.run_ids())
        (self.root / LOADER_VAR).unlink()
        self.assertRefused(*self.run_ids())

    def test_fresh_drive_gets_its_own_ids_then_restarts(self):
        self.disks["/dev/vda"] = finish.seed_disk()
        r, log = self.run_ids()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        lines = log.splitlines()
        self.assertEqual(lines[0], "sfdisk -q --no-reread --no-tell-kernel --relocate gpt-bak-std /dev/vda")
        changed = sorted(re.findall(r"--part-uuid /dev/vda (\d) ", log))
        self.assertEqual(changed, ["1", "4", "6"])  # not the release's own partition (2)
        self.assertIn("e2fsck -fp /dev/vda6", log)
        self.assertIn("tune2fs -U random /dev/vda6", log)
        self.assertRegex(log, r"fatlabel -i /dev/vda1 [0-9a-f]{8}\n")
        # The disk GUID last: a run cut short still has the seed's GUID and starts over.
        self.assertRegex(lines[-2], r"^sfdisk .*--disk-id /dev/vda [0-9a-f-]{36}$")
        self.assertEqual(lines[-1], "systemctl --no-block reboot")
        self.assertNotIn("vdb", log)

    def test_fresh_drive_beside_a_copy_is_refused_before_any_change(self):
        self.disks["/dev/vda"] = self.disks["/dev/vdb"] = finish.seed_disk()
        self.parts[4] = ("/dev/vdb1", "/dev/vdb", ESP_A, "esp")
        self.assertRefused(*self.run_ids())

    def test_root_never_mounts_without_the_check(self):
        u = ini(INITRD / "mkosi.extra/usr/lib/systemd/system/agentos-drive-ids.service")
        self.assertEqual(u["Unit"]["FailureAction"], "poweroff")
        self.assertIn("sysroot.mount", u["Unit"]["Before"])
        self.assertIn("initrd-root-device.target", u["Unit"]["After"])
        self.assertEqual(u["Service"]["StandardError"], "journal")
        d = ini(INITRD / "mkosi.extra/usr/lib/systemd/system/sysroot.mount.d/agentos-drive-ids.conf")
        self.assertEqual(d["Unit"]["Requires"], "agentos-drive-ids.service")
        self.assertEqual(d["Unit"]["After"], "agentos-drive-ids.service")
        self.assertTrue(os.access(INITRD / "mkosi.extra/usr/lib/agentos/drive-ids", os.X_OK))

    def test_initrd_tools(self):
        c = ini(INITRD / "mkosi.conf")["Content"]
        for p in ("fdisk", "dosfstools"):
            self.assertIn(p, c["Packages"].split())
        self.assertEqual(ini(MK / "mkosi.conf")["Config"]["InitrdInclude"], "mkosi.initrd/")

    def test_usr_is_chosen_by_root_hash_only(self):
        cmdline = ini(MK / "mkosi.conf")["Content"]["KernelCommandLine"]
        for opt in ("root=", "mount.usr", "usr=", "systemd.verity_usr", "PARTUUID", "UUID="):
            self.assertNotIn(opt, cmdline)
        with self.assertRaises(ValueError):
            finish.counted_entry(ENTRY.replace("quiet", "quiet root=PARTUUID=%s" % ROOT_A) % H, "7")
        with self.assertRaises(ValueError):
            finish.counted_entry(ENTRY.replace("quiet", "quiet mount.usr=/dev/sda2") % H, "7")


class HostUntouchedImageTest(unittest.TestCase):
    """HW-8 (HOST-1b, HOST-1a H11): the image never writes the host's hardware clock, root units
    get no device access they do not need, and nothing assembles a host's LVM or MD array."""

    def test_chrony_replaces_timesyncd(self):
        c = ini(MK / "mkosi.conf")["Content"]
        pk = c["Packages"].split()
        self.assertIn("chrony", pk)
        for p in ("systemd-timesyncd", "util-linux-extra", "lvm2", "mdadm", "udisks2", "ntpsec", "openntpd"):
            self.assertNotIn(p, pk)
        rm = c["RemoveFiles"].split()
        for f in ("/usr/lib/systemd/systemd-timedated", "/usr/lib/systemd/system/systemd-timedated.service",
                  "/usr/lib/udev/rules.d/85-hwclock.rules"):
            self.assertIn(f, rm)
        preset = (MK / "mkosi.extra/usr/lib/systemd/system-preset/50-agentos.preset").read_text()
        self.assertIn("enable chrony.service", preset)
        self.assertNotIn("timesyncd", preset)

    def test_chrony_config_never_touches_the_rtc(self):
        conf = (MK / "mkosi.extra/etc/chrony/chrony.conf").read_text()
        directives = [l.split()[0] for l in conf.splitlines() if l.strip() and not l.startswith("#")]
        for d in ("rtcsync", "rtcfile", "hwclockfile", "rtconutc", "rtcautotrim", "rtcdevice",
                  "sourcedir", "confdir", "include"):
            self.assertNotIn(d, directives)
        self.assertIn("server", directives)
        # HOST-1b owns the file once it lands on main; the image must ship the same one.
        broker = ROOT / "broker/clock/chrony/chrony.conf"
        if broker.exists():
            self.assertEqual(conf, broker.read_text())

    def test_rtc_is_root_only(self):
        rule = (MK / "mkosi.extra/usr/lib/udev/rules.d/62-agentos-rtc.rules").read_text()
        self.assertIn('SUBSYSTEM=="rtc", OWNER:="root", GROUP:="root", MODE:="0600"', rule)
        d = ini(MK / "mkosi.extra/usr/lib/systemd/system/chrony.service.d/50-agentos.conf")["Service"]
        self.assertEqual(d["DevicePolicy"], "closed")
        self.assertEqual(d["DeviceAllow"], "")

    def test_agentos_units_have_closed_device_policy(self):
        # H11 ruling (c) on #172: root can open a 0600 host-disk node, so root units are fenced.
        units = sorted((MK / "mkosi.extra/usr/lib/systemd/system").glob("*.service"))
        units += sorted((INITRD / "mkosi.extra/usr/lib/systemd/system").glob("*.service"))
        self.assertGreaterEqual(len(units), 4)
        for f in units:
            with self.subTest(f.name):
                s = ini(f)["Service"]
                self.assertTrue(s.get("DevicePolicy") == "closed" or s.get("PrivateDevices") == "yes"
                                or f.name == "agentos-drive-ids.service", f.name)
                for line in f.read_text().splitlines():
                    if line.startswith("DeviceAllow="):
                        self.assertNotRegex(line, r"block-|char-rtc|/dev/(sd|nvme|vd|mmc|rtc)", f.name)

    def test_device_policy_allowlist_is_well_formed(self):
        # The CI boot fails on a root service with open device access that this file does not
        # list; each entry carries its reason.
        lines = [l for l in (IMG / "device-policy.txt").read_text().splitlines() if l and not l.startswith("#")]
        for l in lines:
            unit, _, reason = l.partition(" ")
            self.assertRegex(unit, r"^[\w@.-]+\.service$")
            self.assertGreater(len(reason.strip()), 10, unit)
            self.assertFalse(unit.startswith("agentos"), unit)

    def test_initrd_assembles_no_lvm_or_md(self):
        c = ini(INITRD / "mkosi.conf")["Content"]
        for p in ("lvm2", "mdadm"):
            self.assertIn(p, c["RemovePackages"].split())
            self.assertNotIn(p, c["Packages"].split())
        self.assertTrue(any("lvm" in g for g in c["RemoveFiles"].split()))
        self.assertTrue(any("md-raid" in g for g in c["RemoveFiles"].split()))

    def test_initrd_listing_check(self):
        good = ["usr/lib/agentos/drive-ids", "usr/lib/systemd/system/agentos-drive-ids.service",
                "usr/lib/systemd/system/sysroot.mount.d/agentos-drive-ids.conf", "usr/bin/sfdisk"]
        self.assertEqual(finish.initrd_violations(good), [])
        bad = good[1:] + ["usr/lib/udev/rules.d/69-lvm.rules", "usr/sbin/mdadm", "usr/sbin/pvscan"]
        v = finish.initrd_violations(bad)
        self.assertEqual(len(v), 4, v)

    def test_initrd_names_reads_concatenated_cpio(self):
        def newc(names):
            out = b""
            for n in names + ["TRAILER!!!"]:
                nb = n.encode() + b"\0"
                hdr = b"070701" + b"".join(b"%08X" % v for v in (0, 0o100644, 0, 0, 1, 0, 0, 0, 0, 0, 0, len(nb), 0))
                out += hdr + nb
                out += b"\0" * (-len(out) % 4)
            return out
        data = newc(["early/a"]) + b"\0" * 512 + newc(["usr/lib/agentos/drive-ids", "etc/x"])
        self.assertEqual(finish.initrd_names(data), ["early/a", "usr/lib/agentos/drive-ids", "etc/x"])
        try:
            z = subprocess.run(["zstd", "-q", "-c"], input=newc(["usr/bin/sfdisk"]), capture_output=True, check=True).stdout
        except (OSError, subprocess.CalledProcessError):
            self.skipTest("zstd not installed")
        self.assertEqual(finish.initrd_names(newc(["early/a"]) + z), ["early/a", "usr/bin/sfdisk"])


MACHINES_TYPE = "dbd1b055-3c71-434c-a687-eeefd49cc21b"


class MachinesVolumeTest(unittest.TestCase):
    """SR2-3i (RES-4) with security M1-M3: the agent machines' own XFS volume with project quotas,
    found by type on the boot drive only, mounted nodev,nosuid."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = pathlib.Path(self.tmp.name)
        self.bin, self.mp, self.log = t / "bin", t / "machines", t / "log"
        self.log.write_text("")
        self.parts = [("/dev/vda6", "/dev/vda", "4f68bce3-e8cd-4db1-96e7-fbcaf984b709"),
                      ("/dev/vda7", "/dev/vda", MACHINES_TYPE.upper()),
                      ("/dev/vdb7", "/dev/vdb", MACHINES_TYPE)]
        self.mounted = ""
        stub(self.bin, "udevadm", "exit 0")
        stub(self.bin, "systemd-mount", 'echo "systemd-mount $*" >> %s' % self.log)

    def tearDown(self):
        self.tmp.cleanup()

    def run_mount(self):
        rows = "\n".join("%s part %s %s" % p for p in self.parts)
        stub(self.bin, "lsblk", 'case "$1" in -dnpo) echo /dev/vda ;; *) cat <<\'T\'\n%s\nT\n;; esac' % rows)
        stub(self.bin, "findmnt", 'case "$3" in /) echo /dev/vda6 ;; *) grep -q mount %s || exit 1; echo /dev/vda7 ;; esac'
             % self.log)
        env = dict(os.environ, PATH="%s:%s" % (self.bin, os.environ["PATH"]),
                   AGENTOS_MACHINES_MP=str(self.mp), AGENTOS_MACHINES_HOLD="0")
        r = subprocess.run(["sh", str(MK / "mkosi.extra/usr/lib/agentos/machines-mount")], env=env,
                           capture_output=True, text=True)
        return r, self.log.read_text()

    def test_mounts_the_boot_drives_volume_with_quotas(self):
        r, log = self.run_mount()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("-t xfs -o nodev,nosuid,prjquota /dev/vda7 %s" % self.mp, log)
        self.assertNotIn("vdb", log)
        self.assertEqual(stat.S_IMODE(self.mp.stat().st_mode), 0o700)

    def test_another_drives_volume_is_never_used(self):
        del self.parts[1]
        r, log = self.run_mount()
        self.assertEqual(r.returncode, 1)
        self.assertIn("agentos-machines: FAIL no machines volume on /dev/vda", r.stdout)
        self.assertEqual(log, "")

    def test_two_volumes_on_the_drive_fail(self):
        self.parts.append(("/dev/vda8", "/dev/vda", MACHINES_TYPE))
        r, log = self.run_mount()
        self.assertEqual(r.returncode, 1)
        self.assertEqual(log, "")

    def test_config(self):
        p = ini(MK / "mkosi.extra/usr/lib/repart.d/60-machines.conf")["Partition"]
        self.assertEqual(p["Type"], MACHINES_TYPE)
        self.assertEqual(p["Format"], "xfs")
        self.assertIn("TYPE=%s\n" % MACHINES_TYPE, (MK / "mkosi.extra/usr/lib/agentos/machines-mount").read_text())
        root = ini(MK / "mkosi.extra/usr/lib/repart.d/50-root.conf")["Partition"]
        self.assertGreater(int(p["Weight"]), int(root["Weight"]))
        self.assertIn("xfsprogs", ini(MK / "mkosi.conf")["Content"]["Packages"].split())
        u = ini(MK / "mkosi.extra/usr/lib/systemd/system/agentosd.service")
        self.assertEqual(u["Unit"]["Requires"], "agentos-machines.service")
        self.assertIn("agentos-machines.service", u["Unit"]["After"])
        self.assertEqual(u["Unit"]["ConditionPathIsMountPoint"], "/var/lib/agentos/machines")
        self.assertIn("-machines /var/lib/agentos/machines -disk-quota on", u["Service"]["ExecStart"])
        h = ini(MK / "mkosi.extra/usr/lib/systemd/system/agentos-health.service")
        self.assertIn("agentos-machines.service", h["Unit"]["After"])
        preset = (MK / "mkosi.extra/usr/lib/systemd/system-preset/50-agentos.preset").read_text()
        self.assertIn("enable agentos-machines.service", preset)


if __name__ == "__main__":
    unittest.main()
