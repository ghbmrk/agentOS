# Tests for the device image build (P2-1): the build-time tree check, the release manifest,
# the counted boot entry, the boot health check, and the image's static configuration.
# The image itself is built and booted under Secure Boot by .github/workflows/image.yml.
# REQ: HW-1, HW-5, UPD-1, UPD-1a
import configparser
import importlib.machinery
import importlib.util
import os
import pathlib
import socket
import stat
import subprocess
import tempfile
import unittest

IMG = pathlib.Path(__file__).resolve().parent.parent / "image"
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
                                      ' echo "  status:      verified"')
        stub(self.bin, "findmnt", 'echo "ro,relatime"')
        stub(self.lib, "agentosd", "exit 0")
        stub(self.lib, "runsc", 'echo "runsc version release-20260928.0"')
        (self.lib / "images/openclaw/opt/openclaw").mkdir(parents=True)
        ev = self.root / "sys/firmware/efi/efivars"
        ev.mkdir(parents=True)
        (ev / "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c").write_bytes(b"\x06\x00\x00\x00\x01")

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
            "usr writable": lambda: stub(self.bin, "findmnt", 'echo "rw,relatime"'),
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

    def test_broker_waits_for_onboarding(self):
        u = ini(MK / "mkosi.extra/usr/lib/systemd/system/agentosd.service")
        self.assertEqual(u["Unit"]["ConditionPathExists"], "/etc/agentos/agentosd.env")
        self.assertIn("/usr/lib/agentos/agentosd", u["Service"]["ExecStart"])


if __name__ == "__main__":
    unittest.main()
