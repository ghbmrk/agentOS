"""STO-2c slice ii-b (#2905): the keeper's units under image/, and mkosi.finalize's checks on them.

The keeper (D-154) is enrollment (agentos-keeper-enroll.service) and the unlock step that becomes the
kernel (agentos-keeper-kernel.service), in agentos-keeper.slice. Every other agentos unit is main side:
it cannot see the keeper's state, and only the keeper's units (and the old core's vault process until
it is deleted) reach the TPM. The unlock unit gets no descriptor past 2 and no privilege past its drop
(#2899), and its restarts are bounded so a crash loop cannot wear the TPM counter (#2897); a kernel
that came up and then failed reboots the box, at most twice an hour (#2998). Each test
of a refusal is a mutant of the shipped tree that mkosi.finalize must refuse. CI's boot test enrolls
on the first boot with synthetic factors (image/ci_boot.sh, agentos-keeper lines)."""
# REQ: STO-2, STO-1, HW-5a, CLK-1, UPD-10
import contextlib
import io
import os
import pathlib
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
import unittest.mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_image import MK, ROOT, check, clean_tree, exec_args, arg, ini, write  # noqa: E402
from test_image_noexec import STOCK_TMP, SYSTEM, shipped_units, stage_binaries  # noqa: E402

UNITS = MK / "mkosi.extra/usr/lib/systemd/system"
# The keeper's files beside its units, which shipped_units (agentos* regular files) leaves out.
KEEPER_FILES = tuple("usr/lib/systemd/system/" + n for n in (
    "agentos-keeper.slice", "agentos-.service.d/50-main-side.conf", "agentos-keeper-.service.d/90-keeper.conf",
    "agentos-mor.service.d/50-main-side.conf", "agentos-camdecode@.service.d/90-empty-run.conf"))
# #4392: the decoder unit's empty /run, and its lift of the main side's mask there.
EMPTY_RUN = "agentos-camdecode@.service"
EMPTY_RUN_DROPIN = EMPTY_RUN + ".d/90-empty-run.conf"
ENROLL = UNITS / "agentos-keeper-enroll.service"
KERNEL = UNITS / "agentos-keeper-kernel.service"
ROTATE = UNITS / "agentos-keeper-rotate@.service"
ROTATE_SOCKET = UNITS / "agentos-keeper-rotate.socket"
MAIL = UNITS / "agentos-keeper-mail.service"
PRESET = MK / "mkosi.extra/usr/lib/systemd/system-preset/50-agentos.preset"
SYSUSERS = MK / "mkosi.extra/usr/lib/sysusers.d/agentos-setup.conf"
WITH_UIDS = MK / "mkosi.extra/usr/lib/agentos/with-uids"
TMPFILES = MK / "mkosi.extra/usr/lib/tmpfiles.d/agentos.conf"
BOOT_REPORT = MK / "mkosi.extra/usr/lib/agentos/boot-report"
CI_BOOT = ROOT / "image/ci_boot.sh"


def exec_lines(path, key):
    # Every KEY= line of PATH, in order: ini() keeps only the last of a repeated key.
    return re.findall(r"(?m)^%s=(.*)$" % key, path.read_text())


def go_flags(cmd):
    """The flag names cmd's main.go defines (fs.StringVar(&x, "name", ...) and the like)."""
    src = (ROOT / "broker/cmd" / cmd / "main.go").read_text()
    return set(re.findall(r'fs\.(?:String|Bool|Int|Duration|Uint)?(?:Var)?\((?:[^,]+, )?"([a-z-]+)"', src))


def unlock_refusal(key, val, why, where=SYSTEM + "agentos-keeper-kernel.service"):
    """#4667: an unlock unit's refusal names the file that set the value and what the key may be."""
    allowed = {"FileDescriptorStoreMax": "FileDescriptorStoreMax=0"}.get(
        key, key + "=none" if key.endswith("Action") else "no %s= at all" % key)
    return "agentos-keeper-kernel.service: %s=%s in %s; %s; allowed: %s" % (key, val, where, why, allowed)


def owned_dirs(*units):
    """#5167: the directories the tree check counts as a service user's (SERVICE_DIRS and unit_made_dirs) in
    a tree holding UNITS."""
    with tempfile.TemporaryDirectory() as t:
        for u in units:
            write(pathlib.Path(t), SYSTEM + u.name, u.read_text())
        return set(check.SERVICE_DIRS) | set(check.unit_made_dirs(t)[0])


class KeeperTreeTest(unittest.TestCase):
    """mkosi.finalize's keeper check on a tree holding the image's own units."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = clean_tree(pathlib.Path(self.tmp.name))
        for rel, src in shipped_units().items():
            write(self.root, rel, src.read_text())
        for rel in KEEPER_FILES:
            write(self.root, rel, (MK / "mkosi.extra" / rel).read_text())
        write(self.root, SYSTEM + "tmp.mount", STOCK_TMP)
        write(self.root, "usr/lib/sysusers.d/agentos-setup.conf", SYSUSERS.read_text())
        stage_binaries(self.root)

    def v(self):
        return check.keeper_violations(self.root)

    def unit(self, name):
        return self.root / SYSTEM / name

    def edit(self, name, old, new):
        f = self.unit(name)
        s = f.read_text()
        self.assertIn(old, s)
        f.write_text(s.replace(old, new, 1))

    def add(self, name, section, line):
        self.edit(name, "[%s]\n" % section, "[%s]\n%s\n" % (section, line))

    def test_the_image_passes(self):
        self.assertEqual(self.v(), [])
        self.assertEqual(check.violations(self.root), [])

    def test_the_keeper_is_listed_once(self):
        self.assertEqual(check.KEEPER_UNITS, ("agentos-keeper-enroll.service", "agentos-keeper-kernel.service",
                                              "agentos-keeper-rotate@.service", "agentos-keeper-pageca.service",
                                              "agentos-keeper-setup@.service", "agentos-keeper-mail.service",
                                              "agentos-keeper-link-capture.service", "agentos-keeper-camera.service",
                                              "agentos-keeper-homekit.service"))
        self.assertEqual(check.UNLOCK_UNITS, ("agentos-keeper-kernel.service",))
        # The recovery-key rotation, the page authority's staging and the card's hand-off are the
        # keeper's but open no TPM (MIG-4-recovery-r2, OWN-card-flow).
        self.assertEqual(check.TPM_UNITS, check.KEEPER_UNITS[:2] + ("agentos-egress.service",))
        for rel in KEEPER_FILES + tuple(SYSTEM + n for n in check.KEEPER_UNITS):
            self.assertTrue((MK / "mkosi.extra" / rel).is_file(), rel)
        drop = ini(UNITS / "agentos-keeper-.service.d/90-keeper.conf")["Service"]
        self.assertEqual(drop["Slice"], check.KEEPER_SLICE)
        self.assertEqual(drop["InaccessiblePaths"], "")
        main = ini(UNITS / "agentos-.service.d/50-main-side.conf")["Service"]["InaccessiblePaths"].split()
        self.assertEqual(main, list(check.KEEPER_PATHS))
        # The main side's mask sorts before the keeper's reset, so the reset wins for the keeper only.
        self.assertLess("50-main-side.conf", "90-keeper.conf")

    # The keeper boundary (D-154).

    def test_every_main_side_unit_is_masked_from_the_keeper(self):
        names = sorted(n for n in (p.name for p in (self.root / SYSTEM).iterdir())
                       if check.NOEXEC_UNITS.match(n) and n not in check.KEEPER_UNITS + check.NOEXEC_EXEMPT
                       + check.EMPTY_ROOT_UNITS + (check.MOR_UNIT,))
        self.assertIn("agentos-localui.service", names)
        (self.root / SYSTEM / "agentos-.service.d/50-main-side.conf").unlink()
        (self.root / SYSTEM / EMPTY_RUN_DROPIN).unlink()
        # #4392: the decoder unit's empty /run leaves the keeper's /run paths out of its view.
        want = ["%s: InaccessiblePaths does not hold %s; the main side never sees the keeper's state (D-154)" % (n, p)
                for n in names for p in check.KEEPER_PATHS if n != EMPTY_RUN or not p.startswith("/run/")]
        self.assertEqual(self.v(), want)

    def test_a_unit_that_lifts_the_mask_is_refused(self):
        write(self.root, SYSTEM + "agentos-localui.service.d/99-x.conf", "[Service]\nInaccessiblePaths=\n")
        self.assertEqual(len(self.v()), len(check.KEEPER_PATHS))
        self.assertTrue(all(l.startswith("agentos-localui.service: InaccessiblePaths does not hold") for l in self.v()))

    def test_a_mount_from_the_keeper_s_state_is_refused(self):
        for key, w in (("BindReadOnlyPaths", "/var/lib/agentos-kernel/log:/tmp/log"),
                       ("BindPaths", "-/var/lib/agentos-store"), ("ReadWritePaths", "/var/lib/agentos-kernel"),
                       ("BindReadOnlyPaths", "/var/lib/agentos/../agentos-store:/x")):
            with self.subTest(key):
                good = self.unit("agentos-modem.service").read_text()
                self.add("agentos-modem.service", "Service", "%s=%s" % (key, w))
                self.assertIn("agentos-modem.service: %s=%s reaches the keeper's state (D-154)" % (key, w), self.v())
                self.unit("agentos-modem.service").write_text(good)
        # Each assignment adds to the list: a later one does not hide an earlier one (#2981).
        write(self.root, SYSTEM + "agentos-modem.service.d/99-x.conf",
              "[Service]\nBindPaths=/var/lib/agentos-store:/x\nBindPaths=/srv/y\n")
        self.assertEqual(self.v(), ["agentos-modem.service: BindPaths=/var/lib/agentos-store:/x reaches the keeper's "
                                    "state (D-154)"])

    def test_a_path_is_judged_as_the_image_resolves_it(self):
        # #5119 (Security on #5117): systemd unquotes and expands a path setting, then resolves it when it
        # applies it, so /var/run/x is /run/x; a /proc path, or a /dev link into /proc, is a process's view
        # of the host's tree, past the mask.
        # The box's /var/run and /var/lock count before the tree holds them: tmpfiles makes them at boot.
        (self.root / "srv").mkdir(exist_ok=True)
        (self.root / "srv/vr").symlink_to("/var/run")
        for line in ("ReadOnlyPaths=/var/run/agentos-setup", "BindPaths=/var/run:/x", "ReadOnlyPaths=/srv/vr/agentos-setup"):
            with self.subTest(line):
                d = write(self.root, SYSTEM + "agentos-boot-report.service.d/99-probe.conf", "[Service]\n%s\n" % line)
                key, val = line.split("=", 1)
                self.assertEqual(self.v(), ["agentos-boot-report.service: %s=%s reaches the keeper's state (D-154)"
                                            % (key, val)])
                d.unlink()
        (self.root / "var").mkdir(exist_ok=True)
        (self.root / "var/run").symlink_to("../run")
        # systemd takes ReadOnlyPaths=, ReadWritePaths=, ExecPaths= and NoExecPaths= whole, ':' and all.
        (self.root / "srv/c:").symlink_to("/")
        (self.root / "srv/loop").symlink_to("loop")
        (self.root / "srv/a").mkdir()
        (self.root / "srv/pr").symlink_to("/proc/self/root")
        reach = ("BindReadOnlyPaths=/var/run/agentos-setup:/mnt", "BindPaths=-/var/run:/srv/run",
                 "ReadWritePaths=/var/run/agentos-link-capture", "OpenFile=/var/run/agentos-setup/passphrase",
                 "ReadOnlyPaths=/srv/c:/run/agentos-setup", "ExecPaths=/srv/c:/var/lib/agentos-store",
                 "ReadWritePaths=-/srv/c:/var/lib/agentos-kernel", "NoExecPaths=+/srv/c:/var/lib/agentos-mail",
                 "TemporaryFileSystem=/var/lib/agentos-store:ro", "MountImages=-/var/lib/agentos-kernel:/x",
                 # A '..' is judged as written: /srv/a/.. resolves to /srv, but systemd resolves it on the box.
                 "BindPaths=/srv/a/..:/x")
        view = {"BindReadOnlyPaths=/proc/self/root/run/agentos-setup:/mnt": "/proc/self/root/run/agentos-setup",
                "BindPaths=-/proc/1/root/var/lib/agentos-store": "/proc/1/root/var/lib/agentos-store",
                "BindReadOnlyPaths=/proc:/srv/p": "/proc", "ReadOnlyPaths=/proc/sys": "/proc/sys",
                "BindReadOnlyPaths=/srv/pr/run:/x": "/proc/self/root/run",
                "EnvironmentFile=/proc/self/root/var/lib/agentos-kernel/env": "/proc/self/root/var/lib/agentos-kernel/env",
                "BindReadOnlyPaths=/dev:/x": "/dev", "BindReadOnlyPaths=/dev/sda:/x": "/dev/sda",
                "TTYPath=/dev/tty1": "/dev/tty1", "BindReadOnlyPaths=/dev/nullx:/x": "/dev/nullx",
                "BindReadOnlyPaths=/dev/null/x:/x": "/dev/null/x", "OpenFile=/dev/urandom/x": "/dev/urandom/x"}
        for d in ("/dev/fd/3", "/dev/stdin", "/dev/stdout", "/dev/stderr", "/dev/core"):
            view["BindReadOnlyPaths=%s:/x" % d] = d
        unmodelled = ("ReadOnlyPaths=%t/agentos-setup", 'ReadOnlyPaths="/var/run/agentos-setup"',
                      "BindReadOnlyPaths=%S/agentos-store:/x", "BindReadOnlyPaths='/var/lib/agentos-kernel':/x",
                      "ReadWritePaths=/var/lib/agentos\\x2dstore")
        want = {l: " reaches the keeper's state" for l in reach}
        # The box's /etc/mtab is a /proc view before the tree holds it (#5154 (c)).
        view["BindReadOnlyPaths=/etc/mtab:/x"] = "/proc/self/mounts"
        want.update({l: ": %s is under /proc or /dev, which the tree check does not model (only /dev/null, "
                        "/dev/zero, /dev/random, /dev/urandom pass)" % g for l, g in view.items()})
        want.update({l: ": the tree check does not model it" for l in unmodelled})
        want["BindReadOnlyPaths=/srv/loop:/x"] = ": the image cannot resolve it (too many levels of links)"
        for line, why in want.items():
            with self.subTest(line):
                d = write(self.root, SYSTEM + "agentos-boot-report.service.d/99-probe.conf", "[Service]\n%s\n" % line)
                key, val = line.split("=", 1)
                self.assertEqual(self.v(), ["agentos-boot-report.service: %s=%s%s (D-154)" % (key, val, why)])
                d.unlink()
        # An ordinary source outside the keeper's state, linked or not, and DEV_SAFE, are still allowed.
        for line in ("BindReadOnlyPaths=/var/run/agentos-e2e/share:/x", "BindReadOnlyPaths=/srv/a:/x",
                     "BindPaths=/srv/a/missing:/x", "ReadWritePaths=-/sys/class/leds/x", "OpenFile=/var/run/agentos-e2e/f",
                     "BindReadOnlyPaths=/dev/null:/x", "StandardInput=file:/dev/null", "BindReadOnlyPaths=/dev/urandom:/x",
                     "BindReadOnlyPaths=/dev/zero:/x", "BindReadOnlyPaths=/dev/random:/x",
                     "TemporaryFileSystem=/srv/a:ro", "ReadOnlyPaths=/srv/a:b", "BindReadOnlyPaths=/srv/a:/run/agentos-setup"):
            with self.subTest(line):
                d = write(self.root, SYSTEM + "agentos-boot-report.service.d/99-probe.conf", "[Service]\n%s\n" % line)
                self.assertEqual(self.v(), [])
                d.unlink()

    def probe(self, line):
        d = write(self.root, SYSTEM + "agentos-boot-report.service.d/99-probe.conf", "[Service]\n%s\n" % line)
        try:
            return self.v()
        finally:
            d.unlink()

    def test_a_path_through_a_directory_a_service_can_write_is_refused(self):
        # #5154: systemd resolves a path setting when the unit starts, so whoever can write a directory on
        # its way can plant a link there at runtime (x -> /var/lib/agentos-store) that the build never saw.
        self.assertEqual(self.probe("BindReadOnlyPaths=/var/lib/agentos-localui/x:/y"), [
            "agentos-boot-report.service: BindReadOnlyPaths=/var/lib/agentos-localui/x:/y, which the box resolves "
            "when the unit starts, so a link to it is held to the link rules (#5154): a link to "
            "/var/lib/agentos-localui/x, inside /var/lib/agentos-localui, a directory systemd makes for a unit at "
            "runtime (StateDirectory= in usr/lib/systemd/system/agentos-localui.service); that unit's user would "
            "decide what it reads (#5167) (D-154)"])
        (self.root / "srv").mkdir(exist_ok=True)
        (self.root / "srv/l").symlink_to("/var/lib/agentos-localui")
        (self.root / "srv/open").mkdir(mode=0o777)
        (self.root / "srv/open").chmod(0o777)
        (self.root / "var/lib/agentos-egress").mkdir(parents=True)
        (self.root / "var/lib/agentos-egress/k").symlink_to("/usr/lib")
        (self.root / "srv/via").symlink_to("/var/lib/agentos-egress/k")
        (self.root / "srv/re").mkdir()
        (self.root / "srv/re/k").symlink_to("/usr/lib")
        write(self.root, "usr/lib/tmpfiles.d/zz-probe.conf", "d /srv/made 1777 root root -\nd /srv/re 1777 root root -\n"
              "L /srv/lk - - - - /usr/lib\nL /var/run - - - - ../run\n")
        (self.root / "srv/lk").symlink_to("/usr/lib")
        # Each line's way runs through the directory named, as written, through an image link, or after one.
        refused = {"BindPaths=/var/lib/agentos-localui/x": "/var/lib/agentos-localui",
                   "ReadOnlyPaths=/tmp/x": "/tmp", "ExecPaths=/var/tmp/x": "/var/tmp",
                   "BindReadOnlyPaths=/home/u/x:/y": "/home", "ReadWritePaths=-/run/user/1000/x": "/run/user",
                   "BindReadOnlyPaths=/run/agentos-localui/x:/y": "/run/agentos-localui",
                   "NoExecPaths=/var/run/agentos-localui/x": "/run/agentos-localui",
                   # #5167: a unit-made directory's dynamic user form; /var/lib/private itself is root's 0700.
                   "BindReadOnlyPaths=/var/lib/private/agentos-localui/x:/y": "/var/lib/private/agentos-localui",
                   "TemporaryFileSystem=/var/lib/agentos-localui/x:ro": "/var/lib/agentos-localui",
                   "MountImages=/run/agentos-mail/i:/y": "/run/agentos-mail",
                   "EnvironmentFile=-/var/lib/agentos-egress/env": "/var/lib/agentos-egress",
                   "OpenFile=/run/agentos-egress/f": "/run/agentos-egress",
                   "LoadCredential=c:/run/agentos-homekit/c": "/run/agentos-homekit",
                   "StandardInput=file:/run/agentos-link/f": "/run/agentos-link",
                   "StateDirectory=agentos-localui/s": "/var/lib/agentos-localui",
                   "BindReadOnlyPaths=/srv/l/x:/y": "/var/lib/agentos-localui",
                   "BindReadOnlyPaths=/srv/via/x:/y": "/var/lib/agentos-egress",
                   # The last link the image follows sits in a directory the egress user can write.
                   "BindReadOnlyPaths=/srv/via:/y": "/var/lib/agentos-egress",
                   "BindReadOnlyPaths=/srv/open/x:/y": "/srv/open",
                   # A step before the link, which a tmpfiles.d line remakes for anyone to write.
                   "BindReadOnlyPaths=/srv/re/k/x:/y": "/srv/re"}
        for line, d in refused.items():
            with self.subTest(line):
                got = self.probe(line)
                self.assertEqual(len(got), 1, got)
                self.assertTrue(got[0].startswith("agentos-boot-report.service: %s, which the box resolves when the "
                                                  "unit starts, so a link to it is held to the link rules (#5154): "
                                                  % line), got)
                self.assertIn(" /%s, " % d.lstrip("/"), got[0])
        # A step the tree lacks is weighed by the tmpfiles.d line that makes it.
        got = self.probe("BindReadOnlyPaths=/srv/made/x:/y")
        self.assertEqual(len(got), 1, got)
        self.assertIn("through /srv/made, which the tree lacks and usr/lib/tmpfiles.d/zz-probe.conf line 1 makes", got[0])
        # The box's /var/run is judged as /run even where the tree's link leads elsewhere (tmpfiles' L+).
        (self.root / "var/run").symlink_to("/srv/a")
        (self.root / "srv/a").mkdir()
        self.assertEqual(self.probe("ReadOnlyPaths=/var/run/agentos-setup"), [
            "agentos-boot-report.service: ReadOnlyPaths=/var/run/agentos-setup reaches the keeper's state (D-154)"])
        (self.root / "var/run").unlink()
        # The directory itself is not on its way: only its parent, root's, holds its name. So is a root-owned way,
        # and a box path whose directories are root's.
        for line in ("BindReadOnlyPaths=/var/lib/agentos-localui:/y", "ReadWritePaths=/var/lib/agentos-egress",
                     "BindReadOnlyPaths=/usr/lib/agentos/agentos-imapconn", "BindReadOnlyPaths=/usr/lib/x/y:/z",
                     "ReadOnlyPaths=/tmp", "BindReadOnlyPaths=/srv/open:/y",
                     "BindReadOnlyPaths=/run/agentos-e2e/share:/x", "StateDirectory=agentos-localui",
                     # Under a box mount a step is held to the named directories only, as a link's is:
                     # trixie's own L /var/run line names /run.
                     "RuntimeDirectory=agentos-x",
                     # A link the tree holds is followed, not taken as a step, though a tmpfiles.d line keeps it.
                     "BindReadOnlyPaths=/srv/lk/x:/y"):
            with self.subTest(line):
                self.assertEqual(self.probe(line), [])

    def test_a_path_through_a_stock_service_users_directory_is_refused(self):
        # #5167: systemd makes each *Directory= a unit file names, stock or ours, so systemd-resolved's user can
        # plant a link in /run/systemd/resolve, which /etc/resolv.conf names, and the binding unit reads where
        # it leads on its next start.
        probes = {"BindReadOnlyPaths=/etc/resolv.conf:/x": "/run/systemd/resolve",
                  "BindReadOnlyPaths=/run/systemd/netif/x:/y": "/run/systemd/netif",
                  "EnvironmentFile=/var/run/systemd/resolve/x": "/run/systemd/resolve",
                  "ReadOnlyPaths=/var/lib/systemd/timesync/x": "/var/lib/systemd/timesync",
                  "LoadCredential=c:/run/systemd/timesync/c": "/run/systemd/timesync"}
        for line in probes:
            with self.subTest(line):
                self.assertEqual(self.probe(line), [])
        write(self.root, SYSTEM + "systemd-resolved.service",
              "[Service]\nRuntimeDirectory=systemd/resolve\nRuntimeDirectoryPreserve=yes\nUser=systemd-resolve\n")
        write(self.root, SYSTEM + "systemd-networkd.service", "[Service]\nRuntimeDirectory=systemd/netif\nUser=systemd-network\n")
        write(self.root, SYSTEM + "systemd-timesyncd.service",
              "[Service]\nRuntimeDirectory=systemd/timesync\nStateDirectory=systemd/timesync\nUser=systemd-timesync\n")
        self.assertEqual(self.probe("BindReadOnlyPaths=/etc/resolv.conf:/x"), [
            "agentos-boot-report.service: BindReadOnlyPaths=/etc/resolv.conf:/x, which the box resolves when the unit "
            "starts, so a link to it is held to the link rules (#5154): a link to /etc/resolv.conf, inside "
            "/run/systemd/resolve, a directory systemd makes for a unit at runtime (RuntimeDirectory= in "
            "usr/lib/systemd/system/systemd-resolved.service); that unit's user would decide what it reads (#5167) "
            "(D-154)"])
        for line, d in probes.items():
            with self.subTest(line):
                got = self.probe(line)
                self.assertEqual(len(got), 1, got)
                self.assertIn(", inside %s, a directory systemd makes for a unit at runtime (" % d, got[0])
        # The directory itself, and root's /run/systemd above it, are not on the way; the stock tree passes.
        for line in ("BindReadOnlyPaths=/run/systemd/resolve:/x", "BindReadOnlyPaths=/run/systemd/notify:/x"):
            with self.subTest(line):
                self.assertEqual(self.probe(line), [])
        self.assertEqual(check.violations(self.root), [])

    def place(self, files):
        """Write FILES ({tree path: text, or ("link", target)}) and give back what removes them again."""
        made = []
        for rel, what in files.items():
            if isinstance(what, tuple):
                (self.root / rel).parent.mkdir(parents=True, exist_ok=True)
                (self.root / rel).symlink_to(what[1])
                made.append(self.root / rel)
            else:
                made.append(write(self.root, rel, what))

        def remove():
            for f in reversed(made):
                f.unlink()
        return remove

    def test_every_directory_a_unit_file_names_counts(self):
        # #5167 re-plan: every file in the unit directories, and every link's target, counts whatever names,
        # aliases, precedence or users systemd resolves, so each repro of #5192's four fix-lists is refused
        # under one rule, with no User= line needed.
        etc = "etc/systemd/system/"
        if not (self.root / "lib").is_symlink():
            (self.root / "lib").symlink_to("usr/lib")
        cases = {
            # Security 1 and L3 1 (round 1): drop-ins split across a unit and its alias, or a template alias.
            "alias split": ({SYSTEM + "a.service": "[Service]\nExecStart=/x\n",
                             etc + "b.service": ("link", "/usr/lib/systemd/system/a.service"),
                             etc + "b.service.d/d.conf": "[Service]\nRuntimeDirectory=adir\n"}, "run/adir"),
            "template alias": ({SYSTEM + "t@.service": "[Service]\nExecStart=/x\n", etc + "v@.service": ("link", "/usr/lib/systemd/system/t@.service"),
                                etc + "v@.service.d/d.conf": "[Service]\nStateDirectory=vdir\n"}, "var/lib/vdir"),
            # Security 2 (round 1): a root unit whose mode lets anyone write.
            "root 0777": ({SYSTEM + "w.service": "[Service]\nRuntimeDirectory=wdir\nRuntimeDirectoryMode=0777\n"}, "run/wdir"),
            "root 1777": ({SYSTEM + "w2.service": "[Service]\nStateDirectory=w2dir\nStateDirectoryMode=1777\n"},
                          "var/lib/w2dir"),
            # Rounds 2 and 3: /etc shadowing the alias's target, and a /lib linked unit.
            "etc shadow": ({SYSTEM + "o.service": "[Service]\nExecStart=/x\n", etc + "o.service": "[Service]\nExecStart=/x\n",
                            etc + "ob.service": ("link", "/usr/lib/systemd/system/o.service"),
                            etc + "ob.service.d/d.conf": "[Service]\nRuntimeDirectory=odir\n"}, "run/odir"),
            "lib linked": ({SYSTEM + "la.service": "[Service]\nRuntimeDirectory=libdir\n",
                            etc + "la.service": "[Service]\nExecStart=/x\n",
                            etc + "lb.service": ("link", "/lib/systemd/system/la.service")}, "run/libdir"),
            # Round 3: links systemd rejects as aliases, so it runs the name's next file.
            "plain to template": ({SYSTEM + "x.service": "[Service]\nRuntimeDirectory=xdir\n",
                                   SYSTEM + "y@.service": "[Service]\nExecStart=/x\n",
                                   etc + "x.service": ("link", "/usr/lib/systemd/system/y@.service")}, "run/xdir"),
            "plain to instance": ({SYSTEM + "x2.service": "[Service]\nStateDirectory=x2dir\n",
                                   SYSTEM + "y@.service": "[Service]\nExecStart=/x\n", SYSTEM + "y@i.service": ("link", "y@.service"),
                                   etc + "x2.service": ("link", "/usr/lib/systemd/system/y@i.service")}, "var/lib/x2dir"),
            "template to instance": ({SYSTEM + "z@.service": "[Service]\nStateDirectory=zdir\n",
                                      SYSTEM + "y@.service": "[Service]\nExecStart=/x\n",
                                      SYSTEM + "y@i.service": ("link", "y@.service"),
                                      etc + "z@.service": ("link", "/usr/lib/systemd/system/y@i.service")}, "var/lib/zdir"),
            "mismatched instances": ({SYSTEM + "m@.service": "[Service]\nCacheDirectory=mdir\n",
                                      SYSTEM + "y@.service": "[Service]\nExecStart=/x\n",
                                      SYSTEM + "y@b.service": ("link", "y@.service"),
                                      etc + "m@a.service": ("link", "/usr/lib/systemd/system/y@b.service")}, "var/cache/mdir"),
            "hidden": ({SYSTEM + ".h.service": "[Service]\nLogsDirectory=hdir\n"}, "var/log/hdir"),
            "backup": ({SYSTEM + "h.service~": "[Service]\nLogsDirectory=bdir\n"}, "var/log/bdir"),
            # Monotone: a shadowed file, a masked unit's file, a drop-in with no fragment, another section, a reset.
            "shadowed": ({SYSTEM + "s.service": "[Service]\nRuntimeDirectory=sdir\n", etc + "s.service": "[Service]\nExecStart=/x\n"},
                         "run/sdir"),
            "masked": ({SYSTEM + "mk.service": "[Service]\nStateDirectory=mkdir\n", etc + "mk.service": ("link", "/dev/null")},
                       "var/lib/mkdir"),
            "no fragment": ({etc + "nf.service.d/d.conf": "[Service]\nRuntimeDirectory=nfdir\n"}, "run/nfdir"),
            "unit section": ({SYSTEM + "un.service": "[Unit]\nRuntimeDirectory=undir\n"}, "run/undir"),
            "reset": ({SYSTEM + "rs.service": "[Service]\nRuntimeDirectory=rdir\nRuntimeDirectory=\n"}, "run/rdir"),
            "wants link": ({SYSTEM + "multi-user.target.wants/q.service": ("link", "/srv/q.service"),
                            "srv/q.service": "[Service]\nRuntimeDirectory=qdir\n"}, "run/qdir"),
            "configuration": ({SYSTEM + "cf.service": "[Service]\nConfigurationDirectory=cdir\n"}, "etc/cdir"),
            # Parse: each word, both sides of a:b, nested paths, a tab.
            "colon": ({SYSTEM + "c1.service": "[Service]\nStateDirectory=c1 c1b:c1link\n"}, "var/lib/c1link"),
            "nested": ({SYSTEM + "c2.service": "[Service]\nCacheDirectory=./c2//n/\n"}, "var/cache/c2/n"),
            "tab": ({SYSTEM + "sp.service": "[Service]\nRuntimeDirectory=sp1\tsp2\n"}, "run/sp2"),
        }
        base, err = check.unit_made_dirs(self.root)
        self.assertEqual(err, [])
        for name, (files, d) in cases.items():
            with self.subTest(name):
                self.assertNotIn(d, base)
                remove = self.place(files)
                try:
                    got, err = check.unit_made_dirs(self.root)
                    self.assertEqual(err, [])
                    self.assertIn(d, got)
                    seen = d
                    probe = self.probe("ReadOnlyPaths=/%s/x" % seen)
                    self.assertEqual(len(probe), 1, probe)
                    self.assertIn(", inside /%s, a directory systemd makes for a unit at runtime (" % seen, probe[0])
                    # Its dynamic user form counts too, whoever runs the unit; <top>/private itself does not.
                    top = next(t for t in ("var/lib", "var/cache", "var/log", "run", "etc") if seen.startswith(t + "/"))
                    private = "%s/private/%s" % (top, seen[len(top) + 1:])
                    self.assertEqual(check.service_dir(self.root, private), got[d])
                    self.assertIsNone(check.service_dir(self.root, top + "/private"))
                    self.assertIsNone(check.service_dir(self.root, seen + "/deeper"))
                finally:
                    remove()
        # Nothing names a dynamic user's private/ roots on their own.
        for d in ("var/lib/private", "var/cache/private", "var/log/private", "run/private"):
            self.assertNotIn(d, check.SERVICE_DIRS)
        self.assertEqual(check.SERVICE_DIRS, ("home", "run/user", "var/lib/agentos-mail", "var/lib/agentos-camera",
                                              "var/lib/agentos-homekit"))
        # Monotone: with every case in the tree at once, removing any one file or link leaves a subset.
        removes = [self.place({k: v for k, v in files.items() if not (self.root / k).exists()
                               and not (self.root / k).is_symlink()}) for files, _ in cases.values()]
        try:
            full = set(check.unit_made_dirs(self.root)[0])
            self.assertTrue({d for _, d in cases.values()} <= full)
            for f in sorted(p for p in (self.root / "etc/systemd/system").rglob("*") if p.is_symlink() or p.is_file()):
                with self.subTest(remove=str(f)):
                    keep = f.readlink() if f.is_symlink() else f.read_bytes()
                    f.unlink()
                    try:
                        self.assertTrue(set(check.unit_made_dirs(self.root)[0]) <= full)
                    finally:
                        f.symlink_to(keep) if isinstance(keep, pathlib.Path) else f.write_bytes(keep)
        finally:
            for r in reversed(removes):
                r()

    def test_what_a_unit_file_names_that_the_check_cannot_read_is_refused(self):
        # #5167: a link that ends nowhere the tree holds, and a value the check does not model, fail the build.
        etc = "etc/systemd/system/"
        (self.root / "srv").mkdir(exist_ok=True)
        (self.root / "var/tmp").mkdir(parents=True, exist_ok=True)
        write(self.root, "var/tmp/t.service", "[Service]\nRuntimeDirectory=t\n")
        for target in ("/usr/lib/systemd/system/missing.service", "l2.service", "/run/x.service", "/var/tmp/t.service"):
            with self.subTest(target):
                remove = self.place({etc + "l1.service": ("link", target), etc + "l2.service": ("link", "l1.service")})
                try:
                    err = check.unit_made_dirs(self.root)[1]
                    self.assertTrue(err and all(e.startswith(etc) and ": a link to " in e for e in err), err)
                    self.assertIn(err[0], check.violations(self.root))
                finally:
                    remove()
        # A mask is skipped.
        remove = self.place({etc + "mm.service": ("link", "/dev/null")})
        self.assertEqual(check.unit_made_dirs(self.root)[1], [])
        remove()
        # Security 6760938141: a specifier is refused wherever it sits, never expanded (%i may be "", %j ".").
        for text in ("StateDirectory=%i", "StateDirectory=./%i/x", "StateDirectory=a/%i/b", "StateDirectory=a/%I",
                     "RuntimeDirectory=a/%t", "StateDirectory=a/x%%", "StateDirectory=caps/c-%i", "StateDirectory=qc/%i",
                     "LogsDirectory=journal/%m.%i", "RuntimeDirectory=systemd/journal.%j", "CacheDirectory=a*", "CacheDirectory=a/b?",
                     "LogsDirectory=a/[b]", "RuntimeDirectory=\"q\"", "LogsDirectory=a/../b",
                     "CacheDirectory=a\\b", "StateDirectory=/abs", "StateDirectory=ok x:/abs",
                     "RuntimeDirectory=n\u00a0d", "RuntimeDirectory=n\x0bd", "RuntimeDirectory=n\u0085d"):
            with self.subTest(text):
                d = write(self.root, SYSTEM + "x.service", "[Service]\n%s\n" % text)
                try:
                    key, val = text.split("=", 1)
                    self.assertEqual(check.unit_made_dirs(self.root)[1], [
                        "%sx.service: %s=%s: the tree check does not model it; the tree check never passes a unit file "
                        "whose directories it cannot read (#5167)" % (SYSTEM, key, val if val.isprintable() else repr(val))])
                    self.assertIn(check.unit_made_dirs(self.root)[1][0], check.violations(self.root))
                finally:
                    d.unlink()
        # A value PID 1 acts on that holds a specifier, a quote, a backslash or a byte it does not model is
        # refused whole, wherever it sits in a word (Security 6760938141: %i, %R and %B may expand to "", and
        # systemd unquotes and unescapes words before it makes the path).
        for text in ("ListenStream=%t/x.sock", "Symlinks=/run/a /run/b%i", "Where=/var/lib/'q'",
                     "StandardError=truncate:%S/x", "Symlinks=%i/run/sy", "Symlinks=%R/run/sy", "Symlinks=%B/run/sy",
                     "ListenFIFO=%i/run/sy", 'Symlinks="/run/sy"', "Symlinks='/run/sy'", "Symlinks=\\/run/sy",
                     "Symlinks=/run/s\\x79", "Symlinks=%%%i/run/sy", "ListenStream=/run/a%%b", "Options=size=1%",
                     "Symlinks=%t", "Symlinks=/run/a\x0b/run/sy", "StandardOutput=file:%i/var/lib/so",
                     "StandardOutput=file:%R/var/lib/so",
                     # Security 6762243927, L3 6762274629: a '/' that opens no absolute path is a relative path PID 1
                     # makes from / (What=, overlay dirs), or text the check does not read; a '..' step is not followed.
                     "What=var/lib/w/src", "What=./var/lib/w/src", "What=~/x",
                     "Options=lowerdir=/usr,upperdir=var/lib/w/up,workdir=var/lib/w/wk", "What=/var/lib/a=b/src",
                     "Symlinks=/run/a/../b", "StandardOutput=file:x/var/lib/so"):
            with self.subTest(text):
                d = write(self.root, SYSTEM + "x.socket", "[Socket]\n%s\n" % text)
                try:
                    key, val = text.split("=", 1)
                    got = check.unit_made_paths(self.root)[2]
                    self.assertEqual(len(got), 1, got)
                    self.assertTrue(got[0].startswith("%sx.socket: %s=" % (SYSTEM, key)), got)
                    self.assertTrue(got[0].endswith(": the tree check does not model it; the tree check never passes a "
                                                    "unit file whose paths it cannot read (#5167)"), got)
                    self.assertIn(got[0], check.violations(self.root))
                finally:
                    d.unlink()
        # Names and numbers (PID1_NAMES) are not read for paths, nor is a literal %% outside a path word
        # (stock tmp.mount's size=50%%); PID 1 only opens a TTYPath=.
        d = write(self.root, SYSTEM + "x@.service", "[Service]\nUser=camdec-%I\nAfter=%i.mount %n.socket\n"
                                                    "TTYPath=/dev/%I\nUtmpIdentifier=%I\nWants=%I\nSlice=user-%i.slice\n"
                                                    "TasksMax=33%\nCPUQuota=25%\nMemoryHigh=80%\nIPAddressAllow=10.0.0.0/8 fc00::/7\n"
                                                    "DeviceAllow=char-/dev/console rw\nWantedBy=sys-subsystem-net-devices-a\\x2db.device\n"
                                                    "[Mount]\nOptions=mode=1777,size=50%%\n")
        try:
            self.assertEqual(check.unit_made_paths(self.root)[2], [])
        finally:
            d.unlink()

    def test_a_unit_made_directorys_way_is_roots_alone(self):
        # #5167 re-plan 2: systemd 257's setup_exec_directory makes the missing steps, then chmods and chowns
        # what it finds at the last step to the unit's user, following a link at any step, the last included.
        # So each step, in both forms, is held to the link rules: the tree holds a directory or nothing there,
        # no tmpfiles.d line may leave anything but a directory at the last step, and no one but root may
        # write or remake a step above it. Each case is one unit (User=nobody unless set) and its tree.
        tmpf = "usr/lib/tmpfiles.d/zz.conf"
        (self.root / "srv/qq").mkdir(parents=True, exist_ok=True)
        # Two tree steps another uid owns, as tree_lstat reports them (CI does not run as root).
        (self.root / "var/lib/owned").mkdir(parents=True, exist_ok=True)
        (self.root / "var/cache/private/dz").mkdir(parents=True, exist_ok=True)
        other, real = check.TREE_OWNER + 1000, check.tree_lstat

        def lstat(root, rel):
            st = real(root, rel)
            if rel not in ("var/lib/owned", "var/cache/private/dz") or st is None:
                return st
            return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink, other) + tuple(st)[5:])
        patcher = unittest.mock.patch.object(check, "tree_lstat", lstat)
        patcher.start()
        self.addCleanup(patcher.stop)
        refused = (
            # Security 6758176175: a tmpfiles.d link at the directory itself, in each form and under /run.
            ("StateDirectory=qq", {tmpf: "L /var/lib/qq - - - - /srv/qq\n"}, "/var/lib/qq", "where " + tmpf),
            ("StateDirectory=dq\nDynamicUser=yes", {tmpf: "L /var/lib/private/dq - - - - /srv/qq\n"},
             "/var/lib/private/dq", "where " + tmpf),
            ("RuntimeDirectory=rq", {tmpf: "L /run/rq - - - - /srv/qq\n"}, "/run/rq", "where " + tmpf),
            # Anything else that is not a directory: a device node, a copy, a file; a specifier the box expands;
            # a template's directory.
            ("StateDirectory=cq", {tmpf: "c /var/lib/cq 0600 - - - 8:0\n"}, "/var/lib/cq", "where " + tmpf),
            ("StateDirectory=cq", {tmpf: "b /var/lib/cq 0600 - - - 8:0\n"}, "/var/lib/cq", "where " + tmpf),
            ("StateDirectory=cq", {tmpf: "p /var/lib/cq 0600 - - -\n"}, "/var/lib/cq", "where " + tmpf),
            # A line that reaches the directory through a link the tree holds.
            ("StateDirectory=cq", {"srv/al": ("link", "/var/lib"), tmpf: "f /srv/al/cq 0644 - - -\n"}, "/var/lib/cq",
             "where " + tmpf),
            ("StateDirectory=cq", {tmpf: "C /var/lib/cq - - - - /srv/qq\n"}, "/var/lib/cq", "where " + tmpf),
            ("StateDirectory=cq", {tmpf: "f /var/lib/cq 0644 - - -\n"}, "/var/lib/cq", "where " + tmpf),
            ("StateDirectory=cq", {tmpf: "L /var/lib/c%Hq - - - - /srv/qq\n"}, "/var/lib/cq", "where " + tmpf),
            # A step above: a tmpfiles.d link, or a /run step made for another user.
            ("StateDirectory=pq/b", {tmpf: "L /var/lib/pq - - - - /srv/qq\n"}, "/var/lib/pq/b", "makes a link"),
            ("RuntimeDirectory=sq/x", {tmpf: "L /run/sq - - - - /srv/qq\n"}, "/run/sq/x", "makes a link"),
            ("RuntimeDirectory=sq/x", {tmpf: "d /run/sq 0755 nobody - -\n"}, "/run/sq/x", "for nobody:-"),
            # The tree: a link or a file at the last step or above, in either form.
            ("StateDirectory=foo", {"var/lib/foo": ("link", "/srv/qq")}, "/var/lib/foo", "in the tree (/var/lib/foo)"),
            ("StateDirectory=foo", {"var/lib/foo": ""}, "/var/lib/foo", "in the tree (/var/lib/foo)"),
            ("StateDirectory=pa/b", {"var/lib/pa": ("link", "/srv/qq")}, "/var/lib/pa/b", "a link or a file in the tree"),
            ("CacheDirectory=foo", {"var/cache/private/foo": ("link", "/srv/qq")}, "/var/cache/private/foo",
             "in the tree (/var/cache/private/foo)"),
            ("RuntimeDirectory=r/s", {"run/private/r": ("link", "/srv/qq")}, "/run/private/r/s", "in the tree"),
            # A step another user can write: a tree step another uid owns (also below <top>/private), a
            # world-writable step, a service directory, another unit's directory.
            ("StateDirectory=owned/x", {}, "/var/lib/owned/x", "through /var/lib/owned, which uid %d owns" % other),
            ("CacheDirectory=dz/x", {}, "/var/cache/private/dz/x",
             "through /var/cache/private/dz, which uid %d owns" % other),
            ("RuntimeDirectory=lock/x", {}, "/run/lock/x", "inside /run/lock, which anyone"),
            ("StateDirectory=agentos-mail/x", {}, "/var/lib/agentos-mail/x", "inside /var/lib/agentos-mail, which anyone"),
            ("StateDirectory=na/b", {SYSTEM + "na.service": "[Service]\nStateDirectory=na\nUser=ua\n"}, "/var/lib/na/b",
             "inside /var/lib/na, a directory systemd makes for a unit at runtime (StateDirectory= in %sna.service)" % SYSTEM),
            # Security 6759084501: what PID 1 itself makes for other settings (umask 0): a path unit's directory
            # at a step, a socket's parents with a loose DirectoryMode=, a socket or its Symlinks= at the
            # directory, a mount point at a step (with DirectoryMode=0777), and a mount below the directory.
            ("RuntimeDirectory=pp/x", {SYSTEM + "p.path": "[Path]\nDirectoryNotEmpty=/run/pp\nMakeDirectory=yes\n"
                                                         "DirectoryMode=0777\n"}, "/run/pp/x", "where PID 1 may make, link or mount /run/pp"),
            ("RuntimeDirectory=ss/b", {SYSTEM + "s.socket": "[Socket]\nListenStream=/run/ss/a/sock\nDirectoryMode=0777\n"},
             "/run/ss/b", "below a step PID 1 may make for anyone to write (for /run/ss/a/sock, ListenStream= in %ss.socket" % SYSTEM),
            # The same under /run with the tree holding the step: the box's tmpfs hides it, so PID 1 makes it.
            ("RuntimeDirectory=ss/b", {"run/ss/keep": "", SYSTEM + "s.socket": "[Socket]\nListenStream=/run/ss/a/sock\n"
                                                                              "DirectoryMode=0777\n"},
             "/run/ss/b", "below a step PID 1 may make for anyone to write (for /run/ss/a/sock, ListenStream= in %ss.socket" % SYSTEM),
            ("RuntimeDirectory=sy", {SYSTEM + "s.socket": "[Socket]\nListenStream=/run/x.sock\nSymlinks=/run/sy\n"},
             "/run/sy", "where PID 1 may make, link or mount /run/sy (Symlinks= in %ss.socket)" % SYSTEM),
            ("RuntimeDirectory=sy", {SYSTEM + "s.socket": "[Socket]\nListenFIFO=/run/sy\n"}, "/run/sy",
             "where PID 1 may make, link or mount /run/sy (ListenFIFO="),
            ("StateDirectory=mm/x", {SYSTEM + "var-lib-mm.mount": "[Mount]\nWhat=tmpfs\nDirectoryMode=0777\n"},
             "/var/lib/mm/x", "where PID 1 may make, link or mount /var/lib/mm (the name of %svar-lib-mm.mount)" % SYSTEM),
            ("StateDirectory=mq/e", {SYSTEM + "m.mount": "[Mount]\nWhat=tmpfs\nWhere=/var/lib/mq/d\nDirectoryMode=0777\n"},
             "/var/lib/mq/e", "below a step PID 1 may make for anyone to write (for /var/lib/mq/d, Where= in %sm.mount" % SYSTEM),
            ("StateDirectory=mb", {SYSTEM + "m.mount": "[Mount]\nWhat=/dev/sda\nWhere=/var/lib/mb/in\n"}, "/var/lib/mb",
             "above /var/lib/mb/in, which is mounted (Where= in %sm.mount) and the chown descends into" % SYSTEM),
            # Security 6759651094: a loose DirectoryMode= counts from any unit file (systemd merges drop-ins: the
            # unit's own, and the type-wide socket.d/ and path.d/), and any setting off PID1_READS counts by
            # default, StandardOutput=file: among them.
            ("StateDirectory=sd/x", {SYSTEM + "sd.socket": "[Socket]\nListenStream=/var/lib/sd/sock\n",
                                     SYSTEM + "sd.socket.d/m.conf": "[Socket]\nDirectoryMode=0777\n"},
             "/var/lib/sd/x", "below a step PID 1 may make for anyone to write (for /var/lib/sd/sock, ListenStream="),
            ("StateDirectory=sd/x", {SYSTEM + "sd.socket": "[Socket]\nListenStream=/var/lib/sd/sock\n",
                                     "etc/systemd/system/socket.d/m.conf": "[Socket]\nDirectoryMode=0777\n"},
             "/var/lib/sd/x", "below a step PID 1 may make for anyone to write (for /var/lib/sd/sock, ListenStream="),
            # A mode the check cannot read counts as one others can write.
            ("StateDirectory=sd/x", {SYSTEM + "sd.socket": "[Socket]\nListenStream=/var/lib/sd/sock\nDirectoryMode=0o770\n"},
             "/var/lib/sd/x", "below a step PID 1 may make for anyone to write (for /var/lib/sd/sock, ListenStream="),
            ("StateDirectory=pp/x", {SYSTEM + "pp.path": "[Path]\nDirectoryNotEmpty=/var/lib/pp/w\nMakeDirectory=yes\n",
                                     SYSTEM + "pp.path.d/m.conf": "[Path]\nDirectoryMode=0777\n"},
             "/var/lib/pp/x", "below a step PID 1 may make for anyone to write (for /var/lib/pp/w, DirectoryNotEmpty="),
            # L3 6761389633: PID 1 makes a bind mount's source with the unit's DirectoryMode= (mount_enter_mounting).
            ("StateDirectory=w/x", {SYSTEM + "srv-m.mount": "[Mount]\nWhat=/var/lib/w/src\nWhere=/srv/m\nOptions=bind\n"
                                                            "DirectoryMode=0777\n"},
             "/var/lib/w/x", "below a step PID 1 may make for anyone to write (for /var/lib/w/src, What= in %ssrv-m.mount"
             % SYSTEM),
            # An overlay's upperdir= is made too; a word holding ',' counts cut there (mount options).
            ("StateDirectory=ov", {SYSTEM + "srv-o.mount": "[Mount]\nWhat=overlay\n"
                                                           "Options=lowerdir=/usr,upperdir=/var/lib/ov,workdir=/srv/w\n"},
             "/var/lib/ov", "where PID 1 may make, link or mount /var/lib/ov (Options= in %ssrv-o.mount)" % SYSTEM),
            # What= is not split at '=' or ':', so a path word also counts run on to the next whitespace.
            ("StateDirectory=eq=x", {SYSTEM + "srv-e.mount": "[Mount]\nWhat=/var/lib/eq=x\nWhere=/srv/e\nOptions=bind\n"},
             "/var/lib/eq=x", "where PID 1 may make, link or mount /var/lib/eq=x (What= in %ssrv-e.mount)" % SYSTEM),
            # PID 1 follows a link on the way it makes (mkdir_p_label), so a path counts as the tree resolves it too.
            ("StateDirectory=w/x", {"srv/l": ("link", "/var/lib"),
                                    SYSTEM + "srv-m.mount": "[Mount]\nWhat=/srv/l/w/src\nWhere=/srv/m\nOptions=bind\n"
                                                            "DirectoryMode=0777\n"},
             "/var/lib/w/x", "below a step PID 1 may make for anyone to write (for /var/lib/w/src, What= in %ssrv-m.mount"
             % SYSTEM),
            ("StateDirectory=so", {SYSTEM + "so.service": "[Service]\nStandardOutput=file:/var/lib/so\n"}, "/var/lib/so",
             "where PID 1 may make, link or mount /var/lib/so (StandardOutput= in %sso.service)" % SYSTEM),
            # A namespace mount point is made only by root, 0755, so it may sit above the directory, not at it.
            ("StateDirectory=bp", {SYSTEM + "b.service": "[Service]\nBindReadOnlyPaths=/etc/hostname:/var/lib/bp\n"},
             "/var/lib/bp", "where PID 1 may make, link or mount /var/lib/bp (BindReadOnlyPaths= in %sb.service)" % SYSTEM),
            # tmpfiles.d gives stock /var/log/journal a group (why mkosi.conf removes journald@'s units).
            ("LogsDirectory=journal/x", {tmpf: "z /var/log/journal 2755 root systemd-journal - -\n"},
             "/var/log/journal/x", "for root:systemd-journal"),
        )
        wired = ("where " + tmpf, "in the tree (/var/lib/foo)", "makes a link",
                 "where PID 1 may make, link or mount /run/sy (Symlinks= in %ss.socket)" % SYSTEM)
        for unit, files, made, why in refused:
            with self.subTest(unit=unit, files=files):
                name = "q.service"
                remove = self.place(dict(files, **{SYSTEM + name: "[Service]\n%s\n%s" % (
                    unit, "" if "User" in unit else "User=nobody\n")}))
                try:
                    # A specifier the box expands (%H) may name any unit's directory, so only this unit's is compared.
                    got = [g for g in check.unit_made_refusals(self.root) if "%" not in files.get(tmpf, "")
                           or g.startswith("%s= in %s%s:" % (unit.split("=")[0], SYSTEM, name))]
                    self.assertEqual(len(got), 1, got)
                    self.assertTrue(got[0].startswith("%s= in %s%s: %s, which systemd makes and hands to the unit's "
                                                      "user following any link on its way, " % (
                                                          unit.split("=")[0], SYSTEM, name, made)), got)
                    self.assertIn(why, got[0])
                    self.assertTrue(got[0].endswith(" (#5167)"), got)
                    if why in wired:  # one case per clause through the whole check; the rest by the rule alone
                        self.assertIn(got[0], check.violations(self.root))
                finally:
                    remove()
        passing = (
            # Siblings, one unit's nested steps of its own top, and root's tree steps.
            ("StateDirectory=s1 s2 deep/er\nRuntimeDirectory=r", {}),
            # A root directory line above; another user's directory line at the directory itself (systemd hands
            # it to the unit's user anyway); attribute and ACL lines there; and lines below it.
            ("StateDirectory=rp/x", {tmpf: "d /var/lib/rp 0755 root root -\n"}),
            ("RuntimeDirectory=nd", {tmpf: "d$ /run/nd 0755 nobody nobody -\nd$ /run/nd/links 0755 nobody nobody -\n"}),
            ("StateDirectory=ac", {tmpf: "a+ /var/lib/ac - - - - group:adm:r-x\nh /var/lib/ac - - - - +C\n"
                                         "L /var/lib/ac/x - - - - /srv/qq\n"}),
            # Stock networkd's shape: its own tmpfiles.d lines, under root's /run/systemd.
            ("RuntimeDirectory=systemd/netif",
             {tmpf: "d$ /run/systemd/netif 0755 systemd-network systemd-network -\n"
                    "d$ /run/systemd/netif/links 0755 systemd-network systemd-network -\n"}),
            # A tree directory there.
            ("StateDirectory=foo", {"var/lib/foo/keep": ""}),
            # /run is the box's own mount: the tree's run/ and the stock /var/run link line naming it (by
            # systemd-tmpfiles' /var/run rewrite) do not count against a directory under it.
            ("RuntimeDirectory=systemd/resolve", {"run/keep": "", tmpf: "L /var/run - - - - ../run\n"}),
            # PID 1's own paths below the directory, or beside it with a mode only root can write: stock journald's
            # sockets in /run/systemd/journal, and the shipped sockets' DirectoryMode=0755.
            ("RuntimeDirectory=systemd/journal", {SYSTEM + "j.socket": "[Socket]\nListenStream=/run/systemd/journal/stdout\n"
                                                                       "DirectoryMode=0755\n"}),
            ("RuntimeDirectory=ok", {SYSTEM + "s.socket": "[Socket]\nListenStream=/run/ok2/sock\nDirectoryMode=0777\n"}),
            # A mode only root and the group can write leaves PID 1's parents root's (they are root:root).
            ("RuntimeDirectory=ss/b", {SYSTEM + "s.socket": "[Socket]\nListenStream=/run/ss/a/sock\nDirectoryMode=0775\n"}),
            # Every setting PID 1 only reads (PID1_READS, the Condition/Assert/Exec prefixes) or that holds only
            # names (PID1_NAMES) may name the directory or a step of its way.
            ("StateDirectory=rd", {SYSTEM + "r.service": "[Unit]\nDescription=/var/lib/rd\nDocumentation=file:/var/lib/rd\n"
                                   "RequiresMountsFor=/var/lib/rd\nWantsMountsFor=/var/lib/rd\nConditionPathExists=/var/lib\n"
                                   "AssertPathExists=/var/lib/rd\n[Service]\nEnvironmentFile=-/var/lib/rd\n"
                                   "ReadOnlyPaths=/var/lib/rd\nReadWritePaths=/var/lib\nInaccessiblePaths=/var/lib/rd\n"
                                   "ExecPaths=/var/lib/rd\nNoExecPaths=/var/lib/rd\nTTYPath=/var/lib/rd\n"
                                   "UtmpIdentifier=/var/lib/rd\nExecStart=/var/lib/rd\nExecStartPre=/var/lib/rd\n"
                                   + "".join("%s=/var/lib/rd\n" % k for k in (
                                       "After", "Before", "Wants", "Requires", "Requisite", "BindsTo", "PartOf", "Upholds",
                                       "Conflicts", "OnFailure", "OnSuccess", "PropagatesReloadTo", "ReloadPropagatedFrom",
                                       "PropagatesStopTo", "StopPropagatedFrom", "JoinsNamespaceOf", "WantedBy",
                                       "RequiredBy", "UpheldBy", "Also", "Slice", "User", "Group", "SupplementaryGroups",
                                       "SyslogIdentifier", "ImportCredential", "TasksMax", "CPUQuota", "MemoryMin",
                                       "MemoryLow", "MemoryHigh", "MemoryMax", "MemorySwapMax", "MemoryZSwapMax",
                                       "ManagedOOMMemoryPressureLimit"))}),
            ("StateDirectory=bq/x", {SYSTEM + "b.service": "[Service]\nTemporaryFileSystem=/var/lib/bq:ro\n"
                                                           "BindPaths=/var/lib/bq/x /srv/s:/var/lib/bq/x/y\n"}),
        )
        for unit, files in passing:
            with self.subTest(unit=unit, files=files):
                remove = self.place(dict(files, **{SYSTEM + "q.service": "[Service]\n%s\nUser=nobody\n" % unit}))
                try:
                    self.assertEqual(check.unit_made_refusals(self.root), [])
                finally:
                    remove()
        # Security 6759651094 (c): an etc/fstab mount point below the directory (systemd-fstab-generator).
        fstab = self.root / "etc/fstab"
        kept = fstab.read_text()
        remove = self.place({SYSTEM + "q.service": "[Service]\nStateDirectory=fq\nUser=nobody\n"})
        try:
            fstab.write_text(kept + "tmpfs /var/lib/fq/m tmpfs mode=0755,noexec,nosuid,nodev 0 0\n")
            self.assertEqual(check.unit_made_refusals(self.root), [
                "StateDirectory= in %sq.service: /var/lib/fq, which systemd makes and hands to the unit's user following "
                "any link on its way, above /var/lib/fq/m, which is mounted (etc/fstab) and the chown descends into "
                "(#5167)" % SYSTEM])
            # Security 6760938141: libmount decodes octal escapes (\057 is '/'), so a mount point that is not plain
            # text opening with '/' is refused, not decoded.
            for point in ("/var/lib/fq\\057m", "\\057var/lib/fq/m", "/var/lib/fq\\040m", "var/lib/fq/m", "/var/lib/f\u00e9"):
                with self.subTest(point):
                    line = "tmpfs %s tmpfs mode=0755,noexec,nosuid,nodev 0 0" % point
                    fstab.write_text(kept + line + "\n")
                    want = ("etc/fstab: %s: a line that is not plain text with a mount point opening with '/' and no '..': "
                            "the tree check does not model it; the tree check never passes an fstab line whose paths it "
                            "cannot read (#5167)" % line)
                    self.assertEqual(check.unit_made_paths(self.root)[2], [want])
                    self.assertIn(want, check.violations(self.root))
            fstab.write_text(kept + "tmpfs\n")
            self.assertEqual(len(check.unit_made_paths(self.root)[2]), 1)
            # A relative bind source or overlay dir (PID 1 makes it from /), and a '..' step, are refused too.
            for line in ("/var/lib/f\\040q /srv/b none bind 0 0", "var/lib/fq /srv/b none bind 0 0",
                         "overlay /srv/o overlay lowerdir=/usr,upperdir=var/lib/fq,workdir=/srv/w 0 0",
                         "/var/lib/x/../fq /srv/b none bind 0 0", "tmpfs /var/lib/x/../fq tmpfs noexec 0 0"):
                with self.subTest(line):
                    fstab.write_text(kept + line + "\n")
                    got = check.unit_made_paths(self.root)[2]
                    self.assertEqual(len(got), 1, got)
                    self.assertTrue(got[0].startswith("etc/fstab: %s: " % line), got)
                    self.assertIn(got[0], check.violations(self.root))
            # A bind source and an overlay dir are paths PID 1 makes (L3 6761389633).
            for line in ("/var/lib/fq /srv/b none bind 0 0", "overlay /srv/o overlay lowerdir=/usr,upperdir=/var/lib/fq,workdir=/srv/w 0 0"):
                with self.subTest(line):
                    fstab.write_text(kept + line + "\n")
                    got = check.unit_made_refusals(self.root)
                    self.assertEqual(len(got), 1, got)
                    self.assertIn("where PID 1 may make, link or mount /var/lib/fq (etc/fstab)", got[0])
        finally:
            fstab.write_text(kept)
            remove()
        # A mount unit's name is read only when it holds no escape (\x2d is '-') and no '..' step.
        for name in ("var-lib-fq\\x2dm.mount", "var-..-lib-fq.mount"):
            remove = self.place({SYSTEM + name: "[Mount]\nWhat=tmpfs\n"})
            try:
                self.assertEqual(check.unit_made_paths(self.root)[2], [
                    "%s%s: a mount unit name with an escape or a '..': the tree check does not model it; the tree "
                    "check never passes a unit file whose paths it cannot read (#5167)" % (SYSTEM, name)])
            finally:
                remove()

    def test_the_mask_holds_from_the_first_boot(self):
        # #2981 (Security 1): a "-" entry gives no mask to a unit started before the path exists, so
        # the image makes each keeper path at boot, before any main-side unit, and the mask has no "-".
        drop = UNITS / "agentos-.service.d/50-main-side.conf"
        self.assertEqual(ini(drop)["Service"]["InaccessiblePaths"].split(), list(check.KEEPER_PATHS))
        self.assertIn("systemd-tmpfiles-setup.service", ini(drop)["Unit"]["After"].split())
        made = {w[1]: w for w in (l.split() for l in TMPFILES.read_text().splitlines()) if w and w[0] == "d"}
        for p in check.KEEPER_PATHS:
            self.assertEqual(made[p][2], "0700", p)
        self.assertEqual(made["/var/lib/agentos-kernel"][3:5], ["agentos-kernel", "agentos-kernel"])
        names = sorted(n for n in (p.name for p in (self.root / SYSTEM).iterdir())
                       if check.NOEXEC_UNITS.match(n) and n not in check.KEEPER_UNITS + check.NOEXEC_EXEMPT
                       + check.EMPTY_ROOT_UNITS + (check.MOR_UNIT,))
        self.edit("agentos-.service.d/50-main-side.conf", " /var/lib/agentos-kernel", " -/var/lib/agentos-kernel")
        self.edit(EMPTY_RUN_DROPIN, " /var/lib/agentos-kernel", " -/var/lib/agentos-kernel")
        self.assertEqual(self.v(), ["%s: InaccessiblePaths=-/var/lib/agentos-kernel gives no mask while the path is "
                                    "missing; the image makes it at boot (D-154)" % n for n in names])

    def test_an_empty_run_lifts_only_the_keeper_s_run_paths(self):
        # #4392: below a unit's own empty tmpfs a keeper path is not in view, and systemd fails a mask of a
        # path missing there (226/NAMESPACE), so the decoder unit lifts the mask of the /run paths only.
        self.assertEqual(self.v(), [])
        dec = ini(UNITS / EMPTY_RUN)["Service"]
        self.assertEqual(dec["TemporaryFileSystem"], "/run:ro,noexec")
        lift = (MK / "mkosi.extra" / SYSTEM / EMPTY_RUN_DROPIN).read_text()
        self.assertIn("[Service]\nInaccessiblePaths=\nInaccessiblePaths=%s\n" % " ".join(
            p for p in check.KEEPER_PATHS if not p.startswith("/run/")), lift)
        run = [p for p in check.KEEPER_PATHS if p.startswith("/run/")]
        self.assertTrue(run)
        lacks = ["%s: InaccessiblePaths does not hold %s; the main side never sees the keeper's state (D-154)"
                 % (EMPTY_RUN, p) for p in run]
        good = self.unit(EMPTY_RUN).read_text()
        for line, why in (("", "no empty /run"), ("TemporaryFileSystem=/run/agentos", "a tmpfs beside the paths"),
                          ("TemporaryFileSystem=/run/%i", "a specifier"), ("TemporaryFileSystem=/run/x/../..", "a .. step"),
                          ("TemporaryFileSystem=/", "an empty root, not a driver's")):
            with self.subTest(why):
                self.edit(EMPTY_RUN, "TemporaryFileSystem=/run:ro,noexec\n", line + "\n" if line else "")
                got = self.v()
                self.unit(EMPTY_RUN).write_text(good)
                self.assertEqual([l for l in got if l in lacks], lacks)
        # Another entry at /run would be kept in the tmpfs's place (root_mounts).
        for line in ("ReadOnlyPaths=/run", "ReadWritePaths=-/run/", "BindReadOnlyPaths=/srv:/run",
                     "TemporaryFileSystem=/run"):
            with self.subTest(line):
                self.add(EMPTY_RUN, "Service", line)
                got = self.v()
                self.unit(EMPTY_RUN).write_text(good)
                self.assertEqual(got, lacks)
        # The rest of the mask still holds.
        self.edit(EMPTY_RUN_DROPIN, " /var/lib/agentos-camera", "")
        self.assertEqual(self.v(), ["%s: InaccessiblePaths does not hold /var/lib/agentos-camera; the main side never "
                                    "sees the keeper's state (D-154)" % EMPTY_RUN])

    def test_the_mor_clear_sees_what_it_lists(self):
        # HW-8 (L3 on #5009): masked, /run/agentos-setup reads as empty, and agentos-mor would clear
        # MOR while it holds the card's factors. The rest of the keeper's state stays masked, "-" allowed.
        mor = "agentos-mor.service.d/50-main-side.conf"
        hidden = ini(UNITS / mor)["Service"]["InaccessiblePaths"].split()
        self.assertEqual([w.lstrip("-") for w in hidden], [p for p in check.KEEPER_PATHS if p not in check.MOR_LISTED])
        self.assertNotIn("Unit", ini(UNITS / mor))
        self.edit(mor, "-/var/lib/agentos-homekit", "-/var/lib/agentos-homekit /run/agentos-setup")
        self.assertEqual(self.v(), ["agentos-mor.service: InaccessiblePaths holds /run/agentos-setup, which the MOR "
                                    "clear lists; masked, it reads as empty (HW-8)"])
        self.edit(mor, "-/var/lib/agentos-homekit /run/agentos-setup", "-/var/lib/agentos-homekit /run")
        self.assertEqual(len(self.v()), 2, self.v())
        self.edit(mor, " -/var/lib/agentos-homekit /run\n", "\n")
        self.assertEqual(self.v(), ["agentos-mor.service: InaccessiblePaths does not hold /var/lib/agentos-homekit; "
                                    "the main side never sees the keeper's state (D-154)"])
        # Without its own file, the shared mask hides what it lists.
        (self.root / SYSTEM / mor).unlink()
        self.assertEqual(len(self.v()), len(check.MOR_LISTED), self.v())

    def test_the_setup_factors_are_masked_and_removed(self):
        # #2981 (Security 2): the Owner Card's factors are hidden from the main side, and enrollment
        # removes them once it has made the store.
        e = exec_args(ENROLL)
        factors = [arg(e, "passphrase-file"), arg(e, "recovery-file")]
        self.assertEqual({f.rsplit("/", 1)[0] for f in factors}, {"/run/agentos-setup"})
        self.assertIn("/run/agentos-setup", check.KEEPER_PATHS)
        # The staged page authority and its published certificate go with them (OWN-card-flow).
        self.assertEqual(ini(ENROLL)["Service"]["ExecStartPost"].replace("\\\n", " ").split(),
                         ["/usr/bin/rm", "-f"] + factors + [arg(e, "page-ca-file"), arg(e, "page-ca-cert")])

    def test_permissions_start_only_is_refused(self):
        # #2981 (Security 3): it runs every command but ExecStart= with full privileges, as "+" does.
        self.add("agentos-boot-report.service", "Service", "PermissionsStartOnly=yes")
        self.assertEqual(self.v(), ["agentos-boot-report.service: PermissionsStartOnly=yes runs commands with full "
                                    "privileges, outside its device policy and namespace (STO-2c)"])

    def test_what_the_manager_opens_from_the_keeper_s_state_is_refused(self):
        # #2981 (L3 1): a file the service manager opens as root and hands to the unit, a directory it
        # makes and chowns for it, or a bind from above the keeper's state made before the mask.
        reach = ("OpenFile=/var/lib/agentos-kernel/log:log:append", "LoadCredential=x:/var/lib/agentos-store/store",
                 "LoadCredentialEncrypted=x:/var/lib/agentos-store", "EnvironmentFile=-/var/lib/agentos-kernel/env",
                 "StandardInput=file:/var/lib/agentos-store/store", "StandardOutput=file:/var/lib/agentos-kernel/log",
                 "StandardOutput=append:/run/agentos-setup/passphrase", "StandardError=truncate:/var/lib/agentos-kernel/x",
                 "TTYPath=/var/lib/agentos-store/store", "StateDirectory=agentos-store",
                 "StateDirectory=agentos x:agentos-kernel", "RuntimeDirectory=agentos-setup",
                 "BindReadOnlyPaths=/var/lib:/srv/vl", "BindReadOnlyPaths=/:/srv/r", "BindPaths=-/run:/srv/run",
                 "OpenFile=/var/lib", "StateDirectory=.")
        for line in reach:
            with self.subTest(line):
                d = write(self.root, SYSTEM + "agentos-boot-report.service.d/99-probe.conf", "[Service]\n%s\n" % line)
                key, val = line.split("=", 1)
                want = "agentos-boot-report.service: %s=%s reaches the keeper's state (D-154)" % (key, val)
                if key.endswith("Directory"):
                    want = "agentos-boot-report.service: %s=%s reaches the keeper's state (D-154)" % (
                        key, [w for w in val.split() if w != "agentos"][0])
                # #5167: a probe's StateDirectory=agentos also makes /var/lib/agentos a unit-made directory for
                # every unit, so agentos-modem.service's bind through it is refused too; only the probe's own
                # lines are compared here.
                self.assertEqual([l for l in self.v() if l.startswith("agentos-boot-report.service:")], [want])
                self.assertIn(want, check.violations(self.root))
                d.unlink()
        for line in ("LoadCredential=x:%S/agentos-store/store", "EnvironmentFile=/var/lib/%i"):
            with self.subTest(line):
                d = write(self.root, SYSTEM + "agentos-boot-report.service.d/99-probe.conf", "[Service]\n%s\n" % line)
                self.assertEqual(self.v(), ["agentos-boot-report.service: %s: the tree check does not model it (D-154)" % line])
                d.unlink()
        for line in ("LoadCredential=x", "LoadCredential=x:x.cred", "OpenFile=/etc/hostname", "StandardOutput=journal",
                     "BindReadOnlyPaths=/var/lib/agentos:/srv/a", "StateDirectory=agentos", "RuntimeDirectory=agentos-x",
                     "StandardInput=file:/var/lib/agentos/in"):
            with self.subTest(line):
                d = write(self.root, SYSTEM + "agentos-boot-report.service.d/99-probe.conf", "[Service]\n%s\n" % line)
                self.assertEqual([l for l in self.v() if l.startswith("agentos-boot-report.service:")], [])
                d.unlink()

    # REQ: HW-1, STO-2
    def test_a_keeper_path_unit_starts_only_the_keeper_from_its_state(self):
        """OWN-card-flow decision 6: an agentos-keeper .path unit names only a keeper unit and watches only
        the keeper's state."""
        good = self.unit("agentos-keeper-enroll.path").read_text()
        for old, new, want in (
                ("Unit=agentos-keeper-enroll.service", "Unit=agentos-localui.service",
                 "starts agentos-localui.service, not one of the keeper's units (D-154)"),
                ("Unit=agentos-keeper-enroll.service\n", "",
                 "starts agentos-keeper-enroll.service, not one of the keeper's units (D-154)"),
                ("PathExists=/run/agentos-setup/recovery", "PathExists=/run/agentos-page-ca/authority.der",
                 "PathExists=/run/agentos-page-ca/authority.der is outside the keeper's state (D-154)"),
                ("PathExists=/run/agentos-setup/recovery", "PathChanged=/run/agentos-setup/../agentos-x",
                 "PathChanged=/run/agentos-setup/../agentos-x is outside the keeper's state (D-154)"),
                ("PathExists=/run/agentos-setup/recovery", "DirectoryNotEmpty=/run/agentos-setupx",
                 "DirectoryNotEmpty=/run/agentos-setupx is outside the keeper's state (D-154)"),
                ("PathExists=/run/agentos-setup/recovery", "PathExists=/run/agentos-setup/%I",
                 "PathExists=/run/agentos-setup/%I is outside the keeper's state (D-154)"),
                ("PathExists=/run/agentos-setup/recovery\n", "", "watches nothing the tree check reads (D-154)")):
            with self.subTest(new):
                self.edit("agentos-keeper-enroll.path", old, new)
                name = "agentos-keeper-enroll.path"
                if not new.startswith("Unit") and old.startswith("Unit"):
                    # With no Unit=, the path starts its own name's service, which is the enrollment's:
                    # rename it so that default is not a keeper unit.
                    self.unit(name).rename(self.unit("agentos-keeper-other.path"))
                    name = "agentos-keeper-other.path"
                    want = want.replace("agentos-keeper-enroll.service", "agentos-keeper-other.service")
                self.assertEqual(self.v(), ["%s: %s" % (name, want)])
                self.assertIn("%s: %s" % (name, want), check.violations(self.root))
                self.unit(name).unlink()
                self.unit("agentos-keeper-enroll.path").write_text(good)
        # A main-side .path is not the keeper's to check.
        write(self.root, SYSTEM + "agentos-x.path", "[Path]\nPathExists=/run/x\nUnit=agentos-localui.service\n")
        self.assertEqual(self.v(), [])

    def test_only_the_keeper_s_units_are_in_its_slice(self):
        self.add("agentos-localui.service", "Service", "Slice=agentos-keeper.slice")
        self.assertEqual(self.v(), ["agentos-localui.service: in agentos-keeper.slice but not one of the keeper's units (D-154)"])

    def test_a_run_limit_on_a_oneshot_is_refused(self):
        """#3477: systemd ignores RuntimeMaxSec= on a oneshot, so finalize refuses that vacuous bound."""
        self.add("agentos-keeper-rotate@.service", "Service", "RuntimeMaxSec=60")
        self.assertEqual(self.v(), ["agentos-keeper-rotate@.service: RuntimeMaxSec= has no effect on a Type=oneshot "
                                    "unit; bound it with TimeoutStartSec= (#3477)"])

    def test_an_unlisted_keeper_unit_is_refused(self):
        write(self.root, SYSTEM + "agentos-keeper-extra.service", self.unit("agentos-boot-report.service").read_text())
        v = self.v()
        self.assertEqual(v[0], "agentos-keeper-extra.service: an agentos-keeper unit not in KEEPER_UNITS; "
                               "the keeper group is listed in one place (D-154)")
        # The keeper's drop-in reaches it by name, so it is in the slice and unmasked: refused too.
        self.assertIn("agentos-keeper-extra.service: in agentos-keeper.slice but not one of the keeper's units (D-154)", v)

    def test_a_keeper_unit_outside_the_slice_is_refused(self):
        (self.root / SYSTEM / "agentos-keeper-.service.d/90-keeper.conf").unlink()
        v = self.v()
        for n in check.KEEPER_UNITS:
            self.assertIn("%s: Slice is None; the keeper's units run in agentos-keeper.slice (D-154)" % n, v)

    # The TPM device allowlist (#2889 Security later 2).

    def test_a_tpm_device_on_another_unit_is_refused(self):
        for spec in ("/dev/tpmrm0", "/dev/tpm0", "char-tpm", "char-tpmrm", "char-misc", "char-tpm*", "char-*",
                     "/dev/char/10:224"):
            with self.subTest(spec):
                good = self.unit("agentos-modem.service").read_text()
                self.add("agentos-modem.service", "Service", "DeviceAllow=%s rw" % spec)
                want = "agentos-modem.service: DeviceAllow=%s reaches the TPM; only %s may (#2889)" % (spec, ", ".join(check.TPM_UNITS))
                self.assertEqual(self.v(), [want])
                self.assertIn(want, check.violations(self.root))  # mkosi.finalize runs the check
                self.unit("agentos-modem.service").write_text(good)
        for spec in ("char-ttyUSB", "block-*", "/dev/mapper/control"):
            self.assertFalse(check.tpm_spec(spec), spec)

    def test_a_tpm_unit_opens_only_the_resource_manager(self):
        self.add("agentos-keeper-kernel.service", "Service", "DeviceAllow=/dev/tpm0 rw")
        self.assertEqual(self.v(), ["agentos-keeper-kernel.service: DeviceAllow=/dev/tpm0; a TPM unit opens only "
                                    "/dev/tpmrm0 (#2889)"])

    def test_a_tpm_unit_keeps_a_closed_device_policy(self):
        self.add("agentos-keeper-enroll.service", "Service", "DevicePolicy=auto")
        self.edit("agentos-keeper-enroll.service", "DevicePolicy=closed\n", "")
        self.assertEqual(self.v(), ["agentos-keeper-enroll.service: DevicePolicy is auto; a TPM unit sets closed or strict (#2889)"])

    def test_every_other_unit_has_a_closed_device_policy(self):
        for name in ("agentos-boot-report.service", "agentos-health.service", "agentos-drive-id.service"):
            with self.subTest(name):
                good = self.unit(name).read_text()
                self.edit(name, "DevicePolicy=closed\n", "")
                self.assertEqual(self.v(), ["%s: neither PrivateDevices=yes nor DevicePolicy=closed; only %s may reach "
                                            "the TPM (#2889)" % (name, ", ".join(check.TPM_UNITS))])
                self.add(name, "Service", "PrivateDevices=yes")
                self.assertEqual(self.v(), [])
                self.unit(name).write_text(good)
        # The old core's broker is frozen (D-139, #917), as for UPD-10.
        self.assertNotIn("DevicePolicy", self.unit("agentosd.service").read_text())

    def test_no_unit_or_user_is_in_a_tpm_group(self):
        for key in ("SupplementaryGroups=tss", "Group=agentos-egress", "User=agentos-egress"):
            with self.subTest(key):
                d = write(self.root, SYSTEM + "agentos-modem.service.d/99-x.conf", "[Service]\n%s\n" % key)
                self.assertEqual(self.v(), ["agentos-modem.service: %s can open the TPM (#2889)" % key])
                d.unlink()
        sysusers = self.root / "usr/lib/sysusers.d/agentos-setup.conf"
        good = sysusers.read_text()
        for line, want in (("m agentos-kernel tss", "puts agentos-kernel in tss"),
                           ("m agentos-localui agentos-egress", "puts agentos-localui in agentos-egress"),
                           ("u agentos-x -:tss", "gives agentos-x the group tss")):
            with self.subTest(line):
                sysusers.write_text(good + line + "\n")
                n = len(good.splitlines()) + 1
                self.assertEqual(self.v(), ["usr/lib/sysusers.d/agentos-setup.conf:%d: %s, which can open the TPM (#2889)"
                                            % (n, want)])
        sysusers.write_text(good)
        # The resource manager's group is the vault process's (udev), and is listed.
        rules = (MK / "mkosi.extra/usr/lib/udev/rules.d/60-agentos-tpm.rules").read_text()
        self.assertIn('GROUP="agentos-egress"', rules)

    def test_a_full_privilege_command_is_refused(self):
        self.add("agentos-boot-report.service", "Service", "ExecStartPre=+/usr/bin/true")
        self.assertEqual(self.v(), ["agentos-boot-report.service: ExecStartPre=+/usr/bin/true runs with full privileges, "
                                    "outside its device policy and namespace (STO-2c)"])
        self.assertEqual(check.FULL_PRIVILEGE_EXEMPT, ("agentos-egress.service",))
        # HW12-port1-set: the page's unit runs exactly its two firewall commands as root, and nothing else;
        # so does the edge link's (EDGE-link-core c2c).
        self.assertEqual([(u, k) for u, k, _ in check.FULL_PRIVILEGE_COMMANDS],
                         [("agentos-localui.service", "ExecStartPre"), ("agentos-localui.service", "ExecStopPost"),
                          ("agentos-link.service", "ExecStartPre"), ("agentos-link.service", "ExecStopPost"),
                          ("agentos-keeper-link-capture.service", "ExecStartPre"),
                          ("agentos-keeper-link-capture.service", "ExecStopPost")])
        self.add("agentos-localui.service", "Service", "ExecStartPost=+/usr/bin/true")
        self.assertIn("agentos-localui.service: ExecStartPost=+/usr/bin/true runs with full privileges, "
                      "outside its device policy and namespace (STO-2c)", self.v())
        self.edit("agentos-localui.service", "+/usr/sbin/nft flush set inet agentos_inbound page",
                  "+/usr/sbin/nft flush ruleset")
        self.assertIn("agentos-localui.service: ExecStopPost=+/usr/sbin/nft runs with full privileges, "
                      "outside its device policy and namespace (STO-2c)", self.v())

    # #2899: the unlock unit.

    def test_the_unlock_unit_gets_no_descriptor_past_2(self):
        for line in ("OpenFile=/etc/hostname", "Sockets=agentos-x.socket", "FileDescriptorStoreMax=1",
                     "AmbientCapabilities=CAP_SYS_ADMIN", "SecureBits=keep-caps"):
            with self.subTest(line):
                good = self.unit("agentos-keeper-kernel.service").read_text()
                self.add("agentos-keeper-kernel.service", "Service", line)
                key, val = line.split("=", 1)
                self.assertEqual(self.v(), [unlock_refusal(key, val, check.UNLOCK_DESCRIPTOR)])
                self.unit("agentos-keeper-kernel.service").write_text(good)

    def test_a_later_empty_assignment_does_not_hide_a_descriptor(self):
        # #4306: systemd 257.13 never resets Sockets= and keeps the earlier FileDescriptorStoreMax= past an
        # empty one, so the check reads every non-empty assignment, in the unit or a drop-in.
        for key, val in (("Sockets", "a.socket"), ("FileDescriptorStoreMax", "4"), ("OpenFile", "/etc/hostname"),
                         ("AmbientCapabilities", "CAP_SYS_ADMIN"), ("SecureBits", "keep-caps")):
            with self.subTest(key):
                d = write(self.root, SYSTEM + "agentos-keeper-kernel.service.d/99.conf",
                          "[Service]\n%s=%s\n%s=\n" % (key, val, key))
                self.assertEqual(self.v(), [unlock_refusal(key, val, check.UNLOCK_DESCRIPTOR,
                                                           SYSTEM + "agentos-keeper-kernel.service.d/99.conf")])
                d.unlink()
        self.assertEqual(self.v(), [])

    # #4644: one closed list of what the unlock unit may assign to each key that could hand it a descriptor
    # or a privilege, or start a unit or a reboot when it stops; no empty or later assignment hides a value.
    UNLOCK_BAD = (("Service", "Sockets", "a.socket"), ("Service", "OpenFile", "/etc/hostname"),
                  ("Service", "FileDescriptorStoreMax", "4"), ("Service", "AmbientCapabilities", "CAP_SYS_ADMIN"),
                  ("Service", "SecureBits", "keep-caps"), ("Unit", "StartLimitAction", "reboot"),
                  ("Unit", "FailureAction", "reboot-force"), ("Service", "StartLimitAction", "reboot"),
                  ("Service", "FailureAction", "reboot-force"), ("Unit", "SuccessAction", "reboot"),
                  ("Unit", "JobTimeoutAction", "reboot-force"), ("Unit", "OnFailure", "reboot.target"),
                  ("Unit", "OnSuccess", "reboot.target"))

    def test_the_unlock_unit_assignments_are_one_closed_list(self):
        self.assertEqual(sorted((s, k, a) for s, k, a, _ in check.UNLOCK_ASSIGNMENTS),
                         sorted((s, k, {"FileDescriptorStoreMax": ("0",)}.get(k, ("none",) if k.endswith("Action") else ()))
                                for s, k, _ in self.UNLOCK_BAD))
        self.assertEqual({w for *_, w in check.UNLOCK_ASSIGNMENTS},
                         {check.UNLOCK_DESCRIPTOR, check.UNLOCK_ACTION, check.UNLOCK_START})

    def test_no_later_assignment_hides_an_unlock_unit_value(self):
        # The value in the unit, then an empty or another assignment in a later drop-in; or both in one drop-in.
        # Dependencies such as OnFailure= never reset; for the rest the check does not rest on how they do.
        name = "agentos-keeper-kernel.service"
        rule = {(s, k): (a, w) for s, k, a, w in check.UNLOCK_ASSIGNMENTS}
        for section, key, val in self.UNLOCK_BAD:
            allowed, why = rule[section, key]
            want = [unlock_refusal(key, val, why)]
            for later in ("", "none", "0"):
                with self.subTest(section=section, key=key, later=later, form="unit then drop-in"):
                    good = self.unit(name).read_text()
                    self.add(name, section, "%s=%s" % (key, val))
                    d = write(self.root, SYSTEM + name + ".d/99.conf", "[%s]\n%s=%s\n" % (section, key, later))
                    # The later value is checked too: only an empty one or one on the key's list adds nothing.
                    extra = [] if later == "" or later in allowed else [
                        unlock_refusal(key, later, why, SYSTEM + name + ".d/99.conf")]
                    self.assertEqual(self.v(), want + extra)
                    d.unlink()
                    self.unit(name).write_text(good)
            with self.subTest(section=section, key=key, form="one drop-in"):
                d = write(self.root, SYSTEM + name + ".d/99.conf", "[%s]\n%s=%s\n%s=\n" % (section, key, val, key))
                self.assertEqual(self.v(), [unlock_refusal(key, val, why, SYSTEM + name + ".d/99.conf")])
                d.unlink()
        self.assertEqual(self.v(), [])

    def test_only_the_exact_listed_value_passes(self):
        # Another case or spelling of a listed value is refused, whatever systemd would make of it.
        name = "agentos-keeper-kernel.service"
        for section, key, val, why in (("Unit", "FailureAction", "None", check.UNLOCK_ACTION),
                                       ("Service", "FailureAction", "NONE", check.UNLOCK_ACTION),
                                       ("Service", "FileDescriptorStoreMax", "00", check.UNLOCK_DESCRIPTOR)):
            with self.subTest(section=section, key=key, val=val):
                d = write(self.root, SYSTEM + name + ".d/99.conf", "[%s]\n%s=%s\n" % (section, key, val))
                self.assertEqual(self.v(), [unlock_refusal(key, val, why, SYSTEM + name + ".d/99.conf")])
                d.unlink()

    def test_the_listed_values_pass(self):
        # FileDescriptorStoreMax=0 keeps no descriptor; an action of none reboots nothing.
        name = "agentos-keeper-kernel.service"
        for section, key, allowed, _ in check.UNLOCK_ASSIGNMENTS:
            for val in allowed:
                with self.subTest(section=section, key=key, val=val):
                    good = self.unit(name).read_text()
                    self.add(name, section, "%s=%s" % (key, val))
                    d = write(self.root, SYSTEM + name + ".d/99.conf", "[%s]\n%s=%s\n" % (section, key, val))
                    self.assertEqual(self.v(), [])
                    d.unlink()
                    self.unit(name).write_text(good)

    def test_a_socket_unit_for_the_unlock_step_is_refused(self):
        write(self.root, SYSTEM + "agentos-keeper-kernel.socket", "[Socket]\nListenStream=/run/x.sock\n")
        write(self.root, SYSTEM + "other.socket", "[Socket]\nListenStream=/run/y.sock\nService=agentos-keeper-kernel.service\n")
        self.assertEqual(self.v(), [
            "agentos-keeper-kernel.socket: starts agentos-keeper-kernel.service with its sockets; nothing reaches the "
            "unlock step past descriptor 2 (#2899)",
            "other.socket: starts agentos-keeper-kernel.service with its sockets; nothing reaches the unlock step past "
            "descriptor 2 (#2899)"])

    def test_the_unlock_unit_sets_no_new_privileges(self):
        self.edit("agentos-keeper-kernel.service", "NoNewPrivileges=yes\n", "")
        self.assertEqual(self.v(), ["agentos-keeper-kernel.service: NoNewPrivileges is not yes (#2899)"])

    # #2897: the unit that opens the counter anchor.

    def test_the_unlock_unit_bounds_its_restarts(self):
        u = ini(KERNEL)
        self.assertEqual(u["Unit"]["StartLimitBurst"], "3")
        self.assertEqual(u["Unit"]["StartLimitIntervalSec"], "infinity")
        self.assertEqual(u["Service"]["Restart"], "on-failure")
        cases = (("StartLimitBurst=3\n", "", "StartLimitBurst is None; must be 1 to 5, so a crash loop cannot wear the TPM counter (#2897)"),
                 ("StartLimitBurst=3\n", "StartLimitBurst=100\n", "StartLimitBurst is 100; must be 1 to 5, so a crash loop cannot wear the TPM counter (#2897)"),
                 ("StartLimitIntervalSec=infinity\n", "", "StartLimitIntervalSec is None; a zero or unset interval does not bound restarts (#2897)"),
                 ("StartLimitIntervalSec=infinity\n", "StartLimitIntervalSec=0\n", "StartLimitIntervalSec is 0; a zero or unset interval does not bound restarts (#2897)"),
                 ("StartLimitIntervalSec=infinity\n", "StartLimitIntervalSec=0s\n", "StartLimitIntervalSec is 0s; a zero or unset interval does not bound restarts (#2897)"),
                 ("StartLimitBurst=3\n", "StartLimitBurst=3\nStartLimitAction=reboot\n", unlock_refusal("StartLimitAction", "reboot", check.UNLOCK_ACTION)[len("agentos-keeper-kernel.service: "):]),
                 ("StartLimitBurst=3\n", "StartLimitBurst=3\nFailureAction=reboot-force\n", unlock_refusal("FailureAction", "reboot-force", check.UNLOCK_ACTION)[len("agentos-keeper-kernel.service: "):]),
                 ("StartLimitBurst=3\n", "StartLimitBurst=3\nSuccessAction=reboot\n", unlock_refusal("SuccessAction", "reboot", check.UNLOCK_ACTION)[len("agentos-keeper-kernel.service: "):]),
                 ("StartLimitBurst=3\n", "StartLimitBurst=3\nJobTimeoutAction=reboot-force\n", unlock_refusal("JobTimeoutAction", "reboot-force", check.UNLOCK_ACTION)[len("agentos-keeper-kernel.service: "):]),
                 ("[Service]\n", "[Service]\nStartLimitBurst=100\n", "a start limit outside [Unit]'s StartLimitBurst= and StartLimitIntervalSec=; the tree check does not model it (#2897)"))
        for old, new, want in cases:
            with self.subTest(new or old):
                good = self.unit("agentos-keeper-kernel.service").read_text()
                self.edit("agentos-keeper-kernel.service", old, new)
                self.assertEqual(self.v(), ["agentos-keeper-kernel.service: " + want])
                self.unit("agentos-keeper-kernel.service").write_text(good)

    # #2998: after the unlock cap (#2977) no restart in the same boot unlocks, so a kernel that came up
    # and then failed reboots the box, at most twice an hour; one refused at its start does not.

    def test_a_kernel_that_came_up_and_failed_reboots_the_box(self):
        k = exec_args(KERNEL)
        kern = k[k.index("--") + 1:]
        u = ini(KERNEL)
        self.assertEqual(arg(kern, "up"), "/run/agentos-kernel/up")
        self.assertIn(arg(kern, "up"), check.KERNEL_REBOOT)
        self.assertEqual(u["Service"]["ExecStopPost"], check.KERNEL_REBOOT)
        self.assertEqual(u["Service"]["Restart"], "on-failure")
        # /run/agentos-kernel outlives a stop (#3073), so each start removes the last start's "up" first.
        self.assertEqual(check.KERNEL_UP_CLEAR, "/usr/bin/rm -f " + arg(kern, "up"))
        self.assertIn(check.KERNEL_UP_CLEAR, exec_lines(KERNEL, "ExecStartPre"))

    def test_the_reboot_follows_only_a_kernel_that_came_up(self):
        # The command as systemd runs it ($$ is one $), with the "up" file and systemd-run moved into a
        # temporary directory: it asks for the boot-timed reboot only after a failure of a kernel that
        # made "up".
        argv = shlex.split(check.KERNEL_REBOOT.replace("$$", "$"))
        with tempfile.TemporaryDirectory() as d:
            d = pathlib.Path(d)
            run, calls = d / "systemd-run", d / "calls"
            write(d, "systemd-run", '#!/bin/sh\necho "$*" >> %s\n' % calls, 0o755)
            script = argv[2].replace("/run/agentos-kernel/up", str(d / "up")).replace("/usr/bin/systemd-run", str(run))
            for result, up, want in (("success", True, False), ("exit-code", True, True), ("signal", True, True),
                                     ("core-dump", True, True), ("exit-code", False, False), ("signal", False, False)):
                with self.subTest(result=result, up=up):
                    (d / "up").unlink(missing_ok=True)
                    calls.unlink(missing_ok=True)
                    if up:
                        (d / "up").touch()
                    subprocess.run([argv[0], argv[1], script], env={"SERVICE_RESULT": result}, check=True)
                    got = calls.read_text() if calls.exists() else ""
                    self.assertEqual(got, "--on-boot=30min --unit=agentos-kernel-reboot /usr/bin/systemctl reboot\n" if want else "")

    def test_any_other_reboot_of_the_unlock_unit_is_refused(self):
        name = "agentos-keeper-kernel.service"
        stop = "ExecStopPost=" + check.KERNEL_REBOOT + "\n"
        guard = "if [ \"$$SERVICE_RESULT\" != success ] && [ -e /run/agentos-kernel/up ]; then "
        why = "can reboot the box; its one reboot is ExecStopPost=KERNEL_REBOOT, after a kernel that came up and no " \
              "sooner than 30 minutes into the boot (#2897, #2998)"
        cases = ((stop, stop.replace(guard, "if true; then "), "ExecStopPost=/usr/bin/sh " + why),
                 (stop, stop.replace("--on-boot=30min", "--on-boot=1s"), "ExecStopPost=/usr/bin/sh " + why),
                 (stop, stop.replace("ExecStopPost=", "ExecStopPost=-"), "ExecStopPost=-/usr/bin/sh " + why),
                 (stop, stop + "ExecStopPost=/usr/bin/systemctl reboot\n", "ExecStopPost=/usr/bin/systemctl " + why),
                 ("[Service]\n", "[Service]\nExecStartPre=/usr/bin/systemd-run --on-active=1 /usr/bin/true\n",
                  "ExecStartPre=/usr/bin/systemd-run " + why),
                 ("[Unit]\n", "[Unit]\nOnFailure=reboot.target\n",
                  unlock_refusal("OnFailure", "reboot.target", check.UNLOCK_START)[len(name + ": "):]))
        for old, new, want in cases:
            with self.subTest(new):
                good = self.unit(name).read_text()
                self.edit(name, old, new)
                self.assertEqual(self.v(), [name + ": " + want])
                self.unit(name).write_text(good)
        # Without the line the kernel stays down after the cap, as before #2998, which the check allows.
        self.edit(name, stop, "")
        self.assertEqual(self.v(), [])

    def test_the_reboot_needs_each_start_to_clear_the_last_up(self):
        # #3073 keeps /run/agentos-kernel across a stop: without the removal, a start refused after a good
        # one finds that start's "up", and its ExecStopPost= asks for the reboot.
        name = "agentos-keeper-kernel.service"
        clear = "ExecStartPre=" + check.KERNEL_UP_CLEAR + "\n"
        why = ("no ExecStartPre=%s; a start refused after a good one would find the last start's \"up\" and "
               "reboot the box (#2897, #2998)" % check.KERNEL_UP_CLEAR)
        for new in ("", clear.replace("=", "=-", 1), clear.replace("/up", "/up.old")):
            with self.subTest(new):
                good = self.unit(name).read_text()
                self.edit(name, clear, new)
                self.assertEqual(self.v(), [name + ": " + why])
                self.unit(name).write_text(good)
        # Without the reboot line the file reboots nothing, so its removal is not required.
        good = self.unit(name).read_text()
        self.edit(name, clear, "")
        self.edit(name, "ExecStopPost=" + check.KERNEL_REBOOT + "\n", "")
        self.assertEqual(self.v(), [])
        self.unit(name).write_text(good)

    # UPD-10 (#2875) on the new units: noexec_violations covers every agentos unit.

    def test_the_keeper_s_units_run_nothing_from_writable_storage(self):
        for name in check.KEEPER_UNITS:
            with self.subTest(name):
                good = self.unit(name).read_text()
                self.edit(name, "NoExecPaths=/\n", "")
                self.assertEqual(check.noexec_violations(self.root),
                                 ["%s: NoExecPaths does not hold /; must be NoExecPaths=/ (UPD-10)" % name])
                self.unit(name).write_text(good)


class MadeAllowTest(unittest.TestCase):
    """#5167 re-plan 4: every unit-file and fstab line for which PID 1 makes, links or mounts a host path
    is on image/mkosi/made.allow. Rounds 1 to 3 refused the shapes of value known to reach a unit-made
    directory's way and each review found one more (the last: a bind of / that aliases the whole tree);
    the list fixes the set of such lines, so any new route fails the build until it is reviewed."""
    # REQ: STO-2
    setUp, unit, edit = KeeperTreeTest.setUp, KeeperTreeTest.unit, KeeperTreeTest.edit

    def refused(self):
        return check.made_allow_violations(self.root)

    def entry(self, rel, value):
        return "entry: %s\t%s" % (rel, value)

    def test_the_shipped_tree_passes_and_the_list_has_its_header(self):
        text = (MK / check.MADE_ALLOW).read_text()
        self.assertTrue(text.startswith(check.MADE_ALLOW_HEADER))
        self.assertEqual(self.refused(), [])
        got = set(check.made_entries(self.root))
        self.assertLessEqual(got, check.made_allowed())
        # The shipped units' own lines are there, and none of the list's lines is a read or a name.
        self.assertIn((SYSTEM + "agentos-keeper-rotate.socket", "[Socket] ListenStream=/run/agentos-keeper/rotate.sock"), got)
        self.assertIn(("usr/lib/systemd/system/tmp.mount", "[Mount] What=tmpfs"), check.made_allowed())
        for rel, value in check.made_allowed():
            key = value.split("] ", 1)[-1].split("=", 1)[0] if value.startswith("[") else None
            self.assertFalse(key in check.PID1_READS or key in check.PID1_NAMES, value)

    def test_a_mount_that_aliases_a_path_is_refused(self):
        # Security 6763789301 and L3 6763810610 (#5247): a bind of / joins its shared peer group, so a
        # bind below /srv/r lands on /var/lib/zq, and StateDirectory=zq's chown hands /etc over. Then the
        # same class: a bind of an ancestor, a subdirectory mount, and a bind with no '/' in any line.
        zq = ("zz.service", "[Service]\nStateDirectory=zq\nUser=nobody\n")
        cases = {
            "bind of / and a bind below it": [zq, ("srv-r.mount", "[Mount]\nWhat=/\nWhere=/srv/r\nOptions=bind,noexec\n"),
                                             ("srv-r-var-lib-zq.mount", "[Mount]\nWhat=/etc\nWhere=/srv/r/var/lib/zq\n"
                                              "Options=bind,noexec\n")],
            "bind of / and a socket link below it": [zq, ("srv-r.mount", "[Mount]\nWhat=/\nOptions=bind\n"),
                                                     ("zs.socket", "[Socket]\nListenStream=/run/zs\nSymlinks=/srv/r/var/lib/zq\n")],
            "bind of an ancestor": [zq, ("srv-v.mount", "[Mount]\nWhat=/var/lib\nWhere=/srv/v\nOptions=bind\n")],
            "a subdirectory mount": [zq, ("srv-s.mount", "[Mount]\nWhat=/dev/vda1\nWhere=/srv/s\n"
                                          "Options=X-mount.subdir=var/lib\n")],
            "a bind with no '/' in its lines": [("tmp.mount.d/x.conf", "[Mount]\nWhat=var\nOptions=bind\n")],
            "another root": [("zr.service", "[Service]\nRootDirectory=/srv/r\nMountImages=/srv/i.raw:/var/lib/zq\n")],
            "a directory": [("zd.service", "[Service]\nRuntimeDirectory=zd\n")],
        }
        for case, files in cases.items():
            with self.subTest(case=case):
                written = [write(self.root, SYSTEM + name, text) for name, text in files]
                got = self.refused()
                want = [(SYSTEM + name, v) for name, _ in files for v in
                        (("[%s] %s" % (sec, ln)) for sec, ln in self.lines(files, name))]
                self.assertTrue(want)
                for rel, value in want:
                    self.assertIn(self.entry(rel, value), " | ".join(got))
                self.assertIn("not on the PID 1 path allowlist", " | ".join(check.violations(self.root)))
                for f in written:
                    f.unlink()

    def lines(self, files, name):
        # The lines of NAME in FILES the list holds: every [Mount] line, else a '/' or a *Directory= setting.
        text = dict(files)[name]
        out = []
        for section, key, v in check.config_lines(text.encode()):
            if section == "Mount" or (key in check.UNIT_MADE_DIRS or "/" in v):
                out.append((section, "%s=%s" % (key, v)))
        return out

    def test_an_fstab_bind_is_refused(self):
        fstab = (MK / "mkosi.extra/etc/fstab").read_text()
        write(self.root, "etc/fstab", fstab + "/run /srv/r none bind 0 0\n# /x /y none bind 0 0\n")
        write(self.root, SYSTEM + "zq.socket", "[Socket]\nListenStream=/srv/r/zq\n")
        got = " | ".join(self.refused())
        self.assertIn(self.entry("etc/fstab", "/run /srv/r none bind 0 0"), got)
        self.assertIn(self.entry(SYSTEM + "zq.socket", "[Socket] ListenStream=/srv/r/zq"), got)
        self.assertNotIn("/x /y", got)

    def test_a_listed_line_counts_only_in_its_own_file_and_section(self):
        line = "ListenStream=/run/agentos-keeper/rotate.sock"
        write(self.root, SYSTEM + "zz.socket", "[Socket]\n%s\n" % line)
        self.edit("agentos-keeper-rotate.socket", "[Socket]\n", "[Service]\n%s\n[Socket]\n" % line)
        self.assertEqual(self.refused(), [
            "%s: %s: not on the PID 1 path allowlist (image/mkosi/made.allow, #5167); review the line (what PID 1 "
            "makes, links or mounts for it, and whether that can name or alias a step of a service directory's way), "
            "then add the entry after 'entry:' to that file (mkosi.finalize --made-allowlist ROOT only lists what a "
            "tree holds, it reviews nothing); %s" % (rel, value, self.entry(rel, value))
            for rel, value in ((SYSTEM + "agentos-keeper-rotate.socket", "[Service] " + line),
                               (SYSTEM + "zz.socket", "[Socket] " + line))])
        # An edited value is a new line too.
        self.edit("agentos-keeper-rotate.socket", "[Service]\n%s\n" % line, "")
        self.edit("agentos-keeper-rotate.socket", line, line + "2")
        self.assertIn(self.entry(SYSTEM + "agentos-keeper-rotate.socket", "[Socket] %s2" % line),
                      " | ".join(self.refused()))

    def test_reads_and_names_are_not_listed(self):
        write(self.root, SYSTEM + "zz.service", "[Unit]\nAfter=a/b.service\nConditionPathExists=/x\nRequiresMountsFor=/y\n"
              "[Service]\nInaccessiblePaths=/z\nExecStart=/usr/bin/true\nType=oneshot\n")
        self.assertEqual(self.refused(), [])

    def test_a_driver_s_units_are_listed_only_for_a_listed_driver(self):
        # DRIVER_TEMPLATE is the list for a driver's units; an unlisted name has none of its lines.
        units = check.driver_units("scale")
        for rel, text in units.items():
            write(self.root, rel, text)
        sock = ("usr/lib/systemd/system/agentos-driver-scale.socket", "[Socket] ListenStream=/run/agentos-drivers/scale.sock")
        self.assertIn(self.entry(*sock), " | ".join(self.refused()))
        self.assertNotIn(sock, check.made_allowed())
        with unittest.mock.patch.object(check, "driver_entries", return_value=([{"name": "scale"}], [])):
            self.assertEqual(self.refused(), [])

    def test_a_manager_environment_is_refused(self):
        # Security 6766645273 (#5270): ManagerEnvironment=SYSTEMD_UNIT_PATH moves PID 1's unit search to a
        # directory the check never walks, so an ancestor bind and a unit-made directory there passed.
        write(self.root, "usr/share/zz/srv-v.mount", "[Mount]\nWhat=/var/lib\nWhere=/srv/v\nOptions=bind\n")
        write(self.root, "usr/share/zz/zz.service", "[Service]\nStateDirectory=zq\nUser=nobody\n")
        for rel in ("usr/lib/systemd/system.conf.d/60-zz.conf", "etc/systemd/system.conf"):
            for text in ("[Manager]\nManagerEnvironment=SYSTEMD_UNIT_PATH=/usr/share/zz:\n",
                         "[Manager]\nManagerEnvironment=A=1\n", "[X]\nManagerEnvironment=A=1\n"):
                with self.subTest(rel=rel, text=text):
                    f = write(self.root, rel, text)
                    want = ("%s: sets ManagerEnvironment=, which PID 1 applies to itself (SYSTEMD_UNIT_PATH moves "
                            "where it loads units from); the tree check never passes one (#5167)" % rel)
                    self.assertEqual(check.manager_environment_violations(self.root), [want])
                    self.assertIn(want, check.violations(self.root))
                    f.unlink()
        write(self.root, "usr/lib/systemd/system.conf.d/60-zz.conf", "[Manager]\nDefaultEnvironment=A=1\n")
        self.assertEqual(check.manager_environment_violations(self.root), [])
        write(self.root, "usr/lib/systemd/system.conf.d/60-zz.conf", "[Manager]\nA=\0\n")
        self.assertIn("unreadable", " ".join(check.manager_environment_violations(self.root)))

    def test_regenerate_and_missing(self):
        write(self.root, SYSTEM + "zz.socket", "[Socket]\nListenStream=/run/zz\n")
        text = check.made_allowlist_text(self.root)
        self.assertTrue(text.startswith(check.MADE_ALLOW_HEADER))
        with tempfile.TemporaryDirectory() as tmp:
            p = pathlib.Path(tmp) / check.MADE_ALLOW
            p.write_text(text)
            allowed = check.made_allowed(str(p))
            self.assertEqual(allowed, set(check.made_entries(self.root)))
            self.assertEqual(check.made_allow_violations(self.root, allowed), [])
            out = io.StringIO()
            with unittest.mock.patch.object(sys, "argv", ["mkosi.finalize", "--made-allowlist", str(self.root)]), \
                    contextlib.redirect_stdout(out):
                check.main()
            self.assertEqual(out.getvalue(), text)
        with unittest.mock.patch.object(check, "made_allowed", return_value=None):
            self.assertEqual(check.made_allow_violations(self.root),
                             ["made.allow: missing; every unit-file and fstab line for which PID 1 makes, links or "
                              "mounts a host path must be on it (#5167)"])


class KeeperUnitsTest(unittest.TestCase):
    """The keeper's unit files against the mains they run."""

    def test_the_units_agree_with_each_other_and_the_mains(self):
        e, k = exec_args(ENROLL), exec_args(KERNEL)
        self.assertEqual(e[0], "/usr/lib/agentos/agentos-enroll")
        self.assertEqual(k[0], "/usr/lib/agentos/agentos-unlock")
        i = k.index("--")
        unlock, kern = k[1:i], k[i + 1:]
        self.assertEqual(arg(unlock, "exec"), "/usr/lib/agentos/agentos-kernel")
        self.assertEqual(arg(unlock, "store"), arg(e, "state") + "/store")
        self.assertEqual(arg(kern, "anchor-dir"), arg(e, "anchor-dir"))
        self.assertEqual(arg(kern, "log"), arg(e, "log"))
        self.assertEqual((arg(unlock, "uid"), arg(unlock, "gid")), ("@uid:agentos-kernel", "@gid:agentos-kernel"))
        self.assertEqual((arg(e, "kernel-uid"), arg(e, "kernel-gid")), ("@uid:agentos-kernel", "@gid:agentos-kernel"))
        # Every flag the units pass is one the main defines.
        for cmd, words in (("agentos-enroll", e[1:]), ("agentos-unlock", unlock), ("agentos-kernel", kern)):
            flags = go_flags(cmd)
            for w in words:
                if w.startswith("-"):
                    self.assertIn(w[1:], flags, "%s %s" % (cmd, w))
        # The store's path is the conditions'.
        store = arg(unlock, "store")
        conds = re.findall(r"^ConditionPathExists=(.*)$", ENROLL.read_text(), re.M)
        self.assertEqual(conds, ["!" + store, arg(e, "passphrase-file"), arg(e, "recovery-file"), arg(e, "page-ca-file")])
        self.assertEqual(re.findall(r"^ConditionPathExists=(.*)$", KERNEL.read_text(), re.M), [store])
        # Enrollment comes first, and makes the kernel's state directory for the kernel's user.
        self.assertIn("agentos-keeper-enroll.service", ini(KERNEL)["Unit"]["After"].split())
        self.assertIn("-o agentos-kernel -g agentos-kernel /var/lib/agentos-kernel", ini(ENROLL)["Service"]["ExecStartPre"])
        self.assertEqual(sorted(check.KEEPER_PATHS), sorted({arg(e, "state"), arg(e, "log").rsplit("/", 1)[0],
                                                             arg(e, "passphrase-file").rsplit("/", 1)[0],
                                                             arg(exec_args(MAIL), "dir"),
                                                         arg(exec_args(UNITS / "agentos-keeper-camera.service"), "dir"),
                                                         arg(exec_args(UNITS / "agentos-keeper-homekit.service"), "dir"),
                                                             arg(e, "first-edge").rsplit("/", 1)[0]}))

    def test_the_kernel_owns_its_socket_directory_when_it_binds(self):
        # #3073: systemd chowns a RuntimeDirectory= to the unit's user, root here, at every command's
        # spawn, so a chown in ExecStartPre= is undone before ExecStart and the kernel cannot bind.
        k = exec_args(KERNEL)
        kern = k[k.index("--") + 1:]
        run = {arg(kern, "owner-sock").rsplit("/", 1)[0], arg(kern, "meter-sock").rsplit("/", 1)[0]}
        self.assertEqual(run, {"/run/agentos-kernel"})
        s = ini(KERNEL)["Service"]
        self.assertNotIn("RuntimeDirectory", s)
        self.assertNotIn("User", s)
        self.assertEqual(exec_lines(KERNEL, "ExecStartPre"),
                         ["/usr/bin/install -d -m 0711 -o agentos-kernel -g agentos-kernel /run/agentos-kernel",
                          check.KERNEL_UP_CLEAR])

    def test_the_users_exist_and_none_is_in_a_tpm_group(self):
        lines = [l.split() for l in SYSUSERS.read_text().splitlines() if l.strip() and not l.startswith("#")]
        users = {w[1] for w in lines if w[0] == "u"}
        for unit in (ENROLL, KERNEL, MAIL):
            for w in exec_args(unit):
                if "@uid:" in w or w.startswith("@gid:"):
                    self.assertIn(w.split("@", 1)[1][4:], users)
        self.assertFalse([w for w in lines if w[0] == "m"])

    def test_with_uids_swaps_group_names_for_gids(self):
        out = subprocess.run([str(WITH_UIDS), "echo", "@gid:root", "@uid:root", "x@gid:root"],
                             capture_output=True, text=True, check=True)
        self.assertEqual(out.stdout, "0 0 x@gid:root\n")
        bad = subprocess.run([str(WITH_UIDS), "echo", "@gid:agentos-no-such-user"], capture_output=True, text=True)
        self.assertNotEqual(bad.returncode, 0)
        self.assertEqual(bad.stdout, "")

    # REQ: CLK-1
    def test_with_uids_swaps_a_last_uid_field_and_keeps_descriptor_3_from_its_lookups(self):
        """MAIL-unit: the kernel's -clerk name=socket,uid takes the clerk's user's uid in its last field,
        and a clerk's key on descriptor 3 reaches the command it runs, never the lookups' processes."""
        out = subprocess.run([str(WITH_UIDS), "echo", "mail=/run/m.sock,@uid:root", "a,b,@uid:root", "x@uid:root",
                              "m,@gid:root"], capture_output=True, text=True, check=True)
        self.assertEqual(out.stdout, "mail=/run/m.sock,0 a,b,0 x@uid:root m,@gid:root\n")
        bad = subprocess.run([str(WITH_UIDS), "echo", "mail=/run/m.sock,@uid:agentos-no-such-user"],
                             capture_output=True, text=True)
        self.assertNotEqual(bad.returncode, 0)
        self.assertEqual(bad.stdout, "")
        with tempfile.TemporaryDirectory() as d:
            # An id that fails if it holds descriptor 3, and a command that says whether it does; the
            # outer shell opens descriptor 3 as the service manager's OpenFile= does.
            write(pathlib.Path(d), "id", "#!/bin/sh\n[ -e /proc/self/fd/3 ] && exit 9\necho 7\n", 0o755)
            out = subprocess.run(["sh", "-c", 'exec 3</dev/null; exec "$0" "$@"', str(WITH_UIDS),
                                  "sh", "-c", 'echo "$1 $2"; [ -e /proc/self/fd/3 ] && echo held', "-",
                                  "@uid:x", "m=/s,@uid:x"], capture_output=True, text=True,
                                 env={"PATH": d + ":/usr/bin:/bin"})
        self.assertEqual((out.returncode, out.stdout), (0, "7 m=/s,7\nheld\n"), out.stderr)

    def test_the_build_ships_the_keeper_s_mains(self):
        build = (ROOT / "image/build.sh").read_text()
        for cmd in ("agentos-enroll", "agentos-unlock", "agentos-kernel", "agentos-clerk-mail"):
            self.assertRegex(build, r"for cmd in [^;]*\b%s\b" % cmd)

    def test_the_boot_test_enrolls_on_the_first_boot(self):
        report, ci = BOOT_REPORT.read_text(), CI_BOOT.read_text()
        self.assertIn("agentos-keeper:", report)
        self.assertIn("tmpfiles.extra", ci)
        self.assertIn('"agentos-keeper: enroll=ran kernel=active pageca=staged"', ci)
        self.assertIn('"agentos-keeper: enroll=skipped"', ci)
        # The page authority is staged on the first boot only (OWN-card-flow).
        self.assertIn('"agentos-keeper: enroll=skipped kernel=active pageca=skipped"', ci)
        self.assertIn("pageca=$p", report)
        # The kernel starts setup-only after both boots (#2996), on its own sockets (#3073).
        self.assertIn("/agentos-keeper: enroll=skipped kernel=active/", ci)
        self.assertIn('hasnt "$W/console-reboot.log" "listen unix /run/agentos-kernel/"', ci)
        self.assertNotIn("my store holds none of your hardware keys", ci)
        # The report reads both units once their start jobs settle (#4474).
        after = ini(UNITS / "agentos-boot-report.service")["Unit"]["After"].split()
        self.assertIn("agentos-keeper-enroll.service", after)
        self.assertIn("agentos-keeper-kernel.service", after)
        # The CI unit whose mounts outlive one command lifts the main-side mask in a drop-in that
        # sorts after it.
        for unit in ("agentos-e2e-seal.service",):
            self.assertIn("'systemd.unit-dropin.%s~99-ci-unmask' '[Service]\\nInaccessiblePaths=\\n'" % unit, ci)
        self.assertLess("50-main-side.conf", "99-ci-unmask.conf")
        preset = (MK / "mkosi.extra/usr/lib/systemd/system-preset/50-agentos.preset").read_text().splitlines()
        for n in check.KEEPER_UNITS:
            # A template starts from its socket.
            self.assertIn("enable " + n.replace("@.service", ".socket"), preset)

    # REQ: REC-4, STO-2
    def test_the_recovery_rotation_is_one_root_one_shot_per_connection(self):
        """MIG-4-recovery-r2 (brief decision 7): the owner's group reaches root's one-shot only through its
        socket, one connection at a time; the one-shot answers on the connection, logs to the journal, has
        no TPM, and runs a flag the main defines on the store the other keeper units use."""
        sock = ini(ROTATE_SOCKET)["Socket"]
        self.assertEqual({k: sock[k] for k in ("ListenStream", "SocketUser", "SocketGroup", "SocketMode", "Accept",
                                               "MaxConnections")},
                         {"ListenStream": "/run/agentos-keeper/rotate.sock", "SocketUser": "root",
                          "SocketGroup": "agentos-owner", "SocketMode": "0660", "Accept": "yes", "MaxConnections": "1"})
        self.assertNotIn("Service", sock)
        svc = ini(ROTATE)["Service"]
        self.assertEqual((svc["StandardInput"], svc["StandardOutput"], svc["StandardError"]),
                         ("socket", "socket", "journal"))
        self.assertNotIn("User", svc)
        self.assertEqual(svc["DevicePolicy"], "closed")
        self.assertNotIn("DeviceAllow", svc)
        self.assertNotIn("/dev/tpm", ROTATE.read_text().split("[Service]")[1])
        for k, v in (("NoNewPrivileges", "yes"), ("LimitCORE", "0"), ("UMask", "0077"), ("PrivateNetwork", "yes"),
                     ("RestrictAddressFamilies", "AF_UNIX")):
            self.assertEqual(svc[k], v, k)
        # A oneshot is starting until it exits: its time bound is the start timeout (#3477).
        self.assertEqual(svc["Type"], "oneshot")
        self.assertTrue(svc["TimeoutStartSec"].isdigit() and 0 < int(svc["TimeoutStartSec"]) <= 300)
        self.assertNotIn("RuntimeMaxSec", svc)
        r = exec_args(ROTATE)
        self.assertEqual(r[:2], ["/usr/lib/agentos/agentos-enroll", "-rotate-recovery"])
        self.assertEqual(arg(r, "state"), arg(exec_args(ENROLL), "state"))
        self.assertEqual([w for w in r[1:] if w.startswith("-")], ["-rotate-recovery", "-state"])
        self.assertTrue({"rotate-recovery", "state"} <= go_flags("agentos-enroll"))
        self.assertEqual(re.findall(r"^ConditionPathExists=(.*)$", ROTATE.read_text(), re.M),
                         [arg(r, "state") + "/store"])
        users = SYSUSERS.read_text()
        self.assertRegex(users, r"(?m)^u agentos-owner ")
        # The socket's directory is outside the keeper's state, so the owner side can reach it.
        self.assertFalse(check.keeper_reach(sock["ListenStream"]))


    # REQ: HW-1, CH-9, STO-2
    def test_the_owner_card_flow_units(self):
        """OWN-card-flow slice a: the page authority is staged before enrollment and the owner page; the
        owner page reaches root's one-shot hand-off only through its socket, one connection at a time;
        the factors it writes start enrollment through a path unit, never a command; none of these units
        reaches the TPM or runs systemctl; and they all name the paths enrollment reads."""
        pageca, setup, path = (UNITS / "agentos-keeper-pageca.service", UNITS / "agentos-keeper-setup@.service",
                               UNITS / "agentos-keeper-enroll.path")
        e, p, s = exec_args(ENROLL), exec_args(pageca), exec_args(setup)
        store = arg(e, "state") + "/store"
        # The staging: before enrollment and the owner page, only while no store exists, once a boot.
        self.assertEqual(p[:2], ["/usr/lib/agentos/agentos-enroll", "-stage-page-ca"])
        self.assertEqual((arg(p, "page-ca-file"), arg(p, "page-ca-cert")), (arg(e, "page-ca-file"), arg(e, "page-ca-cert")))
        self.assertTrue(check.keeper_reach(arg(p, "page-ca-file")))
        self.assertFalse(check.keeper_reach(arg(p, "page-ca-cert")))
        pu, ps = ini(pageca)["Unit"], ini(pageca)["Service"]
        self.assertEqual(re.findall(r"^ConditionPathExists=(.*)$", pageca.read_text(), re.M), ["!" + store])
        self.assertEqual(set(pu["Before"].split()), {"agentos-keeper-enroll.service", "agentos-localui.service"})
        self.assertEqual((ps["Type"], ps["RemainAfterExit"]), ("oneshot", "yes"))
        self.assertEqual(ini(pageca)["Install"]["WantedBy"], "multi-user.target")
        # Enrollment pulls the staging into its own transaction and orders after it, waits for its
        # pair, pulls in the kernel, and bounds the path unit's retries.
        eu = ini(ENROLL)["Unit"]
        self.assertEqual(set(eu["Wants"].split()), {"agentos-keeper-pageca.service", "agentos-keeper-kernel.service"})
        self.assertIn("agentos-keeper-pageca.service", eu["After"].split())
        self.assertIn(arg(e, "page-ca-file"), re.findall(r"^ConditionPathExists=(.*)$", ENROLL.read_text(), re.M))
        self.assertEqual((eu["StartLimitBurst"], eu["StartLimitIntervalSec"]), ("3", "infinity"))
        # The published directory: root's, public, made at boot, not a keeper path.
        made = {w[1]: w for w in (l.split() for l in TMPFILES.read_text().splitlines()) if w and w[0] == "d"}
        cert_dir = arg(p, "page-ca-cert").rsplit("/", 1)[0]
        self.assertEqual(made[cert_dir][2:5], ["0755", "root", "root"])
        self.assertNotIn(cert_dir, check.KEEPER_PATHS)
        # The hand-off's socket: root's and the owner page's group, 0660, one connection at a time.
        sock = ini(UNITS / "agentos-keeper-setup.socket")["Socket"]
        self.assertEqual({k: sock[k] for k in ("ListenStream", "SocketUser", "SocketGroup", "SocketMode", "Accept",
                                               "MaxConnections")},
                         {"ListenStream": "/run/agentos-keeper/setup.sock", "SocketUser": "root",
                          "SocketGroup": "agentos-localui", "SocketMode": "0660", "Accept": "yes", "MaxConnections": "1"})
        self.assertNotIn("Service", sock)
        self.assertFalse(check.keeper_reach(sock["ListenStream"]))
        self.assertRegex(SYSUSERS.read_text(), r"(?m)^u agentos-localui ")
        # The hand-off: root's one-shot on the connection, journal for its reasons, no TPM, bounded.
        svc = ini(setup)["Service"]
        self.assertEqual((svc["StandardInput"], svc["StandardOutput"], svc["StandardError"]), ("socket", "socket", "journal"))
        self.assertEqual(svc["Type"], "oneshot")
        self.assertTrue(svc["TimeoutStartSec"].isdigit() and 0 < int(svc["TimeoutStartSec"]) <= 300)
        self.assertNotIn("User", svc)
        self.assertEqual(s[:2], ["/usr/lib/agentos/agentos-enroll", "-take-factors"])
        self.assertEqual(arg(s, "setup-dir"), arg(e, "passphrase-file").rsplit("/", 1)[0])
        self.assertEqual(arg(s, "setup-dir"), arg(e, "recovery-file").rsplit("/", 1)[0])
        self.assertEqual((arg(s, "state"), arg(s, "page-ca-cert")), (arg(e, "state"), arg(e, "page-ca-cert")))
        # The path unit: the recovery file, written last, starts enrollment.
        pp = ini(path)
        self.assertEqual((pp["Path"]["PathExists"], pp["Path"]["Unit"]), (arg(e, "recovery-file"), "agentos-keeper-enroll.service"))
        self.assertEqual(pp["Install"]["WantedBy"], "paths.target")
        # Not on a box with its store: left factors would run enrollment into its start limit.
        self.assertEqual(re.findall(r"^ConditionPathExists=(.*)$", path.read_text(), re.M), ["!" + store])
        preset = (MK / "mkosi.extra/usr/lib/systemd/system-preset/50-agentos.preset").read_text().splitlines()
        self.assertIn("enable agentos-keeper-enroll.path", preset)
        for unit in (pageca, setup):
            body = unit.read_text()
            with self.subTest(unit.name):
                self.assertIn(unit.name, check.KEEPER_UNITS)
                self.assertNotIn(unit.name, check.TPM_UNITS)
                self.assertEqual(ini(unit)["Service"]["DevicePolicy"], "closed")
                self.assertNotIn("DeviceAllow", ini(unit)["Service"])
                self.assertNotIn("/dev/tpm", body.split("[Service]")[1])
                for k, v in (("NoNewPrivileges", "yes"), ("LimitCORE", "0"), ("UMask", "0077"),
                             ("PrivateNetwork", "yes"), ("RestrictAddressFamilies", "AF_UNIX")):
                    self.assertEqual(ini(unit)["Service"][k], v, k)
                self.assertTrue({w[1:] for w in exec_args(unit) if w.startswith("-")} <= go_flags("agentos-enroll"))
        for unit in (pageca, setup, ENROLL, path, UNITS / "agentos-keeper-setup.socket"):
            for line in unit.read_text().replace("\\\n", " ").splitlines():
                if line.startswith("Exec"):
                    self.assertIsNone(check.REBOOT_WORDS.search(line), "%s: %s" % (unit.name, line))


def slice_cgroup(slice_, unit):
    """The cgroup path systemd gives UNIT in SLICE: a slice's name nests at each "-", so a-b.slice is
    under a.slice (systemd.slice(5))."""
    parts = slice_[:-len(".slice")].split("-")
    return "/" + "/".join("-".join(parts[:i + 1]) + ".slice" for i in range(len(parts))) + "/" + unit


class MailClerkUnitTest(unittest.TestCase):
    """MAIL-unit (#3420, briefs/MAIL-main.md slice c): the mail clerk's unit against the kernel's unit,
    the mains they run, and the lifecycle the brief gives it (start, clerk restart, update reboot)."""

    def setUp(self):
        self.m, k = exec_args(MAIL), exec_args(KERNEL)
        i = k.index("--")
        self.unlock, self.kern = k[1:i], k[i + 1:]
        self.svc = ini(MAIL)["Service"]

    # REQ: CLK-1, CLK-2, KRN-2
    def test_the_mail_clerk_and_the_kernel_name_each_other(self):
        m, kern, unlock = self.m, self.kern, self.unlock
        self.assertEqual(m[0], "/usr/lib/agentos/agentos-clerk-mail")
        self.assertTrue(ini(MAIL)["Service"]["ExecStart"].startswith("/usr/lib/agentos/with-uids "))
        for cmd, words in (("agentos-clerk-mail", m[1:]), ("agentos-unlock", unlock), ("agentos-kernel", kern)):
            for w in words:
                if w.startswith("-"):
                    self.assertIn(w[1:], go_flags(cmd), "%s %s" % (cmd, w))
        user = self.svc["User"]
        self.assertEqual((user, self.svc["Group"]), ("agentos-mail", "agentos-mail"))
        # The kernel calls the clerk on the clerk's kernel socket, admitting only the clerk's user.
        self.assertEqual(arg(kern, "clerk"), "mail=%s,@uid:%s" % (arg(m, "kernel-sock"), user))
        # The clerk admits only the kernel's user there: the user unlock drops to.
        self.assertEqual(arg(m, "kernel-uid"), arg(unlock, "uid"))
        # The owner side is agentosd, root (MAIL-main-a-7); the planner is a user of its own.
        self.assertEqual(arg(m, "owner-uid"), "0")
        self.assertEqual(arg(m, "planner-uid"), "@uid:agentos-planner")
        peers = {arg(m, "kernel-uid"), arg(m, "planner-uid"), "@uid:" + user, arg(kern, "owner-uid"),
                 arg(kern, "meter-uid")}
        self.assertEqual(len(peers), 5, peers)
        # The anchors come from the file unlock writes, root's, never from the kernel (D-146); unlock
        # pins them in the kernel's own log.
        self.assertEqual(arg(m, "anchors"), arg(unlock, "clerk-anchors"))
        self.assertEqual(arg(unlock, "log"), arg(kern, "log"))
        self.assertFalse(check.keeper_reach(arg(m, "anchors")))
        made = [l.split() for l in TMPFILES.read_text().splitlines() if l.strip() and not l.startswith("#")]
        self.assertNotIn(arg(m, "anchors").rsplit("/", 1)[0], [w[1] for w in made])
        # Each IMAP session's parser is its own process on its own socket (#3015,
        # tests/test_image_imapconn.py); no reader yet (#3421), which fails closed in the main.
        self.assertEqual(arg(m, "imap-conn"), ini(UNITS / "agentos-imapconn.socket")["Socket"]["ListenStream"])
        self.assertNotIn("-reader-sock", m)

    # REQ: CLK-1
    def test_the_kernel_hands_the_key_to_this_unit_alone(self):
        name, sock_cg = arg(self.kern, "clerk-key").split("=", 1)
        sock, cg = sock_cg.split(",")
        self.assertEqual(name, "mail")
        # The whole cgroup path the unit runs in: the keeper's slice, nested as systemd nests it.
        drop = ini(UNITS / "agentos-keeper-.service.d/90-keeper.conf")["Service"]
        self.assertEqual(cg, slice_cgroup(drop["Slice"], MAIL.name))
        self.assertEqual(cg, "/agentos.slice/agentos-keeper.slice/agentos-keeper-mail.service")
        self.assertNotIn("Slice", self.svc)
        # The manager connects at each start and the clerk gets the connection as descriptor 3, its
        # only one: no socket activation, no descriptor store, no other file.
        self.assertEqual(exec_lines(MAIL, "OpenFile"), [sock + ":clerk-key"])
        self.assertEqual(sock.rsplit("/", 1)[0], arg(self.kern, "owner-sock").rsplit("/", 1)[0])
        for key in ("Sockets", "FileDescriptorStoreMax", "StandardInput", "StandardOutput"):
            self.assertNotIn(key, self.svc)
        # Only ExecStart= runs in the unit, so only the clerk's main is ever handed the key.
        self.assertEqual([k for k in check.EXEC_KEYS if k in self.svc], ["ExecStart"])
        self.assertIn('FD = 3', (ROOT / "broker/clerk/clerkkey/clerkkey.go").read_text())

    # REQ: CLK-1, STO-2, UPD-10
    def test_the_mail_clerk_s_lifecycle(self):
        u = ini(MAIL)["Unit"]
        # Start: after the kernel, on a box with a store; enabled for every boot.
        self.assertIn("agentos-keeper-kernel.service", u["After"].split())
        self.assertIn("systemd-tmpfiles-setup.service", u["After"].split())
        self.assertEqual(re.findall(r"^ConditionPathExists=(.*)$", MAIL.read_text(), re.M), [arg(self.unlock, "store")])
        self.assertEqual(ini(MAIL)["Install"]["WantedBy"], "multi-user.target")
        self.assertIn("enable agentos-keeper-mail.service", PRESET.read_text().splitlines())
        # Clerk restart: every failed start, the kernel's not yet listening and a setup-only boot's
        # missing anchors included, is retried with a backoff to at most five minutes, and no start
        # limit leaves it failed for the rest of the boot. Each start is a new connection, so a new key.
        self.assertEqual(self.svc["Restart"], "on-failure")
        self.assertEqual((self.svc["RestartSec"], self.svc["RestartSteps"], self.svc["RestartMaxDelaySec"]),
                         ("2", "8", "5min"))
        self.assertEqual(u["StartLimitIntervalSec"], "0")
        self.assertNotIn("StartLimitBurst", u)
        # Update reboot: the Secrets stay in a directory on the root partition, made at every boot and
        # never emptied, owned by the clerk's user alone; the key is derived again from the same store.
        state = arg(self.m, "dir")
        self.assertIn(state, check.KEEPER_PATHS)
        self.assertTrue(state.startswith("/var/lib/"))
        made = {w[1]: w for w in (l.split() for l in TMPFILES.read_text().splitlines()) if w and w[0] == "d"}
        self.assertEqual(made[state], ["d", state, "0700", "agentos-mail", "agentos-mail", "-"])
        self.assertEqual(self.svc["ReadWritePaths"], state)
        for key in ("StateDirectory", "RuntimeDirectoryPreserve", "DynamicUser"):
            self.assertNotIn(key, self.svc)
        # The sockets: the clerk's own runtime directory, which its peers reach and the main side may.
        run = "/run/" + self.svc["RuntimeDirectory"]
        for flag in ("kernel-sock", "owner-sock", "planner-sock"):
            self.assertEqual(arg(self.m, flag).rsplit("/", 1)[0], run)
        self.assertEqual(self.svc["RuntimeDirectoryMode"], "0755")
        self.assertFalse(check.keeper_reach(run))

    # REQ: CLK-1, HW-5a, UPD-10
    def test_the_mail_clerk_s_sandbox(self):
        s = self.svc
        for k, v in (("NoNewPrivileges", "yes"), ("CapabilityBoundingSet", ""), ("LimitCORE", "0"), ("UMask", "0077"),
                     ("ProtectSystem", "strict"), ("ProtectHome", "yes"), ("PrivateTmp", "yes"),
                     ("PrivateDevices", "yes"), ("DevicePolicy", "closed"), ("MemoryDenyWriteExecute", "yes"),
                     ("NoExecPaths", "/"), ("ExecPaths", "/usr"), ("SystemCallArchitectures", "native")):
            self.assertEqual(s[k], v, k)
        self.assertNotIn("DeviceAllow", s)
        self.assertNotIn(MAIL.name, check.TPM_UNITS)
        # It ends its own TLS (D-154 rule 3) and learns its network from netlink and /proc/net/route
        # (MAIL-world-a-m1): ProcSubset=pid would hide the routes, and nothing else is reached.
        self.assertEqual(s["RestrictAddressFamilies"].split(), ["AF_UNIX", "AF_INET", "AF_INET6", "AF_NETLINK"])
        self.assertNotIn("PrivateNetwork", s)
        self.assertNotIn("ProcSubset", s)
        self.assertIn("netlink", (ROOT / "broker/cmd/agentos-clerk-mail/netguard.go").read_text())
        # Its TLS roots come only from the verity-checked /usr (Go reads SSL_CERT_FILE, then every file
        # in each SSL_CERT_DIR), and nothing else is set in its environment.
        env = dict(w.split("=", 1) for v in exec_lines(MAIL, "Environment") for w in v.split())
        self.assertEqual(env, {"SSL_CERT_FILE": "/dev/null", "SSL_CERT_DIR": "/usr/share/ca-certificates/mozilla"})
        self.assertNotIn("EnvironmentFile", s)
        self.assertIn("ca-certificates", (MK / "mkosi.conf").read_text().split())
        self.assertEqual(exec_lines(MAIL, "SystemCallFilter"), ["@system-service", "~@debug @mount @privileged"])
        self.assertEqual(s["SystemCallErrorNumber"], "EPERM")


if __name__ == "__main__":
    unittest.main()
