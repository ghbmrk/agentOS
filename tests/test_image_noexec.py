"""TN-noexec (#2856): no code from writable storage, and a weekly reboot (UPD-10, D-149).

Every agentos unit the image ships sets NoExecPaths=/ with ExecPaths= only on the read-only /usr;
root, /tmp, /run, /dev/shm and /dev are mounted noexec; mkosi.finalize and finish_image.py fail the
build otherwise; agentos-reboot.timer reboots the box weekly, waiting out a busy box for at most a
week of uptime. CI's boot test plants an executable in each writable mount and finds it refused
(image/ci_boot.sh, agentos-noexec lines).

Kept apart from tests/test_image.py, which holds the tree check's other tests; the helpers come from
there."""
# REQ: UPD-10
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_image import MK, ROOT, ENTRY, H, check, clean_tree, finish, ini, link, stub, write  # noqa: E402

UNITS = MK / "mkosi.extra/usr/lib/systemd/system"
REBOOT = MK / "mkosi.extra/usr/lib/agentos/reboot-weekly"
SYSTEM = "usr/lib/systemd/system/"
# systemd 257's own tmp.mount, as trixie ships it.
STOCK_TMP = ("[Unit]\nDescription=Temporary Directory /tmp\n\n[Mount]\nWhat=tmpfs\nWhere=/tmp\nType=tmpfs\n"
             "Options=mode=1777,strictatime,nosuid,nodev,size=50%%,nr_inodes=1m\n")


def shipped_units():
    """{in-image path: source} for every agentos unit the image ships: mkosi.extra's, and those
    image/build.sh installs from the commands' directories."""
    out = {SYSTEM + p.name: p for p in UNITS.iterdir() if p.name.startswith("agentos") and p.is_file()}
    for src, dst in re.findall(r'install -D -m 0644 "\$REPO/(\S+\.service)" "\$STAGE/(\S+)"',
                               (ROOT / "image/build.sh").read_text()):
        out[dst] = ROOT / src
    return out


class NoExecTreeTest(unittest.TestCase):
    """mkosi.finalize's UPD-10 check on a tree holding the image's own files."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = clean_tree(pathlib.Path(self.tmp.name))
        for rel, src in shipped_units().items():
            write(self.root, rel, src.read_text())
        write(self.root, SYSTEM + "tmp.mount", STOCK_TMP)

    def tearDown(self):
        self.tmp.cleanup()

    def v(self):
        return check.noexec_violations(self.root)

    def test_the_image_passes(self):
        self.assertEqual(self.v(), [])
        self.assertEqual(check.violations(self.root), [])

    def test_every_shipped_service_but_agentosd_is_checked(self):
        names = {rel.rsplit("/", 1)[1] for rel in shipped_units() if rel.endswith(".service")}
        self.assertIn("agentos-reboot.service", names)
        self.assertIn("agentos-ap.service", names)
        self.assertIn("agentos-ap-exempt@.service", names)
        self.assertEqual(check.NOEXEC_EXEMPT, ("agentosd.service",))
        for name in sorted(names - set(check.NOEXEC_EXEMPT)):
            with self.subTest(name):
                f = self.root / SYSTEM / name
                good = f.read_text()
                f.write_text(good.replace("NoExecPaths=/\n", "").replace("ExecPaths=/usr\n", ""))
                self.assertEqual(self.v(), ["%s: NoExecPaths does not hold /; must be NoExecPaths=/ (UPD-10)" % name,
                                            "%s: no ExecPaths; must be ExecPaths=/usr (UPD-10)" % name])
                f.write_text(good)
        # The old core's broker is frozen (D-139) and its hardening is #917; root's mount still holds.
        self.assertNotIn("NoExecPaths", (self.root / SYSTEM / "agentosd.service").read_text())

    def test_exec_paths_outside_usr_are_refused(self):
        unit = self.root / SYSTEM / "agentos-egress.service"
        good = unit.read_text()
        for line, bad in (("ExecPaths=/var/lib", "/var/lib"), ("ExecPaths=/usr /run", "/run"),
                          ("ExecPaths=/usrx", "/usrx"), ("ExecPaths=-/etc", "/etc"), ("ExecPaths=/", "/")):
            with self.subTest(line):
                unit.write_text(good.replace("ExecPaths=/usr\n", line + "\n"))
                self.assertEqual(self.v(), ["agentos-egress.service: ExecPaths holds %s; only /usr, which is "
                                            "read-only, may execute (UPD-10)" % bad])
        for line in ("ExecPaths=/usr/lib/agentos", "ExecPaths=-/usr", "ExecPaths=/usr/", "ExecPaths=//usr"):
            with self.subTest(line):
                unit.write_text(good.replace("ExecPaths=/usr\n", line + "\n"))
                self.assertEqual(self.v(), [])

    def test_what_the_check_cannot_read_is_refused(self):
        unit = self.root / SYSTEM / "agentos-egress.service"
        good = unit.read_text()
        for line in ("ExecPaths=%t", "ExecPaths=/usr/../var", "ExecPaths=+/usr", "ExecPaths=usr",
                     'ExecPaths="/usr"', "NoExecPaths=/./"):
            with self.subTest(line):
                key = line.split("=", 1)[0]
                unit.write_text(good.replace(key + "=/" + ("usr" if key == "ExecPaths" else "") + "\n", line + "\n"))
                v = self.v()
                self.assertEqual(len(v), 1, v)
                self.assertIn("the tree check does not model it", v[0])

    def test_drop_ins_are_read_as_systemd_reads_them(self):
        # A later empty assignment resets the list, in the unit's own drop-ins, a dash prefix's and
        # service.d; an added path is checked like the unit's own.
        for d in ("agentos-egress.service.d", "agentos-.service.d", "service.d"):
            for body, want in (("[Service]\nNoExecPaths=\n", "NoExecPaths does not hold /"),
                               ("[Service]\nExecPaths=/var/tmp\n", "ExecPaths holds /var/tmp"),
                               ("[Service]\nExecPaths=\n", "no ExecPaths")):
                with self.subTest(d=d, body=body):
                    f = write(self.root, "etc/systemd/system/%s/50-x.conf" % d, body)
                    self.assertTrue(any(want in x for x in self.v()), self.v())
                    f.unlink()
        self.assertEqual(self.v(), [])

    def test_a_units_own_tmpfs_ends_noexec(self):
        # systemd 257 leaves a unit's own mounts out of NoExecPaths=/ (build (a) at 9d00e6b ran a file
        # planted in a plain TemporaryFileSystem=), so a tmpfs the unit can write must say noexec itself.
        unit = self.root / SYSTEM / "agentos-egress.service"
        good = unit.read_text()
        for line in ("TemporaryFileSystem=/var/x", "TemporaryFileSystem=/var/x:mode=0700", "TemporaryFileSystem=/var/x:noexec,exec",
                     "TemporaryFileSystem=/var/x:ro,rw", "TemporaryFileSystem=/var/x:noexec,defaults"):
            with self.subTest(line):
                unit.write_text(good + "\n[Service]\n" + line + "\n")
                self.assertEqual(self.v(), ["agentos-egress.service: %s is writable and does not end noexec (UPD-10)" % line])
        for line in ("TemporaryFileSystem=/var/x:noexec", "TemporaryFileSystem=/var/x:mode=0700,nosuid,nodev,noexec",
                     "TemporaryFileSystem=/var/x:ro", "TemporaryFileSystem=/var/x:rw,ro", "PrivateTmp=yes"):
            with self.subTest(line):
                unit.write_text(good + "\n[Service]\n" + line + "\n")
                self.assertEqual(self.v(), [])
        unit.write_text(good + "\n[Service]\nPrivateTmp=disconnected\n")
        self.assertEqual(self.v(), ["agentos-egress.service: PrivateTmp=disconnected mounts a tmpfs that executes; "
                                    "use PrivateTmp=yes (UPD-10)"])

    def test_nothing_is_mounted_under_usr_in_a_unit(self):
        # ExecPaths=/usr makes whatever a unit mounts under /usr in its own namespace executable.
        unit = self.root / SYSTEM / "agentos-egress.service"
        good = unit.read_text()
        for line in ("BindPaths=/var/lib/x:/usr/lib/x", "BindReadOnlyPaths=-/var/x:/usr/x:rbind", "BindPaths=/usr/lib/x",
                     "TemporaryFileSystem=/usr/local:rw,noexec", "ReadWritePaths=-/usr/lib/agentos", "MountImages=/var/i.raw:/usr/x",
                     "BindPaths=/var/x:/usr", "TemporaryFileSystem=/usr/./x:ro", "BindPaths=/var/x:/bin/x",
                     "TemporaryFileSystem=/lib/agentos:ro", "BindReadOnlyPaths=/var/x:/sbin", "ReadWritePaths=/lib64"):
            with self.subTest(line):
                unit.write_text(good + "\n[Service]\n" + line + "\n")
                self.assertEqual(len(self.v()), 1, self.v())
                self.assertIn("mounts under /usr, which executes", self.v()[0])
        for key in check.NAMESPACE_ROOTS:
            with self.subTest(key):
                unit.write_text(good + "\n[Service]\n%s=/var/lib/x\n" % key)
                self.assertEqual(self.v(), ["agentos-egress.service: sets %s; only the image's own /usr may execute (UPD-10)" % key])
        for line in ("BindPaths=/usr/lib/x:/var/lib/x", "TemporaryFileSystem=/var/usr:ro", "BindPaths=/usrx", "BindPaths=/library",
                     "BindPaths=/usr/x\nBindPaths="):
            with self.subTest(line):
                unit.write_text(good + "\n[Service]\n" + line + "\n")
                self.assertEqual(self.v(), [])
        unit.write_text(good + "\n[Service]\nBindPaths=%t/x:/var/x\n")
        self.assertIn("does not model it", " ".join(self.v()))
        f = write(self.root, "etc/systemd/system/service.d/50-x.conf", "[Service]\nBindPaths=/var/x:/usr/x\n")
        unit.write_text(good)
        self.assertTrue(self.v() and all("mounts under /usr" in x for x in self.v()), self.v())
        f.unlink()
        self.assertEqual(self.v(), [])

    def test_instances_and_links_are_refused_not_modelled(self):
        for rel in ("etc/systemd/system/agentos-ap-exempt@wlan0.service.d/50-x.conf",
                    "etc/systemd/system/agentos-ap-exempt@wlan0.service"):
            with self.subTest(rel):
                f = write(self.root, rel, "[Service]\nNoExecPaths=\n")
                self.assertTrue(any("an instance of a template" in x for x in self.v()), self.v())
                f.unlink()
                if f.parent.name.endswith(".d"):
                    f.parent.rmdir()
        for rel, target in (("etc/systemd/system/agentos-x.service", "/usr/lib/systemd/system/agentos-health.service"),
                            ("etc/systemd/system/other.service", "/usr/lib/systemd/system/agentos-health.service"),
                            ("etc/systemd/system/agentos-health.service", "/dev/null")):
            with self.subTest(rel=rel, target=target):
                f = link(self.root, rel, target)
                self.assertTrue(any(x.startswith(rel + ": a link") for x in self.v()), self.v())
                f.unlink()
        self.assertEqual(self.v(), [])

    def test_an_earlier_unit_file_is_the_one_read(self):
        f = write(self.root, "etc/systemd/system/agentos-health.service", "[Service]\nExecStart=/usr/lib/agentos/health\n")
        self.assertEqual(self.v(), ["agentos-health.service: NoExecPaths does not hold /; must be NoExecPaths=/ (UPD-10)",
                                    "agentos-health.service: no ExecPaths; must be ExecPaths=/usr (UPD-10)"])
        f.unlink()

    def test_fstab_mounts_nothing_executable(self):
        fstab = self.root / "etc/fstab"
        good = fstab.read_text()
        self.assertEqual({ln.split()[1] for ln in good.splitlines() if ln and not ln.startswith("#")},
                         set(check.NOEXEC_FSTAB))
        for t in check.NOEXEC_FSTAB:
            with self.subTest(missing=t):
                fstab.write_text("".join(ln + "\n" for ln in good.splitlines() if not ln.split()[1:2] == [t]))
                self.assertEqual(self.v(), ["etc/fstab: no %s line; the box remounts it noexec from etc/fstab (UPD-10)" % t])
        for opts in ("nosuid,nodev", "noexec,exec", "noexec,defaults", "defaults"):
            with self.subTest(opts=opts):
                fstab.write_text(good.replace("nosuid,nodev,noexec", opts))
                self.assertEqual(self.v(), ["etc/fstab: /dev/shm is mounted without noexec (UPD-10)",
                                            "etc/fstab: /run is mounted without noexec (UPD-10)"])
        for extra, ok in (("UUID=x /srv ext4 defaults 0 2\n", False), ("UUID=x /srv ext4 defaults,noexec 0 2\n", True),
                          ("tmpfs /run/ tmpfs exec 0 0\n", False), ("/swapfile none swap sw 0 0\n", True)):
            with self.subTest(extra=extra):
                fstab.write_text(good + extra)
                self.assertEqual(self.v() == [], ok, self.v())
        fstab.write_text(good)

    def test_mount_units_end_noexec(self):
        drop = self.root / SYSTEM / "tmp.mount.d/50-agentos-noexec.conf"
        good = drop.read_text()
        drop.unlink()
        self.assertEqual(self.v(), ["usr/lib/systemd/system/tmp.mount: Options=mode=1777,strictatime,nosuid,nodev,"
                                    "size=50%%,nr_inodes=1m does not end noexec (UPD-10)"])
        drop.write_text(good)
        for d in ("etc/systemd/system/tmp.mount.d", "etc/systemd/system/mount.d"):
            with self.subTest(d):
                f = write(self.root, d + "/90-x.conf", "[Mount]\nOptions=mode=1777,nosuid\n")
                self.assertEqual(len(self.v()), 1, self.v())
                f.unlink()
        # A tmp.mount earlier in the search path is the one read; a masked one mounts nothing.
        f = write(self.root, "etc/systemd/system/tmp.mount", STOCK_TMP)
        self.assertEqual(self.v(), [])  # the drop-in still applies
        drop.unlink()
        self.assertEqual(len(self.v()), 1, self.v())
        self.assertTrue(self.v()[0].startswith("etc/systemd/system/tmp.mount:"))
        f.unlink()
        link(self.root, "etc/systemd/system/tmp.mount", "/dev/null")
        self.assertEqual([x for x in self.v() if x.startswith("etc/")], [])
        (self.root / "etc/systemd/system/tmp.mount").unlink()
        drop.write_text(good)
        # Only systemd's kernel file systems may lack noexec; any other mount unit is held to it.
        for n in check.NOEXEC_MOUNT_STOCK:
            write(self.root, SYSTEM + n, "[Mount]\nOptions=nosuid,nodev\n")
        self.assertEqual(self.v(), [])
        f = write(self.root, SYSTEM + "var-lib-x.mount", "[Mount]\nWhat=/dev/sdb1\nWhere=/var/lib/x\n")
        self.assertEqual(self.v(), ["usr/lib/systemd/system/var-lib-x.mount: Options= does not end noexec (UPD-10)"])
        f.write_text("[Mount]\nWhat=/dev/sdb1\nWhere=/var/lib/x\nOptions=noexec\n")
        self.assertEqual(self.v(), [])

    def test_the_image_drop_in_keeps_systemd_options(self):
        # The drop-in replaces Options= whole: it is systemd's own list plus noexec, nothing dropped.
        opts = ini(MK / "mkosi.extra" / SYSTEM / "tmp.mount.d/50-agentos-noexec.conf")["Mount"]["Options"].split(",")
        stock = re.search(r"Options=(\S+)", STOCK_TMP).group(1).split(",")
        self.assertEqual(sorted(opts), sorted(stock + ["noexec"]))


class RootNoExecTest(unittest.TestCase):
    """finish_image.py: the built boot entry mounts root noexec."""

    def test_mkosi_mounts_root_noexec(self):
        line = ini(MK / "mkosi.conf")["Content"]["KernelCommandLine"].split()
        flags = [w for w in line if w.startswith("rootflags=")]
        self.assertEqual(flags, ["rootflags=prjquota,noexec"])
        entry = (ENTRY % H).replace("rw quiet", "rw quiet " + flags[0])
        self.assertEqual(finish.noexec_violations(entry), [])
        self.assertEqual(finish.cmdline_violations(entry), [])

    def test_an_entry_without_noexec_fails(self):
        base = ENTRY % H
        for words, ok in (("", False), ("rootflags=prjquota", False), ("rootflags=noexec,exec", False),
                          ("rootflags=noexec,defaults", False), ("rootflags=prjquota,noexec rootflags=prjquota", False),
                          ("rootflags=prjquota rootflags=noexec", True), ("rootflags=defaults,noexec", True)):
            with self.subTest(words):
                v = finish.noexec_violations(base.replace("rw quiet", ("rw quiet " + words).strip()))
                self.assertEqual(v == [], ok, v)


class WeeklyRebootTest(unittest.TestCase):
    """agentos-reboot.timer and reboot-weekly: weekly, waiting out an inhibitor, never past a week."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = pathlib.Path(self.tmp.name)
        self.bin, self.root, self.log = t / "bin", t / "root", t / "calls.log"
        (self.root / "proc").mkdir(parents=True)
        # A drill finished this month, so no restore drill is due (tests/test_image_drill.py).
        write(self.root, "var/lib/agentos/drill/last.json", "{}\n")
        # systemctl refuses while the inhibit file holds a number above zero, and counts it down;
        # sleep moves uptime on.
        self.inhibit = t / "inhibit"
        stub(self.bin, "systemctl", 'echo "systemctl $*" >>"%s"\n'
             'case "$*" in *--check-inhibitors=no*) exit 0 ;; esac\n'
             'n=$(cat "%s"); [ "$n" -gt 0 ] || exit 0; echo $((n - 1)) >"%s"; exit 1'
             % (self.log, self.inhibit, self.inhibit))
        stub(self.bin, "sleep", 'echo "sleep $*" >>"%s"\nu=$(cut -d. -f1 "%s")\necho "$((u + $1)).00 0.00" >"%s"'
             % (self.log, self.root / "proc/uptime", self.root / "proc/uptime"))

    def tearDown(self):
        self.tmp.cleanup()

    def run_reboot(self, uptime, inhibited):
        (self.root / "proc/uptime").write_text("%d.42 12.00\n" % uptime)
        self.inhibit.write_text("%d\n" % inhibited)
        env = dict(os.environ, PATH="%s:%s" % (self.bin, os.environ["PATH"]), AGENTOS_HEALTH_ROOT=str(self.root))
        r = subprocess.run(["sh", str(REBOOT)], env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return r.stdout, self.log.read_text().splitlines()

    def test_reboots_at_once_when_nothing_holds_it(self):
        out, calls = self.run_reboot(3600, 0)
        self.assertEqual(calls, ["systemctl reboot --check-inhibitors=yes"])
        self.assertIn("agentos-reboot: rebooting", out)

    def test_waits_out_an_inhibitor(self):
        out, calls = self.run_reboot(3600, 2)
        self.assertEqual(calls, ["systemctl reboot --check-inhibitors=yes", "sleep 300"] * 2
                         + ["systemctl reboot --check-inhibitors=yes"])
        self.assertIn("agentos-reboot: rebooting", out)

    def test_never_past_a_week_of_uptime(self):
        # An inhibitor that is never let go (an implant's own) holds the box up to a week, no longer.
        out, calls = self.run_reboot(604800 - 900, 10 ** 6)
        self.assertEqual(calls, ["systemctl reboot --check-inhibitors=yes", "sleep 300"] * 3
                         + ["systemctl reboot --check-inhibitors=no"])
        self.assertIn("rebooting through any inhibitor", out)
        self.log.unlink()
        out, calls = self.run_reboot(604800, 10 ** 6)
        self.assertEqual(calls, ["systemctl reboot --check-inhibitors=no"])

    def test_an_unreadable_uptime_reboots(self):
        (self.root / "proc/uptime").mkdir()
        self.inhibit.write_text("1000000\n")
        env = dict(os.environ, PATH="%s:%s" % (self.bin, os.environ["PATH"]), AGENTOS_HEALTH_ROOT=str(self.root))
        subprocess.run(["sh", str(REBOOT)], env=env, capture_output=True, text=True)
        self.assertEqual(self.log.read_text().splitlines(), ["systemctl reboot --check-inhibitors=no"])

    def test_the_timer_is_weekly_and_enabled(self):
        t = ini(UNITS / "agentos-reboot.timer")
        self.assertEqual(t["Timer"]["OnCalendar"], "Sun *-*-* 03:00:00")
        self.assertEqual(t["Timer"]["Persistent"], "no")
        self.assertEqual(t["Timer"]["OnBootSec"], "7d")  # the week on the monotonic clock too
        self.assertEqual(t["Install"]["WantedBy"], "timers.target")
        s = ini(UNITS / "agentos-reboot.service")["Service"]
        self.assertEqual(s["ExecStart"], "/usr/lib/agentos/reboot-weekly")
        self.assertEqual(s["Type"], "oneshot")
        preset = (MK / "mkosi.extra/usr/lib/systemd/system-preset/50-agentos.preset").read_text().splitlines()
        self.assertIn("enable agentos-reboot.timer", preset)
        self.assertTrue(os.access(REBOOT, os.X_OK))


class BootProbeTest(unittest.TestCase):
    """CI's boot test plants an executable in each writable mount and expects it refused."""

    def test_ci_boot_probes_every_writable_mount(self):
        sh = (ROOT / "image/ci_boot.sh").read_text()
        # The same list plants in the guest and is read back on the host.
        self.assertEqual(sh.count("for d in / /var/tmp /etc /tmp /run /dev/shm /dev /boot; do"), 2)
        self.assertIn('mountpoint -q "$d"', sh)
        self.assertIn('has "$W/console.log" "agentos-noexec: $d refused"', sh)
        # systemd reads a credential name once: two multi-user.target drop-ins on one boot would drop one
        # check unseen (#2875 L3, build (a) at b2a9007). One drop-in wants both checks.
        self.assertIn('EXTRA="$NM_EXTRA$NX_EXTRA$CHECKS_WANTED"', sh)
        self.assertIn("Wants=agentos-nm-check.service agentos-noexec-check.service", sh)
        # No credential name repeats on the first boot, whose EXTRA these variables and REPORT_FIRST make up.
        names = []
        for var in ("NM_EXTRA", "NX_EXTRA", "CHECKS_WANTED", "REPORT_FIRST"):
            line = re.search(r"^%s=.*$" % var, sh, re.M).group(0)
            names += re.findall(r"(?:nm_cred |credential\.binary:)([\w.@-]+)", line)
        self.assertEqual(len(names), 4, names)
        self.assertEqual(len(names), len(set(names)), names)
        probe = re.search(r"noexec_check\(\) \{\n\tcat <<'EOS'\n(.*?)\nEOS\n", sh, re.S).group(1)
        self.assertEqual(subprocess.run(["sh", "-n"], input=probe, text=True).returncode, 0)
        for n in ("tmp", "var-tmp", "state", "tmpfs"):
            self.assertIn("%s:" % n, probe)
            self.assertIn('"agentos-noexec: unit %s refused"' % n, sh)
        self.assertIn("-p TemporaryFileSystem=/mnt:noexec", probe)
        for want in ("agentos-noexec: reboot timer active", "agentos-noexec: done"):
            self.assertIn(want, sh)
        self.assertIn('hasnt "$W/console.log" "agentos-noexec: FAIL"', sh)


if __name__ == "__main__":
    unittest.main()
