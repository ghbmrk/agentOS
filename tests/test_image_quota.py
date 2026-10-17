"""P2-2w c4f s2 (#1386, #1302 Security S-R2): the booted image shows root mounted with project quotas,
CI's boot test reads it, and nothing under image/ passes agentosd -disk-quota off (RES-4).

Kept apart from tests/test_image.py, which several open PRs edit (D-111)."""
# REQ: RES-4, ARC-3
import configparser
import os
import pathlib
import re
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
IMG = ROOT / "image"
MK = IMG / "mkosi"
AGENTOS_LIB = MK / "mkosi.extra/usr/lib/agentos"
UNIT = MK / "mkosi.extra/usr/lib/systemd/system/agentosd.service"
ON = "agentos-quota: root=ext4 prjquota"

# Every spelling Go's flag package accepts for turning quotas off: one or two dashes, then a space
# or "=", the value bare or quoted. A line continuation between flag and value counts as a space.
OFF = re.compile(r"""(?<![\w-])--?disk-quota(?:\s|\\\n)*[=\s](?:\s|\\\n)*["']?off\b""")


def ini(path):
    p = configparser.ConfigParser(strict=False, interpolation=None, delimiters=("=",))
    p.optionxform = str
    p.read(path)
    return p


def stub(d, name, body):
    f = d / name
    f.write_text("#!/bin/sh\n" + body + "\n")
    f.chmod(0o755)


def off_uses(text):
    return OFF.findall(text)


class NoQuotaOffTest(unittest.TestCase):
    """The issue's hard rule: never pass -disk-quota off on the image."""

    def test_the_scanner_catches_every_spelling(self):
        for s in ("-disk-quota off", "--disk-quota off", "-disk-quota=off", "--disk-quota=off",
                  '-disk-quota="off"', "-disk-quota 'off'", "-disk-quota  off", "-disk-quota \\\n\toff",
                  "agentosd -owner x -disk-quota=off -image a=b"):
            with self.subTest(s=s):
                self.assertTrue(off_uses(s), s)

    def test_the_scanner_passes_other_values(self):
        for s in ("-disk-quota on", "--disk-quota=on", "-disk-quota offline", "-xdisk-quota off",
                  "# -disk-quota on keeps machines off"):
            with self.subTest(s=s):
                self.assertFalse(off_uses(s), s)

    def test_no_shipped_file_turns_quotas_off(self):
        hits = []
        for f in sorted(IMG.rglob("*")):
            if f.is_file() and f.suffix != ".md":
                try:
                    text = f.read_text()
                except UnicodeDecodeError:
                    continue
                if off_uses(text):
                    hits.append(str(f.relative_to(ROOT)))
        self.assertEqual(hits, [])

    def assert_quota_last_and_once(self, unit_text):
        # Go's flag package takes the last value, so `-disk-quota on` as the last argument wins over
        # anything before it, however spelled (${VAR}, systemd escapes, split quotes: Security #2110
        # point 1). disk-quota appears nowhere else in the command, and there is one ExecStart=.
        starts = [l for l in unit_text.splitlines() if l.startswith("ExecStart=")]
        self.assertEqual(len(starts), 1, starts)
        p = configparser.ConfigParser(strict=False, interpolation=None, delimiters=("=",))
        p.optionxform = str
        p.read_string(unit_text)
        argv = p["Service"]["ExecStart"].replace("\\\n", " ").split()
        self.assertEqual(argv[-2:], ["-disk-quota", "on"], argv)
        self.assertEqual(sum("disk-quota" in a for a in argv), 1, argv)

    def test_the_unit_passes_quotas_on_last_and_once(self):
        self.assert_quota_last_and_once(UNIT.read_text())

    def test_the_check_catches_an_override(self):
        text = UNIT.read_text()
        last = "-worker-image openclaw \\\n        -disk-quota on\n"
        self.assertIn(last, text)
        for mutant in ("-worker-image openclaw \\\n        -disk-quota on -disk-quota=${DQ}\n",
                       "-worker-image openclaw \\\n        -disk-quota=${DQ} -disk-quota on\n",
                       "-worker-image openclaw \\\n        -disk-quota on -image x=/y\n",
                       "-worker-image openclaw\n",
                       last + "ExecStart=/usr/lib/agentos/agentosd -disk-quota=of\\x66\n"):
            with self.subTest(mutant=mutant):
                with self.assertRaises(AssertionError):
                    self.assert_quota_last_and_once(text.replace(last, mutant))

    def test_no_drop_in_overrides_the_unit(self):
        # A drop-in could replace ExecStart= or set the flag's value (Security #2110 point 1).
        self.assertEqual(sorted(str(d.relative_to(ROOT)) for d in IMG.rglob("agentosd.service.d")), [])


class BootReportQuotaTest(unittest.TestCase):
    """boot-report says whether root carries project quotas, read from the mount itself."""

    def report(self, fstype, options, findmnt_fails=False):
        with tempfile.TemporaryDirectory() as t:
            t = pathlib.Path(t)
            (t / "net").mkdir()
            stub(t, "sleep", ":")
            stub(t, "ip", ":")
            stub(t, "systemd-bless-boot", "echo good")
            stub(t, "systemctl", "echo inactive")
            if findmnt_fails:
                stub(t, "findmnt", 'case "$*" in *SIZE*) echo 1073741824 ;; *) exit 1 ;; esac')
            else:
                stub(t, "findmnt", 'case "$*" in *SIZE*) echo 1073741824 ;; *FSTYPE*) echo %s ;; '
                     '*OPTIONS*) echo %s ;; *) exit 9 ;; esac' % (fstype, options))
            script = (AGENTOS_LIB / "boot-report").read_text().replace(
                "/usr/lib/systemd/systemd-bless-boot", str(t / "systemd-bless-boot"))
            env = dict(os.environ, PATH="%s:%s" % (t, os.environ["PATH"]), AGENTOS_SYS_NET=str(t / "net"))
            out = subprocess.run(["sh", "-c", script], env=env, check=True, capture_output=True, text=True).stdout
            return out.splitlines()

    def quota_line(self, lines):
        q = [x for x in lines if x.startswith("agentos-quota: ")]
        self.assertEqual(len(q), 1, lines)
        return q[0]

    def test_root_with_project_quotas_reads_on(self):
        lines = self.report("ext4", "rw,relatime,prjquota")
        self.assertEqual(self.quota_line(lines), ON)
        # The first line is the one test_image.py and ci_boot.sh read; it keeps its exact text.
        self.assertEqual(lines[0], "agentos-uplink: none agentos-boot: bless=good root_bytes=1073741824")

    def test_anything_else_reads_off(self):
        for fstype, options in (("ext4", "rw,relatime"), ("ext4", "rw,relatime,usrquota"),
                                ("xfs", "rw,prjquota"), ("ext4", "rw,noprjquota")):
            with self.subTest(fstype=fstype, options=options):
                q = self.quota_line(self.report(fstype, options))
                self.assertNotIn(ON, q)
                self.assertTrue(q.startswith("agentos-quota: off "), q)

    def test_an_unreadable_mount_reads_off(self):
        q = self.quota_line(self.report(None, None, findmnt_fails=True))
        self.assertTrue(q.startswith("agentos-quota: off "), q)


class BootTestReadsQuotaTest(unittest.TestCase):
    def test_both_boots_need_the_on_line(self):
        sh = (IMG / "ci_boot.sh").read_text()
        for log in ("console.log", "console-reboot.log"):
            with self.subTest(log=log):
                self.assertIn('has "$W/%s" "%s"' % (log, ON), sh)


if __name__ == "__main__":
    unittest.main()
