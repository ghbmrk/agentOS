"""P2-2w c4f s2 (#1386, #1302 Security S-R2): the booted image shows root mounted with project quotas,
CI's boot test reads it, and nothing under image/ passes agentosd -disk-quota off (RES-4).

Kept apart from tests/test_image.py, which several open PRs edit (D-111)."""
# REQ: RES-4, ARC-3
import importlib.machinery
import importlib.util
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
ON = "agentos-quota: root=ext4 prjquota flag=on"
# The one command the image runs agentosd with (Security #2110 re-sign 3: exact, not parsed).
CANON = ("/usr/lib/agentos/with-uids /usr/lib/agentos/agentosd -owner ${AGENTOS_OWNER} "
         "-modem-uid @uid:agentos-modem -localui-uid @uid:agentos-localui "
         "-kernel-owner /run/agentos-kernel/owner.sock -kernel-uid @uid:agentos-kernel "
         "-kernel-owner-uid @uid:agentos-owner "
         "-runsc /usr/lib/agentos/runsc -image openclaw=/usr/lib/agentos/images/openclaw "
         "-image codex=/usr/lib/agentos/images/codex -worker-image openclaw -disk-quota on")
EXEC = ("{ path=/usr/lib/agentos/with-uids ; argv[]=%s ; ignore_errors=no ; start_time=[n/a] ; "
        "stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }")

# Every spelling Go's flag package accepts for turning quotas off: one or two dashes, then a space
# or "=", the value bare or quoted. A line continuation between flag and value counts as a space.
OFF = re.compile(r"""(?<![\w-])--?disk-quota(?:\s|\\\n)*[=\s](?:\s|\\\n)*["']?off\b""")


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


# The image check's model of systemd 257's unit parsing (config_lines) and drop-in names, reused so
# this test reads the unit the way systemd does (Security #2110 re-sign).
finalize = load("image_check_quota", MK / "mkosi.finalize")



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

    def assert_canonical(self, unit_text):
        # Read as systemd reads it (indented keys, continuations, comments), the unit has one
        # ExecStart= and no reset, and its words are exactly CANON, which ends -disk-quota on and
        # names disk-quota nowhere else (Go takes the last value). Three review rounds each found a
        # bypass of a parser that allowed variations, so nothing varies (Security #2110 re-sign 3).
        starts = [v for sec, k, v in finalize.config_lines(unit_text.encode())
                  if sec == "Service" and k == "ExecStart"]
        self.assertEqual(len(starts), 1, starts)
        self.assertEqual(" ".join(starts[0].split()), CANON)

    def test_canon_ends_quotas_on_and_names_it_once(self):
        self.assertTrue(CANON.endswith(" -disk-quota on"))
        self.assertEqual(CANON.count("disk-quota"), 1)

    def test_the_unit_runs_the_canonical_command(self):
        self.assert_canonical(UNIT.read_text())

    def test_the_check_catches_an_override(self):
        text = UNIT.read_text()
        last = "-worker-image openclaw \\\n        -disk-quota on\n"
        self.assertIn(last, text)
        for mutant in ("-worker-image openclaw \\\n        -disk-quota on -disk-quota=${DQ}\n",
                       "-worker-image openclaw \\\n        -disk-quota=${DQ} -disk-quota on\n",
                       "-worker-image openclaw \\\n        -disk-quota on -image x=/y\n",
                       "-worker-image openclaw\n",
                       last + "ExecStart=/usr/lib/agentos/agentosd -disk-quota=of\\x66\n",
                       # Security #2110 re-sign: an indented reset and second ExecStart=, a C escape.
                       last + "Restart=on-failure\n  ExecStart=\n  ExecStart=/usr/lib/agentos/agentosd -disk-quota=${DQ}\n",
                       "-worker-image openclaw \\\n        -disk\\x2dquota=of\\x66 x -disk-quota on\n",
                       # Re-sign 3: another spelling of the binary, and a -- before the pair.
                       "-worker-image openclaw \\\n        ${X} -- -disk-quota on\n",
                       "-worker-image openclaw \\\n        -disk-quota\n"):
            with self.subTest(mutant=mutant):
                with self.assertRaises(AssertionError):
                    self.assert_canonical(text.replace(last, mutant))

    def test_the_unit_is_the_only_one_and_has_no_drop_in(self):
        # A unit of the same name at a higher-priority path replaces it wholesale, and a drop-in
        # (agentosd.service.d, or service.d for every service) can reset ExecStart= or set the flag
        # (Security #2110 re-sign item 3). Neither exists anywhere under image/, in any tree mkosi
        # copies; the boot test also reads the unit systemd actually loaded (the quota line's flag=).
        units = sorted(str(f.relative_to(ROOT)) for f in IMG.rglob("agentosd.service"))
        self.assertEqual(units, [str(UNIT.relative_to(ROOT))])
        self.assertFalse(UNIT.is_symlink())
        dirs = ["%s.d" % n for n in finalize.unit_dropin_names("agentosd.service")] + ["service.d"]
        self.assertIn("agentosd.service.d", dirs)
        found = sorted(str(f.relative_to(ROOT)) for d in dirs for f in IMG.rglob(d))
        self.assertEqual(found, [])


class BootReportQuotaTest(unittest.TestCase):
    """boot-report says whether root carries project quotas, read from the mount itself."""

    def report(self, fstype, options, findmnt_fails=False, exec_start=EXEC % CANON):
        with tempfile.TemporaryDirectory() as t:
            t = pathlib.Path(t)
            (t / "net").mkdir()
            stub(t, "sleep", ":")
            stub(t, "ip", ":")
            stub(t, "systemd-bless-boot", "echo good")
            (t / "exec").write_text(exec_start + "\n")
            stub(t, "systemctl", 'case "$1" in show) [ -s %s ] && cat %s || exit 1 ;; *) echo inactive ;; esac'
                 % (t / "exec", t / "exec"))
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

    def test_the_flag_is_on_only_for_the_canonical_command(self):
        c = CANON
        for exec_start, want in ((EXEC % c, "on"),
                                 (EXEC % (c + " -disk-quota=${DQ}"), "overridden"),
                                 (EXEC % c.replace("-disk-quota on", "-disk-quota=off x -disk-quota on"),
                                  "overridden"),
                                 (EXEC % (c + " -image x=/y"), "overridden"),
                                 (EXEC % c[:-len(" -disk-quota on")], "overridden"),
                                 (EXEC % "", "overridden"),
                                 (EXEC % c + " " + EXEC % c, "overridden"),
                                 # Delta L3 rounds: quoted words holding " ; " or faking the
                                 # next field, a variable, another wrapper or binary path.
                                 (EXEC % (c + " ; x -disk-quota=off"), "overridden"),
                                 (EXEC % (c + " ; ignore_errors=no"), "overridden"),
                                 (EXEC % c.replace("-owner ${AGENTOS_OWNER}", "-owner $A"), "overridden"),
                                 (EXEC % c.replace("with-uids /usr", "other /usr"), "overridden"),
                                 (EXEC.replace("path=/usr/lib/agentos/with-uids", "path=/bin/other") % c,
                                  "overridden"),
                                 (EXEC.replace("ignore_errors=no", "ignore_errors=yes") % c, "overridden"),
                                 # Security re-sign 3: another spelling of the binary, a -- before the pair.
                                 (EXEC % c.replace("lib/agentos/agentosd", "lib/agentos//agentosd"),
                                  "overridden"),
                                 (EXEC % c.replace("-disk-quota on", "${X} -- -disk-quota on"), "overridden"),
                                 ("", "unknown")):
            with self.subTest(exec_start=exec_start):
                q = self.quota_line(self.report("ext4", "rw,prjquota", exec_start=exec_start))
                self.assertEqual(q, "agentos-quota: root=ext4 prjquota flag=" + want)

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
