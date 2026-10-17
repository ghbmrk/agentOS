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
EXEC = ("{ path=/usr/lib/agentos/with-uids ; argv[]=/usr/lib/agentos/with-uids /usr/lib/agentos/agentosd "
        "-owner ${AGENTOS_OWNER} -worker-image openclaw %s ; ignore_errors=no ; start_time=[n/a] ; "
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

# An ExecStart word systemd passes through unchanged: no quote, backslash, specifier (%) or bare $, so
# str.split() is systemd's word splitting. ${NAME} is allowed only where VAR_SLOTS says.
WORD = re.compile(r"(?:[A-Za-z0-9/_.,=:@+-]|\$\{[A-Za-z_][A-Za-z0-9_]*\})+")
# agentosd's bool flags, which take no next word (Go's flag package); every other flag does.
BOOLS = set(re.findall(r'flag\.Bool(?:Var)?\((?:&[\w.]+, )?"([^"]+)"',
                       (ROOT / "broker/cmd/agentosd/main.go").read_text()))
AGENTOSD = "/usr/lib/agentos/agentosd"


def stub(d, name, body):
    f = d / name
    f.write_text("#!/bin/sh\n" + body + "\n")
    f.chmod(0o755)


def off_uses(text):
    return OFF.findall(text)


def go_flags(args):
    """Why Go's flag package, reading agentosd's ARGS, might not reach the last pair as the unit means
    it (empty when it does). Every word in a flag position is a single-dash flag name, so no `--`,
    positional or variable stops parsing or turns into a flag; a non-bool flag takes the next word;
    a variable is only -owner's value as the first flag, a slot no earlier word can shift (Security
    #2110 re-sign 2)."""
    out, i = [], 0
    while i < len(args):
        w = args[i]
        if not re.fullmatch(r"-[a-z][a-z0-9-]*", w):
            return out + ["word %d %r is not a flag name; Go stops or reads it as a flag" % (i, w)]
        if w[1:] in BOOLS:
            i += 1
            continue
        if i + 1 == len(args):
            return out + ["%s has no value" % w]
        v = args[i + 1]
        if "$" in v and not (i == 0 and w == "-owner"):
            out.append("%s %s: a variable only as -owner's value, first" % (w, v))
        i += 2
    return out


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
        # anything before it (Security #2110 point 1). The unit is read as systemd reads it
        # (indented keys, continuations, comments), with one ExecStart= and no reset; its words are
        # plain, so splitting matches systemd's; disk-quota is in no other word, so nothing before
        # the last pair can set it, and a variable fills only a string flag's value, so its content
        # is never read as a flag (re-sign items 1 and 2).
        starts = [v for sec, k, v in finalize.config_lines(unit_text.encode())
                  if sec == "Service" and k == "ExecStart"]
        self.assertEqual(len(starts), 1, starts)
        argv = starts[0].split()
        bad = [w for w in argv if not WORD.fullmatch(w)]
        self.assertEqual(bad, [], argv)
        self.assertEqual(argv[-2:], ["-disk-quota", "on"], argv)
        self.assertEqual(sum("disk-quota" in a for a in argv), 1, argv)
        self.assertIn(AGENTOSD, argv)
        self.assertEqual(go_flags(argv[argv.index(AGENTOSD) + 1:]), [], argv)

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
                       last + "ExecStart=/usr/lib/agentos/agentosd -disk-quota=of\\x66\n",
                       # Security #2110 re-sign: an indented reset and second ExecStart=, a C escape
                       # before a positional, a quoted word, a variable read as flags.
                       last + "Restart=on-failure\n  ExecStart=\n  ExecStart=/usr/lib/agentos/agentosd -disk-quota=${DQ}\n",
                       "-worker-image openclaw \\\n        -disk\\x2dquota=of\\x66 x -disk-quota on\n",
                       "-worker-image openclaw \\\n        \"-x y\" -disk-quota on\n",
                       "-worker-image openclaw \\\n        -modem-bridge ${X} x -disk-quota on\n",
                       "-worker-image openclaw \\\n        %i -disk-quota on\n",
                       "-worker-image openclaw \\\n        $X x -disk-quota on\n",
                       # Security #2110 re-sign 2: -owner as another flag's value, then -- or x.
                       "-worker-image openclaw \\\n        -worker-image -owner ${X} -- -disk-quota on\n",
                       "-worker-image openclaw \\\n        -worker-image -owner ${X} x -disk-quota on\n",
                       "-worker-image openclaw \\\n        -owner-message -owner ${X} -disk-quota on\n",
                       "-worker-image openclaw \\\n        -disk-quota\n"):
            with self.subTest(mutant=mutant):
                with self.assertRaises(AssertionError):
                    self.assert_quota_last_and_once(text.replace(last, mutant))

    def test_the_unit_is_the_only_one_and_has_no_drop_in(self):
        # A unit of the same name at a higher-priority path replaces it wholesale, and a drop-in
        # (agentosd.service.d, or service.d for every service) can reset ExecStart= or set the flag
        # (Security #2110 re-sign item 3). Neither exists anywhere under image/, in any tree mkosi
        # copies; the boot test also reads the unit systemd actually loaded (agentos-quota-flag).
        units = sorted(str(f.relative_to(ROOT)) for f in IMG.rglob("agentosd.service"))
        self.assertEqual(units, [str(UNIT.relative_to(ROOT))])
        self.assertFalse(UNIT.is_symlink())
        dirs = ["%s.d" % n for n in finalize.unit_dropin_names("agentosd.service")] + ["service.d"]
        self.assertIn("agentosd.service.d", dirs)
        found = sorted(str(f.relative_to(ROOT)) for d in dirs for f in IMG.rglob(d))
        self.assertEqual(found, [])


class BootReportQuotaTest(unittest.TestCase):
    """boot-report says whether root carries project quotas, read from the mount itself."""

    def report(self, fstype, options, findmnt_fails=False, exec_start=EXEC % "-disk-quota on"):
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

    def test_the_flag_is_on_only_for_one_command_ending_quotas_on(self):
        on = "-disk-quota on"
        for exec_start, want in ((EXEC % on, "on"),
                                 (EXEC % (on + " -disk-quota=${DQ}"), "overridden"),
                                 (EXEC % ("-disk-quota=off x " + on), "overridden"),
                                 (EXEC % (on + " -image x=/y"), "overridden"),
                                 (EXEC % "", "overridden"),
                                 (EXEC % on + " " + EXEC % on, "overridden"),
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
