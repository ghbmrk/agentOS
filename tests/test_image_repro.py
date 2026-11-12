"""IMG-2: the initrd is reproducible, and the two-runner check fails on any initrd difference.

The image is built on two runners and compared by .github/workflows/image.yml's reproduce job;
these tests hold the pieces that job and the build rely on.
"""
# REQ: UPD-1a
import gzip
import hashlib
import importlib.machinery
import importlib.util
import ast
import contextlib
import io
import json
import os
import pathlib
import re
from shlex import quote as shlex_quote
import shutil
import subprocess
import tempfile
import unittest
import unittest.mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
IMG = ROOT / "image"
MK = IMG / "mkosi"
WORKFLOW = ROOT / ".github/workflows/image.yml"


def load(name, path):
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


cm = load("compare_manifests", IMG / "compare_manifests.py")
fin = load("finish_image_repro", IMG / "finish_image.py")
pin = load("initrd_finalize", MK / "initrd/mkosi.finalize")


def newc(members):
    """A newc cpio archive of MEMBERS, (name, body, mtime) each, as cpio --format=newc writes it."""
    out = b""
    for i, (n, body, mtime) in enumerate(list(members) + [("TRAILER!!!", b"", 0)]):
        name = n.encode() + b"\0"
        hdr = b"070701" + b"".join(b"%08X" % v for v in (i, 0o100644, 0, 0, 1, mtime, len(body), 0, 0, 0, 0,
                                                          len(name), 0))
        out += hdr + name
        out += b"\0" * (-len(out) % 4) + body
        out += b"\0" * (-len(out) % 4)
    return out


def assert_one_line_each(case, out):
    """Every line of OUT is printable ASCII and none is an Actions workflow command (#4648)."""
    for ln in out.splitlines():
        case.assertTrue(ln.isascii() and ln.isprintable(), ln)
        case.assertFalse(ln.lstrip().startswith("::"), ln)


EVIL = "x\n::error::forged\x1b]0;t\x07"
EVIL_SHOWN = '"x\\n::error::forged\\u001b]0;t\\u0007"'


BASE = [("usr", b"", 100), ("usr/lib/systemd/systemd", b"elf", 100), ("etc/shadow", b"root:!:20000::::::\n", 100)]


class InitrdDiffTest(unittest.TestCase):
    """The reproduce job names the member that differs, so the next fix is targeted."""

    def test_same_members_no_lines(self):
        self.assertEqual(cm.initrd_diff(newc(BASE), newc(BASE)), [])

    def test_content_and_header_differences_are_named(self):
        b = [BASE[0], ("usr/lib/systemd/systemd", b"elf", 101), ("etc/shadow", b"root:!:20001::::::\n", 100)]
        lines = cm.initrd_diff(newc(BASE), newc(b))
        self.assertIn('"usr/lib/systemd/systemd": mtime 100/101', lines)
        self.assertIn('"etc/shadow": content', lines)
        self.assertEqual(len(lines), 2)

    def test_members_only_on_one_side(self):
        lines = cm.initrd_diff(newc(BASE + [("var/log/dpkg.log", b"x", 1)]), newc(BASE))
        self.assertEqual(lines, ['only in a: "var/log/dpkg.log"'])

    def test_member_names_are_escaped(self):
        # #4612: an initrd member name cannot forge a log line or an Actions command either.
        evil = "etc/x\n::error::forged\x1b]0;t\x07"
        lines = cm.initrd_diff(newc(BASE + [(evil, b"x", 1)]), newc(BASE + [(evil, b"y", 1)]))
        self.assertEqual(lines, ['"etc/x\\n::error::forged\\u001b]0;t\\u0007": content'])
        lines = cm.initrd_diff(newc(BASE), newc(BASE + [(evil, b"x", 1)]))
        self.assertEqual([ln.splitlines() for ln in lines], [[lines[0]]])
        self.assertTrue(lines[0].startswith('only in b: "etc/x\\n') and lines[0].isprintable(), lines)

    def test_truncated_member_error_is_escaped(self):
        # #4648: the truncated-cpio error names the member through shown() too.
        data = newc([("etc/" + EVIL, b"y" * 64, 1)])
        cut = 110 + len(("etc/" + EVIL).encode()) + 1
        cut += -cut % 4 + 10
        with self.assertRaises(ValueError) as c:
            cm.initrd_members(data[:cut])
        self.assertEqual(str(c.exception), 'initrd: truncated cpio file "etc/%s' % EVIL_SHOWN[1:])
        rc, out = self.run_compare(data[:cut], data)
        self.assertEqual(rc, 1)
        self.assertIn('  unreadable initrd: initrd: truncated cpio file "etc/%s' % EVIL_SHOWN[1:], out.splitlines())
        assert_one_line_each(self, out)

    def test_unreadable_file_path_is_escaped(self):
        with tempfile.TemporaryDirectory() as d:
            fa = pathlib.Path(d) / EVIL
            r = subprocess.run(["python3", str(IMG / "compare_manifests.py"), "--initrd", str(fa), str(fa)],
                               capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stdout, "MISMATCH initrd: cannot read %s: No such file or directory\n"
                         % json.dumps(str(fa)))
        assert_one_line_each(self, r.stdout)

    def test_reads_compressed_and_concatenated_archives(self):
        # The entry's initrd is compressed archives back to back, as the kernel unpacks them.
        a = gzip.compress(newc(BASE[:1]), mtime=0) + b"\0" * 4 + newc(BASE[1:])
        names = [k for k, _, _ in cm.initrd_members(a)]
        self.assertEqual(names, [n for n, _, _ in BASE])
        self.assertEqual(cm.initrd_diff(a, newc(BASE[:1]) + newc(BASE[1:])), [])

    def test_repeated_name_kept_apart(self):
        names = [k for k, _, _ in cm.initrd_members(newc(BASE[:1]) + newc(BASE[:1]))]
        self.assertEqual(names, ["usr", "usr#2"])

    def test_bad_archive_raises(self):
        for bad in (b"junk", newc(BASE)[:-20], newc(BASE).replace(b"070701", b"07070X", 1)):
            with self.assertRaises(ValueError):
                cm.initrd_members(bad)

    def run_compare(self, a, b):
        with tempfile.TemporaryDirectory() as d:
            fa, fb = pathlib.Path(d) / "a", pathlib.Path(d) / "b"
            fa.write_bytes(a)
            fb.write_bytes(b)
            r = subprocess.run(["python3", str(IMG / "compare_manifests.py"), "--initrd", str(fa), str(fb)],
                               capture_output=True, text=True)
        return r.returncode, r.stdout

    def test_cli_same_bytes_pass(self):
        rc, out = self.run_compare(newc(BASE), newc(BASE))
        self.assertEqual(rc, 0, out)
        self.assertIn("same initrd", out)

    def test_cli_fails_on_any_byte_difference(self):
        rc, out = self.run_compare(newc(BASE), newc(BASE[:2] + [("etc/shadow", b"root:!:20001::::::\n", 100)]))
        self.assertEqual(rc, 1)
        self.assertIn("MISMATCH initrd", out)
        self.assertIn('"etc/shadow": content', out)
        # Same members, different compressed bytes: still a failure, said as such.
        rc, out = self.run_compare(gzip.compress(newc(BASE), mtime=0), gzip.compress(newc(BASE), mtime=1))
        self.assertEqual(rc, 1)
        self.assertIn("every member alike", out)

    def test_cli_fails_on_missing_or_unreadable(self):
        with tempfile.TemporaryDirectory() as d:
            r = subprocess.run(["python3", str(IMG / "compare_manifests.py"), "--initrd", d + "/a", d + "/b"],
                               capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("MISMATCH initrd", r.stdout)
        rc, out = self.run_compare(b"junk", b"junk2")
        self.assertEqual(rc, 1)
        self.assertIn("unreadable initrd", out)


class CpioHeaderFieldTest(unittest.TestCase):
    """#4662: both initrd readers take a newc header field only as exactly 8 hex digits. int(x, 16)
    alone also takes a sign, spaces, 0x and _, and a negative size moved the reader back onto its own
    header, so the reproduce job and the build's Bluetooth check looped until their timeout."""
    # REQ: UPD-1a

    BAD = (b"-0000070", b"+0000070", b" 0000070", b"0000070 ", b"0x000070", b"0000_070", b"\t0000070",
           b"0000007\n", b"-0000000")

    def setUp(self):
        import signal
        signal.signal(signal.SIGALRM, lambda *_: self.fail("reader did not stop"))
        signal.alarm(10)
        self.addCleanup(signal.alarm, 0)

    def test_signed_or_padded_size_refused_by_both_readers(self):
        for field in (6, 11):  # filesize, namesize: the two that move the offset
            for v in self.BAD:
                data = newc(BASE)
                data = data[:6 + 8 * field] + v + data[14 + 8 * field:]
                with self.subTest(field=field, value=v):
                    with self.assertRaises(ValueError) as c:
                        cm.initrd_members(data)
                    self.assertEqual(str(c.exception), "initrd: bad cpio header at offset 0")
                    with self.assertRaises(ValueError) as c:
                        fin.cpio_names(data)
                    self.assertEqual(str(c.exception), "initrd: bad cpio header at offset 0")

    def test_every_field_is_checked_at_its_own_offset(self):
        # A bad field in a later member's header names that header's offset, in either reader.
        data = newc(BASE)
        second = (110 + len(b"usr\0") + 3) & ~3
        for field in range(13):
            start = second + 6 + 8 * field
            bad = data[:start] + b"-0000001" + data[start + 8:]
            with self.subTest(field=field):
                with self.assertRaises(ValueError) as c:
                    cm.initrd_members(bad)
                self.assertEqual(str(c.exception), "initrd: bad cpio header at offset %d" % second)
                with self.assertRaises(ValueError) as c:
                    fin.cpio_names(bad)
                self.assertEqual(str(c.exception), "initrd: bad cpio header at offset %d" % second)

    def test_lower_case_hex_still_reads(self):
        # cpio(5) fields are hex in either case; mode 0o100644 is 000081A4.
        lower = newc(BASE).replace(b"000081A4", b"000081a4")
        self.assertNotEqual(lower, newc(BASE))
        self.assertEqual([k for k, _, _ in cm.initrd_members(lower)], [n for n, _, _ in BASE])
        self.assertEqual(fin.cpio_names(lower), [n for n, _, _ in BASE])

    def test_cli_fails_at_once(self):
        data = newc(BASE)
        bad = data[:54] + b"-0000070" + data[62:]
        with tempfile.TemporaryDirectory() as d:
            fa, fb = pathlib.Path(d) / "a", pathlib.Path(d) / "b"
            fa.write_bytes(bad)
            fb.write_bytes(data)
            r = subprocess.run(["python3", str(IMG / "compare_manifests.py"), "--initrd", str(fa), str(fb)],
                               capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 1)
        self.assertIn("  unreadable initrd: initrd: bad cpio header at offset 0", r.stdout.splitlines())


class ErrorLineEscapeTest(unittest.TestCase):
    """#4648: every error line names a path, a package or a bad entry escaped, as one line."""

    def run_cli(self, *args):
        r = subprocess.run(["python3", str(IMG / "compare_manifests.py")] + [str(a) for a in args],
                           capture_output=True, text=True)
        assert_one_line_each(self, r.stdout)
        return r.returncode, r.stdout

    def manifest(self, d, pkgs):
        d.mkdir(parents=True)
        (d / "agentos_1.manifest").write_text(json.dumps({"packages": pkgs}))
        return d

    def test_manifest_dir_and_entry(self):
        with tempfile.TemporaryDirectory() as t:
            good = self.manifest(pathlib.Path(t) / "good", [{"name": "systemd", "version": "257"}])
            rc, out = self.run_cli(pathlib.Path(t) / EVIL, good)
            self.assertEqual(rc, 1)
            self.assertEqual(out, "MISMATCH package manifest: %s: expected one *.manifest, found 0\n"
                             % json.dumps(str(pathlib.Path(t) / EVIL)))
            bad = self.manifest(pathlib.Path(t) / "bad", [{"name": EVIL}])
            rc, out = self.run_cli(bad, good)
            self.assertEqual(rc, 1)
            self.assertTrue(out.endswith(': package entry without a name and version: {"name": %s}\n' % EVIL_SHOWN),
                            out)

    def test_package_names_that_differ(self):
        with tempfile.TemporaryDirectory() as t:
            a = self.manifest(pathlib.Path(t) / "a", [{"name": EVIL, "version": "1"}])
            b = self.manifest(pathlib.Path(t) / "b", [{"name": "systemd", "version": "257", "architecture": "amd64"}])
            rc, out = self.run_cli(a, b)
        self.assertEqual(rc, 0)
        self.assertEqual(out.splitlines()[1:], ["package manifests differ: 1 only in a, 1 only in b",
                                                '  only in a: [%s, "1", ""]' % EVIL_SHOWN,
                                                '  only in b: ["systemd", "257", "amd64"]'])

    def test_package_diff_keeps_each_name(self):
        # #4729: each package prints on its own capped line, so a long name never hides the next.
        names = [AT_CAP, PAST_CAP, "b" + PAST_CAP, "c" * 10 ** 5, "systemd"]
        with tempfile.TemporaryDirectory() as t:
            a = self.manifest(pathlib.Path(t) / "a", [{"name": n, "version": "1"} for n in names])
            b = self.manifest(pathlib.Path(t) / "b", [{"name": "x", "version": "1"}])
            rc, out = self.run_cli(a, b)
        self.assertEqual(rc, 0)
        lines = out.splitlines()
        self.assertEqual(lines[1], "package manifests differ: 5 only in a, 1 only in b")
        self.assertEqual(lines[2:], ["  only in a: %s" % cm.shown([n, "1", ""]) for n in sorted(names)]
                         + ['  only in b: ["x", "1", ""]'])
        self.assertLessEqual(max(map(len, lines)), cm.SHOWN_CAP + len("  only in a: "))

    def test_package_diff_counts_past_the_limit(self):
        with tempfile.TemporaryDirectory() as t:
            a = self.manifest(pathlib.Path(t) / "a", [{"name": "p%03d" % i, "version": "1"} for i in range(250)])
            b = self.manifest(pathlib.Path(t) / "b", [{"name": "x", "version": "1"}])
            rc, out = self.run_cli(a, b)
        lines = out.splitlines()
        self.assertEqual(lines[2], '  only in a: ["p000", "1", ""]')
        self.assertEqual(lines[2 + 199], '  only in a: ["p199", "1", ""]')
        self.assertEqual(lines[2 + 200:], ["  ... and 51 more"])

    def test_usr_list_path_and_line(self):
        with tempfile.TemporaryDirectory() as t:
            fa = pathlib.Path(t) / EVIL
            rc, out = self.run_cli("--usr", fa, fa)
            self.assertEqual((rc, out), (1, "MISMATCH /usr list: %s: unreadable /usr list: No such file or directory\n"
                                         % json.dumps(str(fa))))
            fb = pathlib.Path(t) / "b"
            fb.write_text(json.dumps([EVIL]) + "\n")
            rc, out = self.run_cli("--usr", fb, fb)
            self.assertEqual(rc, 1)
            self.assertTrue(out.endswith(": bad /usr list line [%s]\n" % EVIL_SHOWN), out)

    def test_say_quotes_a_line_that_missed_shown(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            cm.say("ok line")
            cm.say("MISMATCH " + EVIL)
            cm.say("  ::add-mask::x")
            cm.say("::error::x")
        self.assertEqual(buf.getvalue(), 'ok line\n%s\n"  ::add-mask::x"\n"::error::x"\n'
                         % json.dumps("MISMATCH " + EVIL))


def printed(fn, *args):
    """The lines FN(*ARGS) prints."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        fn(*args)
    return buf.getvalue().splitlines()


def mark(s):
    """The marker cut() ends a cut S with: its full length and the head of its sha256."""
    return "... (%d chars, sha256 %s)" % (len(s), hashlib.sha256(s.encode()).hexdigest()[:16])


# The longest value shown() prints whole, and the shortest it cuts (#4729: each site at both).
AT_CAP, PAST_CAP = "a" * (cm.SHOWN_CAP - 2), "a" * (cm.SHOWN_CAP - 1)


class ShownCapTest(unittest.TestCase):
    """#4693, #4728: no value read from a build prints longer than SHOWN_CAP characters, and no
    line longer than LINE_CAP; a cut value carries a digest of the whole value."""

    def test_at_the_cap_prints_whole(self):
        self.assertEqual(cm.shown(AT_CAP), json.dumps(AT_CAP))
        self.assertEqual(len(cm.shown(AT_CAP)), cm.SHOWN_CAP)

    def test_past_the_cap_is_cut_to_exactly_the_cap(self):
        for v in (PAST_CAP, ["b"] * cm.SHOWN_CAP, "c" * 10 ** 6):
            with self.subTest(n=len(json.dumps(v))):
                s = json.dumps(v)
                out = cm.shown(v)
                self.assertEqual(len(out), cm.SHOWN_CAP)
                self.assertEqual(out, s[:cm.SHOWN_CAP - len(mark(s))] + mark(s))

    def test_values_that_share_a_head_print_differently(self):
        a, b = cm.shown("q" * 2000 + "A"), cm.shown("q" * 2000 + "B")
        self.assertNotEqual(a, b)
        self.assertEqual(a[:a.index("...")], b[:b.index("...")])

    def test_cut_escapes_stay_one_printable_line(self):
        out = cm.shown(EVIL * 1000)
        self.assertTrue(out.isascii() and out.isprintable(), out)
        self.assertEqual(len(out), cm.SHOWN_CAP)

    def test_say_caps_a_line_that_missed_shown(self):
        line = "MISMATCH \n" + "x" * 10 ** 6
        self.assertEqual(printed(cm.say, line), [cm.shown(line)])
        self.assertEqual(len(cm.shown(line)), cm.SHOWN_CAP)

    def test_say_caps_a_plain_line(self):
        whole = "z" * cm.LINE_CAP
        self.assertEqual(printed(cm.say, whole), [whole])
        long = whole + "z"
        self.assertEqual(printed(cm.say, long), [long[:cm.LINE_CAP - len(mark(long))] + mark(long)])
        self.assertEqual(len(printed(cm.say, "z" * 10 ** 6)[0]), cm.LINE_CAP)

    def test_the_widest_usr_line_prints_whole(self):
        # A path and every field's two values each past the cap: say() never cuts the line.
        fields = fin.USR_LIST_FIELDS[1:]
        a = {"q" * 5000: {f: "A" * 5000 for f in fields}}
        b = {"q" * 5000: {f: "B" * 5000 for f in fields}}
        line = "  " + cm.usr_diff(a, b)[0]
        self.assertLessEqual(len(line), cm.LINE_CAP)
        self.assertEqual(printed(cm.say, line), [line])

    def test_json_dumps_only_inside_shown(self):
        # #4729: every value printed goes through shown(); a bare json.dumps elsewhere fails here.
        tree = ast.parse((IMG / "compare_manifests.py").read_text())
        inside = set()
        for fn in ast.walk(tree):
            if isinstance(fn, ast.FunctionDef) and fn.name == "shown":
                inside = {id(n) for n in ast.walk(fn)}
        uses = [n for n in ast.walk(tree) if isinstance(n, ast.Attribute) and n.attr == "dumps"]
        self.assertTrue(uses)
        self.assertEqual([n.lineno for n in uses if id(n) not in inside], [])
        self.assertFalse([n for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module == "json"])

    def test_usr_field_values_go_through_shown(self):
        for v in (AT_CAP, PAST_CAP):
            with self.subTest(n=len(v)):
                self.assertEqual(cm.usr_diff({"p": {"digest": v}}, {"p": {"digest": "x"}}),
                                 ['"p": digest %s/"x"' % cm.shown(v)])


class ShadowPinTest(unittest.TestCase):
    """systemd-firstboot stamps root's entry with today's date; the initrd's finalize pins it."""

    def test_pins_every_last_change_field(self):
        text = "root:!:20381:0:99999:7:::\nsystemd-network:!*:20000::::::\n"
        self.assertEqual(pin.pin(text, 19000), "root:!:19000:0:99999:7:::\nsystemd-network:!*:19000::::::\n")

    def test_keeps_empty_field_and_missing_newline(self):
        self.assertEqual(pin.pin("root:!:::::::", 5), "root:!:::::::")
        self.assertEqual(pin.pin("", 5), "")

    def test_refuses_a_line_that_is_not_an_entry(self):
        for bad in ("root:!:1\n", ":!:1::::::\n", "root:!:1:::::::extra\n"):
            with self.assertRaises(ValueError):
                pin.pin(bad, 5)

    def test_finalize_rewrites_buildroot_keeping_mode(self):
        with tempfile.TemporaryDirectory() as d:
            etc = pathlib.Path(d) / "etc"
            etc.mkdir()
            (etc / "shadow").write_text("root:!:20381::::::\n")
            (etc / "shadow").chmod(0o640)
            env = dict(os.environ, BUILDROOT=d, SOURCE_DATE_EPOCH=str(19000 * 86400 + 5))
            r = subprocess.run([str(MK / "initrd/mkosi.finalize")], env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual((etc / "shadow").read_text(), "root:!:19000::::::\n")
            self.assertEqual((etc / "shadow").stat().st_mode & 0o777, 0o640)
            self.assertFalse((etc / "shadow-").exists())

    def test_finalize_refuses_without_epoch(self):
        env = {k: v for k, v in os.environ.items() if k != "SOURCE_DATE_EPOCH"}
        env["BUILDROOT"] = "/nonexistent"
        r = subprocess.run([str(MK / "initrd/mkosi.finalize")], env=env, capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("SOURCE_DATE_EPOCH", r.stderr)


class InitrdConfigTest(unittest.TestCase):
    """The default initrd gets its own include, and drops what differs from build to build."""

    def test_include_is_wired(self):
        conf = (MK / "mkosi.conf").read_text()
        sect = conf[conf.index("[Config]"):conf.index("[Distribution]")]
        self.assertRegex(sect, r"(?m)^InitrdInclude=initrd/$")
        self.assertTrue((MK / "initrd/mkosi.conf").is_file())
        self.assertTrue(os.access(MK / "initrd/mkosi.finalize", os.X_OK))

    def test_build_time_logs_and_caches_are_removed(self):
        conf = (MK / "initrd/mkosi.conf").read_text()
        body = conf[conf.index("RemoveFiles="):]
        entries = [ln.strip() for ln in body.splitlines()[1:] if ln.startswith((" ", "\t")) and ln.strip()]
        # The lvm2 files after these are HOST-1a's (tests/test_image.py HostDiskImageTest).
        self.assertEqual(entries[:2], ["/var/log/*.log", "/var/cache/ldconfig/aux-cache"])


def usr_tree(d, changed=b"v1"):
    """A small /usr tree under D: a file, a hard link to it, a link, a directory and a fifo."""
    root = pathlib.Path(d)
    (root / "lib/agentos").mkdir(parents=True)
    (root / "bin").mkdir()
    (root / "lib/agentos/camdecode").write_bytes(changed)
    (root / "bin/tool").write_bytes(b"elf")
    os.link(root / "bin/tool", root / "bin/tool2")
    (root / "bin/sh").symlink_to("dash")
    os.mkfifo(root / "lib/fifo")
    for p in sorted(root.rglob("*"), reverse=True):
        os.utime(p, ns=(10**9, 10**9), follow_symlinks=False)
    return root


def need_erofs(case):
    """Skip without erofs-utils, unless AGENTOS_REQUIRE_REFERENCE_TOOLS=1 (CI's checks step): fail there."""
    if not (shutil.which("mkfs.erofs") and shutil.which("fsck.erofs")):
        if os.environ.get("AGENTOS_REQUIRE_REFERENCE_TOOLS") == "1":
            case.fail("AGENTOS_REQUIRE_REFERENCE_TOOLS=1 but erofs-utils is not installed")
        case.skipTest("needs erofs-utils")


def mkfs_erofs(d, src, *opts):
    img = pathlib.Path(d) / "usr.raw"
    subprocess.run(["mkfs.erofs", "--quiet", "-T", "1", "-U", "11111111-2222-3333-4444-555555555555", *opts,
                    str(img), str(src)], check=True)
    return img


class UsrListTest(unittest.TestCase):
    """#4059: each build lists every /usr file's hash and metadata, and two lists are diffed."""

    def test_lists_every_entry_sorted_with_its_fields(self):
        with tempfile.TemporaryDirectory() as d:
            rows = [json.loads(ln) for ln in fin.usr_list(usr_tree(d))]
        self.assertEqual([r[0] for r in rows], ["bin", "bin/sh", "bin/tool", "bin/tool2", "lib", "lib/agentos",
                                                "lib/agentos/camdecode", "lib/fifo"])
        by = {r[0]: dict(zip(fin.USR_LIST_FIELDS, r)) for r in rows}
        self.assertEqual(by["lib/agentos/camdecode"]["digest"], hashlib.sha256(b"v1").hexdigest())
        self.assertEqual((by["bin/sh"]["type"], by["bin/sh"]["digest"]), ("l", "dash"))
        self.assertEqual((by["bin/tool"]["nlink"], by["lib/fifo"]["type"], by["lib"]["type"]), (2, "p", "d"))
        self.assertEqual(by["bin/tool"]["mtime_ns"], 10**9)

    def test_diff_names_the_path_and_field(self):
        with tempfile.TemporaryDirectory() as d:
            a = usr_tree(pathlib.Path(d) / "a")
            b = usr_tree(pathlib.Path(d) / "b", changed=b"v2")
            os.chmod(b / "bin/tool", 0o700)
            (b / "bin/new").write_bytes(b"")
            la, lb = (pathlib.Path(d) / n for n in ("a.list", "b.list"))
            la.write_text("\n".join(fin.usr_list(a)) + "\n")
            lb.write_text("\n".join(fin.usr_list(b)) + "\n")
            lines = cm.usr_diff(cm.usr_entries(la), cm.usr_entries(lb))
        self.assertIn('only in b: "bin/new"', lines)
        self.assertTrue(any(ln.startswith('"lib/agentos/camdecode": digest "') for ln in lines), lines)
        self.assertTrue(any(ln.startswith('"bin/tool": mode "0644"/"0700"') for ln in lines), lines)
        # The mtime of bin, changed by the new file, is named too: a timestamp is a cause to fix.
        self.assertTrue(any(ln.startswith('"bin": mtime_ns ') for ln in lines), lines)

    def test_diff_prints_content_differences_first(self):
        # #4471: past the line limit, many time-only differences must not push the one content
        # difference out of the log.
        a = {"d%03d" % i: {"type": "d", "mtime_ns": 1, "digest": ""} for i in range(300)}
        b = {k: dict(v, mtime_ns=2) for k, v in a.items()}
        f = {"type": "f", "mode": "0755", "uid": 0, "gid": 0, "mtime_ns": 1, "nlink": 1, "digest": "aa"}
        for k, ch in (("zz/bin", {"digest": "bb"}), ("zz/gid", {"gid": 5}), ("zz/link", {"nlink": 2}),
                      ("zz/suid", {"mode": "4755"}), ("zz/uid", {"uid": 5})):
            a[k], b[k] = dict(f), dict(f, **ch)
        b["zz/new"] = dict(f)
        lines = cm.usr_diff(a, b)
        # Mode and owner say what a file may do, so they are not cut either; only time and link count are.
        self.assertEqual(lines[:5], ['only in b: "zz/new"', '"zz/bin": digest "aa"/"bb"', '"zz/gid": gid 0/5',
                                     '"zz/suid": mode "0755"/"4755"', '"zz/uid": uid 0/5'])
        self.assertEqual(lines[5:7], ['"d000": mtime_ns 1/2', '"d001": mtime_ns 1/2'])
        self.assertIn('"zz/link": nlink 1/2', cm.usr_diff(a, b, limit=1000))
        self.assertEqual((len(lines), lines[-1]), (201, "... and 106 more"))

    def test_diff_escapes_names_and_values(self):
        # #4612: a path or value holding a newline, a terminal escape or a leading "::" must print
        # as one escaped line, never as a forged log line or a GitHub Actions workflow command.
        evil = "bin/x\n::error::forged\x1b[2J\u2028"
        f = {"type": "f", "mode": "0644", "uid": 0, "gid": 0, "mtime_ns": 1, "nlink": 1, "digest": "aa"}
        a = {evil: dict(f), "bin/y": dict(f), "::warning::a": dict(f)}
        b = {"bin/y": dict(f, digest="bb\n::error::v"), "::warning::b\r": dict(f)}
        lines = cm.usr_diff(a, b)
        self.assertEqual(lines, ['only in a: "::warning::a"',
                                 'only in a: "bin/x\\n::error::forged\\u001b[2J\\u2028"',
                                 'only in b: "::warning::b\\r"',
                                 '"bin/y": digest "aa"/"bb\\n::error::v"'])
        for ln in lines:
            self.assertEqual(ln.splitlines(), [ln])
            self.assertTrue(ln.isascii() and ln.isprintable(), ln)
        # The printed name reads back as the path it names.
        self.assertEqual(json.loads(lines[1][len("only in a: "):]), evil)

    def run_cli(self, ta, tb):
        with tempfile.TemporaryDirectory() as d:
            fa, fb = pathlib.Path(d) / "a", pathlib.Path(d) / "b"
            if ta is not None:
                fa.write_text(ta)
            if tb is not None:
                fb.write_text(tb)
            r = subprocess.run(["python3", str(IMG / "compare_manifests.py"), "--usr", str(fa), str(fb)],
                               capture_output=True, text=True)
        return r.returncode, r.stdout

    def test_cli(self):
        with tempfile.TemporaryDirectory() as d:
            text = "\n".join(fin.usr_list(usr_tree(d))) + "\n"
        rc, out = self.run_cli(text, text)
        self.assertEqual(rc, 0, out)
        self.assertIn("same /usr files (8 entries)", out)
        rc, out = self.run_cli(text, text.replace(hashlib.sha256(b"v1").hexdigest(), "00" * 32))
        self.assertEqual(rc, 1)
        self.assertIn("MISMATCH /usr files", out)
        self.assertIn('"lib/agentos/camdecode": digest', out)
        # Missing, empty, malformed or repeated: a failure, never "same".
        dup = text + text.splitlines()[0] + "\n"
        for ta, tb in ((text, None), ("", ""), (text, "{}\n"), (text, "[1]\n"), (dup, dup)):
            with self.subTest(tb=tb):
                rc, out = self.run_cli(ta, tb)
                self.assertEqual(rc, 1, out)
                self.assertIn("MISMATCH /usr list", out)

    def test_reads_the_erofs_partition_back(self):
        # The list is of what the partition holds, read back the way the build reads its /usr.
        need_erofs(self)
        with tempfile.TemporaryDirectory() as d:
            src = usr_tree(pathlib.Path(d) / "src")
            img, dst = mkfs_erofs(d, src), pathlib.Path(d) / "usr.list"
            self.assertEqual(fin.write_usr_list(img, dst), 8)
            self.assertEqual(dst.read_text(), "\n".join(fin.usr_list(src)) + "\n")
            self.assertEqual([p.name for p in pathlib.Path(d).iterdir() if p.name.startswith(".usr-list-")], [])

    def special_tree(self, d, owners):
        """usr_tree plus a 4755 and a 2755 file, a 2755 and a 1777 directory; OWNERS (root only) gives
        them non-root owners, one past 65535 so its inode is the extended kind."""
        src = usr_tree(pathlib.Path(d) / "src")
        (src / "bin/su").write_bytes(b"suid")
        (src / "bin/wall").write_bytes(b"sgid")
        (src / "lib/group").mkdir()
        (src / "lib/tmp").mkdir()
        for name, mode, uid, gid in (("bin/su", 0o4755, 1234, 5678), ("bin/wall", 0o2755, 0, 5),
                                     ("lib/group", 0o2755, 70000, 70001), ("lib/tmp", 0o1777, 42, 43)):
            if owners:
                os.chown(src / name, uid, gid)  # before chmod: a chown clears setuid and setgid
            os.chmod(src / name, mode)
        for p in sorted(src.rglob("*"), reverse=True):
            os.utime(p, ns=(10**9, 10**9), follow_symlinks=False)
        return src

    def assert_special(self, lines):
        by = {r[0]: dict(zip(fin.USR_LIST_FIELDS, r)) for r in map(json.loads, lines)}
        self.assertEqual([by[p]["mode"] for p in ("bin/su", "bin/wall", "lib/group", "lib/tmp")],
                         ["4755", "2755", "2755", "1777"])
        return by

    def test_records_special_bits_and_owners_as_the_partition_holds_them(self):
        # #4470: fsck.erofs 1.7 extracts a 4755 file as 0755. Any user (CI's checks job is not root):
        # mkfs.erofs offsets every owner, to non-root ids that fit compact inodes, then past 65535,
        # which makes every inode the extended kind.
        need_erofs(self)
        for offset in (1000, 100000):
            with self.subTest(offset=offset), tempfile.TemporaryDirectory() as d:
                src = self.special_tree(d, owners=False)
                img = mkfs_erofs(d, src, "--uid-offset=%d" % offset, "--gid-offset=%d" % (2 * offset))
                dst = pathlib.Path(d) / "l"
                self.assertEqual(fin.write_usr_list(img, dst), 12)
                by = self.assert_special(dst.read_text().splitlines())
                st = src.lstat()
                self.assertEqual({(r["uid"], r["gid"]) for r in by.values()},
                                 {(st.st_uid + offset, st.st_gid + 2 * offset)})

    @unittest.skipUnless(os.geteuid() == 0, "needs root (chown)")
    def test_records_each_entrys_own_non_root_owner(self):
        # Per-entry owners, compact and extended inodes alike: the list equals the source tree's.
        need_erofs(self)
        with tempfile.TemporaryDirectory() as d:
            src = self.special_tree(d, owners=True)
            img, dst = mkfs_erofs(d, src), pathlib.Path(d) / "l"
            fin.write_usr_list(img, dst)
            want = fin.usr_list(src)
            self.assert_special(want)
            self.assertEqual(dst.read_text(), "\n".join(want) + "\n")
            by = {r[0]: r for r in map(json.loads, want)}
            self.assertEqual((by["bin/su"][3:5], by["lib/group"][3:5], by["lib/tmp"][3:5]),
                             ([1234, 5678], [70000, 70001], [42, 43]))

    def test_an_image_the_reader_cannot_read_fails(self):
        need_erofs(self)
        with tempfile.TemporaryDirectory() as d:
            img = mkfs_erofs(d, usr_tree(pathlib.Path(d) / "src"))
            good = img.read_bytes()
            # A later incompat feature: 48-bit layout (0x80, root_nid moves) and metabox (0x100).
            for what, at, value in (("magic", 1024, b"\0\0\0\0"), ("48bit", 1024 + 80, b"\x80"),
                                    ("metabox", 1024 + 81, b"\x01")):
                with self.subTest(what=what):
                    img.write_bytes(good[:at] + value + good[at + len(value):])
                    with self.assertRaises(ValueError):
                        fin.erofs_inodes(img)
            img.write_bytes(good)
            # The extracted copy and the inodes disagree on a path or a type: no list.
            real = fin.erofs_inodes(img)
            for bad in ({**real, "bin/extra": real["bin/tool"]},
                        {**real, "lib/fifo": (0o100644, 0, 0)}):
                with self.subTest(bad=sorted(set(bad.items()) - set(real.items()))), \
                        unittest.mock.patch.object(fin, "erofs_inodes", return_value=bad):
                    with self.assertRaises(ValueError):
                        fin.write_usr_list(img, pathlib.Path(d) / "l")

    def test_build_writes_the_list_and_the_job_compares_it(self):
        src = (IMG / "finish_image.py").read_text()
        self.assertLess(src.index("verify_usr(data, tree, roothash)"),
                        src.index('write_usr_list(data, out / ("agentos_%s.usr.list" % version))'))
        wf = WORKFLOW.read_text()
        rec = wf[wf.index("- name: Release record"):]
        rec = rec[:rec.index("- uses:")]
        self.assertIn('cp "$RUNNER_TEMP"/out/*.usr.list "$RUNNER_TEMP/rec/"', rec)


def compare_step():
    wf = WORKFLOW.read_text()
    job = wf[wf.index("  reproduce:"):]
    step = job[job.index("- name: Compare"):]
    script = step[step.index("run: |") + len("run: |"):]
    lines = []
    for ln in script.splitlines()[1:]:
        if ln and not ln.startswith(" " * 10):
            break
        lines.append(ln[10:])
    return "\n".join(lines) + "\n"


class ReproduceJobTest(unittest.TestCase):
    """The two-runner check is blocking for the initrd (IMG-2): the Compare step itself, run."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = pathlib.Path(self.tmp.name)
        self.initrd = newc(BASE)
        u = usr_tree(self.d / "usr")
        self.usr = "\n".join(fin.usr_list(u)) + "\n"

    def tearDown(self):
        self.tmp.cleanup()

    def side(self, name, initrd, usr=None, usrhash="ab" * 32, edit=None):
        rec = self.d / "rec" / name
        (rec / "initrd/agentos").mkdir(parents=True)
        (rec / "initrd/agentos/initrd").write_bytes(initrd)
        (rec / "SHA256SUMS").write_text("x\n")
        (rec / "agentos_1.manifest").write_text(json.dumps({"packages": [{"name": "systemd", "version": "257"}]}))
        # The guests' Debian package list (image/guest-base.sh, #5570).
        (rec / "guest").mkdir()
        (rec / "guest/agentos-guest.manifest").write_text(json.dumps({"packages": [{"name": "libpcre2-8-0", "version": "10.45-1"}]}))
        (rec / "agentos_1.usr.list").write_text(usr if usr is not None else self.usr)
        # The apt sources both builds installed from, on the run's one security snapshot (#5021).
        (rec / "agentos.sources").write_text("URIs: https://snapshot.debian.org/archive/debian-security/20261112T180512Z/\n")
        rel = {"usrhash": usrhash, "boot_entry": {"sha256": "cd" * 32},
               "boot": {"agentos/vmlinuz": "ef" * 32, "agentos/initrd": hashlib.sha256(initrd).hexdigest()}}
        if edit:
            edit(rel)
        (rec / "agentos_1.release.json").write_text(json.dumps(rel))

    def run_step(self):
        (self.d / "image").symlink_to(IMG)
        return subprocess.run(["bash", "-e", "-c", compare_step()], cwd=self.d, capture_output=True, text=True)

    def test_same_initrd_passes(self):
        self.side("release-a", self.initrd)
        self.side("release-b", self.initrd)
        r = self.run_step()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('same "agentos/initrd"', r.stdout)
        self.assertIn('same "agentos/vmlinuz"', r.stdout)
        self.assertIn("every output identical", r.stdout)

    def test_missing_or_differing_guest_packages(self):
        # #5570: a build without its guest package list fails; a differing list names the package.
        self.side("release-a", self.initrd)
        self.side("release-b", self.initrd)
        lst = self.d / "rec/release-b/guest/agentos-guest.manifest"
        lst.write_text(lst.read_text().replace("10.45-1", "10.45-2"))
        r = self.run_step()
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("libpcre2-8-0", r.stdout)
        self.assertIn("10.45-2", r.stdout)
        lst.unlink()
        (self.d / "image").unlink()
        r = self.run_step()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("MISMATCH package manifest", r.stdout)

    def test_missing_or_differing_security_snapshot_fails(self):
        # #5021: builds a and b must have read the same apt sources, so the same security snapshot.
        for change in ("differ", "missing"):
            with self.subTest(change=change):
                shutil.rmtree(self.d / "rec", ignore_errors=True)
                self.side("release-a", self.initrd)
                self.side("release-b", self.initrd)
                src = self.d / "rec/release-b/agentos.sources"
                if change == "missing":
                    src.unlink()
                else:
                    src.write_text(src.read_text().replace("20261112T180512Z", "20261112T000512Z"))
                if not (self.d / "image").exists():
                    (self.d / "image").symlink_to(IMG)
                r = subprocess.run(["bash", "-e", "-c", compare_step()], cwd=self.d, capture_output=True, text=True)
                self.assertNotEqual(r.returncode, 0, r.stdout)
                self.assertNotIn("20261112T", r.stdout + r.stderr)  # #4648: cmp prints no content

    def test_differing_initrd_fails_and_names_the_member(self):
        self.side("release-a", self.initrd)
        self.side("release-b", newc(BASE[:2] + [("etc/shadow", b"root:!:20001::::::\n", 100)]))
        r = self.run_step()
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn('MISMATCH "agentos/initrd"', r.stdout)
        self.assertIn('"etc/shadow": content', r.stdout)

    def test_differing_usr_file_fails_and_is_named(self):
        self.side("release-a", self.initrd)
        self.side("release-b", self.initrd, usr=self.usr.replace(hashlib.sha256(b"v1").hexdigest(), "00" * 32),
                  usrhash="ef" * 32)
        r = self.run_step()
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn("MISMATCH /usr root hash", r.stdout)
        self.assertIn('"lib/agentos/camdecode": digest', r.stdout)
        self.assertNotIn("every /usr file alike", r.stdout)

    def test_same_files_other_root_hash_says_layout(self):
        self.side("release-a", self.initrd)
        self.side("release-b", self.initrd, usrhash="ef" * 32)
        r = self.run_step()
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn("same /usr files", r.stdout)
        self.assertIn("every /usr file alike: the erofs layout", r.stdout)

    def test_missing_usr_list_fails(self):
        # Same root hash, but a build that wrote no list: the job never reads that as alike.
        self.side("release-a", self.initrd)
        self.side("release-b", self.initrd)
        (self.d / "rec/release-b/agentos_1.usr.list").unlink()
        r = self.run_step()
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn("MISMATCH /usr list", r.stdout)

    def test_boot_file_name_cannot_forge_a_line(self):
        # #4648: a release.json boot key holding a newline and "::error::" fails the job and prints
        # escaped, as one line; it is never word-split or echoed raw.
        evil = "agentos/initrd\n::error::forged initrd"
        add = lambda rel: rel["boot"].update({evil: "12" * 32})  # noqa: E731
        self.side("release-a", self.initrd, edit=add)
        self.side("release-b", self.initrd, edit=add)
        r = self.run_step()
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn("MISMATCH boot file name %s: not a relative path of plain names" % json.dumps(evil),
                      r.stdout.splitlines())
        assert_one_line_each(self, r.stdout)

    def test_boot_file_name_cannot_leave_the_initrd_directory(self):
        for bad in ("../../SHA256SUMS", "/etc/initrd", "agentos/./initrd", "agentos//initrd", "a b/initrd"):
            with self.subTest(bad=bad):
                self.tearDown()
                self.setUp()
                add = lambda rel: rel["boot"].update({bad: "0"})  # noqa: E731
                self.side("release-a", self.initrd, edit=add)
                self.side("release-b", self.initrd)
                r = self.run_step()
                self.assertNotEqual(r.returncode, 0, r.stdout)
                self.assertIn("MISMATCH boot file name %s" % json.dumps(bad), r.stdout)
                self.assertNotIn("MISMATCH initrd", r.stdout)

    def test_huge_boot_file_value_prints_capped(self):
        # #4693: a release record whose boot map value is megabytes of text prints at most
        # SHOWN_CAP characters of it on the MISMATCH line, with its full length.
        big = "z" * (3 * 10 ** 6)
        self.side("release-a", self.initrd, edit=lambda rel: rel["boot"].update({"agentos/vmlinuz": big}))
        self.side("release-b", self.initrd)
        r = self.run_step()
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn('MISMATCH "agentos/vmlinuz" a=%s b="%s"' % (cm.shown(big), "ef" * 32), r.stdout.splitlines())
        self.assertIn(mark(json.dumps(big)), r.stdout)
        self.assertLess(max(len(ln) for ln in r.stdout.splitlines()), 2 * cm.SHOWN_CAP)
        assert_one_line_each(self, r.stdout)

    def release_lines(self):
        return printed(cm.compare_release, self.d / "rec/release-a", self.d / "rec/release-b")

    def test_release_values_go_through_shown(self):
        # #4729: the usrhash, SHA256SUMS and "same <name>" lines print each value through shown(),
        # at the cap and one past it.
        for v in (AT_CAP, PAST_CAP):
            with self.subTest(n=len(v)):
                self.tearDown()
                self.setUp()
                add = lambda rel: rel["boot"].update({v: "12" * 32})  # noqa: E731
                self.side("release-a", self.initrd, usrhash=v, edit=add)
                self.side("release-b", self.initrd, edit=add)
                (self.d / "rec/release-a/SHA256SUMS").write_text(v + "\n")
                lines = self.release_lines()
                for want in ("usrhash a=%s" % cm.shown(v), "  only in a: %s" % cm.shown(v), "same %s" % cm.shown(v)):
                    self.assertIn(want, lines)
                self.assertLessEqual(max(map(len, lines)), cm.SHOWN_CAP + len("  only in a: "))

    def test_a_boot_file_only_one_side_names_fails(self):
        self.side("release-a", self.initrd)
        self.side("release-b", self.initrd, edit=lambda rel: rel["boot"].update({"agentos/extra": "12" * 32}))
        r = self.run_step()
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn('MISMATCH "agentos/extra": not in a\'s release record', r.stdout.splitlines())

    def test_missing_hashes_never_match(self):
        # A record without a /usr root hash or a boot entry hash on both sides is not "the same".
        def drop(rel):
            del rel["usrhash"], rel["boot_entry"]
        self.side("release-a", self.initrd, edit=drop)
        self.side("release-b", self.initrd, edit=drop)
        r = self.run_step()
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn("MISMATCH /usr root hash", r.stdout)
        self.assertIn("MISMATCH boot entry", r.stdout)

    def test_output_differences_are_escaped_and_reported_only(self):
        self.side("release-a", self.initrd)
        self.side("release-b", self.initrd)
        line = "::error::forged\x1b]0;t\x07  agentos_1.img"
        (self.d / "rec/release-b/SHA256SUMS").write_text(line + "\n")
        r = self.run_step()
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("outputs differ (SHA256SUMS, reported only):", r.stdout.splitlines())
        self.assertIn("  only in b: %s" % json.dumps(line), r.stdout.splitlines())
        assert_one_line_each(self, r.stdout)

    def test_unreadable_sha256sums_names_the_build_and_is_reported_only(self):
        self.side("release-a", self.initrd)
        self.side("release-b", self.initrd)
        (self.d / "rec/release-b/SHA256SUMS").unlink()
        r = self.run_step()
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("SHA256SUMS of build b unreadable (reported only): No such file or directory",
                      r.stdout.splitlines())
        self.assertNotIn("SHA256SUMS of build a", r.stdout)

    # #4661: every failure path of the --release check has its own case.
    def test_missing_release_record_on_one_side_fails(self):
        self.side("release-a", self.initrd)
        self.side("release-b", self.initrd)
        (self.d / "rec/release-b/agentos_1.release.json").unlink()
        r = self.run_step()
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn('MISMATCH release record: "rec/release-b": expected one *.release.json, found 0',
                      r.stdout.splitlines())

    def test_differing_boot_entry_fails(self):
        self.side("release-a", self.initrd)
        self.side("release-b", self.initrd, edit=lambda rel: rel["boot_entry"].update({"sha256": "ce" * 32}))
        r = self.run_step()
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertEqual([ln for ln in r.stdout.splitlines() if "MISMATCH" in ln], ["MISMATCH boot entry"])

    def test_boot_file_null_on_both_sides_fails(self):
        # A revert of digest() on boot files would let null == null pass.
        null = lambda rel: rel["boot"].update({"agentos/vmlinuz": None})  # noqa: E731
        self.side("release-a", self.initrd, edit=null)
        self.side("release-b", self.initrd, edit=null)
        r = self.run_step()
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertEqual([ln for ln in r.stdout.splitlines() if "MISMATCH" in ln],
                         ['MISMATCH "agentos/vmlinuz" a=null b=null'])

    def test_differing_boot_file_prints_both_hashes(self):
        self.side("release-a", self.initrd)
        self.side("release-b", self.initrd, edit=lambda rel: rel["boot"].update({"agentos/vmlinuz": EVIL}))
        r = self.run_step()
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn('MISMATCH "agentos/vmlinuz" a="%s" b=%s' % ("ef" * 32, EVIL_SHOWN), r.stdout.splitlines())
        assert_one_line_each(self, r.stdout)

    def test_boot_map_with_one_entry_fails(self):
        one = lambda rel: rel["boot"].pop("agentos/vmlinuz")  # noqa: E731
        self.side("release-a", self.initrd, edit=one)
        self.side("release-b", self.initrd, edit=one)
        r = self.run_step()
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertEqual([ln for ln in r.stdout.splitlines() if "MISMATCH" in ln],
                         ["MISMATCH release.json lists no kernel and initrd"])

    def test_usrhash_prints_escaped_as_one_line(self):
        self.side("release-a", self.initrd)
        self.side("release-b", self.initrd, usrhash="ab" * 32 + "\n::error::forged")
        r = self.run_step()
        self.assertNotEqual(r.returncode, 0, r.stdout)
        self.assertIn("usrhash b=%s" % json.dumps("ab" * 32 + "\n::error::forged"), r.stdout.splitlines())
        self.assertIn("MISMATCH /usr root hash", r.stdout.splitlines())
        assert_one_line_each(self, r.stdout)

    def test_only_a_superseded_pr_run_is_cancelled(self):
        # Same-PR cancellation by a first attempt only; reruns, main and manual runs are grouped by
        # run id, so none cancels or displaces another (#5348).
        wf = WORKFLOW.read_text()
        self.assertIn("\nconcurrency:\n  group: ${{ github.workflow }}-${{ startsWith(github.event_name, 'pull_request') && "
                      "github.run_attempt == 1 && "
                      "format('pr-{0}', github.event.pull_request.number) || format('run-{0}', github.run_id) }}\n"
                      "  cancel-in-progress: ${{ startsWith(github.event_name, 'pull_request') && github.run_attempt == 1 }}"
                      "\njobs:\n", wf)
        # Cancellation is workflow-wide only: no job sets its own group.
        self.assertEqual(wf.count("concurrency:"), 1)

    def test_no_report_only_path_left(self):
        step = compare_step()
        self.assertNotIn("::warning::", step)
        self.assertNotRegex(step, r"report-only")

    def test_step_prints_nothing_from_the_builds_itself(self):
        # #4648: the step only runs the script, which escapes every name it prints.
        step = compare_step()
        self.assertNotIn("echo", step)
        self.assertNotIn("jq", step)
        self.assertNotIn("$(", step)

    def test_build_hands_the_initrds_to_the_job(self):
        build = (IMG / "build.sh").read_text()
        self.assertIn('dst = out / "initrd" / p', build)
        self.assertLess(build.index("finish_image.py\" \"$OUT\""), build.index('rm -rf "$OUT/initrd"'))
        wf = WORKFLOW.read_text()
        rec = wf[wf.index("- name: Release record"):]
        rec = rec[:rec.index("- uses:")]
        self.assertIn('cp -R "$RUNNER_TEMP"/out/initrd "$RUNNER_TEMP/rec/"', rec)


SNAP = IMG / "security-snapshot.sh"
SOURCES = MK / "mkosi.pkgmngr/etc/apt/sources.list.d/mkosi.sources"
LIVE = "URIs: http://security.debian.org/debian-security"


def fake_tools(d, **scripts):
    """A PATH directory in D holding each NAME=body as an executable sh script, plus the real PATH."""
    b = pathlib.Path(d, "bin")
    b.mkdir()
    for name, body in scripts.items():
        f = b / name.replace("_", "-")
        f.write_text("#!/bin/sh\n" + body)
        f.chmod(0o755)
    return "%s:%s" % (b, os.environ["PATH"])


class SecuritySnapshotTest(unittest.TestCase):
    """IMG-repro-security-pin (#5021): one debian-security snapshot per run, for the image and both guest roots."""
    # REQ: UPD-1a

    def run_snap(self, *args, path=None):
        env = {"PATH": path or os.environ["PATH"]}
        return subprocess.run(["sh", str(SNAP), *args], capture_output=True, text=True, env=env)

    def test_sources_read_security_from_the_one_snapshot(self):
        # The image's apt sources with exactly one line changed: the security stanza's URI, onto that
        # snapshot; the main archive's stanza and every other line stay byte for byte.
        p = self.run_snap("sources", "20261112T180512Z")
        self.assertEqual(p.returncode, 0, p.stderr)
        want = SOURCES.read_text().replace(LIVE, "URIs: https://snapshot.debian.org/archive/debian-security/20261112T180512Z/")
        self.assertEqual(p.stdout, want)
        self.assertEqual(SOURCES.read_text().count(LIVE + "\n"), 1)
        self.assertNotIn("security.debian.org", p.stdout.replace("snapshot.debian.org/archive/debian-security", ""))

    def test_sources_refuse_anything_but_one_timestamp(self):
        for bad in ("", "2026", "20261112T180512", "20261112T180512Z/", "20261112T180512Z\nx",
                    "../20261112T180512Z", "2026111xT180512Z"):
            with self.subTest(bad=bad):
                p = self.run_snap("sources", bad)
                self.assertNotEqual(p.returncode, 0)
                self.assertEqual(p.stdout, "")
        for args in ((), ("sources",), ("sources", "20261112T180512Z", "x"), ("resolve", "x"), ("other",)):
            with self.subTest(args=args):
                p = self.run_snap(*args)
                self.assertNotEqual(p.returncode, 0)
                self.assertEqual(p.stdout, "")

    def test_sources_refuse_a_file_without_one_live_security_stanza(self):
        with tempfile.TemporaryDirectory() as d:
            img = pathlib.Path(d, "image")
            src = img / SOURCES.relative_to(IMG)
            src.parent.mkdir(parents=True)
            shutil.copy(SNAP, img)
            for text in (SOURCES.read_text().replace(LIVE, "URIs: http://deb.debian.org/debian-security"),
                         SOURCES.read_text() + "\nTypes: deb\n" + LIVE + "\n"):
                src.write_text(text)
                p = subprocess.run(["sh", str(img / SNAP.name), "sources", "20261112T180512Z"], capture_output=True, text=True)
                self.assertNotEqual(p.returncode, 0)
                self.assertEqual(p.stdout, "")

    def resolve(self, answer, status=0):
        with tempfile.TemporaryDirectory() as d:
            log = pathlib.Path(d, "args")
            # curl's -w format, with %{redirect_url} as ANSWER, as the only output; the arguments logged.
            py = ("import pathlib, sys\na = sys.argv[1:]\npathlib.Path(%r).write_text('\\n'.join(a))\n"
                  "sys.stdout.write(a[a.index('-w') + 1].replace('%%{redirect_url}', %r))\nsys.exit(%d)\n"
                  % (str(log), answer, status))
            path = fake_tools(d, curl="exec python3 -I -c %s \"$@\"\n" % shlex_quote(py))
            p = self.run_snap("resolve", path=path)
            return p, (log.read_text().splitlines() if log.exists() else [])

    def test_resolve_takes_the_snapshot_the_mirror_redirects_to(self):
        # snapshot.debian.org answers a time between two mirror runs with a redirect to the earlier
        # run's own timestamp; that timestamp, not the asked time, names a snapshot that never changes.
        p, args = self.resolve("https://snapshot.debian.org/archive/debian-security/20261112T180512Z/")
        self.assertEqual((p.returncode, p.stdout), (0, "20261112T180512Z\n"), p.stderr)
        self.assertEqual(args[0], "-q")
        self.assertIn("-f", "".join(a for a in args if re.fullmatch(r"-[A-Za-z]+", a)))
        self.assertEqual(args[args.index("--proto") + 1], "=https")
        self.assertNotIn("-L", args)
        self.assertNotIn("--location", args)
        self.assertRegex(args[-1], r"\Ahttps://snapshot\.debian\.org/archive/debian-security/\d{8}T\d{6}Z/\Z")
        self.assertIn("--retry", args)

    def test_resolve_refuses_any_other_answer(self):
        for answer, status in (("", 0), ("https://snapshot.debian.org/archive/debian/20261112T180512Z/", 0),
                               ("https://evil.example/archive/debian-security/20261112T180512Z/", 0),
                               ("https://snapshot.debian.org/archive/debian-security/20261112T180512Z/x/", 0),
                               ("https://snapshot.debian.org/archive/debian-security/20261112T180512Z", 0),
                               ("https://snapshot.debian.org/archive/debian-security/20261112T180512Z/\n", 0),
                               ("http://snapshot.debian.org/archive/debian-security/20261112T180512Z/", 0),
                               ("https://snapshot.debian.org/archive/debian-security/20261112T180512Z/", 22)):
            with self.subTest(answer=answer, status=status):
                p, _ = self.resolve(answer, status)
                self.assertNotEqual(p.returncode, 0)
                self.assertEqual(p.stdout, "")
                self.assertNotIn("evil", p.stderr)  # #4648: nothing the mirror sent reaches the log

    def test_guest_base_reads_the_sources_it_is_given(self):
        # Both guest roots come from guest-base.sh's one root, so the sources it is handed decide
        # their security packages; with two arguments (ci.yml's test roots) it reads the image's file.
        for extra in ((), ("/given/agentos.sources",)):
            with self.subTest(extra=extra), tempfile.TemporaryDirectory() as d:
                log = pathlib.Path(d, "mm")
                path = fake_tools(d, mmdebstrap='printf "%%s\\n" "$@" > %s\n' % log, timeout='shift; exec "$@"\n',
                                  dpkg_query="exit 0\n")
                p = subprocess.run(["sh", str(IMG / "guest-base.sh"), str(pathlib.Path(d, "root")),
                                    str(pathlib.Path(d, "m.json")), *extra], capture_output=True, text=True,
                                   env={"PATH": path})
                self.assertEqual(p.returncode, 0, p.stderr)
                self.assertEqual(log.read_text().splitlines()[-1], extra[0] if extra else str(SOURCES))
        p = subprocess.run(["sh", str(IMG / "guest-base.sh"), "r", "m", "s", "x"], capture_output=True, text=True)
        self.assertEqual(p.returncode, 2)

    def test_build_hands_one_snapshot_to_the_image_and_the_guests(self):
        b = (IMG / "build.sh").read_text()
        self.assertIn('SECURITY_SNAPSHOT=${AGENTOS_SECURITY_SNAPSHOT-}', b)
        self.assertIn('[ -n "$SECURITY_SNAPSHOT" ] || SECURITY_SNAPSHOT=$(sh "$HERE/security-snapshot.sh" resolve)', b)
        write = b.index('sh "$HERE/security-snapshot.sh" sources "$SECURITY_SNAPSHOT" >"$OUT/agentos.sources"')
        tree = b.index('install -D -m 0644 "$OUT/agentos.sources" "$OUT/pkgmngr/etc/apt/sources.list.d/mkosi.sources"')
        guest = b.index('sh "$HERE/guest-base.sh" "$OUT/guest-base" "$OUT/guest/agentos-guest.manifest" "$OUT/agentos.sources"\n')
        mk = b.index('$MKOSI -C "$HERE/mkosi" -f --package-manager-tree="$OUT/pkgmngr" ')
        self.assertLess(write, tree)
        self.assertLess(tree, guest)
        self.assertLess(guest, mk)
        self.assertEqual(b.count("guest-base.sh\""), 1)
        self.assertEqual(b.count("$MKOSI "), 1)
        # mkosi v24.3 appends a command-line tree after mkosi.pkgmngr and copies trees in order, so
        # this file replaces the committed one for the image and its initrd alike.
        self.assertNotIn("security.debian.org", b.replace("debian-security", ""))

    def test_workflow_resolves_once_for_both_builds(self):
        wf = WORKFLOW.read_text()
        job = wf[wf.index("\n  security-snapshot:\n"):wf.index("\n  build:\n")]
        self.assertIn("timestamp: ${{ steps.resolve.outputs.timestamp }}", job)
        self.assertIn('ts=$(sh image/security-snapshot.sh resolve)', job)
        self.assertIn('echo "timestamp=$ts" >> "$GITHUB_OUTPUT"', job)
        self.assertNotIn("matrix", job)
        build = wf[wf.index("\n  build:\n"):wf.index("\n  reproduce:\n")]
        self.assertIn("    needs: security-snapshot\n", build)
        self.assertIn("AGENTOS_SECURITY_SNAPSHOT: ${{ needs.security-snapshot.outputs.timestamp }}", build)
        self.assertIn('sudo env "PATH=$PATH" "AGENTOS_SECURITY_SNAPSHOT=$AGENTOS_SECURITY_SNAPSHOT" ', build)
        self.assertEqual(build.count('MKOSI=/opt/mkosi/bin/mkosi image/build.sh "$RUNNER_TEMP/out"'), 1)
        self.assertIn('"$RUNNER_TEMP"/out/agentos.sources', build[build.index("- name: Release record"):])
        # The reproduce job holds both builds to the same apt sources, security snapshot included.
        self.assertIn("cmp rec/release-a/agentos.sources rec/release-b/agentos.sources || ok=0", compare_step())


if __name__ == "__main__":
    unittest.main()
