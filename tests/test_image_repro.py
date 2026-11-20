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
        build = (IMG / "finish.sh").read_text()
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

    MIRROR = """import json, pathlib, sys
a = sys.argv[1:]
state = pathlib.Path(sys.argv[0]).with_name("calls")
calls = json.loads(state.read_text()) if state.exists() else []
calls.append(a)
state.write_text(json.dumps(calls))
runs, answers, status, missing = json.loads(pathlib.Path(sys.argv[0]).with_name("mirror.json").read_text())
url = a[-1]
base = "https://snapshot.debian.org/archive/debian-security/"
index = ("/InRelease", "/Packages.xz")
if url.endswith(index):
    sys.exit(22 if url[len(base):len(base) + 16] in missing else 0)
n = sum(1 for c in calls if not c[-1].endswith(index)) - 1
if n < len(answers) and answers[n] is not None:
    loc = answers[n]
else:
    asked = url[len(base):-1]
    loc = base + max(r for r in runs if r <= asked) + "/"
sys.stdout.write(a[a.index("-w") + 1].replace("%{redirect_url}", loc))
sys.exit(status[n] if n < len(status) else 0)
"""

    def resolve(self, runs=("20201112T060000Z", "20201112T120000Z", "20201112T180512Z"), answers=(), status=(),
                missing=()):
        """Run resolve against a model snapshot.debian.org holding RUNS; ANSWERS and STATUS override the
        redirect calls' answers and exit codes in order, and MISSING runs serve no InRelease or Packages.xz."""
        with tempfile.TemporaryDirectory() as d:
            path = fake_tools(d, curl='exec python3 -I "$(dirname "$0")/mirror.py" "$@"\n')
            pathlib.Path(d, "bin/mirror.py").write_text(self.MIRROR)
            pathlib.Path(d, "bin/mirror.json").write_text(json.dumps([runs, answers, status, missing]))
            p = self.run_snap("resolve", path=path)
            calls = pathlib.Path(d, "bin/calls")
            return p, (json.loads(calls.read_text()) if calls.exists() else [])

    def test_resolve_takes_the_run_before_the_newest(self):
        # snapshot.debian.org answers a time between two mirror runs with a redirect to the earlier
        # run's own timestamp, a snapshot that never changes. The newest run may still be importing
        # (#5606: InRelease served, Packages 404), so the pin is the run before it, and the run before
        # that is the fallback (#6198), each checked for the files apt reads first.
        p, calls = self.resolve()
        self.assertEqual((p.returncode, p.stdout), (0, "20201112T120000Z 20201112T060000Z\n"), p.stderr)
        base = "https://snapshot.debian.org/archive/debian-security/"
        self.assertRegex(calls[0][-1], r"\A" + re.escape(base) + r"\d{8}T\d{6}Z/\Z")
        self.assertEqual([c[-1] for c in calls[1:]], [
            base + "20201112T180511Z/", base + "20201112T115959Z/",
            base + "20201112T120000Z/dists/trixie-security/InRelease",
            base + "20201112T120000Z/dists/trixie-security/main/binary-amd64/Packages.xz",
            base + "20201112T060000Z/dists/trixie-security/InRelease",
            base + "20201112T060000Z/dists/trixie-security/main/binary-amd64/Packages.xz"])
        for args in calls:
            self.assertEqual(args[0], "-q")
            self.assertIn("f", "".join(a for a in args if re.fullmatch(r"-[A-Za-z]+", a)))
            self.assertEqual(args[args.index("--proto") + 1], "=https")
            self.assertIn("--retry", args)
            self.assertNotIn("--location", args)
            if args[-1].endswith("/"):
                # A redirect lookup reads where the redirect points and never follows it.
                self.assertNotIn("-L", args)
            else:
                # An index check follows snapshot.debian.org's redirect to the stored file, as apt does,
                # and only over https (#6198: the redirect answered, the file it named was 404).
                self.assertIn("-L", args)
                self.assertEqual(args[args.index("--proto-redir") + 1], "=https")
                self.assertIn("--max-redirs", args)
        # A day's first run steps back across midnight.
        p, calls = self.resolve(runs=("20201111T120000Z", "20201111T235000Z", "20201112T000000Z"))
        self.assertEqual((p.returncode, p.stdout), (0, "20201111T235000Z 20201111T120000Z\n"), p.stderr)
        self.assertEqual(calls[1][-1], base + "20201111T235959Z/")

    def test_resolve_lists_only_runs_that_serve_their_index(self):
        # A candidate that answers 404 for InRelease or Packages.xz is left out, so a build never starts
        # on it; the other still pins the run. Neither serving fails resolve.
        for missing, want in ((("20201112T120000Z",), "20201112T060000Z\n"),
                              (("20201112T060000Z",), "20201112T120000Z\n")):
            with self.subTest(missing=missing):
                p, _ = self.resolve(missing=missing)
                self.assertEqual((p.returncode, p.stdout), (0, want), p.stderr)
        p, _ = self.resolve(missing=("20201112T120000Z", "20201112T060000Z"))
        self.assertNotEqual(p.returncode, 0)
        self.assertEqual(p.stdout, "")
        self.assertIn("neither debian-security snapshot 20201112T120000Z nor 20201112T060000Z serves", p.stderr)

    def pick(self, d, candidates, missing):
        """pick CANDIDATES against the model mirror in D (resolve's), with MISSING runs serving no index."""
        mirror = pathlib.Path(d, "bin/mirror.json")
        runs = json.loads(mirror.read_text())[0] if mirror.exists() else []
        if not mirror.exists():
            fake_tools(d, curl='exec python3 -I "$(dirname "$0")/mirror.py" "$@"\n')
            pathlib.Path(d, "bin/mirror.py").write_text(self.MIRROR)
        mirror.write_text(json.dumps([runs, [], [], list(missing)]))
        return self.run_snap("pick", candidates, path="%s:%s" % (pathlib.Path(d, "bin"), os.environ["PATH"]))

    def test_both_builds_fall_back_to_the_same_previous_run(self):
        # REQ: UPD-1a. #6198: resolve passed, and minutes later the builds' apt got 404 for the pinned
        # snapshot's index. Each build picks again from the run's one list of candidates: the first if
        # it serves now, else the previous mirror run, with a notice; so builds a and b, reading the
        # same mirror, take the same snapshot, and a build never fails on a run apt cannot read.
        first, second = "20201112T120000Z", "20201112T060000Z"
        for missing, want, notice in (((), first, False), ((first,), second, True)):
            with self.subTest(missing=missing), tempfile.TemporaryDirectory() as d:
                picks = [self.pick(d, first + " " + second, missing) for _ in "ab"]
                for p in picks:
                    self.assertEqual((p.returncode, p.stdout), (0, want + "\n"), p.stderr)
                    self.assertEqual("::notice title=debian-security snapshot::%s does not serve its trixie-security "
                                     "index now; this build reads the previous mirror run, %s\n" % (first, second)
                                     if notice else "", p.stderr)
                self.assertEqual(picks[0].stdout, picks[1].stdout)
        with tempfile.TemporaryDirectory() as d:
            # A hand-run build's one timestamp has no fallback; nothing serving fails the build.
            for cands, missing in ((first, (first,)), (first + " " + second, (first, second))):
                p = self.pick(d, cands, missing)
                self.assertNotEqual(p.returncode, 0)
                self.assertEqual(p.stdout, "")
                self.assertIn("no candidate debian-security snapshot", p.stderr)
            p = self.pick(d, first, ())
            self.assertEqual((p.returncode, p.stdout), (0, first + "\n"), p.stderr)

    def test_pick_refuses_anything_but_one_or_two_timestamps(self):
        # Checked before any request; a glob is never expanded against the working directory.
        with tempfile.TemporaryDirectory() as d:
            for bad in ("", " ", "*", "20201112T120000Z *", "20201112T120000Z 20201112T060000Z 20201112T000000Z",
                        "20201112T120000Z x\n::error::forged", "../20201112T120000Z"):
                with self.subTest(bad=bad):
                    p = self.pick(d, bad, ())
                    self.assertEqual(p.returncode, 2)
                    self.assertEqual(p.stdout, "")
                    self.assertNotIn("::error", p.stderr)
                    self.assertFalse(pathlib.Path(d, "bin/calls").exists())
        for args in (("pick",), ("pick", "20201112T120000Z", "20201112T060000Z")):
            p = self.run_snap(*args)
            self.assertEqual((p.returncode, p.stdout), (2, ""))

    def test_resolve_refuses_any_other_answer(self):
        good = "https://snapshot.debian.org/archive/debian-security/20201112T180512Z/"
        bad = ("", "https://snapshot.debian.org/archive/debian/20201112T180512Z/",
               "https://evil.example/archive/debian-security/20201112T180512Z/",
               "https://snapshot.debian.org/archive/debian-security/20201112T180512Z/x/",
               "https://snapshot.debian.org/archive/debian-security/20201112T180512Z",
               "https://snapshot.debian.org/archive/debian-security/20201112T180512Z/\n",
               "http://snapshot.debian.org/archive/debian-security/20201112T180512Z/")
        cases = [dict(answers=(b,)) for b in bad] + [dict(answers=(None, b)) for b in bad]
        cases += [dict(answers=(None, None, b)) for b in bad]
        cases += [dict(answers=(good,), status=(22,)), dict(answers=(None, good), status=(0, 22)),
                  dict(answers=(None, None, good), status=(0, 0, 22))]
        for case in cases:
            with self.subTest(**case):
                p, _ = self.resolve(**case)
                self.assertNotEqual(p.returncode, 0)
                self.assertEqual(p.stdout, "")
                self.assertNotIn("evil", p.stderr)  # #4648: nothing the mirror sent reaches the log

    def test_guest_base_reads_the_sources_it_is_given(self):
        # Both guest roots come from guest-base.sh's one root, so the sources it is handed decide
        # their security packages; with two arguments (ci.yml's test roots) it reads the image's file.
        # It runs from a copy beside a stand-in keyring check (IMG-keyring-pin, #5578), which must run
        # first and stop it when it fails.
        for extra, check in (((), 0), (("/given/agentos.sources",), 0), ((), 1)):
            with self.subTest(extra=extra, check=check), tempfile.TemporaryDirectory() as d:
                log = pathlib.Path(d, "mm")
                img = pathlib.Path(d, "image")
                img.mkdir()
                shutil.copy(IMG / "guest-base.sh", img)
                (img / "debian-archive-keyring.sh").write_text("echo keyring-check >> %s\nexit %d\n" % (log, check))
                path = fake_tools(d, mmdebstrap='printf "%%s\\n" "$@" >> %s\n' % log, timeout='shift; exec "$@"\n',
                                  dpkg_query="exit 0\n")
                p = subprocess.run(["sh", str(img / "guest-base.sh"), str(pathlib.Path(d, "root")),
                                    str(pathlib.Path(d, "m.json")), *extra], capture_output=True, text=True,
                                   env={"PATH": path})
                lines = log.read_text().splitlines()
                self.assertEqual(lines[0], "keyring-check")
                if check:
                    self.assertNotEqual(p.returncode, 0)
                    self.assertEqual(lines, ["keyring-check"])
                    continue
                self.assertEqual(p.returncode, 0, p.stderr)
                default = img / SOURCES.relative_to(IMG)
                self.assertEqual(lines[-1], extra[0] if extra else str(default))
        p = subprocess.run(["sh", str(IMG / "guest-base.sh"), "r", "m", "s", "x"], capture_output=True, text=True)
        self.assertEqual(p.returncode, 2)

    def test_build_hands_one_snapshot_to_the_image_and_the_guests(self):
        b = (IMG / "build.sh").read_text()
        self.assertIn('SECURITY_SNAPSHOT=${AGENTOS_SECURITY_SNAPSHOT-}', b)
        self.assertIn('[ -n "$SECURITY_SNAPSHOT" ] || SECURITY_SNAPSHOT=$(sh "$HERE/security-snapshot.sh" resolve)', b)
        pick = b.index('SECURITY_SNAPSHOT=$(sh "$HERE/security-snapshot.sh" pick "$SECURITY_SNAPSHOT")\n')
        self.assertLess(b.index('resolve)\n'), pick)
        write = b.index('sh "$HERE/security-snapshot.sh" sources "$SECURITY_SNAPSHOT" >"$OUT/agentos.sources"')
        tree = b.index('install -D -m 0644 "$OUT/agentos.sources" "$OUT/pkgmngr/etc/apt/sources.list.d/mkosi.sources"')
        guest = b.index('sh "$HERE/guest-base.sh" "$OUT/guest-base" "$OUT/guest/agentos-guest.manifest" "$OUT/agentos.sources"\n')
        self.assertLess(pick, write)
        self.assertLess(write, tree)
        self.assertLess(tree, guest)
        self.assertEqual(b.count("guest-base.sh\""), 1)
        # build.sh only stages (#4690, D-276); image.yml's build job makes mkosi's package manager tree
        # from the same timestamp and holds it equal to the stage's agentos.sources.
        self.assertNotIn("$MKOSI ", b)
        # mkosi v24.3 appends a command-line tree after mkosi.pkgmngr and copies trees in order, so
        # this file replaces the committed one for the image and its initrd alike.
        self.assertNotIn("security.debian.org", b.replace("debian-security", ""))

    def test_workflow_resolves_once_for_both_builds(self):
        wf = WORKFLOW.read_text()
        job = wf[wf.index("\n  security-snapshot:\n"):wf.index("\n  stage:\n")]
        self.assertIn("snapshots: ${{ steps.resolve.outputs.snapshots }}", job)
        self.assertIn('ts=$(sh image/security-snapshot.sh resolve)', job)
        self.assertIn('echo "snapshots=$ts" >> "$GITHUB_OUTPUT"', job)
        self.assertNotIn("matrix", job)
        stage = wf[wf.index("\n  stage:\n"):wf.index("\n  build:\n")]
        self.assertIn("    needs: security-snapshot\n", stage)
        self.assertIn("AGENTOS_SECURITY_SNAPSHOT: ${{ needs.security-snapshot.outputs.snapshots }}", stage)
        self.assertIn('sudo env "PATH=$PATH" "AGENTOS_SECURITY_SNAPSHOT=$AGENTOS_SECURITY_SNAPSHOT" ', stage)
        self.assertEqual(stage.count('image/build.sh "$RUNNER_TEMP/out"'), 1)
        build = wf[wf.index("\n  build:\n"):wf.index("\n  reproduce:\n")]
        self.assertIn("    needs: [security-snapshot, stage]\n", build)
        # The stage picked one of the run's dates (#6198); the build job holds its pick to them (#6148 Security).
        self.assertIn("SNAPSHOTS: ${{ needs.security-snapshot.outputs.snapshots }}", build)
        self.assertIn('case " $SNAPSHOTS " in\n            *" $AGENTOS_SECURITY_SNAPSHOT "*) [ -n "$AGENTOS_SECURITY_SNAPSHOT" ] ;;', build)
        self.assertIn("AGENTOS_SECURITY_SNAPSHOT=$(sed -n 's|^URIs: https://snapshot\\.debian\\.org/archive/debian-security/", build)
        self.assertIn('sh image/security-snapshot.sh sources "$AGENTOS_SECURITY_SNAPSHOT" > "$RUNNER_TEMP/mkosi.sources"', build)
        self.assertIn('"$RUNNER_TEMP"/out/agentos.sources', build[build.index("- name: Release record"):])
        # The reproduce job holds both builds to the same apt sources, security snapshot included.
        self.assertIn("cmp rec/release-a/agentos.sources rec/release-b/agentos.sources || ok=0", compare_step())


ENF = IMG / "enforcer"
ENF_SOURCES = ENF / "mkosi/mkosi.pkgmngr/etc/apt/sources.list.d/mkosi.sources"


class SecuritySnapshotEdgeTest(unittest.TestCase):
    """IMG-security-pin-fu (#5825): the resolver's edge cases, the hand-run build's error, and the enforcer's pin."""
    # REQ: UPD-1a
    run_snap = SecuritySnapshotTest.run_snap
    MIRROR = SecuritySnapshotTest.MIRROR

    def frozen(self, now, runs, status=()):
        """resolve with `date` frozen at NOW (date -d still computes); returns the run and the calls."""
        with tempfile.TemporaryDirectory() as d:
            real = shutil.which("date")
            path = fake_tools(d, curl='exec python3 -I "$(dirname "$0")/mirror.py" "$@"\n',
                              date='case " $* " in *" -d "*) exec %s "$@" ;; esac\necho %s\n' % (real, now))
            pathlib.Path(d, "bin/mirror.py").write_text(self.MIRROR)
            pathlib.Path(d, "bin/mirror.json").write_text(json.dumps([list(runs), [], list(status), []]))
            p = self.run_snap("resolve", path=path)
            calls = pathlib.Path(d, "bin/calls")
            return p, [c[-1] for c in (json.loads(calls.read_text()) if calls.exists() else [])]

    def test_a_frozen_clock_gives_one_answer(self):
        # With the clock fixed, the choice is a function of the mirror's runs alone: the newest run at
        # or before now, then the run before it. A run after now is never taken.
        base = "https://snapshot.debian.org/archive/debian-security/"
        runs = ("20201111T180000Z", "20201112T000000Z", "20201112T060000Z", "20201112T120000Z", "20201112T180000Z")
        for now, before, want, then in (("20201112T130000Z", "20201112T115959Z", "20201112T060000Z", "20201112T000000Z"),
                                        ("20201112T180000Z", "20201112T175959Z", "20201112T120000Z", "20201112T060000Z"),
                                        ("20201112T060001Z", "20201112T055959Z", "20201112T000000Z", "20201111T180000Z")):
            with self.subTest(now=now):
                p, calls = self.frozen(now, runs)
                self.assertEqual((p.returncode, p.stdout), (0, want + " " + then + "\n"), p.stderr)
                self.assertEqual(calls[:2], [base + now + "/", base + before + "/"])
                self.assertEqual(calls[3], base + want + "/dists/trixie-security/InRelease")
                self.assertEqual(calls[4], base + want + "/dists/trixie-security/main/binary-amd64/Packages.xz")
                self.assertEqual(calls[6], base + then + "/dists/trixie-security/main/binary-amd64/Packages.xz")
                self.assertEqual(len(calls), 7)
                again, calls2 = self.frozen(now, runs)
                self.assertEqual((again.stdout, calls2), (p.stdout, calls))

    def test_with_no_retries_left_it_refuses_at_once(self):
        # curl does the retrying (--retry); the script itself never loops. A mirror that keeps failing
        # (curl's retries spent, exit 22) ends resolve after that one call per step, with no stdout.
        for status, ncalls in (((22,), 1), ((0, 22), 2), ((0, 0, 22), 3), ((7,), 1)):
            with self.subTest(status=status):
                p, calls = self.frozen("20201112T130000Z", ("20201112T000000Z", "20201112T060000Z", "20201112T120000Z"),
                                       status=status)
                self.assertNotEqual(p.returncode, 0)
                self.assertEqual(p.stdout, "")
                self.assertEqual(len(calls), ncalls)

    def test_the_live_stanza_is_counted_as_fixed_text(self):
        # grep -cxF: the live URI is matched as a whole line of fixed text. Read as a regex, its dots
        # would match any byte, and without -x a longer line would count; both must be refused.
        with tempfile.TemporaryDirectory() as d:
            src = pathlib.Path(d, "s.sources")
            for line in ("URIs: http://securityXdebianXorg/debian-security",
                         "URIs: http://security.debian.org/debian-security/x",
                         "#URIs: http://security.debian.org/debian-security"):
                with self.subTest(line=line):
                    src.write_text(SOURCES.read_text().replace(LIVE, line))
                    p = self.run_snap("sources", "20261112T180512Z", str(src))
                    self.assertNotEqual(p.returncode, 0)
                    self.assertEqual(p.stdout, "")
                    self.assertIn("no single live security stanza", p.stderr)

    def test_a_bad_timestamp_says_what_was_wrong_and_how_to_get_one(self):
        for bad, shown in (("2026-11-12T18:05:12Z", "2026?11?12T18?05?12Z"), ("20261112T180512", "20261112T180512"),
                           ("x\n::error::forged", "x???error??forged"), ("", ""),
                           ("9" * 60, "9" * 40)):
            with self.subTest(bad=bad):
                p = self.run_snap("sources", bad)
                self.assertEqual(p.returncode, 2)
                self.assertEqual(p.stdout, "")
                self.assertIn('"%s" is not a debian-security snapshot timestamp' % shown, p.stderr)
                self.assertIn("YYYYMMDDTHHMMSSZ", p.stderr)
                self.assertIn("security-snapshot.sh resolve", p.stderr)
                self.assertIn("CI run", p.stderr)
                self.assertNotIn("::error", p.stderr)
                self.assertEqual(len(p.stderr.splitlines()), 5)

    def test_the_enforcer_build_reads_the_pinned_snapshot(self):
        # The enforcer's committed sources still name the live host as the stanza to pin, and build.sh
        # always hands mkosi the pinned copy, so no enforcer build reads security.debian.org.
        self.assertEqual(ENF_SOURCES.read_text().count(LIVE + "\n"), 1)
        p = self.run_snap("sources", "20261112T180512Z", str(ENF_SOURCES))
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout, ENF_SOURCES.read_text().replace(
            LIVE, "URIs: https://snapshot.debian.org/archive/debian-security/20261112T180512Z/"))
        self.assertNotIn("security.debian.org", p.stdout.replace("snapshot.debian.org/archive/debian-security", ""))
        b = (ENF / "build.sh").read_text()
        self.assertIn('SECURITY_SNAPSHOT=${AGENTOS_SECURITY_SNAPSHOT-}', b)
        self.assertIn('[ -n "$SECURITY_SNAPSHOT" ] || SECURITY_SNAPSHOT=$(sh "$HERE/../security-snapshot.sh" resolve)', b)
        pick = b.index('SECURITY_SNAPSHOT=$(sh "$HERE/../security-snapshot.sh" pick "$SECURITY_SNAPSHOT")\n')
        self.assertLess(pick, b.index('sources "$SECURITY_SNAPSHOT"'))
        write = b.index('sh "$HERE/../security-snapshot.sh" sources "$SECURITY_SNAPSHOT" \\\n'
                        '\t"$HERE/mkosi/mkosi.pkgmngr/etc/apt/sources.list.d/mkosi.sources" >"$OUT/enforcer.sources"\n')
        tree = b.index('install -D -m 0644 "$OUT/enforcer.sources" "$OUT/pkgmngr/etc/apt/sources.list.d/mkosi.sources"')
        mk = b.index('$MKOSI -C "$HERE/mkosi" -f --package-manager-tree="$OUT/pkgmngr" ')
        self.assertLess(write, tree)
        self.assertLess(tree, mk)
        self.assertEqual(b.count("$MKOSI "), 1)
        self.assertNotIn("security.debian.org", b)
        wf = (ROOT / ".github/workflows/enforcer-image.yml").read_text()
        self.assertEqual(wf.count('      - "image/security-snapshot.sh"\n'), 2)



class KeyringCheckOtherBuildsTest(unittest.TestCase):
    """IMG-keyring-pin-b (#5933): the enforcer image and the test kit check the Debian archive keyring
    before mkosi, as image/build.sh does (#5578), and stop when the check fails."""

    BUILDS = (("image/enforcer/build.sh", "enforcer-image.yml"), ("spikes/S1S2-testkit/build.sh", "testkit.yml"))

    def test_check_runs_first_and_stops_the_build(self):
        # Each build runs from a copy in a git repository with every later step stubbed, so with a
        # passing check it reaches mkosi; with a failing one, the check is the only thing that runs.
        # (A copy outside a git repository dies at git log whatever the check does: #6055's fix-list.)
        for rel, _ in self.BUILDS:
            for check in (1, 0):
                with self.subTest(build=rel, check=check), tempfile.TemporaryDirectory() as d:
                    log = self.stage(d, rel, check)
                    p = self.run_build(d, rel)
                    lines = log.read_text().splitlines()
                    self.assertEqual(lines[0], "keyring-check")
                    if check:
                        self.assertNotEqual(p.returncode, 0)
                        self.assertEqual(lines, ["keyring-check"])
                    else:
                        self.assertIn("mkosi", lines, p.stderr)

    def test_the_core_build_stops_at_a_failing_check(self):
        # image/build.sh's next step after the check is git log: it runs only when the check passes.
        for check in (1, 0):
            with self.subTest(check=check), tempfile.TemporaryDirectory() as d:
                log = self.stage(d, "image/build.sh", check)
                p = self.run_build(d, "image/build.sh")
                self.assertNotEqual(p.returncode, 0)
                self.assertEqual(log.read_text().splitlines(), ["keyring-check"] + ["git"] * (1 - check))

    def stage(self, d, rel, check):
        """A copy of REL under D beside a stand-in keyring check that exits CHECK; mkosi, git,
        python3 and security-snapshot.sh are stubs, and mkosi and git log their name."""
        log = pathlib.Path(d, "log")
        script = pathlib.Path(d, rel)
        script.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / rel, script)
        img = pathlib.Path(d, "image")
        img.mkdir(exist_ok=True)
        (img / "debian-archive-keyring.sh").write_text("echo keyring-check >> %s\nexit %d\n" % (log, check))
        (img / "security-snapshot.sh").write_text("echo 20260101T000000Z\n")
        pathlib.Path(d, "r.json").write_text("{}")
        self.path = fake_tools(d, mkosi="echo mkosi >> %s\n" % log, python3="exit 0\n",
                               git="echo git >> %s\n[ -d %s/.git ] || exit 1\necho 1700000000\n" % (log, d))
        if rel != "image/build.sh":
            pathlib.Path(d, ".git").mkdir()
        return log

    def run_build(self, d, rel):
        return subprocess.run(["sh", str(pathlib.Path(d, rel)), str(pathlib.Path(d, "out"))], capture_output=True,
                              text=True, cwd=d, stdin=subprocess.DEVNULL, env={"PATH": self.path, "MKOSI": str(pathlib.Path(d, "bin/mkosi")),
                                                     "ENFORCER_RELEASE_ROOT": str(pathlib.Path(d, "r.json")),
                                                     "AGENTOS_RELEASE_KEYS": "k.pem"})

    def test_check_precedes_mkosi_and_its_change_runs_the_workflow(self):
        for rel, wf in self.BUILDS:
            with self.subTest(build=rel):
                b = (ROOT / rel).read_text()
                self.assertEqual(b.count("debian-archive-keyring.sh\""), 1)
                self.assertLess(b.index("debian-archive-keyring.sh\""), b.index("$MKOSI "))
                w = (ROOT / ".github/workflows" / wf).read_text()
                self.assertEqual(w.count('      - "image/debian-archive-keyring.sh"\n'), 2)



class KeyringMinimalTest(unittest.TestCase):
    """IMG-keyring-minimal (#5954): each apt stanza of the image, guest and enforcer builds trusts a
    keyring holding only the Debian key that signs it, and the check pins each such file exactly.
    The runner's keyrings are read from AGENTOS_DEBIAN_KEYRINGS (default /usr/share/keyrings, which
    CI's checks job fills by installing debian-archive-keyring before the unit tests)."""

    CHECK = IMG / "debian-archive-keyring.sh"
    ARCHIVE = "/usr/share/keyrings/debian-archive-bookworm-automatic.gpg"
    SECURITY = "/usr/share/keyrings/debian-archive-bookworm-security-automatic.gpg"
    SOURCES = (MK / "mkosi.pkgmngr/etc/apt/sources.list.d/mkosi.sources",
               IMG / "enforcer/mkosi/mkosi.pkgmngr/etc/apt/sources.list.d/mkosi.sources")
    # The runner's whole keyring, which no build names (#5983), and the Debian 10/buster and
    # 11/bullseye archive, security and release keys and subkeys it holds (ftp-master.debian.org/keys.html).
    WHOLE = "debian-archive-keyring.gpg"
    OLD = frozenset("""
        80D15823B7FD1561F9F7BCDDDC30D7C23CBBABEE 0146DC6D4A0B2914BDED34DB648ACFD622F3D138
        5E61B217265DA9807A23C5FF4DFAB270CAA96DFA 5237CEEEF212F3D51C74ABE0112695A0E562B32A
        6D33866EDD8FFA41C0143AEDDCC9EFBF77E11517 1F89983E0081FDE018F3CC9673A4F27B8DD47936
        A7236886F3CCCAAD148A27F80E98404D386FA1D9 AC530D520F2F3269F5E98313A48449044AAD5C5D
        ED541312A33F1128F10B1C6C54404762BBB6E853 A4285295FC7B1A81600062A9605C66F00D6C9793""".split())

    def pinned(self):
        """{file name: [(fingerprint, label)]} from the check's list."""
        text = self.CHECK.read_text()
        body = text[text.index("cat <<'EOF'\n") + len("cat <<'EOF'\n"):text.index("\nEOF\n")]
        files, cur = {}, None
        for line in body.splitlines():
            m = re.fullmatch(r"([0-9A-F]{40})  (.+)", line)
            if m:
                files[cur].append((m[1], m[2]))
            else:
                self.assertRegex(line, r"\A[a-z0-9-]+\.gpg\Z")
                cur = line
                files[cur] = []
        return files

    def test_each_stanza_trusts_only_its_signing_key(self):
        # REQ: IMG-keyring-minimal. The snapshot (trixie, trixie-updates) is read with the archive
        # key's keyring, the security archive with the security key's, in the core and the enforcer
        # (Potency 1 on #5961: a repointed enforcer Signed-By would bypass the check).
        for src in self.SOURCES:
            with self.subTest(sources=str(src.relative_to(ROOT))):
                stanzas = [dict(ln.split(": ", 1) for ln in st.splitlines() if ln and not ln.startswith("#"))
                           for st in src.read_text().split("\n\n")]
                stanzas = [st for st in stanzas if st]
                self.assertEqual([(st["URIs"].startswith("https://snapshot.debian.org/archive/debian/"),
                                   st["Signed-By"]) for st in stanzas],
                                 [(True, self.ARCHIVE), (False, self.SECURITY)])
                self.assertEqual(stanzas[1]["URIs"], "http://security.debian.org/debian-security")

    def test_the_minimal_keyrings_hold_no_older_release_key(self):
        # REQ: IMG-keyring-minimal. The files the sources name are pinned to the 12/bookworm archive
        # and security keys alone; no buster, bullseye or release key is trusted for the builds.
        files = self.pinned()
        names = {pathlib.Path(self.ARCHIVE).name, pathlib.Path(self.SECURITY).name}
        self.assertEqual(list(files), [pathlib.Path(self.ARCHIVE).name, pathlib.Path(self.SECURITY).name])
        old = self.OLD
        self.assertEqual(len(old), 10)
        for name in names:
            with self.subTest(keyring=name):
                fprs = {f for f, _ in files[name]}
                self.assertEqual(len(fprs), 2)
                self.assertFalse(fprs & old)
                self.assertTrue(all("12/bookworm" in label and "Release" not in label for _, label in files[name]))
        self.assertEqual(files[pathlib.Path(self.ARCHIVE).name][0][1], "Debian Archive Automatic Signing Key (12/bookworm)")
        self.assertEqual(files[pathlib.Path(self.SECURITY).name][0][1],
                         "Debian Security Archive Automatic Signing Key (12/bookworm)")

    def keyrings(self):
        d = pathlib.Path(os.environ.get("AGENTOS_DEBIAN_KEYRINGS", "/usr/share/keyrings"))
        if not all((d / n).is_file() for n in [*self.pinned(), self.WHOLE]):
            if os.environ.get("AGENTOS_REQUIRE_REFERENCE_TOOLS") == "1":
                self.fail("no Debian keyrings in %s (install debian-archive-keyring)" % d)
            self.skipTest("no Debian keyrings in %s" % d)
        return d

    def run_check(self, d):
        return subprocess.run(["sh", str(self.CHECK), str(d)], capture_output=True, text=True, stdin=subprocess.DEVNULL)

    def test_the_check_refuses_a_wider_or_missing_keyring(self):
        # REQ: IMG-keyring-minimal. The runner's files pass; the whole keyring in place of the
        # archive key's file (trust for keys no build needs) fails, and so does a missing file,
        # each with the fix named (UX 2 on #5961).
        src = self.keyrings()
        p = self.run_check(src)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout.count("holds exactly the"), len(self.pinned()))
        with tempfile.TemporaryDirectory() as d:
            for n in self.pinned():
                shutil.copy(src / n, pathlib.Path(d, n))
            shutil.copy(src / self.WHOLE, pathlib.Path(d, pathlib.Path(self.ARCHIVE).name))
            p = self.run_check(d)
            self.assertEqual(p.returncode, 1, p.stderr)
            self.assertIn("debian-archive-bookworm-automatic.gpg does not hold exactly the pinned keys", p.stderr)
            self.assertIn("+ 80D15823B7FD1561F9F7BCDDDC30D7C23CBBABEE", p.stderr)  # buster, not pinned there
            self.assertIn("edit the list in image/debian-archive-keyring.sh", p.stderr)
            self.assertIn("https://ftp-master.debian.org/keys.html", p.stderr)
            pathlib.Path(d, pathlib.Path(self.SECURITY).name).unlink()
            p = self.run_check(d)
            self.assertEqual(p.returncode, 1, p.stderr)
            self.assertIn("no keyring at %s/%s; install the debian-archive-keyring package"
                          % (d, pathlib.Path(self.SECURITY).name), p.stderr)

    def test_the_header_names_every_caller(self):
        # UX 1 on #5961: the check's header and IMG-keyring-pin-1 list every build that runs it.
        callers = [rel for rel in ("image/build.sh", "image/guest-base.sh", "image/enforcer/build.sh",
                                   "spikes/S1S2-testkit/build.sh") if "debian-archive-keyring.sh\"" in (ROOT / rel).read_text()]
        self.assertEqual(len(callers), 4)
        header = self.CHECK.read_text().split("\nset -eu\n")[0]
        row = next(ln for ln in (IMG / "ASSUMPTIONS.md").read_text().splitlines() if ln.startswith("| IMG-keyring-pin-1 |"))
        for rel in callers:
            with self.subTest(caller=rel):
                self.assertIn(rel, header.replace("\n# ", " "))
                self.assertIn("`%s`" % rel, row)


class KeyringSpikesTest(unittest.TestCase):
    """IMG-keyring-spikes (#5983): every mkosi build in the repository trusts only the minimal Debian
    keyrings. The keyring check is each mkosi tree's configure script, which mkosi v24.3 runs for every
    build of the tree before it reads any archive, whoever calls mkosi and however; each tree that is
    not part of another commits its apt sources (mkosi then generates none, so the whole keyring is
    named nowhere)."""

    ARCHIVE, SECURITY = KeyringMinimalTest.ARCHIVE, KeyringMinimalTest.SECURITY
    CHECK = KeyringMinimalTest.CHECK
    TREES = ["image/enforcer/mkosi", "image/mkosi", "image/mkosi/initrd", "spikes/S1S2-testkit/mkosi"]

    @staticmethod
    def trees(root):
        """{tree directory: directories it includes} for every directory under ROOT that mkosi reads
        as configuration: one holding mkosi.conf, mkosi.conf.d or mkosi.local.conf, of any file type,
        links included; one inside a mkosi.conf.d belongs to the tree above it. The walk opens no
        record (ci_scope: a record file or directory, or .git), as test_image.scanned_files:
        tests/records_audit.py counts any open of one as a read."""
        spec = importlib.util.spec_from_file_location("repro_ci_scope", ROOT / "tools/ci_scope.py")
        scope = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(scope)
        found = {}
        for top, dirs, names in os.walk(root):
            rel = pathlib.Path(top).relative_to(root).as_posix()
            rel = "" if rel == "." else rel + "/"
            dirs[:] = sorted(d for d in dirs if not (rel + d == ".git" or (rel + d + "/").startswith(scope.RECORD_DIRS)))
            if "mkosi.conf.d" in pathlib.Path(top).relative_to(root).parts:
                continue
            if {"mkosi.conf", "mkosi.conf.d", "mkosi.local.conf"} & set(dirs + names):
                conf = pathlib.Path(top, "mkosi.conf")
                text = conf.read_text() if conf.is_file() else ""
                found[pathlib.Path(top)] = {(pathlib.Path(top) / v).resolve() for m in re.finditer(
                    r"^(?:Initrd)?Include=(.+)$", text, re.M) for v in m[1].split()}
        return found

    def test_every_tree_runs_the_check_as_its_configure_script(self):
        # REQ: IMG-keyring-spikes. Each tree's mkosi.configure is the check itself, so every build of
        # the tree runs it first (failure path 2 on #5983; the call inventories of #6055 and #6068
        # missed call forms, a fix-list each). S7's Ubuntu tree and run.sh, which the check cannot
        # pin, are retired.
        trees = self.trees(ROOT)
        self.assertEqual(sorted(str(t.relative_to(ROOT)) for t in trees), self.TREES)
        for tree in trees:
            with self.subTest(tree=str(tree.relative_to(ROOT))):
                link = tree / "mkosi.configure"
                self.assertTrue(link.is_symlink())
                self.assertFalse(os.path.isabs(os.readlink(link)))
                self.assertEqual(link.resolve(), self.CHECK)
        self.assertTrue(os.access(self.CHECK, os.X_OK))
        self.assertFalse((ROOT / "spikes/S7-host-image/run.sh").exists())
        self.assertFalse((ROOT / "spikes/S7-host-image/mkosi").exists())

    def test_every_form_of_tree_is_found(self):
        # Security on #6068: a linked mkosi.conf and a tree configured only by mkosi.local.conf are
        # trees; a drop-in directory belongs to its tree; a directory with none of the three is not.
        with tempfile.TemporaryDirectory() as d:
            r = pathlib.Path(d)
            for rel in ("plain/mkosi.conf", "debian.conf", "local/mkosi.local.conf",
                        "dropin/mkosi.conf.d/10.conf", "dropin/mkosi.conf.d/sub/mkosi.conf", "none/mkosi.extra/x"):
                (r / rel).parent.mkdir(parents=True, exist_ok=True)
                (r / rel).write_text("[Config]\nInitrdInclude=../none/\n" if rel.startswith("plain") else "")
            (r / "linked").mkdir()
            (r / "linked/mkosi.conf").symlink_to("../debian.conf")
            found = self.trees(r)
            self.assertEqual(sorted(str(t.relative_to(r)) for t in found), ["dropin", "linked", "local", "plain"])
            self.assertEqual(found[r / "plain"], {(r / "none").resolve()})

    def test_each_tree_commits_sources_naming_only_the_minimal_keyrings(self):
        # REQ: IMG-keyring-spikes. The test kit, as the core and the enforcer, reads the archive
        # (trixie, trixie-updates) with the archive key's keyring and the security archive with the
        # security key's; no stanza names the whole keyring (failure path 1 on #5983). A tree another
        # includes (the initrd) is built with its includer's package manager trees.
        trees = self.trees(ROOT)
        included = set().union(*trees.values())
        own = sorted(str(t.relative_to(ROOT)) for t in trees if t.resolve() not in included)
        self.assertEqual(own, ["image/enforcer/mkosi", "image/mkosi", "spikes/S1S2-testkit/mkosi"])
        for tree in own:
            with self.subTest(tree=tree):
                src = ROOT / tree / "mkosi.pkgmngr/etc/apt/sources.list.d/mkosi.sources"
                stanzas = [dict(ln.split(": ", 1) for ln in st.splitlines() if ln and not ln.startswith("#"))
                           for st in src.read_text().split("\n\n")]
                stanzas = [st for st in stanzas if st]
                self.assertEqual([(st["Suites"], st["Signed-By"]) for st in stanzas],
                                 [("trixie trixie-updates", self.ARCHIVE), ("trixie-security", self.SECURITY)])
                self.assertEqual(stanzas[1]["URIs"], "http://security.debian.org/debian-security")
                self.assertTrue(all(st["Types"] == "deb" for st in stanzas))
                self.assertNotIn(KeyringMinimalTest.WHOLE, src.read_text().replace("whole " + KeyringMinimalTest.WHOLE, ""))
        kit = ROOT / "spikes/S1S2-testkit/mkosi/mkosi.pkgmngr/etc/apt/sources.list.d/mkosi.sources"
        self.assertTrue(kit.read_text().split("\nTypes:")[1].startswith(" deb\nURIs: http://deb.debian.org/debian\n"))

    # What each tree may hold beside its config, and the keys its mkosi.conf may set (mkosi v24.3).
    # None of these names a config, script, tree, mirror or keyring apt reads, except the PINNED keys,
    # whose values each tree must set exactly as its own row says: so a second package manager tree, a
    # drop-in (mkosi.conf.d, mkosi.local.conf), a skeleton or tools tree, an Include= or a sources
    # tarball needs a deliberate edit here (Security 1 on #6082), and so does one tree taking another's
    # pinned value, or dropping or repeating one (#6088). The walk opens no record directory; that none
    # holds a tree is test_ci_scope's check, which may read git (#6088).
    NAMES = {
        "image/mkosi": {"mkosi.conf", "mkosi.configure", "mkosi.extra", "mkosi.finalize", "mkosi.pkgmngr",
                        "mkosi.postinst", "mkosi.repart"},
        "image/mkosi/initrd": {"mkosi.conf", "mkosi.configure", "mkosi.finalize", "mkosi.postinst"},
        "image/enforcer/mkosi": {"mkosi.conf", "mkosi.configure", "mkosi.extra", "mkosi.finalize", "mkosi.pkgmngr",
                                 "mkosi.repart"},
        "spikes/S1S2-testkit/mkosi": {"mkosi.conf", "mkosi.configure", "mkosi.extra", "mkosi.pkgmngr", "mkosi.repart"},
    }
    KEYS = {"BiosBootloader", "Bootable", "Bootloader", "Distribution", "Environment", "Format", "Hostname",
            "ImageId", "ImageVersion", "InitrdInclude", "KernelCommandLine", "KernelModulesExclude",
            "KernelModulesInitrdExclude", "Keymap", "Locale", "ManifestFormat", "Mirror", "Packages", "Release",
            "RemoveFiles", "RepartDirectories", "Repositories", "RootPassword", "Seed", "ShimBootloader",
            "SplitArtifacts", "Timezone", "UnifiedKernelImages", "WithDocs"}
    SNAPSHOT = "https://snapshot.debian.org/archive/debian/20261001T000000Z/"
    PINNED = {
        "image/mkosi": {"InitrdInclude": ["initrd/"], "Mirror": [SNAPSHOT], "Repositories": ["main"],
                        "Environment": ["SYSTEMD_REPART_MKFS_OPTIONS_EXT4=-Oquota,project"]},
        "image/mkosi/initrd": {},
        "image/enforcer/mkosi": {"InitrdInclude": ["../../mkosi/initrd/"], "Mirror": [SNAPSHOT],
                                 "Repositories": ["main"]},
        "spikes/S1S2-testkit/mkosi": {"Repositories": ["main"]},
    }
    PINNED_KEYS = {"InitrdInclude", "Environment", "Mirror", "Repositories"}
    PKGMNGR = {"etc/apt/sources.list.d/mkosi.sources", "etc/apt/apt.conf.d/80-agentos-retries"}

    @staticmethod
    def settings(conf):
        """[(key, [value lines])] of a mkosi.conf in the strict form test_image.ConfigTest holds the
        core to (column-0 comments, sections and Key=value, indented continuations); None if any
        line is in another form."""
        out, cur = [], None
        for line in conf.read_text().splitlines():
            if not line.strip() or re.fullmatch(r"\[[A-Za-z]+\]", line):
                cur = None
            elif line.startswith("#"):
                pass
            elif m := re.fullmatch(r"([A-Z][A-Za-z0-9]*)=(.*)", line):
                cur = (m[1], [m[2].strip()])
                out.append(cur)
            elif line[0] in " \t" and cur is not None:
                cur[1].append(line.strip())
            else:
                return None
        return out

    def apt_input_problems(self, d, tree):
        """Why tree directory D (named TREE) may feed apt something the check cannot see: a mkosi.*
        name, a mkosi.conf key or value, or a mkosi.pkgmngr file not on the lists above."""
        why = []
        names = {n for n in os.listdir(d) if n.startswith("mkosi")}
        if names != self.NAMES[tree]:
            why.append("mkosi.* names %s, not %s" % (sorted(names), sorted(self.NAMES[tree])))
        settings = self.settings(d / "mkosi.conf")
        if settings is None:
            why.append("mkosi.conf is not in the strict form")
        pinned = {}
        for k, v in settings or []:
            if k not in self.KEYS:
                why.append("mkosi.conf sets %s=, not on the list" % k)
            elif k in self.PINNED_KEYS:
                pinned.setdefault(k, []).append(v)
        want = {k: [v] for k, v in self.PINNED[tree].items()}
        if settings is not None and pinned != want:
            why.append("mkosi.conf pins %s, not %s's own %s" % (pinned, tree, want))
        pm = d / "mkosi.pkgmngr"
        if pm.exists():
            retries = (MK / "mkosi.pkgmngr/etc/apt/apt.conf.d/80-agentos-retries").read_bytes()
            for p in sorted(pm.rglob("*")):
                r = p.relative_to(pm).as_posix()
                if p.is_symlink() or (p.is_file() and r not in self.PKGMNGR):
                    why.append("mkosi.pkgmngr holds %s" % r)
                elif p.is_file() and r != "etc/apt/sources.list.d/mkosi.sources" and p.read_bytes() != retries:
                    why.append("mkosi.pkgmngr/%s is not the core's retry settings" % r)
            if not (pm / "etc/apt/sources.list.d/mkosi.sources").is_file():
                why.append("mkosi.pkgmngr has no mkosi.sources")
        return why

    def test_no_tree_adds_apt_input_the_check_cannot_see(self):
        # REQ: IMG-keyring-spikes. The guard sees only that a package manager tree is named; mkosi merges
        # every one into apt's configuration, so each tree's own inputs are pinned: its mkosi.* names, the
        # keys of its mkosi.conf, and its mkosi.pkgmngr's files (the sources, checked above, and the core's
        # retry settings byte for byte, which test_image pins).
        trees = sorted(str(t.relative_to(ROOT)) for t in self.trees(ROOT))
        self.assertEqual(trees, sorted(self.NAMES))
        for tree in trees:
            with self.subTest(tree=tree):
                self.assertEqual(self.apt_input_problems(ROOT / tree, tree), [])

    def test_every_way_to_add_apt_input_fails(self):
        # The repro on #6082 (a second package manager tree with a Trusted: yes stanza, named in the
        # test kit's mkosi.conf) and its siblings, each in a copy of the test kit's and the enforcer's tree.
        cases = {"key": ("mkosi.conf", "\n[Content]\nPackageManagerTrees=evil/\n"),
                 "include": ("mkosi.conf", "\n[Config]\nInclude=evil/\n"),
                 "tools": ("mkosi.conf", "\n[Host]\nToolsTree=default\n"),
                 "dropin": ("mkosi.conf.d/10.conf", "[Content]\nPackageManagerTrees=evil/\n"),
                 "local": ("mkosi.local.conf", ""),
                 "skeleton": ("mkosi.skeleton/etc/apt/sources.list.d/evil.sources", "Trusted: yes\n"),
                 "tar": ("mkosi.pkgmngr.tar", ""),
                 "extra-file": ("mkosi.pkgmngr/etc/apt/sources.list.d/evil.sources", "Trusted: yes\n"),
                 "apt-conf": ("mkosi.pkgmngr/etc/apt/apt.conf.d/80-agentos-retries",
                              'Acquire::AllowInsecureRepositories "true";\n'),
                 "loose": ("mkosi.conf", "\n  [Content]\n")}
        for tree in ("spikes/S1S2-testkit/mkosi", "image/enforcer/mkosi"):
            for name, (rel, text) in cases.items():
                with self.subTest(tree=tree, case=name), tempfile.TemporaryDirectory() as d:
                    copy = pathlib.Path(d, "t")
                    shutil.copytree(ROOT / tree, copy, symlinks=True)
                    f = copy / rel
                    f.parent.mkdir(parents=True, exist_ok=True)
                    with open(f, "a") as out:
                        out.write(text)
                    self.assertTrue(self.apt_input_problems(copy, tree))
        # Each pinned value, a linked directory under mkosi.pkgmngr, and a drop-in on the included initrd tree
        # (Security delta on #6082: these branches had no case).
        more = [("image/enforcer/mkosi", "value", lambda c: open(c / "mkosi.conf", "a").write("\n[Config]\nInitrdInclude=evil/\n")),
                ("spikes/S1S2-testkit/mkosi", "value", lambda c: open(c / "mkosi.conf", "a").write(
                    "\n[Content]\nEnvironment=APT_CONFIG=/work/src/evil.conf\n")),
                ("image/enforcer/mkosi", "link", lambda c: (c / "mkosi.pkgmngr/etc/apt/trusted.gpg.d").symlink_to(c / "evil")),
                ("spikes/S1S2-testkit/mkosi", "link", lambda c: (c / "mkosi.pkgmngr/etc/apt/trusted.gpg.d").symlink_to(c / "evil")),
                ("image/mkosi/initrd", "dropin", lambda c: (c / "mkosi.conf.d").mkdir())]
        for tree, name, change in more:
            with self.subTest(tree=tree, case=name), tempfile.TemporaryDirectory() as d:
                copy = pathlib.Path(d, "t")
                shutil.copytree(ROOT / tree, copy, symlinks=True)
                (copy / "evil").mkdir()
                change(copy)
                self.assertTrue(self.apt_input_problems(copy, tree))
        for tree in self.NAMES:
            with self.subTest(tree=tree, case="none"), tempfile.TemporaryDirectory() as d:
                copy = pathlib.Path(d, "t")
                shutil.copytree(ROOT / tree, copy, symlinks=True)
                self.assertEqual(self.apt_input_problems(copy, tree), [])

    @staticmethod
    def set_pinned(conf, key, values):
        """Rewrite mkosi.conf CONF with every KEY= setting (and its continuation lines) removed, then
        one KEY=v appended per v in VALUES."""
        out, skip = [], False
        for line in conf.read_text().splitlines():
            if line.startswith(key + "="):
                skip = True
                continue
            if skip and line[:1] in (" ", "\t") and line.strip():
                continue
            skip = False
            out.append(line)
        conf.write_text("\n".join(out + ["", "[Config]"] + ["%s=%s" % (key, v) for v in values]) + "\n")

    def test_each_tree_is_held_to_its_own_pinned_values(self):
        # REQ: IMG-keyring-spikes. #6088 failure paths 1 and 2: every pinned value is looked up by tree,
        # so a tree that takes another tree's InitrdInclude=, Environment=, Mirror= or Repositories=
        # (or drops its own) fails, and so does a changed, dropped, added or repeated Mirror= or Repositories=.
        cases = []
        for a in self.NAMES:
            for b in self.NAMES:
                for k in sorted(self.PINNED_KEYS):
                    theirs = self.PINNED[b].get(k)
                    if a != b and theirs != self.PINNED[a].get(k):
                        cases.append((a, "%s from %s" % (k, b), k, [theirs[0]] if theirs else []))
        for a in self.NAMES:
            for k in ("Mirror", "Repositories"):
                own = self.PINNED[a].get(k, [])
                cases += [(a, k + " changed", k, ["https://deb.debian.org/debian/" if k == "Mirror" else "main,contrib"]),
                          (a, k + " repeated", k, own * 2 or ["main"])]
                if own:
                    cases.append((a, k + " dropped", k, []))
        swaps = {k for _, name, k, _ in cases if " from " in name}
        self.assertEqual(swaps, self.PINNED_KEYS)  # each pinned key differs between some two trees
        for tree, name, key, values in cases:
            with self.subTest(tree=tree, case=name), tempfile.TemporaryDirectory() as d:
                copy = pathlib.Path(d, "t")
                shutil.copytree(ROOT / tree, copy, symlinks=True)
                self.set_pinned(copy / "mkosi.conf", key, values)
                self.assertTrue(self.apt_input_problems(copy, tree))
        for tree in self.NAMES:  # the rewrite alone, with each tree's own values, changes nothing
            with self.subTest(tree=tree, case="own values"), tempfile.TemporaryDirectory() as d:
                copy = pathlib.Path(d, "t")
                shutil.copytree(ROOT / tree, copy, symlinks=True)
                for k, v in self.PINNED[tree].items():
                    self.set_pinned(copy / "mkosi.conf", k, v)
                self.assertEqual(self.apt_input_problems(copy, tree), [])

    def test_the_check_pins_no_keyring_that_no_build_names(self):
        # REQ: IMG-keyring-spikes. With the test kit's sources committed, the check lists only the two
        # files the sources name; the whole keyring's buster and bullseye keys are pinned nowhere.
        text = self.CHECK.read_text()
        self.assertNotIn("\n%s\n" % KeyringMinimalTest.WHOLE, text)
        self.assertFalse(KeyringMinimalTest.OLD & set(re.findall(r"^([0-9A-F]{40})  ", text, re.M)))

    def configure(self, config, keyrings):
        """The check run as mkosi v24.3 runs a configure script: as /work/configure (here a link
        named configure), no arguments but the keyring directory, the config JSON on stdin."""
        with tempfile.TemporaryDirectory() as d:
            link = pathlib.Path(d, "configure")
            link.symlink_to(self.CHECK)
            return subprocess.run([str(link), str(keyrings)], input=config, capture_output=True, text=True)

    CONFIG = {"Distribution": "debian", "Release": "trixie", "RepositoryKeyCheck": True,
              "PackageManagerTrees": [{"Source": "/src/image/mkosi/mkosi.pkgmngr", "Target": None}]}

    def test_as_configure_script_it_passes_the_config_through(self):
        # REQ: IMG-keyring-spikes. On the runner's keyrings a Debian build passes: the config goes back
        # on stdout byte for byte (mkosi reads its config from there), the report goes to stderr.
        keyrings = KeyringMinimalTest().keyrings()
        config = json.dumps(self.CONFIG)
        p = self.configure(config, keyrings)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertEqual(p.stdout, config + "\n")
        self.assertEqual(p.stderr.count("holds exactly the"), 2)

    def test_as_configure_script_it_refuses_what_the_check_cannot_vouch_for(self):
        # REQ: IMG-keyring-spikes. However the tree, the command line or mkosi.local.conf set them, a
        # build that is not Debian, turns off apt's signature check, or has no package manager tree
        # (the standalone initrd tree: mkosi would generate sources naming the whole keyring) stops,
        # each reason named and no config passed on; so does a wider keyring, and input not JSON.
        keyrings = KeyringMinimalTest().keyrings()
        bad = {"Distribution": "ubuntu", "RepositoryKeyCheck": False, "PackageManagerTrees": []}
        reasons = {"Distribution": "its distribution is ubuntu, not debian",
                   "RepositoryKeyCheck": "it sets RepositoryKeyCheck=no",
                   "PackageManagerTrees": "it names no package manager tree"}
        for key in bad:
            with self.subTest(key=key):
                p = self.configure(json.dumps(dict(self.CONFIG, **{key: bad[key]})), keyrings)
                self.assertEqual((p.returncode, p.stdout), (1, ""))
                self.assertIn("this mkosi build is refused: " + reasons[key], p.stderr)
                self.assertEqual(p.stderr.count("is refused"), 1)
        p = self.configure(json.dumps(dict(self.CONFIG, **bad)), keyrings)
        self.assertEqual((p.returncode, p.stdout, p.stderr.count("is refused")), (1, "", 3))
        p = self.configure("not json", keyrings)
        self.assertEqual((p.returncode, p.stdout), (1, ""))
        with tempfile.TemporaryDirectory() as d:
            for n in KeyringMinimalTest().pinned():
                shutil.copy(keyrings / KeyringMinimalTest.WHOLE, pathlib.Path(d, n))
            p = self.configure(json.dumps(self.CONFIG), d)
            self.assertEqual((p.returncode, p.stdout), (1, ""))
            self.assertIn("does not hold exactly the pinned keys", p.stderr)

    def test_the_enforcer_reports_every_missing_input_at_once(self):
        # UX 3 on #5961: with both required variables unset and the keyring check failing, one run
        # names all three and runs no mkosi.
        with tempfile.TemporaryDirectory() as d:
            log = pathlib.Path(d, "log")
            script = pathlib.Path(d, "image/enforcer/build.sh")
            script.parent.mkdir(parents=True)
            shutil.copy(IMG / "enforcer/build.sh", script)
            pathlib.Path(d, "image/debian-archive-keyring.sh").write_text(
                "echo keyring-check >> %s\necho keyring-refused >&2\nexit 1\n" % log)
            mkosi = pathlib.Path(d, "mkosi")
            mkosi.write_text("#!/bin/sh\necho mkosi >> %s\n" % log)
            mkosi.chmod(0o755)
            p = subprocess.run(["sh", str(script), str(pathlib.Path(d, "out"))], capture_output=True, text=True,
                               env={"PATH": os.environ["PATH"], "MKOSI": str(mkosi)})
            self.assertEqual(p.returncode, 1)
            for want in ("ENFORCER_RELEASE_ROOT) is required", "AGENTOS_RELEASE_KEYS) are required", "keyring-refused"):
                self.assertIn(want, p.stderr)
            self.assertEqual(log.read_text().splitlines(), ["keyring-check"])


if __name__ == "__main__":
    unittest.main()
