"""VULN-debian-r6-f2 (#5697): image/import_sweep.py reads which ELF files in a built image import
glibc's POSIX regex or wide scanf functions, directly or through a library they need, in the main
tree and in each initrd, so the glibc records' reachability claims come from the tree CI builds."""
# REQ: EVL-5
import contextlib
import fnmatch
import importlib.util
import io
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "image"))
spec = importlib.util.spec_from_file_location("import_sweep", ROOT / "image" / "import_sweep.py")
sweep = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sweep)

REGEX_LIB = '#include <regex.h>\nint f(void) { regex_t r; return regcomp(&r, "a", 0); }\n'
WSCANF = ('#include <wchar.h>\nint main(void) { char b[4]; return swscanf(L"ab", L"%3s", b); }\n')
PLAIN = "int main(void) { return 0; }\n"
# glibc's rpmatch runs the regex engine inside libc: a file importing only it reaches the flaw.
RPMATCH = "#include <stdlib.h>\nint main(int c, char **v) { return rpmatch(v[0]); }\n"
USES_LIB = "int f(void);\nint main(void) { return f(); }\n"
# A library's own re_ name, unversioned: not glibc's, so not counted.
OWN_RE = "int re_mine(void) { return 1; }\n"
USES_OWN_RE = "int re_mine(void);\nint main(void) { return re_mine(); }\n"


def newc(members):
    """A newc cpio archive of MEMBERS (name, mode, content), then the trailer."""
    out = b""
    for i, (n, mode, body) in enumerate(list(members) + [("TRAILER!!!", 0, b"")]):
        name = n.encode() + b"\0"
        out += b"070701" + b"".join(b"%08X" % v for v in (1000 + i, mode, 0, 0, 1, 0, len(body), 0, 0, 0, 0,
                                                            len(name), 0))
        out += name + b"\0" * (-(110 + len(name)) % 4) + body + b"\0" * (-len(body) % 4)
    return out


@unittest.skipUnless(shutil.which("cc") and shutil.which("objdump"), "needs cc and objdump")
class ImportSweepTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        t = pathlib.Path(cls.tmp.name)
        src = t / "src"
        src.mkdir()
        cls.tree = t / "tree"
        for d in ("usr/bin", "usr/lib", "etc"):
            (cls.tree / d).mkdir(parents=True)

        def cc(name, code, out, *args):
            (src / name).write_text(code)
            subprocess.run(["cc", "-o", str(out), str(src / name), *args], check=True)
        lib = cls.tree / "usr/lib"
        # Named as a distribution installs it: the file carries the version, and the SONAME the
        # daemon's NEEDED names is only a symbolic link (not read), so reach goes by SONAME.
        cc("regex.c", REGEX_LIB, lib / "libregex-user.so.1.0.0", "-shared", "-fPIC",
           "-Wl,-soname,libregex-user.so.1")
        os.symlink("libregex-user.so.1.0.0", lib / "libregex-user.so")
        cc("own.c", OWN_RE, lib / "libownre.so", "-shared", "-fPIC")
        cc("uses.c", USES_LIB, cls.tree / "usr/bin/daemon", "-L" + str(lib), "-lregex-user")
        cc("wscanf.c", WSCANF, cls.tree / "usr/bin/wtool")
        cc("plain.c", PLAIN, cls.tree / "usr/bin/plain")
        cc("rpmatch.c", RPMATCH, cls.tree / "usr/bin/askyes")
        cc("ownuse.c", USES_OWN_RE, cls.tree / "usr/bin/ownuse", "-L" + str(lib), "-lownre")
        (cls.tree / "etc/notelf").write_text("regcomp\n")
        os.symlink("daemon", cls.tree / "usr/bin/daemon-link")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_tree_imports_and_reach(self):
        got = sweep.run_tree(str(self.tree))["tree"]
        # Seven ELF files; the text file and the symbolic links are not read.
        self.assertEqual(got["scanned"], 7)
        self.assertEqual(got["imports"]["/usr/lib/libregex-user.so.1.0.0"], ["regcomp"])
        wide = got["imports"]["/usr/bin/wtool"]
        self.assertEqual(len(wide), 1)
        self.assertRegex(wide[0], r"^(__isoc(99|23)_)?swscanf$")
        self.assertEqual(got["imports"]["/usr/bin/askyes"], ["rpmatch"])
        self.assertEqual(set(got["imports"]), {"/usr/lib/libregex-user.so.1.0.0", "/usr/bin/wtool", "/usr/bin/askyes"})
        # The daemon imports nothing itself and reaches regcomp through the library it needs.
        self.assertEqual(got["via"], {"/usr/bin/daemon": ["/usr/lib/libregex-user.so.1.0.0"]})

    def test_main_tree_skips_usr_mount_point_and_reads_usr(self):
        with tempfile.TemporaryDirectory() as root:
            os.mkdir(os.path.join(root, "usr"))
            shutil.copy(self.tree / "usr/bin/wtool", os.path.join(root, "usr", "stale"))
            got = sweep.run_tree(root, str(self.tree / "usr"))["tree"]
        self.assertNotIn("/usr/stale", got["imports"])
        self.assertIn("/usr/bin/wtool", got["imports"])

    def test_initrd_members(self):
        body = (self.tree / "usr/bin/wtool").read_bytes()
        data = newc([("usr", 0o40755, b""), ("usr/bin/wtool", 0o100755, body),
                     ("usr/bin/link", 0o120777, b"wtool"), ("etc/x", 0o100644, b"text")])
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "initrd"
            p.write_bytes(data)
            with tempfile.TemporaryDirectory() as scratch:
                got = sweep.initrd_place(p, scratch)
        self.assertEqual(got["scanned"], 1)
        self.assertEqual(list(got["imports"]), ["/usr/bin/wtool"])

    def test_control(self):
        tree = sweep.run_tree(str(self.tree))
        # The library imports regcomp, which is what the control asks of a main tree.
        self.assertEqual(sweep.problems(tree), [])
        no_regcomp = {"tree": {"scanned": 3, "imports": {"/usr/bin/wtool": ["swscanf"]}, "via": {}}}
        self.assertEqual(len(sweep.problems(no_regcomp)), 1)
        # A modules-only initrd holds no ELF file and passes; any other initrd must hold one (Potency 3).
        mods = {"scanned": 0, "imports": {}, "via": {}, "others": 0}
        one = dict(tree, **{"initrd:modules": mods, "initrd:main": dict(mods, scanned=4)})
        self.assertEqual(sweep.problems(one), [])
        empty_main = dict(one, **{"initrd:main": dict(mods, others=12)})
        self.assertEqual(sweep.problems(empty_main), ["initrd:main: no ELF file read among 12 executable files"])
        # A file objdump cannot read is never counted clean (Potency 2).
        unread = dict(tree, **{"initrd:main": dict(mods, scanned=1, unread=["/usr/bin/x"])})
        self.assertEqual(sweep.problems(unread), ["initrd:main: objdump could not read /usr/bin/x"])

    def test_objdump_failure_is_unread_static_is_read(self):
        with tempfile.TemporaryDirectory() as d:
            bad = pathlib.Path(d) / "bad"
            bad.write_bytes(b"\x7fELF" + b"\xff" * 60)
            got = sweep.sweep({"/usr/bin/bad": str(bad), "/usr/bin/plain": str(self.tree / "usr/bin/plain")})
        self.assertEqual(got["unread"], ["/usr/bin/bad"])
        if shutil.which("cc"):
            with tempfile.TemporaryDirectory() as d:
                (pathlib.Path(d) / "s.c").write_text(PLAIN)
                r = subprocess.run(["cc", "-static", "-o", d + "/st", d + "/s.c"], capture_output=True)
                if r.returncode == 0:
                    self.assertEqual(sweep.sweep({"/st": d + "/st"})["unread"], [])

    def test_initrd_counts_executable_non_elf_files(self):
        data = newc([("usr/lib/modules/x/a.ko.zst", 0o100644, b"\x28\xb5\x2f\xfd"),
                     ("usr/lib/modules/x/modules.dep", 0o100644, b""), ("usr/lib/firmware/f.bin", 0o100644, b"x"),
                     ("usr/bin/script", 0o100755, b"#!/bin/sh\n")])
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d) / "initrd"
            p.write_bytes(data)
            with tempfile.TemporaryDirectory() as scratch:
                got = sweep.initrd_place(p, scratch)
        self.assertEqual((got["scanned"], got["others"]), (0, 1))

    def test_notices_capped_at_ten(self):
        notes = sweep.annotations(["x" * 3000] * 15)
        self.assertEqual(len(notes), 10)
        self.assertIn("5 more notices: the full list is in the step log", notes[-1])

    def test_summary_names_importers_and_reach(self):
        lines = sweep.summary(sweep.run_tree(str(self.tree)))
        self.assertIn("tree regex: 2 files import a function, 1 more reach an importing library through NEEDED", lines)
        self.assertIn("  via /usr/bin/daemon: /usr/lib/libregex-user.so.1.0.0", lines)
        self.assertIn("tree wscanf: 1 files import a function, 0 more reach an importing library through NEEDED", lines)
        notes = sweep.annotations(lines)
        self.assertTrue(notes and all(n.startswith("::notice title=import sweep ") for n in notes))
        self.assertNotIn("\n", "".join(notes))


def place(imports, via=None, scanned=10):
    return {"scanned": scanned, "imports": imports, "via": via or {}}


class RefusalsTest(unittest.TestCase):
    """The claims the glibc records cite this step for fail the step once false (L3 6877627726)."""
    ALLOW = ["/usr/bin/bash", "/usr/lib/libsmartcols.so.1.*", "/usr/bin/lsblk"]
    OK = {"tree": place({"/usr/bin/bash": ["regcomp"], "/usr/lib/libsmartcols.so.1.1.0": ["regexec"]},
                        {"/usr/bin/lsblk": ["/usr/lib/libsmartcols.so.1.1.0"]})}

    def test_allowed_reach_passes(self):
        self.assertEqual(sweep.refusals(self.OK, self.ALLOW), [])

    def test_daemon_importing_regexec_fails(self):
        places = {"tree": dict(self.OK["tree"], imports=dict(self.OK["tree"]["imports"],
                                                             **{"/usr/lib/systemd/systemd": ["regexec"]}))}
        errs = sweep.refusals(places, self.ALLOW)
        self.assertEqual(len(errs), 1)
        self.assertIn("/usr/lib/systemd/systemd imports or reaches a regex function", errs[0])
        self.assertTrue(errs[0].endswith("entry: /usr/lib/systemd/systemd"))

    def test_daemon_reaching_regex_through_a_library_fails(self):
        places = {"initrd:x": place({"/usr/lib/libsmartcols.so.1.1.0": ["regcomp"]},
                                    {"/usr/lib/systemd/systemd-udevd": ["/usr/lib/libsmartcols.so.1.1.0"]}),
                  "tree": self.OK["tree"]}
        errs = sweep.refusals(places, self.ALLOW)
        self.assertEqual(errs, [e for e in errs if "initrd:x: /usr/lib/systemd/systemd-udevd" in e])
        self.assertEqual(len(errs), 1)

    def test_rpmatch_counts_as_regex(self):
        places = {"tree": dict(self.OK["tree"], imports=dict(self.OK["tree"]["imports"], **{"/usr/bin/rm": ["rpmatch"]}))}
        self.assertEqual(len(sweep.refusals(places, self.ALLOW)), 1)

    def test_any_wide_scanf_fails_allowlisted_or_not(self):
        for p in ("/usr/bin/bash", "/usr/lib/systemd/systemd"):
            places = {"tree": dict(self.OK["tree"], imports=dict(self.OK["tree"]["imports"], **{p: self.OK["tree"]["imports"].get(p, []) + ["swscanf"]}))}
            with self.subTest(p=p):
                errs = sweep.refusals(places, self.ALLOW)
                self.assertEqual(len(errs), 1)
                self.assertIn("wide scanf", errs[0])
        lib = {"tree": place({"/usr/lib/libw.so.1": ["__isoc99_vswscanf"]}, {"/usr/bin/bash": ["/usr/lib/libw.so.1"]})}
        self.assertEqual(len([e for e in sweep.refusals(lib, ["/usr/bin/bash"]) if "wide scanf" in e]), 2)

    def test_unused_glob_fails(self):
        errs = sweep.refusals(self.OK, self.ALLOW + ["/usr/bin/gone"])
        self.assertEqual(errs, ["import_sweep.allow: /usr/bin/gone matches no file that reaches a regex function; remove it"])

    def test_summary_exits_one_on_a_refusal(self):
        with tempfile.TemporaryDirectory() as d:
            j, a = pathlib.Path(d) / "p.json", pathlib.Path(d) / "allow"
            a.write_text("# comment\n/usr/bin/bash  # the shell\n/usr/lib/libsmartcols.so.1.*\n/usr/bin/lsblk\n")
            self.assertEqual(sweep.load_allow(a), self.ALLOW)
            bad = {"tree": dict(self.OK["tree"], imports=dict(self.OK["tree"]["imports"],
                                                              **{"/usr/lib/systemd/systemd": ["regexec", "swscanf"]}))}
            for places, want in ((self.OK, 0), (bad, 1)):
                j.write_text(__import__("json").dumps(places))
                with self.subTest(want=want), contextlib.redirect_stdout(io.StringIO()), \
                        contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(sweep.main(["--summary", str(j), str(a)]), want)

    def test_shipped_allowlist_is_absolute_globs(self):
        allow = sweep.load_allow(sweep.ALLOW)
        self.assertTrue(allow)
        for a in allow:
            with self.subTest(a=a):
                self.assertTrue(a.startswith("/usr/"), a)
                self.assertNotIn("systemd/systemd-udevd", a)
                self.assertFalse(fnmatch.fnmatchcase("/usr/lib/systemd/systemd", a), a)


if __name__ == "__main__":
    unittest.main()
