"""VULN-debian-r6-f2 (#5697): image/import_sweep.py reads which ELF files in a built image import
glibc's POSIX regex or wide scanf functions, directly or through a library they need, in the main
tree and in each initrd, so the glibc records' reachability claims come from the tree CI builds."""
# REQ: EVL-5
import importlib.util
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
        cc("regex.c", REGEX_LIB, lib / "libregex-user.so", "-shared", "-fPIC")
        cc("own.c", OWN_RE, lib / "libownre.so", "-shared", "-fPIC")
        cc("uses.c", USES_LIB, cls.tree / "usr/bin/daemon", "-L" + str(lib), "-lregex-user")
        cc("wscanf.c", WSCANF, cls.tree / "usr/bin/wtool")
        cc("plain.c", PLAIN, cls.tree / "usr/bin/plain")
        cc("ownuse.c", USES_OWN_RE, cls.tree / "usr/bin/ownuse", "-L" + str(lib), "-lownre")
        (cls.tree / "etc/notelf").write_text("regcomp\n")
        os.symlink("daemon", cls.tree / "usr/bin/daemon-link")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_tree_imports_and_reach(self):
        got = sweep.run_tree(str(self.tree))["tree"]
        # Six ELF files; the text file and the symbolic link are not read.
        self.assertEqual(got["scanned"], 6)
        self.assertEqual(got["imports"]["/usr/lib/libregex-user.so"], ["regcomp"])
        wide = got["imports"]["/usr/bin/wtool"]
        self.assertEqual(len(wide), 1)
        self.assertRegex(wide[0], r"^(__isoc(99|23)_)?swscanf$")
        self.assertEqual(set(got["imports"]), {"/usr/lib/libregex-user.so", "/usr/bin/wtool"})
        # The daemon imports nothing itself and reaches regcomp through the library it needs.
        self.assertEqual(got["via"], {"/usr/bin/daemon": ["/usr/lib/libregex-user.so"]})

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
        empty = dict(tree, **{"initrd:x": {"scanned": 0, "imports": {}, "via": {}}})
        self.assertEqual(sweep.problems(empty), ["initrd:x: no ELF file read"])

    def test_summary_names_importers_and_reach(self):
        lines = sweep.summary(sweep.run_tree(str(self.tree)))
        self.assertIn("tree regex: 1 import, 1 reach one through NEEDED", lines)
        self.assertIn("  via /usr/bin/daemon: /usr/lib/libregex-user.so", lines)
        self.assertIn("tree wscanf: 1 import, 0 reach one through NEEDED", lines)
        notes = sweep.annotations(lines)
        self.assertTrue(notes and all(n.startswith("::notice title=import sweep ") for n in notes))
        self.assertNotIn("\n", "".join(notes))


if __name__ == "__main__":
    unittest.main()
