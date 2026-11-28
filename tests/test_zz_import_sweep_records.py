"""IMG-pin-refusal-diff (#6448): each pinned image/import_sweep.allow entry records, beside each SHA-256, the
package and version that installed the file and the symbols the sweep reads in it, so an allow change shows a
real diff. The digest still decides what is accepted; a record the build no longer gives fails, a refused
re-pin prints the old and new versions and the symbols added and removed, and the old format is refused."""
# REQ: EVL-5
import contextlib
import hashlib
import importlib.util
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "image"))
spec = importlib.util.spec_from_file_location("import_sweep", ROOT / "image" / "import_sweep.py")
sweep = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sweep)

OLD, NEW, GONE = "aa" * 32, "bb" * 32, "cc" * 32
GLIBC = "/usr/lib/x86_64-linux-gnu/libc.so.6"


def tree(sha, ver="5.2.37-2", syms=("regcomp", "regexec"), owner=True):
    """A main tree whose bash imports SYMS, holds bytes SHA and was installed by bash VER."""
    t = {"scanned": 3, "imports": {"/usr/bin/bash": list(syms)}, "via": {},
         "carries": {"/usr/sbin/ldconfig": ["glob"]}, "glibc": {GLIBC: ["glob", "regcomp", "vfwscanf"]},
         "cipher": {"/usr/lib/libcrypto.so.3": {"EVP_CIPHER_fetch": 1}},
         "sha256": {"/usr/bin/bash": sha, "/usr/sbin/ldconfig": GONE, "/usr/lib/libcrypto.so.3": GONE}}
    if owner:
        t["owner"] = {"/usr/bin/bash": ["bash", ver], "/usr/sbin/ldconfig": ["libc-bin", "2.41-12"],
                      "/usr/lib/libcrypto.so.3": ["libssl3t64", "3.5.4-1"]}
    return {"tree": t}


ALLOW = ("/usr/bin/bash sha256=%s pkg=bash ver=5.2.37-2 syms=regcomp,regexec  # the shell\n"
         "[glob]\n/usr/sbin/ldconfig sha256=%s pkg=libc-bin ver=2.41-12 syms=glob\n"
         "[cipher]\n/usr/lib/libcrypto.so.3 *\n" % (OLD, GONE))


def run(*argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = sweep.main(list(argv))
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


class RecordTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = pathlib.Path(self.tmp.name)
        self.allow = self.d / "allow"
        self.allow.write_text(ALLOW)

    def tearDown(self):
        self.tmp.cleanup()

    def summary(self, places):
        (self.d / "p.json").write_text(json.dumps(places))
        code, out, _ = run("--summary", str(self.d / "p.json"), str(self.allow))
        return code, [l for l in out.splitlines() if l.startswith("::error")]

    def test_a_true_record_passes(self):
        self.assertEqual(self.summary(tree(OLD)), (0, []))

    def test_the_old_format_is_refused(self):
        self.allow.write_text("/usr/bin/bash sha256=%s\n" % OLD)
        with self.assertRaises(SystemExit) as cm:
            sweep.read_allow(self.allow)
        self.assertIn(":1: /usr/bin/bash sha256=%s: sha256=%s is not followed by pkg=NAME ver=VERSION syms=NAME,..."
                      % (OLD, OLD), str(cm.exception))

    def test_a_stale_version_fails_on_the_same_bytes(self):
        code, errs = self.summary(tree(OLD, ver="5.2.37-2+b1"))
        self.assertEqual(code, 1)
        self.assertEqual(len(errs), 1)
        self.assertIn("holds the bytes import_sweep.allow /usr/bin/bash pins (sha256=%s), but its record is stale: "
                      "recorded bash 5.2.37-2, now bash 5.2.37-2+b1; symbols unchanged (regcomp,regexec)" % OLD, errs[0])
        self.assertIn("then record it (import_sweep.py --record): /usr/bin/bash sha256=%s pkg=bash ver=5.2.37-2+b1 "
                      "syms=regcomp,regexec" % OLD, errs[0])

    def test_a_stale_symbol_list_fails(self):
        code, errs = self.summary(tree(OLD, syms=("regcomp", "rpmatch")))
        self.assertEqual(code, 1)
        self.assertIn("recorded bash 5.2.37-2, now bash 5.2.37-2; symbols +rpmatch -regexec", errs[0])

    def test_unread_package_data_fails(self):
        code, errs = self.summary(tree(OLD, owner=False))
        self.assertEqual(code, 1)
        self.assertTrue(any("its package could not be read from the build (the refusal stands)" in e for e in errs))

    def test_a_refused_repin_prints_both_versions_and_the_symbol_diff(self):
        code, errs = self.summary(tree(NEW, ver="5.2.37-3", syms=("regcomp", "rpmatch")))
        self.assertEqual(code, 1)
        repin = [e for e in errs if "holds other bytes" in e]
        self.assertEqual(len(repin), 1)
        self.assertIn("recorded bash 5.2.37-2, now bash 5.2.37-3; symbols +rpmatch -regexec", repin[0])
        self.assertTrue(repin[0].endswith("then pin them: /usr/bin/bash sha256=%s pkg=bash ver=5.2.37-3 "
                                          "syms=regcomp,rpmatch" % NEW), repin[0])
        # It stays a refusal, and the old pin is reported as held by nothing.
        self.assertTrue(any("pins sha256=%s, which no file it accepts holds" % OLD in e for e in errs))

    def test_a_refused_repin_with_unreadable_package_data_says_so(self):
        code, errs = self.summary(tree(NEW, syms=("regcomp",), owner=False))
        self.assertEqual(code, 1)
        repin = [e for e in errs if "holds other bytes" in e][0]
        self.assertIn("recorded bash 5.2.37-2, its package could not be read from the build (the refusal stands); "
                      "symbols -regexec", repin)

    def test_record_rewrites_records_and_keeps_digests_and_comments(self):
        (self.d / "p.json").write_text(json.dumps(tree(OLD, ver="5.2.37-2+b1", syms=("regcomp",))))
        code, out, _ = run("--record", str(self.d / "p.json"), str(self.allow))
        self.assertEqual(code, 0)
        self.assertEqual(out, ALLOW.replace("ver=5.2.37-2 syms=regcomp,regexec", "ver=5.2.37-2+b1 syms=regcomp"))
        self.allow.write_text(out)
        self.assertEqual(self.summary(tree(OLD, ver="5.2.37-2+b1", syms=("regcomp",))), (0, []))

    def test_record_adds_no_pin_for_new_bytes(self):
        (self.d / "p.json").write_text(json.dumps(tree(NEW, ver="5.2.37-3")))
        code, out, _ = run("--record", str(self.d / "p.json"), str(self.allow))
        self.assertEqual((code, out), (0, ALLOW))

    def test_record_refuses_unread_package_data(self):
        (self.d / "p.json").write_text(json.dumps(tree(OLD, owner=False)))
        code, out, _ = run("--record", str(self.d / "p.json"), str(self.allow))
        self.assertIn("import sweep: no package and version read for ", str(code))
        self.assertIn("regex /usr/bin/bash sha256=%s" % OLD, str(code))
        self.assertEqual(out, "")

    def test_bad_records_name_the_line(self):
        pin = "/a sha256=%s " % OLD
        for body, want in ((pin + "pkg=a ver=1 syms=b,a", "syms out of order or twice"),
                           (pin + "pkg=a ver=1 syms=a,a", "syms out of order or twice"),
                           (pin + "pkg=a,b ver=1 syms=-", "not one version for each package"),
                           (pin + "pkg=- ver=1 syms=-", "not one version for each package"),
                           (pin + "pkg=? ver=? syms=-", "is not followed by pkg=NAME"),
                           (pin + "ver=1 pkg=a syms=-", "is not followed by pkg=NAME"),
                           (pin + "pkg=a ver=1", "is not followed by pkg=NAME"),
                           (pin + "pkg=a ver=1 syms=- extra", "is not sha256=HEX")):
            self.allow.write_text(body + "\n")
            with self.subTest(body=body), self.assertRaises(SystemExit) as cm:
                sweep.read_allow(self.allow)
            self.assertIn(":1: ", str(cm.exception))
            self.assertIn(want, str(cm.exception))

    def test_each_section_records_its_own_symbols(self):
        v = {"imports": {"/b": ["glob", "regcomp"]}, "lookups": {"/n": ["glob"]}, "carries": {},
             "through": {"/n": {"/usr/lib/libw.so.1": ["dlsym", "dlvsym"]}}, "unresolved": {"/u": ["libx.so.1"]}}
        self.assertEqual(sweep.syms("regex", v, "/b"), ("regcomp",))
        self.assertEqual(sweep.syms("glob", v, "/b"), ("glob",))
        self.assertEqual(sweep.syms("glob", v, "/n"), ("glob",))
        self.assertEqual(sweep.syms("wrapper", v, "/usr/lib/libw.so.1"), ("dlsym", "dlvsym"))
        self.assertEqual(sweep.syms("unresolved", v, "/u"), ("libx.so.1",))

    def test_shipped_entries_all_carry_records(self):
        text = sweep.ALLOW.read_text()
        regex, _c, globs, wrappers, unres, _u = sweep.read_allow(sweep.ALLOW)
        for e in regex + globs + wrappers + unres:
            with self.subTest(e=e.glob):
                self.assertTrue(e.via or len(e.records) == len(e.sha256) >= 1)
        # The section comments name the format, and --record keeps the file as it is when nothing moved.
        self.assertIn("pkg=NAME ver=VERSION", text)


class PackageDataTest(unittest.TestCase):
    def test_owners_versions_and_fail_closed(self):
        with tempfile.TemporaryDirectory() as d:
            out = pathlib.Path(d)
            (out / "guest").mkdir()
            (out / "agentos.dpkg-status").write_text(
                "Package: bash\nStatus: install ok installed\nVersion: 5.2.37-2\n\n"
                "Package: libc6\nStatus: install ok installed\nArchitecture: amd64\nVersion: 2.41-12\n\n"
                "Package: gone\nStatus: deinstall ok config-files\nVersion: 1\n")
            (out / "agentos.dpkg-owners").write_text(json.dumps(
                {"/usr/bin/bash": "bash", "/lib/x86_64-linux-gnu/libc.so.6": "libc6:amd64", "/usr/bin/old": "gone"}))
            guest_bash = out / "gbash"
            guest_bash.write_bytes(b"guest bash")
            (out / "guest/agentos.dpkg-status").write_text("Package: bash\nStatus: install ok installed\n"
                                                           "Version: 5.2.37-3\n")
            (out / "guest/agentos.md5sums").write_text("%s bash\n" % hashlib.md5(b"guest bash").hexdigest())
            owner = sweep.package_data(out)
            self.assertEqual(owner("/usr/bin/bash", None), ("bash", "5.2.37-2"))
            self.assertEqual(owner(GLIBC, None), ("libc6", "2.41-12"))
            self.assertEqual(owner("/usr/lib/agentos/infer/llama-server", None), ("-", "-"))
            self.assertEqual(owner("/usr/bin/old", None), ("?", "?"))
            self.assertEqual(owner("/usr/lib/agentos/images/codex/usr/bin/bash", guest_bash), ("bash", "5.2.37-3"))
            other = out / "other"
            other.write_bytes(b"node")
            self.assertEqual(owner("/usr/lib/agentos/images/openclaw/usr/local/bin/node", other), ("-", "-"))
            (out / "agentos.dpkg-owners").unlink()
            self.assertEqual(sweep.package_data(out)("/usr/bin/bash", None), ("?", "?"))

    def test_postinst_writes_the_owners_the_sweep_reads(self):
        text = (ROOT / "image/mkosi/mkosi.postinst").read_text()
        self.assertIn('"$OUTPUTDIR/%s"' % sweep.OWNERS, text)
        self.assertIn("drop.owners(", text)
        line = next(l for l in text.splitlines() if sweep.OWNERS in l and not l.startswith("#"))
        with tempfile.TemporaryDirectory() as d:
            root, out = pathlib.Path(d, "root"), pathlib.Path(d, "out")
            (root / "var/lib/dpkg/info").mkdir(parents=True)
            out.mkdir()
            (root / "var/lib/dpkg/info/bash.list").write_text("/.\n/bin/bash\n")
            subprocess.run(["sh", "-ec", line], check=True, env={
                "SRCDIR": str(ROOT / "image/mkosi"), "BUILDROOT": str(root), "OUTPUTDIR": str(out),
                "PATH": "/usr/bin:/bin"})
            self.assertEqual(json.loads((out / sweep.OWNERS).read_text())["/usr/bin/bash"], "bash")


if __name__ == "__main__":
    unittest.main()
