"""VULN-debian-r6-f2 (#5697): image/import_sweep.py reads which ELF files in a built image import
glibc's POSIX regex or wide scanf functions, directly or through a library they need, in the main
tree and in each initrd, so the glibc records' reachability claims come from the tree CI builds.
VULN-debian-r5-reach (#5341): it also counts, in each file whose bytes name an OpenSSL cipher fetch by
name string (the only way to select AES-GCM-SIV), the call sites to it, held to the allowlist's
[cipher] section, so the openssl records' reach note is checked on each build."""
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
# A stand-in libcrypto (its fetch bound to OPENSSL_3.0.0, as the real one's is), a library calling the
# fetch twice, a program naming it only as a dlsym string, and a stand-in libsystemd-shared exporting
# openssl_cipher_many (SD_SHARED) with one caller inside it, stripped as Debian ships it.
FAKE_CRYPTO = "void *EVP_CIPHER_fetch(void *c, const char *n, const char *p) { return (void *)n; }\n"
OPENSSL_MAP = "OPENSSL_3.0.0 { global: EVP_CIPHER_fetch; local: *; };\n"
FETCHER = ('void *EVP_CIPHER_fetch(void *, const char *, const char *);\n'
           'void *a(const char *n) { return EVP_CIPHER_fetch(0, n, 0); }\n'
           'void *b(void) { return EVP_CIPHER_fetch(0, "AES-256-CBC", 0); }\n')
DLSYM = ('#include <dlfcn.h>\nint main(void) { return dlsym(RTLD_DEFAULT, "EVP_get_cipherbyname") != 0; }\n')
SHARED = ('void *EVP_CIPHER_fetch(void *, const char *, const char *);\n'
          'void *openssl_cipher_many(const char *n) { return EVP_CIPHER_fetch(0, n, 0); }\n'
          'void *tpm2_seal(void) { return openssl_cipher_many("aes-128-cfb"); }\n')
SD_MAP = "SD_SHARED { global: openssl_cipher_many; tpm2_seal; local: *; };\n"


def newc(members):
    """A newc cpio archive of MEMBERS (name, mode, content), then the trailer."""
    out = b""
    for i, (n, mode, body) in enumerate(list(members) + [("TRAILER!!!", 0, b"")]):
        name = n.encode() + b"\0"
        out += b"070701" + b"".join(b"%08X" % v for v in (1000 + i, mode, 0, 0, 1, 0, len(body), 0, 0, 0, 0,
                                                            len(name), 0))
        out += name + b"\0" * (-(110 + len(name)) % 4) + body + b"\0" * (-len(body) % 4)
    return out


NEEDS_CC = unittest.skipUnless(shutil.which("cc") and shutil.which("objdump") and shutil.which("strip"),
                               "needs cc, objdump and strip")


class Tree(unittest.TestCase):
    """A small tree of ELF files built with the host's cc (no tests of its own)."""

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
        (src / "openssl.map").write_text(OPENSSL_MAP)
        (src / "sd.map").write_text(SD_MAP)
        cc("crypto.c", FAKE_CRYPTO, lib / "libcrypto.so.3", "-shared", "-fPIC", "-Wl,-soname,libcrypto.so.3",
           "-Wl,--version-script," + str(src / "openssl.map"))
        cc("fetcher.c", FETCHER, lib / "libfetcher.so.1", "-shared", "-fPIC", "-L" + str(lib), "-l:libcrypto.so.3")
        cc("dlsym.c", DLSYM, cls.tree / "usr/bin/dlsymmer", "-ldl")
        cc("shared.c", SHARED, lib / "libsystemd-shared-257.so", "-shared", "-fPIC", "-L" + str(lib),
           "-l:libcrypto.so.3", "-Wl,--version-script," + str(src / "sd.map"))
        subprocess.run(["strip", str(lib / "libsystemd-shared-257.so")], check=True)
        (cls.tree / "etc/notelf").write_text("regcomp\n")
        os.symlink("daemon", cls.tree / "usr/bin/daemon-link")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()


@NEEDS_CC
class ImportSweepTest(Tree):

    def test_tree_imports_and_reach(self):
        got = sweep.run_tree(str(self.tree))["tree"]
        # Eleven ELF files; the text file and the symbolic links are not read.
        self.assertEqual(got["scanned"], 11)
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
        no_regcomp = {"tree": dict(tree["tree"], imports={"/usr/bin/wtool": ["swscanf"]})}
        self.assertEqual(len(sweep.problems(no_regcomp)), 1)
        # No call site of EVP_CIPHER_fetch in the main tree: the cipher scan read nothing (#5341).
        no_fetch = {"tree": dict(tree["tree"], cipher={"/usr/bin/dlsymmer": {"EVP_get_cipherbyname": 0}})}
        self.assertEqual(sweep.problems(no_fetch), [
            "tree: no call site of EVP_CIPHER_fetch, so the cipher scan read nothing it should have (control)"])
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


@NEEDS_CC
class CipherSitesTest(Tree):
    """#5341: the files that can fetch an OpenSSL cipher by name, and their call sites, from the binary."""

    def test_sites_counted_per_file(self):
        got = sweep.run_tree(str(self.tree))["tree"]["cipher"]
        self.assertEqual(got["/usr/lib/libfetcher.so.1"], {"EVP_CIPHER_fetch": 2})
        # The definer counts its own callers: one call to the fetch, one internal call to openssl_cipher_many
        # (through its PLT entry or directly), read from a stripped library's dynamic symbols.
        self.assertEqual(got["/usr/lib/libsystemd-shared-257.so"], {"EVP_CIPHER_fetch": 1, "openssl_cipher_many": 1})
        # A name held only as a string (dlsym) is listed with no site, so it still needs an entry.
        self.assertEqual(got["/usr/bin/dlsymmer"], {"EVP_get_cipherbyname": 0})
        self.assertIn("/usr/lib/libcrypto.so.3", got)
        self.assertNotIn("/usr/bin/plain", got)

    def test_site_patterns(self):
        lines = {"  4f2a3:\tcall   4a0d0 <EVP_CIPHER_fetch@plt>": "EVP_CIPHER_fetch",
                 "  1139:\tjmp    1030 <openssl_cipher_many@@SD_SHARED>": "openssl_cipher_many",
                 "  1139:\tcall   *0x2e91(%rip)        # 3fd0 <EVP_get_cipherbyname@OPENSSL_3.0.0>": "EVP_get_cipherbyname",
                 "  1140:\tjmp    1150 <openssl_cipher_many+0x20>": None,
                 "  1140:\tmov    0x8(%rsp),%rax": None}
        for line, want in lines.items():
            with self.subTest(line=line):
                m = sweep.SITE.search(line)
                self.assertEqual(m and m.group(1), want)

    def test_refusals_against_the_entries(self):
        places = sweep.run_tree(str(self.tree))
        ok = {"/usr/lib/libfetcher.so.*": {"EVP_CIPHER_fetch": 2},
              "/usr/lib/libsystemd-shared-*.so": {"EVP_CIPHER_fetch": 1, "openssl_cipher_many": 1},
              "/usr/lib/libcrypto.so.3": "*", "/usr/bin/dlsymmer": {"EVP_get_cipherbyname": 0}}
        self.assertEqual(sweep.cipher_refusals(places, ok), [])
        # A new call site in a reviewed library fails until its entry is reviewed again.
        more = dict(ok, **{"/usr/lib/libfetcher.so.*": {"EVP_CIPHER_fetch": 1}})
        errs = sweep.cipher_refusals(places, more)
        self.assertEqual(len(errs), 1)
        self.assertIn("/usr/lib/libfetcher.so.1 holds cipher-fetch sites EVP_CIPHER_fetch=2, not the "
                      "EVP_CIPHER_fetch=1", errs[0])
        # A file with no entry fails, naming the entry to add; so does an entry that matches nothing.
        errs = sweep.cipher_refusals(places, dict({k: v for k, v in ok.items() if k != "/usr/bin/dlsymmer"},
                                                  **{"/usr/sbin/gone": "*"}))
        self.assertEqual(len(errs), 2)
        self.assertTrue(errs[0].endswith("add the entry: /usr/bin/dlsymmer EVP_get_cipherbyname=0"), errs[0])
        self.assertIn("[cipher] /usr/sbin/gone matches no file", errs[1])

    def test_summary_lists_sites(self):
        lines = sweep.summary(sweep.run_tree(str(self.tree)))
        self.assertIn("tree cipher: 4 files can fetch an OpenSSL cipher by name", lines)
        self.assertIn("  sites /usr/lib/libfetcher.so.1: EVP_CIPHER_fetch=2", lines)


def place(imports, via=None, scanned=10):
    return {"scanned": scanned, "imports": imports, "via": via or {}}


class RefusalsTest(unittest.TestCase):
    """The claims the glibc records cite this step for fail the step once false (L3 6877627726)."""
    ALLOW = ["/usr/bin/bash", "/usr/lib/libsmartcols.so.1.*", "/usr/bin/lsblk"]
    OK = {"tree": dict(place({"/usr/bin/bash": ["regcomp"], "/usr/lib/libsmartcols.so.1.1.0": ["regexec"]},
                             {"/usr/bin/lsblk": ["/usr/lib/libsmartcols.so.1.1.0"]}),
                       cipher={"/usr/lib/libcrypto.so.3": {"EVP_CIPHER_fetch": 40}})}

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
            a.write_text("# comment\n/usr/bin/bash  # the shell\n/usr/lib/libsmartcols.so.1.*\n/usr/bin/lsblk\n"
                         "[cipher]\n/usr/lib/libc*.so.3 EVP_CIPHER_fetch=1  # why\n/usr/lib/libcrypto.so.3 *\n")
            self.assertEqual(sweep.load_allow(a), self.ALLOW)
            self.assertEqual(sweep.read_allow(a)[1], {"/usr/lib/libc*.so.3": {"EVP_CIPHER_fetch": 1},
                                                      "/usr/lib/libcrypto.so.3": "*"})
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
        # #5341: the [cipher] entries are absolute globs too, and libcryptsetup's sites are counted.
        cipher = sweep.read_allow(sweep.ALLOW)[1]
        self.assertTrue(all(g.startswith("/usr/") for g in cipher), cipher)
        self.assertIn("EVP_CIPHER_fetch", cipher["/usr/lib/x86_64-linux-gnu/libcryptsetup.so.12.*"])


if __name__ == "__main__":
    unittest.main()
