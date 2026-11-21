"""VULN-debian-r6-f2 (#5697): image/import_sweep.py reads which ELF files in a built image import
glibc's POSIX regex or wide scanf functions, directly or through a library they need, in the main
tree and in each initrd, so the glibc records' reachability claims come from the tree CI builds.
VULN-debian-r5-reach (#5341): it also counts, in each file whose bytes name an OpenSSL cipher fetch by
name string (the only way to select AES-GCM-SIV), the references to it, held to the allowlist's
[cipher] section, so the openssl records' reach note is checked on each build.
VULN-cipher-sweep-tidy (#5861): each counted entry is keyed to the reviewed file's SHA-256, so a new
package version fails until its source is read again; malformed, empty, repeated and overlapping
entries are refused, and every refusal points at the records' reach note.
VULN-debian-r13-f1 (#6285): it also reads which files import or reach glibc's glob() (and wordexp, which
calls it), held to the allowlist's [glob] section, so the DEBIAN-CVE-2026-126765 records' reach is
read from the tree."""
# REQ: EVL-5
import contextlib
import ctypes
import ctypes.util
import errno
import fnmatch
import hashlib
import importlib.util
import io
import os
import pathlib
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

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
# L3 6899461135: the same direct call, then the same plus a table holding the fetch's address and a call
# through it. The table must change the count, as a new call would.
ONE_CALL = ('void *EVP_CIPHER_fetch(void *, const char *, const char *);\n'
            'void *a(const char *n) { return EVP_CIPHER_fetch(0, n, 0); }\n')
TABLE = ONE_CALL + ('typedef void *(*F)(void *, const char *, const char *);\n'
                    'F table[] = {EVP_CIPHER_fetch};\n'
                    'void *b(int i, const char *n) { return table[i](0, n, 0); }\n')
# #6298: a static glob() caller, the control's stand-in for Debian's ldconfig.
STATIC_GLOB = "#include <glob.h>\nint main(int c, char **v) { glob_t g; return glob(v[0], 0, 0, &g); }\n"
# A program spelling the cipher, with no fetch name (Security 6899468190).
SPELLS = 'const char *c = "aes-256-gcm-siv";\nint main(void) { return c[0]; }\n'
# A program selecting KRB5KDF by name, which takes a "cipher" and does not check its mode (#5861).
KRB5KDF = 'const char *k = "KRB5KDF";\nint main(void) { return k[0]; }\n'


def newc(members):
    """A newc cpio archive of MEMBERS (name, mode, content, and optionally ino and nlink), then the trailer."""
    out = b""
    for i, (n, mode, body, *link) in enumerate(list(members) + [("TRAILER!!!", 0, b"")]):
        name = n.encode() + b"\0"
        ino, nlink = link or (1000 + i, 1)
        out += b"070701" + b"".join(b"%08X" % v for v in (ino, mode, 0, 0, nlink, 0, len(body), 0, 0, 0, 0,
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
        for d in ("usr/bin", "usr/lib", "usr/sbin", "etc"):
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
        cc("one.c", ONE_CALL, lib / "libonecall.so.1", "-shared", "-fPIC", "-L" + str(lib), "-l:libcrypto.so.3")
        cc("table.c", TABLE, lib / "libtable.so.1", "-shared", "-fPIC", "-L" + str(lib), "-l:libcrypto.so.3")
        cc("spells.c", SPELLS, cls.tree / "usr/bin/spells")
        cc("kdfname.c", KRB5KDF, cls.tree / "usr/bin/krb5kdf")
        cc("shared.c", SHARED, lib / "libsystemd-shared-257.so", "-shared", "-fPIC", "-L" + str(lib),
           "-l:libcrypto.so.3", "-Wl,--version-script," + str(src / "sd.map"))
        subprocess.run(["strip", str(lib / "libsystemd-shared-257.so")], check=True)
        # #6298: the static-scan control's stand-in, a static glob() caller as Debian's ldconfig is.
        cc("ldconfig.c", STATIC_GLOB, cls.tree / "usr/sbin/ldconfig", "-D_GNU_SOURCE", "-static", "-s")
        (cls.tree / "etc/notelf").write_text("regcomp\n")
        os.symlink("daemon", cls.tree / "usr/bin/daemon-link")

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()


@NEEDS_CC
class ImportSweepTest(Tree):

    def test_tree_imports_and_reach(self):
        got = sweep.run_tree(str(self.tree))["tree"]
        # Sixteen ELF files; the text file and the symbolic links are not read.
        self.assertEqual(got["scanned"], 16)
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
        # The library imports regcomp, which is what the control asks of a main tree; a glibc holding every
        # mark is the marks' control (#6299, GlibcControlTest).
        tree["tree"]["glibc"] = {"/usr/lib/libc.so.6": ["glob", "regcomp", "vfwscanf"]}
        # The host's libc is outside this tree: every NEEDED it leaves unresolved is libc.so.6 (UnresolvedTest).
        self.assertEqual({n for names in tree["tree"].pop("unresolved").values() for n in names}, {"libc.so.6"})
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
        self.assertIn("tree regex: 2 files import a function (or look one up, or carry a copy), 1 more reach one through a NEEDED library", lines)
        self.assertIn("  via /usr/bin/daemon: /usr/lib/libregex-user.so.1.0.0", lines)
        self.assertIn("tree wscanf: 1 files import a function (or look one up, or carry a copy), 0 more reach one through a NEEDED library", lines)
        notes = sweep.annotations(lines)
        self.assertTrue(notes and all(n.startswith("::notice title=import sweep ") for n in notes))
        self.assertNotIn("\n", "".join(notes))


@NEEDS_CC
class CipherSitesTest(Tree):
    """#5341: the files holding a by-name cipher selector or spelling GCM-SIV, and their counts, from the binary."""

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

    def test_address_taken_counts(self):
        # L3 6899461135: a pointer to the fetch in a table is a reference, so the two libraries differ.
        got = sweep.run_tree(str(self.tree))["tree"]["cipher"]
        one, table = got["/usr/lib/libonecall.so.1"], got["/usr/lib/libtable.so.1"]
        self.assertEqual(one, {"EVP_CIPHER_fetch": 1})
        self.assertGreater(table["EVP_CIPHER_fetch"], one["EVP_CIPHER_fetch"])

    def test_cipher_spelt_is_held(self):
        got = sweep.run_tree(str(self.tree))["tree"]["cipher"]
        self.assertEqual(got["/usr/bin/spells"], {"GCM-SIV": 1})
        self.assertEqual(got["/usr/bin/krb5kdf"], {"KRB5KDF": 1})

    def test_digest_of_each_held_file(self):
        tree = sweep.run_tree(str(self.tree))["tree"]
        # #6299: and of each file reaching a group, for the pinned [regex] and [glob] entries, and of each
        # with an unresolved NEEDED name, for [unresolved] (Security on #6382).
        self.assertEqual(set(tree["sha256"]), set(tree["cipher"]) | {p for _, p in sweep.reach({"t": tree})}
                         | set(tree["unresolved"]))
        self.assertIn("/usr/bin/daemon", tree["sha256"])
        self.assertEqual(tree["sha256"]["/usr/bin/spells"],
                         __import__("hashlib").sha256((self.tree / "usr/bin/spells").read_bytes()).hexdigest())

    def test_site_patterns(self):
        lines = {"  4f2a3:\tcall   4a0d0 <EVP_CIPHER_fetch@plt>": "EVP_CIPHER_fetch",
                 "  1139:\tjmp    1030 <openssl_cipher_many@@SD_SHARED>": "openssl_cipher_many",
                 "  1139:\tcall   *0x2e91(%rip)        # 3fd0 <EVP_get_cipherbyname@OPENSSL_3.0.0>": "EVP_get_cipherbyname",
                 "  1140:\tjmp    1150 <openssl_cipher_many+0x20>": None,
                 "  1139:\tmov    0x2e99(%rip),%rax        # 3fd8 <EVP_CIPHER_fetch@Base>": "EVP_CIPHER_fetch",
                 "  1139:\tlea    -0x7(%rip),%rax        # 1139 <openssl_cipher_many>": "openssl_cipher_many",
                 "0000000000001139 <openssl_cipher_many@@SD_SHARED>:": None,
                 "  1140:\tmov    0x8(%rsp),%rax": None}
        for line, want in lines.items():
            with self.subTest(line=line):
                m = sweep.SITE.search(line)
                self.assertEqual(m and m.group(1), want)

    def entries(self, places):
        """The [cipher] entries that hold PLACES as read, each counted one keyed to its file's SHA-256."""
        t = places["tree"]

        def counted(p, sites):
            return {"sha256": t["sha256"][p], "sites": sites}
        return {"/usr/lib/libfetcher.so.*": counted("/usr/lib/libfetcher.so.1", {"EVP_CIPHER_fetch": 2}),
                "/usr/lib/libsystemd-shared-*.so": counted("/usr/lib/libsystemd-shared-257.so",
                                                           {"EVP_CIPHER_fetch": 1, "openssl_cipher_many": 1}),
                "/usr/lib/libcrypto.so.3": "*",
                "/usr/bin/dlsymmer": counted("/usr/bin/dlsymmer", {"EVP_get_cipherbyname": 0}),
                "/usr/lib/libonecall.so.1": counted("/usr/lib/libonecall.so.1", {"EVP_CIPHER_fetch": 1}),
                "/usr/lib/libtable.so.1": "*", "/usr/bin/spells": counted("/usr/bin/spells", {"GCM-SIV": 1}),
                "/usr/bin/krb5kdf": "*"}

    def test_refusals_against_the_entries(self):
        places = sweep.run_tree(str(self.tree))
        ok = self.entries(places)
        self.assertEqual(sweep.cipher_refusals(places, ok), [])
        # A new reference in a reviewed library fails until its entry is reviewed again.
        more = dict(ok, **{"/usr/lib/libfetcher.so.*": dict(ok["/usr/lib/libfetcher.so.*"],
                                                            sites={"EVP_CIPHER_fetch": 1})})
        errs = sweep.cipher_refusals(places, more)
        self.assertEqual(len(errs), 1)
        self.assertIn("/usr/lib/libfetcher.so.1 holds cipher references EVP_CIPHER_fetch=2, not the "
                      "EVP_CIPHER_fetch=1 reviewed", errs[0])
        # A file with no entry fails, naming the entry to add; so does an entry that matches nothing.
        errs = sweep.cipher_refusals(places, dict({k: v for k, v in ok.items() if k != "/usr/bin/dlsymmer"},
                                                  **{"/usr/sbin/gone": "*"}))
        self.assertEqual(len(errs), 2)
        self.assertTrue(errs[0].endswith("adding: /usr/bin/dlsymmer sha256=%s EVP_get_cipherbyname=0"
                                         % places["tree"]["sha256"]["/usr/bin/dlsymmer"]), errs[0])
        # #5889 item 3: no entry exists, so the refusal asks for one to be added, not updated.
        self.assertIn("then add the [cipher] entry", errs[0])
        self.assertNotIn("update", errs[0])
        self.assertIn("[cipher] /usr/sbin/gone matches no file", errs[1])

    def test_new_version_with_the_same_counts_fails(self):
        # Security 6899468190 item 2: an update keeping the counts but changing where a name comes from.
        places = sweep.run_tree(str(self.tree))
        ok = self.entries(places)
        old = dict(ok, **{"/usr/bin/spells": dict(ok["/usr/bin/spells"], sha256="ab" * 32)})
        errs = sweep.cipher_refusals(places, old)
        self.assertEqual(len(errs), 1)
        self.assertIn("/usr/bin/spells holds other bytes (a new version?) than the ones reviewed", errs[0])
        self.assertNotIn("cipher references", errs[0])
        self.assertIn("then update the [cipher] entry", errs[0])
        self.assertTrue(errs[0].endswith("as: /usr/bin/spells sha256=%s GCM-SIV=1"
                                         % places["tree"]["sha256"]["/usr/bin/spells"]), errs[0])

    def test_every_refusal_points_at_the_reach_note(self):
        # L3 6899461135 item 4: the allow header asks for the records' reach note to be updated too.
        places = sweep.run_tree(str(self.tree))
        ok = self.entries(places)
        for entries in (dict(ok, **{"/usr/bin/spells": dict(ok["/usr/bin/spells"], sha256="ab" * 32)}),
                        {k: v for k, v in ok.items() if k != "/usr/bin/spells"}):
            errs = sweep.cipher_refusals(places, entries)
            with self.subTest(errs=errs):
                self.assertEqual(len(errs), 1)
                self.assertIn("reach note in assurance/vulncheck.json", errs[0])

    def test_overlapping_entries_fail(self):
        # L3 6899461135 item 5: a "*" glob over a counted one hid its mismatch; now a file matching two
        # entries fails, whatever they say, and the counted one's mismatch is not hidden.
        places = sweep.run_tree(str(self.tree))
        ok = self.entries(places)
        for extra in ("*", ok["/usr/lib/libfetcher.so.*"]):
            with self.subTest(extra=extra):
                errs = sweep.cipher_refusals(places, dict(ok, **{"/usr/lib/libfetch*": extra}))
                self.assertEqual(len(errs), 1)
                self.assertIn("/usr/lib/libfetcher.so.1 matches 2 [cipher] entries", errs[0])

    def test_held_file_without_a_digest_is_a_broken_scan(self):
        # #5889 item 3: a held file with no SHA-256 was offered "sha256=?", which read_allow refuses.
        places = sweep.run_tree(str(self.tree))
        ok = self.entries(places)
        for entries in (ok, {k: v for k, v in ok.items() if k != "/usr/bin/spells"}):
            broken = {"tree": dict(places["tree"], sha256={k: v for k, v in places["tree"]["sha256"].items()
                                                           if k != "/usr/bin/spells"})}
            errs = sweep.cipher_refusals(broken, entries)
            with self.subTest(errs=errs):
                self.assertEqual(len(errs), 1)
                self.assertIn("/usr/bin/spells holds cipher sites (GCM-SIV=1) but the scan gives no SHA-256",
                              errs[0])
                self.assertIn("the scan is broken", errs[0])
                self.assertNotIn("sha256=", errs[0])

    def test_summary_lists_sites(self):
        places = sweep.run_tree(str(self.tree))
        lines = sweep.summary(places)
        self.assertIn("tree cipher: 8 files hold a by-name cipher selector or spell GCM-SIV or KRB5KDF", lines)
        self.assertIn("  sites /usr/lib/libfetcher.so.1 sha256=%s EVP_CIPHER_fetch=2"
                      % places["tree"]["sha256"]["/usr/lib/libfetcher.so.1"], lines)

# #6285: glob() and wordexp (glibc's caller of it) are DEBIAN-CVE-2026-126765's; globfree alone is not.
GLOB_LIB = ('#include <glob.h>\nint f(const char *p) { glob_t g; int r = glob(p, 0, 0, &g); '
            'globfree(&g); return r; }\n')
GLOB64 = '#include <glob.h>\nint main(int c, char **v) { glob64_t g; return glob64(v[0], 0, 0, &g); }\n'
WORDEXP = '#include <wordexp.h>\nint main(int c, char **v) { wordexp_t w; return wordexp(v[0], &w, 0); }\n'
GLOBFREE = '#include <glob.h>\nint main(void) { glob_t g = {0}; globfree(&g); return 0; }\n'
# A library's own glob, unversioned: not glibc's, so not counted.
OWN_GLOB = "int glob(void) { return 1; }\n"
USES_OWN_GLOB = "int glob(void);\nint main(void) { return glob(); }\n"


@NEEDS_CC
class GlobImportsTest(unittest.TestCase):
    """#6285: the glob group is read from the binaries as the regex group is."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        t = pathlib.Path(cls.tmp.name)
        cls.tree, src = t / "tree", t / "src"
        src.mkdir()
        for d in ("usr/bin", "usr/lib"):
            (cls.tree / d).mkdir(parents=True)
        lib = cls.tree / "usr/lib"

        def cc(name, code, out, *args):
            (src / name).write_text(code)
            subprocess.run(["cc", "-D_GNU_SOURCE", "-o", str(out), str(src / name), *args], check=True)
        cc("glob.c", GLOB_LIB, lib / "libglob-user.so.1.0", "-shared", "-fPIC", "-Wl,-soname,libglob-user.so.1")
        os.symlink("libglob-user.so.1.0", lib / "libglob-user.so")
        cc("uses.c", USES_LIB, cls.tree / "usr/bin/globd", "-L" + str(lib), "-lglob-user")
        cc("g64.c", GLOB64, cls.tree / "usr/bin/g64")
        cc("wordexp.c", WORDEXP, cls.tree / "usr/bin/wexp")
        cc("globfree.c", GLOBFREE, cls.tree / "usr/bin/onlyfree")
        cc("own.c", OWN_GLOB, lib / "libownglob.so", "-shared", "-fPIC")
        cc("ownuse.c", USES_OWN_GLOB, cls.tree / "usr/bin/ownglob", "-L" + str(lib), "-lownglob")
        cls.got = sweep.run_tree(str(cls.tree))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_glob_glob64_and_wordexp_import_globfree_and_own_glob_do_not(self):
        got = self.got["tree"]
        self.assertEqual(got["imports"], {"/usr/lib/libglob-user.so.1.0": ["glob"], "/usr/bin/g64": ["glob64"],
                                          "/usr/bin/wexp": ["wordexp"]})
        self.assertEqual(got["via"], {"/usr/bin/globd": ["/usr/lib/libglob-user.so.1.0"]})
        self.assertEqual({sweep.group_of(s) for s in ("glob", "glob64", "wordexp")}, {"glob"})
        self.assertEqual({sweep.group_of(s) for s in ("globfree", "globfree64", "glob_pattern_p", "globber")},
                         {None})

    def test_summary_lists_the_glob_group(self):
        lines = sweep.summary(self.got)
        self.assertIn("tree glob: 3 files import a function (or look one up, or carry a copy), 1 more reach one through a NEEDED library", lines)
        self.assertIn("  via /usr/bin/globd: /usr/lib/libglob-user.so.1.0", lines)

    def test_unlisted_importers_fail_and_listed_pass(self):
        listed = ["/usr/lib/libglob-user.so.*", "/usr/bin/globd", "/usr/bin/g64", "/usr/bin/wexp"]
        self.assertEqual(refusals(self.got, [], listed), [])
        errs = refusals(self.got, [], listed[1:])
        self.assertEqual(errs, ["tree: /usr/lib/libglob-user.so.1.0 imports or reaches glob() and is not in "
                                "import_sweep.allow [glob]; review it, name it in the -126765 records, then "
                                "add the entry: /usr/lib/libglob-user.so.1.0 sha256=" + D])


# #6299: every GLOB entry pins the SHA-256 of the files it accepts. Tests of reach (not of pins) pin every
# reached file to D, through refusals() below; PinTest holds the pins to the real bytes.
D = "ab" * 32
PIN = " sha256=" + D


def E(glob, via=False, *pins):
    return sweep.Entry(glob, via, () if via else tuple(sorted(pins or (D,))))


def refusals(places, allow, globs=()):
    """sweep.refusals with every reached file's SHA-256 D and every plain glob an E entry."""
    places = {k: dict(v, sha256={p: D for (_, p), at in sweep.reach({k: v}).items()}) for k, v in places.items()}
    return sweep.refusals(places, [E(e) if isinstance(e, str) else e for e in allow],
                          [E(e) if isinstance(e, str) else e for e in globs])


def place(imports, via=None, scanned=10):
    return {"scanned": scanned, "imports": imports, "via": via or {}}


class RefusalsTest(unittest.TestCase):
    """The claims the glibc records cite this step for fail the step once false (L3 6877627726)."""
    ALLOW = ["/usr/bin/bash", "/usr/lib/libsmartcols.so.1.*", "/usr/bin/lsblk"]
    OK = {"tree": dict(place({"/usr/bin/bash": ["regcomp"], "/usr/lib/libsmartcols.so.1.1.0": ["regexec"]},
                             {"/usr/bin/lsblk": ["/usr/lib/libsmartcols.so.1.1.0"]}),
                       cipher={"/usr/lib/libcrypto.so.3": {"EVP_CIPHER_fetch": 40},
                               "/usr/lib/libcs.so.12.1": {"EVP_CIPHER_fetch": 1}},
                       sha256={"/usr/lib/libcrypto.so.3": "aa" * 32, "/usr/lib/libcs.so.12.1": "0f" * 32})}

    def test_allowed_reach_passes(self):
        self.assertEqual(refusals(self.OK, self.ALLOW), [])

    def test_daemon_importing_regexec_fails(self):
        places = {"tree": dict(self.OK["tree"], imports=dict(self.OK["tree"]["imports"],
                                                             **{"/usr/lib/systemd/systemd": ["regexec"]}))}
        errs = refusals(places, self.ALLOW)
        self.assertEqual(len(errs), 1)
        self.assertIn("/usr/lib/systemd/systemd imports or reaches a regex function", errs[0])
        self.assertTrue(errs[0].endswith("entry: /usr/lib/systemd/systemd sha256=" + D))

    def test_daemon_reaching_regex_through_a_library_fails(self):
        places = {"initrd:x": place({"/usr/lib/libsmartcols.so.1.1.0": ["regcomp"]},
                                    {"/usr/lib/systemd/systemd-udevd": ["/usr/lib/libsmartcols.so.1.1.0"]}),
                  "tree": self.OK["tree"]}
        errs = refusals(places, self.ALLOW)
        self.assertEqual(errs, [e for e in errs if "initrd:x: /usr/lib/systemd/systemd-udevd" in e])
        self.assertEqual(len(errs), 1)

    def test_rpmatch_counts_as_regex(self):
        places = {"tree": dict(self.OK["tree"], imports=dict(self.OK["tree"]["imports"], **{"/usr/bin/rm": ["rpmatch"]}))}
        self.assertEqual(len(refusals(places, self.ALLOW)), 1)

    def test_any_wide_scanf_fails_allowlisted_or_not(self):
        for p in ("/usr/bin/bash", "/usr/lib/systemd/systemd"):
            places = {"tree": dict(self.OK["tree"], imports=dict(self.OK["tree"]["imports"], **{p: self.OK["tree"]["imports"].get(p, []) + ["swscanf"]}))}
            with self.subTest(p=p):
                errs = refusals(places, self.ALLOW)
                self.assertEqual(len(errs), 1)
                self.assertIn("wide scanf", errs[0])
        lib = {"tree": place({"/usr/lib/libw.so.1": ["__isoc99_vswscanf"]}, {"/usr/bin/bash": ["/usr/lib/libw.so.1"]})}
        self.assertEqual(len([e for e in refusals(lib, ["/usr/bin/bash"]) if "wide scanf" in e]), 2)

    def test_glob_reach_is_held_to_the_glob_section_alone(self):
        # #6285: a daemon reaching glob() fails, directly or through a library, and the regex list does not
        # cover it: each section is its own record's.
        glob = {"tree": dict(self.OK["tree"], imports=dict(self.OK["tree"]["imports"],
                                                           **{"/usr/lib/libg.so.1": ["glob64"],
                                                              "/usr/bin/bash": ["regcomp", "glob"]}),
                             via={"/usr/lib/systemd/systemd": ["/usr/lib/libg.so.1"],
                                  "/usr/bin/lsblk": ["/usr/lib/libsmartcols.so.1.1.0"]})}
        errs = refusals(glob, self.ALLOW)
        self.assertEqual([e.split(" imports")[0] for e in errs],
                         ["tree: /usr/bin/bash", "tree: /usr/lib/libg.so.1", "tree: /usr/lib/systemd/systemd"])
        self.assertTrue(all("reaches glob() and is not in import_sweep.allow [glob]" in e for e in errs), errs)
        self.assertEqual(refusals(glob, self.ALLOW, ["/usr/bin/bash", "/usr/lib/libg.so.*",
                                                           "/usr/lib/systemd/systemd"]), [])
        # A [glob] entry matching no glob() importer fails, even one a regex importer matches.
        self.assertEqual(refusals(self.OK, self.ALLOW, ["/usr/bin/bash"]),
                         ["import_sweep.allow: [glob] /usr/bin/bash matches no file that reaches glob(); remove it"])

    def test_glob_section_is_read_once_and_unknown_sections_fail(self):
        with tempfile.TemporaryDirectory() as d:
            a = pathlib.Path(d) / "allow"
            a.write_text("/usr/bin/bash{0}\n[glob]\n# why\n/usr/bin/bash{0}  # the shell\n/usr/lib/libg.so.*{0}\n"
                         "[cipher]\n/usr/lib/libcrypto.so.3 *\n".format(PIN))
            self.assertEqual(sweep.read_allow(a), ([E("/usr/bin/bash")], {"/usr/lib/libcrypto.so.3": "*"},
                                                   [E("/usr/bin/bash"), E("/usr/lib/libg.so.*")], [], []))
            a.write_text("/usr/bin/bash{0}\n[cipher]\n/usr/lib/libcrypto.so.3 *\n[glob]\n/usr/bin/x{0}\n".format(PIN))
            self.assertEqual(sweep.read_allow(a)[2], [E("/usr/bin/x")])
            for body, want in (("[glob]\n/usr/bin/x%s\n[glob]\n" % PIN, ":3: [glob] is given again"),
                               ("[regex]\n", ":1: [regex] is no section"),
                               ("[glob\n", ":1: [glob is no section")):
                a.write_text(body)
                with self.subTest(body=body), self.assertRaises(SystemExit) as cm:
                    sweep.read_allow(a)
                self.assertIn(want, str(cm.exception))

    def test_unused_glob_fails(self):
        errs = refusals(self.OK, self.ALLOW + ["/usr/bin/gone"])
        self.assertEqual(errs, ["import_sweep.allow: /usr/bin/gone matches no file that reaches a regex function; remove it"])

    def test_summary_exits_one_on_a_refusal(self):
        with tempfile.TemporaryDirectory() as d:
            j, a = pathlib.Path(d) / "p.json", pathlib.Path(d) / "allow"
            a.write_text("# comment\n/usr/bin/bash{0}  # the shell\n/usr/lib/libsmartcols.so.1.*{0}\n"
                         "/usr/bin/lsblk{0}\n[glob]\n/usr/sbin/ldconfig{0}\n"
                         "[cipher]\n/usr/lib/libcs.so.12.* sha256={1} EVP_CIPHER_fetch=1  # why\n"
                         "/usr/lib/libcrypto.so.3 *\n".format(PIN, "0f" * 32))
            self.assertEqual(sweep.load_allow(a), [E(x) for x in self.ALLOW])
            self.assertEqual(sweep.read_allow(a)[1], {"/usr/lib/libcs.so.12.*": {"sha256": "0f" * 32,
                                                                              "sites": {"EVP_CIPHER_fetch": 1}},
                                                      "/usr/lib/libcrypto.so.3": "*"})
            bad = {"tree": dict(self.OK["tree"], imports=dict(self.OK["tree"]["imports"],
                                                              **{"/usr/lib/systemd/systemd": ["regexec", "swscanf"]}))}
            # The carried-copy control's ldconfig (#6298), accepted by the [glob] entry, and the glibc
            # holding every mark (#6299); each reaching file holds the bytes its entry pins.
            ok = {"tree": dict(self.OK["tree"], carries={"/usr/sbin/ldconfig": ["glob"]},
                               glibc={"/usr/lib/libc.so.6": ["glob", "regcomp", "vfwscanf"]},
                               sha256=dict(self.OK["tree"]["sha256"], **dict.fromkeys(
                                   ["/usr/bin/bash", "/usr/lib/libsmartcols.so.1.1.0", "/usr/bin/lsblk",
                                    "/usr/sbin/ldconfig", "/usr/lib/systemd/systemd"], D)))}
            for k in ("carries", "glibc", "sha256"):
                bad["tree"][k] = ok["tree"][k]
            for places, want in ((ok, 0), (bad, 1)):
                j.write_text(__import__("json").dumps(places))
                with self.subTest(want=want), contextlib.redirect_stdout(io.StringIO()), \
                        contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(sweep.main(["--summary", str(j), str(a)]), want)

    def test_shipped_allowlist_is_absolute_globs(self):
        allow = [e.glob for e in sweep.load_allow(sweep.ALLOW)]
        self.assertTrue(allow)
        for a in allow:
            with self.subTest(a=a):
                self.assertTrue(a.startswith("/usr/"), a)
                self.assertNotIn("systemd/systemd-udevd", a)
                self.assertFalse(fnmatch.fnmatchcase("/usr/lib/systemd/systemd", a), a)
        # #5341: the [cipher] entries are absolute globs too, and libcryptsetup's sites are counted.
        cipher = sweep.read_allow(sweep.ALLOW)[1]
        self.assertTrue(all(g.startswith("/usr/") for g in cipher), cipher)
        self.assertIn("EVP_CIPHER_fetch", cipher["/usr/lib/x86_64-linux-gnu/libcryptsetup.so.12.*"]["sites"])
        # #6285: so are the [glob] entries, each named once, and libsystemd-shared's call sites are reviewed there.
        globs = sweep.read_allow(sweep.ALLOW)[2]
        self.assertTrue(all(g.glob.startswith("/usr/") for g in globs), globs)
        self.assertEqual(len(globs), len(set(globs)))
        self.assertIn(("/usr/lib/x86_64-linux-gnu/systemd/libsystemd-shared-*.so", False), {g[:2] for g in globs})

    def test_bad_cipher_entries_name_the_line(self):
        # L3 6899461135 items 2, 3 and 6, and an entry not keyed to its bytes (#5861).
        sha = "sha256=" + "0f" * 32
        cases = {"/usr/bin/x %s EVP_CIPHER_fetch" % sha: "EVP_CIPHER_fetch is not NAME=COUNT",
                 "/usr/bin/x %s EVP_CIPHER_fetch=one" % sha: "EVP_CIPHER_fetch=one is not NAME=COUNT",
                 "/usr/bin/x %s EVP_MAC_fetch=1" % sha: "EVP_MAC_fetch=1 is not NAME=COUNT",
                 "/usr/bin/x": "/usr/bin/x names nothing",
                 "/usr/bin/x * %s" % sha: "'*' with other tokens",
                 "/usr/bin/x EVP_CIPHER_fetch=1": "gives 0 sha256=HEX tokens",
                 "/usr/bin/x sha256=abc EVP_CIPHER_fetch=1": "gives 0 sha256=HEX tokens",
                 "/usr/bin/x %s %s EVP_CIPHER_fetch=1" % (sha, sha): "gives 2 sha256=HEX tokens",
                 "/usr/bin/x %s" % sha: "/usr/bin/x counts no site",
                 "/usr/bin/x %s GCM-SIV=1 GCM-SIV=2" % sha: "gives GCM-SIV twice",
                 "/usr/bin/x *\n/usr/bin/x %s GCM-SIV=1" % sha: "/usr/bin/x has an entry already"}
        with tempfile.TemporaryDirectory() as d:
            a = pathlib.Path(d) / "allow"
            for body, want in cases.items():
                a.write_text("/usr/bin/bash%s\n[cipher]\n# why\n" % PIN + body + "\n")
                with self.subTest(body=body), self.assertRaises(SystemExit) as cm:
                    sweep.read_allow(a)
                line = 3 + body.count("\n") + 1
                self.assertIn("%s:%d: " % (a, line), str(cm.exception))
                self.assertIn(want, str(cm.exception))
                self.assertIn("GLOB sha256=HEX NAME=COUNT", str(cm.exception))

    def test_digest_in_either_case_is_kept_lowercased(self):
        # #5889 item 2: an uppercase digest was refused as "gives 0 sha256=HEX tokens".
        with tempfile.TemporaryDirectory() as d:
            a = pathlib.Path(d) / "allow"
            for hexd in ("0F" * 32, "0f" * 32, "0F0f" * 16):
                a.write_text("/usr/bin/bash%s\n[cipher]\n/usr/bin/x sha256=%s GCM-SIV=1\n" % (PIN, hexd))
                with self.subTest(hexd=hexd):
                    self.assertEqual(sweep.read_allow(a)[1]["/usr/bin/x"],
                                     {"sha256": "0f" * 32, "sites": {"GCM-SIV": 1}})

    def test_shipped_allow_comments_keep_the_wrap(self):
        # #5889 item 4: comment lines wrap near 105 columns; only entry lines (a glob and its tokens) run on.
        long = [(n, len(l)) for n, l in enumerate(pathlib.Path(sweep.ALLOW).read_text().splitlines(), 1)
                if l.startswith("#") and len(l) > 107]
        self.assertEqual(long, [])

    def test_image_workflow_runs_on_every_guest_root_build_sh_builds(self):
        # #5889 item 1: import_sweep.allow pins guest binaries by SHA-256, so a change to a guest root's
        # inputs (a codex version bump) must run image.yml, on its pull request and on main.
        guests = re.findall(r'"\$REPO/guest/([\w-]+)/build-rootfs\.sh"',
                            (ROOT / "image/build.sh").read_text())
        self.assertIn("codex", guests)
        wf = (ROOT / ".github/workflows/image.yml").read_text()
        on = wf.split("\njobs:\n", 1)[0]
        pr, push = on.split("\n  pull_request:\n", 1)[1].split("\n  push:\n", 1)
        for g in guests:
            for name, part in (("pull_request", pr), ("push", push)):
                with self.subTest(guest=g, on=name):
                    self.assertIn('      - "guest/%s/**"\n' % g, part)


class ReadErrorTest(unittest.TestCase):
    """IMG-offline-verity-follow (#5988): a /usr block dm-verity refuses reads as EIO, and a file whose
    first block reads so fails the run instead of being skipped as not ELF."""

    def eio_on(self, target):
        real = open

        def fake(path, *a, **k):
            if os.fspath(path) == target:
                raise OSError(errno.EIO, os.strerror(errno.EIO), path)
            return real(path, *a, **k)
        return mock.patch.object(sweep, "open", fake, create=True)

    def test_eio_fails_the_run_naming_the_file(self):
        with tempfile.TemporaryDirectory() as d:
            f = os.path.join(d, "bin")
            pathlib.Path(f).write_bytes(b"\x7fELF" + b"\0" * 60)
            with self.eio_on(f), self.assertRaises(SystemExit) as cm:
                sweep.is_elf(f)
        self.assertIn("cannot read %s" % f, str(cm.exception))
        self.assertIn(os.strerror(errno.EIO), str(cm.exception))

    def test_eio_in_the_walk_fails_the_tree(self):
        with tempfile.TemporaryDirectory() as d:
            (pathlib.Path(d) / "usr/bin").mkdir(parents=True)
            f = os.path.join(d, "usr/bin/tampered")
            pathlib.Path(f).write_bytes(b"\x7fELF" + b"\0" * 60)
            pathlib.Path(d, "usr/bin/text").write_text("not elf\n")
            with self.eio_on(f), self.assertRaises(SystemExit):
                sweep.run_tree(d)

    def test_eio_on_a_directory_fails_the_run_naming_it(self):
        # A directory block refused by dm-verity: os.walk would drop the subtree and the scan pass smaller.
        real = os.scandir

        def fake(path=".", *a, **k):
            if os.fspath(path).endswith("/usr/bin"):
                raise OSError(errno.EIO, os.strerror(errno.EIO), path)
            return real(path, *a, **k)
        with tempfile.TemporaryDirectory() as d:
            (pathlib.Path(d) / "usr/bin").mkdir(parents=True)
            pathlib.Path(d, "usr/bin/tampered").write_bytes(b"\x7fELF" + b"\0" * 60)
            with mock.patch.object(os, "scandir", fake), self.assertRaises(SystemExit) as cm:
                sweep.run_tree(d)
        self.assertIn("cannot read %s: %s" % (os.path.join(d, "usr/bin"), os.strerror(errno.EIO)),
                      str(cm.exception))

    def test_eio_on_an_initrd_directory_fails_the_build(self):
        real = os.scandir

        def fake(path=".", *a, **k):
            if os.fspath(path).endswith("/initrd"):
                raise OSError(errno.EIO, os.strerror(errno.EIO), path)
            return real(path, *a, **k)
        with tempfile.TemporaryDirectory() as d:
            (pathlib.Path(d) / "initrd").mkdir()
            built = mock.patch.dict(sys.modules, offline_systemd=mock.Mock(
                built_tree=lambda out, v: (d, None, None, lambda: None)))
            with built, mock.patch.object(sweep, "run_tree", lambda root, usr: {}), \
                    mock.patch.object(os, "scandir", fake), self.assertRaises(SystemExit) as cm:
                sweep.run_build(d, "v")
        self.assertIn("cannot read %s" % os.path.join(d, "initrd"), str(cm.exception))

    def initrd_build(self, d):
        """run_build over D's initrd directory alone, with its places' records as {name: path}."""
        built = mock.patch.dict(sys.modules, offline_systemd=mock.Mock(
            built_tree=lambda out, v: (d, None, None, lambda: None)))
        with built, mock.patch.object(sweep, "run_tree", lambda root, usr: {}), \
                mock.patch.object(sweep, "initrd_place", lambda p, scratch: os.fspath(p)):
            return sweep.run_build(d, "v")

    def test_a_stat_error_on_an_initrd_entry_fails_the_build(self):
        # #6073: Path.is_file() read a symlink loop (or EIO) as "not a file" and skipped the initrd.
        with tempfile.TemporaryDirectory() as d:
            (pathlib.Path(d) / "initrd").mkdir()
            loop = pathlib.Path(d, "initrd", "loop")
            loop.symlink_to("loop")
            with self.assertRaises(SystemExit) as cm:
                self.initrd_build(d)
        self.assertIn("cannot read %s: %s" % (loop, os.strerror(errno.ELOOP)), str(cm.exception))

    def test_initrd_entries_read_only_regular_files(self):
        with tempfile.TemporaryDirectory() as d:
            i = pathlib.Path(d) / "initrd"
            (i / "sub").mkdir(parents=True)
            (i / "sub" / "main.img").write_bytes(b"x")
            (i / "link.img").symlink_to("sub/main.img")
            (i / "gone.img").symlink_to("nowhere")
            os.mkfifo(i / "fifo")
            got = self.initrd_build(d)
        self.assertEqual(got, {"initrd:link.img": str(i / "link.img"), "initrd:sub/main.img": str(i / "sub/main.img")})

    def tree_with_stat_error(self, err):
        """run_tree over a tree whose one ELF file's lstat (either spelling) raises ERR."""
        real = os.stat

        def fake(path, *a, **k):
            if os.fspath(path).endswith("/usr/bin/tampered") and k.get("follow_symlinks") is False:
                raise OSError(err, os.strerror(err), path)
            return real(path, *a, **k)
        with tempfile.TemporaryDirectory() as d:
            (pathlib.Path(d) / "usr/bin").mkdir(parents=True)
            pathlib.Path(d, "usr/bin/tampered").write_bytes(b"\x7fELF" + b"\0" * 60)
            with mock.patch.object(os, "stat", fake), \
                    mock.patch.object(os, "lstat", lambda path: fake(path, follow_symlinks=False)):
                return sweep.run_tree(d)

    def test_a_stat_error_in_the_tree_fails_the_run_naming_the_file(self):
        # #6098: the tree walk's lstat raised a bare traceback; it now gives the initrd loop's message.
        for err in (errno.EIO, errno.EACCES):
            with self.subTest(err=errno.errorcode[err]):
                with self.assertRaises(SystemExit) as cm:
                    self.tree_with_stat_error(err)
                self.assertRegex(str(cm.exception), r"^import sweep: cannot read /\S+/usr/bin/tampered: %s$"
                                 % re.escape(os.strerror(err)))

    def test_a_file_gone_from_the_tree_is_not_scanned(self):
        # Gone between the walk and its stat: not a file, as is_elf and the initrd loop read it.
        got = self.tree_with_stat_error(errno.ENOENT)
        self.assertEqual(got["tree"]["scanned"], 0)

    def test_vanished_short_and_plain_files_are_not_elf(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertFalse(sweep.is_elf(os.path.join(d, "gone")))
            pathlib.Path(d, "short").write_bytes(b"\x7fE")
            self.assertFalse(sweep.is_elf(os.path.join(d, "short")))
            pathlib.Path(d, "text").write_text("#!/bin/sh\n")
            self.assertFalse(sweep.is_elf(os.path.join(d, "text")))
            pathlib.Path(d, "elf").write_bytes(b"\x7fELF")
            self.assertTrue(sweep.is_elf(os.path.join(d, "elf")))


if __name__ == "__main__":
    unittest.main()


SMARTCOLS = "/usr/lib/x86_64-linux-gnu/libsmartcols.so.1.1.0"
SHARED_LIB = "/usr/lib/x86_64-linux-gnu/systemd/libsystemd-shared-257.so"


class ViaEntryTest(unittest.TestCase):
    """VULN-debian-r13-f2 (#6297): "via GLOB" accepts a reviewed library's dependents without an entry each;
    a new direct caller still fails, and so does a via entry that accepts nothing."""
    REGEX = [E("/usr/lib/x86_64-linux-gnu/libsmartcols.so.1.*"), E("/usr/lib/x86_64-linux-gnu/libsmartcols.so.1.*", True)]
    PLACES = {"tree": place({SMARTCOLS: ["regcomp"], "/usr/bin/bash": ["regcomp"]},
                            {"/usr/bin/lsblk": [SMARTCOLS], "/usr/sbin/swapon": [SMARTCOLS]}),
              "initrd:x": place({SMARTCOLS: ["regcomp"]}, {"/usr/bin/lsblk": [SMARTCOLS]})}
    ALLOW = REGEX + [E("/usr/bin/bash")]

    def errs(self, places, allow=None, globs=()):
        return refusals(places, self.ALLOW if allow is None else allow, globs)

    def test_dependents_of_a_listed_library_need_no_entry(self):
        self.assertEqual(self.errs(self.PLACES), [])

    def test_a_direct_caller_fails_though_its_library_is_via(self):
        for syms in (["regcomp"], ["rpmatch"]):
            places = {"tree": dict(self.PLACES["tree"], imports=dict(self.PLACES["tree"]["imports"],
                                                                    **{"/usr/bin/lsblk": syms}))}
            with self.subTest(syms=syms):
                self.assertEqual(self.errs(places), [
                    "tree: /usr/bin/lsblk imports or reaches a regex function and is not in import_sweep.allow; "
                    "review it, name it in the image -100290 record, then add the entry: /usr/bin/lsblk sha256=" + D])
                # Its own entry accepts it.
                self.assertEqual(self.errs(places, self.ALLOW + [E("/usr/bin/lsblk")]), [])

    def test_a_direct_caller_in_one_place_fails_there_only(self):
        places = dict(self.PLACES, **{"initrd:x": place({SMARTCOLS: ["regcomp"], "/usr/bin/lsblk": ["regexec"]},
                                                        {"/usr/bin/lsblk": [SMARTCOLS]})})
        errs = self.errs(places)
        self.assertEqual(len(errs), 1)
        self.assertTrue(errs[0].startswith("initrd:x: /usr/bin/lsblk imports"), errs)

    def test_via_a_library_without_its_own_entry_accepts_nothing(self):
        errs = self.errs(self.PLACES, self.REGEX[1:] + [E("/usr/bin/bash")])
        self.assertEqual([e.split(" imports")[0] for e in errs[:-1]],
                         ["tree initrd:x: /usr/bin/lsblk", "tree initrd:x: " + SMARTCOLS,
                          "tree: /usr/sbin/swapon"])
        self.assertEqual(errs[-1], "import_sweep.allow: via /usr/lib/x86_64-linux-gnu/libsmartcols.so.1.* accepts "
                                   "no file that reaches a regex function only through a library it names that "
                                   "has an entry naming it; remove it")

    def test_a_via_entry_matching_no_library_fails(self):
        for g in ("/usr/lib/libgone.so.*", "/usr/bin/bash", "/usr/bin/lsblk"):
            with self.subTest(g=g):
                errs = self.errs(self.PLACES, self.ALLOW + [E(g, True)])
                self.assertEqual(errs, ["import_sweep.allow: via %s accepts no file that reaches a regex function "
                                        "only through a library it names that has an entry naming it; remove it" % g])

    def test_every_library_reached_must_be_via(self):
        other = "/usr/lib/libedit.so.2.0.75"
        places = {"tree": place({SMARTCOLS: ["regcomp"], other: ["regexec"]},
                                {"/usr/sbin/nft": sorted([SMARTCOLS, other])})}
        allow = self.REGEX + [E("/usr/lib/libedit.so.2.*")]
        # nft is refused, so the via entry accepts nothing either.
        self.assertEqual([e.split(" imports")[0].split(" accepts")[0] for e in self.errs(places, allow)],
                         ["tree: /usr/sbin/nft", "import_sweep.allow: via /usr/lib/x86_64-linux-gnu/libsmartcols.so.1.*"])
        self.assertEqual(self.errs(places, allow + [E("/usr/lib/libedit.so.2.*", True)]), [])
        # A library reaching another group only is not this group's: its via entry is not needed here.
        places["tree"]["imports"][other] = ["glob"]
        self.assertEqual(self.errs(places, allow + [E("/usr/bin/x")])[:1],
                         ["tree: /usr/lib/libedit.so.2.0.75 imports or reaches glob() and is not in "
                          "import_sweep.allow [glob]; review it, name it in the -126765 records, then add the "
                          "entry: /usr/lib/libedit.so.2.0.75 sha256=" + D])

    def test_a_named_entry_still_accepts_a_dependent(self):
        self.assertEqual(self.errs(self.PLACES, self.ALLOW + [E("/usr/bin/lsblk")]), [])

    def test_an_importer_of_one_group_reaching_another_through_a_library(self):
        # A file importing a regex function and loading libsystemd-shared reaches glob() too: it is held to
        # [glob], and accepted there through the library (#6297; sweep keeps an importer's via list).
        places = {"tree": place({SHARED_LIB: ["glob64"], "/usr/bin/bash": ["regcomp"]},
                                {"/usr/bin/bash": [SHARED_LIB]})}
        allow = [E("/usr/bin/bash")]
        self.assertEqual([e.split(" and is")[0] for e in refusals(places, allow, [E(SHARED_LIB)])],
                         ["tree: /usr/bin/bash imports or reaches glob()"])
        self.assertEqual(refusals(places, allow, [E(SHARED_LIB), E(SHARED_LIB, True)]), [])
        # And glob() imported directly with the library via is not accepted by the via entry.
        places["tree"]["imports"]["/usr/bin/bash"].append("glob")
        self.assertEqual([e.split(" and is")[0].split(" accepts")[0]
                          for e in refusals(places, allow, [E(SHARED_LIB), E(SHARED_LIB, True)])],
                         ["tree: /usr/bin/bash imports or reaches glob()", "import_sweep.allow: [glob] via " + SHARED_LIB])

    def test_summary_counts_a_direct_importer_once(self):
        # fdisk imports rpmatch and loads libsmartcols: an importer of the group, not one more reacher.
        places = {"tree": place({SMARTCOLS: ["regcomp"], "/usr/sbin/fdisk": ["rpmatch"]},
                                {"/usr/sbin/fdisk": [SMARTCOLS], "/usr/bin/lsblk": [SMARTCOLS]})}
        lines = sweep.summary(places)
        self.assertIn("tree regex: 2 files import a function (or look one up, or carry a copy), 1 more reach one through a NEEDED library", lines)
        self.assertNotIn("  via /usr/sbin/fdisk: " + SMARTCOLS, lines)

    def test_entries_parse_and_bad_lines_name_the_line(self):
        with tempfile.TemporaryDirectory() as d:
            a = pathlib.Path(d) / "allow"
            a.write_text("/usr/lib/libs.so.*%s\nvia /usr/lib/libs.so.*  # its users\n[glob]\nvia  /usr/lib/libg.so.*\n" % PIN)
            self.assertEqual(sweep.read_allow(a), ([E("/usr/lib/libs.so.*"), E("/usr/lib/libs.so.*", True)], {},
                                                   [E("/usr/lib/libg.so.*", True)], [], []))
            for body, want in (("via\n", ":1: via is not an entry; a regex entry is " + sweep.ENTRY_FORMAT),
                               ("via /a /b\n", ":1: via /a /b is not an entry"),
                               ("via /a%s\n" % PIN, "is not an entry"),
                               ("/a /b\n", ":1: /a /b is not an entry"),
                               ("/a sha256=00\n", ":1: /a sha256=00 is not an entry"),
                               ("/a%s b\n" % PIN, "is not an entry"),
                               ("sha256=%s\n" % D, "is not an entry"),
                               ("[glob]\n/a b\n", ":2: /a b is not an entry; a [glob] entry is " + sweep.ENTRY_FORMAT),
                               # #6299: a GLOB entry that pins no file's bytes, or one twice, is refused.
                               ("/a\n", ":1: /a pins no SHA-256"),
                               ("[glob]\n/usr/bin/node  # its dlsym names\n", ":2: /usr/bin/node pins no SHA-256"),
                               ("/a%s%s\n" % (PIN, PIN.upper().replace("SHA", "sha")), "gives a SHA-256 twice"),
                               ("/a%s\n/a%s\n" % (PIN, PIN), ":2: /a%s is given again" % PIN),
                               ("/a%s\n/a sha256=%s\n" % (PIN, "cd" * 32), ":2: /a sha256=%s is given again" % ("cd" * 32)),
                               ("[glob]\nvia /a\nvia   /a\n", ":3: via   /a is given again")):
                a.write_text(body)
                with self.subTest(body=body), self.assertRaises(SystemExit) as cm:
                    sweep.read_allow(a)
                self.assertIn(want, str(cm.exception))

    def test_shipped_lists_are_collapsed(self):
        regex, _, globs, _, _ = sweep.read_allow(sweep.ALLOW)
        for section in (regex, globs):
            for e in section:
                with self.subTest(e=e):
                    # Every via entry names a library that has its own entry, so it can accept a file.
                    self.assertTrue(not e.via or (e.glob, False) in {(x.glob, x.via) for x in section}, e)
                    # #6299: and every other entry pins the bytes of each file it accepts.
                    self.assertTrue(e.via or e.sha256, e)
        self.assertIn(E(SHARED_LIB.replace("257", "*"), True), globs)
        named = {e.glob for e in globs if not e.via}
        for dependent in ("/usr/bin/systemctl", "/usr/lib/systemd/systemd", "/usr/lib/systemd/systemd-networkd",
                          "/usr/sbin/nft", "/usr/sbin/cryptsetup"):
            self.assertNotIn(dependent, named)
        self.assertNotIn("/usr/bin/lsblk", {e.glob for e in regex})
        # A file importing the function itself keeps its own entry: fdisk's rpmatch, ip's glob64.
        self.assertIn("/usr/sbin/fdisk", {e.glob for e in regex if not e.via})
        self.assertIn("/usr/bin/ip", named)


@NEEDS_CC
class CrossGroupReachTest(unittest.TestCase):
    """#6297: sweep lists an importer's own via libraries, so a program importing rpmatch and loading a
    glob() library is held to [glob] (before, any importer's via list was dropped)."""

    def test_importer_keeps_its_via_list(self):
        with tempfile.TemporaryDirectory() as t:
            t = pathlib.Path(t)
            lib, src = t / "tree/usr/lib", t / "src"
            for d in (lib, t / "tree/usr/bin", src):
                d.mkdir(parents=True, exist_ok=True)

            def cc(name, code, out, *args):
                (src / name).write_text(code)
                subprocess.run(["cc", "-D_GNU_SOURCE", "-o", str(out), str(src / name), *args], check=True)
            cc("glob.c", GLOB_LIB, lib / "libglob-user.so.1.0", "-shared", "-fPIC", "-Wl,-soname,libglob-user.so.1")
            os.symlink("libglob-user.so.1.0", lib / "libglob-user.so")
            both = RPMATCH.replace("int main", "int f(const char *);\nint main").replace(
                "return rpmatch(v[0]);", "return rpmatch(v[0]) + f(v[0]);")
            cc("both.c", both, t / "tree/usr/bin/both", "-L" + str(lib), "-lglob-user")
            got = sweep.run_tree(str(t / "tree"))
        self.assertEqual(got["tree"]["imports"]["/usr/bin/both"], ["rpmatch"])
        self.assertEqual(got["tree"]["via"], {"/usr/bin/both": ["/usr/lib/libglob-user.so.1.0"]})
        errs = refusals(got, [E("/usr/bin/both")], [E("/usr/lib/libglob-user.so.*")])
        self.assertEqual([e.split(" and is")[0] for e in errs], ["tree: /usr/bin/both imports or reaches glob()"])
        self.assertEqual(refusals(got, [E("/usr/bin/both")], [E("/usr/lib/libglob-user.so.*"),
                                                                     E("/usr/lib/libglob-user.so.*", True)]), [])
        # The summary counts it among the glob group's reachers, not its importers.
        lines = sweep.summary(got)
        self.assertIn("tree glob: 1 files import a function (or look one up, or carry a copy), 1 more reach one through a NEEDED library", lines)
        self.assertIn("tree regex: 1 files import a function (or look one up, or carry a copy), 0 more reach one through a NEEDED library", lines)


# #6298: what no import shows. Static copies, stripped as the image ships them; dlsym callers.
STATIC_REGEX = "#include <regex.h>\nint main(int c, char **v) { regex_t r; return regcomp(&r, v[0], 0); }\n"
STATIC_WSCANF = WSCANF
# #6299: a dynamic file holding the marks embeds glibc's code (libc_pic objects, a gnulib copy): it carries
# a copy as a static file does, with an interpreter and libraries or without.
MARKS_ONLY = ('const char *m[] = {"Invalid preceding regular expression", "glob_in_dir", "__vfwscanf_internal"};\n'
              'int main(int c, char **v) { return m[c][0]; }\n')
INTERP_ONLY = ('const char *m[] = {"glob_in_dir", "__vfwscanf_internal"};\n'
               'void _start(void) { for (;;) __asm__ volatile("" :: "r"(m)); }\n')
# A static file holding strings that only contain the marks: no mark ends a string of its.
STATIC_NEAR = ('const char *m[] = {"glob_in_dirx", "__vfwscanf_internal2", "Invalid preceding regular expressions"};\n'
               'int main(int c, char **v) { return m[c][0]; }\n')
LOOKS_UP = ('#include <dlfcn.h>\nint main(int c, char **v) { return dlsym(RTLD_DEFAULT, c ? "glob" : "regcomp") != 0; }\n')
# A file importing both dlvsym and dlsym looks a compat-only name up through dlvsym.
LOOKS_UP_V = ('#include <dlfcn.h>\nint main(int c, char **v) { return dlvsym(RTLD_DEFAULT, c ? "__isoc99_swscanf" : "step", '
              'c ? "GLIBC_2.7" : "GLIBC_2.2.5") != dlsym(RTLD_DEFAULT, "x"); }\n')
# Strings no group function's name ends (store_value holds "re_" but no glibc re_* name: RE_NAMES),
# compat-only names dlsym cannot return (COMPAT_ONLY), and a group name held by a file that cannot look it up.
LOOKS_UP_OTHER = ('#include <dlfcn.h>\nconst char *n[] = {"globber", "regcomp2", "store_value", "step", "advance"};\n'
                  'int main(int c, char **v) { return dlsym(RTLD_DEFAULT, n[c]) != 0; }\n')
HOLDS_NAME = 'const char *n = "glob";\nint main(void) { return n[0]; }\n'
LIB_LOOKS_UP = '#include <dlfcn.h>\nint f(void) { return dlsym(RTLD_DEFAULT, "wordexp") != 0; }\n'
# #6299 (L3 on #6339): a file holding a group name that looks it up through a NEEDED library's wrapper
# around dlsym (liblook's f stands in for it), directly or through a library between; and through a dlvsym
# wrapper, a compat-only name.
WRAPPED = 'int f(void);\nconst char *n[] = {"glob", "step"};\nint main(int c, char **v) { return f() + n[c][0]; }\n'
MIDDLE = 'int f(void);\nint g(void) { return f(); }\n'
WRAPPED_MID = WRAPPED.replace("f()", "g()").replace("int f", "int g")
LIB_VLOOKS_UP = '#include <dlfcn.h>\nvoid *h(const char *n) { return dlvsym(RTLD_DEFAULT, n, "GLIBC_2.2.5"); }\n'
WRAPPED_V = ('void *h(const char *);\nconst char *n[] = {"step", "advance"};\n'
             'int main(int c, char **v) { return h(n[c]) != 0; }\n')


@NEEDS_CC
class UnimportedReachTest(unittest.TestCase):
    """#6298: a static copy of glibc's glob, regex or wide scanf code, and a dlsym or dlvsym lookup of a
    function's name, count as the file importing it, in the same groups and allow sections."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        t = pathlib.Path(cls.tmp.name)
        src, cls.tree = t / "src", t / "tree"
        lib = cls.tree / "usr/lib"
        for d in (src, lib, cls.tree / "usr/bin", cls.tree / "usr/sbin"):
            d.mkdir(parents=True, exist_ok=True)

        def cc(name, code, out, *args):
            (src / name).write_text(code)
            subprocess.run(["cc", "-D_GNU_SOURCE", "-o", str(out), str(src / name), *args], check=True)
        for name, code in (("ldconfig", STATIC_GLOB), ("sregex", STATIC_REGEX), ("swide", STATIC_WSCANF),
                           ("splain", STATIC_NEAR)):
            cc(name + ".c", code, cls.tree / "usr/sbin" / name, "-static", "-s")
        cc("pie.c", STATIC_GLOB, cls.tree / "usr/sbin/spie", "-static-pie", "-fPIE", "-s")
        cc("marks.c", MARKS_ONLY, cls.tree / "usr/bin/marks")
        # It calls puts, so it names libc.so.6 (a library calling nothing in libc names no library).
        cc("libmarks.c", "#include <stdio.h>\n" + MARKS_ONLY.replace("return m[c][0];", "return puts(m[c]);")
           .replace("main", "f"), lib / "libmarks.so.1", "-shared", "-fPIC")
        cc("interp.c", INTERP_ONLY, cls.tree / "usr/bin/interp", "-nostdlib", "-pie", "-fPIE",
           "-Wl,--dynamic-linker=/lib64/ld-linux-x86-64.so.2")
        cc("lookup.c", LOOKS_UP, cls.tree / "usr/bin/lookup", "-ldl")
        cc("lookupv.c", LOOKS_UP_V, cls.tree / "usr/bin/lookupv", "-ldl")
        cc("other.c", LOOKS_UP_OTHER, cls.tree / "usr/bin/other", "-ldl")
        cc("holds.c", HOLDS_NAME, cls.tree / "usr/bin/holds")
        cc("liblook.c", LIB_LOOKS_UP, lib / "liblook.so.1", "-shared", "-fPIC", "-Wl,-soname,liblook.so.1", "-ldl")
        cc("uses.c", USES_LIB, cls.tree / "usr/bin/user", "-L" + str(lib), "-l:liblook.so.1")
        cc("wrapped.c", WRAPPED, cls.tree / "usr/bin/wrapped", "-L" + str(lib), "-l:liblook.so.1")
        cc("mid.c", MIDDLE, lib / "libmid.so.1", "-shared", "-fPIC", "-Wl,-soname,libmid.so.1", "-L" + str(lib),
           "-l:liblook.so.1")
        cc("wrappedmid.c", WRAPPED_MID, cls.tree / "usr/bin/wrappedmid", "-L" + str(lib), "-l:libmid.so.1",
           "-Wl,-rpath-link," + str(lib))
        cc("libvlook.c", LIB_VLOOKS_UP, lib / "libvlook.so.1", "-shared", "-fPIC", "-Wl,-soname,libvlook.so.1",
           "-ldl")
        cc("wrappedv.c", WRAPPED_V, cls.tree / "usr/bin/wrappedv", "-L" + str(lib), "-l:libvlook.so.1")
        cls.got = sweep.run_tree(str(cls.tree))

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_carried_copies_are_read_by_glibc_marks(self):
        got = self.got["tree"]
        # Static copies, and (#6299) dynamic files embedding the code, with or without libraries.
        self.assertEqual(got["carries"], {"/usr/sbin/ldconfig": ["glob"], "/usr/sbin/spie": ["glob"],
                                          "/usr/sbin/sregex": ["regcomp"], "/usr/sbin/swide": ["vfwscanf"],
                                          "/usr/bin/marks": ["glob", "regcomp", "vfwscanf"],
                                          "/usr/lib/libmarks.so.1": ["glob", "regcomp", "vfwscanf"],
                                          "/usr/bin/interp": ["glob", "vfwscanf"]})
        for p in ("/usr/bin/marks", "/usr/lib/libmarks.so.1", "/usr/bin/interp"):
            self.assertNotIn(p, got["imports"])
        self.assertEqual((got["unread"], got["packed"]), ([], {}))

    def test_lookups_are_whole_group_names_beside_dlsym(self):
        got = self.got["tree"]
        self.assertEqual(got["lookups"], {"/usr/bin/lookup": ["glob", "regcomp"],
                                          "/usr/bin/lookupv": ["__isoc99_swscanf", "step"],
                                          "/usr/lib/liblook.so.1": ["wordexp"],
                                          "/usr/bin/wrapped": ["glob"], "/usr/bin/wrappedmid": ["glob"],
                                          "/usr/bin/wrappedv": ["advance", "step"]})
        # A library that looks one up is reached through, as an importing library is.
        self.assertEqual(got["via"], {"/usr/bin/user": ["/usr/lib/liblook.so.1"],
                                      "/usr/bin/wrapped": ["/usr/lib/liblook.so.1"],
                                      "/usr/bin/wrappedmid": ["/usr/lib/liblook.so.1"],
                                      "/usr/lib/libmid.so.1": ["/usr/lib/liblook.so.1"]})

    def test_a_lookup_through_a_wrapper_is_the_callers_own(self):
        # #6299: the name is the caller's, so a via entry for the wrapper's library does not accept it.
        globs = [E("/usr/lib/liblook.so.1"), E("/usr/lib/liblook.so.1", True)]
        errs = [e for e in refusals(self.got, [], globs) if "glob()" in e]
        self.assertEqual(sorted(e.split(": ", 1)[1].split(" imports")[0] for e in errs),
                         ["/usr/bin/interp", "/usr/bin/lookup", "/usr/bin/marks", "/usr/bin/wrapped",
                          "/usr/bin/wrappedmid", "/usr/lib/libmarks.so.1", "/usr/sbin/ldconfig", "/usr/sbin/spie"])
        # A dlsym-only wrapper cannot return a compat-only name: wrapped holds "step" too, which is not counted.
        self.assertEqual(self.got["tree"]["lookups"]["/usr/bin/wrapped"], ["glob"])

    def test_each_counts_as_its_own_import(self):
        errs = refusals(self.got, [], [])
        refused = sorted(e.split(" imports or reaches ")[0].split(": ", 1)[1] for e in errs)
        self.assertEqual(refused, sorted(["/usr/bin/lookup", "/usr/bin/lookup", "/usr/bin/lookupv", "/usr/bin/lookupv",
                                          "/usr/bin/user", "/usr/bin/wrapped", "/usr/bin/wrappedmid",
                                          "/usr/bin/wrappedv", "/usr/lib/liblook.so.1", "/usr/lib/libmid.so.1",
                                          "/usr/sbin/ldconfig",
                                          "/usr/sbin/spie", "/usr/sbin/sregex", "/usr/sbin/swide"]
                                         + ["/usr/bin/interp"] * 2 + ["/usr/bin/marks", "/usr/lib/libmarks.so.1"] * 3))
        embedded = ["/usr/bin/marks", "/usr/lib/libmarks.so.1", "/usr/bin/interp"]
        regex = [E("/usr/bin/lookup"), E("/usr/bin/lookupv"), E("/usr/sbin/sregex"), E("/usr/bin/wrappedv")]
        regex += [E(p) for p in embedded[:2]]
        globs = [E("/usr/bin/lookup"), E("/usr/sbin/ldconfig"), E("/usr/sbin/spie"), E("/usr/lib/liblook.so.1"),
                 E("/usr/lib/liblook.so.1", True), E("/usr/bin/wrapped"), E("/usr/bin/wrappedmid")]
        errs = refusals(self.got, regex, globs + [E(p) for p in embedded])
        # The wide scanf group has no allowed file, a static copy, an embedded one or a lookup included.
        self.assertEqual(sorted(e.split(":")[1].split()[0] for e in errs), sorted(["/usr/bin/lookupv", "/usr/sbin/swide"]
                                                                                  + embedded))
        self.assertTrue(all("wide scanf" in e for e in errs), errs)

    def test_compat_only_names_are_glibcs_hidden_ones(self):
        """COMPAT_ONLY is every group function the host's libc exports only under a hidden version, and dlsym
        (ctypes looks names up with it) returns none of them, while it returns the others."""
        libc = ctypes.util.find_library("c")
        c = ctypes.CDLL(libc)
        # The libc this process (and so ctypes) has mapped.
        path = next(line.split()[-1] for line in pathlib.Path("/proc/self/maps").read_text().splitlines()
                    if re.search(r"/libc\.so\.6$", line))
        out = subprocess.run(["objdump", "-T", path], capture_output=True, text=True, check=True).stdout
        default, hidden = set(), set()
        for line in out.splitlines():
            m = re.search(r"\.text\s+\S+\s+(\(?)GLIBC_[\d.]+\)?\s+(\S+)$", line)
            if m and sweep.group_of(m.group(2)):
                (hidden if m.group(1) else default).add(m.group(2))
        self.assertEqual(hidden - default, set(sweep.COMPAT_ONLY))
        self.assertTrue(all(not hasattr(c, n) for n in sweep.COMPAT_ONLY))
        self.assertTrue(hasattr(c, "regcomp") and hasattr(c, "glob"))

    def test_summary_names_how(self):
        lines = sweep.summary(self.got)
        self.assertIn("  carries /usr/sbin/ldconfig: glob", lines)
        self.assertIn("  looks up /usr/bin/lookup: regcomp", lines)
        self.assertIn("  via /usr/bin/user: /usr/lib/liblook.so.1", lines)
        self.assertIn("  looks up /usr/bin/wrapped: glob", lines)
        self.assertIn("  carries /usr/bin/marks: glob", lines)
        self.assertIn("tree glob: 9 files import a function (or look one up, or carry a copy), 2 more reach "
                      "one through a NEEDED library", lines)

    def test_static_control(self):
        tree = self.got["tree"]
        want = ("tree: no file carries glob() (Debian's static ldconfig always does), so the scan reads no "
                "carried copy (control)")
        base = dict(tree, imports={"/usr/bin/bash": ["regcomp"]}, cipher={"/l": {"EVP_CIPHER_fetch": 1}},
                    glibc={"/usr/lib/libc.so.6": ["glob", "regcomp", "vfwscanf"]}, unresolved={})
        self.assertEqual(sweep.problems({"tree": base}), [])
        for carries in ({}, {"/usr/sbin/sregex": ["regcomp"]}):
            with self.subTest(carries=carries):
                self.assertEqual(sweep.problems({"tree": dict(base, carries=carries)}), [want])
        # An initrd's static copy is no main-tree control.
        self.assertEqual(sweep.problems({"tree": dict(base, carries={}), "initrd:x": dict(base, others=0)}), [want])


class PerGroupLibraryTest(unittest.TestCase):
    """#6319: a file reaching glob() through one library and regex through another is held, in each group,
    to the via entries of that group's library only (the per-group filter in reach())."""

    def test_each_group_names_only_its_libraries(self):
        places = {"tree": place({"/usr/lib/libg.so.1": ["glob"], "/usr/lib/libr.so.1": ["regcomp"]},
                                {"/usr/bin/both": ["/usr/lib/libg.so.1", "/usr/lib/libr.so.1"]})}
        self.assertEqual(sweep.reach(places)[("glob", "/usr/bin/both")], {"tree": (False, ["/usr/lib/libg.so.1"])})
        regex = [E("/usr/lib/libr.so.1"), E("/usr/lib/libr.so.1", True)]
        globs = [E("/usr/lib/libg.so.1"), E("/usr/lib/libg.so.1", True)]
        self.assertEqual(refusals(places, regex, globs), [])


def built(src, out, *args):
    """OUT built from the C source SRC with the host's cc."""
    c = pathlib.Path(str(out) + ".c")
    c.write_text(src)
    subprocess.run(["cc", "-D_GNU_SOURCE", "-o", str(out), str(c), *args], check=True)
    c.unlink()
    return out


def host_libc():
    """The path of the libc.so.6 this process has mapped."""
    return next(line.split()[-1] for line in pathlib.Path("/proc/self/maps").read_text().splitlines()
                if re.search(r"/libc\.so\.6$", line))


def host_ld():
    """The path of the dynamic loader this process has mapped, which libc.so.6 needs."""
    return next(line.split()[-1] for line in pathlib.Path("/proc/self/maps").read_text().splitlines()
                if re.search(r"/ld-linux-x86-64\.so\.2$", line))


@NEEDS_CC
class PinTest(unittest.TestCase):
    """VULN-debian-r13-f4 (#6299): every GLOB entry of the regex and [glob] sections pins the SHA-256 of each
    file it accepts, as [cipher] entries do, so a new version of a reviewed file, or another file its glob
    comes to match, fails until reviewed: an entry justified by a binary's dlsym names (node's) among them."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.tree = pathlib.Path(cls.tmp.name) / "tree"
        (cls.tree / "usr/bin").mkdir(parents=True)
        # node's [glob] entry: a dlsym caller holding "glob", justified by the names its dlsym calls take.
        built(LOOKS_UP.replace('"regcomp"', '"x"'), cls.tree / "usr/bin/node", "-ldl")
        built(RPMATCH, cls.tree / "usr/bin/rm")
        built(RPMATCH.replace("v[0]", "v[1]"), cls.tree / "usr/bin/rm2")
        cls.got = sweep.run_tree(str(cls.tree))
        cls.sha = {p: hashlib.sha256((cls.tree / p.lstrip("/")).read_bytes()).hexdigest()
                   for p in ("/usr/bin/node", "/usr/bin/rm", "/usr/bin/rm2")}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def entry(self, glob, *paths):
        return sweep.Entry(glob, False, tuple(sorted({self.sha[p] for p in paths})))

    def test_the_reviewed_bytes_pass(self):
        self.assertEqual(self.got["tree"]["lookups"], {"/usr/bin/node": ["glob"]})
        self.assertEqual({p: self.got["tree"]["sha256"][p] for p in self.sha}, self.sha)
        self.assertEqual(sweep.refusals(self.got, [self.entry("/usr/bin/rm*", "/usr/bin/rm", "/usr/bin/rm2")],
                                        [self.entry("/usr/bin/node", "/usr/bin/node")]), [])

    def test_new_bytes_fail_until_pinned(self):
        # A node built to look up another name has other bytes: its review no longer holds.
        regex = [self.entry("/usr/bin/rm*", "/usr/bin/rm", "/usr/bin/rm2")]
        stale = [sweep.Entry("/usr/bin/node", False, ("cd" * 32,))]
        self.assertEqual(sweep.refusals(self.got, regex, stale), [
            "tree: /usr/bin/node reaches glob() and holds other bytes than import_sweep.allow [glob] /usr/bin/node "
            "pins (a new version, or another file it matches); review it again, then pin them: /usr/bin/node "
            "sha256=" + self.sha["/usr/bin/node"],
            "import_sweep.allow: [glob] /usr/bin/node pins sha256=%s, which no file it accepts holds; remove it"
            % ("cd" * 32)])

    def test_an_unpinned_entry_accepts_nothing(self):
        for globs in (["/usr/bin/node"], [sweep.Entry("/usr/bin/node")]):
            with self.subTest(globs=globs):
                errs = sweep.refusals(self.got, [self.entry("/usr/bin/rm*", "/usr/bin/rm", "/usr/bin/rm2")], globs)
                self.assertEqual(len(errs), 1)
                self.assertIn("/usr/bin/node reaches glob() and holds other bytes", errs[0])
        with tempfile.TemporaryDirectory() as d:
            a = pathlib.Path(d) / "allow"
            a.write_text("[glob]\n# its dlsym names are fixed\n/usr/bin/node\n")
            with self.assertRaises(SystemExit) as cm:
                sweep.read_allow(a)
            self.assertIn(":3: /usr/bin/node pins no SHA-256", str(cm.exception))

    def test_a_glob_pins_each_file_it_accepts(self):
        # One glob over two files with other bytes pins both: a file it comes to match is read first.
        one = [self.entry("/usr/bin/rm*", "/usr/bin/rm")]
        node = [self.entry("/usr/bin/node", "/usr/bin/node")]
        self.assertEqual([e.split(" reaches")[0] for e in sweep.refusals(self.got, one, node)],
                         ["tree: /usr/bin/rm2"])
        # And a pin no accepted file holds fails, so a replaced version's pin does not linger.
        extra = [sweep.Entry("/usr/bin/rm*", False, tuple(sorted([self.sha["/usr/bin/rm"], self.sha["/usr/bin/rm2"],
                                                                  "cd" * 32])))]
        self.assertEqual(sweep.refusals(self.got, extra, node), [
            "import_sweep.allow: /usr/bin/rm* pins sha256=%s, which no file it accepts holds; remove it" % ("cd" * 32)])

    def test_a_pin_holds_in_every_place(self):
        # The same path in an initrd with other bytes fails there, though its main-tree copy passes.
        initrd = dict(self.got["tree"], sha256=dict(self.got["tree"]["sha256"], **{"/usr/bin/rm": "cd" * 32}))
        places = {"tree": self.got["tree"], "initrd:x": initrd}
        errs = sweep.refusals(places, [self.entry("/usr/bin/rm*", "/usr/bin/rm", "/usr/bin/rm2")],
                              [self.entry("/usr/bin/node", "/usr/bin/node")])
        self.assertEqual(errs, ["initrd:x: /usr/bin/rm reaches a regex function and holds other bytes than "
                                "import_sweep.allow /usr/bin/rm* pins (a new version, or another file it matches); "
                                "review it again, then pin them: /usr/bin/rm* sha256=" + "cd" * 32])

    def test_a_via_entry_needs_no_pin(self):
        places = {"tree": dict(place({"/usr/lib/libs.so.1": ["regcomp"]}, {"/usr/bin/lsblk": ["/usr/lib/libs.so.1"]}),
                               sha256={"/usr/lib/libs.so.1": D, "/usr/bin/lsblk": "cd" * 32})}
        self.assertEqual(sweep.refusals(places, [E("/usr/lib/libs.so.*"), E("/usr/lib/libs.so.*", True)]), [])


@NEEDS_CC
class GlibcControlTest(unittest.TestCase):
    """#6299 (L3 and Security on #6339): the marks are checked against every glibc the image holds, not only
    the runner's libc.a; a glibc is not a carried copy of itself."""

    def test_every_glibc_holds_every_mark(self):
        with tempfile.TemporaryDirectory() as t:
            tree = pathlib.Path(t)
            (tree / "usr/lib/x86_64-linux-gnu").mkdir(parents=True)
            shutil.copy(host_libc(), tree / "usr/lib/x86_64-linux-gnu/libc.so.6")
            shutil.copy(host_ld(), tree / "usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")
            (tree / "usr/sbin").mkdir()
            built(STATIC_GLOB, tree / "usr/sbin/ldconfig", "-static", "-s")
            got = sweep.run_tree(str(tree))["tree"]
        self.assertEqual(got["glibc"], {"/usr/lib/x86_64-linux-gnu/libc.so.6": ["glob", "regcomp", "vfwscanf"]})
        self.assertEqual(got["carries"], {"/usr/sbin/ldconfig": ["glob"]})
        base = dict(got, imports={"/usr/bin/bash": ["regcomp"]}, cipher={"/l": {"EVP_CIPHER_fetch": 1}})
        self.assertEqual(sweep.problems({"tree": base}), [])
        self.assertEqual(sweep.problems({"tree": dict(base, glibc={})}),
                         ["tree: no glibc (libc.so.6) read, so the marks are checked against none (control)"])
        # A glibc lacking a mark, in the tree (a guest's among them) or an initrd, fails for that mark.
        lacking = {"/usr/lib/agentos/images/g/lib/libc.so.6": ["glob", "vfwscanf"]}
        want = ("the glibc /usr/lib/agentos/images/g/lib/libc.so.6 holds no regcomp mark, so carried copies of "
                "that code would pass unread (control)")
        self.assertEqual(sweep.problems({"tree": dict(base, glibc=dict(base["glibc"], **lacking))}), ["tree: " + want])
        initrd = dict(base, others=0, glibc=lacking)
        self.assertEqual(sweep.problems({"tree": base, "initrd:x": initrd}), ["initrd:x: " + want])


# #6299 (Security on #6339): packed code. A program whose glob() call no import or mark would show once packed.
PACKED_SRC = STATIC_GLOB


@NEEDS_CC
class PackedTest(unittest.TestCase):
    """#6299: a file whose code is not in its bytes as stored (a UPX-style packer drops the section table and
    unpacks into memory), or whose headers do not parse, is flagged and fails the step."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        t = cls.tree = pathlib.Path(cls.tmp.name)
        plain = built(PACKED_SRC, t / "plain", "-static", "-s").read_bytes()
        built(PLAIN, t / "dynamic")

        def patched(name, data, *edits):
            data = bytearray(data)
            for off, fmt, value in edits:
                struct.pack_into("<" + fmt, data, off, value)
            (t / name).write_bytes(bytes(data))
        # No section table: e_shoff, e_shnum and e_shstrndx zeroed, as UPX leaves them.
        patched("nosections", plain, (0x28, "Q", 0), (0x3C, "H", 0), (0x3E, "H", 0))
        phoff, (phentsize, phnum) = struct.unpack_from("<Q", plain, 0x20)[0], struct.unpack_from("<HH", plain, 0x36)
        loads = [h for h in range(phoff, phoff + phnum * phentsize, phentsize) if struct.unpack_from("<I", plain, h)[0] == 1]
        text = next(h for h in loads if struct.unpack_from("<I", plain, h + 4)[0] & 1)
        flags, filesz = struct.unpack_from("<I", plain, text + 4)[0], struct.unpack_from("<Q", plain, text + 32)[0]
        # Its code segment made writable too, or larger in memory than in the file.
        patched("wx", plain, (text + 4, "I", flags | 2))
        patched("grows", plain, (text + 40, "Q", filesz + 0x10000))
        # Program headers past the end of the file.
        patched("badheaders", plain, (0x20, "Q", len(plain) + 4096))
        cls.got = sweep.sweep({"/" + n: str(t / n) for n in ("plain", "dynamic", "nosections", "wx", "grows",
                                                             "badheaders")})

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_packed_files_are_flagged(self):
        # Headers that do not parse are flagged in their own right, whatever objdump makes of the file
        # (Security R1 on #6382), and objdump leaves this one unread too.
        self.assertEqual(self.got["packed"], {"/nosections": "no section table",
                                              "/wx": "a writable and executable segment",
                                              "/grows": "executable memory past its file bytes",
                                              "/badheaders": "headers that do not parse"})
        self.assertIn("/badheaders", self.got["unread"])
        self.assertNotIn("/plain", self.got["unread"])
        self.assertEqual({sweep.packed(b"\x7fELF"), sweep.packed(b"\x7fELF\x03\x01" + bytes(60))},
                         {"headers that do not parse"})

    def test_packed_files_fail_the_step(self):
        errs = sweep.problems({"t": self.got})
        for p, why in self.got["packed"].items():
            self.assertIn("t: %s is packed (%s): its code cannot be read for imports, lookups or carried copies"
                          % (p, why), errs)
        self.assertIn("t: objdump could not read /badheaders", errs)

    def test_summary_names_them(self):
        self.assertIn("  packed /wx: a writable and executable segment", sweep.summary({"t": self.got}))


# Security blocker on #6382: GNU ld merges a string literal into the tail of a longer one, so a file that
# looks "glob" up and also holds "safe_glob" stores no "glob" with a NUL before it. Built with -O2 as
# distribution packages are.
MERGED_LOOKUP = ('#include <stdio.h>\n#include <dlfcn.h>\n'
                 'int main(void) { puts("safe_glob"); return dlsym(RTLD_DEFAULT, "glob") != 0; }\n')
MERGED_WRAPPED = 'int f(const char *);\nint puts(const char *);\nint main(void) { puts("safe_glob"); return f("glob"); }\n'
LIB_WRAPS = '#include <dlfcn.h>\nint f(const char *n) { return dlsym(RTLD_DEFAULT, n) != 0; }\n'
MERGED_MARK = ('int puts(const char *);\n'
               'int main(void) { puts("my_glob_in_dir"); return puts("glob_in_dir"); }\n')


@NEEDS_CC
class TailMergeTest(unittest.TestCase):
    """A group name or a glibc mark that ends a stored string counts, as a merged literal stores it."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        t = pathlib.Path(cls.tmp.name)
        lib = t / "usr/lib"
        lib.mkdir(parents=True)
        (t / "usr/bin").mkdir()
        built(MERGED_LOOKUP, t / "usr/bin/merged", "-O2", "-ldl")
        built(LIB_WRAPS, lib / "libwraps.so.1", "-O2", "-shared", "-fPIC", "-Wl,-soname,libwraps.so.1", "-ldl")
        built(MERGED_WRAPPED, t / "usr/bin/mwrapped", "-O2", "-L" + str(lib), "-l:libwraps.so.1")
        built(MERGED_MARK, t / "usr/bin/mmark", "-O2")
        cls.bytes = {n: (t / "usr/bin" / n).read_bytes() for n in ("merged", "mwrapped", "mmark")}
        cls.got = sweep.run_tree(str(t))["tree"]

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_the_linker_merged_them(self):
        # The premise: each name is stored only as the tail of the longer string.
        for n, held in (("merged", b"glob"), ("mwrapped", b"glob"), ("mmark", b"glob_in_dir")):
            with self.subTest(n=n):
                self.assertNotIn(b"\0" + held + b"\0", self.bytes[n])
                self.assertIn(held + b"\0", self.bytes[n])

    def test_merged_names_and_marks_count(self):
        self.assertEqual(self.got["lookups"]["/usr/bin/merged"], ["glob"])
        self.assertEqual(self.got["lookups"]["/usr/bin/mwrapped"], ["glob"])
        self.assertEqual(self.got["carries"]["/usr/bin/mmark"], ["glob"])

    def test_re_names_are_glibcs(self):
        """RE_NAMES, the bounded form of the group's re_\\w+ for string tails, is every re_* name the host's
        libc exports."""
        out = subprocess.run(["objdump", "-T", host_libc()], capture_output=True, text=True, check=True).stdout
        exported = {line.split()[-1] for line in out.splitlines() if re.search(r"\sGLIBC_[\d.]+\)?\s+re_\w+$", line)}
        self.assertEqual(exported, set(sweep.RE_NAMES))
        self.assertEqual([m.group() for m in sweep.LOOKUP.finditer(b"\0store_value\0x_re_search_2\0")],
                         [b"re_search_2"])


@NEEDS_CC
class GlibcIdentityTest(unittest.TestCase):
    """Security R2 on #6382: only libc.so.6 at the path Debian installs it is a glibc; a file elsewhere
    with that SONAME is read as any other file, so its marks are a carried copy."""

    def test_a_libc_so_6_elsewhere_is_a_carried_copy(self):
        with tempfile.TemporaryDirectory() as t:
            tree = pathlib.Path(t)
            for d in ("usr/lib/x86_64-linux-gnu", "usr/lib/agentos/images/g/usr/lib/x86_64-linux-gnu",
                      "usr/lib/other"):
                (tree / d).mkdir(parents=True)
                shutil.copy(host_libc(), tree / d / "libc.so.6")
            got = sweep.run_tree(str(tree))["tree"]
        self.assertEqual(set(got["glibc"]), {"/usr/lib/x86_64-linux-gnu/libc.so.6",
                                             "/usr/lib/agentos/images/g/usr/lib/x86_64-linux-gnu/libc.so.6"})
        self.assertEqual(got["carries"], {"/usr/lib/other/libc.so.6": ["glob", "regcomp", "vfwscanf"]})


@NEEDS_CC
class UnresolvedTest(unittest.TestCase):
    """Security R4 on #6382: a NEEDED name no file or link of the place answers to is named in the summary
    and fails the step unless a pinned [unresolved] entry accepts the file (LinkTest has the links)."""

    def test_an_unresolved_needed_is_named(self):
        with tempfile.TemporaryDirectory() as t:
            tree = pathlib.Path(t)
            lib = tree / "usr/lib/x86_64-linux-gnu"
            lib.mkdir(parents=True)
            shutil.copy(host_libc(), lib / "libc.so.6")
            shutil.copy(host_ld(), lib / "ld-linux-x86-64.so.2")
            built(LIB_WRAPS, lib / "libwraps.so.1", "-shared", "-fPIC", "-Wl,-soname,libwraps.so.1", "-ldl")
            (tree / "usr/bin").mkdir()
            built(MERGED_WRAPPED, tree / "usr/bin/w", "-L" + str(lib), "-l:libwraps.so.1")
            got = sweep.run_tree(str(tree))["tree"]
            self.assertEqual(got["unresolved"], {})
            self.assertEqual(got["through"]["/usr/bin/w"], {"/usr/lib/x86_64-linux-gnu/libwraps.so.1": ["dlsym"]})
            # The wrapper gone: what it would look up is not read, and the summary names it.
            (lib / "libwraps.so.1").unlink()
            got = sweep.run_tree(str(tree))["tree"]
        self.assertEqual(got["unresolved"], {"/usr/bin/w": ["libwraps.so.1"]})
        self.assertIn("  unresolved /usr/bin/w: libwraps.so.1", sweep.summary({"t": got}))
        # It fails the step until a pinned [unresolved] entry accepts w's bytes (Security on #6382).
        sha = got["sha256"]["/usr/bin/w"]
        places = {"t": got}
        self.assertEqual(sweep.unresolved_refusals(places, []), [
            "t: /usr/bin/w needs libwraps.so.1, which no file or link there answers to, so what it would import "
            "through it is not read; find why it never loads there, then add the entry, with that reason, to "
            "import_sweep.allow [unresolved]: /usr/bin/w sha256=" + sha])
        self.assertEqual(sweep.unresolved_refusals(places, [sweep.Entry("/usr/bin/*", False, (sha,))]), [])
        self.assertEqual(sweep.unresolved_refusals(places, [sweep.Entry("/usr/bin/w", False, ("cd" * 32,))]), [
            "t: /usr/bin/w needs libwraps.so.1 and holds other bytes than import_sweep.allow [unresolved] /usr/bin/w "
            "pins; review it again, then pin them: /usr/bin/w sha256=" + sha,
            "import_sweep.allow: [unresolved] /usr/bin/w pins sha256=%s, which no file it matches holds; remove it"
            % ("cd" * 32)])
        self.assertEqual(sweep.unresolved_refusals(places, [sweep.Entry("/usr/bin/w", False, (sha,)),
                                                            sweep.Entry("/usr/bin/gone", False, (sha,))]), [
            "import_sweep.allow: [unresolved] /usr/bin/gone matches no file with an unresolved NEEDED name; "
            "remove it"])

    def test_the_section_parses(self):
        with tempfile.TemporaryDirectory() as d:
            a = pathlib.Path(d) / "allow"
            a.write_text("[unresolved]\n# why\n/usr/lib/x.node%s\n" % PIN)
            self.assertEqual(sweep.read_allow(a)[4], [E("/usr/lib/x.node")])
            for body, want in (("[unresolved]\nvia /usr/lib/x.node\n", "is not an entry"),
                               ("[unresolved]\n/usr/lib/x.node\n", "pins no SHA-256"),
                               ("[unresolved]\n[unresolved]\n", "[unresolved] is given again")):
                a.write_text(body)
                with self.subTest(body=body), self.assertRaises(SystemExit) as cm:
                    sweep.read_allow(a)
                self.assertIn(want, str(cm.exception))


LIB_FWD = '#include <dlfcn.h>\nvoid *fwd(const char *n) { return dlsym(RTLD_DEFAULT, n); }\n'
CALLS_FWD = 'void *fwd(const char *);\nint main(void) { return fwd("glob") == 0; }\n'


@NEEDS_CC
class LinkTest(unittest.TestCase):
    """Security on #6382: a NEEDED name the loader resolves through a symbolic link (a library with no
    SONAME, named by a link) answers to the file the link names, so a dlsym wrapper reached that way is a
    lookup source and the library is in the file's closure. The Security repro, built with gcc -O2."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        t = cls.t = pathlib.Path(cls.tmp.name)
        lib = t / "usr/lib/x86_64-linux-gnu"
        lib.mkdir(parents=True)
        (t / "usr/bin").mkdir()
        built(LIB_FWD, lib / "libw-real.so", "-O2", "-shared", "-fPIC", "-ldl")
        os.symlink("libw-real.so", lib / "libw.so")
        built(CALLS_FWD, t / "usr/bin/m", "-O2", "-L" + str(lib), "-lw")
        cls.lib = lib

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    REAL = "/usr/lib/x86_64-linux-gnu/libw-real.so"

    def test_a_library_named_by_a_link_is_resolved(self):
        self.assertEqual(sweep.read_elf(self.t / "usr/bin/m")[1:3], (["libw.so", "libc.so.6"], None))
        got = sweep.run_tree(str(self.t))["tree"]
        self.assertEqual(got["lookups"], {"/usr/bin/m": ["glob"]})
        self.assertEqual(got["through"], {"/usr/bin/m": {self.REAL: ["dlsym"]}})
        self.assertEqual(got["unresolved"]["/usr/bin/m"], ["libc.so.6"])
        # Without the link the name is unresolved, and unresolved_refusals fails it.
        without = sweep.sweep(sweep.tree_files(str(self.t)))
        self.assertEqual(without["unresolved"]["/usr/bin/m"], ["libc.so.6", "libw.so"])
        self.assertEqual(without["lookups"], {})

    def test_links_through_directories_and_absolute_targets(self):
        # /lib -> usr/lib (merged /usr), and an absolute target: both resolve within the place.
        with tempfile.TemporaryDirectory() as d:
            t = pathlib.Path(d)
            shutil.copytree(self.t / "usr", t / "usr", symlinks=True)
            os.symlink("usr/lib", t / "lib")
            (t / "usr/lib/x86_64-linux-gnu/libw.so").unlink()
            os.symlink("/lib/x86_64-linux-gnu/libw-real.so", t / "usr/lib/x86_64-linux-gnu/libw.so")
            got = sweep.run_tree(str(t))["tree"]
        self.assertEqual(got["through"], {"/usr/bin/m": {self.REAL: ["dlsym"]}})

    def test_resolve(self):
        links = {"/lib": "usr/lib", "/usr/lib/a.so": "../lib/b.so", "/usr/lib/loop": "loop",
                 "/usr/lib/agentos/images/g/usr/lib/c.so": "/usr/lib/d.so",
                 "/usr/lib/agentos/images/g/usr/lib/e.so": "../../../../../../../../x.so"}
        self.assertEqual(sweep.resolve("/lib/a.so", links), "/usr/lib/b.so")
        self.assertIsNone(sweep.resolve("/usr/lib/loop", links))
        # A guest's absolute link and its ".." stay in the guest root, as its processes see it.
        self.assertEqual(sweep.resolve("/usr/lib/agentos/images/g/usr/lib/c.so", links),
                         "/usr/lib/agentos/images/g/usr/lib/d.so")
        self.assertEqual(sweep.resolve("/usr/lib/agentos/images/g/usr/lib/e.so", links),
                         "/usr/lib/agentos/images/g/x.so")

    def test_initrd_links_and_hard_links_resolve(self):
        real = (self.lib / "libw-real.so").read_bytes()
        m = (self.t / "usr/bin/m").read_bytes()
        cases = {
            "symbolic": [("usr/lib/libw-real.so", 0o100755, real), ("usr/lib/libw.so", 0o120777, b"libw-real.so")],
            # Hard links: the body is on one name only (newc), the other name answers to the same file.
            "hard": [("usr/lib/libw.so", 0o100755, b"", 7, 2), ("usr/lib/libw-real.so", 0o100755, real, 7, 2)],
        }
        for case, members in cases.items():
            data = newc(members + [("usr/bin/m", 0o100755, m)])
            with self.subTest(case=case), tempfile.TemporaryDirectory() as d:
                p = pathlib.Path(d) / "initrd"
                p.write_bytes(data)
                with tempfile.TemporaryDirectory() as scratch:
                    got = sweep.initrd_place(p, scratch)
                self.assertEqual(got["through"], {"/usr/bin/m": {"/usr/lib/libw-real.so": ["dlsym"]}})
                self.assertEqual(set(got["unresolved"]), {"/usr/bin/m", "/usr/lib/libw-real.so"})


@NEEDS_CC
class WrapperTest(unittest.TestCase):
    """A [wrapper] entry names a library, pinned, whose dlsym calls take only its own names: a dependent's
    string is no lookup through it. The file's own dlsym import still counts."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        t = pathlib.Path(cls.tmp.name)
        lib = t / "usr/lib"
        lib.mkdir(parents=True)
        (t / "usr/bin").mkdir()
        built(LIB_WRAPS, lib / "libwraps.so.1", "-shared", "-fPIC", "-Wl,-soname,libwraps.so.1", "-ldl")
        built(LIB_VLOOKS_UP, lib / "libvlook.so.1", "-shared", "-fPIC", "-Wl,-soname,libvlook.so.1", "-ldl")
        built(MERGED_WRAPPED, t / "usr/bin/w", "-L" + str(lib), "-l:libwraps.so.1")
        built(WRAPPED_V.replace('"advance"', '"glob"'), t / "usr/bin/wv", "-L" + str(lib), "-l:libvlook.so.1")
        built(MERGED_LOOKUP, t / "usr/bin/own", "-O2", "-L" + str(lib), "-l:libwraps.so.1", "-ldl",
              "-Wl,--no-as-needed")
        cls.got = sweep.run_tree(str(t))
        cls.sha = cls.got["tree"]["sha256"]

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def wrap(self, *libs):
        return [sweep.Entry(g, False, (self.sha.get(g, "cd" * 32),)) for g in libs]

    def test_a_reviewed_wrapper_drops_its_dependents_lookups(self):
        lookups = self.got["tree"]["lookups"]
        self.assertEqual((lookups["/usr/bin/w"], lookups["/usr/bin/own"], lookups["/usr/bin/wv"]),
                         (["glob"], ["glob"], ["glob", "step"]))
        got, errs = sweep.unwrapped(self.got, self.wrap("/usr/lib/libwraps.so.1", "/usr/lib/libvlook.so.1"))
        self.assertEqual(errs, [])
        # w looked up only through libwraps; own imports dlsym itself; wv's names go with libvlook's dlvsym.
        self.assertEqual({p: n for p, n in got["tree"]["lookups"].items() if p.startswith("/usr/bin/")},
                         {"/usr/bin/own": ["glob"]})
        self.assertEqual(self.got["tree"]["lookups"]["/usr/bin/w"], ["glob"])

    def test_a_wrapper_holding_other_bytes_accepts_nothing(self):
        stale = [sweep.Entry("/usr/lib/libwraps.so.1", False, ("cd" * 32,))]
        got, errs = sweep.unwrapped(self.got, stale)
        self.assertEqual(got["tree"]["lookups"]["/usr/bin/w"], ["glob"])
        self.assertIn("tree: /usr/lib/libwraps.so.1 holds other bytes than import_sweep.allow [wrapper] "
                      "/usr/lib/libwraps.so.1 pins; review its dlsym calls again, then pin them: "
                      "/usr/lib/libwraps.so.1 sha256=" + self.sha["/usr/lib/libwraps.so.1"], errs)
        self.assertIn("import_sweep.allow: [wrapper] /usr/lib/libwraps.so.1 pins sha256=%s, which no library "
                      "it matches holds; remove it" % ("cd" * 32), errs)

    def test_an_unused_wrapper_fails(self):
        _, errs = sweep.unwrapped(self.got, self.wrap("/usr/lib/libgone.so.1"))
        self.assertEqual(errs, ["import_sweep.allow: [wrapper] /usr/lib/libgone.so.1 matches no library a "
                                "lookup goes through; remove it"])

    def test_the_section_parses(self):
        with tempfile.TemporaryDirectory() as d:
            a = pathlib.Path(d) / "allow"
            a.write_text("[wrapper]\n/usr/lib/libwraps.so.*%s\n" % PIN)
            self.assertEqual(sweep.read_allow(a)[3], [E("/usr/lib/libwraps.so.*")])
            for body, want in (("[wrapper]\nvia /usr/lib/libw.so\n", "is not an entry"),
                               ("[wrapper]\n/usr/lib/libw.so\n", "pins no SHA-256")):
                a.write_text(body)
                with self.subTest(body=body), self.assertRaises(SystemExit) as cm:
                    sweep.read_allow(a)
                self.assertIn(want, str(cm.exception))
