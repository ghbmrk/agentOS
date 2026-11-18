"""VULN-debian-r6-f2 (#5697): image/import_sweep.py reads which ELF files in a built image import
glibc's POSIX regex or wide scanf functions, directly or through a library they need, in the main
tree and in each initrd, so the glibc records' reachability claims come from the tree CI builds.
VULN-debian-r5-reach (#5341): it also counts, in each file whose bytes name an OpenSSL cipher fetch by
name string (the only way to select AES-GCM-SIV), the references to it, held to the allowlist's
[cipher] section, so the openssl records' reach note is checked on each build.
VULN-cipher-sweep-tidy (#5861): each counted entry is keyed to the reviewed file's SHA-256, so a new
package version fails until its source is read again; malformed, empty, repeated and overlapping
entries are refused, and every refusal points at the records' reach note."""
# REQ: EVL-5
import contextlib
import errno
import fnmatch
import importlib.util
import io
import os
import pathlib
import re
import shutil
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
# A program spelling the cipher, with no fetch name (Security 6899468190).
SPELLS = 'const char *c = "aes-256-gcm-siv";\nint main(void) { return c[0]; }\n'
# A program selecting KRB5KDF by name, which takes a "cipher" and does not check its mode (#5861).
KRB5KDF = 'const char *k = "KRB5KDF";\nint main(void) { return k[0]; }\n'


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
        cc("one.c", ONE_CALL, lib / "libonecall.so.1", "-shared", "-fPIC", "-L" + str(lib), "-l:libcrypto.so.3")
        cc("table.c", TABLE, lib / "libtable.so.1", "-shared", "-fPIC", "-L" + str(lib), "-l:libcrypto.so.3")
        cc("spells.c", SPELLS, cls.tree / "usr/bin/spells")
        cc("kdfname.c", KRB5KDF, cls.tree / "usr/bin/krb5kdf")
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
        # Fifteen ELF files; the text file and the symbolic links are not read.
        self.assertEqual(got["scanned"], 15)
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
        self.assertEqual(set(tree["sha256"]), set(tree["cipher"]))
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
                         "[cipher]\n/usr/lib/libcs.so.12.* sha256=%s EVP_CIPHER_fetch=1  # why\n"
                         "/usr/lib/libcrypto.so.3 *\n" % ("0f" * 32))
            self.assertEqual(sweep.load_allow(a), self.ALLOW)
            self.assertEqual(sweep.read_allow(a)[1], {"/usr/lib/libcs.so.12.*": {"sha256": "0f" * 32,
                                                                              "sites": {"EVP_CIPHER_fetch": 1}},
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
        self.assertIn("EVP_CIPHER_fetch", cipher["/usr/lib/x86_64-linux-gnu/libcryptsetup.so.12.*"]["sites"])

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
                a.write_text("/usr/bin/bash\n[cipher]\n# why\n" + body + "\n")
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
                a.write_text("/usr/bin/bash\n[cipher]\n/usr/bin/x sha256=%s GCM-SIV=1\n" % hexd)
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
