"""VULN-static-elf part b (#5885): image/static_elf.py lists every ELF file of the built image that carries
a C library or C++ runtime in its own bytes (static, or dynamic with a static C++ runtime) and holds each
to one declaration in image/static_elf.allow, whose kind says where tools/vulncheck.py image scans what
it links: a Go binary with cgo off links none; a "linked" file's link inputs were recorded by package
against its SHA-256 (image/guest-shipped.sh SHIPPED_FOR) and each is in the status the scan reads; a
"package" file is a Debian package's (whose Built-Using sources the scan also queries); a "bundled" file
is a pinned download a vulncheck.json record names."""
# REQ: EVL-5, SGE-1, SGE-2, SGE-3
import hashlib
import importlib.util
import os
import pathlib
import platform
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
IMG = ROOT / "image"
sys.path.insert(0, str(IMG))
spec = importlib.util.spec_from_file_location("static_elf", IMG / "static_elf.py")
se = importlib.util.module_from_spec(spec)
spec.loader.exec_module(se)
vspec = importlib.util.spec_from_file_location("vulncheck", ROOT / "tools" / "vulncheck.py")
vulncheck = importlib.util.module_from_spec(vspec)
vspec.loader.exec_module(vulncheck)

C = "int main(void) { return 0; }\n"
CXX = ('#include <stdexcept>\nint main(int c, char **v) { try { if (c > 5) throw std::runtime_error(v[0]); }\n'
       ' catch (std::exception &) { return 1; } return 0; }\n')
# No libc: exit by a raw system call, as gVisor's two C sidecars do.
TINY = 'void _start(void) { __asm__ volatile("mov $60, %eax\\n xor %edi, %edi\\n syscall"); }\n'
GO = "package main\n\nfunc main() {}\n"
CGO = 'package main\n\n// int f(void) { return 1; }\nimport "C"\n\nfunc main() { _ = C.f() }\n'
STATUS = "Package: %s\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1.0-1\n\n"


def tools():
    return (platform.system() == "Linux" and platform.machine() == "x86_64" and all(
        shutil.which(t) for t in ("gcc", "g++", "go", "objdump", "strip")))


def build(d, name, src, *cmd, env=None):
    w = pathlib.Path(d) / ("w-" + name)
    w.mkdir()
    ext = {"go": "main.go", "g++": "x.cc"}.get(cmd[0], "x.c")
    (w / ext).write_text(src)
    if cmd[0] == "go":
        (w / "go.mod").write_text("module m\n\ngo 1.21\n")
        cmd = list(cmd) + ["-o", str(pathlib.Path(d) / name), "."]
    else:
        cmd = list(cmd) + [ext, "-o", str(pathlib.Path(d) / name)]
    subprocess.run(cmd, cwd=w, check=True, capture_output=True,
                   env={**os.environ, "GOFLAGS": "-mod=mod", "GOWORK": "off", **(env or {})})
    return pathlib.Path(d) / name


@unittest.skipUnless(tools(), "needs an x86-64 Linux host with gcc, g++, go, objdump and strip")
class StaticElfTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="agentos-static-elf-")
        d = cls.tmp
        cls.bins = {
            "static": build(d, "static", C, "gcc", "-static", "-O2", "-s"),
            "dynamic": build(d, "dynamic", C, "gcc", "-O2"),
            "cxx": build(d, "cxx", CXX, "g++", "-O2"),
            "cxx-static-runtime": build(d, "cxx-static-runtime", CXX, "g++", "-O2", "-static-libstdc++", "-s"),
            "tiny": build(d, "tiny", TINY, "gcc", "-static", "-nostdlib", "-O2", "-s"),
            "go": build(d, "go", GO, "go", "build", "-trimpath", "-ldflags=-s -w", env={"CGO_ENABLED": "0"}),
            "cgo": build(d, "cgo", CGO, "go", "build", "-trimpath",
                         "-ldflags=-s -w -linkmode=external -extldflags=-static", env={"CGO_ENABLED": "1"}),
        }
        subprocess.run(["gcc", "-c", "-x", "c", "-", "-o", str(pathlib.Path(d) / "obj.o")], input=C, text=True, check=True)
        cls.bins["object"] = pathlib.Path(d) / "obj.o"
        # Go binaries with no build info (esbuild's release has none; Bazel's records no cgo setting).
        for b in ("go", "cgo"):
            subprocess.run(["objcopy", "-R", ".go.buildinfo", str(cls.bins[b]), str(cls.bins[b]) + "-noinfo"], check=True)
            # Build info kept with no CGO_ENABLED line, as gVisor's Bazel builds record it (Security 7068790342):
            # the setting's key rewritten to a same-length key the reader does not match.
            data = cls.bins[b].read_bytes()
            assert data.count(b"build\tCGO_ENABLED=") >= 1
            pathlib.Path(str(cls.bins[b]) + "-nosetting").write_bytes(data.replace(b"build\tCGO_ENABLED=", b"build\tXGO_ENABLED="))
            # R2: build info saying cgo off over cgo code.
            if b == "cgo":
                pathlib.Path(str(cls.bins[b]) + "-says0").write_bytes(data.replace(b"build\tCGO_ENABLED=1", b"build\tCGO_ENABLED=0"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, True)

    def test_static_files_and_static_cxx_runtimes_are_listed(self):
        # SEL-5: no PT_INTERP and no DT_NEEDED is static; a dynamic file needing no libstdc++ but carrying
        # the C++ runtime's code (stripped, so by its marks) is listed too; a dynamic C or C++ program and a
        # relocatable object are not.
        got = {k: se.classify(p) for k, p in self.bins.items()}
        self.assertEqual({k for k, v in got.items() if v}, {"static", "tiny", "cxx-static-runtime", "go", "cgo"})
        self.assertEqual(got["static"]["why"], "static")
        self.assertEqual(got["cxx-static-runtime"]["why"], "c++ runtime")
        self.assertEqual(got["static"]["sha256"], hashlib.sha256(self.bins["static"].read_bytes()).hexdigest())
        # Go build info is read from the file: cgo off says 0, cgo on says 1, a C program is no Go binary.
        self.assertEqual((got["go"]["go"], got["cgo"]["go"], got["static"]["go"]), ("0", "1", None))
        # With no build info, cgo is read from runtime/cgo's own C code in the file.
        self.assertEqual(se.go_cgo(pathlib.Path(str(self.bins["go"]) + "-noinfo").read_bytes()), "none")
        self.assertEqual(se.go_cgo(pathlib.Path(str(self.bins["cgo"]) + "-noinfo").read_bytes()), "cgo")
        self.assertNotIn(se.CGO_MARK, self.bins["go"].read_bytes())
        # Build info with no cgo setting (gVisor's): read from the code, both ways.
        self.assertEqual(se.go_cgo(pathlib.Path(str(self.bins["go"]) + "-nosetting").read_bytes()), "none")
        self.assertEqual(se.go_cgo(pathlib.Path(str(self.bins["cgo"]) + "-nosetting").read_bytes()), "cgo")
        # Build info saying cgo off is not trusted over cgo code.
        self.assertEqual(se.go_cgo(pathlib.Path(str(self.bins["cgo"]) + "-says0").read_bytes()), "0-cgo")
        # An imported runtime symbol's name in .dynstr is not the runtime's own string.
        self.assertNotIn(se.CXX_MARKS[1], self.bins["dynamic"].read_bytes())

    def test_an_elf_it_cannot_read_fails(self):
        # SEL-7: a truncated file with the ELF magic is not skipped.
        bad = pathlib.Path(self.tmp) / "bad"
        bad.write_bytes(b"\x7fELF\x02\x01")
        with self.assertRaises(se.Unread):
            se.classify(bad)
        places, unread = se.listed({"/usr/bin/bad": str(bad), "/usr/bin/s": str(self.bins["static"])})
        self.assertEqual(list(places), ["/usr/bin/s"])
        self.assertEqual(se.control({"tree": places}, {"tree": unread})[0][:31], "tree: cannot read /usr/bin/bad:")

    def tree(self):
        """A main tree holding REQUIRED (each a fixture binary) and an OUT with lists that declare them."""
        t = pathlib.Path(tempfile.mkdtemp(prefix="agentos-static-elf-tree-"))
        self.addCleanup(shutil.rmtree, t, True)
        root, out = t / "root", t / "out"
        files = {"/usr/lib/agentos/infer/llama-server": "static", "/usr/lib/agentos/runsc": "go",
                 "/usr/lib/agentos/images/camdecode/agentos-camdecode": "cgo", "/usr/sbin/ldconfig": "static",
                 "/usr/lib/agentos/images/codex/usr/local/bin/rg": "static",
                 "/usr/lib/agentos/images/codex/usr/bin/bwrap": "cxx-static-runtime",
                 "/usr/lib/agentos/gvisor-bin/prewarmer": "tiny", "/usr/bin/dyn": "dynamic"}
        for path, b in files.items():
            dst = root / path.lstrip("/")
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy(self.bins[b], dst)
        sha = {b: hashlib.sha256(self.bins[b].read_bytes()).hexdigest() for b in self.bins}
        for name, lines, pkgs in (("linked", ["%s libc6-dev" % sha["static"], "%s libstdc++-14-dev" % sha["static"]],
                                   ("libc6-dev", "libstdc++-14-dev")),
                                  ("guest", ["%s libavcodec-pin" % sha["cgo"], "%s libcap-dev" % sha["cxx-static-runtime"]],
                                   ("libavcodec-pin", "libcap-dev"))):
            (out / name).mkdir(parents=True)
            (out / name / se.INPUTS).write_text("\n".join(lines) + "\n")
            (out / name / se.STATUS).write_text("".join(STATUS % p for p in pkgs))
        (out / se.STATUS).write_text(STATUS % "libc-bin")
        md5 = hashlib.md5(self.bins["static"].read_bytes()).hexdigest()
        (out / se.MD5SUMS).write_text("%s  usr/sbin/ldconfig\n" % md5)
        config = t / "vulncheck.json"
        config.write_text('{"bundled": [{"holder": "@openai/codex@1-linux-x64"}]}\n')
        allow = t / "allow"
        entries = ["/usr/lib/agentos/infer/llama-server linked linked", "/usr/lib/agentos/runsc go",
                   "/usr/lib/agentos/images/camdecode/agentos-camdecode linked guest",
                   "/usr/sbin/ldconfig package libc-bin",
                   "/usr/lib/agentos/images/codex/usr/local/bin/rg bundled @openai/codex@1-linux-x64",
                   "/usr/lib/agentos/images/codex/usr/bin/bwrap linked guest",
                   "/usr/lib/agentos/gvisor-bin/prewarmer sha256 " + sha["tiny"].upper()]
        allow.write_text("# a comment\n" + "\n".join(entries) + "\n")
        return root, out, allow, config, entries

    def check(self, root, out, allow, config):
        files = se.tree_files(str(root))
        places, unread = se.listed(files)
        for shown, info in places.items():
            info["real"] = files[shown]
        return se.control({"tree": places}, {"tree": unread}) + se.refusals(
            {"tree": places}, se.read_allow(allow), se.context(out, config), {})

    def test_a_declared_tree_passes_and_each_refusal_is_named(self):
        # SEL-6: every listed file matches one entry and passes its kind's check.
        root, out, allow, config, entries = self.tree()
        self.assertEqual(self.check(root, out, allow, config), [])
        cases = [
            # an unlisted static file
            ("unlisted", lambda: shutil.copy(self.bins["static"], root / "usr/bin/new"),
             "/usr/bin/new (static): no entry in static_elf.allow declares it"),
            # two entries match one file
            ("two", lambda: allow.write_text(allow.read_text() + "/usr/lib/agentos/run* go\n"), "matches 2 entries"),
            # an entry matching nothing
            ("unmatched", lambda: allow.write_text(allow.read_text() + "/usr/lib/agentos/gone go\n"),
             "/usr/lib/agentos/gone matches no listed file"),
            # go on a cgo binary
            ("cgo", lambda: allow.write_text(allow.read_text().replace(
                "agentos-camdecode linked guest", "agentos-camdecode go")), "a Go binary with cgo (Go CGO_ENABLED=1)"),
            # go on a C binary
            ("not go", lambda: allow.write_text(allow.read_text().replace(
                "llama-server linked linked", "llama-server go")), "not a Go binary"),
            # sha256, with other bytes than the reviewed ones
            ("sha256", lambda: allow.write_text(re.sub(
                r"(?m)^(/usr/lib/agentos/gvisor-bin/prewarmer sha256 )\w+$", r"\g<1>" + "a" * 64, allow.read_text())),
             "not the reviewed " + "a" * 64),
            # go on a Go binary with no build info and cgo code
            ("cgo, no info", lambda: shutil.copy(str(self.bins["cgo"]) + "-noinfo", root / "usr/lib/agentos/runsc"),
             "a Go binary with cgo (Go, no cgo setting, cgo code)"),
            # go on a Go binary whose build info records no cgo setting and that holds cgo code
            ("cgo, no setting", lambda: shutil.copy(str(self.bins["cgo"]) + "-nosetting", root / "usr/lib/agentos/runsc"),
             "a Go binary with cgo (Go, no cgo setting, cgo code)"),
            # go on a binary whose build info says cgo off over cgo code
            ("cgo, says 0", lambda: shutil.copy(str(self.bins["cgo"]) + "-says0", root / "usr/lib/agentos/runsc"),
             "a Go binary with cgo (Go CGO_ENABLED=0 but cgo code)"),
            # sha256 on a file too large to be declared by review alone
            ("sha256 size", lambda: allow.write_text(allow.read_text().replace(
                "/usr/lib/agentos/runsc go", "/usr/lib/agentos/runsc sha256 " + "a" * 64)), "only a static file of at most"),
            # linked, with a link input missing from the status the scan reads
            ("missing", lambda: (out / "guest" / se.STATUS).write_text(STATUS % "libavcodec-pin"),
             "its link inputs ['libcap-dev'] are not in guest/agentos.dpkg-status"),
            # linked, with nothing recorded for the file's bytes (a rebuilt or replaced binary)
            ("rebuilt", lambda: (out / "linked" / se.INPUTS).write_text("0" * 64 + " libc6-dev\n"),
             "no link inputs recorded for its SHA-256"),
            # linked to a list that does not exist
            ("no list", lambda: allow.write_text(allow.read_text().replace("bwrap linked guest", "bwrap linked other")),
             "linked names no list 'other'"),
            # bundled naming no holder
            ("holder", lambda: config.write_text('{"bundled": []}\n'), "names no holder '@openai/codex@1-linux-x64'"),
            # package not installed in its tree
            ("package", lambda: (out / se.STATUS).write_text(STATUS % "other"), "package libc-bin is not installed"),
            # package, but the bytes are not dpkg's
            ("md5", lambda: (out / se.MD5SUMS).write_text("%s  usr/sbin/ldconfig\n" % ("0" * 32)),
             "not the ones dpkg installed"),
        ]
        for name, edit, want in cases:
            with self.subTest(name):
                root, out, allow, config, _ = self.tree()
                edit()
                errs = self.check(root, out, allow, config)
                self.assertTrue(any(want in e for e in errs), errs)

    def test_the_control_fails_on_a_tree_missing_a_required_file(self):
        # SEL-7: a walk that does not list llama-server, runsc, agentos-camdecode and ldconfig read nothing
        # it should have; and the CLI exits 1 on any refusal, 0 on a clean tree.
        root, out, allow, config, _ = self.tree()
        r = subprocess.run([sys.executable, str(IMG / "static_elf.py"), "--tree", str(root), str(out), str(allow)],
                           capture_output=True, text=True)
        # The shipped vulncheck.json names no @openai/codex@1 holder: the one refusal.
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertEqual(len(re.findall("::error", r.stdout)), 1, r.stdout)
        self.assertIn("tree /usr/lib/agentos/runsc: static, Go CGO_ENABLED=0", r.stdout)
        (root / "usr/lib/agentos/runsc").unlink()
        allow.write_text(allow.read_text().replace("/usr/lib/agentos/runsc go\n", ""))
        errs = self.check(root, out, allow, config)
        self.assertEqual(errs, ["tree: /usr/lib/agentos/runsc is not listed, so the walk did not read what it "
                                "should have (control)"])

    def test_a_glob_star_stays_in_its_segment_and_each_debian_initrd_has_its_control(self):
        # L3 7068815628 point 3: "*" does not cross "/". Points 2 and 5: an initrd with a dpkg status must
        # list ldconfig; a modules initrd (no status) needs nothing.
        self.assertTrue(se.matches("/usr/lib/agentos/agentosd", "/usr/lib/agentos/agentos*"))
        self.assertFalse(se.matches("/usr/lib/agentos/agentos-x/y", "/usr/lib/agentos/agentos*"))
        self.assertTrue(se.matches("/usr/lib/agentos/images/codex/lib64/ld.so", "/usr/lib/agentos/images/*/lib64/ld.so"))
        info = se.classify(self.bins["static"])
        places = {"tree": {p: info for p in se.REQUIRED}, "initrd:a/initrd": {}, "initrd:a/modules": {}}
        errs = se.control(places, {}, {"initrd:a/initrd": {"libc-bin"}, "initrd:a/modules": None})
        self.assertEqual(errs, ["initrd:a/initrd: /usr/sbin/ldconfig is not listed, so the initrd's walk did not "
                                "read what it should have (control)"])
        places["initrd:a/initrd"] = {"/usr/sbin/ldconfig": info}
        self.assertEqual(se.control(places, {}, {"initrd:a/initrd": {"libc-bin"}, "initrd:a/modules": None}), [])

    def test_go_is_read_from_section_headers_and_syso_c_code_is_seen(self):
        # #6482 (L3 7068815628 point 4a): Go is read from the section headers, not from marker bytes
        # anywhere in the file; a C binary carrying .gopclntab's name and Go's build-info magic is no Go.
        data = self.bins["static"].read_bytes()
        pad = b"\0" * (-(len(data) + 12) % 16)
        planted = data + b"\0.gopclntab\0" + pad + se.BUILDINFO + b"\x08\x02" + b"\0" * 16
        self.assertIsNone(se.go_cgo(planted))
        self.assertIsNone(se.go_cgo(data))
        # Point 4b: C code an internal link takes from a .syso, with cgo off, is in the function table with
        # no line table (Go refuses -linkmode=external with cgo off, so this is C's one way in).
        w = pathlib.Path(self.tmp) / "w-syso"
        w.mkdir()
        (w / "go.mod").write_text("module m\n\ngo 1.21\n")
        (w / "main.go").write_text("package main\n\nfunc cfunc() int\n\nfunc main() { println(cfunc()) }\n")
        (w / "stub_amd64.s").write_text('#include "textflag.h"\nTEXT \u00b7cfunc(SB),NOSPLIT,$0-8\n'
                                        "\tCALL my_c_func(SB)\n\tMOVQ AX, ret+0(FP)\n\tRET\n")
        subprocess.run(["gcc", "-O2", "-c", "-x", "c", "-", "-o", str(w / "c_amd64.syso")],
                       input="int my_c_func(void) { return 7; }\n", text=True, check=True)
        syso = pathlib.Path(self.tmp) / "go-syso"
        subprocess.run(["go", "build", "-trimpath", "-ldflags=-s -w", "-o", str(syso), "."], cwd=w, check=True,
                       capture_output=True, env={**os.environ, "CGO_ENABLED": "0", "GOFLAGS": "-mod=mod", "GOWORK": "off"})
        table = se.sections(syso.read_bytes())[".gopclntab"]
        self.assertEqual(se.no_line_funcs(syso.read_bytes()[table[0]:table[0] + table[1]]), ["my_c_func"])
        self.assertEqual(se.go_cgo(syso.read_bytes()), "0-c")
        noinfo = pathlib.Path(str(syso) + "-noinfo")
        subprocess.run(["objcopy", "-R", ".go.buildinfo", str(syso), str(noinfo)], check=True)
        self.assertEqual(se.go_cgo(noinfo.read_bytes()), "c")
        # A plain Go binary lists none.
        table = se.sections(self.bins["go"].read_bytes())[".gopclntab"]
        self.assertEqual(se.no_line_funcs(self.bins["go"].read_bytes()[table[0]:table[0] + table[1]]), [])
        root, out, allow, config, _ = self.tree()
        for src, want in ((syso, "Go CGO_ENABLED=0 but C functions with no line table"),
                          (noinfo, "Go, no cgo setting, C functions with no line table")):
            shutil.copy(src, root / "usr/lib/agentos/runsc")
            errs = self.check(root, out, allow, config)
            self.assertIn("/usr/lib/agentos/runsc: go : a Go binary with C code (%s)" % want, errs)
        # A section table that is not inside the file, or a function table of an unknown format, is unread.
        bad = bytearray(self.bins["go"].read_bytes())
        bad[40:48] = (len(bad) + 1).to_bytes(8, "little")
        with self.assertRaises(se.Unread):
            se.go_cgo(bytes(bad))
        with self.assertRaises(se.Unread):
            se.no_line_funcs(b"\xfa\xff\xff\xff\0\0\x01\x08" + b"\0" * 64)

    def syso_pkg(self, name, asm):
        """A CGO_ENABLED=0 package whose Go stub calls my_c_func, C code in a .syso assembled from ASM."""
        w = pathlib.Path(self.tmp) / ("w-" + name)
        w.mkdir()
        (w / "go.mod").write_text("module m\n\ngo 1.21\n")
        (w / "main.go").write_text("package main\n\nfunc cfunc() int\n\nfunc main() { println(cfunc()) }\n")
        (w / "stub_amd64.s").write_text('#include "textflag.h"\nTEXT \u00b7cfunc(SB),NOSPLIT,$0-8\n'
                                        "\tCALL my_c_func(SB)\n\tMOVQ AX, ret+0(FP)\n\tRET\n")
        (w / "c.s").write_text(asm)
        subprocess.run(["gcc", "-c", str(w / "c.s"), "-o", str(w / "c_amd64.syso")], check=True)
        (w / "c.s").unlink()
        return w

    def go_build(self, w, out, *flags):
        subprocess.run(["go", "build", "-trimpath", "-ldflags=-s -w", *flags, "-o", str(out), "."], cwd=w, check=True,
                       capture_output=True, env={**os.environ, "CGO_ENABLED": "0", "GOFLAGS": "-mod=mod", "GOWORK": "off"})
        return out

    def test_a_go_file_runs_only_code_its_function_table_lists(self):
        # #6563 item 1 (SGE-1): cmd/link takes -linkmode=external with cgo off (a warning only; go build refuses,
        # so the flag is added at the link step, as a build system calling the linker itself does). The C from a
        # .syso then sits outside the function table and runtime/cgo is absent, yet the file holds glibc's crt.
        asm = "\t.text\n\t.globl my_c_func\n\t.type my_c_func, @function\nmy_c_func:\n\tmovl $7, %eax\n\tret\n"
        w = self.syso_pkg("ext", asm)
        tx = pathlib.Path(self.tmp) / "toolexec.sh"
        tx.write_text('#!/bin/sh\nt="$1"; shift\ncase "$(basename "$t")" in\n'
                      '  link) exec "$t" -linkmode=external -extldflags=-static "$@";;\nesac\nexec "$t" "$@"\n')
        tx.chmod(0o755)
        ext = self.go_build(w, pathlib.Path(self.tmp) / "go-ext", "-toolexec=" + str(tx))
        data = ext.read_bytes()
        secs = se.sections(data)
        self.assertTrue({".init", ".plt", ".fini"} <= set(secs))
        o, n = secs[".gopclntab"][:2]
        self.assertEqual(se.no_line_funcs(data[o:o + n]), [])  # the table alone does not see it
        self.assertNotIn(se.CGO_MARK, data)
        self.assertEqual(se.go_cgo(data), "0-o")
        self.assertIn("executable sections", se.go_outside(data))
        # Section flags are header text: with .init, .plt and .fini marked as data the crt and libc code still
        # lies in .text outside the table, and in the executable segment.
        flat = pathlib.Path(str(ext) + "-flat")
        subprocess.run(["objcopy"] + [a for s in (".init", ".plt", ".fini")
                                      for a in ("--set-section-flags", s + "=alloc,load,readonly,data")]
                       + [str(ext), str(flat)], check=True)
        self.assertEqual([k for k, v in se.sections(flat.read_bytes()).items() if v[3] & se.SHF_EXECINSTR], [".text"])
        self.assertEqual(se.go_cgo(flat.read_bytes()), "0-o")
        root, out, allow, config, _ = self.tree()
        shutil.copy(ext, root / "usr/lib/agentos/runsc")
        self.assertIn("/usr/lib/agentos/runsc: go : a Go binary with code outside its function table "
                      "(Go CGO_ENABLED=0 but code outside its function table)", self.check(root, out, allow, config))
        # An entry point outside every listed function, or on a linker marker (no line table), is refused.
        go = self.bins["go"].read_bytes()
        self.assertIsNone(se.go_outside(go))
        _o, size, addr, _f = se.sections(go)[".text"]
        o, n = se.sections(go)[".gopclntab"][:2]
        _base, funcs, _end = se.pcln_funcs(go[o:o + n])
        marker = [e for e, name, _l in funcs if name in se.GO_MARKERS]
        for entry in [addr + size - 1] + [addr + e for e in marker]:
            bad = bytearray(go)
            bad[24:32] = entry.to_bytes(8, "little")
            self.assertIn("entry point", se.go_outside(bytes(bad)))
            self.assertEqual(se.go_cgo(bytes(bad)), "0-o")
        # An executable segment reaching past .text is refused.
        bad = bytearray(go)
        phoff, = struct.unpack_from("<Q", go, 32)
        for k in range(struct.unpack_from("<H", go, 56)[0]):
            at = phoff + 56 * k
            typ, flags = struct.unpack_from("<II", go, at)
            if typ == 1 and flags & 1:
                struct.pack_into("<Q", bad, at + 40, struct.unpack_from("<Q", go, at + 40)[0] + 0x1000)
        self.assertIn("executable segment", se.go_outside(bytes(bad)))

    def test_each_layout_guard_refuses_on_its_own(self):
        # #6700 L3 7175192951 point 1: one edit of a plain Go binary per guard, every other guard still met, so
        # each check is the one that refuses. Offsets: e_phoff 32, e_shoff 40; Elf64_Shdr sh_size at 32;
        # Elf64_Phdr p_vaddr at 16, p_memsz at 40; the table's stored text start at 24 (0 from Go 1.26).
        go = self.bins["go"].read_bytes()
        self.assertIsNone(se.go_outside(go))
        _o, size, addr, _f = se.sections(go)[".text"]
        pcln = se.sections(go)[".gopclntab"][0]
        shoff, = struct.unpack_from("<Q", go, 40)
        strndx, = struct.unpack_from("<H", go, 62)
        names = struct.unpack_from("<Q", go, shoff + 64 * strndx + 24)[0]
        text_sh = next(shoff + 64 * k for k in range(struct.unpack_from("<H", go, 60)[0])
                       if go[names + struct.unpack_from("<I", go, shoff + 64 * k)[0]:].startswith(b".text\0"))
        phoff, = struct.unpack_from("<Q", go, 32)
        run = [phoff + 56 * k for k in range(struct.unpack_from("<H", go, 56)[0])
               if struct.unpack_from("<II", go, phoff + 56 * k) == (1, 5)]
        self.assertEqual(len(run), 1)
        seg = run[0]
        vaddr, = struct.unpack_from("<Q", go, seg + 16)

        def edited(*edits):
            b = bytearray(go)
            for at, form, value in edits:
                struct.pack_into(form, b, at, value)
            return bytes(b)
        # The table stops short of .text's end: .text and its segment grown by a page, the stored start zeroed
        # (as Go 1.26 stores it), so only the span check sees the bytes past the table.
        grown = edited((text_sh + 32, "<Q", size + 0x1000), (seg + 40, "<Q", addr + size + 0x1000 - vaddr),
                       (pcln + 24, "<Q", 0))
        self.assertIn("function table spans", se.go_outside(grown))
        self.assertEqual(se.go_cgo(grown), "0-o")
        # The executable segment starts after .text's start (and still ends at its end).
        late = edited((seg + 16, "<Q", addr + 16), (seg + 40, "<Q", size - 16))
        self.assertIn("executable segment", se.go_outside(late))
        # A stored text start that is not .text's address.
        moved = edited((pcln + 24, "<Q", addr + 16))
        self.assertIn("text start", se.go_outside(moved))
        # A table whose entries are out of address order is unread (fails closed), not walked.
        _base, funcs, _end = se.pcln_funcs(go[pcln:])
        ftab = pcln + struct.unpack_from("<Q", go, pcln + 64)[0]
        unordered = edited((ftab + 8, "<I", funcs[0][0]))
        with self.assertRaises(se.Unread):
            se.go_cgo(unordered)

    def test_a_forged_function_table_is_not_go(self):
        # #6563 item 2 (SGE-2): a .gopclntab section added to a static glibc C binary (a 1.20 header, no
        # functions) does not make it Go, and a real table edited to list no function is refused.
        head = struct.pack("<IBBBB8Q", 0xFFFFFFF1, 0, 0, 1, 8, 0, 0, 0, 72, 72, 72, 72, 72) + b"\0" * 16
        hp = pathlib.Path(self.tmp) / "forged-head"
        hp.write_bytes(head)
        forged = pathlib.Path(self.tmp) / "forged"
        subprocess.run(["objcopy", "--add-section", ".gopclntab=%s" % hp, str(self.bins["static"]), str(forged)],
                       check=True)
        self.assertIn(".gopclntab", se.sections(forged.read_bytes()))
        self.assertEqual(se.go_cgo(forged.read_bytes()), "o")
        self.assertIn("lists no function", se.go_outside(forged.read_bytes()))
        go = bytearray(self.bins["go"].read_bytes())
        o = se.sections(bytes(go))[".gopclntab"][0]
        go[o + 8:o + 16] = b"\0" * 8
        self.assertEqual(se.no_line_funcs(bytes(go[o:])), [])
        self.assertIn("lists no function", se.go_outside(bytes(go)))
        self.assertEqual(se.go_cgo(bytes(go)), "0-o")

    def test_only_the_linkers_own_markers_are_exempt(self):
        # #6563 item 3 (SGE-3): a .syso C function named "go:x" has no line table and is not exempt; only the
        # names cmd/link gives its own text markers are.
        asm = ('\t.text\n\t.globl "go:x"\n\t.type "go:x", @function\n"go:x":\n\tmovl $3, %eax\n\tret\n'
               '\t.globl my_c_func\n\t.type my_c_func, @function\nmy_c_func:\n\tcall "go:x"\n\tret\n')
        data = self.go_build(self.syso_pkg("gox", asm), pathlib.Path(self.tmp) / "go-gox").read_bytes()
        o, n = se.sections(data)[".gopclntab"][:2]
        self.assertEqual(se.no_line_funcs(data[o:o + n]), ["go:x", "my_c_func"])
        self.assertEqual(se.GO_MARKERS, ("go:textfipsstart", "go:textfipsend"))
        # The local toolchain's markers are a subset of the list (Go before 1.24 makes none).
        go = self.bins["go"].read_bytes()
        o, n = se.sections(go)[".gopclntab"][:2]
        self.assertLessEqual({name for _e, name, lines in se.pcln_funcs(go[o:o + n])[1] if not lines},
                             set(se.GO_MARKERS))

    def test_guest_and_initrd_package_files_are_held_to_their_bytes(self):
        # #6482 (Potency 7068815856 point 4): a guest-root file declared "package" must have bytes
        # guest-userland.sh recorded copying from that package; an initrd member, the main tree's md5sum
        # at its path with its package at the main tree's version.
        ld = "/usr/lib/agentos/images/codex/lib64/ld-linux-x86-64.so.2"
        md5 = hashlib.md5(self.bins["static"].read_bytes()).hexdigest()

        def staged():
            root, out, allow, config, _ = self.tree()
            (root / ld.lstrip("/")).parent.mkdir(parents=True)
            shutil.copy(self.bins["static"], root / ld.lstrip("/"))
            allow.write_text(allow.read_text() + "%s package libc6\n" % ld)
            st = out / "guest" / se.STATUS
            st.write_text(st.read_text() + STATUS % "libc6")
            (out / "guest" / se.COPIED).write_text("%s libc6\n" % md5)
            return root, out, allow, config

        root, out, allow, config = staged()
        self.assertEqual(self.check(root, out, allow, config), [])
        for name, edit, want in (
                ("other bytes", lambda: (out / "guest" / se.COPIED).write_text("%s libc6\n" % ("0" * 32)),
                 "are not a copy guest-userland.sh recorded from libc6"),
                ("other package", lambda: (out / "guest" / se.COPIED).write_text("%s libgcc-s1\n" % md5),
                 "are not a copy guest-userland.sh recorded from libc6"),
                ("no record", lambda: (out / "guest" / se.COPIED).unlink(),
                 "are not a copy guest-userland.sh recorded from libc6")):
            with self.subTest(name):
                root, out, allow, config = staged()
                edit()
                errs = self.check(root, out, allow, config)
                self.assertTrue(any(ld in e and want in e for e in errs), errs)
        # Initrd members, against the main tree's md5sums (ldconfig, libc-bin 1.0-1 in the fixture).
        root, out, allow, config, _ = self.tree()
        info = se.classify(self.bins["static"])
        entries = [(1, "/usr/sbin/ldconfig", "package", "libc-bin")]
        for name, status, member, want in (
                ("same", {"libc-bin": "1.0-1"}, info, None),
                ("other bytes", {"libc-bin": "1.0-1"}, {**info, "md5": "0" * 32}, "not the ones dpkg installed"),
                ("other version", {"libc-bin": "2.0-1"}, info, "at version 2.0-1 here and 1.0-1 in the main tree"),
                ("no version", {"libc-bin": None}, info, "at version None here")):
            with self.subTest(name):
                errs = se.refusals({"initrd:a/initrd": {"/usr/sbin/ldconfig": member}}, entries,
                                   se.context(out, config), {"initrd:a/initrd": status})
                self.assertEqual(errs, [] if want is None else errs[:1])
                self.assertTrue(want is None or want in errs[0], errs)

    def test_guest_shipped_records_each_input_against_the_binary(self):
        # SEL-6 linked: with SHIPPED_FOR, each owner is recorded against the binary's SHA-256, and --status
        # moves the lines to DIR/agentos.inputs; without it, nothing is recorded per file.
        t = pathlib.Path(tempfile.mkdtemp(prefix="agentos-static-elf-shipped-"))
        self.addCleanup(shutil.rmtree, t, True)
        base = t / "base"
        (base / "var/lib/dpkg/info").mkdir(parents=True)
        (base / "usr/lib").mkdir(parents=True)
        (base / "usr/lib/libx.a").write_text("x")
        (base / "usr/lib/os-release").write_text('ID=debian\nVERSION_ID="13"\n')
        (base / "var/lib/dpkg/info/libx-dev.list").write_text("/usr/lib/libx.a\n")
        (base / "var/lib/dpkg/status").write_text(
            STATUS.replace("Version", "Maintainer: t <t@example.invalid>\nDescription: t\nVersion") % "libx-dev")
        shipped = t / "shipped"
        env = {**os.environ, "GUEST_SHIPPED": str(shipped)}
        sh = str(IMG / "guest-shipped.sh")
        subprocess.run(["sh", sh, str(base), "/usr/lib/libx.a"], env=env, check=True)
        self.assertFalse(pathlib.Path(str(shipped) + ".inputs").exists())
        r = subprocess.run(["sh", sh, str(base), "/usr/lib/libx.a"], env={**env, "SHIPPED_FOR": str(t / "none")},
                           capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("SHIPPED_FOR", r.stderr)
        subprocess.run(["sh", sh, str(base), "/usr/lib/libx.a"], env={**env, "SHIPPED_FOR": str(self.bins["static"])},
                       check=True)
        subprocess.run(["sh", sh, "--status", str(base), str(t / "st")], env=env, check=True)
        sha = hashlib.sha256(self.bins["static"].read_bytes()).hexdigest()
        self.assertEqual((t / "st" / se.INPUTS).read_text(), "%s libx-dev\n" % sha)
        self.assertFalse(pathlib.Path(str(shipped) + ".inputs").exists())
        ctx = se.context(t / "none", t / "none.json")
        self.assertEqual(ctx["lists"]["guest"], {"inputs": {}, "status": None})


class ShippedTest(unittest.TestCase):
    def test_shipped_allow_reads_and_declares_the_control_files(self):
        entries = se.read_allow(se.ALLOW)
        self.assertTrue(entries)
        for path in se.REQUIRED:
            self.assertEqual(sum(se.matches(path, e[1]) for e in entries), 1, path)
        for bad in ("usr/bin/x go", "/usr/bin/x go extra", "/usr/bin/x linked", "/usr/bin/x static y",
                    "/usr/bin/x sha256 abc"):
            with self.subTest(bad):
                with tempfile.NamedTemporaryFile("w", suffix=".allow") as f:
                    f.write(bad + "\n")
                    f.flush()
                    with self.assertRaises(ValueError):
                        se.read_allow(f.name)

    def test_each_built_using_exclusion_is_a_linked_entry_this_check_reads(self):
        # #6481: vulncheck.py skips a package's Built-Using sources only where image/builtusing.exclude
        # names it against a "linked" entry; differential: that entry, as this check reads the shipped
        # allow-list, is "linked" with the same list, and the shipped exclusion is libcap-dev's alone.
        self.assertEqual(vulncheck.STATIC_ELF_ALLOW, se.ALLOW)
        linked = {g: a for _n, g, k, a in se.read_allow(se.ALLOW) if k == "linked"}
        excluded = vulncheck.excluded_packages()
        self.assertEqual({p for pkgs in excluded.values() for p in pkgs}, {"libcap-dev"})
        for name, pkgs in excluded.items():
            for pkg, glob in pkgs.items():
                self.assertEqual(linked.get(glob), name, (pkg, glob))

    def test_each_link_record_sets_shipped_for_on_the_bytes_it_ships(self):
        # SEL-6 linked: the three static link builds record their inputs against the binary they install.
        cam = (IMG / "camdecode.sh").read_text()
        self.assertIn('SHIPPED_FOR=$base$lib/agentos-camdecode sh "$HERE/guest-shipped.sh" "$base" $loaded\n', cam)
        self.assertIn('install -m 0755 "$base$lib/agentos-camdecode" "$ROOT/agentos-camdecode"', cam)
        cx = (ROOT / "guest/codex/build-rootfs.sh").read_text()
        self.assertIn('SHIPPED_FOR=$src/bwrap/bwrap sh "$here/../../image/guest-shipped.sh" "$base" $linked\n', cx)
        self.assertIn('install -m 0755 "$src/bwrap/bwrap" usr/bin/bwrap', cx)
        ls = (IMG / "llamaserver.sh").read_text()
        rec = ls.index('SHIPPED_FOR=$WORK/llama-server.stripped GUEST_SHIPPED=$linked sh "$HERE/guest-shipped.sh"')
        self.assertLess(ls.index('jail strip -o "$lib/llama-server.stripped"'), rec)
        self.assertLess(rec, ls.index('install -m 0755 "$WORK/llama-server.stripped" "$DEST/llama-server"'))

    def test_image_yml_runs_the_check_in_build_run_a(self):
        # SEL-8: the build job runs it on the built image, in matrix run a, beside the import sweep.
        wf = (ROOT / ".github/workflows/image.yml").read_text()
        i = wf.index("      - name: Static ELF files declared with what they link (image/static_elf.py)\n")
        step = wf[i:wf.index("\n      - name:", i + 1)]
        self.assertIn("        if: matrix.run == 'a'\n", step)
        self.assertIn('sudo python3 -I image/static_elf.py "$RUNNER_TEMP/out" "$v"', step)
        build = wf[wf.index("\n  build:\n"):wf.index("\n  reproduce:\n")]
        self.assertIn(step, build)
        self.assertLess(build.index("- name: Finish the image (image/finish.sh)"), build.index(step))
        # Image changes run the workflow, the allowlist and the script included (image/**).
        self.assertIn('      - "image/**"\n', wf.split("push:")[0])


if __name__ == "__main__":
    unittest.main()
