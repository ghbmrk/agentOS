"""VULN-static-elf part b (#5885): image/static_elf.py lists every ELF file of the built image that carries
a C library or C++ runtime in its own bytes (static, or dynamic with a static C++ runtime) and holds each
to one declaration in image/static_elf.allow, whose kind says where tools/vulncheck.py image scans what
it links: a Go binary with cgo off links none; a "linked" file's link inputs were recorded by package
against its SHA-256 (image/guest-shipped.sh SHIPPED_FOR) and each is in the status the scan reads; a
"package" file is a Debian package's (whose Built-Using sources the scan also queries); a "bundled" file
is a pinned download a vulncheck.json record names."""
# REQ: EVL-5
import hashlib
import importlib.util
import os
import pathlib
import platform
import re
import shutil
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

C = "int main(void) { return 0; }\n"
CXX = ('#include <stdexcept>\nint main(int c, char **v) { try { if (c > 5) throw std::runtime_error(v[0]); }\n'
       ' catch (std::exception &) { return 1; } return 0; }\n')
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
            "go": build(d, "go", GO, "go", "build", "-trimpath", "-ldflags=-s -w", env={"CGO_ENABLED": "0"}),
            "cgo": build(d, "cgo", CGO, "go", "build", "-trimpath",
                         "-ldflags=-s -w -linkmode=external -extldflags=-static", env={"CGO_ENABLED": "1"}),
        }
        subprocess.run(["gcc", "-c", "-x", "c", "-", "-o", str(pathlib.Path(d) / "obj.o")], input=C, text=True, check=True)
        cls.bins["object"] = pathlib.Path(d) / "obj.o"
        # Go binaries with no build info (esbuild's release has none; Bazel's records no cgo setting).
        for b in ("go", "cgo"):
            subprocess.run(["objcopy", "-R", ".go.buildinfo", str(cls.bins[b]), str(cls.bins[b]) + "-noinfo"], check=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, True)

    def test_static_files_and_static_cxx_runtimes_are_listed(self):
        # SEL-5: no PT_INTERP and no DT_NEEDED is static; a dynamic file needing no libstdc++ but carrying
        # the C++ runtime's code (stripped, so by its marks) is listed too; a dynamic C or C++ program and a
        # relocatable object are not.
        got = {k: se.classify(p) for k, p in self.bins.items()}
        self.assertEqual({k for k, v in got.items() if v}, {"static", "cxx-static-runtime", "go", "cgo"})
        self.assertEqual(got["static"]["why"], "static")
        self.assertEqual(got["cxx-static-runtime"]["why"], "c++ runtime")
        self.assertEqual(got["static"]["sha256"], hashlib.sha256(self.bins["static"].read_bytes()).hexdigest())
        # Go build info is read from the file: cgo off says 0, cgo on says 1, a C program is no Go binary.
        self.assertEqual((got["go"]["go"], got["cgo"]["go"], got["static"]["go"]), ("0", "1", None))
        # With no build info, cgo is read from runtime/cgo's own C code in the file.
        self.assertEqual(se.go_cgo(pathlib.Path(str(self.bins["go"]) + "-noinfo").read_bytes()), "none")
        self.assertEqual(se.go_cgo(pathlib.Path(str(self.bins["cgo"]) + "-noinfo").read_bytes()), "cgo")
        self.assertNotIn(se.CGO_MARK, self.bins["go"].read_bytes())
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
                 "/usr/lib/agentos/gvisor-bin/prewarmer": "static", "/usr/bin/dyn": "dynamic"}
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
                   "/usr/lib/agentos/gvisor-bin/prewarmer sha256 " + sha["static"].upper()]
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
            ("sha256", lambda: allow.write_text(allow.read_text().replace(
                "/usr/lib/agentos/runsc go", "/usr/lib/agentos/runsc sha256 " + "a" * 64)), "not the reviewed " + "a" * 64),
            # go on a Go binary with no build info and cgo code
            ("cgo, no info", lambda: shutil.copy(str(self.bins["cgo"]) + "-noinfo", root / "usr/lib/agentos/runsc"),
             "a Go binary with cgo (Go, no cgo setting, cgo code)"),
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
            self.assertEqual(sum(__import__("fnmatch").fnmatchcase(path, e[1]) for e in entries), 1, path)
        for bad in ("usr/bin/x go", "/usr/bin/x go extra", "/usr/bin/x linked", "/usr/bin/x static y",
                    "/usr/bin/x sha256 abc"):
            with self.subTest(bad):
                with tempfile.NamedTemporaryFile("w", suffix=".allow") as f:
                    f.write(bad + "\n")
                    f.flush()
                    with self.assertRaises(ValueError):
                        se.read_allow(f.name)

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
