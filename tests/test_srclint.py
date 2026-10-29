"""Tests for tools/srclint.py: every file under broker/ that a build could compile is plain Go,
so each boundary lint holds for the files it parses (REV-CHK-src).

REQ: KRN-2
All paths and code are synthetic.
"""
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import srclint  # noqa: E402

WORKFLOW = "jobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: go test {flags} ./...\n"

# Each shape the check must refuse: (path under broker/, bytes, words its finding must carry).
SHAPES = [
    ("broker/drv/trap_amd64.s", b"TEXT \xc2\xb7open(SB),0,$0\n\tRET\n", ".s file"),
    ("broker/drv/TRAP.S", b"nop\n", ".S file"),
    ("broker/drv/rsrc_amd64.syso", b"\x00\x01", ".syso file"),
    ("broker/drv/shim.c", b"int x;\n", ".c file"),
    ("broker/drv/shim.h", b"int x;\n", ".h file"),
    ("broker/drv/shim.cc", b"int x;\n", ".cc file"),
    ("broker/drv/cgo.go", b'package drv\n\nimport "C"\n', 'imports "C"'),
    ("broker/drv/cgogroup.go", b'package drv\n\nimport (\n\t"os"\n\t_ "C"\n)\n\nvar _ = os.Args\n',
     'imports "C"'),
    ("broker/drv/cgoescape.go", b'package drv\n\nimport "\\x43"\n', 'imports "C"'),
    ("broker/drv/cgoraw.go", b"package drv\n\nimport `C`\n", 'imports "C"'),
    # #3818: the #cgo line hides behind a C line comment continued by a backslash.
    ("broker/drv/cgocont.go",
     b"package drv\n\n/*\n// a harmless note \\\n#cgo LDFLAGS: -lsock\n*/\nimport \"unsafe\"\n\nvar _ unsafe.Pointer\n",
     "#cgo line"),
    ("broker/drv/link.go",
     b'package drv\n\nimport _ "unsafe"\n\n//go:linkname dial net.dial\nfunc dial()\n', "go:linkname"),
    ("broker/drv/linkblock.go", b"package drv\n\n/* go:linkname x y.z */\nfunc x()\n", "go:linkname"),
    ("broker/drv/dyn.go", b"package drv\n\n//go:cgo_import_dynamic f f \"libc.so\"\n", "go:cgo_import_dynamic"),
    # #3754: a wrapper behind a tag no build sets.
    ("broker/drv/tagged.go", b'//go:build sometag\n\npackage drv\n\nimport _ "os/exec"\n', "sometag"),
    ("broker/drv/plus.go", b"// +build linux,othertag\n\npackage drv\n", "othertag"),
    ("broker/drv/negated.go", b"//go:build !(linux && hidden)\n\npackage drv\n", "hidden"),
    ("broker/drv/exec_windows.go", b"package drv\n", "windows"),
    ("broker/drv/exec_linux_riscv64.go", b"package drv\n", "riscv64"),
    ("broker/drv/broken.go", b"package drv\n\n/* never closed\n", "cannot parse"),
    ("broker/drv/latin1.go", b"package drv\n\n// caf\xe9\n", "cannot parse"),
]

# Plain Go, or files no non-test build compiles: none may fail.
CLEAN = [
    ("broker/ok/ok.go", b'//go:build linux && (amd64 || !amd64) && !race\n\npackage ok\n\nimport "os"\n\n'
                        b'// The C library is not used; "C" here is text.\nvar s = "import \\"C\\" go:linkname #cgo"\n'
                        b"var _ = os.Args\n"),
    ("broker/ok/ok_linux_amd64.go", b"//go:build go1.26 && unix && gc\n\npackage ok\n"),
    ("broker/ok/gen.go", b"//go:build ignore\n\npackage main\n"),
    ("broker/ok/pkgtag.go", b"//go:build newtag\n\npackage ok\n"),
    ("broker/ok/ok_test.go", b'package ok\n\nimport "C"\n'),
    ("broker/ok/_scratch.s", b"nop\n"),
    ("broker/ok/.hidden.c", b"int x;\n"),
    ("broker/ok/notes.md", b"#cgo LDFLAGS\n"),
    ("broker/ok/testdata/drv/trap_amd64.s", b"nop\n"),
    ("broker/vendor/x/y/asm_amd64.s", b"nop\n"),
    ("broker/third_party/z/z.c", b"int x;\n"),
]


class Tree:
    def __init__(self, flags="-race -tags newtag,other"):
        self.td = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.td.name)
        self.allow = self.root / "allow.txt"
        self.workflow(flags)
        for rel, body in CLEAN:
            self.put(rel, body)

    def workflow(self, flags):
        self.put(".github/workflows/ci.yml", WORKFLOW.format(flags=flags).encode())

    def put(self, rel, body):
        p = self.root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(body)

    def check(self):
        return srclint.check(self.root, self.allow)

    def cleanup(self):
        self.td.cleanup()


class SrcLintTest(unittest.TestCase):
    def setUp(self):
        self.t = Tree()
        self.addCleanup(self.t.cleanup)

    def test_clean_synthetic_tree_passes(self):
        # Positive control for every subtest below.
        self.assertEqual(self.t.check(), [])

    def test_refuses_each_shape(self):
        for rel, body, words in SHAPES:
            with self.subTest(rel=rel):
                t = Tree()
                self.addCleanup(t.cleanup)
                t.put(rel, body)
                problems = t.check()
                self.assertTrue(problems, f"{rel} passed")
                self.assertTrue(all(p.startswith(rel + ": ") for p in problems), problems)
                self.assertTrue(any(words in p for p in problems), problems)

    def test_allow_line_excuses_its_file_only(self):
        self.t.put("broker/drv/cgo.go", b'package drv\n\nimport "C"\n')
        self.t.put("broker/drv/trap_amd64.s", b"nop\n")
        self.t.allow.write_text("broker/drv/cgo.go the reviewed decoder\n")
        self.assertEqual(self.t.check(), ["broker/drv/trap_amd64.s: is a .s file the go tool compiles or links, not Go"])

    def test_stale_allow_line_fails(self):
        self.t.allow.write_text("# header\nbroker/ok/ok.go was cgo once\nbroker/gone.go never existed\n")
        self.assertEqual(self.t.check(), [
            "broker/gone.go: allow-listed but plain Go or gone (stale entry)",
            "broker/ok/ok.go: allow-listed but plain Go or gone (stale entry)",
        ])

    def test_allow_line_needs_a_reason_and_no_hidden_break(self):
        for text in ("broker/drv/cgo.go\n", "broker/drv/cgo.go ok\rbroker/x.go ok\n",
                     "broker/drv/cgo.go ok\u2028broker/x.go ok\n", "broker/drv/cgo.go ok\x85\n",
                     "broker/drv/cgo.go a\nbroker/drv/cgo.go b\n"):
            with self.subTest(text=text):
                self.t.allow.write_text(text)
                with self.assertRaises(SystemExit):
                    self.t.check()

    def test_tag_set_comes_from_the_builds(self):
        self.assertEqual(self.t.check(), [])
        self.t.workflow("-race")
        self.assertEqual(self.t.check(), [
            "broker/ok/pkgtag.go: build constraint names newtag, which no workflow or image build sets"])
        # The image's build scripts count as builds; a comment and a Markdown file do not.
        self.t.put("image/notes.md", b"go build -tags newtag\n")
        self.t.put("image/build.sh", b"# go build -tags newtag\n")
        self.assertEqual(len(self.t.check()), 1)
        self.t.put("image/build.sh", b"#!/bin/sh\nGOFLAGS=-tags=newtag go build ./...\n")
        self.assertEqual(self.t.check(), [])
        # `--no-tags` is not a tag flag.
        self.t.put("image/build.sh", b"git fetch --no-tags newtag\n")
        self.assertEqual(len(self.t.check()), 1)

    def test_platform_tags_come_from_the_builds(self):
        tags = srclint.build_tags(self.t.root)
        self.assertTrue({"linux", "amd64", "unix", "race", "newtag", "other", "gc", "ignore"} <= tags, tags)
        self.assertNotIn("cgo", tags)
        self.assertNotIn("arm64", tags)
        self.t.put("image/arm.sh", b"CGO_ENABLED=1 GOOS=linux GOARCH=arm64 go build\n")
        self.assertTrue({"arm64", "cgo"} <= srclint.build_tags(self.t.root))

    def test_main_is_clean(self):
        self.assertEqual(srclint.check(ROOT, ROOT / "tools" / "srclint_allow.txt"), [])
        r = subprocess.run([sys.executable, str(ROOT / "tools" / "srclint.py")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_cli_names_the_path_and_fails(self):
        self.t.put("broker/drv/trap_amd64.s", b"nop\n")
        r = subprocess.run([sys.executable, str(ROOT / "tools" / "srclint.py"), "--root", str(self.t.root),
                            "--allow", str(self.t.allow)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("srclint: broker/drv/trap_amd64.s:", r.stderr)


if __name__ == "__main__":
    unittest.main()
