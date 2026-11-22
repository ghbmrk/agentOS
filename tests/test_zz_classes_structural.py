"""TOOL-classes-structural (#6441): every allow or exit list a gate tool reads is declared in tools/record_merge.py's
CLASSES, and the tool's reader refuses one that is not.

No requirement IDs: PLAN.md tooling, not SPEC.md behaviour. All data is synthetic.

The allow-class probe of #6418 matched file names, so a list with another name escaped the class rules. Each reader
now takes its list through `record_merge.listed` or `record_merge.read_list`, which fail closed (SystemExit naming the
file) on a file in no class. `walk` finds the lists from the tools' own sources, not from a hand-kept list: every
tracked file a tools/*.py module names by a string constant (or a `/` join of constants), kept when it is a non-code
file directly in tools/ or a file CLASSES puts in an allow or exit class.
"""
import ast
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import assumptions_ids  # noqa: E402
import doclint  # noqa: E402
import hostcheck  # noqa: E402
import netguardcheck  # noqa: E402
import record_merge  # noqa: E402
import risk_tier  # noqa: E402
import srclint  # noqa: E402
import trace  # noqa: E402
import trusted_base  # noqa: E402
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _nogit_bg import setUpModule, tearDownModule  # noqa: E402,F401
from test_list_readers import CASES  # noqa: E402

CODE = (".py", ".go", ".c", ".h", ".md", ".sh")
LISTS = ("list", "line")  # the allow and exit classes
PATHLIKE = re.compile(r"[\w.+-]+(?:/[\w.+-]+)*")  # a relative path: no space, no leading `/`
# Each tool loads its own copy of record_merge (by path, for `python3 -I`); a test that drops a CLASSES entry
# drops it from every copy.
COPIES = {id(m.record_merge): m.record_merge for m in (assumptions_ids, doclint, hostcheck, netguardcheck, risk_tier,
                                                         srclint, trace, trusted_base)} | {id(record_merge): record_merge}


def constants(tree):
    """Each string a module names: a constant, and each `/` join of two or more constants (`root / "tools" / "x"`)."""
    for n in ast.walk(tree):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            yield n.value
        elif isinstance(n, ast.BinOp) and isinstance(n.op, ast.Div):
            parts, x = [], n
            while isinstance(x, ast.BinOp) and isinstance(x.op, ast.Div) and isinstance(x.right, ast.Constant):
                parts.insert(0, x.right.value)
                x = x.left
            if len(parts) > 1 and all(isinstance(p, str) for p in parts):
                yield "/".join(parts)


def walk(root):
    """{module: {list file}}: each file of the tree a tools/*.py names (a path, or a bare name of a file directly in
    tools/) that is a non-code file directly in tools/ or in an allow or exit class of CLASSES. record_merge.py, which
    declares them, is left out. Files are found by stat, not by git, so no record or object store is read."""
    root = pathlib.Path(root)
    out = {}
    for py in sorted((root / "tools").glob("*.py")):
        if py.name == "record_merge.py":
            continue
        for v in constants(ast.parse(py.read_text())):
            if not PATHLIKE.fullmatch(v) or ".." in v.split("/"):
                continue  # a message or pattern, not a repository path
            top = "/" not in v and (root / "tools" / v).is_file()
            f = f"tools/{v}" if top else v if v and (root / v).is_file() else None
            if f and (record_merge.record_class(f) in LISTS or f.count("/") == 1 and f.startswith("tools/")
                      and not f.endswith(CODE)):
                out.setdefault(py.name, set()).add(f)
    return out


def uses_reader(source):
    """True when a module calls record_merge.listed or record_merge.read_list."""
    return any(isinstance(n, ast.Attribute) and n.attr in ("listed", "read_list") and isinstance(n.value, ast.Name)
               and n.value.id == "record_merge" for n in ast.walk(ast.parse(source)))


def undeclared(name):
    """Every record_merge copy's CLASSES less `name`."""
    patches = [mock.patch.dict(m.CLASSES) for m in COPIES.values()]
    for p in patches:
        p.start()
    for m in COPIES.values():
        del m.CLASSES[name]
    return patches


class ClassesStructuralTest(unittest.TestCase):

    def test_every_list_a_gate_tool_reads_is_declared(self):
        found = walk(ROOT)
        self.assertIn("tools/hostcheck_hw8.json", found.get("hostcheck.py", ()), "positive control: the walk sees reads")
        for module, lists in sorted(found.items()):
            for f in sorted(lists):
                with self.subTest(module=module, list=f):
                    self.assertIn(record_merge.record_class(f), LISTS, "a list a gate tool reads in no allow or exit class")
            with self.subTest(module=module):
                self.assertTrue(uses_reader((ROOT / "tools" / module).read_text()),
                                "a module reading a list does not take it through record_merge.listed or read_list")

    def test_the_walk_finds_a_new_list_under_any_name(self):
        # Mutation control: a new tool reading tools/permit.txt (no `allow` in its name) is found, and is in no class.
        with tempfile.TemporaryDirectory() as d:
            (pathlib.Path(d) / "tools").mkdir()
            (pathlib.Path(d) / "tools/exits.py").write_text(
                'import pathlib\nROOT = pathlib.Path(".")\nLIST = ROOT / "tools" / "permit.txt"\n'
                'print(LIST.read_text())\n')
            (pathlib.Path(d) / "tools/permit.txt").write_text("x\n")
            found = walk(d)
        self.assertEqual(found, {"exits.py": {"tools/permit.txt"}})
        self.assertIsNone(record_merge.record_class("tools/permit.txt"))
        self.assertFalse(uses_reader("LIST.read_text()"))

    def test_a_list_in_no_class_fails_closed_naming_it(self):
        with tempfile.TemporaryDirectory() as d:
            for name in ("tools/permit.txt", "tools/exits.list", "broker/core/core2.txt"):
                p = pathlib.Path(d, name)
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text("x\n")
                for reader in (record_merge.listed, record_merge.read_list):
                    with self.subTest(name=name, reader=reader.__name__), self.assertRaises(SystemExit) as e:
                        reader(p)
                    self.assertIn(str(p), str(e.exception.code))
            missing = pathlib.Path(d, "tools/gone.list")
            for name, reader in {"netguardcheck.load_allow": netguardcheck.load_allow,
                                 "srclint.load_allow": srclint.load_allow,
                                 "hostcheck.load_allow": hostcheck.load_allow,
                                 "trusted_base.read_list": lambda p: trusted_base.read_list(p.parents[1], f"{p.parent.name}/{p.name}"),
                                 "risk_tier.core_list": risk_tier.core_list.__wrapped__}.items():
                for p in (pathlib.Path(d, "tools/permit.txt"), missing):
                    with self.subTest(reader=name, file=p.name), self.assertRaises(SystemExit) as e:
                        reader(p)
                    self.assertIn("CLASSES", str(e.exception.code))

    def test_a_declared_list_reads_as_before(self):
        self.assertEqual(record_merge.read_list(ROOT / "tools/old_core.txt"), (ROOT / "tools/old_core.txt").read_text())
        for f in ("tools/old_core.txt", "/tmp/t/broker/core/core.txt", "tools/srclint_allow.txt", "x/allow.txt"):
            with self.subTest(f=f):
                self.assertIn(record_merge.listed(f), LISTS)
        # A declared path matches whole path parts only: a longer name ending in it is no copy of it.
        self.assertIsNone(record_merge.record_class("tools/my_old_core.txt"))
        self.assertIsNone(record_merge.record_class("xtools/old_core.txt"))

    def test_each_reader_refuses_its_list_once_undeclared(self):
        # The reader enforces CLASSES: drop a list's entry and every reader of it fails closed, naming CLASSES.
        for name, readers in CASES.items():
            if name not in record_merge.CLASSES:
                continue  # declared by a file-name pattern (*_allow.txt), dropped below
            text = (ROOT / name).read_bytes()
            for rname, reader in readers.items():
                with self.subTest(list=name, reader=rname), tempfile.TemporaryDirectory() as d:
                    tree = pathlib.Path(d)
                    (tree / name).parent.mkdir(parents=True, exist_ok=True)
                    (tree / name).write_bytes(text)
                    patches = undeclared(name)
                    try:
                        with self.assertRaises(SystemExit) as e:
                            reader(tree)
                    finally:
                        for p in patches:
                            p.stop()
                    self.assertIn("CLASSES", str(e.exception.code))
        with tempfile.TemporaryDirectory() as d:
            for name, reads in {"*_allow.txt": (lambda: netguardcheck.load_allow(ROOT / "tools/netguard_allow.txt"),
                                                lambda: srclint.load_allow(ROOT / "tools/srclint_allow.txt")),
                                "allow*.txt": (lambda: srclint.load_allow(pathlib.Path(d, "allow.txt")),)}.items():
                for n, reader in enumerate(reads):
                    patches = undeclared(name)
                    try:
                        with self.subTest(pattern=name, reader=n), self.assertRaises(SystemExit) as e:
                            reader()
                    finally:
                        for p in patches:
                            p.stop()
                    self.assertIn("CLASSES", str(e.exception.code))

    def test_the_cli_fails_on_an_undeclared_allow_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = pathlib.Path(d, "exits.list")
            p.write_text("")
            for tool in ("netguardcheck.py", "srclint.py"):
                with self.subTest(tool=tool):
                    r = subprocess.run([sys.executable, "-I", str(ROOT / "tools" / tool), "--allow", str(p)],
                                       capture_output=True, text=True)
                    self.assertNotEqual(r.returncode, 0)
                    self.assertIn(f"{p}: read as an allow or exit list", r.stderr)

    def test_a_list_class_is_never_merged_by_the_driver(self):
        # A declared exit list is merged by git as text: the driver leaves it to git and refuses it if called.
        self.assertNotIn("list", record_merge.DRIVEN)
        self.assertEqual(record_merge.merge(b"a\n", b"a\nb\n", b"a\nc\n", "tools/old_core.txt"), (None, False))
        with tempfile.TemporaryDirectory() as d:
            for side in ("o", "a", "b"):
                pathlib.Path(d, side).write_bytes(b"a\n")
            self.assertEqual(record_merge.main([str(pathlib.Path(d, s)) for s in ("o", "a", "b")] + ["tools/old_core.txt"]), 1)


if __name__ == "__main__":
    unittest.main()
