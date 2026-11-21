"""No Python file in the repository, outside the record directories, binds one module-level name twice.

A second top-level binding silently replaces the first for every function that reads the name at
call time. Two PRs that each add a constant under one name both pass on their own, and merged, one
of them reads the other's value: #6403 and #6378 each added IMPORT_SPEC to tools/mutgate.py, and
the merge crashed `mutgate claimed` on any grouped Go import. pyflakes' redefinition check (F811)
covers only unused functions, classes and imports, so it misses that shape.

A binding here is a top-level def, class, plain or annotated assignment to a bare name (tuple
targets included), or import. `import a.b` beside `import a.c` binds `a` to one package and is not
a repeat; the same module imported twice is. Bindings inside a top-level if, try, for or with are
conditional by design and not read, nor is an attribute or item assignment (`m.X = 1`). The walk
skips .git and the record directories, so scripts kept as evidence under reviews/ are not read.
"""
import ast
import os
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import ci_scope  # noqa: E402


def bindings(tree):
    """[(name, line, module)] for each top-level binding of tree; module is the dotted path of a
    plain `import a.b` (which binds a), else None."""
    out = []
    for s in tree.body:
        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.append((s.name, s.lineno, None))
        elif isinstance(s, (ast.Assign, ast.AnnAssign)):
            targets, todo = [], list(s.targets if isinstance(s, ast.Assign) else [s.target])
            while todo:
                t = todo.pop()
                if isinstance(t, (ast.Tuple, ast.List)):
                    todo.extend(t.elts)
                elif isinstance(t, ast.Starred):
                    todo.append(t.value)
                elif isinstance(t, ast.Name):
                    out.append((t.id, s.lineno, None))
        elif isinstance(s, ast.Import):
            out.extend((a.asname, s.lineno, None) if a.asname else (a.name.split(".")[0], s.lineno, a.name)
                       for a in s.names)
        elif isinstance(s, ast.ImportFrom):
            out.extend((a.asname or a.name, s.lineno, None) for a in s.names if a.name != "*")
    return out


def repeats(source, path="<src>"):
    """["name: lines"] for each name source binds more than once at module level."""
    seen = {}
    for name, line, module in bindings(ast.parse(source, path)):
        seen.setdefault(name, []).append((line, module))
    out = []
    for name, rows in seen.items():
        modules = [m for _, m in rows]
        if len(rows) > 1 and (None in modules or len(set(modules)) < len(modules)):
            out.append(f"{name}: lines {', '.join(str(line) for line, _ in rows)}")
    return out


class Repeats(unittest.TestCase):
    def test_each_shape(self):
        for name, src, want in (
                ("two constants", "A = 1\n\ndef f():\n    return A\n\nA = 2\n", ["A: lines 1, 6"]),
                ("a def then a constant", "def f(): pass\nf = 1\n", ["f: lines 1, 2"]),
                ("an annotated assignment", "A: int = 1\nA = 2\n", ["A: lines 1, 2"]),
                ("a tuple target", "A, (B, *C) = 1, (2, 3)\nC = 4\n", ["C: lines 1, 2"]),
                ("an import then a def", "import os\ndef os(): pass\n", ["os: lines 1, 2"]),
                ("one module twice", "import os.path\nimport os.path\n", ["os: lines 1, 2"]),
                ("a from-import twice", "from a import b\nfrom c import d as b\n", ["b: lines 1, 2"]),
                ("submodules of one package", "import urllib.request\nimport urllib.error\n", []),
                ("an attribute or an item", "import m\nm.X = 1\nm.p[:0] = []\n", []),
                ("a conditional binding", "try:\n    import a\nexcept ImportError:\n    a = None\n", []),
                ("a nested binding", "A = 1\ndef f():\n    A = 2\n    return A\n", [])):
            with self.subTest(name):
                self.assertEqual(repeats(src), want)

    def test_no_python_file_repeats_a_name(self):
        # A walk that never enters .git or a record directory (tools/ci_scope.RECORD_DIRS), so the
        # module reads no record (tests/records_audit.py); git ls-files would read .git.
        skip = {".git"} | {d.rstrip("/") for d in ci_scope.RECORD_DIRS}
        files = []
        for top, dirs, names in os.walk(ROOT):
            rel = pathlib.Path(top).relative_to(ROOT)
            dirs[:] = sorted(d for d in dirs if (rel / d).as_posix() not in skip)
            files += [(rel / n).as_posix() for n in sorted(names) if n.endswith(".py")]
        self.assertIn("tools/mutgate.py", files)
        found = [f"{f}: {r}" for f in files for r in repeats((ROOT / f).read_text(), f)]
        self.assertEqual(found, [], "a module-level name is bound twice; rename one")


if __name__ == "__main__":
    unittest.main()
