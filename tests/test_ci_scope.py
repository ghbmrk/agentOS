"""Tests for tools/ci_scope.py and its wiring into the workflows (CI-docs)."""
import ast
import re
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))
import ci_scope  # noqa: E402

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from test_workflows import lane_gate_problems  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"


def git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout


def ci_jobs():
    """ci.yml's jobs as {id: (job-level `if`, header lines, checks-job RECORDS env or None)}."""
    ci = (WORKFLOWS / "ci.yml").read_text()
    body = ci[ci.index("\njobs:\n") + len("\njobs:\n"):]
    jobs = {}
    for m in re.finditer(r"^  ([a-z][a-z-]*):\n((?:(?!  [a-z][a-z-]*:\n).*\n)*)", body, re.M):
        text = m.group(2)
        cond = re.search(r"^    if: \$\{\{ (.*) \}\}$", text, re.M)
        rec = re.search(r"^      RECORDS: \$\{\{ (.*) \}\}$", text, re.M)
        header = [l for l in text.splitlines() if re.match(r"^    [a-z-]+:", l)]
        jobs[m.group(1)] = (cond.group(1) if cond else None, header, rec.group(1) if rec else None)
    return jobs


def evaluate(expr, event, records):
    """Evaluate the small Actions expression subset ci.yml uses: !, &&, ||, ==, !=, parentheses,
    'strings', cancelled() and the two contexts github.event_name and needs.scope.outputs.records.
    && and || return an operand, as in Actions. Anything else raises."""
    ctx = {"github.event_name": event, "needs.scope.outputs.records": records}
    tokens = re.findall(r"\s*(&&|\|\||==|!=|!|\(|\)|'[^']*'|cancelled\(\)|[a-z_][a-z_.-]*)", expr)
    if "".join(tokens).replace(" ", "") != expr.replace(" ", ""):
        raise ValueError(f"unsupported expression: {expr}")
    py = []
    for i, t in enumerate(tokens):
        if t == "!" and tokens[i + 1:i + 2] != ["cancelled()"]:
            raise ValueError(f"! binds tighter in Actions than not in Python: {expr}")
        if t in ctx:
            py.append(repr(ctx[t]))
        elif t == "cancelled()":
            py.append("False")
        elif t in ("&&", "||", "!"):
            py.append({"&&": " and ", "||": " or ", "!": " not "}[t])
        elif t in ("==", "!=", "(", ")") or t.startswith("'"):
            py.append(t)
        else:
            raise ValueError(f"unknown name {t} in {expr}")
    return eval("".join(py), {"__builtins__": {}})  # noqa: S307 - tokens are whitelisted above


# The jobs a records-only pull request skips (CI-docs); a push to main runs them (CI-mainguard).
FILTERED = ("broker", "broker-race", "broker-checks", "machines", "hostcheck")


def ci_top_level(key):
    """The lines of ci.yml's top-level `key:` block, without the key line."""
    lines = (WORKFLOWS / "ci.yml").read_text().splitlines()
    start = lines.index(f"{key}:") + 1
    end = next(i for i in range(start, len(lines)) if lines[i] and not lines[i].startswith((" ", "#")))
    return [l for l in lines[start:end] if l.strip() and not l.lstrip().startswith("#")]


def ci_triggers():
    """The events ci.yml's `on:` block names."""
    return [l.strip().rstrip(":") for l in ci_top_level("on") if re.match(r"^  [a-z_]+:$", l)]


def records_run_tests(text=None):
    """The test names ci.yml's records-only step runs (CI-docs). Fails, rather than returning a
    partial list, unless exactly one records-only step runs `python -m unittest` on names."""
    lines = (text if text is not None else (WORKFLOWS / "ci.yml").read_text()).splitlines()
    steps = [i for i, l in enumerate(lines) if l.strip() == "if: env.RECORDS == 'true'"]
    runs = []
    for i in steps:
        indent = len(lines[i]) - len(lines[i].lstrip())
        end = next((j for j in range(i + 1, len(lines))
                    if lines[j].strip() and len(lines[j]) - len(lines[j].lstrip()) < indent), len(lines))
        key = next((j for j in range(i + 1, end) if lines[j].startswith(" " * indent + "run:")), None)
        if key is None:
            continue
        # The run value: inline, a block scalar, or a plain scalar continued on deeper lines.
        value = [lines[key].split(":", 1)[1]] + [l for l in lines[key + 1:end]
                                                 if len(l) - len(l.lstrip()) > indent or not l.strip()]
        words = " ".join(value).replace("\\", " ").split()
        if words[:1] in (["|"], [">"], ["|-"], [">-"]):
            words = words[1:]
        if words[:3] == ["python", "-m", "unittest"]:
            runs.append(words[3:])
    assert len(runs) == 1, f"want one records-only unittest step in ci.yml, found {len(runs)}"
    names = [w for w in runs[0] if not w.startswith("-")]
    assert names and all(re.fullmatch(r"tests(\.\w+)+", n) for n in names), runs[0]
    return names


# Path evaluation for the record-reader guard (CI-docs). A value is a list of the repo-relative
# paths an expression may name, each a list of components; _ANY in a component stands for any
# text, slashes included. Over-approximating is the fail-closed direction: a read the
# evaluator cannot pin down is assumed to reach any file below its known prefix.
_ANY = "\0"
_SAME = {"resolve", "absolute", "expanduser", "as_posix"}
_THROUGH = {"str", "sorted", "list", "set", "tuple", "reversed", "iter", "enumerate", "Path",
            "PurePath", "PosixPath", "PurePosixPath", "fspath", "abspath", "realpath",
            "normpath", "expanduser", "open", "glob", "iglob"}
_PATH_TYPES = {"Path", "PurePath", "PosixPath", "PurePosixPath", "open", "glob", "iglob"}


def _split(text, glob=False):
    """The components of a path string; a glob's wildcards become _ANY."""
    if glob:
        text = re.sub(r"\*+|\?|\[[^]]*\]", _ANY, text)
    return [c for c in text.split("/") if c not in ("", ".")]


def _join(base, parts):
    out = list(base)
    for c in parts:
        if c == "..":
            if not out:
                return None  # above the repo root
            if out[-1] != _ANY:
                out.pop()
        else:
            out.append(c)
    return out


def _parent(paths, n=1):
    out = []
    for p in paths:
        p = list(p)
        for _ in range(n):
            if not p:
                break
            if p[-1] != _ANY:
                p.pop()
        else:
            out.append(p)
    return out


class _Paths:
    """The paths each expression in one test module may name, with its bindings: names,
    attributes (self.x, cls.x) and function returns, gathered in every scope."""

    def __init__(self, tree):
        self.env = {}
        self.scope = {}
        self._scopes(tree, "", "")
        binds = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for t in targets:
                    if isinstance(t, ast.Tuple) and isinstance(node.value, ast.Tuple):
                        binds += list(zip(t.elts, node.value.elts))
                    else:
                        binds.append((t, node.value))
            elif isinstance(node, (ast.For, ast.comprehension)):
                binds.append((node.target, node.iter))
            elif isinstance(node, ast.withitem) and node.optional_vars is not None:
                binds.append((node.optional_vars, node.context_expr))
            elif isinstance(node, (ast.FunctionDef, ast.Lambda)):
                rets = [node.body] if isinstance(node, ast.Lambda) else \
                    [r.value for r in ast.walk(node) if isinstance(r, ast.Return) and r.value]
                binds += [("()" + getattr(node, "name", "<lambda>"), r) for r in rets]
        for _ in range(8):
            self.memo = {}
            before = {k: list(v) for k, v in self.env.items()}
            for target, value in binds:
                keys = [target] if isinstance(target, str) else self._keys(target)
                paths = self.eval(value) if keys else []
                for key in keys:
                    old = self.env.setdefault(key, [])
                    old += [p for p in paths if p not in old]
                    if len(old) > 64:
                        self.env[key] = [[_ANY]]
            if self.env == before:
                break
        self.memo = {}

    def _scopes(self, node, scope, cls):
        # Each node's scope, as a path of function and class scopes, and its class (whose
        # self.x and cls.x attributes it sees).
        self.scope[id(node)] = (scope, cls)
        for child in ast.iter_child_nodes(node):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                self._scopes(child, f"{scope}/{id(node)}", cls)
            elif isinstance(node, ast.ClassDef):
                self._scopes(child, f"{scope}/class:{node.name}", node.name)
            else:
                self._scopes(child, scope, cls)

    def _keys(self, node):
        """Where an assignment to `node` binds: a name in its scope (a class-body name is also
        the class's attribute), or self.x or cls.x on its class."""
        scope, cls = self.scope.get(id(node), ("", ""))
        if isinstance(node, ast.Name):
            in_body = scope.rsplit("/", 1)[-1].startswith("class:")
            return [(scope, node.id)] + ([(cls, "." + node.id)] if in_body else [])
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) \
                and node.value.id in ("self", "cls"):
            return [(cls, "." + node.attr)]
        return []

    def _lookup(self, node):
        """A name's bindings in the innermost scope that binds it, as Python resolves it: its
        own scope, then enclosing functions (not classes), then the module."""
        scope, cls = self.scope.get(id(node), ("", ""))
        if isinstance(node, ast.Attribute):
            return self.env.get((cls, "." + node.attr), []) if isinstance(node.value, ast.Name) \
                and node.value.id in ("self", "cls") else []
        own = True
        while True:
            if (own or not scope.rsplit("/", 1)[-1].startswith("class:")) and (scope, node.id) in self.env:
                return self.env[(scope, node.id)]
            if not scope:
                return []
            scope, own = scope.rsplit("/", 1)[0], False

    def text(self, node, glob=False):
        """Components of a string-valued part (a join argument, a glob pattern)."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return _split(node.value, glob)
        if isinstance(node, ast.JoinedStr):
            s = "".join(v.value if isinstance(v, ast.Constant) else _ANY for v in node.values)
            return _split(s, glob)
        return [_ANY]

    def relative(self, node):
        """A path string read relative to the working directory, which in CI is the repo root:
        a literal, an f-string or an os.path.join whose text starts with a relative literal."""
        if isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "join" and node.args:
            first, parts = node.args[0], [c for a in node.args for c in self.text(a)]
        else:
            first, parts = node, self.text(node)
        if isinstance(first, ast.JoinedStr) and first.values:
            first = first.values[0]
        if not (isinstance(first, ast.Constant) and isinstance(first.value, str)) \
                or first.value.startswith(("/", "~")):
            return []
        return self._joined([[]], parts)

    def eval(self, node):
        key = id(node)
        if key not in self.memo:
            self.memo[key] = []
            self.memo[key] = self._eval(node)
        return self.memo[key]

    def _eval(self, node):
        if isinstance(node, ast.Name):
            return [["tests", "test_x.py"]] if node.id == "__file__" else self._lookup(node)
        if isinstance(node, ast.Attribute):
            if node.attr == "parent":
                return _parent(self.eval(node.value))
            if node.attr in ("parents", "stem", "name", "suffix"):
                return []
            return self._lookup(node)
        if isinstance(node, ast.Subscript):
            if isinstance(node.value, ast.Attribute) and node.value.attr == "parents":
                n = node.slice.value + 1 if isinstance(node.slice, ast.Constant) \
                    and isinstance(node.slice.value, int) else 0
                base = self.eval(node.value.value)
                return _parent(base, n) if n else [[_ANY]] if base else []
            return []
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            # Lists of paths concatenate; a path string takes on text.
            paths = self.eval(node.right)
            if paths:
                return self.eval(node.left) + paths
            right = node.right.value if isinstance(node.right, ast.Constant) \
                and isinstance(node.right.value, str) else _ANY
            return [q for p in self.eval(node.left) for q in [_join([], _split("/".join(p) + right))]
                    if q is not None]
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
            return self._joined(self.eval(node.left), self.text(node.right))
        if isinstance(node, ast.JoinedStr) and node.values and isinstance(node.values[0], ast.FormattedValue):
            rest = ast.JoinedStr(values=node.values[1:])
            return [q for p in self.eval(node.values[0].value)
                    for q in [_join(p, self.text(rest))] if q is not None]
        if isinstance(node, ast.Call):
            return self._call(node)
        return []

    def _joined(self, base, parts):
        return [q for p in base for q in [_join(p, parts)] if q is not None]

    def _call(self, node):
        f, args = node.func, node.args
        name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
        base = self.eval(f.value) if isinstance(f, ast.Attribute) else []
        if base:  # a method of a path
            if name in ("joinpath", "glob", "rglob"):
                parts = [c for a in args for c in self.text(a, glob=name != "joinpath")]
                return self._joined(base, ([_ANY] if name == "rglob" else []) + parts)
            if name in ("with_name", "with_suffix", "with_stem", "iterdir"):
                return [(p if name == "iterdir" else p[:-1]) + [_ANY] for p in base]
            return base if name in _SAME else []
        if name in ("cwd", "getcwd") and not args:
            return [[]]
        if isinstance(f, ast.Name) or isinstance(f.value, ast.Name) and f.value.id in ("self", "cls"):
            if "()" + str(name) in self.env:  # a function of this module
                return self.env["()" + name]
        if not args:
            return []
        first = self.eval(args[0])
        if name == "join":
            return self._joined(first, [c for a in args[1:] for c in self.text(a)])
        if name == "dirname":
            return _parent(first)
        if name in ("listdir", "scandir", "walk"):
            return [p + [_ANY] for p in first]
        if name not in _THROUGH:
            return []
        if not first and name in _PATH_TYPES:
            first = self.relative(args[0])
        if name in ("glob", "iglob"):
            first = [[x for c in p for x in (_split(c, glob=True) or [c])] for p in first]
        return first


def _may_be_record(path):
    """Whether a path with _ANY parts may name a record file."""
    s = "/".join(path)
    if _ANY not in s:
        return ci_scope.is_record(s)
    rx = re.compile(".*".join(re.escape(x) for x in s.split(_ANY)), re.S)
    if any(rx.fullmatch(f) for f in ci_scope.RECORD_FILES):
        return True
    head, tail = s.split(_ANY)[0], s.split(_ANY)[-1]
    return any((head.startswith(d) or d.startswith(head)) and (tail.endswith(".md") or ".md".endswith(tail))
               for d in ci_scope.RECORD_DIRS)


def record_readers(source):
    """The unittest names a test module's source needs in the records run: each TestCase
    class, or the module itself for a read outside a class, whose code may name a record
    document's path below the repo root (from __file__ or the working directory). A path
    joined onto anything else, such as a temporary directory, is not a read."""
    tree = ast.parse(source)
    paths = _Paths(tree)
    found = set()

    def visit(node, owner):
        if isinstance(node, ast.ClassDef) and owner is None:
            owner = node.name
        if isinstance(node, ast.expr) and any(_may_be_record(p) for p in paths.eval(node)):
            found.add(owner)
            return
        for child in ast.iter_child_nodes(node):
            visit(child, owner)

    visit(tree, None)
    return found


class ScopeTest(unittest.TestCase):
    def test_record_documents_are_records(self):
        for p in ("BOARD.md", "LATER.md", "LEDGER.md", "DECISIONS.md", "METRICS.md", "TRACE.md",
                  "docs/MARK-QUEUE.md", "reviews/security/2026-10-12-pr1082.md", "reviews/l3/README.md",
                  "decisions/D-098.md", "briefs/DOC-6.md", "handoff/CURRENT.md"):
            self.assertEqual(ci_scope.scope_of([p]), ("records", None), p)

    def test_prose_no_test_reads_is_a_record(self):
        # REQ: CI-PATHS
        for p in ("README.md", "PLAN.md", "SPEC.md", "CLAUDE.md", "AGENTS.md", "docs/OPERATING.md",
                  "docs/LANES.md", "docs/BOARD-HISTORY.md", "docs/LATER-HISTORY.md", "docs/conv-3-triage.md", "docs/conv-5-uncovered.md",
                  "docs/development/trial-measurements.md", "docs/learning/new.md",
                  "docs/security/provider-worker-isolation.md", "docs/security/deep/x.md"):
            self.assertEqual(ci_scope.scope_of([p]), ("records", None), p)

    def test_prose_a_test_or_tool_reads_stays_full(self):
        # REQ: CI-PATHS
        # owners-guide.md: broker/hostchange's Go test reads it. The rest are not Markdown
        # prose, or sit outside the listed paths.
        for p in ("docs/owners-guide.md", "docs/security/provider-worker-surfaces.csv",
                  "docs/development/x.sh", "docs/new-top-level.md"):
            self.assertEqual(ci_scope.scope_of([p]), ("full", p), p)

    def test_the_records_pr_that_cost_97_minutes_is_records_only(self):
        # #1083's files.
        paths = ["BOARD.md", "LATER.md", "reviews/potency/2026-10-12-pr1082.md",
                 "reviews/security/2026-10-12-pr1082.md", "reviews/ux/2026-10-12-pr1082.md"]
        self.assertEqual(ci_scope.scope_of(paths)[0], "records")

    def test_anything_else_is_full(self):
        for p in ("docs/owners-guide.md", "broker/go.mod", "broker/vault/vault.go", "broker/vault/ASSUMPTIONS.md",
                  "tests/test_board.py", "tools/ci_scope.py", "tools/doclint.py",
                  ".github/workflows/ci.yml", ".github/workflows/scope.yml", ".claude/settings.json",
                  "image/build.sh", "image/README.md", "guest/openclaw/package-lock.json",
                  "reviews/combined/run.sh", "reviews/x.json", "briefs/x.txt", "decisions/x.py",
                  "spikes/S1S2-testkit/README.md", "BOARD.md.orig", "board.md", "reviews.md",
                  "reviews/../broker/x.md", "/reviews/x.md", "reviews//x.md", "./BOARD.md", "newdir/x.md"):
            self.assertEqual(ci_scope.scope_of([p]), ("full", p), p)

    def test_one_path_outside_the_set_makes_the_change_full(self):
        self.assertEqual(ci_scope.scope_of(["BOARD.md", "LATER.md", "broker/x/x.go", "reviews/a.md"]),
                         ("full", "broker/x/x.go"))

    def test_an_empty_change_is_full(self):
        self.assertEqual(ci_scope.scope_of([]), ("full", None))
        self.assertEqual(ci_scope.scope_of([""]), ("full", None))

    def test_every_tracked_file_outside_the_set_is_full(self):
        # The self-check: walk the repository, so a new file anywhere is classed by the rule,
        # and no record path is something a build, test or tool could run.
        files = git(ROOT, "ls-files", "-z").split("\0")
        records = [f for f in files if f and ci_scope.is_record(f)]
        self.assertIn("BOARD.md", records)
        for f in files:
            if f and not ci_scope.is_record(f):
                self.assertEqual(ci_scope.scope_of(["LATER.md", f])[0], "full", f)
        for f in records:
            self.assertTrue(f.endswith(".md"), f)
            self.assertFalse((ROOT / f).stat().st_mode & 0o111, f"{f} is executable")

    def test_git_diff_lists_a_moved_file_under_its_old_path(self):
        with tempfile.TemporaryDirectory() as d:
            git(d, "init", "-q", "-b", "main")
            git(d, "config", "user.email", "t@example.invalid")
            git(d, "config", "user.name", "t")
            (pathlib.Path(d) / "broker").mkdir()
            (pathlib.Path(d) / "broker" / "x.go").write_text("package x\n" * 20)
            (pathlib.Path(d) / "LATER.md").write_text("a\n")
            git(d, "add", "-A")
            git(d, "commit", "-qm", "base")
            (pathlib.Path(d) / "reviews").mkdir()
            git(d, "mv", "broker/x.go", "reviews/x.md")
            git(d, "commit", "-qm", "move")
            out = subprocess.run([sys.executable, str(ROOT / "tools" / "ci_scope.py"), "--git", "HEAD^", "HEAD"],
                                 cwd=d, capture_output=True, text=True, check=True)
            self.assertEqual(out.stdout, "full\n")
            (pathlib.Path(d) / "LATER.md").write_text("b\n")
            git(d, "commit", "-qam", "records")
            out = subprocess.run([sys.executable, str(ROOT / "tools" / "ci_scope.py"), "--git", "HEAD^", "HEAD"],
                                 cwd=d, capture_output=True, text=True, check=True)
            self.assertEqual(out.stdout, "records\n")
            # An unknown base is full, not an error.
            out = subprocess.run([sys.executable, str(ROOT / "tools" / "ci_scope.py"), "--git", "0" * 40, "HEAD"],
                                 cwd=d, capture_output=True, text=True, check=True)
            self.assertEqual(out.stdout, "full\n")

    def test_pull_request_scope_unchanged(self):
        # CIMG-b: on a pull request a records-only change still skips the code jobs and runs
        # the checks job's document steps; anything else, or a failed scope, runs them all.
        jobs = ci_jobs()
        # Every trigger but push is scoped, and a pull request is one of them.
        events = [e for e in ci_triggers() if e != "push"]
        self.assertIn("pull_request", events)
        for event in events:
            for job in FILTERED:
                cond = jobs[job][0]
                self.assertFalse(evaluate(cond, event, "true"), (job, event))
                self.assertTrue(evaluate(cond, event, ""), (job, event))
            self.assertTrue(evaluate(jobs["checks"][0], event, "true"))
            self.assertEqual(evaluate(jobs["checks"][2], event, "true"), "true", event)
            self.assertNotEqual(evaluate(jobs["checks"][2], event, ""), "true", event)
        # scope.yml still decides records-only from the PR's own diff.
        wf = (WORKFLOWS / "scope.yml").read_text()
        self.assertIn("pull_request) base=HEAD^1 head=HEAD^2 ;;", wf)


# ci.yml's settings above its jobs, pinned so no top-level env or defaults reaches the machines job.
CI_PREAMBLE_LINES = [
    'name: ci',
    'on:',
    '  push:',
    '    branches: [main]',
    '  pull_request:',
    '  merge_group:',
    '  workflow_dispatch:',
    'permissions:',
    '  contents: read',
    'concurrency:',
    '  group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.sha }}',
    "  cancel-in-progress: ${{ github.event_name == 'pull_request' }}",
    'env:',
    '  GOTOOLCHAIN: local',
]

# The machines job from its header through "Machine tests as root" (INFER-CI-2), pinned line by
# line as lane-gate.yml is: the job's keys (no continue-on-error, defaults or container), every
# step before the infer run (none writes GITHUB_ENV or GITHUB_PATH or edits the tools), and the
# step's own keys (no shell, if or continue-on-error) and run block. Any edit here is a reviewed
# change to this list.
MACHINES_LINES = [
    '  machines:',
    '    needs: scope',
    "    if: ${{ !cancelled() && (github.event_name == 'push' || needs.scope.outputs.records != 'true') }}",
    '    runs-on: ubuntu-latest',
    '    timeout-minutes: 60',
    '    steps:',
    '      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2',
    '        with:',
    "          fetch-depth: 2 # a PR's test merge and its base, for the fuzz peaks decision",
    '          persist-credentials: false',
    '      - uses: actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16  # v6.5.0',
    '        with:',
    '          go-version: "1.26.8" # = broker/go.mod\'s toolchain line; checked below',
    '          cache: false',
    '      - name: Go is the toolchain go.mod names',
    '        run: |',
    '          want=$(awk \'$1 == "toolchain" {print $2}\' "$GITHUB_WORKSPACE/broker/go.mod")',
    "          got=$(go version | awk '{print $3}')",
    '          [ -n "$want" ] && [ "$got" = "$want" ] || { echo "Go is $got; broker/go.mod names $want" >&2; exit 1; }',
    '      - name: Go build cache (CI-PATHS)',
    '        uses: actions/cache/restore@d4323d4df104b026a6aa633fdb11d772146be0bf  # v4.2.2',
    '        with:',
    '          path: /tmp/gocache',
    "          key: go-build-machines-${{ runner.os }}-${{ hashFiles('broker/go.mod', 'broker/go.sum') }}-${{ github.sha }}",
    "          restore-keys: go-build-machines-${{ runner.os }}-${{ hashFiles('broker/go.mod', 'broker/go.sum') }}-",
    '      - name: Install gVisor release-20260928.0 (checksum pinned)',
    '        run: |',
    '          B=https://storage.googleapis.com/gvisor/releases/release/20260928.0/x86_64',
    '          curl -fsSLo /tmp/gvisor.tar.bz2 "$B/gvisor.tar.bz2"',
    '          echo "c8d3a9fd4d4c4f5b8ff213caa4517356be128d18659ec4cde37828fe797f61a9725a602a846c81a8ed19c057a996515d31c081eba343ed4613a89951ba32ed59  /tmp/gvisor.tar.bz2" | sha512sum -c',
    '          mkdir /tmp/gv && tar -xjf /tmp/gvisor.tar.bz2 -C /tmp/gv',
    '          sudo install -m 0755 /tmp/gv/runsc /usr/local/bin/runsc',
    '          sudo mkdir -p /usr/local/bin/gvisor-bin',
    '          sudo install -m 0755 /tmp/gv/gvisor-bin/* /usr/local/bin/gvisor-bin/',
    '          runsc --version',
    '      - name: Project quotas (SR2-3)',
    '        run: |',
    '          sudo apt-get update -q',
    '          sudo apt-get install -yq xfsprogs acl',
    '          sudo modprobe quota_v2 2>/dev/null || {',
    '            sudo apt-get install -yq "linux-modules-extra-$(uname -r)" && sudo modprobe quota_v2',
    '          } || echo "::warning::no quota_v2 module: ext4 quota tests skip; XFS covers them"',
    '      - name: Machine tests as root',
    '        working-directory: broker',
    '        run: |',
    '          sudo mkdir /sys/fs/cgroup/agentos-ci',
    '          sudo setpriv --no-new-privs env "PATH=$PATH" GOTOOLCHAIN=local HOME=/root GOCACHE=/tmp/gocache \\',
    '            AGENTOS_RUNSC=/usr/local/bin/runsc AGENTOS_CGROUP_PARENT=/sys/fs/cgroup/agentos-ci \\',
    '            AGENTOS_REQUIRE_QUOTA=1 \\',
    '            go test -count=1 -v ./cgroup ./quota/... ./vm/... ./recovery ./cleanroom',
    '          sudo env "PATH=$PATH" GOTOOLCHAIN=local HOME=/root GOCACHE=/tmp/gocache \\',
    '            AGENTOS_CGROUP_PARENT=/sys/fs/cgroup/agentos-ci \\',
    '            go test -count=1 -v ./loop7',
    '          rc=0',
    '          sudo setpriv --no-new-privs env "PATH=$PATH" GOTOOLCHAIN=local HOME=/root GOCACHE=/tmp/gocache \\',
    '            AGENTOS_CGROUP_PARENT=/sys/fs/cgroup/agentos-ci \\',
    '            go test -count=1 -json ./infer/... > /tmp/infer-test.json || rc=$?',
    '          python3 -I ../tools/require_ran.py < /tmp/infer-test.json \\',
    '            github.com/ghbmrk/agentos/broker/infer/supervise.TestServiceRunsInInferenceLeaf \\',
    '            github.com/ghbmrk/agentos/broker/infer/supervise.TestServiceOOMStaysInLeaf || exit 1',
    '          [ "$rc" -eq 0 ]',
    '          sudo env "PATH=$PATH" GOTOOLCHAIN=local HOME=/root GOCACHE=/tmp/gocache \\',
    '            AGENTOS_CGROUP_PARENT=/sys/fs/cgroup/agentos-ci AGENTOS_REQUIRE_QUOTA=1 \\',
    "            go test -count=1 -v -run '^(TestTheFuzzLeafSitsBesideTheBrokerAndConfinesARound|TestAFuzzChildReachesOnlyItsOwnBoundedTree)$' ./cmd/agentosd",
    '          sudo env "PATH=$PATH" GOTOOLCHAIN=local HOME=/root GOCACHE=/tmp/gocache AGENTOS_REQUIRE_QUOTA=1 \\',
    "            go test -count=1 -v -run '^(TestMachinesGetTheStateFileSystemsQuota|TestMachineDiskWithQuotasAddsNoLine)$' ./cmd/agentosd",
]


def machines_problems(ci):
    """Why ci.yml's machines job could pass with the infer tests skipped or unrun; empty when pinned."""
    # YAML also breaks lines at CR, NEL, LS and PS; this check splits on LF only.
    breaks = sorted({c for c in ci if c in "\r\x85\u2028\u2029"})
    if breaks:
        return ["a line break other than LF: %r" % "".join(breaks)]
    if ci.count("\n  machines:\n") != 1:
        return ["no single machines job"]
    preamble = ci[:ci.index("\njobs:\n") + 1]
    # Below `jobs:` every line not indented four or more is a job's own key, plain and unique,
    # so no top-level key (defaults, env) and no quoted or repeated job id follows the jobs.
    keys = [l for l in ci[len(preamble) + len("jobs:\n"):].split("\n")
            if l.strip() and not l.lstrip().startswith("#") and not l.startswith("    ")]
    bad = [l for l in keys if not re.fullmatch(r"  [a-z][\w-]*:", l)]
    if bad:
        return ["not a plain job key below jobs: %r" % bad[0]]
    if len(set(keys)) != len(keys):
        return ["a job key repeats"]
    start = ci.index("\n  machines:\n") + 1
    nxt = re.compile(r"^  \S", re.M).search(ci, start + 1)
    job = ci[start:nxt.start() if nxt else len(ci)]
    lines = job.split("\n")
    code = [i for i, l in enumerate(lines) if l.strip() and not l.lstrip().startswith("#")]
    cut = code[len(MACHINES_LINES)] if len(code) > len(MACHINES_LINES) else len(lines)
    pinned = "\n".join(lines[:cut])
    problems = lane_gate_problems(preamble, CI_PREAMBLE_LINES) + lane_gate_problems(pinned, MACHINES_LINES)
    # The first line after the pinned step starts the next step: nothing more is added to this
    # step, and every later line sits inside a later step.
    rest = [lines[i] for i in code[len(MACHINES_LINES):]]
    if rest and not rest[0].startswith("      - "):
        problems.append("line after the infer step is %r, not the next step" % rest[0])
    problems += ["job-level line after the steps: %r" % l for l in rest if not l.startswith("      ")]
    # A comment or blank line after a trailing backslash ends the command there.
    for a, b in zip(MACHINES_LINES, MACHINES_LINES[1:]):
        if a.endswith("\\") and a + "\n" + b not in pinned:
            problems.append("%r is not followed directly by %r" % (a, b))
    return problems


class WiringTest(unittest.TestCase):
    """The workflows fail safe: only an exact 'true' from scope skips anything."""

    def test_scope_runs_the_base_copy_and_defaults_to_full(self):
        wf = (WORKFLOWS / "scope.yml").read_text()
        self.assertIn('git show "$base:tools/ci_scope.py"', wf)
        self.assertIn("scope=full", wf)
        self.assertIn('if [ "$scope" = records ]; then', wf)

    def test_ci_skips_only_on_records_and_checks_always_runs(self):
        ci = (WORKFLOWS / "ci.yml").read_text()
        self.assertIn("uses: ./.github/workflows/scope.yml", ci)
        cond = "    if: ${{ !cancelled() && (github.event_name == 'push' || needs.scope.outputs.records != 'true') }}\n"
        for job in ("broker-race", "broker-checks", "machines", "hostcheck"):
            self.assertIn(f"  {job}:\n    needs: scope\n" + cond, ci, job)
        # The required `broker` check gathers the split jobs (CI-SHARD) and skips with them.
        self.assertIn("    needs: [scope, broker-race, broker-checks]\n" + cond, ci)
        self.assertIn("  checks:\n    needs: scope\n    if: ${{ !cancelled() }}\n", ci)
        # The document checks never depend on scope.
        for step in ("python tools/trace.py && python tools/trace.py --check", "python tools/doclint.py",
                     "python tools/board.py check", "PRs must not change TRACE.md"):
            i = ci.index(step)
            step_text = ci[ci.rindex("- name:", 0, i):i]
            self.assertNotIn("RECORDS", step_text, step)
        self.assertIn("if: env.RECORDS == 'true'\n        run: python -m unittest tests.test_ci_scope tests.test_board", ci)

    def test_go_jobs_restore_a_build_cache_and_the_records_run_checks_prose(self):
        # REQ: CI-PATHS
        ci = (WORKFLOWS / "ci.yml").read_text()
        for job, key in (("broker-race", "broker-race"), ("broker-checks", "broker"), ("machines", "machines")):
            body = ci[ci.index(f"\n  {job}:\n") + 1:]
            nxt = re.search(r"^  [a-z][a-z-]*:\n", body[1:], re.M)
            body = body[:nxt.start() + 1] if nxt else body
            self.assertIn("uses: actions/cache/restore@", body, job)
            self.assertIn("uses: actions/cache/save@", body, job)
            self.assertNotIn("uses: actions/cache@", body, job)
            self.assertIn(f"key: go-build-{key}-", body, job)
            # Only a push to main writes the cache that PRs restore (D29).
            save = body[body.index("uses: actions/cache/save@"):]
            self.assertIn("github.event_name == 'push' && github.ref == 'refs/heads/main'",
                          body[:body.index("uses: actions/cache/save@")].rsplit("- name:", 1)[1], job)
            self.assertIn("go-build", save)
        for name in ("tests.test_risk_tier", "tests.test_product_name", "tests.test_specslice",
                     "tests.test_g1_scope.CheckTest", "tests.test_g1_scope.ListTest"):
            self.assertIn(name, records_run_tests())

    def test_records_run_includes_every_test_that_reads_a_record(self):
        # REQ: CI-PATHS
        # A records-only change can edit any record file, so every test whose outcome rests on
        # one must run on it; the records step skips discovery, so this is its only guard.
        listed = set(records_run_tests())
        missing = []
        for f in sorted((ROOT / "tests").glob("test_*.py")):
            for owner in record_readers(f.read_text()):
                name = f"tests.{f.stem}" + (f".{owner}" if owner else "")
                if name not in listed and f"tests.{f.stem}" not in listed:
                    missing.append(name)
        self.assertEqual(missing, [], "add these to ci.yml's records-only step")

    def test_a_spec_only_change_runs_the_spec_readers(self):
        # REQ: CI-PATHS
        # SPEC.md is a record, so a SPEC-only PR takes the records run, whose list the test
        # above holds to every reader.
        self.assertEqual(ci_scope.scope_of(["SPEC.md"]), ("records", None))

    def test_record_readers_tells_a_repo_read_from_a_temp_write(self):
        # The guard's controls: each shape of repo read is caught, at the right owner, and a
        # path it cannot pin down (J) counts as a read; temp-directory joins, non-records,
        # absolute paths and shadowed or unbound names (C) are not reads.
        src = """import glob, os, pathlib
ROOT = pathlib.Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
TOP = (ROOT / "SPEC.md").read_text()
class A:
    def t(self):
        (DOCS / "OPERATING.md").read_text()
class B:
    def t(self):
        open(os.path.join(ROOT, "reviews", "l3", "x.md"))
class D:
    def t(self):
        ROOT.joinpath("handoff", "CURRENT.md").read_text()
class E:
    def t(self):
        for p in sorted((ROOT / "briefs").glob("*.md")):
            p.read_text()
class F:
    def t(self):
        (pathlib.Path(__file__).parents[1] / "PLAN.md").read_text()
class G:
    def t(self):
        r = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        open(os.path.join(r, "LEDGER.md"))
class H:
    def t(self, n):
        open(f"{ROOT}/decisions/D-{n}.md")
class I:
    def t(self):
        open("SPEC.md")
class J:
    def t(self, name):
        (ROOT / name).read_text()
class K:
    def setUp(self):
        self.base = ROOT / "docs" / "security"
    def t(self):
        (self.base / "x.md").read_text()
class L:
    DIR = ROOT / "decisions"
    def t(self):
        (self.DIR / "D-1.md").read_text()
class M:
    def t(self):
        top = ROOT
        def inner():
            return (top / "BOARD.md").read_text()
        inner()
class C:
    def t(self, d):
        (pathlib.Path(d) / "SPEC.md").write_text("x")
        open(os.path.join(d, "SPEC.md"), "w")
        open(f"{d}/SPEC.md", "w")
        open("/etc/SPEC.md")
        (self.r / "CLAUDE.md").write_text("x")
        (ROOT / "docs" / "owners-guide.md").read_text()
        units = list((ROOT / "image").glob("*.service")) + list(ROOT.glob("tools/*.py"))
        text = (ROOT / "tools" / "x.py").read_text() + "x"
        glob.glob(os.path.join(d, "*.md"))
    def u(self, d):
        ROOT = pathlib.Path(d)
        (ROOT / "SPEC.md").write_text("x")
"""
        self.assertEqual(record_readers(src), {None, "A", "B", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M"})
        self.assertNotIn(None, record_readers(src.replace('TOP = (ROOT / "SPEC.md").read_text()\n', "")))

    def test_records_run_tests_reads_the_step_or_fails(self):
        # The list parse takes the run line in any YAML shape and fails rather than guess.
        step = "      - name: Docs\n        if: env.RECORDS == 'true'\n        run: {}\n"
        self.assertEqual(records_run_tests(step.format("python -m unittest tests.a tests.b -v")),
                         ["tests.a", "tests.b"])
        self.assertEqual(records_run_tests(step.format("|\n          python -m unittest tests.a \\\n"
                                                       "            tests.b")), ["tests.a", "tests.b"])
        self.assertEqual(records_run_tests(step.format("python -m unittest tests.a\n          tests.b")),
                         ["tests.a", "tests.b"])
        for bad in ("python -m unittest discover -s tests", "python -m unittest tests.a && rm x",
                    "make test", "python -m unittest -v"):
            with self.assertRaises(AssertionError, msg=bad):
                records_run_tests(step.format(bad))
        with self.assertRaises(AssertionError):
            records_run_tests(step.format("python -m unittest tests.a") * 2)

    def test_no_privileged_workflow_uses_a_cache(self):
        # REQ: CI-PATHS
        # pull_request_target and workflow_run run with a token that can write main's cache scope.
        for wf in sorted(WORKFLOWS.glob("*.yml")):
            text = wf.read_text()
            if re.search(r"^\s{0,4}(pull_request_target|workflow_run):", text, re.M):
                self.assertNotIn("actions/cache", text, wf.name)

    def test_assurance_skips_only_on_records(self):
        wf = (WORKFLOWS / "assurance.yml").read_text()
        self.assertIn("uses: ./.github/workflows/scope.yml", wf)
        self.assertEqual(wf.count("needs.scope.outputs.records != 'true'"), wf.count("\n    runs-on:"))

    def test_push_to_main_runs_every_job(self):
        # CIMG-a: whatever scope says (records-only, empty or full), a push runs every job,
        # and the checks job runs its full steps (RECORDS is not 'true').
        jobs = ci_jobs()
        self.assertEqual(set(jobs), {"scope", "checks", *FILTERED})
        for job, (cond, _, _) in jobs.items():
            if job == "scope":
                self.assertIsNone(cond)
                continue
            for records in ("true", "", "false"):
                self.assertTrue(evaluate(cond, "push", records), (job, records))
        rec = jobs["checks"][2]
        for records in ("true", "", "false"):
            self.assertNotEqual(evaluate(rec, "push", records), "true", records)

    def test_push_runs_only_on_main(self):
        # CIMG-a holds because push fires only for main: an unscoped push from any other
        # branch would run full CI where the scoped pull_request run is meant to.
        self.assertIn("push", ci_triggers())
        on = ci_top_level("on")
        i = on.index("  push:")
        self.assertEqual(on[i + 1], "    branches: [main]")
        self.assertFalse(on[i + 2:i + 3] and on[i + 2].startswith("    "), on[i + 2:i + 3])

    def test_default_token_is_read_only(self):
        # Every job inherits a read-only token unless it narrows its own grant.
        self.assertEqual(ci_top_level("permissions"), ["  contents: read"])

    def test_required_check_names_unchanged(self):
        # CIMG-c: branch protection matches checks by job id (no job sets `name:`) and the
        # race shards by their matrix values, so neither may change.
        jobs = ci_jobs()
        for job, (_, header, _) in jobs.items():
            self.assertFalse([l for l in header if l.startswith("    name:")], job)
        ci = (WORKFLOWS / "ci.yml").read_text()
        self.assertIn("        shard: [0, 1, 2]", ci)
        self.assertEqual(sorted(jobs), sorted(["scope", "checks", "broker", "broker-race",
                                               "broker-checks", "machines", "hostcheck"]))

    def test_evaluator_rejects_what_it_does_not_know(self):
        for expr in ("github.ref == 'refs/heads/main'", "always()", "1 == 1", "!github.event_name == 'push'"):
            with self.assertRaises(ValueError, msg=expr):
                evaluate(expr, "push", "true")

    def test_machines_job_lists_infer(self):
        # REQ: INFER-CI-1
        ci = (WORKFLOWS / "ci.yml").read_text()
        self.assertEqual(machines_problems(ci), [])
        self.assertTrue(machines_problems(ci.replace(" -json ./infer/... ", " -json ./cleanroom ")))

    def test_machines_step_uses_require_ran(self):
        # REQ: INFER-CI-2
        ci = (WORKFLOWS / "ci.yml").read_text()
        self.assertEqual(machines_problems(ci), [])
        step = "      - name: Machine tests as root\n        working-directory: broker\n        run: |\n"
        rc0 = "          rc=0\n"
        go = "          sudo setpriv --no-new-privs env \"PATH=$PATH\" GOTOOLCHAIN=local HOME=/root GOCACHE=/tmp/gocache \\\n            AGENTOS_CGROUP_PARENT"
        run = "          python3 -I ../tools/require_ran.py"
        rc = '          [ "$rc" -eq 0 ]\n'
        hostapd = "      - name: hostapd runs as its own user"
        job = "\n  machines:\n"
        # Each edit, as (old, new) applied once, stops the step failing on a skipped or missing test.
        edits = {
            "commented out": (run, "          # python3 ../tools/require_ran.py"),
            "branch around it": (run, "          if false; then\n" + run),
            "dropped": (run, "          true #"),
            "exit code ignored": (rc, ""),
            "set +e": (rc0, "          set +e\n" + rc0),
            "python3 overridden": (rc0, "          python3() { :; }\n" + rc0),
            "trap on exit": (rc0, "          trap 'exit 0' EXIT\n" + rc0),
            "here-doc swallows it": (rc0, "          cat >/dev/null <<'X'\n" + rc0 + "X\n"),
            "multi-line quote": (rc0, "          : '\n" + rc0),
            "uncalled function": (rc0, "          f() {\n" + rc0),
            "or-true group": (rc0, "          { true || {\n" + rc0),
            "comment after a continuation": (go, go.replace(" \\\n", " \\\n          #\n")),
            "step continue-on-error": (step, step.replace("        run: |", "        continue-on-error: true\n        run: |")),
            "step continue-on-error last": ("\n" + hostapd, "\n        continue-on-error: true\n" + hostapd),
            "step shell without -e": (step, step.replace("        run: |", "        shell: bash {0}\n        run: |")),
            "step if": (step, step.replace("        working", "        if: false\n        working")),
            "job continue-on-error": (job, job + "    continue-on-error: true\n"),
            "job defaults shell": (job, job + "    defaults:\n      run:\n        shell: bash {0}\n"),
            "job key after the steps": ("\n  hostcheck:", "\n    continue-on-error: true\n  hostcheck:"),
            "top-level defaults": ("\njobs:\n", "\ndefaults:\n  run:\n    shell: bash {0}\njobs:\n"),
            "top-level BASH_ENV": ("  GOTOOLCHAIN: local\n", "  GOTOOLCHAIN: local\n  BASH_ENV: /tmp/x\n"),
            "an earlier step writes GITHUB_ENV": ("          runsc --version\n", "          runsc --version\n          echo BASH_ENV=/tmp/x >> \"$GITHUB_ENV\"\n"),
            "a carriage return": ("          rc=0\n", "          rc=0\r          true\n"),
            "trailing top-level defaults": (ci, ci + "defaults:\n  run:\n    shell: bash {0}\n"),
            "trailing top-level env": (ci, ci + "env:\n  BASH_ENV: /tmp/x\n"),
            "top-level defaults after NEL": (ci, ci.rstrip("\n") + "\x85" + "defaults:\n  run:\n    shell: bash {0}\n"),
            "top-level defaults after LS": (ci, ci.rstrip("\n") + "\u2028" + "defaults:\n  run:\n    shell: bash {0}\n"),
            "top-level defaults after PS": (ci, ci.rstrip("\n") + "\u2029" + "defaults:\n  run:\n    shell: bash {0}\n"),
            "quoted duplicate machines key": ("\n  hostcheck:", "\n  'machines':\n    runs-on: ubuntu-latest\n  hostcheck:"),
            "a second machines job": ("\n  hostcheck:", "\n  machines:\n    runs-on: ubuntu-latest\n  hostcheck:"),
            "isolation flag dropped": (run, "          python3 ../tools/require_ran.py"),
            "exit on failure dropped": ("StaysInLeaf || exit 1\n", "StaysInLeaf\n"),
            "infer run moved off the infer tests": (" -json ./infer/... ", " -json ./cleanroom "),
        }
        for what, (old, new) in edits.items():
            with self.subTest(what):
                self.assertIn(old, ci)
                self.assertTrue(machines_problems(ci.replace(old, new, 1)))
        sup = (ROOT / "broker" / "infer" / "supervise" / "supervise_test.go").read_text()
        for name in ("TestServiceRunsInInferenceLeaf", "TestServiceOOMStaysInLeaf"):
            self.assertRegex(sup, rf"(?m)^func {name}\(t \*testing\.T\)", name)


class FuzzStepTest(unittest.TestCase):
    """The short fuzz step in broker-checks names every broker target, and each one exists."""

    BROKER_TARGETS = ("grants:FuzzApprovals", "localsrv:FuzzSessions", "netguard:FuzzSourcesRead",
                      "netguard:FuzzGatewayPolicy", "netguard:FuzzCheck", "vault:FuzzSlots")

    def fuzz_targets(self):
        ci = (WORKFLOWS / "ci.yml").read_text()
        loops = re.findall(r"^\s*for t in (.+); do\n.*\n\s*python3 \.\./tools/fuzzrun\.py ", ci, re.M)
        self.assertEqual(len(loops), 1, loops)
        # pkg:Target[:calibrate]; the calibrate field is the first chunk's exec count.
        entries = [e.split(":") for e in loops[0].split()]
        for e in entries:
            self.assertIn(len(e), (2, 3), e)
            if len(e) == 3:
                self.assertRegex(e[2], r"^[1-9][0-9]*$", e)
        return [f"{e[0]}:{e[1]}" for e in entries]

    def test_fuzz_step_lists_broker_targets(self):
        # REQ: FUZZ-broker-ci-1
        targets = self.fuzz_targets()
        for t in self.BROKER_TARGETS:
            self.assertIn(t, targets)
        self.assertEqual(len(targets), len(set(targets)), targets)

    def test_fuzz_step_targets_exist(self):
        # REQ: FUZZ-broker-ci-2
        for t in self.fuzz_targets():
            pkg, _, name = t.partition(":")
            self.assertRegex(name, r"^Fuzz\w+$", t)
            pkgdir = ROOT / "broker" / pkg
            self.assertTrue(pkgdir.is_dir(), t)
            found = any(re.search(rf"^func {name}\(f \*testing\.F\)", f.read_text(), re.M)
                        for f in pkgdir.glob("*_test.go"))
            self.assertTrue(found, f"{t}: no func {name}( in broker/{pkg}/*_test.go")


if __name__ == "__main__":
    unittest.main()
