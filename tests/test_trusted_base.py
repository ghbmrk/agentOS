"""KRN-2m (#2849): tools/trusted_base.py measures the trusted base and gates its growth;
KRN-2cap (#2935): it also holds the trusted core to a shrink-only line and import budget.

SPEC KRN-2: "The trusted base's size is measured on every PR (lines, dependencies, exposed
parsers) and shown in the PR; growth needs a stated reason ... It is a measure, not a cap."
Local cases KRN-2m-a..f are in the brief on #2849. The synthetic-tree tests run `go list`
(any Go toolchain new enough for a `go 1.22` module); the repository test runs it over the
real broker, so a package that enters a trusted process unclassified fails here too.
"""
# REQ: KRN-2
import contextlib
import io
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import trusted_base as tb  # noqa: E402

OWN = "github.com/ghbmrk/agentos/broker"


def write(root, rel, text):
    p = pathlib.Path(root) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)


REGISTRY = """\
parser {own}/cmd/a -- entry
inert  {own}/calc -- arithmetic
parser example.com/dec -- decodes frames
parser encoding/json -- JSON
""".format(own=OWN)


def tree(root, extra_own=0, use_dec=True, registry=REGISTRY, mains=("a",), calc_dec=False):
    """A minimal broker tree: cmd/<main> -> calc (own) and example.com/dec (vendored).
    With calc_dec, calc itself links dec."""
    write(root, "broker/go.mod", f"module {OWN}\n\ngo 1.22\n\nrequire example.com/dec v1.0.0\n")
    write(root, "broker/vendor/modules.txt", "# example.com/dec v1.0.0\n## explicit; go 1.22\nexample.com/dec\n")
    write(root, "broker/vendor/example.com/dec/dec.go", "package dec\n\nfunc Decode(b []byte) int { return len(b) }\n")
    write(root, "broker/core/core.txt", "".join(f"wiring cmd/{m}\n" for m in mains) + "core calc\n")
    calc = ('package calc\n\nimport "example.com/dec"\n\nfunc Add(a, b int) int { return a + b + dec.Decode(nil) }\n'
            if calc_dec else "package calc\n\nfunc Add(a, b int) int { return a + b }\n")
    write(root, "broker/calc/calc.go", calc + "// x\n" * extra_own)
    write(root, "broker/calc/calc_test.go", "package calc\n" + "// test lines never count\n" * 50)
    for m in mains:
        imports = f'"{OWN}/calc"\n\t"encoding/json"\n' + ('\t"example.com/dec"\n' if use_dec else "")
        use = "_ = dec.Decode(nil)\n\t" if use_dec else ""
        write(root, f"broker/cmd/{m}/main.go",
              f"package main\n\nimport (\n\t{imports})\n\nfunc main() {{\n\t{use}_ = calc.Add(1, 2)\n\t_, _ = json.Marshal(1)\n}}\n")
    write(root, tb.REGISTRY, registry)


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = tb.main(argv)
    return rc, out.getvalue() + err.getvalue()


class Pure(unittest.TestCase):
    def test_registry_longest_pattern_wins(self):
        rules = tb.parse_registry("inert a/... -- tables\nparser a/b -- frames\nparser c/... -- x y\n")
        self.assertEqual(tb.classify("a/b", rules), "parser")
        self.assertEqual(tb.classify("a/b/c", rules), "inert")
        self.assertEqual(tb.classify("a", rules), "inert")
        self.assertEqual(tb.classify("c/d", rules), "parser")
        self.assertIsNone(tb.classify("ab", rules))
        self.assertIsNone(tb.classify("d", rules))

    def test_registry_rejects_bad_lines(self):
        for text in ("parser a/b\n", "parser a/b -- \n", "maybe a/b -- why\n", "parser a -- x\ninert a -- y\n"):
            with self.assertRaises(tb.MeasureError, msg=text):
                tb.parse_registry(text)

    def test_reason_lines(self):
        got, bad = tb.reasons("x\nTrusted-base: lines -- new kernel module for STO-2\n"
                              "Trusted-base: deps -- TODO\nTrusted-base: size -- big growth\n"
                              "  Trusted-base: parsers -- adds the CBOR decoder\n")
        self.assertEqual(set(got), {"lines", "parsers"})
        self.assertEqual(len(bad), 2)

    def m(self, lines=10, deps=10, parsers=("p",), unclassified=()):
        return {"lines": lines, "deps": deps, "parsers": set(parsers), "unclassified": list(unclassified)}

    def test_each_growth_needs_its_own_reason(self):
        # KRN-2m-e: each of the three grows alone and fails without its key, passes with it.
        cases = [("lines", self.m(lines=11)), ("deps", self.m(deps=11)), ("parsers", self.m(parsers=("p", "q")))]
        for key, head in cases:
            problems, owed = tb.compare(self.m(), head, [], "")
            self.assertEqual(set(owed), {key})
            self.assertEqual(len(problems), 1, key)
            other = next(k for k in tb.KEYS if k != key)
            self.assertTrue(tb.compare(self.m(), head, [], f"Trusted-base: {other} -- unrelated reason here")[0])
            self.assertEqual(tb.compare(self.m(), head, [], f"Trusted-base: {key} -- needed for the change")[0], [])

    def test_shrink_and_equal_pass_without_reason(self):
        self.assertEqual(tb.compare(self.m(), self.m(), [], "")[0], [])
        self.assertEqual(tb.compare(self.m(), self.m(lines=1, deps=1, parsers=()), [], "")[0], [])

    def test_swapped_parser_counts_as_new(self):
        # Same count, different parser: a new decoder still needs a reason.
        problems, owed = tb.compare(self.m(), self.m(parsers=("q",)), [], "")
        self.assertIn("parsers", owed)
        self.assertTrue(problems)

    def test_reclassification_needs_registry_reason(self):
        problems, owed = tb.compare(self.m(), self.m(), ["x/y"], "")
        self.assertEqual(set(owed), {"registry"})
        self.assertTrue(problems)
        self.assertEqual(tb.compare(self.m(), self.m(), ["x/y"], "Trusted-base: registry -- x/y only reads its own store")[0], [])

    def test_unclassified_fails_whatever_the_body(self):
        # KRN-2m-d: no reason line lets a package in unclassified.
        body = "\n".join(f"Trusted-base: {k} -- stated reason here" for k in tb.KEYS)
        self.assertTrue(tb.compare(self.m(), self.m(unclassified=["new/pkg"]), [], body)[0])


@unittest.skipUnless(shutil.which("go"), "go is not installed")
class SyntheticTree(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        # The trees stand alone: no fallback core file from this checkout.
        saved, tb.FALLBACK = tb.FALLBACK, pathlib.Path(self.tmp, "no-fallback")
        self.addCleanup(setattr, tb, "FALLBACK", saved)
        self.base, self.head = os.path.join(self.tmp, "base"), os.path.join(self.tmp, "head")
        self.body = os.path.join(self.tmp, "body.txt")
        pathlib.Path(self.body).write_text("")
        tree(self.base)

    def check(self, body=""):
        pathlib.Path(self.body).write_text(body)
        return run(["check", "--base-tree", self.base, "--head-tree", self.head, "--body", self.body])

    def test_counts(self):
        # KRN-2m-a/b/c: own lines are compiled own files only (no _test.go), deps the
        # vendored lines, stdlib excluded from lines; parsers include a listed stdlib package.
        m = tb.measure(tb.packages(self.base), tb.parse_registry(REGISTRY))
        calc = (pathlib.Path(self.base) / "broker/calc/calc.go").read_text().count("\n")
        main = (pathlib.Path(self.base) / "broker/cmd/a/main.go").read_text().count("\n")
        dec = (pathlib.Path(self.base) / "broker/vendor/example.com/dec/dec.go").read_text().count("\n")
        self.assertEqual(m["lines"], calc + main)
        self.assertEqual(m["deps"], dec)
        self.assertEqual(m["parsers"], {f"{OWN}/cmd/a", "example.com/dec", "encoding/json"})
        self.assertEqual(m["unclassified"], [])

    def test_unchanged_passes(self):
        tree(self.head)
        rc, out = self.check()
        self.assertEqual(rc, 0, out)
        self.assertIn("| Own lines |", out)

    def test_own_growth_fails_then_passes_with_reason(self):
        tree(self.head, extra_own=5)
        rc, out = self.check()
        self.assertEqual(rc, 1, out)
        self.assertIn("+5", out)
        rc, out = self.check("Body.\n\nTrusted-base: lines -- calc grows for the test\n")
        self.assertEqual(rc, 0, out)

    def test_new_trusted_main_counts(self):
        # KRN-2m-a: the process list is the head tree's core.txt; a new wiring binary grows lines.
        tree(self.head, mains=("a", "b"))
        write(self.head, tb.REGISTRY, REGISTRY + f"parser {OWN}/cmd/b -- entry\n")
        rc, out = self.check()
        self.assertEqual(rc, 1, out)
        self.assertIn("cmd/b", out)

    def test_unclassified_package_fails(self):
        tree(self.head, registry=REGISTRY.replace("parser example.com/dec -- decodes frames\n", ""))
        rc, out = self.check("Trusted-base: registry -- dropped the dec line on purpose\n")
        self.assertEqual(rc, 1, out)
        self.assertIn("example.com/dec is linked into a trusted process but no line", out)

    def test_reclassified_parser_fails_without_reason(self):
        reg = REGISTRY.replace("parser example.com/dec -- decodes frames", "inert example.com/dec -- trust me now")
        tree(self.head, registry=reg)
        rc, out = self.check()
        self.assertEqual(rc, 1, out)
        self.assertIn("reclassified from parser to inert: example.com/dec", out)
        self.assertEqual(self.check("Trusted-base: registry -- dec reads only its own frames\n")[0], 0)

    def test_dropping_a_dependency_passes(self):
        tree(self.head, use_dec=False)
        rc, out = self.check()
        self.assertEqual(rc, 0, out)
        self.assertIn("Parsers gone: `example.com/dec`", out)

    def test_measure_error_exits_2(self):
        tree(self.head)
        os.remove(os.path.join(self.head, "broker/core/core.txt"))
        self.assertEqual(self.check()[0], 2)
        tree(self.head)
        write(self.head, "broker/cmd/a/main.go", "package main\n\nimport \"example.com/missing\"\n\nfunc main() { missing.X() }\n")
        self.assertEqual(self.check()[0], 2)

    def test_markdown_goes_to_the_summary(self):
        tree(self.head)
        summary = os.path.join(self.tmp, "summary.md")
        rc, _ = run(["check", "--base-tree", self.base, "--head-tree", self.head, "--body", self.body,
                     "--markdown", summary])
        self.assertEqual(rc, 0)
        self.assertIn("## Trusted base (KRN-2)", pathlib.Path(summary).read_text())


CORE = "root calc\nallow golang.org/x/crypto/argon2\n"
DECISIONS = "| ID | Date | Status | Decision |\n|---|---|---|---|\n| D-7 | 2026-10-23 | active | grow calc |\n| D-6 | 2026-10-01 | superseded | old |\n"


class CorePure(unittest.TestCase):
    """KRN-2cap (#2935): the core file's grammar and the shrink-only comparison."""

    def test_parse(self):
        c = tb.parse_core("# x\nroot kernel\nroot kernel/key\nallow golang.org/x/sys/unix\nknown a/b -- linked via c\n")
        self.assertEqual(c, {"root": {"kernel", "kernel/key"}, "allow": {"golang.org/x/sys/unix"}, "known": {"a/b"}})

    def test_parse_rejects(self):
        for text in ("allow x/...\n", "root a\nroot a\n", "root ../vault\n", "root ./kernel\n", "root /k\n",
                     "root a\nknown a/b\n", "root a\nallow golang.org/x/sys/...\n", "root a\nknown a/b -- \n", "root a\ncore b\n", "root a b\n"):
            with self.assertRaises(tb.MeasureError, msg=text):
                tb.parse_core(text)

    def m(self, lines=10, imports=("a/b",), unlisted=(), unused=()):
        return {"lines": lines, "imports": set(imports), "unlisted": list(unlisted), "unused": list(unused)}

    def c(self, root=("k",), allow=(), known=("a/b",)):
        return {"root": set(root), "allow": set(allow), "known": set(known)}

    def test_equal_and_shrink_pass(self):
        self.assertEqual(tb.compare_core(self.c(), self.c(), self.m(), self.m(), "", ""), ([], {}))
        self.assertEqual(tb.compare_core(self.c(), self.c(known=()), self.m(), self.m(lines=3, imports=()), "", "")[0], [])
        self.assertEqual(tb.compare_core(self.c(), self.c(root=("k", "j")), self.m(), self.m(), "", "")[0], [])

    def test_each_loosening_needs_a_decision(self):
        cases = [("lines", self.c(), self.m(lines=11)),
                 ("root", self.c(root=()), self.m()),
                 ("allow", self.c(allow=("x/...",)), self.m()),
                 ("known", self.c(known=("a/b", "c/d")), self.m(imports=("a/b", "c/d"))),
                 ("file", None, None)]
        for key, head_core, head in cases:
            problems, owed = tb.compare_core(self.c(), head_core, self.m(), head, "", DECISIONS)
            self.assertEqual(set(owed), {key})
            self.assertEqual(len(problems), 1, key)
            self.assertIn("no `Trusted-core: <decision ID>` line", problems[0])
            for body in ("Trusted-core: D-6", "Trusted-core: D-8", "Trusted-base: lines -- calc grows here"):
                self.assertTrue(tb.compare_core(self.c(), head_core, self.m(), head, body, DECISIONS)[0], (key, body))
            self.assertEqual(tb.compare_core(self.c(), head_core, self.m(), head, "Body.\nTrusted-core: D-7\n", DECISIONS)[0], [])

    def test_unlisted_and_unused_fail_whatever_the_body(self):
        head = self.m(unlisted=["new/pkg"])
        self.assertTrue(tb.compare_core(self.c(), self.c(), self.m(), head, "Trusted-core: D-7", DECISIONS)[0])
        self.assertTrue(tb.compare_core(None, self.c(), None, head, "", "")[0])
        self.assertTrue(tb.compare_core(None, self.c(), None, self.m(unused=["a/b"]), "", "")[0])

    def test_no_base_file_owes_nothing(self):
        self.assertEqual(tb.compare_core(None, self.c(), None, self.m(lines=10**6), "", ""), ([], {}))
        self.assertEqual(tb.compare_core(None, None, None, None, "", ""), ([], {}))


@unittest.skipUnless(shutil.which("go"), "go is not installed")
class CoreTree(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        # The trees stand alone: no fallback core file from this checkout.
        saved, tb.FALLBACK = tb.FALLBACK, pathlib.Path(self.tmp, "no-fallback")
        self.addCleanup(setattr, tb, "FALLBACK", saved)
        self.base, self.head = os.path.join(self.tmp, "base"), os.path.join(self.tmp, "head")
        self.body = os.path.join(self.tmp, "body.txt")
        tree(self.base)
        write(self.base, tb.CORE, CORE)

    def check(self, body="", head_core=CORE, **kw):
        tree(self.head, **kw)
        write(self.head, "DECISIONS.md", DECISIONS)
        if head_core is not None:
            write(self.head, tb.CORE, head_core)
        pathlib.Path(self.body).write_text(body)
        return run(["check", "--base-tree", self.base, "--head-tree", self.head, "--body", self.body])

    def test_counts_only_the_roots_closure(self):
        m = tb.measure_core(self.base, tb.parse_core(CORE))
        calc = (pathlib.Path(self.base) / "broker/calc/calc.go").read_text().count("\n")
        self.assertEqual((m["lines"], m["imports"], m["unlisted"], m["unused"]), (calc, set(), [], []))

    def test_unchanged_passes(self):
        rc, out = self.check()
        self.assertEqual(rc, 0, out)
        self.assertIn("| Core lines |", out)

    def test_growth_fails_then_passes_with_a_decision(self):
        rc, out = self.check(extra_own=4)
        self.assertEqual(rc, 1, out)
        self.assertIn("core lines", out)
        # The KRN-2m reason covers the process measure but not the core.
        self.assertEqual(self.check("Trusted-base: lines -- calc grows here", extra_own=4)[0], 1)
        rc, out = self.check("Trusted-base: lines -- calc grows here\nTrusted-core: D-7\n", extra_own=4)
        self.assertEqual(rc, 0, out)

    def test_new_import_fails_until_listed_with_a_decision(self):
        body = "Trusted-base: lines -- calc links dec now\n"
        rc, out = self.check(body + "Trusted-core: D-7\n", calc_dec=True)
        self.assertEqual(rc, 1, out)
        self.assertIn("example.com/dec is linked into the trusted core", out)
        listed = CORE + "known example.com/dec -- frames for calc\n"
        self.assertEqual(self.check(body, head_core=listed, calc_dec=True)[0], 1)
        rc, out = self.check(body + "Trusted-core: D-7\n", head_core=listed, calc_dec=True)
        self.assertEqual(rc, 0, out)

    def test_package_beside_an_allowed_one_fails(self):
        # Security blocker on #2941: an allow line covers one package, so a new package of the
        # same module (here example.com/dec beside an allowed example.com/dec/other) is an import.
        allow = CORE + "allow example.com/dec/other\n"
        write(self.base, tb.CORE, allow)
        rc, out = self.check("Trusted-base: lines -- calc links dec now\nTrusted-core: D-7\n", head_core=allow, calc_dec=True)
        self.assertEqual(rc, 1, out)
        self.assertIn("example.com/dec is linked into the trusted core", out)

    def test_allowed_import_passes(self):
        allow = CORE + "allow example.com/dec\n"
        write(self.base, tb.CORE, allow)
        # calc's own lines grow, so the decision is owed; dec itself needs no known line.
        rc, out = self.check("Trusted-base: lines -- calc links dec now\nTrusted-core: D-7\n", head_core=allow, calc_dec=True)
        self.assertEqual(rc, 0, out)
        self.assertIn("| Linked packages outside std and allow | 0 | 0 | +0 |", out)

    def test_deleting_the_file_needs_a_decision(self):
        rc, out = self.check(head_core=None)
        self.assertEqual(rc, 1, out)
        self.assertIn(f"{tb.CORE} is deleted", out)
        self.assertEqual(self.check("Trusted-core: D-7", head_core=None)[0], 0)

    def test_first_file_owes_nothing(self):
        os.remove(os.path.join(self.base, tb.CORE))
        rc, out = self.check(extra_own=4, body="Trusted-base: lines -- calc grows here")
        self.assertEqual(rc, 0, out)

    def checked(self, body, fallback, **kw):
        tree(self.head, **kw)
        write(self.head, "DECISIONS.md", DECISIONS)
        return tb.run_check(self.base, self.head, body, fallback_tree=fallback)[0]

    def test_branch_older_than_the_file_uses_the_running_copy(self):
        # L3 blocker on #2941: neither tree has the file, the base branch tip does.
        os.remove(os.path.join(self.base, tb.CORE))
        tip = os.path.join(self.tmp, "tip")
        write(tip, tb.CORE, CORE)
        body = "Trusted-base: lines -- calc grows here\n"
        problems = self.checked(body, tip, extra_own=4)
        self.assertTrue(any("core lines" in p for p in problems), problems)
        self.assertEqual(self.checked(body + "Trusted-core: D-7\n", tip, extra_own=4), [])
        problems = self.checked(body + "Trusted-core: D-7\n", tip, calc_dec=True)
        self.assertTrue(any("example.com/dec is linked into the trusted core" in p for p in problems), problems)
        # No copy anywhere (this PR's own run): nothing to check.
        self.assertEqual(self.checked(body, os.path.join(self.tmp, "none"), extra_own=4), [])

    def test_bad_core_file_exits_2(self):
        self.assertEqual(self.check(head_core="root ../vault\n")[0], 2)
        self.assertEqual(self.check(head_core="root missing\n")[0], 2)


def toolchain_ok():
    if not shutil.which("go"):
        return False
    want = next((l.split()[1] for l in (ROOT / "broker/go.mod").read_text().splitlines()
                 if l.startswith("toolchain ")), "")
    got = subprocess.run(["go", "env", "GOVERSION"], capture_output=True, text=True,
                         env={**os.environ, "GOTOOLCHAIN": "local"}).stdout.strip()
    return got == want


class Repository(unittest.TestCase):
    """KRN-2m-d over the real broker: every linked package outside the stdlib is classified."""

    def test_registry_parses(self):
        rules = tb.parse_registry((ROOT / tb.REGISTRY).read_text())
        self.assertTrue(any(k == "parser" for _, k in rules))

    @unittest.skipUnless(toolchain_ok(), "the Go toolchain broker/go.mod names is not on PATH")
    def test_every_linked_package_is_classified(self):
        rules = tb.parse_registry((ROOT / tb.REGISTRY).read_text())
        m = tb.measure(tb.packages(ROOT), rules)
        self.assertEqual(m["unclassified"], [], f"classify these in {tb.REGISTRY}")
        self.assertGreater(m["lines"], 0)
        self.assertGreater(m["deps"], 0)
        self.assertTrue(m["parsers"])

    def test_core_file_parses_and_names_the_core(self):
        # KRN-2cap: the kernel, the key-check library and the clerk check path.
        core = tb.parse_core((ROOT / tb.CORE).read_text())
        self.assertTrue({"kernel", "kernel/key", "clerk"} <= core["root"])
        self.assertEqual(core["allow"], {"golang.org/x/sys/unix"})
        self.assertTrue(all(a.startswith(("golang.org/x/crypto/", "golang.org/x/sys/")) for a in core["allow"]))

    @unittest.skipUnless(toolchain_ok(), "the Go toolchain broker/go.mod names is not on PATH")
    def test_core_links_only_listed_packages(self):
        m = tb.measure_core(ROOT, tb.parse_core((ROOT / tb.CORE).read_text()))
        self.assertEqual((m["unlisted"], m["unused"]), ([], []), f"update {tb.CORE}")
        self.assertGreater(m["lines"], 0)


# KRN-2m-f: the workflow runs only the base's copy and fails closed. Every line that is not
# blank or a whole-line comment must equal this pin, in order (as lane-gate's pin does in
# tests/test_workflows.py), so no edit can switch to pull_request, check out or run the head,
# widen permissions, add `if:` or `continue-on-error:`, or swallow the exit code.
PIN = [
    "name: trusted-base",
    "on:",
    "  pull_request_target:",
    "    types: [opened, synchronize, reopened, edited]",
    "permissions:",
    "  contents: read",
    "jobs:",
    "  trusted-base:",
    "    name: trusted-base",
    "    runs-on: ubuntu-latest",
    "    timeout-minutes: 10",
    "    permissions:",
    "      contents: read",
    "    steps:",
    "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2",
    "        with:",
    "          ref: ${{ github.event.pull_request.base.sha }}",
    "          fetch-depth: 0 # the merge base with the PR head",
    "          persist-credentials: false",
    "      - name: Go version (the base's broker/go.mod toolchain line)",
    "        id: go",
    "        run: |",
    "          v=$(awk '$1 == \"toolchain\" {print $2}' broker/go.mod)",
    "          echo \"$v\" | grep -Eqx 'go1\\.[0-9]+(\\.[0-9]+)?'",
    "          echo \"version=${v#go}\" >> \"$GITHUB_OUTPUT\"",
    "      - uses: actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16  # v6.5.0",
    "        with:",
    "          go-version: ${{ steps.go.outputs.version }}",
    "          cache: false",
    "      - name: Trusted base (base copy of tools/trusted_base.py)",
    "        env:",
    "          HEAD_SHA: ${{ github.event.pull_request.head.sha }}",
    "          PR_NUMBER: ${{ github.event.pull_request.number }}",
    "          PR_BODY: ${{ github.event.pull_request.body }}",
    "        run: |",
    "          git fetch --no-tags origin \"+refs/pull/$PR_NUMBER/head:refs/remotes/pr/head\"",
    "          git cat-file -e \"$HEAD_SHA^{commit}\"",
    "          MERGE_BASE=$(git merge-base HEAD \"$HEAD_SHA\")",
    "          git -c core.hooksPath=/dev/null worktree add --detach \"$RUNNER_TEMP/base\" \"$MERGE_BASE\"",
    "          git -c core.hooksPath=/dev/null worktree add --detach \"$RUNNER_TEMP/head\" \"$HEAD_SHA\"",
    "          printf '%s\\n' \"$PR_BODY\" > \"$RUNNER_TEMP/body.txt\"",
    "          python3 -I tools/trusted_base.py check --base-tree \"$RUNNER_TEMP/base\" --head-tree \"$RUNNER_TEMP/head\""
    " --body \"$RUNNER_TEMP/body.txt\" --markdown \"$GITHUB_STEP_SUMMARY\"",
]


def pin_problems(text):
    import re
    if re.search(r"[^\x20-\x7e\n]", text):
        return ["a character other than printable ASCII or a newline"]
    code = [l for l in text.split("\n") if l.strip() and not l.lstrip().startswith("#")]
    out = []
    for i in range(max(len(code), len(PIN))):
        got = code[i] if i < len(code) else "<missing>"
        want = PIN[i] if i < len(PIN) else "<nothing>"
        if got != want:
            out.append(f"line {i + 1}: {got!r} != {want!r}")
    return out


class Workflow(unittest.TestCase):
    def test_workflow_matches_its_pin(self):
        text = (ROOT / ".github/workflows/trusted-base.yml").read_text()
        self.assertEqual(pin_problems(text), [])

    def test_pin_catches_mutations(self):
        text = (ROOT / ".github/workflows/trusted-base.yml").read_text()
        for old, new in [("pull_request_target:", "pull_request:"),
                         ("ref: ${{ github.event.pull_request.base.sha }}", "ref: ${{ github.event.pull_request.head.sha }}"),
                         ("python3 -I tools/trusted_base.py", "python3 -I \"$RUNNER_TEMP/head/tools/trusted_base.py\""),
                         ("      contents: read\n    steps:", "      contents: write\n    steps:"),
                         ("--markdown \"$GITHUB_STEP_SUMMARY\"", "--markdown \"$GITHUB_STEP_SUMMARY\" || true"),
                         ("    runs-on: ubuntu-latest", "    continue-on-error: true\n    runs-on: ubuntu-latest")]:
            self.assertIn(old, text)
            self.assertTrue(pin_problems(text.replace(old, new, 1)), old)


if __name__ == "__main__":
    unittest.main()
