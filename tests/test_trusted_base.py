"""KRN-2m (#2849): tools/trusted_base.py measures the trusted base and gates its growth;
KRN-2cap (#2935): it also holds the trusted core to a shrink-only line and import budget.

SPEC KRN-2: "The trusted base's size is measured on every PR (lines, dependencies, exposed
parsers) and shown in the PR; growth needs a stated reason ... It is a measure, not a cap."
Local cases KRN-2m-a..f are in the brief on #2849. The synthetic-tree tests run `go list`
(any Go toolchain new enough for a `go 1.22` module); the repository test runs it over the
real broker, so a package that enters a trusted process unclassified fails here too.
"""
# REQ: KRN-2
import ast
import contextlib
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import trusted_base as tb  # noqa: E402
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _nogit_bg import setUpModule, tearDownModule  # noqa: E402,F401

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
        got, bad = tb.reasons("x\nTrusted-base: registry -- dec reads its own frames\n"
                              "Trusted-base: parsers -- TODO\nTrusted-base: size -- big growth\n"
                              "  Trusted-base: lines -- an old body's line, ignored now\n")
        self.assertEqual(set(got), {"registry"})
        self.assertEqual(len(bad), 2)

    def m(self, lines=10, deps=10, parsers=("p",), unclassified=()):
        return {"lines": lines, "deps": deps, "parsers": set(parsers), "unclassified": list(unclassified)}

    def test_new_parser_needs_its_own_reason(self):
        # KRN-2m-e: a new parser fails without its key, passes with it.
        head = self.m(parsers=("p", "q"))
        problems, owed = tb.compare(self.m(), head, [], "")
        self.assertEqual(set(owed), {"parsers"})
        self.assertEqual(len(problems), 1)
        self.assertTrue(tb.compare(self.m(), head, [], "Trusted-base: registry -- unrelated reason here")[0])
        self.assertEqual(tb.compare(self.m(), head, [], "Trusted-base: parsers -- needed for the change")[0], [])

    def test_line_growth_is_reported_not_gated(self):
        # D-157: own and dependency growth passes with no body line; the trusted core gates the keeper.
        self.assertEqual(tb.compare(self.m(), self.m(lines=11, deps=11), [], ""), ([], {}))

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

    def test_own_growth_is_reported_and_passes(self):
        tree(self.head, extra_own=5)
        rc, out = self.check()
        self.assertEqual(rc, 0, out)
        self.assertIn("+5", out)

    def test_new_trusted_main_counts(self):
        # KRN-2m-a: the process list is the head tree's core.txt; a new wiring binary is measured.
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
# D-7 names the test PR (#42, as --pr 42); D-5 is active but names another PR (#2945).
PR = 42


def ceilings(lines, words=0):
    return f"# synthetic\ntrusted-lines {lines}\nspec-words {words}\n"
DECISIONS = ("| ID | Date | Status | Decision |\n|---|---|---|---|\n| D-7 | 2026-10-23 | active | grow calc for #42 |\n"
             "| D-6 | 2026-10-01 | superseded | old #42 |\n| D-5 | 2026-10-01 | active | the trusted core, #420 |\n")


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
        cases = [("root", self.c(root=()), self.m()),
                 ("allow", self.c(allow=("x/...",)), self.m()),
                 ("known", self.c(known=("a/b", "c/d")), self.m(imports=("a/b", "c/d"))),
                 ("file", None, None)]
        for key, head_core, head in cases:
            problems, owed = tb.compare_core(self.c(), head_core, self.m(), head, "", DECISIONS)
            self.assertEqual(set(owed), {key})
            self.assertEqual(len(problems), 1, key)
            self.assertIn("no `Trusted-core: <decision ID>` line", problems[0])
            for body in ("Trusted-core: D-6", "Trusted-core: D-8", "Trusted-core: D-5", "Trusted-base: lines -- calc grows here"):
                self.assertTrue(tb.compare_core(self.c(), head_core, self.m(), head, body, DECISIONS, PR)[0], (key, body))
            self.assertEqual(tb.compare_core(self.c(), head_core, self.m(), head, "Body.\nTrusted-core: D-7\n", DECISIONS, PR)[0], [])
            # #2945: the row has to name this PR; with no PR number nothing waives.
            self.assertTrue(tb.compare_core(self.c(), head_core, self.m(), head, "Trusted-core: D-7", DECISIONS, 43)[0])
            self.assertTrue(tb.compare_core(self.c(), head_core, self.m(), head, "Trusted-core: D-7", DECISIONS)[0])

    def test_unlisted_and_unused_fail_whatever_the_body(self):
        head = self.m(unlisted=["new/pkg"])
        self.assertTrue(tb.compare_core(self.c(), self.c(), self.m(), head, "Trusted-core: D-7", DECISIONS, PR)[0])
        self.assertTrue(tb.compare_core(None, self.c(), None, head, "", "")[0])
        self.assertTrue(tb.compare_core(None, self.c(), None, self.m(unused=["a/b"]), "", "")[0])

    def test_no_base_file_owes_nothing(self):
        self.assertEqual(tb.compare_core(None, self.c(), None, self.m(lines=10**6), "", ""), ([], {}))
        self.assertEqual(tb.compare_core(None, None, None, None, "", ""), ([], {}))


class CeilingsPure(unittest.TestCase):
    """D-310: the ceilings file's grammar, and SPEC words counted as tools/word_budget.py counts them."""

    def test_parse(self):
        self.assertEqual(tb.parse_ceilings("# x\n\ntrusted-lines 5\nspec-words 0\n"), {"trusted-lines": 5, "spec-words": 0})

    def test_parse_rejects(self):
        for text in ("trusted-lines 5\n", "trusted-lines 5\nspec-words 1\nspec-words 2\n", "trusted-lines -5\nspec-words 1\n",
                     "trusted-lines 05\nspec-words 1\n", "trusted-lines 5.0\nspec-words 1\n", "trusted-lines 5\nspec-words 1\nother 3\n",
                     "trusted-lines 5 6\nspec-words 1\n", "trusted-lines 5\r\nspec-words 1\n"):
            with self.assertRaises(tb.MeasureError, msg=text):
                tb.parse_ceilings(text)

    def test_spec_words_match_the_word_budget(self):
        import word_budget
        with tempfile.TemporaryDirectory() as d:
            write(d, "SPEC.md", "a  b\n\u2014 `c d`\t| \u00a0e\u2028f")
            self.assertEqual(tb.spec_words(d), word_budget.tree_counts(d)["spec"])
            self.assertEqual(tb.spec_words(d), 8)

    def test_repository_file_parses(self):
        c = tb.parse_ceilings((ROOT / tb.CEILINGS).read_text())
        self.assertEqual(set(c), set(tb.CEILING_NAMES))


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
        write(self.base, "DECISIONS.md", DECISIONS)
        # D-310: trusted lines capped at the base's measure, so any core growth ends above it.
        self.ceil = ceilings(tb.measure_core(self.base, tb.parse_core(CORE))["lines"])
        write(self.base, tb.CEILINGS, self.ceil)

    def check(self, body="", head_core=CORE, pr=PR, head_decisions="", head_ceil=None, **kw):
        tree(self.head, **kw)
        write(self.head, "DECISIONS.md", DECISIONS + head_decisions)
        if head_core is not None:
            write(self.head, tb.CORE, head_core)
        write(self.head, tb.CEILINGS, self.ceil if head_ceil is None else head_ceil)
        pathlib.Path(self.body).write_text(body)
        return run(["check", "--base-tree", self.base, "--head-tree", self.head, "--body", self.body]
                   + ([] if pr is None else ["--pr", str(pr)]))

    def test_counts_only_the_roots_closure(self):
        m = tb.measure_core(self.base, tb.parse_core(CORE))
        calc = (pathlib.Path(self.base) / "broker/calc/calc.go").read_text().count("\n")
        self.assertEqual((m["lines"], m["imports"], m["unlisted"], m["unused"]), (calc, set(), [], []))

    def test_unchanged_passes(self):
        rc, out = self.check()
        self.assertEqual(rc, 0, out)
        self.assertIn("| Core lines |", out)

    def test_growth_over_the_ceiling_fails_until_mark_raises_it(self):
        # D-310: core lines no longer take a per-PR Trusted-core waiver; the ceiling holds them.
        n = tb.measure_core(self.base, tb.parse_core(CORE))["lines"]
        rc, out = self.check(extra_own=4)
        self.assertEqual(rc, 1, out)
        # #4946 UX: the message names the cut that makes the PR pass.
        self.assertIn(f"trusted-lines {n} -> {n + 4} ends above its ceiling {n} ({tb.CEILINGS}):"
                      " cut 4 lines elsewhere in this PR (D-310)", out)
        self.assertEqual(self.check("Trusted-core: D-7\n", extra_own=4)[0], 1)
        rc, out = self.check(extra_own=4, head_ceil=ceilings(n + 4))
        self.assertEqual(rc, 1, out)
        self.assertIn(f"trusted-lines ceiling {n} -> {n + 4}: only Mark raises a ceiling (D-310),"
                      " and the PR body has no `Ceiling: <decision ID>` line", out)
        # #4946 Potency: an unwaived raise leaves the base's ceiling in force, not the head's.
        self.assertIn(f"trusted-lines {n} -> {n + 4} ends above its ceiling {n} ({tb.CEILINGS}): cut 4 lines", out)
        self.assertIn(f"| trusted-lines | {n} | {n + 4} | +4 | {n} |", out)
        self.assertEqual(self.check("Ceiling: D-7\n", extra_own=4, head_ceil=ceilings(n + 3))[0], 1)
        rc, out = self.check("Ceiling: D-7\n", extra_own=4, head_ceil=ceilings(n + 4))
        self.assertEqual(rc, 0, out)
        self.assertIn(f"| trusted-lines | {n} | {n + 4} | +4 | {n + 4} |", out)

    def test_growth_under_the_ceiling_passes(self):
        n = tb.measure_core(self.base, tb.parse_core(CORE))["lines"]
        write(self.base, tb.CEILINGS, ceilings(n + 10))
        self.assertEqual(self.check(extra_own=4, head_ceil=ceilings(n + 10))[0], 0)
        # A head may lower a ceiling, and is then held to it.
        rc, out = self.check(extra_own=4, head_ceil=ceilings(n + 3))
        self.assertEqual(rc, 1, out)
        self.assertIn("ends above its ceiling", out)

    def test_over_the_ceiling_a_pr_may_not_grow_but_may_stay(self):
        n = tb.measure_core(self.base, tb.parse_core(CORE))["lines"]
        write(self.base, tb.CEILINGS, ceilings(n - 2))
        self.assertEqual(self.check(head_ceil=ceilings(n - 2))[0], 0)
        rc, out = self.check(extra_own=1, head_ceil=ceilings(n - 2))
        self.assertEqual(rc, 1, out)
        # The cut is the growth, not the gap to the ceiling: ending at main's measure passes.
        self.assertIn("cut 1 line elsewhere in this PR", out)

    def test_two_prs_from_one_main_overshoot_once_then_the_ceiling_holds(self):
        # #4946 L3 7: each PR is checked against main at its last push, so two PRs that each fit
        # the headroom can land together above the ceiling. Main then sits over it, and no later PR
        # may grow the measure until cuts bring main back under (the same rule as main today).
        n = tb.measure_core(self.base, tb.parse_core(CORE))["lines"]
        write(self.base, tb.CEILINGS, ceilings(n + 3))
        self.assertEqual(self.check(extra_own=2, head_ceil=ceilings(n + 3))[0], 0)
        tree(self.base, extra_own=4)  # both PRs merged: 1 line over
        self.assertEqual(self.check(extra_own=4, head_ceil=ceilings(n + 3))[0], 0)
        rc, out = self.check(extra_own=5, head_ceil=ceilings(n + 3))
        self.assertEqual(rc, 1, out)
        self.assertIn(f"trusted-lines {n + 4} -> {n + 5} ends above its ceiling {n + 3}", out)
        self.assertIn("cut 1 line elsewhere", out)

    # REQ: CI-ceiling-fall
    def test_crossing_from_under_names_the_gap_to_the_ceiling(self):
        # #4982 item 1: main under the ceiling, the PR over it; the cut is head - ceiling (2),
        # not head - main (5), and more than one takes the plural (item 2).
        n = tb.measure_core(self.base, tb.parse_core(CORE))["lines"]
        write(self.base, tb.CEILINGS, ceilings(n + 3))
        rc, out = self.check(extra_own=5, head_ceil=ceilings(n + 3))
        self.assertEqual(rc, 1, out)
        self.assertIn(f"trusted-lines {n} -> {n + 5} ends above its ceiling {n + 3} ({tb.CEILINGS}):"
                      " cut 2 lines elsewhere in this PR (D-310)", out)

    # REQ: CI-ceiling-fall
    def test_main_that_grows_turns_an_earlier_pass_red(self):
        # Two PRs each fit 3 lines of headroom; once the first lands (+2), the second (+2),
        # measured again against the new main as the rerun does, no longer fits.
        n = tb.measure_core(self.base, tb.parse_core(CORE))["lines"]
        self.ceil = ceilings(n + 3)
        write(self.base, tb.CEILINGS, self.ceil)
        self.assertEqual(self.check(extra_own=2)[0], 0)
        tree(self.base, extra_own=2)  # the first PR merged
        rc, out = self.check(extra_own=4)
        self.assertEqual(rc, 1, out)
        self.assertIn(f"trusted-lines {n + 2} -> {n + 4} ends above its ceiling {n + 3}", out)

    # REQ: CI-ceiling-fall
    def test_main_that_shrinks_can_still_turn_an_earlier_pass_red(self):
        # L3 on #5179: main is over the spec-words ceiling; PR B cuts paragraph X and adds less, so
        # it passes. PR A makes the same cut and merges: main shrinks, yet B merged onto the new
        # main grows it while over the ceiling. Hence a rerun on every push, not only on growth.
        x = " ".join(["x"] * 11)
        write(self.base, "SPEC.md", " ".join(["w"] * 101) + "\n" + x + "\n")  # 112 words
        self.ceil = ceilings(10**6, 100)
        write(self.base, tb.CEILINGS, self.ceil)
        b_spec = " ".join(["w"] * 101) + "\n" + " ".join(["b"] * 5) + "\n"  # B: -11 +5 = 106
        write(self.head, "SPEC.md", b_spec)
        self.assertEqual(self.check()[0], 0)
        write(self.base, "SPEC.md", " ".join(["w"] * 101) + "\n")  # A merged: 101
        rc, out = self.check()
        self.assertEqual(rc, 1, out)
        self.assertIn("spec-words 101 -> 106 ends above its ceiling 100", out)

    def test_old_core_lines_count_and_move_into_the_core_at_par(self):
        # A migration step: the core grows by the lines the old core loses, in one PR.
        write(self.base, tb.OLD_CORE, "broker/old\n")
        write(self.base, "broker/old/old.go", "package old\n" + "// o\n" * 9)
        write(self.base, "broker/old/old_test.go", "package old\n" + "// t\n" * 99)
        write(self.base, "broker/old/testdata/x.go", "package x\n" * 99)
        n = tb.measure_core(self.base, tb.parse_core(CORE))["lines"]
        write(self.base, tb.CEILINGS, ceilings(n + 10))
        write(self.head, tb.OLD_CORE, "broker/old\n")
        write(self.head, "broker/old/old.go", "package old\n" + "// o\n" * 5)
        self.assertEqual(self.check(extra_own=4, head_ceil=ceilings(n + 10))[0], 0)
        self.assertEqual(self.check(extra_own=5, head_ceil=ceilings(n + 10))[0], 1)
        # Dropping the directory's line while its file stays sheds nothing.
        write(self.head, tb.OLD_CORE, "")
        self.assertEqual(self.check(extra_own=5, head_ceil=ceilings(n + 10))[0], 1)
        os.remove(os.path.join(self.head, "broker/old/old.go"))
        self.assertEqual(self.check(extra_own=5, head_ceil=ceilings(n + 10))[0], 0)

    def test_an_old_core_dir_only_the_head_lists_counts(self):
        # L3 finding 1 on #4946: the head side of the directory union. A head that adds broker/new
        # to tools/old_core.txt with new Go lines grows trusted lines like any other code.
        write(self.head, tb.OLD_CORE, "broker/new\n")
        write(self.head, "broker/new/n.go", "package n\n" + "// n\n" * 49)
        rc, out = self.check()
        self.assertEqual(rc, 1, out)
        n = tb.measure_core(self.base, tb.parse_core(CORE))["lines"]
        self.assertIn(f"trusted-lines {n} -> {n + 50} ends above its ceiling {n}", out)
        # #4946 UX: the table shows the growth is the old core's, with core lines unchanged.
        self.assertIn(f"| &nbsp;&nbsp;core | {n} | {n} | +0 | |", out)
        self.assertIn("| &nbsp;&nbsp;old core | 0 | 50 | +50 | |", out)

    def test_old_core_dirs_stay_inside_the_repository(self):
        # #4946 Potency: a listed `..` or absolute path would count files outside the tree.
        outside = os.path.join(self.tmp, "outside")
        write(outside, "o.go", "package o\n")
        for d in ("../outside", "broker/../../outside", outside):
            with self.assertRaises(tb.MeasureError, msg=d):
                tb.old_core_lines(self.base, {d})

    def test_spec_words_are_capped(self):
        write(self.base, "SPEC.md", "a b c")
        write(self.base, tb.CEILINGS, ceilings(10**6, 4))
        write(self.head, "SPEC.md", "a b c d")
        self.assertEqual(self.check(head_ceil=ceilings(10**6, 4))[0], 0)
        write(self.head, "SPEC.md", "a b c d e")
        rc, out = self.check(head_ceil=ceilings(10**6, 4))
        self.assertEqual(rc, 1, out)
        self.assertIn("spec-words 3 -> 5 ends above its ceiling 4", out)
        # The D-152 waiver does not reach the ceiling.
        self.assertEqual(self.check("Word-budget: D-7\n", head_ceil=ceilings(10**6, 4))[0], 1)

    def test_the_raise_is_the_base_trees_decision_and_names_the_pr(self):
        # #2945 (L3 3 and Security R2 on #2941): a row the PR adds itself, a row for another PR,
        # an inactive row and a waiver checked with no PR number all fail.
        n = tb.measure_core(self.base, tb.parse_core(CORE))["lines"]
        up = dict(extra_own=4, head_ceil=ceilings(n + 4))
        own_row = "| D-9 | 2026-10-24 | active | raise for #42 |\n"
        rc, out = self.check("Ceiling: D-9\n", head_decisions=own_row, **up)
        self.assertEqual(rc, 1, out)
        self.assertIn("names no active DECISIONS.md row on the base branch that names #42", out)
        self.assertEqual(self.check("Ceiling: D-7\n", pr=43, **up)[0], 1)
        self.assertEqual(self.check("Ceiling: D-7\n", pr=None, **up)[0], 1)
        self.assertEqual(self.check("Ceiling: D-5\n", **up)[0], 1)
        self.assertEqual(self.check("Ceiling: D-6\n", **up)[0], 1)
        self.assertEqual(self.check("Trusted-core: D-7\n", **up)[0], 1)
        # #4946 Potency: the line must start the line, so prose that quotes it waives nothing.
        self.assertEqual(self.check("Ceiling: D-7\n", **up)[0], 0)
        self.assertEqual(self.check("Not a Ceiling: D-7\n", **up)[0], 1)
        # #4946 UX: with no PR number the message says so instead of naming #None.
        rc, out = self.check("Ceiling: D-7\n", pr=None, **up)
        self.assertIn("`Ceiling: D-7` cannot be checked without the PR number (--pr)", out)
        self.assertNotIn("#None", out)

    def test_deleting_the_ceilings_file_needs_a_decision(self):
        self.check()
        os.remove(os.path.join(self.head, tb.CEILINGS))
        pathlib.Path(self.body).write_text("")
        problems = tb.run_check(self.base, self.head, "", pr=PR)[0]
        self.assertTrue(any(f"{tb.CEILINGS} is deleted" in p for p in problems), problems)
        self.assertEqual(tb.run_check(self.base, self.head, "Ceiling: D-7", pr=PR)[0], [])
        # Without its file the base ceiling still holds.
        tree(self.head, extra_own=4)
        problems = tb.run_check(self.base, self.head, "", pr=PR)[0]
        self.assertTrue(any("ends above its ceiling" in p for p in problems), problems)

    def test_deleting_the_core_file_sheds_no_lines(self):
        problems = self.check("Trusted-core: D-7", head_core=None, extra_own=4)
        self.assertEqual(problems[0], 1, problems[1])
        self.assertIn("trusted-lines", problems[1])

    def test_new_import_fails_until_listed_with_a_decision(self):
        self.ceil = ceilings(10**6)  # room under the ceiling: only the import is owed
        write(self.base, tb.CEILINGS, self.ceil)
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
        self.ceil = ceilings(10**6)
        write(self.base, tb.CEILINGS, self.ceil)
        # calc's own lines grow under the ceiling; dec itself needs no known line.
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
        os.remove(os.path.join(self.base, tb.CEILINGS))
        rc, out = self.check(extra_own=4, body="Trusted-base: lines -- calc grows here")
        self.assertEqual(rc, 0, out)

    def checked(self, body, fallback, **kw):
        tree(self.head, **kw)
        return tb.run_check(self.base, self.head, body, fallback_tree=fallback, pr=PR)[0]

    def test_branch_older_than_the_file_uses_the_running_copy(self):
        # L3 blocker on #2941: neither tree has the file, the base branch tip does.
        os.remove(os.path.join(self.base, tb.CORE))
        tip = os.path.join(self.tmp, "tip")
        write(tip, tb.CORE, CORE)
        os.remove(os.path.join(self.base, tb.CEILINGS))
        body = "Trusted-base: lines -- calc grows here\n"
        problems = self.checked(body, tip, calc_dec=True)
        self.assertTrue(any("example.com/dec is linked into the trusted core" in p for p in problems), problems)
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
        # KRN-2cap and D-157: D-154's keeper domain, the kernel and its process, the key-check
        # library, the clerk check path, the sealed store and the unlock step.
        core = tb.parse_core((ROOT / tb.CORE).read_text())
        self.assertTrue({"kernel", "kernel/key", "cmd/agentos-kernel", "clerk", "clerk/seal",
                         "cmd/agentos-unlock"} <= core["root"])
        self.assertEqual(core["allow"], {"golang.org/x/sys/unix", "golang.org/x/sys/cpu",
                                         "golang.org/x/crypto/argon2", "golang.org/x/crypto/blake2b"})
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
    "concurrency:",
    "  group: ${{ github.workflow }}-${{ startsWith(github.event_name, 'pull_request') && github.run_attempt == 1 && format('pr-{0}', github.event.pull_request.number) || format('run-{0}', github.run_id) }}",
    "  cancel-in-progress: ${{ startsWith(github.event_name, 'pull_request') && github.run_attempt == 1 }}",
    "permissions:",
    "  contents: read",
    "jobs:",
    "  trusted-base:",
    "    name: trusted-base",
    "    runs-on: ubuntu-24.04",
    "    timeout-minutes: 10",
    "    permissions:",
    "      contents: read",
    "    steps:",
    "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2",
    "        with:",
    "          ref: ${{ github.event.pull_request.base.ref }} # the live tip, also on a rerun",
    "          fetch-depth: 0 # history for the merge with the PR head",
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
    "          MERGED=$(git merge-tree --write-tree --no-messages HEAD \"$HEAD_SHA\")",
    "          MERGE=$(git -c user.name=trusted-base -c user.email=trusted-base@invalid commit-tree"
    " -p HEAD -p \"$HEAD_SHA\" -m merge \"$MERGED\")",
    "          git -c core.hooksPath=/dev/null worktree add --detach \"$RUNNER_TEMP/base\" HEAD",
    "          git -c core.hooksPath=/dev/null worktree add --detach \"$RUNNER_TEMP/head\" \"$MERGE\"",
    "          printf '%s\\n' \"$PR_BODY\" > \"$RUNNER_TEMP/body.txt\"",
    "          python3 -I tools/trusted_base.py check --base-tree \"$RUNNER_TEMP/base\" --head-tree \"$RUNNER_TEMP/head\""
    " --body \"$RUNNER_TEMP/body.txt\" --pr \"$PR_NUMBER\" --markdown \"$GITHUB_STEP_SUMMARY\"",
    "      - name: Measure sentences of added trusted-core growth decisions (base copy, D-159)",
    "        if: ${{ !cancelled() }}",
    "        run: python3 -I tools/trusted_base.py claims --base-tree \"$RUNNER_TEMP/base\" --head-tree \"$RUNNER_TEMP/head\""
    " --repo . --fetch origin --markdown \"$GITHUB_STEP_SUMMARY\"",
    "      - name: Closing keywords against deferred parts (base copy of tools/claims.py)",
    "        if: ${{ !cancelled() }}",
    "        env:",
    "          PR_BODY: ${{ github.event.pull_request.body }}",
    "        run: |",
    "          printf '%s\\n' \"$PR_BODY\" > \"$RUNNER_TEMP/claims-body.txt\"",
    "          python3 -I tools/claims.py closes --body \"$RUNNER_TEMP/claims-body.txt\" --markdown \"$GITHUB_STEP_SUMMARY\"",
]


# CI-ceiling-fall (#5174): the rerun workflow runs only on pushes to main, checks out nothing and
# runs no repository code; its token may rerun runs and read PRs, nothing else. Pinned as
# trusted-base.yml is, so no edit can add a PR trigger, check out code, widen the token, skip a
# push, or swallow a refused rerun; RerunScript runs the pinned script against a stub `gh`.
RERUN_PIN = [
    'name: trusted-base-rerun',
    'on:',
    '  push:',
    '    branches: [main]',
    'permissions:',
    '  contents: read',
    'concurrency:',
    '  group: trusted-base-rerun',
    '  cancel-in-progress: false',
    'jobs:',
    '  rerun:',
    '    name: trusted-base-rerun',
    '    runs-on: ubuntu-24.04',
    '    timeout-minutes: 30',
    '    permissions:',
    '      actions: write # rerun trusted-base runs, nothing else',
    "      contents: read # compare main's commits",
    '      pull-requests: read',
    '    steps:',
    "      - name: Rerun every open PR's newest trusted-base run",
    '        shell: bash',
    '        env:',
    '          GH_TOKEN: ${{ github.token }}',
    '          REPO: ${{ github.repository }}',
    '          ROUNDS: 50',
    '          WAIT: 30',
    '        run: |',
    '          prs=$(gh api --paginate "repos/$REPO/pulls?state=open&base=main&per_page=100" --jq \'.[] | "\\(.number) \\(.head.sha)"\') || { echo "::error::cannot list open PRs"; exit 1; }',
    '          since=$(gh api "repos/$REPO/actions/runs/$GITHUB_RUN_ID" --jq .created_at) && [[ $since =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || { echo "::error::cannot read this run\'s start"; exit 1; }',
    "          measured='^(broker/|decisions/|(SPEC|DECISIONS)\\.md$|\\.gitattributes$|\\.github/workflows/trusted-base\\.yml$|tools/(trusted_base\\.py|claims\\.py|trusted_base_parsers\\.txt|trusted_core\\.txt|ceilings\\.txt|old_core\\.txt)$)'",
    '          last=$(gh api "repos/$REPO/actions/workflows/trusted-base-rerun.yml/runs?branch=main&event=push&status=success&per_page=1" --jq \'.workflow_runs[0].head_sha // ""\') || { echo "::error::cannot list this workflow\'s runs"; exit 1; }',
    '          if [[ $last =~ ^[0-9a-f]{40}$ ]] && changed=$(gh api "repos/$REPO/compare/$last...$GITHUB_SHA" --jq \'if (.status == "ahead" or .status == "identical") and (.files | length) < 300 then (.files[] | .filename, (.previous_filename // empty)) else "broker/" end\') && { grep -Eq "$measured" <<< "$changed"; [ $? = 1 ]; }; then',
    '            printf \'\\n%s\\n\' "No path the check reads changed since $last; nothing rerun." | tee -a "$GITHUB_STEP_SUMMARY"; exit 0',
    '          fi',
    '          failed=0 reran=0 missed=""',
    '          pending="$prs"',
    '          for round in $(seq 1 "$ROUNDS"); do',
    '            [ -n "$pending" ] || break',
    '            left=""',
    '            while read -r pr sha; do',
    '              [ -n "$pr" ] || continue',
    '              run=$(gh api "repos/$REPO/actions/workflows/trusted-base.yml/runs?head_sha=$sha&event=pull_request_target&per_page=1" --jq \'.workflow_runs[0] | select(. != null) | "\\(.id) \\(.status)"\') || { echo "::warning::#$pr: cannot list runs"; failed=1; missed="$missed #$pr"; continue; }',
    '              if [ -z "$run" ]; then',
    '                echo "#$pr: no trusted-base run yet; its first run reads the new main"',
    '              elif [ "${run#* }" = completed ]; then',
    '                fresh=$(gh api "repos/$REPO/actions/runs/${run% *}/jobs" --jq "if ([.jobs[] | if .conclusion == \\"success\\" then .started_at else null end] | min) > \\"$since\\" then \\"fresh\\" else \\"\\" end") || { echo "::warning::#$pr: cannot list the jobs of ${run% *}"; failed=1; missed="$missed #$pr"; continue; }',
    '                if [ -n "$fresh" ]; then echo "#$pr: ${run% *} started after this push and passed, so it measured the new main"',
    '                elif gh api -X POST "repos/$REPO/actions/runs/${run% *}/rerun" > /dev/null; then echo "#$pr: reran ${run% *}"; reran=$((reran + 1)); else echo "::warning::#$pr: rerun of ${run% *} refused"; failed=1; missed="$missed #$pr"; fi',
    '              else',
    '                left="$left$pr $sha"$\'\\n\'',
    '              fi',
    '            done <<< "$pending"',
    '            pending="$left"',
    '            [ -z "$pending" ] || sleep "$WAIT"',
    '          done',
    '          while read -r pr sha; do',
    '            [ -n "$pr" ] || continue',
    '            echo "::warning::#$pr ($sha): still running after the last round, not rerun"; failed=1; missed="$missed #$pr"',
    '          done <<< "$pending"',
    '          total=$(printf \'%s\' "$prs" | grep -c . || true)',
    '          msg="Reran $reran of $total open PRs\' trusted-base runs."',
    '          [ -z "$missed" ] || msg="$msg Not rerun:$missed (rerun their trusted-base check by hand; tools/ASSUMPTIONS.md CI-ceiling-fall)."',
    '          printf \'\\n%s\\n\' "$msg" | tee -a "$GITHUB_STEP_SUMMARY"',
    '          exit "$failed"',
]


def pin_problems(text, pin=None):
    pin = PIN if pin is None else pin
    if re.search(r"[^\x20-\x7e\n]", text):
        return ["a character other than printable ASCII or a newline"]
    code = [l for l in text.split("\n") if l.strip() and not l.lstrip().startswith("#")]
    out = []
    for i in range(max(len(code), len(pin))):
        got = code[i] if i < len(code) else "<missing>"
        want = pin[i] if i < len(pin) else "<nothing>"
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
                         ("ref: ${{ github.event.pull_request.base.ref }}", "ref: ${{ github.event.pull_request.head.sha }}"),
                         # CI-ceiling-fall: the event's base.sha would make a rerun measure the old main.
                         ("ref: ${{ github.event.pull_request.base.ref }}", "ref: ${{ github.event.pull_request.base.sha }}"),
                         ("python3 -I tools/trusted_base.py", "python3 -I \"$RUNNER_TEMP/head/tools/trusted_base.py\""),
                         ("      contents: read\n    steps:", "      contents: write\n    steps:"),
                         ("--markdown \"$GITHUB_STEP_SUMMARY\"", "--markdown \"$GITHUB_STEP_SUMMARY\" || true"),
                         (" --pr \"$PR_NUMBER\"", ""),
                         ("--detach \"$RUNNER_TEMP/head\" \"$MERGE\"", "--detach \"$RUNNER_TEMP/head\" \"$HEAD_SHA\""),
                         ("--detach \"$RUNNER_TEMP/base\" HEAD", "--detach \"$RUNNER_TEMP/base\" \"$(git merge-base HEAD \"$HEAD_SHA\")\""),
                         ("    runs-on: ubuntu-24.04", "    continue-on-error: true\n    runs-on: ubuntu-24.04"),
                         # REV-PROOF-claims (#4909): the claim steps run the base copies and cannot be skipped.
                         ("python3 -I tools/claims.py", "python3 -I \"$RUNNER_TEMP/head/tools/claims.py\""),
                         (" --fetch origin", ""),
                         ("--body \"$RUNNER_TEMP/claims-body.txt\" --markdown \"$GITHUB_STEP_SUMMARY\"",
                          "--body \"$RUNNER_TEMP/claims-body.txt\" --markdown \"$GITHUB_STEP_SUMMARY\" || true"),
                         ("--head-tree \"$RUNNER_TEMP/head\" --repo .", "--head-tree \"$RUNNER_TEMP/base\" --repo .")]:
            self.assertIn(old, text)
            self.assertTrue(pin_problems(text.replace(old, new, 1)), old)

    # REQ: CI-ceiling-fall
    def test_rerun_workflow_matches_its_pin(self):
        text = (ROOT / ".github/workflows/trusted-base-rerun.yml").read_text()
        self.assertEqual(pin_problems(text, RERUN_PIN), [])
        for old, new in [("  push:\n    branches: [main]", "  pull_request_target:"),
                         ("  push:\n    branches: [main]", "  push:"),
                         ("      actions: write # rerun", "      contents: write\n      actions: write # rerun"),
                         ("      pull-requests: read", "      pull-requests: write"),
                         ("    steps:\n", "    steps:\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2\n"),
                         ("        shell: bash\n", "        shell: bash\n        if: github.event.before != ''\n"),
                         ("          exit \"$failed\"", "          exit 0"),
                         ("&event=pull_request_target", ""),
                         # CI-rerun-fresh (#5222): only bot-written files are ignored; a run that
                         # started before the push is rerun, so a later start is the only skip.
                         ("min) > \\\"$since", "min) < \\\"$since"),
                         # #5224: an empty push time fails closed, a run that did not pass is rerun,
                         # and only a push that changes no path the check reads is skipped.
                         (" && [[ $since =~", " || [[ $since =~"),
                         ("[0-9]{2}Z$ ]]", "[0-9]{2}Z ]]"),
                         ("if .conclusion == \\\"success\\\" then .started_at else null end", ".started_at"),
                         ("measured='^(broker/|", "measured='^("),
                         ("[ $? = 1 ]", "[ $? != 0 ]"),
                         ("(.status == \"ahead\" or .status == \"identical\") and ", ""),
                         ("&status=success&per_page=1", "&per_page=1"),
                         ("$last...$GITHUB_SHA", "$GITHUB_SHA~1...$GITHUB_SHA"),
                         ("(.files | length) < 300", "(.files | length) < 3000"),
                         (", (.previous_filename // empty)", ""),
                         ("    branches: [main]\n", "    branches: [main]\n    paths: [broker/**]\n"),
                         ("    runs-on: ubuntu-24.04", "    continue-on-error: true\n    runs-on: ubuntu-24.04")]:
            self.assertIn(old, text)
            self.assertTrue(pin_problems(text.replace(old, new, 1), RERUN_PIN), old)


def rerun_script():
    """The rerun step's `run:` block of trusted-base-rerun.yml, as one bash script."""
    lines = (ROOT / ".github/workflows/trusted-base-rerun.yml").read_text().split("\n")
    start = next(i for i, l in enumerate(lines) if l.strip() == "run: |") + 1
    return "\n".join(l[10:] for l in lines[start:] if l.strip()) + "\n"


STUB_GH = r"""#!/bin/bash
# A stand-in for `gh api`: open PRs from $STUB/prs, each head's runs from $STUB/runs/<sha> (one
# "<id> <status>" line per listing, the last line repeating), reruns logged to $STUB/reran. This
# run's record and each run's jobs are JSON in $STUB/run and $STUB/jobs/<id>, read with the
# script's own --jq expression by jq, as are this workflow's newest successful run ($STUB/last)
# and the compare from it ($STUB/compare).
[ "$1" = api ] || exit 9
shift
if [ "$1" = -X ]; then
  id=${3%/rerun}; id=${id##*/}
  [ -e "$STUB/refuse-$id" ] && exit 1
  echo "$id" >> "$STUB/reran"; exit 0
fi
case "$1" in
  */actions/runs/*/jobs) id=${1%/jobs}; f="$STUB/jobs/${id##*/}"; [ -e "$f" ] && exec jq -r "$3" "$f"; exit 1 ;;
  */actions/runs/"$GITHUB_RUN_ID") [ -e "$STUB/run" ] && exec jq -r "$3" "$STUB/run"; exit 1 ;;
  */workflows/trusted-base-rerun.yml/runs?branch=main\&event=push\&status=success\&per_page=1)
    [ -e "$STUB/last" ] && exec jq -r "$3" "$STUB/last"; exit 1 ;;
  */compare/*) [ "$1" = "repos/o/r/compare/$(jq -r '.workflow_runs[0].head_sha' "$STUB/last")...$GITHUB_SHA" ] || exit 8
    [ -e "$STUB/compare" ] && exec jq -r "$3" "$STUB/compare"; exit 1 ;;
esac
[ "$1" = --paginate ] && { [ -e "$STUB/prs" ] || exit 1; cat "$STUB/prs"; exit 0; }
sha=${1#*head_sha=}; sha=${sha%%&*}
f="$STUB/runs/$sha"
[ -e "$f" ] || exit 0
head -n 1 "$f"
[ "$(wc -l < "$f")" -gt 1 ] && sed -i 1d "$f"
exit 0
"""


class RerunScript(unittest.TestCase):
    """CI-ceiling-fall: the pinned rerun script, run against a stub `gh`."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        os.makedirs(os.path.join(self.tmp, "bin"))
        os.makedirs(os.path.join(self.tmp, "runs"))
        os.makedirs(os.path.join(self.tmp, "jobs"))
        write(self.tmp, "bin/gh", STUB_GH)
        os.chmod(os.path.join(self.tmp, "bin/gh"), 0o755)

    PUSH = "2026-11-10T03:05:49Z"  # this rerun run's created_at, no earlier than the push

    def run_script(self, prs, runs, refuse=(), rounds=3, started=None, push=PUSH, last={"workflow_runs": []},
                   compare=None):
        # last: this workflow's runs listing (None: it cannot be read); compare: the compare JSON
        # from its newest successful run to this push, or a list of changed paths (None: it fails).
        # started: {run id: [job started_at or (started_at, conclusion), ...]}, a job passing unless its
        # conclusion is given, or a whole jobs JSON as a dict; a run left out has one job started
        # before the push.
        for f in pathlib.Path(self.tmp).glob("**/*"):
            if f.is_file() and f.parent.name != "bin":
                f.unlink()
        if prs is not None:
            write(self.tmp, "prs", "".join(f"{n} {sha}\n" for n, sha in prs))
        if push is not None:
            write(self.tmp, "run", json.dumps(push if isinstance(push, dict) else {"id": 99, "created_at": push}))
        ids = {l.split()[0] for lines in runs.values() for l in lines}
        for sha, lines in runs.items():
            write(self.tmp, f"runs/{sha}", "".join(l + "\n" for l in lines))
        for i in ids:
            starts = (started or {}).get(i, ["2026-11-10T02:55:35Z"])
            if isinstance(starts, dict):
                write(self.tmp, f"jobs/{i}", json.dumps(starts))
            elif starts is not None:
                jobs = [{"started_at": s[0], "conclusion": s[1]} if isinstance(s, tuple)
                        else {"started_at": s, "conclusion": "success"} for s in starts]
                write(self.tmp, f"jobs/{i}", json.dumps({"total_count": len(jobs), "jobs": jobs}))
        for i in refuse:
            write(self.tmp, f"refuse-{i}", "")
        if last is not None:
            write(self.tmp, "last", json.dumps(last))
        if compare is not None:
            write(self.tmp, "compare", json.dumps(
                {"status": "ahead", "files": [{"filename": f} for f in compare]} if isinstance(compare, list)
                else compare))
        env = {**os.environ, "PATH": os.path.join(self.tmp, "bin") + os.pathsep + os.environ["PATH"],
               "STUB": self.tmp, "REPO": "o/r", "GITHUB_RUN_ID": "99", "GITHUB_SHA": "f" * 40, "ROUNDS": str(rounds), "WAIT": "0",
               "GITHUB_STEP_SUMMARY": os.path.join(self.tmp, "summary")}
        r = subprocess.run(["bash", "-eo", "pipefail", "-c", rerun_script()], env=env, capture_output=True, text=True)
        reran = pathlib.Path(self.tmp, "reran")
        return r.returncode, r.stdout + r.stderr, reran.read_text().split() if reran.exists() else []

    # REQ: CI-ceiling-fall
    def test_reruns_every_open_pr_waiting_for_one_in_progress(self):
        rc, out, reran = self.run_script(
            [(1, "a1"), (2, "b2"), (3, "c3")],
            {"a1": ["11 completed"], "b2": ["22 in_progress", "22 queued", "22 completed"]})
        self.assertEqual((rc, sorted(reran)), (0, ["11", "22"]), out)
        self.assertIn("#3: no trusted-base run yet", out)
        self.assertEqual(pathlib.Path(self.tmp, "summary").read_text(), "\nReran 2 of 3 open PRs' trusted-base runs.\n")

    # REQ: CI-ceiling-fall
    def test_failures_turn_the_job_red(self):
        # A refused rerun, a run still going after the last round, and an unlistable PR list each
        # exit 1, and the other PRs are still rerun.
        rc, out, reran = self.run_script([(1, "a1"), (2, "b2")], {"a1": ["11 completed"], "b2": ["22 completed"]},
                                         refuse=("11",))
        self.assertEqual((rc, reran), (1, ["22"]), out)
        self.assertIn("rerun of 11 refused", out)
        rc, out, reran = self.run_script([(1, "a1"), (2, "b2")], {"a1": ["11 in_progress"], "b2": ["22 completed"]},
                                         rounds=2)
        self.assertEqual((rc, reran), (1, ["22"]), out)
        self.assertIn("#1 (a1): still running after the last round, not rerun", out)
        self.assertIn("Reran 1 of 2 open PRs' trusted-base runs. Not rerun: #1 (rerun their trusted-base check by hand",
                      pathlib.Path(self.tmp, "summary").read_text())
        rc, out, reran = self.run_script(None, {})
        self.assertEqual((rc, reran), (1, []), out)
        # CI-rerun-fresh: this run's start or a run's jobs that cannot be read fail closed too.
        rc, out, reran = self.run_script([(1, "a1")], {"a1": ["11 completed"]}, push=None)
        self.assertEqual((rc, reran), (1, []), out)
        self.assertIn("cannot read this run's start", out)
        rc, out, reran = self.run_script([(1, "a1"), (2, "b2")], {"a1": ["11 completed"], "b2": ["22 completed"]},
                                         started={"11": None})
        self.assertEqual((rc, reran), (1, ["22"]), out)
        self.assertIn("#1: cannot list the jobs of 11", out)
        self.assertIn("Not rerun: #1 (", pathlib.Path(self.tmp, "summary").read_text())

    # REQ: CI-rerun-fresh
    def test_skips_a_run_that_started_after_the_push(self):
        # #5203: attempt 10 of run 42727562333 was queued before push 7bceb9d7 (03:05:49Z), started
        # at 03:28:42Z, so it checked out the new main, and was rerun 8 s after it passed. It stands
        # now. A run whose job started before the push, at the push's second, or not at all is still
        # rerun, and so is a run with any job that started before it.
        rc, out, reran = self.run_script(
            [(1, "a1"), (2, "b2"), (3, "c3"), (4, "d4"), (5, "e5"), (6, "f6")],
            {"a1": ["11 queued", "11 in_progress", "11 completed"], "b2": ["22 in_progress", "22 completed"],
             "c3": ["33 completed"], "d4": ["44 completed"], "e5": ["55 completed"], "f6": ["66 completed"]},
            started={"11": ["2026-11-10T03:28:42Z"], "22": ["2026-11-10T02:55:35Z"],
                     "33": [self.PUSH], "44": [], "55": [None], "66": ["2026-11-10T03:28:42Z", "2026-11-10T03:00:00Z"]})
        self.assertEqual((rc, sorted(reran)), (0, ["22", "33", "44", "55", "66"]), out)
        self.assertIn("#1: 11 started after this push and passed, so it measured the new main", out)
        self.assertEqual(pathlib.Path(self.tmp, "summary").read_text(), "\nReran 5 of 6 open PRs' trusted-base runs.\n")

    # REQ: CI-rerun-fresh-fu
    def test_empty_or_malformed_push_time_fails_closed(self):
        # Security 6 on #5223: an empty `since` sorts below every start, so every completed run read
        # as fresh and none was rerun. A null, empty or non-timestamp push time turns the job red.
        for push in ({"id": 99}, {"id": 99, "created_at": None}, "", "2026-11-10", " 2026-11-10T03:05:49Z",
                     "2026-11-10T03:05:49Z\" or true or \""):
            rc, out, reran = self.run_script([(1, "a1")], {"a1": ["11 completed"]}, push=push)
            self.assertEqual((rc, reran), (1, []), (push, out))
            self.assertIn("cannot read this run's start", out)

    # REQ: CI-rerun-fresh-fu
    def test_reruns_a_run_that_started_after_the_push_but_did_not_pass(self):
        # L3 6 on #5223: a run that started after the push and failed, timed out, was cancelled or
        # has a job with no conclusion is rerun now, not left red until main's next push; one
        # failing job among passing ones is enough.
        late = "2026-11-10T03:28:42Z"
        rc, out, reran = self.run_script(
            [(1, "a1"), (2, "b2"), (3, "c3"), (4, "d4"), (5, "e5"), (6, "f6")],
            {"a1": ["11 completed"], "b2": ["22 completed"], "c3": ["33 completed"], "d4": ["44 completed"],
             "e5": ["55 completed"], "f6": ["66 completed"]},
            started={"11": [(late, "success")], "22": [(late, "failure")], "33": [(late, "cancelled")],
                     "44": [(late, "timed_out")], "55": [(late, None)], "66": [late, (late, "failure")]})
        self.assertEqual((rc, sorted(reran)), (0, ["22", "33", "44", "55", "66"]), out)
        self.assertIn("#1: 11 started after this push and passed", out)

    # REQ: CI-rerun-fresh-fu
    def test_jobs_json_without_jobs_fails_closed(self):
        # L3 7 on #5223: a jobs JSON with no `jobs` key (or a null one) turns the job red and names
        # the PR; `(.jobs // [])` would quietly rerun instead. The other PR is still handled.
        for jobs in ({"total_count": 1}, {"total_count": 0, "jobs": None}):
            rc, out, reran = self.run_script([(1, "a1"), (2, "b2")], {"a1": ["11 completed"], "b2": ["22 completed"]},
                                             started={"11": jobs})
            self.assertEqual((rc, reran), (1, ["22"]), (jobs, out))
            self.assertIn("#1: cannot list the jobs of 11", out)
            self.assertIn("Not rerun: #1 (", pathlib.Path(self.tmp, "summary").read_text())

    LAST = {"workflow_runs": [{"head_sha": "e" * 40}]}

    # REQ: CI-rerun-fresh-fu
    def test_reruns_only_when_a_path_the_check_reads_changed(self):
        # Nothing is rerun when no path the check reads changed since this workflow's newest
        # successful run (#5223's merge, run 42753132786, and 16 other pushes 11-07 to 11-10).
        prs, runs = [(1, "a1")], {"a1": ["11 completed"]}
        for changed in ([], {"status": "identical", "files": []}, ["BOARD.md"], ["docs/OPERATING.md", "tools/ASSUMPTIONS.md", "tests/test_trusted_base.py",
                                           ".github/workflows/trusted-base-rerun.yml", "briefs/broker.md"]):
            rc, out, reran = self.run_script(prs, runs, last=self.LAST, compare=changed)
            self.assertEqual((rc, reran), (0, []), (changed, out))
            self.assertEqual(pathlib.Path(self.tmp, "summary").read_text(),
                             f"\nNo path the check reads changed since {'e' * 40}; nothing rerun.\n")
        # Any listed path, a rename away from one, 300 files or more, a compare that fails, has no
        # files or is not ahead or identical (main reset), and no earlier successful run (or one
        # that is not a commit id) rerun as before.
        for changed, last in [(["docs/a.md", "broker/x/y.go"], self.LAST), (["SPEC.md"], self.LAST),
                              (["decisions/D-1.md"], self.LAST), ([".gitattributes"], self.LAST),
                              (["tools/old_core.txt"], self.LAST),
                              ({"status": "ahead", "files": [{"filename": "docs/b.md",
                                                              "previous_filename": "DECISIONS.md"}]}, self.LAST),
                              ({"status": "ahead", "files": [{"filename": f"docs/{i}.md"} for i in range(300)]},
                               self.LAST),
                              ({"status": "behind", "files": []}, self.LAST),
                              ({"status": "diverged", "files": [{"filename": "docs/a.md"}]}, self.LAST),
                              ({"files": [{"filename": "docs/a.md"}]}, self.LAST),
                              # Security on f4bf05b6: over 64 KB with an early match, a pipe into
                              # grep -q took SIGPIPE under pipefail and read as no match.
                              (["broker/x.go"] + [f"docs/{i:0240d}" for i in range(298)], self.LAST),
                              (None, self.LAST), ({"status": "identical"}, self.LAST),
                              (["docs/a.md"], {"workflow_runs": []}),
                              (["docs/a.md"], {"workflow_runs": [{"head_sha": "main"}]})]:
            rc, out, reran = self.run_script(prs, runs, last=last, compare=changed)
            self.assertEqual((rc, reran), (0, ["11"]), (changed, last, out))
        # Only grep's "no match" (1) skips; an error (2) reruns.
        write(self.tmp, "bin/grep", '#!/bin/bash\n[ "$1" = -Eq ] && exit 2\nexec /usr/bin/env -S "PATH=/usr/bin:/bin" grep "$@"\n')
        os.chmod(os.path.join(self.tmp, "bin/grep"), 0o755)
        rc, out, reran = self.run_script(prs, runs, last=self.LAST, compare=["docs/a.md"])
        self.assertEqual((rc, reran), (0, ["11"]), out)
        os.unlink(os.path.join(self.tmp, "bin/grep"))
        rc, out, reran = self.run_script(prs, runs, last=None, compare=[])
        self.assertEqual((rc, reran), (1, []), out)
        self.assertIn("cannot list this workflow's runs", out)

    # REQ: CI-rerun-fresh-fu
    def test_measured_paths_hold_every_path_the_check_reads(self):
        # A push that changes no `measured` path cannot change any PR's measure only if the list
        # holds every repository path the check reads: the two base-copy tools, trusted-base.yml
        # (broker/go.mod's toolchain line), .gitattributes (git merge-tree honours it) and every
        # string constant in the tools, any quote or f-string part, whose first part names an
        # entry at the root or in broker/ (where go.mod is read), plus each old-core directory.
        text = (ROOT / ".github/workflows/trusted-base-rerun.yml").read_text()
        measured = re.compile(re.search(r"^ +measured='(.*)'$", text, re.M).group(1))

        def covered(p):
            return bool(measured.search(p) or measured.search(p.rstrip("/") + "/x"))

        tools = ("tools/trusted_base.py", "tools/claims.py")
        reads = {*tools, ".github/workflows/trusted-base.yml", ".gitattributes"}
        for name in tools:
            reads |= path_constants((ROOT / name).read_text())
        # L3 on f4bf05b6: a dot-entry keeps its dot, bytes count, and "./" is a prefix, not a set.
        self.assertEqual(path_constants("a = '.github/CODEOWNERS'\nb = b'PLAN.md'\nc = f'{d}/./SPEC.md'\n"
                                        "e = './go.mod'\nf = 'two words/x'\ng = 'nowhere/x'\n"),
                         {".github/CODEOWNERS", "PLAN.md", "SPEC.md", "broker/go.mod"})
        self.assertTrue({"SPEC.md", "DECISIONS.md", "decisions", "broker", "broker/go.mod", tb.CORE, tb.REGISTRY,
                         tb.CORE_LIST, tb.CEILINGS, tb.OLD_CORE} <= reads, reads)
        reads |= {l.strip() for l in (ROOT / tb.OLD_CORE).read_text().splitlines()
                  if l.strip() and not l.startswith("#")}
        self.assertEqual([p for p in sorted(reads) if not covered(p)], [])
        self.assertIn("awk '$1 == \"toolchain\" {print $2}' broker/go.mod",
                      (ROOT / ".github/workflows/trusted-base.yml").read_text())
        for name in ("BOARD.md", "METRICS.md", "TRACE.md", "tools/ASSUMPTIONS.md", "docs/SPEC.md", "xbroker/a.go"):
            self.assertFalse(covered(name), name)

def path_constants(source):
    """Each str or bytes constant in Python `source` (f-string parts too) that reads as a repository
    path: no whitespace, and its first part, after any "./" or "/" and other than "." or "..",
    names an entry at the root or, as a broker/-relative path, in broker/."""
    out = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Constant) and isinstance(node.value, (str, bytes)):
            s = node.value.decode("utf-8", "replace") if isinstance(node.value, bytes) else node.value
            s = s.strip()
            while s.startswith(("./", "/")):
                s = s.removeprefix("./").removeprefix("/")
            if s.split("/")[0] in ("", ".", "..") or re.search(r"\s", s):
                continue
            if (ROOT / s.split("/")[0]).exists():
                out.add(s)
            elif (ROOT / "broker" / s.split("/")[0]).exists():
                out.add("broker/" + s)
    return out


def merge_steps():
    """The workflow's lines from the merge to the worktrees, as one bash script."""
    text = (ROOT / ".github/workflows/trusted-base.yml").read_text().split("\n")
    start = next(i for i, l in enumerate(text) if "MERGED=$(git merge-tree" in l)
    end = next(i for i, l in enumerate(text) if '"$RUNNER_TEMP/head" "$MERGE"' in l)
    return "set -e\n" + "\n".join(l.strip() for l in text[start:end + 1]) + "\n"


@unittest.skipUnless(shutil.which("go"), "go is not installed")
class MergeMeasure(unittest.TestCase):
    """#2945 (L3 2 on #2941): the workflow measures the base tip against the head merged onto it."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        saved, tb.FALLBACK = tb.FALLBACK, pathlib.Path(self.tmp, "no-fallback")
        self.addCleanup(setattr, tb, "FALLBACK", saved)
        self.repo = os.path.join(self.tmp, "repo")
        os.makedirs(self.repo)
        self.git("init", "-q", "-b", "main")
        tree(self.repo, extra_own=20)
        write(self.repo, tb.CORE, CORE)
        write(self.repo, "DECISIONS.md", DECISIONS)
        self.lines = tb.measure_core(self.repo, tb.parse_core(CORE))["lines"]
        write(self.repo, tb.CEILINGS, ceilings(self.lines))
        self.commit("fork point")

    def git(self, *a):
        return subprocess.run(["git", "-C", self.repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", *a],
                              check=True, capture_output=True, text=True).stdout.strip()

    def commit(self, msg):
        self.git("add", "-A")
        self.git("commit", "-qm", msg)
        return self.git("rev-parse", "HEAD")

    def measure(self, head_sha):
        """rc of the workflow's merge lines plus the check, run on main's checkout."""
        self.git("checkout", "-q", "main")
        env = {**os.environ, "HEAD_SHA": head_sha, "RUNNER_TEMP": os.path.join(self.tmp, f"run-{head_sha[:7]}")}
        os.makedirs(env["RUNNER_TEMP"])
        r = subprocess.run(["bash", "-c", merge_steps()], cwd=self.repo, env=env, capture_output=True, text=True)
        if r.returncode:
            return r.returncode, "merge step: " + r.stdout + r.stderr
        body = os.path.join(env["RUNNER_TEMP"], "body.txt")
        pathlib.Path(body).write_text("Trusted-base: lines -- calc grows here\n")
        return run(["check", "--base-tree", os.path.join(env["RUNNER_TEMP"], "base"),
                    "--head-tree", os.path.join(env["RUNNER_TEMP"], "head"), "--body", body, "--pr", str(PR)])

    def test_cherry_picked_cut_does_not_keep_the_old_budget(self):
        # main cuts 20 lines and lowers the ceiling with them; the branch copies the cut instead
        # of merging main and adds 10.
        self.git("checkout", "-qb", "branch")
        self.git("checkout", "-q", "main")
        tree(self.repo)
        write(self.repo, tb.CEILINGS, ceilings(self.lines - 20))
        self.commit("main cuts calc")
        self.git("checkout", "-q", "branch")
        tree(self.repo)
        write(self.repo, "broker/calc/more.go", "package calc\n" + "// y\n" * 10)
        head = self.commit("branch: the same cut, by hand, plus a 10-line file")
        merge_base = self.git("merge-base", "main", head)
        old = tempfile.mkdtemp(dir=self.tmp)
        self.git("worktree", "add", "-q", "--detach", old + "/b", merge_base)
        self.git("worktree", "add", "-q", "--detach", old + "/h", head)
        body = os.path.join(old, "body.txt")
        pathlib.Path(body).write_text("Trusted-base: lines -- calc grows here\n")
        # The merge-base measure this replaces reads the branch as a 10-line cut.
        self.assertEqual(run(["check", "--base-tree", old + "/b", "--head-tree", old + "/h", "--body", body])[0], 0)
        rc, out = self.measure(head)
        self.assertEqual(rc, 1, out)
        self.assertIn("ends above its ceiling", out)

    def test_conflict_fails_closed(self):
        self.git("checkout", "-qb", "branch")
        write(self.repo, "broker/calc/calc.go", "package calc\n\nfunc Add(a, b int) int { return b + a }\n")
        head = self.commit("branch edits calc")
        self.git("checkout", "-q", "main")
        write(self.repo, "broker/calc/calc.go", "package calc\n\nfunc Add(a, b int) int { return a - -b }\n")
        self.commit("main edits calc")
        rc, out = self.measure(head)
        self.assertNotEqual(rc, 0, out)
        self.assertTrue(out.startswith("merge step: "), out)

    def test_clean_merge_unchanged_passes(self):
        self.git("checkout", "-qb", "branch")
        write(self.repo, "notes.txt", "unrelated\n")
        head = self.commit("branch adds a note")
        rc, out = self.measure(head)
        self.assertEqual(rc, 0, out)


# REQ: REV-PROOF-claims
CALC_EXTRA = ('package calc\n\nimport (\n\t"example.com/dec"\n\t"' + OWN + '/extra"\n)\n\n'
              "func Add(a, b int) int { return a + b + dec.Decode(nil) + extra.X() }\n")
GROWTH_ROW = ("| D-9 | 2026-11-03 | active | Trusted-core growth (D-159) for PR #7 (issue #6): calc links dec ({claim});"
              " review checks each line | standing rule D-159 |\n")


@unittest.skipUnless(shutil.which("go"), "go is not installed")
class GrowthSentence(unittest.TestCase):
    """REV-PROOF-claims (#4909): a D-159 decision carries the tool's measure sentence for its PR,
    measured from that PR head's merge base to the head; #4862 hand-wrote "no new linked packages"
    over a measured +1."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        saved, tb.FALLBACK = tb.FALLBACK, pathlib.Path(self.tmp, "no-fallback")
        self.addCleanup(setattr, tb, "FALLBACK", saved)
        self.repo = os.path.join(self.tmp, "repo")
        os.makedirs(self.repo)
        self.git("init", "-q", "-b", "main")
        tree(self.repo, calc_dec=True)  # the base core already links dec: calc 5 lines, dec 3
        write(self.repo, tb.CORE, CORE)
        self.fork = self.commit("fork point")
        self.git("checkout", "-qb", "grow")
        write(self.repo, "broker/extra/extra.go", "package extra\n\nfunc X() int { return 1 }\n")
        write(self.repo, "broker/calc/calc.go", CALC_EXTRA)  # 8 lines: calc +3, extra +3
        self.grow = self.commit("calc links extra")
        self.git("update-ref", "refs/remotes/pr/7", self.grow)
        self.git("checkout", "-q", "main")
        write(self.repo, "notes.txt", "main moves on\n")
        self.commit("main moves on")
        self.base, self.head = os.path.join(self.tmp, "base"), os.path.join(self.tmp, "head")
        write(self.base, "DECISIONS.md", DECISIONS)

    def git(self, *a):
        return subprocess.run(["git", "-C", self.repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", *a],
                              check=True, capture_output=True, text=True).stdout.strip()

    def commit(self, msg):
        self.git("add", "-A")
        self.git("commit", "-qm", msg)
        return self.git("rev-parse", "HEAD")

    def claims(self, row="", files=()):
        write(self.head, "DECISIONS.md", DECISIONS + row)
        for name, text in files:
            write(self.head, f"decisions/{name}", text)
        return run(["claims", "--base-tree", self.base, "--head-tree", self.head, "--repo", self.repo])

    def want(self):
        rc, out = run(["measure", "--sentence", self.fork, self.grow, "--pr", "7", "--tree", self.repo])
        self.assertEqual(rc, 0, out)
        return out.strip()

    def test_sentence_names_the_measure(self):
        # The two fields #4862 got wrong: the delta, and the packages new against the base (dec is not).
        self.assertEqual(self.want(), f"trusted-base measure of #7: core lines 8 to 14 (+6) from merge base"
                                      f" {self.fork[:7]} to head {self.grow[:7]}, new linked packages: broker/extra")
        self.assertEqual(self.git("worktree", "list").count("\n"), 0, "the measure leaves no worktree")

    def test_sentence_needs_a_pr(self):
        with self.assertRaises(SystemExit):
            run(["measure", "--sentence", self.fork, self.grow])

    def test_the_tools_sentence_passes(self):
        rc, out = self.claims(GROWTH_ROW.format(claim=self.want()))
        self.assertEqual(rc, 0, out)
        self.assertIn("DECISIONS.md:6 (D-9)", out)

    def test_hand_written_claim_fails_naming_the_line(self):
        # #4862: "no new linked packages" while the tool measures one.
        rc, out = self.claims(GROWTH_ROW.format(claim="+11 core lines against main, no new linked packages"))
        self.assertEqual(rc, 1, out)
        self.assertIn("DECISIONS.md:6 (D-9): records trusted-core growth under D-159 but has no measure sentence", out)

    def test_misworded_sentence_fails(self):
        wrong = self.want().replace("broker/extra", "none")
        rc, out = self.claims(GROWTH_ROW.format(claim=wrong))
        self.assertEqual(rc, 1, out)
        self.assertIn("DECISIONS.md:6 (D-9): the measure sentence is not the tool's output", out)
        self.assertIn(self.want(), out)

    def test_extended_package_list_fails(self):
        rc, out = self.claims(GROWTH_ROW.format(claim=self.want() + ", broker/other"))
        self.assertEqual(rc, 1, out)

    def test_stale_sentence_fails(self):
        old = self.want()
        self.git("checkout", "-q", "grow")
        write(self.repo, "broker/calc/more.go", "package calc\n" + "// z\n" * 4)
        self.git("update-ref", "refs/remotes/pr/7", self.commit("grow more"))
        self.git("checkout", "-q", "main")
        rc, out = self.claims(GROWTH_ROW.format(claim=old))
        self.assertEqual(rc, 1, out)
        self.assertIn("is not the tool's output", out)

    def test_sentence_for_another_pr_fails(self):
        self.git("update-ref", "refs/remotes/pr/8", self.grow)
        other = self.want().replace("of #7:", "of #8:")
        rc, out = self.claims(GROWTH_ROW.format(claim=other))
        self.assertEqual(rc, 1, out)
        self.assertIn("names PR #7 but has no measure sentence for it", out)

    def test_decision_file_is_checked(self):
        bad = "# D-9: growth\n\nStanding rule: D-159.\n\nPR #7 may grow (trusted-core growth, no new linked packages).\n"
        rc, out = self.claims(files=[("D-9.md", bad)])
        self.assertEqual(rc, 1, out)
        self.assertIn("decisions/D-9.md (D-9)", out)
        good = bad.replace("no new linked packages", self.want())
        self.assertEqual(self.claims(files=[("D-9.md", good)])[0], 0)

    def test_existing_and_unrelated_decisions_are_not_read(self):
        write(self.base, "decisions/D-1.md", "trusted-core growth under D-159, hand-written\n")
        write(self.head, "decisions/D-1.md", "trusted-core growth under D-159, hand-written, edited\n")
        row = "| D-10 | 2026-11-03 | active | cites D-159 about something else for PR #7 | Mark |\n"
        rc, out = self.claims(row)
        self.assertEqual(rc, 0, out)
        self.assertIn("No decision added records trusted-core growth.", out)

    def test_unfetchable_pr_is_an_error(self):
        rc, out = self.claims(GROWTH_ROW.format(claim=self.want().replace("of #7:", "of #99:")))
        self.assertEqual(rc, 2, out)

    def test_merged_pr_fails(self):
        # L3 on #4913: once merged, the merge base is the head and the measure reads +0, "none".
        self.git("merge", "-q", "--no-ff", "-m", "merge #7", "grow")
        rc, out = self.claims(GROWTH_ROW.format(claim=f"trusted-base measure of #7: core lines 14 to 14 (+0) from merge"
                                                      f" base {self.grow[:7]} to head {self.grow[:7]}, new linked packages: none"))
        self.assertEqual(rc, 1, out)
        self.assertIn(f"PR #7's head {self.grow[:7]} is already in the base; record its measure before it merges", out)

    def test_every_named_pr_needs_a_sentence(self):
        rc, out = self.claims(GROWTH_ROW.format(claim=self.want() + "; with PR #8"))
        self.assertEqual(rc, 1, out)
        self.assertIn("names PR #8 but has no measure sentence for it; paste the output of `git fetch origin pull/8/head", out)

    def test_wrong_sentence_names_the_command(self):
        rc, out = self.claims(GROWTH_ROW.format(claim=self.want().replace("+6", "+5")))
        self.assertIn(f"tools/trusted_base.py measure --sentence {self.fork[:12]} {self.grow[:12]} --pr 7", out)

    def test_edited_existing_row_is_not_read(self):
        row = GROWTH_ROW.format(claim="hand-written")
        write(self.base, "DECISIONS.md", DECISIONS + row)
        rc, out = self.claims(row.replace("| active |", "| superseded |"))
        self.assertEqual(rc, 0, out)

    def test_d159_itself_is_not_read(self):
        row = "| D-159 | 2026-10-24 | active | Trusted-core growth (D-159) standing rule for PR #7 | Mark |\n"
        rc, out = self.claims(row, files=[("D-159.md", "# D-159: Trusted-core growth, PR #7 (D-159)\n")])
        self.assertEqual(rc, 0, out)

    def test_a_trees_own_core_file_beats_the_fallback(self):
        other = os.path.join(self.tmp, "fallback")
        write(other, tb.CORE, "root cmd/a\n")
        saved, tb.FALLBACK = tb.FALLBACK, pathlib.Path(other)
        self.addCleanup(setattr, tb, "FALLBACK", saved)
        self.assertIn("core lines 8 to 14 (+6)", self.want())

    def test_markdown_gets_the_result_and_errors(self):
        summary = os.path.join(self.tmp, "summary.md")
        write(self.head, "DECISIONS.md", DECISIONS + GROWTH_ROW.format(claim=self.want()))
        argv = ["claims", "--base-tree", self.base, "--head-tree", self.head, "--repo", self.repo, "--markdown", summary]
        self.assertEqual(run(argv)[0], 0)
        self.assertIn("## Trusted-core growth decisions (REV-PROOF-claims)", pathlib.Path(summary).read_text())
        write(self.head, "DECISIONS.md", DECISIONS + GROWTH_ROW.format(claim=self.want().replace("of #7:", "of #99:")))
        self.assertEqual(run(argv)[0], 2)
        self.assertIn("**Error (claims):**", pathlib.Path(summary).read_text())


class SentenceEnd(unittest.TestCase):
    def test_check_claims_pure(self):
        def exp(pr):
            return (f"trusted-base measure of #{pr}: core lines 1 to 2 (+1) from merge base aaaaaaa to head bbbbbbb,"
                    " new linked packages: none", "cmd")
        want = exp(12)[0]
        for tail, ok in [("", True), (")", True), ("; review", True), (". Next", True), (" |", True),
                         (", broker/x", False), ("x", False), (".go", False)]:
            text = f"| D-9 | x | active | Trusted-core growth for PR #12 (D-159) ({want}{tail}"
            self.assertEqual(tb.check_claims([("DECISIONS.md:1", "D-9", text)], exp) == [], ok, tail)


if __name__ == "__main__":
    unittest.main()
