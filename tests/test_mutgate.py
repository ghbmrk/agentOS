"""tools/mutgate.py: the mutation gate over gremlins results (MUT-tierA, #1814; REV-PROOF-mut,
#4908), and the workflow that runs it on pull requests (REV-CHK-mut, #3899).

Gremlins itself is not run: the gate reads its JSON, so fixtures stand in for it.
"""
import collections
import contextlib
import fnmatch
import io
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "mutgate.yml"
sys.path.insert(0, str(ROOT / "tools"))
import mutgate  # noqa: E402

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from _nogit_bg import setUpModule as _bg_up, tearDownModule as _bg_down  # noqa: E402

_LOCAL = {}


def setUpModule():
    _bg_up()
    # Without a delegated cgroup these tests run mutgate as a local, advisory run does, in CI's unit
    # tests too, where CI is set; ci.yml's cgroup step runs the containment tests with one (#6392).
    if not os.environ.get(mutgate.CGROUP_ENV):
        _LOCAL.update({k: os.environ.pop(k) for k in ("CI", "GITHUB_ACTIONS") if k in os.environ})


def tearDownModule():
    os.environ.update(_LOCAL)
    _LOCAL.clear()
    _bg_down()


DIFF = """\
diff --git a/broker/hint/hint.go b/broker/hint/hint.go
--- a/broker/hint/hint.go
+++ b/broker/hint/hint.go
@@ -10,0 +11,2 @@ func f() {
+\tif x > 1 {
+\t}
diff --git a/broker/hint/hint_test.go b/broker/hint/hint_test.go
--- a/broker/hint/hint_test.go
+++ b/broker/hint/hint_test.go
@@ -1,0 +2 @@
+// REQ: CRED-1
"""
LIVE = {"hint": [("hint.go", 11, "CONDITIONALS_BOUNDARY"), ("hint.go", 40, "CONDITIONALS_NEGATION")]}


def gate(diff, live, waived=None):
    """violations() on the target lines a diff that changes non-test files gives each package of live."""
    added = mutgate.added_lines(diff)[0]
    return [v[:4] for v in mutgate.violations({p: mutgate.diff_targets(added, p) for p in live}, live, waived)]


def as_ci(args):
    """Before a `verify` of results that `run` and `delete` wrote here, drop their advisory mark (#6392):
    without a delegated cgroup they ran as a local run does, and these tests read the verdict as CI's."""
    if args[:1] == ("verify",):
        for f in pathlib.Path(args[1]).rglob("*.json"):
            data = json.loads(f.read_text())
            if isinstance(data, dict) and data.pop("advisory", None):
                f.write_text(json.dumps(data))

class Gate(unittest.TestCase):
    def test_live_mutant_on_added_line_in_claimed_package_fails(self):
        self.assertEqual(
            gate(DIFF, LIVE),
            [("hint", "broker/hint/hint.go", 11, "CONDITIONALS_BOUNDARY")],
        )

    def test_claimed_needs_no_req_marker(self):
        # REV-PROOF-mut (#4908): #2637, #2703 and #3476 guarded lines with no `REQ:` marker.
        diff = DIFF.replace("REQ: CRED-1", "a comment")
        self.assertEqual(gate(diff, LIVE), [("hint", "broker/hint/hint.go", 11, "CONDITIONALS_BOUNDARY")])
        self.assertEqual(mutgate.claimed(diff, packages=["hint"]), ["hint"])
        source_only = diff.split("diff --git a/broker/hint/hint_test.go")[0]
        self.assertEqual(mutgate.claimed(source_only, packages=["hint"]), ["hint"])

    def test_survivor_on_untouched_line_or_other_package_passes(self):
        self.assertEqual(gate(DIFF, {"hint": [("hint.go", 40, "X")]}), [])
        self.assertEqual(gate(DIFF, {"mail": [("hint.go", 11, "X")]}), [])

    def test_survivor_in_a_test_file_is_not_counted(self):
        self.assertEqual(gate(DIFF, {"hint": [("hint_test.go", 2, "X")]}), [])

    def test_added_lines_follow_hunk_numbers(self):
        added, tests = mutgate.added_lines(DIFF)
        self.assertEqual(added["broker/hint/hint.go"], {11, 12})
        self.assertEqual(tests, {"broker/hint/hint_test.go": {2}})

    def test_added_lines_split_on_newline_only(self):
        # #4028: a Go comment may carry any of these; str.splitlines() broke the diff line there.
        for ch in ("\u2028", "\u2029", "\r", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85"):
            diff = DIFF.replace("+\tif x > 1 {\n", f"+// a{ch}b\n+\tif x > 1 {{\n")
            added, _ = mutgate.added_lines(diff)
            self.assertEqual(added["broker/hint/hint.go"], {11, 12, 13}, repr(ch))
            self.assertEqual(gate(diff, {"hint": [("hint.go", 12, "X")]}),
                             [("hint", "broker/hint/hint.go", 12, "X")], repr(ch))

    def test_added_lines_skip_the_no_newline_marker(self):
        # #4103: the marker after a rewritten unterminated last line is not a line.
        diff = ("diff --git a/broker/x/a.go b/broker/x/a.go\n--- a/broker/x/a.go\n+++ b/broker/x/a.go\n"
                "@@ -2 +2,2 @@\n-old\n\\ No newline at end of file\n+n1\n+n2\n")
        self.assertEqual(mutgate.added_lines(diff)[0], {"broker/x/a.go": {2, 3}})
        diff += "\\ No newline at end of file\n"
        self.assertEqual(mutgate.added_lines(diff)[0], {"broker/x/a.go": {2, 3}})
        # a LIVED mutant on the first added line is read, not skipped
        diff = diff.replace("broker/x/a.go", "broker/hint/hint.go")
        self.assertEqual(gate(diff, {"hint": [("hint.go", 2, "X")]}),
                         [("hint", "broker/hint/hint.go", 2, "X")])

    def test_added_lines_read_quoted_and_tab_suffixed_headers(self):
        # #4105: git quotes a non-ASCII name and appends a TAB after a name with a space.
        for header, path in (('"b/broker/hint/h\\303\\251.go"', "broker/hint/h\u00e9.go"),
                             ("b/broker/hint/a b.go\t", "broker/hint/a b.go"),
                             ('"b/broker/hint/q\\"\\\\t.go"', 'broker/hint/q"\\t.go')):
            diff = f"diff --git a/x b/x\n--- a/x\n+++ {header}\n@@ -1,0 +2 @@\n+x\n"
            self.assertEqual(mutgate.added_lines(diff)[0], {path: {2}}, header)
        gone = "diff --git a/x b/x\n--- a/x\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n"
        self.assertEqual(mutgate.added_lines(gone)[0], {})

    def test_added_line_starting_plus_plus_space_is_not_a_header(self):
        diff = ("diff --git a/broker/x/a.go b/broker/x/a.go\n--- a/broker/x/a.go\n+++ b/broker/x/a.go\n"
                "@@ -1,0 +2,4 @@\n+a\n+++ b\n+c\n+d\n")
        self.assertEqual(mutgate.added_lines(diff)[0], {"broker/x/a.go": {2, 3, 4, 5}})
        diff = diff.replace("+++ b\n", "+++ b/other.go\n")
        self.assertEqual(mutgate.added_lines(diff)[0], {"broker/x/a.go": {2, 3, 4, 5}})

    def test_gate_numbers_lines_by_newline_only_on_a_real_diff(self):
        # #4028: git's own diff, read as text, would turn a lone \r into a line break too.
        with tempfile.TemporaryDirectory() as d:
            git = lambda *a: subprocess.run(["git", "-C", d, *a], check=True, capture_output=True, text=True)
            shutil.copytree(ROOT / "tools", pathlib.Path(d) / "tools")
            pkg = pathlib.Path(d) / "broker" / "hint"
            pkg.mkdir(parents=True)
            (pkg / "hint.go").write_text("package hint\n")
            git("init", "-q")
            git("add", "-A")
            git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "-m", "base")
            (pkg / "hint.go").write_bytes(b"package hint\n// a\rb \xe2\x80\xa8 c\nvar a = 1 + 1\n")
            git("add", "-A")
            git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "-m", "pr")
            res = pathlib.Path(d) / "res"
            res.mkdir()
            (res / "hint.json").write_text(json.dumps({"files": [{"file_name": "hint.go", "mutations": [
                {"status": "LIVED", "line": 3, "type": "ARITHMETIC_BASE"}]}], "mutants_lived": 1}))
            r = subprocess.run([sys.executable, "-I", str(pathlib.Path(d) / "tools" / "mutgate.py"), "gate", str(res),
                                "--git", "HEAD~1"], capture_output=True, text=True)
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("broker/hint/hint.go:3 ARITHMETIC_BASE survives", r.stdout)

    def test_gate_reads_a_real_diff_whatever_the_git_prefix_config(self):
        # #4115: prefix, colour and external-diff git config must not drop the PR's added lines.
        for key, value in (("diff.noprefix", "true"), ("diff.mnemonicPrefix", "true"), ("diff.dstPrefix", "w/"),
                           ("color.ui", "always"), ("diff.external", "true")):
            with self.subTest(key), tempfile.TemporaryDirectory() as d:
                git = lambda *a: subprocess.run(["git", "-C", d, *a], check=True, capture_output=True, text=True)
                shutil.copytree(ROOT / "tools", pathlib.Path(d) / "tools")
                pkg = pathlib.Path(d) / "broker" / "hint"
                pkg.mkdir(parents=True)
                (pkg / "hint.go").write_text("package hint\n")
                git("init", "-q")
                git("add", "-A")
                git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "-m", "base")
                (pkg / "hint.go").write_text("package hint\nvar a = 1 + 1\n")
                git("add", "-A")
                git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "-m", "pr")
                res = pathlib.Path(d) / "res"
                res.mkdir()
                (res / "hint.json").write_text(json.dumps({"files": [{"file_name": "hint.go", "mutations": [
                    {"status": "LIVED", "line": 2, "type": "ARITHMETIC_BASE"}]}], "mutants_lived": 1}))
                env = {**os.environ, "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": key, "GIT_CONFIG_VALUE_0": value}
                r = subprocess.run([sys.executable, "-I", str(pathlib.Path(d) / "tools" / "mutgate.py"), "gate",
                                    str(res), "--git", "HEAD~1"], capture_output=True, text=True, env=env)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("broker/hint/hint.go:2 ARITHMETIC_BASE survives", r.stdout)

    def test_gate_counts_a_copied_file_as_added_whatever_diff_renames_says(self):
        # #4115: with diff.renames=copies a new file copied from another shows only the lines that differ.
        for value in ("true", "copies"):
            with self.subTest(value), tempfile.TemporaryDirectory() as d:
                git = lambda *a: subprocess.run(["git", "-C", d, *a], check=True, capture_output=True, text=True)
                shutil.copytree(ROOT / "tools", pathlib.Path(d) / "tools")
                pkg = pathlib.Path(d) / "broker" / "hint"
                pkg.mkdir(parents=True)
                body = "package hint\n" + "".join(f"var v{i} = {i}\n" for i in range(20))
                (pkg / "a.go").write_text(body)
                git("init", "-q")
                git("add", "-A")
                git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "-m", "base")
                (pkg / "a.go").write_text(body + "var other = 2\n")  # git copies only from a modified file
                (pkg / "b.go").write_text(body + "var extra = 1\n")
                git("add", "-A")
                git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "-m", "pr")
                res = pathlib.Path(d) / "res"
                res.mkdir()
                (res / "hint.json").write_text(json.dumps({"files": [{"file_name": "b.go", "mutations": [
                    {"status": "LIVED", "line": 5, "type": "ARITHMETIC_BASE"}]}], "mutants_lived": 1}))
                env = {**os.environ, "GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "diff.renames",
                       "GIT_CONFIG_VALUE_0": value}
                r = subprocess.run([sys.executable, "-I", str(pathlib.Path(d) / "tools" / "mutgate.py"), "gate",
                                    str(res), "--git", "HEAD~1"], capture_output=True, text=True, env=env)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("broker/hint/b.go:5 ARITHMETIC_BASE survives", r.stdout)

    def test_survivors_reads_lived_only_and_nested_package_names(self):
        with tempfile.TemporaryDirectory() as d:
            data = {"files": [{"file_name": "a.go", "mutations": [
                {"type": "T", "status": "LIVED", "line": 3},
                {"type": "T", "status": "KILLED", "line": 4}]}]}
            (pathlib.Path(d) / "vm+gvisor.json").write_text(json.dumps(data))
            self.assertEqual(mutgate.survivors(d), {"vm/gvisor": [("a.go", 3, "T", None)]})
            self.assertEqual(mutgate.package_of("broker/vm/gvisor/a.go"), "vm/gvisor")

    def test_tier_b_package_is_claimed(self):
        # REV-PROOF-mut (#4908): tier B is gated as tier A is; a tier-C path never is.
        pkgs = mutgate.gated_packages()
        self.assertIn("netguard", pkgs)
        self.assertEqual(mutgate.risk_tier.tier_of("broker/quota/quota.go")[0], "B")
        self.assertIn("quota", pkgs)
        diff = DIFF.replace("broker/hint/", "broker/quota/").replace("REQ: CRED-1", "x")
        self.assertEqual(mutgate.claimed(diff), ["quota"])
        self.assertEqual(gate(diff, {"quota": [("hint.go", 11, "X")]}), [("quota", "broker/quota/hint.go", 11, "X")])
        with tempfile.TemporaryDirectory() as d:
            for name in ("a", "b", "c"):
                (pathlib.Path(d) / name).mkdir()
                (pathlib.Path(d) / name / "a.go").write_text("package x\n")
            real = mutgate.risk_tier.tier_of
            mutgate.risk_tier.tier_of = lambda p: (p.split("/")[1].upper(), p)
            try:
                self.assertEqual(mutgate.gated_packages(pathlib.Path(d)), ["a", "b"])
            finally:
                mutgate.risk_tier.tier_of = real

    def test_prefix_listed_packages_are_tier_a(self):
        # #3948 blocker: only exact core-list names counted, so packages under a prefix line were skipped.
        pkgs = mutgate.gated_packages()
        for pkg in ("kernel/key", "kernel/privfile", "clerk/inbox/imapsmtp"):
            self.assertIn(pkg, pkgs)
            diff = DIFF.replace("broker/hint/", f"broker/{pkg}/")
            self.assertEqual(mutgate.claimed(diff), [pkg])

    def test_tier_a_packages_match_risk_tier_on_every_package(self):
        # Every .go file, not a made-up name, through the tier rule premerge uses: a package is
        # in the set when any of its files is tier A or B (#3948 Security delta 2, #4908).
        broker = ROOT / "broker"
        pkgs = set(mutgate.gated_packages())
        for d in sorted({f.parent for f in broker.rglob("*.go")}):
            rel = d.relative_to(broker).as_posix()
            if rel == "." or {"vendor", "testdata"} & set(rel.split("/")):
                continue
            want = any(mutgate.risk_tier.tier_of(f.relative_to(ROOT).as_posix())[0] in "AB" for f in d.glob("*.go"))
            self.assertEqual(rel in pkgs, want, rel)

    def test_one_gated_file_puts_its_package_in(self):
        # A tier rule naming one .go file in an otherwise tier-C package must still count.
        with tempfile.TemporaryDirectory() as d:
            for name in ("a.go", "b.go"):
                (pathlib.Path(d) / "quota").mkdir(exist_ok=True)
                (pathlib.Path(d) / "quota" / name).write_text("package quota\n")
            real = mutgate.risk_tier.tier_of
            for one in ("broker/quota/a.go", "broker/quota/b.go"):
                mutgate.risk_tier.tier_of = lambda p, one=one: ("A", p) if p == one else ("C", p)
                try:
                    self.assertEqual(mutgate.gated_packages(pathlib.Path(d)), ["quota"], one)
                finally:
                    mutgate.risk_tier.tier_of = real

    def test_odd_tier_a_package_names_fail_loudly(self):
        # Go accepts `+` and `~` in a path: such a tier-A package must stop the run, not drop out
        # of the gate unseen (#3948 Security delta 1). vendor/ and testdata/ stay out quietly.
        def tree(d, names):
            for name in names:
                (pathlib.Path(d) / name).mkdir(parents=True)
                (pathlib.Path(d) / name / "a.go").write_text("package x\n")
        with tempfile.TemporaryDirectory() as d:
            tree(d, ["kernel/ok", "kernel/vendor/v", "kernel/testdata/t"])
            self.assertEqual(mutgate.gated_packages(pathlib.Path(d)), ["kernel/ok"])
        for odd in ("kernel/key+v2", "kernel/key~old", "kernel/a b", "kernel/$(x)"):
            with tempfile.TemporaryDirectory() as d:
                tree(d, ["kernel/ok", odd])
                with self.assertRaises(ValueError, msg=odd) as cm:
                    mutgate.gated_packages(pathlib.Path(d))
                self.assertIn(odd, str(cm.exception))

    def test_report_and_cli(self):
        with tempfile.TemporaryDirectory() as d:
            (pathlib.Path(d) / "hint.json").write_text(json.dumps(
                {"files": [{"file_name": "h.go", "mutations": [{"type": "T", "status": "LIVED", "line": 9}]}]}))
            r = subprocess.run([sys.executable, str(ROOT / "tools" / "mutgate.py"), "report", d],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0)
            self.assertIn("hint: 1 surviving", r.stdout)
            self.assertIn("h.go:9 T", r.stdout)


DOCS_ONLY = """\
diff --git a/docs/x.md b/docs/x.md
--- a/docs/x.md
+++ b/docs/x.md
@@ -1,0 +2 @@
+REQ: CRED-1
"""


def gremlins_json(statuses, lived=None):
    muts = [{"type": "T", "status": s, "line": i + 1, "column": 1} for i, s in enumerate(statuses)]
    n = sum(s == "LIVED" for s in statuses) if lived is None else lived
    return {"files": [{"file_name": "a.go", "mutations": muts}], "mutants_lived": n}


class Claimed(unittest.TestCase):
    # REV-CHK-mut: gremlins runs only where the gate can fail, so the run is the claim, not the package list.
    def test_claimed_is_changed_listed_packages_only(self):
        self.assertEqual(mutgate.claimed(DIFF, packages=["hint", "mail"]), ["hint"])
        self.assertEqual(mutgate.claimed(DIFF, packages=["mail"]), [])
        self.assertEqual(mutgate.claimed(DOCS_ONLY, packages=["hint"]), [])
        # A non-Go file of no package is no claim; a test file alone is (#4908). A data file of a
        # package is (#5779): see DataFiles.
        other = DIFF.replace("hint/hint.go", "hint/notes.md").replace("hint/hint_test.go", "hint/x.json")
        self.assertEqual(mutgate.claimed(other, packages=["hint"]), [])  # no broker/hint/ here
        tests_only = DIFF.split("diff --git a/broker/hint/hint_test.go")[1]
        self.assertEqual(mutgate.claimed("diff --git a/broker/hint/hint_test.go" + tests_only, packages=["hint"]), ["hint"])

    def test_a_changed_record_claims_its_package(self):
        # MUT-waiver-store-claim (#5786): a diff that changes only broker/<pkg>/MUTANTS-EQUIVALENT claims a
        # gated package, with no target line, so verify resolves the record and lists its new entries.
        rec = ("diff --git a/broker/hint/MUTANTS-EQUIVALENT b/broker/hint/MUTANTS-EQUIVALENT\n"
               "--- a/broker/hint/MUTANTS-EQUIVALENT\n+++ b/broker/hint/MUTANTS-EQUIVALENT\n@@ -1,0 +2 @@\n+{}\n")
        self.assertEqual(mutgate.claimed(rec, packages=["hint"]), ["hint"])
        self.assertEqual(mutgate.claimed(rec, packages=["mail"]), [])
        added, tests = mutgate.added_lines(rec)
        self.assertEqual((mutgate.diff_targets(added, "hint"), mutgate.tests_changed(tests, "hint")), ({}, False))
        # Added, deleted, or only lines removed: each changes the record.
        for d in (rec.replace("--- a/broker/hint/MUTANTS-EQUIVALENT", "--- /dev/null"),
                  rec.replace("+++ b/broker/hint/MUTANTS-EQUIVALENT", "+++ /dev/null").replace("@@ -1,0 +2 @@\n+{}", "@@ -1 +0,0 @@\n-{}"),
                  rec.replace("@@ -1,0 +2 @@\n+{}", "@@ -2 +1,0 @@\n-{}")):
            with self.subTest(d):
                self.assertEqual(mutgate.claimed(d, packages=["hint"]), ["hint"])
        # A file of another name, a record of another directory (testdata is never gated), or a `+++` line inside a
        # hunk claims no package.
        for d in (rec.replace("MUTANTS-EQUIVALENT", "MUTANTS-EQUIVALENT.md"),
                  rec.replace("broker/hint/MUTANTS", "broker/hint/testdata/MUTANTS"),
                  DOCS_ONLY + "@@ -3,0 +4 @@\n+++ b/broker/hint/MUTANTS-EQUIVALENT\n"):
            with self.subTest(d):
                self.assertEqual(mutgate.claimed(d, packages=["hint"]), [])

    def test_claimed_covers_every_package_violations_reads(self):
        # Any listed package outside claimed() could never yield a violation, whatever survives
        # there. The real tier list, not an injected one, so a prefix-line package counts (#3948).
        pkgs = ["netguard", "kernel/privfile", "clerk/inbox/imapsmtp", "quota"]
        diff = "".join(DIFF.replace("broker/hint/", f"broker/{p}/") for p in pkgs)
        live = {p: [("hint.go", 11, "X")] for p in pkgs}
        found = {v[0] for v in gate(diff, live)}
        self.assertEqual(found, set(pkgs))
        self.assertEqual(set(mutgate.claimed(diff)), found)

    def test_claimed_cli_on_a_real_diff(self):
        with tempfile.TemporaryDirectory() as d:
            git = lambda *a: subprocess.run(["git", "-C", d, *a], check=True, capture_output=True, text=True)
            # The CLI diffs the repo it sits in, so run a copy of tools/ (and the tier lists) in a temp repo.
            shutil.copytree(ROOT / "tools", pathlib.Path(d) / "tools")
            shutil.copytree(ROOT / "broker" / "core", pathlib.Path(d) / "broker" / "core")
            git("init", "-q")
            git("add", "-A")
            git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "-m", "base")
            pkg = pathlib.Path(d) / "broker" / "netguard"
            pkg.mkdir(parents=True)
            (pkg / "a.go").write_text("package netguard\n")
            (pkg / "a_test.go").write_text("package netguard\n// REQ: CRED-1\n")
            # A `-diff` attribute must not hide the marker as a binary file (L3 on #4026).
            (pkg / ".gitattributes").write_text("*.go -diff\n")
            (pkg / "blob.bin").write_bytes(b"\xbb\xff\n")  # not UTF-8, as broker/ already tracks
            (pathlib.Path(d) / "docs").mkdir()
            (pathlib.Path(d) / "docs" / "x.md").write_text("REQ: CRED-1\n")
            git("add", "-A")
            git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "-m", "pr")
            r = subprocess.run([sys.executable, "-I", str(pathlib.Path(d) / "tools" / "mutgate.py"),
                                "claimed", "--git", "HEAD~1", "--json"], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(json.loads(r.stdout), ["netguard"])


class Shape(unittest.TestCase):
    # ASSUMPTIONS D33: another JSON shape would make survivors() read nothing and the gate pass.
    def test_gremlins_shape_passes(self):
        self.assertTrue(mutgate.shape_ok(gremlins_json(["LIVED", "KILLED", "NOT COVERED"])))

    def test_each_unreadable_shape_fails(self):
        for bad in (
            [],
            {"results": []},
            gremlins_json(["LIVED"], lived=2),            # gremlins counted a survivor we cannot see
            gremlins_json(["SURVIVED"], lived=1),         # a renamed status
            {"files": [{"file_name": "a.go", "mutations": [{"status": "LIVED", "line": "3"}]}], "mutants_lived": 1},
            {"files": [{"name": "a.go", "mutations": []}], "mutants_lived": 0},
            {"files": [], "mutants_lived": None},
        ):
            self.assertFalse(mutgate.shape_ok(bad), bad)

    def test_run_fails_on_an_unreadable_shape(self):
        with tempfile.TemporaryDirectory() as d:
            stub = pathlib.Path(d) / "bin"
            stub.mkdir()
            # A stub gremlins writing JSON whose status is renamed: the run must fail, not pass empty.
            (stub / "gremlins").write_text(
                "#!/bin/sh\nwhile [ \"$1\" != -o ]; do shift; done\n"
                "printf '%s' '{\"files\":[{\"file_name\":\"a.go\",\"mutations\":"
                "[{\"status\":\"SURVIVED\",\"line\":1}]}],\"mutants_lived\":1}' > \"$2\"\n")
            (stub / "gremlins").chmod(0o755)
            env = {"PATH": f"{stub}:/usr/bin:/bin"}
            r = subprocess.run([sys.executable, str(ROOT / "tools" / "mutgate.py"), "run", "hint", "--out",
                                str(pathlib.Path(d) / "out")], capture_output=True, text=True, env=env)
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("not gremlins' files[].mutations[] shape", r.stderr)

    def run_config_stub(self, status="KILLED", env_extra=None):
        """mutgate.py run with a stub gremlins that records the --config file it is given and its
        GREMLINS_* environment, and reports one mutant with the given status."""
        with tempfile.TemporaryDirectory() as d:
            stub = pathlib.Path(d) / "bin"
            stub.mkdir()
            out = json.dumps({"files": [{"file_name": "x.go", "mutations": [{"status": status, "line": 1}]}],
                              "mutants_lived": 0})
            (stub / "gremlins").write_text(
                "#!/bin/sh\n{ echo \"$*\"; env | grep ^GREMLINS_; } > \"%s/seen\"\n"
                "while [ \"$1\" != --config ]; do shift; done\ncat \"$2\" > \"%s/cfg\"\n"
                "while [ \"$1\" != -o ]; do shift; done\nprintf '%%s' '%s' > \"$2\"\n" % (d, d, out))
            (stub / "gremlins").chmod(0o755)
            env = {"PATH": f"{stub}:/usr/bin:/bin", **(env_extra or {})}
            r = subprocess.run([sys.executable, str(ROOT / "tools" / "mutgate.py"), "run", "hint", "--out",
                                str(pathlib.Path(d) / "out")], capture_output=True, text=True, env=env)
            seen = (pathlib.Path(d) / "seen").read_text()
            return r, seen, (pathlib.Path(d) / "cfg").read_text()

    def test_run_reads_no_config_but_its_own_empty_one(self):
        # #4027: a PR-added broker/**/.gremlins.yaml or a GREMLINS_* variable must not reach gremlins.
        r, seen, cfg = self.run_config_stub(env_extra={"GREMLINS_UNLEASH_DRY_RUN": "true"})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertRegex(seen.splitlines()[0], r"^unleash \./hint --config \S+/gremlins\.yaml --exclude-files / -o ")
        self.assertNotIn("GREMLINS_", "\n".join(seen.splitlines()[1:]))
        self.assertEqual(cfg, "{}\n")

    def test_run_fails_on_a_mutant_gremlins_did_not_run(self):
        # #4027: a dry run leaves every mutant RUNNABLE and no LIVED one, which the gate would pass.
        r, _, _ = self.run_config_stub(status="RUNNABLE")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("mutants gremlins did not run", r.stderr)

    def test_foreign_names_are_lived_files_not_in_the_package(self):
        # #3956: violations() joins broker/<pkg>/<file_name>, so only a bare file name in the package matches.
        with tempfile.TemporaryDirectory() as d:
            pkg = pathlib.Path(d)
            (pkg / "clock.go").write_text("package clock\n")
            (pkg / "sub").mkdir()
            data = {"files": [
                {"file_name": "clock.go", "mutations": [{"status": "LIVED", "line": 1}]},
                {"file_name": "clock/clock.go", "mutations": [{"status": "LIVED", "line": 1}]},
                {"file_name": "sub", "mutations": [{"status": "LIVED", "line": 1}]},
                {"file_name": "gone.go", "mutations": [{"status": "KILLED", "line": 1}]},
            ], "mutants_lived": 3}
            self.assertEqual(mutgate.foreign_names(data, pkg), ["clock/clock.go", "sub"])

    def run_stub(self, file_name):
        """mutgate.py run on a real tier-A package, with a stub gremlins reporting one LIVED mutant in file_name."""
        pkg = mutgate.gated_packages()[0]
        with tempfile.TemporaryDirectory() as d:
            stub = pathlib.Path(d) / "bin"
            stub.mkdir()
            out = json.dumps({"files": [{"file_name": file_name, "mutations": [{"status": "LIVED", "line": 1}]}],
                              "mutants_lived": 1})
            (stub / "gremlins").write_text(
                f"#!/bin/sh\nwhile [ \"$1\" != -o ]; do shift; done\nprintf '%s' '{out}' > \"$2\"\n")
            (stub / "gremlins").chmod(0o755)
            env = {"PATH": f"{stub}:/usr/bin:/bin"}
            return subprocess.run([sys.executable, str(ROOT / "tools" / "mutgate.py"), "run", pkg, "--out",
                                   str(pathlib.Path(d) / "out")], capture_output=True, text=True, env=env)

    def test_run_fails_on_a_module_relative_file_name(self):
        pkg = mutgate.gated_packages()[0]
        name = sorted(f.name for f in (ROOT / "broker" / pkg).glob("*.go") if not f.name.endswith("_test.go"))[0]
        r = self.run_stub(f"{pkg.split('/')[-1]}/{name}")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn(f"not files in broker/{pkg}/", r.stderr)
        r = self.run_stub(name)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_run_writes_a_relative_out_dir_from_the_callers_cwd(self):
        # The workflow passes `--out mutants` from the repo root while gremlins runs in broker/;
        # gremlins (like this stub) does not create the -o directory (#3947's live run).
        with tempfile.TemporaryDirectory() as d:
            stub = pathlib.Path(d) / "bin"
            stub.mkdir()
            (stub / "gremlins").write_text(
                "#!/bin/sh\nwhile [ \"$1\" != -o ]; do shift; done\n"
                "[ -d \"$(dirname \"$2\")\" ] || exit 0\n"
                "printf '%s' '{\"files\":[],\"mutants_lived\":0}' > \"$2\"\n")
            (stub / "gremlins").chmod(0o755)
            env = {"PATH": f"{stub}:/usr/bin:/bin"}
            r = subprocess.run([sys.executable, str(ROOT / "tools" / "mutgate.py"), "run", "hint", "--out", "rel"],
                               capture_output=True, text=True, env=env, cwd=d)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertTrue((pathlib.Path(d) / "rel" / "hint.json").exists())

    def run_silent_stub(self, says, code=0):
        """mutgate.py run with a stub gremlins that prints says, writes no -o file and exits code."""
        with tempfile.TemporaryDirectory() as d:
            stub = pathlib.Path(d) / "bin"
            stub.mkdir()
            (stub / "gremlins").write_text(f"#!/bin/sh\nprintf '%s' '{says}'\nexit {code}\n")
            (stub / "gremlins").chmod(0o755)
            env = {"PATH": f"{stub}:/usr/bin:/bin"}
            out = pathlib.Path(d) / "out"
            r = subprocess.run([sys.executable, str(ROOT / "tools" / "mutgate.py"), "run", "hint", "--out",
                                str(out)], capture_output=True, text=True, env=env)
            dest = out / "hint.json"
            return r, json.loads(dest.read_text()) if dest.exists() else None

    def test_run_reads_no_results_as_zero_mutants(self):
        # #5173: gremlins finding no mutant prints this, exits 0 and writes no -o file.
        r, data = self.run_silent_stub("Starting...\n\nNo results to report.\n")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("No results to report.", r.stdout)  # its output still shows
        data.pop("advisory", None)  # a local run's mark (#6392)
        self.assertEqual(data, {"files": [], "mutants_total": 0, "mutants_lived": 0})

    def test_run_fails_closed_on_any_other_missing_result(self):
        for says, code in (("Starting...\n", 0),                          # no file, no word why
                           ("No results to report.\n", 1),                # it failed after saying so
                           ("a test said No results to report.\n", 0)):   # not gremlins' own line
            with self.subTest(says=says, code=code):
                r, data = self.run_silent_stub(says, code)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn(f"gremlins failed on hint (exit {code})", r.stderr)
                self.assertIsNone(data)

    def test_skipped_added_reads_only_skips_on_lines_the_gate_reads(self):
        added = mutgate.added_lines(DIFF)[0]
        data = {"files": [
            {"file_name": "hint.go", "mutations": [{"status": "SKIPPED", "line": 11},
                                                   {"status": "SKIPPED", "line": 40},
                                                   {"status": "KILLED", "line": 12}]},
            {"file_name": "hint_test.go", "mutations": [{"status": "SKIPPED", "line": 2}]},
        ]}
        self.assertEqual(mutgate.skipped_added(data, "hint", added), [("hint.go", 11)])
        self.assertEqual(mutgate.skipped_added(data, "mail", added), [])

    def run_diff_stub(self, skipped_line):
        """mutgate.py run --git in a temp repo whose last commit adds hint.go lines 2-3, with a stub
        gremlins that records its cwd, argv and git config and reports a SKIPPED mutant on skipped_line."""
        with tempfile.TemporaryDirectory() as d:
            git = lambda *a: subprocess.run(["git", "-C", d, *a], check=True, capture_output=True, text=True)
            shutil.copytree(ROOT / "tools", pathlib.Path(d) / "tools")
            shutil.copytree(ROOT / "broker" / "core", pathlib.Path(d) / "broker" / "core")
            pkg = pathlib.Path(d) / "broker" / "hint"
            pkg.mkdir(parents=True)
            (pkg / "hint.go").write_text("package hint\n")
            git("init", "-q")
            git("add", "-A")
            git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "-m", "base")
            (pkg / "hint.go").write_text("package hint\nvar a = 1 + 1\nvar b = 2 + 2\n")
            git("add", "-A")
            git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "-m", "pr")
            stub = pathlib.Path(d) / "bin"
            stub.mkdir()
            out = json.dumps({"files": [{"file_name": "hint.go", "mutations": [
                {"status": "SKIPPED", "line": skipped_line}, {"status": "KILLED", "line": 2}]}], "mutants_lived": 0})
            (stub / "gremlins").write_text(
                f"#!/bin/sh\n{{ pwd; echo \"$*\"; git diff --merge-base \"$4\"; }} > \"{d}/seen\"\n"
                f"while [ \"$1\" != -o ]; do shift; done\nprintf '%s' '{out}' > \"$2\"\n")
            (stub / "gremlins").chmod(0o755)
            env = {"PATH": f"{stub}:/usr/bin:/bin"}
            r = subprocess.run([sys.executable, "-I", str(pathlib.Path(d) / "tools" / "mutgate.py"), "run", "hint",
                                "--git", "HEAD~1", "--out", str(pathlib.Path(d) / "out")],
                               capture_output=True, text=True, env=env)
            return r, (pathlib.Path(d) / "seen").read_text().replace(d, "D")

    def test_run_with_git_mutates_only_added_lines_and_fails_on_a_skip_there(self):
        # Gremlins runs in the package directory with -D BASE, and its `git diff` names files as
        # its mutants do (relative to the package) with one exact hunk per added run (no context).
        r, seen = self.run_diff_stub(skipped_line=1)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        cwd, argv, diff = seen.split("\n", 2)
        self.assertEqual(pathlib.Path(cwd).name, "hint")
        self.assertRegex(argv, r"/broker/hint -D HEAD~1 --config \S+ --exclude-files / -o D/out/hint\.json --workers \d+$")
        self.assertIn("+++ b/hint.go\n@@ -1,0 +2,2 @@", diff)
        self.assertNotIn("\n package hint\n", diff)  # no context line
        # A mutant gremlins skipped on a line the gate reads fails the run, not the gate empty.
        r, _ = self.run_diff_stub(skipped_line=3)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("gremlins skipped mutants on target lines in broker/hint/: [('hint.go', 3)]", r.stderr)

    def test_gremlins_diff_counts_a_moved_file_as_added(self):
        # #4147: broker_diff passes --no-renames, so gremlins' own diff must not detect the move
        # either, whatever the repo's diff.renames says, or it skips lines the gate counts as added.
        for value in (None, "true", "copies"):
            with self.subTest(value), tempfile.TemporaryDirectory() as d:
                git = lambda *a: subprocess.run(["git", "-C", d, *a], check=True, capture_output=True, text=True)
                pkg = pathlib.Path(d) / "broker" / "hint"
                pkg.mkdir(parents=True)
                body = "package hint\n" + "".join(f"var v{i} = {i}\n" for i in range(20))
                (pkg / "a.go").write_text(body)
                git("init", "-q")
                if value:
                    git("config", "diff.renames", value)
                git("add", "-A")
                git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "-m", "base")
                git("mv", "broker/hint/a.go", "broker/hint/b.go")
                git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "-m", "pr")
                env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_CONFIG")}
                diff = subprocess.run(["git", "diff", "--merge-base", "HEAD~1"], cwd=pkg, capture_output=True,
                                      text=True, check=True, env={**env, **mutgate.DIFF_GIT_CONFIG}).stdout
                self.assertNotIn("rename from", diff)
                self.assertIn("+++ b/b.go\n@@ -0,0 +1,21 @@", diff)

    def test_run_mutates_only_the_packages_own_files(self):
        # #4025: gremlins walks subdirectories and filters by its --exclude-files regexps on the path
        # from the package directory (internal/engine/engine.go, v0.6.0), where a subpackage's file
        # carries a `/` and the package's own files never do.
        self.assertEqual(mutgate.SUBDIRS, ["--exclude-files", "/"])
        rule = re.compile(mutgate.SUBDIRS[1])
        self.assertTrue(rule.search("graph/graph.go"))
        self.assertTrue(rule.search("kernelsock/sub/x.go"))
        self.assertFalse(rule.search("name.go"))
        r, seen, _ = self.run_config_stub()
        self.assertIn(" --exclude-files / ", seen.splitlines()[0])
        r, seen = self.run_diff_stub(skipped_line=1)
        self.assertIn(" --exclude-files / ", seen.split("\n")[1])


class Verify(unittest.TestCase):
    # REV-CHK-mut-selftest (#4106): the JSON comes from a job that ran the PR's tests, so the
    # deciding job reads it as data and rechecks everything `run` checks before it gates.
    def verify(self, results, test=None, src="package netguard\nvar a = 1 + 1\n", body=None,
               summary=False, extra=(), pr_body=None, kind="ARITHMETIC_BASE"):
        """mutgate.py verify in a temp repo whose last commit adds broker/netguard/a.go line 2 (with src)
        and a_test.go (unless test is None), on a results dir holding {file name: JSON or raw text}.
        body's waiver lines go into the package record through `waive` in that commit (a line waive
        refuses writes nothing; its output is r.waive; `--mutant kind` unless a line names its own), and pr_body is passed as --body, which waives
        nothing (#6379); with summary, the summary file's text is set on the result."""
        with tempfile.TemporaryDirectory() as d:
            git = lambda *a: subprocess.run(["git", "-C", d, *a], check=True, capture_output=True, text=True)
            shutil.copytree(ROOT / "tools", pathlib.Path(d) / "tools")
            shutil.copytree(ROOT / "broker" / "core", pathlib.Path(d) / "broker" / "core")
            pkg = pathlib.Path(d) / "broker" / "netguard"
            pkg.mkdir(parents=True)
            (pkg / "a.go").write_text("package netguard\n")
            git("init", "-q")
            git("add", "-A")
            git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "-m", "base")
            (pkg / "a.go").write_text(src)
            if test is not None:
                (pkg / "a_test.go").write_text(test)
            (pathlib.Path(d) / "notes.md").write_text("x\n")
            waive = None
            if body is not None:
                (pathlib.Path(d) / "lines.md").write_bytes(body.encode())
                waive = subprocess.run([sys.executable, "-I", str(pathlib.Path(d) / "tools" / "mutgate.py"), "waive",
                                        str(pathlib.Path(d) / "lines.md"), "--accepted", "#1",
                                        *(["--mutant", kind] if kind and not any(w[2] for w in mutgate.waivers(body)) else [])],
                                       capture_output=True, text=True, cwd=d)
                (pathlib.Path(d) / "lines.md").unlink()
            git("add", "-A")
            git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "-m", "pr")
            res = pathlib.Path(d) / "res"
            res.mkdir()
            for name, data in results.items():
                # "mutants-0/netguard.json": one directory per artifact, as download-artifact lays them out.
                name = name if "/" in name else f"mutants-0/{name}"
                (res / name).parent.mkdir(parents=True, exist_ok=True)
                (res / name).write_text(data if isinstance(data, str) else json.dumps(data))
            extra = list(extra)
            if pr_body is not None:
                (pathlib.Path(d) / "body.md").write_bytes(pr_body.encode())
                extra += ["--body", str(pathlib.Path(d) / "body.md")]
            if summary:
                extra += ["--summary", str(pathlib.Path(d) / "summary.md")]
            r = subprocess.run([sys.executable, "-I", str(pathlib.Path(d) / "tools" / "mutgate.py"), "verify",
                                str(res), "--git", "HEAD~1", *extra], capture_output=True, text=True)
            r.waive = waive
            if summary:
                r.summary = (pathlib.Path(d) / "summary.md").read_text()
            return r

    @staticmethod
    def result(status, line=2, file_name="a.go"):
        return {"files": [{"file_name": file_name, "mutations": [
            {"type": "ARITHMETIC_BASE", "status": status, "line": line}]}], "mutants_lived": int(status == "LIVED"),
            "statement_deletions": 0}

    def test_killed_passes(self):
        r = self.verify({"netguard.json": self.result("KILLED")})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_lived_on_an_added_line_fails(self):
        r = self.verify({"netguard.json": self.result("LIVED")})
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("broker/netguard/a.go:2 ARITHMETIC_BASE survives", r.stdout)

    def test_not_covered_on_an_added_line_fails_where_tests_are_unchanged(self):
        # L3 R1 and Security S2 on #5770 (#5779): NOT COVERED failed only where the diff changed the
        # package's tests, so new code with no test (or moved in with its test deleted) passed. It
        # fails in every gated package; `Mutant-uncovered:`, the same waiver as `Mutant-equivalent:`,
        # names one no test can reach.
        # REQ: MUT-deleted-test-own-lines-fu
        r = self.verify({"netguard.json": self.result("NOT COVERED")}, summary=True)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("broker/netguard/a.go:2 is a target line no test of package netguard runs at the head", r.stdout)
        self.assertIn("name it in a Mutant-uncovered line", r.stdout)
        self.assertIn("**NOT COVERED**: no test of the package runs it", r.summary)
        for word in ("uncovered", "equivalent"):
            with self.subTest(word):
                r = self.verify({"netguard.json": self.result("NOT COVERED")}, summary=True,
                                body=f"Mutant-{word}: broker/netguard/a.go:2 a has no reader, so no test can run it\n")
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn("waived as uncovered (no test can run it): a has no reader", r.summary)
        r = self.verify({"netguard.json": self.result("LIVED")},
                        body="Mutant-uncovered: broker/netguard/a.go:2 a has no reader, so no test can tell\n")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)  # one waiver, two spellings

    def test_a_claimed_package_without_a_result_fails(self):
        # A deleted or never-written result must not read as "nothing survived".
        for results in ({}, {"other.json": self.result("KILLED")}, {"netguard.json": "{"}):
            with self.subTest(results):
                r = self.verify(results)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertTrue("no readable result for netguard" in r.stderr
                                or "0 results for netguard" in r.stderr, r.stderr)

    def test_a_result_in_two_artifacts_fails(self):
        # Code in one package's job could upload a second, clean copy of another package's result.
        r = self.verify({"mutants-0/netguard.json": self.result("LIVED"),
                         "mutants-1/netguard.json": self.result("KILLED")})
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("are both results for netguard: one run gives one result", r.stderr)  # #4983: not "shard 0 of 1"
        for f in ("mutants-0/netguard.json", "mutants-1/netguard.json"):
            self.assertIn(f, r.stderr)
        self.assertNotIn("shard", r.stderr)

    def test_twin_packages_each_need_their_own_result(self):
        # The repro on #4154: broker/netguard/sub and broker/netguard__sub both claimed; the LIVED
        # mutant in netguard/sub is read whatever the twin's result says.
        with tempfile.TemporaryDirectory() as d:
            git = lambda *a: subprocess.run(["git", "-C", d, *a], check=True, capture_output=True, text=True)
            shutil.copytree(ROOT / "tools", pathlib.Path(d) / "tools")
            shutil.copytree(ROOT / "broker" / "core", pathlib.Path(d) / "broker" / "core")
            git("init", "-q")
            git("add", "-A")
            git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "-m", "base")
            for rel in ("netguard/sub", "netguard__sub"):
                pkg = pathlib.Path(d) / "broker" / rel
                pkg.mkdir(parents=True)
                (pkg / "a.go").write_text("package sub\nvar a = 1 + 1\n")
            git("add", "-A")
            git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "-m", "pr")
            res = pathlib.Path(d) / "res"
            for i, (rel, status) in enumerate((("netguard/sub", "LIVED"), ("netguard__sub", "KILLED"))):
                (res / f"mutants-{i}").mkdir(parents=True)
                (res / f"mutants-{i}" / mutgate.result_name(rel)).write_text(json.dumps(self.result(status)))
            r = subprocess.run([sys.executable, "-I", str(pathlib.Path(d) / "tools" / "mutgate.py"), "verify",
                                str(res), "--git", "HEAD~1"], capture_output=True, text=True)
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("broker/netguard/sub/a.go:2 ARITHMETIC_BASE survives", r.stdout)

    def test_result_names_are_one_to_one(self):
        # Security on #4154: `a/b` and `a__b` both mapped to a__b.json, and one stood in for the other.
        names = ["netguard/sub", "netguard__sub", "netguard_sub", "netguard/s/ub", "netguard.sub"]
        self.assertEqual(len({mutgate.result_name(n) for n in names}), len(names))
        for n in names:
            self.assertTrue(mutgate.PKG_NAME.fullmatch(n))
            self.assertNotIn("+", n)
        with tempfile.TemporaryDirectory() as d:
            for n in ("netguard/sub", "netguard__sub"):
                (pathlib.Path(d) / mutgate.result_name(n)).write_text(json.dumps(
                    {"files": [{"file_name": "a.go", "mutations": [{"type": "T", "status": "LIVED", "line": 1}]}]}))
            self.assertEqual(sorted(mutgate.survivors(d)), ["netguard/sub", "netguard__sub"])

    def test_each_check_run_makes_fails_verify_too(self):
        for data, want in (
            ({"files": [], "mutants_lived": 1}, "not gremlins' files[].mutations[] shape"),
            (self.result("RUNNABLE"), "mutants gremlins did not run"),
            (self.result("LIVED", line=1, file_name="netguard/a.go"), "not files in broker/netguard/"),
            (self.result("LIVED", line=1, file_name="gone.go"), "not files in broker/netguard/"),
            (self.result("SKIPPED"), "gremlins skipped mutants on target lines"),
            # #4573: gremlins' JSON without `delete`'s pass, or a count that is not its mutants'.
            ({k: v for k, v in self.result("KILLED").items() if k != "statement_deletions"},
             "holds no statement-deletion pass"),
            ({**self.result("KILLED"), "statement_deletions": 1}, "holds no statement-deletion pass"),
            ({**self.result("KILLED"), "statement_deletions": "0"}, "holds no statement-deletion pass"),
        ):
            with self.subTest(want):
                r = self.verify({"netguard.json": data})
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn(want, r.stderr)

    def test_verify_lists_the_deletion_sites_itself(self):
        # #4602: a result's own count proved nothing; verify lists the sites with the base's lister
        # and needs one deletion verdict at each (file, line, column), no more and no fewer.
        src = "package netguard\nfunc F() { g(1 + 1) }\nfunc g(int) {}\n"
        deletion = {"type": mutgate.DELETION, "status": "KILLED", "line": 2, "column": 12}
        def result(*deletions):
            data = self.result("KILLED")
            data["files"][0]["mutations"] += deletions
            return {**data, "statement_deletions": len(deletions)}
        r = self.verify({"netguard.json": result(deletion)}, src=src)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        for bad in (result(), result({**deletion, "line": 3}), result({**deletion, "column": 1}),
                    result(deletion, deletion)):
            with self.subTest(bad):
                r = self.verify({"netguard.json": bad}, src=src)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("not one for each site this diff touches", r.stderr)
        r = self.verify({"netguard.json": result({**deletion, "status": "LIVED"}) | {"mutants_lived": 1}}, src=src)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("broker/netguard/a.go:2 deleting the whole statement holding line 2 survives", r.stdout)

    # MUT-test-only-cost (#4961): a package's target lines and deletion sites split into K shards,
    # one mutants job each; verify joins them and refuses a missing or overlapping shard.
    SHARD_SRC = "package netguard\nfunc F() {\n\tg(1)\n\tg(2)\n\tg(3)\n}\nfunc g(int) {}\n"

    def sharded(self, of, lived=4):
        """{artifact path: result} of the K=of shards of one run over SHARD_SRC's targets: lines 2-7,
        a gremlins mutant on each call line and a deletion site at each call, LIVED on line lived."""
        targets = {"broker/netguard/a.go": set(range(2, 8))}
        sites = [3, 4, 5]  # deletion_sites' order: the lister's, by file then position
        out = {}
        for i in range(of):
            mine = mutgate.shard_lines(targets, i, of).get("broker/netguard/a.go", set()) if of > 1 else targets["broker/netguard/a.go"]
            # Gremlins v0.6.0 writes the mutants outside its -D diff too, as SKIPPED (Security on #4978).
            muts = [{"type": "INCREMENT_DECREMENT", "status": ("LIVED" if n == lived else "KILLED") if n in mine
                     else "SKIPPED", "line": n, "column": 4} for n in (3, 4, 5)]
            dels = [{"type": mutgate.DELETION, "status": "LIVED" if n == lived else "KILLED", "line": n, "column": 2}
                    for n in sites[i::of]]
            data = {"files": [{"file_name": "a.go", "mutations": muts + dels}],
                    "mutants_total": len(muts) + len(dels), "statement_deletions": len(dels),
                    "mutants_lived": sum(m["status"] == "LIVED" for m in muts + dels)}
            if of > 1:
                data["shard"] = {"index": i, "of": of}
            out[f"mutants-{i}/netguard.json"] = data
        return out

    def test_shards_join_to_the_unsharded_verdicts(self):
        one = self.verify(self.sharded(1), src=self.SHARD_SRC, summary=True)
        self.assertEqual(one.returncode, 1, one.stdout + one.stderr)
        self.assertIn("broker/netguard/a.go:4 INCREMENT_DECREMENT survives", one.stdout)
        self.assertIn("broker/netguard/a.go:4 deleting the whole statement holding line 4 survives", one.stdout)
        for of in (2, 3, 6, 7):  # 7: more shards than target lines, so one shard holds none
            with self.subTest(of):
                r = self.verify(self.sharded(of), src=self.SHARD_SRC, summary=True)
                self.assertEqual((r.returncode, r.stdout, r.summary), (one.returncode, one.stdout, one.summary), r.stderr)
        r = self.verify(self.sharded(3, lived=None), src=self.SHARD_SRC)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_shards_one_job_ran_in_turn_join_from_their_own_directories(self):
        # MUT-plan-overflow (#6170): a job running several shards writes each to mutants/<index>/, so
        # its artifact holds one directory a shard. The join reads them as one-shard jobs' results, and
        # a shard written both there and as another job's result is refused as an overlap.
        one = self.verify(self.sharded(1), src=self.SHARD_SRC, summary=True)
        flat = self.sharded(3)
        nested = {f"mutants-{int(k.split('/')[0].split('-')[1]) % 2}/{k.split('/')[0].split('-')[1]}/netguard.json": v
                  for k, v in flat.items()}
        self.assertEqual(sorted(nested), ["mutants-0/0/netguard.json", "mutants-0/2/netguard.json",
                                          "mutants-1/1/netguard.json"])
        r = self.verify(nested, src=self.SHARD_SRC, summary=True)
        self.assertEqual((r.returncode, r.stdout, r.summary), (one.returncode, one.stdout, one.summary), r.stderr)
        twice = {**nested, "mutants-2/netguard.json": flat["mutants-0/netguard.json"]}
        r = self.verify(twice, src=self.SHARD_SRC)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("shards overlap", r.stderr)
        # K past the 256-job matrix is a schedule like any other.
        self.assertEqual(mutgate.shard_of({"shard": {"index": 295, "of": 296}}), (295, 296))

    def test_a_missing_or_overlapping_shard_is_refused(self):
        good = self.sharded(2, lived=None)
        moved = json.loads(json.dumps(good))
        # Shard 0 (lines 2, 4, 6) reporting a KILLED gremlins mutant on shard 1's line 3.
        moved["mutants-0/netguard.json"]["files"][0]["mutations"].append(
            {"type": "INCREMENT_DECREMENT", "status": "KILLED", "line": 3, "column": 4})
        moved["mutants-0/netguard.json"]["mutants_total"] += 1
        # Shard 1 carrying shard 0's deletion site too.
        stolen = json.loads(json.dumps(good))
        stolen["mutants-1/netguard.json"]["files"][0]["mutations"].append(
            {"type": mutgate.DELETION, "status": "KILLED", "line": 3, "column": 2})
        stolen["mutants-1/netguard.json"]["statement_deletions"] += 1
        # Shard 1 (lines 3, 5, 7) leaving its own line 3 SKIPPED: no verdict there, refused.
        own_skip = json.loads(json.dumps(good))
        for m in own_skip["mutants-1/netguard.json"]["files"][0]["mutations"]:
            if m["line"] == 3 and m["type"] != mutgate.DELETION:
                m["status"] = "SKIPPED"
        unsharded = {k: {**v} for k, v in good.items()}
        unsharded["mutants-1/netguard.json"].pop("shard")
        for name, results, want in (
            ("missing", {"mutants-0/netguard.json": good["mutants-0/netguard.json"]}, "missing shard(s) [1] of 2"),
            ("twice", {**good, "mutants-2/netguard.json": good["mutants-0/netguard.json"]}, "shards overlap"),
            ("other line", moved, "holds mutants on lines of another shard of netguard"),
            ("other site", stolen, "not one for each site this diff touches"),
            ("skipped on its own line", own_skip, "gremlins skipped mutants on target lines"),
            ("counts", {**good, "mutants-1/netguard.json": {**good["mutants-1/netguard.json"], "shard": {"index": 1, "of": 3}}},
             "disagree on the number of shards"),
            ("unsharded twin", unsharded, "disagree on the number of shards"),
            ("index", {**good, "mutants-1/netguard.json": {**good["mutants-1/netguard.json"], "shard": {"index": 2, "of": 2}}},
             "records a shard that is not"),
            ("bool", {**good, "mutants-1/netguard.json": {**good["mutants-1/netguard.json"], "shard": {"index": True, "of": 2}}},
             "records a shard that is not"),
            ("over the limit", {"mutants-0/netguard.json": {**good["mutants-0/netguard.json"], "shard": {"index": 0, "of": 1281}}},
             "records a shard that is not"),
        ):
            with self.subTest(name):
                r = self.verify(results, src=self.SHARD_SRC)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn(want, r.stderr)

    def test_no_claim_needs_no_result(self):
        r = self.verify({}, test=None, src="package netguard\n", summary=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("changes no .go line", r.summary)
        # MUT-waiver-store-claim-fu R1 (#5812): the message also names the record, which claims a package too.
        self.assertIn("and no MUTANTS-EQUIVALENT record of one", r.summary)


# A fixture module pins broker/go.mod's toolchain, whose gofmt mutgate needs (#6442).
TOOLCHAIN = re.search(r"^toolchain\s+(\S+)$", (ROOT / "broker" / "go.mod").read_text(), re.M)[1]
GO_MOD = f"module example.invalid/broker\n\ngo 1.22\n\ntoolchain {TOOLCHAIN}\n"
# hint.go before the PR: one function the tests call.
BASE_SRC = """package hint

func Keep(n int) int {
	return n
}
"""
# The PR adds a reset the tests check, a guard they do not, a function they never call, and a
# statement whose deletion does not compile. Keep's `return n` is the base's line, so not a site.
PR_SRC = """package hint

var count int

func Keep(n int) int {
	count = n
	if n < 0 {
		n = 0
	}
	return n
}

func Never() {
	count = 0
}

func Last() int {
	return count
}
"""
TEST_SRC = """package hint

import "testing"

// REQ: CRED-1
func TestKeep(t *testing.T) {
	if Keep(3) != 3 || count != 3 || Last() != 3 {
		t.Fatal("keep")
	}
}
"""


class Deletion(unittest.TestCase):
    # MUTGATE-stmt-delete (#4573): gremlins v0.6.0 has no mutator that deletes a statement, so
    # `delete` deletes each statement starting on an added line alone and reports it as a mutant.
    def lister(self, d):
        out = pathlib.Path(d) / "stmts"
        subprocess.run(["go", "build", "-o", str(out), str(mutgate.STMTS)], cwd=d, check=True,
                       env={**os.environ, "GOFLAGS": "", "GOWORK": "off"})
        return out

    def test_lister_lists_statements_not_declarations(self):
        src = ("package p\n\nfunc f(c chan int) (n int) {\n\tvar a int\n\tb := 1\n\ta = b\n\tn++\n"
               "\tif a > 0 {\n\t\treturn\n\t}\n\tswitch {\n\tcase a > 1:\n\t\tg()\n\t}\n\tc <- n; ;\n"
               "\treturn n\n}\n\nfunc g() {}\n")
        with tempfile.TemporaryDirectory() as d:
            (pathlib.Path(d) / "p.go").write_text(src)
            r = subprocess.run([str(self.lister(d)), str(pathlib.Path(d) / "p.go")], capture_output=True, check=True)
            sites = json.loads(r.stdout)
        got = sorted((s["line"], src.encode()[s["start"]:s["end"]].decode()) for s in sites)
        self.assertEqual(got, [(6, "a = b"), (7, "n++"), (8, "if a > 0 {\n\t\treturn\n\t}"), (9, "return"),
                               (11, "switch {\n\tcase a > 1:\n\t\tg()\n\t}"), (12, "case a > 1:\n\t\tg()"), (13, "g()"), (15, "c <- n"),
                               (16, "return n")])
        self.assertTrue(all(s["file"] == "p.go" and s["col"] >= 2 for s in sites))
        # A clause's cover block starts after its colon, so its coverage is its switch's (L3 on #4597).
        cover = {(s["line"], s["col"]): (s["cover_line"], s["cover_col"]) for s in sites}
        self.assertEqual(cover[(12, 2)], (11, 2))
        self.assertEqual(cover[(13, 3)], (13, 3))
        # A compound statement's lines are its header's, not its body's (#4603).
        self.assertEqual({s["line"]: s["lines"] for s in sites}[8], [8])

    def test_lister_lines_are_the_statements_own_syntax(self):
        # #4603: an edit to any line of a statement's own syntax makes it a site; a nested block's
        # inner lines (its statements are sites of their own), comments and blank lines do not.
        src = ("package p\n\nfunc f(a, b int) {\n\tg(a,\n\t\tb, // note\n\t\t// only a comment\n\n\t\ta)\n"
               "\tif a > 0 &&\n\t\tb > 0 {\n\t\tg(1)\n\t} else if b < 0 {\n\t\tg(2)\n\t} else {\n\t\ta++\n\t}\n"
               "\tg(len(`raw\nline`))\n\tdefer func() {\n\t\tg(3)\n\t}()\n\tswitch {\n\tcase a > 1,\n\t\tb > 1:\n"
               "\t\tg(4)\n\t}\n}\n\nfunc g(...int) {}\n")
        with tempfile.TemporaryDirectory() as d:
            (pathlib.Path(d) / "p.go").write_text(src)
            r = subprocess.run([str(self.lister(d)), str(pathlib.Path(d) / "p.go")], capture_output=True, check=True)
            got = {s["line"]: s["lines"] for s in json.loads(r.stdout)}
        self.assertEqual(got, {
            4: [4, 5, 8],            # g(a, b, a): not the comment or blank lines
            9: [9, 10, 12, 14],      # if: its condition, else-if header and else, not its bodies
            11: [11], 13: [13], 15: [15],
            17: [17, 18],            # a raw string's every line
            19: [19, 21], 20: [20],  # defer: not the func literal's body
            22: [22],                # switch: its clauses are sites of their own
            23: [23, 24],            # case: through its colon, not its body
            25: [25],
        })

    def test_deleted_keeps_every_other_line_where_it_was(self):
        src = b"a\n\tif x {\n\t\ty()\n\t}\nz\n"
        start = src.index(b"if")
        site = {"start": start, "end": src.index(b"}") + 1}
        self.assertEqual(mutgate.deleted(src, site), b"a\n\t\n\n\nz\n")

    def test_coverage_counts_only_blocks_that_ran(self):
        prof = ("mode: set\nexample.invalid/broker/hint/hint.go:5.24,7.11 2 1\n"
                "example.invalid/broker/hint/hint.go:13.14,15.2 1 0\n")
        blocks = mutgate.covered_blocks(prof)
        self.assertTrue(mutgate.is_covered(blocks, {"file": "hint.go", "cover_line": 6, "cover_col": 2}))
        self.assertTrue(mutgate.is_covered(blocks, {"file": "hint.go", "cover_line": 5, "cover_col": 24}))
        self.assertFalse(mutgate.is_covered(blocks, {"file": "hint.go", "cover_line": 7, "cover_col": 11}))
        self.assertFalse(mutgate.is_covered(blocks, {"file": "hint.go", "cover_line": 14, "cover_col": 2}))
        self.assertFalse(mutgate.is_covered(blocks, {"file": "other.go", "cover_line": 6, "cover_col": 2}))

    def test_a_test_run_past_its_timeout_is_timed_out_and_its_children_killed(self):
        with tempfile.TemporaryDirectory() as d:
            stub = pathlib.Path(d) / "t.test"
            pid = pathlib.Path(d) / "pid"
            stub.write_text(f"#!/bin/sh\nsleep 60 &\necho $! > {pid}\nwait\n")
            stub.chmod(0o755)
            self.assertEqual(mutgate.run_tests(stub, d, 1), "TIMED OUT")
            # The test binary's own child is gone too (dead, or a zombie awaiting its reaper).
            state = pathlib.Path(f"/proc/{int(pid.read_text())}/stat")

            def gone():
                # One read, no exists() check first: the reaper can remove the entry between the two (#4712).
                try:
                    return state.read_text().split(")")[-1].split()[0] in "ZX"
                except (FileNotFoundError, ProcessLookupError):
                    return True
            for _ in range(50):
                if gone():
                    break
                time.sleep(0.1)
            else:
                self.fail("the timed-out test's child still runs")
            (stub).write_text("#!/bin/sh\nexit 0\n")
            self.assertEqual(mutgate.run_tests(stub, d, 5), "LIVED")
            (stub).write_text("#!/bin/sh\nexit 1\n")
            self.assertEqual(mutgate.run_tests(stub, d, 5), "KILLED")

    def test_failed_test_reads_a_flooded_output_bounded(self):
        # MUT-failed-test-bounded (#5834, from #5796): a deletion that loops logging filled BINARY.out
        # with gigabytes, and a whole read raised MemoryError and lost the shard's verdict. Only each
        # end is read, in whole lines; the test that failed is still named from either end.
        # REQ: MUT-failed-test-bounded
        flood = b"http: superfluous response.WriteHeader call\n" * 400
        with tempfile.TemporaryDirectory() as d, mock.patch.object(mutgate, "OUTPUT_READ", 1000):
            binary, out = pathlib.Path(d) / "t.test", pathlib.Path(d) / "t.out"
            reads = []
            real = open

            def counted(*a, **kw):
                f = real(*a, **kw)
                orig = f.read
                f.read = lambda n=-1: reads.append(len(b := orig(n))) or b
                return f
            for name, text, want in (
                    ("before the flood", b"--- FAIL: TestHead (0.01s)\n" + flood, "TestHead"),
                    ("after it", flood + b"--- FAIL: TestTail (9.00s)\n", "TestTail"),
                    ("memory cap", flood + b"\n--- FAIL: memory_cap\n", "memory_cap"),
                    ("in the middle only", flood + b"--- FAIL: TestMid\n" + flood, None),
                    ("short", b"--- FAIL: TestShort\n", "TestShort"),
                    ("cut at the head's end", b"x" * 980 + b"\n--- FAIL: TestLongName\n" + flood, None),
                    # L3 on #5943: a tail with no newline is all one cut line, so it names nothing.
                    ("a tail with no newline", flood + b"--- FAIL: TestCut" + b"z" * 983, None)):
                with self.subTest(name):
                    out.write_bytes(text)
                    reads.clear()
                    with mock.patch("builtins.open", counted):
                        self.assertEqual(mutgate.failed_test(binary), want)
                    self.assertLessEqual(sum(reads), max(len(text), 0) if len(text) <= 2000 else 2000)

    @unittest.skipUnless(os.path.isdir("/proc/self"), "the memory cap reads /proc")
    def test_a_test_run_past_its_memory_cap_is_killed_with_its_children(self):
        # egress on #5011: a deletion that drops a bound grew one test by gigabytes and took the
        # runner down. A child's memory counts too, and the run ends well before its timeout.
        with tempfile.TemporaryDirectory() as d:
            stub = pathlib.Path(d) / "t.test"
            stub.write_text("#!/bin/sh\npython3 -c 'import time; b = bytearray(64 << 20); time.sleep(60)' &\nwait\n")
            stub.chmod(0o755)
            began = time.monotonic()
            self.assertEqual(mutgate.run_tests(stub, d, 30, mem=32 << 20), "KILLED")
            self.assertLess(time.monotonic() - began, 20)
            self.assertEqual(mutgate.failed_test(stub), "memory_cap")  # the table says why (L3 on #5026)
            stub.write_text("#!/bin/sh\nexec python3 -c 'b = bytearray(1 << 20)'\n")
            self.assertEqual(mutgate.run_tests(stub, d, 30, mem=1 << 30), "LIVED")
            stub.write_text("#!/bin/sh\nsleep 60\n")
            self.assertEqual(mutgate.run_tests(stub, d, 1, mem=1 << 30), "TIMED OUT")

    @unittest.skipUnless(os.path.isdir("/proc/self"), "the memory cap reads /proc")
    def test_a_capped_run_kills_a_child_that_left_its_process_group(self):
        # #6392 item 1: the session's memory is counted, so the whole session is killed, a child that
        # moved itself to a group of its own (setpgid) too, not only the run's process group.
        with tempfile.TemporaryDirectory() as d:
            stub, pidfile = pathlib.Path(d) / "t.test", pathlib.Path(d) / "child"
            stub.write_text(f"#!/bin/sh\npython3 -c 'import os, time; os.setpgid(0, 0); open(\"{pidfile}\", \"w\").write(str(os.getpid())); "
                            "b = bytearray(64 << 20); time.sleep(60)' &\nwait\n")
            stub.chmod(0o755)
            began = time.monotonic()
            self.assertEqual(mutgate.run_tests(stub, d, 30, mem=32 << 20), "KILLED")
            self.assertLess(time.monotonic() - began, 20)
            child = int(pidfile.read_text())
            for _ in range(100):  # reparented and reaped, or a zombie: nothing left running
                if (mutgate.proc_stat(child) or ("", "Z"))[1] in "ZX":
                    break
                time.sleep(0.05)
            self.assertIn((mutgate.proc_stat(child) or ("", "Z"))[1], "ZX")

    @unittest.skipUnless(os.path.isdir("/proc/self"), "the memory cap reads /proc")
    def test_kill_session_leaves_other_sessions_alone(self):
        with tempfile.TemporaryDirectory() as d:
            pidfile = pathlib.Path(d) / "child"
            p = subprocess.Popen(["sh", "-c", f"python3 -c 'import os, time; os.setpgid(0, 0); "
                                  f"open(\"{pidfile}\", \"w\").write(str(os.getpid())); time.sleep(60)' & sleep 60"],
                                 start_new_session=True)
            other = subprocess.Popen(["sleep", "60"], start_new_session=True)
            try:
                for _ in range(200):
                    if pidfile.exists() and pidfile.read_text():
                        break
                    time.sleep(0.05)
                child = int(pidfile.read_text())
                self.assertNotEqual(os.getpgid(child), p.pid)  # its own group: killpg alone misses it
                mutgate.kill_session(p.pid)
                self.assertEqual(p.wait(), -signal.SIGKILL)
                self.assertEqual(mutgate.session_procs(p.pid), [])
                self.assertIsNone(other.poll())
            finally:
                other.kill()
                other.wait()

    @unittest.skipUnless(os.path.isdir("/proc/self"), "the memory cap reads /proc")
    def test_a_spike_between_reads_still_counts(self):
        # #6392 item 2: a base run's peak is the kernel's high-water mark, so a spike that ends between
        # two reads still counts; a run that ends before any read counts its whole-life peak (wait4).
        spike = "import time; b = bytearray(128 << 20); del b; time.sleep({})"
        with mock.patch.object(mutgate, "MEM_POLL", 1.0):
            for rest in (2.5, 0):  # read once after the spike, or never
                with self.subTest(rest=rest):
                    p = subprocess.Popen([sys.executable, "-c", spike.format(rest)], start_new_session=True)
                    end, peak = mutgate.watch(p, 30)
                    self.assertEqual(end, 0)
                    self.assertGreater(peak, 128 << 20)
            p = subprocess.Popen([sys.executable, "-c", spike.format(2.5)], start_new_session=True)
            time.sleep(1.5)
            rss = sum(r for r, _ in mutgate.session_memory(p.pid).values())
            p.wait()
            self.assertLess(rss, 64 << 20)  # what a read of the current memory alone saw after it

    def test_ci_without_a_delegated_cgroup_is_an_error(self):
        # #6392: in CI every run is in a cgroup leaf; a missing or unusable one fails, never advisory.
        with tempfile.TemporaryDirectory() as d:
            for env in ({"CI": "true"}, {"GITHUB_ACTIONS": "true"}, {mutgate.CGROUP_ENV: d}):
                with self.subTest(env=env), mock.patch.dict(os.environ, env, clear=False):
                    for k in {"CI", "GITHUB_ACTIONS", mutgate.CGROUP_ENV} - set(env):
                        os.environ.pop(k, None)
                    with self.assertRaises(RuntimeError):
                        mutgate.contained(["true"])
                    with self.assertRaises(RuntimeError):
                        mutgate.advisory()
        with mock.patch.dict(os.environ, {}, clear=False):
            for k in ("CI", "GITHUB_ACTIONS", mutgate.CGROUP_ENV):
                os.environ.pop(k, None)
            with contextlib.redirect_stderr(io.StringIO()) as err:
                self.assertTrue(mutgate.advisory())
            self.assertIn("ADVISORY", err.getvalue())

    def test_verify_refuses_an_advisory_result(self):
        data = {"files": [], "mutants_total": 0, "mutants_lived": 0, "shard": {"index": 0, "of": 1}, "advisory": True}
        _, problem = mutgate.join_shards("hint", [(pathlib.Path("a/hint.json"), data)], {}, {}, None, {})
        self.assertIn("advisory", problem)

    @unittest.skipUnless(os.environ.get(mutgate.CGROUP_ENV), "needs a delegated cgroup v2 directory (CI's checks job)")
    def test_a_cgroup_leaf_holds_every_descendant_and_its_exact_peak(self):
        # #6392: a child that leaves the session (setsid) and its process group is still in the leaf: the
        # cap kills it and the run's end kills it; the peak is memory.peak, a spike between reads included.
        with tempfile.TemporaryDirectory() as d:
            pidfile = pathlib.Path(d) / "child"
            grow = (f"import os, time; os.setsid(); open('{pidfile}', 'w').write(str(os.getpid())); "
                    "b = bytearray(64 << 20); time.sleep(60)")
            stub = pathlib.Path(d) / "t.test"
            stub.write_text(f"#!/bin/sh\npython3 -c \"{grow}\" &\nwait\n")
            stub.chmod(0o755)
            began = time.monotonic()
            self.assertEqual(mutgate.run_tests(stub, d, 30, mem=32 << 20), "KILLED")
            self.assertLess(time.monotonic() - began, 20)
            self.assertIn((mutgate.proc_stat(int(pidfile.read_text())) or ("", "Z"))[1], "ZX")
            # Left running when the run ends: killed with the leaf.
            stub.write_text(f"#!/bin/sh\npython3 -c \"{grow.replace('64 << 20', '1')}\" &\nsleep 1\n")
            self.assertEqual(mutgate.run_tests(stub, d, 30, mem=1 << 30), "LIVED")
            self.assertIn((mutgate.proc_stat(int(pidfile.read_text())) or ("", "Z"))[1], "ZX")
            end, peak = mutgate.contained([sys.executable, "-c", "b = bytearray(128 << 20); del b"], 1 << 30)
            self.assertEqual(end, 0)
            self.assertGreater(peak, 128 << 20)
            self.assertEqual([p.name for p in pathlib.Path(os.environ[mutgate.CGROUP_ENV]).glob("run-*")], [])

    def test_available_memory_reads_meminfo(self):
        got = mutgate.available_memory()
        if os.path.isfile("/proc/meminfo"):
            self.assertGreater(got, 0)
        else:
            self.assertIsNone(got)

    def repo(self, d, base_src=BASE_SRC, pr_src=PR_SRC, test_src=TEST_SRC):
        git = lambda *a: subprocess.run(["git", "-C", d, *a], check=True, capture_output=True, text=True)
        shutil.copytree(ROOT / "tools", pathlib.Path(d) / "tools")
        shutil.copytree(ROOT / "broker" / "core", pathlib.Path(d) / "broker" / "core")
        (pathlib.Path(d) / "broker" / "go.mod").write_text(GO_MOD)
        pkg = pathlib.Path(d) / "broker" / "hint"
        pkg.mkdir()
        (pkg / "hint.go").write_text(base_src)
        # The tests are the base's, so the diff changes only hint.go: its own lines are the targets.
        (pkg / "hint_test.go").write_text(test_src)
        git("init", "-q")
        git("add", "-A")
        git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "-m", "base")
        (pkg / "hint.go").write_text(pr_src)
        git("add", "-A")
        git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "-m", "pr")
        return pkg

    def mutgate(self, d, *args):
        as_ci(args)
        return subprocess.run([sys.executable, "-I", str(pathlib.Path(d) / "tools" / "mutgate.py"), *args],
                              capture_output=True, text=True, env={**os.environ, "GOFLAGS": "", "GOWORK": "off"})

    def test_delete_adds_a_verdict_for_each_statement_on_an_added_line_and_verify_gates_it(self):
        with tempfile.TemporaryDirectory() as d:
            pkg = self.repo(d)
            before = (pkg / "hint.go").read_text()
            out = pathlib.Path(d) / "res" / "mutants-0"
            out.mkdir(parents=True)
            # gremlins' result (here one killed operator mutant) is what `delete` adds to.
            (out / "hint.json").write_text(json.dumps({"files": [{"file_name": "hint.go", "mutations": [
                {"type": "CONDITIONALS_BOUNDARY", "status": "KILLED", "line": 7}]}], "mutants_lived": 0}))
            # Without `delete`, verify refuses gremlins' result alone.
            r = self.mutgate(d, "verify", str(out.parent), "--git", "HEAD~1")
            self.assertIn("holds no statement-deletion pass", r.stderr)
            r = self.mutgate(d, "delete", "hint", "--out", str(out), "--git", "HEAD~1")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertEqual((pkg / "hint.go").read_text(), before)  # the overlay left the tree as it was
            data = json.loads((out / "hint.json").read_text())
            got = sorted((m["line"], m["type"], m["status"]) for m in data["files"][0]["mutations"])
            self.assertEqual(got, [
                (6, mutgate.DELETION, "KILLED"),       # count = n: the test reads count
                (7, "CONDITIONALS_BOUNDARY", "KILLED"),
                (7, mutgate.DELETION, "LIVED"),        # the n < 0 guard: no test gives a negative n
                (8, mutgate.DELETION, "NOT COVERED"),  # n = 0 never runs
                (14, mutgate.DELETION, "NOT COVERED"),  # Never is never called
                (18, mutgate.DELETION, "NOT VIABLE"),  # Last's return
            ])
            self.assertEqual((data["statement_deletions"], data["mutants_lived"], data["mutants_total"]), (5, 1, 5))
            # #4908: a deletion's verdict names the test that failed first, for the summary table.
            self.assertEqual({m["line"]: m.get("killed_by") for m in data["files"][0]["mutations"]
                              if m["type"] == mutgate.DELETION and m["status"] == "KILLED"}, {6: "TestKeep"})
            # A second pass on the same result is refused, not counted twice.
            r = self.mutgate(d, "delete", "hint", "--out", str(out), "--git", "HEAD~1")
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("not one gremlins result without deletions", r.stderr)
            # The gate reads a deletion mutant as it reads gremlins' own.
            r = self.mutgate(d, "verify", str(out.parent), "--git", "HEAD~1")
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("broker/hint/hint.go:7 deleting the whole statement holding line 7 survives", r.stdout)

    def deletion_verdicts(self, base_src, pr_src, test_src, jobs=None):
        """{line: status} of `delete`'s STATEMENT_DELETION mutants on a repo built from these sources."""
        with tempfile.TemporaryDirectory() as d:
            self.repo(d, base_src, pr_src, test_src)
            out = pathlib.Path(d) / "out"
            out.mkdir()
            (out / "hint.json").write_text(json.dumps({"files": [], "mutants_lived": 0}))
            r = self.mutgate(d, "delete", "hint", "--out", str(out), "--git", "HEAD~1", *(["--jobs", jobs] if jobs else []))
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            data = json.loads((out / "hint.json").read_text())
        return {m["line"]: m["status"] for f in data["files"] for m in f["mutations"]}

    def test_shards_of_the_deletion_pass_join_to_the_unsharded_verdicts(self):
        # #4961: each shard deletes every K-th site, alone, with the whole suite; the union of the
        # shards' mutants is the unsharded pass's, verdicts and killers included.
        def mutants(d, shard):
            out = pathlib.Path(d) / f"out-{shard}"
            out.mkdir()
            rec = {} if shard is None else {"shard": {"index": shard[0], "of": shard[1]}}
            (out / "hint.json").write_text(json.dumps({"files": [], "mutants_lived": 0, **rec}))
            r = self.mutgate(d, "delete", "hint", "--out", str(out), "--git", "HEAD~1", "--jobs", "1")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            data = json.loads((out / "hint.json").read_text())
            return sorted(json.dumps({**m, "file": f["file_name"]}, sort_keys=True)
                          for f in data["files"] for m in f["mutations"])
        with tempfile.TemporaryDirectory() as d:
            self.repo(d)
            whole = mutants(d, None)
            self.assertEqual(len(whole), 5)
            for of in (2, 3, 6):
                with self.subTest(of):
                    parts = [mutants(d, (i, of)) for i in range(of)]
                    self.assertEqual(sorted(sum(parts, [])), whole)
                    self.assertTrue(all(len(p) <= -(-5 // of) for p in parts), parts)

    def test_a_guard_that_is_its_variables_only_use_is_deleted_and_tested(self):
        # Security on #4597: deleting `if err != nil { ... }` leaves err unused and does not build,
        # so the pass keeps err (and an import) in use with `_ =` and tests the deletion.
        pr = """package hint

import (
	"errors"
	e2 "errors"
)

func check(s string) error {
	if len(s) > 5 {
		return errors.New("long")
	}
	return nil
}

func Allow(s string) bool {
	err := check(s)
	if err != nil {
		return false
	}
	ok := len(s) > 0
	if !ok {
		return false
	}
	_ = e2.New("x")
	return true
}
"""
        test = """package hint

import "testing"

// REQ: CRED-1
func TestAllow(t *testing.T) {
	if !Allow("abc") {
		t.Fatal("allow")
	}
}
"""
        got = self.deletion_verdicts("package hint\n", pr, test)
        self.assertEqual(got[17], "LIVED")       # if err != nil: err kept with `_ = err`
        self.assertEqual(got[21], "LIVED")       # if !ok
        self.assertEqual(got[24], "LIVED")       # e2's only use: the import renamed `_`
        self.assertEqual(got[10], "NOT COVERED")  # return errors.New("long") never runs

    def test_a_case_clause_is_covered_when_its_switch_ran(self):
        # L3 on #4597: a clause's cover block starts after its colon (or is empty), so a covered
        # empty guard clause read NOT COVERED and its deletion passed.
        base = """package hint

func Class(n int) string {
	switch {
	default:
		return "other"
	}
}
"""
        pr = """package hint

func Class(n int) string {
	switch {
	case n < 0:
	case n > 9:
		return "big"
	default:
		return "other"
	}
	return "neg"
}

func Pick(c chan int) int {
	select {
	case v := <-c:
		return v
	default:
	}
	return -1
}
"""
        test = """package hint

import "testing"

// REQ: CRED-1
func TestClass(t *testing.T) {
	if Class(1) != "other" || Class(10) != "big" {
		t.Fatal("class")
	}
	c := make(chan int, 1)
	c <- 4
	if Pick(c) != 4 {
		t.Fatal("pick")
	}
}
"""
        got = self.deletion_verdicts(base, pr, test)
        self.assertEqual(got[5], "LIVED")    # case n < 0: no test gives a negative n
        self.assertEqual(got[6], "KILLED")   # case n > 9: Class(10) checks it
        self.assertEqual(got[16], "KILLED")  # case v := <-c: Pick(c) checks it
        self.assertEqual(got[18], "LIVED")   # default: no test reads an empty channel

    def test_a_clause_that_is_a_variables_only_use_is_deleted_and_tested(self):
        # Round 2 on #4597: a deleted clause's `_ = NAME` cannot stand in a switch or select body,
        # so it goes after a sibling clause's colon, before the select, or in a lone `default:`.
        pr = """package hint

import "strconv"

func Allow(s string) string {
	a, err := strconv.Atoi(s)
	switch {
	case err != nil:
		return "deny"
	default:
		return strconv.Itoa(a)
	}
}

func Good(s string) string {
	switch good := s != ""; {
	case !good:
		return "deny"
	}
	return "ok"
}

func Kind(x any) string {
	switch v := x.(type) {
	case int:
		return strconv.Itoa(v)
	default:
		return "other"
	}
}

func Drain(c chan int, stop chan bool) int {
	n := 0
	select {
	case <-stop:
		return n
	case v := <-c:
		return v
	}
}

func Loop(xs []int) int {
	t := 0
L:
	for _, x := range xs {
		if x < 0 {
			break L
		}
		t += x
	}
	return t
}
"""
        test = """package hint

import "testing"

// REQ: CRED-1
func TestAll(t *testing.T) {
	if Allow("12") != "12" || Good("x") != "ok" || Kind("s") != "other" || Loop([]int{1, -1, 2}) != 1 {
		t.Fatal("all")
	}
	c := make(chan int, 1)
	c <- 4
	if Drain(c, make(chan bool)) != 4 {
		t.Fatal("drain")
	}
}
"""
        got = self.deletion_verdicts("package hint\n", pr, test, "1")  # one worker: no rerun of the timeout
        self.assertEqual(got[8], "LIVED")    # case err != nil: err kept after default's colon
        self.assertEqual(got[17], "LIVED")   # case !good: the only clause, so `default: _ = good`
        self.assertEqual(got[25], "LIVED")   # case int: v kept in the default clause
        self.assertEqual(got[35], "LIVED")   # case <-stop: n kept before the select
        self.assertEqual(got[37], "TIMED OUT")  # case v := <-c: Drain(c) blocks without it
        # Deleting `if x < 0 { break L }` or `break L` leaves L unused: the label is dropped and tested.
        self.assertEqual((got[46], got[47]), ("KILLED", "KILLED"))
        # Every NOT VIABLE left is a deletion that leaves a function without its return.
        self.assertEqual(sorted(k for k, v in got.items() if v == "NOT VIABLE"), [7, 10, 11, 20, 24, 27, 28, 34, 38, 51])

    def test_an_edit_to_a_later_line_deletes_the_statement(self):
        # #4603: the PR edits only the second line of a call; the call is deleted, its verdict
        # reported on that line. A body-only edit deletes the body's statement, not its if.
        base = """package hint

var count int

func Keep(n int) int {
	set(n,
		0)
	if n > 50 {
		count = 1
	}
	return n
}

func set(n, m int) {
	if n > 100 {
		count = n + m
	}
}
"""
        pr = base.replace("\t\t0)", "\t\t1)").replace("count = 1", "count = 2")
        test = TEST_SRC.replace("count != 3 || Last() != 3", "false")
        got = self.deletion_verdicts(base, pr, test)
        self.assertEqual(got, {7: "LIVED", 9: "NOT COVERED"})

    def test_parallel_workers_give_the_serial_verdicts(self):
        # #4633: sites run on parallel workers, each in its own directory.
        verdicts = [self.deletion_verdicts(BASE_SRC, PR_SRC, TEST_SRC, jobs) for jobs in ("1", "3")]
        self.assertEqual(verdicts[0], verdicts[1])
        self.assertEqual(verdicts[0], {6: "KILLED", 7: "LIVED", 8: "NOT COVERED", 14: "NOT COVERED", 18: "NOT VIABLE"})

    def test_a_site_detected_on_a_worker_runs_again_alone(self):
        # #4633, Potency on #4643: a loaded runner can slow a passing run past its timeout or fail a
        # wall-clock bound, which reads as detected, so a parallel TIMED OUT or KILLED runs its own
        # binary again alone and that verdict stands.
        with tempfile.TemporaryDirectory() as d:
            pkg = self.repo(d)
            added = mutgate.added_lines(subprocess.run(
                ["git", "-C", d, "diff", "-U0", "--src-prefix=a/", "--dst-prefix=b/", "HEAD~1", "--", "broker"],
                capture_output=True, text=True, check=True).stdout)[0]
            calls, first = [], ["TIMED OUT"]
            mems = []
            def fake(binary, cwd, timeout, mem=None, names=None):
                self.assertTrue(pathlib.Path(binary).is_file())  # the worker's own binary, kept for the rerun
                calls.append(pathlib.Path(binary).parent.name)
                mems.append(mem)
                return "LIVED" if calls.count(calls[-1]) > 1 else first[0]
            broker, run_tests = mutgate.BROKER, mutgate.run_tests
            mutgate.BROKER, mutgate.run_tests = pkg.parent, fake
            try:
                tmp = pathlib.Path(d) / "tmp"
                for jobs, first[0], want in ((1, "TIMED OUT", "TIMED OUT"), (3, "TIMED OUT", "LIVED"),
                                             (1, "KILLED", "KILLED"), (3, "KILLED", "LIVED")):
                    calls.clear()
                    tmp.mkdir()
                    got, problem = mutgate.deletion_mutants("hint", added, tmp, self.lister(tmp), jobs)
                    shutil.rmtree(tmp)
                    self.assertIsNone(problem)
                    self.assertEqual({m["line"]: m["status"] for m in got if m["line"] in (6, 7)}, {6: want, 7: want})
                    self.assertEqual(len(calls), 2 * (jobs > 1) + 2)
                    # A parallel run gets 1/jobs of the cap a run alone gets (egress on #5011).
                    alone = mems[-1]
                    self.assertTrue(alone is None or alone > 0)
                    if alone and jobs > 1:
                        self.assertEqual(mems[:2], [alone // jobs] * 2)
                    mems.clear()
            finally:
                mutgate.BROKER, mutgate.run_tests = broker, run_tests

    @unittest.skipUnless(os.path.isdir("/proc/self"), "the memory cap reads /proc")
    def test_a_package_whose_unmutated_tests_near_the_memory_cap_is_a_problem(self):
        # L3 on #5026: were the base run unmeasured, a suite that already holds more than the cap
        # would read every covered deletion KILLED, the one that lives (line 7) too.
        heavy = TEST_SRC.replace('import "testing"', 'import (\n\t"testing"\n\t"time"\n)') + (
            "\nvar Sink []byte\n\nfunc TestHeavy(t *testing.T) {\n\tSink = make([]byte, 96<<20)\n"
            "\tfor i := range Sink {\n\t\tSink[i] = 1\n\t}\n\ttime.Sleep(time.Second)\n}\n")
        with tempfile.TemporaryDirectory() as d:
            pkg = self.repo(d, test_src=heavy)
            added = mutgate.added_lines(subprocess.run(
                ["git", "-C", d, "diff", "-U0", "--src-prefix=a/", "--dst-prefix=b/", "HEAD~1", "--", "broker"],
                capture_output=True, text=True, check=True).stdout)[0]
            broker, avail = mutgate.BROKER, mutgate.available_memory
            mutgate.BROKER = pkg.parent
            try:
                for free in (128 << 20, 320 << 20):  # cap 64 MB: over it; cap 160 MB: under it, without the headroom
                    mutgate.available_memory = lambda: free
                    tmp = pathlib.Path(d) / "tmp"
                    tmp.mkdir()
                    got, problem = mutgate.deletion_mutants("hint", added, tmp, self.lister(tmp), 1)
                    shutil.rmtree(tmp)
                    self.assertIsNone(got)
                    self.assertIn("before any statement is deleted", problem)
                    self.assertIn("memory cap", problem)
                mutgate.available_memory = lambda: 8 << 30  # ample: the gate runs and line 7 lives
                tmp = pathlib.Path(d) / "tmp"
                tmp.mkdir()
                got, problem = mutgate.deletion_mutants("hint", added, tmp, self.lister(tmp), 1)
            finally:
                mutgate.BROKER, mutgate.available_memory = broker, avail
            self.assertIsNone(problem)
            self.assertEqual({m["line"]: m["status"] for m in got if m["line"] in (6, 7)}, {6: "KILLED", 7: "LIVED"})

    def test_lines_only_a_re_executed_child_runs_are_covered_and_mutated(self):
        # #5803 (Security on #5800): a test binary re-executed as a child (proc.Main's driver) writes
        # its counters only where GOCOVERDIR says, so the base run's profile must merge them, or the
        # child's lines read NOT COVERED instead of being mutated. Without GOCOVERDIR the child also
        # prints a warning, which failed proc's output checks before any deletion; the test checks that too.
        pr = ("package hint\n\nimport \"os\"\n\nvar count int\n\nfunc Child() {\n"
              "\tif os.Getenv(\"HINT_CHILD\") != \"1\" {\n\t\treturn\n\t}\n\tcount = 7\n\tos.Exit(count)\n}\n")
        test = ("package hint\n\nimport (\n\t\"errors\"\n\t\"os\"\n\t\"os/exec\"\n\t\"testing\"\n)\n\n"
                "func TestMain(m *testing.M) {\n\tChild()\n\tos.Exit(m.Run())\n}\n\n"
                "// REQ: CRED-1\nfunc TestChild(t *testing.T) {\n"
                "\tc := exec.Command(os.Args[0], \"-test.run=^$\")\n"
                "\tc.Env = append(os.Environ(), \"HINT_CHILD=1\")\n"
                "\tvar e *exec.ExitError\n"
                "\tout, err := c.CombinedOutput()\n"
                "\tif !errors.As(err, &e) || e.ExitCode() != 7 || len(out) != 0 {\n\t\tt.Fatal(err, string(out))\n\t}\n}\n")
        with tempfile.TemporaryDirectory() as d:
            pkg = self.repo(d, "package hint\n", pr, test)
            added = mutgate.added_lines(subprocess.run(
                ["git", "-C", d, "diff", "-U0", "--src-prefix=a/", "--dst-prefix=b/", "HEAD~1", "--", "broker"],
                capture_output=True, text=True, check=True).stdout)[0]
            broker, mutgate.BROKER = mutgate.BROKER, pkg.parent
            try:
                tmp = pathlib.Path(d) / "tmp"
                tmp.mkdir()
                got, problem = mutgate.deletion_mutants("hint", added, tmp, self.lister(tmp), 1)
            finally:
                mutgate.BROKER = broker
            self.assertIsNone(problem)
            # Lines 11 and 12 run only in the child; 8 and 9 in the parent, as before.
            self.assertEqual({m["line"]: m["status"] for m in got}, {8: "KILLED", 9: "KILLED", 11: "KILLED", 12: "KILLED"})

    # MUT-delete-covering (#6172): a fixture where each test reaches only some sites, so a site runs
    # with the tests whose run alone covers it, not the whole suite.
    COVER_PR = ("package hint\n\nvar count, other int\n\nfunc Keep(n int) int {\n\tcount = n\n\tif n < 0 {\n"
                "\t\tn = 0\n\t}\n\treturn n\n}\n\nfunc Side(n int) int {\n\tother = n\n\treturn n + 1\n}\n")
    COVER_TEST = ("package hint\n\nimport \"testing\"\n\n// REQ: CRED-1\nfunc TestKeep(t *testing.T) {\n"
                  "\tif Keep(3) != 3 || count != 3 {\n\t\tt.Fatal(\"keep\")\n\t}\n}\n\n"
                  "func TestSide(t *testing.T) {\n\tif Side(1) != 2 {\n\t\tt.Fatal(\"side\")\n\t}\n}\n\n"
                  "func TestNothing(t *testing.T) {}\n"
                  + "".join(f"\nfunc TestPad{i}(t *testing.T) {{}}\n" for i in range(4)))

    @staticmethod
    def even(per):
        """per_test with every test's seconds alone read as 1.0, so `selected`'s half rule decides
        the same set on any runner: run times of near-empty tests are noise (#6172's rerun test went
        red on #5998 when TestBreak and TestUse ran slow)."""
        def timed(*a, **k):
            if (got := per(*a, **k)) is None:
                return None
            ran, failing = got
            return {n: (blocks, 1.0) for n, (blocks, _) in ran.items()}, {n: 1.0 for n in failing}
        return timed

    def spied_deletions(self, pr, test, whole=False, jobs=1, patches=None):
        """({line: status}, [(site dir, names)]) of deletion_mutants on a repo of these sources, with
        each run_tests call's tests recorded; whole runs every site with the whole suite (no per-test
        pass); patches ({name: value}) replaces those mutgate names first, run_tests under the spy.
        per_test's seconds are `even` unless patches replaces it."""
        from unittest import mock
        with tempfile.TemporaryDirectory() as d:
            pkg = self.repo(d, "package hint\n", pr, test)
            added = mutgate.added_lines(subprocess.run(
                ["git", "-C", d, "diff", "-U0", "--src-prefix=a/", "--dst-prefix=b/", "HEAD~1", "--", "broker"],
                capture_output=True, text=True, check=True).stdout)[0]
            calls, real = [], (patches or {}).get("run_tests", mutgate.run_tests)
            def spy(binary, cwd, timeout, mem=None, names=None):
                calls.append((pathlib.Path(binary).parent.name, names))
                return real(binary, cwd, timeout, mem=mem, names=names)
            with contextlib.ExitStack() as st:
                for name, value in (patches or {}).items():
                    st.enter_context(mock.patch.object(mutgate, name, value))
                st.enter_context(mock.patch.object(mutgate, "BROKER", pkg.parent))
                st.enter_context(mock.patch.object(mutgate, "run_tests", spy))
                if whole:
                    st.enter_context(mock.patch.object(mutgate, "per_test", lambda *a, **k: None))
                elif "per_test" not in (patches or {}):
                    st.enter_context(mock.patch.object(mutgate, "per_test", self.even(mutgate.per_test)))
                tmp = pathlib.Path(d) / "tmp"
                tmp.mkdir()
                got, problem = mutgate.deletion_mutants("hint", added, tmp, self.lister(tmp), jobs)
            self.assertIsNone(problem)
        return {m["line"]: m["status"] for m in got}, calls

    def test_each_site_runs_only_the_tests_that_cover_it_with_the_whole_suites_verdicts(self):
        # REQ: MUT-delete-covering
        whole, wcalls = self.spied_deletions(self.COVER_PR, self.COVER_TEST, whole=True)
        self.assertEqual(whole, {6: "KILLED", 7: "LIVED", 8: "NOT COVERED", 10: "NOT VIABLE", 14: "LIVED", 15: "NOT VIABLE"})
        self.assertTrue(all(names is None for _, names in wcalls))
        for jobs in (1, 3):
            with self.subTest(jobs=jobs):
                got, calls = self.spied_deletions(self.COVER_PR, self.COVER_TEST, jobs=jobs)
                self.assertEqual(got, whole)
                # Keep's sites run TestKeep alone, Side's TestSide alone; TestNothing covers neither.
                ran = {names and tuple(names) for _, names in calls}
                self.assertEqual(ran, {("TestKeep",), ("TestSide",)})

    def test_a_kill_from_a_test_set_that_fails_unmutated_reruns_the_whole_suite(self):
        # #6172's soundness question: TestUse passes alone and in the whole suite, but after TestBreak
        # (which also covers line 6) without TestFix between them it fails, so the set {TestBreak,
        # TestUse} fails whatever is deleted. Its failure on a mutant is no kill: the set is run
        # unmutated, fails, and the whole suite decides (line 6's deletion lives there).
        # REQ: MUT-delete-covering
        pr = "package hint\n\nvar count int\n\nfunc Keep(n int) int {\n\tcount = n\n\treturn n\n}\n"
        test = ("package hint\n\nimport \"testing\"\n\nvar ready = true\n\n// REQ: CRED-1\n"
                "func TestBreak(t *testing.T) {\n\tready = false\n\tKeep(1)\n}\n\n"
                "func TestFix(t *testing.T) {\n\tready = true\n}\n\n"
                "func TestUse(t *testing.T) {\n\tif !ready || Keep(2) != 2 {\n\t\tt.Fatal(\"use\")\n\t}\n}\n"
                # Tests that reach nothing, so the set is under half the suite's runs alone (`selected`).
                + "".join(f"\nfunc TestPad{i}(t *testing.T) {{}}\n" for i in range(4)))
        whole, _ = self.spied_deletions(pr, test, whole=True)
        self.assertEqual(whole, {6: "LIVED", 7: "NOT VIABLE"})
        for jobs in (1, 3):
            with self.subTest(jobs=jobs):
                got, calls = self.spied_deletions(pr, test, jobs=jobs)
                self.assertEqual(got, whole)
                six = [names for site, names in calls if site == "site-0"]
                self.assertEqual(six[0], ["TestBreak", "TestUse"])
                self.assertIsNone(six[-1])  # the set failed unmutated: the whole suite's verdict stands

    def test_a_set_past_half_the_memory_cap_unmutated_reruns_the_whole_suite(self):
        # #6217 (Security on #6213): a set's kill stands only if the set, run unmutated, stays under
        # half the memory cap, as the whole suite must (L3 on #5026); else a deletion that lives could
        # read KILLED by the cap. TestKeep's unmutated run is made to report exactly half (it stands)
        # or one byte more (the whole suite decides line 6).
        # REQ: MUT-delete-covering
        real = mutgate.run_alone
        for over, last in ((0, ["TestKeep"]), (1, None)):
            with self.subTest(over=over):
                caps = []
                def alone(binary, cwd, args, timeout, mem, counters=None):
                    end, top, secs = real(binary, cwd, args, timeout, mem, counters)
                    if pathlib.Path(binary).name == "plain.test":
                        caps.append(mem)
                        top = mem // 2 + over
                    return end, top, secs
                got, calls = self.spied_deletions(self.COVER_PR, self.COVER_TEST, patches={
                    "run_alone": alone, "available_memory": lambda: 16 << 30})
                self.assertEqual(got[6], "KILLED")
                self.assertEqual(caps, [8 << 30])  # one unmutated run of the one detected set, under the cap
                six = [names for site, names in calls if site == "site-0"]
                self.assertEqual(six[0], ["TestKeep"])
                self.assertEqual(six[-1], last)

    def test_a_sets_runs_time_out_at_three_times_its_tests_runs_alone(self):
        # #6217 (L3 and Security on #6213): a set's mutant run and its unmutated run time out at three
        # times its tests' runs alone, summed, plus 10 s, not at the whole suite's timeout.
        # REQ: MUT-delete-covering
        seen, timed = [], []
        per, runs, alone = self.even(mutgate.per_test), mutgate.run_tests, mutgate.run_alone
        def per_test(*a, **k):
            seen.append(per(*a, **k))
            return seen[-1]
        def run_tests(binary, cwd, timeout, mem=None, names=None):
            timed.append((names, timeout))
            return runs(binary, cwd, timeout, mem=mem, names=names)
        def run_alone(binary, cwd, args, timeout, mem, counters=None):
            if pathlib.Path(binary).name == "plain.test":
                timed.append((re.fullmatch(r"-test\.run=\^\((.*)\)\$", args[-1])[1].split("|"), timeout))
            return alone(binary, cwd, args, timeout, mem, counters)
        self.spied_deletions(self.COVER_PR, self.COVER_TEST, patches={
            "per_test": per_test, "run_tests": run_tests, "run_alone": run_alone})
        sets = [(names, t) for names, t in timed if names is not None]
        self.assertTrue(any(names == ["TestKeep"] for names, _ in sets), timed)
        self.assertEqual(len(sets), len(timed) - sum(names is None for names, _ in timed))
        for names, t in sets:
            self.assertAlmostEqual(t, 3 * mutgate.set_seconds(names, seen[0]) + 10)

    def test_selected_reads_each_tests_own_coverage(self):
        # REQ: MUT-delete-covering
        site = {"file": "a.go", "cover_line": 5, "cover_col": 2}
        at = lambda line: {"a.go": [((line, 1), (line, 9))]}
        tests = ({"TestA": (at(5), 1.0), "TestB": (at(9), 6.0), "TestC": (at(5), 2.0)}, {})
        self.assertEqual(mutgate.selected(site, tests), ["TestA", "TestC"])
        self.assertEqual(mutgate.set_seconds(["TestA", "TestC"], tests), 3.0)
        # No per-test result, or no test covering the site alone: the whole suite.
        self.assertIsNone(mutgate.selected(site, None))
        self.assertIsNone(mutgate.selected(site, ({"TestB": (at(9), 2.0)}, {})))
        # A set whose runs alone take half the sum of every test's or more costs no less than the
        # whole suite (kernel/sim: each set of disk.go held its slow sweeps), so the whole suite runs.
        self.assertIsNone(mutgate.selected(site, ({"TestA": (at(5), 1.0)}, {})))
        self.assertIsNone(mutgate.selected(site, ({"TestA": (at(5), 3.0), "TestB": (at(9), 3.0)}, {})))
        self.assertEqual(mutgate.selected(site, ({"TestA": (at(5), 2.9), "TestB": (at(9), 3.0)}, {})), ["TestA"])
        # A test that fails alone has no coverage of its own, so it joins every set, timed by its failing run.
        failing = ({"TestA": (at(5), 1.0), "TestB": (at(9), 6.0)}, {"TestF": 2.0})
        self.assertEqual(mutgate.selected(site, failing), ["TestA", "TestF"])
        self.assertEqual(mutgate.set_seconds(["TestA", "TestF"], failing), 3.0)
        self.assertIsNone(mutgate.selected(site, ({"TestA": (at(5), 1.0), "TestB": (at(9), 6.0)}, {"TestF": 9.0})))
        # #6226: the total counts failing-alone seconds too; here they alone keep the set under half.
        tipped = ({"TestA": (at(5), 1.0), "TestB": (at(9), 4.0)}, {"TestF": 2.0})
        self.assertEqual(mutgate.selected(site, tipped), ["TestA", "TestF"])

    def test_per_test_runs_each_test_alone_and_names_those_that_fail_alone(self):
        # REQ: MUT-delete-covering
        test = self.COVER_TEST + ("\nvar order []string\n\nfunc TestFirst(t *testing.T) {\n\torder = append(order, \"first\")\n}\n\n"
                                  "func TestAfterFirst(t *testing.T) {\n\tif len(order) == 0 {\n\t\tt.Fatal(\"alone\")\n\t}\n\tSide(2)\n}\n")
        with tempfile.TemporaryDirectory() as d:
            pkg = self.repo(d, "package hint\n", self.COVER_PR, test)
            binary = pathlib.Path(d) / "b.test"
            subprocess.run(["go", "test", "-c", "-cover", "-covermode=set", "-o", str(binary), "."], cwd=pkg, check=True,
                           env={**os.environ, "GOFLAGS": "", "GOWORK": "off"})
            ran, failing = mutgate.per_test(binary, pkg, d, 60, jobs=2)
        self.assertEqual(list(ran), ["TestKeep", "TestSide", "TestNothing", *(f"TestPad{i}" for i in range(4)), "TestFirst"])
        self.assertEqual(list(failing), ["TestAfterFirst"])
        self.assertTrue(all(secs > 0 for _, secs in ran.values()))
        lines = lambda name: {n for (s, _), (e, _) in ran[name][0].get("hint.go", []) for n in range(s, e + 1)}
        self.assertTrue({6, 7} <= lines("TestKeep") and 14 not in lines("TestKeep"))
        self.assertTrue(14 in lines("TestSide") and 6 not in lines("TestSide"))
        self.assertEqual(lines("TestNothing"), set())

    def test_per_test_runs_a_test_that_failed_beside_another_again_alone(self):
        # #6226 (L3 and Security on #6225): tests that collide on a fixed path when run in parallel
        # each get their own coverage; the one that failed there runs again alone and passes.
        # REQ: MUT-delete-covering
        test = ("package hint\n\nimport (\n\t\"os\"\n\t\"testing\"\n\t\"time\"\n)\n\n"
                "// The first to start holds lock until the second has failed on it, so they always collide.\n"
                "func hold(t *testing.T) {\n\tf, err := os.OpenFile(\"lock\", os.O_CREATE|os.O_EXCL, 0o600)\n"
                "\tif err != nil {\n\t\tos.WriteFile(\"collided\", nil, 0o600)\n\t\tt.Fatal(err)\n\t}\n"
                "\tf.Close()\n\tdefer os.Remove(\"lock\")\n"
                "\tfor end := time.Now().Add(30 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {\n"
                "\t\tif _, err := os.Stat(\"collided\"); err == nil {\n\t\t\treturn\n\t\t}\n\t}\n}\n\n"
                "func TestOne(t *testing.T) {\n\thold(t)\n\tKeep(1)\n}\n\n"
                "func TestTwo(t *testing.T) {\n\thold(t)\n\tSide(1)\n}\n")
        with tempfile.TemporaryDirectory() as d:
            pkg = self.repo(d, "package hint\n", self.COVER_PR, test)
            binary = pathlib.Path(d) / "b.test"
            subprocess.run(["go", "test", "-c", "-cover", "-covermode=set", "-o", str(binary), "."], cwd=pkg, check=True,
                           env={**os.environ, "GOFLAGS": "", "GOWORK": "off"})
            ran, failing = mutgate.per_test(binary, pkg, d, 60, jobs=2)
            self.assertTrue((pkg / "collided").exists())  # the parallel runs did collide
        self.assertEqual((list(ran), failing), (["TestOne", "TestTwo"], {}))
        lines = lambda name: {n for (s, _), (e, _) in ran[name][0].get("hint.go", []) for n in range(s, e + 1)}
        self.assertTrue(6 in lines("TestOne") and 14 not in lines("TestOne"))
        self.assertTrue(14 in lines("TestTwo") and 6 not in lines("TestTwo"))

    def test_site_costs_overhead_counts_tests_that_fail_alone(self):
        # #6226 (Security on #6225): the per-test pass runs a test that fails alone twice (in the pool,
        # then alone), so its seconds count twice in the overhead each shard spends before its sites.
        # REQ: MUT-delete-covering
        at = lambda line: {"a.go": [((line, 1), (line, 9))]}
        tests = ({"TestA": (at(5), 1.0), "TestB": (at(9), 6.0)}, {"TestF": 2.0})
        sites = [{"file": "a.go", "cover_line": 5, "cover_col": 2}, {"file": "a.go", "cover_line": 7, "cover_col": 2}]
        with tempfile.TemporaryDirectory() as tmp:
            (pathlib.Path(tmp) / "suite.test").write_text("")
            with mock.patch.object(mutgate, "per_test", lambda *a, **k: tests):
                costs, overhead = mutgate.site_costs("hint", sites, 100.0, tmp)
        self.assertEqual(costs, [6.0, 100.0])
        self.assertEqual(overhead, 11.0)

    def test_site_costs_are_each_sites_own_tests(self):
        # REQ: MUT-delete-covering
        with tempfile.TemporaryDirectory() as d:
            pkg = self.repo(d, "package hint\n", self.COVER_PR, self.COVER_TEST)
            added = {"broker/hint/hint.go": set(range(1, 17))}
            tmp = pathlib.Path(d) / "tmp"
            tmp.mkdir()
            with mock.patch.object(mutgate, "BROKER", pkg.parent), \
                    mock.patch.object(mutgate, "per_test", self.even(mutgate.per_test)):
                sites, _ = mutgate.deletion_sites("hint", added, self.lister(tmp))
                costs, overhead = mutgate.site_costs("hint", sites, 1000.0, tmp)
        got = {s["line"]: c for s, c in zip(sites, costs)}
        self.assertEqual(sorted(got), [6, 7, 8, 10, 14, 15])
        self.assertEqual(got[8], 1000.0)  # no test covers it alone: a whole suite
        self.assertTrue(all(0 < got[n] < 1000.0 for n in (6, 7, 10, 14, 15)), got)
        self.assertEqual(got[6], got[7])  # both TestKeep's: its run and the set's unmutated run
        self.assertTrue(0 < overhead < 1000.0)

    def test_a_batch_that_mostly_times_out_leaves_the_rest_to_one_worker(self):
        # L3 on #4643: when every worker's run times out, retrying each alone costs more than one
        # worker would, so after such a batch the rest runs alone, once each.
        body = "\n".join(f"\tcount += {i}" for i in range(12))
        pr = f"package hint\n\nvar count int\n\nfunc Keep(n int) int {{\n{body}\n\treturn n\n}}\n"
        test = TEST_SRC.replace("count != 3 || Last() != 3", "false")
        with tempfile.TemporaryDirectory() as d:
            pkg = self.repo(d, "package hint\n", pr, test)
            added = mutgate.added_lines(subprocess.run(
                ["git", "-C", d, "diff", "-U0", "--src-prefix=a/", "--dst-prefix=b/", "HEAD~1", "--", "broker"],
                capture_output=True, text=True, check=True).stdout)[0]
            calls = []
            def fake(binary, cwd, timeout, mem=None, names=None):
                calls.append(pathlib.Path(binary).parent.name)
                return "TIMED OUT"
            broker, run_tests = mutgate.BROKER, mutgate.run_tests
            mutgate.BROKER, mutgate.run_tests = pkg.parent, fake
            try:
                tmp = pathlib.Path(d) / "tmp"
                tmp.mkdir()
                got, problem = mutgate.deletion_mutants("hint", added, tmp, self.lister(tmp), 2)
            finally:
                mutgate.BROKER, mutgate.run_tests = broker, run_tests
            self.assertIsNone(problem)
            covered = [m for m in got if m["status"] == "TIMED OUT"]
            self.assertEqual(len(covered), 12)
            # The first batch of 8 ran on workers and again alone; the other 4 ran alone once.
            self.assertEqual(len(calls), 8 * 2 + 4)

    def test_a_symlinked_go_file_is_refused(self):
        # L3 on #4643: verify must not read (and echo) a runner file through a PR-added link.
        with tempfile.TemporaryDirectory() as d:
            pkg = self.repo(d)
            (pkg / "link.go").symlink_to(pkg / "hint.go")
            git = lambda *a: subprocess.run(["git", "-C", d, *a], check=True, capture_output=True, text=True)
            git("add", "-A")
            git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "--amend", "-m", "pr")
            out = pathlib.Path(d) / "out"
            out.mkdir()
            (out / "hint.json").write_text(json.dumps({"files": [], "mutants_lived": 0}))
            r = self.mutgate(d, "delete", "hint", "--out", str(out), "--git", "HEAD~1")
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("symbolic links, which mutgate does not follow: ['link.go']", r.stderr)

    def test_unused_label_and_import_spellings(self):
        text = b'package p\n\nimport (\n\tl "log"\n\t"os"\n)\n\nfunc f() {\nL:\n\tfor {\n\t}\n}\n'
        got = mutgate.respelled(text, [(4, 2, "import"), (5, 2, "import"), (9, 1, "label")])
        self.assertEqual(got, b'package p\n\nimport (\n\t_ "log"\n\t_ "os"\n)\n\nfunc f() {\n  \n\tfor {\n\t}\n}\n')
        self.assertEqual(mutgate.fixes("./a.go:5:1: label L defined and not used\n", "a.go"), ([], [(5, 1, "label")]))
        self.assertIsNone(mutgate.fixes("./a.go:5:1: undefined: x\n", "a.go"))
        self.assertIsNone(mutgate.fixes("./b.go:5:2: declared and not used: x\n", "a.go"))

    def test_a_line_directive_is_refused(self):
        # Round 2 on #4597: `//line other.go:7` renames the file in the cover profile too, so every
        # later site would read NOT COVERED; the lister refuses the file instead.
        src = "package p\n\nfunc f() {\n//line other.go:7\n\tg()\n}\n\nfunc g() {}\n"
        with tempfile.TemporaryDirectory() as d:
            (pathlib.Path(d) / "p.go").write_text(src)
            r = subprocess.run([str(self.lister(d)), str(pathlib.Path(d) / "p.go")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("a //line directive", r.stderr)

    def test_delete_needs_gremlins_result_and_passing_tests(self):
        with tempfile.TemporaryDirectory() as d:
            pkg = self.repo(d)
            out = pathlib.Path(d) / "out"
            r = self.mutgate(d, "delete", "hint", "--out", str(out), "--git", "HEAD~1")
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("no gremlins result for hint", r.stderr)
            out.mkdir()
            (out / "hint.json").write_text(json.dumps({"files": [], "mutants_lived": 0}))
            (pkg / "hint_test.go").write_text(TEST_SRC.replace('t.Fatal("keep")', "").replace("{\n\t\t\n\t}", "{\n\t}")
                                              + "func TestFails(t *testing.T) { t.Fatal(1) }\n")
            r = self.mutgate(d, "delete", "hint", "--out", str(out), "--git", "HEAD~1")
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("tests fail before any statement is deleted", r.stderr)
            # A package with no tests covers nothing: each site is NOT COVERED, as gremlins reads it.
            (pkg / "hint_test.go").unlink()
            (pkg / "doc.go").write_text("package hint\n\n// REQ: CRED-1\n")
            r = self.mutgate(d, "delete", "hint", "--out", str(out), "--git", "HEAD~1")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            data = json.loads((out / "hint.json").read_text())
            self.assertEqual({m["status"] for m in data["files"][0]["mutations"]}, {"NOT COVERED"})
            self.assertEqual(data["statement_deletions"], 5)


# REV-PROOF-mut (#4908): a diff that changes only a package's tests mutates the lines they run.
TWO_SRC = """package hint

func Up(n int) int {
	if n > 10 {
		return 10
	}
	return n + 1
}

func Down(n int) int {
	return n - 1
}
"""
# The plan's failure (#5942) for hint.go's `return 10`, run by the base's TestUp and by no head test.
UNRUN_5 = (r"mutgate: broker/hint/hint\.go: (\d+, )*5(, \d+)* ran under the base's version of the tests this diff "
           r"changes, and no test of package hint runs them at the head")
TWO_TEST = """package hint

import "testing"

func TestUp(t *testing.T) {
	if Up(1) != 2 || Up(20) != 10 {
		t.Fatal("up")
	}
}

func TestDown(t *testing.T) {
	if Down(3) != 2 {
		t.Fatal("down")
	}
}
"""


class TestOnly(unittest.TestCase):
    def repo(self, d, test_pr, src=TWO_SRC, test_base=TWO_TEST, src_pr=None, base_extra=None):
        """A temp repo whose last commit changes broker/hint/hint_test.go to test_pr, and
        broker/hint/hint.go to src_pr when given; base_extra {name: text} are files of broker/hint/
        in the base commit."""
        git = lambda *a: subprocess.run(["git", "-C", d, *a], check=True, capture_output=True, text=True)
        shutil.copytree(ROOT / "tools", pathlib.Path(d) / "tools")
        shutil.copytree(ROOT / "broker" / "core", pathlib.Path(d) / "broker" / "core")
        (pathlib.Path(d) / "broker" / "go.mod").write_text(GO_MOD)
        pkg = pathlib.Path(d) / "broker" / "hint"
        pkg.mkdir()
        (pkg / "hint.go").write_text(src)
        (pkg / "hint_test.go").write_text(test_base)
        for name, text in (base_extra or {}).items():
            (pkg / name).parent.mkdir(parents=True, exist_ok=True)
            (pkg / name).write_text(text)
        git("init", "-q")
        git("add", "-A")
        git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "-m", "base")
        (pkg / "hint_test.go").write_text(test_pr)
        if src_pr is not None:
            (pkg / "hint.go").write_text(src_pr)
        git("add", "-A")
        # --allow-empty: gate_run may add the PR's only change as a new file after this commit.
        git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "pr")
        return git

    def mutgate(self, d, *args, env=None):
        as_ci(args)
        return subprocess.run([sys.executable, "-I", str(pathlib.Path(d) / "tools" / "mutgate.py"), *args],
                              capture_output=True, text=True,
                              env={**os.environ, "GOFLAGS": "", "GOWORK": "off", **(env or {})})

    def stub(self, d, mutations):
        """A gremlins on PATH that records `git diff --merge-base` of its -D ref and writes mutations."""
        stub = pathlib.Path(d) / "bin"
        stub.mkdir()
        out = json.dumps({"files": [{"file_name": "hint.go", "mutations": mutations}],
                          "mutants_lived": sum(m["status"] == "LIVED" for m in mutations)})
        (stub / "gremlins").write_text(
            f"#!/bin/sh\ngit diff --merge-base \"$4\" > \"{d}/seen\"\n"
            f"while [ \"$1\" != -o ]; do shift; done\nprintf '%s' '{out}' > \"$2\"\n")
        (stub / "gremlins").chmod(0o755)
        return {"PATH": f"{stub}:{os.environ['PATH']}"}

    def test_suite_seconds_times_one_whole_run(self):
        # MUT-kernel-sim-budget (#5069): plan times the package's whole suite, built as delete builds it.
        from unittest import mock
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"GOFLAGS": "", "GOWORK": "off"}), \
                mock.patch.object(mutgate, "BROKER", pathlib.Path(d) / "broker"):
            self.repo(d, TWO_TEST + "\n// changed\n")
            pkg, tmp = mutgate.BROKER / "hint", pathlib.Path(d) / "tmp"
            tmp.mkdir()
            slow = 'package hint\n\nimport (\n\t"testing"\n\t"time"\n)\n\nfunc TestSlow(t *testing.T) { time.Sleep(time.Second) }\n'
            (pkg / "slow_test.go").write_text(slow)
            secs, problem = mutgate.suite_seconds("hint", tmp)
            self.assertIsNone(problem)
            self.assertGreaterEqual(secs, 1.0)
            (pkg / "slow_test.go").write_text(slow.replace("time.Second)", '0); t.Fatal("no")'))
            self.assertEqual(mutgate.suite_seconds("hint", tmp),
                             (None, "broker/hint/'s tests fail before any mutant runs, so its shards cannot be sized"))
            (pkg / "slow_test.go").write_text("package hint\n\nfunc broken(\n")
            self.assertEqual(mutgate.suite_seconds("hint", tmp), (None, "broker/hint/ does not build its tests"))
            # A package with no tests costs no suite runs; a stale binary from another package is not timed.
            (pkg / "slow_test.go").unlink()
            (pkg / "hint_test.go").unlink()
            self.assertEqual(mutgate.suite_seconds("hint", tmp), (0.0, None))

    def test_timed_cover_times_its_run(self):
        # MUT-plan-budget (#6155): a test-changing package's whole-suite coverage run is timed, so the
        # plan sizes its shards from that run and needs no other suite run.
        from unittest import mock
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"GOFLAGS": "", "GOWORK": "off"}), \
                mock.patch.object(mutgate, "BROKER", pathlib.Path(d) / "broker"):
            self.repo(d, TWO_TEST + "\n// changed\n")
            pkg, tmp = mutgate.BROKER / "hint", pathlib.Path(d) / "tmp"
            tmp.mkdir()
            (pkg / "slow_test.go").write_text(
                'package hint\n\nimport (\n\t"testing"\n\t"time"\n)\n\nfunc TestSlow(t *testing.T) { time.Sleep(time.Second) }\n')
            got, secs, problem = mutgate.timed_cover("hint", None, tmp)
            self.assertIsNone(problem)
            self.assertGreaterEqual(secs, 1.0)
            self.assertEqual(mutgate.covered_by("hint", None, tmp), (got, None))
            # A run that leaves TestSlow out does not take its second.
            _, quick, problem = mutgate.timed_cover("hint", ["TestUp"], tmp)
            self.assertIsNone(problem)
            self.assertLess(quick, secs)

    def test_timed_cover_times_the_test_binary_not_its_build(self):
        # MUT-plan-timing-skew (#6162, Potency on #6156): suite_seconds times the built binary's run,
        # so timed_cover's time must leave out what `go test` spends before it (build, link, vet),
        # which a cold cache makes many times a fast suite. A `go` that sleeps 2 s first stands in for
        # that; with no `ok` line to read, the wall time stands, which can only add shards.
        from unittest import mock
        real = shutil.which("go")
        with tempfile.TemporaryDirectory() as d, mock.patch.object(mutgate, "BROKER", pathlib.Path(d) / "broker"):
            self.repo(d, TWO_TEST + "\n// changed\n")
            pkg, tmp, shim = mutgate.BROKER / "hint", pathlib.Path(d) / "tmp", pathlib.Path(d) / "shim"
            tmp.mkdir()
            shim.mkdir()
            (pkg / "slow_test.go").write_text(
                'package hint\n\nimport (\n\t"testing"\n\t"time"\n)\n\nfunc TestSlow(t *testing.T) { time.Sleep(time.Second) }\n')
            for tail, low, high in (("", 1.0, 2.0), (" >/dev/null", 3.0, None)):
                with self.subTest(tail=tail):
                    (shim / "go").write_text(f'#!/bin/sh\nsleep 2\nexec "{real}" "$@"{tail}\n')
                    (shim / "go").chmod(0o755)
                    with mock.patch.dict(os.environ, {"GOFLAGS": "", "GOWORK": "off",
                                                      "PATH": f"{shim}:{os.environ['PATH']}"}):
                        got, secs, problem = mutgate.timed_cover("hint", None, tmp)
                    self.assertIsNone(problem)
                    self.assertIn("broker/hint/hint.go", got)
                    self.assertGreaterEqual(secs, low)
                    if high is not None:
                        self.assertLess(secs, high)

    def test_go_ok_reads_go_tests_summary_line(self):
        # MUT-plan-timing-skew (#6162): the last `ok` line's seconds, coverage suffix or not.
        out = "ok  \tagentos/broker/x\t0.5s\n--- some log\nok  \tagentos/broker/hint\t12.034s\tcoverage: 50.0% of statements\n"
        self.assertEqual(mutgate.GO_OK.findall(out), ["0.5", "12.034"])
        self.assertEqual(mutgate.GO_OK.findall("ok  \tagentos/broker/hint\t3s\n"), ["3"])
        for none in ("FAIL\tagentos/broker/hint\t1.0s\n", "ok  \tagentos/broker/hint\t(cached)\n", "  ok  \tp\t1s\n"):
            self.assertEqual(mutgate.GO_OK.findall(none), [], none)

    def test_echo_ok_streams_and_reads_the_last_ok_line(self):
        # MUT-plan-timing-skew-fu (#6232): stdout reaches stderr chunk by chunk (`plan`'s stdout is
        # the matrix, #4961), split lines and characters join, and the last `ok` line's seconds stand.
        from unittest import mock

        class Chunks:
            def __init__(self, chunks):
                self.chunks = list(chunks)

            def read1(self, n):
                return self.chunks.pop(0) if self.chunks else b""

        cases = (
            ([b"ok  \tagentos/broker/x\t9s\nlog \xc3", b"\xa9\nok  \tagentos/broker/hint\t1.", b"5s\tcoverage: 5%\n"], "1.5"),
            ([b"ok  \tp\t9s\nok  \tp\t2s"], "2"),  # a last line with no newline
            ([b"ok  \tp\t3s\t" + b"x" * 200000 + b"\n"], "3"),  # a long line's head still reads
            ([b"x" * 200000 + b"ok  \tp\t4s\n"], None),  # an `ok` mid-line is no summary line
            ([b"FAIL\tp\t1s\n"], None),
            ([b"x\xc3"], None),  # a cut last character still echoes
            ([], None),
        )
        for chunks, want in cases:
            with self.subTest(want=want), mock.patch.object(sys, "stderr", io.StringIO()) as err:
                self.assertEqual(mutgate.echo_ok(Chunks(chunks)), want)
                self.assertEqual(err.getvalue(), b"".join(chunks).decode("utf-8", "replace"))

    def test_echo_ok_holds_no_flood(self):
        # MUT-plan-timing-skew-fu (#6232): a test flooding 64 MiB, in lines or in one line, costs
        # echo_ok about a chunk, where buffering the output whole raised MemoryError in the plan job.
        import tracemalloc
        from unittest import mock

        class Flood:
            def __init__(self, piece, tail):
                self.left, self.piece, self.tail = 1024, piece, tail

            def read1(self, n):
                self.left -= 1
                return self.piece if self.left > 0 else (self.tail if self.left == 0 else b"")

        class Sink:
            seen = 0

            def write(self, text):
                Sink.seen += len(text)

            def flush(self):
                pass

        for piece in (b"x" * 65536, (b"x" * 63 + b"\n") * 1024):
            with self.subTest(lines=piece.count(b"\n")), mock.patch.object(sys, "stderr", Sink()):
                Sink.seen = 0
                tracemalloc.start()
                try:
                    got = mutgate.echo_ok(Flood(piece, b"\nok  \tagentos/broker/hint\t7.5s\n"))
                    _, peak = tracemalloc.get_traced_memory()
                finally:
                    tracemalloc.stop()
                self.assertEqual(got, "7.5")
                self.assertEqual(Sink.seen, 1023 * 65536 + 31)
                self.assertLess(peak, 4 << 20)

    def test_echo_ok_scans_no_bare_newline(self):
        # MUT-plan-timing-skew-fu2 (#6236): a flood of bare newlines reaches no regex search (each
        # cost about 90 ns a byte), lines split at a chunk's edge still join, and the last `ok` line
        # stands. The one search past the lines is echo_ok's read of its unfinished last line.
        from unittest import mock

        class Chunks:
            def __init__(self, chunks):
                self.chunks = list(chunks)

            def read1(self, n):
                return self.chunks.pop(0) if self.chunks else b""

        flood = b"\n" * 65536
        cases = (
            ([b"ok  \tp\t1", b"s" + flood, flood, b"ok  \tp\t7.5s" + flood, flood], "7.5", 3),
            ([b"ok  \tp\t2s", flood], "2", 2),  # a chunk opening with a newline ends the carried line
            ([flood, b"x\n" + flood + b"ok  \tp\t3s"], "3", 2),
            ([flood, flood], None, 1),
        )
        for chunks, want, searches in cases:
            with self.subTest(want=want), mock.patch.object(sys, "stderr", io.StringIO()), \
                    mock.patch.object(mutgate, "GO_OK", wraps=mutgate.GO_OK) as go_ok:
                self.assertEqual(mutgate.echo_ok(Chunks(chunks)), want)
                self.assertEqual(go_ok.search.call_count, searches)

    def test_timed_cover_echoes_live_and_times_the_last_ok_line(self):
        # MUT-plan-timing-skew-fu (#6232): a `go` that prints another `ok` line, then waits 2 s
        # before the real run: that line reaches stderr at once, and the real run's own (last) `ok`
        # line times the run, not the first one's 99 s.
        from unittest import mock
        real = shutil.which("go")

        class Clock(io.StringIO):
            first = None

            def flush(self):  # stderr shows text only once flushed
                if self.getvalue() and Clock.first is None:
                    Clock.first = time.monotonic()

        with tempfile.TemporaryDirectory() as d, mock.patch.object(mutgate, "BROKER", pathlib.Path(d) / "broker"):
            self.repo(d, TWO_TEST + "\n// changed\n")
            tmp, shim = pathlib.Path(d) / "tmp", pathlib.Path(d) / "shim"
            tmp.mkdir()
            shim.mkdir()
            (shim / "go").write_text(f'#!/bin/sh\nprintf \'ok  \\tagentos/broker/other\\t99s\\n\'\nsleep 2\nexec "{real}" "$@"\n')
            (shim / "go").chmod(0o755)
            with mock.patch.dict(os.environ, {"GOFLAGS": "", "GOWORK": "off", "PATH": f"{shim}:{os.environ['PATH']}"}), \
                    mock.patch.object(sys, "stderr", Clock()) as err:
                began = time.monotonic()
                got, secs, problem = mutgate.timed_cover("hint", None, tmp)
                ended = time.monotonic()
            self.assertIsNone(problem)
            self.assertIn("broker/hint/hint.go", got)
            self.assertLess(secs, 2.0)
            self.assertLess(Clock.first - began, 1.5)
            self.assertGreaterEqual(ended - began, 2.0)
            out = err.getvalue()
            self.assertTrue(out.startswith("ok  \tagentos/broker/other\t99s\n"), out)
            self.assertRegex(out, r"(?m)^ok  \s*\S*hint\s+[0-9.]+s")

    def test_test_only_diff_mutates_covered_lines(self):
        # #3607: a test-only diff passed every gate. TestUp still runs Up(20) but no longer checks
        # the clamp, so its guard survives; TestDown is untouched, so Down's line is no target.
        weak = TWO_TEST.replace("Up(20) != 10", "Up(20) < 0")
        mutations = [{"type": "CONDITIONALS_BOUNDARY", "status": "LIVED", "line": 4, "column": 7},
                     {"type": "ARITHMETIC_BASE", "status": "KILLED", "line": 7, "column": 11}]
        with tempfile.TemporaryDirectory() as d:
            git = self.repo(d, weak)
            self.assertEqual(mutgate.claimed(git("diff", "-U0", "--src-prefix=a/", "--dst-prefix=b/", "HEAD~1").stdout,
                                             packages=["hint"]), ["hint"])
            head, ref = git("rev-parse", "HEAD").stdout, git("symbolic-ref", "HEAD").stdout
            out = pathlib.Path(d) / "res" / "mutants-0"
            r = self.mutgate(d, "run", "hint", "--git", "HEAD~1", "--out", str(out), env=self.stub(d, mutations))
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            # HEAD, the branch and the tree are as they were.
            self.assertEqual((git("rev-parse", "HEAD").stdout, git("symbolic-ref", "HEAD").stdout), (head, ref))
            self.assertEqual(git("status", "--porcelain", "--", "broker").stdout, "")
            data = json.loads((out / "hint.json").read_text())
            covered = data["targets"]["lines"]["hint.go"]
            self.assertEqual(data["targets"]["tests"], ["TestUp"])
            self.assertTrue({3, 4, 5, 7} <= set(covered), covered)
            self.assertFalse({10, 11} & set(covered), covered)  # Down: only TestDown runs it
            # Gremlins' own diff marks exactly those lines, relative to the package.
            seen = mutgate.added_lines((pathlib.Path(d) / "seen").read_text())[0]
            self.assertEqual(seen, {"hint.go": set(covered)})
            r = self.mutgate(d, "delete", "hint", "--git", "HEAD~1", "--out", str(out))
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            summary = pathlib.Path(d) / "summary.md"
            r = self.mutgate(d, "verify", str(out.parent), "--git", "HEAD~1", "--summary", str(summary))
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("broker/hint/hint.go:4 CONDITIONALS_BOUNDARY survives", r.stdout)
            # Deleting `return 10` lives too: nothing checks the clamp now.
            self.assertIn("broker/hint/hint.go:5 deleting the whole statement holding line 5 survives", r.stdout)
            self.assertNotIn("hint.go:11", r.stdout)
            table = summary.read_text()
            self.assertIn("the lines TestUp cover", table)
            self.assertIn("| broker/hint/hint.go:4:7 | CONDITIONALS\\_BOUNDARY | **LIVED**: no test fails |", table)
            self.assertIn("killed (gremlins names no test)", table)
            self.assertIn("| broker/hint/hint.go:5:3 | STATEMENT\\_DELETION | **LIVED**: no test fails |", table)
            # The record must name the tests verify names itself, and lines of the package's own files.
            for bad in ({**data["targets"], "tests": ["TestDown"]}, {**data["targets"], "tests": None},
                        {"tests": ["TestUp"], "lines": {"hint_test.go": [5]}},
                        {"tests": ["TestUp"], "lines": {"../x.go": [1]}},
                        {"tests": ["TestUp"], "lines": {"hint.go": ["4"]}}, None):
                with self.subTest(bad):
                    forged = dict(json.loads((out / "hint.json").read_text()))
                    if bad is None:
                        forged.pop("targets")
                    else:
                        forged["targets"] = bad
                    (out / "hint.json").write_text(json.dumps(forged))
                    r = self.mutgate(d, "verify", str(out.parent), "--git", "HEAD~1")
                    self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                    self.assertRegex(r.stderr, "holds no record of the lines|records covered lines")

    def line_stub(self, d):
        """A gremlins on PATH that writes one mutant on each line its `git diff --merge-base` adds,
        LIVED on line 4 and KILLED elsewhere, and appends the lines to d/seen-lines."""
        stub = pathlib.Path(d) / "bin"
        stub.mkdir(exist_ok=True)
        (stub / "gremlins").write_text(f"""#!{sys.executable}
import json, re, subprocess, sys
a = sys.argv
diff = subprocess.run(["git", "diff", "--merge-base", a[a.index("-D") + 1]], capture_output=True, text=True, check=True).stdout
muts, name = {{}}, None
for row in diff.split("\\n"):
    if row.startswith("+++ b/"):
        name = row[6:]
    m = re.match(r"@@ -\\S+ \\+(\\d+)(?:,(\\d+))? @@", row)
    if m:
        first = int(m.group(1))
        muts.setdefault(name, []).extend(range(first, first + int(m.group(2) or 1)))
open("{d}/seen-lines", "a").write(json.dumps(muts) + "\\n")
# Like gremlins v0.6.0, every other line's mutant is written too, SKIPPED (Security on #4978).
files = [{{"file_name": f, "mutations": [{{"type": "CONDITIONALS_NEGATION", "status": ("LIVED" if n == 4 else "KILLED")
          if n in ns else "SKIPPED", "line": n, "column": 1}} for n in range(1, len(open(f).read().split("\\n")))]}}
         for f, ns in muts.items()]
count = lambda s: sum(m["status"] == s for f in files for m in f["mutations"])
lived, killed = count("LIVED"), count("KILLED")
# gremlins' total is lived + killed + not viable (v0.6.0 report.go:178); SKIPPED is not counted.
open(a[a.index("-o") + 1], "w").write(json.dumps({{"files": files, "mutants_total": lived + killed,
                                                  "mutants_killed": killed, "mutants_lived": lived}}))
""")
        (stub / "gremlins").chmod(0o755)
        return {"PATH": f"{stub}:{os.environ['PATH']}"}

    def test_shards_of_a_run_join_to_the_unsharded_verdicts(self):
        # MUT-test-only-cost (#4961): K shards of `run` and `delete`, each a mutants job, give verify
        # the verdicts and summary table one job gives, and each shard mutates only its own lines.
        weak = TWO_TEST.replace("Up(20) != 10", "Up(20) < 0")
        with tempfile.TemporaryDirectory() as d:
            git = self.repo(d, weak)
            env = self.line_stub(d)
            # The plan runs the changed test's coverage: a few lines, one shard. Its record names the
            # changed test, as each shard's changed_tests does, so the shards accept it (#4970).
            plan = pathlib.Path(d) / "targets.json"
            r = self.mutgate(d, "plan", "--git", "HEAD~1", "--targets-out", str(plan))
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertEqual(json.loads(r.stdout), [{"pkg": "hint", "shards": "0", "of": 1, "minutes": 75}])
            up = {"tests": ["TestUp"], "lines": {"hint.go": [3, 4, 5, 6, 7]}}
            self.assertEqual(json.loads(plan.read_text()), {"hint": {**up, "base": up}})
            got = {}
            for of in (1, 2, 3):
                res = pathlib.Path(d) / f"res-{of}"
                (pathlib.Path(d) / "seen-lines").unlink(missing_ok=True)
                for i in range(of):
                    out = res / f"mutants-{i}"
                    r = self.mutgate(d, "run", "hint", "--git", "HEAD~1", "--out", str(out),
                                     "--shard", str(i), "--of", str(of), "--targets", str(plan), env=env)
                    self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                    r = self.mutgate(d, "delete", "hint", "--git", "HEAD~1", "--out", str(out), "--jobs", "1")
                    self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                    data = json.loads((out / "hint.json").read_text())
                    self.assertEqual(data["shard"], {"index": i, "of": of})
                    covered = {"broker/hint/hint.go": set(data["targets"]["lines"]["hint.go"])}
                # Gremlins saw exactly each shard's lines: disjoint, and together every target line.
                seen = [json.loads(row).get("hint.go", []) for row in (pathlib.Path(d) / "seen-lines").read_text().splitlines()]
                self.assertEqual(seen, [sorted(mutgate.shard_lines(covered, i, of).get("broker/hint/hint.go", ()))
                                        for i in range(of) if mutgate.shard_lines(covered, i, of)])
                self.assertEqual(sorted(sum(seen, [])), sorted(covered["broker/hint/hint.go"]))
                summary = pathlib.Path(d) / f"summary-{of}.md"
                r = self.mutgate(d, "verify", str(res), "--git", "HEAD~1", "--summary", str(summary))
                got[of] = (r.returncode, r.stdout, summary.read_text())
            self.assertEqual(got[1][0], 1)
            self.assertIn("broker/hint/hint.go:4 CONDITIONALS_NEGATION survives", got[1][1])
            self.assertIn("broker/hint/hint.go:5 deleting the whole statement holding line 5 survives", got[1][1])
            self.assertEqual(got[2], got[1])
            self.assertEqual(got[3], got[1])
            # Shards whose coverage runs recorded other target lines are refused, not joined.
            forged = pathlib.Path(d) / "res-2" / "mutants-1" / "hint.json"
            data = json.loads(forged.read_text())
            for part in (data["targets"], data["targets"]["base"]):  # the union holds both parts' lines
                part["lines"]["hint.go"] = part["lines"]["hint.go"][:-1]
            forged.write_text(json.dumps(data))
            r = self.mutgate(d, "verify", str(pathlib.Path(d) / "res-2"), "--git", "HEAD~1")
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("records other target lines than", r.stderr)
            self.assertIn("the shards of hint disagree; rerun the mutgate workflow", r.stderr)  # #4983: the remedy
            self.assertEqual(git("status", "--porcelain", "--", "broker").stdout, "")
            # A shard asked for outside 0 <= I < K is refused before anything runs.
            for bad in (("--shard", "2", "--of", "2"), ("--shard", "-1", "--of", "2"), ("--of", "1281", "--shard", "0")):
                r = self.mutgate(d, "run", "hint", "--git", "HEAD~1", "--out", str(pathlib.Path(d) / "x"), *bad, env=env)
                self.assertEqual(r.returncode, 2, r.stdout + r.stderr)

    def test_a_deleted_test_widens_the_targets_beside_an_added_line(self):
        # MUT-deleted-test-own-lines (#5762): the diff deletes TestUp, the only test that checks
        # Up's clamp, and adds one comment line to hint.go. The target used to be that comment
        # alone, so no mutant ran and the gate passed; it is now the comment plus the lines the
        # deleted test ran at the base and its neighbour runs at the head (D-319), and the clamp's
        # survivor fails the gate.
        # REQ: MUT-deleted-test-own-lines
        # Here TestDown also runs the clamp's `return 10` (line 5), so every line the base ran still runs
        # at the head; where it does not, the plan fails first (#5942).
        alone = TWO_TEST.replace("if Down(3) != 2 {", "if Down(Up(2)) != 2 {")
        with tempfile.TemporaryDirectory() as d:
            self.repo(d, alone[:alone.index("func TestUp")] + alone[alone.index("func TestDown"):], test_base=alone,
                      src_pr=TWO_SRC + "// Down is Up's inverse below the clamp.\n")
            r = self.mutgate(d, "plan", "--git", "HEAD~1")
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertRegex(r.stderr, UNRUN_5)
        base = TWO_TEST.replace("if Down(3) != 2 {", "if Down(Up(2)) != 2 || Down(Up(20)) != 9 {")
        pr = base[:base.index("func TestUp")] + base[base.index("func TestDown"):]
        with tempfile.TemporaryDirectory() as d:
            git = self.repo(d, pr, test_base=base, src_pr=TWO_SRC + "// Down is Up's inverse below the clamp.\n")
            env = self.line_stub(d)
            plan = pathlib.Path(d) / "targets.json"
            r = self.mutgate(d, "plan", "--git", "HEAD~1", "--targets-out", str(plan))
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            rec = json.loads(plan.read_text())["hint"]
            self.assertEqual(rec["tests"], ["TestDown"])  # the deletion's neighbour at the head
            self.assertTrue({3, 4, 7, 10} <= set(rec["lines"]["hint.go"]), rec)
            self.assertNotIn(13, rec["lines"]["hint.go"])  # the record holds coverage only
            out = pathlib.Path(d) / "res" / "mutants-0"
            r = self.mutgate(d, "run", "hint", "--git", "HEAD~1", "--out", str(out), "--targets", str(plan), env=env)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            seen = json.loads((pathlib.Path(d) / "seen-lines").read_text().splitlines()[0])["hint.go"]
            # TestDown ran after TestUp at the base, so its run order changed too (#6385): the base runs both.
            self.assertEqual(rec["base"]["tests"], ["TestDown", "TestUp"])
            self.assertTrue({3, 4, 5, 6, 7} <= set(rec["base"]["lines"]["hint.go"]), rec)
            self.assertEqual(sorted(seen), sorted(set(rec["lines"]["hint.go"]) | set(rec["base"]["lines"]["hint.go"]) | {13}))
            r = self.mutgate(d, "delete", "hint", "--git", "HEAD~1", "--out", str(out), "--jobs", "1")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            summary = pathlib.Path(d) / "summary.md"
            r = self.mutgate(d, "verify", str(out.parent), "--git", "HEAD~1", "--summary", str(summary))
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("broker/hint/hint.go:4 CONDITIONALS_NEGATION survives", r.stdout)
            self.assertIn("the lines the diff changes and the lines TestDown cover", summary.read_text())
            # The record is still required beside the added line: without it verify refuses.
            data = json.loads((out / "hint.json").read_text())
            data.pop("targets")
            (out / "hint.json").write_text(json.dumps(data))
            r = self.mutgate(d, "verify", str(out.parent), "--git", "HEAD~1")
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("holds no record of the lines that ['TestDown'] covers", r.stderr)
            self.assertEqual(git("status", "--porcelain", "--", "broker").stdout, "")

    def gate_run(self, d, pr_test, base_test, src_pr=None, extra=None, move=None, base_extra=None, plan_fails=False):
        """(verify's result, the lines gremlins was given) for a PR of pr_test (and src_pr, extra
        {name: text} new or changed files in broker/hint/ (None: deleted) over base_extra's, and hint.go
        renamed to move), through plan, run, delete and verify; or, with plan_fails, (plan's failed
        result, None)."""
        git = self.repo(d, pr_test, test_base=base_test, src_pr=src_pr, base_extra=base_extra)
        for name, text in (extra or {}).items():
            f = pathlib.Path(d) / "broker" / "hint" / name
            if text is None:
                f.unlink()
            else:
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_text(text)
        if move:
            git("mv", "broker/hint/hint.go", f"broker/hint/{move}")
        if extra or move:
            git("add", "-A")
            git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "--amend", "--no-edit")
        env, plan = self.line_stub(d), pathlib.Path(d) / "targets.json"
        r = self.mutgate(d, "plan", "--git", "HEAD~1", "--targets-out", str(plan))
        self.assertEqual(r.returncode, 1 if plan_fails else 0, r.stdout + r.stderr)
        if plan_fails:
            return r, None
        out = pathlib.Path(d) / "res" / "mutants-0"
        r = self.mutgate(d, "run", "hint", "--git", "HEAD~1", "--out", str(out), "--targets", str(plan), env=env)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        r = self.mutgate(d, "delete", "hint", "--git", "HEAD~1", "--out", str(out), "--jobs", "1")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        seen = json.loads((pathlib.Path(d) / "seen-lines").read_text().splitlines()[0])[move or "hint.go"]
        self.assertEqual(git("status", "--porcelain", "--", "broker").stdout, "")
        return self.mutgate(d, "verify", str(out.parent), "--git", "HEAD~1"), set(seen)

    def test_a_weakened_test_fails_on_the_lines_its_base_version_ran(self):
        # Security and L3 on #5770: the changed tests' coverage at the head is empty for a test that
        # skips, returns early, no longer builds or is gone, so the widening added nothing and a
        # comment line passed. The base's version of those tests, run on the base tree, names what
        # they checked; a line of that left unrun at the head fails (here `return 10`, line 5, which
        # only TestUp runs: TestDown's Up(2) never reaches the clamp).
        # REQ: MUT-deleted-test-own-lines
        base = TWO_TEST.replace("if Down(3) != 2 {", "if Down(Up(2)) != 2 {")
        first = "func TestUp(t *testing.T) {\n"
        comment = TWO_SRC + "// Down is Up's inverse below the clamp.\n"
        main = ('package hint\n\nimport (\n\t"flag"\n\t"os"\n\t"testing"\n)\n\n'
                'func TestMain(m *testing.M) {\n\tflag.Set("test.run", "^$")\n\tos.Exit(m.Run())\n}\n')
        skip = base.replace(first, first + '\tt.Skip("flaky")\n')
        outside = (base.replace('import "testing"', 'import (\n\t"os"\n\t"testing"\n)')
                   .replace(first, first + '\tif _, err := os.Stat("../../tools/mutgate.py"); err != nil {\n\t\tt.Fatal(err)\n\t}\n'))
        # Security on 87b77d3c: an edit to each line the skipped test ran, or a moved file, takes those
        # lines out of the base record's mapping, so every target line of the package must run.
        marked = "\n".join(row + (" // c" if n in (4, 5, 7) else "") for n, row in enumerate(TWO_SRC.split("\n"), 1))
        cases = {
            "skip, beside an added line": (skip, base, comment, None, None),
            "early return, beside an added line": (base.replace(first, first + "\treturn\n"), base, comment, None, None),
            "skip, test-only": (skip, base, None, None, None),
            "build tag": ("//go:build never\n\n" + base, base, comment, None, None),
            "the only test of Up deleted": (TWO_TEST[:TWO_TEST.index("func TestUp")] + TWO_TEST[TWO_TEST.index("func TestDown"):],
                                            TWO_TEST, comment, None, None),
            "a new file's TestMain runs no test": (base, base, comment, {"main_test.go": main}, None),
            "skip, and the lines it ran edited": (skip, base, marked, None, None),
            "skip, and the file moved": (skip, base, None, None, "clamp.go"),
            # L3 on #5770: the base's tests read files outside broker/, so the whole base tree is archived.
            "skip, where the base's test reads tools/": (outside.replace(first, first + '\tt.Skip("flaky")\n'),
                                                         outside, comment, None, None),
        }
        for name, (pr, was, src, extra, move) in cases.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as d:
                # Since #5942 the plan fails a line the base ran that the head's whole suite runs nowhere,
                # before any mutant runs. A moved file's base lines map to no head line, so there the
                # NOT COVERED rule fails it.
                r, seen = self.gate_run(d, pr, was, src, extra, move, plan_fails=not move)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                if move:
                    self.assertIn(5, seen)
                    self.assertIn(f"broker/hint/{move}:5 is a target line no test of package hint runs at the head", r.stdout)
                elif "edited" in name:
                    # The edit drops lines 4, 5 and 7 from the base's mapping; the if's closing brace (line
                    # 6), which no mutant names, is still one the base ran and the head runs nowhere.
                    self.assertIn("mutgate: broker/hint/hint.go: 6 ran under the base's version", r.stderr)
                else:
                    self.assertRegex(r.stderr, UNRUN_5)

    def test_a_helper_edit_beside_an_added_line_targets_the_tests_that_reach_it(self):
        # #5753: a helper change plus an added comment line used to narrow the targets to that
        # comment. The helper stops checking, so the lines of every test that reaches it, directly or
        # through another helper, are targets again (D-319 item 1); TestDown reaches neither, so
        # Down's line 11 is not one.
        # REQ: MUT-deleted-test-own-lines, MUT-test-helper-scope
        helper = "\nfunc check(t *testing.T, ok bool) {\n\tif !ok {\n\t\tt.Fatal(\"check\")\n\t}\n}\n"
        direct = TWO_TEST.replace('if Up(1) != 2 || Up(20) != 10 {\n\t\tt.Fatal("up")\n\t}',
                                  "check(t, Up(1) == 2 && Up(20) == 10)") + helper
        outer = direct.replace("check(t, Up", "both(t, Up") + "\nfunc both(t *testing.T, ok bool) {\n\tcheck(t, ok)\n}\n"
        for name, base in (("direct", direct), ("through another helper", outer)):
            pr = base.replace('\tif !ok {\n\t\tt.Fatal(\"check\")\n\t}\n', "\t_ = ok\n")
            with self.subTest(name), tempfile.TemporaryDirectory() as d:
                r, seen = self.gate_run(d, pr, base, TWO_SRC + "// a comment\n")
                self.assertTrue({3, 4, 5, 7, 13} <= seen, seen)
                self.assertNotIn(11, seen)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("broker/hint/hint.go:4 CONDITIONALS_NEGATION survives", r.stdout)

    def test_a_weakened_test_table_fails_on_the_lines_its_base_version_ran(self):
        # Security S1 on #5770 (#5779): the trigger read only _test.go changes, so dropping a case row
        # from a test's testdata/ table, or emptying it, plus a comment line passed: TestUp no longer
        # reaches the clamp, and nothing ran it. A changed data file now changes its package's tests,
        # every one, so the base's run of them names `return 10` (line 5) and the head runs it nowhere.
        # The same holds for a file the package's code names outside testdata/.
        # REQ: MUT-deleted-test-own-lines-fu
        def reader(path):
            return TWO_TEST.replace('import "testing"', 'import (\n\t"os"\n\t"strconv"\n\t"strings"\n\t"testing"\n)').replace(
                'if Up(1) != 2 || Up(20) != 10 {\n\t\tt.Fatal("up")\n\t}',
                f'b, err := os.ReadFile("{path}")\n\tif err != nil {{\n\t\tt.Fatal(err)\n\t}}\n'
                '\tf := strings.Fields(string(b))\n\tfor i := 0; i+1 < len(f); i += 2 {\n'
                '\t\tin, _ := strconv.Atoi(f[i])\n\t\twant, _ := strconv.Atoi(f[i+1])\n'
                '\t\tif Up(in) != want {\n\t\t\tt.Fatal("up", in)\n\t\t}\n\t}')
        comment = TWO_SRC + "// Down is Up's inverse below the clamp.\n"
        table = "1 2\n20 10\n"
        cases = {
            "a row dropped, beside an added line": ("testdata/up.txt", "1 2\n", comment),
            "the table emptied, data only": ("testdata/up.txt", "", None),
            "a nested testdata file emptied": ("testdata/cases/up.txt", "", None),
            "a named file beside the code emptied": ("up.txt", "", None),
        }
        for name, (path, pr, src) in cases.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as d:
                test = reader(path)
                r, _ = self.gate_run(d, test, test, src, extra={path: pr}, base_extra={path: table}, plan_fails=True)
                self.assertRegex(r.stderr, UNRUN_5)  # #5942: the plan fails it before any mutant runs

    def test_a_line_no_mutant_names_fails_where_the_base_ran_it_and_the_head_runs_it_nowhere(self):
        # L1 on #5770 (#5942): every target line runs was checked only through NOT COVERED mutants, so
        # a line no mutant and no statement deletion names (here mark's empty body, lines 14 and 15)
        # that a weakened test stopped running passed. The plan now runs the head's whole suite and
        # fails each line the base's version of the changed tests ran that no head test runs.
        # REQ: MUT-own-lines-no-mutant
        src = TWO_SRC + "\nfunc mark() {\n}\n"
        base = TWO_TEST.replace("func TestUp(t *testing.T) {\n", "func TestUp(t *testing.T) {\n\tmark()\n")
        down = base.replace("func TestDown(t *testing.T) {\n", "func TestDown(t *testing.T) {\n\tmark()\n")
        cases = {
            "the only call dropped": (TWO_TEST, base, None, 1),
            "a comment line beside it": (TWO_TEST, base, src + "// a comment\n", 1),
            # TestDown still runs mark at the head: the line runs, so the plan passes.
            "another test still runs it": (down.replace("\tmark()\n\tif Up", "\tif Up"), down, None, 0),
        }
        for name, (pr, was, src_pr, code) in cases.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as d:
                self.repo(d, pr, src=src, test_base=was, src_pr=src_pr)
                r = self.mutgate(d, "plan", "--git", "HEAD~1")
                self.assertEqual(r.returncode, code, r.stdout + r.stderr)
                # mark's `}` (line 15) is in its empty body's block, so it is code still (#6216).
                gone = "broker/hint/hint.go: 14, 15 ran under the base's version of the tests this diff changes"
                if code:
                    self.assertIn(gone + ", and no test of package hint runs them at the head", r.stderr)
                    self.assertNotIn(", 3,", r.stderr)  # Up's lines still run under TestUp
                else:
                    self.assertNotIn(gone, r.stderr)

    def test_a_closing_brace_the_base_ran_that_no_head_block_holds_is_not_unrun(self):
        # #6216 (from #6012's cut.go:177): Go's cover profile ends a block at the start of a nested block
        # that ends it, so the `}` closing Up's `if` (line 6), in the if's block at the base, is in no
        # block once the head nests an `if` inside it. It is no code a test could run, so the plan passes.
        # REQ: MUT-unrun-closing-brace
        nested = TWO_SRC.replace("\t\treturn 10\n", "\t\tif n > 0 {\n\t\t\treturn 10\n\t\t}\n")
        with tempfile.TemporaryDirectory() as d:
            self.repo(d, TWO_TEST.replace('t.Fatal("up")', 't.Fatal("up!")'), src_pr=nested)
            r = self.mutgate(d, "plan", "--git", "HEAD~1")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertNotIn("ran under the base's version", r.stderr)

    def test_unrun_skips_only_closing_lines_no_head_block_holds(self):
        # #6216: the closing shapes Go's profile leaves out of every block (measured on go1.26: `}`,
        # `})`, `},`, `}()`, `}}` after a nested block) are no code. The same line inside a head block (an
        # `if` body's own `}`, an empty body's) is, and a line with any other token is named either way.
        # REQ: MUT-unrun-closing-brace
        rows = ["\t}", "\t})", "\t\t},", "\t}()", "\t}}", "} // end",
                "\t} else {", "\t}, nil)", "\t}}.f", "\treturn 10", "\t)", "\t}(x)", "\tcase a,", "\t}"]
        p = "broker/hint/hint.go"
        with tempfile.TemporaryDirectory() as d:
            (pathlib.Path(d) / "hint").mkdir()
            (pathlib.Path(d) / "hint" / "hint.go").write_text("\n".join(rows) + "\n")
            with mock.patch.object(mutgate, "BROKER", pathlib.Path(d)):
                got = mutgate.unrun({p: set(range(1, len(rows) + 1))}, {p: {10}}, {p: {14}})
        self.assertEqual(got, {p: [7, 8, 9, 11, 12, 13, 14]})

    def test_an_archive_that_fails_prints_the_problem(self):
        # L3 R3 on #5770 (#5779): a failed `git archive` wrote no tar, and tarfile's ReadError came
        # before the exit code was read, so plan stopped with a traceback. It is the formatted problem.
        # REQ: MUT-deleted-test-own-lines-fu
        with tempfile.TemporaryDirectory() as d:
            git = lambda *a: subprocess.run(["git", "-C", d, *a], check=True, capture_output=True, text=True)
            (pathlib.Path(d) / "f").write_text("x\n")
            git("init", "-q")
            git("add", "-A")
            git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "-m", "base")
            with mock.patch.object(mutgate, "ROOT", pathlib.Path(d)):
                got, problem = mutgate.base_covered("hint", "0" * 40, None, d, "")
            self.assertIsNone(got)
            self.assertRegex(problem, r"^`git archive 000000000000` failed \(exit \d+\)$")

    def test_base_tree_skips_a_link_the_data_filter_refuses(self):
        from unittest import mock
        # #5523 put an absolute symlink on main, and the data filter's AbsoluteLinkError failed every
        # plan that reached base_covered (#5774). The link is left out; files and in-tree links stay.
        # REQ: MUT-deleted-test-own-lines
        with tempfile.TemporaryDirectory() as d:
            git = lambda *a: subprocess.run(["git", "-C", d, *a], check=True, capture_output=True, text=True)
            (pathlib.Path(d) / "spikes").mkdir()
            (pathlib.Path(d) / "spikes" / "unit").write_text("x\n")
            os.symlink("/etc/systemd/system/x.service", pathlib.Path(d) / "spikes" / "abs")
            os.symlink("../../outside", pathlib.Path(d) / "spikes" / "up")
            os.symlink("unit", pathlib.Path(d) / "spikes" / "rel")
            git("init", "-q")
            git("add", "-A")
            git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "-m", "base")
            err = io.StringIO()
            with mock.patch.object(mutgate, "ROOT", pathlib.Path(d)), contextlib.redirect_stderr(err):
                self.assertEqual(mutgate.base_covered("absent", "HEAD", None, d, ""), ({}, None))
            # L3 on #5781 (#5779): plan names each member it leaves out.
            self.assertEqual(sorted(err.getvalue().splitlines()), [
                f"mutgate: the base tree leaves out spikes/{n}, a link tar's data filter refuses" for n in ("abs", "up")])
            tree = pathlib.Path(d) / "base-tree" / "spikes"
            self.assertEqual((tree / "unit").read_text(), "x\n")
            self.assertEqual(os.readlink(tree / "rel"), "unit")
            self.assertFalse((tree / "abs").is_symlink())
            self.assertFalse((tree / "up").is_symlink())

    def test_base_side_lines_of_a_diff(self):
        # REQ: MUT-deleted-test-own-lines
        diff = ("diff --git a/broker/h/a_test.go b/broker/h/a_test.go\n--- a/broker/h/a_test.go\n+++ b/broker/h/a_test.go\n"
                "@@ -4,2 +4 @@\n-\tx()\n-\ty()\n+\tz()\n@@ -9,0 +9,2 @@\n+\ta()\n+\tb()\n"
                "diff --git a/broker/h/b_test.go b/broker/h/b_test.go\n--- a/broker/h/b_test.go\n+++ /dev/null\n"
                "@@ -1,2 +0,0 @@\n-package h\n-\n"
                "diff --git a/broker/h/c_test.go b/broker/h/c_test.go\n--- /dev/null\n+++ b/broker/h/c_test.go\n"
                "@@ -0,0 +1 @@\n+package h\n")
        self.assertEqual(mutgate.base_test_lines(diff),
                         ({"broker/h/a_test.go": {4, 5}, "broker/h/b_test.go": None}, {"broker/h/a_test.go": {9}}))
        move = mutgate.head_line_of(diff.replace("_test.go", ".go"))
        self.assertEqual([move["broker/h/a.go"](n) for n in (3, 4, 5, 6, 9, 10)], [3, None, None, 5, 8, 11])
        self.assertIsNone(move["broker/h/b.go"](1))
        self.assertNotIn("broker/h/c.go", move)

    def test_a_test_appended_after_another_widens_to_no_neighbour(self):
        # REQ: MUT-add-neighbour-widen
        base = ("package h\n\nimport \"testing\"\n\n// TestA checks a.\nfunc TestA(t *testing.T) {\n\ta()\n\ta()\n}\n\n"
                "// TestB checks b.\nfunc TestB(t *testing.T) {\n\tb()\n}\n")
        rows = base.split("\n")
        at = lambda s: rows.index(s) + 1
        gap = lambda after: mutgate._gap_lines(base, after)
        # After TestA's closing brace, in the blank line, or beside TestB's doc: no function body.
        self.assertEqual([gap(at("}")), gap(at("}") + 1), gap(at("// TestB checks b."))], [set(), set(), set()])
        # Inside a body, even right after its head or before its closing brace, still touches it.
        self.assertEqual(gap(at("func TestA(t *testing.T) {")), {at("func TestA(t *testing.T) {"), at("func TestA(t *testing.T) {") + 1})
        self.assertEqual(gap(at("\ta()") + 1), {at("\ta()") + 1, at("\ta()") + 2})
        self.assertEqual(gap(at("\tb()")), {at("\tb()"), at("\tb()") + 1})
        # A closing brace with a trailing comment is still the closing brace (Security on #5860).
        noted = base.replace("\n}\n\n// TestB", "\n} // done\n\n// TestB")
        self.assertEqual(mutgate._gap_lines(noted, at("}")), set())
        self.assertEqual(mutgate._gap_lines(noted, at("\ta()")), {at("\ta()"), at("\ta()") + 1})
        # No closing brace found: the wide rule, both lines.
        open_ = "package h\n\nfunc TestA(t *testing.T) {\n\ta()\n"
        self.assertEqual(mutgate._gap_lines(open_, 4), {4, 5})
        # Reached by name: the appended test names none of the old ones at the base.
        files = {"broker/h/a_test.go": base}
        self.assertEqual(mutgate.reaching_tests(files, {"broker/h/a_test.go": gap(at("}")) | {at("\ta()")}}), ["TestA"])
        self.assertEqual(mutgate.reaching_tests(files, {"broker/h/a_test.go": {at("\tb()")}}), ["TestB"])
        # At the head the lines the diff adds, read from a real unified diff (the blank line before the
        # new test comes first), name only the new test, not the one above (L3 on #5860).
        head = base + "\n// TestC checks c.\nfunc TestC(t *testing.T) {\n\tc()\n}\n"
        import difflib
        added = set()
        for row in difflib.unified_diff(base.splitlines(), head.splitlines(), n=0, lineterm=""):
            if m := re.match(r"@@ -\S+ \+(\d+)(?:,(\d+))? @@", row):
                start, count = int(m[1]), int(m[2] or 1)
                added.update(range(start, start + count))
        self.assertIn(len(base.splitlines()) + 1, added)  # the blank line after TestB's closing brace
        self.assertEqual(mutgate.reaching_tests({"broker/h/a_test.go": head}, {"broker/h/a_test.go": added}), ["TestC"])

    def test_targets_for_unions_own_lines_with_changed_tests_coverage(self):
        # REQ: MUT-deleted-test-own-lines
        from unittest import mock
        with tempfile.TemporaryDirectory() as d, mock.patch.object(mutgate, "BROKER", pathlib.Path(d)):
            (pathlib.Path(d) / "hint").mkdir()
            (pathlib.Path(d) / "hint" / "hint.go").write_text(TWO_SRC)
            self.check_union()

    def check_union(self):
        added, bases = {"broker/hint/hint.go": {12}}, {"hint": ["TestUp"]}
        # The deleted file has no head lines, so no head test reaches the change; its base side runs.
        rec = {"targets": {"tests": [], "lines": {"hint.go": [3, 4]},
                           "base": {"tests": ["TestUp"], "lines": {"hint.go": [5, 7]}}}}
        self.assertEqual(mutgate.targets_for("hint", added, {}, rec, {}), ({"broker/hint/hint.go": {12}}, None))
        gone = {"broker/hint/hint_test.go": None}
        self.assertEqual(mutgate.targets_for("hint", added, gone, rec, bases),
                         ({"broker/hint/hint.go": {3, 4, 5, 7, 12}}, None))
        for bad in ({}, {"targets": {**rec["targets"], "base": None}},
                    {"targets": {**rec["targets"], "base": {"tests": ["TestDown"], "lines": {}}}}):
            with self.subTest(bad):
                targets, problem = mutgate.targets_for("hint", added, gone, bad, bases)
                self.assertIsNone(targets)
                self.assertIn("holds no record", problem)
        # Another package's test change widens nothing here.
        self.assertEqual(mutgate.targets_for("hint", added, {"broker/other/a_test.go": None}, {}, {}),
                         ({"broker/hint/hint.go": {12}}, None))

    def test_a_target_line_equal_to_an_earlier_non_target_line_is_still_mutated(self):
        # #5008: lines 9-10 (`return -1`, `}`), run by TestUp, equal lines 5-6, which it does not
        # run. Marking only the targets let git pair base 5-6 with head 9-10, gremlins skipped those
        # targets and `run` failed. Each shard's diff now adds all its lines, and verdicts on lines
        # the diff adds beyond them are dropped, so shards still join without overlap.
        src = "package hint\n\nfunc Up(n int) int {\n\tif n > 10 {\n\t\treturn -1\n\t}\n\tn++\n" \
              "\tif n > 5 {\n\t\treturn -1\n\t}\n\treturn n\n}\n"
        test = 'package hint\n\nimport "testing"\n\nfunc TestUp(t *testing.T) {\n\tif Up(6) != -1 {\n\t\tt.Fatal("up")\n\t}\n}\n'
        with tempfile.TemporaryDirectory() as d:
            git = self.repo(d, test.replace("!= -1", "> 0"), src=src, test_base=test)
            env = self.line_stub(d)
            plan = pathlib.Path(d) / "targets.json"
            r = self.mutgate(d, "plan", "--git", "HEAD~1", "--targets-out", str(plan))
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            targets = set(json.loads(plan.read_text())["hint"]["lines"]["hint.go"])
            self.assertTrue({9, 10} <= targets and not {5, 6} & targets, targets)
            # The collision is real: the targets-only base gives git the misaligned pairing.
            base = pathlib.Path(d) / "base.go"
            base.write_text("\n".join(row + " //mutgate" * (i in targets) for i, row in enumerate(src.split("\n"), 1)))
            plain = subprocess.run(["git", "diff", "--no-index", "-U0", str(base), str(pathlib.Path(d) / "broker/hint/hint.go")],
                                   capture_output=True, text=True, cwd=d).stdout
            self.assertFalse({9, 10} <= set().union(*mutgate.added_lines(plain)[0].values()), plain)
            for of in (1, 2):
                res = pathlib.Path(d) / f"res-{of}"
                (pathlib.Path(d) / "seen-lines").unlink(missing_ok=True)
                for i in range(of):
                    out = res / f"mutants-{i}"
                    r = self.mutgate(d, "run", "hint", "--git", "HEAD~1", "--out", str(out),
                                     "--shard", str(i), "--of", str(of), "--targets", str(plan), env=env)
                    self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                    mine = mutgate.shard_lines({"hint.go": targets}, i, of)["hint.go"]
                    data = json.loads((out / "hint.json").read_text())
                    self.assertTrue(mutgate.shape_ok(data))
                    self.assertEqual({m["line"] for m in data["files"][0]["mutations"] if m["status"] != "SKIPPED"}, mine)
                    r = self.mutgate(d, "delete", "hint", "--git", "HEAD~1", "--out", str(out), "--jobs", "1")
                    self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                seen = [set(json.loads(row)["hint.go"]) for row in (pathlib.Path(d) / "seen-lines").read_text().splitlines()]
                self.assertTrue(targets <= set().union(*seen), seen)
                r = self.mutgate(d, "verify", str(res), "--git", "HEAD~1")
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)  # line 4's stub mutant lives
                self.assertIn("broker/hint/hint.go:4 CONDITIONALS_NEGATION survives", r.stdout)
                self.assertNotIn("skipped", r.stderr)
            self.assertEqual(git("status", "--porcelain", "--", "broker").stdout, "")

    def test_a_shard_of_a_source_diff_mutates_only_its_own_lines(self):
        # #4961: one unsharded job keeps gremlins on the base's own diff; a shard marks its lines.
        with tempfile.TemporaryDirectory() as d:
            git = self.repo(d, TWO_TEST + "\n")  # the PR commit needs a change; this one is a blank line
            pkg = pathlib.Path(d) / "broker" / "hint"
            # Lines 4, 7 and 11 change and the tests still pass: plan times them (#5069).
            (pkg / "hint.go").write_text(TWO_SRC.replace("n > 10", "n >= 10").replace("n + 1", "1 + n")
                                         .replace("n - 1", "-1 + n"))
            git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-qam", "src")
            env = self.line_stub(d)
            target = {"broker/hint/hint.go": {4, 7, 11}}
            # A source diff's targets are its own lines, so the plan records none, and still writes the
            # file the plan job uploads with if-no-files-found: error (#4970).
            plan = pathlib.Path(d) / "targets.json"
            r = self.mutgate(d, "plan", "--git", "HEAD~1", "--targets-out", str(plan))
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertEqual(plan.read_text(), "{}")
            for of in (1, 2, 3):
                (pathlib.Path(d) / "seen-lines").unlink(missing_ok=True)
                for i in range(of):
                    r = self.mutgate(d, "run", "hint", "--git", "HEAD~1", "--out", str(pathlib.Path(d) / f"o{of}-{i}"),
                                     "--shard", str(i), "--of", str(of), env=env)
                    self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                    self.assertNotIn("targets", json.loads((pathlib.Path(d) / f"o{of}-{i}" / "hint.json").read_text()))
                seen = [json.loads(row)["hint.go"] for row in (pathlib.Path(d) / "seen-lines").read_text().splitlines()]
                self.assertEqual(seen, [sorted(mutgate.shard_lines(target, i, of)["broker/hint/hint.go"]) for i in range(of)])
            self.assertEqual(git("status", "--porcelain", "--", "broker").stdout, "")

    def test_shards_read_the_plans_one_coverage_run_so_they_agree(self):
        # #4970: each shard of a test-only package measured its own coverage, a run could cover other
        # lines (a timing branch), and verify refused the package: "the shards of clerk/inbox disagree".
        # The plan measures it once and every shard reads that record (--targets), so they agree.
        # Here the import change runs every test of its file, and TestDown calls Up only while FLIP names a file.
        flaky = (TWO_TEST.replace('import "testing"', 'import (\n\t"os"\n\t"testing"\n)')
                 .replace('\tif Down(3) != 2 {', '\tif _, err := os.Stat(os.Getenv("FLIP")); err == nil {\n\t\tUp(20)\n\t}\n\tif Down(3) != 2 {')
                 .replace("Up(1) != 2 || Up(20) != 10", "Down(3) != 2"))
        with tempfile.TemporaryDirectory() as d:
            # The base's TestUp already tests Down, so no line the base's tests ran goes unrun.
            git = self.repo(d, flaky, test_base=TWO_TEST.replace("Up(1) != 2 || Up(20) != 10", "Down(3) != 2"))
            env = self.line_stub(d)
            on, off = {"FLIP": str(pathlib.Path(d) / "tools")}, {"FLIP": str(pathlib.Path(d) / "absent")}
            plan = pathlib.Path(d) / "targets.json"
            r = self.mutgate(d, "plan", "--git", "HEAD~1", "--targets-out", str(plan), env=off)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            down = {"tests": ["TestDown", "TestUp"], "lines": {"hint.go": [10, 11, 12]}}
            self.assertEqual(json.loads(plan.read_text()), {"hint": {**down, "base": down}})

            def shards(res, flips, *extra):
                for i, flip in enumerate(flips):
                    out = pathlib.Path(d) / res / f"mutants-{i}"
                    r = self.mutgate(d, "run", "hint", "--git", "HEAD~1", "--out", str(out), "--shard", str(i),
                                     "--of", str(len(flips)), *extra, env={**env, **flip})
                    self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                    r = self.mutgate(d, "delete", "hint", "--git", "HEAD~1", "--out", str(out), "--jobs", "1",
                                     env=flip)
                    self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                return self.mutgate(d, "verify", str(pathlib.Path(d) / res), "--git", "HEAD~1")
            # Each shard measuring its own coverage: the shards disagree, as on #4970.
            r = shards("own", (off, on))
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("the shards of hint disagree", r.stderr)
            # Reading the plan's record: the same flip, and the shards agree on the plan's lines.
            r = shards("planned", (off, on), "--targets", str(plan))
            self.assertNotIn("disagree", r.stderr)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            for i in (0, 1):
                data = json.loads((pathlib.Path(d) / "planned" / f"mutants-{i}" / "hint.json").read_text())
                self.assertEqual(data["targets"], {**down, "base": down})
            # A plan that names no record for the package, or one verify would refuse, is refused before
            # gremlins runs; the shard never falls back to a coverage run of its own.
            for bad, want in (({}, "the plan names no target lines for broker/hint/"),
                              ({"hint": {"tests": ["TestUp"], "lines": {"hint.go": [9]}}}, "the plan holds no record"),
                              ({"hint": {**down, "lines": {"../x.go": [1]}, "base": down}}, "the plan records covered lines"),
                              ({"hint": {**down, "base": {**down, "lines": {"../x.go": [1]}}}}, "the plan records covered lines"),
                              ({"hint": down}, "the plan holds no record of the lines that ['TestDown', 'TestUp'] covers at the base")):
                with self.subTest(bad):
                    forged = pathlib.Path(d) / "forged.json"
                    forged.write_text(json.dumps(bad))
                    (pathlib.Path(d) / "seen-lines").unlink(missing_ok=True)
                    r = self.mutgate(d, "run", "hint", "--git", "HEAD~1", "--out", str(pathlib.Path(d) / "x"),
                                     "--targets", str(forged), env=env)
                    self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                    self.assertIn(want, r.stderr)
                    self.assertFalse((pathlib.Path(d) / "seen-lines").exists())
            r = self.mutgate(d, "run", "hint", "--git", "HEAD~1", "--out", str(pathlib.Path(d) / "x"),
                             "--targets", str(pathlib.Path(d) / "absent.json"), env=env)
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("no readable plan of target lines", r.stderr)
            self.assertEqual(git("status", "--porcelain", "--", "broker").stdout, "")

    def test_shard_count_follows_the_targets_not_a_constant(self):
        lines = lambda n: {"broker/p/a.go": set(range(1, n + 1))}
        self.assertEqual(mutgate.shard_count({}, []), 1)
        self.assertEqual(mutgate.shard_count(lines(mutgate.LINES_PER_SHARD), [0] * mutgate.SITES_PER_SHARD), 1)
        self.assertEqual(mutgate.shard_count(lines(mutgate.LINES_PER_SHARD + 1), []), 2)
        self.assertEqual(mutgate.shard_count(lines(1), [0] * (2 * mutgate.SITES_PER_SHARD + 1)), 3)
        # #4945's localui: 1048 target lines and about 0.35 deletion sites a line.
        self.assertEqual(mutgate.shard_count(lines(1048), [0] * 367), 5)
        # The shards are disjoint and together are the targets, for any K.
        t = {"broker/p/a.go": {1, 2, 5, 9}, "broker/p/b.go": {3, 4}}
        for of in range(1, 9):
            parts = [mutgate.shard_lines(t, i, of) for i in range(of)]
            flat = [(p, n) for part in parts for p, ns in part.items() for n in ns]
            self.assertEqual(sorted(flat), sorted((p, n) for p, ns in t.items() for n in ns))
            self.assertEqual(len(flat), len(set(flat)))

    def test_a_change_every_test_runs_targets_every_covered_line(self):
        # D-319 (#5826) item 3: TestMain, an init function, a package var's initializer and a blank
        # import run before every test, and nothing names them, so a change there is every test.
        # REQ: MUT-test-helper-scope
        from unittest import mock
        extra = ('\nfunc TestMain(m *testing.M) {\n\tm.Run()\n}\n\nfunc init() {\n\t_ = 1\n}\n\n'
                 'var seed = 1\n\nvar plain int\n')
        base = (TWO_TEST.replace('import "testing"', 'import (\n\t"testing"\n)').replace("\tif Down(3)", "\t_ = plain\n\tif Down(3)")
                + extra)
        for name, pr in (
                ("TestMain", base.replace("\tm.Run()", "\tm.Run()\n\t_ = 2")),
                ("init", base.replace("\t_ = 1", "\t_ = 2")),
                ("var initializer", base.replace("var seed = 1", "var seed = 2")),
                ("blank import", base.replace('\t"testing"\n', '\t"testing"\n\t_ "embed"\n')),
                ("deleted TestMain", base.replace("func TestMain(m *testing.M) {\n\tm.Run()\n}\n\n", ""))):
            with self.subTest(name), tempfile.TemporaryDirectory() as d:
                git = self.repo(d, pr, test_base=base)
                diff = git("diff", "-U0", "--src-prefix=a/", "--dst-prefix=b/", "HEAD~1").stdout
                tests = mutgate.added_lines(diff)[1]
                with mock.patch.object(mutgate, "BROKER", pathlib.Path(d) / "broker"), \
                        mock.patch.object(mutgate, "ROOT", pathlib.Path(d)):
                    bases = mutgate.bases_for(diff, "HEAD~1", "HEAD", tests, ["hint"])
                    self.assertEqual(bases, {"hint": None})
                    self.assertIsNone(mutgate.changed_tests(tests, "hint", bases))
        # A var with no initializer is reached by the tests that name it, here TestDown.
        with tempfile.TemporaryDirectory() as d:
            git = self.repo(d, base.replace("var plain int", "var plain int64"), test_base=base)
            diff = git("diff", "-U0", "--src-prefix=a/", "--dst-prefix=b/", "HEAD~1").stdout
            with mock.patch.object(mutgate, "BROKER", pathlib.Path(d) / "broker"), \
                    mock.patch.object(mutgate, "ROOT", pathlib.Path(d)):
                tests = mutgate.added_lines(diff)[1]
                self.assertEqual(mutgate.bases_for(diff, "HEAD~1", "HEAD", tests, ["hint"]), {"hint": ["TestDown"]})
        with tempfile.TemporaryDirectory() as d:
            self.repo(d, base.replace("var seed = 1", "var seed = 2"), test_base=base)
            out = pathlib.Path(d) / "out"
            r = self.mutgate(d, "run", "hint", "--git", "HEAD~1", "--out", str(out), env=self.stub(d, []))
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            data = json.loads((out / "hint.json").read_text())
            self.assertIsNone(data["targets"]["tests"])
            self.assertIsNone(data["targets"]["base"]["tests"])
            self.assertTrue({4, 5, 7, 11} <= set(data["targets"]["lines"]["hint.go"]))

    def test_reaching_tests_name_the_tests_that_reach_a_line(self):
        # D-319 (#5826): a line outside a test function maps to the tests that name its declaration,
        # transitively; a type reaches its methods; a file's header reaches what the file reaches.
        # REQ: MUT-test-helper-scope
        text = (TWO_TEST.replace("Up(1) != 2", "Up(one()) != 2").replace("Down(3)", "Down(box{}.three())")
                + "\nfunc one() int { return inner() }\n\nfunc inner() int { return 1 }\n"
                + "\ntype box struct{}\n\nfunc (b *box) three() int { return 3 }\n"
                + "\nfunc unused() {}\n\nfunc Testhelper() {}\n\nfunc FuzzUp(f *testing.F) {}\n"
                + "\nfunc BenchmarkUp(b *testing.B) {}\n")
        rows = text.split("\n")
        at = lambda s: rows.index(s) + 1
        files = {"broker/h/a_test.go": text}
        reach = lambda *lines: mutgate.reaching_tests(files, {"broker/h/a_test.go": set(lines)})
        self.assertEqual(reach(at('\t\tt.Fatal("up")')), ["TestUp"])
        self.assertEqual(reach(at('\t\tt.Fatal("up")'), at('\t\tt.Fatal("down")')), ["TestDown", "TestUp"])
        self.assertEqual(reach(at("func FuzzUp(f *testing.F) {}")), ["FuzzUp"])
        self.assertEqual(reach(at("func inner() int { return 1 }")), ["TestUp"])  # through one()
        self.assertEqual(reach(at("func (b *box) three() int { return 3 }")), ["TestDown"])  # through box
        self.assertEqual(reach(at("func one() int { return inner() }") + 1), ["TestUp"])  # a comment line after it
        # A line no test reaches (dead code, a benchmark) fails closed to every test (Security on #5838).
        for line in (at("func unused() {}"), at("func Testhelper() {}"), at("func BenchmarkUp(b *testing.B) {}")):
            self.assertIsNone(reach(line), rows[line - 1])
        self.assertEqual(reach(1), ["FuzzUp", "TestDown", "TestUp"])  # the header: what its file reaches
        self.assertEqual(reach(at('import "testing"')), ["FuzzUp", "TestDown", "TestUp"])
        # Another file's tests reach a helper by name, and its header reaches only its own file's reach.
        files["broker/h/b_test.go"] = 'package h\n\nimport "testing"\n\nfunc TestB(t *testing.T) { _ = one() }\n'
        self.assertEqual(reach(at("func inner() int { return 1 }")), ["TestB", "TestUp"])
        self.assertEqual(mutgate.reaching_tests(files, {"broker/h/b_test.go": {3}}), ["TestB"])
        # A comment names nothing; a doc comment or directive belongs to the declaration below it.
        doc = ('package h\n\nimport "testing"\n\n// TestC does not call one().\nfunc TestC(t *testing.T) {}\n'
               '\n//go:embed x.txt\nvar data string\n\nfunc TestD(t *testing.T) { _ = data }\n')
        self.assertEqual(reach_in := mutgate.reaching_tests({**files, "broker/h/d_test.go": doc},
                                                            {"broker/h/a_test.go": {at("func inner() int { return 1 }")}}),
                         ["TestB", "TestUp"], reach_in)
        self.assertEqual(mutgate.reaching_tests({**files, "broker/h/d_test.go": doc}, {"broker/h/d_test.go": {8}}), ["TestD"])
        self.assertEqual(mutgate.reaching_tests({**files, "broker/h/d_test.go": doc}, {"broker/h/d_test.go": {5}}), ["TestC"])
        # Security on #5838: a column-0 line inside a raw string starts no declaration, so the lines
        # after it stay the helper's; a type declared by the x_test package is not x's test type, so
        # an x test file's method on x's own Owner is every test.
        raw = ('package h\n\nimport "testing"\n\nfunc helper() int {\n\t_ = `\nfunc zzz() {\n`\n\treturn 1\n}\n'
               '\nfunc TestA(t *testing.T) { _ = helper() }\n')
        self.assertEqual(mutgate.reaching_tests({"broker/h/r_test.go": raw}, {"broker/h/r_test.go": {9}}), ["TestA"])
        lint = ('package h\n\nimport "testing"\n\nfunc lintSrc() (string, bool) {\n\ts := `package q\n\nfunc zzz() {}\n`\n'
                '\treturn s, true\n}\n\nfunc TestA(t *testing.T) { if _, ok := lintSrc(); !ok { t.Fatal("x") } }\n')
        self.assertEqual(mutgate.reaching_tests({"broker/h/l_test.go": lint}, {"broker/h/l_test.go": {9, 10}}), ["TestA"])
        own = {"broker/h/a_test.go": 'package h\n\nfunc (o *Owner) String() string {\n\treturn "o"\n}\n',
               "broker/h/b_test.go": 'package h_test\n\nimport "testing"\n\ntype Owner struct{}\n\nfunc TestB(t *testing.T) { _ = Owner{} }\n',
               "broker/h/c_test.go": 'package h\n\nimport (\n\t"fmt"\n\t"testing"\n)\n\nfunc TestPrint(t *testing.T) { _ = fmt.Sprint(New()) }\n'}
        self.assertIsNone(mutgate.reaching_tests(own, {"broker/h/a_test.go": {4}}))
        # Every test: a method on a type no test file declares (package code may call it through an
        # interface), a file with a linkname, a dot import, a line of a file not read.
        self.assertIsNone(mutgate.reaching_tests({**files, "broker/h/c_test.go": "package h\n\nfunc (s *Store) Hook() {}\n"},
                                                 {"broker/h/c_test.go": {3}}))
        # A test type group names its types by gofmt's layout, so a package type in a field is not one.
        group = "package h\n\ntype (\n\tfake struct {\n\t\ts *Store\n\t}\n)\n\nfunc (s *Store) Hook() {}\n"
        self.assertIsNone(mutgate.reaching_tests({**files, "broker/h/c_test.go": group}, {"broker/h/c_test.go": {9}}))
        self.assertIsNone(mutgate.reaching_tests({**files, "broker/h/c_test.go": "package h\n\n//go:linkname x y\nfunc x()\n"},
                                                 {"broker/h/c_test.go": {4}}))
        self.assertIsNone(mutgate.reaching_tests({**files, "broker/h/c_test.go": 'package h\n\nimport . "strings"\n'},
                                                 {"broker/h/c_test.go": {3}}))
        self.assertIsNone(mutgate.reaching_tests(files, {"broker/h/gone_test.go": {1}}))
        # A hunk that only deletes touches the lines either side, a deleted declaration too (its base
        # side names what it reached); a deleted file is None, read whole at the base.
        diff = ("diff --git a/broker/h/a_test.go b/broker/h/a_test.go\n--- a/broker/h/a_test.go\n+++ b/broker/h/a_test.go\n"
                "@@ -7 +6,0 @@\n-\tx()\n")
        self.assertEqual(mutgate.added_lines(diff)[1], {"broker/h/a_test.go": {6, 7}})
        self.assertEqual(mutgate.added_lines(diff.replace("-\tx()", "-func TestGone(t *testing.T) {"))[1],
                         {"broker/h/a_test.go": {6, 7}})
        gone = ("diff --git a/broker/h/a_test.go b/broker/h/a_test.go\n--- a/broker/h/a_test.go\n+++ /dev/null\n"
                "@@ -1,2 +0,0 @@\n-package h\n-\n")
        self.assertEqual(mutgate.added_lines(gone)[1], {"broker/h/a_test.go": None})
        self.assertEqual(mutgate.claimed(gone, packages=["h"]), ["h"])

    def test_a_new_test_file_claims_only_its_own_tests_lines(self):
        # D-319 (#5826) item 4, #5757's shape: a new _test.go file whose import and helper only its
        # own test uses used to make every test's lines targets, so the package's old survivor (Up's
        # clamp, line 4, LIVED in the stub) failed a PR that never touched Up. It claims only the
        # lines its test covers now (Down's), and the gate passes. Named after hint_test.go, it changes no
        # other test's run order (#6385).
        # REQ: MUT-test-helper-scope
        new = ('package hint\n\nimport (\n\t"strconv"\n\t"testing"\n)\n\n'
               'func text(n int) string { return strconv.Itoa(n) }\n\n'
               'func TestDownText(t *testing.T) {\n\tif text(Down(5)) != "4" {\n\t\tt.Fatal("down")\n\t}\n}\n')
        with tempfile.TemporaryDirectory() as d:
            r, seen = self.gate_run(d, TWO_TEST, TWO_TEST, extra={"more_test.go": new})
            self.assertEqual(seen, {10, 11, 12})
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            # The same file with a package var's initializer runs before every test: every line again.
        with tempfile.TemporaryDirectory() as d:
            r, seen = self.gate_run(d, TWO_TEST, TWO_TEST, extra={"more_test.go": new + "\nvar four = text(4)\n"})
            self.assertTrue({4, 5, 7, 11} <= seen, seen)
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("broker/hint/hint.go:4 CONDITIONALS_NEGATION survives", r.stdout)

    def test_tests_that_cover_nothing_run_no_gremlins(self):
        # Gremlins' -D mutates every line when its diff is empty, so no target line means no run.
        # The base's TestDown runs nothing either, so neither side covers a line. The pinned go leads PATH:
        # a runner's /usr/bin can hold another Go, whose gofmt mutgate refuses (#6442).
        base = TWO_TEST.replace("func TestDown(t *testing.T) {\n\tif Down(3) != 2 {", "func TestDown(t *testing.T) {\n\tif 3 != 3 {")
        with tempfile.TemporaryDirectory() as d:
            self.repo(d, base.replace('t.Fatal("down")', 't.Fatal("down!")'), test_base=base)
            out = pathlib.Path(d) / "res" / "mutants-0"
            r = self.mutgate(d, "run", "hint", "--git", "HEAD~1", "--out", str(out), env={"PATH": os.path.dirname(shutil.which("go")) + ":/usr/bin:/bin:" + str(pathlib.Path(sys.executable).parent)})
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertEqual(json.loads((out / "hint.json").read_text())["targets"], {"tests": ["TestDown"], "lines": {}, "base": {"tests": ["TestDown"], "lines": {}}})
            self.assertFalse((pathlib.Path(d) / "seen").exists())
            self.assertEqual(self.mutgate(d, "delete", "hint", "--git", "HEAD~1", "--out", str(out)).returncode, 0)
            r = self.mutgate(d, "verify", str(out.parent), "--git", "HEAD~1")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


def data_diff(path, kind="change"):
    """A -U0 diff of one file: a changed line, an added empty file (no hunk), or a deleted one."""
    head = f"diff --git a/{path} b/{path}\n"
    if kind == "empty":
        return head + "new file mode 100644\nindex 0000000..e69de29\n"
    if kind == "delete":
        return head + f"deleted file mode 100644\n--- a/{path}\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n"
    return head + f"--- a/{path}\n+++ b/{path}\n@@ -1 +1 @@\n-x\n+y\n"


# The base of MovedDecls: a helper TestUp names, with an import only it uses.
MOVE_TEST = """package hint

import (
\t"strings"
\t"testing"
)

// one is TestUp's helper.
func one() int { return len(strings.Repeat("x", 1)) }

func TestUp(t *testing.T) {
\tif Up(one()) != 2 || Up(20) != 10 {
\t\tt.Fatal("up")
\t}
}

func TestDown(t *testing.T) {
\tif Down(3) != 2 {
\t\tt.Fatal("down")
\t}
}
"""
MOVE_ONE = """// one is TestUp's helper.
func one() int { return len(strings.Repeat("x", 1)) }

"""
MOVE_DOWN = """func TestDown(t *testing.T) {
\tif Down(3) != 2 {
\t\tt.Fatal("down")
\t}
}
"""


class MovedDecls(unittest.TestCase):
    """TOOL-mutgate-moved-lines (#6369): a declaration moved unchanged is no change of the tests."""

    def reach(self, base, head, src=TWO_SRC, head_src=None, tree=None, fmt=True, extra=None):
        """(head tests, base tests) changed_tests and bases_for name for broker/hint/, the base holding
        hint.go (src) and the test files base {name: text}, the PR replacing them with head (and head_src),
        each through gofmt unless fmt is False; tree {name: text} is then written to the working tree,
        uncommitted."""
        if fmt:
            gofmt = lambda t: subprocess.run([mutgate.gofmt()], input=t, capture_output=True, text=True, check=True).stdout
            base, head = ({n: gofmt(t) for n, t in files.items()} for files in (base, head))
        with tempfile.TemporaryDirectory() as d:
            git = lambda *a: subprocess.run(["git", "-C", d, *a], check=True, capture_output=True, text=True)
            pkg = pathlib.Path(d) / "broker" / "hint"
            pkg.mkdir(parents=True)
            (pkg.parent / "go.mod").write_text(GO_MOD)
            for name, text in (extra or {}).items():  # other broker/ files, on both sides
                (pkg.parent / name).parent.mkdir(parents=True, exist_ok=True)
                (pkg.parent / name).write_text(text)
            git("init", "-q")
            for side, files, text in (("base", base, src), ("pr", head, src if head_src is None else head_src)):
                for f in pkg.glob("*_test.go"):
                    f.unlink()
                (pkg / "hint.go").write_text(text)
                for name, body in files.items():
                    (pkg / name).write_text(body)
                git("add", "-A")
                git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", side)
            diff = git("diff", "-U0", "--text", "--src-prefix=a/", "--dst-prefix=b/", "--no-renames", "HEAD~1", "HEAD").stdout  # as main() runs it
            for name, body in (tree or {}).items():
                (pkg / name).write_text(body)
            with mock.patch.object(mutgate, "BROKER", pkg.parent), mock.patch.object(mutgate, "ROOT", pathlib.Path(d)):
                tests = mutgate.changes(diff, "HEAD~1", "HEAD")[1]
                bases = mutgate.bases_for(diff, "HEAD~1", "HEAD", tests, ["hint"])
                return mutgate.changed_tests(tests, "hint", bases), bases.get("hint", [])

    def test_a_pure_move_changes_no_test(self):
        # REQ: TOOL-mutgate-moved-lines
        rest = MOVE_TEST.replace(MOVE_ONE, "").replace('\t"strings"\n', "")
        none = 'package hint\n\nimport "testing"\n\nfunc TestNone(t *testing.T) {}\n'
        base = {"hint_test.go": MOVE_TEST}
        for name, was, now in (
                ("within a file", base, {"hint_test.go": MOVE_TEST.replace(MOVE_ONE, "") + "\n" + MOVE_ONE.rstrip("\n") + "\n"}),
                ("to a new file, an import with it", base,
                 {"hint_test.go": rest, "other_test.go": 'package hint\n\nimport "strings"\n\n' + MOVE_ONE}),
                ("to an existing file", {**base, "other_test.go": none},
                 {"hint_test.go": rest, "other_test.go": none.replace('import "testing"', 'import (\n\t"strings"\n\t"testing"\n)')
                  + "\n" + MOVE_ONE})):
            with self.subTest(name):
                self.assertEqual(self.reach(was, now), ([], []))
        # Both sides are read from git: the working tree, here a file that drops the move, is not read.
        self.assertEqual(self.reach(base, {"hint_test.go": rest, "other_test.go": 'package hint\n\nimport "strings"\n\n' + MOVE_ONE},
                                    tree={"other_test.go": "package hint\n"}), ([], []))

    def test_a_moved_test_function_is_a_change(self):
        # `go test` runs tests in file then source order, so moving one can change what another sees;
        # one in a non-test file never ran (Security on #6378). A helper's move is still none (above).
        # REQ: TOOL-mutgate-moved-lines
        up = MOVE_TEST[MOVE_TEST.index("func TestUp"):MOVE_TEST.index(MOVE_DOWN)]
        for name, files, src in (
                ("reordered in its file", {"hint_test.go": MOVE_TEST.replace(up, "").rstrip("\n") + "\n\n" + up.rstrip("\n") + "\n"}, None),
                ("to another file", {"hint_test.go": MOVE_TEST.replace("\n" + MOVE_DOWN, ""),
                                     "down_test.go": 'package hint\n\nimport "testing"\n\n' + MOVE_DOWN}, None),
                ("every test file into one new", {"all_test.go": MOVE_TEST}, None)):
            with self.subTest(name):
                got = self.reach({"hint_test.go": MOVE_TEST}, files, head_src=src)
                self.assertIn("TestDown" if name != "reordered in its file" else "TestUp", got[0] or ["TestUp", "TestDown"])
        never = 'package hint\n\nimport "testing"\n\n' + MOVE_DOWN
        self.assertIn("TestDown", self.reach({"hint_test.go": TWO_TEST.replace("\n" + MOVE_DOWN, "")},
                                             {"hint_test.go": TWO_TEST.replace("\n" + MOVE_DOWN, ""), "down_test.go": never},
                                             src=TWO_SRC.replace("package hint\n", 'package hint\n\nimport "testing"\n') + "\n" + MOVE_DOWN,
                                             head_src=TWO_SRC)[0])

    def test_a_deleted_test_beside_a_moved_declaration_is_a_change(self):
        # L3 and Security on #6378: in -U0 a test deleted where a moved declaration lands is one replace
        # hunk; every added line moved, the deletion must still change the file and read the base.
        # REQ: TOOL-mutgate-moved-lines
        keep = "func TestKeep(t *testing.T) {\n\tif Up(1) != 2 {\n\t\tt.Fatal(1)\n\t}\n}\n"
        gone = "func TestCritical(t *testing.T) {\n\tif Down(3) != 2 {\n\t\tt.Fatal(2)\n\t}\n}\n"
        tail = "func TestTail(t *testing.T) {\n\tif Up(20) != 10 || helperH() != 0 {\n\t\tt.Fatal(3)\n\t}\n}\n"
        helper = "func helperH() int {\n\treturn Down(1)\n}\n"
        head = 'package hint\n\nimport "testing"\n\n'
        base = {"a_test.go": head + keep + "\n" + gone + "\n" + tail, "b_test.go": "package hint\n\n" + helper}
        now = {"a_test.go": head + keep + "\n" + helper + "\n" + tail, "b_test.go": "package hint\n"}
        got = self.reach(base, now)
        self.assertIn("TestCritical", got[1])
        self.assertTrue(got[0])  # the head side is changed too, so the base side is read
        # The whole file deleted, part of it moved: still a deleted file, every base test of it (here every test).
        self.assertEqual(self.reach(base, {"b_test.go": "package hint\n", "c_test.go": head + keep + "\n" + tail}), (None, None))

    def test_production_code_moved_into_a_test_file_changes_no_test(self):
        # #6305's shape: a client no binary links moves from a non-test file into a new test file.
        # REQ: TOOL-mutgate-moved-lines
        three = "// Three is what TestThree checks.\nfunc Three() int { return 3 }\n"
        test = 'package hint\n\nimport "testing"\n\nfunc TestThree(t *testing.T) {\n\tif Three() != 3 {\n\t\tt.Fatal(3)\n\t}\n}\n'
        base = {"hint_test.go": TWO_TEST, "three_test.go": test}
        self.assertEqual(self.reach(base, {**base, "client_test.go": "package hint\n\n// Moved out of the binary.\n\n" + three},
                                    src=TWO_SRC + "\n" + three, head_src=TWO_SRC), ([], []))
        # Left in place as well, it is held twice: a new test function's change.
        self.assertEqual(self.reach(base, {**base, "client_test.go": "package hint\n\n" + three}, src=TWO_SRC + "\n" + three),
                         (["TestThree"], []))

    def test_an_edited_or_unsure_move_is_a_change(self):
        # Fail closed: one token edited, a block held twice, another import behind a qualifier, another
        # build constraint, another package clause, and init (its order is its file's) all stay changes.
        # REQ: TOOL-mutgate-moved-lines
        rest = MOVE_TEST.replace(MOVE_ONE, "").replace("\n" + MOVE_DOWN, "").replace('\t"strings"\n', "")
        head = 'package hint\n\nimport (\n\t"strings"\n\t"testing"\n)\n\n'
        for name, files, want in (
                ("one token", {"hint_test.go": rest, "other_test.go": head + MOVE_ONE + MOVE_DOWN.replace("Down(3) != 2", "Down(3) != 1")},
                 (["TestDown", "TestUp"], ["TestDown"])),  # the deletion's line either side is TestUp's brace
                ("held twice", {"hint_test.go": MOVE_TEST.replace(MOVE_ONE, ""), "other_test.go": head + MOVE_ONE,
                                "again_test.go": head.replace('\t"testing"\n', "") + MOVE_ONE},
                 (["TestDown", "TestUp"], ["TestUp"])),  # the deletion's line either side is the header's
                ("another import", {"hint_test.go": rest, "other_test.go": head.replace('"strings"', 'strings "example.invalid/strings"')
                                    + MOVE_ONE + MOVE_DOWN}, (None, None)),
                ("a build constraint", {"hint_test.go": rest, "other_test.go": "//go:build linux\n\n" + head + MOVE_ONE + MOVE_DOWN},
                 (["TestDown", "TestUp"], ["TestDown", "TestUp"])),
                ("a file name constraint", {"hint_test.go": rest, "other_linux_test.go": head + MOVE_ONE + MOVE_DOWN},
                 (["TestDown", "TestUp"], ["TestDown", "TestUp"]))):
            with self.subTest(name):
                got = self.reach({"hint_test.go": MOVE_TEST}, files)
                if want == (None, None):
                    self.assertNotEqual(got, ([], []))
                    self.assertIn("TestUp", got[0] or ["TestUp"])
                else:
                    self.assertEqual(got, want)
        # A test moved where `go test` no longer runs it (a non-test file, a file go ignores) was deleted.
        rest = MOVE_TEST.replace("\n" + MOVE_DOWN, "")
        for name, files, src in (("into a non-test file", {"hint_test.go": rest},
                                  TWO_SRC.replace("package hint\n", 'package hint\n\nimport "testing"\n') + "\n" + MOVE_DOWN),
                                 ("into an ignored file", {"hint_test.go": rest, "_down_test.go": head + MOVE_DOWN}, TWO_SRC)):
            with self.subTest(name):
                self.assertIn("TestDown", self.reach({"hint_test.go": MOVE_TEST}, files, head_src=src)[1])
        init = "func init() {\n\t_ = 1\n}\n"
        self.assertEqual(self.reach({"hint_test.go": MOVE_TEST + "\n" + init},
                                    {"hint_test.go": MOVE_TEST, "init_test.go": "package hint\n\n" + init}), (None, None))

    def test_an_import_swapped_under_one_name_is_a_change(self):
        # A header change counts as none only when no line of the file can bind a name differently.
        # REQ: TOOL-mutgate-moved-lines
        swapped = MOVE_TEST.replace('\t"strings"\n', '\tstrings "example.invalid/broker/hint/fake"\n')
        self.assertEqual(self.reach({"hint_test.go": MOVE_TEST}, {"hint_test.go": swapped}),
                         (["TestDown", "TestUp"], ["TestDown", "TestUp"]))
        # An import named as a universe name would shadow the builtin in every line of its file (L3 on #6378).
        shadow = MOVE_TEST.replace('\t"testing"\n', '\t"testing"\n\tmax "example.invalid/broker/hint"\n')
        self.assertEqual(self.reach({"hint_test.go": MOVE_TEST}, {"hint_test.go": shadow}),
                         (["TestDown", "TestUp"], ["TestDown", "TestUp"]))
        # An import added for new code, with nothing else of the header changed, changes only that code's tests.
        added = MOVE_TEST.replace('\t"testing"\n', '\t"testing"\n\t"unicode"\n').replace(
            "Down(3) != 2", "Down(3) != 2 || !unicode.IsDigit('3')")
        self.assertEqual(self.reach({"hint_test.go": MOVE_TEST, "u_test.go": 'package hint\n\nimport "unicode"\n\nvar _ = unicode.IsDigit\n'},
                                    {"hint_test.go": added, "u_test.go": 'package hint\n\nimport "unicode"\n\nvar _ = unicode.IsDigit\n'}),
                         (["TestDown"], ["TestDown"]))

    def test_a_package_wide_directive_is_every_test(self):
        # #6377: a //go:debug line sets a GODEBUG default for the whole test binary, so adding, changing,
        # removing or moving one changes every test of the package, not only its own file's. A //go:
        # directive not known to reach only its declaration or file is read so too (fail closed).
        # REQ: MUT-go-debug-every
        other = 'package hint\n\nimport "testing"\n\nfunc TestOther(t *testing.T) {}\n'
        base = {"hint_test.go": MOVE_TEST, "other_test.go": other}
        debug = "//go:debug panicnil=1\n\n"
        for name, was, now in (
                ("added above the package clause", base, {**base, "other_test.go": debug + other}),
                ("added right above it", base, {**base, "other_test.go": debug.rstrip("\n") + "\n" + other}),
                ("changed", {**base, "other_test.go": debug + other},
                 {**base, "other_test.go": debug.replace("=1", "=0") + other}),
                ("removed", {**base, "other_test.go": debug + other}, base),
                ("moved to another file", {**base, "other_test.go": debug + other},
                 {"hint_test.go": debug + MOVE_TEST, "other_test.go": other}),
                ("in a new file", base, {**base, "new_test.go": debug + "package hint\n"}),
                ("misplaced on a function", base,
                 {**base, "other_test.go": other.replace("func TestOther", "//go:debug panicnil=1\nfunc TestOther")}),
                ("a directive not known", base, {**base, "other_test.go": "//go:future x\n\n" + other}),
                # Security on #6419: go skips a leading byte order mark and reads the directive behind it.
                ("behind a byte order mark", base, {**base, "other_test.go": "\ufeff" + debug + other}),
                ("indented, as go/build reads it", base, {**base, "other_test.go": "\t" + debug + other}),
                # Text go refuses to compile (a NUL, a BOM past the start) is not read: every test.
                ("a NUL", base, {**base, "other_test.go": other + "// \0\n"}),
                ("a byte order mark past the start", base, {**base, "other_test.go": other + "// \ufeff\n"})):
            with self.subTest(name):
                # gofmt drops a leading BOM and a header's indent and refuses a NUL, so these stay as written.
                raw = name.startswith(("behind", "indented", "a NUL", "a byte order"))
                self.assertEqual(self.reach(was, now, fmt=not raw), (None, None))
        # An unchanged go:debug line changes nothing: an edit elsewhere in its file is still that code's.
        held = {**base, "other_test.go": debug + other}
        self.assertEqual(self.reach(held, {**held, "other_test.go": debug + other.replace("{}\n", "{\n\t_ = Up(1)\n}\n")}),
                         (["TestOther"], ["TestOther"]))
        # A directive that reaches only its declaration stays that declaration's tests.
        self.assertEqual(self.reach(base, {**base, "hint_test.go": MOVE_TEST.replace("func one()", "//go:noinline\nfunc one()")}),
                         (["TestUp"], ["TestUp"]))
        for d in ("go:debug x=1", "go:linkname a b", "go:future"):
            self.assertTrue(mutgate._decls("broker/hint/a_test.go", f"//{d}\npackage hint\n")[0][5], d)
        for d in ("go:build linux", "go:noinline", "go:nosplit", "go:embed x.txt"):
            self.assertFalse(mutgate._decls("broker/hint/a_test.go", f"//{d}\npackage hint\n")[0][5], d)

    def test_go_text_reads_go_source_as_go_does(self):
        # Security on #6419: every Go-source read goes through go_text, which skips one leading byte
        # order mark as go/scanner does and refuses what go does not compile (#6377).
        # REQ: MUT-go-debug-every
        self.assertEqual(mutgate.go_text("\ufeffpackage p\n".encode()), "package p\n")
        self.assertEqual(mutgate.go_text(b"package p\n"), "package p\n")
        for raw in (b"package p\n// \xff\n", b"package p\n// \x00\n", "\ufeff\ufeffpackage p\n".encode(),
                    "package p\n// \ufeff\n".encode()):
            self.assertIsNone(mutgate.go_text(raw), raw)
        with tempfile.TemporaryDirectory() as d:
            pkg = pathlib.Path(d) / "broker" / "p"
            pkg.mkdir(parents=True)
            (pkg / "a_test.go").write_bytes(b'package p\n\nimport "testing"\n\nfunc TestA(t *testing.T) {}\n// \xff\n')
            with mock.patch.object(mutgate, "BROKER", pkg.parent):
                self.assertIsNone(mutgate.head_tests({"broker/p/a_test.go": {5}}, "p"))
                self.assertTrue(mutgate.names_file(pkg, "x.txt"))

    def test_directives_match_go_build(self):
        # Differential check (Security on #6419): each header spelling go/build reads a //go: directive
        # from, other than one LOCAL_DIRECTIVES holds, is every test here.
        # REQ: MUT-go-debug-every
        corpus = {
            "plain_test.go": "//go:debug panicnil=1\npackage p\n",
            "blank_test.go": "//go:debug panicnil=1\n\npackage p\n",
            "bom_test.go": "\ufeff//go:debug panicnil=1\npackage p\n",
            "crlf_test.go": "//go:debug panicnil=1\r\npackage p\r\n",
            "tab_test.go": "\t//go:debug panicnil=1\npackage p\n",
            "space_test.go": "  //go:debug panicnil=1\npackage p\n",
            "doc_test.go": "// Package p.\n//go:debug panicnil=1\npackage p\n",
            "block_test.go": "/* x */\n//go:debug panicnil=1\npackage p\n",
            "build_test.go": "//go:build linux\n\n//go:debug panicnil=1\npackage p\n",
            "future_test.go": "//go:future\npackage p\n",
            "local_test.go": "//go:build linux\n\npackage p\n",
        }
        oracle = ('package main\n\nimport (\n\t"encoding/json"\n\t"go/build"\n\t"os"\n)\n\nfunc main() {\n'
                  '\tp, err := build.ImportDir(os.Args[1], build.IgnoreVendor)\n\tif err != nil {\n\t\tpanic(err)\n\t}\n'
                  '\tjson.NewEncoder(os.Stdout).Encode(p.TestDirectives)\n}\n')
        with tempfile.TemporaryDirectory() as d:
            pkg, tool = pathlib.Path(d) / "p", pathlib.Path(d) / "oracle"
            pkg.mkdir()
            tool.mkdir()
            (pkg / "p.go").write_text("package p\n")
            for name, text in corpus.items():
                (pkg / name).write_bytes(text.encode())
            (tool / "main.go").write_text(oracle)
            env = {**os.environ, "GOOS": "linux", "GO111MODULE": "off", "GOFLAGS": ""}
            got = json.loads(subprocess.run(["go", "run", "main.go", str(pkg)], cwd=tool, env=env, capture_output=True,
                                            text=True, check=True).stdout) or []
        wide = {pathlib.Path(g["Pos"]["Filename"]).name for g in got
                if g["Text"][len("//go:"):].split()[0] not in mutgate.LOCAL_DIRECTIVES}
        self.assertEqual(wide, set(corpus) - {"local_test.go"})  # go/build reads every spelling above
        for name, text in corpus.items():
            with self.subTest(name):
                read = mutgate._decls(f"broker/p/{name}", mutgate.go_text(text.encode()))
                self.assertEqual(any(x[5] for x in read if x[1] == "header"), name in wide)

    def test_build_constraints_compare_as_go_reads_them(self):
        # #6385: a constraint is read as go/build reads the header and compared by meaning, not text.
        # REQ: TOOL-mutgate-moved-lines-fu
        c = mutgate._constraint
        self.assertEqual(c("p/a_test.go", "//go:build linux && amd64\n\npackage p\n"),
                         c("p/b_test.go", "//go:build amd64 && linux\n\npackage p\n"))
        self.assertEqual(c("p/a_test.go", "//go:build linux && amd64\n\npackage p\n"), c("p/b_linux_amd64_test.go", "package p\n"))
        self.assertEqual(c("p/a_test.go", "//go:build linux || !linux\n\npackage p\n"), mutgate.ALWAYS)
        self.assertEqual(c("p/a_test.go", "/*\n//go:build linux\n*/\npackage p\n"), mutgate.ALWAYS)  # inside /* */: none
        self.assertEqual(c("p/a_test.go", "package p\n\n//go:build linux\n"), mutgate.ALWAYS)  # after the clause: none
        self.assertNotEqual(c("p/a_test.go", "//go:build linux\n\npackage p\n"), mutgate.ALWAYS)
        self.assertNotEqual(c("p/a_test.go", "//go:build linux\n\npackage p\n"), c("p/a_test.go", "//go:build linux && cgo\n\npackage p\n"))
        self.assertEqual(c("p/_a_test.go", "package p\n"), "ignored")
        for unread in ("// +build linux\n\npackage p\n", "//go:build linux\n//go:build amd64\n\npackage p\n",
                       "//go:build linux &&\n\npackage p\n", "//go:build (linux\n\npackage p\n", "//go:build a b\n\npackage p\n",
                       "//go:build " + " && ".join(f"t{i}" for i in range(13)) + "\n\npackage p\n",
                       "//go:build\x1cfoo\n\npackage p\n", "//go:build linux\n\npackage p // \x1f\n", "//go:build\vlinux\n\npackage p\n",
                       "//go:build linux &&\u00a0foo\n\npackage p\n", "//go:build \u00e9t\u00e9\n\npackage p\n"):
            with self.subTest(unread):
                self.assertIsNone(c("p/a_test.go", unread))

    def test_build_constraints_match_go_list(self):
        # The differential corpus #6385 asks for: for each header shape and build context, a file is in
        # `go list`'s GoFiles exactly when its _constraint's truth table says it builds there.
        # REQ: TOOL-mutgate-moved-lines-fu
        heads = ["", "//go:build linux\n\n", "//go:build amd64 && linux\n\n", "//go:build !linux || foo\n\n",
                 "/*\n//go:build linux\n*/\n", "// doc\n/* x */\n//go:build (linux || darwin) && !arm64\n\n",
                 "//go:build linux\n// +build linux\n\n", "//go:build ignore\n\n", "//go:build go1.1 && foo\n\n",
                 "package q\n\n//go:build linux\n",
                 # Security on #6421: Go reads U+001C-U+001F as no space, Python as space; go/build/constraint
                 # skips only spaces and tabs; a tag is letters, digits, _ and .
                 "//go:build\x1cfoo\n\n", "//go:build\x1ffoo\n\n", "//go:build linux\x1c\n\n", "//go:build\vlinux\n\n",
                 "//go:build\u00a0linux\n\n", "//go:build linux &&\u00a0foo\n\n", "//go:build linux\f\n\n",
                 "//go:build \u00e9t\u00e9\n\n", "//go:build\tlinux\t&&\tfoo\n\n", "//go:build  ( linux )\n\n"]
        names = ["x{}.go", "x{}_linux.go", "x{}_darwin_arm64.go", "x{}_amd64.go"]
        with tempfile.TemporaryDirectory() as d:
            (pathlib.Path(d) / "go.mod").write_text("module ex\n\ngo 1.22\n")
            files = {}
            for i, head in enumerate(heads):
                for name in names:
                    f = name.format(i)
                    files[f] = head + ("" if head.startswith("package") else "package q\n")
                    (pathlib.Path(d) / f).write_text(files[f])
            for goos, goarch, tags in (("linux", "amd64", ""), ("darwin", "arm64", "foo"), ("windows", "amd64", "foo"),
                                       ("linux", "arm64", "ignore")):
                with self.subTest(goos=goos, goarch=goarch, tags=tags):
                    env = {**os.environ, "GOOS": goos, "GOARCH": goarch, "GOFLAGS": "", "CGO_ENABLED": "0"}
                    got = subprocess.run(["go", "list", "-e", "-tags", tags, "-f", "{{range .GoFiles}}{{.}} {{end}}", "."], cwd=d,
                                         env=env, capture_output=True, text=True, check=True).stdout.split()
                    on = {goos, goarch, "go1.1", "gc", *filter(None, tags.split(","))} | ({"unix"} if goos != "windows" else set())
                    want, read = [], 0
                    for f, text in sorted(files.items()):
                        if (c := mutgate._constraint(f"p/{f}", text)) is None:
                            got = [g for g in got if g != f]  # not read: fails closed, whatever go makes of it
                            continue
                        read += 1
                        used, table = c
                        want += [f] if table[sum(1 << i for i, t in enumerate(used) if t in on)] else []
                    self.assertEqual(sorted(got), want)
                    self.assertGreaterEqual(read, 4 * 12)

    def test_a_move_across_another_effective_constraint_is_a_change(self):
        # #6385: the same build text where go reads none (inside /* */) is another build context; equal
        # constraints written in another order are the same one.
        # REQ: TOOL-mutgate-moved-lines-fu
        rest = MOVE_TEST.replace(MOVE_ONE, "").replace('\t"strings"\n', "")
        head = 'package hint\n\nimport "strings"\n\n'
        base = {"hint_test.go": rest, "a_test.go": "/*\n//go:build linux\n*/\n" + head + MOVE_ONE}
        self.assertEqual(self.reach(base, {"hint_test.go": rest, "b_test.go": "//go:build linux\n\n" + head + MOVE_ONE}),
                         (["TestUp"], ["TestUp"]))
        base = {"hint_test.go": rest, "a_test.go": "//go:build linux && amd64\n\n" + head + MOVE_ONE}
        self.assertEqual(self.reach(base, {"hint_test.go": rest, "b_test.go": "//go:build amd64 && linux\n\n" + head + MOVE_ONE}),
                         ([], []))

    def test_a_constraint_go_reads_otherwise_moves_nothing(self):
        # Security on #6421: `//go:build\x1cfoo` is a plain comment to Go (always built), a constraint foo to
        # Python's whitespace; read as foo it made a move out of `//go:build foo` an unchanged one.
        # REQ: TOOL-mutgate-moved-lines-fu
        rest = MOVE_TEST.replace(MOVE_ONE, "").replace('\t"strings"\n', "")
        head = 'package hint\n\nimport "strings"\n\n'
        for was, now in (("//go:build foo", "//go:build\x1cfoo"), ("//go:build\x1ffoo", "//go:build foo")):
            with self.subTest(was=was):
                got = self.reach({"hint_test.go": rest, "b_test.go": was + "\n\n" + head + MOVE_ONE},
                                 {"hint_test.go": rest, "a_test.go": now + "\n\n" + head + MOVE_ONE})
                self.assertNotEqual(got, ([], []))

    def test_a_layout_gofmt_would_change_moves_nothing(self):
        # Security on #6378: `func TestB (t` hid TestB from RUNNABLE, so a reorder read as a move.
        # REQ: TOOL-mutgate-moved-lines-fu
        spaced = MOVE_TEST.replace("func TestDown(t", "func TestDown (t")
        up = spaced[spaced.index("func TestUp"):spaced.index("func TestDown")]
        got = self.reach({"hint_test.go": spaced}, {"hint_test.go": spaced.replace(up, "") + "\n" + up.rstrip("\n") + "\n"}, fmt=False)
        self.assertEqual(got, (None, None))

    def test_a_new_test_file_that_runs_first_changes_the_tests_after_it(self):
        # Security on #6378: `go test` runs files in name order, so a new file's tests run before every
        # test of a file named after it; a file named last, or one that adds no test, changes no other.
        # REQ: TOOL-mutgate-moved-lines-fu
        new = 'package hint\n\nimport "testing"\n\nfunc TestNew(t *testing.T) {\n\tif Up(2) != 3 {\n\t\tt.Fatal(0)\n\t}\n}\n'
        base = {"hint_test.go": MOVE_TEST}
        self.assertEqual(self.reach(base, {**base, "a_test.go": new}), (["TestDown", "TestNew", "TestUp"], ["TestDown", "TestUp"]))
        self.assertEqual(self.reach(base, {**base, "z_test.go": new}), (["TestNew"], []))
        # Renamed: its tests run in another place, so the tests between both places run after other ones.
        self.assertEqual(self.reach({**base, "z_test.go": new}, {**base, "a_test.go": new}),
                         (["TestDown", "TestNew", "TestUp"], ["TestDown", "TestNew", "TestUp"]))
        # A parallel test resumes after every sequential one: any change to the run list reaches it.
        par = MOVE_TEST.replace('t.Fatal("down")\n\t}', 't.Fatal("down")\n\t}\n\tt.Parallel()')
        self.assertEqual(self.reach({"hint_test.go": par}, {"hint_test.go": par, "z_test.go": new}),
                         (["TestDown", "TestNew", "TestUp"], ["TestDown", "TestUp"]))
        # So does one a helper calls: in a non-test file of the package, or in a package it imports (L3 and
        # Security on #6421).
        both = (["TestDown", "TestNew", "TestUp"], ["TestDown", "TestUp"])
        helper = TWO_SRC.replace("package hint\n", 'package hint\n\nimport "testing"\n') + "\nfunc par(t *testing.T) { t.Parallel() }\n"
        self.assertEqual(self.reach(base, {**base, "z_test.go": new}, src=helper), both)
        lib = 'package lib\n\nimport "testing"\n\n// Par runs t in parallel.\nfunc Par(t *testing.T) { t.Parallel() }\n'
        src = TWO_SRC.replace("package hint\n", 'package hint\n\nimport _ "example.invalid/broker/lib"\n')
        self.assertEqual(self.reach(base, {**base, "z_test.go": new}, src=src, extra={"lib/lib.go": lib}), both)
        self.assertEqual(self.reach(base, {**base, "z_test.go": new}, src=src, extra={"lib/lib.go": lib.replace("t.Parallel()", "t.Helper()")}),
                         (["TestNew"], []))
        # An imported package's own tests are not built into this package's test binary (#6372).
        quiet = lib.replace("t.Parallel()", "t.Helper()")
        self.assertEqual(self.reach(base, {**base, "z_test.go": new}, src=src,
                                    extra={"lib/lib.go": quiet, "lib/lib_test.go": lib.replace("func Par(", "func par(")}),
                         (["TestNew"], []))

    def test_a_declaration_of_a_cgo_file_never_moves(self):
        # #6385, from #6376: a cgo file's code binds its own preamble, so nothing moves out of one.
        # REQ: TOOL-mutgate-moved-lines-fu
        helper = "// two is a helper.\nfunc two() int { return Up(1) }\n"
        test = 'package hint\n\nimport "testing"\n\nfunc TestTwo(t *testing.T) {\n\tif two() != 2 {\n\t\tt.Fatal(2)\n\t}\n}\n'
        cgo = TWO_SRC.replace("package hint\n", 'package hint\n\n// int c(void) { return 1; }\nimport "C"\n') + "\n" + helper
        base = {"hint_test.go": TWO_TEST, "two_test.go": test}
        self.assertEqual(self.reach(base, {**base, "z_test.go": "package hint\n\n" + helper}, src=cgo, head_src=TWO_SRC),
                         (["TestTwo"], []))
        self.assertEqual(self.reach(base, {**base, "z_test.go": "package hint\n\n" + helper},
                                    src=TWO_SRC + "\n" + helper, head_src=TWO_SRC), ([], []))

    def test_a_qualifier_bound_otherwise_and_a_pure_add_of_moved_lines(self):
        # #6385 items from #6376, shown held: a package name is usable only as a qualifier (Go refuses a
        # bare one, and one name in both the file and package block), so a word's binding differs only
        # behind `q.`, which must bind the same import; and a hunk that only adds moved lines is no gap.
        # REQ: TOOL-mutgate-moved-lines-fu
        rest = MOVE_TEST.replace(MOVE_ONE, "").replace('\t"strings"\n', "")
        local = "package hint\n\nvar strings struct{ Repeat func(string, int) string }\n\n" + MOVE_ONE.rstrip("\n") + "\n"
        got = self.reach({"hint_test.go": MOVE_TEST}, {"hint_test.go": rest, "other_test.go": local})
        self.assertIn("TestUp", got[0])
        self.assertIn("TestUp", got[1])
        none = 'package hint\n\nimport "testing"\n\nfunc TestNone(t *testing.T) {}\n'
        with_one = none.replace('import "testing"', 'import (\n\t"strings"\n\t"testing"\n)') + "\n" + MOVE_ONE.rstrip("\n") + "\n"
        diff = ("diff --git a/broker/hint/other_test.go b/broker/hint/other_test.go\n--- a/broker/hint/other_test.go\n"
                "+++ b/broker/hint/other_test.go\n@@ -5,0 +6,3 @@\n+\n+// one is TestUp's helper.\n+func one() int\n")
        self.assertEqual(mutgate.base_test_lines(diff, ({"broker/hint/other_test.go": {6, 7, 8}}, {})), ({}, {}))
        self.assertEqual(mutgate.base_test_lines(diff)[1], {"broker/hint/other_test.go": {5}})
        self.assertEqual(self.reach({"hint_test.go": MOVE_TEST, "other_test.go": none}, {"hint_test.go": rest, "other_test.go": with_one}),
                         ([], []))

    def test_file_name_constraints_cover_every_port(self):
        # _name_tags reads a GOOS or GOARCH from a file name only if it is listed: every port the pinned
        # Go names must be (L3 on #6378). go/build's known lists hold more (nacl, zos); that is safe.
        ports = subprocess.run(["go", "tool", "dist", "list"], capture_output=True, text=True, check=True).stdout.split()
        self.assertTrue(ports)
        for port in ports:
            goos, goarch = port.split("/")
            self.assertIn(goos, mutgate.GOOS)
            self.assertIn(goarch, mutgate.GOARCH)
            self.assertEqual(mutgate._name_tags(f"broker/p/x_{goos}_{goarch}_test.go"), (goos, goarch))
        self.assertEqual(mutgate._name_tags("broker/p/x_linux.go"), ("linux",))
        self.assertEqual(mutgate._name_tags("broker/p/clients_test.go"), ())
        self.assertEqual(mutgate._name_tags("broker/p/_x_test.go"), ("ignored",))


class GofmtPin(unittest.TestCase):
    """TOOL-mutgate-gofmt-pin (#6442): moved() reads layout with the toolchain's own gofmt, never PATH's;
    a gofmt that is missing or not go.mod's toolchain version refuses the run."""

    def setUp(self):
        mutgate.gofmt.cache_clear()
        self.addCleanup(mutgate.gofmt.cache_clear)

    def test_the_gofmt_is_the_toolchains_and_its_version(self):
        # REQ: TOOL-mutgate-gofmt-pin
        env = {**os.environ, "GOWORK": "off"}
        goroot = subprocess.run(["go", "env", "GOROOT"], cwd=mutgate.BROKER, capture_output=True, text=True,
                                check=True, env=env).stdout.strip()
        got = mutgate.gofmt()
        self.assertEqual(got, str(pathlib.Path(goroot) / "bin" / "gofmt"))
        self.assertEqual(subprocess.run(["go", "version", got], cwd=mutgate.BROKER, capture_output=True,
                                        text=True, env=env).stdout.strip(), f"{got}: {TOOLCHAIN}")
        # The pin stays broker/go.mod's where a test moves BROKER.
        with mock.patch.object(mutgate, "BROKER", pathlib.Path("/nonexistent")):
            mutgate.gofmt.cache_clear()
            self.assertEqual(mutgate.gofmt(), got)

    def test_unformatted_runs_the_pinned_gofmt_not_paths(self):
        # REQ: TOOL-mutgate-gofmt-pin
        real, argv = subprocess.run, []
        record = lambda cmd, *a, **k: (argv.append(list(cmd)), real(cmd, *a, **k))[1]
        with mock.patch.object(mutgate.subprocess, "run", side_effect=record):
            self.assertEqual(mutgate._unformatted({"broker/x/a.go": "package x\nfunc  F() {}\n",
                                                   "broker/x/b.go": "package x\n"}), {"broker/x/a.go"})
        self.assertEqual([c for c in argv if "-l" in c], [[mutgate.gofmt(), "-l", "."]])

    def pinned(self, mod, answers):
        """mutgate.gofmt() with go.mod text mod and `go` answering answers: {first arg: (rc, stdout) or an
        OSError}; any other command is refused, so PATH's gofmt never runs."""
        d = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d)
        (d / "go.mod").write_text(mod)
        calls = []

        def run(cmd, *a, **k):
            calls.append(list(cmd))
            if cmd[0] != "go" or cmd[1] not in answers:
                raise AssertionError(f"unexpected command {cmd}")
            got = answers[cmd[1]]
            if isinstance(got, OSError):
                raise got
            rc, out = got(d) if callable(got) else got
            return subprocess.CompletedProcess(cmd, rc, out, "refused" if rc else "")
        with mock.patch.object(mutgate, "GO_MOD_PIN", d / "go.mod"), \
                mock.patch.object(mutgate.subprocess, "run", side_effect=run):
            try:
                return mutgate.gofmt(), calls
            except RuntimeError as e:
                return e, calls

    def test_a_gofmt_not_the_pinned_one_refuses_the_run(self):
        # REQ: TOOL-mutgate-gofmt-pin
        mod = "module example.invalid/broker\n\ngo 1.26.4\n\ntoolchain go1.26.11\n"

        def goroot(d, made=True):
            if made:
                (d / "root" / "bin").mkdir(parents=True, exist_ok=True)
                (d / "root" / "bin" / "gofmt").write_text("")
            return 0, f"{d / 'root'}\n"
        version = lambda d, v="go1.26.11": (0, f"{d / 'root' / 'bin' / 'gofmt'}: {v}\n")
        got, calls = self.pinned(mod, {"env": goroot, "version": version})
        self.assertIsInstance(got, str)
        self.assertTrue(got.endswith("/root/bin/gofmt"), got)
        self.assertEqual([c[:2] for c in calls], [["go", "env"], ["go", "version"]])
        for why, m, answers in (
                ("no toolchain line", mod.replace("toolchain go1.26.11\n", ""), {}),
                ("go missing", mod, {"env": FileNotFoundError("go")}),
                ("go env fails", mod, {"env": (1, "")}),
                ("no GOROOT", mod, {"env": (0, "\n")}),
                ("no gofmt in GOROOT", mod, {"env": lambda d: goroot(d, made=False)}),
                ("another version", mod, {"env": goroot, "version": lambda d: version(d, "go1.24.7")}),
                ("a version that only starts alike", mod, {"env": goroot, "version": lambda d: version(d, "go1.26.110")}),
                ("go version fails", mod, {"env": goroot, "version": (1, "")})):
            with self.subTest(why):
                mutgate.gofmt.cache_clear()
                got, calls = self.pinned(m, answers)
                self.assertIsInstance(got, RuntimeError)
                self.assertTrue(all(c[0] == "go" for c in calls), calls)

    def test_a_refused_gofmt_refuses_unformatted(self):
        # The run refuses rather than reading every file as rough, the old fallback for a missing gofmt.
        # REQ: TOOL-mutgate-gofmt-pin
        with mock.patch.object(mutgate, "gofmt", side_effect=RuntimeError("mutgate: no gofmt")):
            with self.assertRaises(RuntimeError):
                mutgate._unformatted({"broker/x/a.go": "package x\n"})
        with mock.patch.object(mutgate, "gofmt", return_value="/nonexistent/bin/gofmt"):
            with self.assertRaises(RuntimeError):
                mutgate._unformatted({"broker/x/a.go": "package x\n"})


class DataFiles(unittest.TestCase):
    """MUT-deleted-test-own-lines-fu (#5779, Security S1 on #5770): a changed data file of a package
    changes its tests, every one of them."""

    def tree(self, d, files):
        broker = pathlib.Path(d) / "broker"
        for name, text in files.items():
            (broker / name).parent.mkdir(parents=True, exist_ok=True)
            (broker / name).write_text(text)
        return mock.patch.object(mutgate, "BROKER", broker)

    def test_a_data_file_changes_its_owners_tests(self):
        # REQ: MUT-deleted-test-own-lines-fu
        code = {"hint/hint.go": "package hint\n", "hint/hint_test.go": 'package hint\n// reads "cases.json"\nvar _ = "cases.json"\n',
                "hint/static/x.go": "package static\n", "hint/tmpl/a.html": ""}
        with tempfile.TemporaryDirectory() as d, self.tree(d, code):
            for path, owner in (("broker/hint/testdata/a.txt", "hint"),
                                ("broker/hint/testdata/deep/b.go", "hint"),     # a Go fixture is data too
                                ("broker/hint/testdata/c_test.go", "hint"),
                                ("broker/hint/cases.json", "hint"),
                                ("broker/hint/tmpl/a.html", "hint"),            # no .go there: its parent's
                                ("broker/hint/static/s.css", "hint/static"),
                                ("broker/hint/notes.txt", "hint"),              # any non-Markdown file counts
                                ("broker/hint/ASSUMPTIONS.md", None),           # no .go file names it
                                ("broker/hint/MUTANTS-EQUIVALENT", None),       # records_changed reads it
                                ("broker/go.sum", None),
                                ("broker/gone/testdata/a.txt", None)):
                for kind in ("change", "empty", "delete"):
                    with self.subTest(path=path, kind=kind):
                        added, tests = mutgate.added_lines(data_diff(path, kind))
                        self.assertEqual(mutgate.touched(added, tests), {owner} - {None})
                        if owner:
                            self.assertTrue(mutgate.tests_changed(tests, owner))
                            self.assertIsNone(mutgate.head_tests(tests, owner))  # every test
                            self.assertEqual(mutgate.diff_targets(added, owner), {})
                            self.assertEqual(mutgate.claimed(data_diff(path, kind), packages=[owner]), [owner])
            # A quoted name is read from its header too.
            q = 'diff --git "a/broker/hint/testdata/\\303\\251.txt" "b/broker/hint/testdata/\\303\\251.txt"\nnew file mode 100644\n'
            self.assertEqual(mutgate.touched(*mutgate.added_lines(q)), {"hint"})

    def test_a_markdown_file_counts_where_code_can_name_it(self):
        # ASSUMPTIONS.md changes in about a third of broker merges, and most packages' code never reads
        # it, so it counts only where a .go file can name it: by name, by a glob, or through a link;
        # a listing names none (hide_docs removes the file from the gate's trees, #6373). Comments name nothing.
        # REQ: MUT-deleted-test-own-lines-fu
        for name, src, counts in (
                ("by name", 'var _ = os.ReadFile("ASSUMPTIONS.md")', True),
                ("by embed", "//go:embed ASSUMPTIONS.md\nvar s string", True),
                ("by a glob", 'var _, _ = filepath.Glob("*.md")', True),
                ("by a listing", 'var _, _ = os.ReadDir(".")', False),
                ("by climbing out", 'var _ = filepath.WalkDir("..", nil)', False),
                ("by a relative path", 'var _ = os.ReadFile("../hint/ASSUMPTIONS.md")', True),
                # Security and L3 on #5943: a glob in any literal or embed pattern, and a listing in
                # any argument of a path call, name it too.
                ("by an embed glob", '//go:embed *.md\nvar docs embed.FS', True),
                ("by an embed of everything", '//go:embed *\nvar docs embed.FS', True),
                ("by an all: embed glob", '//go:embed all:*.md\nvar docs embed.FS', True),
                ("by fs.Glob", 'var _, _ = fs.Glob(F, "*.md")', True),
                ("by fs.WalkDir", 'var _ = fs.WalkDir(os.DirFS(root), ".", nil)', False),
                ("by fs.ReadDir", 'var _, _ = fs.ReadDir(F, ".")', False),
                ("by a glob in a join", 'var _, _ = filepath.Glob(filepath.Join(dir, "*.md"))', True),
                # Security on #5943 (38364f58): a glob behind a directory part matches by its last part.
                ("by a glob after a directory", 'var _, _ = filepath.Glob(dir + "/*.md")', True),
                ("by a glob in a format", 'var _, _ = filepath.Glob(fmt.Sprintf("%s/*.md", dir))', True),
                ("by a recursive glob", 'var _ = match("**/*.md")', True),
                ("a directory glob of another name", 'var _, _ = fs.Glob(F, "templates/*.html")', False),
                ("by a climb in a join", 'var _ = os.ReadFile(filepath.Join("..", x))', False),
                ("past a rune", "var _ = os.ReadDir(string(')') + \".\")", False),
                ("in a comment", "// see ASSUMPTIONS.md", False),
                ("a glob of another name", '//go:embed *.html\nvar docs embed.FS', False),
                ("a join of words", 'import "strings"\n\nvar _ = strings.Join(words, "")', False),
                ("another glob", 'var _, _ = filepath.Glob("*.go")', False),
                ("a dot elsewhere", 'import "strings"\n\nvar _ = strings.Split(h, ".")', False),
                ("an absolute listing", 'var _, _ = os.ReadDir("/proc/self/fd")', False)):
            with self.subTest(name), tempfile.TemporaryDirectory() as d, \
                    self.tree(d, {"hint/hint.go": "package hint\n", "hint/hint_test.go": f"package hint\n\n{src}\n"}):
                got = mutgate.touched(*mutgate.added_lines(data_diff("broker/hint/ASSUMPTIONS.md")))
                self.assertEqual(got, {"hint"} if counts else set())
        with tempfile.TemporaryDirectory() as d, self.tree(d, {"hint/hint.go": "package hint\n"}):
            os.symlink("hint.go", pathlib.Path(d) / "broker" / "hint" / "link.go")
            self.assertEqual(mutgate.data_owner("broker/hint/ASSUMPTIONS.md"), "hint")

    def assertNames(self, cases, path="broker/hint/ASSUMPTIONS.md"):
        for name, src, counts in cases:
            with self.subTest(name), tempfile.TemporaryDirectory() as d, \
                    self.tree(d, {"hint/hint.go": "package hint\n", "hint/hint_test.go": f"package hint\n\n{src}\n"}):
                got = mutgate.touched(*mutgate.added_lines(data_diff(path)))
                self.assertEqual(got, {"hint"} if counts else set())

    def test_a_glob_counts_anywhere(self):
        # #6390: a glob held as data can reach any listing call through a variable, and no list of
        # listing functions is complete (ParseGlob, Readdirnames), so a glob holding part of a name
        # counts anywhere (#6328 and #6336 counted it only beside a listing function the gate knew by name).
        # REQ: MUT-deleted-test-own-lines-fu
        self.assertNames((
                ("a star beside a name", 'var s = "ASSUMPTIONS*"', True),
                ("a star before a dot", 'var s = "*.md"', True),
                ("a star in a variable", 'func f() { p := "*.md"; fs.Glob(F, p) }', True),
                ("a star embedded", '//go:embed *\nvar docs embed.FS', True),
                ("stars embedded", '//go:embed */*\nvar docs embed.FS', True),
                ("a star only in a comment", '// "*.md"\nvar s = "x"', False),
                ("a glob of another name", 'var s = "*.html"', False)))
        self.assertNames((('var q = "??.md"', 'var q = "??.md"', True), ('var q = "?.md"', 'var q = "?.md"', False)),
                         "broker/hint/ab.md")

    def test_a_literal_of_wildcards_alone_names_no_markdown_file(self):
        # #6584: a literal of `*`, `?` and `/` alone matches every name, so a table's "*" (#6514's
        # confusables, #6485's skeleton fold) or a DNS wildcard made each ASSUMPTIONS.md edit claim
        # every test of its package. It names none; a //go:embed pattern of wildcards still does.
        # REQ: MUT-deleted-test-own-lines-fu
        self.assertNames((
                ("a table's star", 'var table = map[rune]string{0x2217: "*"}', False),
                ("a DNS wildcard", 'var _ = listHas(v, "email") || listHas(v, "*")', False),
                ("an Accept header", 'var h = map[string]string{"Accept": "*/*"}', False),
                ("a raw star", "var s = `**`", False),
                ("a star in a variable", 'func f() { p := "*"; fs.Glob(F, p) }', False),
                ("a star beside a template glob", 'var s = "*"\nvar _ = template.Must(template.ParseGlob(s))', False),
                ("a star and a name", 'var _, _ = "*", "ASSUMPTIONS.md"', True),
                ("a star with a dot", 'var s = "*.*"', True),
                ("a star with a bracket", 'var s = "[A-Z]*"', True),
                ("a star embedded", '//go:embed *\nvar docs embed.FS', True)))
        self.assertNames((('var q = "????"', 'var q = "????"', False), ('var q = "/????"', 'var q = "/????"', False),
                          ('var q = "?.md"', 'var q = "?.md"', True)), "broker/hint/a.md")
        self.assertNames((('var q = "*[*"', 'var q = "*[*"', True),), "broker/hint/a[1].md")  # a bracket is no wildcard here
        # Another data file a "*" lists stays in every tree, so embedded_by still reads the star.
        star = {**EMBED_PKG, "v/glob_test.go": 'package v\n\nvar _ = "*"\n'}
        with tempfile.TemporaryDirectory() as d, self.tree(d, star):
            self.assertIsNone(mutgate.embedded_by("v", "models.pins"))

    def test_a_listing_by_a_star_reads_no_hidden_markdown_file(self):
        # #6584: a test that lists its package with a bare "*" and needs ASSUMPTIONS.md fails in the
        # gate's tree, closed: the file is hidden there, as for a listing by "." (#6373).
        # REQ: MUT-deleted-test-own-lines-fu
        test = ('package hint\n\nimport (\n\t"path/filepath"\n\t"testing"\n)\n\n'
                'func TestDoc(t *testing.T) {\n\tm, _ := filepath.Glob("*")\n\tfor _, f := range m {\n'
                '\t\tif f == "ASSUMPTIONS"+".md" {\n\t\t\treturn\n\t\t}\n\t}\n\tt.Fatal(m)\n}\n')
        files = {"go.mod": "module example.com/b\n\ngo 1.21\n", "hint/hint.go": "package hint\n",
                 "hint/hint_test.go": test, "hint/ASSUMPTIONS.md": "x"}
        with tempfile.TemporaryDirectory() as d, self.tree(d, files), self.made(d):
            broker = pathlib.Path(d) / "broker"
            run = lambda: subprocess.run(["go", "test", "-count=1", "./hint"], cwd=broker, capture_output=True,
                                         env={**os.environ, "GOFLAGS": "-mod=mod", "GOTOOLCHAIN": "local"})
            self.assertEqual(run().returncode, 0)
            self.assertEqual(mutgate.hide_docs(broker), ["broker/hint/ASSUMPTIONS.md"])
            self.assertNotEqual(run().returncode, 0)

    def test_only_a_name_keeps_a_markdown_file(self):
        # #6373: a listing, a child process, cgo, a raw system call or a path built at run time
        # names no file: hide_docs removes the file from every tree the gate runs, so such a read
        # fails the gate's run instead of counting the package. Escapes decode (Security on #6403).
        # REQ: MUT-deleted-test-own-lines-fu
        self.assertNames((
                ("an escaped dot", 'var _ = os.ReadFile("ASSUMPTIONS\\x2emd")', True),
                ("an octal escape", 'var _ = os.ReadFile("ASSUMPTIONS\\056md")', True),
                ("a unicode escape", 'var _ = os.ReadFile("\\u0041SSUMPTIONS.md")', True),
                ("a climb back", 'var _ = os.ReadFile("sub/../ASSUMPTIONS.md")', True),
                ("a const", 'const doc = "ASSUMPTIONS.md"', True),
                ("from Getwd", 'func f() { wd, _ := os.Getwd(); os.ReadFile(filepath.Join(wd, "ASSUMPTIONS.md")) }', True),
                ("a raw string keeps its backslash", 'var _ = os.ReadFile(`ASSUMPTIONS\\x2emd`)', False),
                ("a listing", 'var _, _ = os.ReadDir(".")', False),
                ("a climb", 'var _ = filepath.WalkDir("..", nil)', False),
                ("sub/..", 'var _, _ = os.ReadDir("sub/..")', False),
                ("runes", "var _ = os.ReadFile(string([]rune{'A', 'S'}) + \"SUMPTIONS\" + string('.') + \"md\")", False),
                ("bytes", 'var _ = os.ReadFile(string([]byte{65, 83, 83, 85, 77, 80, 84, 73, 79, 78, 83, 46, 109, 100}))', False),
                ("runtime.Caller", 'func f() { _, file, _, _ := runtime.Caller(0); os.ReadDir(filepath.Dir(file)) }', False),
                ("exec", 'import "os/exec"\n\nvar _ = exec.Command("cat", "README")', False),
                ("cgo", '// #include <stdio.h>\nimport "C"', False),
                ("syscall", 'import "syscall"\n\nvar _, _ = syscall.Open(".", 0, 0)', False)))
        # Go's escapes, each kind; an out-of-range one (a compile error in Go) reads, never raises.
        self.assertEqual(mutgate._go_string(r'\a\b\f\n\r\t\v\\\'\"\x41\101\u00e9\U0001F600'),
                         '\a\b\f\n\r\t\v\\\'"AAé\U0001F600')
        self.assertEqual(mutgate._go_string(r'\400\U0011FFFF\uD800'), "\ufffd\U0010ffff?")

    def test_an_unnamed_markdown_file_is_gone_from_every_gate_tree(self):
        # #6373: the gate's verdicts cannot depend on a Markdown file whose edit claims nothing,
        # because no tree the gate runs tests in holds it: it removes them before plan, run and
        # delete run anything, and from the base tree before its run. Named files, testdata,
        # other data and vendor/ stay; a directory with no package loses its own.
        # REQ: MUT-deleted-test-own-lines-fu
        files = {"hint/hint.go": "package hint\n", "hint/hint_test.go": 'package hint\n\nvar _ = os.ReadDir(".")\n',
                 "hint/ASSUMPTIONS.md": "x", "hint/sub/notes.md": "x", "hint/testdata/t.md": "x", "hint/cases.json": "x",
                 "named/named.go": 'package named\n\nconst doc = "ASSUMPTIONS.md"\n', "named/ASSUMPTIONS.md": "x",
                 "vendor/example.com/m/README.md": "x", "vendor/example.com/m/m.go": "package m\n",
                 "docs/guide.md": "x"}
        with tempfile.TemporaryDirectory() as d, self.tree(d, files), self.made(d):
            broker = pathlib.Path(d) / "broker"
            gone = mutgate.hide_docs(broker)
            self.assertEqual(gone, ["broker/docs/guide.md", "broker/hint/ASSUMPTIONS.md", "broker/hint/sub/notes.md"])
            left = sorted(p.relative_to(broker).as_posix() for p in broker.rglob("*") if p.is_file())
            self.assertEqual(left, ["hint/cases.json", "hint/hint.go", "hint/hint_test.go", "hint/testdata/t.md",
                                    "named/ASSUMPTIONS.md", "named/named.go", "vendor/example.com/m/README.md",
                                    "vendor/example.com/m/m.go"])
            self.assertEqual(mutgate.hide_docs(broker), [])
        # Each command that runs the gate's tests runs in scratch's tree; `run` without --git (whole
        # packages, never the gate's) runs in none, and no command hides in the tree it was given.
        for argv, want in ((["plan", "--git", "b"], "cmd_plan"), (["delete", "p", "--git", "b"], "cmd_delete"),
                           (["run", "p", "--git", "b"], "cmd_run"), (["run", "p"], None)):
            with self.subTest(argv), contextlib.ExitStack() as st:
                inside = []

                @contextlib.contextmanager
                def scratch():
                    inside.append(True)
                    yield
                    inside.append(False)
                st.enter_context(mock.patch.object(mutgate, "scratch", scratch))
                hide = st.enter_context(mock.patch.object(mutgate, "hide_docs"))
                cmds = {n: st.enter_context(mock.patch.object(mutgate, n, side_effect=lambda a: 0 if inside[-1:] == [True] else 7))
                        for n in ("cmd_plan", "cmd_delete", "cmd_run")}
                self.assertEqual(mutgate.main(argv), 0 if want else 7)
                self.assertEqual(inside, [True, False] if want else [])
                self.assertEqual([n for n, c in cmds.items() if c.called], [want or "cmd_run"])
                hide.assert_not_called()

    @staticmethod
    def made(d):
        """mutgate.MADE holding only d: hide_docs deletes in no other tree."""
        return mock.patch.object(mutgate, "MADE", {pathlib.Path(d).resolve()})

    def test_hiding_refuses_every_tree_mutgate_did_not_make(self):
        # #6456: hide_docs deleted from whatever broker/ it was given, so a local plan, delete or
        # run --git wiped uncommitted ASSUMPTIONS.md edits. It now refuses any tree but its own copies.
        # REQ: MUT-deleted-test-own-lines-fu
        with tempfile.TemporaryDirectory() as d, self.tree(d, {"hint/hint.go": "package hint\n", "hint/A.md": "edit"}):
            broker = pathlib.Path(d) / "broker"
            for made in (set(), {broker.resolve()}, {pathlib.Path(d).resolve().parent}):
                with self.subTest(made), mock.patch.object(mutgate, "MADE", made):
                    with self.assertRaisesRegex(ValueError, "no tree mutgate made"):
                        mutgate.hide_docs(broker)
            self.assertEqual((broker / "hint/A.md").read_text(), "edit")

    def test_a_gate_command_leaves_the_working_tree_as_it_was(self):
        # #6456: plan, delete and run --git run in a copy of the working tree, hidden there; the
        # clone's dirty, untracked and committed docs, its index and its HEAD are as they were after,
        # and the copy is gone. The copy holds what is on disk: a dirty, staged, untracked or
        # deleted file is so there too, and an ignored one is not.
        # REQ: MUT-deleted-test-own-lines-fu
        repo = self.repo({"broker/hint/hint.go": "package hint\n", "broker/hint/ASSUMPTIONS.md": "base",
                          "broker/hint/notes.md": "x", "broker/hint/gone.go": "package hint\n",
                          "broker/hint/staged.go": "package hint\n", ".gitignore": "*.out\n"})
        git = lambda *a: subprocess.run(["git", *a], cwd=repo, capture_output=True, text=True, check=True).stdout
        (repo / "broker/hint/ASSUMPTIONS.md").write_text("uncommitted")
        (repo / "broker/hint/new.md").write_text("untracked")
        (repo / "broker/hint/new.go").write_text('package hint\n\nconst n = "new.md"\n')
        (repo / "broker/hint/hint.go").write_text("package hint // dirty\n")
        (repo / "broker/hint/staged.go").write_text("package hint // staged\n")
        git("add", "broker/hint/staged.go")
        (repo / "broker/hint/gone.go").unlink()
        (repo / "broker/hint/x.out").write_text("ignored")
        before = (git("rev-parse", "HEAD"), git("status", "--porcelain", "--ignored"), git("ls-files", "-s"))
        seen = {}

        def plan(args):
            broker = mutgate.BROKER
            seen["root"] = mutgate.ROOT
            seen["left"] = {p.relative_to(broker).as_posix(): p.read_text() for p in broker.rglob("*") if p.is_file()}
            seen["head"] = subprocess.run(["git", "rev-parse", "HEAD"], cwd=broker, capture_output=True,
                                          text=True).stdout
            return 0
        with mock.patch.object(mutgate, "ROOT", repo), mock.patch.object(mutgate, "BROKER", repo / "broker"), \
                mock.patch.object(mutgate, "cmd_plan", side_effect=plan):
            self.assertEqual(mutgate.main(["plan", "--git", "HEAD"]), 0)
            self.assertEqual((mutgate.ROOT, mutgate.BROKER), (repo, repo / "broker"))
        self.assertNotEqual(seen["root"], repo)
        self.assertEqual(seen["left"], {"hint/hint.go": "package hint // dirty\n", "hint/new.go": 'package hint\n\nconst n = "new.md"\n',
                                        "hint/new.md": "untracked", "hint/staged.go": "package hint // staged\n"})
        self.assertEqual(seen["head"], before[0])
        self.assertEqual((git("rev-parse", "HEAD"), git("status", "--porcelain", "--ignored"), git("ls-files", "-s")), before)
        self.assertEqual((repo / "broker/hint/ASSUMPTIONS.md").read_text(), "uncommitted")
        self.assertFalse(seen["root"].exists())
        self.assertEqual(git("worktree", "list").count("\n"), 1)
        self.assertEqual(mutgate.MADE, set())

    def test_a_base_tree_run_reads_no_unnamed_markdown_file(self):
        # #6373: base_covered's archive of the base holds the base's docs; they go before its run.
        # REQ: MUT-deleted-test-own-lines-fu
        seen = {}

        def cover(pkg, names, tmp, broker):
            seen["left"] = sorted(p.name for p in (broker / pkg).iterdir())
            return {}, None
        repo = self.repo({"broker/hint/hint.go": "package hint\n", "broker/hint/ASSUMPTIONS.md": "x",
                          "broker/hint/notes.md": "x"})
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(mutgate, "ROOT", repo), \
                mock.patch.object(mutgate, "covered_by", side_effect=cover):
            sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()
            self.assertEqual(mutgate.base_covered("hint", sha, None, tmp, ""), ({}, None))
        self.assertEqual(seen["left"], ["hint.go"])

    def test_a_file_named_by_path_changes_its_readers_tests(self):
        # #6436: a test reading another package's fixture, another package's code or a file outside
        # broker/ by a literal path from its own directory changes when that file does, every test
        # of it; the file's own package keeps its claim. A path built otherwise, a directory, a
        # vendored file, an absolute path or one leaving the repository names nothing.
        # REQ: MUT-deleted-test-own-lines-fu
        code = {"other/other.go": "package other\n", "other/testdata/x.json": "x",
                "cmd/x/main.go": "package main\n", "vendor/example.com/m/m.go": "package m\n",
                "page/page.go": "package page\n",
                "page/page_test.go": 'package page\n\nvar (\n\t_ = "../../SPEC.md"\n\t_ = "../other/testdata/x\\x2ejson"\n'
                                     '\t_ = "../cmd/x/main.go"\n\t_ = "../vendor/example.com/m/m.go"\n\t_ = "../other"\n'
                                     '\t_ = "/etc/hosts"\n\t_ = "../../../outside.txt"\n\t_ = "page.go"\n'
                                     '\t_ = filepath.Join("..", "..", "docs", "guide.md")\n)\n\n// "../../README.md"\n'}
        with tempfile.TemporaryDirectory() as d, self.tree(d, code):
            for path, want in (("SPEC.md", {"page"}),
                               ("broker/other/testdata/x.json", {"page", "other"}),
                               ("broker/cmd/x/main.go", {"page", "cmd/x"}),
                               ("broker/page/page.go", {"page"}),               # its own code: its own lines
                               ("broker/other/other.go", {"other"}),            # a directory names no file
                               ("broker/vendor/example.com/m/m.go", set()),     # go mod vendor fixes it
                               ("docs/guide.md", set()),                        # built at run time
                               ("README.md", set()),                            # a comment names nothing
                               ("outside.txt", set())):
                for kind in ("change", "empty", "delete"):
                    with self.subTest(path=path, kind=kind):
                        added, tests = mutgate.added_lines(data_diff(path, kind))
                        own = {mutgate.package_of(path)} if mutgate.is_source(path) and kind != "change" else set()
                        self.assertEqual(mutgate.touched(added, tests), want - own)  # code claims by added lines
                        self.assertEqual(mutgate.tests_changed(tests, "page"), path != "broker/page/page.go" and "page" in want)
                        if "page" in want and path != "broker/page/page.go":
                            self.assertIsNone(mutgate.head_tests(tests, "page"))  # every test
                            self.assertEqual(mutgate.diff_targets(added, "page"), {})
                            self.assertEqual(mutgate.claimed(data_diff(path, kind), packages=["page"]), ["page"])
            self.assertEqual(mutgate.readers("broker/vendor/example.com/m/m.go"), set())
            self.assertEqual(mutgate.owners("broker/vendor/example.com/m/m.go"), set())
            self.assertTrue(mutgate.is_vendored("broker/vendor/example.com/m/m.go"))
            self.assertFalse(mutgate.is_vendored("vendor/x.go"))

    def test_a_markdown_file_another_package_names_stays_in_the_gate_trees(self):
        # #6436: hide_docs keeps a Markdown file whose edit claims a reader in another package.
        # REQ: MUT-deleted-test-own-lines-fu
        files = {"hint/hint.go": "package hint\n", "hint/ASSUMPTIONS.md": "x", "hint/NOTES.md": "x",
                 "read/read.go": 'package read\n\nconst doc = "../hint/NOTES.md"\n'}
        with tempfile.TemporaryDirectory() as d, self.tree(d, files), self.made(d):
            self.assertEqual(mutgate.hide_docs(pathlib.Path(d) / "broker"), ["broker/hint/ASSUMPTIONS.md"])
            self.assertEqual(mutgate.owners("broker/hint/NOTES.md"), {"read"})

    def test_the_gates_diff_holds_the_files_outside_broker_a_package_reads(self):
        # #6436: broker_diff adds each file outside broker/ that a package names by path, and no
        # other; a name holding pattern characters is read as a path.
        # REQ: MUT-deleted-test-own-lines-fu
        files = {"broker/page/page.go": 'package page\n\nvar _ = []string{"../../SPEC.md", "../../a[1].md"}\n',
                 "SPEC.md": "x\n", "README.md": "x\n", "a[1].md": "x\n", "a1.md": "x\n"}
        repo = self.repo(files)
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
        for name in ("SPEC.md", "README.md", "a[1].md", "a1.md"):
            (repo / name).write_text("y\n")
        subprocess.run(["git", "-c", "commit.gpgsign=false", "commit", "-qam", "head"], cwd=repo, env=env, check=True)
        with mock.patch.object(mutgate, "ROOT", repo), mock.patch.object(mutgate, "BROKER", repo / "broker"):
            diff = mutgate.broker_diff("HEAD~1", "HEAD")
            heads = sorted(line for line in diff.split("\n") if line.startswith("diff --git"))
            self.assertEqual(heads, ["diff --git a/SPEC.md b/SPEC.md", "diff --git a/a[1].md b/a[1].md"])
            self.assertEqual(mutgate.touched(*mutgate.added_lines(diff)), {"page"})

    def test_the_base_tree_keeps_a_doc_the_head_names(self):
        # #6456: the base tree hid by the base's names alone, so a doc the head newly names was read
        # at the head and gone at the base. A doc either tree names is now in the base's run; one
        # neither names is gone from it.
        # REQ: MUT-deleted-test-own-lines-fu
        seen = {}

        def cover(pkg, names, tmp, broker):
            seen["left"] = sorted(p.name for p in (broker / pkg).iterdir())
            return {}, None
        repo = self.repo({"broker/hint/hint.go": 'package hint\n\nconst a = "A.md"\n', "broker/hint/A.md": "x",
                          "broker/hint/B.md": "x", "broker/hint/C.md": "x"})
        with tempfile.TemporaryDirectory() as head, self.tree(head, {"hint/hint.go": 'package hint\n\nconst b = "B.md"\n'}), \
                tempfile.TemporaryDirectory() as tmp, mock.patch.object(mutgate, "ROOT", repo), \
                mock.patch.object(mutgate, "covered_by", side_effect=cover):
            sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()
            self.assertEqual(mutgate.base_covered("hint", sha, None, tmp, ""), ({}, None))
        self.assertEqual(seen["left"], ["A.md", "B.md", "hint.go"])

    def repo(self, files):
        d = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, d, True)
        for name, text in files.items():
            (d / name).parent.mkdir(parents=True, exist_ok=True)
            (d / name).write_text(text)
        env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
               "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}
        for c in (["init", "-q"], ["add", "-A"], ["commit", "-qm", "base"]):
            subprocess.run(["git", "-c", "commit.gpgsign=false", *c], cwd=d, env=env, check=True)
        return d

    @unittest.skipUnless(shutil.which("go"), "needs go")
    def test_a_test_reading_a_hidden_file_fails_closed(self):
        # #6373: a read the names rule cannot see (a path built from bytes) finds no file in the
        # gate's tree, so the package's tests fail there and the gate refuses, never passes quietly.
        # REQ: MUT-deleted-test-own-lines-fu
        files = {"go.mod": "module example.com/b\n\ngo 1.21\n", "hint/hint.go": "package hint\n",
                 "hint/hint_test.go": 'package hint\n\nimport (\n\t"os"\n\t"testing"\n)\n\n'
                 "func TestDoc(t *testing.T) {\n\tif _, err := os.ReadFile(string([]byte{65, 46, 109, 100})); err != nil {\n"
                 "\t\tt.Fatal(err)\n\t}\n}\n", "hint/A.md": "x"}
        with tempfile.TemporaryDirectory() as d, self.tree(d, files), self.made(d):
            broker = pathlib.Path(d) / "broker"
            run = lambda: subprocess.run(["go", "test", "-count=1", "./hint"], cwd=broker, capture_output=True,
                                         env={**os.environ, "GOFLAGS": "-mod=mod", "GOTOOLCHAIN": "local"})
            self.assertEqual(run().returncode, 0)
            self.assertEqual(mutgate.hide_docs(broker), ["broker/hint/A.md"])
            self.assertNotEqual(run().returncode, 0)

    def test_a_glob_matches_by_its_last_part_against_the_files_base_name(self):
        # Potency on #5943 (d92c2e23): the last-part clause survived `rsplit`→`split` (needs a glob
        # with two directory parts) and `parts[-1]`→`parts[0]` (needs a file below a subdirectory).
        # REQ: MUT-deleted-test-own-lines-fu
        for name, path, src in (
                ("a glob behind two directories", "broker/hint/ASSUMPTIONS.md",
                 'var _, _ = filepath.Glob(root + "/a/b/*.md")'),
                ("a Markdown file in a subdirectory", "broker/hint/sub/notes.md",
                 'var _, _ = filepath.Glob(fmt.Sprintf("%s/*.md", dir))')):
            with self.subTest(name), tempfile.TemporaryDirectory() as d, \
                    self.tree(d, {"hint/hint.go": "package hint\n", "hint/hint_test.go": f"package hint\n\n{src}\n"}):
                self.assertEqual(mutgate.touched(*mutgate.added_lines(data_diff(path))), {"hint"})


# A package that embeds one data file into a var, read by package code a test reaches (#6409's shape).
EMBED_PKG = {
    "v/pins.go": 'package v\n\nimport _ "embed"\n\n// pins names each file.\n//\n//go:embed models.pins\n'
                 'var modelPins string\n\nfunc pinFor(f string) string { return modelPins + f }\n',
    "v/other.go": "package v\n\nfunc other() int { return 1 }\n",
    "v/models.pins": "abc lib.so\n",
    "v/pins_test.go": 'package v\n\nimport "testing"\n\nfunc TestPins(t *testing.T) { _ = pinFor("x") }\n',
    "v/other_test.go": 'package v\n\nimport "testing"\n\nfunc TestOther(t *testing.T) { _ = other() }\n',
}


class EmbedReach(unittest.TestCase):
    """MUT-embed-reach (#6458): a changed data file whose only namer is a //go:embed var changes the
    tests that reach that var, through package code too; any other namer, or a reach every test may
    run, is every test."""

    def reach(self, files, path="broker/v/models.pins", kind="change", env=None):
        with tempfile.TemporaryDirectory() as d, DataFiles.tree(None, d, files), \
                mock.patch.dict(os.environ, env or {"GOFLAGS": ""}):
            added, tests = mutgate.added_lines(data_diff(path, kind))
            self.assertEqual(mutgate.touched(added, tests), {"v"})
            return mutgate.head_tests(tests, "v")

    def test_an_embedded_file_reaches_its_vars_tests(self):
        # REQ: MUT-embed-reach
        for kind in ("change", "empty", "delete"):  # a moved or comment-only line is a change too
            self.assertEqual(self.reach(EMBED_PKG, kind=kind), ["TestPins"], kind)
        quoted = EMBED_PKG["v/pins.go"].replace("embed models.pins", 'embed "all:models.pins"')
        self.assertEqual(self.reach({**EMBED_PKG, "v/pins.go": quoted}), ["TestPins"])
        # A test that names the var directly, or reaches it through a type's method, counts.
        held = {**EMBED_PKG, "v/held_test.go": 'package v\n\nimport "testing"\n\nfunc TestHeld(t *testing.T) { _ = modelPins }\n',
                "v/kind.go": "package v\n\ntype K struct{}\n\nfunc (K) Pin() string { return pinFor(\"y\") }\n",
                "v/kind_test.go": 'package v\n\nimport "testing"\n\nfunc TestKind(t *testing.T) { _ = K{} }\n'}
        self.assertEqual(self.reach(held), ["TestHeld", "TestKind", "TestPins"])
        # A Test-named function of package code is no test.
        self.assertEqual(self.reach({**EMBED_PKG, "v/other.go": "package v\n\nfunc TestLike() string { return modelPins }\n"
                                     "\nfunc other() int { return 1 }\n"}), ["TestPins"])
        # A testdata file embedded by its path.
        td = {**EMBED_PKG, "v/testdata/m.pins": "x\n",
              "v/pins.go": EMBED_PKG["v/pins.go"].replace("embed models.pins", "embed testdata/m.pins")}
        self.assertEqual(self.reach(td, "broker/v/testdata/m.pins"), ["TestPins"])
        # With a test file also changed, both reaches join.
        with tempfile.TemporaryDirectory() as d, DataFiles.tree(None, d, EMBED_PKG):
            tests = {"broker/v/models.pins": None, "broker/v/other_test.go": {5}}
            self.assertEqual(mutgate.head_tests(tests, "v"), ["TestOther", "TestPins"])

    def test_any_other_namer_is_every_test(self):
        # REQ: MUT-embed-reach
        pins = EMBED_PKG["v/pins.go"]
        for name, files in (
                ("a test literal", {"v/read_test.go": 'package v\n\nvar _ = "models.pins"\n'}),
                ("a package literal", {"v/other.go": 'package v\n\nfunc other() int { return len("models.pins") }\n'}),
                ("a glob literal", {"v/read_test.go": 'package v\n\nvar _ = "*.pins"\n'}),
                ("an embed.FS glob", {"v/pins.go": pins.replace("embed models.pins\nvar modelPins string",
                                                                 "embed *.pins\nvar modelPins embed.FS")}),
                ("a directive listing more", {"v/pins.go": pins.replace("embed models.pins", "embed models.pins other.pins")}),
                ("a second var on another shape", {"v/two.go": 'package v\n\nvar (\n\t//go:embed models.pins\n\ttwo string\n)\n'}),
                ("an indented directive", {"v/pins.go": pins.replace("//go:embed", " //go:embed")}),
                ("a directive in a raw string", {"v/gen_test.go": 'package v\n\nvar src = `\n//go:embed models.pins\nvar x string\n`\n'}),
                ("a directory embed", {"v/pins.go": pins.replace("embed models.pins", "embed sub"), "v/sub/models.pins": ""}),
                ("an init reading the var", {"v/init.go": "package v\n\nfunc init() { _ = pinFor(\"z\") }\n"}),
                ("an initializer reading it", {"v/init.go": "package v\n\nvar h = len(modelPins)\n"}),
                ("TestMain reaching it", {"v/main_test.go": 'package v\n\nimport "testing"\n\nfunc TestMain(m *testing.M) { _ = pinFor("") }\n'}),
                ("a toolchain-tagged init", {"v/init.go": "//go:build linux && amd64.v2\n\npackage v\n\nfunc init() { _ = modelPins }\n"}),
                ("a linked file", {}),
                ("a directive in a block comment", {"v/x.go": "package v\n\nvar x string\n\n/*\n//go:embed models.pins\nvar x string\n*/\n"}),
                ("an exported var", {"v/pins.go": pins.replace("modelPins", "ModelPins")}),
                ("no inotify to watch the run", {}),
                ("nothing embeds it", {"v/pins.go": "package v\n\nvar modelPins string\n\nfunc pinFor(f string) string { return modelPins + f }\n"})):
            with self.subTest(name):
                files = {**EMBED_PKG, **files}
                if name == "no inotify to watch the run":
                    with mock.patch.object(mutgate, "_inotify", lambda: None):
                        self.assertIsNone(self.reach(files))
                    continue
                if name == "a linked file":
                    with tempfile.TemporaryDirectory() as d, DataFiles.tree(None, d, files):
                        (pathlib.Path(d) / "broker/v/link.go").symlink_to(pathlib.Path(d) / "broker/v/other.go")
                        self.assertIsNone(mutgate.head_tests({"broker/v/models.pins": None}, "v"))
                        self.assertIsNone(mutgate.embedded_by("v", "models.pins"))
                    continue
                self.assertIsNone(self.reach(files))
        # A file named like a glob: its pattern may match more files.
        glob = {**EMBED_PKG, "v/m*.pins": "", "v/pins.go": EMBED_PKG["v/pins.go"].replace("embed models.pins", "embed m*.pins")}
        self.assertIsNone(self.reach(glob, "broker/v/m*.pins"))
        # Another package naming the file by its path reaches every test of its own (readers).
        other = {**EMBED_PKG, "w/w.go": "package w\n", "w/w_test.go": 'package w\n\nvar _ = "../v/models.pins"\n'}
        with tempfile.TemporaryDirectory() as d, DataFiles.tree(None, d, other), mock.patch.dict(os.environ, {"GOFLAGS": ""}):
            mutgate.read_index.cache_clear()
            added, tests = mutgate.added_lines(data_diff("broker/v/models.pins"))
            self.assertEqual(mutgate.touched(added, tests), {"v", "w"})
            self.assertEqual(mutgate.head_tests(tests, "v"), ["TestPins"])
            self.assertIsNone(mutgate.head_tests(tests, "w"))
            mutgate.read_index.cache_clear()
        # A file no `go test` here builds (a custom tag, a name go ignores) is not read for reach; a
        # GOFLAGS naming tags reads it.
        tagged = {**EMBED_PKG, "v/onnx.go": "//go:build vision_onnx\n\npackage v\n\nvar h = len(modelPins)\n",
                  "v/_x.go": "package v\n\nfunc init() { _ = modelPins }\n"}
        self.assertEqual(self.reach(tagged), ["TestPins"])
        self.assertIsNone(self.reach(tagged, env={"GOFLAGS": "-tags=vision_onnx"}))
        # A test file under a custom tag still counts: more tests, never fewer.
        self.assertEqual(self.reach({**EMBED_PKG, "v/onnx_test.go": '//go:build vision_onnx\n\npackage v\n\nimport "testing"\n\n'
                                     'func TestOnnx(t *testing.T) { _ = modelPins }\n'}), ["TestOnnx", "TestPins"])

    def test_the_whole_suite_watches_the_embedded_file(self):
        # The narrowing's other half (#6458; Security on #6518): the whole-suite run builds the
        # package from a copy of the file and watches the file itself, so a test reading it at run
        # time by a path no literal holds fails the gate's run, even one that passes with it absent.
        # REQ: MUT-embed-reach
        def lister(cond, read):
            return ('package v\n\nimport (\n\t"os"\n\t"os/exec"\n\t"strings"\n\t"testing"\n)\n\n'
                    'var _ = exec.Command\n\nfunc TestList(t *testing.T) {\n\tes, _ := os.ReadDir(".")\n'
                    '\tfor _, e := range es {\n\t\tif ' + cond + ' {\n\t\t\tb, err := ' + read + '\n'
                    '\t\t\tif err != nil {\n\t\t\t\treturn\n\t\t\t}\n'
                    '\t\t\tif !strings.HasPrefix(string(b), "abc") {\n\t\t\t\tt.Fatal("weak pin")\n\t\t\t}\n\t\t}\n\t}\n}\n')
        tolerant = lister('strings.HasSuffix(e.Name(), ".pins")', "os.ReadFile(e.Name())")
        child = lister('strings.HasSuffix(e.Name(), ".pins")', 'exec.Command("cat", e.Name()).Output()')
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"GOFLAGS": "", "GOWORK": "off"}):
            d = pathlib.Path(d).resolve()
            tree, tmp = d / "tree", d / "tmp"
            tmp.mkdir()
            with DataFiles.tree(None, tree, {**EMBED_PKG, "go.mod": GO_MOD}):
                pins, watched = tree / "broker/v/models.pins", ["broker/v/models.pins"]
                got, _, problem = mutgate.timed_cover("v", None, tmp, watched=watched)
                self.assertIsNone(problem)  # the build reads the copy: no event
                self.assertIn("broker/v/pins.go", got)
                self.assertEqual(pins.read_text(), "abc lib.so\n")  # untouched
                # A reader that passes with the file absent, a child process reading it: seen.
                pins.write_text("zzz lib.so\n")
                for name, src in (("tolerant", tolerant), ("child", child)):
                    with self.subTest(name):
                        (tree / "broker/v/list_test.go").write_text(src)
                        problem = mutgate.timed_cover("v", None, tmp, watched=watched)[2]
                        self.assertIn("a test read broker/v/models.pins at run time", problem)
                # Emptied, read by a reader that checks each line (so passes on no lines): a read of 0
                # bytes raises no IN_ACCESS, only the open is seen (L3 on #6518).
                pins.write_text("")
                (tree / "broker/v/list_test.go").write_text(
                    'package v\n\nimport (\n\t"os"\n\t"strings"\n\t"testing"\n)\n\nfunc TestLines(t *testing.T) {\n'
                    '\tes, _ := os.ReadDir(".")\n\tfor _, e := range es {\n\t\tif strings.HasSuffix(e.Name(), ".pins") {\n'
                    '\t\t\tb, _ := os.ReadFile(e.Name())\n\t\t\tfor _, l := range strings.Split(string(b), "\\n") {\n'
                    '\t\t\t\tif l != "" && !strings.HasPrefix(l, "abc") {\n\t\t\t\t\tt.Fatal("weak pin")\n\t\t\t\t}\n'
                    '\t\t\t}\n\t\t}\n\t}\n}\n')
                self.assertIsNone(mutgate.timed_cover("v", None, tmp)[2])  # unwatched, it passes
                problem = mutgate.timed_cover("v", None, tmp, watched=watched)[2]
                self.assertIn("a test read broker/v/models.pins at run time", problem)
                pins.write_text("abc lib.so\n")
                # A reader through mmap: its reads raise no IN_ACCESS either (Security on #6518).
                (tree / "broker/v/list_test.go").write_text(
                    'package v\n\nimport (\n\t"os"\n\t"strings"\n\t"syscall"\n\t"testing"\n)\n\n'
                    'func TestMapped(t *testing.T) {\n\tes, _ := os.ReadDir(".")\n\tfor _, e := range es {\n'
                    '\t\tif strings.HasSuffix(e.Name(), ".pins") {\n\t\t\tf, err := os.Open(e.Name())\n'
                    '\t\t\tif err != nil {\n\t\t\t\treturn\n\t\t\t}\n\t\t\tdefer f.Close()\n'
                    '\t\t\tb, err := syscall.Mmap(int(f.Fd()), 0, 3, syscall.PROT_READ, syscall.MAP_SHARED)\n'
                    '\t\t\tif err != nil {\n\t\t\t\tt.Fatal(err)\n\t\t\t}\n\t\t\tdefer syscall.Munmap(b)\n'
                    '\t\t\tif string(b) != "abc" {\n\t\t\t\tt.Fatal("weak pin")\n\t\t\t}\n\t\t}\n\t}\n}\n')
                self.assertIsNone(mutgate.timed_cover("v", None, tmp)[2])  # unwatched, it passes
                problem = mutgate.timed_cover("v", None, tmp, watched=watched)[2]
                self.assertIn("a test read broker/v/models.pins at run time", problem)
                # The same for a testdata file embedded by its path.
                (tree / "broker/v/testdata").mkdir()
                (tree / "broker/v/testdata/m.pins").write_text("abc\n")
                (tree / "broker/v/pins.go").write_text(EMBED_PKG["v/pins.go"].replace("embed models.pins", "embed testdata/m.pins"))
                (tree / "broker/v/list_test.go").write_text(
                    tolerant.replace('os.ReadDir(".")', 'os.ReadDir("testdata")').replace(
                        "os.ReadFile(e.Name())", 'os.ReadFile("testdata/" + e.Name())'))
                problem = mutgate.timed_cover("v", None, tmp, watched=["broker/v/testdata/m.pins"])[2]
                self.assertIn("a test read broker/v/testdata/m.pins at run time", problem)
                self.assertIsNone(mutgate.timed_cover("v", None, tmp, watched=watched)[2])  # unread: fine
                # Not a regular file, or no inotify: no run, a problem; and no narrowing without it.
                self.assertIn("not a regular file", mutgate.timed_cover("v", None, tmp, watched=["broker/v/gone.pins"])[2])
                with mock.patch.object(mutgate, "_inotify", lambda: None):
                    self.assertIn("cannot watch", mutgate.timed_cover("v", None, tmp, watched=watched)[2])
                # record_for watches the narrowed package's embedded data files in its whole-suite run only.
                runs = []

                def cover(pkg, names, tmp, code=None, watched=()):
                    runs.append((names, list(watched)))
                    return {}, 1.0, None
                with mock.patch.object(mutgate, "timed_cover", cover), \
                        mock.patch.object(mutgate, "merge_base", lambda b, h: "b" * 40), \
                        mock.patch.object(mutgate, "base_covered", lambda *a: ({}, None)):
                    (tree / "broker/v/pins.go").write_text(EMBED_PKG["v/pins.go"])
                    (tree / "broker/v/list_test.go").unlink()
                    tests = {"broker/v/models.pins": None, "broker/v/other_test.go": {5}}
                    self.assertIsNone(mutgate.record_for("v", tests, {"v": []}, "", "HEAD~1", tmp)[2])
                    self.assertEqual(runs, [(["TestOther", "TestPins"], []), (None, watched)])
                    runs.clear()
                    self.assertIsNone(mutgate.record_for("v", {"broker/v/other_test.go": {5}}, {"v": []}, "", "HEAD~1", tmp)[2])
                    self.assertEqual(runs, [(["TestOther"], []), (None, [])])

    def test_unbuilt_reads_the_toolchain_tags(self):
        # REQ: MUT-embed-reach
        with mock.patch.dict(os.environ, {"GOFLAGS": ""}):
            for line, out in (("", False), ("//go:build vision_onnx\n", True), ("//go:build !vision_onnx\n", False),
                              ("//go:build linux\n", False), ("//go:build windows\n", False), ("//go:build cgo && x\n", True),
                              ("//go:build go1.21 || x\n", False), ("//go:build goexperiment.foo\n", False),
                              ("//go:build amd64.v3\n", False), ("//go:build race\n", False), ("//go:build ignore\n", True),
                              ("//go:build (\n", False)):
                self.assertEqual(mutgate.unbuilt("a.go", line + "\npackage v\n"), out, line)
            self.assertTrue(mutgate.unbuilt("_a.go", "package v\n"))
            self.assertFalse(mutgate.unbuilt("a_linux.go", "package v\n"))

    def test_vision_pins_reach_only_their_var(self):
        # #6409's case on the real tree: models.pins reaches modelPins' tests, not the package.
        # REQ: MUT-embed-reach
        with mock.patch.dict(os.environ, {"GOFLAGS": ""}):
            got = mutgate.head_tests({"broker/cmd/agentos-vision/models.pins": None}, "cmd/agentos-vision")
        self.assertIn("TestPinsCheckEveryFile", got)
        self.assertNotIn("TestHeatBlobBoxAndConfidence", got or ["x"])
        self.assertLess(len(got), 20)


class Plan(unittest.TestCase):
    def test_a_plan_past_the_matrix_limit_names_a_remedy(self):
        # #4983: a refused plan says what to do next. Each claimed package plans 100 shards here.
        from unittest import mock
        import contextlib, io, types
        for pkgs, fix in (([f"p{i}" for i in range(13)], "1300 shards do not fit 256 jobs (GitHub's matrix limit) of at "
                           "most 5 shards of one package each (its 360-minute job limit): split the PR so each part "
                           "changes fewer tier-A or tier-B packages"),
                          ([], "0 shards: no claimed package was planned; rerun the mutgate workflow")):
            with self.subTest(pkgs), contextlib.ExitStack() as st:
                for name, value in (("broker_diff", lambda *a: ""), ("changes", lambda *a: ({}, {})),
                                    ("build_lister", lambda tmp: "lister"), ("claimed", lambda d, **_: pkgs),
                                    ("diff_targets", lambda added, pkg: {f"broker/{pkg}/x.go": {1}}),
                                    ("deletion_sites", lambda *a: ([], None)), ("lint_budget", lambda pkg, sites: (0.0, [0.0] * len(sites))), ("suite_seconds", lambda *a: (1.0, None)),
                                    ("shard_count", lambda *a: 100)):
                    st.enter_context(mock.patch.object(mutgate, name, value))
                err = st.enter_context(contextlib.redirect_stderr(io.StringIO()))
                st.enter_context(contextlib.redirect_stdout(io.StringIO()))
                self.assertEqual(mutgate.cmd_plan(types.SimpleNamespace(git="HEAD~1")), 1)
                self.assertIn(f"mutgate: {fix}\n", err.getvalue())

    def plan(self, pkg_targets, suite, costs=(None, 0.0)):
        """cmd_plan's (code, matrix, stderr) with each package's ({path: lines}, sites) given and
        suite_seconds stubbed to suite ((seconds, problem)), site_costs to costs."""
        from unittest import mock
        import contextlib, io, types
        with contextlib.ExitStack() as st:
            for name, value in (("broker_diff", lambda *a: ""), ("changes", lambda *a: ({}, {})),
                                ("build_lister", lambda tmp: "lister"), ("claimed", lambda d, **_: sorted(pkg_targets)),
                                ("diff_targets", lambda added, pkg: pkg_targets[pkg][0]),
                                ("deletion_sites", lambda pkg, t, lister: (pkg_targets[pkg][1], None)), ("lint_budget", lambda pkg, sites: (0.0, [0.0] * len(sites))),
                                ("suite_seconds", lambda pkg, tmp: suite), ("site_costs", lambda *a: costs)):
                st.enter_context(mock.patch.object(mutgate, name, value))
            err = st.enter_context(contextlib.redirect_stderr(io.StringIO()))
            out = st.enter_context(contextlib.redirect_stdout(io.StringIO()))
            code = mutgate.cmd_plan(types.SimpleNamespace(git="HEAD~1", targets_out=None))
        return code, out.getvalue(), err.getvalue()

    def test_a_plan_past_the_matrix_runs_every_shard_once_in_at_most_256_jobs(self):
        # MUT-plan-overflow (#6170): #6144's plan (run 44309775605) asked for 320 shards, enforcer/nft's
        # 296 among them, past GitHub's 256-job matrix. Each job then runs shards of one package in turn,
        # each stopped at its own 60 minutes, the job at 60 a shard plus 15 for setup, never past a hosted
        # job's 360; at or under 256 it is one shard a job.
        six = [("clerk/enflist", 1), ("cmd/agentos-enforcer", 7), ("enforcer/dns", 6), ("enforcer/nft", 296),
               ("enforcer/page", 3), ("enforcer/policy", 5), ("enforcer/traffic", 2)]
        for counts, jobs, most in ((six, 162, 2), ([("p", 256)], 256, 1), ([("p", 20), ("q", 1)], 21, 1),
                                   ([("p", 1280)], 256, 5), ([("p", 1000), ("q", 280)], 256, 5)):
            with self.subTest(counts=counts):
                got = mutgate.pack(counts)
                self.assertEqual(len(got), jobs)
                ran = collections.Counter()
                for e in got:
                    self.assertEqual(set(e), {"pkg", "shards", "of", "minutes"})
                    mine = [int(i) for i in e["shards"].split(", ")]
                    self.assertEqual(e["minutes"], 60 * len(mine) + 15)
                    self.assertLessEqual(len(mine), most)
                    self.assertEqual(e["of"], dict(counts)[e["pkg"]])
                    ran.update((e["pkg"], i) for i in mine)
                # Every shard of every package exactly once.
                self.assertEqual(ran, collections.Counter((pkg, i) for pkg, of in counts for i in range(of)))
                self.assertLessEqual(max(e["minutes"] for e in got), 360)
        self.assertIsNone(mutgate.pack([("p", 1281)]))
        # Each package fills its own jobs, so two that each leave one part-filled fit fewer shards in all.
        self.assertIsNone(mutgate.pack([("p", 1001), ("q", 279)]))
        self.assertEqual(mutgate.SHARDS_MAX, 1280)
        # The bounds verify reads a result's shard by (L3 4 on #6171): K up to SHARDS_MAX, never past it.
        self.assertEqual(mutgate.shard_of({"shard": {"index": 1279, "of": 1280}}), (1279, 1280))
        self.assertIsNone(mutgate.shard_of({"shard": {"index": 0, "of": 1281}}))

    def test_run_takes_every_shard_a_plan_can_pack(self):
        # MUT-plan-overflow-fu: `run` refused K past MATRIX_MAX after #6170 packed plans up to
        # SHARDS_MAX, so all 294 of #6144's enforcer/nft shards exited 2 (run 44488046218). The K
        # bound `run` takes is the largest one pack fits, whatever the constants become.
        top = max(k for k in range(1, mutgate.SHARDS_MAX + 2) if mutgate.pack([("p", k)]))
        with mock.patch.object(mutgate, "cmd_run", return_value=0) as ran, \
                mock.patch.object(mutgate, "scratch", contextlib.nullcontext):
            for i in (0, top - 1):
                self.assertEqual(mutgate.main(["run", "p", "--git", "HEAD~1", "--shard", str(i), "--of", str(top)]), 0)
            self.assertEqual(ran.call_count, 2)
            with self.assertRaises(SystemExit) as e, contextlib.redirect_stderr(io.StringIO()):
                mutgate.main(["run", "p", "--git", "HEAD~1", "--shard", "0", "--of", str(top + 1)])
            self.assertEqual(e.exception.code, 2)
            self.assertEqual(ran.call_count, 2)

    def test_a_plan_past_the_matrix_names_its_packing(self):
        code, out, err = self.plan({"enforcer/nft": ({"broker/enforcer/nft/a.go": set(range(1, 1767))}, [{}] * 1019)},
                                   (364.0, None))
        self.assertEqual(code, 0, err)
        self.assertIn("enforcer/nft: 1766 target lines, 1019 deletion sites, a 364 s suite, 296 shard(s)", err)
        self.assertIn("296 shards past 256 jobs: up to 2 shards a job, one after another", err)
        got = json.loads(out)
        self.assertEqual(len(got), 148)
        self.assertEqual(got[0], {"pkg": "enforcer/nft", "shards": "0, 148", "of": 296, "minutes": 135})

    def test_a_plan_sizes_each_site_by_the_tests_that_cover_it(self):
        # MUT-delete-covering (#6172): #6144's enforcer/nft (1766 target lines, 1019 sites, a 364 s
        # suite) planned 296 shards with a whole suite a site. With each site costing its own tests'
        # runs (here 20 s: its set's run and at most one unmutated run of the set) and each shard first
        # spending its per-test pass (one suite's time), it plans fewer.
        # REQ: MUT-delete-covering
        nft = {"enforcer/nft": ({"broker/enforcer/nft/a.go": set(range(1, 1767))}, [{}] * 1019)}
        code, out, err = self.plan(nft, (364.0, None), ([20.0] * 1019, 364.0))
        self.assertEqual(code, 0, err)
        self.assertIn("enforcer/nft: 1766 target lines, 1019 deletion sites, a 364 s suite, 127 shard(s)", err)
        self.assertEqual(len(json.loads(out)), 127)
        # No per-test result (a test list or build failure): sized as before, a whole suite a site.
        self.assertIn("296 shard(s)", self.plan(nft, (364.0, None))[2])
        lines = {"broker/p/a.go": {1}}
        self.assertEqual(mutgate.shard_count(lines, [0] * 10, 100.0), 1)
        self.assertEqual(mutgate.shard_count(lines, [0] * 10, 100.0, [1000.0] * 10, 0.0), 6)
        # A per-test pass past half the budget leaves each shard half the budget, not less.
        self.assertEqual(mutgate.shard_count(lines, [0] * 10, 100.0, [1000.0] * 10, 1500.0), 12)

    def test_a_slow_suite_gets_more_shards(self):
        # MUT-kernel-sim-budget (#5069): on #5006 kernel/sim (823 target lines, 534 deletion sites, a
        # 48 s suite) planned 6 shards from its counts alone and 5 of them passed the 60-minute limit.
        lines = lambda n: {"broker/p/a.go": set(range(1, n + 1))}
        self.assertEqual(mutgate.shard_count(lines(823), [0] * 534), 6)
        k = mutgate.shard_count(lines(823), [0] * 534, 48.0)
        self.assertEqual(k, 20)
        # Each shard's suite runs fit the budget, which is half the job's 60 minutes.
        self.assertLessEqual(48.0 * (mutgate.LINE_RUNS * 823 / k + mutgate.SITE_RUNS * 534 / k), mutgate.SHARD_SECONDS)
        self.assertLessEqual(2 * mutgate.SHARD_SECONDS, 60 * 60)
        self.assertIn("    timeout-minutes: ${{ matrix.minutes }}\n", job(WORKFLOW.read_text(), "mutants"))
        self.assertEqual(mutgate.pack([("p", 1)])[0]["minutes"], 75)
        # browser's 7 s suite on #5006 (9 shards in 6 to 14 minutes) and a package with no tests keep
        # the count budgets: the time term only ever adds shards.
        self.assertEqual(mutgate.shard_count(lines(1364), [0] * 825, 7.0), 9)
        self.assertEqual(mutgate.shard_count(lines(1048), [0] * 367, 0.0), 5)
        self.assertEqual(mutgate.shard_count({}, [], 1000.0), 1)
        # #6217 (L3 on #6213): a shard's budget is what its per-test pass leaves of SHARD_SECONDS, but
        # never under half: a pass past 15 minutes plans shards past the 30-minute target.
        self.assertEqual(mutgate.shard_count({}, [0], costs=[1300.0], overhead=600.0), 2)
        self.assertEqual(mutgate.shard_count({}, [0], costs=[1800.0], overhead=1700.0), 2)

    def test_a_package_with_no_target_line_plans_one_shard_and_no_suite_run(self):
        # MUT-waiver-store-claim (#5786): a record-only claim runs one cheap shard, never its suite.
        code, out, err = self.plan({"netguard": ({}, [])}, (None, "the suite must not run"))
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out), [{"pkg": "netguard", "shards": "0", "of": 1, "minutes": 75}])

    def test_plan_sizes_each_package_by_its_suite(self):
        sim = ({"broker/kernel/sim/a.go": set(range(1, 824))}, [{}] * 534)
        code, out, err = self.plan({"kernel/sim": sim}, (48.0, None))
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out), [{"pkg": "kernel/sim", "shards": str(i), "of": 20, "minutes": 75} for i in range(20)])
        self.assertIn("kernel/sim: 823 target lines, 534 deletion sites, a 48 s suite, 20 shard(s)", err)
        # A suite that does not build or pass cannot be timed: the plan fails and says why.
        code, out, err = self.plan({"kernel/sim": sim}, (None, "broker/kernel/sim/'s tests fail"))
        self.assertEqual((code, out), (1, ""))
        self.assertIn("mutgate: broker/kernel/sim/'s tests fail", err)


    def test_a_test_changing_package_is_sized_by_its_record_run_with_no_other_suite_run(self):
        # MUT-plan-budget (#6155): on #6144 enforcer/nft's 374 s suite ran four times in the plan and
        # passed its time limit; the record's whole-suite run sizes the shards, and suite_seconds
        # runs only for a package whose tests the diff leaves alone.
        from unittest import mock
        import contextlib, io, types
        sim = {"broker/kernel/sim/a.go": set(range(1, 824))}
        timed = []
        with contextlib.ExitStack() as st:
            for name, value in (("broker_diff", lambda *a: ""), ("changes", lambda *a: ({}, {})),
                                ("build_lister", lambda tmp: "lister"), ("claimed", lambda d, **_: ["kernel/sim", "other"]),
                                ("bases_for", lambda *a: {}), ("diff_targets", lambda added, pkg: sim),
                                ("tests_changed", lambda tests, pkg: pkg == "kernel/sim"),
                                ("record_for", lambda *a: ({"rec": 1}, 48.0, None)),
                                ("targets_for", lambda pkg, added, tests, data, bases: (sim, None)),
                                ("deletion_sites", lambda pkg, t, lister: ([{}] * 534, None)), ("lint_budget", lambda pkg, sites: (0.0, [0.0] * len(sites))),
                                ("suite_seconds", lambda pkg, tmp: timed.append(pkg) or (1.0, None)),
                                ("site_costs", lambda *a: (None, 0.0))):
                st.enter_context(mock.patch.object(mutgate, name, value))
            err = st.enter_context(contextlib.redirect_stderr(io.StringIO()))
            out = st.enter_context(contextlib.redirect_stdout(io.StringIO()))
            code = mutgate.cmd_plan(types.SimpleNamespace(git="HEAD~1", targets_out=None))
        self.assertEqual(code, 0, err.getvalue())
        self.assertEqual(timed, ["other"])
        self.assertIn("kernel/sim: 823 target lines, 534 deletion sites, a 48 s suite, 20 shard(s)", err.getvalue())
        self.assertEqual(len(json.loads(out.getvalue())), 20 + mutgate.shard_count(sim, [{}] * 534, 1.0))

    def test_record_for_times_the_whole_suite_not_the_changed_tests(self):
        # MUT-plan-budget (#6155), Potency on #6156: a PR that changes only some of a package's tests
        # sizes its shards from the head's whole-suite run, not from the changed tests' shorter run;
        # when the changed tests are every test, their one run is the whole suite's.
        from unittest import mock
        runs = []

        def timed_cover(pkg, names, tmp, code=None, watched=()):
            runs.append(names)
            return {"broker/p/a.go": {1}}, (2.0 if names is not None else 40.0), None
        for names, want, ran in ((["TestFast"], 40.0, [["TestFast"], None]), (None, 40.0, [None])):
            runs.clear()
            with self.subTest(names), contextlib.ExitStack() as st:
                for name, value in (("changed_tests", lambda tests, pkg, bases: names),
                                    ("timed_cover", timed_cover), ("merge_base", lambda base, head: "b" * 40),
                                    ("base_covered", lambda *a: ({}, None))):
                    st.enter_context(mock.patch.object(mutgate, name, value))
                record, secs, problem = mutgate.record_for("p", {}, {"p": names}, "", "HEAD~1", "tmp")
            self.assertIsNone(problem)
            self.assertEqual((secs, runs), (want, ran))
            self.assertEqual(record["tests"], names)

    def test_the_plan_job_fits_three_runs_of_the_slowest_suite(self):
        # #6155: enforcer/nft's coverage run took 374 s on #6144 (run 44265885820). A test-only change
        # to it runs the suite three times in the plan: the head's changed tests, the base's, the
        # head's whole suite. The plan job's limit holds that with half again as headroom.
        plan = job(WORKFLOW.read_text(), "plan")
        limit = int(re.search(r"(?m)^    timeout-minutes: (\d+)$", plan).group(1))
        self.assertGreaterEqual(limit * 60, 1.5 * 3 * 374)
        self.assertIn(f"the plan job timed out at its {limit}-minute limit", job(WORKFLOW.read_text(), "mutgate"))


class Summary(unittest.TestCase):
    """Potency on #4922: every verdict the step-summary table prints, and its one-row-per-mutant guard."""

    def test_summary_rows_are_target_mutants_with_their_verdicts(self):
        muts = [
            {"type": "A", "status": "LIVED", "line": 9, "column": 1},          # not a target line: left out
            {"type": "B", "status": "LIVED", "line": 2, "column": 1},
            {"type": mutgate.DELETION, "status": "KILLED", "line": 3, "column": 2, "killed_by": "TestX"},
            {"type": mutgate.DELETION, "status": "KILLED", "line": 3, "column": 4, "killed_by": "Test X|y"},
            {"type": "C", "status": "KILLED", "line": 3, "column": 5},
            {"type": "D", "status": "NOT COVERED", "line": 4, "column": 1},
            {"type": "E", "status": "TIMED OUT", "line": 4, "column": 2},
            {"type": "F", "status": "NOT VIABLE", "line": 4, "column": 3},
            {"type": "G\n| broker/forged.go:1 | X | killed |", "status": "WEIRD\nSTATUS", "line": 5, "column": 1},
        ]
        data = {"files": [{"file_name": "a.go", "mutations": muts}]}
        targets = {"broker/p/a.go": {2, 3, 4, 5}}
        waived = {("broker/p/a.go", 7, None, None): "names no survivor"}
        text = mutgate.summary({"p": (data, targets)}, {"p": None}, waived)
        rows = [l for l in text.split("\n") if l.startswith("| broker/") or l.startswith("| ")]
        body = [l for l in text.split("\n") if l.startswith("| broker/")]
        self.assertEqual(body, [
            "| broker/p/a.go:2:1 | B | **LIVED**: no test fails |",
            # A target line no test runs fails (#5762; in every package since #5779).
            "| broker/p/a.go:4:1 | D | **NOT COVERED**: no test of the package runs it |",
            "| broker/p/a.go:3:2 | STATEMENT\\_DELETION | killed by TestX |",
            "| broker/p/a.go:3:4 | STATEMENT\\_DELETION | killed |",
            "| broker/p/a.go:3:5 | C | killed (gremlins names no test) |",
            "| broker/p/a.go:4:2 | E | killed (timed out) |",
            "| broker/p/a.go:4:3 | F | not viable (does not build) |",
            "| broker/p/a.go:5:1 | G \\| broker/forged.go:1 \\| X \\| killed \\| | WEIRD STATUS |",
        ])
        self.assertNotIn("forged.go:1 | X", text)  # a newline in a result field makes no row of its own
        self.assertNotIn("a.go:9", text)
        self.assertIn("- p: 4 target lines, the lines every test covers (a change every test may run)", text)
        self.assertNotIn("a.go:7", text)  # a waiver naming no mutant is not listed: records are read on their own
        self.assertTrue(rows)
        for tested, caption in (({"p": ["TestA", "TestB"]}, "the lines TestA, TestB cover"), ({}, "the lines the diff changes")):
            self.assertIn(caption, mutgate.summary({"p": (data, targets)}, tested, {}))

    def test_summary_caps_its_rows(self):
        muts = [{"type": "T", "status": "KILLED", "line": n, "column": 1} for n in range(1, mutgate.ROWS + 6)]
        text = mutgate.summary({"p": ({"files": [{"file_name": "a.go", "mutations": muts}]},
                                      {"broker/p/a.go": set(range(1, mutgate.ROWS + 6))})}, {}, {})
        self.assertEqual(sum(l.startswith("| broker/") for l in text.split("\n")), mutgate.ROWS)
        self.assertIn("| 5 more rows | | not shown |", text)


class UntrustedPaths(unittest.TestCase):
    """Potency on #4922: the trusted job reads changed test files and the record's names as data only."""

    def test_a_symlinked_changed_test_runs_every_test_unread(self):
        with tempfile.TemporaryDirectory() as d:
            pkg = pathlib.Path(d) / "broker" / "p"
            pkg.mkdir(parents=True)
            outside = pathlib.Path(d) / "outside_test.go"
            outside.write_text("package p\n\nfunc TestA(t *testing.T) {\n}\n")
            (pkg / "a_test.go").symlink_to(outside)
            (pkg / "b_test.go").write_text(outside.read_text())
            broker, mutgate.BROKER = mutgate.BROKER, pathlib.Path(d) / "broker"
            try:
                # The linked file is not read, so its tests may reach b_test.go's change too (D-319).
                self.assertIsNone(mutgate.changed_tests({"broker/p/b_test.go": {4}}, "p", {}))
                self.assertIsNone(mutgate.changed_tests({"broker/p/a_test.go": {4}}, "p", {}))
                (pkg / "a_test.go").unlink()
                self.assertEqual(mutgate.changed_tests({"broker/p/b_test.go": {4}}, "p", {}), ["TestA"])
            finally:
                mutgate.BROKER = broker

    def test_a_record_naming_a_file_outside_the_package_dir_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            pkg = pathlib.Path(d) / "broker" / "p"
            (pkg / "sub").mkdir(parents=True)
            (pkg / "x.go").write_text("package p\n")
            (pkg / "sub" / "x.go").write_text("package sub\n")
            (pkg / "y.go").symlink_to(pkg / "x.go")
            broker, mutgate.BROKER = mutgate.BROKER, pathlib.Path(d) / "broker"
            try:
                base = {"tests": None, "lines": {}}
                ok = {"targets": {"tests": None, "lines": {"x.go": [1]}, "base": base}}
                self.assertEqual(mutgate.targets_for("p", {}, {"broker/p/x_test.go": None}, ok, {"p": None}),
                                 ({"broker/p/x.go": {1}}, None))
                for name in ("sub/x.go", "sub\\x.go", "y.go", "x_test.go", "gone.go"):
                    for rec in ({"tests": None, "lines": {name: [1]}, "base": base},
                                {"tests": None, "lines": {}, "base": {"tests": None, "lines": {name: [1]}}}):
                        with self.subTest(name=name, rec=rec):
                            got, problem = mutgate.targets_for(
                                "p", {}, {"broker/p/x_test.go": None}, {"targets": rec}, {"p": None})
                            self.assertIsNone(got)
                            self.assertIn("records covered lines", problem)
            finally:
                mutgate.BROKER = broker


class Equivalent(unittest.TestCase):
    """REV-PROOF-mut (#4908): `Mutant-equivalent: <path>:<line> <reason>` in the PR body waives one site."""

    def setUp(self):
        self.v = Verify()

    @staticmethod
    def result(*lines):
        muts = [{"type": "ARITHMETIC_BASE", "status": "LIVED", "line": n, "column": 9} for n in lines]
        return {"files": [{"file_name": "a.go", "mutations": muts}], "mutants_lived": len(muts), "statement_deletions": 0}

    SRC = "package netguard\nvar a = 1 + 1\nvar b = 2 + 2\n"

    def test_equivalent_line_waives_only_its_site(self):
        ok = "Mutant-equivalent: broker/netguard/a.go:2 a and b are never read, so no value tells the mutants apart\n"
        r = self.v.verify({"netguard.json": self.result(2)}, src=self.SRC, body="Intro.\n\n" + ok)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        for body in (
                ok.replace("a.go:2", "a.go:3"),                       # another line
                ok.replace("broker/netguard/a.go", "broker/netguard/b.go"),
                ok.replace("broker/netguard/a.go", "broker/netguard/*.go"),  # never a pattern
                ok.replace("a.go:2", "a.go:1-9"),                     # never a range
                ok.replace("a.go:2", "a.go:02"),
                "Mutant-equivalent: broker/netguard/a.go:2\n",        # no reason
                "Mutant-equivalent: broker/netguard/a.go:2 .\n",
                "  " + ok,                                             # not at the line's start
                ok.replace("Mutant-equivalent", "mutant-equivalent"),
                "Mutant-equivalent: all\n",
                ""):
            with self.subTest(body):
                r = self.v.verify({"netguard.json": self.result(2)}, src=self.SRC, body=body)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn("broker/netguard/a.go:2 ARITHMETIC_BASE survives", r.stdout)
        # Two survivors, one waived: the other still fails, and the table shows each verdict.
        r = self.v.verify({"netguard.json": self.result(2, 3)}, src=self.SRC, body=ok.replace("\n", "\r\n"), summary=True)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertNotIn("a.go:2 ", r.stdout)
        self.assertIn("broker/netguard/a.go:3 ARITHMETIC_BASE survives", r.stdout)
        rows = [l for l in r.summary.split("\n") if l.startswith("| broker/")]
        self.assertEqual(rows, [
            "| broker/netguard/a.go:3:9 | ARITHMETIC\\_BASE | **LIVED**: no test fails |",
            "| broker/netguard/a.go:2:9 | ARITHMETIC\\_BASE | equivalent: a and b are never read, so no value tells the mutants apart "
            "(record, \\#1, new in this PR) |",
        ])

    def test_a_reason_saying_not_equivalent_fails_the_gate(self):
        # REQ: MUT-equivalent-not-equivalent
        # #5891 (from #5863, #5883): a line whose reason says its mutant is not equivalent never reaches a
        # record: waive refuses the file, writes nothing, and its survivor fails the gate.
        ok = "Mutant-equivalent: broker/netguard/a.go:2 a and b are never read, so no value tells the mutants apart\n"
        for reason in ("not equivalent: gremlins misreads it, follow-up #1", "NOT  Equivalent, a real survivor",
                       "the guard is not-equivalent here"):
            bad = f"Mutant-equivalent: broker/netguard/a.go:3 {reason}\n"
            with self.subTest(reason):
                r = self.v.verify({"netguard.json": self.result(2, 3)}, src=self.SRC, body=ok + bad, summary=True)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertEqual(r.waive.returncode, 1, r.waive.stdout + r.waive.stderr)
                self.assertIn("mutgate: the Mutant-equivalent line broker/netguard/a.go:3 says its mutant is not "
                              "equivalent", r.waive.stderr)
                self.assertIn("delete the line, or reword it only if the mutant is in fact equivalent", r.waive.stderr)
                self.assertIn("broker/netguard/a.go:3 ARITHMETIC_BASE survives", r.stdout)
                self.assertIn("broker/netguard/a.go:2 ARITHMETIC_BASE survives", r.stdout)
        self.assertEqual(mutgate.not_equivalent(mutgate.waivers(ok + "Mutant-equivalent: broker/netguard/a.go:3 "
                                                                       "equivalent: every caller passes x > 0\n")), [])

    def test_untrusted_body_cannot_change_the_gate(self):
        # The body is the PR author's text: parsed for waiver lines only, never run or read as options.
        hostile = ("$(touch pwned) `touch pwned` \"; exit 0; '\n--git HEAD\n--summary /etc/x\n"
                   "Mutant-equivalent: broker/netguard/a.go:3 waives another site | <img src=x> `x`\n"
                   "Mutant-equivalent: broker/netguard/a.go:2\x00 hidden\n"
                   "\udcff   Mutant-equivalent: broker/netguard/a.go:2 behind a separator\n")
        r = self.v.verify({"netguard.json": self.result(2, 3)}, src=self.SRC,
                          body=hostile.encode("utf-8", "surrogateescape").decode("utf-8", "replace"), summary=True)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("broker/netguard/a.go:2 ARITHMETIC_BASE survives", r.stdout)
        self.assertNotIn("a.go:3 ", r.stdout)
        self.assertFalse(pathlib.Path("pwned").exists())
        # The reason reaches the table as text: no column break, no markup.
        row = [l for l in r.summary.split("\n") if l.startswith("| broker/netguard/a.go:3")][0]
        self.assertEqual(row.count(" | "), 2, row)
        self.assertIn("waives another site \\| \\<img src=x\\> \\`x\\`", row)
        self.assertEqual(mutgate.waivers(hostile), {("broker/netguard/a.go", 3, None, None): "waives another site | <img src=x> `x`"})


class Record(unittest.TestCase):
    """MUT-waiver-store (#5776): accepted proofs live in broker/<pkg>/MUTANTS-EQUIVALENT, keyed by statement."""
    # REQ: MUT-waiver-store

    SRC = "package netguard\n\n// x\nfunc f(x int) int {\n\tif x > 1 {\n\t\treturn 2\n\t}\n\tif x > 1 {\n\t\treturn 3\n\t}\n\treturn x\n}\n"

    def repo(self, d, base, head, base_record=None, record=None, body=None):
        """A temp repo whose base commit holds broker/netguard/a.go = base (and base_record) and whose
        last commit makes it head (and record); returns a function running tools/mutgate.py there."""
        git = lambda *a: subprocess.run(["git", "-C", d, *a], check=True, capture_output=True, text=True)
        shutil.copytree(ROOT / "tools", pathlib.Path(d) / "tools")
        shutil.copytree(ROOT / "broker" / "core", pathlib.Path(d) / "broker" / "core")
        pkg = pathlib.Path(d) / "broker" / "netguard"
        pkg.mkdir(parents=True)
        for text, rec in ((base, base_record), (head, record)):
            (pkg / "a.go").write_text(text)
            if rec is not None:
                (pkg / mutgate.RECORD).write_text(rec)
            git("init", "-q")
            git("add", "-A")
            git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "c")
        return lambda *a: subprocess.run([sys.executable, "-I", str(pathlib.Path(d) / "tools" / "mutgate.py"), *a],
                                         capture_output=True, text=True, cwd=d)

    def waive(self, d, run, line, reason="the two branches return the same value for every input here"):
        (pathlib.Path(d) / "w.txt").write_text(f"Mutant-equivalent: broker/netguard/a.go:{line} {reason}\n")
        r = run("waive", str(pathlib.Path(d) / "w.txt"), "--accepted", "#5743")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return (pathlib.Path(d) / "broker" / "netguard" / mutgate.RECORD).read_text()

    def test_an_entry_follows_its_statement_when_lines_move_above_it(self):
        with tempfile.TemporaryDirectory() as d:
            run = self.repo(d, self.SRC, self.SRC)
            rec = self.waive(d, run, 8)
            entry = json.loads(rec.split("\n")[1])
            self.assertEqual({k: entry[k] for k in ("file", "mutant", "func", "stmt", "at", "after", "occurrence", "accepted")},
                             {"file": "a.go", "mutant": "STATEMENT_DELETION", "func": "f", "stmt": ["if x > 1 {"], "at": 0,
                              "after": "}", "occurrence": [1, 1], "accepted": "#5743"})
            self.assertRegex(entry["decl"], "^[0-9a-f]{64}$")
            r = run("records", "netguard")
            self.assertEqual((r.returncode, r.stdout.split(" ")[0]), (0, "broker/netguard/a.go:8"), r.stderr)
            # Lines added above the statement's func, and another func: the entry moves with it.
            for moved, line in ((self.SRC.replace("// x\n", "// x\n// y\n\nvar z = 1\n"), 11),
                                (self.SRC.replace("// x\n", "func g() {\n\tprintln()\n}\n\n// x\n"), 12)):
                with self.subTest(moved):
                    (pathlib.Path(d) / "broker" / "netguard" / "a.go").write_text(moved)
                    r = run("records", "netguard")
                    self.assertEqual(r.returncode, 0, r.stderr)
                    self.assertEqual(r.stdout.split(" ")[0], f"broker/netguard/a.go:{line}")

    def test_an_edited_or_deleted_statement_is_stale(self):
        with tempfile.TemporaryDirectory() as d:
            run = self.repo(d, self.SRC, self.SRC)
            self.waive(d, run, 8)
            for changed in (self.SRC.replace("\t}\n\tif x > 1 {\n\t\treturn 3", "\t}\n\tif x >= 1 {\n\t\treturn 3"),  # the statement
                            self.SRC.replace("\t}\n\tif x > 1 {\n\t\treturn 3\n\t}\n", "\t}\n"),                   # deleted
                            self.SRC.replace("\t\treturn 2\n\t}\n", "\t\treturn 2\n\t}\n\tx--\n"),                # the line before it
                            self.SRC.replace("\treturn x\n", "\treturn x + 1\n"),                                # code after it (Security on #5780)
                            self.SRC.replace("\tif x > 1 {\n\t\treturn 2", "\tx++\n\tif x > 1 {\n\t\treturn 2"),  # anywhere in its func
                            self.SRC.replace("func f(", "func g(")):                                              # another declaration
                with self.subTest(changed):
                    (pathlib.Path(d) / "broker" / "netguard" / "a.go").write_text(changed)
                    r = run("records", "netguard")
                    self.assertEqual(r.returncode, 1, r.stdout)
                    self.assertIn("names no statement at the head", r.stderr)
        # A twin outside any func (no digest), with the same line before it: the count changes, so it is stale.
        src = "package netguard\n\nvar b = 0\nvar a = 1 + 1\n"
        with tempfile.TemporaryDirectory() as d:
            run = self.repo(d, src, src)
            self.waive(d, run, 4)
            (pathlib.Path(d) / "broker" / "netguard" / "a.go").write_text(src + "var b = 0\nvar a = 1 + 1\n")
            r = run("records", "netguard")
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertIn("was written for occurrence 1 of 1, and the head has 2", r.stderr)

    def test_a_proof_premise_later_in_any_declaration_shape_is_keyed(self):
        # Security delta on #5780: a multi-line signature closing in column 0, and a top-level func literal,
        # still digest their whole declaration, so an edit after the statement makes the entry stale.
        for src in ("package netguard\n\nfunc f(e interface {\n\tRead() error\n}) bool {\n\tif err := e.Read(); err != nil {\n"
                    "\t\treturn false\n\t}\n\treturn check()\n}\n\nfunc check() bool { return false }\n",
                    "package netguard\n\nvar f = func(err error) bool {\n\tif err != nil {\n\t\treturn false\n\t}\n"
                    "\treturn check()\n}\n\nfunc check() bool { return false }\n"):
            with self.subTest(src), tempfile.TemporaryDirectory() as d:
                run = self.repo(d, src, src)
                line = 1 + src.split("\n").index(next(l for l in src.split("\n") if l.startswith("\tif ")))
                entry = json.loads(self.waive(d, run, line).split("\n")[1])
                self.assertEqual(entry["func"], "f")
                self.assertRegex(entry["decl"], "^[0-9a-f]{64}$")
                self.assertEqual(run("records", "netguard").returncode, 0)
                (pathlib.Path(d) / "broker" / "netguard" / "a.go").write_text(src.replace("\treturn check()", "\treturn true"))
                r = run("records", "netguard")
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("names no statement at the head", r.stderr)

    def test_waive_writes_nothing_while_a_stale_entry_remains(self):
        # L3 and UX on #5780: waive never guesses which stale entry a new one rewrites. Each way an entry goes
        # stale (an edit elsewhere in the func, the statement edited, the func renamed, a twin's count) leaves
        # the record untouched and names every stale entry; deleting those lines and waiving again goes green.
        twins = "package netguard\n\nfunc f(x int) int {\n\tx++\n\tg(x)\n\tx++\n\tg(x)\n\treturn x\n}\n\nfunc g(int) {}\n"
        for src, lines, edit, again in (
                (self.SRC, (8, 11), lambda t: t.replace("\tif x > 1 {\n\t\treturn 2", "\tx++\n\tif x > 1 {\n\t\treturn 2"), (9, 12)),
                (self.SRC, (8, 11), lambda t: t.replace("\t}\n\tif x > 1 {\n\t\treturn 3", "\t}\n\tif x >= 1 {\n\t\treturn 3"), (8, 11)),
                (self.SRC, (8, 11), lambda t: t.replace("func f(", "func h("), (8, 11)),
                (twins, (5, 7), lambda t: t.replace("\treturn x\n", "\tx--\n\treturn x\n"), (5, 7))):
            with self.subTest(edit(src)), tempfile.TemporaryDirectory() as d:
                run = self.repo(d, src, src)
                for n in lines:
                    rec = self.waive(d, run, n, reason=f"proof number {n} for this site, read by review")
                (pathlib.Path(d) / "broker" / "netguard" / "a.go").write_text(edit(src))
                self.assertEqual(run("records", "netguard").returncode, 1)
                (pathlib.Path(d) / "w.txt").write_text(f"Mutant-equivalent: broker/netguard/a.go:{again[0]} a fresh proof read again\n")
                r = run("waive", str(pathlib.Path(d) / "w.txt"), "--accepted", "#5780")
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertEqual(r.stderr.count("holds a stale entry"), 2, r.stderr)
                path = pathlib.Path(d) / "broker" / "netguard" / mutgate.RECORD
                self.assertEqual(path.read_text(), rec)  # no reviewed proof dropped, none added
                path.write_text("\n".join(l for l in rec.split("\n") if not l.startswith("{")) + "\n")
                for n in again:
                    self.waive(d, run, n, reason=f"proof number {n} for this site, read again")
                r = run("records", "netguard")
                self.assertEqual((r.returncode, len(r.stdout.strip().split("\n"))), (0, 2), r.stdout + r.stderr)

    def test_waive_refuses_a_reason_saying_not_equivalent(self):
        # REQ: MUT-equivalent-not-equivalent
        # #5891: waive run on a whole PR body writes nothing while one line says its mutant is not equivalent.
        with tempfile.TemporaryDirectory() as d:
            run = self.repo(d, self.SRC, self.SRC)
            path = pathlib.Path(d) / "broker" / "netguard" / mutgate.RECORD
            rec = self.waive(d, run, 5)
            (pathlib.Path(d) / "w.txt").write_text(
                "Mutant-equivalent: broker/netguard/a.go:8 the two branches return the same value for every input\n"
                "Mutant-equivalent: broker/netguard/a.go:11 Not Equivalent: a real survivor, left to a follow-up\n")
            r = run("waive", str(pathlib.Path(d) / "w.txt"), "--accepted", "#5891")
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("broker/netguard/a.go:11 says its mutant is not equivalent", r.stderr)
            self.assertIn("delete the line, or reword it only if the mutant is in fact equivalent", r.stderr)
            self.assertNotIn("a.go:8", r.stderr)
            self.assertEqual(path.read_text(), rec)  # nothing written, the good line included

    def test_a_method_is_named_by_its_receiver_type(self):
        # Potency on #5780: generic receivers (IndexExpr, IndexListExpr) name the type, not its parameters.
        src = ("package netguard\n\ntype T[K any] struct{ n int }\n\ntype U[K, V any] struct{ n int }\n\n"
               "func (t *T[K]) m() {\n\tt.n++\n}\n\nfunc (u U[K, V]) m() {\n\tu.n++\n}\n\nfunc (t2 *T[K]) p() {\n\tt2.n--\n}\n")
        with tempfile.TemporaryDirectory() as d:
            run = self.repo(d, src, src)
            self.waive(d, run, 8)
            self.waive(d, run, 12)
            rec = self.waive(d, run, 16)
            self.assertEqual(sorted(json.loads(l)["func"] for l in rec.split("\n") if l.startswith("{")), ["T.m", "T.p", "U.m"])

    def test_twins_are_told_apart_by_occurrence(self):
        src = "package netguard\n\nfunc f(x int) int {\n\tx++\n\tg(x)\n\tx++\n\tg(x)\n\treturn x\n}\n\nfunc g(int) {}\n"
        with tempfile.TemporaryDirectory() as d:
            run = self.repo(d, src, src)
            rec = self.waive(d, run, 7)
            self.assertEqual([json.loads(r)["occurrence"] for r in rec.strip().split("\n")[1:]], [[2, 2]])
            rec = self.waive(d, run, 5)
            self.assertEqual(sorted(json.loads(r)["occurrence"] for r in rec.strip().split("\n")[1:]), [[1, 2], [2, 2]])
            r = run("records", "netguard")
            self.assertEqual((r.returncode, sorted(l.split(" ")[0] for l in r.stdout.strip().split("\n"))),
                             (0, ["broker/netguard/a.go:5", "broker/netguard/a.go:7"]), r.stderr)

    def test_a_multi_line_statement_is_keyed_by_every_line_of_its_own_syntax(self):
        src = "package netguard\n\nfunc f(x int) int {\n\tg(x,\n\t\t1)\n\treturn x\n}\n\nfunc g(int, int) {}\n"
        with tempfile.TemporaryDirectory() as d:
            run = self.repo(d, src, src)
            entry = json.loads(self.waive(d, run, 4).split("\n")[1])
            self.assertEqual((entry["stmt"], entry["at"]), (["g(x,", "1)"], 0))
            (pathlib.Path(d) / "broker" / "netguard" / "a.go").write_text(src.replace("\t\t1)", "\t\t2)"))
            r = run("records", "netguard")
            self.assertEqual(r.returncode, 1, r.stdout)  # an edit to a continuation line is an edit to the statement

    def test_a_malformed_or_linked_record_fails(self):
        with tempfile.TemporaryDirectory() as d:
            run = self.repo(d, self.SRC, self.SRC)
            good = json.loads(self.waive(d, run, 8).split("\n")[1])
            path = pathlib.Path(d) / "broker" / "netguard" / mutgate.RECORD
            for bad in ("{", "[]", json.dumps({**good, "extra": 1}), json.dumps({**good, "file": "../x.go"}),
                        json.dumps({**good, "file": "a_test.go"}), json.dumps({**good, "reason": "."}),
                        json.dumps({**good, "accepted": "5743"}), json.dumps({**good, "occurrence": [2, 1]}),
                        json.dumps({**good, "at": 1}), json.dumps({**good, "stmt": []}),
                        json.dumps({**good, "mutant": "all"}), json.dumps({**good, "decl": "x"}), json.dumps({**good, "decl": ""}),
                        json.dumps({k: v for k, v in good.items() if k != "mutant"})):
                with self.subTest(bad):
                    path.write_text(bad + "\n")
                    r = run("records", "netguard")
                    self.assertEqual(r.returncode, 1, r.stdout)
                    self.assertIn(mutgate.RECORD, r.stderr)
                    # Refused as malformed, not merely stale (Potency on #5780).
                    self.assertTrue("is not an entry of" in r.stderr or "is not one JSON object" in r.stderr, r.stderr)
            path.unlink()
            (pathlib.Path(d) / "elsewhere").write_text(json.dumps(good) + "\n")
            path.symlink_to(pathlib.Path(d) / "elsewhere")
            r = run("records", "netguard")
            self.assertEqual(r.returncode, 1, r.stdout)
            self.assertIn("symbolic link", r.stderr)

    VAR = "package netguard\n\nvar a = 1 + 1\n"

    @staticmethod
    def digest(text):
        """A record's decl for a one-line top-level declaration."""
        import hashlib
        return hashlib.sha256(text.encode()).hexdigest()

    @staticmethod
    def result(*lines):
        muts = [{"type": "ARITHMETIC_BASE", "status": "LIVED", "line": n, "column": 9} for n in lines]
        return {"files": [{"file_name": "a.go", "mutations": muts}], "mutants_lived": len(muts), "statement_deletions": 0}

    def verify(self, d, run, *lines, body=""):
        res = pathlib.Path(d) / "res" / "mutants-0"
        res.mkdir(parents=True, exist_ok=True)
        (res / "netguard.json").write_text(json.dumps(self.result(*lines)))
        (pathlib.Path(d) / "body.md").write_text(body)
        r = run("verify", str(res.parent), "--git", "HEAD~1", "--body", str(pathlib.Path(d) / "body.md"),
                "--summary", str(pathlib.Path(d) / "summary.md"))
        r.summary = (pathlib.Path(d) / "summary.md").read_text() if (pathlib.Path(d) / "summary.md").exists() else ""
        return r

    def test_a_record_entry_waives_its_site_with_no_body_line(self):
        head = self.VAR + "var b = 2 + 2\n"
        with tempfile.TemporaryDirectory() as d:
            run = self.repo(d, self.VAR, head)
            r = self.verify(d, run, 4)
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("broker/netguard/a.go:4 ARITHMETIC_BASE survives", r.stdout)
        with tempfile.TemporaryDirectory() as d:
            rec = json.dumps({"file": "a.go", "mutant": "ARITHMETIC_BASE", "func": "b", "decl": Record.digest("var b = 2 + 2"), "stmt": ["var b = 2 + 2"], "at": 0, "after": "var a = 1 + 1",
                              "occurrence": [1, 1], "reason": "b is never read", "accepted": "#5743"}) + "\n"
            run = self.repo(d, self.VAR, head, record=rec)
            r = self.verify(d, run, 4)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("| broker/netguard/a.go:4:9 | ARITHMETIC\\_BASE | equivalent: b is never read "
                          "(record, \\#5743, new in this PR) |", r.summary)
        with tempfile.TemporaryDirectory() as d:
            # A survivor the entry does not name still fails.
            run = self.repo(d, self.VAR, head + "var c = 3 + 3\n", record=rec)
            r = self.verify(d, run, 4, 5)
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("broker/netguard/a.go:5 ARITHMETIC_BASE survives", r.stdout)
            self.assertNotIn("a.go:4 ", r.stdout)
        with tempfile.TemporaryDirectory() as d:
            # The base's entry, unchanged, on a line the PR moves and edits around: not marked new.
            base = self.VAR + "var b = 2 + 2\n"
            rec = json.dumps({"file": "a.go", "mutant": "ARITHMETIC_BASE", "func": "b", "decl": Record.digest("var b = 2 + 2"), "stmt": ["var b = 2 + 2"], "at": 0, "after": "var a = 1 + 1",
                              "occurrence": [1, 1], "reason": "b is never read", "accepted": "#5743"}) + "\n"
            run = self.repo(d, base, "package netguard\n\n// moved\nvar a = 1 + 1\nvar b = 2 + 2\nvar c = 3 + 3\n",
                            base_record=rec)
            # PROC-review-no-mutgate-wait (#6379): a PR body line waives nothing; it is named, and the survivor fails.
            r = self.verify(d, run, 6, body="Mutant-equivalent: broker/netguard/a.go:6:9:ARITHMETIC_BASE c is never read\n")
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("broker/netguard/a.go:6 ARITHMETIC_BASE survives", r.stdout)
            self.assertIn("mutgate: the PR body's Mutant-equivalent and Mutant-uncovered lines waive nothing (#6379)", r.stdout)
            self.assertIn("| broker/netguard/a.go:6:9 | ARITHMETIC\\_BASE | **LIVED**: no test fails |", r.summary)
            self.assertNotIn("new in this PR", r.summary)

    def test_a_record_entry_saying_not_equivalent_fails_records_and_the_gate(self):
        # REQ: MUT-legacy-not-equivalent-records
        # #5909: an entry whose reason says its mutant is not equivalent waives nothing, fails `records`
        # and the gate even where no mutant survives, and waive writes nothing to its record.
        head = self.VAR + "var b = 2 + 2\n"
        entry = {"file": "a.go", "mutant": "ARITHMETIC_BASE", "func": "b", "decl": Record.digest("var b = 2 + 2"),
                 "stmt": ["var b = 2 + 2"], "at": 0, "after": "var a = 1 + 1", "occurrence": [1, 1], "accepted": "#5774"}
        for reason in ("not equivalent but unseen by gremlins", "Not-Equivalent: a real survivor", "b is never read"):
            rec = json.dumps({**entry, "reason": reason}) + "\n"
            # On the base too: an entry already merged is refused, not only a new one.
            with self.subTest(reason), tempfile.TemporaryDirectory() as d:
                run = self.repo(d, self.VAR, head, base_record=rec, record=rec)
                refused = reason != "b is never read"
                r = run("records", "netguard")
                self.assertEqual(r.returncode, int(refused), r.stdout + r.stderr)
                self.assertEqual("says its mutant is not equivalent" in r.stderr, refused, r.stderr)
                self.assertEqual("broker/netguard/a.go:4 " in r.stdout, not refused, r.stdout)
                for lines in ((4,), ()):
                    r = self.verify(d, run, *lines)
                    self.assertEqual(r.returncode, int(refused), r.stdout + r.stderr)
                    self.assertEqual("whose reason says its mutant is not equivalent" in r.stdout + r.stderr, refused)
                    self.assertEqual("equivalent: " in r.summary.rsplit("### mutgate", 1)[-1], not refused and bool(lines), r.summary)  # appended
                path = pathlib.Path(d) / "broker" / "netguard" / mutgate.RECORD
                (pathlib.Path(d) / "w.txt").write_text("Mutant-equivalent: broker/netguard/a.go:3 a is never read\n")
                r = run("waive", str(pathlib.Path(d) / "w.txt"), "--accepted", "#5909")
                self.assertEqual(r.returncode, int(refused), r.stdout + r.stderr)
                self.assertEqual(path.read_text() == rec, refused)

    def test_an_entry_waives_only_its_mutant_kind(self):
        # Security on #5780: a deletion proof carried forward must not waive a gremlins mutant on its line.
        rec = json.dumps({"file": "a.go", "mutant": "STATEMENT_DELETION", "func": "b", "decl": Record.digest("var b = 2 + 2"), "stmt": ["var b = 2 + 2"],
                          "at": 0, "after": "var a = 1 + 1", "occurrence": [1, 1], "reason": "b is never read",
                          "accepted": "#5743"}) + "\n"
        with tempfile.TemporaryDirectory() as d:
            run = self.repo(d, self.VAR, self.VAR + "var b = 2 + 2\n", record=rec)
            r = self.verify(d, run, 4)
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("broker/netguard/a.go:4 ARITHMETIC_BASE survives", r.stdout)
        self.assertEqual(mutgate.violations({"p": {"broker/p/a.go": {4}}}, {"p": [("a.go", 4, "STATEMENT_DELETION"),
                         ("a.go", 4, "CONDITIONALS_NEGATION")]}, {("broker/p/a.go", 4, "STATEMENT_DELETION", None): "r"}),
                         [("p", "broker/p/a.go", 4, "CONDITIONALS_NEGATION", None)])

    def test_a_stale_entry_fails_the_gate(self):
        rec = json.dumps({"file": "a.go", "mutant": "ARITHMETIC_BASE", "func": "a", "decl": Record.digest("var a = 1 + 1"), "stmt": ["var a = 1 + 1"], "at": 0, "after": "package netguard",
                          "occurrence": [1, 1], "reason": "a is never read", "accepted": "#5743"}) + "\n"
        with tempfile.TemporaryDirectory() as d:
            run = self.repo(d, self.VAR, "package netguard\n\nvar a = 1 + 2\n", base_record=rec)
            r = self.verify(d, run, 3, body="Mutant-equivalent: broker/netguard/a.go:3 a is never read, still\n")
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("names no statement at the head", r.stdout)
            self.assertIn("Stale MUTANTS-EQUIVALENT entries", r.summary)

    def test_a_record_only_change_lists_its_new_entries(self):
        # MUT-waiver-store-claim (#5786): a PR that adds an entry and changes no .go line is claimed, its
        # (empty) result read, and the summary lists the entry as new for review; a stale one fails.
        head = self.VAR + "var b = 2 + 2\n"
        rec = json.dumps({"file": "a.go", "mutant": "ARITHMETIC_BASE", "func": "b", "decl": Record.digest("var b = 2 + 2"),
                          "stmt": ["var b = 2 + 2"], "at": 0, "after": "var a = 1 + 1", "occurrence": [1, 1],
                          "reason": "b is never read", "accepted": "#5743"}) + "\n"
        old = rec.replace("ARITHMETIC_BASE", "STATEMENT_DELETION")
        with tempfile.TemporaryDirectory() as d:
            run = self.repo(d, head, head, base_record=old, record=old + rec)
            r = run("claimed", "--git", "HEAD~1", "--json")
            self.assertEqual((r.returncode, json.loads(r.stdout)), (0, ["netguard"]), r.stderr)
            r = self.verify(d, run)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn("- netguard: 0 target lines", r.summary)
            self.assertIn("New MUTANTS-EQUIVALENT entries in this PR", r.summary)
            self.assertIn("- broker/netguard/a.go:4 ARITHMETIC\\_BASE (\\#5743): b is never read", r.summary)
            self.assertNotIn("STATEMENT\\_DELETION (", r.summary)  # the base's entry is not new
            # The claimed package needs its result, as any claim does.
            shutil.rmtree(pathlib.Path(d) / "res")
            (pathlib.Path(d) / "res").mkdir()
            r = run("verify", str(pathlib.Path(d) / "res"), "--git", "HEAD~1")
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("0 results for netguard", r.stderr)
        with tempfile.TemporaryDirectory() as d:
            # A record-only PR whose new entry names no statement fails the gate.
            run = self.repo(d, head, head, record=rec.replace("2 + 2", "2 + 3"))
            r = self.verify(d, run)
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("names no statement at the head", r.stdout)
        with tempfile.TemporaryDirectory() as d:
            # Unchanged records claim nothing, so no result is needed.
            run = self.repo(d, self.VAR, self.VAR, base_record=rec, record=rec)
            r = run("claimed", "--git", "HEAD~1", "--json")
            self.assertEqual((r.returncode, json.loads(r.stdout)), (0, []), r.stderr)

    def test_a_cut_new_entry_reason_is_marked_and_names_its_record(self):
        # MUT-waiver-store-claim-fu R2 (#5812): the heading says to read each proof, so a cut one says so.
        site = ("broker/netguard/a.go", 4, "ARITHMETIC_BASE", None)
        for n, cut in ((300, False), (301, True), (400, True)):
            with self.subTest(n):
                out = mutgate.summary({}, {}, {}, fresh=[(site, "b" * n, "#5743")])
                line = next(l for l in out.split("\n") if l.startswith("- broker/netguard/a.go:4 "))
                self.assertEqual(line.endswith(" … (cut; see broker/netguard/MUTANTS-EQUIVALENT)"), cut, line)
                self.assertIn("b" * 300, line)
                self.assertNotIn("b" * 301, line)

    def test_the_new_entry_list_is_capped_with_a_count_naming_the_records(self):
        # MUT-waiver-store-claim-fu R3 (#5812): a 1 MiB record's new entries cannot push the step summary
        # past GitHub's 1 MiB limit, which would drop the summary and show no entry at all.
        fresh = [(("broker/netguard/a.go" if i % 2 else "broker/clerk/run/b.go", i + 1, "ARITHMETIC_BASE", None),
                  "r" * 1000, "#5743") for i in range(mutgate.FRESH + 7)]
        out = mutgate.summary({}, {}, {}, fresh=fresh)
        listed = out.split("New MUTANTS-EQUIVALENT entries in this PR", 1)[1].split("\n\n", 1)[0].rstrip("\n").split("\n")[1:]
        self.assertEqual(len(listed), mutgate.FRESH + 1, listed[-2:])
        self.assertEqual(listed[-1], "- 7 more new entries not shown: read them in broker/clerk/run/MUTANTS-EQUIVALENT, "
                                     "broker/netguard/MUTANTS-EQUIVALENT")
        self.assertLess(len(out.encode()), 1 << 19)
        out = mutgate.summary({}, {}, {}, fresh=fresh[:mutgate.FRESH])
        self.assertNotIn("more new entries", out)

    def test_local_gate_reads_a_record_only_package(self):
        # MUT-waiver-store-claim-fu R4 (#5812): `gate` claims as `verify` does, so a record-only diff with a
        # stale entry fails locally, not first in CI; a package with no result file is still skipped.
        head = self.VAR + "var b = 2 + 2\n"
        rec = json.dumps({"file": "a.go", "mutant": "ARITHMETIC_BASE", "func": "b", "decl": Record.digest("var b = 2 + 2"),
                          "stmt": ["var b = 2 + 3"], "at": 0, "after": "var a = 1 + 1", "occurrence": [1, 1],
                          "reason": "b is never read", "accepted": "#5743"}) + "\n"
        with tempfile.TemporaryDirectory() as d:
            run = self.repo(d, head, head, record=rec)
            res = pathlib.Path(d) / "res"
            res.mkdir()
            r = run("gate", str(res), "--git", "HEAD~1")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)  # no result file: skipped
            (res / mutgate.result_name("netguard")).write_text(json.dumps(self.result()))
            r = run("gate", str(res), "--git", "HEAD~1")
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("names no statement at the head", r.stdout)

    def test_every_record_in_the_repository_resolves(self):
        # A record-only PR, or an edit to a proven statement in any package, fails here as well as in mutgate.
        r = subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "mutgate.py"), "records"],
                           capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_the_clerk_run_record_holds_the_5743_proofs(self):
        # Acceptance (#5776): the 27 proofs L3 checked on #5743 resolve at the head with no body line.
        r = subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "mutgate.py"), "records", "clerk/run"],
                           capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(r.returncode, 0, r.stderr)
        sites = sorted(l.split(" ")[0] for l in r.stdout.strip().split("\n"))
        # #5774 dropped three of them (boxFor's StartTLS branch is gone; readMail's open-error branch and
        # its return are now killed by the ELOOP check). The nine it added for gremlins' cover-gap lines
        # said their mutants were not equivalent; #5909 deleted them once gremlins ran and killed each.
        # #6346 dropped ownGmailSignIn's clear(k): the sealer key-wipe lint kills its deletion.
        self.assertEqual(len(sites), 23, r.stdout)
        self.assertEqual(len(set(sites)), 23, r.stdout)
        # The two loadSenders proofs were re-read on #5780 after #5733 edited that func, readMail's
        # ReadAll proof on #5804 after it gained the setup-form check, and work's tick.Stop proof on #5998
        # after its ticker took MailConfig.every.
        self.assertEqual(sorted(" ".join(l.split(" ")[1:3]) for l in r.stdout.strip().split("\n")),
                         ["STATEMENT_DELETION #5743"] * 19 + ["STATEMENT_DELETION #5780"] * 2
                         + ["STATEMENT_DELETION #5804", "STATEMENT_DELETION #5998"])


class WaiveKeepsOrder(unittest.TestCase):
    """TOOL-waive-keeps-order (#6573): waive keeps a record's lines in place, so premerge's union check reads it as kept."""
    # REQ: TOOL-waive-keeps-order
    SRC, repo, waive = Record.SRC, Record.repo, Record.waive

    def test_waive_keeps_an_unsorted_record_in_its_order(self):
        sys.path.insert(0, str(ROOT / "tools"))
        import premerge
        with tempfile.TemporaryDirectory() as d:
            git = lambda *a: subprocess.run(["git", "-C", d, "-c", "user.email=t@example.invalid", "-c", "user.name=t", *a],
                                            check=True, capture_output=True, text=True).stdout.strip()
            run = self.repo(d, self.SRC, self.SRC)
            pkg = pathlib.Path(d) / "broker" / "netguard"
            (pkg / "b.go").write_text("package netguard\n\nfunc g(x int) int {\n\tif x > 1 {\n\t\treturn 2\n\t}\n\treturn x\n}\n")
            wfile = pathlib.Path(d) / "w.txt"

            def waive(*sites, accepted="#5743"):
                wfile.write_text("".join(f"Mutant-equivalent: broker/netguard/{s} both give the same value on every input\n"
                                         for s in sites))
                r = run("waive", str(wfile), "--accepted", accepted)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                return r.stdout
            for site in ("a.go:5", "a.go:8", "a.go:11", "b.go:4"):
                waive(site)
            path = pkg / mutgate.RECORD
            rows = path.read_text().rstrip("\n").split("\n")
            a5, a8, a11, b4 = rows[1:]  # each new site after its file's last entry: in waive order here
            self.assertEqual([(e["file"], e["stmt"][e["at"]]) for e in map(json.loads, rows[1:])],
                             [("a.go", "if x > 1 {"), ("a.go", "if x > 1 {"), ("a.go", "return x"), ("b.go", "if x > 1 {")])
            # A hand-ordered record: a.go's entries reversed, a comment and a blank line between them, a word-for-word
            # repeat of one entry, and b.go's entry last.
            hand = [rows[0], a11, "# a note between entries", "", a8, a8, a5, b4]
            path.write_text("\n".join(hand) + "\n")
            git("add", "-A")
            git("commit", "-qm", "base")
            base = git("rev-parse", "HEAD")
            # Rewrite a.go:8 (the repeated entry, under another accepting PR) and add a.go:6.
            self.assertIn("2 entries written, 5 in all", waive("a.go:8", "a.go:6", accepted="#6573"))
            out = path.read_text().rstrip("\n").split("\n")
            self.assertEqual(out[:4], hand[:4])               # untouched lines in place, word for word
            self.assertEqual(json.loads(out[4])["accepted"], "#6573")  # rewritten in its own place; its repeat gone
            self.assertEqual(json.loads(out[4])["stmt"], json.loads(a8)["stmt"])
            self.assertEqual(out[5], a5)
            self.assertEqual(json.loads(out[6])["stmt"], ["return 2"])  # new: after a.go's last entry, not at the end
            self.assertEqual(json.loads(out[6])["file"], "a.go")
            self.assertEqual(out[7:], [b4])
            git("add", "-A")
            git("commit", "-qm", "waive")
            head = git("rev-parse", "HEAD")
            rel = f"broker/netguard/{mutgate.RECORD}"
            self.assertIs(premerge._records_kept(d, head, head, rel, head, base), True)
            # Two untouched entries swapped (as the old sorted rewrite moved them, #6559) read as changed.
            moved = [out[0], out[5], out[2], out[3], out[4], out[1], out[6], out[7]]
            path.write_text("\n".join(moved) + "\n")
            git("commit", "-qam", "moved")
            head = git("rev-parse", "HEAD")
            self.assertIs(premerge._records_kept(d, head, head, rel, head, base), False)

    def test_waive_writes_a_head_into_a_new_record(self):
        rows, total = mutgate.waive_rows("p", "", [])
        self.assertEqual((rows[0][0], total), ("#", 0))


class RecordDeps(unittest.TestCase):
    """MUT-record-deps (#6282): an entry names the declarations its proof rests on, in any file under broker/,
    and goes stale when one of them changes, moves or goes."""
    # REQ: MUT-record-deps

    SRC = Record.SRC
    DEP = ("package netguard\n\n// g is what the proof of f's line 8 cites.\nfunc g() int {\n\treturn 1\n}\n\n"
           "func unrelated() int {\n\treturn 2\n}\n\nvar (\n\tfirst  = 1\n\tprobe = g()\n)\n")

    def setUp(self):
        self.d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.d)
        self.run_ = Record().repo(self.d, self.SRC, self.SRC)
        self.pkg = pathlib.Path(self.d) / "broker" / "netguard"
        (self.pkg / "b.go").write_text(self.DEP)
        self.record = self.pkg / mutgate.RECORD

    def waive(self, *deps, line=8, reason="the two branches return the same value, as g always returns 1"):
        (pathlib.Path(self.d) / "w.txt").write_text(f"Mutant-equivalent: broker/netguard/a.go:{line} {reason}\n")
        return self.run_("waive", str(pathlib.Path(self.d) / "w.txt"), "--accepted", "#6282",
                         *(a for dep in deps for a in ("--dep", dep)))

    def records(self):
        return self.run_("records", "netguard")

    def entry(self):
        return json.loads(next(l for l in self.record.read_text().split("\n") if l.startswith("{")))

    def test_waive_writes_each_dep_with_its_digest(self):
        r = self.waive("broker/netguard/b.go:g", "broker/netguard/b.go:probe")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        deps = self.entry()["deps"]
        self.assertEqual([(x["file"], x["func"]) for x in deps], [("broker/netguard/b.go", "g"), ("broker/netguard/b.go", "probe")])
        self.assertEqual(deps[0]["decl"], Record.digest("func g() int {\nreturn 1\n}"))
        # probe is the second name of a var group: the dep is the whole group's text.
        self.assertEqual(deps[1]["decl"], Record.digest("var (\nfirst = 1\nprobe = g()\n)"))
        r = self.records()
        self.assertEqual((r.returncode, r.stdout.split(" ")[0]), (0, "broker/netguard/a.go:8"), r.stderr)

    def test_a_changed_moved_or_missing_dep_is_stale_and_an_unrelated_edit_is_not(self):
        self.assertEqual(self.waive("broker/netguard/b.go:g").returncode, 0)
        for edit, why in ((lambda: (self.pkg / "b.go").write_text(self.DEP.replace("return 1", "return 3")), "which has changed g"),
                          (lambda: (self.pkg / "b.go").unlink(), "which is no file now"),
                          (lambda: ((self.pkg / "b.go").write_text(self.DEP.replace("func g() int {\n\treturn 1\n}\n", "")),
                                    (self.pkg / "c.go").write_text("package netguard\n\nfunc g() int {\n\treturn 1\n}\n")),
                           "which declares g 0 times now, not once"),
                          (lambda: (self.pkg / "c.go").write_text("package netguard\n\nfunc (T) g() {}\n\ntype T int\n"
                                                                  "\nvar _ = 0\n") or (self.pkg / "b.go").write_text(
                              self.DEP + "\nfunc init() {}\n"), None)):
            with self.subTest(why):
                (self.pkg / "b.go").write_text(self.DEP)
                (self.pkg / "c.go").unlink(missing_ok=True)
                self.assertEqual(self.records().returncode, 0)
                edit()
                r = self.records()
                if why is None:  # another file's method g (T.g) and a new init are other declarations
                    self.assertEqual(r.returncode, 0, r.stderr)
                    continue
                self.assertEqual(r.returncode, 1, r.stdout)
                self.assertIn("a.go f 'if x > 1 {' rests on g in broker/netguard/b.go, " + why, r.stderr)
                self.assertIn("`mutgate.py waive --dep`", r.stderr)
                self.assertEqual(r.stdout, "")
        # Another declaration, or g's doc comment (outside go/parser's span, as for an entry's own decl), is no change.
        for unrelated in (self.DEP.replace("return 2", "return 4"), self.DEP.replace("first  = 1", "first  = 5"),
                          self.DEP.replace("// g is", "// g, now, is"),
                          "package netguard\n\nvar z = 0\n\n" + self.DEP.split("\n", 2)[2]):
            with self.subTest(unrelated):
                (self.pkg / "b.go").write_text(unrelated)
                self.assertEqual(self.records().returncode, 0, self.records().stderr)

    def test_a_name_declared_twice_is_stale(self):
        self.assertEqual(self.waive("broker/netguard/b.go:g").returncode, 0)
        (self.pkg / "b.go").write_text(self.DEP + "\nvar _x = 0\n")
        self.assertEqual(self.records().returncode, 0)
        # Go refuses a redeclared g, but the record does not rely on the compiler: two declarations name none.
        (self.pkg / "b.go").write_text(self.DEP + "\nvar g = 2\n")
        r = self.records()
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("which declares g 2 times now, not once", r.stderr)

    def test_a_dep_in_another_package_is_tracked(self):
        other = pathlib.Path(self.d) / "broker" / "other" / "deep"
        other.mkdir(parents=True)
        (other / "t.go").write_text("package deep\n\ntype (\n\tRecord struct{ N int }\n\tRecipient struct{ K string }\n)\n")
        r = self.waive("broker/other/deep/t.go:Recipient")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertEqual(self.records().returncode, 0)
        (other / "t.go").write_text("package deep\n\ntype (\n\tRecord struct{ N int }\n\tRecipient struct{ K chan int }\n)\n")
        r = self.records()
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("rests on Recipient in broker/other/deep/t.go, which has changed Recipient", r.stderr)

    def test_an_entry_without_deps_reads_as_before(self):
        self.assertEqual(self.waive().returncode, 0)
        self.assertNotIn("deps", self.entry())
        (self.pkg / "b.go").unlink()
        self.assertEqual(self.records().returncode, 0)

    def test_waive_refuses_a_dep_it_cannot_digest(self):
        for dep, code, said in (("broker/netguard/b.go:nothere", 1, "declares nothere 0 times, not once"),
                                ("broker/netguard/z.go:g", 1, "broker/netguard/z.go is no file"),
                                ("broker/netguard/b_test.go:g", 2, "is not broker/<pkg>/<file>.go:<name>"),
                                ("broker/../tools/x.go:g", 2, "is not broker/<pkg>/<file>.go:<name>"),
                                ("tools/x.go:g", 2, "is not broker/<pkg>/<file>.go:<name>"),
                                ("broker/netguard/b.go:", 2, "is not broker/<pkg>/<file>.go:<name>"),
                                ("broker/netguard/b.go:g()", 2, "is not broker/<pkg>/<file>.go:<name>")):
            with self.subTest(dep):
                r = self.waive(dep)
                self.assertEqual(r.returncode, code, r.stdout + r.stderr)
                self.assertIn(said, r.stderr)
                self.assertFalse(self.record.exists())
        (self.pkg / "l.go").symlink_to(self.pkg / "b.go")
        r = self.waive("broker/netguard/l.go:g")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("symbolic link", r.stderr)
        self.assertFalse(self.record.exists())

    def test_waive_writes_nothing_while_an_entry_s_dep_is_stale(self):
        self.assertEqual(self.waive("broker/netguard/b.go:g").returncode, 0)
        rec = self.record.read_text()
        (self.pkg / "b.go").write_text(self.DEP.replace("return 1", "return 3"))
        r = self.waive("broker/netguard/b.go:g", line=11, reason="a second proof resting on g")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("holds a stale entry", r.stderr)
        self.assertEqual(self.record.read_text(), rec)
        # Written again at the same site, the entry takes g's new digest.
        self.record.write_text(rec.split("\n")[0] + "\n")
        self.assertEqual(self.waive("broker/netguard/b.go:g").returncode, 0)
        self.assertEqual(self.records().returncode, 0)

    def test_a_record_s_deps_are_checked_for_shape(self):
        good = {"file": "a.go", "mutant": "STATEMENT_DELETION", "func": "b", "decl": "0" * 64, "stmt": ["b()"], "at": 0,
                "after": "", "occurrence": [1, 1], "reason": "b does nothing", "accepted": "#6282"}
        dep = {"file": "broker/kernel/edge.go", "func": "orderProbe", "decl": "1" * 64}
        for ok in ([dep], [dep, {**dep, "func": "State.Apply"}]):
            self.assertIsNotNone(mutgate.record_entries(json.dumps({**good, "deps": ok}))[0], ok)
        for bad in ([], dep, [dep, dep], [{**dep, "x": 1}], [{k: v for k, v in dep.items() if k != "decl"}],
                    [{**dep, "decl": "x"}], [{**dep, "func": ""}], [{**dep, "func": "a b"}], [{**dep, "func": 1}],
                    [{**dep, "file": "edge.go"}], [{**dep, "file": "broker/kernel/edge_test.go"}],
                    [{**dep, "file": "broker/../x.go"}], [{**dep, "file": "broker/.x/x.go"}], [{**dep, "file": "/broker/x.go"}],
                    [{**dep, "file": "broker/x.txt"}], [{**dep, "file": "tools/x.go"}], [{**dep, "file": None}], ["x"], None):
            with self.subTest(bad):
                self.assertIsNone(mutgate.record_entries(json.dumps({**good, "deps": bad}))[0])
        # A whole entry is stale when the dep's file is not among the listed ones (fail closed).
        keys = {"a.go": {4: mutgate._entry_key(good)}}
        found, problems = mutgate.resolve_record("k", [{**good, "deps": [dep]}], keys)
        self.assertEqual(found, {})
        self.assertIn("rests on orderProbe in broker/kernel/edge.go, which is no file now", problems[0])


class MutantScope(unittest.TestCase):
    """MUT-waiver-mutant-scope (#5792, Security on #5774): a waiver waives the one mutant it proves, never
    every mutant of its kind on its line."""
    # REQ: MUT-waiver-mutant-scope

    # broker/clerk/run/mail.go:144's shape: three CONDITIONALS_BOUNDARY mutants on one line, the proof for
    # the cover-gap `< 0` at column 113 and the `len(p) >= 12` one at column 16 alive.
    LINE = [("a.go", 4, "CONDITIONALS_BOUNDARY", 16), ("a.go", 4, "CONDITIONALS_BOUNDARY", 32),
            ("a.go", 4, "CONDITIONALS_BOUNDARY", 113), ("a.go", 4, "CONDITIONALS_NEGATION", 113)]
    TARGETS = {"p": {"broker/p/a.go": {4}}}

    def test_a_two_comparison_line_with_one_proved_mutant_fails_on_the_other(self):
        every = {"p": self.LINE}
        live = {"p": [self.LINE[0]]}
        gone = {"p": [self.LINE[2]]}  # NOT COVERED: what the proof is for
        for waived in ({("broker/p/a.go", 4, "CONDITIONALS_BOUNDARY", None): "the < 0 is killed by hand"},  # a record entry
                       {("broker/p/a.go", 4, None, None): "the < 0 is killed by hand"}):                     # a body line
            with self.subTest(waived):
                # #5774's gate passed this: the entry waived the live `>= 12` mutant with the proof for `< 0`.
                self.assertEqual(mutgate.violations(self.TARGETS, live, waived, every),
                                 [("p", "broker/p/a.go", 4, "CONDITIONALS_BOUNDARY", 16)])
                # It names three mutants, so it waives none, the one it proves included.
                self.assertEqual(mutgate.violations(self.TARGETS, gone, waived, every),
                                 [("p", "broker/p/a.go", 4, "CONDITIONALS_BOUNDARY", 113)])
                cover, ambiguous = mutgate.covering(waived, every)
                self.assertEqual(cover, {})
                self.assertEqual(len(ambiguous[0][1]), 3 if list(waived)[0][2] else 4)
        # Named by its column and kind, it waives that mutant alone: the live one still fails.
        exact = {("broker/p/a.go", 4, "CONDITIONALS_BOUNDARY", 113): "the < 0 is killed by hand"}
        self.assertEqual(mutgate.violations(self.TARGETS, gone, exact, every), [])
        self.assertEqual(mutgate.violations(self.TARGETS, live, exact, every),
                         [("p", "broker/p/a.go", 4, "CONDITIONALS_BOUNDARY", 16)])
        # A column alone still matches both kinds there, so a body line needs the kind too.
        self.assertEqual(mutgate.violations(self.TARGETS, gone, {("broker/p/a.go", 4, None, 113): "r"}, every),
                         [("p", "broker/p/a.go", 4, "CONDITIONALS_BOUNDARY", 113)])
        self.assertEqual(mutgate.violations(self.TARGETS, gone, {("broker/p/a.go", 4, "CONDITIONALS_BOUNDARY", 113): "r"},
                                            every), [])
        # A waiver whose line holds one mutant of its scope needs no column, as before.
        one = {"p": [("a.go", 4, "STATEMENT_DELETION", 2), ("a.go", 4, "CONDITIONALS_NEGATION", 9)]}
        self.assertEqual(mutgate.violations(self.TARGETS, one, {("broker/p/a.go", 4, "STATEMENT_DELETION", None): "r"}, one),
                         [("p", "broker/p/a.go", 4, "CONDITIONALS_NEGATION", 9)])
        # A killed sibling still counts: the proof cannot say which one it is for, and a later run may not kill it.
        self.assertEqual(mutgate.violations(self.TARGETS, {"p": [self.LINE[3]]},
                                            {("broker/p/a.go", 4, None, None): "r"}, every),
                         [("p", "broker/p/a.go", 4, "CONDITIONALS_NEGATION", 113)])

    def test_the_body_line_names_a_column_and_kind(self):
        self.assertEqual(mutgate.waivers("Mutant-equivalent: broker/p/a.go:4:113:CONDITIONALS_BOUNDARY the < 0 is dead\n"
                                         "Mutant-equivalent: broker/p/a.go:5:9 a column only\n"
                                         "Mutant-equivalent: broker/p/a.go:6:STATEMENT_DELETION a kind only\n"
                                         "Mutant-equivalent: broker/p/a.go:7:0 column zero\n"
                                         "Mutant-equivalent: broker/p/a.go:8:9:lower a lower-case kind\n"
                                         "Mutant-equivalent: broker/p/a.go:9:9:X:Y two kinds\n"),
                         {("broker/p/a.go", 4, "CONDITIONALS_BOUNDARY", 113): "the < 0 is dead",
                          ("broker/p/a.go", 5, None, 9): "a column only",
                          ("broker/p/a.go", 6, "STATEMENT_DELETION", None): "a kind only"})
        self.assertEqual(mutgate.site_text(("broker/p/a.go", 4, "CONDITIONALS_BOUNDARY", 113)),
                         "broker/p/a.go:4:113:CONDITIONALS_BOUNDARY")

    def test_verify_waives_only_the_named_mutant(self):
        v = Verify()
        src = "package netguard\nvar a = 1 + 1 + 1\n"
        muts = [{"type": "ARITHMETIC_BASE", "status": "LIVED", "line": 2, "column": c} for c in (11, 15)]
        result = {"files": [{"file_name": "a.go", "mutations": muts}], "mutants_lived": 2, "statement_deletions": 0}
        reason = "a is never read, so no value tells the mutants apart"
        r = v.verify({"netguard.json": result}, src=src, body=f"Mutant-equivalent: broker/netguard/a.go:2 {reason}\n",
                     summary=True)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("the waiver broker/netguard/a.go:2:ARITHMETIC_BASE matches 2 mutants (broker/netguard/a.go:2:11:ARITHMETIC_BASE, "
                      "broker/netguard/a.go:2:15:ARITHMETIC_BASE), so it waives none", r.stdout)
        self.assertIn("Waivers matching more than one mutant", r.summary)
        self.assertNotIn("equivalent:", r.summary)
        r = v.verify({"netguard.json": result}, src=src, body=f"Mutant-equivalent: broker/netguard/a.go:2:15 {reason}\n",
                     summary=True)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("broker/netguard/a.go:2 ARITHMETIC_BASE survives", r.stdout)
        rows = [l for l in r.summary.split("\n") if l.startswith("| broker/")]
        self.assertEqual(rows, ["| broker/netguard/a.go:2:11 | ARITHMETIC\\_BASE | **LIVED**: no test fails |",
                                f"| broker/netguard/a.go:2:15 | ARITHMETIC\\_BASE | equivalent: {reason} (record, \\#1, new in this PR) |"])
        body = "".join(f"Mutant-equivalent: broker/netguard/a.go:2:{c}:ARITHMETIC_BASE {reason}\n" for c in (11, 15))
        r = v.verify({"netguard.json": result}, src=src, body=body)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)

    def test_a_record_entry_with_a_column_waives_that_mutant_only(self):
        rec = Record()
        head = rec.VAR + "var b = 2 + 2 + 2\n"
        muts = [{"type": "ARITHMETIC_BASE", "status": "LIVED", "line": 4, "column": c} for c in (11, 15)]
        result = {"files": [{"file_name": "a.go", "mutations": muts}], "mutants_lived": 2, "statement_deletions": 0}

        def verify(d, run):
            res = pathlib.Path(d) / "res" / "mutants-0"
            res.mkdir(parents=True, exist_ok=True)
            (res / "netguard.json").write_text(json.dumps(result))
            return run("verify", str(res.parent), "--git", "HEAD~1", "--summary", str(pathlib.Path(d) / "summary.md"))

        with tempfile.TemporaryDirectory() as d:
            run = rec.repo(d, rec.VAR, head)
            w = pathlib.Path(d) / "w.txt"
            # waive refuses a column past its line's end, and a kind other than --mutant's.
            w.write_text("Mutant-equivalent: broker/netguard/a.go:4:99:ARITHMETIC_BASE b is never read\n")
            r = run("waive", str(w), "--accepted", "#5792")
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("no such line: broker/netguard/a.go:4:99", r.stderr)
            w.write_text("Mutant-equivalent: broker/netguard/a.go:4:15:ARITHMETIC_BASE b is never read\n")
            r = run("waive", str(w), "--accepted", "#5792", "--mutant", "STATEMENT_DELETION")
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("names another mutant kind than --mutant", r.stderr)
            self.assertFalse((pathlib.Path(d) / "broker" / "netguard" / mutgate.RECORD).exists())
            r = run("waive", str(w), "--accepted", "#5792")
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            entry = json.loads((pathlib.Path(d) / "broker" / "netguard" / mutgate.RECORD).read_text().split("\n")[1])
            self.assertEqual((entry["mutant"], entry["col"]), ("ARITHMETIC_BASE", 15))
            r = run("records", "netguard")
            self.assertEqual((r.returncode, r.stdout.split(" ")[:2]), (0, ["broker/netguard/a.go:4:15", "ARITHMETIC_BASE"]))
            r = verify(d, run)
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("broker/netguard/a.go:4 ARITHMETIC_BASE survives", r.stdout)
            summary = (pathlib.Path(d) / "summary.md").read_text()
            self.assertIn("| broker/netguard/a.go:4:15 | ARITHMETIC\\_BASE | equivalent: b is never read", summary)
            self.assertIn("| broker/netguard/a.go:4:11 | ARITHMETIC\\_BASE | **LIVED**", summary)
            self.assertIn("- broker/netguard/a.go:4:15 ARITHMETIC\\_BASE (\\#5792): b is never read", summary)
        # The same entry with no column names two mutants, so it waives neither.
        del entry["col"]
        with tempfile.TemporaryDirectory() as d:
            run = rec.repo(d, rec.VAR, head, record=json.dumps(entry) + "\n")
            r = verify(d, run)
            self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
            self.assertIn("broker/netguard/a.go:4 ARITHMETIC_BASE survives", r.stdout)
            self.assertIn("the waiver broker/netguard/a.go:4:ARITHMETIC_BASE matches 2 mutants", r.stdout)

    def test_a_record_column_is_a_positive_integer(self):
        good = {"file": "a.go", "mutant": "ARITHMETIC_BASE", "func": "b", "decl": "0" * 64, "stmt": ["var b = 2"], "at": 0,
                "after": "", "occurrence": [1, 1], "reason": "b is never read", "accepted": "#5792"}
        self.assertEqual(mutgate.record_entries(json.dumps({**good, "col": 9}))[0][0]["col"], 9)
        for bad in ({**good, "col": 0}, {**good, "col": "9"}, {**good, "col": True}, {**good, "col": 9, "x": 1}):
            with self.subTest(bad):
                self.assertIsNone(mutgate.record_entries(json.dumps(bad))[0])

    def test_a_record_entry_repeated_word_for_word_is_one_entry(self):
        # #6358: two PRs merged one proof; the union kept it twice, and mutgate read one site twice.
        good = {"file": "a.go", "mutant": "STATEMENT_DELETION", "func": "b", "decl": "0" * 64, "stmt": ["b()"], "at": 0,
                "after": "", "occurrence": [1, 1], "reason": "b does nothing", "accepted": "#6358"}
        keys = {"a.go": {4: mutgate._entry_key(good)}}
        line = json.dumps(good)
        entries, problem = mutgate.record_entries("# c\n" + line + "\n# c\n" + line + "\n")
        self.assertEqual((entries, problem), ([good], None))
        self.assertEqual(mutgate.resolve_record("k", entries, keys), ({("broker/k/a.go", 4, "STATEMENT_DELETION", None): good}, []))
        other = {**good, "reason": "b is never called"}  # one mutant, another proof: still fails, both printed
        entries, _ = mutgate.record_entries(line + "\n" + json.dumps(other) + "\n")
        found, problems = mutgate.resolve_record("k", entries, keys)
        self.assertEqual(len(problems), 1)
        self.assertIn("names the same line, column and mutant as another entry; keep one of:", problems[0])
        self.assertIn("b does nothing", problems[0])
        self.assertIn("b is never called", problems[0])
        self.assertEqual(len(mutgate.record_entries(line + "\n" + line.replace(", ", ",  ", 1) + "\n")[0]), 2,
                         "only a word-for-word repeat is one entry")
        # #6375: a CRLF repeat would read as a second entry of one mutant; any carriage return fails the record.
        for text in (line + "\n" + line + "\r\n", line + "\r\n" + line + "\n", "# c\r\n" + line + "\n"):
            self.assertEqual(mutgate.record_entries(text)[0], None, text)
        self.assertEqual(mutgate.record_entries(line + "\r\n")[1], "line 1 holds a carriage return; a record's lines end in LF only")

    def test_the_clerk_run_entries_on_two_comparison_lines_name_their_column(self):
        # #5792's follow-up pinned the #5774 entries on mail.go:104 and :145; #5909 deleted those (gremlins now
        # runs and kills their mutants), so the rule is pinned on every record: a comparison entry on a line
        # holding several comparisons names its column.
        r = subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "mutgate.py"), "records"],
                           capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(r.returncode, 0, r.stderr)
        for row in r.stdout.strip().split("\n"):
            site, kind = row.split(" ")[:2]
            path, line, *col = site.split(":")
            text = (ROOT / path).read_text().split("\n")[int(line) - 1]
            if kind.startswith("CONDITIONALS_") and len(re.findall(r"[<>!=]=|[<>]", text)) > 1:
                self.assertTrue(col, row)
        self.assertNotIn("broker/clerk/run/mail.go:104", r.stdout)
        self.assertNotIn("broker/clerk/run/mail.go:145", r.stdout)


class WaiverMessages(unittest.TestCase):
    """MUT-waiver-messages (#5828, from #5824): a builder can write the right waiver line from the gate's own
    output, and a mistyped waiver line is named, never dropped without a word."""
    # REQ: MUT-waiver-messages
    SRC = "package netguard\nvar a = 1 + 1 + 1\n"
    REASON = "a is never read, so no value tells the mutants apart"

    @classmethod
    def result(cls, status):
        muts = [{"type": "ARITHMETIC_BASE", "status": status, "line": 2, "column": c} for c in (11, 15)]
        return {"files": [{"file_name": "a.go", "mutations": muts}], "mutants_lived": 2 * (status == "LIVED"),
                "statement_deletions": 0}

    def test_a_failure_names_its_mutant_by_column_and_kind(self):
        # Item 1: two survivors of one kind on one line printed the same text, so neither line could be pasted.
        r = Verify().verify({"netguard.json": self.result("LIVED")}, src=self.SRC)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        for col in (11, 15):
            self.assertIn(f"; its waiver line: Mutant-equivalent: broker/netguard/a.go:2:{col}:ARITHMETIC_BASE <reason>\n", r.stdout)
        r = Verify().verify({"netguard.json": self.result("NOT COVERED")}, src=self.SRC)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        for col in (11, 15):
            self.assertIn(f"; its waiver line: Mutant-uncovered: broker/netguard/a.go:2:{col}:ARITHMETIC_BASE <reason>\n", r.stdout)
        # The printed line, pasted with a reason, waives exactly that mutant.
        body = "".join(f"Mutant-equivalent: broker/netguard/a.go:2:{c}:ARITHMETIC_BASE {self.REASON}\n" for c in (11, 15))
        self.assertEqual(Verify().verify({"netguard.json": self.result("LIVED")}, src=self.SRC, body=body).returncode, 0)
        self.assertEqual(mutgate.violations({"p": {"broker/p/a.go": {4}}}, {"p": [("a.go", 4, "X", 7), ("a.go", 4, "X")]}),
                         [("p", "broker/p/a.go", 4, "X", 7), ("p", "broker/p/a.go", 4, "X", None)])

    def test_a_pr_body_waiver_has_no_effect(self):
        # PROC-review-no-mutgate-wait (#6379): the PR body can change after a review without changing the head,
        # so it waives nothing; a waiver counts only from the package record the head holds. This also ends
        # MUT-stale-body (#6077): no body is read, so none can be stale.
        # REQ: MUT-stale-body
        sha = "1adcc9bd" + "0" * 32
        lines = "".join(f"Mutant-equivalent: broker/netguard/a.go:2:{c}:ARITHMETIC_BASE {self.REASON}\n" for c in (11, 15))
        notice = "mutgate: the PR body's Mutant-equivalent and Mutant-uncovered lines waive nothing (#6379)"
        # --body-from is still accepted so an older workflow copy runs, and is ignored.
        for extra in ((), ("--body-from", sha)):
            with self.subTest(extra):
                r = Verify().verify({"netguard.json": self.result("LIVED")}, src=self.SRC, pr_body=lines, extra=extra)
                self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
                self.assertIn(notice, r.stdout)
                for c in (11, 15):
                    self.assertIn(f"its waiver line: Mutant-equivalent: broker/netguard/a.go:2:{c}:ARITHMETIC_BASE", r.stdout)
                self.assertNotIn("the body read is", r.stdout)
        # A line only malformed is named too; a body with no waiver line prints nothing about it.
        r = Verify().verify({"netguard.json": self.result("LIVED")}, src=self.SRC,
                            pr_body=f"- Mutant-equivalent: broker/netguard/a.go:2:11 {self.REASON}\n")
        self.assertIn(notice, r.stdout)
        r = Verify().verify({"netguard.json": self.result("KILLED")}, src=self.SRC, pr_body="Intro.\n")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertNotIn(notice, r.stdout)
        # The same lines recorded through waive pass; the body adds and takes away nothing.
        for pr_body in (None, "", lines):
            with self.subTest(pr_body=pr_body):
                r = Verify().verify({"netguard.json": self.result("LIVED")}, src=self.SRC, body=lines, pr_body=pr_body)
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        # A refused or misspelt body line on a killed mutant no longer fails the gate: the body is not a waiver.
        r = Verify().verify({"netguard.json": self.result("KILLED")}, src=self.SRC,
                            pr_body="Mutant-equivalent: broker/netguard/a.go:2:11:ARITHMETIC_BASE not equivalent, a real survivor\n")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        # Only a full commit sha is accepted for the ignored --body-from, as before.
        for bad in ("1adcc9bd", "HEAD", sha.upper(), sha + "0", "-x"):
            r = Verify().verify({"netguard.json": self.result("LIVED")}, src=self.SRC, extra=["--body-from=" + bad])
            self.assertEqual(r.returncode, 2, bad + r.stdout + r.stderr)

    def test_an_ambiguous_waiver_is_not_listed_as_naming_no_mutant(self):
        # Item 2: a waiver matching both mutants was listed as ambiguous and also as naming no surviving mutant.
        r = Verify().verify({"netguard.json": self.result("LIVED")}, src=self.SRC, summary=True,
                            body=f"Mutant-equivalent: broker/netguard/a.go:2 {self.REASON}\n")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("Waivers matching more than one mutant, which waive none of them (#5792):\n"
                      "- broker/netguard/a.go:2:ARITHMETIC\\_BASE: ", r.summary)
        self.assertNotIn("naming no surviving mutant", r.summary)

    def test_a_malformed_waiver_line_is_warned_about(self):
        # Item 3: these lines were dropped unread, or (an unknown kind) shown only as unused.
        bad = {"Mutant-equivalent: broker/netguard/a.go:2:0 column zero": "is not read as a waiver",
               "Mutant-equivalent: broker/netguard/a.go:2:11:arithmetic_base lower case": "is not read as a waiver",
               "mutant-equivalent: broker/netguard/a.go:2:11:ARITHMETIC_BASE lower-case prefix": "is not read as a waiver",
               "  Mutant-uncovered: broker/netguard/a.go:2:11 indented": "is not read as a waiver",
               "Mutant-equivalent: broker/netguard/a.go:2:11 ?": "is not read as a waiver",
               "Mutant-equivalent: broker/netguard/a.go 2 no line": "is not read as a waiver",
               # L3 on #5976: behind the Markdown a PR body wraps lines in, the line was dropped unread and unwarned.
               f"`Mutant-equivalent: broker/netguard/a.go:2:11:ARITHMETIC_BASE {self.REASON}`": "is not read as a waiver",
               f"- Mutant-equivalent: broker/netguard/a.go:2:11:ARITHMETIC_BASE {self.REASON}": "is not read as a waiver",
               f"* `Mutant-uncovered: broker/netguard/a.go:2:11 {self.REASON}`": "is not read as a waiver",
               f"+ Mutant-equivalent: broker/netguard/a.go:2:11 {self.REASON}": "is not read as a waiver",
               f"> Mutant-equivalent: broker/netguard/a.go:2:11 {self.REASON}": "is not read as a waiver",
               f">> 12. Mutant-equivalent: broker/netguard/a.go:2:11 {self.REASON}": "is not read as a waiver",
               f"3) Mutant-equivalent: broker/netguard/a.go:2:11 {self.REASON}": "is not read as a waiver",
               "Mutant-equivalent: broker/netguard/a.go:2:11:ARITHMETIC_BASE <reason>": "still holds the <reason> placeholder",
               "Mutant-equivalent: broker/netguard/a.go:2:11 `<Reason>`": "still holds the <reason> placeholder",
               "Mutant-equivalent: broker/netguard/a.go:2:11 <reason> here.": "still holds the <reason> placeholder",
               # L3 round 2 on #5976: any Markdown before the waiver, not a listed few.
               f"- [ ] Mutant-equivalent: broker/netguard/a.go:2:11 {self.REASON}": "is not read as a waiver",
               f"- [x] Mutant-equivalent: broker/netguard/a.go:2:11 {self.REASON}": "is not read as a waiver",
               f"**Mutant-equivalent: broker/netguard/a.go:2:11 {self.REASON}**": "is not read as a waiver",
               f"## Mutant-equivalent: broker/netguard/a.go:2:11 {self.REASON}": "is not read as a waiver",
               f"| Mutant-equivalent: broker/netguard/a.go:2:11 {self.REASON} |": "is not read as a waiver",
               "Mutant-equivalent: broker/netguard/a.go:2:11:BOGUS a kind no mutant has":
                   "the waiver broker/netguard/a.go:2:11:BOGUS names the kind BOGUS, which no mutant has"}
        good = [f"Mutant-equivalent: broker/netguard/a.go:2:15:ARITHMETIC_BASE {self.REASON}",
                f"Mutant-uncovered: broker/netguard/a.go:3:STATEMENT_DELETION {self.REASON}",
                "A Mutant-equivalent: line quoted mid-sentence is no waiver line.",
                "- the syntax is `Mutant-equivalent: <path>:<line>` in a bullet of prose",
                f"Mutant-equivalent: broker/netguard/a.go:4 the reason names reason among other words"]
        got = mutgate.malformed_waivers("\r\n".join([*bad, *good]))
        self.assertEqual(len(got), len(bad), got)
        for (line, want), warning in zip(bad.items(), got):
            with self.subTest(line):
                self.assertIn(want, warning)
        # waive prints each warning, and the mutant the bad line meant to waive still fails the gate (fail closed).
        r = Verify().verify({"netguard.json": self.result("LIVED")}, src=self.SRC, body="\n".join([*bad, good[0]]) + "\n")
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertEqual(r.waive.stderr.count("mutgate: the line "), len(bad) - 4, r.waive.stderr)
        self.assertEqual(r.waive.stderr.count("still holds the <reason> placeholder, so it waives nothing"), 3, r.waive.stderr)
        # A reason holding the placeholder waives nothing, as the warning says.
        self.assertEqual(mutgate.waivers("\n".join(good)), {("broker/netguard/a.go", 2, "ARITHMETIC_BASE", 15): self.REASON,
                         ("broker/netguard/a.go", 3, "STATEMENT_DELETION", None): self.REASON,
                         ("broker/netguard/a.go", 4, None, None): "the reason names reason among other words"})
        self.assertIn("names the kind BOGUS, which no mutant has, so it waives nothing", r.waive.stderr)
        self.assertIn("broker/netguard/a.go:2 ARITHMETIC_BASE survives", r.stdout)
        self.assertNotIn("a.go:2:15:ARITHMETIC_BASE <reason>", r.stdout)
        # KINDS is gremlins v0.6.0's list, so it moves with the version the workflow installs.
        self.assertIn("gremlins/cmd/gremlins@v0.6.0", WORKFLOW.read_text())
        self.assertIn(mutgate.DELETION, mutgate.KINDS)

    def test_the_workflow_header_gives_the_waiver_source(self):
        # Item 4, then #6379: the header names the one waiver source, the package record, and that the body waives nothing.
        head = " ".join(l.lstrip("# ") for l in WORKFLOW.read_text().split("\n")[:12])
        self.assertIn("MUTANTS-EQUIVALENT record", head)
        self.assertIn("the PR body waives nothing", head)
        self.assertNotIn("<path>:<line> <reason>", head)


class CaseClauseCover(unittest.TestCase):
    """MUT-case-clause-cover (#5822): Go's cover blocks hold no `case` expression, so gremlins read every
    mutant in one as NOT COVERED and never ran it. The profile gremlins and covered_by read gains a ran
    block for each clause expression the counts show evaluated, and gremlins then runs its mutants."""
    # REQ: MUT-case-clause-cover

    SRC = ("package p\n\nfunc G(x, y int) int {\n\tswitch {\n\tcase x > 0 && y > 0:\n\t\treturn 1\n\tcase x < 0:\n"
           "\t\treturn 2\n\tcase y == 7:\n\t}\n\treturn 0\n}\n\nfunc S(c chan int) int {\n\tselect {\n\tcase v := <-c:\n"
           "\t\treturn v\n\tdefault:\n\t\treturn -1\n\t}\n}\n")
    TEST = ("package p\n\nimport \"testing\"\n\nfunc TestFirst(t *testing.T) {\n\tif G(1, 1) != 1 {\n\t\tt.Fatal()\n\t}\n}\n\n"
            "func TestNone(t *testing.T) {\n\tif G(0, 0) != 0 {\n\t\tt.Fatal()\n\t}\n}\n\n"
            "func TestSelect(t *testing.T) {\n\tif S(nil) != -1 {\n\t\tt.Fatal()\n\t}\n}\n")
    # The three case expressions of G (lines 5, 7, 9) and S's one (line 16), each to just past its colon.
    FIRST, SECOND, THIRD, COMM = ((5, 2), (5, 22)), ((7, 2), (7, 13)), ((9, 2), (9, 14)), ((16, 2), (16, 16))

    # L3's repro on #5902: F(9) matches nothing, but the fallthrough's entry into `x == 2`'s body makes
    # the bodies' entries (1, 1, 0) add up to the switch's two runs, as if every run had matched.
    FALL_SRC = ("package p\n\nfunc F(x int) int {\n\tr := 0\n\tswitch {\n\tcase x == 1:\n\t\tr += 1\n\t\tfallthrough\n"
                "\tcase x == 2:\n\t\tr += 2\n\tcase x == 3:\n\t\tr += 3\n\t}\n\treturn r\n}\n")
    FALL_TEST = ("package p\n\nimport \"testing\"\n\nfunc TestFall(t *testing.T) {\n\tif F(1) != 3 {\n\t\tt.Fatal()\n\t}\n"
                 "\tF(9)\n}\n")

    def package(self, d, src=None, test=None):
        broker = pathlib.Path(d) / "broker"
        (broker / "p").mkdir(parents=True)
        (broker / "go.mod").write_text(GO_MOD)
        (broker / "p" / "a.go").write_text(src or self.SRC)
        (broker / "p" / "a_test.go").write_text(test or self.TEST)
        return broker

    def test_the_lister_names_each_clause(self):
        with tempfile.TemporaryDirectory() as d:
            broker = self.package(d)
            got = json.loads(subprocess.run([str(mutgate.build_lister(d)), "-cases", str(broker / "p" / "a.go")],
                                            capture_output=True, text=True, check=True).stdout)
        self.assertEqual([(s["line"], s["col"], s["select"], len(s["clauses"])) for s in got], [(4, 2, False, 3), (15, 2, True, 2)])
        self.assertEqual(got[0]["clauses"][2], {"line": 9, "col": 2, "colon_line": 9, "colon_col": 13,
                                                 "end_line": 10, "end_col": 2, "default": False})
        self.assertTrue(got[1]["clauses"][1]["default"])

    def blocks(self, *tests, src=None, test=None):
        """with_cases' added blocks for a.go, after a `-covermode=count` run of tests."""
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"GOFLAGS": "", "GOWORK": "off"}):
            broker, profile = self.package(d, src, test), pathlib.Path(d) / "c.out"
            subprocess.run(["go", "test", "-count=1", "-covermode=count", f"-coverprofile={profile}", "-run",
                            "^(" + "|".join(tests) + ")$", "."], cwd=broker / "p", check=True, capture_output=True)
            text = profile.read_text()
            got = mutgate.with_cases(text, mutgate.build_lister(d), broker / "p")
        self.assertTrue(got.startswith(text.rstrip("\n")))
        return {((int(m[0]), int(m[1])), (int(m[2]), int(m[3]))) for m in
                re.findall(r"^example\.invalid/broker/p/a\.go:(\d+)\.(\d+),(\d+)\.(\d+) 0 1$", got[len(text.rstrip()):], re.M)}

    def test_a_matched_clause_is_evaluated_and_the_ones_after_it_are_not(self):
        self.assertEqual(self.blocks("TestFirst"), {self.FIRST})

    def test_a_run_that_matches_no_clause_evaluates_every_one(self):
        # No body ran, yet the switch ran more often than its bodies were entered.
        self.assertEqual(self.blocks("TestNone"), {self.FIRST, self.SECOND, self.THIRD})

    def test_a_switch_holding_a_fallthrough_evaluates_every_clause_once_it_ran(self):
        # Without the fallthrough rule `x == 3` (line 11) read NOT COVERED, and its negation lives.
        self.assertEqual(self.blocks("TestFall", src=self.FALL_SRC, test=self.FALL_TEST),
                         {((6, 2), (6, 14)), ((9, 2), (9, 14)), ((11, 2), (11, 14))})

    def test_the_lister_marks_a_switch_that_falls_through(self):
        with tempfile.TemporaryDirectory() as d:
            broker = self.package(d, self.FALL_SRC)
            lister = mutgate.build_lister(d)
            fall = json.loads(subprocess.run([str(lister), "-cases", str(broker / "p" / "a.go")],
                                             capture_output=True, text=True, check=True).stdout)
            (broker / "p" / "a.go").write_text(self.SRC)
            plain = json.loads(subprocess.run([str(lister), "-cases", str(broker / "p" / "a.go")],
                                              capture_output=True, text=True, check=True).stdout)
        self.assertEqual([sw["fallthrough"] for sw in fall], [True])
        self.assertEqual([sw["fallthrough"] for sw in plain], [False, False])

    # Security's repro on #5902: the clause's last statement is a goto; its labeled `fallthrough` still
    # enters `x == 2`'s body without a match.
    GOTO_SRC = FALL_SRC.replace("\t\tr += 1\n\t\tfallthrough\n", "\t\tr += 1\n\t\tgoto L\n\tL:\n\t\tfallthrough\n")

    def test_a_labeled_fallthrough_reached_by_goto_marks_the_switch(self):
        self.assertIn("goto L", self.GOTO_SRC)
        # `x == 3` moves to line 13 with the two added lines.
        self.assertEqual(self.blocks("TestFall", src=self.GOTO_SRC, test=self.FALL_TEST),
                         {((6, 2), (6, 14)), ((11, 2), (11, 14)), ((13, 2), (13, 14))})

    def test_a_select_evaluates_every_clause_on_entry(self):
        self.assertEqual(self.blocks("TestSelect"), {self.COMM})

    def test_clause_rules(self):
        def sw(*clauses, select=False, falls=False):
            return {"file": "a.go", "line": 1, "col": 2, "select": select, "fallthrough": falls,
                    "clauses": [{"line": 2 * i + 2, "col": 2, "colon_line": 2 * i + 2, "colon_col": 9,
                                 "end_line": 2 * i + 4, "end_col": 2, "default": dflt} for i, dflt in enumerate(clauses)]}
        header = (1, 1, 2, 2)

        def run(s, runs, entered):
            bs = {header: runs, **{(2 * i + 2, 10, 2 * i + 3, 9): n for i, n in enumerate(entered)}}
            return [at[0] for _, at, _ in mutgate.evaluated_clauses([s], {"a.go": bs})]
        self.assertEqual(run(sw(False, False, False), 0, [0, 0, 0]), [])         # never ran
        self.assertEqual(run(sw(False, False, False), 2, [0, 2, 0]), [2, 4])     # the second always matched
        self.assertEqual(run(sw(False, False, False), 3, [0, 2, 0]), [2, 4, 6])  # once none matched
        self.assertEqual(run(sw(False, True, False), 1, [0, 1, 0]), [2, 6])      # the default (mid-source) ran
        self.assertEqual(run(sw(False, False, True), 4, [4, 0, 0]), [2])         # the first always matched
        self.assertEqual(run(sw(False, False, select=True), 1, [0, 0]), [2, 4])  # a select, entered
        self.assertEqual(run(sw(False, False, select=True), 0, [0, 0]), [])
        self.assertEqual(run(sw(False, False, False, falls=True), 2, [1, 1, 0]), [2, 4, 6])  # #5902's repro
        self.assertEqual(run(sw(False, False, True, falls=True), 0, [0, 0, 0]), [])

    def test_covered_by_counts_an_evaluated_case_line(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"GOFLAGS": "", "GOWORK": "off"}):
            broker = self.package(d)
            first, problem = mutgate.covered_by("p", ["TestFirst"], d, broker)
            self.assertIsNone(problem)
            none, problem = mutgate.covered_by("p", ["TestNone"], d, broker)
        self.assertEqual(first, {"broker/p/a.go": {3, 4, 5, 6}})
        self.assertEqual(none, {"broker/p/a.go": {3, 4, 5, 7, 9, 11}})

    def test_a_file_the_lister_refuses_fails_the_run(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"GOFLAGS": "", "GOWORK": "off"}):
            broker = self.package(d)
            (broker / "p" / "a.go").write_text(self.SRC.replace("func S", "//line x.go:1\nfunc S"))
            got, problem = mutgate.covered_by("p", ["TestFirst"], d, broker)
        self.assertIsNone(got)
        self.assertIn("//line directive", problem)

    def test_gremlins_go_rewrites_only_its_cover_run(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"GOFLAGS": "", "GOWORK": "off"}):
            broker = self.package(d)
            shim = mutgate.go_shim(d) / "go"
            r = subprocess.run([str(shim), "env", "GOWORK"], capture_output=True, text=True)
            self.assertEqual((r.returncode, r.stdout.strip()), (0, "off"))  # every other call: the real go
            self.assertFalse((pathlib.Path(d) / "stmts").exists())
            # Gremlins' own form (internal/coverage, v0.6.0): `-cover -coverprofile FILE ./...`, mode unnamed.
            out = pathlib.Path(d) / "coverage"
            r = subprocess.run([str(shim), "test", "-cover", "-coverprofile", str(out), "-run", "^TestNone$", "./..."],
                               cwd=broker / "p", capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            text = out.read_text()
        self.assertTrue(text.startswith("mode: count\n"), text[:40])
        self.assertIn("example.invalid/broker/p/a.go:7.2,7.13 0 1\n", text)

    def test_run_puts_the_shim_first_on_gremlins_path(self):
        # The wiring the end-to-end test below cannot show where gremlins is absent (Potency on #5902):
        # the `go` the gremlins that `run` starts finds is the shim, and the shim reaches the real go.
        with tempfile.TemporaryDirectory() as d:
            stub = pathlib.Path(d) / "bin"
            stub.mkdir()
            (stub / "gremlins").write_text(
                "#!/bin/sh\ncommand -v go > \"%s/seen\"\ngo env GOROOT >> \"%s/seen\"\n"
                "while [ \"$1\" != -o ]; do shift; done\nprintf '%%s' '{\"files\": [], \"mutants_lived\": 0}' > \"$2\"\n" % (d, d))
            (stub / "gremlins").chmod(0o755)
            real = shutil.which("go")
            env = {"PATH": f"{stub}:/usr/bin:/bin:{os.path.dirname(real)}", "HOME": os.environ.get("HOME", d)}
            r = subprocess.run([sys.executable, str(ROOT / "tools" / "mutgate.py"), "run", "hint", "--out",
                                str(pathlib.Path(d) / "out")], capture_output=True, text=True, env=env)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            found, goroot = (pathlib.Path(d) / "seen").read_text().split("\n")[:2]
        self.assertTrue(found.endswith("/gobin/go"), found)
        self.assertNotEqual(found, real)
        self.assertTrue(goroot, "the shim did not reach the real go")

    def test_gremlins_go_passes_a_failing_test_run_on(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"GOFLAGS": "", "GOWORK": "off"}):
            broker = self.package(d)
            (broker / "p" / "a_test.go").write_text(self.TEST.replace("G(1, 1) != 1", "G(1, 1) != 2"))
            r = subprocess.run([str(mutgate.go_shim(d) / "go"), "test", "-cover", "-coverprofile", str(pathlib.Path(d) / "c"), "."],
                               cwd=broker / "p", capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)

    @unittest.skipUnless(shutil.which("gremlins"), "gremlins v0.6.0 is not installed")
    def test_gremlins_runs_a_case_expression_mutant(self):
        # #5822's shape: before, every mutant on lines 5, 7 and 9 was NOT COVERED.
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"GOFLAGS": "", "GOWORK": "off"}):
            broker = self.package(d)
            (pathlib.Path(d) / "cfg.yaml").write_text("{}\n")
            out = pathlib.Path(d) / "out.json"
            env = {**os.environ, "PATH": f"{mutgate.go_shim(d)}{os.pathsep}{os.environ['PATH']}"}
            r = subprocess.run(["gremlins", "unleash", "--config", str(pathlib.Path(d) / "cfg.yaml"), "-o", str(out), str(broker / "p")],
                           cwd=broker / "p", env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            got = {(m["line"], m["status"]) for f in json.loads(out.read_text())["files"] for m in f["mutations"]}
        # `y == 7` negated lives (no test calls G with y == 7 and x == 0): a survivor NOT COVERED hid.
        self.assertTrue({(5, "KILLED"), (7, "KILLED"), (9, "LIVED")} <= got, got)
        self.assertFalse({s for line, s in got if line in (5, 7, 9)} & {"NOT COVERED"}, got)


@unittest.skipUnless(os.path.isdir("/proc/self"), "the memory cap reads /proc")
class GremlinsMemoryCap(unittest.TestCase):
    """MUT-gremlins-memcap (#6388): a gremlins mutant grew a test past 13 GB and took the runner down on
    #6000. Each mutant's `go test` runs under a memory cap through the shim, and a run past it exits 1,
    which gremlins reads as KILLED; that counts only where the unmutated tests stay under half the cap."""
    # REQ: MUT-gremlins-memcap, MUT-gremlins-memcap-go

    GROW = "import time; b = bytearray(96 << 20); time.sleep(60)"
    # As `go test -exec X` runs a test binary: `eval "$x BINARY"` in a body runs it through X.
    EXEC = 'x=; for a; do case "$a" in -exec=*) x="${a#-exec=}";; esac; done\n'

    def fake_go(self, d, body):
        """A directory holding a `go` that runs body (a sh script) in place of the real go."""
        bindir = pathlib.Path(d) / "fakego"
        bindir.mkdir(exist_ok=True)
        (bindir / "go").write_text("#!/bin/sh\n" + self.EXEC + body)
        (bindir / "go").chmod(0o755)
        return bindir

    def shim(self, d, body, mem):
        (pathlib.Path(d) / mutgate.REFUSED).touch()  # as `run` makes it before gremlins starts
        with mock.patch.dict(os.environ, {"PATH": f"{self.fake_go(d, body)}{os.pathsep}{os.environ['PATH']}"}):
            return mutgate.go_shim(d, mem) / "go"

    def test_a_mutant_run_past_its_cap_is_killed_and_exits_1(self):
        with tempfile.TemporaryDirectory() as d:
            shim = self.shim(d, f"eval \"$x python3 -c '{self.GROW}'\"\n", 32 << 20)
            began = time.monotonic()
            r = subprocess.run([str(shim), "test", "-timeout", "62s", "-failfast", "./p"], capture_output=True, text=True)
            self.assertEqual(r.returncode, 1, r.stderr)  # gremlins v0.6.0: exit 1 is KILLED
            self.assertLess(time.monotonic() - began, 20)
            self.assertIn("--- FAIL: memory_cap", r.stderr)

    def test_a_mutant_run_under_its_cap_keeps_gos_exit_code(self):
        with tempfile.TemporaryDirectory() as d:
            for code in (0, 1, 2):
                shim = self.shim(d, f"eval \"$x python3 -c 'b = bytearray(1 << 20)'\"\nexit {code}\n", 1 << 30)
                self.assertEqual(subprocess.run([str(shim), "test", "./p"]).returncode, code)

    def test_a_mutant_runs_own_toolchain_is_not_counted(self):
        # L3 on #6389: a mutant's rebuild is the toolchain's memory; counted, a compile alone would read KILLED.
        with tempfile.TemporaryDirectory() as d:
            link = pathlib.Path(d) / "compile"
            link.symlink_to(sys.executable)
            shim = self.shim(d, f"{link} -c 'import time; b = bytearray(96 << 20); time.sleep(2)'\n"
                                f"eval \"$x python3 -c 'pass'\"\nexit 0\n", 32 << 20)
            r = subprocess.run([str(shim), "test", "-timeout", "62s", "-failfast", "./p"], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn("memory_cap", r.stderr)

    def test_no_cap_runs_the_real_go_directly(self):
        with tempfile.TemporaryDirectory() as d:
            shim = self.shim(d, "exit 0\n", None)
            self.assertNotIn("go-capped", shim.read_text())
            self.assertIn("go-capped", self.shim(d, "exit 0\n", 1 << 30).read_text())

    def test_a_cover_run_past_half_the_cap_fails(self):
        # The unmutated tests must leave a cap kill meaning a test failed (L3 on #5026), so gremlins'
        # own coverage run is measured under the same cap and fails the run past half of it.
        with tempfile.TemporaryDirectory() as d:
            prof = pathlib.Path(d) / "c"
            shim = self.shim(d, f"eval \"$x python3 -c 'import time; b = bytearray(64 << 20); time.sleep(1)'\"\n: > {prof}\n", 96 << 20)
            r = subprocess.run([str(shim), "test", "-cover", "-coverprofile", str(prof), "./..."], capture_output=True, text=True)
            self.assertEqual(r.returncode, 1, r.stderr)
            self.assertIn("more than half", r.stderr)

    def test_a_cover_run_counts_each_test_binarys_whole_life_peak(self):
        # #6392 item 2: each test binary of gremlins' coverage run goes through cap_exec (go test -exec),
        # which records its exact peak (memory.peak, or wait4 in an advisory run), so a spike just before
        # it exits counts against half the cap.
        with tempfile.TemporaryDirectory() as d:
            prof = pathlib.Path(d) / "c"
            shim = self.shim(d, f"eval \"$x python3 -c 'b = bytearray(128 << 20)'\" || exit 9\n: > {prof}\n", 192 << 20)
            r = subprocess.run([str(shim), "test", "-cover", "-coverprofile", str(prof), "./..."], capture_output=True, text=True)
            self.assertEqual(r.returncode, 1, r.stderr)
            self.assertIn("more than half", r.stderr)
            (top, end), = [row.split() for row in (pathlib.Path(d) / "exits").read_text().splitlines()]
            self.assertGreater(int(top), 128 << 20)
            self.assertEqual(end, "0")

    def test_a_go_test_that_cannot_be_capped_is_refused(self):
        # A run naming its own -exec would put its test binaries outside the cap: refused, and REFUSED
        # written, which fails `run` (a mutant run's exit 1 alone would read KILLED).
        with tempfile.TemporaryDirectory() as d:
            prof = pathlib.Path(d) / "c"
            shim = self.shim(d, "exit 0\n", 1 << 30)
            for args in (["test", "-exec=x", "-coverprofile", str(prof), "./..."], ["test", "-exec", "x", "./p"]):
                (pathlib.Path(d) / mutgate.REFUSED).write_text("")  # as `run` makes it
                r = subprocess.run([str(shim), *args], capture_output=True, text=True)
                self.assertEqual(r.returncode, 1)
                self.assertIn("cannot be put under", r.stderr)
                self.assertIn(args[-1], mutgate.refusal(d))
            self.assertEqual(subprocess.run([str(shim), "env", "GOWORK"]).returncode, 0)  # not `go test`: as is

    def test_a_mutant_runs_output_never_reaches_the_go_driver(self):
        # MUT-gremlins-memcap-go (#6507): `go test PKG` buffers the test binary's output in the driver, so a
        # mutant that loops printing grew the process named go past the cap (#5974). Gremlins discards a
        # mutant run's output, so cap_exec sends it to /dev/null; a coverage run's output still passes.
        with tempfile.TemporaryDirectory() as d:
            seen = pathlib.Path(d) / "seen"
            loud = "eval \"$x python3 -c 'print(\\\"x\\\" * 4096)'\" > " + str(seen) + " 2>&1\n"
            r = subprocess.run([str(self.shim(d, loud, 1 << 30)), "test", "./p"], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(seen.read_text(), "")
            prof = pathlib.Path(d) / "c"
            shim = self.shim(d, loud + f": > {prof}\n", 1 << 30)
            subprocess.run([str(shim), "test", "-coverprofile", str(prof), "./..."], capture_output=True)
            self.assertIn("x" * 4096, seen.read_text())

    def broken_cgroup(self, d):
        """A directory that passes cgroup_parent but is no cgroup: contained fails once its run ends."""
        cg = pathlib.Path(d) / "notcg"
        cg.mkdir()
        (cg / "cgroup.subtree_control").write_text("memory\n")
        return str(cg)

    def test_a_containment_error_in_a_mutant_run_is_no_verdict(self):
        # L3 and Security on #6423: an error inside cap_exec exited 1, which go test passes on and gremlins
        # reads as KILLED. It writes REFUSED instead, the only channel, on both cap_exec paths.
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {mutgate.CGROUP_ENV: self.broken_cgroup(d)}):
            refused = pathlib.Path(d) / mutgate.REFUSED
            refused.touch()  # as `run` makes it
            r = subprocess.run([str(self.shim(d, "eval \"$x true\"\n", 1 << 30)), "test", "./p"], capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 1, r.stderr)
            self.assertIn("no verdict", r.stderr)
            self.assertIn("cap_exec", refused.read_text())
            refused.write_text("")
            prof = pathlib.Path(d) / "c"
            shim = self.shim(d, f"eval \"$x true\" || exit 1\n: > {prof}\n", 1 << 30)
            r = subprocess.run([str(shim), "test", "-coverprofile", str(prof), "./..."], capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0, r.stderr)
            self.assertIn("cap_exec", refused.read_text())

    def test_run_drops_a_package_whose_mutant_run_was_refused(self):
        # The marker, not gremlins' scored KILLED, decides: `run` keeps no result for that package.
        with tempfile.TemporaryDirectory() as d:
            bindir = self.fake_go(d, "eval \"$x true\"\nexit 1\n")  # go test's own exit 1 for a failing -exec
            (bindir / "gremlins").write_text(
                f"#!/bin/sh\n{mutgate.CGROUP_ENV}={self.broken_cgroup(d)} go test -timeout 62s ./hint\n"
                "while [ \"$1\" != -o ]; do shift; done\n"
                "printf '%s' '{\"files\": [], \"mutants_total\": 0, \"mutants_killed\": 1, \"mutants_lived\": 0}' > \"$2\"\n")
            (bindir / "gremlins").chmod(0o755)
            out = pathlib.Path(d) / "out"
            err = io.StringIO()
            with mock.patch.dict(os.environ, {"PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}"}), \
                    mock.patch.object(mutgate, "available_memory", return_value=1 << 30), \
                    mock.patch.object(mutgate, "default_jobs", return_value=2), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                self.assertEqual(mutgate.main(["run", "hint", "--out", str(out)]), 1)
            self.assertFalse((out / mutgate.result_name("hint")).exists())
            self.assertIn("hint has no verdict", err.getvalue())

    def test_the_half_cap_refusal_names_page_cache_the_cap_and_the_peak(self):
        # #6512 (Lens on #6423): memory.peak counts page cache, so a refusal at a figure the tests never held
        # as heap says why, with both figures, in gremlins' coverage run and in delete's base run alike.
        why = mutgate.past_half(1017 << 20, 1820 << 20)
        for part in ("peaked at 1017 MB", "1820 MB memory cap", "memory.peak", "page cache", "without a leak"):
            self.assertIn(part, why)
        self.assertIn("where the cap killed them", mutgate.past_half(1820 << 20, 1820 << 20, over=True))
        with tempfile.TemporaryDirectory() as d:
            prof = pathlib.Path(d) / "c"
            shim = self.shim(d, f"eval \"$x python3 -c 'b = bytearray(64 << 20)'\"\n: > {prof}\n", 96 << 20)
            r = subprocess.run([str(shim), "test", "-cover", "-coverprofile", str(prof), "./..."], capture_output=True, text=True)
            self.assertEqual(r.returncode, 1, r.stderr)
            self.assertRegex(r.stderr, r"peaked at (6[4-9]|[7-9]\d) MB, more than half of their 96 MB memory cap")
            self.assertIn("page cache", r.stderr)

    def test_a_shim_fault_with_an_unwritable_marker_never_reads_killed(self):
        # #6512 (Security item 1 on #6423): a fault whose marker write failed exited 125, go test made that
        # its own exit 1, and gremlins read KILLED. The marker is opened before the entry runs, so a later
        # fault still writes it; where it cannot be opened the entry does not run, and `run` reads no verdict.
        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stderr(io.StringIO()):
            tmp = pathlib.Path(d) / "tmp"
            tmp.mkdir()
            (tmp / mutgate.REFUSED).touch()
            self.assertEqual(mutgate.refusal(tmp), "")

            def fault():  # nothing can be opened any more, then the cgroup fails
                mock.patch.object(mutgate, "open_marker", side_effect=PermissionError(13, "Permission denied")).start()
                raise RuntimeError("memory.events: No such file or directory")
            try:
                self.assertEqual(mutgate.shim_entry(tmp, fault), mutgate.NO_VERDICT)
            finally:
                mock.patch.stopall()
            self.assertIn("fault: RuntimeError('memory.events", mutgate.refusal(tmp))

            gone = pathlib.Path(d) / "nonexistent"  # a marker that cannot be opened: a fault is told by refusal
            self.assertEqual(mutgate.shim_entry(gone, fault), mutgate.NO_VERDICT)
            mock.patch.stopall()
            self.assertIn("cannot be written", mutgate.refusal(gone))
            self.assertEqual(mutgate.shim_entry(gone, int, "7"), 7)  # with no fault, the run's own result

            # Security on #6557: an open that fails before the entry runs, then a fault once it would pass,
            # still writes the marker, as the open at fault time before #6512 did.
            (tmp / mutgate.REFUSED).write_text("")
            real, calls = mutgate.open_marker, []

            def first_open_fails(tmp):
                calls.append(tmp)
                if len(calls) == 1:
                    raise OSError(24, "Too many open files")
                return real(tmp)

            def cap_exec():
                raise RuntimeError("cgroup write failed")
            with mock.patch.object(mutgate, "open_marker", side_effect=first_open_fails):
                self.assertEqual(mutgate.shim_entry(tmp, cap_exec), mutgate.NO_VERDICT)
            self.assertEqual(len(calls), 2)
            self.assertIn("cap_exec: RuntimeError('cgroup write failed')", mutgate.refusal(tmp))

            # L3 on #6557: a marker that opens but cannot be written (a full disk) is removed, so `run` sees it gone.
            (tmp / mutgate.REFUSED).write_text("")
            full = mock.Mock(**{"write.side_effect": OSError(28, "No space left on device")})
            with mock.patch.object(mutgate, "open_marker", return_value=full):
                self.assertEqual(mutgate.shim_entry(tmp, cap_exec), mutgate.NO_VERDICT)
            self.assertFalse((tmp / mutgate.REFUSED).exists())
            self.assertIn("cannot be written", mutgate.refusal(tmp))  # gone after run made it: no verdict
            # L3 round 3 on #6557: the next mutants, a clean one and a faulting one, never make it again.
            self.assertEqual(mutgate.shim_entry(tmp, int, "0"), 0)
            self.assertEqual(mutgate.shim_entry(tmp, cap_exec), mutgate.NO_VERDICT)
            self.assertFalse((tmp / mutgate.REFUSED).exists())
            self.assertIn("cannot be written", mutgate.refusal(tmp))

            # Security on #6557: capped_go's own refusal, written to a full disk, removes the marker too.
            (tmp / mutgate.REFUSED).write_text("")
            with mock.patch.object(mutgate, "open_marker", return_value=full):
                self.assertIsNone(mutgate.capped_go("go", tmp, ["test", "-exec=x", "./p"], 1 << 30))
            self.assertIn("cannot be written", mutgate.refusal(tmp))

    def test_run_gives_no_verdict_when_its_marker_is_gone(self):
        # #6512: a shim that could not open the marker cannot say so, so `run` checks the channel it made.
        with tempfile.TemporaryDirectory() as d:
            bindir = self.fake_go(d, "exit 0\n")
            (bindir / "gremlins").write_text(
                "#!/bin/sh\nrm -f \"$(dirname \"$(command -v go)\")/../refused\"\n"
                "while [ \"$1\" != -o ]; do shift; done\n"
                "printf '%s' '{\"files\": [], \"mutants_total\": 0, \"mutants_killed\": 1, \"mutants_lived\": 0}' > \"$2\"\n")
            (bindir / "gremlins").chmod(0o755)
            out = pathlib.Path(d) / "out"
            err = io.StringIO()
            with mock.patch.dict(os.environ, {"PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}"}), \
                    mock.patch.object(mutgate, "available_memory", return_value=1 << 30), \
                    mock.patch.object(mutgate, "default_jobs", return_value=2), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
                self.assertEqual(mutgate.main(["run", "hint", "--out", str(out)]), 1)
            self.assertFalse((out / mutgate.result_name("hint")).exists())
            self.assertIn("hint has no verdict: its refused marker cannot be written", err.getvalue())

    def fake_leaf(self, events):
        """A stand-in for empty: its first call gives the leaf the files a cgroup's kernel would (memory.peak,
        memory.events with events), its second clears the leaf so contained can remove it."""
        calls = []

        def empty(cg):
            calls.append(cg)
            if len(calls) == 1:
                (cg / "memory.peak").write_text("4096\n")
                (cg / "memory.events").write_text(events)
            else:
                for f in cg.iterdir():
                    f.unlink()
        return empty

    def test_an_oom_kill_after_a_clean_exit_is_no_cap_kill(self):
        # #6512 (Security item 4 on #6423): memory.oom.group kills argv with its leaf, so an oom_kill once argv
        # has exited 0 hit only a child left behind after the tests passed; a run that did not exit 0 stays over.
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {mutgate.CGROUP_ENV: self.broken_cgroup(d)}):
            for code, want in ((0, 0), (1, "over")):
                with self.subTest(code=code), mock.patch.object(mutgate, "empty", self.fake_leaf("oom 1\noom_kill 1\n")):
                    self.assertEqual(mutgate.contained(["/bin/sh", "-c", f"exit {code}"], 1 << 30), (want, 4096))
                with self.subTest(code=code), mock.patch.object(mutgate, "empty", self.fake_leaf("oom_kill 0\n")):
                    self.assertEqual(mutgate.contained(["/bin/sh", "-c", f"exit {code}"], 1 << 30), (code, 4096))

    def test_a_cleanup_error_keeps_the_first_error_as_its_cause(self):
        # #6512 (Security item 4 on #6423): `finally: empty(leaf)` raised over the run's own error and hid it.
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {mutgate.CGROUP_ENV: self.broken_cgroup(d)}):
            first = RuntimeError("memory.max: Invalid argument")
            with mock.patch.object(mutgate, "in_leaf", side_effect=first), \
                    mock.patch.object(mutgate, "empty", side_effect=RuntimeError("outlived cgroup.kill")):
                with self.assertRaises(RuntimeError) as got:
                    mutgate.contained(["true"], 1 << 30)
            self.assertIn("outlived", str(got.exception))
            self.assertIs(got.exception.__cause__, first)

    def test_run_caps_gremlins_mutant_runs(self):
        # The wiring: `run` gives gremlins' shim each run's share of half the free memory.
        with tempfile.TemporaryDirectory() as d:
            seen = pathlib.Path(d) / "seen"
            bindir = self.fake_go(d, f"eval \"$x python3 -c '{self.GROW}'\"\n")
            (bindir / "gremlins").write_text(
                f"#!/bin/sh\ngo test -timeout 62s -failfast ./hint\necho $? > {seen}\n"
                "while [ \"$1\" != -o ]; do shift; done\nprintf '%s' '{\"files\": [], \"mutants_lived\": 0}' > \"$2\"\n")
            (bindir / "gremlins").chmod(0o755)
            with mock.patch.dict(os.environ, {"PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}"}), \
                    mock.patch.object(mutgate, "available_memory", return_value=128 << 20), \
                    mock.patch.object(mutgate, "default_jobs", return_value=2), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(mutgate.main(["run", "hint", "--out", str(pathlib.Path(d) / "out")]), 0)
            self.assertEqual(seen.read_text().strip(), "1")  # 96 MB past the 32 MB share: killed

    def fitted_run(self, d, grow, free, jobs, pkgs=("hint",)):
        """`run` over pkgs with a fake gremlins whose coverage run holds grow bytes: (exit, [--workers of
        each gremlins run]). The fake fails, as gremlins does, where the shim's coverage run fails."""
        seen, prof = pathlib.Path(d) / "seen", pathlib.Path(d) / "c"
        bindir = self.fake_go(d, f"eval \"$x python3 -c 'b = bytearray({grow}); import time; time.sleep(0.5)'\"\n: > {prof}\n")
        (bindir / "gremlins").write_text(
            "#!/bin/sh\nw=; o=; while [ $# -gt 0 ]; do case \"$1\" in --workers) w=$2;; -o) o=$2;; esac; shift; done\n"
            f"echo $w >> {seen}\n"
            f"go test -cover -coverprofile {prof} ./... 2>&1 | grep -q 'more than half' && exit 1\n"
            "printf '%s' '{\"files\": [], \"mutants_total\": 0, \"mutants_lived\": 0}' > \"$o\"\n")
        (bindir / "gremlins").chmod(0o755)
        with mock.patch.dict(os.environ, {"PATH": f"{bindir}{os.pathsep}{os.environ['PATH']}"}), \
                mock.patch.object(mutgate, "available_memory", return_value=free), \
                mock.patch.object(mutgate, "default_jobs", return_value=jobs), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = mutgate.main(["run", *pkgs, "--out", str(pathlib.Path(d) / "out")])
        return code, [int(w) for w in seen.read_text().split()]

    def test_tests_past_half_a_share_run_again_on_fewer_workers(self):
        # #6396: egress's tests held 1017 MB of a 1820 MB share, so every run of it failed by name. The
        # parallel share gives way, not the half-cap check: 4 workers of 64 MB, then shares that fit.
        with tempfile.TemporaryDirectory() as d:
            code, workers = self.fitted_run(d, 48 << 20, 512 << 20, 4)
            self.assertEqual(code, 0)
            self.assertEqual(workers[0], 4)
            self.assertEqual(len(workers), 2, workers)
            self.assertIn(workers[1], (1, 2))

    def test_tests_past_half_of_all_the_memory_still_fail(self):
        # One worker under all of it is the floor: tests past half of that still give no verdict.
        with tempfile.TemporaryDirectory() as d:
            code, workers = self.fitted_run(d, 96 << 20, 256 << 20, 4)
            self.assertEqual(code, 1)
            self.assertEqual(workers[0], 4)
            self.assertEqual(workers[-1], 1)
            self.assertEqual(workers, sorted(workers, reverse=True))

    def test_each_package_starts_at_the_full_worker_count(self):
        # A refit share is the package's own: the next package runs on every worker again, so the
        # workers' shares together never pass half the free memory.
        with tempfile.TemporaryDirectory() as d:
            code, workers = self.fitted_run(d, 48 << 20, 512 << 20, 4, ("hint", "hint2"))
            self.assertEqual(code, 0)
            self.assertEqual(workers[0], 4)
            self.assertEqual(workers.count(4), 2, workers)

    @unittest.skipUnless(shutil.which("gremlins"), "gremlins v0.6.0 is not installed")
    def test_gremlins_reads_a_capped_mutant_as_killed(self):
        # #6000's shape: a mutant (`i--`) turns a bounded append into one that grows until the runner dies.
        src = ("package p\n\nfunc Pad(n int) []byte {\n\tvar b []byte\n"
               "\tfor i := 0; i < n; i++ {\n\t\tb = append(b, make([]byte, 1<<20)...)\n\t}\n\treturn b\n}\n")
        test = ("package p\n\nimport \"testing\"\n\nfunc TestPad(t *testing.T) {\n"
                "\tif len(Pad(3)) != 3<<20 {\n\t\tt.Fatal()\n\t}\n}\n")
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"GOFLAGS": "", "GOWORK": "off"}):
            pkg = pathlib.Path(d) / "broker" / "p"
            pkg.mkdir(parents=True)
            (pkg.parent / "go.mod").write_text(GO_MOD)
            (pkg / "a.go").write_text(src)
            (pkg / "a_test.go").write_text(test)
            (pathlib.Path(d) / "cfg.yaml").write_text("{}\n")
            out = pathlib.Path(d) / "out.json"
            env = {**os.environ, "PATH": f"{mutgate.go_shim(d, 256 << 20)}{os.pathsep}{os.environ['PATH']}"}
            began = time.monotonic()
            r = subprocess.run(["gremlins", "unleash", "--config", str(pathlib.Path(d) / "cfg.yaml"), "-o", str(out), str(pkg)],
                               cwd=pkg, env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            got = {(m["line"], m["type"], m["status"]) for f in json.loads(out.read_text())["files"] for m in f["mutations"]}
        self.assertIn((5, "INCREMENT_DECREMENT", "KILLED"), got)
        self.assertLess(time.monotonic() - began, 120)

    @unittest.skipUnless(shutil.which("gremlins"), "gremlins v0.6.0 is not installed")
    def test_gremlins_reads_a_capped_output_flood_as_killed(self):
        # #5974's class through the driver (MUT-gremlins-memcap-go): `i--` turns a bounded print loop into an
        # unbounded one, and `go test PKG` holds all of it; the test binary's own memory stays small.
        src = ("package p\n\nimport (\n\t\"fmt\"\n\t\"strings\"\n)\n\nfunc Say(n int) int {\n"
               "\tfor i := 0; i < n; i++ {\n\t\tfmt.Println(strings.Repeat(\"x\", 1<<20))\n\t}\n\treturn n\n}\n")
        test = ("package p\n\nimport \"testing\"\n\nfunc TestSay(t *testing.T) {\n"
                "\tif Say(3) != 3 {\n\t\tt.Fatal()\n\t}\n}\n")
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"GOFLAGS": "", "GOWORK": "off"}):
            pkg = pathlib.Path(d) / "broker" / "p"
            pkg.mkdir(parents=True)
            (pkg.parent / "go.mod").write_text(GO_MOD)
            (pkg / "a.go").write_text(src)
            (pkg / "a_test.go").write_text(test)
            (pathlib.Path(d) / "cfg.yaml").write_text("{}\n")
            out = pathlib.Path(d) / "out.json"
            env = {**os.environ, "PATH": f"{mutgate.go_shim(d, 256 << 20)}{os.pathsep}{os.environ['PATH']}"}
            began = time.monotonic()
            r = subprocess.run(["gremlins", "unleash", "--config", str(pathlib.Path(d) / "cfg.yaml"), "-o", str(out), str(pkg)],
                               cwd=pkg, env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            got = {(m["line"], m["type"], m["status"]) for f in json.loads(out.read_text())["files"] for m in f["mutations"]}
        self.assertIn((9, "INCREMENT_DECREMENT", "KILLED"), got)
        self.assertLess(time.monotonic() - began, 120)


class LiteralTailCover(unittest.TestCase):
    """MUT-legacy-not-equivalent-records (#5909): Go's cover ends a statement's block at a func literal it
    holds, so the code after the literal on its line was in no block and gremlins read its mutants NOT
    COVERED. The profile gains a ran block for that code wherever the statement's block ran."""
    # REQ: MUT-legacy-not-equivalent-records

    SRC = ("package p\n\nimport \"strings\"\n\nfunc H(s string) bool {\n"
           "\tif len(s) > 3 || strings.IndexFunc(s, func(r rune) bool { return r == 'x' }) >= 0 {\n\t\treturn true\n\t}\n"
           "\treturn false\n}\n\nfunc B(s string) bool {\n\treturn strings.IndexFunc(s, func(r rune) bool { return r == 'y' }) < 0\n}\n\n"
           "func N(s string) int {\n\treturn strings.IndexFunc(s, func(r rune) bool { return r == 'z' }) + 1\n}\n")
    TEST = ("package p\n\nimport \"testing\"\n\nfunc TestH(t *testing.T) {\n\tif !H(\"x\") || H(\"a\") || B(\"y\") || !B(\"a\") {\n"
            "\t\tt.Fatal()\n\t}\n}\n")

    def tail(self, line, end=None):
        """The code after line's func literal: from its `})`'s `)` to the last character of the line's last end (default: the line's end)."""
        text = self.SRC.split("\n")[line - 1]
        start = text.index("})") + 2
        return (line, start), (line, text.rindex(end) + len(end) if end else len(text) + 1)

    def package(self, d):
        broker = pathlib.Path(d) / "broker"
        (broker / "p").mkdir(parents=True)
        (broker / "go.mod").write_text(GO_MOD)
        (broker / "p" / "a.go").write_text(self.SRC)
        (broker / "p" / "a_test.go").write_text(self.TEST)
        return broker

    def test_the_code_after_a_ran_literal_gains_a_ran_block(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"GOFLAGS": "", "GOWORK": "off"}):
            broker, profile = self.package(d), pathlib.Path(d) / "c.out"
            subprocess.run(["go", "test", "-count=1", "-covermode=count", f"-coverprofile={profile}", "."],
                           cwd=broker / "p", check=True, capture_output=True)
            text = profile.read_text()
            got = mutgate.with_cases(text, mutgate.build_lister(d), broker / "p")
        added = {((int(m[0]), int(m[1])), (int(m[2]), int(m[3]))) for m in
                 re.findall(r"^example\.invalid/broker/p/a\.go:(\d+)\.(\d+),(\d+)\.(\d+) 0 1$", got[len(text.rstrip()):], re.M)}
        # H's `>= 0` up to its body's `{`, and B's `< 0` to its line's end; N never ran, so its `+ 1` gains none.
        self.assertEqual(added, {self.tail(6, " {"), self.tail(13)})

    def test_tail_rules(self):
        lines = [b"\tif f(func() { g() }) > 0 {", b"\t\tx()", b"\t}"]
        lit, after = (1, 15, 1, 22), (1, 28, 3, 3)
        # The statement's block ran: the tail runs to the next block's start; it never ran: no tail.
        self.assertEqual(mutgate.literal_tails({(1, 2, 1, 15): 1, lit: 1, after: 1}, lines), [((1, 22), (1, 28))])
        self.assertEqual(mutgate.literal_tails({(1, 2, 1, 15): 0, lit: 0, after: 0}, lines), [])
        # A nested body closing its line, or a literal ending its statement, leaves no code after it.
        self.assertEqual(mutgate.literal_tails({(1, 2, 1, 28): 1, (1, 28, 3, 3): 1}, lines), [])
        self.assertEqual(mutgate.literal_tails({(1, 2, 1, 14): 1, (1, 14, 1, 21): 1}, [b"\tf := func() { g() }"]), [])

    @unittest.skipUnless(shutil.which("gremlins"), "gremlins v0.6.0 is not installed")
    def test_gremlins_runs_a_mutant_after_a_literal(self):
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"GOFLAGS": "", "GOWORK": "off"}):
            broker = self.package(d)
            (pathlib.Path(d) / "cfg.yaml").write_text("{}\n")
            out = pathlib.Path(d) / "out.json"
            env = {**os.environ, "PATH": f"{mutgate.go_shim(d)}{os.pathsep}{os.environ['PATH']}"}
            r = subprocess.run(["gremlins", "unleash", "--config", str(pathlib.Path(d) / "cfg.yaml"), "-o", str(out), str(broker / "p")],
                               cwd=broker / "p", env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            got = {(m["line"], m["column"], m["type"], m["status"]) for f in json.loads(out.read_text())["files"] for m in f["mutations"]}
        tails = {(line, c, t, s) for line, c, t, s in got if line in (6, 13) and c >= self.tail(line)[0][1]}
        # Both kinds on H's `>= 0` and on B's `< 0`, each run and killed; before, each was NOT COVERED.
        self.assertEqual({(line, t, s) for line, _, t, s in tails},
                         {(n, t, "KILLED") for n in (6, 13) for t in ("CONDITIONALS_BOUNDARY", "CONDITIONALS_NEGATION")}, got)
        self.assertFalse({s for line, *_, s in got if line == 17} - {"NOT COVERED"}, got)  # N: no test runs it


def job(text, name):
    """The body of job `name` in a workflow's jobs: block."""
    m = re.search(rf"(?ms)^  {re.escape(name)}:\n(.*?)(?=^  [a-z][\w-]*:\n|\Z)", text.split("\njobs:\n", 1)[1])
    return m.group(1) if m else ""


class Workflow(unittest.TestCase):
    # REV-CHK-mut, brief acceptance test test_mutgate_runs_only_on_touched_tier_a_packages. It lives
    # here, not in tests/test_workflows.py, because open PR #3885 edits that file (D-111).
    def setUp(self):
        self.text = WORKFLOW.read_text()

    def test_mutgate_runs_only_on_touched_tier_a_packages(self):
        on = self.text.split("\non:\n", 1)[1].split("\npermissions:", 1)[0]
        self.assertEqual(on.strip(), "pull_request:")
        claimed = job(self.text, "claimed")
        self.assertIn('python3 -I tools/mutgate.py claimed --git "$BASE" --json', claimed)
        # The base is the merge commit's first parent, checked in both jobs, never the event's base sha.
        self.assertNotIn("base.sha", self.text)
        for body in (claimed, job(self.text, "plan"), job(self.text, "mutants")):
            self.assertIn('          [ "$(git rev-parse HEAD^2)" = "$PR_HEAD" ] || '
                          '{ echo "::error::HEAD is not the merge of this PR\'s head"; exit 1; }\n', body)
            self.assertIn('echo "BASE=$(git rev-parse HEAD^1)" >> "$GITHUB_ENV"', body)
            self.assertIn("PR_HEAD: ${{ github.event.pull_request.head.sha }}", body)
            self.assertLess(body.index("HEAD^1"), body.index('--git "$BASE"'))
        self.assertIn("fetch-depth: 0", claimed)
        mutants = job(self.text, "mutants")
        # An empty claim (a docs-only PR) runs no plan and no gremlins; otherwise the plan's shards
        # are the matrix, one job for each shard of each package (#4961).
        plan = job(self.text, "plan")
        for body in (plan, mutants):
            self.assertIn("if: ${{ needs.claimed.outputs.packages != '[]' }}", body)
        self.assertIn("    needs: claimed\n", plan)
        self.assertIn("    needs: [claimed, plan]\n", mutants)
        self.assertIn('shards=$(python3 -I tools/mutgate.py plan --git "$BASE" --targets-out "$RUNNER_TEMP/targets.json")',
                      plan)
        self.assertIn('echo "shards=$shards" >> "$GITHUB_OUTPUT"', plan)
        self.assertIn("shards: ${{ steps.plan.outputs.shards }}", plan)
        self.assertIn("include: ${{ fromJSON(needs.plan.outputs.shards) }}", mutants)
        self.assertIn("fail-fast: false", mutants)
        for env in ("PKG: ${{ matrix.pkg }}", "SHARDS: ${{ matrix.shards }}", "OF: ${{ matrix.of }}"):
            self.assertIn(env, mutants)
        # #6170: each of the job's shards runs in turn into its own directory, which verify reads.
        self.assertIn('          for s in ${SHARDS//,/ }; do\n'
                      '            [[ "$s" =~ ^[0-9]+$ ]] || { echo "::error::shard $s is not an index"; exit 1; }\n', mutants)
        self.assertIn('            timeout -k 30 3600 python3 -I tools/mutgate.py run "$PKG" --out "mutants/$s" --git "$BASE" --shard "$s" --of "$OF" \\\n'
                      '              --targets "$RUNNER_TEMP/plan/targets.json" || rc=$?\n', mutants)
        self.assertEqual(3600, 60 * mutgate.SHARD_MINUTES)
        # The job's name shows the shard in the checks list (#4983); a name is display text, never run.
        name = "    name: mutants ${{ matrix.pkg }} shard ${{ matrix.shards }} of ${{ matrix.of }}\n"
        self.assertIn(name, mutants)
        self.assertNotIn("matrix.", mutants.replace(name, "").replace("${{ matrix.pkg }}\n", "").replace("${{ matrix.shards }}\n", "")
                         .replace("${{ matrix.of }}\n", "").replace("    timeout-minutes: ${{ matrix.minutes }}\n", ""))
        # matrix values reach scripts through env only
        # #4573: the deletion pass adds to the same result, after gremlins wrote it.
        self.assertIn('                timeout -k 30 "$left" python3 -I tools/mutgate.py delete "$PKG" --out "mutants/$s" --git "$BASE" || rc=$?\n',
                      mutants)
        self.assertLess(mutants.index("mutgate.py run"), mutants.index("mutgate.py delete"))
        self.assertNotIn("mutgate.py gate", self.text)  # the gate is `verify`, in the job no PR code reaches
        self.assertNotIn("${{ matrix.pkg }}\"", mutants)  # never interpolated into a script
        self.assertIn("gremlins@v0.6.0", mutants)
        self.assertIn("gremlins@v0.6.0", (ROOT / "tools" / "mutgate.py").read_text())
        self.assertNotIn("continue-on-error", self.text)

    def test_summary_fails_unless_the_claim_ran_and_each_package_passed(self):
        script = job(self.text, "mutgate").split("name: The claim ran", 1)[1].split("run: |\n", 1)[1]
        script = re.split(r"\n      [-#] ", script, maxsplit=1)[0]
        script = "\n".join(l[10:] for l in script.split("\n"))
        cases = [
            # #6401: an empty claim skips this job; were it to run, it fails, never passes.
            ("success", "[]", "skipped", "skipped", 1),
            ("success", '["kernel"]', "success", "success", 0),
            ("success", '["kernel"]', "success", "failure", 1),
            ("success", '["kernel"]', "success", "cancelled", 1),  # #5069: a shard timed out
            ("success", '["kernel"]', "success", "skipped", 1),
            ("success", '["kernel"]', "failure", "skipped", 1),  # #4961: no plan, no shards
            ("success", '["kernel"]', "cancelled", "skipped", 1),  # #6155: the plan timed out
            ("success", '["kernel"]', "skipped", "success", 1),
            ("success", "[]", "skipped", "failure", 1),
            ("success", "[]", "success", "skipped", 1),
            ("failure", "", "skipped", "skipped", 1),
        ]
        for claimed, pkgs, plan, mutants, want in cases:
            env = {"CLAIMED": claimed, "PACKAGES": pkgs, "PLAN": plan, "MUTANTS": mutants, "PATH": "/usr/bin:/bin"}
            r = subprocess.run(["sh", "-ec", script], env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode != 0, bool(want), (claimed, pkgs, plan, mutants, r.stdout, r.stderr))
            # #5069: a timed-out shard says so, not a bare "cancelled"; nothing else claims a timeout.
            self.assertEqual("::error::a mutants job timed out at its job limit (60 minutes for each shard it runs, plus 15 for setup" in r.stdout,
                             mutants == "cancelled" and claimed == "success", r.stdout)
            self.assertEqual("::error::the plan job timed out" in r.stdout,
                             plan == "cancelled" and claimed == "success", r.stdout)
        self.assertIn("if: ${{ !cancelled() && (needs.claimed.result != 'success' || needs.claimed.outputs.packages != '[]') }}",
                      job(self.text, "mutgate"))
        self.assertIn("needs: [claimed, plan, mutants]", job(self.text, "mutgate"))

    def test_each_shard_of_a_job_stops_at_its_own_60_minutes_and_is_named(self):
        # L3 1 on #6171 (MUT-plan-overflow, #6170): a job of several shards gives each its own 60 minutes
        # for gremlins and its deletions together, and a shard past them fails naming itself, not a job
        # cancelled at its pooled limit. The step's script runs here with python3 and timeout stubbed.
        step = next(st for st in job(self.text, "mutants").split("\n      - ")
                    if st.startswith("name: Gremlins and statement deletions on the package (#4573)\n"))
        script = "\n".join(l[10:] for l in step.split("run: |\n", 1)[1].split("\n"))
        for slow, want in ((None, 0), ("run 148", 124), ("delete 148", 124), ("run 0", 124)):
            with self.subTest(slow), tempfile.TemporaryDirectory() as d:
                bin_, log = pathlib.Path(d) / "bin", pathlib.Path(d) / "log"
                bin_.mkdir()
                # timeout LIMIT CMD...: the stub logs the limit and the shard's command, then fails as a
                # timed-out command does (124) for the one slow call.
                (bin_ / "timeout").write_text(
                    '#!/bin/bash\nshift 2\nlim=$1; shift\nwhat="$4 $(basename "$7")"\n'
                    f'echo "$lim $what" >> {log}\n[ "$what" = "{slow}" ] && exit 124\nexit 0\n')
                (bin_ / "timeout").chmod(0o755)
                (bin_ / "sudo").write_text("#!/bin/sh\ncat > /dev/null\n")  # the move into the cgroup (#6392)
                (bin_ / "sudo").chmod(0o755)
                env = {"PATH": f"{bin_}:/usr/bin:/bin", "PKG": "enforcer/nft", "SHARDS": "0, 148", "OF": "296",
                       "BASE": "b" * 40, "RUNNER_TEMP": d}
                r = subprocess.run(["bash", "-ec", script], env=env, capture_output=True, text=True, cwd=d)
                self.assertEqual(r.returncode, want, r.stdout + r.stderr)
                calls = log.read_text().split("\n")[:-1]
                ran = [c.split(" ", 1)[1] for c in calls]
                stop = ran.index(slow) + 1 if slow else len(ran)
                self.assertEqual(ran, ["run 0", "delete 0", "run 148", "delete 148"][:stop])
                # Each shard's gremlins run gets the full 60 minutes, its deletions what is left of them.
                for c in calls:
                    self.assertLessEqual(int(c.split(" ")[0]), 3600)
                    if c.split(" ")[1] == "run":
                        self.assertEqual(c.split(" ")[0], "3600")
                shard = slow.split(" ")[1] if slow else None
                self.assertEqual(f"::error::shard {shard} of 296 of enforcer/nft passed its 60-minute limit" in r.stdout,
                                 slow is not None, r.stdout)
        # A non-index shard fails before anything runs.
        r = subprocess.run(["bash", "-ec", script], env={"PATH": "/usr/bin:/bin", "SHARDS": "../x, 0"},
                           capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("::error::shard ../x is not an index", r.stdout)

    def test_only_the_plan_and_mutants_jobs_run_pr_code_and_they_hand_on_data(self):
        # REV-CHK-mut-selftest (#4106): the PR's tests run in `mutants` and can write anything there,
        # so that job ends in an upload and decides nothing. #4961: `plan` runs them too (a test-only
        # diff's coverage) and ends in the matrix it outputs and the one record of a test-only package's
        # covered lines that every shard reads (#4970); verify checks the shards whatever they say.
        plan = job(self.text, "plan")
        steps = plan.split("\n      - ")
        self.assertTrue(steps[-2].startswith("name: Shards for each package"), plan)
        self.assertTrue(steps[-1].startswith("uses: actions/upload-artifact@"), steps[-1])
        self.assertIn("name: mutgate-plan\n", steps[-1])
        self.assertIn("path: ${{ runner.temp }}/targets.json\n", steps[-1])
        self.assertIn("if-no-files-found: error", steps[-1])
        self.assertNotIn("verify", plan)
        mutants = job(self.text, "mutants")
        steps = mutants.split("\n      - ")
        # The shard reads the plan's record from outside the workspace, just before gremlins.
        self.assertTrue(steps[-4].startswith("uses: actions/download-artifact@"), steps[-4])
        self.assertIn("name: mutgate-plan\n", steps[-4])
        self.assertTrue(steps[-4].endswith("path: ${{ runner.temp }}/plan"), steps[-4])
        # The deciding job's download takes the shards' results only, never the plan's record.
        self.assertIn("pattern: mutants-*\n", job(self.text, "mutgate"))
        self.assertFalse(fnmatch.fnmatch("mutgate-plan", "mutants-*"))
        self.assertIn("name: Gremlins and statement deletions on the package (#4573)", steps[-3])
        self.assertTrue(steps[-1].startswith("uses: actions/upload-artifact@"), steps[-1])
        self.assertIn("name: mutants-${{ strategy.job-index }}", steps[-1])
        self.assertIn("path: mutants/", steps[-1])
        self.assertIn("if-no-files-found: error", steps[-1])
        self.assertNotIn("verify", mutants)
        # The jobs that decide never run PR code and run tools/ only after it is the base's copy;
        # mutgate sets up Go only to build the base's lister (#4602), which mutgate.py does.
        restore = ('        run: |\n          rm -rf tools broker/core/core.txt\n'
                   '          git archive "$BASE" tools broker/core/core.txt | tar -x\n')
        for name in ("claimed", "mutgate"):
            body = job(self.text, name)
            self.assertNotRegex(body, r"\bgo (test|build|run|install)\b|gremlins unleash", name)
            self.assertEqual("setup-go" in body, name == "mutgate", name)
            self.assertIn(restore, body)
            self.assertLess(body.index("HEAD^1"), body.index("rm -rf tools"), name)
            self.assertLess(body.index("rm -rf tools"), body.index("python3 -I tools/mutgate.py"), name)
            self.assertEqual(body.count("python3 -I tools/mutgate.py"), 1, name)

    def test_mutgate_job_verifies_the_artifacts_from_a_fresh_checkout(self):
        body = job(self.text, "mutgate")
        # The first step reads the PR's head (#5409); tests/test_workflows.py pins it.
        steps = body.split("\n      - ")[2:]
        names = [st.split("\n", 1)[0] for st in steps]
        self.assertEqual(body.split("\n      - ")[1].split("\n", 1)[0], "name: This run's head is still the PR's current head")
        self.assertEqual(names, [
            "name: The claim ran and every claimed package passed",
            "uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2",
            "name: The base this merge commit was built on",
            "uses: actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16  # v6.5.0",
            "uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093  # v4.3.0",
            "name: The base copy of the gate",
            "name: Gate (MUT-tierA)",
        ])
        # The job runs only on a non-empty or failed claim (#6401), so no step carries its own `if`.
        self.assertNotIn("        if:", body)
        self.assertIn("persist-credentials: false", steps[1])
        self.assertIn("fetch-depth: 0", steps[1])
        self.assertIn('[ "$(git rev-parse HEAD^2)" = "$PR_HEAD" ]', steps[2])
        # Both jobs list the deletion sites with one Go, and the trusted one reads no repo file for it.
        go = re.compile(r'go-version: "([\d.]+)"')
        self.assertEqual(go.findall(steps[3]), go.findall(job(self.text, "mutants")))
        self.assertIn("cache: false", steps[3])
        self.assertNotIn("go-version-file", steps[3])
        self.assertIn("pattern: mutants-*", steps[4])
        self.assertIn("path: ${{ runner.temp }}/mutants", steps[4])
        self.assertNotIn("merge-multiple", steps[4])  # one directory per artifact: verify refuses a duplicate
        self.assertIn("RESULTS: ${{ runner.temp }}/mutants", steps[6])
        self.assertIn('python3 -I tools/mutgate.py verify "$RESULTS" --git "$BASE"', steps[6])

    def test_pr_body_never_reaches_the_gate(self):
        # #6379: the body waives nothing, so the workflow never hands it to the gate (#4908 kept it data; now it is absent).
        self.assertNotIn("github.event.pull_request.body", self.text)
        self.assertNotIn("--body", self.text)
        gate = job(self.text, "mutgate").split("      - name: Gate (MUT-tierA)\n", 1)[1]
        script = gate.split("        run: |\n", 1)[1]
        self.assertNotIn("${{", script)
        script = "\n".join(l[10:] for l in script.split("\n"))
        with tempfile.TemporaryDirectory() as d:
            stub = pathlib.Path(d) / "bin"
            stub.mkdir()
            (stub / "python3").write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$OUT/argv"\n')
            (stub / "python3").chmod(0o755)
            env = {"PATH": f"{stub}:/usr/bin:/bin", "OUT": d, "RUNNER_TEMP": d, "RESULTS": "R", "BASE": "B",
                   "GITHUB_STEP_SUMMARY": "S"}
            r = subprocess.run(["bash", "-e", "-c", script], cwd=d, env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual((pathlib.Path(d) / "argv").read_text().split("\n")[:-1], [
                "-I", "tools/mutgate.py", "verify", "R", "--git", "B", "--summary", "S"])

    def test_base_copy_step_drops_files_the_pr_adds_under_tools(self):
        # A PR-added tools/fnmatch.py would be imported by risk_tier under the base's mutgate.py.
        script = job(self.text, "mutgate").split("name: The base copy of the gate\n", 1)[1]
        script = "\n".join(l[10:] for l in re.split(r"\n      [-#] ", script.split("run: |\n", 1)[1], maxsplit=1)[0].split("\n"))
        with tempfile.TemporaryDirectory() as d:
            git = lambda *a: subprocess.run(["git", "-C", d, *a], check=True, capture_output=True, text=True)
            (pathlib.Path(d) / "tools").mkdir()
            (pathlib.Path(d) / "broker" / "core").mkdir(parents=True)
            (pathlib.Path(d) / "tools" / "mutgate.py").write_text("base\n")
            (pathlib.Path(d) / "broker" / "core" / "core.txt").write_text("base\n")
            git("init", "-q")
            git("add", "-A")
            git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "-m", "base")
            (pathlib.Path(d) / "tools" / "mutgate.py").write_text("pr\n")
            (pathlib.Path(d) / "tools" / "fnmatch.py").write_text("pr\n")
            (pathlib.Path(d) / "broker" / "core" / "core.txt").write_text("pr\n")
            # Security on #4154: a PR's attributes must not rewrite the base copy's bytes.
            (pathlib.Path(d) / ".gitattributes").write_text("* text eol=crlf\n")
            git("add", "-A")
            git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "-m", "pr")
            base = git("rev-parse", "HEAD~1").stdout.strip()
            subprocess.run(["bash", "-ec", script], cwd=d, check=True, env={"BASE": base, "PATH": "/usr/bin:/bin"})
            self.assertEqual(sorted(f.name for f in (pathlib.Path(d) / "tools").iterdir()), ["mutgate.py"])
            self.assertEqual((pathlib.Path(d) / "tools" / "mutgate.py").read_bytes(), b"base\n")
            self.assertEqual((pathlib.Path(d) / "broker" / "core" / "core.txt").read_bytes(), b"base\n")


class Jobs(unittest.TestCase):
    """#4672: --jobs defaults without os.sched_getaffinity, which macOS lacks."""

    def test_default_without_sched_getaffinity_uses_cpu_count(self):
        from unittest import mock
        with mock.patch.object(os, "sched_getaffinity", create=True, side_effect=AttributeError), \
                mock.patch.object(os, "cpu_count", return_value=6):
            self.assertEqual(mutgate.default_jobs(), 6)
            os.cpu_count.return_value = None
            self.assertEqual(mutgate.default_jobs(), 1)

    def test_default_uses_affinity_when_present(self):
        from unittest import mock
        with mock.patch.object(os, "sched_getaffinity", create=True, return_value={0, 1, 2}):
            self.assertEqual(mutgate.default_jobs(), 3)



# The fixture lints read hint.go from the tree they run in, as broker's lints read theirs.
LINT_SRC = """package lint

import (
	"os"
	"strings"
	"testing"
	"time"
)

func src(t *testing.T) string {
	b, err := os.ReadFile("../hint/hint.go")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestWiped(t *testing.T) {
	if !strings.Contains(src(t), "clear(b)") {
		t.Fatal("hint.go: b is not wiped")
	}
}

func TestBroken(t *testing.T) { t.Fatal("fails on every tree") }

func TestSlow(t *testing.T) {
	if !strings.Contains(src(t), "clear(b)") {
		time.Sleep(time.Hour)
	}
}

// TestFlaky refuses a tree once, then passes it: no confirming refusal (#6366).
func TestFlaky(t *testing.T) {
	if !strings.Contains(src(t), "clear(b)") {
		if _, err := os.Stat("../flaky-seen"); err != nil {
			os.WriteFile("../flaky-seen", nil, 0o644)
			t.Fatal("hint.go: b is not wiped")
		}
	}
}

// TestPanics panics on the tree it would refuse: Go prints its --- FAIL: line all the same (#6366).
func TestPanics(t *testing.T) {
	if !strings.Contains(src(t), "clear(b)") {
		panic("hint.go: b is not wiped")
	}
}

var hog []byte

func TestHog(t *testing.T) {
	if !strings.Contains(src(t), "clear(b)") {
		hog = make([]byte, 1<<30)
		for i := range hog {
			hog[i] = 1
		}
		time.Sleep(time.Hour)
	}
}
"""
LINT_PR = "package hint\n\nfunc Keep(b []byte) int {\n\tn := len(b)\n\tclear(b)\n\treturn n\n}\n"
LINT_TEST = "package hint\n\nimport \"testing\"\n\nfunc TestKeep(t *testing.T) {\n\tif Keep([]byte{1, 2}) != 2 {\n\t\tt.Fatal(\"Keep\")\n\t}\n}\n"


def lint(name, pkg="lint", scope=(("hint",), None)):
    """A LINTS entry for the fixture lint package, reading broker/hint's files by default."""
    return (pkg, name, scope)


class LintHeld(unittest.TestCase):
    """MUT-lint-held (#6346): a deletion no test of its package fails, refused by a listed lint."""
    repo, lister = Deletion.repo, Deletion.lister

    def fixture(self, d):
        """broker/hint of a repo whose PR adds LINT_PR, with the fixture lint package beside it."""
        pkg = self.repo(d, "package hint\n", LINT_PR, LINT_TEST)
        (pkg.parent / "lint").mkdir()
        (pkg.parent / "lint" / "lint_test.go").write_text(LINT_SRC)
        return pkg

    def lint_verdicts(self, lints):
        """({line: (status, killed_by)}, the tree's files after) of deletion_mutants on hint.go with
        the fixture lint package beside it and LINTS as given."""
        from unittest import mock
        with tempfile.TemporaryDirectory() as d:
            pkg = self.fixture(d)
            added = mutgate.added_lines(subprocess.run(
                ["git", "-C", d, "diff", "-U0", "--src-prefix=a/", "--dst-prefix=b/", "HEAD~1", "--", "broker"],
                capture_output=True, text=True, check=True).stdout)[0]
            tmp = pathlib.Path(d) / "tmp"
            tmp.mkdir()
            with mock.patch.object(mutgate, "BROKER", pkg.parent), mock.patch.object(mutgate, "LINTS", lints):
                got, problem = mutgate.deletion_mutants("hint", added, tmp, self.lister(tmp), 1)
            self.assertIsNone(problem)
            after = {p.relative_to(d).as_posix(): p.read_text() for p in pkg.parent.rglob("*.go")}
        return {m["line"]: (m["status"], m.get("killed_by")) for m in got}, after

    def test_a_deletion_a_listed_lint_refuses_is_killed_by_that_lint(self):
        # REQ: MUT-lint-held
        none, _ = self.lint_verdicts(())
        self.assertEqual(none[5], ("LIVED", None))  # no test of hint reads b after Keep
        # A lint that fails unmutated, or names no test, kills nothing; the one that refuses the tree does.
        got, after = self.lint_verdicts((lint("TestBroken"), lint("TestMissing"), lint("TestWiped")))
        self.assertEqual(got[5], ("KILLED", "TestWiped"))
        self.assertEqual({**got, 5: none[5]}, none)  # the other sites keep their verdicts
        # The lint ran on a copy: the tree holds the PR's text, and no lint-tree is left behind.
        self.assertEqual(after["broker/hint/hint.go"], LINT_PR)
        self.assertEqual(after["broker/lint/lint_test.go"], LINT_SRC)

    def test_a_lint_that_passes_fails_unmutated_times_out_or_passes_the_cap_kills_nothing(self):
        # REQ: MUT-lint-held
        from unittest import mock
        with tempfile.TemporaryDirectory() as d:
            pkg = self.fixture(d)
            gone = LINT_PR.replace("\tclear(b)\n", "\n").encode()
            for name in ("TestBroken", "TestSlow", "TestHog", "TestKeep", "TestMissing"):
                with self.subTest(name), mock.patch.object(mutgate, "BROKER", pkg.parent), \
                        mock.patch.object(mutgate, "LINTS", (lint(name),)), tempfile.TemporaryDirectory() as tmp:
                    self.assertEqual(mutgate.lint_kills("hint", [(0, "hint.go", gone)], pathlib.Path(tmp), 256 << 20), ({}, None))
            with mock.patch.object(mutgate, "BROKER", pkg.parent), mock.patch.object(mutgate, "LINTS", (lint("TestWiped", "nolint"),)), \
                    tempfile.TemporaryDirectory() as tmp:
                self.assertEqual(mutgate.lint_kills("hint", [(0, "hint.go", gone)], pathlib.Path(tmp)), ({}, None))
            # The same call with the refusing lint kills, so each case above is the lint's own.
            with mock.patch.object(mutgate, "BROKER", pkg.parent), mock.patch.object(mutgate, "LINTS", (lint("TestWiped"),)), \
                    tempfile.TemporaryDirectory() as tmp:
                self.assertEqual(mutgate.lint_kills("hint", [(0, "hint.go", gone)], pathlib.Path(tmp), 256 << 20),
                                 ({0: "TestWiped"}, None))
            # Each deletion is alone in the tree its lint reads: the one before it is put back. The second
            # site is in another file of the package, so only the restore keeps the first out of its tree.
            (pkg / "other.go").write_text("package hint\n")
            with mock.patch.object(mutgate, "BROKER", pkg.parent), mock.patch.object(mutgate, "LINTS", (lint("TestWiped"),)), \
                    tempfile.TemporaryDirectory() as tmp:
                self.assertEqual(mutgate.lint_kills("hint", [(0, "hint.go", gone), (1, "other.go", b"package hint\n")],
                                                    pathlib.Path(tmp)), ({0: "TestWiped"}, None))

    def test_each_listed_lint_is_a_top_level_test_of_its_package(self):
        # REQ: MUT-lint-held
        self.assertTrue(mutgate.LINTS)
        for pkg, name, _ in mutgate.LINTS:
            srcs = "".join(p.read_text() for p in (ROOT / "broker" / pkg).glob("*_test.go"))
            self.assertRegex(srcs, rf"(?m)^func {name}\(t \*testing\.T\) {{$", (pkg, name))

    def test_the_wipe_lints_kill_the_deletions_whose_records_retired(self):
        # REQ: MUT-lint-held
        # The acceptance of #6346 on broker itself: each wipe whose record entry this row dropped.
        sites = [("clerk/run", "gmailsignin.go", "sl, err := clerk.NewAESSealer(k)", "clear(k)"),
                 ("clerk/handoff", "codeseed.go", "plain, err := g.Open(nil, rest[:g.NonceSize()]", "defer clear(plain)"),
                 ("clerk/camera", "store.go", "plain, err := g.Open(nil, make([]byte, g.NonceSize()), ct", "defer clear(plain)")]
        want = {}
        for i, (pkg, fname, call, wipe) in enumerate(sites):
            lines = (ROOT / "broker" / pkg / fname).read_text().split("\n")
            at = next(n for n, l in enumerate(lines) if call in l) + 1
            self.assertEqual(lines[at].strip(), wipe, (pkg, fname))
            lines[at] = ""
            with tempfile.TemporaryDirectory() as tmp:
                got = mutgate.lint_kills(pkg, [(i, fname, "\n".join(lines).encode())], pathlib.Path(tmp))
            want[i] = ("TestEverySealingKeyIsWipedRightAfterItsSealer" if i == 0
                       else "TestEveryOpenedPlaintextIsWipedOnEveryPath")
            self.assertEqual(got, ({i: want[i]}, None), (pkg, fname))


class LintHeldFollowUp(unittest.TestCase):
    """MUT-lint-held-fu (#6366): a lint kill is two refusals by the lint's own check, the lints read
    only their files, and their time is budgeted apart from the tests'."""
    fixture = LintHeld.fixture
    repo, lister = Deletion.repo, Deletion.lister
    gone = LINT_PR.replace("\tclear(b)\n", "\n").encode()

    def kills(self, lints, mem=None, **budget):
        from unittest import mock
        with tempfile.TemporaryDirectory() as d:
            pkg = self.fixture(d)
            with mock.patch.object(mutgate, "BROKER", pkg.parent), mock.patch.object(mutgate, "LINTS", lints), \
                    (mock.patch.multiple(mutgate, **budget) if budget else contextlib.nullcontext()), \
                    tempfile.TemporaryDirectory() as tmp:
                got = mutgate.lint_kills("hint", [(0, "hint.go", self.gone)], pathlib.Path(tmp), mem)
                self.assertFalse((pathlib.Path(tmp) / "lint-tree").exists())
            # The lints ran on a copy: a flaky lint's mark is not left in the tree.
            self.assertFalse((pkg.parent / "flaky-seen").exists())
        return got

    def test_a_lint_that_refuses_once_then_passes_kills_nothing(self):
        # REQ: MUT-lint-held-fu
        self.assertEqual(self.kills((lint("TestFlaky"),)), ({}, None))
        # A lint after it in LINTS still runs on the deletion, and its two refusals kill.
        self.assertEqual(self.kills((lint("TestFlaky"), lint("TestWiped"))), ({0: "TestWiped"}, None))

    def test_a_lint_that_panics_on_the_mutated_tree_kills_nothing(self):
        # REQ: MUT-lint-held-fu
        self.assertEqual(self.kills((lint("TestPanics"),)), ({}, None))
        self.assertEqual(self.kills((lint("TestPanics"), lint("TestWiped"))), ({0: "TestWiped"}, None))

    def test_a_refusal_is_exit_1_with_its_own_fail_line_and_no_panic(self):
        # REQ: MUT-lint-held-fu
        from unittest import mock
        with tempfile.TemporaryDirectory() as d:
            binary, out = pathlib.Path(d) / "l.test", pathlib.Path(d) / "l.out"
            cases = [(1, b"--- FAIL: TestWiped (0.00s)\n    lint_test.go:9: hint.go: panic: b\nFAIL\n", "refused"),
                     (1, b"--- FAIL: TestWiped (0.00s)\npanic: boom [recovered]\n", "exit 1, with a panic"),
                     (1, b"--- FAIL: TestWiped (0.00s)\nfatal error: concurrent map writes\n", "exit 1, with a panic"),
                     (1, b"--- FAIL: TestOther (0.00s)\nFAIL\n", "exit 1"),
                     (1, b"exit status 1\n", "exit 1"),
                     (2, b"--- FAIL: TestWiped (0.00s)\npanic: boom\n", "exit 2"),
                     (0, b"PASS\n", "passed"), ("timeout", b"", "timeout"), ("over", b"", "memory cap")]
            for end, text, want in cases:
                class P:
                    def __init__(self, *a, stdout, **k):
                        stdout.write(text)
                with self.subTest(want=want, text=text), mock.patch.object(subprocess, "Popen", P), \
                        mock.patch.object(mutgate, "watch", lambda p, t, m: (end, 0)):
                    self.assertEqual(mutgate.lint_run(binary, d, 5, None, "TestWiped"), want)
                    self.assertTrue(out.exists())

    def test_a_lint_reads_only_its_files_and_a_package_none_reads_makes_no_copy(self):
        # REQ: MUT-lint-held-fu
        from unittest import mock
        copied = []
        real = shutil.copytree

        def copytree(src, dst, *a, **k):  # the fixture's repo is made with copytree too
            if pathlib.Path(dst).parent.name == "lint-tree":
                copied.append(src)
            return real(src, dst, *a, **k)
        with mock.patch.object(shutil, "copytree", copytree):
            self.assertEqual(self.kills((lint("TestWiped", scope=(("other", "hin"), None)),)), ({}, None))
            self.assertEqual(copied, [])
            # A needle in the file's text, or the package under a listed directory, brings the lint in.
            self.assertEqual(self.kills((lint("TestWiped", scope=((), b"func Keep(")),)), ({0: "TestWiped"}, None))
            self.assertEqual(self.kills((lint("TestWiped", scope=(("hint",), b"nowhere")),)), ({0: "TestWiped"}, None))
            self.assertEqual(len(copied), 2)
        # broker's lints: the key lint reads clerk and its importers, the wipe lint clerk alone.
        key, wipe = mutgate.LINTS
        imports = b'import (\n\tc "github.com/ghbmrk/agentos/broker/clerk"\n)\n'
        self.assertEqual(mutgate.lints_for("localui", b"package localui\n"), [])
        self.assertEqual(mutgate.lints_for("clerkish", b"package clerkish\n"), [])
        self.assertEqual(mutgate.lints_for("localui", b"package localui\n" + imports), [key])
        self.assertEqual(mutgate.lints_for("clerk", b"package clerk\n"), [key, wipe])
        self.assertEqual(mutgate.lints_for("clerk/run", b"package run\n"), [key, wipe])

    def test_lint_time_past_its_budget_fails_the_run_and_names_the_lints(self):
        # REQ: MUT-lint-held-fu
        from unittest import mock
        # TestSlow sleeps on the mutated tree: its own limit is 3 times its unmutated run plus 10 s,
        # past the runs' 2 s budget, so the budget stops it and the run gives no verdict.
        got = self.kills((lint("TestSlow"),), LINT_SETUP_SECONDS=300, LINT_RUN_SECONDS=1)
        self.assertEqual(got, (None, got[1]))
        self.assertIn("lints passed their 2 s budget of runs on 1 deletion(s) at hint.go", got[1])
        self.assertIn("LINT_SETUP_SECONDS", got[1])
        # A budget spent before the unmutated run names that.
        got = self.kills((lint("TestWiped"),), LINT_SETUP_SECONDS=-10, LINT_RUN_SECONDS=1)
        self.assertEqual(got, (None, got[1]))
        self.assertIn("building the lints", got[1])
        # deletion_mutants returns the problem in place of verdicts.
        with tempfile.TemporaryDirectory() as d:
            pkg = self.fixture(d)
            added = mutgate.added_lines(subprocess.run(
                ["git", "-C", d, "diff", "-U0", "--src-prefix=a/", "--dst-prefix=b/", "HEAD~1", "--", "broker"],
                capture_output=True, text=True, check=True).stdout)[0]
            tmp = pathlib.Path(d) / "tmp"
            tmp.mkdir()
            with mock.patch.object(mutgate, "BROKER", pkg.parent), mock.patch.object(mutgate, "LINTS", (lint("TestSlow"),)), \
                    mock.patch.multiple(mutgate, LINT_SETUP_SECONDS=300, LINT_RUN_SECONDS=1):
                got, problem = mutgate.deletion_mutants("hint", added, tmp, self.lister(tmp), 1)
            self.assertIsNone(got)
            self.assertIn("lints passed their", problem)

    def test_the_plan_charges_lint_time_to_the_shards_of_a_package_the_lints_read(self):
        # REQ: MUT-lint-held-fu
        from unittest import mock
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            for path, text in (("localui/a.go", "package localui\n"), ("clerk/run/a.go", "package run\n"),
                               ("localui/b.go", 'package localui\n\nimport "github.com/ghbmrk/agentos/broker/clerk"\n')):
                (root / path).parent.mkdir(parents=True, exist_ok=True)
                (root / path).write_text(text)
            with mock.patch.object(mutgate, "BROKER", root), mock.patch.multiple(mutgate, LINT_SETUP_SECONDS=300, LINT_RUN_SECONDS=10):
                self.assertEqual(mutgate.lint_budget("localui", [{"file": "a.go"}] * 3), (0.0, [0, 0, 0]))
                # A clerk file: both lints may run, and one refusal's confirming run.
                self.assertEqual(mutgate.lint_budget("clerk/run", [{"file": "a.go"}] * 2), (300, [30, 30]))
                self.assertEqual(mutgate.lint_budget("localui", [{"file": "a.go"}, {"file": "b.go"}]), (300, [0, 20]))
                many = mutgate.lint_budget("clerk/run", [{"file": "a.go"}] * 100)
        lines = {"a.go": list(range(10))}
        # 100 sites of 10 s each fit one shard's 1800 s; 30 s of lints each and 300 s of setup take three.
        self.assertEqual(mutgate.shard_count(lines, [0] * 100, 1.0, [10.0] * 100, 0.0), 1)
        self.assertEqual(mutgate.shard_count(lines, [0] * 100, 1.0, [10.0] * 100, 0.0, many), 3)
        self.assertEqual(mutgate.shard_count(lines, [0] * 100, 1.0, None, 0.0, many), 3)
        # cmd_plan charges lint_budget's figure for the package's sites.
        seen = []

        def budget(pkg, sites):
            seen.append((pkg, len(sites)))
            return many
        code, out, err = self.plan_with(budget, {"clerk/run": ({"broker/clerk/run/a.go": set(range(1, 11))}, [{}] * 100)})
        self.assertEqual(code, 0, err)
        self.assertEqual(seen, [("clerk/run", 100)])
        self.assertIn("clerk/run: 10 target lines, 100 deletion sites, a 1 s suite, 3 shard(s)", err)

    def plan_with(self, budget, pkg_targets):
        """Plan.plan's (code, matrix, stderr) with lint_budget as given and site_costs at 10 s a site."""
        from unittest import mock
        import contextlib, io, types
        with contextlib.ExitStack() as st:
            for name, value in (("broker_diff", lambda *a: ""), ("changes", lambda *a: ({}, {})),
                                ("build_lister", lambda tmp: "lister"), ("claimed", lambda d, **_: sorted(pkg_targets)),
                                ("diff_targets", lambda added, pkg: pkg_targets[pkg][0]),
                                ("deletion_sites", lambda pkg, t, lister: (pkg_targets[pkg][1], None)),
                                ("lint_budget", budget), ("suite_seconds", lambda pkg, tmp: (1.0, None)),
                                ("site_costs", lambda pkg, sites, *a: ([10.0] * len(sites), 0.0))):
                st.enter_context(mock.patch.object(mutgate, name, value))
            err = st.enter_context(contextlib.redirect_stderr(io.StringIO()))
            out = st.enter_context(contextlib.redirect_stdout(io.StringIO()))
            code = mutgate.cmd_plan(types.SimpleNamespace(git="HEAD~1", targets_out=None))
        return code, out.getvalue(), err.getvalue()


def mod_diff(path, minus=(), plus=()):
    """A -U0 diff of one file that deletes the lines minus and adds the lines plus, in one hunk."""
    out = f"diff --git a/{path} b/{path}\n--- a/{path}\n+++ b/{path}\n@@ -3,{len(minus)} +3,{len(plus)} @@\n"
    return out + "".join(f"-{x}\n" for x in minus) + "".join(f"+{x}\n" for x in plus)


class GoDebugEveryFu(unittest.TestCase):
    """MUT-go-debug-every-fu (#6420): an edit that changes Go's runtime defaults for a whole package or
    module (a package-wide //go: directive in a non-test file, a go.mod `go` or `godebug` line) changes
    every test there, as #6377's test-file directive does; an edit the go.mod reading cannot place is one."""

    CODE = {"hint/hint.go": "package hint\n", "hint/hint_test.go": "package hint\n",
            "cmd/tool/main.go": "package main\n", "cmd/tool/main_test.go": "package main\n",
            "mail/mail.go": "package mail\n", "mail/mail_test.go": "package mail\n"}
    ALL = {"hint", "cmd/tool", "mail"}

    def tree(self, d):
        return DataFiles.tree(self, d, self.CODE)

    def every(self, diff, pkgs):
        added, tests = mutgate.added_lines(diff)
        self.assertEqual(mutgate.touched(added, tests), pkgs)
        for pkg in pkgs:
            self.assertTrue(mutgate.tests_changed(tests, pkg), pkg)
            self.assertIsNone(mutgate.head_tests(tests, pkg), pkg)  # every test
        self.assertEqual(mutgate.claimed(diff, packages=sorted(self.ALL)), sorted(pkgs))

    def test_a_directive_in_a_main_file_is_every_test_of_its_package(self):
        # REQ: MUT-go-debug-every-fu
        with tempfile.TemporaryDirectory() as d, self.tree(d):
            for name, minus, plus in (("added", (), ("//go:debug panicnil=1",)),
                                      ("changed", ("//go:debug panicnil=1",), ("//go:debug panicnil=0",)),
                                      ("removed", ("//go:debug panicnil=1",), ()),
                                      ("indented", (), ("\t//go:debug panicnil=1",)),
                                      # L3 on #6558: go skips one leading byte order mark and reads the directive.
                                      ("behind a byte order mark", (), ("\ufeff//go:debug panicnil=1",)),
                                      ("removed behind a byte order mark", ("\ufeff//go:debug panicnil=1",), ()),
                                      ("a directive not known", (), ("//go:future x",))):
                with self.subTest(name):
                    self.every(mod_diff("broker/cmd/tool/main.go", minus, plus), {"cmd/tool"})
            # A deleted main file takes its directive with it.
            gone = data_diff("broker/cmd/tool/main.go", "delete").replace("-x\n", "-//go:debug panicnil=1\n")
            self.every(gone, {"cmd/tool"})
            # Any package's non-test file counts: go reads the directive only in main, the gate fails closed.
            self.every(mod_diff("broker/hint/hint.go", (), ("//go:debug x=1",)), {"hint"})
            # A directive that reaches only its declaration or file, or ordinary code, widens nothing.
            for line in ("//go:build linux", "//go:noinline", "//go:embed x.txt", "x := 1", "// go:debug x=1"):
                with self.subTest(line):
                    added, tests = mutgate.added_lines(mod_diff("broker/cmd/tool/main.go", (), (line,)))
                    self.assertEqual(tests, {})
                    self.assertEqual(mutgate.touched(added, tests), {"cmd/tool"})
            # A vendored file's directive is fixed by go.sum (is_vendored): no claim.
            added, tests = mutgate.added_lines(mod_diff("broker/vendor/x/y/y.go", (), ("//go:debug x=1",)))
            self.assertEqual(mutgate.touched(added, tests), set())

    def test_an_edit_that_switches_on_an_unchanged_directive_is_every_test(self):
        # Security on #6558: a //go:debug line the diff leaves alone is switched on by its file's //go:build
        # line, or by removing a /* */ pair around it; any change to a non-test file holding a package-wide
        # directive at the base or head is every test of its package (dormant, read from git).
        # REQ: MUT-go-debug-every-fu
        main = "//go:build never\n\n//go:debug panicnil=1\n\npackage main\n\nfunc main() {}\n"
        hidden = "/*\n//go:debug http2client=0\n*/\n\npackage main\n\nfunc main() {}\n"
        plain = "//go:build never\n\npackage main\n\nfunc main() {}\n"
        for name, was, now, wide in (("its build line", main, main.replace("never", "linux"), True),
                                     ("a comment pair removed", hidden, hidden.replace("/*\n", "").replace("*/\n", ""), True),
                                     ("ordinary code beside it", main, main.replace("{}", "{ println() }"), True),
                                     ("the directive's file deleted", main, None, True),
                                     ("added in a new file", None, main, True),
                                     ("no package-wide directive", plain, plain.replace("never", "linux"), False)):
            with self.subTest(name), tempfile.TemporaryDirectory() as d:
                git = lambda *a: subprocess.run(["git", "-C", d, *a], check=True, capture_output=True, text=True)
                tool = pathlib.Path(d) / "broker" / "cmd" / "tool"
                tool.mkdir(parents=True)
                (tool / "main_test.go").write_text("package main\n")
                git("init", "-q")
                for text in (was, now):
                    if text is None:
                        (tool / "main.go").unlink(missing_ok=True)
                    else:
                        (tool / "main.go").write_text(text)
                    git("add", "-A")
                    git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "-m", "x")
                diff = git("diff", "-U0", "--no-renames", "HEAD~1...HEAD", "--", "broker").stdout
                with mock.patch.object(mutgate, "ROOT", pathlib.Path(d)), \
                        mock.patch.object(mutgate, "BROKER", pathlib.Path(d) / "broker"):
                    got = mutgate.dormant(diff, "HEAD~1", "HEAD")
                    self.assertEqual(got, {f"broker/cmd/tool/{mutgate.EVERY_TEST}": None} if wide else {})
                    tests = mutgate._widen(mutgate.added_lines(diff)[1], got)
                    self.assertEqual(mutgate.head_tests(tests, "cmd/tool"), None if wide else [])
                    self.assertEqual(mutgate.claimed(diff, ["cmd/tool"], "HEAD~1", "HEAD"), ["cmd/tool"])

    def test_the_gate_entry_points_read_a_dormant_directive(self):
        # L3 on #6558: changes(), cmd_plan, cmd_verify and cmd_claimed each read dormant(), so reverting any
        # call site fails here. Security's case (b): only the /* */ pair around an unchanged //go:debug goes.
        # REQ: MUT-go-debug-every-fu
        import contextlib, io, types
        hidden = "/*\n//go:debug http2client=0\n*/\n\npackage main\n\nfunc main() {}\n"
        key = f"broker/cmd/tool/{mutgate.EVERY_TEST}"

        class Reached(Exception):
            pass

        def stop(diff, base, head, tests, pkgs):
            raise Reached(tests, pkgs)

        with tempfile.TemporaryDirectory() as d:
            git = lambda *a: subprocess.run(["git", "-C", d, *a], check=True, capture_output=True, text=True)
            tool = pathlib.Path(d) / "broker" / "cmd" / "tool"
            tool.mkdir(parents=True)
            (tool / "main_test.go").write_text("package main\n")
            git("init", "-q")
            for text in (hidden, hidden.replace("/*\n", "").replace("*/\n", "")):
                (tool / "main.go").write_text(text)
                git("add", "-A")
                git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "-m", "x")
            diff = git("diff", "-U0", "--no-renames", "HEAD~1...HEAD", "--", "broker").stdout
            self.assertEqual(mutgate.claimed(diff, ["cmd/tool"]), [])  # the diff alone shows no directive line
            with contextlib.ExitStack() as st:
                for name, value in (("ROOT", pathlib.Path(d)), ("BROKER", pathlib.Path(d) / "broker"),
                                    ("broker_diff", lambda *a: diff), ("gated_packages", lambda *a: ["cmd/tool"]),
                                    ("advisory", lambda: None), ("build_lister", lambda tmp: "lister"),
                                    ("bases_for", stop), ("read_results", lambda *a: ({}, []))):
                    st.enter_context(mock.patch.object(mutgate, name, value))
                st.enter_context(contextlib.redirect_stderr(io.StringIO()))
                out = st.enter_context(contextlib.redirect_stdout(io.StringIO()))
                self.assertIn(key, mutgate.changes(diff, "HEAD~1", "HEAD")[1])
                for name, cmd, args in (("plan", mutgate.cmd_plan, types.SimpleNamespace(git="HEAD~1", targets_out=None)),
                                        ("verify", mutgate.cmd_verify,
                                         types.SimpleNamespace(git="HEAD~1", head="HEAD", dir=d, summary=None))):
                    with self.subTest(name), self.assertRaises(Reached) as got:
                        cmd(args)
                    tests, pkgs = got.exception.args
                    self.assertIn(key, tests)
                    self.assertEqual(pkgs, ["cmd/tool"])
                self.assertEqual(mutgate.cmd_claimed(types.SimpleNamespace(git="HEAD~1", head="HEAD", json=True)), 0)
                self.assertEqual(json.loads(out.getvalue().splitlines()[-1]), ["cmd/tool"])

    def test_a_go_mod_go_line_is_every_test_of_the_module(self):
        # REQ: MUT-go-debug-every-fu
        with tempfile.TemporaryDirectory() as d, self.tree(d):
            for minus, plus in ((("go 1.26.4",), ("go 1.27",)), ((), ("go 1.27 // pinned",)), (("go 1.26.4",), ())):
                with self.subTest(minus=minus, plus=plus):
                    self.every(mod_diff("broker/go.mod", minus, plus), self.ALL)

    def test_a_go_mod_godebug_line_is_every_test_of_the_module(self):
        # REQ: MUT-go-debug-every-fu
        with tempfile.TemporaryDirectory() as d, self.tree(d):
            for minus, plus in (((), ("godebug default=go1.21",)),
                                ((), ("godebug (", "\tpanicnil=1", ")")),
                                (("\tpanicnil=1",), ("\tpanicnil=0",)),   # -U0: an entry with no block in sight
                                (("\thttp2client=0 // off",), ())):
                with self.subTest(minus=minus, plus=plus):
                    self.every(mod_diff("broker/go.mod", minus, plus), self.ALL)

    def test_an_unplaceable_go_mod_edit_is_every_test_of_the_module(self):
        # REQ: MUT-go-debug-every-fu
        with tempfile.TemporaryDirectory() as d, self.tree(d):
            # An unindented entry and a bare directive keyword are lines go refuses; they fail closed too.
            for line in ("ignore ./old", "use ./x", "\tx=>1", "garbage", "\ta = b", "godebug(", "go",
                         "github.com/a/b v1.0.0", "require", "toolchain", "\ufeffrequire x v1"):
                with self.subTest(line):
                    self.every(mod_diff("broker/go.mod", (), (line,)), self.ALL)
            # What sets no default stays no claim: requirements (go.sum fixes vendor/), replacements,
            # exclusions, retractions, the toolchain, comments and layout.
            for minus, plus in ((("\tgithub.com/a/b v1.0.0",), ("\tgithub.com/a/b v1.1.0 // indirect",)),
                                ((), ("require github.com/a/b v1.0.0",)),
                                ((), ("require (", "\tgithub.com/a/b v1.0.0", ")")),
                                ((), ("replace github.com/a/b => ./third_party/b",)),
                                ((), ("\tgithub.com/a/b v1.0.0 => github.com/c/b v1.0.1",)),
                                ((), ("exclude github.com/a/b v0.9.0", "retract [v1.0.0, v1.0.1] // bad")),
                                (("toolchain go1.26.11",), ("toolchain go1.26.12",)),
                                ((), ("// godebug panicnil=1", "", "module github.com/x/broker"))):
                with self.subTest(minus=minus, plus=plus):
                    added, tests = mutgate.added_lines(mod_diff("broker/go.mod", minus, plus))
                    self.assertEqual(mutgate.touched(added, tests), set())
            # Security on #6558: a toolchain bump can satisfy an unchanged file's `//go:build go1.N` line and switch
            # on its //go:debug, so it is every test of each package holding a package-wide directive, only those.
            bump = mod_diff("broker/go.mod", ("toolchain go1.26.11",), ("toolchain go1.27.0",))
            dormant = {"cmd/tool/new.go": "//go:build go1.27\n\n//go:debug panicnil=1\n\npackage main\n",
                       "mail/x.go": "/*\n//go:debug x=1\n*/\npackage mail\n", "hint/y.go": "//go:noinline\npackage hint\n"}
            with tempfile.TemporaryDirectory() as d2, DataFiles.tree(self, d2, {**self.CODE, **dormant}):
                added, tests = mutgate.added_lines(bump)
                self.assertEqual(mutgate.touched(added, tests), {"cmd/tool", "mail"})
                self.assertIsNone(mutgate.head_tests(tests, "cmd/tool"))
                self.assertEqual(mutgate.head_tests(tests, "hint"), [])
            # Another module's go.mod (third_party/, a replace directory) is that package's data, as before.
            added, tests = mutgate.added_lines(mod_diff("broker/hint/go.mod", (), ("go 1.27",)))
            self.assertEqual(mutgate.touched(added, tests), {"hint"})

    def test_a_patch_level_go_line_bump_is_no_claim(self):
        # REQ: MUT-go-patch-quiet
        # The language version and the GODEBUG defaults follow go1.N, so one hunk swapping one `go` line for
        # another of the same major.minor sets no default (#6567).
        with tempfile.TemporaryDirectory() as d, self.tree(d):
            for minus, plus in ((("go 1.26.4",), ("go 1.26.5",)), (("go 1.26",), ("go 1.26.0 // patch",)),
                                (("go 1.26.5\r",), ("go 1.26.4",)), (("module x", "go 1.26.4"), ("module x", "go 1.26.5"))):
                with self.subTest(minus=minus, plus=plus):
                    added, tests = mutgate.added_lines(mod_diff("broker/go.mod", minus, plus))
                    self.assertEqual(mutgate.touched(added, tests), set())
            # Two hunks, the first pairing its own lines: still quiet.
            two = mod_diff("broker/go.mod", ("go 1.26.4",), ("go 1.26.5",)) + "@@ -9,1 +9,1 @@\n-// a\n+// b\n"
            self.assertEqual(mutgate.touched(*mutgate.added_lines(two)), set())

    def test_any_other_go_line_change_is_every_test_of_the_module(self):
        # REQ: MUT-go-patch-quiet
        # Fail closed: a minor or major bump, one side only, an unparsable version on either side, two go
        # lines on a side, the pair split across hunks or files, or an indented go line all widen.
        with tempfile.TemporaryDirectory() as d, self.tree(d):
            for minus, plus in ((("go 1.26.4",), ("go 1.27.0",)), (("go 1.26.4",), ("go 2.26.4",)),
                                ((), ("go 1.26.5",)), (("go 1.26.4",), ()),
                                (("go 1.26.4",), ("go 1.26rc1",)), (("go 1.26rc1",), ("go 1.26.4",)),
                                (("go 1.26.4",), ("go 1.026.4",)), (("go 1.26.4",), ("go 1.26.4.1",)),
                                (("go 1.26.4",), ("go 1.26.5", "go 1.26.6")), (("go 1.26.4", "go 1.26.4"), ("go 1.26.5",)),
                                (("go 1.26.4",), ("\tgo 1.26.5",)), (("\tgo 1.26.4",), ("\tgo 1.26.5",)),
                                (("go 1.26.4",), ("go 1.26.5 x",)), (("go 1.26.4",), ("go",))):
                with self.subTest(minus=minus, plus=plus):
                    self.every(mod_diff("broker/go.mod", minus, plus), self.ALL)
            split = mod_diff("broker/go.mod", ("go 1.26.4",)) + "@@ -9,0 +9,1 @@\n+go 1.26.5\n"
            self.every(split, self.ALL)
            other = mod_diff("broker/go.mod", ("go 1.26.4",)) + mod_diff("broker/hint/go.mod", (), ("go 1.26.5",))
            self.every(other, self.ALL)


if __name__ == "__main__":
    unittest.main()
