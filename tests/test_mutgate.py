"""tools/mutgate.py: the REQ-claim gate over gremlins results (MUT-tierA, #1814), and the
workflow that runs it on pull requests (REV-CHK-mut, #3899).

Gremlins itself is not run: the gate reads its JSON, so fixtures stand in for it.
"""
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "mutgate.yml"
sys.path.insert(0, str(ROOT / "tools"))
import mutgate  # noqa: E402

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


class Gate(unittest.TestCase):
    def test_live_mutant_on_added_line_in_claimed_package_fails(self):
        self.assertEqual(
            mutgate.violations(DIFF, LIVE),
            [("hint", "broker/hint/hint.go", 11, "CONDITIONALS_BOUNDARY")],
        )

    def test_no_marker_no_claim(self):
        self.assertEqual(mutgate.violations(DIFF.replace("REQ:", "NOTE:"), LIVE), [])

    def test_survivor_on_untouched_line_or_other_package_passes(self):
        self.assertEqual(mutgate.violations(DIFF, {"hint": [("hint.go", 40, "X")]}), [])
        self.assertEqual(mutgate.violations(DIFF, {"mail": [("hint.go", 11, "X")]}), [])

    def test_survivor_in_a_test_file_is_not_counted(self):
        self.assertEqual(mutgate.violations(DIFF, {"hint": [("hint_test.go", 2, "X")]}), [])

    def test_added_lines_follow_hunk_numbers(self):
        added, marked = mutgate.added_lines(DIFF)
        self.assertEqual(added["broker/hint/hint.go"], {11, 12})
        self.assertEqual(marked, {"broker/hint/hint_test.go"})

    def test_added_lines_split_on_newline_only(self):
        # #4028: a Go comment may carry any of these; str.splitlines() broke the diff line there.
        for ch in ("\u2028", "\u2029", "\r", "\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85"):
            diff = DIFF.replace("+\tif x > 1 {\n", f"+// a{ch}b\n+\tif x > 1 {{\n")
            added, _ = mutgate.added_lines(diff)
            self.assertEqual(added["broker/hint/hint.go"], {11, 12, 13}, repr(ch))
            self.assertEqual(mutgate.violations(diff, {"hint": [("hint.go", 12, "X")]}),
                             [("hint", "broker/hint/hint.go", 12, "X")], repr(ch))

    def test_added_lines_skip_the_no_newline_marker(self):
        # #4103: the marker after a rewritten unterminated last line is not a line.
        diff = ("diff --git a/broker/x/a.go b/broker/x/a.go\n--- a/broker/x/a.go\n+++ b/broker/x/a.go\n"
                "@@ -2 +2,2 @@\n-old\n\\ No newline at end of file\n+n1\n+n2\n")
        self.assertEqual(mutgate.added_lines(diff)[0], {"broker/x/a.go": {2, 3}})
        diff += "\\ No newline at end of file\n"
        self.assertEqual(mutgate.added_lines(diff)[0], {"broker/x/a.go": {2, 3}})
        # a LIVED mutant on the first added line is read, not skipped
        diff = diff.replace("broker/x/a.go", "broker/hint/hint.go").replace("+n1", "+n1\n+// REQ: CRED-1")
        self.assertEqual(mutgate.violations(diff, {"hint": [("hint.go", 2, "X")]}),
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
            (pkg / "hint_test.go").write_text("package hint\n// REQ: CRED-1\n")
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
                (pkg / "hint_test.go").write_text("package hint\n// REQ: CRED-1\n")
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
                (pkg / "hint_test.go").write_text("package hint\n// REQ: CRED-1\n")
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
            self.assertEqual(mutgate.survivors(d), {"vm/gvisor": [("a.go", 3, "T")]})
            self.assertEqual(mutgate.package_of("broker/vm/gvisor/a.go"), "vm/gvisor")

    def test_tier_a_packages_are_tier_a(self):
        pkgs = mutgate.tier_a_packages()
        self.assertIn("netguard", pkgs)
        self.assertNotIn("quota", pkgs)

    def test_prefix_listed_packages_are_tier_a(self):
        # #3948 blocker: only exact core-list names counted, so packages under a prefix line were skipped.
        pkgs = mutgate.tier_a_packages()
        for pkg in ("kernel/key", "kernel/privfile", "clerk/inbox/imapsmtp"):
            self.assertIn(pkg, pkgs)
            diff = DIFF.replace("broker/hint/", f"broker/{pkg}/")
            self.assertEqual(mutgate.claimed(diff), [pkg])

    def test_tier_a_packages_match_risk_tier_on_every_package(self):
        # Every .go file, not a made-up name, through the tier rule premerge uses: a package is
        # in the set when any of its files is tier A (#3948 Security delta 2).
        broker = ROOT / "broker"
        pkgs = set(mutgate.tier_a_packages())
        for d in sorted({f.parent for f in broker.rglob("*.go")}):
            rel = d.relative_to(broker).as_posix()
            if rel == "." or {"vendor", "testdata"} & set(rel.split("/")):
                continue
            want = any(mutgate.risk_tier.tier_of(f.relative_to(ROOT).as_posix())[0] == "A" for f in d.glob("*.go"))
            self.assertEqual(rel in pkgs, want, rel)

    def test_one_tier_a_file_puts_its_package_in(self):
        # A tier rule naming one .go file in an otherwise tier-B package must still count.
        with tempfile.TemporaryDirectory() as d:
            for name in ("a.go", "b.go"):
                (pathlib.Path(d) / "quota").mkdir(exist_ok=True)
                (pathlib.Path(d) / "quota" / name).write_text("package quota\n")
            real = mutgate.risk_tier.tier_of
            for one in ("broker/quota/a.go", "broker/quota/b.go"):
                mutgate.risk_tier.tier_of = lambda p, one=one: ("A", p) if p == one else ("B", p)
                try:
                    self.assertEqual(mutgate.tier_a_packages(pathlib.Path(d)), ["quota"], one)
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
            self.assertEqual(mutgate.tier_a_packages(pathlib.Path(d)), ["kernel/ok"])
        for odd in ("kernel/key+v2", "kernel/key~old", "kernel/a b", "kernel/$(x)"):
            with tempfile.TemporaryDirectory() as d:
                tree(d, ["kernel/ok", odd])
                with self.assertRaises(ValueError, msg=odd) as cm:
                    mutgate.tier_a_packages(pathlib.Path(d))
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
    def test_claimed_is_marked_tier_a_packages_only(self):
        self.assertEqual(mutgate.claimed(DIFF, tier_a=["hint", "mail"]), ["hint"])
        self.assertEqual(mutgate.claimed(DIFF, tier_a=["mail"]), [])
        self.assertEqual(mutgate.claimed(DIFF.replace("REQ:", "NOTE:"), tier_a=["hint"]), [])
        self.assertEqual(mutgate.claimed(DOCS_ONLY, tier_a=["hint"]), [])

    def test_claimed_covers_every_package_violations_reads(self):
        # Any tier-A package outside claimed() could never yield a violation, whatever survives
        # there. The real tier list, not an injected one, so a prefix-line package counts (#3948).
        pkgs = ["netguard", "kernel/privfile", "clerk/inbox/imapsmtp", "quota"]
        diff = "".join(DIFF.replace("broker/hint/", f"broker/{p}/") for p in pkgs)
        live = {p: [("hint.go", 11, "X")] for p in pkgs}
        tier_a = set(mutgate.tier_a_packages())
        found = {v[0] for v in mutgate.violations(diff, live)} & tier_a
        self.assertEqual(found, set(pkgs) - {"quota"})
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
        pkg = mutgate.tier_a_packages()[0]
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
        pkg = mutgate.tier_a_packages()[0]
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
        self.assertRegex(argv, r"/broker/hint -D HEAD~1 --config \S+ --exclude-files / -o D/out/hint\.json$")
        self.assertIn("+++ b/hint.go\n@@ -1,0 +2,2 @@", diff)
        self.assertNotIn("\n package hint\n", diff)  # no context line
        # A mutant gremlins skipped on a line the gate reads fails the run, not the gate empty.
        r, _ = self.run_diff_stub(skipped_line=3)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("gremlins skipped mutants on lines this diff adds in broker/hint/: [('hint.go', 3)]", r.stderr)

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
    def verify(self, results, req=True, src="package netguard\nvar a = 1 + 1\n"):
        """mutgate.py verify in a temp repo whose last commit adds broker/netguard/a.go line 2 (and a
        REQ marker unless req is False), on a results dir holding {file name: JSON or raw text}."""
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
            (pkg / "a_test.go").write_text("package netguard\n// %s: CRED-1\n" % ("REQ" if req else "NOTE"))
            git("add", "-A")
            git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "-m", "pr")
            res = pathlib.Path(d) / "res"
            res.mkdir()
            for name, data in results.items():
                # "mutants-0/netguard.json": one directory per artifact, as download-artifact lays them out.
                name = name if "/" in name else f"mutants-0/{name}"
                (res / name).parent.mkdir(exist_ok=True)
                (res / name).write_text(data if isinstance(data, str) else json.dumps(data))
            return subprocess.run([sys.executable, "-I", str(pathlib.Path(d) / "tools" / "mutgate.py"), "verify",
                                   str(res), "--git", "HEAD~1"], capture_output=True, text=True)

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
        self.assertIn("2 results for netguard", r.stderr)

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
                (pkg / "a_test.go").write_text("package sub\n// REQ: CRED-1\n")
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
            (self.result("SKIPPED"), "gremlins skipped mutants on lines this diff adds"),
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

    def test_no_claim_needs_no_result(self):
        r = self.verify({}, req=False)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)


GO_MOD = "module example.invalid/broker\n\ngo 1.22\n"
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

    def repo(self, d, base_src=BASE_SRC, pr_src=PR_SRC, test_src=TEST_SRC):
        git = lambda *a: subprocess.run(["git", "-C", d, *a], check=True, capture_output=True, text=True)
        shutil.copytree(ROOT / "tools", pathlib.Path(d) / "tools")
        shutil.copytree(ROOT / "broker" / "core", pathlib.Path(d) / "broker" / "core")
        (pathlib.Path(d) / "broker" / "go.mod").write_text(GO_MOD)
        pkg = pathlib.Path(d) / "broker" / "hint"
        pkg.mkdir()
        (pkg / "hint.go").write_text(base_src)
        git("init", "-q")
        git("add", "-A")
        git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "-m", "base")
        (pkg / "hint.go").write_text(pr_src)
        (pkg / "hint_test.go").write_text(test_src)
        git("add", "-A")
        git("-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-q", "-m", "pr")
        return pkg

    def mutgate(self, d, *args):
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
            def fake(binary, cwd, timeout):
                self.assertTrue(pathlib.Path(binary).is_file())  # the worker's own binary, kept for the rerun
                calls.append(pathlib.Path(binary).parent.name)
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
            finally:
                mutgate.BROKER, mutgate.run_tests = broker, run_tests

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
            def fake(binary, cwd, timeout):
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
        for body in (claimed, job(self.text, "mutants")):
            self.assertIn('          [ "$(git rev-parse HEAD^2)" = "$PR_HEAD" ] || '
                          '{ echo "::error::HEAD is not the merge of this PR\'s head"; exit 1; }\n', body)
            self.assertIn('echo "BASE=$(git rev-parse HEAD^1)" >> "$GITHUB_ENV"', body)
            self.assertIn("PR_HEAD: ${{ github.event.pull_request.head.sha }}", body)
            self.assertLess(body.index("HEAD^1"), body.index('--git "$BASE"'))
        self.assertIn("fetch-depth: 0", claimed)
        mutants = job(self.text, "mutants")
        # The package list comes from the claim, and an empty claim (a docs-only PR) runs no gremlins.
        self.assertIn("if: ${{ needs.claimed.outputs.packages != '[]' }}", mutants)
        self.assertIn("pkg: ${{ fromJSON(needs.claimed.outputs.packages) }}", mutants)
        self.assertIn("PKG: ${{ matrix.pkg }}", mutants)
        self.assertIn('python3 -I tools/mutgate.py run "$PKG" --out mutants --git "$BASE"', mutants)
        # #4573: the deletion pass adds to the same result, after gremlins wrote it.
        self.assertIn('python3 -I tools/mutgate.py delete "$PKG" --out mutants --git "$BASE"', mutants)
        self.assertLess(mutants.index("mutgate.py run"), mutants.index("mutgate.py delete"))
        self.assertNotIn("mutgate.py gate", self.text)  # the gate is `verify`, in the job no PR code reaches
        self.assertNotIn("${{ matrix.pkg }}\"", mutants)  # never interpolated into a script
        self.assertIn("gremlins@v0.6.0", mutants)
        self.assertIn("gremlins@v0.6.0", (ROOT / "tools" / "mutgate.py").read_text())
        self.assertNotIn("continue-on-error", self.text)

    def test_summary_fails_unless_the_claim_ran_and_each_package_passed(self):
        script = job(self.text, "mutgate").split("run: |\n", 1)[1]
        script = re.split(r"\n      [-#] ", script, maxsplit=1)[0]
        script = "\n".join(l[10:] for l in script.split("\n"))
        cases = [
            ("success", "[]", "skipped", 0),
            ("success", '["kernel"]', "success", 0),
            ("success", '["kernel"]', "failure", 1),
            ("success", '["kernel"]', "skipped", 1),
            ("success", "[]", "failure", 1),
            ("failure", "", "skipped", 1),
        ]
        for claimed, pkgs, mutants, want in cases:
            env = {"CLAIMED": claimed, "PACKAGES": pkgs, "MUTANTS": mutants, "PATH": "/usr/bin:/bin"}
            r = subprocess.run(["sh", "-ec", script], env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode != 0, bool(want), (claimed, pkgs, mutants, r.stdout, r.stderr))
        self.assertIn("if: ${{ !cancelled() }}", job(self.text, "mutgate"))
        self.assertIn("needs: [claimed, mutants]", job(self.text, "mutgate"))

    def test_only_the_mutants_jobs_run_pr_code_and_they_hand_on_data(self):
        # REV-CHK-mut-selftest (#4106): the PR's tests run in `mutants` and can write anything there,
        # so that job ends in an upload and decides nothing.
        mutants = job(self.text, "mutants")
        steps = mutants.split("\n      - ")
        self.assertIn("Gremlins on the package", steps[-4])
        self.assertIn("Statement deletions on the package", steps[-3])
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
            self.assertIn(restore, body.replace("        if: ${{ needs.claimed.outputs.packages != '[]' }}\n", ""))
            self.assertLess(body.index("HEAD^1"), body.index("rm -rf tools"), name)
            self.assertLess(body.index("rm -rf tools"), body.index("python3 -I tools/mutgate.py"), name)
            self.assertEqual(body.count("python3 -I tools/mutgate.py"), 1, name)

    def test_mutgate_job_verifies_the_artifacts_from_a_fresh_checkout(self):
        body = job(self.text, "mutgate")
        steps = body.split("\n      - ")[1:]
        names = [st.split("\n", 1)[0] for st in steps]
        self.assertEqual(names, [
            "name: The claim ran and every claimed package passed",
            "uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2",
            "name: The base this merge commit was built on",
            "uses: actions/setup-go@924ae3a1cded613372ab5595356fb5720e22ba16  # v6.5.0",
            "uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093  # v4.3.0",
            "name: The base copy of the gate",
            "name: Gate (MUT-tierA)",
        ])
        for st in steps[1:]:
            self.assertIn("        if: ${{ needs.claimed.outputs.packages != '[]' }}\n", st)
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


if __name__ == "__main__":
    unittest.main()
