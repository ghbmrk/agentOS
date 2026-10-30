"""tools/mutgate.py: the REQ-claim gate over gremlins results (MUT-tierA, #1814), and the
workflow that runs it on pull requests (REV-CHK-mut, #3899).

Gremlins itself is not run: the gate reads its JSON, so fixtures stand in for it.
"""
import json
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
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

    def test_survivors_reads_lived_only_and_nested_package_names(self):
        with tempfile.TemporaryDirectory() as d:
            data = {"files": [{"file_name": "a.go", "mutations": [
                {"type": "T", "status": "LIVED", "line": 3},
                {"type": "T", "status": "KILLED", "line": 4}]}]}
            (pathlib.Path(d) / "vm__gvisor.json").write_text(json.dumps(data))
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
        self.assertTrue(argv.endswith("/broker/hint -D HEAD~1 -o D/out/hint.json"), argv)
        self.assertIn("+++ b/hint.go\n@@ -1,0 +2,2 @@", diff)
        self.assertNotIn("\n package hint\n", diff)  # no context line
        # A mutant gremlins skipped on a line the gate reads fails the run, not the gate empty.
        r, _ = self.run_diff_stub(skipped_line=3)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("gremlins skipped mutants on lines this diff adds in broker/hint/: [('hint.go', 3)]", r.stderr)


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
        self.assertIn('python3 -I tools/mutgate.py gate mutants --git "$BASE"', mutants)
        self.assertNotIn("${{ matrix.pkg }}\"", mutants)  # never interpolated into a script
        self.assertIn("gremlins@v0.6.0", mutants)
        self.assertIn("gremlins@v0.6.0", (ROOT / "tools" / "mutgate.py").read_text())
        self.assertNotIn("continue-on-error", self.text)

    def test_summary_fails_unless_the_claim_ran_and_each_package_passed(self):
        script = job(self.text, "mutgate").split("run: |\n", 1)[1]
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


if __name__ == "__main__":
    unittest.main()
