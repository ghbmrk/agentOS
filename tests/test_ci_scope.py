"""Tests for tools/ci_scope.py and its wiring into the workflows (CI-docs)."""
import re
import pathlib
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))
import ci_scope  # noqa: E402

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
        for event in ("pull_request", "workflow_dispatch", "merge_group"):
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
        self.assertIn("tests.test_risk_tier tests.test_product_name tests.test_specslice tests.test_g1_scope.CheckTest tests.test_g1_scope.ListTest -v", ci)

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
