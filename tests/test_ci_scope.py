"""Tests for tools/ci_scope.py and its wiring into the workflows (CI-docs)."""
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


class ScopeTest(unittest.TestCase):
    def test_record_documents_are_records(self):
        for p in ("BOARD.md", "LATER.md", "LEDGER.md", "DECISIONS.md", "METRICS.md", "TRACE.md",
                  "docs/MARK-QUEUE.md", "reviews/security/2026-10-12-pr1082.md", "reviews/l3/README.md",
                  "decisions/D-098.md", "briefs/DOC-6.md", "handoff/CURRENT.md"):
            self.assertEqual(ci_scope.scope_of([p]), ("records", None), p)

    def test_prose_no_test_reads_is_a_record(self):
        # REQ: CI-PATHS
        for p in ("README.md", "PLAN.md", "docs/conv-3-triage.md", "docs/conv-5-uncovered.md",
                  "docs/development/trial-measurements.md", "docs/learning/new.md",
                  "docs/security/provider-worker-isolation.md", "docs/security/deep/x.md"):
            self.assertEqual(ci_scope.scope_of([p]), ("records", None), p)

    def test_prose_a_test_or_tool_reads_stays_full(self):
        # REQ: CI-PATHS
        # owners-guide.md: broker/hostchange's Go test reads it. SPEC.md: specslice tests.
        # OPERATING.md: risk_tier tests. LANES.md: board.py and lane-gate. CLAUDE/AGENTS: doclint rules.
        for p in ("docs/owners-guide.md", "SPEC.md", "docs/OPERATING.md", "docs/LANES.md", "CLAUDE.md",
                  "AGENTS.md", "docs/security/provider-worker-surfaces.csv", "docs/development/x.sh",
                  "docs/new-top-level.md", "docs/BOARD-HISTORY.md"):
            self.assertEqual(ci_scope.scope_of([p]), ("full", p), p)

    def test_the_records_pr_that_cost_97_minutes_is_records_only(self):
        # #1083's files.
        paths = ["BOARD.md", "LATER.md", "reviews/potency/2026-10-12-pr1082.md",
                 "reviews/security/2026-10-12-pr1082.md", "reviews/ux/2026-10-12-pr1082.md"]
        self.assertEqual(ci_scope.scope_of(paths)[0], "records")

    def test_anything_else_is_full(self):
        for p in ("SPEC.md", "CLAUDE.md", "AGENTS.md", "docs/OPERATING.md",
                  "docs/LANES.md", "broker/go.mod", "broker/vault/vault.go", "broker/vault/ASSUMPTIONS.md",
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
        for job in ("broker", "machines", "hostcheck"):
            self.assertIn(f"  {job}:\n    needs: scope\n"
                          "    if: ${{ !cancelled() && needs.scope.outputs.records != 'true' }}\n", ci, job)
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
        for job in ("broker", "machines"):
            body = ci[ci.index(f"\n  {job}:\n"):]
            body = body[:body.index("\n  hostcheck:\n")] if job == "machines" else body[:body.index("\n  machines:\n")]
            self.assertIn("uses: actions/cache@", body, job)
            self.assertIn(f"key: go-build-{job}-", body, job)
        self.assertIn("tests.test_risk_tier tests.test_product_name -v", ci)

    def test_assurance_skips_only_on_records(self):
        wf = (WORKFLOWS / "assurance.yml").read_text()
        self.assertIn("uses: ./.github/workflows/scope.yml", wf)
        self.assertEqual(wf.count("needs.scope.outputs.records != 'true'"), wf.count("\n    runs-on:"))


if __name__ == "__main__":
    unittest.main()
