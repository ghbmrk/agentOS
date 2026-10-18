"""Tests for tools/ci_split.py and its wiring into ci.yml (CI-SHARD, #1868)."""
import io
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "tools"))
import ci_split  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
CI = ROOT / ".github" / "workflows" / "ci.yml"
M = ci_split.MODULE


def job(ci, name):
    body = ci[ci.index(f"\n  {name}:\n") + 1:]
    nxt = re.search(r"^  [a-z][a-z-]*:\n", body[1:], re.M)
    return body[:nxt.start() + 1] if nxt else body


def go_list():
    if not shutil.which("go"):
        return None
    r = subprocess.run(["go", "list", "./..."], cwd=ROOT / "broker", capture_output=True, text=True)
    return r.stdout.split() if r.returncode == 0 else None


class SplitTest(unittest.TestCase):
    """Every package runs on exactly one shard."""

    PKGS = [f"{M}/{p}" for p in ("pubid", "journal", "holder", "recall", "a", "b", "c", "d/e")]

    def assertExactCover(self, pkgs, parts):
        self.assertEqual(ci_split.gaps_and_duplicates(pkgs, parts), ([], [], []))
        self.assertEqual(sorted(p for part in parts for p in part), sorted(pkgs))

    def test_the_split_covers_the_list_exactly_once(self):
        for n in (1, 2, 3, 5, 20):
            self.assertExactCover(self.PKGS, ci_split.split(self.PKGS, n))

    def test_the_split_covers_the_brokers_go_list_exactly_once(self):
        pkgs = go_list()
        if pkgs is None:
            self.skipTest("no go toolchain")
        parts = ci_split.split(pkgs, 3)
        self.assertExactCover(pkgs, parts)
        self.assertTrue(all(parts), "an empty shard")

    def test_every_weighted_package_exists(self):
        # A renamed or deleted package would leave its weight behind and unbalance the shards.
        pkgs = go_list()
        if pkgs is None:
            self.skipTest("no go toolchain")
        names = {p.removeprefix(M).lstrip("/") for p in pkgs}
        self.assertEqual(sorted(set(ci_split.WEIGHTS) - names), [])

    def test_a_new_package_lands_on_one_shard(self):
        parts = ci_split.split(self.PKGS + [f"{M}/brandnew"], 3)
        self.assertEqual(sum(part.count(f"{M}/brandnew") for part in parts), 1)

    def test_the_split_is_a_function_of_the_set(self):
        self.assertEqual(ci_split.split(self.PKGS, 3), ci_split.split(list(reversed(self.PKGS)), 3))

    def test_the_heaviest_packages_go_to_different_shards(self):
        parts = ci_split.split(self.PKGS, 3)
        for heavy in ("pubid", "journal", "holder"):
            self.assertEqual(sum(f"{M}/{heavy}" in part for part in parts), 1)
        self.assertEqual(len({i for i, part in enumerate(parts) for p in part
                              if p in {f"{M}/pubid", f"{M}/journal", f"{M}/holder"}}), 3)

    def test_a_duplicate_or_an_empty_list_or_no_shards_is_refused(self):
        with self.assertRaises(ValueError):
            ci_split.split(self.PKGS + [self.PKGS[0]], 3)
        with self.assertRaises(ValueError):
            ci_split.split(self.PKGS, 0)
        with self.assertRaises(ValueError):
            ci_split.read_packages(io.StringIO("\n \n"))

    def test_check_finds_a_gap_a_duplicate_and_an_unlisted_package(self):
        gaps, dups, extra = ci_split.gaps_and_duplicates(["x", "y", "z"], [["x", "w"], ["x"]])
        self.assertEqual((gaps, dups, extra), (["y", "z"], ["x"], ["w"]))

    def test_the_shards_together_print_the_list(self):
        pkgs = self.PKGS
        out = []
        for i in range(3):
            buf = io.StringIO()
            sys.stdin, old = io.StringIO("\n".join(pkgs) + "\n"), sys.stdin
            try:
                with redirect_stdout(buf):
                    self.assertEqual(ci_split.main(["shard", "--shards", "3", "--index", str(i)]), 0)
            finally:
                sys.stdin = old
            out += buf.getvalue().split()
        self.assertEqual(sorted(out), sorted(pkgs))

    def test_a_shard_lists_its_heaviest_package_first(self):
        # go test starts packages in command-line order, so the longest must lead.
        sys.stdin, old = io.StringIO("\n".join(self.PKGS) + "\n"), sys.stdin
        buf = io.StringIO()
        try:
            with redirect_stdout(buf):
                self.assertEqual(ci_split.main(["shard", "--shards", "1", "--index", "0"]), 0)
        finally:
            sys.stdin = old
        out = buf.getvalue().split()
        self.assertEqual(out[:4], [f"{M}/{p}" for p in ("pubid", "journal", "holder", "recall")])
        self.assertEqual([ci_split.weight(p) for p in out], sorted((ci_split.weight(p) for p in out), reverse=True))


class PeaksTest(unittest.TestCase):
    """The fuzz-peaks measurement is skipped only for a PR that misses all its inputs."""

    DEPS = [f"{M}/loop7", f"{M}/loop7.test", f"{M}/sockets", f"{M}/sockets [{M}/sockets.test]",
            f"{M}/cgroup", "fmt", "golang.org/x/sys/unix"]

    def need(self, event, *changed, deps=DEPS):
        return ci_split.peaks_needed(event, list(changed), deps)

    def test_a_push_or_any_non_pr_event_measures(self):
        for event in ("push", "workflow_dispatch", "schedule", "merge_group", ""):
            self.assertTrue(self.need(event, "README.md"), event)

    def test_a_pr_that_misses_every_input_skips(self):
        self.assertFalse(self.need("pull_request", "README.md", "docs/OPERATING.md", "broker/pubid/x.go",
                                   "broker/sockets2/x.go", "tools/trace.py"))

    def test_a_pr_touching_an_input_measures(self):
        for path in ("broker/sockets/x.go", "broker/sockets/testdata/fuzz/FuzzRequest/seed",
                     "broker/loop7/peak_test.go", "broker/cgroup/cgroup.go", "image/fuzz-targets.json",
                     "image/build.sh", "broker/go.mod", "broker/go.sum", "broker/vendor/x/y.go",
                     ".github/workflows/ci.yml", "tools/ci_split.py"):
            self.assertTrue(self.need("pull_request", "README.md", path), path)

    def test_an_empty_change_or_no_dependency_list_measures(self):
        self.assertTrue(self.need("pull_request"))
        self.assertTrue(self.need("pull_request", "", " "))
        self.assertTrue(self.need("pull_request", "README.md", deps=[]))
        self.assertTrue(self.need("pull_request", "README.md", deps=["fmt"]))

    def test_an_unreadable_file_measures(self):
        with tempfile.TemporaryDirectory() as d:
            changed = pathlib.Path(d) / "changed"
            changed.write_text("README.md\n")
            buf = io.StringIO()
            with redirect_stdout(buf):
                ci_split.main(["peaks", "--event", "pull_request", "--deps", str(pathlib.Path(d) / "none"),
                               "--changed", str(changed)])
            self.assertEqual(buf.getvalue().strip(), "run")
            deps = pathlib.Path(d) / "deps"
            deps.write_text("\n".join(self.DEPS))
            buf = io.StringIO()
            with redirect_stdout(buf):
                ci_split.main(["peaks", "--event", "pull_request", "--deps", str(deps), "--changed", str(changed)])
            self.assertEqual(buf.getvalue().strip(), "skip")


class QuotedPathTest(unittest.TestCase):
    """A changed path git quotes (non-ASCII, `"`, `\\`, control bytes) never makes the step skip."""

    DEPS = PeaksTest.DEPS

    def git(self, d, *args):
        return subprocess.run(["git", *args], cwd=d, check=True, capture_output=True).stdout

    def decide(self, changed_bytes):
        with tempfile.TemporaryDirectory() as d:
            changed = pathlib.Path(d) / "changed"
            changed.write_bytes(changed_bytes)
            deps = pathlib.Path(d) / "deps"
            deps.write_text("\n".join(self.DEPS))
            buf = io.StringIO()
            with redirect_stdout(buf):
                ci_split.main(["peaks", "--event", "pull_request", "--deps", str(deps), "--changed", str(changed)])
            return buf.getvalue().strip()

    def diffs(self, *names):
        """(default `git diff --name-only`, ci.yml's `-z` form) for a commit adding `names`."""
        if not shutil.which("git"):
            self.skipTest("no git")
        with tempfile.TemporaryDirectory() as d:
            env = ["-c", "user.name=t", "-c", "user.email=t@example.invalid"]
            self.git(d, "init", "-q")
            (pathlib.Path(d) / "README.md").write_text("x\n")
            self.git(d, "add", "README.md")
            self.git(d, *env, "commit", "-qm", "base")
            for n in names:
                f = pathlib.Path(d) / n
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_text("package loop7\n")
            self.git(d, "add", "-A")
            self.git(d, *env, "commit", "-qm", "change")
            plain = self.git(d, "-c", "core.quotePath=true", "diff", "--no-renames", "--name-only", "HEAD^1", "HEAD")
            z = self.git(d, "-c", "core.quotePath=false", "diff", "-z", "--no-renames", "--name-only",
                         "HEAD^1", "HEAD")
            return plain, z

    def test_a_quoted_path_in_a_fuzz_target_package_measures(self):
        plain, z = self.diffs("broker/loop7/\u00fc.go", 'broker/loop7/a"b.go')
        self.assertIn(b'"broker/loop7/\\303\\274.go"', plain)  # git did quote it
        self.assertEqual(self.decide(plain), "run")
        self.assertEqual(self.decide(z), "run")
        for n in ("broker/loop7/\u00fc.go", 'broker/loop7/a"b.go'):
            self.assertIn(n.encode(), z.split(b"\0"))

    def test_a_quoted_path_anywhere_measures(self):
        plain, z = self.diffs("docs/\u00fc.md")
        self.assertTrue(plain.startswith(b'"'))
        self.assertEqual(self.decide(plain), "run")  # fail safe: never unquote
        self.assertEqual(self.decide(z), "skip")     # -z names it exactly, and it is no input

    def test_nul_separated_paths_are_read_whole(self):
        self.assertEqual(ci_split.changed_paths("a\0broker/loop7/x\ny.go\0"), ["a", "broker/loop7/x\ny.go", ""])
        self.assertTrue(ci_split.peaks_needed("pull_request", ['"docs/x"'], self.DEPS))
        self.assertEqual(self.decide(b"README.md\0broker/loop7/x\ny.go\0"), "run")
        self.assertEqual(self.decide(b"README.md\0docs/\xff.md\0"), "skip")


class WiringTest(unittest.TestCase):
    """ci.yml runs the split it tests, and the peaks filter fails toward measuring."""

    def setUp(self):
        self.ci = CI.read_text()

    def test_the_matrix_is_the_range_of_the_shard_count(self):
        race = job(self.ci, "broker-race")
        counts = set(re.findall(r"ci_split\.py (?:check|shard) --shards (\d+)", race))
        self.assertEqual(len(counts), 1, counts)
        n = int(counts.pop())
        shards = re.search(r"^\s+shard: \[([\d, ]+)\]", race, re.M).group(1)
        self.assertEqual([int(x) for x in shards.split(",")], list(range(n)))
        self.assertIn("fail-fast: false", race)
        # Each shard checks the whole split before running its part.
        self.assertLess(race.index("ci_split.py check"), race.index("go test -race"))
        self.assertIn('go test -race -count=1 $(cat "$RUNNER_TEMP/shard")', race)
        self.assertIn('AGENTOS_REQUIRE_SWTPM: "1"', race)
        # D29: the corpus goes before the main-only cache save, as in broker-checks and machines.
        drop = race.index('run: rm -rf "$(go env GOCACHE)/fuzz"')
        self.assertLess(race.index("go test -race"), drop)
        self.assertLess(drop, race.index("actions/cache/save"))

    def test_the_race_tests_run_only_in_the_shards(self):
        self.assertEqual(self.ci.count("go test -race"), 1)
        self.assertNotIn("go test -race -count=1 ./...", self.ci)

    def test_broker_passes_only_when_its_parts_pass(self):
        broker = job(self.ci, "broker")
        self.assertIn("needs: [scope, broker-race, broker-checks]", broker)
        self.assertIn("RACE: ${{ needs.broker-race.result }}", broker)
        self.assertIn("CHECKS: ${{ needs.broker-checks.result }}", broker)
        self.assertIn('[ "$RACE" = success ] && [ "$CHECKS" = success ]', broker)

    def test_the_broker_checks_keep_their_steps(self):
        checks = job(self.ci, "broker-checks")
        for step in ("gofmt -l", "go vet ./...", "-run '^TestOP2(SameEffectModel|Model.*)$' -v ./journal",
                     "tools/fuzzrun.py", 'rm -rf "$(go env GOCACHE)/fuzz"'):
            self.assertIn(step, checks, step)

    def test_the_op2_model_step_caps_its_parallel_subtests(self):
        # The five model configurations are parallel subtests; the default -parallel
        # (GOMAXPROCS) runs four searches at once and the step was killed (exit 143).
        checks = job(self.ci, "broker-checks")
        step = checks[checks.index("- name: OP-2 same-effect model"):]
        step = step[:step.index("- name: Fuzz the socket")]
        self.assertIn("go test -count=1 -timeout 20m -parallel 2 -run ", step)

    def test_the_peaks_step_skips_only_on_an_exact_skip(self):
        machines = job(self.ci, "machines")
        self.assertIn("fetch-depth: 2", machines)
        step = machines[machines.index("- name: Fuzz leaf memory peaks (P3-4b-3r-confine-r1)"):]
        self.assertIn("        if: steps.peaks.outputs.run != 'skip'\n", step[:step.index("run: |")])
        dec = machines[machines.index("id: peaks"):machines.index("- name: Fuzz leaf memory peaks (P3")]
        self.assertIn("run=run", dec)
        self.assertIn('[ "$run" = skip ] || run=run', dec)
        self.assertIn('[ "$EVENT" = pull_request ]', dec)
        # The base commit's rule decides, as scope.yml does for ci_scope.py.
        self.assertIn("git show HEAD^1:tools/ci_split.py", dec)
        self.assertIn("git -c core.quotePath=false diff -z --no-renames --name-only HEAD^1 HEAD", dec)
        self.assertNotIn("cannot change the rule", dec)
        self.assertIn('python3 -I "$t/ci_split.py" peaks', dec)
        self.assertNotIn("paths:", self.ci[:self.ci.index("\njobs:\n")])


if __name__ == "__main__":
    unittest.main()
