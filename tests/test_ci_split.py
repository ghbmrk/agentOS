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

    PKGS = [f"{M}/{p}" for p in ("guest", "journal", "holder", "update", "a", "b", "c", "d/e")]

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
        for heavy in ("guest", "journal", "holder"):
            self.assertEqual(sum(f"{M}/{heavy}" in part for part in parts), 1)
        self.assertEqual(len({i for i, part in enumerate(parts) for p in part
                              if p in {f"{M}/guest", f"{M}/journal", f"{M}/holder"}}), 3)

    def test_kernel_sim_runs_alone_on_the_last_shard(self):
        # CI-race-sim-alone (#6582): beside decoy/match, enforcer/nft and agentos-enroll, which
        # weighed 1, kernel/sim ran 970 s of its 25-minute timeout and sometimes ran out.
        sim = f"{M}/kernel/sim"
        pkgs = self.PKGS + [sim]
        for n in (2, 3, 5):
            parts = ci_split.split(pkgs, n)
            self.assertExactCover(pkgs, parts)
            self.assertEqual(parts[-1], [sim], n)
        # One shard runs everything; a list without kernel/sim leaves no shard empty for it.
        self.assertEqual(ci_split.split(pkgs, 1), [sorted(pkgs)])
        self.assertTrue(all(ci_split.split(self.PKGS, 3)))

    def test_kernel_sim_is_alone_in_the_brokers_split(self):
        pkgs = go_list()
        if pkgs is None:
            self.skipTest("no go toolchain")
        self.assertEqual(ci_split.split(pkgs, 3)[-1], [f"{M}/kernel/sim"])

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
        self.assertEqual(out[:4], [f"{M}/{p}" for p in ("journal", "holder", "guest", "update")])
        self.assertEqual([ci_split.weight(p) for p in out], sorted((ci_split.weight(p) for p in out), reverse=True))


class WiringTest(unittest.TestCase):
    """ci.yml runs the split it tests."""

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
        self.assertIn('go test -race -count=1 -timeout 25m $(cat "$RUNNER_TEMP/shard")', race)
        # An explicit timeout under the job's: go test's default 10 minutes flaked kernel/sim (#2623).
        self.assertIn("timeout-minutes: 30", race)
        self.assertIn('AGENTOS_REQUIRE_SWTPM: "1"', race)
        # D29: the corpus goes before the main-only cache save, as in broker-checks and machines.
        drop = race.index('run: rm -rf "$(go env GOCACHE)/fuzz"')
        self.assertLess(race.index("go test -race"), drop)
        self.assertLess(drop, race.index("actions/cache/save"))

    def test_the_race_tests_run_only_in_the_shards(self):
        self.assertEqual(self.ci.count("go test -race"), 1)
        self.assertNotIn("go test -race -count=1 ./...", self.ci)

    def test_no_broker_aggregator_job(self):
        # CI-par-5: main requires each shard and broker-checks by name, so no job gathers them.
        self.assertNotIn("\n  broker:\n", self.ci)
        self.assertNotIn("needs.broker-race", self.ci)

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
        step = step[:step.index("- name: Fuzz the broker")]
        self.assertIn("go test -count=1 -timeout 20m -parallel 2 -run ", step)

    def test_go_mod_vendor_is_retried_three_times_and_the_comparison_is_not(self):
        # #3977, as #3768: a Go proxy stream error retries `go mod vendor`; its third failure
        # fails the step. A real vendor mismatch fails at once, with no retry.
        checks = job(self.ci, "broker-checks")
        lines = checks[checks.index("- name: Vendored code equals the modules go.sum pins"):].splitlines()
        lines = lines[next(i for i, l in enumerate(lines) if l.strip() == "run: |") + 1:]
        script = "\n".join(l[10:] for l in lines[:lines.index(next(l for l in lines if not l.startswith(" " * 10)))])
        for fails, drift in ((0, False), (2, False), (3, False), (0, True), (1, True)):
            with self.subTest(fails=fails, drift=drift), tempfile.TemporaryDirectory() as tmp:
                d = pathlib.Path(tmp)
                # The go stub fails its first `fails` runs; the git stub reports a change when `drift`.
                (d / "go").write_text(
                    f"#!/bin/sh\necho \"go $*\" >> {d}/calls\n"
                    f"[ $(grep -cx 'go mod vendor' {d}/calls) -le {fails} ] && "
                    "{ echo 'stream error: INTERNAL_ERROR' >&2; exit 1; }\nexit 0\n")
                (d / "git").write_text(f"#!/bin/sh\necho \"git $*\" >> {d}/calls\n"
                                       + ("echo ' M vendor/x/y.go'\n" if drift else ""))
                (d / "sleep").write_text(f"#!/bin/sh\necho $1 >> {d}/slept\n")
                for stub in ("go", "git", "sleep"):
                    (d / stub).chmod(0o755)
                (d / "step.sh").write_text(script + "\n")
                r = subprocess.run(["bash", "--noprofile", "--norc", "-e", str(d / "step.sh")],
                                   env={"PATH": f"{d}:/usr/bin:/bin"}, capture_output=True, text=True)
                calls = (d / "calls").read_text().splitlines()
                slept = (d / "slept").read_text().split() if (d / "slept").exists() else []
                status = "git status --porcelain --untracked-files=all -- vendor"
                tries = min(fails + 1, 3)
                if fails < 3:
                    self.assertEqual(calls, ["go mod vendor"] * tries + [status])
                    self.assertEqual(r.returncode != 0, drift, r.stdout + r.stderr)
                    if drift:
                        self.assertIn("broker/vendor differs from go mod vendor", r.stderr)
                else:
                    self.assertNotEqual(r.returncode, 0)
                    self.assertEqual(calls, ["go mod vendor"] * 3)
                    self.assertIn("go mod vendor failed 3 times", r.stdout)
                    self.assertIn("stream error: INTERNAL_ERROR", r.stderr)
                self.assertEqual(slept, ["15", "30"][:min(fails, 2)])
                for t in range(1, min(fails, 3) + 1):
                    self.assertIn(f"try {t} of 3 failed: go mod vendor", r.stderr)


if __name__ == "__main__":
    unittest.main()
