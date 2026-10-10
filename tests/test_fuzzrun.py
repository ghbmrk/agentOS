"""tools/fuzzrun.py: fuzz a target for a time budget as count-bound chunks (P1-4-flake-ci).

REQ: LOOP-7

A fake `go` (a Python script first on PATH) records its argv and, by environment variable,
sleeps per execution, fails, or hangs. Budgets are a fraction of a second; margins are wide.
"""
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
TOOL = ROOT / "tools" / "fuzzrun.py"

FAKE_GO = f"""#!{sys.executable}
import json, os, re, sys, time
d = os.environ["FAKE_DIR"]
log = os.path.join(d, "argv.jsonl")
k = sum(1 for _ in open(log)) + 1 if os.path.exists(log) else 1
with open(log, "a") as f:
    f.write(json.dumps(sys.argv[1:]) + "\\n")
n = int(re.search(r"-fuzztime\\s+(\\d+)x", " ".join(sys.argv)).group(1))
per = 1.0 / float(os.environ.get("FAKE_RATE", "1000"))
if k > int(os.environ.get("FAKE_SLOW_AFTER", "999")):
    per *= 2
if k == int(os.environ.get("FAKE_HANG_CHUNK", "0")):
    time.sleep(600)
if k == int(os.environ.get("FAKE_FAIL_CHUNK", "0")):
    print("--- FAIL: FuzzX (0.00s)\\n    Failing input written to testdata/fuzz/FuzzX/abc123", flush=True)
    sys.exit(1)
time.sleep(float(os.environ.get("FAKE_BUILD", "0")))  # the build, before go reports its run
time.sleep(n * per)
print(f'ok  \\tfake/x\\t{{n * per:.3f}}s', flush=True)
"""

COMMON = ["--pkg", "./sockets", "--target", "FuzzFrames", "--calibrate", "100", "--grace", "0.4"]


class Fake:
    def __init__(self, **env):
        self.tmp = tempfile.TemporaryDirectory()
        d = pathlib.Path(self.tmp.name)
        go = d / "go"
        go.write_text(FAKE_GO)
        go.chmod(go.stat().st_mode | stat.S_IXUSR)
        self.env = dict(os.environ, PATH=f"{d}{os.pathsep}{os.environ['PATH']}", FAKE_DIR=str(d),
                        **{k: str(v) for k, v in env.items()})
        self.env.pop("GITHUB_STEP_SUMMARY", None)
        self.dir = d

    def run(self, *args, **extra_env):
        env = dict(self.env, **extra_env)
        t = time.monotonic()
        p = subprocess.run([sys.executable, str(TOOL), *args], env=env, capture_output=True,
                           text=True, timeout=60)
        p.wall = time.monotonic() - t
        return p

    def argv(self):
        log = self.dir / "argv.jsonl"
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text().splitlines()]

    def close(self):
        self.tmp.cleanup()


def fuzztime(argv):
    return argv[argv.index("-fuzztime") + 1]


class FuzzrunTest(unittest.TestCase):
    def fake(self, **env):
        f = Fake(**env)
        self.addCleanup(f.close)
        return f

    def test_no_duration_ever(self):
        f = self.fake()
        p = f.run(*COMMON, "--budget", "0.8s", "--chunk", "0.25s")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        calls = f.argv()
        self.assertGreaterEqual(len(calls), 3)
        for argv in calls:
            self.assertRegex(fuzztime(argv), r"^\d+x$")
            self.assertEqual(argv[0], "test")
            self.assertIn("./sockets", argv)
            self.assertEqual(argv[argv.index("-fuzz") + 1], "^FuzzFrames$")
            self.assertEqual(argv[argv.index("-run") + 1], "^$")
            self.assertIn("-timeout", argv)

    def test_chunks_fill_the_budget(self):
        f = self.fake(FAKE_RATE=1000)
        p = f.run(*COMMON, "--budget", "0.8s", "--chunk", "0.3s")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertGreaterEqual(p.wall, 0.8)
        # at most the budget plus one chunk's cap (2.5 * 0.3 + 0.4) plus process startup
        self.assertLessEqual(p.wall, 0.8 + 2.5 * 0.3 + 0.4 + 1.5)
        calls = f.argv()
        self.assertEqual(fuzztime(calls[0]), "100x")
        n2 = int(fuzztime(calls[1])[:-1])
        # rate (about 1000/s, startup included so a little less) times the 0.3 s chunk
        self.assertTrue(150 <= n2 <= 300, n2)

    def test_a_slow_build_is_not_a_slow_target(self):
        # a cold build (0.5 s here) must not read as 200 execs/s: the rate is go's own run time
        f = self.fake(FAKE_RATE=1000, FAKE_BUILD=0.5)
        p = f.run(*COMMON, "--grace", "2", "--budget", "1.2s", "--chunk", "0.3s")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        n2 = int(fuzztime(f.argv()[1])[:-1])
        self.assertTrue(250 <= n2 <= 330, n2)

    def test_slowdown_is_not_a_hang(self):
        # chunk 2 onwards runs at half the rate: 2E, inside 2.5E + G, outside E + G
        f = self.fake(FAKE_RATE=1000, FAKE_SLOW_AFTER=1)
        p = f.run("--pkg", "./sockets", "--target", "FuzzFrames", "--calibrate", "200", "--grace", "0.1",
                  "--slack", "0.05", "--budget", "1.2s", "--chunk", "0.8s")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        self.assertNotIn("timeout", (p.stdout + p.stderr).lower())
        self.assertGreaterEqual(len(f.argv()), 2)

    def test_chunk_is_capped_at_four_times_the_previous(self):
        # calibration runs 0.1 s; with 1 s of budget and a 5 s chunk limit, chunk 2 is held to
        # about 4 x 0.1 s = 400 execs (uncapped it would be about 900), re-measuring the rate first
        f = self.fake(FAKE_RATE=1000)
        p = f.run(*COMMON, "--budget", "1s", "--chunk", "5s")
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        calls = f.argv()
        self.assertEqual(fuzztime(calls[0]), "100x")
        n2 = int(fuzztime(calls[1])[:-1])
        self.assertTrue(300 <= n2 <= 450, n2)
        self.assertGreaterEqual(len(calls), 3)
        n3 = int(fuzztime(calls[2])[:-1])
        self.assertLessEqual(n3, 4.5 * n2)

    def test_rate_is_logged(self):
        f = self.fake()
        summary = f.dir / "summary.md"
        p = f.run(*COMMON, "--budget", "0.6s", "--chunk", "0.25s", GITHUB_STEP_SUMMARY=str(summary))
        self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
        lines = [l for l in p.stdout.splitlines() if l.startswith("fuzzrun ")]
        chunks = [l for l in lines if re.search(r"chunk \d+: \d+ execs in [\d.]+s \(\d+/s\)$", l)]
        totals = [l for l in lines if " total" in l]
        self.assertEqual(len(chunks), len(f.argv()))
        self.assertEqual(len(totals), 1)
        self.assertIn("./sockets:FuzzFrames", totals[0])
        self.assertIn(totals[0], summary.read_text())

    def test_hang_is_loud(self):
        for chunk in (1, 2):
            with self.subTest(hang_chunk=chunk):
                f = self.fake(FAKE_HANG_CHUNK=chunk)
                budget, ch, grace = 0.5, 0.2, 0.4
                p = f.run("--pkg", "./sockets", "--target", "FuzzFrames", "--calibrate", "100",
                          "--grace", str(grace), "--slack", "0.5", "--budget", f"{budget}s", "--chunk", f"{ch}s")
                self.assertNotEqual(p.returncode, 0)
                msg = p.stdout + p.stderr
                self.assertIn("./sockets", msg)
                self.assertIn("FuzzFrames", msg)
                self.assertIn(f"chunk {chunk}", msg)
                # bound: 2.5 * E + G, killed a little above it, plus startup
                self.assertLessEqual(p.wall, (2.5 * ch + grace) * 1.05 + 0.5 + 2.0)
                self.assertEqual(len(f.argv()), chunk)

    def test_failure_stops(self):
        f = self.fake(FAKE_FAIL_CHUNK=2)
        p = f.run(*COMMON, "--budget", "2s", "--chunk", "0.3s")
        self.assertEqual(p.returncode, 1)
        self.assertEqual(len(f.argv()), 2)
        self.assertIn("Failing input written to testdata/fuzz/FuzzX/abc123", p.stdout + p.stderr)

    def test_budget_parsing(self):
        f = self.fake()
        for ok in ("20s", "3h", "1h30m", "90", "0.2s"):
            with self.subTest(ok=ok):
                p = subprocess.run([sys.executable, str(TOOL), "--check-budget", ok],
                                   capture_output=True, text=True, env=f.env)
                self.assertEqual(p.returncode, 0, p.stderr)
        for bad in ("3 hours", "-1s", "", "0", "1d", "s", "1m30"):
            with self.subTest(bad=bad):
                p = f.run("--pkg", "./sockets", "--target", "FuzzFrames", "--budget", bad)
                self.assertNotEqual(p.returncode, 0)
                self.assertEqual(f.argv(), [])


if __name__ == "__main__":
    unittest.main()
