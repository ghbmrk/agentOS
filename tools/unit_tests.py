#!/usr/bin/env python3
"""Run every tests/test*.py module in its own process tree under strace, several at once (CI-par).

ci.yml's unit-test step. Each module runs as `python -m unittest discover -s tests -p <module>.py
-v` under `strace -f -y`, which writes <dir>/<module>.trace for tests/records_audit.py
(CI-PATHS) and tests/clash_audit.py; only the number running at a time changes. A module in
SPLIT runs as that many shards at once, each with about an equal share of the module's expected
time (SLOW_TESTS) and its own <module>@<k>.trace. A unit's output is buffered and printed whole,
in name order, so logs do not interleave; a line per finished unit shows progress meanwhile.
The longest units start first (SECONDS, then file size), and the step prints each unit's wall
time and the critical path: the worker that finished last and what it ran.
Exit 1 if any unit failed or did not run, or if the longest unit is more than LONG_POLE times
the step's ideal time (all units' time over the jobs): that one unit then sets the step's
length, so split it (SPLIT). A module listed in SERIAL runs alone after the pool drains: one
that cannot share the runner with another module goes there, with its reason.

    python3 tools/unit_tests.py TRACE_DIR [--jobs N]
"""
import argparse
import concurrent.futures
import os
import pathlib
import subprocess
import sys
import threading
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
# bind: a fixed port or socket name shared by two modules is a clash (tests/clash_audit.py).
STRACE = ["strace", "-f", "--seccomp-bpf", "-q", "-y", "-e", "trace=open,openat,openat2,bind", "-e", "signal=none"]
# Modules that must not overlap another module, with why. Empty until a clash is seen.
SERIAL = {}
# Modules run as N shards at once. test_image alone took 741 s of the 742 s step (#4331).
SPLIT = {"test_image": 4}
# A split module's tests that take far longer than the rest, in seconds, so that assign spreads
# them over the shards (measured in a shard's "Slowest test durations"); any other takes DEFAULT_TEST.
SLOW_TESTS = {"test_image.DiffOracleTest.test_allowlist_coverage_fails_on_a_harmful_group": 92,
              "test_image.DiffOracleTest.test_oracles_fail_when_their_subject_is_broken": 76,
              "test_image.TmpfilesDiffTest.test_passed_lines_change_nothing_guarded": 44,
              "test_image.TmpfilesTest.test_review_probes_are_refused": 20,
              "test_image.ConfFilesTest.test_a_link_through_what_the_box_mounts_is_refused": 12}
DEFAULT_TEST = 0.5
# Seconds per module on the CI runner (checks job of #4308, 2026-10-31), for ordering only: a
# module not listed starts after these, biggest file first. A shard is its module's time over n.
SECONDS = {"test_image": 741, "test_image_keeper": 169, "test_slice_inbox_slice": 101,
           "test_image_noexec": 82, "test_premerge": 51, "test_slice_boot": 46,
           "test_image_drivers": 31, "test_image_imapconn": 22, "test_boot_net": 19,
           "test_mutgate": 15, "test_trusted_base": 15, "test_root_tests": 14,
           "test_risk_tier_custody": 13, "test_fuzzrun": 12, "test_require_ran": 11}
# git status and diff refresh the worktree's index under .git/index.lock as a side effect; two
# units doing so at once in the shared worktree is a clash (tests/clash_audit.py). Without the
# optional lock, any write left there is a git command that changes the index: a real clash.
ENV = {**os.environ, "GIT_OPTIONAL_LOCKS": "0"}
LONG_POLE = 1.25
FLOOR = 60  # seconds: a unit shorter than this never fails the long-pole check


def modules(root=ROOT):
    return sorted(p.stem for p in (root / "tests").glob("test*.py"))


def units(names):
    """The units the pool runs: a module, or its shards `<module>@<k>` for k in 1..SPLIT[module]."""
    return [u for m in names for u in ([f"{m}@{k}" for k in range(1, SPLIT[m] + 1)] if m in SPLIT else [m])]


def module_of(unit):
    return unit.split("@")[0]


def command(unit, trace_dir):
    module, _, k = unit.partition("@")
    if k:
        run = [sys.executable, str(ROOT / "tools" / "unit_tests.py"), "--shard", f"{k}/{SPLIT[module]}", module]
    else:
        run = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", f"{module}.py", "-v"]
    return [*STRACE, "-o", str(pathlib.Path(trace_dir) / f"{unit}.trace"), *run]


def flatten(suite):
    for t in suite:
        if isinstance(t, unittest.TestSuite):
            yield from flatten(t)
        else:
            yield t


def assign(ids, n):
    """Split test ids into n shards of about equal expected time: longest first (SLOW_TESTS,
    else DEFAULT_TEST seconds), each to the least-loaded shard. Each shard keeps load order. The
    same ids give the same split in every process, so the shards together run each test once."""
    load = [0.0] * n
    out = [[] for _ in range(n)]
    for i in sorted(range(len(ids)), key=lambda i: (-SLOW_TESTS.get(ids[i], DEFAULT_TEST), i)):
        s = min(range(n), key=lambda s: (load[s], s))
        out[s].append(i)
        load[s] += SLOW_TESTS.get(ids[i], DEFAULT_TEST)
    return [[ids[i] for i in sorted(shard)] for shard in out]


def shard(module, k, n):
    """Run shard k (1..n) of module (its tests as assign splits them), as `python -m unittest
    discover -s tests -p <module>.py -v` would load and run them, with its slowest tests' times."""
    sys.path[0] = os.getcwd()  # as under -m, not this file's directory
    tests = list(flatten(unittest.defaultTestLoader.discover("tests", pattern=f"{module}.py")))
    ids = [t.id() for t in tests]
    want = set(assign(ids, n)[k - 1])
    mine = [t for t in tests if t.id() in want]
    print(f"shard {k}/{n} of {module}: {len(mine)} of {len(tests)} tests", file=sys.stderr)
    result = unittest.TextTestRunner(verbosity=2, warnings="default", durations=10).run(unittest.TestSuite(mine))
    return 0 if mine and result.wasSuccessful() else 1


def run_one(unit, trace_dir, root=ROOT):
    start = time.monotonic()
    p = subprocess.run(command(unit, trace_dir), cwd=root, stdin=subprocess.DEVNULL, env=ENV,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return unit, p.returncode, time.monotonic() - start, p.stdout.decode("utf-8", "replace")


def size(module, root=ROOT):
    try:
        return (root / "tests" / f"{module}.py").stat().st_size
    except OSError:
        return 0


def expected(unit):
    m = module_of(unit)
    return SECONDS.get(m, 0) / SPLIT.get(m, 1)


def run(names, trace_dir, jobs, runner=run_one, progress=lambda line: print(line, end="", flush=True),
        lanes=None):
    """Run names' units (SERIAL ones last, one at a time) and return {unit: (rc, seconds, output)}.
    lanes, if given, gets [(worker, unit)] in finishing order."""
    all_units = units(names)
    pooled = sorted((u for u in all_units if module_of(u) not in SERIAL), key=lambda u: (-expected(u), -size(module_of(u)), u))
    results = {}
    lock = threading.Lock()
    lanes = [] if lanes is None else lanes

    def done(unit, rc, secs, out, lane):
        with lock:
            results[unit] = (rc, secs, out)
            lanes.append((lane, unit))
            progress(f"{len(results)}/{len(all_units)} {unit} {'ok' if rc == 0 else 'FAILED'} {secs:.0f}s\n")

    def pooled_run(unit):
        done(*runner(unit, trace_dir), threading.current_thread().name)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        for f in concurrent.futures.as_completed([pool.submit(pooled_run, u) for u in pooled]):
            f.result()
    for u in all_units:
        if module_of(u) in SERIAL:
            done(*runner(u, trace_dir), "serial")
    return results


def critical_path(results, lanes):
    """The pool worker whose units took longest in all, then the SERIAL units: [(unit, seconds)]."""
    per = {}
    for lane, unit in lanes:
        if lane != "serial":
            per.setdefault(lane, []).append(unit)
    worst = max(per.values(), key=lambda us: sum(results[u][1] for u in us), default=[])
    return [(u, results[u][1]) for u in worst + [u for lane, u in lanes if lane == "serial"]]


def long_pole(results, jobs):
    """The longest unit if it is over LONG_POLE times the ideal step (all time over jobs) and over FLOOR."""
    if not results:
        return None
    unit = max(results, key=lambda u: results[u][1])
    secs = results[unit][1]
    ideal = sum(r[1] for r in results.values()) / max(1, jobs)
    return (unit, secs, ideal) if secs > FLOOR and secs > LONG_POLE * ideal else None


def report(names, results, write=sys.stdout.write, jobs=1, lanes=(), wall=None):
    expect = units(names)
    failed = [u for u in expect if u not in results or results[u][0] != 0]
    for u in expect:
        rc, secs, out = results.get(u, (None, 0.0, "did not run\n"))
        write(f"::group::{u} ({'ok' if rc == 0 else 'FAILED'}, {secs:.0f}s)\n{out}::endgroup::\n")
    write("unit times, slowest first:\n")
    for u in sorted(results, key=lambda u: -results[u][1]):
        write(f"  {results[u][1]:7.1f}s  {u}{'  FAILED' if u in failed else ''}\n")
    total = sum(r[1] for r in results.values())
    path = critical_path(results, lanes)
    write(f"{total:.0f}s of tests over {jobs} jobs: {total / max(1, jobs):.0f}s ideal"
          + (f", {wall:.0f}s wall" if wall is not None else "") + "\n")
    write(f"critical path {sum(s for _, s in path):.0f}s: " + ", ".join(f"{u} {s:.0f}s" for u, s in path) + "\n")
    for u in failed:
        write(f"::error::{u} failed\n")
    pole = long_pole(results, jobs)
    if pole:
        write(f"::error::{pole[0]} took {pole[1]:.0f}s, over {LONG_POLE} times the step's ideal {pole[2]:.0f}s: "
              f"split it into more shards (tools/unit_tests.py SPLIT)\n")
    return 1 if failed or pole else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("trace_dir", nargs="?")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    ap.add_argument("--shard", nargs=2, metavar=("K/N", "MODULE"), help="run one shard (the pool's child)")
    args = ap.parse_args(argv)
    if args.shard:
        k, n = (int(x) for x in args.shard[0].split("/"))
        return shard(args.shard[1], k, n)
    if args.trace_dir is None:
        ap.error("TRACE_DIR is required")
    os.makedirs(args.trace_dir, exist_ok=True)
    names = modules()
    lanes = []
    start = time.monotonic()
    results = run(names, args.trace_dir, args.jobs, lanes=lanes)
    return report(names, results, jobs=args.jobs, lanes=lanes, wall=time.monotonic() - start)


if __name__ == "__main__":
    sys.exit(main())
