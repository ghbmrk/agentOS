#!/usr/bin/env python3
"""Run every tests/test*.py module in its own process tree under strace, several at once (CI-par).

ci.yml's unit-test step. Each module runs as `python -m unittest discover -s tests -p <module>.py
-v` under `strace -f -y`, which writes <dir>/<module>.trace for tests/records_audit.py
(CI-PATHS) and tests/clash_audit.py (CI-par-clash); only the number running at a time
changes. A module's output is buffered and printed whole, in name order, so logs do not
interleave; a line per finished module shows progress meanwhile. The longest modules start
first (SECONDS, then file size), and the step prints each module's wall time, the ideal (all
modules' time over the jobs) and the critical path: the worker that finished last and what it ran.
Exit 1 if any module failed or did not run, or if the longest module runs over FLOOR seconds and
over LONG_POLE times the ideal: that one module then sets the step's length, so split it
(SPLIT). A module listed in SERIAL runs alone after the pool drains: one that cannot share the
runner with another module goes there, with its reason.
A module listed in SPLIT runs as `unit_tests.py --split <module>` under the same strace: that one
process forks worker processes, each taking the next test from a shared counter, so the module's
slowest test, not the module, sets the step's floor (CI-par-3). The trace is still one tree whose
first process exits after every worker, as tests/records_audit.py requires.

    python3 tools/unit_tests.py TRACE_DIR [--jobs N]
    python3 tools/unit_tests.py --split MODULE [--workers N]   (run from the repository root)
"""
import argparse
import concurrent.futures
import io
import multiprocessing
import multiprocessing.connection
import os
import pathlib
import subprocess
import sys
import threading
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
# bind: a fixed port or socket name shared by two modules is a clash (tests/clash_audit.py).
STRACE = ["strace", "-f", "--seccomp-bpf", "-q", "-y", "-e", "trace=open,openat,openat2,bind",
          "-e", "signal=none"]
# Modules that must not overlap another module, with why. Empty until a clash is seen.
SERIAL = {}
# Modules whose tests run across workers inside their one strace tree (CI-par-3), with why.
SPLIT = {"test_image": "about 10 min on a shared runner; one class is 45% of it, so it splits by test (#4332)"}
# Seconds per module on the CI runner (checks job of #4308, 2026-10-31), for ordering only: a
# module not listed starts after these, biggest file first.
SECONDS = {"test_image": 741, "test_image_keeper": 169, "test_slice_inbox_slice": 101,
           "test_image_noexec": 82, "test_premerge": 51, "test_slice_boot": 46,
           "test_image_drivers": 31, "test_image_imapconn": 22, "test_boot_net": 19,
           "test_mutgate": 15, "test_trusted_base": 15, "test_root_tests": 14,
           "test_risk_tier_custody": 13, "test_fuzzrun": 12, "test_require_ran": 11}
# git status and diff refresh the worktree's index under .git/index.lock as a side effect; two
# modules doing so at once in the shared worktree is a clash (tests/clash_audit.py). Without the
# optional lock, any write left there is a git command that changes the index: a real clash.
ENV = {**os.environ, "GIT_OPTIONAL_LOCKS": "0"}
LONG_POLE = 1.25
FLOOR = 60  # seconds: a module shorter than this never fails the long-pole check


def modules(root=ROOT):
    return sorted(p.stem for p in (root / "tests").glob("test*.py"))


def command(module, trace_dir, workers=None):
    if module in SPLIT:
        run = [sys.executable, str(pathlib.Path(__file__).resolve()), "--split", module,
               "--workers", str(workers or os.cpu_count() or 1)]
    else:
        run = [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", f"{module}.py", "-v"]
    return [*STRACE, "-o", str(pathlib.Path(trace_dir) / f"{module}.trace"), *run]


class _Claimed(unittest.TestSuite):
    """The tests this worker claims, one at a time, from a counter all workers share. TestSuite.run
    still sets up and tears down each class and module around the tests it is handed."""
    _cleanup = False  # run() would otherwise blank _tests[index], which this suite does not hold

    def __init__(self, tests, counter, ran):
        super().__init__()
        self.all, self.counter, self.ran = tests, counter, ran

    def __iter__(self):
        while True:
            with self.counter.get_lock():
                i = self.counter.value
                self.counter.value += 1
            if i >= len(self.all):
                return
            self.ran.append(i)
            yield self.all[i]


def _flatten(suite):
    for t in suite:
        if isinstance(t, unittest.TestSuite):
            yield from _flatten(t)
        else:
            yield t


def _worker(tests, counter, conn):
    out, ran = io.StringIO(), []
    ok = unittest.TextTestRunner(stream=out, verbosity=2).run(_Claimed(tests, counter, ran)).wasSuccessful()
    conn.send((ran, ok, out.getvalue()))
    conn.close()


def split(module, workers, write=sys.stdout.write):
    """Run tests/<module>.py, loaded as `unittest discover -s tests` loads it, across `workers`
    forked processes. 0 only if every test ran exactly once and passed."""
    tests = list(_flatten(unittest.defaultTestLoader.discover("tests", pattern=f"{module}.py")))
    if not tests:
        write(f"{module}: no tests found\n")
        return 1
    ctx = multiprocessing.get_context("fork")  # workers inherit the loaded tests
    counter = ctx.Value("q", 0)
    sys.stdout.flush()
    sys.stderr.flush()
    procs = {}
    for _ in range(max(1, min(workers, len(tests)))):
        recv, send = ctx.Pipe(duplex=False)
        p = ctx.Process(target=_worker, args=(tests, counter, send))
        p.start()
        send.close()
        procs[recv] = p
    got = {}
    pending = list(procs)
    while pending:
        for conn in multiprocessing.connection.wait(pending):
            pending.remove(conn)
            try:
                got[conn] = conn.recv()
            except EOFError:  # the worker died before it reported
                pass
    for p in procs.values():
        p.join()
    lost = sum(1 for conn, p in procs.items() if conn not in got or p.exitcode != 0)
    reports = list(got.values())
    ran = sorted(i for r in reports for i in r[0])
    for k, (_, _, out) in enumerate(reports, 1):
        write(f"--- {module} worker {k} of {len(procs)} ---\n{out}")
    missing = len(tests) - len(set(ran))
    write(f"{module}: {len(ran)} of {len(tests)} tests run across {len(procs)} workers"
          f"{f', {lost} worker(s) lost' if lost else ''}{f', {missing} not run' if missing else ''}\n")
    return 0 if not lost and ran == list(range(len(tests))) and all(r[1] for r in reports) else 1


def run_one(module, trace_dir, root=ROOT):
    start = time.monotonic()
    p = subprocess.run(command(module, trace_dir), cwd=root, stdin=subprocess.DEVNULL, env=ENV,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return module, p.returncode, time.monotonic() - start, p.stdout.decode("utf-8", "replace")


def size(module, root=ROOT):
    try:
        return (root / "tests" / f"{module}.py").stat().st_size
    except OSError:
        return 0


def run(names, trace_dir, jobs, runner=run_one, progress=lambda line: print(line, end="", flush=True),
        lanes=None):
    """Run names (SERIAL ones last, one at a time) and return {module: (rc, seconds, output)}.
    lanes, if given, gets [(worker, module)] in finishing order."""
    pooled = sorted((m for m in names if m not in SERIAL), key=lambda m: (-SECONDS.get(m, 0), -size(m), m))
    results = {}
    lock = threading.Lock()
    lanes = [] if lanes is None else lanes

    def done(module, rc, secs, out, lane):
        with lock:
            results[module] = (rc, secs, out)
            lanes.append((lane, module))
            progress(f"{len(results)}/{len(names)} {module} {'ok' if rc == 0 else 'FAILED'} {secs:.0f}s\n")

    def pooled_run(module):
        done(*runner(module, trace_dir), threading.current_thread().name)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        for f in concurrent.futures.as_completed([pool.submit(pooled_run, m) for m in pooled]):
            f.result()
    for m in names:
        if m in SERIAL:
            done(*runner(m, trace_dir), "serial")
    return results


def critical_path(results, lanes):
    """The pool worker whose modules took longest in all, then the SERIAL ones: [(module, seconds)]."""
    per = {}
    for lane, m in lanes:
        if lane != "serial":
            per.setdefault(lane, []).append(m)
    worst = max(per.values(), key=lambda ms: sum(results[m][1] for m in ms), default=[])
    return [(m, results[m][1]) for m in worst + [m for lane, m in lanes if lane == "serial"]]


def long_pole(results, jobs):
    """The longest module if it is over LONG_POLE times the ideal step (all time over jobs) and over FLOOR."""
    if not results:
        return None
    m = max(results, key=lambda m: results[m][1])
    secs = results[m][1]
    ideal = sum(r[1] for r in results.values()) / max(1, jobs)
    return (m, secs, ideal) if secs > FLOOR and secs > LONG_POLE * ideal else None


def report(names, results, write=sys.stdout.write, jobs=1, lanes=(), wall=None):
    failed = [m for m in names if m not in results or results[m][0] != 0]
    for m in names:
        rc, secs, out = results.get(m, (None, 0.0, "did not run\n"))
        write(f"::group::{m} ({'ok' if rc == 0 else 'FAILED'}, {secs:.0f}s)\n{out}::endgroup::\n")
    write("module times, slowest first:\n")
    for m in sorted(results, key=lambda m: -results[m][1]):
        write(f"  {results[m][1]:7.1f}s  {m}{'  FAILED' if m in failed else ''}\n")
    total = sum(r[1] for r in results.values())
    path = critical_path(results, lanes)
    write(f"{total:.0f}s of tests over {jobs} jobs: {total / max(1, jobs):.0f}s ideal"
          + (f", {wall:.0f}s wall" if wall is not None else "") + "\n")
    write(f"critical path {sum(s for _, s in path):.0f}s: " + ", ".join(f"{m} {s:.0f}s" for m, s in path) + "\n")
    for m in failed:
        write(f"::error::{m} failed\n")
    pole = long_pole(results, jobs)
    if pole:
        write(f"::error::{pole[0]} took {pole[1]:.0f}s, over {LONG_POLE} times the step's ideal {pole[2]:.0f}s: "
              f"split it (tools/unit_tests.py SPLIT)\n")
    return 1 if failed or pole else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("trace_dir", nargs="?")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    ap.add_argument("--split", metavar="MODULE", help="run one module's tests across --workers processes")
    ap.add_argument("--workers", type=int, default=os.cpu_count() or 1)
    args = ap.parse_args(argv)
    if args.split:
        return split(args.split, args.workers)
    if not args.trace_dir:
        ap.error("TRACE_DIR is required")
    os.makedirs(args.trace_dir, exist_ok=True)
    names = modules()
    lanes = []
    start = time.monotonic()
    results = run(names, args.trace_dir, args.jobs, lanes=lanes)
    return report(names, results, jobs=args.jobs, lanes=lanes, wall=time.monotonic() - start)


if __name__ == "__main__":
    sys.exit(main())
