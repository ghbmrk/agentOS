#!/usr/bin/env python3
"""Run every tests/test*.py module in its own process tree under strace, several at once (CI-par).

ci.yml's unit-test step. Each module runs as `python -m unittest discover -s tests -p <module>.py
-v` under `strace -f -y`, which writes <dir>/<module>.trace for tests/records_audit.py
(CI-PATHS), exactly as the serial loop did; only the number running at a time changes. A
module's output is buffered and printed whole, in name order, so logs do not interleave; a
line per finished module shows progress meanwhile.
Exit 1 if any module failed or did not run. A module listed in SERIAL runs alone after the
pool drains: one that cannot share the runner with another module goes there, with its reason.
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
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
STRACE = ["strace", "-f", "--seccomp-bpf", "-q", "-y", "-e", "trace=open,openat,openat2", "-e", "signal=none"]
# Modules that must not overlap another module, with why. Empty until a clash is seen.
SERIAL = {}
# Modules whose tests run across workers inside their one strace tree (CI-par-3), with why.
SPLIT = {"test_image": "about 10 min on a shared runner; one class is 45% of it, so it splits by test (#4332)"}


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
    p = subprocess.run(command(module, trace_dir), cwd=root, stdin=subprocess.DEVNULL,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return module, p.returncode, time.monotonic() - start, p.stdout.decode("utf-8", "replace")


def size(module, root=ROOT):
    try:
        return (root / "tests" / f"{module}.py").stat().st_size
    except OSError:
        return 0


def run(names, trace_dir, jobs, runner=run_one, progress=lambda line: print(line, end="", flush=True)):
    """Run names (SERIAL ones last, one at a time) and return {module: (rc, seconds, output)}."""
    # Biggest file first: the longest module must not start last.
    pooled = sorted((m for m in names if m not in SERIAL), key=lambda m: -size(m))
    results = {}

    def done(module, rc, secs, out):
        results[module] = (rc, secs, out)
        progress(f"{len(results)}/{len(names)} {module} {'ok' if rc == 0 else 'FAILED'} {secs:.0f}s\n")
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        for f in concurrent.futures.as_completed([pool.submit(runner, m, trace_dir) for m in pooled]):
            done(*f.result())
    for m in names:
        if m in SERIAL:
            done(*runner(m, trace_dir))
    return results


def report(names, results, write=sys.stdout.write):
    failed = [m for m in names if m not in results or results[m][0] != 0]
    for m in names:
        rc, secs, out = results.get(m, (None, 0.0, "did not run\n"))
        write(f"::group::{m} ({'ok' if rc == 0 else 'FAILED'}, {secs:.0f}s)\n{out}::endgroup::\n")
    write("module times, slowest first:\n")
    for m in sorted(results, key=lambda m: -results[m][1]):
        write(f"  {results[m][1]:7.1f}s  {m}{'  FAILED' if m in failed else ''}\n")
    for m in failed:
        write(f"::error::{m} failed\n")
    return 1 if failed else 0


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
    return report(names, run(names, args.trace_dir, args.jobs))


if __name__ == "__main__":
    sys.exit(main())
