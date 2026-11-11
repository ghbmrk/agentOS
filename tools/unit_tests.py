#!/usr/bin/env python3
"""Run every tests/test*.py module in its own process tree under strace, several at once (CI-par).

ci.yml's unit-test step. Each module runs as `python -m unittest discover -s tests -p <module>.py
-v` under `strace -f -y`, which writes <dir>/<module>.trace for tests/records_audit.py
(CI-PATHS) and tests/clash_audit.py (CI-par-clash); only the number running at a time
changes. A module's output is buffered and printed whole, in name order, so logs do not
interleave; a line per finished module shows progress meanwhile. The longest modules start
first (SECONDS, then file size), and the step prints each module's wall time, the ideal (all
modules' time over the jobs) and the critical path: the worker that finished last and what it ran.
A run strace itself cut short (STRACE_FAULT, read from strace's own stderr, which the module's
output never reaches: JOIN) has no verdict and reruns whole, once, into a fresh trace; a run that
already showed a failed test is never rerun (#5358). Each run is its own
session, killed whole when strace ends, so nothing of a cut run outlives it, and a cut run's trace
stays as <module>.trace.cut, which records_audit.py and clash_audit.py read as the module's (#5364, #5413).
Exit 1 if any module failed or did not run, or if the longest unit runs over FLOOR seconds and
over LONG_POLE times the ideal: that one unit then sets the step's length. A unit is a module, so
split it (SPLIT), or for a module already split, its slowest part (one test with any class or
module setup and teardown its worker ran around it), which further splitting cannot shorten: the
step says the module is at its split limit. A module listed in SERIAL runs alone after the pool
drains: one that cannot share the runner with another module goes there, with its reason.
A module listed in SPLIT runs as `unit_tests.py --split <module>` under the same strace: that one
process forks worker processes, each taking the next test from a shared counter, so the module's
slowest test, not the module, sets the step's floor (CI-par-3). Its last line names that slowest
part and its time, for the long-pole check. The trace is still one tree whose
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
import re
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
# bind: a fixed port or socket name shared by two modules is a clash; symlink, symlinkat, chdir
# and fchdir let tests/clash_audit.py resolve a path the kernel gave no file for, as it was walked.
# unlink, unlinkat, rename, renameat, renameat2 and truncate change a name as a write open does
# (#5413): another module's file, or a trace (tests/records_audit.py).
# --kill-on-exit: the kernel SIGKILLs every process strace still traces when strace exits, so a run
# strace gives up on (STRACE_FAULT) cannot go on untraced, whatever session it moved to (#5364).
STRACE = ["strace", "-f", "--kill-on-exit", "--seccomp-bpf", "-q", "-y", "-e",
          "trace=open,openat,openat2,bind,symlink,symlinkat,chdir,fchdir,"
          "unlink,unlinkat,rename,renameat,renameat2,truncate",
          "-e", "signal=none"]
# Modules that must not overlap another module, with why. Empty until a clash is seen.
SERIAL = {}
# Modules whose tests run across workers inside their one strace tree (CI-par-3), with why.
SPLIT = {"test_image": "about 10 min on a shared runner; one class is 45% of it, so it splits by test (#4332)",
         "test_image_keeper": "481s on the runner after #5167's way tests, over the step's long pole; it splits by test"}
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
# The module's first step, under strace: its stderr joins its stdout, so strace keeps its own
# stderr, on which alone a fault is read; nothing a test prints can fake one (#5407). sh joins
# them before Python starts, so no site hook (.pth, sitecustomize, usercustomize) or child it
# starts holds strace's stream (#5413). Only a test that opens that stream by its /proc name
# reaches it, and a cut it fakes so gains only a rerun: both audits read the cut attempt's trace.
JOIN = ["/bin/sh", "-c", 'exec "$@" 2>&1', "sh"]
LONG_POLE = 1.25
FLOOR = 60  # seconds: a module shorter than this never fails the long-pole check


def modules(root=ROOT):
    return sorted(p.stem for p in (root / "tests").glob("test*.py"))


def command(module, trace_dir, workers=None):
    if module in SPLIT:
        run = [*JOIN, sys.executable, "-c", "import runpy, sys; sys.argv.pop(0); runpy.run_path(sys.argv[0], run_name='__main__')",
               str(pathlib.Path(__file__).resolve()), "--split", module, "--workers", str(workers or os.cpu_count() or 1)]
    else:  # as `python -m unittest discover ...`
        run = [*JOIN, sys.executable, "-c", "import runpy, sys; runpy.run_module(sys.argv.pop(1), run_name='__main__', alter_sys=True)",
               "unittest", "discover", "-s", "tests", "-p", f"{module}.py", "-v"]
    return [*STRACE, "-o", str(pathlib.Path(trace_dir) / f"{module}.trace"), *run]


class _Claimed(unittest.TestSuite):
    """The tests this worker claims, one at a time, from a counter all workers share. TestSuite.run
    still sets up and tears down each class and module around the tests it is handed."""
    _cleanup = False  # run() would otherwise blank _tests[index], which this suite does not hold

    def __init__(self, tests, counter, ran, parts):
        super().__init__()
        self.all, self.counter, self.ran, self.parts = tests, counter, ran, parts

    def __iter__(self):
        # A part's time runs from handing out its test to handing out the next, or to the end of
        # run(): the test, its class and module setup if this worker had not set them up, the
        # previous class's teardown, and for the worker's last part its final class and module
        # teardown.
        while True:
            with self.counter.get_lock():
                i = self.counter.value
                self.counter.value += 1
            if i >= len(self.all):
                return
            self._close()
            self.ran.append(i)
            self.start = time.monotonic()
            yield self.all[i]

    def _close(self):
        if self.ran:
            self.parts[self.ran[-1]] = time.monotonic() - self.start

    def run(self, result, debug=False):
        try:
            return super().run(result, debug)
        finally:
            self._close()


def _flatten(suite):
    for t in suite:
        if isinstance(t, unittest.TestSuite):
            yield from _flatten(t)
        else:
            yield t


class _Streamed(unittest.TextTestResult):
    """A worker's result that also puts each failed test's verdict on the shared stdout as the test
    ends, in one write so the line stays whole: the worker's buffered report reaches the parent only
    when the worker ends, and a run strace cuts before then must still show the failure (#5358)."""

    def _now(self, test, verdict):
        os.write(1, f"\n{test.id()} ... {verdict}\n".encode("utf-8", "replace"))

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self._now(test, "FAIL")

    def addError(self, test, err):
        super().addError(test, err)
        self._now(test, "ERROR")

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self._now(test, "unexpected success")

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            self._now(subtest, "FAIL" if issubclass(err[0], test.failureException) else "ERROR")


def _worker(tests, counter, conn):
    out, ran, parts = io.StringIO(), [], {}
    runner = unittest.TextTestRunner(stream=out, verbosity=2, resultclass=_Streamed)
    ok = runner.run(_Claimed(tests, counter, ran, parts)).wasSuccessful()
    conn.send((ran, ok, out.getvalue(), parts))
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
    for k, (_, _, out, _) in enumerate(reports, 1):
        write(f"--- {module} worker {k} of {len(procs)} ---\n{out}")
    missing = len(tests) - len(set(ran))
    write(f"{module}: {len(ran)} of {len(tests)} tests run across {len(procs)} workers"
          f"{f', {lost} worker(s) lost' if lost else ''}{f', {missing} not run' if missing else ''}\n")
    parts = {i: secs for r in reports for i, secs in r[3].items()}
    if parts:
        i = max(parts, key=parts.get)
        write(f"{module}: slowest part {parts[i]:.3f}s {tests[i].id()}\n")
    return 0 if not lost and ran == list(range(len(tests))) and all(r[1] for r in reports) else 1


# strace's own failure, not a test's: "strace: ptrace(PTRACE_LISTEN,pid:N,sig:0): Input/output
# error" (#5258, #5355; tools/depaudit.py's STRACE_FAULT). strace then stops tracing, the run is cut
# and its trace is partial, so the attempt has no verdict, whatever strace's exit status. Read on
# strace's own stderr only (JOIN), so a test's output never matches it (#5407). Both sightings
# cut test_mutgate in or after a test whose code kills a traced process group (tools/mutgate.py
# watch(): os.killpg SIGKILL), the likely trigger of strace's race.
STRACE_FAULT = re.compile(r"(?m)^strace: .*(?:Input/output error|PTRACE_)")
# A failed test in the output so far, failing closed: a match only stops a rerun. unittest's -v
# verdict can land on a bare line or after a child's partial line, so any line ending FAIL or ERROR
# counts, as do an unexpected success and the run's failure summary.
TEST_FAILED = re.compile(r"(?m)(?:FAIL|ERROR)$|unexpected success|^(?:FAIL|ERROR): |^FAILED \(")
RERAN = "the module reruns whole into a fresh trace"
# A module strace faults on runs once more, whole, into a fresh trace. Two, so at most one attempt
# is cut and kept (CUT): a cut trace ends mid-line, so a second one could not follow it whole.
STRACE_ATTEMPTS = 2
CUT = ".trace.cut"  # a cut attempt's trace: not `*.trace`, the one finished trace per module


def attempt(cmd, root=ROOT):
    """(rc, output, strace's own stderr) of one traced run, started in its own session. When strace
    ends, whatever is left of that session's process group is killed before this returns, so
    nothing of the run goes on into the next one (#5364). strace's pid, and so the group id, stays held until the
    group is killed: it is reaped only after. Output goes to files, not pipes, so a process that
    keeps a copy of one cannot hold the run open."""
    with tempfile.TemporaryFile() as log, tempfile.TemporaryFile() as err:
        p = subprocess.Popen(cmd, cwd=root, stdin=subprocess.DEVNULL, env=ENV, stdout=log,
                             stderr=err, start_new_session=True)
        try:
            os.waitid(os.P_PID, p.pid, os.WEXITED | os.WNOWAIT)
        finally:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            p.wait()
        log.seek(0)
        err.seek(0)
        return p.returncode, log.read().decode("utf-8", "replace"), err.read().decode("utf-8", "replace")


def run_one(module, trace_dir, root=ROOT):
    """(module, rc, seconds, output). An attempt that strace cut short (STRACE_FAULT on strace's
    own stderr, which follows the module's output in the log) reruns the module whole, and strace
    -o rewrites its trace, so the trace kept is the passing attempt's; the cut attempt's trace is
    kept as <module>.trace.cut, for records_audit.py and clash_audit.py (each sees every attempt). A cut attempt
    that already showed a failing test fails the module and is not rerun, and a module strace cuts
    on every attempt fails."""
    start, outs = time.monotonic(), []
    trace = pathlib.Path(trace_dir) / f"{module}.trace"
    cut = trace.with_name(module + CUT)
    cut.unlink(missing_ok=True)  # one left by an earlier run in this directory is not this run's
    for n in range(1, STRACE_ATTEMPTS + 1):
        rc, out, err = attempt(command(module, trace_dir), root)
        failed = TEST_FAILED.search(out)
        if err:  # strace's own lines, after the module's, on a line of their own
            out += ("\n" if out and not out.endswith("\n") else "") + err
        if not STRACE_FAULT.search(err):
            outs.append(out)
            break
        rc = rc or 1
        last = failed or n == STRACE_ATTEMPTS
        outs.append(f"{out}\nunit_tests: strace failed itself on attempt {n} of {STRACE_ATTEMPTS}, so the "
                    f"run and its trace are cut short; "
                    + ("a test had already failed, so the module fails without a rerun\n" if failed else
                       "the module fails\n" if last else RERAN + "\n"))
        if last:
            break
        if trace.exists():  # the one cut attempt's trace (STRACE_ATTEMPTS)
            trace.replace(cut)
    return module, rc, time.monotonic() - start, "".join(outs)


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


def slowest_part(module, out):
    """(seconds, test id) from a split run's last line, or None if it did not print one."""
    lines = out.splitlines()
    m = re.fullmatch(rf"{re.escape(module)}: slowest part (\d+\.\d+)s (\S+)", lines[-1] if lines else "")
    return (float(m.group(1)), m.group(2)) if m else None


def long_pole(results, jobs, split=None):
    """(module, seconds, ideal, part) for the longest unit if it is over LONG_POLE times the ideal
    step (all modules' time over jobs) and over FLOOR. A unit is a module, or for one in split, its
    slowest part: part is then (seconds, test id), or None if the run named none (its whole time
    counts)."""
    split = SPLIT if split is None else split
    if not results:
        return None
    units = {}
    for m, (_, secs, out) in results.items():
        part = slowest_part(m, out) if m in split else None
        units[m] = (part[0] if part else secs, part)
    m = max(units, key=lambda m: units[m][0])
    secs, part = units[m]
    ideal = sum(r[1] for r in results.values()) / max(1, jobs)
    return (m, secs, ideal, part) if secs > FLOOR and secs > LONG_POLE * ideal else None


def report(names, results, write=sys.stdout.write, jobs=1, lanes=(), wall=None, split=None):
    split = SPLIT if split is None else split
    failed = [m for m in names if m not in results or results[m][0] != 0]
    for m in names:
        rc, secs, out = results.get(m, (None, 0.0, "did not run\n"))
        write(f"::group::{m} ({'ok' if rc == 0 else 'FAILED'}, {secs:.0f}s)\n{out}::endgroup::\n")
    write("module times, slowest first:\n")
    for m in sorted(results, key=lambda m: -results[m][1]):
        part = slowest_part(m, results[m][2]) if m in split else None
        write(f"  {results[m][1]:7.1f}s  {m}{'  FAILED' if m in failed else ''}"
              + (f"  (split; slowest part {part[0]:.1f}s, {part[1]})" if part else "") + "\n")
    total = sum(r[1] for r in results.values())
    path = critical_path(results, lanes)
    write(f"{total:.0f}s of tests over {jobs} jobs: {total / max(1, jobs):.0f}s ideal"
          + (f", {wall:.0f}s wall" if wall is not None else "") + "\n")
    write(f"critical path {sum(s for _, s in path):.0f}s: " + ", ".join(f"{m} {s:.0f}s" for m, s in path) + "\n")
    for m in failed:
        write(f"::error::{m} failed\n")
    pole = long_pole(results, jobs, split)
    if pole and pole[0] in split and pole[3]:
        write(f"::error::{pole[0]} is already split (tools/unit_tests.py SPLIT): its slowest part, {pole[3][1]}, "
              f"took {pole[1]:.0f}s, over {LONG_POLE} times the step's ideal {pole[2]:.0f}s. It is at its split "
              f"limit: a part is the test plus any class or module setup and teardown its worker ran around it, "
              f"so shorten that test or that setup or teardown, or break the test into smaller ones\n")
    elif pole and pole[0] in split:
        write(f"::error::{pole[0]} is already split (tools/unit_tests.py SPLIT), but its run gave no slowest part "
              f"(it stopped before its last line: see its log above), so its whole time counts: {pole[1]:.0f}s, "
              f"over {LONG_POLE} times the step's ideal {pole[2]:.0f}s\n")
    elif pole and RERAN in results[pole[0]][2]:
        write(f"::error::{pole[0]} took {pole[1]:.0f}s, over {LONG_POLE} times the step's ideal {pole[2]:.0f}s, "
              f"counting the run strace cut short and its rerun (see its log above)\n")
    elif pole:
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
