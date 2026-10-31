#!/usr/bin/env python3
"""Run every tests/test*.py module in its own process tree under strace, several at once (CI-par).

ci.yml's unit-test step. Each module runs as `python -m unittest discover -s tests -p <module>.py
-v` under `strace -f -y`, which writes <dir>/<module>.trace for tests/records_audit.py
(CI-PATHS), exactly as the serial loop did; only the number running at a time changes. A
module's output is buffered and printed whole, in name order, so logs do not interleave.
Exit 1 if any module failed or did not run. A module listed in SERIAL runs alone after the
pool drains: one that cannot share the runner with another module goes there, with its reason.

    python3 tools/unit_tests.py TRACE_DIR [--jobs N]
"""
import argparse
import concurrent.futures
import os
import pathlib
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
STRACE = ["strace", "-f", "--seccomp-bpf", "-q", "-y", "-e", "trace=open,openat,openat2", "-e", "signal=none"]
# Modules that must not overlap another module, with why. Empty until a clash is seen.
SERIAL = {}


def modules(root=ROOT):
    return sorted(p.stem for p in (root / "tests").glob("test*.py"))


def command(module, trace_dir):
    return [*STRACE, "-o", str(pathlib.Path(trace_dir) / f"{module}.trace"),
            sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", f"{module}.py", "-v"]


def run_one(module, trace_dir, root=ROOT):
    start = time.monotonic()
    p = subprocess.run(command(module, trace_dir), cwd=root, stdin=subprocess.DEVNULL,
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    return module, p.returncode, time.monotonic() - start, p.stdout.decode("utf-8", "replace")


def run(names, trace_dir, jobs, runner=run_one):
    """Run names (SERIAL ones last, one at a time) and return {module: (rc, seconds, output)}."""
    pooled = [m for m in names if m not in SERIAL]
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
        for module, rc, secs, out in pool.map(lambda m: runner(m, trace_dir), pooled):
            results[module] = (rc, secs, out)
    for m in names:
        if m in SERIAL:
            module, rc, secs, out = runner(m, trace_dir)
            results[module] = (rc, secs, out)
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
    ap.add_argument("trace_dir")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 1)
    args = ap.parse_args(argv)
    os.makedirs(args.trace_dir, exist_ok=True)
    names = modules()
    return report(names, run(names, args.trace_dir, args.jobs))


if __name__ == "__main__":
    sys.exit(main())
