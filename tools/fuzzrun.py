#!/usr/bin/env python3
"""Fuzz one Go target for a time budget, as count-bound chunks (P1-4-flake-ci).

    python3 tools/fuzzrun.py --pkg ./sockets --target FuzzFrames --budget 20s [--chunk 10m]

Never passes a duration to -fuzztime: a duration bound can end in a bare "context deadline
exceeded" with no input written (the fuzz coordinator's deadline race). Each chunk runs
`go test -fuzztime <N>x -timeout <T>`; N comes from the rate the previous chunk measured, and T
is proportional to the chunk's expected time, so a hang is loud and a slowdown is not a hang.
Exit status: go's own on failure (its output, with any crasher path, passes through), 124 on a
chunk that overran its cap, 2 on a bad argument.
"""
import argparse
import math
import os
import re
import signal
import subprocess
import sys
import threading
import time

FACTOR = 2.5  # a chunk may take this many times its expected time (the rate can halve)
DEFAULT_CALIBRATE = 20000
# go test's `ok  \tpkg\t0.337s`: the run without the build, which a cold cache makes far longer
OK_LINE = re.compile(r"^ok\s+\S+\s+([\d.]+)s\b")


def parse_budget(text):
    """Seconds, or h/m/s parts ('3h', '90s', '1h30m'); anything else is ValueError."""
    if re.fullmatch(r"\d+(\.\d+)?", text):
        secs = float(text)
    else:
        m = re.fullmatch(r"(?:(\d+)h)?(?:(\d+)m)?(?:(\d+(?:\.\d+)?)s)?", text)
        if not text or not m:
            raise ValueError(f"bad budget {text!r}: use seconds or h/m/s parts such as 90, 20s, 1h30m")
        h, mi, s = m.groups()
        secs = int(h or 0) * 3600 + int(mi or 0) * 60 + float(s or 0)
    if secs <= 0:
        raise ValueError(f"bad budget {text!r}: must be positive")
    return secs


def run_chunk(cmd, kill_after):
    """Run cmd in its own process group, echoing its output; kill the group at kill_after seconds.

    -> (rc, timed_out, test_seconds). test_seconds is the time go reports on its `ok` line (the
    test run without the build), or None if there was none.
    """
    p = subprocess.Popen(cmd, start_new_session=True, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, errors="replace")
    fired = []

    def kill():
        fired.append(True)
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    timer = threading.Timer(kill_after, kill)
    timer.start()
    test_seconds = None
    for line in p.stdout:
        sys.stdout.write(line)
        sys.stdout.flush()
        m = OK_LINE.match(line)
        if m:
            test_seconds = float(m.group(1))
    rc = p.wait()
    timer.cancel()
    return rc, bool(fired), test_seconds


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--pkg")
    ap.add_argument("--target")
    ap.add_argument("--budget")
    ap.add_argument("--chunk", help="longest chunk (default: the budget)")
    ap.add_argument("--grace", default="2m", help="fixed allowance per chunk for the build (default 2m)")
    ap.add_argument("--slack", type=float, default=2.0,
                    help="seconds past go's own -timeout before the process group is killed")
    ap.add_argument("--calibrate", type=int, default=DEFAULT_CALIBRATE, help="first chunk's count")
    ap.add_argument("--check-budget", metavar="TEXT", help="only validate a budget string")
    a = ap.parse_args(argv)
    try:
        if a.check_budget is not None:
            parse_budget(a.check_budget)
            return 0
        if not (a.pkg and a.target and a.budget is not None):
            raise ValueError("--pkg, --target and --budget are required")
        budget = parse_budget(a.budget)
        chunk_max = parse_budget(a.chunk) if a.chunk else budget
        grace = parse_budget(a.grace)
        if a.calibrate < 1:
            raise ValueError("--calibrate must be at least 1")
    except ValueError as e:
        print(f"fuzzrun: {e}", file=sys.stderr)
        return 2

    name = f"{a.pkg}:{a.target}"
    start = time.monotonic()
    rate = None
    total_execs = 0
    k = 0
    while k == 0 or time.monotonic() - start < budget:
        k += 1
        remaining = budget - (time.monotonic() - start)
        span = min(max(remaining, 0.0) if k > 1 else budget, chunk_max)
        if rate is None:
            n = a.calibrate
        else:
            n = max(1, int(rate * span))
        expected = span if rate is None else n / rate
        cap = FACTOR * expected + grace
        cmd = ["go", "test", a.pkg, "-run", "^$", "-fuzz", f"^{a.target}$",
               "-fuzztime", f"{n}x", "-timeout", f"{math.ceil(cap * 1000) / 1000}s"]
        t0 = time.monotonic()
        rc, timed_out, ran = run_chunk(cmd, cap * 1.05 + a.slack)
        took = max(time.monotonic() - t0, 1e-9)
        if timed_out:
            print(f"fuzzrun {name} chunk {k}: no result within {cap:.1f}s "
                  f"(expected {expected:.1f}s for {n} execs); killed", file=sys.stderr, flush=True)
            return 124
        if rc != 0:
            return rc if rc > 0 else 1
        # the build is not fuzzing: rate from go's own run time, else from the wall clock
        rate = n / max(ran, 1e-9) if ran else n / took
        total_execs += n
        print(f"fuzzrun {name} chunk {k}: {n} execs in {took:.1f}s ({rate:.0f}/s)", flush=True)

    elapsed = time.monotonic() - start
    total = (f"fuzzrun {name} total: {total_execs} execs in {elapsed:.1f}s "
             f"({total_execs / elapsed:.0f}/s) over {k} chunks")
    print(total, flush=True)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            f.write(total + "\n\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
