#!/usr/bin/env python3
"""Fail a `go test -json` run unless the named tests ran and passed, and nothing skipped (INFER-CI).

A test that needs root or a delegated cgroup skips without it, so a job that loses either
goes green with the test unrun; a renamed or deleted test goes green the same way. This reads
the stream on stdin, echoes its output so the job log reads like `go test -v`, then exits 1
when a named test has no top-level `pass` event, or when any test in the stream skipped. A name
is the package import path and the test, so a same-named test in another package does not count.
A package-level skip (a package with no test files) is not a test skip.

  go test -json ./infer/... > run.json
  require_ran.py example.com/m/pkg.TestA example.com/m/pkg.TestB < run.json
                                          exit 0, or 1 with each problem on stderr
  require_ran.py --gated ./vm/... ./recovery < run.json
                                          also names every root-gated test of those packages
                                          (tools/root_tests.py), so a root step covers them (#3541)
  require_ran.py --named-skips-only ...   fail on a skip only in a named test or its subtests, for a
                                          whole-package run whose other tests may skip by design
"""
import json
import os
import sys


def check(lines, names, named_skips_only=False):
    """Problems in a `go test -json` stream, as strings; empty when every name passed."""
    passed, skipped, problems = set(), [], []
    for n, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except ValueError:
            problems.append(f"line {n}: not a go test -json event")
            continue
        if not isinstance(ev, dict):
            problems.append(f"line {n}: not a go test -json event")
            continue
        out = ev.get("Output")
        if isinstance(out, str):
            sys.stdout.write(out)
        test, action = ev.get("Test"), ev.get("Action")
        if not isinstance(test, str):
            continue
        key = f"{ev.get('Package', '?')}.{test}"
        if action == "pass":
            passed.add(key)  # a subtest's key carries "/" and so never equals a name
        elif action == "skip":
            skipped.append(key)
    for name in names:
        if name not in passed:
            problems.append(f"{name}: no pass (skipped, failed or missing)")
    if named_skips_only:
        skipped = [t for t in skipped if any(t == n or t.startswith(n + "/") for n in names)]
    problems += [f"{t}: skipped" for t in skipped]
    return problems


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    named_skips_only = "--named-skips-only" in args
    args = names = [a for a in args if a != "--named-skips-only"]
    if "--gated" in args:
        i = args.index("--gated")
        pats = [a for a in args[i + 1:] if a.startswith("./")]
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import root_tests
        gated = root_tests.gated_names(pats) if pats else []
        if not gated:
            print("require_ran.py: --gated names no root-gated test", file=sys.stderr)
            return 2
        names = [a for a in args[:i] + args[i + 1:] if a not in pats] + gated
    if not names or any("." not in n for n in names):
        print("usage: require_ran.py [--named-skips-only] [--gated ./pkg...] import/path.TestName... < go-test.json",
              file=sys.stderr)
        return 2
    problems = check(sys.stdin, names, named_skips_only)
    for p in problems:
        print(f"::error::{p}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
