#!/usr/bin/env python3
"""Split and filter the broker's CI work (CI-SHARD, #1868).

`shard` splits the broker's `go list ./...` across the `broker-race` matrix job's shards, so
each package's race tests run on exactly one runner. `check` proves a split covers the list
with no gap and no duplicate: every shard runs it on the full list before its tests. `peaks`
decides whether the machines job's "Fuzz leaf memory peaks" step must run for a change.

The split is a pure function of the package list: packages are placed heaviest first
(WEIGHTS, then name), each on the shard with the least weight so far (the lowest index on a
tie). A package WEIGHTS does not name weighs 1, so a new package lands on the lightest shard;
the split never drops it, it only balances less well until WEIGHTS names it. `shard` prints a
shard's packages heaviest first: `go test` starts packages in command-line order, so the
longest one (pubid) starts at once instead of after the packages that sort before it.

`peaks` prints `run` or `skip`. It prints `skip` only for a pull request whose changed paths
miss every input of the measurement: the source directory of every module package the fuzz
targets' test binaries and the loop7 harness build from (`go list -deps -test`, passed in as
a file), the fuzz manifest and the build script the harness mirrors, the module and vendor
files, the workflow, and this file. Any other event, an empty change, or any error prints
`run`; a push to main always measures. A changed path git had to quote (a line starting
with `"`) also prints `run`. The changed-path file may be NUL-separated (`git diff -z`).
CI runs the base commit's copy of this file for `peaks`. That is defence in depth only: on
`pull_request` the workflow itself comes from the PR head, so a PR can rewrite the step; what
catches that is that ci.yml and this file are tier A (human review) and in PEAK_FILES.

Usage:
  tools/ci_split.py shard --shards N --index I < packages    this shard's packages
  tools/ci_split.py check --shards N < packages              exit 1 on a gap or a duplicate
  tools/ci_split.py peaks --event E --deps FILE --changed FILE   `run` or `skip`
Standard library only.
"""
import argparse
import sys

MODULE = "github.com/ghbmrk/agentos/broker"

# Seconds each package's `go test -race` took in the 3-shard run 38790596302 (2026-10-15,
# rounded), for the packages at 10 s or over; the rest weigh 1. Stale numbers only unbalance
# the shards.
WEIGHTS = {
    "pubid": 259, "journal": 223, "guest": 128, "cmd/agentosd": 124, "localui": 117,
    "holder": 99, "cmd/agentos-egress": 83, "recovery": 72, "update": 62, "recall": 57,
    "loop7": 48, "sim": 35, "childproc": 35, "daemon": 34, "vm/gvisor": 33, "mail": 30,
    "change": 26, "loops": 25, "maintain": 18, "guesterr": 18, "core": 17, "digestqueue": 16,
    "e2e": 16, "claim": 16, "vm/overlay": 14, "cmd/agentos-guest-bridge": 14, "firstboot": 14,
    "apply": 13, "journal/check": 13, "modem/bridge": 11, "vault": 11, "probecmd": 10,
    "cmd/agentos-seller": 10, "projection": 10,
}

# Inputs of TestFuzzLeafPeakPerTarget besides the Go packages it builds.
PEAK_FILES = frozenset({
    "image/fuzz-targets.json", "image/build.sh", "broker/go.mod", "broker/go.sum",
    ".github/workflows/ci.yml", "tools/ci_split.py",
})
PEAK_PREFIXES = ("broker/vendor/", "broker/third_party/")


def weight(pkg):
    return WEIGHTS.get(pkg.removeprefix(MODULE).lstrip("/"), 1)


def split(packages, shards):
    """Return a list of `shards` sorted package lists; each package is on exactly one."""
    if shards < 1:
        raise ValueError("shards must be at least 1")
    if len(set(packages)) != len(packages):
        raise ValueError("duplicate package in the list")
    load = [0] * shards
    out = [[] for _ in range(shards)]
    for pkg in by_weight(packages):
        i = min(range(shards), key=lambda s: (load[s], s))
        load[i] += weight(pkg)
        out[i].append(pkg)
    return [sorted(s) for s in out]


def gaps_and_duplicates(packages, parts):
    """Return (packages no part runs, packages more than one part runs, packages not listed)."""
    seen = {}
    for part in parts:
        for p in part:
            seen[p] = seen.get(p, 0) + 1
    listed = set(packages)
    return (sorted(listed - set(seen)), sorted(p for p, n in seen.items() if n > 1),
            sorted(set(seen) - listed))


def read_packages(stream):
    pkgs = [line.strip() for line in stream if line.strip()]
    if not pkgs:
        raise ValueError("empty package list")
    return pkgs


def peak_dirs(deps):
    """Repository directories of the module's packages among `go list` import paths."""
    dirs = set()
    for path in deps:
        path = path.strip().split(" ")[0].removesuffix(".test")
        if path == MODULE or path.startswith(MODULE + "/"):
            dirs.add("broker" + path[len(MODULE):] + "/")
    return dirs


def by_weight(packages):
    """The packages heaviest first (then by name), the order `shard` prints them in."""
    return sorted(packages, key=lambda p: (-weight(p), p))


def changed_paths(text):
    """Paths from `git diff --name-only` output: NUL-separated if it has a NUL, else lines."""
    return text.split("\0") if "\0" in text else text.splitlines()


def peaks_needed(event, changed, deps):
    """True unless a pull request changed none of the measurement's inputs."""
    if event != "pull_request":
        return True
    changed = [p.strip() for p in changed if p.strip()]
    if not changed:
        return True
    if any(p.startswith('"') for p in changed):
        return True  # git quoted a path (core.quotePath): measure rather than unquote
    dirs = peak_dirs(deps)
    if not dirs:
        return True  # no dependency list: measure rather than guess
    for p in changed:
        if p in PEAK_FILES or p.startswith(PEAK_PREFIXES) or any(p.startswith(d) for d in dirs):
            return True
    return False


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("shard")
    s.add_argument("--shards", type=int, required=True)
    s.add_argument("--index", type=int, required=True)
    c = sub.add_parser("check")
    c.add_argument("--shards", type=int, required=True)
    p = sub.add_parser("peaks")
    p.add_argument("--event", required=True)
    p.add_argument("--deps", required=True)
    p.add_argument("--changed", required=True)
    a = ap.parse_args(argv)
    if a.cmd == "peaks":
        try:
            with open(a.deps) as f, open(a.changed, encoding="utf-8", errors="surrogateescape") as c:
                need = peaks_needed(a.event, changed_paths(c.read()), f.read().splitlines())
        except (OSError, ValueError) as e:
            print(f"ci_split: {e}; measuring", file=sys.stderr)
            need = True
        print("run" if need else "skip")
        return 0
    try:
        pkgs = read_packages(sys.stdin)
        parts = split(pkgs, a.shards)
    except ValueError as e:
        print(f"ci_split: {e}", file=sys.stderr)
        return 1
    if a.cmd == "shard":
        if not 0 <= a.index < a.shards:
            print(f"ci_split: index {a.index} outside 0..{a.shards - 1}", file=sys.stderr)
            return 1
        print("\n".join(by_weight(parts[a.index])))
        return 0
    gaps, dups, extra = gaps_and_duplicates(pkgs, parts)
    for i, part in enumerate(parts):
        print(f"shard {i}: {len(part)} packages, weight {sum(weight(x) for x in part)}")
    if gaps or dups or extra:
        print(f"ci_split: gaps {gaps}, duplicates {dups}, unlisted {extra}", file=sys.stderr)
        return 1
    print(f"{len(pkgs)} packages, each on exactly one of {a.shards} shards")
    return 0


if __name__ == "__main__":
    sys.exit(main())
