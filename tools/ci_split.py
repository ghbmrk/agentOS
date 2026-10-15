#!/usr/bin/env python3
"""Split and filter the broker's CI work (CI-SHARD, #1868).

`shard` splits the broker's `go list ./...` across the `broker-race` matrix job's shards, so
each package's race tests run on exactly one runner. `check` proves a split covers the list
with no gap and no duplicate: every shard runs it on the full list before its tests. `peaks`
decides whether the machines job's "Fuzz leaf memory peaks" step must run for a change.

The split is a pure function of the package list: packages are placed heaviest first
(WEIGHTS, then name), each on the shard with the least weight so far (the lowest index on a
tie). A package WEIGHTS does not name weighs 1, so a new package lands on the lightest shard;
the split never drops it, it only balances less well until WEIGHTS names it.

`peaks` prints `run` or `skip`. It prints `skip` only for a pull request whose changed paths
miss every input of the measurement: the source directory of every module package the fuzz
targets' test binaries and the loop7 harness build from (`go list -deps -test`, passed in as
a file), the fuzz manifest and the build script the harness mirrors, the module and vendor
files, the workflow, and this file. Any other event, an empty change, or any error prints
`run`; a push to main always measures. CI runs the base commit's copy of this file for
`peaks`, so a pull request cannot change the rule for itself.

Usage:
  tools/ci_split.py shard --shards N --index I < packages    this shard's packages
  tools/ci_split.py check --shards N < packages              exit 1 on a gap or a duplicate
  tools/ci_split.py peaks --event E --deps FILE --changed FILE   `run` or `skip`
Standard library only.
"""
import argparse
import sys

MODULE = "github.com/ghbmrk/agentos/broker"

# Seconds each package's `go test -race` took on main's run 38778073510 (2026-10-15), for
# the packages over 10 s; the rest weigh 1. Stale numbers only unbalance the shards.
WEIGHTS = {
    "pubid": 319, "journal": 294, "holder": 170, "recall": 145, "cmd/agentosd": 140,
    "guest": 132, "localui": 119, "recovery": 102, "cmd/agentos-egress": 86, "sim": 78,
    "update": 56, "mail": 54, "loop7": 51, "digestqueue": 35, "daemon": 34, "vm/gvisor": 31,
    "childproc": 26, "maintain": 26, "loops": 25, "change": 22, "cmd/agentos-guest-bridge": 20,
    "apply": 20, "firstboot": 19, "claim": 17, "guesterr": 17, "probecmd": 13, "core": 13,
    "vm/overlay": 12, "journal/check": 12, "e2e": 12, "mail/imapsmtp": 12,
    "cmd/agentos-seller": 12, "grants": 11, "modem/bridge": 11, "projection": 10,
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
    for pkg in sorted(packages, key=lambda p: (-weight(p), p)):
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


def peaks_needed(event, changed, deps):
    """True unless a pull request changed none of the measurement's inputs."""
    if event != "pull_request":
        return True
    changed = [p.strip() for p in changed if p.strip()]
    if not changed:
        return True
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
            with open(a.deps) as f, open(a.changed) as c:
                need = peaks_needed(a.event, c.read().splitlines(), f.read().splitlines())
        except OSError as e:
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
        print("\n".join(parts[a.index]))
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
