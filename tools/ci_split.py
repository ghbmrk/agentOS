#!/usr/bin/env python3
"""Split the broker's CI work (CI-SHARD, #1868).

`shard` splits the broker's `go list ./...` across the `broker-race` matrix job's shards, so
each package's race tests run on exactly one runner. `check` proves a split covers the list
with no gap and no duplicate: every shard runs it on the full list before its tests.

The split is a pure function of the package list: packages are placed heaviest first
(WEIGHTS, then name), each on the shard with the least weight so far (the lowest index on a
tie). A package WEIGHTS does not name weighs 1, so a new package lands on the lightest shard;
the split never drops it, it only balances less well until WEIGHTS names it. `shard` prints a
shard's packages heaviest first: `go test` starts packages in command-line order, so the
longest one (journal) starts at once instead of after the packages that sort before it.

Usage:
  tools/ci_split.py shard --shards N --index I < packages    this shard's packages
  tools/ci_split.py check --shards N < packages              exit 1 on a gap or a duplicate
Standard library only.
"""
import argparse
import sys

MODULE = "github.com/ghbmrk/agentos/broker"

# Seconds each package's `go test -race` took in the 3-shard run 38790596302 (2026-10-15,
# rounded), for the packages at 10 s or over; the rest weigh 1. Stale numbers only unbalance
# the shards.
WEIGHTS = {
    "journal": 223, "guest": 128, "cmd/agentosd": 124, "localui": 117,
    "holder": 99, "cmd/agentos-egress": 83, "recovery": 72, "update": 62, "recall": 57,
    "kernel/sim": 35, "childproc": 35, "daemon": 34, "vm/gvisor": 33,
    "change": 26, "loops": 25, "maintain": 18, "guesterr": 18, "core": 17,
    "e2e": 16, "claim": 16, "vm/overlay": 14, "cmd/agentos-guest-bridge": 14, "firstboot": 14,
    "apply": 13, "journal/check": 13, "modem/bridge": 11, "vault": 11, "probecmd": 10,
    "cmd/agentos-seller": 10,
}

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


def by_weight(packages):
    """The packages heaviest first (then by name), the order `shard` prints them in."""
    return sorted(packages, key=lambda p: (-weight(p), p))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("shard")
    s.add_argument("--shards", type=int, required=True)
    s.add_argument("--index", type=int, required=True)
    c = sub.add_parser("check")
    c.add_argument("--shards", type=int, required=True)
    a = ap.parse_args(argv)
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
