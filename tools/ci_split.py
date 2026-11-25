#!/usr/bin/env python3
"""Split the broker's CI work (CI-SHARD, #1868).

`shard` splits the broker's `go list ./...` across the `broker-race` matrix job's shards, so
each package's race tests run on exactly one runner. `check` proves a split covers the list
with no gap and no duplicate: every shard runs it on the full list before its tests.

The split is a pure function of the package list: packages are placed heaviest first
(WEIGHTS, then name), each on the shard with the least weight so far (the lowest index on a
tie), after each ALONE package present takes one of the last shards for itself. A package WEIGHTS does not name weighs 1, so a new package lands on the lightest shard;
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

# Seconds each package's `go test -race` took in main's ci run 45142437210 (2026-11-23, rounded),
# for the packages at 10 s or over; the rest weigh 1. Stale numbers only unbalance the shards, but
# they did put three new heavy packages beside kernel/sim (CI-race-sim-alone, #6582).
WEIGHTS = {
    "kernel/sim": 970, "decoy/match": 445, "enforcer/nft": 445, "journal": 324,
    "cmd/agentos-enroll": 235, "daemon": 225, "e2e/boxe2e": 135, "holder": 115, "drone": 114,
    "guest": 105, "cmd/agentos-egress": 102, "cmd/agentos-vision": 100, "egress": 88, "localui": 87,
    "kernel": 80, "browser": 74, "enforcer/mdns": 71, "vault": 71, "kernel/privfile": 66,
    "recovery": 64, "owner": 59, "clerk/inbox": 58, "core": 57, "enforcer/dns": 57,
    "clerk/run": 55, "cmd/agentos-photo": 55, "owner/graph": 53, "update": 51,
    "cmd/agentos-unlock": 50, "apply": 49, "enforcer/channel": 41, "vm/requal/driver": 39,
    "e2e": 37, "enforcer/dns/run": 36, "loops": 33, "cmd/agentosd": 31, "kernel/proc": 29,
    "backup": 28, "cmd/agentos-clerk-model": 28, "attention": 25, "clerk/wipelint": 25,
    "clerk/inbox/imapsmtp": 23, "clerk/inbox/cmd/slice": 20, "cmd/agentos-link": 20,
    "guesterr": 17, "hostiletext": 17, "call": 16, "cmd/agentos-a8scan": 16, "journal/check": 16,
    "enforcer/ap/push": 15, "kernel/key": 13, "vm/requal": 13, "durable": 12,
    "enforcer/radio/ble": 12, "probecmd": 12, "apply/bootab": 11, "childproc": 11,
    "enforcer/radio": 11, "firstboot": 11, "modem/bridge": 11, "apply/activatortest": 10,
    "claim": 10, "vm/gvisor": 10,
}

# Packages that get a shard to themselves, the last shards in this order, while at least one
# shard is left for the rest. kernel/sim uses every core (#6575) and ran 970 s of its 25-minute
# timeout beside other heavy packages; alone it has the runner to itself (CI-race-sim-alone, #6582).
ALONE = ("kernel/sim",)


def name(pkg):
    return pkg.removeprefix(MODULE).lstrip("/")


def weight(pkg):
    return WEIGHTS.get(name(pkg), 1)


def split(packages, shards):
    """Return a list of `shards` sorted package lists; each package is on exactly one."""
    if shards < 1:
        raise ValueError("shards must be at least 1")
    if len(set(packages)) != len(packages):
        raise ValueError("duplicate package in the list")
    out = [[] for _ in range(shards)]
    alone = [p for a in ALONE for p in packages if name(p) == a][:shards - 1]
    for i, pkg in enumerate(alone):
        out[shards - 1 - i].append(pkg)
    rest = shards - len(alone)
    load = [0] * rest
    for pkg in by_weight([p for p in packages if p not in alone]):
        i = min(range(rest), key=lambda s: (load[s], s))
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
