#!/usr/bin/env python3
"""Fail when a broker dialer is not hooked into the home-network address guard (DEV-2).

Every non-test Go file under broker/ that opens a network connection (net.Dialer, net.Dial*,
tls.Dial*, smtp.Dial*, an http.Transport, http.DefaultClient/DefaultTransport, http.Get/Post/Head)
must import broker/netguard, or be listed in tools/netguard_allow.txt with a reason. Unix-socket
dials are exempt, as is testdata/ (guest programs). The allowlist is a debt list: an entry whose
file is gone, now imports the guard, or no longer has an unhooked dial fails the check, so it
cannot go stale. DEV-net-b empties it.

The check is per file, not per call: a file that imports netguard is trusted to use it for every
dial it makes; the netguard tests and review cover that use. Heuristic by design (a regex, not
the Go type checker): it finds the common dial forms and errs toward a flag.

Usage: netguardcheck.py [--root DIR] [--allow FILE]
"""
import argparse
import pathlib
import re
import sys

GUARD = '"github.com/ghbmrk/agentos/broker/netguard"'
DIAL = re.compile(
    r"\bnet\.Dialer\b|\bnet\.Dial(?:Timeout|TCP|UDP|IP)?\(|\btls\.Dial(?:WithDialer)?\(|\bsmtp\.Dial|"
    r"\bhttp\.Transport\b|\bhttp\.Default(?:Client|Transport)\b|\bhttp\.(?:Get|Post|Head|PostForm)\("
)
WINDOW = 4  # lines after a match searched for "unix"


def sites(path):
    """Line numbers of dial sites in a Go file that are not Unix-socket dials."""
    lines = path.read_text(encoding="utf-8", errors="replace").split("\n")
    out = []
    for i, line in enumerate(lines):
        if line.lstrip().startswith("//") or not DIAL.search(line):
            continue
        if any('"unix"' in l for l in lines[i : i + WINDOW + 1]):
            continue
        out.append(i + 1)
    return out


def hooked(path):
    return GUARD in path.read_text(encoding="utf-8", errors="replace")


def load_allow(path):
    allow = {}
    if path.exists():
        for n, raw in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
            raw = raw.strip()
            if not raw or raw.startswith("#"):
                continue
            rel, _, why = raw.partition(" ")
            if not why.strip():
                raise SystemExit(f"{path}:{n}: {rel} needs a reason")
            allow[rel] = why.strip()
    return allow


def check(root, allow_file):
    root = pathlib.Path(root)
    allow = load_allow(pathlib.Path(allow_file))
    problems, seen = [], set()
    for f in sorted((root / "broker").rglob("*.go")):
        rel = f.relative_to(root).as_posix()
        if "/vendor/" in rel or "/testdata/" in rel or rel.endswith("_test.go") or rel.startswith("broker/netguard/"):
            continue
        found = sites(f)
        if not found:
            continue
        if hooked(f):
            if rel in allow:
                problems.append(f"{rel}: imports the guard, remove it from the allowlist")
            continue
        seen.add(rel)
        if rel not in allow:
            problems.append(f"{rel}:{found[0]}: dialer not hooked into broker/netguard (use netguard.Policy.DialContext, or list the file with a reason)")
    for rel in sorted(set(allow) - seen):
        if rel not in {p.split(":")[0] for p in problems}:
            problems.append(f"{rel}: allowlisted but has no unhooked dialer (stale entry)")
    return problems


def main(argv=None):
    ap = argparse.ArgumentParser()
    root = pathlib.Path(__file__).resolve().parent.parent
    ap.add_argument("--root", default=str(root))
    ap.add_argument("--allow", default=str(root / "tools" / "netguard_allow.txt"))
    a = ap.parse_args(argv)
    problems = check(a.root, a.allow)
    for p in problems:
        print("netguardcheck:", p, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
