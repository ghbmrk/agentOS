#!/usr/bin/env python3
"""Compare the package manifests of two builds of one commit (the image workflow's reproduce job).

Each directory must hold exactly one mkosi JSON manifest (*.manifest) that parses and lists at
least one package, each with a name and a version; otherwise this exits non-zero, so a missing,
empty or truncated manifest can never read as "same packages" (#1474). It prints each side's
package count, then whether the package lists match. A difference is reported, not fatal: the /usr
root hash comparison already fails on any content difference.
Usage: compare_manifests.py DIR_A DIR_B"""
import json
import pathlib
import sys


def packages(d):
    """The (name, version, architecture) of every package in D's one manifest. Raises ValueError."""
    found = sorted(pathlib.Path(d).glob("*.manifest"))
    if len(found) != 1:
        raise ValueError("%s: expected one *.manifest, found %d" % (d, len(found)))
    try:
        m = json.loads(found[0].read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError("%s: unreadable manifest: %s" % (found[0], e))
    pkgs = m.get("packages") if isinstance(m, dict) else None
    if not isinstance(pkgs, list) or not pkgs:
        raise ValueError("%s: manifest lists no packages" % found[0])
    out = []
    for p in pkgs:
        if not isinstance(p, dict) or not p.get("name") or not p.get("version"):
            raise ValueError("%s: package entry without a name and version: %r" % (found[0], p))
        out.append((p["name"], p["version"], p.get("architecture", "")))
    return sorted(out)


def main(a, b):
    try:
        pa, pb = packages(a), packages(b)
    except ValueError as e:
        print("MISMATCH package manifest: %s" % e)
        return 1
    print("packages a=%d b=%d" % (len(pa), len(pb)))
    if pa == pb:
        print("same packages")
    else:
        sa, sb = set(pa), set(pb)
        print("package manifests differ: only in a %s; only in b %s" % (sorted(sa - sb), sorted(sb - sa)))
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    sys.exit(main(sys.argv[1], sys.argv[2]))
