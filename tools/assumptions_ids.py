#!/usr/bin/env python3
"""Order-independent ASSUMPTIONS.md row IDs (ASSUMPTIONS-ID).

Two PRs that each append "the next number" to one table collide, whichever merges first.
A new row is therefore keyed by its package, `<PACKAGE-ID>-<suffix>` (e.g. `DEP-2-a`,
`ASSUMPTIONS-ID-1`): package IDs are unique per PR, so rows from different PRs never share an ID
and a merge needs no renumbering.

Rows that existed when this rule landed keep their bare IDs (`A21`, `D35`, `7`), listed in
tools/assumptions_legacy_ids.txt as `<file> <ID>`. Any other row whose ID is not package-scoped
fails doclint. The list only shrinks: never add a line to it; use a package-scoped ID instead.

Usage: python3 tools/assumptions_ids.py [repo root]    prints the legacy list for that tree
"""
import pathlib
import re
import subprocess
import sys

LEGACY = "tools/assumptions_legacy_ids.txt"
# a letter-led token, a hyphen, then more: DEP-2-a, RT-1c, ASSUMPTIONS-ID-1. Bare A21 / D35 / 7 do not match.
SCOPED = re.compile(r"[A-Za-z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)+")


def rows(root, name):
    """Yield (line number, ID) for each table row of one ASSUMPTIONS.md."""
    in_table = False
    for n, line in enumerate((pathlib.Path(root) / name).read_text().splitlines(), 1):
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if not line.startswith("|"):
            in_table = False
        elif cells[0] in ("ID", "#"):
            in_table = True
        elif in_table and not set(cells[0]) <= set("-: "):
            yield n, cells[0]


def assumption_files(root):
    out = subprocess.run(["git", "ls-files", "*ASSUMPTIONS.md"], cwd=root, capture_output=True, text=True, check=True).stdout
    return [f for f in out.splitlines() if pathlib.PurePosixPath(f).name == "ASSUMPTIONS.md"]


def legacy(root):
    path = pathlib.Path(root) / LEGACY
    if not path.is_file():
        return set()
    return {tuple(l.split(None, 1)) for l in path.read_text().splitlines() if l.strip() and not l.startswith("#")}


def check(root, files):
    """One problem line for each row whose ID is neither package-scoped nor legacy."""
    old = legacy(root)
    for name in files:
        if pathlib.PurePosixPath(name).name != "ASSUMPTIONS.md":
            continue
        for n, rid in rows(root, name):
            if not SCOPED.fullmatch(rid) and (name, rid) not in old:
                yield (f"{name}:{n}: row ID {rid} is not package-scoped; use `<PACKAGE-ID>-<suffix>` "
                       f"so parallel PRs cannot collide (tools/assumptions_ids.py)")


def snapshot(root):
    return [f"{name} {rid}" for name in assumption_files(root) for _, rid in rows(root, name)
            if not SCOPED.fullmatch(rid)]


if __name__ == "__main__":
    print("# Bare ASSUMPTIONS.md row IDs that predate tools/assumptions_ids.py. Only shrinks.")
    print("\n".join(snapshot(pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "."))))
