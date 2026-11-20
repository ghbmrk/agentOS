#!/usr/bin/env python3
"""Merge driver for ASSUMPTIONS.md: rows merge by row ID, so a main merge never keeps an edited row twice (#6316).

  tools/assumptions_merge.py --install            once per clone: this clone's merges of ASSUMPTIONS.md use the driver
  tools/assumptions_merge.py BASE OURS THEIRS [PATH]   git's driver call (%O %A %B %P); writes the merge to OURS

`.gitattributes` gives ASSUMPTIONS.md `merge=union`, which CI's merges (premerge's replay, trusted-base, lookup)
keep reading. Git runs no command a repository names until the clone's own config does, so `--install` sets
`merge.assumptions.driver` and puts `ASSUMPTIONS.md merge=assumptions` in `info/attributes`, which outranks
`.gitattributes` for this clone only. A clone without it merges by union, as before; doclint still fails a
duplicate ID, and its error names the install (OPERATING §7).

The driver runs `git merge-file --diff3` on the three versions and resolves each conflict hunk whose lines are
all table rows as union by row ID: the ours rows, then the theirs rows, less each base row the other side changed
or deleted. That is premerge's first resolution of a union hunk (`_stale_dropped`), so CI reads the result as
`same` beside the reviewed commit. A row both sides changed, differently, or one side changed and the other
deleted, and any hunk holding a line that is no table row, keep conflict markers; a result with one row ID twice
(both sides appended one ID) keeps both rows. Either exits 1, so git stops the merge for the builder to resolve
(renumber the PR's row, which premerge reads as `same`). Standard library only.
"""
import collections
import pathlib
import re
import secrets
import subprocess
import sys
import tempfile

FIRST_CELL = re.compile(rb"^\|[ \t]*([^|\s][^|]*?)[ \t]*\|")  # premerge.py's FIRST_CELL
LABELS = ("ours", "base", "theirs")
DRIVER = "python3 tools/assumptions_merge.py %O %A %B %P"


def _key(line):
    m = FIRST_CELL.match(line)
    return m and m.group(1)


def _less(rows, drop):
    """`rows` less the first drop[x] copies of each row x, in order."""
    drop, out = drop.copy(), []
    for x in rows:
        if drop[x] > 0:
            drop[x] -= 1
        else:
            out.append(x)
    return out


def resolve(ours, base, theirs):
    """The rows of one conflict hunk merged by row ID, or None when it stays a conflict."""
    if not all(_key(x) for x in ours + base + theirs):
        return None
    for k in {_key(x) for x in base}:
        o, b, t = (collections.Counter(x for x in side if _key(x) == k) for side in (ours, base, theirs))
        if o != b and t != b and o != t:
            return None  # changed differently on both sides, or changed on one and deleted on the other
    n = [collections.Counter(h) for h in (ours, base, theirs)]
    gone = collections.Counter({x: min(n[2][x], c - n[0][x]) for x, c in n[1].items() if c > n[0][x]})
    cut = collections.Counter({x: min(n[0][x], c - n[2][x]) for x, c in n[1].items() if c > n[2][x]})
    return _less(ours, cut) + _less(theirs, gone)


def duplicates(text):
    """Row IDs a table of `text` repeats, each with its lines: doclint's assumption_ids rule (premerge `_duplicate_id`)."""
    rows, in_table = collections.defaultdict(list), False
    for line in text.splitlines():
        cells = [c.strip() for c in line.decode(errors="surrogateescape").strip().strip("|").split("|")]
        if not line.startswith(b"|"):
            in_table = False
        elif cells[0] in ("ID", "#"):
            in_table = True
        elif in_table and not set(cells[0]) <= set("-: "):
            rows[cells[0]].append(line.decode(errors="surrogateescape"))
    return {k: v for k, v in rows.items() if len(v) > 1}


def merge(base, ours, theirs):
    """(merged bytes, clean) for three versions of an ASSUMPTIONS.md."""
    mark = secrets.token_hex(16)  # labels no file can carry
    with tempfile.TemporaryDirectory() as d:
        names = [pathlib.Path(d, n) for n in LABELS]
        for name, text in zip(names, (ours, base, theirs)):
            name.write_bytes(text)
        merged = subprocess.run(["git", "merge-file", "-p", "--diff3", *(f"-L{mark}{i}" for i in range(3)),
                                 *map(str, names)], capture_output=True).stdout
    out, hunk, side, clean = [], None, 0, True
    for line in merged.splitlines(keepends=True):
        bare = line.rstrip(b"\r\n")
        if hunk is None and bare == f"<<<<<<< {mark}0".encode():
            hunk, side = ([], [], []), 0
        elif hunk is None:
            out.append(line)
        elif bare == f"||||||| {mark}1".encode() and side == 0:
            side = 1
        elif bare == b"=======" and side == 1:
            side = 2
        elif bare == f">>>>>>> {mark}2".encode() and side == 2:
            rows = resolve(*hunk)
            if rows is None:
                clean = False
                out += [b"<<<<<<< ours\n", *hunk[0], b"||||||| base\n", *hunk[1], b"=======\n", *hunk[2],
                        b">>>>>>> theirs\n"]
            else:
                out += rows
            hunk = None
        else:
            hunk[side].append(line)
    return b"".join(out), clean


def install(cwd="."):
    """Point this clone's merges of ASSUMPTIONS.md at the driver; running it again changes nothing."""
    git = lambda *a: subprocess.run(["git", *a], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()
    git("config", "merge.assumptions.name", "ASSUMPTIONS.md rows by ID (tools/assumptions_merge.py)")
    git("config", "merge.assumptions.driver", DRIVER)
    attrs = pathlib.Path(cwd, git("rev-parse", "--git-path", "info/attributes"))
    line = "ASSUMPTIONS.md merge=assumptions"
    old = attrs.read_text() if attrs.exists() else ""
    if line not in old.splitlines():
        attrs.parent.mkdir(parents=True, exist_ok=True)
        attrs.write_text(old + ("" if not old or old.endswith("\n") else "\n") + line + "\n")


def main(argv):
    if argv == ["--install"]:
        install()
        return 0
    if len(argv) not in (3, 4):
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    path = argv[3] if len(argv) == 4 else argv[1]
    base, ours, theirs = (pathlib.Path(a).read_bytes() for a in argv[:3])
    text, clean = merge(base, ours, theirs)
    pathlib.Path(argv[1]).write_bytes(text)
    if not clean:
        print(f"{path}: a row both sides changed, or a non-row line, is left in conflict markers", file=sys.stderr)
    for k, lines in sorted(duplicates(text).items()):
        clean = False
        print(f"{path}: row ID {k} twice, renumber the PR's row:", *lines, sep="\n  ", file=sys.stderr)
    return 0 if clean else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
