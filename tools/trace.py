#!/usr/bin/env python3
"""Requirement traceability: SPEC.md requirement IDs <-> tests and spikes.

Requirement IDs are bold tokens like **KEY-1** in SPEC.md.
Tests claim coverage with a marker comment anywhere in a file:  REQ: KEY-1, CLK-2
A marker naming an ID retired in SPEC.md Appendix A is an old-core marker: it is
accepted and counted, and the count falls to zero by the end of PLAN step 5.
The old-core ratchet compares a base commit with the head: no measure of the old
core (tools/old_core.txt) may grow, a directory leaves that list only in the
PR that deletes its old files, and no old-core file survives, at its path or
renamed or copied (git's rename detection), outside the listed directories.
Usage:
  tools/trace.py            write TRACE.md (PRs don't commit it; .github/workflows/trace.yml does, on main)
  tools/trace.py --check    fail if TRACE.md is stale or a marker cites an unknown ID
  tools/trace.py --gate A,B fail unless every listed ID has at least one covering file
  tools/trace.py --ratchet BASE  fail if the old core grew between BASE and HEAD
"""
import argparse
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
ID_DEF = re.compile(r"\*\*([A-Z]{2,4}-\d+[a-z]?)\*\*")
MARKER = re.compile(r"REQ:\s*([A-Z]{2,4}-\d+[a-z]?(?:\s*,\s*[A-Z]{2,4}-\d+[a-z]?)*)")
ID_ANY = re.compile(r"[A-Z]{2,4}-\d+[a-z]?")
SCAN_DIRS = ("tests", "spikes", "src", "broker")
SKIP_SUFFIXES = {".png", ".jpg", ".img", ".iso", ".bin", ".pyc"}
OLD_CORE = "tools/old_core.txt"
MODULE = "github.com/ghbmrk/agentos/"


def spec_ids(spec_text):
    seen = []
    for m in ID_DEF.finditer(spec_text):
        if m.group(1) not in seen:
            seen.append(m.group(1))
    return seen


def retired_ids(spec_text):
    """IDs in the first column of SPEC.md Appendix A's retired-ID table."""
    _, sep, appendix = spec_text.partition("## Appendix A.")
    seen = []
    if not sep:
        return seen
    for line in appendix.splitlines():
        cells = line.split("|")
        if len(cells) < 3 or cells[1].strip() in ("Retired", "") or set(cells[1].strip()) <= {"-"}:
            continue
        for rid in ID_ANY.findall(cells[1]):
            if rid not in seen:
                seen.append(rid)
    return seen


def markers(cov, path, text):
    for m in MARKER.finditer(text):
        for rid in re.split(r"\s*,\s*", m.group(1)):
            cov.setdefault(rid, set()).add(path)


def coverage(root):
    cov = {}
    for d in SCAN_DIRS:
        base = root / d
        if not base.is_dir():
            continue
        for f in sorted(base.rglob("*")):
            if not f.is_file() or f.suffix in SKIP_SUFFIXES:
                continue
            try:
                text = f.read_text(errors="ignore")
            except OSError:
                continue
            markers(cov, str(f.relative_to(root)), text)
    return cov


def git_tree(root, ref):
    """{path: text} for every file at ref, read through git."""
    rows = subprocess.run(["git", "-C", str(root), "ls-tree", "-r", "-z", ref],
                          check=True, capture_output=True).stdout.decode().split("\0")
    names = [r.split("\t", 1)[1] for r in rows if r and r.split()[1] == "blob"]
    blobs = "".join(f"{ref}:{n}\n" for n in names).encode()
    out = subprocess.run(["git", "-C", str(root), "cat-file", "--batch"], input=blobs,
                         check=True, capture_output=True).stdout
    tree, i = {}, 0
    for n in names:
        header_end = out.index(b"\n", i)
        size = int(out[i:header_end].split()[2])
        body = out[header_end + 1:header_end + 1 + size]
        i = header_end + 2 + size
        # The old-core list decodes with "replace" so old_core_dirs refuses an invalid byte rather
        # than dropping it ("broker/jou\xffrnal" read as broker/journal, #3952). Other files keep
        # "ignore": a dropped byte can only join a marker, so the ratchet over-counts, never under.
        tree[n] = body.decode(errors="replace" if n == OLD_CORE else "ignore")
    return tree


def old_core_dirs(tree):
    # "\n" only, printable ASCII only: splitlines() also ends a line at "\r", U+2028 and
    # others, so a break hidden in a comment would add a line (REV-CHK-crlf, #3902).
    dirs = []
    for n, l in enumerate(tree.get(OLD_CORE, "").split("\n"), 1):
        bad = [c for c in l if not " " <= c <= "~"]
        if bad:
            raise SystemExit(f"{OLD_CORE}:{n}: character {bad[0]!r} outside printable ASCII")
        if l.strip() and not l.startswith("#"):
            dirs.append(l.strip())
    return dirs


def under(path, d):
    return path.startswith(d + "/")


def old_core_measures(tree, dirs, retired):
    """Markers citing retired IDs, lines in each old-core directory, and imports
    of an old-core package from a Go file outside the old core (its wiring)."""
    cov = {}
    for path, text in tree.items():
        if path.split("/")[0] in SCAN_DIRS and pathlib.PurePath(path).suffix not in SKIP_SUFFIXES:
            markers(cov, path, text)
    m = {"old-core markers": sum(len(cov.get(r, ())) for r in retired)}
    for d in dirs:
        m[f"lines in {d}"] = sum(t.count("\n") for p, t in tree.items() if under(p, d))
        imp = re.compile(r'"' + re.escape(MODULE + d) + r'(?:/[^"]*)?"')
        m[f"imports of {d}"] = sum(len(imp.findall(t)) for p, t in tree.items()
                                   if p.endswith(".go") and not any(under(p, o) for o in dirs))
    return m


def moves(root, base, head):
    """{base path: [head paths]} for files git sees renamed or copied (D-139).
    -l0 lifts git's rename limit; if git still skips detection, fail closed."""
    r = subprocess.run(["git", "-C", str(root), "diff", "-M", "-C", "--find-copies-harder", "-l0",
                        "--name-status", "-z", base, head], check=True, capture_output=True)
    if b"too many files" in r.stderr:
        raise SystemExit("Old core grew: rename detection was skipped (too many files)")
    out = r.stdout.decode().split("\0")
    m, i = {}, 0
    while i < len(out) and out[i]:
        if out[i][0] in "RC":
            m.setdefault(out[i + 1], []).append(out[i + 2])
            i += 3
        else:
            i += 2
    return m


def ratchet(root, base, head, retired):
    """Problems with the old core between base and head; empty when it did not grow."""
    bt, ht = git_tree(root, base), git_tree(root, head)
    bdirs, dirs = old_core_dirs(bt), old_core_dirs(ht)
    problems, moved = [], moves(root, base, head)
    for bp in sorted(p for p in bt if any(under(p, d) for d in bdirs)):
        for hp in ([bp] if bp in ht else []) + moved.get(bp, []):
            if not any(under(hp, d) for d in dirs):
                problems.append(f"old-core file {bp} persists outside {OLD_CORE} at {hp}")
    bm, hm = old_core_measures(bt, dirs, retired), old_core_measures(ht, dirs, retired)
    for k in hm:
        if hm[k] > bm[k]:
            problems.append(f"{k} grew from {bm[k]} to {hm[k]}")
    return problems


def render(ids, cov, retired=()):
    covered = sum(1 for i in ids if i in cov)
    old = [i for i in retired if i in cov]
    lines = [
        "# TRACE (generated by tools/trace.py; do not edit)",
        "",
        f"Covered: {covered} / {len(ids)} requirement IDs",
        "",
        "| ID | Covered by |",
        "|---|---|",
    ]
    for i in ids:
        files = ", ".join(f"`{f}`" for f in sorted(cov.get(i, ()))) or "—"
        lines.append(f"| {i} | {files} |")
    lines += [
        "",
        "## Old-core markers (retired IDs)",
        "",
        f"Old-core markers: {sum(len(cov[i]) for i in old)} in {len(old)} retired IDs",
    ]
    if old:
        lines += ["", "| Retired ID | Cited by |", "|---|---|"]
        for i in old:
            files = ", ".join(f"`{f}`" for f in sorted(cov[i]))
            lines.append(f"| {i} | {files} |")
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--gate", default="")
    ap.add_argument("--root", default=str(ROOT))
    ap.add_argument("--ratchet", default="", metavar="BASE")
    ap.add_argument("--head", default="HEAD")
    args = ap.parse_args(argv)
    root = pathlib.Path(args.root)

    spec = (root / "SPEC.md").read_text()
    ids = spec_ids(spec)
    retired = retired_ids(spec)
    cov = coverage(root)
    out = render(ids, cov, retired)
    trace = root / "TRACE.md"

    if args.ratchet:
        problems = ratchet(root, args.ratchet, args.head, retired)
        for p in problems:
            print("Old core grew: " + p, file=sys.stderr)
        return 1 if problems else 0

    unknown = sorted(set(cov) - set(ids) - set(retired))
    if unknown:
        print("Markers cite IDs not in SPEC.md: " + ", ".join(unknown), file=sys.stderr)
        return 1
    if args.gate:
        missing = [g.strip() for g in args.gate.split(",") if g.strip() and g.strip() not in cov]
        if missing:
            print("Gate not covered: " + ", ".join(missing), file=sys.stderr)
            return 1
    if args.check:
        if not trace.exists() or trace.read_text() != out:
            print("TRACE.md is stale; run tools/trace.py", file=sys.stderr)
            return 1
        return 0
    trace.write_text(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
