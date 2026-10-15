#!/usr/bin/env python3
"""Print exactly the SPEC.md requirement blocks you cite (CTX-slice, issue #1681).

A block is the line that defines a requirement ID in bold (**CRED-1**) plus its continuation lines;
a table row is one line. Each block comes under the headings that enclose it, and the output is
stamped with the commit hash so a reader knows which SPEC it came from. Not a digest: the text is
copied verbatim.

Usage:
  tools/specslice.py --ids A-1,B-2 [--ref REV] [--root DIR]
Exits 2 and prints nothing to stdout if any ID is unknown (stderr names them).
"""
import argparse
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
ID_DEF = re.compile(r"\*\*([A-Z]{2,4}-\d+[a-z]?)\*\*")
HEADING = re.compile(r"^(#{1,6})\s+\S")
ITEM = re.compile(r"^(\s*)(?:[-*]|\d+\.)\s")


def parse(spec_text):
    """Return {id: (heading_chain, block_text)} for every bold-defined ID."""
    lines = spec_text.split("\n")
    out = {}
    chain = []  # [(level, heading line)]
    fence = False
    for i, line in enumerate(lines):
        if line.lstrip().startswith("```"):
            fence = not fence
            continue
        if fence:
            continue
        h = HEADING.match(line)
        if h:
            level = len(h.group(1))
            chain = [c for c in chain if c[0] < level] + [(level, line)]
            continue
        ids = ID_DEF.findall(line)
        if not ids:
            continue
        block = [line]
        if not line.lstrip().startswith("|"):
            item = ITEM.match(line)
            indent = len(item.group(1)) if item else None
            base = indent or 0
            for nxt in lines[i + 1:]:
                if not nxt.strip():
                    block.append(nxt)  # kept only if a deeper-indented line follows
                    continue
                if HEADING.match(nxt) or nxt.lstrip().startswith("```") or ID_DEF.search(nxt):
                    break
                if not block[-1].strip() and len(nxt) - len(nxt.lstrip()) <= base:
                    break
                m = ITEM.match(nxt)
                if indent is not None and m and len(m.group(1)) <= indent:
                    break
                block.append(nxt)
            while not block[-1].strip():
                block.pop()
        for rid in ids:
            out.setdefault(rid, ([c[1] for c in chain], "\n".join(block)))
    return out


def read_spec(root, ref=None):
    """Return (spec text, stamp)."""
    def git(*args):
        return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True)

    if ref:
        rev = git("rev-parse", "--verify", f"{ref}^{{commit}}")
        shown = git("show", f"{ref}:SPEC.md")
        if rev.returncode or shown.returncode:
            raise SystemExit(f"specslice: cannot read SPEC.md at {ref}")
        return shown.stdout, rev.stdout.strip()
    text = (pathlib.Path(root) / "SPEC.md").read_text()
    rev = git("rev-parse", "HEAD")
    stamp = rev.stdout.strip() if rev.returncode == 0 else "unknown"
    if rev.returncode == 0:
        committed = git("show", "HEAD:SPEC.md")
        if committed.returncode or committed.stdout != text:
            stamp += "+dirty"
    return text, stamp


def render(spec_text, stamp, ids):
    """Return the slice, or raise KeyError listing unknown IDs."""
    table = parse(spec_text)
    unknown = [i for i in ids if i not in table]
    if unknown:
        raise KeyError(", ".join(unknown))
    lines = [f"<!-- specslice: SPEC.md at {stamp}; ids {','.join(ids)} -->"]
    last = None
    done = set()
    for rid in ids:
        chain, block = table[rid]
        if block in done:
            continue
        done.add(block)
        if chain != last:
            lines += ["", *chain, ""]
            last = chain
        lines.append(block)
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--ids", required=True, help="comma-separated requirement IDs")
    ap.add_argument("--ref", help="git revision to read SPEC.md from (default: working tree)")
    ap.add_argument("--root", default=str(ROOT))
    args = ap.parse_args(argv)
    ids = [i.strip() for i in args.ids.split(",") if i.strip()]
    text, stamp = read_spec(args.root, args.ref)
    try:
        out = render(text, stamp, ids)
    except KeyError as e:
        print(f"specslice: unknown ID(s): {e.args[0]}", file=sys.stderr)
        return 2
    sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
