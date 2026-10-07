#!/usr/bin/env python3
"""What to build next, in a few lines.

Prints uncovered requirement IDs (TRACE.md) and board rows that are queued
and neither blocked nor deferred. Agents should read this instead of BOARD.md.

Usage: python3 tools/next.py
"""
import argparse
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
ID = re.compile(r"[A-Z]{2,4}-\d+[a-z]?$")
EMPTY = {"—", "–", "-", ""}


def uncovered(trace_text):
    ids = []
    for line in trace_text.splitlines():
        if not line.startswith("|"):
            continue
        cols = [c.strip().strip("`") for c in line.strip().strip("|").split("|")]
        if len(cols) < 2 or not ID.match(cols[0]):
            continue
        if cols[1] in EMPTY:
            ids.append(cols[0])
    return ids


def board_rows(text):
    rows = []
    for line in text.splitlines():
        if not line.startswith("|"):
            continue
        cols = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cols) < 4:
            continue
        pid = cols[0]
        if pid in ("ID",) or set(pid) <= {"-", ":"} or not pid[:1].isalnum():
            continue
        rows.append((pid, cols[-1], cols[1]))
    return rows


def actionable(state):
    s = state.lower()
    if not re.search(r"\bqueued\b", s):
        return False
    # "unblocked" contains the letters of "blocked"; match the word.
    if re.search(r"\bblocked\b", s) or re.search(r"\bdeferred\b", s) or re.search(r"\bdropped\b", s):
        return False
    return True


def deduped(rows):
    """Last row for an ID wins; later board sections are the current state."""
    order = []
    by = {}
    for pid, state, name in rows:
        if pid not in by:
            order.append(pid)
        by[pid] = (state, name)
    return [(pid, *by[pid]) for pid in order]


def in_review(state):
    s = state.lower()
    return "in review" in s or s.strip() == "review"


def report(trace_text, board_text):
    missing = uncovered(trace_text)
    rows = deduped(board_rows(board_text))
    review = [(i, n) for i, st, n in rows if in_review(st)]
    queued = [(i, st, n) for i, st, n in rows if actionable(st)]
    lines = [
        f"Uncovered ({len(missing)}): " + (" ".join(missing) if missing else "none"),
        f"In review: {len(review)}. Finish or reject one of these before adding surface.",
        f"Queued, not blocked or deferred ({len(queued)}):",
    ]
    if not queued:
        lines.append("  none")
    for pid, state, name in queued:
        name = re.sub(r"\s+", " ", name)[:110]
        lines.append(f"  {pid}: {name}")
    return "\n".join(lines) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=str(ROOT))
    args = ap.parse_args(argv)
    root = pathlib.Path(args.root)
    try:
        trace = (root / "TRACE.md").read_text()
        board = (root / "BOARD.md").read_text()
    except OSError as e:
        print(e, file=sys.stderr)
        return 1
    sys.stdout.write(report(trace, board))
    return 0


if __name__ == "__main__":
    sys.exit(main())
