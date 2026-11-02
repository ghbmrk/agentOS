#!/usr/bin/env python3
"""Say whether each cited line is one the PR's diff adds or changes (OPERATING §2, §4 blocker evidence).

  tools/difflines.py [--base origin/main] [--head HEAD] <path:line> ...

A blocker must cite a head-side `path:line` the diff changes: the defect itself, or the PR's line that
newly reaches or breaks older code (its new call site, its changed argument). For each citation this
prints `in-diff path:line` or `unchanged path:line`, and exits 0 only when every citation is in-diff.
A line counts as in-diff when `git diff -U0 merge-base(base, head) head` adds it, when a pure deletion
sits right next to it (the line before or after the removed block), or when its file is deleted. An
`unchanged` citation is pre-existing code: its finding is a `release` work item, never a blocker, unless
the reviewer cites the in-diff line that causes it. Git only, no network; fetch first.
"""
import re
import subprocess
import sys

HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@", re.M)


def _git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True).stdout.decode(errors="surrogateescape")


def changed_lines(base, head, path):
    """Head-side line numbers of `path` the diff adds or borders a deletion of; None if the diff deletes it."""
    onto = _git("merge-base", base, head).strip()
    status = _git("diff", "--no-color", "--no-ext-diff", "--no-renames", "--name-status", onto, head, "--", path)
    if status.startswith("D"):
        return None
    out = _git("diff", "--no-color", "--no-ext-diff", "--no-textconv", "--no-renames", "-U0", onto, head, "--", path)
    lines = set()
    for m in HUNK.finditer(out):
        start, count = int(m.group(1)), int(m.group(2) or 1)
        # A pure deletion (+N,0) removes lines after head line N: both neighbours carry the change.
        lines.update(range(start, start + count) if count else (start, start + 1))
    return lines


def main(argv):
    args, base, head = argv[1:], "origin/main", "HEAD"
    while args[:1] in (["--base"], ["--head"]):
        if len(args) < 2:
            break
        if args[0] == "--base":
            base = args[1]
        else:
            head = args[1]
        args = args[2:]
    cites = [a.rpartition(":") for a in args]
    if not cites or any(not p or not n.isdigit() for p, _, n in cites):
        print(__doc__)
        return 2
    ok = True
    for path, _, n in cites:
        lines = changed_lines(base, head, path)
        hit = lines is None or int(n) in lines
        ok &= hit
        print(f"{'in-diff' if hit else 'unchanged'} {path}:{n}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
