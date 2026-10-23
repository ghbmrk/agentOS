#!/usr/bin/env python3
"""Shrink-only word budget for SPEC.md and the process docs (D-152).

Two sets, each counted as a whole: `spec` (SPEC.md) and `process` (CLAUDE.md, AGENTS.md,
PLAN.md, docs/OPERATING.md, docs/LANES.md and every `.claude/skills/<name>/SKILL.md`).
A word is a run of non-whitespace (Python's str.split), so a standalone dash counts;
`wc -w` in the C locale skips those and reads a little lower.

A PR may not grow either set. It passes when each set's count at the head is at most
the base's, or when its body has a line `Word-budget: <decision ID>` naming an active
row of DECISIONS.md at the head; the reviewer checks that the row records Mark approving
the addition. Words cut from one set do not pay for words added to the other.

word-budget.yml runs the base commit's copy of this file, so a PR cannot loosen the check
for itself; only the PR that adds the file runs its own copy. Standard library only.

Usage:
  tools/word_budget.py                                 counts in the working tree
  tools/word_budget.py --git BASE HEAD [--body-file F] fail (exit 1) if HEAD grew a set
"""
import argparse
import pathlib
import re
import subprocess
import sys

SPEC = ("SPEC.md",)
PROCESS = ("CLAUDE.md", "AGENTS.md", "PLAN.md", "docs/OPERATING.md", "docs/LANES.md")
SKILL = re.compile(r"^\.claude/skills/[^/]+/SKILL\.md$")
WAIVER = re.compile(r"^Word-budget:\s*(\S+)\s*$", re.M)


def words(text):
    return len(text.split())


def sets(paths):
    """Map each set name to its member paths, given every path that exists."""
    paths = set(paths)
    return {
        "spec": [p for p in SPEC if p in paths],
        "process": [p for p in PROCESS if p in paths] + sorted(p for p in paths if SKILL.match(p)),
    }


def counts(read, paths):
    """Word count per set; `read(path)` returns a member's text."""
    return {name: sum(words(read(p)) for p in members) for name, members in sets(paths).items()}


def tree_counts(root):
    root = pathlib.Path(root)
    named = [p for p in SPEC + PROCESS if (root / p).is_file()]
    paths = named + [p.relative_to(root).as_posix() for p in root.glob(".claude/skills/*/SKILL.md")]
    return counts(lambda p: (root / p).read_text(encoding="utf-8"), paths)


def _git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True).stdout


def git_counts(ref):
    paths = _git("ls-tree", "-r", "--name-only", ref).decode().splitlines()
    return counts(lambda p: _git("show", f"{ref}:{p}").decode("utf-8"), paths)


def active_decision(decisions, ident):
    """True if DECISIONS.md text has a row for `ident` whose status is active."""
    for line in decisions.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) >= 3 and cells[0] == ident:
            return cells[2] == "active"
    return False


def check(base, head, body, decisions):
    """Return (ok, report lines)."""
    grew = [k for k in head if head[k] > base.get(k, 0)]
    lines = [f"{k}: {base.get(k, 0)} -> {head[k]} words ({head[k] - base.get(k, 0):+d})" for k in head]
    if not grew:
        return True, lines
    m = WAIVER.search(body or "")
    if m and active_decision(decisions, m.group(1)):
        return True, lines + [f"grew {', '.join(grew)}: allowed by {m.group(1)} (reviewer: confirm Mark approved the addition)"]
    why = f"`Word-budget: {m.group(1)}` names no active DECISIONS.md row" if m else "no `Word-budget: <decision ID>` line"
    return False, lines + [f"grew {', '.join(grew)} and {why}: retire as many words in the same set (D-152)"]


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--git", nargs=2, metavar=("BASE", "HEAD"))
    ap.add_argument("--body-file")
    args = ap.parse_args(argv)
    if not args.git:
        for k, v in tree_counts(".").items():
            print(f"{k} {v}")
        return 0
    base_ref, head_ref = args.git
    body = pathlib.Path(args.body_file).read_text(encoding="utf-8") if args.body_file else ""
    decisions = _git("show", f"{head_ref}:DECISIONS.md").decode("utf-8")
    ok, lines = check(git_counts(base_ref), git_counts(head_ref), body, decisions)
    print("\n".join(lines))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
