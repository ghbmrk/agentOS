#!/usr/bin/env python3
"""Shrink-only word budget for SPEC.md and the process docs (D-152).

Two sets, each counted as a whole: `spec` (SPEC.md) and `process` (CLAUDE.md, AGENTS.md,
PLAN.md, docs/OPERATING.md, docs/LANES.md and every `.claude/skills/<name>/SKILL.md`).
A word is a run of non-whitespace (Python's str.split), so a standalone dash counts;
`wc -w` in the C locale skips those and reads a little lower.

A PR may not grow either set. It passes when each set's count at the head is at most
the base's, or when it adds a line `word-budget #<PR> -- <decision ID>` to tools/word_budget_reasons.txt
naming an active row of DECISIONS.md at the base whose text names the PR (`#<number>`, from
$PR_NUMBER), so neither a row the PR adds nor an unrelated standing row can waive it (#2945);
the reviewer checks that the row records Mark approving the addition. Words cut from one set do
not pay for words added to the other. The waiver is a committed line, never PR-body text (#6490):
a body can change after the reviews accept a head, the line cannot without a new head. A line the
base already holds is history and waives nothing; an added line that is malformed or names
another PR fails the check.

word-budget.yml runs the base commit's copy of this file, so a PR cannot loosen the check
for itself; only the PR that adds the file runs its own copy. Standard library only.

Usage:
  tools/word_budget.py                                 counts in the working tree
  tools/word_budget.py --git BASE HEAD                 fail (exit 1) if HEAD grew a set
      a waiver counts only with the PR number in $PR_NUMBER
"""
import argparse
import os
import pathlib
import re
import subprocess
import sys

SPEC = ("SPEC.md",)
PROCESS = ("CLAUDE.md", "AGENTS.md", "PLAN.md", "docs/OPERATING.md", "docs/LANES.md")
SKILL = re.compile(r"^\.claude/skills/[^/]+/SKILL\.md$")
RECORD = "tools/word_budget_reasons.txt"
RECORD_LINE = re.compile(r"^word-budget #([1-9]\d*) -- (\S+)$")


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
    # NUL-delimited: without -z git quotes a path holding a non-ASCII byte, quote or backslash, so
    # such a skill would not match and its words would go uncounted (REV-LOW-tools finding 21).
    paths = [p for p in _git("ls-tree", "-r", "-z", "--name-only", ref).decode("utf-8").split("\0") if p]
    return counts(lambda p: _git("show", f"{ref}:{p}").decode("utf-8"), paths)


def active_decision(decisions, ident, pr):
    """True if DECISIONS.md text has a row for `ident` whose status is active and whose text names
    PR `pr` as `#<pr>`; never true without a PR number."""
    for line in decisions.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) >= 3 and cells[0] == ident:
            return cells[2] == "active" and pr is not None and bool(re.search(rf"#{int(pr)}(?!\d)", line))
    return False


def record_lines(text):
    """The record's entries, whitespace runs folded to one space: lines neither blank nor `#` comments."""
    return [" ".join(x.split()) for x in (text or "").splitlines() if x.strip() and not x.lstrip().startswith("#")]


def waivers(base_text, head_text, pr):
    """([decision ID], [problem]) from the record lines the head adds to the base's, for PR `pr`."""
    got, bad, old = [], [], set(record_lines(base_text))
    for line in record_lines(head_text):
        if line in old:
            continue
        r = RECORD_LINE.match(line)
        if not r:
            bad.append(f"{RECORD}: `{line}`: want `word-budget #<PR> -- <decision ID>`")
        elif pr is None or int(r.group(1)) != int(pr):
            bad.append(f"{RECORD}: `{line}`: names #{r.group(1)}, not this PR (#{pr})")
        else:
            got.append(r.group(2))
    return got, bad


def check(base, head, record, decisions, pr=None):
    """Return (ok, report lines). `record` is waivers()' pair for the PR's added record lines."""
    grew = [k for k in head if head[k] > base.get(k, 0)]
    lines = [f"{k}: {base.get(k, 0)} -> {head[k]} words ({head[k] - base.get(k, 0):+d})" for k in head]
    got, bad = record
    if bad:
        return False, lines + bad
    if not grew:
        return True, lines
    ok = [d for d in got if active_decision(decisions, d, pr)]
    if ok:
        note = " SPEC.md stays capped by tools/ceilings.txt (D-310), which the trusted-base check enforces." if "spec" in grew else ""
        return True, lines + [f"grew {', '.join(grew)}: allowed by {ok[0]} (reviewer: confirm Mark approved the addition).{note}"]
    why = (f"`{RECORD}` names no active DECISIONS.md row at the base that names #{pr} ({', '.join(got)})" if got
           else f"no `word-budget #{pr if pr is not None else '<PR>'} -- <decision ID>` line added to {RECORD}")
    return False, lines + [f"grew {', '.join(grew)} and {why}: retire as many words in the same set (D-152)"]


def git_record(ref):
    """The record's text at `ref`, or "" where the tree has none."""
    r = subprocess.run(["git", "cat-file", "-e", f"{ref}:{RECORD}"], capture_output=True)
    return _git("show", f"{ref}:{RECORD}").decode("utf-8") if r.returncode == 0 else ""


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--git", nargs=2, metavar=("BASE", "HEAD"))
    args = ap.parse_args(argv)
    if not args.git:
        for k, v in tree_counts(".").items():
            print(f"{k} {v}")
        return 0
    base_ref, head_ref = args.git
    # The base's decisions: a row the PR adds itself is not yet Mark's record (#2945).
    decisions = _git("show", f"{base_ref}:DECISIONS.md").decode("utf-8")
    pr = os.environ.get("PR_NUMBER", "")
    pr = int(pr) if pr.isdigit() else None
    record = waivers(git_record(base_ref), git_record(head_ref), pr)
    ok, lines = check(git_counts(base_ref), git_counts(head_ref), record, decisions, pr)
    print("\n".join(lines))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
