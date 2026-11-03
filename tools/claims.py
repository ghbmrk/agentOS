#!/usr/bin/env python3
"""Claims in a PR body that a tool can check, checked (REV-PROOF-claims, #4909).

  closes   a body that says `Closes #N` (or Fixes, Resolves, in any of GitHub's forms) and,
           on another line or the same one, defers part of #N (a line with a deferral word, such
           as deferred, later, follow-up, remaining, out of scope, that names #N) fails, unless
           that line also names a follow-up issue (an `#M` the body does not close). Merging would close #N with
           its deferred part on no open issue (#2623 closed #2619 so).

Fenced code blocks and HTML comments are not read. A deferral word just after "no", "not",
"nothing" or "none" ("nothing deferred") does not count.

Usage:
  tools/claims.py closes --body FILE    exit 0 pass, 1 a deferred part of a closed issue with no follow-up
"""
import argparse
import pathlib
import re
import sys

CLOSE = re.compile(r"(?i)\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s*:?\s+(?:[\w.-]+/[\w.-]+)?#(\d+)(?!\d)")
ISSUE = re.compile(r"(?<![\w&/])(?:[\w.-]+/[\w.-]+)?#(\d+)(?!\d)")
DEFER = re.compile(r"(?i)\b(?:defer(?:s|red|ring)?|later|follow[- ]?ups?|remaining|out of scope|left for|"
                   r"postponed?|not in this pr|todo)\b")
NEGATION = re.compile(r"(?i)\b(?:no|not|nothing|none)\s+$")
FENCE = re.compile(r"^\s*(```|~~~)")


def lines(body):
    """(number, text) of each body line outside fenced code, with HTML comments blanked."""
    body = re.sub(r"<!--.*?-->", lambda m: re.sub(r"[^\n]", " ", m.group(0)), body, flags=re.S)
    fenced = False
    for n, line in enumerate(body.split("\n"), 1):
        if FENCE.match(line):
            fenced = not fenced
            continue
        if not fenced:
            yield n, line


def defers(line):
    return any(not NEGATION.search(line[:m.start()]) for m in DEFER.finditer(line))


def closes(body):
    """Problems: each deferral line naming a closed issue and no follow-up issue."""
    text = list(lines(body or ""))
    closed = {int(m.group(1)) for _, line in text for m in CLOSE.finditer(line)}
    problems = []
    for n, line in text:
        if not closed or not defers(line):
            continue
        named = {int(x) for x in ISSUE.findall(line)}
        for issue in sorted(named & closed):
            if not named - closed:
                problems.append(f"body line {n}: the body closes #{issue}, but this line defers part of it and names"
                                f" no follow-up issue; name the follow-up (`#M`) or drop the closing keyword:"
                                f" {line.strip()[:200]}")
    return problems


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("closes")
    c.add_argument("--body", required=True, help="file holding the PR body")
    a = ap.parse_args(argv)
    problems = closes(pathlib.Path(a.body).read_text())
    for p in problems:
        print(f"claims: {p}")
    if not problems:
        print("claims: pass")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
