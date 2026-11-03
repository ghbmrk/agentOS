#!/usr/bin/env python3
"""Claims in a PR body that a tool can check, checked (REV-PROOF-claims, #4909).

  closes   a body that says `Closes #N` (or Fixes, Resolves, in any of GitHub's forms) and,
           on another line or the same one, defers part of #N (a line with deferral phrasing,
           such as deferred, left for, out of scope, not in this PR, or "later" only as "in a later
           PR", that names #N) fails, unless that line also names a follow-up issue
           (an `#M` the body does not close). Merging would close #N with its deferred part on no
           open issue (#2623 closed #2619 so).

Fenced code blocks and HTML comments are not read. A deferral word just after "no", "not",
"nothing" or "none" ("nothing deferred") does not count; nor does one inside an identifier
("G1-e2e-later-fu8"). Plain "later" ("a later header") and "remaining" are ordinary English, and "follow-ups" often
names the closed issues themselves ("ENF-d follow-ups (#3759)", #4536), so none of them count.

Usage:
  tools/claims.py closes --body FILE [--markdown FILE]
      exit 0 pass, 1 a deferred part of a closed issue with no follow-up; --markdown also appends
      the result to FILE (the job summary)
"""
import argparse
import pathlib
import re
import sys

CLOSE = re.compile(r"(?i)\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?)\s*:?\s+(?:[\w.-]+/[\w.-]+)?#(\d+)(?!\d)")
ISSUE = re.compile(r"(?<![\w&/])(?:[\w.-]+/[\w.-]+)?#(\d+)(?!\d)")
LATER_ITEM = r"(?:prs?|pull requests?|packages?|rows?|changes?|rounds?|builds?)"
DEFER = re.compile(r"(?i)(?<![\w-])(?:defer(?:s|red|ring)?|out of scope|left for|postponed?|"
                   rf"not in this pr|todo|(?:in|to|for|until) (?:a |the )?later {LATER_ITEM}|later {LATER_ITEM})(?![\w-])")
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
    c = sub.add_parser("closes", help="a closed issue's deferred part names a follow-up issue")
    c.add_argument("--body", required=True, help="file holding the PR body")
    c.add_argument("--markdown", help="also append the result to this file")
    a = ap.parse_args(argv)
    problems = closes(pathlib.Path(a.body).read_text())
    text = "".join(f"claims: {p}\n" for p in problems) or "claims: pass\n"
    print(text, end="")
    if a.markdown:
        with open(a.markdown, "a") as f:
            f.write("\n## Closing keywords (REV-PROOF-claims)\n\n" + ("**Fail:**\n" if problems else "**Pass.**\n")
                    + "".join(f"- {p}\n" for p in problems))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
